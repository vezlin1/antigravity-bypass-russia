use crate::net::socket::bind_socket_to_interface;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

#[inline]
pub fn build_query(name: &str, id: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(64);
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&[0x01, 0x00]); // RD=1
    p.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    for label in name.trim_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            continue;
        }
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0x00);
    p.extend_from_slice(&[0x00, 0x01]); // TYPE A
    p.extend_from_slice(&[0x00, 0x01]); // CLASS IN
    p
}

#[inline]
fn skip_name(buf: &[u8], pos: usize) -> usize {
    skip_name_opt(buf, pos).unwrap_or(buf.len())
}

fn skip_name_opt(buf: &[u8], mut pos: usize) -> Option<usize> {
    let mut hops = 0;
    while pos < buf.len() && hops < 64 {
        hops += 1;
        let len = *buf.get(pos)? as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if (len & 0xC0) == 0xC0 {
            return if pos + 1 < buf.len() {
                Some(pos + 2)
            } else {
                None
            };
        }
        pos += 1 + len;
    }
    None
}

/// Reuse a packet only within every record's TTL, aging it for downstream caches.
/// OPT uses this field for EDNS flags and must not be changed.
pub fn aged_reply(reply: &[u8], elapsed: u32) -> Option<Vec<u8>> {
    if elapsed >= 300 {
        return None;
    }
    rewrite_ttls(reply, elapsed, u32::MAX, true)
}

pub fn answer_addrs(buf: &[u8]) -> Vec<IpAddr> {
    let mut out = Vec::new();
    if buf.len() < 12 {
        return out;
    }
    let questions = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let answers = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut i = 12;
    for _ in 0..questions {
        i = match skip_name_opt(buf, i) {
            Some(n) => n + 4,
            None => return out,
        };
    }
    for _ in 0..answers {
        i = match skip_name_opt(buf, i) {
            Some(n) => n,
            None => return out,
        };
        if i + 10 > buf.len() {
            return out;
        }
        let rtype = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let rdlen = u16::from_be_bytes([buf[i + 8], buf[i + 9]]) as usize;
        i += 10;
        if i + rdlen > buf.len() {
            return out;
        }
        match (rtype, rdlen) {
            (1, 4) => out.push(IpAddr::V4(Ipv4Addr::new(
                buf[i],
                buf[i + 1],
                buf[i + 2],
                buf[i + 3],
            ))),
            (28, 16) => {
                let mut o = [0u8; 16];
                o.copy_from_slice(&buf[i..i + 16]);
                out.push(IpAddr::V6(Ipv6Addr::from(o)));
            }
            _ => {}
        }
        i += rdlen;
    }
    out
}

/// Drop listed addresses from the answer section when the packet shape is simple
/// (no authority, optional trailing OPT). Returns None if the edit is unsafe.
pub fn without_addrs(reply: &[u8], drop: &[IpAddr]) -> Option<Vec<u8>> {
    if reply.len() < 12 || drop.is_empty() {
        return None;
    }
    let questions = u16::from_be_bytes([reply[4], reply[5]]) as usize;
    let answers = u16::from_be_bytes([reply[6], reply[7]]) as usize;
    let authority = u16::from_be_bytes([reply[8], reply[9]]) as usize;
    let additional = u16::from_be_bytes([reply[10], reply[11]]) as usize;
    if questions != 1 || authority != 0 || additional > 1 || answers == 0 {
        return None;
    }

    let mut i = 12;
    for _ in 0..questions {
        i = skip_name_opt(reply, i)? + 4;
    }
    let question_end = i;
    if question_end > reply.len() || question_name(reply).is_none() {
        return None;
    }

    let mut kept: Vec<(usize, usize)> = Vec::new();
    let mut removed = 0usize;
    for _ in 0..answers {
        let start = i;
        // Deleting a record moves all following bytes. Only pointers into the
        // unchanged question can survive that move; CNAME RDATA needs rewriting.
        let mut name_pos = i;
        loop {
            let length = *reply.get(name_pos)? as usize;
            if length == 0 {
                break;
            }
            if length & 0xc0 == 0xc0 {
                let target = ((length & 0x3f) << 8) | *reply.get(name_pos + 1)? as usize;
                if target < 12 || target >= question_end - 4 {
                    return None;
                }
                break;
            }
            if length > 63 {
                return None;
            }
            name_pos = name_pos.checked_add(length + 1)?;
        }
        let after_name = skip_name_opt(reply, i)?;
        if after_name + 10 > reply.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([reply[after_name], reply[after_name + 1]]);
        let rdlen = u16::from_be_bytes([reply[after_name + 8], reply[after_name + 9]]) as usize;
        let rdata = after_name + 10;
        let end = rdata.checked_add(rdlen)?;
        if end > reply.len() {
            return None;
        }
        let addr = match (rtype, rdlen) {
            (1, 4) => Some(IpAddr::V4(Ipv4Addr::new(
                reply[rdata],
                reply[rdata + 1],
                reply[rdata + 2],
                reply[rdata + 3],
            ))),
            (28, 16) => {
                let mut o = [0u8; 16];
                o.copy_from_slice(&reply[rdata..rdata + 16]);
                Some(IpAddr::V6(Ipv6Addr::from(o)))
            }
            _ => return None,
        };
        if addr.is_some_and(|a| drop.contains(&a)) {
            removed += 1;
        } else {
            kept.push((start, end));
        }
        i = end;
    }
    if removed == 0 || kept.is_empty() {
        return None;
    }
    let tail = &reply[i..];
    if additional == 1
        && (tail.len() < 11
            || tail[..3] != [0, 0, 41]
            || tail.len() != 11 + u16::from_be_bytes([tail[9], tail[10]]) as usize)
    {
        return None;
    }
    if additional == 0 && !tail.is_empty() {
        return None;
    }

    let mut out = Vec::with_capacity(reply.len());
    out.extend_from_slice(&reply[..12]);
    let count = (answers - removed) as u16;
    out[6..8].copy_from_slice(&count.to_be_bytes());
    out.extend_from_slice(&reply[12..question_end]);
    for (start, end) in kept {
        out.extend_from_slice(&reply[start..end]);
    }
    out.extend_from_slice(tail);
    Some(out)
}

pub fn question_name(buf: &[u8]) -> Option<String> {
    if buf.len() < 12 {
        return None;
    }
    let mut pos = 12;
    let mut labels = Vec::new();
    let mut hops = 0;
    while pos < buf.len() && hops < 64 {
        hops += 1;
        let len = buf[pos] as usize;
        if len == 0 {
            break;
        }
        if (len & 0xC0) == 0xC0 {
            return None;
        }
        pos += 1;
        if pos + len > buf.len() {
            return None;
        }
        let s = std::str::from_utf8(&buf[pos..pos + len]).ok()?;
        labels.push(s);
        pos += len;
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

/// DNS question type (A=1, AAAA=28, ...) from a standard query packet.
pub fn question_type(buf: &[u8]) -> Option<u16> {
    if buf.len() < 12 {
        return None;
    }
    let mut pos = 12;
    pos = skip_name(buf, pos);
    if pos + 4 > buf.len() {
        return None;
    }
    Some(u16::from_be_bytes([buf[pos], buf[pos + 1]]))
}

/// NODATA response for AAAA: keep clients from falling back to IPv6.
pub fn nodata_response(query: &[u8]) -> Vec<u8> {
    let mut resp = query.to_vec();
    if resp.len() < 12 {
        resp.resize(12, 0);
    }
    // QR=1, RD copied, RA=1, RCODE=0, ANCOUNT=0
    resp[2] = (resp[2] & 0x01) | 0x80;
    resp[3] = 0x80;
    resp[6] = 0;
    resp[7] = 0;
    resp[8] = 0;
    resp[9] = 0;
    resp[10] = 0;
    resp[11] = 0;
    // Counts above discard OPT/other records, so discard their bytes as well.
    if let Some(end) = skip_name_opt(query, 12).and_then(|n| n.checked_add(4)) {
        if end <= resp.len() {
            resp.truncate(end);
        }
    }
    resp
}

pub fn servfail_response(query: &[u8]) -> Vec<u8> {
    let mut reply = nodata_response(query);
    reply[3] |= 2;
    reply
}

pub fn is_successful_response(buf: &[u8]) -> bool {
    if buf.len() < 12 {
        return false;
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    (flags & 0x8000) != 0 && (flags & 0x000F) == 0
}

pub fn response_matches(query: &[u8], reply: &[u8]) -> bool {
    query.len() >= 12
        && reply.len() >= 12
        && query[..2] == reply[..2]
        && reply[2] & 0x80 != 0
        && reply[2] & 0x02 == 0
        && query[4..6] == [0, 1]
        && reply[4..6] == [0, 1]
        && question_name(query)
            .zip(question_name(reply))
            .is_some_and(|(a, b)| a.eq_ignore_ascii_case(&b))
        && question_type(query).is_some()
        && question_type(query) == question_type(reply)
        && age_ttls(reply, 0, u32::MAX).is_some()
}

/// Cache hits never renew a DNS record's original lifetime. OPT is not a TTL.
pub fn age_ttls(packet: &[u8], age_secs: u32, cap_secs: u32) -> Option<Vec<u8>> {
    rewrite_ttls(packet, age_secs, cap_secs, false)
}

fn rewrite_ttls(
    packet: &[u8],
    age_secs: u32,
    cap_secs: u32,
    reject_expired: bool,
) -> Option<Vec<u8>> {
    if packet.len() < 12 {
        return None;
    }
    let mut out = packet.to_vec();
    let mut pos = 12;
    for _ in 0..u16::from_be_bytes([out[4], out[5]]) {
        pos = skip_name_opt(&out, pos)?.checked_add(4)?;
    }
    let count: usize = [6, 8, 10]
        .iter()
        .map(|i| u16::from_be_bytes([out[*i], out[*i + 1]]) as usize)
        .sum();
    for _ in 0..count {
        pos = skip_name_opt(&out, pos)?;
        if pos + 10 > out.len() {
            return None;
        }
        let kind = u16::from_be_bytes([out[pos], out[pos + 1]]);
        if kind != 41 {
            let ttl = u32::from_be_bytes(out[pos + 4..pos + 8].try_into().ok()?);
            if reject_expired && ttl <= age_secs {
                return None;
            }
            let ttl = ttl.saturating_sub(age_secs).min(cap_secs);
            out[pos + 4..pos + 8].copy_from_slice(&ttl.to_be_bytes());
        }
        pos += 10 + u16::from_be_bytes([out[pos + 8], out[pos + 9]]) as usize;
        if pos > out.len() {
            return None;
        }
    }
    Some(out)
}

pub fn query_raw_via(
    packet: &[u8],
    server: std::net::Ipv4Addr,
    if_index: u32,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    query_raw_to(packet, SocketAddrV4::new(server, 53), if_index, timeout)
}

pub fn query_raw_to(
    packet: &[u8],
    target: SocketAddrV4,
    if_index: u32,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("Bind error: {}", e))?;
    if if_index > 0 {
        bind_socket_to_interface(&sock, if_index)?;
    }
    let _ = sock.set_read_timeout(Some(timeout));
    let _ = sock.set_write_timeout(Some(timeout));

    sock.send_to(packet, target)
        .map_err(|e| format!("Send error: {}", e))?;

    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 1500];
    loop {
        let left = deadline
            .checked_duration_since(Instant::now())
            .ok_or("DNS: timeout")?;
        sock.set_read_timeout(Some(left))
            .map_err(|e| e.to_string())?;
        let (n, from) = sock
            .recv_from(&mut buf)
            .map_err(|e| format!("Recv error from {}: {}", target, e))?;
        if from == std::net::SocketAddr::V4(target) && response_matches(packet, &buf[..n]) {
            return Ok(buf[..n].to_vec());
        }
        if Instant::now() >= deadline {
            return Err(format!("Recv error from {}: timeout", target));
        }
    }
}

#[cfg(test)]
mod readiness_transport_tests {
    use super::*;
    #[test]
    fn loopback_readiness_uses_its_own_port_and_validates_the_reply() {
        let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
        listener
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let std::net::SocketAddr::V4(target) = listener.local_addr().unwrap() else {
            panic!()
        };
        let worker = std::thread::spawn(move || {
            let mut bytes = [0u8; 512];
            let (n, peer) = listener.recv_from(&mut bytes).unwrap();
            let reply = address_response(&bytes[..n], &[Ipv4Addr::LOCALHOST]).unwrap();
            listener.send_to(&reply, peer).unwrap();
        });
        let query = build_query(crate::net::relay::HEALTH_NAME, 321);
        let reply = query_raw_to(&query, target, 0, Duration::from_secs(1)).unwrap();
        worker.join().unwrap();
        assert_eq!(
            answer_addrs(&reply),
            vec![std::net::IpAddr::V4(Ipv4Addr::LOCALHOST)]
        );
    }
}

/// Build a plain A answer for a ranked SNI route. No upstream compression or
/// DNSSEC assertions are copied into this locally constructed response.
pub fn address_response(query: &[u8], addresses: &[Ipv4Addr]) -> Option<Vec<u8>> {
    if query.len() < 12
        || query[4..6] != [0, 1]
        || question_type(query) != Some(1)
        || addresses.is_empty()
        || addresses.len() > 32
        || question_name(query).is_none()
    {
        return None;
    }
    let end = skip_name_opt(query, 12)?.checked_add(4)?;
    if query.get(end - 2..end)? != [0, 1] {
        return None;
    }
    let mut reply = query.get(..end)?.to_vec();
    reply[2] = 0x80 | (query[2] & 1);
    reply[3] = 0x80;
    reply[6..8].copy_from_slice(&(addresses.len() as u16).to_be_bytes());
    reply[8..12].fill(0);
    for ip in addresses {
        reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 20, 0, 4]);
        reply.extend_from_slice(&ip.octets());
    }
    Some(reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cached_packets_age_ttls_expire_and_preserve_edns_flags() {
        let query = build_query("example.test", 12);
        let mut reply = address_response(&query, &[Ipv4Addr::LOCALHOST]).unwrap();
        reply[11] = 1;
        reply.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 0]);
        let ttl = query.len() + 6;
        let aged = aged_reply(&reply, 7).unwrap();
        assert_eq!(
            u32::from_be_bytes(aged[ttl..ttl + 4].try_into().unwrap()),
            13
        );
        assert_eq!(&aged[aged.len() - 11..], &reply[reply.len() - 11..]);
        assert!(aged_reply(&reply, 20).is_none());
        assert!(aged_reply(&reply[..reply.len() - 1], 0).is_none());
        reply[ttl..ttl + 4].fill(0);
        assert!(aged_reply(&reply, 0).is_none());
    }
    #[test]
    fn negative_responses_preserve_question_and_discard_edns_without_waiting_for_timeout() {
        let query = build_query("cloudcode-pa.googleapis.com", 0x1234);
        let mut edns = query.clone();
        edns[11] = 1;
        edns.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
        let failed = servfail_response(&edns);
        assert!(response_matches(&query, &failed));
        assert_eq!(failed[3] & 15, 2);
        assert_eq!(failed.len(), query.len());
        assert!(answer_addrs(&failed).is_empty());
        let empty = nodata_response(&edns);
        assert!(response_matches(&query, &empty));
        assert!(is_successful_response(&empty));
        assert_eq!(empty.len(), query.len());
    }
    fn answer() -> Vec<u8> {
        let mut reply = nodata_response(&build_query("example.test", 5));
        reply[7] = 1;
        reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 1]);
        reply
    }
    #[test]
    fn dns_cache_ages_ttl_and_rejects_truncated_records_and_wrong_question() {
        let reply = answer();
        let aged = age_ttls(&reply, 11, 20).unwrap();
        let ttl_at = aged.len() - 10;
        assert_eq!(
            u32::from_be_bytes(aged[ttl_at..ttl_at + 4].try_into().unwrap()),
            19
        );
        assert!(age_ttls(&reply[..reply.len() - 1], 0, 20).is_none());
        assert!(response_matches(&build_query("example.test", 5), &reply));
        assert!(!response_matches(&build_query("different.test", 5), &reply));
        let mut truncated = reply;
        truncated[2] |= 2;
        assert!(!response_matches(
            &build_query("example.test", 5),
            &truncated
        ));
    }
    #[test]
    fn filtering_never_moves_compression_targets_and_ranked_answers_have_no_stale_sections() {
        let query = build_query("example.test", 5);
        let a: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let b: Ipv4Addr = "127.0.0.2".parse().unwrap();
        let reply = address_response(&query, &[a, b]).unwrap();
        assert!(response_matches(&query, &reply));
        let filtered = without_addrs(&reply, &[a.into()]).unwrap();
        assert_eq!(answer_addrs(&filtered), vec![IpAddr::V4(b)]);
        assert!(response_matches(&query, &filtered));
        let mut moved_pointer = reply;
        let second = query.len() + 16;
        moved_pointer[second + 1] = query.len() as u8;
        assert!(without_addrs(&moved_pointer, &[a.into()]).is_none());
        let mut cname = answer();
        cname[query.len() + 3] = 5;
        assert!(without_addrs(&cname, &[a.into()]).is_none());
    }
}
