use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};
use crate::net::socket::bind_socket_to_interface;

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
            return if pos + 1 < buf.len() { Some(pos + 2) } else { None };
        }
        pos += 1 + len;
    }
    None
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
            (1, 4) => out.push(IpAddr::V4(Ipv4Addr::new(buf[i], buf[i + 1], buf[i + 2], buf[i + 3]))),
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
    if authority != 0 || additional > 1 || answers == 0 {
        return None;
    }

    let mut i = 12;
    for _ in 0..questions {
        i = skip_name_opt(reply, i)? + 4;
    }
    let question_end = i;

    let mut kept: Vec<(usize, usize)> = Vec::new();
    let mut removed = 0usize;
    for _ in 0..answers {
        let start = i;
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
            _ => None,
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
    if additional == 1 && (tail.len() < 11 || tail[0] != 0) {
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
    resp
}

pub fn is_successful_response(buf: &[u8]) -> bool {
    if buf.len() < 12 {
        return false;
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    (flags & 0x8000) != 0 && (flags & 0x000F) == 0
}

pub fn query_raw_via(
    packet: &[u8],
    server: std::net::Ipv4Addr,
    if_index: u32,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("Bind error: {}", e))?;
    if if_index > 0 {
        let _ = bind_socket_to_interface(&sock, if_index);
    }
    let _ = sock.set_read_timeout(Some(timeout));
    let _ = sock.set_write_timeout(Some(timeout));

    let target = SocketAddrV4::new(server, 53);
    sock.send_to(packet, target)
        .map_err(|e| format!("Send error: {}", e))?;

    let want_id = packet.get(0..2).map(|b| [b[0], b[1]]);
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 1500];
    loop {
        let (n, from) = sock
            .recv_from(&mut buf)
            .map_err(|e| format!("Recv error from {}: {}", server, e))?;
        let right_source = from.ip() == IpAddr::V4(server);
        let right_id = match (want_id, n >= 12) {
            (Some(id), true) => buf[0..2] == id,
            _ => false,
        };
        if right_source && right_id {
            return Ok(buf[..n].to_vec());
        }
        if Instant::now() >= deadline {
            return Err(format!("Recv error from {}: timeout", server));
        }
    }
}
