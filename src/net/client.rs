#![allow(dead_code)]

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::Duration;
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
pub fn parse_a_records(buf: &[u8], expect_id: u16) -> Vec<Ipv4Addr> {
    if buf.len() < 12 {
        return Vec::new();
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    if id != expect_id {
        return Vec::new();
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if (flags & 0x8000) == 0 || (flags & 0x000F) != 0 {
        return Vec::new();
    }

    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(buf, pos);
        if pos + 4 > buf.len() {
            return Vec::new();
        }
        pos += 4;
    }

    let mut addrs = Vec::new();
    for _ in 0..ancount {
        if pos >= buf.len() {
            break;
        }
        pos = skip_name(buf, pos);
        if pos + 10 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlen > buf.len() {
            break;
        }
        if rtype == 1 && rclass == 1 && rdlen == 4 {
            let ip = Ipv4Addr::new(buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]);
            if !ip.is_unspecified() && !addrs.contains(&ip) {
                addrs.push(ip);
            }
        }
        pos += rdlen;
    }
    addrs
}

#[inline]
fn skip_name(buf: &[u8], mut pos: usize) -> usize {
    let mut hops = 0;
    while pos < buf.len() && hops < 64 {
        hops += 1;
        let len = buf[pos] as usize;
        if len == 0 {
            return pos + 1;
        }
        if (len & 0xC0) == 0xC0 {
            return pos + 2;
        }
        pos += 1 + len;
    }
    pos.min(buf.len())
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

pub fn query_raw_via(
    packet: &[u8],
    server: Ipv4Addr,
    _if_index: u32,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("Bind error: {}", e))?;
    let _ = sock.set_read_timeout(Some(timeout));
    let _ = sock.set_write_timeout(Some(timeout));

    let target = SocketAddrV4::new(server, 53);
    sock.send_to(packet, target)
        .map_err(|e| format!("Send error: {}", e))?;

    let mut buf = [0u8; 1500];
    let (n, _) = sock
        .recv_from(&mut buf)
        .map_err(|e| format!("Recv error from {}: {}", server, e))?;
    Ok(buf[..n].to_vec())
}

pub fn resolve_a_via(host: &str, server: Ipv4Addr, if_index: u32) -> Result<Vec<Ipv4Addr>, String> {
    let id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        & 0xFFFF) as u16;

    let pkt = build_query(host, id);
    let resp = query_raw_via(&pkt, server, if_index, Duration::from_millis(1500))?;
    let addrs = parse_a_records(&resp, id);
    if addrs.is_empty() {
        Err("No A records".to_string())
    } else {
        Ok(addrs)
    }
}
