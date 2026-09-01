use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::net::client::{
    answer_addrs, build_query, is_successful_response, query_raw_via, question_name, question_type,
    without_addrs,
};

/// SmartDNS that *substitutes* Google AI names with their SNI-proxy IPs.
/// A passthrough (real Google anycast) is a failure for the region gate.
pub struct Provider {
    pub name: &'static str,
    pub v4: &'static [&'static str],
}

pub const PROVIDERS: &[Provider] = &[
    Provider {
        name: "xbox-dns.ru",
        v4: &["111.88.96.50", "111.88.96.51"],
    },
    Provider {
        name: "comss.one",
        v4: &["83.220.169.155", "212.109.195.93", "195.133.25.16"],
    },
    Provider {
        name: "geohide.ru",
        v4: &["45.155.204.190", "37.230.192.51"],
    },
];

const REFERENCE_V4: &[&str] = &["8.8.8.8", "1.1.1.1"];
const REFERENCE_STUBS: [Ipv4Addr; 2] = [Ipv4Addr::new(8, 6, 112, 0), Ipv4Addr::new(8, 47, 69, 0)];

const CONTROL_NAMES: &[&str] = &[
    "chatgpt.com",
    "api.openai.com",
    "claude.ai",
    "gemini.google.com",
    "ai.google.dev",
];

const CHOICE_TTL: Duration = Duration::from_secs(30);
const PROXY_SET_TTL: Duration = Duration::from_secs(30 * 60);
const RACE_BUDGET: Duration = Duration::from_millis(700);
const QUERY_TIMEOUT: Duration = Duration::from_millis(800);
const LIVENESS_PORT: u16 = 443;
const LIVENESS_BUDGET: Duration = Duration::from_millis(250);
const TLS_PROBE_BUDGET: Duration = Duration::from_millis(1500);
const LIVENESS_TTL_ALIVE: Duration = Duration::from_secs(10 * 60);
const LIVENESS_TTL_DEAD: Duration = Duration::from_secs(60);

static PROXY_SET: Mutex<Option<(HashMap<usize, Vec<IpAddr>>, Instant)>> = Mutex::new(None);
static LIVENESS: Mutex<Option<HashMap<IpAddr, (bool, Instant)>>> = Mutex::new(None);
static CHOICE: Mutex<Option<HashMap<(String, u16), (usize, Verdict, Instant)>>> = Mutex::new(None);
const DNS_PACKET_CACHE_TTL: Duration = Duration::from_secs(300);
static DNS_PACKET_CACHE: Mutex<Option<HashMap<(String, u16), (Vec<u8>, &'static str, Verdict, Instant)>>> = Mutex::new(None);
static ROTATION: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Substituted,
    Sibling,
    Passthrough,
    Unknown,
}

pub struct ResolveHit {
    pub reply: Vec<u8>,
    pub provider: &'static str,
    pub verdict: Verdict,
}

pub fn all_provider_v4() -> Vec<&'static str> {
    PROVIDERS.iter().flat_map(|p| p.v4.iter().copied()).collect()
}

pub fn fallback_v4() -> Vec<&'static str> {
    PROVIDERS.iter().filter_map(|p| p.v4.first().copied()).collect()
}

fn parse_v4(s: &str) -> Option<Ipv4Addr> {
    s.parse().ok()
}

fn netblock(addr: &IpAddr) -> (u8, u32) {
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            (4, u32::from_be_bytes([o[0], o[1], 0, 0]))
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            (6, u32::from_be_bytes([o[0], o[1], o[2], o[3]]))
        }
    }
}

pub fn classify(candidate: &[IpAddr], reference: &[IpAddr], proxy: &[IpAddr]) -> Verdict {
    if candidate.is_empty() {
        return Verdict::Unknown;
    }
    let reference: Vec<&IpAddr> = reference
        .iter()
        .filter(|a| match a {
            IpAddr::V4(v4) => !REFERENCE_STUBS.contains(v4),
            IpAddr::V6(_) => true,
        })
        .collect();
    if reference.is_empty() {
        return Verdict::Unknown;
    }

    let fam: Vec<u8> = candidate.iter().map(|a| netblock(a).0).collect();
    let comparable: Vec<&&IpAddr> = reference
        .iter()
        .filter(|a| fam.contains(&netblock(a).0))
        .collect();
    if comparable.is_empty() {
        return Verdict::Unknown;
    }

    let ref_blocks: Vec<(u8, u32)> = comparable.iter().map(|a| netblock(a)).collect();
    if candidate.iter().any(|a| ref_blocks.contains(&netblock(a))) {
        return Verdict::Passthrough;
    }
    if !proxy.is_empty() && candidate.iter().any(|a| proxy.contains(a)) {
        return Verdict::Substituted;
    }
    if proxy.is_empty() {
        return Verdict::Substituted;
    }
    Verdict::Sibling
}

fn query_a(name: &str, server: Ipv4Addr, if_index: u32, timeout: Duration) -> Option<Vec<u8>> {
    let id = (Instant::now().elapsed().as_nanos() as u16).wrapping_add(server.octets()[3] as u16);
    let pkt = build_query(name, id);
    match query_raw_via(&pkt, server, if_index, timeout) {
        Ok(resp) if is_successful_response(&resp) => Some(resp),
        _ => None,
    }
}

pub fn warmup(if_index: u32) {
    thread::spawn(move || {
        let _ = learn_proxy_addrs(if_index);
    });
}

fn cached_proxy() -> HashMap<usize, Vec<IpAddr>> {
    if let Ok(guard) = PROXY_SET.lock() {
        if let Some((map, at)) = guard.as_ref() {
            if at.elapsed() < PROXY_SET_TTL {
                return map.clone();
            }
        }
    }
    HashMap::new()
}

fn learn_proxy_addrs(if_index: u32) -> HashMap<usize, Vec<IpAddr>> {
    if let Ok(guard) = PROXY_SET.lock() {
        if let Some((map, at)) = guard.as_ref() {
            if at.elapsed() < PROXY_SET_TTL {
                return map.clone();
            }
        }
    }

    let reference = reference_addrs("gemini.google.com", if_index);
    let mut map: HashMap<usize, Vec<IpAddr>> = HashMap::new();

    for (idx, provider) in PROVIDERS.iter().enumerate() {
        let mut learned = Vec::new();
        let Some(server) = parse_v4(provider.v4[0]) else {
            continue;
        };
        for name in CONTROL_NAMES {
            if let Some(resp) = query_a(name, server, if_index, QUERY_TIMEOUT) {
                let addrs = answer_addrs(&resp);
                let v = classify(&addrs, &reference, &[]);
                if v == Verdict::Substituted {
                    for a in addrs {
                        if !learned.contains(&a) {
                            learned.push(a);
                        }
                    }
                }
            }
        }
        map.insert(idx, learned);
    }

    if let Ok(mut guard) = PROXY_SET.lock() {
        *guard = Some((map.clone(), Instant::now()));
    }
    map
}

fn reference_addrs(name: &str, if_index: u32) -> Vec<IpAddr> {
    for ns in REFERENCE_V4 {
        if let Ok(ip) = ns.parse::<Ipv4Addr>() {
            if let Some(resp) = query_a(name, ip, 0, QUERY_TIMEOUT) {
                let addrs: Vec<IpAddr> = answer_addrs(&resp)
                    .into_iter()
                    .filter(|a| match a {
                        IpAddr::V4(v4) => !REFERENCE_STUBS.contains(v4),
                        _ => true,
                    })
                    .collect();
                if !addrs.is_empty() {
                    return addrs;
                }
            }
        }
    }
    let _ = if_index;
    Vec::new()
}

/// TLS-ok IPv4s, fastest first. TCP-open is not enough: a proxy can accept
/// SYN and still RST or stall the handshake.
pub fn rank_tls_v4(addrs: &[IpAddr], sni: &str) -> Vec<(Ipv4Addr, u128)> {
    let candidates: Vec<IpAddr> = addrs.iter().copied().filter(|a| a.is_ipv4()).collect();
    if candidates.is_empty() {
        return Vec::new();
    }
    let (tx, rx) = mpsc::channel();
    for addr in candidates {
        let sni = sni.to_string();
        let tx = tx.clone();
        thread::spawn(move || {
            let _ = tx.send((addr, tls_handshake_ms(addr, &sni)));
        });
    }
    drop(tx);
    let mut out = Vec::new();
    while let Ok((addr, ms)) = rx.recv() {
        let Some(ms) = ms else {
            continue;
        };
        let IpAddr::V4(v4) = addr else {
            continue;
        };
        out.push((v4, ms));
    }
    out.sort_by_key(|(_, ms)| *ms);
    out
}

fn tls_handshake_ms(addr: IpAddr, sni: &str) -> Option<u128> {
    let start = Instant::now();
    let mut stream = TcpStream::connect_timeout(&SocketAddr::new(addr, LIVENESS_PORT), TLS_PROBE_BUDGET).ok()?;
    let left = TLS_PROBE_BUDGET.saturating_sub(start.elapsed());
    if left.is_zero() {
        return None;
    }
    crate::net::socket::configure_tcp_stream(&stream).ok()?;
    stream.set_read_timeout(Some(left)).ok()?;
    stream.set_write_timeout(Some(left)).ok()?;
    stream.write_all(&tls_client_hello(sni)).ok()?;
    let mut hdr = [0u8; 5];
    stream.read_exact(&mut hdr).ok()?;
    // Handshake (0x16) or alert (0x15) means a TLS speaker, not a SYN blackhole.
    if hdr[0] != 0x16 && hdr[0] != 0x15 {
        return None;
    }
    Some(start.elapsed().as_millis().max(1))
}

fn tls_client_hello(sni: &str) -> Vec<u8> {
    let host = sni.as_bytes();
    let mut ext = Vec::new();

    let mut sni_name = Vec::new();
    sni_name.push(0x00);
    sni_name.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni_name.extend_from_slice(host);
    let mut sni_list = Vec::new();
    sni_list.extend_from_slice(&(sni_name.len() as u16).to_be_bytes());
    sni_list.extend(sni_name);
    ext.extend_from_slice(&0x0000u16.to_be_bytes());
    ext.extend_from_slice(&(sni_list.len() as u16).to_be_bytes());
    ext.extend(sni_list);

    let groups: &[u8] = &[0x00, 0x04, 0x00, 0x1d, 0x00, 0x17];
    ext.extend_from_slice(&0x000au16.to_be_bytes());
    ext.extend_from_slice(&(groups.len() as u16).to_be_bytes());
    ext.extend_from_slice(groups);

    let epf: &[u8] = &[0x01, 0x00];
    ext.extend_from_slice(&0x000bu16.to_be_bytes());
    ext.extend_from_slice(&(epf.len() as u16).to_be_bytes());
    ext.extend_from_slice(epf);

    let sig: &[u8] = &[0x00, 0x08, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x01];
    ext.extend_from_slice(&0x000du16.to_be_bytes());
    ext.extend_from_slice(&(sig.len() as u16).to_be_bytes());
    ext.extend_from_slice(sig);

    let mut ch = Vec::new();
    ch.extend_from_slice(&[0x03, 0x03]);
    ch.extend_from_slice(&[0u8; 32]);
    ch.push(0);
    ch.extend_from_slice(&[
        0x00, 0x0c, 0x13, 0x01, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x13, 0x00, 0x9c, 0x00, 0x2f,
    ]);
    ch.push(0x01);
    ch.push(0x00);
    ch.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    ch.extend(ext);

    let mut hs = Vec::new();
    hs.push(0x01);
    let n = ch.len();
    hs.push(((n >> 16) & 0xff) as u8);
    hs.push(((n >> 8) & 0xff) as u8);
    hs.push((n & 0xff) as u8);
    hs.extend(ch);

    let mut rec = Vec::new();
    rec.push(0x16);
    rec.extend_from_slice(&[0x03, 0x01]);
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend(hs);
    rec
}

fn is_alive(addr: IpAddr) -> bool {
    if let Ok(guard) = LIVENESS.lock() {
        if let Some(map) = guard.as_ref() {
            if let Some((ok, at)) = map.get(&addr) {
                let ttl = if *ok {
                    LIVENESS_TTL_ALIVE
                } else {
                    LIVENESS_TTL_DEAD
                };
                if at.elapsed() < ttl {
                    return *ok;
                }
            }
        }
    }

    let sock = SocketAddr::new(addr, LIVENESS_PORT);
    let ok = TcpStream::connect_timeout(&sock, LIVENESS_BUDGET).is_ok();
    if let Ok(mut guard) = LIVENESS.lock() {
        let map = guard.get_or_insert_with(HashMap::new);
        map.insert(addr, (ok, Instant::now()));
    }
    ok
}

fn drop_dead(reply: &[u8]) -> Vec<u8> {
    let addrs = answer_addrs(reply);
    if addrs.is_empty() {
        return reply.to_vec();
    }
    let dead = probe_dead(&addrs);
    if dead.is_empty() || dead.len() == addrs.len() {
        return reply.to_vec();
    }
    without_addrs(reply, &dead).unwrap_or_else(|| reply.to_vec())
}

fn probe_dead(addrs: &[IpAddr]) -> Vec<IpAddr> {
    if addrs.len() == 1 {
        return if is_alive(addrs[0]) {
            Vec::new()
        } else {
            vec![addrs[0]]
        };
    }
    let (tx, rx) = mpsc::channel();
    for addr in addrs {
        let addr = *addr;
        let tx = tx.clone();
        thread::spawn(move || {
            let _ = tx.send((addr, is_alive(addr)));
        });
    }
    drop(tx);
    let mut dead = Vec::new();
    while let Ok((addr, ok)) = rx.recv() {
        if !ok {
            dead.push(addr);
        }
    }
    dead
}

struct RaceResult {
    idx: usize,
    reply: Vec<u8>,
    addrs: Vec<IpAddr>,
}

enum RaceMsg {
    Provider(RaceResult),
    Reference(Vec<IpAddr>),
}

fn race_providers(query: &[u8], if_index: u32) -> (Vec<RaceResult>, Vec<IpAddr>) {
    let (tx, rx) = mpsc::channel();
    for (idx, provider) in PROVIDERS.iter().enumerate() {
        let q = query.to_vec();
        let tx = tx.clone();
        thread::spawn(move || {
            for s in provider.v4 {
                let Ok(ip) = s.parse::<Ipv4Addr>() else { continue };
                if let Ok(resp) = query_raw_via(&q, ip, if_index, QUERY_TIMEOUT) {
                    if is_successful_response(&resp) && !answer_addrs(&resp).is_empty() {
                        let addrs = answer_addrs(&resp);
                        let _ = tx.send(RaceMsg::Provider(RaceResult {
                            idx,
                            reply: resp,
                            addrs,
                        }));
                        return;
                    }
                }
            }
        });
    }
    for ns in REFERENCE_V4 {
        let q = query.to_vec();
        let tx = tx.clone();
        let Ok(ip) = ns.parse::<Ipv4Addr>() else { continue };
        thread::spawn(move || {
            if let Ok(resp) = query_raw_via(&q, ip, 0, QUERY_TIMEOUT) {
                let addrs: Vec<IpAddr> = answer_addrs(&resp)
                    .into_iter()
                    .filter(|a| match a {
                        IpAddr::V4(v4) => !REFERENCE_STUBS.contains(v4),
                        _ => true,
                    })
                    .collect();
                if !addrs.is_empty() {
                    let _ = tx.send(RaceMsg::Reference(addrs));
                }
            }
        });
    }
    drop(tx);

    let deadline = Instant::now() + RACE_BUDGET;
    let mut out = Vec::new();
    let mut reference = Vec::new();
    while Instant::now() < deadline {
        let remain = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remain) {
            Ok(RaceMsg::Provider(hit)) => {
                let has_addrs = !hit.addrs.is_empty();
                out.push(hit);
                // Early exit: as soon as we receive at least 1 provider with answers and reference (or 2 answers)
                if has_addrs && (!reference.is_empty() || out.len() >= 2) {
                    break;
                }
            }
            Ok(RaceMsg::Reference(addrs)) => {
                if reference.is_empty() {
                    reference = addrs;
                }
                if !out.is_empty() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    (out, reference)
}

pub(crate) fn looks_google(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            matches!(
                (o[0], o[1]),
                (64, 233)
                    | (66, 102)
                    | (66, 249)
                    | (72, 14)
                    | (74, 125)
                    | (142, 250)
                    | (142, 251)
                    | (172, 217)
                    | (173, 194)
                    | (192, 178)
                    | (216, 58)
                    | (216, 239)
            )
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            o[0] == 0x20 && o[1] == 0x01 && o[2] == 0x48 && o[3] == 0x60
        }
    }
}

fn pick_winner(hits: &[RaceResult], reference: &[IpAddr], if_index: u32) -> Option<usize> {
    if hits.is_empty() {
        return None;
    }
    let proxy = cached_proxy();
    let rot = ROTATION.fetch_add(1, Ordering::Relaxed);
    let mut best_sub: Vec<usize> = Vec::new();
    let mut rest: Vec<usize> = Vec::new();
    for (i, hit) in hits.iter().enumerate() {
        let proxy_addrs = proxy.get(&hit.idx).cloned().unwrap_or_default();
        if classify(&hit.addrs, reference, &proxy_addrs) == Verdict::Substituted
            || (reference.is_empty() && hit.addrs.iter().any(|a| !looks_google(a)))
        {
            best_sub.push(i);
        } else {
            rest.push(i);
        }
    }
    let pool = if !best_sub.is_empty() {
        best_sub
    } else {
        rest
    };
    let _ = if_index;
    if pool.is_empty() {
        return Some(rot % hits.len());
    }
    Some(pool[rot % pool.len()])
}

pub fn resolve_best(query: &[u8], if_index: u32) -> Option<ResolveHit> {
    let name = question_name(query).unwrap_or_else(|| "?".into());
    let qtype = question_type(query).unwrap_or(1);

    // 1. High-speed in-memory DNS packet cache (0.01ms response from RAM)
    if let Ok(guard) = DNS_PACKET_CACHE.lock() {
        if let Some(map) = guard.as_ref() {
            if let Some((cached_reply, provider, verdict, at)) = map.get(&(name.clone(), qtype)) {
                if at.elapsed() < DNS_PACKET_CACHE_TTL {
                    let mut fast_reply = cached_reply.clone();
                    if query.len() >= 2 && fast_reply.len() >= 2 {
                        // Stamp incoming query's Transaction ID
                        fast_reply[0] = query[0];
                        fast_reply[1] = query[1];
                    }
                    return Some(ResolveHit {
                        reply: fast_reply,
                        provider,
                        verdict: *verdict,
                    });
                }
            }
        }
    }

    if let Ok(guard) = CHOICE.lock() {
        if let Some(map) = guard.as_ref() {
            if let Some((idx, verdict, at)) = map.get(&(name.clone(), qtype)) {
                if at.elapsed() < CHOICE_TTL {
                    for s in PROVIDERS[*idx].v4 {
                        let Some(ip) = parse_v4(s) else { continue };
                        if let Ok(resp) = query_raw_via(query, ip, if_index, QUERY_TIMEOUT) {
                            if is_successful_response(&resp) && !answer_addrs(&resp).is_empty() {
                                let reply = drop_dead(&resp);
                                let provider = PROVIDERS[*idx].name;
                                if let Ok(mut cguard) = DNS_PACKET_CACHE.lock() {
                                    let cmap = cguard.get_or_insert_with(HashMap::new);
                                    cmap.insert((name.clone(), qtype), (reply.clone(), provider, *verdict, Instant::now()));
                                }
                                return Some(ResolveHit {
                                    reply,
                                    provider,
                                    verdict: *verdict,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    let (hits, reference) = race_providers(query, if_index);
    if let Some(win) = pick_winner(&hits, &reference, if_index) {
        let hit = &hits[win];
        let proxy = cached_proxy();
        let proxy_addrs = proxy.get(&hit.idx).cloned().unwrap_or_default();
        let verdict = classify(&hit.addrs, &reference, &proxy_addrs);
        let final_reply = drop_dead(&hit.reply);
        let provider = PROVIDERS[hit.idx].name;

        // Populate in-memory packet cache
        if is_successful_response(&final_reply) && !answer_addrs(&final_reply).is_empty() {
            if let Ok(mut cguard) = DNS_PACKET_CACHE.lock() {
                let cmap = cguard.get_or_insert_with(HashMap::new);
                cmap.insert((name.clone(), qtype), (final_reply.clone(), provider, verdict, Instant::now()));
            }
        }

        if verdict == Verdict::Substituted {
            if let Ok(mut guard) = CHOICE.lock() {
                let map = guard.get_or_insert_with(HashMap::new);
                map.insert((name, qtype), (hit.idx, verdict, Instant::now()));
            }
        }
        return Some(ResolveHit {
            reply: final_reply,
            provider,
            verdict,
        });
    }

    for ns in REFERENCE_V4 {
        let Ok(ip) = ns.parse::<Ipv4Addr>() else { continue };
        if let Ok(resp) = query_raw_via(query, ip, 0, QUERY_TIMEOUT) {
            if is_successful_response(&resp) && !answer_addrs(&resp).is_empty() {
                let provider = "system";
                let verdict = Verdict::Passthrough;
                if let Ok(mut cguard) = DNS_PACKET_CACHE.lock() {
                    let cmap = cguard.get_or_insert_with(HashMap::new);
                    cmap.insert((name, qtype), (resp.clone(), provider, verdict, Instant::now()));
                }
                return Some(ResolveHit {
                    reply: resp,
                    provider,
                    verdict,
                });
            }
        }
    }
    None
}

/// Nameserver IPs (not the relay) that currently substitute `name`.
/// Asked one provider at a time so a slow substituter is not lost to the race.
pub fn substituting_addrs(name: &str, if_index: u32) -> Vec<&'static str> {
    let reference = reference_addrs(name, if_index);
    let proxy = {
        let cached = cached_proxy();
        if cached.is_empty() {
            learn_proxy_addrs(if_index)
        } else {
            cached
        }
    };
    let mut out = Vec::new();
    for (idx, provider) in PROVIDERS.iter().enumerate() {
        let Some(server) = parse_v4(provider.v4[0]) else {
            continue;
        };
        let Some(resp) = query_a(name, server, if_index, QUERY_TIMEOUT) else {
            continue;
        };
        let addrs = answer_addrs(&resp);
        let proxy_addrs = proxy.get(&idx).cloned().unwrap_or_default();
        let substituted = classify(&addrs, &reference, &proxy_addrs) == Verdict::Substituted
            || (reference.is_empty() && addrs.iter().any(|a| !looks_google(a)));
        if substituted {
            if let Some(first) = provider.v4.first() {
                if !out.contains(first) {
                    out.push(*first);
                }
            }
        }
    }
    out
}

pub fn verdict_tag(v: Verdict) -> &'static str {
    match v {
        Verdict::Substituted => "substituted",
        Verdict::Sibling => "sibling",
        Verdict::Passthrough => "PASSTHROUGH",
        Verdict::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn same_slash16_is_passthrough() {
        let cand = [v4(172, 217, 22, 14)];
        let refer = [v4(172, 217, 0, 1)];
        assert_eq!(classify(&cand, &refer, &[]), Verdict::Passthrough);
    }

    #[test]
    fn different_from_reference_without_proxy_set_is_substituted() {
        let cand = [v4(87, 228, 47, 204)];
        let refer = [v4(142, 250, 1, 1)];
        assert_eq!(classify(&cand, &refer, &[]), Verdict::Substituted);
    }

    #[test]
    fn known_proxy_ip_is_substituted() {
        let cand = [v4(45, 155, 204, 190)];
        let refer = [v4(142, 250, 1, 1)];
        let proxy = [v4(45, 155, 204, 190)];
        assert_eq!(classify(&cand, &refer, &proxy), Verdict::Substituted);
    }

    #[test]
    fn other_google_edge_with_proxy_knowledge_is_sibling() {
        let cand = [v4(64, 233, 161, 1)];
        let refer = [v4(142, 250, 1, 1)];
        let proxy = [v4(45, 155, 204, 190)];
        assert_eq!(classify(&cand, &refer, &proxy), Verdict::Sibling);
    }
}
