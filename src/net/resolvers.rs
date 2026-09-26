//! Configured UDP/DoH selection. DNS substitution is evidence about routing, not model access.
use super::{
    client::{
        answer_addrs, build_query, is_successful_response, query_raw_via, question_name,
        without_addrs,
    },
    resolver_pool::{self, Provider as ActiveProvider},
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::{mpsc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

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

const LIVENESS_PORT: u16 = 443;
const LIVENESS_BUDGET: Duration = Duration::from_millis(250);
const LIVENESS_TTL_ALIVE: Duration = Duration::from_secs(600);
const LIVENESS_TTL_DEAD: Duration = Duration::from_secs(60);
static LIVENESS: Mutex<Option<HashMap<IpAddr, (bool, Instant)>>> = Mutex::new(None);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Substituted,
    Sibling,
    Passthrough,
    Unknown,
}
pub struct ResolveHit {
    pub reply: Vec<u8>,
    pub provider: String,
    pub verdict: Verdict,
}

pub fn all_provider_v4() -> Vec<String> {
    resolver_pool::load()
        .unwrap_or_default()
        .iter()
        .flat_map(|p| p.udp_addresses().iter().map(ToString::to_string))
        .collect()
}
pub fn fallback_v4() -> Vec<String> {
    resolver_pool::load()
        .unwrap_or_default()
        .iter()
        .filter_map(|p| p.udp_addresses().first().map(ToString::to_string))
        .collect()
}

// Exact question bytes (including flags/EDNS), pool and interface are part of the key.
// Changing/disabling an endpoint cannot reuse an answer from the previous configuration.
#[derive(Hash, PartialEq, Eq)]
struct CacheKey {
    pool: String,
    interface: u32,
    question: Vec<u8>,
}
struct Cached {
    reply: Vec<u8>,
    provider: String,
    verdict: Verdict,
    at: Instant,
}
static PACKETS: Mutex<Option<HashMap<CacheKey, Cached>>> = Mutex::new(None);
fn cache_key(pool: &[ActiveProvider], query: &[u8], interface: u32) -> CacheKey {
    CacheKey {
        pool: format!("{pool:?}"),
        interface,
        question: query.get(2..).unwrap_or_default().to_vec(),
    }
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
    if candidate.iter().all(looks_google) {
        return Verdict::Sibling;
    }
    if proxy.is_empty() {
        return Verdict::Substituted;
    }
    Verdict::Sibling
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
            let _ = tx.send((addr, verified_latency(SocketAddr::new(addr, 443), &sni)));
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

fn verified_latency(addr: SocketAddr, sni: &str) -> Option<u128> {
    super::health::probe_ip(addr, sni).ok()
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

struct RaceResult {
    idx: usize,
    reply: Vec<u8>,
    addrs: Vec<IpAddr>,
    server: Option<Ipv4Addr>,
}
enum RaceMsg {
    Provider(RaceResult),
    Reference(Vec<IpAddr>),
}

fn collect_race(rx: mpsc::Receiver<RaceMsg>, deadline: Instant) -> (Vec<RaceResult>, Vec<IpAddr>) {
    let mut hits = Vec::new();
    let mut reference = Vec::new();
    // A fast passthrough must not hide a slower substituting provider.
    while let Ok(message) = rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        match message {
            RaceMsg::Provider(hit) => hits.push(hit),
            RaceMsg::Reference(addrs) => {
                for addr in addrs {
                    if !reference.contains(&addr) {
                        reference.push(addr);
                    }
                }
            }
        }
    }
    hits.sort_by_key(|h| h.idx);
    (hits, reference)
}

fn race_providers(
    pool: &[ActiveProvider],
    query: &[u8],
    interface: u32,
) -> (Vec<RaceResult>, Vec<IpAddr>) {
    let deadline = Instant::now() + resolver_pool::BUDGET;
    let (tx, rx) = mpsc::channel();
    for (idx, provider) in pool.iter().cloned().enumerate() {
        let query = query.to_vec();
        let tx = tx.clone();
        thread::spawn(move || {
            if let Some((reply, server)) = provider.query(&query, interface) {
                if is_successful_response(&reply) {
                    let addrs = answer_addrs(&reply);
                    let _ = tx.send(RaceMsg::Provider(RaceResult {
                        idx,
                        reply,
                        addrs,
                        server,
                    }));
                }
            }
        });
    }
    for ns in REFERENCE_V4 {
        let query = query.to_vec();
        let tx = tx.clone();
        let ip = ns.parse().unwrap();
        thread::spawn(move || {
            if let Ok(reply) = query_raw_via(&query, ip, 0, resolver_pool::UDP_TIMEOUT) {
                if is_successful_response(&reply) {
                    let addrs = answer_addrs(&reply)
                        .into_iter()
                        .filter(|a| !matches!(a, IpAddr::V4(ip) if REFERENCE_STUBS.contains(ip)))
                        .collect();
                    let _ = tx.send(RaceMsg::Reference(addrs));
                }
            }
        });
    }
    drop(tx);
    collect_race(rx, deadline)
}

fn pick_winner(hits: &[RaceResult], reference: &[IpAddr]) -> Option<usize> {
    hits.iter()
        .enumerate()
        .min_by_key(|(_, hit)| {
            let score = match classify(&hit.addrs, reference, &[]) {
                Verdict::Substituted => 0,
                Verdict::Unknown if hit.addrs.iter().any(|a| !looks_google(a)) => 1,
                _ if !hit.addrs.is_empty() => 2,
                _ => 3,
            };
            (score, hit.idx)
        })
        .map(|(i, _)| i)
}

pub fn resolve_best(query: &[u8], interface: u32) -> Option<ResolveHit> {
    question_name(query)?;
    let pool = resolver_pool::load().ok()?;
    let key = cache_key(&pool, query, interface);
    if let Ok(guard) = PACKETS.lock() {
        if let Some(cached) = guard.as_ref().and_then(|c| c.get(&key)) {
            if let Some(mut reply) =
                super::client::aged_reply(&cached.reply, cached.at.elapsed().as_secs() as u32)
            {
                reply[..2].copy_from_slice(&query[..2]);
                return Some(ResolveHit {
                    reply,
                    provider: cached.provider.clone(),
                    verdict: cached.verdict,
                });
            }
        }
    }
    let (hits, reference) = race_providers(&pool, query, interface);
    let hit = &hits[pick_winner(&hits, &reference)?];
    let verdict = classify(&hit.addrs, &reference, &[]);
    let reply = drop_dead(&hit.reply);
    let provider = pool[hit.idx].name.clone();
    // Only address answers are cached; negative answers require SOA handling.
    if !answer_addrs(&reply).is_empty() && super::client::aged_reply(&reply, 0).is_some() {
        if let Ok(mut guard) = PACKETS.lock() {
            let cache = guard.get_or_insert_with(HashMap::new);
            if cache.len() >= 64 {
                cache.clear();
            }
            cache.insert(
                key,
                Cached {
                    reply: reply.clone(),
                    provider: provider.clone(),
                    verdict,
                    at: Instant::now(),
                },
            );
        }
    }
    Some(ResolveHit {
        reply,
        provider,
        verdict,
    })
}

/// Only UDP addresses belong in NRPT/resolver files. DoH is served by the local worker.
pub fn substituting_addrs(name: &str, interface: u32) -> Vec<String> {
    let Ok(pool) = resolver_pool::load() else {
        return vec![];
    };
    let (hits, reference) = race_providers(&pool, &build_query(name, 0x5355), interface);
    let mut ips = Vec::new();
    for hit in hits {
        if classify(&hit.addrs, &reference, &[]) == Verdict::Substituted {
            // Use the endpoint that actually answered, never a DoH bootstrap IP.
            if let Some(ip) = hit.server {
                if !ips.contains(&ip.to_string()) {
                    ips.push(ip.to_string());
                }
            }
        }
    }
    ips
}

#[derive(serde::Serialize)]
pub struct Capability {
    pub provider: usize,
    pub transport: &'static str,
    pub host: String,
    pub status: &'static str,
    pub addresses: Vec<IpAddr>,
}

fn substituted_candidates(hits: &[RaceResult], reference: &[IpAddr]) -> Vec<IpAddr> {
    let mut candidates = Vec::new();
    for hit in hits {
        if matches!(
            classify(&hit.addrs, reference, &[]),
            Verdict::Substituted | Verdict::Unknown
        ) {
            for addr in &hit.addrs {
                if !looks_google(addr) && !candidates.contains(addr) {
                    candidates.push(*addr);
                }
            }
        }
    }
    candidates
}

/// Ranking tries every substituter, even if the preferred DNS returns a dead proxy.
pub fn candidate_addrs(name: &str, interface: u32) -> Result<Vec<IpAddr>, String> {
    let pool = resolver_pool::load()?;
    let (hits, reference) = race_providers(&pool, &build_query(name, 0x524b), interface);
    Ok(substituted_candidates(&hits, &reference))
}

/// An allowlisted report: custom names and URLs may contain secrets.
pub fn capabilities(interface: u32) -> Result<Vec<Capability>, String> {
    let pool = resolver_pool::load()?;
    let mut out = Vec::new();
    let mut names = super::provider::NRPT_AGENT.to_vec();
    for name in super::provider::SUBSTITUTION_CANARIES {
        if !names.contains(name) {
            names.push(name);
        }
    }
    for name in names {
        let host = name.trim_start_matches('.');
        let (hits, reference) = race_providers(&pool, &build_query(host, 0x4341), interface);
        for (idx, provider) in pool.iter().enumerate() {
            let hit = hits.iter().find(|h| h.idx == idx);
            out.push(Capability {
                provider: idx + 1,
                transport: provider.kind(),
                host: host.into(),
                status: hit
                    .map(|h| {
                        if h.addrs.is_empty() {
                            "no_addresses"
                        } else {
                            verdict_tag(classify(&h.addrs, &reference, &[]))
                        }
                    })
                    .unwrap_or("timeout_or_error"),
                addresses: hit.map(|h| h.addrs.clone()).unwrap_or_default(),
            });
        }
    }
    Ok(out)
}

pub fn verdict_tag(v: Verdict) -> &'static str {
    match v {
        Verdict::Substituted => "substituted",
        Verdict::Sibling => "sibling",
        Verdict::Passthrough => "PASSTHROUGH",
        Verdict::Unknown => "unknown",
    }
}
pub fn invalidate_network_caches() {
    if let Ok(mut cache) = PACKETS.lock() {
        *cache = None;
    }
    if let Ok(mut cache) = LIVENESS.lock() {
        *cache = None;
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn ranking_rejects_tls_alerts_plain_http_and_untrusted_certificates() {
        use std::io::{Read, Write};
        for reply in [
            b"\x15\x03\x03\x00\x02\x02\x28".as_slice(),
            b"HTTP/1.1 200 OK\r\n\r\n",
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let _ = stream.read(&mut [0; 4096]);
                let _ = stream.write_all(reply);
            });
            assert!(verified_latency(addr, "localhost").is_none());
            server.join().unwrap();
        }
        let (addr, server) = super::super::health::tests::server(
            b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
            Duration::ZERO,
        );
        assert!(verified_latency(addr, "localhost").is_none());
        server.join().unwrap();
    }

    #[test]
    fn slower_substituter_is_not_hidden_by_a_fast_passthrough() {
        let (tx, rx) = mpsc::channel();
        let google = v4(142, 250, 1, 1);
        tx.send(RaceMsg::Reference(vec![google])).unwrap();
        tx.send(RaceMsg::Provider(RaceResult {
            idx: 0,
            reply: vec![],
            addrs: vec![google],
            server: None,
        }))
        .unwrap();
        let worker = thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));
            tx.send(RaceMsg::Provider(RaceResult {
                idx: 1,
                reply: vec![],
                addrs: vec![v4(192, 0, 2, 1)],
                server: None,
            }))
            .unwrap();
        });
        let (hits, reference) = collect_race(rx, Instant::now() + Duration::from_secs(1));
        worker.join().unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[pick_winner(&hits, &reference).unwrap()].idx, 1);
        assert_eq!(pick_winner(&hits, &[]), Some(1));
        assert_eq!(
            substituted_candidates(&hits, &reference),
            vec![v4(192, 0, 2, 1)]
        );
    }

    #[test]
    fn cache_is_invalidated_by_interface_endpoint_and_order_changes() {
        let mut config = super::super::config::Config::default();
        let pool = resolver_pool::from_config(&config).unwrap();
        let query = build_query("example.test", 1);
        let key = cache_key(&pool, &query, 0);
        assert!(key != cache_key(&pool, &query, 7));
        assert!(key == cache_key(&pool, &build_query("example.test", 2), 0));
        config.doh[0].url = "https://another.test/dns-query".into();
        assert!(key != cache_key(&resolver_pool::from_config(&config).unwrap(), &query, 0));
        config = super::super::config::Config::default();
        config.provider_order = vec!["dns-ai.ru".into()];
        assert!(key != cache_key(&resolver_pool::from_config(&config).unwrap(), &query, 0));
        config.disabled_providers.push("dns-ai.ru".into());
        assert!(key != cache_key(&resolver_pool::from_config(&config).unwrap(), &query, 0));
    }

    #[test]
    fn another_google_block_is_not_evidence_of_substitution() {
        assert_eq!(
            classify(&[v4(64, 233, 1, 1)], &[v4(142, 250, 1, 1)], &[]),
            Verdict::Sibling
        );
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
