//! Configured UDP/DoH selection. DNS substitution is evidence about routing, not model access.
use super::{
    client::{
        answer_addrs, build_query, is_successful_response, query_raw_via, question_name,
        question_type, without_addrs,
    },
    resolver_pool::{self, Provider as ActiveProvider},
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub struct Provider {
    pub name: &'static str,
    pub v4: &'static [&'static str],
}

pub const PROVIDERS: &[Provider] = &[
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

const CACHE_CAPACITY: usize = 1024;
// An expired answer is served at once with a short TTL while one refresh runs.
const STALE_LIMIT: Duration = Duration::from_secs(3600);
const STALE_TTL: u32 = 5;
// Once an answer is usable, higher-priority providers get this long to beat it.
const PREFERENCE_GRACE: Duration = Duration::from_millis(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Substituted,
    Sibling,
    Passthrough,
    Unknown,
}
#[derive(Clone)]
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
#[derive(Clone, Hash, PartialEq, Eq)]
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
// Identical concurrent questions share one upstream race.
type Flight = Arc<(Mutex<Option<Option<ResolveHit>>>, Condvar)>;
static IN_FLIGHT: Mutex<Option<HashMap<CacheKey, Flight>>> = Mutex::new(None);
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
    /// Sent after the provider's answer, or alone when it failed.
    Done(usize),
}

/// Stop rule for client-facing lookups; setup and reports wait for everyone.
struct Settle {
    providers: usize,
    wants_address: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum Progress {
    Wait,
    Grace,
    Now,
}

fn progress(hits: &[RaceResult], reference: &[IpAddr], done: &[usize], rule: &Settle) -> Progress {
    if done.len() >= rule.providers {
        return Progress::Now;
    }
    let Some(best) = pick_winner(hits, reference).map(|i| &hits[i]) else {
        return Progress::Wait;
    };
    // A non-Google answer for a Google name is the substitution we want; the
    // reference DNS only tells "substituted" from "unknown", both of which win.
    if rule.wants_address && score(best, reference) > 1 {
        return Progress::Wait;
    }
    if (0..best.idx).all(|idx| done.contains(&idx)) {
        Progress::Now
    } else {
        Progress::Grace
    }
}

fn collect_race(
    rx: mpsc::Receiver<RaceMsg>,
    deadline: Instant,
    settle: Option<&Settle>,
) -> (Vec<RaceResult>, Vec<IpAddr>) {
    let mut hits = Vec::new();
    let mut reference = Vec::new();
    let mut done = Vec::new();
    let mut grace: Option<Instant> = None;
    // A fast passthrough must not hide a slower substituting provider.
    loop {
        let until = grace.map_or(deadline, |g| g.min(deadline));
        let Ok(message) = rx.recv_timeout(until.saturating_duration_since(Instant::now())) else {
            break;
        };
        match message {
            RaceMsg::Provider(hit) => hits.push(hit),
            RaceMsg::Reference(addrs) => {
                for addr in addrs {
                    if !reference.contains(&addr) {
                        reference.push(addr);
                    }
                }
            }
            RaceMsg::Done(idx) => done.push(idx),
        }
        if let Some(rule) = settle {
            match progress(&hits, &reference, &done, rule) {
                Progress::Now => break,
                Progress::Grace => {
                    grace.get_or_insert_with(|| Instant::now() + PREFERENCE_GRACE);
                }
                Progress::Wait => {}
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
    early: bool,
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
            let _ = tx.send(RaceMsg::Done(idx));
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
    let settle = early.then(|| Settle {
        providers: pool.len(),
        wants_address: question_type(query) == Some(1),
    });
    collect_race(rx, deadline, settle.as_ref())
}

fn score(hit: &RaceResult, reference: &[IpAddr]) -> u8 {
    match classify(&hit.addrs, reference, &[]) {
        Verdict::Substituted => 0,
        Verdict::Unknown if hit.addrs.iter().any(|a| !looks_google(a)) => 1,
        _ if !hit.addrs.is_empty() => 2,
        _ => 3,
    }
}

fn pick_winner(hits: &[RaceResult], reference: &[IpAddr]) -> Option<usize> {
    hits.iter()
        .enumerate()
        .min_by_key(|(_, hit)| (score(hit, reference), hit.idx))
        .map(|(i, _)| i)
}

enum Lookup {
    Fresh(ResolveHit),
    Stale(ResolveHit),
    Miss,
}

fn cached(key: &CacheKey) -> Lookup {
    let Ok(guard) = PACKETS.lock() else {
        return Lookup::Miss;
    };
    let Some(entry) = guard.as_ref().and_then(|c| c.get(key)) else {
        return Lookup::Miss;
    };
    let age = entry.at.elapsed();
    let hit = |reply| ResolveHit {
        reply,
        provider: entry.provider.clone(),
        verdict: entry.verdict,
    };
    if let Some(reply) = super::client::aged_reply(&entry.reply, age.as_secs() as u32) {
        return Lookup::Fresh(hit(reply));
    }
    if age < STALE_LIMIT {
        if let Some(reply) = super::client::age_ttls(&entry.reply, 0, STALE_TTL) {
            return Lookup::Stale(hit(reply));
        }
    }
    Lookup::Miss
}

fn remember(key: CacheKey, hit: &ResolveHit) {
    let Ok(mut guard) = PACKETS.lock() else {
        return;
    };
    let cache = guard.get_or_insert_with(HashMap::new);
    if cache.len() >= CACHE_CAPACITY && !cache.contains_key(&key) {
        let oldest = cache
            .iter()
            .min_by_key(|(_, entry)| entry.at)
            .map(|(key, _)| key.clone());
        if let Some(oldest) = oldest {
            cache.remove(&oldest);
        }
    }
    cache.insert(
        key,
        Cached {
            reply: hit.reply.clone(),
            provider: hit.provider.clone(),
            verdict: hit.verdict,
            at: Instant::now(),
        },
    );
}

fn with_id(mut hit: ResolveHit, query: &[u8]) -> ResolveHit {
    if hit.reply.len() >= 2 && query.len() >= 2 {
        hit.reply[..2].copy_from_slice(&query[..2]);
    }
    hit
}

pub fn resolve_best(query: &[u8], interface: u32) -> Option<ResolveHit> {
    question_name(query)?;
    let pool = resolver_pool::load().ok()?;
    let key = cache_key(&pool, query, interface);
    match cached(&key) {
        Lookup::Fresh(hit) => return Some(with_id(hit, query)),
        Lookup::Stale(hit) => {
            refresh_in_background(pool, query.to_vec(), interface, key);
            return Some(with_id(hit, query));
        }
        Lookup::Miss => {}
    }
    shared(key, || resolve_uncached(&pool, query, interface)).map(|hit| with_id(hit, query))
}

fn refresh_in_background(pool: Vec<ActiveProvider>, query: Vec<u8>, interface: u32, key: CacheKey) {
    let running = IN_FLIGHT
        .lock()
        .is_ok_and(|guard| guard.as_ref().is_some_and(|f| f.contains_key(&key)));
    if !running {
        thread::spawn(move || shared(key, || resolve_uncached(&pool, &query, interface)));
    }
}

/// The first caller resolves and caches; concurrent callers with the same key wait for it.
fn shared(key: CacheKey, resolve: impl FnOnce() -> Option<ResolveHit>) -> Option<ResolveHit> {
    let (flight, leader) = {
        let mut guard = IN_FLIGHT.lock().ok()?;
        let flights = guard.get_or_insert_with(HashMap::new);
        match flights.get(&key) {
            Some(flight) => (Arc::clone(flight), false),
            None => {
                let flight: Flight = Arc::new((Mutex::new(None), Condvar::new()));
                flights.insert(key.clone(), Arc::clone(&flight));
                (flight, true)
            }
        }
    };
    let (slot, ready) = &*flight;
    if !leader {
        let wait = resolver_pool::BUDGET + LIVENESS_BUDGET + Duration::from_secs(1);
        let guard = slot.lock().ok()?;
        let (guard, _) = ready
            .wait_timeout_while(guard, wait, |result| result.is_none())
            .ok()?;
        return guard.clone().flatten();
    }
    let hit = resolve();
    if let Some(hit) = &hit {
        // Only address answers are cached; negative answers require SOA handling.
        if !answer_addrs(&hit.reply).is_empty()
            && super::client::aged_reply(&hit.reply, 0).is_some()
        {
            remember(key.clone(), hit);
        }
    }
    if let Ok(mut guard) = IN_FLIGHT.lock() {
        if let Some(flights) = guard.as_mut() {
            flights.remove(&key);
        }
    }
    if let Ok(mut result) = slot.lock() {
        *result = Some(hit.clone());
    }
    ready.notify_all();
    hit
}

fn resolve_uncached(pool: &[ActiveProvider], query: &[u8], interface: u32) -> Option<ResolveHit> {
    let (hits, reference) = race_providers(pool, query, interface, true);
    let hit = &hits[pick_winner(&hits, &reference)?];
    Some(ResolveHit {
        reply: drop_dead(&hit.reply),
        provider: pool[hit.idx].name.clone(),
        verdict: classify(&hit.addrs, &reference, &[]),
    })
}

/// Only UDP addresses belong in NRPT/resolver files. DoH is served by the local worker.
pub fn substituting_addrs(name: &str, interface: u32) -> Vec<String> {
    let Ok(pool) = resolver_pool::load() else {
        return vec![];
    };
    let (hits, reference) = race_providers(&pool, &build_query(name, 0x5355), interface, false);
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
    let (hits, reference) = race_providers(&pool, &build_query(name, 0x524b), interface, false);
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
        let (hits, reference) = race_providers(&pool, &build_query(host, 0x4341), interface, false);
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
        let (hits, reference) = collect_race(rx, Instant::now() + Duration::from_secs(1), None);
        worker.join().unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[pick_winner(&hits, &reference).unwrap()].idx, 1);
        assert_eq!(pick_winner(&hits, &[]), Some(1));
        assert_eq!(
            substituted_candidates(&hits, &reference),
            vec![v4(192, 0, 2, 1)]
        );
    }

    fn race_hit(idx: usize, addrs: Vec<IpAddr>) -> RaceMsg {
        RaceMsg::Provider(RaceResult {
            idx,
            reply: vec![],
            addrs,
            server: None,
        })
    }

    #[test]
    fn client_lookup_returns_once_no_pending_provider_can_win() {
        let rule = Settle {
            providers: 3,
            wants_address: true,
        };
        let (tx, rx) = mpsc::channel();
        tx.send(race_hit(0, vec![v4(142, 250, 1, 1)])).unwrap();
        tx.send(RaceMsg::Done(0)).unwrap();
        let worker = thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));
            tx.send(race_hit(1, vec![v4(192, 0, 2, 1)])).unwrap();
            tx.send(RaceMsg::Done(1)).unwrap();
            // Provider 2 and the reference DNS stay silent until the deadline.
            thread::sleep(Duration::from_secs(2));
            drop(tx);
        });
        let start = Instant::now();
        let (hits, reference) =
            collect_race(rx, Instant::now() + Duration::from_secs(2), Some(&rule));
        assert!(start.elapsed() < PREFERENCE_GRACE);
        assert_eq!(hits[pick_winner(&hits, &reference).unwrap()].idx, 1);
        worker.join().unwrap();
    }

    #[test]
    fn pending_preferred_provider_gets_only_a_short_grace() {
        let rule = Settle {
            providers: 2,
            wants_address: true,
        };
        let (tx, rx) = mpsc::channel();
        tx.send(race_hit(1, vec![v4(192, 0, 2, 1)])).unwrap();
        tx.send(RaceMsg::Done(1)).unwrap();
        let start = Instant::now();
        let (hits, _) = collect_race(rx, Instant::now() + Duration::from_secs(2), Some(&rule));
        let elapsed = start.elapsed();
        assert!(elapsed >= PREFERENCE_GRACE && elapsed < Duration::from_secs(1));
        assert_eq!(hits.len(), 1);
        drop(tx);

        let (tx, rx) = mpsc::channel();
        tx.send(race_hit(1, vec![v4(192, 0, 2, 1)])).unwrap();
        tx.send(RaceMsg::Done(1)).unwrap();
        let worker = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            tx.send(race_hit(0, vec![v4(198, 51, 100, 1)])).unwrap();
            tx.send(RaceMsg::Done(0)).unwrap();
            thread::sleep(Duration::from_secs(2));
        });
        let start = Instant::now();
        let (hits, reference) =
            collect_race(rx, Instant::now() + Duration::from_secs(2), Some(&rule));
        assert!(start.elapsed() < PREFERENCE_GRACE);
        assert_eq!(hits[pick_winner(&hits, &reference).unwrap()].idx, 0);
        worker.join().unwrap();
    }

    #[test]
    fn genuine_google_answers_still_wait_for_substituters() {
        let rule = Settle {
            providers: 2,
            wants_address: true,
        };
        let google = vec![v4(142, 250, 1, 1)];
        let hits = [RaceResult {
            idx: 0,
            reply: vec![],
            addrs: google.clone(),
            server: None,
        }];
        assert_eq!(progress(&hits, &google, &[0], &rule), Progress::Wait);
        assert_eq!(progress(&hits, &google, &[0, 1], &rule), Progress::Now);
        let other = Settle {
            providers: 2,
            wants_address: false,
        };
        let empty = [RaceResult {
            idx: 0,
            reply: vec![],
            addrs: vec![],
            server: None,
        }];
        assert_eq!(progress(&empty, &[], &[0], &other), Progress::Now);
        assert_eq!(progress(&[], &[], &[0], &other), Progress::Wait);
    }

    // Cache tests share the process-wide cache.
    static CACHE_TESTS: Mutex<()> = Mutex::new(());

    fn test_key(name: &str) -> CacheKey {
        CacheKey {
            pool: format!("test-{name}"),
            interface: 0,
            question: build_query(name, 0)[2..].to_vec(),
        }
    }

    fn address_hit(name: &str) -> ResolveHit {
        let query = build_query(name, 9);
        ResolveHit {
            reply: super::super::client::address_response(&query, &[Ipv4Addr::new(192, 0, 2, 7)])
                .unwrap(),
            provider: "test".into(),
            verdict: Verdict::Substituted,
        }
    }

    #[test]
    fn concurrent_identical_questions_share_one_upstream_race() {
        let _serial = CACHE_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let key = test_key("single-flight.test");
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let key = key.clone();
                let calls = Arc::clone(&calls);
                thread::spawn(move || {
                    shared(key, || {
                        calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        thread::sleep(Duration::from_millis(200));
                        Some(address_hit("single-flight.test"))
                    })
                })
            })
            .collect();
        for worker in workers {
            let hit = worker.join().unwrap().unwrap();
            assert!(!answer_addrs(&hit.reply).is_empty());
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(matches!(cached(&key), Lookup::Fresh(_)));
    }

    #[test]
    fn expired_answers_are_served_briefly_then_dropped() {
        let _serial = CACHE_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let hit = address_hit("stale.test");
        let ttl = super::super::client::age_ttls(&hit.reply, 0, u32::MAX).unwrap();
        assert!(super::super::client::aged_reply(&ttl, 0).is_some());
        for (name, age, expected) in [
            ("stale-a.test", Duration::from_secs(400), "stale"),
            ("stale-b.test", STALE_LIMIT + Duration::from_secs(1), "miss"),
        ] {
            let key = test_key(name);
            remember(key.clone(), &hit);
            if let Some(entry) = PACKETS
                .lock()
                .unwrap()
                .as_mut()
                .and_then(|c| c.get_mut(&key))
            {
                entry.at = Instant::now().checked_sub(age).unwrap();
            }
            match (cached(&key), expected) {
                (Lookup::Stale(stale), "stale") => {
                    let fresh = super::super::client::aged_reply(&stale.reply, 0).unwrap();
                    assert!(super::super::client::aged_reply(&fresh, STALE_TTL).is_none());
                    assert_eq!(answer_addrs(&stale.reply), answer_addrs(&hit.reply));
                }
                (Lookup::Miss, "miss") => {}
                _ => panic!("{name}: unexpected cache state"),
            }
        }
    }

    #[test]
    fn full_cache_evicts_the_oldest_answer_only() {
        let _serial = CACHE_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        *PACKETS.lock().unwrap() = None;
        let hit = address_hit("evict.test");
        let first = test_key("evict-first.test");
        remember(first.clone(), &hit);
        if let Some(entry) = PACKETS
            .lock()
            .unwrap()
            .as_mut()
            .and_then(|c| c.get_mut(&first))
        {
            entry.at = Instant::now().checked_sub(Duration::from_secs(30)).unwrap();
        }
        for i in 0..CACHE_CAPACITY {
            remember(test_key(&format!("evict-{i}.test")), &hit);
        }
        let guard = PACKETS.lock().unwrap();
        let cache = guard.as_ref().unwrap();
        assert!(cache.len() <= CACHE_CAPACITY);
        assert!(!cache.contains_key(&first));
        assert!(cache.contains_key(&test_key(&format!("evict-{}.test", CACHE_CAPACITY - 1))));
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
        config.provider_order = vec!["geohide.ru".into(), "dns-ai.ru".into()];
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
