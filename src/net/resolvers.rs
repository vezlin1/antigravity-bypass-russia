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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const REFERENCE_V4: &[&str] = &["8.8.8.8", "1.1.1.1"];
const REFERENCE_STUBS: [Ipv4Addr; 2] = [Ipv4Addr::new(8, 6, 112, 0), Ipv4Addr::new(8, 47, 69, 0)];
// Reference answers only tell which Google netblocks a name normally uses.
// Reuse them for a while instead of asking both public resolvers on every miss.
const REFERENCE_TTL_ANSWER: Duration = Duration::from_secs(300);
const REFERENCE_TTL_FAILURE: Duration = Duration::from_secs(30);
type ReferenceKey = (String, u16, Ipv4Addr);
struct ReferenceEntry {
    addrs: Option<Vec<IpAddr>>,
    at: Instant,
    generation: u64,
}
static REFERENCES: Mutex<Option<HashMap<ReferenceKey, ReferenceEntry>>> = Mutex::new(None);

const LIVENESS_PORT: u16 = 443;
const LIVENESS_BUDGET: Duration = Duration::from_millis(250);
const LIVENESS_TTL_ALIVE: Duration = Duration::from_secs(600);
const LIVENESS_TTL_DEAD: Duration = Duration::from_secs(60);
static LIVENESS: Mutex<Option<HashMap<IpAddr, (bool, Instant)>>> = Mutex::new(None);
static NETWORK_GENERATION: AtomicU64 = AtomicU64::new(0);

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
    configured_udp_v4(&resolver_pool::load().unwrap_or_default())
}

pub(super) fn configured_udp_v4(pool: &[ActiveProvider]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    pool.iter()
        .flat_map(|p| p.udp_addresses())
        .filter(|ip| seen.insert(**ip))
        .map(ToString::to_string)
        .collect()
}

// Exact question bytes (including flags/EDNS), pool and interface are part of the key.
// Changing/disabling an endpoint cannot reuse an answer from the previous configuration.
#[derive(Clone, Hash, PartialEq, Eq)]
struct CacheKey {
    pool: Arc<str>,
    interface: u32,
    network_generation: u64,
    question: Vec<u8>,
}
struct Cached {
    reply: Vec<u8>,
    provider: String,
    verdict: Verdict,
    at: Instant,
    /// A refresh before expiry was already started for this answer.
    prefetching: bool,
}
static PACKETS: Mutex<Option<HashMap<CacheKey, Cached>>> = Mutex::new(None);
// Identical concurrent questions share one upstream race.
type Flight = Arc<(Mutex<Option<Option<ResolveHit>>>, Condvar)>;
static IN_FLIGHT: Mutex<Option<HashMap<CacheKey, Flight>>> = Mutex::new(None);
#[cfg(test)]
fn cache_key(pool: &[ActiveProvider], query: &[u8], interface: u32) -> CacheKey {
    snapshot_key(
        &resolver_pool::Snapshot::new(pool.to_vec()),
        query,
        interface,
    )
}

fn snapshot_key(pool: &resolver_pool::Snapshot, query: &[u8], interface: u32) -> CacheKey {
    CacheKey {
        pool: Arc::clone(&pool.fingerprint),
        interface,
        network_generation: NETWORK_GENERATION.load(Ordering::Acquire),
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
#[cfg(windows)]
pub fn rank_tls_v4(addrs: &[IpAddr], sni: &str) -> Vec<(Ipv4Addr, u128)> {
    rank_tls_v4_report(addrs, sni).0
}

/// Verified addresses sorted by latency, plus the probe error of every
/// address that failed. The errors explain an empty result to the user.
/// Lookup threads that wait a minute after their work for the next lookup,
/// instead of a new thread for every upstream question. Without an idle
/// thread this behaves like `thread::spawn`.
mod reuse {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{mpsc, Mutex};
    use std::thread;
    use std::time::Duration;

    type Task = Box<dyn FnOnce() + Send>;

    struct Idle {
        id: u64,
        sender: mpsc::Sender<Task>,
    }

    static IDLE: Mutex<Vec<Idle>> = Mutex::new(Vec::new());
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    pub(super) const KEEP: Duration = Duration::from_secs(60);
    const MAX_IDLE: usize = 16;

    fn idle() -> std::sync::MutexGuard<'static, Vec<Idle>> {
        IDLE.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(super) fn run(task: impl FnOnce() + Send + 'static) {
        let mut task: Task = Box::new(task);
        loop {
            let Some(worker) = idle().pop() else {
                break;
            };
            match worker.sender.send(task) {
                Ok(()) => return,
                // The worker exited between being listed and taking the task.
                Err(mpsc::SendError(back)) => task = back,
            }
        }
        thread::spawn(move || work(task, KEEP));
    }

    pub(super) fn work(first: Task, keep: Duration) {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let (sender, tasks) = mpsc::channel();
        let mut task = first;
        loop {
            task();
            {
                let mut idle = idle();
                if idle.len() >= MAX_IDLE {
                    return;
                }
                idle.push(Idle {
                    id,
                    sender: sender.clone(),
                });
            }
            task = match tasks.recv_timeout(keep) {
                Ok(next) => next,
                Err(_) => {
                    let mut idle = idle();
                    match idle.iter().position(|worker| worker.id == id) {
                        Some(position) => {
                            idle.remove(position);
                            return;
                        }
                        // Taken just as the wait ended: its task is on the way.
                        None => {
                            drop(idle);
                            match tasks.recv() {
                                Ok(next) => next,
                                Err(_) => return,
                            }
                        }
                    }
                }
            };
        }
    }

    #[cfg(test)]
    pub(super) fn idle_count() -> usize {
        idle().len()
    }
}

pub fn rank_tls_v4_report(addrs: &[IpAddr], sni: &str) -> (Vec<(Ipv4Addr, u128)>, Vec<String>) {
    let candidates: Vec<IpAddr> = addrs.iter().copied().filter(|a| a.is_ipv4()).collect();
    if candidates.is_empty() {
        return (Vec::new(), Vec::new());
    }
    let (tx, rx) = mpsc::channel();
    for addr in candidates {
        let sni = sni.to_string();
        let tx = tx.clone();
        thread::spawn(move || {
            let _ = tx.send((
                addr,
                super::health::probe_ip(SocketAddr::new(addr, 443), &sni),
            ));
        });
    }
    drop(tx);
    let mut out = Vec::new();
    let mut errors = Vec::new();
    while let Ok((addr, result)) = rx.recv() {
        match (addr, result) {
            (IpAddr::V4(v4), Ok(ms)) => out.push((v4, ms)),
            (_, Err(error)) => errors.push(error),
            _ => {}
        }
    }
    out.sort_by_key(|(_, ms)| *ms);
    (out, errors)
}

fn is_alive(addr: IpAddr) -> bool {
    let generation = NETWORK_GENERATION.load(Ordering::Acquire);
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
        if generation == NETWORK_GENERATION.load(Ordering::Acquire) {
            let map = guard.get_or_insert_with(HashMap::new);
            map.insert(addr, (ok, Instant::now()));
        }
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

/// Google front-end (GFE) networks that serve `*.googleapis.com` directly.
/// Google Cloud customer space (34/8, 35/8, …) is deliberately excluded: proxies
/// may be hosted there. Missing a GFE block lets a direct Google address pass
/// as a proxy and outrank real proxies (issues #55–#57).
const GOOGLE_V4: &[([u8; 4], u8)] = &[
    ([64, 233, 0, 0], 16),
    ([66, 102, 0, 0], 16),
    ([66, 249, 0, 0], 16),
    ([72, 14, 0, 0], 16),
    ([74, 125, 0, 0], 16),
    ([108, 177, 0, 0], 17),
    ([142, 250, 0, 0], 15),
    ([172, 217, 0, 0], 16),
    ([172, 253, 0, 0], 16),
    ([173, 194, 0, 0], 16),
    ([192, 178, 0, 0], 15),
    ([209, 85, 128, 0], 17),
    ([216, 58, 0, 0], 16),
    ([216, 239, 0, 0], 16),
];

/// Google /32 IPv6 allocations (first two segments).
const GOOGLE_V6: &[[u16; 2]] = &[
    [0x2001, 0x4860],
    [0x2404, 0x6800],
    [0x2607, 0xf8b0],
    [0x2800, 0x03f0],
    [0x2a00, 0x1450],
    [0x2c0f, 0xfb50],
];

pub(crate) fn looks_google(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let ip = u32::from(*v4);
            GOOGLE_V4.iter().any(|(net, bits)| {
                let mask = u32::MAX << (32 - u32::from(*bits));
                ip & mask == u32::from_be_bytes(*net) & mask
            })
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            GOOGLE_V6.iter().any(|prefix| s[..2] == prefix[..])
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
    collect_race_with(
        |until| {
            rx.recv_timeout(until.saturating_duration_since(Instant::now()))
                .ok()
        },
        Instant::now,
        deadline,
        settle,
    )
}

fn collect_race_with(
    mut receive: impl FnMut(Instant) -> Option<RaceMsg>,
    mut now: impl FnMut() -> Instant,
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
        let Some(message) = receive(until) else {
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
                    grace.get_or_insert_with(|| now() + PREFERENCE_GRACE);
                }
                Progress::Wait => {}
            }
        }
    }
    hits.sort_by_key(|h| h.idx);
    (hits, reference)
}

fn reference_question(query: &[u8]) -> Option<(String, u16)> {
    Some((
        question_name(query)?.to_ascii_lowercase(),
        question_type(query)?,
    ))
}

/// Addresses from every reference resolver, if all of them have a fresh entry
/// (an answer or a recent failure) for this question.
fn cached_references(question: &(String, u16)) -> Option<Vec<IpAddr>> {
    let generation = NETWORK_GENERATION.load(Ordering::Acquire);
    let guard = REFERENCES.lock().ok()?;
    let cache = guard.as_ref()?;
    let mut merged = Vec::new();
    for ns in REFERENCE_V4 {
        let key = (question.0.clone(), question.1, ns.parse().ok()?);
        let entry = cache.get(&key)?;
        let ttl = if entry.addrs.is_some() {
            REFERENCE_TTL_ANSWER
        } else {
            REFERENCE_TTL_FAILURE
        };
        if entry.generation != generation || entry.at.elapsed() >= ttl {
            return None;
        }
        for addr in entry.addrs.iter().flatten() {
            if !merged.contains(addr) {
                merged.push(*addr);
            }
        }
    }
    Some(merged)
}

fn remember_reference(
    question: (String, u16),
    server: Ipv4Addr,
    addrs: Option<Vec<IpAddr>>,
    generation: u64,
) {
    let Ok(mut guard) = REFERENCES.lock() else {
        return;
    };
    if generation != NETWORK_GENERATION.load(Ordering::Acquire) {
        return;
    }
    let cache = guard.get_or_insert_with(HashMap::new);
    if cache.len() >= CACHE_CAPACITY {
        cache.clear();
    }
    cache.insert(
        (question.0, question.1, server),
        ReferenceEntry {
            addrs,
            at: Instant::now(),
            generation,
        },
    );
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
        reuse::run(move || {
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
    let question = reference_question(query);
    if let Some(addrs) = question.as_ref().and_then(cached_references) {
        let _ = tx.send(RaceMsg::Reference(addrs));
    } else {
        let generation = NETWORK_GENERATION.load(Ordering::Acquire);
        for ns in REFERENCE_V4 {
            let query = query.to_vec();
            let tx = tx.clone();
            let question = question.clone();
            let ip = ns.parse().unwrap();
            reuse::run(move || {
                let reply = query_raw_via(&query, ip, 0, resolver_pool::UDP_TIMEOUT)
                    .ok()
                    .filter(|reply| is_successful_response(reply));
                let addrs = reply.map(|reply| {
                    answer_addrs(&reply)
                        .into_iter()
                        .filter(|a| !matches!(a, IpAddr::V4(ip) if REFERENCE_STUBS.contains(ip)))
                        .collect::<Vec<_>>()
                });
                if let Some(question) = question {
                    remember_reference(question, ip, addrs.clone(), generation);
                }
                if let Some(addrs) = addrs {
                    let _ = tx.send(RaceMsg::Reference(addrs));
                }
            });
        }
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
    /// Still valid, but less than a fifth of its lifetime is left: answer from
    /// the cache and refresh it now, so popular names rarely reach expiry.
    Expiring(ResolveHit),
    Stale(ResolveHit),
    Miss,
}

fn cached(key: &CacheKey) -> Lookup {
    let Ok(mut guard) = PACKETS.lock() else {
        return Lookup::Miss;
    };
    let Some(entry) = guard.as_mut().and_then(|c| c.get_mut(key)) else {
        return Lookup::Miss;
    };
    let age = entry.at.elapsed();
    match cached_answer(entry, age) {
        // One early refresh per answer: a failed one leaves the stale path.
        Lookup::Fresh(hit) if !entry.prefetching && expiring_soon(&entry.reply, age) => {
            entry.prefetching = true;
            Lookup::Expiring(hit)
        }
        lookup => lookup,
    }
}

/// Less than a fifth of the answer's lifetime is left.
fn expiring_soon(reply: &[u8], age: Duration) -> bool {
    let age = age.as_secs() as u32;
    super::client::aged_reply(reply, age + age / 4 + 1).is_none()
}

fn cached_answer(entry: &Cached, age: Duration) -> Lookup {
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
    if key.network_generation != NETWORK_GENERATION.load(Ordering::Acquire) {
        return;
    }
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
            prefetching: false,
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
    let pool = resolver_pool::load_shared().ok()?;
    let key = snapshot_key(&pool, query, interface);
    match cached(&key) {
        Lookup::Fresh(hit) => return Some(with_id(hit, query)),
        Lookup::Expiring(hit) | Lookup::Stale(hit) => {
            refresh_in_background(pool, query.to_vec(), interface, key);
            return Some(with_id(hit, query));
        }
        Lookup::Miss => {}
    }
    shared(key, || resolve_uncached(&pool.providers, query, interface))
        .map(|hit| with_id(hit, query))
}

fn refresh_in_background(
    pool: Arc<resolver_pool::Snapshot>,
    query: Vec<u8>,
    interface: u32,
    key: CacheKey,
) {
    let running = IN_FLIGHT
        .lock()
        .is_ok_and(|guard| guard.as_ref().is_some_and(|f| f.contains_key(&key)));
    if !running {
        reuse::run(move || {
            shared(key, || resolve_uncached(&pool.providers, &query, interface));
        });
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
    let Ok(mut pool) = resolver_pool::load() else {
        return vec![];
    };
    pool.retain(|provider| !provider.udp_addresses().is_empty());
    if pool.is_empty() {
        return vec![];
    }
    let (hits, reference) = race_providers(&pool, &build_query(name, 0x5355), interface, false);
    substituting_udp_servers(&pool, &hits, &reference)
}

fn substituting_udp_servers(
    pool: &[ActiveProvider],
    hits: &[RaceResult],
    reference: &[IpAddr],
) -> Vec<String> {
    let mut confirmed = Vec::new();
    let mut backups = Vec::new();
    for hit in hits {
        if let Some(server) = hit.server {
            if classify(&hit.addrs, reference, &[]) == Verdict::Substituted {
                confirmed.push(server);
                backups.extend_from_slice(pool[hit.idx].udp_addresses());
            }
        }
    }
    // Try every confirmed server before any sibling which has not answered.
    let mut seen = std::collections::HashSet::new();
    confirmed
        .into_iter()
        .chain(backups)
        .filter(|ip| seen.insert(*ip))
        .map(|ip| ip.to_string())
        .collect()
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
    // Sequential timeouts for seven names could exhaust the entire report's
    // 20-second deadline and hide even the providers which did answer.
    for batch in names.chunks(3) {
        let results = thread::scope(|scope| {
            let workers: Vec<_> = batch
                .iter()
                .map(|name| {
                    let host = name.trim_start_matches('.');
                    let pool = &pool;
                    scope.spawn(move || {
                        (
                            host,
                            race_providers(pool, &build_query(host, 0x4341), interface, false),
                        )
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|worker| worker.join().map_err(|_| "Ошибка проверки DNS".to_string()))
                .collect::<Result<Vec<_>, _>>()
        })?;
        for (host, (hits, reference)) in results {
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
    super::dns_https::invalidate_connections();
    NETWORK_GENERATION.fetch_add(1, Ordering::AcqRel);
    if let Ok(mut cache) = PACKETS.lock() {
        *cache = None;
    }
    if let Ok(mut cache) = LIVENESS.lock() {
        *cache = None;
    }
    if let Ok(mut cache) = REFERENCES.lock() {
        *cache = None;
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn google_front_end_blocks_are_recognised_and_neighbours_are_not() {
        for google in [
            "172.217.114.4",
            "142.251.1.95",
            "108.177.14.95",
            "209.85.233.95",
            "172.253.63.95",
            "192.179.1.1",
            "2a00:1450:4010::5f",
            "2001:4860:4860::8888",
        ] {
            assert!(looks_google(&google.parse().unwrap()), "{google}");
        }
        for other in [
            "45.131.64.204",
            "185.4.64.180",
            "108.177.200.1",
            "209.85.1.1",
            "34.120.0.1",
            "2a00:1451::1",
        ] {
            assert!(!looks_google(&other.parse().unwrap()), "{other}");
        }
    }

    #[test]
    fn reference_answers_are_reused_only_while_both_resolvers_are_fresh() {
        // Another test changes the network generation; run apart from it.
        let _serial = CACHE_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let question = ("reference-cache.example".to_string(), 1);
        let google: Ipv4Addr = "8.8.8.8".parse().unwrap();
        let cloudflare: Ipv4Addr = "1.1.1.1".parse().unwrap();
        let generation = NETWORK_GENERATION.load(Ordering::Acquire);
        remember_reference(
            question.clone(),
            google,
            Some(vec![v4(142, 250, 1, 1)]),
            generation,
        );
        assert_eq!(cached_references(&question), None);
        remember_reference(question.clone(), cloudflare, None, generation);
        assert_eq!(cached_references(&question), Some(vec![v4(142, 250, 1, 1)]));
        remember_reference(
            question.clone(),
            cloudflare,
            Some(vec![v4(142, 250, 1, 1), v4(172, 217, 2, 2)]),
            generation,
        );
        assert_eq!(
            cached_references(&question),
            Some(vec![v4(142, 250, 1, 1), v4(172, 217, 2, 2)])
        );
        // An answer from before a network change is neither served nor stored.
        remember_reference(
            question.clone(),
            google,
            Some(vec![]),
            generation.wrapping_sub(1),
        );
        assert_eq!(cached_references(&question).map(|a| a.len()), Some(2));
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn udp_rules_put_responding_servers_first_and_keep_their_other_addresses_once() {
        let first = Ipv4Addr::new(192, 0, 2, 1);
        let second = Ipv4Addr::new(192, 0, 2, 2);
        let third = Ipv4Addr::new(192, 0, 2, 3);
        let udp = |name: &str, ips| ActiveProvider {
            name: name.into(),
            transport: resolver_pool::Transport::Udp(ips),
        };
        let pool = [udp("a", vec![first, second]), udp("b", vec![first, third])];
        let hit = |idx, server| RaceResult {
            idx,
            server,
            addrs: vec![v4(203, 0, 113, 9)],
            reply: vec![],
        };
        let hits = [hit(0, Some(second)), hit(1, Some(third))];
        assert_eq!(
            substituting_udp_servers(&pool, &hits, &[v4(142, 250, 1, 1)]),
            [second, third, first].map(|ip| ip.to_string())
        );
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
            assert!(super::super::health::probe_ip(addr, "localhost").is_err());
            server.join().unwrap();
        }
        let (addr, server) = super::super::health::tests::server(
            b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
            Duration::ZERO,
        );
        assert!(super::super::health::probe_ip(addr, "localhost").is_err());
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

    // Drive the production collector with scheduled replies and a logical clock.
    // Wall-clock assertions below 300 ms flake on a busy CI runner even when the
    // collector stops at the right event. Unconsumed events prove early return.
    fn scheduled_race(
        messages: Vec<(Duration, RaceMsg)>,
        budget: Duration,
        rule: &Settle,
    ) -> (Vec<RaceResult>, Vec<IpAddr>, Duration, usize) {
        let start = Instant::now();
        let now = std::cell::Cell::new(start);
        let mut messages = std::collections::VecDeque::from(messages);
        let (hits, reference) = collect_race_with(
            |until| {
                if messages.front().is_some_and(|(at, _)| start + *at <= until) {
                    let (at, message) = messages.pop_front().unwrap();
                    now.set(start + at);
                    Some(message)
                } else {
                    now.set(until);
                    None
                }
            },
            || now.get(),
            start + budget,
            Some(rule),
        );
        (hits, reference, now.get() - start, messages.len())
    }

    #[test]
    fn client_lookup_returns_once_no_pending_provider_can_win() {
        let rule = Settle {
            providers: 3,
            wants_address: true,
        };
        let (hits, reference, elapsed, pending) = scheduled_race(
            vec![
                (Duration::ZERO, race_hit(0, vec![v4(142, 250, 1, 1)])),
                (Duration::ZERO, RaceMsg::Done(0)),
                (
                    Duration::from_millis(30),
                    race_hit(1, vec![v4(192, 0, 2, 1)]),
                ),
                (Duration::from_secs(1), RaceMsg::Done(2)),
            ],
            Duration::from_secs(2),
            &rule,
        );
        assert_eq!(elapsed, Duration::from_millis(30));
        assert_eq!(pending, 1);
        assert_eq!(hits[pick_winner(&hits, &reference).unwrap()].idx, 1);
    }

    #[test]
    fn pending_preferred_provider_gets_only_a_short_grace() {
        let rule = Settle {
            providers: 2,
            wants_address: true,
        };
        let (hits, _, elapsed, pending) = scheduled_race(
            vec![
                (Duration::ZERO, race_hit(1, vec![v4(192, 0, 2, 1)])),
                (Duration::ZERO, RaceMsg::Done(1)),
                (Duration::from_millis(100), RaceMsg::Reference(vec![])),
                (
                    Duration::from_secs(1),
                    race_hit(0, vec![v4(198, 51, 100, 1)]),
                ),
            ],
            Duration::from_secs(2),
            &rule,
        );
        assert_eq!(elapsed, PREFERENCE_GRACE);
        assert_eq!(hits.len(), 1);
        assert_eq!(pending, 1);

        let (hits, reference, elapsed, pending) = scheduled_race(
            vec![
                (Duration::ZERO, race_hit(1, vec![v4(192, 0, 2, 1)])),
                (Duration::ZERO, RaceMsg::Done(1)),
                (
                    Duration::from_millis(50),
                    race_hit(0, vec![v4(198, 51, 100, 1)]),
                ),
                (Duration::from_secs(1), RaceMsg::Done(0)),
            ],
            Duration::from_secs(2),
            &rule,
        );
        assert_eq!(elapsed, Duration::from_millis(50));
        assert_eq!(pending, 1);
        assert_eq!(hits[pick_winner(&hits, &reference).unwrap()].idx, 0);
    }

    #[test]
    fn preferred_provider_grace_cannot_extend_the_lookup_deadline() {
        let rule = Settle {
            providers: 2,
            wants_address: true,
        };
        let budget = Duration::from_millis(100);
        let (hits, _, elapsed, pending) = scheduled_race(
            vec![
                (Duration::ZERO, race_hit(1, vec![v4(192, 0, 2, 1)])),
                (PREFERENCE_GRACE, race_hit(0, vec![v4(198, 51, 100, 1)])),
            ],
            budget,
            &rule,
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(elapsed, budget);
        assert_eq!(pending, 1);
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
            pool: format!("test-{name}").into(),
            interface: 0,
            network_generation: NETWORK_GENERATION.load(Ordering::Acquire),
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
        let start = Arc::new(std::sync::Barrier::new(8));
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let key = key.clone();
                let calls = Arc::clone(&calls);
                let start = Arc::clone(&start);
                thread::spawn(move || {
                    start.wait();
                    shared(key, || {
                        calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        thread::sleep(Duration::from_millis(500));
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
            // Model the answer age directly: Windows Instant cannot represent
            // an hour before startup when this test runs soon after boot.
            let guard = PACKETS.lock().unwrap();
            let entry = guard.as_ref().unwrap().get(&key).unwrap();
            match (cached_answer(entry, age), expected) {
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
    fn lookup_threads_are_reused_and_leave_when_idle() {
        let (done, finished) = mpsc::channel();
        let first_thread = Arc::new(Mutex::new(None));
        let seen = Arc::clone(&first_thread);
        let tx = done.clone();
        reuse::run(move || {
            *seen.lock().unwrap() = Some(thread::current().id());
            tx.send(()).unwrap();
        });
        finished.recv_timeout(Duration::from_secs(5)).unwrap();
        // Let the worker list itself as idle, then hand it the next task.
        let deadline = Instant::now() + Duration::from_secs(5);
        while reuse::idle_count() == 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        let second_thread = Arc::new(Mutex::new(None));
        let seen = Arc::clone(&second_thread);
        reuse::run(move || {
            *seen.lock().unwrap() = Some(thread::current().id());
            done.send(()).unwrap();
        });
        finished.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(
            *first_thread.lock().unwrap(),
            *second_thread.lock().unwrap()
        );

        // A worker with nothing to do removes itself and ends.
        let worker = thread::spawn(|| reuse::work(Box::new(|| {}), Duration::from_millis(20)));
        worker.join().unwrap();
    }

    #[test]
    fn popular_answers_are_refreshed_once_before_they_expire() {
        let _serial = CACHE_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        // The fixture answers with TTL 20 s: refresh once under 4 s is left.
        let hit = address_hit("prefetch.test");
        assert!(!expiring_soon(&hit.reply, Duration::from_secs(14)));
        assert!(expiring_soon(&hit.reply, Duration::from_secs(16)));
        let key = test_key("prefetch.test");
        remember(key.clone(), &hit);
        assert!(matches!(cached(&key), Lookup::Fresh(_)));
        {
            let mut guard = PACKETS.lock().unwrap();
            let entry = guard.as_mut().unwrap().get_mut(&key).unwrap();
            entry.at = Instant::now() - Duration::from_secs(17);
        }
        assert!(matches!(cached(&key), Lookup::Expiring(_)));
        // The refresh is already running: later hits are plain fresh answers.
        assert!(matches!(cached(&key), Lookup::Fresh(_)));
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
        let _serial = CACHE_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let mut config = super::super::config::Config::default();
        let pool = resolver_pool::from_config(&config).unwrap();
        let query = build_query("example.test", 1);
        let key = cache_key(&pool, &query, 0);
        assert!(key != cache_key(&pool, &query, 7));
        assert!(key == cache_key(&pool, &build_query("example.test", 2), 0));
        config.doh[0].url = "https://another.test/dns-query".into();
        assert!(key != cache_key(&resolver_pool::from_config(&config).unwrap(), &query, 0));
        config = super::super::config::Config::default();
        config.provider_order = vec!["eu.geohide.ru".into(), "dns-ai.ru".into()];
        assert!(key != cache_key(&resolver_pool::from_config(&config).unwrap(), &query, 0));
        config.disabled_providers.push("dns-ai.ru".into());
        assert!(key != cache_key(&resolver_pool::from_config(&config).unwrap(), &query, 0));
    }

    #[test]
    fn a_reply_from_before_a_route_change_cannot_repopulate_the_dns_cache() {
        let _serial = CACHE_TESTS
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let host = "vpn-switch.test";
        let old = test_key(host);
        remember(old.clone(), &address_hit(host));
        assert!(matches!(cached(&old), Lookup::Fresh(_)));

        invalidate_network_caches();
        let current = test_key(host);
        assert!(old != current);
        remember(old.clone(), &address_hit(host));
        assert!(matches!(cached(&old), Lookup::Miss));
        assert!(matches!(cached(&current), Lookup::Miss));

        remember(current.clone(), &address_hit(host));
        assert!(matches!(cached(&current), Lookup::Fresh(_)));
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
