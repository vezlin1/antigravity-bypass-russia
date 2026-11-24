//! RFC 8484 transport using reqwest's HTTP/2 implementation and certificate validation.
use super::{client, config::DohProvider};
use reqwest::blocking::Client;
use std::{
    collections::HashMap,
    io::Read,
    net::{IpAddr, SocketAddr, UdpSocket},
    sync::{mpsc, Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

pub const TIMEOUT: Duration = Duration::from_millis(2500);
static CLIENTS: OnceLock<Mutex<HashMap<String, Client>>> = OnceLock::new();

pub(super) fn invalidate_connections() {
    if let Some(clients) = CLIENTS.get() {
        if let Ok(mut clients) = clients.lock() {
            clients.clear();
        }
    }
    if let Some(preferred) = PREFERRED_BOOTSTRAP.get() {
        if let Ok(mut preferred) = preferred.lock() {
            preferred.clear();
        }
    }
}

fn source_address(if_index: u32) -> Result<Option<IpAddr>, String> {
    if if_index == 0 {
        return Ok(None);
    }
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    super::socket::bind_socket_to_interface(&socket, if_index)?;
    // UDP connect selects a source address; it sends no DNS packet.
    socket.connect("8.8.8.8:443").map_err(|e| e.to_string())?;
    let ip = socket.local_addr().map_err(|e| e.to_string())?.ip();
    if ip.is_unspecified() {
        Err("DoH: исходящий адрес не определён".into())
    } else {
        Ok(Some(ip))
    }
}

fn http_client(provider: &DohProvider, source: Option<IpAddr>) -> Result<Client, String> {
    let key = format!("{}|{:?}|{:?}", provider.url, provider.bootstrap, source);
    let mut clients = CLIENTS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|e| e.to_string())?;
    if let Some(client) = clients.get(&key) {
        return Ok(client.clone());
    }
    let client = build_http_client(provider, source)?;
    if clients.len() >= 32 {
        clients.clear();
    }
    clients.insert(key, client.clone());
    Ok(client)
}

fn build_http_client(provider: &DohProvider, source: Option<IpAddr>) -> Result<Client, String> {
    let url = reqwest::Url::parse(&provider.url).map_err(|e| e.to_string())?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return Err("DoH требует HTTPS без credentials".into());
    }
    let host = url.host_str().ok_or("DoH: отсутствует hostname")?;
    let port = url.port_or_known_default().ok_or("DoH: отсутствует порт")?;
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(TIMEOUT)
        .timeout(TIMEOUT)
        // A new TLS session through a remote resolver costs hundreds of
        // milliseconds; keep the connection between bursts of lookups.
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_keepalive(Duration::from_secs(30));
    if let Some(ip) = source {
        builder = builder.local_address(ip);
    }
    if !provider.bootstrap.is_empty() {
        let addresses: Vec<_> = provider
            .bootstrap
            .iter()
            .map(|ip| SocketAddr::new(*ip, port))
            .collect();
        builder = builder.resolve_to_addrs(host, &addresses);
    }
    builder
        .build()
        .map_err(|e| format!("DoH client: {}", e.without_url()))
}

#[cfg(windows)]
pub(super) fn query_vpn_bootstrap(
    provider: &DohProvider,
    packet: &[u8],
    tunnel: u32,
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    let mut pinned = provider.clone();
    pinned.bootstrap.retain(|ip| {
        matches!(ip, IpAddr::V4(address) if super::egress::windows_ipv4_route(*address) == Some(tunnel))
    });
    if pinned.bootstrap.is_empty() {
        return Err("DoH: для bootstrap нет маршрута через текущий VPN".into());
    }

    // Use the VPN source address on a fresh client and explicit bootstrap IPs.
    // In particular, never invoke the ordinary system-DNS retry here.
    let source = source_address(tunnel)?.ok_or("DoH: не найден адрес интерфейса VPN")?;
    let client = build_http_client(&pinned, Some(source))?;
    exchange_until(&client, &pinned.url, packet, deadline)
}

#[cfg(test)]
fn exchange(client: &Client, url: &str, query: &[u8]) -> Result<Vec<u8>, String> {
    exchange_until(client, url, query, Instant::now() + TIMEOUT)
}

fn exchange_until(
    client: &Client,
    url: &str,
    query: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or("DoH: deadline expired")?;
    let response = client
        .post(url)
        .timeout(remaining)
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .body(query.to_vec())
        .send()
        .map_err(|e| format!("DoH transport: {}", e.without_url()))?;
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let mut body = Vec::new();
    response
        .take(65_536)
        .read_to_end(&mut body)
        .map_err(|e| format!("DoH body: {e}"))?;
    validate_answer(query, status, &content_type, &body)?;
    Ok(body)
}

/// Start the system-DNS candidate only after the pinned bootstrap addresses
/// stayed silent for this long. A healthy bootstrap keeps priority and the
/// endpoint name is not leaked to the system resolver on every query.
const SYSTEM_DNS_DELAY: Duration = Duration::from_millis(750);
const ANSWER_GRACE: Duration = Duration::from_millis(300);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum AnswerQuality {
    DnsError,
    NoAddress,
    Ordinary,
    Preferred,
}

// The TLS probe during route setup verifies each candidate. Here we can only
// distinguish DNS evidence, using the same Google ranges as the provider race.
fn answer_quality(answer: &[u8]) -> AnswerQuality {
    if !client::is_successful_response(answer) {
        return AnswerQuality::DnsError;
    }
    let Some(qtype @ (1 | 28)) = client::question_type(answer) else {
        return AnswerQuality::Preferred;
    };
    let agent = client::question_name(answer).is_some_and(|name| {
        super::provider::NRPT_AGENT
            .iter()
            .any(|host| host.eq_ignore_ascii_case(&name))
    });
    let mut quality = AnswerQuality::NoAddress;
    for ip in client::answer_addrs(answer) {
        if ip.is_ipv4() != (qtype == 1) {
            continue;
        }
        if !agent {
            return AnswerQuality::Preferred;
        }
        if ip.is_unspecified()
            || ip.is_loopback()
            || ip.is_multicast()
            || matches!(ip, IpAddr::V4(v4) if v4.is_broadcast())
        {
            continue;
        }
        if !super::resolvers::looks_google(&ip) {
            return AnswerQuality::Preferred;
        }
        quality = AnswerQuality::Ordinary;
    }
    quality
}

pub fn query(provider: &DohProvider, query: &[u8], if_index: u32) -> Result<Vec<u8>, String> {
    let source = source_address(if_index)?;
    let query = query.to_vec();
    race_exchanges(
        provider,
        TIMEOUT + Duration::from_millis(100),
        SYSTEM_DNS_DELAY,
        move |candidate, deadline| {
            http_client(&candidate, source)
                .and_then(|client| exchange_until(&client, &candidate.url, &query, deadline))
        },
    )
}

#[derive(Clone, Copy)]
enum Attempt {
    Bootstrap(IpAddr),
    System,
}

/// A further bootstrap address starts only if the earlier ones stay silent this
/// long (or fail), instead of every address receiving every query.
const BOOTSTRAP_STAGGER: Duration = Duration::from_millis(200);

/// The bootstrap address that answered last, per provider, tried first.
static PREFERRED_BOOTSTRAP: OnceLock<Mutex<HashMap<String, IpAddr>>> = OnceLock::new();

fn bootstrap_key(provider: &DohProvider) -> String {
    format!("{}|{:?}", provider.url, provider.bootstrap)
}

fn preferred_bootstrap(provider: &DohProvider) -> Option<IpAddr> {
    PREFERRED_BOOTSTRAP
        .get()?
        .lock()
        .ok()?
        .get(&bootstrap_key(provider))
        .copied()
}

fn remember_bootstrap(provider: &DohProvider, address: IpAddr) {
    if let Ok(mut preferred) = PREFERRED_BOOTSTRAP
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
    {
        if preferred.len() >= 32 {
            preferred.clear();
        }
        preferred.insert(bootstrap_key(provider), address);
    }
}

fn race_exchanges(
    provider: &DohProvider,
    budget: Duration,
    system_delay: Duration,
    exchange: impl Fn(DohProvider, Instant) -> Result<Vec<u8>, String> + Send + Sync + 'static,
) -> Result<Vec<u8>, String> {
    let started = Instant::now();
    let deadline = started + budget;
    let fallback_at = started + system_delay;
    let exchange = Arc::new(exchange);
    let (tx, rx) = mpsc::channel();
    let start = |attempt, candidate| {
        spawn_exchange(&tx, attempt, candidate, deadline, Arc::clone(&exchange));
    };
    // The address that answered last goes first; the rest keep their order.
    let mut queue = provider.bootstrap.clone();
    if let Some(preferred) = preferred_bootstrap(provider) {
        if let Some(position) = queue.iter().position(|ip| *ip == preferred) {
            let preferred = queue.remove(position);
            queue.insert(0, preferred);
        }
    }
    let mut queue = std::collections::VecDeque::from(queue);
    // When the most recent bootstrap address was started, relative to the race.
    let last_start = std::cell::Cell::new(started);
    let start_next_bootstrap = |queue: &mut std::collections::VecDeque<IpAddr>| {
        let Some(ip) = queue.pop_front() else {
            return false;
        };
        let mut candidate = provider.clone();
        candidate.bootstrap = vec![ip];
        start(Attempt::Bootstrap(ip), candidate);
        last_start.set(Instant::now());
        true
    };
    // Unstarted addresses count as pending: the system fallback still waits
    // for every bootstrap address to fail or for its own delay.
    let mut bootstrap_pending = provider.bootstrap.len();
    let mut next_stagger =
        start_next_bootstrap(&mut queue).then(|| Instant::now() + BOOTSTRAP_STAGGER);
    let mut system = provider.clone();
    system.bootstrap.clear();
    let mut system_started = bootstrap_pending == 0;
    let mut system_pending = system_started;
    if system_started {
        start(Attempt::System, system.clone());
    }
    let mut bootstrap_error = None;
    let mut system_error = None;
    let mut best: Option<(AnswerQuality, Vec<u8>, Option<IpAddr>)> = None;
    let mut settle_at = deadline;
    loop {
        let now = Instant::now();
        if now >= settle_at {
            break;
        }
        if next_stagger.is_some_and(|at| now >= at) {
            next_stagger = start_next_bootstrap(&mut queue).then(|| now + BOOTSTRAP_STAGGER);
        }
        let may_start_system = !system_started
            && best
                .as_ref()
                .is_none_or(|(quality, _, _)| *quality < AnswerQuality::Ordinary);
        if may_start_system && (bootstrap_pending == 0 || now >= fallback_at) {
            // Fast failures need no artificial delay; silent addresses still
            // get the bootstrap preference window. All attempts share a deadline.
            start(Attempt::System, system.clone());
            system_started = true;
            system_pending = true;
        }
        if bootstrap_pending == 0 && !system_pending {
            break;
        }
        let mut until = if may_start_system && !system_started {
            settle_at.min(fallback_at)
        } else {
            settle_at
        };
        if let Some(at) = next_stagger {
            until = until.min(at);
        }
        match rx.recv_timeout(until.saturating_duration_since(Instant::now())) {
            Ok((attempt, result)) => {
                let source = match attempt {
                    Attempt::Bootstrap(ip) => {
                        bootstrap_pending -= 1;
                        Some(ip)
                    }
                    Attempt::System => {
                        system_pending = false;
                        None
                    }
                };
                match result {
                    Ok(answer) => {
                        let quality = answer_quality(&answer);
                        if quality == AnswerQuality::Preferred {
                            if let Some(ip) = source {
                                remember_bootstrap(provider, ip);
                            }
                            return Ok(answer);
                        }
                        // A weaker answer: let every remaining address compete.
                        // The usual grace is extended only by how much later
                        // than the race the last address actually started, so
                        // each one gets the run time it had without staggering.
                        while start_next_bootstrap(&mut queue) {}
                        next_stagger = None;
                        if best.as_ref().is_none_or(|(old, _, _)| quality > *old) {
                            best = Some((quality, answer, source));
                            if quality == AnswerQuality::Ordinary {
                                let now = Instant::now();
                                let start_delay = last_start.get() - started;
                                settle_at = deadline.min(now + ANSWER_GRACE + start_delay);
                            }
                        }
                    }
                    Err(error) => {
                        if source.is_some() {
                            // Do not wait for the stagger after a failure.
                            if start_next_bootstrap(&mut queue) {
                                next_stagger = Some(Instant::now() + BOOTSTRAP_STAGGER);
                            }
                            bootstrap_error = Some(error);
                        } else {
                            system_error = Some(error);
                        }
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    if let Some((_, answer, source)) = best {
        if let Some(ip) = source {
            remember_bootstrap(provider, ip);
        }
        return Ok(answer);
    }
    let timeout = "DoH: deadline expired";
    if provider.bootstrap.is_empty() {
        Err(system_error.unwrap_or_else(|| timeout.into()))
    } else {
        // A bootstrap result can arrive after the system attempt. Tagging the
        // source keeps diagnostics correct regardless of completion order.
        Err(format!(
            "bootstrap: {}; через системный DNS: {}",
            bootstrap_error.as_deref().unwrap_or(timeout),
            system_error.as_deref().unwrap_or(timeout)
        ))
    }
}

fn spawn_exchange(
    tx: &mpsc::Sender<(Attempt, Result<Vec<u8>, String>)>,
    attempt: Attempt,
    provider: DohProvider,
    deadline: Instant,
    exchange: Arc<impl Fn(DohProvider, Instant) -> Result<Vec<u8>, String> + Send + Sync + 'static>,
) {
    let worker_tx = tx.clone();
    if let Err(error) = std::thread::Builder::new()
        .name("antigravity-doh".into())
        .spawn(move || {
            let result = if Instant::now() >= deadline {
                Err("DoH: deadline expired".into())
            } else {
                exchange(provider, deadline)
            };
            let _ = worker_tx.send((attempt, result));
        })
    {
        let _ = tx.send((attempt, Err(format!("DoH worker: {error}"))));
    }
}

fn validate_answer(
    query: &[u8],
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<(), String> {
    if status != 200 {
        return Err(format!("DoH HTTP {status}"));
    }
    if !content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .eq_ignore_ascii_case("application/dns-message")
    {
        return Err("DoH: неверный Content-Type".into());
    }
    if body.len() > 65_535 || !client::response_matches(query, body) {
        return Err("DoH: ответ не соответствует DNS-запросу".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn provider(bootstrap: bool) -> DohProvider {
        DohProvider {
            name: "test-doh".into(),
            url: "https://resolver.invalid/dns-query".into(),
            bootstrap: if bootstrap {
                vec!["192.0.2.1".parse().unwrap()]
            } else {
                vec![]
            },
        }
    }

    fn a_reply(host: &str, ip: [u8; 4]) -> Vec<u8> {
        client::address_response(&client::build_query(host, 71), &[ip.into()]).unwrap()
    }

    #[test]
    fn bootstrap_addresses_are_staggered_and_the_last_winner_goes_first() {
        let mut p = provider(true);
        p.url = "https://stagger.invalid/dns-query".into();
        p.bootstrap.push("192.0.2.2".parse().unwrap());
        let first: IpAddr = "192.0.2.1".parse().unwrap();
        let second: IpAddr = "192.0.2.2".parse().unwrap();
        let reply = a_reply("example.test", [192, 0, 2, 9]);

        // A healthy first address answers alone.
        let calls = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&calls);
        let answer = reply.clone();
        race_exchanges(&p, TIMEOUT, SYSTEM_DNS_DELAY, move |candidate, _| {
            seen.lock().unwrap().push(candidate.bootstrap.clone());
            Ok(answer.clone())
        })
        .unwrap();
        assert_eq!(*calls.lock().unwrap(), [vec![first]]);

        // A silent first address hands over after the stagger, not at once.
        let calls = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&calls);
        let answer = reply.clone();
        let started = Instant::now();
        race_exchanges(&p, TIMEOUT, SYSTEM_DNS_DELAY, move |candidate, _| {
            seen.lock()
                .unwrap()
                .push((candidate.bootstrap.clone(), started.elapsed()));
            if candidate.bootstrap == [first] {
                std::thread::sleep(Duration::from_millis(600));
                Err("silent".into())
            } else {
                Ok(answer.clone())
            }
        })
        .unwrap();
        assert!(started.elapsed() < Duration::from_millis(500));
        let calls = calls.lock().unwrap().clone();
        assert_eq!(calls[1].0, [second]);
        assert!(calls[1].1 >= BOOTSTRAP_STAGGER - Duration::from_millis(20));

        // The address that answered is tried first next time.
        let calls = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&calls);
        race_exchanges(&p, TIMEOUT, SYSTEM_DNS_DELAY, move |candidate, _| {
            seen.lock().unwrap().push(candidate.bootstrap.clone());
            Ok(reply.clone())
        })
        .unwrap();
        assert_eq!(*calls.lock().unwrap(), [vec![second]]);
    }

    #[test]
    fn a_staggered_silent_address_does_not_stretch_the_answer_grace() {
        let host = "cloudcode-pa.googleapis.com";
        let mut p = provider(true);
        p.url = "https://grace.invalid/dns-query".into();
        p.bootstrap.push("192.0.2.2".parse().unwrap());
        let first: IpAddr = "192.0.2.1".parse().unwrap();
        let started = Instant::now();
        let answer = race_exchanges(&p, TIMEOUT, Duration::from_secs(2), move |candidate, _| {
            if candidate.bootstrap == [first] {
                std::thread::sleep(Duration::from_millis(600));
                Ok(a_reply(host, [142, 250, 1, 1]))
            } else {
                std::thread::sleep(Duration::from_secs(3));
                Err("silent".into())
            }
        })
        .unwrap();
        let elapsed = started.elapsed();
        assert_eq!(answer, a_reply(host, [142, 250, 1, 1]));
        // 600 ms answer + 300 ms grace + 200 ms start delay of the second
        // address; adding the whole first wait would end near 1.5 s.
        assert!(elapsed >= Duration::from_millis(1000), "{elapsed:?}");
        assert!(elapsed < Duration::from_millis(1300), "{elapsed:?}");
    }

    #[test]
    fn unusable_agent_addresses_rank_below_a_normal_google_reply() {
        let host = "cloudcode-pa.googleapis.com";
        for ip in [[0, 0, 0, 0], [127, 0, 0, 1], [255; 4], [224, 0, 0, 1]] {
            assert!(
                answer_quality(&a_reply(host, ip))
                    < answer_quality(&a_reply(host, [142, 250, 1, 1]))
            );
        }
        assert!(
            answer_quality(&a_reply("other.test", [142, 250, 1, 1])) == AnswerQuality::Preferred
        );
    }

    #[test]
    fn agent_bootstraps_prefer_the_slower_route_over_passthrough_or_empty_dns() {
        let host = "daily-cloudcode-pa.googleapis.com";
        let query = client::build_query(host, 71);
        let mut p = provider(true);
        p.bootstrap.push("192.0.2.2".parse().unwrap());
        let route = a_reply(host, [203, 0, 113, 9]);
        for first in [
            a_reply(host, [172, 217, 1, 1]),
            client::nodata_response(&query),
            client::servfail_response(&query),
        ] {
            let second = route.clone();
            let answer = race_exchanges(&p, TIMEOUT, SYSTEM_DNS_DELAY, move |candidate, _| {
                if candidate.bootstrap == ["192.0.2.1".parse::<IpAddr>().unwrap()] {
                    Ok(first.clone())
                } else {
                    assert!(!candidate.bootstrap.is_empty());
                    std::thread::sleep(Duration::from_millis(25));
                    Ok(second.clone())
                }
            })
            .unwrap();
            assert_eq!(answer, route);
        }
    }

    #[test]
    fn healthy_bootstrap_does_not_start_a_system_lookup() {
        let calls = Arc::new(AtomicUsize::new(0));
        let worker_calls = Arc::clone(&calls);
        let answer = race_exchanges(
            &provider(true),
            Duration::from_secs(2),
            Duration::from_secs(1),
            move |candidate, _| {
                assert!(!candidate.bootstrap.is_empty());
                worker_calls.fetch_add(1, Ordering::SeqCst);
                Ok(a_reply("example.test", [192, 0, 2, 1]))
            },
        )
        .unwrap();
        assert_eq!(answer, a_reply("example.test", [192, 0, 2, 1]));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn keeps_the_passthrough_answer_when_the_other_bootstrap_stalls() {
        let host = "cloudcode-pa.googleapis.com";
        let mut p = provider(true);
        p.bootstrap.push("192.0.2.2".parse().unwrap());
        let (finished, wait) = mpsc::channel();
        let wait = Mutex::new(wait);
        let answer = race_exchanges(
            &p,
            Duration::from_secs(3),
            Duration::from_secs(2),
            move |candidate, _| {
                if candidate.bootstrap == ["192.0.2.1".parse::<IpAddr>().unwrap()] {
                    Ok(a_reply(host, [142, 250, 1, 1]))
                } else {
                    // A regression waiting for the whole budget selects this later answer.
                    let _ = wait.lock().unwrap().recv_timeout(Duration::from_secs(1));
                    Ok(a_reply(host, [203, 0, 113, 9]))
                }
            },
        )
        .unwrap();
        let _ = finished.send(());
        assert_eq!(answer, a_reply(host, [142, 250, 1, 1]));
    }

    #[test]
    fn failed_bootstraps_start_fallback_without_waiting_for_the_delay() {
        let answer = race_exchanges(
            &provider(true),
            Duration::from_millis(300),
            Duration::from_secs(2),
            |candidate, _| {
                if candidate.bootstrap.is_empty() {
                    Ok(a_reply("example.test", [192, 0, 2, 2]))
                } else {
                    Err("retired bootstrap".into())
                }
            },
        )
        .unwrap();
        assert_eq!(answer, a_reply("example.test", [192, 0, 2, 2]));
    }

    #[test]
    fn silent_bootstrap_does_not_prevent_the_system_fallback_from_winning() {
        let started = Instant::now();
        let answer = race_exchanges(
            &provider(true),
            Duration::from_millis(300),
            Duration::from_millis(30),
            |candidate, deadline| {
                if !candidate.bootstrap.is_empty() {
                    std::thread::sleep(Duration::from_millis(450));
                    Err("bootstrap timeout".into())
                } else {
                    // The fallback inherits the original deadline, rather than
                    // starting another full provider budget after the delay.
                    assert!(
                        deadline.saturating_duration_since(Instant::now())
                            < Duration::from_millis(290)
                    );
                    Ok(a_reply("example.test", [192, 0, 2, 3]))
                }
            },
        )
        .unwrap();
        assert_eq!(answer, a_reply("example.test", [192, 0, 2, 3]));
        assert!(started.elapsed() < Duration::from_millis(400));
    }

    #[test]
    fn errors_keep_their_source_even_when_bootstrap_finishes_last() {
        let error = race_exchanges(
            &provider(true),
            Duration::from_secs(1),
            Duration::from_millis(10),
            |candidate, _| {
                if candidate.bootstrap.is_empty() {
                    Err("SYSTEM_FAILURE".into())
                } else {
                    std::thread::sleep(Duration::from_millis(50));
                    Err("BOOTSTRAP_FAILURE".into())
                }
            },
        )
        .unwrap_err();
        assert_eq!(
            error,
            "bootstrap: BOOTSTRAP_FAILURE; через системный DNS: SYSTEM_FAILURE"
        );
    }

    #[test]
    fn provider_without_bootstrap_runs_only_one_system_attempt() {
        let calls = Arc::new(AtomicUsize::new(0));
        let worker_calls = Arc::clone(&calls);
        let error = race_exchanges(
            &provider(false),
            Duration::from_secs(1),
            SYSTEM_DNS_DELAY,
            move |candidate, _| {
                assert!(candidate.bootstrap.is_empty());
                worker_calls.fetch_add(1, Ordering::SeqCst);
                Err("system unavailable".into())
            },
        )
        .unwrap_err();
        assert_eq!(error, "system unavailable");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn stalled_attempts_share_one_caller_deadline() {
        let started = Instant::now();
        assert!(race_exchanges(
            &provider(true),
            Duration::from_millis(80),
            Duration::from_millis(10),
            |_, _| {
                std::thread::sleep(Duration::from_millis(400));
                Err("too late".into())
            },
        )
        .is_err());
        assert!(started.elapsed() < Duration::from_millis(250));
    }

    #[test]
    fn doh_posts_wire_dns_over_verified_tls_and_checks_the_binary_response() {
        let query = client::build_query("example.test", 71);
        let answer = client::nodata_response(&query);
        let mut response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", answer.len()).into_bytes();
        response.extend_from_slice(&answer);
        let (addr, server) = super::super::health::tests::server(response, Duration::ZERO);
        let cert =
            reqwest::Certificate::from_der(&super::super::health::tests::identity().0).unwrap();
        let client = Client::builder()
            .no_proxy()
            .add_root_certificate(cert)
            .resolve("localhost", addr)
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let result = exchange(
            &client,
            &format!("https://localhost:{}/dns-query", addr.port()),
            &query,
        );
        assert_eq!(result.unwrap(), answer);
        server.join().unwrap();
    }
    #[test]
    fn rejects_http_error_wrong_question_transaction_and_oversized_payload() {
        let query = client::build_query("example.test", 42);
        let reply = client::nodata_response(&query);
        assert!(validate_answer(&query, 200, "application/dns-message", &reply).is_ok());
        for (status, mime) in [(503, "application/dns-message"), (200, "text/html")] {
            assert!(validate_answer(&query, status, mime, &reply).is_err());
        }
        let mut wrong = reply.clone();
        wrong[1] ^= 1;
        assert!(validate_answer(&query, 200, "application/dns-message", &wrong).is_err());
        let other = client::nodata_response(&client::build_query("other.test", 42));
        assert!(validate_answer(&query, 200, "application/dns-message", &other).is_err());
        let mut big = reply;
        big.resize(65_536, 0);
        assert!(validate_answer(&query, 200, "application/dns-message", &big).is_err());
    }
}
