//! A per-user HTTPS proxy for clients launched from Windows full setup.
//! Normal requests use Windows routing. The DoH fallback requires a usable
//! VPN route for both its bootstrap server and the destination.
use super::{client, dns_https, egress, provider, relay, resolver_pool};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::os::windows::io::AsRawSocket;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_HEADER: usize = 8192;
const MAX_CONNECTIONS: usize = 48;
const HEADER_TIMEOUT: Duration = Duration::from_secs(3);
const DIAL_TIMEOUT: Duration = Duration::from_secs(7);
const RANKED_PROBE_BUDGET: Duration = Duration::from_millis(2400);
const CONNECT_BUDGET: Duration = Duration::from_millis(900);
const DNS_RECHECK: Duration = Duration::from_secs(1);
const VERIFIED_TTL: Duration = Duration::from_secs(60);
const VERIFIED_LIMIT: usize = 64;
const ENABLED_VALUE: &[u8] = b"connect-v1\n";

fn activation_path() -> std::path::PathBuf {
    super::config::directory().join("connect.enabled")
}

pub fn enabled() -> bool {
    std::fs::read(activation_path()).is_ok_and(|contents| contents == ENABLED_VALUE)
}

pub fn enable() -> Result<(), String> {
    std::fs::create_dir_all(super::config::directory()).map_err(|error| error.to_string())?;
    crate::system::fs_utils::robust_write_file(&activation_path(), ENABLED_VALUE)
}

pub fn disable() -> Result<(), String> {
    match std::fs::remove_file(activation_path()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

pub fn fallback_available() -> bool {
    vpn_present() && matches!(relay::local_dns_available(), Ok(false))
}

pub fn vpn_present() -> bool {
    egress::windows_vpn_route().is_some()
}

pub fn verify_fallback(host: &str) -> Result<(), String> {
    dial_vpn(host).map(drop)
}

#[derive(Debug, PartialEq, Eq)]
enum Request {
    Pac,
    Connect(String),
}

fn parse_request(line: &str) -> Option<Request> {
    let mut parts = line.split_ascii_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    if !matches!(parts.next(), Some("HTTP/1.0" | "HTTP/1.1")) || parts.next().is_some() {
        return None;
    }
    if method == "GET" && target == "/proxy.pac" {
        return Some(Request::Pac);
    }
    let host = target.strip_suffix(":443")?.trim_end_matches('.');
    if method != "CONNECT"
        || !host.contains('.')
        || host.len() > 253
        || host.parse::<IpAddr>().is_ok()
        || !host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return None;
    }
    Some(Request::Connect(host.to_ascii_lowercase()))
}

fn matches_domain(host: &str, rule: &str) -> bool {
    host == rule.trim_start_matches('.') || (rule.starts_with('.') && host.ends_with(rule))
}

fn browser_destination(host: &str) -> bool {
    provider::NRPT_STUDIO
        .iter()
        .any(|rule| matches_domain(host, rule))
}

fn ai_destination(host: &str) -> bool {
    provider::NRPT_AGENT.contains(&host) || browser_destination(host)
}

fn pac(port: u16) -> String {
    let rules = serde_json::to_string(&provider::nrpt_domains()).expect("static domain names");
    format!(
        r#"function FindProxyForURL(url, host) {{
  if (url.substring(0, 6) !== "https:") return "DIRECT";
  host = host.toLowerCase().replace(/\.$/, "");
  var rules = {rules};
  for (var i = 0; i < rules.length; i++) {{
    var rule = rules[i];
    if (rule.charAt(0) === "." ? host === rule.substring(1) || dnsDomainIs(host, rule) : host === rule)
      return "PROXY 127.0.0.1:{port}";
  }}
  return "DIRECT";
}}"#
    )
}

fn public_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            let [first, second, ..] = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || first == 0
                || first >= 224
                || (first == 100 && (64..128).contains(&second)))
        }
        // Allow globally routed IPv6, excluding mapped, tunneled and local forms.
        IpAddr::V6(ip) => (ip.segments()[0] & 0xe000) == 0x2000,
    }
}

type Dial<'a> = dyn Fn(&str) -> Result<TcpStream, String> + Sync + 'a;

#[derive(Default)]
struct DnsRoute {
    cached: Option<(Instant, bool)>,
    using_vpn_fallback: bool,
}

impl DnsRoute {
    fn update(&mut self, dns_blocked: Option<bool>, vpn_present: bool, browser: bool) -> bool {
        // During a tunnel reconnect, keep waiting for the guarded path while
        // local DNS is still blocked. A healthy DNS probe returns to Windows.
        if browser && vpn_present {
            self.using_vpn_fallback = true;
        } else if let Some(blocked) = dns_blocked {
            self.using_vpn_fallback = blocked && (vpn_present || self.using_vpn_fallback);
        }
        self.using_vpn_fallback
    }

    fn vpn_needed(&mut self, browser: bool) -> bool {
        if let Some((checked, vpn_only)) = self.cached {
            if checked.elapsed() < DNS_RECHECK {
                return vpn_only;
            }
        }
        let vpn = vpn_present();
        let dns_blocked = if browser && vpn {
            None
        } else {
            relay::local_dns_available()
                .ok()
                .map(|available| !available)
        };
        let vpn_only = self.update(dns_blocked, vpn, browser);
        self.cached = Some((Instant::now(), vpn_only));
        vpn_only
    }
}

fn dial_destination(
    host: &str,
    dns_blocked: bool,
    system: &Dial<'_>,
    vpn: &Dial<'_>,
) -> Result<TcpStream, String> {
    if dns_blocked && ai_destination(host) {
        vpn(host)
    } else {
        system(host)
    }
}

fn dial_system(host: &str) -> Result<TcpStream, String> {
    let addresses = (host, 443).to_socket_addrs().map_err(|e| e.to_string())?;
    let deadline = Instant::now() + DIAL_TIMEOUT;
    addresses
        .filter(|address| public_address(address.ip()))
        .take(8)
        .find_map(|address| {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            TcpStream::connect_timeout(&address, remaining.min(CONNECT_BUDGET)).ok()
        })
        .ok_or_else(|| "Назначение недоступно по маршрутам Windows".into())
}

fn on_tunnel(address: Ipv4Addr, tunnel: u32) -> bool {
    egress::windows_vpn_route() == Some(tunnel)
        && egress::windows_ipv4_route(address) == Some(tunnel)
}

fn connect_through_tunnel(
    address: Ipv4Addr,
    tunnel: u32,
    deadline: Instant,
) -> Result<TcpStream, String> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() || !on_tunnel(address, tunnel) {
        return Err("Нет маршрута к назначению через текущий VPN".into());
    }
    let socket =
        Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).map_err(|e| e.to_string())?;
    super::socket::bind_ipv4_interface(socket.as_raw_socket(), tunnel)?;
    let target = SockAddr::from(SocketAddr::from((address, 443)));
    socket
        .connect_timeout(&target, remaining.min(CONNECT_BUDGET))
        .map_err(|e| e.to_string())?;
    if !on_tunnel(address, tunnel) {
        return Err("Маршрут через VPN изменился во время подключения".into());
    }
    Ok(socket.into())
}

type VerifiedKey = (Ipv4Addr, String, u32);

/// Addresses that recently passed the TLS/HTTP probe for a host through a
/// particular tunnel. A browser page opens many connections; probing each one
/// doubles the handshakes and page requests seen by Google.
struct VerifiedRoutes {
    entries: Vec<(VerifiedKey, Instant)>,
}

impl VerifiedRoutes {
    const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    fn prune(&mut self, now: Instant) {
        self.entries
            .retain(|(_, verified)| now.saturating_duration_since(*verified) < VERIFIED_TTL);
    }

    fn fresh(&mut self, key: &VerifiedKey, now: Instant) -> bool {
        self.prune(now);
        self.entries.iter().any(|(entry, _)| entry == key)
    }

    fn record(&mut self, key: VerifiedKey, now: Instant) {
        self.prune(now);
        self.entries.retain(|(entry, _)| *entry != key);
        if self.entries.len() >= VERIFIED_LIMIT {
            self.entries.remove(0);
        }
        self.entries.push((key, now));
    }

    fn forget(&mut self, key: &VerifiedKey) {
        self.entries.retain(|(entry, _)| entry != key);
    }
}

static VERIFIED: Mutex<VerifiedRoutes> = Mutex::new(VerifiedRoutes::new());

fn verified_routes() -> std::sync::MutexGuard<'static, VerifiedRoutes> {
    VERIFIED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn verify_then_connect(
    address: Ipv4Addr,
    host: &str,
    tunnel: u32,
    deadline: Instant,
) -> Option<TcpStream> {
    let key = (address, host.to_owned(), tunnel);
    if verified_routes().fresh(&key, Instant::now()) {
        let stream = connect_through_tunnel(address, tunnel, deadline).ok();
        if stream.is_none() {
            verified_routes().forget(&key);
        }
        return stream;
    }
    let probe = connect_through_tunnel(address, tunnel, deadline).ok()?;
    let probe_deadline = deadline.min(Instant::now() + Duration::from_millis(1500));
    match provider::BROWSER_PAGES
        .iter()
        .find(|(page, _)| *page == host)
    {
        Some((_, path)) => {
            super::health::probe_browser_connected(probe, host, path, probe_deadline).ok()?
        }
        None => {
            super::health::probe_connected(probe, host, probe_deadline).ok()?;
        }
    }
    verified_routes().record(key, Instant::now());
    connect_through_tunnel(address, tunnel, deadline).ok()
}

fn dial_vpn(host: &str) -> Result<TcpStream, String> {
    let tunnel =
        egress::windows_vpn_route().ok_or("Нет подтверждённого системного маршрута VPN")?;
    // Setup already found these addresses through the system route. They still
    // need a fresh TLS probe bound to the current tunnel before use.
    let ranked_deadline = Instant::now() + RANKED_PROBE_BUDGET;
    if let Some(stream) = super::rank::saved_addresses(host)
        .into_iter()
        .filter(|ip| public_address(IpAddr::V4(*ip)))
        .find_map(|ip| verify_then_connect(ip, host, tunnel, ranked_deadline))
    {
        return Ok(stream);
    }

    let pool = resolver_pool::load()?;
    if browser_destination(host) {
        // Only try frontends belonging to the configured provider. Prefer its
        // addresses verified during setup, and probe the browser hostname anew.
        let seeds: Vec<Ipv4Addr> = super::rank::geohide_proxy_seeds(&pool)
            .iter()
            .filter_map(|seed| seed.parse().ok())
            .collect();
        let deadline = Instant::now() + RANKED_PROBE_BUDGET;
        let mut tried = std::collections::HashSet::new();
        if let Some(stream) = super::rank::saved_addresses(provider::DAILY_CLOUD_CODE)
            .into_iter()
            .filter(|address| seeds.contains(address))
            .chain(seeds.iter().copied())
            .filter(|address| tried.insert(*address))
            .find_map(|address| verify_then_connect(address, host, tunnel, deadline))
        {
            return Ok(stream);
        }
    }

    let deadline = Instant::now() + DIAL_TIMEOUT;
    let packet = client::build_query(host, 0xa641);
    let mut tried = std::collections::HashSet::new();
    for provider in pool {
        let resolver_pool::Transport::Doh(doh) = &provider.transport else {
            continue;
        };
        if Instant::now() >= deadline || egress::windows_vpn_route() != Some(tunnel) {
            break;
        }
        let deadline_for_dns = deadline.min(Instant::now() + dns_https::TIMEOUT);
        let Ok(reply) = dns_https::query_vpn_bootstrap(doh, &packet, tunnel, deadline_for_dns)
        else {
            continue;
        };
        let candidates = client::answer_addrs(&reply)
            .into_iter()
            .filter(|&ip| public_address(ip))
            .filter_map(|ip| match ip {
                IpAddr::V4(address) => Some(address),
                IpAddr::V6(_) => None,
            });
        if let Some(stream) = candidates
            .filter(|ip| tried.insert(*ip))
            .take(6)
            .find_map(|ip| verify_then_connect(ip, host, tunnel, deadline))
        {
            return Ok(stream);
        }
    }
    Err("Проверенное назначение через VPN недоступно".into())
}

fn read_request(stream: &mut TcpStream) -> io::Result<(Option<Request>, Vec<u8>)> {
    let deadline = Instant::now() + HEADER_TIMEOUT;
    let mut bytes = Vec::with_capacity(1024);
    let mut buffer = [0; 1024];
    while bytes.len() < MAX_HEADER {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        stream.set_read_timeout(Some(remaining))?;
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(end) = memchr::memmem::find(&bytes, b"\r\n\r\n") {
            if end > MAX_HEADER {
                break;
            }
            let header = std::str::from_utf8(&bytes[..end]).ok();
            let request = header.and_then(|header| parse_request(header.split("\r\n").next()?));
            return Ok((request, bytes.split_off(end + 4)));
        }
    }
    Ok((None, Vec::new()))
}

fn forward(mut client: TcpStream, mut upstream: TcpStream, first: &[u8]) -> io::Result<()> {
    client.set_read_timeout(None)?;
    let _ = client.set_nodelay(true);
    let _ = upstream.set_nodelay(true);
    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    upstream.write_all(first)?;
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let result = io::copy(&mut &client, &mut &upstream);
            let _ = upstream.shutdown(if result.is_ok() {
                Shutdown::Write
            } else {
                Shutdown::Both
            });
        });
        let result = io::copy(&mut &upstream, &mut &client);
        let _ = client.shutdown(if result.is_ok() {
            Shutdown::Write
        } else {
            Shutdown::Both
        });
    });
    Ok(())
}

fn handle(mut stream: TcpStream, port: u16, dial: &Dial<'_>) -> io::Result<()> {
    stream.set_write_timeout(Some(HEADER_TIMEOUT))?;
    let (request, buffered) = read_request(&mut stream)?;
    match request {
        Some(Request::Pac) => {
            let script = pac(port);
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{script}", script.len())
        }
        Some(Request::Connect(host)) => match dial(&host) {
            Ok(upstream) => {
                stream.set_write_timeout(None)?;
                forward(stream, upstream, &buffered)
            }
            Err(_) => stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"),
        },
        None => stream.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"),
    }
}

pub fn listen(browser: bool) -> io::Result<u16> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    let dns = Arc::new(Mutex::new(DnsRoute::default()));
    let active = Arc::new(AtomicUsize::new(0));
    std::thread::Builder::new()
        .name("local-connect".into())
        .spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                if active
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                        (count < MAX_CONNECTIONS).then_some(count + 1)
                    })
                    .is_err()
                {
                    continue;
                }
                let workers = Arc::clone(&active);
                let dns = Arc::clone(&dns);
                if std::thread::Builder::new()
                    .spawn(move || {
                        let dial = |host: &str| {
                            let blocked = enabled()
                                && ai_destination(host)
                                && dns.lock().is_ok_and(|mut state| state.vpn_needed(browser));
                            dial_destination(host, blocked, &dial_system, &dial_vpn)
                        };
                        if let Err(error) = handle(stream, port, &dial) {
                            relay::log_event(&format!("Локальный CONNECT: {error}"));
                        }
                        workers.fetch_sub(1, Ordering::Relaxed);
                    })
                    .is_err()
                {
                    active.fetch_sub(1, Ordering::Relaxed);
                }
            }
        })?;
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn verified_routes_expire_and_are_scoped_to_host_and_tunnel() {
        let mut routes = VerifiedRoutes::new();
        let start = Instant::now();
        let address = Ipv4Addr::new(203, 0, 113, 7);
        let key = (address, "gemini.google.com".to_owned(), 12);
        routes.record(key.clone(), start);

        assert!(routes.fresh(&key, start + Duration::from_secs(30)));
        assert!(!routes.fresh(&(address, "aistudio.google.com".to_owned(), 12), start));
        assert!(!routes.fresh(&(address, "gemini.google.com".to_owned(), 13), start));
        assert!(!routes.fresh(&key, start + VERIFIED_TTL));
        assert!(routes.entries.is_empty());

        routes.record(key.clone(), start);
        routes.forget(&key);
        assert!(!routes.fresh(&key, start));
    }

    #[test]
    fn verified_routes_stay_bounded_and_refresh_existing_entries() {
        let mut routes = VerifiedRoutes::new();
        let now = Instant::now();
        let key = |index: usize| (Ipv4Addr::new(203, 0, 113, 1), format!("h{index}"), 1);
        for index in 0..VERIFIED_LIMIT + 5 {
            routes.record(key(index), now);
        }
        assert_eq!(routes.entries.len(), VERIFIED_LIMIT);
        assert!(!routes.fresh(&key(0), now));
        assert!(routes.fresh(&key(VERIFIED_LIMIT + 4), now));

        routes.record(key(VERIFIED_LIMIT + 4), now);
        assert_eq!(routes.entries.len(), VERIFIED_LIMIT);
    }

    #[test]
    fn blocked_dns_cannot_fall_back_to_a_direct_ai_connection() {
        let forbidden = |_: &str| panic!("a blocked AI route must not use the ordinary dial");
        let blocked = |_: &str| Err("vpn unavailable".into());
        let outcome = dial_destination("gemini.google.com", true, &forbidden, &blocked);
        assert_eq!(outcome.unwrap_err(), "vpn unavailable");
        let normal = |name: &str| Err(name.to_owned());
        let forbidden_vpn = |_: &str| panic!("ordinary destinations must keep Windows DNS");
        for (name, blocked) in [("example.com", true), ("gemini.google.com", false)] {
            assert_eq!(
                dial_destination(name, blocked, &normal, &forbidden_vpn).unwrap_err(),
                name
            );
        }
    }

    #[test]
    fn vpn_reconnect_keeps_the_guard_while_local_dns_is_blocked() {
        let mut route = DnsRoute::default();
        assert!(!route.update(Some(true), false, false));
        assert!(!route.update(Some(false), true, false));
        assert!(route.update(Some(true), true, false));
        assert!(route.update(Some(true), false, false));
        assert!(route.update(None, false, false));
        assert!(route.update(Some(true), true, false));
        assert!(!route.update(Some(false), false, false));
    }

    #[test]
    fn browser_uses_vpn_even_when_local_dns_answers() {
        let mut route = DnsRoute::default();
        assert!(route.update(Some(false), true, true));
        assert!(route.update(Some(true), false, true));
        assert!(!route.update(Some(false), false, true));
    }

    #[test]
    fn only_named_https_destinations_are_accepted() {
        assert_eq!(
            parse_request("CONNECT Gemini.Google.Com:443 HTTP/1.1"),
            Some(Request::Connect("gemini.google.com".into()))
        );
        for bad in [
            "CONNECT 127.0.0.1:443 HTTP/1.1",
            "CONNECT gemini.google.com:80 HTTP/1.1",
            "CONNECT gemini.google.com:443 extra HTTP/1.1",
            "GET http://example.com/ HTTP/1.1",
        ] {
            assert_eq!(parse_request(bad), None);
        }
        assert!(!ai_destination("evilgemini.google.com"));
        assert!(!ai_destination("gemini.google.com.example.net"));
        assert!(ai_destination("gemini.google.com"));
        assert!(ai_destination("region.aistudio.google.com"));
        assert!(!public_address("::ffff:127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn the_same_proxy_switches_new_sessions_when_local_dns_becomes_blocked() {
        fn backend(tag: &'static [u8; 3]) -> (SocketAddr, std::thread::JoinHandle<()>) {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let address = listener.local_addr().unwrap();
            let worker = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream.set_read_timeout(Some(HEADER_TIMEOUT)).unwrap();
                let mut request = [0; 4];
                stream.read_exact(&mut request).unwrap();
                assert_eq!(&request, b"ping");
                stream.write_all(tag).unwrap();
            });
            (address, worker)
        }

        let (ordinary, ordinary_worker) = backend(b"SYS");
        let (tunnel, vpn_worker) = backend(b"VPN");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let blocked = Arc::new(AtomicBool::new(false));
        let proxy_state = Arc::clone(&blocked);
        let proxy = std::thread::spawn(move || {
            for _ in 0..2 {
                let (stream, _) = listener.accept().unwrap();
                let dial = |host: &str| {
                    dial_destination(
                        host,
                        proxy_state.load(Ordering::Acquire),
                        &|_| TcpStream::connect(ordinary).map_err(|e| e.to_string()),
                        &|_| TcpStream::connect(tunnel).map_err(|e| e.to_string()),
                    )
                };
                handle(stream, address.port(), &dial).unwrap();
            }
        });
        for (dns_blocked, expected) in [(false, b"SYS"), (true, b"VPN")] {
            blocked.store(dns_blocked, Ordering::Release);
            let mut stream = TcpStream::connect(address).unwrap();
            stream.set_read_timeout(Some(HEADER_TIMEOUT)).unwrap();
            stream
                .write_all(b"CONNECT gemini.google.com:443 HTTP/1.1\r\n\r\nping")
                .unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).unwrap();
            assert!(reply.starts_with(b"HTTP/1.1 200 Connection Established\r\n\r\n"));
            assert!(reply.ends_with(expected));
        }
        proxy.join().unwrap();
        ordinary_worker.join().unwrap();
        vpn_worker.join().unwrap();
    }
}
