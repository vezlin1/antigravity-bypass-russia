use crate::net::client::{nodata_response, question_name, question_type};
use crate::net::resolvers;
use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, UdpSocket};
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

#[cfg(target_os = "macos")]
pub const LISTEN_IP: &str = "127.0.0.1";
#[cfg(target_os = "linux")]
pub const LISTEN_IP: &str = "127.0.0.55";
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub const LISTEN_IP: &str = "127.0.0.53";
pub const LISTEN_PORT: u16 = 53;
pub const HEALTH_PORT: u16 = 15353;
pub const HEALTH_NAME: &str = "antigravity-relay-health.invalid";
// A miss can block a worker for the whole upstream budget; keep queries from queuing behind it.
const WORKER_THREADS: usize = 32;

static UPSTREAM_CACHE: std::sync::RwLock<Option<Vec<Ipv4Addr>>> = std::sync::RwLock::new(None);
static IF_INDEX_CACHE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

#[cfg(any(windows, test))]
#[derive(Default)]
struct NetworkRefresh {
    applied: Option<(u32, Ipv4Addr)>,
}

#[cfg(any(windows, test))]
impl NetworkRefresh {
    fn update(
        &mut self,
        physical: Option<(u32, Ipv4Addr)>,
        mut apply: impl FnMut(u32, Ipv4Addr) -> Result<(), String>,
    ) -> Result<(), String> {
        let Some((interface, gateway)) = physical else {
            // Retry even the same gateway when connectivity returns after sleep.
            self.applied = None;
            return Ok(());
        };
        if self.applied != physical {
            apply(interface, gateway)?;
            // An interrupted/locked refresh is retried, never marked complete.
            self.applied = physical;
        }
        Ok(())
    }
}

#[cfg(windows)]
fn refresh_windows_network(state: &mut NetworkRefresh) -> Result<(), String> {
    let physical = super::egress::detect_physical().and_then(|(interface, gateway)| {
        gateway
            .parse::<Ipv4Addr>()
            .ok()
            .map(|gateway| (interface, gateway))
    });
    state.update(physical, |interface, gateway| {
        // Setup/rollback owns this same lock. A foreground setup has already
        // prepared the routes before launching us; retry after it releases it.
        let _configuration = super::configuration_lock()?;
        super::routes::restore_recorded_routes(interface, gateway)?;
        save_if_index(interface);
        if let Ok(mut cache) = UPSTREAM_CACHE.write() {
            *cache = None;
        }
        resolvers::invalidate_network_caches();
        Ok(())
    })
}

#[cfg(windows)]
struct RouteNotifications {
    handle: *mut std::ffi::c_void,
    context: Option<Box<mpsc::SyncSender<()>>>,
}

#[cfg(windows)]
#[link(name = "iphlpapi")]
extern "system" {
    fn NotifyRouteChange2(
        family: u16,
        callback: unsafe extern "system" fn(*mut std::ffi::c_void, *mut std::ffi::c_void, u32),
        context: *mut std::ffi::c_void,
        initial: u8,
        handle: *mut *mut std::ffi::c_void,
    ) -> u32;
    fn CancelMibChangeNotify2(handle: *mut std::ffi::c_void) -> u32;
}

#[cfg(windows)]
unsafe extern "system" fn route_changed(
    context: *mut std::ffi::c_void,
    _row: *mut std::ffi::c_void,
    _notification: u32,
) {
    // Coalesce notifications, including the routes we recreate ourselves.
    // No network query, blocking send or lock runs on the OS callback thread.
    let sender = &*context.cast::<mpsc::SyncSender<()>>();
    let _ = sender.try_send(());
}

#[cfg(windows)]
impl RouteNotifications {
    fn new(sender: mpsc::SyncSender<()>) -> Option<Self> {
        let mut context = Box::new(sender);
        let mut handle = std::ptr::null_mut();
        let code = unsafe {
            NotifyRouteChange2(
                2, // AF_INET
                route_changed,
                (&mut *context as *mut mpsc::SyncSender<()>).cast(),
                0,
                &mut handle,
            )
        };
        if code != 0 {
            return None;
        }
        Some(Self {
            handle,
            context: Some(context),
        })
    }
}

#[cfg(windows)]
impl Drop for RouteNotifications {
    fn drop(&mut self) {
        // Cancellation runs outside the callback and waits for pending calls.
        if unsafe { CancelMibChangeNotify2(self.handle) } != 0 {
            // On an unexpected cancellation failure preserve the callback's
            // allocation until process exit instead of exposing freed memory.
            if let Some(context) = self.context.take() {
                let _ = Box::leak(context);
            }
        }
    }
}

#[cfg(windows)]
fn start_network_refresh() {
    // Route discovery and recovery can invoke OS utilities. Keep every one of
    // those operations off the DNS startup/readiness path, including boot.
    thread::spawn(move || {
        let (wake, notifications) = mpsc::sync_channel(1);
        let _subscription = RouteNotifications::new(wake.clone());
        let _keep_channel_open = wake;
        let mut state = NetworkRefresh::default();
        let mut previous_error = None;
        loop {
            let error = refresh_windows_network(&mut state).err();
            if error != previous_error {
                match &error {
                    Some(error) => log_event(&format!("Обновление подключения отложено: {error}")),
                    None => log_event("Маршруты и DNS обновлены для текущего подключения"),
                }
            }
            let delay = if error.is_some() || state.applied.is_none() {
                Duration::from_secs(5)
            } else {
                Duration::from_secs(60)
            };
            previous_error = error;
            // Notifications react immediately to adapter/gateway changes. The
            // timeout covers offline boot, a busy foreground lock and missed
            // notifications without repeatedly spawning utilities on VPNs.
            let _ = notifications.recv_timeout(delay);
        }
    });
}

pub fn detach_console() {
    #[cfg(target_os = "windows")]
    {
        #[link(name = "kernel32")]
        extern "system" {
            fn FreeConsole() -> i32;
        }
        unsafe {
            FreeConsole();
        }
    }
}

pub fn log_dir() -> PathBuf {
    crate::system::service::install_dir()
}

pub fn upstream_conf_path() -> PathBuf {
    log_dir().join("upstream.conf")
}

pub fn iface_conf_path() -> PathBuf {
    log_dir().join("iface.conf")
}

fn mode_conf_path() -> PathBuf {
    log_dir().join("mode.conf")
}

pub fn save_upstream_config(servers: &[String]) {
    let dir = log_dir();
    let _ = fs::create_dir_all(&dir);
    let _ = fs::write(upstream_conf_path(), servers.join("\n"));
    if let Ok(mut lock) = UPSTREAM_CACHE.write() {
        *lock = None;
    }
}

pub fn clear_custom_mode() {
    let _ = fs::remove_file(mode_conf_path());
}

pub fn save_if_index(idx: u32) {
    let dir = log_dir();
    let _ = fs::create_dir_all(&dir);
    let _ = fs::write(iface_conf_path(), idx.to_string());
    IF_INDEX_CACHE.store(idx, std::sync::atomic::Ordering::SeqCst);
}

pub fn load_if_index() -> u32 {
    let cached = IF_INDEX_CACHE.load(std::sync::atomic::Ordering::SeqCst);
    if cached > 0 {
        return cached;
    }
    let p = iface_conf_path();
    if p.exists() {
        if let Ok(c) = fs::read_to_string(&p) {
            if let Ok(idx) = c.trim().parse::<u32>() {
                IF_INDEX_CACHE.store(idx, std::sync::atomic::Ordering::SeqCst);
                return idx;
            }
        }
    }
    0
}

pub fn load_upstream_servers() -> Vec<Ipv4Addr> {
    if let Ok(lock) = UPSTREAM_CACHE.read() {
        if let Some(cached) = lock.as_ref() {
            return cached.clone();
        }
    }

    let mut list = Vec::new();
    let p = upstream_conf_path();
    if p.exists() {
        if let Ok(c) = fs::read_to_string(&p) {
            for line in c.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Ok(ip) = trimmed.parse::<Ipv4Addr>() {
                    if !list.contains(&ip) {
                        list.push(ip);
                    }
                }
            }
        }
    }

    if list.is_empty() {
        for ip in crate::net::resolvers::all_provider_v4() {
            if let Ok(addr) = ip.parse::<Ipv4Addr>() {
                if !list.contains(&addr) {
                    list.push(addr);
                }
            }
        }
    }

    if let Ok(mut lock) = UPSTREAM_CACHE.write() {
        *lock = Some(list.clone());
    }
    list
}

pub fn log_path() -> PathBuf {
    log_dir().join("dns_relay.log")
}

pub(crate) fn log_line(msg: &str) {
    #[cfg(debug_assertions)]
    {
        let p = log_path();
        let _ = fs::create_dir_all(log_dir());
        if fs::metadata(&p)
            .map(|m| m.len() > 64 * 1024)
            .unwrap_or(false)
        {
            let _ = fs::remove_file(&p);
        }
        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(p) {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let _ = writeln!(f, "[{}] {}", ts, msg);
        }
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = msg;
    }
}

pub fn log_fatal(msg: &str) {
    let p = log_path();
    let _ = fs::create_dir_all(log_dir());
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(p) {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = writeln!(f, "[{}] FATAL: {}", ts, msg);
    }
}

pub fn run() -> Result<(), String> {
    let _ = load_if_index();
    #[cfg(windows)]
    start_network_refresh();
    let addr = format!("{}:{}", LISTEN_IP, LISTEN_PORT);
    let socket =
        UdpSocket::bind(&addr).map_err(|e| format!("Не удалось занять {}: {}", addr, e))?;
    #[cfg(target_os = "linux")]
    start_tcp_listener(&addr)?;
    let _ = crate::net::socket::set_socket_buffers(&socket, 512 * 1024);
    log_line(&format!("start {}", addr));
    // Local readiness responds only when requested; it does not probe the Internet.
    let health = UdpSocket::bind((LISTEN_IP, HEALTH_PORT)).map_err(|e| e.to_string())?;
    thread::spawn(move || {
        let mut bytes = [0u8; 512];
        while let Ok((n, peer)) = health.recv_from(&mut bytes) {
            if question_name(&bytes[..n]).as_deref() == Some(HEALTH_NAME) {
                if let Some(reply) =
                    crate::net::client::address_response(&bytes[..n], &[Ipv4Addr::LOCALHOST])
                {
                    let _ = health.send_to(&reply, peer);
                }
            }
        }
    });
    let sock_arc = Arc::new(socket);

    let (tx, rx) = mpsc::sync_channel::<(Vec<u8>, std::net::SocketAddr)>(256);
    let rx = Arc::new(Mutex::new(rx));
    for _ in 0..WORKER_THREADS {
        let rx_c = Arc::clone(&rx);
        let sock_c = Arc::clone(&sock_arc);
        thread::spawn(move || loop {
            let job = {
                let guard = match rx_c.lock() {
                    Ok(g) => g,
                    Err(_) => break,
                };
                guard.recv()
            };
            match job {
                Ok((query, client_addr)) => {
                    if let Some(resp) = relay(&query) {
                        let _ = sock_c.send_to(&resp, client_addr);
                    } else {
                        let name = question_name(&query).unwrap_or_else(|| "?".into());
                        log_fatal(&format!("no answer for {} from {:?}", name, client_addr));
                    }
                }
                Err(_) => break,
            }
        });
    }

    let mut buf = [0u8; 1500];
    let mut backoff_ms = 100;
    loop {
        match sock_arc.recv_from(&mut buf) {
            Ok((n, client_addr)) => {
                backoff_ms = 100;
                if n >= 12 {
                    let query = buf[..n].to_vec();
                    let _ = tx.try_send((query, client_addr));
                }
            }
            Err(e) => {
                log_fatal(&format!("Socket recv error: {}", e));
                thread::sleep(Duration::from_millis(backoff_ms));
                backoff_ms = (backoff_ms * 2).min(2000);
            }
        }
    }
}

fn answered_locally(qtype: Option<u16>) -> bool {
    // AAAA: pinned proxies are IPv4. SVCB/HTTPS (64/65): macOS asks for them on
    // every lookup, and waiting on upstream for them delays each connection.
    matches!(qtype, Some(28 | 64 | 65))
}

fn relay(query: &[u8]) -> Option<Vec<u8>> {
    #[cfg(target_os = "linux")]
    if !super::linux_dns::is_target(&question_name(query)?) {
        return Some(
            super::linux_dns::passthrough(query)
                .unwrap_or_else(|| crate::net::client::servfail_response(query)),
        );
    }
    if answered_locally(question_type(query)) {
        return Some(nodata_response(query));
    }

    let if_index = load_if_index();
    match resolvers::resolve_best(query, if_index) {
        Some(hit) => {
            log_line(&format!(
                "{:<12} {} [{}]",
                resolvers::verdict_tag(hit.verdict),
                question_name(query).unwrap_or_default(),
                hit.provider
            ));
            Some(hit.reply)
        }
        None => Some(crate::net::client::servfail_response(query)),
    }
}

#[cfg(target_os = "linux")]
fn start_tcp_listener(addr: &str) -> Result<(), String> {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind(addr).map_err(|e| format!("TCP DNS {addr}: {e}"))?;
    let (tx, rx) = mpsc::sync_channel::<std::net::TcpStream>(32);
    let rx = Arc::new(Mutex::new(rx));
    for _ in 0..8 {
        let rx = Arc::clone(&rx);
        thread::spawn(move || loop {
            let Ok(mut stream) = rx.lock().unwrap().recv() else {
                break;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
            let mut length = [0; 2];
            if stream.read_exact(&mut length).is_err() {
                continue;
            }
            let mut query = vec![0; u16::from_be_bytes(length) as usize];
            if query.len() < 12 || stream.read_exact(&mut query).is_err() {
                continue;
            }
            if let Some(reply) = relay(&query) {
                if let Ok(length) = u16::try_from(reply.len()) {
                    let _ = stream
                        .write_all(&length.to_be_bytes())
                        .and_then(|_| stream.write_all(&reply));
                }
            }
        });
    }
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let _ = tx.try_send(stream);
        }
    });
    Ok(())
}

pub fn log_event(msg: &str) {
    let dir = super::config::directory();
    let _ = fs::create_dir_all(&dir);
    let path = dir.join("network-events.log");
    if fs::metadata(&path).is_ok_and(|m| m.len() > 256 * 1024) {
        let _ = fs::rename(&path, dir.join("network-events.previous.log"));
    }
    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = super::config::inherit_directory_owner(&path);
        let _ = writeln!(
            file,
            "[{}] {}",
            super::route_health::now_ms(),
            msg.replace(['\r', '\n'], " ")
        );
    }
}

pub fn local_dns_available() -> Result<bool, String> {
    let receiver =
        UdpSocket::bind("127.0.0.254:53").map_err(|e| format!("Проверка локального DNS: {e}"))?;
    receiver
        .set_read_timeout(Some(Duration::from_millis(250)))
        .map_err(|e| e.to_string())?;
    let sender = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let packet = crate::net::client::build_query(HEALTH_NAME, 0xA657);
    sender
        .send_to(&packet, receiver.local_addr().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let mut bytes = [0u8; 512];
    match receiver.recv_from(&mut bytes) {
        Ok((n, peer)) => {
            Ok(peer == sender.local_addr().map_err(|e| e.to_string())? && bytes[..n] == packet)
        }
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) =>
        {
            Ok(false)
        }
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn route_notifications_are_coalesced_without_blocking_the_os_callback() {
        let (mut sender, receiver) = mpsc::sync_channel(1);
        for _ in 0..3 {
            unsafe {
                route_changed(
                    (&mut sender as *mut mpsc::SyncSender<()>).cast(),
                    std::ptr::null_mut(),
                    0,
                );
            }
        }
        receiver.try_recv().unwrap();
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
    }

    #[test]
    fn startup_and_gateway_changes_restore_routes_once_per_connection() {
        let mut refresh = NetworkRefresh::default();
        let ethernet = Some((7, "192.0.2.1".parse().unwrap()));
        let wifi = Some((9, "198.51.100.1".parse().unwrap()));
        let changed_gateway = Some((9, "198.51.100.254".parse().unwrap()));
        let mut applied = Vec::new();
        for connection in [
            None,
            ethernet,
            ethernet,
            wifi,
            changed_gateway,
            None,
            changed_gateway,
        ] {
            refresh
                .update(connection, |interface, gateway| {
                    applied.push((interface, gateway));
                    Ok(())
                })
                .unwrap();
        }
        assert_eq!(
            applied,
            [
                ethernet.unwrap(),
                wifi.unwrap(),
                changed_gateway.unwrap(),
                changed_gateway.unwrap()
            ]
        );
    }

    #[test]
    fn failed_or_busy_startup_refresh_is_retried_without_losing_the_last_connection() {
        let mut refresh = NetworkRefresh::default();
        let original = Some((7, "192.0.2.1".parse().unwrap()));
        let changed = Some((9, "198.51.100.1".parse().unwrap()));
        assert!(refresh
            .update(original, |_, _| Err("foreground owns lock".into()))
            .is_err());
        assert_eq!(refresh.applied, None);
        refresh.update(original, |_, _| Ok(())).unwrap();
        assert!(refresh
            .update(changed, |_, _| Err("route operation failed".into()))
            .is_err());
        assert_eq!(refresh.applied, original);
        let mut retried = false;
        refresh
            .update(changed, |_, _| {
                retried = true;
                Ok(())
            })
            .unwrap();
        assert!(retried);
        assert_eq!(refresh.applied, changed);
    }

    #[test]
    fn address_family_and_service_binding_questions_skip_upstream() {
        for qtype in [28u16, 64, 65] {
            let mut query = crate::net::client::build_query("daily-cloudcode-pa.googleapis.com", 7);
            let at = query.len() - 4;
            query[at..at + 2].copy_from_slice(&qtype.to_be_bytes());
            assert_eq!(question_type(&query), Some(qtype));
            let reply = relay(&query).unwrap();
            assert!(crate::net::client::is_successful_response(&reply));
            assert!(crate::net::client::answer_addrs(&reply).is_empty());
        }
        assert!(!answered_locally(Some(1)));
        assert!(!answered_locally(None));
    }
}
