use crate::net::client::{nodata_response, question_name, question_type};
use crate::net::resolvers;
use crate::net::routes::RoutePolicy;
use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, UdpSocket};
use std::path::PathBuf;
#[cfg(any(windows, target_os = "linux"))]
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

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
// Workers are added only while every running one is busy and leave after a
// quiet minute, so an idle relay keeps a couple of small threads.
const MIN_WORKERS: usize = 2;
const WORKER_IDLE_EXIT: Duration = Duration::from_secs(60);
// Upstream lookups and DoH transfers run on their own threads; a worker only
// parses packets and coordinates them.
const WORKER_STACK: usize = 512 * 1024;

type Job = (Vec<u8>, std::net::SocketAddr);
type Handler = Box<dyn Fn(Job) + Send + Sync>;
// Same bound as the former channel: a flood beyond it is dropped, not queued.
const QUEUE_LIMIT: usize = 256;

struct PoolState {
    jobs: std::collections::VecDeque<Job>,
    /// Workers waiting for a job, including ones that are still starting.
    idle: usize,
    total: usize,
}

/// Grows from MIN_WORKERS to WORKER_THREADS while queued jobs outnumber idle
/// workers. Every worker has its own idle timer, so extra workers leave
/// independently after a quiet `idle_exit`.
struct WorkerPool {
    state: Mutex<PoolState>,
    ready: std::sync::Condvar,
    handler: Handler,
    idle_exit: Duration,
}

impl WorkerPool {
    fn new(handler: Handler, idle_exit: Duration) -> Arc<Self> {
        let pool = Arc::new(Self {
            state: Mutex::new(PoolState {
                jobs: std::collections::VecDeque::new(),
                idle: 0,
                total: 0,
            }),
            ready: std::sync::Condvar::new(),
            handler,
            idle_exit,
        });
        for _ in 0..MIN_WORKERS {
            let reserved = {
                let mut state = pool.lock();
                Self::reserve(&mut state)
            };
            if reserved {
                Self::spawn(&pool);
            }
        }
        pool
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, PoolState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Counts a new worker as idle before it starts, so a burst of submits
    /// does not spawn a thread per job while earlier ones are still starting.
    fn reserve(state: &mut PoolState) -> bool {
        if state.total >= WORKER_THREADS {
            return false;
        }
        state.total += 1;
        state.idle += 1;
        true
    }

    fn spawn(pool: &Arc<Self>) {
        let worker = Arc::clone(pool);
        let spawned = thread::Builder::new()
            .name("ag-dns-worker".into())
            .stack_size(WORKER_STACK)
            .spawn(move || worker.run());
        if spawned.is_err() {
            let mut state = pool.lock();
            state.total -= 1;
            state.idle -= 1;
        }
    }

    /// Queues a job; false when the queue is full and the packet is dropped.
    fn submit(pool: &Arc<Self>, job: Job) -> bool {
        let grow = {
            let mut state = pool.lock();
            if state.jobs.len() >= QUEUE_LIMIT {
                return false;
            }
            state.jobs.push_back(job);
            state.jobs.len() > state.idle && Self::reserve(&mut state)
        };
        pool.ready.notify_one();
        if grow {
            Self::spawn(pool);
        }
        true
    }

    fn run(&self) {
        let mut state = self.lock();
        let mut idle_since = Instant::now();
        loop {
            if let Some(job) = state.jobs.pop_front() {
                state.idle -= 1;
                drop(state);
                (self.handler)(job);
                state = self.lock();
                state.idle += 1;
                idle_since = Instant::now();
                continue;
            }
            let waited = idle_since.elapsed();
            if waited >= self.idle_exit {
                if state.total > MIN_WORKERS {
                    state.total -= 1;
                    state.idle -= 1;
                    return;
                }
                idle_since = Instant::now();
                continue;
            }
            state = self
                .ready
                .wait_timeout(state, self.idle_exit - waited)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    #[cfg(test)]
    fn workers(&self) -> usize {
        self.lock().total
    }
}

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
        save_if_index(interface)?;
        clear_upstream_cache();
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
    fn new(sender: mpsc::SyncSender<()>, family: u16) -> Option<Self> {
        let mut context = Box::new(sender);
        let mut handle = std::ptr::null_mut();
        let code = unsafe {
            NotifyRouteChange2(
                family,
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
fn start_network_refresh(policy: RoutePolicy) {
    // Route discovery and recovery can invoke OS utilities. Keep every one of
    // those operations off the DNS startup/readiness path, including boot.
    thread::spawn(move || {
        let (wake, notifications) = mpsc::sync_channel(1);
        let family = if policy == RoutePolicy::System { 0 } else { 2 }; // AF_UNSPEC / AF_INET
        let subscription = RouteNotifications::new(wake.clone(), family);
        let _keep_channel_open = wake;
        if policy == RoutePolicy::System {
            return refresh_system_network(&notifications, subscription.is_some());
        }
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

#[cfg(windows)]
fn refresh_system_network(notifications: &mpsc::Receiver<()>, subscribed: bool) {
    const RETRY: Duration = Duration::from_secs(10);
    const POLL: Duration = Duration::from_secs(30);
    let mut retry = true;
    loop {
        let delay = if retry { RETRY } else { POLL };
        let changed = match notifications.recv_timeout(delay) {
            Ok(()) => true,
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
            Err(mpsc::RecvTimeoutError::Timeout) => false,
        };
        if !changed && !retry && subscribed {
            continue;
        }
        // VPN clients commonly update several routes in succession. Do not
        // publish pins found on the old network if another event arrives.
        if changed {
            thread::sleep(Duration::from_millis(350));
            let _ = notifications.try_recv();
        }
        resolvers::invalidate_network_caches();
        retry = match super::rank::refresh_system_pins(|| notifications.try_recv().is_err()) {
            Ok(ready) => !ready,
            Err(error) => {
                log_event(&format!("Обновление резервных адресов отложено: {error}"));
                true
            }
        };
    }
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

pub(super) fn mode_conf_path() -> PathBuf {
    log_dir().join("mode.conf")
}

pub fn save_upstream_config(servers: &[String]) -> Result<(), String> {
    crate::system::fs_utils::robust_write_file(
        &upstream_conf_path(),
        servers.join("\n").as_bytes(),
    )?;
    clear_upstream_cache();
    Ok(())
}

fn clear_upstream_cache() {
    if let Ok(mut lock) = UPSTREAM_CACHE.write() {
        *lock = None;
    }
}

pub(super) fn clear_settings_cache() {
    IF_INDEX_CACHE.store(0, std::sync::atomic::Ordering::SeqCst);
    clear_upstream_cache();
    super::resolver_pool::forget_shared();
}

#[cfg(windows)]
const SYSTEM_ROUTE_MARKER: &[u8] = b"windows-system-route-v1\n";

pub(super) fn load_route_policy() -> Result<RoutePolicy, String> {
    #[cfg(windows)]
    match fs::read(mode_conf_path()) {
        Ok(marker) if marker == SYSTEM_ROUTE_MARKER => return Ok(RoutePolicy::System),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("Режим маршрутизации: {error}")),
    }
    Ok(RoutePolicy::Physical)
}

pub(super) fn save_route_policy(policy: RoutePolicy) -> Result<(), String> {
    #[cfg(windows)]
    if policy == RoutePolicy::System {
        return crate::system::fs_utils::robust_write_file(&mode_conf_path(), SYSTEM_ROUTE_MARKER);
    }
    let _ = policy;
    match fs::remove_file(mode_conf_path()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("Не удалось сбросить mode.conf: {error}")),
    }
}

pub fn save_if_index(idx: u32) -> Result<(), String> {
    crate::system::fs_utils::robust_write_file(&iface_conf_path(), idx.to_string().as_bytes())?;
    IF_INDEX_CACHE.store(idx, std::sync::atomic::Ordering::SeqCst);
    Ok(())
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
    let policy = load_route_policy()?;
    #[cfg(windows)]
    start_network_refresh(policy);
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

    let reply_socket = Arc::clone(&sock_arc);
    let pool = WorkerPool::new(
        Box::new(move |(query, client_addr): Job| {
            if let Some(resp) = relay(&query, policy) {
                let _ = reply_socket.send_to(&resp, client_addr);
            } else {
                let name = question_name(&query).unwrap_or_else(|| "?".into());
                log_fatal(&format!("no answer for {} from {:?}", name, client_addr));
            }
        }),
        WORKER_IDLE_EXIT,
    );

    let mut buf = [0u8; 1500];
    let mut backoff_ms = 100;
    loop {
        match sock_arc.recv_from(&mut buf) {
            Ok((n, client_addr)) => {
                backoff_ms = 100;
                if n >= 12 {
                    let query = buf[..n].to_vec();
                    WorkerPool::submit(&pool, (query, client_addr));
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

fn relay(query: &[u8], policy: RoutePolicy) -> Option<Vec<u8>> {
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

    let if_index = match policy {
        RoutePolicy::Physical => load_if_index(),
        #[cfg(windows)]
        RoutePolicy::System => 0,
    };
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
            if let Some(reply) = relay(&query, RoutePolicy::Physical) {
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

#[cfg(windows)]
pub fn local_dns_available() -> Result<bool, String> {
    match probe_local_dns() {
        Ok(passed) => Ok(passed),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::PermissionDenied
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::WouldBlock
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(format!("Проверка локального DNS: {error}")),
    }
}

#[cfg(windows)]
fn probe_local_dns() -> std::io::Result<bool> {
    let receiver = UdpSocket::bind("127.0.0.254:53")?;
    receiver.set_read_timeout(Some(Duration::from_millis(250)))?;
    let sender = UdpSocket::bind("127.0.0.1:0")?;
    let packet = crate::net::client::build_query(HEALTH_NAME, 0xA657);
    sender.send_to(&packet, receiver.local_addr()?)?;
    let mut bytes = [0u8; 512];
    let (n, peer) = receiver.recv_from(&mut bytes)?;
    Ok(peer == sender.local_addr()? && bytes[..n] == packet)
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
    fn worker_pool_answers_relay_jobs_and_stays_bounded() {
        let relay_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let reply_socket = Arc::clone(&relay_socket);
        let pool = WorkerPool::new(
            Box::new(move |(query, client_addr): Job| {
                if let Some(resp) = relay(&query, RoutePolicy::Physical) {
                    let _ = reply_socket.send_to(&resp, client_addr);
                }
            }),
            WORKER_IDLE_EXIT,
        );
        assert_eq!(pool.workers(), MIN_WORKERS);
        // AAAA questions are answered locally, without upstream traffic.
        let jobs = 40u16;
        for id in 0..jobs {
            let mut query =
                crate::net::client::build_query("daily-cloudcode-pa.googleapis.com", id);
            let at = query.len() - 4;
            query[at..at + 2].copy_from_slice(&28u16.to_be_bytes());
            assert!(WorkerPool::submit(
                &pool,
                (query, client.local_addr().unwrap())
            ));
        }
        let mut answered = std::collections::HashSet::new();
        let mut bytes = [0u8; 512];
        while answered.len() < usize::from(jobs) {
            let (n, _) = client.recv_from(&mut bytes).unwrap();
            answered.insert(u16::from_be_bytes([bytes[0], bytes[1]]));
            assert!(n >= 12);
        }
        assert!((MIN_WORKERS..=WORKER_THREADS).contains(&pool.workers()));
    }

    #[test]
    fn worker_pool_grows_for_a_burst_and_extra_workers_retire_independently() {
        let done = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let finished = Arc::clone(&done);
        let pool = WorkerPool::new(
            Box::new(move |_: Job| {
                std::thread::sleep(Duration::from_millis(20));
                finished.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }),
            Duration::from_millis(200),
        );
        let client: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
        let burst = || {
            let started = Instant::now();
            let before = done.load(std::sync::atomic::Ordering::SeqCst);
            for _ in 0..32 {
                assert!(WorkerPool::submit(&pool, (vec![0; 12], client)));
            }
            while done.load(std::sync::atomic::Ordering::SeqCst) < before + 32 {
                std::thread::sleep(Duration::from_millis(1));
            }
            started.elapsed()
        };
        // 32 jobs of 20 ms take 320 ms on two workers; the pool must grow.
        let first = burst();
        assert!(first < Duration::from_millis(200), "{first:?}");
        assert!(pool.workers() > MIN_WORKERS);
        // Each extra worker has its own idle timer: all of them leave after
        // one quiet period, not one per period.
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(pool.workers(), MIN_WORKERS);
        let second = burst();
        assert!(second < Duration::from_millis(200), "{second:?}");
    }

    #[test]
    fn address_family_and_service_binding_questions_skip_upstream() {
        for qtype in [28u16, 64, 65] {
            let mut query = crate::net::client::build_query("daily-cloudcode-pa.googleapis.com", 7);
            let at = query.len() - 4;
            query[at..at + 2].copy_from_slice(&qtype.to_be_bytes());
            assert_eq!(question_type(&query), Some(qtype));
            let reply = relay(&query, RoutePolicy::Physical).unwrap();
            assert!(crate::net::client::is_successful_response(&reply));
            assert!(crate::net::client::answer_addrs(&reply).is_empty());
        }
        assert!(!answered_locally(Some(1)));
        assert!(!answered_locally(None));
    }
}
