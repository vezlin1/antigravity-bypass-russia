use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;
use crate::net::client::query_raw_via;
use crate::net::egress;

pub const LISTEN_IP: &str = if cfg!(target_os = "windows") {
    "127.0.0.53"
} else {
    "127.0.0.1"
};
pub const LISTEN_PORT: u16 = 53;
const WORKER_THREADS: usize = 4;
const UPSTREAM_TIMEOUT: Duration = Duration::from_millis(1500);

static UPSTREAM_CACHE: RwLock<Option<Vec<Ipv4Addr>>> = RwLock::new(None);

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

pub fn save_upstream_config(servers: &[String]) {
    let dir = log_dir();
    let _ = fs::create_dir_all(&dir);
    let p = upstream_conf_path();
    let content = servers.join("\n");
    let _ = fs::write(&p, content);

    // Invalidate in-memory cache
    if let Ok(mut lock) = UPSTREAM_CACHE.write() {
        *lock = None;
    }
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
                if !trimmed.is_empty() {
                    if let Ok(ip) = trimmed.parse::<Ipv4Addr>() {
                        if !list.contains(&ip) {
                            list.push(ip);
                        }
                    }
                }
            }
        }
    }

    if list.is_empty() {
        list = vec![
            Ipv4Addr::new(111, 88, 96, 50),
            Ipv4Addr::new(176, 108, 243, 68),
        ];
    }

    if let Ok(mut lock) = UPSTREAM_CACHE.write() {
        *lock = Some(list.clone());
    }

    list
}

pub fn log_path() -> PathBuf {
    log_dir().join("dns_relay.log")
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

static CACHED_IF_INDEX: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

pub fn run() -> Result<(), String> {
    let addr = format!("{}:{}", LISTEN_IP, LISTEN_PORT);
    let socket = UdpSocket::bind(&addr).map_err(|e| format!("Не удалось занять {}: {}", addr, e))?;
    let _ = crate::net::socket::set_socket_buffers(&socket, 512 * 1024);
    let sock_arc = Arc::new(socket);

    if let Some(e) = egress::detect_fast() {
        CACHED_IF_INDEX.store(e.if_index, std::sync::atomic::Ordering::Release);
    }

    let (tx, rx) = mpsc::sync_channel::<(Vec<u8>, SocketAddr)>(1024);
    let rx_arc = Arc::new(Mutex::new(rx));

    for _ in 0..WORKER_THREADS {
        let rx_c = Arc::clone(&rx_arc);
        let sock_c = Arc::clone(&sock_arc);
        thread::spawn(move || {
            loop {
                let task = {
                    let lock = rx_c.lock().unwrap_or_else(|p| p.into_inner());
                    lock.recv().ok()
                };
                match task {
                    Some((query, client_addr)) => {
                        if let Some(resp) = relay(&query) {
                            let _ = sock_c.send_to(&resp, client_addr);
                        }
                    }
                    None => break,
                }
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
                    let _ = tx.try_send((buf[..n].to_vec(), client_addr));
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

fn relay(query: &[u8]) -> Option<Vec<u8>> {
    let mut if_index = CACHED_IF_INDEX.load(std::sync::atomic::Ordering::Relaxed);
    if if_index == 0 {
        if let Some(e) = egress::detect() {
            if_index = e.if_index;
            CACHED_IF_INDEX.store(if_index, std::sync::atomic::Ordering::Release);
        }
    }
    let servers = load_upstream_servers();

    for &srv in &servers {
        if let Ok(resp) = query_raw_via(query, srv, if_index, Duration::from_millis(800)) {
            if resp.len() >= 12 {
                return Some(resp);
            }
        } else if if_index > 0 {
            // If interface index changed (e.g. Wi-Fi switched or woken from sleep), re-detect
            if let Some(e) = egress::detect() {
                if e.if_index != if_index {
                    if_index = e.if_index;
                    CACHED_IF_INDEX.store(if_index, std::sync::atomic::Ordering::Release);
                    if let Ok(resp) = query_raw_via(query, srv, if_index, Duration::from_millis(800)) {
                        if resp.len() >= 12 {
                            return Some(resp);
                        }
                    }
                }
            }
        }
    }
    None
}
