use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, UdpSocket};
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;
use crate::net::client::{nodata_response, question_name, question_type};
use crate::net::resolvers;

pub const LISTEN_IP: &str = "127.0.0.53";
pub const LISTEN_PORT: u16 = 53;
#[cfg(target_os = "macos")]
const WORKER_THREADS: usize = 1;
#[cfg(not(target_os = "macos"))]
const WORKER_THREADS: usize = 4;

static UPSTREAM_CACHE: std::sync::RwLock<Option<Vec<Ipv4Addr>>> = std::sync::RwLock::new(None);
static IF_INDEX_CACHE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

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
        if fs::metadata(&p).map(|m| m.len() > 64 * 1024).unwrap_or(false) {
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
    let addr = format!("{}:{}", LISTEN_IP, LISTEN_PORT);
    let socket = UdpSocket::bind(&addr).map_err(|e| format!("Не удалось занять {}: {}", addr, e))?;
    let _ = crate::net::socket::set_socket_buffers(&socket, 512 * 1024);
    log_line(&format!("start {}", addr));
    resolvers::warmup(load_if_index());
    #[cfg(not(target_os = "macos"))]
    crate::net::rank::spawn_background();
    let sock_arc = Arc::new(socket);

    let (tx, rx) = mpsc::channel::<(Vec<u8>, std::net::SocketAddr)>();
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
                    if tx.send((query, client_addr)).is_err() {
                        log_fatal("worker queue closed");
                        return Err("worker queue closed".into());
                    }
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
    if question_type(query) == Some(28) {
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
        None => None,
    }
}
