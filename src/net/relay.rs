use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;
use crate::net::client::query_raw_via;
use crate::net::egress;

pub const LISTEN_IP: &str = "127.0.0.1";
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

    let mut buf = [0u8; 1500];
    let mut backoff_ms = 100;
    loop {
        match sock_arc.recv_from(&mut buf) {
            Ok((n, client_addr)) => {
                backoff_ms = 100;
                if n >= 12 {
                    let query = buf[..n].to_vec();
                    let sock_c = Arc::clone(&sock_arc);
                    thread::spawn(move || {
                        if let Some(resp) = relay(&query) {
                            let _ = sock_c.send_to(&resp, client_addr);
                        } else {
                            log_fatal(&format!("relay returned None for query from {:?}", client_addr));
                        }
                    });
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
    let servers = load_upstream_servers();

    for &srv in &servers {
        match query_raw_via(query, srv, 0, Duration::from_millis(800)) {
            Ok(resp) if resp.len() >= 12 => return Some(resp),
            Ok(resp) => log_fatal(&format!("Short resp from {}: len {}", srv, resp.len())),
            Err(e) => log_fatal(&format!("Query error for {}: {}", srv, e)),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loopback_cross_send() {
        let srv = UdpSocket::bind("127.0.0.53:53535").expect("bind srv");
        let cli = UdpSocket::bind("127.0.0.1:0").expect("bind cli");
        cli.connect("127.0.0.53:53535").expect("connect");
        cli.send(b"hello").expect("send");

        let mut buf = [0u8; 100];
        let (_n, from) = srv.recv_from(&mut buf).expect("recv srv");
        println!("Server received from: {:?}", from);

        let res = srv.send_to(b"world", from);
        println!("Server send_to result: {:?}", res);
        assert!(res.is_ok());

        let mut cli_buf = [0u8; 100];
        let n_cli = cli.recv(&mut cli_buf).expect("recv cli");
        assert_eq!(&cli_buf[..n_cli], b"world");
        println!("Client received response successfully!");
    }
}
