use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

pub fn test_google_connectivity() -> Result<(String, u128), String> {
    let start = Instant::now();
    let host = "cloudcode-pa.googleapis.com";
    let target = format!("{}:443", host);

    let addrs: Vec<SocketAddr> = target
        .to_socket_addrs()
        .map_err(|e| format!("Ошибка DNS-резолвинга {}: {}", host, e))?
        .collect();

    if addrs.is_empty() {
        return Err(format!("Не удалось получить адрес для {}", host));
    }

    let mut last_err = String::new();
    for addr in &addrs {
        match TcpStream::connect_timeout(addr, Duration::from_millis(3000)) {
            Ok(_) => {
                let latency = start.elapsed().as_millis();
                return Ok((format!("{} ({})", host, addr.ip()), latency));
            }
            Err(e) => {
                last_err = e.to_string();
            }
        }
    }

    Err(format!("Таймаут подключения к {}: {}", host, last_err))
}
