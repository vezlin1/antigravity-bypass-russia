use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::net::resolvers::looks_google;

#[derive(Debug, Default)]
pub struct ConnReport {
    pub resolved: Vec<String>,
    pub connected: Option<String>,
    pub latency_ms: u128,
    pub used_ipv6: bool,
    pub looks_like_google: bool,
    pub error: Option<String>,
}

pub fn probe_google_api() -> ConnReport {
    let mut report = ConnReport::default();
    let host = "daily-cloudcode-pa.googleapis.com";
    let target = format!("{}:443", host);
    let start = Instant::now();

    let addrs: Vec<SocketAddr> = match target.to_socket_addrs() {
        Ok(iter) => iter.collect(),
        Err(e) => {
            report.error = Some(format!("DNS: {}", e));
            return report;
        }
    };

    if addrs.is_empty() {
        report.error = Some(format!("Нет A/AAAA для {}", host));
        return report;
    }

    for addr in &addrs {
        report.resolved.push(addr.ip().to_string());
        if looks_google(&addr.ip()) {
            report.looks_like_google = true;
        }
    }

    let mut last_err = String::new();
    for addr in &addrs {
        match TcpStream::connect_timeout(addr, Duration::from_millis(3000)) {
            Ok(_) => {
                report.latency_ms = start.elapsed().as_millis();
                report.connected = Some(format!("{} ({})", host, addr.ip()));
                report.used_ipv6 = addr.is_ipv6();
                return report;
            }
            Err(e) => last_err = e.to_string(),
        }
    }

    report.error = Some(format!("TCP 443: {}", last_err));
    report
}
