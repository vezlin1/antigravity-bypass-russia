//! Host name and clock helpers shared by DNS, ranking and diagnostics.
//!
//! The persistent route score table that used to live here had no writers
//! since 2.2.1; `remove_dns_configuration` deletes its leftover file.
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub fn host_name(host: &str) -> String {
    host.trim_matches('.').to_ascii_lowercase()
}
