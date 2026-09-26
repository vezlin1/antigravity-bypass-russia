//! Local, opt-in support reports. Export an allowlist, never raw configuration or logs.
mod platform;

use crate::{
    core::{detector, patcher},
    net, system,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::mpsc,
    time::{Duration, Instant},
};

const MAX_TEXT: u64 = 1024 * 1024;

fn unavailable(reason: &str) -> Value {
    json!({"status": reason})
}

fn read_limited(path: &Path, limit: u64) -> Result<Vec<u8>, &'static str> {
    let file = File::open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => "not_found",
        std::io::ErrorKind::PermissionDenied => "permission_denied",
        _ => "read_failed",
    })?;
    if !file.metadata().map_err(|_| "read_failed")?.is_file() {
        return Err("not_a_file");
    }
    let mut data = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut data)
        .map_err(|_| "read_failed")?;
    if data.len() as u64 > limit {
        return Err("size_limit");
    }
    Ok(data)
}

// Deliberately do not include error text: TLS, filesystem and JSON errors may contain
// remote-controlled strings, URL credentials or a user's home directory.
fn error_stage(error: &str) -> &'static str {
    if error.starts_with("DNS:") {
        "dns"
    } else if error.starts_with("TCP:") {
        "tcp"
    } else if error.starts_with("TLS") {
        "tls_or_certificate"
    } else if error.starts_with("HTTP") {
        "http"
    } else {
        "transport"
    }
}

fn connection(report: net::health::ConnReport) -> Value {
    let resolved: Vec<IpAddr> = report
        .resolved
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    let connected = report.connected.and_then(|s| s.parse::<SocketAddr>().ok());
    json!({"host": report.host, "resolved": resolved, "connected": connected,
        "latency_ms": report.latency_ms, "used_ipv6": report.used_ipv6,
        "looks_like_google": report.looks_like_google, "http_status": report.http_status,
        "status": if report.error.is_some() { "failed" } else { "transport_available" },
        "error_stage": report.error.as_deref().map(error_stage)})
}

/// Independent sections finish within their own budget. A stuck OS lookup must not
/// prevent saving the other evidence. At most one collector per named section is started.
fn bounded_jobs(jobs: Vec<(String, Box<dyn FnOnce() -> Value + Send>)>, budget: Duration) -> Value {
    let (tx, rx) = mpsc::channel();
    let mut results = serde_json::Map::new();
    let count = jobs.len();
    for (name, job) in jobs {
        results.insert(name.clone(), unavailable("timeout"));
        let tx = tx.clone();
        std::thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job))
                .unwrap_or_else(|_| unavailable("collector_failed"));
            let _ = tx.send((name, result));
        });
    }
    drop(tx);
    let deadline = Instant::now() + budget;
    for _ in 0..count {
        let Some(left) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        match rx.recv_timeout(left) {
            Ok((name, value)) => {
                results.insert(name, value);
            }
            Err(_) => break,
        }
    }
    Value::Object(results)
}

fn config_summary(config: &net::config::Config) -> Value {
    // Provider names and the entire URL are user-controlled. Neither is exported.
    let doh: Vec<_> = config
        .doh
        .iter()
        .enumerate()
        .map(|(i, p)| {
            json!({
                "provider": i + 1, "bootstrap": p.bootstrap,
                "https": reqwest::Url::parse(&p.url).is_ok_and(|url| url.scheme() == "https")
            })
        })
        .collect();
    let udp: Vec<_> = config
        .extra_udp
        .iter()
        .enumerate()
        .map(|(i, p)| {
            json!({
                "provider": i + 1, "addresses": p.addresses
            })
        })
        .collect();
    json!({"status": "ok", "doh": doh, "extra_udp": udp,
        "mode": "configured-udp-doh",
        "active_providers": net::resolver_pool::from_config(config).ok().map(|pool| pool.iter().enumerate().map(|(i, p)| json!({"provider": i + 1, "transport": p.kind()})).collect::<Vec<_>>()),
        "disabled_provider_count": config.disabled_providers.len(),
        "watch_region_errors": config.watch_region_errors,
        "log_root_count": config.log_roots.len(),
        "log_reading": "bounded recent language-server logs"})
}

fn rank_snapshot(path: &Path) -> Value {
    let bytes = match read_limited(path, MAX_TEXT) {
        Ok(v) => v,
        Err(e) => return unavailable(e),
    };
    let rows: Vec<_> = String::from_utf8_lossy(&bytes)
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let host = fields.next()?;
            if !net::provider::NRPT_AGENT.contains(&host) {
                return None;
            }
            let ip = fields.next()?.parse::<Ipv4Addr>().ok()?;
            let latency = fields.next()?.parse::<u64>().ok()?;
            Some(json!({"host": host, "ip": ip, "latency_ms": latency}))
        })
        .take(64)
        .collect();
    json!({"status": "ok", "entries": rows})
}

fn recent_events(path: &Path) -> Value {
    let mut file = match File::open(path) {
        Ok(v) => v,
        Err(_) => return unavailable("unavailable"),
    };
    let size = match file.metadata() {
        Ok(m) if m.is_file() => m.len(),
        _ => return unavailable("read_failed"),
    };
    let offset = size.saturating_sub(64 * 1024);
    if file.seek(SeekFrom::Start(offset)).is_err() {
        return unavailable("read_failed");
    }
    let mut bytes = Vec::new();
    if file.take(64 * 1024).read_to_end(&mut bytes).is_err() {
        return unavailable("read_failed");
    }
    let text = String::from_utf8_lossy(&bytes);
    let mut events: Vec<_> = text
        .lines()
        .skip(usize::from(offset > 0))
        .filter_map(event_summary)
        .collect();
    events.drain(..events.len().saturating_sub(100));
    json!({"status": "ok", "events": events, "scope": "recognized recovery events only"})
}

fn event_summary(line: &str) -> Option<Value> {
    let (time, message) = line.strip_prefix('[')?.split_once("] ")?;
    let timestamp = time.parse::<u64>().ok()?;
    let kind = if message.starts_with("rank path-down ") {
        "route_changed_after_failure"
    } else if message.starts_with("rank periodic ") {
        "route_refreshed"
    } else if message.starts_with("Региональный отказ: ") {
        "region_refusal"
    } else if message.starts_with("Повторный выбор маршрута не завершён:")
    {
        "route_refresh_failed"
    } else {
        return None;
    };
    // The free-form message is never copied, including configuration dumps from older versions.
    Some(json!({"timestamp_ms": timestamp, "kind": kind}))
}

fn version_text(value: &str) -> Option<String> {
    let valid =
        regex::Regex::new(r"^[0-9]{1,6}\.[0-9]{1,6}(?:\.[0-9]{1,6})?(?:[-+][0-9A-Za-z.-]{1,32})?$")
            .unwrap();
    valid.is_match(value).then(|| value.to_owned())
}

fn installations() -> Value {
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for root in detector::find_installations().into_iter().take(64) {
        let mut versions = BTreeSet::new();
        for relative in [
            "package.json",
            "resources/app/package.json",
            "Contents/Resources/app/package.json",
        ] {
            if let Ok(bytes) = read_limited(&root.join(relative), MAX_TEXT) {
                if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                    if let Some(v) = value["version"].as_str().and_then(version_text) {
                        versions.insert(v);
                    }
                }
            }
        }
        let mut targets = Vec::new();
        for target in detector::find_targets_in_path(&root).into_iter().take(32) {
            if !seen.insert(target.path.clone()) {
                continue;
            }
            let size = fs::metadata(&target.path).ok().map(|m| m.len());
            let inspected = size.is_some_and(|n| n <= 256 * 1024 * 1024);
            let state = if inspected {
                format!("{:?}", patcher::check_target_state(&target))
            } else {
                "not_inspected".into()
            };
            if inspected && target.kind == detector::TargetKind::IdeAsar {
                if let Some(v) = crate::core::asar::read_asar_package_version(&target.path)
                    .as_deref()
                    .and_then(version_text)
                {
                    versions.insert(v);
                }
            }
            targets.push(
                json!({"component": format!("{:?}", target.kind), "size_bytes": size,
                "architecture": binary_architecture(&target.path), "patch_state": state}),
            );
        }
        if !targets.is_empty() || !versions.is_empty() {
            result.push(
                json!({"installation": result.len() + 1, "versions": versions, "targets": targets}),
            );
        }
    }
    json!({"status": "ok", "installations": result, "paths": "omitted", "discovery": "standard locations and PATH"})
}

fn binary_architecture(path: &Path) -> Option<&'static str> {
    let mut file = File::open(path).ok()?;
    let mut header = [0u8; 64];
    file.read_exact(&mut header).ok()?;
    let machine = if header.starts_with(b"MZ") {
        let offset = u32::from_le_bytes(header[60..64].try_into().ok()?);
        if offset > 1024 * 1024 {
            return None;
        }
        file.seek(SeekFrom::Start(offset as u64)).ok()?;
        let mut pe = [0u8; 6];
        file.read_exact(&mut pe).ok()?;
        if !pe.starts_with(b"PE\0\0") {
            return None;
        }
        match u16::from_le_bytes([pe[4], pe[5]]) {
            0x8664 => 7,
            0xaa64 => 12,
            _ => return None,
        }
    } else if header.starts_with(&[0xcf, 0xfa, 0xed, 0xfe]) {
        u32::from_le_bytes(header[4..8].try_into().ok()?) & 0x00ff_ffff
    } else if header.starts_with(&[0xfe, 0xed, 0xfa, 0xcf]) {
        u32::from_be_bytes(header[4..8].try_into().ok()?) & 0x00ff_ffff
    } else if matches!(
        header[..4],
        [0xca, 0xfe, 0xba, 0xbe]
            | [0xbe, 0xba, 0xfe, 0xca]
            | [0xca, 0xfe, 0xba, 0xbf]
            | [0xbf, 0xba, 0xfe, 0xca]
    ) {
        return Some("universal");
    } else {
        return None;
    };
    match machine {
        7 => Some("x86_64"),
        12 => Some("aarch64"),
        _ => None,
    }
}

fn fingerprint(path: &Path) -> Option<String> {
    let mut file = File::open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut hash = Sha256::new();
    let mut remaining = 64 * 1024 * 1024usize;
    let mut buffer = [0; 64 * 1024];
    loop {
        let n = file.read(&mut buffer).ok()?;
        if n == 0 {
            return Some(format!("{:x}", hash.finalize()));
        }
        remaining = remaining.checked_sub(n)?;
        hash.update(&buffer[..n]);
    }
}

fn service_summary() -> Value {
    let installed = fingerprint(&system::service::installed_exe());
    let current = std::env::current_exe().ok().and_then(|p| fingerprint(&p));
    let same = installed
        .as_ref()
        .zip(current.as_ref())
        .map(|(a, b)| a == b);
    let registered = system::service::registered_state();
    let running = system::service::running_state();
    json!({"status": if registered.is_ok() && running.is_ok() { "ok" } else { "partial" },
        "registered": registered.ok(), "process_detected": running.ok(),
        "installed_binary_sha256": installed, "current_binary_sha256": current,
        "installed_matches_current": same,
        "note": "process detection alone does not confirm DNS readiness"})
}

fn relay_probe(port: u16) -> Value {
    let name = if port == net::relay::HEALTH_PORT {
        net::relay::HEALTH_NAME
    } else {
        "cloudcode-pa.googleapis.com"
    };
    let query = net::client::build_query(name, 0xD154);
    let reply = net::client::query_raw_to(
        &query,
        std::net::SocketAddrV4::new(net::relay::LISTEN_IP.parse().unwrap(), port),
        0,
        Duration::from_millis(if port == net::relay::HEALTH_PORT {
            800
        } else {
            5000
        }),
    );
    match reply {
        Ok(bytes) => {
            json!({"status": if net::client::is_successful_response(&bytes) { "responding" } else { "dns_error" },
            "rcode": bytes.get(3).map(|b| b & 15), "name": name, "answers": net::client::answer_addrs(&bytes)})
        }
        Err(_) => unavailable("no_response"),
    }
}

pub fn collect() -> Value {
    let started = net::route_health::now_ms();
    let pins = net::hosts::owned_entries();
    let ranks = rank_snapshot(&net::rank::rank_path());
    let state = net::route_health::store().snapshot();
    let mut candidates: BTreeSet<(String, Ipv4Addr)> = BTreeSet::new();
    for host in net::provider::NRPT_AGENT {
        let mut ips = BTreeSet::new();
        // Actual pins take priority over the cached rank when they disagree.
        if let Ok(pins) = &pins {
            for (h, ip) in pins.iter().filter(|(h, _)| h == host) {
                candidates.insert((h.clone(), *ip));
                ips.insert(*ip);
            }
        }
        if let Some(rows) = ranks["entries"].as_array() {
            for row in rows.iter().filter(|v| v["host"] == *host) {
                if ips.len() >= 3 {
                    break;
                }
                if let Some(ip) = row["ip"].as_str().and_then(|s| s.parse().ok()) {
                    ips.insert(ip);
                    candidates.insert(((*host).into(), ip));
                }
            }
        }
    }
    let route_ips: Vec<_> = candidates
        .iter()
        .map(|(_, ip)| *ip)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut jobs: Vec<(String, Box<dyn FnOnce() -> Value + Send>)> = vec![
        ("installations".into(), Box::new(installations)),
        ("service".into(), Box::new(service_summary)),
        (
            "model_observation".into(),
            Box::new(|| serde_json::to_value(crate::model_status::snapshot()).unwrap()),
        ),
        (
            "dns_capabilities".into(),
            Box::new(|| {
                let interface = net::egress::detect().map(|e| e.if_index).unwrap_or(0);
                match net::resolvers::capabilities(interface) {
                    Ok(rows) => {
                        json!({"status": "ok", "providers": rows, "scope": "DNS substitution per domain; not model access"})
                    }
                    Err(_) => unavailable("unreadable_or_invalid_configuration"),
                }
            }),
        ),
        (
            "system_network".into(),
            Box::new(move || platform::network(&route_ips)),
        ),
        ("os_version".into(), Box::new(platform::os_version)),
        (
            "configuration".into(),
            Box::new(|| match net::config::load() {
                Ok(config) => config_summary(&config),
                Err(_) => unavailable("unreadable_or_invalid"),
            }),
        ),
        (
            "relay_dns_port".into(),
            Box::new(|| relay_probe(net::relay::LISTEN_PORT)),
        ),
        (
            "relay_health_port".into(),
            Box::new(|| relay_probe(net::relay::HEALTH_PORT)),
        ),
    ];
    for host in net::provider::NRPT_AGENT {
        jobs.push((
            format!("connection:{host}"),
            Box::new(move || connection(net::health::probe_host(host))),
        ));
    }
    for (host, ip) in candidates {
        jobs.push((
            format!("candidate:{host}:{ip}"),
            Box::new(move || {
                let result = net::health::probe_ip((ip, 443).into(), &host);
                json!({"host": host, "ip": ip, "latency_ms": result.as_ref().ok(),
                "status": if result.is_ok() { "transport_available" } else { "failed" },
                "error_stage": result.err().as_deref().map(error_stage)})
            }),
        ));
    }
    let checks = bounded_jobs(jobs, Duration::from_secs(20));
    let safe_pins: Vec<_> = pins
        .as_ref()
        .map(|p| {
            p.iter()
                .filter(|(h, _)| net::provider::NRPT_AGENT.contains(&h.as_str()))
                .map(|(h, ip)| json!({"host": h, "ip": ip}))
                .collect()
        })
        .unwrap_or_default();
    json!({
        "schema_version": 1, "bypass_version": env!("CARGO_PKG_VERSION"),
        "os": std::env::consts::OS, "architecture": std::env::consts::ARCH,
        "started_ms": started, "finished_ms": net::route_health::now_ms(),
        "model_access": "not_tested; verify with a real request in Antigravity",
        "privacy": "Local report; no account data, prompts, raw logs, paths or provider URLs. Contains server and local gateway IP addresses.",
        "hosts": {"status": if pins.is_ok() { "ok" } else { "unreadable_or_conflicting" }, "owned_entries": safe_pins},
        "rank": ranks,
        "configured_interface": net::relay::load_if_index(),
        "configured_upstream_dns": net::relay::load_upstream_servers(),
        "route_health": state.map(|s| s.diagnostic_snapshot(started)).unwrap_or_else(|_| unavailable("unreadable_or_invalid")),
        "recent_recovery": recent_events(&net::config::directory().join("network-events.log")),
        "previous_recovery": recent_events(&net::config::directory().join("network-events.previous.log")),
        "checks": checks
    })
}

fn write_report(directory: &Path, report: &Value) -> Result<PathBuf, String> {
    let mut file = tempfile::Builder::new()
        .prefix("antigravity-diagnostics-")
        .suffix(".json")
        .tempfile_in(directory)
        .map_err(|e| format!("Не создать отчёт: {e}"))?;
    serde_json::to_writer_pretty(&mut file, report).map_err(|e| e.to_string())?;
    file.write_all(b"\n")
        .and_then(|_| file.as_file().sync_all())
        .map_err(|e| e.to_string())?;
    #[cfg(unix)]
    if unsafe { libc::geteuid() } == 0 {
        net::config::inherit_directory_owner(file.path())?;
    }
    let (_, path) = file.keep().map_err(|e| e.to_string())?;
    Ok(path)
}

pub fn save(directory: Option<&Path>) -> Result<PathBuf, String> {
    let directory = if let Some(path) = directory {
        // A supplied destination must exist; do not silently create a mistyped tree.
        path.to_path_buf()
    } else {
        net::config::ensure_directory()?;
        net::config::directory()
    };
    if !directory.is_dir() {
        return Err("Каталог для отчёта не существует".into());
    }
    let directory = fs::canonicalize(directory).map_err(|e| e.to_string())?;
    write_report(&directory, &collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_architecture_is_read_without_executing_the_application() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("application");
        let mut data = vec![0u8; 128];
        data[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        data[4..8].copy_from_slice(&0x0100_000cu32.to_le_bytes());
        fs::write(&file, &data).unwrap();
        assert_eq!(binary_architecture(&file), Some("aarch64"));
        data[..2].copy_from_slice(b"MZ");
        data[60..64].copy_from_slice(&64u32.to_le_bytes());
        data[64..70].copy_from_slice(b"PE\0\0\x64\x86");
        fs::write(&file, &data).unwrap();
        assert_eq!(binary_architecture(&file), Some("x86_64"));
        fs::write(&file, b"#!/bin/sh\nSECRET").unwrap();
        assert_eq!(binary_architecture(&file), None);
    }

    #[test]
    fn route_report_keeps_bans_but_omits_event_ids_and_unrelated_hosts() {
        use net::route_health::{Key, State};
        let mut state = State::default();
        let host = "cloudcode-pa.googleapis.com";
        let key = Key::ip(host, "1.2.3.4:443".parse().unwrap());
        state.record(&key, Ok(12), 1000);
        state.region_refusal("SECRET_EVENT_ID", Some(host), Some(&key.route), 1100);
        state.record(
            &Key::ip("SECRET_HOST", "2.3.4.5:443".parse().unwrap()),
            Ok(12),
            1000,
        );
        let result = state.diagnostic_snapshot(1200);
        assert!(!result.to_string().contains("SECRET"));
        assert_eq!(result["entries"].as_array().unwrap().len(), 1);
        assert_eq!(result["entries"][0]["blocked_now"], true);
    }

    #[test]
    fn report_omits_secrets_from_configuration_errors_and_legacy_logs() {
        let mut config = net::config::Config::default();
        config.doh[0].name = "SECRET_PROVIDER".into();
        config.doh[0].url = "https://SECRET_HOST.test/SECRET_PATH?key=SECRET_KEY".into();
        config.log_roots = vec![PathBuf::from("/SECRET_USER/logs")];
        let report = json!({"config": config_summary(&config),
            "error": connection(net::health::ConnReport { host: net::provider::NRPT_AGENT[0].into(),
                error: Some("TLS: SECRET_TOKEN /SECRET_USER".into()), ..Default::default() }),
            "event": event_summary("[123] Повторный выбор маршрута не завершён: SECRET_TOKEN")});
        assert!(!report.to_string().contains("SECRET"));
        assert!(event_summary("[123] DNS servers: config: SECRET_TOKEN").is_none());
        assert_eq!(report["error"]["error_stage"], "tls_or_certificate");
        assert!(version_text("1.2.3\nSECRET").is_none());
        assert!(version_text("1.2.3").is_some());
    }

    #[test]
    fn corrupt_and_oversize_files_do_not_leak_content_or_prevent_report_saving() {
        let temp = tempfile::tempdir().unwrap();
        let rank = temp.path().join("rank");
        fs::write(
            &rank,
            "SECRET_HOST 1.2.3.4 1\ncloudcode-pa.googleapis.com 5.6.7.8 12\nSECRET",
        )
        .unwrap();
        let report = json!({"rank": rank_snapshot(&rank), "missing": rank_snapshot(&temp.path().join("absent"))});
        assert!(!report.to_string().contains("SECRET"));
        assert_eq!(report["rank"]["entries"].as_array().unwrap().len(), 1);
        assert_eq!(report["missing"]["status"], "not_found");
        let first = write_report(temp.path(), &report).unwrap();
        let second = write_report(temp.path(), &json!({"second": true})).unwrap();
        assert_ne!(first, second);
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(first).unwrap()).unwrap(),
            report
        );
        fs::write(&rank, vec![0; MAX_TEXT as usize + 1]).unwrap();
        assert_eq!(rank_snapshot(&rank)["status"], "size_limit");
    }

    #[test]
    fn stalled_check_preserves_completed_sections() {
        // Keep the slow collector blocked until after the deadline, even when CI
        // pauses this thread between spawning collectors and starting the budget.
        let (release, blocked) = mpsc::channel::<()>();
        let result = bounded_jobs(
            vec![
                ("fast".into(), Box::new(|| json!(42))),
                (
                    "stalled".into(),
                    Box::new(move || {
                        let _ = blocked.recv();
                        json!(1)
                    }),
                ),
            ],
            Duration::from_secs(2),
        );
        drop(release);
        assert_eq!(result["fast"], 42);
        assert_eq!(result["stalled"]["status"], "timeout");
    }
}
