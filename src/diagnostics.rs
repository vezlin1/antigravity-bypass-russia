//! Local, opt-in support reports. Export an allowlist, never raw configuration or logs.
pub mod attempt;
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
    static VALID: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"^[0-9]{1,6}\.[0-9]{1,6}(?:\.[0-9]{1,6})?(?:[-+][0-9A-Za-z.-]{1,32})?$")
            .unwrap()
    });
    VALID.is_match(value).then(|| value.to_owned())
}

fn installations() -> Value {
    installations_for(detector::find_installations_with_sources())
}

fn installations_for(roots: Vec<(PathBuf, detector::DiscoverySource)>) -> Value {
    const MAX_TARGET_INSPECT_BYTES: u64 = 256 * 1024 * 1024;
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for (root, source) in roots.into_iter().take(64) {
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
        // Read App/IDE version directly from app.asar so Antigravity App's
        // version is preserved even when its non-IDE archive is not a patch target.
        if let Some(asar) = detector::find_asar_in_path(&root) {
            if let Some(v) = crate::core::asar::read_asar_package_version(&asar)
                .as_deref()
                .and_then(version_text)
            {
                versions.insert(v);
            }
        }
        let mut targets = Vec::new();
        for target in detector::find_targets_in_path(&root).into_iter().take(32) {
            if target.kind == detector::TargetKind::IdeAsar
                && crate::core::asar::has_ide_entry(&target.path) == Some(false)
            {
                continue;
            }
            let dedup_key = fs::canonicalize(&target.path).unwrap_or_else(|_| target.path.clone());
            if !seen.insert(dedup_key) {
                continue;
            }
            let size = fs::metadata(&target.path).ok().map(|m| m.len());
            let inspected = size.is_some_and(|n| n <= MAX_TARGET_INSPECT_BYTES);
            if inspected && target.kind == detector::TargetKind::IdeAsar {
                if let Some(v) = crate::core::asar::read_asar_package_version(&target.path)
                    .as_deref()
                    .and_then(version_text)
                {
                    versions.insert(v);
                }
            }
            let inspection = inspected.then(|| patcher::inspect_target(&target));
            let state = match &inspection {
                Some(info) => format!("{:?}", info.state),
                None => "not_inspected".into(),
            };
            let needs_identity = matches!(
                inspection.as_ref().map(|info| info.state),
                None | Some(patcher::BinaryState::Unknown | patcher::BinaryState::PartiallyPatched)
            );
            let mut entry = serde_json::Map::new();
            entry.insert("component".into(), json!(format!("{:?}", target.kind)));
            entry.insert("size_bytes".into(), json!(size));
            entry.insert(
                "architecture".into(),
                json!(binary_architecture(&target.path)),
            );
            entry.insert("patch_state".into(), json!(state));
            if needs_identity {
                if let Some(name) = attempt::safe_file_name(&target.path) {
                    entry.insert("file_name".into(), json!(name));
                }
                if inspected {
                    if let Some(digest) =
                        sha256_limited(&target.path, MAX_TARGET_INSPECT_BYTES as usize)
                    {
                        entry.insert("sha256".into(), json!(digest));
                    }
                }
                if let Some(info) = &inspection {
                    if let Some(profile) = info.profile {
                        entry.insert("profile".into(), json!(profile));
                    }
                    if let Some(reason) = info.reason {
                        entry.insert("reason".into(), json!(reason));
                    }
                    if let Some(counts) = info.counts {
                        let mut count_map = serde_json::Map::new();
                        if let Some(matches) = counts.matches {
                            count_map.insert("matches".into(), json!(matches));
                        }
                        if let Some(core) = counts.core {
                            count_map.insert("core".into(), json!(core));
                        }
                        if let Some(login) = counts.login {
                            count_map.insert("login".into(), json!(login));
                        }
                        if !count_map.is_empty() {
                            entry.insert("match_counts".into(), Value::Object(count_map));
                        }
                    }
                }
            }
            targets.push(Value::Object(entry));
        }
        if !targets.is_empty() || !versions.is_empty() {
            result.push(json!({
                "installation": result.len() + 1,
                "discovery_source": source.as_str(),
                "versions": versions,
                "targets": targets
            }));
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

fn sha256_limited(path: &Path, limit: usize) -> Option<String> {
    let mut file = File::open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut hash = Sha256::new();
    let mut remaining = limit;
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

fn fingerprint(path: &Path) -> Option<String> {
    sha256_limited(path, 64 * 1024 * 1024)
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
    json!({
        "status": "pending",
        "query_status": if registered.is_ok() && running.is_ok() { "ok" } else { "partial" },
        "registered": registered.ok(),
        "process_detected": running.ok(),
        "installed_binary_sha256": installed,
        "current_binary_sha256": current,
        "installed_matches_current": same,
        "note": "process detection alone does not confirm DNS readiness"
    })
}

fn has_non_public_answer(port_report: &Value) -> bool {
    port_report["answers"].as_array().is_some_and(|answers| {
        !answers.is_empty()
            && answers.iter().all(|value| {
                value
                    .as_str()
                    .and_then(|s| s.parse::<IpAddr>().ok())
                    .is_some_and(|ip| match ip {
                        IpAddr::V4(v4) => {
                            v4.is_loopback()
                                || v4.is_private()
                                || v4.is_unspecified()
                                || v4.is_link_local()
                        }
                        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
                    })
            })
    })
}

fn finalize_service_check(service: &mut Value, dns_port: &mut Value, health_port: &Value) {
    let dns_raw_ok = dns_port["status"].as_str() == Some("responding");
    let health_ok = health_port["status"].as_str() == Some("responding");
    let foreign_dns = dns_raw_ok && (!health_ok || has_non_public_answer(dns_port));
    if foreign_dns {
        if let Some(dns_map) = dns_port.as_object_mut() {
            dns_map.insert("status".into(), json!("foreign_dns"));
        }
    }

    let Some(map) = service.as_object_mut() else {
        return;
    };
    if !map.contains_key("query_status") {
        // Timed out or collector failed: preserve its unavailable status.
        return;
    }
    let dns_ok = dns_raw_ok && !foreign_dns;
    let both_responding = dns_ok && health_ok;
    let any_responding = dns_ok || health_ok;
    let registered = map.get("registered").and_then(Value::as_bool);
    let running = map.get("process_detected").and_then(Value::as_bool);
    let matches_current = map
        .get("installed_matches_current")
        .and_then(Value::as_bool);

    let state = match (registered, running) {
        (None, _) | (_, None) => "query_failed",
        _ if foreign_dns => "port_53_conflict",
        (Some(false), Some(false)) if !any_responding => "not_installed",
        (Some(false), _) if any_responding => "unregistered_responding",
        (Some(true), Some(false)) if !any_responding => "registered_not_running",
        (_, Some(true)) if !any_responding => "running_not_responding",
        (Some(true), Some(true)) if both_responding && matches_current == Some(false) => {
            "running_binary_mismatch"
        }
        (Some(true), Some(true)) if both_responding => "running",
        _ if any_responding && matches_current == Some(false) => "running_binary_mismatch",
        _ if any_responding => "degraded_ports",
        _ => "not_installed",
    };

    map.insert("status".into(), json!(state));
    map.insert("dns_port_responding".into(), json!(dns_ok));
    map.insert("health_port_responding".into(), json!(health_ok));
    if foreign_dns {
        map.insert("foreign_dns_on_port_53".into(), json!(true));
    }
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
    for host in net::provider::NRPT_AGENT
        .iter()
        .copied()
        .chain(["gemini.google.com", "aistudio.google.com"])
    {
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
    let mut checks = bounded_jobs(jobs, Duration::from_secs(20));
    if let Some(map) = checks.as_object_mut() {
        let mut dns_port = map.get("relay_dns_port").cloned().unwrap_or(Value::Null);
        let health_port = map.get("relay_health_port").cloned().unwrap_or(Value::Null);
        if let Some(service) = map.get_mut("service") {
            finalize_service_check(service, &mut dns_port, &health_port);
            if service["foreign_dns_on_port_53"] == true {
                let owners = system::process::udp_port_owners(
                    net::relay::LISTEN_IP.parse().unwrap(),
                    net::relay::LISTEN_PORT,
                );
                if let Some(service) = service.as_object_mut() {
                    service.insert("port_53_owners".into(), json!(owners));
                }
            }
        }
        if map.contains_key("relay_dns_port") {
            map.insert("relay_dns_port".into(), dns_port);
        }
    }
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
        "last_attempt": attempt::snapshot(),
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

    #[test]
    fn service_check_reports_actual_runtime_state() {
        let down = json!({"status": "no_response"});
        let up = json!({"status": "responding", "answers": ["31.58.216.201"]});
        let health_up = json!({"status": "responding", "answers": ["127.0.0.1"]});

        let mut not_installed = json!({
            "status": "pending",
            "query_status": "ok",
            "registered": false,
            "process_detected": false,
            "installed_matches_current": null
        });
        let mut dns = down.clone();
        finalize_service_check(&mut not_installed, &mut dns, &down);
        assert_eq!(not_installed["status"], "not_installed");
        assert_eq!(not_installed["dns_port_responding"], false);
        assert_eq!(not_installed["health_port_responding"], false);

        let mut mismatch = json!({
            "status": "pending",
            "query_status": "ok",
            "registered": true,
            "process_detected": true,
            "installed_matches_current": false
        });
        let mut dns = up.clone();
        finalize_service_check(&mut mismatch, &mut dns, &health_up);
        assert_eq!(mismatch["status"], "running_binary_mismatch");
        assert_eq!(mismatch["dns_port_responding"], true);
        assert_eq!(mismatch["health_port_responding"], true);

        let mut healthy = json!({
            "status": "pending",
            "query_status": "ok",
            "registered": true,
            "process_detected": true,
            "installed_matches_current": true
        });
        let mut dns = up.clone();
        finalize_service_check(&mut healthy, &mut dns, &health_up);
        assert_eq!(healthy["status"], "running");

        let mut stuck = json!({
            "status": "pending",
            "query_status": "ok",
            "registered": true,
            "process_detected": true,
            "installed_matches_current": true
        });
        let mut dns = down.clone();
        finalize_service_check(&mut stuck, &mut dns, &down);
        assert_eq!(stuck["status"], "running_not_responding");

        // Issue #57: foreign DNS (e.g. AdGuard 127.65.71.1) occupies port 53 while our health port is silent.
        let mut conflict = json!({
            "status": "pending",
            "query_status": "ok",
            "registered": true,
            "process_detected": false,
            "installed_matches_current": true
        });
        let mut foreign = json!({"status": "responding", "answers": ["127.65.71.1"]});
        finalize_service_check(&mut conflict, &mut foreign, &down);
        assert_eq!(conflict["status"], "port_53_conflict");
        assert_eq!(conflict["foreign_dns_on_port_53"], true);
        assert_eq!(conflict["dns_port_responding"], false);
        assert_eq!(foreign["status"], "foreign_dns");

        let mut failed_query = json!({
            "status": "pending",
            "query_status": "partial",
            "registered": null,
            "process_detected": false,
            "installed_matches_current": null
        });
        let mut dns = down.clone();
        finalize_service_check(&mut failed_query, &mut dns, &down);
        assert_eq!(failed_query["status"], "query_failed");
    }

    #[test]
    fn installations_report_skips_app_asar_and_desktop_rtc_and_identifies_unknown_cli() {
        fn app_asar(version: &str) -> Vec<u8> {
            let pkg = format!(r#"{{"name":"antigravity","version":"{version}"}}"#).into_bytes();
            let main_js = b"// app dist";
            let header = serde_json::to_vec(&json!({
                "files": {
                    "package.json": {"size": pkg.len(), "offset": "0"},
                    "dist": {"files": {
                        "main.js": {"size": main_js.len(), "offset": pkg.len().to_string()}
                    }}
                }
            }))
            .unwrap();
            let header_size = 8 + header.len().div_ceil(4) * 4;
            let mut data = Vec::new();
            for value in [
                4u32,
                header_size as u32,
                (header_size - 4) as u32,
                header.len() as u32,
            ] {
                data.extend(value.to_le_bytes());
            }
            data.extend(header);
            data.resize(8 + header_size, 0);
            data.extend(pkg);
            data.extend(main_js);
            data
        }

        fn go_pe_fixture() -> Vec<u8> {
            let mut data = vec![0u8; 1024];
            data[..2].copy_from_slice(b"MZ");
            data[60..64].copy_from_slice(&128u32.to_le_bytes());
            data[128..132].copy_from_slice(b"PE\0\0");
            for (offset, value) in [(132, 0x8664u16), (134, 1), (148, 240), (152, 0x20b)] {
                data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
            }
            data[392..400].copy_from_slice(b".data\0\0\0");
            for (offset, value) in [(400, 512u32), (404, 0x1000), (408, 512), (412, 512)] {
                data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            }
            data[512..526].copy_from_slice(b"\xff Go buildinf:");
            data[526] = 8;
            data[527] = 2;
            data
        }

        let dir = tempfile::tempdir().unwrap();
        let app_root = dir.path().join("SECRET_USER_APP");
        fs::create_dir_all(app_root.join("resources/bin")).unwrap();
        fs::write(app_root.join("resources/app.asar"), app_asar("2.35.2")).unwrap();
        fs::write(
            app_root.join("resources/bin/agy-desktop-rtc"),
            go_pe_fixture(),
        )
        .unwrap();

        let cli_dir = dir.path().join("SECRET_PATH_BIN");
        fs::create_dir_all(&cli_dir).unwrap();
        let unknown_cli = cli_dir.join("agy.exe");
        fs::write(&unknown_cli, go_pe_fixture()).unwrap();
        let canonical_cli = fs::canonicalize(&unknown_cli).unwrap();

        let report = installations_for(vec![
            (app_root, detector::DiscoverySource::Standard),
            (cli_dir, detector::DiscoverySource::Standard),
            (canonical_cli, detector::DiscoverySource::Path),
        ]);
        assert!(!report.to_string().contains("SECRET"));
        let items = report["installations"].as_array().unwrap();
        assert_eq!(items.len(), 2);

        // Antigravity App: version preserved, no false IdeAsar, no agy-desktop-rtc.
        assert_eq!(items[0]["discovery_source"], "standard");
        assert_eq!(items[0]["versions"], json!(["2.35.2"]));
        assert!(items[0]["targets"].as_array().unwrap().is_empty());

        // Unknown CLI discovered both by folder and verbatim canonical path appears once.
        assert_eq!(items[1]["discovery_source"], "standard");
        let target = &items[1]["targets"][0];
        assert_eq!(target["component"], "AgyCli");
        assert_eq!(target["patch_state"], "Unknown");
        assert_eq!(target["file_name"], "agy.exe");
        assert_eq!(target["profile"], "agy-x64-long-v2");
        assert_eq!(target["reason"], "profile_mismatch");
        assert_eq!(target["match_counts"]["matches"], 0);
        assert_eq!(target["sha256"].as_str().unwrap().len(), 64);
    }
}
