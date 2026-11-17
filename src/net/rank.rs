//! Rank substituted proxy IPs by TLS speed and keep a short fallback list.
//!
//! Certificate and HTTP checks run when the user enables the bypass.
//! No scheduled rescans or model-response measurements.

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::net::hosts::write_entries as write_hosts_entries;
use crate::net::provider::{NRPT_AGENT, PRIMARY_CLOUD_CODE};
use crate::net::relay;
use crate::net::resolvers;
use crate::net::routes;

const MAX_FALLBACKS: usize = 3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RankedHost {
    pub host: String,
    pub ips: Vec<(Ipv4Addr, u128)>,
}

pub fn rank_path() -> PathBuf {
    relay::log_dir().join("proxy_rank.conf")
}

pub(super) fn discover_agent(
    if_index: u32,
    prepare_routes: &mut dyn FnMut(&[Ipv4Addr]) -> Result<(), String>,
) -> Result<Vec<RankedHost>, String> {
    let previous = load();
    let geohide_enabled = super::resolver_pool::load()?
        .iter()
        .any(|p| p.name == "geohide.ru");
    let mut host_candidates = Vec::new();
    let mut addresses = std::collections::BTreeSet::new();
    for name in NRPT_AGENT {
        let host = name.trim_start_matches('.').to_string();
        let mut candidates = resolvers::candidate_addrs(&host, if_index)?;
        if let Some(old) = previous.iter().find(|h| h.host == host) {
            for (ip, _) in &old.ips {
                let a = IpAddr::V4(*ip);
                if !candidates.contains(&a) {
                    candidates.push(a);
                }
            }
        }
        for seed in crate::net::provider::GEOHIDE_PROXY_V4
            .iter()
            .filter(|_| geohide_enabled)
        {
            if let Ok(v4) = seed.parse::<Ipv4Addr>() {
                let a = IpAddr::V4(v4);
                if !candidates.contains(&a) {
                    candidates.push(a);
                }
            }
        }
        // Test the same physical path that will be used after pinning. Custom
        // DoH answers can introduce proxy IPs absent from the built-in routes.
        let candidates: Vec<_> = candidates
            .into_iter()
            .filter(IpAddr::is_ipv4)
            .take(32)
            .collect();
        addresses.extend(candidates.iter().filter_map(|ip| match ip {
            IpAddr::V4(ip) => Some(*ip),
            _ => None,
        }));
        host_candidates.push((host, candidates));
    }

    // The same relay often serves several names. Inspect its OS route once
    // before probing TLS separately with each host's SNI.
    prepare_routes(&addresses.into_iter().collect::<Vec<_>>())?;
    let mut ranked = Vec::new();
    for (host, candidates) in host_candidates {
        let mut ips = resolvers::rank_tls_v4(&candidates, &host);
        if ips.is_empty() {
            continue;
        }
        if ips.len() > MAX_FALLBACKS {
            ips.truncate(MAX_FALLBACKS);
        }
        ranked.push(RankedHost { host, ips });
    }
    Ok(ranked)
}

pub(super) fn apply_ranked(ranked: &[RankedHost], skip_primary: bool) -> Result<(), String> {
    apply_complete_ranking(ranked, skip_primary, || {
        routes::sync_physical_hosts(&ranked_ips(ranked))?;
        save(ranked)?;
        apply_hosts(ranked)
    })
}

// An incomplete scan must never replace a previously working hosts block or
// ranking. In particular, a reachable native endpoint cannot stand in for the
// daily endpoint that is configured in the application.
pub(super) fn check_agent_routes(
    ranked: &[RankedHost],
    daily_configured: impl FnOnce() -> bool,
) -> Result<bool, String> {
    let missing: Vec<_> = NRPT_AGENT
        .iter()
        .filter(|host| {
            let mut rows = ranked
                .iter()
                .filter(|row| super::route_health::host_name(&row.host) == **host);
            !matches!(rows.next(), Some(row) if !row.ips.is_empty()) || rows.next().is_some()
        })
        .copied()
        .collect();
    if missing.is_empty() {
        return Ok(false);
    }
    if missing == [PRIMARY_CLOUD_CODE]
        && !ranked
            .iter()
            .any(|row| super::route_health::host_name(&row.host) == PRIMARY_CLOUD_CODE)
    {
        return if daily_configured() {
            Ok(true)
        } else {
            Err(format!(
                "Нет проверенного маршрута для {PRIMARY_CLOUD_CODE}. Настройки daily для закрытых клиентов не подтверждены. Прежние hosts и рейтинг сохранены"
            ))
        };
    }
    Err(format!(
        "Нет однозначного проверенного маршрута для {}; прежние hosts и рейтинг сохранены",
        missing.join(", ")
    ))
}

fn apply_complete_ranking(
    ranked: &[RankedHost],
    skip_primary: bool,
    apply: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    check_agent_routes(ranked, || skip_primary)?;
    apply()
}

pub fn format_notes(ranked: &[RankedHost]) -> Vec<String> {
    ranked
        .iter()
        .map(|h| {
            let list = h
                .ips
                .iter()
                .map(|(ip, ms)| format!("{ip} {ms}мс"))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{} → {}", h.host, list)
        })
        .collect()
}

fn ranked_ips(ranked: &[RankedHost]) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    for h in ranked {
        for (ip, _) in &h.ips {
            if !out.contains(ip) {
                out.push(*ip);
            }
        }
    }
    out
}

fn apply_hosts(ranked: &[RankedHost]) -> Result<(), String> {
    let mut entries: Vec<(String, Ipv4Addr)> = Vec::new();
    for h in ranked {
        // Pin ONLY the single fastest leader IP for each host into hosts file.
        // This prevents Windows getaddrinfo and Electron Happy Eyeballs from attempting
        // slower fallback IPs and causing 1-3s connection stalling.
        if let Some((best_ip, _)) = h.ips.first() {
            entries.push((h.host.clone(), *best_ip));
        }
    }
    if !entries.is_empty() {
        write_hosts_entries(&entries)?;
    }
    Ok(())
}

fn save(ranked: &[RankedHost]) -> Result<(), String> {
    let dir = relay::log_dir();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut out = format!("# antigravity-proxy-rank 1\n# ts={ts}\n");
    for h in ranked {
        for (ip, ms) in &h.ips {
            out.push_str(&format!("{} {} {}\n", h.host, ip, ms));
        }
    }
    crate::system::fs_utils::robust_write_file(&rank_path(), out.as_bytes())
}

fn load() -> Vec<RankedHost> {
    let Ok(text) = fs::read_to_string(rank_path()) else {
        return Vec::new();
    };
    let mut ranked: Vec<RankedHost> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(host) = parts.next() else { continue };
        let Some(ip) = parts.next().and_then(|s| s.parse::<Ipv4Addr>().ok()) else {
            continue;
        };
        let ms = parts
            .next()
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or(0);
        if let Some(existing) = ranked.iter_mut().find(|h| h.host == host) {
            if !existing.ips.iter().any(|(x, _)| *x == ip) {
                existing.ips.push((ip, ms));
            }
        } else {
            ranked.push(RankedHost {
                host: host.to_string(),
                ips: vec![(ip, ms)],
            });
        }
    }
    ranked
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_ranking() -> Vec<RankedHost> {
        NRPT_AGENT
            .iter()
            .enumerate()
            .map(|(index, host)| RankedHost {
                host: (*host).into(),
                ips: vec![(Ipv4Addr::new(192, 0, 2, index as u8 + 1), 10)],
            })
            .collect()
    }

    #[test]
    fn incomplete_scan_preserves_previous_hosts_and_ranking_before_any_write() {
        let directory = tempfile::tempdir().unwrap();
        let hosts = directory.path().join("hosts");
        let rank = directory.path().join("proxy_rank.conf");
        fs::write(&hosts, b"previous working hosts").unwrap();
        fs::write(&rank, b"previous working ranking").unwrap();
        for missing in 0..NRPT_AGENT.len() {
            let mut ranked = complete_ranking();
            ranked.remove(missing);
            let error = apply_complete_ranking(&ranked, false, || {
                fs::write(&rank, b"replacement").unwrap();
                fs::write(&hosts, b"replacement").unwrap();
                Ok(())
            })
            .unwrap_err();
            assert!(error.contains(NRPT_AGENT[missing]), "{error}");
            assert_eq!(fs::read(&rank).unwrap(), b"previous working ranking");
            assert_eq!(fs::read(&hosts).unwrap(), b"previous working hosts");
        }
    }

    #[test]
    fn every_agent_needs_one_nonempty_route_and_complete_scans_can_be_applied() {
        let ranked = complete_ranking();
        for index in 0..ranked.len() {
            let mut empty = ranked.clone();
            empty[index].ips.clear();
            assert!(check_agent_routes(&empty, || true).is_err());
            let mut duplicate = ranked.clone();
            duplicate.push(ranked[index].clone());
            assert!(check_agent_routes(&duplicate, || true).is_err());
        }
        assert!(check_agent_routes(&[], || true).is_err());
        let mut applied = false;
        apply_complete_ranking(&ranked, false, || {
            applied = true;
            Ok(())
        })
        .unwrap();
        assert!(applied);
    }

    #[test]
    fn missing_primary_route_is_accepted_only_after_daily_configuration_is_confirmed() {
        let mut ranked = complete_ranking();
        ranked.retain(|row| row.host != PRIMARY_CLOUD_CODE);
        assert!(check_agent_routes(&ranked, || false)
            .unwrap_err()
            .contains(PRIMARY_CLOUD_CODE));
        let skip_primary = check_agent_routes(&ranked, || true).unwrap();
        assert!(skip_primary);
        let mut applied = false;
        apply_complete_ranking(&ranked, skip_primary, || {
            applied = true;
            Ok(())
        })
        .unwrap();
        assert!(applied);
    }

    #[test]
    fn missing_daily_route_never_changes_working_pins_even_when_daily_is_configured() {
        let dir = tempfile::tempdir().unwrap();
        let hosts = dir.path().join("hosts");
        let rank = dir.path().join("proxy_rank.conf");
        fs::write(&hosts, b"original hosts").unwrap();
        fs::write(&rank, b"original ranking").unwrap();
        let mut ranked = complete_ranking();
        let daily = super::super::provider::DAILY_CLOUD_CODE;
        ranked.retain(|row| row.host != daily);
        let error = apply_complete_ranking(&ranked, true, || {
            fs::write(&hosts, b"new hosts").unwrap();
            fs::write(&rank, b"new ranking").unwrap();
            Ok(())
        })
        .unwrap_err();
        assert!(error.contains(daily));
        assert_eq!(fs::read(hosts).unwrap(), b"original hosts");
        assert_eq!(fs::read(rank).unwrap(), b"original ranking");
    }
}
