//! Rank substituted proxy IPs by TLS speed and keep a short fallback list.
//!
//! Certificate and HTTP checks run when the user enables the bypass.
//! No scheduled rescans or model-response measurements.

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::net::hosts::write_entries as write_hosts_entries;
use crate::net::provider::NRPT_AGENT;
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

pub fn discover_agent(if_index: u32) -> Result<Vec<RankedHost>, String> {
    let previous = load();
    let geohide_enabled = super::resolver_pool::load()?
        .iter()
        .any(|p| p.name == "geohide.ru");
    let mut ranked = Vec::new();
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
        let addresses: Vec<_> = candidates
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(ip) => Some(*ip),
                _ => None,
            })
            .collect();
        routes::sync_physical_hosts(&addresses)?;
        let mut ips = resolvers::rank_tls_v4(&candidates, &host);
        if ips.is_empty() {
            // Fallback: if no proxy candidate yielded a verified route, probe standard resolved addresses
            use std::net::ToSocketAddrs;
            if let Ok(addrs) = (host.as_str(), 443).to_socket_addrs() {
                let direct_candidates: Vec<IpAddr> = addrs
                    .map(|s| s.ip())
                    .filter(|a| a.is_ipv4())
                    .collect();
                if !direct_candidates.is_empty() {
                    let direct_v4: Vec<_> = direct_candidates
                        .iter()
                        .filter_map(|ip| match ip {
                            IpAddr::V4(ip) => Some(*ip),
                            _ => None,
                        })
                        .collect();
                    let _ = routes::sync_physical_hosts(&direct_v4);
                    ips = resolvers::rank_tls_v4(&direct_candidates, &host);
                }
            }
        }
        if ips.is_empty() {
            continue;
        }
        if ips.len() > MAX_FALLBACKS {
            ips.truncate(MAX_FALLBACKS);
        }
        ranked.push(RankedHost { host, ips });
    }
    require_complete_agent_routes(&ranked)?;
    Ok(ranked)
}

pub fn apply_ranked(ranked: &[RankedHost]) -> Result<(), String> {
    apply_complete_ranking(ranked, || {
        routes::sync_physical_hosts(&ranked_ips(ranked))?;
        save(ranked)?;
        apply_hosts(ranked)
    })
}

// An incomplete scan must never replace a previously working hosts block or
// ranking. In particular, a reachable native endpoint cannot stand in for the
// daily endpoint that is configured in the application.
fn require_complete_agent_routes(ranked: &[RankedHost]) -> Result<(), String> {
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
        Ok(())
    } else {
        Err(format!(
            "Нет однозначного проверенного маршрута для {}; прежние hosts и рейтинг сохранены",
            missing.join(", ")
        ))
    }
}

fn apply_complete_ranking(
    ranked: &[RankedHost],
    apply: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    require_complete_agent_routes(ranked)?;
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
            let error = apply_complete_ranking(&ranked, || {
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
            assert!(require_complete_agent_routes(&empty).is_err());
            let mut duplicate = ranked.clone();
            duplicate.push(ranked[index].clone());
            assert!(require_complete_agent_routes(&duplicate).is_err());
        }
        assert!(require_complete_agent_routes(&[]).is_err());
        let mut applied = false;
        apply_complete_ranking(&ranked, || {
            applied = true;
            Ok(())
        })
        .unwrap();
        assert!(applied);
    }
}
