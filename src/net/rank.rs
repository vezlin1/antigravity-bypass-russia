//! Rank substituted proxy IPs by TLS speed and keep a short fallback list.
//!
//! Certificate and HTTP checks run when the user enables the bypass.
//! No scheduled rescans or model-response measurements.

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::net::hosts::write_entries as write_hosts_entries;
use crate::net::provider::{GEOHIDE_EU_DOH, GEOHIDE_PROXY_V4, NRPT_AGENT, PRIMARY_CLOUD_CODE};
use crate::net::relay;
use crate::net::resolver_pool::{self, Provider, Transport};
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

fn geohide_proxy_seeds(pool: &[Provider]) -> &'static [&'static str] {
    if pool.iter().any(
        |provider| matches!(&provider.transport, Transport::Doh(doh) if doh.url == GEOHIDE_EU_DOH),
    ) {
        GEOHIDE_PROXY_V4
    } else {
        &[]
    }
}

pub(super) fn discover_agent(
    if_index: u32,
    policy: routes::RoutePolicy,
    prepare_routes: &mut dyn FnMut(&[Ipv4Addr]) -> Result<(), String>,
) -> Result<Vec<RankedHost>, String> {
    let previous = load();
    let geohide_seeds = geohide_proxy_seeds(&resolver_pool::load()?);
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
        for seed in geohide_seeds {
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
        #[cfg(windows)]
        if ips.is_empty() && policy == routes::RoutePolicy::System {
            ips = resolvers::rank_tls_v4(&system_addresses(&host), &host);
        }
        #[cfg(not(windows))]
        let _ = policy;
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

#[cfg(windows)]
fn system_addresses(host: &str) -> Vec<IpAddr> {
    use std::net::ToSocketAddrs;

    (host, 443)
        .to_socket_addrs()
        .into_iter()
        .flatten()
        .map(|address| address.ip())
        .filter(IpAddr::is_ipv4)
        .filter(|address| resolvers::looks_google(address))
        .take(MAX_FALLBACKS)
        .collect()
}

#[cfg(windows)]
pub(super) fn refresh_system_pins(still_current: impl FnOnce() -> bool) -> Result<bool, String> {
    let current = {
        let _configuration = super::configuration_lock()?;
        super::hosts::owned_entries()?
    };
    if current.is_empty() {
        return Ok(true);
    }

    let ranked = load();
    let updates = std::thread::scope(|scope| {
        let checks: Vec<_> = current
            .iter()
            .map(|(host, ip)| {
                let ranked = &ranked;
                scope.spawn(move || {
                    recover_pin(
                        *ip,
                        super::health::probe_ip((*ip, 443).into(), host).is_ok(),
                        || replacement_pin(host, *ip, ranked),
                    )
                })
            })
            .collect();
        checks
            .into_iter()
            .map(|check| check.join().unwrap_or(None))
            .collect::<Vec<_>>()
    });

    let all_reachable = updates.iter().all(Option::is_some);
    let next: Vec<_> = current
        .iter()
        .zip(updates)
        .map(|((host, ip), replacement)| (host.clone(), replacement.unwrap_or(*ip)))
        .collect();
    let _configuration = super::configuration_lock()?;
    if !still_current()
        || relay::load_route_policy()? != routes::RoutePolicy::System
        || super::hosts::owned_entries()? != current
    {
        return Ok(false);
    }
    if next != current {
        write_hosts_entries(&next)?;
        super::flush_dns_cache()?;
    }
    Ok(all_reachable)
}

#[cfg(windows)]
fn replacement_pin(host: &str, current: Ipv4Addr, ranked: &[RankedHost]) -> Option<Ipv4Addr> {
    let known = ranked
        .iter()
        .find(|entry| entry.host == host)
        .into_iter()
        .flat_map(|entry| entry.ips.iter().map(|&(ip, _)| IpAddr::V4(ip)));
    let fresh = resolvers::candidate_addrs(host, 0).unwrap_or_default();
    let mut seen = std::collections::HashSet::from([IpAddr::V4(current)]);
    let candidates: Vec<_> = known
        .chain(fresh)
        .filter(IpAddr::is_ipv4)
        .filter(|ip| seen.insert(*ip))
        .take(12)
        .collect();

    resolvers::rank_tls_v4(&candidates, host)
        .first()
        .map(|&(ip, _)| ip)
        .or_else(|| {
            let native: Vec<_> = system_addresses(host)
                .into_iter()
                .filter(|ip| seen.insert(*ip))
                .collect();
            resolvers::rank_tls_v4(&native, host)
                .first()
                .map(|&(ip, _)| ip)
        })
}

#[cfg(any(windows, test))]
fn recover_pin(
    current: Ipv4Addr,
    still_works: bool,
    verified_replacement: impl FnOnce() -> Option<Ipv4Addr>,
) -> Option<Ipv4Addr> {
    if still_works {
        Some(current)
    } else {
        verified_replacement()
    }
}

pub(super) fn apply_ranked(
    ranked: &[RankedHost],
    skip_primary: bool,
    policy: routes::RoutePolicy,
) -> Result<(), String> {
    apply_complete_ranking(ranked, skip_primary, || {
        if policy == routes::RoutePolicy::Physical {
            routes::sync_physical_hosts(&ranked_ips(ranked))?;
        }
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

    #[test]
    fn network_change_keeps_working_pins_and_only_accepts_verified_replacements() {
        let active = Ipv4Addr::new(192, 0, 2, 4);
        let alternate = Ipv4Addr::new(192, 0, 2, 5);
        assert_eq!(
            recover_pin(active, true, || panic!("working pin should be kept")),
            Some(active)
        );
        assert_eq!(
            recover_pin(active, false, || Some(alternate)),
            Some(alternate)
        );
        assert_eq!(
            recover_pin(active, false, || None).unwrap_or(active),
            active
        );
    }

    #[test]
    fn geohide_proxy_seeds_follow_its_doh_endpoint_independently_of_udp() {
        let mut config = super::super::config::Config::default();
        let pool = resolver_pool::from_config(&config).unwrap();
        assert!(pool
            .iter()
            .all(|provider| provider.udp_addresses().is_empty()));
        let seeds = geohide_proxy_seeds(&pool);
        assert!(seeds.contains(&"5.175.161.3"));
        assert!(seeds.contains(&"5.175.161.40"));
        config.disabled_providers.push("eu.geohide.ru".into());
        assert!(geohide_proxy_seeds(&resolver_pool::from_config(&config).unwrap()).is_empty());
    }

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
