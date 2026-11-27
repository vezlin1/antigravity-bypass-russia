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

/// The furthest stage reached by any candidate of a host that failed
/// verification. Declaration order is the order of the stages.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum FailureStage {
    NoAddresses,
    Tcp,
    Tls,
    Certificate,
    Http,
}

impl FailureStage {
    fn classify(error: &str) -> Self {
        if let Some(detail) = error.strip_prefix("TLS/certificate:") {
            let detail = detail.to_lowercase();
            let certificate = [
                "certif",
                "trust",
                "verify",
                "issuer",
                "self signed",
                "self-signed",
                "сертифик",
                "довер",
            ]
            .iter()
            .any(|word| detail.contains(word));
            if certificate {
                Self::Certificate
            } else {
                Self::Tls
            }
        } else if error.starts_with("TLS") {
            Self::Tls
        } else if error.starts_with("HTTP") {
            Self::Http
        } else {
            Self::Tcp
        }
    }

    fn furthest(errors: &[String]) -> Self {
        errors
            .iter()
            .map(|error| Self::classify(error))
            .max()
            .unwrap_or(Self::NoAddresses)
    }

    fn label(self) -> &'static str {
        match self {
            Self::NoAddresses => "DNS не вернул адресов",
            Self::Tcp => "нет TCP-подключения",
            Self::Tls => "обрыв TLS",
            Self::Certificate => "сертификат не прошёл проверку",
            Self::Http => "сервер отвечает ошибкой HTTP 5xx",
        }
    }

    fn advice(self) -> &'static str {
        match self {
            Self::NoAddresses => {
                "Проверьте подключение к интернету и повторите. Если не поможет, добавьте другой DNS-провайдер в network.json"
            }
            Self::Tcp => {
                "Проверьте, не блокируют ли подключение файрвол, антивирус или VPN с Kill Switch, и повторите через несколько минут"
            }
            Self::Tls => {
                "Похоже на блокировку по имени сайта у интернет-провайдера. Повторите позже, попробуйте другую сеть (например, мобильный интернет) или VPN с обфускацией трафика"
            }
            Self::Certificate => {
                "Если антивирус проверяет HTTPS-трафик, отключите эту проверку или добавьте исключение для *.googleapis.com"
            }
            Self::Http => "Релей временно перегружен. Повторите через несколько минут",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct HostFailure {
    pub host: String,
    pub attempted: usize,
    pub stage: FailureStage,
}

pub(super) struct Discovery {
    pub ranked: Vec<RankedHost>,
    pub failures: Vec<HostFailure>,
}

pub fn rank_path() -> PathBuf {
    relay::log_dir().join("proxy_rank.conf")
}

#[cfg(windows)]
pub(super) fn saved_addresses(host: &str) -> Vec<Ipv4Addr> {
    load()
        .into_iter()
        .find(|entry| entry.host == host)
        .map(|entry| entry.ips.into_iter().map(|(address, _)| address).collect())
        .unwrap_or_default()
}

pub(super) fn geohide_proxy_seeds(pool: &[Provider]) -> &'static [&'static str] {
    if pool.iter().any(
        |provider| matches!(&provider.transport, Transport::Doh(doh) if doh.url == GEOHIDE_EU_DOH),
    ) {
        GEOHIDE_PROXY_V4
    } else {
        &[]
    }
}

/// A direct Google IP is only a usable bypass candidate when its route
/// actually traverses a VPN tunnel (full or split-tunnel). Without a VPN,
/// direct Google IPs answer `HEAD /` quickly with HTTP 404 and would outrank
/// proxies while failing regional checks.
fn address_allowed_for_ranking(address: IpAddr, is_vpn_route: impl Fn(Ipv4Addr) -> bool) -> bool {
    match address {
        IpAddr::V4(ip) => !resolvers::looks_google(&address) || is_vpn_route(ip),
        IpAddr::V6(_) => false,
    }
}

fn address_routed_via_vpn(ip: Ipv4Addr) -> bool {
    #[cfg(windows)]
    {
        super::egress::windows_route_is_vpn(ip)
    }
    #[cfg(not(windows))]
    {
        let _ = ip;
        false
    }
}

pub(super) fn discover_agent(
    if_index: u32,
    policy: routes::RoutePolicy,
    prepare_routes: &mut dyn FnMut(&[Ipv4Addr]) -> Result<(), String>,
    progress: &mut dyn FnMut(super::SetupProgress<'_>),
) -> Result<Discovery, String> {
    use super::SetupProgress::{Detail, Working};
    let previous = load();
    let geohide_seeds = geohide_proxy_seeds(&resolver_pool::load()?);
    let mut host_candidates = Vec::new();
    let mut addresses = std::collections::BTreeSet::new();
    for (index, name) in NRPT_AGENT.iter().enumerate() {
        let host = name.trim_start_matches('.').to_string();
        progress(Working(&format!(
            "ищем адреса {}/{}: {}",
            index + 1,
            NRPT_AGENT.len(),
            super::server_label(&host)
        )));
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
        // Never allow non-VPN direct Google IPs (including stale ones from an
        // old rank file) to outrank real proxies.
        let candidates: Vec<_> = candidates
            .into_iter()
            .filter(|ip| address_allowed_for_ranking(*ip, address_routed_via_vpn))
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
    progress(Working("проверяем путь до найденных адресов"));
    prepare_routes(&addresses.into_iter().collect::<Vec<_>>())?;
    let mut ranked = Vec::new();
    let mut failures = Vec::new();
    let mut tried = std::collections::HashMap::new();
    for (index, (host, candidates)) in host_candidates.into_iter().enumerate() {
        progress(Working(&format!(
            "проверяем связь {}/{}: {}",
            index + 1,
            NRPT_AGENT.len(),
            super::server_label(&host)
        )));
        match verify_host(&host, &candidates, policy, progress) {
            Ok(row) => ranked.push(row),
            Err(failure) => failures.push(failure),
        }
        tried.insert(host, candidates);
    }

    // DoH answers and relays occasionally fail for a moment. Give each failed
    // host one more attempt with a fresh DNS answer before rejecting setup.
    if !failures.is_empty() {
        progress(Working(&format!(
            "повторим проверку через {} с",
            RETRY_DELAY.as_secs()
        )));
    }
    let (recovered, failures) = retry_failed(
        failures,
        || std::thread::sleep(RETRY_DELAY),
        |failure| {
            let host = &failure.host;
            progress(Working(&format!(
                "повторно ищем адреса: {}",
                super::server_label(host)
            )));
            let known = tried.remove(host).unwrap_or_default();
            let fresh: Vec<_> = resolvers::candidate_addrs(host, if_index)
                .unwrap_or_default()
                .into_iter()
                .filter(|ip| {
                    address_allowed_for_ranking(*ip, address_routed_via_vpn) && !known.contains(ip)
                })
                .collect();
            let new_routes: Vec<_> = fresh
                .iter()
                .filter_map(|ip| match ip {
                    IpAddr::V4(ip) => Some(*ip),
                    _ => None,
                })
                .collect();
            if !new_routes.is_empty() {
                if let Err(error) = prepare_routes(&new_routes) {
                    progress(Detail(&format!("– {host} · маршруты для повтора: {error}")));
                    return Err(failure);
                }
            }
            let candidates: Vec<_> = known.into_iter().chain(fresh).take(32).collect();
            progress(Working(&format!(
                "повторно проверяем связь: {}",
                super::server_label(host)
            )));
            verify_host(host, &candidates, policy, progress)
        },
    );
    ranked.extend(recovered);
    Ok(Discovery { ranked, failures })
}

const RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(3);

/// Pause once, then verify each failed host one more time. A host that fails
/// again keeps the result of its latest attempt.
fn retry_failed(
    failures: Vec<HostFailure>,
    pause: impl FnOnce(),
    mut attempt: impl FnMut(HostFailure) -> Result<RankedHost, HostFailure>,
) -> (Vec<RankedHost>, Vec<HostFailure>) {
    if failures.is_empty() {
        return (Vec::new(), failures);
    }
    pause();
    let mut recovered = Vec::new();
    let mut remaining = Vec::new();
    for failure in failures {
        match attempt(failure) {
            Ok(row) => recovered.push(row),
            Err(failure) => remaining.push(failure),
        }
    }
    (recovered, remaining)
}

/// Verify one host's candidates with its SNI and keep the fastest few.
fn verify_host(
    host: &str,
    candidates: &[IpAddr],
    policy: routes::RoutePolicy,
    progress: &mut dyn FnMut(super::SetupProgress<'_>),
) -> Result<RankedHost, HostFailure> {
    use super::SetupProgress::Detail;
    let attempted = candidates.len();
    #[allow(unused_mut)]
    let (mut ips, mut errors) = resolvers::rank_tls_v4_report(candidates, host);
    #[cfg(windows)]
    let attempted = if ips.is_empty() && policy == routes::RoutePolicy::System {
        use super::SetupProgress::Working;
        progress(Working(&format!(
            "спрашиваем адреса у Windows: {}",
            super::server_label(host)
        )));
        let native = system_addresses(host);
        progress(Working(&format!(
            "проверяем адреса Windows: {}",
            super::server_label(host)
        )));
        let (native_ips, native_errors) = resolvers::rank_tls_v4_report(&native, host);
        ips = native_ips;
        errors.extend(native_errors);
        attempted + native.len()
    } else {
        attempted
    };
    #[cfg(not(windows))]
    let _ = policy;
    let Some(&(_, fastest)) = ips.first() else {
        let stage = FailureStage::furthest(&errors);
        progress(Detail(&format!(
            "– {host} · проверено {attempted}, подходящих адресов нет ({})",
            stage.label()
        )));
        return Err(HostFailure {
            host: host.to_owned(),
            attempted,
            stage,
        });
    };
    progress(Detail(&format!(
        "✓ {host} · прошли {}/{} · лучший {} мс",
        ips.len(),
        attempted,
        fastest
    )));
    ips.truncate(MAX_FALLBACKS);
    Ok(RankedHost {
        host: host.to_owned(),
        ips,
    })
}

#[cfg(windows)]
fn system_addresses(host: &str) -> Vec<IpAddr> {
    use std::net::ToSocketAddrs;

    (host, 443)
        .to_socket_addrs()
        .into_iter()
        .flatten()
        .map(|address| address.ip())
        .filter(|address| match address {
            IpAddr::V4(ip) => {
                resolvers::looks_google(address) && super::egress::windows_route_is_vpn(*ip)
            }
            IpAddr::V6(_) => false,
        })
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
        .filter(|ip| address_allowed_for_ranking(*ip, address_routed_via_vpn))
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

#[cfg(not(windows))]
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

/// Persists routes and ranking without touching `hosts`, so callers can
/// evaluate whether NRPT + relay can safely absorb a `hosts` permission denial.
#[cfg(windows)]
pub(super) fn save_ranked_without_hosts(
    ranked: &[RankedHost],
    skip_primary: bool,
    policy: routes::RoutePolicy,
) -> Result<(), String> {
    apply_complete_ranking(ranked, skip_primary, || {
        if policy == routes::RoutePolicy::Physical {
            routes::sync_physical_hosts(&ranked_ips(ranked))?;
        }
        save(ranked)
    })
}

#[cfg(windows)]
pub(super) fn apply_ranked_hosts(ranked: &[RankedHost]) -> Result<(), String> {
    apply_hosts(ranked)
}

// An incomplete scan must never replace a previously working hosts block or
// ranking. In particular, a reachable native endpoint cannot stand in for the
// daily endpoint that is configured in the application.
//
// The regular Cloud Code endpoint may be missing when `primary_optional`: the
// caller switches every client that would use it to daily right after setup.
// Returns whether the regular endpoint is skipped.
pub(super) fn check_agent_routes(
    ranked: &[RankedHost],
    failures: &[HostFailure],
    primary_optional: bool,
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
    let only_primary_absent = missing == [PRIMARY_CLOUD_CODE]
        && !ranked
            .iter()
            .any(|row| super::route_health::host_name(&row.host) == PRIMARY_CLOUD_CODE);
    if only_primary_absent && primary_optional {
        return Ok(true);
    }
    let mut error = route_failure_message(&missing, failures);
    if only_primary_absent {
        error.push_str(
            ". Daily доступен, но найденные Antigravity App или CLI на этой системе не переключаются на него автоматически",
        );
    }
    error.push_str(". Прежние hosts и рейтинг сохранены");
    Err(error)
}

fn route_failure_message(missing: &[&str], failures: &[HostFailure]) -> String {
    let mut reasons = Vec::new();
    let mut advice: Vec<&str> = Vec::new();
    for host in missing {
        match failures.iter().find(|failure| failure.host == *host) {
            Some(failure) => {
                reasons.push(format!(
                    "{host} — {} (проверено адресов: {})",
                    failure.stage.label(),
                    failure.attempted
                ));
                if !advice.contains(&failure.stage.advice()) {
                    advice.push(failure.stage.advice());
                }
            }
            None => reasons.push(format!("{host} — нет однозначного проверенного маршрута")),
        }
    }
    let mut message = format!("Не удалось подобрать маршрут: {}", reasons.join("; "));
    for line in advice {
        message.push_str(". ");
        message.push_str(line);
    }
    message
}

fn apply_complete_ranking(
    ranked: &[RankedHost],
    skip_primary: bool,
    apply: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    check_agent_routes(ranked, &[], skip_primary)?;
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
    parse_ranked(&text, address_routed_via_vpn)
}

fn parse_ranked(text: &str, is_vpn_route: impl Fn(Ipv4Addr) -> bool) -> Vec<RankedHost> {
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
        if !address_allowed_for_ranking(IpAddr::V4(ip), &is_vpn_route) {
            continue;
        }
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
    fn direct_google_ips_are_rejected_without_vpn_route_and_allowed_through_split_tunnel() {
        let google: IpAddr = "172.217.114.4".parse().unwrap();
        let proxy: IpAddr = "45.131.64.204".parse().unwrap();
        let ipv6: IpAddr = "2001:4860:4860::8888".parse().unwrap();

        assert!(!address_allowed_for_ranking(google, |_| false));
        assert!(address_allowed_for_ranking(google, |ip| ip == Ipv4Addr::new(172, 217, 114, 4)));
        assert!(!address_allowed_for_ranking(google, |ip| ip == Ipv4Addr::new(1, 1, 1, 1)));
        assert!(address_allowed_for_ranking(proxy, |_| false));
        assert!(!address_allowed_for_ranking(ipv6, |_| true));

        let stale = "# antigravity-proxy-rank 1\ncloudcode-pa.googleapis.com 172.217.114.4 183\ncloudcode-pa.googleapis.com 45.131.64.204 220\n";
        let without_vpn = parse_ranked(stale, |_| false);
        assert_eq!(without_vpn.len(), 1);
        assert_eq!(
            without_vpn[0].ips,
            vec![(Ipv4Addr::new(45, 131, 64, 204), 220)]
        );
        let with_split_vpn = parse_ranked(stale, |ip| ip == Ipv4Addr::new(172, 217, 114, 4));
        assert_eq!(with_split_vpn[0].ips.len(), 2);
    }

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
            assert!(check_agent_routes(&empty, &[], true).is_err());
            let mut duplicate = ranked.clone();
            duplicate.push(ranked[index].clone());
            assert!(check_agent_routes(&duplicate, &[], true).is_err());
        }
        assert!(check_agent_routes(&[], &[], true).is_err());
        let mut applied = false;
        apply_complete_ranking(&ranked, false, || {
            applied = true;
            Ok(())
        })
        .unwrap();
        assert!(applied);
    }

    #[test]
    fn missing_primary_route_is_skipped_only_when_clients_can_switch_to_daily() {
        let mut ranked = complete_ranking();
        ranked.retain(|row| row.host != PRIMARY_CLOUD_CODE);
        let error = check_agent_routes(&ranked, &[], false).unwrap_err();
        assert!(error.contains(PRIMARY_CLOUD_CODE), "{error}");
        assert!(error.contains("Daily доступен"), "{error}");
        let skip_primary = check_agent_routes(&ranked, &[], true).unwrap();
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
    fn failed_hosts_get_exactly_one_retry_after_a_single_pause() {
        let failure = |host: &str, stage| HostFailure {
            host: host.into(),
            attempted: 4,
            stage,
        };

        let mut paused = false;
        let (recovered, remaining) =
            retry_failed(Vec::new(), || paused = true, |_| panic!("nothing to retry"));
        assert!(!paused && recovered.is_empty() && remaining.is_empty());

        let mut pauses = 0;
        let mut attempts = Vec::new();
        let (recovered, remaining) = retry_failed(
            vec![
                failure("a.example", FailureStage::Tcp),
                failure("b.example", FailureStage::Tls),
            ],
            || pauses += 1,
            |failure| {
                attempts.push(failure.host.clone());
                if failure.host == "a.example" {
                    Ok(RankedHost {
                        host: failure.host,
                        ips: vec![(Ipv4Addr::new(192, 0, 2, 1), 30)],
                    })
                } else {
                    Err(HostFailure {
                        stage: FailureStage::Http,
                        ..failure
                    })
                }
            },
        );
        assert_eq!(pauses, 1);
        assert_eq!(attempts, ["a.example", "b.example"]);
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].host, "a.example");
        assert_eq!(remaining, [failure("b.example", FailureStage::Http)]);
    }

    #[test]
    fn probe_errors_are_classified_by_the_furthest_stage_reached() {
        use FailureStage::*;
        for (error, stage) in [
            ("TCP: connection timed out", Tcp),
            ("TCP/TLS/HTTP: общий срок проверки истёк", Tcp),
            ("TLS: общий срок проверки истёк", Tls),
            (
                "TLS/certificate: connection reset by peer (os error 10054)",
                Tls,
            ),
            ("TLS/certificate: certificate verify failed", Certificate),
            (
                "TLS/certificate: Цепочка сертификатов выпущена центром, не имеющим доверия",
                Certificate,
            ),
            ("HTTP 502", Http),
            ("HTTP header: EOF", Http),
        ] {
            assert_eq!(FailureStage::classify(error), stage, "{error}");
        }
        assert_eq!(FailureStage::furthest(&[]), NoAddresses);
        let mixed = [
            "TCP: timed out".to_string(),
            "TLS: общий срок проверки истёк".into(),
        ];
        assert_eq!(FailureStage::furthest(&mixed), Tls);
    }

    #[test]
    fn route_errors_explain_each_failed_host_and_give_advice_once() {
        let mut ranked = complete_ranking();
        let daily = super::super::provider::DAILY_CLOUD_CODE;
        ranked.retain(|row| row.host != PRIMARY_CLOUD_CODE && row.host != daily);
        let failures = [
            HostFailure {
                host: PRIMARY_CLOUD_CODE.into(),
                attempted: 7,
                stage: FailureStage::Tls,
            },
            HostFailure {
                host: daily.into(),
                attempted: 5,
                stage: FailureStage::Tls,
            },
        ];
        let error = check_agent_routes(&ranked, &failures, true).unwrap_err();
        assert!(error.contains(&format!(
            "{PRIMARY_CLOUD_CODE} — обрыв TLS (проверено адресов: 7)"
        )));
        assert!(error.contains(&format!("{daily} — обрыв TLS (проверено адресов: 5)")));
        assert_eq!(
            error.matches(FailureStage::Tls.advice()).count(),
            1,
            "{error}"
        );
        assert!(!error.contains("Daily доступен"), "{error}");
        assert!(
            error.ends_with("Прежние hosts и рейтинг сохранены"),
            "{error}"
        );
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
