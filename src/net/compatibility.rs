//! Verify that exact hosts pins really bypass a preserved NRPT namespace.
//!
//! These checks use the system resolver after setup flushes its cache. Explicit
//! provider DNS and a successful local relay do not establish the application's
//! effective resolution path when another network tool owns the namespace.

use super::rank::RankedHost;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

const DNS_BUDGET: Duration = Duration::from_secs(3);
// Include thread startup and trust-store overhead in the outer deadline.
const HTTP_BUDGET: Duration =
    super::health::PROBE_BUDGET.saturating_add(Duration::from_millis(500));

/// Check fallback coverage before changing hosts or retiring obsolete own rules.
pub fn require_agent_pins(required: &[String], ranked: &[RankedHost]) -> Result<(), String> {
    selected_pins(required, ranked).map(|_| ())
}

/// Verify all required hosts in parallel, with one shared budget per phase.
/// DNS worker threads may outlive a timed-out platform lookup; the caller never
/// joins them, and at most the three allowlisted agent hosts can start a lookup.
pub fn verify_agent_pins(required: &[String], ranked: &[RankedHost]) -> Result<(), String> {
    let pins = selected_pins(required, ranked)?;
    verify_with(
        &pins,
        |host| {
            (host, 443)
                .to_socket_addrs()
                .map(|addrs| addrs.collect())
                .map_err(|e| format!("системное разрешение имени: {e}"))
        },
        |addr, host| super::health::probe_ip(addr, host).map(|_| ()),
        DNS_BUDGET,
        HTTP_BUDGET,
    )
}

fn selected_pins(
    required: &[String],
    ranked: &[RankedHost],
) -> Result<Vec<(String, Ipv4Addr)>, String> {
    let mut pins = Vec::new();
    let mut errors = Vec::new();
    let mut seen = BTreeSet::new();
    for name in required {
        let host = super::route_health::host_name(name);
        if !seen.insert(host.clone()) {
            continue;
        }
        if !super::provider::NRPT_AGENT.contains(&host.as_str()) {
            errors.push(format!("{host}: имя не входит в домены Antigravity"));
            continue;
        }
        let leaders: BTreeSet<_> = ranked
            .iter()
            .filter(|row| super::route_health::host_name(&row.host) == host)
            .filter_map(|row| row.ips.first().map(|(ip, _)| *ip))
            .collect();
        match leaders.len() {
            1 => pins.push((host, *leaders.first().unwrap())),
            0 => errors.push(format!(
                "{host}: нет проверенного IPv4 для hosts; правило другого приложения сохранено"
            )),
            _ => errors.push(format!(
                "{host}: неоднозначный адрес в проверенном рейтинге"
            )),
        }
    }
    if errors.is_empty() {
        Ok(pins)
    } else {
        Err(format!(
            "Совместимость через hosts не подтверждена: {}",
            errors.join("; ")
        ))
    }
}

fn verify_resolved(host: &str, selected: Ipv4Addr, addresses: &[SocketAddr]) -> Result<(), String> {
    let actual: BTreeSet<_> = addresses.iter().map(SocketAddr::ip).collect();
    if actual.len() == 1 && actual.contains(&IpAddr::V4(selected)) {
        return Ok(());
    }
    let returned = if actual.is_empty() {
        "нет адресов".to_string()
    } else {
        actual
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    Err(format!(
        "{host}: системный DNS вернул {returned}; ожидался только IPv4 {selected}. Проверьте записи hosts и DNS другого обхода"
    ))
}

fn verify_with(
    pins: &[(String, Ipv4Addr)],
    resolve: impl Fn(&str) -> Result<Vec<SocketAddr>, String> + Send + Sync + 'static,
    probe: impl Fn(SocketAddr, &str) -> Result<(), String> + Send + Sync + 'static,
    dns_budget: Duration,
    http_budget: Duration,
) -> Result<(), String> {
    if pins.is_empty() {
        return Ok(());
    }
    // Verify the complete returned address set before opening a socket: a
    // working IPv4 beside a foreign IPv6/second hosts entry does not prove that
    // Electron will select the working path.
    collect_results(run_checks(
        pins,
        dns_budget,
        "системный DNS: срок проверки истёк",
        move |host, ip| verify_resolved(host, ip, &resolve(host)?),
    ))?;
    collect_results(run_checks(
        pins,
        http_budget,
        "TLS/HTTP: срок проверки истёк",
        move |host, ip| probe((ip, 443).into(), host),
    ))
}

fn run_checks(
    pins: &[(String, Ipv4Addr)],
    budget: Duration,
    timeout: &'static str,
    check: impl Fn(&str, Ipv4Addr) -> Result<(), String> + Send + Sync + 'static,
) -> Vec<(String, Result<(), String>)> {
    let deadline = Instant::now() + budget;
    let check = Arc::new(check);
    let (tx, rx) = mpsc::channel();
    let mut results = BTreeMap::new();
    for (host, ip) in pins {
        let host = host.clone();
        let failed_host = host.clone();
        let ip = *ip;
        let tx = tx.clone();
        let check = Arc::clone(&check);
        if let Err(error) = std::thread::Builder::new()
            .name("antigravity-hosts-check".into())
            .spawn(move || {
                let result = check(&host, ip);
                let _ = tx.send((host, result));
            })
        {
            results.insert(
                failed_host,
                Err(format!("не удалось запустить проверку: {error}")),
            );
        }
    }
    drop(tx);
    let mut unfinished = timeout;
    while results.len() < pins.len() {
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok((host, result)) => {
                results.insert(host, result);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => break,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                unfinished = "проверка прервана";
                break;
            }
        }
    }
    pins.iter()
        .map(|(host, _)| {
            (
                host.clone(),
                results
                    .remove(host)
                    .unwrap_or_else(|| Err(unfinished.to_string())),
            )
        })
        .collect()
}

fn collect_results(results: Vec<(String, Result<(), String>)>) -> Result<(), String> {
    let errors: Vec<_> = results
        .into_iter()
        .filter_map(|(host, result)| {
            result.err().map(|e| {
                if e.starts_with(&format!("{host}:")) {
                    e
                } else {
                    format!("{host}: {e}")
                }
            })
        })
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "Совместимость через hosts не подтверждена: {}. Чужие настройки сохранены",
            errors.join("; ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(host: &str, ips: &[&str]) -> RankedHost {
        RankedHost {
            host: host.into(),
            ips: ips.iter().map(|ip| (ip.parse().unwrap(), 1)).collect(),
        }
    }

    #[test]
    fn fallback_requires_each_requested_host_and_uses_only_its_leader() {
        let one = super::super::provider::NRPT_AGENT[0];
        let two = super::super::provider::NRPT_AGENT[1];
        let rank = [row(one, &["192.0.2.1", "192.0.2.2"]), row(two, &[])];
        assert_eq!(
            selected_pins(&[one.into(), one.to_uppercase()], &rank).unwrap(),
            vec![(one.into(), "192.0.2.1".parse().unwrap())]
        );
        let error = require_agent_pins(&[one.into(), two.into()], &rank).unwrap_err();
        assert!(error.contains(two), "{error}");
        assert!(error.contains("нет проверенного IPv4"), "{error}");
        assert!(require_agent_pins(&["unrelated.test".into()], &rank).is_err());
        assert!(require_agent_pins(&[], &[]).is_ok());
        assert!(require_agent_pins(
            &[one.into()],
            &[row(one, &["192.0.2.1"]), row(one, &["192.0.2.2"])]
        )
        .is_err());
    }

    #[test]
    fn system_resolution_must_contain_only_the_selected_ipv4() {
        let selected = "192.0.2.1".parse().unwrap();
        assert!(verify_resolved(
            "agent.test",
            selected,
            &["192.0.2.1:443".parse().unwrap(); 2]
        )
        .is_ok());
        for addresses in [
            vec![],
            vec!["192.0.2.2:443".parse().unwrap()],
            vec![
                "192.0.2.1:443".parse().unwrap(),
                "192.0.2.2:443".parse().unwrap(),
            ],
            vec![
                "192.0.2.1:443".parse().unwrap(),
                "[2001:db8::1]:443".parse().unwrap(),
            ],
            vec!["[::ffff:192.0.2.1]:443".parse().unwrap()],
        ] {
            let error = verify_resolved("agent.test", selected, &addresses).unwrap_err();
            assert!(error.contains("agent.test"), "{error}");
            assert!(error.contains("192.0.2.1"), "{error}");
        }
    }

    #[test]
    fn empty_fallback_does_not_query_dns_or_connect() {
        verify_with(
            &[],
            |_| panic!("unexpected DNS lookup"),
            |_, _| panic!("unexpected connection"),
            Duration::ZERO,
            Duration::ZERO,
        )
        .unwrap();
    }

    #[test]
    fn verified_resolution_is_followed_by_the_same_address_tls_probe() {
        let host = super::super::provider::NRPT_AGENT[0];
        let pins = selected_pins(&[host.into()], &[row(host, &["192.0.2.1"])]).unwrap();
        let probed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = Arc::clone(&probed);
        verify_with(
            &pins,
            move |name| {
                assert_eq!(name, host);
                Ok(vec!["192.0.2.1:443".parse().unwrap()])
            },
            move |addr, name| {
                assert_eq!(addr, "192.0.2.1:443".parse().unwrap());
                assert_eq!(name, host);
                observed.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            },
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(probed.load(std::sync::atomic::Ordering::SeqCst));
        let error = verify_with(
            &pins,
            |_| Ok(vec!["192.0.2.1:443".parse().unwrap()]),
            |_, _| Err("TLS/certificate: test refusal".into()),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(error.contains("TLS/certificate"), "{error}");
        assert!(error.contains(host), "{error}");
    }

    #[test]
    fn wrong_dns_path_skips_tls_and_slow_system_lookups_cannot_hold_the_caller() {
        let host = super::super::provider::NRPT_AGENT[0];
        let pins = selected_pins(&[host.into()], &[row(host, &["192.0.2.1"])]).unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        assert!(verify_with(
            &pins,
            |_| Ok(vec!["192.0.2.2:443".parse().unwrap()]),
            move |_, _| {
                observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            },
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .is_err());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        let (release, wait) = mpsc::channel::<()>();
        let wait = std::sync::Mutex::new(wait);
        let start = Instant::now();
        let error = verify_with(
            &pins,
            move |_| {
                let _ = wait.lock().unwrap().recv();
                Ok(vec!["192.0.2.1:443".parse().unwrap()])
            },
            |_, _| panic!("timed out DNS must not start a probe"),
            Duration::from_millis(40),
            Duration::from_secs(1),
        )
        .unwrap_err();
        release.send(()).unwrap();
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(error.contains("срок проверки истёк"), "{error}");
    }

    #[test]
    fn multiple_slow_probes_share_one_caller_budget() {
        let pins: Vec<_> = super::super::provider::NRPT_AGENT
            .iter()
            .map(|host| ((*host).into(), "192.0.2.1".parse().unwrap()))
            .collect();
        let (release, wait) = mpsc::channel::<()>();
        let wait = std::sync::Mutex::new(wait);
        let start = Instant::now();
        let error = verify_with(
            &pins,
            |_| Ok(vec!["192.0.2.1:443".parse().unwrap()]),
            move |_, _| {
                let _ = wait.lock().unwrap().recv();
                Ok(())
            },
            Duration::from_secs(1),
            Duration::from_millis(40),
        )
        .unwrap_err();
        for _ in &pins {
            release.send(()).unwrap();
        }
        assert!(start.elapsed() < Duration::from_secs(1));
        for (host, _) in pins {
            assert!(error.contains(&host), "{error}");
        }
        assert!(error.contains("TLS/HTTP: срок проверки истёк"), "{error}");
    }
}
