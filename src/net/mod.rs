pub mod client;
pub mod config;
pub mod dns_https;
pub mod doh;
pub mod egress;
pub mod health;
pub mod hosts;
pub mod nrpt;
pub mod provider;
pub mod rank;
pub mod relay;
pub mod resolver_pool;
pub mod resolvers;
pub mod route_health;
pub mod routes;
pub mod socket;
#[cfg(any(target_os = "macos", test))]
pub mod split_dns;

pub use relay::{detach_console, log_fatal, run as run_dns_relay};

use provider::{nrpt_domains, NRPT_AGENT, NRPT_STUDIO, NRPT_TAG, SUBSTITUTION_CANARIES};
use relay::{LISTEN_IP, LISTEN_PORT};
use routes::{add_static_routes, remove_static_routes};
use std::thread;
use std::time::Duration;

fn assemble_nameservers(via_relay: bool, substituters: &[&str]) -> String {
    let mut servers: Vec<String> = Vec::new();
    if via_relay {
        servers.push(LISTEN_IP.to_string());
    }
    if substituters.is_empty() {
        for s in resolvers::fallback_v4() {
            servers.push(s.to_string());
        }
    } else {
        for s in substituters {
            servers.push((*s).to_string());
        }
    }
    servers.join(";")
}

fn assemble_dns_rules(
    agent_rules: &[(String, Vec<&str>)],
    studio_servers: &[&str],
    via_relay: bool,
    use_split_dns: bool,
) -> Vec<(String, String)> {
    let namespace = |name: &str| {
        if use_split_dns {
            name.trim_start_matches('.').to_ascii_lowercase()
        } else {
            name.to_string()
        }
    };
    // Agent probes are specific to each host. Keep their results when Studio
    // also covers that domain; macOS maps exact and suffix names to one file.
    let mut rules: Vec<_> = agent_rules
        .iter()
        .map(|(name, servers)| (namespace(name), assemble_nameservers(via_relay, servers)))
        .collect();
    for name in NRPT_STUDIO {
        let name = namespace(name);
        if !rules.iter().any(|(existing, _)| *existing == name) {
            rules.push((name, assemble_nameservers(via_relay, studio_servers)));
        }
    }
    rules
}

#[cfg(test)]
mod tests {
    #[test]
    fn network_writers_are_exclusive_and_unlock_without_deleting_the_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("network-update.lock");
        let foreground = super::lock_configuration_file(&path).unwrap();
        // A concurrent process launch on Unix may temporarily retain a duplicate
        // descriptor until exec. Releasing the guard must not wait for that copy.
        let inherited = foreground.0.try_clone().unwrap();
        assert!(super::lock_configuration_file(&path).is_err());
        drop(foreground);
        let background = super::lock_configuration_file(&path).unwrap();
        assert!(super::lock_configuration_file(&path).is_err());
        drop(background);
        drop(inherited);
        assert!(path.exists());
        assert!(super::lock_configuration_file(&path).is_ok());
    }

    #[test]
    fn classic_mode_keeps_external_dns_fallbacks_alongside_the_relay() {
        assert_eq!(
            super::assemble_nameservers(true, &["1.2.3.4"]),
            format!("{};1.2.3.4", super::LISTEN_IP)
        );
        assert_eq!(super::assemble_nameservers(false, &["1.2.3.4"]), "1.2.3.4");
        assert_eq!(
            super::assemble_nameservers(false, &[]).split(';').count(),
            3
        );
    }

    #[test]
    fn macos_rules_keep_agent_dns_when_studio_results_differ() {
        use super::*;
        let cases: &[(&[&str], &[&str])] = &[
            (&["45.155.204.190"], &["111.88.96.50", "45.155.204.190"]),
            (
                &["45.155.204.190", "111.88.96.50"],
                &["111.88.96.50", "45.155.204.190"],
            ),
            (&[], &[]),
            (&[], &["111.88.96.50"]),
            (&["45.155.204.190"], &[]),
        ];
        let expected_domains: std::collections::BTreeSet<_> = nrpt_domains()
            .into_iter()
            .map(|name| name.trim_start_matches('.').to_string())
            .collect();
        for (agent_servers, studio_servers) in cases {
            let agent_rules: Vec<_> = NRPT_AGENT
                .iter()
                .map(|name| (name.to_string(), agent_servers.to_vec()))
                .collect();
            let rules = assemble_dns_rules(&agent_rules, studio_servers, false, true);
            assert_eq!(rules.len(), expected_domains.len());
            assert_eq!(
                rules
                    .iter()
                    .map(|(name, _)| name.clone())
                    .collect::<std::collections::BTreeSet<_>>(),
                expected_domains
            );
            for host in NRPT_AGENT {
                assert_eq!(
                    rules.iter().find(|(name, _)| name == host).unwrap().1,
                    assemble_nameservers(false, agent_servers)
                );
            }
            assert_eq!(
                rules
                    .iter()
                    .find(|(name, _)| name == "aistudio.google.com")
                    .unwrap()
                    .1,
                assemble_nameservers(false, studio_servers)
            );
            let dir = tempfile::tempdir().unwrap();
            let resolver_dir = dir.path().join("resolver");
            let prepared = split_dns::prepare(&resolver_dir, &rules).unwrap();
            assert!(!resolver_dir.exists());
            split_dns::apply(&resolver_dir, &prepared).unwrap();
            let content =
                std::fs::read_to_string(resolver_dir.join("generativelanguage.googleapis.com"))
                    .unwrap();
            let servers: Vec<_> = content
                .lines()
                .filter_map(|line| line.strip_prefix("nameserver "))
                .collect();
            assert_eq!(
                servers.join(";"),
                assemble_nameservers(false, agent_servers)
            );
            assert!(split_dns::remove(&resolver_dir, &nrpt_domains()).is_empty());
            for domain in &expected_domains {
                assert!(!resolver_dir.join(domain).exists());
            }
        }
    }

    #[test]
    fn windows_rules_keep_exact_and_suffix_namespaces_with_their_dns() {
        use super::*;
        let agent_servers = vec!["45.155.204.190"];
        let studio_servers = ["111.88.96.50", "45.155.204.190"];
        let agent_rules: Vec<_> = NRPT_AGENT
            .iter()
            .map(|name| (name.to_string(), agent_servers.clone()))
            .collect();
        for via_relay in [false, true] {
            let rules = assemble_dns_rules(&agent_rules, &studio_servers, via_relay, false);
            let expected_names: std::collections::BTreeSet<_> =
                nrpt_domains().into_iter().collect();
            assert_eq!(rules.len(), expected_names.len());
            assert_eq!(
                rules
                    .iter()
                    .map(|(name, _)| name.as_str())
                    .collect::<std::collections::BTreeSet<_>>(),
                expected_names
            );
            for host in NRPT_AGENT {
                assert_eq!(
                    rules.iter().find(|(name, _)| name == host).unwrap().1,
                    assemble_nameservers(via_relay, &agent_servers)
                );
            }
            assert_eq!(
                rules
                    .iter()
                    .find(|(name, _)| name == ".generativelanguage.googleapis.com")
                    .unwrap()
                    .1,
                assemble_nameservers(via_relay, &studio_servers)
            );
        }
    }
}

pub fn preflight() -> Result<(), String> {
    // Version 2.0 uses physical routes and external DNS fallbacks with VPNs.
    // Do not require a responsive loopback DNS port before configuring them.
    #[cfg(target_os = "macos")]
    split_dns::preflight(std::path::Path::new("/etc/resolver"), &nrpt_domains())?;
    Ok(())
}

pub(super) fn flush_dns_cache() -> Result<(), String> {
    #[cfg(windows)]
    let commands: &[(&str, &[&str])] = &[("ipconfig", &["/flushdns"])];
    #[cfg(target_os = "macos")]
    let commands: &[(&str, &[&str])] = &[
        ("dscacheutil", &["-flushcache"]),
        ("killall", &["-HUP", "mDNSResponder"]),
    ];
    #[cfg(not(any(windows, target_os = "macos")))]
    let commands: &[(&str, &[&str])] = &[];
    let mut errors = Vec::new();
    for (program, args) in commands {
        match crate::system::command::output(program, *args) {
            Ok(out) if out.status.success() => {}
            Ok(out) => errors.push(format!("{program}: {}", out.status)),
            Err(error) => errors.push(format!("{program}: {error}")),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "Не удалось обновить кэш DNS: {}",
            errors.join("; ")
        ))
    }
}

pub struct NetworkSetup {
    pub message: String,
    pub local_relay_running: bool,
}

/// Serialize foreground setup and background OS/configuration writers. The DNS
/// request workers deliberately do not take this lock, so existing routes work
/// while replacement candidates are being discovered.
pub(super) struct ConfigurationLock(std::fs::File);

impl Drop for ConfigurationLock {
    fn drop(&mut self) {
        // Close alone can leave flock held by a descriptor inherited during fork.
        // Only this guard owns the critical section; explicitly end it before close.
        let _ = self.0.unlock();
    }
}

pub(super) fn configuration_lock() -> Result<ConfigurationLock, String> {
    let dir = relay::log_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    lock_configuration_file(&dir.join("network-update.lock"))
}

fn lock_configuration_file(path: &std::path::Path) -> Result<ConfigurationLock, String> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| format!("Блокировка настройки сети: {e}"))?;
    file.try_lock().map_err(|e| match e {
        std::fs::TryLockError::WouldBlock =>
            "Настройки сети уже обновляются другим процессом. Повторите после завершения обновления.".to_string(),
        other => format!("Блокировка настройки сети: {other}"),
    })?;
    Ok(ConfigurationLock(file))
}

pub fn apply_dns_rules() -> Result<NetworkSetup, String> {
    fn step(msg: &str) {
        println!("  \x1b[90m… {}\x1b[0m", msg);
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }

    preflight()?;
    let _configuration = configuration_lock()?;
    config::prepare_service()?;
    step("Подготавливаем подключение");
    // Reconfigure owned rules in place. Removing the working service/hosts/DNS
    // before discovery left users disconnected whenever all probes failed.

    let names = nrpt_domains();
    step("Проверяем настройки сети");
    let conflicts = nrpt::conflicting_rules(&names)?;
    if !conflicts.is_empty() {
        return Err(format!(
            "Конфликт NRPT: {}. Чужие правила сохранены.",
            conflicts.join(", ")
        ));
    }

    step("Определяем подключение к интернету");
    let egress = crate::net::egress::detect();
    let if_index = egress.as_ref().map(|e| e.if_index).unwrap_or(0);
    #[cfg(windows)]
    if if_index == 0 || egress.as_ref().is_none_or(|e| e.gateway.is_none()) {
        return Err("Не найден физический выход в интернет; проверка через VPN отменена".into());
    }
    if if_index > 0 {
        crate::net::relay::save_if_index(if_index);
    }

    crate::net::relay::clear_custom_mode();
    let ips: Vec<String> = resolvers::all_provider_v4()
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    crate::net::relay::save_upstream_config(&ips);

    // Routes first. If VPN is the default route, substitution probes otherwise
    // leak into the tunnel and SmartDNS returns genuine Google.
    #[cfg(target_os = "windows")]
    {
        step("Подготавливаем DNS");
        add_static_routes()?;
        thread::sleep(Duration::from_millis(400));
    }

    let mut sub_notes = Vec::new();
    let mut agent_rules: Vec<(String, Vec<String>)> = Vec::new();
    let mut studio_subs: Vec<String> = Vec::new();
    step("Проверяем доступные серверы");
    {
        for name in NRPT_AGENT {
            let host = name.trim_start_matches('.');
            let subs = resolvers::substituting_addrs(host, if_index);
            if subs.is_empty() {
                sub_notes.push(format!("{host}: нет"));
                agent_rules.push(((*name).to_string(), resolvers::fallback_v4()));
            } else {
                sub_notes.push(format!("{host}: {}", subs.join(", ")));
                agent_rules.push(((*name).to_string(), subs));
            }
        }
        for name in SUBSTITUTION_CANARIES {
            let host = name.trim_start_matches('.');
            for s in resolvers::substituting_addrs(host, if_index) {
                if !studio_subs.contains(&s) {
                    studio_subs.push(s);
                }
            }
        }
        if studio_subs.is_empty() {
            sub_notes
                .push("Studio/Gemini: подмена не подтверждена, оставлены все резервные DNS".into());
        } else {
            sub_notes.push(format!("Studio/Gemini: {}", studio_subs.join(", ")));
        }
    }
    let agent_rules: Vec<_> = agent_rules
        .iter()
        .map(|(name, servers)| {
            (
                name.clone(),
                servers.iter().map(String::as_str).collect::<Vec<_>>(),
            )
        })
        .collect();
    let studio_subs: Vec<_> = studio_subs.iter().map(String::as_str).collect();
    // Reject invalid or conflicting resolver plans before ranking writes hosts
    // or setup changes the service. Applying later rechecks file ownership.
    #[cfg(target_os = "macos")]
    let _prepared = split_dns::prepare(
        std::path::Path::new("/etc/resolver"),
        &assemble_dns_rules(&agent_rules, &studio_subs, true, true),
    )?;
    step("Выбираем подходящее подключение");
    let ranked = crate::net::rank::discover_agent(if_index)?;
    for note in crate::net::rank::format_notes(&ranked) {
        sub_notes.push(note);
    }
    let mut relay_ok = false;
    let mut relay_note = String::new();
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    {
        step("Запускаем DNS-обход");
        match crate::system::service::enable() {
            Ok(()) => {
                relay_ok = wait_for_ready(Duration::from_secs(4), relay_ready);
                if !relay_ok {
                    relay_note = "фоновый процесс не подтвердил готовность за 4с".into();
                }
            }
            Err(e) => {
                relay_note = format!("релей не установлен ({e}), используются прямые UDP DNS");
            }
        }
    }
    // Readiness is local; separately verify that the DNS data path answers.
    if relay_ok && !relay_answers() {
        relay_ok = false;
        relay_note =
            "процесс запущен, но DNS-проверка не прошла; сохранены резервные адреса".into();
    }
    if !relay_ok && resolvers::fallback_v4().is_empty() {
        return Err("Включены только DoH-провайдеры, но локальный DNS не запустился".into());
    }
    if !relay_ok && resolver_pool::load()?.iter().any(|p| p.kind() == "doh") {
        sub_notes.push(
            "DoH доступен при подборе IP; для текущих DNS-запросов нужна работающая служба".into(),
        );
    }
    #[cfg(target_os = "macos")]
    let rules = split_dns::prepare(
        std::path::Path::new("/etc/resolver"),
        &assemble_dns_rules(&agent_rules, &studio_subs, relay_ok, true),
    )?;
    crate::net::rank::apply_ranked(&ranked)?;
    crate::net::doh::disable_system_doh()?;

    // Keep verified agent addresses installed by apply_ranked. A VPN enabled
    // later may intercept loopback DNS even while the relay remains healthy.

    #[cfg(target_os = "windows")]
    {
        let rules = assemble_dns_rules(&agent_rules, &studio_subs, relay_ok, false);
        step("Сохраняем настройки подключения");
        let count = crate::net::nrpt::apply_nrpt_rules_direct(&rules, NRPT_TAG, "Antigravity DNS");
        if count != rules.len() {
            return Err(format!("NRPT: записано {count}/{} правил", rules.len()));
        }
        crate::net::nrpt::verify_effective(&rules)?;
    }

    #[cfg(target_os = "macos")]
    {
        split_dns::apply(std::path::Path::new("/etc/resolver"), &rules)?;
    }
    flush_dns_cache()?;

    let mut msg = if relay_ok {
        format!("Сеть настроена (релей {}:{})", LISTEN_IP, LISTEN_PORT)
    } else if cfg!(target_os = "macos") {
        "Сеть настроена (/etc/resolver, без фона)".to_string()
    } else if relay_note.is_empty() {
        "Сеть настроена".to_string()
    } else {
        format!("Сеть настроена; {}", relay_note)
    };
    if !sub_notes.is_empty() {
        msg.push_str(" | ");
        msg.push_str(&sub_notes.join("; "));
    }
    Ok(NetworkSetup {
        message: msg,
        local_relay_running: relay_ok,
    })
}

fn relay_answers() -> bool {
    let query = client::build_query("daily-cloudcode-pa.googleapis.com", 0xA651);
    client::query_raw_via(
        &query,
        LISTEN_IP.parse().unwrap(),
        0,
        Duration::from_secs(5),
    )
    .is_ok_and(|reply| client::is_successful_response(&reply))
}

fn relay_ready(timeout: Duration) -> bool {
    let query = client::build_query(relay::HEALTH_NAME, 0xA652);
    client::query_raw_to(
        &query,
        std::net::SocketAddrV4::new(LISTEN_IP.parse().unwrap(), relay::HEALTH_PORT),
        0,
        timeout,
    )
    .is_ok_and(|reply| {
        client::answer_addrs(&reply) == vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]
    })
}

fn wait_for_ready(budget: Duration, mut probe: impl FnMut(Duration) -> bool) -> bool {
    let deadline = std::time::Instant::now() + budget;
    while let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) {
        if left.is_zero() {
            break;
        }
        if probe(left.min(Duration::from_millis(250))) {
            return true;
        }
        thread::sleep(
            deadline
                .saturating_duration_since(std::time::Instant::now())
                .min(Duration::from_millis(100)),
        );
    }
    false
}

#[cfg(test)]
mod startup_tests {
    use super::*;
    #[test]
    fn slow_probe_cannot_multiply_the_startup_budget() {
        let start = std::time::Instant::now();
        let mut calls = 0;
        assert!(!wait_for_ready(Duration::from_millis(40), |left| {
            calls += 1;
            thread::sleep(left);
            false
        }));
        assert_eq!(calls, 1);
        assert!(start.elapsed() < Duration::from_millis(200));
    }
    #[test]
    fn ready_probe_finishes_without_waiting_out_the_budget() {
        let start = std::time::Instant::now();
        assert!(wait_for_ready(Duration::from_secs(4), |_| true));
        assert!(start.elapsed() < Duration::from_millis(200));
    }
}

pub fn remove_dns_rules() -> Result<(), String> {
    remove_dns_configuration(true)
}

fn remove_dns_configuration(restore_tcp: bool) -> Result<(), String> {
    let mut errors = Vec::new();
    let _configuration = configuration_lock()?;
    // Stop the background writer, but retain its directory and every backup.
    crate::system::service::disable()?;
    // Remove only the obsolete marker from the experimental TUN mode.
    let legacy_mode = relay::log_dir().join("hosts-mode");
    match std::fs::remove_file(legacy_mode) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.to_string()),
    }
    if let Err(e) = crate::net::hosts::remove_entries() {
        errors.push(e);
    }
    if let Err(e) = crate::net::doh::restore_system_doh() {
        errors.push(e);
    }
    if restore_tcp {
        if let Err(e) = crate::net::socket::restore_current_network_stack() {
            errors.push(e);
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Err(e) = remove_static_routes() {
            errors.push(e);
        }
        if let Err(e) = crate::net::nrpt::native_remove_nrpt_rules() {
            errors.push(e);
        }
        if crate::net::nrpt::get_nrpt_status_info().0 != 0 {
            errors.push("Не все правила NRPT удалены".into());
        }
    }
    #[cfg(target_os = "macos")]
    {
        errors.extend(split_dns::remove(
            std::path::Path::new("/etc/resolver"),
            &nrpt_domains(),
        ));
    }
    if let Err(error) = flush_dns_cache() {
        errors.push(error);
    }
    resolvers::invalidate_network_caches();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}
