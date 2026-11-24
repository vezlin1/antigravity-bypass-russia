pub mod client;
#[cfg(any(windows, test))]
pub mod compatibility;
pub mod config;
pub mod dns_https;
pub mod doh;
pub mod egress;
pub mod health;
pub mod hosts;
#[cfg(any(target_os = "linux", test))]
pub mod linux_dns;
pub mod nrpt;
pub mod provider;
pub mod rank;
pub mod relay;
mod relay_update;
pub mod resolver_pool;
pub mod resolvers;
pub mod route_health;
pub mod routes;
pub mod socket;
#[cfg(any(target_os = "macos", test))]
pub mod split_dns;
#[cfg(windows)]
mod web_rules;
#[cfg(windows)]
pub mod windows_connect;

pub use relay::{detach_console, log_fatal, run as run_dns_relay};

#[cfg(any(target_os = "macos", test))]
use provider::nrpt_domains;
#[cfg(any(windows, target_os = "macos", test))]
use provider::NRPT_STUDIO;
#[cfg(windows)]
use provider::NRPT_TAG;
use provider::{NRPT_AGENT, PRIMARY_CLOUD_CODE, SUBSTITUTION_CANARIES};
use relay::{LISTEN_IP, LISTEN_PORT};
#[cfg(windows)]
use routes::remove_static_routes;
use routes::RoutePolicy;
use std::thread;
use std::time::Duration;

#[cfg(any(windows, target_os = "macos", test))]
fn assemble_nameservers(via_relay: bool, substituters: &[&str], fallback: &[&str]) -> String {
    let servers = if substituters.is_empty() {
        fallback
    } else {
        substituters
    };
    via_relay
        .then_some(LISTEN_IP)
        .into_iter()
        .chain(servers.iter().copied())
        .collect::<Vec<_>>()
        .join(";")
}

#[cfg(any(windows, target_os = "macos", test))]
fn assemble_dns_rules(
    agent_rules: &[(String, Vec<&str>)],
    studio_servers: &[&str],
    udp_fallback: &[&str],
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
        .map(|(name, servers)| {
            (
                namespace(name),
                assemble_nameservers(via_relay, servers, udp_fallback),
            )
        })
        .collect();
    for name in NRPT_STUDIO {
        let name = namespace(name);
        if !rules.iter().any(|(existing, _)| *existing == name) {
            rules.push((
                name,
                assemble_nameservers(via_relay, studio_servers, udp_fallback),
            ));
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
        use super::*;
        let config = config::Config {
            extra_udp: vec![config::UdpProvider {
                name: "my-udp".into(),
                addresses: vec!["192.0.2.53".parse().unwrap(), "192.0.2.54".parse().unwrap()],
            }],
            ..config::Config::default()
        };
        let pool = resolver_pool::from_config(&config).unwrap();
        let fallback = resolvers::configured_udp_v4(&pool);
        let servers: Vec<_> = fallback.iter().map(String::as_str).collect();
        assert_eq!(
            assemble_nameservers(true, &["192.0.2.80"], &servers),
            format!("{LISTEN_IP};192.0.2.80")
        );
        assert_eq!(
            assemble_nameservers(false, &["192.0.2.80"], &servers),
            "192.0.2.80"
        );
        assert_eq!(
            assemble_nameservers(false, &[], &servers),
            "192.0.2.53;192.0.2.54"
        );
        assert_eq!(
            assemble_nameservers(true, &[], &servers),
            format!("{LISTEN_IP};192.0.2.53;192.0.2.54")
        );
    }

    #[test]
    fn default_doh_rules_use_only_the_relay_or_require_agent_hosts_on_windows() {
        use super::*;
        let pool = resolver_pool::from_config(&config::Config::default()).unwrap();
        let fallback = resolvers::configured_udp_v4(&pool);
        assert!(fallback.is_empty());
        let agent_rules: Vec<_> = NRPT_AGENT
            .iter()
            .map(|host| (host.to_string(), vec![]))
            .collect();
        let inventory = nrpt::NrptInventory::default();

        let desired = assemble_dns_rules(&agent_rules, &[], &[], true, false);
        let plan = inventory.plan(&desired);
        assert_eq!(plan.rules, desired);
        assert!(plan.rules.iter().all(|(_, servers)| servers == LISTEN_IP));
        assert!(compatibility_coverage(&plan, &[], false)
            .agent_hosts
            .is_empty());

        let desired = assemble_dns_rules(&agent_rules, &[], &[], false, false);
        let plan = inventory.plan(&desired);
        assert!(plan.rules.is_empty());
        assert_eq!(
            compatibility_coverage(&plan, &[], false).agent_hosts,
            NRPT_AGENT
        );
    }

    #[test]
    fn macos_rules_keep_agent_dns_when_studio_results_differ() {
        use super::*;
        let fallback = ["192.0.2.53"];
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
            let rules = assemble_dns_rules(&agent_rules, studio_servers, &fallback, false, true);
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
                    assemble_nameservers(false, agent_servers, &fallback)
                );
            }
            assert_eq!(
                rules
                    .iter()
                    .find(|(name, _)| name == "aistudio.google.com")
                    .unwrap()
                    .1,
                assemble_nameservers(false, studio_servers, &fallback)
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
                assemble_nameservers(false, agent_servers, &fallback)
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
            let rules = assemble_dns_rules(&agent_rules, &studio_servers, &[], via_relay, false);
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
                    assemble_nameservers(via_relay, &agent_servers, &[])
                );
            }
            assert_eq!(
                rules
                    .iter()
                    .find(|(name, _)| name == ".generativelanguage.googleapis.com")
                    .unwrap()
                    .1,
                assemble_nameservers(via_relay, &studio_servers, &[])
            );
        }
    }

    #[test]
    fn compatibility_requires_the_specific_agent_host_but_not_for_a_studio_suffix() {
        use super::*;
        let inventory = nrpt::NrptInventory {
            foreign_rules: vec![nrpt::ForeignRule {
                id: "other-bypass".into(),
                namespaces: vec![
                    "DAILY-CLOUDCODE-PA.GOOGLEAPIS.COM.".into(),
                    ".generativelanguage.googleapis.com".into(),
                    "unrelated.test".into(),
                ],
                nameservers: vec!["192.0.2.53".into()],
                display_name: "Existing DNS".into(),
            }],
            policy_present: false,
        };
        let desired = [
            (
                "daily-cloudcode-pa.googleapis.com".into(),
                "127.0.0.53".into(),
            ),
            (
                "generativelanguage.googleapis.com".into(),
                "127.0.0.53".into(),
            ),
            (
                ".generativelanguage.googleapis.com".into(),
                "127.0.0.53".into(),
            ),
        ];
        let plan = inventory.plan(&desired);
        let coverage = compatibility_coverage(&plan, &[], false);
        assert_eq!(coverage.agent_hosts, ["daily-cloudcode-pa.googleapis.com"]);
        assert!(!coverage.browser_rules_effective);
        assert!(coverage
            .notes
            .iter()
            .any(|note| note.contains("Existing DNS") && note.contains("192.0.2.53")));
        assert!(coverage
            .notes
            .iter()
            .any(|note| note.contains("не подтверждён")));
        assert!(coverage
            .notes
            .iter()
            .all(|note| !note.contains("unrelated.test")));
    }

    #[test]
    fn effective_override_and_domain_policy_require_agent_hosts_fallback() {
        use super::*;
        let desired: Vec<_> = NRPT_AGENT
            .iter()
            .map(|host| (host.to_string(), "127.0.0.53".into()))
            .collect();
        let mut inventory = nrpt::NrptInventory {
            foreign_rules: vec![],
            policy_present: false,
        };
        let plan = inventory.plan(&desired);
        let coverage = compatibility_coverage(
            &plan,
            &[nrpt::EffectiveIssue {
                namespace: "CLOUDCODE-PA.GOOGLEAPIS.COM.".into(),
                reason: "Windows uses another DNS".into(),
            }],
            false,
        );
        assert_eq!(coverage.agent_hosts, ["cloudcode-pa.googleapis.com"]);
        inventory.policy_present = true;
        assert_eq!(
            compatibility_coverage(&inventory.plan(&desired), &[], false).agent_hosts,
            NRPT_AGENT
        );
        let daily_only = compatibility_coverage(&inventory.plan(&desired), &[], true);
        let required: Vec<_> = NRPT_AGENT
            .iter()
            .copied()
            .filter(|host| *host != PRIMARY_CLOUD_CODE)
            .collect();
        assert_eq!(daily_only.agent_hosts, required);
    }

    #[test]
    fn late_foreign_dns_or_hosts_only_mode_preserves_system_doh() {
        use super::*;
        let clean = nrpt::NrptInventory::default();
        let plan = clean.plan(&[("example.test".into(), "127.0.0.53".into())]);
        assert!(may_disable_system_doh(&[&clean, &clean], &plan));
        let policy = nrpt::NrptInventory {
            foreign_rules: vec![],
            policy_present: true,
        };
        assert!(!may_disable_system_doh(&[&clean, &policy], &plan));
        let foreign = nrpt::NrptInventory {
            foreign_rules: vec![nrpt::ForeignRule {
                id: "late-vpn".into(),
                namespaces: vec!["unrelated.test".into()],
                nameservers: vec![],
                display_name: String::new(),
            }],
            policy_present: false,
        };
        assert!(!may_disable_system_doh(&[&clean, &foreign], &plan));
        assert!(!may_disable_system_doh(&[&foreign, &clean], &plan));
        let hosts_only = clean.plan(&[("example.test".into(), String::new())]);
        assert!(!may_disable_system_doh(&[&clean], &hosts_only));
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
    #[cfg(target_os = "linux")]
    let commands: &[(&str, &[&str])] = &[
        ("resolvectl", &["flush-caches"]),
        ("systemd-resolve", &["--flush-caches"]),
    ];
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    let commands: &[(&str, &[&str])] = &[];
    let mut errors: Vec<String> = Vec::new();
    for (program, args) in commands {
        match crate::system::command::output(program, *args) {
            Ok(out) if out.status.success() => {
                #[cfg(target_os = "linux")]
                return Ok(());
            }
            Ok(out) => {
                #[cfg(not(target_os = "linux"))]
                errors.push(format!("{program}: {}", out.status));
                #[cfg(target_os = "linux")]
                let _ = out;
            }
            Err(error) => {
                #[cfg(not(target_os = "linux"))]
                errors.push(format!("{program}: {error}"));
                #[cfg(target_os = "linux")]
                let _ = error;
            }
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
    pub hosts_fallback: bool,
    pub system_routes: bool,
    pub browser_dns_confirmed: bool,
    /// The regular Cloud Code endpoint failed verification; clients must use daily.
    pub primary_skipped: bool,
}

pub enum SetupProgress<'a> {
    /// A new user-visible step begins; the previous one succeeded.
    Stage(SetupStage),
    Working(&'a str),
    Detail(&'a str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupStage {
    /// Finding and checking the Google servers.
    Connection,
    /// Starting and checking the background DNS service.
    Service,
    /// Writing the system settings.
    Saving,
}

/// Whether the web versions of Gemini and AI Studio go through the bypass
/// now, and when the service last switched them after a VPN change.
pub fn web_rules_status() -> Option<(bool, Option<u64>)> {
    #[cfg(windows)]
    return web_rules::status();
    #[cfg(not(windows))]
    None
}

/// A plain-language name for a Google server, for on-screen text.
pub fn server_label(host: &str) -> &'static str {
    match host.trim_start_matches('.') {
        provider::PRIMARY_CLOUD_CODE => "основной сервер Antigravity",
        provider::DAILY_CLOUD_CODE => "резервный сервер Antigravity",
        "aicode.googleapis.com" => "сервер проверки доступа",
        "generativelanguage.googleapis.com" => "сервер Gemini",
        _ => "сервер Google",
    }
}

#[cfg(any(windows, test))]
struct CompatibilityCoverage {
    agent_hosts: Vec<String>,
    browser_rules_effective: bool,
    notes: Vec<String>,
}

#[cfg(any(windows, test))]
fn compatibility_coverage(
    plan: &nrpt::CompatibilityPlan,
    issues: &[nrpt::EffectiveIssue],
    skip_primary: bool,
) -> CompatibilityCoverage {
    let normalize = |name: &str| name.trim().trim_end_matches('.').to_ascii_lowercase();
    let unavailable: std::collections::BTreeSet<_> = plan
        .skipped
        .iter()
        .chain(issues.iter().map(|issue| &issue.namespace))
        .map(|name| normalize(name))
        .collect();
    // Exact Agent rules are planned independently of Studio suffixes. A
    // skipped suffix must not invalidate an effective exact Agent rule.
    let agent_hosts: Vec<_> = NRPT_AGENT
        .iter()
        .filter(|host| !skip_primary || **host != PRIMARY_CLOUD_CODE)
        .filter(|host| unavailable.contains(**host))
        .map(|host| (*host).to_string())
        .collect();
    let mut notes = Vec::new();
    if plan.policy_present {
        notes.push("Политика DNS Windows сохранена; локальные правила NRPT не добавлялись".into());
    }
    for rule in &plan.preserved {
        let label = if rule.display_name.trim().is_empty() {
            rule.id.as_str()
        } else {
            rule.display_name.as_str()
        };
        let domains: Vec<_> = rule
            .namespaces
            .iter()
            .filter(|name| unavailable.contains(&normalize(name)))
            .map(String::as_str)
            .collect();
        if !domains.is_empty() {
            notes.push(format!(
                "Сохранён DNS {}: {} → {}",
                label,
                domains.join(", "),
                if rule.nameservers.is_empty() {
                    "системные DNS".into()
                } else {
                    rule.nameservers.join(", ")
                }
            ));
        }
    }
    let optional: Vec<_> = unavailable
        .iter()
        .filter(|name| !NRPT_AGENT.contains(&name.as_str()))
        .cloned()
        .collect();
    if !optional.is_empty() {
        notes.push(format!(
            "Gemini/AI Studio: используются существующие настройки для {}; обход этих доменов не подтверждён",
            optional.join(", ")
        ));
    }
    for issue in issues {
        notes.push(format!("DNS {}: {}", issue.namespace, issue.reason));
    }
    CompatibilityCoverage {
        agent_hosts,
        browser_rules_effective: optional.is_empty(),
        notes,
    }
}

#[cfg(any(windows, test))]
fn may_disable_system_doh(
    inventories: &[&nrpt::NrptInventory],
    plan: &nrpt::CompatibilityPlan,
) -> bool {
    !plan.rules.is_empty()
        && inventories
            .iter()
            .all(|inventory| inventory.foreign_rules.is_empty() && !inventory.policy_present)
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
    try_configuration_lock()?.ok_or_else(configuration_busy)
}

fn try_configuration_lock() -> Result<Option<ConfigurationLock>, String> {
    let dir = relay::log_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    try_lock_configuration_file(&dir.join("network-update.lock"))
}

fn configuration_busy() -> String {
    "Настройки сети уже обновляются другим процессом. Повторите после завершения обновления.".into()
}

#[cfg(test)]
fn lock_configuration_file(path: &std::path::Path) -> Result<ConfigurationLock, String> {
    try_lock_configuration_file(path)?.ok_or_else(configuration_busy)
}

fn try_lock_configuration_file(
    path: &std::path::Path,
) -> Result<Option<ConfigurationLock>, String> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| format!("Блокировка настройки сети: {e}"))?;
    match file.try_lock() {
        Ok(()) => Ok(Some(ConfigurationLock(file))),
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(error) => Err(format!("Блокировка настройки сети: {error}")),
    }
}

pub fn apply_dns_rules(
    progress: &mut dyn FnMut(SetupProgress<'_>),
) -> Result<NetworkSetup, String> {
    #[cfg(windows)]
    let policy = RoutePolicy::System;
    #[cfg(not(windows))]
    let policy = RoutePolicy::Physical;
    apply_dns_rules_with(policy, progress)
}

/// Each probe waits on the network for up to the resolver budget. Run every
/// distinct host at once instead of one after another; a host shared by the
/// Agent rules and the canaries is probed once.
fn substitutions_by_host<'a>(
    names: impl IntoIterator<Item = &'a str>,
    probe: impl Fn(&str) -> Vec<String> + Sync,
) -> std::collections::HashMap<String, Vec<String>> {
    let mut hosts: Vec<&str> = Vec::new();
    for name in names {
        let host = name.trim_start_matches('.');
        if !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    let probe = &probe;
    thread::scope(|scope| {
        let probes: Vec<_> = hosts
            .iter()
            .map(|host| (*host, scope.spawn(move || probe(host))))
            .collect();
        probes
            .into_iter()
            .map(|(host, probe)| (host.to_string(), probe.join().unwrap_or_default()))
            .collect()
    })
}

fn apply_dns_rules_with(
    policy: RoutePolicy,
    progress: &mut dyn FnMut(SetupProgress<'_>),
) -> Result<NetworkSetup, String> {
    use SetupProgress::{Detail, Stage, Working};
    progress(Stage(SetupStage::Connection));
    progress(Working("проверяем настройки сети"));
    preflight()?;
    let _configuration = configuration_lock()?;
    // Reconfigure owned rules in place. Removing the working service/hosts/DNS
    // before discovery left users disconnected whenever all probes failed.

    // Read before changing routes/service; unreadable rules are not evidence
    // that DNS is safe to overwrite. Re-read before applying the final plan.
    #[cfg(windows)]
    let initial_inventory = nrpt::inventory()?;
    let previously_configured = nrpt::get_nrpt_status_info().0 > 0;
    let pool = resolver_pool::load()?;
    let udp_ips = resolvers::configured_udp_v4(&pool);
    let mut compatibility_notes = Vec::new();
    #[cfg(windows)]
    let hosts_fallback;
    #[cfg(not(windows))]
    let hosts_fallback = false;

    progress(Working("определяем подключение к интернету"));
    let egress = match policy {
        RoutePolicy::Physical => crate::net::egress::detect(),
        #[cfg(windows)]
        RoutePolicy::System => None,
    };
    let if_index = egress.as_ref().map(|e| e.if_index).unwrap_or(0);
    #[cfg(windows)]
    if policy == RoutePolicy::Physical
        && (if_index == 0 || egress.as_ref().is_none_or(|e| e.gateway.is_none()))
    {
        return Err("Не найден физический выход в интернет; проверка через VPN отменена".into());
    }

    progress(Detail("Подбор маршрута · проверяем DNS и TLS/HTTP"));
    progress(Working("готовим проверку"));
    let mut update = None;
    let staged = routes::with_probe_routes(policy, |prepare_routes| {
        // DNS probes and the running relay use the same route policy.
        prepare_routes(&[])?;
        // Give freshly added physical routes time to apply. The system route
        // policy changes no routes here, so it has nothing to wait for.
        #[cfg(windows)]
        if policy == RoutePolicy::Physical {
            thread::sleep(Duration::from_millis(400));
        }
        let discovery = rank::discover_agent(if_index, policy, prepare_routes, progress)?;
        // Every caller switches client endpoints to daily right after this
        // setup, so the regular endpoint is optional wherever that switch
        // covers all discovered clients.
        let skip_primary = rank::check_agent_routes(
            &discovery.ranked,
            &discovery.failures,
            crate::core::endpoint::primary_optional(),
        )?;
        let ranked = discovery.ranked;

        let update = update.insert(relay_update::RelayUpdate::capture()?);
        config::prepare_service()?;
        if if_index > 0 || policy != RoutePolicy::Physical {
            relay::save_if_index(if_index)?;
        }
        #[cfg(target_os = "linux")]
        linux_dns::prepare(if_index)?;
        relay::save_route_policy(policy)?;
        relay::save_upstream_config(&udp_ips)?;

        progress(Stage(SetupStage::Service));
        progress(Working("запускаем фоновую службу"));
        let mut browser_missing = Vec::new();
        let startup = update.start().and_then(|()| {
            if !wait_for_ready(Duration::from_secs(4), relay_ready) {
                return Err("DNS-релей не подтвердил готовность за 4с".into());
            }
            let answers = relay_answers(skip_primary, relay_returns_address);
            browser_missing = answers.browser_missing;
            if !answers.agent_missing.is_empty() {
                #[cfg(windows)]
                if matches!(relay::local_dns_available(), Ok(false)) {
                    return Err("Локальный UDP-порт 53 недоступен даже для тестового пакета".into());
                }
                return Err(format!(
                    "Релей не вернул пригодный A-ответ для Agent ({})",
                    answers.agent_missing.join(", ")
                ));
            }
            if previously_configured && !browser_missing.is_empty() {
                return Err(format!(
                    "Релей не вернул пригодный A-ответ для браузерных доменов ({})",
                    browser_missing.join(", ")
                ));
            }
            Ok(())
        });
        let fallback_supported =
            cfg!(windows) || (cfg!(target_os = "macos") && !udp_ips.is_empty());
        let relay_error =
            relay_update::allow_relay_fallback(startup, previously_configured, fallback_supported)?;
        config::keep_downgrade_compatible()?;
        Ok((ranked, skip_primary, relay_error, browser_missing))
    });
    let (ranked, skip_primary, relay_error, browser_missing) =
        relay_update::finish_staging(staged, || update.map_or(Ok(()), |update| update.rollback()))?;
    if skip_primary {
        compatibility_notes.push(format!(
            "{PRIMARY_CLOUD_CODE}: недоступен из этой сети, клиенты переключаются на daily"
        ));
    }

    let mut sub_notes = Vec::new();
    let mut agent_rules: Vec<_> = NRPT_AGENT
        .iter()
        .map(|name| (name.to_string(), Vec::new()))
        .collect();
    let mut studio_subs: Vec<String> = Vec::new();
    if !udp_ips.is_empty() {
        progress(Working("проверяем запасные серверы адресов"));
        let substitutions = substitutions_by_host(
            agent_rules
                .iter()
                .map(|(name, _)| name.as_str())
                .chain(SUBSTITUTION_CANARIES.iter().copied()),
            |host| resolvers::substituting_addrs(host, if_index),
        );
        for (name, subs) in &mut agent_rules {
            let host = name.trim_start_matches('.');
            *subs = substitutions[host].clone();
            if subs.is_empty() {
                sub_notes.push(format!("{host}: подмена через прямой UDP не подтверждена"));
            } else {
                sub_notes.push(format!("{host}: {}", subs.join(", ")));
            }
        }
        for name in SUBSTITUTION_CANARIES {
            let host = name.trim_start_matches('.');
            for s in &substitutions[host] {
                if !studio_subs.contains(s) {
                    studio_subs.push(s.clone());
                }
            }
        }
        if studio_subs.is_empty() {
            sub_notes.push("Studio/Gemini: подмена через прямой UDP не подтверждена".into());
        } else {
            sub_notes.push(format!("Studio/Gemini: {}", studio_subs.join(", ")));
        }
    }
    let _ = (&agent_rules, &studio_subs);
    // The background service rewrites these same rules when the VPN is
    // turned on or off (see web_rules).
    #[cfg(windows)]
    let mut followed_rules = web_rules::SavedRules {
        agent: agent_rules.clone(),
        studio: studio_subs.clone(),
        udp_fallback: udp_ips.clone(),
        skip_primary,
        via_relay: false,
        switched_at_ms: None,
    };
    #[cfg(not(target_os = "linux"))]
    let agent_rules: Vec<_> = agent_rules
        .iter()
        .map(|(name, servers)| {
            (
                name.clone(),
                servers.iter().map(String::as_str).collect::<Vec<_>>(),
            )
        })
        .collect();
    #[cfg(not(target_os = "linux"))]
    let studio_subs: Vec<_> = studio_subs.iter().map(String::as_str).collect();
    #[cfg(not(target_os = "linux"))]
    let udp_fallback: Vec<_> = udp_ips.iter().map(String::as_str).collect();
    for note in crate::net::rank::format_notes(&ranked) {
        sub_notes.push(note);
    }
    let relay_ok = relay_error.is_none();
    let browser_dns_confirmed = relay_ok && browser_missing.is_empty();
    let relay_note = relay_error.unwrap_or_default();
    if !browser_missing.is_empty() {
        compatibility_notes.push(format!(
            "Gemini/AI Studio: релей не вернул пригодный A-ответ для {}",
            browser_missing.join(", ")
        ));
    }
    if !relay_ok && udp_ips.is_empty() {
        #[cfg(windows)]
        compatibility_notes.push(format!(
            "{relay_note}. Подключение Antigravity проверяется через hosts"
        ));
    }
    if !relay_ok && pool.iter().any(|p| p.kind() == "doh") {
        sub_notes.push(
            "DoH доступен при подборе IP; для текущих DNS-запросов нужна работающая служба".into(),
        );
    }
    #[cfg(target_os = "macos")]
    let rules = split_dns::prepare(
        std::path::Path::new("/etc/resolver"),
        &assemble_dns_rules(&agent_rules, &studio_subs, &udp_fallback, relay_ok, true),
    )?;
    #[cfg(windows)]
    let (inventory, plan) = {
        let rules = assemble_dns_rules(&agent_rules, &studio_subs, &udp_fallback, relay_ok, false);
        let inventory = nrpt::inventory()?;
        let plan = inventory.plan(&rules);
        let coverage = compatibility_coverage(&plan, &[], skip_primary);
        // Reject a known uncovered Agent before replacing its working pins or
        // removing an old owned NRPT rule during reconciliation.
        compatibility::require_agent_pins(&coverage.agent_hosts, &ranked)?;
        (inventory, plan)
    };
    progress(Stage(SetupStage::Saving));
    crate::net::rank::apply_ranked(&ranked, skip_primary, policy)?;

    // Keep verified agent addresses installed by apply_ranked. A VPN enabled
    // later may intercept loopback DNS even while the relay remains healthy.

    #[cfg(target_os = "windows")]
    let browser_dns_confirmed = {
        progress(Working("записываем настройки Windows"));
        let plan = nrpt::apply_compatible_rules(&plan, NRPT_TAG, "Antigravity DNS")?;
        followed_rules.via_relay = relay_ok;
        if let Err(error) = web_rules::save(&followed_rules) {
            // Setup itself succeeded; only the switch on VPN changes is lost.
            relay::log_event(&format!("Правила для смены VPN не сохранены: {error}"));
        }
        let latest_inventory = nrpt::inventory()?;
        // Foreign split-DNS often relies on system DoH policy. Hosts provides
        // the Agent fallback without changing those global settings.
        if policy == RoutePolicy::System {
            if let Err(error) = crate::net::doh::restore_system_doh() {
                compatibility_notes.push(format!("Восстановление исходного DoH: {error}"));
            }
        } else if may_disable_system_doh(
            &[&initial_inventory, &inventory, &latest_inventory],
            &plan,
        ) {
            crate::net::doh::disable_system_doh()?;
        } else {
            compatibility_notes
                .push("Существующие правила DNS и настройки системного DoH сохранены".into());
        }
        let issues = match nrpt::ineffective_namespaces(&plan.rules) {
            Ok(issues) => issues,
            Err(error) => plan
                .rules
                .iter()
                .map(|(namespace, _)| nrpt::EffectiveIssue {
                    namespace: namespace.clone(),
                    reason: format!("проверка действующей политики недоступна: {error}"),
                })
                .collect(),
        };
        let coverage = compatibility_coverage(&plan, &issues, skip_primary);
        hosts_fallback = !coverage.agent_hosts.is_empty();
        flush_dns_cache()?;
        if hosts_fallback {
            progress(Working("проверяем запасной список адресов"));
            compatibility::verify_agent_pins(&coverage.agent_hosts, &ranked)?;
            compatibility_notes.push(format!(
                "Antigravity: проверен резервный путь через hosts для {}",
                coverage.agent_hosts.join(", ")
            ));
        }
        compatibility_notes.extend(coverage.notes);
        browser_dns_confirmed && coverage.browser_rules_effective
    };

    #[cfg(target_os = "macos")]
    {
        crate::net::doh::disable_system_doh()?;
        split_dns::apply(std::path::Path::new("/etc/resolver"), &rules)?;
    }
    #[cfg(not(windows))]
    #[cfg(target_os = "linux")]
    linux_dns::apply()?;
    #[cfg(not(windows))]
    flush_dns_cache()?;

    let mut msg = if relay_ok {
        format!("Сеть настроена (релей {}:{})", LISTEN_IP, LISTEN_PORT)
    } else if cfg!(target_os = "macos") {
        "Сеть настроена (/etc/resolver, без фона)".to_string()
    } else if cfg!(target_os = "linux") {
        "Сеть настроена (hosts)".to_string()
    } else if relay_note.is_empty() {
        "Сеть настроена".to_string()
    } else {
        format!("Сеть настроена; {}", relay_note)
    };
    if !sub_notes.is_empty() {
        msg.push_str(" | ");
        msg.push_str(&sub_notes.join("; "));
    }
    if !compatibility_notes.is_empty() {
        msg.push_str(" | ");
        msg.push_str(&compatibility_notes.join("; "));
    }
    Ok(NetworkSetup {
        message: msg,
        local_relay_running: relay_ok,
        hosts_fallback,
        system_routes: policy != RoutePolicy::Physical,
        browser_dns_confirmed,
        primary_skipped: skip_primary,
    })
}

struct RelayAnswers {
    agent_missing: Vec<&'static str>,
    browser_missing: Vec<&'static str>,
}

fn relay_answers(skip_primary: bool, probe: impl Fn(&str) -> bool + Sync) -> RelayAnswers {
    let agent: Vec<_> = NRPT_AGENT
        .iter()
        .copied()
        .filter(|host| !skip_primary || *host != PRIMARY_CLOUD_CODE)
        .collect();
    let hosts: std::collections::BTreeSet<_> =
        agent.iter().chain(SUBSTITUTION_CANARIES).copied().collect();
    let missing: std::collections::BTreeSet<_> = thread::scope(|scope| {
        let checks: Vec<_> = hosts
            .into_iter()
            .map(|host| {
                let probe = &probe;
                (host, scope.spawn(move || probe(host)))
            })
            .collect();
        checks
            .into_iter()
            .filter_map(|(host, result)| (!result.join().unwrap_or(false)).then_some(host))
            .collect()
    });
    RelayAnswers {
        agent_missing: agent
            .into_iter()
            .filter(|host| missing.contains(host))
            .collect(),
        browser_missing: SUBSTITUTION_CANARIES
            .iter()
            .copied()
            .filter(|host| missing.contains(host))
            .collect(),
    }
}

fn relay_returns_address(host: &str) -> bool {
    relay_returns_address_within(host, Duration::from_secs(5))
}

fn relay_returns_address_within(host: &str, timeout: Duration) -> bool {
    let query = client::build_query(host, 0xA651);
    client::query_raw_via(&query, LISTEN_IP.parse().unwrap(), 0, timeout)
        .is_ok_and(|reply| has_usable_a_answer(&query, &reply))
}

fn has_usable_a_answer(query: &[u8], reply: &[u8]) -> bool {
    client::response_matches(query, reply)
        && client::is_successful_response(reply)
        && client::answer_addrs(reply)
            .into_iter()
            .any(|address| match address {
                std::net::IpAddr::V4(ip) => {
                    !ip.is_unspecified()
                        && !ip.is_loopback()
                        && !ip.is_private()
                        && !ip.is_link_local()
                        && !ip.is_multicast()
                        && !ip.is_broadcast()
                }
                std::net::IpAddr::V6(_) => false,
            })
}

#[cfg(target_os = "linux")]
pub fn apply_linux_dns_on_service_start() -> Result<(), String> {
    // Manual setup holds the lock and verifies the data path before applying
    // DNS itself. ExecStartPost must not modify system DNS in the meantime.
    let Some(_configuration) = try_configuration_lock()? else {
        return Ok(());
    };
    if !wait_for_ready(Duration::from_secs(4), relay_ready) {
        return Err("DNS-служба не подтвердила готовность; настройки DNS сохранены".into());
    }
    linux_dns::apply()
}

pub(crate) fn relay_ready(timeout: Duration) -> bool {
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

pub(crate) fn wait_for_ready(budget: Duration, mut probe: impl FnMut(Duration) -> bool) -> bool {
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
    fn substitution_probes_run_concurrently_once_per_host() {
        let calls = std::sync::Mutex::new(Vec::new());
        let started = std::time::Instant::now();
        let result = substitutions_by_host(
            NRPT_AGENT
                .iter()
                .copied()
                .chain(SUBSTITUTION_CANARIES.iter().copied())
                .chain([".gemini.google.com"]),
            |host| {
                calls.lock().unwrap().push(host.to_string());
                std::thread::sleep(Duration::from_millis(200));
                if host == "generativelanguage.googleapis.com" {
                    vec!["192.0.2.1".into()]
                } else {
                    Vec::new()
                }
            },
        );
        // Seven distinct hosts at 200 ms each would take 1.4 s sequentially.
        assert!(started.elapsed() < Duration::from_millis(1000));
        let mut calls = calls.into_inner().unwrap();
        calls.sort();
        let before = calls.len();
        calls.dedup();
        assert_eq!(before, calls.len(), "a host was probed twice");
        assert_eq!(calls.len(), 7);
        assert_eq!(result["generativelanguage.googleapis.com"], ["192.0.2.1"]);
        assert!(result["gemini.google.com"].is_empty());
    }

    #[test]
    fn relay_requires_a_matching_address_answer_for_a_public_domain() {
        use std::net::Ipv4Addr;
        let query = client::build_query(provider::DAILY_CLOUD_CODE, 17);
        assert!(!has_usable_a_answer(
            &query,
            &client::nodata_response(&query)
        ));
        assert!(!has_usable_a_answer(
            &query,
            &client::servfail_response(&query)
        ));
        for ip in [
            [0, 0, 0, 0],
            [127, 0, 0, 1],
            [169, 254, 0, 1],
            [10, 0, 0, 1],
            [224, 0, 0, 1],
            [255; 4],
        ] {
            let reply = client::address_response(&query, &[Ipv4Addr::from(ip)]).unwrap();
            assert!(!has_usable_a_answer(&query, &reply));
        }
        let address = Ipv4Addr::new(192, 0, 2, 17);
        let wrong_query = client::build_query("other.test", 17);
        let wrong_reply = client::address_response(&wrong_query, &[address]).unwrap();
        assert!(!has_usable_a_answer(&query, &wrong_reply));
        assert!(has_usable_a_answer(
            &query,
            &client::address_response(&query, &[address]).unwrap()
        ));
    }

    #[test]
    fn relay_can_report_browser_failure_separately_from_agent() {
        let browser_host = "aistudio.google.com";
        let status = relay_answers(false, |host| host != browser_host);
        assert!(status.agent_missing.is_empty());
        assert_eq!(status.browser_missing, [browser_host]);

        let status = relay_answers(false, |host| host != provider::DAILY_CLOUD_CODE);
        assert_eq!(status.agent_missing, [provider::DAILY_CLOUD_CODE]);
        assert!(status.browser_missing.is_empty());

        let status = relay_answers(true, |host| {
            assert_ne!(host, PRIMARY_CLOUD_CODE);
            true
        });
        assert!(status.agent_missing.is_empty());
        assert!(status.browser_missing.is_empty());
    }

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
    // Restore the system resolver while its DNS worker is still answering.
    #[cfg(target_os = "linux")]
    linux_dns::remove()?;
    crate::system::service::disable()?;
    // Remove obsolete files: the marker from the experimental TUN mode and
    // the route score table that releases before 2.2.1 maintained.
    for legacy in [
        relay::log_dir().join("hosts-mode"),
        config::directory().join("route-health.json"),
        config::directory().join("route-health.lock"),
    ] {
        match std::fs::remove_file(legacy) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
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
        if let Err(e) = web_rules::forget() {
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
        relay::save_route_policy(RoutePolicy::Physical)?;
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}
