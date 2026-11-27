//! User-owned network configuration shared with the elevated DNS worker.
use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DohProvider {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub bootstrap: Vec<IpAddr>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UdpProvider {
    pub name: String,
    pub addresses: Vec<std::net::Ipv4Addr>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    // Read the marker used by early development builds. Files written by this
    // version use the v2.5.0 schema so the previous binary can read them.
    #[serde(default, skip_serializing)]
    pub provider_defaults_version: u8,
    pub doh: Vec<DohProvider>,
    pub extra_udp: Vec<UdpProvider>,
    pub disabled_providers: Vec<String>,
    pub provider_order: Vec<String>,
    pub watch_region_errors: bool,
    pub log_roots: Vec<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            provider_defaults_version: 2,
            // HTTPS hostname verification still applies to every bootstrap IP.
            // Keep these in sync with the current A records of dns.dns-ai.ru:
            // the endpoint is HTTP/2-only, so a retired address fails the
            // whole provider even though the service itself is healthy.
            doh: vec![
                DohProvider {
                    name: "dns-ai.ru".into(),
                    url: "https://dns.dns-ai.ru/dns-query".into(),
                    bootstrap: vec![
                        "45.151.102.219".parse().unwrap(),
                        "194.87.196.13".parse().unwrap(),
                    ],
                },
                DohProvider {
                    name: "eu.geohide.ru".into(),
                    url: super::provider::GEOHIDE_EU_DOH.into(),
                    bootstrap: vec![
                        "217.60.245.219".parse().unwrap(),
                        "217.60.245.233".parse().unwrap(),
                    ],
                },
            ],
            extra_udp: vec![],
            disabled_providers: vec![],
            provider_order: vec![],
            watch_region_errors: true,
            log_roots: user_log_roots(),
        }
    }
}

fn user_root() -> PathBuf {
    #[cfg(windows)]
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| crate::system::env::expand_env_vars("%USERPROFILE%"));
    #[cfg(not(windows))]
    let base = crate::system::env::expand_env_vars("~").join(if cfg!(target_os = "macos") {
        "Library/Application Support"
    } else {
        ".config"
    });
    base.join("AntigravityBypass").join("network")
}

fn user_log_roots() -> Vec<PathBuf> {
    if crate::system::env::args().any(|arg| arg == crate::system::service::FORWARDER_FLAG) {
        return context().map(|c| c.log_roots).unwrap_or_default();
    }
    #[cfg(windows)]
    let base = std::env::var_os("APPDATA").map(PathBuf::from);
    #[cfg(not(windows))]
    let base = Some(
        crate::system::env::expand_env_vars("~").join(if cfg!(target_os = "macos") {
            "Library/Application Support"
        } else {
            ".config"
        }),
    );
    base.into_iter()
        .flat_map(|base| {
            ["Antigravity", "Antigravity IDE", "Google Antigravity"]
                .map(|product| base.join(product).join("logs"))
        })
        .chain(std::iter::once(cli_log_root()))
        .collect()
}

/// Antigravity CLI writes `cli-*.log` here, including region errors such as
/// `FAILED_PRECONDITION … User location is not supported` (#50, #52).
fn cli_log_root() -> PathBuf {
    #[cfg(windows)]
    let home = crate::system::env::expand_env_vars("%USERPROFILE%");
    #[cfg(not(windows))]
    let home = crate::system::env::expand_env_vars("~");
    home.join(".gemini").join("antigravity-cli").join("log")
}

/// Configurations saved before the CLI log root existed list exactly the old
/// stock roots: extend those, keep any list the user changed.
fn upgrade_log_roots(roots: &mut Vec<PathBuf>, stock: &[PathBuf], added: &Path) {
    let legacy: Vec<_> = stock.iter().filter(|root| *root != added).collect();
    if !roots.iter().any(|root| root == added)
        && roots.len() == legacy.len()
        && roots.iter().zip(&legacy).all(|(root, old)| root == *old)
    {
        roots.push(added.to_path_buf());
    }
}

pub(super) fn context_path() -> PathBuf {
    super::relay::log_dir().join("network-user.json")
}

#[derive(Serialize, Deserialize)]
struct Context {
    directory: PathBuf,
    log_roots: Vec<PathBuf>,
}
fn context() -> Option<Context> {
    serde_json::from_slice(&fs::read(context_path()).ok()?).ok()
}

pub fn directory() -> PathBuf {
    if crate::system::env::args().any(|arg| arg == crate::system::service::FORWARDER_FLAG) {
        if let Some(c) = context() {
            if c.directory.is_absolute() {
                return c.directory;
            }
        }
    }
    user_root()
}

pub fn path() -> PathBuf {
    directory().join("network.json")
}

pub fn ensure_directory() -> Result<(), String> {
    let dir = directory();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
        // An elevated launch must not leave the user's network state owned by root.
        if let Some(owner) = dir
            .ancestors()
            .skip(1)
            .filter_map(|p| fs::metadata(p).ok())
            .find(|m| m.uid() != 0)
        {
            for path in [dir.parent().unwrap(), &dir] {
                let file = fs::File::open(path).map_err(|e| e.to_string())?;
                let meta = file.metadata().map_err(|e| e.to_string())?;
                if (meta.uid(), meta.gid()) != (owner.uid(), owner.gid())
                    && unsafe { libc::fchown(file.as_raw_fd(), owner.uid(), owner.gid()) } != 0
                {
                    return Err(std::io::Error::last_os_error().to_string());
                }
            }
        }
    }
    Ok(())
}

pub fn inherit_directory_owner(path: &std::path::Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
        let owner = fs::metadata(path.parent().ok_or("Нет каталога состояния")?)
            .map_err(|e| e.to_string())?;
        let file = fs::File::open(path).map_err(|e| e.to_string())?;
        let meta = file.metadata().map_err(|e| e.to_string())?;
        if (meta.uid(), meta.gid()) != (owner.uid(), owner.gid())
            && unsafe { libc::fchown(file.as_raw_fd(), owner.uid(), owner.gid()) } != 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

pub fn prepare_user() -> Result<(), String> {
    let config = load()?;
    ensure_directory()?;
    if !path().exists() {
        crate::system::fs_utils::robust_write_file(
            &path(),
            &serde_json::to_vec_pretty(&config).map_err(|e| e.to_string())?,
        )?;
        inherit_directory_owner(&path())?;
    }
    Ok(())
}

pub fn load() -> Result<Config, String> {
    match fs::read(path()) {
        Ok(bytes) => decode(&bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let defaults = Config::default();
            validate(&defaults)?;
            Ok(defaults)
        }
        Err(e) => Err(format!("network.json: {e}")),
    }
}

fn decode(bytes: &[u8]) -> Result<Config, String> {
    let mut config = serde_json::from_slice(bytes).map_err(|e| format!("network.json: {e}"))?;
    upgrade_builtin_defaults(&mut config);
    validate(&config)?;
    Ok(config)
}

pub(super) fn keep_downgrade_compatible() -> Result<(), String> {
    let path = path();
    let original = fs::read(&path).map_err(|e| format!("network.json: {e}"))?;
    if let Some(compatible) = without_dev_marker(&original)? {
        crate::system::fs_utils::guarded_write_file(&path, Some(&original), Some(&compatible))?;
    }
    Ok(())
}

fn without_dev_marker(bytes: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let mut raw: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| format!("network.json: {e}"))?;
    let Some(fields) = raw.as_object_mut() else {
        return Err("network.json: ожидался JSON-объект".into());
    };
    if fields.remove("provider_defaults_version").is_none() {
        return Ok(None);
    }

    let before = decode(bytes)?;
    let mut compatible = serde_json::to_vec_pretty(&raw).map_err(|e| e.to_string())?;
    if decode(&compatible)?.doh != before.doh {
        // The old public defaults also had a single DoH. Record the already
        // selected order explicitly so the next read keeps this dev choice.
        raw["provider_order"] = serde_json::json!([before.doh[0].name]);
        compatible = serde_json::to_vec_pretty(&raw).map_err(|e| e.to_string())?;
    }
    Ok(Some(compatible))
}

// Old network.json files contain the previous defaults explicitly. Upgrade only
// those exact bootstrap lists; custom endpoints/address lists remain user-owned.
fn upgrade_builtin_defaults(config: &mut Config) {
    let defaults = Config::default();
    upgrade_log_roots(&mut config.log_roots, &defaults.log_roots, &cli_log_root());
    let current = &defaults.doh[0].bootstrap;
    let legacy: Vec<Vec<IpAddr>> = [
        &["192.144.59.14", "186.246.49.127"][..],
        &["192.144.59.14", "186.246.49.127", "94.232.43.149"][..],
    ]
    .iter()
    .map(|list| list.iter().map(|ip| ip.parse().unwrap()).collect())
    .collect();
    for provider in &mut config.doh {
        if provider.name == "dns-ai.ru"
            && provider.url == "https://dns.dns-ai.ru/dns-query"
            && legacy.contains(&provider.bootstrap)
        {
            provider.bootstrap = current.clone();
        }
    }
    for retired in ["xbox-dns.ru", "comss.one"] {
        forget_retired_provider(config, retired);
    }
    if config.provider_defaults_version < defaults.provider_defaults_version {
        // Only extend the old stock pool. Explicit UDP-only, exclusions, custom
        // endpoints and ordered configurations keep their transport choices.
        if config.doh == defaults.doh[..1]
            && config.extra_udp.is_empty()
            && config.disabled_providers.is_empty()
            && config.provider_order.is_empty()
        {
            config.doh = defaults.doh;
        }
        config.provider_defaults_version = defaults.provider_defaults_version;
    }
    // Keep an explicit GeoHide exclusion or ordering relevant to the older DoH
    // migration above, then discard references to the removed built-in UDP.
    forget_retired_provider(config, "geohide.ru");
}

fn forget_retired_provider(config: &mut Config, name: &str) {
    let custom = config.extra_udp.iter().any(|p| p.name == name)
        || config.doh.iter().any(|p| p.name == name);
    if !custom {
        config
            .disabled_providers
            .retain(|provider| provider != name);
        config.provider_order.retain(|provider| provider != name);
    }
}

pub fn validate(config: &Config) -> Result<(), String> {
    if config.doh.len() > 8 || config.extra_udp.len() > 8 || config.log_roots.len() > 16 {
        return Err("Слишком много провайдеров/каталогов в network.json".into());
    }
    if config.doh.is_empty() && config.extra_udp.is_empty() {
        return Err("В network.json не осталось DNS-серверов. Для DoH удалите пустое поле doh. Для UDP добавьте серверы в extra_udp".into());
    }
    let mut names = std::collections::HashSet::new();
    for provider in &config.extra_udp {
        if provider.addresses.is_empty()
            || provider.addresses.len() > 8
            || provider.name.is_empty()
            || provider.name.len() > 64
            || provider.name.chars().any(char::is_control)
            || !names.insert(provider.name.as_str())
        {
            return Err("Некорректный UDP-провайдер в network.json".into());
        }
    }
    for provider in &config.doh {
        let url = reqwest::Url::parse(&provider.url).map_err(|e| e.to_string())?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || provider.bootstrap.len() > 8
            || provider.name.is_empty()
            || provider.name.len() > 64
            || provider.name.chars().any(char::is_control)
            || !names.insert(provider.name.as_str())
        {
            return Err("DoH: нужны уникальное имя и HTTPS URL без пароля/фрагмента".into());
        }
    }
    if config.log_roots.iter().any(|p| !p.is_absolute()) {
        return Err("Каталоги журналов должны быть абсолютными".into());
    }
    for list in [&config.disabled_providers, &config.provider_order] {
        let mut seen = std::collections::HashSet::new();
        if list
            .iter()
            .any(|name| !names.contains(name.as_str()) || !seen.insert(name))
        {
            return Err(
                "Порядок/отключение DNS: неизвестное или повторяющееся имя провайдера".into(),
            );
        }
    }
    if config.disabled_providers.len() == names.len() {
        return Err("Нужен хотя бы один включённый DNS-провайдер. Проверьте doh, extra_udp и disabled_providers в network.json".into());
    }
    Ok(())
}

/// Called before installing the SYSTEM/launchd worker, in the initiating user's context.
pub fn prepare_service() -> Result<(), String> {
    prepare_user()?;
    let dir = directory();
    fs::create_dir_all(super::relay::log_dir()).map_err(|e| e.to_string())?;
    let context = Context {
        directory: dir,
        log_roots: user_log_roots(),
    };
    crate::system::fs_utils::robust_write_file(
        &context_path(),
        &serde_json::to_vec(&context).map_err(|e| e.to_string())?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_config_reads_in_both_new_and_public_schemas() {
        // v2.5.0 accepts only these fields in network.json.
        #[derive(Deserialize, Serialize)]
        #[serde(deny_unknown_fields)]
        struct PublicConfig {
            doh: Vec<DohProvider>,
            extra_udp: Vec<UdpProvider>,
            disabled_providers: Vec<String>,
            provider_order: Vec<String>,
            watch_region_errors: bool,
            log_roots: Vec<PathBuf>,
        }

        let defaults = Config::default();
        let mut public: PublicConfig =
            serde_json::from_value(serde_json::to_value(&defaults).unwrap()).unwrap();
        assert_eq!(public.doh, defaults.doh);
        public.doh.truncate(1);
        let mut migrated: Config =
            serde_json::from_value(serde_json::to_value(&public).unwrap()).unwrap();
        upgrade_builtin_defaults(&mut migrated);
        validate(&migrated).unwrap();
        assert_eq!(migrated.doh, defaults.doh);
        serde_json::from_slice::<PublicConfig>(&serde_json::to_vec(&migrated).unwrap()).unwrap();
        let mut early_dev = serde_json::to_value(&public).unwrap();
        early_dev["provider_defaults_version"] = 2.into();
        let compatible = without_dev_marker(&serde_json::to_vec(&early_dev).unwrap())
            .unwrap()
            .unwrap();
        let restored: PublicConfig = serde_json::from_slice(&compatible).unwrap();
        assert_eq!(restored.doh, public.doh);
        assert_eq!(decode(&compatible).unwrap().doh, public.doh);
        assert!(without_dev_marker(&compatible).unwrap().is_none());
    }

    #[test]
    fn old_provider_settings_upgrade_without_resetting_user_choices() {
        for previous in [
            serde_json::json!(["192.144.59.14", "186.246.49.127"]),
            serde_json::json!(["192.144.59.14", "186.246.49.127", "94.232.43.149"]),
        ] {
            let mut config: Config = serde_json::from_value(serde_json::json!({
                "doh": [{"name": "dns-ai.ru", "url": "https://dns.dns-ai.ru/dns-query", "bootstrap": previous}],
                "provider_order": ["xbox-dns.ru", "comss.one"],
                "disabled_providers": ["xbox-dns.ru", "comss.one"],
                "watch_region_errors": false
            })).unwrap();
            upgrade_builtin_defaults(&mut config);
            assert_eq!(config.doh[0].bootstrap, Config::default().doh[0].bootstrap);
            assert!(config.provider_order.is_empty());
            assert!(config.disabled_providers.is_empty());
            assert!(validate(&config).is_ok());
            let upgraded = serde_json::to_value(&config).unwrap();
            upgrade_builtin_defaults(&mut config);
            assert_eq!(upgraded, serde_json::to_value(&config).unwrap());
        }
        let mut config: Config = serde_json::from_value(serde_json::json!({
            "doh": [{"name": "dns-ai.ru", "url": "https://dns.dns-ai.ru/dns-query", "bootstrap": ["192.144.59.14", "186.246.49.127"]}],
            "provider_order": ["xbox-dns.ru", "comss.one"],
            "disabled_providers": ["xbox-dns.ru", "comss.one"],
            "watch_region_errors": false
        })).unwrap();
        upgrade_builtin_defaults(&mut config);
        assert!(!config.watch_region_errors);
        assert!(config.disabled_providers.is_empty());
        let pool = super::super::resolver_pool::from_config(&config).unwrap();
        assert_eq!(
            pool.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            ["dns-ai.ru", "eu.geohide.ru"]
        );
        config.provider_order = vec!["eu.geohide.ru".into(), "dns-ai.ru".into()];
        let pool = super::super::resolver_pool::from_config(&config).unwrap();
        assert_eq!(
            pool.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            ["eu.geohide.ru", "dns-ai.ru"]
        );
    }

    #[test]
    fn new_doh_is_only_added_to_the_old_unmodified_pool() {
        for edit in [
            "udp_only",
            "custom_bootstrap",
            "disabled",
            "ordered",
            "custom_udp",
            "current",
        ] {
            let mut config = Config::default();
            config.provider_defaults_version = 0;
            config.doh.truncate(1);
            match edit {
                "udp_only" => {
                    config.doh.clear();
                    config.extra_udp.push(UdpProvider {
                        name: "my-udp".into(),
                        addresses: vec!["192.0.2.53".parse().unwrap()],
                    });
                }
                "custom_bootstrap" => config.doh[0].bootstrap.clear(),
                "disabled" => config.disabled_providers.push("geohide.ru".into()),
                "ordered" => config.provider_order.push("geohide.ru".into()),
                "custom_udp" => config.extra_udp.push(UdpProvider {
                    name: "custom".into(),
                    addresses: vec!["192.0.2.10".parse().unwrap()],
                }),
                _ => config.provider_defaults_version = 2,
            }
            let before = config.doh.clone();
            upgrade_builtin_defaults(&mut config);
            assert_eq!(config.doh, before, "{edit}");
            validate(&config).unwrap();
        }
    }

    #[test]
    fn removed_default_geohide_is_pruned_from_saved_provider_lists() {
        let mut config = Config {
            disabled_providers: vec!["geohide.ru".into()],
            provider_order: vec![
                "geohide.ru".into(),
                "eu.geohide.ru".into(),
                "dns-ai.ru".into(),
            ],
            ..Config::default()
        };
        upgrade_builtin_defaults(&mut config);
        assert!(config.disabled_providers.is_empty());
        let pool = super::super::resolver_pool::from_config(&config).unwrap();
        assert_eq!(
            pool.iter()
                .map(|provider| provider.name.as_str())
                .collect::<Vec<_>>(),
            ["eu.geohide.ru", "dns-ai.ru"]
        );
    }

    #[test]
    fn old_implicit_udp_only_requires_an_explicit_provider_after_removal() {
        let mut config: Config = serde_json::from_str(r#"{"doh":[]}"#).unwrap();
        upgrade_builtin_defaults(&mut config);
        let error = validate(&config).unwrap_err();
        assert!(error.contains("удалите пустое поле doh"));
        assert!(error.contains("extra_udp"));
        assert!(config.doh.is_empty());
        config.extra_udp.push(UdpProvider {
            name: "custom".into(),
            addresses: vec!["192.0.2.53".parse().unwrap(), "192.0.2.54".parse().unwrap()],
        });
        let pool = super::super::resolver_pool::from_config(&config).unwrap();
        assert_eq!(pool[0].udp_addresses(), config.extra_udp[0].addresses);
    }

    #[test]
    fn retired_provider_names_preserve_explicit_custom_definitions() {
        for name in ["xbox-dns.ru", "comss.one", "geohide.ru"] {
            for use_doh in [false, true] {
                let mut config = Config::default();
                if use_doh {
                    config.doh.push(DohProvider {
                        name: name.into(),
                        url: "https://resolver.example/dns-query".into(),
                        bootstrap: vec!["192.0.2.10".parse().unwrap()],
                    });
                } else {
                    config.extra_udp.push(UdpProvider {
                        name: name.into(),
                        addresses: vec!["192.0.2.10".parse().unwrap()],
                    });
                }
                config.provider_order = vec![name.into()];
                config.disabled_providers = vec![name.into()];
                let before = serde_json::to_value(&config).unwrap();
                upgrade_builtin_defaults(&mut config);
                assert_eq!(before, serde_json::to_value(&config).unwrap());
                assert!(validate(&config).is_ok());
            }
        }
    }

    #[test]
    fn provider_upgrade_keeps_custom_endpoints_and_rejects_unknown_names() {
        let mut config = Config::default();
        config.doh[0].bootstrap = vec!["192.0.2.9".parse().unwrap()];
        config.extra_udp.push(UdpProvider {
            name: "xbox-dns.ru".into(),
            addresses: vec!["192.0.2.10".parse().unwrap()],
        });
        config.disabled_providers = vec!["xbox-dns.ru".into()];
        upgrade_builtin_defaults(&mut config);
        assert_eq!(
            config.doh[0].bootstrap,
            vec!["192.0.2.9".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(config.disabled_providers, ["xbox-dns.ru"]);
        assert!(validate(&config).is_ok());
        config.provider_order = vec!["typo".into()];
        upgrade_builtin_defaults(&mut config);
        assert!(validate(&config).is_err());
        config.doh[0].url = "https://custom.test/dns-query".into();
        config.doh[0].bootstrap = vec![
            "192.144.59.14".parse().unwrap(),
            "186.246.49.127".parse().unwrap(),
        ];
        upgrade_builtin_defaults(&mut config);
        assert_eq!(config.doh[0].bootstrap.len(), 2);
        // A list the user edited is custom even when it starts from the old defaults.
        config.doh[0].url = "https://dns.dns-ai.ru/dns-query".into();
        config.doh[0].bootstrap = vec![
            "192.144.59.14".parse().unwrap(),
            "186.246.49.127".parse().unwrap(),
            "94.232.43.149".parse().unwrap(),
            "192.0.2.7".parse().unwrap(),
        ];
        upgrade_builtin_defaults(&mut config);
        assert_eq!(config.doh[0].bootstrap.len(), 4);
    }

    #[test]
    fn stock_log_roots_gain_the_cli_log_directory_and_custom_lists_are_kept() {
        let stock: Vec<PathBuf> = [
            "/a/Antigravity/logs",
            "/a/Antigravity IDE/logs",
            "/h/cli/log",
        ]
        .map(PathBuf::from)
        .into();
        let cli = PathBuf::from("/h/cli/log");
        let mut old = stock[..2].to_vec();
        upgrade_log_roots(&mut old, &stock, &cli);
        assert_eq!(old, stock);
        upgrade_log_roots(&mut old, &stock, &cli);
        assert_eq!(old, stock, "already upgraded lists are unchanged");
        let mut custom = vec![PathBuf::from("/custom/logs")];
        upgrade_log_roots(&mut custom, &stock, &cli);
        assert_eq!(custom, vec![PathBuf::from("/custom/logs")]);
        let mut empty = Vec::new();
        upgrade_log_roots(&mut empty, &stock, &cli);
        assert!(empty.is_empty(), "an explicitly empty list stays empty");
        assert!(Config::default()
            .log_roots
            .iter()
            .any(|root| root.ends_with("log")
                && root
                    .parent()
                    .is_some_and(|p| p.ends_with("antigravity-cli"))));
    }

    #[test]
    fn config_rejects_plaintext_credentials_duplicates_and_relative_log_roots() {
        let mut c = Config::default();
        assert!(validate(&c).is_ok());
        for bad in [
            "http://resolver.test/dns-query",
            "https://user:secret@resolver.test/dns-query",
        ] {
            c.doh[0].url = bad.into();
            assert!(validate(&c).is_err());
        }
        c = Config::default();
        c.doh.push(c.doh[0].clone());
        assert!(validate(&c).is_err());
        c = Config::default();
        c.log_roots = vec!["relative".into()];
        assert!(validate(&c).is_err());
    }
}
