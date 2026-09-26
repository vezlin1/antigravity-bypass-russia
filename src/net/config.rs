//! User-owned network configuration shared with the elevated DNS worker.
use serde::{Deserialize, Serialize};
use std::{fs, net::IpAddr, path::PathBuf};

#[derive(Clone, Debug, Deserialize, Serialize)]
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
            // Public connection settings: https://dns-ai.ru/ (2026-09-08).
            doh: vec![DohProvider {
                name: "dns-ai.ru".into(),
                url: "https://dns.dns-ai.ru/dns-query".into(),
                bootstrap: vec![
                    "192.144.59.14".parse().unwrap(),
                    "186.246.49.127".parse().unwrap(),
                ],
            }],
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
    if std::env::args().any(|arg| arg == crate::system::service::FORWARDER_FLAG) {
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
        .collect()
}

fn context_path() -> PathBuf {
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
    if std::env::args().any(|arg| arg == crate::system::service::FORWARDER_FLAG) {
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
    let config: Config = match fs::read(path()) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| format!("network.json: {e}"))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Config::default(),
        Err(e) => return Err(format!("network.json: {e}")),
    };
    validate(&config)?;
    Ok(config)
}

pub fn validate(config: &Config) -> Result<(), String> {
    if config.doh.len() > 8 || config.extra_udp.len() > 8 || config.log_roots.len() > 16 {
        return Err("Слишком много провайдеров/каталогов в network.json".into());
    }
    let mut names: std::collections::HashSet<&str> =
        super::resolvers::PROVIDERS.iter().map(|p| p.name).collect();
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
        return Err("Нужен хотя бы один включённый DNS-провайдер".into());
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
