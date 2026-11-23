//! One configuration snapshot for both UDP and RFC 8484 exchanges.
use super::{client, config, dns_https};
use std::{
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::{mpsc, Arc, Mutex},
    time::{Duration, SystemTime},
};

pub const UDP_TIMEOUT: Duration = Duration::from_millis(800);
pub const BUDGET: Duration = Duration::from_millis(2800);

#[derive(Clone, Debug)]
pub enum Transport {
    Udp(Vec<Ipv4Addr>),
    Doh(config::DohProvider),
}

#[derive(Clone, Debug)]
pub struct Provider {
    pub name: String,
    pub transport: Transport,
}

impl Provider {
    pub fn kind(&self) -> &'static str {
        match self.transport {
            Transport::Udp(_) => "udp",
            Transport::Doh(_) => "doh",
        }
    }

    pub fn udp_addresses(&self) -> &[Ipv4Addr] {
        match &self.transport {
            Transport::Udp(ips) => ips,
            Transport::Doh(_) => &[],
        }
    }

    pub fn query(&self, query: &[u8], interface: u32) -> Option<(Vec<u8>, Option<Ipv4Addr>)> {
        match &self.transport {
            Transport::Doh(provider) => dns_https::query(provider, query, interface)
                .ok()
                .map(|reply| (reply, None)),
            Transport::Udp(ips) => {
                let (tx, rx) = mpsc::channel();
                for ip in ips {
                    let ip = *ip;
                    let query = query.to_vec();
                    let tx = tx.clone();
                    std::thread::spawn(move || {
                        if let Ok(reply) = client::query_raw_via(&query, ip, interface, UDP_TIMEOUT)
                        {
                            if client::is_successful_response(&reply) {
                                let _ = tx.send((reply, Some(ip)));
                            }
                        }
                    });
                }
                drop(tx);
                let deadline = std::time::Instant::now() + UDP_TIMEOUT + Duration::from_millis(50);
                let wants_address = matches!(client::question_type(query), Some(1 | 28));
                let mut empty = None;
                while let Ok(result) =
                    rx.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                {
                    if !wants_address || !client::answer_addrs(&result.0).is_empty() {
                        return Some(result);
                    }
                    empty = Some(result);
                }
                empty
            }
        }
    }
}

pub fn from_config(config: &config::Config) -> Result<Vec<Provider>, String> {
    config::validate(config)?;
    let mut providers: Vec<_> = config
        .extra_udp
        .iter()
        .map(|p| Provider {
            name: p.name.clone(),
            transport: Transport::Udp(p.addresses.clone()),
        })
        .collect();
    providers.extend(config.doh.iter().map(|p| Provider {
        name: p.name.clone(),
        transport: Transport::Doh(p.clone()),
    }));
    providers.retain(|p| !config.disabled_providers.contains(&p.name));
    // dns-ai leads by default, including when an old config lists only UDP
    // providers. An explicit position for dns-ai remains the user's choice.
    let explicit_lead = config.provider_order.iter().any(|name| name == "dns-ai.ru");
    providers.sort_by_key(|p| {
        if !explicit_lead && p.name == "dns-ai.ru" {
            return 0;
        }
        config
            .provider_order
            .iter()
            .position(|name| name == &p.name)
            .map(|position| position + 1)
            .unwrap_or(usize::MAX)
    });
    Ok(providers)
}

pub fn load() -> Result<Vec<Provider>, String> {
    from_config(&config::load()?)
}

/// A validated pool and the identity that DNS cache entries are keyed by.
pub struct Snapshot {
    pub providers: Vec<Provider>,
    pub fingerprint: Arc<str>,
}

impl Snapshot {
    pub fn new(providers: Vec<Provider>) -> Self {
        let fingerprint = format!("{providers:?}").into();
        Self {
            providers,
            fingerprint,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    len: u64,
    modified: Option<SystemTime>,
}

fn file_stamp(path: &Path) -> Option<FileStamp> {
    let metadata = std::fs::metadata(path).ok()?;
    Some(FileStamp {
        len: metadata.len(),
        modified: metadata.modified().ok(),
    })
}

struct CachedSnapshot {
    context: Option<FileStamp>,
    config_path: PathBuf,
    config: Option<FileStamp>,
    snapshot: Arc<Snapshot>,
}

static SNAPSHOT: Mutex<Option<CachedSnapshot>> = Mutex::new(None);

/// The relay resolves every DNS packet through the pool. Reuse the parsed
/// configuration while network.json and the relay context are unchanged: two
/// metadata calls replace two file reads, JSON parsing and validation.
pub fn load_shared() -> Result<Arc<Snapshot>, String> {
    cached_snapshot(&SNAPSHOT, &config::context_path(), config::path, load)
}

fn cached_snapshot(
    cache: &Mutex<Option<CachedSnapshot>>,
    context_path: &Path,
    config_path: impl FnOnce() -> PathBuf,
    load: impl FnOnce() -> Result<Vec<Provider>, String>,
) -> Result<Arc<Snapshot>, String> {
    let context = file_stamp(context_path);
    let mut cached = cache.lock().map_err(|e| e.to_string())?;
    if let Some(entry) = cached.as_ref() {
        if entry.context == context && file_stamp(&entry.config_path) == entry.config {
            return Ok(Arc::clone(&entry.snapshot));
        }
    }
    // Stamps are taken before reading, so a write during the reload is seen
    // as a change by the next lookup instead of hiding behind the cache.
    let config_path = config_path();
    let config_stamp = file_stamp(&config_path);
    let snapshot = Arc::new(Snapshot::new(load()?));
    *cached = Some(CachedSnapshot {
        context,
        config_path,
        config: config_stamp,
        snapshot: Arc::clone(&snapshot),
    });
    Ok(snapshot)
}

pub fn forget_shared() {
    if let Ok(mut cached) = SNAPSHOT.lock() {
        *cached = None;
    }
}

#[cfg(windows)]
pub fn bootstrap_v4() -> Result<Vec<Ipv4Addr>, String> {
    Ok(load()?
        .into_iter()
        .flat_map(|p| match p.transport {
            Transport::Udp(_) => vec![],
            Transport::Doh(p) => p
                .bootstrap
                .into_iter()
                .filter_map(|ip| match ip {
                    std::net::IpAddr::V4(ip) => Some(ip),
                    _ => None,
                })
                .collect(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn relay_pool_is_reused_until_network_json_or_context_changes() {
        let dir = tempfile::tempdir().unwrap();
        let context = dir.path().join("network-user.json");
        let config_path = dir.path().join("network.json");
        std::fs::write(&context, b"{}").unwrap();
        let cache = Mutex::new(None);
        let loads = std::cell::Cell::new(0);
        let lookup = || {
            cached_snapshot(
                &cache,
                &context,
                || config_path.clone(),
                || {
                    loads.set(loads.get() + 1);
                    from_config(&config::Config::default())
                },
            )
            .unwrap()
        };
        let first = lookup();
        let second = lookup();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(loads.get(), 1);
        std::fs::write(&config_path, b"{\"doh\":[]}").unwrap();
        lookup();
        assert_eq!(loads.get(), 2);
        lookup();
        assert_eq!(loads.get(), 2);
        std::fs::write(&config_path, b"{\"doh\":[], \"extra_udp\":[]}").unwrap();
        lookup();
        assert_eq!(loads.get(), 3);
        std::fs::write(&context, b"{\"directory\":\"x\"}").unwrap();
        lookup();
        assert_eq!(loads.get(), 4);
        assert!(cached_snapshot(
            &cache,
            &context,
            || config_path.clone(),
            || Err("bad".into())
        )
        .is_ok());
        std::fs::remove_file(&config_path).unwrap();
        assert!(cached_snapshot(
            &cache,
            &context,
            || config_path.clone(),
            || Err("bad".into())
        )
        .is_err());
        assert_eq!(loads.get(), 4);
    }
    #[test]
    fn configured_transports_order_and_disabling_are_shared() {
        let mut c = config::Config::default();
        c.extra_udp.push(config::UdpProvider {
            name: "custom".into(),
            addresses: vec!["192.0.2.1".parse().unwrap()],
        });
        c.disabled_providers = vec!["eu.geohide.ru".into()];
        c.provider_order = vec!["dns-ai.ru".into(), "custom".into()];
        let pool = from_config(&c).unwrap();
        assert_eq!(
            pool.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            ["dns-ai.ru", "custom"]
        );
        assert!(
            pool[0].udp_addresses().is_empty(),
            "DoH bootstrap is never a UDP nameserver"
        );
        assert_eq!(
            pool[1].udp_addresses(),
            ["192.0.2.1".parse::<Ipv4Addr>().unwrap()]
        );
        c.provider_order.push("missing".into());
        assert!(from_config(&c).is_err());
    }
    #[test]
    fn duplicate_provider_names_and_all_disabled_are_invalid() {
        let mut c = config::Config::default();
        c.doh[0].name = c.doh[1].name.clone();
        assert!(from_config(&c).is_err());
        c = config::Config::default();
        c.disabled_providers = from_config(&c)
            .unwrap()
            .iter()
            .map(|p| p.name.clone())
            .collect();
        assert!(from_config(&c).is_err());
        c.disabled_providers.retain(|name| name != "dns-ai.ru");
        let pool = from_config(&c).unwrap();
        assert_eq!(pool.len(), 1);
        assert_eq!(pool[0].kind(), "doh");
    }
    #[test]
    fn configured_doh_endpoint_is_reached_but_untrusted_tls_is_rejected() {
        let (addr, worker) = super::super::health::tests::server(
            b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
            Duration::ZERO,
        );
        let mut config = config::Config::default();
        config.doh.truncate(1);
        config.doh[0].url = format!("https://localhost:{}/dns-query", addr.port());
        config.doh[0].bootstrap = vec![addr.ip()];
        let pool = from_config(&config).unwrap();
        assert_eq!(pool.len(), 1);
        assert!(pool[0]
            .query(&client::build_query("example.test", 3), 0)
            .is_none());
        worker.join().unwrap();
    }
}
