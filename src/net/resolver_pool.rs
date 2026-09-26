//! One configuration snapshot for both UDP and RFC 8484 exchanges.
use super::{client, config, dns_https, resolvers};
use std::{net::Ipv4Addr, sync::mpsc, time::Duration};

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
    let mut providers: Vec<_> = resolvers::PROVIDERS
        .iter()
        .map(|p| Provider {
            name: p.name.into(),
            transport: Transport::Udp(p.v4.iter().filter_map(|s| s.parse().ok()).collect()),
        })
        .collect();
    providers.extend(config.extra_udp.iter().map(|p| Provider {
        name: p.name.clone(),
        transport: Transport::Udp(p.addresses.clone()),
    }));
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
    fn configured_transports_order_and_disabling_are_shared() {
        let mut c = config::Config::default();
        c.extra_udp.push(config::UdpProvider {
            name: "custom".into(),
            addresses: vec!["192.0.2.1".parse().unwrap()],
        });
        c.disabled_providers = vec!["comss.one".into()];
        c.provider_order = vec!["dns-ai.ru".into(), "custom".into()];
        let pool = from_config(&c).unwrap();
        assert_eq!(
            pool.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            ["dns-ai.ru", "custom", "geohide.ru"]
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
    fn names_cannot_shadow_builtins_and_all_disabled_is_invalid() {
        let mut c = config::Config::default();
        c.doh[0].name = "geohide.ru".into();
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
        config.disabled_providers = resolvers::PROVIDERS
            .iter()
            .map(|p| p.name.to_string())
            .collect();
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
