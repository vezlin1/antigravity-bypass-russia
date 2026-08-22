#![allow(unused_imports, dead_code)]

pub mod client;
pub mod egress;
pub mod health;
pub mod hosts;
pub mod nrpt;
pub mod provider;
pub mod relay;
pub mod routes;
pub mod socket;

pub use client::{build_query, parse_a_records, query_raw_via, resolve_a_via};
pub use egress::{detect as detect_egress, remove_legacy_routes, Egress};
pub use health::test_google_connectivity;
pub use hosts::{hosts_path, remove_entries as remove_hosts_entries, write_entries as write_hosts_entries};
pub use nrpt::{get_nrpt_status_info, take_over_conflicting_rules};
pub use provider::{DnsProvider, ALL_DNS_IPS, NRPT_DOMAINS, NRPT_TAG};
pub use relay::{
    detach_console, load_upstream_servers, log_dir, log_fatal, log_path, run as run_dns_relay,
    save_upstream_config, LISTEN_IP, LISTEN_PORT,
};
pub use routes::{
    add_static_routes, remove_static_routes, restore_ipv4_preference, set_ipv4_preference,
};

use std::process::Command;
use crate::system::process::no_window;

pub fn apply_dns_rules(provider: &DnsProvider) -> Result<(), String> {
    apply_dns_rules_advanced(provider, false)
}

pub fn apply_dns_rules_advanced(provider: &DnsProvider, enable_relay: bool) -> Result<(), String> {
    remove_dns_rules();

    let _servers_arg = provider.to_nameservers_arg(enable_relay);
    save_upstream_config(&provider.server_ips());

    if enable_relay {
        crate::system::service::enable()?;
    }

    #[cfg(target_os = "windows")]
    {
        set_ipv4_preference();
        add_static_routes(provider);

        let servers_csv = _servers_arg.replace(',', ";");
        crate::net::nrpt::apply_nrpt_rules_direct(&servers_csv, NRPT_DOMAINS, NRPT_TAG, "Antigravity DNS");
        let _ = no_window(&mut Command::new("ipconfig")).arg("/flushdns").output();
    }

    #[cfg(target_os = "macos")]
    {
        let res_dir = std::path::Path::new("/etc/resolver");
        if !res_dir.exists() {
            let _ = std::fs::create_dir_all(res_dir);
        }
        let ips = if enable_relay {
            vec!["127.0.0.1".to_string()]
        } else {
            provider.server_ips()
        };

        for d in NRPT_DOMAINS {
            let domain_name = d.trim_start_matches('.');
            let file_path = res_dir.join(domain_name);
            let mut content = format!("# ANTIGRAVITY-BYPASS-RUSSIA\n# {}\n", domain_name);
            for ip in &ips {
                content.push_str(&format!("nameserver {}\n", ip));
            }
            content.push_str("port 53\nsearch_order 1\ntimeout 2\n");
            let _ = std::fs::write(&file_path, content);
        }

        let _ = Command::new("dscacheutil").arg("-flushcache").output();
        let _ = Command::new("killall").args(["-HUP", "mDNSResponder"]).output();
    }

    Ok(())
}

pub fn remove_dns_rules() {
    let _ = crate::system::service::disable();
    remove_legacy_routes();
    let _ = remove_hosts_entries();

    #[cfg(target_os = "windows")]
    {
        restore_ipv4_preference();
        remove_static_routes();
        crate::net::nrpt::native_remove_nrpt_rules();
        let _ = no_window(&mut Command::new("ipconfig")).arg("/flushdns").output();
    }

    #[cfg(target_os = "macos")]
    {
        let res_dir = std::path::Path::new("/etc/resolver");
        if res_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(res_dir) {
                for entry in entries.flatten() {
                    let file_path = entry.path();
                    if file_path.is_file() {
                        if let Ok(c) = std::fs::read_to_string(&file_path) {
                            if c.contains("# ANTIGRAVITY-BYPASS-RUSSIA") {
                                let _ = std::fs::remove_file(file_path);
                            }
                        }
                    }
                }
            }
        }
        let _ = Command::new("dscacheutil").arg("-flushcache").output();
        let _ = Command::new("killall").args(["-HUP", "mDNSResponder"]).output();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_and_remove_rules() {
        let res = apply_dns_rules(&DnsProvider::XboxDns);
        assert!(res.is_ok(), "apply_dns_rules failed: {:?}", res);
    }
}
