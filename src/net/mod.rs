pub mod client;
pub mod doh;
pub mod egress;
pub mod health;
pub mod hosts;
pub mod nrpt;
pub mod provider;
pub mod proxy;
pub mod rank;
pub mod relay;
pub mod resolvers;
pub mod routes;
pub mod socket;

pub use relay::{detach_console, log_fatal, run as run_dns_relay};

use std::process::Command;
use std::thread;
use std::time::Duration;
use crate::system::process::no_window;
use provider::{nrpt_domains, GEOHIDE_PROXY_V4, NRPT_AGENT, NRPT_STUDIO, SUBSTITUTION_CANARIES, NRPT_TAG};
use relay::{LISTEN_IP, LISTEN_PORT};
use routes::{add_static_routes, remove_static_routes, restore_ipv4_preference, set_ipv4_preference};

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

pub fn apply_dns_rules() -> Result<String, String> {
    fn step(msg: &str) {
        println!("  \x1b[90m… {}\x1b[0m", msg);
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }

    step("очистка старых DNS-правил");
    remove_dns_rules();

    let names = nrpt_domains();
    step("перехват чужих NRPT / отключение Auto-DoH");
    let _ = nrpt::take_over_conflicting_rules(&names);
    crate::net::doh::disable_system_doh();

    step("оптимизация TCP-стека (TCP Auto-Tuning normal, 512KB buffers)");
    let _ = crate::net::socket::tune_os_network_stack();

    step("поиск физического адаптера (не VPN)");
    let egress = crate::net::egress::detect();
    let if_index = egress.as_ref().map(|e| e.if_index).unwrap_or(0);
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
        step("маршруты SmartDNS через физический адаптер");
        set_ipv4_preference();
        add_static_routes();
        thread::sleep(Duration::from_millis(400));
    }

    let mut sub_notes = Vec::new();
    let mut pending: Vec<(String, Vec<&'static str>)> = Vec::new();
    step("проверка подмены по каждому хосту");
    for name in NRPT_AGENT {
        let host = name.trim_start_matches('.');
        let subs = resolvers::substituting_addrs(host, if_index);
        if subs.is_empty() {
            sub_notes.push(format!("{host}: нет"));
            pending.push(((*name).to_string(), GEOHIDE_PROXY_V4.to_vec()));
        } else {
            sub_notes.push(format!("{host}: {}", subs.join(", ")));
            pending.push(((*name).to_string(), subs));
        }
    }
    let mut studio_subs: Vec<&'static str> = Vec::new();
    for name in SUBSTITUTION_CANARIES {
        let host = name.trim_start_matches('.');
        for s in resolvers::substituting_addrs(host, if_index) {
            if !studio_subs.contains(&s) {
                studio_subs.push(s);
            }
        }
    }
    if studio_subs.is_empty() {
        sub_notes.push("Studio/Gemini: SmartDNS пропущен, используем Geohide SNI прокси".into());
        for name in NRPT_STUDIO {
            pending.push(((*name).to_string(), GEOHIDE_PROXY_V4.to_vec()));
        }
    } else {
        sub_notes.push(format!("Studio/Gemini: {}", studio_subs.join(", ")));
        for name in NRPT_STUDIO {
            pending.push(((*name).to_string(), studio_subs.clone()));
        }
    }

    let mut relay_ok = false;
    let mut relay_note = String::new();
    #[cfg(target_os = "windows")]
    {
        step("запуск локального релея 127.0.0.53:53");
        match crate::system::service::enable() {
            Ok(()) => {
                for _ in 0..40 {
                    if crate::system::service::is_running() {
                        relay_ok = true;
                        break;
                    }
                    thread::sleep(Duration::from_millis(100));
                }
                if !relay_ok {
                    relay_note = "релей не поднялся за 4с, NRPT напрямую на SmartDNS".into();
                }
            }
            Err(e) => {
                relay_note = format!("релей не установлен ({e}), NRPT напрямую на SmartDNS");
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        // No resident daemon: /etc/resolver talks to SmartDNS directly.
        // Lid close / sleep then costs nothing (no wake, no polling).
        step("DNS через /etc/resolver (без фонового процесса)");
        let _ = crate::system::service::disable();
    }

    let mut rules: Vec<(String, String)> = Vec::new();
    for (name, subs) in &pending {
        rules.push((name.clone(), assemble_nameservers(relay_ok, subs)));
    }

    #[cfg(target_os = "windows")]
    {
        step("запись NRPT");
        crate::net::nrpt::apply_nrpt_rules_direct(&rules, NRPT_TAG, "Antigravity DNS");
        let _ = no_window(&mut Command::new("ipconfig")).arg("/flushdns").output();
    }

    #[cfg(target_os = "macos")]
    {
        let res_dir = std::path::Path::new("/etc/resolver");
        if !res_dir.exists() {
            let _ = std::fs::create_dir_all(res_dir);
        }
        for (domain, csv) in &rules {
            let clean_domain = domain.trim_start_matches('.');
            let file_path = res_dir.join(clean_domain);
            let mut content = format!("# ANTIGRAVITY-BYPASS-RUSSIA\n# {}\n", clean_domain);
            for ip in csv.split(';').filter(|s| !s.is_empty()) {
                content.push_str(&format!("nameserver {}\n", ip));
            }
            content.push_str("port 53\nsearch_order 1\ntimeout 2\n");
            let _ = std::fs::write(&file_path, content);
        }
        let _ = Command::new("dscacheutil").arg("-flushcache").output();
        let _ = Command::new("killall").args(["-HUP", "mDNSResponder"]).output();
    }

    step("ранжирование прокси Cloud Code (быстрый первый, остальные запас)");
    #[cfg(target_os = "windows")]
    {
        let ranked = crate::net::rank::rescan_agent(if_index);
        for note in crate::net::rank::format_notes(&ranked) {
            sub_notes.push(note);
        }
    }

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
    Ok(msg)
}

pub fn remove_dns_rules() {
    let _ = crate::system::service::disable();
    crate::net::egress::remove_legacy_routes();
    let _ = crate::net::hosts::remove_entries();
    crate::net::doh::restore_system_doh();
    let _ = crate::net::socket::restore_os_network_stack();

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
