use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::Command;

use crate::net::egress::detect_physical;
use crate::net::resolvers::all_provider_v4;
use crate::system::process::no_window;

pub fn set_ipv4_preference() {
    #[cfg(target_os = "windows")]
    {
        let _ = no_window(&mut Command::new("netsh"))
            .args(["interface", "ipv6", "set", "prefixpolicy", "::ffff:0:0/96", "46", "4"])
            .output();
    }
}

pub fn restore_ipv4_preference() {
    #[cfg(target_os = "windows")]
    {
        let _ = no_window(&mut Command::new("netsh"))
            .args(["interface", "ipv6", "set", "prefixpolicy", "::ffff:0:0/96", "35", "4"])
            .output();
    }
}

fn extra_path() -> PathBuf {
    crate::net::relay::log_dir().join("proxy_host_routes.conf")
}

fn load_extra() -> Vec<Ipv4Addr> {
    let Ok(text) = fs::read_to_string(extra_path()) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|l| l.trim().parse::<Ipv4Addr>().ok())
        .collect()
}

fn save_extra(ips: &[Ipv4Addr]) {
    let dir = crate::net::relay::log_dir();
    let _ = fs::create_dir_all(&dir);
    let body = ips
        .iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    let _ = fs::write(extra_path(), body);
}

#[cfg(target_os = "windows")]
fn pin_via_physical(ips: &[String]) {
    let Some((if_index, gateway)) = detect_physical() else {
        return;
    };
    let if_index = if_index.to_string();
    for ip in ips {
        let _ = no_window(&mut Command::new("route"))
            .args(["delete", ip])
            .output();
        let _ = no_window(&mut Command::new("route"))
            .args([
                "add",
                ip,
                "mask",
                "255.255.255.255",
                &gateway,
                "metric",
                "1",
                "if",
                &if_index,
            ])
            .output();
    }
}

/// /32 through the physical NIC for SmartDNS *and* the ranked Cloud Code
/// proxy IPs, so HTTPS does not follow a full-tunnel VPN default route.
pub fn sync_physical_hosts(extra: &[Ipv4Addr]) {
    #[cfg(not(target_os = "windows"))]
    {
        let _ = extra;
        return;
    }
    #[cfg(target_os = "windows")]
    {
        let mut extra_u: Vec<Ipv4Addr> = Vec::new();
        for ip in extra {
            if !extra_u.contains(ip) {
                extra_u.push(*ip);
            }
        }
        let old = load_extra();
        for ip in &old {
            if !extra_u.contains(ip) && !all_provider_v4().iter().any(|s| s.parse::<Ipv4Addr>().ok() == Some(*ip)) {
                let _ = no_window(&mut Command::new("route"))
                    .args(["delete", &ip.to_string()])
                    .output();
            }
        }
        save_extra(&extra_u);

        let mut all: Vec<String> = all_provider_v4().into_iter().map(|s| s.to_string()).collect();
        for ip in extra_u {
            let s = ip.to_string();
            if !all.contains(&s) {
                all.push(s);
            }
        }
        pin_via_physical(&all);
    }
}

pub fn add_static_routes() {
    #[cfg(target_os = "windows")]
    {
        let ips: Vec<String> = all_provider_v4().into_iter().map(|s| s.to_string()).collect();
        pin_via_physical(&ips);
    }
}

pub fn remove_static_routes() {
    #[cfg(target_os = "windows")]
    {
        for ip in all_provider_v4() {
            let _ = no_window(&mut Command::new("route"))
                .args(["delete", ip])
                .output();
        }
        for ip in load_extra() {
            let _ = no_window(&mut Command::new("route"))
                .args(["delete", &ip.to_string()])
                .output();
        }
        let _ = fs::remove_file(extra_path());
    }
}
