#![allow(dead_code)]

use std::process::Command;
use crate::system::process::no_window;

pub struct Egress {
    pub if_index: u32,
    pub vpn_active: bool,
}

pub const XBOX_NS_V4: &[&str] = &["111.88.96.50", "176.108.243.68"];
pub const XBOX_NS_V6: &[&str] = &["2a00:ab00:533:6::100", "2a00:ab00:533:6::101"];

pub const LEGACY_PINNED_PREFIXES: &[&str] = &[
    "178.130.155.0/24",
    "185.158.113.0/24",
    "185.158.114.0/24",
    "82.148.16.0/24",
    "82.148.17.0/24",
    "82.148.18.0/24",
    "82.148.19.0/24",
];

pub fn detect_fast() -> Option<Egress> {
    detect()
}

pub fn detect() -> Option<Egress> {
    #[cfg(target_os = "windows")]
    {
        #[link(name = "iphlpapi")]
        extern "system" {
            fn GetBestInterface(dwDestAddr: u32, pdwBestIfIndex: *mut u32) -> u32;
        }

        let mut if_index: u32 = 0;
        let dest: u32 = u32::from_ne_bytes([8, 8, 8, 8]);
        let res = unsafe { GetBestInterface(dest, &mut if_index) };
        if res == 0 && if_index > 0 {
            return Some(Egress {
                if_index,
                vpn_active: false,
            });
        }
        None
    }

    #[cfg(target_os = "macos")]
    {
        let out = Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .ok()?;
        let txt = String::from_utf8_lossy(&out.stdout);

        let mut if_name = String::new();
        for line in txt.lines() {
            let l = line.trim();
            if l.starts_with("interface:") {
                if_name = l.trim_start_matches("interface:").trim().to_string();
                break;
            }
        }

        if if_name.is_empty() {
            return None;
        }

        let vpn = if_name.starts_with("utun") || if_name.starts_with("ppp");
        let idx = unsafe {
            let c_name = std::ffi::CString::new(if_name.as_str()).ok()?;
            libc::if_nametoindex(c_name.as_ptr())
        };

        if idx > 0 {
            Some(Egress {
                if_index: idx,
                vpn_active: vpn,
            })
        } else {
            None
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    None
}

#[cfg(target_os = "windows")]
fn is_vpn_ip_or_name(ip: &str) -> bool {
    ip.starts_with("10.") || ip.starts_with("192.168.254.") || ip.starts_with("198.18.")
}

#[cfg(target_os = "windows")]
fn if_ip_to_index(ip: &str) -> Option<u32> {
    let out = no_window(&mut Command::new("powershell"))
        .args([
            "-NoProfile",
            "-Command",
            &format!("(Get-NetIPAddress -IPAddress '{}' -ErrorAction SilentlyContinue).InterfaceIndex", ip),
        ])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    s.parse::<u32>().ok()
}

pub fn remove_legacy_routes() {
    #[cfg(target_os = "windows")]
    {
        for pfx in LEGACY_PINNED_PREFIXES {
            let ip_only = pfx.split('/').next().unwrap_or(pfx);
            let _ = no_window(&mut Command::new("route"))
                .args(["delete", ip_only])
                .output();
        }
    }
}
