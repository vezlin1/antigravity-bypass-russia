use std::process::Command;
use crate::net::provider::{DnsProvider, ALL_DNS_IPS};
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

pub fn add_static_routes(provider: &DnsProvider) {
    #[cfg(not(target_os = "windows"))]
    let _ = provider;
    #[cfg(target_os = "windows")]
    {
        #[repr(C)]
        struct MibIpForwardRow {
            dw_forward_dest: u32,
            dw_forward_mask: u32,
            dw_forward_policy: u32,
            dw_forward_next_hop: u32,
            dw_forward_if_index: u32,
            dw_forward_type: u32,
            dw_forward_proto: u32,
            dw_forward_age: u32,
            dw_forward_next_hop_as: u32,
            dw_forward_metric1: u32,
            dw_forward_metric2: u32,
            dw_forward_metric3: u32,
            dw_forward_metric4: u32,
            dw_forward_metric5: u32,
        }

        #[link(name = "iphlpapi")]
        extern "system" {
            fn GetBestRoute(dwDestAddr: u32, dwSourceAddr: u32, pBestRoute: *mut MibIpForwardRow) -> u32;
        }

        let mut row: MibIpForwardRow = unsafe { std::mem::zeroed() };
        let dest: u32 = u32::from_ne_bytes([8, 8, 8, 8]);
        let res = unsafe { GetBestRoute(dest, 0, &mut row) };
        if res != 0 {
            return;
        }

        let gw = row.dw_forward_next_hop.to_ne_bytes();
        if gw == [0, 0, 0, 0] {
            return;
        }
        let gateway = format!("{}.{}.{}.{}", gw[0], gw[1], gw[2], gw[3]);
        let if_index = row.dw_forward_if_index;

        let mut ips = provider.server_ips();
        for &static_ip in ALL_DNS_IPS {
            if !ips.contains(&static_ip.to_string()) {
                ips.push(static_ip.to_string());
            }
        }

        for ip in ips {
            let _ = no_window(&mut Command::new("route"))
                .args(["delete", &ip])
                .output();
            let _ = no_window(&mut Command::new("route"))
                .args(["add", &ip, "mask", "255.255.255.255", &gateway, "metric", "1", "if", &if_index.to_string()])
                .output();
        }
    }
}

pub fn remove_static_routes() {
    #[cfg(target_os = "windows")]
    {
        for &ip in ALL_DNS_IPS {
            let _ = no_window(&mut Command::new("route"))
                .args(["delete", ip])
                .output();
        }
    }
}
