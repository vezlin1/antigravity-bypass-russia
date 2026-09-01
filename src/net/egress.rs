use std::process::Command;
use crate::system::process::no_window;

pub struct Egress {
    pub if_index: u32,
    #[allow(dead_code)]
    pub gateway: Option<String>,
    pub vpn_active: bool,
}

const LEGACY_PINNED_PREFIXES: &[&str] = &[
    "178.130.155.0/24",
    "185.158.113.0/24",
    "185.158.114.0/24",
    "82.148.16.0/24",
    "82.148.17.0/24",
    "82.148.18.0/24",
    "82.148.19.0/24",
];

const VPN_KEYWORDS: &[&str] = &[
    "wireguard",
    "wintun",
    "tap-windows",
    "tap-win",
    "openvpn",
    "tailscale",
    "globalprotect",
    "pangp",
    "anyconnect",
    "cisco",
    "zerotier",
    "hamachi",
    "cloudflare",
    "warp",
    "nordlynx",
    "proton",
    "outline",
    "softether",
    "tun2socks",
    "wintun",
];

fn descr_is_vpn(descr: &str) -> bool {
    let d = descr.to_lowercase();
    VPN_KEYWORDS.iter().any(|k| d.contains(k))
}

#[cfg(target_os = "windows")]
fn if_entry_meta(if_index: u32) -> Option<(u32, String)> {
    #[repr(C)]
    struct MibIfRow {
        wsz_name: [u16; 256],
        dw_index: u32,
        dw_type: u32,
        dw_mtu: u32,
        dw_speed: u32,
        dw_phys_addr_len: u32,
        b_phys_addr: [u8; 8],
        dw_admin_status: u32,
        dw_oper_status: u32,
        dw_last_change: u32,
        dw_in_octets: u32,
        dw_in_ucast_pkts: u32,
        dw_in_nucast_pkts: u32,
        dw_in_discards: u32,
        dw_in_errors: u32,
        dw_in_unknown_protos: u32,
        dw_out_octets: u32,
        dw_out_ucast_pkts: u32,
        dw_out_nucast_pkts: u32,
        dw_out_discards: u32,
        dw_out_errors: u32,
        dw_out_qlen: u32,
        dw_descr_len: u32,
        b_descr: [u8; 256],
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetIfEntry(pIfRow: *mut MibIfRow) -> u32;
    }

    let mut row: MibIfRow = unsafe { std::mem::zeroed() };
    row.dw_index = if_index;
    if unsafe { GetIfEntry(&mut row) } != 0 {
        return None;
    }
    let n = (row.dw_descr_len as usize).min(row.b_descr.len());
    let descr = String::from_utf8_lossy(&row.b_descr[..n])
        .trim_end_matches('\0')
        .trim()
        .to_string();
    Some((row.dw_type, descr))
}

#[cfg(target_os = "windows")]
fn is_vpn_iface(if_index: u32) -> bool {
    const IF_TYPE_PPP: u32 = 23;
    const IF_TYPE_TUNNEL: u32 = 131;
    const IF_TYPE_PROP_VIRTUAL: u32 = 53;
    match if_entry_meta(if_index) {
        Some((ty, descr)) => {
            ty == IF_TYPE_PPP || ty == IF_TYPE_TUNNEL || ty == IF_TYPE_PROP_VIRTUAL || descr_is_vpn(&descr)
        }
        None => false,
    }
}

/// Physical default route (skips VPN adapters). Used for pinning Xbox-DNS /32 routes.
pub fn detect_physical() -> Option<(u32, String)> {
    #[cfg(target_os = "windows")]
    {
        let native = {
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
            if unsafe { GetBestRoute(dest, 0, &mut row) } == 0 && !is_vpn_iface(row.dw_forward_if_index) {
                let gw = row.dw_forward_next_hop.to_ne_bytes();
                if gw != [0, 0, 0, 0] {
                    Some((
                        row.dw_forward_if_index,
                        format!("{}.{}.{}.{}", gw[0], gw[1], gw[2], gw[3]),
                    ))
                } else {
                    None
                }
            } else {
                None
            }
        };
        if native.is_some() {
            return native;
        }

        let ps = r#"
$vpn = 'WireGuard|TAP|Wintun|OpenVPN|Tailscale|Cisco|GlobalProtect|PANGP|ZeroTier|Hamachi|Cloudflare|WARP|NordLynx|Proton|Outline|SoftEther|tun2socks'
$phys = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
    $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch $vpn -and $_.InterfaceDescription -notmatch 'Hyper-V|VMware|VirtualBox|WSL'
} | ForEach-Object { $_.ifIndex })
$def = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
$mine = @($def | Where-Object { $phys -contains $_.ifIndex -and $_.NextHop -ne '0.0.0.0' })
if ($mine.Count -gt 0) {
    $best = $mine | Sort-Object { [int]$_.RouteMetric } | Select-Object -First 1
    Write-Output ("{0}|{1}" -f $best.ifIndex, $best.NextHop)
}
"#;
        let out = no_window(&mut Command::new("powershell"))
            .args(["-NoProfile", "-NonInteractive", "-Command", ps])
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if let Some((idx, gw)) = s.split_once('|') {
            if let Ok(i) = idx.trim().parse::<u32>() {
                let gw = gw.trim().to_string();
                if i > 0 && !gw.is_empty() && gw != "0.0.0.0" {
                    return Some((i, gw));
                }
            }
        }

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
        if unsafe { GetBestRoute(dest, 0, &mut row) } != 0 {
            return None;
        }
        if is_vpn_iface(row.dw_forward_if_index) {
            return None;
        }
        let gw = row.dw_forward_next_hop.to_ne_bytes();
        if gw == [0, 0, 0, 0] {
            return None;
        }
        Some((
            row.dw_forward_if_index,
            format!("{}.{}.{}.{}", gw[0], gw[1], gw[2], gw[3]),
        ))
    }

    #[cfg(target_os = "macos")]
    {
        let out = Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .ok()?;
        let txt = String::from_utf8_lossy(&out.stdout);
        let mut if_name = String::new();
        let mut gateway = String::new();
        for line in txt.lines() {
            let l = line.trim();
            if l.starts_with("interface:") {
                if_name = l.trim_start_matches("interface:").trim().to_string();
            }
            if l.starts_with("gateway:") {
                gateway = l.trim_start_matches("gateway:").trim().to_string();
            }
        }
        if if_name.is_empty() || if_name.starts_with("utun") || if_name.starts_with("ppp") {
            return None;
        }
        let idx = unsafe {
            let c_name = std::ffi::CString::new(if_name.as_str()).ok()?;
            libc::if_nametoindex(c_name.as_ptr())
        };
        if idx > 0 && !gateway.is_empty() {
            Some((idx, gateway))
        } else {
            None
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    None
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
        let default_vpn = res == 0 && if_index > 0 && is_vpn_iface(if_index);

        if let Some((phys, gw)) = detect_physical() {
            return Some(Egress {
                if_index: phys,
                gateway: Some(gw),
                vpn_active: default_vpn && phys != if_index,
            });
        }

        if res == 0 && if_index > 0 {
            return Some(Egress {
                if_index,
                gateway: None,
                vpn_active: default_vpn,
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
        let mut gateway = String::new();
        for line in txt.lines() {
            let l = line.trim();
            if l.starts_with("interface:") {
                if_name = l.trim_start_matches("interface:").trim().to_string();
            }
            if l.starts_with("gateway:") {
                gateway = l.trim_start_matches("gateway:").trim().to_string();
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
                gateway: if gateway.is_empty() { None } else { Some(gateway) },
                vpn_active: vpn,
            })
        } else {
            None
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    None
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
