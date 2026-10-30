pub struct Egress {
    pub if_index: u32,
    #[allow(dead_code)]
    pub gateway: Option<String>,
    pub vpn_active: bool,
}

const VPN_KEYWORDS: &[&str] = &[
    "wireguard",
    "wintun",
    "sing-tun",
    "throne",
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

/// Read-only preflight; call before patching files or changing network state.
pub fn ensure_tun_disabled() -> Result<(), String> {
    #[cfg(windows)]
    {
        let adapters = active_virtual_adapters()?;
        if adapters.iter().any(|name| is_active_tun_name(name)) {
            return Err("Обнаружен включённый TUN. Выключите VPN и режим TUN в VPN-клиенте, затем повторите включение обхода.".into());
        }
        // Also catches unfamiliar TUN clients whose DNS protection remains on.
        if !super::relay::local_dns_available()? {
            return Err("Локальный DNS заблокирован. Выключите VPN вместе с режимом TUN, затем повторите включение обхода.".into());
        }
    }
    #[cfg(target_os = "macos")]
    {
        let egress = detect().ok_or("Не удалось определить подключение к интернету. Проверьте сеть и повторите включение обхода.")?;
        if egress.vpn_active {
            return Err("Выключите VPN и режим TUN, затем повторите включение обхода.".into());
        }
    }
    Ok(())
}

#[cfg(windows)]
const TUN_ADAPTER_QUERY: &str = r#"
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$ErrorActionPreference='Stop'
try {
    ConvertTo-Json -Compress -InputObject @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and -not $_.HardwareInterface } | ForEach-Object { $_.Name + '|' + $_.InterfaceDescription })
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
"#;

#[cfg(windows)]
fn active_virtual_adapters() -> Result<Vec<String>, String> {
    let output = crate::system::powershell::output(TUN_ADAPTER_QUERY)
        .map_err(|e| format!("Не удалось запустить Windows PowerShell для проверки TUN: {e}"))?;
    parse_tun_adapters(output)
}

#[cfg(windows)]
fn parse_tun_adapters(output: std::process::Output) -> Result<Vec<String>, String> {
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "Не удалось проверить сетевые адаптеры через Windows PowerShell ({}): {}",
            output.status,
            detail.trim()
        ));
    }
    // A failed or empty query is not evidence that TUN is disabled.
    serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("Некорректный ответ Windows PowerShell при проверке TUN: {e}"))
}

#[cfg(any(windows, test))]
fn is_active_tun_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    // An always-on overlay alone (e.g. Tailscale) is not evidence of TUN
    // interception. Port-53 protection is checked separately above.
    if name.contains("tailscale") || name.contains("zerotier") {
        return false;
    }
    [
        "sing-tun",
        "throne",
        "wintun",
        "wireguard",
        "tap-windows",
        "tap-win",
        "openvpn",
        "tun2socks",
        "clash",
        "mihomo",
        "warp",
        "nordlynx",
        "proton",
        "outline",
    ]
    .iter()
    .any(|pattern| name.contains(pattern))
        || name
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|part| part == "tun")
}

#[cfg(test)]
mod tun_preflight_tests {
    #[test]
    fn detects_throne_and_tun_clients_but_not_unrelated_overlays() {
        for name in [
            "throne-tun|sing-tun Tunnel",
            "VPN|Wintun Userspace Tunnel",
            "tun0|WireGuard Tunnel",
            "tun|VPN Adapter",
        ] {
            assert!(super::is_active_tun_name(name), "{name}");
        }
        for name in [
            "Tailscale|Tailscale Tunnel",
            "ZeroTier One",
            "Ethernet|Realtek",
            "vEthernet|Hyper-V Virtual Ethernet Adapter",
        ] {
            assert!(!super::is_active_tun_name(name), "{name}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn queries_adapters_without_path_and_ignores_shadow_powershell() {
        use crate::system::{powershell, process::no_window};
        use std::{
            process::Command,
            time::{Duration, Instant},
        };

        const CHILD: &str = "ABR_TEST_POWERSHELL_ENVIRONMENT";
        if let Ok(mode) = std::env::var(CHILD) {
            if mode != "shadow" {
                // Reproduce issue #6 in an isolated process. Setting PATH on
                // only the PowerShell child leaves Rust's parent-PATH fallback.
                let error = no_window(&mut Command::new("powershell.exe"))
                    .args(["-NoProfile", "-NonInteractive", "-Command", "exit 0"])
                    .output()
                    .unwrap_err();
                assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
                assert_eq!(error.to_string(), "program not found");
            }
            let executable = powershell::executable().unwrap();
            assert!(executable.is_absolute());
            assert!(!executable.starts_with(std::env::current_dir().unwrap()));
            // Actual read-only NetAdapter query, without patching or binding DNS.
            super::active_virtual_adapters().unwrap();
            return;
        }

        for mode in ["empty", "unset", "shadow"] {
            let directory = tempfile::Builder::new()
                .prefix("tun query путь ")
                .tempdir()
                .unwrap();
            if mode == "shadow" {
                std::fs::write(
                    directory.path().join("powershell.exe"),
                    b"not an executable",
                )
                .unwrap();
            }
            let mut cmd = Command::new(std::env::current_exe().unwrap());
            no_window(&mut cmd);
            cmd.args(["--exact", "net::egress::tun_preflight_tests::queries_adapters_without_path_and_ignores_shadow_powershell", "--nocapture"])
                .env(CHILD, mode).current_dir(directory.path());
            match mode {
                "unset" => {
                    cmd.env_remove("PATH");
                }
                "shadow" => {
                    cmd.env("PATH", directory.path());
                }
                _ => {
                    cmd.env("PATH", "");
                }
            }
            let mut child = cmd.spawn().unwrap();
            let started = Instant::now();
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success(), "{mode}: {status}");
                    break;
                }
                if started.elapsed() > Duration::from_secs(30) {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("{mode}: adapter query timed out");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn adapter_query_handles_empty_lists_unicode_and_query_failures() {
        fn query(body: &str) -> Result<Vec<String>, String> {
            let script = format!(
                "function Get-NetAdapter {{ {body} }}\n{}",
                super::TUN_ADAPTER_QUERY
            );
            let output = crate::system::powershell::command()
                .unwrap()
                .args(["-NoProfile", "-NonInteractive", "-Command", &script])
                .output()
                .unwrap();
            super::parse_tun_adapters(output)
        }
        assert!(query("return @()").unwrap().is_empty());
        assert_eq!(query("[pscustomobject]@{Name='Сеть';InterfaceDescription='Wintun';Status='Up';HardwareInterface=$false}").unwrap(), ["Сеть|Wintun"]);
        assert_eq!(query(r#"
            [pscustomobject]@{Name='Ethernet';InterfaceDescription='Realtek';Status='Up';HardwareInterface=$true}
            [pscustomobject]@{Name='VPN';InterfaceDescription='Wintun';Status='Disconnected';HardwareInterface=$false}
            [pscustomobject]@{Name='Сеть';InterfaceDescription='WireGuard';Status='Up';HardwareInterface=$false}
            [pscustomobject]@{Name='throne-tun';InterfaceDescription='sing-tun';Status='Up';HardwareInterface=$false}
        "#).unwrap(), ["Сеть|WireGuard", "throne-tun|sing-tun"]);
        let error = query("throw 'Ошибка службы адаптеров'").unwrap_err();
        assert!(error.contains("Ошибка службы адаптеров"), "{error}");
        assert!(!error.contains("Выключите VPN"), "{error}");
        for response in ["", "not json"] {
            let output = crate::system::powershell::command()
                .unwrap()
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    &format!("Write-Output '{response}'"),
                ])
                .output()
                .unwrap();
            assert!(super::parse_tun_adapters(output).is_err());
        }
    }
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
            ty == IF_TYPE_PPP
                || ty == IF_TYPE_TUNNEL
                || ty == IF_TYPE_PROP_VIRTUAL
                || descr_is_vpn(&descr)
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
                fn GetBestRoute(
                    dwDestAddr: u32,
                    dwSourceAddr: u32,
                    pBestRoute: *mut MibIpForwardRow,
                ) -> u32;
            }
            let mut row: MibIpForwardRow = unsafe { std::mem::zeroed() };
            let dest: u32 = u32::from_ne_bytes([8, 8, 8, 8]);
            if unsafe { GetBestRoute(dest, 0, &mut row) } == 0
                && !is_vpn_iface(row.dw_forward_if_index)
            {
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
    $_.Status -eq 'Up' -and $_.HardwareInterface -and $_.InterfaceDescription -notmatch $vpn -and $_.InterfaceDescription -notmatch 'Hyper-V|VMware|VirtualBox|WSL'
} | ForEach-Object { $_.ifIndex })
$def = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
$mine = @($def | Where-Object { $phys -contains $_.ifIndex -and $_.NextHop -ne '0.0.0.0' })
if ($mine.Count -gt 0) {
    $best = $mine | Sort-Object { [int]$_.RouteMetric } | Select-Object -First 1
    Write-Output ("{0}|{1}" -f $best.ifIndex, $best.NextHop)
}
"#;
        let out = crate::system::powershell::output(ps).ok()?;
        if !out.status.success() {
            return None;
        }
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
            fn GetBestRoute(
                dwDestAddr: u32,
                dwSourceAddr: u32,
                pBestRoute: *mut MibIpForwardRow,
            ) -> u32;
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
        let out = crate::system::command::output("route", ["-n", "get", "8.8.8.8"]).ok()?;
        if !out.status.success() {
            return None;
        }
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

    #[cfg(target_os = "linux")]
    {
        if let Ok(out) = crate::system::command::output("ip", ["route", "show", "default"]) {
            if out.status.success() {
                let txt = String::from_utf8_lossy(&out.stdout);
                for line in txt.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    let mut if_name = "";
                    let mut gateway = "";
                    for i in 0..parts.len() {
                        if parts[i] == "dev" && i + 1 < parts.len() {
                            if_name = parts[i + 1];
                        } else if parts[i] == "via" && i + 1 < parts.len() {
                            gateway = parts[i + 1];
                        }
                    }
                    if !if_name.is_empty()
                        && !if_name.starts_with("tun")
                        && !if_name.starts_with("tap")
                        && !if_name.starts_with("wg")
                        && !if_name.starts_with("ppp")
                    {
                        let idx = unsafe {
                            let c_name = std::ffi::CString::new(if_name).ok()?;
                            libc::if_nametoindex(c_name.as_ptr())
                        };
                        if idx > 0 && !gateway.is_empty() {
                            return Some((idx, gateway.to_string()));
                        }
                    }
                }
            }
        }
        None
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
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
        // A VPN can install /1 routes while leaving the physical default intact.
        let out = crate::system::command::output("route", ["-n", "get", "8.8.8.8"]).ok()?;
        if !out.status.success() {
            return None;
        }
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
                gateway: if gateway.is_empty() {
                    None
                } else {
                    Some(gateway)
                },
                vpn_active: vpn,
            })
        } else {
            None
        }
    }

    #[cfg(target_os = "linux")]
    {
        let phys_gw = detect_physical();
        if let Ok(out) = crate::system::command::output("ip", ["route", "get", "8.8.8.8"]) {
            if out.status.success() {
                let txt = String::from_utf8_lossy(&out.stdout);
                let mut if_name = String::new();
                let mut gateway = String::new();
                let parts: Vec<&str> = txt.split_whitespace().collect();
                for i in 0..parts.len() {
                    if parts[i] == "dev" && i + 1 < parts.len() {
                        if_name = parts[i + 1].to_string();
                    } else if parts[i] == "via" && i + 1 < parts.len() {
                        gateway = parts[i + 1].to_string();
                    }
                }
                if !if_name.is_empty() {
                    let vpn = if_name.starts_with("tun")
                        || if_name.starts_with("tap")
                        || if_name.starts_with("wg")
                        || if_name.starts_with("ppp");
                    let idx = unsafe {
                        let c_name = std::ffi::CString::new(if_name.as_str()).ok()?;
                        libc::if_nametoindex(c_name.as_ptr())
                    };
                    if idx > 0 {
                        let gw = if !gateway.is_empty() {
                            Some(gateway)
                        } else {
                            phys_gw.as_ref().map(|(_, g)| g.clone())
                        };
                        return Some(Egress {
                            if_index: idx,
                            gateway: gw,
                            vpn_active: vpn,
                        });
                    }
                }
            }
        }
        if let Some((phys, gw)) = phys_gw {
            return Some(Egress {
                if_index: phys,
                gateway: Some(gw),
                vpn_active: false,
            });
        }
        None
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    None
}
