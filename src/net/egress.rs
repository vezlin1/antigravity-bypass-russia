pub struct Egress {
    pub if_index: u32,
    #[allow(dead_code)]
    pub gateway: Option<String>,
    pub vpn_active: bool,
}

#[cfg(windows)]
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

#[cfg(windows)]
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

/// Adapter description fragments excluded from the physical route search.
/// Kept identical to the former `Get-NetAdapter` filters.
#[cfg(any(windows, test))]
const NON_PHYSICAL_DESCRIPTIONS: &[&str] = &[
    "wireguard",
    "tap",
    "wintun",
    "openvpn",
    "tailscale",
    "cisco",
    "globalprotect",
    "pangp",
    "zerotier",
    "hamachi",
    "cloudflare",
    "warp",
    "nordlynx",
    "proton",
    "outline",
    "softether",
    "tun2socks",
    "hyper-v",
    "vmware",
    "virtualbox",
    "wsl",
];

#[cfg(any(windows, test))]
struct AdapterInfo {
    index: u32,
    up: bool,
    hardware: bool,
    description: String,
}

#[cfg(any(windows, test))]
struct DefaultRoute {
    index: u32,
    next_hop: std::net::Ipv4Addr,
    metric: u32,
}

/// The lowest-metric IPv4 default route with a gateway on an up, hardware,
/// non-tunnel adapter. Equal metrics keep the routing table order.
#[cfg(any(windows, test))]
fn pick_physical_route(adapters: &[AdapterInfo], routes: &[DefaultRoute]) -> Option<(u32, String)> {
    let physical = |index: u32| {
        adapters.iter().any(|adapter| {
            let description = adapter.description.to_lowercase();
            adapter.index == index
                && adapter.up
                && adapter.hardware
                && !NON_PHYSICAL_DESCRIPTIONS
                    .iter()
                    .any(|fragment| description.contains(fragment))
        })
    };
    routes
        .iter()
        .filter(|route| !route.next_hop.is_unspecified() && physical(route.index))
        .min_by_key(|route| route.metric)
        .map(|route| (route.index, route.next_hop.to_string()))
}

/// Native replacement for `Get-NetAdapter`/`Get-NetRoute`. The relay runs this
/// whenever a VPN owns the default route, so it must not start PowerShell.
#[cfg(windows)]
fn physical_default_route() -> Option<(u32, String)> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIfTable2, GetIpForwardTable2, MIB_IF_ROW2, MIB_IF_TABLE2,
        MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::AF_INET;
    const HARDWARE_INTERFACE: u8 = 0b01;
    const FILTER_INTERFACE: u8 = 0b10;

    let mut adapters = Vec::new();
    unsafe {
        let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
        if GetIfTable2(&mut table) != 0 || table.is_null() {
            return None;
        }
        let rows = std::slice::from_raw_parts(
            std::ptr::addr_of!((*table).Table).cast::<MIB_IF_ROW2>(),
            (*table).NumEntries as usize,
        );
        for row in rows {
            let flags = row.InterfaceAndOperStatusFlags._bitfield;
            let length = row
                .Description
                .iter()
                .position(|&unit| unit == 0)
                .unwrap_or(row.Description.len());
            adapters.push(AdapterInfo {
                index: row.InterfaceIndex,
                up: row.OperStatus == IfOperStatusUp,
                // NDIS filter instances repeat the adapter description.
                hardware: flags & HARDWARE_INTERFACE != 0 && flags & FILTER_INTERFACE == 0,
                description: String::from_utf16_lossy(&row.Description[..length]),
            });
        }
        FreeMibTable(table.cast());
    }

    let mut routes = Vec::new();
    unsafe {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        if GetIpForwardTable2(AF_INET, &mut table) != 0 || table.is_null() {
            return None;
        }
        let rows = std::slice::from_raw_parts(
            std::ptr::addr_of!((*table).Table).cast::<MIB_IPFORWARD_ROW2>(),
            (*table).NumEntries as usize,
        );
        for row in rows {
            let prefix = &row.DestinationPrefix;
            if prefix.PrefixLength != 0
                || prefix.Prefix.si_family != AF_INET
                || prefix.Prefix.Ipv4.sin_addr.S_un.S_addr != 0
                || row.NextHop.si_family != AF_INET
            {
                continue;
            }
            routes.push(DefaultRoute {
                index: row.InterfaceIndex,
                next_hop: std::net::Ipv4Addr::from(
                    row.NextHop.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
                ),
                metric: row.Metric,
            });
        }
        FreeMibTable(table.cast());
    }
    pick_physical_route(&adapters, &routes)
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

#[cfg(windows)]
pub(super) fn windows_ipv4_route(address: std::net::Ipv4Addr) -> Option<u32> {
    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetBestInterface(address: u32, interface: *mut u32) -> u32;
    }
    let mut index = 0;
    let address = u32::from_ne_bytes(address.octets());
    (unsafe { GetBestInterface(address, &mut index) } == 0 && index != 0).then_some(index)
}

#[cfg(windows)]
pub(super) fn windows_vpn_route() -> Option<u32> {
    // Look at the default internet path, rather than an installed adapter name.
    windows_ipv4_route([1, 1, 1, 1].into()).filter(|&index| {
        is_vpn_iface(index)
            && if_entry_meta(index).is_some_and(|(_, descr)| {
                let descr = descr.to_ascii_lowercase();
                !["tailscale", "zerotier", "hyper-v", "virtualbox", "vmware"]
                    .iter()
                    .any(|overlay| descr.contains(overlay))
            })
    })
}

/// Physical default route (skips VPN adapters). Used for pinning Xbox-DNS /32 routes.
#[cfg(not(target_os = "macos"))]
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

        if let Some(found) = physical_default_route() {
            return Some(found);
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
        let if_index = windows_ipv4_route([8, 8, 8, 8].into()).unwrap_or(0);
        let default_vpn = if_index > 0 && is_vpn_iface(if_index);

        if let Some((phys, gw)) = detect_physical() {
            return Some(Egress {
                if_index: phys,
                gateway: Some(gw),
                vpn_active: default_vpn && phys != if_index,
            });
        }

        if if_index > 0 {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter(index: u32, description: &str) -> AdapterInfo {
        AdapterInfo {
            index,
            up: true,
            hardware: true,
            description: description.into(),
        }
    }

    fn route(index: u32, next_hop: [u8; 4], metric: u32) -> DefaultRoute {
        DefaultRoute {
            index,
            next_hop: next_hop.into(),
            metric,
        }
    }

    #[test]
    fn physical_route_skips_tunnels_virtual_and_down_adapters() {
        let mut down = adapter(4, "Intel(R) Ethernet Connection");
        down.up = false;
        let mut software = adapter(5, "Microsoft Loopback Adapter");
        software.hardware = false;
        let adapters = [
            adapter(7, "Realtek PCIe GbE Family Controller"),
            adapter(9, "Intel(R) Wi-Fi 6 AX201 160MHz"),
            adapter(11, "WireGuard Tunnel"),
            adapter(12, "Hyper-V Virtual Ethernet Adapter"),
            down,
            software,
        ];
        let routes = [
            route(11, [10, 0, 0, 1], 0),
            route(12, [172, 16, 0, 1], 1),
            route(4, [192, 168, 0, 1], 2),
            route(5, [192, 168, 5, 1], 3),
            route(9, [0, 0, 0, 0], 5),
            route(9, [192, 168, 1, 1], 35),
            route(7, [192, 168, 2, 1], 25),
        ];
        assert_eq!(
            pick_physical_route(&adapters, &routes),
            Some((7, "192.168.2.1".into()))
        );
        assert_eq!(pick_physical_route(&adapters, &routes[..5]), None);
    }

    #[test]
    fn equal_metrics_keep_routing_table_order() {
        let adapters = [adapter(3, "Ethernet"), adapter(8, "Wi-Fi")];
        let routes = [route(8, [192, 168, 1, 1], 10), route(3, [10, 1, 1, 1], 10)];
        assert_eq!(
            pick_physical_route(&adapters, &routes),
            Some((8, "192.168.1.1".into()))
        );
    }
}
