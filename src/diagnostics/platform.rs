//! Read-only OS queries. Commands have deadlines; only validated fields leave this module.
use super::*;
use std::process::{Command, Stdio};

fn command(
    program: impl AsRef<std::ffi::OsStr>,
    args: &[&str],
    budget: Duration,
) -> Result<String, &'static str> {
    #[cfg(target_os = "linux")]
    let program = {
        let name = program.as_ref().to_str().ok_or("invalid_command")?;
        system::command::executable(name).map_err(|_| "command_unavailable")?
    };
    // A temporary output file avoids pipe deadlocks and inheriting a live reader on timeout.
    let mut output = tempfile::tempfile().map_err(|_| "temporary_file_failed")?;
    let mut child = system::process::no_window(&mut Command::new(program))
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(output.try_clone().map_err(|_| "temporary_file_failed")?)
        .spawn()
        .map_err(|_| "command_unavailable")?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) => return Err("query_failed"),
            Ok(None) if started.elapsed() < budget => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("timeout");
            }
        }
    }
    output.seek(SeekFrom::Start(0)).map_err(|_| "read_failed")?;
    let mut bytes = Vec::new();
    output
        .take(MAX_TEXT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "read_failed")?;
    if bytes.len() as u64 > MAX_TEXT {
        return Err("size_limit");
    }
    String::from_utf8(bytes).map_err(|_| "invalid_encoding")
}

#[cfg(windows)]
fn powershell(script: &str) -> Result<Value, &'static str> {
    let script = format!("[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); $ErrorActionPreference='Stop'; {script}");
    let text = command(
        system::powershell::executable().map_err(|_| "command_unavailable")?,
        &["-NoProfile", "-NonInteractive", "-Command", &script],
        Duration::from_secs(10),
    )?;
    serde_json::from_str(text.trim_start_matches('\u{feff}').trim()).map_err(|_| "invalid_response")
}

#[cfg(any(windows, target_os = "macos", test))]
fn namespace(value: &str) -> Option<String> {
    let name = value.trim_start_matches('.').to_ascii_lowercase();
    if value == "."
        || net::provider::nrpt_domains().iter().any(|h| {
            let host = h.trim_start_matches('.');
            host == name || host.ends_with(&format!(".{name}"))
        })
    {
        Some(value.to_ascii_lowercase())
    } else {
        None
    }
}

#[cfg(any(windows, test))]
fn safe_windows(value: &Value, ips: &[Ipv4Addr]) -> Value {
    let dns: Vec<_> = value["dns"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|rule| {
            let namespace = namespace(rule["namespace"].as_str()?)?;
            let servers: Vec<IpAddr> = rule["servers"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .flat_map(|s| s.split([';', ',', ' ']))
                .filter_map(|s| s.parse().ok())
                .collect();
            Some(json!({"namespace": namespace, "servers": servers}))
        })
        .collect();
    let routes: Vec<_> = value["routes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|route| {
            let (ip, prefix) = route["destination"].as_str()?.split_once('/')?;
            let ip: Ipv4Addr = ip.parse().ok()?;
            let prefix = prefix.parse::<u8>().ok()?;
            if !((ip.is_unspecified() && prefix == 0) || (prefix == 32 && ips.contains(&ip))) {
                return None;
            }
            let gateway: IpAddr = route["gateway"].as_str()?.parse().ok()?;
            Some(
                json!({"destination": format!("{ip}/{prefix}"), "gateway": gateway,
            "interface": route["interface"].as_u64(), "metric": route["metric"].as_u64()}),
            )
        })
        .collect();
    let selected: Vec<_> = value["selected"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| {
            let target: Ipv4Addr = row["target"].as_str()?.parse().ok()?;
            if !ips.contains(&target) {
                return None;
            }
            if row["ok"].as_bool() != Some(true) {
                return Some(json!({"target": target, "status": "query_failed"}));
            }
            let (ip, prefix) = row["destination"].as_str()?.split_once('/')?;
            let ip: Ipv4Addr = ip.parse().ok()?;
            let prefix = prefix.parse::<u8>().ok().filter(|p| *p <= 32)?;
            let gateway: IpAddr = row["gateway"].as_str()?.parse().ok()?;
            Some(
                json!({"target": target, "status": "ok", "destination": format!("{ip}/{prefix}"),
            "gateway": gateway, "interface": row["interface"].as_u64()}),
            )
        })
        .collect();
    json!({"status": "ok", "dns_query_ok": value["dns_ok"].as_bool(),
        "routes_query_ok": value["routes_ok"].as_bool(), "effective_dns": dns, "routes": routes,
        "selected_routes": selected})
}

/// The route Windows selects for each address, from the routing table itself
/// (`GetBestRoute`) instead of one `Find-NetRoute` call per address.
#[cfg(windows)]
fn selected_routes(ips: &[Ipv4Addr]) -> Value {
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetBestRoute, MIB_IPFORWARDROW};
    let dotted = |raw: u32| Ipv4Addr::from(raw.to_ne_bytes());
    let rows: Vec<Value> = ips
        .iter()
        .map(|ip| {
            let mut row: MIB_IPFORWARDROW = unsafe { std::mem::zeroed() };
            let destination = u32::from_ne_bytes(ip.octets());
            if unsafe { GetBestRoute(destination, 0, &mut row) } != 0 {
                return json!({"target": ip.to_string(), "ok": false});
            }
            let prefix = u32::from_be(row.dwForwardMask).count_ones();
            json!({"target": ip.to_string(), "ok": true,
                "destination": format!("{}/{prefix}", dotted(row.dwForwardDest)),
                "gateway": dotted(row.dwForwardNextHop).to_string(),
                "interface": row.dwForwardIfIndex})
        })
        .collect();
    json!(rows)
}

#[cfg(windows)]
pub(super) fn network(ips: &[Ipv4Addr]) -> Value {
    let script = r#"
    $dnsOk=$true; $routesOk=$true; $dns=@(); $routes=@()
    try { $dns=@(Get-DnsClientNrptPolicy -Effective | ForEach-Object { $r=$_; foreach($n in $r.Namespace) {
        [pscustomobject]@{namespace=[string]$n; servers=@($r.NameServers | ForEach-Object { [string]$_ })}
    } }) } catch { $dnsOk=$false }
    try { $routes=@(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore | ForEach-Object {
        [pscustomobject]@{destination=$_.DestinationPrefix; gateway=$_.NextHop; interface=$_.InterfaceIndex; metric=$_.RouteMetric}
    }) } catch { $routesOk=$false }
    [pscustomobject]@{dns_ok=$dnsOk; routes_ok=$routesOk; dns=$dns; routes=$routes} | ConvertTo-Json -Depth 6 -Compress
    "#;
    match powershell(script) {
        Ok(mut v) => {
            v["selected"] = selected_routes(ips);
            safe_windows(&v, ips)
        }
        Err(e) => unavailable(e),
    }
}

#[cfg(any(target_os = "macos", test))]
fn mac_field(line: &str) -> Option<(&str, &str)> {
    let (name, value) = line.split_once(':')?;
    Some((name.trim(), value.trim()))
}

#[cfg(any(target_os = "macos", test))]
fn mac_dns(text: &str) -> Value {
    let mut result = Vec::new();
    for block in text.split("resolver #").skip(1) {
        let domain = block
            .lines()
            .filter_map(mac_field)
            .find_map(|(name, value)| (name == "domain").then_some(value));
        let domain = match domain {
            Some(d) => match namespace(d.trim()) {
                Some(d) => d,
                None => continue,
            },
            None => ".".into(),
        };
        let mut servers = Vec::<IpAddr>::new();
        let mut port = None;
        for (name, value) in block.lines().filter_map(mac_field) {
            if name.starts_with("nameserver[") {
                if let Ok(ip) = value.parse() {
                    servers.push(ip);
                }
            } else if name == "port" {
                port = value.parse::<u16>().ok();
            }
        }
        result.push(json!({"namespace": domain, "servers": servers, "port": port}));
    }
    json!(result)
}

#[cfg(any(target_os = "macos", test))]
fn mac_route(text: &str) -> Value {
    let gateway = text
        .lines()
        .filter_map(mac_field)
        .find_map(|(name, value)| (name == "gateway").then_some(value))
        .and_then(|s| s.parse::<IpAddr>().ok());
    let interface = text
        .lines()
        .filter_map(mac_field)
        .find_map(|(name, value)| (name == "interface").then_some(value))
        .filter(|s| {
            static INTERFACE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
                regex::Regex::new(r"^(en|utun|ppp|bridge|lo)[0-9]{1,4}$").unwrap()
            });
            INTERFACE.is_match(s)
        });
    json!({"status": "ok", "gateway": gateway, "interface": interface})
}

#[cfg(target_os = "macos")]
pub(super) fn network(ips: &[Ipv4Addr]) -> Value {
    let dns = match command("/usr/sbin/scutil", &["--dns"], Duration::from_secs(3)) {
        Ok(text) => json!({"status": "ok", "effective_dns": mac_dns(&text)}),
        Err(e) => unavailable(e),
    };
    let mut routes = Vec::new();
    for address in
        std::iter::once("default".to_string()).chain(ips.iter().take(9).map(ToString::to_string))
    {
        let route = match command(
            "/sbin/route",
            &["-n", "get", &address],
            Duration::from_millis(900),
        ) {
            Ok(text) => mac_route(&text),
            Err(e) => unavailable(e),
        };
        routes.push(json!({"destination": address, "route": route}));
    }
    let files: Vec<_> = net::provider::nrpt_domains()
        .iter()
        .map(|h| h.trim_start_matches('.'))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|host| {
            let value = match read_limited(&Path::new("/etc/resolver").join(host), 16 * 1024) {
                Ok(bytes) => {
                    let servers: Vec<IpAddr> = String::from_utf8_lossy(&bytes)
                        .lines()
                        .filter_map(|line| {
                            let mut fields = line.split_whitespace();
                            (fields.next()? == "nameserver")
                                .then(|| fields.next()?.parse().ok())
                                .flatten()
                        })
                        .collect();
                    json!({"status": "ok", "servers": servers})
                }
                Err(e) => unavailable(e),
            };
            json!({"host": host, "resolver_file": value})
        })
        .collect();
    json!({"status": "ok", "dns": dns, "routes": routes, "resolver_files": files})
}

#[cfg(target_os = "linux")]
pub(super) fn network(_ips: &[Ipv4Addr]) -> Value {
    let routes = command("ip", &["route"], Duration::from_secs(2))
        .map(|out| json!({"status": "ok", "output": out.trim()}))
        .unwrap_or_else(|e| unavailable(&e));
    let dns = command("resolvectl", &["status"], Duration::from_secs(2))
        .or_else(|_| command("systemd-resolve", &["--status"], Duration::from_secs(2)))
        .map(|out| json!({"status": "ok", "output": out.trim()}))
        .unwrap_or_else(|_| {
            std::fs::read_to_string("/etc/resolv.conf")
                .map(|c| json!({"status": "ok", "resolv_conf": c.trim()}))
                .unwrap_or_else(|e| unavailable(&e.to_string()))
        });
    json!({"status": "ok", "dns": dns, "routes": routes})
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
pub(super) fn network(_ips: &[Ipv4Addr]) -> Value {
    unavailable("unsupported_platform")
}

pub(super) fn os_version() -> Value {
    #[cfg(windows)]
    {
        // Four registry values, read directly instead of starting PowerShell.
        match windows_version() {
            Ok((major, minor, build, revision)) => {
                json!({"status": "ok", "major": major, "minor": minor,
                "build": build, "revision": revision})
            }
            // Report a fixed reason; registry codes are not exported.
            Err(_) => unavailable("query_failed"),
        }
    }
    #[cfg(target_os = "macos")]
    {
        match command(
            "/usr/bin/sw_vers",
            &["-productVersion"],
            Duration::from_secs(2),
        ) {
            Ok(text) => json!({"status": "ok", "version": version_text(text.trim())}),
            Err(e) => unavailable(e),
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
            let mut name = String::new();
            let mut version = String::new();
            for line in content.lines() {
                if let Some(val) = line.strip_prefix("PRETTY_NAME=") {
                    name = val.trim_matches('"').to_string();
                } else if let Some(val) = line.strip_prefix("VERSION_ID=") {
                    version = val.trim_matches('"').to_string();
                }
            }
            if !name.is_empty() {
                return json!({"status": "ok", "distro": name, "version": version});
            }
        }
        if let Ok(out) = command("uname", &["-sr"], Duration::from_secs(2)) {
            return json!({"status": "ok", "version": version_text(out.trim())});
        }
        unavailable("unsupported_platform")
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    unavailable("unsupported_platform")
}

#[cfg(windows)]
fn windows_version() -> Result<(u64, u64, u64, u64), String> {
    use windows_sys::Win32::System::Registry::{
        RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ,
    };
    const ERROR_FILE_NOT_FOUND: u32 = 2;
    let wide = |text: &str| text.encode_utf16().chain([0]).collect::<Vec<u16>>();
    let key = wide(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
    let dword = |name: &str| -> Result<u64, String> {
        let mut value = 0u32;
        let mut size = std::mem::size_of::<u32>() as u32;
        let code = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                wide(name).as_ptr(),
                RRF_RT_REG_DWORD,
                std::ptr::null_mut(),
                (&mut value as *mut u32).cast(),
                &mut size,
            )
        };
        match code {
            0 => Ok(u64::from(value)),
            // Older builds lack UBR and the major/minor values; report 0 as
            // the former PowerShell query did, instead of failing the whole
            // version.
            ERROR_FILE_NOT_FOUND => Ok(0),
            _ => Err(format!("{name}: {code}")),
        }
    };
    // CurrentBuildNumber is stored as text.
    let mut text = [0u16; 32];
    let mut size = std::mem::size_of_val(&text) as u32;
    let code = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            wide("CurrentBuildNumber").as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            text.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if code != 0 {
        return Err(format!("CurrentBuildNumber: {code}"));
    }
    let length = text
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(text.len());
    let build = String::from_utf16_lossy(&text[..length])
        .trim()
        .parse::<u64>()
        .map_err(|e| format!("CurrentBuildNumber: {e}"))?;
    Ok((
        dword("CurrentMajorVersionNumber")?,
        dword("CurrentMinorVersionNumber")?,
        build,
        dword("UBR")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    #[test]
    fn native_windows_queries_match_the_system() {
        let (major, _, build, _) = windows_version().unwrap();
        assert_eq!(major, 10);
        assert!(build >= 10240);
        let loopback = selected_routes(&[Ipv4Addr::LOCALHOST]);
        assert_eq!(loopback[0]["ok"], true);
        assert_eq!(loopback[0]["destination"], "127.0.0.1/32");
        assert_eq!(loopback[0]["gateway"], "0.0.0.0");
    }

    #[test]
    fn os_queries_export_only_relevant_names_and_typed_addresses() {
        let v = json!({"dns_ok": true, "routes_ok": true, "SECRET": "SECRET_USER",
            "dns": [{"namespace": ".googleapis.com", "servers": ["127.0.0.53;::1", "SECRET_TOKEN"]},
                {"namespace": "SECRET.corp", "servers": ["10.0.0.1"]}],
            "routes": [{"destination": "0.0.0.0/0", "gateway": "192.168.0.1", "interface": 12, "metric": 5},
                {"destination": "10.0.0.0/24", "gateway": "10.0.0.1"}]});
        let result = safe_windows(&v, &[]);
        assert!(!result.to_string().contains("SECRET"));
        assert_eq!(result["effective_dns"].as_array().unwrap().len(), 1);
        assert_eq!(
            result["effective_dns"][0]["servers"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(result["routes"].as_array().unwrap().len(), 1);
        let mac = mac_dns("resolver #1\n domain   : SECRET.corp\n nameserver[0] : 10.0.0.1\nresolver #2\n domain   : cloudcode-pa.googleapis.com\n nameserver[0] : 127.0.0.1\n port     : 53\n search domain[0] : SECRET.corp");
        assert!(!mac.to_string().contains("SECRET"));
        assert_eq!(mac.as_array().unwrap().len(), 1);
        assert_eq!(mac[0]["namespace"], "cloudcode-pa.googleapis.com");
        assert_eq!(mac[0]["port"], 53);
        assert_eq!(
            mac_route(" gateway: 192.168.0.1\n interface: en0\n hostname: SECRET")["interface"],
            "en0"
        );
    }
}
