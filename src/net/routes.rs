use serde::{Deserialize, Serialize};
use std::{fs, net::Ipv4Addr, path::PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct OwnedRoute {
    ip: Ipv4Addr,
    gateway: Ipv4Addr,
    interface: u32,
}
fn state_path() -> PathBuf {
    super::relay::log_dir().join("owned_routes.json")
}
fn load() -> Result<Vec<OwnedRoute>, String> {
    match fs::read(state_path()) {
        Ok(b) => serde_json::from_slice(&b).map_err(|e| format!("Журнал маршрутов: {e}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.to_string()),
    }
}
fn save(routes: &[OwnedRoute]) -> Result<(), String> {
    fs::create_dir_all(super::relay::log_dir()).map_err(|e| e.to_string())?;
    crate::system::fs_utils::robust_write_file(
        &state_path(),
        &serde_json::to_vec(routes).map_err(|e| e.to_string())?,
    )
}
#[cfg(target_os = "windows")]
fn powershell(script: &str) -> Result<String, String> {
    let script = format!(
        "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); $ErrorActionPreference='Stop'; try {{ & {{ {script} }}; exit 0 }} catch {{ [Console]::Error.WriteLine($_.Exception.Message); exit 1 }}"
    );
    let out = crate::system::powershell::output(&script).map_err(|e| e.to_string())?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let detail = if !stderr.trim().is_empty() {
            stderr.trim()
        } else {
            stdout.trim()
        };
        return Err(format!(
            "Маршруты (код {}): {}",
            out.status,
            if detail.is_empty() {
                "PowerShell завершился без сообщения об ошибке"
            } else {
                detail
            }
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().into())
}
pub fn sync_physical_hosts(extra: &[Ipv4Addr]) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let (interface, gateway) =
            super::egress::detect_physical().ok_or("Не найден физический адаптер")?;
        let gateway: Ipv4Addr = gateway.parse().map_err(|_| "Некорректный шлюз")?;
        let mut owned = load()?;
        let mut ips: Vec<Ipv4Addr> = super::resolvers::all_provider_v4()
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        ips.extend(extra);
        // Bootstrap HTTPS DNS through the same physical route, without asking
        // the VPN's system resolver how to reach the DoH provider.
        ips.extend(super::resolver_pool::bootstrap_v4()?);
        ips.sort();
        ips.dedup();
        for ip in ips {
            let route = OwnedRoute {
                ip,
                gateway,
                interface,
            };
            match powershell(&inspect_route_script(&route, &owned))?.as_str() {
                "present" => continue,
                "owned-stale" => {
                    // Move only exact recorded routes when Wi-Fi/gateway changes.
                    let retired: Vec<_> = owned
                        .iter()
                        .filter(|r| r.ip == ip && *r != &route)
                        .cloned()
                        .collect();
                    for old in retired {
                        powershell(&remove_route_script(&old))?;
                        owned.retain(|r| r != &old);
                        save(&owned)?;
                    }
                }
                "missing" => {}
                _ => return Err("Не удалось проверить существующий маршрут".into()),
            }
            if !owned.contains(&route) {
                owned.push(route.clone());
                save(&owned)?;
            }
            powershell(&format!("$ErrorActionPreference='Stop'; New-NetRoute -DestinationPrefix '{ip}/32' -InterfaceIndex {interface} -NextHop '{gateway}' -RouteMetric 1 -PolicyStore ActiveStore | Out-Null"))?;
        }
    }
    #[cfg(not(target_os = "windows"))]
    let _ = extra;
    Ok(())
}

#[cfg(windows)]
fn inspect_route_script(route: &OwnedRoute, owned: &[OwnedRoute]) -> String {
    let predicates: Vec<_> = owned
        .iter()
        .filter(|old| old.ip == route.ip)
        .map(|old| {
            format!(
                "($_.InterfaceIndex -eq {} -and $_.NextHop -eq '{}' -and $_.RouteMetric -eq 1)",
                old.interface, old.gateway
            )
        })
        .collect();
    let tracked = if predicates.is_empty() {
        "$false".into()
    } else {
        predicates.join(" -or ")
    };
    format!("$r=@(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {{ $_.DestinationPrefix -eq '{}/32' }}); if ($r.Count -eq 0) {{ 'missing' }} elseif (@($r | Where-Object {{ $_.InterfaceIndex -eq {} -and $_.NextHop -eq '{}' }}).Count -gt 0) {{ 'present' }} elseif (@($r | Where-Object {{ -not ({tracked}) }}).Count -eq 0) {{ 'owned-stale' }} else {{ throw 'Конфликт существующего маршрута {}/32; он сохранён' }}", route.ip, route.interface, route.gateway, route.ip)
}
pub fn add_static_routes() -> Result<(), String> {
    sync_physical_hosts(&[])
}
pub fn remove_static_routes() -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let owned = load()?;
        let mut remaining = owned.clone();
        for route in owned {
            powershell(&remove_route_script(&route))?;
            remaining.retain(|r| r != &route);
            save(&remaining)?;
        }
        if state_path().exists() {
            fs::remove_file(state_path()).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

#[cfg(windows)]
fn remove_route_script(route: &OwnedRoute) -> String {
    // Query the table first: an absent exact-prefix query is a CIM error even
    // with SilentlyContinue, and can make powershell.exe return exit code 1.
    format!("$ownedMatches=@(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {{ $_.DestinationPrefix -eq '{}/32' -and $_.InterfaceIndex -eq {} -and $_.NextHop -eq '{}' -and $_.RouteMetric -eq 1 }}); foreach ($ownedMatch in $ownedMatches) {{ $ownedMatch | Remove-NetRoute -Confirm:$false -ErrorAction Stop }}", route.ip, route.interface, route.gateway)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    #[test]
    fn gateway_migration_accepts_only_exact_owned_routes_and_preserves_foreign_conflicts() {
        let old = route();
        let desired = OwnedRoute {
            interface: 9,
            gateway: "192.0.2.254".parse().unwrap(),
            ..old.clone()
        };
        for (interface, gateway, metric, expected) in [
            (7, "192.0.2.1", 1, Some("owned-stale")),
            (9, "192.0.2.254", 1, Some("present")),
            (7, "192.0.2.1", 99, None),
            (8, "192.0.2.1", 1, None),
        ] {
            let script = format!("function Get-NetRoute {{ param($AddressFamily,$PolicyStore,$ErrorAction) [pscustomobject]@{{DestinationPrefix='192.0.2.25/32';InterfaceIndex={interface};NextHop='{gateway}';RouteMetric={metric}}} }}; {}", inspect_route_script(&desired, &[old.clone()]));
            let result = powershell(&script);
            match expected {
                Some(expected) => assert_eq!(result.unwrap(), expected),
                None => assert!(result.is_err()),
            }
        }
    }
    fn route() -> OwnedRoute {
        OwnedRoute {
            ip: "192.0.2.25".parse().unwrap(),
            gateway: "192.0.2.1".parse().unwrap(),
            interface: 7,
        }
    }

    #[test]
    fn missing_route_cleanup_succeeds_without_deleting_anything() {
        let script = format!("function Get-NetRoute {{ param($AddressFamily,$PolicyStore,$ErrorAction) }}; function Remove-NetRoute {{ throw 'unexpected delete' }}; {}", remove_route_script(&route()));
        assert_eq!(powershell(&script).unwrap(), "");
    }

    #[test]
    fn cleanup_only_deletes_the_exact_owned_route() {
        let script = format!(
            r#"
function Get-NetRoute {{ param($AddressFamily,$PolicyStore,$ErrorAction)
    foreach ($item in @(@('192.0.2.25/32',7,'192.0.2.1',1), @('192.0.2.25/32',8,'192.0.2.1',1), @('192.0.2.25/32',7,'192.0.2.2',1), @('192.0.2.25/32',7,'192.0.2.1',9), @('192.0.2.26/32',7,'192.0.2.1',1))) {{
        [pscustomobject]@{{DestinationPrefix=$item[0];InterfaceIndex=$item[1];NextHop=$item[2];RouteMetric=$item[3]}}
    }}
}}
function Remove-NetRoute {{ [CmdletBinding(SupportsShouldProcess)]param([Parameter(ValueFromPipeline)]$InputObject) process {{ 'removed ' + $InputObject.DestinationPrefix + ' ' + $InputObject.InterfaceIndex + ' ' + $InputObject.NextHop + ' ' + $InputObject.RouteMetric }} }}
{}
"#,
            remove_route_script(&route())
        );
        assert_eq!(
            powershell(&script).unwrap(),
            "removed 192.0.2.25/32 7 192.0.2.1 1"
        );
    }

    #[test]
    fn real_query_failure_is_not_reported_as_success() {
        let script = format!(
            "function Get-NetRoute {{ throw 'Не удалось прочитать маршруты' }}; {}",
            remove_route_script(&route())
        );
        let error = powershell(&script).unwrap_err();
        assert!(error.contains("Не удалось прочитать маршруты"), "{error}");
    }
}
