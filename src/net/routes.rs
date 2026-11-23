#[cfg(windows)]
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
#[cfg(windows)]
use std::{fs, path::PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RoutePolicy {
    Physical,
    #[cfg(windows)]
    System,
}

#[cfg(windows)]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct OwnedRoute {
    ip: Ipv4Addr,
    gateway: Ipv4Addr,
    interface: u32,
}
#[cfg(windows)]
fn state_path() -> PathBuf {
    super::relay::log_dir().join("owned_routes.json")
}
#[cfg(windows)]
fn load() -> Result<Vec<OwnedRoute>, String> {
    match fs::read(state_path()) {
        Ok(b) => serde_json::from_slice(&b).map_err(|e| format!("Журнал маршрутов: {e}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.to_string()),
    }
}
#[cfg(windows)]
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
    return prepare_probe_routes(extra, &mut Vec::new());
    #[cfg(not(target_os = "windows"))]
    {
        let _ = extra;
        Ok(())
    }
}

/// Setup holds the configuration lock while staging routes for its probes.
/// A rejected ranking must not leave those routes installed or retire old ones.
pub(super) fn with_probe_routes<T>(
    policy: RoutePolicy,
    probe: impl FnOnce(&mut dyn FnMut(&[Ipv4Addr]) -> Result<(), String>) -> Result<T, String>,
) -> Result<T, String> {
    #[cfg(windows)]
    {
        let path = state_path();
        let previous = match fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.to_string()),
        };
        let mut changes = Vec::new();
        let result = match policy {
            RoutePolicy::Physical => probe(&mut |ips| prepare_probe_routes(ips, &mut changes)),
            RoutePolicy::System => {
                release_owned_routes(&mut changes).and_then(|()| probe(&mut |_| Ok(())))
            }
        };
        if let Err(error) = result {
            let rollback = restore_probe_routes(&path, previous, &changes, |script| {
                powershell(script).map(|_| ())
            });
            return match rollback {
                Ok(()) => Err(error),
                Err(rollback_error) => Err(format!(
                    "{error}. Не удалось восстановить маршруты: {rollback_error}"
                )),
            };
        }
        result
    }
    #[cfg(not(windows))]
    {
        let _ = policy;
        probe(&mut sync_physical_hosts)
    }
}

#[cfg(windows)]
fn release_owned_routes(changes: &mut Vec<RouteChange>) -> Result<(), String> {
    let owned = load()?;
    if !owned.is_empty() {
        remove_recorded_routes(&owned, changes, powershell)?;
        save(&[])?;
    }
    Ok(())
}

#[cfg(windows)]
fn remove_recorded_routes(
    routes: &[OwnedRoute],
    changes: &mut Vec<RouteChange>,
    mut run: impl FnMut(&str) -> Result<String, String>,
) -> Result<(), String> {
    for route in routes {
        if run(&remove_route_script(route))? == "removed" {
            changes.push(RouteChange::Removed(route.clone()));
        }
    }
    Ok(())
}

#[cfg(windows)]
enum RouteChange {
    Added(OwnedRoute),
    Removed(OwnedRoute),
}

#[cfg(windows)]
fn restore_probe_routes(
    journal: &std::path::Path,
    previous: Option<Vec<u8>>,
    changes: &[RouteChange],
    run: impl FnMut(&str) -> Result<(), String>,
) -> Result<(), String> {
    undo_probe_routes(changes, run)?;
    match previous {
        Some(bytes) if fs::read(journal).ok().as_ref() != Some(&bytes) => {
            crate::system::fs_utils::robust_write_file(journal, &bytes)
        }
        None => match fs::remove_file(journal) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.to_string()),
        },
        _ => Ok(()),
    }
}

#[cfg(windows)]
fn undo_probe_routes(
    changes: &[RouteChange],
    mut run: impl FnMut(&str) -> Result<(), String>,
) -> Result<(), String> {
    let mut errors = Vec::new();
    for change in changes.iter().rev() {
        let script = match change {
            RouteChange::Added(route) => remove_route_script(route),
            RouteChange::Removed(route) => format!(
                "{}; if ($ownedMatches.Count -eq 0) {{ {} }}",
                exact_route_query(route),
                add_route_script(route)
            ),
        };
        if let Err(error) = run(&script) {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

#[cfg(windows)]
fn prepare_probe_routes(extra: &[Ipv4Addr], changes: &mut Vec<RouteChange>) -> Result<(), String> {
    let (interface, gateway) =
        super::egress::detect_physical().ok_or("Не найден физический адаптер")?;
    let gateway: Ipv4Addr = gateway.parse().map_err(|_| "Некорректный шлюз")?;
    sync_physical_hosts_on(interface, gateway, extra, changes)
}

/// ActiveStore is cleared at boot. Rebuild the recorded destinations against
/// today's physical gateway, retaining the same ownership checks as setup.
#[cfg(windows)]
pub(super) fn restore_recorded_routes(interface: u32, gateway: Ipv4Addr) -> Result<(), String> {
    let owned = load()?;
    if !owned.is_empty() {
        let destinations: Vec<_> = owned.iter().map(|route| route.ip).collect();
        sync_physical_hosts_on(interface, gateway, &destinations, &mut Vec::new())?;
    }
    Ok(())
}

#[cfg(windows)]
fn sync_physical_hosts_on(
    interface: u32,
    gateway: Ipv4Addr,
    extra: &[Ipv4Addr],
    changes: &mut Vec<RouteChange>,
) -> Result<(), String> {
    if interface == 0 || gateway.is_unspecified() {
        return Err("Не найден физический выход в интернет".into());
    }
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
            "foreign" => {
                // A different bypass may deliberately route this provider
                // through its tunnel. Preserve that route and let the DNS
                // and TLS probes decide whether this candidate is usable.
                super::relay::log_event(&format!(
                    "Существующий маршрут {ip}/32 сохранён; проверяем доступность по текущему пути"
                ));
                continue;
            }
            "owned-stale" => {
                // Move only exact recorded routes when Wi-Fi/gateway changes.
                let retired: Vec<_> = owned
                    .iter()
                    .filter(|r| r.ip == ip && *r != &route)
                    .cloned()
                    .collect();
                for old in retired {
                    if powershell(&remove_route_script(&old))? == "removed" {
                        changes.push(RouteChange::Removed(old.clone()));
                    }
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
        powershell(&add_route_script(&route))?;
        changes.push(RouteChange::Added(route));
    }
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
    format!("$r=@(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {{ $_.DestinationPrefix -eq '{}/32' }}); if ($r.Count -eq 0) {{ 'missing' }} elseif (@($r | Where-Object {{ $_.InterfaceIndex -eq {} -and $_.NextHop -eq '{}' }}).Count -gt 0) {{ 'present' }} elseif (@($r | Where-Object {{ -not ({tracked}) }}).Count -eq 0) {{ 'owned-stale' }} else {{ 'foreign' }}", route.ip, route.interface, route.gateway)
}
#[cfg(windows)]
fn add_route_script(route: &OwnedRoute) -> String {
    format!("New-NetRoute -DestinationPrefix '{}/32' -InterfaceIndex {} -NextHop '{}' -RouteMetric 1 -PolicyStore ActiveStore | Out-Null", route.ip, route.interface, route.gateway)
}
#[cfg(windows)]
pub fn remove_static_routes() -> Result<(), String> {
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
    Ok(())
}

#[cfg(windows)]
fn exact_route_query(route: &OwnedRoute) -> String {
    // Query the table first: an absent exact-prefix query is a CIM error even
    // with SilentlyContinue, and can make powershell.exe return exit code 1.
    format!("$ownedMatches=@(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {{ $_.DestinationPrefix -eq '{}/32' -and $_.InterfaceIndex -eq {} -and $_.NextHop -eq '{}' -and $_.RouteMetric -eq 1 }})", route.ip, route.interface, route.gateway)
}

#[cfg(windows)]
fn remove_route_script(route: &OwnedRoute) -> String {
    format!("{}; foreach ($ownedMatch in $ownedMatches) {{ $ownedMatch | Remove-NetRoute -Confirm:$false -ErrorAction Stop }}; if ($ownedMatches.Count -gt 0) {{ 'removed' }}", exact_route_query(route))
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn system_route_migration_can_undo_a_partial_release() {
        let released = route();
        let pending = OwnedRoute {
            ip: "192.0.2.26".parse().unwrap(),
            ..released.clone()
        };
        let mut changes = Vec::new();
        let result = remove_recorded_routes(&[released, pending], &mut changes, |script| {
            if script.contains("192.0.2.25/32") {
                Ok("removed".into())
            } else {
                Err("route table unavailable".into())
            }
        });
        assert_eq!(result.unwrap_err(), "route table unavailable");
        let mut restored = Vec::new();
        undo_probe_routes(&changes, |script| {
            restored.push(script.to_owned());
            Ok(())
        })
        .unwrap();
        assert_eq!(restored.len(), 1);
        assert!(restored[0].contains("New-NetRoute -DestinationPrefix '192.0.2.25/32'"));
    }

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
            (7, "192.0.2.1", 99, Some("foreign")),
            (8, "192.0.2.1", 1, Some("foreign")),
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
    fn mixed_foreign_and_owned_stale_routes_are_preserved() {
        let old = route();
        let desired = OwnedRoute {
            interface: 9,
            gateway: "192.0.2.254".parse().unwrap(),
            ..old.clone()
        };
        for reverse in ["$true", "$false"] {
            let script = format!(
                r#"
$script:routes=@(
    [pscustomobject]@{{DestinationPrefix='192.0.2.25/32';InterfaceIndex=7;NextHop='192.0.2.1';RouteMetric=1}},
    [pscustomobject]@{{DestinationPrefix='192.0.2.25/32';InterfaceIndex=8;NextHop='192.0.2.2';RouteMetric=5}}
)
if ({reverse}) {{ [array]::Reverse($script:routes) }}
function Get-NetRoute {{ param($AddressFamily,$PolicyStore,$ErrorAction) $script:routes }}
function Remove-NetRoute {{ throw 'unexpected route deletion' }}
function New-NetRoute {{ throw 'unexpected route creation' }}
{}
'remaining=' + $script:routes.Count
"#,
                inspect_route_script(&desired, &[old.clone()])
            );
            let lines: Vec<_> = powershell(&script)
                .unwrap()
                .lines()
                .map(str::to_owned)
                .collect();
            assert_eq!(lines, ["foreign", "remaining=2"]);
        }
    }

    #[test]
    fn existing_desired_route_and_foreign_route_are_both_preserved() {
        for reverse in ["$true", "$false"] {
            let script = format!(
                r#"
$script:routes=@(
    [pscustomobject]@{{DestinationPrefix='192.0.2.25/32';InterfaceIndex=7;NextHop='192.0.2.1';RouteMetric=1}},
    [pscustomobject]@{{DestinationPrefix='192.0.2.25/32';InterfaceIndex=8;NextHop='192.0.2.2';RouteMetric=5}}
)
if ({reverse}) {{ [array]::Reverse($script:routes) }}
function Get-NetRoute {{ param($AddressFamily,$PolicyStore,$ErrorAction) $script:routes }}
function Remove-NetRoute {{ throw 'unexpected route deletion' }}
function New-NetRoute {{ throw 'unexpected route creation' }}
{}
'remaining=' + $script:routes.Count
"#,
                inspect_route_script(&route(), &[])
            );
            let lines: Vec<_> = powershell(&script)
                .unwrap()
                .lines()
                .map(str::to_owned)
                .collect();
            assert_eq!(lines, ["present", "remaining=2"]);
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
            powershell(&script).unwrap().lines().collect::<Vec<_>>(),
            ["removed 192.0.2.25/32 7 192.0.2.1 1", "removed"]
        );
    }

    #[test]
    fn rejected_probe_removes_new_route_before_restoring_displaced_owned_route() {
        let old = route();
        let new = OwnedRoute {
            interface: 9,
            ..old.clone()
        };
        let changes = [RouteChange::Removed(old), RouteChange::Added(new)];
        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("owned_routes.json");
        fs::write(&journal, b"updated journal").unwrap();
        let mut scripts = Vec::new();
        restore_probe_routes(
            &journal,
            Some(b"previous journal".to_vec()),
            &changes,
            |script| {
                scripts.push(script.to_owned());
                Ok(())
            },
        )
        .unwrap();
        assert!(scripts[0].contains("InterfaceIndex -eq 9"));
        assert!(scripts[0].contains("Remove-NetRoute"));
        assert!(scripts[1].contains("InterfaceIndex -eq 7"));
        assert!(scripts[1].contains("New-NetRoute"));
        assert_eq!(fs::read(journal).unwrap(), b"previous journal");
    }

    #[test]
    fn real_query_failure_is_not_reported_as_success() {
        for check in [
            inspect_route_script(&route(), &[]),
            remove_route_script(&route()),
        ] {
            let script = format!(
                "function Get-NetRoute {{ throw 'Не удалось прочитать маршруты' }}; function Remove-NetRoute {{ throw 'unexpected route deletion' }}; function New-NetRoute {{ throw 'unexpected route creation' }}; {check}"
            );
            let error = powershell(&script).unwrap_err();
            assert!(error.contains("Не удалось прочитать маршруты"), "{error}");
        }
    }
}
