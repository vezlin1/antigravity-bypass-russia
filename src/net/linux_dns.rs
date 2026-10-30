//! Linux resolver ownership and passthrough. Only AI domains use SmartDNS.
use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::{IpAddr, SocketAddr, UdpSocket},
    path::Path,
    time::Duration,
};

#[derive(Serialize, Deserialize)]
enum Backend {
    File {
        original: Vec<u8>,
        applied: Vec<u8>,
    },
    Resolved {
        interface: String,
        domains: Vec<String>,
        default_route: bool,
    },
}

#[derive(Serialize, Deserialize)]
struct Plan {
    servers: Vec<IpAddr>,
    backend: Backend,
}

fn state_path() -> std::path::PathBuf {
    super::relay::log_dir().join("linux-dns.json")
}

fn read_plan() -> Result<Option<Plan>, String> {
    match fs::read(state_path()) {
        Ok(bytes) => {
            let plan: Plan = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            validate_servers(&plan.servers)?;
            Ok(Some(plan))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

fn validate_servers(servers: &[IpAddr]) -> Result<(), String> {
    if servers.is_empty()
        || servers.len() > 16
        || servers.iter().any(|s| {
            s.to_string() == super::relay::LISTEN_IP || s.is_unspecified() || s.is_multicast()
        })
    {
        return Err("Не найдены исходные DNS-серверы Linux; настройки сохранены".into());
    }
    Ok(())
}

fn run(args: &[String]) -> Result<String, String> {
    let out = crate::system::command::output("resolvectl", args).map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "resolvectl: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn values(kind: &str, link: impl ToString) -> Result<Vec<String>, String> {
    let text = run(&[kind.into(), link.to_string()])?;
    let (_, values) = text.split_once(':').ok_or("Неизвестный ответ resolvectl")?;
    Ok(values.split_whitespace().map(String::from).collect())
}

fn set_values(kind: &str, link: impl ToString, values: &[String]) -> Result<(), String> {
    let mut args = vec![kind.into(), link.to_string()];
    if values.is_empty() {
        args.push(String::new());
    } else {
        args.extend_from_slice(values);
    }
    run(&args).map(|_| ())
}

fn routed_domains(original: &[String], default_route: bool) -> Vec<String> {
    let mut domains = original.to_vec();
    // Adding a route-only suffix makes resolved's automatic DefaultRoute false.
    // Preserve the original default path explicitly; ordinary queries are then
    // passed through to the saved DNS servers. Rollback removes this domain.
    if default_route && !domains.iter().any(|domain| domain == "~.") {
        domains.push("~.".into());
    }
    for name in super::provider::nrpt_domains() {
        let name = format!("~{}", name.trim_start_matches('.'));
        if !domains.contains(&name) {
            domains.push(name);
        }
    }
    domains
}

pub fn is_target(name: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    super::provider::nrpt_domains().iter().any(|domain| {
        let suffix = domain.trim_start_matches('.');
        name == suffix || (domain.starts_with('.') && name.ends_with(&format!(".{suffix}")))
    })
}

fn file_plan(original: &[u8]) -> Result<Plan, String> {
    let text = std::str::from_utf8(original).map_err(|_| "resolv.conf не является UTF-8")?;
    let mut servers = Vec::new();
    let mut applied = format!(
        "# ANTIGRAVITY-BYPASS-RUSSIA\nnameserver {}\n",
        super::relay::LISTEN_IP
    );
    for line in text.split_inclusive('\n') {
        let fields: Vec<_> = line
            .split('#')
            .next()
            .unwrap_or("")
            .split_whitespace()
            .collect();
        if fields.first() == Some(&"nameserver") {
            let server: IpAddr = fields
                .get(1)
                .ok_or("Пустой nameserver")?
                .parse()
                .map_err(|_| "Некорректный nameserver")?;
            if !servers.contains(&server) {
                servers.push(server);
            }
        } else {
            applied.push_str(line);
        }
    }
    validate_servers(&servers)?;
    Ok(Plan {
        servers,
        backend: Backend::File {
            original: original.to_vec(),
            applied: applied.into_bytes(),
        },
    })
}

pub fn prepare(if_index: u32) -> Result<(), String> {
    if let Some(plan) = read_plan()? {
        return validate_current(&plan);
    }
    let plan = if if_index > 0 && run(&["status".into(), if_index.to_string()]).is_ok() {
        let servers = values("dns", if_index)?
            .iter()
            .map(|s| {
                s.parse::<IpAddr>()
                    .map_err(|_| "Неподдерживаемый формат DNS resolvectl".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        validate_servers(&servers)?;
        let default_route = match values("default-route", if_index)?.as_slice() {
            [value] if value == "yes" => true,
            [value] if value == "no" => false,
            _ => {
                return Err(
                    "Неизвестная настройка default-route systemd-resolved; DNS сохранён".into(),
                )
            }
        };
        Plan {
            servers,
            backend: Backend::Resolved {
                // Interface indices can change at boot or after a reconnect.
                interface: interface_name(if_index)?,
                domains: values("domain", if_index)?,
                default_route,
            },
        }
    } else {
        let path = Path::new("/etc/resolv.conf");
        if fs::symlink_metadata(path)
            .map_err(|e| e.to_string())?
            .file_type()
            .is_symlink()
        {
            return Err("resolv.conf управляется другой службой, а systemd-resolved недоступен; настройки DNS сохранены".into());
        }
        file_plan(&fs::read(path).map_err(|e| e.to_string())?)?
    };
    crate::system::fs_utils::robust_write_file(
        &state_path(),
        &serde_json::to_vec(&plan).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

fn interface_name(index: u32) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    {
        let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
        if !unsafe { libc::if_indextoname(index, name.as_mut_ptr()) }.is_null() {
            return unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }
                .to_str()
                .map(str::to_owned)
                .map_err(|_| "Некорректное имя интерфейса".into());
        }
    }
    let _ = index;
    Err("Сетевой интерфейс уже изменился; повторите настройку".into())
}

fn interface_index(interface: &str) -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        let name = std::ffi::CString::new(interface).ok()?;
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        return (index > 0).then_some(index);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = interface;
        None
    }
}

fn original_dns(plan: &Plan) -> Vec<String> {
    plan.servers.iter().map(ToString::to_string).collect()
}

fn validate_current(plan: &Plan) -> Result<(), String> {
    match &plan.backend {
        Backend::File { original, applied } => {
            let current = fs::read("/etc/resolv.conf").map_err(|e| e.to_string())?;
            if &current != original && &current != applied {
                return Err(
                    "resolv.conf изменён другой программой; файл и резервная копия сохранены"
                        .into(),
                );
            }
        }
        Backend::Resolved {
            interface,
            domains,
            default_route,
        } => {
            let dns = values("dns", interface)?;
            let current_domains = values("domain", interface)?;
            if (dns != original_dns(plan) && dns != [super::relay::LISTEN_IP])
                || (current_domains != *domains
                    && current_domains != routed_domains(domains, *default_route))
            {
                return Err("DNS интерфейса изменён другой программой; настройки и резервная копия сохранены".into());
            }
        }
    }
    Ok(())
}

pub fn apply() -> Result<(), String> {
    let Some(plan) = read_plan()? else {
        return Ok(());
    };
    validate_current(&plan)?;
    match &plan.backend {
        Backend::File { original, applied } => {
            let before = fs::read("/etc/resolv.conf").map_err(|e| e.to_string())?;
            if &before == applied
                && !crate::system::journal::verify_recorded_file(Path::new("/etc/resolv.conf"))?
            {
                return Err("Нет подтверждённой резервной копии resolv.conf".into());
            }
            if &before == original {
                crate::system::journal::apply(
                    Path::new("/etc/resolv.conf"),
                    Some(original),
                    applied,
                    "linux-dns",
                )?;
            }
            Ok(())
        }
        Backend::Resolved {
            interface,
            domains,
            default_route,
        } => {
            set_values("dns", interface, &[super::relay::LISTEN_IP.into()])?;
            if let Err(error) = set_values(
                "domain",
                interface,
                &routed_domains(domains, *default_route),
            ) {
                let restore = set_values("dns", interface, &original_dns(&plan));
                return Err(format!("{error}; восстановление DNS: {restore:?}"));
            }
            Ok(())
        }
    }
}

pub fn remove() -> Result<(), String> {
    let Some(plan) = read_plan()? else {
        return Ok(());
    };
    validate_current(&plan)?;
    match &plan.backend {
        Backend::File { original, .. } => {
            crate::system::journal::restore(Path::new("/etc/resolv.conf"))?;
            if fs::read("/etc/resolv.conf").map_err(|e| e.to_string())? != *original {
                return Err(
                    "Не восстановлен исходный resolv.conf; служба оставлена включённой".into(),
                );
            }
        }
        Backend::Resolved {
            interface, domains, ..
        } => {
            set_values("domain", interface, domains)?;
            set_values("dns", interface, &original_dns(&plan))?;
        }
    }
    fs::remove_file(state_path()).map_err(|e| e.to_string())
}

/// Preserve ordinary DNS, including private names and AAAA/SVCB queries.
pub fn passthrough(query: &[u8]) -> Option<Vec<u8>> {
    let plan = read_plan().ok()??;
    for server in &plan.servers {
        let address = match server {
            IpAddr::V6(ip) if ip.is_unicast_link_local() => {
                let Backend::Resolved { interface, .. } = &plan.backend else {
                    continue;
                };
                let Some(scope) = interface_index(interface) else {
                    continue;
                };
                SocketAddr::V6(std::net::SocketAddrV6::new(*ip, 53, 0, scope))
            }
            _ => SocketAddr::new(*server, 53),
        };
        if let Some(reply) = forward(query, address) {
            return Some(reply);
        }
    }
    None
}

fn forward(query: &[u8], server: SocketAddr) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind(if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .ok()?;
    socket.connect(server).ok()?;
    socket
        .set_read_timeout(Some(Duration::from_millis(800)))
        .ok()?;
    socket
        .set_write_timeout(Some(Duration::from_millis(800)))
        .ok()?;
    socket.send(query).ok()?;
    let mut bytes = vec![0; 65535];
    let n = socket.recv(&mut bytes).ok()?;
    bytes.truncate(n);
    if !super::client::response_matches(query, &bytes) {
        return None;
    }
    if bytes[2] & 2 != 0 {
        use std::io::{Read, Write};
        let mut stream =
            std::net::TcpStream::connect_timeout(&server, Duration::from_millis(800)).ok()?;
        stream
            .set_read_timeout(Some(Duration::from_millis(800)))
            .ok()?;
        stream
            .set_write_timeout(Some(Duration::from_millis(800)))
            .ok()?;
        stream
            .write_all(&u16::try_from(query.len()).ok()?.to_be_bytes())
            .ok()?;
        stream.write_all(query).ok()?;
        let mut length = [0; 2];
        stream.read_exact(&mut length).ok()?;
        bytes.resize(u16::from_be_bytes(length) as usize, 0);
        stream.read_exact(&mut bytes).ok()?;
    }
    super::client::response_matches(query, &bytes).then_some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resolver_plan_keeps_search_and_options_and_rejects_loops() {
        let original = b"# custom DNS\nsearch corp.test\nnameserver 192.0.2.1\nnameserver 2001:db8::53\noptions ndots:2\n";
        let plan = file_plan(original).unwrap();
        assert_eq!(plan.servers.len(), 2);
        let Backend::File {
            original: saved,
            applied,
        } = plan.backend
        else {
            panic!()
        };
        assert_eq!(saved, original);
        let text = String::from_utf8(applied).unwrap();
        assert!(text.contains("search corp.test\n") && text.contains("options ndots:2\n"));
        assert_eq!(text.matches("nameserver ").count(), 1);
        assert!(
            file_plan(format!("nameserver {}\n", super::super::relay::LISTEN_IP).as_bytes())
                .is_err()
        );
        assert!(file_plan(b"options ndots:2\n").is_err());
    }
    #[test]
    fn browser_subdomains_and_cli_eligibility_use_smartdns_but_other_names_do_not() {
        for host in [
            "aicode.googleapis.com",
            "gemini.google.com",
            "api.aistudio.google.com",
            "GEMINI.GOOGLE.COM.",
        ] {
            assert!(is_target(host), "{host}");
        }
        for host in [
            "corp.test",
            "oauth2.googleapis.com",
            "fakegemini.google.com",
            "gemini.google.com.attacker.test",
        ] {
            assert!(!is_target(host), "{host}");
        }
        let domains = routed_domains(&["corp.test".into()], true);
        assert!(
            domains.contains(&"corp.test".into())
                && domains.contains(&"~aicode.googleapis.com".into())
        );
        assert!(domains.contains(&"~.".into()));
        assert!(!routed_domains(&["corp.test".into()], false).contains(&"~.".into()));
        assert_eq!(routed_domains(&domains, true), domains);
    }
    #[test]
    fn passthrough_keeps_non_ai_aaaa_answers_unchanged() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut query = super::super::client::build_query("corp.test", 42);
        let len = query.len();
        query[len - 4..len - 2].copy_from_slice(&28u16.to_be_bytes());
        let expected = super::super::client::nodata_response(&query);
        let reply = expected.clone();
        let task = std::thread::spawn(move || {
            let mut packet = [0; 512];
            let (_, peer) = server.recv_from(&mut packet).unwrap();
            server.send_to(&reply, peer).unwrap();
        });
        assert_eq!(forward(&query, addr).unwrap(), expected);
        task.join().unwrap();
    }
}
