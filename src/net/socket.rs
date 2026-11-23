use std::fs;
use std::net::UdpSocket;
use std::path::PathBuf;

const TCP_BACKUP_NAME: &str = "tcp_backup.conf";

fn tcp_backup_path() -> PathBuf {
    crate::net::relay::log_dir().join(TCP_BACKUP_NAME)
}

// ---------------------------------------------------------------------------
// Low-Level Socket Option Helpers
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
mod win_sock {
    #[link(name = "ws2_32")]
    extern "system" {
        pub fn setsockopt(
            s: usize,
            level: i32,
            optname: i32,
            optval: *const u8,
            optlen: i32,
        ) -> i32;
        pub fn WSAGetLastError() -> i32;
    }
}

// ---------------------------------------------------------------------------
// UDP Socket Utilities (Interface Binding & Buffers)
// ---------------------------------------------------------------------------

pub fn bind_socket_to_interface(sock: &UdpSocket, if_index: u32) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawSocket;
        bind_ipv4_interface(sock.as_raw_socket(), if_index)
    }

    #[cfg(target_os = "macos")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = sock.as_raw_fd();
        let idx = if_index as libc::c_int;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                25, // IP_BOUND_IF
                &idx as *const _ as *const libc::c_void,
                std::mem::size_of_val(&idx) as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err("setsockopt(IP_BOUND_IF) failed".to_string());
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = sock.as_raw_fd();
        let mut ifname = [0u8; libc::IF_NAMESIZE];
        let name_ptr =
            unsafe { libc::if_indextoname(if_index, ifname.as_mut_ptr() as *mut libc::c_char) };
        if !name_ptr.is_null() {
            let len = unsafe { libc::strlen(ifname.as_ptr() as *const libc::c_char) };
            let result = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    ifname.as_ptr() as *const libc::c_void,
                    (len + 1) as libc::socklen_t,
                )
            };
            if result != 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
        } else {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = (sock, if_index);
        Ok(())
    }
}

#[cfg(windows)]
pub(super) fn bind_ipv4_interface(
    socket: std::os::windows::io::RawSocket,
    index: u32,
) -> Result<(), String> {
    const IPPROTO_IP: i32 = 0;
    const IP_UNICAST_IF: i32 = 31;
    let bytes = index.to_be_bytes();
    if unsafe {
        win_sock::setsockopt(
            socket as usize,
            IPPROTO_IP,
            IP_UNICAST_IF,
            bytes.as_ptr(),
            4,
        )
    } != 0
    {
        return Err(format!("IP_UNICAST_IF: {}", unsafe {
            win_sock::WSAGetLastError()
        }));
    }
    Ok(())
}
pub fn set_socket_buffers(sock: &UdpSocket, size: i32) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawSocket;
        #[link(name = "ws2_32")]
        extern "system" {
            fn setsockopt(
                s: usize,
                level: i32,
                optname: i32,
                optval: *const u8,
                optlen: i32,
            ) -> i32;
        }
        const SOL_SOCKET: i32 = 0xFFFF;
        const SO_RCVBUF: i32 = 0x1002;
        const SO_SNDBUF: i32 = 0x1001;

        let raw = sock.as_raw_socket() as usize;
        let bytes = size.to_ne_bytes();
        unsafe {
            let _ = setsockopt(raw, SOL_SOCKET, SO_RCVBUF, bytes.as_ptr(), 4);
            let _ = setsockopt(raw, SOL_SOCKET, SO_SNDBUF, bytes.as_ptr(), 4);
        }
        Ok(())
    }

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = sock.as_raw_fd();
        let size_c = size as libc::c_int;
        unsafe {
            let _ = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &size_c as *const _ as *const libc::c_void,
                std::mem::size_of_val(&size_c) as libc::socklen_t,
            );
            let _ = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &size_c as *const _ as *const libc::c_void,
                std::mem::size_of_val(&size_c) as libc::socklen_t,
            );
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "windows", unix)))]
    {
        let _ = (sock, size);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// OS-Level Network Stack Tuning & Status Inspection
// ---------------------------------------------------------------------------

/// Queries the current OS TCP network stack configuration and returns a structured summary.
pub fn get_os_network_status() -> String {
    #[cfg(target_os = "windows")]
    {
        let mut lines = Vec::new();
        lines.push("OS Network Stack Status (Windows TCP Global Parameters):".to_string());

        if let Ok(output) =
            crate::system::command::output("netsh", ["int", "tcp", "show", "global"])
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let line_lower = line.to_lowercase();
                if let Some((_, val)) = line.split_once(':') {
                    let v = val.trim();
                    let v_lower = v.to_lowercase();
                    if line_lower.contains("autotuning") || line_lower.contains("автонастро")
                    {
                        let note = if v_lower == "normal" {
                            " [optimal]"
                        } else {
                            " [suboptimal: recommend normal]"
                        };
                        lines.push(format!("  - Receive Window Auto-Tuning: {}{}", v, note));
                    } else if line_lower.contains("receive-side scaling")
                        || line_lower.contains("масштабирования на стороне приема")
                    {
                        let note = if v_lower == "enabled" {
                            " [optimal]"
                        } else {
                            " [disabled]"
                        };
                        lines.push(format!("  - Receive-Side Scaling (RSS): {}{}", v, note));
                    } else if line_lower.contains("fast open")
                        && !line_lower.contains("откат")
                        && !line_lower.contains("fallback")
                    {
                        let note = if v_lower == "enabled" {
                            " [optimal]"
                        } else {
                            " [disabled]"
                        };
                        lines.push(format!("  - TCP Fast Open (TFO): {}{}", v, note));
                    } else if line_lower.contains("hystart") {
                        let note = if v_lower == "enabled" {
                            " [optimal]"
                        } else {
                            " [disabled]"
                        };
                        lines.push(format!("  - HyStart Slow-Start: {}{}", v, note));
                    } else if line_lower.contains("proportional rate")
                        || line_lower.contains("коэффициента пропорции")
                    {
                        let note = if v_lower == "enabled" {
                            " [optimal]"
                        } else {
                            " [disabled]"
                        };
                        lines.push(format!("  - Proportional Rate Reduction: {}{}", v, note));
                    } else if line_lower.contains("timestamps")
                        || line_lower.contains("метки времени")
                    {
                        lines.push(format!("  - RFC 1323 Timestamps: {}", v));
                    }
                }
            }
        }

        if let Ok(output) =
            crate::system::command::output("netsh", ["int", "tcp", "show", "heuristics"])
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let line_lower = line.to_lowercase();
                if (line_lower.contains("heuristic") || line_lower.contains("эвристик"))
                    && line.contains(':')
                {
                    if let Some((_, val)) = line.split_once(':') {
                        let v = val.trim();
                        let note = if v.to_lowercase() == "disabled" {
                            " [optimal]"
                        } else {
                            " [enabled - may throttle TCP]"
                        };
                        lines.push(format!("  - Window Scaling Heuristics: {}{}", v, note));
                        break;
                    }
                }
            }
        }

        if lines.len() == 1 {
            lines.push("  - Unable to query netsh TCP parameters".to_string());
        }

        lines.join("\n")
    }

    #[cfg(target_os = "macos")]
    {
        let mut lines = Vec::new();
        lines.push("OS Network Stack Status (macOS sysctl Parameters):".to_string());

        let sysctl_keys = [
            ("net.inet.tcp.autorcvbufmax", "TCP Auto-Receive Buffer Max"),
            ("net.inet.tcp.autosndbufmax", "TCP Auto-Send Buffer Max"),
            ("net.inet.tcp.autorcvbuf", "TCP Auto-Receive Dynamic Buffer"),
            ("net.inet.tcp.autosndbuf", "TCP Auto-Send Dynamic Buffer"),
            ("net.inet.tcp.sendspace", "TCP Default Send Space"),
            ("net.inet.tcp.recvspace", "TCP Default Recv Space"),
            ("kern.ipc.maxsockbuf", "Kernel Max Socket Buffer"),
            ("net.inet.tcp.fastopen", "TCP Fast Open"),
        ];

        let keys: Vec<&str> = sysctl_keys.iter().map(|(key, _)| *key).collect();
        let values = sysctl_values(&keys);
        for ((key, label), batch) in sysctl_keys.iter().zip(values) {
            let val = batch.or_else(|| {
                let output = crate::system::command::output("sysctl", ["-n", key]).ok()?;
                Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
            });
            if let Some(val) = val.filter(|val| !val.is_empty()) {
                lines.push(format!("  - {}: {}", label, val));
            }
        }

        if lines.len() == 1 {
            lines.push("  - Unable to query sysctl TCP parameters".to_string());
        }

        lines.join("\n")
    }

    #[cfg(target_os = "linux")]
    {
        let mut lines = Vec::new();
        lines.push("OS Network Stack Status (Linux sysctl Parameters):".to_string());

        let sysctl_keys = [
            ("net.ipv4.tcp_window_scaling", "TCP Window Scaling"),
            ("net.core.rmem_max", "Core Max Receive Buffer"),
            ("net.core.wmem_max", "Core Max Send Buffer"),
            ("net.ipv4.tcp_fastopen", "TCP Fast Open"),
        ];

        let keys: Vec<&str> = sysctl_keys.iter().map(|(key, _)| *key).collect();
        let values = sysctl_values(&keys);
        for ((key, label), batch) in sysctl_keys.iter().zip(values) {
            let val = batch.or_else(|| {
                let output = crate::system::command::output("sysctl", ["-n", key]).ok()?;
                Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
            });
            if let Some(val) = val.filter(|val| !val.is_empty()) {
                lines.push(format!("  - {}: {}", label, val));
            }
        }

        if lines.len() == 1 {
            lines.push("  - Unable to query sysctl TCP parameters".to_string());
        }

        lines.join("\n")
    }

    #[cfg(not(any(target_os = "windows", unix)))]
    {
        "OS network stack tuning not supported on this platform".to_string()
    }
}

/// Applies OS-level network stack fine-tuning (TCP window auto-tuning, RSS, Fast Open, etc.).
/// Backs up every modified setting to `tcp_snapshot.json` before any writes.
#[derive(serde::Serialize, serde::Deserialize)]
struct TcpSnapshot {
    platform: String,
    original: std::collections::BTreeMap<String, String>,
}

fn tcp_tunables() -> &'static [(&'static str, &'static str)] {
    #[cfg(target_os = "windows")]
    {
        &[
            ("autotuninglevel", "normal"),
            ("rss", "enabled"),
            ("fastopen", "enabled"),
            ("hystart", "enabled"),
            ("prr", "enabled"),
            ("timestamps", "allowed"),
            ("rsc", "enabled"),
            ("ecncapability", "enabled"),
            ("initialrto", "2000"),
        ]
    }
    #[cfg(target_os = "macos")]
    {
        &[
            ("net.inet.tcp.autorcvbufmax", "16777216"),
            ("net.inet.tcp.autosndbufmax", "16777216"),
            ("net.inet.tcp.autorcvbuf", "1"),
            ("net.inet.tcp.autosndbuf", "1"),
            ("net.inet.tcp.sendspace", "524288"),
            ("net.inet.tcp.recvspace", "524288"),
            ("kern.ipc.maxsockbuf", "16777216"),
            ("net.inet.tcp.fastopen", "3"),
        ]
    }
    #[cfg(target_os = "linux")]
    {
        &[
            ("net.ipv4.tcp_window_scaling", "1"),
            ("net.core.rmem_max", "16777216"),
            ("net.core.wmem_max", "16777216"),
            ("net.ipv4.tcp_fastopen", "3"),
        ]
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        &[]
    }
}
/// All values from one `sysctl -n` call, in key order. Every entry is None
/// when the combined call fails (an unknown key shifts the output lines), so
/// callers then query keys one by one as before.
#[cfg(unix)]
fn sysctl_values(keys: &[&str]) -> Vec<Option<String>> {
    let batch =
        crate::system::command::output("sysctl", std::iter::once("-n").chain(keys.iter().copied()))
            .ok()
            .filter(|out| out.status.success())
            .map(|out| {
                String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .map(|line| line.trim().to_string())
                    .collect::<Vec<_>>()
            })
            .filter(|values| values.len() == keys.len());
    match batch {
        Some(values) => values.into_iter().map(Some).collect(),
        None => vec![None; keys.len()],
    }
}

fn tcp_state_path() -> PathBuf {
    crate::net::relay::log_dir().join("tcp_snapshot.json")
}
fn capture_tcp() -> Result<TcpSnapshot, String> {
    let mut original = std::collections::BTreeMap::new();
    #[cfg(target_os = "windows")]
    {
        let out = crate::system::command::output("netsh", ["int", "tcp", "dump"])
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err("Не удалось сохранить TCP snapshot".into());
        }
        let text = String::from_utf8_lossy(&out.stdout);
        for token in text.split_whitespace() {
            if let Some((key, value)) = token.split_once('=') {
                if tcp_tunables().iter().any(|(k, _)| *k == key) {
                    original.insert(key.to_string(), value.to_string());
                }
            }
        }
    }
    #[cfg(unix)]
    {
        let keys: Vec<&str> = tcp_tunables().iter().map(|(key, _)| *key).collect();
        for (key, batch) in keys.iter().zip(sysctl_values(&keys)) {
            let value = match batch {
                Some(value) => value,
                None => {
                    let out = crate::system::command::output("sysctl", ["-n", key])
                        .map_err(|e| e.to_string())?;
                    if !out.status.success() {
                        return Err(format!("Нет snapshot {key}"));
                    }
                    String::from_utf8_lossy(&out.stdout).trim().to_string()
                }
            };
            original.insert(key.to_string(), value);
        }
    }
    if original.len() != tcp_tunables().len() || original.is_empty() {
        return Err("Неполный TCP snapshot; настройки не изменены".into());
    }
    Ok(TcpSnapshot {
        platform: std::env::consts::OS.into(),
        original,
    })
}
fn validate_snapshot(snapshot: &TcpSnapshot) -> Result<(), String> {
    if snapshot.platform != std::env::consts::OS
        || snapshot.original.len() != tcp_tunables().len()
        || tcp_tunables().iter().any(|(key, _)| {
            !snapshot.original.get(*key).is_some_and(|v| {
                !v.is_empty() && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        })
    {
        return Err("TCP snapshot повреждён, неполон или относится к другой платформе".into());
    }
    Ok(())
}
fn valid_tcp_setting(key: &str, value: &str) -> Result<(), String> {
    if !tcp_tunables().iter().any(|(k, _)| *k == key)
        || value.is_empty()
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err("Некорректный TCP snapshot".into());
    }
    Ok(())
}

/// One `netsh int tcp set global` (or `sysctl -w`) for every value instead of
/// a process per setting. If the combined command is refused, for example
/// because this OS build lacks one option, each value is written separately
/// exactly as before; callers verify the result afterwards either way.
fn write_tcp_all(values: &[(&str, &str)]) -> Result<(), String> {
    for (key, value) in values {
        valid_tcp_setting(key, value)?;
    }
    let assignments: Vec<String> = values
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect();
    #[cfg(target_os = "windows")]
    let combined = crate::system::command::output(
        "netsh",
        ["int", "tcp", "set", "global"]
            .into_iter()
            .chain(assignments.iter().map(String::as_str)),
    );
    #[cfg(not(target_os = "windows"))]
    let combined = crate::system::command::output(
        "sysctl",
        std::iter::once("-w").chain(assignments.iter().map(String::as_str)),
    );
    if combined.is_ok_and(|out| out.status.success()) {
        return Ok(());
    }
    for (key, value) in values {
        write_tcp(key, value)?;
    }
    Ok(())
}

fn write_tcp(key: &str, value: &str) -> Result<(), String> {
    valid_tcp_setting(key, value)?;
    #[cfg(target_os = "windows")]
    let result = crate::system::command::output(
        "netsh",
        ["int", "tcp", "set", "global", &format!("{key}={value}")],
    );
    #[cfg(not(target_os = "windows"))]
    let result = crate::system::command::output("sysctl", ["-w", &format!("{key}={value}")]);
    let out = result.map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("Не применён TCP {key}; snapshot сохранён"))
    }
}
pub fn tune_os_network_stack() -> Result<Vec<String>, String> {
    if !crate::system::privilege::is_admin() {
        return Err("Требуются права администратора".into());
    }
    if tcp_backup_path().exists() && !tcp_state_path().exists() {
        // Releases 1.x changed TCP without a complete snapshot. Capturing the
        // current values now could record their changes as the originals.
        return Err(format!(
            "Найден {} от версии 1.x: текущие параметры TCP могли остаться изменёнными. Сбросьте TCP к стандартным значениям (Windows: netsh int tcp reset, затем перезагрузка), удалите этот файл и повторите",
            tcp_backup_path().display()
        ));
    }
    if !tcp_state_path().exists() {
        let snapshot = capture_tcp()?;
        fs::create_dir_all(crate::net::relay::log_dir()).map_err(|e| e.to_string())?;
        crate::system::fs_utils::robust_write_file(
            &tcp_state_path(),
            &serde_json::to_vec(&snapshot).map_err(|e| e.to_string())?,
        )?;
    }
    let snapshot: TcpSnapshot =
        serde_json::from_slice(&fs::read(tcp_state_path()).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    validate_snapshot(&snapshot)?;
    write_tcp_all(tcp_tunables())?;
    let logs = tcp_tunables()
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect();
    let actual = capture_tcp()?;
    if tcp_tunables()
        .iter()
        .any(|(key, value)| actual.original.get(*key).map(String::as_str) != Some(*value))
    {
        return Err("Проверка TCP после записи не пройдена; snapshot сохранён".into());
    }
    Ok(logs)
}
fn restore_tcp_snapshot() -> Result<Vec<String>, String> {
    let snapshot: TcpSnapshot =
        serde_json::from_slice(&fs::read(tcp_state_path()).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    validate_snapshot(&snapshot)?;
    let current = capture_tcp()?;
    if tcp_tunables().iter().any(|(key, applied)| {
        current.original.get(*key) != snapshot.original.get(*key)
            && current.original.get(*key).map(String::as_str) != Some(*applied)
    }) {
        return Err("TCP изменён после настройки; текущие значения и backup сохранены".into());
    }
    let original: Vec<(&str, &str)> = snapshot
        .original
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    write_tcp_all(&original)?;
    if capture_tcp()?.original != snapshot.original {
        return Err("Проверка TCP rollback не пройдена; snapshot сохранён".into());
    }
    fs::remove_file(tcp_state_path()).map_err(|e| e.to_string())?;
    Ok(vec![
        "Исходные TCP параметры восстановлены и проверены".into()
    ])
}

/// Rollback restores only settings captured by the current engine.
pub fn restore_current_network_stack() -> Result<Vec<String>, String> {
    restore_if_current(&tcp_state_path(), restore_tcp_snapshot)
}
fn restore_if_current(
    path: &std::path::Path,
    restore: impl FnOnce() -> Result<Vec<String>, String>,
) -> Result<Vec<String>, String> {
    match fs::metadata(path) {
        Ok(_) => restore(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream, UdpSocket};
    use std::time::Duration;
    #[test]
    fn dns_rollback_ignores_unrelated_legacy_backup_but_preserves_current_errors() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("tcp_backup.conf"), "rss=enabled").unwrap();
        let current = dir.path().join("tcp_snapshot.json");
        assert!(
            restore_if_current(&current, || panic!("legacy restore must not run"))
                .unwrap()
                .is_empty()
        );
        assert!(dir.path().join("tcp_backup.conf").exists());
        fs::write(&current, "broken").unwrap();
        assert_eq!(
            restore_if_current(&current, || Err("damaged current backup".into())).unwrap_err(),
            "damaged current backup"
        );
    }
    #[test]
    fn tcp_snapshot_must_contain_every_original_setting_before_writing() {
        let mut snapshot = TcpSnapshot {
            platform: std::env::consts::OS.into(),
            original: tcp_tunables()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        };
        assert!(validate_snapshot(&snapshot).is_ok());
        snapshot
            .original
            .insert("unexpected".into(), "enabled".into());
        assert!(validate_snapshot(&snapshot).is_err());
        snapshot.original.remove("unexpected");
        snapshot.original.pop_first();
        assert!(validate_snapshot(&snapshot).is_err());
    }
    #[test]
    fn test_udp_socket_buffers() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("Udp bind failed");
        let result = set_socket_buffers(&socket, 512 * 1024);
        assert!(
            result.is_ok(),
            "set_socket_buffers on UDP socket failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_os_network_status_query() {
        let status = get_os_network_status();
        assert!(
            !status.is_empty(),
            "get_os_network_status must return a descriptive string"
        );
    }
}
