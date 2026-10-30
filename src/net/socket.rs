use std::fs;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;

pub const TCP_BUFFER_SIZE_512K: i32 = 512 * 1024; // 524,288 bytes (512 KB)
const TCP_BACKUP_NAME: &str = "tcp_backup.conf";

fn tcp_backup_path() -> PathBuf {
    crate::net::relay::log_dir().join(TCP_BACKUP_NAME)
}

// ---------------------------------------------------------------------------
// Low-Level Socket Option Helpers
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
mod win_sock {
    use std::os::windows::io::RawSocket;

    #[link(name = "ws2_32")]
    extern "system" {
        pub fn setsockopt(
            s: usize,
            level: i32,
            optname: i32,
            optval: *const u8,
            optlen: i32,
        ) -> i32;
        #[allow(dead_code)]
        pub fn getsockopt(
            s: usize,
            level: i32,
            optname: i32,
            optval: *mut u8,
            optlen: *mut i32,
        ) -> i32;
        pub fn WSAGetLastError() -> i32;
    }

    pub const SOL_SOCKET: i32 = 0xFFFF;
    pub const SO_RCVBUF: i32 = 0x1002;
    pub const SO_SNDBUF: i32 = 0x1001;

    pub fn set_socket_buffer_with_fallback(
        raw: RawSocket,
        optname: i32,
        target_size: i32,
    ) -> Result<(), String> {
        let handle = raw as usize;
        let fallbacks = [target_size, 256 * 1024, 128 * 1024, 64 * 1024];
        let mut last_err = 0;

        for &size in &fallbacks {
            if size > target_size {
                continue;
            }
            let bytes = size.to_ne_bytes();
            let ret = unsafe { setsockopt(handle, SOL_SOCKET, optname, bytes.as_ptr(), 4) };
            if ret == 0 {
                return Ok(());
            }
            last_err = unsafe { WSAGetLastError() };
        }
        Err(format!(
            "setsockopt(SOL_SOCKET, 0x{:X}) failed on raw socket, WSA error: {}",
            optname, last_err
        ))
    }

    #[allow(dead_code)]
    pub fn get_socket_buffer_size(raw: RawSocket, optname: i32) -> Result<i32, String> {
        let handle = raw as usize;
        let mut buf_size: i32 = 0;
        let mut len: i32 = 4;
        let ret = unsafe {
            getsockopt(
                handle,
                SOL_SOCKET,
                optname,
                &mut buf_size as *mut _ as *mut u8,
                &mut len,
            )
        };
        if ret == 0 {
            Ok(buf_size)
        } else {
            let last_err = unsafe { WSAGetLastError() };
            Err(format!("getsockopt failed: WSA {}", last_err))
        }
    }
}

#[cfg(unix)]
mod unix_sock {
    use std::os::unix::io::RawFd;

    pub fn set_socket_buffer_with_fallback(
        fd: RawFd,
        optname: libc::c_int,
        target_size: i32,
    ) -> Result<(), String> {
        let fallbacks = [target_size, 256 * 1024, 128 * 1024, 64 * 1024];
        let mut last_errno = 0;

        for &size in &fallbacks {
            if size > target_size {
                continue;
            }
            let size_c = size as libc::c_int;
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    optname,
                    &size_c as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&size_c) as libc::socklen_t,
                )
            };
            if ret == 0 {
                return Ok(());
            }
            last_errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        }
        Err(format!(
            "setsockopt(SOL_SOCKET, {}) failed on fd {}, errno: {}",
            optname, fd, last_errno
        ))
    }

    #[allow(dead_code)]
    pub fn get_socket_buffer_size(fd: RawFd, optname: libc::c_int) -> Result<i32, String> {
        let mut size: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                optname,
                &mut size as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if ret == 0 {
            Ok(size as i32)
        } else {
            Err(format!(
                "getsockopt failed: errno {}",
                std::io::Error::last_os_error()
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// High-Level TCP Stream & Listener Configuration
// ---------------------------------------------------------------------------

/// Queries the current SO_RCVBUF and SO_SNDBUF sizes of a TCP stream.
#[allow(dead_code)]
pub fn get_stream_buffer_sizes(stream: &TcpStream) -> Result<(i32, i32), String> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawSocket;
        let raw = stream.as_raw_socket();
        let rcv = win_sock::get_socket_buffer_size(raw, win_sock::SO_RCVBUF)?;
        let snd = win_sock::get_socket_buffer_size(raw, win_sock::SO_SNDBUF)?;
        Ok((rcv, snd))
    }

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        let rcv = unix_sock::get_socket_buffer_size(fd, libc::SO_RCVBUF)?;
        let snd = unix_sock::get_socket_buffer_size(fd, libc::SO_SNDBUF)?;
        Ok((rcv, snd))
    }

    #[cfg(not(any(target_os = "windows", unix)))]
    {
        let _ = stream;
        Ok((0, 0))
    }
}

// ---------------------------------------------------------------------------
// High-Level TCP Stream & Listener Configuration
// ---------------------------------------------------------------------------

/// Configures a TCP stream for maximum streaming performance and zero-latency interaction:
/// 1. Enforces TCP_NODELAY = true (disables Nagle algorithm to avoid Delayed-ACK latency).
/// 2. Sets SO_RCVBUF = 512 KB with graceful OS fallback ladder (512KB -> 256KB -> 128KB -> 64KB).
/// 3. Sets SO_SNDBUF = 512 KB with graceful OS fallback ladder (512KB -> 256KB -> 128KB -> 64KB).
pub fn configure_tcp_stream(stream: &TcpStream) -> Result<(), String> {
    stream
        .set_nodelay(true)
        .map_err(|e| format!("Failed to set TCP_NODELAY: {}", e))?;

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawSocket;
        let raw = stream.as_raw_socket();
        win_sock::set_socket_buffer_with_fallback(raw, win_sock::SO_RCVBUF, TCP_BUFFER_SIZE_512K)?;
        win_sock::set_socket_buffer_with_fallback(raw, win_sock::SO_SNDBUF, TCP_BUFFER_SIZE_512K)?;
        Ok(())
    }

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        unix_sock::set_socket_buffer_with_fallback(fd, libc::SO_RCVBUF, TCP_BUFFER_SIZE_512K)?;
        unix_sock::set_socket_buffer_with_fallback(fd, libc::SO_SNDBUF, TCP_BUFFER_SIZE_512K)?;
        Ok(())
    }

    #[cfg(not(any(target_os = "windows", unix)))]
    {
        let _ = stream;
        Ok(())
    }
}

/// Configures a TCP listener socket with 512 KB receive and send buffers so that
/// all newly accepted incoming connections inherit optimized TCP window capacities.
pub fn configure_tcp_listener(listener: &TcpListener) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawSocket;
        let raw = listener.as_raw_socket();
        win_sock::set_socket_buffer_with_fallback(raw, win_sock::SO_RCVBUF, TCP_BUFFER_SIZE_512K)?;
        win_sock::set_socket_buffer_with_fallback(raw, win_sock::SO_SNDBUF, TCP_BUFFER_SIZE_512K)?;
        Ok(())
    }

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = listener.as_raw_fd();
        unix_sock::set_socket_buffer_with_fallback(fd, libc::SO_RCVBUF, TCP_BUFFER_SIZE_512K)?;
        unix_sock::set_socket_buffer_with_fallback(fd, libc::SO_SNDBUF, TCP_BUFFER_SIZE_512K)?;
        Ok(())
    }

    #[cfg(not(any(target_os = "windows", unix)))]
    {
        let _ = listener;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// UDP Socket Utilities (Interface Binding & Buffers)
// ---------------------------------------------------------------------------

pub fn bind_socket_to_interface(sock: &UdpSocket, if_index: u32) -> Result<(), String> {
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
        let raw = sock.as_raw_socket() as usize;
        let be = if_index.to_be();
        let bytes = be.to_ne_bytes();
        let ret = unsafe { setsockopt(raw, 0, 31, bytes.as_ptr(), 4) };
        if ret != 0 {
            return Err("setsockopt(IP_UNICAST_IF) failed".to_string());
        }
        Ok(())
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

        for (key, label) in &sysctl_keys {
            if let Ok(output) = crate::system::command::output("sysctl", ["-n", key]) {
                let val = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !val.is_empty() {
                    lines.push(format!("  - {}: {}", label, val));
                }
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

        for (key, label) in &sysctl_keys {
            if let Ok(output) = crate::system::command::output("sysctl", ["-n", key]) {
                let val = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !val.is_empty() {
                    lines.push(format!("  - {}: {}", label, val));
                }
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
    for (key, _) in tcp_tunables() {
        let out =
            crate::system::command::output("sysctl", ["-n", key]).map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(format!("Нет snapshot {key}"));
        }
        original.insert(
            key.to_string(),
            String::from_utf8_lossy(&out.stdout).trim().to_string(),
        );
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
fn write_tcp(key: &str, value: &str) -> Result<(), String> {
    if !tcp_tunables().iter().any(|(k, _)| *k == key)
        || value.is_empty()
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err("Некорректный TCP snapshot".into());
    }
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
        return Err(
            "Обнаружен старый неполный TCP backup. Сначала разберите прежний откат.".into(),
        );
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
    let mut logs = Vec::new();
    for (key, value) in tcp_tunables() {
        write_tcp(key, value)?;
        logs.push(format!("{key}={value}"));
    }
    let actual = capture_tcp()?;
    if tcp_tunables()
        .iter()
        .any(|(key, value)| actual.original.get(*key).map(String::as_str) != Some(*value))
    {
        return Err("Проверка TCP после записи не пройдена; snapshot сохранён".into());
    }
    Ok(logs)
}
pub fn restore_os_network_stack() -> Result<Vec<String>, String> {
    if !tcp_state_path().exists() {
        return if tcp_backup_path().exists() {
            restore_legacy_tcp()
        } else {
            Ok(Vec::new())
        };
    }
    restore_tcp_snapshot()
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
    for (key, value) in &snapshot.original {
        write_tcp(key, value)?;
    }
    if capture_tcp()?.original != snapshot.original {
        return Err("Проверка TCP rollback не пройдена; snapshot сохранён".into());
    }
    fs::remove_file(tcp_state_path()).map_err(|e| e.to_string())?;
    Ok(vec![
        "Исходные TCP параметры восстановлены и проверены".into()
    ])
}

pub fn legacy_tcp_pending() -> bool {
    tcp_backup_path().exists() && !tcp_state_path().exists()
}

/// Ordinary DNS rollback restores only settings captured by the current engine.
/// An older incomplete backup remains available for explicit legacy recovery.
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

fn parse_legacy_tcp(text: &str) -> Result<std::collections::BTreeMap<String, String>, String> {
    let mut values = std::collections::BTreeMap::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let (key, value) = line
            .split_once('=')
            .ok_or("Некорректная строка TCP backup")?;
        let known = tcp_tunables().iter().any(|(k, _)| *k == key)
            || cfg!(windows)
                && matches!(
                    key,
                    "heuristics" | "congestion_internet" | "congestion_custom"
                );
        if !known
            || value.is_empty()
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || values.insert(key.into(), value.into()).is_some()
        {
            return Err(
                "TCP backup содержит неизвестный, повторный или некорректный параметр".into(),
            );
        }
    }
    if values.is_empty() {
        return Err("Старый TCP backup пуст".into());
    }
    Ok(values)
}

fn legacy_tcp_plan(
    original: &std::collections::BTreeMap<String, String>,
    current: &std::collections::BTreeMap<String, String>,
) -> (Vec<(String, String)>, Vec<String>, usize) {
    let mut required = tcp_tunables().to_vec();
    if cfg!(windows) {
        required.extend([
            ("heuristics", "disabled"),
            ("congestion_internet", "cubic"),
            ("congestion_custom", "cubic"),
        ]);
    }
    let mut writes = vec![];
    let mut unresolved = vec![];
    let mut verified = 0;
    for (key, applied) in required {
        match (original.get(key), current.get(key)) {
            (None, _) => unresolved.push(format!("{key}: исходное значение отсутствует")),
            (Some(_), None) => unresolved.push(format!("{key}: текущее значение не прочитано")),
            (Some(before), Some(now)) if before == now => verified += 1,
            (Some(before), Some(now)) if now == applied => {
                writes.push((key.into(), before.clone()))
            }
            _ => unresolved.push(format!("{key}: изменён после настройки, сохранён")),
        }
    }
    (writes, unresolved, verified)
}

#[cfg(windows)]
fn read_legacy_heuristics() -> Option<String> {
    let output =
        crate::system::command::output("netsh", ["int", "tcp", "show", "heuristics"]).ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let value = text.lines().find_map(|l| {
        l.split_once(':')
            .map(|(_, v)| v.trim().to_ascii_lowercase())
    })?;
    if matches!(value.as_str(), "enabled" | "disabled") {
        Some(value)
    } else {
        None
    }
}

fn restore_legacy_tcp() -> Result<Vec<String>, String> {
    let original =
        parse_legacy_tcp(&fs::read_to_string(tcp_backup_path()).map_err(|e| e.to_string())?)?;
    #[allow(unused_mut)]
    let mut current = capture_tcp()?.original;
    #[cfg(windows)]
    if let Some(value) = read_legacy_heuristics() {
        current.insert("heuristics".into(), value);
    }
    let (writes, mut unresolved, verified) = legacy_tcp_plan(&original, &current);
    for (key, value) in &writes {
        #[cfg(windows)]
        if key == "heuristics" {
            if !matches!(value.as_str(), "enabled" | "disabled") {
                unresolved.push("heuristics: неподдерживаемое исходное значение".into());
                continue;
            }
            let output =
                crate::system::command::output("netsh", ["int", "tcp", "set", "heuristics", value])
                    .map_err(|e| e.to_string())?;
            if !output.status.success() {
                unresolved.push("heuristics: запись не выполнена".into());
            }
            continue;
        }
        if let Err(e) = write_tcp(key, value) {
            unresolved.push(e);
        }
    }
    #[allow(unused_mut)]
    let mut after = capture_tcp()?.original;
    #[cfg(windows)]
    if let Some(value) = read_legacy_heuristics() {
        after.insert("heuristics".into(), value);
    }
    let mut restored = verified;
    for (key, value) in &writes {
        if after.get(key) == Some(value) {
            restored += 1;
        } else {
            unresolved.push(format!("{key}: восстановление не подтверждено"));
        }
    }
    if unresolved.is_empty() {
        // Keep the old backup as an archive, but do not retry a completed restore.
        let bytes = fs::read(tcp_backup_path()).map_err(|e| e.to_string())?;
        crate::system::journal::archive_legacy(&tcp_backup_path(), &bytes)?;
        fs::remove_file(tcp_backup_path()).map_err(|e| e.to_string())?;
        Ok(vec![format!(
            "Старый TCP backup: восстановлено и проверено {restored} параметров"
        )])
    } else {
        Err(format!("Старый TCP backup: восстановлено/уже совпадает {restored} параметров. Осталось: {}. Backup сохранён: {}. Для отсутствующих значений нужен прежний системный профиль; сброс к стандартным значениям — отдельная операция, не точный откат.", unresolved.join("; "), tcp_backup_path().display()))
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
    fn legacy_tcp_restores_only_recorded_values_and_preserves_later_edits() {
        let first = tcp_tunables()[0];
        let second = tcp_tunables()[1];
        let original =
            parse_legacy_tcp(&format!("{}=disabled\n{}=disabled", first.0, second.0)).unwrap();
        let current = [
            (first.0.to_string(), first.1.to_string()),
            (second.0.to_string(), "userchanged".into()),
        ]
        .into_iter()
        .collect();
        let (writes, unresolved, _) = legacy_tcp_plan(&original, &current);
        assert_eq!(writes, vec![(first.0.into(), "disabled".into())]);
        assert!(unresolved
            .iter()
            .any(|s| s.contains(second.0) && s.contains("изменён")));
        assert!(unresolved.iter().any(|s| s.contains("отсутствует")));
        assert!(parse_legacy_tcp("rss=enabled\nrss=disabled").is_err());
        assert!(parse_legacy_tcp("rss=enabled & injected").is_err());
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
    fn test_configure_tcp_stream_basic() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind test listener");
        let local_addr = listener.local_addr().expect("Failed to get local addr");

        let handle = std::thread::spawn(move || {
            let (incoming, _) = listener.accept().expect("Accept failed");
            configure_tcp_stream(&incoming).expect("Configure incoming stream failed");
            incoming
        });

        let client = TcpStream::connect_timeout(&local_addr, Duration::from_secs(2))
            .expect("Connect failed");
        configure_tcp_stream(&client).expect("Configure client stream failed");

        // Verify TCP_NODELAY is enabled on client
        assert!(
            client.nodelay().unwrap_or(false),
            "TCP_NODELAY must be true on configured client"
        );

        let incoming = handle.join().expect("Thread join failed");
        assert!(
            incoming.nodelay().unwrap_or(false),
            "TCP_NODELAY must be true on configured server stream"
        );
    }

    #[test]
    fn test_configure_tcp_listener_basic() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind listener");
        let result = configure_tcp_listener(&listener);
        assert!(
            result.is_ok(),
            "configure_tcp_listener must succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_socket_buffer_getsockopt_verification() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind listener");
        let addr = listener.local_addr().expect("Local addr failed");

        let client = TcpStream::connect(addr).expect("Connect failed");
        configure_tcp_stream(&client).expect("Configure failed");

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::io::AsRawSocket;
            let raw = client.as_raw_socket();
            let rcvbuf = win_sock::get_socket_buffer_size(raw, win_sock::SO_RCVBUF)
                .expect("getsockopt SO_RCVBUF failed");
            assert!(
                rcvbuf >= 65536,
                "SO_RCVBUF expected >= 64KB, got {}",
                rcvbuf
            );

            let sndbuf = win_sock::get_socket_buffer_size(raw, win_sock::SO_SNDBUF)
                .expect("getsockopt SO_SNDBUF failed");
            assert!(
                sndbuf >= 65536,
                "SO_SNDBUF expected >= 64KB, got {}",
                sndbuf
            );
        }

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = client.as_raw_fd();
            let rcvbuf = unix_sock::get_socket_buffer_size(fd, libc::SO_RCVBUF)
                .expect("getsockopt SO_RCVBUF failed");
            assert!(
                rcvbuf >= 65536,
                "SO_RCVBUF expected >= 64KB, got {}",
                rcvbuf
            );

            let sndbuf = unix_sock::get_socket_buffer_size(fd, libc::SO_SNDBUF)
                .expect("getsockopt SO_SNDBUF failed");
            assert!(
                sndbuf >= 65536,
                "SO_SNDBUF expected >= 64KB, got {}",
                sndbuf
            );
        }
    }

    #[test]
    fn test_nonblocking_stream_compatibility() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Bind failed");
        let addr = listener.local_addr().expect("Addr failed");

        let mut client = TcpStream::connect(addr).expect("Connect failed");
        client
            .set_nonblocking(true)
            .expect("Set nonblocking failed");

        // configure_tcp_stream should not reset or break non-blocking state
        configure_tcp_stream(&client).expect("Configure on nonblocking stream failed");
        assert!(client.nodelay().unwrap_or(false));

        let mut buf = [0u8; 16];
        match client.read(&mut buf) {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Expected behavior for non-blocking stream
            }
            other => panic!(
                "Expected WouldBlock on empty non-blocking read, got {:?}",
                other
            ),
        }
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

    #[test]
    fn test_stream_data_integrity_after_configuration() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Bind failed");
        let addr = listener.local_addr().expect("Addr failed");

        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().expect("Accept failed");
            configure_tcp_stream(&s).expect("Server configure failed");
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).expect("Read failed");
            assert_eq!(&buf, b"HELLO");
            s.write_all(b"WORLD").expect("Write failed");
        });

        let mut client = TcpStream::connect(addr).expect("Connect failed");
        configure_tcp_stream(&client).expect("Client configure failed");
        client.write_all(b"HELLO").expect("Write failed");
        let mut resp = [0u8; 5];
        client.read_exact(&mut resp).expect("Read failed");
        assert_eq!(&resp, b"WORLD");

        server.join().expect("Join failed");
    }
}
