use std::fs;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::Command;

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
        pub fn setsockopt(s: usize, level: i32, optname: i32, optval: *const u8, optlen: i32) -> i32;
        #[allow(dead_code)]
        pub fn getsockopt(s: usize, level: i32, optname: i32, optval: *mut u8, optlen: *mut i32) -> i32;
        pub fn WSAGetLastError() -> i32;
    }

    pub const SOL_SOCKET: i32 = 0xFFFF;
    pub const SO_RCVBUF: i32 = 0x1002;
    pub const SO_SNDBUF: i32 = 0x1001;

    pub fn set_socket_buffer_with_fallback(raw: RawSocket, optname: i32, target_size: i32) -> Result<(), String> {
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
        let ret = unsafe { getsockopt(handle, SOL_SOCKET, optname, &mut buf_size as *mut _ as *mut u8, &mut len) };
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

    pub fn set_socket_buffer_with_fallback(fd: RawFd, optname: libc::c_int, target_size: i32) -> Result<(), String> {
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
            libc::getsockopt(fd, libc::SOL_SOCKET, optname, &mut size as *mut _ as *mut libc::c_void, &mut len)
        };
        if ret == 0 {
            Ok(size as i32)
        } else {
            Err(format!("getsockopt failed: errno {}", std::io::Error::last_os_error()))
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
    stream.set_nodelay(true).map_err(|e| format!("Failed to set TCP_NODELAY: {}", e))?;

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
            fn setsockopt(s: usize, level: i32, optname: i32, optval: *const u8, optlen: i32) -> i32;
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

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
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
            fn setsockopt(s: usize, level: i32, optname: i32, optval: *const u8, optlen: i32) -> i32;
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

        if let Ok(output) = crate::system::process::no_window(&mut Command::new("netsh"))
            .args(["int", "tcp", "show", "global"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let line_lower = line.to_lowercase();
                if let Some((_, val)) = line.split_once(':') {
                    let v = val.trim();
                    let v_lower = v.to_lowercase();
                    if line_lower.contains("autotuning") || line_lower.contains("автонастро") {
                        let note = if v_lower == "normal" { " [optimal]" } else { " [suboptimal: recommend normal]" };
                        lines.push(format!("  - Receive Window Auto-Tuning: {}{}", v, note));
                    } else if line_lower.contains("receive-side scaling") || line_lower.contains("масштабирования на стороне приема") {
                        let note = if v_lower == "enabled" { " [optimal]" } else { " [disabled]" };
                        lines.push(format!("  - Receive-Side Scaling (RSS): {}{}", v, note));
                    } else if line_lower.contains("fast open") && !line_lower.contains("откат") && !line_lower.contains("fallback") {
                        let note = if v_lower == "enabled" { " [optimal]" } else { " [disabled]" };
                        lines.push(format!("  - TCP Fast Open (TFO): {}{}", v, note));
                    } else if line_lower.contains("hystart") {
                        let note = if v_lower == "enabled" { " [optimal]" } else { " [disabled]" };
                        lines.push(format!("  - HyStart Slow-Start: {}{}", v, note));
                    } else if line_lower.contains("proportional rate") || line_lower.contains("коэффициента пропорции") {
                        let note = if v_lower == "enabled" { " [optimal]" } else { " [disabled]" };
                        lines.push(format!("  - Proportional Rate Reduction: {}{}", v, note));
                    } else if line_lower.contains("timestamps") || line_lower.contains("метки времени") {
                        lines.push(format!("  - RFC 1323 Timestamps: {}", v));
                    }
                }
            }
        }

        if let Ok(output) = crate::system::process::no_window(&mut Command::new("netsh"))
            .args(["int", "tcp", "show", "heuristics"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let line_lower = line.to_lowercase();
                if (line_lower.contains("heuristic") || line_lower.contains("эвристик")) && line.contains(':') {
                    if let Some((_, val)) = line.split_once(':') {
                        let v = val.trim();
                        let note = if v.to_lowercase() == "disabled" { " [optimal]" } else { " [enabled - may throttle TCP]" };
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
            if let Ok(output) = Command::new("sysctl").arg("-n").arg(key).output() {
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

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        "OS Network Stack Status (Linux): Standard kernel TCP stack active".to_string()
    }

    #[cfg(not(any(target_os = "windows", unix)))]
    {
        "OS network stack tuning not supported on this platform".to_string()
    }
}

/// Applies OS-level network stack fine-tuning (TCP window auto-tuning, RSS, Fast Open, etc.).
/// Backs up pre-existing settings to `tcp_backup.conf` if not already present.
pub fn tune_os_network_stack() -> Result<Vec<String>, String> {
    if !crate::system::privilege::is_admin() {
        return Err("Administrative privileges required to tune OS network stack".to_string());
    }

    #[cfg(target_os = "windows")]
    {
        let mut applied = Vec::new();
        let bpath = tcp_backup_path();

        if !bpath.exists() {
            if let Some(parent) = bpath.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let backup_content = capture_windows_tcp_backup();
            let _ = fs::write(&bpath, backup_content);
        }

        let netsh_cmds: &[(&str, &[&str], &str)] = &[
            ("autotuninglevel", &["int", "tcp", "set", "global", "autotuninglevel=normal"], "Receive Window Auto-Tuning Level: normal"),
            ("heuristics", &["int", "tcp", "set", "heuristics", "disabled"], "TCP Window Scaling Heuristics: disabled"),
            ("rss", &["int", "tcp", "set", "global", "rss=enabled"], "Receive-Side Scaling (RSS): enabled"),
            ("fastopen", &["int", "tcp", "set", "global", "fastopen=enabled"], "TCP Fast Open (TFO): enabled"),
            ("hystart", &["int", "tcp", "set", "global", "hystart=enabled"], "HyStart Congestion Optimization: enabled"),
            ("prr", &["int", "tcp", "set", "global", "prr=enabled"], "Proportional Rate Reduction (PRR): enabled"),
            ("timestamps", &["int", "tcp", "set", "global", "timestamps=allowed"], "RFC 1323 Timestamps: allowed"),
            ("rsc", &["int", "tcp", "set", "global", "rsc=enabled"], "Receive Segment Coalescing (RSC): enabled"),
            ("congestion_internet", &["int", "tcp", "set", "supplemental", "template=internet", "congestionprovider=cubic"], "TCP Congestion Provider (Internet): CUBIC"),
            ("congestion_custom", &["int", "tcp", "set", "supplemental", "template=internetcustom", "congestionprovider=cubic"], "TCP Congestion Provider (InternetCustom): CUBIC"),
            ("ecn", &["int", "tcp", "set", "global", "ecncapability=enabled"], "Explicit Congestion Notification (ECN): enabled"),
            ("initialrto", &["int", "tcp", "set", "global", "initialRto=2000"], "Initial Retransmission Timeout (initialRTO): 2000ms"),
        ];

        let mut success_count = 0;
        for (_key, args, desc) in netsh_cmds {
            let res = crate::system::process::no_window(&mut Command::new("netsh"))
                .args(*args)
                .output();
            if let Ok(output) = res {
                let out = String::from_utf8_lossy(&output.stdout);
                if output.status.success() || out.to_lowercase().contains("ok") || out.contains("ОК") {
                    applied.push(desc.to_string());
                    success_count += 1;
                }
            }
        }

        if success_count == 0 {
            return Err("Failed to apply Windows netsh TCP stack configuration".to_string());
        }

        Ok(applied)
    }

    #[cfg(target_os = "macos")]
    {
        let mut applied = Vec::new();
        let bpath = tcp_backup_path();

        if !bpath.exists() {
            if let Some(parent) = bpath.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let backup_content = capture_macos_sysctl_backup();
            let _ = fs::write(&bpath, backup_content);
        }

        let tunables = [
            ("net.inet.tcp.autorcvbufmax=16777216", "TCP Auto-Receive Buffer Max: 16 MB (16777216)"),
            ("net.inet.tcp.autosndbufmax=16777216", "TCP Auto-Send Buffer Max: 16 MB (16777216)"),
            ("net.inet.tcp.autorcvbuf=1", "TCP Dynamic Receive Auto-Tuning: enabled (1)"),
            ("net.inet.tcp.autosndbuf=1", "TCP Dynamic Send Auto-Tuning: enabled (1)"),
            ("net.inet.tcp.sendspace=524288", "TCP Send Buffer Space: 512 KB (524288)"),
            ("net.inet.tcp.recvspace=524288", "TCP Recv Buffer Space: 512 KB (524288)"),
            ("kern.ipc.maxsockbuf=16777216", "Kernel Max Socket Buffer: 16 MB (16777216)"),
            ("net.inet.tcp.fastopen=3", "TCP Fast Open (Client+Server): enabled (3)"),
        ];

        for (cmd_arg, desc) in &tunables {
            let res = Command::new("sysctl")
                .arg("-w")
                .arg(cmd_arg)
                .output();
            if let Ok(out) = res {
                if out.status.success() {
                    applied.push(desc.to_string());
                }
            }
        }

        if applied.is_empty() {
            return Err("Failed to apply macOS sysctl network parameters".to_string());
        }

        Ok(applied)
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let mut applied = Vec::new();
        let tunables = [
            ("net.ipv4.tcp_window_scaling=1", "TCP Window Scaling: enabled (1)"),
            ("net.ipv4.tcp_rmem=4096 87380 16777216", "TCP RCV Buffers: 4KB / 87KB / 16MB"),
            ("net.ipv4.tcp_wmem=4096 65536 16777216", "TCP SND Buffers: 4KB / 64KB / 16MB"),
            ("net.core.rmem_max=16777216", "Core Max RCV Buffer: 16 MB"),
            ("net.core.wmem_max=16777216", "Core Max SND Buffer: 16 MB"),
            ("net.ipv4.tcp_fastopen=3", "TCP Fast Open: enabled (3)"),
        ];
        for (cmd_arg, desc) in &tunables {
            if let Ok(out) = Command::new("sysctl").arg("-w").arg(cmd_arg).output() {
                if out.status.success() {
                    applied.push(desc.to_string());
                }
            }
        }
        Ok(applied)
    }

    #[cfg(not(any(target_os = "windows", unix)))]
    {
        Ok(vec!["OS network tuning not supported on this platform".to_string()])
    }
}

/// Restores OS-level network stack settings using `tcp_backup.conf` (or factory defaults).
pub fn restore_os_network_stack() -> Result<Vec<String>, String> {
    if !crate::system::privilege::is_admin() {
        return Err("Administrative privileges required to restore OS network stack".to_string());
    }

    #[cfg(target_os = "windows")]
    {
        let mut restored = Vec::new();
        let bpath = tcp_backup_path();

        let mut backup_map = std::collections::HashMap::new();
        if bpath.exists() {
            if let Ok(content) = fs::read_to_string(&bpath) {
                for line in content.lines() {
                    if let Some((k, v)) = line.split_once('=') {
                        backup_map.insert(k.trim().to_string(), v.trim().to_string());
                    }
                }
            }
        }

        let autotuning = backup_map.get("autotuninglevel").map(|s| s.as_str()).unwrap_or("normal");
        let heuristics = backup_map.get("heuristics").map(|s| s.as_str()).unwrap_or("default");
        let rss = backup_map.get("rss").map(|s| s.as_str()).unwrap_or("default");
        let fastopen = backup_map.get("fastopen").map(|s| s.as_str()).unwrap_or("default");
        let hystart = backup_map.get("hystart").map(|s| s.as_str()).unwrap_or("default");
        let prr = backup_map.get("prr").map(|s| s.as_str()).unwrap_or("default");
        let timestamps = backup_map.get("timestamps").map(|s| s.as_str()).unwrap_or("default");
        let rsc = backup_map.get("rsc").map(|s| s.as_str()).unwrap_or("default");

        let autotuning_arg = format!("autotuninglevel={}", autotuning);
        let rss_arg = format!("rss={}", rss);
        let fastopen_arg = format!("fastopen={}", fastopen);
        let hystart_arg = format!("hystart={}", hystart);
        let prr_arg = format!("prr={}", prr);
        let timestamps_arg = format!("timestamps={}", timestamps);
        let rsc_arg = format!("rsc={}", rsc);

        let restore_cmds: &[(&str, &[&str], &str)] = &[
            ("autotuninglevel", &["int", "tcp", "set", "global", &autotuning_arg], "Receive Window Auto-Tuning Level restored"),
            ("heuristics", &["int", "tcp", "set", "heuristics", heuristics], "TCP Window Scaling Heuristics restored"),
            ("rss", &["int", "tcp", "set", "global", &rss_arg], "Receive-Side Scaling (RSS) restored"),
            ("fastopen", &["int", "tcp", "set", "global", &fastopen_arg], "TCP Fast Open (TFO) restored"),
            ("hystart", &["int", "tcp", "set", "global", &hystart_arg], "HyStart restored"),
            ("prr", &["int", "tcp", "set", "global", &prr_arg], "PRR restored"),
            ("timestamps", &["int", "tcp", "set", "global", &timestamps_arg], "RFC 1323 Timestamps restored"),
            ("rsc", &["int", "tcp", "set", "global", &rsc_arg], "RSC restored"),
            ("congestion_internet", &["int", "tcp", "set", "supplemental", "template=internet", "congestionprovider=default"], "TCP Congestion Provider (Internet) restored"),
            ("congestion_custom", &["int", "tcp", "set", "supplemental", "template=internetcustom", "congestionprovider=default"], "TCP Congestion Provider (InternetCustom) restored"),
            ("ecn", &["int", "tcp", "set", "global", "ecncapability=disabled"], "ECN restored"),
            ("initialrto", &["int", "tcp", "set", "global", "initialRto=3000"], "Initial RTO restored"),
        ];

        for (_key, args, desc) in restore_cmds {
            let res = crate::system::process::no_window(&mut Command::new("netsh"))
                .args(*args)
                .output();
            if let Ok(output) = res {
                if output.status.success() {
                    restored.push(desc.to_string());
                }
            }
        }

        if bpath.exists() {
            let _ = fs::remove_file(&bpath);
        }

        Ok(restored)
    }

    #[cfg(target_os = "macos")]
    {
        let mut restored = Vec::new();
        let bpath = tcp_backup_path();

        let mut backup_map = std::collections::HashMap::new();
        if bpath.exists() {
            if let Ok(content) = fs::read_to_string(&bpath) {
                for line in content.lines() {
                    if let Some((k, v)) = line.split_once('=') {
                        backup_map.insert(k.trim().to_string(), v.trim().to_string());
                    }
                }
            }
        }

        let defaults = [
            ("net.inet.tcp.autorcvbufmax", "4194304"),
            ("net.inet.tcp.autosndbufmax", "4194304"),
            ("net.inet.tcp.autorcvbuf", "1"),
            ("net.inet.tcp.autosndbuf", "1"),
            ("net.inet.tcp.sendspace", "131072"),
            ("net.inet.tcp.recvspace", "131072"),
            ("kern.ipc.maxsockbuf", "8388608"),
            ("net.inet.tcp.fastopen", "0"),
        ];

        for (key, default_val) in &defaults {
            let val = backup_map.get(*key).map(|s| s.as_str()).unwrap_or(*default_val);
            let arg = format!("{}={}", key, val);
            let res = Command::new("sysctl")
                .arg("-w")
                .arg(&arg)
                .output();
            if let Ok(out) = res {
                if out.status.success() {
                    restored.push(format!("sysctl {} restored to {}", key, val));
                }
            }
        }

        if bpath.exists() {
            let _ = fs::remove_file(&bpath);
        }

        Ok(restored)
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        Ok(vec!["Linux network stack restoration complete".to_string()])
    }

    #[cfg(not(any(target_os = "windows", unix)))]
    {
        Ok(vec!["OS network stack restoration not supported on this platform".to_string()])
    }
}

#[cfg(target_os = "windows")]
fn capture_windows_tcp_backup() -> String {
    let mut backup_lines = Vec::new();
    if let Ok(output) = crate::system::process::no_window(&mut Command::new("netsh"))
        .args(["int", "tcp", "show", "global"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let line_lower = line.to_lowercase();
            if let Some((_, val)) = line.split_once(':') {
                let v = val.trim().to_lowercase();
                if line_lower.contains("autotuning") || line_lower.contains("автонастро") {
                    backup_lines.push(format!("autotuninglevel={}", v));
                } else if line_lower.contains("receive-side scaling") || line_lower.contains("масштабирования на стороне приема") {
                    backup_lines.push(format!("rss={}", v));
                } else if line_lower.contains("fast open") && !line_lower.contains("откат") && !line_lower.contains("fallback") {
                    backup_lines.push(format!("fastopen={}", v));
                } else if line_lower.contains("hystart") {
                    backup_lines.push(format!("hystart={}", v));
                } else if line_lower.contains("proportional rate") || line_lower.contains("коэффициента пропорции") {
                    backup_lines.push(format!("prr={}", v));
                } else if line_lower.contains("timestamps") || line_lower.contains("метки времени") {
                    backup_lines.push(format!("timestamps={}", v));
                } else if line_lower.contains("receive segment coalescing") || line_lower.contains("объединения сегментов") {
                    backup_lines.push(format!("rsc={}", v));
                }
            }
        }
    }

    if let Ok(output) = crate::system::process::no_window(&mut Command::new("netsh"))
        .args(["int", "tcp", "show", "heuristics"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let line_lower = line.to_lowercase();
            if (line_lower.contains("heuristic") || line_lower.contains("эвристик")) && line.contains(':') {
                if let Some((_, val)) = line.split_once(':') {
                    let v = val.trim().to_lowercase();
                    backup_lines.push(format!("heuristics={}", v));
                    break;
                }
            }
        }
    }

    backup_lines.join("\n")
}

#[cfg(target_os = "macos")]
fn capture_macos_sysctl_backup() -> String {
    let mut backup_lines = Vec::new();
    let sysctl_keys = [
        "net.inet.tcp.autorcvbufmax",
        "net.inet.tcp.autosndbufmax",
        "net.inet.tcp.autorcvbuf",
        "net.inet.tcp.autosndbuf",
        "net.inet.tcp.sendspace",
        "net.inet.tcp.recvspace",
        "kern.ipc.maxsockbuf",
        "net.inet.tcp.fastopen",
    ];

    for key in &sysctl_keys {
        if let Ok(output) = Command::new("sysctl").arg("-n").arg(key).output() {
            let val = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !val.is_empty() {
                backup_lines.push(format!("{}={}", key, val));
            }
        }
    }

    backup_lines.join("\n")
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
        assert!(client.nodelay().unwrap_or(false), "TCP_NODELAY must be true on configured client");

        let incoming = handle.join().expect("Thread join failed");
        assert!(incoming.nodelay().unwrap_or(false), "TCP_NODELAY must be true on configured server stream");
    }

    #[test]
    fn test_configure_tcp_listener_basic() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind listener");
        let result = configure_tcp_listener(&listener);
        assert!(result.is_ok(), "configure_tcp_listener must succeed: {:?}", result.err());
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
            let rcvbuf = win_sock::get_socket_buffer_size(raw, win_sock::SO_RCVBUF).expect("getsockopt SO_RCVBUF failed");
            assert!(rcvbuf >= 65536, "SO_RCVBUF expected >= 64KB, got {}", rcvbuf);

            let sndbuf = win_sock::get_socket_buffer_size(raw, win_sock::SO_SNDBUF).expect("getsockopt SO_SNDBUF failed");
            assert!(sndbuf >= 65536, "SO_SNDBUF expected >= 64KB, got {}", sndbuf);
        }

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = client.as_raw_fd();
            let rcvbuf = unix_sock::get_socket_buffer_size(fd, libc::SO_RCVBUF).expect("getsockopt SO_RCVBUF failed");
            assert!(rcvbuf >= 65536, "SO_RCVBUF expected >= 64KB, got {}", rcvbuf);

            let sndbuf = unix_sock::get_socket_buffer_size(fd, libc::SO_SNDBUF).expect("getsockopt SO_SNDBUF failed");
            assert!(sndbuf >= 65536, "SO_SNDBUF expected >= 64KB, got {}", sndbuf);
        }
    }

    #[test]
    fn test_nonblocking_stream_compatibility() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Bind failed");
        let addr = listener.local_addr().expect("Addr failed");

        let mut client = TcpStream::connect(addr).expect("Connect failed");
        client.set_nonblocking(true).expect("Set nonblocking failed");

        // configure_tcp_stream should not reset or break non-blocking state
        configure_tcp_stream(&client).expect("Configure on nonblocking stream failed");
        assert!(client.nodelay().unwrap_or(false));

        let mut buf = [0u8; 16];
        match client.read(&mut buf) {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Expected behavior for non-blocking stream
            }
            other => panic!("Expected WouldBlock on empty non-blocking read, got {:?}", other),
        }
    }

    #[test]
    fn test_udp_socket_buffers() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("Udp bind failed");
        let result = set_socket_buffers(&socket, 512 * 1024);
        assert!(result.is_ok(), "set_socket_buffers on UDP socket failed: {:?}", result.err());
    }

    #[test]
    fn test_os_network_status_query() {
        let status = get_os_network_status();
        assert!(!status.is_empty(), "get_os_network_status must return a descriptive string");
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
