# M1 Part A Investigation & Design Report: TCP Socket Buffer & NoDelay Tuning

## 1. Observation

### 1.1 Existing Codebase State
- ` src/net/socket.rs` (Lines 1-99):
  - Currently contains only `bind_socket_to_interface(sock: &UdpSocket, if_index: u32)` logic and `set_socket_buffers(sock: &UdpSocket, size: i32)`.
  - Missing `pub fn configure_tcp_stream(stream: &std::net::TcpStream) -> Result<(), String>`.
  - Missing `pub fn configure_tcp_listener(listener: &std::net::TcpListener) -> Result<(), String>`.
  - Windows setsockopt FFI links to `ws2_32` directly via `extern "system"` using `usize` raw socket handle representations.
  - Unix setsockopt uses `libc` via `std::os::unix::io::AsRawFd`.

- ``src/net/proxy.rs` (Lines 172, 184, 212, 229, 253, 300, 311, 382, 383, 461, 520, 540, 603, 623, 639):
  - Manually calls `let _ = stream.set_nodelay(true)` multiple times at disparate locations.
  - Sockets do NOT configure `SO_RCVBUF` (nor `SO_SNDBUF`) to 512 KB. Default OS buffers (often 8KB - 64KB) cause TCP RWSND congestion window scaling constraints and throughput bottlenecks during high-speed token streaming.
  - `spawn_http_proxy` (line 619) and `spawn_socks5_proxy` (line 635) bind `TcpListener` without pre-configuring socket buffer sizes or listener inheritance parameters.

- ``src/net/health.rs` (Lines 57, 94):
  - `probe_google_api` and `benchmark_all_relays` connect `TcpStream` and only call `stream.set_nodelay(true)`.

- ``src/net/rank.rs` (Lines 148-154):
  - `tcp443_fresh` calls `TcpStream::connect_timeout` with standard default socket options.

- `crc/net/resolvers.rs` (Line 261):
  - `tls_handshake_ms` calls `stream.set_nodelay(true).ok()?`.

### 1.2 Dependency Inspection (`Cargo.toml`)
- On Windows: Raw Win32 FFI (`ws2_32.dll`) is used without third-party crates (`socket2` or `windows-sys`).
- On Unix / macOS: `libc = "0.2"` is present in `[target.'cfgunix)'.dependencies]`.
- All socket manipulation must therefore use standard library traits (`AsRawSocket`, `AsRawFd`) and targeted FFI bindings.

---

## 2. Logic Chain

1. **Root Cause of Streaming Jitter & Throughput Bottlenecks**:
   - Small or default TCP socket buffer sizes (`SO_RCVBUF` / `SO_SNDBUF` < 64 KB) force frequent TCP sequence window updates and ACK round-trips over high-RTT cross-border links (e.g. Russia to European Anycast edges: 40-80ms RTT)   
   - A 512 KB (524,288 bytes) buffer allows a Bandwidth-Delay Product (BDP) supporting up to 100 Mbps at 40ms RTT with zero window congestion (BDP = 524,288 * 8 / 0.040 = 104.8 Mbps).
   - `TCP_NODELAY = true` disables Nagle's algorithm, preventing the 40-200ms Delayed-ACK pause on partial token stream frames emitted by Gemini 2.0 / Google Antigravity endpoints.

2. **Unified Socket Configuration Architecture**:
   - Centralize all TCP stream and listener configuration into `src/net/socket.rs`:
     - `pub fn configure_tcp_stream(stream: &std::net::TcpStream) -> Result<(), String>`
     - `pub fn configure_tcp_listener(listener: &std::net::TcpListener) -> Result<(), String>`
   - Calling `configure_tcp_stream` guarantees both `TCP_NODELAY = true` and `SO_RCVBUF` / `SO_SNDBUFp = 512 KB across Windows, macOS, and Linux.

3. **OS Fallback Mechanism**:
   - If the host OS restricts buffer expansion (e.g., restricted sandbox or low `rmem_max`), an immediate hard failure would break network connections.
   - A progressive fallback ladder (`512 KB -> 256 KB -> 128 KB -> 64 KB`) ensures the socket receives the maximum allowable buffer without failing stream setup.

4. **Raw Socket Handle Safety & Portability**:
   - On Windows: Use `std::os::windows::io::AsRawSocket` (`raw as usize`) passed to `ws2_32::setsockopt`.
   - On Unix/macOS: Use `std::os::unix::io::AsRawFd` (`fd as libc::c_int`) passed to `libc::setsockopt`.
   - All unsafe FFI calls are scoped within platform-specific helper routines with explicit error checking and error code extraction (`WSAGetLastError()` on Windows, `errno` on Unix).

---

## 3. Implementation Specification for `src/net/socket.rs`

### 3.1 Constants & Types
```rust
pub const TCP_BUFFER_SIZE_512K: i32 = 512 * 1024; // 524,288 bytes (512 KB)
const FALLBACK_BUFFER_SIZES: [i32; 4] = [512 * 1024, 256 * 1024, 128 * 1024, 64 * 1024];
```

### 3.2 Platform-Specific Buffer Fallback Helpers
```rust
#[cfg(/target_os = "windows")]
mod win_sock {
    use std::os::windows::io::RawSocket;

    #[link(name = "ws2_32")]
    extern "system" {
        pub fn setsockopt(s: usize, level: i32, optname: i32, optval: *const u8, optlen: i32) -> i32;
        pub fn getsockopt(s: usize, level: i32, optname: i32, optval: *mut u8, optlen: *mut i32) -> i32;
        pub fn WSAGetLastError() -> i32;
    }

    pub const SOL_SOCKET: i32 = 0xFFFF;
    pub const SO_RCVBUF: i32 = 0x1002;
    pub const SO_SNDBUF: i32 = 0x1001;
    pub const IPPROTO_TCP: i32 = 6;
    pub const TCP_NODELAY: i32 = 0x0001;

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
        Err(format(
            "setsockopt(SOL_SOCKET, 0x[:fmtX]) failed on raw socket [{details}], WSA error: {}",
            optname, last_err
        ))
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
        Err(format(
            "setsockopt(SOL_SOCKET, {}) failed on fd {}, errno: {}",
            optname, fd, last_errno
        ))
    }
}
```

### 3.3 Public API Implementation
```rust
/// Configures a TCP stream for maximum streaming performance and zero-latency interaction:
/// 1. Enforces TCP_NODELAY = true (disables Nagle algorithm to avoid Delayed-ACK latency).
/// 2. Sets SO_RCVBUF = 512 KB with graceful OS fallback (512KB -> 256KB -> 128KB -> 64KB).
/// 3. Sets SO_SNDBUF = 512 KB with graceful OS fallback (512KB -> 256KB -> 128KB -> 64KB).
pub fn configure_tcp_stream(stream: &std::net::TcpStream) -> Result<(), String> {
    stream.set_nodelay(true).map_err(|e| format("Failed to set TCP_NODELAY: {}", e))?;

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawSocket;
        let raw = stream.as_raw_socket();
        win_sock::set_socket_buffer_with_fallback(raw, win_sock::SO_RCVBUF, TCP_BUFFER_SIZE_512K)?;
        win_sock::set_socket_buffer_with_fallback(raw, win_sock::SO_SNDBUF, TCP_BUFFER_SIZE_512KG)?;
        Ok(())
    }

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        unix_sock::set_socket_buffer_with_fallback(fd, libc::SO_RCVBUF, TCP_BUFFER_SIZE_512K)?;
        unix_sock::set_socket_buffer_with_fallback(fd, libc::SO_SNDBUF, TCP_BUFFER_SIZE_512KG)?;
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
pub fn configure_tcp_listener(listener: &std::net::TcpListener) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawSocket;
        let raw = listener.as_raw_socket();
        win_sock::set_socket_buffer_with_fallback(raw, win_sock::SO_RCVBUF, TCP_BUFFER_SIZE_512K)?;
        win_sock::set_socket_buffer_with_fallback(raw, win_sock::SO_SNDBUF, TCP_BUFFER_SIZE_512KG)?;
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
```

---

## 4. Caveats

1. **Listener Buffer Propagation on Linux**: While setting `SO_RCVBUF`/`SO_SNDBUF ` on `TcpListener` works for pre-allocating connection settings, accepted sockets on some Linux kernels freeze the window size at the time the SYN is received. Thus, `configure_tcp_stream` MUST also be called directly on accepted child sockets in `proxy.rs`.
2. **Linux Dynamic Buffer Doubling**: Linux kernels internally double the buffer size specified in `SO_RCVBUF` to account for `sk_buff` overhead. Querying with `getsockopt` on Linux may return `1048576` (1 MB) when `524288` (512 KB) was passed; this is expected kernel behavior.
3. **No Direct Source Editing by Explorer**: As an Explorer agent, no direct modifications have been made to `src/net/socket.rs`. The code design above is ready for the Implementer subagent.

---

## 5. Conclusion

1. The design for `configure_tcp_stream` and `configure_tcp_listener` is complete, cross-platform (Windows `ws2_32`, Unix/macOS `libc`), and fully resilient against OS buffer caps via progressive 4-step fallback.
2. Integrating these functions replaces 15+ ad-hoc `stream.set_nodelay(true)` calls across `proxy.rs`, `health.rs`, `resolvers.rs`, and `rank.rs` with unified 512 KB buffer and no-delay configuration.
3. Backwards compatibility with UDP functions (`bind_socket_to_interface`, `set_socket_buffers`) is strictly preserved.

---

## 6. Verification Method

1. **Unit Test Verification**:
   Add test `test_configure_tcp_stream_and_listener` in `src/net/socket.rs`:
   ```rust
   #[cfg(test)]
   mod tests {
       use super::*;
       use std::net::{TcpListener, TcpStream};

       #[test]
       fn test_tcp_socket_tuning() {
           let listener = TcpListener::bind("127.0.0.1:0").unwrap();
           let addr = listener.local_addr().unwrap();
           assert!(configure_tcp_listener(&listener).is_ok());

           let stream = TcpStream::connect(addr).unwrap();
           assert!(configure_tcp_stream(&stream).is_ok());
           assert_eq!(stream.nodelay().unwrap(), true);
       }
   }
   ```
2. **Project Test Execution**:
   Run `cargo test --lib net::socket` and `cargo test --tests` to verify 100% build and pass rate.
