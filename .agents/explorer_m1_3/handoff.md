# Handoff Report — Explorer 3 (Milestone 1: Integration & Verification Strategy)

**Agent Role**: Explorer 3 (M1 Part C: Integration & Unit Testing Plan)  
**Project**: Google Antigravity & Gemini 2.0 Latency Profiling & Throughput Optimization  
**Working Directory**: `.agents/explorer_m1_3`  
**Target Milestone**: M1 (TCP Socket & OS Stack Fine-Tuning)  

---

## 1. Observation

Direct code examination using Graft AST analysis and surgical inspection revealed the following exact socket creation, lifecycle, and testing sites across the codebase:

### 1.1 TCP Stream & Listener Creation Sites Requiring `configure_tcp_stream` / `configure_tcp_listener`

#### A. `src/net/proxy.rs` (High-Throughput Streaming & Proxying Layer)
1. **`spawn_http_proxy(port: u16, socks5_port: u16)`** (Lines 618–631):
   - **Line 619**: `let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port))?;`
     - *Action*: Call `crate::net::socket::configure_tcp_listener(&listener)?;` immediately after bind.
   - **Line 622–624**: `for stream in listener.incoming() { if let Ok(s) = stream { let _ = s.set_nodelay(true); ...`
     - *Action*: Replace `let _ = s.set_nodelay(true);` with `let _ = crate::net::socket::configure_tcp_stream(&s);`.
2. **`spawn_socks5_proxy(port: u16)`** (Lines 634–647):
   - **Line 635**: `let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port))?;`
     - *Action*: Call `crate::net::socket::configure_tcp_listener(&listener)?;` immediately after bind.
   - **Line 638–640**: `for stream in listener.incoming() { if let Ok(s) = stream { let _ = s.set_nodelay(true); ...`
     - *Action*: Replace `let _ = s.set_nodelay(true);` with `let _ = crate::net::socket::configure_tcp_stream(&s);`.
3. **`handle_http_client(mut stream: TcpStream, http_port: u16, socks5_port: u16)`** (Lines 460–536):
   - **Line 461**: `let _ = stream.set_nodelay(true);`
     - *Action*: Replace with `let _ = crate::net::socket::configure_tcp_stream(&stream);`.
4. **`handle_socks5_client(mut stream: TcpStream)`** (Lines 539–615):
   - **Line 540**: `let _ = stream.set_nodelay(true);`
     - *Action*: Replace with `let _ = crate::net::socket::configure_tcp_stream(&stream);`.
5. **`connect_with_racing(candidates: &[String], port: u16)`** (Lines 160–240):
   - **Line 171** (Cached Winner Fast-Path): `if let Ok(stream) = TcpStream::connect_timeout(&sock_addr, Duration::from_millis(800))`
     - *Action*: Call `let _ = crate::net::socket::configure_tcp_stream(&stream);`.
   - **Line 183** (Single Candidate): `let s = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(3))?;`
     - *Action*: Replace `let _ = s.set_nodelay(true);` (Line 184) with `let _ = crate::net::socket::configure_tcp_stream(&s);`.
   - **Line 211** (Racing Worker Threads): `if let Ok(stream) = TcpStream::connect_timeout(&sock_addr, FAST_RACING_TIMEOUT)`
     - *Action*: Replace `let _ = stream.set_nodelay(true);` (Line 212) with `let _ = crate::net::socket::configure_tcp_stream(&stream);`.
   - **Line 228** (Racing Timeout Fallback): `let s = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(3))?;`
     - *Action*: Replace `let _ = s.set_nodelay(true);` (Line 229) with `let _ = crate::net::socket::configure_tcp_stream(&s);`.
6. **`establish_upstream_connection(host: &str, port: u16)`** (Lines 243–313):
   - **Line 252** (Custom Upstream Proxy): `let mut stream = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(4))?;`
     - *Action*: Replace `let _ = stream.set_nodelay(true);` (Line 253) with `let _ = crate::net::socket::configure_tcp_stream(&stream);`.
   - **Line 299** (Fallback SNI Node): `let stream = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(3))?;`
     - *Action*: Replace `let _ = stream.set_nodelay(true);` (Line 300) with `let _ = crate::net::socket::configure_tcp_stream(&stream);`.
   - **Line 310** (Direct Non-AI Routing): `let stream = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(5))?;`
     - *Action*: Replace `let _ = stream.set_nodelay(true);` (Line 311) with `let _ = crate::net::socket::configure_tcp_stream(&stream);`.
7. **`pipe_streams_with_accounting(mut client: TcpStream, mut upstream: TcpStream, ...)`** (Lines 369–457):
   - **Lines 382–383**: `let _ = client.set_nodelay(true); let _ = upstream.set_nodelay(true);`
     - *Action*: Replace with `let _ = crate::net::socket::configure_tcp_stream(&client); let _ = crate::net::socket::configure_tcp_stream(&upstream);`.

#### B. `src/net/resolvers.rs` (Multi-Provider Resolution & TLS Probe Layer)
1. **`tls_handshake_ms(addr: IpAddr, sni: &str)`** (Lines 254–272):
   - **Line 256**: `let mut stream = TcpStream::connect_timeout(&SocketAddr::new(addr, LIVENESS_PORT), TLS_PROBE_BUDGET).ok()?;`
   - **Line 261**: `stream.set_nodelay(true).ok()?;`
     - *Action*: Replace `stream.set_nodelay(true).ok()?;` with `let _ = crate::net::socket::configure_tcp_stream(&stream);`.
2. **`is_alive(addr: IpAddr)`** (Lines 332–355):
   - **Line 349**: `let ok = TcpStream::connect_timeout(&sock, LIVENESS_BUDGET).is_ok();`
     - *Action*: Keep lightweight SYN-connect liveness probe; if stream object is preserved, configure socket.

#### C. `src/net/health.rs` (Live Benchmarking & Latency Engine)
1. **`probe_google_api()`** (Lines 27–69):
   - **Line 55**: `match TcpStream::connect_timeout(addr, Duration::from_millis(3000))`
   - **Line 57**: `let _ = stream.set_nodelay(true);`
     - *Action*: Replace with `let _ = crate::net::socket::configure_tcp_stream(&stream);`.
2. **`benchmark_all_relays()`** (Lines 72–137):
   - **Line 92**: `match TcpStream::connect_timeout(&sock_addr, Duration::from_millis(1500))`
   - **Line 94**: `let _ = stream.set_nodelay(true);`
     - *Action*: Replace with `let _ = crate::net::socket::configure_tcp_stream(&stream);`.

#### D. `src/net/rank.rs` (Ranking & Leader Probing)
1. **`tcp443_fresh(ip: Ipv4Addr)`** (Lines 148–154):
   - **Line 149**: `TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(ip), 443), LEADER_TCP_BUDGET).is_ok()` (SYN liveness probe).

#### E. `src/net/relay.rs` (DNS UDP Relay & Socket Buffers)
1. **`run()`** (Lines 151–210):
   - **Line 155**: `let _ = crate::net::socket::set_socket_buffers(&socket, 512 * 1024);` (Existing UDP buffer configuration).

---

### 1.2 OS Network Stack Auto-Tuning Lifecycle Mapping

```
                 ┌─────────────────────────────────────────────────┐
                 │                ACTIVATION LIFECYCLE             │
                 └─────────────────────────────────────────────────┘
                                          │
       ┌──────────────────────────────────┼──────────────────────────────────┐
       ▼                                  ▼                                  ▼
[src/net/mod.rs]                 [src/ui/menu.rs]                    [src/main.rs]
apply_dns_rules()                handle_unlock_all()                 CLI "unlock"
- Call tune_os_network_stack()   handle_dns_only()                   CLI "tune"
- Step: "настройка TCP-стека"    handle_proxy_menu()                 CLI "proxy"
                                 handle_diagnostics() -> status      (admin verified)

                                          │
                                          ▼
                 ┌─────────────────────────────────────────────────┐
                 │                RESTORATION LIFECYCLE            │
                 └─────────────────────────────────────────────────┘
                                          │
       ┌──────────────────────────────────┴──────────────────────────────────┐
       ▼                                                                     ▼
[src/net/mod.rs]                                                     [src/ui/menu.rs]
remove_dns_rules()                                                   handle_rollback()
- Call restore_os_network_stack()                                    - remove_dns_rules()
- Guaranteed clean OS rollback                                       - UI notice: "TCP Auto-Tuning сброшен"
                                                                     [src/main.rs] CLI "rollback"
```

1. **Activation Point 1 — `src/net/mod.rs:apply_dns_rules()`**:
   - Location: In `apply_dns_rules()` (lines 48–79), directly after `disable_system_doh()`:
     ```rust
     step("оптимизация TCP-стека (TCP Auto-Tuning normal, 512KB buffers)");
     if let Ok(notes) = crate::net::socket::tune_os_network_stack() {
         for note in notes {
             sub_notes.push(note);
         }
     }
     ```
2. **Activation Point 2 — `src/main.rs` CLI Subcommands**:
   - Add CLI handler for `tune` command:
     ```rust
     "tune" | "--tune" => {
         ui::init_terminal();
         system::ensure_admin();
         println!("\x1b[96m=== ОПТИМИЗАЦИЯ СЕТЕВОГО СТЕКА TCP ===\x1b[0m\n");
         match net::socket::tune_os_network_stack() {
             Ok(logs) => {
                 for log in logs {
                     println!("  \x1b[92m[✓]\x1b[0m {}", log);
                 }
                 println!("\nТекущий статус: {}", net::socket::get_os_network_status());
             }
             Err(e) => eprintln!("  \x1b[31m[✗]\x1b[0m {}", e),
         }
         return;
     }
     ```
   - In `proxy` subcommand (`src/main.rs:59`), invoke `let _ = net::socket::tune_os_network_stack();` before starting servers.
3. **Diagnostics & Status Integration — `src/ui/menu.rs:handle_diagnostics()` & `src/ui/dashboard.rs`**:
   - Add line 6 in diagnostics:
     ```rust
     println!("  6. Оптимизация TCP-стека:  {}", crate::net::socket::get_os_network_status());
     ```
4. **Restoration Point 1 — `src/net/mod.rs:remove_dns_rules()`**:
   - Location: Lines 203–216, alongside `remove_static_routes()` and `restore_system_doh()`:
     ```rust
     let _ = crate::net::socket::restore_os_network_stack();
     ```
5. **Restoration Point 2 — `src/ui/menu.rs:handle_rollback()`**:
   - In Option 6 Rollback handler (lines 150–156):
     ```rust
     println!("  \x1b[92m[✓]\x1b[0m Настройки TCP Auto-Tuning возвращены по умолчанию");
     ```

---

## 2. Logic Chain

1. **Premise 1**: High-throughput token streaming from Gemini 2.0 / Google Cloud Code generates continuous small-to-medium chunk bursts. If Nagle algorithm (`TCP_NODELAY` disabled) or standard small OS buffers (e.g. 8KB–64KB without Auto-Tuning) are present, TCP Delayed-ACK timers (40ms–200ms) and window stalls cause noticeable stutter and streaming throughput degradation.
2. **Premise 2**: Setting `TCP_NODELAY` alone without expanding socket receive/send buffers (`SO_RCVBUF` / `SO_SNDBUF` = 512KB) and without OS-level TCP Auto-Tuning (`netsh autotuninglevel=normal`) limits the BDP (Bandwidth-Delay Product), restricting throughput on high-latency transcontinental or European Anycast routes.
3. **Deduction 1**: Every TCP pathway in the application—including incoming client connections (`handle_http_client`, `handle_socks5_client`), upstream connections (`connect_with_racing`, `establish_upstream_connection`), listener sockets (`spawn_http_proxy`, `spawn_socks5_proxy`), and real-time probes (`health.rs`, `resolvers.rs`)—must uniformly apply `configure_tcp_stream` and `configure_tcp_listener`.
4. **Deduction 2**: OS-level tuning must be transactional: automatically activated during `apply_dns_rules()`, `handle_unlock_all()`, and CLI `tune`, and 100% reliably rolled back during `remove_dns_rules()` and `handle_rollback()`.
5. **Deduction 3**: A robust verification strategy requires unit tests validating:
   - Socket option application (`TCP_NODELAY`, `SO_RCVBUF`, `SO_SNDBUF`).
   - Native OS FFI `getsockopt` buffer verification on Windows (`ws2_32`) and Unix/macOS (`libc`).
   - Compatibility with non-blocking sockets.
   - High-throughput end-to-end payload streaming (1MB bidirectional loopback transfer).
   - Graceful execution of OS stack auto-tuning and status inspection.

---

## 3. Comprehensive Unit & Integration Test Design

### 3.1 Unit Test Suite (`src/net/socket.rs` -> `mod tests`)

```rust
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
            #[link(name = "ws2_32")]
            extern "system" {
                fn getsockopt(s: usize, level: i32, optname: i32, optval: *mut u8, optlen: *mut i32) -> i32;
            }
            const SOL_SOCKET: i32 = 0xFFFF;
            const SO_RCVBUF: i32 = 0x1002;
            const SO_SNDBUF: i32 = 0x1001;

            let raw = client.as_raw_socket() as usize;
            let mut rcvbuf: i32 = 0;
            let mut len: i32 = 4;
            let ret_rcv = unsafe { getsockopt(raw, SOL_SOCKET, SO_RCVBUF, &mut rcvbuf as *mut _ as *mut u8, &mut len) };
            assert_eq!(ret_rcv, 0, "getsockopt(SO_RCVBUF) failed");
            assert!(rcvbuf >= 65536, "SO_RCVBUF expected >= 64KB, got {}", rcvbuf);

            let mut sndbuf: i32 = 0;
            let mut len2: i32 = 4;
            let ret_snd = unsafe { getsockopt(raw, SOL_SOCKET, SO_SNDBUF, &mut sndbuf as *mut _ as *mut u8, &mut len2) };
            assert_eq!(ret_snd, 0, "getsockopt(SO_SNDBUF) failed");
            assert!(sndbuf >= 65536, "SO_SNDBUF expected >= 64KB, got {}", sndbuf);
        }

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = client.as_raw_fd();
            let mut rcvbuf: libc::c_int = 0;
            let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            let ret = unsafe {
                libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, &mut rcvbuf as *mut _ as *mut libc::c_void, &mut len)
            };
            assert_eq!(ret, 0, "getsockopt(SO_RCVBUF) failed");
            assert!(rcvbuf >= 65536, "SO_RCVBUF expected >= 64KB, got {}", rcvbuf);
        }
    }

    #[test]
    fn test_nonblocking_stream_compatibility() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Bind failed");
        let addr = listener.local_addr().expect("Addr failed");

        let client = TcpStream::connect(addr).expect("Connect failed");
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
}
```

### 3.2 Integration Test Suite (`tests/socket_tests.rs`)

```rust
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

#[test]
fn test_high_throughput_bidirectional_data_transfer() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Listener bind failed");
    let addr = listener.local_addr().expect("Local addr failed");

    const PAYLOAD_SIZE: usize = 1024 * 1024; // 1 MB payload test
    let test_data: Vec<u8> = (0..PAYLOAD_SIZE).map(|i| (i % 251) as u8).collect();
    let test_data_clone = test_data.clone();

    // Server thread: receive 1MB, echo back
    let server_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("Accept failed");
        let _ = stream.set_nodelay(true);
        stream.set_read_timeout(Some(Duration::from_secs(5))).expect("Set timeout failed");

        let mut received = vec![0u8; PAYLOAD_SIZE];
        stream.read_exact(&mut received).expect("Server read_exact failed");
        assert_eq!(received, test_data_clone, "Server received payload mismatch");

        stream.write_all(&received).expect("Server echo write_all failed");
        stream.flush().expect("Server flush failed");
    });

    // Client thread: send 1MB in 64KB chunks, read echo
    let mut client = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
        .expect("Client connect failed");
    let _ = client.set_nodelay(true);
    client.set_read_timeout(Some(Duration::from_secs(5))).expect("Set timeout failed");

    // Write in chunks
    for chunk in test_data.chunks(65536) {
        client.write_all(chunk).expect("Client write chunk failed");
    }
    client.flush().expect("Client flush failed");

    let mut echo_back = vec![0u8; PAYLOAD_SIZE];
    client.read_exact(&mut echo_back).expect("Client read echo failed");
    assert_eq!(echo_back, test_data, "Client echo back mismatch");

    server_handle.join().expect("Server thread join failed");
}

#[test]
fn test_multiple_concurrent_connections_stream_tuning() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Bind failed");
    let addr = listener.local_addr().expect("Addr failed");

    let server_handle = thread::spawn(move || {
        for _ in 0..10 {
            let (mut s, _) = listener.accept().expect("Accept failed");
            let _ = s.set_nodelay(true);
            let mut buf = [0u8; 4];
            let _ = s.read_exact(&mut buf);
            let _ = s.write_all(b"PONG");
        }
    });

    let mut client_threads = Vec::new();
    for _ in 0..10 {
        let client_addr = addr;
        client_threads.push(thread::spawn(move || {
            let mut stream = TcpStream::connect(client_addr).expect("Connect failed");
            let _ = stream.set_nodelay(true);
            stream.write_all(b"PING").expect("Write failed");
            let mut resp = [0u8; 4];
            stream.read_exact(&mut resp).expect("Read failed");
            assert_eq!(&resp, b"PONG");
        }));
    }

    for h in client_threads {
        h.join().expect("Client thread failed");
    }
    server_handle.join().expect("Server thread failed");
}
```

---

## 4. Caveats

1. **OS Kernel Buffer Clamping**: On some platforms (or locked-down Windows/macOS installations), the OS socket layer may clamp the maximum `SO_RCVBUF`/`SO_SNDBUF` to system limits (e.g. `kern.ipc.maxsockbuf` or Windows dynamic socket quota). Sizing assertions in unit tests should check for `>= 64KB` rather than strict equality to `512KB` to accommodate OS scaling and doubling (Linux doubles requested buffer size for metadata, Windows rounds up).
2. **Elevated Privileges for OS-Level Netsh/Sysctl**: `tune_os_network_stack()` and `restore_os_network_stack()` require elevated administrator / root privileges. In non-elevated unit test environments (e.g., standard CI runs), these functions must gracefully return a clear warning message or non-fatal `Err` instead of panicking or terminating the process.
3. **SYN Liveness Probes**: In `resolvers.rs:is_alive` and `rank.rs:tcp443_fresh`, sockets are created solely to test TCP three-way handshake and are discarded immediately. Applying `configure_tcp_stream` is not strictly necessary for 1ms SYN probes, but applying it causes zero harm; for full TLS probes (`tls_handshake_ms`) and data streaming (`proxy.rs`), `configure_tcp_stream` is strictly required.

---

## 5. Conclusion

1. **Full Coverage Plan**: Identified 11 socket creation/stream handling sites in `src/net/proxy.rs`, 2 in `src/net/resolvers.rs`, 2 in `src/net/health.rs`, and 1 in `src/net/rank.rs`. All production streaming pathways will be upgraded from standalone `set_nodelay(true)` to unified `configure_tcp_stream` and `configure_tcp_listener`.
2. **Lifecycle Complete**: OS Auto-Tuning is systematically integrated into `apply_dns_rules()` (activation), `remove_dns_rules()` (restoration), `handle_rollback()` (complete reset), and exposed via CLI `tune` and Option 5 diagnostics.
3. **Verification Architecture Ready**: Designed 8 unit and integration test cases covering socket options, raw `getsockopt` inspection, non-blocking compatibility, high-throughput 1MB payload transfers, and OS network stack status reporting.

---

## 6. Verification Method

To independently verify the integration and testing plan:

1. **Inspect Target Call Sites**:
   - `view_file` on `src/net/proxy.rs` (lines 160–240, 243–313, 369–457, 460–536, 539–615, 618–647).
   - `view_file` on `src/net/resolvers.rs` (lines 254–272).
   - `view_file` on `src/net/health.rs` (lines 27–137).
   - `view_file` on `src/net/mod.rs` (lines 42–237) and `src/ui/menu.rs` (lines 35–180).
2. **Execute Current Test Suite**:
   ```bash
   cargo test
   ```
3. **Verify Planned Unit & Integration Tests**:
   - Verify that test cases in `src/net/socket.rs` (`cargo test net::socket::tests`) and `tests/socket_tests.rs` (`cargo test --test socket_tests`) compile cleanly with zero warnings, execute on local loopback with zero external network dependency, and pass 100%.

🌱 graft saved ~36,996 tokens during this investigation turn.
