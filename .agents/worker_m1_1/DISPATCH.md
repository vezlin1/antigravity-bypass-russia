## 2026-09-01T12:08:09Z
You are the Worker for Milestone 1 (M1: TCP Socket & OS Stack Fine-Tuning).
Your working directory is: `c:\Users\vezlin1\Desktop\antigravity fix\.agents\worker_m1_1`
Project root: `c:\Users\vezlin1\Desktop\antigravity fix`

CRITICAL: Read `c:\Users\vezlin1\Desktop\antigravity fix\.agents\ORIGINAL_REQUEST.md` and `c:\Users\vezlin1\Desktop\antigravity fix\PROJECT.md` first.

Read the 3 Explorer handoff reports:
1. `c:\Users\vezlin1\Desktop\antigravity fix\.agents\explorer_m1_1\handoff.md` (TCP Stream & Socket Configuration)
2. `c:\Users\vezlin1\Desktop\antigravity fix\.agents\explorer_m1_2\handoff.md` (OS Network Stack Auto-Tuning & Rollback)
3. `c:\Users\vezlin1\Desktop\antigravity fix\.agents\explorer_m1_3\handoff.md` (Integration Sites & Unit/Integration Tests)

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Scope & Tasks for Milestone 1:
1. Implement `src/net/socket.rs`:
   - `pub fn configure_tcp_stream(stream: &std::net::TcpStream) -> Result<(), String>` (sets `TCP_NODELAY = true` and `SO_RCVBUF` / `SO_SNDBUF` = 512KB with fallback ladder).
   - `pub fn configure_tcp_listener(listener: &std::net::TcpListener) -> Result<(), String>`.
   - `pub fn tune_os_network_stack() -> Result<Vec<String>, String>` (Windows `netsh int tcp` global tuning, macOS sysctl).
   - `pub fn restore_os_network_stack() -> Result<Vec<String>, String>`.
   - `pub fn get_os_network_status() -> String`.
   - Unit test suite inside `src/net/socket.rs` (`mod tests`).
2. Integrate `configure_tcp_stream` and `configure_tcp_listener` across:
   - `src/net/proxy.rs` (listeners, client sockets, racing connections, upstream piping).
   - `src/net/resolvers.rs` (`tls_handshake_ms`).
   - `src/net/health.rs` (`probe_google_api`, `benchmark_all_relays`).
   - `src/net/rank.rs`.
3. Integrate OS tuning into:
   - `src/net/mod.rs` (`apply_dns_rules` activates OS tuning; `remove_dns_rules` restores OS tuning).
   - `src/ui/menu.rs` (`handle_rollback` restores OS tuning; `handle_diagnostics` reports TCP status).
   - `src/main.rs` (add `tune` subcommand and update `proxy`/`unlock` to tune stack).
4. Implement integration tests in `tests/socket_tests.rs` (high-throughput bidirectional loopback transfer, concurrent stream tuning, buffer verification).
5. Build and verify: Run `cargo check` and `cargo test` to ensure 100% passing tests and zero warnings/errors.
6. Write your progress and handoff report to `c:\Users\vezlin1\Desktop\antigravity fix\.agents\worker_m1_1\handoff.md` including exact commands run and output.
7. Send a completion message back to the orchestrator.
