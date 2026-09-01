# BRIEFING — 2026-09-01T15:02:00Z

## Mission
Investigate Proxy Pool, Ranking Engine, and Bandwidth/Throughput Probing (R1) for Google Antigravity & Gemini 2.0 bypass tool on Windows and macOS.

## 🔒 My Identity
- Archetype: explorer
- Roles: Survey Explorer (Survey Agent 1)
- Working directory: c:\Users\vezlin1\Desktop\antigravity fix\.agents\explorer_survey_1
- Original parent: 2204d774-883c-44fe-b0b5-96bdf83adb9d
- Milestone: Architectural Survey & Design for R1

## 🔒 Key Constraints
- Read-only investigation — do NOT implement code changes in src/
- Graft-first exploration for Rust AST code
- Produce self-contained 5-component handoff report in .agents/explorer_survey_1/handoff.md
- Ground all findings with exact line numbers, structs, functions, and logic flows

## Current Parent
- Conversation ID: 2204d774-883c-44fe-b0b5-96bdf83adb9d
- Updated: 2026-09-01T15:02:00Z

## Investigation State
- **Explored paths**:
  - `src/net/provider.rs`: `NRPT_TAG`, `NRPT_AGENT`, `NRPT_STUDIO`, `GEOHIDE_PROXY_V4`, `RouteCircuitBreaker`, `CustomUpstreamProxy`.
  - `src/net/rank.rs`: `RankedHost`, `rescan_agent`, `apply_hosts`, `spawn_background`, `save`, `load`.
  - `src/net/resolvers.rs`: `PROVIDERS`, `rank_tls_v4`, `tls_handshake_ms`, `tls_client_hello`, `classify`, `resolve_best`.
  - `src/net/health.rs`: `ConnReport`, `BenchmarkResult`, `probe_google_api`, `benchmark_all_relays`.
  - `src/net/proxy.rs`: `connect_with_racing`, `establish_upstream_connection`, `WINNING_UPSTREAM`, `TELEMETRY_RING`.
  - `src/net/hosts.rs`: `write_entries`, `remove_entries`, `hosts_path`.
  - `src/net/routes.rs`: `sync_physical_hosts`, `pin_via_physical`, `add_static_routes`.
  - `src/net/socket.rs`: `bind_socket_to_interface`, `set_socket_buffers`.
  - `src/net/nrpt.rs`: `apply_nrpt_rules_direct`, `get_nrpt_status_info`, `take_over_conflicting_rules`.
  - `src/ui/menu.rs`: `handle_unlock_all`, `handle_diagnostics`, `handle_proxy_menu`, `run_app`.
- **Key findings**:
  1. `resolvers::rank_tls_v4` only measures TCP SYN/ACK + ClientHello 5-byte header response time (local RTT to the proxy). It does NOT measure upstream Google Cloud connection speed, TTFT, or streaming throughput.
  2. Local Moscow seed proxies (`37.230.192.51`, `45.155.204.190`) have ~15ms local ping from Russian ISPs, causing them to be ranked at #1 over European Anycast (`83.220.169.155`, `212.109.195.93`, `111.88.96.50`) which have ~50ms local ping.
  3. `rank.rs::rescan_agent` writes this ranked list directly into `C:\Windows\System32\drivers\etc\hosts`. The OS/Antigravity IDE then directs all Cloud Code and Gemini traffic to the overloaded Moscow seed proxy, causing severe throttling, token stutter, and high TTFT.
  4. In `src/net/health.rs:benchmark_all_relays`, "TTFT" was actually only measuring TLS ServerHello receipt, not HTTP stream response or token speed.
  5. In `src/net/proxy.rs:connect_with_racing`, the fallback IP on circuit break or failure was hardcoded to `GEOHIDE_PROXY_V4[GEOHIDE_PROXY_V4.len() - 1]` (`37.230.192.51`).
- **Unexplored areas**: None within R1 scope.

## Key Decisions Made
- Fully documented the root causes of the ranking anomaly and detailed the complete architecture for multi-provider expansion, throughput-aware probing, and European 10G relay preference.

## Artifact Index
- `.agents/explorer_survey_1/handoff.md` — Complete 5-component architectural survey and design report for R1.
- `.agents/explorer_survey_1/progress.md` — Task progress & heartbeat.
- `.agents/explorer_survey_1/BRIEFING.md` — Persistent memory.
- `.agents/explorer_survey_1/DISPATCH.md` — Dispatch logs.
