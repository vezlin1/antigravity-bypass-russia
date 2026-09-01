# Project: Google Antigravity & Gemini 2.0 Latency Profiling and Throughput Optimization

## Architecture
The Antigravity Bypass system consists of five core layers:
1. **OS Socket & TCP Stack Layer** (`src/net/socket.rs`, `src/net/routes.rs`):
   - Socket buffer configuration (512 KB `SO_RCVBUF` / `SO_SNDBUF`).
   - Strict `TCP_NODELAY` enforcement across all streams to eliminate Nagle Delayed-ACK jitter.
   - OS-level TCP Window Auto-Tuning (`netsh int tcp set global autotuninglevel=normal` on Windows, `sysctl` buffer tuning on macOS).
2. **Multi-Provider SNI Relay Pool & Ranking Engine** (`src/net/provider.rs`, `src/net/resolvers.rs`, `src/net/rank.rs`, `src/net/proxy.rs`):
   - Structured `RelayNode` pool with European 10G Anycast frontends (Comss Frankfurt/Amsterdam, Xbox-DNS Anycast) and regional tags.
   - Throughput-aware probing engine measuring TCP RTT, TLS ServerHello RTT, network TTFT, and download streaming bandwidth (KB/s).
   - Composite scoring algorithm prioritizing European 10G backbones (`RoutingPreference::PreferEurope10G`).
3. **Clean DNS & NRPT Direct Resolution Subsystem** (`src/net/mod.rs`, `src/net/nrpt.rs`, `src/net/hosts.rs`):
   - Direct NRPT mode: Windows `HKLM\...\DnsPolicyConfig` directly querying ranked SmartDNS IPs (`111.88.96.50;83.220.169.155;212.109.195.93`) with zero background daemon hop in Option 1 and Option 3.
   - macOS `/etc/resolver/` direct split-DNS parity.
   - Bandwidth-gated `hosts` population (only verified ultra-low-latency, non-throttled endpoints) with 100% clean rollback.
4. **Interactive In-App Benchmark & CLI Dashboard** (`src/net/health.rs`, `src/ui/menu.rs`, `src/main.rs`):
   - Option 5 upgrade to live interactive benchmark & speedtest table.
   - CLI subcommands `benchmark`, `speedtest`, `diagnostics`, and `tune`.
   - Real-time TTFT, token generation rate (tokens/s), and MB/s throughput telemetry.
5. **E2E Testing & Verification Infrastructure** (`tests/`, `TEST_INFRA.md`):
   - Comprehensive test suite covering Tiers 1–5 (Feature, Boundary, Combinatorial, Real-World, Adversarial).

## Code Layout
- `src/net/socket.rs`: Unified TCP stream / listener configuration, OS TCP stack auto-tuning and rollback.
- `src/net/provider.rs`: `RelayNode`, `RelayRegion`, `RoutingPreference`, `MULTI_PROVIDER_RELAYS`.
- `src/net/resolvers.rs`: Multi-provider resolution, TLS probe with SNI, composite metrics probing.
- `src/net/rank.rs`: Composite ranking, safe bandwidth-aware hosts application, ranking persistence.
- `src/net/proxy.rs`: High-throughput streaming proxy, racing connections with European Anycast priority.
- `src/net/mod.rs`: Direct NRPT / split-DNS setup without daemon hop for Options 1 & 3.
- `src/net/nrpt.rs`: Direct Win32 registry NRPT configuration and deletion.
- `src/net/hosts.rs`: Safe atomic hosts block insertion, validation, and clean rollback.
- `src/net/health.rs`: Live multi-relay benchmark engine, TTFT calculations, throughput measurement table.
- `src/ui/menu.rs`: Interactive UI, Option 5 Benchmark dashboard, Option 6 Clean Rollback.
- `src/main.rs`: CLI argument parsing (`benchmark`, `speedtest`, `tune`, `diagnostics`).
- `tests/`: Opaque-box E2E test harness and test cases.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| F1 | TCP Socket Buffer & NoDelay Tuning | Configure 512KB SO_RCVBUF/SO_SNDBUF and TCP_NODELAY across all streams | M1 | R4 |
| F2 | OS-Level TCP Window Auto-Tuning | Windows netsh autotuninglevel=normal, heuristics disabled, macOS sysctl | M1 | R4 |
| F3 | Multi-Provider SNI Relay Pool | Expand pool with Comss 10G (Frankfurt/Amsterdam/Helsinki), Xbox-DNS Anycast | M2 | R1 |
| F4 | Real-Time Bandwidth & TTFT Probing | Probe TCP RTT, TLS RTT, network TTFT, and download throughput | M2 | R1 |
| F5 | Preference-Aware Composite Scoring | Route preference favoring high-bandwidth European 10G nodes over congested RU seeds | M2 | R1 |
| F6 | Direct NRPT Resolution Mode | Windows DnsPolicyConfig direct upstream query without 127.0.0.53 daemon hop | M3 | R2 |
| F7 | Bandwidth-Gated Hosts Management | Only write confirmed ultra-low-latency, non-throttled IPs to hosts | M3 | R2 |
| F8 | Clean Rollback Across OS Platforms | 100% clean rollback of NRPT, hosts, routes, DoH, and socket settings | M3 | R2 |
| F9 | Interactive In-App Speedtest & Benchmark | Menu Option 5 real-time table with TTFT, MB/s, and tokens/sec | M4 | R3 |
| F10 | CLI Subcommands for Diagnostics & Tuning | `cargo run -- benchmark`, `speedtest`, `diagnostics`, `tune` | M4 | R3 |
| F11 | E2E Regression & Performance Verification | 100% pass of Tiers 1-4 E2E test suite and Tier 5 adversarial hardening | M5 | Acceptance Criteria |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | TCP Socket & OS Stack Fine-Tuning | F1, F2: `src/net/socket.rs`, `src/net/routes.rs`, OS autotuning | none | PLANNED |
| M2 | Multi-Provider Pool & Bandwidth-Aware Ranking | F3, F4, F5: `src/net/provider.rs`, `src/net/resolvers.rs`, `src/net/rank.rs`, `src/net/proxy.rs` | M1 | PLANNED |
| M3 | Clean Direct NRPT & Safe Hosts Management | F6, F7, F8: `src/net/mod.rs`, `src/net/nrpt.rs`, `src/net/hosts.rs` | M1, M2 | PLANNED |
| M4 | Interactive Benchmark & CLI Subcommands | F9, F10: `src/net/health.rs`, `src/ui/menu.rs`, `src/main.rs` | M1, M2, M3 | PLANNED |
| M5 | E2E Testing Suite Validation & Hardening | F11: Pass 100% E2E test suite (Tiers 1-4) and Tier 5 Adversarial Coverage Hardening | M1, M2, M3, M4 | PLANNED |

## Interface Contracts
### `src/net/socket.rs`
- `pub fn configure_tcp_stream(stream: &std::net::TcpStream) -> Result<(), String>`
- `pub fn configure_tcp_listener(listener: &std::net::TcpListener) -> Result<(), String>`
- `pub fn tune_os_network_stack() -> Result<Vec<String>, String>`
- `pub fn restore_os_network_stack() -> Result<Vec<String>, String>`
- `pub fn get_os_network_status() -> String`

### `src/net/provider.rs`
- `pub enum RelayRegion { EuropeCentral, EuropeNorth, AnycastGlobal, DomesticRu, Custom }`
- `pub struct RelayNode { pub ip: &'static str, pub provider: &'static str, pub location: &'static str, pub region: RelayRegion, pub bandwidth_mbps: u32, pub priority_weight: i32 }`
- `pub const MULTI_PROVIDER_RELAYS: &[RelayNode]`
- `pub enum RoutingPreference { PreferEurope10G, Balanced, LowestPing }`

### `src/net/health.rs`
- `pub struct BenchmarkResult { pub name: String, pub ip: String, pub tcp_rtt_ms: u128, pub tls_rtt_ms: u128, pub est_ttft_ms: u128, pub throughput_kb_s: f64, pub est_tokens_sec: f64, pub status: String, pub is_leader: bool }`
- `pub fn benchmark_all_relays() -> Vec<BenchmarkResult>`
- `pub fn format_benchmark_table(results: &[BenchmarkResult]) -> String`

### `src/net/rank.rs` & `src/net/resolvers.rs`
- `pub fn rank_relays_composite(preference: RoutingPreference) -> Vec<(Ipv4Addr, u64)>`
- `pub fn rescan_agent(if_index: u32) -> Vec<RankedHost>`
