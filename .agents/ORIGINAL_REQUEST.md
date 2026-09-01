# Original User Request

## 2026-09-01T11:57:31Z

Comprehensive diagnosis, latency profiling, and throughput optimization for Google Antigravity & Gemini 2.0 bypass tool on Windows and macOS, bringing response latency and streaming throughput to parity with high-speed direct connections / native VPN.

Working directory: `c:\Users\vezlin1\Desktop\antigravity fix`
Integrity mode: development

## Problem Identification & Root Causes

1. **Hosts File Forcing to Overloaded/Throttled Seed Proxies**:
   - The ranking engine (`src/net/rank.rs`) was prioritizing local Moscow seed proxies (`37.230.192.51`, `45.155.204.190`) based solely on local TCP ping (~15ms), ignoring throughput and upstream transit speed to Google Cloud.
   - Writing these IPs to `hosts` forced Antigravity IDE to bypass high-bandwidth European Anycast SNI edges from Comss (`83.220.169.155`, `212.109.195.93`) and Xbox-DNS (`111.88.96.50`, `111.88.96.51`).

2. **Missing Real-Time Throughput / Speed Probing**:
   - Ranking only measured TLS handshake RTT, not TTFT or streaming download speed.

3. **DNS Query Layering & Relay Redundancy**:
   - NRPT rule delegation to `127.0.0.53:53` introduces unnecessary local context-switching when direct SmartDNS server IPs can be registered directly into Windows `DnsPolicyConfig` and macOS `/etc/resolver/`.

## Requirements

### R1. Multi-Provider SNI Proxy Pool Expansion & Bandwidth-Aware Ranking
- Expand the proxy pool beyond Geohide to include high-speed Comss, Xbox-DNS, and European Anycast SNI nodes.
- Implement throughput-aware benchmarking (measuring both Handshake RTT and HTTP response stream speed).
- Provide an option to prefer high-bandwidth European relays over congested local seed proxies.

### R2. Clean DNS & NRPT Direct Resolution Mode
- Optimize Windows NRPT (`DnsPolicyConfig`) to directly query the fastest ranked SmartDNS servers (`111.88.96.50`, `83.220.169.155`) without requiring an intermediate local daemon hop when running in Option 1.
- Ensure `hosts` is only populated with confirmed ultra-low-latency, non-throttled endpoints.

### R3. Interactive In-App Benchmark & Speed Test (Option in Menu)
- Add an interactive speedtest tool to the CLI and Menu (`src/ui/menu.rs` -> Option 5) that live-tests:
  - Latency to Gemini API endpoints
  - Time-To-First-Token (TTFT)
  - Real streaming speed in tokens/sec and KB/sec across all available relays.

### R4. Windows / macOS TCP Socket Fine-Tuning
- Configure TCP Window Auto-Tuning and socket buffer sizes (`SO_RCVBUF` / `SO_SNDBUF` = 512 KB).
- Guarantee `TCP_NODELAY` across all forwarding pathways.

## Acceptance Criteria

### Performance & Latency Guardrails
- [ ] Time-to-First-Token (TTFT) for simple queries (e.g. "Привет") is under 400ms on standard broadband connections.
- [ ] Token streaming generates continuous, real-time output with zero stutter or Delayed-ACK pauses.
- [ ] Interactive benchmark reports real-time latency (< 60ms) and streaming throughput for each candidate server.
- [ ] Clean rollback and zero regression across Windows 10/11 and macOS Apple Silicon/Intel.
