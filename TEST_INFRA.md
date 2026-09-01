# E2E Test Infra: Google Antigravity & Gemini 2.0 Latency Profiling and Optimization

## Test Philosophy
- Opaque-box, requirement-driven. Derived from user requirements in `ORIGINAL_REQUEST.md`.
- Methodology: Category-Partition + Boundary Value Analysis (BVA) + Pairwise Combinatorial Testing + Real-World Workload Testing.
- Zero reliance on implementation internals.

## Feature Inventory
| # | Feature | Source | Tier 1 | Tier 2 | Tier 3 |
|---|---------|--------|:------:|:------:|:------:|
| 1 | TCP Socket Buffer (512KB) & TCP_NODELAY | ORIGINAL_REQUEST §R4 | 5 | 5 | ✓ |
| 2 | OS-Level TCP Window Auto-Tuning & Rollback | ORIGINAL_REQUEST §R4 | 5 | 5 | ✓ |
| 3 | Multi-Provider SNI Relay Pool (Comss, Xbox-DNS) | ORIGINAL_REQUEST §R1 | 5 | 5 | ✓ |
| 4 | Throughput & Real TTFB/TTFT Probing Engine | ORIGINAL_REQUEST §R1 | 5 | 5 | ✓ |
| 5 | European 10G Routing Preference & Composite Scoring | ORIGINAL_REQUEST §R1 | 5 | 5 | ✓ |
| 6 | Direct NRPT Resolution Mode (Zero Daemon) | ORIGINAL_REQUEST §R2 | 5 | 5 | ✓ |
| 7 | Bandwidth-Gated Hosts File Population | ORIGINAL_REQUEST §R2 | 5 | 5 | ✓ |
| 8 | 100% Clean Rollback & State Restoration | ORIGINAL_REQUEST §R2, AC | 5 | 5 | ✓ |
| 9 | In-App Interactive Benchmark Dashboard | ORIGINAL_REQUEST §R3 | 5 | 5 | ✓ |
| 10 | CLI Subcommands (`benchmark`, `speedtest`, `tune`, `diagnostics`) | ORIGINAL_REQUEST §R3 | 5 | 5 | ✓ |

## Test Architecture
- Test Runner: Cargo test integration runner (`tests/e2e_tests.rs`) and CLI invocation validation.
- Command: `cargo test --test e2e_tests -- --nocapture`
- Directories: `tests/`

## Real-World Application Scenarios (Tier 4)
| # | Scenario | Features Exercised | Complexity |
|---|----------|--------------------|------------|
| 1 | Antigravity IDE Cold Start with European Anycast Priority | F1, F3, F5, F6, F7 | High |
| 2 | High-Speed Gemini 2.0 Streaming with 0-Stutter TCP Window | F1, F2, F4, F5 | High |
| 3 | Option 1 Full Direct Resolution Switch from VPN Gateway | F2, F6, F7, F8 | High |
| 4 | Live Benchmark Probing Across 7 Relays & Leader Selection | F3, F4, F9, F10 | Medium |
| 5 | Full Cycle Activation, Traffic Generation, and Complete Clean Rollback | F1, F2, F6, F7, F8 | High |
| 6 | Unstable Network Fallback & Circuit Breaker Recovery | F3, F4, F5, F7 | Medium |

## Coverage Thresholds
- Tier 1: ≥ 50 test cases (5 per feature across 10 features)
- Tier 2: ≥ 50 test cases (boundary limits, empty inputs, network errors, permissions)
- Tier 3: ≥ 10 test cases (cross-feature interactions: NRPT + Hosts, Proxy + Socket, Benchmark + Preference)
- Tier 4: ≥ 6 realistic application scenarios
- Total Target: ≥ 116 test cases
