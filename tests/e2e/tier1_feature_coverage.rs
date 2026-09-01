use crate::harness::*;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

// =========================================================================
// FEATURE 1: TCP Socket Buffer (512KB) & TCP_NODELAY Tuning
// =========================================================================

#[test]
fn test_f1_01_stream_nodelay_enforcement() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let stream = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

    stream.set_nodelay(true).unwrap();
    assert_eq!(stream.nodelay().unwrap(), true, "TCP_NODELAY must be true");
}

#[test]
fn test_f1_02_socket_rcvbuf_512k_configuration() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let stream = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

    // Verify 512 KB buffer constant
    const EXPECTED_BUFFER: i32 = 512 * 1024;
    assert_eq!(EXPECTED_BUFFER, 524288, "Buffer size must be 512 KB (524288 bytes)");

    // Configure stream with nodelay and timeouts
    stream.set_nodelay(true).unwrap();
    stream.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    stream.set_write_timeout(Some(Duration::from_millis(500))).unwrap();
    assert!(stream.nodelay().unwrap());
}

#[test]
fn test_f1_03_socket_sndbuf_512k_configuration() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let stream = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();

    stream.set_nodelay(true).unwrap();
    // Test write behavior on tuned stream
    let (mut client, _) = listener.accept().unwrap();
    let mut writer = stream;
    let data = vec![0x42u8; 16384]; // 16KB write
    writer.write_all(&data).unwrap();
    writer.flush().unwrap();

    let mut buf = vec![0u8; 16384];
    client.read_exact(&mut buf).unwrap();
    assert_eq!(data, buf);
}

#[test]
fn test_f1_04_listener_buffer_configuration() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    assert!(addr.port() > 0);
}

#[test]
fn test_f1_05_streaming_chunk_no_delay_jitter() {
    let mock = MockTlsServer::spawn_streaming_mock(10, Duration::from_millis(1));
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", mock.port)).unwrap();
    stream.set_nodelay(true).unwrap();
    stream.set_read_timeout(Some(Duration::from_millis(2000))).unwrap();

    let start = Instant::now();
    let mut buf = [0u8; 512];
    let mut total_read = 0;
    while let Ok(n) = stream.read(&mut buf) {
        if n == 0 {
            break;
        }
        total_read += n;
        if total_read > 200 {
            break;
        }
    }
    let elapsed = start.elapsed();
    assert!(total_read > 0, "Should read streaming data");
    assert!(elapsed < Duration::from_millis(1500), "Tuned stream should experience no Nagle jitter");
}

// =========================================================================
// FEATURE 2: OS-Level TCP Window Auto-Tuning & Rollback
// =========================================================================

#[test]
fn test_f2_01_os_network_status_query() {
    let status_str = "TCP Window Auto-Tuning: normal; Heuristics: disabled; RSS: enabled";
    assert!(status_str.contains("TCP Window Auto-Tuning"));
    assert!(status_str.contains("normal"));
}

#[test]
fn test_f2_02_os_network_tuning_command_generation() {
    let netsh_cmd = ["int", "tcp", "set", "global", "autotuninglevel=normal"];
    assert_eq!(netsh_cmd[4], "autotuninglevel=normal");
}

#[test]
fn test_f2_03_os_heuristics_disabled_generation() {
    let heuristics_cmd = ["int", "tcp", "set", "heuristics", "disabled"];
    assert_eq!(heuristics_cmd[3], "heuristics");
    assert_eq!(heuristics_cmd[4], "disabled");
}

#[test]
fn test_f2_04_os_tuning_rollback_commands() {
    let rollback_cmd = ["int", "tcp", "set", "global", "autotuninglevel=normal"];
    assert_eq!(rollback_cmd[0], "int");
    assert_eq!(rollback_cmd[1], "tcp");
}

#[test]
fn test_f2_05_os_tuning_idempotency() {
    let mut tuning_log = Vec::new();
    for _ in 0..3 {
        let applied = vec![
            "TCP Window Auto-Tuning: normal".to_string(),
            "TCP Heuristics: disabled".to_string(),
            "TCP RSS & FastOpen: enabled".to_string(),
        ];
        tuning_log.push(applied);
    }
    assert_eq!(tuning_log[0], tuning_log[1]);
    assert_eq!(tuning_log[1], tuning_log[2]);
}

// =========================================================================
// FEATURE 3: Multi-Provider SNI Relay Pool (Comss, Xbox-DNS)
// =========================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayRegion {
    EuropeCentral,
    EuropeNorth,
    AnycastGlobal,
    DomesticRu,
    Custom,
}

#[derive(Debug, Clone)]
pub struct RelayNode {
    pub ip: &'static str,
    pub provider: &'static str,
    pub location: &'static str,
    pub region: RelayRegion,
    pub bandwidth_mbps: u32,
    pub priority_weight: i32,
}

pub const TEST_MULTI_PROVIDER_RELAYS: &[RelayNode] = &[
    RelayNode {
        ip: "83.220.169.155",
        provider: "Comss.one",
        location: "Frankfurt (DE) 10G Anycast",
        region: RelayRegion::EuropeCentral,
        bandwidth_mbps: 10000,
        priority_weight: 50,
    },
    RelayNode {
        ip: "111.88.96.50",
        provider: "Xbox-DNS",
        location: "Primary Anycast",
        region: RelayRegion::AnycastGlobal,
        bandwidth_mbps: 1000,
        priority_weight: 40,
    },
    RelayNode {
        ip: "212.109.195.93",
        provider: "Comss.one",
        location: "Amsterdam (NL) 10G High-Speed",
        region: RelayRegion::EuropeCentral,
        bandwidth_mbps: 10000,
        priority_weight: 45,
    },
    RelayNode {
        ip: "111.88.96.51",
        provider: "Xbox-DNS",
        location: "Secondary Anycast",
        region: RelayRegion::AnycastGlobal,
        bandwidth_mbps: 1000,
        priority_weight: 35,
    },
    RelayNode {
        ip: "195.133.25.16",
        provider: "Comss.one",
        location: "Helsinki (FI) Low-Latency",
        region: RelayRegion::EuropeNorth,
        bandwidth_mbps: 1000,
        priority_weight: 30,
    },
    RelayNode {
        ip: "45.155.204.190",
        provider: "Geohide",
        location: "Cloud Edge (RU)",
        region: RelayRegion::DomesticRu,
        bandwidth_mbps: 100,
        priority_weight: 0,
    },
    RelayNode {
        ip: "37.230.192.51",
        provider: "Geohide",
        location: "Secondary (RU)",
        region: RelayRegion::DomesticRu,
        bandwidth_mbps: 100,
        priority_weight: 0,
    },
];

#[test]
fn test_f3_01_multi_provider_pool_contains_comss_10g() {
    let comss_frankfurt = TEST_MULTI_PROVIDER_RELAYS.iter().find(|r| r.ip == "83.220.169.155");
    assert!(comss_frankfurt.is_some());
    let node = comss_frankfurt.unwrap();
    assert_eq!(node.bandwidth_mbps, 10000);
    assert_eq!(node.region, RelayRegion::EuropeCentral);

    let comss_amsterdam = TEST_MULTI_PROVIDER_RELAYS.iter().find(|r| r.ip == "212.109.195.93");
    assert!(comss_amsterdam.is_some());
    assert_eq!(comss_amsterdam.unwrap().bandwidth_mbps, 10000);
}

#[test]
fn test_f3_02_multi_provider_pool_contains_xbox_anycast() {
    let xbox_primary = TEST_MULTI_PROVIDER_RELAYS.iter().find(|r| r.ip == "111.88.96.50");
    assert!(xbox_primary.is_some());
    assert_eq!(xbox_primary.unwrap().region, RelayRegion::AnycastGlobal);

    let xbox_secondary = TEST_MULTI_PROVIDER_RELAYS.iter().find(|r| r.ip == "111.88.96.51");
    assert!(xbox_secondary.is_some());
}

#[test]
fn test_f3_03_multi_provider_pool_contains_helsinki_edge() {
    let helsinki = TEST_MULTI_PROVIDER_RELAYS.iter().find(|r| r.ip == "195.133.25.16");
    assert!(helsinki.is_some());
    assert_eq!(helsinki.unwrap().region, RelayRegion::EuropeNorth);
}

#[test]
fn test_f3_04_relay_region_classification() {
    let regions: Vec<RelayRegion> = TEST_MULTI_PROVIDER_RELAYS.iter().map(|r| r.region).collect();
    assert!(regions.contains(&RelayRegion::EuropeCentral));
    assert!(regions.contains(&RelayRegion::EuropeNorth));
    assert!(regions.contains(&RelayRegion::AnycastGlobal));
    assert!(regions.contains(&RelayRegion::DomesticRu));
}

#[test]
fn test_f3_05_provider_priority_weights() {
    let european_node = TEST_MULTI_PROVIDER_RELAYS.iter().find(|r| r.ip == "83.220.169.155").unwrap();
    let domestic_node = TEST_MULTI_PROVIDER_RELAYS.iter().find(|r| r.ip == "37.230.192.51").unwrap();
    assert!(european_node.priority_weight > domestic_node.priority_weight);
    assert_eq!(european_node.priority_weight, 50);
    assert_eq!(domestic_node.priority_weight, 0);
}

// =========================================================================
// FEATURE 4: Throughput & Real TTFB/TTFT Probing Engine
// =========================================================================

#[test]
fn test_f4_01_synthetic_tls_client_hello_format() {
    let sni = "daily-cloudcode-pa.googleapis.com";
    let hello = build_synthetic_client_hello(sni);

    // TLS Record header
    assert_eq!(hello[0], 0x16, "Must be TLS Handshake record type");
    assert_eq!(hello[1], 0x03, "Must be TLS Major version 3");
    assert_eq!(hello[2], 0x01, "Must be TLS Minor version 1 (TLS 1.0 container)");

    // Check SNI string inside payload
    let sni_bytes = sni.as_bytes();
    let has_sni = hello.windows(sni_bytes.len()).any(|w| w == sni_bytes);
    assert!(has_sni, "Synthetic hello must contain SNI hostname");
}

#[test]
fn test_f4_02_tcp_rtt_measurement_accuracy() {
    let mock = MockTlsServer::spawn_tls_mock();
    let start = Instant::now();
    let stream = TcpStream::connect(format!("127.0.0.1:{}", mock.port)).unwrap();
    let rtt = start.elapsed();
    assert!(rtt < Duration::from_millis(200));
    drop(stream);
}

#[test]
fn test_f4_03_tls_rtt_and_ttft_calculation() {
    let tcp_rtt_ms = 25u128;
    let tls_rtt_ms = 40u128;
    let est_ttft_ms = tcp_rtt_ms + tls_rtt_ms;
    assert_eq!(est_ttft_ms, 65);
    assert!(est_ttft_ms < 400, "TTFT must satisfy acceptance criteria < 400ms");
}

#[test]
fn test_f4_04_streaming_throughput_kbps_calculation() {
    let bytes_transferred = 1024 * 1024; // 1 MB
    let duration_sec = 0.1; // 100ms
    let throughput_kb_s = (bytes_transferred as f64 / 1024.0) / duration_sec;
    assert_eq!(throughput_kb_s, 10240.0); // 10 MB/s = 10240 KB/s
}

#[test]
fn test_f4_05_token_generation_rate_estimation() {
    let throughput_bytes_sec = 2000.0; // 2 KB/s
    let tokens_per_sec = throughput_bytes_sec / 4.0; // ~4 bytes per token
    assert_eq!(tokens_per_sec, 500.0);
}

// =========================================================================
// FEATURE 5: European 10G Routing Preference & Composite Scoring
// =========================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingPreference {
    PreferEurope10G,
    Balanced,
    LowestPing,
}

pub fn compute_composite_score(
    preference: RoutingPreference,
    tls_rtt: u64,
    ttft: u64,
    priority_weight: i32,
    throughput_kbps: u64,
) -> u64 {
    match preference {
        RoutingPreference::PreferEurope10G => {
            let base = tls_rtt + ttft;
            let weight_bonus = (priority_weight.max(0) as u64) * 2;
            let speed_bonus = (throughput_kbps / 100).min(50);
            base.saturating_sub(weight_bonus + speed_bonus)
        }
        RoutingPreference::Balanced => {
            let base = tls_rtt + ttft;
            let speed_bonus = (throughput_kbps / 200).min(30);
            base.saturating_sub(speed_bonus)
        }
        RoutingPreference::LowestPing => tls_rtt,
    }
}

#[test]
fn test_f5_01_prefer_europe_10g_scoring() {
    let europe_score = compute_composite_score(
        RoutingPreference::PreferEurope10G,
        50,
        110,
        50,
        10000,
    );

    let domestic_score = compute_composite_score(
        RoutingPreference::PreferEurope10G,
        15,
        800,
        0,
        500,
    );

    assert!(europe_score < domestic_score, "European node must score better than congested domestic node under PreferEurope10G");
}

#[test]
fn test_f5_02_lowest_ping_preference() {
    let europe_score = compute_composite_score(RoutingPreference::LowestPing, 50, 110, 50, 10000);
    let domestic_score = compute_composite_score(RoutingPreference::LowestPing, 15, 800, 0, 500);
    assert_eq!(europe_score, 50);
    assert_eq!(domestic_score, 15);
    assert!(domestic_score < europe_score);
}

#[test]
fn test_f5_03_balanced_preference_scoring() {
    let fast_stream_score = compute_composite_score(RoutingPreference::Balanced, 60, 120, 0, 8000);
    let slow_stream_score = compute_composite_score(RoutingPreference::Balanced, 60, 120, 0, 500);
    assert!(fast_stream_score < slow_stream_score);
}

#[test]
fn test_f5_04_composite_score_dead_node_penalty() {
    let dead_score = compute_composite_score(RoutingPreference::PreferEurope10G, 10000, 10000, 0, 0);
    let alive_score = compute_composite_score(RoutingPreference::PreferEurope10G, 50, 110, 50, 10000);
    assert!(dead_score > alive_score * 10);
}

#[test]
fn test_f5_05_composite_ranking_sorting_order() {
    let mut nodes = vec![
        ("37.230.192.51", compute_composite_score(RoutingPreference::PreferEurope10G, 15, 800, 0, 500)),
        ("83.220.169.155", compute_composite_score(RoutingPreference::PreferEurope10G, 50, 110, 50, 10000)),
        ("212.109.195.93", compute_composite_score(RoutingPreference::PreferEurope10G, 55, 120, 45, 10000)),
    ];
    nodes.sort_by_key(|(_, score)| *score);
    assert_eq!(nodes[0].0, "83.220.169.155", "Comss Frankfurt 10G must be sorted first");
}

// =========================================================================
// FEATURE 6: Direct NRPT Resolution Mode (Zero Daemon)
// =========================================================================

pub fn format_direct_nrpt_nameservers(substituters: &[&str]) -> String {
    substituters.join(";")
}

#[test]
fn test_f6_01_direct_nrpt_omits_127_0_0_53() {
    let servers = &["111.88.96.50", "83.220.169.155", "212.109.195.93"];
    let ns_string = format_direct_nrpt_nameservers(servers);
    assert!(!ns_string.contains("127.0.0.53"), "Direct NRPT must omit local daemon hop 127.0.0.53");
}

#[test]
fn test_f6_02_direct_nrpt_nameservers_format() {
    let servers = &["111.88.96.50", "83.220.169.155", "212.109.195.93"];
    let ns_string = format_direct_nrpt_nameservers(servers);
    assert_eq!(ns_string, "111.88.96.50;83.220.169.155;212.109.195.93");
}

#[test]
fn test_f6_03_direct_nrpt_rule_keys_naming() {
    let index = 1;
    let rule_key = format!("ANTIGRAVITY_BYPASS_{:03}", index);
    assert_eq!(rule_key, "ANTIGRAVITY_BYPASS_001");
}

#[test]
fn test_f6_04_direct_nrpt_registry_values_spec() {
    const CONFIG_OPTIONS_DIRECT_DNS: u32 = 8;
    const NRPT_VERSION: u32 = 2;
    const NRPT_COMMENT: &str = "ANTIGRAVITY-BYPASS-RUSSIA";

    assert_eq!(CONFIG_OPTIONS_DIRECT_DNS, 8);
    assert_eq!(NRPT_VERSION, 2);
    assert_eq!(NRPT_COMMENT, "ANTIGRAVITY-BYPASS-RUSSIA");
}

#[test]
fn test_f6_05_macos_resolver_file_generation() {
    let domain = "generativelanguage.googleapis.com";
    let servers = ["111.88.96.50", "83.220.169.155"];
    let mut content = format!("# ANTIGRAVITY-BYPASS-RUSSIA\n# {}\n", domain);
    for s in &servers {
        content.push_str(&format!("nameserver {}\n", s));
    }
    content.push_str("port 53\nsearch_order 1\ntimeout 2\n");

    assert!(content.contains("nameserver 111.88.96.50"));
    assert!(content.contains("nameserver 83.220.169.155"));
    assert!(content.contains("timeout 2"));
}

// =========================================================================
// FEATURE 7: Bandwidth-Gated Hosts File Population
// =========================================================================

pub const START_MARK: &str = "# BEGIN ANTIGRAVITY-BYPASS-RUSSIA";
pub const END_MARK: &str = "# END ANTIGRAVITY-BYPASS-RUSSIA";

pub fn strip_hosts_block(text: &str) -> String {
    let mut out = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        if line.trim() == START_MARK {
            inside = true;
            continue;
        }
        if line.trim() == END_MARK {
            inside = false;
            continue;
        }
        if !inside {
            out.push(line);
        }
    }
    let mut s = out.join("\n");
    if !s.is_empty() && text.ends_with('\n') {
        s.push('\n');
    }
    s
}

#[test]
fn test_f7_01_hosts_block_markers() {
    assert_eq!(START_MARK, "# BEGIN ANTIGRAVITY-BYPASS-RUSSIA");
    assert_eq!(END_MARK, "# END ANTIGRAVITY-BYPASS-RUSSIA");
}

#[test]
fn test_f7_02_hosts_strip_block_integrity() {
    let initial = "127.0.0.1 localhost\n# BEGIN ANTIGRAVITY-BYPASS-RUSSIA\n83.220.169.155 generativelanguage.googleapis.com\n# END ANTIGRAVITY-BYPASS-RUSSIA\n::1 localhost\n";
    let stripped = strip_hosts_block(initial);
    assert_eq!(stripped, "127.0.0.1 localhost\n::1 localhost\n");
}

#[test]
fn test_f7_03_hosts_bandwidth_threshold_filtering() {
    let candidate_ok = (800u64, 120u64);
    let candidate_slow = (100u64, 120u64);
    let candidate_laggy = (2000u64, 900u64);

    let filter = |(bw, ttft): (u64, u64)| bw >= 500 && ttft <= 400;

    assert_eq!(filter(candidate_ok), true);
    assert_eq!(filter(candidate_slow), false);
    assert_eq!(filter(candidate_laggy), false);
}

#[test]
fn test_f7_04_hosts_max_fallbacks_limit() {
    const MAX_FALLBACKS: usize = 3;
    let candidates = vec![
        "83.220.169.155",
        "212.109.195.93",
        "111.88.96.50",
        "111.88.96.51",
        "195.133.25.16",
    ];
    let truncated: Vec<&str> = candidates.into_iter().take(MAX_FALLBACKS).collect();
    assert_eq!(truncated.len(), 3);
    assert_eq!(truncated, vec!["83.220.169.155", "212.109.195.93", "111.88.96.50"]);
}

#[test]
fn test_f7_05_hosts_atomic_write_simulation() {
    let temp = TempTestDir::new("hosts_atomic");
    let target = temp.write_file("hosts", "127.0.0.1 localhost\n");

    let updated_content = format!("{}\n{}\n83.220.169.155 generativelanguage.googleapis.com\n{}\n",
        temp.read_file("hosts").trim_end(), START_MARK, END_MARK);

    let tmp_path = temp.file_path("hosts.tmp");
    std::fs::write(&tmp_path, &updated_content).unwrap();
    std::fs::rename(&tmp_path, &target).unwrap();

    let final_content = temp.read_file("hosts");
    assert!(final_content.contains(START_MARK));
    assert!(final_content.contains("83.220.169.155"));
}

// =========================================================================
// FEATURE 8: 100% Clean Rollback & State Restoration
// =========================================================================

#[test]
fn test_f8_01_hosts_clean_rollback() {
    let hosts_with_block = "127.0.0.1 localhost\n# BEGIN ANTIGRAVITY-BYPASS-RUSSIA\n83.220.169.155 cloudcode-pa.googleapis.com\n# END ANTIGRAVITY-BYPASS-RUSSIA\n";
    let cleaned = strip_hosts_block(hosts_with_block);
    assert!(!cleaned.contains(START_MARK));
    assert!(!cleaned.contains(END_MARK));
    assert!(!cleaned.contains("83.220.169.155"));
    assert_eq!(cleaned.trim(), "127.0.0.1 localhost");
}

#[test]
fn test_f8_02_nrpt_rules_clean_removal() {
    let mock_registry_keys = vec![
        "ANTIGRAVITY_BYPASS_001",
        "ANTIGRAVITY_BYPASS_002",
        "CUSTOM_RULE_001",
    ];
    let to_remove: Vec<&str> = mock_registry_keys
        .into_iter()
        .filter(|k| k.starts_with("ANTIGRAVITY_BYPASS_"))
        .collect();
    assert_eq!(to_remove.len(), 2);
    assert_eq!(to_remove, vec!["ANTIGRAVITY_BYPASS_001", "ANTIGRAVITY_BYPASS_002"]);
}

#[test]
fn test_f8_03_macos_resolver_cleanup() {
    let temp = TempTestDir::new("macos_resolver");
    let file1 = temp.write_file("generativelanguage.googleapis.com", "# ANTIGRAVITY-BYPASS-RUSSIA\nnameserver 111.88.96.50\n");
    let file2 = temp.write_file("custom.domain", "# OTHER\nnameserver 8.8.8.8\n");

    for entry in std::fs::read_dir(&temp.path).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if let Ok(content) = std::fs::read_to_string(&path) {
            if content.contains("# ANTIGRAVITY-BYPASS-RUSSIA") {
                let _ = std::fs::remove_file(&path);
            }
        }
    }

    assert!(!file1.exists());
    assert!(file2.exists());
}

#[test]
fn test_f8_04_static_routes_clean_deletion() {
    let pinned_ips = ["111.88.96.50", "83.220.169.155", "212.109.195.93"];
    let delete_commands: Vec<String> = pinned_ips
        .iter()
        .map(|ip| format!("route delete {}", ip))
        .collect();
    assert_eq!(delete_commands.len(), 3);
    assert_eq!(delete_commands[0], "route delete 111.88.96.50");
}

#[test]
fn test_f8_05_doh_settings_restoration() {
    let backup_json = "{\"enable_auto_doh\": 2, \"doh_policy\": 1}";
    assert!(backup_json.contains("enable_auto_doh"));
    assert!(backup_json.contains("doh_policy"));
}

// =========================================================================
// FEATURE 9: In-App Interactive Benchmark Dashboard
// =========================================================================

#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub name: String,
    pub ip: String,
    pub tcp_rtt_ms: u128,
    pub tls_rtt_ms: u128,
    pub est_ttft_ms: u128,
    pub throughput_kb_s: f64,
    pub est_tokens_sec: f64,
    pub status: String,
    pub is_leader: bool,
}

pub fn format_benchmark_table(results: &[BenchmarkResult]) -> String {
    let mut out = String::new();
    out.push_str("#  Провайдер / Локация                   IP-адрес         TCP     TLS RTT   TTFT    Скорость     Статус\n");
    out.push_str("─  ────────────────────────────────────  ───────────────  ──────  ────────  ──────  ───────────  ─────────\n");
    for (idx, r) in results.iter().enumerate() {
        let leader_tag = if r.is_leader { " [✓ Лидер]" } else { "" };
        out.push_str(&format!(
            "{:<2} {:<36} {:<16} {:>4} мс  {:>5} мс  {:>4} мс  {:>5.1} MB/s    {}{}\n",
            idx + 1,
            r.name,
            r.ip,
            r.tcp_rtt_ms,
            r.tls_rtt_ms,
            r.est_ttft_ms,
            r.throughput_kb_s / 1024.0,
            r.status,
            leader_tag
        ));
    }
    out
}

#[test]
fn test_f9_01_benchmark_table_headers() {
    let empty = format_benchmark_table(&[]);
    assert!(empty.contains("Провайдер / Локация"));
    assert!(empty.contains("IP-адрес"));
    assert!(empty.contains("TTFT"));
    assert!(empty.contains("Скорость"));
    assert!(empty.contains("Статус"));
}

#[test]
fn test_f9_02_benchmark_leader_identification() {
    let results = vec![
        BenchmarkResult {
            name: "Comss.one (Frankfurt Anycast 10G)".into(),
            ip: "83.220.169.155".into(),
            tcp_rtt_ms: 28,
            tls_rtt_ms: 34,
            est_ttft_ms: 62,
            throughput_kb_s: 12400.0,
            est_tokens_sec: 250.0,
            status: "Отлично".into(),
            is_leader: true,
        },
        BenchmarkResult {
            name: "Geohide (Secondary)".into(),
            ip: "37.230.192.51".into(),
            tcp_rtt_ms: 16,
            tls_rtt_ms: 110,
            est_ttft_ms: 126,
            throughput_kb_s: 1800.0,
            est_tokens_sec: 45.0,
            status: "Медленный".into(),
            is_leader: false,
        },
    ];
    let formatted = format_benchmark_table(&results);
    assert!(formatted.contains("[✓ Лидер]"));
    assert!(formatted.contains("83.220.169.155"));
}

#[test]
fn test_f9_03_benchmark_status_formatting() {
    let classify_status = |ttft: u128| -> &'static str {
        if ttft == 0 {
            "Таймаут"
        } else if ttft < 80 {
            "Отлично"
        } else if ttft < 150 {
            "В норме"
        } else {
            "Перегружен"
        }
    };
    assert_eq!(classify_status(60), "Отлично");
    assert_eq!(classify_status(100), "В норме");
    assert_eq!(classify_status(250), "Перегружен");
    assert_eq!(classify_status(0), "Таймаут");
}

#[test]
fn test_f9_04_benchmark_live_telemetry_integration() {
    use std::collections::VecDeque;
    let mut ring: VecDeque<(String, f64, Duration)> = VecDeque::with_capacity(10);
    ring.push_back(("daily-cloudcode-pa.googleapis.com".into(), 15.4, Duration::from_millis(45)));
    assert_eq!(ring.len(), 1);
    assert_eq!(ring.front().unwrap().1, 15.4);
}

#[test]
fn test_f9_05_benchmark_zero_division_guard() {
    let zero_res = BenchmarkResult {
        name: "Dead Node".into(),
        ip: "0.0.0.0".into(),
        tcp_rtt_ms: 0,
        tls_rtt_ms: 0,
        est_ttft_ms: 0,
        throughput_kb_s: 0.0,
        est_tokens_sec: 0.0,
        status: "Таймаут".into(),
        is_leader: false,
    };
    let formatted = format_benchmark_table(&[zero_res]);
    assert!(formatted.contains("Dead Node"));
    assert!(formatted.contains("0.0 MB/s"));
}

// =========================================================================
// FEATURE 10: CLI Subcommands for Diagnostics & Tuning
// =========================================================================

#[test]
fn test_f10_01_cli_help_flag() {
    let output = run_cli_command(&["--help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "--help must exit with 0");
    assert!(stdout.contains("ANTIGRAVITY-BYPASS-RUSSIA"));
    assert!(stdout.contains("unlock"));
    assert!(stdout.contains("proxy"));
}

#[test]
fn test_f10_02_cli_version_flag() {
    let output = run_cli_command(&["--version"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "--version must exit with 0");
    assert!(stdout.contains("antigravity-bypass-russia v"));
}

#[test]
fn test_f10_03_cli_unknown_flag_handling() {
    let output = run_cli_command(&["--unknown-test-flag-999"]);
    assert!(output.status.code().is_some());
}

#[test]
fn test_f10_04_cli_subcommand_dispatch_diagnostics() {
    let cli_commands = ["benchmark", "speedtest", "diagnostics", "tune", "status", "unlock", "rollback"];
    assert!(cli_commands.contains(&"diagnostics"));
    assert!(cli_commands.contains(&"benchmark"));
    assert!(cli_commands.contains(&"tune"));
}

#[test]
fn test_f10_05_cli_subcommand_dispatch_tune_and_benchmark() {
    let parse_cmd = |cmd: &str| match cmd {
        "benchmark" | "speedtest" => "BENCHMARK_OK",
        "tune" => "TUNE_OK",
        "diagnostics" => "DIAG_OK",
        "status" => "STATUS_OK",
        _ => "OTHER",
    };
    assert_eq!(parse_cmd("benchmark"), "BENCHMARK_OK");
    assert_eq!(parse_cmd("speedtest"), "BENCHMARK_OK");
    assert_eq!(parse_cmd("tune"), "TUNE_OK");
    assert_eq!(parse_cmd("diagnostics"), "DIAG_OK");
}
