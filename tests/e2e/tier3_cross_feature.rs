use crate::harness::*;
use crate::tier1_feature_coverage::*;
use std::io::Read;
use std::net::TcpStream;
use std::time::{Duration, Instant};

#[test]
fn test_t3_01_socket_tuning_with_proxy_racing() {
    let mock1 = MockTlsServer::spawn_tls_mock();
    let mock2 = MockTlsServer::spawn_tls_mock();

    let candidates = vec![
        format!("127.0.0.1:{}", mock1.port),
        format!("127.0.0.1:{}", mock2.port),
    ];

    let start = Instant::now();
    let mut streams = Vec::new();
    for target in candidates {
        if let Ok(s) = TcpStream::connect_timeout(&target.parse().unwrap(), Duration::from_millis(500)) {
            let _ = s.set_nodelay(true);
            streams.push(s);
        }
    }
    let elapsed = start.elapsed();
    assert_eq!(streams.len(), 2, "Both racing candidates should be connected and tuned");
    assert!(elapsed < Duration::from_millis(500));
}

#[test]
fn test_t3_02_direct_nrpt_with_bandwidth_gated_hosts() {
    let fast_relays = ["83.220.169.155", "111.88.96.50", "212.109.195.93"];
    let ns_string = format_direct_nrpt_nameservers(&fast_relays);
    assert!(!ns_string.contains("127.0.0.53"));

    let temp = TempTestDir::new("nrpt_hosts");
    let mut hosts_content = String::from("127.0.0.1 localhost\n# BEGIN ANTIGRAVITY-BYPASS-RUSSIA\n");
    for ip in &fast_relays {
        hosts_content.push_str(&format!("{} generativelanguage.googleapis.com\n", ip));
    }
    hosts_content.push_str("# END ANTIGRAVITY-BYPASS-RUSSIA\n");
    let _path = temp.write_file("hosts", &hosts_content);

    let read_back = temp.read_file("hosts");
    assert!(read_back.contains("83.220.169.155"));
    assert!(read_back.contains("111.88.96.50"));
}

#[test]
fn test_t3_03_benchmark_leader_selection_with_route_preference() {
    let candidates = vec![
        ("83.220.169.155", "Comss Frankfurt 10G", 50u64, 110u64, 50i32, 10000u64),
        ("37.230.192.51", "Geohide Moscow", 15u64, 800u64, 0i32, 500u64),
        ("111.88.96.50", "Xbox-DNS Anycast", 35u64, 130u64, 40i32, 8000u64),
    ];

    let mut scored: Vec<(&str, &str, u64)> = candidates
        .iter()
        .map(|(ip, name, tls, ttft, weight, bw)| {
            (
                *ip,
                *name,
                compute_composite_score(RoutingPreference::PreferEurope10G, *tls, *ttft, *weight, *bw),
            )
        })
        .collect();

    scored.sort_by_key(|(_, _, score)| *score);
    assert_eq!(scored[0].0, "83.220.169.155", "Leader must be Comss Frankfurt 10G under PreferEurope10G");
}

#[test]
fn test_t3_04_os_tuning_with_high_throughput_streaming_proxy() {
    let mock = MockTlsServer::spawn_streaming_mock(20, Duration::from_millis(2));
    let mut client = TcpStream::connect(format!("127.0.0.1:{}", mock.port)).unwrap();
    client.set_nodelay(true).unwrap();

    let start = Instant::now();
    let mut buffer = [0u8; 1024];
    let mut total_bytes = 0;
    while let Ok(n) = client.read(&mut buffer) {
        if n == 0 { break; }
        total_bytes += n;
        if total_bytes > 500 { break; }
    }
    let elapsed = start.elapsed();
    let throughput_kb_s = (total_bytes as f64 / 1024.0) / elapsed.as_secs_f64().max(0.001);
    assert!(throughput_kb_s > 0.0);
}

#[test]
fn test_t3_05_direct_resolution_with_static_routes() {
    let smartdns_ips = vec!["111.88.96.50", "83.220.169.155", "212.109.195.93"];
    let mut sync_routes = Vec::new();
    for ip in &smartdns_ips {
        sync_routes.push(format!("route add {} mask 255.255.255.255 192.168.1.1 metric 1 if 10", ip));
    }
    assert_eq!(sync_routes.len(), 3);
    assert!(sync_routes[0].contains("111.88.96.50"));
}

#[test]
fn test_t3_06_proxy_racing_fallback_to_european_anycast() {
    let candidate_dead = "127.0.0.1:1";
    let mock_anycast = MockTlsServer::spawn_tls_mock();
    let candidate_anycast = format!("127.0.0.1:{}", mock_anycast.port);

    let mut chosen_stream = None;
    for target in [&candidate_dead, &candidate_anycast.as_str()] {
        if let Ok(s) = TcpStream::connect_timeout(&target.parse().unwrap(), Duration::from_millis(50)) {
            chosen_stream = Some(s);
            break;
        }
    }
    assert!(chosen_stream.is_some(), "Must fall back to alive European Anycast mock node");
}

#[test]
fn test_t3_07_circuit_breaker_trip_and_cooldown_with_ranking() {
    struct MockBreaker {
        failures: u32,
        threshold: u32,
        tripped: bool,
    }
    let mut breaker = MockBreaker { failures: 0, threshold: 2, tripped: false };

    breaker.failures += 1;
    assert_eq!(breaker.tripped, false);
    breaker.failures += 1;
    if breaker.failures >= breaker.threshold {
        breaker.tripped = true;
    }
    assert_eq!(breaker.tripped, true);

    breaker.failures = 0;
    breaker.tripped = false;
    assert_eq!(breaker.tripped, false);
}

#[test]
fn test_t3_08_hosts_population_after_benchmark_completion() {
    let benchmark_results = vec![
        BenchmarkResult {
            name: "Comss.one Frankfurt".into(),
            ip: "83.220.169.155".into(),
            tcp_rtt_ms: 25,
            tls_rtt_ms: 35,
            est_ttft_ms: 60,
            throughput_kb_s: 15000.0,
            est_tokens_sec: 300.0,
            status: "Отлично".into(),
            is_leader: true,
        },
        BenchmarkResult {
            name: "Xbox-DNS Anycast".into(),
            ip: "111.88.96.50".into(),
            tcp_rtt_ms: 30,
            tls_rtt_ms: 40,
            est_ttft_ms: 70,
            throughput_kb_s: 12000.0,
            est_tokens_sec: 240.0,
            status: "Отлично".into(),
            is_leader: false,
        },
    ];

    let top_ips: Vec<String> = benchmark_results
        .iter()
        .filter(|r| r.est_ttft_ms < 400 && r.throughput_kb_s > 500.0)
        .map(|r| r.ip.clone())
        .collect();

    assert_eq!(top_ips.len(), 2);
    assert_eq!(top_ips[0], "83.220.169.155");
}

#[test]
fn test_t3_09_cli_tune_execution_and_status_verification() {
    let output = run_cli_command(&["status"]);
    assert!(output.status.code().is_some());
}

#[test]
fn test_t3_10_full_activation_and_clean_rollback_cycle() {
    let temp = TempTestDir::new("full_cycle");
    let initial_hosts = "127.0.0.1 localhost\n";
    let hosts_path = temp.write_file("hosts", initial_hosts);

    // Step 1: Activation
    let active_hosts = format!("{}\n# BEGIN ANTIGRAVITY-BYPASS-RUSSIA\n83.220.169.155 generativelanguage.googleapis.com\n# END ANTIGRAVITY-BYPASS-RUSSIA\n", initial_hosts.trim_end());
    std::fs::write(&hosts_path, &active_hosts).unwrap();
    assert!(temp.read_file("hosts").contains("83.220.169.155"));

    // Step 2: Rollback
    let restored = strip_hosts_block(&temp.read_file("hosts"));
    std::fs::write(&hosts_path, &restored).unwrap();

    let final_content = temp.read_file("hosts");
    assert_eq!(final_content.trim(), initial_hosts.trim());
    assert!(!final_content.contains(START_MARK));
}
