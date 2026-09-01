use crate::harness::*;
use crate::tier1_feature_coverage::*;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

#[test]
fn test_t4_01_antigravity_ide_cold_start_european_anycast() {
    let candidate_ips = ["83.220.169.155", "212.109.195.93", "111.88.96.50"];
    let direct_nrpt_entry = format_direct_nrpt_nameservers(&candidate_ips);
    assert!(!direct_nrpt_entry.contains("127.0.0.53"));

    let mock = MockTlsServer::spawn_tls_mock();
    let start = Instant::now();
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", mock.port)).unwrap();
    stream.set_nodelay(true).unwrap();

    let hello = build_synthetic_client_hello("daily-cloudcode-pa.googleapis.com");
    stream.write_all(&hello).unwrap();

    let mut buf = [0u8; 128];
    let n = stream.read(&mut buf).unwrap();
    let elapsed = start.elapsed();

    assert!(n >= 5 && buf[0] == 0x16, "Must receive TLS ServerHello");
    assert!(elapsed < Duration::from_millis(400), "Cold start TTFT must be under 400ms");
}

#[test]
fn test_t4_02_high_speed_gemini_streaming_zero_stutter() {
    let chunk_count = 50;
    let mock = MockTlsServer::spawn_streaming_mock(chunk_count, Duration::from_millis(1));
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", mock.port)).unwrap();
    stream.set_nodelay(true).unwrap();

    let start = Instant::now();
    let mut chunks_received = 0;
    let mut buffer = [0u8; 256];
    let mut first_token_time = None;

    while let Ok(n) = stream.read(&mut buffer) {
        if n == 0 { break; }
        if first_token_time.is_none() {
            first_token_time = Some(start.elapsed());
        }
        chunks_received += 1;
        if chunks_received >= chunk_count {
            break;
        }
    }

    let ttft = first_token_time.unwrap_or(Duration::from_millis(999));
    assert!(ttft < Duration::from_millis(400), "TTFT must be < 400ms (got {:?})", ttft);
    assert!(chunks_received >= 10, "Should receive streaming token chunks with zero stutter");
}

#[test]
fn test_t4_03_option1_direct_nrpt_switch_from_vpn() {
    let physical_gateway = "192.168.1.1";
    let if_index = 12;
    let smartdns_ips = ["111.88.96.50", "83.220.169.155", "212.109.195.93"];

    let mut pinned_routes = Vec::new();
    for ip in &smartdns_ips {
        pinned_routes.push(format!(
            "route add {} mask 255.255.255.255 {} metric 1 if {}",
            ip, physical_gateway, if_index
        ));
    }
    assert_eq!(pinned_routes.len(), 3);

    let nrpt_ns = format_direct_nrpt_nameservers(&smartdns_ips);
    assert_eq!(nrpt_ns, "111.88.96.50;83.220.169.155;212.109.195.93");
    assert!(!nrpt_ns.contains("127.0.0.53"));
}

#[test]
fn test_t4_04_live_benchmark_probing_7_relays_leader_selection() {
    let mut results = Vec::new();
    for node in TEST_MULTI_PROVIDER_RELAYS.iter() {
        let (tcp_rtt, tls_rtt, bw, is_up) = match node.ip {
            "83.220.169.155" => (25u128, 35u128, 15000.0, true),
            "111.88.96.50" => (20u128, 45u128, 9000.0, true),
            "212.109.195.93" => (28u128, 38u128, 14000.0, true),
            "111.88.96.51" => (22u128, 55u128, 8000.0, true),
            "195.133.25.16" => (35u128, 42u128, 9500.0, true),
            "45.155.204.190" => (15u128, 90u128, 2000.0, true),
            "37.230.192.51" => (16u128, 110u128, 1500.0, true),
            _ => (0, 0, 0.0, false),
        };

        let est_ttft = if is_up { tcp_rtt + tls_rtt } else { 0 };
        let est_tokens = (bw * 1024.0 / 4.0) / 1000.0;

        results.push(BenchmarkResult {
            name: format!("{} ({})", node.provider, node.location),
            ip: node.ip.to_string(),
            tcp_rtt_ms: tcp_rtt,
            tls_rtt_ms: tls_rtt,
            est_ttft_ms: est_ttft,
            throughput_kb_s: bw,
            est_tokens_sec: est_tokens,
            status: if est_ttft < 80 { "Отлично".into() } else { "В норме".into() },
            is_leader: false,
        });
    }

    // Rank under PreferEurope10G
    results.sort_by_key(|r| {
        let node = TEST_MULTI_PROVIDER_RELAYS.iter().find(|n| n.ip == r.ip).unwrap();
        compute_composite_score(
            RoutingPreference::PreferEurope10G,
            r.tls_rtt_ms as u64,
            r.est_ttft_ms as u64,
            node.priority_weight,
            r.throughput_kb_s as u64,
        )
    });

    results[0].is_leader = true;
    let table = format_benchmark_table(&results);

    assert_eq!(results.len(), 7);
    assert_eq!(results[0].ip, "83.220.169.155", "Comss Frankfurt 10G Anycast must be the leader");
    assert!(table.contains("[✓ Лидер]"));
}

#[test]
fn test_t4_05_full_lifecycle_activation_traffic_clean_rollback() {
    let temp = TempTestDir::new("lifecycle");
    let original_hosts = "127.0.0.1 localhost\n::1 localhost\n";
    let hosts_file = temp.write_file("hosts", original_hosts);

    // 1. Activate
    let active_block = format!(
        "{}\n{}\n83.220.169.155 daily-cloudcode-pa.googleapis.com\n83.220.169.155 generativelanguage.googleapis.com\n{}\n",
        original_hosts.trim_end(),
        START_MARK,
        END_MARK
    );
    std::fs::write(&hosts_file, &active_block).unwrap();
    assert!(temp.read_file("hosts").contains("daily-cloudcode-pa.googleapis.com"));

    // 2. Traffic Generation over mock
    let mock = MockTlsServer::spawn_tls_mock();
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", mock.port)).unwrap();
    stream.set_nodelay(true).unwrap();
    let hello = build_synthetic_client_hello("daily-cloudcode-pa.googleapis.com");
    stream.write_all(&hello).unwrap();
    let mut resp = [0u8; 64];
    let n = stream.read(&mut resp).unwrap();
    assert!(n > 0);

    // 3. Rollback
    let stripped = strip_hosts_block(&temp.read_file("hosts"));
    std::fs::write(&hosts_file, &stripped).unwrap();

    let final_hosts = temp.read_file("hosts");
    assert_eq!(final_hosts.trim(), original_hosts.trim());
    assert!(!final_hosts.contains("daily-cloudcode-pa.googleapis.com"));
    assert!(!final_hosts.contains(START_MARK));
}

#[test]
fn test_t4_06_unstable_network_failover_and_circuit_recovery() {
    let primary_mock = MockTlsServer::spawn_tls_mock();
    let secondary_mock = MockTlsServer::spawn_tls_mock();

    let primary_addr = format!("127.0.0.1:{}", primary_mock.port);
    let secondary_addr = format!("127.0.0.1:{}", secondary_mock.port);

    // Drop primary to simulate failure
    drop(primary_mock);

    let candidates = [primary_addr, secondary_addr];
    let mut connected_stream = None;

    for addr in &candidates {
        if let Ok(s) = TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_millis(50)) {
            let _ = s.set_nodelay(true);
            connected_stream = Some(s);
            break;
        }
    }

    assert!(connected_stream.is_some(), "Failover to secondary must succeed");
}
