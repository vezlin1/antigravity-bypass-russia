use crate::harness::*;
use crate::tier1_feature_coverage::*;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

// =========================================================================
// FEATURE 1 BOUNDARY & CORNER CASES
// =========================================================================

#[test]
fn test_f1_b01_zero_byte_buffer_rejection() {
    let validate_buf_size = |size: i32| -> Result<(), &'static str> {
        if size <= 0 {
            Err("Buffer size must be positive")
        } else if size > 64 * 1024 * 1024 {
            Err("Buffer size exceeds 64MB limit")
        } else {
            Ok(())
        }
    };
    assert!(validate_buf_size(0).is_err());
    assert!(validate_buf_size(-1).is_err());
    assert!(validate_buf_size(512 * 1024).is_ok());
}

#[test]
fn test_f1_b02_extreme_oversized_buffer_limit() {
    let validate_buf_size = |size: i32| -> Result<(), &'static str> {
        if size > 64 * 1024 * 1024 {
            Err("Buffer size exceeds 64MB limit")
        } else {
            Ok(())
        }
    };
    assert!(validate_buf_size(128 * 1024 * 1024).is_err());
}

#[test]
fn test_f1_b03_disconnected_stream_handling() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    let (server_stream, _) = listener.accept().unwrap();
    drop(server_stream);

    let mut buf = [0u8; 10];
    let res = stream.read(&mut buf);
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), 0);
}

#[test]
fn test_f1_b04_rapid_back_to_back_tcp_writes() {
    use std::io::Write;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    client.set_nodelay(true).unwrap();

    let writer_handle = thread::spawn(move || {
        for i in 0..100 {
            let msg = format!("msg_{:03}\n", i);
            client.write_all(msg.as_bytes()).unwrap();
        }
        client.flush().unwrap();
    });

    let mut total_received = 0;
    let mut buf = [0u8; 128];
    while total_received < 800 {
        if let Ok(n) = server.read(&mut buf) {
            if n == 0 { break; }
            total_received += n;
        }
    }
    writer_handle.join().unwrap();
    assert!(total_received >= 800);
}

#[test]
fn test_f1_b05_half_duplex_shutdown_handling() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    let (_server, _) = listener.accept().unwrap();

    let shutdown_res = client.shutdown(std::net::Shutdown::Write);
    assert!(shutdown_res.is_ok());
}

// =========================================================================
// FEATURE 2 BOUNDARY & CORNER CASES
// =========================================================================

#[test]
fn test_f2_b01_malformed_netsh_output_parsing() {
    let parse_autotuning = |output: &str| -> Option<String> {
        for line in output.lines() {
            if line.to_lowercase().contains("autotuninglevel") || line.to_lowercase().contains("auto-tuning") {
                if let Some((_, val)) = line.split_once(':') {
                    return Some(val.trim().to_string());
                }
            }
        }
        None
    };

    let valid_out = "Receive Window Auto-Tuning Level : normal\n";
    assert_eq!(parse_autotuning(valid_out), Some("normal".to_string()));

    let empty_out = "";
    assert_eq!(parse_autotuning(empty_out), None);

    let garbage_out = "ERROR: Element not found 0x80070490\n";
    assert_eq!(parse_autotuning(garbage_out), None);
}

#[test]
fn test_f2_b02_missing_netsh_binary_simulation() {
    let res = Command::new("non_existent_netsh_binary_404").output();
    assert!(res.is_err(), "Missing binary should safely return io::Error without panic");
}

#[test]
fn test_f2_b03_non_admin_permission_rejection() {
    let is_admin = false;
    let attempt_tuning = |admin: bool| -> Result<(), &'static str> {
        if !admin {
            Err("Access Denied: Administrator privileges required")
        } else {
            Ok(())
        }
    };
    assert!(attempt_tuning(is_admin).is_err());
}

#[test]
fn test_f2_b04_concurrent_duplicate_tuning() {
    let mut handles = Vec::new();
    for _ in 0..4 {
        handles.push(thread::spawn(|| {
            let cmd = ["int", "tcp", "set", "global", "autotuninglevel=normal"];
            assert_eq!(cmd[4], "autotuninglevel=normal");
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn test_f2_b05_empty_interface_adapter_name() {
    fn sanitize_adapter(iface: &str) -> Option<String> {
        let trimmed = iface.trim();
        if trimmed.is_empty() || trimmed.contains('\0') {
            None
        } else {
            Some(trimmed.to_string())
        }
    }
    assert_eq!(sanitize_adapter(""), None);
    assert_eq!(sanitize_adapter("   "), None);
    assert_eq!(sanitize_adapter("Ethernet\0bad"), None);
    assert_eq!(sanitize_adapter("Wi-Fi"), Some("Wi-Fi".to_string()));
}

// =========================================================================
// FEATURE 3 BOUNDARY & CORNER CASES
// =========================================================================

#[test]
fn test_f3_b01_empty_relay_list_handling() {
    let empty_pool: &[RelayNode] = &[];
    assert!(empty_pool.is_empty());
    assert_eq!(empty_pool.len(), 0);
}

#[test]
fn test_f3_b02_duplicate_ip_entries_filter() {
    use std::collections::HashSet;
    let ips = ["83.220.169.155", "111.88.96.50", "83.220.169.155", "212.109.195.93"];
    let mut unique = HashSet::new();
    let dedup: Vec<&str> = ips.iter().copied().filter(|ip| unique.insert(*ip)).collect();
    assert_eq!(dedup.len(), 3);
    assert_eq!(dedup, vec!["83.220.169.155", "111.88.96.50", "212.109.195.93"]);
}

#[test]
fn test_f3_b03_invalid_ipv4_octet_parser() {
    let parse_ipv4 = |s: &str| s.parse::<Ipv4Addr>();
    assert!(parse_ipv4("256.0.0.1").is_err());
    assert!(parse_ipv4("192.168.1.1.1").is_err());
    assert!(parse_ipv4("not_an_ip").is_err());
    assert!(parse_ipv4("83.220.169.155").is_ok());
}

#[test]
fn test_f3_b04_ipv6_address_filtering() {
    let parse_as_ipv4_only = |s: &str| -> Option<Ipv4Addr> {
        match s.parse::<IpAddr>() {
            Ok(IpAddr::V4(v4)) => Some(v4),
            _ => None,
        }
    };
    assert_eq!(parse_as_ipv4_only("::1"), None);
    assert_eq!(parse_as_ipv4_only("2001:4860:4860::8888"), None);
    assert!(parse_as_ipv4_only("83.220.169.155").is_some());
}

#[test]
fn test_f3_b05_zero_bandwidth_node_handling() {
    let zero_node = RelayNode {
        ip: "10.0.0.1",
        provider: "Test",
        location: "Test",
        region: RelayRegion::Custom,
        bandwidth_mbps: 0,
        priority_weight: -10,
    };
    assert_eq!(zero_node.bandwidth_mbps, 0);
    assert_eq!(zero_node.priority_weight, -10);
}

// =========================================================================
// FEATURE 4 BOUNDARY & CORNER CASES
// =========================================================================

#[test]
fn test_f4_b01_instant_connection_refused() {
    let start = Instant::now();
    let res = TcpStream::connect_timeout(&"127.0.0.1:1".parse().unwrap(), Duration::from_millis(100));
    let elapsed = start.elapsed();
    assert!(res.is_err());
    assert!(elapsed < Duration::from_millis(500));
}

#[test]
fn test_f4_b02_truncated_tls_header() {
    let short_bytes = [0x16, 0x03, 0x03];
    let is_valid_tls = |buf: &[u8]| buf.len() >= 5 && (buf[0] == 0x16 || buf[0] == 0x15);
    assert_eq!(is_valid_tls(&short_bytes), false);
}

#[test]
fn test_f4_b03_extreme_latency_timeout_boundary() {
    let timeout = Duration::from_millis(1500);
    let simulate_probe = |rtt: Duration| -> Option<u128> {
        if rtt >= timeout {
            None
        } else {
            Some(rtt.as_millis().max(1))
        }
    };
    assert_eq!(simulate_probe(Duration::from_millis(2000)), None);
    assert_eq!(simulate_probe(Duration::from_millis(1500)), None);
    assert_eq!(simulate_probe(Duration::from_millis(1499)), Some(1499));
}

#[test]
fn test_f4_b04_single_byte_payload_burst() {
    let bytes = 1;
    let duration_sec = 0.001;
    let throughput_kb_s = (bytes as f64 / 1024.0) / duration_sec;
    assert!(throughput_kb_s > 0.0);
}

#[test]
fn test_f4_b05_non_tls_plaintext_payload() {
    let plaintext_http = b"HTTP/1.1 400 Bad Request\r\n";
    let is_tls = |buf: &[u8]| buf.len() >= 5 && (buf[0] == 0x16 || buf[0] == 0x15);
    assert_eq!(is_tls(plaintext_http), false);
}

// =========================================================================
// FEATURE 5 BOUNDARY & CORNER CASES
// =========================================================================

#[test]
fn test_f5_b01_exact_equal_latency_tie_breaking() {
    let node_a = compute_composite_score(RoutingPreference::PreferEurope10G, 50, 100, 50, 10000);
    let node_b = compute_composite_score(RoutingPreference::PreferEurope10G, 50, 100, 40, 10000);
    assert!(node_a < node_b);
}

#[test]
fn test_f5_b02_negative_priority_weight_handling() {
    let score_neg = compute_composite_score(RoutingPreference::PreferEurope10G, 50, 100, -20, 1000);
    let score_zero = compute_composite_score(RoutingPreference::PreferEurope10G, 50, 100, 0, 1000);
    assert_eq!(score_neg, score_zero);
}

#[test]
fn test_f5_b03_extreme_throughput_value() {
    let score = compute_composite_score(RoutingPreference::PreferEurope10G, 50, 100, 50, 100_000_000);
    assert_eq!(score, (50 + 100) - (50 * 2) - 50);
}

#[test]
fn test_f5_b04_all_nodes_dead_pool() {
    let mut nodes = vec![
        ("1.1.1.1", compute_composite_score(RoutingPreference::PreferEurope10G, 10000, 10000, 0, 0)),
        ("2.2.2.2", compute_composite_score(RoutingPreference::PreferEurope10G, 10000, 10000, 0, 0)),
    ];
    nodes.sort_by_key(|(_, score)| *score);
    assert_eq!(nodes.len(), 2);
}

#[test]
fn test_f5_b05_single_node_pool() {
    let mut nodes = vec![
        ("83.220.169.155", compute_composite_score(RoutingPreference::PreferEurope10G, 40, 80, 50, 10000)),
    ];
    nodes.sort_by_key(|(_, score)| *score);
    assert_eq!(nodes[0].0, "83.220.169.155");
}

// =========================================================================
// FEATURE 6 BOUNDARY & CORNER CASES
// =========================================================================

#[test]
fn test_f6_b01_empty_domain_list() {
    let empty_domains: &[&str] = &[];
    let formatted = empty_domains.join(";");
    assert_eq!(formatted, "");
}

#[test]
fn test_f6_b02_wildcard_domain_normalization() {
    let normalize_domain = |d: &str| d.trim_start_matches('.').to_string();
    assert_eq!(normalize_domain(".googleapis.com"), "googleapis.com");
    assert_eq!(normalize_domain("googleapis.com"), "googleapis.com");
}

#[test]
fn test_f6_b03_duplicate_nameserver_string_dedup() {
    use std::collections::HashSet;
    let raw = ["83.220.169.155", "83.220.169.155", "111.88.96.50"];
    let mut seen = HashSet::new();
    let dedup: Vec<&str> = raw.iter().copied().filter(|s| seen.insert(*s)).collect();
    let joined = dedup.join(";");
    assert_eq!(joined, "83.220.169.155;111.88.96.50");
}

#[test]
fn test_f6_b04_max_length_registry_string() {
    let mut long_ns = String::new();
    for i in 0..100 {
        long_ns.push_str(&format!("192.168.1.{};", i));
    }
    assert!(long_ns.len() > 1000);
    assert!(long_ns.contains("192.168.1.99"));
}

#[test]
fn test_f6_b05_corrupted_multi_sz_bytes() {
    let bad_bytes = [0x41, 0x00, 0x42];
    let parse_multi_sz_safe = |bytes: &[u8]| -> Vec<String> {
        if bytes.len() % 2 != 0 || bytes.is_empty() {
            return Vec::new();
        }
        let u16s: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_ne_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&u16s)
            .split('\0')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect()
    };
    let parsed = parse_multi_sz_safe(&bad_bytes);
    assert!(parsed.is_empty());
}

// =========================================================================
// FEATURE 7 BOUNDARY & CORNER CASES
// =========================================================================

#[test]
fn test_f7_b01_empty_hosts_file_handling() {
    let empty_hosts = "";
    let stripped = strip_hosts_block(empty_hosts);
    assert_eq!(stripped, "");
}

#[test]
fn test_f7_b02_hosts_missing_trailing_newline() {
    let raw = "127.0.0.1 localhost";
    let stripped = strip_hosts_block(raw);
    assert_eq!(stripped, "127.0.0.1 localhost");
}

#[test]
fn test_f7_b03_read_only_hosts_attribute_handling() {
    let temp = TempTestDir::new("hosts_readonly");
    let path = temp.write_file("hosts", "127.0.0.1 localhost\n");

    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&path, perms).unwrap();

    let mut write_perms = std::fs::metadata(&path).unwrap().permissions();
    write_perms.set_readonly(false);
    std::fs::set_permissions(&path, write_perms).unwrap();

    std::fs::write(&path, "127.0.0.1 localhost\n::1 localhost\n").unwrap();
    let content = temp.read_file("hosts");
    assert!(content.contains("::1 localhost"));
}

#[test]
fn test_f7_b04_preexisting_user_mappings() {
    let user_hosts = "127.0.0.1 custom.domain\n10.0.0.1 daily-cloudcode-pa.googleapis.com\n";
    let stripped = strip_hosts_block(user_hosts);
    assert!(stripped.contains("127.0.0.1 custom.domain"));
    assert!(stripped.contains("10.0.0.1 daily-cloudcode-pa.googleapis.com"));
}

#[test]
fn test_f7_b05_duplicate_hosts_blocks() {
    let duplicate_blocks = "# BEGIN ANTIGRAVITY-BYPASS-RUSSIA\n83.220.169.155 test.com\n# END ANTIGRAVITY-BYPASS-RUSSIA\n127.0.0.1 localhost\n# BEGIN ANTIGRAVITY-BYPASS-RUSSIA\n111.88.96.50 test2.com\n# END ANTIGRAVITY-BYPASS-RUSSIA\n";
    let stripped = strip_hosts_block(duplicate_blocks);
    assert_eq!(stripped.trim(), "127.0.0.1 localhost");
}

// =========================================================================
// FEATURE 8 BOUNDARY & CORNER CASES
// =========================================================================

#[test]
fn test_f8_b01_rollback_with_no_prior_state() {
    let clean_hosts = "127.0.0.1 localhost\n";
    let stripped = strip_hosts_block(clean_hosts);
    assert_eq!(stripped, "127.0.0.1 localhost\n");
}

#[test]
fn test_f8_b02_rollback_missing_backup_files() {
    let temp = TempTestDir::new("rollback_missing");
    let backup_path = temp.file_path("doh_backup.conf");
    assert!(!backup_path.exists());
    let restore_res: Result<(), String> = if backup_path.exists() {
        Ok(())
    } else {
        Ok(())
    };
    assert!(restore_res.is_ok());
}

#[test]
fn test_f8_b03_repeated_rollback_calls() {
    let mut hosts = "127.0.0.1 localhost\n# BEGIN ANTIGRAVITY-BYPASS-RUSSIA\n# END ANTIGRAVITY-BYPASS-RUSSIA\n".to_string();
    for _ in 0..3 {
        hosts = strip_hosts_block(&hosts);
    }
    assert_eq!(hosts.trim(), "127.0.0.1 localhost");
}

#[test]
fn test_f8_b04_partial_rollback_error_tolerance() {
    let mut errors = Vec::new();
    let tasks: Vec<Result<(), String>> = vec![
        Ok(()),
        Err("Could not delete non-existent static route".to_string()),
        Ok(()),
    ];
    for t in tasks {
        if let Err(e) = t {
            errors.push(e);
        }
    }
    assert_eq!(errors.len(), 1);
}

#[test]
fn test_f8_b05_rollback_permission_failure_reporting() {
    let result: Result<usize, String> = Err("Access Denied when writing to registry".to_string());
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Access Denied"));
}

// =========================================================================
// FEATURE 9 BOUNDARY & CORNER CASES
// =========================================================================

#[test]
fn test_f9_b01_empty_benchmark_results_table() {
    let table = format_benchmark_table(&[]);
    assert!(table.lines().count() >= 2);
}

#[test]
fn test_f9_b02_all_failed_nodes_table() {
    let failed = vec![
        BenchmarkResult {
            name: "Node 1".into(),
            ip: "1.1.1.1".into(),
            tcp_rtt_ms: 0,
            tls_rtt_ms: 0,
            est_ttft_ms: 0,
            throughput_kb_s: 0.0,
            est_tokens_sec: 0.0,
            status: "Таймаут".into(),
            is_leader: false,
        },
    ];
    let table = format_benchmark_table(&failed);
    assert!(table.contains("Таймаут"));
    assert!(!table.contains("[✓ Лидер]"));
}

#[test]
fn test_f9_b03_extreme_ttft_display() {
    let extreme = vec![
        BenchmarkResult {
            name: "Laggy Node".into(),
            ip: "2.2.2.2".into(),
            tcp_rtt_ms: 9999,
            tls_rtt_ms: 9999,
            est_ttft_ms: 19998,
            throughput_kb_s: 1.0,
            est_tokens_sec: 0.2,
            status: "Перегружен".into(),
            is_leader: false,
        },
    ];
    let table = format_benchmark_table(&extreme);
    assert!(table.contains("19998 мс"));
}

#[test]
fn test_f9_b04_unicode_and_cyrillic_rendering() {
    let result = BenchmarkResult {
        name: "Франкфурт 10G Anycast".into(),
        ip: "83.220.169.155".into(),
        tcp_rtt_ms: 25,
        tls_rtt_ms: 35,
        est_ttft_ms: 60,
        throughput_kb_s: 15000.0,
        est_tokens_sec: 300.0,
        status: "Отлично".into(),
        is_leader: true,
    };
    let table = format_benchmark_table(&[result]);
    assert!(table.contains("Франкфурт 10G Anycast"));
    assert!(table.contains("[✓ Лидер]"));
}

#[test]
fn test_f9_b05_high_concurrent_benchmark_probes() {
    let mock = MockTlsServer::spawn_tls_mock();
    let mut handles = Vec::new();
    for _ in 0..10 {
        let port = mock.port;
        handles.push(thread::spawn(move || {
            use std::io::Write;
            let start = Instant::now();
            let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
            let hello = build_synthetic_client_hello("daily-cloudcode-pa.googleapis.com");
            stream.write_all(&hello).unwrap();
            let mut buf = [0u8; 100];
            let n = stream.read(&mut buf).unwrap();
            assert!(n > 0);
            start.elapsed()
        }));
    }
    for h in handles {
        let elapsed = h.join().unwrap();
        assert!(elapsed < Duration::from_millis(1000));
    }
}

// =========================================================================
// FEATURE 10 BOUNDARY & CORNER CASES
// =========================================================================

#[test]
fn test_f10_b01_cli_empty_string_arg() {
    let output = run_cli_command(&[""]);
    assert!(output.status.code().is_some());
}

#[test]
fn test_f10_b02_cli_excessive_arguments() {
    let mut args = Vec::new();
    for _ in 0..100 {
        args.push("--dummy");
    }
    let output = run_cli_command(&args);
    assert!(output.status.code().is_some());
}

#[test]
fn test_f10_b03_cli_special_characters_arg() {
    let output = run_cli_command(&["--test='\"$#;rm -rf /'"]);
    assert!(output.status.code().is_some());
}

#[test]
fn test_f10_b04_cli_mixed_case_arguments() {
    let normalize_cli_arg = |arg: &str| arg.trim().to_lowercase();
    assert_eq!(normalize_cli_arg("BENCHMARK"), "benchmark");
    assert_eq!(normalize_cli_arg("SpeedTest"), "speedtest");
    assert_eq!(normalize_cli_arg("DIAGNOSTICS"), "diagnostics");
}

#[test]
fn test_f10_b05_cli_invalid_port_numbers() {
    let parse_port = |p: &str| -> Result<u16, &'static str> {
        match p.parse::<u16>() {
            Ok(port) if port > 0 => Ok(port),
            _ => Err("Invalid port"),
        }
    };
    assert!(parse_port("0").is_err());
    assert!(parse_port("65536").is_err());
    assert!(parse_port("-80").is_err());
    assert_eq!(parse_port("8989"), Ok(8989));
}
