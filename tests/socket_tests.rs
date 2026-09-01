//! Integration tests for TCP Socket tuning and high-throughput streaming.

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

#[test]
fn test_rapid_connect_disconnect_stream_lifecycle() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Bind failed");
    let addr = listener.local_addr().expect("Addr failed");

    let server_handle = thread::spawn(move || {
        for _ in 0..20 {
            if let Ok((stream, _)) = listener.accept() {
                let _ = stream.set_nodelay(true);
            }
        }
    });

    for _ in 0..20 {
        let stream = TcpStream::connect(addr).expect("Connect failed");
        let _ = stream.set_nodelay(true);
        assert!(stream.nodelay().unwrap_or(false));
    }

    server_handle.join().expect("Server join failed");
}

#[test]
fn test_half_duplex_shutdown_and_flush() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Bind failed");
    let addr = listener.local_addr().expect("Addr failed");

    let server_handle = thread::spawn(move || {
        let (mut s, _) = listener.accept().expect("Accept failed");
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).expect("Read to end failed");
        assert_eq!(&buf, b"FINAL DATA BEFORE SHUTDOWN");
    });

    let mut client = TcpStream::connect(addr).expect("Connect failed");
    let _ = client.set_nodelay(true);
    client.write_all(b"FINAL DATA BEFORE SHUTDOWN").expect("Write failed");
    client.flush().expect("Flush failed");
    client.shutdown(std::net::Shutdown::Write).expect("Shutdown failed");

    server_handle.join().expect("Server join failed");
}

#[test]
fn test_large_burst_transfer_with_nodelay() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Bind failed");
    let addr = listener.local_addr().expect("Addr failed");

    let server = thread::spawn(move || {
        let (mut s, _) = listener.accept().expect("Accept failed");
        let mut total = 0;
        let mut buf = [0u8; 1024];
        while total < 50 * 1024 {
            let n = s.read(&mut buf).expect("Read failed");
            if n == 0 { break; }
            total += n;
        }
        assert_eq!(total, 50 * 1024);
    });

    let mut client = TcpStream::connect(addr).expect("Connect failed");
    let _ = client.set_nodelay(true);
    let chunk = vec![0xABu8; 1024];
    for _ in 0..50 {
        client.write_all(&chunk).expect("Write chunk failed");
    }
    client.flush().expect("Flush failed");

    server.join().expect("Server join failed");
}
