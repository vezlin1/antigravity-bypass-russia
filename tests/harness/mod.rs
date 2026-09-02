use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Helper to get the compiled binary path for CLI execution tests.
pub fn binary_path() -> &'static str {
    env!("CARGO_BIN_EXE_antigravity-bypass-russia")
}

/// Run the compiled binary with given arguments and optional timeout.
pub fn run_cli_command(args: &[&str]) -> Output {
    Command::new(binary_path())
        .args(args)
        .output()
        .expect("Failed to execute binary")
}

/// Temporary isolated directory helper for file-based tests (e.g. hosts file testing).
pub struct TempTestDir {
    pub path: PathBuf,
}

impl TempTestDir {
    pub fn new(prefix: &str) -> Self {
        let unique = format!("{}_{}_{}", prefix, std::process::id(), Instant::now().elapsed().as_nanos());
        let path = std::env::temp_dir().join("antigravity_test").join(unique);
        std::fs::create_dir_all(&path).expect("Failed to create temp test directory");
        Self { path }
    }

    pub fn file_path(&self, filename: &str) -> PathBuf {
        self.path.join(filename)
    }

    pub fn write_file(&self, filename: &str, content: &str) -> PathBuf {
        let p = self.file_path(filename);
        std::fs::write(&p, content).expect("Failed to write temp file");
        p
    }

    pub fn read_file(&self, filename: &str) -> String {
        let p = self.file_path(filename);
        std::fs::read_to_string(&p).unwrap_or_default()
    }
}

impl Drop for TempTestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A Mock TCP Server that simulates TLS ServerHello and streaming SSE responses.
pub struct MockTlsServer {
    pub port: u16,
    running: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockTlsServer {
    /// Spawns a mock server that replies to TLS ClientHello with a mock ServerHello + Certificate burst.
    pub fn spawn_tls_mock() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind mock TLS listener");
        let port = listener.local_addr().unwrap().port();
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();

        let handle = thread::spawn(move || {
            let _ = listener.set_nonblocking(true);
            while running_clone.load(Ordering::Relaxed) {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 1024];
                    if let Ok(n) = stream.read(&mut buf) {
                        if n >= 5 && buf[0] == 0x16 {
                            // Synthesize a valid TLS 1.2 / 1.3 ServerHello header (0x16 0x03 0x03)
                            // and Certificate burst of ~4096 bytes
                            let mut resp = vec![0x16, 0x03, 0x03, 0x0f, 0xff];
                            resp.resize(4096, 0xaa);
                            let _ = stream.write_all(&resp);
                            let _ = stream.flush();
                            let _ = stream.shutdown(std::net::Shutdown::Write);
                            let mut drain = [0u8; 256];
                            let _ = stream.read(&mut drain);
                        }
                    }
                }
                thread::sleep(Duration::from_millis(5));
            }
        });

        Self {
            port,
            running,
            handle: Some(handle),
        }
    }

    /// Spawns a mock streaming server that emits Gemini SSE token chunks.
    pub fn spawn_streaming_mock(chunk_count: usize, delay_per_chunk: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind mock streaming listener");
        let port = listener.local_addr().unwrap().port();
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();

        let handle = thread::spawn(move || {
            let _ = listener.set_nonblocking(true);
            while running_clone.load(Ordering::Relaxed) {
                if let Ok((mut stream, _)) = listener.accept() {
                    // Send HTTP 200 OK header
                    let header = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
                    let _ = stream.write_all(header);
                    let _ = stream.flush();

                    for i in 0..chunk_count {
                        if !running_clone.load(Ordering::Relaxed) {
                            break;
                        }
                        let chunk_data = format!("data: {{\"token_id\": {}, \"text\": \"chunk_{}\"}}\n\n", i, i);
                        let chunk = format!("{:X}\r\n{}\r\n", chunk_data.len(), chunk_data);
                        let _ = stream.write_all(chunk.as_bytes());
                        let _ = stream.flush();
                        if !delay_per_chunk.is_zero() {
                            thread::sleep(delay_per_chunk);
                        }
                    }
                    let _ = stream.write_all(b"0\r\n\r\n");
                    let _ = stream.flush();
                    let _ = stream.shutdown(std::net::Shutdown::Write);
                    let mut drain = [0u8; 256];
                    let _ = stream.read(&mut drain);
                }
                thread::sleep(Duration::from_millis(5));
            }
        });

        Self {
            port,
            running,
            handle: Some(handle),
        }
    }
}

impl Drop for MockTlsServer {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Synthesize a realistic TLS ClientHello with Server Name Indication (SNI).
pub fn build_synthetic_client_hello(sni: &str) -> Vec<u8> {
    let mut ext_sni = Vec::new();
    let sni_bytes = sni.as_bytes();
    let sni_len = sni_bytes.len() as u16;

    ext_sni.extend_from_slice(&(sni_len + 3).to_be_bytes()); // ServerNameList length
    ext_sni.push(0x00); // NameType: host_name
    ext_sni.extend_from_slice(&sni_len.to_be_bytes());
    ext_sni.extend_from_slice(sni_bytes);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&0x0000u16.to_be_bytes()); // Extension: server_name (0)
    extensions.extend_from_slice(&(ext_sni.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&ext_sni);

    // Extension: supported_versions (TLS 1.3, TLS 1.2)
    extensions.extend_from_slice(&0x002bu16.to_be_bytes());
    extensions.extend_from_slice(&0x0003u16.to_be_bytes());
    extensions.push(0x02); // Length
    extensions.extend_from_slice(&0x0304u16.to_be_bytes()); // TLS 1.3

    let mut client_hello = Vec::new();
    client_hello.extend_from_slice(&0x0303u16.to_be_bytes()); // Legacy version: TLS 1.2
    client_hello.extend_from_slice(&[0x42; 32]); // Random 32 bytes
    client_hello.push(0x00); // Session ID length: 0

    // Cipher suites (TLS_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
    let ciphers = [0x13, 0x01, 0xc0, 0x2f];
    client_hello.extend_from_slice(&(ciphers.len() as u16).to_be_bytes());
    client_hello.extend_from_slice(&ciphers);

    // Compression methods (0 = null)
    client_hello.push(0x01);
    client_hello.push(0x00);

    // Extensions length + extensions
    client_hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    client_hello.extend_from_slice(&extensions);

    // Handshake record (0x01 = ClientHello)
    let mut handshake = Vec::new();
    handshake.push(0x01); // HandshakeType: ClientHello
    let ch_len = client_hello.len() as u32;
    handshake.push(((ch_len >> 16) & 0xff) as u8);
    handshake.push(((ch_len >> 8) & 0xff) as u8);
    handshake.push((ch_len & 0xff) as u8);
    handshake.extend_from_slice(&client_hello);

    // TLS Record Header: ContentType=Handshake(0x16), Version=TLS 1.0(0x0301)
    let mut record = Vec::new();
    record.push(0x16);
    record.push(0x03);
    record.push(0x01);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}
