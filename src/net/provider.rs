pub const NRPT_TAG: &str = "ANTIGRAVITY-BYPASS-RUSSIA";

/// Studio/Gemini canaries. Cloud Code is a separate family: xbox-dns and
/// comss currently pass it through to real Google, so their IPs must not
/// sit in that host's NRPT fallback list.
pub const SUBSTITUTION_CANARIES: &[&str] = &[
    "aistudio.google.com",
    "makersuite.google.com",
    "generativelanguage.googleapis.com",
    "gemini.google.com",
];

/// Browser AI surfaces (AI Studio, Gemini, NotebookLM, …).
/// These must NOT include Cloud Code, Unleash, OAuth, or www.googleapis.com:
/// those names either passthrough (extra DNS delay) or hang the IDE splash.
pub const NRPT_STUDIO: &[&str] = &[
    ".generativelanguage.googleapis.com",
    "generativelanguage.googleapis.com",
    ".gemini.google.com",
    "gemini.google.com",
    ".gemini.google",
    "gemini.google",
    ".gemini.gstatic.com",
    ".bard.google.com",
    ".generativeai.google",
    ".aistudio.google.com",
    "aistudio.google.com",
    ".ai.studio",
    "ai.studio",
    ".ai.google.dev",
    "ai.google.dev",
    ".makersuite.google.com",
    "makersuite.google.com",
    ".alkalicore-pa.clients6.google.com",
    ".alkalimakersuite-pa.clients6.google.com",
    ".webchannel-alkalimakersuite-pa.clients6.google.com",
    ".alkalimakersuite-pa.googleapis.com",
    ".alkalimakersuiteapplets.pa.googleapis.com",
    ".notebooklm-pa.googleapis.com",
    ".notebooklm.googleapis.com",
    ".notebooklm.google",
    ".notebooklm.google.com",
    ".jules.google",
    ".jules.google.com",
    ".aisandbox-pa.googleapis.com",
    ".deepmind.com",
    ".deepmind.google",
    "deepmind.google",
    ".aiplatform.googleapis.com",
    ".s-aiplatform.googleapis.com",
];

/// Agent Cloud Code & Gemini API hosts. Each gets its own NRPT nameserver list —
/// only providers that actually substitute *this* name, with fallback to ranked SNI proxies.
pub const NRPT_AGENT: &[&str] = &[
    "daily-cloudcode-pa.googleapis.com",
    "cloudcode-pa.googleapis.com",
    "generativelanguage.googleapis.com",
];

/// Geohide HTTP/SNI frontends. Used when VPN makes SmartDNS skip substitution:
/// we still TLS-probe these with Cloud Code SNI and pin whoever answers.
pub const GEOHIDE_PROXY_V4: &[&str] = &["37.230.192.51", "45.155.204.190"];

pub fn nrpt_domains() -> Vec<&'static str> {
    let mut out = Vec::with_capacity(NRPT_AGENT.len() + NRPT_STUDIO.len());
    out.extend_from_slice(NRPT_AGENT);
    out.extend_from_slice(NRPT_STUDIO);
    out
}

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Circuit Breaker protecting against broken or blackholed upstream relays.
pub struct RouteCircuitBreaker {
    fail_threshold: u32,
    cooldown_duration: Duration,
    consecutive_failures: AtomicU32,
    cooldown_until: Mutex<Option<Instant>>,
}

impl RouteCircuitBreaker {
    pub const fn new(fail_threshold: u32, cooldown_secs: u64) -> Self {
        Self {
            fail_threshold,
            cooldown_duration: Duration::from_secs(cooldown_secs),
            consecutive_failures: AtomicU32::new(0),
            cooldown_until: Mutex::new(None),
        }
    }

    pub fn is_available(&self) -> bool {
        if let Ok(guard) = self.cooldown_until.lock() {
            if let Some(until) = *guard {
                if Instant::now() < until {
                    return false;
                }
            }
        }
        true
    }

    pub fn report_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        if let Ok(mut guard) = self.cooldown_until.lock() {
            *guard = None;
        }
    }

    pub fn report_failure(&self) {
        let fails = self.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;
        if fails >= self.fail_threshold {
            if let Ok(mut guard) = self.cooldown_until.lock() {
                *guard = Some(Instant::now() + self.cooldown_duration);
            }
        }
    }
}

pub static GLOBAL_CIRCUIT_BREAKER: RouteCircuitBreaker = RouteCircuitBreaker::new(2, 300);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomUpstreamProxy {
    pub host: String,
    pub port: u16,
    pub auth_header: Option<String>,
}

fn get_upstream_config_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| "C:\\ProgramData".to_string());
        let dir = PathBuf::from(appdata).join("AntigravityBypass");
        let _ = fs::create_dir_all(&dir);
        dir.join("upstream.conf")
    }
    #[cfg(target_os = "macos")]
    {
        let home = crate::system::env::expand_env_vars("~");
        let dir = home.join("Library").join("Application Support").join("AntigravityBypass");
        let _ = fs::create_dir_all(&dir);
        dir.join("upstream.conf")
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let home = crate::system::env::expand_env_vars("~");
        let dir = home.join(".config").join("AntigravityBypass");
        let _ = fs::create_dir_all(&dir);
        dir.join("upstream.conf")
    }
}

pub fn load_custom_upstream() -> Option<CustomUpstreamProxy> {
    let p = get_upstream_config_path();
    let text = fs::read_to_string(p).ok()?;
    let line = text.lines().next()?.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    // Format: http://user:pass@host:port or host:port
    let raw = line.trim_start_matches("http://").trim_start_matches("https://");
    let (auth_part, host_port) = if let Some(idx) = raw.find('@') {
        let (user_pass, hp) = raw.split_at(idx);
        (Some(user_pass), &hp[1..])
    } else {
        (None, raw)
    };

    let mut parts = host_port.split(':');
    let host = parts.next()?.trim().to_string();
    let port = parts.next().and_then(|p| p.trim().parse::<u16>().ok()).unwrap_or(8080);

    let auth_header = auth_part.map(|ap| {
        // Base64 encode for Basic auth
        let mut b64 = String::new();
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let bytes = ap.as_bytes();
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0] as usize;
            let b1 = if chunk.len() > 1 { chunk[1] as usize } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] as usize } else { 0 };

            b64.push(CHARS[(b0 >> 2) & 0x3F] as char);
            b64.push(CHARS[((b0 << 4) | (b1 >> 4)) & 0x3F] as char);
            if chunk.len() > 1 {
                b64.push(CHARS[((b1 << 2) | (b2 >> 6)) & 0x3F] as char);
            } else {
                b64.push('=');
            }
            if chunk.len() > 2 {
                b64.push(CHARS[b2 & 0x3F] as char);
            } else {
                b64.push('=');
            }
        }
        format!("Basic {}", b64)
    });

    Some(CustomUpstreamProxy {
        host,
        port,
        auth_header,
    })
}

pub fn save_custom_upstream(upstream_url: Option<&str>) -> std::io::Result<()> {
    let p = get_upstream_config_path();
    match upstream_url {
        Some(url) if !url.trim().is_empty() => fs::write(p, url.trim()),
        _ => {
            if p.exists() {
                let _ = fs::remove_file(p);
            }
            Ok(())
        }
    }
}

