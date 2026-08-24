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

/// Agent Cloud Code hosts. Each gets its own NRPT nameserver list —
/// only providers that actually substitute *this* name. xbox-dns is
/// fine for Studio and poison for daily-cloudcode-pa.
pub const NRPT_AGENT: &[&str] = &[
    "daily-cloudcode-pa.googleapis.com",
    "cloudcode-pa.googleapis.com",
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
