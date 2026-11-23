#[cfg(windows)]
pub const NRPT_TAG: &str = "ANTIGRAVITY-BYPASS-RUSSIA";

#[cfg(windows)]
pub const BROWSER_PAGES: &[(&str, &str)] = &[
    ("gemini.google.com", "/app"),
    ("aistudio.google.com", "/welcome"),
];

/// Studio/Gemini canaries. Their substitution results must be checked separately
/// from Cloud Code: a provider can support one family and pass the other through.
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

pub const DAILY_CLOUD_CODE: &str = "daily-cloudcode-pa.googleapis.com";
pub const PRIMARY_CLOUD_CODE: &str = "cloudcode-pa.googleapis.com";

/// Agent Cloud Code & Gemini API hosts. Each gets its own NRPT nameserver list —
/// only providers that actually substitute *this* name, with fallback to ranked SNI proxies.
/// aicode.googleapis.com serves CLI 1.4.11+ eligibility/entitlement checks
/// (ManagementService/GetUserInfo, entitlement.userTier); routing it directly
/// fails the check even with the local gate patched.
pub const NRPT_AGENT: &[&str] = &[
    DAILY_CLOUD_CODE,
    PRIMARY_CLOUD_CODE,
    "generativelanguage.googleapis.com",
    "aicode.googleapis.com",
];

pub const GEOHIDE_EU_DOH: &str = "https://eu.geohide.ru/dns-query";

/// GeoHide frontends used as TLS candidates when its DoH endpoint is active.
/// Each address must pass verification for the particular hostname before use.
pub const GEOHIDE_PROXY_V4: &[&str] = &[
    "193.233.112.68",
    "193.233.112.88",
    "5.175.161.40",
    "5.175.161.3",
    "45.13.237.213",
    "159.194.200.33",
    "193.233.112.67",
    "37.221.93.141",
    "143.20.64.192",
    "37.221.93.128",
];

pub fn nrpt_domains() -> Vec<&'static str> {
    let mut out = Vec::with_capacity(NRPT_AGENT.len() + NRPT_STUDIO.len());
    out.extend_from_slice(NRPT_AGENT);
    out.extend_from_slice(NRPT_STUDIO);
    out
}
