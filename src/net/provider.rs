pub const NRPT_TAG: &str = "ANTIGRAVITY-BYPASS-RUSSIA";

pub const NRPT_DOMAINS: &[&str] = &[
    // Antigravity & AI Core Endpoints
    ".cloudcode-pa.googleapis.com",
    ".daily-cloudcode-pa.googleapis.com",
    ".daily-cloudcode-pa.sandbox.googleapis.com",
    ".antigravity-pa.googleapis.com",
    ".antigravity.googleapis.com",
    ".antigravity.google",
    ".antigravity-unleash.goog",
    ".cloudaicompanion.googleapis.com",
    ".cloudaicompanion.sandbox.googleapis.com",
    ".optimizationguide-pa.googleapis.com",
    ".developerprofiles-pa.googleapis.com",
    ".aicode.googleapis.com",
    ".aida.googleapis.com",
    ".geller-pa.googleapis.com",
    ".proactivebackend-pa.googleapis.com",
    ".robinfrontend-pa.googleapis.com",
    ".generativelanguage.googleapis.com",
    ".gemini.google.com",
    ".gemini.google",
    ".gemini.gstatic.com",
    ".bard.google.com",
    ".generativeai.google",
    ".aistudio.google.com",
    ".ai.studio",
    ".ai.google.dev",
    ".makersuite.google.com",
    ".alkalicore-pa.clients6.google.com",
    ".alkalimakersuite-pa.clients6.google.com",
    ".webchannel-alkalimakersuite-pa.clients6.google.com",
    ".alkalimakersuite-pa.googleapis.com",
    ".alkalimakersuiteapplets.pa.googleapis.com",
    ".people-pa.clients6.google.com",
    ".notebooklm-pa.googleapis.com",
    ".notebooklm.googleapis.com",
    ".notebooklm.google",
    ".notebooklm.google.com",
    ".notebook.google.com",
    ".jules.google",
    ".jules.google.com",
    ".opal.google",
    ".opal.google.com",
    ".labs.google",
    ".labs.google.com",
    ".flow.google",
    ".aisandbox-pa.googleapis.com",
    ".deepmind.com",
    ".deepmind.google",
    ".stitch.withgoogle.com",
    ".iamcredentials.googleapis.com",
    ".cloudresourcemanager.googleapis.com",
    ".sts.googleapis.com",
    ".aiplatform.googleapis.com",
    ".s-aiplatform.googleapis.com",
    ".play.googleapis.com",
    // Google Sheets, Drive, Docs & OAuth Endpoints
    ".oauth2.googleapis.com",
    ".accounts.google.com",
    ".sheets.googleapis.com",
    ".docs.googleapis.com",
    ".drive.googleapis.com",
    ".script.google.com",
    ".script.googleusercontent.com",
    ".spreadsheets.google.com",
    ".docs.google.com",
    ".drive.google.com",
    ".apis.google.com",
    ".clients6.google.com",
    ".servicecontrol.googleapis.com",
    ".servicemanagement.googleapis.com",
    ".googleapis.com",
    ".google.com",
    ".gstatic.com",
    ".googleusercontent.com",
    // Exact domain names for strict matching
    "googleapis.com",
    "google.com",
    "oauth2.googleapis.com",
    "accounts.google.com",
    "sheets.googleapis.com",
    "docs.google.com",
    "drive.google.com",
    "script.google.com",
    "apis.google.com",
    "www.googleapis.com",
    "antigravity.google",
    "gemini.google",
    "deepmind.google",
];

pub const ALL_DNS_IPS: &[&str] = &[
    "111.88.96.50",
    "111.88.96.51",
    "176.108.243.68",
    "176.108.243.69",
    "176.108.243.70",
    "176.108.243.71",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsProvider {
    XboxDns,
    Custom(String),
}

impl DnsProvider {
    pub fn name(&self) -> &str {
        match self {
            Self::XboxDns => "Xbox-DNS.ru (Быстрый SmartDNS)",
            Self::Custom(s) => s.as_str(),
        }
    }

    pub fn server_ips(&self) -> Vec<String> {
        match self {
            Self::XboxDns => vec!["111.88.96.50".to_string(), "176.108.243.68".to_string()],
            Self::Custom(s) => {
                let ips: Vec<String> = s
                    .split([',', ' '])
                    .map(|x| x.trim().to_string())
                    .filter(|x| !x.is_empty() && x.parse::<std::net::Ipv4Addr>().is_ok())
                    .collect();
                if ips.is_empty() {
                    vec!["111.88.96.50".to_string()]
                } else {
                    ips
                }
            }
        }
    }

    pub fn to_nameservers_arg(&self, via_relay: bool) -> String {
        if via_relay {
            crate::net::relay::LISTEN_IP.to_string()
        } else {
            self.server_ips().join(",")
        }
    }
}
