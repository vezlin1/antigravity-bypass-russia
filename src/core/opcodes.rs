use std::sync::OnceLock;
use regex::bytes::Regex as BytesRegex;
use regex::Regex as StrRegex;

pub const STRING_FROM: &str = "ineligible";
pub const STRING_TO: &str = "inexigible";

pub const MGR_GATE_X64_ORIG_REGEX: &str =
    r"(?-u)\x80\x78\x08\x00\x74.\x48\x8b.[\x24\x00-\xff].\x48\x89.[\x60\x00-\xff]";
pub const MGR_GATE_X64_PATCHED_REGEX: &str =
    r"(?-u)\xc6\x40\x08\x01\x90\x90\x48\x8b.[\x24\x00-\xff].\x48\x89.[\x60\x00-\xff]";
pub const MGR_GATE_X64_FIX: &[u8] = b"\xc6\x40\x08\x01\x90\x90";
pub const MGR_GATE_X64_RESTORE: &[u8] = b"\x80\x78\x08\x00\x74\x00";

pub const MGR_GATE_ARM64_ORIG_REGEX: &str =
    r"(?-u)\x03\x20\x40\x39[\x03\x23\x43\x63\x83\xa3\xc3\xe3]..\x36(?:....){1,2}\x03\x10\x06\xa9";
pub const MGR_GATE_ARM64_PATCHED_REGEX: &str =
    r"(?-u)\x23\x00\x80\x52\x03\x20\x00\x39(?:....){1,2}\x03\x10\x06\xa9";
pub const MGR_GATE_ARM64_FIX: &[u8] = b"\x23\x00\x80\x52\x03\x20\x00\x39";
pub const MGR_GATE_ARM64_RESTORE: &[u8] = b"\x03\x20\x40\x39\x03\x00\x00\x36";

pub const CLI_GATE_X64_ORIG_REGEX: &str = r"(?-u)\x48\x85\xc0\x74.\x48\x8b";
pub const CLI_GATE_X64_PATCHED_REGEX: &str = r"(?-u)\x48\x85\xc0\x90\x90\x48\x8b";
pub const CLI_GATE_X64_FIX: &[u8] = b"\x48\x85\xc0\x90\x90";
pub const CLI_GATE_X64_RESTORE: &[u8] = b"\x48\x85\xc0\x74\x00";

#[inline]
pub fn regex_mgr_x64_orig() -> &'static BytesRegex {
    static RE: OnceLock<BytesRegex> = OnceLock::new();
    RE.get_or_init(|| BytesRegex::new(MGR_GATE_X64_ORIG_REGEX).expect("Valid regex"))
}
#[inline]
pub fn regex_mgr_x64_patched() -> &'static BytesRegex {
    static RE: OnceLock<BytesRegex> = OnceLock::new();
    RE.get_or_init(|| BytesRegex::new(MGR_GATE_X64_PATCHED_REGEX).expect("Valid regex"))
}
#[inline]
pub fn regex_mgr_arm64_orig() -> &'static BytesRegex {
    static RE: OnceLock<BytesRegex> = OnceLock::new();
    RE.get_or_init(|| BytesRegex::new(MGR_GATE_ARM64_ORIG_REGEX).expect("Valid regex"))
}
#[inline]
pub fn regex_mgr_arm64_patched() -> &'static BytesRegex {
    static RE: OnceLock<BytesRegex> = OnceLock::new();
    RE.get_or_init(|| BytesRegex::new(MGR_GATE_ARM64_PATCHED_REGEX).expect("Valid regex"))
}
#[inline]
pub fn regex_cli_x64_orig() -> &'static BytesRegex {
    static RE: OnceLock<BytesRegex> = OnceLock::new();
    RE.get_or_init(|| BytesRegex::new(CLI_GATE_X64_ORIG_REGEX).expect("Valid regex"))
}
#[inline]
pub fn regex_cli_x64_patched() -> &'static BytesRegex {
    static RE: OnceLock<BytesRegex> = OnceLock::new();
    RE.get_or_init(|| BytesRegex::new(CLI_GATE_X64_PATCHED_REGEX).expect("Valid regex"))
}
#[inline]
pub fn regex_ide_main_js_stock() -> &'static StrRegex {
    static RE: OnceLock<StrRegex> = OnceLock::new();
    RE.get_or_init(|| {
        StrRegex::new(
            r#"(resetIsTierGCPTos\(\)\s*[,;]\s*)(?:this|[A-Za-z_$0-9]+)(?:\.[A-Za-z_$0-9]+)*\.isGoogleInternal"#
        ).expect("Valid regex")
    })
}
