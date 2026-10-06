use regex::bytes::Regex as BytesRegex;
use regex::Regex as StrRegex;
use std::sync::OnceLock;

pub const MGR_GATE_X64_ORIG_REGEX: &str = r"(?s-u)\x80\x78\x08\x00\x74.\x48\x8b.\x24.\x48\x89.\x60";
pub const MGR_GATE_X64_PATCHED_REGEX: &str =
    r"(?s-u)\xc6\x40\x08\x01\x90\x90\x48\x8b.\x24.\x48\x89.\x60";
pub const MGR_GATE_X64_FIX: &[u8] = b"\xc6\x40\x08\x01\x90\x90";

pub const MGR_GATE_ARM64_ORIG_REGEX: &str =
    r"(?s-u)\x03\x20\x40\x39[\x03\x23\x43\x63\x83\xa3\xc3\xe3]..\x36(?:....){1,2}\x03\x10\x06\xa9";
pub const MGR_GATE_ARM64_PATCHED_REGEX: &str =
    r"(?s-u)\x23\x00\x80\x52\x03\x20\x00\x39(?:....){1,2}\x03\x10\x06\xa9";
pub const MGR_GATE_ARM64_FIX: &[u8] = b"\x23\x00\x80\x52\x03\x20\x00\x39";

/// CLI sign-in: CBNZ X1 (error), CBZ X0 (nil result), LDRB W2,[X0,#8],
/// TBNZ W2,#0 (eligible), BL (ineligibility details). The two success
/// branches must share a forward target; the patcher validates all targets.
pub const CLI_GATE_ARM64_ORIG_REGEX: &str = r"(?s-u)[\x01\x21\x41\x61\x81\xa1\xc1\xe1]..\xb5[\x00\x20\x40\x60\x80\xa0\xc0\xe0]..\xb4\x02\x20\x40\x39[\x02\x22\x42\x62\x82\xa2\xc2\xe2].[\x00-\x07]\x37...[\x94-\x97]";
pub const CLI_GATE_ARM64_PATCHED_REGEX: &str = r"(?s-u)[\x01\x21\x41\x61\x81\xa1\xc1\xe1]..\xb5[\x00\x20\x40\x60\x80\xa0\xc0\xe0]..\xb4\x22\x00\x80\x52[\x02\x22\x42\x62\x82\xa2\xc2\xe2].[\x00-\x07]\x37...[\x94-\x97]";
/// MOV W2,#1 replaces only the flag load. Preserve nil/error handling and
/// the existing branch, and never write into the authentication result.
pub const CLI_GATE_ARM64_FIX: &[u8] = b"\x22\x00\x80\x52";
pub const CLI_GATE_ARM64_FIX_AT: usize = 8;

pub const CLI_GATE_X64_LONG_ORIG_REGEX: &str =
    r"(?s-u)\x48\x85\xc0\x0f\x84....\x80\x78\x08\x00\x0f\x85....";
/// Keep the null branch and remove only the flag comparison. For non-null
/// pointers the preceding `test %rax, %rax` leaves ZF clear, so `jne` skips
/// the ineligible path without writing to the object.
pub const CLI_GATE_X64_LONG_PATCHED_REGEX: &str =
    r"(?s-u)\x48\x85\xc0\x0f\x84....\x90\x90\x90\x90\x0f\x85....";
pub const CLI_GATE_X64_LONG_FIX: &[u8] = b"\x90\x90\x90\x90";
pub const CLI_GATE_X64_LONG_FIX_AT: usize = 9;
pub const CLI_GATE_X64_LONG_V1_PATCHED_REGEX: &str =
    r"(?s-u)\x48\x85\xc0\x90\x90\x90\x90\x90\x90\x80\x78\x08\x00\x0f\x85....";
pub const CLI_GATE_X64_LONG_V1_FIX: &[u8] = b"\x48\x85\xc0\x90\x90\x90\x90\x90\x90";

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
pub fn regex_cli_arm64_orig() -> &'static BytesRegex {
    static RE: OnceLock<BytesRegex> = OnceLock::new();
    RE.get_or_init(|| BytesRegex::new(CLI_GATE_ARM64_ORIG_REGEX).expect("Valid regex"))
}
#[inline]
pub fn regex_cli_arm64_patched() -> &'static BytesRegex {
    static RE: OnceLock<BytesRegex> = OnceLock::new();
    RE.get_or_init(|| BytesRegex::new(CLI_GATE_ARM64_PATCHED_REGEX).expect("Valid regex"))
}
#[inline]
pub fn regex_cli_x64_long_orig() -> &'static BytesRegex {
    static RE: OnceLock<BytesRegex> = OnceLock::new();
    RE.get_or_init(|| BytesRegex::new(CLI_GATE_X64_LONG_ORIG_REGEX).expect("Valid regex"))
}
#[inline]
pub fn regex_cli_x64_long_patched() -> &'static BytesRegex {
    static RE: OnceLock<BytesRegex> = OnceLock::new();
    RE.get_or_init(|| BytesRegex::new(CLI_GATE_X64_LONG_PATCHED_REGEX).expect("Valid regex"))
}
#[inline]
pub fn regex_cli_x64_long_v1_patched() -> &'static BytesRegex {
    static RE: OnceLock<BytesRegex> = OnceLock::new();
    RE.get_or_init(|| BytesRegex::new(CLI_GATE_X64_LONG_V1_PATCHED_REGEX).expect("Valid regex"))
}
#[inline]
pub fn regex_ide_js_patched() -> &'static StrRegex {
    static RE: OnceLock<StrRegex> = OnceLock::new();
    RE.get_or_init(|| {
        StrRegex::new(r"resetIsTierGCPTos\(\)[ \t\r\n]*[,;][ \t\r\n]*true").expect("Valid regex")
    })
}
#[inline]
pub fn regex_ide_main_js_stock() -> &'static StrRegex {
    static RE: OnceLock<StrRegex> = OnceLock::new();
    RE.get_or_init(|| {
        StrRegex::new(
            r#"(resetIsTierGCPTos\(\)[ \t\r\n]*[,;][ \t\r\n]*)(?:this|[A-Za-z_$0-9]+)(?:\.[A-Za-z_$0-9]+)*\.isGoogleInternal"#
        ).expect("Valid regex")
    })
}
