use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

pub fn read_asar_package_version(asar_path: &Path) -> Option<String> {
    let mut file = File::open(asar_path).ok()?;
    let mut header = [0u8; 16];
    file.read_exact(&mut header).ok()?;

    let magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    if magic != 4 {
        return None;
    }
    let header_size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as u64;
    let json_size = u32::from_le_bytes([header[12], header[13], header[14], header[15]]) as usize;

    if json_size > 32 * 1024 * 1024 {
        return None;
    }

    let mut json_bytes = vec![0u8; json_size];
    file.read_exact(&mut json_bytes).ok()?;

    // Fast SIMD search for "package.json" within ASAR header
    let finder = memchr::memmem::Finder::new(b"\"package.json\"");
    let pkg_idx = finder.find(&json_bytes)?;

    // Scan a local window of 1024 bytes around package.json
    let window_end = (pkg_idx + 1024).min(json_bytes.len());
    let window = String::from_utf8_lossy(&json_bytes[pkg_idx..window_end]);

    let offset = extract_json_num(&window, "offset")?;
    let size = extract_json_num(&window, "size")? as usize;

    if size == 0 || size > 5 * 1024 * 1024 {
        return None;
    }

    let payload_start = 8 + header_size;
    file.seek(SeekFrom::Start(payload_start + offset)).ok()?;
    let mut pkg_bytes = vec![0u8; size];
    file.read_exact(&mut pkg_bytes).ok()?;

    let pkg_str = String::from_utf8_lossy(&pkg_bytes);
    extract_json_string(&pkg_str, "version")
}

fn extract_json_num(s: &str, key: &str) -> Option<u64> {
    let key_pat = format!("\"{}\"", key);
    let key_pos = s.find(&key_pat)?;
    let after_key = &s[key_pos + key_pat.len()..];
    let colon_pos = after_key.find(':')?;
    let val_str = after_key[colon_pos + 1..].trim_start();

    if let Some(stripped) = val_str.strip_prefix('"') {
        let end_quote = stripped.find('"')?;
        stripped[..end_quote].parse::<u64>().ok()
    } else {
        let num_str: String = val_str.chars().take_while(|c| c.is_ascii_digit()).collect();
        num_str.parse::<u64>().ok()
    }
}

fn extract_json_string(s: &str, key: &str) -> Option<String> {
    let key_pat = format!("\"{}\"", key);
    let key_pos = s.find(&key_pat)?;
    let after_key = &s[key_pos + key_pat.len()..];
    let colon_pos = after_key.find(':')?;
    let val_str = after_key[colon_pos + 1..].trim_start();
    let stripped = val_str.strip_prefix('"')?;
    let end_quote = stripped.find('"')?;
    Some(stripped[..end_quote].to_string())
}
