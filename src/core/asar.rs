use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use crate::core::opcodes::regex_ide_main_js_stock;
use crate::system::fs_utils::robust_write_file;

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

    let finder = memchr::memmem::Finder::new(b"\"package.json\"");
    let pkg_idx = finder.find(&json_bytes)?;

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

fn chunked_contains(path: &Path, needles: &[&[u8]]) -> Option<usize> {
    let mut file = File::open(path).ok()?;
    let overlap = needles.iter().map(|n| n.len()).max().unwrap_or(1).saturating_sub(1);
    let mut buf = vec![0u8; 1024 * 1024];
    let mut carry: Vec<u8> = Vec::new();
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        let mut chunk = carry.clone();
        chunk.extend_from_slice(&buf[..n]);
        for (i, needle) in needles.iter().enumerate() {
            if memchr::memmem::find(&chunk, needle).is_some() {
                return Some(i);
            }
        }
        carry.clear();
        if overlap > 0 && chunk.len() >= overlap {
            carry.extend_from_slice(&chunk[chunk.len() - overlap..]);
        }
    }
    None
}

/// Some(true) patched, Some(false) stock, None unknown.
pub fn asar_js_is_patched(path: &Path) -> Option<bool> {
    const PATCHED: &[&[u8]] = &[
        b"resetIsTierGCPTos(),true",
        b"resetIsTierGCPTos();true",
        b"resetIsTierGCPTos(),!0",
        b"resetIsTierGCPTos();!0",
    ];
    const STOCK: &[&[u8]] = &[b".isGoogleInternal"];
    if chunked_contains(path, PATCHED).is_some() {
        return Some(true);
    }
    if chunked_contains(path, STOCK).is_some() {
        return Some(false);
    }
    None
}

/// Size-preserving in-place patch of `isGoogleInternal` inside app.asar.
pub fn patch_asar_main_js(path: &Path) -> Result<String, String> {
    if asar_js_is_patched(path) == Some(true) {
        return Ok("Уже пропатчен (app.asar)".to_string());
    }

    let data = fs::read(path).map_err(|e| format!("Чтение asar: {}", e))?;
    let needle = b"resetIsTierGCPTos";
    let finder = memchr::memmem::Finder::new(needle);
    let re = regex_ide_main_js_stock();
    let mut patches: Vec<(usize, usize, Vec<u8>)> = Vec::new();
    let mut pos = 0usize;

    while let Some(idx) = finder.find(&data[pos..]) {
        let abs = pos + idx;
        let win_end = (abs + 240).min(data.len());
        let window = &data[abs..win_end];
        if let Ok(s) = std::str::from_utf8(window) {
            if let Some(caps) = re.captures(s) {
                let full = caps.get(0).unwrap();
                let prefix = caps.get(1).unwrap();
                let rest_start = abs + prefix.end();
                let rest_end = abs + full.end();
                let rest_len = rest_end - rest_start;
                if rest_len >= 4 {
                    let mut repl = b"true".to_vec();
                    repl.extend(std::iter::repeat(b' ').take(rest_len - 4));
                    patches.push((rest_start, rest_end, repl));
                }
            }
        }
        pos = abs + needle.len();
    }

    if patches.is_empty() {
        return Ok(
            "В этой версии IDE нет isGoogleInternal в app.asar (гейт в Core) — файл не трогаем"
                .to_string(),
        );
    }

    let bak = path.with_extension("asar.bak");
    if !bak.exists() {
        let _ = fs::copy(path, &bak);
    }

    let mut data = data;
    for (start, end, repl) in &patches {
        data[*start..*end].copy_from_slice(repl);
    }
    robust_write_file(path, &data)?;
    Ok(format!(
        "app.asar пропатчен (замен: {}, размер сохранён)",
        patches.len()
    ))
}

pub fn restore_asar_main_js(path: &Path) -> Result<String, String> {
    let bak = path.with_extension("asar.bak");
    if bak.exists() {
        if let Ok(data) = fs::read(&bak) {
            if data.len() > 1000 {
                robust_write_file(path, &data)?;
                return Ok("app.asar восстановлен из .asar.bak".to_string());
            }
        }
    }
    Ok("Нет бэкапа app.asar — оставлен как есть".to_string())
}
