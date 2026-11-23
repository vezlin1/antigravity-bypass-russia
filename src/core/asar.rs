use super::patcher::{plan_js, Plan};
use serde_json::Value;
use std::{
    borrow::Cow,
    fs,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

const PREFIX_LEN: usize = 16;

/// Header JSON length and payload offset, from the 16-byte prefix and the
/// total archive length.
fn layout(prefix: &[u8], length: usize) -> Result<(usize, usize), String> {
    let read_u32 = |offset: usize| -> Result<u32, String> {
        Ok(u32::from_le_bytes(
            prefix
                .get(offset..offset + 4)
                .ok_or("Короткий ASAR")?
                .try_into()
                .unwrap(),
        ))
    };
    if read_u32(0)? != 4 {
        return Err("Некорректный ASAR".into());
    }
    let payload = (read_u32(4)? as usize)
        .checked_add(8)
        .ok_or("ASAR overflow")?;
    let json_len = read_u32(12)? as usize;
    if json_len > 32 * 1024 * 1024 || payload > length || PREFIX_LEN + json_len > payload {
        return Err("Некорректный размер ASAR header".into());
    }
    Ok((json_len, payload))
}

fn parse_header(json: &[u8]) -> Result<Value, String> {
    serde_json::from_slice(json).map_err(|e| format!("ASAR JSON: {e}"))
}

fn archive(data: &[u8]) -> Result<(Value, usize), String> {
    let (json_len, payload) = layout(data, data.len())?;
    let header = parse_header(&data[PREFIX_LEN..PREFIX_LEN + json_len])?;
    Ok((header, payload))
}
fn entry<'a>(header: &'a Value, path: &str) -> Option<&'a Value> {
    let mut value = header;
    for component in path.split('/') {
        value = value.get("files")?.get(component)?;
    }
    Some(value)
}
fn content_range(
    entry: &Value,
    payload: usize,
    length: usize,
) -> Result<std::ops::Range<usize>, String> {
    if entry.get("unpacked").and_then(Value::as_bool) == Some(true) || entry.get("link").is_some() {
        return Err("ASAR entry unpacked/link".into());
    }
    let offset = entry
        .get("offset")
        .and_then(|v| {
            v.as_str()
                .and_then(|s| s.parse::<usize>().ok())
                .or_else(|| v.as_u64().and_then(|n| usize::try_from(n).ok()))
        })
        .ok_or("ASAR offset")?;
    let size = entry
        .get("size")
        .and_then(Value::as_u64)
        .and_then(|n| usize::try_from(n).ok())
        .ok_or("ASAR size")?;
    let start = payload.checked_add(offset).ok_or("ASAR offset overflow")?;
    let end = start
        .checked_add(size)
        .filter(|n| *n <= length)
        .ok_or("ASAR entry вне файла")?;
    Ok(start..end)
}
/// Reads only the header and the package.json entry, not the whole archive.
pub fn read_asar_package_version(path: &Path) -> Option<String> {
    const PACKAGE_LIMIT: usize = 4 * 1024 * 1024;
    let mut file = fs::File::open(path).ok()?;
    let length = usize::try_from(file.metadata().ok()?.len()).ok()?;
    let mut prefix = [0u8; PREFIX_LEN];
    file.read_exact(&mut prefix).ok()?;
    let (json_len, payload) = layout(&prefix, length).ok()?;
    let mut json = vec![0u8; json_len];
    file.read_exact(&mut json).ok()?;
    let header = parse_header(&json).ok()?;
    let range = content_range(entry(&header, "package.json")?, payload, length).ok()?;
    if range.len() > PACKAGE_LIMIT {
        return None;
    }
    let mut package = vec![0u8; range.len()];
    file.seek(SeekFrom::Start(range.start as u64)).ok()?;
    file.read_exact(&mut package).ok()?;
    let package: Value = serde_json::from_slice(&package).ok()?;
    package.get("version")?.as_str().map(str::to_string)
}
pub(crate) fn plan_asar(data: &[u8]) -> Result<Plan<'_>, String> {
    let (header, payload) = archive(data)?;
    let mut result = Plan {
        data: Cow::Borrowed(data),
        changes: 0,
        existing: 0,
        profile: "asar-ide-reset-tier-v1".into(),
    };
    for name in [
        "out/main.js",
        "out/vs/code/electron-main/main.js",
        "main.js",
    ] {
        let Some(file) = entry(&header, name) else {
            continue;
        };
        let range = content_range(file, payload, data.len())?;
        let p = plan_js(&data[range.clone()])?;
        if p.changes > 0 && file.get("integrity").is_some() {
            return Err("ASAR содержит integrity-метаданные: эта упаковка пока не поддерживается; архив сохранён".into());
        }
        result.changes += p.changes;
        result.existing += p.existing;
        if p.changes > 0 {
            result.data.to_mut()[range].copy_from_slice(&p.data);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(js: &[u8], integrity: bool) -> Vec<u8> {
        let mut node = serde_json::json!({"size": js.len(), "offset":"0"});
        if integrity {
            node["integrity"] = serde_json::json!({"hash":"example"});
        }
        let header =
            serde_json::to_vec(&serde_json::json!({"files":{"out":{"files":{"main.js":node}}}}))
                .unwrap();
        let header_size = 8 + (header.len() + 3) / 4 * 4;
        let mut data = Vec::new();
        for value in [
            4,
            header_size as u32,
            (header_size - 4) as u32,
            header.len() as u32,
        ] {
            data.extend(value.to_le_bytes());
        }
        data.extend(header);
        data.resize(8 + header_size, 0);
        data.extend(js);
        data
    }
    #[test]
    fn unrelated_internal_marker_does_not_trigger_watcher() {
        let input = fixture(b"x.isGoogleInternal", false);
        let p = plan_asar(&input).unwrap();
        assert_eq!((p.changes, p.existing), (0, 0));
    }
    #[test]
    fn patches_complete_js_entry_and_refuses_integrity_archive() {
        let js = "x.resetIsTierGCPTos(),x.isGoogleInternal; // привет".as_bytes();
        let input = fixture(js, false);
        let p = plan_asar(&input).unwrap();
        assert_eq!(p.changes, 1);
        assert_eq!(p.data.len(), input.len());
        assert_eq!(plan_asar(&p.data).unwrap().existing, 1);
        assert!(plan_asar(&fixture(js, true)).is_err());
    }
}
