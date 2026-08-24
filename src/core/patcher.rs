use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use crate::core::asar::{asar_js_is_patched, patch_asar_main_js, restore_asar_main_js};
use crate::core::detector::{FoundTarget, TargetKind};
use crate::core::opcodes::*;
use crate::system::fs_utils::robust_write_file;
use crate::system::process::kill_processes;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryState {
    Patched,
    Stock,
    Unknown,
}

static BINARY_STATE_CACHE: Mutex<Option<HashMap<PathBuf, (u64, BinaryState)>>> = Mutex::new(None);

pub fn invalidate_binary_cache() {
    if let Ok(mut lock) = BINARY_STATE_CACHE.lock() {
        *lock = None;
    }
}

pub fn check_binary_state(path: &Path) -> BinaryState {
    let mtime = fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if let Ok(mut lock) = BINARY_STATE_CACHE.lock() {
        let cache = lock.get_or_insert_with(HashMap::new);
        if let Some((cached_mtime, state)) = cache.get(path) {
            if *cached_mtime == mtime && mtime > 0 {
                return *state;
            }
        }
    }

    let state = check_binary_state_uncached(path);
    if let Ok(mut lock) = BINARY_STATE_CACHE.lock() {
        if let Some(cache) = lock.as_mut() {
            cache.insert(path.to_path_buf(), (mtime, state));
        }
    }
    state
}

fn check_binary_state_uncached(path: &Path) -> BinaryState {
    let file_name = path.file_name().unwrap_or_default().to_string_lossy();
    if file_name.ends_with(".asar") {
        return match asar_js_is_patched(path) {
            Some(true) => BinaryState::Patched,
            Some(false) => BinaryState::Stock,
            None => BinaryState::Unknown,
        };
    }

    let Ok(mut file) = File::open(path) else {
        return BinaryState::Unknown;
    };
    let mut data = Vec::new();
    if file.read_to_end(&mut data).is_err() {
        return BinaryState::Unknown;
    }

    if file_name.ends_with(".js") {
        let Ok(text) = String::from_utf8(data) else {
            return BinaryState::Unknown;
        };
        if regex_ide_js_patched().is_match(&text) {
            return BinaryState::Patched;
        }
        if regex_ide_main_js_stock().is_match(&text) {
            return BinaryState::Stock;
        }
        return BinaryState::Unknown;
    }

    static FINDER_TO: std::sync::OnceLock<memchr::memmem::Finder<'static>> = std::sync::OnceLock::new();
    static FINDER_FROM: std::sync::OnceLock<memchr::memmem::Finder<'static>> = std::sync::OnceLock::new();

    let finder_to = FINDER_TO.get_or_init(|| memchr::memmem::Finder::new(STRING_TO.as_bytes()));
    let finder_from = FINDER_FROM.get_or_init(|| memchr::memmem::Finder::new(STRING_FROM.as_bytes()));

    if finder_to.find(&data).is_some() {
        return BinaryState::Patched;
    }

    if regex_mgr_x64_patched().is_match(&data)
        || regex_mgr_arm64_patched().is_match(&data)
        || regex_cli_x64_patched().is_match(&data)
        || regex_cli_x64_long_patched().is_match(&data)
    {
        return BinaryState::Patched;
    }

    if regex_mgr_x64_orig().is_match(&data)
        || regex_mgr_arm64_orig().is_match(&data)
        || regex_cli_x64_orig().is_match(&data)
        || regex_cli_x64_long_orig().is_match(&data)
    {
        return BinaryState::Stock;
    }

    if finder_from.find(&data).is_some() {
        return BinaryState::Stock;
    }

    BinaryState::Unknown
}

pub fn patch_target(target: &FoundTarget) -> Result<String, String> {
    invalidate_binary_cache();
    kill_processes();
    match target.kind {
        TargetKind::IdeMainJs => patch_main_js(&target.path),
        TargetKind::IdeAsar => patch_asar_main_js(&target.path),
        TargetKind::LanguageServer | TargetKind::AgyCli => patch_binary_file(&target.path),
    }
}

pub fn restore_target(target: &FoundTarget) -> Result<String, String> {
    invalidate_binary_cache();
    kill_processes();
    match target.kind {
        TargetKind::IdeMainJs => restore_main_js(&target.path),
        TargetKind::IdeAsar => restore_asar_main_js(&target.path),
        TargetKind::LanguageServer | TargetKind::AgyCli => restore_binary_file(&target.path),
    }
}

fn patch_main_js(path: &Path) -> Result<String, String> {
    let data = fs::read(path).map_err(|e| format!("Ошибка чтения {}: {}", path.display(), e))?;
    let content = String::from_utf8(data).map_err(|e| format!("Файл не в UTF-8: {}", e))?;

    if regex_ide_js_patched().is_match(&content) {
        return Ok("Уже пропатчен (isGoogleInternal -> true)".to_string());
    }

    let bak_path = path.with_extension("js.bak");
    if !bak_path.exists() {
        let _ = fs::copy(path, &bak_path);
    }

    let re = regex_ide_main_js_stock();
    let spans: Vec<(usize, usize, usize)> = re
        .captures_iter(&content)
        .filter_map(|c| {
            let full = c.get(0)?;
            let prefix = c.get(1)?;
            Some((full.start(), prefix.end(), full.end()))
        })
        .collect();

    if spans.is_empty() {
        return Err("Сигнатура isGoogleInternal не найдена".to_string());
    }

    let mut new_content = content;
    for (_start, prefix_end, end) in spans.iter().copied().rev() {
        let rest_len = end - prefix_end;
        if rest_len < 4 {
            continue;
        }
        let replacement = format!("true{}", " ".repeat(rest_len - 4));
        new_content.replace_range(prefix_end..end, &replacement);
    }

    let count = regex_ide_js_patched().find_iter(&new_content).count();
    if count == 0 {
        return Err("Не удалось сохранить размер при патче main.js".to_string());
    }

    robust_write_file(path, new_content.as_bytes())?;
    Ok(format!("Пропатчен успешно (замен: {}, размер сохранён)", count))
}

fn restore_main_js(path: &Path) -> Result<String, String> {
    let bak_candidates = [
        path.with_extension("js.bak"),
        path.with_extension("bak"),
        path.with_extension("js.original"),
    ];

    for bak in &bak_candidates {
        if bak.exists() {
            if let Ok(data) = fs::read(bak) {
                if data.len() > 100 {
                    robust_write_file(path, &data)?;
                    return Ok("Восстановлен из бэкапа (.bak)".to_string());
                }
            }
        }
    }

    let data = fs::read(path).map_err(|e| format!("Ошибка чтения: {}", e))?;
    let content = String::from_utf8_lossy(&data);
    if let Ok(re) = regex::Regex::new(r"(resetIsTierGCPTos\(\)[ \t\r\n]*[,;][ \t\r\n]*)true[ \t\r\n]*") {
        if re.is_match(&content) {
            let restored = re.replace_all(&content, "${1}this.isGoogleInternal").to_string();
            robust_write_file(path, restored.as_bytes())?;
            return Ok("Откат main.js выполнен без .bak".to_string());
        }
    }

    Ok("Уже в исходном состоянии".to_string())
}

fn patch_binary_file(path: &Path) -> Result<String, String> {
    let mut data = fs::read(path).map_err(|e| format!("Ошибка чтения {}: {}", path.display(), e))?;

    let bak_candidates = [
        path.with_extension("exe.bak"),
        path.with_extension("bak"),
        path.with_extension("original"),
    ];
    let has_backup = bak_candidates.iter().any(|b| b.exists());
    if !has_backup {
        let bak = if path.extension().is_some_and(|ext| ext == "exe") {
            path.with_extension("exe.bak")
        } else {
            path.with_extension("bak")
        };
        let _ = fs::copy(path, &bak);
    }

    let mut applied_patches = Vec::new();

    let re_x64_orig = regex_mgr_x64_orig();
    let re_x64_patched = regex_mgr_x64_patched();
    let x64_hits: Vec<usize> = re_x64_orig.find_iter(&data).map(|m| m.start()).collect();
    if x64_hits.len() > 5 {
        return Err("x64 Core: слишком много совпадений сигнатуры, отказ патчить".to_string());
    }
    if !x64_hits.is_empty() {
        for start in x64_hits {
            data[start..start + MGR_GATE_X64_FIX.len()].copy_from_slice(MGR_GATE_X64_FIX);
        }
        applied_patches.push("x64 Core 2.0 (hasValidAuth=true)");
    } else if re_x64_patched.is_match(&data) {
        applied_patches.push("x64 Core 2.0 (уже пропатчен)");
    }

    let re_arm_orig = regex_mgr_arm64_orig();
    let re_arm_patched = regex_mgr_arm64_patched();
    let arm_hits: Vec<usize> = re_arm_orig.find_iter(&data).map(|m| m.start()).collect();
    if arm_hits.len() > 5 {
        return Err("ARM64 Core: слишком много совпадений сигнатуры, отказ патчить".to_string());
    }
    if !arm_hits.is_empty() {
        for start in arm_hits {
            data[start..start + MGR_GATE_ARM64_FIX.len()].copy_from_slice(MGR_GATE_ARM64_FIX);
        }
        applied_patches.push("ARM64 Core 2.0 (hasValidAuth=true)");
    } else if re_arm_patched.is_match(&data) {
        applied_patches.push("ARM64 Core 2.0 (уже пропатчен)");
    }

    let re_cli_long_orig = regex_cli_x64_long_orig();
    let re_cli_long_patched = regex_cli_x64_long_patched();
    let cli_long_hits: Vec<usize> = re_cli_long_orig.find_iter(&data).map(|m| m.start()).collect();
    if !cli_long_hits.is_empty() && cli_long_hits.len() <= 8 {
        for start in cli_long_hits {
            data[start..start + CLI_GATE_X64_LONG_FIX.len()].copy_from_slice(CLI_GATE_X64_LONG_FIX);
        }
        applied_patches.push("CLI Gate long (agy)");
    } else if re_cli_long_patched.is_match(&data) {
        applied_patches.push("CLI Gate long (уже пропатчен)");
    }

    let re_cli_orig = regex_cli_x64_orig();
    let re_cli_patched = regex_cli_x64_patched();
    let cli_hits: Vec<usize> = re_cli_orig.find_iter(&data).map(|m| m.start()).collect();
    if cli_hits.len() > 8 {
        // too generic — skip rather than corrupt the binary
    } else if !cli_hits.is_empty() {
        for start in cli_hits {
            data[start..start + CLI_GATE_X64_FIX.len()].copy_from_slice(CLI_GATE_X64_FIX);
        }
        applied_patches.push("CLI Gate (agy)");
    } else if re_cli_patched.is_match(&data) {
        applied_patches.push("CLI Gate (уже пропатчен)");
    }

    if applied_patches.is_empty() {
        let finder = memchr::memmem::Finder::new(STRING_FROM.as_bytes());
        let to_bytes = STRING_TO.as_bytes();
        let from_len = STRING_FROM.len();
        let mut count = 0;
        let mut pos = 0;
        while let Some(idx) = finder.find(&data[pos..]) {
            let abs_idx = pos + idx;
            data[abs_idx..abs_idx + from_len].copy_from_slice(to_bytes);
            count += 1;
            pos = abs_idx + from_len;
        }
        if count > 0 {
            applied_patches.push("Строковый fallback (ineligible -> inexigible)");
        }
    }

    if applied_patches.is_empty() {
        return Err("Патчи не применимы (неизвестная версия бинарника)".to_string());
    }

    robust_write_file(path, &data)?;
    Ok(applied_patches.join(", "))
}

fn restore_binary_file(path: &Path) -> Result<String, String> {
    let bak_candidates = [
        path.with_extension("exe.bak"),
        path.with_extension("bak"),
        path.with_extension("original"),
    ];

    for bak in &bak_candidates {
        if bak.exists() {
            if let Ok(data) = fs::read(bak) {
                if data.len() > 1000 {
                    robust_write_file(path, &data)?;
                    return Ok("Восстановлен из бэкапа (.bak)".to_string());
                }
            }
        }
    }

    // Without .bak do not guess original jump offsets — only reverse the string swap.
    let mut data = fs::read(path).map_err(|e| format!("Ошибка чтения {}: {}", path.display(), e))?;
    let finder = memchr::memmem::Finder::new(STRING_TO.as_bytes());
    let to_bytes = STRING_FROM.as_bytes();
    let from_len = STRING_TO.len();
    let mut count = 0;
    let mut pos = 0;
    while let Some(idx) = finder.find(&data[pos..]) {
        let abs_idx = pos + idx;
        data[abs_idx..abs_idx + from_len].copy_from_slice(to_bytes);
        count += 1;
        pos = abs_idx + from_len;
    }
    if count > 0 {
        robust_write_file(path, &data)?;
        return Ok(format!(
            "Строковый откат без .bak (inexigible -> ineligible, {}). Опкоды не тронуты — нужен .bak",
            count
        ));
    }

    Ok("Нет .bak и нечего откатывать строками".to_string())
}
