use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
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
    let Ok(mut file) = File::open(path) else {
        return BinaryState::Unknown;
    };
    let mut data = Vec::new();
    if file.read_to_end(&mut data).is_err() {
        return BinaryState::Unknown;
    }

    let file_name = path.file_name().unwrap_or_default().to_string_lossy();
    if file_name.ends_with(".js") {
        let Ok(text) = String::from_utf8(data) else {
            return BinaryState::Unknown;
        };
        let is_patched = text.contains("resetIsTierGCPTos(),true")
            || text.contains("resetIsTierGCPTos();true")
            || text.contains("resetIsTierGCPTos(),!0")
            || text.contains("resetIsTierGCPTos();!0");

        if is_patched {
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
    {
        return BinaryState::Patched;
    }

    if regex_mgr_x64_orig().is_match(&data)
        || regex_mgr_arm64_orig().is_match(&data)
        || regex_cli_x64_orig().is_match(&data)
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
        TargetKind::LanguageServer | TargetKind::AgyCli => patch_binary_file(&target.path),
    }
}

pub fn restore_target(target: &FoundTarget) -> Result<String, String> {
    invalidate_binary_cache();
    kill_processes();
    match target.kind {
        TargetKind::IdeMainJs => restore_main_js(&target.path),
        TargetKind::LanguageServer | TargetKind::AgyCli => restore_binary_file(&target.path),
    }
}

fn patch_main_js(path: &Path) -> Result<String, String> {
    let data = fs::read(path).map_err(|e| format!("Ошибка чтения {}: {}", path.display(), e))?;
    let content = String::from_utf8(data).map_err(|e| format!("Файл не в UTF-8: {}", e))?;

    let is_already = content.contains("resetIsTierGCPTos(),true")
        || content.contains("resetIsTierGCPTos();true")
        || content.contains("resetIsTierGCPTos(),!0")
        || content.contains("resetIsTierGCPTos();!0");

    if is_already {
        return Ok("Уже пропатчен (isGoogleInternal -> true)".to_string());
    }

    let bak_path = path.with_extension("js.bak");
    if !bak_path.exists() {
        let _ = fs::copy(path, &bak_path);
    }

    let re = regex_ide_main_js_stock();
    let count = re.find_iter(&content).count();
    if count == 0 {
        return Err("Сигнатура isGoogleInternal не найдена".to_string());
    }

    let new_content = re.replace_all(&content, "${1}true").to_string();
    robust_write_file(path, new_content.as_bytes())?;
    Ok(format!("Пропатчен успешно (замен: {})", count))
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
    let patched_patterns = [
        ("resetIsTierGCPTos(),true", "resetIsTierGCPTos(),this.isGoogleInternal"),
        ("resetIsTierGCPTos();true", "resetIsTierGCPTos();this.isGoogleInternal"),
        ("resetIsTierGCPTos(),!0", "resetIsTierGCPTos(),this.isGoogleInternal"),
        ("resetIsTierGCPTos();!0", "resetIsTierGCPTos();this.isGoogleInternal"),
    ];

    let mut restored = content.to_string();
    let mut count = 0;
    for (pat, repl) in &patched_patterns {
        if restored.contains(pat) {
            restored = restored.replace(pat, repl);
            count += 1;
        }
    }

    if count > 0 {
        robust_write_file(path, restored.as_bytes())?;
        return Ok(format!("Откат выполнен (замен: {})", count));
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
    if let Some(m) = re_x64_orig.find(&data) {
        let start = m.start();
        data[start..start + MGR_GATE_X64_FIX.len()].copy_from_slice(MGR_GATE_X64_FIX);
        applied_patches.push("x64 Core 2.0 (hasValidAuth=true)");
    } else if re_x64_patched.is_match(&data) {
        applied_patches.push("x64 Core 2.0 (уже пропатчен)");
    }

    let re_arm_orig = regex_mgr_arm64_orig();
    let re_arm_patched = regex_mgr_arm64_patched();
    if let Some(m) = re_arm_orig.find(&data) {
        let start = m.start();
        data[start..start + MGR_GATE_ARM64_FIX.len()].copy_from_slice(MGR_GATE_ARM64_FIX);
        applied_patches.push("ARM64 Core 2.0 (hasValidAuth=true)");
    } else if re_arm_patched.is_match(&data) {
        applied_patches.push("ARM64 Core 2.0 (уже пропатчен)");
    }

    let re_cli_orig = regex_cli_x64_orig();
    let re_cli_patched = regex_cli_x64_patched();
    if let Some(m) = re_cli_orig.find(&data) {
        let start = m.start();
        data[start..start + CLI_GATE_X64_FIX.len()].copy_from_slice(CLI_GATE_X64_FIX);
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

    let mut data = fs::read(path).map_err(|e| format!("Ошибка чтения {}: {}", path.display(), e))?;
    let mut restored_patches = Vec::new();

    let re_x64_patched = regex_mgr_x64_patched();
    if let Some(m) = re_x64_patched.find(&data) {
        let start = m.start();
        data[start..start + MGR_GATE_X64_RESTORE.len()].copy_from_slice(MGR_GATE_X64_RESTORE);
        restored_patches.push("x64 Core 2.0 (возврат opcodes)");
    }

    let re_arm_patched = regex_mgr_arm64_patched();
    if let Some(m) = re_arm_patched.find(&data) {
        let start = m.start();
        data[start..start + MGR_GATE_ARM64_RESTORE.len()].copy_from_slice(MGR_GATE_ARM64_RESTORE);
        restored_patches.push("ARM64 Core 2.0 (возврат opcodes)");
    }

    let re_cli_patched = regex_cli_x64_patched();
    if let Some(m) = re_cli_patched.find(&data) {
        let start = m.start();
        data[start..start + CLI_GATE_X64_RESTORE.len()].copy_from_slice(CLI_GATE_X64_RESTORE);
        restored_patches.push("CLI Gate (возврат opcodes)");
    }

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
        restored_patches.push("Строковый откат (inexigible -> ineligible)");
    }

    if !restored_patches.is_empty() {
        robust_write_file(path, &data)?;
        return Ok(restored_patches.join(", "));
    }

    Ok("Уже в исходном состоянии".to_string())
}
