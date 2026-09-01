use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
#[allow(unused_imports)]
use std::process::Command;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

static TEMP_FILE_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub fn robust_write_file(path: &Path, data: &[u8]) -> Result<(), String> {
    let src_metadata = fs::metadata(path).ok();
    #[cfg(unix)]
    let orig_mode = src_metadata
        .as_ref()
        .map(|m| m.permissions().mode())
        .unwrap_or(0o755);

    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("chflags").args(["nouchg,noschg", path.to_str().unwrap_or_default()]).output();
        if let Some(parent) = path.parent() {
            let _ = Command::new("chflags").args(["nouchg,noschg", parent.to_str().unwrap_or_default()]).output();
            let _ = Command::new("chmod").args(["u+w", parent.to_str().unwrap_or_default()]).output();
        }
    }

    if let Some(ref metadata) = src_metadata {
        let mut perms = metadata.permissions();
        if perms.readonly() {
            #[allow(clippy::permissions_set_readonly_false)]
            perms.set_readonly(false);
            let _ = fs::set_permissions(path, perms);
        }
    }

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let seq = TEMP_FILE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let temp_path = parent.join(format!(".tmp_patch_{}_{}", std::process::id(), seq));

    let mut temp_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temp_path)
        .map_err(|e| format!("Не удалось создать временный файл: {}", e))?;

    temp_file
        .write_all(data)
        .map_err(|e| format!("Ошибка записи во временный файл: {}", e))?;
    temp_file
        .flush()
        .map_err(|e| format!("Ошибка сброса буфера: {}", e))?;
    drop(temp_file);

    #[cfg(unix)]
    {
        let _ = fs::set_permissions(&temp_path, fs::Permissions::from_mode(orig_mode));
    }

    let mut replace_ok = fs::rename(&temp_path, path).is_ok();
    if !replace_ok {
        if fs::copy(&temp_path, path).is_ok() {
            replace_ok = true;
        }
        let _ = fs::remove_file(&temp_path);
    } else {
        let _ = fs::remove_file(&temp_path);
    }

    if !replace_ok {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .map_err(|e| format!("Прямая запись не удалась: {}", e))?;
        file.write_all(data)
            .map_err(|e| format!("Ошибка прямой записи: {}", e))?;
        file.flush()
            .map_err(|e| format!("Ошибка сброса буфера: {}", e))?;
    }

    #[cfg(unix)]
    {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(orig_mode));
    }

    post_write_hook(path);
    Ok(())
}

pub fn post_write_hook(path: &Path) {
    #[cfg(target_os = "macos")]
    {
        let is_macho_target = path
            .extension()
            .map_or(true, |ext| ext != "js" && ext != "json" && ext != "asar" && ext != "bak");
        let path_str = path.to_str().unwrap_or_default();
        if is_macho_target {
            let res = Command::new("codesign")
                .args([
                    "--force",
                    "--sign",
                    "-",
                    "--preserve-metadata=entitlements,requirements,flags",
                    path_str,
                ])
                .output();
            if res.map(|o| !o.status.success()).unwrap_or(true) {
                let _ = Command::new("codesign")
                    .args(["--force", "--sign", "-", path_str])
                    .output();
            }
        }
        let _ = Command::new("xattr")
            .args(["-d", "com.apple.quarantine", path_str])
            .output();

        // Clear quarantine recursively without re-signing the entire .app with --deep
        let mut curr = path.parent();
        while let Some(p) = curr {
            if p.extension().and_then(|e| e.to_str()) == Some("app") {
                let app_str = p.to_str().unwrap_or_default();
                let _ = Command::new("xattr").args(["-cr", app_str]).output();
                break;
            }
            curr = p.parent();
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = path;
}
