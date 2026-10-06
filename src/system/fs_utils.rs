use std::{fs, io::Write, path::Path};

/// Never truncate the destination on a failed replacement.
pub fn robust_write_file(path: &Path, data: &[u8]) -> Result<(), String> {
    let temp = prepared_file(path, data)?;
    temp.persist(path).map_err(|e| {
        let holders = super::file_lock::holders(&[path.to_path_buf()]).unwrap_or_default();
        let action = if holders.is_empty() {
            "Проверьте права на файл, атрибут «только чтение» и защиту антивируса".to_string()
        } else { format!("Файл используется: {}. Сохраните работу, закройте эти приложения и повторите откат", holders.join(", ")) };
        format!(
            "Атомарная замена {} не удалась: {}. {}",
            path.display(),
            e.error, action
        )
    })?;
    Ok(())
}

pub(super) fn prepared_file(path: &Path, data: &[u8]) -> Result<tempfile::NamedTempFile, String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp =
        tempfile::NamedTempFile::new_in(parent).map_err(|e| format!("Временный файл: {e}"))?;
    temp.write_all(data).map_err(|e| e.to_string())?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err("Цель записи не является обычным файлом".into());
            }
            temp.as_file()
                .set_permissions(metadata.permissions())
                .map_err(|e| e.to_string())?;
            #[cfg(unix)]
            {
                use std::os::unix::{fs::MetadataExt, io::AsRawFd};
                if unsafe {
                    libc::fchown(temp.as_file().as_raw_fd(), metadata.uid(), metadata.gid())
                } != 0
                {
                    return Err(format!(
                        "Не сохранить владельца: {}",
                        std::io::Error::last_os_error()
                    ));
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // Root creates settings on behalf of the desktop user. A fresh file
            // inherits its parent's owner, while NamedTempFile keeps mode 0600.
            #[cfg(unix)]
            {
                use std::os::unix::{fs::MetadataExt, io::AsRawFd};
                let metadata = fs::metadata(parent).map_err(|e| e.to_string())?;
                if unsafe {
                    libc::fchown(temp.as_file().as_raw_fd(), metadata.uid(), metadata.gid())
                } != 0
                {
                    return Err(format!(
                        "Не сохранить владельца нового файла: {}",
                        std::io::Error::last_os_error()
                    ));
                }
            }
        }
        Err(error) => return Err(error.to_string()),
    }
    temp.as_file().sync_all().map_err(|e| e.to_string())?;
    Ok(temp)
}

/// Replace only the expected file. A competing updater's destination is never
/// overwritten; an interrupted move has a durable recovery copy.
pub fn guarded_write_file(
    path: &Path,
    expected: Option<&[u8]>,
    after: Option<&[u8]>,
) -> Result<(), String> {
    super::guarded_io::replace(path, expected, after)
}

pub fn recover_pending(path: &Path) -> Result<(), String> {
    super::guarded_io::recover_pending(path)
}

pub(super) fn inherit_directory_owner(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::{
            fs::{MetadataExt, OpenOptionsExt},
            io::AsRawFd,
        };
        let metadata = fs::metadata(path.parent().ok_or("Нет родителя каталога")?)
            .map_err(|e| e.to_string())?;
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(path)
            .map_err(|e| e.to_string())?;
        if unsafe { libc::fchown(file.as_raw_fd(), metadata.uid(), metadata.gid()) } != 0 {
            return Err(format!(
                "Не сохранить владельца каталога: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

pub(super) fn create_private_directory(path: &Path) -> Result<(), String> {
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    let mut builder = builder;
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => inherit_directory_owner(path),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if fs::symlink_metadata(path).is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink()) {
                Ok(())
            } else {
                Err("Каталог backup не является обычным каталогом".into())
            }
        }
        Err(error) => Err(format!("Backup: {error}")),
    }
}

pub fn post_write_hook(path: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let is_macho_target = path.extension().map_or(true, |ext| {
            ext != "js" && ext != "json" && ext != "asar" && ext != "bak"
        });
        let path_str = path.to_str().unwrap_or_default();
        if is_macho_target {
            let res = crate::system::command::output(
                "codesign",
                [
                    "--force",
                    "--sign",
                    "-",
                    "--preserve-metadata=entitlements,requirements,flags",
                    path_str,
                ],
            );
            let res = res.map_err(|e| format!("codesign: {e}"))?;
            if !res.status.success() {
                return Err(format!(
                    "codesign: {}",
                    String::from_utf8_lossy(&res.stderr).trim()
                ));
            }
            let verify =
                crate::system::command::output("codesign", ["--verify", "--strict", path_str])
                    .map_err(|e| e.to_string())?;
            if !verify.status.success() {
                return Err(format!(
                    "Проверка подписи службы: {}",
                    String::from_utf8_lossy(&verify.stderr).trim()
                ));
            }
        }
        let _ = crate::system::command::output("xattr", ["-d", "com.apple.quarantine", path_str]);

        // Clear quarantine recursively without re-signing the entire .app with --deep
        let mut curr = path.parent();
        while let Some(p) = curr {
            if p.extension().and_then(|e| e.to_str()) == Some("app") {
                let app_str = p.to_str().unwrap_or_default();
                let _ = crate::system::command::output("xattr", ["-cr", app_str]);
                break;
            }
            curr = p.parent();
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = path;
    Ok(())
}
