use std::{
    ffi::{CString, OsStr},
    fs, io,
    os::unix::{ffi::OsStrExt, fs::MetadataExt, fs::OpenOptionsExt},
    path::{Component, Path, PathBuf},
};

pub(crate) fn bundle(path: &Path) -> Option<&Path> {
    path.ancestors()
        .filter(|part| {
            part.extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("app"))
        })
        .last()
}

pub(crate) fn resolved_file(path: &Path) -> io::Result<PathBuf> {
    Ok(fs::canonicalize(parent(path))?.join(path.file_name().ok_or(io::ErrorKind::InvalidInput)?))
}

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

/// Ask the kernel under the same TCC identity as the writer. No truncation,
/// file creation or attribute changes are needed to detect a denied write.
pub(crate) fn check_write_access(path: &Path) -> Result<(), String> {
    if bundle(path).is_none() {
        return Ok(());
    }
    fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map(|_| ())
        .map_err(|error| {
            if error.raw_os_error() == Some(libc::EPERM) {
                format!(
                    "Защита «Управление приложениями» запретила запись в {}: {error}",
                    path.display()
                )
            } else {
                format!("Проверка записи в {}: {error}", path.display())
            }
        })
}

pub(super) fn backup_directory(path: &Path) -> Result<Option<PathBuf>, String> {
    if bundle(path).is_none() {
        return Ok(None);
    }
    let path = resolved_file(path).map_err(|error| error.to_string())?;
    let key = super::journal::digest(path.as_os_str().as_bytes());
    Ok(Some(
        super::user_context::home()?
            .join("Library/Application Support/AntigravityBypass/patch-backups")
            .join(key),
    ))
}

pub(super) fn create_backup_parents(directory: &Path) -> Result<(), String> {
    let backups = parent(directory);
    let data = parent(backups);
    fs::create_dir_all(parent(data)).map_err(|error| error.to_string())?;
    super::fs_utils::create_private_directory(data)?;
    super::fs_utils::create_private_directory(backups)
}

/// Sibling of the *outer* bundle, so even a helper .app does not stage inside
/// the IDE. This location survives an interrupted write and is on its volume.
pub(crate) fn transactions(app: &Path) -> PathBuf {
    let key = super::journal::digest(app.file_name().unwrap_or_default().as_bytes());
    parent(app).join(format!(".antigravity-bypass-{key}"))
}

pub(crate) fn transaction_directory_exists(directory: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.is_dir() => Ok(true),
        Ok(_) => Err("Каталог подготовки не является обычным каталогом".into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("Каталог подготовки: {error}")),
    }
}

pub(super) fn create_transactions(app: &Path, path: &Path) -> Result<PathBuf, String> {
    let directory = transactions(app);
    let volume = |path: &Path| fs::metadata(path).map(|metadata| metadata.dev());
    let target_volume = volume(parent(path)).map_err(|error| error.to_string())?;
    if volume(parent(app)).map_err(|error| error.to_string())? != target_volume {
        return Err("Рядом с приложением нет каталога для атомарной замены на томе файла".into());
    }
    super::fs_utils::create_private_directory(&directory)?;
    if volume(&directory).map_err(|error| error.to_string())? != target_volume {
        return Err("Каталог подготовки находится на другом томе; файл сохранён".into());
    }
    Ok(directory)
}

pub(super) fn rename_exclusive(from: &Path, to: &Path) -> io::Result<()> {
    let from = CString::new(from.as_os_str().as_bytes())?;
    let to = CString::new(to.as_os_str().as_bytes())?;
    if unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), libc::RENAME_EXCL) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Move a service directory out of the bundle in one rename. Returns the
/// archive (`recovered-*`) that now holds it as `original`.
pub(super) fn archive_legacy(path: &Path, source: &Path) -> Result<PathBuf, String> {
    let app = bundle(path).ok_or("Не найден бандл для переноса служебных файлов")?;
    let directory = create_transactions(app, path)?;
    let archive = tempfile::Builder::new()
        .prefix("recovered-")
        .tempdir_in(directory)
        .map_err(|error| error.to_string())?;
    fs::rename(source, archive.path().join("original")).map_err(|error| error.to_string())?;
    Ok(archive.keep())
}

/// Remove finished transactions and archives next to `app`, then the
/// directory itself once it is empty. A transaction without `COMMITTED` is
/// never touched: it is what recovers an interrupted write. A finished one
/// is kept while its saved old file is still open by another process.
/// Deleting a name never deletes data that is reachable under another name.
pub(crate) fn prune_transactions(app: &Path) {
    let directory = transactions(app);
    let Ok(entries) = fs::read_dir(&directory) else {
        return;
    };
    for entry in entries.flatten() {
        let is_dir = entry
            .file_type()
            .is_ok_and(|kind| kind.is_dir() && !kind.is_symlink());
        if is_dir && finished_transaction(&entry.path()) {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
    let _ = fs::remove_dir(&directory);
}

fn finished_transaction(dir: &Path) -> bool {
    // `recovered-*/original` holds a transaction moved out of an old bundle.
    let archived = dir.join("original");
    let root = if archived.is_dir() {
        archived
    } else {
        dir.to_path_buf()
    };
    if !root.join("COMMITTED").is_file() {
        return false;
    }
    let captured = root.join("captured");
    !captured.exists()
        || super::file_lock::holders(&[captured]).is_ok_and(|holders| holders.is_empty())
}

/// Translate a recovery marker without following a symlink into another
/// installation. The caller still checks the target name and file format.
pub(crate) fn pending_target(app: &Path, marker: &[u8]) -> Option<PathBuf> {
    let relative = Path::new(OsStr::from_bytes(marker));
    if relative.as_os_str().is_empty()
        || !relative
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return None;
    }
    let target = fs::canonicalize(app).ok()?.join(relative);
    (resolved_file(&target).ok()? == target).then_some(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pruning_keeps_pending_transactions_and_removes_the_empty_directory() {
        let root = tempfile::tempdir().unwrap();
        let app = root.path().join("Antigravity.app");
        fs::create_dir_all(app.join("Contents/Resources/bin")).unwrap();
        let directory = transactions(&app);
        let done = directory.join(".language_server.ag-transaction-done");
        let pending = directory.join(".language_server.ag-transaction-pending");
        let archived = directory.join("recovered-old/original");
        for dir in [&done, &pending, &archived] {
            fs::create_dir_all(dir).unwrap();
        }
        fs::write(
            done.join("PENDING"),
            b"Contents/Resources/bin/language_server",
        )
        .unwrap();
        fs::write(done.join("COMMITTED"), b"complete").unwrap();
        fs::write(
            pending.join("PENDING"),
            b"Contents/Resources/bin/language_server",
        )
        .unwrap();
        fs::write(pending.join("captured"), b"original").unwrap();
        fs::write(archived.join("COMMITTED"), b"destination preserved").unwrap();

        prune_transactions(&app);
        assert!(!done.exists());
        assert!(!directory.join("recovered-old").exists());
        assert_eq!(fs::read(pending.join("captured")).unwrap(), b"original");

        fs::remove_dir_all(&pending).unwrap();
        prune_transactions(&app);
        assert!(!directory.exists());
        // Nothing to clean is not an error.
        prune_transactions(&app);
    }
}
