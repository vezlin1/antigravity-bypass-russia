//! Content-checked replacement without clobbering an updater's new pathname.
//! The old file is claimed before publication; failed/interrupted transactions
//! retain it. Unix recovery copies also retain writes through old open FDs.
use std::{
    ffi::OsStr,
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

fn prefix(path: &Path) -> String {
    format!(
        ".{}.ag-transaction-",
        path.file_name().unwrap_or_default().to_string_lossy()
    )
}

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn bytes(file: &mut fs::File) -> Result<Vec<u8>, String> {
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).map_err(|e| e.to_string())?;
    Ok(data)
}

fn open_locked(path: &Path) -> Result<fs::File, String> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::{
            Foundation::GENERIC_READ,
            Storage::FileSystem::{DELETE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ},
        };
        // Permit readers, prohibit writes and renames until this handle closes.
        // DELETE access lets us rename our own handle without releasing it.
        options
            .access_mode(GENERIC_READ | DELETE)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|e| {
        format!(
            "Не захватить {} для записи: {e}. Закройте приложение и обновление, затем повторите",
            path.display()
        )
    })?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file()
        || fs::symlink_metadata(path)
            .map_err(|e| e.to_string())?
            .file_type()
            .is_symlink()
    {
        return Err("Цель записи не является обычным файлом".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(format!(
                "Файл занят другой операцией: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(file)
}

#[cfg(windows)]
fn rename_handle(file: &fs::File, destination: &Path) -> Result<(), String> {
    use std::os::windows::{ffi::OsStrExt, io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        FileRenameInfo, SetFileInformationByHandle, FILE_RENAME_INFO,
    };
    let absolute = fs::canonicalize(parent(destination))
        .map_err(|e| e.to_string())?
        .join(destination.file_name().ok_or("Нет имени файла")?);
    let name: Vec<u16> = absolute.as_os_str().encode_wide().collect();
    // Reserve a terminating UTF-16 NUL too. The Win32 wrapper may normalize
    // the DOS path before handing the length-delimited name to the kernel.
    let length = std::mem::offset_of!(FILE_RENAME_INFO, FileName) + (name.len() + 1) * 2;
    let mut buffer = vec![0usize; length.div_ceil(std::mem::size_of::<usize>())];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    unsafe {
        (*info).Anonymous.ReplaceIfExists = false;
        (*info).RootDirectory = std::ptr::null_mut();
        (*info).FileNameLength = (name.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            name.len(),
        );
        if SetFileInformationByHandle(
            file.as_raw_handle(),
            FileRenameInfo,
            info.cast(),
            length as u32,
        ) == 0
        {
            return Err(format!(
                "{} ({} -> {})",
                std::io::Error::last_os_error(),
                absolute.display(),
                destination.display()
            ));
        }
    }
    Ok(())
}

fn claim(file: &fs::File, path: &Path, destination: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        let _ = path;
        rename_handle(file, destination)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file.metadata().map_err(|e| e.to_string())?;
        let named = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if opened.dev() != named.dev() || opened.ino() != named.ino() {
            return Err("Файл заменён другим процессом; операция отменена".into());
        }
        // An updater can still rename between this check and our rename. The
        // captured pathname is revalidated AFTER the move, before publication.
        fs::rename(path, destination).map_err(|e| e.to_string())
    }
}

fn restore_claim(path: &Path, captured: &Path, file: &fs::File) -> Result<(), String> {
    #[cfg(windows)]
    {
        let _ = captured;
        rename_handle(file, path)
    }
    #[cfg(unix)]
    {
        let _ = file;
        // link fails if anyone has already created the destination. In
        // particular, it must never overwrite a freshly installed executable.
        fs::hard_link(captured, path).map_err(|e| e.to_string())
    }
}

fn mark_finished(directory: &Path, status: &[u8]) -> Result<(), String> {
    let marker = directory.join("COMMITTED");
    #[cfg(target_os = "macos")]
    let marker = fs::File::create_new(marker);
    #[cfg(not(target_os = "macos"))]
    let marker = fs::File::create(marker);
    let mut marker = marker.map_err(|e| e.to_string())?;
    marker.write_all(status).map_err(|e| e.to_string())?;
    marker.sync_all().map_err(|e| e.to_string())
}

fn file_marker(path: &Path) -> &OsStr {
    path.file_name().unwrap_or_default()
}

pub(super) fn recover_pending(path: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    if let Some(app) = super::macos_app::bundle(path) {
        let directory = super::macos_app::transactions(app);
        let relative = path.strip_prefix(app).map_err(|error| error.to_string())?;
        if super::macos_app::transaction_directory_exists(&directory)? {
            recover_from(
                path,
                &directory,
                relative.as_os_str().as_encoded_bytes(),
                false,
            )?;
        }
    }
    recover_from(
        path,
        parent(path),
        file_marker(path).to_string_lossy().as_bytes(),
        true,
    )
}

fn recover_from(
    path: &Path,
    directory: &Path,
    expected_marker: &[u8],
    adjacent: bool,
) -> Result<(), String> {
    let exists = match fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e.to_string()),
    };
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.to_string()),
    };
    let _ = adjacent;
    let mut pending = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        if !entry
            .file_name()
            .to_string_lossy()
            .starts_with(&prefix(path))
            || !entry.file_type().map_err(|e| e.to_string())?.is_dir()
        {
            continue;
        }
        let dir = entry.path();
        let pending_marker = dir.join("PENDING");
        if !fs::symlink_metadata(&pending_marker)
            .is_ok_and(|m| m.is_file() && !m.file_type().is_symlink())
            || fs::read(&pending_marker).ok().as_deref() != Some(expected_marker)
        {
            continue;
        }
        let captured = dir.join("captured");
        if fs::symlink_metadata(&captured).is_ok_and(|m| m.is_file() && !m.file_type().is_symlink())
        {
            if dir.join("COMMITTED").exists() {
                #[cfg(target_os = "macos")]
                if adjacent {
                    archive_bundle_capture(path, &dir, &captured, exists)?;
                }
                continue;
            }
            if exists {
                // Finish interrupted publication without touching the existing
                // destination; later user deletion must not revive old bytes.
                #[cfg(target_os = "macos")]
                if adjacent {
                    super::macos_app::check_write_access(path)?;
                }
                mark_finished(&dir, b"destination preserved")?;
                #[cfg(target_os = "macos")]
                if adjacent {
                    archive_bundle_capture(path, &dir, &captured, exists)?;
                }
            } else {
                pending.push(captured);
            }
        }
    }
    if pending.len() > 1 {
        return Err("Несколько незавершённых записей: сохранённые файлы требуют проверки".into());
    }
    if let Some(captured) = pending.pop() {
        #[cfg(target_os = "macos")]
        if adjacent {
            super::macos_app::check_write_access(&captured)?;
        }
        match fs::hard_link(&captured, path) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => {
                return Err(format!(
                    "Восстановите сохранённый файл {}: {e}",
                    captured.display()
                ))
            }
        }
        let dir = captured.parent().ok_or("Нет каталога восстановления")?;
        mark_finished(dir, b"recovered")?;
        #[cfg(target_os = "macos")]
        if adjacent {
            archive_bundle_capture(path, dir, &captured, true)?;
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn archive_bundle_capture(
    path: &Path,
    directory: &Path,
    captured: &Path,
    target_exists: bool,
) -> Result<(), String> {
    use super::macos_app;
    if macos_app::bundle(path).is_none() {
        return Ok(());
    }
    macos_app::check_write_access(if target_exists { path } else { captured })?;
    macos_app::archive_legacy(path, directory)
        .map_err(|error| format!("Не удалось вынести журнал восстановления из приложения: {error}"))
}

pub(super) fn replace(
    path: &Path,
    expected: Option<&[u8]>,
    after: Option<&[u8]>,
) -> Result<(), String> {
    replace_with(path, expected, after, |_| {})
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Prepared,
    Claimed,
    Publish,
    Cleanup,
}

fn replace_with(
    path: &Path,
    expected: Option<&[u8]>,
    after: Option<&[u8]>,
    mut hook: impl FnMut(Stage),
) -> Result<(), String> {
    recover_pending(path)?;
    let name = file_marker(path).to_string_lossy();
    let (staging, marker) = (parent(path).to_path_buf(), name.as_bytes());
    #[cfg(target_os = "macos")]
    let (staging, marker) = if let Some(app) = super::macos_app::bundle(path) {
        (
            super::macos_app::create_transactions(app, path)?,
            path.strip_prefix(app)
                .map_err(|error| error.to_string())?
                .as_os_str()
                .as_encoded_bytes(),
        )
    } else {
        (staging, marker)
    };
    // Complete expensive preparation before claiming the target pathname.
    let replacement = after
        .map(|data| super::fs_utils::prepared_file_in(path, data, &staging))
        .transpose()?;
    hook(Stage::Prepared);
    let Some(expected) = expected else {
        if fs::symlink_metadata(path).is_ok() {
            return Err("Файл появился после проверки; запись отменена".into());
        }
        if let Some(replacement) = replacement {
            replacement
                .persist_noclobber(path)
                .map_err(|e| format!("Файл появился или запись недоступна: {}", e.error))?;
        }
        return Ok(());
    };
    let mut source = open_locked(path)?;
    if bytes(&mut source)? != expected {
        return Err("Файл изменён другим процессом; запись отменена".into());
    }
    let transaction = tempfile::Builder::new()
        .prefix(&prefix(path))
        .tempdir_in(&staging)
        .map_err(|e| e.to_string())?;
    let mut pending =
        fs::File::create(transaction.path().join("PENDING")).map_err(|e| e.to_string())?;
    super::fs_utils::inherit_directory_owner(transaction.path())?;
    pending.write_all(marker).map_err(|e| e.to_string())?;
    pending.sync_all().map_err(|e| e.to_string())?;
    drop(pending);
    let dir: PathBuf = transaction.keep();
    let captured = dir.join("captured");
    if let Err(error) = claim(&source, path, &captured) {
        let _ = fs::remove_file(dir.join("PENDING"));
        let _ = fs::remove_dir(&dir);
        return Err(format!(
            "Не переместить файл для безопасной записи: {error}"
        ));
    }
    // Leave the transaction durable even on panic/process exit.
    hook(Stage::Claimed);
    let result: Result<(), String> = (|| {
        #[cfg(target_os = "macos")]
        {
            super::file_lock::wait_for_other_holders(&[captured.clone()])?;
        }
        #[cfg(unix)]
        {
            if fs::read(&captured).map_err(|e| e.to_string())? != expected {
                return Err("Во время захвата установлена другая версия; запись отменена".into());
            }
        }
        if bytes(&mut source)? != expected {
            return Err("Файл изменился во время подготовки записи".into());
        }
        hook(Stage::Publish);
        if let Some(replacement) = replacement {
            replacement.persist_noclobber(path).map_err(|e| {
                format!(
                    "Новая версия появилась во время записи; она сохранена ({})",
                    e.error
                )
            })?;
        } else if fs::symlink_metadata(path).is_ok() {
            return Err("Файл обновлён во время удаления; новая версия сохранена".into());
        }
        #[cfg(unix)]
        if fs::read(&captured).map_err(|e| e.to_string())? != expected {
            return Err("Запись через прежний открытый файл обнаружена; сохранённая версия требует проверки".into());
        }
        Ok(())
    })();
    if let Err(error) = result {
        let recovery = restore_claim(path, &captured, &source).err();
        if fs::symlink_metadata(path).is_ok() {
            // An ordinary conflict/abort is no longer a crash-recovery task.
            // Later user deletion must not resurrect this old captured file.
            mark_finished(&dir, b"aborted")?;
        }
        // A failed recovery means the updater's destination stays untouched.
        return Err(format!(
            "{error}. Сохранённый файл: {}{}",
            captured.display(),
            recovery
                .map(|e| format!("; восстановление без перезаписи: {e}"))
                .unwrap_or_default()
        ));
    }
    mark_finished(&dir, b"complete")?;
    drop(source);
    hook(Stage::Cleanup);
    #[cfg(windows)]
    let cleanup = true;
    #[cfg(all(unix, not(target_os = "macos")))]
    let cleanup = false;
    #[cfg(target_os = "macos")]
    let cleanup = {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(&captured).is_ok_and(|m| m.nlink() == 1)
            && super::file_lock::holders(&[captured.clone()])
                .is_ok_and(|holders| holders.is_empty())
            && fs::read(&captured).is_ok_and(|data| data == expected)
    };
    if cleanup && fs::remove_file(&captured).is_ok() {
        // Windows sharing excluded all writers to the captured handle.
        let _ = fs::remove_file(dir.join("PENDING"));
        let _ = fs::remove_file(dir.join("COMMITTED"));
        let _ = fs::remove_dir(&dir);
    }
    // Retain uncertain Unix captures, including aliases/open descriptors, so
    // a late in-place update is recoverable. Conflicted captures are never pruned.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn update_during_preparation_is_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app");
        fs::write(&path, b"patched").unwrap();
        assert!(
            replace_with(&path, Some(b"patched"), Some(b"stock"), |stage| {
                if stage == Stage::Prepared {
                    fs::write(&path, b"new version").unwrap();
                }
            })
            .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), b"new version");
    }
    #[test]
    fn update_in_commit_window_is_never_overwritten() {
        for after in [Some(b"stock".as_slice()), None] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("app");
            fs::write(&path, b"patched").unwrap();
            assert!(replace_with(&path, Some(b"patched"), after, |stage| {
                if stage == Stage::Publish {
                    fs::write(&path, b"new version").unwrap();
                }
            })
            .is_err());
            assert_eq!(fs::read(&path).unwrap(), b"new version");
            assert!(fs::read_dir(dir.path())
                .unwrap()
                .flatten()
                .any(|e| e.path().join("captured").is_file()));
        }
    }
    #[test]
    fn interrupted_claim_recovers_without_overwriting_an_update() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app");
        fs::write(&path, b"patched").unwrap();
        assert!(std::panic::catch_unwind(|| replace_with(
            &path,
            Some(b"patched"),
            Some(b"stock"),
            |stage| {
                if stage == Stage::Claimed {
                    panic!("simulated interruption");
                }
            }
        ))
        .is_err());
        assert!(!path.exists());
        recover_pending(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"patched");
        fs::write(&path, b"new version").unwrap();
        recover_pending(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new version");
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn bundle_recovery_stages_outside_and_accepts_the_previous_layout() {
        for legacy in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let app = directory.path().join("IDE.app");
            let path = app.join("Contents/Resources/language_server");
            let parent = path.parent().unwrap();
            fs::create_dir_all(parent).unwrap();
            fs::write(&path, b"original").unwrap();
            if legacy {
                let stage = parent.join(".language_server.ag-transaction-legacy");
                fs::create_dir(&stage).unwrap();
                fs::write(stage.join("PENDING"), b"language_server").unwrap();
                fs::rename(&path, stage.join("captured")).unwrap();
            } else {
                let interrupted = std::panic::catch_unwind(|| {
                    replace_with(&path, Some(b"original"), Some(b"patched"), |stage| {
                        if stage == Stage::Claimed {
                            assert_eq!(fs::read_dir(parent).unwrap().count(), 0);
                            panic!("simulated interruption");
                        }
                    })
                });
                assert!(interrupted.is_err());
            }
            assert!(!path.exists());
            recover_pending(&path).unwrap();
            assert_eq!(fs::read(&path).unwrap(), b"original");
            assert_eq!(fs::read_dir(parent).unwrap().count(), 1);
        }
    }
    #[test]
    fn successful_replace_and_delete_are_exact() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app");
        replace(&path, None, Some(b"stock")).unwrap();
        replace(&path, Some(b"stock"), Some(b"patched")).unwrap();
        replace(&path, Some(b"patched"), Some(b"stock")).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"stock");
        replace(&path, Some(b"stock"), None).unwrap();
        recover_pending(&path).unwrap();
        assert!(!path.exists());
    }
    #[test]
    fn interrupted_transaction_with_existing_update_does_not_resurrect_it_later() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app");
        fs::write(&path, b"patched").unwrap();
        let _ = std::panic::catch_unwind(|| {
            replace_with(&path, Some(b"patched"), Some(b"stock"), |stage| {
                if stage == Stage::Claimed {
                    panic!("interrupted");
                }
            })
        });
        fs::write(&path, b"update").unwrap();
        recover_pending(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"update");
        fs::remove_file(&path).unwrap();
        recover_pending(&path).unwrap();
        assert!(!path.exists());
    }
    #[test]
    fn unrelated_transaction_marker_cannot_restore_another_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app");
        let transaction = dir.path().join(format!("{}fixture", prefix(&path)));
        fs::create_dir(&transaction).unwrap();
        fs::write(transaction.join("PENDING"), b"different application").unwrap();
        fs::write(transaction.join("captured"), b"unrelated bytes").unwrap();
        recover_pending(&path).unwrap();
        assert!(!path.exists());
        assert_eq!(
            fs::read(transaction.join("captured")).unwrap(),
            b"unrelated bytes"
        );
    }
    #[cfg(windows)]
    #[test]
    fn failed_cleanup_of_readonly_capture_keeps_commit_marker() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.exe");
        fs::write(&path, b"stock").unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        let writable_permissions = permissions.clone();
        permissions.set_readonly(true);
        fs::set_permissions(&path, permissions).unwrap();
        let mut reader = None;
        replace_with(&path, Some(b"stock"), Some(b"patched"), |stage| {
            if stage == Stage::Cleanup {
                let captured = fs::read_dir(dir.path())
                    .unwrap()
                    .flatten()
                    .find_map(|e| {
                        e.path()
                            .join("captured")
                            .is_file()
                            .then(|| e.path().join("captured"))
                    })
                    .unwrap();
                reader = Some(
                    fs::OpenOptions::new()
                        .read(true)
                        .share_mode(FILE_SHARE_READ)
                        .open(captured)
                        .unwrap(),
                );
            }
        })
        .unwrap();
        drop(reader);
        let transaction = fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .find_map(|e| e.path().join("captured").is_file().then(|| e.path()))
            .unwrap();
        assert!(transaction.join("COMMITTED").is_file());
        fs::set_permissions(&path, writable_permissions.clone()).unwrap();
        fs::remove_file(&path).unwrap();
        recover_pending(&path).unwrap();
        assert!(!path.exists());
        fs::set_permissions(transaction.join("captured"), writable_permissions).unwrap();
    }
    #[test]
    fn filenames_with_dots_spaces_and_unicode_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "agy.exe",
            "main.js",
            "current.json",
            "my app.exe",
            "настройки.json",
        ] {
            let path = dir.path().join(name);
            replace(&path, None, Some(b"original")).unwrap();
            replace(&path, Some(b"original"), Some(b"patched")).unwrap();
            replace(&path, Some(b"patched"), Some(b"original")).unwrap();
            assert_eq!(fs::read(&path).unwrap(), b"original");
        }
    }
    #[test]
    fn aborted_and_recovered_transactions_do_not_resurrect_user_deletions() {
        for interrupt in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("app");
            fs::write(&path, b"patched").unwrap();
            let _ = std::panic::catch_unwind(|| {
                replace_with(&path, Some(b"patched"), Some(b"stock"), |stage| {
                    if stage == Stage::Claimed && interrupt {
                        panic!("interrupted");
                    }
                    if stage == Stage::Publish {
                        fs::write(&path, b"update").unwrap();
                    }
                })
            });
            recover_pending(&path).unwrap();
            fs::remove_file(&path).unwrap();
            recover_pending(&path).unwrap();
            assert!(!path.exists());
        }
    }
    #[cfg(windows)]
    #[test]
    fn windows_claim_excludes_writes_through_other_handles() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app");
        fs::write(&path, b"patched").unwrap();
        replace_with(&path, Some(b"patched"), Some(b"stock"), |stage| {
            if stage == Stage::Claimed {
                let captured = fs::read_dir(dir.path())
                    .unwrap()
                    .flatten()
                    .find_map(|e| {
                        e.path()
                            .join("captured")
                            .is_file()
                            .then(|| e.path().join("captured"))
                    })
                    .unwrap();
                assert!(fs::write(captured, b"late update").is_err());
            }
        })
        .unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn late_in_place_writer_has_a_retained_inode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app");
        fs::write(&path, b"patched").unwrap();
        let mut updater = fs::OpenOptions::new().write(true).open(&path).unwrap();
        replace(&path, Some(b"patched"), Some(b"stock")).unwrap();
        updater.write_all(b"updated").unwrap();
        updater.sync_all().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"stock");
        let captured = fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .find_map(|e| {
                e.path()
                    .join("captured")
                    .is_file()
                    .then(|| e.path().join("captured"))
            })
            .unwrap();
        assert_eq!(fs::read(captured).unwrap(), b"updated");
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_refuses_an_updater_holding_the_claimed_inode() {
        use std::{
            process::{Command, Stdio},
            time::{Duration, Instant},
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app");
        let ready = dir.path().join("ready");
        fs::write(&path, b"patched").unwrap();
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            // Keep the holder alive until the parent terminates it. A fixed
            // sleep can expire while a loaded runner is still checking lsof.
            .arg("exec 3>>\"$1\"; printf ready > \"$2\"; exec /bin/cat")
            .arg("fixture")
            .arg(&path)
            .arg(&ready)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !ready.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let result = replace(&path, Some(b"patched"), Some(b"stock"));
        let _ = child.kill();
        let _ = child.wait();
        assert!(ready.exists());
        assert!(result.is_err());
        assert_eq!(fs::read(&path).unwrap(), b"patched");
    }
}
