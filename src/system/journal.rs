//! Exact, content-addressed backups. A changed upstream file is never overwritten on rollback.
use super::fs_utils::{guarded_write_file, recover_pending};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Serialize, Deserialize)]
struct Record {
    schema: u32,
    original: String,
    modified: String,
    #[serde(default)]
    previous: Option<String>,
    existed: bool,
    profile: String,
    #[serde(default)]
    snapshots: bool,
}

pub fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn directory(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".ag-backups");
    path.with_file_name(name)
}
fn record_path(path: &Path) -> PathBuf {
    directory(path).join("current.json")
}

pub fn apply(
    path: &Path,
    before: Option<&[u8]>,
    after: &[u8],
    profile: &str,
) -> Result<(), String> {
    apply_impl(path, before, after, profile, false)
}

/// Upgrade an existing patch without silently backing up partial patched bytes
/// if its journal disappears or no longer describes the current executable.
pub fn apply_continuing(
    path: &Path,
    before: &[u8],
    after: &[u8],
    profile: &str,
) -> Result<(), String> {
    apply_impl(path, Some(before), after, profile, true)
}

fn apply_impl(
    path: &Path,
    before: Option<&[u8]>,
    after: &[u8],
    profile: &str,
    require_continuation: bool,
) -> Result<(), String> {
    let current = read_optional(path)?;
    if current.as_deref() != before {
        return Err("Файл изменён другим процессом; повторите проверку".into());
    }
    let dir = directory(path);
    super::fs_utils::create_private_directory(&dir)?;
    let old_bytes = read_optional(&record_path(path))?;
    let old_record = old_bytes
        .as_ref()
        .map(|bytes| parse_record(bytes))
        .transpose()?;
    let continuation = old_record.as_ref().filter(|r| {
        current.as_ref().is_some_and(|b| {
            let hash = digest(b);
            hash == r.modified || r.previous.as_ref() == Some(&hash)
        })
    });
    if require_continuation && continuation.is_none() {
        return Err("Журнал прежнего патча недоступен или изменён; обновление отменено".into());
    }
    let original = continuation
        .map(|r| r.original.clone())
        .unwrap_or_else(|| digest(before.unwrap_or_default()));
    let backup = dir.join(format!("{original}.bin"));
    if !backup.exists() && continuation.is_none() {
        guarded_write_file(&backup, None, Some(before.unwrap_or_default()))?;
    }
    if digest(&fs::read(&backup).map_err(|e| e.to_string())?) != original {
        return Err("Повреждена резервная копия; запись отменена".into());
    }
    let snapshots = profile.ends_with("jsonc");
    if snapshots {
        save_snapshot(path, after)?;
        if let Some(before) = before {
            save_snapshot(path, before)?;
        }
    }
    if continuation.is_none() {
        if let Some(old_bytes) = &old_bytes {
            archive_record(path, old_bytes)?;
        }
    }
    let record = Record {
        schema: 1,
        original,
        modified: digest(after),
        previous: continuation.map(|_| digest(before.unwrap_or_default())),
        existed: continuation.map(|r| r.existed).unwrap_or(before.is_some()),
        profile: profile.into(),
        snapshots,
    };
    // A crash before replacement is recoverable: restore accepts either hash.
    guarded_write_file(
        &record_path(path),
        old_bytes.as_deref(),
        Some(&serde_json::to_vec_pretty(&record).map_err(|e| e.to_string())?),
    )?;
    if read_optional(path)?.as_deref() != before {
        return Err("Файл изменился во время подготовки backup".into());
    }
    guarded_write_file(path, before, Some(after))
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, String> {
    recover_pending(path)?;
    match fs::read(path) {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn load_record(path: &Path) -> Result<Option<Record>, String> {
    read_optional(&record_path(path))?
        .map(|bytes| parse_record(&bytes))
        .transpose()
}

fn original_bytes(path: &Path, record: &Record) -> Result<Vec<u8>, String> {
    let bytes = fs::read(directory(path).join(format!("{}.bin", record.original)))
        .map_err(|e| format!("Backup недоступен: {e}"))?;
    if digest(&bytes) != record.original {
        return Err("Хеш backup не совпадает; откат отменён".into());
    }
    Ok(bytes)
}

/// Outer None: no journal. Inner None: the managed file did not exist.
pub fn read_original(path: &Path) -> Result<Option<Option<Vec<u8>>>, String> {
    let Some(record) = load_record(path)? else {
        return Ok(None);
    };
    let bytes = original_bytes(path, &record)?;
    Ok(Some(record.existed.then_some(bytes)))
}

pub fn record_profile(path: &Path) -> Result<Option<String>, String> {
    Ok(load_record(path)?.map(|r| r.profile))
}

pub fn recorded_modified_hash(path: &Path) -> Result<Option<String>, String> {
    Ok(load_record(path)?.map(|r| r.modified))
}

fn save_snapshot(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let snapshot = directory(path).join(format!("{}.applied.bin", digest(bytes)));
    match read_optional(&snapshot)? {
        Some(existing) if existing == bytes => Ok(()),
        Some(_) => Err("Повреждена копия применённых настроек".into()),
        None => guarded_write_file(&snapshot, None, Some(bytes)),
    }
}

/// Latest applied settings first, then an interrupted predecessor. Legacy
/// schema-1 journals without applied snapshots return an empty vector.
pub fn read_modified(path: &Path) -> Result<Option<Vec<Vec<u8>>>, String> {
    let Some(record) = load_record(path)? else {
        return Ok(None);
    };
    if !record.snapshots {
        return Ok(Some(Vec::new()));
    }
    let mut snapshots = Vec::new();
    for hash in std::iter::once(&record.modified).chain(record.previous.iter()) {
        let bytes = fs::read(directory(path).join(format!("{hash}.applied.bin")))
            .map_err(|e| format!("Копия применённых настроек недоступна: {e}"))?;
        if digest(&bytes) != *hash {
            return Err("Повреждена копия применённых настроек".into());
        }
        snapshots.push(bytes);
    }
    Ok(Some(snapshots))
}

pub fn verified_original(path: &Path, expected: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let Some(record) = load_record(path)? else {
        return Ok(None);
    };
    let hash = digest(expected);
    if !record.existed || (hash != record.modified && record.previous.as_ref() != Some(&hash)) {
        return Err("Журнал не соответствует текущему файлу; исходная копия не применена".into());
    }
    Ok(Some(original_bytes(path, &record)?))
}

fn archive_record(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let archive = directory(path).join(format!("{}.record.json", digest(bytes)));
    match read_optional(&archive)? {
        Some(existing) if existing == bytes => Ok(()),
        Some(_) => Err("Архив журнала повреждён".into()),
        None => guarded_write_file(&archive, None, Some(bytes)),
    }
}

/// Retire a restored/superseded journal while retaining all exact backups.
pub fn retire(path: &Path, expected: Option<&[u8]>) -> Result<(), String> {
    if read_optional(path)?.as_deref() != expected {
        return Err("Файл изменён во время завершения отката; журнал сохранён".into());
    }
    let Some(record_bytes) = read_optional(&record_path(path))? else {
        return Ok(());
    };
    parse_record(&record_bytes)?;
    archive_record(path, &record_bytes)?;
    if read_optional(path)?.as_deref() != expected {
        return Err("Файл обновлён во время завершения отката; журнал сохранён".into());
    }
    guarded_write_file(&record_path(path), Some(&record_bytes), None)
}

fn parse_record(bytes: &[u8]) -> Result<Record, String> {
    let record: Record =
        serde_json::from_slice(bytes).map_err(|e| format!("Журнал повреждён: {e}"))?;
    if record.schema != 1
        || [&record.original, &record.modified]
            .into_iter()
            .chain(record.previous.iter())
            .any(|s| s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err("Неподдерживаемый журнал backup".into());
    }
    Ok(record)
}
pub fn has_record(path: &Path) -> bool {
    record_path(path).is_file()
}

pub fn verify_recorded_file(path: &Path) -> Result<bool, String> {
    let Some(bytes) = read_optional(&record_path(path))? else {
        return Ok(false);
    };
    let record = parse_record(&bytes)?;
    let current = read_optional(path)?;
    if current.as_ref().is_some_and(|bytes| {
        let hash = digest(bytes);
        hash == record.modified
            || hash == record.original
            || record.previous.as_ref() == Some(&hash)
    }) || (!record.existed && current.is_none())
    {
        Ok(true)
    } else {
        Err(format!(
            "{} изменён после настройки; пользовательские изменения сохранены",
            path.display()
        ))
    }
}

/// Preserve legacy configuration before removing a known override. This is an
/// archive, not an active patch record: another rollback must not reapply it.
pub fn archive_legacy(path: &Path, bytes: &[u8]) -> Result<PathBuf, String> {
    if read_optional(path)?.as_deref() != Some(bytes) {
        return Err("Настройки изменились; очистка отменена".into());
    }
    let dir = directory(path);
    super::fs_utils::create_private_directory(&dir)?;
    let backup = dir.join(format!("legacy-{}.bin", digest(bytes)));
    if !backup.exists() {
        guarded_write_file(&backup, None, Some(bytes))?;
    }
    if fs::read(&backup).map_err(|e| e.to_string())? != bytes {
        return Err("Архив старых настроек повреждён; очистка отменена".into());
    }
    Ok(backup)
}

pub fn restore(path: &Path) -> Result<bool, String> {
    restore_with(path, || {})
}

fn restore_with(path: &Path, before_commit: impl FnOnce()) -> Result<bool, String> {
    let Some(bytes) = read_optional(&record_path(path))? else {
        return Ok(false);
    };
    let record = parse_record(&bytes)?;
    let current = read_optional(path)?;
    if (record.existed
        && current
            .as_ref()
            .is_some_and(|b| digest(b) == record.original))
        || (!record.existed && current.is_none())
    {
        retire(path, current.as_deref())?;
        return Ok(true);
    }
    if !current.as_ref().is_some_and(|b| {
        let hash = digest(b);
        hash == record.modified || record.previous.as_ref() == Some(&hash)
    }) {
        return Err("Файл обновлён/отредактирован после патча; старая копия не применена".into());
    }
    let backup = original_bytes(path, &record)?;
    let after = record.existed.then_some(backup.as_slice());
    before_commit();
    guarded_write_file(path, current.as_deref(), after)?;
    retire(path, after)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn updater_during_rollback_keeps_new_version_and_original_journal() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("app.exe");
        fs::write(&p, b"stock v1").unwrap();
        apply(&p, Some(b"stock v1"), b"patched v1", "cli").unwrap();
        let record = fs::read(record_path(&p)).unwrap();
        assert!(restore_with(&p, || {
            fs::write(&p, b"stock v2").unwrap();
        })
        .is_err());
        assert_eq!(fs::read(&p).unwrap(), b"stock v2");
        assert_eq!(fs::read(record_path(&p)).unwrap(), record);
        assert_eq!(read_original(&p).unwrap(), Some(Some(b"stock v1".to_vec())));
    }
    #[test]
    fn new_file_rollback_does_not_delete_a_concurrent_user_file() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("settings.json");
        apply(&p, None, b"managed", "settings-jsonc").unwrap();
        assert!(restore_with(&p, || {
            fs::write(&p, b"user preferences").unwrap();
        })
        .is_err());
        assert_eq!(fs::read(&p).unwrap(), b"user preferences");
        assert!(has_record(&p));
    }
    #[test]
    fn updated_version_rebases_and_archives_previous_record_without_losing_backups() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("app");
        fs::write(&p, b"v1").unwrap();
        apply(&p, Some(b"v1"), b"patched v1", "cli").unwrap();
        let record = fs::read(record_path(&p)).unwrap();
        fs::write(&p, b"v2").unwrap();
        apply(&p, Some(b"v2"), b"patched v2", "cli").unwrap();
        assert_eq!(
            fs::read(directory(&p).join(format!("{}.record.json", digest(&record)))).unwrap(),
            record
        );
        assert_eq!(
            fs::read(directory(&p).join(format!("{}.bin", digest(b"v1")))).unwrap(),
            b"v1"
        );
        restore(&p).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"v2");
        assert!(!has_record(&p));
    }
    #[test]
    fn applied_jsonc_snapshots_are_validated_and_legacy_record_remains_readable() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("settings.json");
        apply(&p, None, b"first", "settings-jsonc").unwrap();
        apply(&p, Some(b"first"), b"second", "settings-jsonc").unwrap();
        assert_eq!(
            read_modified(&p).unwrap(),
            Some(vec![b"second".to_vec(), b"first".to_vec()])
        );
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(record_path(&p)).unwrap()).unwrap();
        value.as_object_mut().unwrap().remove("snapshots");
        fs::write(record_path(&p), serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(read_modified(&p).unwrap(), Some(Vec::new()));
        assert_eq!(read_original(&p).unwrap(), Some(None));
        restore(&p).unwrap();
        assert!(!p.exists());
    }
    #[test]
    fn repeated_edits_keep_original_baseline_and_failed_write_is_recoverable() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("settings.json");
        fs::write(&p, b"original").unwrap();
        apply(&p, Some(b"original"), b"first", "settings").unwrap();
        apply(&p, Some(b"first"), b"second", "settings").unwrap();
        // Simulate a crash after the second journal write, before file replacement.
        fs::write(&p, b"first").unwrap();
        restore(&p).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"original");
    }

    #[test]
    fn required_continuation_rejects_missing_or_unrelated_record_without_writing() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("app");
        fs::write(&p, b"partial").unwrap();
        assert!(apply_continuing(&p, b"partial", b"complete", "v2").is_err());
        assert_eq!(fs::read(&p).unwrap(), b"partial");
        assert!(!has_record(&p));
        apply(&p, Some(b"partial"), b"old recorded bytes", "v1").unwrap();
        fs::write(&p, b"other partial").unwrap();
        let record = fs::read(record_path(&p)).unwrap();
        assert!(apply_continuing(&p, b"other partial", b"complete", "v2").is_err());
        assert_eq!(fs::read(&p).unwrap(), b"other partial");
        assert_eq!(fs::read(record_path(&p)).unwrap(), record);
    }

    #[test]
    fn required_continuation_keeps_baseline_and_recovers_predecessor_hash() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("app");
        fs::write(&p, b"stock").unwrap();
        apply(&p, Some(b"stock"), b"partial", "v1").unwrap();
        apply_continuing(&p, b"partial", b"complete", "v2").unwrap();
        fs::write(&p, b"partial").unwrap();
        apply_continuing(&p, b"partial", b"complete", "v2").unwrap();
        let record = parse_record(&fs::read(record_path(&p)).unwrap()).unwrap();
        assert_eq!(record.original, digest(b"stock"));
        assert_eq!(record.previous, Some(digest(b"partial")));
        restore(&p).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"stock");
    }
    #[test]
    fn rollback_rejects_updated_binary_and_preserves_backup() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("app");
        fs::write(&p, b"v1").unwrap();
        apply(&p, Some(b"v1"), b"patched v1", "test").unwrap();
        fs::write(&p, b"v2").unwrap();
        assert!(restore(&p).is_err());
        assert_eq!(fs::read(&p).unwrap(), b"v2");
        assert!(has_record(&p));
        apply(&p, Some(b"v2"), b"patched v2", "test").unwrap();
        restore(&p).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"v2");
    }
    #[test]
    fn corruption_and_concurrent_changes_never_overwrite_file() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("app");
        fs::write(&p, b"original").unwrap();
        assert!(apply(&p, Some(b"stale"), b"patched", "test").is_err());
        apply(&p, Some(b"original"), b"patched", "test").unwrap();
        fs::write(
            directory(&p).join(format!("{}.bin", digest(b"original"))),
            b"wrong",
        )
        .unwrap();
        assert!(restore(&p).is_err());
        assert_eq!(fs::read(&p).unwrap(), b"patched");
    }
    #[test]
    fn new_file_is_removed_and_original_bytes_roundtrip() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("settings.json");
        apply(&p, None, b"new", "settings").unwrap();
        restore(&p).unwrap();
        assert!(!p.exists());
        fs::write(&p, b"// comment\r\n{}").unwrap();
        apply(&p, Some(b"// comment\r\n{}"), b"changed", "settings").unwrap();
        restore(&p).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"// comment\r\n{}");
    }
}
