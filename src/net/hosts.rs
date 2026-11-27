#![allow(dead_code)]

use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

const START_MARK: &str = "# BEGIN ANTIGRAVITY-BYPASS-RUSSIA";
const END_MARK: &str = "# END ANTIGRAVITY-BYPASS-RUSSIA";

pub fn hosts_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        PathBuf::from(root)
            .join("System32")
            .join("drivers")
            .join("etc")
            .join("hosts")
    }
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/etc/hosts")
    }
}

pub fn write_entries(entries: &[(String, Ipv4Addr)]) -> Result<(), String> {
    let path = hosts_path();
    if write_entries_at(&path, entries)? {
        log_repair(&path);
    }
    Ok(())
}

fn log_repair(path: &Path) {
    super::relay::log_event(&format!(
        "Блок hosts был повреждён и восстановлен; прежний файл сохранён в {}",
        backup_path(path).display()
    ));
}

fn backup_path(path: &Path) -> PathBuf {
    path.with_file_name("hosts.antigravity-bypass.bak")
}

/// Returns whether damaged block boundaries were repaired (a backup was saved).
fn write_entries_at(p: &Path, entries: &[(String, Ipv4Addr)]) -> Result<bool, String> {
    // Windows hosts can contain legacy-encoded comments. Only our ASCII block
    // needs parsing; decoding the complete file would reject or change user bytes.
    let original = match fs::read(p) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(format!("Чтение hosts: {e}")),
    };

    let (stripped, repaired) = strip_or_repair(p, &original)?;
    let mut block = String::new();
    block.push_str(START_MARK);
    block.push('\n');
    for (host, ip) in entries {
        block.push_str(&format!("{} {}\n", ip, host));
    }
    block.push_str(END_MARK);
    block.push('\n');

    // Prepending needs no separator added to the user's bytes, even without
    // an existing final newline. Rollback removes exactly our complete block.
    let mut combined = block.into_bytes();
    combined.extend_from_slice(&stripped);
    if combined == original {
        return Ok(false);
    }

    safe_write_hosts(p, &original, &combined)?;
    Ok(repaired)
}

pub fn remove_entries() -> Result<(), String> {
    let path = hosts_path();
    if remove_entries_at(&path)? {
        log_repair(&path);
    }
    Ok(())
}

/// Returns whether damaged block boundaries were repaired (a backup was saved).
fn remove_entries_at(p: &Path) -> Result<bool, String> {
    let original = match fs::read(p) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(format!("Чтение hosts: {e}")),
    };
    let (stripped, repaired) = strip_or_repair(p, &original)?;
    if stripped != original {
        safe_write_hosts(p, &original, &stripped)?;
    }
    Ok(repaired)
}

/// Strips our block. If its boundaries are damaged (a lone, repeated or
/// unterminated marker, e.g. after an interrupted edit or a manual change),
/// repairs conservatively: drops marker lines and only those lines inside a
/// marked region that look like our pins (an IP followed by Google hosts).
/// Every other line is kept byte-for-byte. The original file is saved next
/// to `hosts` first; without that backup nothing is written.
fn strip_or_repair(path: &Path, original: &[u8]) -> Result<(Vec<u8>, bool), String> {
    let error = match strip_block(original) {
        Ok(stripped) => return Ok((stripped, false)),
        Err(error) => error,
    };
    let repaired = repair_block(original);
    fs::write(backup_path(path), original)
        .map_err(|e| format!("{error}; резервную копию hosts сохранить не удалось: {e}"))?;
    Ok((repaired, true))
}

fn repair_block(text: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let mut in_block = false;
    for line in text.split_inclusive(|byte| *byte == b'\n') {
        let trimmed = line.trim_ascii();
        if trimmed == START_MARK.as_bytes() {
            in_block = true;
        } else if trimmed == END_MARK.as_bytes() {
            in_block = false;
        } else if !(in_block && is_google_pin_line(trimmed)) {
            result.extend_from_slice(line);
        }
    }
    result
}

fn is_google_pin_line(line: &[u8]) -> bool {
    let Ok(line) = std::str::from_utf8(line) else {
        return false;
    };
    let mut fields = line.split_ascii_whitespace();
    if fields
        .next()
        .and_then(|ip| ip.parse::<std::net::IpAddr>().ok())
        .is_none()
    {
        return false;
    }
    let mut hosts = fields.peekable();
    hosts.peek().is_some()
        && hosts.all(|host| {
            let host = super::route_health::host_name(host);
            ["googleapis.com", "google.com"]
                .iter()
                .any(|domain| host == *domain || host.ends_with(&format!(".{domain}")))
        })
}

pub fn owned_entries() -> Result<Vec<(String, Ipv4Addr)>, String> {
    match fs::read(hosts_path()) {
        Ok(bytes) => parse_owned_entries(&bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(format!("Чтение hosts: {e}")),
    }
}

/// Hosts from `required` that already appear anywhere in `hosts` (active lines).
/// Used when `hosts` cannot be written due to antivirus/permissions: Windows
/// gives `hosts` precedence over NRPT, so NRPT fallback is safe only when none
/// of the required Agent hosts are already pinned in `hosts`.
#[cfg(any(windows, test))]
pub fn conflicting_entries(required: &[&str]) -> Result<Vec<String>, String> {
    conflicting_entries_at(&hosts_path(), required)
}

#[cfg(any(windows, test))]
fn conflicting_entries_at(path: &Path, required: &[&str]) -> Result<Vec<String>, String> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("Чтение hosts: {e}")),
    };
    let mut found = Vec::new();
    for line in bytes.split(|byte| *byte == b'\n') {
        let mut fields = line
            .split(|byte| *byte == b'#')
            .next()
            .unwrap_or_default()
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|field| !field.is_empty());
        let Some(ip_bytes) = fields.next() else {
            continue;
        };
        if std::str::from_utf8(ip_bytes)
            .ok()
            .and_then(|s| s.parse::<std::net::IpAddr>().ok())
            .is_none()
        {
            continue;
        }
        for host_bytes in fields {
            let Ok(host) = std::str::from_utf8(host_bytes) else {
                continue;
            };
            let normalized = super::route_health::host_name(host);
            if required.iter().any(|want| *want == normalized) && !found.contains(&normalized) {
                found.push(normalized);
            }
        }
    }
    Ok(found)
}

fn parse_owned_entries(text: &[u8]) -> Result<Vec<(String, Ipv4Addr)>, String> {
    strip_block(text)?; // Refuse damaged boundaries rather than guessing ownership.
    let mut entries = Vec::new();
    let mut inside = false;
    for line in text.split(|byte| *byte == b'\n') {
        match line.trim_ascii() {
            marker if marker == START_MARK.as_bytes() => inside = true,
            marker if marker == END_MARK.as_bytes() => inside = false,
            _ if inside => {
                let mut fields = line
                    .split(|byte| *byte == b'#')
                    .next()
                    .unwrap_or_default()
                    .split(|byte| byte.is_ascii_whitespace())
                    .filter(|field| !field.is_empty());
                let Some(ip) = fields
                    .next()
                    .and_then(|ip| std::str::from_utf8(ip).ok())
                    .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
                else {
                    continue;
                };
                for host in fields {
                    let Ok(host) = std::str::from_utf8(host) else {
                        continue;
                    };
                    let host = super::route_health::host_name(host);
                    if !super::provider::NRPT_AGENT.contains(&host.as_str()) {
                        continue;
                    }
                    if entries
                        .iter()
                        .any(|(name, previous)| name == &host && previous != &ip)
                    {
                        return Err(format!("Неоднозначные адреса {host} в блоке hosts"));
                    }
                    if !entries.contains(&(host.clone(), ip)) {
                        entries.push((host, ip));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(entries)
}

fn strip_block(text: &[u8]) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();
    let mut in_block = false;
    for line in text.split_inclusive(|byte| *byte == b'\n') {
        match line.trim_ascii() {
            marker if marker == START_MARK.as_bytes() && !in_block => in_block = true,
            marker if marker == END_MARK.as_bytes() && in_block => in_block = false,
            marker if marker == START_MARK.as_bytes() || marker == END_MARK.as_bytes() => {
                return Err("Повреждены границы блока hosts; файл сохранён".into())
            }
            _ if !in_block => result.extend_from_slice(line),
            _ => {}
        }
    }
    if in_block {
        return Err("Нет конца блока hosts; файл сохранён".into());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_unambiguous_owned_agent_entries_can_identify_a_refused_route() {
        let unmanaged = "192.0.2.9 cloudcode-pa.googleapis.com\n";
        assert!(parse_owned_entries(unmanaged.as_bytes())
            .unwrap()
            .is_empty());
        let text = format!("{unmanaged}{START_MARK}\n192.0.2.1 CLOUDCODE-PA.GOOGLEAPIS.COM # keep\n192.0.2.2 unrelated.test\n{END_MARK}\n");
        assert_eq!(
            parse_owned_entries(text.as_bytes()).unwrap(),
            vec![(
                "cloudcode-pa.googleapis.com".into(),
                "192.0.2.1".parse().unwrap()
            )]
        );
        let conflicting = text.replace(
            END_MARK,
            &format!("192.0.2.3 cloudcode-pa.googleapis.com\n{END_MARK}"),
        );
        assert!(parse_owned_entries(conflicting.as_bytes()).is_err());
        assert!(parse_owned_entries(text.replace(END_MARK, "").as_bytes()).is_err());
    }

    #[test]
    fn stale_hosts_update_preserves_concurrent_edit_on_every_platform() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        fs::write(&path, "user changed this").unwrap();
        assert!(safe_write_hosts(&path, b"old", b"replacement").is_err());
        assert_eq!(fs::read_to_string(path).unwrap(), "user changed this");
    }
    #[test]
    fn removing_owned_block_preserves_unmanaged_bytes_and_user_additions() {
        for original in [
            "# user\r\n127.0.0.1 localhost\r\n",
            "# user without final newline",
            "",
        ] {
            let text = format!("{START_MARK}\n127.0.0.2 example.com\n{END_MARK}\n{original}");
            assert_eq!(strip_block(text.as_bytes()).unwrap(), original.as_bytes());
            assert_eq!(
                strip_block(original.as_bytes()).unwrap(),
                original.as_bytes()
            );
        }
        assert!(strip_block(format!("{START_MARK}\n# user lines").as_bytes()).is_err());
        assert!(strip_block(END_MARK.as_bytes()).is_err());
    }

    #[test]
    fn legacy_encoded_hosts_roundtrip_and_preserve_later_user_additions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        // CP1251 Cyrillic, a CRLF line and no final newline must survive exactly.
        let unmanaged = b"# \xcf\xf0\xee\xe2\xe5\xf0\xea\xe0\r\n127.0.0.1 localhost";
        fs::write(&path, unmanaged).unwrap();
        let entries = vec![(
            "daily-cloudcode-pa.googleapis.com".into(),
            "192.0.2.1".parse().unwrap(),
        )];
        write_entries_at(&path, &entries).unwrap();
        let applied = fs::read(&path).unwrap();
        assert!(applied.ends_with(unmanaged));
        assert_eq!(parse_owned_entries(&applied).unwrap(), entries);
        write_entries_at(&path, &entries).unwrap();
        assert_eq!(fs::read(&path).unwrap(), applied);

        let addition = b"\r\n# \xe4\xee\xe1\xe0\xe2\xeb\xe5\xed\xee\r\n192.0.2.9 custom.test\r\n";
        let mut later = applied;
        later.extend_from_slice(addition);
        fs::write(&path, later).unwrap();
        remove_entries_at(&path).unwrap();
        assert_eq!(
            fs::read(&path).unwrap(),
            [unmanaged.as_slice(), addition.as_slice()].concat()
        );
        remove_entries_at(&path).unwrap();
        assert!(parse_owned_entries(&fs::read(&path).unwrap())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn damaged_boundaries_are_repaired_with_backup_and_keep_user_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        let user = b"# \xcf\xf0\xee\xe2\xe5\xf0\xea\xe0\r\n127.0.0.1 localhost\r\n".as_slice();
        let entries = [(
            "cloudcode-pa.googleapis.com".to_string(),
            "192.0.2.1".parse().unwrap(),
        )];
        let nested = format!(
            "{START_MARK}\n5.175.161.3 aicode.googleapis.com\n{START_MARK}\n\
             172.217.114.4 CLOUDCODE-PA.GOOGLEAPIS.COM\n{END_MARK}\n"
        );
        let unterminated =
            format!("{START_MARK}\n45.131.64.204 daily-cloudcode-pa.googleapis.com\n");
        let damaged = [
            // Lone markers (interrupted edit).
            [user, START_MARK.as_bytes()].concat(),
            [user, END_MARK.as_bytes(), b"\n"].concat(),
            // Repeated START with stale pins (issue #58).
            [nested.as_bytes(), user].concat(),
            // Unterminated block followed by a user line.
            [user, unterminated.as_bytes(), b"10.0.0.5 nas.local\r\n"].concat(),
        ];
        for bytes in damaged {
            assert!(parse_owned_entries(&bytes).is_err());
            fs::write(&path, &bytes).unwrap();
            assert!(write_entries_at(&path, &entries).unwrap());
            assert_eq!(fs::read(backup_path(&path)).unwrap(), bytes);
            let applied = fs::read(&path).unwrap();
            assert_eq!(parse_owned_entries(&applied).unwrap(), entries);
            let text = String::from_utf8_lossy(&applied);
            for stale in ["172.217.114.4", "5.175.161.3", "45.131.64.204"] {
                assert!(!text.contains(stale), "{stale}");
            }
            assert!(applied.windows(user.len()).any(|window| window == user));
            assert_eq!(
                bytes.ends_with(b"nas.local\r\n"),
                text.contains("10.0.0.5 nas.local")
            );

            fs::write(&path, &bytes).unwrap();
            assert!(remove_entries_at(&path).unwrap());
            let removed = fs::read(&path).unwrap();
            assert!(parse_owned_entries(&removed).unwrap().is_empty());
            assert!(!String::from_utf8_lossy(&removed).contains("ANTIGRAVITY-BYPASS-RUSSIA"));
        }
    }

    #[test]
    fn damaged_boundaries_without_backup_are_not_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        let bytes = format!("127.0.0.1 localhost\n{END_MARK}\n");
        fs::write(&path, &bytes).unwrap();
        // A directory in place of the backup file makes the backup fail.
        fs::create_dir(backup_path(&path)).unwrap();
        let error = remove_entries_at(&path).unwrap_err();
        assert!(error.contains("резервную копию"), "{error}");
        assert_eq!(fs::read_to_string(&path).unwrap(), bytes);
    }

    #[cfg(windows)]
    #[test]
    fn removes_owned_entries_when_windows_denies_replacement() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        let unmanaged = "127.0.0.1 localhost\r\n# other application's entries\r\n";
        let original = format!("{START_MARK}\n127.0.0.2 example.com\n{END_MARK}\n{unmanaged}");
        fs::write(&path, &original).unwrap();
        // A reader that shares writes but not deletion reproduces the failure.
        let _reader = fs::OpenOptions::new()
            .read(true)
            .share_mode(3)
            .open(&path)
            .unwrap();
        assert!(crate::system::fs_utils::robust_write_file(&path, unmanaged.as_bytes()).is_err());
        assert_eq!(fs::read(&path).unwrap(), original.as_bytes());
        safe_write_hosts(&path, original.as_bytes(), unmanaged.as_bytes()).unwrap();
        assert_eq!(fs::read(&path).unwrap(), unmanaged.as_bytes());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(windows)]
    #[test]
    fn fallback_preserves_concurrent_changes_and_refuses_active_writers() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        fs::write(&path, b"user addition").unwrap();
        assert!(write_hosts_in_place(&path, b"stale content", b"replacement").is_err());
        let _writer = fs::OpenOptions::new()
            .write(true)
            .share_mode(3)
            .open(&path)
            .unwrap();
        assert!(safe_write_hosts(&path, b"user addition", b"replacement").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"user addition");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(windows)]
    #[test]
    fn readonly_hosts_is_updated_and_restores_readonly_on_success_and_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        let original = "127.0.0.1 localhost\r\n";
        fs::write(&path, original).unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(&path, perms).unwrap();

        let entries = vec![(
            "daily-cloudcode-pa.googleapis.com".into(),
            "45.131.64.204".parse().unwrap(),
        )];
        write_entries_at(&path, &entries).unwrap();
        assert!(fs::metadata(&path).unwrap().permissions().readonly());
        assert_eq!(
            parse_owned_entries(&fs::read(&path).unwrap()).unwrap(),
            entries
        );

        // Stale expectation fails before writing and still preserves readonly.
        assert!(safe_write_hosts(&path, b"wrong", b"replacement").is_err());
        assert!(fs::metadata(&path).unwrap().permissions().readonly());

        // Cleanup tempdir cleanly.
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_readonly(false);
        fs::set_permissions(&path, perms).unwrap();
    }

    #[test]
    fn conflicting_entries_detects_active_agent_pins_and_ignores_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        fs::write(
            &path,
            "# 1.2.3.4 daily-cloudcode-pa.googleapis.com\n127.0.0.1 localhost\n",
        )
        .unwrap();
        assert!(
            conflicting_entries_at(&path, &["daily-cloudcode-pa.googleapis.com"])
                .unwrap()
                .is_empty()
        );

        fs::write(
            &path,
            "127.0.0.1 localhost\n5.175.161.3 AICODE.GOOGLEAPIS.COM # stale\n",
        )
        .unwrap();
        assert_eq!(
            conflicting_entries_at(
                &path,
                &["daily-cloudcode-pa.googleapis.com", "aicode.googleapis.com"]
            )
            .unwrap(),
            vec!["aicode.googleapis.com"]
        );
    }
}

#[cfg(windows)]
struct ReadOnlyGuard<'a> {
    path: &'a Path,
    was_readonly: bool,
    cleared: bool,
}

#[cfg(windows)]
impl<'a> ReadOnlyGuard<'a> {
    fn acquire(path: &'a Path) -> Self {
        let was_readonly = fs::metadata(path)
            .map(|meta| meta.permissions().readonly())
            .unwrap_or(false);
        let cleared = if was_readonly {
            fs::metadata(path).ok().is_some_and(|meta| {
                let mut perms = meta.permissions();
                perms.set_readonly(false);
                fs::set_permissions(path, perms).is_ok()
            })
        } else {
            false
        };
        Self {
            path,
            was_readonly,
            cleared,
        }
    }
}

#[cfg(windows)]
impl Drop for ReadOnlyGuard<'_> {
    fn drop(&mut self) {
        if self.cleared {
            if let Ok(meta) = fs::metadata(self.path) {
                let mut perms = meta.permissions();
                perms.set_readonly(true);
                let _ = fs::set_permissions(self.path, perms);
            }
        }
    }
}

fn safe_write_hosts(path: &Path, _expected: &[u8], data: &[u8]) -> Result<(), String> {
    let current = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && _expected.is_empty() => vec![],
        Err(e) => return Err(e.to_string()),
    };
    if current != _expected {
        return Err("hosts изменён другой программой; повторите операцию".into());
    }
    #[cfg(windows)]
    let readonly = ReadOnlyGuard::acquire(path);
    let result = crate::system::fs_utils::robust_write_file(path, data);
    #[cfg(windows)]
    if let Err(atomic_error) = result {
        return write_hosts_in_place(path, _expected, data).map_err(|e| {
            let note = if readonly.was_readonly && !readonly.cleared {
                " (обнаружен атрибут «только чтение», снять не удалось)"
            } else if readonly.was_readonly {
                " (на файле был атрибут «только чтение»)"
            } else {
                ""
            };
            format!("{atomic_error}. Обновление hosts на месте: {e}{note}")
        });
    }
    result
}

/// Windows can allow writing hosts while denying replacement of its directory
/// entry. Keep its identity/ACL and a flushed recovery copy before modifying it.
/// This fallback is deliberately restricted to hosts, not application binaries.
#[cfg(windows)]
fn write_hosts_in_place(path: &Path, expected: &[u8], data: &[u8]) -> Result<(), String> {
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::windows::fs::OpenOptionsExt;

    // Allow readers but exclude other writers/deletion throughout read and write.
    // No truncate on open: a failed open must leave the original untouched.
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(1) // FILE_SHARE_READ
        .open(path)
        .map_err(|e| e.to_string())?;
    let mut original = Vec::new();
    file.read_to_end(&mut original).map_err(|e| e.to_string())?;
    if original != expected {
        return Err("hosts изменён другой программой; повторите операцию".into());
    }
    let mut backup = tempfile::Builder::new()
        .prefix("hosts.antigravity-recovery-")
        .tempfile_in(path.parent().unwrap_or_else(|| Path::new(".")))
        .map_err(|e| e.to_string())?;
    backup.write_all(&original).map_err(|e| e.to_string())?;
    backup.as_file().sync_all().map_err(|e| e.to_string())?;
    let (backup_file, backup_path) = backup.keep().map_err(|e| e.to_string())?;
    drop(backup_file);

    let mut replace = |bytes: &[u8]| -> std::io::Result<()> {
        file.seek(SeekFrom::Start(0))?;
        file.write_all(bytes)?;
        file.set_len(bytes.len() as u64)?;
        file.sync_all()
    };
    if let Err(error) = replace(data) {
        let restored = replace(&original);
        return Err(format!(
            "{error}; восстановление исходного файла: {}; резервная копия: {}",
            match restored {
                Ok(()) => "выполнено".to_string(),
                Err(e) => e.to_string(),
            },
            backup_path.display()
        ));
    }
    let _ = fs::remove_file(backup_path);
    Ok(())
}
