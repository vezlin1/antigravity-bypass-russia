use crate::core::{
    detector::{is_agy_cli_name, FoundTarget, TargetKind},
    opcodes::*,
};
use crate::system::journal;
use object::{Architecture, Object, ObjectSection, SectionKind};
use std::{
    fs,
    path::Path,
    sync::{Mutex, MutexGuard},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryState {
    Patched,
    PartiallyPatched,
    Stock,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchOutcome {
    Changed(usize),
    AlreadyPatched,
    Restored,
    AlreadyStock,
    NotApplicable,
}
impl std::fmt::Display for PatchOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Changed(n) => write!(f, "Изменено {n} проверенных участков; backup сохранён"),
            Self::AlreadyPatched => write!(f, "Все поддерживаемые участки уже пропатчены"),
            Self::Restored => write!(f, "Точные исходные байты восстановлены"),
            Self::AlreadyStock => write!(f, "Исходное состояние; изменений нет"),
            Self::NotApplicable => write!(
                f,
                "Поддерживаемых участков патча нет; файл оставлен без изменений"
            ),
        }
    }
}
static OPERATIONS: Mutex<()> = Mutex::new(());
pub fn operation_guard() -> MutexGuard<'static, ()> {
    OPERATIONS.lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) struct Plan {
    pub data: Vec<u8>,
    pub changes: usize,
    pub existing: usize,
    pub profile: String,
}
pub(crate) fn state_from_counts(stock: usize, patched: usize) -> BinaryState {
    match (stock > 0, patched > 0) {
        (true, true) => BinaryState::PartiallyPatched,
        (true, false) => BinaryState::Stock,
        (false, true) => BinaryState::Patched,
        _ => BinaryState::Unknown,
    }
}
pub(crate) fn plan_js(data: &[u8]) -> Result<Plan, String> {
    let text = std::str::from_utf8(data).map_err(|_| "JavaScript не в UTF-8")?;
    let mut output = data.to_vec();
    let re = regex_ide_main_js_stock();
    let spans: Vec<_> = re
        .captures_iter(text)
        .map(|c| (c.get(1).unwrap().end(), c.get(0).unwrap().end()))
        .collect();
    let existing = regex_ide_js_patched().find_iter(text).count();
    for (start, end) in &spans {
        output[*start..*end].fill(b' ');
        output[*start..*start + 4].copy_from_slice(b"true");
    }
    Ok(Plan {
        data: output,
        changes: spans.len(),
        existing,
        profile: "ide-reset-tier-v1".into(),
    })
}

fn apply_pattern(
    bytes: &mut [u8],
    original: &regex::bytes::Regex,
    patched: &regex::bytes::Regex,
    fix: &[u8],
    fix_at: usize,
    max_matches: usize,
) -> Result<(usize, usize), String> {
    let offsets: Vec<_> = original.find_iter(bytes).map(|m| m.start()).collect();
    let existing = patched.find_iter(bytes).count();
    if offsets.len() + existing > max_matches {
        return Err("Неоднозначная машинная сигнатура; файл не изменён".into());
    }
    for offset in &offsets {
        let at = offset
            .checked_add(fix_at)
            .ok_or("Смещение патча переполнено")?;
        let end = at.checked_add(fix.len()).ok_or("Длина патча переполнена")?;
        let slot = bytes
            .get_mut(at..end)
            .ok_or("Патч выходит за пределы секции")?;
        slot.copy_from_slice(fix);
    }
    Ok((offsets.len(), existing))
}

fn cli_x64_branches_share_target(bytes: &[u8]) -> bool {
    if bytes.len() != 19 {
        return false;
    }
    let je = i32::from_le_bytes(bytes[5..9].try_into().unwrap());
    let jne = i32::from_le_bytes(bytes[15..19].try_into().unwrap());
    i64::from(je) == i64::from(jne) + 10
}

fn plan_binary(data: &[u8], kind: TargetKind) -> Result<Plan, String> {
    plan_binary_with_cli_profile(data, kind, false)
}

fn plan_binary_with_cli_profile(
    data: &[u8],
    kind: TargetKind,
    legacy_cli: bool,
) -> Result<Plan, String> {
    let file = object::File::parse(data)
        .map_err(|e| format!("Неподдерживаемый executable (PE/ELF/Mach-O): {e}"))?;
    let (original, patched, fix, fix_at, max_matches, profile) = match (kind, file.architecture()) {
        (TargetKind::LanguageServer, Architecture::X86_64) => (
            regex_mgr_x64_orig(),
            regex_mgr_x64_patched(),
            MGR_GATE_X64_FIX,
            0,
            1,
            "core-x64-v1",
        ),
        (TargetKind::LanguageServer, Architecture::Aarch64) => (
            regex_mgr_arm64_orig(),
            regex_mgr_arm64_patched(),
            MGR_GATE_ARM64_FIX,
            0,
            1,
            "core-arm64-v1",
        ),
        (TargetKind::AgyCli, Architecture::X86_64) if legacy_cli => (
            regex_cli_x64_long_orig(),
            regex_cli_x64_long_v1_patched(),
            CLI_GATE_X64_LONG_V1_FIX,
            0,
            1,
            "agy-x64-long-v1",
        ),
        (TargetKind::AgyCli, Architecture::X86_64) => (
            regex_cli_x64_long_orig(),
            regex_cli_x64_long_patched(),
            CLI_GATE_X64_LONG_FIX,
            CLI_GATE_X64_LONG_FIX_AT,
            2,
            "agy-x64-long-v2",
        ),
        (TargetKind::AgyCli, Architecture::Aarch64) => (
            regex_mgr_arm64_orig(),
            regex_mgr_arm64_patched(),
            MGR_GATE_ARM64_FIX,
            0,
            1,
            "agy-arm64-v1",
        ),
        _ => return Err("Нет профиля патча для этой архитектуры/компонента".into()),
    };
    let mut output = data.to_vec();
    let (mut changes, mut existing) = (0, 0);
    for section in file.sections().filter(|s| s.kind() == SectionKind::Text) {
        let Some((offset, size)) = section.file_range() else {
            continue;
        };
        let start = usize::try_from(offset).map_err(|_| "Некорректное смещение секции")?;
        let end = start
            .checked_add(usize::try_from(size).map_err(|_| "Некорректная секция")?)
            .ok_or("Переполнение секции")?;
        let section_bytes = output
            .get_mut(start..end)
            .ok_or("Секция за пределами файла")?;
        if kind == TargetKind::AgyCli
            && file.architecture() == Architecture::X86_64
            && !legacy_cli
            && original
                .find_iter(section_bytes)
                .chain(patched.find_iter(section_bytes))
                .any(|m| !cli_x64_branches_share_target(m.as_bytes()))
        {
            return Err("Переходы agy x64 ведут в разные адреса; файл не изменён".into());
        }
        let (c, p) = apply_pattern(section_bytes, original, patched, fix, fix_at, max_matches)?;
        changes += c;
        existing += p;
    }
    let total = changes + existing;
    if total == 0 || total > max_matches {
        return Err(format!(
            "Версия не поддерживается профилем {profile}: совпадений {}. SHA-256 {}",
            changes + existing,
            journal::digest(data)
        ));
    }
    Ok(Plan {
        data: output,
        changes,
        existing,
        profile: profile.into(),
    })
}

fn plan(data: &[u8], kind: TargetKind) -> Result<Plan, String> {
    match kind {
        TargetKind::IdeMainJs => plan_js(data),
        TargetKind::IdeAsar => crate::core::asar::plan_asar(data),
        _ => plan_binary(data, kind),
    }
}
fn inferred_kind(path: &Path) -> TargetKind {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    if name.ends_with(".asar") {
        TargetKind::IdeAsar
    } else if name.ends_with(".js") {
        TargetKind::IdeMainJs
    } else if is_agy_cli_name(&name) {
        TargetKind::AgyCli
    } else {
        TargetKind::LanguageServer
    }
}
pub fn check_binary_state(path: &Path) -> BinaryState {
    state_for_kind(path, inferred_kind(path))
}

pub fn check_target_state(target: &FoundTarget) -> BinaryState {
    state_for_kind(&target.path, target.kind)
}

fn state_for_kind(path: &Path, kind: TargetKind) -> BinaryState {
    let Ok(data) = fs::read(path) else {
        return BinaryState::Unknown;
    };
    match plan(&data, kind) {
        Ok(p) => state_from_counts(p.changes, p.existing),
        Err(_) => BinaryState::Unknown,
    }
}

fn ensure_file_closed(path: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let holders = crate::system::file_lock::holders(&[path.to_path_buf()])?;
        if !holders.is_empty() {
            return Err(format!(
                "Закройте Antigravity перед изменением файлов: {}",
                holders.join(", ")
            ));
        }
    }
    let _ = path;
    Ok(())
}

fn ensure_not_symlink(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "{} — символическая ссылка; укажите путь к исполняемому файлу, чтобы сохранить связь с обновлениями",
            path.display()
        ));
    }
    Ok(())
}

/// Signing is done on a temporary copy, before backup metadata and replacement.
fn prepare_for_write(path: &Path, data: Vec<u8>, kind: TargetKind) -> Result<Vec<u8>, String> {
    #[cfg(target_os = "macos")]
    if matches!(kind, TargetKind::LanguageServer | TargetKind::AgyCli) {
        use std::io::Write;
        let mut temp =
            tempfile::NamedTempFile::new_in(path.parent().unwrap()).map_err(|e| e.to_string())?;
        temp.write_all(&data).map_err(|e| e.to_string())?;
        let status = crate::system::command::output(
            "codesign",
            [
                "--force",
                "--sign",
                "-",
                "--preserve-metadata=entitlements,requirements,flags",
            ]
            .into_iter()
            .map(std::ffi::OsStr::new)
            .chain([temp.path().as_os_str()]),
        )
        .map_err(|e| e.to_string())?;
        if !status.status.success() {
            return Err(format!(
                "Не удалось подписать временную копию; оригинал сохранён: {}",
                String::from_utf8_lossy(&status.stderr).trim()
            ));
        }
        let verified = crate::system::command::output(
            "codesign",
            ["--verify", "--strict"]
                .into_iter()
                .map(std::ffi::OsStr::new)
                .chain([temp.path().as_os_str()]),
        )
        .map_err(|e| e.to_string())?;
        if !verified.status.success() {
            return Err(format!(
                "Подпись временной копии не прошла проверку: {}",
                String::from_utf8_lossy(&verified.stderr).trim()
            ));
        }
        return fs::read(temp.path()).map_err(|e| e.to_string());
    }
    let _ = (path, kind);
    Ok(data)
}

fn is_legacy_x64_cli(data: &[u8]) -> bool {
    if !regex_cli_x64_long_v1_patched().is_match(data) {
        return false;
    }
    plan_binary_with_cli_profile(data, TargetKind::AgyCli, true)
        .is_ok_and(|p| p.changes == 0 && p.existing == 1)
}

fn legacy_cli_backup_matches(original: &[u8], current: &[u8]) -> bool {
    plan_binary_with_cli_profile(original, TargetKind::AgyCli, true)
        .is_ok_and(|p| p.changes == 1 && p.existing == 0 && p.data == current)
}

fn legacy_backup_paths(path: &Path) -> Vec<std::path::PathBuf> {
    let mut paths = vec![path.with_extension("bak"), path.with_extension("original")];
    let mut appended = path.as_os_str().to_os_string();
    appended.push(".bak");
    paths.push(appended.into());
    paths
}

fn verified_legacy_cli_backup(path: &Path, current: &[u8]) -> Option<Vec<u8>> {
    legacy_backup_paths(path).into_iter().find_map(|backup| {
        let original = fs::read(backup).ok()?;
        legacy_cli_backup_matches(&original, current).then_some(original)
    })
}

pub fn patch_target(target: &FoundTarget) -> Result<PatchOutcome, String> {
    let _guard = operation_guard();
    ensure_not_symlink(&target.path)?;
    let mut before = fs::read(&target.path).map_err(|e| e.to_string())?;
    if target.kind == TargetKind::AgyCli && is_legacy_x64_cli(&before) {
        ensure_file_closed(&target.path)?;
        if journal::has_record(&target.path) {
            if !journal::restore(&target.path)? {
                return Err("Backup старого патча исчез; файл не изменён".into());
            }
        } else {
            let original = verified_legacy_cli_backup(&target.path, &before).ok_or(
                "Обнаружен старый патч agy-x64-long-v1, но точный исходный backup не найден; переустановите исходный agy",
            )?;
            if fs::read(&target.path).map_err(|e| e.to_string())? != before {
                return Err("Файл изменён другим процессом; повторите проверку".into());
            }
            crate::system::fs_utils::robust_write_file(&target.path, &original)?;
        }
        before = fs::read(&target.path).map_err(|e| e.to_string())?;
    }
    let p = plan(&before, target.kind)?;
    if p.changes == 0 {
        return if p.existing > 0 {
            Ok(PatchOutcome::AlreadyPatched)
        } else if matches!(target.kind, TargetKind::IdeAsar) {
            Ok(PatchOutcome::NotApplicable)
        } else {
            Err("Версия/сигнатура не поддерживается; файл не изменён".into())
        };
    }
    ensure_file_closed(&target.path)?;
    let after = prepare_for_write(&target.path, p.data, target.kind)?;
    journal::apply(&target.path, Some(&before), &after, &p.profile)?;
    Ok(PatchOutcome::Changed(p.changes))
}

pub fn restore_target(target: &FoundTarget) -> Result<PatchOutcome, String> {
    let _guard = operation_guard();
    ensure_not_symlink(&target.path)?;
    ensure_file_closed(&target.path)?;
    if journal::restore(&target.path)? {
        return Ok(PatchOutcome::Restored);
    }
    let before = fs::read(&target.path).map_err(|e| e.to_string())?;
    if matches!(target.kind, TargetKind::IdeAsar | TargetKind::IdeMainJs)
        && plan(&before, target.kind).is_ok_and(|p| p.changes == 0 && p.existing == 0)
    {
        return Ok(PatchOutcome::NotApplicable);
    }
    let current_state = plan(&before, target.kind)
        .map(|p| state_from_counts(p.changes, p.existing))
        .unwrap_or(BinaryState::Unknown);
    if current_state == BinaryState::Stock {
        return Ok(PatchOutcome::AlreadyStock);
    }
    // Legacy backups are accepted only when they reproduce the current bytes.
    for backup in legacy_backup_paths(&target.path) {
        if let Ok(original) = fs::read(&backup) {
            let current_matches = plan(&original, target.kind)
                .is_ok_and(|p| p.changes > 0 && p.existing == 0 && p.data == before);
            let old_cli_matches =
                target.kind == TargetKind::AgyCli && legacy_cli_backup_matches(&original, &before);
            if current_matches || old_cli_matches {
                crate::system::fs_utils::robust_write_file(&target.path, &original)?;
                return Ok(PatchOutcome::Restored);
            }
        }
    }
    Err("Нет backup, соответствующего текущей версии. Файл сохранён; восстановите точную версию приложения.".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn symlink_target_is_not_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.js");
        let link = dir.path().join("main.js");
        let original = b"x.resetIsTierGCPTos(),x.isGoogleInternal;";
        fs::write(&real, original).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let target = FoundTarget {
            path: link.clone(),
            kind: TargetKind::IdeMainJs,
            name: "main.js".into(),
        };
        assert!(patch_target(&target).is_err());
        assert!(restore_target(&target).is_err());
        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(&real).unwrap(), original);
    }
    #[test]
    fn unrelated_valid_asar_is_skipped_but_damaged_archive_is_not_called_restored() {
        let dir = tempfile::tempdir().unwrap();
        let target = FoundTarget {
            path: dir.path().join("app.asar"),
            kind: TargetKind::IdeAsar,
            name: "fixture".into(),
        };
        let header = b"{\"files\":{}}";
        let mut bytes = vec![];
        for value in [4u32, 20, 16, header.len() as u32] {
            bytes.extend(value.to_le_bytes());
        }
        bytes.extend(header);
        bytes.resize(28, 0);
        fs::write(&target.path, &bytes).unwrap();
        assert_eq!(patch_target(&target).unwrap(), PatchOutcome::NotApplicable);
        assert_eq!(
            restore_target(&target).unwrap(),
            PatchOutcome::NotApplicable
        );
        assert_eq!(fs::read(&target.path).unwrap(), bytes);
        fs::write(&target.path, b"broken archive").unwrap();
        assert!(restore_target(&target).is_err());
    }
    fn macho_fixture(code: &[u8], cpu: u32) -> Vec<u8> {
        let mut data = vec![0u8; 1024];
        // mach_header_64 + LC_SEGMENT_64 + one executable __text section.
        for (offset, value) in [
            (0, 0xfeedfacfu32),
            (4, cpu),
            (12, 2),
            (16, 1),
            (20, 152),
            (32, 0x19),
            (36, 152),
            (88, 7),
            (92, 5),
            (96, 1),
            (152, 512),
            (156, 2),
            (168, 0x80000400),
        ] {
            data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [(64, 1024u64), (80, 1024), (144, code.len() as u64)] {
            data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        data[40..46].copy_from_slice(b"__TEXT");
        data[104..110].copy_from_slice(b"__text");
        data[120..126].copy_from_slice(b"__TEXT");
        data[512..512 + code.len()].copy_from_slice(code);
        data
    }

    #[test]
    fn macho_core_profiles_support_both_architectures_and_reject_unknown_x64_cli() {
        let x64 = b"\x80\x78\x08\x00\x74\x0a\x48\x8b\x44\x24\x20\x48\x89\x44\x60";
        let arm64 = b"\x03\x20\x40\x39\x03\x00\x00\x36\x00\x00\x00\x00\x03\x10\x06\xa9";
        for (code, cpu) in [(x64.as_slice(), 0x01000007), (arm64.as_slice(), 0x0100000c)] {
            let original = macho_fixture(code, cpu);
            let patched = plan_binary(&original, TargetKind::LanguageServer).unwrap();
            assert_eq!((patched.changes, patched.existing), (1, 0));
            assert_eq!(&patched.data[..512], &original[..512]);
            let repeated = plan_binary(&patched.data, TargetKind::LanguageServer).unwrap();
            assert_eq!((repeated.changes, repeated.existing), (0, 1));
            assert_eq!(repeated.data, patched.data);
        }
        assert!(plan_binary(&macho_fixture(x64, 0x01000007), TargetKind::AgyCli).is_err());
        let cli = b"\x48\x85\xc0\x0f\x84\x0a\x00\x00\x00\x80\x78\x08\x00\x0f\x85\x00\x00\x00\x00";
        let patched = plan_binary(&macho_fixture(cli, 0x01000007), TargetKind::AgyCli).unwrap();
        assert_eq!((patched.changes, patched.existing), (1, 0));
        assert_eq!(&patched.data[512 + 9..512 + 13], b"\x90\x90\x90\x90");
        assert_eq!(&patched.data[512..512 + 9], &cli[..9]);
        let repeated = plan_binary(&patched.data, TargetKind::AgyCli).unwrap();
        assert_eq!((repeated.changes, repeated.existing), (0, 1));
    }

    #[test]
    fn x64_cli_patches_every_copy_of_the_same_gate() {
        let gate =
            b"\x48\x85\xc0\x0f\x84\x0a\x00\x00\x00\x80\x78\x08\x00\x0f\x85\x00\x00\x00\x00\x11\x22";
        let other =
            b"\x48\x85\xc0\x0f\x84\x22\x00\x00\x00\x80\x78\x08\x00\x0f\x85\x18\x00\x00\x00\x33\x44";
        let original = macho_fixture(&[gate.as_slice(), other.as_slice()].concat(), 0x01000007);
        let patched = plan_binary(&original, TargetKind::AgyCli).unwrap();
        assert_eq!(patched.profile, "agy-x64-long-v2");
        assert_eq!((patched.changes, patched.existing), (2, 0));
        assert_eq!(&patched.data[512 + 9..512 + 13], b"\x90\x90\x90\x90");
        assert_eq!(
            &patched.data[512 + 21 + 9..512 + 21 + 13],
            b"\x90\x90\x90\x90"
        );
        let again = plan_binary(&patched.data, TargetKind::AgyCli).unwrap();
        assert_eq!((again.changes, again.existing), (0, 2));
        assert_eq!(again.data, patched.data);
        let three = macho_fixture(
            &[gate.as_slice(), other.as_slice(), gate.as_slice()].concat(),
            0x01000007,
        );
        assert!(plan_binary(&three, TargetKind::AgyCli).is_err());
        let mut wrong_target = gate.to_vec();
        wrong_target[15] = 1;
        let error = plan_binary(
            &macho_fixture(&wrong_target, 0x01000007),
            TargetKind::AgyCli,
        )
        .err()
        .unwrap();
        assert!(error.contains("разные адреса"));
    }

    #[test]
    #[ignore = "set AGY_X64_FIXTURE to an extracted official agy binary"]
    fn official_x64_cli_fixture_has_two_gates() {
        let path = std::path::PathBuf::from(std::env::var("AGY_X64_FIXTURE").unwrap());
        let targets = crate::core::detector::find_targets_in_path(&path);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].kind, TargetKind::AgyCli);
        let stock = fs::read(path).unwrap();
        let patched = plan_binary(&stock, TargetKind::AgyCli).unwrap();
        assert_eq!((patched.changes, patched.existing), (2, 0));
        assert_eq!(
            stock
                .iter()
                .zip(&patched.data)
                .filter(|(a, b)| a != b)
                .count(),
            8
        );
        let repeated = plan_binary(&patched.data, TargetKind::AgyCli).unwrap();
        assert_eq!((repeated.changes, repeated.existing), (0, 2));
        assert_eq!(repeated.data, patched.data);
    }

    #[test]
    fn legacy_x64_cli_requires_an_exact_backup_to_restore() {
        let code = b"\x48\x85\xc0\x0f\x84\x0a\x00\x00\x00\x80\x78\x08\x00\x0f\x85\x00\x00\x00\x00";
        let stock = pe_fixture(code, 0x8664);
        let legacy = plan_binary_with_cli_profile(&stock, TargetKind::AgyCli, true)
            .unwrap()
            .data;
        let dir = tempfile::tempdir().unwrap();
        let target = FoundTarget {
            path: dir.path().join("agy.exe"),
            kind: TargetKind::AgyCli,
            name: "agy".into(),
        };
        fs::write(&target.path, &legacy).unwrap();
        fs::write(target.path.with_extension("bak"), b"wrong backup").unwrap();
        assert!(restore_target(&target).is_err());
        assert_eq!(fs::read(&target.path).unwrap(), legacy);
        fs::write(target.path.with_extension("bak"), &stock).unwrap();
        assert_eq!(restore_target(&target).unwrap(), PatchOutcome::Restored);
        assert_eq!(fs::read(&target.path).unwrap(), stock);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn legacy_x64_cli_migrates_from_verified_backup_and_restores_stock() {
        let code = b"\x48\x85\xc0\x0f\x84\x0a\x00\x00\x00\x80\x78\x08\x00\x0f\x85\x00\x00\x00\x00";
        let stock = pe_fixture(code, 0x8664);
        let legacy = plan_binary_with_cli_profile(&stock, TargetKind::AgyCli, true)
            .unwrap()
            .data;
        let dir = tempfile::tempdir().unwrap();
        let target = FoundTarget {
            path: dir.path().join("agy.exe"),
            kind: TargetKind::AgyCli,
            name: "agy".into(),
        };
        fs::write(&target.path, &legacy).unwrap();
        let error = patch_target(&target).unwrap_err();
        assert!(error.contains("agy-x64-long-v1"));
        assert_eq!(fs::read(&target.path).unwrap(), legacy);
        fs::write(target.path.with_extension("bak"), &stock).unwrap();
        assert_eq!(patch_target(&target).unwrap(), PatchOutcome::Changed(1));
        assert_eq!(patch_target(&target).unwrap(), PatchOutcome::AlreadyPatched);
        assert_eq!(restore_target(&target).unwrap(), PatchOutcome::Restored);
        assert_eq!(fs::read(&target.path).unwrap(), stock);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn legacy_x64_cli_migrates_through_journal() {
        let code = b"\x48\x85\xc0\x0f\x84\x0a\x00\x00\x00\x80\x78\x08\x00\x0f\x85\x00\x00\x00\x00";
        let stock = pe_fixture(code, 0x8664);
        let legacy = plan_binary_with_cli_profile(&stock, TargetKind::AgyCli, true)
            .unwrap()
            .data;
        let dir = tempfile::tempdir().unwrap();
        let target = FoundTarget {
            path: dir.path().join("agy.exe"),
            kind: TargetKind::AgyCli,
            name: "agy".into(),
        };
        fs::write(&target.path, &stock).unwrap();
        journal::apply(&target.path, Some(&stock), &legacy, "agy-x64-long-v1").unwrap();
        assert_eq!(patch_target(&target).unwrap(), PatchOutcome::Changed(1));
        assert_eq!(restore_target(&target).unwrap(), PatchOutcome::Restored);
        assert_eq!(fs::read(&target.path).unwrap(), stock);
    }

    #[test]
    fn macho_arm64_cli_patch_is_exact_and_idempotent() {
        // Exercise both supported instruction gaps and every TBZ immediate prefix.
        for branch in [0x03, 0x23, 0x43, 0x63, 0x83, 0xa3, 0xc3, 0xe3] {
            for gap in [1, 2] {
                let mut code = vec![0x03, 0x20, 0x40, 0x39, branch, 0x0a, 0x00, 0x36];
                for _ in 0..gap {
                    code.extend_from_slice(b"\x1f\x20\x03\xd5"); // NOP
                }
                code.extend_from_slice(b"\x03\x10\x06\xa9");
                let mut original = macho_fixture(&code, 0x0100000c);
                // A matching sequence outside __text must remain untouched.
                original[800..800 + code.len()].copy_from_slice(&code);
                let patched = plan_binary(&original, TargetKind::AgyCli).unwrap();
                assert_eq!(patched.profile, "agy-arm64-v1");
                assert_eq!((patched.changes, patched.existing), (1, 0));
                let mut expected = original;
                expected[512..520].copy_from_slice(b"\x23\x00\x80\x52\x03\x20\x00\x39");
                assert_eq!(patched.data, expected);
                let repeated = plan_binary(&patched.data, TargetKind::AgyCli).unwrap();
                assert_eq!((repeated.changes, repeated.existing), (0, 1));
                assert_eq!(repeated.data, patched.data);
            }
        }
    }

    #[test]
    fn macho_arm64_cli_rejects_missing_ambiguous_and_wrong_architecture_gates() {
        let code = b"\x03\x20\x40\x39\x03\x00\x00\x36\x1f\x20\x03\xd5\x03\x10\x06\xa9";
        let stock = macho_fixture(code, 0x0100000c);
        let patched = plan_binary(&stock, TargetKind::AgyCli).unwrap();
        let patched_code = &patched.data[512..512 + code.len()];
        for unsupported in [
            vec![0u8; code.len()],
            code[..code.len() - 1].to_vec(),
            [code.as_slice(), code.as_slice()].concat(),
            [code.as_slice(), patched_code].concat(),
            [patched_code, patched_code].concat(),
        ] {
            assert!(
                plan_binary(&macho_fixture(&unsupported, 0x0100000c), TargetKind::AgyCli).is_err()
            );
        }
        assert!(plan_binary(&macho_fixture(code, 0x01000007), TargetKind::AgyCli).is_err());
    }

    fn pe_fixture(code: &[u8], machine: u16) -> Vec<u8> {
        let mut data = vec![0u8; 1536];
        data[..2].copy_from_slice(b"MZ");
        data[60..64].copy_from_slice(&128u32.to_le_bytes());
        data[128..132].copy_from_slice(b"PE\0\0");
        for (offset, value) in [
            (132, machine),
            (134, 2),
            (148, 240),
            (150, 0x22),
            (152, 0x20b),
            (220, 3),
        ] {
            data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [
            (156, 512u32),
            (168, 0x1000),
            (172, 0x1000),
            (184, 0x1000),
            (188, 512),
            (208, 0x3000),
            (212, 512),
            (260, 16),
        ] {
            data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (section, name, raw, address, flags) in [
            (392, b".text\0\0\0", 512u32, 0x1000u32, 0x60000020u32),
            (432, b".rdata\0\0", 1024, 0x2000, 0x40000040),
        ] {
            data[section..section + 8].copy_from_slice(name);
            for (offset, value) in [(8, 512), (12, address), (16, 512), (20, raw), (36, flags)] {
                data[section + offset..section + offset + 4].copy_from_slice(&value.to_le_bytes());
            }
            data[raw as usize..raw as usize + code.len()].copy_from_slice(code);
        }
        data
    }
    #[test]
    fn pe_architecture_code_sections_and_exact_rollback() {
        let code = b"\x80\x78\x08\x00\x74\x0a\x48\x8b\x44\x24\x20\x48\x89\x44\x60";
        let original = pe_fixture(code, 0x8664);
        let p = plan_binary(&original, TargetKind::LanguageServer).unwrap();
        assert_eq!((p.changes, p.existing), (1, 0));
        assert_eq!(&p.data[1024..], &original[1024..]); // Identical marker in data is untouched.
        assert!(plan_binary(&pe_fixture(code, 0xaa64), TargetKind::LanguageServer).is_err());
        assert!(plan_binary(
            &pe_fixture(&[code.as_slice(), code.as_slice()].concat(), 0x8664),
            TargetKind::LanguageServer
        )
        .is_err());
        // Synthetic PE can be used for planner tests on every platform. A JS
        // target exercises filesystem transactions without invoking macOS signing.
        let dir = tempfile::tempdir().unwrap();
        let target = FoundTarget {
            path: dir.path().join("main.js"),
            kind: TargetKind::IdeMainJs,
            name: "fixture".into(),
        };
        let original = b"x.resetIsTierGCPTos(),x.isGoogleInternal;";
        fs::write(&target.path, original).unwrap();
        assert_eq!(patch_target(&target).unwrap(), PatchOutcome::Changed(1));
        assert_eq!(patch_target(&target).unwrap(), PatchOutcome::AlreadyPatched);
        assert_eq!(restore_target(&target).unwrap(), PatchOutcome::Restored);
        assert_eq!(fs::read(&target.path).unwrap(), original);
        assert_eq!(restore_target(&target).unwrap(), PatchOutcome::AlreadyStock);
    }
    #[test]
    fn binary_wildcards_match_linefeed_but_ambiguous_gates_are_rejected() {
        let bytes = b"\x48\x85\xc0\x0f\x84\x0a\x00\x00\x00\x80\x78\x08\x00\x0f\x85\x00\x00\x00\x00";
        assert!(regex_cli_x64_long_orig().is_match(bytes));
        let mut duplicate = [bytes.as_slice(), bytes.as_slice()].concat();
        assert!(apply_pattern(
            &mut duplicate,
            regex_cli_x64_long_orig(),
            regex_cli_x64_long_patched(),
            CLI_GATE_X64_LONG_FIX,
            CLI_GATE_X64_LONG_FIX_AT,
            1
        )
        .is_err());
        let (changes, existing) = apply_pattern(
            &mut duplicate,
            regex_cli_x64_long_orig(),
            regex_cli_x64_long_patched(),
            CLI_GATE_X64_LONG_FIX,
            CLI_GATE_X64_LONG_FIX_AT,
            2,
        )
        .unwrap();
        assert_eq!((changes, existing), (2, 0));
        assert_eq!(&duplicate[9..13], b"\x90\x90\x90\x90");
        assert_eq!(&duplicate[19 + 9..19 + 13], b"\x90\x90\x90\x90");
    }
    #[test]
    fn partial_js_is_completed_and_unrelated_text_is_unsupported() {
        let p = plan_js(b"x.resetIsTierGCPTos(),true; y.resetIsTierGCPTos(),y.isGoogleInternal")
            .unwrap();
        assert_eq!(
            state_from_counts(p.changes, p.existing),
            BinaryState::PartiallyPatched
        );
        let next = plan_js(&p.data).unwrap();
        assert_eq!((next.changes, next.existing), (0, 2));
        assert_eq!(plan_js(b"object.isGoogleInternal").unwrap().changes, 0);
    }
    #[test]
    fn raw_bytes_and_generic_cli_gate_do_not_authorize_a_binary_patch() {
        assert!(plan_binary(
            b"\x48\x85\xc0\x74\x0a\x48\x8b ineligible",
            TargetKind::AgyCli
        )
        .is_err());
    }
}
