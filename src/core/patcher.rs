use crate::core::{
    detector::{FoundTarget, TargetKind},
    opcodes::*,
};
use crate::system::journal;
use object::{Architecture, Object, ObjectSection, SectionKind};
use std::{
    borrow::Cow,
    collections::HashMap,
    fs,
    ops::Range,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
    time::SystemTime,
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

/// `data` borrows the input until the first byte is changed, so read-only
/// state checks of large executables never allocate a second full copy.
pub(crate) struct Plan<'a> {
    pub data: Cow<'a, [u8]>,
    pub changes: usize,
    pub existing: usize,
    pub profile: String,
}
impl Plan<'_> {
    fn into_owned(self) -> Plan<'static> {
        Plan {
            data: Cow::Owned(self.data.into_owned()),
            changes: self.changes,
            existing: self.existing,
            profile: self.profile,
        }
    }
}

/// Unsupported-version errors name the file digest. Hashing a 100 MB binary is
/// deferred until a caller actually reports the error to the user.
const DIGEST_PLACEHOLDER: &str = "{sha256}";

fn with_digest(error: String, data: &[u8]) -> String {
    if error.contains(DIGEST_PLACEHOLDER) {
        error.replace(DIGEST_PLACEHOLDER, &journal::digest(data))
    } else {
        error
    }
}

pub(crate) fn state_from_counts(stock: usize, patched: usize) -> BinaryState {
    match (stock > 0, patched > 0) {
        (true, true) => BinaryState::PartiallyPatched,
        (true, false) => BinaryState::Stock,
        (false, true) => BinaryState::Patched,
        _ => BinaryState::Unknown,
    }
}
/// `Apply` builds the patched bytes; `Count` only counts stock and patched
/// sites, so a status check never copies a large executable. Both run the same
/// format checks and return the same counts.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Apply,
    Count,
}

#[cfg(test)]
pub(crate) fn plan_js(data: &[u8]) -> Result<Plan<'_>, String> {
    plan_js_mode(data, Mode::Apply)
}

pub(crate) fn plan_js_mode(data: &[u8], mode: Mode) -> Result<Plan<'_>, String> {
    let text = std::str::from_utf8(data).map_err(|_| "JavaScript не в UTF-8")?;
    let mut output = Cow::Borrowed(data);
    let re = regex_ide_main_js_stock();
    let spans: Vec<_> = re
        .captures_iter(text)
        .map(|c| (c.get(1).unwrap().end(), c.get(0).unwrap().end()))
        .collect();
    let existing = regex_ide_js_patched().find_iter(text).count();
    for (start, end) in spans.iter().filter(|_| mode == Mode::Apply) {
        let output = output.to_mut();
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

fn section_range(start: u64, size: u64) -> Result<Range<usize>, String> {
    let start = usize::try_from(start).map_err(|_| "Некорректное смещение секции")?;
    let end = start
        .checked_add(usize::try_from(size).map_err(|_| "Некорректная секция")?)
        .ok_or("Переполнение секции")?;
    Ok(start..end)
}

fn section_bytes<'b>(output: &'b [u8], range: &Range<usize>) -> Result<&'b [u8], String> {
    output
        .get(range.clone())
        .ok_or_else(|| "Секция за пределами файла".into())
}

/// Stock offsets (relative to the section) and the number of patched sites.
type Sites = (Vec<usize>, usize);

fn pair_sites(
    bytes: &[u8],
    original: &regex::bytes::Regex,
    patched: &regex::bytes::Regex,
) -> Sites {
    (
        original.find_iter(bytes).map(|m| m.start()).collect(),
        patched.find_iter(bytes).count(),
    )
}

fn x64_manager_sites(bytes: &[u8]) -> Sites {
    pair_sites(bytes, regex_mgr_x64_orig(), regex_mgr_x64_patched())
}

/// Rewrites the stock sites of one section; the output is copied only when a
/// stock site is actually rewritten.
fn rewrite_sites(
    output: &mut Cow<'_, [u8]>,
    section_range: Range<usize>,
    (offsets, existing): Sites,
    fix: &[u8],
    fix_at: usize,
    max_matches: usize,
    mode: Mode,
) -> Result<(usize, usize), String> {
    if offsets.len() + existing > max_matches {
        return Err("Неоднозначная машинная сигнатура; файл не изменён".into());
    }
    if offsets.is_empty() || mode == Mode::Count {
        return Ok((offsets.len(), existing));
    }
    section_bytes(output, &section_range)?;
    let bytes = &mut output.to_mut()[section_range];
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

/// Searches the current bytes of the section, then rewrites its stock sites.
#[cfg(test)]
fn apply_pattern(
    output: &mut Cow<'_, [u8]>,
    section_range: Range<usize>,
    original: &regex::bytes::Regex,
    patched: &regex::bytes::Regex,
    fix: &[u8],
    fix_at: usize,
    max_matches: usize,
) -> Result<(usize, usize), String> {
    let sites = pair_sites(section_bytes(output, &section_range)?, original, patched);
    rewrite_sites(
        output,
        section_range,
        sites,
        fix,
        fix_at,
        max_matches,
        Mode::Apply,
    )
}

fn cli_x64_branches_share_target(bytes: &[u8]) -> bool {
    if bytes.len() != 19 {
        return false;
    }
    let je = i32::from_le_bytes(bytes[5..9].try_into().unwrap());
    let jne = i32::from_le_bytes(bytes[15..19].try_into().unwrap());
    i64::from(je) == i64::from(jne) + 10
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum X64GateState {
    Stock,
    Legacy,
    Patched,
}

type X64Gates = Vec<(usize, X64GateState)>;

/// Inspect all supported variants together. Looking only for stock/v2 misses
/// a v1 gate beside a stock gate and would back up a partially patched file.
fn x64_cli_gates(data: &[u8]) -> Result<Option<X64Gates>, String> {
    let file = object::File::parse(data).map_err(|e| e.to_string())?;
    x64_cli_gates_in(&file, data)
}

fn x64_cli_gates_in(file: &object::File<'_>, data: &[u8]) -> Result<Option<X64Gates>, String> {
    if file.architecture() != Architecture::X86_64 {
        return Ok(None);
    }
    let mut gates = Vec::new();
    for section in file.sections().filter(|s| s.kind() == SectionKind::Text) {
        let Some((start, size)) = section.file_range() else {
            continue;
        };
        let range = section_range(start, size)?;
        let start = range.start;
        let bytes = section_bytes(data, &range)?;
        // Separate searches: each variant has a long literal prefix for the
        // regex prefilter, which a combined pattern (`test rax, rax` only) lacks.
        for (pattern, state) in [
            (regex_cli_x64_long_orig(), X64GateState::Stock),
            (regex_cli_x64_long_v1_patched(), X64GateState::Legacy),
            (regex_cli_x64_long_patched(), X64GateState::Patched),
        ] {
            for m in pattern.find_iter(bytes) {
                if state != X64GateState::Legacy && !cli_x64_branches_share_target(m.as_bytes()) {
                    return Err("Переходы agy x64 ведут в разные адреса; файл не изменён".into());
                }
                gates.push((start + m.start(), state));
            }
        }
    }
    gates.sort_unstable_by_key(|(offset, _)| *offset);
    if !(1..=2).contains(&gates.len()) || gates.windows(2).any(|pair| pair[0].0 + 19 > pair[1].0) {
        return Err(format!(
            "Версия не поддерживается профилем agy-x64-long-v2: совпадений {}. SHA-256 {DIGEST_PLACEHOLDER}",
            gates.len(),
        ));
    }
    Ok(Some(gates))
}

fn x64_backend_cli_gate_in(
    file: &object::File<'_>,
    data: &[u8],
    diagnostic_gates: &[(usize, X64GateState)],
) -> Result<Option<(usize, X64GateState)>, String> {
    if file.architecture() != Architecture::X86_64 {
        return Ok(None);
    }
    let mut found = None;
    for section in file.sections().filter(|s| s.kind() == SectionKind::Text) {
        let Some((start, size)) = section.file_range() else {
            continue;
        };
        let range = section_range(start, size)?;
        let start = range.start;
        let bytes = section_bytes(data, &range)?;
        for (pattern, state) in [
            (regex_cli_x64_backend_orig(), X64GateState::Stock),
            (regex_cli_x64_backend_patched(), X64GateState::Patched),
        ] {
            for m in pattern.find_iter(bytes) {
                if found.is_some() {
                    return Err(
                        "Неоднозначная проверка входа agy x64 backend; файл не изменён".into(),
                    );
                }
                const ERROR_GUARD_LEN: usize = 9;
                const GATE_LEN: usize = 19;
                const MAX_HELPER_PROLOGUE: usize = 64;
                let code = m.as_bytes();
                let relative =
                    |at| i64::from(i32::from_le_bytes(code[at..at + 4].try_into().unwrap()));
                let error = m.start() as i64 + ERROR_GUARD_LEN as i64 + relative(5);
                let success = m.start() as i64 + 18 + relative(14);
                let helper = m.end() as i64 + relative(33);
                if !cli_x64_branches_share_target(
                    &code[ERROR_GUARD_LEN..ERROR_GUARD_LEN + GATE_LEN],
                ) || error < m.end() as i64
                    || success < m.end() as i64
                    || error == success
                    || error >= bytes.len() as i64
                    || success >= bytes.len() as i64
                    || helper < 0
                    || helper + GATE_LEN as i64 > bytes.len() as i64
                {
                    return Err("Некорректные переходы agy x64 backend; файл не изменён".into());
                }
                let helper_file = start + helper as usize;
                if diagnostic_gates.len() != 1
                    || !(helper_file..=helper_file + MAX_HELPER_PROLOGUE)
                        .contains(&diagnostic_gates[0].0)
                    || diagnostic_gates[0].0 + GATE_LEN > start + bytes.len()
                {
                    return Err(
                        "Вызов agy x64 backend не ведёт в проверенную диагностическую функцию"
                            .into(),
                    );
                }
                found = Some((start + m.start() + ERROR_GUARD_LEN, state));
            }
        }
    }
    Ok(found)
}

fn plan_x64_cli<'a>(
    file: &object::File<'_>,
    data: &'a [u8],
    legacy_cli: bool,
    diagnostic_gates: X64Gates,
    mode: Mode,
) -> Result<Plan<'a>, String> {
    let backend_gate = if legacy_cli {
        None
    } else {
        x64_backend_cli_gate_in(file, data, &diagnostic_gates)?
    };
    if backend_gate.is_some()
        && diagnostic_gates
            .iter()
            .any(|(_, state)| *state != X64GateState::Stock)
    {
        return Err(
            "Обнаружен патч диагностической функции agy x64; необходим проверенный исходный backup"
                .into(),
        );
    }
    let gates = backend_gate.map_or(diagnostic_gates, |gate| vec![gate]);
    if gates.iter().any(|(_, state)| {
        if legacy_cli {
            *state == X64GateState::Patched
        } else {
            *state == X64GateState::Legacy
        }
    }) {
        return Err("Обнаружен старый или смешанный патч agy-x64-long-v1; необходим проверенный исходный backup".into());
    }
    let mut output = Cow::Borrowed(data);
    let mut changes = 0;
    for (offset, state) in &gates {
        if *state == X64GateState::Stock {
            let (fix, at) = if legacy_cli {
                (CLI_GATE_X64_LONG_V1_FIX, 0)
            } else {
                (CLI_GATE_X64_LONG_FIX, CLI_GATE_X64_LONG_FIX_AT)
            };
            // The gate edit cannot create or remove a manager-gate match (their
            // fixed bytes never overlap), so counting can skip it.
            if mode == Mode::Apply {
                output.to_mut()[offset + at..offset + at + fix.len()].copy_from_slice(fix);
            }
            changes += 1;
        }
    }
    let mut existing = gates.len() - changes;
    let mut hub_sites = 0;
    // New IDEs run agy --hub, which also uses PersonalAuthValidator.Validate.
    // Older CLI builds may lack this gate. Keep the legacy planner byte-exact
    // for backup migration, and include both gates in the current transaction.
    if !legacy_cli {
        for section in file.sections().filter(|s| s.kind() == SectionKind::Text) {
            let Some((start, size)) = section.file_range() else {
                continue;
            };
            let range = section_range(start, size)?;
            let sites = x64_manager_sites(section_bytes(&output, &range)?);
            let (stock, patched) =
                rewrite_sites(&mut output, range, sites, MGR_GATE_X64_FIX, 0, 1, mode)?;
            hub_sites += stock + patched;
            changes += stock;
            existing += patched;
        }
        if hub_sites > 1 {
            return Err("Неоднозначная проверка авторизации agy --hub; файл не изменён".into());
        }
    }
    Ok(Plan {
        data: output,
        changes,
        existing,
        profile: if legacy_cli {
            "agy-x64-long-v1"
        } else if backend_gate.is_some() {
            "agy-x64-backend-v4"
        } else if hub_sites > 0 {
            "agy-x64-cli-hub-v3"
        } else {
            "agy-x64-long-v2"
        }
        .into(),
    })
}

fn arm64_branch_target(instruction: u32, pc: usize, bits: u32, shift: u32) -> i64 {
    let immediate = (instruction >> shift) & ((1 << bits) - 1);
    let signed = ((immediate as i32) << (32 - bits)) >> (32 - bits);
    pc as i64 + i64::from(signed) * 4
}

fn cli_arm64_branches_are_valid(bytes: &[u8], offset: usize, section_size: usize) -> bool {
    if bytes.len() != 20 || !offset.is_multiple_of(4) {
        return false;
    }
    let instruction = |at| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    let error = arm64_branch_target(instruction(0), offset, 19, 5);
    let nil = arm64_branch_target(instruction(4), offset + 4, 19, 5);
    let eligible = arm64_branch_target(instruction(12), offset + 12, 14, 5);
    let details = arm64_branch_target(instruction(16), offset + 16, 26, 0);
    let inside = |target: i64| target >= 0 && target < section_size as i64;
    nil == eligible
        && nil >= (offset + bytes.len()) as i64
        && error >= (offset + bytes.len()) as i64
        && error != nil
        && inside(nil)
        && inside(error)
        && inside(details)
}

/// Whether the sign-in gate matches could differ after the core edits at
/// `core_offsets`. Both gate patterns are 20 bytes, so only matches that
/// overlap an edit can change; those cases are counted from patched bytes.
fn core_edit_touches_login(bytes: &[u8], core_offsets: &[usize], login_found: &[usize]) -> bool {
    const LOGIN_LEN: usize = 20;
    core_offsets.iter().any(|&edit| {
        let edit_end = edit + MGR_GATE_ARM64_FIX.len();
        if login_found
            .iter()
            .any(|&login| login < edit_end && edit < login + LOGIN_LEN)
        {
            return true;
        }
        let start = edit.saturating_sub(LOGIN_LEN - 1);
        let end = (edit_end + LOGIN_LEN - 1).min(bytes.len());
        let Some(window) = bytes.get(start..end) else {
            return true;
        };
        let mut window = window.to_vec();
        let at = edit - start;
        if window.len() < at + MGR_GATE_ARM64_FIX.len() {
            return true;
        }
        window[at..at + MGR_GATE_ARM64_FIX.len()].copy_from_slice(MGR_GATE_ARM64_FIX);
        regex_cli_arm64_orig().is_match(&window) || regex_cli_arm64_patched().is_match(&window)
    })
}

fn plan_arm64_cli<'a>(
    file: &object::File<'_>,
    data: &'a [u8],
    mode: Mode,
) -> Result<Plan<'a>, String> {
    let mut output = Cow::Borrowed(data);
    let (mut core_stock, mut core_patched, mut login_stock, mut login_patched) = (0, 0, 0, 0);
    for section in file.sections().filter(|s| s.kind() == SectionKind::Text) {
        let Some((offset, size)) = section.file_range() else {
            continue;
        };
        let range = section_range(offset, size)?;
        let bytes = section_bytes(&output, &range)?;
        // The validation matches are reused for patching instead of searching
        // the same section again with the same four patterns.
        let login_stock_found: Vec<_> = regex_cli_arm64_orig().find_iter(bytes).collect();
        let login_patched_found: Vec<_> = regex_cli_arm64_patched().find_iter(bytes).collect();
        let core_stock_found: Vec<_> = regex_mgr_arm64_orig().find_iter(bytes).collect();
        let core_patched_found: Vec<_> = regex_mgr_arm64_patched().find_iter(bytes).collect();
        if !section.address().is_multiple_of(4)
            || login_stock_found
                .iter()
                .chain(&login_patched_found)
                .any(|m| !cli_arm64_branches_are_valid(m.as_bytes(), m.start(), bytes.len()))
            || core_stock_found
                .iter()
                .chain(&core_patched_found)
                .any(|m| !m.start().is_multiple_of(4))
        {
            return Err("Некорректные переходы или выравнивание agy ARM64; файл не изменён".into());
        }
        let starts = |found: &[regex::bytes::Match<'_>]| -> Vec<usize> {
            found.iter().map(|m| m.start()).collect()
        };
        let core_offsets = starts(&core_stock_found);
        if mode == Mode::Count {
            let login_found: Vec<usize> = starts(&login_stock_found)
                .into_iter()
                .chain(starts(&login_patched_found))
                .collect();
            if core_edit_touches_login(bytes, &core_offsets, &login_found) {
                // Rare overlap: count from the patched bytes, as patching does.
                return plan_arm64_cli(file, data, Mode::Apply);
            }
        }
        let core_sites = (core_offsets, core_patched_found.len());
        let login_sites: Sites = (starts(&login_stock_found), login_patched_found.len());
        let (stock, patched) = rewrite_sites(
            &mut output,
            range.clone(),
            core_sites,
            MGR_GATE_ARM64_FIX,
            0,
            1,
            mode,
        )?;
        core_stock += stock;
        core_patched += patched;
        // The sign-in gate is searched in the bytes after the core edit, as
        // before; without a core edit (or when counting, where the edit was
        // shown not to touch it) the section bytes are unchanged.
        let login_sites = if stock > 0 && mode == Mode::Apply {
            pair_sites(
                section_bytes(&output, &range)?,
                regex_cli_arm64_orig(),
                regex_cli_arm64_patched(),
            )
        } else {
            login_sites
        };
        let (stock, patched) = rewrite_sites(
            &mut output,
            range,
            login_sites,
            CLI_GATE_ARM64_FIX,
            CLI_GATE_ARM64_FIX_AT,
            1,
            mode,
        )?;
        login_stock += stock;
        login_patched += patched;
    }
    // A v1 core-only patch is partial. Never report full success when the
    // independent sign-in gate is absent or ambiguous in a future executable.
    if core_stock + core_patched != 1 || login_stock + login_patched != 1 {
        return Err(format!(
            "Версия не поддерживается профилем agy-arm64-v2: core {}, login {}. SHA-256 {DIGEST_PLACEHOLDER}",
            core_stock + core_patched,
            login_stock + login_patched,
        ));
    }
    Ok(Plan {
        data: output,
        changes: core_stock + login_stock,
        existing: core_patched + login_patched,
        profile: "agy-arm64-v2".into(),
    })
}

fn plan_binary(data: &[u8], kind: TargetKind) -> Result<Plan<'_>, String> {
    plan_binary_with_cli_profile(data, kind, false)
}

fn arm64_manager_sites(bytes: &[u8]) -> Sites {
    pair_sites(bytes, regex_mgr_arm64_orig(), regex_mgr_arm64_patched())
}

fn plan_binary_with_cli_profile(
    data: &[u8],
    kind: TargetKind,
    legacy_cli: bool,
) -> Result<Plan<'_>, String> {
    plan_binary_mode(data, kind, legacy_cli, Mode::Apply)
}

fn plan_binary_mode(
    data: &[u8],
    kind: TargetKind,
    legacy_cli: bool,
    mode: Mode,
) -> Result<Plan<'_>, String> {
    let file = object::File::parse(data)
        .map_err(|e| format!("Неподдерживаемый executable (PE/ELF/Mach-O): {e}"))?;
    if kind == TargetKind::AgyCli && file.architecture() == Architecture::Aarch64 && !legacy_cli {
        return plan_arm64_cli(&file, data, mode);
    }
    if kind == TargetKind::AgyCli && file.architecture() == Architecture::X86_64 {
        let gates = x64_cli_gates_in(&file, data)?.ok_or("Нет профиля agy x64")?;
        return plan_x64_cli(&file, data, legacy_cli, gates, mode);
    }
    let (sites, fix, fix_at, max_matches, profile): (fn(&[u8]) -> Sites, _, _, _, _) =
        match (kind, file.architecture()) {
            (TargetKind::LanguageServer, Architecture::X86_64) => {
                (x64_manager_sites, MGR_GATE_X64_FIX, 0, 1, "core-x64-v1")
            }
            (TargetKind::LanguageServer, Architecture::Aarch64) => (
                arm64_manager_sites,
                MGR_GATE_ARM64_FIX,
                0,
                1,
                "core-arm64-v1",
            ),
            (TargetKind::AgyCli, Architecture::Aarch64) => (
                arm64_manager_sites,
                MGR_GATE_ARM64_FIX,
                0,
                1,
                "agy-arm64-v1",
            ),
            _ => return Err("Нет профиля патча для этой архитектуры/компонента".into()),
        };
    let mut output = Cow::Borrowed(data);
    let (mut changes, mut existing) = (0, 0);
    for section in file.sections().filter(|s| s.kind() == SectionKind::Text) {
        let Some((offset, size)) = section.file_range() else {
            continue;
        };
        let range = section_range(offset, size)?;
        let found = sites(section_bytes(&output, &range)?);
        let (c, p) = rewrite_sites(&mut output, range, found, fix, fix_at, max_matches, mode)?;
        changes += c;
        existing += p;
    }
    let total = changes + existing;
    if total == 0 || total > max_matches {
        return Err(format!(
            "Версия не поддерживается профилем {profile}: совпадений {}. SHA-256 {DIGEST_PLACEHOLDER}",
            changes + existing,
        ));
    }
    Ok(Plan {
        data: output,
        changes,
        existing,
        profile: profile.into(),
    })
}

/// A legacy v1 or diagnostic-only x64 CLI patch needs its verified backup;
/// anything else gets a plan. The x64 gates are parsed and searched once.
enum Scan<'a> {
    LegacyX64V1,
    LegacyX64Diagnostic,
    Plan(Result<Plan<'a>, String>),
}

fn scan(data: &[u8], kind: TargetKind, mode: Mode) -> Scan<'_> {
    if kind == TargetKind::AgyCli {
        if let Ok(file) = object::File::parse(data) {
            if file.architecture() == Architecture::X86_64 {
                return match x64_cli_gates_in(&file, data) {
                    Ok(Some(gates))
                        if gates
                            .iter()
                            .any(|(_, state)| *state == X64GateState::Legacy) =>
                    {
                        Scan::LegacyX64V1
                    }
                    Ok(Some(gates))
                        if gates
                            .iter()
                            .any(|(_, state)| *state == X64GateState::Patched)
                            && x64_backend_cli_gate_in(&file, data, &gates)
                                .is_ok_and(|gate| gate.is_some()) =>
                    {
                        Scan::LegacyX64Diagnostic
                    }
                    Ok(Some(gates)) => Scan::Plan(plan_x64_cli(&file, data, false, gates, mode)),
                    Ok(None) => Scan::Plan(plan_mode(data, kind, mode)),
                    Err(error) => Scan::Plan(Err(error)),
                };
            }
        }
    }
    Scan::Plan(plan_mode(data, kind, mode))
}

fn plan(data: &[u8], kind: TargetKind) -> Result<Plan<'_>, String> {
    plan_mode(data, kind, Mode::Apply)
}

fn plan_mode(data: &[u8], kind: TargetKind, mode: Mode) -> Result<Plan<'_>, String> {
    match kind {
        TargetKind::IdeMainJs => plan_js_mode(data, mode),
        TargetKind::IdeAsar => crate::core::asar::plan_asar_mode(data, mode),
        _ => plan_binary_mode(data, kind, false, mode),
    }
}
/// File identity used to reuse a state result across dashboard redraws. Any
/// update replaces the file (new mtime/size); patch/restore also clear it.
#[derive(Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    len: u64,
    modified: SystemTime,
}

type StateCache = HashMap<(PathBuf, TargetKind), (FileStamp, BinaryState)>;
static STATES: Mutex<Option<StateCache>> = Mutex::new(None);

fn file_stamp(path: &Path) -> Option<FileStamp> {
    let metadata = fs::metadata(path).ok()?;
    Some(FileStamp {
        len: metadata.len(),
        modified: metadata.modified().ok()?,
    })
}

fn forget_cached_states() {
    if let Ok(mut cache) = STATES.lock() {
        *cache = None;
    }
}

pub fn check_target_state(target: &FoundTarget) -> BinaryState {
    let key = (target.path.clone(), target.kind);
    let before = file_stamp(&target.path);
    if let (Some(stamp), Ok(cache)) = (before, STATES.lock()) {
        if let Some((cached, state)) = cache.as_ref().and_then(|c| c.get(&key)) {
            if *cached == stamp {
                return *state;
            }
        }
    }
    // A read error (for example a file briefly locked by the IDE or an
    // updater) is reported as Unknown but never cached: the next refresh
    // reads the unchanged file again.
    let Ok(data) = fs::read(&target.path) else {
        return BinaryState::Unknown;
    };
    let state = state_for_data(&data, target.kind);
    // A file replaced during the scan is not cached under either stamp.
    if let Some(stamp) = before.filter(|stamp| file_stamp(&target.path) == Some(*stamp)) {
        if let Ok(mut cache) = STATES.lock() {
            let cache = cache.get_or_insert_with(HashMap::new);
            if cache.len() >= 64 {
                cache.clear();
            }
            cache.insert(key, (stamp, state));
        }
    }
    state
}

fn state_for_data(data: &[u8], kind: TargetKind) -> BinaryState {
    // Status needs only the counts: never build (and copy) patched bytes.
    match scan(data, kind, Mode::Count) {
        Scan::LegacyX64V1 | Scan::LegacyX64Diagnostic => BinaryState::PartiallyPatched,
        Scan::Plan(Ok(p)) => state_from_counts(p.changes, p.existing),
        Scan::Plan(Err(_)) => BinaryState::Unknown,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatchCounts {
    pub matches: Option<usize>,
    pub core: Option<usize>,
    pub login: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetInspection {
    pub state: BinaryState,
    pub profile: Option<&'static str>,
    pub reason: Option<&'static str>,
    pub counts: Option<MatchCounts>,
}

fn known_profile(name: &str) -> Option<&'static str> {
    match name {
        "core-x64-v1" => Some("core-x64-v1"),
        "core-arm64-v1" => Some("core-arm64-v1"),
        "agy-arm64-v1" => Some("agy-arm64-v1"),
        "agy-arm64-v2" => Some("agy-arm64-v2"),
        "agy-x64-long-v1" => Some("agy-x64-long-v1"),
        "agy-x64-long-v2" => Some("agy-x64-long-v2"),
        "agy-x64-cli-hub-v3" => Some("agy-x64-cli-hub-v3"),
        "agy-x64-backend-v4" => Some("agy-x64-backend-v4"),
        "ide-reset-tier-v1" => Some("ide-reset-tier-v1"),
        "asar-ide-reset-tier-v1" => Some("asar-ide-reset-tier-v1"),
        _ => None,
    }
}

fn parse_leading_usize(text: &str) -> Option<usize> {
    let digits: String = text
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

fn classify_scan_error(error: &str) -> (Option<&'static str>, &'static str, Option<MatchCounts>) {
    if let Some(rest) = error.strip_prefix("Версия не поддерживается профилем ")
    {
        let (profile_str, detail) = rest.split_once(':').unwrap_or((rest, ""));
        let profile = known_profile(profile_str.trim());
        let counts = if let Some(after_core) = detail.trim().strip_prefix("core ") {
            let core = parse_leading_usize(after_core);
            let login = after_core
                .split_once("login ")
                .and_then(|(_, right)| parse_leading_usize(right));
            Some(MatchCounts {
                matches: None,
                core,
                login,
            })
        } else {
            detail
                .trim()
                .strip_prefix("совпадений ")
                .map(|after_matches| MatchCounts {
                    matches: parse_leading_usize(after_matches),
                    core: None,
                    login: None,
                })
        };
        return (profile, "profile_mismatch", counts);
    }
    if error.starts_with("Неподдерживаемый executable") {
        (None, "unsupported_executable", None)
    } else if error.starts_with("Нет профиля") {
        (None, "unsupported_architecture", None)
    } else if error.starts_with("Неоднозначная") {
        (None, "ambiguous_signature", None)
    } else if error.contains("переходы")
        || error.contains("Переходы")
        || error.contains("не ведёт в проверенную")
    {
        (None, "invalid_branches", None)
    } else if error.contains("agy-x64-long-v1") {
        (Some("agy-x64-long-v1"), "legacy_x64_v1", None)
    } else if error.contains("диагностической функции") {
        (Some("agy-x64-backend-v4"), "legacy_x64_diagnostic", None)
    } else if error.contains("integrity") {
        (Some("asar-ide-reset-tier-v1"), "asar_integrity", None)
    } else if error.contains("ASAR") {
        (Some("asar-ide-reset-tier-v1"), "asar_invalid", None)
    } else if error.contains("UTF-8") {
        (Some("ide-reset-tier-v1"), "invalid_utf8", None)
    } else if error.contains("секц") || error.contains("Секц") {
        (None, "invalid_section", None)
    } else {
        (None, "scan_error", None)
    }
}

/// Structured, allowlisted inspection for support reports: explains why a file
/// is `Unknown` or `PartiallyPatched` without exporting raw error strings.
pub fn inspect_target(target: &FoundTarget) -> TargetInspection {
    let data = match fs::read(&target.path) {
        Ok(data) => data,
        Err(error) => {
            let reason = match error.kind() {
                std::io::ErrorKind::NotFound => "not_found",
                std::io::ErrorKind::PermissionDenied => "permission_denied",
                _ => "read_failed",
            };
            return TargetInspection {
                state: BinaryState::Unknown,
                profile: None,
                reason: Some(reason),
                counts: None,
            };
        }
    };
    inspect_data(&data, target.kind)
}

pub(crate) fn inspect_data(data: &[u8], kind: TargetKind) -> TargetInspection {
    match scan(data, kind, Mode::Count) {
        Scan::LegacyX64V1 => TargetInspection {
            state: BinaryState::PartiallyPatched,
            profile: Some("agy-x64-long-v1"),
            reason: Some("legacy_x64_v1"),
            counts: None,
        },
        Scan::LegacyX64Diagnostic => TargetInspection {
            state: BinaryState::PartiallyPatched,
            profile: Some("agy-x64-backend-v4"),
            reason: Some("legacy_x64_diagnostic"),
            counts: None,
        },
        Scan::Plan(Ok(p)) => {
            let state = state_from_counts(p.changes, p.existing);
            TargetInspection {
                state,
                profile: known_profile(&p.profile),
                reason: (state == BinaryState::Unknown).then_some("no_pattern_match"),
                counts: (state == BinaryState::Unknown).then_some(MatchCounts {
                    matches: Some(p.changes + p.existing),
                    core: None,
                    login: None,
                }),
            }
        }
        Scan::Plan(Err(error)) => {
            let (profile, reason, counts) = classify_scan_error(&error);
            TargetInspection {
                state: BinaryState::Unknown,
                profile,
                reason: Some(reason),
                counts,
            }
        }
    }
}

fn ensure_file_closed(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
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
        // This file is read back after signing. Only the final replacement
        // needs to share a volume with the target.
        let mut temp =
            tempfile::NamedTempFile::new_in("/private/tmp").map_err(|e| e.to_string())?;
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

#[cfg(test)]
fn is_legacy_x64_cli(data: &[u8]) -> bool {
    let Ok(file) = object::File::parse(data) else {
        return false;
    };
    x64_cli_gates_in(&file, data).is_ok_and(|gates| {
        gates.is_some_and(|gates| {
            gates
                .iter()
                .any(|(_, state)| *state == X64GateState::Legacy)
                || (gates
                    .iter()
                    .any(|(_, state)| *state == X64GateState::Patched)
                    && x64_backend_cli_gate_in(&file, data, &gates)
                        .is_ok_and(|gate| gate.is_some()))
        })
    })
}

fn legacy_cli_backup_matches(original: &[u8], current: &[u8]) -> bool {
    if !plan_binary(original, TargetKind::AgyCli).is_ok_and(|p| p.changes > 0 && p.existing == 0) {
        return false;
    }
    if let Ok(Some(stock_gates)) = x64_cli_gates(original) {
        let Ok(Some(current_gates)) = x64_cli_gates(current) else {
            return false;
        };
        if stock_gates.len() != current_gates.len() {
            return false;
        }
        let mut expected = original.to_vec();
        for ((stock_at, _), (current_at, state)) in stock_gates.iter().zip(current_gates) {
            if *stock_at != current_at {
                return false;
            }
            let (fix, at) = match state {
                X64GateState::Stock => continue,
                X64GateState::Legacy => (CLI_GATE_X64_LONG_V1_FIX, 0),
                X64GateState::Patched => (CLI_GATE_X64_LONG_FIX, CLI_GATE_X64_LONG_FIX_AT),
            };
            expected[current_at + at..current_at + at + fix.len()].copy_from_slice(fix);
        }
        if expected == current {
            return true;
        }
        if let Ok(file) = object::File::parse(original) {
            let mut with_hub = Cow::Owned(expected);
            for section in file.sections().filter(|s| s.kind() == SectionKind::Text) {
                let Some((start, size)) = section.file_range() else {
                    continue;
                };
                let Ok(range) = section_range(start, size) else {
                    return false;
                };
                let Ok(bytes) = section_bytes(&with_hub, &range) else {
                    return false;
                };
                let sites = x64_manager_sites(bytes);
                if rewrite_sites(
                    &mut with_hub,
                    range,
                    sites,
                    MGR_GATE_X64_FIX,
                    0,
                    1,
                    Mode::Apply,
                )
                .is_err()
                {
                    return false;
                }
            }
            if *with_hub == *current {
                return true;
            }
        }
        return false;
    }
    plan_binary_with_cli_profile(original, TargetKind::AgyCli, true)
        .is_ok_and(|p| p.changes == 1 && p.existing == 0 && *p.data == *current)
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
    forget_cached_states();
    #[cfg(target_os = "macos")]
    let target = &resolve_target(target)?;
    let result = patch_target_locked(target);
    forget_cached_states();
    #[cfg(target_os = "macos")]
    prune_bundle_transactions(target);
    result
}

/// Finished write journals next to the app are no longer needed; pending ones
/// stay for crash recovery (see `macos_app::prune_transactions`).
#[cfg(target_os = "macos")]
fn prune_bundle_transactions(target: &FoundTarget) {
    if let Some(app) = crate::system::macos_app::bundle(&target.path) {
        crate::system::macos_app::prune_transactions(app);
    }
}

#[cfg(target_os = "macos")]
fn resolve_target(target: &FoundTarget) -> Result<FoundTarget, String> {
    let mut target = target.clone();
    target.path =
        crate::system::macos_app::resolved_file(&target.path).map_err(|error| error.to_string())?;
    Ok(target)
}

/// The outcome when a plan has nothing to change.
fn unchanged_outcome(existing: usize, kind: TargetKind) -> Result<PatchOutcome, String> {
    if existing > 0 {
        Ok(PatchOutcome::AlreadyPatched)
    } else if matches!(kind, TargetKind::IdeAsar) {
        Ok(PatchOutcome::NotApplicable)
    } else {
        Err("Версия/сигнатура не поддерживается; файл не изменён".into())
    }
}

fn patch_target_locked(target: &FoundTarget) -> Result<PatchOutcome, String> {
    crate::system::fs_utils::recover_pending(&target.path)?;
    ensure_not_symlink(&target.path)?;
    #[cfg(target_os = "macos")]
    journal::migrate_app_backup(&target.path)?;
    let mut before = fs::read(&target.path).map_err(|e| e.to_string())?;
    let (legacy_x64_error, mut p) = match scan(&before, target.kind, Mode::Apply) {
        Scan::LegacyX64V1 => (
            Some("Обнаружен старый или смешанный патч agy-x64-long-v1, но точный исходный backup не найден; переустановите исходный agy"),
            None,
        ),
        Scan::LegacyX64Diagnostic => (
            Some("Обнаружен старый патч диагностической функции agy x64, но точный исходный backup не найден; переустановите исходный agy"),
            None,
        ),
        Scan::Plan(planned) => {
            let planned = planned.map_err(|e| with_digest(e, &before))?;
            let partial =
                target.kind == TargetKind::AgyCli && planned.changes > 0 && planned.existing > 0;
            // Nothing to write: answer without copying the (borrowed) file.
            if planned.changes == 0 && !partial {
                return unchanged_outcome(planned.existing, target.kind);
            }
            (None, Some(planned.into_owned()))
        }
    };
    let partial_cli = target.kind == TargetKind::AgyCli
        && p.as_ref().is_some_and(|p| p.changes > 0 && p.existing > 0);
    let mut require_continuation = false;
    if legacy_x64_error.is_some() || partial_cli {
        ensure_file_closed(&target.path)?;
        #[cfg(target_os = "macos")]
        crate::system::macos_app::check_write_access(&target.path)?;
        if journal::has_record(&target.path) {
            let original = journal::verified_original(&target.path, &before)?
                .ok_or("Backup старого патча исчез; файл не изменён")?;
            let fresh = plan(&original, target.kind)
                .map_err(|e| with_digest(e, &original))?
                .into_owned();
            if fresh.changes == 0 || fresh.existing > 0 {
                return Err(
                    "Backup agy не содержит чистую исходную версию; обновление отменено".into(),
                );
            }
            // Rebuild every gate from the verified stock baseline. The active
            // record retains that baseline, including after an interrupted write.
            let changes = p.as_ref().map(|p| p.changes).unwrap_or(fresh.changes);
            p = Some(Plan { changes, ..fresh });
            require_continuation = true;
        } else {
            let original = verified_legacy_cli_backup(&target.path, &before).ok_or(
                legacy_x64_error.unwrap_or(
                    "Обнаружен частичный патч agy, но точный исходный backup не найден; переустановите исходный agy",
                ),
            )?;
            let fresh = plan(&original, target.kind)
                .map_err(|e| with_digest(e, &original))?
                .into_owned();
            if fresh.existing != 0 {
                return Err("Backup agy не содержит исходный файл; запись отменена".into());
            }
            crate::system::fs_utils::guarded_write_file(
                &target.path,
                Some(&before),
                Some(&original),
            )?;
            before = original;
            p = Some(fresh);
        }
    }
    let p = p.ok_or("Нет проверенного плана патча")?;
    if p.changes == 0 {
        return unchanged_outcome(p.existing, target.kind);
    }
    ensure_file_closed(&target.path)?;
    #[cfg(target_os = "macos")]
    crate::system::macos_app::check_write_access(&target.path)?;
    let after = prepare_for_write(&target.path, p.data.into_owned(), target.kind)?;
    if require_continuation {
        journal::apply_continuing(&target.path, &before, &after, &p.profile)?;
    } else {
        journal::apply(&target.path, Some(&before), &after, &p.profile)?;
    }
    Ok(PatchOutcome::Changed(p.changes))
}

pub fn restore_target(target: &FoundTarget) -> Result<PatchOutcome, String> {
    let _guard = operation_guard();
    forget_cached_states();
    #[cfg(target_os = "macos")]
    let target = &resolve_target(target)?;
    let result = restore_target_locked(target);
    forget_cached_states();
    #[cfg(target_os = "macos")]
    prune_bundle_transactions(target);
    result
}

fn restore_target_locked(target: &FoundTarget) -> Result<PatchOutcome, String> {
    crate::system::fs_utils::recover_pending(&target.path)?;
    ensure_not_symlink(&target.path)?;
    ensure_file_closed(&target.path)?;
    #[cfg(target_os = "macos")]
    journal::migrate_app_backup(&target.path)?;
    let before = fs::read(&target.path).map_err(|e| e.to_string())?;
    let current_state = state_for_data(&before, target.kind);
    if current_state == BinaryState::Stock {
        // The updater has already replaced patched bytes with a known clean
        // executable. Retire the old record while keeping historical backups.
        journal::retire(&target.path, Some(&before))?;
        return Ok(PatchOutcome::AlreadyStock);
    }
    #[cfg(target_os = "macos")]
    if journal::has_record(&target.path) {
        crate::system::macos_app::check_write_access(&target.path)?;
    }
    if target.kind == TargetKind::AgyCli
        && journal::has_record(&target.path)
        && matches!(
            current_state,
            BinaryState::Patched | BinaryState::PartiallyPatched
        )
    {
        let original = journal::verified_original(&target.path, &before)?
            .ok_or("Backup патча исчез; откат отменён")?;
        if state_for_data(&original, target.kind) != BinaryState::Stock {
            return Err("Backup agy содержит частичный/неизвестный патч; восстановите исходную версию приложения".into());
        }
    }
    if journal::restore(&target.path)? {
        return Ok(PatchOutcome::Restored);
    }
    if matches!(target.kind, TargetKind::IdeAsar | TargetKind::IdeMainJs)
        && plan(&before, target.kind).is_ok_and(|p| p.changes == 0 && p.existing == 0)
    {
        return Ok(PatchOutcome::NotApplicable);
    }
    // Legacy backups are accepted only when they reproduce the current bytes.
    for backup in legacy_backup_paths(&target.path) {
        if let Ok(original) = fs::read(&backup) {
            let current_matches = plan(&original, target.kind)
                .is_ok_and(|p| p.changes > 0 && p.existing == 0 && *p.data == *before);
            let old_cli_matches =
                target.kind == TargetKind::AgyCli && legacy_cli_backup_matches(&original, &before);
            if current_matches || old_cli_matches {
                #[cfg(target_os = "macos")]
                crate::system::macos_app::check_write_access(&target.path)?;
                crate::system::fs_utils::guarded_write_file(
                    &target.path,
                    Some(&before),
                    Some(&original),
                )?;
                return Ok(PatchOutcome::Restored);
            }
        }
    }
    Err("Нет backup, соответствующего текущей версии. Файл сохранён; восстановите точную версию приложения.".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn x64_backend_fixture() -> Vec<u8> {
        let mut code = vec![0x90; 512];
        let helper =
            b"\x48\x85\xc0\x0f\x84\x0a\x00\x00\x00\x80\x78\x08\x00\x0f\x85\x00\x00\x00\x00";
        code[32..32 + helper.len()].copy_from_slice(helper);
        let hub = b"\x80\x78\x08\x00\x74\x0a\x48\x8b\x44\x24\x20\x48\x89\x44\x60";
        code[64..64 + hub.len()].copy_from_slice(hub);
        let gate = b"\x48\x85\xc0\x0f\x85\x00\x01\x00\x00\x48\x85\xc9\x0f\x84\x80\x00\x00\x00\x80\x79\x08\x00\x0f\x85\x76\x00\x00\x00\x48\x89\xc8\x90\xe8\x00\x00\x00\x00";
        code[96..96 + gate.len()].copy_from_slice(gate);
        code[96 + 33..96 + 37].copy_from_slice(&(-133i32).to_le_bytes());
        pe_fixture(&code, 0x8664)
    }

    #[test]
    fn x64_backend_patches_the_login_gate_and_preserves_diagnostics_and_error_handling() {
        let stock = x64_backend_fixture();
        let plan = plan_binary(&stock, TargetKind::AgyCli).unwrap();
        assert_eq!((plan.changes, plan.existing), (2, 0));
        assert_eq!(plan.profile, "agy-x64-backend-v4");
        assert_eq!(&plan.data[512 + 32..512 + 51], &stock[512 + 32..512 + 51]);
        assert_eq!(&plan.data[512 + 96..512 + 114], &stock[512 + 96..512 + 114]);
        assert_eq!(&plan.data[512 + 114..512 + 118], CLI_GATE_X64_LONG_FIX);
        assert_eq!(
            &plan.data[512 + 118..512 + 133],
            &stock[512 + 118..512 + 133]
        );
        let repeated = plan_binary(&plan.data, TargetKind::AgyCli).unwrap();
        assert_eq!((repeated.changes, repeated.existing), (0, 2));
        assert_eq!(repeated.data, plan.data);
        for index in [96 + 5, 96 + 14, 96 + 24, 96 + 33] {
            let mut invalid = stock.clone();
            invalid[512 + index..512 + index + 4].copy_from_slice(&i32::MAX.to_le_bytes());
            assert!(plan_binary(&invalid, TargetKind::AgyCli).is_err());
        }
        let mut duplicate = stock.clone();
        duplicate[512 + 160..512 + 197].copy_from_slice(&stock[512 + 96..512 + 133]);
        duplicate[512 + 193..512 + 197].copy_from_slice(&(-197i32).to_le_bytes());
        assert!(plan_binary(&duplicate, TargetKind::AgyCli).is_err());

        // Shifted Go prologue within the bounded window still matches; outside is rejected.
        let mut shifted = vec![0x90; 512];
        let helper =
            b"\x48\x85\xc0\x0f\x84\x0a\x00\x00\x00\x80\x78\x08\x00\x0f\x85\x00\x00\x00\x00";
        shifted[40..40 + helper.len()].copy_from_slice(helper);
        let hub = b"\x80\x78\x08\x00\x74\x0a\x48\x8b\x44\x24\x20\x48\x89\x44\x60";
        shifted[64..64 + hub.len()].copy_from_slice(hub);
        let gate = b"\x48\x85\xc0\x0f\x85\x00\x01\x00\x00\x48\x85\xc9\x0f\x84\x80\x00\x00\x00\x80\x79\x08\x00\x0f\x85\x76\x00\x00\x00\x48\x89\xc8\x90\xe8\x00\x00\x00\x00";
        shifted[96..96 + gate.len()].copy_from_slice(gate);
        shifted[96 + 33..96 + 37].copy_from_slice(&(-133i32).to_le_bytes());
        let shifted_pe = pe_fixture(&shifted, 0x8664);
        let shifted_plan = plan_binary(&shifted_pe, TargetKind::AgyCli).unwrap();
        assert_eq!(shifted_plan.profile, "agy-x64-backend-v4");

        let mut too_far = vec![0x90; 512];
        too_far[72..72 + helper.len()].copy_from_slice(helper);
        too_far[96..96 + gate.len()].copy_from_slice(gate);
        too_far[96 + 33..96 + 37].copy_from_slice(&(-133i32).to_le_bytes());
        assert!(plan_binary(&pe_fixture(&too_far, 0x8664), TargetKind::AgyCli).is_err());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn x64_backend_replaces_the_old_diagnostic_patch_from_a_verified_backup() {
        let stock = x64_backend_fixture();
        let fresh = plan_binary(&stock, TargetKind::AgyCli).unwrap();
        let mut old = stock.clone();
        old[512 + 32 + 9..512 + 32 + 13].copy_from_slice(CLI_GATE_X64_LONG_FIX);
        old[512 + 64..512 + 70].copy_from_slice(MGR_GATE_X64_FIX);
        assert_eq!(
            state_for_data(&old, TargetKind::AgyCli),
            BinaryState::PartiallyPatched
        );
        let directory = tempfile::tempdir().unwrap();
        let target = FoundTarget {
            path: directory.path().join("agy.exe"),
            kind: TargetKind::AgyCli,
            name: "agy".into(),
        };
        fs::write(&target.path, &old).unwrap();
        let error = patch_target(&target).unwrap_err();
        assert!(error.contains("диагностической функции"), "{error}");
        assert_eq!(fs::read(&target.path).unwrap(), old);
        let legacy_bak = target.path.with_extension("bak");
        fs::write(&legacy_bak, &stock).unwrap();
        assert_eq!(patch_target(&target).unwrap(), PatchOutcome::Changed(2));
        assert_eq!(fs::read(&target.path).unwrap(), fresh.data.as_ref());
        assert_eq!(restore_target(&target).unwrap(), PatchOutcome::Restored);
        assert_eq!(fs::read(&target.path).unwrap(), stock);
        fs::remove_file(&legacy_bak).unwrap();
        fs::remove_dir_all(directory.path().join("agy.exe.ag-backups")).unwrap();
        fs::write(&target.path, &stock).unwrap();
        journal::apply(&target.path, Some(&stock), &old, "agy-x64-cli-hub-v3").unwrap();
        assert_eq!(patch_target(&target).unwrap(), PatchOutcome::Changed(2));
        assert_eq!(fs::read(&target.path).unwrap(), fresh.data.as_ref());
        assert_eq!(patch_target(&target).unwrap(), PatchOutcome::AlreadyPatched);
        assert_eq!(restore_target(&target).unwrap(), PatchOutcome::Restored);
        assert_eq!(fs::read(&target.path).unwrap(), stock);
    }

    #[test]
    fn x64_hub_gate_upgrade_is_transactional_and_reversible() {
        let cli = b"\x48\x85\xc0\x0f\x84\x0a\x00\x00\x00\x80\x78\x08\x00\x0f\x85\x00\x00\x00\x00";
        let hub = b"\x80\x78\x08\x00\x74\x0a\x48\x8b\x44\x24\x20\x48\x89\x44\x60";
        let stock = pe_fixture(&[cli.as_slice(), hub.as_slice()].concat(), 0x8664);
        let p = plan_binary(&stock, TargetKind::AgyCli).unwrap();
        assert_eq!((p.changes, p.existing), (2, 0));
        assert_eq!(p.profile, "agy-x64-cli-hub-v3");
        assert_eq!(
            plan_binary(&p.data, TargetKind::AgyCli).unwrap().existing,
            2
        );
        let mut old = stock.clone();
        old[521..525].copy_from_slice(CLI_GATE_X64_LONG_FIX);
        assert_eq!(
            state_for_data(&old, TargetKind::AgyCli),
            BinaryState::PartiallyPatched
        );
        let dir = tempfile::tempdir().unwrap();
        let target = FoundTarget {
            path: dir.path().join("agy.exe"),
            kind: TargetKind::AgyCli,
            name: "agy".into(),
        };
        fs::write(&target.path, &old).unwrap();
        assert!(patch_target(&target).is_err());
        assert_eq!(fs::read(&target.path).unwrap(), old);
        journal::apply(&target.path, Some(&old), &stock, "fixture-reset").unwrap();
        journal::retire(&target.path, Some(&stock)).unwrap();
        journal::apply(&target.path, Some(&stock), &old, "agy-x64-long-v2").unwrap();
        assert_eq!(patch_target(&target).unwrap(), PatchOutcome::Changed(1));
        assert_eq!(patch_target(&target).unwrap(), PatchOutcome::AlreadyPatched);
        assert_eq!(restore_target(&target).unwrap(), PatchOutcome::Restored);
        assert_eq!(fs::read(&target.path).unwrap(), stock);
        let ambiguous = pe_fixture(
            &[cli.as_slice(), hub.as_slice(), hub.as_slice()].concat(),
            0x8664,
        );
        assert!(plan_binary(&ambiguous, TargetKind::AgyCli).is_err());
    }
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
        let macho = macho_fixture(cli, 0x01000007);
        let patched = plan_binary(&macho, TargetKind::AgyCli).unwrap();
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
    fn official_x64_cli_fixture_patches_supported_gates() {
        let path = std::path::PathBuf::from(std::env::var("AGY_X64_FIXTURE").unwrap());
        let gates = std::env::var("AGY_X64_GATE_COUNT")
            .unwrap_or_else(|_| "2".into())
            .parse::<usize>()
            .unwrap();
        assert!((1..=2).contains(&gates));
        let targets = crate::core::detector::find_targets_in_path(&path);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].kind, TargetKind::AgyCli);
        let stock = fs::read(path).unwrap();
        let hub = plan_binary(&stock, TargetKind::LanguageServer).ok();
        let hub_count = hub.as_ref().map_or(0, |p| p.changes);
        let hub_bytes = hub.as_ref().map_or(0, |p| {
            stock
                .iter()
                .zip(p.data.iter())
                .filter(|(a, b)| a != b)
                .count()
        });
        let patched = plan_binary(&stock, TargetKind::AgyCli).unwrap();
        if let Ok(expected_profile) = std::env::var("AGY_X64_EXPECTED_PROFILE") {
            assert_eq!(patched.profile, expected_profile);
        }
        assert_eq!((patched.changes, patched.existing), (gates + hub_count, 0));
        let counted = plan_binary_mode(&stock, TargetKind::AgyCli, false, Mode::Count).unwrap();
        assert_eq!(
            (counted.changes, counted.existing),
            (patched.changes, patched.existing)
        );
        assert!(matches!(counted.data, Cow::Borrowed(_)));
        assert_eq!(
            stock
                .iter()
                .zip(patched.data.iter())
                .filter(|(a, b)| a != b)
                .count(),
            gates * 4 + hub_bytes
        );
        let repeated = plan_binary(&patched.data, TargetKind::AgyCli).unwrap();
        assert_eq!(
            (repeated.changes, repeated.existing),
            (0, gates + hub_count)
        );
        assert_eq!(repeated.data, patched.data);
        // Optional artifact for live testing in a separate VM. Never overwrite
        // the official input fixture, including through a symlink.
        if let Some(output) = std::env::var_os("AGY_X64_PATCH_OUTPUT") {
            use std::io::Write;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output)
                .unwrap();
            file.write_all(&patched.data).unwrap();
        }
        drop(repeated);
        drop(patched);
        let legacy = plan_binary_with_cli_profile(&stock, TargetKind::AgyCli, true).unwrap();
        assert_eq!((legacy.changes, legacy.existing), (gates, 0));
        // Actual official Mach-O copies exercise codesigning and guarded I/O
        // in macOS CI, with exact stock rollback after a v1 migration.
        for migrate in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let target = FoundTarget {
                path: dir.path().join("agy"),
                kind: TargetKind::AgyCli,
                name: "agy".into(),
            };
            fs::write(&target.path, &stock).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&target.path, fs::Permissions::from_mode(0o755)).unwrap();
            }
            if migrate {
                let signed =
                    prepare_for_write(&target.path, legacy.data.to_vec(), target.kind).unwrap();
                journal::apply(&target.path, Some(&stock), &signed, "agy-x64-long-v1").unwrap();
            }
            assert_eq!(
                patch_target(&target).unwrap(),
                PatchOutcome::Changed(gates + hub_count)
            );
            assert_eq!(patch_target(&target).unwrap(), PatchOutcome::AlreadyPatched);
            assert_eq!(restore_target(&target).unwrap(), PatchOutcome::Restored);
            assert_eq!(fs::read(&target.path).unwrap(), stock);
        }
    }

    #[test]
    fn legacy_x64_cli_requires_an_exact_backup_to_restore() {
        let code = b"\x48\x85\xc0\x0f\x84\x0a\x00\x00\x00\x80\x78\x08\x00\x0f\x85\x00\x00\x00\x00";
        let stock = pe_fixture(code, 0x8664);
        let legacy = plan_binary_with_cli_profile(&stock, TargetKind::AgyCli, true)
            .unwrap()
            .data
            .into_owned();
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
            .data
            .into_owned();
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
            .data
            .into_owned();
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

    fn two_gate_x64_fixture() -> Vec<u8> {
        let gate = b"\x48\x85\xc0\x0f\x84\x0a\x00\x00\x00\x80\x78\x08\x00\x0f\x85\x00\x00\x00\x00";
        let mut code = vec![0xcc; 80];
        code[..gate.len()].copy_from_slice(gate);
        code[48..48 + gate.len()].copy_from_slice(gate);
        pe_fixture(&code, 0x8664)
    }

    fn mixed_x64_fixture(stock: &[u8], second: X64GateState) -> Vec<u8> {
        let mut mixed = stock.to_vec();
        mixed[512..512 + CLI_GATE_X64_LONG_V1_FIX.len()].copy_from_slice(CLI_GATE_X64_LONG_V1_FIX);
        match second {
            X64GateState::Stock => {}
            X64GateState::Legacy => mixed[560..560 + CLI_GATE_X64_LONG_V1_FIX.len()]
                .copy_from_slice(CLI_GATE_X64_LONG_V1_FIX),
            X64GateState::Patched => {
                mixed[569..569 + CLI_GATE_X64_LONG_FIX.len()].copy_from_slice(CLI_GATE_X64_LONG_FIX)
            }
        }
        mixed
    }

    #[test]
    fn x64_cli_mixed_v1_variants_are_partial_and_exact_backup_validation_counts_every_gate() {
        let stock = two_gate_x64_fixture();
        let legacy = plan_binary_with_cli_profile(&stock, TargetKind::AgyCli, true).unwrap();
        assert_eq!((legacy.changes, legacy.existing), (2, 0));
        for second in [
            X64GateState::Stock,
            X64GateState::Legacy,
            X64GateState::Patched,
        ] {
            let mixed = mixed_x64_fixture(&stock, second);
            assert!(is_legacy_x64_cli(&mixed));
            assert_eq!(
                state_for_data(&mixed, TargetKind::AgyCli),
                BinaryState::PartiallyPatched
            );
            assert!(plan_binary(&mixed, TargetKind::AgyCli).is_err());
            assert!(legacy_cli_backup_matches(&stock, &mixed));
            assert!(!legacy_cli_backup_matches(&mixed, &mixed));
            let mut changed = mixed.clone();
            changed[900] = 1;
            assert!(!legacy_cli_backup_matches(&stock, &changed));
            // A changed jump displacement cannot be legitimized by a stock
            // backup even when the v1 pattern has erased the null branch.
            changed = mixed;
            changed[527] = 1;
            assert!(!legacy_cli_backup_matches(&stock, &changed));
        }
        // Do not interpret markers in data sections as executable gates.
        let mut decoy = stock.clone();
        decoy[1024..1033].copy_from_slice(CLI_GATE_X64_LONG_V1_FIX);
        assert!(!is_legacy_x64_cli(&decoy));
        assert_eq!(plan_binary(&decoy, TargetKind::AgyCli).unwrap().changes, 2);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn mixed_x64_cli_refuses_missing_or_partial_backup_and_migrates_with_verified_baseline() {
        let stock = two_gate_x64_fixture();
        for second in [
            X64GateState::Stock,
            X64GateState::Legacy,
            X64GateState::Patched,
        ] {
            for recorded in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let target = FoundTarget {
                    path: dir.path().join("agy.exe"),
                    kind: TargetKind::AgyCli,
                    name: "agy".into(),
                };
                let mixed = mixed_x64_fixture(&stock, second);
                if recorded {
                    fs::write(&target.path, &stock).unwrap();
                    journal::apply(&target.path, Some(&stock), &mixed, "agy-x64-long-v1").unwrap();
                } else {
                    fs::write(&target.path, &mixed).unwrap();
                    assert!(patch_target(&target).is_err());
                    assert_eq!(fs::read(&target.path).unwrap(), mixed);
                    assert!(!journal::has_record(&target.path));
                    fs::write(target.path.with_extension("bak"), &mixed).unwrap();
                    assert!(patch_target(&target).is_err());
                    assert_eq!(fs::read(&target.path).unwrap(), mixed);
                    fs::write(target.path.with_extension("bak"), &stock).unwrap();
                }
                assert_eq!(patch_target(&target).unwrap(), PatchOutcome::Changed(2));
                assert_eq!(check_target_state(&target), BinaryState::Patched);
                let expected = plan_binary(&stock, TargetKind::AgyCli)
                    .unwrap()
                    .data
                    .into_owned();
                assert_eq!(fs::read(&target.path).unwrap(), expected);
                assert_eq!(patch_target(&target).unwrap(), PatchOutcome::AlreadyPatched);
                assert_eq!(restore_target(&target).unwrap(), PatchOutcome::Restored);
                assert_eq!(fs::read(&target.path).unwrap(), stock);
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn old_journal_with_partial_x64_baseline_is_never_used_as_stock() {
        let dir = tempfile::tempdir().unwrap();
        let target = FoundTarget {
            path: dir.path().join("agy.exe"),
            kind: TargetKind::AgyCli,
            name: "agy".into(),
        };
        let stock = two_gate_x64_fixture();
        let mixed = mixed_x64_fixture(&stock, X64GateState::Stock);
        let mut recorded = mixed.clone();
        recorded[569..573].copy_from_slice(CLI_GATE_X64_LONG_FIX);
        fs::write(&target.path, &mixed).unwrap();
        journal::apply(&target.path, Some(&mixed), &recorded, "agy-x64-long-v2").unwrap();
        for action in [patch_target, restore_target] {
            assert!(action(&target).is_err());
            assert_eq!(fs::read(&target.path).unwrap(), recorded);
            assert!(journal::has_record(&target.path));
        }
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn stock_v2_partial_x64_does_not_become_a_new_backup_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let target = FoundTarget {
            path: dir.path().join("agy.exe"),
            kind: TargetKind::AgyCli,
            name: "agy".into(),
        };
        let stock = two_gate_x64_fixture();
        let mut partial = stock.clone();
        partial[521..525].copy_from_slice(CLI_GATE_X64_LONG_FIX);
        fs::write(&target.path, &partial).unwrap();
        assert_eq!(check_target_state(&target), BinaryState::PartiallyPatched);
        assert!(patch_target(&target).is_err());
        assert_eq!(fs::read(&target.path).unwrap(), partial);
        assert!(!journal::has_record(&target.path));
        fs::write(target.path.with_extension("bak"), &stock).unwrap();
        assert_eq!(patch_target(&target).unwrap(), PatchOutcome::Changed(2));
        assert_eq!(restore_target(&target).unwrap(), PatchOutcome::Restored);
        assert_eq!(fs::read(&target.path).unwrap(), stock);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn interrupted_mixed_x64_migration_keeps_stock_backup_and_recovers() {
        let dir = tempfile::tempdir().unwrap();
        let target = FoundTarget {
            path: dir.path().join("agy.exe"),
            kind: TargetKind::AgyCli,
            name: "agy".into(),
        };
        let stock = two_gate_x64_fixture();
        let mixed = mixed_x64_fixture(&stock, X64GateState::Stock);
        let complete = plan_binary(&stock, TargetKind::AgyCli)
            .unwrap()
            .data
            .into_owned();
        fs::write(&target.path, &stock).unwrap();
        journal::apply(&target.path, Some(&stock), &mixed, "agy-x64-long-v1").unwrap();
        journal::apply_continuing(&target.path, &mixed, &complete, "agy-x64-long-v2").unwrap();
        // Journal advanced to v2 but the old executable survived the write.
        fs::write(&target.path, &mixed).unwrap();
        assert_eq!(patch_target(&target).unwrap(), PatchOutcome::Changed(2));
        assert_eq!(fs::read(&target.path).unwrap(), complete);
        assert_eq!(restore_target(&target).unwrap(), PatchOutcome::Restored);
        assert_eq!(fs::read(&target.path).unwrap(), stock);
    }

    #[test]
    fn mixed_x64_legacy_backup_rolls_back_every_gate_without_guessing() {
        let stock = two_gate_x64_fixture();
        for second in [
            X64GateState::Stock,
            X64GateState::Legacy,
            X64GateState::Patched,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let target = FoundTarget {
                path: dir.path().join("agy.exe"),
                kind: TargetKind::AgyCli,
                name: "agy".into(),
            };
            let mixed = mixed_x64_fixture(&stock, second);
            fs::write(&target.path, &mixed).unwrap();
            fs::write(target.path.with_extension("bak"), &stock).unwrap();
            assert_eq!(restore_target(&target).unwrap(), PatchOutcome::Restored);
            assert_eq!(fs::read(&target.path).unwrap(), stock);
            assert_eq!(restore_target(&target).unwrap(), PatchOutcome::AlreadyStock);
        }
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn rollback_after_app_update_keeps_new_stock_and_archives_old_record() {
        for repatch in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let target = FoundTarget {
                path: dir.path().join("agy.exe"),
                kind: TargetKind::AgyCli,
                name: "agy".into(),
            };
            let old = two_gate_x64_fixture();
            fs::write(&target.path, &old).unwrap();
            assert_eq!(patch_target(&target).unwrap(), PatchOutcome::Changed(2));
            let mut updated = old.clone();
            updated[900] = 2;
            fs::write(&target.path, &updated).unwrap();
            if repatch {
                assert_eq!(patch_target(&target).unwrap(), PatchOutcome::Changed(2));
                assert_eq!(restore_target(&target).unwrap(), PatchOutcome::Restored);
            } else {
                assert_eq!(restore_target(&target).unwrap(), PatchOutcome::AlreadyStock);
            }
            assert_eq!(fs::read(&target.path).unwrap(), updated);
            assert!(!journal::has_record(&target.path));
            let backup_dir = dir.path().join("agy.exe.ag-backups");
            assert_eq!(
                fs::read(backup_dir.join(format!("{}.bin", journal::digest(&old)))).unwrap(),
                old
            );
            assert_eq!(restore_target(&target).unwrap(), PatchOutcome::AlreadyStock);
        }
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn rollback_after_unknown_update_preserves_file_record_and_backup() {
        let dir = tempfile::tempdir().unwrap();
        let target = FoundTarget {
            path: dir.path().join("agy.exe"),
            kind: TargetKind::AgyCli,
            name: "agy".into(),
        };
        let stock = two_gate_x64_fixture();
        fs::write(&target.path, &stock).unwrap();
        patch_target(&target).unwrap();
        let backup_dir = dir.path().join("agy.exe.ag-backups");
        let record = fs::read(backup_dir.join("current.json")).unwrap();
        let updated = pe_fixture(b"unsupported instructions", 0x8664);
        fs::write(&target.path, &updated).unwrap();
        assert!(restore_target(&target).is_err());
        assert_eq!(fs::read(&target.path).unwrap(), updated);
        assert_eq!(fs::read(backup_dir.join("current.json")).unwrap(), record);
        assert_eq!(
            fs::read(backup_dir.join(format!("{}.bin", journal::digest(&stock)))).unwrap(),
            stock
        );
    }

    const ARM64_CORE: &[u8] = b"\x03\x20\x40\x39\xa3\x01\x00\x36\xe3\x13\x48\xa9\x03\x10\x06\xa9";
    const ARM64_LOGIN: &[u8] =
        b"\x01\x03\x00\xb5\x60\x02\x00\xb4\x02\x20\x40\x39\x22\x02\x00\x37\xf4\xff\xff\x97";
    const ARM64_LOGIN_OFFSET: usize = 64;

    fn arm64_cli_fixture(core: &[u8]) -> Vec<u8> {
        let mut code = vec![0u8; 192];
        code[..core.len()].copy_from_slice(core);
        code[ARM64_LOGIN_OFFSET..ARM64_LOGIN_OFFSET + ARM64_LOGIN.len()]
            .copy_from_slice(ARM64_LOGIN);
        macho_fixture(&code, 0x0100000c)
    }

    #[test]
    fn counting_matches_the_full_plan_without_copying() {
        let manager = b"\x80\x78\x08\x00\x74\x0a\x48\x8b\x44\x24\x20\x48\x89\x44\x60";
        let gate = b"\x48\x85\xc0\x0f\x84\x0a\x00\x00\x00\x80\x78\x08\x00\x0f\x85\x00\x00\x00\x00";
        let cases: Vec<(Vec<u8>, TargetKind)> = vec![
            (pe_fixture(manager, 0x8664), TargetKind::LanguageServer),
            (
                pe_fixture(&[gate.as_slice(), manager.as_slice()].concat(), 0x8664),
                TargetKind::AgyCli,
            ),
            (macho_fixture(gate, 0x01000007), TargetKind::AgyCli),
            (arm64_cli_fixture(ARM64_CORE), TargetKind::AgyCli),
            (
                pe_fixture(b"\x90\x90\x90\x90", 0x8664),
                TargetKind::LanguageServer,
            ),
            (
                b"x.resetIsTierGCPTos(), this.isGoogleInternal".to_vec(),
                TargetKind::IdeMainJs,
            ),
        ];
        for (stock, kind) in cases {
            let full = plan_mode(&stock, kind, Mode::Apply);
            let counted = plan_mode(&stock, kind, Mode::Count);
            match (&full, &counted) {
                (Ok(full), Ok(counted)) => {
                    assert_eq!(
                        (full.changes, full.existing),
                        (counted.changes, counted.existing)
                    );
                    assert!(matches!(counted.data, Cow::Borrowed(_)));
                    // The patched result counts the same way as well.
                    let patched = full.data.to_vec();
                    let again = plan_mode(&patched, kind, Mode::Apply).unwrap();
                    let again_counted = plan_mode(&patched, kind, Mode::Count).unwrap();
                    assert_eq!(
                        (again.changes, again.existing),
                        (again_counted.changes, again_counted.existing)
                    );
                }
                (Err(full), Err(counted)) => assert_eq!(full, counted),
                _ => panic!("modes disagree for {kind:?}"),
            }
        }
    }

    #[test]
    fn counting_falls_back_when_the_core_edit_touches_the_sign_in_gate() {
        // A sign-in gate match that overlaps the core edit is counted from the
        // patched bytes, exactly as the full plan does.
        let edit = 100;
        let mut bytes = vec![0u8; 256];
        assert!(!core_edit_touches_login(&bytes, &[edit], &[]));
        assert!(core_edit_touches_login(&bytes, &[edit], &[edit + 4]));
        assert!(core_edit_touches_login(&bytes, &[edit], &[edit - 19]));
        assert!(!core_edit_touches_login(&bytes, &[edit], &[edit - 20]));
        assert!(!core_edit_touches_login(&bytes, &[edit], &[edit + 8]));
        bytes[edit..edit + 4].copy_from_slice(b"\x00\x00\x00\x00");
        // An edit near the end of the section only looks at the bytes it has.
        assert!(!core_edit_touches_login(&bytes, &[240], &[]));
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
                let mut original = arm64_cli_fixture(&code);
                // A matching sequence outside __text must remain untouched.
                original[800..800 + code.len()].copy_from_slice(&code);
                original[850..850 + ARM64_LOGIN.len()].copy_from_slice(ARM64_LOGIN);
                let patched = plan_binary(&original, TargetKind::AgyCli).unwrap();
                assert_eq!(patched.profile, "agy-arm64-v2");
                assert_eq!((patched.changes, patched.existing), (2, 0));
                let mut expected = original.clone();
                expected[512..520].copy_from_slice(b"\x23\x00\x80\x52\x03\x20\x00\x39");
                let login = 512 + ARM64_LOGIN_OFFSET + CLI_GATE_ARM64_FIX_AT;
                expected[login..login + 4].copy_from_slice(CLI_GATE_ARM64_FIX);
                assert_eq!(patched.data, expected);
                let repeated = plan_binary(&patched.data, TargetKind::AgyCli).unwrap();
                assert_eq!((repeated.changes, repeated.existing), (0, 2));
                assert_eq!(repeated.data, patched.data);
            }
        }
    }

    #[test]
    fn macho_arm64_cli_rejects_missing_ambiguous_and_wrong_architecture_gates() {
        let stock = arm64_cli_fixture(ARM64_CORE);
        let patched = plan_binary(&stock, TargetKind::AgyCli).unwrap();
        let login = 512 + ARM64_LOGIN_OFFSET;
        for base in [&stock, &patched.data.to_vec()] {
            for (offset, length) in [(512, ARM64_CORE.len()), (login, ARM64_LOGIN.len())] {
                let mut missing = base.clone();
                missing[offset..offset + length].fill(0);
                assert!(plan_binary(&missing, TargetKind::AgyCli).is_err());
            }
            for source in [&stock, &patched.data.to_vec()] {
                for (offset, length, copy) in [
                    (512, ARM64_CORE.len(), 512 + 32),
                    (login, ARM64_LOGIN.len(), login + 32),
                ] {
                    let mut ambiguous = base.clone();
                    ambiguous[copy..copy + length]
                        .copy_from_slice(&source[offset..offset + length]);
                    assert!(plan_binary(&ambiguous, TargetKind::AgyCli).is_err());
                }
            }
        }
        let mut wrong_arch = stock;
        wrong_arch[4..8].copy_from_slice(&0x01000007u32.to_le_bytes());
        assert!(plan_binary(&wrong_arch, TargetKind::AgyCli).is_err());
    }

    #[test]
    fn arm64_login_rejects_changed_control_flow_and_unaligned_instructions() {
        let stock = arm64_cli_fixture(ARM64_CORE);
        let login = 512 + ARM64_LOGIN_OFFSET;
        // Alter success/error targets, the called routine, the register or bit.
        for (at, instruction) in [
            (4, 0xb4000280u32), // null and eligible branches differ
            (0, 0xb5000f01),    // error target outside __text
            (0, 0xb5000281),    // error and success paths collapse
            (4, 0xb4fffe00),    // backward null branch
            (16, 0x9400ffff),   // call outside __text
            (12, 0x37080222),   // tests bit 1 instead of eligibility bit 0
            (8, 0x39402003),    // flag loaded into a different register
        ] {
            let mut invalid = stock.clone();
            invalid[login + at..login + at + 4].copy_from_slice(&instruction.to_le_bytes());
            assert!(plan_binary(&invalid, TargetKind::AgyCli).is_err());
        }
        for (at, size) in [(512, ARM64_CORE.len()), (login, ARM64_LOGIN.len())] {
            let mut invalid = stock.clone();
            invalid[at..at + size + 1].fill(0);
            invalid[at + 1..at + size + 1].copy_from_slice(&stock[at..at + size]);
            assert!(plan_binary(&invalid, TargetKind::AgyCli).is_err());
        }
        let mut invalid = stock;
        invalid[136..144].copy_from_slice(&1u64.to_le_bytes()); // section virtual address
        assert!(plan_binary(&invalid, TargetKind::AgyCli).is_err());
    }

    #[test]
    fn arm64_old_patch_is_partial_and_language_server_keeps_its_profile() {
        let stock = arm64_cli_fixture(ARM64_CORE);
        let legacy = plan_binary_with_cli_profile(&stock, TargetKind::AgyCli, true).unwrap();
        assert_eq!((legacy.changes, legacy.existing), (1, 0));
        assert_eq!(legacy.profile, "agy-arm64-v1");
        let upgrade = plan_binary(&legacy.data, TargetKind::AgyCli).unwrap();
        assert_eq!((upgrade.changes, upgrade.existing), (1, 1));
        assert_eq!(
            state_from_counts(upgrade.changes, upgrade.existing),
            BinaryState::PartiallyPatched
        );
        assert_eq!(
            upgrade.data,
            plan_binary(&stock, TargetKind::AgyCli).unwrap().data
        );
        let core = plan_binary(&stock, TargetKind::LanguageServer).unwrap();
        assert_eq!(core.profile, "core-arm64-v1");
        assert_eq!(core.data, legacy.data);
    }

    #[test]
    #[ignore = "set AGY_ARM64_FIXTURE to an extracted official agy binary"]
    fn official_arm64_cli_fixture_patches_login_and_migrates_v1() {
        let path = std::path::PathBuf::from(std::env::var("AGY_ARM64_FIXTURE").unwrap());
        let targets = crate::core::detector::find_targets_in_path(&path);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].kind, TargetKind::AgyCli);
        let stock = fs::read(path).unwrap();
        let patched = plan_binary(&stock, TargetKind::AgyCli).unwrap();
        assert_eq!((patched.changes, patched.existing), (2, 0));
        let counted = plan_binary_mode(&stock, TargetKind::AgyCli, false, Mode::Count).unwrap();
        assert_eq!(
            (counted.changes, counted.existing),
            (patched.changes, patched.existing)
        );
        assert!(matches!(counted.data, Cow::Borrowed(_)));
        let mut expected = stock.clone();
        let file = object::File::parse(stock.as_slice()).unwrap();
        for section in file.sections().filter(|s| s.kind() == SectionKind::Text) {
            let (start, size) = section.file_range().unwrap();
            let start = start as usize;
            let bytes = &stock[start..start + size as usize];
            for m in regex_mgr_arm64_orig().find_iter(bytes) {
                let at = start + m.start();
                expected[at..at + MGR_GATE_ARM64_FIX.len()].copy_from_slice(MGR_GATE_ARM64_FIX);
            }
            for m in regex_cli_arm64_orig().find_iter(bytes) {
                let at = start + m.start() + CLI_GATE_ARM64_FIX_AT;
                expected[at..at + CLI_GATE_ARM64_FIX.len()].copy_from_slice(CLI_GATE_ARM64_FIX);
            }
        }
        // No other bytes, including nil/error branches and Mach-O metadata, change.
        assert_eq!(patched.data, expected);
        drop(expected);
        let legacy = plan_binary_with_cli_profile(&stock, TargetKind::AgyCli, true).unwrap();
        assert_eq!((legacy.changes, legacy.existing), (1, 0));
        let upgrade = plan_binary(&legacy.data, TargetKind::AgyCli).unwrap();
        assert_eq!((upgrade.changes, upgrade.existing), (1, 1));
        assert_eq!(upgrade.data, patched.data);
        let repeated = plan_binary(&patched.data, TargetKind::AgyCli).unwrap();
        assert_eq!((repeated.changes, repeated.existing), (0, 2));
        assert_eq!(repeated.data, patched.data);
        drop(upgrade);
        drop(repeated);
        drop(patched);

        // Use disposable official Mach-O files so macOS CI also exercises the
        // actual codesign path and rollback, rather than signing synthetic data.
        for migrate in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let target = FoundTarget {
                path: dir.path().join("agy"),
                kind: TargetKind::AgyCli,
                name: "agy".into(),
            };
            fs::write(&target.path, &stock).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&target.path, fs::Permissions::from_mode(0o755)).unwrap();
            }
            if migrate {
                let signed =
                    prepare_for_write(&target.path, legacy.data.to_vec(), target.kind).unwrap();
                journal::apply(&target.path, Some(&stock), &signed, "agy-arm64-v1").unwrap();
            }
            assert_eq!(
                patch_target(&target).unwrap(),
                PatchOutcome::Changed(if migrate { 1 } else { 2 })
            );
            assert_eq!(patch_target(&target).unwrap(), PatchOutcome::AlreadyPatched);
            assert_eq!(restore_target(&target).unwrap(), PatchOutcome::Restored);
            assert_eq!(fs::read(&target.path).unwrap(), stock);
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn arm64_target(dir: &Path) -> FoundTarget {
        FoundTarget {
            path: dir.join("agy"),
            kind: TargetKind::AgyCli,
            name: "agy".into(),
        }
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn arm64_cli_upgrade_preserves_original_journal_and_exact_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let target = arm64_target(dir.path());
        let stock = arm64_cli_fixture(ARM64_CORE);
        let legacy = plan_binary_with_cli_profile(&stock, TargetKind::AgyCli, true)
            .unwrap()
            .data
            .into_owned();
        fs::write(&target.path, &stock).unwrap();
        journal::apply(&target.path, Some(&stock), &legacy, "agy-arm64-v1").unwrap();
        assert_eq!(check_target_state(&target), BinaryState::PartiallyPatched);
        assert_eq!(patch_target(&target).unwrap(), PatchOutcome::Changed(1));
        assert_eq!(check_target_state(&target), BinaryState::Patched);
        assert_eq!(patch_target(&target).unwrap(), PatchOutcome::AlreadyPatched);
        assert_eq!(restore_target(&target).unwrap(), PatchOutcome::Restored);
        assert_eq!(fs::read(&target.path).unwrap(), stock);
        assert_eq!(restore_target(&target).unwrap(), PatchOutcome::AlreadyStock);
        assert!(!journal::has_record(&target.path));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn arm64_cli_upgrade_without_journal_requires_exact_legacy_backup() {
        let dir = tempfile::tempdir().unwrap();
        let target = arm64_target(dir.path());
        let stock = arm64_cli_fixture(ARM64_CORE);
        let legacy = plan_binary_with_cli_profile(&stock, TargetKind::AgyCli, true)
            .unwrap()
            .data
            .into_owned();
        fs::write(&target.path, &legacy).unwrap();
        for backup in [None, Some(b"unrelated".as_slice())] {
            if let Some(bytes) = backup {
                fs::write(target.path.with_extension("bak"), bytes).unwrap();
            }
            assert!(patch_target(&target)
                .unwrap_err()
                .contains("точный исходный backup"));
            assert_eq!(fs::read(&target.path).unwrap(), legacy);
            assert!(!journal::has_record(&target.path));
        }
        fs::write(target.path.with_extension("bak"), &stock).unwrap();
        assert_eq!(patch_target(&target).unwrap(), PatchOutcome::Changed(2));
        assert_eq!(restore_target(&target).unwrap(), PatchOutcome::Restored);
        assert_eq!(fs::read(&target.path).unwrap(), stock);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn arm64_cli_upgrade_refuses_corrupt_backup_journal_or_user_changes() {
        for failure in ["backup", "journal", "user-edit"] {
            let dir = tempfile::tempdir().unwrap();
            let target = arm64_target(dir.path());
            let stock = arm64_cli_fixture(ARM64_CORE);
            let legacy = plan_binary_with_cli_profile(&stock, TargetKind::AgyCli, true)
                .unwrap()
                .data
                .into_owned();
            fs::write(&target.path, &stock).unwrap();
            journal::apply(&target.path, Some(&stock), &legacy, "agy-arm64-v1").unwrap();
            let backup_dir = dir.path().join("agy.ag-backups");
            match failure {
                "backup" => fs::write(
                    backup_dir.join(format!("{}.bin", journal::digest(&stock))),
                    b"corrupt",
                )
                .unwrap(),
                "journal" => fs::write(backup_dir.join("current.json"), b"corrupt").unwrap(),
                _ => {
                    let mut edited = legacy;
                    edited[900] = 1;
                    fs::write(&target.path, edited).unwrap();
                }
            }
            let before = fs::read(&target.path).unwrap();
            let record = fs::read(backup_dir.join("current.json")).unwrap();
            assert!(patch_target(&target).is_err(), "{failure}");
            assert_eq!(fs::read(&target.path).unwrap(), before);
            assert_eq!(fs::read(backup_dir.join("current.json")).unwrap(), record);
        }
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn arm64_cli_upgrade_recovers_interrupted_write_and_new_upstream_baseline() {
        for interrupted in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let target = arm64_target(dir.path());
            let stock = arm64_cli_fixture(ARM64_CORE);
            let legacy = plan_binary_with_cli_profile(&stock, TargetKind::AgyCli, true)
                .unwrap()
                .data
                .into_owned();
            fs::write(&target.path, &stock).unwrap();
            journal::apply(&target.path, Some(&stock), &legacy, "agy-arm64-v1").unwrap();
            let mut baseline = stock;
            if interrupted {
                let complete = plan_binary(&legacy, TargetKind::AgyCli)
                    .unwrap()
                    .data
                    .into_owned();
                journal::apply_continuing(&target.path, &legacy, &complete, "agy-arm64-v2")
                    .unwrap();
                // Journal was committed, but the executable replacement did not finish.
                fs::write(&target.path, &legacy).unwrap();
            } else {
                // An upstream replacement with unpatched gates starts a new backup baseline.
                baseline[900] = 1;
                fs::write(&target.path, &baseline).unwrap();
            }
            assert_eq!(
                patch_target(&target).unwrap(),
                PatchOutcome::Changed(if interrupted { 1 } else { 2 })
            );
            assert_eq!(restore_target(&target).unwrap(), PatchOutcome::Restored);
            assert_eq!(fs::read(&target.path).unwrap(), baseline);
        }
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn unsupported_arm64_cli_never_changes_executable_or_creates_backup() {
        let dir = tempfile::tempdir().unwrap();
        let target = arm64_target(dir.path());
        let mut stock = arm64_cli_fixture(ARM64_CORE);
        stock[512 + ARM64_LOGIN_OFFSET..512 + ARM64_LOGIN_OFFSET + ARM64_LOGIN.len()].fill(0);
        fs::write(&target.path, &stock).unwrap();
        assert!(patch_target(&target).is_err());
        assert_eq!(fs::read(&target.path).unwrap(), stock);
        assert!(!dir.path().join("agy.ag-backups").exists());
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
        let mut duplicate: Cow<[u8]> = Cow::Owned([bytes.as_slice(), bytes.as_slice()].concat());
        let whole = 0..duplicate.len();
        assert!(apply_pattern(
            &mut duplicate,
            whole.clone(),
            regex_cli_x64_long_orig(),
            regex_cli_x64_long_patched(),
            CLI_GATE_X64_LONG_FIX,
            CLI_GATE_X64_LONG_FIX_AT,
            1
        )
        .is_err());
        let (changes, existing) = apply_pattern(
            &mut duplicate,
            whole,
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

    #[test]
    fn read_only_checks_borrow_the_input_and_defer_the_digest() {
        let code = b"\x80\x78\x08\x00\x74\x0a\x48\x8b\x44\x24\x20\x48\x89\x44\x60";
        let stock = pe_fixture(code, 0x8664);
        let patched = plan_binary(&stock, TargetKind::LanguageServer).unwrap();
        assert!(matches!(patched.data, Cow::Owned(_)));
        let again = plan_binary(&patched.data, TargetKind::LanguageServer).unwrap();
        assert_eq!((again.changes, again.existing), (0, 1));
        assert!(matches!(again.data, Cow::Borrowed(_)));

        let unsupported = pe_fixture(b"\x90\x90\x90\x90", 0x8664);
        let error = plan_binary(&unsupported, TargetKind::LanguageServer)
            .err()
            .unwrap();
        assert!(error.contains(DIGEST_PLACEHOLDER));
        let digest = journal::digest(&unsupported);
        assert!(with_digest(error, &unsupported).ends_with(&digest));

        let dir = tempfile::tempdir().unwrap();
        let target = FoundTarget {
            path: dir.path().join("language_server.exe"),
            kind: TargetKind::LanguageServer,
            name: "language_server".into(),
        };
        fs::write(&target.path, &unsupported).unwrap();
        let reported = patch_target(&target).unwrap_err();
        assert!(reported.ends_with(&digest), "{reported}");
        assert_eq!(fs::read(&target.path).unwrap(), unsupported);
    }

    #[test]
    fn cached_state_follows_a_replaced_file() {
        fn stamp(path: &Path, seconds: u64) {
            let at = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(seconds);
            fs::File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_modified(at)
                .unwrap();
        }
        let code = b"\x80\x78\x08\x00\x74\x0a\x48\x8b\x44\x24\x20\x48\x89\x44\x60";
        let stock = pe_fixture(code, 0x8664);
        let patched = plan_binary(&stock, TargetKind::LanguageServer)
            .unwrap()
            .data
            .into_owned();
        assert_eq!(stock.len(), patched.len());
        let dir = tempfile::tempdir().unwrap();
        let target = FoundTarget {
            path: dir.path().join("language_server.exe"),
            kind: TargetKind::LanguageServer,
            name: "language_server".into(),
        };
        fs::write(&target.path, &stock).unwrap();
        stamp(&target.path, 1_700_000_000);
        assert_eq!(check_target_state(&target), BinaryState::Stock);
        assert_eq!(check_target_state(&target), BinaryState::Stock);
        fs::write(&target.path, &patched).unwrap();
        stamp(&target.path, 1_700_000_001);
        assert_eq!(check_target_state(&target), BinaryState::Patched);

        // A failed read is not remembered for the unchanged file.
        let missing = FoundTarget {
            path: dir.path().join("absent.exe"),
            kind: TargetKind::LanguageServer,
            name: "absent".into(),
        };
        assert_eq!(check_target_state(&missing), BinaryState::Unknown);
        assert!(STATES
            .lock()
            .unwrap()
            .as_ref()
            .is_none_or(|cache| !cache.contains_key(&(missing.path.clone(), missing.kind))));
    }

    #[cfg(windows)]
    #[test]
    fn a_briefly_locked_file_is_read_again_on_the_next_refresh() {
        use std::os::windows::fs::OpenOptionsExt;
        let code = b"\x80\x78\x08\x00\x74\x0a\x48\x8b\x44\x24\x20\x48\x89\x44\x60";
        let dir = tempfile::tempdir().unwrap();
        let target = FoundTarget {
            path: dir.path().join("language_server.exe"),
            kind: TargetKind::LanguageServer,
            name: "language_server".into(),
        };
        fs::write(&target.path, pe_fixture(code, 0x8664)).unwrap();
        // Share mode 0 denies other readers, like an exclusive updater lock.
        let lock = fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&target.path)
            .unwrap();
        assert_eq!(check_target_state(&target), BinaryState::Unknown);
        drop(lock);
        assert_eq!(check_target_state(&target), BinaryState::Stock);
    }
}
