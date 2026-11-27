//! Structured, allowlisted record of the latest setup/rollback attempt.
//! Persists only fixed codes, basenames, OS error numbers and known Google hostnames;
//! never stores raw error strings, paths or user-controlled configuration.

use crate::{
    core::detector::TargetKind,
    net::{self, config},
    system::fs_utils::robust_write_file,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    cell::Cell,
    fs,
    path::{Path, PathBuf},
};

const FILE_NAME: &str = "last-attempt.json";
const MAX_ERRORS: usize = 16;

thread_local! {
    static STAGING_ROLLBACK: Cell<Option<bool>> = const { Cell::new(None) };
    #[cfg(target_os = "macos")]
    static XATTR_ERRORS: std::cell::RefCell<Vec<StepError>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Called by staged updates when an automatic rollback executes.
/// `Some(false)` takes precedence over `Some(true)` if multiple rollbacks ran.
pub fn note_staging_rollback(ok: bool) {
    STAGING_ROLLBACK.with(|slot| {
        let next = match slot.get() {
            Some(false) => Some(false),
            _ => Some(ok),
        };
        slot.set(next);
    });
}

fn take_staging_rollback() -> Option<bool> {
    STAGING_ROLLBACK.with(|slot| slot.replace(None))
}

#[cfg(target_os = "macos")]
pub(crate) fn note_xattr_error(path: &Path, error: &std::io::Error) {
    let file_name = safe_file_name(path);
    net::relay::log_event(&format!(
        "Не удалось удалить com.apple.quarantine с {}: {error}",
        file_name.as_deref().unwrap_or("временного файла"),
    ));
    XATTR_ERRORS.with_borrow_mut(|errors| {
        if errors.len() < MAX_ERRORS {
            errors.push(StepError {
                step: "post_write".into(),
                reason: "xattr_failed".into(),
                component: None,
                file_name,
                host: None,
                os_error: error.raw_os_error(),
            });
        }
    });
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Unlock,
    PatchFiles,
    Dns,
    Rollback,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AttemptOutcome {
    Complete,
    Limited,
    Failed,
    Stopped,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StepError {
    pub step: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_error: Option<i32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttemptRecord {
    pub schema_version: u32,
    pub bypass_version: String,
    pub operation: Operation,
    pub timestamp_ms: u64,
    pub outcome: AttemptOutcome,
    pub first_error: Option<StepError>,
    pub errors: Vec<StepError>,
    pub rollback_performed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback_ok: Option<bool>,
}

pub struct AttemptRecorder {
    operation: Operation,
    errors: Vec<StepError>,
    rollback: Option<bool>,
    saved: bool,
}

impl AttemptRecorder {
    pub fn start(operation: Operation) -> Self {
        let _ = take_staging_rollback();
        #[cfg(target_os = "macos")]
        XATTR_ERRORS.with_borrow_mut(Vec::clear);
        Self {
            operation,
            errors: Vec::new(),
            rollback: None,
            saved: false,
        }
    }

    pub fn absorb_staging_rollback(&mut self) {
        if let Some(ok) = take_staging_rollback() {
            self.rollback = match self.rollback {
                Some(false) => Some(false),
                _ => Some(ok),
            };
        }
    }

    pub fn record_error(
        &mut self,
        step: &'static str,
        cause: &str,
        component: Option<TargetKind>,
        path: Option<&Path>,
    ) {
        self.absorb_staging_rollback();
        if self.errors.len() >= MAX_ERRORS {
            return;
        }
        let error = classify_error(step, cause, component, path);
        self.errors.push(error);
    }

    pub fn record_reason(&mut self, step: &'static str, reason: &'static str) {
        self.absorb_staging_rollback();
        if self.errors.len() >= MAX_ERRORS {
            return;
        }
        self.errors.push(StepError {
            step: step.into(),
            reason: reason.into(),
            component: None,
            file_name: None,
            host: None,
            os_error: None,
        });
    }

    pub fn finish(mut self, outcome: AttemptOutcome) {
        self.absorb_staging_rollback();
        #[cfg(target_os = "macos")]
        XATTR_ERRORS.with_borrow_mut(|errors| {
            let remaining = MAX_ERRORS.saturating_sub(self.errors.len());
            self.errors.extend(errors.drain(..).take(remaining));
        });
        let record = AttemptRecord {
            schema_version: 1,
            bypass_version: env!("CARGO_PKG_VERSION").into(),
            operation: self.operation,
            timestamp_ms: net::route_health::now_ms(),
            outcome,
            first_error: self.errors.first().cloned(),
            errors: std::mem::take(&mut self.errors),
            rollback_performed: self.rollback.is_some(),
            rollback_ok: self.rollback,
        };
        self.saved = true;
        let _ = save_record(&record_path(), &record);
    }
}

impl Drop for AttemptRecorder {
    fn drop(&mut self) {
        let _ = take_staging_rollback();
    }
}

fn record_path() -> PathBuf {
    config::directory().join(FILE_NAME)
}

fn save_record(path: &Path, record: &AttemptRecord) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let bytes = serde_json::to_vec_pretty(record).map_err(|e| e.to_string())?;
    robust_write_file(path, &bytes)
}

pub(super) fn safe_file_name(path: &Path) -> Option<String> {
    let raw = path.file_name()?.to_string_lossy();
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '/' | '\\'))
        .take(128)
        .collect();
    (!cleaned.is_empty()).then_some(cleaned)
}

fn extract_os_error(cause: &str) -> Option<i32> {
    let (_, rest) = cause.split_once("(os error ")?;
    let (digits, _) = rest.split_once(')')?;
    digits.trim().parse().ok()
}

fn extract_known_host(cause: &str) -> Option<String> {
    let lower = cause.to_ascii_lowercase();
    net::provider::NRPT_AGENT
        .iter()
        .chain(net::provider::SUBSTITUTION_CANARIES.iter())
        .find(|host| lower.contains(&host.to_ascii_lowercase()))
        .map(|host| (*host).to_owned())
}

fn is_app_management_eperm(path: Option<&Path>, cause: &str) -> bool {
    extract_os_error(cause) == Some(1)
        && (cause.starts_with("Защита «Управление приложениями»")
            || path.is_some_and(|p| {
                p.ancestors()
                    .any(|dir| dir.extension().is_some_and(|ext| ext == "app"))
            }))
}

pub fn classify_error(
    step: &'static str,
    cause: &str,
    component: Option<TargetKind>,
    path: Option<&Path>,
) -> StepError {
    let os_error = extract_os_error(cause);
    let lower = cause.to_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| lower.contains(w));

    let reason = if is_app_management_eperm(path, cause) {
        "app_management_blocked"
    } else if has(&["gatekeeper заблокировал запуск"]) {
        "gatekeeper_rejected"
    } else if has(&["пробный запуск antigravity не удался"]) {
        "app_launch_failed"
    } else if step == "verify_app" {
        "app_launch_unverified"
    } else if has(&["integrity"]) {
        "asar_integrity"
    } else if has(&["старый или смешанный патч", "старый патч диагностической"])
    {
        "legacy_patch_missing_backup"
    } else if has(&["частичный патч"]) {
        "partial_patch_missing_backup"
    } else if has(&["не поддерживается"]) {
        "unsupported_version"
    } else if has(&["неоднозначная"]) {
        "ambiguous_signature"
    } else if has(&["символическая ссылка"]) {
        "symlink_target"
    } else if has(&[
        "закройте antigravity",
        "всё ещё используются",
        "запущен из antigravity",
    ]) {
        "application_open"
    } else if has(&["повреждены границы блока hosts", "нет конца блока hosts"])
    {
        "hosts_block_damaged"
    } else if has(&["hosts"])
        && (matches!(os_error, Some(5 | 13))
            || has(&[
                "отказано в доступе",
                "access is denied",
                "permission denied",
            ]))
    {
        "hosts_access_denied"
    } else if has(&["lsof", "проверка открытых файлов", "restart manager"]) {
        "file_lock_check_failed"
    } else if has(&["порт 53"]) {
        "port_53_busy"
    } else if has(&["не подтвердил готовность", "не подтвердила готовность"])
    {
        "relay_not_ready"
    } else if has(&["a-ответ для agent"]) {
        "relay_no_agent_answer"
    } else if has(&["a-ответ для браузерных"]) {
        "relay_no_browser_answer"
    } else if has(&["dns-провайдер обхода (doh) не ответил"]) {
        "doh_unreachable"
    } else if has(&["dns не вернул адресов"]) {
        "route_no_addresses"
    } else if has(&["нет tcp-подключения"]) {
        "route_tcp_failed"
    } else if has(&["обрыв tls"]) {
        "route_tls_failed"
    } else if has(&["сертификат не прошёл"]) {
        "route_certificate_failed"
    } else if has(&["ошибкой http 5xx"]) {
        "route_http_failed"
    } else if has(&["не удалось подобрать маршрут", "проверенного маршрута"])
    {
        "route_discovery_failed"
    } else if has(&["физический выход в интернет", "физический адаптер"])
    {
        "no_physical_egress"
    } else if has(&["уже существует dns-настройка"]) {
        "dns_conflict"
    } else if has(&["уже обновляются другим процессом"]) {
        "network_lock_busy"
    } else if has(&[
        "launchctl",
        "schtasks",
        "systemctl",
        "бинарник службы",
        "plist",
    ]) {
        "service_install_failed"
    } else if matches!(os_error, Some(32))
        || has(&[
            "используется другим процессом",
            "being used by another process",
        ])
    {
        "file_in_use"
    } else if matches!(os_error, Some(5 | 13))
        || has(&[
            "отказано в доступе",
            "access is denied",
            "permission denied",
        ])
    {
        "permission_denied"
    } else if matches!(os_error, Some(2 | 3)) || has(&["не удается найти", "no such file"])
    {
        "not_found"
    } else if has(&["нет backup", "backup патча исчез"]) {
        "backup_missing"
    } else if has(&["timed out", "тайм-аут", "время ожидания"]) {
        "timeout"
    } else if step == "endpoints" {
        "endpoint_failed"
    } else if step == "clear_cache" {
        "cache_clear_failed"
    } else if step == "preflight" {
        "preflight_failed"
    } else {
        "other"
    };

    StepError {
        step: step.into(),
        reason: reason.into(),
        component: component.map(|c| format!("{c:?}")),
        file_name: path.and_then(safe_file_name),
        host: extract_known_host(cause),
        os_error,
    }
}

fn is_safe_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn sanitize_error(error: &StepError) -> Option<Value> {
    if !is_safe_code(&error.step) || !is_safe_code(&error.reason) {
        return None;
    }
    let component = error
        .component
        .as_deref()
        .filter(|c| matches!(*c, "LanguageServer" | "IdeMainJs" | "IdeAsar" | "AgyCli"));
    let file_name = error
        .file_name
        .as_deref()
        .and_then(|name| safe_file_name(Path::new(name)));
    let host = error.host.as_deref().filter(|h| {
        net::provider::NRPT_AGENT.contains(h) || net::provider::SUBSTITUTION_CANARIES.contains(h)
    });
    let mut map = serde_json::Map::new();
    map.insert("step".into(), json!(error.step));
    map.insert("reason".into(), json!(error.reason));
    if let Some(component) = component {
        map.insert("component".into(), json!(component));
    }
    if let Some(file_name) = file_name {
        map.insert("file_name".into(), json!(file_name));
    }
    if let Some(host) = host {
        map.insert("host".into(), json!(host));
    }
    if let Some(os_error) = error.os_error {
        map.insert("os_error".into(), json!(os_error));
    }
    Some(Value::Object(map))
}

pub(super) fn snapshot() -> Value {
    snapshot_from(&record_path())
}

fn snapshot_from(path: &Path) -> Value {
    let bytes = match super::read_limited(path, 64 * 1024) {
        Ok(bytes) => bytes,
        Err(reason) => return super::unavailable(reason),
    };
    let Ok(record) = serde_json::from_slice::<AttemptRecord>(&bytes) else {
        return super::unavailable("invalid_record");
    };
    let version = super::version_text(&record.bypass_version);
    let errors: Vec<Value> = record
        .errors
        .iter()
        .take(MAX_ERRORS)
        .filter_map(sanitize_error)
        .collect();
    let first_error = record
        .first_error
        .as_ref()
        .and_then(sanitize_error)
        .or_else(|| errors.first().cloned());
    json!({
        "status": "ok",
        "bypass_version": version,
        "operation": record.operation,
        "timestamp_ms": record.timestamp_ms,
        "outcome": record.outcome,
        "first_error": first_error,
        "errors": errors,
        "rollback_performed": record.rollback_performed,
        "rollback_ok": record.rollback_ok,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_classification_preserves_codes_without_leaking_paths_or_secrets() {
        let eperm = classify_error(
            "patch_files",
            "Operation not permitted (os error 1) at /Users/SECRET_USER/Applications/Antigravity.app/Contents/Resources/bin/language_server",
            Some(TargetKind::LanguageServer),
            Some(Path::new("/Applications/Antigravity.app/Contents/Resources/bin/language_server")),
        );
        assert_eq!(eperm.reason, "app_management_blocked");
        assert_eq!(eperm.os_error, Some(1));
        assert_eq!(eperm.file_name.as_deref(), Some("language_server"));
        assert_eq!(eperm.component.as_deref(), Some("LanguageServer"));

        let route = classify_error(
            "network",
            "Не удалось подобрать маршрут: daily-cloudcode-pa.googleapis.com — DNS не вернул адресов (проверено адресов: 0); SECRET_TOKEN",
            None,
            None,
        );
        assert_eq!(route.reason, "route_no_addresses");
        assert_eq!(
            route.host.as_deref(),
            Some("daily-cloudcode-pa.googleapis.com")
        );
        assert!(!serde_json::to_string(&route).unwrap().contains("SECRET"));
    }

    #[test]
    fn snapshot_sanitizes_tampered_records_and_tracks_rollback_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        assert_eq!(snapshot_from(&path)["status"], "not_found");

        let record = AttemptRecord {
            schema_version: 1,
            bypass_version: "3.0.1".into(),
            operation: Operation::Unlock,
            timestamp_ms: 12345,
            outcome: AttemptOutcome::Failed,
            first_error: Some(StepError {
                step: "patch_files".into(),
                reason: "unsupported_version".into(),
                component: Some("AgyCli".into()),
                file_name: Some("/Users/SECRET/agy".into()),
                host: Some("SECRET.internal".into()),
                os_error: None,
            }),
            errors: vec![
                StepError {
                    step: "patch_files".into(),
                    reason: "unsupported_version".into(),
                    component: Some("AgyCli".into()),
                    file_name: Some("agy".into()),
                    host: None,
                    os_error: None,
                },
                StepError {
                    step: "network".into(),
                    reason: "relay_not_ready".into(),
                    component: None,
                    file_name: None,
                    host: None,
                    os_error: None,
                },
            ],
            rollback_performed: true,
            rollback_ok: Some(true),
        };
        save_record(&path, &record).unwrap();
        let exported = snapshot_from(&path);
        assert!(!exported.to_string().contains("SECRET"));
        assert_eq!(exported["status"], "ok");
        assert_eq!(exported["first_error"]["reason"], "unsupported_version");
        assert_eq!(exported["first_error"]["file_name"], "agy");
        assert!(exported["first_error"].get("host").is_none());
        assert_eq!(exported["errors"].as_array().unwrap().len(), 2);
        assert_eq!(exported["rollback_performed"], true);
        assert_eq!(exported["rollback_ok"], true);
    }

    #[test]
    fn staging_rollback_notes_keep_failure_over_success() {
        let _ = take_staging_rollback();
        assert_eq!(take_staging_rollback(), None);
        note_staging_rollback(true);
        note_staging_rollback(false);
        note_staging_rollback(true);
        assert_eq!(take_staging_rollback(), Some(false));
        assert_eq!(take_staging_rollback(), None);
    }
}
