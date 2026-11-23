//! Restore the per-user macOS GUI environment saved by the former HTTP gateway.
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};
const LABEL: &str = "com.antigravity.bypass.response-endpoint";
#[derive(Serialize, Deserialize)]
struct Backup {
    original: Option<String>,
    modified: String,
}
fn backup_path() -> PathBuf {
    crate::net::config::directory().join("automatic-endpoint-session.json")
}
fn agent_path() -> PathBuf {
    crate::system::env::expand_env_vars("~/Library/LaunchAgents").join(format!("{LABEL}.plist"))
}
fn user_id() -> Result<String, String> {
    use std::os::unix::fs::MetadataExt;
    let uid = fs::metadata(crate::system::env::expand_env_vars("~"))
        .map_err(|e| e.to_string())?
        .uid();
    if uid == 0 {
        return Err("Не найден пользователь GUI для настройки endpoint".into());
    }
    Ok(uid.to_string())
}
fn command(args: &[&str]) -> Result<std::process::Output, String> {
    let uid = user_id()?;
    if unsafe { libc::geteuid() } != 0 {
        return crate::system::command::output("launchctl", args).map_err(|e| e.to_string());
    }
    let mut command = vec!["asuser", &uid, "/bin/launchctl"];
    command.extend_from_slice(args);
    crate::system::command::output("launchctl", command).map_err(|e| e.to_string())
}
pub(super) fn read() -> Result<Option<String>, String> {
    let out = command(&["getenv", "CLOUD_CODE_URL"])?;
    if out.status.success() {
        return Ok(Some(String::from_utf8_lossy(&out.stdout).trim().into()));
    }
    if out.status.code() == Some(1) && out.stderr.is_empty() {
        return Ok(None);
    }
    Err("Не удалось прочитать CLOUD_CODE_URL сессии GUI".into())
}
pub(super) fn write(value: Option<&str>) -> Result<(), String> {
    let out = match value {
        Some(v) => command(&["setenv", "CLOUD_CODE_URL", v]),
        None => command(&["unsetenv", "CLOUD_CODE_URL"]),
    }?;
    if !out.status.success() || read()?.as_deref() != value {
        return Err("Не удалось настроить CLOUD_CODE_URL сессии GUI".into());
    }
    Ok(())
}
fn load() -> Result<Option<Backup>, String> {
    match fs::read(backup_path()) {
        Ok(bytes) => {
            let backup: Backup = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            if !super::endpoint_env::is_gateway_endpoint(&backup.modified) {
                return Err("Некорректная копия endpoint".into());
            }
            Ok(Some(backup))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}
pub fn restore() -> Result<(), String> {
    if let Some(backup) = load()? {
        let current = read()?;
        if current.as_ref() == Some(&backup.modified) {
            write(backup.original.as_deref())?;
        } else if current != backup.original && current.is_some() {
            return Err("Endpoint сессии изменён; копия сохранена".into());
        }
        crate::system::journal::restore(&agent_path())?;
        fs::remove_file(backup_path()).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn session_environment_query_reaches_launchctl_without_changing_settings() {
        let output = super::command(&["getenv", "ANTIGRAVITY_MIGRATION_TEST_UNSET"]).unwrap();
        // getenv returns 1 for an absent variable and 0 for a present one.
        assert!(
            matches!(output.status.code(), Some(0 | 1)) && output.stderr.is_empty(),
            "launchctl query failed: {output:?}"
        );
    }
}
