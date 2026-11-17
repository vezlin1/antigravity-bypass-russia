//! Preserve the exact previous HKCU environment value, including its registry type.
#[cfg(windows)]
mod windows {
    use serde::{Deserialize, Serialize};
    use std::{fs, path::PathBuf};
    use windows_sys::Win32::System::Registry::*;

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Value {
        kind: u32,
        data: Vec<u8>,
    }
    #[derive(Serialize, Deserialize)]
    struct Backup {
        schema: u32,
        original: Option<Value>,
        modified: Value,
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }
    fn expected() -> Value {
        Value {
            kind: REG_SZ,
            data: wide(super::super::endpoint::DAILY_ENDPOINT)
                .into_iter()
                .flat_map(u16::to_le_bytes)
                .collect(),
        }
    }
    fn path() -> Result<PathBuf, String> {
        Ok(
            PathBuf::from(std::env::var_os("APPDATA").ok_or("APPDATA не задан")?)
                .join("AntigravityBypassRussia")
                .join("cli_endpoint.json"),
        )
    }
    fn read() -> Result<Option<Value>, String> {
        let (user_hive, environment) = crate::system::user_context::environment_key();
        let mut kind = 0;
        let mut length = 0;
        let code = unsafe {
            RegGetValueW(
                user_hive,
                environment.as_ptr(),
                wide("CLOUD_CODE_URL").as_ptr(),
                RRF_RT_ANY | RRF_NOEXPAND,
                &mut kind,
                std::ptr::null_mut(),
                &mut length,
            )
        };
        if code == 2 {
            return Ok(None);
        }
        if code != 0 || length > 64 * 1024 {
            return Err(format!("Чтение CLOUD_CODE_URL: {code}"));
        }
        let mut data = vec![0u8; length as usize];
        let code = unsafe {
            RegGetValueW(
                user_hive,
                environment.as_ptr(),
                wide("CLOUD_CODE_URL").as_ptr(),
                RRF_RT_ANY | RRF_NOEXPAND,
                &mut kind,
                data.as_mut_ptr().cast(),
                &mut length,
            )
        };
        if code != 0 {
            return Err(format!("Чтение CLOUD_CODE_URL: {code}"));
        }
        data.truncate(length as usize);
        Ok(Some(Value { kind, data }))
    }
    fn write(value: Option<&Value>) -> Result<(), String> {
        let (user_hive, environment) = crate::system::user_context::environment_key();
        let mut key = std::ptr::null_mut();
        let code = unsafe {
            RegCreateKeyExW(
                user_hive,
                environment.as_ptr(),
                0,
                std::ptr::null(),
                0,
                KEY_SET_VALUE,
                std::ptr::null(),
                &mut key,
                std::ptr::null_mut(),
            )
        };
        if code != 0 {
            return Err(format!("HKCU Environment: {code}"));
        }
        let code = unsafe {
            match value {
                Some(v) => RegSetValueExW(
                    key,
                    wide("CLOUD_CODE_URL").as_ptr(),
                    0,
                    v.kind,
                    v.data.as_ptr(),
                    v.data.len() as u32,
                ),
                None => RegDeleteValueW(key, wide("CLOUD_CODE_URL").as_ptr()),
            }
        };
        unsafe {
            RegCloseKey(key);
        }
        if code != 0 && code != 2 {
            return Err(format!("Запись CLOUD_CODE_URL: {code}"));
        }
        if read()?.as_ref() != value {
            return Err("CLOUD_CODE_URL: проверка записи не пройдена".into());
        }
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
        };
        unsafe {
            SendMessageTimeoutW(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                0,
                wide("Environment").as_ptr() as isize,
                SMTO_ABORTIFHUNG,
                300,
                std::ptr::null_mut(),
            );
        }
        Ok(())
    }
    fn load(path: &std::path::Path) -> Result<Option<Backup>, String> {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };
        let backup: Backup =
            serde_json::from_slice(&bytes).map_err(|e| format!("CLOUD_CODE_URL backup: {e}"))?;
        if backup.schema != 1
            || backup.modified != expected()
            || backup
                .original
                .as_ref()
                .is_some_and(|v| !matches!(v.kind, REG_SZ | REG_EXPAND_SZ))
        {
            return Err("Некорректный backup CLOUD_CODE_URL".into());
        }
        Ok(Some(backup))
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn backup_keeps_absence_and_original_registry_type_and_rejects_corruption() {
            let d = tempfile::tempdir().unwrap();
            let p = d.path().join("backup.json");
            for original in [
                None,
                Some(Value {
                    kind: REG_EXPAND_SZ,
                    data: vec![37, 0, 65, 0, 37, 0, 0, 0],
                }),
            ] {
                let backup = Backup {
                    schema: 1,
                    original: original.clone(),
                    modified: expected(),
                };
                fs::write(&p, serde_json::to_vec(&backup).unwrap()).unwrap();
                assert_eq!(load(&p).unwrap().unwrap().original, original);
            }
            fs::write(&p, b"{broken").unwrap();
            assert!(load(&p).is_err());
        }
    }
    pub fn apply_if_default() -> Result<String, String> {
        if read()?
            .is_some_and(|value| !value_text(&value).is_some_and(|s| super::managed_endpoint(&s)))
        {
            return Ok("Пользовательский CLOUD_CODE_URL сохранён".into());
        }
        apply()
    }
    pub fn daily_configured() -> bool {
        read().is_ok_and(|value| value.as_ref() == Some(&expected()))
    }
    pub fn apply() -> Result<String, String> {
        let path = path()?;
        let current = read()?;
        let modified = expected();
        if current.as_ref() == Some(&modified) {
            return Ok("CLI endpoint уже настроен".into());
        }
        if let Some(backup) = load(&path)? {
            if current != backup.original {
                return Err("CLOUD_CODE_URL изменён пользователем; значение сохранено".into());
            }
        } else {
            if current
                .as_ref()
                .is_some_and(|v| !matches!(v.kind, REG_SZ | REG_EXPAND_SZ))
            {
                return Err("CLOUD_CODE_URL имеет неподдерживаемый тип; значение сохранено".into());
            }
            fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
            let backup = Backup {
                schema: 1,
                original: current.clone(),
                modified: modified.clone(),
            };
            crate::system::fs_utils::robust_write_file(
                &path,
                &serde_json::to_vec(&backup).map_err(|e| e.to_string())?,
            )?;
        }
        if read()? != current {
            return Err("CLOUD_CODE_URL изменился во время подготовки backup".into());
        }
        write(Some(&modified))?;
        Ok(
            "CLI CLOUD_CODE_URL настроен; прежнее значение сохранено. Откройте новый терминал."
                .into(),
        )
    }
    pub fn restore() -> Result<(), String> {
        let path = path()?;
        let Some(backup) = load(&path)? else {
            return Ok(());
        };
        let current = read()?;
        if current != backup.original {
            if current.as_ref() != Some(&backup.modified) {
                return Err(
                    "CLOUD_CODE_URL изменён после настройки; backup и текущее значение сохранены"
                        .into(),
                );
            }
            write(backup.original.as_ref())?;
        }
        fs::remove_file(path).map_err(|e| e.to_string())
    }

    fn automatic_path() -> PathBuf {
        crate::net::config::directory().join("automatic-endpoint.json")
    }
    fn value_text(value: &Value) -> Option<String> {
        if !matches!(value.kind, REG_SZ | REG_EXPAND_SZ) || value.data.len() % 2 != 0 {
            return None;
        }
        let chars: Vec<_> = value
            .data
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .take_while(|c| *c != 0)
            .collect();
        String::from_utf16(&chars).ok()
    }
    fn automatic_backup() -> Result<Option<Backup>, String> {
        match fs::read(automatic_path()) {
            Ok(bytes) => {
                let backup: Backup = serde_json::from_slice(&bytes)
                    .map_err(|_| "Повреждена копия автоматического endpoint")?;
                if backup.schema != 2
                    || !value_text(&backup.modified).is_some_and(|v| super::is_gateway_endpoint(&v))
                {
                    return Err("Неизвестный формат копии автоматического endpoint".into());
                }
                Ok(Some(backup))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
    pub fn restore_gateway() -> Result<(), String> {
        let Some(backup) = automatic_backup()? else {
            return Ok(());
        };
        let current = read()?;
        if current != backup.original {
            if current.as_ref() != Some(&backup.modified) {
                return Err("CLOUD_CODE_URL изменён пользователем; копия сохранена".into());
            }
            write(backup.original.as_ref())?;
        }
        fs::remove_file(automatic_path()).map_err(|e| e.to_string())
    }
}

pub(super) fn managed_endpoint(value: &str) -> bool {
    matches!(
        value,
        "" | "https://cloudcode-pa.googleapis.com" | super::endpoint::DAILY_ENDPOINT
    ) || is_gateway_endpoint(value)
}
pub fn restore_gateway() -> Result<(), String> {
    #[cfg(windows)]
    {
        windows::restore_gateway()
    }
    #[cfg(target_os = "macos")]
    {
        super::endpoint_session::restore()
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        Ok(())
    }
}

pub fn apply_if_default() -> Result<String, String> {
    #[cfg(windows)]
    {
        windows::apply_if_default()
    }
    #[cfg(not(windows))]
    {
        Ok(
            "CLOUD_CODE_URL для CLI: глобальная настройка на этой платформе не поддерживается"
                .into(),
        )
    }
}

pub fn daily_configured() -> bool {
    #[cfg(windows)]
    return windows::daily_configured();

    #[cfg(not(windows))]
    false
}
pub fn restore() -> Result<(), String> {
    #[cfg(windows)]
    {
        windows::restore()
    }
    #[cfg(not(windows))]
    {
        Ok(())
    }
}

/// Recognize only endpoints installed by versions 2.3.0/2.3.1, for migration.
pub(super) fn is_gateway_endpoint(value: &str) -> bool {
    (18443..=18463).any(|port| value == format!("http://127.0.0.1:{port}"))
}
