use crate::core::detector::find_installations;
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};

pub const DAILY_ENDPOINT: &str = "https://daily-cloudcode-pa.googleapis.com";
pub const IDE_SETTING: &str = "jetski.cloudCodeUrl";

pub fn apply_all() -> Vec<Result<String, String>> {
    if let Err(error) = migrate_gateway_settings() {
        return vec![Err(error)];
    }
    let mut notes = Vec::new();
    for inst in find_installations() {
        match apply_ide(&inst) {
            Ok(msg) => notes.push(Ok(format!("{}: {}", inst.display(), msg))),
            Err(e) => notes.push(Err(format!("{}: {}", inst.display(), e))),
        }
    }
    // Fresh installs keep settings under APPDATA even if we missed the folder.
    for folder in ["Antigravity", "Antigravity IDE"] {
        if let Some(path) = appdata_settings(folder) {
            if find_installations()
                .iter()
                .any(|p| ide_settings_path(p).as_ref() == Some(&path))
            {
                continue;
            }
            match apply_daily_settings(&path) {
                Ok(msg) => notes.push(Ok(format!("{}: {}", path.display(), msg))),
                Err(e) => notes.push(Err(format!("{}: {}", path.display(), e))),
            }
        }
    }
    notes.push(super::endpoint_env::apply_if_default());
    notes
}

/// Restore the settings journalled by 2.3.0/2.3.1 before stopping their gateway.
fn migrate_gateway_settings() -> Result<(), String> {
    super::endpoint_env::restore_gateway()?;
    for path in settings_paths() {
        restore_gateway_profile(&path)?;
    }
    Ok(())
}
fn restore_gateway_profile(path: &Path) -> Result<(), String> {
    let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let value = jsonc_parser::parse_to_serde_value(
        text.trim_start_matches('\u{feff}'),
        &Default::default(),
    )
    .map_err(|e| e.to_string())?;
    let local = value
        .as_ref()
        .and_then(|v| v.get(IDE_SETTING))
        .and_then(|v| v.as_str())
        .is_some_and(super::endpoint_env::is_gateway_endpoint);
    if local {
        if !crate::system::journal::has_record(path) {
            return Err(format!(
                "{}: отсутствует исходная копия настройки локального шлюза",
                path.display()
            ));
        }
        remove_settings_file(path)?;
    }
    Ok(())
}
#[cfg(test)]
fn apply_automatic_settings(path: &Path, endpoint: &str) -> Result<String, String> {
    let Some(text) = automatic_settings_text(path)? else {
        return Ok("Собственный endpoint профиля сохранён".into());
    };
    let updated = upsert_key(&text, IDE_SETTING, endpoint)?;
    if updated != text {
        crate::system::journal::apply(
            path,
            Some(text.as_bytes()),
            updated.as_bytes(),
            "automatic-endpoint-jsonc",
        )?;
    }
    Ok("Профиль подключён к автоматическому выбору маршрутов".into())
}
#[cfg(test)]
fn automatic_settings_text(path: &Path) -> Result<Option<String>, String> {
    let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let value = jsonc_parser::parse_to_serde_value(
        text.trim_start_matches('\u{feff}'),
        &Default::default(),
    )
    .map_err(|e| e.to_string())?;
    if let Some(setting) = value
        .as_ref()
        .and_then(|v| v.get(IDE_SETTING))
        .filter(|v| !v.is_null())
    {
        let Some(setting) = setting.as_str() else {
            return Err("Некорректный jetski.cloudCodeUrl; настройка сохранена".into());
        };
        if !super::endpoint_env::managed_endpoint(setting) {
            return Ok(None);
        }
    }
    // Also validate the object shape and duplicate keys before writing env.
    upsert_key(&text, IDE_SETTING, DAILY_ENDPOINT)?;
    Ok(Some(text))
}

pub fn settings_paths() -> Vec<PathBuf> {
    let mut paths: Vec<_> = find_installations()
        .iter()
        .filter_map(|p| ide_settings_path(p))
        .collect();
    for folder in ["Antigravity", "Antigravity IDE", "Google Antigravity"] {
        if let Some(path) = appdata_settings(folder) {
            if path.exists() {
                paths.push(path);
            }
        }
    }
    paths.sort();
    paths.dedup();
    // Standalone Antigravity has no VS Code User/settings.json. Its endpoint is
    // configured through CLOUD_CODE_URL; a missing IDE profile is not an error.
    paths.retain(|path| path.exists());
    paths
}

#[cfg(test)]
pub fn selected_host(path: &Path) -> Result<String, String> {
    let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let value = jsonc_parser::parse_to_serde_value(
        text.trim_start_matches('\u{feff}'),
        &Default::default(),
    )
    .map_err(|e| e.to_string())?;
    let setting = value.as_ref().and_then(|v| v.get(IDE_SETTING));
    let endpoint = match setting {
        None | Some(serde_json::Value::Null) => "",
        Some(serde_json::Value::String(value)) => value.as_str(),
        _ => return Err("Некорректный jetski.cloudCodeUrl; настройки не изменены".into()),
    };
    match endpoint {
        "" | "https://cloudcode-pa.googleapis.com" => Ok("cloudcode-pa.googleapis.com".into()),
        DAILY_ENDPOINT => Ok("daily-cloudcode-pa.googleapis.com".into()),
        _ => Err("В этом профиле задан собственный endpoint. Выберите профиль со стандартным Cloud Code.".into()),
    }
}

/// An explicit test selection; native and daily are both journalled, so switching
/// repeatedly still restores the original settings on rollback.
#[cfg(test)]
pub fn select_for_test(path: &Path, host: &str) -> Result<(), String> {
    selected_host(path)?;
    if !matches!(
        host,
        "cloudcode-pa.googleapis.com" | "daily-cloudcode-pa.googleapis.com"
    ) {
        return Err("Неизвестный endpoint".into());
    }
    let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let updated = upsert_key(&text, IDE_SETTING, &format!("https://{host}"))?;
    if updated != text {
        crate::system::journal::apply(
            path,
            Some(text.as_bytes()),
            updated.as_bytes(),
            "settings-jsonc",
        )?;
    }
    Ok(())
}

fn restore_automatic_overrides() -> Vec<Result<String, String>> {
    let mut paths: Vec<_> = find_installations()
        .iter()
        .filter_map(|p| ide_settings_path(p))
        .collect();
    for folder in ["Antigravity", "Antigravity IDE", "Google Antigravity"] {
        if let Some(path) = appdata_settings(folder) {
            paths.push(path);
        }
    }
    paths.sort();
    paths.dedup();
    let mut notes = vec![Ok(
        "Основной Cloud Code имеет проверенный путь; принудительный daily-endpoint не нужен".into(),
    )];
    for path in paths {
        if crate::system::journal::has_record(&path) {
            notes.push(
                remove_settings_file(&path)
                    .map(|_| "Прежние настройки endpoint восстановлены по журналу".into()),
            );
        }
    }
    notes.push(
        super::endpoint_env::restore()
            .map(|_| "CLI: собственный override снят, пользовательское значение сохранено".into()),
    );
    notes
}

pub fn remove_all() -> Vec<String> {
    let mut errors = Vec::new();
    if let Err(error) = super::endpoint_env::restore_gateway() {
        errors.push(error);
    }
    let mut paths = Vec::new();
    for inst in find_installations() {
        if let Some(p) = ide_settings_path(&inst) {
            paths.push(p);
        }
    }
    for folder in ["Antigravity", "Antigravity IDE", "Google Antigravity"] {
        if let Some(p) = appdata_settings(folder) {
            paths.push(p);
        }
    }
    paths.sort();
    paths.dedup();
    for path in paths {
        if let Err(e) = remove_settings_file(&path) {
            errors.push(e);
        }
    }
    if let Err(e) = super::endpoint_env::restore() {
        errors.push(e);
    }
    errors
}

fn appdata_settings(folder: &str) -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var("APPDATA").ok()?;
        Some(
            PathBuf::from(appdata)
                .join(folder)
                .join("User")
                .join("settings.json"),
        )
    }
    #[cfg(target_os = "macos")]
    {
        for home in crate::system::env::get_user_homes() {
            let p = home
                .join("Library")
                .join("Application Support")
                .join(folder)
                .join("User")
                .join("settings.json");
            if p.parent().map(|d| d.exists()).unwrap_or(false) || p.exists() {
                return Some(p);
            }
        }
        let home = crate::system::env::expand_env_vars("~");
        Some(
            home.join("Library")
                .join("Application Support")
                .join(folder)
                .join("User")
                .join("settings.json"),
        )
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        for home in crate::system::env::get_user_homes() {
            let p = home
                .join(".config")
                .join(folder)
                .join("User")
                .join("settings.json");
            if p.parent().map(|d| d.exists()).unwrap_or(false) || p.exists() {
                return Some(p);
            }
        }
        let home = crate::system::env::expand_env_vars("~");
        Some(
            home.join(".config")
                .join(folder)
                .join("User")
                .join("settings.json"),
        )
    }
}

fn ide_settings_path(install: &Path) -> Option<PathBuf> {
    let product_candidates = [
        install.join("resources").join("app").join("product.json"),
        install
            .join("Contents")
            .join("Resources")
            .join("app")
            .join("product.json"),
        install.join("product.json"),
    ];
    let re = Regex::new(r#""nameShort"[ \t\r\n]*:[ \t\r\n]*"([^"]+)""#).ok();
    for product in product_candidates {
        if let Ok(text) = fs::read_to_string(&product) {
            if let Some(ref re) = re {
                if let Some(cap) = re.captures(&text) {
                    let name = cap.get(1)?.as_str();
                    return appdata_settings(name);
                }
            }
        }
    }
    let fallbacks = ["Antigravity", "Antigravity IDE", "Google Antigravity"];
    for f in fallbacks {
        if let Some(p) = appdata_settings(f) {
            if p.exists() {
                return Some(p);
            }
        }
    }
    appdata_settings("Antigravity")
}

pub fn apply_ide(install: &Path) -> Result<String, String> {
    let path = ide_settings_path(install)
        .ok_or_else(|| "не удалось найти settings.json IDE".to_string())?;
    apply_daily_settings(&path)
}

fn apply_daily_settings(path: &Path) -> Result<String, String> {
    if let Ok(text) = fs::read_to_string(path) {
        if let Some(value) = endpoint_value(&text)? {
            if !value.is_null()
                && !value
                    .as_str()
                    .is_some_and(super::endpoint_env::managed_endpoint)
            {
                return Ok("Пользовательский jetski.cloudCodeUrl сохранён".into());
            }
        }
    }
    upsert_settings_file(path)
}

fn upsert_settings_file(path: &Path) -> Result<String, String> {
    crate::system::fs_utils::recover_pending(path)?;
    let (text, existed) = match fs::read_to_string(path) {
        Ok(t) => (t, true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (String::new(), false),
        Err(e) => return Err(format!("не прочитать {}: {}", path.display(), e)),
    };
    let updated = upsert_key(&text, IDE_SETTING, DAILY_ENDPOINT)?;
    if updated == text {
        return Ok("endpoint уже настроен".into());
    }
    create_settings_directory(path)?;
    crate::system::journal::apply(
        path,
        if existed { Some(text.as_bytes()) } else { None },
        updated.as_bytes(),
        "settings-jsonc",
    )?;
    Ok(format!("jetski.cloudCodeUrl → {}", DAILY_ENDPOINT))
}

fn remove_settings_file(path: &Path) -> Result<(), String> {
    crate::system::fs_utils::recover_pending(path)?;
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Deleting settings is a user edit too. Never recreate the old file.
            if crate::system::journal::has_record(path) {
                crate::system::journal::retire(path, None)?;
            }
            return Ok(());
        }
        Err(e) => return Err(e.to_string()),
    };
    if let Some(original) = crate::system::journal::read_original(path)? {
        let current_endpoint = endpoint_value(&text)?;
        let original_text = original
            .as_deref()
            .map(std::str::from_utf8)
            .transpose()
            .map_err(|e| format!("Исходные настройки не являются UTF-8: {e}"))?;
        let original_endpoint = original_text.map(endpoint_value).transpose()?.flatten();
        let original_is_gateway = original_endpoint
            .as_ref()
            .and_then(|v| v.as_str())
            .is_some_and(super::endpoint_env::is_gateway_endpoint);
        if matches!(crate::system::journal::verify_recorded_file(path), Ok(true)) {
            if original_endpoint.as_ref().and_then(|v| v.as_str()) == Some(DAILY_ENDPOINT)
                || original_is_gateway
            {
                // This endpoint predates our change. Retain its provenance so a
                // second rollback cannot mistake it for an unjournalled override.
                let original = original
                    .as_deref()
                    .ok_or("Исходные настройки endpoint недоступны")?;
                if text.as_bytes() != original {
                    crate::system::fs_utils::guarded_write_file(
                        path,
                        Some(text.as_bytes()),
                        Some(original),
                    )?;
                }
                if original_is_gateway {
                    return Err(format!("{}: исходный endpoint локального шлюза восстановлен; автоматическое отключение шлюза отменено", path.display()));
                }
                return Ok(());
            }
            // An untouched file retains an exact byte-for-byte rollback, including
            // removal of a file that did not exist before the patch.
            if !crate::system::journal::restore(path)? {
                return Err("Журнал endpoint исчез; откат отменён".into());
            }
            return Ok(());
        }
        let snapshots = crate::system::journal::read_modified(path)?
            .ok_or("Журнал endpoint исчез; откат отменён")?;
        let expected = if let Some(latest) = snapshots.first() {
            let latest = std::str::from_utf8(latest)
                .map_err(|e| format!("Снимок endpoint не является UTF-8: {e}"))?;
            endpoint_value(latest)?
        } else {
            legacy_owned_endpoint(path, original_text.unwrap_or_default())?
        };
        if current_endpoint == original_endpoint || current_endpoint != expected {
            if current_endpoint
                .as_ref()
                .and_then(|v| v.as_str())
                .is_some_and(super::endpoint_env::is_gateway_endpoint)
            {
                return Err(format!("{}: пользовательский endpoint локального шлюза сохранён; автоматическое отключение шлюза отменено", path.display()));
            }
            // Keep provenance for a changed key: otherwise the next rollback
            // could mistake a user-selected daily endpoint for a legacy override.
            // Removal or restoration to the original non-daily value is complete.
            if current_endpoint.is_none()
                || (current_endpoint == original_endpoint
                    && current_endpoint.as_ref().and_then(|v| v.as_str()) != Some(DAILY_ENDPOINT))
            {
                crate::system::journal::retire(path, Some(text.as_bytes()))?;
            }
            return Ok(());
        }
        let updated = replace_endpoint(&text, original_endpoint.as_ref())?;
        crate::system::fs_utils::guarded_write_file(
            path,
            Some(text.as_bytes()),
            Some(updated.as_bytes()),
        )?;
        if original_endpoint.as_ref().and_then(|v| v.as_str()) != Some(DAILY_ENDPOINT)
            && !original_is_gateway
        {
            crate::system::journal::retire(path, Some(updated.as_bytes()))?;
        }
        if original_is_gateway {
            return Err(format!("{}: исходный endpoint локального шлюза восстановлен; автоматическое отключение шлюза отменено", path.display()));
        }
        return Ok(());
    }
    if let Some(updated) = remove_legacy_daily(&text)? {
        let archive = crate::system::journal::archive_legacy(path, text.as_bytes())?;
        crate::system::fs_utils::guarded_write_file(
            path,
            Some(text.as_bytes()),
            Some(updated.as_bytes()),
        )?;
        crate::net::relay::log_event(&format!(
            "{}: старый daily-override снят; копия {}",
            path.display(),
            archive.display()
        ));
    }
    Ok(())
}

fn legacy_owned_endpoint(path: &Path, original: &str) -> Result<Option<serde_json::Value>, String> {
    let candidates = match crate::system::journal::record_profile(path)?.as_deref() {
        Some("settings-jsonc") => vec![
            DAILY_ENDPOINT.to_owned(),
            "https://cloudcode-pa.googleapis.com".into(),
        ],
        Some("automatic-endpoint-jsonc") => (18443..=18463)
            .map(|port| format!("http://127.0.0.1:{port}"))
            .collect(),
        _ => return Ok(None),
    };
    let expected = crate::system::journal::recorded_modified_hash(path)?
        .ok_or("Журнал endpoint исчез; откат отменён")?;
    for candidate in candidates {
        // Legacy releases only upserted this key. Reproduce those exact bytes
        // and verify their hash, rather than assuming any loopback port is ours.
        let applied = upsert_key(original, IDE_SETTING, &candidate)?;
        if crate::system::journal::digest(applied.as_bytes()) == expected {
            return Ok(Some(serde_json::Value::String(candidate)));
        }
    }
    Ok(None)
}

/// Validate the object and the managed key before reading a value. Serde alone
/// resolves duplicate keys silently, which is unsafe for ownership decisions.
fn endpoint_value(text: &str) -> Result<Option<serde_json::Value>, String> {
    let clean = text.trim_start_matches('\u{feff}');
    let clean = if clean.trim().is_empty() { "{}" } else { clean };
    let root = jsonc_parser::cst::CstRootNode::parse(clean, &Default::default())
        .map_err(|e| format!("settings.json не изменён: {e}"))?;
    let object = root
        .value()
        .and_then(|v| v.as_object())
        .ok_or("settings.json должен быть объектом")?;
    if object
        .properties()
        .iter()
        .filter(|p| p.name().and_then(|n| n.decoded_value().ok()).as_deref() == Some(IDE_SETTING))
        .count()
        > 1
    {
        return Err("Повторный jetski.cloudCodeUrl: неоднозначные настройки сохранены".into());
    }
    let value = jsonc_parser::parse_to_serde_value(clean, &Default::default())
        .map_err(|e| e.to_string())?;
    Ok(value.and_then(|v| v.get(IDE_SETTING).cloned()))
}

fn replace_endpoint(text: &str, original: Option<&serde_json::Value>) -> Result<String, String> {
    use jsonc_parser::cst::{CstInputValue, CstRootNode};
    fn input(value: &serde_json::Value) -> CstInputValue {
        match value {
            serde_json::Value::Null => CstInputValue::Null,
            serde_json::Value::Bool(v) => CstInputValue::Bool(*v),
            serde_json::Value::Number(v) => CstInputValue::Number(v.to_string()),
            serde_json::Value::String(v) => CstInputValue::String(v.clone()),
            serde_json::Value::Array(values) => {
                CstInputValue::Array(values.iter().map(input).collect())
            }
            serde_json::Value::Object(values) => CstInputValue::Object(
                values
                    .iter()
                    .map(|(key, value)| (key.clone(), input(value)))
                    .collect(),
            ),
        }
    }
    endpoint_value(text)?;
    let bom = text.starts_with('\u{feff}');
    let clean = text.trim_start_matches('\u{feff}');
    let root = CstRootNode::parse(
        if clean.trim().is_empty() { "{}" } else { clean },
        &Default::default(),
    )
    .map_err(|e| e.to_string())?;
    let object = root
        .value()
        .and_then(|v| v.as_object())
        .ok_or("settings.json должен быть объектом")?;
    match (object.get(IDE_SETTING), original) {
        (Some(property), Some(value)) => property.set_value(input(value)),
        (None, Some(value)) => {
            object.append(IDE_SETTING, input(value));
        }
        (Some(property), None) => property.remove(),
        (None, None) => {}
    }
    let output = format!("{}{}", if bom { "\u{feff}" } else { "" }, root);
    endpoint_value(&output)?;
    Ok(output)
}

fn create_settings_directory(path: &Path) -> Result<(), String> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::{
            fs::{DirBuilderExt, MetadataExt},
            io::AsRawFd,
        };
        let mut missing = Vec::new();
        let mut ancestor = parent;
        let mut owner = None;
        loop {
            match fs::symlink_metadata(ancestor) {
                Ok(meta) => {
                    if !meta.is_dir() || meta.file_type().is_symlink() {
                        return Err(format!(
                            "{}: каталог настроек должен быть обычным каталогом",
                            ancestor.display()
                        ));
                    }
                    if meta.uid() != 0 {
                        owner = Some((meta.uid(), meta.gid()));
                    }
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    missing.push(ancestor.to_path_buf())
                }
                Err(e) => return Err(format!("{}: {e}", ancestor.display())),
            }
            ancestor = ancestor
                .parent()
                .ok_or("Не найден родитель каталога настроек")?;
        }
        if owner.is_none() {
            owner = std::env::var("SUDO_UID")
                .ok()
                .and_then(|uid| uid.parse::<u32>().ok())
                .filter(|uid| *uid > 0)
                .zip(
                    std::env::var("SUDO_GID")
                        .ok()
                        .and_then(|gid| gid.parse::<u32>().ok()),
                );
        }
        if owner.is_none() {
            let uid = unsafe { libc::geteuid() };
            let gid = unsafe { libc::getegid() };
            if uid != 0 {
                owner = Some((uid, gid));
            }
        }
        // GUI elevation may not set SUDO_UID: search the existing user-owned
        // profile ancestors, without changing their permissions or ownership.
        if owner.is_none() {
            for candidate in ancestor.ancestors().skip(1) {
                let metadata = fs::metadata(candidate).map_err(|e| e.to_string())?;
                if metadata.uid() != 0 {
                    owner = Some((metadata.uid(), metadata.gid()));
                    break;
                }
            }
        }
        let (uid, gid) =
            owner.ok_or("Не найден обычный владелец профиля; создание settings.json отменено")?;
        if !path.exists()
            && missing.is_empty()
            && fs::metadata(parent).map_err(|e| e.to_string())?.uid() != uid
        {
            return Err(format!(
                "{}: каталог принадлежит другому пользователю; создание settings.json отменено",
                parent.display()
            ));
        }
        for directory in missing.iter().rev() {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(directory)
                .map_err(|e| format!("не создать {}: {e}", directory.display()))?;
            use std::os::unix::fs::OpenOptionsExt;
            let file = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
                .open(directory)
                .map_err(|e| e.to_string())?;
            if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
                return Err(format!(
                    "Не назначить владельца {}: {}",
                    directory.display(),
                    std::io::Error::last_os_error()
                ));
            }
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    fs::create_dir_all(parent).map_err(|e| format!("не создать {}: {e}", parent.display()))
}

fn remove_legacy_daily(text: &str) -> Result<Option<String>, String> {
    let clean = text.trim_start_matches('\u{feff}');
    if clean.trim().is_empty() {
        return Ok(None);
    }
    let value = jsonc_parser::parse_to_serde_value(clean, &Default::default())
        .map_err(|e| e.to_string())?;
    if value
        .as_ref()
        .and_then(|v| v.get(IDE_SETTING))
        .and_then(|v| v.as_str())
        != Some(DAILY_ENDPOINT)
    {
        return Ok(None);
    }
    let root = jsonc_parser::cst::CstRootNode::parse(clean, &Default::default())
        .map_err(|e| e.to_string())?;
    let object = root
        .value()
        .and_then(|v| v.as_object())
        .ok_or("settings.json должен быть объектом")?;
    if object
        .properties()
        .iter()
        .filter(|p| p.name().and_then(|n| n.decoded_value().ok()).as_deref() == Some(IDE_SETTING))
        .count()
        != 1
    {
        return Err("Повторный jetski.cloudCodeUrl: неоднозначные настройки сохранены".into());
    }
    if let Some(prop) = object.get(IDE_SETTING) {
        prop.remove();
    }
    Ok(Some(format!(
        "{}{}",
        if text.starts_with('\u{feff}') {
            "\u{feff}"
        } else {
            ""
        },
        root
    )))
}

fn upsert_key(text: &str, key: &str, value: &str) -> Result<String, String> {
    use jsonc_parser::{cst::CstRootNode, ParseOptions};
    let bom = text.starts_with('\u{feff}');
    let text = text.trim_start_matches('\u{feff}');
    let options = ParseOptions {
        allow_comments: true,
        allow_trailing_commas: true,
        allow_loose_object_property_names: false,
        ..Default::default()
    };
    let root = CstRootNode::parse(if text.trim().is_empty() { "{}" } else { text }, &options)
        .map_err(|e| format!("settings.json не изменён: {e}"))?;
    let object = root
        .value()
        .and_then(|v| v.as_object())
        .ok_or("settings.json должен быть объектом")?;
    if object
        .properties()
        .iter()
        .filter(|p| p.name().and_then(|n| n.decoded_value().ok()).as_deref() == Some(key))
        .count()
        > 1
    {
        return Err("Повторный ключ endpoint: неоднозначные настройки сохранены".into());
    }
    if let Some(prop) = object.get(key) {
        prop.set_value(value.into());
    } else {
        object.append(key, value.into());
    }
    let output = root.to_string();
    CstRootNode::parse(&output, &options).map_err(|e| e.to_string())?;
    Ok(format!("{}{}", if bom { "\u{feff}" } else { "" }, output))
}

#[cfg(test)]
mod tests {
    #[test]
    fn classic_migration_removes_loopback_and_preserves_original_rollback() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settings.json");
        let original = "{ // original\n \"editor.fontSize\": 18, }";
        std::fs::write(&path, original).unwrap();
        super::apply_automatic_settings(&path, "http://127.0.0.1:18443").unwrap();
        super::restore_gateway_profile(&path).unwrap();
        super::apply_daily_settings(&path).unwrap();
        let classic = std::fs::read_to_string(&path).unwrap();
        assert!(classic.contains(super::DAILY_ENDPOINT));
        assert!(!classic.contains("127.0.0.1"));
        assert!(classic.contains("// original") && classic.contains("18"));
        super::restore_gateway_profile(&path).unwrap();
        super::remove_settings_file(&path).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    }
    #[test]
    fn automatic_endpoint_is_reversible_and_preserves_custom_profiles() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let original = "{\n // keep\n \"editor.fontSize\":19,\n}";
        std::fs::write(&path, original).unwrap();
        super::apply_automatic_settings(&path, "http://127.0.0.1:18443").unwrap();
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("http://127.0.0.1:18443"));
        super::remove_settings_file(&path).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        let custom = "{\"jetski.cloudCodeUrl\":\"https://custom.example\"}";
        std::fs::write(&path, custom).unwrap();
        assert!(super::automatic_settings_text(&path).unwrap().is_none());
        super::apply_automatic_settings(&path, "http://127.0.0.1:18443").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), custom);
        for invalid in [
            "[]",
            "{broken",
            "{\"jetski.cloudCodeUrl\":5}",
            "{\"jetski.cloudCodeUrl\":\"\",\"jetski.cloudCodeUrl\":\"\"}",
        ] {
            std::fs::write(&path, invalid).unwrap();
            assert!(super::automatic_settings_text(&path).is_err());
            assert_eq!(std::fs::read_to_string(&path).unwrap(), invalid);
        }
    }
    #[test]
    fn explicit_endpoint_comparison_preserves_jsonc_and_original_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let original = "{\n // user setting\n \"editor.fontSize\": 15,\n}\n";
        std::fs::write(&path, original).unwrap();
        super::select_for_test(&path, "daily-cloudcode-pa.googleapis.com").unwrap();
        assert_eq!(
            super::selected_host(&path).unwrap(),
            "daily-cloudcode-pa.googleapis.com"
        );
        super::select_for_test(&path, "cloudcode-pa.googleapis.com").unwrap();
        assert_eq!(
            super::selected_host(&path).unwrap(),
            "cloudcode-pa.googleapis.com"
        );
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("// user setting"));
        super::remove_settings_file(&path).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        for custom in [
            r#"{"jetski.cloudCodeUrl":"https://custom.example"}"#,
            r#"{"jetski.cloudCodeUrl":123}"#,
            "{broken",
        ] {
            std::fs::write(&path, custom).unwrap();
            assert!(super::select_for_test(&path, "cloudcode-pa.googleapis.com").is_err());
            assert_eq!(std::fs::read_to_string(&path).unwrap(), custom);
        }
    }
    use super::*;
    #[test]
    fn legacy_daily_cleanup_is_archived_idempotent_and_preserves_other_settings() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let original = format!("\u{feff}{{ // preserve\n \"jetski.cloudCodeUrl\": \"{DAILY_ENDPOINT}\",\n \"editor.fontSize\": 19, }}");
        fs::write(&path, &original).unwrap();
        remove_settings_file(&path).unwrap();
        let cleaned = fs::read_to_string(&path).unwrap();
        assert!(
            cleaned.contains("// preserve")
                && cleaned.contains("19")
                && cleaned.starts_with('\u{feff}')
        );
        assert!(!cleaned.contains(IDE_SETTING));
        assert!(!crate::system::journal::has_record(&path));
        remove_settings_file(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), cleaned);
        assert_eq!(
            fs::read(dir.path().join("settings.json.ag-backups").join(format!(
                "legacy-{}.bin",
                crate::system::journal::digest(original.as_bytes())
            )))
            .unwrap(),
            original.as_bytes()
        );
        assert!(
            remove_legacy_daily("{\"jetski.cloudCodeUrl\":\"https://custom.test\"}")
                .unwrap()
                .is_none()
        );
        assert!(remove_legacy_daily("{broken").is_err());
        assert!(remove_legacy_daily(&format!("{{\"jetski.cloudCodeUrl\":\"https://custom.test\",\"jetski.cloudCodeUrl\":\"{DAILY_ENDPOINT}\"}}")).is_err());
    }
    #[test]
    fn automatic_daily_policy_preserves_explicit_user_endpoint_and_keeps_exact_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let user = "{ // keep\n \"jetski.cloudCodeUrl\": \"https://custom.example\", }";
        fs::write(&path, user).unwrap();
        apply_daily_settings(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), user);
        assert!(!crate::system::journal::has_record(&path));
        let native = "{ // keep\n \"editor.fontSize\": 17, }";
        fs::write(&path, native).unwrap();
        apply_daily_settings(&path).unwrap();
        assert!(fs::read_to_string(&path).unwrap().contains(DAILY_ENDPOINT));
        remove_settings_file(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), native);
    }
    #[test]
    fn settings_roundtrip_and_user_edits_are_protected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let original = "{\r\n // my preferences\r\n \"jetski.cloudCodeUrl\": \"https://custom.example\",\r\n \"editor.fontSize\": 17,\r\n}";
        fs::write(&path, original).unwrap();
        upsert_settings_file(&path).unwrap();
        upsert_settings_file(&path).unwrap();
        remove_settings_file(&path).unwrap();
        remove_settings_file(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        upsert_settings_file(&path).unwrap();
        let user_edit = fs::read_to_string(&path).unwrap().replace("17", "19");
        fs::write(&path, &user_edit).unwrap();
        remove_settings_file(&path).unwrap();
        let restored = fs::read_to_string(&path).unwrap();
        assert_eq!(restored, original.replace("17", "19"));
        assert!(!crate::system::journal::has_record(&path));
    }
    #[test]
    fn rollback_merges_only_endpoint_after_preferences_edits_and_reapply() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settings.json");
        let original = "\u{feff}{\r\n // preferences\r\n \"editor.fontSize\": 14,\r\n}";
        fs::write(&path, original).unwrap();
        apply_daily_settings(&path).unwrap();
        let user_edit = fs::read_to_string(&path).unwrap().replace("14", "16");
        fs::write(&path, &user_edit).unwrap();
        apply_daily_settings(&path).unwrap();
        remove_settings_file(&path).unwrap();
        let restored = fs::read_to_string(&path).unwrap();
        assert!(restored.starts_with('\u{feff}'));
        assert!(restored.contains("// preferences"));
        assert!(restored.contains("\"editor.fontSize\": 16"));
        assert!(restored.contains("\r\n"));
        assert!(!restored.contains(IDE_SETTING));
        assert!(!crate::system::journal::has_record(&path));
        remove_settings_file(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), restored);
    }
    #[test]
    fn newly_created_settings_keep_preferences_added_by_user_on_rollback() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .join("new-profile")
            .join("User")
            .join("settings.json");
        apply_daily_settings(&path).unwrap();
        let user_edit = upsert_key(
            &fs::read_to_string(&path).unwrap(),
            "editor.fontFamily",
            "Fira Code",
        )
        .unwrap();
        fs::write(&path, &user_edit).unwrap();
        remove_settings_file(&path).unwrap();
        let restored = fs::read_to_string(&path).unwrap();
        assert!(restored.contains("editor.fontFamily"));
        assert!(!restored.contains(IDE_SETTING));
        assert!(!crate::system::journal::has_record(&path));
        assert!(path.exists());
        // A separate untouched fresh profile is still deleted exactly.
        let untouched = directory
            .path()
            .join("untouched")
            .join("User")
            .join("settings.json");
        apply_daily_settings(&untouched).unwrap();
        remove_settings_file(&untouched).unwrap();
        assert!(!untouched.exists());
    }
    #[test]
    fn changed_endpoint_values_are_preserved_on_repeated_rollback() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settings.json");
        for endpoint in [
            serde_json::Value::String("https://custom.example".into()),
            serde_json::Value::String("https://cloudcode-pa.googleapis.com".into()),
            serde_json::Value::Null,
            serde_json::Value::Number(123.into()),
        ] {
            fs::write(&path, "{ \"editor.fontSize\": 14 }").unwrap();
            upsert_settings_file(&path).unwrap();
            let updated =
                replace_endpoint(&fs::read_to_string(&path).unwrap(), Some(&endpoint)).unwrap();
            fs::write(&path, &updated).unwrap();
            remove_settings_file(&path).unwrap();
            remove_settings_file(&path).unwrap();
            assert_eq!(fs::read_to_string(&path).unwrap(), updated);
            // Each scenario gets its own clean journal baseline.
            crate::system::journal::retire(&path, Some(updated.as_bytes())).unwrap();
        }
        fs::write(&path, "{}").unwrap();
        select_for_test(&path, "cloudcode-pa.googleapis.com").unwrap();
        let updated = upsert_key(
            &fs::read_to_string(&path).unwrap(),
            IDE_SETTING,
            DAILY_ENDPOINT,
        )
        .unwrap();
        fs::write(&path, &updated).unwrap();
        remove_settings_file(&path).unwrap();
        remove_settings_file(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), updated);
    }
    #[test]
    fn missing_endpoint_or_file_is_not_recreated_from_backup() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settings.json");
        fs::write(&path, "{ \"editor.fontSize\": 14 }").unwrap();
        apply_daily_settings(&path).unwrap();
        let user_edit = "{ // deleted endpoint\n \"editor.fontSize\": 18 }";
        fs::write(&path, user_edit).unwrap();
        remove_settings_file(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), user_edit);
        assert!(!crate::system::journal::has_record(&path));
        apply_daily_settings(&path).unwrap();
        fs::remove_file(&path).unwrap();
        remove_settings_file(&path).unwrap();
        assert!(!path.exists());
        assert!(!crate::system::journal::has_record(&path));
    }
    #[test]
    fn ambiguous_and_malformed_edits_keep_file_and_journal() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settings.json");
        fs::write(&path, "{}").unwrap();
        apply_daily_settings(&path).unwrap();
        for user_edit in [
            "{broken".to_string(),
            "[]".to_string(),
            format!("{{\"jetski.cloudCodeUrl\":\"{DAILY_ENDPOINT}\",\"jetski.cloudCodeUrl\":\"https://custom.example\"}}"),
        ] {
            fs::write(&path, &user_edit).unwrap();
            assert!(remove_settings_file(&path).is_err());
            assert_eq!(fs::read_to_string(&path).unwrap(), user_edit);
            assert!(crate::system::journal::has_record(&path));
        }
    }
    #[test]
    fn gateway_migration_preserves_preferences_and_rejects_changed_local_endpoint() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settings.json");
        fs::write(&path, "{ \"editor.fontSize\": 14 }").unwrap();
        apply_automatic_settings(&path, "http://127.0.0.1:18443").unwrap();
        let user_edit = fs::read_to_string(&path).unwrap().replace("14", "18");
        fs::write(&path, &user_edit).unwrap();
        restore_gateway_profile(&path).unwrap();
        let restored = fs::read_to_string(&path).unwrap();
        assert!(restored.contains("18"));
        assert!(!restored.contains(IDE_SETTING));
        apply_automatic_settings(&path, "http://127.0.0.1:18443").unwrap();
        let changed_local = fs::read_to_string(&path).unwrap().replace("18443", "18444");
        fs::write(&path, &changed_local).unwrap();
        assert!(remove_settings_file(&path).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), changed_local);
        assert!(crate::system::journal::has_record(&path));
    }
    #[test]
    fn legacy_journal_reconstructs_exact_owned_endpoint_for_preference_merge() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settings.json");
        let original = "{ // original\n \"editor.fontSize\": 14, }";
        for endpoint in [DAILY_ENDPOINT, "http://127.0.0.1:18443"] {
            fs::write(&path, original).unwrap();
            let modified = upsert_key(original, IDE_SETTING, endpoint).unwrap();
            let profile = if endpoint == DAILY_ENDPOINT {
                "settings-jsonc"
            } else {
                "automatic-endpoint-jsonc"
            };
            crate::system::journal::apply(
                &path,
                Some(original.as_bytes()),
                modified.as_bytes(),
                profile,
            )
            .unwrap();
            let record = path
                .with_file_name("settings.json.ag-backups")
                .join("current.json");
            let mut legacy: serde_json::Value =
                serde_json::from_slice(&fs::read(&record).unwrap()).unwrap();
            legacy.as_object_mut().unwrap().remove("snapshots");
            fs::write(&record, serde_json::to_vec(&legacy).unwrap()).unwrap();
            assert!(crate::system::journal::read_modified(&path)
                .unwrap()
                .unwrap()
                .is_empty());
            let user_edit = modified.replace("14", "18");
            fs::write(&path, &user_edit).unwrap();
            remove_settings_file(&path).unwrap();
            let restored = fs::read_to_string(&path).unwrap();
            assert!(restored.contains("18") && restored.contains("// original"));
            assert!(!restored.contains(IDE_SETTING));
            assert!(!crate::system::journal::has_record(&path));
        }
        fs::write(&path, original).unwrap();
        apply_automatic_settings(&path, "http://127.0.0.1:18443").unwrap();
        let record = path
            .with_file_name("settings.json.ag-backups")
            .join("current.json");
        let mut legacy: serde_json::Value =
            serde_json::from_slice(&fs::read(&record).unwrap()).unwrap();
        legacy.as_object_mut().unwrap().remove("snapshots");
        fs::write(&record, serde_json::to_vec(&legacy).unwrap()).unwrap();
        let changed_local = fs::read_to_string(&path)
            .unwrap()
            .replace("14", "18")
            .replace("18443", "18444");
        fs::write(&path, &changed_local).unwrap();
        assert!(remove_settings_file(&path).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), changed_local);
    }
    #[test]
    fn damaged_applied_snapshot_blocks_key_merge_and_keeps_backup() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settings.json");
        fs::write(&path, "{ \"editor.fontSize\": 14 }").unwrap();
        apply_daily_settings(&path).unwrap();
        let modified = fs::read(&path).unwrap();
        let applied_backup = path
            .with_file_name("settings.json.ag-backups")
            .join(format!(
                "{}.applied.bin",
                crate::system::journal::digest(&modified)
            ));
        fs::write(applied_backup, b"broken snapshot").unwrap();
        let user_edit = String::from_utf8(modified).unwrap().replace("14", "18");
        fs::write(&path, &user_edit).unwrap();
        assert!(remove_settings_file(&path).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), user_edit);
        assert!(crate::system::journal::has_record(&path));
    }
    #[test]
    fn preexisting_daily_endpoint_is_preserved_on_repeated_rollback() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settings.json");
        let original = format!("{{ // preexisting endpoint\n \"jetski.cloudCodeUrl\": \"{DAILY_ENDPOINT}\",\n \"editor.fontSize\": 14 }}");
        fs::write(&path, &original).unwrap();
        select_for_test(&path, "cloudcode-pa.googleapis.com").unwrap();
        remove_settings_file(&path).unwrap();
        remove_settings_file(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        select_for_test(&path, "cloudcode-pa.googleapis.com").unwrap();
        let edited = fs::read_to_string(&path).unwrap().replace("14", "18");
        fs::write(&path, &edited).unwrap();
        remove_settings_file(&path).unwrap();
        remove_settings_file(&path).unwrap();
        let restored = fs::read_to_string(&path).unwrap();
        assert_eq!(
            endpoint_value(&restored).unwrap().unwrap().as_str(),
            Some(DAILY_ENDPOINT)
        );
        assert!(restored.contains("18"));
    }
    #[test]
    fn preexisting_local_endpoint_is_restored_and_keeps_teardown_blocked() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("settings.json");
        let original =
            "{ \"jetski.cloudCodeUrl\": \"http://127.0.0.1:18450\", \"editor.fontSize\": 14 }";
        fs::write(&path, original).unwrap();
        upsert_settings_file(&path).unwrap();
        assert!(remove_settings_file(&path).is_err());
        assert!(remove_settings_file(&path).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        assert!(crate::system::journal::has_record(&path));
        upsert_settings_file(&path).unwrap();
        let edited = fs::read_to_string(&path).unwrap().replace("14", "18");
        fs::write(&path, &edited).unwrap();
        assert!(remove_settings_file(&path).is_err());
        assert!(remove_settings_file(&path).is_err());
        let restored = fs::read_to_string(&path).unwrap();
        assert_eq!(
            endpoint_value(&restored).unwrap().unwrap().as_str(),
            Some("http://127.0.0.1:18450")
        );
        assert!(restored.contains("18"));
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn fresh_settings_inherit_user_owner_and_private_permissions() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let directory = tempfile::tempdir().unwrap();
        let original_parent = fs::metadata(directory.path()).unwrap();
        let path = directory
            .path()
            .join("fresh")
            .join("User")
            .join("settings.json");
        apply_daily_settings(&path).unwrap();
        for created in [
            path.parent().unwrap(),
            path.parent().unwrap().parent().unwrap(),
        ] {
            let metadata = fs::metadata(created).unwrap();
            assert_eq!(metadata.uid(), original_parent.uid());
            assert_eq!(metadata.gid(), original_parent.gid());
            assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        }
        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.uid(), original_parent.uid());
        assert_eq!(metadata.gid(), original_parent.gid());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        remove_settings_file(&path).unwrap();
        assert!(!path.exists());
        let unchanged_parent = fs::metadata(directory.path()).unwrap();
        assert_eq!(unchanged_parent.uid(), original_parent.uid());
        assert_eq!(
            unchanged_parent.permissions().mode(),
            original_parent.permissions().mode()
        );
    }
    #[test]
    fn comments_bom_trailing_comma_and_other_settings_survive() {
        let text = "\u{feff}{\n \"http.proxy\": \"http://localhost:1234\", // keep proxy\n}";
        let updated = upsert_key(text, IDE_SETTING, DAILY_ENDPOINT).unwrap();
        assert!(updated.starts_with('\u{feff}'));
        assert!(updated.contains("// keep proxy"));
        assert!(updated.contains("http://localhost:1234"));
        assert_eq!(
            upsert_key(&updated, IDE_SETTING, DAILY_ENDPOINT).unwrap(),
            updated
        );
    }
    #[test]
    fn malformed_settings_are_not_replaced_with_empty_object() {
        assert!(upsert_key("{broken", IDE_SETTING, DAILY_ENDPOINT).is_err());
        assert!(upsert_key("[]", IDE_SETTING, DAILY_ENDPOINT).is_err());
    }
}
