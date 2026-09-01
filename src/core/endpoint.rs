use std::fs;
use std::path::{Path, PathBuf};
use regex::Regex;
use crate::core::detector::find_installations;

pub const DAILY_ENDPOINT: &str = "https://daily-cloudcode-pa.googleapis.com";
pub const IDE_SETTING: &str = "jetski.cloudCodeUrl";
pub const CLI_ENV_VAR: &str = "CLOUD_CODE_URL";

pub fn apply_all() -> Vec<String> {
    let mut notes = Vec::new();
    for inst in find_installations() {
        match apply_ide(&inst) {
            Ok(msg) => notes.push(format!("{}: {}", inst.display(), msg)),
            Err(e) => notes.push(format!("{}: {}", inst.display(), e)),
        }
    }
    // Fresh installs keep settings under APPDATA even if we missed the folder.
    for folder in ["Antigravity", "Antigravity IDE"] {
        if let Some(path) = appdata_settings(folder) {
            if find_installations().iter().any(|p| ide_settings_path(p).as_ref() == Some(&path)) {
                continue;
            }
            match upsert_settings_file(&path) {
                Ok(msg) => notes.push(format!("{}: {}", path.display(), msg)),
                Err(e) => notes.push(format!("{}: {}", path.display(), e)),
            }
        }
    }
    match apply_cli() {
        Ok(msg) => notes.push(msg),
        Err(e) => notes.push(e),
    }
    notes
}

pub fn remove_all() {
    for inst in find_installations() {
        let _ = remove_ide(&inst);
    }
    for folder in ["Antigravity", "Antigravity IDE"] {
        if let Some(path) = appdata_settings(folder) {
            let _ = remove_settings_file(&path);
        }
    }
    let _ = remove_cli();
}

fn appdata_settings(folder: &str) -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var("APPDATA").ok()?;
        Some(PathBuf::from(appdata).join(folder).join("User").join("settings.json"))
    }
    #[cfg(target_os = "macos")]
    {
        for home in crate::system::env::get_user_homes() {
            let p = home.join("Library").join("Application Support").join(folder).join("User").join("settings.json");
            if p.parent().map(|d| d.exists()).unwrap_or(false) || p.exists() {
                return Some(p);
            }
        }
        let home = crate::system::env::expand_env_vars("~");
        Some(home.join("Library").join("Application Support").join(folder).join("User").join("settings.json"))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        for home in crate::system::env::get_user_homes() {
            let p = home.join(".config").join(folder).join("User").join("settings.json");
            if p.parent().map(|d| d.exists()).unwrap_or(false) || p.exists() {
                return Some(p);
            }
        }
        let home = crate::system::env::expand_env_vars("~");
        Some(home.join(".config").join(folder).join("User").join("settings.json"))
    }
}

fn ide_settings_path(install: &Path) -> Option<PathBuf> {
    let product_candidates = [
        install.join("resources").join("app").join("product.json"),
        install.join("Contents").join("Resources").join("app").join("product.json"),
        install.join("product.json"),
    ];
    for product in product_candidates {
        if let Ok(text) = fs::read_to_string(&product) {
            if let Ok(re) = Regex::new(r#""nameShort"[ \t\r\n]*:[ \t\r\n]*"([^"]+)""#) {
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

fn build_reads_setting(install: &Path) -> bool {
    let main_js = install.join("resources").join("app").join("out").join("main.js");
    fs::read_to_string(main_js).map(|s| s.contains(IDE_SETTING)).unwrap_or(true)
}

pub fn apply_ide(install: &Path) -> Result<String, String> {
    let _ = build_reads_setting(install);
    let path = ide_settings_path(install)
        .ok_or_else(|| "не удалось найти settings.json IDE".to_string())?;
    upsert_settings_file(&path)
}

fn upsert_settings_file(path: &Path) -> Result<String, String> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("не прочитать {}: {}", path.display(), e)),
    };
    let needle = format!("\"{}\": \"{}\"", IDE_SETTING, DAILY_ENDPOINT);
    if text.contains(&needle) {
        return Ok("endpoint уже daily-cloudcode-pa".into());
    }
    let updated = upsert_key(&text, IDE_SETTING, DAILY_ENDPOINT)?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("не создать {}: {}", dir.display(), e))?;
    }
    fs::write(path, updated).map_err(|e| format!("не записать {}: {}", path.display(), e))?;
    Ok(format!("jetski.cloudCodeUrl → {}", DAILY_ENDPOINT))
}

fn remove_ide(install: &Path) -> Result<(), String> {
    let Some(path) = ide_settings_path(install) else {
        return Ok(());
    };
    remove_settings_file(&path)
}

fn remove_settings_file(path: &Path) -> Result<(), String> {
    let Ok(text) = fs::read_to_string(path) else {
        return Ok(());
    };
    if !text.contains(IDE_SETTING) {
        return Ok(());
    }
    let updated = remove_key(&text, IDE_SETTING)?;
    fs::write(path, updated).map_err(|e| format!("не записать {}: {}", path.display(), e))
}

fn upsert_key(text: &str, key: &str, value: &str) -> Result<String, String> {
    let existing = Regex::new(&format!(r#""{}"[ \t\r\n]*:[ \t\r\n]*"[^"]*""#, regex::escape(key)))
        .map_err(|_| "неверный шаблон настройки".to_string())?;
    let entry = format!("\"{}\": \"{}\"", key, value);
    if existing.is_match(text) {
        return Ok(existing.replace(text, entry.as_str()).into_owned());
    }
    if text.trim().is_empty() {
        return Ok(format!("{{\n  {}\n}}\n", entry));
    }
    let cut = text
        .rfind('}')
        .ok_or_else(|| "settings.json без закрывающей скобки".to_string())?;
    let head = text[..cut].trim_end();
    let mut out = String::with_capacity(text.len() + entry.len() + 8);
    out.push_str(head);
    if !head.ends_with('{') && !head.ends_with(',') {
        out.push(',');
    }
    out.push_str("\n  ");
    out.push_str(&entry);
    out.push('\n');
    out.push_str(&text[cut..]);
    Ok(out)
}

fn remove_key(text: &str, key: &str) -> Result<String, String> {
    let escaped = regex::escape(key);
    let trailing = Regex::new(&format!(r#",[ \t\r\n]*"{}"[ \t\r\n]*:[ \t\r\n]*"[^"]*""#, escaped))
        .map_err(|_| "неверный шаблон настройки".to_string())?;
    if trailing.is_match(text) {
        return Ok(trailing.replace(text, "").into_owned());
    }
    let alone = Regex::new(&format!(r#""{}"[ \t\r\n]*:[ \t\r\n]*"[^"]*"[ \t\r\n]*,?[ \t\r\n]*"#, escaped))
        .map_err(|_| "неверный шаблон настройки".to_string())?;
    Ok(alone.replace(text, "").into_owned())
}

fn apply_cli() -> Result<String, String> {
    set_user_env(CLI_ENV_VAR, DAILY_ENDPOINT)?;
    Ok(format!("{}={}", CLI_ENV_VAR, DAILY_ENDPOINT))
}

fn remove_cli() -> Result<(), String> {
    delete_user_env(CLI_ENV_VAR)
}

#[cfg(target_os = "windows")]
fn set_user_env(name: &str, value: &str) -> Result<(), String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    const HKEY_CURRENT_USER: usize = 0x80000001u32 as i32 as isize as usize;
    const KEY_SET_VALUE: u32 = 0x0002;
    const REG_SZ: u32 = 1;
    const HWND_BROADCAST: usize = 0xFFFF;
    const WM_SETTINGCHANGE: u32 = 0x001A;
    const SMTO_ABORTIFHUNG: u32 = 0x0002;

    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(hKey: usize, lpSubKey: *const u16, ulOptions: u32, samDesired: u32, phkResult: *mut usize) -> i32;
        fn RegSetValueExW(hKey: usize, lpValueName: *const u16, Reserved: u32, dwType: u32, lpData: *const u8, cbData: u32) -> i32;
        fn RegCloseKey(hKey: usize) -> i32;
    }
    #[link(name = "user32")]
    extern "system" {
        fn SendMessageTimeoutW(
            hWnd: usize, Msg: u32, wParam: usize, lParam: *const u16,
            fuFlags: u32, uTimeout: u32, lpdwResult: *mut usize,
        ) -> isize;
    }

    let wide = |s: &str| -> Vec<u16> { OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect() };
    let mut hkey: usize = 0;
    if unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, wide("Environment").as_ptr(), 0, KEY_SET_VALUE, &mut hkey) } != 0 {
        return Err("не открыть HKCU\\Environment".into());
    }
    let val = wide(value);
    let rc = unsafe {
        RegSetValueExW(
            hkey,
            wide(name).as_ptr(),
            0,
            REG_SZ,
            val.as_ptr() as *const u8,
            (val.len() * 2) as u32,
        )
    };
    unsafe { RegCloseKey(hkey) };
    if rc != 0 {
        return Err(format!("не записать {}", name));
    }
    let mut result: usize = 0;
    unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST, WM_SETTINGCHANGE, 0, wide("Environment").as_ptr(),
            SMTO_ABORTIFHUNG, 300, &mut result,
        );
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn set_user_env(_name: &str, _value: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "windows")]
fn delete_user_env(name: &str) -> Result<(), String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    const HKEY_CURRENT_USER: usize = 0x80000001u32 as i32 as isize as usize;
    const KEY_SET_VALUE: u32 = 0x0002;
    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(hKey: usize, lpSubKey: *const u16, ulOptions: u32, samDesired: u32, phkResult: *mut usize) -> i32;
        fn RegDeleteValueW(hKey: usize, lpValueName: *const u16) -> i32;
        fn RegCloseKey(hKey: usize) -> i32;
    }
    let wide = |s: &str| -> Vec<u16> { OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect() };
    let mut hkey: usize = 0;
    if unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, wide("Environment").as_ptr(), 0, KEY_SET_VALUE, &mut hkey) } == 0 {
        unsafe { RegDeleteValueW(hkey, wide(name).as_ptr()) };
        unsafe { RegCloseKey(hkey) };
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn delete_user_env(_name: &str) -> Result<(), String> {
    Ok(())
}
