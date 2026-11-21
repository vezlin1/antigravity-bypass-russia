//! Start the CONNECT helper in the Explorer user's desktop and security context.
use super::{powershell, privilege, user_context};
use crate::net::windows_connect;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub const FLAG: &str = "--connect-launch";

fn desktop_app() -> Option<PathBuf> {
    crate::core::detector::find_installations()
        .into_iter()
        .flat_map(|folder| {
            [
                folder.join("Antigravity.exe"),
                folder.join("Antigravity IDE.exe"),
            ]
        })
        .find(|path| path.is_file())
}

fn chrome() -> Option<PathBuf> {
    ["%PROGRAMFILES%", "%PROGRAMFILES(X86)%", "%LOCALAPPDATA%"]
        .into_iter()
        .map(super::env::expand_env_vars)
        .map(|folder| folder.join(r"Google\Chrome\Application\chrome.exe"))
        .find(|path| path.is_file())
}

fn ps_string(value: &str) -> String {
    let characters: Vec<_> = value.encode_utf16().map(|unit| unit.to_string()).collect();
    format!("[string]::new([char[]]@({}))", characters.join(","))
}

fn start_explorer_helper(exe: &Path, args: &[&OsStr]) -> Result<(), String> {
    let wide =
        privilege::windows_arguments(args.iter().map(|arg| arg.encode_wide().collect()).collect());
    let args = String::from_utf16(&wide[..wide.len() - 1])
        .map_err(|_| "Не удалось передать путь в Explorer")?;
    let exe = exe
        .to_str()
        .ok_or("Путь к утилите не поддерживается Explorer")?;
    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
$shell = New-Object -ComObject Shell.Application
$folder = 0
$root = $null
$handle = 0
$desktop = $shell.Windows().FindWindowSW([ref]$folder, [ref]$root, 8, [ref]$handle, 1)
if ($null -eq $desktop) {{ throw 'Explorer desktop unavailable' }}
$desktop.Document.Application.ShellExecute({}, {}, '', 'open', 0)
"#,
        ps_string(exe),
        ps_string(&args)
    );
    let output = powershell::output(&script).map_err(|error| error.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err("Explorer не смог запустить CONNECT в сеансе пользователя".into())
    }
}

pub fn launch_desktop() -> Result<bool, String> {
    if desktop_app().is_none() {
        return Ok(false);
    }
    let current = std::env::current_exe().map_err(|e| e.to_string())?;
    let sid = user_context::profile_sid()?;
    let directory = crate::net::config::directory();
    fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
    let temporary = tempfile::Builder::new()
        .prefix("connect-launch-")
        .tempdir_in(directory)
        .map_err(|e| e.to_string())?;
    let receipt = temporary.path().join("result");
    start_explorer_helper(
        &current,
        &[
            OsStr::new(FLAG),
            OsStr::new("app"),
            OsStr::new(&sid),
            receipt.as_os_str(),
        ],
    )?;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match fs::read_to_string(&receipt) {
            Ok(result) if result == "ready\n" => return Ok(true),
            Ok(result) if result.starts_with("error: ") => {
                return Err(result["error: ".len()..].trim().to_owned());
            }
            Ok(_) => {} // The helper may still be writing its acknowledgement.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
        if Instant::now() >= deadline {
            return Err("Запуск CONNECT в сеансе пользователя не подтвердился".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn start(kind: &str) -> Result<Child, String> {
    let web = kind == "web";
    let executable = if web {
        chrome().ok_or("Chrome не найден")?
    } else {
        desktop_app().ok_or("Antigravity App или IDE не найдены")?
    };
    if !web
        && !super::file_lock::running_applications(std::slice::from_ref(&executable))?.is_empty()
    {
        return Err("Закройте открытый Antigravity перед запуском через CONNECT".into());
    }
    let port = windows_connect::listen().map_err(|e| format!("Локальный CONNECT: {e}"))?;
    let vpn_fallback = windows_connect::fallback_available();
    if vpn_fallback {
        let host = if web {
            "gemini.google.com"
        } else {
            crate::net::provider::DAILY_CLOUD_CODE
        };
        windows_connect::verify_fallback(host)?;
    }
    let mut command = Command::new(&executable);
    if let Some(directory) = executable.parent() {
        command.current_dir(directory);
    }
    command
        .arg(format!("--proxy-pac-url=http://127.0.0.1:{port}/proxy.pac"))
        .arg("--disable-quic")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if web {
        command.arg(format!(
            "--user-data-dir={}",
            crate::net::config::directory()
                .join("connect-chrome")
                .display()
        ));
        command.args([
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-mode",
            "--disable-sync",
            "--disable-extensions",
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
            "https://gemini.google.com/",
            "https://aistudio.google.com/",
        ]);
    } else {
        let proxy = format!("http://127.0.0.1:{port}");
        command
            .env("HTTP_PROXY", &proxy)
            .env("HTTPS_PROXY", &proxy)
            .env("NO_PROXY", "localhost,127.0.0.1,::1")
            .env_remove("ALL_PROXY");
        if vpn_fallback {
            command.env(
                "CLOUD_CODE_URL",
                "https://daily-cloudcode-pa.googleapis.com",
            );
        }
    }
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    std::thread::sleep(Duration::from_millis(350));
    if child.try_wait().map_err(|e| e.to_string())?.is_some() {
        return Err("Клиент завершил запуск, проверьте уже открытые экземпляры".into());
    }
    Ok(child)
}

pub fn run(args: &[OsString]) -> Result<(), String> {
    let (kind, receipt) = match args {
        [kind] => (kind, None),
        [kind, sid, receipt] => {
            if sid != OsStr::new(&user_context::profile_sid()?) {
                return Err("CONNECT запущен в другом профиле Windows".into());
            }
            let receipt = Path::new(receipt);
            if !receipt.parent().is_some_and(Path::is_dir) {
                return Err("Ожидание запуска CONNECT уже завершилось".into());
            }
            (kind, Some(receipt))
        }
        _ => return Err("Использование: --connect-launch app | web".into()),
    };
    let previously_enabled = windows_connect::enabled();
    let started = if privilege::is_admin() {
        Err("Запускайте CONNECT от обычного пользователя Windows".into())
    } else if receipt.is_none() && !previously_enabled {
        Err("Сначала включите CONNECT через пункт [1] утилиты".into())
    } else if let Some(kind @ ("app" | "web")) = kind.to_str() {
        if receipt.is_some() {
            windows_connect::enable().and_then(|()| start(kind))
        } else {
            start(kind)
        }
    } else {
        Err("Использование: --connect-launch app | web".into())
    };
    if let Some(receipt) = receipt {
        if started.is_err() && !previously_enabled && !privilege::is_admin() {
            let _ = windows_connect::disable();
        }
        let message = match &started {
            Ok(_) => "ready\n".to_owned(),
            Err(error) => format!("error: {error}\n"),
        };
        if let Err(error) = super::fs_utils::robust_write_file(receipt, message.as_bytes()) {
            crate::net::relay::log_event(&format!("Подтверждение запуска CONNECT: {error}"));
        }
    }
    started?.wait().map_err(|error| error.to_string())?;
    Ok(())
}
