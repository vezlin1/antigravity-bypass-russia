//! Start the CONNECT helper in the Explorer user's desktop and security context.
use super::{powershell, privilege, user_context};
use crate::net::provider::BROWSER_PAGES;
use crate::net::windows_connect;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub const FLAG: &str = "--connect-launch";

pub enum DesktopLaunch {
    Started,
    AlreadyRunning,
    NotInstalled,
    ElevatedSession(String),
}

/// The process token is the user's only token: there is no filtered
/// counterpart to fall back to. This holds with UAC disabled and for the
/// built-in Administrator account (Admin Approval Mode off) with UAC enabled.
/// A token elevated through a UAC prompt reports `TokenElevationTypeFull`.
fn unfiltered_admin_session() -> bool {
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevationType, TokenElevationTypeDefault, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return false;
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut kind = 0i32;
    let mut length = 0;
    let read = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevationType,
            (&mut kind as *mut i32).cast(),
            std::mem::size_of_val(&kind) as u32,
            &mut length,
        )
    };
    read != 0 && kind == TokenElevationTypeDefault
}

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

pub fn launch_desktop() -> Result<DesktopLaunch, String> {
    launch_in_session("app", desktop_app().is_some())
}

pub fn launch_browser() -> Result<DesktopLaunch, String> {
    launch_in_session("web", chrome().is_some())
}

fn launch_in_session(kind: &str, installed: bool) -> Result<DesktopLaunch, String> {
    if !installed {
        return Ok(DesktopLaunch::NotInstalled);
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
            OsStr::new(kind),
            OsStr::new(&sid),
            receipt.as_os_str(),
        ],
    )?;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match fs::read_to_string(&receipt) {
            Ok(result) if result == "ready\n" => return Ok(DesktopLaunch::Started),
            Ok(result) if result == "already-running\n" => {
                return Ok(DesktopLaunch::AlreadyRunning)
            }
            Ok(result) if result.starts_with("elevated: ") => {
                return Ok(DesktopLaunch::ElevatedSession(
                    result["elevated: ".len()..].trim().to_owned(),
                ));
            }
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

fn lock_browser_session() -> Result<Option<fs::File>, String> {
    let directory = crate::net::config::directory();
    fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(directory.join("connect-browser.lock"))
        .map_err(|error| error.to_string())?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(fs::TryLockError::WouldBlock) => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

fn verify_browser_pages() -> Result<(), String> {
    std::thread::scope(|scope| {
        let checks: Vec<_> = BROWSER_PAGES
            .iter()
            .map(|&(host, _)| {
                (
                    host,
                    scope.spawn(move || windows_connect::verify_fallback(host)),
                )
            })
            .collect();
        for (host, check) in checks {
            check
                .join()
                .map_err(|_| format!("{host}: проверка оборвалась"))?
                .map_err(|error| format!("{host}: {error}"))?;
        }
        Ok(())
    })
}

fn start(kind: &str, browser_session: &mut Option<fs::File>) -> Result<Option<Child>, String> {
    let web = kind == "web";
    let executable = if web {
        *browser_session = lock_browser_session()?;
        if browser_session.is_none() {
            return Ok(None);
        }
        chrome().ok_or("Chrome не найден")?
    } else {
        desktop_app().ok_or("Antigravity App или IDE не найдены")?
    };
    if !web
        && !super::file_lock::running_applications(std::slice::from_ref(&executable))?.is_empty()
    {
        return Err("Закройте открытый Antigravity перед запуском через CONNECT".into());
    }
    let vpn_fallback = if web {
        let vpn = windows_connect::vpn_present();
        if vpn {
            verify_browser_pages()?;
        }
        vpn
    } else {
        let vpn = windows_connect::fallback_available();
        if vpn {
            windows_connect::verify_fallback(crate::net::provider::DAILY_CLOUD_CODE)?;
        }
        vpn
    };
    let port = windows_connect::listen(web).map_err(|e| format!("Локальный CONNECT: {e}"))?;
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
        ]);
        command.args(
            BROWSER_PAGES
                .iter()
                .map(|(host, path)| format!("https://{host}{path}")),
        );
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
    Ok(Some(child))
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
    // When Explorer itself runs with the user's only (unfiltered) admin token,
    // as with UAC off or the built-in Administrator, allow its same-profile
    // handoff, keeping the regular elevation guard elsewhere.
    let blocked_by_elevation =
        privilege::is_admin() && !(receipt.is_some() && unfiltered_admin_session());
    let mut browser_session = None;
    let started = if blocked_by_elevation {
        Err("CONNECT запустился с правами администратора. Нужен обычный пользовательский сеанс Windows.".into())
    } else if receipt.is_none() && !previously_enabled {
        Err("Сначала включите CONNECT через пункт [1] утилиты".into())
    } else if let Some(kind @ ("app" | "web")) = kind.to_str() {
        if receipt.is_some() {
            windows_connect::enable().and_then(|()| start(kind, &mut browser_session))
        } else {
            start(kind, &mut browser_session)
        }
    } else {
        Err("Использование: --connect-launch app | web".into())
    };
    if let Some(receipt) = receipt {
        if started.is_err() && !previously_enabled && !blocked_by_elevation {
            let _ = windows_connect::disable();
        }
        let message = match &started {
            Ok(Some(_)) => "ready\n".to_owned(),
            Ok(None) => "already-running\n".to_owned(),
            Err(error) if blocked_by_elevation => format!("elevated: {error}\n"),
            Err(error) => format!("error: {error}\n"),
        };
        if let Err(error) = super::fs_utils::robust_write_file(receipt, message.as_bytes()) {
            crate::net::relay::log_event(&format!("Подтверждение запуска CONNECT: {error}"));
        }
    }
    if let Some(mut child) = started? {
        child.wait().map_err(|error| error.to_string())?;
    }
    Ok(())
}
