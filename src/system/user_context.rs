//! Preserve the initiating user's identity across privilege elevation.
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::OnceLock;

const ORIGIN_PROCESS: &str = "--abr-origin-process=";
const ORIGIN_PATH: &str = "--abr-origin-path=";
const ORIGIN_UID: &str = "--abr-origin-uid=";
static ARGUMENTS: OnceLock<Vec<OsString>> = OnceLock::new();

#[derive(Default, Debug, Clone)]
struct Handoff {
    process: Option<String>,
    path: Option<OsString>,
    uid: Option<String>,
}

fn take_handoff(arguments: Vec<OsString>) -> Result<(Vec<OsString>, Handoff), String> {
    let mut public = Vec::new();
    let mut handoff = Handoff::default();
    for (index, arg) in arguments.into_iter().enumerate() {
        let text = arg.to_string_lossy();
        if index != 0 && text.starts_with(ORIGIN_PROCESS) {
            if handoff
                .process
                .replace(text[ORIGIN_PROCESS.len()..].into())
                .is_some()
            {
                return Err("Повторный контекст пользователя".into());
            }
        } else if index != 0 && text.starts_with(ORIGIN_PATH) {
            // Keep Windows PATH as native UTF-16, including non-Unicode spelling.
            let value = strip_os_prefix(&arg, ORIGIN_PATH);
            if handoff.path.replace(value).is_some() {
                return Err("Повторный PATH пользователя".into());
            }
        } else if index != 0 && text.starts_with(ORIGIN_UID) {
            if handoff
                .uid
                .replace(text[ORIGIN_UID.len()..].into())
                .is_some()
            {
                return Err("Повторный UID пользователя".into());
            }
        } else {
            public.push(arg);
        }
    }
    Ok((public, handoff))
}

fn strip_os_prefix(value: &std::ffi::OsStr, prefix: &str) -> OsString {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        OsString::from_wide(&value.encode_wide().skip(prefix.len()).collect::<Vec<_>>())
    }
    #[cfg(not(windows))]
    OsString::from(&value.to_string_lossy()[prefix.len()..])
}

/// Must run before any user profile is inspected, including read-only commands.
pub fn initialize() -> Result<(), String> {
    let (arguments, handoff) = take_handoff(std::env::args_os().collect())?;
    #[cfg(windows)]
    windows::initialize(&handoff)?;
    #[cfg(unix)]
    {
        if handoff.process.is_some() || handoff.path.is_some() {
            return Err("Контекст Windows не поддерживается на Unix".into());
        }
        if requires_profile(&arguments) || handoff.uid.is_some() {
            unix::initialize(handoff.uid.as_deref())?;
        }
    }
    ARGUMENTS
        .set(arguments)
        .map_err(|_| "Контекст уже настроен".to_string())
}

#[cfg(any(unix, test))]
fn requires_profile(arguments: &[OsString]) -> bool {
    !matches!(
        arguments.get(1).and_then(|a| a.to_str()),
        Some(
            "-h" | "--help"
                | "help"
                | "-V"
                | "--version"
                | "version"
                | "--dns-forwarder"
                | "--linux-dns-apply"
        )
    )
}

pub fn args_os() -> std::vec::IntoIter<OsString> {
    ARGUMENTS
        .get()
        .cloned()
        .unwrap_or_else(|| std::env::args_os().collect())
        .into_iter()
}

pub fn args() -> std::vec::IntoIter<String> {
    args_os()
        .map(|a| a.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .into_iter()
}

#[cfg(unix)]
pub use unix::{elevation_arguments, home};
#[cfg(windows)]
pub use windows::{elevation_arguments, environment_key};

#[cfg(windows)]
mod windows {
    use super::*;
    use std::ffi::{c_void, OsStr};
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, LocalFree, FILETIME, HANDLE, WAIT_TIMEOUT},
        System::{
            Registry::{HKEY, HKEY_CURRENT_USER, HKEY_USERS},
            Threading::*,
        },
        UI::Shell::{
            FOLDERID_LocalAppData, FOLDERID_Profile, FOLDERID_RoamingAppData, SHGetKnownFolderPath,
        },
    };

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(process: HANDLE, access: u32, token: *mut HANDLE) -> i32;
        fn GetTokenInformation(
            token: HANDLE,
            class: u32,
            info: *mut c_void,
            length: u32,
            needed: *mut u32,
        ) -> i32;
        fn ConvertSidToStringSidW(sid: *mut c_void, string: *mut *mut u16) -> i32;
    }
    #[link(name = "ole32")]
    extern "system" {
        fn CoTaskMemFree(pointer: *const c_void);
    }

    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    #[derive(Debug)]
    struct User {
        sid: String,
        profile: PathBuf,
        local: PathBuf,
        roaming: PathBuf,
    }
    static USER: OnceLock<User> = OnceLock::new();

    fn creation_time(process: HANDLE) -> Result<u64, String> {
        let mut times: [FILETIME; 4] = unsafe { std::mem::zeroed() };
        if unsafe {
            GetProcessTimes(
                process,
                &mut times[0],
                &mut times[1],
                &mut times[2],
                &mut times[3],
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok((times[0].dwHighDateTime as u64) << 32 | times[0].dwLowDateTime as u64)
    }

    fn process_image(process: HANDLE) -> Result<PathBuf, String> {
        let mut value = vec![0u16; 32768];
        let mut size = value.len() as u32;
        if unsafe { QueryFullProcessImageNameW(process, 0, value.as_mut_ptr(), &mut size) } == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(OsString::from_wide(&value[..size as usize]).into())
    }

    fn known_folder(token: HANDLE, id: &windows_sys::core::GUID) -> Result<PathBuf, String> {
        let mut value = std::ptr::null_mut();
        let code = unsafe { SHGetKnownFolderPath(id, 0x4000, token, &mut value) }; // KF_FLAG_DONT_VERIFY
        if code < 0 {
            return Err(format!("Каталог профиля: HRESULT {code:#x}"));
        }
        if value.is_null() {
            return Err("Пустой каталог профиля".into());
        }
        let mut length = 0;
        while unsafe { *value.add(length) } != 0 {
            length += 1;
        }
        let path = PathBuf::from(OsString::from_wide(unsafe {
            std::slice::from_raw_parts(value, length)
        }));
        unsafe {
            CoTaskMemFree(value.cast());
        }
        if !path.is_absolute() {
            return Err("Каталог профиля не абсолютный".into());
        }
        Ok(path)
    }

    fn token_user(token: HANDLE) -> Result<User, String> {
        let mut size = 0;
        unsafe {
            GetTokenInformation(token, 1, std::ptr::null_mut(), 0, &mut size);
        }
        if size == 0 || size > 64 * 1024 {
            return Err("Некорректный токен пользователя".into());
        }
        // Pointer alignment is required by TOKEN_USER, whose first field is a SID pointer.
        let mut info = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
        if unsafe { GetTokenInformation(token, 1, info.as_mut_ptr().cast(), size, &mut size) } == 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let sid = info[0] as *mut c_void;
        let mut text = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut length = 0;
        while unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
            .map_err(|e| e.to_string());
        unsafe {
            LocalFree(text.cast());
        }
        Ok(User {
            sid: sid?,
            profile: known_folder(token, &FOLDERID_Profile)?,
            local: known_folder(token, &FOLDERID_LocalAppData)?,
            roaming: known_folder(token, &FOLDERID_RoamingAppData)?,
        })
    }

    fn parse_process(value: &str) -> Result<(u32, u64), String> {
        let (pid, time) = value
            .split_once(':')
            .ok_or("Некорректный процесс инициатора")?;
        let pid = pid
            .parse::<u32>()
            .map_err(|_| "Некорректный PID инициатора")?;
        let time = time
            .parse::<u64>()
            .map_err(|_| "Некорректное время процесса инициатора")?;
        if pid == 0 || time == 0 {
            return Err("Пустой процесс инициатора".into());
        }
        Ok((pid, time))
    }

    fn same_image(left: &std::path::Path, right: &std::path::Path) -> bool {
        let canonical = |p: &std::path::Path| {
            std::fs::canonicalize(p)
                .unwrap_or_else(|_| p.into())
                .to_string_lossy()
                .replace('/', "\\")
        };
        canonical(left).eq_ignore_ascii_case(&canonical(right))
    }

    pub(super) fn initialize(handoff: &Handoff) -> Result<(), String> {
        let elevated = super::super::privilege::is_admin();
        if elevated && handoff.process.is_some() {
            super::super::privilege::enable_debug_privilege();
        }
        initialize_checked(handoff, elevated)
    }

    fn initialize_checked(handoff: &Handoff, elevated: bool) -> Result<(), String> {
        if handoff.uid.is_some() {
            return Err("UID macOS не поддерживается на Windows".into());
        }
        let Some(origin) = &handoff.process else {
            if handoff.path.is_some() {
                return Err("PATH передан без процесса инициатора".into());
            }
            return Ok(());
        };
        if !elevated {
            return Err("Контекст инициатора требует повышения прав".into());
        }
        let (pid, expected_time) = parse_process(origin)?;
        if pid == std::process::id() {
            return Err("Инициатор не может быть текущим процессом".into());
        }
        let raw = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                pid,
            )
        };
        if raw.is_null() {
            return Err(format!(
                "Процесс инициатора: {}",
                std::io::Error::last_os_error()
            ));
        }
        let process = Handle(raw);
        if unsafe { WaitForSingleObject(process.0, 0) } != WAIT_TIMEOUT
            || creation_time(process.0)? != expected_time
        {
            return Err("Процесс инициатора завершён или PID использован повторно".into());
        }
        if !same_image(
            &process_image(process.0)?,
            &std::env::current_exe().map_err(|e| e.to_string())?,
        ) {
            return Err("Процесс инициатора принадлежит другой программе".into());
        }
        let mut raw = std::ptr::null_mut();
        if unsafe { OpenProcessToken(process.0, 0x0008 | 0x0004, &mut raw) } == 0 {
            // TOKEN_QUERY | TOKEN_IMPERSONATE
            return Err(format!(
                "Токен инициатора: {}",
                std::io::Error::last_os_error()
            ));
        }
        let token = Handle(raw);
        let user = token_user(token.0)?;
        let path = handoff.path.as_ref().ok_or("Не передан PATH инициатора")?;
        std::env::set_var("USERPROFILE", &user.profile);
        std::env::set_var("LOCALAPPDATA", &user.local);
        std::env::set_var("APPDATA", &user.roaming);
        std::env::set_var("PATH", path);
        USER.set(user)
            .map_err(|_| "Пользователь уже настроен".to_string())
    }

    pub fn elevation_arguments() -> Result<Vec<OsString>, String> {
        let mut args = super::args_os().skip(1).collect::<Vec<_>>();
        let time = creation_time(unsafe { GetCurrentProcess() })?;
        args.push(format!("{ORIGIN_PROCESS}{}:{time}", std::process::id()).into());
        let mut path = OsString::from(ORIGIN_PATH);
        path.push(std::env::var_os("PATH").unwrap_or_default());
        args.push(path);
        Ok(args)
    }

    /// An elevated process may have another HKCU. The initiating user's hive is
    /// already loaded because their original process is still waiting for UAC.
    pub fn environment_key() -> (HKEY, Vec<u16>) {
        environment_key_for(USER.get().map(|user| user.sid.as_str()))
    }

    fn environment_key_for(sid: Option<&str>) -> (HKEY, Vec<u16>) {
        let (root, name) = match sid {
            Some(sid) => (HKEY_USERS, format!("{sid}\\Environment")),
            None => (HKEY_CURRENT_USER, "Environment".into()),
        };
        (
            root,
            OsStr::new(&name).encode_wide().chain(Some(0)).collect(),
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn origin_is_bound_to_a_live_process_instance_and_same_image() {
            assert_eq!(parse_process("42:123456").unwrap(), (42, 123456));
            for bad in ["42", "0:5", "4:0", "4:5:6", "-1:2"] {
                assert!(parse_process(bad).is_err());
            }
            let this = unsafe { GetCurrentProcess() };
            assert!(creation_time(this).unwrap() > 0);
            assert!(same_image(
                &process_image(this).unwrap(),
                &std::env::current_exe().unwrap()
            ));
        }
        #[test]
        fn known_folders_come_from_the_token_without_creating_files_or_registry_values() {
            let mut raw = std::ptr::null_mut();
            assert_ne!(
                unsafe { OpenProcessToken(GetCurrentProcess(), 0x0008 | 0x0004, &mut raw) },
                0
            );
            let token = Handle(raw);
            let user = token_user(token.0).unwrap();
            assert!(user.sid.starts_with("S-1-"));
            assert!(
                user.profile.is_absolute()
                    && user.local.is_absolute()
                    && user.roaming.is_absolute()
            );
        }
        #[test]
        fn another_administrators_hkcu_is_not_used_for_the_originating_user() {
            let (root, path) = environment_key_for(Some("S-1-5-21-111-222-333-1001"));
            assert_eq!(root, HKEY_USERS);
            assert_eq!(
                String::from_utf16(&path[..path.len() - 1]).unwrap(),
                "S-1-5-21-111-222-333-1001\\Environment"
            );
            assert_eq!(environment_key_for(None).0, HKEY_CURRENT_USER);
        }

        #[test]
        #[ignore = "launched only by the isolated origin-context regression"]
        fn handoff_child() {
            let mut raw = std::ptr::null_mut();
            assert_ne!(
                unsafe { OpenProcessToken(GetCurrentProcess(), 0x0008 | 0x0004, &mut raw) },
                0
            );
            let expected = token_user(Handle(raw).0).unwrap();
            let origin = std::env::var("ABR_TEST_ORIGIN").unwrap();
            let original_path = std::env::var_os("ABR_TEST_ORIGINAL_PATH").unwrap();
            let handoff = Handoff {
                process: Some(origin.clone()),
                path: Some(original_path.clone()),
                uid: None,
            };
            let before =
                ["USERPROFILE", "APPDATA", "LOCALAPPDATA", "PATH"].map(|key| std::env::var_os(key));
            assert!(initialize_checked(&handoff, false).is_err());
            let (pid, time) = parse_process(&origin).unwrap();
            let mut reused = handoff.clone();
            reused.process = Some(format!("{pid}:{}", time + 1));
            assert!(initialize_checked(&reused, true)
                .unwrap_err()
                .contains("PID"));
            let mut foreign = handoff.clone();
            foreign.process = Some(std::env::var("ABR_TEST_OTHER_IMAGE").unwrap());
            assert!(initialize_checked(&foreign, true)
                .unwrap_err()
                .contains("другой программе"));
            let mut absent = handoff.clone();
            absent.process = Some(format!("{}:1", u32::MAX));
            assert!(initialize_checked(&absent, true).is_err());
            assert_eq!(
                ["USERPROFILE", "APPDATA", "LOCALAPPDATA", "PATH"].map(|key| std::env::var_os(key)),
                before
            );
            initialize_checked(&handoff, true).unwrap();
            assert_eq!(
                std::env::var_os("USERPROFILE"),
                Some(expected.profile.into_os_string())
            );
            assert_eq!(
                std::env::var_os("APPDATA"),
                Some(expected.roaming.into_os_string())
            );
            assert_eq!(
                std::env::var_os("LOCALAPPDATA"),
                Some(expected.local.into_os_string())
            );
            assert_eq!(std::env::var_os("PATH"), Some(original_path));
            let (root, key) = environment_key();
            assert_eq!(root, HKEY_USERS);
            assert_eq!(
                String::from_utf16(&key[..key.len() - 1]).unwrap(),
                format!("{}\\Environment", expected.sid)
            );
        }

        #[test]
        fn validated_handoff_restores_token_profile_and_rejects_invalid_origins_before_changes() {
            let mut other = crate::system::powershell::command()
                .unwrap()
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Start-Sleep -Seconds 30",
                ])
                .spawn()
                .unwrap();
            let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, other.id()) };
            assert!(!raw.is_null());
            let other_time = creation_time(Handle(raw).0).unwrap();
            let this_time = creation_time(unsafe { GetCurrentProcess() }).unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "system::user_context::windows::tests::handoff_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env(
                    "ABR_TEST_ORIGIN",
                    format!("{}:{this_time}", std::process::id()),
                )
                .env(
                    "ABR_TEST_OTHER_IMAGE",
                    format!("{}:{other_time}", other.id()),
                )
                .env(
                    "ABR_TEST_ORIGINAL_PATH",
                    "C:\\User CLI с пробелами;D:\\Custom Bin",
                )
                .env("USERPROFILE", "C:\\Different Administrator")
                .env("APPDATA", "C:\\Different Administrator\\Roaming")
                .env("LOCALAPPDATA", "C:\\Different Administrator\\Local")
                .env("PATH", "C:\\Different Administrator\\bin")
                .output();
            let _ = other.kill();
            let _ = other.wait();
            let output = output.unwrap();
            assert!(output.status.success(), "{output:?}");
        }
    }
}

#[cfg(any(unix, test))]
fn select_uid(
    real: u32,
    elevated: bool,
    handed: Option<&str>,
    sudo: Option<&str>,
    console: Option<u32>,
) -> Result<u32, String> {
    if !elevated {
        if handed.is_some() {
            return Err("UID инициатора требует повышения прав".into());
        }
        return (real != 0)
            .then_some(real)
            .ok_or_else(|| "Не найден пользователь".into());
    }
    if let Some(uid) = handed.or(sudo) {
        return uid
            .parse::<u32>()
            .ok()
            .filter(|id| *id != 0)
            .ok_or_else(|| "Некорректный UID инициатора".into());
    }
    (real != 0)
        .then_some(real)
        .or(console.filter(|id| *id != 0))
        .ok_or_else(|| "Не найден пользователь; запускайте утилиту из своей сессии".into())
}

#[cfg(any(unix, test))]
fn home_for_uid(
    uid: u32,
    lookup: impl FnOnce(u32) -> Result<PathBuf, String>,
) -> Result<PathBuf, String> {
    let path = lookup(uid)?;
    if !path.is_absolute() {
        return Err("Домашний каталог не абсолютный".into());
    }
    Ok(path)
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStrExt;
    static HOME: OnceLock<Result<PathBuf, String>> = OnceLock::new();

    fn account_home(uid: u32) -> Result<PathBuf, String> {
        home_for_uid(uid, lookup_account_home)
    }

    fn lookup_account_home(uid: u32) -> Result<PathBuf, String> {
        let mut length = 4096;
        loop {
            let mut buffer = vec![0u8; length];
            let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
            let mut result = std::ptr::null_mut();
            let code = unsafe {
                libc::getpwuid_r(
                    uid,
                    &mut entry,
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut result,
                )
            };
            if code == libc::ERANGE && length < 1024 * 1024 {
                length *= 2;
                continue;
            }
            if code != 0 {
                return Err(format!(
                    "Профиль UID {uid}: {}",
                    std::io::Error::from_raw_os_error(code)
                ));
            }
            if result.is_null() || entry.pw_dir.is_null() {
                return Err(format!("Профиль UID {uid} не найден"));
            }
            let path = PathBuf::from(std::ffi::OsStr::from_bytes(
                unsafe { CStr::from_ptr(entry.pw_dir) }.to_bytes(),
            ));
            return Ok(path);
        }
    }

    fn origin_uid(handed: Option<&str>) -> Result<u32, String> {
        let real = unsafe { libc::getuid() };
        let elevated = unsafe { libc::geteuid() } == 0;
        let sudo = std::env::var("SUDO_UID").ok();
        let console = if elevated && handed.is_none() && sudo.is_none() && real == 0 {
            std::fs::metadata("/dev/console").ok().map(|m| {
                use std::os::unix::fs::MetadataExt;
                m.uid()
            })
        } else {
            None
        };
        select_uid(real, elevated, handed, sudo.as_deref(), console)
    }

    pub(super) fn initialize(handed: Option<&str>) -> Result<(), String> {
        let home = origin_uid(handed).and_then(account_home);
        let result = home.clone();
        HOME.set(home)
            .map_err(|_| "Профиль уже настроен".to_string())?;
        result.map(|_| ())
    }
    pub fn home() -> Result<PathBuf, String> {
        HOME.get_or_init(|| origin_uid(None).and_then(account_home))
            .clone()
    }
    pub fn elevation_arguments() -> Result<Vec<OsString>, String> {
        let mut args: Vec<_> = super::args_os().skip(1).collect();
        args.push(format!("{ORIGIN_UID}{}", origin_uid(None)?).into());
        Ok(args)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn actual_home_is_read_from_the_account_database() {
            let uid = unsafe { libc::getuid() };
            let home = account_home(uid).unwrap();
            assert!(home.is_absolute());
            assert!(std::fs::metadata(home).unwrap().is_dir());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn internal_handoff_does_not_change_interactive_or_explicit_path_arguments() {
        let (args, handoff) = take_handoff(vec![
            "tool".into(),
            "patch-files".into(),
            "C:\\My App\\".into(),
            format!("{ORIGIN_PROCESS}42:123").into(),
            format!("{ORIGIN_PATH}C:\\Custom Bin;D:\\Other").into(),
        ])
        .unwrap();
        assert_eq!(
            args,
            vec![
                OsString::from("tool"),
                "patch-files".into(),
                "C:\\My App\\".into()
            ]
        );
        assert_eq!(handoff.process.as_deref(), Some("42:123"));
        assert_eq!(handoff.path, Some("C:\\Custom Bin;D:\\Other".into()));
        let (args, _) =
            take_handoff(vec!["tool".into(), format!("{ORIGIN_UID}501").into()]).unwrap();
        assert_eq!(args.len(), 1);
        assert!(take_handoff(vec![
            "tool".into(),
            format!("{ORIGIN_UID}501").into(),
            format!("{ORIGIN_UID}502").into()
        ])
        .is_err());
    }
    #[test]
    fn sudo_selects_one_origin_and_never_adds_an_unrelated_console_user() {
        assert_eq!(
            select_uid(0, true, None, Some("501"), Some(502)).unwrap(),
            501
        );
        assert_eq!(
            select_uid(0, true, Some("503"), None, Some(502)).unwrap(),
            503
        );
        assert_eq!(
            select_uid(501, false, None, Some("502"), Some(502)).unwrap(),
            501
        );
        assert_eq!(select_uid(0, true, None, None, Some(502)).unwrap(), 502);
        assert!(select_uid(0, true, None, Some("0"), Some(502)).is_err());
        assert!(select_uid(501, false, Some("502"), None, None).is_err());
    }
    #[test]
    fn informational_commands_and_worker_do_not_require_a_logged_in_macos_user() {
        for command in [
            "-h",
            "--help",
            "help",
            "-V",
            "--version",
            "version",
            "--dns-forwarder",
        ] {
            assert!(!requires_profile(&["tool".into(), command.into()]));
        }
        assert!(requires_profile(&["tool".into()]));
        for command in [
            "unlock",
            "patch-files",
            "dns",
            "rollback",
            "status",
            "report",
            "diagnostics",
        ] {
            assert!(requires_profile(&["tool".into(), command.into()]));
        }
    }
    #[test]
    fn moved_home_is_selected_from_the_originating_account_without_users_directory_guessing() {
        let uid = select_uid(0, true, None, Some("501"), Some(502)).unwrap();
        let relocated = std::env::temp_dir()
            .join("External Volume")
            .join("Moved Home");
        assert_eq!(
            home_for_uid(uid, |selected| {
                assert_eq!(selected, 501);
                Ok(relocated.clone())
            })
            .unwrap(),
            relocated
        );
        assert!(home_for_uid(uid, |_| Err("Account lookup failed".into())).is_err());
        assert!(home_for_uid(uid, |_| Ok("relative-home".into())).is_err());
    }
}
