#[allow(unused_imports)]
use std::process::Command;

#[cfg(target_os = "windows")]
pub fn is_admin() -> bool {
    #[link(name = "shell32")]
    extern "system" {
        fn IsUserAnAdmin() -> i32;
    }
    unsafe { IsUserAnAdmin() != 0 }
}

#[cfg(not(target_os = "windows"))]
pub fn is_admin() -> bool {
    #[cfg(unix)]
    unsafe {
        libc::geteuid() == 0
    }
    #[cfg(not(unix))]
    false
}

#[cfg(target_os = "windows")]
pub fn enable_debug_privilege() {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
    const TOKEN_QUERY: u32 = 0x0008;
    const SE_PRIVILEGE_ENABLED: u32 = 0x00000002;

    #[repr(C)]
    struct LUID {
        low_part: u32,
        high_part: i32,
    }

    #[repr(C)]
    struct LUID_AND_ATTRIBUTES {
        luid: LUID,
        attributes: u32,
    }

    #[repr(C)]
    struct TOKEN_PRIVILEGES {
        privilege_count: u32,
        privileges: [LUID_AND_ATTRIBUTES; 1],
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(
            ProcessHandle: *mut std::ffi::c_void,
            DesiredAccess: u32,
            TokenHandle: *mut *mut std::ffi::c_void,
        ) -> i32;
        fn LookupPrivilegeValueW(
            lpSystemName: *const u16,
            lpName: *const u16,
            lpLuid: *mut LUID,
        ) -> i32;
        fn AdjustTokenPrivileges(
            TokenHandle: *mut std::ffi::c_void,
            DisableAllPrivileges: i32,
            NewState: *const TOKEN_PRIVILEGES,
            BufferLength: u32,
            PreviousState: *mut std::ffi::c_void,
            ReturnLength: *mut u32,
        ) -> i32;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> *mut std::ffi::c_void;
        fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
    }

    let mut token: *mut std::ffi::c_void = std::ptr::null_mut();
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
    } != 0
    {
        let priv_name: Vec<u16> = OsStr::new("SeDebugPrivilege")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut luid = LUID {
            low_part: 0,
            high_part: 0,
        };
        if unsafe { LookupPrivilegeValueW(std::ptr::null(), priv_name.as_ptr(), &mut luid) } != 0 {
            let tp = TOKEN_PRIVILEGES {
                privilege_count: 1,
                privileges: [LUID_AND_ATTRIBUTES {
                    luid,
                    attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            unsafe {
                AdjustTokenPrivileges(
                    token,
                    0,
                    &tp,
                    std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
        }
        unsafe { CloseHandle(token) };
    }
}

#[cfg(not(target_os = "windows"))]
pub fn enable_debug_privilege() {}

pub fn ensure_admin() {
    if is_admin() {
        enable_debug_privilege();
        return;
    }

    #[cfg(target_os = "windows")]
    {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        use windows_sys::Win32::{
            Foundation::{CloseHandle, WAIT_OBJECT_0},
            System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE},
            UI::{
                Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW},
                WindowsAndMessaging::SW_SHOWNORMAL,
            },
        };
        let current_exe = std::env::current_exe().unwrap_or_default();
        let exe_path: Vec<u16> = current_exe
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let verb: Vec<u16> = OsStr::new("runas").encode_wide().chain(Some(0)).collect();
        let origin_args = super::user_context::elevation_arguments().unwrap_or_else(|error| {
            eprintln!("Не удалось сохранить профиль пользователя: {error}");
            std::process::exit(1);
        });
        let args = windows_arguments(
            origin_args
                .into_iter()
                .map(|a| a.encode_wide().collect::<Vec<_>>())
                .collect(),
        );
        let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
        info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOCLOSEPROCESS;
        info.lpVerb = verb.as_ptr();
        info.lpFile = exe_path.as_ptr();
        info.lpParameters = args.as_ptr();
        info.lpDirectory = std::ptr::null();
        info.nShow = SW_SHOWNORMAL;
        unsafe {
            if ShellExecuteExW(&mut info) != 0 && !info.hProcess.is_null() {
                let wait = WaitForSingleObject(info.hProcess, INFINITE);
                let mut code = 1;
                if wait != WAIT_OBJECT_0 || GetExitCodeProcess(info.hProcess, &mut code) == 0 {
                    code = 1;
                }
                CloseHandle(info.hProcess);
                std::process::exit(code as i32);
            }
        }
        println!("\x1b[31m[!] Требуются права Администратора (UAC отклонен).\x1b[0m");
        std::process::exit(1);
    }

    #[cfg(target_os = "macos")]
    {
        let current_exe = std::env::current_exe().unwrap_or_default();
        let args = super::user_context::elevation_arguments().unwrap_or_else(|error| {
            eprintln!("Не удалось сохранить профиль пользователя: {error}");
            std::process::exit(1);
        });

        let is_tty = unsafe { libc::isatty(0) == 1 };
        if is_tty {
            let mut cmd = Command::new("/usr/bin/sudo");
            cmd.arg(current_exe);
            for a in args {
                cmd.arg(a);
            }
            if let Ok(mut child) = cmd.spawn() {
                let status = child.wait().unwrap_or_default();
                std::process::exit(status.code().unwrap_or(1));
            }
        } else {
            let shell_quote = |s: &str| format!("'{}'", s.replace('\'', "'\"'\"'"));
            let command = std::iter::once(current_exe.to_string_lossy().into_owned())
                .chain(args.into_iter().map(|a| a.to_string_lossy().into_owned()))
                .map(|s| shell_quote(&s))
                .collect::<Vec<_>>()
                .join(" ");
            let script = format!(
                "do shell script {} with administrator privileges",
                serde_json::to_string(&command).unwrap()
            );
            let status = Command::new("/usr/bin/osascript")
                .args(["-e", &script])
                .status();
            std::process::exit(if status.is_ok_and(|s| s.success()) {
                0
            } else {
                1
            });
        }
        std::process::exit(1);
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let current_exe = std::env::current_exe().unwrap_or_default();
        let args = super::user_context::elevation_arguments().unwrap_or_else(|error| {
            eprintln!("Не удалось сохранить профиль пользователя: {error}");
            std::process::exit(1);
        });
        let is_tty = unsafe { libc::isatty(0) == 1 };
        if is_tty {
            let mut cmd = Command::new("sudo");
            cmd.arg(current_exe);
            for a in args {
                cmd.arg(a);
            }
            if let Ok(mut child) = cmd.spawn() {
                let status = child.wait().unwrap_or_default();
                std::process::exit(status.code().unwrap_or(1));
            }
        } else {
            if let Ok(mut child) = Command::new("pkexec").arg(&current_exe).args(&args).spawn() {
                let status = child.wait().unwrap_or_default();
                std::process::exit(status.code().unwrap_or(1));
            }
            let mut cmd = Command::new("sudo");
            cmd.arg(current_exe);
            for a in args {
                cmd.arg(a);
            }
            if let Ok(mut child) = cmd.spawn() {
                let status = child.wait().unwrap_or_default();
                std::process::exit(status.code().unwrap_or(1));
            }
        }
        std::process::exit(1);
    }
}

/// Microsoft CRT argument escaping, including a path ending with backslashes.
#[cfg(any(windows, test))]
fn windows_arguments(args: Vec<Vec<u16>>) -> Vec<u16> {
    let mut out = Vec::new();
    for (i, arg) in args.into_iter().enumerate() {
        if i > 0 {
            out.push(32);
        }
        out.push(34);
        let mut slashes = 0;
        for c in arg {
            if c == 92 {
                slashes += 1;
                continue;
            }
            out.extend(std::iter::repeat_n(
                92,
                if c == 34 { slashes * 2 + 1 } else { slashes },
            ));
            slashes = 0;
            out.push(c);
        }
        out.extend(std::iter::repeat_n(92, slashes * 2));
        out.push(34);
    }
    out.push(0);
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn elevated_arguments_preserve_spaces_quotes_and_trailing_slash() {
        let output = windows_arguments(vec![
            "patch-files".encode_utf16().collect(),
            r#"C:\My App\"#.encode_utf16().collect(),
            "a\"b".encode_utf16().collect(),
        ]);
        assert_eq!(
            String::from_utf16(&output[..output.len() - 1]).unwrap(),
            r#""patch-files" "C:\My App\\" "a\"b""#
        );
    }
}
