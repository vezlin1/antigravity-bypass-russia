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

pub fn ensure_admin() {
    if is_admin() {
        return;
    }

    #[cfg(target_os = "windows")]
    {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use std::ptr::null_mut;

        #[link(name = "shell32")]
        extern "system" {
            fn ShellExecuteW(
                hwnd: *mut std::ffi::c_void,
                lpOperation: *const u16,
                lpFile: *const u16,
                lpParameters: *const u16,
                lpDirectory: *const u16,
                nShowCmd: i32,
            ) -> *mut std::ffi::c_void;
        }

        let current_exe = std::env::current_exe().unwrap_or_default();
        let exe_path: Vec<u16> = current_exe
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let verb: Vec<u16> = OsStr::new("runas")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let args: Vec<String> = std::env::args().skip(1).collect();
        let args_str = args.join(" ");
        let params: Vec<u16> = OsStr::new(&args_str)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            let res = ShellExecuteW(
                null_mut(),
                verb.as_ptr(),
                exe_path.as_ptr(),
                if args.is_empty() {
                    null_mut()
                } else {
                    params.as_ptr()
                },
                null_mut(),
                1,
            );
            if res as usize > 32 {
                std::process::exit(0);
            }
        }
        println!("\x1b[31m[!] Требуются права Администратора (UAC отклонен).\x1b[0m");
        std::process::exit(1);
    }

    #[cfg(target_os = "macos")]
    {
        let current_exe = std::env::current_exe().unwrap_or_default();
        let args: Vec<String> = std::env::args().skip(1).collect();

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
            let cmd_str = format!(
                "do shell script \"'{}' {}\" with administrator privileges",
                current_exe.display(),
                args.join(" ")
            );
            let _ = Command::new("osascript")
                .arg("-e")
                .arg(&cmd_str)
                .status();
            std::process::exit(0);
        }
        std::process::exit(1);
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let current_exe = std::env::current_exe().unwrap_or_default();
        let args: Vec<String> = std::env::args().skip(1).collect();
        let mut cmd = Command::new("sudo");
        cmd.arg(current_exe);
        for a in args {
            cmd.arg(a);
        }
        if let Ok(mut child) = cmd.spawn() {
            let status = child.wait().unwrap_or_default();
            std::process::exit(status.code().unwrap_or(1));
        }
        std::process::exit(1);
    }
}
