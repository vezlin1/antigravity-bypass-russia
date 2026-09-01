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
        fn OpenProcessToken(ProcessHandle: *mut std::ffi::c_void, DesiredAccess: u32, TokenHandle: *mut *mut std::ffi::c_void) -> i32;
        fn LookupPrivilegeValueW(lpSystemName: *const u16, lpName: *const u16, lpLuid: *mut LUID) -> i32;
        fn AdjustTokenPrivileges(TokenHandle: *mut std::ffi::c_void, DisableAllPrivileges: i32, NewState: *const TOKEN_PRIVILEGES, BufferLength: u32, PreviousState: *mut std::ffi::c_void, ReturnLength: *mut u32) -> i32;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> *mut std::ffi::c_void;
        fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
    }

    let mut token: *mut std::ffi::c_void = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) } != 0 {
        let priv_name: Vec<u16> = OsStr::new("SeDebugPrivilege").encode_wide().chain(std::iter::once(0)).collect();
        let mut luid = LUID { low_part: 0, high_part: 0 };
        if unsafe { LookupPrivilegeValueW(std::ptr::null(), priv_name.as_ptr(), &mut luid) } != 0 {
            let tp = TOKEN_PRIVILEGES {
                privilege_count: 1,
                privileges: [LUID_AND_ATTRIBUTES {
                    luid,
                    attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            unsafe { AdjustTokenPrivileges(token, 0, &tp, std::mem::size_of::<TOKEN_PRIVILEGES>() as u32, std::ptr::null_mut(), std::ptr::null_mut()) };
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

pub fn clean_legacy_certificates() {
    #[cfg(target_os = "windows")]
    {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        #[link(name = "crypt32")]
        extern "system" {
            fn CertOpenSystemStoreW(hprov: *mut std::ffi::c_void, szSubsystemProtocol: *const u16) -> *mut std::ffi::c_void;
            fn CertEnumCertificatesInStore(hCertStore: *mut std::ffi::c_void, pPrevCertContext: *const std::ffi::c_void) -> *const std::ffi::c_void;
            fn CertGetNameStringW(pCertContext: *const std::ffi::c_void, dwType: u32, dwFlags: u32, pvTypePara: *const std::ffi::c_void, pszNameString: *mut u16, cchNameString: u32) -> u32;
            fn CertDeleteCertificateFromStore(pCertContext: *const std::ffi::c_void) -> i32;
            fn CertCloseStore(hCertStore: *mut std::ffi::c_void, dwFlags: u32) -> i32;
        }

        const CERT_NAME_SIMPLE_DISPLAY_TYPE: u32 = 4;

        for store_name in ["Root", "MY", "CA"] {
            let wide: Vec<u16> = OsStr::new(store_name).encode_wide().chain(std::iter::once(0)).collect();
            let h_store = unsafe { CertOpenSystemStoreW(std::ptr::null_mut(), wide.as_ptr()) };
            if !h_store.is_null() {
                let mut prev: *const std::ffi::c_void = std::ptr::null();
                loop {
                    let cert = unsafe { CertEnumCertificatesInStore(h_store, prev) };
                    if cert.is_null() {
                        break;
                    }
                    let mut name_buf = [0u16; 256];
                    let len = unsafe {
                        CertGetNameStringW(
                            cert,
                            CERT_NAME_SIMPLE_DISPLAY_TYPE,
                            0,
                            std::ptr::null(),
                            name_buf.as_mut_ptr(),
                            name_buf.len() as u32,
                        )
                    };
                    if len > 1 {
                        let name = String::from_utf16_lossy(&name_buf[..len as usize - 1]);
                        if name.contains("Antigravity") || name.contains("AGUnlocker") || name.contains("AG_Relay") {
                            unsafe {
                                CertDeleteCertificateFromStore(cert);
                            }
                            prev = std::ptr::null();
                            continue;
                        }
                    }
                    prev = cert;
                }
                unsafe { CertCloseStore(h_store, 0) };
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("security").args(["delete-certificate", "-c", "Antigravity"]).output();
        let _ = Command::new("security").args(["delete-certificate", "-c", "AGUnlocker"]).output();
    }
}

