use std::fs;
use std::path::PathBuf;

const BACKUP_NAME: &str = "doh_backup.conf";

fn backup_path() -> PathBuf {
    crate::net::relay::log_dir().join(BACKUP_NAME)
}

#[cfg(target_os = "windows")]
fn wide(s: &str) -> Vec<u16> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
fn read_dword(subkey: &str, name: &str) -> Option<u32> {
    const HKEY_LOCAL_MACHINE: usize = 0x80000002u32 as i32 as isize as usize;
    const KEY_READ: u32 = 0x20019;
    const REG_DWORD: u32 = 4;

    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(
            hKey: usize,
            lpSubKey: *const u16,
            ulOptions: u32,
            samDesired: u32,
            phkResult: *mut usize,
        ) -> i32;
        fn RegQueryValueExW(
            hKey: usize,
            lpValueName: *const u16,
            lpReserved: *mut u32,
            lpType: *mut u32,
            lpData: *mut u8,
            lpcbData: *mut u32,
        ) -> i32;
        fn RegCloseKey(hKey: usize) -> i32;
    }

    let mut hkey: usize = 0;
    let sk = wide(subkey);
    if unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, sk.as_ptr(), 0, KEY_READ, &mut hkey) } != 0 {
        return None;
    }
    let mut ty: u32 = 0;
    let mut val: u32 = 0;
    let mut len: u32 = 4;
    let vn = wide(name);
    let ret = unsafe {
        RegQueryValueExW(
            hkey,
            vn.as_ptr(),
            std::ptr::null_mut(),
            &mut ty,
            &mut val as *mut u32 as *mut u8,
            &mut len,
        )
    };
    unsafe { RegCloseKey(hkey) };
    if ret == 0 && ty == REG_DWORD {
        Some(val)
    } else {
        None
    }
}

#[cfg(target_os = "windows")]
fn write_dword(subkey: &str, name: &str, value: u32) -> bool {
    const HKEY_LOCAL_MACHINE: usize = 0x80000002u32 as i32 as isize as usize;
    const KEY_ALL_ACCESS: u32 = 0xF003F;
    const REG_DWORD: u32 = 4;

    #[link(name = "advapi32")]
    extern "system" {
        fn RegCreateKeyExW(
            hKey: usize,
            lpSubKey: *const u16,
            Reserved: u32,
            lpClass: *mut u16,
            dwOptions: u32,
            samDesired: u32,
            lpSecurityAttributes: *mut std::ffi::c_void,
            phkResult: *mut usize,
            lpdwDisposition: *mut u32,
        ) -> i32;
        fn RegSetValueExW(
            hKey: usize,
            lpValueName: *const u16,
            Reserved: u32,
            dwType: u32,
            lpData: *const u8,
            cbData: u32,
        ) -> i32;
        fn RegCloseKey(hKey: usize) -> i32;
    }

    let mut hkey: usize = 0;
    let sk = wide(subkey);
    let ret = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            sk.as_ptr(),
            0,
            std::ptr::null_mut(),
            0,
            KEY_ALL_ACCESS,
            std::ptr::null_mut(),
            &mut hkey,
            std::ptr::null_mut(),
        )
    };
    if ret != 0 || hkey == 0 {
        return false;
    }
    let vn = wide(name);
    let ok = unsafe {
        RegSetValueExW(
            hkey,
            vn.as_ptr(),
            0,
            REG_DWORD,
            &value as *const u32 as *const u8,
            4,
        )
    } == 0;
    unsafe { RegCloseKey(hkey) };
    ok
}

#[cfg(target_os = "windows")]
fn delete_value(subkey: &str, name: &str) {
    const HKEY_LOCAL_MACHINE: usize = 0x80000002u32 as i32 as isize as usize;
    const KEY_SET_VALUE: u32 = 0x0002;

    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(
            hKey: usize,
            lpSubKey: *const u16,
            ulOptions: u32,
            samDesired: u32,
            phkResult: *mut usize,
        ) -> i32;
        fn RegDeleteValueW(hKey: usize, lpValueName: *const u16) -> i32;
        fn RegCloseKey(hKey: usize) -> i32;
    }

    let mut hkey: usize = 0;
    let sk = wide(subkey);
    if unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, sk.as_ptr(), 0, KEY_SET_VALUE, &mut hkey) } == 0 {
        let vn = wide(name);
        unsafe { RegDeleteValueW(hkey, vn.as_ptr()) };
        unsafe { RegCloseKey(hkey) };
    }
}

const DNSCACHE: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters";
const DNSCLIENT: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";

pub fn disable_system_doh() {
    #[cfg(target_os = "windows")]
    {
        let prev_auto = read_dword(DNSCACHE, "EnableAutoDoh");
        let prev_policy = read_dword(DNSCLIENT, "DoHPolicy");
        let backup = format!(
            "EnableAutoDoh={}\nDoHPolicy={}\n",
            prev_auto.map(|v| v.to_string()).unwrap_or_else(|| "absent".into()),
            prev_policy
                .map(|v| v.to_string())
                .unwrap_or_else(|| "absent".into())
        );
        let dir = crate::net::relay::log_dir();
        let _ = fs::create_dir_all(&dir);
        if !backup_path().exists() {
            let _ = fs::write(backup_path(), backup);
        }

        // 0 = DoH off (Windows default is 2 = auto)
        let _ = write_dword(DNSCACHE, "EnableAutoDoh", 0);
        // 2 = Prohibit DoH (Windows 11 DNSClient policy)
        let _ = write_dword(DNSCLIENT, "DoHPolicy", 2);
    }
}

pub fn restore_system_doh() {
    #[cfg(target_os = "windows")]
    {
        let p = backup_path();
        let Ok(c) = fs::read_to_string(&p) else {
            return;
        };
            let mut auto: Option<String> = None;
            let mut policy: Option<String> = None;
            for line in c.lines() {
                if let Some(v) = line.strip_prefix("EnableAutoDoh=") {
                    auto = Some(v.to_string());
                }
                if let Some(v) = line.strip_prefix("DoHPolicy=") {
                    policy = Some(v.to_string());
                }
            }
            match auto.as_deref() {
                Some("absent") | None => delete_value(DNSCACHE, "EnableAutoDoh"),
                Some(v) => {
                    if let Ok(n) = v.parse::<u32>() {
                        let _ = write_dword(DNSCACHE, "EnableAutoDoh", n);
                    }
                }
            }
            match policy.as_deref() {
                Some("absent") | None => delete_value(DNSCLIENT, "DoHPolicy"),
                Some(v) => {
                    if let Ok(n) = v.parse::<u32>() {
                        let _ = write_dword(DNSCLIENT, "DoHPolicy", n);
                    }
                }
            }
            let _ = fs::remove_file(p);
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = backup_path();
    }
}

pub fn is_doh_disabled() -> bool {
    #[cfg(target_os = "windows")]
    {
        let auto = read_dword(DNSCACHE, "EnableAutoDoh").unwrap_or(2);
        let policy = read_dword(DNSCLIENT, "DoHPolicy");
        auto == 0 || policy == Some(2)
    }
    #[cfg(not(target_os = "windows"))]
    false
}
