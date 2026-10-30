#[cfg(target_os = "windows")]
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
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(target_os = "windows")]
fn read_dword(subkey: &str, name: &str) -> Result<Option<u32>, String> {
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
    let opened = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, sk.as_ptr(), 0, KEY_READ, &mut hkey) };
    if opened == 2 {
        return Ok(None);
    }
    if opened != 0 {
        return Err(format!("Чтение DoH registry: {opened}"));
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
    if ret == 2 {
        Ok(None)
    } else if ret == 0 && ty == REG_DWORD {
        Ok(Some(val))
    } else {
        Err(format!("Чтение {name}: код {ret}, тип {ty}"))
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
fn delete_value(subkey: &str, name: &str) -> Result<(), String> {
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
    let opened =
        unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, sk.as_ptr(), 0, KEY_SET_VALUE, &mut hkey) };
    if opened == 2 {
        return Ok(());
    }
    if opened != 0 {
        return Err(format!("DoH delete open: {opened}"));
    }
    let result = unsafe { RegDeleteValueW(hkey, wide(name).as_ptr()) };
    unsafe { RegCloseKey(hkey) };
    if result == 0 || result == 2 {
        Ok(())
    } else {
        Err(format!("DoH delete: {result}"))
    }
}

const DNSCACHE: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters";
const DNSCLIENT: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";

pub fn disable_system_doh() -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let auto = read_dword(DNSCACHE, "EnableAutoDoh")?;
        let policy = read_dword(DNSCLIENT, "DoHPolicy")?;
        let encode = |n: Option<u32>| n.map(|v| v.to_string()).unwrap_or_else(|| "absent".into());
        let backup = format!(
            "# antigravity-doh-v2\nEnableAutoDoh={}\nDoHPolicy={}\n",
            encode(auto),
            encode(policy)
        );
        fs::create_dir_all(crate::net::relay::log_dir()).map_err(|e| e.to_string())?;
        if !backup_path().exists() {
            crate::system::fs_utils::robust_write_file(&backup_path(), backup.as_bytes())?;
        } else {
            parse_backup(&fs::read_to_string(backup_path()).map_err(|e| e.to_string())?)?;
        }
        if !write_dword(DNSCACHE, "EnableAutoDoh", 0) || !write_dword(DNSCLIENT, "DoHPolicy", 1) {
            return Err("DoH: не удалось записать политику; backup сохранён".into());
        }
        if read_dword(DNSCACHE, "EnableAutoDoh")? != Some(0)
            || read_dword(DNSCLIENT, "DoHPolicy")? != Some(1)
        {
            return Err("DoH: политика не подтвердилась после записи".into());
        }
    }
    Ok(())
}

fn parse_backup(text: &str) -> Result<[Option<u32>; 2], String> {
    let mut values = Vec::new();
    for key in ["EnableAutoDoh", "DoHPolicy"] {
        let prefix = format!("{key}=");
        let value = text
            .lines()
            .find_map(|l| l.strip_prefix(&prefix))
            .ok_or("Неполный DoH backup")?;
        values.push(if value == "absent" {
            None
        } else {
            Some(value.parse::<u32>().map_err(|_| "Повреждён DoH backup")?)
        });
    }
    Ok([values[0], values[1]])
}

pub fn restore_system_doh() -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let p = backup_path();
        if !p.exists() {
            return Ok(());
        }
        let text = fs::read_to_string(&p).map_err(|e| e.to_string())?;
        let values = parse_backup(&text)?;
        let legacy = !text.starts_with("# antigravity-doh-v2");
        for ((path, key, applied), original) in
            [(DNSCACHE, "EnableAutoDoh", 0), (DNSCLIENT, "DoHPolicy", 1)]
                .into_iter()
                .zip(values)
        {
            let current = read_dword(path, key)?;
            if current != original
                && current != Some(applied)
                && !(legacy && key == "DoHPolicy" && current == Some(2))
            {
                return Err(format!(
                    "{key} изменён после настройки; backup сохранён, откат отменён"
                ));
            }
        }
        for ((path, key), value) in [(DNSCACHE, "EnableAutoDoh"), (DNSCLIENT, "DoHPolicy")]
            .into_iter()
            .zip(values)
        {
            match value {
                None => delete_value(path, key)?,
                Some(n) => {
                    if !write_dword(path, key, n) {
                        return Err(format!("Не восстановлен {key}; backup сохранён"));
                    }
                }
            }
            if read_dword(path, key)? != value {
                return Err(format!("Проверка восстановления {key} не пройдена"));
            }
        }
        fs::remove_file(p).map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub fn is_doh_disabled() -> bool {
    #[cfg(target_os = "windows")]
    {
        matches!(read_dword(DNSCLIENT, "DoHPolicy"), Ok(Some(1)))
    }
    #[cfg(not(target_os = "windows"))]
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn backup_distinguishes_absent_from_zero_and_rejects_damage() {
        assert_eq!(
            parse_backup("EnableAutoDoh=absent\nDoHPolicy=0\n").unwrap(),
            [None, Some(0)]
        );
        assert!(parse_backup("DoHPolicy=2").is_err());
        assert!(parse_backup("EnableAutoDoh=oops\nDoHPolicy=1").is_err());
    }
}
