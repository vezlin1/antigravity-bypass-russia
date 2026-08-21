#![allow(dead_code)]

#[allow(unused_imports)]
use std::process::Command;
use crate::net::provider::NRPT_TAG;
#[allow(unused_imports)]
use crate::system::process::no_window;

pub fn get_nrpt_status_info() -> (usize, Option<String>, bool) {
    #[cfg(target_os = "windows")]
    {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;
        use std::ptr::null_mut;

        const HKEY_LOCAL_MACHINE: usize = 0x80000002u32 as i32 as isize as usize;
        const KEY_READ: u32 = 0x20019;

        #[link(name = "advapi32")]
        extern "system" {
            fn RegOpenKeyExW(
                hKey: usize,
                lpSubKey: *const u16,
                ulOptions: u32,
                samDesired: u32,
                phkResult: *mut usize,
            ) -> i32;
            fn RegEnumKeyExW(
                hKey: usize,
                dwIndex: u32,
                lpName: *mut u16,
                lpcchName: *mut u32,
                lpReserved: *mut u32,
                lpClass: *mut u16,
                lpcchClass: *mut u32,
                lpftLastWriteTime: *mut u64,
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

        let subkey = wide_str(r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig");
        let mut hkey: usize = 0;
        if unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.as_ptr(), 0, KEY_READ, &mut hkey) } != 0 {
            return (0, None, false);
        }

        let mut count = 0;
        let mut provider_name: Option<String> = None;
        let mut is_relay = false;
        let comment_val = wide_str("Comment");
        let display_val = wide_str("DisplayName");
        let ip_val_primary = wide_str("GenericDNSServers");
        let ip_val_secondary = wide_str("GenericDNSCAServers");

        let mut idx = 0;
        loop {
            let mut name_buf = [0u16; 256];
            let mut name_len = name_buf.len() as u32;
            let ret = unsafe {
                RegEnumKeyExW(
                    hkey,
                    idx,
                    name_buf.as_mut_ptr(),
                    &mut name_len,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                )
            };
            if ret != 0 {
                break;
            }
            idx += 1;

            let rule_subkey = wide_str(&format!(
                r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\{}",
                OsString::from_wide(&name_buf[..name_len as usize]).to_string_lossy()
            ));

            let mut hrule: usize = 0;
            if unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, rule_subkey.as_ptr(), 0, KEY_READ, &mut hrule) } == 0 {
                let mut comment = String::new();
                let mut display_name = String::new();

                let mut data = [0u8; 512];
                let mut data_len = data.len() as u32;
                if unsafe {
                    RegQueryValueExW(
                        hrule,
                        comment_val.as_ptr(),
                        null_mut(),
                        null_mut(),
                        data.as_mut_ptr(),
                        &mut data_len,
                    )
                } == 0 {
                    comment = parse_wide_string(&data, data_len);
                }

                let mut disp_data = [0u8; 512];
                let mut disp_len = disp_data.len() as u32;
                if unsafe {
                    RegQueryValueExW(
                        hrule,
                        display_val.as_ptr(),
                        null_mut(),
                        null_mut(),
                        disp_data.as_mut_ptr(),
                        &mut disp_len,
                    )
                } == 0 {
                    display_name = parse_wide_string(&disp_data, disp_len);
                }

                let is_managed = comment.contains(NRPT_TAG) || display_name.contains(NRPT_TAG);

                if is_managed {
                    count += 1;
                    if provider_name.is_none() {
                        let mut ip_data = [0u8; 512];
                        let mut ip_len = ip_data.len() as u32;
                        let mut found_ip = false;

                        if unsafe {
                            RegQueryValueExW(
                                hrule,
                                ip_val_primary.as_ptr(),
                                null_mut(),
                                null_mut(),
                                ip_data.as_mut_ptr(),
                                &mut ip_len,
                            )
                        } == 0 {
                            found_ip = true;
                        } else {
                            ip_len = ip_data.len() as u32;
                            if unsafe {
                                RegQueryValueExW(
                                    hrule,
                                    ip_val_secondary.as_ptr(),
                                    null_mut(),
                                    null_mut(),
                                    ip_data.as_mut_ptr(),
                                    &mut ip_len,
                                )
                            } == 0 {
                                found_ip = true;
                            }
                        }

                        if found_ip {
                            let ips = parse_wide_string(&ip_data, ip_len);
                            if ips.contains("127.0.0.53") || ips.contains("127.0.0.1") {
                                is_relay = true;
                            }
                            provider_name = Some(ips);
                        }
                    }
                }
                unsafe { RegCloseKey(hrule) };
            }
        }
        unsafe { RegCloseKey(hkey) };
        (count, provider_name, is_relay)
    }

    #[cfg(target_os = "macos")]
    {
        let res_dir = std::path::Path::new("/etc/resolver");
        if !res_dir.exists() {
            return (0, None, false);
        }
        let mut count = 0;
        let mut ns = None;
        if let Ok(entries) = std::fs::read_dir(res_dir) {
            for entry in entries.flatten() {
                let file_path = entry.path();
                if file_path.is_file() {
                    if let Ok(c) = std::fs::read_to_string(&file_path) {
                        if c.contains("# ANTIGRAVITY-BYPASS-RUSSIA") {
                            count += 1;
                            if ns.is_none() {
                                for line in c.lines() {
                                    if line.starts_with("nameserver ") {
                                        ns = Some(line.trim_start_matches("nameserver ").trim().to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        let is_relay = ns.as_deref() == Some("127.0.0.1");
        (count, ns, is_relay)
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    (0, None, false)
}

#[cfg(target_os = "windows")]
fn wide_str(s: &str) -> Vec<u16> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
fn parse_wide_string(bytes: &[u8], len: u32) -> String {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    let u16_len = (len as usize) / 2;
    let slice: &[u16] = unsafe { std::slice::from_raw_parts(bytes.as_ptr() as *const u16, u16_len) };
    let trim_len = slice.iter().position(|&c| c == 0).unwrap_or(u16_len);
    OsString::from_wide(&slice[..trim_len]).to_string_lossy().to_string()
}

#[cfg(target_os = "windows")]
pub fn native_remove_nrpt_rules() -> usize {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::ptr::null_mut;

    const HKEY_LOCAL_MACHINE: usize = 0x80000002u32 as i32 as isize as usize;
    const KEY_READ: u32 = 0x20019;
    const KEY_WRITE: u32 = 0x20006;

    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(hKey: usize, lpSubKey: *const u16, ulOptions: u32, samDesired: u32, phkResult: *mut usize) -> i32;
        fn RegEnumKeyExW(hKey: usize, dwIndex: u32, lpName: *mut u16, lpcchName: *mut u32, lpReserved: *mut u32, lpClass: *mut u16, lpcchClass: *mut u32, lpftLastWriteTime: *mut u64) -> i32;
        fn RegQueryValueExW(hKey: usize, lpValueName: *const u16, lpReserved: *mut u32, lpType: *mut u32, lpData: *mut u8, lpcbData: *mut u32) -> i32;
        fn RegDeleteKeyW(hKey: usize, lpSubKey: *const u16) -> i32;
        fn RegCloseKey(hKey: usize) -> i32;
    }

    let subkey = wide_str(r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig");
    let mut hkey: usize = 0;
    if unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.as_ptr(), 0, KEY_READ | KEY_WRITE, &mut hkey) } != 0 {
        return 0;
    }

    let comment_val = wide_str("Comment");
    let display_val = wide_str("DisplayName");
    let mut keys_to_delete = Vec::new();

    let mut idx = 0;
    loop {
        let mut name_buf = [0u16; 256];
        let mut name_len = name_buf.len() as u32;
        let ret = unsafe {
            RegEnumKeyExW(
                hkey,
                idx,
                name_buf.as_mut_ptr(),
                &mut name_len,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
            )
        };
        if ret != 0 {
            break;
        }
        idx += 1;

        let rule_key_name = &name_buf[..name_len as usize];
        let rule_subkey = wide_str(&format!(
            r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\{}",
            OsString::from_wide(rule_key_name).to_string_lossy()
        ));

        let mut hrule: usize = 0;
        if unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, rule_subkey.as_ptr(), 0, KEY_READ, &mut hrule) } == 0 {
            let mut comment = String::new();
            let mut display_name = String::new();

            let mut data = [0u8; 512];
            let mut data_len = data.len() as u32;
            if unsafe { RegQueryValueExW(hrule, comment_val.as_ptr(), null_mut(), null_mut(), data.as_mut_ptr(), &mut data_len) } == 0 {
                comment = parse_wide_string(&data, data_len);
            }

            let mut disp_data = [0u8; 512];
            let mut disp_len = disp_data.len() as u32;
            if unsafe { RegQueryValueExW(hrule, display_val.as_ptr(), null_mut(), null_mut(), disp_data.as_mut_ptr(), &mut disp_len) } == 0 {
                display_name = parse_wide_string(&disp_data, disp_len);
            }

            let is_managed = comment.contains(NRPT_TAG) || display_name.contains(NRPT_TAG);

            if is_managed {
                keys_to_delete.push(rule_key_name.to_vec());
            }

            unsafe { RegCloseKey(hrule) };
        }
    }

    let mut deleted = 0;
    for key_name in keys_to_delete {
        let mut key_wide = key_name;
        key_wide.push(0);
        if unsafe { RegDeleteKeyW(hkey, key_wide.as_ptr()) } == 0 {
            deleted += 1;
        }
    }

    unsafe { RegCloseKey(hkey) };
    deleted
}

#[cfg(target_os = "windows")]
pub fn apply_nrpt_rules_direct(servers_csv: &str, domains: &[&str], tag: &str, display_prefix: &str) -> usize {
    use std::ptr::null_mut;

    const HKEY_LOCAL_MACHINE: usize = 0x80000002u32 as i32 as isize as usize;
    const KEY_ALL_ACCESS: u32 = 0xF003F;
    const REG_SZ: u32 = 1;
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

    let base_path = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";
    let servers_wide = wide_str(servers_csv);
    let comment_wide = wide_str(tag);
    let version_val: u32 = 2;
    let config_options: u32 = 8;
    let mut count = 0;

    for (i, domain) in domains.iter().enumerate() {
        let rule_key = format!(r"{}\ANTIGRAVITY_BYPASS_{:03}", base_path, i + 1);
        let rule_wide = wide_str(&rule_key);
        let mut hrule: usize = 0;

        let ret = unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                rule_wide.as_ptr(),
                0,
                null_mut(),
                0,
                KEY_ALL_ACCESS,
                null_mut(),
                &mut hrule,
                null_mut(),
            )
        };

        if ret == 0 && hrule != 0 {
            let ns_wide = wide_str(domain);
            let disp_name = format!("{} ({})", display_prefix, domain);
            let disp_wide = wide_str(&disp_name);

            unsafe {
                RegSetValueExW(hrule, wide_str("Version").as_ptr(), 0, REG_DWORD, &version_val as *const _ as *const u8, 4);
                RegSetValueExW(hrule, wide_str("Name").as_ptr(), 0, REG_SZ, ns_wide.as_ptr() as *const u8, (ns_wide.len() * 2) as u32);
                RegSetValueExW(hrule, wide_str("GenericDNSServers").as_ptr(), 0, REG_SZ, servers_wide.as_ptr() as *const u8, (servers_wide.len() * 2) as u32);
                RegSetValueExW(hrule, wide_str("Comment").as_ptr(), 0, REG_SZ, comment_wide.as_ptr() as *const u8, (comment_wide.len() * 2) as u32);
                RegSetValueExW(hrule, wide_str("DisplayName").as_ptr(), 0, REG_SZ, disp_wide.as_ptr() as *const u8, (disp_wide.len() * 2) as u32);
                RegSetValueExW(hrule, wide_str("ConfigOptions").as_ptr(), 0, REG_DWORD, &config_options as *const _ as *const u8, 4);
                RegCloseKey(hrule);
            }
            count += 1;
        }
    }

    count
}

pub fn take_over_conflicting_rules(_namespaces: &[&str]) -> Vec<String> {
    #[cfg(target_os = "windows")]
    {
        let ps_cmd = r#"
            $res = @()
            Get-DnsClientNrptRule -ErrorAction SilentlyContinue | ForEach-Object {
                $rule = $_
                foreach ($ns in $args) {
                    if ($rule.Namespace -eq $ns -or $rule.Namespace -eq ".$ns" -or $rule.Namespace -eq $ns.TrimStart('.')) {
                        Remove-DnsClientNrptRule -Name $rule.Name -Force -ErrorAction SilentlyContinue
                        $res += $rule.Name
                        break
                    }
                }
            }
            $res -join ','
        "#;
        let mut cmd = Command::new("powershell");
        no_window(&mut cmd);
        cmd.args(["-NoProfile", "-Command", ps_cmd]);
        for ns in _namespaces {
            cmd.arg(ns);
        }
        let out = cmd.output().ok();
        if let Some(o) = out {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if !s.is_empty() {
                return s.split(',').map(|x| x.trim().to_string()).collect();
            }
        }
    }
    Vec::new()
}
