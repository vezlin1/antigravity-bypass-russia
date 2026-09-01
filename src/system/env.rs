use std::path::{Path, PathBuf};

pub fn expand_env_vars(input: &str) -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::ffi::OsStringExt;

        #[link(name = "kernel32")]
        extern "system" {
            fn ExpandEnvironmentStringsW(
                lpSrc: *const u16,
                lpDst: *mut u16,
                nSize: u32,
            ) -> u32;
        }

        let wide_in: Vec<u16> = OsStr::new(input)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut wide_out = vec![0u16; 4096];

        unsafe {
            let len = ExpandEnvironmentStringsW(
                wide_in.as_ptr(),
                wide_out.as_mut_ptr(),
                wide_out.len() as u32,
            );
            if len > 0 && (len as usize) < wide_out.len() {
                wide_out.truncate(len as usize - 1);
                return PathBuf::from(std::ffi::OsString::from_wide(&wide_out));
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        if input.starts_with("~/") || input == "~" {
            let subpath = if input.len() > 2 { &input[2..] } else { "" };
            #[cfg(target_os = "macos")]
            {
                if let Ok(sudo_user) = std::env::var("SUDO_USER") {
                    if !sudo_user.is_empty() && sudo_user != "root" {
                        let user_home = PathBuf::from(format!("/Users/{}", sudo_user));
                        if user_home.exists() {
                            return user_home.join(subpath);
                        }
                    }
                }
                // When elevated via GUI / osascript, query the active console user
                if let Ok(out) = std::process::Command::new("stat").args(["-f", "%Su", "/dev/console"]).output() {
                    let user = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if !user.is_empty() && user != "root" {
                        let user_home = PathBuf::from(format!("/Users/{}", user));
                        if user_home.exists() {
                            return user_home.join(subpath);
                        }
                    }
                }
            }
            #[cfg(all(unix, not(target_os = "macos")))]
            {
                if let Ok(sudo_user) = std::env::var("SUDO_USER") {
                    if !sudo_user.is_empty() && sudo_user != "root" {
                        let user_home = PathBuf::from(format!("/home/{}", sudo_user));
                        if user_home.exists() {
                            return user_home.join(subpath);
                        }
                    }
                }
            }
            if let Ok(home) = std::env::var("HOME") {
                return PathBuf::from(home).join(subpath);
            }
        }
    }

    PathBuf::from(input)
}

pub fn mask_path(path: &Path) -> String {
    let p = path.to_string_lossy();
    if let Ok(appdata) = std::env::var("LOCALAPPDATA") {
        if p.starts_with(&appdata) {
            return p.replace(&appdata, "%LOCALAPPDATA%");
        }
    }
    if let Ok(appdata) = std::env::var("APPDATA") {
        if p.starts_with(&appdata) {
            return p.replace(&appdata, "%APPDATA%");
        }
    }
    if let Ok(home) = std::env::var("USERPROFILE") {
        if p.starts_with(&home) {
            return p.replace(&home, "%USERPROFILE%");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if p.starts_with(&home) {
            return p.replace(&home, "~");
        }
    }
    p.to_string()
}

pub fn get_user_homes() -> Vec<PathBuf> {
    let mut homes = Vec::new();
    #[cfg(target_os = "windows")]
    {
        if let Ok(u) = std::env::var("USERPROFILE") {
            homes.push(PathBuf::from(u));
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        #[cfg(target_os = "macos")]
        {
            if let Ok(sudo_user) = std::env::var("SUDO_USER") {
                if !sudo_user.is_empty() && sudo_user != "root" {
                    let p = PathBuf::from(format!("/Users/{}", sudo_user));
                    if p.exists() && !homes.contains(&p) {
                        homes.push(p);
                    }
                }
            }
            if let Ok(out) = std::process::Command::new("stat").args(["-f", "%Su", "/dev/console"]).output() {
                let user = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !user.is_empty() && user != "root" {
                    let p = PathBuf::from(format!("/Users/{}", user));
                    if p.exists() && !homes.contains(&p) {
                        homes.push(p);
                    }
                }
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            if let Ok(sudo_user) = std::env::var("SUDO_USER") {
                if !sudo_user.is_empty() && sudo_user != "root" {
                    let p = PathBuf::from(format!("/home/{}", sudo_user));
                    if p.exists() {
                        homes.push(p);
                    }
                }
            }
        }
        if let Ok(h) = std::env::var("HOME") {
            let p = PathBuf::from(h);
            if !homes.contains(&p) && p != PathBuf::from("/var/root") && p != PathBuf::from("/root") {
                homes.push(p);
            }
        }
    }
    homes
}
