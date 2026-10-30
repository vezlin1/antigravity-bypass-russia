use std::path::{Path, PathBuf};

/// Public command arguments, excluding the validated elevation handoff.
pub fn args() -> std::vec::IntoIter<String> {
    #[cfg(any(windows, unix))]
    return super::user_context::args();
    #[cfg(not(any(windows, unix)))]
    std::env::args().collect::<Vec<_>>().into_iter()
}

/// User-facing spelling only; filesystem operations retain the original path.
pub fn display_path(path: &Path) -> String {
    let text = path.to_string_lossy();
    #[cfg(windows)]
    {
        if let Some(unc) = text.strip_prefix(r"\\?\UNC\") {
            return format!(r"\\{unc}");
        }
        if let Some(disk) = text.strip_prefix(r"\\?\") {
            let bytes = disk.as_bytes();
            if bytes.len() >= 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && bytes[2] == b'\\'
            {
                return disk.to_owned();
            }
        }
    }
    text.into_owned()
}

pub fn expand_env_vars(input: &str) -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::ffi::OsStringExt;

        #[link(name = "kernel32")]
        extern "system" {
            fn ExpandEnvironmentStringsW(lpSrc: *const u16, lpDst: *mut u16, nSize: u32) -> u32;
        }

        let wide_in: Vec<u16> = OsStr::new(input)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut wide_out = vec![0u16; 4096];

        // The API returns the required size, including the final NUL. Retry
        // with that capacity rather than returning an unexpanded long path.
        for _ in 0..3 {
            let len = unsafe {
                ExpandEnvironmentStringsW(
                    wide_in.as_ptr(),
                    wide_out.as_mut_ptr(),
                    wide_out.len() as u32,
                )
            } as usize;
            if len == 0 || len > 32768 {
                break;
            }
            if len <= wide_out.len() {
                wide_out.truncate(len as usize - 1);
                return PathBuf::from(std::ffi::OsString::from_wide(&wide_out));
            }
            wide_out.resize(len, 0);
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        if input.starts_with("~/") || input == "~" {
            let subpath = if input.len() > 2 { &input[2..] } else { "" };
            #[cfg(unix)]
            {
                if let Ok(home) = super::user_context::home() {
                    return home.join(subpath);
                }
            }
            if let Ok(sudo_user) = std::env::var("SUDO_USER") {
                if !sudo_user.is_empty() && sudo_user != "root" {
                    let user_home = PathBuf::from(format!("/home/{}", sudo_user));
                    if user_home.exists() {
                        return user_home.join(subpath);
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
        #[cfg(unix)]
        {
            if let Ok(home) = super::user_context::home() {
                homes.push(home);
            }
        }
        if let Ok(sudo_user) = std::env::var("SUDO_USER") {
            if !sudo_user.is_empty() && sudo_user != "root" {
                let p = PathBuf::from(format!("/home/{}", sudo_user));
                if p.exists() && !homes.contains(&p) {
                    homes.push(p);
                }
            }
        }
        if let Ok(h) = std::env::var("HOME") {
            let p = PathBuf::from(h);
            if !homes.contains(&p) && p != PathBuf::from("/var/root") && p != PathBuf::from("/root")
            {
                homes.push(p);
            }
        }
    }
    homes
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn expands_variables_when_the_result_reaches_or_exceeds_the_initial_buffer() {
        let variable = "SystemRoot";
        let value = std::env::var(variable).unwrap();
        for characters in [4095, 5000] {
            let suffix = "x".repeat(characters - value.encode_utf16().count());
            let input = format!("%{variable}%{suffix}");
            let expected = PathBuf::from(format!("{value}{suffix}"));
            assert!(
                expand_env_vars(&input) == expected,
                "failed to expand a {characters}-character path"
            );
        }
    }
}
