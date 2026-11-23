//! Read the Windows uninstall records for Antigravity installations.
use super::detector::{native_cli, CLI_NAMES};
use crate::system::{env::expand_env_vars, user_context};
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
    KEY_WOW64_32KEY, KEY_WOW64_64KEY, RRF_NOEXPAND, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ,
};

const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}

impl Key {
    fn open(parent: HKEY, path: &[u16], view: u32) -> Option<Self> {
        let mut key = null_mut();
        let code = unsafe { RegOpenKeyExW(parent, path.as_ptr(), 0, KEY_READ | view, &mut key) };
        (code == ERROR_SUCCESS).then(|| Self(key))
    }

    fn text(&self, name: &str) -> Option<String> {
        let name: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
        let mut size = 0;
        let read = |data, size| unsafe {
            RegGetValueW(
                self.0,
                std::ptr::null(),
                name.as_ptr(),
                RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND,
                null_mut(),
                data,
                size,
            )
        };
        if read(null_mut(), &mut size) != ERROR_SUCCESS || size == 0 || size > 64 * 1024 {
            return None;
        }
        let mut units = vec![0u16; (size as usize).div_ceil(2)];
        if read(units.as_mut_ptr().cast(), &mut size) != ERROR_SUCCESS || size % 2 != 0 {
            return None;
        }
        units.truncate(size as usize / 2);
        let end = units
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(units.len());
        String::from_utf16(&units[..end]).ok()
    }

    fn installations(&self, view: u32) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        for index in 0.. {
            let mut name = [0u16; 256];
            let mut length = name.len() as u32;
            let code = unsafe {
                RegEnumKeyExW(
                    self.0,
                    index,
                    name.as_mut_ptr(),
                    &mut length,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                )
            };
            match code {
                ERROR_SUCCESS => {}
                ERROR_MORE_DATA => continue,
                _ => break,
            }
            let Some(entry) = Self::open(self.0, &name, view) else {
                continue;
            };
            let Some(product) = entry
                .text("DisplayName")
                .as_deref()
                .and_then(Product::from_name)
            else {
                continue;
            };
            let location = entry.text("InstallLocation");
            let icon = entry.text("DisplayIcon");
            if let Some(path) = product.installation(location.as_deref(), icon.as_deref()) {
                paths.push(path);
            }
        }
        paths
    }
}

pub(super) fn find() -> Vec<PathBuf> {
    let (user, user_path) = user_context::user_registry_key(UNINSTALL);
    let machine_path: Vec<_> = UNINSTALL.encode_utf16().chain(Some(0)).collect();
    let mut paths = Vec::new();
    for (hive, path) in [(user, user_path), (HKEY_LOCAL_MACHINE, machine_path)] {
        for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
            if let Some(key) = Key::open(hive, &path, view) {
                paths.extend(key.installations(view));
            }
        }
    }
    paths
}

#[derive(Clone, Copy)]
enum Product {
    App,
    Ide,
    Cli,
}

impl Product {
    fn from_name(display_name: &str) -> Option<Self> {
        let name = display_name.trim().to_ascii_lowercase();
        let name = name.strip_prefix("google ").unwrap_or(&name);
        [
            ("antigravity ide", Self::Ide),
            ("antigravity cli", Self::Cli),
            ("antigravity", Self::App),
            ("agy", Self::Cli),
        ]
        .into_iter()
        .find_map(|(label, product)| {
            let version = name.strip_prefix(label)?;
            (version.is_empty()
                || version.strip_prefix(' ').is_some_and(|suffix| {
                    let version = suffix.strip_prefix('v').unwrap_or(suffix);
                    version.split('.').all(|part| {
                        !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())
                    })
                }))
            .then_some(product)
        })
    }

    fn installation(self, location: Option<&str>, icon: Option<&str>) -> Option<PathBuf> {
        location
            .and_then(local_path)
            .filter(|path| self.is_installation(path))
            .or_else(|| {
                let icon = icon?.trim();
                let path = match icon.rsplit_once(',') {
                    Some((path, index)) if index.trim().parse::<i32>().is_ok() => path,
                    _ => icon,
                };
                let launcher = local_path(path)?;
                let name = launcher.file_name()?.to_str()?;
                let root = launcher.parent()?;
                match self {
                    Self::Cli if native_cli(&launcher, name) => Some(root.to_path_buf()),
                    Self::App | Self::Ide
                        if self.is_launcher_name(name)
                            && launcher.is_file()
                            && self.is_installation(root) =>
                    {
                        Some(root.to_path_buf())
                    }
                    _ => None,
                }
            })
    }

    fn is_launcher_name(self, name: &str) -> bool {
        name.eq_ignore_ascii_case("Antigravity.exe")
            || matches!(self, Self::Ide) && name.eq_ignore_ascii_case("Antigravity IDE.exe")
    }

    fn is_installation(self, root: &Path) -> bool {
        match self {
            Self::App => root.join("Antigravity.exe").is_file() && root.join("resources").is_dir(),
            Self::Ide => {
                (root.join("Antigravity IDE.exe").is_file()
                    || root.join("Antigravity.exe").is_file())
                    && root.join("resources/app").is_dir()
            }
            Self::Cli => [root.to_path_buf(), root.join("bin")].iter().any(|dir| {
                CLI_NAMES
                    .iter()
                    .any(|name| native_cli(&dir.join(name), name))
            }),
        }
    }
}

fn local_path(text: &str) -> Option<PathBuf> {
    let path = expand_env_vars(text.trim().trim_matches('"'));
    (path.is_absolute()
        && path.file_name().is_some()
        && matches!(
            path.components().next(),
            Some(Component::Prefix(prefix))
                if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        ))
    .then_some(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn resolves_app_from_display_icon_when_install_location_is_missing_or_stale() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp
            .path()
            .join("Google, custom folder")
            .join("Antigravity");
        fs::create_dir_all(root.join("resources")).unwrap();
        let launcher = root.join("Antigravity.exe");
        fs::write(&launcher, b"fixture").unwrap();
        let product = Product::from_name("Antigravity 2.34.0").unwrap();
        let missing = temp.path().join("missing");
        for icon in [
            format!("{},0", launcher.display()),
            format!("\"{}\",-1", launcher.display()),
            launcher.display().to_string(),
        ] {
            assert_eq!(
                product.installation(missing.to_str(), Some(&icon)),
                Some(root.clone())
            );
        }
    }

    #[test]
    fn validates_the_installation_layout_and_ignores_unrelated_products() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("IDE on another drive");
        fs::create_dir_all(root.join("resources/app")).unwrap();
        let product = Product::from_name("Google Antigravity IDE 2.8.0").unwrap();
        let location = format!("\"{}\"", root.display());
        assert_eq!(product.installation(Some(&location), None), None);
        fs::write(root.join("Antigravity IDE.exe"), b"fixture").unwrap();
        assert_eq!(product.installation(Some(&location), None), Some(root));
        assert!(Product::from_name("Antigravity CLI 1.5.13").is_some());
        for name in [
            "Gemini Desktop",
            "Antigravity Bypass",
            "Antigravity Unlocker",
        ] {
            assert!(Product::from_name(name).is_none(), "{name}");
        }
        assert!(local_path(r"..\Antigravity").is_none());
        assert!(local_path(r"\\server\share\Antigravity").is_none());
    }

    #[test]
    #[ignore = "set ABR_WINDOWS_REGISTERED_INSTALL to an installed Antigravity directory"]
    fn reads_the_real_uninstall_registration() {
        let expected = PathBuf::from(std::env::var_os("ABR_WINDOWS_REGISTERED_INSTALL").unwrap());
        let expected = fs::canonicalize(expected).unwrap();
        assert!(find()
            .into_iter()
            .any(|path| fs::canonicalize(path).ok().as_ref() == Some(&expected)));
    }
}
