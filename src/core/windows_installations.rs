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
            let suffix = name.strip_prefix(label)?;
            (suffix.is_empty() || suffix.starts_with(' ') && installer_suffix(suffix))
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

/// Installers append versions and scope labels to the product name, such as
/// "2.34.0", "v1.5.13-beta.1", "(User)" or "(x64)". Any other word belongs to
/// a different product, for example "Antigravity Bypass".
fn installer_suffix(suffix: &str) -> bool {
    let mut rest = suffix.trim();
    let mut tokens = Vec::new();
    while !rest.is_empty() {
        if let Some(inner) = rest.strip_prefix('(') {
            let Some((scope, after)) = inner.split_once(')') else {
                return false;
            };
            if scope.trim().is_empty()
                || !scope
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_'))
            {
                return false;
            }
            rest = after.trim_start();
            continue;
        }
        let end = rest.find([' ', '(']).unwrap_or(rest.len());
        tokens.push(&rest[..end]);
        rest = rest[end..].trim_start();
    }
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    let label = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric());
    tokens.into_iter().all(|token| {
        let token = token.strip_prefix('v').unwrap_or(token);
        let (number, prerelease) = match token.split_once('-') {
            Some((number, prerelease)) => (number, Some(prerelease)),
            None => (token, None),
        };
        number.split('.').all(digits)
            && prerelease.is_none_or(|prerelease| prerelease.split('.').all(label))
    })
}

/// Variables that the elevated process resolves for the initiating user, or
/// that are the same for every user. Other profile variables, such as
/// %HOMEPATH% or %TEMP%, would expand into the elevated account's profile.
const EXPANDABLE: &[&str] = &[
    "userprofile",
    "localappdata",
    "appdata",
    "programfiles",
    "programfiles(x86)",
    "programw6432",
    "programdata",
    "commonprogramfiles",
    "commonprogramfiles(x86)",
    "commonprogramw6432",
    "systemdrive",
    "systemroot",
    "windir",
];

fn expandable(text: &str) -> bool {
    let mut parts = text.split('%');
    parts.next();
    let mut names = Vec::new();
    while let Some(name) = parts.next() {
        if parts.next().is_none() {
            return false;
        }
        names.push(name);
    }
    names
        .iter()
        .all(|name| EXPANDABLE.contains(&name.to_ascii_lowercase().as_str()))
}

fn local_path(text: &str) -> Option<PathBuf> {
    let text = text.trim().trim_matches('"');
    if !expandable(text) {
        return None;
    }
    let path = expand_env_vars(text);
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
    fn accepts_installer_versions_and_scope_labels_but_not_other_products() {
        for (name, ide, cli) in [
            ("Antigravity (User)", false, false),
            ("Antigravity 2.34.0 (User)", false, false),
            ("Google Antigravity (x64) 2.34.0", false, false),
            ("Antigravity v2.35.0-beta.1", false, false),
            ("Antigravity IDE (Machine - x64)", true, false),
            ("Antigravity CLI 1.5.13 (per_user)", false, true),
        ] {
            let product = Product::from_name(name).unwrap_or_else(|| panic!("{name}"));
            assert_eq!(matches!(product, Product::Ide), ide, "{name}");
            assert_eq!(matches!(product, Product::Cli), cli, "{name}");
        }
        for name in [
            "Antigravity Bypass 2.6.0",
            "Antigravity x64",
            "Antigravity (User",
            "Antigravity ()",
            "Antigravity (a.b)",
            "Antigravity 2.34.0-",
            "Antigravity 2..0",
            "Antigravityfix",
        ] {
            assert!(Product::from_name(name).is_none(), "{name}");
        }
    }

    #[test]
    fn profile_variables_of_another_account_are_not_expanded() {
        assert!(local_path(r"%LOCALAPPDATA%\Programs\Antigravity").is_some());
        assert!(local_path(r"%ProgramFiles%\Antigravity").is_some());
        for text in [
            r"%HOMEDRIVE%%HOMEPATH%\Antigravity",
            r"%TEMP%\Antigravity",
            r"%OneDrive%\Antigravity",
            r"C:@%\Antigravity",
        ] {
            assert!(local_path(text).is_none(), "{text}");
        }
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
