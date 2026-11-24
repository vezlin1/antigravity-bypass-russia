use super::detector::{find_targets_in_path, recover_targets_in_path, FoundTarget, TargetKind};
use super::patcher::{check_target_state, BinaryState};
use crate::net::config;
use crate::system::{env::mask_path, fs_utils::robust_write_file};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

fn settings_path() -> PathBuf {
    config::directory().join("manual-installations.json")
}

fn read_paths(settings: &Path) -> Result<Vec<PathBuf>, String> {
    match fs::read(settings) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|error| error.to_string()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error.to_string()),
    }
}

/// Saved paths, including ones no longer on disk.
pub fn saved() -> Vec<PathBuf> {
    read_paths(&settings_path())
        .unwrap_or_default()
        .into_iter()
        .filter(|path| path.is_absolute() && !is_gemini_desktop(path))
        .collect()
}

fn is_gemini_desktop(path: &Path) -> bool {
    path.ancestors().any(|part| {
        let name = part.file_name().unwrap_or_default();
        name.eq_ignore_ascii_case("Gemini.exe")
            || name.eq_ignore_ascii_case("Gemini.app")
            || (name.eq_ignore_ascii_case("Gemini")
                && part
                    .parent()
                    .and_then(Path::file_name)
                    .is_some_and(|parent| parent.eq_ignore_ascii_case("Google")))
    }) || path
        .ancestors()
        .take(4)
        .any(|dir| dir.join("Gemini.exe").is_file())
}

fn reject_gemini(path: &Path) -> Result<(), String> {
    if is_gemini_desktop(path) {
        return Err("Указан путь к Gemini Desktop. В пункте [4] укажите папку Antigravity App или IDE либо файл Antigravity CLI (agy.exe).".into());
    }
    Ok(())
}

fn validate(path: &Path) -> Result<(PathBuf, Vec<FoundTarget>), String> {
    reject_gemini(path)?;
    if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err("Укажите фактический путь к установке Antigravity.".into());
    }
    recover_targets_in_path(path)?;
    let root = fs::canonicalize(path)
        .map_err(|error| format!("Не удалось открыть {}: {error}", mask_path(path)))?;
    reject_gemini(&root)?;
    let found = find_targets_in_path(&root);
    if found.is_empty() {
        return Err(format!(
            "Файлы Antigravity не найдены в {}. Проверьте путь к установке.",
            mask_path(path)
        ));
    }
    // app.asar and main.js exist in every Electron/VS Code application; only
    // ones holding the Antigravity code (patched or not) identify Antigravity.
    let targets: Vec<_> = found
        .into_iter()
        .filter(|target| {
            !matches!(target.kind, TargetKind::IdeAsar | TargetKind::IdeMainJs)
                || check_target_state(target) != BinaryState::Unknown
        })
        .collect();
    if targets.is_empty() {
        return Err(format!(
            "В {} нет кода Antigravity: похоже, это другое приложение или неподдерживаемая версия. Укажите папку Antigravity App или IDE либо файл Antigravity CLI (agy.exe).",
            mask_path(path)
        ));
    }
    Ok((root, targets))
}

/// Checks a path without saving it, so the user can confirm what was found.
pub fn inspect(path: &Path) -> Result<(PathBuf, Vec<FoundTarget>), String> {
    validate(path)
}

pub fn save(root: &Path) -> Result<(), String> {
    config::ensure_directory()?;
    write_path(&settings_path(), root)
}

/// Removes a saved path; `false` when it was not saved.
pub fn forget(root: &Path) -> Result<bool, String> {
    remove_path(&settings_path(), root)
}

fn remove_path(settings: &Path, root: &Path) -> Result<bool, String> {
    let mut paths = read_paths(settings)?;
    let before = paths.len();
    paths.retain(|path| path != root);
    if paths.len() == before {
        return Ok(false);
    }
    let bytes = serde_json::to_vec_pretty(&paths).map_err(|error| error.to_string())?;
    robust_write_file(settings, &bytes)?;
    Ok(true)
}

fn write_path(settings: &Path, root: &Path) -> Result<(), String> {
    // The interactive menu holds the application's single-instance lock.
    let mut paths = read_paths(settings)?;
    paths.retain(|path| path != root);
    paths.insert(0, root.to_path_buf());
    let bytes = serde_json::to_vec_pretty(&paths).map_err(|error| error.to_string())?;
    robust_write_file(settings, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonstandard_installations_are_saved_and_reloaded_without_duplicates() {
        let temp = tempfile::tempdir().unwrap();
        let settings = temp.path().join("manual-installations.json");
        assert!(read_paths(&settings).unwrap().is_empty());
        let mut installations = Vec::new();
        for folder in ["Антигравити App", "Antigravity IDE"] {
            let install = temp.path().join(folder);
            let out = install.join("resources/app/out");
            fs::create_dir_all(&out).unwrap();
            fs::write(out.join("main.js"), STOCK_JS).unwrap();
            let (root, targets) = validate(&install).unwrap();
            assert_eq!(targets.len(), 1);
            write_path(&settings, &root).unwrap();
            installations.push(root);
        }
        write_path(&settings, &installations[0]).unwrap();
        let reloaded = read_paths(&settings).unwrap();
        assert_eq!(reloaded, installations);
        assert_eq!(
            super::super::detector::find_installation_targets(&reloaded).len(),
            2
        );
    }

    const STOCK_JS: &[u8] = b"x.resetIsTierGCPTos(),x.isGoogleInternal";

    #[test]
    fn other_electron_applications_are_rejected_and_only_antigravity_files_kept() {
        let temp = tempfile::tempdir().unwrap();
        // Slack/Discord-like archive and a VS Code-like main.js without the
        // Antigravity code.
        let install = temp.path().join("Other app");
        let out = install.join("resources/app/out");
        fs::create_dir_all(&out).unwrap();
        fs::write(install.join("resources/app.asar"), b"fixture").unwrap();
        fs::write(out.join("main.js"), b"require('./bootstrap')").unwrap();
        assert!(!find_targets_in_path(&install).is_empty());
        assert!(validate(&install)
            .unwrap_err()
            .contains("нет кода Antigravity"));

        // The Antigravity app: its own archive has no IDE code, its language
        // server identifies it.
        let bin = install.join("resources/bin");
        fs::create_dir_all(&bin).unwrap();
        fs::write(bin.join("language_server.exe"), b"MZ").unwrap();
        let (_, targets) = validate(&install).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].kind, TargetKind::LanguageServer);

        // A patched IDE file is still recognised, so it can be rolled back.
        fs::write(out.join("main.js"), b"x.resetIsTierGCPTos(),true").unwrap();
        assert_eq!(validate(&install).unwrap().1.len(), 2);
    }

    #[test]
    fn saved_path_can_be_removed() {
        let temp = tempfile::tempdir().unwrap();
        let settings = temp.path().join("manual-installations.json");
        let (first, second) = (temp.path().join("first"), temp.path().join("second"));
        assert!(!remove_path(&settings, &first).unwrap());
        write_path(&settings, &first).unwrap();
        write_path(&settings, &second).unwrap();
        assert!(remove_path(&settings, &first).unwrap());
        assert_eq!(read_paths(&settings).unwrap(), vec![second.clone()]);
        assert!(!remove_path(&settings, &first).unwrap());
        assert!(remove_path(&settings, &second).unwrap());
        assert!(read_paths(&settings).unwrap().is_empty());
    }

    #[test]
    fn rejects_gemini_desktop_from_issue_33_and_moved_installations() {
        let temp = tempfile::tempdir().unwrap();
        for path in ["Google/Gemini/app-1.17.0", "Moved application"] {
            let install = temp.path().join(path);
            let resources = install.join("resources");
            fs::create_dir_all(&resources).unwrap();
            let archive = resources.join("app.asar");
            fs::write(&archive, b"fixture").unwrap();
            if path == "Moved application" {
                fs::write(install.join("Gemini.exe"), b"fixture").unwrap();
            }
            assert!(!find_targets_in_path(&install).is_empty());
            let message = validate(&install).unwrap_err();
            assert!(message.contains("Gemini Desktop"));
            assert!(message.contains("Antigravity"));
            assert!(validate(&archive).unwrap_err().contains("Gemini Desktop"));
            assert_eq!(fs::read(&archive).unwrap(), b"fixture");
        }
    }
}
