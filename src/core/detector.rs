use crate::core::asar::read_asar_package_version;
use crate::core::patcher::BinaryState;
use crate::system::env::expand_env_vars;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    LanguageServer,
    IdeMainJs,
    IdeAsar,
    AgyCli,
}

#[derive(Debug, Clone)]
pub struct FoundTarget {
    pub path: PathBuf,
    pub kind: TargetKind,
    pub name: String,
}

pub(crate) fn is_agy_cli_name(name: &str) -> bool {
    matches!(name, "agy" | "agy.exe" | "antigravity" | "antigravity.exe")
        || (name.starts_with("agy-") && !name.ends_with(".bak") && !name.ends_with(".js"))
}

#[derive(Debug, Clone, Default)]
pub struct SystemComponentsStatus {
    pub core_status: Option<BinaryState>,
    pub ide_status: Option<BinaryState>,
    pub cli_status: Option<BinaryState>,
    pub asar_version: Option<String>,
    pub has_installations: bool,
    pub ide_installations: Vec<PathBuf>,
    pub incomplete_ide_installations: Vec<PathBuf>,
    pub cli_launchers: Vec<PathBuf>,
    pub ide_cli_available: bool,
}

pub fn find_asar_in_path(root: &Path) -> Option<PathBuf> {
    let asar_candidates = [
        root.join("resources").join("app.asar"),
        root.join("resources").join("app1.asar"),
        root.join("app.asar"),
        root.join("app1.asar"),
        root.join("Contents").join("Resources").join("app.asar"),
        root.join("Contents").join("Resources").join("app1.asar"),
    ];
    asar_candidates
        .into_iter()
        .find(|p| p.exists() && p.is_file())
}

fn is_already_contained(installs: &[PathBuf], candidate: &Path) -> bool {
    #[cfg(target_os = "windows")]
    {
        let cand_str = candidate.to_string_lossy().to_lowercase();
        let cand_canon = std::fs::canonicalize(candidate).ok();
        installs.iter().any(|existing| {
            if existing.to_string_lossy().to_lowercase() == cand_str {
                return true;
            }
            if let (Some(c1), Some(c2)) = (&cand_canon, std::fs::canonicalize(existing).ok()) {
                if c1 == &c2 {
                    return true;
                }
            }
            false
        })
    }
    #[cfg(not(target_os = "windows"))]
    {
        installs.iter().any(|existing| existing == candidate)
    }
}

pub fn find_installations() -> Vec<PathBuf> {
    let mut installs = Vec::new();

    #[cfg(target_os = "windows")]
    {
        let candidates = [
            r"%LOCALAPPDATA%\agy",
            r"%LOCALAPPDATA%\Programs\Antigravity",
            r"%LOCALAPPDATA%\Programs\antigravity",
            r"%LOCALAPPDATA%\Programs\Antigravity IDE",
            r"%LOCALAPPDATA%\Programs\antigravity-ide",
            r"%PROGRAMFILES%\Antigravity",
            r"%PROGRAMFILES%\Antigravity IDE",
            r"%PROGRAMFILES(X86)%\Antigravity",
            r"%PROGRAMFILES(X86)%\Antigravity IDE",
            r"%USERPROFILE%\scoop\apps\antigravity\current",
            r"%USERPROFILE%\scoop\apps\antigravity-ide\current",
        ];
        for c in candidates {
            let p = expand_env_vars(c);
            if p.exists() && p.is_dir() && !is_already_contained(&installs, &p) {
                installs.push(p);
            }
        }

        let ext_roots = [
            r"%USERPROFILE%\.vscode\extensions",
            r"%USERPROFILE%\.vscode-insiders\extensions",
            r"%USERPROFILE%\.cursor\extensions",
            r"%USERPROFILE%\.windsurf\extensions",
            r"%USERPROFILE%\.vscodium\extensions",
        ];
        for ext_root_str in ext_roots {
            let ext_dir = expand_env_vars(ext_root_str);
            if ext_dir.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&ext_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            let name = path
                                .file_name()
                                .unwrap_or_default()
                                .to_string_lossy()
                                .to_lowercase();
                            if (name.contains("antigravity")
                                || name.starts_with("google.antigravity"))
                                && !is_already_contained(&installs, &path)
                            {
                                installs.push(path);
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let candidates = [
            "/Applications/Antigravity.app",
            "/Applications/Antigravity IDE.app",
            "/Applications/Google Antigravity.app",
            "~/Applications/Antigravity.app",
            "~/Applications/Antigravity IDE.app",
            "~/Applications/Google Antigravity.app",
            "~/Library/Application Support/Antigravity",
            "~/Library/Application Support/Antigravity IDE",
            "~/Library/Application Support/Google Antigravity",
            "/opt/homebrew/Caskroom/antigravity",
            "/opt/homebrew/Caskroom/antigravity-ide",
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "~/.local/bin",
        ];
        for c in candidates {
            let p = expand_env_vars(c);
            if p.exists() && !installs.contains(&p) {
                installs.push(p);
            }
        }

        let ext_roots = [
            "~/.vscode/extensions",
            "~/.vscode-insiders/extensions",
            "~/.cursor/extensions",
            "~/.windsurf/extensions",
            "~/.vscodium/extensions",
        ];
        for ext_root_str in ext_roots {
            let ext_dir = expand_env_vars(ext_root_str);
            if ext_dir.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&ext_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            let name = path
                                .file_name()
                                .unwrap_or_default()
                                .to_string_lossy()
                                .to_lowercase();
                            if (name.contains("antigravity")
                                || name.starts_with("google.antigravity"))
                                && !installs.contains(&path)
                            {
                                installs.push(path);
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let candidates = [
            "/opt/antigravity",
            "/opt/Antigravity",
            "/opt/antigravity-ide",
            "/opt/Antigravity IDE",
            "/usr/lib/antigravity",
            "/usr/lib/antigravity-ide",
            "/usr/share/antigravity",
            "/usr/share/antigravity-ide",
            "~/.local/share/antigravity",
            "~/.local/share/antigravity-ide",
            "~/.config/Antigravity",
            "~/.config/Antigravity IDE",
        ];
        for c in candidates {
            let p = expand_env_vars(c);
            if p.exists() && !installs.contains(&p) {
                installs.push(p);
            }
        }

        let ext_roots = [
            "~/.vscode/extensions",
            "~/.vscode-insiders/extensions",
            "~/.cursor/extensions",
            "~/.windsurf/extensions",
            "~/.vscodium/extensions",
        ];
        for ext_root_str in ext_roots {
            let ext_dir = expand_env_vars(ext_root_str);
            if ext_dir.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&ext_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            let name = path
                                .file_name()
                                .unwrap_or_default()
                                .to_string_lossy()
                                .to_lowercase();
                            if (name.contains("antigravity")
                                || name.starts_with("google.antigravity"))
                                && !installs.contains(&path)
                            {
                                installs.push(path);
                            }
                        }
                    }
                }
            }
        }
    }

    // Discover native CLI installations outside the fixed application folders.
    // Only inspect named executables; never recursively scan every PATH directory.
    let mut cli_dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect())
        .unwrap_or_default();
    for home in crate::system::env::get_user_homes() {
        cli_dirs.push(home.join(".local/bin"));
        cli_dirs.push(home.join(".agy/bin"));
    }
    for dir in cli_dirs {
        for name in ["agy.exe", "agy"] {
            let path = dir.join(name);
            let path = std::fs::canonicalize(&path).unwrap_or(path);
            if native_executable(&path) && !is_already_contained(&installs, &path) {
                installs.push(path);
            }
        }
    }
    installs
}

fn native_executable(path: &Path) -> bool {
    use std::io::Read;
    let mut magic = [0u8; 4];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .is_ok()
        && (magic.starts_with(b"MZ")
            || magic == *b"\x7fELF"
            || matches!(
                magic,
                [0xcf, 0xfa, 0xed, 0xfe]
                    | [0xfe, 0xed, 0xfa, 0xcf]
                    | [0xca, 0xfe, 0xba, 0xbe]
                    | [0xbe, 0xba, 0xfe, 0xca]
            ))
}

pub fn find_targets_in_path(root: &Path) -> Vec<FoundTarget> {
    let mut targets = Vec::new();

    if root.is_file() {
        let name = root
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let kind = if name.ends_with(".asar") {
            TargetKind::IdeAsar
        } else if name.ends_with(".js") {
            TargetKind::IdeMainJs
        } else if is_agy_cli_name(&name) {
            TargetKind::AgyCli
        } else {
            TargetKind::LanguageServer
        };
        targets.push(FoundTarget {
            path: root.to_path_buf(),
            kind,
            name,
        });
        return targets;
    }

    let bin_names = [
        "language_server_windows_x64.exe",
        "language_server_windows_arm64.exe",
        "language_server.exe",
        "language_server_darwin_arm64",
        "language_server_darwin_x64",
        "language_server_linux_x64",
        "language_server_linux_arm64",
        "language_server_linux_amd64",
        "language_server",
        "agy.exe",
        "agy",
    ];

    let sub_paths = [
        PathBuf::from(""),
        PathBuf::from("bin"),
        PathBuf::from("resources"),
        PathBuf::from("resources").join("bin"),
        PathBuf::from("resources").join("app"),
        PathBuf::from("resources").join("app").join("bin"),
        PathBuf::from("resources")
            .join("app")
            .join("extensions")
            .join("antigravity")
            .join("bin"),
        PathBuf::from("resources")
            .join("app.asar.unpacked")
            .join("bin"),
        PathBuf::from("resources")
            .join("app.asar.unpacked")
            .join("extensions")
            .join("antigravity")
            .join("bin"),
        PathBuf::from("Contents").join("Resources"),
        PathBuf::from("Contents").join("Resources").join("bin"),
        PathBuf::from("Contents").join("Resources").join("app"),
        PathBuf::from("Contents")
            .join("Resources")
            .join("app")
            .join("bin"),
        PathBuf::from("Contents")
            .join("Resources")
            .join("app")
            .join("extensions")
            .join("antigravity")
            .join("bin"),
        PathBuf::from("Contents")
            .join("Resources")
            .join("app.asar.unpacked")
            .join("bin"),
        PathBuf::from("Contents")
            .join("Resources")
            .join("app.asar.unpacked")
            .join("extensions")
            .join("antigravity")
            .join("bin"),
        PathBuf::from("Contents").join("MacOS"),
    ];

    for sp in &sub_paths {
        let dir = root.join(sp);
        if !dir.exists() {
            continue;
        }

        for &bn in &bin_names {
            let p = dir.join(bn);
            if p.is_file() && (!bn.starts_with("agy") || native_executable(&p)) {
                let kind = if bn.starts_with("agy") {
                    TargetKind::AgyCli
                } else {
                    TargetKind::LanguageServer
                };
                if !targets.iter().any(|t: &FoundTarget| t.path == p) {
                    targets.push(FoundTarget {
                        path: p,
                        kind,
                        name: bn.to_string(),
                    });
                }
            }
        }
    }

    let js_rel_candidates = [
        PathBuf::from("resources")
            .join("app")
            .join("out")
            .join("vs")
            .join("code")
            .join("electron-main")
            .join("main.js"),
        PathBuf::from("Contents")
            .join("Resources")
            .join("app")
            .join("out")
            .join("vs")
            .join("code")
            .join("electron-main")
            .join("main.js"),
        PathBuf::from("resources")
            .join("app")
            .join("out")
            .join("main.js"),
        PathBuf::from("Contents")
            .join("Resources")
            .join("app")
            .join("out")
            .join("main.js"),
        PathBuf::from("out")
            .join("vs")
            .join("code")
            .join("electron-main")
            .join("main.js"),
        PathBuf::from("dist").join("extension.js"),
        PathBuf::from("out").join("extension.js"),
        PathBuf::from("extension.js"),
    ];

    for rel in &js_rel_candidates {
        let p = root.join(rel);
        if p.is_file() && !targets.iter().any(|t: &FoundTarget| t.path == p) {
            targets.push(FoundTarget {
                path: p,
                kind: TargetKind::IdeMainJs,
                name: "main.js (IDE)".to_string(),
            });
        }
    }

    if let Some(asar) = find_asar_in_path(root) {
        if !targets.iter().any(|t: &FoundTarget| t.path == asar) {
            let name = asar
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            targets.push(FoundTarget {
                path: asar,
                kind: TargetKind::IdeAsar,
                name: format!("{} (IDE)", name),
            });
        }
    }

    // Walk fallback for any unconventional subfolder
    walk_targets(root, 0, 8, &mut targets);

    targets
}

fn walk_targets(dir: &Path, depth: usize, max_depth: usize, targets: &mut Vec<FoundTarget>) {
    if depth > max_depth {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };

        let file_name_os = entry.file_name();
        let file_name = file_name_os.to_string_lossy();

        if file_type.is_dir() {
            if matches!(
                file_name.as_ref(),
                "node_modules"
                    | ".git"
                    | "Cache"
                    | "Code Cache"
                    | "GPUCache"
                    | "Session Storage"
                    | "IndexedDB"
                    | "Local Storage"
                    | "blob_storage"
                    | "Network"
                    | "Crashpad"
                    | "logs"
                    | "dist"
                    | "obj"
            ) {
                continue;
            }
            walk_targets(&entry.path(), depth + 1, max_depth, targets);
        } else if file_type.is_file() {
            let is_ls = (file_name.starts_with("language_server")
                && (file_name.ends_with(".exe") || !file_name.contains('.')))
                && !file_name.ends_with(".bak");
            let is_agy =
                (file_name == "agy.exe" || file_name == "agy" || file_name.starts_with("agy-"))
                    && !file_name.ends_with(".bak")
                    && native_executable(&entry.path());

            if is_ls || is_agy {
                let kind = if is_agy {
                    TargetKind::AgyCli
                } else {
                    TargetKind::LanguageServer
                };
                let path = entry.path();
                if !targets.iter().any(|t| t.path == path) {
                    targets.push(FoundTarget {
                        path,
                        kind,
                        name: file_name.to_string(),
                    });
                }
            } else if file_name == "main.js" {
                let path = entry.path();
                let path_str = path.to_string_lossy();
                if (path_str.contains("electron-main")
                    || path_str.ends_with(r"out\main.js")
                    || path_str.ends_with("out/main.js"))
                    && !targets.iter().any(|t| t.path == path)
                {
                    targets.push(FoundTarget {
                        path,
                        kind: TargetKind::IdeMainJs,
                        name: "main.js (IDE)".to_string(),
                    });
                }
            }
        }
    }
}

fn update_component_state(current: &mut Option<BinaryState>, new_state: BinaryState) {
    *current = Some(match *current {
        None => new_state,
        Some(old) if old == new_state => old,
        Some(BinaryState::Unknown) => BinaryState::Unknown,
        Some(_) if new_state == BinaryState::Unknown => BinaryState::Unknown,
        Some(_) => BinaryState::PartiallyPatched,
    });
}

#[cfg(test)]
mod detection_tests {
    use super::*;
    #[test]
    fn installed_ide_with_missing_resources_is_not_absent() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("Antigravity IDE.exe"), b"MZ00").unwrap();
        let roots = vec![root.path().to_path_buf()];
        let status = status_for_installations(&roots);
        assert_eq!(status.ide_installations, roots);
        assert_eq!(status.incomplete_ide_installations, roots);
        assert!(!status.ide_cli_available);
        let app = root.path().join("resources/app");
        std::fs::create_dir_all(app.join("out")).unwrap();
        std::fs::write(app.join("package.json"), b"{}").unwrap();
        std::fs::write(app.join("out/main.js"), b"// unknown UI version").unwrap();
        std::fs::write(app.join("out/cli.js"), b"// IDE launcher").unwrap();
        let status = status_for_installations(&roots);
        assert!(status.incomplete_ide_installations.is_empty());
        assert!(status.ide_cli_available);
        assert_eq!(status.ide_status, Some(BinaryState::Unknown));
    }
    #[test]
    fn cli_scripts_and_backups_are_not_binary_patch_targets() {
        let root = tempfile::tempdir().unwrap();
        for name in ["agy", "agy-helper.js", "agy-x64.exe.bak"] {
            std::fs::write(root.path().join(name), b"#!/bin/sh\necho launcher").unwrap();
        }
        std::fs::write(root.path().join("agy-x64.exe"), b"MZ00").unwrap();
        let targets = find_targets_in_path(root.path());
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].kind, TargetKind::AgyCli);
        assert_eq!(targets[0].name, "agy-x64.exe");
    }

    #[test]
    fn extracted_official_cli_file_is_not_classified_as_language_server() {
        let root = tempfile::tempdir().unwrap();
        for name in ["antigravity", "antigravity.exe"] {
            let path = root.path().join(name);
            std::fs::write(&path, b"\x7fELF").unwrap();
            let targets = find_targets_in_path(&path);
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].kind, TargetKind::AgyCli);
        }
    }
}

pub fn get_quick_status() -> SystemComponentsStatus {
    let installs = find_installations();
    status_for_installations(&installs)
}

fn status_for_installations(installs: &[PathBuf]) -> SystemComponentsStatus {
    let mut status = SystemComponentsStatus::default();
    status.has_installations = !installs.is_empty();

    for inst in installs {
        let app = if inst.join("Contents").is_dir() {
            inst.join("Contents/Resources/app")
        } else {
            inst.join("resources/app")
        };
        // Presence of the installed application is independent of a known patch pattern.
        let ide_present = inst.join("Antigravity IDE.exe").is_file()
            || app.join("product.json").is_file()
            || (inst
                .file_name()
                .is_some_and(|n| n.to_string_lossy().contains("IDE.app"))
                && inst.join("Contents/MacOS").is_dir());
        if ide_present {
            status.ide_installations.push(inst.clone());
            if !app.join("package.json").is_file()
                || !(app.join("out/main.js").is_file()
                    || app.join("out/vs/code/electron-main/main.js").is_file())
            {
                status.incomplete_ide_installations.push(inst.clone());
            }
            status.ide_cli_available |= app.join("out/cli.js").is_file();
        }
        for name in ["agy.cmd", "agy.ps1", "agy"] {
            let launcher = inst.join("bin").join(name);
            if launcher.is_file() && !native_executable(&launcher) {
                status.cli_launchers.push(launcher);
            }
        }
        let targets = find_targets_in_path(inst);
        for t in targets {
            let state = crate::core::patcher::check_target_state(&t);
            match t.kind {
                TargetKind::LanguageServer => {
                    update_component_state(&mut status.core_status, state);
                }
                TargetKind::IdeMainJs | TargetKind::IdeAsar => {
                    update_component_state(&mut status.ide_status, state);
                }
                TargetKind::AgyCli => {
                    update_component_state(&mut status.cli_status, state);
                }
            }
        }
        if status.asar_version.is_none() {
            if let Some(asar) = find_asar_in_path(inst) {
                status.asar_version = read_asar_package_version(&asar);
            }
        }
    }

    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            for name in ["agy.cmd", "agy.ps1", "agy"] {
                let path = dir.join(name);
                if path.is_file()
                    && !native_executable(&path)
                    && !status.cli_launchers.contains(&path)
                {
                    status.cli_launchers.push(path);
                }
            }
        }
    }

    status
}
