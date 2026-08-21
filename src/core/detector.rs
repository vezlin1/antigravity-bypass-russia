use std::path::{Path, PathBuf};
use crate::core::asar::read_asar_package_version;
use crate::core::patcher::{check_binary_state, BinaryState};
use crate::system::env::expand_env_vars;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    LanguageServer,
    IdeMainJs,
    AgyCli,
}

#[derive(Debug, Clone)]
pub struct FoundTarget {
    pub path: PathBuf,
    pub kind: TargetKind,
    pub name: String,
}

#[derive(Debug, Clone, Default)]
pub struct SystemComponentsStatus {
    pub core_status: Option<BinaryState>,
    pub ide_status: Option<BinaryState>,
    pub cli_status: Option<BinaryState>,
    pub asar_version: Option<String>,
    pub has_installations: bool,
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
    asar_candidates.into_iter().find(|p| p.exists() && p.is_file())
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
                            let name = path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
                            if (name.contains("antigravity") || name.starts_with("google.antigravity")) && !is_already_contained(&installs, &path) {
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
            "~/Applications/Antigravity.app",
            "~/Applications/Antigravity IDE.app",
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
                            let name = path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
                            if (name.contains("antigravity") || name.starts_with("google.antigravity")) && !installs.contains(&path) {
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
            "/usr/share/antigravity",
            "~/.local/share/antigravity",
        ];
        for c in candidates {
            let p = expand_env_vars(c);
            if p.exists() && p.is_dir() && !installs.contains(&p) {
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
                            let name = path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
                            if (name.contains("antigravity") || name.starts_with("google.antigravity")) && !installs.contains(&path) {
                                installs.push(path);
                            }
                        }
                    }
                }
            }
        }
    }

    installs
}

pub fn find_targets_in_path(root: &Path) -> Vec<FoundTarget> {
    let mut targets = Vec::new();

    if root.is_file() {
        let name = root.file_name().unwrap_or_default().to_string_lossy().to_string();
        let kind = if name.ends_with(".js") {
            TargetKind::IdeMainJs
        } else if name.contains("agy") {
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
        PathBuf::from("resources").join("app").join("extensions").join("antigravity").join("bin"),
        PathBuf::from("resources").join("app.asar.unpacked").join("bin"),
        PathBuf::from("Contents").join("Resources"),
        PathBuf::from("Contents").join("Resources").join("bin"),
        PathBuf::from("Contents").join("Resources").join("app"),
        PathBuf::from("Contents").join("Resources").join("app").join("bin"),
        PathBuf::from("Contents").join("Resources").join("app").join("extensions").join("antigravity").join("bin"),
        PathBuf::from("Contents").join("Resources").join("app.asar.unpacked").join("bin"),
        PathBuf::from("Contents").join("MacOS"),
    ];

    for sp in &sub_paths {
        let dir = root.join(sp);
        if !dir.exists() {
            continue;
        }

        for &bn in &bin_names {
            let p = dir.join(bn);
            if p.is_file() {
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
        PathBuf::from("resources").join("app").join("out").join("vs").join("code").join("electron-main").join("main.js"),
        PathBuf::from("Contents").join("Resources").join("app").join("out").join("vs").join("code").join("electron-main").join("main.js"),
        PathBuf::from("out").join("vs").join("code").join("electron-main").join("main.js"),
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

    // Shallow walk fallback (depth <= 4) for any unconventional subfolder
    walk_targets(root, 0, 4, &mut targets);

    targets
}

fn walk_targets(dir: &Path, depth: usize, max_depth: usize, targets: &mut Vec<FoundTarget>) {
    if depth > max_depth {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else { return; };
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
            let is_agy = (file_name == "agy.exe" || file_name == "agy" || file_name.starts_with("agy-"))
                && !file_name.ends_with(".bak");

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
                if path.to_string_lossy().contains("electron-main")
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

pub fn get_quick_status() -> SystemComponentsStatus {
    let mut status = SystemComponentsStatus::default();
    let installs = find_installations();
    status.has_installations = !installs.is_empty();

    for inst in &installs {
        let targets = find_targets_in_path(inst);
        for t in targets {
            let state = check_binary_state(&t.path);
            match t.kind {
                TargetKind::LanguageServer => {
                    if status.core_status.is_none() || status.core_status == Some(BinaryState::Stock) {
                        status.core_status = Some(state);
                    }
                }
                TargetKind::IdeMainJs => {
                    if status.ide_status.is_none() || status.ide_status == Some(BinaryState::Stock) {
                        status.ide_status = Some(state);
                    }
                }
                TargetKind::AgyCli => {
                    if status.cli_status.is_none() || status.cli_status == Some(BinaryState::Stock) {
                        status.cli_status = Some(state);
                    }
                }
            }
        }
        if status.asar_version.is_none() {
            if let Some(asar) = find_asar_in_path(inst) {
                status.asar_version = read_asar_package_version(&asar);
            }
        }
    }

    status
}
