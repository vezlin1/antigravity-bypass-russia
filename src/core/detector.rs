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
    let name = name.to_ascii_lowercase();
    matches!(
        name.as_str(),
        "agy" | "agy.exe" | "antigravity" | "antigravity.exe"
    ) || (name.starts_with("agy-")
        && Path::new(&name)
            .extension()
            .is_none_or(|extension| extension == "exe"))
}

const CLI_NAMES: [&str; 4] = ["agy.exe", "agy", "antigravity.exe", "antigravity"];

fn same_target_path(left: &Path, right: &Path) -> bool {
    #[cfg(windows)]
    return left
        .to_string_lossy()
        .replace('/', "\\")
        .eq_ignore_ascii_case(&right.to_string_lossy().replace('/', "\\"));
    // APFS is case-insensitive by default: a listed "Antigravity.exe" and a probed
    // "antigravity.exe" are one file. Compare identity, not spelling.
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::MetadataExt;
        left == right
            || matches!(
                (std::fs::metadata(left), std::fs::metadata(right)),
                (Ok(a), Ok(b)) if a.dev() == b.dev() && a.ino() == b.ino()
            )
    }
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
    for path in cli_files_in_dirs(&cli_search_dirs()) {
        if !is_already_contained(&installs, &path) {
            installs.push(path);
        }
    }
    installs
}

fn cli_search_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<_> = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect())
        .unwrap_or_default();
    for home in crate::system::env::get_user_homes() {
        dirs.push(home.join(".local/bin"));
        dirs.push(home.join(".agy/bin"));
    }
    dirs
}

/// Only mutating commands call recovery. Read-only discovery/status never
/// resurrect files or finalize transactions.
pub fn recover_installations() -> Result<(), String> {
    recover_cli_in_dirs(&cli_search_dirs())?;
    for root in find_installations() {
        recover_targets_in_path(&root)?;
    }
    Ok(())
}

fn recover_cli_in_dirs(dirs: &[PathBuf]) -> Result<(), String> {
    for dir in dirs {
        recover_directory(dir, 0, 0, None, true)?;
    }
    Ok(())
}

/// Restore claimed files before target discovery, including an explicit path
/// whose filename disappeared when the previous process was interrupted.
pub fn recover_targets_in_path(root: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(root) {
        Ok(metadata) if metadata.file_type().is_symlink() => Ok(()),
        Ok(metadata) if metadata.is_dir() => recover_directory(root, 0, 8, None, false),
        Ok(_) => recover_explicit_file(root),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => recover_explicit_file(root),
        Err(error) => Err(format!("{}: {error}", root.display())),
    }
}

fn recover_explicit_file(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .ok_or("Нет имени восстанавливаемого файла")?;
    recover_directory(parent, 0, 0, Some(name), false)
}

fn recovery_kind(name: &str, captured: &Path) -> Option<TargetKind> {
    if native_cli(captured, name) {
        Some(TargetKind::AgyCli)
    } else if name.starts_with("language_server")
        && (name.ends_with(".exe") || !name.contains('.'))
        && native_executable(captured)
    {
        Some(TargetKind::LanguageServer)
    } else if matches!(name, "main.js" | "extension.js") {
        Some(TargetKind::IdeMainJs)
    } else if matches!(name, "app.asar" | "app1.asar") {
        Some(TargetKind::IdeAsar)
    } else {
        None
    }
}

fn recover_directory(
    directory: &Path,
    depth: usize,
    max_depth: usize,
    only_name: Option<&std::ffi::OsStr>,
    cli_only: bool,
) -> Result<(), String> {
    if std::fs::symlink_metadata(directory).is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Ok(());
    }
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("{}: {error}", directory.display())),
    };
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        if !entry
            .file_type()
            .map_err(|error| error.to_string())?
            .is_dir()
        {
            continue;
        }
        let name_os = entry.file_name();
        let dir_name = name_os.to_string_lossy();
        let path = entry.path();
        if dir_name.starts_with('.') && dir_name.contains(".ag-transaction-") {
            if std::fs::symlink_metadata(path.join("COMMITTED")).is_ok() {
                continue;
            }
            let marker = path.join("PENDING");
            if !regular_file(&marker) {
                continue;
            }
            let Ok(name) = std::fs::read_to_string(&marker) else {
                continue;
            };
            if name.is_empty()
                || name.contains(['/', '\\', '\0', ':'])
                || !matches!(
                    Path::new(&name).components().next(),
                    Some(std::path::Component::Normal(_))
                )
                || !dir_name.starts_with(&format!(".{name}.ag-transaction-"))
                || only_name.is_some_and(|selected| selected != std::ffi::OsStr::new(&name))
            {
                continue;
            }
            let captured = path.join("captured");
            if !regular_file(&captured) {
                continue;
            }
            let kind = recovery_kind(&name, &captured);
            if kind.is_none() || (cli_only && kind != Some(TargetKind::AgyCli)) {
                continue;
            }
            crate::system::fs_utils::recover_pending(&directory.join(name))?;
        } else if depth < max_depth
            && !matches!(
                dir_name.as_ref(),
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
            )
            && !dir_name.ends_with(".ag-backups")
        {
            recover_directory(&path, depth + 1, max_depth, only_name, cli_only)?;
        }
    }
    Ok(())
}

fn cli_files_in_dirs(dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for dir in dirs {
        for name in CLI_NAMES {
            // Resolve PATH launchers to their real file, never patch the link itself.
            let Ok(path) = std::fs::canonicalize(dir.join(name)) else {
                continue;
            };
            let target_name = path.file_name().unwrap_or_default().to_string_lossy();
            if native_cli(&path, &target_name) && !files.contains(&path) {
                files.push(path);
            }
        }
    }
    files
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

fn regular_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
}

fn regular_file_under(root: &Path, path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(root) else {
        return false;
    };
    let mut candidate = root.to_path_buf();
    for component in relative.components() {
        candidate.push(component);
        if !std::fs::symlink_metadata(&candidate)
            .is_ok_and(|metadata| !metadata.file_type().is_symlink())
        {
            return false;
        }
    }
    regular_file(path)
}

fn native_cli(path: &Path, name: &str) -> bool {
    if !is_agy_cli_name(name) || !regular_file(path) || !native_executable(path) {
        return false;
    }
    // The IDE's Electron executable has the same official name. Go build-info
    // distinguishes the native CLI without depending on a particular patch profile.
    // Read only headers and small data ranges, not an entire 180+ MB executable.
    use object::{Object, ObjectSection, ReadRef};
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let cache = object::read::ReadCache::new(file);
    let Ok(binary) = object::File::parse(&cache) else {
        return false;
    };
    binary.sections().any(|section| {
        if !matches!(
            section.name(),
            Ok(".go.buildinfo" | "__go_buildinfo" | ".data")
        ) {
            return false;
        }
        let Some((offset, size)) = section.file_range() else {
            return false;
        };
        let Ok(bytes) = (&cache).read_bytes_at(offset, size.min(64 * 1024)) else {
            return false;
        };
        (0..bytes.len().saturating_sub(31)).step_by(16).any(|at| {
            bytes[at..].starts_with(b"\xff Go buildinf:")
                && matches!(bytes[at + 14], 4 | 8)
                && bytes[at + 15] & !3 == 0
        })
    })
}

pub fn find_targets_in_path(root: &Path) -> Vec<FoundTarget> {
    let mut targets = Vec::new();

    if std::fs::symlink_metadata(root).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return targets;
    }

    if root.is_file() {
        if !regular_file(root) {
            return targets;
        }
        let name = root
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let lower = name.to_ascii_lowercase();
        let cli_artifact = lower == "agy"
            || lower.starts_with("agy.")
            || lower.starts_with("agy-")
            || lower == "antigravity"
            || lower.starts_with("antigravity.");
        if [".bak", ".backup", ".old", ".orig"]
            .iter()
            .any(|suffix| lower.ends_with(suffix))
            || (cli_artifact && !is_agy_cli_name(&name))
        {
            return targets;
        }
        let kind = if name.ends_with(".asar") {
            TargetKind::IdeAsar
        } else if name.ends_with(".js") {
            TargetKind::IdeMainJs
        } else if is_agy_cli_name(&name) {
            if !native_cli(root, &name) {
                return targets;
            }
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
        "antigravity.exe",
        "antigravity",
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
            let is_cli = is_agy_cli_name(bn);
            if regular_file_under(root, &p) && (!is_cli || native_cli(&p, bn)) {
                let kind = if is_cli {
                    TargetKind::AgyCli
                } else {
                    TargetKind::LanguageServer
                };
                if !targets
                    .iter()
                    .any(|t: &FoundTarget| same_target_path(&t.path, &p))
                {
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
        if p.is_file()
            && !targets
                .iter()
                .any(|t: &FoundTarget| same_target_path(&t.path, &p))
        {
            targets.push(FoundTarget {
                path: p,
                kind: TargetKind::IdeMainJs,
                name: "main.js (IDE)".to_string(),
            });
        }
    }

    if let Some(asar) = find_asar_in_path(root) {
        if !targets
            .iter()
            .any(|t: &FoundTarget| same_target_path(&t.path, &asar))
        {
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
            let is_agy = native_cli(&entry.path(), &file_name);

            if is_ls || is_agy {
                let kind = if is_agy {
                    TargetKind::AgyCli
                } else {
                    TargetKind::LanguageServer
                };
                let path = entry.path();
                if !targets.iter().any(|t| same_target_path(&t.path, &path)) {
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
                    && !targets.iter().any(|t| same_target_path(&t.path, &path))
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

    fn pending_fixture(path: &Path, bytes: &[u8]) -> PathBuf {
        let name = path.file_name().unwrap().to_string_lossy();
        let transaction = path
            .parent()
            .unwrap()
            .join(format!(".{name}.ag-transaction-fixture"));
        std::fs::create_dir_all(&transaction).unwrap();
        std::fs::write(transaction.join("PENDING"), name.as_bytes()).unwrap();
        std::fs::write(transaction.join("captured"), bytes).unwrap();
        transaction
    }

    #[test]
    fn interrupted_cli_is_recovered_before_directory_and_explicit_file_discovery() {
        for explicit in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("antigravity");
            let original = cli_fixture(true, false);
            pending_fixture(&path, &original);
            assert!(find_targets_in_path(root.path()).is_empty());
            assert!(!path.exists()); // Read-only discovery must not repair files.
            recover_targets_in_path(if explicit { &path } else { root.path() }).unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), original);
            let targets = find_targets_in_path(root.path());
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].kind, TargetKind::AgyCli);
        }
    }

    #[test]
    fn path_recovery_restores_only_named_native_cli_and_preserves_new_versions() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("agy.exe");
        let original = cli_fixture(true, false);
        let transaction = pending_fixture(&path, &original);
        let js = root.path().join("main.js");
        pending_fixture(&js, b"// unrelated PATH entry");
        assert!(cli_files_in_dirs(&[root.path().into()]).is_empty());
        recover_cli_in_dirs(&[root.path().into()]).unwrap();
        assert_eq!(
            cli_files_in_dirs(&[root.path().into()]),
            vec![std::fs::canonicalize(&path).unwrap()]
        );
        assert!(!js.exists());
        std::fs::remove_file(transaction.join("COMMITTED")).unwrap();
        std::fs::write(&path, b"new version").unwrap();
        recover_cli_in_dirs(&[root.path().into()]).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new version");
        std::fs::remove_file(&path).unwrap();
        recover_cli_in_dirs(&[root.path().into()]).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn interrupted_ide_patch_is_discovered_and_exactly_rolled_back() {
        use crate::core::patcher::{patch_target, restore_target, PatchOutcome};
        let root = tempfile::tempdir().unwrap();
        let folder = root.path().join("out");
        std::fs::create_dir(&folder).unwrap();
        let path = folder.join("main.js");
        let original = b"x.resetIsTierGCPTos(),x.isGoogleInternal;";
        std::fs::write(&path, original).unwrap();
        let target = find_targets_in_path(root.path()).pop().unwrap();
        assert_eq!(patch_target(&target).unwrap(), PatchOutcome::Changed(1));
        let patched = std::fs::read(&path).unwrap();
        pending_fixture(&path, &patched);
        std::fs::remove_file(&path).unwrap();
        assert!(find_targets_in_path(root.path()).is_empty());
        recover_targets_in_path(root.path()).unwrap();
        let target = find_targets_in_path(root.path()).pop().unwrap();
        assert_eq!(restore_target(&target).unwrap(), PatchOutcome::Restored);
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

    #[test]
    fn recovery_rejects_traversal_and_wrong_transaction_markers() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("antigravity");
        let transaction = pending_fixture(&path, &cli_fixture(true, false));
        for marker in ["../antigravity", "unrelated.exe", "antigravity/extra"] {
            std::fs::write(transaction.join("PENDING"), marker).unwrap();
            recover_targets_in_path(root.path()).unwrap();
            assert!(!path.exists());
        }
    }

    #[test]
    fn uppercase_cli_is_found_once_and_gui_of_same_name_is_excluded() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("Antigravity.exe");
        std::fs::write(&path, cli_fixture(true, false)).unwrap();
        assert_eq!(find_targets_in_path(&path).len(), 1);
        let targets = find_targets_in_path(root.path());
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].kind, TargetKind::AgyCli);
        std::fs::write(&path, cli_fixture(false, false)).unwrap();
        assert!(find_targets_in_path(&path).is_empty());
        assert!(find_targets_in_path(root.path()).is_empty());
    }

    fn cli_fixture(go: bool, in_text: bool) -> Vec<u8> {
        let mut data = vec![0u8; 1024];
        data[..2].copy_from_slice(b"MZ");
        data[60..64].copy_from_slice(&128u32.to_le_bytes());
        data[128..132].copy_from_slice(b"PE\0\0");
        for (offset, value) in [(132, 0x8664u16), (134, 1), (148, 240), (152, 0x20b)] {
            data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        data[392..400].copy_from_slice(if in_text {
            b".text\0\0\0"
        } else {
            b".data\0\0\0"
        });
        for (offset, value) in [(400, 512u32), (404, 0x1000), (408, 512), (412, 512)] {
            data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        if go {
            data[512..526].copy_from_slice(b"\xff Go buildinf:");
            data[526] = 8;
            data[527] = 2;
        }
        data
    }
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
        std::fs::write(root.path().join("agy-x64.exe"), cli_fixture(true, false)).unwrap();
        let targets = find_targets_in_path(root.path());
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].kind, TargetKind::AgyCli);
        assert_eq!(targets[0].name, "agy-x64.exe");
    }

    #[test]
    fn official_cli_is_found_consistently_as_file_directory_and_path_entry() {
        let root = tempfile::tempdir().unwrap();
        for name in CLI_NAMES {
            let dir = root.path().join(name.replace('.', "_"));
            std::fs::create_dir(&dir).unwrap();
            let path = dir.join(name);
            std::fs::write(&path, cli_fixture(true, false)).unwrap();
            let targets = find_targets_in_path(&path);
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].kind, TargetKind::AgyCli);
            assert_eq!(targets[0].path, path);
            let directory_targets = find_targets_in_path(&dir);
            assert_eq!(directory_targets.len(), 1);
            assert_eq!(directory_targets[0].kind, targets[0].kind);
            assert_eq!(directory_targets[0].path, path);
            assert_eq!(
                cli_files_in_dirs(&[dir]),
                vec![std::fs::canonicalize(&path).unwrap()]
            );
        }
    }

    #[test]
    fn recursive_cli_discovery_excludes_gui_wrappers_backups_and_fake_markers() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("custom/deep/install");
        std::fs::create_dir_all(&nested).unwrap();
        let cli = nested.join("antigravity");
        std::fs::write(&cli, cli_fixture(true, false)).unwrap();
        for (name, contents) in [
            ("Antigravity.exe", cli_fixture(false, false)),
            ("agy-fake.exe", cli_fixture(true, true)),
            ("agy-helper.js", cli_fixture(true, false)),
            ("agy-x64.exe.bak", cli_fixture(true, false)),
            ("antigravity.exe.old", cli_fixture(true, false)),
            ("agy", b"#!/bin/sh\necho launcher".to_vec()),
            ("agy.cmd", b"@echo off".to_vec()),
            ("antigravity.ps1", b"Write-Output launcher".to_vec()),
        ] {
            let path = nested.join(name);
            std::fs::write(&path, contents).unwrap();
            assert!(find_targets_in_path(&path).is_empty(), "{name}");
        }
        let targets = find_targets_in_path(root.path());
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].path, cli);
        assert_eq!(targets[0].kind, TargetKind::AgyCli);
        assert_eq!(
            cli_files_in_dirs(&[nested]),
            vec![std::fs::canonicalize(cli).unwrap()]
        );
    }

    fn assert_official_fixture_discovery(variable: &str) {
        let path = PathBuf::from(std::env::var_os(variable).expect("official fixture path"));
        let directory = path.parent().unwrap();
        let explicit = find_targets_in_path(&path);
        assert_eq!(explicit.len(), 1);
        assert_eq!(explicit[0].kind, TargetKind::AgyCli);
        let discovered = find_targets_in_path(directory);
        assert!(discovered
            .iter()
            .any(|target| { target.path == path && target.kind == TargetKind::AgyCli }));
        assert!(cli_files_in_dirs(&[directory.to_path_buf()])
            .contains(&std::fs::canonicalize(&path).unwrap()));
    }

    #[test]
    #[ignore = "set AGY_ARM64_FIXTURE to a pinned official CLI binary"]
    fn official_arm64_cli_fixture_discovery_works_for_file_directory_and_path() {
        assert_official_fixture_discovery("AGY_ARM64_FIXTURE");
    }

    #[test]
    #[ignore = "set AGY_X64_FIXTURE to a pinned official CLI binary"]
    fn official_x64_cli_fixture_discovery_works_for_file_directory_and_path() {
        assert_official_fixture_discovery("AGY_X64_FIXTURE");
    }

    #[cfg(unix)]
    #[test]
    fn directory_links_are_skipped_and_path_links_resolve_to_the_cli() {
        let root = tempfile::tempdir().unwrap();
        let actual_dir = root.path().join("actual");
        let linked_dir = root.path().join("links");
        std::fs::create_dir(&actual_dir).unwrap();
        std::fs::create_dir(&linked_dir).unwrap();
        let cli = actual_dir.join("antigravity");
        std::fs::write(&cli, cli_fixture(true, false)).unwrap();
        let link = linked_dir.join("agy");
        std::os::unix::fs::symlink(&cli, &link).unwrap();
        std::os::unix::fs::symlink(&actual_dir, linked_dir.join("bin")).unwrap();
        std::os::unix::fs::symlink(&actual_dir, root.path().join("linked-install")).unwrap();
        assert!(find_targets_in_path(&link).is_empty());
        assert!(find_targets_in_path(&linked_dir).is_empty());
        assert!(find_targets_in_path(&root.path().join("linked-install")).is_empty());
        assert_eq!(
            cli_files_in_dirs(&[linked_dir]),
            vec![std::fs::canonicalize(&cli).unwrap()]
        );
        assert!(std::fs::symlink_metadata(link)
            .unwrap()
            .file_type()
            .is_symlink());
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
