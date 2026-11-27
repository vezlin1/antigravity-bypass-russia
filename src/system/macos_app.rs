use std::{
    ffi::{CString, OsStr},
    fs, io,
    os::unix::{ffi::OsStrExt, fs::MetadataExt, fs::OpenOptionsExt, io::AsRawFd},
    path::{Component, Path, PathBuf},
    process::Command,
    time::Duration,
};

pub(crate) fn bundle(path: &Path) -> Option<&Path> {
    path.ancestors()
        .filter(|part| {
            part.extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("app"))
        })
        .last()
}

pub(crate) fn resolved_file(path: &Path) -> io::Result<PathBuf> {
    Ok(fs::canonicalize(parent(path))?.join(path.file_name().ok_or(io::ErrorKind::InvalidInput)?))
}

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

/// Ask the kernel under the same TCC identity as the writer. No truncation,
/// file creation or attribute changes are needed to detect a denied write.
pub(crate) fn check_write_access(path: &Path) -> Result<(), String> {
    if bundle(path).is_none() {
        return Ok(());
    }
    fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map(|_| ())
        .map_err(|error| {
            if error.raw_os_error() == Some(libc::EPERM) {
                format!(
                    "Защита «Управление приложениями» запретила запись в {}: {error}",
                    path.display()
                )
            } else {
                format!("Проверка записи в {}: {error}", path.display())
            }
        })
}

pub(super) fn backup_directory(path: &Path) -> Result<Option<PathBuf>, String> {
    if bundle(path).is_none() {
        return Ok(None);
    }
    let path = resolved_file(path).map_err(|error| error.to_string())?;
    let key = super::journal::digest(path.as_os_str().as_bytes());
    Ok(Some(
        super::user_context::home()?
            .join("Library/Application Support/AntigravityBypass/patch-backups")
            .join(key),
    ))
}

pub(super) fn create_backup_parents(directory: &Path) -> Result<(), String> {
    let backups = parent(directory);
    let data = parent(backups);
    fs::create_dir_all(parent(data)).map_err(|error| error.to_string())?;
    super::fs_utils::create_private_directory(data)?;
    super::fs_utils::create_private_directory(backups)
}

/// Sibling of the *outer* bundle, so even a helper .app does not stage inside
/// the IDE. This location survives an interrupted write and is on its volume.
pub(crate) fn transactions(app: &Path) -> PathBuf {
    let key = super::journal::digest(app.file_name().unwrap_or_default().as_bytes());
    parent(app).join(format!(".antigravity-bypass-{key}"))
}

pub(crate) fn transaction_directory_exists(directory: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.is_dir() => Ok(true),
        Ok(_) => Err("Каталог подготовки не является обычным каталогом".into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("Каталог подготовки: {error}")),
    }
}

pub(super) fn create_transactions(app: &Path, path: &Path) -> Result<PathBuf, String> {
    let directory = transactions(app);
    let volume = |path: &Path| fs::metadata(path).map(|metadata| metadata.dev());
    let target_volume = volume(parent(path)).map_err(|error| error.to_string())?;
    if volume(parent(app)).map_err(|error| error.to_string())? != target_volume {
        return Err("Рядом с приложением нет каталога для атомарной замены на томе файла".into());
    }
    super::fs_utils::create_private_directory(&directory)?;
    if volume(&directory).map_err(|error| error.to_string())? != target_volume {
        return Err("Каталог подготовки находится на другом томе; файл сохранён".into());
    }
    Ok(directory)
}

pub(super) fn rename_exclusive(from: &Path, to: &Path) -> io::Result<()> {
    let from = CString::new(from.as_os_str().as_bytes())?;
    let to = CString::new(to.as_os_str().as_bytes())?;
    if unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), libc::RENAME_EXCL) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(super) fn archive_legacy(path: &Path, source: &Path) -> Result<(), String> {
    let app = bundle(path).ok_or("Не найден бандл для переноса служебных файлов")?;
    let directory = create_transactions(app, path)?;
    let archive = tempfile::Builder::new()
        .prefix("recovered-")
        .tempdir_in(directory)
        .map_err(|error| error.to_string())?;
    fs::rename(source, archive.path().join("original")).map_err(|error| error.to_string())?;
    let _ = archive.keep();
    Ok(())
}

/// Translate a recovery marker without following a symlink into another
/// installation. The caller still checks the target name and file format.
pub(crate) fn pending_target(app: &Path, marker: &[u8]) -> Option<PathBuf> {
    let relative = Path::new(OsStr::from_bytes(marker));
    if relative.as_os_str().is_empty()
        || !relative
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return None;
    }
    let target = fs::canonicalize(app).ok()?.join(relative);
    (resolved_file(&target).ok()? == target).then_some(target)
}

// Launch Services performs the same policy check as a Finder launch and
// supplies a PID even while Gatekeeper is assessing the process. Use a fresh
// Electron profile so the probe cannot take over the user's running instance.
const PROBE: &str = r#"
ObjC.import("AppKit");

function run(argv) {
    const workspace = $.NSWorkspace.sharedWorkspace;
    const url = $.NSURL.fileURLWithPath(argv[0]);
    const bundle = $.NSBundle.bundleWithURL(url);
    if (bundle.isNil() || bundle.bundleIdentifier.isNil()) {
        return JSON.stringify({error: "macOS не определила идентификатор приложения"});
    }
    if ($.NSRunningApplication.runningApplicationsWithBundleIdentifier(bundle.bundleIdentifier).count > 0) {
        return JSON.stringify({error: "Уже запущен экземпляр этого приложения"});
    }
    const options = $.NSWorkspaceLaunchNewInstance | $.NSWorkspaceLaunchWithoutActivation;
    const config = $({NSWorkspaceLaunchConfigurationArguments: [
        "--user-data-dir=" + argv[1], "--disable-updates"
    ]});
    const error = Ref();
    const app = workspace.launchApplicationAtURLOptionsConfigurationError(url, options, config, error);
    if (app.isNil()) {
        return JSON.stringify({failed: true, error: ObjC.unwrap(error[0].localizedDescription)});
    }
    const pid = Number(app.processIdentifier);
    const deadline = Date.now() + 10000;
    function tick() {
        $.NSRunLoop.currentRunLoop.runUntilDate($.NSDate.dateWithTimeIntervalSinceNow(0.1));
    }
    while (!app.isTerminated && !app.isFinishedLaunching && Date.now() < deadline) {
        tick();
    }
    const terminated = app.isTerminated;
    const finished = !terminated && app.isFinishedLaunching;
    if (!app.isTerminated) {
        app.terminate();
        const stop = Date.now() + 1500;
        while (!app.isTerminated && Date.now() < stop) {
            tick();
        }
        if (!app.isTerminated) {
            app.forceTerminate();
        }
    }
    return JSON.stringify({pid: pid, finished: finished, terminated: terminated});
}
"#;

#[derive(serde::Deserialize)]
struct ProbeResult {
    pid: Option<u32>,
    #[serde(default)]
    finished: bool,
    #[serde(default)]
    terminated: bool,
    #[serde(default)]
    failed: bool,
    error: Option<String>,
}

pub(crate) enum LaunchCheck {
    Started,
    Rejected(u32),
    Failed(String),
    Unconfirmed(String),
}

pub(crate) fn check_launch(app: &Path) -> LaunchCheck {
    match probe_launch(app) {
        Ok(result) => result,
        Err(error) => LaunchCheck::Unconfirmed(error),
    }
}

fn probe_launch(app: &Path) -> Result<LaunchCheck, String> {
    let owner = fs::metadata(super::user_context::home()?).map_err(|e| e.to_string())?;
    let console = fs::metadata("/dev/console")
        .map_err(|e| e.to_string())?
        .uid();
    if owner.uid() == 0 || owner.uid() != console {
        return Err("Для проверки запуска нужна открытая графическая сессия пользователя".into());
    }
    let profile = tempfile::Builder::new()
        .prefix("antigravity-launch-")
        .tempdir_in("/private/tmp")
        .map_err(|e| e.to_string())?;
    let mut command = if unsafe { libc::geteuid() } == 0 {
        let file = fs::File::open(profile.path()).map_err(|e| e.to_string())?;
        if unsafe { libc::fchown(file.as_raw_fd(), owner.uid(), owner.gid()) } != 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        let mut command = Command::new("/bin/launchctl");
        command.args([
            "asuser",
            &console.to_string(),
            "/usr/bin/sudo",
            "-n",
            "-H",
            "-u",
            &format!("#{console}"),
            "--",
            "/usr/bin/osascript",
        ]);
        command
    } else {
        Command::new("/usr/bin/osascript")
    };
    command
        .args(["-l", "JavaScript", "-e", PROBE])
        .arg(app)
        .arg(profile.path());
    let output = super::command::capture(&mut command, Duration::from_secs(22))
        .map_err(|e| format!("Launch Services: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "Launch Services: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let result: ProbeResult = serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())?;
    if result.finished {
        return Ok(LaunchCheck::Started);
    }
    if let Some(pid) = result.pid {
        match gatekeeper_rejected(pid) {
            Ok(true) => return Ok(LaunchCheck::Rejected(pid)),
            Ok(false) => (),
            Err(error) => crate::net::relay::log_event(&error),
        }
        // A Gatekeeper dialog can remain pending beyond the probe deadline.
        // Restore the file if the trial process did not finish launching.
        let reason = if result.terminated {
            "Пробный процесс завершился до подтверждения запуска"
        } else {
            "macOS не подтвердила запуск за 10 с"
        };
        return Ok(LaunchCheck::Failed(reason.into()));
    }
    let reason = result
        .error
        .unwrap_or_else(|| "Launch Services не вернула процесс".into());
    if result.failed {
        return Ok(LaunchCheck::Failed(reason));
    }
    Err(reason)
}

fn gatekeeper_rejected(pid: u32) -> Result<bool, String> {
    // The message contains the victim PID even when macOS redacts the path.
    let message = format!("Terminating process due to Gatekeeper rejection: {pid},");
    let predicate = format!(r#"process == "syspolicyd" AND eventMessage BEGINSWITH "{message}""#);
    let mut command = Command::new("/usr/bin/log");
    command.args([
        "show",
        "--last",
        "30s",
        "--style",
        "ndjson",
        "--predicate",
        &predicate,
    ]);
    let log = super::command::capture(&mut command, Duration::from_secs(5))
        .map_err(|e| format!("Журнал Gatekeeper: {e}"))?;
    if !log.status.success() {
        return Err(format!(
            "Журнал Gatekeeper: {}",
            String::from_utf8_lossy(&log.stderr).trim()
        ));
    }
    Ok(has_rejection(&log.stdout, &message))
}

fn has_rejection(log: &[u8], message: &str) -> bool {
    #[derive(serde::Deserialize)]
    struct Event {
        #[serde(rename = "eventMessage")]
        message: String,
    }
    log.split(|byte| *byte == b'\n')
        .filter_map(|line| serde_json::from_slice::<Event>(line).ok())
        .any(|event| event.message.starts_with(message))
}

#[cfg(test)]
mod tests {
    use super::has_rejection;

    #[test]
    fn only_a_gatekeeper_event_for_the_launched_pid_is_a_rejection() {
        let message = "Terminating process due to Gatekeeper rejection: 403,";
        assert!(has_rejection(
            br#"{"eventMessage":"Terminating process due to Gatekeeper rejection: 403, <private>"}"#,
            message
        ));
        assert!(!has_rejection(
            br#"{"eventMessage":"Terminating process due to Gatekeeper rejection: 4030, <private>"}"#,
            message
        ));
        assert!(!has_rejection(
            br#"{"filter":"Terminating process due to Gatekeeper rejection: 403,"}"#,
            message
        ));
    }
}
