//! Restart Manager is used only to inspect locks. Shutdown uses individual PIDs
//! so Windows cannot broadcast a close event to a console shared with the patcher.
use std::path::PathBuf;

pub fn holders(paths: &[PathBuf]) -> Result<Vec<String>, String> {
    query(paths)
}

pub fn close_application(paths: &[PathBuf]) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    return crate::system::macos_shutdown::close_application(paths);
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        // Do not kill unrelated installations or a terminal sharing a process
        // name. The caller can ask the user to close the reported holders.
        return wait_for_holders_to_exit(|| holders(paths), std::time::Duration::from_secs(5));
    }
    #[cfg(not(any(windows, unix)))]
    return wait_for_holders_to_exit(|| holders(paths), std::time::Duration::from_secs(5));
    #[cfg(windows)]
    {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            // IDE shutdown can make another PID from the snapshot exit while
            // we are trying to stop it. Decide using fresh process/lock state.
            let stop_error = stop_owned_processes(paths).err();
            if running_applications(paths)?.is_empty() && holders(paths)?.is_empty() {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(stop_error.unwrap_or_else(|| {
                    "Приложение не завершило работу. Закройте его вручную и повторите.".into()
                }));
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }
}

#[cfg(target_os = "macos")]
pub(super) fn wait_for_other_holders(paths: &[PathBuf]) -> Result<(), String> {
    // A concurrent fork can briefly inherit our open file before exec closes
    // close-on-exec descriptors. Confirm the lock instead of treating that
    // snapshot as a running updater. Persistent holders still prevent writes.
    wait_for_other_holders_with(
        || holders(paths),
        std::process::id(),
        std::time::Duration::from_secs(1),
    )
}

#[cfg(any(target_os = "macos", test))]
fn wait_for_other_holders_with(
    mut query: impl FnMut() -> Result<Vec<String>, String>,
    our_pid: u32,
    budget: std::time::Duration,
) -> Result<(), String> {
    let own_pid = format!("(PID {our_pid})");
    wait_for_holders_to_exit(
        || {
            Ok(query()?
                .into_iter()
                .filter(|holder| !holder.ends_with(&own_pid))
                .collect())
        },
        budget,
    )
}

#[cfg(any(not(windows), test))]
fn wait_for_holders_to_exit(
    mut query: impl FnMut() -> Result<Vec<String>, String>,
    budget: std::time::Duration,
) -> Result<(), String> {
    let started = std::time::Instant::now();
    loop {
        let remaining = query()?;
        if remaining.is_empty() {
            return Ok(());
        }
        if started.elapsed() >= budget {
            return Err(format!(
                "Файлы Antigravity всё ещё используются: {}. Завершите эти процессы и повторите операцию.",
                remaining.join(", ")
            ));
        }
        // Closing the IDE window does not instantly release its helpers/files.
        std::thread::sleep(
            std::time::Duration::from_millis(200).min(budget.saturating_sub(started.elapsed())),
        );
    }
}

pub fn running_applications(paths: &[PathBuf]) -> Result<Vec<String>, String> {
    #[cfg(windows)]
    {
        Ok(crate::system::process::snapshot()?
            .iter()
            .filter(|p| owned_application(&p.executable, paths))
            .map(|p| {
                format!(
                    "{} (PID {})",
                    p.executable
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy(),
                    p.pid
                )
            })
            .collect())
    }
    #[cfg(target_os = "macos")]
    return crate::system::macos_shutdown::running_applications(paths);
    #[cfg(not(any(windows, target_os = "macos")))]
    holders(paths)
}

#[cfg(windows)]
fn stop_owned_processes(paths: &[PathBuf]) -> Result<(), String> {
    let processes = crate::system::process::snapshot()?;
    let protected = crate::system::process::ancestor_pids(&processes, std::process::id());
    let targets: Vec<_> = processes
        .iter()
        .filter(|p| owned_application(&p.executable, paths))
        .collect();
    if targets.iter().any(|p| protected.contains(&p.pid)) {
        return Err("Патчер запущен из Antigravity. Откройте патчер в отдельном терминале Windows, чтобы закрыть IDE без потери этого окна.".into());
    }
    let mut errors = Vec::new();
    for process in targets {
        if let Err(error) = crate::system::process::terminate_verified(process) {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

#[cfg(windows)]
fn owned_application(executable: &std::path::Path, paths: &[PathBuf]) -> bool {
    let name = executable
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_ascii_lowercase();
    let normalize = |path: &std::path::Path| {
        // canonicalize() returns verbatim paths, while process image queries
        // normally return DOS/UNC paths. Compare both spellings consistently.
        crate::system::env::display_path(path)
            .replace('/', "\\")
            .to_ascii_lowercase()
    };
    if (name.starts_with("language_server") || name == "agy.exe" || name.starts_with("agy-"))
        && name.ends_with(".exe")
    {
        return paths.iter().any(|p| normalize(p) == normalize(executable));
    }
    if matches!(
        name.as_str(),
        "crashpad_handler.exe" | "node.exe" | "rg.exe"
    ) {
        // Bundled helpers belong to the installation only; never target a
        // system-wide Node.js/ripgrep process by its image name.
        return paths.iter().any(|p| {
            let target = normalize(p);
            target
                .find("\\resources\\")
                .is_some_and(|index| normalize(executable).starts_with(&target[..index + 1]))
        });
    }
    if name != "antigravity.exe" {
        return false;
    }
    let Some(parent) = executable.parent() else {
        return false;
    };
    let prefix = format!("{}\\", normalize(parent));
    paths.iter().any(|p| normalize(p).starts_with(&prefix))
}

fn query(paths: &[PathBuf]) -> Result<Vec<String>, String> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::{Foundation::ERROR_MORE_DATA, System::RestartManager::*};
        if paths.is_empty() {
            return Ok(vec![]);
        }
        let mut handle = 0;
        let mut key = [0u16; 33];
        let code = unsafe { RmStartSession(&mut handle, 0, key.as_mut_ptr()) };
        if code != 0 {
            return Err(format!("Restart Manager: {code}"));
        }
        struct Session(u32);
        impl Drop for Session {
            fn drop(&mut self) {
                unsafe {
                    RmEndSession(self.0);
                }
            }
        }
        let _session = Session(handle);
        let names: Vec<Vec<u16>> = paths
            .iter()
            .map(|p| p.as_os_str().encode_wide().chain(Some(0)).collect())
            .collect();
        let pointers: Vec<_> = names.iter().map(|n| n.as_ptr()).collect();
        let code = unsafe {
            RmRegisterResources(
                handle,
                pointers.len() as u32,
                pointers.as_ptr(),
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
            )
        };
        if code != 0 {
            return Err(format!("Регистрация файлов в Restart Manager: {code}"));
        }
        let mut needed = 0;
        let mut count = 0;
        let mut reasons = 0;
        let mut entries = Vec::<RM_PROCESS_INFO>::new();
        for _ in 0..3 {
            let code = unsafe {
                RmGetList(
                    handle,
                    &mut needed,
                    &mut count,
                    if entries.is_empty() {
                        std::ptr::null_mut()
                    } else {
                        entries.as_mut_ptr()
                    },
                    &mut reasons,
                )
            };
            if code == 0 {
                let mut result: Vec<_> = entries
                    .iter()
                    .take(count as usize)
                    .map(|p| {
                        let length = p
                            .strAppName
                            .iter()
                            .position(|c| *c == 0)
                            .unwrap_or(p.strAppName.len());
                        format!(
                            "{} (PID {})",
                            String::from_utf16_lossy(&p.strAppName[..length]),
                            p.Process.dwProcessId
                        )
                    })
                    .collect();
                result.sort();
                result.dedup();
                return Ok(result);
            }
            if code != ERROR_MORE_DATA || needed > 4096 {
                return Err(format!("Проверка занятых файлов: {code}"));
            }
            entries.resize(needed as usize, RM_PROCESS_INFO::default());
            count = needed;
        }
        Err("Список процессов меняется; повторите проверку".into())
    }
    #[cfg(unix)]
    {
        if paths.is_empty() {
            return Ok(vec![]);
        }
        let output = crate::system::command::output(
            "lsof",
            ["-n", "-P", "-Fpc", "--"]
                .into_iter()
                .map(std::ffi::OsStr::new)
                .chain(paths.iter().map(|p| p.as_os_str())),
        )
        .map_err(|e| format!("Проверка открытых файлов (нужен lsof): {e}"))?;
        parse_lsof(
            output.status.code(),
            &String::from_utf8_lossy(&output.stdout),
            &String::from_utf8_lossy(&output.stderr),
            paths,
        )
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = paths;
        Ok(vec![])
    }
}

#[cfg(any(unix, test))]
fn parse_lsof(
    code: Option<i32>,
    stdout: &str,
    stderr: &str,
    paths: &[PathBuf],
) -> Result<Vec<String>, String> {
    #[cfg(target_os = "linux")]
    let safe_stderr = linux_lsof_stderr_is_safe(stderr, paths);
    #[cfg(not(target_os = "linux"))]
    let safe_stderr = {
        let _ = paths;
        stderr.trim().is_empty()
    };
    if !matches!(code, Some(0 | 1)) || !safe_stderr {
        return Err(format!(
            "Проверка открытых файлов: код {code:?}; {}",
            stderr.trim()
        ));
    }
    let mut result = Vec::new();
    let mut pid = None;
    for line in stdout.lines() {
        if let Some(value) = line.strip_prefix('p') {
            pid = Some(
                value
                    .parse::<u32>()
                    .map_err(|_| "Некорректный PID в выводе lsof")?,
            );
        } else if let Some(name) = line.strip_prefix('c') {
            if let Some(pid) = pid.take() {
                result.push(format!("{name} (PID {pid})"));
            }
        }
    }
    if !stdout.trim().is_empty() && result.is_empty() {
        return Err("Не удалось разобрать список открытых файлов".into());
    }
    result.sort();
    result.dedup();
    Ok(result)
}

#[cfg(any(target_os = "linux", test))]
fn linux_lsof_stderr_is_safe(stderr: &str, paths: &[PathBuf]) -> bool {
    let mut incomplete_expected = false;
    for line in stderr
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if line == "Output information may be incomplete." && incomplete_expected {
            incomplete_expected = false;
            continue;
        }
        let Some((filesystem, mount)) = line
            .strip_prefix("lsof: WARNING: can't stat() ")
            .and_then(|text| text.split_once(" file system "))
        else {
            return false;
        };
        let directory = match filesystem {
            "fuse.portal" => "doc",
            "fuse.gvfsd-fuse" => "gvfs",
            _ => return false,
        };
        let Some(uid) = mount
            .strip_prefix("/run/user/")
            .and_then(|path| path.strip_suffix(&format!("/{directory}")))
        else {
            return false;
        };
        if uid.is_empty() || !uid.bytes().all(|b| b.is_ascii_digit()) || uid.parse::<u32>().is_err()
        {
            return false;
        }
        // These desktop mounts are unrelated only when every target can be
        // resolved outside them. Preserve errors for targets reached via links.
        let mount = std::path::Path::new(mount);
        if paths.is_empty()
            || paths.iter().any(|path| {
                path.starts_with(mount)
                    || path
                        .canonicalize()
                        .map_or(true, |resolved| resolved.starts_with(mount))
            })
        {
            return false;
        }
        incomplete_expected = true;
    }
    true
}

#[cfg(test)]
mod mac_lock_tests {
    use super::wait_for_holders_to_exit;
    use std::path::PathBuf;
    use std::time::Duration;

    #[test]
    fn transient_inherited_handle_is_rechecked_and_our_own_handle_is_allowed() {
        let ours = "patcher (PID 123)".to_string();
        let mut snapshots =
            [vec![ours.clone(), "patcher (PID 456)".into()], vec![ours]].into_iter();
        super::wait_for_other_holders_with(
            || Ok(snapshots.next().unwrap()),
            123,
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(snapshots.next().is_none());
    }

    #[test]
    fn persistent_holder_is_blocked_even_if_its_name_matches_the_patcher() {
        let error = super::wait_for_other_holders_with(
            || Ok(vec!["patcher (PID 123)".into(), "patcher (PID 456)".into()]),
            123,
            Duration::ZERO,
        )
        .unwrap_err();
        assert!(error.contains("PID 456"));
        assert!(!error.contains("PID 123"));
    }

    #[test]
    fn failed_holder_recheck_does_not_allow_publication() {
        let mut snapshots = [
            Ok(vec!["updater (PID 456)".into()]),
            Err("lsof failed".into()),
        ]
        .into_iter();
        let error = super::wait_for_other_holders_with(
            || snapshots.next().unwrap(),
            123,
            Duration::from_secs(5),
        )
        .unwrap_err();
        assert_eq!(error, "lsof failed");
    }

    #[test]
    fn recheck_waits_for_a_closing_helper_to_release_its_files() {
        let mut snapshots = [vec!["Antigravity Helper (PID 123)".into()], vec![]].into_iter();
        wait_for_holders_to_exit(|| Ok(snapshots.next().unwrap()), Duration::from_secs(5)).unwrap();
        assert!(snapshots.next().is_none());
    }

    #[test]
    fn busy_files_report_the_actual_holders_and_do_not_assume_rollback() {
        let error = wait_for_holders_to_exit(
            || {
                Ok(vec![
                    "Antigravity Helper (PID 123)".into(),
                    "agy (PID 456)".into(),
                ])
            },
            Duration::ZERO,
        )
        .unwrap_err();
        assert!(error.contains("Antigravity Helper (PID 123)"), "{error}");
        assert!(error.contains("agy (PID 456)"), "{error}");
        assert!(error.contains("повторите операцию"), "{error}");
    }

    #[test]
    fn timeout_reports_the_latest_holder_instead_of_a_process_that_already_exited() {
        let mut snapshots = [
            vec!["helper (PID 123)".into()],
            vec!["agy (PID 456)".into()],
        ]
        .into_iter();
        let error =
            wait_for_holders_to_exit(|| Ok(snapshots.next().unwrap()), Duration::from_millis(10))
                .unwrap_err();
        assert!(error.contains("agy (PID 456)"), "{error}");
        assert!(!error.contains("PID 123"), "{error}");
    }

    #[test]
    fn recheck_propagates_inspection_errors_instead_of_assuming_files_are_free() {
        let error = wait_for_holders_to_exit(
            || Err("lsof: permission denied".into()),
            Duration::from_secs(5),
        )
        .unwrap_err();
        assert_eq!(error, "lsof: permission denied");
    }

    #[test]
    fn already_closed_application_does_not_need_a_wait() {
        wait_for_holders_to_exit(|| Ok(vec![]), Duration::ZERO).unwrap();
    }

    #[test]
    fn lsof_partial_match_is_busy_and_empty_exit_one_is_free() {
        assert_eq!(
            super::parse_lsof(Some(1), "p123\ncAntigravity Helper\np456\ncagy\n", "", &[])
                .unwrap()
                .len(),
            2
        );
        assert!(super::parse_lsof(Some(1), "", "", &[]).unwrap().is_empty());
        assert!(super::parse_lsof(Some(1), "", "permission denied", &[]).is_err());
        assert!(super::parse_lsof(Some(0), "unexpected output", "", &[]).is_err());
    }

    #[test]
    fn only_unrelated_desktop_fuse_warnings_are_safe() {
        let target = tempfile::NamedTempFile::new().unwrap();
        let paths = [target.path().to_path_buf()];
        let warnings = "lsof: WARNING: can't stat() fuse.portal file system /run/user/1000/doc\n\
                        Output information may be incomplete.\n\
                        lsof: WARNING: can't stat() fuse.gvfsd-fuse file system /run/user/1000/gvfs\n\
                        Output information may be incomplete.";
        assert!(super::linux_lsof_stderr_is_safe(warnings, &paths));
        for stderr in [
            "lsof: WARNING: can't stat() ext4 file system /opt",
            "lsof: WARNING: can't stat() fuse.sshfs file system /run/user/1000/gvfs",
            "lsof: WARNING: can't stat() fuse.portal file system /opt/doc",
            "lsof: WARNING: can't stat() fuse.portal file system /run/user/invalid/doc",
            "lsof: WARNING: can't stat() fuse.portal file system /run/user/1000/doc/subdir",
            "lsof: WARNING: permission denied",
            "Output information may be incomplete.",
        ] {
            assert!(
                !super::linux_lsof_stderr_is_safe(stderr, &paths),
                "{stderr}"
            );
        }
        assert!(!super::linux_lsof_stderr_is_safe(
            &format!("{warnings}\nlsof: fatal: permission denied"),
            &paths
        ));
        assert!(!super::linux_lsof_stderr_is_safe(warnings, &[]));
        assert!(!super::linux_lsof_stderr_is_safe(
            warnings,
            &[PathBuf::from("/run/user/1000/doc/agy")]
        ));
        assert!(!super::linux_lsof_stderr_is_safe(
            warnings,
            &[target.path().join("missing")]
        ));
        #[cfg(target_os = "linux")]
        {
            assert!(super::parse_lsof(Some(1), "", warnings, &paths)
                .unwrap()
                .is_empty());
            assert_eq!(
                super::parse_lsof(Some(0), "p123\ncagy\n", warnings, &paths).unwrap(),
                ["agy (PID 123)"]
            );
            assert!(super::parse_lsof(Some(2), "", warnings, &paths).is_err());
            assert!(super::parse_lsof(None, "", warnings, &paths).is_err());
            assert!(super::parse_lsof(Some(0), "unparseable", warnings, &paths).is_err());
            let link = target.path().with_extension("link");
            std::os::unix::fs::symlink("/run/user/1000/doc/agy", &link).unwrap();
            assert!(!super::linux_lsof_stderr_is_safe(warnings, &[link.clone()]));
            std::fs::remove_file(link).unwrap();
        }
        #[cfg(not(target_os = "linux"))]
        assert!(super::parse_lsof(Some(1), "", warnings, &paths).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "launched only by the isolated macOS file-holder regression test"]
    fn hold_file_fixture() {
        let file = std::fs::File::open(std::env::var_os("ABR_TEST_LOCK_FILE").unwrap()).unwrap();
        std::fs::write(std::env::var_os("ABR_TEST_LOCK_READY").unwrap(), b"ready").unwrap();
        std::thread::sleep(Duration::from_secs(30));
        drop(file);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_checks_open_files_instead_of_antigravity_in_a_process_name() {
        use std::{fs, os::unix::process::CommandExt, process::Command, time::Instant};

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("Antigravity-target.js");
        let unrelated = directory.path().join("unrelated.js");
        let ready = directory.path().join("ready");
        fs::write(&target, b"target").unwrap();
        fs::write(&unrelated, b"unrelated").unwrap();

        struct Fixture(std::process::Child);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Fixture(
            Command::new(std::env::current_exe().unwrap())
                .arg0(format!("Antigravity-script {}", unrelated.display()))
                .args([
                    "--exact",
                    "system::file_lock::mac_lock_tests::hold_file_fixture",
                    "--ignored",
                ])
                .env("ABR_TEST_LOCK_FILE", &target)
                .env("ABR_TEST_LOCK_READY", &ready)
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(ready.exists(), "file-holder fixture did not become ready");
        let holders = super::holders(&[target.clone()]).unwrap();
        assert!(
            holders
                .iter()
                .any(|holder| holder.contains(&format!("PID {}", child.0.id()))),
            "{holders:?}"
        );
        // The patcher and fixture names/arguments contain Antigravity; only the
        // actual open file must matter, even when another filename is in argv.
        assert!(super::holders(&[unrelated.clone()]).unwrap().is_empty());
        super::close_application(&[unrelated]).unwrap();
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        super::close_application(&[target]).unwrap();
    }
}

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn shutdown_matches_verbatim_windows_and_unc_target_paths() {
        use std::path::Path;
        for (target, executable) in [
            (r"\\?\C:\Tools\agy.exe", r"C:\Tools\agy.exe"),
            (
                r"\\?\C:\Apps\Antigravity\resources\bin\language_server.exe",
                r"C:\Apps\Antigravity\Antigravity.exe",
            ),
            (
                r"\\?\C:\Apps\Antigravity\resources\bin\language_server.exe",
                r"C:\Apps\Antigravity\resources\node.exe",
            ),
            (r"\\?\UNC\server\apps\agy.exe", r"\\server\apps\agy.exe"),
        ] {
            assert!(
                super::owned_application(Path::new(executable), &[target.into()]),
                "{target} -> {executable}"
            );
        }
        assert!(!super::owned_application(
            Path::new(r"C:\Other\agy.exe"),
            &[r"\\?\C:\Tools\agy.exe".into()]
        ));
    }

    #[test]
    fn cli_and_helpers_are_scoped_to_the_selected_installation() {
        use std::path::Path;
        let paths = vec![
            "C:/Apps/Antigravity/resources/bin/language_server.exe".into(),
            "C:/Tools/agy.exe".into(),
        ];
        for path in [
            "C:/Tools/agy.exe",
            "C:/Apps/Antigravity/resources/node.exe",
            "C:/Apps/Antigravity/crashpad_handler.exe",
        ] {
            assert!(super::owned_application(Path::new(path), &paths), "{path}");
        }
        for path in [
            "C:/Other/agy.exe",
            "C:/Program Files/nodejs/node.exe",
            "C:/Apps/Antigravity-other/node.exe",
            "C:/Apps/Antigravity/antigravity-bypass-russia.exe",
            "C:/Windows/System32/cmd.exe",
        ] {
            assert!(!super::owned_application(Path::new(path), &paths), "{path}");
        }
    }

    #[test]
    #[ignore = "requires Windows .NET Framework compiler; launches isolated hidden fixtures"]
    fn closes_ide_cli_and_server_without_stopping_unrelated_process() {
        use std::{
            fs,
            os::windows::process::CommandExt,
            process::Command,
            time::{Duration, Instant},
        };
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("Fixture.cs");
        let exe = dir.path().join("Antigravity.exe");
        fs::write(&source, r#"using System; using System.IO;
class P { static void Main(string[] args) { File.WriteAllText(args[0], "ready"); System.Threading.Thread.Sleep(-1); } }"#).unwrap();
        let compiler = std::path::PathBuf::from(std::env::var_os("WINDIR").unwrap())
            .join("Microsoft.NET/Framework64/v4.0.30319/csc.exe");
        let output = Command::new(compiler)
            .creation_flags(0x08000000)
            .args(["/nologo", "/target:exe"])
            .arg(format!("/out:{}", exe.display()))
            .arg(&source)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        struct Fixture(std::process::Child);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let unrelated_dir = tempfile::tempdir().unwrap();
        let executables = [
            exe.clone(),
            dir.path().join("agy.exe"),
            dir.path().join("language_server.exe"),
            unrelated_dir.path().join("Antigravity.exe"),
        ];
        let mut children = Vec::new();
        let mut ready_files = Vec::new();
        for (index, path) in executables.iter().enumerate() {
            if path != &exe {
                fs::copy(&exe, path).unwrap();
            }
            let ready = dir.path().join(format!("ready-{index}"));
            children.push(Fixture(
                Command::new(path)
                    .arg(&ready)
                    .creation_flags(0x08000000)
                    .spawn()
                    .unwrap(),
            ));
            ready_files.push(ready);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready_files.iter().all(|p| p.exists()) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(ready_files.iter().all(|p| p.exists()));
        assert!(!super::holders(&[exe.clone()]).unwrap().is_empty());
        let targets: Vec<_> = executables[..3]
            .iter()
            .map(|path| fs::canonicalize(path).unwrap())
            .collect();
        assert_eq!(super::running_applications(&targets).unwrap().len(), 3);
        super::close_application(&targets).unwrap();
        for child in &mut children[..3] {
            assert!(child.0.try_wait().unwrap().is_some());
        }
        assert!(children[3].0.try_wait().unwrap().is_none());
    }
    #[test]
    fn automatic_close_refuses_unrelated_process_without_stopping_it() {
        assert!(super::close_application(&[std::env::current_exe().unwrap()]).is_err());
        assert!(super::holders(&[std::env::current_exe().unwrap()])
            .unwrap()
            .iter()
            .any(|s| s.contains(&format!("PID {}", std::process::id()))));
    }
    #[test]
    fn shutdown_scope_excludes_other_editors_and_similar_directories() {
        use std::path::Path;
        let paths = vec!["C:/Apps/Antigravity/resources/bin/language_server.exe".into()];
        assert!(super::owned_application(
            Path::new("C:/Apps/Antigravity/Antigravity.exe"),
            &paths
        ));
        assert!(super::owned_application(
            Path::new("C:/Apps/Antigravity/resources/bin/language_server.exe"),
            &paths
        ));
        assert!(!super::owned_application(
            Path::new("C:/Apps/Antigravity/Code.exe"),
            &paths
        ));
        assert!(!super::owned_application(
            Path::new("C:/Apps/Anti/Antigravity.exe"),
            &paths
        ));
        assert!(!super::owned_application(
            Path::new("C:/Other/language_server.exe"),
            &paths
        ));
    }
    #[test]
    fn identifies_running_executable_without_terminating_it() {
        let list = super::holders(&[std::env::current_exe().unwrap()]).unwrap();
        assert!(list
            .iter()
            .any(|s| s.contains(&format!("PID {}", std::process::id()))));
    }
}
