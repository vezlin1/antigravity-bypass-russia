//! Shut down only executables belonging to the selected Antigravity installation.
//! Command-line substrings and process groups are never used as shutdown targets.
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(target_os = "macos")]
pub use native::{close_application, running_applications};
#[cfg(target_os = "macos")]
pub(crate) use native::launching_app_name;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Process {
    pid: u32,
    parent: u32,
    started: (u64, u64),
    executable: PathBuf,
}

type Identity = (u32, (u64, u64), PathBuf);

impl Process {
    fn identity(&self) -> Identity {
        (self.pid, self.started, self.executable.clone())
    }

    fn same_instance(&self, other: &Self) -> bool {
        self.identity() == other.identity()
    }

    fn label(&self) -> String {
        format!("{} (PID {})", self.executable.display(), self.pid)
    }
}

struct Scope {
    files: Vec<PathBuf>,
    bundles: Vec<PathBuf>,
    patcher: PathBuf,
}

impl Scope {
    // Inputs are canonicalized by the native entry points, including symlinks
    // used by Homebrew/PATH launchers and the patcher's own executable.
    fn new(files: Vec<PathBuf>, patcher: PathBuf) -> Self {
        let mut bundles = Vec::new();
        for file in &files {
            // A target grants ownership of its nearest containing bundle only.
            // An unrelated container .app must never become a shutdown target.
            if let Some(bundle) = file.ancestors().find(|path| {
                path.extension().is_some_and(|ext| ext == "app")
                    && file.starts_with(path.join("Contents"))
            }) {
                let contents = bundle.join("Contents");
                if !bundles.contains(&contents) {
                    bundles.push(contents);
                }
            }
        }
        Self {
            files,
            bundles,
            patcher,
        }
    }

    fn owns(&self, executable: &Path) -> bool {
        !executable.as_os_str().is_empty()
            && executable != self.patcher
            && (self.files.iter().any(|path| path == executable)
                || self
                    .bundles
                    .iter()
                    .any(|contents| executable.starts_with(contents)))
    }
}

fn protected_ancestors(
    processes: &[Process],
    current: u32,
    mut query_parent: impl FnMut(u32) -> Result<u32, String>,
) -> Result<HashSet<u32>, String> {
    let mut protected = HashSet::new();
    let mut pid = current;
    while pid > 1 {
        if !protected.insert(pid) {
            return Err("Не удалось проверить цепочку запуска утилиты: цикл PID".into());
        }
        pid = match processes.iter().find(|process| process.pid == pid) {
            Some(process) => process.parent,
            // Full inspection can omit a root-owned login/sudo parent. Its
            // basic PID/PPID relationship does not require full process access.
            None => query_parent(pid)?,
        };
    }
    protected.insert(1);
    Ok(protected)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Signal {
    Terminate,
    Kill,
}

#[derive(Default)]
struct Shutdown {
    requested: HashMap<Identity, Duration>,
    forced: HashSet<Identity>,
}

impl Shutdown {
    fn actions(
        &mut self,
        targets: &[Process],
        protected: &HashSet<u32>,
        now: Duration,
        grace: Duration,
    ) -> Result<Vec<(Process, Signal)>, String> {
        // Check the complete batch before sending any signals. Closing an IDE
        // ancestor would also destroy the terminal running this utility.
        if targets
            .iter()
            .any(|process| process.pid <= 1 || protected.contains(&process.pid))
        {
            return Err("Утилита запущена из Antigravity. Сохраните работу и запустите утилиту в отдельном приложении Terminal, чтобы закрытие IDE не завершило саму утилиту.".into());
        }
        let mut actions = Vec::new();
        for process in targets {
            let identity = process.identity();
            match self.requested.get(&identity) {
                None => {
                    self.requested.insert(identity, now);
                    actions.push((process.clone(), Signal::Terminate));
                }
                Some(requested) if now.saturating_sub(*requested) >= grace => {
                    if self.forced.insert(identity) {
                        actions.push((process.clone(), Signal::Kill));
                    }
                }
                _ => {}
            }
        }
        Ok(actions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(pid: u32, parent: u32, path: &str) -> Process {
        Process {
            pid,
            parent,
            started: (100, 0),
            executable: path.into(),
        }
    }

    fn scope() -> Scope {
        Scope::new(
            vec![
                "/Applications/Antigravity.app/Contents/Resources/app.asar".into(),
                "/Users/test/.local/bin/agy".into(),
                "/Users/test/.vscode/extensions/google.antigravity/bin/language_server_darwin_arm64".into(),
            ],
            "/Users/test/Downloads/antigravity-bypass-russia-macos-arm64".into(),
        )
    }

    #[test]
    fn owns_the_selected_ide_helpers_and_exact_cli_and_server_paths() {
        let scope = scope();
        for path in [
            "/Applications/Antigravity.app/Contents/MacOS/Electron",
            "/Applications/Antigravity.app/Contents/Frameworks/Antigravity Helper (Renderer).app/Contents/MacOS/Antigravity Helper (Renderer)",
            "/Applications/Antigravity.app/Contents/Frameworks/Electron Framework.framework/Helpers/chrome_crashpad_handler",
            "/Applications/Antigravity.app/Contents/Resources/app/node_modules/@vscode/ripgrep/bin/rg",
            "/Users/test/.local/bin/agy",
            "/Users/test/.vscode/extensions/google.antigravity/bin/language_server_darwin_arm64",
        ] {
            assert!(scope.owns(Path::new(path)), "{path}");
        }
    }

    #[test]
    fn excludes_the_patcher_shell_other_installations_and_unrelated_tools() {
        let scope = scope();
        for path in [
            "",
            "/Users/test/Downloads/antigravity-bypass-russia-macos-arm64",
            "/bin/bash",
            "/usr/bin/sudo",
            "/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
            "/Applications/Antigravity-other.app/Contents/MacOS/Electron",
            "/Applications/Antigravity.app-other/Contents/MacOS/Electron",
            "/Applications/Antigravity.app/Contents-other/node",
            "/Applications/Visual Studio Code.app/Contents/MacOS/Electron",
            "/opt/homebrew/bin/node",
            "/opt/homebrew/bin/rg",
            "/Other/agy",
            "/Other/language_server_darwin_arm64",
        ] {
            assert!(!scope.owns(Path::new(path)), "{path}");
        }
        let scope = Scope::new(
            scope.files,
            "/Applications/Antigravity.app/Contents/MacOS/patcher".into(),
        );
        assert!(!scope.owns(Path::new(
            "/Applications/Antigravity.app/Contents/MacOS/patcher"
        )));
    }

    #[test]
    fn standalone_cli_does_not_claim_its_entire_bin_directory() {
        let scope = Scope::new(vec!["/opt/homebrew/bin/agy".into()], "/tmp/patcher".into());
        assert!(scope.owns(Path::new("/opt/homebrew/bin/agy")));
        assert!(!scope.owns(Path::new("/opt/homebrew/bin/node")));
    }

    #[test]
    fn nested_installation_does_not_claim_an_unrelated_outer_app_bundle() {
        let scope = Scope::new(
            vec!["/Applications/Container.app/Contents/Apps/Antigravity.app/Contents/Resources/app.asar".into()],
            "/tmp/patcher".into(),
        );
        assert!(scope.owns(Path::new(
            "/Applications/Container.app/Contents/Apps/Antigravity.app/Contents/MacOS/Electron"
        )));
        assert!(!scope.owns(Path::new(
            "/Applications/Container.app/Contents/MacOS/Container"
        )));
        let scope = Scope::new(
            vec!["/Projects/Example.app/agy".into()],
            "/tmp/patcher".into(),
        );
        assert!(scope.owns(Path::new("/Projects/Example.app/agy")));
        assert!(!scope.owns(Path::new("/Projects/Example.app/Contents/MacOS/Other")));
    }

    #[test]
    fn ancestors_protect_sudo_script_terminal_and_ide_without_protecting_siblings() {
        let processes: Vec<_> = [(10, 20), (20, 30), (30, 40), (40, 1), (50, 40)]
            .into_iter()
            .map(|(pid, parent)| process(pid, parent, "/irrelevant"))
            .collect();
        let unavailable = |pid| Err(format!("unavailable PID {pid}"));
        let protected = protected_ancestors(&processes, 10, unavailable).unwrap();
        assert_eq!(protected, [1, 10, 20, 30, 40].into_iter().collect());
        assert!(!protected.contains(&50));
        assert!(protected_ancestors(&processes[..2], 10, unavailable).is_err());
        assert!(
            protected_ancestors(&[process(10, 20, ""), process(20, 10, "")], 10, unavailable)
                .is_err()
        );
    }

    #[test]
    fn an_uninspectable_login_parent_is_protected_using_only_its_parent_link() {
        let processes = [
            process(10, 20, "/tmp/patcher"),
            process(20, 5402, "/bin/zsh"),
            process(50, 5402, "/unrelated/sibling"),
        ];
        let protected = protected_ancestors(&processes, 10, |pid| {
            assert_eq!(pid, 5402);
            Ok(1)
        })
        .unwrap();
        assert_eq!(protected, [1, 10, 20, 5402].into_iter().collect());
        assert!(!protected.contains(&50));
        let error =
            protected_ancestors(&processes, 10, |_| Err("inspection denied".into())).unwrap_err();
        assert_eq!(error, "inspection denied");
    }

    #[test]
    fn fallback_parent_links_cannot_hide_a_cycle_or_authorize_signaling_an_ancestor() {
        let processes = [process(10, 5402, "/tmp/patcher")];
        assert!(protected_ancestors(&processes, 10, |_| Ok(10)).is_err());
        let protected = protected_ancestors(&processes, 10, |_| Ok(1)).unwrap();
        let mut shutdown = Shutdown::default();
        assert!(shutdown
            .actions(
                &[process(5402, 1, "/ide")],
                &protected,
                Duration::ZERO,
                Duration::from_secs(3),
            )
            .is_err());
        assert!(shutdown.requested.is_empty());
    }

    #[test]
    fn ide_ancestor_aborts_the_entire_batch_before_signaling_a_helper() {
        let mut shutdown = Shutdown::default();
        let targets = [process(50, 40, "/helper"), process(40, 1, "/ide")];
        let error = shutdown
            .actions(
                &targets,
                &[10, 20, 30, 40].into_iter().collect(),
                Duration::ZERO,
                Duration::from_secs(3),
            )
            .unwrap_err();
        assert!(error.contains("отдельном приложении Terminal"), "{error}");
        assert!(shutdown.requested.is_empty());
        for pid in [0, 1] {
            assert!(shutdown
                .actions(
                    &[process(pid, 0, "/ide")],
                    &HashSet::new(),
                    Duration::ZERO,
                    Duration::from_secs(3)
                )
                .is_err());
        }
    }

    #[test]
    fn gives_each_process_a_grace_period_before_forcing_shutdown() {
        let mut shutdown = Shutdown::default();
        let first = process(50, 1, "/ide");
        let late_helper = process(51, 50, "/helper");
        let protected = [10, 20, 1].into_iter().collect();
        let grace = Duration::from_secs(3);
        assert_eq!(
            shutdown
                .actions(&[first.clone()], &protected, Duration::ZERO, grace)
                .unwrap(),
            vec![(first.clone(), Signal::Terminate)]
        );
        assert!(shutdown
            .actions(&[first.clone()], &protected, Duration::from_secs(2), grace)
            .unwrap()
            .is_empty());
        assert_eq!(
            shutdown
                .actions(
                    &[first.clone(), late_helper.clone()],
                    &protected,
                    Duration::from_secs(3),
                    grace
                )
                .unwrap(),
            vec![
                (first.clone(), Signal::Kill),
                (late_helper.clone(), Signal::Terminate)
            ]
        );
        assert!(shutdown
            .actions(
                &[first, late_helper.clone()],
                &protected,
                Duration::from_secs(4),
                grace
            )
            .unwrap()
            .is_empty());
        assert_eq!(
            shutdown
                .actions(
                    &[late_helper.clone()],
                    &protected,
                    Duration::from_secs(6),
                    grace
                )
                .unwrap(),
            vec![(late_helper, Signal::Kill)]
        );
    }

    #[test]
    fn reused_pids_and_exec_changes_are_different_processes() {
        let original = process(50, 1, "/ide");
        let mut replacement = original.clone();
        replacement.started.1 += 1;
        assert!(!original.same_instance(&replacement));
        let mut shutdown = Shutdown::default();
        let grace = Duration::from_secs(3);
        shutdown
            .actions(&[original.clone()], &HashSet::new(), Duration::ZERO, grace)
            .unwrap();
        assert_eq!(
            shutdown
                .actions(&[replacement.clone()], &HashSet::new(), grace, grace)
                .unwrap(),
            vec![(replacement, Signal::Terminate)]
        );
        let mut exec = original.clone();
        exec.executable = "/another/program".into();
        assert!(!original.same_instance(&exec));
        assert_eq!(
            shutdown
                .actions(&[exec.clone()], &HashSet::new(), grace, grace)
                .unwrap(),
            vec![(exec, Signal::Terminate)]
        );
        let mut reparented = original.clone();
        reparented.parent = 99;
        assert!(original.same_instance(&reparented));
        assert!(original.label().contains("PID 50"));
    }
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use std::{io, os::unix::ffi::OsStringExt, time::Instant};

    fn parent_pid(pid: u32) -> Result<u32, String> {
        // Unlike PROC_PIDTBSDINFO, SHORTBSDINFO does not require same-UID
        // privileges. Use it only to protect ancestors, never to select or
        // identify a process for termination. XNU: bsd/kern/proc_info.c.
        let mut info: libc::proc_bsdshortinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of_val(&info) as i32;
        let read = unsafe {
            libc::proc_pidinfo(
                pid as i32,
                libc::PROC_PIDT_SHORTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdshortinfo).cast(),
                size,
            )
        };
        if read != size || info.pbsi_pid != pid {
            let detail = if read == 0 {
                io::Error::last_os_error().to_string()
            } else {
                "неполный или некорректный ответ macOS".into()
            };
            return Err(format!(
                "Не удалось проверить родительский процесс PID {pid}: {detail}; повторите операцию из отдельного Terminal"
            ));
        }
        Ok(info.pbsi_ppid)
    }

    fn bsd_info(pid: u32) -> io::Result<Option<libc::proc_bsdinfo>> {
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of_val(&info) as i32;
        let read = unsafe {
            libc::proc_pidinfo(
                pid as i32,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                size,
            )
        };
        if read != size {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(libc::ESRCH) {
                Ok(None)
            } else {
                Err(error)
            };
        }
        Ok((info.pbi_status != libc::SZOMB).then_some(info))
    }

    fn inspect(pid: u32) -> io::Result<Option<Process>> {
        let Some(before) = bsd_info(pid)? else {
            return Ok(None);
        };
        let mut path = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let length =
            unsafe { libc::proc_pidpath(pid as i32, path.as_mut_ptr().cast(), path.len() as u32) };
        // Preserve parent links even when the executable is inaccessible.
        let executable = if length > 0 && (length as usize) < path.len() {
            path.truncate(length as usize);
            let path = PathBuf::from(std::ffi::OsString::from_vec(path));
            std::fs::canonicalize(&path).unwrap_or(path)
        } else {
            PathBuf::new()
        };
        let Some(after) = bsd_info(pid)? else {
            return Ok(None);
        };
        let started = (after.pbi_start_tvsec, after.pbi_start_tvusec);
        if started != (before.pbi_start_tvsec, before.pbi_start_tvusec) {
            return Ok(None);
        }
        Ok(Some(Process {
            pid,
            parent: after.pbi_ppid,
            started,
            executable,
        }))
    }

    /// Best-effort display name for permission guidance. TCC itself remains
    /// authoritative about which process is responsible for the request.
    pub(crate) fn launching_app_name() -> Option<String> {
        use crate::system::macos_app::bundle;
        let mut pid = std::process::id();
        for _ in 0..32 {
            pid = parent_pid(pid).ok()?;
            if pid <= 1 {
                break;
            }
            if let Ok(Some(process)) = inspect(pid) {
                if let Some(name) = bundle(&process.executable).and_then(Path::file_stem) {
                    let name = name.to_str()?;
                    return Some(if name == "Terminal" { "Терминал" } else { name }.into());
                }
            }
        }
        None
    }

    fn snapshot() -> Result<Vec<Process>, String> {
        let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
        if count <= 0 || count > 1_000_000 {
            return Err(format!(
                "Список процессов macOS: {}",
                io::Error::last_os_error()
            ));
        }
        let mut pids = vec![0i32; count as usize + 128];
        for _ in 0..3 {
            let count = unsafe {
                libc::proc_listallpids(
                    pids.as_mut_ptr().cast(),
                    std::mem::size_of_val(pids.as_slice()) as i32,
                )
            };
            if count <= 0 {
                return Err(format!(
                    "Список процессов macOS: {}",
                    io::Error::last_os_error()
                ));
            }
            if (count as usize) < pids.len() {
                pids.truncate(count as usize);
                return Ok(pids
                    .into_iter()
                    .filter(|pid| *pid > 0)
                    .filter_map(|pid| inspect(pid as u32).ok().flatten())
                    .collect());
            }
            pids.resize(pids.len() * 2, 0);
        }
        Err("Список процессов macOS меняется; повторите операцию".into())
    }

    fn scope(paths: &[PathBuf]) -> Result<Scope, String> {
        let canonicalize = |path: &Path| {
            std::fs::canonicalize(path).map_err(|error| format!("{}: {error}", path.display()))
        };
        let files = paths
            .iter()
            .map(|path| canonicalize(path))
            .collect::<Result<_, _>>()?;
        let patcher = canonicalize(&std::env::current_exe().map_err(|error| error.to_string())?)?;
        Ok(Scope::new(files, patcher))
    }

    fn signal_verified(
        process: &Process,
        signal: Signal,
        protected: &HashSet<u32>,
    ) -> Result<(), String> {
        if process.pid <= 1 || process.pid == std::process::id() || protected.contains(&process.pid)
        {
            return Err(format!("Нельзя завершить защищённый PID {}", process.pid));
        }
        let Some(current) = inspect(process.pid)
            .map_err(|error| format!("Проверка PID {}: {error}", process.pid))?
        else {
            return Ok(());
        };
        // A PID can be reused, including by another copy of the same program.
        // Re-read both executable and start time immediately before signaling.
        if !process.same_instance(&current) {
            return Err(format!(
                "Процесс PID {} изменился; сигнал не отправлен",
                process.pid
            ));
        }
        let signal = match signal {
            Signal::Terminate => libc::SIGTERM,
            Signal::Kill => libc::SIGKILL,
        };
        if unsafe { libc::kill(process.pid as i32, signal) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(format!("Завершение PID {}: {error}", process.pid))
        }
    }

    pub fn running_applications(paths: &[PathBuf]) -> Result<Vec<String>, String> {
        if paths.is_empty() {
            return Ok(vec![]);
        }
        let scope = scope(paths)?;
        Ok(snapshot()?
            .iter()
            .filter(|process| scope.owns(&process.executable))
            .map(Process::label)
            .collect())
    }

    pub fn close_application(paths: &[PathBuf]) -> Result<(), String> {
        if paths.is_empty() {
            return Ok(());
        }
        let scope = scope(paths)?;
        let mut shutdown = Shutdown::default();
        let mut errors: HashMap<Identity, String> = HashMap::new();
        let started = Instant::now();
        let budget = Duration::from_secs(8);
        loop {
            let processes = snapshot()?;
            let protected = protected_ancestors(&processes, std::process::id(), parent_pid)?;
            let targets: Vec<_> = processes
                .into_iter()
                .filter(|process| scope.owns(&process.executable))
                .collect();
            let now = started.elapsed();
            let holders = if targets.is_empty() || now >= budget {
                crate::system::file_lock::holders(paths)?
            } else {
                vec![]
            };
            if targets.is_empty() && holders.is_empty() {
                return Ok(());
            }
            if now >= budget {
                let mut remaining = holders;
                for process in &targets {
                    remaining.push(process.label());
                    if let Some(error) = errors.get(&process.identity()) {
                        remaining.push(error.clone());
                    }
                }
                remaining.sort();
                remaining.dedup();
                return Err(format!("Antigravity не освободила файлы: {}. Завершите указанные процессы вручную и повторите операцию.", remaining.join("; ")));
            }
            for (process, signal) in
                shutdown.actions(&targets, &protected, now, Duration::from_secs(3))?
            {
                match signal_verified(&process, signal, &protected) {
                    Ok(()) => {
                        errors.remove(&process.identity());
                    }
                    Err(error) => {
                        errors.insert(process.identity(), error);
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{
            fs,
            os::unix::process::{CommandExt, ExitStatusExt},
            process::{Command, Stdio},
        };

        #[test]
        #[ignore = "launched only by isolated macOS shutdown regression tests"]
        fn process_fixture() {
            if std::env::var_os("ABR_SHUTDOWN_IGNORE_TERM").is_some() {
                assert_ne!(
                    unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) },
                    libc::SIG_ERR
                );
            }
            let file = std::env::var_os("ABR_SHUTDOWN_OPEN_FILE")
                .map(|path| fs::File::open(path).unwrap());
            fs::write(std::env::var_os("ABR_SHUTDOWN_READY").unwrap(), b"ready").unwrap();
            std::thread::sleep(Duration::from_secs(30));
            drop(file);
        }

        struct Fixture(std::process::Child);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        #[test]
        fn basic_parent_links_include_system_processes_without_elevation() {
            assert_eq!(parent_pid(1).unwrap(), 0);
            let current = std::process::id();
            let parent = unsafe { libc::getppid() } as u32;
            assert_eq!(parent_pid(current).unwrap(), parent);
            // Force every link through the unprivileged query, including the
            // login/sudo process a full process snapshot can legitimately omit.
            let protected = protected_ancestors(&[], current, parent_pid).unwrap();
            assert!(protected.contains(&current));
            assert!(protected.contains(&parent));
            assert!(protected.contains(&1));
        }

        fn spawn_fixture(
            executable: &Path,
            open_file: Option<&Path>,
            ignore_term: bool,
        ) -> Fixture {
            fs::create_dir_all(executable.parent().unwrap()).unwrap();
            fs::copy(std::env::current_exe().unwrap(), executable).unwrap();
            let ready = executable.with_extension("ready");
            let mut command = Command::new(executable);
            command
                .arg0("Antigravity unlock_and_restore.sh")
                .args([
                    "--exact",
                    "system::macos_shutdown::native::tests::process_fixture",
                    "--ignored",
                ])
                .env("ABR_SHUTDOWN_READY", &ready)
                .env_remove("ABR_SHUTDOWN_OPEN_FILE")
                .env_remove("ABR_SHUTDOWN_IGNORE_TERM")
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            if let Some(file) = open_file {
                command.env("ABR_SHUTDOWN_OPEN_FILE", file);
            }
            if ignore_term {
                command.env("ABR_SHUTDOWN_IGNORE_TERM", "1");
            }
            let fixture = Fixture(command.spawn().unwrap());
            let deadline = Instant::now() + Duration::from_secs(5);
            while !ready.exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            assert!(
                ready.exists(),
                "fixture {} did not start",
                executable.display()
            );
            fixture
        }

        #[test]
        fn closes_ide_helpers_cli_and_server_but_preserves_the_patcher_and_other_installations() {
            let directory = tempfile::tempdir().unwrap();
            let app = directory.path().join("Antigravity.app/Contents");
            let asar = app.join("Resources/app.asar");
            fs::create_dir_all(asar.parent().unwrap()).unwrap();
            fs::write(&asar, b"fixture archive").unwrap();
            let mut ide = spawn_fixture(&app.join("MacOS/Electron"), Some(&asar), false);
            let mut helper = spawn_fixture(&app.join("Frameworks/Antigravity Helper (Renderer).app/Contents/MacOS/Antigravity Helper (Renderer)"), None, true);
            let cli_path = directory.path().join("cli/agy");
            let server_path = directory
                .path()
                .join("extension/language_server_darwin_arm64");
            let mut cli = spawn_fixture(&cli_path, None, false);
            let mut server = spawn_fixture(&server_path, None, false);
            let mut unrelated = spawn_fixture(
                &directory
                    .path()
                    .join("Other Antigravity.app/Contents/MacOS/Electron"),
                None,
                false,
            );
            let paths = [asar, cli_path, server_path];
            assert_eq!(running_applications(&paths).unwrap().len(), 4);
            close_application(&paths).unwrap();
            assert_eq!(ide.0.wait().unwrap().signal(), Some(libc::SIGTERM));
            assert_eq!(helper.0.wait().unwrap().signal(), Some(libc::SIGKILL));
            assert!(cli.0.try_wait().unwrap().is_some());
            assert!(server.0.try_wait().unwrap().is_some());
            assert!(unrelated.0.try_wait().unwrap().is_none());
            assert!(running_applications(&paths).unwrap().is_empty());
            assert!(crate::system::file_lock::holders(&paths)
                .unwrap()
                .is_empty());
            assert!(running_applications(&[std::env::current_exe().unwrap()])
                .unwrap()
                .is_empty());
        }

        #[test]
        fn refuses_self_and_a_changed_identity_and_accepts_an_already_exited_process() {
            let current = inspect(std::process::id()).unwrap().unwrap();
            assert!(signal_verified(&current, Signal::Kill, &HashSet::new()).is_err());
            let directory = tempfile::tempdir().unwrap();
            let mut child = spawn_fixture(&directory.path().join("Antigravity"), None, false);
            let original = inspect(child.0.id()).unwrap().unwrap();
            let mut changed = original.clone();
            changed.started.1 += 1;
            assert!(signal_verified(&changed, Signal::Kill, &HashSet::new()).is_err());
            assert!(signal_verified(
                &original,
                Signal::Kill,
                &[child.0.id()].into_iter().collect()
            )
            .is_err());
            assert!(child.0.try_wait().unwrap().is_none());
            child.0.kill().unwrap();
            child.0.wait().unwrap();
            signal_verified(&original, Signal::Kill, &HashSet::new()).unwrap();
        }

        #[test]
        fn reports_an_unrelated_file_holder_without_terminating_it() {
            let directory = tempfile::tempdir().unwrap();
            let target = directory.path().join("main.js");
            fs::write(&target, b"fixture target").unwrap();
            let mut unrelated = spawn_fixture(
                &directory.path().join("Antigravity-script"),
                Some(&target),
                false,
            );
            let error = close_application(&[target]).unwrap_err();
            assert!(
                error.contains(&format!("PID {}", unrelated.0.id())),
                "{error}"
            );
            assert!(unrelated.0.try_wait().unwrap().is_none());
        }
    }
}
