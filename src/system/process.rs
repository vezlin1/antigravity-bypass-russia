use std::process::Command;

#[cfg(windows)]
#[derive(Clone)]
pub struct RunningProcess {
    pub pid: u32,
    pub parent: u32,
    pub executable: std::path::PathBuf,
}

#[cfg(windows)]
struct Handle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(windows)]
fn image_path(handle: windows_sys::Win32::Foundation::HANDLE) -> Option<std::path::PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    let mut buffer = vec![0u16; 32768];
    let mut length = buffer.len() as u32;
    if unsafe {
        windows_sys::Win32::System::Threading::QueryFullProcessImageNameW(
            handle,
            0,
            buffer.as_mut_ptr(),
            &mut length,
        )
    } == 0
    {
        return None;
    }
    Some(std::ffi::OsString::from_wide(&buffer[..length as usize]).into())
}

#[cfg(windows)]
pub fn snapshot() -> Result<Vec<RunningProcess>, String> {
    use windows_sys::Win32::{
        Foundation::INVALID_HANDLE_VALUE,
        System::{Diagnostics::ToolHelp::*, Threading::*},
    };
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if raw == INVALID_HANDLE_VALUE {
        return Err(format!(
            "Список процессов: {}",
            std::io::Error::last_os_error()
        ));
    }
    let handle = Handle(raw);
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut result = Vec::new();
    let mut more = unsafe { Process32FirstW(handle.0, &mut entry) };
    while more != 0 {
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, entry.th32ProcessID) };
        let executable = if raw.is_null() {
            None
        } else {
            image_path(Handle(raw).0)
        };
        // Keep parent links even when a protected process cannot be inspected.
        result.push(RunningProcess {
            pid: entry.th32ProcessID,
            parent: entry.th32ParentProcessID,
            executable: executable.unwrap_or_default(),
        });
        more = unsafe { Process32NextW(handle.0, &mut entry) };
    }
    Ok(result)
}

#[cfg(windows)]
pub fn ancestor_pids(processes: &[RunningProcess], current: u32) -> std::collections::HashSet<u32> {
    let mut protected = std::collections::HashSet::new();
    let mut pid = current;
    while pid != 0 && protected.insert(pid) {
        match processes.iter().find(|p| p.pid == pid) {
            Some(p) => pid = p.parent,
            None => break,
        }
    }
    protected
}

#[cfg(all(test, windows))]
mod shutdown_tests {
    fn query_only_child() -> (super::Handle, std::process::Child) {
        use windows_sys::Win32::System::Threading::*;
        let child = crate::system::powershell::command()
            .unwrap()
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Sleep -Seconds 30",
            ])
            .spawn()
            .unwrap();
        // Deliberately omit PROCESS_TERMINATE to reproduce an access denial.
        let raw = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                child.id(),
            )
        };
        assert!(!raw.is_null());
        (super::Handle(raw), child)
    }

    #[test]
    fn denied_termination_is_success_when_process_finishes_shortly_afterward() {
        let (handle, mut child) = query_only_child();
        let pid = child.id();
        let finishing = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(150));
            child.kill().unwrap();
            child.wait().unwrap();
        });
        let result = super::terminate_handle(handle.0, pid);
        finishing.join().unwrap();
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn denied_termination_remains_error_if_process_is_still_running() {
        let (handle, mut child) = query_only_child();
        let result = super::terminate_handle(handle.0, child.id());
        let running = child.try_wait().unwrap().is_none();
        let _ = child.kill();
        let _ = child.wait();
        assert!(running);
        assert!(result.unwrap_err().contains("os error 5"));
    }

    #[test]
    fn protects_patcher_terminal_and_ide_ancestors_without_protecting_siblings() {
        let processes: Vec<_> = [(10, 20), (20, 30), (30, 40), (40, 40), (50, 30)]
            .into_iter()
            .map(|(pid, parent)| super::RunningProcess {
                pid,
                parent,
                executable: Default::default(),
            })
            .collect();
        let protected = super::ancestor_pids(&processes, 10);
        assert_eq!(protected, [10, 20, 30, 40].into_iter().collect());
        assert!(!protected.contains(&50));
    }
}

#[cfg(windows)]
pub fn terminate_verified(process: &RunningProcess) -> Result<(), String> {
    use windows_sys::Win32::{Foundation::ERROR_INVALID_PARAMETER, System::Threading::*};
    if process.pid == std::process::id() {
        return Err("Нельзя завершить процесс патчера".into());
    }
    let raw = unsafe {
        OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            process.pid,
        )
    };
    if raw.is_null() {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
            return Ok(());
        }
        return Err(format!("Доступ к PID {}: {error}", process.pid));
    }
    let handle = Handle(raw);
    // Validate through the very handle being terminated, not a name/task tree.
    if unsafe { WaitForSingleObject(handle.0, 0) } == 0 {
        return Ok(());
    }
    if image_path(handle.0).as_ref() != Some(&process.executable) {
        return Err(format!(
            "Процесс PID {} изменился; повторите операцию",
            process.pid
        ));
    }
    terminate_handle(handle.0, process.pid)
}

#[cfg(windows)]
fn terminate_handle(
    handle: windows_sys::Win32::Foundation::HANDLE,
    pid: u32,
) -> Result<(), String> {
    use windows_sys::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};
    if unsafe { TerminateProcess(handle, 0) } == 0 {
        // ERROR_ACCESS_DENIED also occurs during an asynchronous exit. Preserve
        // the original error, then allow the process to reach its signaled state.
        let error = std::io::Error::last_os_error();
        if unsafe { WaitForSingleObject(handle, 1000) } == 0 {
            return Ok(());
        }
        return Err(format!("Завершение PID {}: {}", pid, error));
    }
    unsafe {
        WaitForSingleObject(handle, 1000);
    }
    Ok(())
}

#[inline]
pub fn no_window(cmd: &mut Command) -> &mut Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

#[cfg(target_os = "macos")]
pub fn stop_process_by_name(process_name: &str) {
    let _ = crate::system::command::output("killall", ["-9", process_name]);
    let _ = crate::system::command::output("pkill", ["-9", "-x", process_name]);
}

/// One Toolhelp row: PID, parent PID and the lower-cased image file name.
#[cfg(any(windows, test))]
#[derive(Clone)]
struct ProcessEntry {
    pid: u32,
    parent: u32,
    image: String,
}

#[cfg(windows)]
fn process_entries() -> Result<Vec<ProcessEntry>, String> {
    use windows_sys::Win32::{Foundation::INVALID_HANDLE_VALUE, System::Diagnostics::ToolHelp::*};
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if raw == INVALID_HANDLE_VALUE {
        return Err(format!(
            "Список процессов: {}",
            std::io::Error::last_os_error()
        ));
    }
    let snapshot = Handle(raw);
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut entries = Vec::new();
    let mut more = unsafe { Process32FirstW(snapshot.0, &mut entry) };
    while more != 0 {
        let length = entry
            .szExeFile
            .iter()
            .position(|&unit| unit == 0)
            .unwrap_or(entry.szExeFile.len());
        entries.push(ProcessEntry {
            pid: entry.th32ProcessID,
            parent: entry.th32ParentProcessID,
            image: String::from_utf16_lossy(&entry.szExeFile[..length]).to_lowercase(),
        });
        more = unsafe { Process32NextW(snapshot.0, &mut entry) };
    }
    Ok(entries)
}

#[cfg(any(windows, test))]
fn matches_image(entry: &ProcessEntry, image: &str, own_pid: u32) -> bool {
    entry.pid != 0 && entry.pid != own_pid && entry.image.eq_ignore_ascii_case(image)
}

/// Matching processes first, then all of their descendants, as `taskkill /T /IM`
/// selects them. The current process is never included.
#[cfg(any(windows, test))]
fn process_tree(entries: &[ProcessEntry], image: &str, own_pid: u32) -> Vec<u32> {
    let mut selected: Vec<u32> = entries
        .iter()
        .filter(|entry| matches_image(entry, image, own_pid))
        .map(|entry| entry.pid)
        .collect();
    let mut next = 0;
    while next < selected.len() {
        let parent = selected[next];
        next += 1;
        for entry in entries {
            if entry.parent == parent
                && entry.pid != 0
                && entry.pid != own_pid
                && entry.pid != parent
                && !selected.contains(&entry.pid)
            {
                selected.push(entry.pid);
            }
        }
    }
    selected
}

/// Whether a process with this image file name runs from `expected`. The
/// rule matches `terminate_image_tree`, so a same-named copy elsewhere (a dev
/// build, an unpacked archive) neither counts as the service nor blocks it.
/// A process whose path cannot be read (a SYSTEM service seen without admin
/// rights) counts as running, as a name match always did.
#[cfg(windows)]
pub fn image_running_at(image: &str, expected: &std::path::Path) -> Result<bool, String> {
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    let own_pid = std::process::id();
    Ok(process_entries()?
        .iter()
        .filter(|entry| matches_image(entry, image, own_pid))
        .any(|entry| {
            let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, entry.pid) };
            if raw.is_null() {
                return true;
            }
            let handle = Handle(raw);
            image_path(handle.0).is_none_or(|path| same_image_path(&path, expected))
        }))
}

/// Descendants of `roots` that are provably theirs. Windows reuses PIDs, so a
/// recorded parent PID may now belong to an unrelated, newer process: a child
/// counts only if it was created no earlier than the parent it points to. Both
/// creation times come from handles held open, which pins each PID.
#[cfg(any(windows, test))]
fn verified_tree(
    entries: &[ProcessEntry],
    roots: &[u32],
    created: &std::collections::HashMap<u32, u64>,
    own_pid: u32,
) -> Vec<u32> {
    let mut selected: Vec<u32> = roots.to_vec();
    let mut next = 0;
    while next < selected.len() {
        let parent = selected[next];
        next += 1;
        let Some(parent_created) = created.get(&parent) else {
            continue;
        };
        for entry in entries {
            if entry.parent != parent
                || entry.pid == 0
                || entry.pid == own_pid
                || entry.pid == parent
                || selected.contains(&entry.pid)
            {
                continue;
            }
            if created
                .get(&entry.pid)
                .is_some_and(|child_created| child_created >= parent_created)
            {
                selected.push(entry.pid);
            }
        }
    }
    selected
}

/// A handle that can terminate and wait for one process, with its creation time.
#[cfg(windows)]
fn open_for_termination(pid: u32) -> Option<(Handle, u64)> {
    use windows_sys::Win32::{
        Foundation::FILETIME,
        System::Threading::{
            GetProcessTimes, OpenProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
            PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
        },
    };
    let raw = unsafe {
        OpenProcess(
            PROCESS_TERMINATE | PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            pid,
        )
    };
    if raw.is_null() {
        return None;
    }
    let handle = Handle(raw);
    // An exited process keeps its PID only while handles exist; skip it.
    if unsafe { WaitForSingleObject(handle.0, 0) } == 0 {
        return None;
    }
    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut creation, mut exit, mut kernel, mut user) = (zero, zero, zero, zero);
    if unsafe { GetProcessTimes(handle.0, &mut creation, &mut exit, &mut kernel, &mut user) } == 0 {
        return None;
    }
    let created = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    Some((handle, created))
}

#[cfg(windows)]
fn same_image_path(actual: &std::path::Path, expected: &std::path::Path) -> bool {
    // Canonical forms also resolve 8.3 short names and differing separators.
    let canonical = |path: &std::path::Path| std::fs::canonicalize(path).unwrap_or(path.into());
    canonical(actual)
        .as_os_str()
        .to_string_lossy()
        .eq_ignore_ascii_case(&canonical(expected).as_os_str().to_string_lossy())
}

/// Native `taskkill /F /T /IM`, restricted to provable members of the tree:
/// roots must run `expected` (when given), descendants must be newer than
/// their parent, and every process is terminated through the handle that was
/// verified. Waits up to `wait` for them to exit.
#[cfg(windows)]
pub fn terminate_image_tree(
    image: &str,
    expected: Option<&std::path::Path>,
    wait: std::time::Duration,
) -> Result<(), String> {
    use windows_sys::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};
    let own_pid = std::process::id();
    // Open every candidate first; an open handle keeps its PID from reuse.
    let candidates = process_tree(&process_entries()?, image, own_pid);
    let mut held = std::collections::HashMap::new();
    for pid in candidates {
        if let Some(opened) = open_for_termination(pid) {
            held.insert(pid, opened);
        }
    }
    // Parent links are read again while the handles pin those PIDs.
    let entries = process_entries()?;
    let roots: Vec<u32> = entries
        .iter()
        .filter(|entry| matches_image(entry, image, own_pid))
        .filter_map(|entry| {
            let (handle, _) = held.get(&entry.pid)?;
            let path = image_path(handle.0)?;
            expected
                .is_none_or(|expected| same_image_path(&path, expected))
                .then_some(entry.pid)
        })
        .collect();
    let created = held
        .iter()
        .map(|(pid, (_, created))| (*pid, *created))
        .collect();
    let tree = verified_tree(&entries, &roots, &created, own_pid);
    for pid in &tree {
        if let Some((handle, _)) = held.get(pid) {
            unsafe {
                TerminateProcess(handle.0, 1);
            }
        }
    }
    let deadline = std::time::Instant::now() + wait;
    for pid in &tree {
        if let Some((handle, _)) = held.get(pid) {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            unsafe {
                WaitForSingleObject(handle.0, remaining.as_millis().min(u32::MAX as u128) as u32);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tree_tests {
    use super::*;

    fn entry(pid: u32, parent: u32, image: &str) -> ProcessEntry {
        ProcessEntry {
            pid,
            parent,
            image: image.into(),
        }
    }

    #[test]
    fn tree_selects_matching_images_and_descendants_but_never_self() {
        let entries = [
            entry(4, 0, "system"),
            entry(100, 4, "ag_dns.exe"),
            entry(200, 100, "powershell.exe"),
            entry(300, 200, "conhost.exe"),
            entry(400, 4, "AG_DNS.EXE"),
            entry(500, 4, "explorer.exe"),
            entry(600, 500, "powershell.exe"),
            entry(700, 100, "patcher.exe"),
            entry(800, 800, "ag_dns.exe"),
        ];
        let mut tree = process_tree(&entries, "ag_dns.exe", 700);
        tree.sort_unstable();
        assert_eq!(tree, [100, 200, 300, 400, 800]);
        assert!(process_tree(&entries, "missing.exe", 700).is_empty());
    }

    #[test]
    fn reused_parent_pid_does_not_adopt_an_older_process() {
        // 100 is the relay (created at t=50). 200 is its real child (t=60).
        // 300 recorded parent 100 long ago (t=10), before the PID was reused.
        let entries = [
            entry(100, 4, "ag_dns.exe"),
            entry(200, 100, "powershell.exe"),
            entry(250, 200, "conhost.exe"),
            entry(300, 100, "editor.exe"),
            entry(400, 300, "child-of-editor.exe"),
            entry(500, 100, "unverifiable.exe"),
        ];
        let created = [(100, 50), (200, 60), (250, 61), (300, 10), (400, 70)]
            .into_iter()
            .collect();
        let mut tree = verified_tree(&entries, &[100], &created, 1);
        tree.sort_unstable();
        // 300 is older than 100, so neither it nor its child is touched; 500
        // could not be opened and verified.
        assert_eq!(tree, [100, 200, 250]);
    }
}

#[cfg(all(test, windows))]
mod tree_windows_tests {
    #[test]
    fn same_image_name_from_another_folder_is_left_running() {
        use std::os::windows::process::CommandExt;
        let image = format!("ag_tree_other_{}.exe", std::process::id());
        let system = std::env::var_os("SystemRoot").unwrap();
        let cmd = std::path::Path::new(&system).join(r"System32\cmd.exe");
        let expected_dir = tempfile::tempdir().unwrap();
        let other_dir = tempfile::tempdir().unwrap();
        let expected = expected_dir.path().join(&image);
        let other = other_dir.path().join(&image);
        std::fs::copy(&cmd, &expected).unwrap();
        std::fs::copy(&cmd, &other).unwrap();
        let spawn = |path: &std::path::Path| {
            std::process::Command::new(path)
                .args(["/d", "/c", "ping -n 30 127.0.0.1 >nul"])
                .creation_flags(0x0800_0000)
                .spawn()
                .unwrap()
        };
        let mut wanted = spawn(&expected);
        let mut stranger = spawn(&other);
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(super::image_running_at(&image, &expected).unwrap());
        super::terminate_image_tree(&image, Some(&expected), std::time::Duration::from_secs(2))
            .unwrap();
        assert!(wanted.try_wait().unwrap().is_some());
        let survived = stranger.try_wait().unwrap().is_none();
        // The copy left running is not mistaken for the stopped service, so
        // rollback and restart do not wait for it.
        let blocked = super::image_running_at(&image, &expected).unwrap();
        let _ = stranger.kill();
        let _ = stranger.wait();
        assert!(survived, "a process from another folder was terminated");
        assert!(
            !blocked,
            "a process from another folder counted as the service"
        );
    }

    #[test]
    fn image_tree_termination_stops_the_process_and_its_children() {
        use std::os::windows::process::CommandExt;
        let dir = tempfile::tempdir().unwrap();
        let image = format!("ag_tree_test_{}.exe", std::process::id());
        let shell = dir.path().join(&image);
        let system = std::env::var_os("SystemRoot").unwrap();
        std::fs::copy(
            std::path::Path::new(&system).join(r"System32\cmd.exe"),
            &shell,
        )
        .unwrap();
        let mut parent = std::process::Command::new(&shell)
            .args(["/d", "/c", "ping -n 30 127.0.0.1 >nul"])
            .creation_flags(0x0800_0000)
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let children = loop {
            let entries = super::process_entries().unwrap();
            let tree = super::process_tree(&entries, &image, std::process::id());
            if tree.len() > 1 || std::time::Instant::now() > deadline {
                break tree;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        assert!(
            children.len() > 1,
            "child process did not start: {children:?}"
        );
        assert!(super::image_running_at(&image, &shell).unwrap());

        super::terminate_image_tree(&image, Some(&shell), std::time::Duration::from_secs(2))
            .unwrap();

        assert!(parent.try_wait().unwrap().is_some());
        assert!(!super::image_running_at(&image, &shell).unwrap());
        let alive = super::process_entries().unwrap();
        for pid in &children {
            assert!(
                alive.iter().all(|entry| entry.pid != *pid),
                "PID {pid} survived"
            );
        }
    }
}
