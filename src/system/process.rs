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

/// Whether a process with this image file name is running (`tasklist /FI`
/// without starting a process).
#[cfg(windows)]
pub fn image_running(image: &str) -> Result<bool, String> {
    let own_pid = std::process::id();
    Ok(process_entries()?
        .iter()
        .any(|entry| matches_image(entry, image, own_pid)))
}

/// Native `taskkill /F /T /IM`: terminates every process with this image name
/// and its descendants, then waits up to `wait` for them to exit.
#[cfg(windows)]
pub fn terminate_image_tree(image: &str, wait: std::time::Duration) -> Result<(), String> {
    use windows_sys::Win32::System::Threading::{
        OpenProcess, TerminateProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    };
    let pids = process_tree(&process_entries()?, image, std::process::id());
    let mut handles = Vec::new();
    for pid in pids {
        let raw = unsafe { OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, 0, pid) };
        if raw.is_null() {
            // Already exited, or not accessible; the caller re-checks the state.
            continue;
        }
        let handle = Handle(raw);
        unsafe {
            TerminateProcess(handle.0, 1);
        }
        handles.push(handle);
    }
    let deadline = std::time::Instant::now() + wait;
    for handle in &handles {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        unsafe {
            WaitForSingleObject(handle.0, remaining.as_millis().min(u32::MAX as u128) as u32);
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
}

#[cfg(all(test, windows))]
mod tree_windows_tests {
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
        assert!(super::image_running(&image).unwrap());

        super::terminate_image_tree(&image, std::time::Duration::from_secs(2)).unwrap();

        assert!(parent.try_wait().unwrap().is_some());
        assert!(!super::image_running(&image).unwrap());
        let alive = super::process_entries().unwrap();
        for pid in &children {
            assert!(
                alive.iter().all(|entry| entry.pid != *pid),
                "PID {pid} survived"
            );
        }
    }
}
