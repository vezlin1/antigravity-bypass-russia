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

pub fn stop_process_by_name(process_name: &str) {
    #[cfg(target_os = "windows")]
    {
        let clean_name = process_name.trim_end_matches(".exe");
        let exe_name = format!("{}.exe", clean_name);
        let _ = crate::system::command::output("taskkill", ["/F", "/T", "/IM", &exe_name]);
        stop_processes_by_names(&[clean_name, &exe_name]);
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = crate::system::command::output("killall", ["-9", process_name]);
        let _ = crate::system::command::output("pkill", ["-9", "-x", process_name]);
    }
}

#[cfg(target_os = "windows")]
pub fn stop_processes_by_names(names: &[&str]) -> usize {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    const TH32CS_SNAPPROCESS: u32 = 0x00000002;
    const PROCESS_TERMINATE: u32 = 0x0001;
    const INVALID_HANDLE_VALUE: *mut std::ffi::c_void = -1isize as *mut std::ffi::c_void;

    #[repr(C)]
    struct ProcessEntry32W {
        dw_size: u32,
        cnt_usage: u32,
        th32_process_id: u32,
        th32_default_heap_id: usize,
        th32_module_id: u32,
        cnt_threads: u32,
        th32_parent_process_id: u32,
        pc_pri_class_base: i32,
        dw_flags: u32,
        sz_exe_file: [u16; 260],
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) -> *mut std::ffi::c_void;
        fn Process32FirstW(hSnapshot: *mut std::ffi::c_void, lppe: *mut ProcessEntry32W) -> i32;
        fn Process32NextW(hSnapshot: *mut std::ffi::c_void, lppe: *mut ProcessEntry32W) -> i32;
        fn OpenProcess(
            dwDesiredAccess: u32,
            bInheritHandle: i32,
            dwProcessId: u32,
        ) -> *mut std::ffi::c_void;
        fn TerminateProcess(hProcess: *mut std::ffi::c_void, uExitCode: u32) -> i32;
        fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
    }

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot.is_null() || snapshot == INVALID_HANDLE_VALUE {
        return 0;
    }

    let mut entry = ProcessEntry32W {
        dw_size: std::mem::size_of::<ProcessEntry32W>() as u32,
        cnt_usage: 0,
        th32_process_id: 0,
        th32_default_heap_id: 0,
        th32_module_id: 0,
        cnt_threads: 0,
        th32_parent_process_id: 0,
        pc_pri_class_base: 0,
        dw_flags: 0,
        sz_exe_file: [0u16; 260],
    };

    let mut killed = 0;
    let my_pid = std::process::id();
    let target_names_lower: Vec<String> = names.iter().map(|n| n.to_lowercase()).collect();

    if unsafe { Process32FirstW(snapshot, &mut entry) } != 0 {
        loop {
            if entry.th32_process_id != my_pid && entry.th32_process_id != 0 {
                let null_pos = entry
                    .sz_exe_file
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.sz_exe_file.len());
                let exe_name = OsString::from_wide(&entry.sz_exe_file[..null_pos])
                    .to_string_lossy()
                    .to_lowercase();

                if target_names_lower
                    .iter()
                    .any(|target| target == &exe_name || target == &format!("{}.exe", exe_name))
                {
                    let h_proc =
                        unsafe { OpenProcess(PROCESS_TERMINATE, 0, entry.th32_process_id) };
                    if !h_proc.is_null() {
                        if unsafe { TerminateProcess(h_proc, 1) } != 0 {
                            killed += 1;
                        }
                        unsafe { CloseHandle(h_proc) };
                    }
                }
            }

            if unsafe { Process32NextW(snapshot, &mut entry) } == 0 {
                break;
            }
        }
    }

    unsafe { CloseHandle(snapshot) };
    killed
}
