use std::process::Command;

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
        let _ = no_window(&mut Command::new("taskkill"))
            .args(["/F", "/T", "/IM", &exe_name])
            .output();
        stop_processes_by_names(&[clean_name, &exe_name]);
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = Command::new("killall").args(["-9", process_name]).output();
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
        fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> *mut std::ffi::c_void;
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
                let null_pos = entry.sz_exe_file.iter().position(|&c| c == 0).unwrap_or(entry.sz_exe_file.len());
                let exe_name = OsString::from_wide(&entry.sz_exe_file[..null_pos]).to_string_lossy().to_lowercase();

                if target_names_lower.iter().any(|target| target == &exe_name || target == &format!("{}.exe", exe_name)) {
                    let h_proc = unsafe { OpenProcess(PROCESS_TERMINATE, 0, entry.th32_process_id) };
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

pub fn kill_processes() {
    let procs = [
        "Antigravity.exe",
        "Antigravity IDE.exe",
        "language_server_windows_x64.exe",
        "language_server_windows_arm64.exe",
        "language_server.exe",
        "agy.exe",
        "ag_dns.exe",
        "Antigravity",
        "Antigravity IDE",
        "language_server_darwin_arm64",
        "language_server_darwin_x64",
        "language_server",
        "agy",
        "ag_dns",
    ];

    #[cfg(target_os = "windows")]
    {
        stop_processes_by_names(&procs);
    }
    #[cfg(not(target_os = "windows"))]
    {
        let mut cmd = Command::new("killall");
        cmd.arg("-9");
        for p in procs {
            cmd.arg(p);
        }
        let _ = cmd.output();
    }
}
