#[cfg(target_os = "windows")]
static MUTEX_HANDLE: std::sync::atomic::AtomicPtr<std::ffi::c_void> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

pub fn check_single_instance() -> bool {
    #[cfg(target_os = "windows")]
    {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use std::sync::atomic::Ordering;

        #[link(name = "kernel32")]
        extern "system" {
            fn CreateMutexW(
                lpMutexAttributes: *mut std::ffi::c_void,
                bInitialOwner: i32,
                lpName: *const u16,
            ) -> *mut std::ffi::c_void;
            fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
            fn GetLastError() -> u32;
        }

        const ERROR_ALREADY_EXISTS: u32 = 183;
        let name: Vec<u16> = OsStr::new("Global\\AntigravityBypassRussia_Instance_Lock")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            let handle = CreateMutexW(std::ptr::null_mut(), 1, name.as_ptr());
            if handle.is_null() {
                return false;
            }
            if GetLastError() == ERROR_ALREADY_EXISTS {
                CloseHandle(handle);
                return false;
            }
            MUTEX_HANDLE.store(handle, Ordering::SeqCst);
            true
        }
    }

    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::io::AsRawFd;

        let lock_path = "/tmp/antigravity_bypass_russia.lock";
        if let Ok(file) = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
        {
            let fd = file.as_raw_fd();
            let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
            if ret != 0 {
                return false;
            }
            // Retain lock descriptor until termination
            std::mem::forget(file);
            true
        } else {
            true
        }
    }

    #[cfg(not(any(target_os = "windows", unix)))]
    true
}
