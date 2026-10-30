#![allow(dead_code)]

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

pub const FORWARDER_FLAG: &str = "--dns-forwarder";
pub const TASK_NAME: &str = "AntigravityBypassRussia";
pub const LAUNCHD_LABEL: &str = "com.antigravity.bypass.russia";
pub const LAUNCHD_PLIST: &str = "/Library/LaunchDaemons/com.antigravity.bypass.russia.plist";
pub const SYSTEMD_SERVICE: &str = "/etc/systemd/system/antigravity-bypass-russia.service";
pub const SYSTEMD_LABEL: &str = "antigravity-bypass-russia";
pub const EXE_NAME: &str = if cfg!(target_os = "windows") {
    "ag_dns.exe"
} else {
    "ag_dns"
};

pub fn install_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(p) = std::env::var("ProgramData") {
            return PathBuf::from(p).join("AntigravityBypassRussia");
        }
        PathBuf::from("C:\\ProgramData\\AntigravityBypassRussia")
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/AntigravityBypassRussia")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        PathBuf::from("/var/lib/antigravity_bypass_russia")
    }
}

pub fn installed_exe() -> PathBuf {
    install_dir().join(EXE_NAME)
}

#[cfg(any(target_os = "macos", test))]
fn classify_launchd_query(success: bool, code: Option<i32>, stderr: &str) -> Result<bool, String> {
    if success {
        return Ok(true);
    }
    if code == Some(113) || stderr.contains("Could not find service") {
        return Ok(false);
    }
    Err(format!(
        "Проверка launchd (код {code:?}): {}",
        stderr.trim()
    ))
}

#[cfg(target_os = "macos")]
fn mac_job_loaded() -> Result<bool, String> {
    let output =
        crate::system::command::output("launchctl", ["print", &format!("system/{LAUNCHD_LABEL}")])
            .map_err(|e| format!("launchctl print: {e}"))?;
    classify_launchd_query(
        output.status.success(),
        output.status.code(),
        &String::from_utf8_lossy(&output.stderr),
    )
}

#[cfg(target_os = "macos")]
fn unload_mac_job() -> Result<(), String> {
    if !mac_job_loaded()? {
        return Ok(());
    }
    let output = crate::system::command::output(
        "launchctl",
        ["bootout", &format!("system/{LAUNCHD_LABEL}")],
    )
    .map_err(|e| format!("launchctl bootout: {e}"))?;
    if !output.status.success() && mac_job_loaded()? {
        return Err(format!(
            "Не выгрузить DNS-службу: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    if mac_job_loaded()? {
        return Err("DNS-служба ещё зарегистрирована в launchd; повторите отключение".into());
    }
    Ok(())
}

#[cfg(test)]
mod launchd_tests {
    #[test]
    fn absent_job_is_idempotent_but_query_failure_blocks_cleanup() {
        assert_eq!(
            super::classify_launchd_query(false, Some(113), "Could not find service").unwrap(),
            false
        );
        assert_eq!(
            super::classify_launchd_query(true, Some(0), "").unwrap(),
            true
        );
        assert!(super::classify_launchd_query(false, Some(1), "Operation not permitted").is_err());
        assert!(super::classify_launchd_query(false, None, "").is_err());
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[test]
    fn task_xml_preserves_spaces_unicode_ampersands_and_quotes_in_paths() {
        let path = Path::new(r"D:\Данные & John's Apps\ag_dns.exe");
        let xml = windows_task_xml(path).replace('\'', "''");
        let script = format!("[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $ErrorActionPreference='Stop'; $task=[xml]'{xml}'; ConvertTo-Json -Compress -InputObject ([string]$task.Task.Actions.Exec.Command)");
        let out = crate::system::powershell::output(&script).unwrap();
        assert!(out.status.success(), "{out:?}");
        let command: String = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(command, format!("\"{}\"", path.display()));
    }

    #[test]
    fn task_query_distinguishes_absence_from_scheduler_failure() {
        use std::os::windows::process::ExitStatusExt;
        for (text, code, expected) in [
            ("", 0, Some(false)),
            (
                "\"\\other\\AntigravityBypassRussia\",\"N/A\",\"Ready\"",
                0,
                Some(false),
            ),
            (
                "\"\\AntigravityBypassRussia,other\",\"N/A\",\"Ready\"",
                0,
                Some(false),
            ),
            (
                "\"\\AntigravityBypassRussia\",\"Н/Д\",\"Выполняется\"",
                0,
                Some(true),
            ),
            (
                "\"\\ANTIGRAVITYBYPASSRUSSIA\",\"N/A\",\"Ready\"",
                0,
                Some(true),
            ),
            ("\"\\AntigravityBypassRussia\",\"N/A\",\"Ready\"", 1, None),
        ] {
            let result = registered_response(std::process::Output {
                status: std::process::ExitStatus::from_raw(code),
                stdout: text.as_bytes().to_vec(),
                stderr: b"scheduler query failed".to_vec(),
            });
            match expected {
                Some(value) => assert_eq!(result.unwrap(), value),
                None => assert!(result.unwrap_err().contains("scheduler query failed")),
            }
        }
    }
}

fn same_file_bytes(a: &Path, b: &Path) -> bool {
    let (Ok(meta_a), Ok(meta_b)) = (fs::metadata(a), fs::metadata(b)) else {
        return false;
    };
    if meta_a.len() != meta_b.len() {
        return false;
    }
    let (Ok(mut fa), Ok(mut fb)) = (File::open(a), File::open(b)) else {
        return false;
    };
    let mut buf_a = [0u8; 64 * 1024];
    let mut buf_b = [0u8; 64 * 1024];
    loop {
        let (Ok(n_a), Ok(n_b)) = (fa.read(&mut buf_a), fb.read(&mut buf_b)) else {
            return false;
        };
        if n_a != n_b || buf_a[..n_a] != buf_b[..n_b] {
            return false;
        }
        if n_a == 0 {
            return true;
        }
    }
}

fn xml_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(windows)]
fn registered_response(output: std::process::Output) -> Result<bool, String> {
    if !output.status.success() {
        return Err(format!(
            "Не удалось проверить задачу DNS-службы: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    // /FO CSV /NH always puts the full task path in the first quoted field.
    // Match the complete root task, including its closing quote and delimiter;
    // localized status/date fields and similarly named tasks are irrelevant.
    let prefix = format!("\"\\{TASK_NAME}\",");
    Ok(String::from_utf8_lossy(&output.stdout).lines().any(|line| {
        line.trim_start()
            .as_bytes()
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
    }))
}

pub fn registered_state() -> Result<bool, String> {
    #[cfg(windows)]
    {
        registered_response(
            crate::system::command::output("schtasks", ["/Query", "/FO", "CSV", "/NH"])
                .map_err(|e| format!("Проверка задачи DNS-службы: {e}"))?,
        )
    }
    #[cfg(target_os = "macos")]
    {
        if Path::new(LAUNCHD_PLIST).exists() {
            Ok(true)
        } else {
            mac_job_loaded()
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        Ok(linux_has_systemd() && Path::new(SYSTEMD_SERVICE).exists())
    }
}

pub fn running_state() -> Result<bool, String> {
    #[cfg(windows)]
    {
        let out = crate::system::command::output(
            "tasklist",
            [
                "/FI",
                &format!("IMAGENAME eq {}", EXE_NAME),
                "/FO",
                "CSV",
                "/NH",
            ],
        )
        .map_err(|e| format!("Проверка процесса DNS-службы: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "Не удалось проверить процесс DNS-службы ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).lines().any(|line| {
            line.split(',')
                .next()
                .unwrap_or("")
                .trim()
                .trim_matches('"')
                .eq_ignore_ascii_case(EXE_NAME)
        }))
    }
    #[cfg(target_os = "linux")]
    return linux_worker_pids().map(|pids| !pids.is_empty());
    #[cfg(target_os = "macos")]
    {
        #[cfg(target_os = "macos")]
        let args = vec!["-f".to_string(), format!("{} {}", EXE_NAME, FORWARDER_FLAG)];
        #[cfg(not(target_os = "macos"))]
        let args = vec![EXE_NAME.to_string()];
        let out = crate::system::command::output("pgrep", &args)
            .map_err(|e| format!("Проверка процесса DNS-службы: {e}"))?;
        match out.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(format!(
                "Не удалось проверить процесс DNS-службы: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )),
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_worker_pids() -> Result<Vec<i32>, String> {
    let mut pids = Vec::new();
    for entry in fs::read_dir("/proc").map_err(|e| e.to_string())?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
        else {
            continue;
        };
        let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        if stat
            .rsplit_once(") ")
            .is_some_and(|(_, rest)| rest.starts_with('Z'))
        {
            continue;
        }
        let executable = fs::read_link(entry.path().join("exe"));
        if executable
            .as_ref()
            .is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied)
            && stat.contains(&format!("({EXE_NAME}) "))
        {
            return Err("Не удалось проверить процесс DNS-службы; запустите проверку с правами администратора".into());
        }
        if executable.is_ok_and(|path| {
            path == installed_exe()
                || path.to_string_lossy() == format!("{} (deleted)", installed_exe().display())
        }) {
            pids.push(pid);
        }
    }
    Ok(pids)
}

fn stop_worker() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let pids = linux_worker_pids()?;
        for pid in &pids {
            if unsafe { libc::kill(*pid, libc::SIGTERM) } != 0
                && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while !linux_worker_pids()?.is_empty() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        for pid in linux_worker_pids()?.iter().filter(|pid| pids.contains(pid)) {
            if unsafe { libc::kill(*pid, libc::SIGKILL) } != 0
                && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    crate::system::process::stop_process_by_name(EXE_NAME);
    Ok(())
}

#[cfg(windows)]
fn windows_task_xml(dst: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Antigravity Bypass Russia DNS Forwarder (Local Relay)</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"{}"</Command>
      <Arguments>{}</Arguments>
    </Exec>
  </Actions>
</Task>"#,
        xml_text(&dst.to_string_lossy()),
        FORWARDER_FLAG
    )
}

// Prepare the complete replacement beside the destination before stopping the
// service. Closing the temporary file also permits Windows to rename it later.
fn prepare_service_binary(src: &Path, dst: &Path) -> Result<tempfile::TempPath, String> {
    let prepare = || -> std::io::Result<tempfile::TempPath> {
        let mut source = File::open(src)?;
        let parent = dst.parent().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "Нет каталога службы")
        })?;
        let mut staged = tempfile::Builder::new()
            .prefix("ag_dns-update-")
            .tempfile_in(parent)?;
        std::io::copy(&mut source, staged.as_file_mut())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            staged
                .as_file()
                .set_permissions(fs::Permissions::from_mode(0o755))?;
        }
        staged.as_file().sync_all()?;
        Ok(staged.into_temp_path())
    };
    prepare().map_err(|e| format!("Не удалось подготовить обновление DNS-службы: {e}"))
}

fn finish_prepared_service_binary(staged: &Path) -> Result<(), String> {
    crate::system::fs_utils::post_write_hook(staged)?;
    // FlushFileBuffers on Windows requires a writable handle.
    File::options()
        .write(true)
        .open(staged)
        .and_then(|file| file.sync_all())
        .map_err(|e| format!("Не удалось сохранить обновление DNS-службы: {e}"))
}

#[cfg(test)]
mod binary_update_tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn staged_service_signature_remains_valid_after_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let dst = temp.path().join(EXE_NAME);
        let staged = prepare_service_binary(&std::env::current_exe().unwrap(), &dst).unwrap();
        finish_prepared_service_binary(&staged).unwrap();
        fs::rename(&staged, &dst).unwrap();
        let verified = crate::system::command::output(
            "codesign",
            [
                std::ffi::OsStr::new("--verify"),
                std::ffi::OsStr::new("--strict"),
                dst.as_os_str(),
            ],
        )
        .unwrap();
        assert!(verified.status.success(), "{verified:?}");
    }

    #[test]
    fn failed_preparation_preserves_installed_binary_and_leaves_no_partial_copy() {
        let temp = tempfile::tempdir().unwrap();
        let dst = temp.path().join(EXE_NAME);
        fs::write(&dst, b"old service").unwrap();
        assert!(prepare_service_binary(&temp.path().join("missing"), &dst).is_err());
        // A directory can open on Unix but cannot be copied as a file.
        assert!(prepare_service_binary(temp.path(), &dst).is_err());
        assert_eq!(fs::read(&dst).unwrap(), b"old service");
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[test]
    fn replacement_is_staged_beside_destination_and_preserves_source() {
        let temp = tempfile::tempdir().unwrap();
        let src = temp.path().join("new binary");
        let dst = temp.path().join(EXE_NAME);
        fs::write(&src, b"new service").unwrap();
        fs::write(&dst, b"old service").unwrap();
        let staged = prepare_service_binary(&src, &dst).unwrap();
        #[cfg(windows)]
        finish_prepared_service_binary(&staged).unwrap();
        assert_eq!(staged.parent(), dst.parent());
        assert_eq!(fs::read(&dst).unwrap(), b"old service");
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let locked = fs::OpenOptions::new()
                .read(true)
                .share_mode(1)
                .open(&dst)
                .unwrap();
            assert!(fs::rename(&staged, &dst).is_err());
            assert_eq!(fs::read(&dst).unwrap(), b"old service");
            assert_eq!(fs::read(&staged).unwrap(), b"new service");
            drop(locked);
        }
        fs::rename(&staged, &dst).unwrap();
        drop(staged);
        assert_eq!(fs::read(&dst).unwrap(), b"new service");
        assert_eq!(fs::read(&src).unwrap(), b"new service");
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 2);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&dst).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
    }
}

pub fn enable() -> Result<(), String> {
    let dir = install_dir();
    fs::create_dir_all(&dir).map_err(|e| {
        format!(
            "Не удалось создать директорию службы {}: {}",
            dir.display(),
            e
        )
    })?;

    let src = std::env::current_exe()
        .map_err(|e| format!("Не удалось определить путь к текущему exe: {}", e))?;
    let dst = installed_exe();

    if !dst.exists() || !same_file_bytes(&src, &dst) {
        let staged = prepare_service_binary(&src, &dst)?;
        finish_prepared_service_binary(&staged)?;
        #[cfg(target_os = "windows")]
        {
            let _ = crate::system::command::output("schtasks", ["/End", "/TN", TASK_NAME]);
            let _ = crate::system::command::output("taskkill", ["/F", "/T", "/IM", EXE_NAME]);
        }
        #[cfg(target_os = "macos")]
        {
            unload_mac_job()?;
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            if linux_has_systemd() && Path::new(SYSTEMD_SERVICE).exists() {
                linux_systemctl(&["stop", SYSTEMD_LABEL])?;
            }
        }

        stop_worker()?;

        let mut copy_res = Err(std::io::Error::new(std::io::ErrorKind::Other, "init"));
        for attempt in 0..20 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            // Rename on the same filesystem replaces the old binary atomically.
            // A failed attempt keeps both the old binary and the staged copy.
            copy_res = fs::rename(&staged, &dst);
            if copy_res.is_ok() {
                break;
            }
            if attempt % 5 == 0 {
                #[cfg(target_os = "windows")]
                {
                    let _ = crate::system::command::output("schtasks", ["/End", "/TN", TASK_NAME]);
                    let _ =
                        crate::system::command::output("taskkill", ["/F", "/T", "/IM", EXE_NAME]);
                }
                stop_worker()?;
            }
        }

        copy_res.map_err(|e| {
            format!(
                "Не удалось заменить бинарник службы ({} -> {}): {}",
                src.display(),
                dst.display(),
                e
            )
        })?;
    }

    #[cfg(target_os = "windows")]
    {
        // A worker is a separate process: updating iface.conf/network-user.json
        // cannot invalidate its in-memory caches. Restart on every successful
        // setup, including when the executable bytes have not changed.
        stop_windows_worker()?;
        let task_xml = windows_task_xml(&dst);

        let xml_path = dir.join("task.xml");
        let mut file =
            File::create(&xml_path).map_err(|e| format!("Не удалось создать XML задачи: {}", e))?;
        use std::io::Write;
        file.write_all(&[0xFF, 0xFE]).map_err(|e| e.to_string())?;
        for unit in task_xml.encode_utf16() {
            file.write_all(&unit.to_le_bytes())
                .map_err(|e| e.to_string())?;
        }
        drop(file);

        // /Create /F updates an existing task; keep it registered if validation fails.
        let out = crate::system::command::output(
            "schtasks",
            [
                "/Create",
                "/TN",
                TASK_NAME,
                "/XML",
                &xml_path.to_string_lossy(),
                "/F",
            ],
        )
        .map_err(|e| format!("Не удалось запустить schtasks /Create: {}", e))?;

        let _ = fs::remove_file(&xml_path);
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            return Err(format!("schtasks /Create завершился ошибкой: {}", err));
        }

        let started = crate::system::command::output("schtasks", ["/Run", "/TN", TASK_NAME])
            .map_err(|e| format!("Запуск DNS-службы: {e}"))?;
        if !started.status.success() {
            return Err(format!(
                "Не запустить DNS-службу ({}): {} {}",
                started.status,
                String::from_utf8_lossy(&started.stderr).trim(),
                String::from_utf8_lossy(&started.stdout).trim()
            ));
        }
    }

    #[cfg(target_os = "macos")]
    {
        unload_mac_job()?;
        let plist_path = LAUNCHD_PLIST;
        let stderr_log = dir.join("stderr.log");
        let stdout_log = dir.join("stdout.log");
        let plist_content = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>{}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
        <key>Crashed</key>
        <true/>
    </dict>
    <key>ProcessType</key>
    <string>Background</string>
    <key>Nice</key>
    <integer>10</integer>
    <key>LowPriorityIO</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>30</integer>
    <key>StandardErrorPath</key>
    <string>{}</string>
    <key>StandardOutPath</key>
    <string>{}</string>
</dict>
</plist>"#,
            LAUNCHD_LABEL,
            xml_text(&dst.to_string_lossy()),
            FORWARDER_FLAG,
            xml_text(&stderr_log.to_string_lossy()),
            xml_text(&stdout_log.to_string_lossy())
        );

        crate::system::fs_utils::robust_write_file(Path::new(plist_path), plist_content.as_bytes())
            .map_err(|e| format!("Не удалось записать plist демона: {}", e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(plist_path, fs::Permissions::from_mode(0o644))
                .map_err(|e| e.to_string())?;
            use std::os::fd::AsRawFd;
            let file = File::open(plist_path).map_err(|e| e.to_string())?;
            if unsafe { libc::fchown(file.as_raw_fd(), 0, 0) } != 0 {
                return Err(format!(
                    "Владелец plist: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }

        let out = crate::system::command::output("launchctl", ["bootstrap", "system", plist_path]);
        if out.map(|o| !o.status.success()).unwrap_or(true) {
            let fallback = crate::system::command::output("launchctl", ["load", "-w", plist_path])
                .map_err(|e| format!("launchctl load failed: {}", e))?;
            if !fallback.status.success() {
                return Err("Не удалось загрузить LaunchDaemon через launchctl".to_string());
            }
        }
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let unit_content = format!(
            "[Unit]\n\
            Description=Antigravity Bypass Russia DNS Forwarder\n\
            After=network.target\n\n\
            [Service]\n\
            Type=simple\n\
            ExecStart={} {}\n\
            ExecStartPost={} --linux-dns-apply\n\
            Restart=on-failure\n\
            RestartSec=5\n\n\
            [Install]\n\
            WantedBy=multi-user.target\n",
            dst.display(),
            FORWARDER_FLAG,
            dst.display()
        );

        if linux_has_systemd() {
            crate::system::fs_utils::robust_write_file(
                Path::new(SYSTEMD_SERVICE),
                unit_content.as_bytes(),
            )
            .map_err(|e| e.to_string())?;
            linux_systemctl(&["daemon-reload"])?;
            linux_systemctl(&["enable", SYSTEMD_LABEL])?;
            linux_systemctl(&["restart", SYSTEMD_LABEL])?;
        } else {
            stop_worker()?;
            linux_spawn_worker()?;
        }
    }

    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn linux_has_systemd() -> bool {
    Path::new("/run/systemd/system").is_dir()
}

#[cfg(all(unix, not(target_os = "macos")))]
fn linux_systemctl(args: &[&str]) -> Result<(), String> {
    let out =
        crate::system::command::output("systemctl", args).map_err(|e| format!("systemctl: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "systemctl {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn linux_spawn_worker() -> Result<(), String> {
    use std::os::unix::process::CommandExt;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while running_state()? {
        if std::time::Instant::now() >= deadline {
            return Err("Прежний DNS-процесс ещё работает; повторный запуск отменён".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    std::process::Command::new(installed_exe())
        .arg(FORWARDER_FLAG)
        .process_group(0)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("Запуск DNS-службы: {e}"))?;
    if !crate::net::wait_for_ready(std::time::Duration::from_secs(4), crate::net::relay_ready) {
        return Err("DNS-служба Linux не подтвердила готовность; DNS не переключён".into());
    }
    Ok(())
}

#[cfg(windows)]
fn stop_windows_worker() -> Result<(), String> {
    let _ = crate::system::command::output("schtasks", ["/End", "/TN", TASK_NAME]);
    if running_state()? {
        stop_worker()?;
    }
    for _ in 0..20 {
        if !running_state()? {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err("Прежняя DNS-служба ещё работает; повторный запуск отменён".into())
}

pub fn start() -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let out = crate::system::command::output("schtasks", ["/Run", "/TN", TASK_NAME])
            .map_err(|e| format!("Ошибка запуска службы: {}", e))?;
        if out.status.success() {
            for _ in 0..10 {
                std::thread::sleep(std::time::Duration::from_millis(50));
                if running_state()? {
                    return Ok(());
                }
            }
        }
        Err("Служба не перешла в состояние выполнения".to_string())
    }
    #[cfg(target_os = "macos")]
    {
        let out = crate::system::command::output("launchctl", ["start", LAUNCHD_LABEL])
            .map_err(|e| format!("Ошибка launchctl: {}", e))?;
        if out.status.success() {
            Ok(())
        } else {
            Err("launchctl start failed".to_string())
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if linux_has_systemd() {
            linux_systemctl(&["start", SYSTEMD_LABEL])
        } else if running_state()? {
            Ok(())
        } else {
            linux_spawn_worker()
        }
    }
}

pub fn disable() -> Result<(), String> {
    // Unknown state must not authorize removal of the service or DNS settings.
    registered_state()?;
    running_state()?;
    #[cfg(target_os = "windows")]
    {
        let _ = crate::system::command::output("schtasks", ["/End", "/TN", TASK_NAME]);
        let _ = crate::system::command::output("schtasks", ["/Delete", "/TN", TASK_NAME, "/F"]);
        let _ = crate::system::command::output("taskkill", ["/F", "/T", "/IM", EXE_NAME]);
    }
    #[cfg(target_os = "macos")]
    {
        unload_mac_job()?;
        if Path::new(LAUNCHD_PLIST).exists() {
            fs::remove_file(LAUNCHD_PLIST).map_err(|e| format!("Удаление plist: {e}"))?;
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if linux_has_systemd() && Path::new(SYSTEMD_SERVICE).exists() {
            linux_systemctl(&["stop", SYSTEMD_LABEL])?;
            linux_systemctl(&["disable", SYSTEMD_LABEL])?;
        }
        if Path::new(SYSTEMD_SERVICE).exists() {
            fs::remove_file(SYSTEMD_SERVICE).map_err(|e| e.to_string())?;
            if linux_has_systemd() {
                linux_systemctl(&["daemon-reload"])?;
            }
        }
    }

    stop_worker()?;

    for _ in 0..20 {
        if !running_state()? {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if running_state()? || registered_state()? {
        return Err(
            "Служба ещё активна; восстановление сетевых файлов отменено до её остановки".into(),
        );
    }

    // Keep state/backups until their owners have verified restoration. Never delete this tree.
    let installed = installed_exe();
    if std::env::current_exe().ok().as_ref() != Some(&installed) && installed.exists() {
        fs::remove_file(&installed).map_err(|e| format!("Не удалить бинарник службы: {e}"))?;
    }
    Ok(())
}
