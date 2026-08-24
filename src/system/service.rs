#![allow(dead_code)]

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use crate::system::process::no_window;

pub const FORWARDER_FLAG: &str = "--dns-forwarder";
pub const TASK_NAME: &str = "AntigravityBypassRussia";
pub const LAUNCHD_LABEL: &str = "com.antigravity.bypass.russia";
pub const LAUNCHD_PLIST: &str = "/Library/LaunchDaemons/com.antigravity.bypass.russia.plist";
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

fn same_file_bytes(a: &Path, b: &Path) -> bool {
    let (Ok(meta_a), Ok(meta_b)) = (fs::metadata(a), fs::metadata(b)) else { return false };
    if meta_a.len() != meta_b.len() {
        return false;
    }
    let (Ok(mut fa), Ok(mut fb)) = (File::open(a), File::open(b)) else { return false };
    let mut buf_a = [0u8; 64 * 1024];
    let mut buf_b = [0u8; 64 * 1024];
    loop {
        let n_a = fa.read(&mut buf_a).unwrap_or(0);
        let n_b = fb.read(&mut buf_b).unwrap_or(0);
        if n_a != n_b || buf_a[..n_a] != buf_b[..n_b] {
            return false;
        }
        if n_a == 0 {
            return true;
        }
    }
}

pub fn is_enabled() -> bool {
    #[cfg(target_os = "windows")]
    {
        let out = no_window(&mut Command::new("schtasks"))
            .args(["/Query", "/TN", TASK_NAME])
            .output();
        out.map(|o| o.status.success()).unwrap_or(false)
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from(LAUNCHD_PLIST).exists()
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    false
}

pub fn is_running() -> bool {
    #[cfg(target_os = "windows")]
    {
        let out = no_window(&mut Command::new("tasklist"))
            .args(["/FI", &format!("IMAGENAME eq {}", EXE_NAME)])
            .output();
        if let Ok(o) = out {
            let s = String::from_utf8_lossy(&o.stdout);
            return s.contains(EXE_NAME);
        }
        false
    }
    #[cfg(target_os = "macos")]
    {
        let out = Command::new("pgrep")
            .args(["-f", &format!("{} {}", EXE_NAME, FORWARDER_FLAG)])
            .output();
        out.map(|o| o.status.success()).unwrap_or(false)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let out = Command::new("pgrep").arg(EXE_NAME).output();
        out.map(|o| o.status.success()).unwrap_or(false)
    }
}

pub fn enable() -> Result<(), String> {
    let dir = install_dir();
    fs::create_dir_all(&dir)
        .map_err(|e| format!("Не удалось создать директорию службы {}: {}", dir.display(), e))?;

    let src = std::env::current_exe()
        .map_err(|e| format!("Не удалось определить путь к текущему exe: {}", e))?;
    let dst = installed_exe();

    if !dst.exists() || !same_file_bytes(&src, &dst) {
        #[cfg(target_os = "windows")]
        {
            let _ = no_window(&mut Command::new("schtasks"))
                .args(["/End", "/TN", TASK_NAME])
                .output();
            let _ = no_window(&mut Command::new("taskkill"))
                .args(["/F", "/T", "/IM", EXE_NAME])
                .output();
        }
        #[cfg(target_os = "macos")]
        {
            let _ = Command::new("launchctl").args(["bootout", &format!("system/{}", LAUNCHD_LABEL)]).output();
            let _ = Command::new("launchctl").args(["unload", "-w", LAUNCHD_PLIST]).output();
        }

        crate::system::process::stop_process_by_name(EXE_NAME);

        let mut copy_res = Err(std::io::Error::new(std::io::ErrorKind::Other, "init"));
        for attempt in 0..20 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            let _ = fs::remove_file(&dst);
            copy_res = fs::copy(&src, &dst);
            if copy_res.is_ok() {
                break;
            }
            if attempt % 5 == 0 {
                #[cfg(target_os = "windows")]
                {
                    let _ = no_window(&mut Command::new("schtasks")).args(["/End", "/TN", TASK_NAME]).output();
                    let _ = no_window(&mut Command::new("taskkill")).args(["/F", "/T", "/IM", EXE_NAME]).output();
                }
                crate::system::process::stop_process_by_name(EXE_NAME);
            }
        }

        copy_res.map_err(|e| {
            format!(
                "Не удалось скопировать бинарник службы ({} -> {}): {}",
                src.display(),
                dst.display(),
                e
            )
        })?;
        crate::system::fs_utils::post_write_hook(&dst);
    }

    #[cfg(target_os = "windows")]
    {
        let task_xml = format!(
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
            dst.display(),
            FORWARDER_FLAG
        );

        let xml_path = dir.join("task.xml");
        let mut file = File::create(&xml_path)
            .map_err(|e| format!("Не удалось создать XML задачи: {}", e))?;
        use std::io::Write;
        file.write_all(&[0xFF, 0xFE]).map_err(|e| e.to_string())?;
        for unit in task_xml.encode_utf16() {
            file.write_all(&unit.to_le_bytes()).map_err(|e| e.to_string())?;
        }
        drop(file);

        let _ = no_window(&mut Command::new("schtasks"))
            .args(["/Delete", "/TN", TASK_NAME, "/F"])
            .output();

        let out = no_window(&mut Command::new("schtasks"))
            .args([
                "/Create",
                "/TN",
                TASK_NAME,
                "/XML",
                &xml_path.to_string_lossy(),
                "/F",
            ])
            .output()
            .map_err(|e| format!("Не удалось запустить schtasks /Create: {}", e))?;

        let _ = fs::remove_file(&xml_path);
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            return Err(format!("schtasks /Create завершился ошибкой: {}", err));
        }

        let _ = no_window(&mut Command::new("schtasks"))
            .args(["/Run", "/TN", TASK_NAME])
            .output();
    }

    #[cfg(target_os = "macos")]
    {
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
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>StandardErrorPath</key>
    <string>{}</string>
    <key>StandardOutPath</key>
    <string>{}</string>
</dict>
</plist>"#,
            LAUNCHD_LABEL,
            dst.display(),
            FORWARDER_FLAG,
            stderr_log.display(),
            stdout_log.display()
        );

        fs::write(plist_path, plist_content)
            .map_err(|e| format!("Не удалось записать plist демона: {}", e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(plist_path, fs::Permissions::from_mode(0o644));
        }

        let _ = Command::new("launchctl").args(["bootout", &format!("system/{}", LAUNCHD_LABEL)]).output();
        let _ = Command::new("launchctl").args(["unload", plist_path]).output();

        let out = Command::new("launchctl").args(["bootstrap", "system", plist_path]).output();
        if out.map(|o| !o.status.success()).unwrap_or(true) {
            let fallback = Command::new("launchctl").args(["load", "-w", plist_path]).output()
                .map_err(|e| format!("launchctl load failed: {}", e))?;
            if !fallback.status.success() {
                return Err("Не удалось загрузить LaunchDaemon через launchctl".to_string());
            }
        }
    }

    Ok(())
}

pub fn disable() -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let _ = no_window(&mut Command::new("schtasks"))
            .args(["/End", "/TN", TASK_NAME])
            .output();
        let _ = no_window(&mut Command::new("schtasks"))
            .args(["/Delete", "/TN", TASK_NAME, "/F"])
            .output();
        let _ = no_window(&mut Command::new("taskkill"))
            .args(["/F", "/T", "/IM", EXE_NAME])
            .output();
    }
    #[cfg(target_os = "macos")]
    {
        if Path::new(LAUNCHD_PLIST).exists() {
            let _ = Command::new("launchctl").args(["bootout", &format!("system/{}", LAUNCHD_LABEL)]).output();
            let _ = Command::new("launchctl").args(["unload", "-w", LAUNCHD_PLIST]).output();
            let _ = fs::remove_file(LAUNCHD_PLIST);
        }
    }

    crate::system::process::stop_process_by_name(EXE_NAME);

    let dir = install_dir();
    let current_exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(|p| p.to_path_buf()));
    if dir.exists() && Some(&dir) != current_exe_dir.as_ref() {
        for _ in 0..10 {
            std::thread::sleep(std::time::Duration::from_millis(50));
            let _ = fs::remove_file(installed_exe());
            if fs::remove_dir_all(&dir).is_ok() || !dir.exists() {
                break;
            }
        }
    }
    Ok(())
}
