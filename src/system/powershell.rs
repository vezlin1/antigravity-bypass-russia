//! Windows PowerShell is a system dependency; resolve it independently of PATH.
use std::{io, path::PathBuf, process::Output};

pub fn executable() -> io::Result<PathBuf> {
    super::command::executable("powershell").map_err(|error| io::Error::new(error.kind(), format!("Windows PowerShell недоступен: {error}. Проверьте наличие и доступность этого компонента Windows.")))
}

#[cfg(test)]
pub fn command() -> io::Result<std::process::Command> {
    let mut command = std::process::Command::new(executable()?);
    super::process::no_window(&mut command);
    Ok(command)
}

pub fn output(script: &str) -> io::Result<Output> {
    super::command::output(
        "powershell",
        ["-NoProfile", "-NonInteractive", "-Command", script],
    )
}

#[cfg(test)]
mod tests {
    /// Issue #6: PowerShell is found without PATH, and a `powershell.exe` placed
    /// in PATH or in the working directory is never started.
    #[test]
    fn executable_is_resolved_without_path_and_ignores_shadow_powershell() {
        use super::super::process::no_window;
        use std::{
            process::Command,
            time::{Duration, Instant},
        };

        const CHILD: &str = "ABR_TEST_POWERSHELL_ENVIRONMENT";
        if let Ok(mode) = std::env::var(CHILD) {
            if mode != "shadow" {
                // Reproduce issue #6 in an isolated process. Setting PATH on
                // only the PowerShell child leaves Rust's parent-PATH fallback.
                let error = no_window(&mut Command::new("powershell.exe"))
                    .args(["-NoProfile", "-NonInteractive", "-Command", "exit 0"])
                    .output()
                    .unwrap_err();
                assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
                assert_eq!(error.to_string(), "program not found");
            }
            let executable = super::executable().unwrap();
            assert!(executable.is_absolute());
            assert!(!executable.starts_with(std::env::current_dir().unwrap()));
            assert!(super::output("exit 0").unwrap().status.success());
            return;
        }

        for mode in ["empty", "unset", "shadow"] {
            let directory = tempfile::Builder::new()
                .prefix("powershell путь ")
                .tempdir()
                .unwrap();
            if mode == "shadow" {
                std::fs::write(
                    directory.path().join("powershell.exe"),
                    b"not an executable",
                )
                .unwrap();
            }
            let mut cmd = Command::new(std::env::current_exe().unwrap());
            no_window(&mut cmd);
            cmd.args(["--exact", "system::powershell::tests::executable_is_resolved_without_path_and_ignores_shadow_powershell", "--nocapture"])
                .env(CHILD, mode).current_dir(directory.path());
            match mode {
                "unset" => {
                    cmd.env_remove("PATH");
                }
                "shadow" => {
                    cmd.env("PATH", directory.path());
                }
                _ => {
                    cmd.env("PATH", "");
                }
            }
            let mut child = cmd.spawn().unwrap();
            let started = Instant::now();
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success(), "{mode}: {status}");
                    break;
                }
                if started.elapsed() > Duration::from_secs(30) {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("{mode}: PowerShell query timed out");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}
