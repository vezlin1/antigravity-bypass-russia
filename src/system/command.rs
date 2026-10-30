//! Run OS utilities from their system locations, with bounded waits and output.
use std::{
    ffi::OsStr,
    io::{self, Read, Seek, SeekFrom},
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

const OUTPUT_LIMIT: u64 = 4 * 1024 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

#[cfg(windows)]
fn windows_directory() -> io::Result<PathBuf> {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt};
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
    let mut buffer = vec![0u16; 260];
    loop {
        let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
        if length == 0 {
            return Err(io::Error::last_os_error());
        }
        if (length as usize) < buffer.len() {
            return Ok(OsString::from_wide(&buffer[..length as usize]).into());
        }
        if length > 32768 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Некорректный системный путь Windows",
            ));
        }
        buffer.resize(length as usize, 0);
    }
}

pub fn executable(program: &str) -> io::Result<PathBuf> {
    #[cfg(windows)]
    {
        let path = windows_directory()?.join(match program {
            "powershell" => r"WindowsPowerShell\v1.0\powershell.exe",
            "netsh" => "netsh.exe",
            "ipconfig" => "ipconfig.exe",
            "schtasks" => "schtasks.exe",
            "tasklist" => "tasklist.exe",
            "taskkill" => "taskkill.exe",
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Неизвестная системная команда",
                ))
            }
        });
        return match path.metadata() {
            Ok(metadata) if metadata.is_file() => Ok(path),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "Системная команда {program}: {} не является файлом",
                    path.display()
                ),
            )),
            Err(error) => Err(io::Error::new(
                error.kind(),
                format!(
                    "Системная команда {program} недоступна по пути {}: {error}",
                    path.display()
                ),
            )),
        };
    }
    #[cfg(unix)]
    {
        let candidates: &[&str] = match program {
            "launchctl" => &["/bin/launchctl"],
            "route" => &["/sbin/route", "/usr/sbin/route"],
            "sysctl" => &[
                "/sbin/sysctl",
                "/usr/sbin/sysctl",
                "/bin/sysctl",
                "/usr/bin/sysctl",
            ],
            "lsof" => &["/usr/sbin/lsof", "/usr/bin/lsof"],
            "scutil" => &["/usr/sbin/scutil"],
            "codesign" => &["/usr/bin/codesign"],
            "xattr" => &["/usr/bin/xattr"],
            "pgrep" => &["/usr/bin/pgrep", "/bin/pgrep"],
            "pkill" => &["/usr/bin/pkill", "/bin/pkill"],
            "killall" => &["/usr/bin/killall", "/bin/killall"],
            "dscacheutil" => &["/usr/bin/dscacheutil"],
            "stat" => &["/usr/bin/stat", "/bin/stat"],
            "uname" => &["/usr/bin/uname", "/bin/uname"],
            "systemctl" => &["/bin/systemctl", "/usr/bin/systemctl"],
            "ip" => &["/sbin/ip", "/usr/sbin/ip", "/bin/ip", "/usr/bin/ip"],
            "resolvectl" => &["/usr/bin/resolvectl", "/bin/resolvectl"],
            "systemd-resolve" => &["/usr/bin/systemd-resolve", "/bin/systemd-resolve"],
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Неизвестная системная команда",
                ))
            }
        };
        for &cand in candidates {
            let p = PathBuf::from(cand);
            if let Ok(metadata) = p.metadata() {
                if metadata.is_file() {
                    return Ok(p);
                }
            }
        }
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Системная команда {program} недоступна в системных путях"),
        ));
    }
}

pub fn output<I, S>(program: &str, args: I) -> io::Result<Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = Command::new(executable(program)?);
    command.args(args);
    capture(&mut command, COMMAND_TIMEOUT)
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn capture(command: &mut Command, budget: Duration) -> io::Result<Output> {
    // Temporary files avoid stdout/stderr pipe deadlocks and reader threads
    // retained by a grandchild after a timeout.
    let mut stdout = tempfile::tempfile()?;
    let mut stderr = tempfile::tempfile()?;
    let mut child = ChildGuard(
        super::process::no_window(command)
            .stdin(Stdio::null())
            .stdout(stdout.try_clone()?)
            .stderr(stderr.try_clone()?)
            .spawn()?,
    );
    let started = Instant::now();
    let status = loop {
        if stdout.metadata()?.len() > OUTPUT_LIMIT || stderr.metadata()?.len() > OUTPUT_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Системная команда вернула слишком большой ответ",
            ));
        }
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        if started.elapsed() >= budget {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "Системная команда {} не завершилась за {} с",
                    command.get_program().to_string_lossy(),
                    budget.as_secs_f32()
                ),
            ));
        }
        std::thread::sleep(Duration::from_millis(20).min(budget.saturating_sub(started.elapsed())));
    };
    fn read(file: &mut std::fs::File) -> io::Result<Vec<u8>> {
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        file.take(OUTPUT_LIMIT + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > OUTPUT_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Слишком большой ответ системной команды",
            ));
        }
        Ok(bytes)
    }
    Ok(Output {
        status,
        stdout: read(&mut stdout)?,
        stderr: read(&mut stderr)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn fixture(mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "system::command::tests::subprocess_fixture",
                "--ignored",
                "--nocapture",
            ])
            .env("ABR_TEST_SYSTEM_COMMAND", mode);
        command
    }

    #[test]
    #[ignore = "launched only by isolated command regression tests"]
    fn subprocess_fixture() {
        match std::env::var("ABR_TEST_SYSTEM_COMMAND").unwrap().as_str() {
            "output" => {
                for _ in 0..64 {
                    std::io::stdout().write_all(&[b'A'; 16384]).unwrap();
                    std::io::stderr().write_all(&[b'B'; 16384]).unwrap();
                }
                std::process::exit(23);
            }
            "excessive" => {
                for _ in 0..512 {
                    std::io::stdout().write_all(&[b'A'; 16384]).unwrap();
                }
            }
            "hang" => std::thread::sleep(Duration::from_secs(60)),
            "environment" => {
                #[cfg(windows)]
                let commands = [
                    "powershell",
                    "netsh",
                    "ipconfig",
                    "schtasks",
                    "tasklist",
                    "taskkill",
                ];
                #[cfg(target_os = "macos")]
                let commands = [
                    "launchctl",
                    "route",
                    "sysctl",
                    "lsof",
                    "scutil",
                    "codesign",
                    "xattr",
                    "pgrep",
                    "killall",
                    "dscacheutil",
                    "stat",
                ];
                #[cfg(target_os = "linux")]
                let commands = ["sysctl", "pgrep", "stat"];
                #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
                let commands: [&str; 0] = [];
                for program in commands {
                    let path = executable(program).unwrap();
                    assert!(path.is_absolute());
                    assert!(!path.starts_with(std::env::current_dir().unwrap()));
                }
                #[cfg(windows)]
                for (program, args) in [
                    ("netsh", vec!["int", "tcp", "dump"]),
                    ("ipconfig", vec!["/?"]),
                    ("schtasks", vec!["/Query", "/FO", "CSV", "/NH"]),
                    (
                        "tasklist",
                        vec!["/FI", "IMAGENAME eq ag_dns.exe", "/FO", "CSV", "/NH"],
                    ),
                    ("taskkill", vec!["/?"]),
                ] {
                    let out = output(program, args).unwrap();
                    if program == "ipconfig" {
                        // ipconfig /? prints help but returns 1 on some Windows builds.
                        assert!(String::from_utf8_lossy(&out.stdout).contains("ipconfig"));
                    } else {
                        assert!(out.status.success(), "{program}: {}", out.status);
                    }
                }
                #[cfg(target_os = "macos")]
                for (program, args) in [
                    ("stat", vec!["-f", "%Su", "/dev/console"]),
                    ("sysctl", vec!["-n", "kern.ostype"]),
                    ("launchctl", vec!["help"]),
                ] {
                    let out = output(program, args).unwrap();
                    assert!(out.status.success(), "{program}: {out:?}");
                }
            }
            mode => panic!("unknown fixture: {mode}"),
        }
    }

    #[test]
    fn large_stdout_and_stderr_do_not_deadlock_and_exit_code_is_preserved() {
        let out = capture(&mut fixture("output"), Duration::from_secs(15)).unwrap();
        assert_eq!(out.status.code(), Some(23));
        assert_eq!(
            out.stdout.iter().filter(|b| **b == b'A').count(),
            1024 * 1024
        );
        assert_eq!(
            out.stderr.iter().filter(|b| **b == b'B').count(),
            1024 * 1024
        );
    }

    #[test]
    fn stalled_and_excessive_commands_fail_with_bounded_waits() {
        let started = Instant::now();
        let error = capture(&mut fixture("hang"), Duration::from_secs(2)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(15));
        let error = capture(&mut fixture("excessive"), Duration::from_secs(15)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn system_utilities_work_without_path_and_ignore_local_namesakes() {
        for shadow in [false, true] {
            let directory = tempfile::Builder::new()
                .prefix("system command путь ")
                .tempdir()
                .unwrap();
            for name in [
                "netsh.exe",
                "ipconfig.exe",
                "schtasks.exe",
                "tasklist.exe",
                "taskkill.exe",
                "powershell.exe",
                "stat",
                "sysctl",
                "launchctl",
            ] {
                std::fs::write(directory.path().join(name), b"invalid executable").unwrap();
            }
            let mut command = fixture("environment");
            command.current_dir(directory.path()).env(
                "PATH",
                if shadow {
                    directory.path().as_os_str()
                } else {
                    OsStr::new("")
                },
            );
            let out = capture(&mut command, Duration::from_secs(60)).unwrap();
            assert!(out.status.success(), "{out:?}");
        }
    }
}
