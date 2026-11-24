use std::io::{self, IsTerminal, Write};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

enum ProgressLine {
    Working(String),
    Detail(String),
    Stage { running: String, done: String },
    Finish(bool),
}

/// Numbers the steps of one operation: "2/5 ". Without a total, steps are
/// shown without numbers.
pub struct Steps {
    total: usize,
    next: std::cell::Cell<usize>,
}

impl Steps {
    pub fn new(total: usize) -> Self {
        Self {
            total,
            next: std::cell::Cell::new(0),
        }
    }

    pub fn unnumbered() -> Self {
        Self::new(0)
    }

    fn prefix(&self) -> String {
        if self.total == 0 {
            return String::new();
        }
        let number = (self.next.get() + 1).min(self.total);
        self.next.set(number);
        format!("{number}/{} ", self.total)
    }
}

/// A spinner line. In step mode (`stage`) every finished step stays on screen
/// as one line with ✓ or ✗, the current activity is shown in grey next to the
/// running step, and technical details are left to the log.
pub struct Progress(Option<(mpsc::Sender<ProgressLine>, thread::JoinHandle<()>)>);

impl Progress {
    pub fn new() -> Self {
        Self(io::stdout().is_terminal().then(|| {
            let (sender, lines) = mpsc::channel();
            let worker = thread::spawn(move || animate_progress(lines));
            (sender, worker)
        }))
    }

    pub fn working(&self, text: &str) {
        if let Some((worker, _)) = &self.0 {
            let _ = worker.send(ProgressLine::Working(text.to_owned()));
        } else {
            println!("    … {text}");
        }
    }

    pub fn detail(&self, text: &str) {
        if let Some((worker, _)) = &self.0 {
            let _ = worker.send(ProgressLine::Detail(text.to_owned()));
        } else {
            println!("    {text}");
        }
    }

    /// Completes the previous step successfully and starts the next one.
    pub fn stage(&self, steps: &Steps, running: &str, done: &str) {
        let prefix = steps.prefix();
        let (running, done) = (format!("{prefix}{running}"), format!("{prefix}{done}"));
        if let Some((worker, _)) = &self.0 {
            let _ = worker.send(ProgressLine::Stage { running, done });
        } else {
            println!("  {running}…");
        }
    }

    /// Marks the current step ✓ or ✗.
    pub fn finish(&self, ok: bool) {
        if let Some((worker, _)) = &self.0 {
            let _ = worker.send(ProgressLine::Finish(ok));
        } else {
            println!(
                "  {}",
                if ok {
                    "✓ готово"
                } else {
                    "✗ не удалось"
                }
            );
        }
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        if let Some((sender, worker)) = self.0.take() {
            drop(sender);
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{fit, Steps};

    #[test]
    fn steps_are_numbered_and_lines_fit_without_wrapping() {
        let steps = Steps::new(3);
        assert_eq!(
            [
                steps.prefix(),
                steps.prefix(),
                steps.prefix(),
                steps.prefix()
            ],
            ["1/3 ", "2/3 ", "3/3 ", "3/3 "]
        );
        assert_eq!(Steps::unnumbered().prefix(), "");
        assert_eq!(fit("Связь", 10), "Связь");
        let short = fit("проверяем связь 3/4: сервер Gemini", 12);
        assert_eq!(short.chars().count(), 12);
        assert!(short.ends_with('…'));
    }
}

struct RunningStage {
    running: String,
    done: String,
    started: Instant,
}

/// Visible characters on the spinner line; a wrapped line could not be
/// redrawn in place.
const LINE_LIMIT: usize = 76;

fn fit(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_owned();
    }
    let mut short: String = text.chars().take(limit.saturating_sub(1)).collect();
    short.push('…');
    short
}

fn print_stage_result(stage: &RunningStage, ok: bool) {
    let seconds = stage.started.elapsed().as_secs();
    let (mark, colour) = if ok {
        ("✓", "\x1b[92m")
    } else {
        ("✗", "\x1b[91m")
    };
    let time = if seconds > 0 {
        format!("  \x1b[90m{seconds} с\x1b[0m")
    } else {
        String::new()
    };
    println!("\r\x1b[2K  {colour}{mark}\x1b[0m {}{time}", stage.done);
}

fn animate_progress(lines: mpsc::Receiver<ProgressLine>) {
    const FRAMES: [char; 8] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧'];
    let mut stage: Option<RunningStage> = None;
    let mut activity: Option<(String, Instant)> = None;
    let tick = Duration::from_millis(100);
    let started = Instant::now();
    loop {
        match lines.recv_timeout(tick) {
            Ok(ProgressLine::Working(text)) => activity = Some((text, Instant::now())),
            Ok(ProgressLine::Detail(text)) => {
                if stage.is_none() {
                    activity = None;
                    println!("\r\x1b[2K    {text}");
                }
            }
            Ok(ProgressLine::Stage { running, done }) => {
                if let Some(previous) = stage.take() {
                    print_stage_result(&previous, true);
                }
                activity = None;
                stage = Some(RunningStage {
                    running,
                    done,
                    started: Instant::now(),
                });
            }
            Ok(ProgressLine::Finish(ok)) => {
                if let Some(current) = stage.take() {
                    print_stage_result(&current, ok);
                }
                activity = None;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                print!("\r\x1b[2K");
                let _ = io::stdout().flush();
                break;
            }
        }
        let frame =
            FRAMES[(started.elapsed().as_millis() / tick.as_millis()) as usize % FRAMES.len()];
        let line = match (&stage, &activity) {
            (Some(stage), activity) => {
                let seconds = stage.started.elapsed().as_secs();
                let time = format!("  {seconds} с");
                let time_width = time.chars().count();
                let title = fit(&stage.running, LINE_LIMIT - time_width);
                let room = LINE_LIMIT.saturating_sub(title.chars().count() + time_width + 3);
                let note = match activity {
                    Some((text, _)) if room > 8 => format!(" \x1b[90m· {}\x1b[0m", fit(text, room)),
                    _ => String::new(),
                };
                Some(format!("{title}{note}\x1b[90m{time}\x1b[0m"))
            }
            (None, Some((text, since))) => Some(format!(
                "{}  \x1b[90m{} с\x1b[0m",
                fit(text, LINE_LIMIT - 8),
                since.elapsed().as_secs()
            )),
            (None, None) => None,
        };
        if let Some(line) = line {
            print!("\r\x1b[2K  \x1b[96m{frame}\x1b[0m {line}");
            let _ = io::stdout().flush();
        }
    }
}

pub fn init_terminal() {
    #[cfg(target_os = "windows")]
    {
        #[link(name = "kernel32")]
        extern "system" {
            fn SetConsoleOutputCP(wCodePageID: u32) -> i32;
            fn SetConsoleCP(wCodePageID: u32) -> i32;
            fn GetStdHandle(nStdHandle: i32) -> *mut std::ffi::c_void;
            fn GetConsoleMode(hConsoleHandle: *mut std::ffi::c_void, lpMode: *mut u32) -> i32;
            fn SetConsoleMode(hConsoleHandle: *mut std::ffi::c_void, dwMode: u32) -> i32;
        }

        const STD_OUTPUT_HANDLE: i32 = -11;
        const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;

        unsafe {
            SetConsoleOutputCP(65001);
            SetConsoleCP(65001);
            let handle = GetStdHandle(STD_OUTPUT_HANDLE);
            let mut mode: u32 = 0;
            if GetConsoleMode(handle, &mut mode) != 0 {
                SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
    }
}

pub fn clear_screen() {
    print!("\x1b[3J\x1b[2J\x1b[1;1H");
    let _ = io::stdout().flush();
}

pub fn prompt(text: &str) -> String {
    print!("{}", text);
    let _ = io::stdout().flush();
    let mut buf = String::new();
    match io::stdin().read_line(&mut buf) {
        Ok(0) => {
            // EOF (Ctrl+D) detected, exit cleanly
            println!("\n\x1b[92m[✓] Завершение работы.\x1b[0m");
            std::process::exit(0);
        }
        Ok(_) => buf.trim().to_string(),
        Err(error) => {
            eprintln!("Не удалось прочитать ввод: {error}");
            std::process::exit(1);
        }
    }
}

pub fn pause() {
    if crate::system::env::args().len() > 1 {
        return;
    }
    println!();
    prompt("Нажмите Enter для продолжения...");
}
