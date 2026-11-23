use std::io::{self, IsTerminal, Write};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

enum ProgressLine {
    Working(String),
    Detail(String),
}

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
            println!("  … {text}");
        }
    }

    pub fn detail(&self, text: &str) {
        if let Some((worker, _)) = &self.0 {
            let _ = worker.send(ProgressLine::Detail(text.to_owned()));
        } else {
            println!("    {text}");
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

fn animate_progress(lines: mpsc::Receiver<ProgressLine>) {
    const FRAMES: [char; 8] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧'];
    let mut current: Option<(String, Instant)> = None;
    let tick = Duration::from_millis(100);
    loop {
        match lines.recv_timeout(tick) {
            Ok(ProgressLine::Working(text)) => current = Some((text, Instant::now())),
            Ok(ProgressLine::Detail(text)) => {
                current = None;
                println!("\r\x1b[2K    {text}");
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if current.is_some() {
                    print!("\r\x1b[2K");
                    let _ = io::stdout().flush();
                }
                break;
            }
        }
        if let Some((text, started)) = &current {
            let elapsed = started.elapsed();
            let frame = FRAMES[(elapsed.as_millis() / tick.as_millis()) as usize % FRAMES.len()];
            print!(
                "\r\x1b[2K  \x1b[96m{frame}\x1b[0m {text}  \x1b[90m{} с\x1b[0m",
                elapsed.as_secs()
            );
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
