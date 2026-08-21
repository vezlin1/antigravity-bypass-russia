use std::io::{self, Write};

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
        Err(_) => String::new(),
    }
}

pub fn pause() {
    println!();
    prompt("Нажмите Enter для продолжения...");
}
