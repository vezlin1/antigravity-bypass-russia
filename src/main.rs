mod core;
mod net;
mod system;
mod ui;

use std::env;
use std::thread;
use std::time::Duration;

fn main() {
    // Background DNS Forwarder mode check
    if env::args().any(|a| a == system::FORWARDER_FLAG) {
        net::detach_console();
        if let Err(e) = net::run_dns_relay() {
            net::log_fatal(&e);
            std::process::exit(1);
        }
        return;
    }

    // Terminal VT100 / UTF-8 initialization
    ui::init_terminal();

    // Ensure elevated administrative / root privileges
    system::ensure_admin();

    // Single-instance enforcement
    if !system::check_single_instance() {
        println!("\x1b[33m[!] ANTIGRAVITY-BYPASS-RUSSIA уже запущен в другом окне.\x1b[0m");
        thread::sleep(Duration::from_millis(1500));
        return;
    }

    // Launch interactive UI menu
    ui::run_app();
}
