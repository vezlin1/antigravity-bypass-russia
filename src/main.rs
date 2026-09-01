mod core;
mod net;
mod system;
mod ui;

use std::env;
use std::thread;
use std::time::Duration;

fn print_help() {
    println!(
        "ANTIGRAVITY-BYPASS-RUSSIA (v{})\n\
        Использование: antigravity-bypass-russia [КОМАНДА] [ОПЦИИ]\n\n\
        Команды:\n\
          unlock        Полная разблокировка (Файлы + SmartDNS NRPT)\n\
          patch-files   Только бинарники и ASAR (без смены страны аккаунта)\n\
          dns           Настройка SmartDNS / NRPT обхода\n\
          proxy         Запуск локального HTTP CONNECT (8989) & SOCKS5 (10808) прокси\n\
          tune          Оптимизация сетевого стека TCP (Window Auto-Tuning, 512KB)\n\
          watch         Фоновый мониторинг обновлений Antigravity и авто-репатчер\n\
          diagnostics   Диагностика связи и проверка Google Cloud Code API\n\
          rollback      Полный откат: восстановление исходных файлов и сброс DNS\n\
          status        Отображение текущего статуса системы и выход\n\n\
        Опции:\n\
          -h, --help    Показать эту справку\n\
          -V, --version Показать версию\n",
        env!("CARGO_PKG_VERSION")
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();

    // Background DNS Forwarder mode check
    if args.iter().any(|a| a == system::FORWARDER_FLAG) {
        net::detach_console();
        if let Err(e) = net::run_dns_relay() {
            net::log_fatal(&e);
            std::process::exit(1);
        }
        return;
    }

    // CLI Subcommands without admin prompt if help/version/proxy
    let first_arg = args.get(1).map(|s| s.as_str()).unwrap_or("");
    match first_arg {
        "-h" | "--help" | "help" => {
            print_help();
            return;
        }
        "-V" | "--version" | "version" => {
            println!("antigravity-bypass-russia v{}", env!("CARGO_PKG_VERSION"));
            return;
        }
        "proxy" | "--proxy" => {
            ui::init_terminal();
            let _ = net::socket::tune_os_network_stack();
            let http_port = net::proxy::DEFAULT_HTTP_PROXY_PORT;
            let socks5_port = net::proxy::DEFAULT_SOCKS5_PROXY_PORT;
            println!("\x1b[96m=== ANTIGRAVITY EMBEDDED PROXY ===\x1b[0m");
            match net::proxy::start_proxy_servers(http_port, socks5_port) {
                Ok(()) => {
                    println!("\x1b[92m[✓] HTTP CONNECT прокси активен:\x1b[0m http://127.0.0.1:{}", http_port);
                    println!("\x1b[92m[✓] SOCKS5 прокси активен:\x1b[0m       socks5://127.0.0.1:{}", socks5_port);
                    println!("\x1b[92m[✓] Dynamic PAC URL:\x1b[0m             http://127.0.0.1:{}/proxy.pac", http_port);
                    println!("\n\x1b[90mНажмите Ctrl+C для остановки прокси-сервера...\x1b[0m");
                    loop {
                        thread::sleep(Duration::from_secs(3600));
                    }
                }
                Err(e) => {
                    eprintln!("\x1b[31m[!] Ошибка запуска прокси: {}\x1b[0m", e);
                    std::process::exit(1);
                }
            }
        }
        "tune" | "--tune" => {
            ui::init_terminal();
            system::ensure_admin();
            println!("\x1b[96m=== ОПТИМИЗАЦИЯ СЕТЕВОГО СТЕКА TCP ===\x1b[0m\n");
            match net::socket::tune_os_network_stack() {
                Ok(logs) => {
                    for log in logs {
                        println!("  \x1b[92m[✓]\x1b[0m {}", log);
                    }
                    println!("\nТекущий статус:\n{}", net::socket::get_os_network_status());
                }
                Err(e) => eprintln!("  \x1b[31m[✗]\x1b[0m {}", e),
            }
            return;
        }
        "watch" | "--watch" => {
            ui::init_terminal();
            system::ensure_admin();
            core::watcher::run_watcher_loop(Duration::from_secs(8));
            return;
        }
        "status" => {
            ui::init_terminal();
            ui::dashboard::banner();
            ui::dashboard::print_dashboard();
            return;
        }
        "unlock" => {
            ui::init_terminal();
            system::ensure_admin();
            ui::menu::handle_unlock_all();
            return;
        }
        "rollback" | "restore" => {
            ui::init_terminal();
            system::ensure_admin();
            ui::menu::handle_rollback();
            return;
        }
        _ => {}
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
