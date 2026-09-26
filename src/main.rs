mod core;
mod diagnostics;
mod model_status;
mod net;
mod system;
mod ui;

use std::env;

fn print_help() {
    println!(
        "ANTIGRAVITY-BYPASS-RUSSIA (v{})\n\
        Использование: antigravity-bypass-russia [КОМАНДА] [ОПЦИИ]\n\n\
        Команды:\n\
          unlock        Включить обход (файлы приложения и DNS)\n\
          patch-files   Патч поддерживаемых файлов [необязательный путь]\n\
          dns           Настройка SmartDNS / NRPT обхода\n\
          tune          Оптимизация сетевого стека TCP (Window Auto-Tuning, 512KB)\n\
          diagnostics   DNS, проверка TLS/сертификата и HTTP (без входа в аккаунт)\n\
          report        Сохранить диагностику в JSON [необязательный каталог]\n\
          speed         Показать режим прямого подключения\n\
          rollback      Отключить обход и восстановить сохранённые настройки\n\
          status        Отображение текущего статуса системы и выход\n\n\
        Опции:\n\
          -h, --help    Показать эту справку\n\
          -V, --version Показать версию\n",
        env!("CARGO_PKG_VERSION")
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let command = args.get(1).map(String::as_str).unwrap_or("");
    #[cfg(target_os = "macos")]
    if command == "--endpoint-session" {
        if let Err(error) = core::endpoint_session::restore() {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return;
    }
    if command == system::FORWARDER_FLAG {
        net::detach_console();
        if let Err(e) = net::run_dns_relay() {
            net::log_fatal(&e);
            std::process::exit(1);
        }
        return;
    }
    ui::init_terminal();
    if matches!(command, "-h" | "--help" | "help") {
        print_help();
        return;
    }
    if matches!(command, "-V" | "--version" | "version") {
        println!("antigravity-bypass-russia v{}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if !matches!(
        command,
        "" | "status"
            | "diagnostics"
            | "report"
            | "speed"
            | "unlock"
            | "patch-files"
            | "dns"
            | "rollback"
            | "restore"
            | "tune"
            | "--tune"
    ) {
        eprintln!("Неизвестная команда: {command}");
        std::process::exit(2);
    }
    if args.len()
        > if matches!(command, "patch-files" | "rollback" | "restore" | "report") {
            3
        } else {
            2
        }
    {
        eprintln!("Лишние аргументы. См. --help");
        std::process::exit(2);
    }
    if command == "status" {
        ui::dashboard::print_dashboard();
        return;
    }
    if command == "speed" {
        std::process::exit(if ui::speed::run() { 0 } else { 1 });
    }
    if command == "diagnostics" {
        let ok = ui::menu::handle_diagnostics();
        std::process::exit(if ok { 0 } else { 1 });
    }
    if command == "report" {
        let directory = args.get(2).map(std::path::Path::new);
        let ok = ui::menu::handle_save_diagnostics(directory);
        std::process::exit(if ok { 0 } else { 1 });
    }
    system::ensure_admin();
    if !system::check_single_instance() {
        eprintln!("Уже выполняется другая операция обходчика");
        std::process::exit(1);
    }
    let ok = match command {
        "unlock" => ui::menu::handle_unlock_all(),
        "patch-files" => ui::menu::handle_patch_files_only(),
        "dns" => ui::menu::handle_dns_only(),
        "speed" => ui::speed::run(),
        "rollback" | "restore" => ui::menu::handle_rollback(),
        "tune" | "--tune" => match net::socket::tune_os_network_stack() {
            Ok(logs) => {
                for log in logs {
                    println!("{log}");
                }
                println!("{}", net::socket::get_os_network_status());
                true
            }
            Err(e) => {
                eprintln!("{e}");
                false
            }
        },
        _ => {
            ui::run_app();
            true
        }
    };
    std::process::exit(if ok { 0 } else { 1 });
}
