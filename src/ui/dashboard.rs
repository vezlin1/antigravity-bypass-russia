use crate::core::detector::get_quick_status;
use crate::core::patcher::BinaryState;
use crate::net::nrpt::get_nrpt_status_info;
use crate::system::privilege::is_admin;

pub fn banner() {
    println!("\x1b[96m=====================================================\x1b[0m");
    println!(
        "\x1b[96m          ANTIGRAVITY-BYPASS-RUSSIA (v{})        \x1b[0m",
        env!("CARGO_PKG_VERSION")
    );
    println!("\x1b[96m=====================================================\x1b[0m");
    println!(" Открытая утилита обхода блокировок и чистого отката\n");
}

pub fn print_dashboard() {
    let (nrpt_count, _, _) = get_nrpt_status_info();
    let comp_status = get_quick_status();

    let admin_str = if is_admin() {
        "\x1b[92m[✓] Администратор\x1b[0m"
    } else {
        "\x1b[93m[!] Нет прав (запустите с правами администратора)\x1b[0m"
    };

    let dns_str = if nrpt_count > 0 {
        "\x1b[92m[✓] Настроено\x1b[0m".to_string()
    } else {
        "\x1b[90m[Не настроено]\x1b[0m".to_string()
    };

    let core_str = match comp_status.core_status {
        Some(BinaryState::Patched) => "\x1b[92m[✓] Пропатчен\x1b[0m",
        Some(BinaryState::Stock) => "\x1b[93m[Исходный]\x1b[0m",
        Some(BinaryState::Unknown) => "\x1b[90m[Неизвестно]\x1b[0m",
        None => "\x1b[90m[Не установлено]\x1b[0m",
    };

    let ide_str = match comp_status.ide_status {
        Some(BinaryState::Patched) => "\x1b[92m[✓] Пропатчен\x1b[0m",
        Some(BinaryState::Stock) => "\x1b[93m[Исходный]\x1b[0m",
        Some(BinaryState::Unknown) => "\x1b[90m[Неизвестно]\x1b[0m",
        None => "\x1b[90m[Не установлено]\x1b[0m",
    };

    let cli_str = match comp_status.cli_status {
        Some(BinaryState::Patched) => "\x1b[92m[✓] Пропатчен\x1b[0m",
        Some(BinaryState::Stock) => "\x1b[93m[Исходный]\x1b[0m",
        Some(BinaryState::Unknown) => "\x1b[90m[Неизвестно]\x1b[0m",
        None => "\x1b[90m[Не установлено]\x1b[0m",
    };

    println!("\x1b[90m┌──────────────────── ТЕКУЩИЙ СТАТУС ────────────────────┐\x1b[0m");
    println!("  • Права процесса:       {}", admin_str);
    println!("  • Сеть и DNS (NRPT):    {}", dns_str);

    let relay_str = if crate::system::service::is_running() {
        "\x1b[92m[✓] 127.0.0.53:53\x1b[0m"
    } else if crate::system::service::is_enabled() {
        "\x1b[93m[!] Зарегистрирован, не запущен\x1b[0m"
    } else {
        "\x1b[90m[-- Выключен]\x1b[0m"
    };
    println!("  • DNS-релей:            {}", relay_str);
    let watcher_str = if crate::core::watcher::is_watcher_running() {
        "\x1b[92m[✓] Активен (авто-репатч)\x1b[0m"
    } else {
        "\x1b[90m[-- Отключен]\x1b[0m"
    };
    println!("  • Авто-репатчер:        {}", watcher_str);
    println!("  • Antigravity 2.0 Core: {}", core_str);
    println!("  • Antigravity IDE UI:   {}", ide_str);
    println!("  • Antigravity CLI:      {}", cli_str);
    if let Some(ver) = comp_status.asar_version {
        println!("  • Версия в app.asar:    \x1b[96mv{}\x1b[0m", ver);
    }
    println!("\x1b[90m└────────────────────────────────────────────────────────┘\x1b[0m\n");
}
