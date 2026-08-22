use crate::core::detector::get_quick_status;
use crate::core::patcher::BinaryState;
use crate::net::nrpt::get_nrpt_status_info;
use crate::system::privilege::is_admin;

pub fn banner() {
    println!("\x1b[96m=====================================================\x1b[0m");
    println!("\x1b[96m          ANTIGRAVITY-BYPASS-RUSSIA (v1.0.1)         \x1b[0m");
    println!("\x1b[96m=====================================================\x1b[0m");
    println!(" Открытая утилита обхода блокировок и чистого отката\n");
}

pub fn print_dashboard() {
    let (nrpt_count, nrpt_server, _is_relay) = get_nrpt_status_info();
    let comp_status = get_quick_status();

    let admin_str = if is_admin() {
        "\x1b[92m[✓] Администратор\x1b[0m"
    } else {
        "\x1b[93m[!] Нет прав (запустите с правами администратора)\x1b[0m"
    };

    let dns_str = if nrpt_count > 0 {
        let raw_server = nrpt_server.unwrap_or_else(|| "Активен".to_string());
        let clean_upstream = raw_server
            .split([';', ',', ' '])
            .map(|s| s.trim())
            .filter(|s| !s.is_empty() && *s != "127.0.0.53" && *s != "127.0.0.1")
            .collect::<Vec<_>>()
            .join(", ");

        let display_label = if clean_upstream.contains("111.88.96.50")
            || clean_upstream.contains("176.108.243.68")
            || clean_upstream.contains("111.88.96.51")
        {
            "Xbox-DNS.ru".to_string()
        } else if !clean_upstream.is_empty() {
            clean_upstream
        } else {
            let upstreams = crate::net::relay::load_upstream_servers();
            let upstream_strs: Vec<String> = upstreams.iter().map(|ip| ip.to_string()).collect();
            if upstream_strs.iter().any(|ip| ip == "111.88.96.50" || ip == "176.108.243.68" || ip == "111.88.96.51") {
                "Xbox-DNS.ru".to_string()
            } else if !upstream_strs.is_empty() {
                upstream_strs.join(", ")
            } else {
                "Xbox-DNS.ru".to_string()
            }
        };

        format!("\x1b[92m[✓] ({})\x1b[0m", display_label)
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
    println!("  • Antigravity 2.0 Core: {}", core_str);
    println!("  • Antigravity IDE UI:   {}", ide_str);
    println!("  • Antigravity CLI:      {}", cli_str);
    if let Some(ver) = comp_status.asar_version {
        println!("  • Версия в app.asar:    \x1b[96mv{}\x1b[0m", ver);
    }
    println!("\x1b[90m└────────────────────────────────────────────────────────┘\x1b[0m\n");
}
