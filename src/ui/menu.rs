use crate::core::detector::{find_asar_in_path, find_installations, find_targets_in_path};
use crate::core::patcher::{check_binary_state, patch_target, restore_target, BinaryState};
use crate::core::v8_cache::clear_ide_v8_caches;
use crate::core::asar::read_asar_package_version;
use crate::net::health::test_google_connectivity;
use crate::net::nrpt::get_nrpt_status_info;
use crate::net::provider::DnsProvider;
use crate::net::{apply_dns_rules, remove_dns_rules};
use crate::system::env::{expand_env_vars, mask_path};
use crate::system::privilege::is_admin;
use crate::ui::dashboard::{banner, print_dashboard};
use crate::ui::terminal::{clear_screen, pause, prompt};

pub fn select_dns_provider() -> DnsProvider {
    clear_screen();
    banner();
    println!("\x1b[96m=== ВЫБОР DNS ДЛЯ РАЗБЛОКИРОВКИ API И СЕТИ ===\x1b[0m\n");
    println!("1. \x1b[92mXbox-DNS.ru\x1b[0m (Рекомендуется, быстрый SmartDNS в РФ)");
    println!("2. Свой DNS (ввести IP-адрес вручную)");

    loop {
        match prompt("\nВыберите DNS [1-2, Enter=1]: ").as_str() {
            "1" | "" => return DnsProvider::XboxDns,
            "2" => {
                let custom = prompt("Введите IP-адреса DNS через запятую: ");
                if !custom.is_empty() {
                    return DnsProvider::Custom(custom);
                }
            }
            _ => println!("\x1b[31mНеверный выбор.\x1b[0m"),
        }
    }
}

pub fn handle_unlock_all() {
    let provider = select_dns_provider();
    clear_screen();
    banner();
    println!("\x1b[92m=== ПОЛНАЯ РАЗБЛОКИРОВКА (ФАЙЛЫ + DNS/СЕТЬ) ===\x1b[0m\n");

    let installs = find_installations();
    if installs.is_empty() {
        println!("\x1b[93m[!] Antigravity не найден в стандартных путях (используйте пункт 4 для ручного ввода).\x1b[0m");
    }

    for inst in &installs {
        println!("\x1b[96mПапка:\x1b[0m {}", mask_path(inst));
        let targets = find_targets_in_path(inst);
        for t in &targets {
            match patch_target(t) {
                Ok(msg) => println!("  \x1b[92m[✓]\x1b[0m {} - {}", t.name, msg),
                Err(e) => println!("  \x1b[31m[✗]\x1b[0m {} - {}", t.name, e),
            }
        }
    }

    let caches = clear_ide_v8_caches();
    println!("  \x1b[92m[✓]\x1b[0m Кэш V8 сброшен ({} папок)", caches);

    println!("\n\x1b[93mНастройка селективной DNS-маршрутизации через {}...\x1b[0m", provider.name());
    match apply_dns_rules(&provider) {
        Ok(_) => println!("  \x1b[92m[✓]\x1b[0m Правила DNS и локальный релей успешно применены!"),
        Err(e) => println!("  \x1b[31m[✗]\x1b[0m Ошибка DNS: {}", e),
    }

    println!("\n\x1b[92mГотово! Запустите Antigravity и войдите в аккаунт.\x1b[0m");
    pause();
}

pub fn handle_patch_files_only() {
    clear_screen();
    banner();
    println!("\x1b[94m=== ТОЛЬКО ФАЙЛЫ (РАБОТА БЕЗ СМЕНЫ СТРАНЫ АККАУНТА) ===\x1b[0m\n");

    let installs = find_installations();
    if installs.is_empty() {
        println!("\x1b[93m[!] Antigravity не найден в стандартных путях (используйте пункт 4 для ручного ввода).\x1b[0m");
    }

    for inst in &installs {
        println!("\x1b[96mПапка:\x1b[0m {}", mask_path(inst));
        let targets = find_targets_in_path(inst);
        for t in &targets {
            match patch_target(t) {
                Ok(msg) => println!("  \x1b[92m[✓]\x1b[0m {} - {}", t.name, msg),
                Err(e) => println!("  \x1b[31m[✗]\x1b[0m {} - {}", t.name, e),
            }
        }
    }

    let caches = clear_ide_v8_caches();
    println!("  \x1b[92m[✓]\x1b[0m Кэш V8 сброшен ({} папок)", caches);
    println!("\n\x1b[92m[✓] Патчинг файлов завершен! Запустите Antigravity.\x1b[0m");
    pause();
}

pub fn handle_dns_only() {
    let provider = select_dns_provider();
    clear_screen();
    banner();
    println!("\x1b[93m=== ТОЛЬКО DNS И СЕТЬ (РАБОТА БЕЗ VPN) ===\x1b[0m\n");
    println!("Применение селективной маршрутизации через {}...", provider.name());

    match apply_dns_rules(&provider) {
        Ok(_) => println!("\x1b[92m[✓] Правила DNS, локальный релей и маршруты успешно применены!\x1b[0m"),
        Err(e) => println!("\x1b[31m[✗] Ошибка настройки DNS: {}\x1b[0m", e),
    }
    pause();
}

pub fn handle_manual_path() {
    clear_screen();
    banner();
    println!("\x1b[96m=== УКАЗАТЬ ПУТЬ ВРУЧНУЮ ===\x1b[0m\n");
    let input = prompt("Введите путь к папке или файлу Antigravity: ");
    if input.is_empty() {
        return;
    }

    let p = expand_env_vars(&input);
    if !p.exists() {
        println!("\x1b[31m[!] Путь не существует: {}\x1b[0m", p.display());
        pause();
        return;
    }

    let targets = find_targets_in_path(&p);
    if targets.is_empty() {
        println!("\x1b[93m[!] В указанном пути целевые файлы не найдены.\x1b[0m");
    } else {
        println!("Найдено целей: {}\n", targets.len());
        for t in &targets {
            match patch_target(t) {
                Ok(msg) => println!("  \x1b[92m[✓]\x1b[0m {} - {}", t.name, msg),
                Err(e) => println!("  \x1b[31m[✗]\x1b[0m {} - {}", t.name, e),
            }
        }
        let caches = clear_ide_v8_caches();
        println!("  \x1b[92m[✓]\x1b[0m Кэш V8 сброшен ({} папок)", caches);
        println!("\n\x1b[92m[✓] Патчинг по указанному пути успешно завершен! Запустите Antigravity.\x1b[0m");
    }
    pause();
}

pub fn handle_rollback() {
    clear_screen();
    banner();
    println!("\x1b[91m=== ПОЛНЫЙ ОТКАТ К ИСХОДНОМУ СОСТОЯНИЮ ===\x1b[0m\n");

    let installs = find_installations();
    for inst in &installs {
        println!("\x1b[96mПапка:\x1b[0m {}", mask_path(inst));
        let targets = find_targets_in_path(inst);
        for t in &targets {
            match restore_target(t) {
                Ok(msg) => println!("  \x1b[92m[✓]\x1b[0m {} - {}", t.name, msg),
                Err(e) => println!("  \x1b[31m[✗]\x1b[0m {} - {}", t.name, e),
            }
        }

        let app_dir = inst.join("resources").join("app");
        let app_asar = inst.join("resources").join("app.asar");
        if app_dir.exists() && app_asar.exists() {
            let _ = std::fs::remove_dir_all(&app_dir);
            println!("  \x1b[92m[✓]\x1b[0m resources/app удален (возврат к оригинальному app.asar)");
        }
    }

    let caches = clear_ide_v8_caches();
    println!("  \x1b[92m[✓]\x1b[0m Кэш V8 сброшен ({} папок)", caches);

    println!("\n\x1b[93mУдаление сетевых правил и служб:\x1b[0m");
    remove_dns_rules();
    println!("  \x1b[92m[✓]\x1b[0m Служба DNS-релея остановлена и удалена");
    println!("  \x1b[92m[✓]\x1b[0m Правила NRPT и статические маршруты очищены");
    println!("  \x1b[92m[✓]\x1b[0m Системный кэш DNS сброшен");

    #[cfg(target_os = "windows")]
    {
        delete_user_env_vars(&["GEMINI_API_BASE_URL", "GOOGLE_GEMINI_ENDPOINT"]);
        println!("  \x1b[92m[✓]\x1b[0m Переменные окружения сброшены");
    }

    println!("\n\x1b[92m=====================================================\x1b[0m");
    println!("\x1b[92m[✓] Полный откат завершен. Всё возвращено в заводское состояние.\x1b[0m");
    println!("\x1b[92m=====================================================\x1b[0m");
    pause();
}

#[cfg(target_os = "windows")]
fn delete_user_env_vars(names: &[&str]) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    const HKEY_CURRENT_USER: usize = 0x80000001u32 as i32 as isize as usize;
    const KEY_SET_VALUE: u32 = 0x0002;
    const HWND_BROADCAST: usize = 0xFFFF;
    const WM_SETTINGCHANGE: u32 = 0x001A;
    const SMTO_ABORTIFHUNG: u32 = 0x0002;

    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(hKey: usize, lpSubKey: *const u16, ulOptions: u32, samDesired: u32, phkResult: *mut usize) -> i32;
        fn RegDeleteValueW(hKey: usize, lpValueName: *const u16) -> i32;
        fn RegCloseKey(hKey: usize) -> i32;
    }

    #[link(name = "user32")]
    extern "system" {
        fn SendMessageTimeoutW(
            hWnd: usize,
            Msg: u32,
            wParam: usize,
            lParam: *const u16,
            fuFlags: u32,
            uTimeout: u32,
            lpdwResult: *mut usize,
        ) -> isize;
    }

    let wide = |s: &str| -> Vec<u16> { OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect() };

    let env_subkey = wide("Environment");
    let mut hkey: usize = 0;
    if unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, env_subkey.as_ptr(), 0, KEY_SET_VALUE, &mut hkey) } == 0 {
        for &name in names {
            let val_name = wide(name);
            unsafe { RegDeleteValueW(hkey, val_name.as_ptr()) };
        }
        unsafe { RegCloseKey(hkey) };

        let env_param = wide("Environment");
        let mut result: usize = 0;
        unsafe {
            SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, env_param.as_ptr(), SMTO_ABORTIFHUNG, 300, &mut result);
        }
    }
}

pub fn handle_diagnostics() {
    clear_screen();
    banner();
    println!("\x1b[96m================ ДИАГНОСТИКА СИСТЕМЫ ================\x1b[0m\n");

    let admin_str = if is_admin() {
        "\x1b[92m[✓] Администратор\x1b[0m"
    } else {
        "\x1b[93m[!] Нет прав (запустите с правами администратора)\x1b[0m"
    };
    println!("  1. Права процесса:       {}", admin_str);

    let (nrpt_count, nrpt_server, is_relay) = get_nrpt_status_info();
    let dns_str = if nrpt_count > 0 {
        let srv = nrpt_server.unwrap_or_default();
        let clean_upstream = srv
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

        if is_relay {
            format!("\x1b[92m[✓] Локальный релей (127.0.0.1:53) -> {}\x1b[0m (правил: {})", display_label, nrpt_count)
        } else {
            format!("\x1b[92m[✓] ({})\x1b[0m (правил: {})", display_label, nrpt_count)
        }
    } else {
        "\x1b[90m[Не настроено]\x1b[0m".to_string()
    };
    println!("  2. Сеть и DNS (NRPT):    {}", dns_str);

    let relay_running = crate::system::service::is_running();
    let relay_enabled = crate::system::service::is_enabled();
    let relay_str = if relay_running {
        "\x1b[92m[✓] Работает (фоновый процесс активен)\x1b[0m"
    } else if relay_enabled {
        "\x1b[93m[!] Зарегистрирован, но не запущен\x1b[0m"
    } else {
        "\x1b[90m[-- Отключен]\x1b[0m"
    };
    println!("  3. Служба DNS-релея:     {}", relay_str);

    let egress_info = crate::net::egress::detect();
    let vpn_str = match egress_info {
        Some(e) => {
            if e.vpn_active {
                format!("\x1b[93m[!] Активен VPN (адаптер #{}, сокеты привязаны)\x1b[0m", e.if_index)
            } else {
                format!("\x1b[92m[✓] Прямое соединение (адаптер #{})\x1b[0m", e.if_index)
            }
        }
        None => "\x1b[90m[-- Не определен]\x1b[0m".to_string(),
    };
    println!("  4. Сетевой интерфейс:    {}", vpn_str);

    print!("  5. Связь с Google API:   ");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    match test_google_connectivity() {
        Ok((target, latency)) => {
            println!("\x1b[92m[✓] Доступен ({} мс) — {}\x1b[0m", latency, target);
        }
        Err(e) => {
            println!("\x1b[31m[✗] Не удалось подключиться ({})\x1b[0m", e);
        }
    }

    println!("\n\x1b[96m--- Обнаруженные установки и файлы ---\x1b[0m");
    let installs = find_installations();
    if installs.is_empty() {
        println!("  \x1b[93m[!] Antigravity не найден в стандартных папках.\x1b[0m");
    } else {
        for inst in &installs {
            println!("  \x1b[96mПапка:\x1b[0m {}", mask_path(inst));
            if let Some(asar) = find_asar_in_path(inst) {
                if let Some(ver) = read_asar_package_version(&asar) {
                    let asar_name = asar.file_name().unwrap_or_default().to_string_lossy();
                    println!("    • Версия в ASAR:        \x1b[92m{}\x1b[0m ({})", ver, asar_name);
                }
            }
            let targets = find_targets_in_path(inst);
            for t in targets {
                let state = check_binary_state(&t.path);
                let state_str = match state {
                    BinaryState::Patched => "\x1b[92m[✓ Пропатчен]\x1b[0m",
                    BinaryState::Stock => "\x1b[93m[Исходный]\x1b[0m",
                    BinaryState::Unknown => "\x1b[90m[Неизвестно]\x1b[0m",
                };
                println!("    • {:<36} {}", t.name, state_str);
            }
        }
    }

    println!("\n\x1b[92m[✓] Диагностика системы завершена.\x1b[0m");
    pause();
}

pub fn run_app() {
    loop {
        clear_screen();
        banner();
        print_dashboard();

        println!("1. \x1b[92mПолная разблокировка\x1b[0m (Файлы Core 2.0/IDE/CLI + DNS-релей/Сеть)");
        println!("2. \x1b[94mТолько файлы\x1b[0m (Работа без смены страны аккаунта)");
        println!("3. \x1b[93mТолько DNS и сеть\x1b[0m (Работа без VPN)");
        println!("4. \x1b[95mУказать путь вручную\x1b[0m (к папке или файлу Antigravity)");
        println!("5. \x1b[96mДиагностика и проверка связи\x1b[0m");
        println!("6. \x1b[91mПОЛНЫЙ ОТКАТ\x1b[0m (вернуть всё в исходное состояние)");
        println!("0. Выход\n");

        match prompt("Выберите действие [0-6]: ").as_str() {
            "1" => handle_unlock_all(),
            "2" => handle_patch_files_only(),
            "3" => handle_dns_only(),
            "4" => handle_manual_path(),
            "5" => handle_diagnostics(),
            "6" => handle_rollback(),
            "0" => {
                clear_screen();
                break;
            }
            _ => {
                println!("\x1b[31mНеверный выбор.\x1b[0m");
                std::thread::sleep(std::time::Duration::from_millis(400));
            }
        }
    }
}
