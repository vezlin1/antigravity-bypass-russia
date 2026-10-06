use crate::core::detector::{
    find_installations, find_targets_in_path, recover_installations, recover_targets_in_path,
    FoundTarget,
};
use crate::core::patcher::{patch_target, restore_target};
use crate::core::v8_cache::clear_ide_v8_caches;
use crate::net::{apply_dns_rules, remove_dns_rules};
use crate::system::env::{display_path, expand_env_vars, mask_path};
use crate::ui::dashboard::{banner, print_dashboard};
use crate::ui::terminal::{clear_screen, pause, prompt};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileSetupOutcome {
    // Cancellation, missing targets, or a failed application-close check.
    Stopped,
    // All targets were attempted; individual files may have failed.
    Completed(bool),
}

impl FileSetupOutcome {
    fn succeeded(self) -> bool {
        matches!(self, Self::Completed(true))
    }
}

fn continue_setup(outcome: FileSetupOutcome, next: impl FnOnce() -> bool) -> FileSetupOutcome {
    match outcome {
        FileSetupOutcome::Stopped => FileSetupOutcome::Stopped,
        FileSetupOutcome::Completed(ok) => {
            // Run the next stage even after partial failure, preserving that failure.
            FileSetupOutcome::Completed(next() && ok)
        }
    }
}

#[cfg(test)]
mod setup_tests {
    use super::{continue_setup, FileSetupOutcome};

    #[test]
    fn cancelled_or_blocked_file_setup_skips_all_following_mutations() {
        let outcome = continue_setup(FileSetupOutcome::Stopped, || {
            panic!("Cancelled setup must not change endpoints")
        });
        let outcome = continue_setup(outcome, || {
            panic!("Cancelled setup must not configure DNS or install a service")
        });
        assert_eq!(outcome, FileSetupOutcome::Stopped);
        assert!(!outcome.succeeded());
    }

    #[test]
    fn partial_setup_runs_remaining_stages_in_order_and_keeps_every_failure() {
        for files_ok in [false, true] {
            for side_ok in [false, true] {
                for network_ok in [false, true] {
                    let mut stages = vec!["patch files and clear caches"];
                    let outcome = continue_setup(FileSetupOutcome::Completed(files_ok), || {
                        stages.push("configure endpoints");
                        side_ok
                    });
                    let outcome = continue_setup(outcome, || {
                        stages.push("configure DNS and refresh endpoints");
                        network_ok
                    });
                    assert_eq!(
                        stages,
                        [
                            "patch files and clear caches",
                            "configure endpoints",
                            "configure DNS and refresh endpoints"
                        ]
                    );
                    assert_eq!(outcome.succeeded(), files_ok && side_ok && network_ok);
                }
            }
        }
    }
}

fn print_error_details() {
    println!(
        "  Подробности для поддержки: {}",
        crate::net::config::directory()
            .join("network-events.log")
            .display()
    );
}

fn operation_error(message: &str, detail: &str) {
    crate::net::relay::log_event(&format!("{message}: {detail}"));
    eprintln!("  \x1b[91m✗\x1b[0m {message}");
    eprintln!("  {detail}");
}

fn print_patch_result(
    t: &FoundTarget,
    result: Result<crate::core::patcher::PatchOutcome, String>,
) -> bool {
    use crate::core::{detector::TargetKind, patcher::PatchOutcome};
    let label = match t.kind {
        TargetKind::LanguageServer => "Файлы Antigravity",
        TargetKind::AgyCli => "Командная строка Antigravity",
        _ => "Интерфейс приложения",
    };
    match result {
        Ok(PatchOutcome::NotApplicable) => {
            println!("  \x1b[90m– {label}: без изменений\x1b[0m");
            true
        }
        Ok(outcome) => {
            let status = match outcome {
                PatchOutcome::Restored | PatchOutcome::AlreadyStock => "восстановлены",
                _ => "настроены",
            };
            println!("  \x1b[92m✓\x1b[0m {label}: {status}");
            true
        }
        Err(error) => {
            operation_error(
                &format!("{label}: не удалось завершить операцию"),
                &format!("{} ({}): {error}", t.name, t.path.display()),
            );
            if cfg!(target_os = "macos") && app_management_blocked(&t.path, &error) {
                for line in APP_MANAGEMENT_HINT {
                    eprintln!("  \x1b[93m{line}\x1b[0m");
                }
            }
            false
        }
    }
}

const APP_MANAGEMENT_HINT: &[&str] = &[
    "macOS запретила изменять файлы внутри приложения (защита «Управление приложениями»).",
    "1. Закройте Antigravity.",
    "2. Системные настройки → Конфиденциальность и безопасность → Управление приложениями:",
    "   включите Терминал (или iTerm, из которого запускаете утилиту).",
    "3. Полностью закройте терминал (⌘Q), откройте его снова и повторите операцию.",
];

/// App Management denies writes inside signed bundles with EPERM, even to root;
/// a missing Unix permission is EACCES (os error 13) and needs no such hint.
fn app_management_blocked(path: &Path, error: &str) -> bool {
    error.contains("(os error 1)")
        && path
            .ancestors()
            .any(|dir| dir.extension().is_some_and(|ext| ext == "app"))
}

#[cfg(test)]
mod app_management_tests {
    use super::app_management_blocked;
    use std::path::Path;

    #[test]
    fn only_eperm_inside_an_app_bundle_explains_app_management() {
        let bundled =
            Path::new("/Applications/Antigravity.app/Contents/Resources/bin/language_server");
        let eperm = "Operation not permitted (os error 1) at path \"/Applications/Antigravity.app/Contents/Resources/bin/.tmpvbl0fy\"";
        assert!(app_management_blocked(bundled, eperm));
        assert!(!app_management_blocked(
            bundled,
            "Permission denied (os error 13)"
        ));
        assert!(!app_management_blocked(
            bundled,
            "Version not supported (os error 10)"
        ));
        assert!(!app_management_blocked(
            Path::new("/usr/local/bin/agy"),
            eperm
        ));
    }
}
fn patch_root(root: &Path) -> bool {
    if let Err(error) = recover_targets_in_path(root) {
        operation_error("Не удалось восстановить прерванную запись", &error);
        return false;
    }
    let targets = find_targets_in_path(root);
    if targets.is_empty() {
        eprintln!("[✗] Нет поддерживаемых целей: {}", mask_path(root));
        return false;
    }
    patch_targets(targets).succeeded()
}
fn patch_targets(targets: Vec<FoundTarget>) -> FileSetupOutcome {
    let paths: Vec<_> = targets.iter().map(|target| target.path.clone()).collect();
    if !ensure_application_closed(&paths, "включение обхода") {
        return FileSetupOutcome::Stopped;
    }
    let mut ok = true;
    for t in targets {
        ok &= print_patch_result(&t, patch_target(&t));
    }
    // Successful JS patches need cache invalidation even when another file failed.
    if let Err(error) = clear_ide_v8_caches() {
        operation_error("Не удалось очистить кэш приложения", &error);
        ok = false;
    }
    FileSetupOutcome::Completed(ok)
}
fn apply_files_side() -> bool {
    let mut ok = true;
    for note in crate::core::endpoint::apply_all() {
        match note {
            Ok(msg) => crate::net::relay::log_event(&msg),
            Err(e) => {
                ok = false;
                operation_error("Не удалось завершить настройку", &e);
            }
        }
    }
    ok
}
fn patch_installations() -> FileSetupOutcome {
    if let Err(error) = recover_installations() {
        operation_error("Не удалось восстановить прерванную запись", &error);
        return FileSetupOutcome::Stopped;
    }
    let installs = find_installations();
    if installs.is_empty() {
        eprintln!("[✗] Установки не найдены; укажите путь в пункте 4.");
        return FileSetupOutcome::Stopped;
    }
    let targets: Vec<_> = installs
        .iter()
        .flat_map(|root| find_targets_in_path(root))
        .collect();
    if targets.is_empty() {
        eprintln!("[✗] Файлы приложения не найдены; укажите путь в пункте 4.");
        return FileSetupOutcome::Stopped;
    }
    continue_setup(patch_targets(targets), apply_files_side)
}
fn show_result(ok: bool) {
    if ok {
        println!("\n  \x1b[92mГотово. Изменения применены.\x1b[0m\n  Теперь откройте Antigravity и проверьте работу.");
    } else {
        eprintln!("\n  Операция не завершена. Причина указана выше.");
        print_error_details();
    }
}

fn show_network_result(setup: &crate::net::NetworkSetup) -> bool {
    crate::net::relay::log_event(&setup.message);
    if setup.local_relay_running {
        println!("  \x1b[92m✓\x1b[0m DNS настроен. Прямое подключение, без фонового подбора");
    } else {
        eprintln!("  \x1b[93m!\x1b[0m Используются прямые DNS и сохранённые адреса");
        eprintln!("  {}", setup.message);
        print_error_details();
    }
    true
}
pub fn handle_unlock_all() -> bool {
    clear_screen();
    banner();
    println!("  ВКЛЮЧЕНИЕ ОБХОДА\n");
    if !check_vpn_before_setup() {
        return false;
    }
    let outcome = continue_setup(patch_installations(), || {
        let mut ok;
        match apply_dns_rules() {
            Ok(setup) => {
                ok = show_network_result(&setup);
                for note in crate::core::endpoint::apply_all() {
                    match note {
                        Ok(msg) => crate::net::relay::log_event(&msg),
                        Err(e) => {
                            operation_error("Не удалось завершить настройку", &e);
                            ok = false;
                        }
                    }
                }
            }
            Err(e) => {
                operation_error("Не удалось настроить подключение", &e);
                ok = false;
            }
        }
        ok
    });
    let ok = outcome.succeeded();
    show_result(ok);
    pause();
    ok
}
pub fn handle_patch_files_only() -> bool {
    let ok = if let Some(path) = std::env::args().nth(2) {
        patch_root(&expand_env_vars(&path))
    } else {
        patch_installations().succeeded()
    };
    show_result(ok);
    pause();
    ok
}
pub fn handle_dns_only() -> bool {
    if !check_vpn_before_setup() {
        return false;
    }
    if !apply_files_side() {
        return false;
    }
    let ok = match apply_dns_rules() {
        Ok(setup) => show_network_result(&setup),
        Err(e) => {
            operation_error("Не удалось завершить настройку", &e);
            false
        }
    };
    pause();
    ok
}

fn check_vpn_before_setup() -> bool {
    match crate::net::preflight() {
        Ok(()) => true,
        Err(message) => {
            println!("  \x1b[93mВключение обхода приостановлено\x1b[0m\n");
            println!("  {message}\n");
            println!("  Устраните причину и выберите этот пункт ещё раз.");
            pause();
            false
        }
    }
}
pub fn handle_manual_path() {
    let input = prompt("Путь к папке или файлу Antigravity: ");
    if input.is_empty() {
        return;
    }
    let root = expand_env_vars(input.trim().trim_matches('"'));
    let ok = patch_root(&root);
    show_result(ok);
    pause();
}
fn ensure_application_closed(paths: &[std::path::PathBuf], action: &str) -> bool {
    let running = crate::system::file_lock::running_applications(paths).and_then(|mut running| {
        running.extend(crate::system::file_lock::holders(paths)?);
        running.sort();
        running.dedup();
        Ok(running)
    });
    match running {
        Ok(holders) if !holders.is_empty() => {
            println!("  \x1b[93mНужно закрыть Antigravity\x1b[0m");
            println!("  Перед изменением файлов завершите IDE, CLI и языковой сервер.");
            println!("  Сохраните работу: несохранённые изменения будут потеряны.\n");
            if std::env::args().len() > 1 {
                operation_error(
                    "Закройте Antigravity и повторите команду",
                    &holders.join(", "),
                );
                return false;
            }
            println!("  \x1b[96mВыберите действие\x1b[0m");
            #[cfg(windows)]
            println!("  \x1b[1m[1]\x1b[0m  Закрыть Antigravity и продолжить: {action}");
            #[cfg(not(windows))]
            println!("  \x1b[1m[1]\x1b[0m  Я закрыл Antigravity — проверить и продолжить");
            println!("  \x1b[1m[0]\x1b[0m  Отмена — вернуться в меню\n");
            loop {
                match prompt("  Введите 1 или 0 и нажмите Enter: ").as_str() {
                    "1" => break,
                    "0" => {
                        println!("  Операция отменена.");
                        return false;
                    }
                    _ => println!("  Введите номер действия: 1 — продолжить, 0 — отмена."),
                }
            }
            #[cfg(windows)]
            println!("\n  Закрываем Antigravity…");
            #[cfg(not(windows))]
            println!("\n  Проверяем открытые файлы…");
            if let Err(error) = crate::system::file_lock::close_application(paths) {
                operation_error(
                    "Не удалось закрыть приложение. Закройте его вручную",
                    &error,
                );
                print_error_details();
                pause();
                return false;
            }
            println!("  \x1b[92m✓\x1b[0m Процессы Antigravity закрыты.\n");
        }
        Err(error) => {
            operation_error("Не удалось проверить, закрыто ли приложение", &error);
            print_error_details();
            pause();
            return false;
        }
        _ => {}
    }
    true
}

pub fn handle_rollback() -> bool {
    let installs = if let Some(path) = std::env::args().nth(2) {
        let root = expand_env_vars(&path);
        if let Err(error) = recover_targets_in_path(&root) {
            operation_error("Не удалось восстановить прерванную запись", &error);
            return false;
        }
        vec![root]
    } else {
        if let Err(error) = recover_installations() {
            operation_error("Не удалось восстановить прерванную запись", &error);
            return false;
        }
        find_installations()
    };
    let paths: Vec<_> = installs
        .iter()
        .flat_map(|root| find_targets_in_path(root))
        .map(|t| t.path)
        .collect();
    clear_screen();
    banner();
    println!("  ОТКЛЮЧЕНИЕ ОБХОДА\n");
    if !ensure_application_closed(&paths, "отключение обхода") {
        return false;
    }
    println!("  Восстанавливаем настройки…\n");
    let mut ok = true;
    for root in installs {
        let targets = find_targets_in_path(&root);
        if targets.is_empty() {
            if std::env::args().nth(2).is_some() {
                eprintln!("[✗] Цели для отката не найдены: {}", root.display());
                ok = false;
            }
        }
        for target in targets {
            ok &= print_patch_result(&target, restore_target(&target));
        }
    }
    if !paths.is_empty() {
        if let Err(error) = clear_ide_v8_caches() {
            operation_error("Не удалось очистить кэш приложения", &error);
            ok = false;
        }
    }
    let endpoint_errors = crate::core::endpoint::remove_all();
    let endpoints_restored = endpoint_errors.is_empty();
    for e in endpoint_errors {
        operation_error("Не удалось восстановить настройки приложения", &e);
        ok = false;
    }
    if !endpoints_restored {
        operation_error("Шлюз сохранён работающим", "Сначала необходимо восстановить endpoint приложения; остановка сейчас оборвала бы подключение.");
        pause();
        return false;
    }
    if let Err(e) = remove_dns_rules() {
        operation_error("Не удалось восстановить подключение", &e);
        ok = false;
    }
    if ok {
        println!("  \x1b[92m✓\x1b[0m Настройки подключения восстановлены");
        println!("\n  \x1b[92mОбход отключён. Можно открыть Antigravity.\x1b[0m");
    } else {
        eprintln!("\n  Не всё удалось восстановить. Резервные копии сохранены.");
        print_error_details();
    }
    pause();
    ok
}

pub fn handle_diagnostics() -> bool {
    clear_screen();
    banner();
    println!("  ПРОВЕРКА ПОДКЛЮЧЕНИЯ\n");
    let reports = crate::net::health::probe_all();
    let state = crate::net::route_health::store().snapshot();
    let now = crate::net::route_health::now_ms();
    let mut ok = true;
    if let Err(e) = &state {
        operation_error("Не удалось прочитать историю ошибок подключения", e);
        ok = false;
    }
    for report in &reports {
        let label = match report.host.as_str() {
            "cloudcode-pa.googleapis.com" => "Основной сервер",
            "daily-cloudcode-pa.googleapis.com" => "Резервный сервер",
            _ => "Gemini",
        };
        if let Some(error) = &report.error {
            operation_error(&format!("{label}: нет подключения"), error);
            ok = false;
        } else if state
            .as_ref()
            .is_ok_and(|s| s.host_refused(&report.host, now))
        {
            println!(
                "  \x1b[93m!\x1b[0m {label}: сеть доступна, недавно получен региональный отказ"
            );
            ok = false;
        } else {
            println!("  \x1b[92m✓\x1b[0m {label}: TLS/HTTP-соединение доступно");
        }
    }
    println!("\n  Проверена сеть. Доступ к моделям и аккаунту этой проверкой не подтверждается.");
    println!("  Откройте Antigravity и отправьте короткий запрос нужной модели.");
    let observation = crate::model_status::snapshot();
    println!("\n  Модель: {}.", observation.label());
    println!("  Учитываются события за 15 минут. Начало ответа не подтверждает его завершение.");
    if observation.last_failure.is_some()
        && observation.state == crate::model_status::State::StreamStarted
    {
        println!("  Ранее в этом интервале была ошибка; начало нового ответа её не опровергает.");
    }
    if observation.partial {
        println!("  Прочитана только часть журналов; сведения могут быть неполными.");
    }
    for report in &reports {
        crate::net::relay::log_event(&format!("Диагностика: {report:?}"));
    }
    #[cfg(windows)]
    crate::net::relay::log_event(&format!(
        "System DoH disabled: {}",
        crate::net::doh::is_doh_disabled()
    ));
    if let Some(egress) = crate::net::egress::detect() {
        crate::net::relay::log_event(&format!("VPN active: {}", egress.vpn_active));
    }
    if !ok {
        print_error_details();
    }
    pause();
    ok
}

pub fn handle_save_diagnostics(directory: Option<&std::path::Path>) -> bool {
    println!("\n  Собираем диагностику подключения и приложения…");
    println!("  Отчёт сохраняется локально; тексты переписок и токены не включаются.");
    let ok = match crate::diagnostics::save(directory) {
        Ok(path) => {
            println!("\n  Диагностика сохранена:\n  {}", display_path(&path));
            println!("\n  Файл можно приложить к Issue.");
            true
        }
        Err(error) => {
            eprintln!("  Не удалось сохранить диагностику: {error}");
            false
        }
    };
    pause();
    ok
}

pub fn run_app() {
    loop {
        clear_screen();
        banner();
        print_dashboard();

        println!("  \x1b[92m[1]\x1b[0m  Включить обход");
        println!("  [2]  Настроить только файлы приложения");
        println!("  [3]  Настроить только подключение");
        println!("  [4]  Указать папку Antigravity");
        println!("  \x1b[96m[5]\x1b[0m  Проверить подключение");
        println!("  \x1b[91m[6]\x1b[0m  Отключить обход");
        println!("  [7]  Сохранить диагностику");
        println!("\n  [0]  Выход\n");

        match prompt("Выберите действие [0-7]: ").as_str() {
            "1" => {
                handle_unlock_all();
            }
            "2" => {
                handle_patch_files_only();
            }
            "3" => {
                handle_dns_only();
            }
            "4" => handle_manual_path(),
            "5" => {
                handle_diagnostics();
            }
            "6" => {
                handle_rollback();
            }
            "7" => {
                handle_save_diagnostics(None);
            }
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
