use crate::core::detector::{
    find_installation_targets, find_installations, find_targets_in_path, recover_installations,
    recover_targets_in_path, FoundTarget,
};
use crate::core::patcher::{patch_target, restore_target};
use crate::core::v8_cache::clear_ide_v8_caches;
use crate::net::{apply_dns_rules, remove_dns_rules, NetworkSetup, SetupProgress};
use crate::system::env::{display_path, expand_env_vars, mask_path};
use crate::ui::dashboard::{banner, print_dashboard};
use crate::ui::terminal::{clear_screen, pause, prompt, Progress};
use std::path::Path;
use std::time::Instant;

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

// A failed DNS/ranking update must leave the application's endpoint alone.
// Both full setup and DNS-only setup use this same ordering.
fn configure_connection_with<T>(
    network: impl FnOnce() -> Result<T, String>,
    endpoints: impl FnOnce() -> Result<(), String>,
) -> Result<T, String> {
    let setup = network()?;
    endpoints()?;
    Ok(setup)
}

#[cfg(test)]
mod setup_tests {
    use super::{configure_connection_with, continue_setup, FileSetupOutcome};

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
                    let stages = std::cell::RefCell::new(vec!["patch files and clear caches"]);
                    let outcome = continue_setup(FileSetupOutcome::Completed(files_ok), || {
                        configure_connection_with(
                            || {
                                stages.borrow_mut().push("configure DNS");
                                if network_ok {
                                    Ok(())
                                } else {
                                    Err("network".into())
                                }
                            },
                            || {
                                stages.borrow_mut().push("configure endpoints");
                                if side_ok {
                                    Ok(())
                                } else {
                                    Err("endpoint".into())
                                }
                            },
                        )
                        .is_ok()
                    });
                    let expected = if network_ok {
                        vec![
                            "patch files and clear caches",
                            "configure DNS",
                            "configure endpoints",
                        ]
                    } else {
                        vec!["patch files and clear caches", "configure DNS"]
                    };
                    assert_eq!(*stages.borrow(), expected);
                    assert_eq!(outcome.succeeded(), files_ok && side_ok && network_ok);
                }
            }
        }
    }

    #[test]
    fn missing_daily_route_keeps_endpoint_file_unchanged_and_creates_no_override() {
        let dir = tempfile::tempdir().unwrap();
        let settings = dir.path().join("settings.json");
        let cli_override = dir.path().join("cli_endpoint.json");
        let original = b"{\"jetski.cloudCodeUrl\":\"https://cloudcode-pa.googleapis.com\"}";
        std::fs::write(&settings, original).unwrap();
        let error = configure_connection_with(
            || {
                Err::<(), _>(
                    "Нет проверенного маршрута для daily-cloudcode-pa.googleapis.com".into(),
                )
            },
            || {
                std::fs::write(&settings, b"daily endpoint").unwrap();
                std::fs::write(&cli_override, b"new override").unwrap();
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.contains("daily-cloudcode"));
        assert_eq!(std::fs::read(settings).unwrap(), original);
        assert!(!cli_override.exists());
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
fn apply_endpoints() -> Result<(), String> {
    let mut errors = Vec::new();
    for note in crate::core::endpoint::apply_all() {
        match note {
            Ok(msg) => crate::net::relay::log_event(&msg),
            Err(e) => {
                errors.push(e);
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SetupStatus {
    Complete,
    Limited,
    Failed,
}

impl SetupStatus {
    fn succeeded(self) -> bool {
        self != Self::Failed
    }
}

fn configure_network() -> Result<NetworkSetup, String> {
    println!("\n  \x1b[96m── Настройка подключения ──\x1b[0m");
    let progress = Progress::new();
    apply_dns_rules(&mut |event| {
        let message = match event {
            SetupProgress::Working(message) => {
                progress.working(message);
                message
            }
            SetupProgress::Detail(message) => {
                progress.detail(message);
                message
            }
        };
        crate::net::relay::log_event(message);
    })
}

fn apply_connection() -> SetupStatus {
    match configure_connection_with(configure_network, apply_endpoints) {
        Ok(setup) => show_network_result(&setup),
        Err(error) => {
            operation_error("Не удалось завершить настройку подключения", &error);
            SetupStatus::Failed
        }
    }
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
    let targets = find_installation_targets(&installs);
    if targets.is_empty() {
        eprintln!("[✗] Файлы приложения не найдены; укажите путь в пункте 4.");
        return FileSetupOutcome::Stopped;
    }
    patch_targets(targets)
}
fn show_result(ok: bool) {
    if ok {
        println!(
            "\n  \x1b[92mГотово. Изменения применены.\x1b[0m\n  Проверьте работу Antigravity."
        );
    } else {
        eprintln!("\n  Операция не завершена. Причина указана выше.");
        print_error_details();
    }
}

fn show_network_result(setup: &NetworkSetup) -> SetupStatus {
    crate::net::relay::log_event(&setup.message);
    println!("\n  \x1b[96m── Состояние подключения ──\x1b[0m");
    if setup.hosts_fallback {
        println!("  \x1b[92m✓\x1b[0m Antigravity · проверен запасной путь через hosts");
    } else if setup.local_relay_running {
        println!("  \x1b[92m✓\x1b[0m Antigravity · локальный DNS-релей работает");
    } else {
        println!("  \x1b[93m!\x1b[0m Antigravity · применены запасные настройки DNS");
    }
    if setup.system_routes {
        println!("    Используются системные маршруты Windows.");
    }
    if setup.primary_skipped {
        println!(
            "  \x1b[93m!\x1b[0m Основной Cloud Code недоступен из этой сети · Antigravity переключён на daily"
        );
        for hint in crate::core::endpoint::primary_skip_hints() {
            crate::net::relay::log_event(&hint);
            println!("    {hint}");
        }
    }
    if setup.browser_dns_confirmed {
        println!("  \x1b[92m✓\x1b[0m Gemini и AI Studio · DNS проверен");
    } else {
        println!("  \x1b[93m!\x1b[0m Gemini и AI Studio · DNS не подтверждён");
    }
    if !setup.local_relay_running {
        println!("  \x1b[93m!\x1b[0m Локальный DNS-релей не прошёл проверку");
    }
    if setup.browser_dns_confirmed {
        SetupStatus::Complete
    } else {
        SetupStatus::Limited
    }
}

#[cfg(windows)]
fn apply_connection_and_launch() -> SetupStatus {
    use crate::net::windows_connect;
    use crate::system::windows_connect_launch::{launch_desktop, DesktopLaunch};

    let setup = configure_connection_with(configure_network, apply_endpoints);
    let browser_dns = setup
        .as_ref()
        .is_ok_and(|setup| setup.browser_dns_confirmed);
    let try_browser = !browser_dns && windows_connect::vpn_present();
    let try_app = setup.is_ok() || windows_connect::fallback_available();
    match &setup {
        Ok(setup) => {
            show_network_result(setup);
        }
        Err(error) if try_app || try_browser => {
            crate::net::relay::log_event(&format!("Настройка DNS: {error}"));
            println!("  \x1b[93m!\x1b[0m DNS не настроен. Проверяем запасной CONNECT внутри VPN.");
        }
        Err(error) => {
            operation_error("Не удалось завершить настройку подключения", error);
            return SetupStatus::Failed;
        }
    };
    let antigravity_ok = if try_app {
        let launch = {
            let progress = Progress::new();
            progress.working("Запускаем Antigravity с запасным CONNECT");
            launch_desktop()
        };
        match launch {
            Ok(DesktopLaunch::Started | DesktopLaunch::AlreadyRunning) => {
                println!("  \x1b[92m✓\x1b[0m Antigravity запущен с резервным CONNECT");
                true
            }
            Ok(DesktopLaunch::NotInstalled) => {
                if let Err(error) = &setup {
                    operation_error("Режим CONNECT требует Antigravity App или IDE", error);
                }
                setup.is_ok()
            }
            Ok(DesktopLaunch::ElevatedSession(reason)) | Err(reason) => {
                crate::net::relay::log_event(&format!("Запуск CONNECT не выполнен: {reason}"));
                println!("  \x1b[93m!\x1b[0m CONNECT не запущен. {reason}");
                if setup.is_ok() {
                    println!("    Сеть настроена. Antigravity можно открыть обычным способом.");
                }
                false
            }
        }
    } else {
        false
    };
    let browser_ok = browser_dns || (try_browser && launch_browser_fallback());
    if setup.is_ok() && antigravity_ok && browser_ok {
        SetupStatus::Complete
    } else if setup.is_ok() || antigravity_ok || browser_ok {
        SetupStatus::Limited
    } else {
        SetupStatus::Failed
    }
}

#[cfg(windows)]
fn launch_browser_fallback() -> bool {
    use crate::system::windows_connect_launch::{launch_browser, DesktopLaunch};

    let launch = {
        let progress = Progress::new();
        progress.working("Проверяем Gemini и AI Studio через CONNECT");
        launch_browser()
    };
    match launch {
        Ok(DesktopLaunch::Started) => {
            println!(
                "  \x1b[92m✓\x1b[0m Gemini и AI Studio открыты через CONNECT в отдельном Chrome"
            );
            true
        }
        Ok(DesktopLaunch::AlreadyRunning) => {
            println!("  \x1b[92m✓\x1b[0m Отдельный Chrome с CONNECT уже открыт");
            true
        }
        Ok(DesktopLaunch::NotInstalled) => {
            println!("  \x1b[93m!\x1b[0m Для запуска Gemini и AI Studio через CONNECT нужен Google Chrome");
            false
        }
        Ok(DesktopLaunch::ElevatedSession(reason)) | Err(reason) => {
            crate::net::relay::log_event(&format!("Браузерный CONNECT не запущен: {reason}"));
            println!("  \x1b[93m!\x1b[0m Gemini и AI Studio не открылись через CONNECT. {reason}");
            false
        }
    }
}

fn finish_setup(status: SetupStatus, started: Instant) {
    let (color, title) = match status {
        SetupStatus::Complete => ("\x1b[92m", "Настройка завершена"),
        SetupStatus::Limited => ("\x1b[93m", "Завершено с ограничениями"),
        SetupStatus::Failed => ("\x1b[91m", "Настройка остановлена"),
    };
    let seconds = started.elapsed().as_secs();
    println!(
        "\n  {color}━━ {title} · {:02}:{:02} ━━\x1b[0m",
        seconds / 60,
        seconds % 60,
    );
    if status != SetupStatus::Complete {
        print_error_details();
    }
}

pub fn handle_unlock_all() -> bool {
    let started = Instant::now();
    clear_screen();
    banner();
    println!("  ВКЛЮЧЕНИЕ ОБХОДА\n");
    if !check_vpn_before_setup() {
        finish_setup(SetupStatus::Failed, started);
        pause();
        return false;
    }
    println!("  \x1b[96m── Файлы приложения ──\x1b[0m");
    let mut status = SetupStatus::Failed;
    let outcome = continue_setup(patch_installations(), || {
        #[cfg(windows)]
        if crate::system::env::args().nth(1).is_none() {
            status = apply_connection_and_launch();
            return status.succeeded();
        }
        status = apply_connection();
        status.succeeded()
    });
    let ok = outcome.succeeded();
    if !ok && status.succeeded() {
        status = SetupStatus::Limited;
    }
    finish_setup(status, started);
    pause();
    ok
}
pub fn handle_patch_files_only() -> bool {
    let ok = if let Some(path) = crate::system::env::args().nth(2) {
        patch_root(&expand_env_vars(&path))
    } else {
        patch_installations().succeeded()
    };
    show_result(ok);
    pause();
    ok
}
pub fn handle_dns_only() -> bool {
    let started = Instant::now();
    if !check_vpn_before_setup() {
        finish_setup(SetupStatus::Failed, started);
        pause();
        return false;
    }
    let status = apply_connection();
    finish_setup(status, started);
    pause();
    status.succeeded()
}

fn check_vpn_before_setup() -> bool {
    #[cfg(windows)]
    if crate::net::windows_connect::vpn_present() {
        println!("  \x1b[93m!\x1b[0m Обнаружен VPN. Он может мешать DNS и подключению.");
        println!("    Если VPN не нужен, лучше временно отключить его.");
    }
    match crate::net::preflight() {
        Ok(()) => true,
        Err(message) => {
            crate::net::relay::log_event(&message);
            println!("  \x1b[93mВключение обхода приостановлено\x1b[0m\n");
            println!("  {message}\n");
            println!("  Устраните причину и выберите этот пункт ещё раз.");
            false
        }
    }
}
pub fn handle_manual_path() {
    use crate::core::install_paths;
    if install_paths::saved().is_empty() {
        add_manual_path();
        return;
    }
    loop {
        let saved = install_paths::saved();
        if saved.is_empty() {
            return;
        }
        clear_screen();
        banner();
        println!("  ПУТИ К ANTIGRAVITY\n");
        println!("  Сохранённые пути:");
        for (index, path) in saved.iter().enumerate() {
            let note = if path.exists() {
                ""
            } else {
                "  \x1b[90m(нет на диске)\x1b[0m"
            };
            println!("    {}. {}{note}", index + 1, display_path(path));
        }
        println!("\n  [1]  Добавить путь");
        println!("  [2]  Убрать сохранённый путь");
        println!("\n  [0]  Назад\n");
        match prompt("Выберите действие [0-2]: ").as_str() {
            "1" => {
                add_manual_path();
                return;
            }
            "2" => remove_manual_path(&saved),
            "0" | "" => return,
            _ => {
                println!("\x1b[31mНеверный выбор.\x1b[0m");
                std::thread::sleep(std::time::Duration::from_millis(400));
            }
        }
    }
}

fn add_manual_path() {
    use crate::core::install_paths;
    let input = prompt("Путь к папке или файлу Antigravity (Enter — отмена): ");
    if input.is_empty() {
        return;
    }
    let path = expand_env_vars(input.trim_matches('"'));
    let (root, targets) = match install_paths::inspect(&path) {
        Ok(found) => found,
        Err(error) => {
            operation_error("Не удалось добавить путь к Antigravity", &error);
            pause();
            return;
        }
    };
    println!("\n  Найдено в {}:", display_path(&root));
    print_found_targets(&root, &targets);
    println!("\n  [1]  Сохранить путь и настроить эти файлы");
    println!("  [0]  Отмена — ничего не сохранять\n");
    if choose(&["1", "0"]) != "1" {
        println!("  Путь не сохранён.");
        pause();
        return;
    }
    if let Err(error) = install_paths::save(&root) {
        operation_error("Не удалось сохранить путь", &error);
        pause();
        return;
    }
    println!(
        "  Путь сохранён, пункты [1] и [6] будут его учитывать: {}",
        display_path(&root)
    );
    show_result(patch_targets(targets).succeeded());
    pause();
}

fn remove_manual_path(saved: &[std::path::PathBuf]) {
    use crate::core::detector::found_automatically;
    use crate::core::patcher::{check_target_state, BinaryState};
    let choice = prompt(&format!(
        "Номер пути, который убрать [1-{}], Enter — отмена: ",
        saved.len()
    ));
    let Some(root) = choice
        .parse::<usize>()
        .ok()
        .and_then(|number| saved.get(number.checked_sub(1)?))
    else {
        if !choice.is_empty() {
            println!("  Нет пути с таким номером.");
            pause();
        }
        return;
    };
    // Without the saved path, rollback no longer finds files that only it
    // pointed to; offer to restore them first.
    let automatic = root.exists() && found_automatically(root);
    if root.exists() && !automatic {
        if let Err(error) = recover_targets_in_path(root) {
            operation_error("Не удалось восстановить прерванную запись", &error);
            pause();
            return;
        }
        let patched: Vec<_> = find_targets_in_path(root)
            .into_iter()
            .filter(|target| {
                matches!(
                    check_target_state(target),
                    BinaryState::Patched | BinaryState::PartiallyPatched
                )
            })
            .collect();
        if !patched.is_empty() {
            println!("\n  В {} есть пропатченные файлы:", display_path(root));
            print_found_targets(root, &patched);
            println!("  Без сохранённого пути пункт [6] их не найдёт.\n");
            println!("  [1]  Вернуть исходные файлы и убрать путь");
            println!("  [2]  Только убрать путь — файлы останутся пропатченными");
            println!("  [0]  Отмена\n");
            match choose(&["1", "2", "0"]) {
                "1" => {
                    if !restore_targets(patched) {
                        eprintln!("\n  Путь не убран: сначала нужно вернуть исходные файлы.");
                        pause();
                        return;
                    }
                }
                "2" => {}
                _ => return,
            }
        }
    }
    match crate::core::install_paths::forget(root) {
        Ok(_) => println!("  \x1b[92m✓\x1b[0m Путь убран: {}", display_path(root)),
        Err(error) => operation_error("Не удалось убрать путь", &error),
    }
    if automatic {
        println!("  Эта установка находится и без сохранённого пути: статус и пункты [1] и [6] по-прежнему её учитывают.");
    }
    pause();
}

/// Restores the given files after the application is closed.
fn restore_targets(targets: Vec<FoundTarget>) -> bool {
    let paths: Vec<_> = targets.iter().map(|target| target.path.clone()).collect();
    if !ensure_application_closed(&paths, "возврат исходных файлов") {
        return false;
    }
    let mut ok = true;
    for target in targets {
        ok &= print_patch_result(&target, restore_target(&target));
    }
    if let Err(error) = clear_ide_v8_caches() {
        operation_error("Не удалось очистить кэш приложения", &error);
        ok = false;
    }
    ok
}

fn print_found_targets(root: &Path, targets: &[FoundTarget]) {
    use crate::core::patcher::{check_target_state, BinaryState};
    for target in targets {
        let file = target
            .path
            .strip_prefix(root)
            .ok()
            .filter(|relative| !relative.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new(&target.name));
        let state = match check_target_state(target) {
            BinaryState::Patched => "пропатчено",
            BinaryState::Stock => "не пропатчено",
            BinaryState::PartiallyPatched => "пропатчено частично",
            BinaryState::Unknown => "версия не распознана",
        };
        println!(
            "    • {} — {} \x1b[90m({state})\x1b[0m",
            component_name(target.kind),
            file.display()
        );
    }
}

fn component_name(kind: crate::core::detector::TargetKind) -> &'static str {
    use crate::core::detector::TargetKind;
    match kind {
        TargetKind::LanguageServer => "Antigravity",
        TargetKind::IdeMainJs | TargetKind::IdeAsar => "Antigravity IDE",
        TargetKind::AgyCli => "Antigravity CLI",
    }
}

/// Asks until one of `options` is entered.
fn choose(options: &[&'static str]) -> &'static str {
    loop {
        let answer = prompt(&format!(
            "  Введите {} и нажмите Enter: ",
            options.join(", ")
        ));
        if let Some(option) = options.iter().find(|option| **option == answer) {
            return option;
        }
    }
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
            println!("  Файлы используют: {}", holders.join(", "));
            println!("  Перед изменением файлов завершите IDE, CLI и языковой сервер.");
            println!("  Сохраните работу: несохранённые изменения будут потеряны.\n");
            if crate::system::env::args().len() > 1 {
                operation_error(
                    "Закройте Antigravity и повторите команду",
                    &holders.join(", "),
                );
                return false;
            }
            println!("  \x1b[96mВыберите действие\x1b[0m");
            #[cfg(any(windows, unix))]
            println!("  \x1b[1m[1]\x1b[0m  Закрыть Antigravity и продолжить: {action}");
            #[cfg(not(any(windows, unix)))]
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
            #[cfg(any(windows, unix))]
            println!("\n  Закрываем Antigravity…");
            #[cfg(not(any(windows, unix)))]
            println!("\n  Проверяем открытые файлы…");
            if let Err(error) = crate::system::file_lock::close_application(paths) {
                #[cfg(any(windows, unix))]
                let message = "Не удалось закрыть приложение. Закройте его вручную";
                #[cfg(not(any(windows, unix)))]
                let message = "Не удалось подтвердить, что файлы Antigravity свободны";
                operation_error(message, &error);
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
    let explicit_root = crate::system::env::args()
        .nth(2)
        .map(|path| expand_env_vars(&path));
    let installs = if let Some(root) = &explicit_root {
        if let Err(error) = recover_targets_in_path(root) {
            operation_error("Не удалось восстановить прерванную запись", &error);
            return false;
        }
        vec![root.clone()]
    } else {
        if let Err(error) = recover_installations() {
            operation_error("Не удалось восстановить прерванную запись", &error);
            return false;
        }
        find_installations()
    };
    let targets = find_installation_targets(&installs);
    let paths: Vec<_> = targets.iter().map(|target| target.path.clone()).collect();
    clear_screen();
    banner();
    println!("  ОТКЛЮЧЕНИЕ ОБХОДА\n");
    if !ensure_application_closed(&paths, "отключение обхода") {
        return false;
    }
    println!("  Восстанавливаем настройки…\n");
    let mut ok = true;
    if let Some(root) = explicit_root.filter(|_| targets.is_empty()) {
        eprintln!("[✗] Цели для отката не найдены: {}", root.display());
        ok = false;
    }
    for target in targets {
        ok &= print_patch_result(&target, restore_target(&target));
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
    match remove_dns_rules() {
        Err(error) => {
            operation_error("Не удалось восстановить подключение", &error);
            ok = false;
        }
        Ok(()) =>
        {
            #[cfg(windows)]
            if let Err(error) = crate::net::windows_connect::disable() {
                operation_error("Не удалось отключить запасной CONNECT", &error);
                ok = false;
            }
        }
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
    // Reading the IDE logs does not depend on the network checks.
    let observation = std::thread::spawn(crate::model_status::snapshot);
    let reports = crate::net::health::probe_all();
    let mut ok = true;
    for report in &reports {
        let label = match report.host.as_str() {
            "cloudcode-pa.googleapis.com" => "Основной сервер",
            "daily-cloudcode-pa.googleapis.com" => "Резервный сервер",
            "aicode.googleapis.com" => "Eligibility сервер (CLI)",
            _ => "Gemini",
        };
        if let Some(error) = &report.error {
            operation_error(&format!("{label}: нет подключения"), error);
            ok = false;
        } else {
            println!("  \x1b[92m✓\x1b[0m {label}: TLS/HTTP-соединение доступно");
        }
    }
    println!("\n  Проверена сеть. Доступ к моделям и аккаунту этой проверкой не подтверждается.");
    println!("  Откройте Antigravity и отправьте короткий запрос нужной модели.");
    let observation = observation
        .join()
        .unwrap_or_else(|_| crate::model_status::snapshot());
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
        println!("  [4]  Пути к Antigravity");
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
