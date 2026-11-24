use crate::core::detector::{
    find_installation_targets, find_installations, find_targets_in_path, recover_installations,
    recover_targets_in_path, FoundTarget,
};
use crate::core::patcher::{patch_target, restore_target};
use crate::core::v8_cache::clear_ide_v8_caches;
use crate::net::{apply_dns_rules, remove_dns_rules, NetworkSetup, SetupProgress, SetupStage};
use crate::system::env::{display_path, expand_env_vars};
use crate::ui::dashboard::{banner, print_dashboard};
use crate::ui::terminal::{clear_screen, pause, prompt, Progress, Steps};
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
        "  \x1b[90mЖурнал для поддержки: {}\x1b[0m",
        crate::net::config::directory()
            .join("network-events.log")
            .display()
    );
}

fn operation_error(message: &str, detail: &str) {
    print_problem(2, message, detail, None);
}

/// "✗ what failed", then the cause and what the user can do about it.
/// `advice: None` derives the advice from the cause.
fn print_problem(indent: usize, message: &str, cause: &str, advice: Option<&str>) {
    crate::net::relay::log_event(&format!("{message}: {cause}"));
    let pad = " ".repeat(indent);
    eprintln!("{pad}\x1b[91m✗\x1b[0m {message}");
    let readable = readable_cause(cause);
    if !readable.is_empty() {
        eprintln!("{pad}  \x1b[90mПричина:\x1b[0m {readable}");
    }
    if let Some(advice) = advice.or_else(|| advice_for(cause)) {
        eprintln!("{pad}  \x1b[96mЧто сделать:\x1b[0m {advice}");
    }
}

/// The OS error text without its numeric code, which means nothing to users.
fn readable_cause(cause: &str) -> String {
    let mut text = cause.trim().to_owned();
    while let Some(start) = text.find(" (os error ") {
        let Some(length) = text[start..].find(')') else {
            break;
        };
        text.replace_range(start..start + length + 1, "");
    }
    text
}

const ADVICE_DIAGNOSTICS: &str =
    "сохраните диагностику (пункт 7) и приложите файл к обращению на GitHub.";

/// What to do about a failure, from its cause. `None` when the cause already
/// tells the user what to do.
fn advice_for(cause: &str) -> Option<&'static str> {
    let text = cause.to_lowercase();
    let has = |words: &[&str]| words.iter().any(|word| text.contains(word));
    if has(&[
        "закройте ",
        "укажите ",
        "проверьте ",
        "устраните ",
        "отключите ",
    ]) {
        return None;
    }
    Some(
        if has(&[
            "os error 32",
            "используется другим процессом",
            "being used by another process",
        ]) {
            "закройте Antigravity (приложение, IDE и CLI) и повторите."
        } else if has(&[
            "os error 5)",
            "os error 13)",
            "отказано в доступе",
            "access is denied",
            "permission denied",
        ]) {
            "запустите утилиту от имени администратора. Если не помогло — изменения может блокировать антивирус: добавьте папку Antigravity в его исключения."
        } else if has(&["os error 123", "синтаксическая ошибка в имени"])
        {
            "путь указан с ошибкой. Скопируйте его из адресной строки Проводника и вставьте целиком."
        } else if has(&[
            "os error 2)",
            "os error 3)",
            "не удается найти",
            "no such file",
        ]) {
            "проверьте, что папка существует. Если Antigravity установлен в другом месте, укажите путь в пункте 4."
        } else if has(&["не поддерживается", "integrity"]) {
            "эта версия Antigravity пока не поддерживается. Скачайте свежую версию утилиты на странице релизов."
        } else if has(&[
            "выход в интернет",
            "network is unreachable",
            "сеть недоступна",
        ]) {
            "проверьте подключение к интернету. Если включён VPN, временно отключите его и повторите."
        } else if has(&["порт 53"]) {
            "системный порт для адресов занят другой программой (VPN, AdGuard или DNS-фильтр). Закройте её и повторите."
        } else if has(&[
            "маршрут",
            "подходящих адресов",
            "timed out",
            "тайм-аут",
            "время ожидания",
        ]) {
            "серверы Google не ответили. Проверьте интернет, отключите VPN или прокси и повторите через минуту."
        } else {
            ADVICE_DIAGNOSTICS
        },
    )
}

#[cfg(test)]
mod problem_tests {
    use super::{advice_for, readable_cause, ADVICE_DIAGNOSTICS};

    #[test]
    fn os_codes_are_hidden_and_common_failures_get_advice() {
        assert_eq!(
            readable_cause("C:\\x: Отказано в доступе. (os error 5)"),
            "C:\\x: Отказано в доступе."
        );
        for (cause, expected) in [
            ("Отказано в доступе. (os error 5)", "администратора"),
            (
                "файл используется другим процессом (os error 32)",
                "закройте Antigravity",
            ),
            (
                "Синтаксическая ошибка в имени файла (os error 123)",
                "адресной строки",
            ),
            ("Не удается найти указанный файл. (os error 2)", "пункте 4"),
            (
                "Версия/сигнатура не поддерживается; файл не изменён",
                "свежую версию",
            ),
            ("Локальный UDP-порт 53 недоступен", "AdGuard"),
            ("Нет проверенного маршрута для daily", "серверы Google"),
        ] {
            assert!(advice_for(cause).unwrap().contains(expected), "{cause}");
        }
        // The cause already says what to do: no second instruction.
        assert_eq!(
            advice_for("Закройте Antigravity перед изменением файлов"),
            None
        );
        assert_eq!(advice_for("что-то неожиданное"), Some(ADVICE_DIAGNOSTICS));
    }
}

/// One line per file under its step. Files with nothing to change are not
/// listed: the user cannot act on them.
fn print_patch_result(
    t: &FoundTarget,
    result: Result<crate::core::patcher::PatchOutcome, String>,
) -> bool {
    use crate::core::patcher::PatchOutcome;
    let label = component_name(t.kind);
    match result {
        Ok(PatchOutcome::NotApplicable) => true,
        Ok(outcome) => {
            let status = match outcome {
                PatchOutcome::Restored | PatchOutcome::AlreadyStock => "возвращён к исходному",
                _ => "настроен",
            };
            println!("      \x1b[92m✓\x1b[0m {label} \x1b[90m— {status}\x1b[0m");
            true
        }
        Err(error) => {
            print_problem(
                6,
                &format!("{label}: файл не изменён"),
                &format!("{error} — {}", t.path.display()),
                None,
            );
            if cfg!(target_os = "macos") && app_management_blocked(&t.path, &error) {
                for line in APP_MANAGEMENT_HINT {
                    eprintln!("        \x1b[93m{line}\x1b[0m");
                }
            }
            false
        }
    }
}

/// Runs `action` on every file under one step and lists the results below it.
fn run_file_step(
    steps: &Steps,
    (running, done): (&str, &str),
    targets: Vec<FoundTarget>,
    action: fn(&FoundTarget) -> Result<crate::core::patcher::PatchOutcome, String>,
) -> bool {
    let progress = Progress::new();
    progress.stage(steps, running, done);
    let results: Vec<_> = targets
        .into_iter()
        .map(|target| {
            let result = action(&target);
            (target, result)
        })
        .collect();
    // Changed JS needs cache invalidation even when another file failed.
    let cache = clear_ide_v8_caches();
    progress.finish(results.iter().all(|(_, result)| result.is_ok()) && cache.is_ok());
    drop(progress);
    let mut ok = true;
    for (target, result) in results {
        ok &= print_patch_result(&target, result);
    }
    if let Err(error) = cache {
        print_problem(6, "Не удалось очистить кэш Antigravity", &error, None);
        ok = false;
    }
    ok
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
        print_problem(
            2,
            "Файлы Antigravity не найдены",
            &format!("в папке {} нет файлов Antigravity", display_path(root)),
            Some("проверьте путь к установке."),
        );
        return false;
    }
    patch_targets(targets, &Steps::unnumbered()).succeeded()
}

const FILES_STEP: (&str, &str) = ("Настраиваем файлы Antigravity", "Файлы Antigravity");

fn patch_targets(targets: Vec<FoundTarget>, steps: &Steps) -> FileSetupOutcome {
    let paths: Vec<_> = targets.iter().map(|target| target.path.clone()).collect();
    if !ensure_application_closed(&paths, "включение обхода") {
        return FileSetupOutcome::Stopped;
    }
    FileSetupOutcome::Completed(run_file_step(steps, FILES_STEP, targets, patch_target))
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

/// What the final screen tells the user besides the verdict.
#[derive(Default)]
struct Summary {
    next: Option<&'static str>,
    notes: Vec<String>,
}

fn stage_titles(stage: SetupStage) -> (&'static str, &'static str) {
    match stage {
        SetupStage::Connection => (
            "Проверяем связь с серверами Google",
            "Связь с серверами Google",
        ),
        SetupStage::Service => ("Запускаем фоновую службу", "Фоновая служба"),
        SetupStage::Saving => ("Сохраняем настройки системы", "Настройки системы"),
    }
}

fn configure_network(steps: &Steps) -> Result<NetworkSetup, String> {
    let progress = Progress::new();
    let result = apply_dns_rules(&mut |event| {
        let message = match event {
            SetupProgress::Stage(stage) => {
                let (running, done) = stage_titles(stage);
                progress.stage(steps, running, done);
                running
            }
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
    });
    progress.finish(result.is_ok());
    result
}

fn apply_connection(steps: &Steps, summary: &mut Summary) -> SetupStatus {
    match configure_connection_with(|| configure_network(steps), apply_endpoints) {
        Ok(setup) => network_result(&setup, summary),
        Err(error) => {
            operation_error("Подключение не настроено", &error);
            SetupStatus::Failed
        }
    }
}
fn patch_installations(steps: &Steps) -> FileSetupOutcome {
    if let Err(error) = recover_installations() {
        operation_error("Не удалось восстановить прерванную запись", &error);
        return FileSetupOutcome::Stopped;
    }
    let installs = find_installations();
    if installs.is_empty() {
        print_problem(
            2,
            "Antigravity не найден",
            "утилита не нашла установку в стандартных папках",
            Some("если Antigravity установлен, укажите путь к нему в пункте 4."),
        );
        return FileSetupOutcome::Stopped;
    }
    let targets = find_installation_targets(&installs);
    if targets.is_empty() {
        print_problem(
            2,
            "Файлы Antigravity не найдены",
            "в найденных папках нет файлов, которые нужно настроить",
            Some("укажите путь к установке Antigravity в пункте 4."),
        );
        return FileSetupOutcome::Stopped;
    }
    patch_targets(targets, steps)
}
fn show_result(ok: bool) {
    if ok {
        println!("\n  \x1b[92m✓ Готово.\x1b[0m Перезапустите Antigravity, чтобы изменения вступили в силу.");
    } else {
        eprintln!(
            "\n  \x1b[91m✗ Не всё получилось.\x1b[0m Причина и что сделать — в строках с ✗ выше."
        );
        print_error_details();
    }
}

/// Network facts become notes in plain words; technical details go to the log.
fn network_result(setup: &NetworkSetup, summary: &mut Summary) -> SetupStatus {
    crate::net::relay::log_event(&setup.message);
    if setup.system_routes {
        crate::net::relay::log_event("Используются системные маршруты Windows");
    }
    if !setup.local_relay_running && !setup.hosts_fallback {
        summary.notes.push(
            "Фоновая служба не запустилась, поэтому используются запасные серверы адресов. \
             Если Antigravity будет работать с перебоями, включите обход ещё раз."
                .into(),
        );
    }
    if setup.primary_skipped {
        summary.notes.push(
            "Основной сервер Antigravity недоступен из вашей сети, поэтому Antigravity \
             переключён на резервный сервер Google. Так и должно быть."
                .into(),
        );
        for hint in crate::core::endpoint::primary_skip_hints() {
            crate::net::relay::log_event(&hint);
            summary.notes.push(hint);
        }
    }
    if setup.browser_dns_confirmed {
        SetupStatus::Complete
    } else {
        summary.notes.push(BROWSER_UNCHECKED.into());
        SetupStatus::Limited
    }
}

const BROWSER_UNCHECKED: &str =
    "Доступ к Gemini и AI Studio в браузере проверить не удалось. На Antigravity это не влияет.";

#[cfg(windows)]
fn apply_connection_and_launch(steps: &Steps, summary: &mut Summary) -> SetupStatus {
    use crate::net::windows_connect;
    use crate::system::windows_connect_launch::{launch_desktop, DesktopLaunch};

    let setup = configure_connection_with(|| configure_network(steps), apply_endpoints);
    let browser_dns = setup
        .as_ref()
        .is_ok_and(|setup| setup.browser_dns_confirmed);
    let try_browser = !browser_dns && windows_connect::vpn_present();
    let try_app = setup.is_ok() || windows_connect::fallback_available();
    match &setup {
        Ok(setup) => {
            network_result(setup, summary);
            if try_browser {
                // The browser fallback below reports its own result.
                summary.notes.retain(|note| note != BROWSER_UNCHECKED);
            }
        }
        Err(error) if try_app || try_browser => {
            crate::net::relay::log_event(&format!("Настройка DNS: {error}"));
            summary.notes.push(
                "Обычная настройка не удалась из-за VPN, поэтому используется резервный канал."
                    .into(),
            );
        }
        Err(error) => {
            operation_error("Подключение не настроено", error);
            return SetupStatus::Failed;
        }
    };
    let progress = Progress::new();
    progress.stage(steps, "Запускаем Antigravity", "Antigravity запущен");
    let antigravity_ok = if try_app {
        match launch_desktop() {
            Ok(DesktopLaunch::Started | DesktopLaunch::AlreadyRunning) => {
                summary.next = Some(
                    "Antigravity открыт. Войдите в аккаунт Google и отправьте короткий запрос, чтобы проверить работу.",
                );
                true
            }
            Ok(DesktopLaunch::NotInstalled) => {
                if let Err(error) = &setup {
                    progress.finish(false);
                    drop(progress);
                    operation_error("Для резервного канала нужен Antigravity App или IDE", error);
                    return SetupStatus::Failed;
                }
                true
            }
            Ok(DesktopLaunch::ElevatedSession(reason)) | Err(reason) => {
                crate::net::relay::log_event(&format!("Запуск CONNECT не выполнен: {reason}"));
                summary.notes.push(format!(
                    "Не удалось запустить Antigravity через резервный канал: {reason}"
                ));
                false
            }
        }
    } else {
        false
    };
    let browser_ok = browser_dns || (try_browser && launch_browser_fallback(&progress, summary));
    progress.finish(antigravity_ok);
    drop(progress);
    if setup.is_ok() && antigravity_ok && browser_ok {
        SetupStatus::Complete
    } else if setup.is_ok() || antigravity_ok || browser_ok {
        SetupStatus::Limited
    } else {
        SetupStatus::Failed
    }
}

#[cfg(windows)]
fn launch_browser_fallback(progress: &Progress, summary: &mut Summary) -> bool {
    use crate::system::windows_connect_launch::{launch_browser, DesktopLaunch};

    progress.working("открываем Gemini и AI Studio в отдельном Chrome");
    let (ok, note) = match launch_browser() {
        Ok(DesktopLaunch::Started | DesktopLaunch::AlreadyRunning) => (
            true,
            "Gemini и AI Studio открыты в отдельном окне Chrome — для них пользуйтесь этим окном."
                .to_owned(),
        ),
        Ok(DesktopLaunch::NotInstalled) => (
            false,
            "Для Gemini и AI Studio в браузере нужен Google Chrome. Установите его и включите обход ещё раз."
                .to_owned(),
        ),
        Ok(DesktopLaunch::ElevatedSession(reason)) | Err(reason) => {
            crate::net::relay::log_event(&format!("Браузерный CONNECT не запущен: {reason}"));
            (
                false,
                format!("Gemini и AI Studio не открылись через резервный канал: {reason}"),
            )
        }
    };
    summary.notes.push(note);
    ok
}

/// The verdict titles of one operation: complete, limited, failed.
type Verdicts = (&'static str, &'static str, &'static str);

const UNLOCK_VERDICTS: Verdicts = (
    "Готово — обход включён",
    "Обход включён, но есть замечания",
    "Обход не включён",
);

fn finish_setup(status: SetupStatus, started: Instant, verdicts: Verdicts, summary: &Summary) {
    let (colour, mark, title) = match status {
        SetupStatus::Complete => ("\x1b[92m", "✓", verdicts.0),
        SetupStatus::Limited => ("\x1b[93m", "!", verdicts.1),
        SetupStatus::Failed => ("\x1b[91m", "✗", verdicts.2),
    };
    let seconds = started.elapsed().as_secs();
    let time = format!("{}:{:02}", seconds / 60, seconds % 60);
    let width = 64usize;
    let padding = width.saturating_sub(title.chars().count() + time.chars().count() + 2);
    println!("\n  \x1b[90m{}\x1b[0m", "─".repeat(width));
    println!(
        "  {colour}{mark} {title}\x1b[0m{}\x1b[90m{time}\x1b[0m",
        " ".repeat(padding)
    );
    println!("  \x1b[90m{}\x1b[0m", "─".repeat(width));
    match (status, summary.next) {
        (SetupStatus::Failed, _) => {
            println!("  Причина и что сделать — в строке с ✗ выше.");
        }
        (_, Some(next)) => println!("  \x1b[96mЧто дальше:\x1b[0m {next}"),
        (_, None) => println!(
            "  \x1b[96mЧто дальше:\x1b[0m перезапустите Antigravity и войдите в аккаунт Google."
        ),
    }
    if !summary.notes.is_empty() {
        println!("\n  Обратите внимание:");
        for note in &summary.notes {
            println!("    • {note}");
        }
    }
    if status != SetupStatus::Complete {
        println!();
        print_error_details();
    }
}

pub fn handle_unlock_all() -> bool {
    let started = Instant::now();
    clear_screen();
    banner();
    println!("  ВКЛЮЧЕНИЕ ОБХОДА\n");
    let mut summary = Summary::default();
    if !check_vpn_before_setup() {
        finish_setup(SetupStatus::Failed, started, UNLOCK_VERDICTS, &summary);
        pause();
        return false;
    }
    #[cfg(windows)]
    let launch = crate::system::env::args().nth(1).is_none();
    #[cfg(not(windows))]
    let launch = false;
    let steps = Steps::new(if launch { 5 } else { 4 });
    let mut status = SetupStatus::Failed;
    let outcome = continue_setup(patch_installations(&steps), || {
        #[cfg(windows)]
        if launch {
            status = apply_connection_and_launch(&steps, &mut summary);
            return status.succeeded();
        }
        status = apply_connection(&steps, &mut summary);
        status.succeeded()
    });
    let ok = outcome.succeeded();
    if !ok && status.succeeded() {
        status = SetupStatus::Limited;
        summary.notes.insert(
            0,
            "Не все файлы Antigravity удалось настроить — подробности выше.".into(),
        );
    }
    finish_setup(status, started, UNLOCK_VERDICTS, &summary);
    pause();
    ok
}
pub fn handle_patch_files_only() -> bool {
    let ok = if let Some(path) = crate::system::env::args().nth(2) {
        patch_root(&expand_env_vars(&path))
    } else {
        patch_installations(&Steps::unnumbered()).succeeded()
    };
    show_result(ok);
    pause();
    ok
}
pub fn handle_dns_only() -> bool {
    const VERDICTS: Verdicts = (
        "Готово — подключение настроено",
        "Подключение настроено, но есть замечания",
        "Подключение не настроено",
    );
    let started = Instant::now();
    let mut summary = Summary::default();
    if !check_vpn_before_setup() {
        finish_setup(SetupStatus::Failed, started, VERDICTS, &summary);
        pause();
        return false;
    }
    summary.next = Some("перезапустите Antigravity, чтобы он подхватил новые настройки.");
    let status = apply_connection(&Steps::new(3), &mut summary);
    finish_setup(status, started, VERDICTS, &summary);
    pause();
    status.succeeded()
}

fn check_vpn_before_setup() -> bool {
    #[cfg(windows)]
    if crate::net::windows_connect::vpn_present() {
        println!("  \x1b[93m!\x1b[0m Включён VPN. Он может помешать настройке.");
        println!("    Если VPN сейчас не нужен, лучше временно его отключить.\n");
    }
    match crate::net::preflight() {
        Ok(()) => true,
        Err(message) => {
            crate::net::relay::log_event(&message);
            print_problem(2, "Включение обхода приостановлено", &message, None);
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
    show_result(patch_targets(targets, &Steps::unnumbered()).succeeded());
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
            println!("\n  В {} есть настроенные файлы:", display_path(root));
            print_found_targets(root, &patched);
            println!("  Без сохранённого пути пункт [6] их не найдёт.\n");
            println!("  [1]  Вернуть исходные файлы и убрать путь");
            println!("  [2]  Только убрать путь — файлы останутся настроенными");
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
    run_file_step(&Steps::unnumbered(), RESTORE_STEP, targets, restore_target)
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
            BinaryState::Patched => "настроено",
            BinaryState::Stock => "не настроено",
            BinaryState::PartiallyPatched => "настроено частично",
            BinaryState::Unknown => "версия не распознана",
        };
        println!(
            "    • {} — {} \x1b[90m({state})\x1b[0m",
            component_name(target.kind),
            file.display()
        );
    }
}

fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
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
            println!("  \x1b[93m! Нужно закрыть Antigravity\x1b[0m");
            println!("    Пока он открыт, его файлы нельзя изменить.");
            println!("    \x1b[90mОткрыто сейчас: {}\x1b[0m", holders.join(", "));
            println!("    Сохраните работу: несохранённые изменения будут потеряны.\n");
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
    let started = Instant::now();
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
    let steps = Steps::new(2);
    let mut ok = true;
    if let Some(root) = explicit_root.filter(|_| targets.is_empty()) {
        print_problem(
            2,
            "Файлы Antigravity не найдены",
            &format!("в папке {} нечего возвращать", display_path(&root)),
            Some("проверьте путь к установке."),
        );
        ok = false;
    }
    if !targets.is_empty() {
        ok &= run_file_step(&steps, RESTORE_STEP, targets, restore_target);
    }
    let progress = Progress::new();
    progress.stage(&steps, "Отключаем обход в системе", "Настройки системы");
    let endpoint_errors = crate::core::endpoint::remove_all();
    if !endpoint_errors.is_empty() {
        progress.finish(false);
        drop(progress);
        for error in endpoint_errors {
            print_problem(6, "Не удалось вернуть настройки Antigravity", &error, None);
        }
        print_problem(
            6,
            "Подключение оставлено включённым",
            "без прежних настроек Antigravity потерял бы связь",
            Some("закройте Antigravity и выберите пункт 6 ещё раз."),
        );
        finish_setup(
            SetupStatus::Failed,
            started,
            ROLLBACK_VERDICTS,
            &Summary::default(),
        );
        pause();
        return false;
    }
    let mut problems = Vec::new();
    match remove_dns_rules() {
        Err(error) => problems.push(("Не удалось вернуть настройки подключения", error)),
        Ok(()) =>
        {
            #[cfg(windows)]
            if let Err(error) = crate::net::windows_connect::disable() {
                problems.push(("Не удалось отключить резервный канал", error));
            }
        }
    }
    progress.finish(problems.is_empty());
    drop(progress);
    for (message, error) in &problems {
        print_problem(6, message, error, None);
    }
    ok &= problems.is_empty();
    let mut summary = Summary {
        next: Some("можно открыть Antigravity — он работает так же, как до включения обхода."),
        notes: Vec::new(),
    };
    if !ok {
        summary
            .notes
            .push("Резервные копии исходных файлов сохранены — ничего не потеряно.".into());
    }
    let status = if ok {
        SetupStatus::Complete
    } else {
        SetupStatus::Failed
    };
    finish_setup(status, started, ROLLBACK_VERDICTS, &summary);
    pause();
    ok
}

const RESTORE_STEP: (&str, &str) = ("Возвращаем исходные файлы", "Исходные файлы Antigravity");

const ROLLBACK_VERDICTS: Verdicts = (
    "Готово — обход отключён",
    "Обход отключён, но есть замечания",
    "Обход отключён не полностью",
);

pub fn handle_diagnostics() -> bool {
    clear_screen();
    banner();
    println!("  ПРОВЕРКА ПОДКЛЮЧЕНИЯ\n");
    // Reading the IDE logs does not depend on the network checks.
    let observation = std::thread::spawn(crate::model_status::snapshot);
    let reports = {
        let progress = Progress::new();
        progress.working("Проверяем связь с серверами Google");
        crate::net::health::probe_all()
    };
    let mut ok = true;
    for report in &reports {
        let label = capitalized(crate::net::server_label(&report.host));
        if let Some(error) = &report.error {
            operation_error(&format!("{label}: нет связи"), error);
            ok = false;
        } else {
            println!("  \x1b[92m✓\x1b[0m {label}: связь есть");
        }
    }
    println!("\n  Проверена только связь с серверами. Работает ли модель в вашем аккаунте,");
    println!("  эта проверка не показывает: откройте Antigravity и отправьте короткий запрос.");
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
