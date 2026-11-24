use crate::core::detector::{
    find_installation_targets, find_installations, find_targets_in_path, recover_installations,
    recover_targets_in_path, FoundTarget,
};
use crate::core::patcher::{patch_target, restore_target};
use crate::core::v8_cache::clear_ide_v8_caches;
use crate::net::{apply_dns_rules, remove_dns_rules, NetworkSetup, SetupProgress, SetupStage};
use crate::system::env::{display_path, expand_env_vars};
use crate::ui::dashboard::{banner, print_dashboard};
use crate::ui::style::{self, mark, paint, Tone};
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
    let log = crate::net::config::directory().join("network-events.log");
    println!(
        "  {}",
        paint(
            Tone::Muted,
            &format!("Журнал для поддержки: {}", log.display())
        )
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
    eprintln!("{pad}{} {message}", mark(Tone::Error));
    let readable = readable_cause(cause);
    if !readable.is_empty() {
        eprintln!("{pad}  {} {readable}", paint(Tone::Muted, "Причина:"));
    }
    if let Some(advice) = advice.or_else(|| advice_for(cause)) {
        eprintln!("{pad}  {} {advice}", paint(Tone::Accent, "Что сделать:"));
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
            println!(
                "      {} {label} {}",
                mark(Tone::Ok),
                paint(Tone::Muted, &format!("— {status}"))
            );
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
                    eprintln!("        {}", paint(Tone::Warn, line));
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
    if !ensure_application_closed(&paths, "настроить файлы") {
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
        println!(
            "\n  {} Перезапустите Antigravity, чтобы изменения вступили в силу.",
            style::status(Tone::Ok, "Готово.")
        );
    } else {
        eprintln!(
            "\n  {} Причина и что сделать — в строках с ✗ выше.",
            style::status(Tone::Error, "Не всё получилось.")
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
const BROWSER_VPN: &str =
    "Веб-версии Gemini и AI Studio могут не работать: во время настройки был \
     включён VPN. Если они не открываются в браузере, отключите VPN и включите обход ещё раз. \
     На Antigravity это не влияет.";

#[cfg(windows)]
const BROWSER_FOLLOWS_VPN: &str =
    "Пока включён VPN, веб-версии Gemini и AI Studio открываются через него. Когда вы \
     отключите VPN, утилита сама включит для них обход, перезапускать её не нужно. \
     На Antigravity это не влияет.";

#[cfg(windows)]
fn apply_connection_and_launch(steps: &Steps, summary: &mut Summary) -> SetupStatus {
    use crate::net::windows_connect;
    use crate::system::windows_connect_launch::{
        launch_desktop, remove_retired_browser_profile, DesktopLaunch,
    };

    remove_retired_browser_profile();
    let setup = configure_connection_with(|| configure_network(steps), apply_endpoints);
    let browser_dns = setup
        .as_ref()
        .is_ok_and(|setup| setup.browser_dns_confirmed);
    let vpn = windows_connect::vpn_present();
    let try_app = setup.is_ok() || windows_connect::fallback_available();
    match &setup {
        Ok(setup) => {
            network_result(setup, summary);
        }
        Err(error) if try_app => {
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
    // The VPN blocked the local DNS service: the service itself moves the web
    // versions to the bypass once the VPN is off (net::web_rules).
    let follows_vpn = vpn && setup.as_ref().is_ok_and(|setup| !setup.local_relay_running);
    if !browser_dns && vpn {
        // With a VPN the reason is known: say it instead of the generic note.
        summary.notes.retain(|note| note != BROWSER_UNCHECKED);
        summary.notes.push(
            if follows_vpn {
                BROWSER_FOLLOWS_VPN
            } else {
                BROWSER_VPN
            }
            .into(),
        );
    }
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
    progress.finish(antigravity_ok);
    drop(progress);
    if setup.is_ok() && antigravity_ok && (browser_dns || follows_vpn) {
        SetupStatus::Complete
    } else if setup.is_ok() || antigravity_ok {
        SetupStatus::Limited
    } else {
        SetupStatus::Failed
    }
}

/// The verdict titles of one operation: complete, limited, failed.
type Verdicts = (&'static str, &'static str, &'static str);

const UNLOCK_VERDICTS: Verdicts = (
    "Готово — обход включён",
    "Обход включён, но есть замечания",
    "Обход не включён",
);

fn finish_setup(status: SetupStatus, started: Instant, verdicts: Verdicts, summary: &Summary) {
    let (tone, title) = match status {
        SetupStatus::Complete => (Tone::Ok, verdicts.0),
        SetupStatus::Limited => (Tone::Warn, verdicts.1),
        SetupStatus::Failed => (Tone::Error, verdicts.2),
    };
    let seconds = started.elapsed().as_secs();
    let time = format!("{}:{:02}", seconds / 60, seconds % 60);
    let headline = style::bold(&style::status(tone, title));
    let padding =
        style::width().saturating_sub(style::visible_width(&headline) + time.chars().count());
    println!("\n{}", style::rule());
    println!(
        "  {headline}{}{}",
        " ".repeat(padding),
        paint(Tone::Muted, &time)
    );
    println!("{}", style::rule());
    match (status, summary.next) {
        (SetupStatus::Failed, _) => {
            println!("  Причина и что сделать — в строке с ✗ выше.");
        }
        (_, next) => println!(
            "  {} {}",
            paint(Tone::Accent, "Что дальше:"),
            next.unwrap_or("перезапустите Antigravity и войдите в аккаунт Google.")
        ),
    }
    if !summary.notes.is_empty() {
        println!("\n  Обратите внимание:");
        for note in &summary.notes {
            println!("    {} {note}", style::BULLET);
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
    style::screen_title("ВКЛЮЧЕНИЕ ОБХОДА");
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
        println!(
            "  {} Включён VPN. Он может помешать настройке.",
            mark(Tone::Warn)
        );
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
        style::screen_title("ПУТИ К ANTIGRAVITY");
        println!("  Сохранённые пути:");
        for (index, path) in saved.iter().enumerate() {
            let note = if path.exists() {
                ""
            } else {
                "  (нет на диске)"
            };
            println!(
                "    {}. {}{}",
                index + 1,
                display_path(path),
                paint(Tone::Muted, note)
            );
        }
        println!();
        style::menu_item("1", "Добавить путь", Tone::Ok);
        style::menu_item("2", "Убрать сохранённый путь", Tone::Error);
        println!();
        style::menu_item("0", "Назад", Tone::Plain);
        println!();
        match prompt("  Выберите действие [0-2]: ").as_str() {
            "1" => {
                add_manual_path();
                return;
            }
            "2" => remove_manual_path(&saved),
            "0" | "" => return,
            _ => {
                println!("  {}", paint(Tone::Error, "Неверный выбор."));
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
    println!();
    style::menu_item("1", "Сохранить путь и настроить эти файлы", Tone::Ok);
    style::menu_item("0", "Отмена — ничего не сохранять", Tone::Plain);
    println!();
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
            style::menu_item("1", "Вернуть исходные файлы и убрать путь", Tone::Ok);
            style::menu_item(
                "2",
                "Только убрать путь — файлы останутся настроенными",
                Tone::Plain,
            );
            style::menu_item("0", "Отмена", Tone::Plain);
            println!();
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
        Ok(_) => println!("  {} Путь убран: {}", mark(Tone::Ok), display_path(root)),
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
    if !ensure_application_closed(&paths, "вернуть исходные файлы") {
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
            "    {} {} — {} {}",
            style::BULLET,
            component_name(target.kind),
            file.display(),
            paint(Tone::Muted, &format!("({state})"))
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
/// "Antigravity (12 процессов), служебный процесс Antigravity": open programs
/// by name, each process once. PIDs only help support; they go to the log.
fn describe_holders(holders: &[String]) -> String {
    let mut programs: Vec<(String, std::collections::BTreeSet<String>)> = Vec::new();
    for holder in holders {
        let (name, pid) = holder
            .rsplit_once(" (PID ")
            .map(|(name, pid)| (name, pid.trim_end_matches(')')))
            .unwrap_or((holder.as_str(), holder.as_str()));
        let program = program_name(name);
        match programs.iter_mut().find(|(known, _)| *known == program) {
            Some((_, pids)) => {
                pids.insert(pid.to_owned());
            }
            None => programs.push((program, [pid.to_owned()].into())),
        }
    }
    programs
        .into_iter()
        .map(|(program, pids)| match pids.len() {
            1 => program,
            count => format!("{program} ({count} {})", processes_word(count)),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn program_name(executable: &str) -> String {
    let name = executable
        .strip_suffix(".exe")
        .or_else(|| executable.strip_suffix(".EXE"))
        .unwrap_or(executable);
    let lower = name.to_lowercase();
    if lower.starts_with("language_server") {
        "служебный процесс Antigravity".into()
    } else if lower == "agy" || lower.starts_with("agy-") || lower.contains("antigravity-cli") {
        "Antigravity CLI".into()
    } else if lower.contains("antigravity") && lower.contains("ide") {
        "Antigravity IDE".into()
    } else if lower.starts_with("antigravity") {
        "Antigravity".into()
    } else {
        name.to_owned()
    }
}

fn processes_word(count: usize) -> &'static str {
    style::plural(count as u64, ["процесс", "процесса", "процессов"])
}

#[cfg(test)]
mod holder_tests {
    use super::{describe_holders, processes_word};

    #[test]
    fn processes_are_grouped_by_program_without_pids() {
        let mut holders = vec!["Antigravity (PID 17752)".to_string()];
        for pid in [
            11744, 13344, 17752, 20256, 20584, 26420, 29872, 31588, 35268, 5964, 6628,
        ] {
            holders.push(format!("Antigravity.exe (PID {pid})"));
        }
        holders.push("language_server.exe (PID 38816)".into());
        assert_eq!(
            describe_holders(&holders),
            "Antigravity (11 процессов), служебный процесс Antigravity"
        );
        assert_eq!(
            describe_holders(&[
                "Antigravity IDE.exe (PID 1)".into(),
                "agy.exe (PID 2)".into(),
                "agy.exe (PID 3)".into(),
                "Code.exe (PID 4)".into(),
            ]),
            "Antigravity IDE, Antigravity CLI (2 процесса), Code"
        );
        assert_eq!(
            [1, 2, 5, 11, 21, 22, 112].map(processes_word),
            [
                "процесс",
                "процесса",
                "процессов",
                "процессов",
                "процесс",
                "процесса",
                "процессов"
            ]
        );
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
            crate::net::relay::log_event(&format!(
                "Открытые процессы Antigravity: {}",
                holders.join(", ")
            ));
            println!(
                "  {}",
                style::status(Tone::Warn, "Antigravity сейчас открыт")
            );
            println!("    Чтобы изменить его файлы, его нужно закрыть.");
            println!(
                "    {}",
                paint(
                    Tone::Muted,
                    &format!("Открыто: {}", describe_holders(&holders))
                )
            );
            println!("    Несохранённые изменения будут потеряны — сохраните работу.\n");
            if crate::system::env::args().len() > 1 {
                print_problem(
                    2,
                    "Antigravity открыт",
                    "",
                    Some("закройте Antigravity и повторите команду."),
                );
                return false;
            }
            #[cfg(any(windows, unix))]
            style::menu_item("1", &format!("Закрыть Antigravity и {action}"), Tone::Ok);
            #[cfg(not(any(windows, unix)))]
            style::menu_item("1", &format!("Я закрыл Antigravity — {action}"), Tone::Ok);
            style::menu_item("0", "Отмена", Tone::Plain);
            println!();
            if choose(&["1", "0"]) == "0" {
                println!("  Отменено, ничего не изменено.");
                return false;
            }
            println!();
            let closed = {
                let progress = Progress::new();
                #[cfg(any(windows, unix))]
                progress.working("Закрываем Antigravity");
                #[cfg(not(any(windows, unix)))]
                progress.working("Проверяем, что Antigravity закрыт");
                crate::system::file_lock::close_application(paths)
            };
            if let Err(error) = closed {
                #[cfg(any(windows, unix))]
                let message = "Не удалось закрыть Antigravity";
                #[cfg(not(any(windows, unix)))]
                let message = "Antigravity ещё открыт";
                print_problem(
                    2,
                    message,
                    &error,
                    Some("закройте Antigravity вручную и повторите."),
                );
                print_error_details();
                pause();
                return false;
            }
            println!("  {} Antigravity закрыт\n", mark(Tone::Ok));
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
    style::screen_title("ОТКЛЮЧЕНИЕ ОБХОДА");
    if !ensure_application_closed(&paths, "отключить обход") {
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
        Ok(()) => {
            #[cfg(windows)]
            if let Err(error) = crate::net::windows_connect::disable() {
                problems.push(("Не удалось отключить резервный канал", error));
            }
            #[cfg(windows)]
            crate::system::windows_connect_launch::remove_retired_browser_profile();
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
    style::screen_title("ПРОВЕРКА ПОДКЛЮЧЕНИЯ");
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
            println!("  {} {label}: связь есть", mark(Tone::Ok));
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

        style::menu_item("1", "Включить обход", Tone::Ok);
        style::menu_item("2", "Настроить только файлы приложения", Tone::Plain);
        style::menu_item("3", "Настроить только подключение", Tone::Plain);
        style::menu_item("4", "Пути к Antigravity", Tone::Plain);
        style::menu_item("5", "Проверить подключение", Tone::Accent);
        style::menu_item("6", "Отключить обход", Tone::Error);
        style::menu_item("7", "Сохранить диагностику", Tone::Plain);
        println!();
        style::menu_item("0", "Выход", Tone::Plain);
        println!();

        match prompt("  Выберите действие [0-7]: ").as_str() {
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
                println!("  {}", paint(Tone::Error, "Неверный выбор."));
                std::thread::sleep(std::time::Duration::from_millis(400));
            }
        }
    }
}
