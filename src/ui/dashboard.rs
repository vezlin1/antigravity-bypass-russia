use crate::core::detector::get_quick_status;
use crate::core::patcher::BinaryState;
use crate::ui::style::{self, paint, Tone};

/// One status: what it means and what it says.
type Status = (Tone, &'static str);

pub fn banner() {
    println!();
    println!(
        "{}{}  {}",
        style::INDENT,
        style::bold(&paint(Tone::Accent, "ANTIGRAVITY BYPASS RUSSIA")),
        paint(Tone::Muted, concat!("v", env!("CARGO_PKG_VERSION")))
    );
    println!(
        "{}{}\n",
        style::INDENT,
        paint(
            Tone::Muted,
            "Открытая утилита обхода блокировок с чистым откатом"
        )
    );
}

pub fn print_dashboard() {
    let (rules, _, _) = crate::net::nrpt::get_nrpt_status_info();
    let running = crate::system::service::running_state();
    let hosts_count = crate::net::hosts::owned_entries()
        .ok()
        .map(|entries| entries.len());
    let status = get_quick_status();
    let cli = if status.cli_status.is_none() && !status.cli_launchers.is_empty() {
        (Tone::Warn, "Нужна проверка")
    } else {
        component_status(status.cli_status)
    };
    let model = crate::model_status::snapshot();
    let model_tone = if model.warning() {
        Tone::Warn
    } else {
        Tone::Muted
    };
    let rows = [
        row("Обход", network_status(rules, running.ok(), hosts_count)),
        row("Antigravity", component_status(status.core_status)),
        row("Antigravity IDE", ide_display_status(&status)),
        row("Antigravity CLI", cli),
        row("Модель (журнал)", (model_tone, model.label())),
    ];
    style::panel("Текущий статус", &rows);
    println!();
}

fn row(label: &str, (tone, text): Status) -> String {
    format!("{label:<17} {}", style::status(tone, text))
}

fn network_status(
    rules: usize,
    service_running: Option<bool>,
    hosts_count: Option<usize>,
) -> Status {
    match hosts_count {
        Some(count) if count == crate::net::provider::NRPT_AGENT.len() => {
            // Pins describe complete installed Agent coverage; no connection
            // probe ran here. A running process or a single DNS rule alone
            // cannot establish that the remaining domains were configured.
            return (Tone::Ok, "Включён");
        }
        Some(count) if count > 0 => return (Tone::Warn, "Включён не полностью"),
        None => return (Tone::Warn, "Не удалось проверить системный список адресов"),
        _ => {}
    }
    match (rules, service_running) {
        (_, None) => (Tone::Warn, "Не удалось проверить фоновую службу"),
        (count, _) if count > 0 => (Tone::Warn, "Нужна проверка"),
        (_, Some(true)) => (Tone::Warn, "Нужна проверка"),
        _ => (Tone::Muted, "Выключен"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::detector::SystemComponentsStatus;
    use crate::core::patcher::BinaryState;
    use std::path::PathBuf;

    #[test]
    fn ide_display_status_reflects_patch_state() {
        let mut status = SystemComponentsStatus::default();
        assert_eq!(ide_display_status(&status), (Tone::Muted, "Не найдена"));

        status.ide_installations.push(PathBuf::from("/ide"));
        assert_eq!(ide_display_status(&status), (Tone::Ok, "Установлена"));

        status.ide_status = Some(BinaryState::Stock);
        assert_eq!(ide_display_status(&status), (Tone::Warn, "Не настроено"));

        status.ide_status = Some(BinaryState::Patched);
        assert_eq!(ide_display_status(&status), (Tone::Ok, "Настроено"));

        status
            .incomplete_ide_installations
            .push(PathBuf::from("/ide"));
        assert_eq!(
            ide_display_status(&status),
            (Tone::Warn, "Переустановите Antigravity IDE")
        );
    }

    #[test]
    fn hosts_configuration_does_not_require_a_relay_or_mask_partial_pins() {
        let complete = crate::net::provider::NRPT_AGENT.len();
        for service in [Some(true), Some(false), None] {
            for rules in [0, 1, 30] {
                assert_eq!(
                    network_status(rules, service, Some(complete)),
                    (Tone::Ok, "Включён")
                );
                assert_eq!(
                    network_status(rules, service, Some(1)),
                    (Tone::Warn, "Включён не полностью")
                );
                assert_eq!(
                    network_status(rules, service, None).1,
                    "Не удалось проверить системный список адресов"
                );
            }
        }
        assert_eq!(
            network_status(0, Some(false), Some(0)),
            (Tone::Muted, "Выключен")
        );
        for (rules, service) in [(1, Some(true)), (0, Some(true)), (1, Some(false))] {
            assert_eq!(
                network_status(rules, service, Some(0)),
                (Tone::Warn, "Нужна проверка")
            );
        }
        assert_eq!(
            network_status(1, None, Some(0)).1,
            "Не удалось проверить фоновую службу"
        );
    }
}

fn ide_display_status(status: &crate::core::detector::SystemComponentsStatus) -> Status {
    if !status.incomplete_ide_installations.is_empty() {
        (Tone::Warn, "Переустановите Antigravity IDE")
    } else if let Some(state) = status.ide_status {
        component_status(Some(state))
    } else if !status.ide_installations.is_empty() {
        (Tone::Ok, "Установлена")
    } else {
        (Tone::Muted, "Не найдена")
    }
}

fn component_status(status: Option<BinaryState>) -> Status {
    match status {
        Some(BinaryState::Patched) => (Tone::Ok, "Настроено"),
        Some(BinaryState::Stock) => (Tone::Warn, "Не настроено"),
        Some(BinaryState::PartiallyPatched | BinaryState::Unknown) => {
            (Tone::Warn, "Нужна проверка")
        }
        None => (Tone::Muted, "Не найдено"),
    }
}
