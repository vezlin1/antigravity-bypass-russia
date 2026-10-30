use crate::core::detector::get_quick_status;
use crate::core::patcher::BinaryState;

pub fn banner() {
    println!(
        "\x1b[96m=====================================================================\x1b[0m"
    );
    println!(
        "\x1b[96m{:^69}\x1b[0m",
        format!("ANTIGRAVITY-BYPASS-RUSSIA (v{})", env!("CARGO_PKG_VERSION"))
    );
    println!(
        "\x1b[96m=====================================================================\x1b[0m"
    );
    println!(" Открытая утилита обхода блокировок и чистого отката\n");
}

pub fn print_dashboard() {
    let (rules, _, _) = crate::net::nrpt::get_nrpt_status_info();
    let running = crate::system::service::running_state();
    let hosts_count = crate::net::hosts::owned_entries()
        .ok()
        .map(|entries| entries.len());
    let status = get_quick_status();
    let title = " ТЕКУЩИЙ СТАТУС ";
    let left = (67 - title.chars().count()) / 2;
    let right = 67 - title.chars().count() - left;
    println!(
        "\x1b[90m╭{}\x1b[96m{}\x1b[90m{}╮\x1b[0m",
        "─".repeat(left),
        title,
        "─".repeat(right)
    );
    println!("\x1b[90m│{}│\x1b[0m", " ".repeat(67));
    let network = network_status(rules, running.ok(), hosts_count);
    status_row("Обход:", network);
    status_row("Antigravity:", component_status(status.core_status));
    let ide = ide_display_status(&status);
    status_row("Antigravity IDE:", ide);
    let cli = if status.cli_status.is_none() && !status.cli_launchers.is_empty() {
        "\x1b[93mНужна проверка\x1b[0m"
    } else {
        component_status(status.cli_status)
    };
    status_row("Antigravity CLI:", cli);
    let model = crate::model_status::snapshot();
    let colour = if model.warning() {
        "\x1b[93m"
    } else {
        "\x1b[90m"
    };
    status_row(
        "Модель (журнал):",
        &format!("{colour}{}\x1b[0m", model.label()),
    );
    println!("\x1b[90m│{}│\x1b[0m", " ".repeat(67));
    println!("\x1b[90m╰{}╯\x1b[0m\n", "─".repeat(67));
}

fn network_status(
    rules: usize,
    service_running: Option<bool>,
    hosts_count: Option<usize>,
) -> &'static str {
    match hosts_count {
        Some(count) if count == crate::net::provider::NRPT_AGENT.len() => {
            // Pins describe complete installed Agent coverage; no connection
            // probe ran here. A running process or a single DNS rule alone
            // cannot establish that the remaining domains were configured.
            return "\x1b[92mНастроен (hosts)\x1b[0m";
        }
        Some(count) if count > 0 => return "\x1b[93mНужна проверка (hosts)\x1b[0m",
        None => return "\x1b[93mНе удалось проверить hosts\x1b[0m",
        _ => {}
    }
    match (rules, service_running) {
        (_, None) => "\x1b[93mНе удалось проверить службу\x1b[0m",
        (count, _) if count > 0 => "\x1b[93mНужна проверка\x1b[0m",
        (_, Some(true)) => "\x1b[93mНужна проверка\x1b[0m",
        _ => "\x1b[90mВыключен\x1b[0m",
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
        assert_eq!(ide_display_status(&status), "\x1b[90mНе найдена\x1b[0m");

        status.ide_installations.push(PathBuf::from("/ide"));
        assert_eq!(ide_display_status(&status), "\x1b[92mУстановлена\x1b[0m");

        status.ide_status = Some(BinaryState::Stock);
        assert_eq!(ide_display_status(&status), "\x1b[93mНе пропатчено\x1b[0m");

        status.ide_status = Some(BinaryState::Patched);
        assert_eq!(ide_display_status(&status), "\x1b[92mПропатчено\x1b[0m");

        status
            .incomplete_ide_installations
            .push(PathBuf::from("/ide"));
        assert_eq!(
            ide_display_status(&status),
            "\x1b[93mПереустановите Antigravity IDE\x1b[0m"
        );
    }

    #[test]
    fn hosts_configuration_does_not_require_a_relay_or_mask_partial_pins() {
        let complete = crate::net::provider::NRPT_AGENT.len();
        for service in [Some(true), Some(false), None] {
            for rules in [0, 1, 30] {
                assert!(network_status(rules, service, Some(complete)).contains("Настроен (hosts)"));
                assert!(network_status(rules, service, Some(1)).contains("Нужна проверка (hosts)"));
                assert!(network_status(rules, service, None).contains("Не удалось проверить hosts"));
            }
        }
        assert!(network_status(0, Some(false), Some(0)).contains("Выключен"));
        assert!(network_status(1, Some(true), Some(0)).contains("Нужна проверка"));
        assert!(network_status(0, Some(true), Some(0)).contains("Нужна проверка"));
        assert!(network_status(1, Some(false), Some(0)).contains("Нужна проверка"));
        assert!(network_status(1, None, Some(0)).contains("Не удалось проверить службу"));
    }
}

fn ide_display_status(status: &crate::core::detector::SystemComponentsStatus) -> &'static str {
    if !status.incomplete_ide_installations.is_empty() {
        "\x1b[93mПереустановите Antigravity IDE\x1b[0m"
    } else if let Some(state) = status.ide_status {
        component_status(Some(state))
    } else if !status.ide_installations.is_empty() {
        "\x1b[92mУстановлена\x1b[0m"
    } else {
        "\x1b[90mНе найдена\x1b[0m"
    }
}

fn component_status(status: Option<BinaryState>) -> &'static str {
    match status {
        Some(BinaryState::Patched) => "\x1b[92mПропатчено\x1b[0m",
        Some(BinaryState::Stock) => "\x1b[93mНе пропатчено\x1b[0m",
        Some(BinaryState::PartiallyPatched | BinaryState::Unknown) => {
            "\x1b[93mНужна проверка\x1b[0m"
        }
        None => "\x1b[90mНе найдено\x1b[0m",
    }
}

// Pad the visible text, not ANSI colour sequences, to keep the right border straight.
fn status_row(label: &str, status: &str) {
    let (colour, icon) = if status.starts_with("\x1b[92m") {
        ("\x1b[92m", "✓")
    } else if status.starts_with("\x1b[93m") {
        ("\x1b[93m", "!")
    } else {
        ("\x1b[90m", "–")
    };
    let text = status
        .strip_prefix(colour)
        .unwrap_or(status)
        .strip_suffix("\x1b[0m")
        .unwrap_or(status);
    let prefix = format!("  {label:<18} ");
    let padding = 67usize.saturating_sub(prefix.chars().count() + 4 + text.chars().count());
    println!(
        "\x1b[90m│\x1b[0m{prefix}{colour}[{icon}] {text}\x1b[0m{}\x1b[90m│\x1b[0m",
        " ".repeat(padding)
    );
}
