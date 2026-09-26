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
    let network = if running.is_err() {
        "\x1b[93mНе удалось проверить службу\x1b[0m"
    } else if rules > 0 && running == Ok(true) {
        "\x1b[92mВключён\x1b[0m"
    } else if rules > 0 {
        "\x1b[93mНужна проверка\x1b[0m"
    } else {
        "\x1b[90mВыключен\x1b[0m"
    };
    status_row("Обход:", network);
    status_row("Antigravity:", component_status(status.core_status));
    let ide = if !status.incomplete_ide_installations.is_empty() {
        "\x1b[93mПереустановите Antigravity IDE\x1b[0m"
    } else if !status.ide_installations.is_empty() {
        "\x1b[92mУстановлена\x1b[0m"
    } else {
        "\x1b[90mНе найдена\x1b[0m"
    };
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
