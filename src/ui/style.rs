//! One visual language for every screen: colours by meaning, one set of
//! icons, one frame style, and a width that follows the console window.

use std::io::IsTerminal;
use std::sync::OnceLock;

/// What a piece of text means; the colour and icon follow from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    /// Done, working, safe.
    Ok,
    /// Needs attention, but nothing is broken.
    Warn,
    /// Failed or destructive.
    Error,
    /// Headings, keys and the action in progress.
    Accent,
    /// Secondary text: hints, times, paths.
    Muted,
    /// Ordinary text.
    Plain,
}

impl Tone {
    fn code(self) -> &'static str {
        match self {
            Self::Ok => "92",
            Self::Warn => "93",
            Self::Error => "91",
            Self::Accent => "96",
            Self::Muted => "90",
            Self::Plain => "",
        }
    }

    pub fn icon(self) -> &'static str {
        match self {
            Self::Ok => "✓",
            Self::Warn => "!",
            Self::Error => "✗",
            Self::Accent => "›",
            Self::Muted | Self::Plain => "–",
        }
    }
}

pub const BULLET: &str = "•";
/// Left margin of every line on screen.
pub const INDENT: &str = "  ";

/// Colours only reach a terminal, and `NO_COLOR` turns them off.
pub fn colours_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var_os("NO_COLOR").is_none_or(|value| value.is_empty())
            && std::io::stdout().is_terminal()
    })
}

fn sgr(code: &str, text: &str) -> String {
    if code.is_empty() || !colours_enabled() {
        text.to_owned()
    } else {
        format!("\x1b[{code}m{text}\x1b[0m")
    }
}

pub fn paint(tone: Tone, text: &str) -> String {
    sgr(tone.code(), text)
}

pub fn bold(text: &str) -> String {
    sgr("1", text)
}

/// The tone's icon in the tone's colour.
pub fn mark(tone: Tone) -> String {
    paint(tone, tone.icon())
}

/// Icon and text in one colour: "✓ Включён".
pub fn status(tone: Tone, text: &str) -> String {
    paint(tone, &format!("{} {text}", tone.icon()))
}

/// Characters a string takes on screen, without colour codes.
pub fn visible_width(text: &str) -> usize {
    let mut width = 0;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // CSI: ESC [ parameters final-letter
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            width += 1;
        }
    }
    width
}

/// Shortens plain text to `limit` characters with an ellipsis.
pub fn fit(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_owned();
    }
    let mut short: String = text.chars().take(limit.saturating_sub(1)).collect();
    short.push('…');
    short
}

const MIN_WIDTH: usize = 44;
const MAX_WIDTH: usize = 76;

/// Width of frames and rules: the window minus the margins, within limits
/// that keep the layout readable.
pub fn width() -> usize {
    width_for(console_columns())
}

fn width_for(columns: Option<usize>) -> usize {
    columns
        .map(|columns| columns.saturating_sub(2 * INDENT.len()))
        .unwrap_or(MAX_WIDTH)
        .clamp(MIN_WIDTH, MAX_WIDTH)
}

#[cfg(windows)]
fn console_columns() -> Option<usize> {
    #[repr(C)]
    #[derive(Default)]
    struct Coord {
        x: i16,
        y: i16,
    }
    #[repr(C)]
    #[derive(Default)]
    struct SmallRect {
        left: i16,
        top: i16,
        right: i16,
        bottom: i16,
    }
    #[repr(C)]
    #[derive(Default)]
    struct ScreenBufferInfo {
        size: Coord,
        cursor: Coord,
        attributes: u16,
        window: SmallRect,
        maximum: Coord,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetStdHandle(handle: i32) -> *mut std::ffi::c_void;
        fn GetConsoleScreenBufferInfo(
            console: *mut std::ffi::c_void,
            info: *mut ScreenBufferInfo,
        ) -> i32;
    }
    const STD_OUTPUT_HANDLE: i32 = -11;
    let mut info = ScreenBufferInfo::default();
    // SAFETY: the handle comes from the process; the struct matches
    // CONSOLE_SCREEN_BUFFER_INFO and lives for the call.
    let ok = unsafe { GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &mut info) };
    let columns = i32::from(info.window.right) - i32::from(info.window.left) + 1;
    (ok != 0 && columns > 0)
        .then_some(columns as usize)
        .or_else(columns_from_env)
}

#[cfg(unix)]
fn console_columns() -> Option<usize> {
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: TIOCGWINSZ writes a winsize into the provided struct.
    let ok = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut size) } == 0;
    (ok && size.ws_col > 0)
        .then_some(usize::from(size.ws_col))
        .or_else(columns_from_env)
}

#[cfg(not(any(windows, unix)))]
fn console_columns() -> Option<usize> {
    columns_from_env()
}

fn columns_from_env() -> Option<usize> {
    std::env::var("COLUMNS").ok()?.trim().parse().ok()
}

/// A muted horizontal line across the content width.
pub fn rule() -> String {
    format!("{INDENT}{}", paint(Tone::Muted, &"─".repeat(width())))
}

/// The heading of a screen.
pub fn screen_title(text: &str) {
    println!("{INDENT}{}\n", bold(&paint(Tone::Accent, text)));
}

/// A menu line: the key in its tone, the label plain.
pub fn menu_item(key: &str, label: &str, tone: Tone) {
    println!("{INDENT}{}  {label}", paint(tone, &format!("[{key}]")));
}

/// A rounded frame with a title and one row per line; rows are padded or
/// shortened to the frame so the right border stays straight.
pub fn panel(title: &str, rows: &[String]) {
    let inner = width().saturating_sub(2);
    let border = |text: &str| paint(Tone::Muted, text);
    let title = fit(title, inner.saturating_sub(4));
    let line = "─".repeat(inner.saturating_sub(title.chars().count() + 3));
    println!(
        "{INDENT}{}{}{}",
        border("╭─ "),
        paint(Tone::Accent, &title),
        border(&format!(" {line}╮"))
    );
    let blank = format!(
        "{INDENT}{}{}{}",
        border("│"),
        " ".repeat(inner),
        border("│")
    );
    println!("{blank}");
    for row in rows {
        let row = if visible_width(row) > inner - 2 {
            // Colour codes cannot be cut safely: shorten the plain text.
            fit(&strip(row), inner - 2)
        } else {
            row.clone()
        };
        let padding = inner.saturating_sub(visible_width(&row) + 2);
        println!(
            "{INDENT}{}  {row}{}{}",
            border("│"),
            " ".repeat(padding),
            border("│")
        );
    }
    println!("{blank}");
    println!("{INDENT}{}", border(&format!("╰{}╯", "─".repeat(inner))));
}

fn strip(text: &str) -> String {
    let mut plain = String::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            plain.push(c);
        }
    }
    plain
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn width_follows_the_window_within_limits() {
        assert_eq!(width_for(None), MAX_WIDTH);
        assert_eq!(width_for(Some(200)), MAX_WIDTH);
        assert_eq!(width_for(Some(70)), 66);
        assert_eq!(width_for(Some(30)), MIN_WIDTH);
    }

    #[test]
    fn colour_codes_take_no_space_and_can_be_removed() {
        let text = "\x1b[92m✓ Включён\x1b[0m";
        assert_eq!(visible_width(text), 9);
        assert_eq!(strip(text), "✓ Включён");
        assert_eq!(visible_width("Обход"), 5);
    }

    #[test]
    fn every_tone_has_one_icon() {
        assert_eq!(Tone::Ok.icon(), "✓");
        assert_eq!(Tone::Warn.icon(), "!");
        assert_eq!(Tone::Error.icon(), "✗");
        assert_eq!(Tone::Muted.icon(), "–");
    }
}
