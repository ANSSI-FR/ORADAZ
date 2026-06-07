// Theme module handling coloured output and fallback to ASCII when colour is disabled.
use anstyle::{AnsiColor, Effects, Style};
use std::env;
use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum UiMode {
    Color,
    NoColor,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Icon {
    Ok,
    Warn,
    Err,
    Info,
    Arrow,
    Bullet,
    Selected,
    LeftUpTable,
    LeftBottomTable,
    RightBottomTable,
    RightUpTable,
    UpOrBottomTable,
    LeftOrRightTable,
    LeftUpBoldTable,
    LeftBottomBoldTable,
    RightBottomBoldTable,
    RightUpBoldTable,
    UpOrBottomBoldTable,
    LeftOrRightBoldTable,
    Spinner(u8), // frame index 0-7
}

static FORCE_NO_COLOR: AtomicBool = AtomicBool::new(false);

/// Initialize UI mode. Call once at startup.
pub fn init(force_no_color: bool) {
    // Enable Virtual Terminal processing on Windows so ANSI escape codes work.
    #[cfg(windows)]
    {
        crate::utils::ui::vt::enable_vt_processing();
    }

    // environment variable overrides
    let env_no = env::var("NO_COLOR").is_ok();
    let term = std::io::stdout().is_terminal();
    let mode = if force_no_color || env_no || !term {
        UiMode::NoColor
    } else {
        UiMode::Color
    };
    set_mode(mode);
    crate::utils::logger::config::NO_COLOR.store(mode == UiMode::NoColor, Ordering::Relaxed);
    FORCE_NO_COLOR.store(force_no_color, Ordering::Relaxed);
}

pub fn set_mode(mode: UiMode) {
    UI_MODE.store(mode as u8, Ordering::Relaxed);
}

static UI_MODE: AtomicU8 = AtomicU8::new(UiMode::Color as u8);

fn current_mode() -> UiMode {
    match UI_MODE.load(Ordering::Relaxed) {
        0 => UiMode::Color,
        _ => UiMode::NoColor,
    }
}

fn with_color<F>(s: &str, color_fn: F) -> String
where
    F: FnOnce(&str) -> String,
{
    match current_mode() {
        UiMode::Color => color_fn(s),
        UiMode::NoColor => s.to_string(),
    }
}

/// Visual styles used across oradaz output. Centralises every colour/effect so
/// `anstyle` is imported in this module only; other modules paint via [`paint`].
#[derive(Clone, Copy)]
pub enum Paint {
    Blue,
    Green,
    Yellow,
    YellowBold,
    Red,
    Dim,
    BlinkRedBold,
}

fn style_of(p: Paint) -> Style {
    match p {
        Paint::Blue => Style::new().fg_color(Some(AnsiColor::Blue.into())),
        Paint::Green => Style::new().fg_color(Some(AnsiColor::Green.into())),
        Paint::Yellow => Style::new().fg_color(Some(AnsiColor::Yellow.into())),
        Paint::YellowBold => Style::new()
            .fg_color(Some(AnsiColor::Yellow.into()))
            .effects(Effects::BOLD),
        Paint::Red => Style::new().fg_color(Some(AnsiColor::Red.into())),
        Paint::Dim => Style::new().effects(Effects::DIMMED),
        Paint::BlinkRedBold => Style::new()
            .fg_color(Some(AnsiColor::Red.into()))
            .effects(Effects::BOLD | Effects::BLINK),
    }
}

/// Wrap `s` in the ANSI escapes for `p`. Always paints — callers needing the
/// NoColor fallback gate on [`mode`] (or use the guarded helpers below).
pub fn paint(p: Paint, s: &str) -> String {
    // `BlinkRedBold` is emitted as the single combined SGR (as `ansiterm` did)
    // rather than anstyle's three separate escapes, so its byte length is
    // unchanged: the auth banner feeds this string to `calculate_rendered_lines`,
    // which counts raw chars (escapes included) to size the live region.
    if matches!(p, Paint::BlinkRedBold) {
        return format!("\x1b[1;5;31m{s}\x1b[0m");
    }
    let st = style_of(p);
    format!("{}{}{}", st.render(), s, st.render_reset())
}

/// Return string representation of an icon according to current mode.
pub fn icon(i: Icon) -> String {
    match (i, current_mode()) {
        (Icon::Ok, UiMode::Color) => "✔".to_string(),
        (Icon::Ok, UiMode::NoColor) => "OK".to_string(),
        (Icon::Warn, UiMode::Color) => "⚠".to_string(),
        (Icon::Warn, UiMode::NoColor) => "!!".to_string(),
        (Icon::Err, UiMode::Color) => "✖".to_string(),
        (Icon::Err, UiMode::NoColor) => "!!".to_string(),
        (Icon::Info, UiMode::Color) => "ℹ".to_string(),
        (Icon::Info, UiMode::NoColor) => "i".to_string(),
        (Icon::Arrow, UiMode::Color) => "➜".to_string(),
        (Icon::Arrow, UiMode::NoColor) => ">".to_string(),
        (Icon::Bullet, UiMode::Color) => "•".to_string(),
        (Icon::Bullet, UiMode::NoColor) => "*".to_string(),
        (Icon::Selected, UiMode::Color) => "▸".to_string(),
        (Icon::Selected, UiMode::NoColor) => ">".to_string(),
        (Icon::LeftUpTable, UiMode::Color) => "╭".to_string(),
        (Icon::LeftUpTable, UiMode::NoColor) => "+".to_string(),
        (Icon::LeftBottomTable, UiMode::Color) => "╰".to_string(),
        (Icon::LeftBottomTable, UiMode::NoColor) => "+".to_string(),
        (Icon::RightBottomTable, UiMode::Color) => "╯".to_string(),
        (Icon::RightBottomTable, UiMode::NoColor) => "+".to_string(),
        (Icon::RightUpTable, UiMode::Color) => "╮".to_string(),
        (Icon::RightUpTable, UiMode::NoColor) => "+".to_string(),
        (Icon::UpOrBottomTable, UiMode::Color) => "─".to_string(),
        (Icon::UpOrBottomTable, UiMode::NoColor) => "-".to_string(),
        (Icon::LeftOrRightTable, UiMode::Color) => "│".to_string(),
        (Icon::LeftOrRightTable, UiMode::NoColor) => "|".to_string(),
        (Icon::LeftUpBoldTable, UiMode::Color) => "┏".to_string(),
        (Icon::LeftUpBoldTable, UiMode::NoColor) => "+".to_string(),
        (Icon::LeftBottomBoldTable, UiMode::Color) => "┗".to_string(),
        (Icon::LeftBottomBoldTable, UiMode::NoColor) => "+".to_string(),
        (Icon::RightBottomBoldTable, UiMode::Color) => "┛".to_string(),
        (Icon::RightBottomBoldTable, UiMode::NoColor) => "+".to_string(),
        (Icon::RightUpBoldTable, UiMode::Color) => "┓".to_string(),
        (Icon::RightUpBoldTable, UiMode::NoColor) => "+".to_string(),
        (Icon::UpOrBottomBoldTable, UiMode::Color) => "━".to_string(),
        (Icon::UpOrBottomBoldTable, UiMode::NoColor) => "-".to_string(),
        (Icon::LeftOrRightBoldTable, UiMode::Color) => "┃".to_string(),
        (Icon::LeftOrRightBoldTable, UiMode::NoColor) => "|".to_string(),
        (Icon::Spinner(frame), UiMode::Color) => {
            // simple spinner frames
            let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"];
            frames[(frame as usize) % frames.len()].to_string()
        }
        (Icon::Spinner(frame), UiMode::NoColor) => {
            // ASCII spinner frames for NoColor mode
            let frames = ["|", "/", "-", "\\"];
            frames[(frame as usize) % frames.len()].to_string()
        }
    }
}

pub fn mode() -> UiMode {
    current_mode()
}

pub fn header(s: &str) -> String {
    let wrapped = format!("=== {} ===", s);
    with_color(&wrapped, |s| paint(Paint::Blue, s))
}

pub fn success(s: &str) -> String {
    with_color(s, |s| paint(Paint::Green, s))
}

pub fn warn_text(s: &str) -> String {
    with_color(s, |s| paint(Paint::Yellow, s))
}

pub fn err_text(s: &str) -> String {
    with_color(s, |s| paint(Paint::Red, s))
}

pub fn dim(s: &str) -> String {
    with_color(s, |s| paint(Paint::Dim, s))
}

pub fn blink_red_bold(s: &str) -> String {
    with_color(s, |s| paint(Paint::BlinkRedBold, s))
}

pub fn blue(s: &str) -> String {
    with_color(s, |s| paint(Paint::Blue, s))
}

pub fn success_icon() -> String {
    match current_mode() {
        UiMode::Color => paint(Paint::Green, &icon(Icon::Ok)),
        UiMode::NoColor => icon(Icon::Ok),
    }
}

/// Force NoColor mode (e.g. when writing to a report file).
pub fn force_no_color() {
    set_mode(UiMode::NoColor);
}

// Convenience re-exports

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paint_emits_ansi_escapes_byte_identical_to_ansiterm() {
        // The anstyle migration must keep stdout byte-for-byte identical so the
        // live-region width math (`calculate_rendered_lines`, which counts raw
        // chars) is unaffected. These are exactly the sequences `ansiterm` emitted.
        assert_eq!(paint(Paint::Blue, "x"), "\x1b[34mx\x1b[0m");
        assert_eq!(paint(Paint::Green, "x"), "\x1b[32mx\x1b[0m");
        assert_eq!(paint(Paint::Yellow, "x"), "\x1b[33mx\x1b[0m");
        assert_eq!(paint(Paint::Red, "x"), "\x1b[31mx\x1b[0m");
        assert_eq!(paint(Paint::Dim, "x"), "\x1b[2mx\x1b[0m");
        assert_eq!(paint(Paint::BlinkRedBold, "x"), "\x1b[1;5;31mx\x1b[0m");
    }

    #[test]
    fn paint_yellow_bold_combines_bold_and_yellow() {
        // YellowBold carries both the bold effect (param 1) and the yellow
        // foreground (param 33), wraps the text, and resets afterwards. Asserted
        // structurally (not byte-exact) so the test is robust to anstyle's SGR
        // parameter ordering.
        let painted = paint(Paint::YellowBold, "x");
        assert!(
            painted.starts_with("\x1b["),
            "should open with a CSI escape"
        );
        assert!(painted.contains('1'), "should carry the bold parameter");
        assert!(painted.contains("33"), "should carry the yellow foreground");
        assert!(painted.contains('x'), "should wrap the text");
        assert!(painted.ends_with("\x1b[0m"), "should reset at the end");
        assert_ne!(
            painted,
            paint(Paint::Yellow, "x"),
            "must differ from plain yellow"
        );
    }
}
