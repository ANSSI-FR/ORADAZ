use crate::utils::mutex::lock_force;

use crossterm::terminal;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex};

pub static PROGRESS_LINE_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Whether in-place, cursor-control live updates may be emitted.
///
/// They are only meaningful on a colour-capable interactive terminal. `NO_COLOR`
/// is set at startup whenever colour is disabled — by `--no-color`, the
/// `NO_COLOR` env var, OR a non-TTY stdout (see `ui::theme::init`). Guarding every
/// ANSI cursor sequence on this flag prevents escape codes from leaking into
/// piped output or `--no-color` runs; such runs fall back to plain line output.
fn live_updates_enabled() -> bool {
    !crate::utils::logger::config::NO_COLOR.load(Ordering::Relaxed)
}

/// Describes the state of the terminal's "live region" (the area where dynamic
/// content like progress bars or banners are displayed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveRegionState {
    None,
    Progress { lines: u16 },
    AuthBanner { lines: u16 },
    Prereq { lines: u16 },
    Step { lines: u16 },
}

pub static ACTIVE_LIVE_REGION: LazyLock<Mutex<LiveRegionState>> =
    LazyLock::new(|| Mutex::new(LiveRegionState::None));
pub static LIVE_REGION_TEXT: LazyLock<Mutex<String>> = LazyLock::new(|| Mutex::new(String::new()));
/// Serialises an entire terminal-render sequence (clear→write→redraw, or a
/// standalone redraw/tear-down) so concurrent log writers and the progress
/// ticker cannot interleave their stateful, *relative* cursor-control output.
/// Always the OUTERMOST lock: the `*_raw` primitives must NOT acquire it (they
/// run inside an already-guarded sequence), while the public
/// `clear_live_region_lines` / `redraw_live_region` / `tear_down_live_region`
/// wrappers acquire it for callers emitting a single standalone sequence.
static RENDER_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Shared serialisation lock for the unit tests that mutate the process-global
/// live-region state ([`ACTIVE_LIVE_REGION`] / [`LIVE_REGION_TEXT`]). Those tests
/// live in several modules (`live_region`, `logger`, `ui::progress`) but all run
/// in one test binary against the same globals, so they must take THIS one lock —
/// not a per-module lock — or they race (e.g. the long-running `ticker_terminates`
/// overwriting the state another module's test just tore down).
#[cfg(test)]
pub(crate) static LIVE_REGION_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Runs `f` while holding [`RENDER_LOCK`], serialising terminal rendering.
///
/// Used by composite sequences (`dump_event::write_to_terminal`,
/// `backend::handle_stdout`) that must hold the lock across `clear`→write→`redraw`
/// while calling the `*_raw` primitives. The closure must be synchronous — never
/// hold the guard across an `.await`.
pub fn with_render_lock<R>(f: impl FnOnce() -> R) -> R {
    let _guard = lock_force(&RENDER_LOCK);
    f()
}

/// Returns the number of visible terminal columns in `s`, ignoring ANSI CSI
/// escape sequences (e.g. `\x1b[34m` … `\x1b[0m`). These sequences are
/// invisible on screen but inflate `chars().count()`, causing
/// `calculate_rendered_lines` to over-estimate the number of wrapped lines and
/// scroll the cursor further up than needed — overwriting content above the
/// live region.
fn visible_len(s: &str) -> usize {
    if !s.contains('\x1b') {
        return s.chars().count();
    }
    let mut count = 0usize;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if let Some('[') = chars.next() {
                // CSI sequence: skip parameter/intermediate bytes until the
                // final byte (0x40–0x7E, i.e. '@'–'~').
                for c in chars.by_ref() {
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
            }
            // Other escape sequences (non-CSI): the one-char payload was already
            // consumed by `chars.next()` above — nothing extra to skip.
        } else {
            count += 1;
        }
    }
    count
}

pub fn calculate_rendered_lines(text: &str) -> u16 {
    let term_width = terminal::size().map(|(w, _)| w as usize).unwrap_or(80);
    if term_width == 0 {
        return text.lines().count() as u16;
    }

    let mut total = 0;
    for line in text.lines() {
        let len = visible_len(line);
        if len == 0 {
            total += 1;
        } else {
            total += (len as f64 / term_width as f64).ceil() as u16;
        }
    }
    total
}

/// Clears the current live region lines from the terminal without resetting the
/// state. Acquires [`RENDER_LOCK`]; use [`clear_live_region_lines_raw`] when
/// already inside a [`with_render_lock`] sequence.
pub fn clear_live_region_lines() {
    with_render_lock(clear_live_region_lines_raw);
}

/// [`RENDER_LOCK`]-free body of [`clear_live_region_lines`]. Call only while
/// holding [`RENDER_LOCK`] (e.g. inside [`with_render_lock`]).
pub fn clear_live_region_lines_raw() {
    if !live_updates_enabled() {
        return;
    }
    let state = *lock_force(&ACTIVE_LIVE_REGION);
    let lines_to_clear = match state {
        LiveRegionState::None => 0,
        LiveRegionState::Progress { lines } => lines,
        LiveRegionState::AuthBanner { lines } => lines,
        LiveRegionState::Prereq { lines } => lines,
        LiveRegionState::Step { lines } => lines,
    };
    if lines_to_clear > 0 {
        let out = std::io::stdout();
        let mut handle = out.lock();
        for _ in 0..lines_to_clear {
            let _ = handle.write_all(b"\x1B[1A\r\x1B[2K");
        }
        let _ = handle.flush();
    }
}

/// Clears the current live region from the terminal and resets the state to
/// `None`. Acquires [`RENDER_LOCK`].
pub fn tear_down_live_region() {
    with_render_lock(tear_down_live_region_raw);
}

/// [`RENDER_LOCK`]-free body of [`tear_down_live_region`]. Call only while holding
/// [`RENDER_LOCK`].
pub fn tear_down_live_region_raw() {
    let mut state = lock_force(&ACTIVE_LIVE_REGION);
    let lines_to_clear = match *state {
        LiveRegionState::None => 0,
        LiveRegionState::Progress { lines } => lines,
        LiveRegionState::AuthBanner { lines } => lines,
        LiveRegionState::Prereq { lines } => lines,
        LiveRegionState::Step { lines } => lines,
    };
    if live_updates_enabled() && lines_to_clear > 0 {
        let out = std::io::stdout();
        let mut handle = out.lock();
        for _ in 0..lines_to_clear {
            let _ = handle.write_all(b"\x1B[1A\r\x1B[2K");
        }
        let _ = handle.flush();
    }
    *state = LiveRegionState::None;
    PROGRESS_LINE_ACTIVE.store(false, Ordering::Relaxed);
}

/// Repaints the live region content to the terminal. Acquires [`RENDER_LOCK`];
/// use [`redraw_live_region_raw`] when already inside a [`with_render_lock`]
/// sequence.
pub fn redraw_live_region(move_up: bool) {
    with_render_lock(|| redraw_live_region_raw(move_up));
}

/// [`RENDER_LOCK`]-free body of [`redraw_live_region`]. Call only while holding
/// [`RENDER_LOCK`].
///
/// * `move_up` — if true, moves the cursor up by the number of lines in the region
///   before painting. Used by tickers to overwrite the previous frame.
///   If false, paints from the current cursor position. Used after printing a log
///   message to restore the region below the log.
pub fn redraw_live_region_raw(move_up: bool) {
    if !live_updates_enabled() {
        return;
    }
    let state = *lock_force(&ACTIVE_LIVE_REGION);
    match state {
        LiveRegionState::Progress { lines }
        | LiveRegionState::AuthBanner { lines }
        | LiveRegionState::Prereq { lines }
        | LiveRegionState::Step { lines } => {
            // lock_force instead of try_lock — try_lock silently drops frames
            // when another thread holds LIVE_REGION_TEXT, causing frozen counters
            // under heavy concurrent logging.
            let text = lock_force(&LIVE_REGION_TEXT);
            if !text.is_empty() {
                let mut out = std::io::stdout().lock();
                if move_up {
                    let up_seq = format!("\x1b[{}A", lines);
                    let _ = out.write_all(up_seq.as_bytes());
                }
                for line in text.lines() {
                    let _ = out.write_all(b"\x1b[2K");
                    let _ = out.write_all(line.as_bytes());
                    let _ = out.write_all(b"\n");
                }
                // Erase any orphan lines left by previously longer content.
                // When the live region shrinks (e.g. the "Pending:" auth line
                // disappears), the cursor ends above the old bottom line; \x1b[J
                // (erase-to-end-of-screen) clears it before the state is updated
                // to the new shorter count. When the region is the same size or
                // grew, the cursor is already at or below the old end, so
                // \x1b[J clears nothing visible.
                if move_up {
                    let _ = out.write_all(b"\x1b[J");
                }
                let _ = out.flush();
                PROGRESS_LINE_ACTIVE.store(true, Ordering::Relaxed);
            }
        }
        LiveRegionState::None => {}
    }
}

/// Atomically replaces the live region content and repaints it.
///
/// The text update, the repaint and the line-count state update all happen under
/// a single [`RENDER_LOCK`] acquisition. Performing those three steps as separate
/// calls (as a ticker frame otherwise would) leaves a window where a concurrently
/// printed log line clears the region using a line count that does not match what
/// is on screen — whenever the region height just changed, one frame line then
/// survives above the log line, or the log line itself is eaten.
///
/// * `move_up` — `true` overwrites the previous frame in place: the repaint moves
///   the cursor up by the *previous* state's line count, so the state is updated
///   *after* the repaint. `false` paints fresh at the current cursor: the state is
///   set *before* the repaint (which no-ops on a torn-down `None` region).
/// * `to_state` — builds the new region state from the rendered line count of
///   `text`.
pub fn replace_live_region(
    text: &str,
    move_up: bool,
    to_state: impl FnOnce(u16) -> LiveRegionState,
) {
    with_render_lock(|| {
        update_live_region_text(text);
        let lines = calculate_rendered_lines(text);
        if move_up {
            redraw_live_region_raw(true);
            update_live_region_state(to_state(lines));
        } else {
            update_live_region_state(to_state(lines));
            redraw_live_region_raw(false);
        }
    });
}

pub fn update_live_region_text(text: &str) {
    // No `is_empty` guard: passing "" must be able to *clear* the live-region
    // text, not be silently ignored.
    let mut t = lock_force(&LIVE_REGION_TEXT);
    *t = text.to_string();
}

pub fn update_live_region_state(state: LiveRegionState) {
    let mut region = lock_force(&ACTIVE_LIVE_REGION);
    *region = state;
}

/// Completely removes the progress line and clears its associated text.
pub fn clear_progress_line() {
    tear_down_live_region();
    let mut t = lock_force(&LIVE_REGION_TEXT);
    t.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests mutate process-global live-region state; serialise them on the
    // shared LIVE_REGION_TEST_LOCK (taken by every module's live-region tests, not
    // a per-module lock) so they don't race across the whole test binary.

    #[test]
    fn test_progress_line_counting() {
        let _guard = LIVE_REGION_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Reset state
        tear_down_live_region();

        update_live_region_text("Single line");
        update_live_region_state(LiveRegionState::Progress { lines: 1 });
        let state = *lock_force(&ACTIVE_LIVE_REGION);
        assert_eq!(state, LiveRegionState::Progress { lines: 1 });

        update_live_region_text("Line 1\nLine 2");
        update_live_region_state(LiveRegionState::Progress { lines: 2 });
        let state = *lock_force(&ACTIVE_LIVE_REGION);
        assert_eq!(state, LiveRegionState::Progress { lines: 2 });

        update_live_region_text("L1\nL2\nL3\nL4");
        update_live_region_state(LiveRegionState::Progress { lines: 4 });
        let state = *lock_force(&ACTIVE_LIVE_REGION);
        assert_eq!(state, LiveRegionState::Progress { lines: 4 });
    }

    #[test]
    fn test_tear_down_resets_state() {
        let _guard = LIVE_REGION_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        update_live_region_text("Something");
        update_live_region_state(LiveRegionState::Progress { lines: 1 });
        tear_down_live_region();
        let state = *lock_force(&ACTIVE_LIVE_REGION);
        assert_eq!(state, LiveRegionState::None);
        assert!(!PROGRESS_LINE_ACTIVE.load(Ordering::Relaxed));
    }

    #[test]
    fn visible_len_ignores_ansi_sequences() {
        // Plain text — fast path, no stripping needed.
        assert_eq!(visible_len("hello"), 5);
        // A single CSI colour sequence: \x1b[34m … \x1b[0m wraps the text.
        let blue = "\x1b[34mAuthentication\x1b[0m";
        assert_eq!(visible_len(blue), "Authentication".len());
        // Multiple sequences on one line (spinner + blue label, as in auth_banner).
        let spinner_line = "\x1b[33m⠸\x1b[0m  \x1b[34mPerforming collect\x1b[0m";
        assert_eq!(
            visible_len(spinner_line),
            "⠸  Performing collect".chars().count()
        );
        // Multi-parameter SGR (blink_red_bold): \x1b[1;5;31m … \x1b[0m — the
        // semicolons and digits are all < '@' so the loop keeps going until 'm'.
        let blink = "\x1b[1;5;31mALERT\x1b[0m";
        assert_eq!(visible_len(blink), "ALERT".len());
        // Empty string.
        assert_eq!(visible_len(""), 0);
        // No ESC — returns accurate char count for non-ASCII.
        assert_eq!(visible_len("日本語"), 3);
    }

    #[test]
    fn calculate_rendered_lines_strips_ansi() {
        // A line that is 14 visible chars wide should never wrap on an 80-col
        // terminal, even when it carries ~9 extra ANSI bytes.
        let blue_auth = "\x1b[34mAuthentication\x1b[0m"; // 14 visible chars
        assert_eq!(calculate_rendered_lines(blue_auth), 1);
        // Two plain lines.
        assert_eq!(calculate_rendered_lines("line one\nline two"), 2);
    }

    #[test]
    fn empty_text_clears_live_region_text() {
        let _guard = LIVE_REGION_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // passing "" must be able to clear the live-region text, not be
        // silently ignored. Set then clear within the same test to avoid
        // depending on cross-test ordering of the shared static.
        update_live_region_text("not empty");
        assert!(!lock_force(&LIVE_REGION_TEXT).is_empty());
        update_live_region_text("");
        assert!(lock_force(&LIVE_REGION_TEXT).is_empty());
    }
}
