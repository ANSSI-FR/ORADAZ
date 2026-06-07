use crate::FL;
use crate::utils::ui::theme::{Icon, icon};

use crossterm::cursor::{MoveToColumn, MoveUp};
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::execute;
use crossterm::style::Print;
use crossterm::terminal::{Clear, ClearType, disable_raw_mode, enable_raw_mode};
use log::error;
use std::io::{IsTerminal, Write, stdout};

struct RawModeGuard;

impl RawModeGuard {
    fn new() -> Result<Self, std::io::Error> {
        enable_raw_mode()?;
        Ok(RawModeGuard)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}

/// Handles SIGINT (Ctrl+C) interaction.
///
/// Returns `true` if the user decided to stop, `false` if they decided to continue.
pub fn handle_sigint_menu() -> bool {
    // On a non-interactive stdin (piped/redirected/no TTY) there is no operator to
    // drive the menu. Treat the interruption as a definitive stop rather than entering
    // raw mode and risking a wait on an input source that never produces a key — which
    // would otherwise leave the coordinator paused indefinitely.
    if !std::io::stdin().is_terminal() {
        return true;
    }
    let _guard = match RawModeGuard::new() {
        Ok(g) => g,
        Err(e) => {
            error!("{:FL$}Error enabling raw mode: {}", "SIGINT", e);
            return true; // Stop on error
        }
    };
    // Remove any queued Ctrl+C event that arrived together with the signal so the menu
    // does not instantly consume it. This ensures the pause stays active until the user
    // explicitly interacts with the menu.
    while event::poll(std::time::Duration::from_millis(0)).unwrap_or(false) {
        let _ = event::read();
    }

    let mut stdout = stdout();

    // Clear the current line to remove the '^C' echoed by the terminal before raw mode was enabled
    // Use \n for cross-platform compatibility; crossterm handles the abstraction.
    let _ = execute!(
        stdout,
        MoveToColumn(0),
        Clear(ClearType::CurrentLine),
        Print(format!("{}\n", icon(Icon::UpOrBottomBoldTable).repeat(70))),
        MoveToColumn(0),
        Print(format!(
            "{} Are you sure you want to abort the program?\n",
            icon(Icon::Warn)
        ))
    );
    let _ = stdout.flush();

    let mut selected = 1; // 0: Yes, 1: No
    let mut first_render = true;
    // The opening Ctrl+C (the one that triggered this menu) is ignored so the menu does
    // not instantly abort; a deliberate second Ctrl+C aborts. Windows-only: there the
    // opener also surfaces as a queued key event that reaches this loop, whereas on Linux
    // it is consumed as a SIGINT before raw mode and never arrives — so gating the flag to
    // Windows avoids swallowing the Linux user's first *real* in-menu Ctrl+C.
    #[cfg(windows)]
    let mut first_ctrl_c = true;

    let stop = loop {
        let yes_marker = if selected == 0 {
            icon(Icon::Selected)
        } else {
            " ".to_string()
        };
        let no_marker = if selected == 1 {
            icon(Icon::Selected)
        } else {
            " ".to_string()
        };

        if first_render {
            let _ = execute!(
                stdout,
                MoveToColumn(0),
                Print(format!("     {} Yes\n", yes_marker)),
                MoveToColumn(0),
                Print(format!("     {} No", no_marker))
            );
            first_render = false;
        } else {
            let _ = execute!(
                stdout,
                MoveUp(1),
                MoveToColumn(0),
                Clear(ClearType::FromCursorDown),
                MoveToColumn(0),
                Print(format!("     {} Yes\n", yes_marker)),
                MoveToColumn(0),
                Print(format!("     {} No", no_marker))
            );
        }
        let _ = stdout.flush();

        if let Ok(Event::Key(key)) = event::read() {
            // Detect Ctrl+C.
            let is_ctrl_c = (key.modifiers.contains(KeyModifiers::CONTROL)
                && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('\x03')))
                || matches!(key.code, KeyCode::Char('\x03'));
            if is_ctrl_c {
                // On Windows, swallow the first Ctrl+C (the opener that triggered the menu)
                // and keep the menu open; a deliberate second one aborts. On Linux the
                // opener never reaches here, so any Ctrl+C is a deliberate abort.
                #[cfg(windows)]
                {
                    if first_ctrl_c {
                        first_ctrl_c = false;
                        continue;
                    }
                }
                break true;
            }

            match key.code {
                KeyCode::Up => {
                    if selected != 0 {
                        selected = 0;
                    }
                }
                KeyCode::Down => {
                    if selected != 1 {
                        selected = 1;
                    }
                }
                KeyCode::Enter => break selected == 0,
                KeyCode::Esc => break false,
                _ => {}
            }
        }
    };

    // Move up to clear the whole menu:
    // Total lines printed: 1 (bar) + 1 (question) + 1 (Yes) + 1 (No) = 4 lines.
    // Cursor is at the end of the "No" line. Move up 3 to reach the first line, then
    // clear downward — this leaves the cursor exactly where the progress line started,
    // so the resuming ticker repaints in place with no blank gap.
    let _ = execute!(
        stdout,
        MoveUp(3),
        MoveToColumn(0),
        Clear(ClearType::FromCursorDown)
    );
    let _ = stdout.flush();

    stop
}
