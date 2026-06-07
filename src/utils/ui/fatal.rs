// Fatal UI rendering utilities
use crate::utils::ui::{self, Icon, UiMode};

use std::io::{self, Write};

/// Renders a fatal error block to stdout.
///
/// * `title`   – short title of the error
/// * `context` – optional structured context extracted from the error (shown below the title)
/// * `steps`   – zero or more actionable remedy steps, each rendered with a `→` bullet
pub fn fatal(title: &str, context: Option<&str>, steps: &[&str]) {
    match ui::mode() {
        UiMode::Color => fatal_color(title, context, steps),
        UiMode::NoColor => fatal_no_color(title, context, steps),
    }
}

fn fatal_color(title: &str, context: Option<&str>, steps: &[&str]) {
    let err = ui::icon(Icon::Err);
    let mut out = String::from("\n");

    // Header
    let header = format!(
        "━━━ {} FATAL ERROR ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        err
    );
    out.push_str(&format!("{}\n", ui::err_text(&header)));

    // Title
    out.push_str(&format!("{}: {}\n", ui::dim("Title    "), title));

    // Context
    if let Some(ctx) = context {
        for (i, line) in ctx.lines().enumerate() {
            if i == 0 {
                out.push_str(&format!("{}: {}\n", ui::dim("Context  "), line));
            } else {
                out.push_str(&format!("           {}\n", line));
            }
        }
    }

    // Solutions
    if !steps.is_empty() {
        out.push('\n');
        out.push_str(&format!("{}\n", ui::warn_text("💡 Solution(s) :")));
        for step in steps {
            out.push_str(&format!("➜ {}\n", step));
        }
    }

    // Footer
    let footer = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━";
    out.push_str(&format!("{}\n", ui::dim(footer)));
    let _ = io::stdout().write_all(out.as_bytes());
}

fn fatal_no_color(title: &str, context: Option<&str>, steps: &[&str]) {
    let mut out = String::from("\n");

    // Header
    out.push_str("--- [!] FATAL ERROR --------------------------------------------\n");

    // Title
    out.push_str(&format!("Title    : {}\n", title));

    // Context
    if let Some(ctx) = context {
        for (i, line) in ctx.lines().enumerate() {
            if i == 0 {
                out.push_str(&format!("Context  : {}\n", line));
            } else {
                out.push_str(&format!("           {}\n", line));
            }
        }
    }

    // Solutions
    if !steps.is_empty() {
        out.push_str("\nSolution(s) :\n");
        for step in steps {
            out.push_str(&format!("> {}\n", step));
        }
    }

    // Footer
    out.push_str("----------------------------------------------------------------\n");
    let _ = io::stdout().write_all(out.as_bytes());
}
