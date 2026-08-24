// UI helpers for section headers and startup summary
use crate::utils::ui::{Icon, UiMode, blue, icon, mode};

const MAX_WIDTH: usize = 71;

/// Render a section header.
/// In colour mode a boxed header is drawn using Unicode box‑drawing characters.
/// In no‑colour mode a simple "=== Title ===" line is returned.
pub fn section(title: &str) -> String {
    // Truncate title if it would exceed the width (allow some padding). Count and
    // slice by *characters*, not bytes — byte slicing (`&title[..n]`) panics when
    // `n` falls inside a multi-byte UTF-8 sequence (e.g. an accented title).
    let title: String = if title.chars().count() > MAX_WIDTH - 6 {
        title.chars().take(MAX_WIDTH - 6).collect()
    } else {
        title.to_string()
    };
    match mode() {
        UiMode::Color => {
            // Compute padding to centre the title inside the box
            let inner_width = MAX_WIDTH - 2; // borders
            let title_len = title.chars().count();
            let padding = inner_width.saturating_sub(title_len);
            let left = padding / 2;
            let right = padding - left;
            let line = format!("┌{}{}{}┐", "─".repeat(left), title, "─".repeat(right));
            line
        }
        UiMode::NoColor => format!("=== {} ===", title),
    }
}

/// Render a sub-section marker: `  ▸ Title` (blue triangle in color mode).
pub fn section_sub(title: &str) -> String {
    let triangle = match mode() {
        UiMode::Color => "▸".to_string(),
        UiMode::NoColor => ">".to_string(),
    };
    format!("  {} {}", triangle, blue(title))
}

/// Render a two‑column startup summary.
/// `fields` is a slice of `(Icon, label, value)`. The left column (icon + label) is left‑justified,
/// the right column (value) is right‑justified, both fitting within `MAX_WIDTH`.
pub fn startup_summary(fields: &[(Icon, &str, &str)]) -> String {
    let mut lines = Vec::new();
    for (ic, label, value) in fields {
        let left = format!("{}  {}", icon(*ic), label);
        let left_len = left.chars().count();
        let right_len = value.chars().count();
        let space = if MAX_WIDTH > left_len + right_len {
            MAX_WIDTH - left_len - right_len
        } else {
            1
        };
        let line = format!("{}{}{}", left, " ".repeat(space), value);
        lines.push(line);
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_multibyte_title_truncates_without_panicking() {
        // 70 two-byte chars (140 bytes) — longer than MAX_WIDTH - 6 (65). Byte
        // slicing (`&title[..65]`) would land inside a multi-byte sequence and
        // panic; char-based truncation must not.
        let title = "é".repeat(70);
        let out = section(&title); // must not panic
        assert!(!out.is_empty());
        // No more than MAX_WIDTH - 6 chars of the title survive truncation.
        assert!(title.chars().count() > MAX_WIDTH - 6);
    }
}
