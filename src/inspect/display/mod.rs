pub mod compare;
pub mod coverage;
pub mod overview;
pub mod remediation;
pub mod sections;
pub mod stats;
pub mod summary;
pub mod table;
pub mod timeline;

pub use compare::*;
pub use coverage::*;
pub use overview::*;
pub use remediation::*;
pub use sections::*;
pub use stats::*;
pub use summary::*;
pub use table::*;
pub use timeline::*;

use crate::inspect::analysis::Verdict;
// `dim` is private to this module but reachable by submodules via `super::dim`
// (children can see parent's private items). Several submodules rely on that.
use crate::utils::ui::{Icon, Paint, UiMode, dim, err_text, icon, mode, paint, warn_text};

pub const SECTION_WIDTH: usize = 72;
pub const INDENT: &str = "       "; // 7 spaces

// ─── mode-aware decorative glyphs ────────────────────────────────────────────
// The inspect display layer routes every decorative separator through these
// helpers so `--no-color` output is ASCII-clean (NoColor stdout is designed
// for piping). Each helper returns the Color glyph in color mode and an
// equivalent ASCII fallback in no-color mode.

/// Horizontal-rule character: `─` in Color, `-` in NoColor (reuses the shared
/// `Icon` mapping).
pub fn rule_char() -> String {
    icon(Icon::UpOrBottomTable)
}

/// A horizontal rule of `n` cells.
pub fn rule(n: usize) -> String {
    rule_char().repeat(n)
}

/// Inline list separator: `" · "` in Color, `" - "` in NoColor.
pub fn mid_sep() -> &'static str {
    match mode() {
        UiMode::Color => " · ",
        UiMode::NoColor => " - ",
    }
}

/// Bare middot glyph (no surrounding spaces): `"·"` / `"-"`. Use when the call
/// site supplies its own spacing.
pub fn mid_dot() -> &'static str {
    match mode() {
        UiMode::Color => "·",
        UiMode::NoColor => "-",
    }
}

/// Transition arrow used in deltas / time windows: `"→"` / `"->"`.
pub fn transition_arrow() -> &'static str {
    match mode() {
        UiMode::Color => "→",
        UiMode::NoColor => "->",
    }
}

/// Detail/branch marker for indented sub-lines: `"↳"` / `">"`.
pub fn branch_glyph() -> &'static str {
    match mode() {
        UiMode::Color => "↳",
        UiMode::NoColor => ">",
    }
}

/// Box corner for continuation/annotation rows: `"└"` / `"\\"`.
pub fn corner_glyph() -> &'static str {
    match mode() {
        UiMode::Color => "└",
        UiMode::NoColor => "\\",
    }
}

/// Ellipsis used for truncation / short ids: `"…"` / `"..."`. Mode-aware so
/// `--no-color` stays ASCII. Routed at the source (not the flush sanitizer)
/// because the width difference (1 vs 3 cells) must be visible to
/// [`table::render_table`] when the ellipsis sits inside a measured cell.
pub fn ellipsis() -> &'static str {
    match mode() {
        UiMode::Color => "…",
        UiMode::NoColor => "...",
    }
}

/// Column header for a delta column: `"Δ"` / `"Delta"`. Mode-aware and routed at
/// the source so `render_table` measures the final width.
pub fn delta_header() -> &'static str {
    match mode() {
        UiMode::Color => "Δ",
        UiMode::NoColor => "Delta",
    }
}

pub fn section_line(title: &str, count: Option<usize>) -> String {
    let rule3 = rule(3);
    let header = match count {
        Some(n) => format!("{rule3} {} ({}) ", title, n),
        None => format!("{rule3} {} ", title),
    };
    let dash_count = SECTION_WIDTH.saturating_sub(header.chars().count());
    format!("{}{}", header, rule(dash_count))
}

/// Glyph + colour for a verdict badge — kept in one place so every command
/// header renders the same badge.
fn verdict_glyph(v: Verdict) -> (Icon, Paint) {
    match v {
        Verdict::Complete => (Icon::Ok, Paint::Green),
        Verdict::Partial => (Icon::Warn, Paint::Yellow),
        Verdict::AuthFailed | Verdict::Interrupted => (Icon::Err, Paint::Red),
        Verdict::NoData => (Icon::Info, Paint::Dim),
    }
}

/// `"✔ COMPLETE"` (green) / `"⚠ PARTIAL"` (yellow) / `"✖ INTERRUPTED"` (red),
/// with ASCII fallback (`OK`/`!!`) in no-color mode.
pub fn verdict_badge(v: Verdict) -> String {
    let (glyph, colour) = verdict_glyph(v);
    let text = format!("{} {}", icon(glyph), v.label());
    match mode() {
        UiMode::Color => paint(colour, &text),
        UiMode::NoColor => text,
    }
}

/// Section header with the verdict badge right-aligned, e.g.
/// `─── COLLECTION SUMMARY ───── ✔ COMPLETE ───`. Padding accounts for the
/// ANSI escapes in the badge so the line still totals [`SECTION_WIDTH`] cells.
pub fn section_line_with_verdict(title: &str, verdict: Verdict) -> String {
    let prefix = format!("{} {} ", rule(3), title);
    let badge = verdict_badge(verdict);
    let trailing = format!(" {}", rule(3));
    let badge_visible = strip_ansi_codes(&badge).chars().count();
    let dashes = SECTION_WIDTH
        .saturating_sub(prefix.chars().count() + 1 + badge_visible + trailing.chars().count());
    format!("{}{} {}{}", prefix, rule(dashes), badge, trailing)
}

/// Badge for the `PROBLEMATIC APIS` rows in `stats` and `timeline`. Returns
/// a pre-coloured glyph: `●` (red) for critical entries, `◐` (yellow) for
/// warnings; `"!!"` / `"!"` in no-color mode. Shared so both commands stay
/// in lockstep on severity affordance.
pub fn severity_icon(critical: bool) -> String {
    let glyph = if critical { "●" } else { "◐" };
    match mode() {
        UiMode::Color if critical => err_text(glyph),
        UiMode::Color => warn_text(glyph),
        UiMode::NoColor if critical => "!!".to_string(),
        UiMode::NoColor => "!".to_string(),
    }
}

/// Insert a regular space every three digits (`12345` → `"12 345"`) — used
/// in coverage tables and totals to keep large counts readable.
pub fn format_thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

/// Truncate `s` to `max` visible characters, appending `…` when shortened.
/// Used by the `logs` grouped-table renderer to keep long columns readable.
pub fn truncate(s: &str, max: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        return s.to_string();
    }
    if max == 0 {
        return String::new();
    }
    // Reserve room for the (mode-aware) ellipsis: 1 cell in Color ("…"),
    // 3 cells in NoColor ("..."). When there isn't room for ellipsis + at least
    // one content char, hard-cut so the result still fits in `max`.
    let ell = ellipsis();
    let ell_len = ell.chars().count();
    if max <= ell_len {
        return chars[..max].iter().collect();
    }
    let head: String = chars[..max - ell_len].iter().collect();
    format!("{head}{ell}")
}

/// Human-friendly byte count using binary prefixes (matches the collect-end
/// "Archive : ... (4.2 MiB)" line in the README).
pub fn format_bytes(n: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    if n >= GIB {
        format!("{:.2} GiB", n as f64 / GIB as f64)
    } else if n >= MIB {
        format!("{:.2} MiB", n as f64 / MIB as f64)
    } else if n >= KIB {
        format!("{:.1} KiB", n as f64 / KIB as f64)
    } else {
        format!("{} B", n)
    }
}

pub fn strip_ansi_codes(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            chars.next(); // consume '['
            for ch in chars.by_ref() {
                if ch.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            result.push(c);
        }
    }
    result
}

pub fn print_collection_summary(
    metadata: Option<&serde_json::Value>,
    config: Option<&serde_json::Value>,
    out: &mut Vec<String>,
) {
    out.push(section_line("COLLECTION SUMMARY", None));
    out.push(String::new());

    if let Some(m) = metadata {
        if let Some(v) = m.get("tenant").and_then(|v| v.as_str()) {
            out.push(format!("  {:<17} {}", "Tenant", v));
        }
        if let Some(v) = m.get("collection_date").and_then(|v| v.as_str()) {
            out.push(format!("  {:<17} {}", "Date", v));
        }
        if let Some(t) = m.get("dump_duration_secs").and_then(|t| t.as_i64()) {
            out.push(format!("  {:<17} {} s", "Dump duration", t));
        }
        if let Some(t) = m.get("total_duration_secs").and_then(|t| t.as_i64()) {
            out.push(format!("  {:<17} {} s", "Total duration", t));
        }
        if let Some(v) = m.get("oradaz_version").and_then(|v| v.as_str()) {
            out.push(format!("  {:<17} {}", "ORADAZ version", v));
        }
        if let Some(c) = config {
            out.push(format!(
                "  {:<17} {}",
                "Authentication",
                crate::inspect::display::sections::auth_type_from_config(c)
            ));
        }
        if let Some(v) = m.get("schema_version").and_then(|v| v.as_str()) {
            out.push(format!("  {:<17} {}", "Schema version", v));
        }
        if let Some(v) = m.get("schema_hash").and_then(|v| v.as_str()) {
            out.push(format!("  {:<17} {}", "Schema hash", v));
        }
    } else {
        out.push(format!("{}(no collection metadata available)", INDENT));
    }
}
