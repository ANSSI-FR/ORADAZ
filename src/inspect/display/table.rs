//! Shared dynamic-width table renderer for the `inspect` display commands.
//!
//! Column widths are measured from actual content (header and cells), so
//! nothing is ever truncated and columns never collide, in colour and no-color.
//! A long `userPrincipalName` or an HTTP cell like `"117 batch + 15 single"`
//! (22 chars) fits without overflowing adjacent columns.
//!
//! Column width = `max(visible_width(header), visible_width(every cell))`.
//! Cells may carry ANSI colour codes; padding is computed on the *visible*
//! width via [`visible_width`]. Columns are separated by [`GAP`] spaces; the
//! last column is not padded, so lines carry no trailing whitespace.

use super::{dim, rule, visible_width};

/// Spaces inserted between adjacent columns (3 spaces), matching the gap
/// before the `Status` column in the coverage tables.
const GAP: usize = 3;

/// Per-column horizontal alignment.
#[derive(Clone, Copy)]
pub enum Align {
    Left,
    Right,
}

/// A table row. `Cells` is a measured data row; `Raw` is a verbatim line
/// (e.g. a continuation/annotation row such as the `└ prerequisite …` note
/// printed under a failed service) that is emitted as-is and excluded from
/// column-width measurement so it cannot distort the layout.
pub enum Row {
    Cells(Vec<String>),
    Raw(String),
}

/// Render a dynamic-width table into `out`: a dimmed header, a dimmed `───`
/// rule spanning the measured width, then one line per row. `indent` is
/// prefixed to every emitted line.
pub fn render_table(
    indent: &str,
    headers: &[&str],
    aligns: &[Align],
    rows: &[Row],
    out: &mut Vec<String>,
) {
    let widths = measure(headers, rows);

    out.push(dim(&format_row(indent, headers, aligns, &widths)));

    let rule_w: usize = widths.iter().sum::<usize>() + GAP * widths.len().saturating_sub(1);
    out.push(dim(&format!("{indent}{}", rule(rule_w))));

    for row in rows {
        match row {
            Row::Cells(cells) => out.push(format_row(indent, cells, aligns, &widths)),
            Row::Raw(line) => out.push(line.clone()),
        }
    }
}

/// Column widths = max visible width of the header and every `Cells` row.
fn measure(headers: &[&str], rows: &[Row]) -> Vec<usize> {
    let mut widths: Vec<usize> = headers.iter().map(|h| visible_width(h)).collect();
    for row in rows {
        if let Row::Cells(cells) = row {
            for (i, cell) in cells.iter().enumerate() {
                if i < widths.len() {
                    widths[i] = widths[i].max(visible_width(cell));
                }
            }
        }
    }
    widths
}

/// Format one row: pad each cell to its column width (visible-width aware),
/// joined by [`GAP`] spaces. The last column is left un-padded to avoid
/// trailing whitespace. Accepts `&str` (header) or `String` (cell) via
/// `AsRef<str>`.
fn format_row<S: AsRef<str>>(
    indent: &str,
    cells: &[S],
    aligns: &[Align],
    widths: &[usize],
) -> String {
    let mut line = String::from(indent);
    let last = cells.len().saturating_sub(1);
    for (i, cell) in cells.iter().enumerate() {
        let cell = cell.as_ref();
        if i > 0 {
            line.push_str(&" ".repeat(GAP));
        }
        let pad = widths
            .get(i)
            .copied()
            .unwrap_or(0)
            .saturating_sub(visible_width(cell));
        match aligns.get(i).copied().unwrap_or(Align::Left) {
            Align::Left => {
                line.push_str(cell);
                if i != last {
                    line.push_str(&" ".repeat(pad));
                }
            }
            Align::Right => {
                line.push_str(&" ".repeat(pad));
                line.push_str(cell);
            }
        }
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspect::display::strip_ansi_codes;

    fn render_plain(headers: &[&str], aligns: &[Align], rows: &[Row]) -> Vec<String> {
        let mut out = Vec::new();
        render_table("  ", headers, aligns, rows, &mut out);
        out.iter().map(|l| strip_ansi_codes(l)).collect()
    }

    #[test]
    fn measures_width_from_content_without_truncation() {
        let rows = vec![
            Row::Cells(vec!["a".into(), "1".into()]),
            Row::Cells(vec!["a-very-long-value".into(), "200".into()]),
        ];
        let plain = render_plain(&["Name", "N"], &[Align::Left, Align::Right], &rows);
        // The long value is rendered in full (no truncation).
        assert!(plain.iter().any(|l| l.contains("a-very-long-value")));
        // Right-aligned numbers share the same end column: "1" and "200" both
        // finish where the longest cell ("200") does.
        let row_short = plain
            .iter()
            .find(|l| l.trim_start().starts_with("a "))
            .unwrap();
        let row_long = plain
            .iter()
            .find(|l| l.contains("a-very-long-value"))
            .unwrap();
        assert_eq!(
            row_short.len(),
            row_long.len(),
            "rows must align to same width"
        );
        assert!(row_short.ends_with("  1"));
        assert!(row_long.ends_with("200"));
    }

    #[test]
    fn pads_ansi_coloured_cell_by_visible_width() {
        use crate::utils::ui::{Paint, paint};
        // A coloured cell carries many ANSI bytes but a visible width of 2.
        let coloured = paint(Paint::Green, "ab");
        let rows = vec![
            Row::Cells(vec![coloured, "1".into()]),
            Row::Cells(vec!["abcd".into(), "2".into()]),
        ];
        let plain = render_plain(&["C", "N"], &[Align::Left, Align::Right], &rows);
        // plain[0] = header, plain[1] = rule, plain[2] = coloured row, plain[3] = plain row.
        // If padding had used byte length instead of visible width, the coloured
        // row would be padded short and end up a different length once stripped.
        assert_eq!(
            plain[2].len(),
            plain[3].len(),
            "ANSI bytes must not inflate padding"
        );
        assert!(plain[2].ends_with("  1"));
        assert!(plain[3].ends_with("  2"));
    }

    #[test]
    fn raw_rows_are_verbatim_and_excluded_from_measurement() {
        let rows = vec![
            Row::Cells(vec!["x".into(), "1".into()]),
            Row::Raw("      └ a very very long annotation line".into()),
        ];
        let plain = render_plain(&["H", "N"], &[Align::Left, Align::Right], &rows);
        // Raw line emitted exactly as given.
        assert!(
            plain
                .iter()
                .any(|l| l == "      └ a very very long annotation line")
        );
        // The long Raw line did NOT widen column 0: the data row stays compact
        // (col0 = max("H", "x") = 1, GAP = 3, col1 = 1).
        assert!(plain.iter().any(|l| l == "  x   1"));
    }
}
