#[cfg(test)]
mod tests {
    use oradaz::utils::logger;
    use oradaz::utils::ui;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_no_color_propagation() {
        // Initialise UI with no‑color forced
        ui::init(true);
        assert!(matches!(ui::mode(), ui::UiMode::NoColor));
        // Propagate to logger
        logger::set_no_color(matches!(ui::mode(), ui::UiMode::NoColor));
        assert!(logger::NO_COLOR.load(Ordering::Relaxed));
    }
}

/// In NoColor mode the `inspect` display layer must emit no decorative Unicode.
/// Lives in this isolated single-binary test (never in the shared `inspect_*.rs`
/// binaries) because it mutates the process-wide UI mode, which would otherwise
/// bleed into Color-asserting tests running in parallel.
#[cfg(test)]
mod inspect_ascii {
    use oradaz::collect::dump::response::DumpError;
    use oradaz::inspect::analysis::Verdict;
    use oradaz::inspect::display::{
        branch_glyph, corner_glyph, mid_dot, mid_sep, print_overview, rule, section_line,
        section_line_with_verdict, severity_icon, strip_ansi_codes, transition_arrow,
    };
    use oradaz::inspect::loader::LogSource;
    use oradaz::utils::ui;

    use serde_json::json;

    /// Codepoints that must never appear in `--no-color` output: box-drawing
    /// (U+2500–U+257F), middot, bullet, arrows and the severity dots. Asserting
    /// the *class* (not specific glyphs) makes a forgotten conversion site fail.
    fn has_decorative(s: &str) -> bool {
        s.chars().any(|c| {
            ('\u{2500}'..='\u{257F}').contains(&c)
                || matches!(
                    c,
                    '\u{00B7}'
                        | '\u{2022}'
                        | '\u{2192}'
                        | '\u{21B3}'
                        | '\u{279C}'
                        | '\u{25CF}'
                        | '\u{25D0}'
                )
        })
    }

    #[test]
    fn inspect_nocolor_output_is_ascii_clean() {
        ui::init(true);
        assert!(matches!(ui::mode(), ui::UiMode::NoColor));

        // 1. Every shared decorative helper must be ASCII in NoColor.
        let helper_outputs = [
            rule(8),
            mid_sep().to_string(),
            mid_dot().to_string(),
            transition_arrow().to_string(),
            branch_glyph().to_string(),
            corner_glyph().to_string(),
            section_line("SECTION", Some(3)),
            section_line_with_verdict("SUMMARY", Verdict::Partial),
            severity_icon(true),
            severity_icon(false),
        ];
        for s in &helper_outputs {
            assert!(
                !has_decorative(s),
                "decorative glyph leaked from helper: {s:?}"
            );
        }

        // 2. A real command render (`summary`) must also be decorative-free — this
        //    guards against a future raw literal added outside the helpers.
        let source = LogSource {
            log_text: String::new(),
            dump_errors: Vec::<DumpError>::new(),
            metadata: Some(json!({
                "tenant": "t",
                "collection_date": "2026-05-27 06:55:05",
                "dump_duration_secs": 39,
                "total_duration_secs": 41,
                "services": {"graph": "enabled", "resources": "enabled", "exchange": "enabled"},
                "tables": [{"name": "users", "folder": "graph", "file": "users", "count": 7000}],
                "auth_errors": 0,
                "prerequisites_errors": 0,
                "errors": 2,
                "expected_errors": 1,
                "unexpected_errors": 1,
            })),
            config: Some(json!({"use_device_code": true})),
            prerequisites: None,
            stats: Some(json!({
                "duration_seconds": 39,
                "services": {"graph": {"http_batch_calls": 10, "http_single_calls": 0, "http_call_failures": 1}},
                "apis": [{"service": "graph", "api": "users", "unexpected_errors": 1,
                          "retries_rate_limit": 3, "rate_limit_wait_secs": 12, "network_errors": 1}],
            })),
            is_archive: true,
            is_broken: false,
            size_bytes: Some(6_450_000),
        };
        let mut out: Vec<String> = vec![String::new()];
        print_overview(&source, &mut out);
        let text = out
            .iter()
            .map(|l| strip_ansi_codes(l))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !has_decorative(&text),
            "decorative glyph leaked into NoColor `inspect summary` output:\n{text}"
        );
    }
}
