mod common;

use oradaz::VERSION;
use oradaz::inspect::display::{
    print_all_api_errors, print_logs_details, print_summary, print_timeline, strip_ansi_codes,
};
use oradaz::inspect::loader::{ArchiveNeeds, LogNeed, LogSource, load_log_source};

/// The `inspect logs` view needs both expensive entries; reused by the loader
/// tests below so they exercise the same path as the live command.
const FULL_NEEDS: ArchiveNeeds = ArchiveNeeds {
    errors: true,
    log: LogNeed::Always,
};
use oradaz::inspect::log_parser::{LogEntry, LogFilters, LogLevel};

use serde_json::json;
use std::fs;
use tempfile::tempdir;

fn make_mock_log_source() -> LogSource {
    LogSource {
        log_text: "".to_string(),
        metadata: Some(json!({
            "tenant": "test-tenant",
            "collection_date": "2026-04-29 17:43:31",
            "dump_duration_secs": 10,
            "oradaz_version": VERSION,
            "schema_version": VERSION,
            "schema_hash": "abcdef1234567890",
        })),
        config: Some(json!({
            "services": {
                "service": [
                    {"@name": "graph", "#text": true},
                    {"@name": "resources", "#text": true},
                    {"@name": "exchange", "#text": false},
                ]
            }
        })),
        prerequisites: None,
        stats: None,
        dump_errors: vec![],
        is_broken: false,
        is_archive: false,
        size_bytes: None,
    }
}

#[test]
fn test_print_summary_enabled_services() {
    let source = make_mock_log_source();
    let entries: Vec<LogEntry> = vec![LogEntry {
        timestamp: "2026-04-29 17:43:31".to_string(),
        level: LogLevel::Error,
        module: "graph".to_string(),
        service: Some("graph".to_string()),
        api: Some("users".to_string()),
        url: None,
        http_status: Some(403),
        upstream_code: None,
        message: "Forbidden".to_string(),
    }];

    let mut lines = vec![];
    print_summary(
        &entries,
        source.metadata.as_ref(),
        source.config.as_ref(),
        source.is_broken,
        &mut lines,
    );

    let output: String = lines
        .iter()
        .map(|l| strip_ansi_codes(l))
        .collect::<Vec<_>>()
        .join("\n");

    assert!(output.contains("LOGS SUMMARY"));
    assert!(
        output.contains("Graph"),
        "Graph should be present (enabled in config)"
    );
    assert!(
        output.contains("Resources"),
        "Resources should be present (enabled in config, 0 errors)"
    );
    assert!(
        !output.contains("Exchange"),
        "Exchange should not be present (disabled in config)"
    );
}

#[test]
fn test_print_logs_details_sorting() {
    let entries: Vec<LogEntry> = vec![
        LogEntry {
            timestamp: "2026-04-29 17:43:31".to_string(),
            level: LogLevel::Error,
            module: "graph".to_string(),
            service: Some("graph".to_string()),
            api: Some("api_a".to_string()),
            url: None,
            http_status: Some(403),
            upstream_code: Some("ErrA".to_string()),
            message: "Msg A".to_string(),
        },
        LogEntry {
            timestamp: "2026-04-29 17:43:32".to_string(),
            level: LogLevel::Error,
            module: "graph".to_string(),
            service: Some("graph".to_string()),
            api: Some("api_b".to_string()),
            url: None,
            http_status: Some(403),
            upstream_code: Some("ErrB".to_string()),
            message: "Msg B".to_string(),
        },
        LogEntry {
            timestamp: "2026-04-29 17:43:33".to_string(),
            level: LogLevel::Error,
            module: "graph".to_string(),
            service: Some("graph".to_string()),
            api: Some("api_a".to_string()),
            url: None,
            http_status: Some(403),
            upstream_code: Some("ErrA".to_string()),
            message: "Msg A".to_string(),
        },
    ];

    let mut lines = vec![];
    let filters = LogFilters::default();
    print_logs_details(&entries, &mut lines, &filters);

    let output: String = lines
        .iter()
        .map(|l| strip_ansi_codes(l))
        .collect::<Vec<_>>()
        .join("\n");

    // api_a has 2 entries, api_b has 1. api_a should come first.
    let pos_a = output.find("graph_api_a").unwrap();
    let pos_b = output.find("graph_api_b").unwrap();
    assert!(
        pos_a < pos_b,
        "api_a (count 2) should be before api_b (count 1)"
    );
}

#[test]
fn test_print_all_api_errors_ordering() {
    let source = make_mock_log_source();
    let entries: Vec<LogEntry> = vec![
        LogEntry {
            timestamp: "2026-04-29 10:00:00".to_string(),
            level: LogLevel::Error,
            module: "graph".to_string(),
            service: Some("graph".to_string()),
            api: Some("api_1".to_string()),
            url: Some("url_1".to_string()),
            http_status: Some(403),
            upstream_code: None,
            message: "Error 1".to_string(),
        },
        LogEntry {
            timestamp: "2026-04-29 09:00:00".to_string(),
            level: LogLevel::Error,
            module: "graph".to_string(),
            service: Some("graph".to_string()),
            api: Some("api_2".to_string()),
            url: Some("url_2".to_string()),
            http_status: Some(404),
            upstream_code: None,
            message: "Error 2".to_string(),
        },
    ];

    let mut lines = vec![];
    let filters = LogFilters {
        full: true,
        ..Default::default()
    };
    print_all_api_errors(&entries, &mut lines, &source, &filters);

    let output: String = lines
        .iter()
        .map(|l| strip_ansi_codes(l))
        .collect::<Vec<_>>()
        .join("\n");

    let pos_2 = output.find("09:00:00").unwrap();
    let pos_1 = output.find("10:00:00").unwrap();
    assert!(pos_2 < pos_1, "Errors should be ordered by date ascending");
}

#[test]
fn test_print_timeline_granularity_second() {
    let entries: Vec<LogEntry> = vec![
        LogEntry {
            timestamp: "2026-04-29 10:00:00".to_string(),
            level: LogLevel::Error,
            module: "graph".to_string(),
            service: Some("graph".to_string()),
            api: Some("api".to_string()),
            url: None,
            http_status: Some(403),
            upstream_code: None,
            message: "Err".to_string(),
        },
        LogEntry {
            timestamp: "2026-04-29 10:00:05".to_string(),
            level: LogLevel::Error,
            module: "graph".to_string(),
            service: Some("graph".to_string()),
            api: Some("api".to_string()),
            url: None,
            http_status: Some(403),
            upstream_code: None,
            message: "Err".to_string(),
        },
    ];

    let mut lines = vec![];
    print_timeline(&entries, false, None, &mut lines);

    let output: String = lines
        .iter()
        .map(|l| strip_ansi_codes(l))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(output.contains("TIMELINE (errors by second)"));
    assert!(output.contains("10:00:00"));
    assert!(output.contains("10:00:05"));
}

#[test]
fn test_print_timeline_granularity_minute() {
    let entries: Vec<LogEntry> = vec![
        LogEntry {
            timestamp: "2026-04-29 10:00:00".to_string(),
            level: LogLevel::Error,
            module: "graph".to_string(),
            service: Some("graph".to_string()),
            api: Some("api".to_string()),
            url: None,
            http_status: Some(403),
            upstream_code: None,
            message: "Err".to_string(),
        },
        LogEntry {
            timestamp: "2026-04-29 10:10:00".to_string(),
            level: LogLevel::Error,
            module: "graph".to_string(),
            service: Some("graph".to_string()),
            api: Some("api".to_string()),
            url: None,
            http_status: Some(403),
            upstream_code: None,
            message: "Err".to_string(),
        },
    ];

    let mut lines = vec![];
    print_timeline(&entries, false, None, &mut lines);

    let output: String = lines
        .iter()
        .map(|l| strip_ansi_codes(l))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(output.contains("TIMELINE (errors by minute)"));
    assert!(output.contains("10:00"));
    assert!(output.contains("10:10"));
}

#[test]
fn folder_mode_loads_dump_errors_from_errors_json() {
    // `load_log_source` on a folder must parse `errors.json` from disk so
    // `inspect logs --full --folder` can render response bodies.
    let dir = tempdir().expect("tempdir");
    let path = dir.path();

    // Minimal oradaz.log (loader reads it but doesn't require content).
    fs::write(path.join("oradaz.log"), "").expect("write oradaz.log");

    // Two DumpError entries (one expected, one not) + a blank line to verify
    // the parser tolerates it (matches mla_reader's behaviour).
    let lines = [
        r#"{"folder":"graph","file":"users","url":"https://example/u","status":403,"code":"Forbidden","message":"Access denied","expected":false,"full_response":{"error":{"code":"Forbidden"}}}"#,
        r#"{"folder":"graph","file":"audits","url":"https://example/a","status":404,"code":"NotFound","message":"Not found","expected":true}"#,
        "",
    ];
    fs::write(path.join("errors.json"), lines.join("\n")).expect("write errors.json");

    let source = load_log_source(path.to_str().expect("utf-8 path"), None, &FULL_NEEDS);

    assert_eq!(source.dump_errors.len(), 2, "expected 2 dump errors");
    assert_eq!(source.dump_errors[0].folder, "graph");
    assert_eq!(source.dump_errors[0].file, "users");
    assert_eq!(source.dump_errors[0].status, 403);
    assert!(
        source.dump_errors[0].full_response.is_some(),
        "loader must round-trip full_response (consumed by find_dump_error \
         URL fallback today, and by the entry-detail renderers in entries.rs \
         once Phase 1 wires them into `--full`)"
    );
    assert!(
        source.dump_errors[1].expected,
        "loader must round-trip `expected` (drives the default hide of \
         schema-benign entries and the `--include-expected` opt-in)"
    );
}

#[test]
fn folder_mode_broken_marker_flags_interrupted() {
    // Folder-mode collections have no `.broken` extension to signal an
    // interruption (unlike `.mla` archives). `writer::file::FileWriter::mark_broken`
    // drops a `.broken` marker file instead; the loader must surface it as
    // `is_broken` so `compute_verdict` reports INTERRUPTED rather than COMPLETE.
    use oradaz::inspect::analysis::{Verdict, compute_verdict};

    let dir = tempdir().expect("tempdir");
    let path = dir.path();
    fs::write(path.join("oradaz.log"), "").expect("write oradaz.log");

    // No marker → not broken.
    let clean = load_log_source(path.to_str().expect("utf-8 path"), None, &FULL_NEEDS);
    assert!(
        !clean.is_broken,
        "a folder without a .broken marker must not be flagged interrupted"
    );

    // Marker present → broken (interrupted), even with no metadata.
    fs::write(path.join(".broken"), "").expect("write .broken marker");
    let broken = load_log_source(path.to_str().expect("utf-8 path"), None, &FULL_NEEDS);
    assert!(
        broken.is_broken,
        "a .broken marker file must flag the folder as interrupted"
    );
    assert_eq!(
        compute_verdict(
            broken.metadata.as_ref(),
            broken.stats.as_ref(),
            broken.is_broken,
            false,
        ),
        Verdict::Interrupted,
        "a folder with a .broken marker must report INTERRUPTED"
    );
}

// ─── Phase 1c new behaviour ──────────────────────────────────────────────

fn err_entry(api: &str, status: u16, code: &str, msg: &str, ts: &str) -> LogEntry {
    LogEntry {
        timestamp: ts.to_string(),
        level: LogLevel::Error,
        module: "graph".to_string(),
        service: Some("graph".to_string()),
        api: Some(api.to_string()),
        url: None,
        http_status: Some(status),
        upstream_code: Some(code.to_string()),
        message: msg.to_string(),
    }
}

fn warn_entry(api: &str, msg: &str, ts: &str) -> LogEntry {
    LogEntry {
        timestamp: ts.to_string(),
        level: oradaz::inspect::log_parser::LogLevel::Warn,
        module: "graph".to_string(),
        service: Some("graph".to_string()),
        api: Some(api.to_string()),
        url: None,
        http_status: Some(429),
        upstream_code: None,
        message: msg.to_string(),
    }
}

fn render_details(entries: &[LogEntry], filters: LogFilters) -> String {
    let mut out: Vec<String> = vec![];
    print_logs_details(entries, &mut out, &filters);
    out.iter()
        .map(|l| strip_ansi_codes(l))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn logs_details_warn_entries_render_without_full_flag() {
    // The grouped renderer must show warnings when --warnings is set,
    // independently of --full.
    let entries = vec![warn_entry(
        "users",
        "Too many requests",
        "2026-04-29 10:00:00",
    )];
    let filters = LogFilters {
        warnings: true,
        ..Default::default()
    };
    let text = render_details(&entries, filters);
    assert!(text.contains("graph_users"), "warn entry should appear");
    assert!(text.contains("429"));
}

#[test]
fn logs_details_distinguishes_empty_from_hidden_by_level() {
    // Warn entries exist but no level flag is set → must NOT claim the log
    // is empty; report how many are hidden and how to reveal them.
    let entries = vec![warn_entry(
        "users",
        "Too many requests",
        "2026-04-29 10:00:00",
    )];
    let hidden = render_details(&entries, LogFilters::default());
    assert!(
        hidden.contains("hidden") && hidden.contains("--warnings"),
        "level-hidden entries must say so, got: {hidden}"
    );
    assert!(
        !hidden.contains("no API event log entries"),
        "must not show the empty-log message when entries are merely hidden by level"
    );

    // A genuinely empty log shows the reworded message pointing at the debug-level /
    // traceLogs cause rather than implying there is simply no data.
    let empty = render_details(&[], LogFilters::default());
    assert!(
        empty.contains("no API event log entries") && empty.contains("--debug"),
        "a genuinely empty log must explain the debug-level cause, got: {empty}"
    );
}

#[test]
fn load_log_source_reads_a_plain_log_file() {
    // `inspect logs <oradaz.log>` — a raw .log path is read directly as log
    // text (the loader auto-detects file vs folder vs archive). The CLI wires a
    // positional PATH straight to this loader.
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("oradaz.log");
    fs::write(&log_path, "2026-04-29 10:00:00 [graph] users HTTP 403\n").unwrap();
    let src = load_log_source(log_path.to_str().unwrap(), None, &FULL_NEEDS);
    assert!(!src.is_archive, "a .log file is not an archive");
    assert!(
        src.log_text.contains("graph"),
        "log text must be read from the plain file, got: {:?}",
        src.log_text
    );
}

#[test]
fn logs_details_pre_flight_banner_kicks_in_above_limit() {
    let mut entries = Vec::new();
    for i in 0..30 {
        entries.push(err_entry(
            &format!("api_{i:02}"),
            403,
            "Forbidden",
            "denied",
            &format!("2026-04-29 10:00:{i:02}"),
        ));
    }
    let filters = LogFilters {
        limit: Some(10),
        ..Default::default()
    };
    let text = render_details(&entries, filters);
    assert!(
        text.contains("30 groups") && text.contains("showing the 10"),
        "expected pre-flight banner, got:\n{text}"
    );
    assert!(text.contains("--all"));
    assert!(text.contains("--sort recent"));
    // Suggested drill-in pointers in the footer.
    assert!(text.contains("drill in"));
}

#[test]
fn logs_details_all_flag_disables_limit() {
    let mut entries = Vec::new();
    for i in 0..30 {
        entries.push(err_entry(
            &format!("api_{i:02}"),
            403,
            "Forbidden",
            "x",
            &format!("2026-04-29 10:00:{i:02}"),
        ));
    }
    let filters = LogFilters {
        all: true,
        ..Default::default()
    };
    let text = render_details(&entries, filters);
    assert!(text.contains("api_00") && text.contains("api_29"));
    assert!(!text.contains("groups —"), "no banner when --all");
}

#[test]
fn logs_details_sort_recent_orders_by_timestamp_desc() {
    // Two equal-count groups; recent-sort should place the later one first.
    let entries = vec![
        err_entry("alpha", 403, "Forbidden", "x", "2026-04-29 10:00:00"),
        err_entry("zulu", 403, "Forbidden", "x", "2026-04-29 11:00:00"),
    ];
    let filters = LogFilters {
        sort: oradaz::inspect::log_parser::SortBy::Recent,
        ..Default::default()
    };
    let text = render_details(&entries, filters);
    let pos_zulu = text.find("graph_zulu").unwrap();
    let pos_alpha = text.find("graph_alpha").unwrap();
    assert!(
        pos_zulu < pos_alpha,
        "recent sort should place zulu (later timestamp) first"
    );
}

#[test]
fn logs_details_truncates_long_message_with_ellipsis() {
    let long_msg = "x".repeat(100);
    let entries = vec![err_entry(
        "users",
        403,
        "Forbidden",
        &long_msg,
        "2026-04-29 10:00:00",
    )];
    let text = render_details(&entries, LogFilters::default());
    assert!(text.contains("…"), "long message must be ellipsised");
    // No row should be longer than ~95 chars (safe upper bound for 80-col target).
    for line in text.lines() {
        assert!(
            line.chars().count() < 200,
            "row unexpectedly long: {line:?}"
        );
    }
}

#[test]
fn logs_details_include_expected_pointer_only_when_filter_off() {
    let entries = vec![err_entry(
        "users",
        403,
        "Forbidden",
        "x",
        "2026-04-29 10:00:00",
    )];
    let on = render_details(
        &entries,
        LogFilters {
            include_expected: true,
            ..Default::default()
        },
    );
    let off = render_details(&entries, LogFilters::default());
    assert!(off.contains("--include-expected"));
    assert!(!on.contains("--include-expected"));
}

#[test]
fn logs_full_renders_response_body_when_dump_error_present() {
    let mut source = make_mock_log_source();
    source.dump_errors = vec![oradaz::collect::dump::response::DumpError {
        folder: "graph".to_string(),
        file: "users".to_string(),
        url: "https://example/users".to_string(),
        status: 403,
        code: "Forbidden".to_string(),
        message: "Access denied".to_string(),
        expected: false,
        full_response: Some(serde_json::json!({
            "error": {"code": "Forbidden", "message": "Access denied — missing scope."}
        })),
        post_data: None,
    }];
    let entries = vec![err_entry(
        "users",
        403,
        "Forbidden",
        "Access denied",
        "2026-04-29 10:00:00",
    )];
    let filters = LogFilters {
        full: true,
        ..Default::default()
    };
    let mut out: Vec<String> = vec![];
    print_all_api_errors(&entries, &mut out, &source, &filters);
    let text = out
        .iter()
        .map(|l| strip_ansi_codes(l))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(text.contains("Response"));
    assert!(
        text.contains("missing scope"),
        "body content must be in output"
    );
    // The new section title.
    assert!(text.contains("ENTRY DETAILS"));
}

#[test]
fn test_print_timeline_only_429() {
    let entries: Vec<LogEntry> = vec![
        LogEntry {
            timestamp: "2026-04-29 10:00:00".to_string(),
            level: LogLevel::Error,
            module: "graph".to_string(),
            service: Some("graph".to_string()),
            api: Some("api".to_string()),
            url: None,
            http_status: Some(429),
            upstream_code: None,
            message: "Too Many".to_string(),
        },
        LogEntry {
            timestamp: "2026-04-29 10:00:01".to_string(),
            level: LogLevel::Error,
            module: "graph".to_string(),
            service: Some("graph".to_string()),
            api: Some("api".to_string()),
            url: None,
            http_status: Some(403),
            upstream_code: None,
            message: "Forbidden".to_string(),
        },
    ];

    let mut lines = vec![];
    print_timeline(&entries, true, None, &mut lines);

    let output: String = lines
        .iter()
        .map(|l| strip_ansi_codes(l))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(output.contains("TIMELINE (429 by second)"));
    // Only 429 should be counted
    // The bar should represent 1 error
    assert!(output.contains(" 1 "));
    // If 403 was counted, it would be 2.
    assert!(!output.contains(" 2 "));
}
