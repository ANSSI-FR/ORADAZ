mod common;

use oradaz::collect::dump::response::DumpError;
use oradaz::inspect::display::{print_compare_section, strip_ansi_codes};
use oradaz::inspect::loader::LogSource;

use serde_json::{Value, json};

// ─── fixtures ────────────────────────────────────────────────────────────

fn make_source(metadata: Value, stats: Option<Value>, config: Option<Value>) -> LogSource {
    LogSource {
        log_text: String::new(),
        dump_errors: Vec::<DumpError>::new(),
        metadata: Some(metadata),
        config,
        prerequisites: None,
        stats,
        is_archive: true,
        is_broken: false,
        size_bytes: Some(6_000_000),
    }
}

fn rendered(a: &LogSource, b: &LogSource) -> String {
    let mut out: Vec<String> = vec![String::new()];
    print_compare_section(a, b, &mut out);
    out.iter()
        .map(|l| strip_ansi_codes(l))
        .collect::<Vec<_>>()
        .join("\n")
}

// ─── headers + verdict per source ────────────────────────────────────────

#[test]
fn compare_header_shows_both_sources_with_verdict() {
    let a = make_source(
        json!({"collection_date": "2026-05-27 06:55:05",
               "total_duration_secs": 39,
               "auth_errors": 0, "unexpected_errors": 0, "prerequisites_errors": 0}),
        None,
        None,
    );
    let b = make_source(
        json!({"collection_date": "2026-05-28 06:51:10",
               "total_duration_secs": 44,
               "auth_errors": 0, "unexpected_errors": 2, "prerequisites_errors": 0}),
        None,
        None,
    );
    let text = rendered(&a, &b);
    assert!(text.contains("COMPARE COLLECTIONS"));
    let header = text
        .split_once("QUALITY DELTAS")
        .map(|(h, _)| h.to_string())
        .unwrap_or(text.clone());
    assert!(header.contains("A  2026-05-27 06:55:05"));
    assert!(header.contains("B  2026-05-28 06:51:10"));
    assert!(header.contains("COMPLETE"), "A should be COMPLETE");
    assert!(header.contains("PARTIAL"), "B should be PARTIAL");
}

// ─── QUALITY DELTAS ──────────────────────────────────────────────────────

#[test]
fn compare_quality_deltas_render_metrics_and_signs() {
    let a = make_source(
        json!({"auth_errors": 0, "unexpected_errors": 0, "prerequisites_errors": 0,
               "expected_errors": 3, "total_duration_secs": 39}),
        None,
        None,
    );
    let b = make_source(
        json!({"auth_errors": 0, "unexpected_errors": 2, "prerequisites_errors": 0,
               "expected_errors": 3, "total_duration_secs": 44}),
        None,
        None,
    );
    let text = rendered(&a, &b);
    assert!(text.contains("QUALITY DELTAS"));
    assert!(text.contains("Unexpected errors"));
    assert!(text.contains("Expected errors"));
    assert!(text.contains("429 retries"));
    // L2: relabelled from "Network errors" → "Request failures".
    assert!(text.contains("Request failures"));
    assert!(text.contains("Duration (s)"));
    // Δ markers visible (in no-color mode: + / - / =).
    assert!(text.contains(" +2"), "expected +2 for unexpected");
    assert!(text.contains(" +5"), "expected +5 s for duration");
    // Several rows are unchanged (3 vs 3 expected errors, 0 vs 0 retries, etc.)
    // and must end with `=` (after stripping color codes).
    assert!(
        text.lines().any(|l| l.trim_end().ends_with("=")),
        "expected at least one row ending in =, got:\n{text}"
    );
}

/// "Expected errors" falls back to summing `stats.apis[].expected_errors` when
/// the metadata counter is absent (archives predating that field), mirroring the
/// `unexpected_count` fallback — instead of misreporting 0.
#[test]
fn compare_expected_errors_falls_back_to_stats_for_old_archives() {
    // A: no `expected_errors` in metadata → stats fallback (3 + 1 = 4).
    let a = make_source(
        json!({"auth_errors": 0, "unexpected_errors": 0, "prerequisites_errors": 0}),
        Some(json!({"apis": [
            {"expected_errors": 3},
            {"expected_errors": 1}
        ]})),
        None,
    );
    // B: modern archive — the metadata counter is used directly.
    let b = make_source(
        json!({"auth_errors": 0, "unexpected_errors": 0, "prerequisites_errors": 0,
               "expected_errors": 7}),
        None,
        None,
    );
    let text = rendered(&a, &b);
    assert!(text.contains("Expected errors"));
    assert!(
        text.contains(" +3"),
        "expected a 4 (stats fallback) -> 7 (metadata) delta of +3:\n{text}"
    );
}

#[test]
fn compare_quality_deltas_include_throttling_and_writer_peaks() {
    // The debug-telemetry peaks must surface as QUALITY DELTAS so the slow-start /
    // ARM-window / writer-saturation comparison is readable cross-run.
    let a = make_source(
        json!({"peak_backoff_active": 4, "peak_writer_queue_pct": 10,
               "writer_budget_blocked_secs": 0}),
        None,
        None,
    );
    let b = make_source(
        json!({"peak_backoff_active": 30, "peak_writer_queue_pct": 75,
               "writer_budget_blocked_secs": 12}),
        None,
        None,
    );
    let text = rendered(&a, &b);
    assert!(text.contains("Backoff peak"));
    assert!(text.contains("Writer queue peak %"));
    assert!(text.contains("Writer blocked (s)"));
    assert!(text.contains(" +26"), "expected +26 backoff delta:\n{text}");
    assert!(
        text.contains(" +65"),
        "expected +65 writer-queue delta:\n{text}"
    );
    assert!(
        text.contains(" +12"),
        "expected +12 writer-blocked delta:\n{text}"
    );
}

#[test]
fn compare_quality_deltas_include_lost_data_and_stalls() {
    // Reliability counters: lost-data abandonments (the PARTIAL-verdict driver)
    // and stall-watchdog fires; both read 0 on archives predating the fields.
    let a = make_source(
        json!({"lost_data_errors": 0, "stall_events": 0}),
        None,
        None,
    );
    let b = make_source(
        json!({"lost_data_errors": 7, "stall_events": 2}),
        None,
        None,
    );
    let text = rendered(&a, &b);
    assert!(text.contains("Lost data (abandoned)"));
    assert!(text.contains("Stall watchdog fires"));
    assert!(text.contains(" +7"), "expected +7 lost-data delta:\n{text}");
    assert!(text.contains(" +2"), "expected +2 stall delta:\n{text}");
}

// ─── COVERAGE DELTAS ─────────────────────────────────────────────────────

#[test]
fn compare_coverage_per_service_object_deltas() {
    let a = make_source(
        json!({"auth_errors": 0, "unexpected_errors": 0,
        "tables": [
            {"folder": "graph", "file": "users", "count": 7842},
            {"folder": "resources", "file": "subs", "count": 9542},
            {"folder": "exchange", "file": "mb", "count": 21},
        ]}),
        None,
        None,
    );
    let b = make_source(
        json!({"auth_errors": 0, "unexpected_errors": 0,
        "tables": [
            {"folder": "graph", "file": "users", "count": 7901},
            {"folder": "resources", "file": "subs", "count": 9488},
            // exchange dropped entirely in B
        ]}),
        None,
        None,
    );
    let text = rendered(&a, &b);
    assert!(text.contains("COVERAGE DELTAS"));
    // Graph: 7842 → 7901  (+59)
    assert!(text.contains("7 842") && text.contains("7 901"));
    // Resources: 9542 → 9488  (-54)
    assert!(text.contains("9 542") && text.contains("9 488"));
    // Exchange: 21 → 0 with "not collected in B" annotation
    assert!(text.contains("Exchange"));
    assert!(text.contains("not collected in B"));
}

/// Guards the intentional unification of the compare delta tables onto the shared
/// `render_table` renderer: the A and B value columns sit side by side (separated
/// by padding), with direction shown only by the Δ column's ▲/▼ glyph — not by a
/// `→` separator between A and B. (`→` is still used by CONFIG CHANGES rows, so the
/// assertion is scoped to the coverage-delta row.)
#[test]
fn compare_coverage_delta_row_uses_unified_layout_without_arrow() {
    let a = make_source(
        json!({"auth_errors": 0, "unexpected_errors": 0,
        "tables": [{"folder": "graph", "file": "users", "count": 7842}]}),
        None,
        None,
    );
    let b = make_source(
        json!({"auth_errors": 0, "unexpected_errors": 0,
        "tables": [{"folder": "graph", "file": "users", "count": 7901}]}),
        None,
        None,
    );
    let text = rendered(&a, &b);

    // The single coverage-delta row carries both values on one line.
    let row = text
        .lines()
        .find(|l| l.contains("7 842") && l.contains("7 901"))
        .expect("a coverage-delta row carrying both A and B values");
    assert!(
        !row.contains('→'),
        "coverage-delta row must use the unified, arrow-less layout; got: {row:?}"
    );
    // Direction/magnitude is still shown by the Δ column (+59 = 7901 − 7842).
    assert!(
        row.contains("+59"),
        "Δ column must show the signed delta; got: {row:?}"
    );
}

// ─── TOP TABLE MOVERS ────────────────────────────────────────────────────

#[test]
fn compare_table_movers_joined_on_folder_file_tuple() {
    // Build two collections where two services have a table named "x" — must
    // not collapse them when computing deltas.
    let a = make_source(
        json!({"auth_errors": 0,
        "tables": [
            {"folder": "graph",     "file": "x", "count": 100},
            {"folder": "resources", "file": "x", "count": 50},
            {"folder": "graph",     "file": "y", "count": 10},
        ]}),
        None,
        None,
    );
    let b = make_source(
        json!({"auth_errors": 0,
        "tables": [
            {"folder": "graph",     "file": "x", "count": 200},
            {"folder": "resources", "file": "x", "count": 60},
        ]}),
        None,
        None,
    );
    let text = rendered(&a, &b);
    assert!(text.contains("TOP TABLE MOVERS"));
    assert!(text.contains("graph/x"));
    assert!(text.contains("resources/x"));
    assert!(text.contains("graph/y"));
    // graph/x has the biggest absolute delta (+100); should come first.
    let pos_gx = text.find("graph/x").unwrap();
    let pos_rx = text.find("resources/x").unwrap();
    assert!(
        pos_gx < pos_rx,
        "graph/x (Δ=100) should precede resources/x (Δ=10)"
    );
}

#[test]
fn compare_table_movers_skips_unchanged() {
    let a = make_source(
        json!({"tables": [
            {"folder": "graph", "file": "x", "count": 100},
            {"folder": "graph", "file": "stable", "count": 50},
        ]}),
        None,
        None,
    );
    let b = make_source(
        json!({"tables": [
            {"folder": "graph", "file": "x", "count": 200},
            {"folder": "graph", "file": "stable", "count": 50},
        ]}),
        None,
        None,
    );
    let text = rendered(&a, &b);
    assert!(text.contains("graph/x"));
    assert!(
        !text.contains("graph/stable"),
        "unchanged tables must be omitted from the movers list"
    );
}

#[test]
fn compare_table_movers_empty_message_when_no_change() {
    let same = json!({"tables": [
        {"folder": "graph", "file": "x", "count": 100},
    ]});
    let a = make_source(same.clone(), None, None);
    let b = make_source(same, None, None);
    let text = rendered(&a, &b);
    assert!(text.contains("no table changed"));
}

// ─── CONFIG CHANGES ──────────────────────────────────────────────────────

#[test]
fn compare_config_changes_lists_diffs_only() {
    let a = make_source(
        json!({}),
        None,
        Some(json!({
            "proxy": false,
            "trace_logs": false,
            "concurrency_max_window": 30u64,
            "services": {"service": [
                {"@name": "exchange", "#text": true},
                {"@name": "graph", "#text": true},
            ]},
        })),
    );
    let b = make_source(
        json!({}),
        None,
        Some(json!({
            "proxy": false,
            "trace_logs": true,             // changed
            "concurrency_max_window": 100u64, // changed
            "services": {"service": [
                {"@name": "exchange", "#text": false}, // changed
                {"@name": "graph", "#text": true},
            ]},
        })),
    );
    let text = rendered(&a, &b);
    let cfg = text
        .split_once("CONFIG CHANGES")
        .map(|(_, t)| t.to_string())
        .unwrap_or_default();
    assert!(cfg.contains("trace_logs"));
    assert!(cfg.contains("no → yes"));
    assert!(cfg.contains("concurrency_max_window"));
    assert!(cfg.contains("30 → 100"));
    assert!(cfg.contains("services.exchange"));
    assert!(cfg.contains("on → off"));
    // proxy unchanged → must not appear.
    assert!(!cfg.contains("proxy"), "unchanged toggle must be omitted");
}

#[test]
fn compare_config_changes_includes_liveness_ceiling_secs() {
    // liveness_ceiling_secs is a tuning field (the sole transient-retry bound and
    // an A/B knob); a pair differing only in it must appear under CONFIG CHANGES.
    let a = make_source(
        json!({}),
        None,
        Some(json!({ "liveness_ceiling_secs": 900u64 })),
    );
    let b = make_source(
        json!({}),
        None,
        Some(json!({ "liveness_ceiling_secs": 600u64 })),
    );
    let text = rendered(&a, &b);
    let cfg = text
        .split_once("CONFIG CHANGES")
        .map(|(_, t)| t.to_string())
        .unwrap_or_default();
    assert!(cfg.contains("liveness_ceiling_secs"));
    assert!(cfg.contains("900 → 600"));
}

#[test]
fn compare_config_changes_says_so_when_identical() {
    let cfg = json!({"proxy": false, "concurrency_max_window": 30u64});
    let a = make_source(json!({}), None, Some(cfg.clone()));
    let b = make_source(json!({}), None, Some(cfg));
    let text = rendered(&a, &b);
    assert!(text.contains("no relevant config field changed"));
}

/// The breaker-skipped delta sums the per-API map and reads as neutral (a
/// reduction signal, not a regression in either direction).
#[test]
fn compare_breaker_skipped_delta_renders() {
    let a = make_source(serde_json::json!({"dump_duration_secs": 100}), None, None);
    let b = make_source(
        serde_json::json!({
            "dump_duration_secs": 100,
            "breaker_skipped_by_api": {"graph/x": 100, "graph/y": 20},
        }),
        None,
        None,
    );
    let text = rendered(&a, &b);
    let line = text
        .lines()
        .find(|l| l.contains("Breaker-skipped URLs"))
        .unwrap_or_else(|| panic!("breaker delta row missing:\n{text}"));
    assert!(
        line.contains('0') && line.contains("120"),
        "delta must sum the per-API map (0 -> 120): {line:?}"
    );
}
