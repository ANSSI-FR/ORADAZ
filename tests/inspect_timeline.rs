mod common;

use oradaz::collect::dump::response::DumpError;
use oradaz::inspect::display::{TimelineOptions, print_timeline_view, strip_ansi_codes};
use oradaz::inspect::loader::LogSource;
use oradaz::inspect::log_parser::{LogEntry, LogLevel};

use serde_json::{Value, json};

// ─── fixtures ────────────────────────────────────────────────────────────

fn err(api: &str, status: u16, ts: &str) -> LogEntry {
    LogEntry {
        timestamp: ts.to_string(),
        level: LogLevel::Error,
        module: "graph".to_string(),
        service: Some("graph".to_string()),
        api: Some(api.to_string()),
        url: None,
        http_status: Some(status),
        upstream_code: Some("Forbidden".to_string()),
        message: "x".to_string(),
    }
}

fn stats_with_three_apis() -> Value {
    json!({
        "duration_seconds": 100,
        "services": {
            "graph":     {"http_batch_calls": 10, "http_single_calls": 0, "http_call_failures": 0},
            "resources": {"http_batch_calls":  5, "http_single_calls": 0, "http_call_failures": 0},
        },
        "apis": [
            // Critical: unexpected errors
            {"service": "graph", "api": "users", "requests_sent": 50,
             "unexpected_errors": 2, "expected_errors": 0, "network_errors": 0,
             "retries_real": 0, "retries_rate_limit": 0, "rate_limit_wait_secs": 0,
             "prereq_rechecks_triggered": 0,
             "first_request_at": "2026-05-27T06:57:12Z",
             "last_request_at":  "2026-05-27T06:57:15Z",
             "responses_by_status": {"200": 48, "403": 2},
             "upstream_error_codes": {"Forbidden": 2}},
            // Warning: heavy throttling
            {"service": "resources", "api": "roleAssignments", "requests_sent": 44,
             "unexpected_errors": 0, "expected_errors": 0, "network_errors": 0,
             "retries_real": 0, "retries_rate_limit": 31, "rate_limit_wait_secs": 268,
             "prereq_rechecks_triggered": 0,
             "first_request_at": "2026-05-27T06:55:40Z",
             "last_request_at":  "2026-05-27T06:57:30Z",
             "responses_by_status": {"200": 13, "429": 31},
             "upstream_error_codes": {}},
            // Clean — must not appear in PROBLEMATIC APIS.
            {"service": "graph", "api": "groups", "requests_sent": 10,
             "unexpected_errors": 0, "expected_errors": 0, "network_errors": 0,
             "retries_real": 0, "retries_rate_limit": 0, "rate_limit_wait_secs": 0,
             "prereq_rechecks_triggered": 0,
             "first_request_at": "2026-05-27T06:55:11Z",
             "last_request_at":  "2026-05-27T06:55:30Z",
             "responses_by_status": {"200": 10}, "upstream_error_codes": {}},
        ],
    })
}

fn make_source(stats: Option<Value>) -> LogSource {
    LogSource {
        log_text: String::new(),
        dump_errors: Vec::<DumpError>::new(),
        metadata: Some(json!({
            "auth_errors": 0,
            "prerequisites_errors": 0,
            "unexpected_errors": 2,
            "services": {"graph": "enabled", "resources": "enabled"},
        })),
        config: None,
        prerequisites: None,
        stats,
        is_archive: true,
        is_broken: false,
        size_bytes: None,
    }
}

fn rendered(source: &LogSource, entries: &[LogEntry], opts: &TimelineOptions) -> String {
    let mut out: Vec<String> = vec![String::new()];
    print_timeline_view(source, entries, opts, &mut out);
    out.iter()
        .map(|l| strip_ansi_codes(l))
        .collect::<Vec<_>>()
        .join("\n")
}

fn opts_default() -> TimelineOptions {
    TimelineOptions {
        service: None,
        only_429: false,
        problematic_only: false,
        bucket: None,
    }
}

// ─── tests ────────────────────────────────────────────────────────────────

#[test]
fn timeline_renders_all_sections_with_verdict_header() {
    let source = make_source(Some(stats_with_three_apis()));
    let entries = vec![err("users", 403, "2026-05-27 06:57:12")];
    let text = rendered(&source, &entries, &opts_default());
    assert!(text.contains("TIMELINE"));
    assert!(
        text.contains("PARTIAL"),
        "verdict should be PARTIAL (2 unexpected_errors)"
    );
    assert!(text.contains("Window 2026-05-27 06:57:12"));
    assert!(text.contains("granularity auto"));
    assert!(text.contains("API ACTIVITY WINDOWS"));
    assert!(text.contains("PROBLEMATIC APIS (when)"));
}

#[test]
fn timeline_activity_windows_lists_apis_sorted_by_duration_desc() {
    let source = make_source(Some(stats_with_three_apis()));
    let text = rendered(&source, &[], &opts_default());
    // resources/roleAssignments spans 1m50s (110s) — should come before
    // graph/users (3s) and graph/groups (19s).
    let pos_resources = text.find("resources/roleAssignments").unwrap();
    let pos_groups = text.find("graph/groups").unwrap();
    let pos_users = text.find("graph/users").unwrap();
    assert!(pos_resources < pos_groups);
    assert!(pos_groups < pos_users);
}

#[test]
fn timeline_problematic_critical_first_then_warning() {
    let source = make_source(Some(stats_with_three_apis()));
    let text = rendered(&source, &[], &opts_default());
    let prob_start = text.find("PROBLEMATIC APIS (when)").unwrap();
    let prob_section = &text[prob_start..];
    let pos_users = prob_section.find("graph/users").unwrap();
    let pos_role = prob_section.find("resources/roleAssignments").unwrap();
    assert!(
        pos_users < pos_role,
        "critical (graph/users, 2 unexpected) must precede warning (resources, 31× 429)"
    );
    // graph/groups is clean — must NOT appear in problematic list.
    assert!(
        !prob_section.contains("graph/groups"),
        "clean API must be omitted from problematic list, got:\n{prob_section}"
    );
}

#[test]
fn timeline_problematic_row_shows_time_range_and_details() {
    let source = make_source(Some(stats_with_three_apis()));
    let text = rendered(&source, &[], &opts_default());
    assert!(text.contains("2 unexpected errors"));
    assert!(text.contains("31× 429"));
    assert!(text.contains("268 s"));
    // HH:MM:SS – HH:MM:SS time range.
    assert!(text.contains("06:57:12 – 06:57:15"));
    assert!(text.contains("06:55:40 – 06:57:30"));
}

#[test]
fn timeline_service_filter_narrows_activity_and_problematic() {
    let source = make_source(Some(stats_with_three_apis()));
    let opts = TimelineOptions {
        service: Some("graph".to_string()),
        ..opts_default()
    };
    let text = rendered(&source, &[], &opts);
    assert!(text.contains("graph/users"));
    assert!(
        !text.contains("resources/roleAssignments"),
        "resources should be filtered out"
    );
}

#[test]
fn timeline_only_429_drops_unexpected_from_problematic_list() {
    let source = make_source(Some(stats_with_three_apis()));
    let opts = TimelineOptions {
        only_429: true,
        ..opts_default()
    };
    let text = rendered(&source, &[], &opts);
    let prob_section = &text[text.find("PROBLEMATIC APIS (when)").unwrap()..];
    assert!(
        !prob_section.contains("unexpected"),
        "--only-429 must drop unexpected-error rows"
    );
    assert!(prob_section.contains("resources/roleAssignments"));
}

#[test]
fn timeline_problematic_only_hides_chart_and_activity_table() {
    let source = make_source(Some(stats_with_three_apis()));
    let entries = vec![err("users", 403, "2026-05-27 06:57:12")];
    let opts = TimelineOptions {
        problematic_only: true,
        ..opts_default()
    };
    let text = rendered(&source, &entries, &opts);
    assert!(text.contains("PROBLEMATIC APIS (when)"));
    assert!(
        !text.contains("API ACTIVITY WINDOWS"),
        "--problematic-only must hide activity windows section"
    );
    // Header line for the chart section ("TIMELINE (...)") should also be absent.
    let chart_visible = text
        .lines()
        .any(|l| l.contains("TIMELINE (") && !l.contains("PARTIAL"));
    assert!(!chart_visible, "--problematic-only must hide the chart");
}

#[test]
fn timeline_bucket_override_changes_granularity_label() {
    let source = make_source(Some(stats_with_three_apis()));
    let entries = vec![err("users", 403, "2026-05-27 06:57:12")];
    let opts = TimelineOptions {
        bucket: Some(60),
        ..opts_default()
    };
    let text = rendered(&source, &entries, &opts);
    assert!(text.contains("granularity 1 m"));
}

#[test]
fn timeline_handles_missing_stats_gracefully() {
    let source = make_source(None);
    let entries = vec![err("users", 403, "2026-05-27 06:57:12")];
    let text = rendered(&source, &entries, &opts_default());
    assert!(text.contains("TIMELINE"));
    assert!(
        text.contains("(no stats.json found)"),
        "activity-windows / problematic sections must degrade with a clear message"
    );
}

#[test]
fn timeline_handles_no_entries_clear_message() {
    let source = make_source(Some(stats_with_three_apis()));
    let opts = opts_default();
    let text = rendered(&source, &[], &opts);
    assert!(text.contains("no entries in the selected window"));
}
