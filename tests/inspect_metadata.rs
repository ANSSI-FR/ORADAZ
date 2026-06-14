mod common;

use oradaz::VERSION;
use oradaz::inspect::display::{print_metadata_section, strip_ansi_codes};
use serde_json::{Value, json};

fn rendered(metadata: Option<&Value>, top: usize, all: bool) -> String {
    let mut lines: Vec<String> = vec![];
    print_metadata_section(metadata, None, top, all, &mut lines);
    lines
        .iter()
        .map(|l| strip_ansi_codes(l))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn metadata_section_contains_collection_summary() {
    let metadata = json!({
        "tenant": "test-tenant-id",
        "collection_date": "2026-04-29 17:43:31",
        "dump_duration_secs": 10,
        "oradaz_version": VERSION,
        "schema_version": VERSION,
        "schema_hash": "abcdef1234567890",
    });
    let text = rendered(Some(&metadata), 10, false);
    assert!(text.contains("COLLECTION SUMMARY"));
    assert!(text.contains("test-tenant-id"));
    assert!(text.contains(VERSION));
}

#[test]
fn metadata_section_error_counters_full_breakdown() {
    let metadata = json!({
        "auth_errors": 2,
        "prerequisites_errors": 1,
        "errors": 95,
        "expected_errors": 3,
        "unexpected_errors": 5,
    });
    let text = rendered(Some(&metadata), 10, false);
    assert!(text.contains("ERROR COUNTERS"));
    assert!(text.contains("Authentication errors") && text.contains(" 2"));
    assert!(text.contains("Prerequisite errors") && text.contains(" 1"));
    // Total + breakdown on the same line: 95 total, 3 expected, 5 unexpected,
    // 87 non-HTTP (= 95 - 3 - 5).
    assert!(text.contains("Errors (errors.json)"));
    assert!(text.contains("3 expected"));
    assert!(text.contains("5 unexpected"));
    assert!(text.contains("87 non-HTTP"));
}

#[test]
fn metadata_section_error_counters_prefers_exact_non_http_field() {
    // expected + unexpected (13) exceeds errors (10) — the derivation would
    // underflow and clamp to 0. The exact `non_http_errors` counter must be
    // shown instead.
    let metadata = json!({
        "errors": 10,
        "expected_errors": 8,
        "unexpected_errors": 5,
        "non_http_errors": 4,
    });
    let text = rendered(Some(&metadata), 10, false);
    assert!(
        text.contains("4 non-HTTP"),
        "exact counter must win:\n{text}"
    );
    assert!(
        !text.contains("0 non-HTTP"),
        "must not show the underflowed derivation:\n{text}"
    );
}

#[test]
fn metadata_section_error_counters_default_when_fields_absent() {
    let metadata = json!({"errors": 0});
    let text = rendered(Some(&metadata), 10, false);
    // Missing fields → all zeros.
    assert!(text.contains("Authentication errors"));
    assert!(text.contains("0 expected"));
    assert!(text.contains("0 unexpected"));
    assert!(text.contains("0 non-HTTP"));
}

#[test]
fn metadata_section_data_manifest_groups_by_service() {
    let metadata = json!({
        "tables": [
            {"name": "users", "folder": "graph", "file": "users", "count": 100},
            {"name": "sps", "folder": "graph", "file": "sps", "count": 50},
            {"name": "subs", "folder": "resources", "file": "subs", "count": 3},
            {"name": "mb", "folder": "exchange", "file": "mb", "count": 21},
        ]
    });
    let text = rendered(Some(&metadata), 10, false);
    assert!(text.contains("DATA MANIFEST"));
    // Service headers with totals.
    assert!(
        text.contains("Graph — 150 objects · 2 tables"),
        "Graph total must group its tables, got:\n{text}"
    );
    assert!(text.contains("Resources — 3 objects · 1 tables"));
    assert!(text.contains("Exchange — 21 objects · 1 tables"));
    // Service order is canonical: graph, resources, exchange.
    let pos_g = text.find("Graph —").unwrap();
    let pos_r = text.find("Resources —").unwrap();
    let pos_e = text.find("Exchange —").unwrap();
    assert!(pos_g < pos_r && pos_r < pos_e);
}

#[test]
fn metadata_section_tables_sorted_by_count_desc_within_service() {
    let metadata = json!({
        "tables": [
            {"name": "small",  "folder": "graph", "count": 1},
            {"name": "big",    "folder": "graph", "count": 100},
            {"name": "medium", "folder": "graph", "count": 50},
        ]
    });
    let text = rendered(Some(&metadata), 10, false);
    let pos_big = text.find("big").unwrap();
    let pos_med = text.find("medium").unwrap();
    let pos_small = text.find("small").unwrap();
    assert!(pos_big < pos_med && pos_med < pos_small);
}

#[test]
fn metadata_section_top_n_caps_per_service_and_shows_more_footer() {
    let mut tables: Vec<Value> = Vec::new();
    for i in 0..15 {
        tables.push(json!({"name": format!("t{i:02}"), "folder": "graph", "count": 100 - i}));
    }
    let metadata = json!({"tables": tables});
    let text = rendered(Some(&metadata), 5, false);
    // Show 5 tables + "(10 more tables — use --all)"
    assert!(text.contains("t00"));
    assert!(text.contains("t04"));
    assert!(!text.contains(" t05 "), "should have truncated at 5");
    assert!(text.contains("10 more tables — use --all"));
}

#[test]
fn metadata_section_all_disables_per_service_limit() {
    let mut tables: Vec<Value> = Vec::new();
    for i in 0..15 {
        tables.push(json!({"name": format!("t{i:02}"), "folder": "graph", "count": 100 - i}));
    }
    let metadata = json!({"tables": tables});
    let text = rendered(Some(&metadata), 5, true);
    assert!(text.contains("t00"));
    assert!(text.contains("t14"));
    assert!(!text.contains("more tables"));
}

#[test]
fn metadata_section_tables_without_folder_go_to_other_bucket() {
    let metadata = json!({
        "tables": [
            {"name": "users",   "folder": "graph", "count": 10},
            {"name": "orphan1", "count": 5},
            {"name": "orphan2", "count": 3},
        ]
    });
    let text = rendered(Some(&metadata), 10, false);
    assert!(text.contains("Graph — 10 objects"));
    // Orphans go to "(other)" group.
    assert!(text.contains("(other) — 8 objects · 2 tables"));
    assert!(text.contains("orphan1"));
    assert!(text.contains("orphan2"));
}

#[test]
fn metadata_section_no_metadata_fallback() {
    let text = rendered(None, 10, false);
    assert!(text.contains("no metadata available"));
}

#[test]
fn metadata_section_empty_tables_fallback() {
    let metadata = json!({"tables": []});
    let text = rendered(Some(&metadata), 10, false);
    assert!(text.contains("no tables found"));
}

#[test]
fn metadata_section_renders_writer_throttling_observability() {
    let metadata = json!({
        "peak_writer_queue_pct": 73,
        "peak_writer_inflight_bytes": 268_435_456u64,
        "writer_budget_blocked_secs": 12,
        "writer_budget_blocked_count": 4,
        "peak_backoff_active": 9,
        "min_window_by_service": {"resources": 1, "graph": 80},
        "window_decreases_by_service": {"resources": 7, "graph": 0},
        "window_increases_by_service": {"resources": 3},
        "time_at_floor_secs_by_service": {"resources": 120},
    });
    let text = rendered(Some(&metadata), 10, false);
    assert!(text.contains("WRITER & THROTTLING"));
    assert!(text.contains("Writer queue peak"));
    assert!(text.contains("73%"));
    assert!(text.contains("Writer budget-blocked"));
    assert!(text.contains("12s over 4 stall(s)"));
    assert!(text.contains("Backoff slots peak"));
    // Only services that actually collapsed (decreases > 0) are listed, with the
    // recovery (increases) and floor-duration dynamics.
    assert!(
        text.contains("resources")
            && text.contains("floor 1")
            && text.contains("7 halvings")
            && text.contains("3 increases")
            && text.contains("120s at floor"),
        "the collapsed service must show floor, halvings, increases, and time-at-floor:\n{text}"
    );
    assert!(
        !text.contains("graph                       floor"),
        "a service with 0 halvings must be omitted from the collapse list"
    );
}

/// A sub-second total blocked time (integer seconds rounds to 0) with a non-zero
/// stall count must render `<1s`, not the self-contradictory `0s over N stall(s)`.
#[test]
fn metadata_section_observability_sub_second_blocked_renders_lt_1s() {
    let metadata = json!({
        "writer_budget_blocked_secs": 0,
        "writer_budget_blocked_count": 1,
    });
    let text = rendered(Some(&metadata), 10, false);
    assert!(
        text.contains("<1s over 1 stall(s)"),
        "0 s + 1 stall must render as <1s, got:\n{text}"
    );
    assert!(!text.contains("0s over 1 stall"));
}

/// Older archives lack the new observability fields: the section must still
/// render (zeros), never panic.
#[test]
fn metadata_section_observability_defaults_when_absent() {
    let metadata = json!({"errors": 0});
    let text = rendered(Some(&metadata), 10, false);
    assert!(text.contains("WRITER & THROTTLING"));
    assert!(text.contains("Writer queue peak"));
    // The new volume/phase/runtime context lines render with defaults too.
    assert!(text.contains("Total data written"));
    assert!(text.contains("Auth+prereq phase"));
    assert!(text.contains("CPU parallelism"));
    // Reliability blocks are presence-gated: an old archive without the fields
    // must not show them (a fabricated 0 would read as a measured clean run).
    assert!(!text.contains("Service pauses"));
    assert!(!text.contains("Token refreshes"));
    assert!(!text.contains("Retry-After clamped"));
    assert!(!text.contains("Stall watchdog fired"));
    assert!(!text.contains("Lost data (abandoned)"));
    assert!(!text.contains("Expected-error breaker"));
    assert!(!text.contains("429 escalation engaged"));
    assert!(!text.contains("Response admission wait"));
}

/// The breaker / 429-escalation / response-admission telemetry renders when
/// present, listing only non-zero buckets.
#[test]
fn metadata_section_renders_breaker_and_escalation_telemetry() {
    let metadata = json!({
        "errors": 0,
        "breaker_skipped_by_api": {"graph/users_permissionGrants": 16200, "graph/clean": 0},
        "cooldown_escalated_by_api": {"graph/authenticationMethodsPolicy": 41},
        "resp_sem_wait_ms_total": 1234,
    });
    let text = rendered(Some(&metadata), 10, false);
    assert!(
        text.contains("Expected-error breaker:") && text.contains("16200 URL(s) skipped"),
        "breaker block with per-bucket skip count:\n{text}"
    );
    assert!(
        !text.contains("graph/clean"),
        "zero-count buckets must be omitted:\n{text}"
    );
    assert!(
        text.contains("429 escalation engaged:") && text.contains("max streak 41"),
        "escalation block with the bucket's max streak:\n{text}"
    );
    assert!(
        text.contains("Response admission wait") && text.contains("1234ms total"),
        "response-worker admission wait:\n{text}"
    );
}

/// Reliability telemetry: pause/token-refresh/clamp maps, the stall counter and
/// the lost-data counter render when present, listing only non-zero services.
#[test]
fn metadata_section_renders_reliability_telemetry() {
    let metadata = json!({
        "errors": 3,
        "expected_errors": 1,
        "unexpected_errors": 0,
        "non_http_errors": 2,
        "lost_data_errors": 2,
        "pause_secs_by_service": {"graph": 42, "exchange": 0},
        "token_refreshes_by_service": {"graph": 2},
        "retry_after_clamped_by_service": {"resources": 5},
        "stall_events": 1,
    });
    let text = rendered(Some(&metadata), 10, false);
    assert!(
        text.contains("Lost data (abandoned)") && text.contains("lost_data_by_code"),
        "lost-data counter with the stats.json pointer:\n{text}"
    );
    assert!(
        text.contains("Service pauses (prereq/token):") && text.contains("42s paused"),
        "pause accounting for the paused service:\n{text}"
    );
    assert!(
        !text.contains("exchange                    0s paused"),
        "zero-second services must be omitted:\n{text}"
    );
    assert!(
        text.contains("Token refreshes (mid-dump):") && text.contains("2 refreshes"),
        "token refresh count:\n{text}"
    );
    assert!(
        text.contains("Retry-After clamped:") && text.contains("5 clamped cooldown(s)"),
        "clamped-cooldown count:\n{text}"
    );
    let stall_line = text
        .lines()
        .find(|l| l.contains("Stall watchdog fired"))
        .unwrap_or_else(|| panic!("stall line missing:\n{text}"));
    assert!(
        stall_line.trim_end().ends_with('1'),
        "stall count must be on the stall line itself: {stall_line:?}"
    );
}

/// The new volume / phase / runtime context lines and the per-service AIMD
/// ceiling-contention block render from their metadata fields.
#[test]
fn metadata_section_renders_volume_phase_and_ceiling_contention() {
    let metadata = json!({
        "total_bytes_written": 5_242_880u64, // 5 MiB
        "auth_prereq_secs": 8,
        "num_cpus": 16,
        "slot_wait_events_by_service": {"resources": 42, "graph": 0},
        "slot_wait_secs_by_service": {"resources": 3, "graph": 0},
    });
    let text = rendered(Some(&metadata), 10, false);
    assert!(text.contains("Total data written") && text.contains("5.0 MiB"));
    assert!(text.contains("Auth+prereq phase") && text.contains("8s"));
    assert!(text.contains("CPU parallelism") && text.contains("16"));
    assert!(text.contains("AIMD ceiling contention"));
    assert!(
        text.contains("42 park(s) at ceiling (3s)"),
        "the cap-contended service must show its park count and seconds, got:\n{text}"
    );
    assert_eq!(
        text.matches("park(s) at ceiling").count(),
        1,
        "only services with ceiling parks > 0 are listed (graph has 0), got:\n{text}"
    );
}

/// The per-service "cooldown active (single timeline)" block renders from
/// `cooldown_active_secs_by_service`; only services that entered a cooldown are
/// listed.
#[test]
fn metadata_section_renders_cooldown_active_timeline() {
    let metadata = json!({
        "cooldown_active_secs_by_service": {"graph": 1136u64, "exchange": 0},
    });
    let text = rendered(Some(&metadata), 10, false);
    assert!(text.contains("Cooldown active (timeline)"));
    assert!(
        text.contains("1136s active"),
        "the throttled service must show its active-cooldown timeline, got:\n{text}"
    );
    assert_eq!(
        text.matches("s active").count(),
        1,
        "only services with active cooldown > 0 are listed (exchange has 0), got:\n{text}"
    );
}

/// The data manifest shows per-table byte size and a grouped service-byte total.
#[test]
fn metadata_section_data_manifest_shows_per_table_bytes() {
    let metadata = json!({
        "tables": [
            {"name": "users", "folder": "graph", "count": 100, "bytes": 2048},
            {"name": "sps", "folder": "graph", "count": 50, "bytes": 1024},
        ]
    });
    let text = rendered(Some(&metadata), 10, false);
    // Service header includes the grouped byte total (2048 + 1024 = 3 KiB).
    assert!(
        text.contains("Graph — 150 objects · 2 tables · 3.0 KiB"),
        "got:\n{text}"
    );
    // Per-table rows show their individual byte size.
    assert!(text.contains("2.0 KiB") && text.contains("1.0 KiB"));
}
