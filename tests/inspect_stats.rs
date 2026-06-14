use oradaz::inspect::display::print_stats_section;

use serde_json::json;

fn rendered(stats: Option<&serde_json::Value>, top: usize, all: bool) -> String {
    rendered_filtered(stats, top, all, None)
}

fn rendered_filtered(
    stats: Option<&serde_json::Value>,
    top: usize,
    all: bool,
    service: Option<&str>,
) -> String {
    let mut out: Vec<String> = vec![String::new()];
    print_stats_section(None, None, stats, top, all, service, &mut out);
    out.join("\n")
}

/// API YIELD joins per-API requests (stats) with objects written (metadata):
/// a high-request, zero-object endpoint is listed as low-yield. ACHIEVED
/// CONCURRENCY flags a service that ran sequentially (achieved ≈ 1 against a
/// large window) and names the paginated endpoint responsible.
#[test]
fn print_stats_section_renders_yield_and_sequential_pole() {
    let metadata = json!({
        "tables": [
            { "name": "graph_users", "folder": "graph", "file": "users.json", "count": 100, "bytes": 1 }
        ]
    });
    let config = json!({ "concurrencyMaxWindow": 30 });
    let stats = json!({
        "duration_seconds": 2700,
        "apis": [
            {
                "service": "exchange", "api": "recipients",
                "requests_sent": 305, "pages_followed": 304,
                "first_request_at": "2026-06-13T00:00:00+00:00",
                "last_request_at": "2026-06-13T00:45:00+00:00",
                "empty_responses": 0
            },
            {
                "service": "graph", "api": "devices_registeredOwners",
                "requests_sent": 500, "pages_followed": 0,
                "empty_responses": 480
            }
        ],
        "services": {
            "exchange": { "http_latency_sum_ms": 2_700_000u64 }
        }
    });

    let mut out: Vec<String> = vec![String::new()];
    print_stats_section(
        Some(&metadata),
        Some(&config),
        Some(&stats),
        10,
        false,
        None,
        &mut out,
    );
    let text = out.join("\n");

    // O1: 500 requests for 0 objects → listed as a low-yield waster.
    assert!(text.contains("API YIELD"), "{text}");
    assert!(text.contains("devices_registeredOwners"), "{text}");
    // O2/O3: exchange spent ~2700 s in HTTP over a ~2700 s span → achieved ≈ 1
    // against window 150 → sequential pole on recipients.
    assert!(text.contains("ACHIEVED CONCURRENCY BY SERVICE"), "{text}");
    assert!(text.contains("sequential pole"), "{text}");
    assert!(text.contains("recipients"), "{text}");
}

#[test]
fn print_stats_section_handles_missing_stats() {
    let text = rendered(None, 10, false);
    assert!(
        text.contains("no stats.json found"),
        "expected fallback message, got: {text}"
    );
}

#[test]
fn print_stats_section_handles_empty_stats() {
    let stats = json!({});
    let text = rendered(Some(&stats), 10, false);
    // Section headers must still render; nothing should panic.
    assert!(text.contains("STATISTICS SUMMARY"));
    assert!(text.contains("PROBLEMATIC APIS"));
    assert!(text.contains("TOP APIS BY VOLUME"));
    assert!(text.contains("TOP APIS BY ACTIVITY WINDOW"));
    assert!(text.contains("TOP APIS BY LATENCY"));
    assert!(text.contains("LATENCY & RETRY-AFTER BY SERVICE"));
    assert!(text.contains("NETWORK ERRORS & BACKOFF BY SERVICE"));
    assert!(text.contains("no transport failures recorded"));
    assert!(text.contains("REQUEST SHAPE (PAGINATION / FAN-OUT)"));
    assert!(text.contains("BATCH FILL BY SERVICE"));
    assert!(text.contains("no pagination or relationship fan-out recorded"));
    assert!(text.contains("API YIELD (objects / request)"));
    assert!(text.contains("no low-yield API recorded"));
    assert!(text.contains("ACHIEVED CONCURRENCY BY SERVICE"));
    assert!(text.contains("no service activity recorded"));
    assert!(text.contains("CONDITIONS EVALUATED"));
    assert!(text.contains("PREREQUISITE RE-CHECKS"));
    assert!(text.contains("no problematic API detected"));
    assert!(text.contains("no condition recorded"));
    assert!(text.contains("no prereq re-check recorded"));
    // L2: the per-sub-request reconciliation note is gated on actual failures —
    // a healthy run must not show it.
    assert!(!text.contains("counted per sub-request"));
}

#[test]
fn print_stats_section_renders_problematic_api() {
    let stats = json!({
        "started_at": "2026-05-20T14:32:11Z",
        "ended_at": "2026-05-20T15:00:00Z",
        "duration_seconds": 1669,
        "services": {
            "graph": {"http_batch_calls": 3, "http_single_calls": 0, "http_call_failures": 0}
        },
        "apis": [
            {
                "service": "graph",
                "api": "users",
                "requests_sent": 100,
                "http_batch_calls": 5,
                "http_single_calls": 0,
                "first_request_at": "2026-05-20T14:32:13Z",
                "last_request_at": "2026-05-20T14:55:00Z",
                "responses_by_status": {"200": 80, "500": 15, "502": 5},
                "expected_errors": 0,
                "unexpected_errors": 20,
                "network_errors": 0,
                "retries_real": 8,
                "retries_rate_limit": 0,
                "rate_limit_wait_secs": 0,
                "prereq_rechecks_triggered": 2,
                "condition_checks": [],
                "upstream_error_codes": {"UnknownError": 5, "InternalServerError": 15}
            }
        ],
        "conditions": [
            {"name": "GA", "checks": 100, "true_count": 1, "false_count": 99}
        ],
        "prereq_rechecks": {"graph": 1, "exchange": 0}
    });
    let text = rendered(Some(&stats), 10, false);
    assert!(text.contains("graph/users"), "API label missing in: {text}");
    assert!(text.contains("20 unexpected errors"));
    assert!(text.contains("2 prereq rechecks"));
    assert!(text.contains("GA"));
    // Activity window section should pick up graph/users (~23 min).
    assert!(text.contains("min"));
    // Enriched problematic detail lines.
    assert!(
        text.contains("statuses:") && text.contains("500×15"),
        "expected status breakdown, got: {text}"
    );
    assert!(
        text.contains("codes:") && text.contains("InternalServerError×15"),
        "expected upstream code breakdown, got: {text}"
    );
    assert!(text.contains("8 real retries"));
    // HTTP calls summary uses per-service totals.
    assert!(text.contains("3 batched + 0 single"));
}

#[test]
fn print_stats_section_relabels_network_as_request_failures() {
    // L2: the per-API "network errors" wording is relabelled to "request
    // failures" (it conflates transport + JSON-parse failures), and a note
    // reconciles the per-sub-request count with the per-call summary.
    let stats = json!({
        "duration_seconds": 100,
        "services": {
            "graph": {"http_batch_calls": 1, "http_single_calls": 0, "http_call_failures": 1}
        },
        "apis": [
            {
                "service": "graph",
                "api": "users",
                "requests_sent": 20,
                "http_batch_calls": 1,
                "http_single_calls": 0,
                "responses_by_status": {},
                "expected_errors": 0,
                "unexpected_errors": 0,
                "network_errors": 12,
                "retries_real": 0,
                "retries_rate_limit": 0,
                "rate_limit_wait_secs": 0,
                "prereq_rechecks_triggered": 0
            }
        ]
    });
    let text = rendered(Some(&stats), 10, false);
    // Summary line and the per-API problematic row both use "request failures".
    assert!(text.contains("Request failures"));
    assert!(text.contains("12 request failures"));
    assert!(!text.contains("12 network errors"));
    // The reconciliation note is present so the 1-vs-12 gap is explained.
    assert!(text.contains("counted per sub-request"));
}

#[test]
fn print_stats_section_renders_latency_and_retry_after() {
    let stats = json!({
        "duration_seconds": 100,
        "services": {
            // graph: batched → service-level latency only, no Retry-After events.
            "graph": {"http_batch_calls": 5, "http_single_calls": 0, "http_call_failures": 0,
                      "http_latency_sum_ms": 5200, "http_latency_max_ms": 900, "http_latency_count": 52,
                      "retry_after_server_count": 0, "retry_after_default_count": 0, "retry_after_max_secs": 0},
            // resources: single calls → also per-API latency; throttled with mostly
            // default-cooldown 429s.
            "resources": {"http_batch_calls": 0, "http_single_calls": 40, "http_call_failures": 0,
                          "http_latency_sum_ms": 8000, "http_latency_max_ms": 1500, "http_latency_count": 40,
                          "retry_after_server_count": 18, "retry_after_default_count": 423, "retry_after_max_secs": 60}
        },
        "apis": [
            {"service": "resources", "api": "subscriptions",
             "requests_sent": 40, "http_single_calls": 40, "http_batch_calls": 0,
             "http_latency_sum_ms": 8000, "http_latency_max_ms": 1500, "http_latency_count": 40,
             "responses_by_status": {"200": 40}}
        ]
    });
    let text = rendered(Some(&stats), 10, false);

    assert!(text.contains("TOP APIS BY LATENCY"), "got:\n{text}");
    assert!(
        text.contains("LATENCY & RETRY-AFTER BY SERVICE"),
        "got:\n{text}"
    );

    // Per-API latency: resources/subscriptions mean = 8000/40 = 200 ms, max 1500 ms.
    assert!(text.contains("resources/subscriptions"), "got:\n{text}");
    assert!(
        text.contains("200 ms") && text.contains("1500 ms"),
        "per-API mean/max latency, got:\n{text}"
    );

    // Per-service: graph mean = 5200/52 = 100 ms (batched, no per-API row), and the
    // resources Retry-After provenance split with the max server value.
    assert!(
        text.contains("100 ms"),
        "graph service-level mean latency, got:\n{text}"
    );
    assert!(
        text.contains("18/423 (max 60 s)"),
        "Retry-After server/default split, got:\n{text}"
    );
}

#[test]
fn print_stats_section_renders_ok_latency_and_network_breakdown() {
    let stats = json!({
        "duration_seconds": 100,
        "services": {
            // 2xx-only latency split: all-mean 100 ms vs 2xx-mean 400 ms (fast
            // 429 turnarounds drag the all-mean down). Transport failures split
            // by cause, with the cumulative backoff sleep.
            "resources": {"http_batch_calls": 0, "http_single_calls": 50, "http_call_failures": 7,
                          "http_latency_sum_ms": 5000, "http_latency_max_ms": 900, "http_latency_count": 50,
                          "http_latency_ok_sum_ms": 4000, "http_latency_ok_max_ms": 900, "http_latency_ok_count": 10,
                          "network_timeout_errors": 5, "network_connect_errors": 2,
                          "network_other_errors": 0, "backoff_wait_ms_total": 12500}
        },
        "apis": [
            {"service": "resources", "api": "subscriptions",
             "requests_sent": 50, "http_single_calls": 50, "http_batch_calls": 0,
             "http_latency_sum_ms": 5000, "http_latency_max_ms": 900, "http_latency_count": 50,
             "http_latency_ok_sum_ms": 4000, "http_latency_ok_max_ms": 900, "http_latency_ok_count": 10,
             "responses_by_status": {"200": 10, "429": 40}}
        ]
    });
    let text = rendered(Some(&stats), 10, false);

    // 2xx mean (400 ms) rendered next to the all-response mean (100 ms).
    assert!(text.contains("2xx mean"), "got:\n{text}");
    assert!(
        text.contains("400 ms") && text.contains("100 ms"),
        "ok vs all-response means, got:\n{text}"
    );

    // Network breakdown table with the backoff sleep in seconds.
    assert!(
        text.contains("NETWORK ERRORS & BACKOFF BY SERVICE"),
        "got:\n{text}"
    );
    assert!(
        !text.contains("no transport failures recorded"),
        "rows must replace the empty fallback, got:\n{text}"
    );
    assert!(text.contains("timeouts"), "got:\n{text}");
    let net_row = text
        .lines()
        .find(|l| l.contains("12 s"))
        .unwrap_or_else(|| panic!("network row with backoff seconds missing:\n{text}"));
    assert!(
        net_row.contains("resources") && net_row.contains('5') && net_row.contains('2'),
        "timeout/connect counts must sit on the service's network row: {net_row:?}"
    );
}

#[test]
fn print_stats_section_ok_latency_column_dash_on_old_archives() {
    // Archives predating the ok-split counters must render "—" in the 2xx
    // column, not 0 ms.
    let stats = json!({
        "duration_seconds": 100,
        "services": {
            "resources": {"http_batch_calls": 0, "http_single_calls": 10, "http_call_failures": 0,
                          "http_latency_sum_ms": 1000, "http_latency_max_ms": 200, "http_latency_count": 10}
        },
        "apis": [
            {"service": "resources", "api": "subscriptions",
             "requests_sent": 10, "http_single_calls": 10, "http_batch_calls": 0,
             "http_latency_sum_ms": 1000, "http_latency_max_ms": 200, "http_latency_count": 10,
             "responses_by_status": {"200": 10}}
        ]
    });
    let text = rendered(Some(&stats), 10, false);
    assert!(text.contains("2xx mean"), "got:\n{text}");
    assert!(text.contains('—'), "missing-data dash, got:\n{text}");
}

#[test]
fn print_stats_section_renders_request_shape() {
    let stats = json!({
        "duration_seconds": 100,
        "services": {
            // graph: batched, 30 sub-requests across 4 envelopes → avg fill 7.5.
            "graph": {"http_batch_calls": 4, "http_single_calls": 0, "http_call_failures": 0,
                      "batch_subrequests_total": 30},
            // resources: single calls only → excluded from BATCH FILL (no batches).
            "resources": {"http_batch_calls": 0, "http_single_calls": 12, "http_call_failures": 0,
                          "batch_subrequests_total": 0}
        },
        "apis": [
            {"service": "graph", "api": "users",
             "requests_sent": 50, "http_batch_calls": 4, "http_single_calls": 0,
             "responses_by_status": {"200": 50},
             "pages_followed": 7, "child_urls_generated": 120},
            {"service": "resources", "api": "subscriptions",
             "requests_sent": 12, "http_batch_calls": 0, "http_single_calls": 12,
             "responses_by_status": {"200": 12},
             "pages_followed": 3, "child_urls_generated": 0}
        ]
    });
    let text = rendered(Some(&stats), 10, false);

    assert!(
        text.contains("REQUEST SHAPE (PAGINATION / FAN-OUT)"),
        "got:\n{text}"
    );
    assert!(text.contains("BATCH FILL BY SERVICE"), "got:\n{text}");

    // Scope assertions to each new section so they can't be satisfied by a sibling
    // table (e.g. graph/users also appears in TOP APIS BY VOLUME).
    let shape = text
        .split_once("REQUEST SHAPE (PAGINATION / FAN-OUT)")
        .map(|(_, rest)| {
            rest.split_once("BATCH FILL BY SERVICE")
                .map(|(h, _)| h)
                .unwrap_or(rest)
        })
        .unwrap_or(&text);
    let batch = text
        .split_once("BATCH FILL BY SERVICE")
        .map(|(_, rest)| {
            rest.split_once("CONDITIONS EVALUATED")
                .map(|(h, _)| h)
                .unwrap_or(rest)
        })
        .unwrap_or(&text);

    // Per-API shape: both endpoints with amplification appear (graph/users leads on
    // pages 7 + fan-out 120; 120 is unique to this section).
    assert!(shape.contains("graph/users"), "got:\n{shape}");
    assert!(shape.contains("resources/subscriptions"), "got:\n{shape}");
    assert!(
        shape.contains("120"),
        "fan-out value in REQUEST SHAPE, got:\n{shape}"
    );

    // Batch fill: graph avg = 30 / 4 = 7.5; resources is excluded (no batch calls).
    assert!(batch.contains("7.5"), "graph batch fill avg, got:\n{batch}");
    assert!(
        !batch.contains("resources"),
        "resources has no batch calls and must be excluded from BATCH FILL, got:\n{batch}"
    );
}

#[test]
fn print_stats_section_batch_fill_shows_dash_on_old_archive() {
    // Archive predating request-shape telemetry: a batched service has
    // http_batch_calls > 0 but no batch_subrequests_total → avg fill must show
    // "—" (field absent), not a misleading 0.0.
    let stats = json!({
        "duration_seconds": 100,
        "services": {
            "graph": {"http_batch_calls": 4, "http_single_calls": 0, "http_call_failures": 0}
        },
        "apis": [
            {"service": "graph", "api": "users", "requests_sent": 50, "http_batch_calls": 4,
             "responses_by_status": {"200": 50}}
        ]
    });
    let text = rendered(Some(&stats), 10, false);
    let batch_section = text
        .split_once("BATCH FILL BY SERVICE")
        .map(|(_, rest)| {
            rest.split_once("CONDITIONS EVALUATED")
                .map(|(h, _)| h)
                .unwrap_or(rest)
        })
        .unwrap_or(&text);
    assert!(
        batch_section.contains("graph"),
        "batched service row present, got:\n{batch_section}"
    );
    assert!(
        batch_section.contains('—'),
        "avg fill must be '—' when batch_subrequests_total is absent, got:\n{batch_section}"
    );
    assert!(
        !batch_section.contains("0.0"),
        "must not render a fake 0.0 avg fill, got:\n{batch_section}"
    );
}

#[test]
fn print_stats_section_service_filter_narrows_per_api_sections() {
    let stats = json!({
        "duration_seconds": 100,
        "services": {
            "graph": {"http_batch_calls": 5, "http_single_calls": 0, "http_call_failures": 0},
            "resources": {"http_batch_calls": 3, "http_single_calls": 0, "http_call_failures": 0},
        },
        "apis": [
            {"service": "graph", "api": "users",
             "requests_sent": 50, "http_batch_calls": 5,
             "unexpected_errors": 3, "expected_errors": 0,
             "network_errors": 0, "retries_real": 0,
             "retries_rate_limit": 0, "rate_limit_wait_secs": 0,
             "prereq_rechecks_triggered": 0,
             "responses_by_status": {"200": 47, "500": 3},
             "upstream_error_codes": {"Forbidden": 3}},
            {"service": "resources", "api": "subs",
             "requests_sent": 30, "http_batch_calls": 3,
             "unexpected_errors": 5, "expected_errors": 0,
             "network_errors": 0, "retries_real": 0,
             "retries_rate_limit": 0, "rate_limit_wait_secs": 0,
             "prereq_rechecks_triggered": 0,
             "responses_by_status": {"200": 25, "500": 5},
             "upstream_error_codes": {"InternalError": 5}},
        ],
    });

    // Unfiltered: both services appear in PROBLEMATIC APIS / TOP BY VOLUME.
    let all_text = rendered(Some(&stats), 10, false);
    assert!(all_text.contains("graph/users"));
    assert!(all_text.contains("resources/subs"));

    // Filtered to graph only: resources rows must be gone from per-API
    // sections, BUT the STATISTICS SUMMARY block stays tenant-wide.
    let filtered = rendered_filtered(Some(&stats), 10, false, Some("graph"));
    let after_summary = filtered
        .split_once("PROBLEMATIC APIS")
        .map(|(_, rest)| rest)
        .unwrap_or(&filtered);
    assert!(after_summary.contains("graph/users"));
    assert!(
        !after_summary.contains("resources/subs"),
        "resources should be filtered out, got:\n{after_summary}"
    );
    // Sanity: summary block still mentions both services (per-service HTTP
    // breakdown line is kept global).
    let summary_block = filtered
        .split_once("PROBLEMATIC APIS")
        .map(|(head, _)| head)
        .unwrap_or(&filtered);
    assert!(summary_block.contains("graph"));
    assert!(summary_block.contains("resources"));
}
