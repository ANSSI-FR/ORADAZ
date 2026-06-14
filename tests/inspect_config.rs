mod common;

use oradaz::VERSION;
use oradaz::inspect::display::{print_config_section, strip_ansi_codes};

use serde_json::{Value, json};

// ─── helpers ──────────────────────────────────────────────────────────────

fn rendered(metadata: Option<&Value>, config: Option<&Value>, all: bool) -> String {
    let mut lines: Vec<String> = vec![];
    print_config_section(metadata, config, all, &mut lines);
    lines
        .iter()
        .map(|l| strip_ansi_codes(l))
        .collect::<Vec<_>>()
        .join("\n")
}

fn make_metadata() -> Value {
    json!({
        "tenant": "a231f063-c06b-4187-9d22-a1cff7defbab",
        "collection_date": "2026-04-29 17:43:31",
        "dump_duration_secs": 10,
        "oradaz_version": VERSION,
        "schema_version": VERSION,
        "schema_hash": "fe0f0b03f6d4d61f2baddb677f0269416bedc50e9de5fa91d17838774b0d14d9",
    })
}

fn config_default_perf() -> Value {
    json!({
        "app_id": "fdce9d1a-3472-4bdb-a7a0-dcdfa1434600",
        "proxy": false,
        "no_check": false,
        "trace_logs": false,
        "services": {
            "service": [
                {"@name": "graph", "#text": true},
                {"@name": "resources", "#text": true},
                {"@name": "exchange", "#text": false},
            ]
        },
        "use_application_credentials": true,
        "application_credential_type": "certificate",
    })
}

fn config_with_overrides() -> Value {
    // Same as default plus a tuning override for the "differ" table.
    let mut c = config_default_perf();
    c["concurrency_max_window"] = json!(100u64);
    c
}

// ─── headers ──────────────────────────────────────────────────────────────

#[test]
fn config_section_renders_top_headers() {
    let text = rendered(Some(&make_metadata()), Some(&config_default_perf()), false);
    assert!(text.contains("COLLECTION SUMMARY"));
    assert!(text.contains("CONFIGURATION"));
    assert!(text.contains("PERFORMANCE TUNING"));
}

#[test]
fn config_section_collection_summary_fields() {
    let text = rendered(Some(&make_metadata()), Some(&config_default_perf()), false);
    assert!(text.contains("a231f063-c06b-4187-9d22-a1cff7defbab"));
    assert!(text.contains(VERSION));
    assert!(text.contains("2026-04-29 17:43:31"));
    assert!(text.contains("Client credentials (certificate)"));
}

// ─── CONFIGURATION groups ────────────────────────────────────────────────

#[test]
fn config_groups_show_authentication_block() {
    let text = rendered(None, Some(&config_default_perf()), false);
    assert!(text.contains("Authentication"));
    assert!(text.contains("AppId"));
    assert!(text.contains("fdce9d1a-3472-4bdb-a7a0-dcdfa1434600"));
    assert!(text.contains("Flow"));
    assert!(text.contains("Client credentials (certificate)"));
}

#[test]
fn config_groups_show_services_list_with_icons() {
    let text = rendered(None, Some(&config_default_perf()), false);
    assert!(text.contains("Services"));
    // Three services on a single inline line.
    assert!(text.contains("Graph"));
    assert!(text.contains("Resources"));
    assert!(text.contains("Exchange"));
}

#[test]
fn config_groups_show_output_and_schema() {
    let text = rendered(None, Some(&config_default_perf()), false);
    assert!(text.contains("Output & schema"));
    // no_check=false → prereq check enabled
    assert!(text.contains("Prereq check"));
    assert!(text.contains("enabled"));
    assert!(text.contains("Trace logs"));
}

#[test]
fn config_groups_prereq_check_disabled_when_no_check_true() {
    let mut c = config_default_perf();
    c["no_check"] = json!(true);
    let text = rendered(None, Some(&c), false);
    assert!(text.contains("Prereq check"));
    assert!(
        text.contains("disabled"),
        "no_check=true must render 'Prereq check disabled', got:\n{text}"
    );
}

#[test]
fn config_groups_network_proxy_and_user_agent() {
    let text = rendered(None, Some(&config_default_perf()), false);
    assert!(text.contains("Network"));
    assert!(text.contains("Proxy"));
    assert!(text.contains("User agent"));
    // No user_agent set → "default"
    assert!(text.contains("default"));
}

#[test]
fn config_groups_user_agent_custom_renders_value() {
    let mut c = config_default_perf();
    c["user_agent"] = json!("CustomAgent/1.0");
    let text = rendered(None, Some(&c), false);
    assert!(text.contains("CustomAgent/1.0"));
}

// ─── PERFORMANCE TUNING ──────────────────────────────────────────────────

#[test]
fn performance_tuning_default_mode_hides_when_all_at_defaults() {
    let text = rendered(None, Some(&config_default_perf()), false);
    assert!(text.contains("PERFORMANCE TUNING"));
    assert!(
        text.contains("all performance tuning values at defaults"),
        "expected the 'all at defaults' shortcut message, got:\n{text}"
    );
}

#[test]
fn performance_tuning_default_mode_shows_only_overrides() {
    let text = rendered(None, Some(&config_with_overrides()), false);
    // The overridden line must appear with `*`
    assert!(text.contains("concurrency_max_window"));
    assert!(
        text.contains(" * "),
        "marker `*` must be present on overrides"
    );
    // Default-only params must be hidden.
    assert!(
        !text.contains("url_retry_limit"),
        "url_retry_limit is at default; default mode must not list it"
    );
}

#[test]
fn performance_tuning_all_lists_every_parameter() {
    let text = rendered(None, Some(&config_with_overrides()), true);
    for field in &[
        "concurrency_min_window",
        "concurrency_max_window",
        "default_retry_after_seconds",
        "http_timeout_seconds",
        "http_connect_timeout_seconds",
        "dispatch_burst_cap",
        "url_retry_limit",
        "rate_limit_retry_limit",
        "rate_limit_max_wait_secs",
        "stall_detection_timeout",
        "prereq_recheck_cache_secs",
        "retry_backoff_base_ms",
        "retry_backoff_cap_ms",
    ] {
        assert!(text.contains(field), "missing tuning row {field}");
    }
    // Legend should appear when at least one row differs from default.
    assert!(text.contains("* = different from default"));
}

#[test]
fn performance_tuning_default_value_substituted_when_field_null() {
    // concurrency_min_window omitted → effective = default (5) → no marker.
    let c = json!({"app_id": "x"});
    let text = rendered(None, Some(&c), true);
    let row = text
        .lines()
        .find(|l| l.contains("concurrency_min_window"))
        .expect("concurrency_min_window row");
    assert!(row.contains("5"));
    assert!(!row.contains(" * "), "default row must not carry a marker");
}

// ─── None / fallback ─────────────────────────────────────────────────────

#[test]
fn config_section_no_metadata_fallback() {
    let text = rendered(None, Some(&config_default_perf()), false);
    assert!(text.contains("no collection metadata available"));
}

#[test]
fn config_section_no_config_fallback() {
    let text = rendered(Some(&make_metadata()), None, false);
    assert!(text.contains("no configuration available"));
    assert!(text.contains("PERFORMANCE TUNING"));
}

// ─── invariance: TUNING_DEFAULTS ↔ Config::* literals ────────────────────

/// The `TUNING_DEFAULTS` table in `src/inspect/display/sections.rs` must stay
/// in sync with the `unwrap_or(...)` literals in the corresponding `Config::*`
/// getters in `src/utils/config.rs`. A default that drifts in one place but
/// not the other causes `inspect config` to display a misleading `*` marker
/// for a parameter that is actually at the current default.
#[test]
fn tuning_defaults_match_config_unwrap_or_literals() {
    use oradaz::inspect::display::sections::TUNING_DEFAULTS;
    use oradaz::utils::config::Config;

    // Start from the minimal test config and explicitly null every tuning
    // field; the `Config::*` getters then return the literal default.
    let mut c = common::default_test_config();
    c.concurrency_min_window = None;
    c.concurrency_max_window = None;
    c.default_retry_after_seconds = None;
    c.http_timeout_seconds = None;
    c.http_connect_timeout_seconds = None;
    c.dispatch_burst_cap = None;
    c.url_retry_limit = None;
    c.rate_limit_retry_limit = None;
    c.rate_limit_max_wait_secs = None;
    c.stall_detection_timeout = None;
    c.prereq_recheck_cache_secs = None;
    c.liveness_ceiling_secs = None;
    c.retry_backoff_base_ms = None;
    c.retry_backoff_cap_ms = None;
    c.response_workers_max = None;
    c.expected_error_breaker_threshold = None;

    for (field, expected) in TUNING_DEFAULTS {
        let actual: u64 = match *field {
            "concurrency_min_window" => Config::concurrency_min_window(&c) as u64,
            "concurrency_max_window" => Config::concurrency_max_window(&c) as u64,
            "default_retry_after_seconds" => Config::default_retry_after_seconds(&c),
            "http_timeout_seconds" => Config::http_timeout_seconds(&c),
            "http_connect_timeout_seconds" => Config::http_connect_timeout_seconds(&c),
            "dispatch_burst_cap" => Config::dispatch_burst_cap(&c) as u64,
            "url_retry_limit" => Config::url_retry_limit(&c) as u64,
            "rate_limit_retry_limit" => Config::rate_limit_retry_limit(&c) as u64,
            "rate_limit_max_wait_secs" => Config::rate_limit_max_wait_secs(&c),
            "stall_detection_timeout" => Config::stall_detection_timeout(&c),
            "prereq_recheck_cache_secs" => Config::prereq_recheck_cache_secs(&c),
            "liveness_ceiling_secs" => Config::liveness_ceiling_secs(&c),
            "retry_backoff_base_ms" => Config::retry_backoff_base_ms(&c),
            "retry_backoff_cap_ms" => Config::retry_backoff_cap_ms(&c),
            "response_workers_max" => Config::response_workers_max(&c) as u64,
            "expected_error_breaker_threshold" => {
                Config::expected_error_breaker_threshold(&c) as u64
            }
            other => panic!(
                "TUNING_DEFAULTS lists field '{other}' but no Config::{other}() exists — \
                 update this test if a new tuning knob was added, or fix the table."
            ),
        };
        assert_eq!(
            actual, *expected,
            "TUNING_DEFAULTS literal {expected} for `{field}` doesn't match Config::{field}() = \
             {actual}. The two must stay in lockstep — update either \
             src/inspect/display/sections.rs::TUNING_DEFAULTS or the corresponding \
             unwrap_or(...) literal in src/utils/config.rs."
        );
    }
}
