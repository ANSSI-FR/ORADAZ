mod common;

use oradaz::VERSION;
use oradaz::collect::dump::response::DumpError;
use oradaz::inspect::display::{print_overview, strip_ansi_codes};
use oradaz::inspect::loader::LogSource;

use serde_json::{Value, json};

// ─── helpers ─────────────────────────────────────────────────────────────

fn metadata_complete() -> Value {
    // A "happy path" archive: tenant, durations, tokens for all services,
    // tables grouped by folder, zero errors.
    json!({
        "tenant": "11111111-2222-3333-4444-555555555555",
        "collection_date": "2026-05-27 06:55:05",
        "dump_duration_secs": 39,
        "total_duration_secs": 41,
        "oradaz_version": VERSION,
        "schema_version": VERSION,
        "schema_hash": "abcdef1234567890",
        "services": {
            "graph": "enabled",
            "resources": "enabled",
            "exchange": "enabled",
        },
        "tokens": [
            {"name": "graph", "user_principal_name": "auditor@contoso.com",
             "user_id": "d4c1a3b4-1111-2222-3333-444455556666", "client_id": "app"},
            {"name": "resources", "user_principal_name": "auditor@contoso.com",
             "user_id": "d4c1a3b4-1111-2222-3333-444455556666", "client_id": "app"},
            {"name": "exchange", "user_principal_name": "auditor@contoso.com",
             "user_id": "d4c1a3b4-1111-2222-3333-444455556666", "client_id": "app"},
        ],
        "tables": [
            {"name": "users",      "folder": "graph",     "file": "users",     "count": 7000},
            {"name": "sps",        "folder": "graph",     "file": "sps",       "count": 842},
            {"name": "subs",       "folder": "resources", "file": "subs",      "count": 9540},
            {"name": "policies",   "folder": "resources", "file": "policies",  "count": 2},
            {"name": "mailboxes",  "folder": "exchange",  "file": "mailboxes", "count": 21},
        ],
        "auth_errors": 0,
        "prerequisites_errors": 0,
        "errors": 3,
        "expected_errors": 3,
        "unexpected_errors": 0,
    })
}

fn config_app_password() -> Value {
    json!({
        "use_application_credentials": true,
        "application_credential_type": "password",
    })
}

fn stats_healthy() -> Value {
    json!({
        "duration_seconds": 39,
        "services": {
            "graph": {"http_batch_calls": 117, "http_single_calls": 0, "http_call_failures": 0},
            "resources": {"http_batch_calls": 45, "http_single_calls": 0, "http_call_failures": 0},
            "exchange": {"http_batch_calls": 0, "http_single_calls": 15, "http_call_failures": 0},
        },
        "apis": [
            {"service": "graph", "api": "users", "unexpected_errors": 0,
             "retries_rate_limit": 0, "rate_limit_wait_secs": 0, "network_errors": 0},
        ],
    })
}

fn make_source(metadata: Value, config: Value, stats: Value, errors: Vec<DumpError>) -> LogSource {
    LogSource {
        log_text: String::new(),
        dump_errors: errors,
        metadata: Some(metadata),
        config: Some(config),
        prerequisites: None,
        stats: Some(stats),
        is_archive: true,
        is_broken: false,
        size_bytes: Some(6_450_000), // ~6.15 MiB
    }
}

fn rendered(source: &LogSource) -> String {
    let mut out: Vec<String> = vec![String::new()];
    print_overview(source, &mut out);
    out.iter()
        .map(|l| strip_ansi_codes(l))
        .collect::<Vec<_>>()
        .join("\n")
}

// ─── happy path ──────────────────────────────────────────────────────────

#[test]
fn summary_complete_renders_all_four_sections_with_verdict() {
    let source = make_source(
        metadata_complete(),
        config_app_password(),
        stats_healthy(),
        vec![],
    );
    let text = rendered(&source);
    assert!(text.contains("COLLECTION SUMMARY"));
    assert!(text.contains("COMPLETE"), "expected COMPLETE badge");
    assert!(text.contains("COVERAGE"));
    assert!(text.contains("HEALTH"));
    assert!(text.contains("ATTENTION"));
    assert!(
        text.contains("nothing requires attention"),
        "healthy collection must say so"
    );
}

#[test]
fn summary_provenance_shows_tenant_date_duration_versions_auth() {
    let source = make_source(
        metadata_complete(),
        config_app_password(),
        stats_healthy(),
        vec![],
    );
    let text = rendered(&source);
    assert!(text.contains("11111111-2222-3333-4444-555555555555"));
    assert!(text.contains("2026-05-27 06:55:05"));
    assert!(text.contains("39 s collection · 41 s total"));
    assert!(
        text.contains("abcdef12…"),
        "schema hash should be truncated"
    );
    assert!(text.contains("Client credentials (password)"));
}

#[test]
fn summary_coverage_aggregates_objects_per_service_and_total() {
    let source = make_source(
        metadata_complete(),
        config_app_password(),
        stats_healthy(),
        vec![],
    );
    let text = rendered(&source);
    // Per-service totals derived from objects_per_service (sum by folder):
    // graph 7000+842=7842, resources 9540+2=9542, exchange 21.
    assert!(text.contains("7 842"));
    assert!(text.contains("9 542"));
    assert!(text.contains(" 21 "));
    // Total line: 17 405 objects · 5 tables.
    assert!(text.contains("Total:"));
    assert!(text.contains("17 405 objects"));
    assert!(text.contains("5 tables"));
    assert!(text.contains("MiB"), "archive size must be formatted");
}

#[test]
fn summary_coverage_shows_http_call_breakdown_per_service() {
    let source = make_source(
        metadata_complete(),
        config_app_password(),
        stats_healthy(),
        vec![],
    );
    let text = rendered(&source);
    assert!(text.contains("117 batch"));
    assert!(text.contains("45 batch"));
    assert!(text.contains("15 single"));
}

#[test]
fn summary_health_counters_render() {
    let source = make_source(
        metadata_complete(),
        config_app_password(),
        stats_healthy(),
        vec![],
    );
    let text = rendered(&source);
    assert!(text.contains("Authentication errors"));
    assert!(text.contains("Prerequisite errors"));
    assert!(text.contains("API errors (4xx/5xx)"));
    assert!(text.contains("3 expected · 0 unexpected"));
    assert!(text.contains("429 throttling"));
    // L2: "Network errors" was relabelled to "Request failures" (the metric
    // includes transport *and* JSON-parse failures).
    assert!(text.contains("Request failures"));
}

// ─── degraded paths ──────────────────────────────────────────────────────

#[test]
fn summary_partial_when_unexpected_errors_present() {
    let mut metadata = metadata_complete();
    metadata["unexpected_errors"] = json!(2);
    let errors = vec![DumpError {
        folder: "graph".to_string(),
        file: "users".to_string(),
        url: "https://example/u".to_string(),
        status: 403,
        code: "Forbidden".to_string(),
        message: "Access denied".to_string(),
        expected: false,
        full_response: None,
        post_data: None,
    }];
    let source = make_source(metadata, config_app_password(), stats_healthy(), errors);
    let text = rendered(&source);
    assert!(text.contains("PARTIAL"), "verdict should be PARTIAL");
    assert!(
        text.contains("graph/users"),
        "ATTENTION should list the offending API"
    );
    assert!(text.contains("403"), "ATTENTION should mention HTTP 403");
    assert!(
        text.contains("Forbidden"),
        "ATTENTION should mention the code"
    );
}

#[test]
fn summary_attention_lists_service_disabled_by_prereq_failure() {
    let mut metadata = metadata_complete();
    metadata["services"]["exchange"] = json!("disabled_by_prerequisite_failure");
    // Remove exchange token to mirror what the collector does in that case.
    metadata["tokens"] = json!(
        metadata["tokens"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|t| t.get("name").and_then(|n| n.as_str()) != Some("exchange"))
            .collect::<Vec<_>>()
    );
    let source = make_source(metadata, config_app_password(), stats_healthy(), vec![]);
    let text = rendered(&source);
    // A non-fatal prereq skip no longer flips the verdict: the badge stays
    // COMPLETE (matching the collector), but the gap is still surfaced in
    // ATTENTION so the operator sees the missing service.
    assert!(text.contains("COMPLETE"));
    assert!(!text.contains("PARTIAL"));
    assert!(text.contains("Exchange not collected"));
    assert!(text.contains("prerequisite failed"));
}

#[test]
fn summary_attention_no_available_subscription_reads_as_benign() {
    // U4: resources skipped for lack of an Azure subscription must not be worded
    // as a mid-run "prerequisite failed during the run".
    let mut metadata = metadata_complete();
    metadata["services"]["resources"] = json!("disabled_by_prerequisite_failure");
    let mut source = make_source(metadata, config_app_password(), stats_healthy(), vec![]);
    source.prerequisites = Some(json!({
        "resources": {"status": "error", "error": "NoAvailableSubscription"}
    }));
    let text = rendered(&source);
    assert!(text.contains("Resources skipped — no Azure subscription"));
    assert!(text.contains("checked at startup"));
    assert!(!text.contains("Resources not collected"));
    assert!(!text.contains("prerequisite failed during the run"));
}

#[test]
fn summary_interrupted_when_broken() {
    let metadata = metadata_complete();
    let mut source = make_source(metadata, config_app_password(), stats_healthy(), vec![]);
    source.is_broken = true;
    let text = rendered(&source);
    assert!(text.contains("INTERRUPTED"));
    assert!(text.contains("Archive interrupted"));
}

#[test]
fn summary_log_context_emitted_once_when_broken_and_auth_both_fire() {
    // When an archive is BOTH broken *and* carries auth_errors > 0, the
    // quoted log-tail block must appear exactly once — duplicating it on
    // each fatal item is noise.
    let log_text = "2026-05-28 16:59:52  |  ERROR  | Auth                     boom\n";
    let mut metadata = metadata_complete();
    metadata["auth_errors"] = json!(1);
    let mut source = make_source(metadata, config_app_password(), stats_healthy(), vec![]);
    source.is_broken = true;
    source.log_text = log_text.to_string();
    let text = rendered(&source);
    let banner_count = text.matches("Last errors logged before the abort").count();
    assert_eq!(
        banner_count, 1,
        "log-tail banner must appear exactly once when both broken + auth fire, got {banner_count} times:\n{text}"
    );
}

#[test]
fn summary_broken_surfaces_log_error_context_under_attention() {
    // Synthesise the kind of log content `inspect summary` should quote
    // under the "Archive interrupted" line: last ERROR + its DEBUG follow-up.
    let log_text = concat!(
        "2026-05-28 16:59:42  |  INFO   | main                     start\n",
        "2026-05-28 16:59:52  |  ERROR  | ClientCredentialsAuth    Error acquiring client credentials token for service \"graph\"\n",
        "2026-05-28 16:59:52  |  DEBUG  | ClientCredentialsAuth    token error: TimedOut\n",
    );
    let mut source = make_source(
        metadata_complete(),
        config_app_password(),
        stats_healthy(),
        vec![],
    );
    source.is_broken = true;
    source.log_text = log_text.to_string();
    let text = rendered(&source);
    assert!(text.contains("Archive interrupted"));
    assert!(
        text.contains("Last errors logged before the abort"),
        "must announce the quoted context"
    );
    assert!(
        text.contains("Error acquiring client credentials token"),
        "must include the ERROR message"
    );
    assert!(
        text.contains("TimedOut"),
        "must include the DEBUG follow-up message"
    );
}

#[test]
fn summary_attention_surfaces_heavy_throttle_apis() {
    let mut stats = stats_healthy();
    stats["apis"] = json!([
        {"service": "resources", "api": "subscriptions_roleAssignmentSchedules",
         "unexpected_errors": 0, "retries_rate_limit": 31, "rate_limit_wait_secs": 268,
         "network_errors": 0}
    ]);
    let source = make_source(metadata_complete(), config_app_password(), stats, vec![]);
    let text = rendered(&source);
    assert!(text.contains("subscriptions_roleAssignmentSchedules"));
    assert!(text.contains("31× 429"));
    assert!(text.contains("268 s"));
    assert!(text.contains("cumulative Retry-After"));
}

#[test]
fn summary_attention_flags_writer_saturation_when_budget_blocked() {
    // The §3.8 writer-saturation signal (debug telemetry) is otherwise invisible
    // in the one-screen digest; it must surface in ATTENTION when producers
    // actually stalled on the writer byte budget.
    let mut metadata = metadata_complete();
    metadata["writer_budget_blocked_count"] = json!(7);
    metadata["writer_budget_blocked_secs"] = json!(18);
    let source = make_source(metadata, config_app_password(), stats_healthy(), vec![]);
    let text = rendered(&source);
    assert!(text.contains("Writer saturation"), "got:\n{text}");
    assert!(text.contains("18s over 7 stall(s)"), "got:\n{text}");
}

#[test]
fn summary_writer_saturation_subsecond_total_renders_less_than_one() {
    // A non-zero stall count with a sub-second total (secs == 0, since secs comes
    // from integer nanos/1e9) must render "<1s", not "0s" — otherwise "0s over N
    // stall(s)" reads as a contradiction.
    let mut metadata = metadata_complete();
    metadata["writer_budget_blocked_count"] = json!(3);
    metadata["writer_budget_blocked_secs"] = json!(0);
    let source = make_source(metadata, config_app_password(), stats_healthy(), vec![]);
    let text = rendered(&source);
    assert!(text.contains("Writer saturation"), "got:\n{text}");
    assert!(text.contains("<1s over 3 stall(s)"), "got:\n{text}");
}

#[test]
fn summary_attention_no_writer_saturation_when_not_blocked() {
    // Healthy archive (no writer stall) must NOT show the writer-saturation line.
    let source = make_source(
        metadata_complete(),
        config_app_password(),
        stats_healthy(),
        vec![],
    );
    let text = rendered(&source);
    assert!(!text.contains("Writer saturation"), "got:\n{text}");
}

#[test]
fn summary_attention_pipeline_stalls_when_watchdog_fired() {
    // `stall_events > 0` earns an attention line pointing at the log; a healthy
    // run (0, or the field absent on older archives) must not show it.
    let mut metadata = metadata_complete();
    metadata["stall_events"] = json!(2);
    let source = make_source(metadata, config_app_password(), stats_healthy(), vec![]);
    let text = rendered(&source);
    assert!(text.contains("Pipeline stalls"), "got:\n{text}");
    assert!(
        text.contains("stall watchdog fired 2×"),
        "count + log pointer expected:\n{text}"
    );

    let healthy = make_source(
        metadata_complete(),
        config_app_password(),
        stats_healthy(),
        vec![],
    );
    let text = rendered(&healthy);
    assert!(!text.contains("Pipeline stalls"), "got:\n{text}");
}

#[test]
fn summary_next_steps_change_with_verdict() {
    // Healthy → inspect stats + inspect logs suggestions
    let source = make_source(
        metadata_complete(),
        config_app_password(),
        stats_healthy(),
        vec![],
    );
    assert!(rendered(&source).contains("oradaz inspect stats"));

    // Unhealthy → inspect hints + targeted logs suggestions
    let mut metadata = metadata_complete();
    metadata["unexpected_errors"] = json!(1);
    let source = make_source(metadata, config_app_password(), stats_healthy(), vec![]);
    let text = rendered(&source);
    assert!(text.contains("oradaz inspect hints"));
    assert!(text.contains("--service"));
}

#[test]
fn summary_works_without_stats_or_config() {
    // Older archive: no stats.json, no config — should still render header,
    // coverage shell, health (zeros), and a "nothing to surface" attention.
    let source = LogSource {
        log_text: String::new(),
        dump_errors: Vec::new(),
        metadata: Some(metadata_complete()),
        config: None,
        prerequisites: None,
        stats: None,
        is_archive: true,
        is_broken: false,
        size_bytes: None,
    };
    let text = rendered(&source);
    assert!(text.contains("COLLECTION SUMMARY"));
    assert!(text.contains("COVERAGE"));
    assert!(text.contains("HEALTH"));
    assert!(text.contains("ATTENTION"));
    // No HTTP stats → coverage shows "—" in HTTP column.
    assert!(text.contains("—"));
}

/// The breaker line is informative HEALTH content: it renders when URLs were
/// skipped, never as an ATTENTION flag, and does not change the verdict.
#[test]
fn summary_breaker_skips_are_informative_not_attention() {
    let mut metadata = metadata_complete();
    metadata["breaker_skipped_by_api"] = serde_json::json!({"graph/users_permissionGrants": 16200});
    let source = make_source(metadata, config_app_password(), stats_healthy(), vec![]);
    let text = rendered(&source);

    assert!(text.contains("COMPLETE"), "skips must not flip the verdict");
    assert!(
        text.contains("Skipped by breaker") && text.contains("16200 URL(s) on 1 API(s)"),
        "informative skip line expected:\n{text}"
    );
    let attention = text.split("ATTENTION").nth(1).unwrap_or("");
    assert!(
        !attention.contains("Skipped by breaker"),
        "the breaker line must not be an attention item:\n{text}"
    );
}

#[test]
fn summary_partial_when_lost_data_abandonment_present() {
    // A lost-data abandonment (status == 0, non-HTTP terminal failure) must flip
    // the rendered verdict to PARTIAL even with zero unexpected HTTP errors. This
    // guards the compute_verdict → print_overview wiring (has_lost_data is read
    // from source.dump_errors at overview.rs), not just the pure verdict fn.
    let metadata = metadata_complete(); // unexpected_errors stays 0
    let errors = vec![DumpError {
        folder: "graph".to_string(),
        file: "users".to_string(),
        url: "https://example/u".to_string(),
        status: 0,
        code: "UrlRetryLimit".to_string(),
        message: "retry budget exhausted".to_string(),
        expected: false,
        full_response: None,
        post_data: None,
    }];
    let source = make_source(metadata, config_app_password(), stats_healthy(), errors);
    let text = rendered(&source);
    assert!(
        text.contains("PARTIAL"),
        "a lost-data abandonment must render the PARTIAL verdict:\n{text}"
    );
}

#[test]
fn summary_missing_token_for_relationships_does_not_flip_to_partial() {
    // MissingTokenForRelationships is excluded from is_lost_data: it fires after
    // the endpoint's own page was already written (only relationship expansion
    // was skipped), so it must NOT flip the rendered verdict.
    let errors = vec![DumpError {
        folder: "graph".to_string(),
        file: "users".to_string(),
        url: "https://example/u".to_string(),
        status: 0,
        code: "MissingTokenForRelationships".to_string(),
        message: "no token for relationship expansion".to_string(),
        expected: false,
        full_response: None,
        post_data: None,
    }];
    let source = make_source(
        metadata_complete(),
        config_app_password(),
        stats_healthy(),
        errors,
    );
    let text = rendered(&source);
    assert!(text.contains("COMPLETE"), "got:\n{text}");
    assert!(
        !text.contains("PARTIAL"),
        "MissingTokenForRelationships must not flip the verdict:\n{text}"
    );
}
