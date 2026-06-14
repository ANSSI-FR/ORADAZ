mod common;

use oradaz::collect::dump::response::DumpError;
use oradaz::inspect::display::{print_remediation_section, strip_ansi_codes};
use oradaz::inspect::loader::LogSource;

use serde_json::{Value, json};

// ─── fixtures ────────────────────────────────────────────────────────────

fn dump_error(folder: &str, file: &str, status: u16, code: &str, expected: bool) -> DumpError {
    DumpError {
        folder: folder.to_string(),
        file: file.to_string(),
        url: format!("https://example/{folder}/{file}"),
        status,
        code: code.to_string(),
        message: format!("err {folder}/{file} {status}"),
        expected,
        full_response: None,
        post_data: None,
    }
}

fn make_source(
    metadata: Option<Value>,
    stats: Option<Value>,
    prereq: Option<Value>,
    errors: Vec<DumpError>,
    is_broken: bool,
) -> LogSource {
    LogSource {
        log_text: String::new(),
        dump_errors: errors,
        metadata,
        config: None,
        prerequisites: prereq,
        stats,
        is_archive: true,
        is_broken,
        size_bytes: None,
    }
}

fn rendered(source: &LogSource, service: Option<&str>, include_expected: bool) -> String {
    let mut out: Vec<String> = vec![String::new()];
    print_remediation_section(source, service, include_expected, &mut out);
    out.iter()
        .map(|l| strip_ansi_codes(l))
        .collect::<Vec<_>>()
        .join("\n")
}

// ─── headers / healthy / verdict ─────────────────────────────────────────

#[test]
fn remediation_healthy_collection_says_so() {
    let source = make_source(
        Some(json!({"auth_errors": 0, "prerequisites_errors": 0, "unexpected_errors": 0})),
        None,
        None,
        vec![],
        false,
    );
    let text = rendered(&source, None, false);
    assert!(text.contains("REMEDIATION"));
    assert!(text.contains("COMPLETE"));
    assert!(text.contains("nothing to fix"));
}

#[test]
fn remediation_header_shows_partial_verdict_when_unexpected_present() {
    let source = make_source(
        Some(json!({"unexpected_errors": 1})),
        None,
        None,
        vec![dump_error("graph", "users", 403, "Forbidden", false)],
        false,
    );
    let text = rendered(&source, None, false);
    assert!(text.contains("PARTIAL"));
}

// ─── FATAL section ───────────────────────────────────────────────────────

#[test]
fn remediation_fatal_section_for_broken_archive() {
    let source = make_source(
        Some(json!({"unexpected_errors": 0})),
        None,
        None,
        vec![],
        true,
    );
    let text = rendered(&source, None, false);
    assert!(text.contains("FATAL"));
    assert!(text.contains("Archive interrupted"));
    assert!(text.contains("INTERRUPTED"));
}

#[test]
fn remediation_broken_archive_surfaces_log_error_context_in_fatal_block() {
    // Reproduce the broken-archive case where the underlying cause is
    // visible in oradaz.log: an ERROR plus its DEBUG follow-up. The FATAL
    // item must render those as bullet lines (Item.details) between
    // explanation and action.
    let log_text = "2026-05-28 16:59:42  |  INFO   | main                     start\n\
                    2026-05-28 16:59:52  |  ERROR  | ClientCredentialsAuth    Error acquiring client credentials token for service \"graph\"\n\
                    2026-05-28 16:59:52  |  DEBUG  | ClientCredentialsAuth    Client credentials token exchange error: TimedOut\n";
    let mut source = make_source(
        Some(json!({"unexpected_errors": 0})),
        None,
        None,
        vec![],
        true,
    );
    source.log_text = log_text.to_string();
    let text = rendered(&source, None, false);
    assert!(text.contains("FATAL"));
    assert!(text.contains("Archive interrupted"));
    assert!(
        text.contains("Error acquiring client credentials token"),
        "FATAL must quote the ERROR line"
    );
    assert!(
        text.contains("TimedOut"),
        "FATAL must include the DEBUG follow-up that carries the cause"
    );
}

#[test]
fn remediation_log_bullets_attached_to_first_fatal_only_when_broken_and_auth_both_fire() {
    // When both `is_broken == true` and `auth_errors > 0`, the FATAL section
    // emits two items. The log-tail bullets must attach to the first (broken)
    // item only — printing the same lines twice is noise.
    let log_text = "2026-05-28 16:59:52  |  ERROR  | Auth                     boom\n\
                    2026-05-28 16:59:52  |  DEBUG  | Auth                     reason: TimedOut\n";
    let mut source = make_source(
        Some(json!({"auth_errors": 1})),
        None,
        None,
        vec![],
        true, // is_broken
    );
    source.log_text = log_text.to_string();
    let text = rendered(&source, None, false);
    let context_lines = text.matches("reason: TimedOut").count();
    assert_eq!(
        context_lines, 1,
        "the log-tail DEBUG message must appear exactly once across both fatal items, got {context_lines} times:\n{text}"
    );
    // Both fatal items must still be rendered.
    assert!(text.contains("Archive interrupted"));
    assert!(text.contains("authentication error"));
}

#[test]
fn remediation_auth_failed_surfaces_log_error_context() {
    let log_text = "2026-05-28 16:59:42  |  INFO   | main                     start\n\
                    2026-05-28 16:59:52  |  ERROR  | Auth                     refresh_token grant denied\n\
                    2026-05-28 16:59:52  |  DEBUG  | Auth                     invalid_grant: AADSTS50173\n";
    let mut source = make_source(Some(json!({"auth_errors": 2})), None, None, vec![], false);
    source.log_text = log_text.to_string();
    let text = rendered(&source, None, false);
    assert!(text.contains("AUTH FAILED"));
    assert!(text.contains("authentication error"));
    assert!(
        text.contains("refresh_token grant denied"),
        "AUTH FAILED must quote the ERROR line"
    );
    assert!(
        text.contains("AADSTS50173"),
        "AUTH FAILED must include the DEBUG follow-up with the AAD error code"
    );
}

#[test]
fn remediation_fatal_for_auth_errors() {
    let source = make_source(Some(json!({"auth_errors": 2})), None, None, vec![], false);
    let text = rendered(&source, None, false);
    assert!(text.contains("AUTH FAILED"));
    assert!(text.contains("2 authentication error"));
}

#[test]
fn remediation_fatal_for_disabled_by_prereq_failure() {
    let source = make_source(
        Some(json!({
            "unexpected_errors": 0,
            "services": {"exchange": "disabled_by_prerequisite_failure"},
        })),
        None,
        Some(json!({"exchange": {"error": "missing role: Exchange Administrator"}})),
        vec![],
        false,
    );
    let text = rendered(&source, None, false);
    assert!(text.contains("FATAL"));
    assert!(text.contains("Exchange not collected"));
    assert!(text.contains("missing role: Exchange Administrator"));
    assert!(text.contains("Grant the missing"));
}

#[test]
fn remediation_no_available_subscription_is_benign_skip() {
    // U4: NoAvailableSubscription is a startup skip, not a mid-run permission
    // failure — it must read as benign, not "grant the missing permission".
    let source = make_source(
        Some(json!({
            "unexpected_errors": 0,
            "services": {"resources": "disabled_by_prerequisite_failure"},
        })),
        None,
        Some(json!({"resources": {"status": "error", "error": "NoAvailableSubscription"}})),
        vec![],
        false,
    );
    let text = rendered(&source, None, false);
    assert!(text.contains("Resources skipped — no Azure subscription"));
    assert!(text.contains("NoAvailableSubscription (checked at startup)"));
    assert!(text.contains("Normal if the tenant has no Azure subscription"));
    // Must NOT use the misleading permission-failure wording.
    assert!(!text.contains("Resources not collected"));
    assert!(!text.contains("Grant the missing"));
}

// ─── UNEXPECTED section ──────────────────────────────────────────────────

#[test]
fn remediation_unexpected_attaches_hint_explanation_and_action() {
    let source = make_source(
        Some(json!({"unexpected_errors": 2})),
        None,
        None,
        vec![
            dump_error("graph", "users", 403, "Authorization_RequestDenied", false),
            dump_error("graph", "users", 403, "Authorization_RequestDenied", false),
        ],
        false,
    );
    let text = rendered(&source, None, false);
    assert!(text.contains("UNEXPECTED ERRORS"));
    assert!(text.contains("graph/users · 403"));
    assert!(text.contains("(×2)"), "grouped count must appear");
    // The hints catalog answer for 403 / Authorization_RequestDenied:
    assert!(text.contains("Microsoft Graph API permission"));
    assert!(text.contains("admin consent"));
}

#[test]
fn remediation_unexpected_falls_back_when_no_hint_catalogued() {
    let source = make_source(
        Some(json!({"unexpected_errors": 1})),
        None,
        None,
        vec![dump_error("graph", "users", 418, "ImATeapot", false)],
        false,
    );
    let text = rendered(&source, None, false);
    assert!(text.contains("graph/users · 418 ImATeapot"));
    assert!(text.contains("No catalogued remediation"));
}

/// A lost-data abandonment (`status == 0`, e.g. `ThrottleStalled` from the
/// liveness ceiling) renders with a clean "data lost" headline (not a confusing
/// literal `0`) and a code-specific cause/remediation from the catalog — so a
/// post-hoc inspector reads the loss cause, not "no catalogued remediation".
#[test]
fn remediation_lost_data_throttle_stalled_shows_cause() {
    let source = make_source(
        Some(json!({"errors": 1})),
        None,
        None,
        vec![dump_error(
            "graph",
            "authMethods",
            0,
            "ThrottleStalled",
            false,
        )],
        false,
    );
    let text = rendered(&source, None, false);
    assert!(
        text.contains("graph/authMethods · ThrottleStalled (data lost)"),
        "lost-data headline must mark the loss, not show status 0:\n{text}"
    );
    assert!(
        text.contains("throttled") && text.contains("concurrencyMaxWindow"),
        "must surface the ThrottleStalled cause + remediation:\n{text}"
    );
    assert!(
        !text.contains("No catalogued remediation"),
        "a catalogued lost-data cause must not fall back to the generic message:\n{text}"
    );
}

/// `MissingTokenForRelationships` is `status == 0` but is NOT lost data (the
/// page was written; only relationship expansion was skipped). It must render
/// without the "(data lost)" marker and, since it carries no api, with a
/// service-only label (no dangling `graph/ ·`).
#[test]
fn remediation_missing_token_for_relationships_is_not_data_lost() {
    let source = make_source(
        Some(json!({"errors": 1})),
        None,
        None,
        vec![dump_error(
            "graph",
            "",
            0,
            "MissingTokenForRelationships",
            false,
        )],
        false,
    );
    let text = rendered(&source, None, false);
    assert!(
        text.contains("graph · MissingTokenForRelationships"),
        "must use a service-only label with no dangling slash:\n{text}"
    );
    assert!(
        !text.contains("MissingTokenForRelationships (data lost)"),
        "MissingTokenForRelationships must not be marked as data lost:\n{text}"
    );
    assert!(
        !text.contains("graph/ ·"),
        "must not render a dangling service/ separator:\n{text}"
    );
}

// ─── THROTTLING section ──────────────────────────────────────────────────

fn stats_with_throttling() -> Value {
    json!({
        "duration_seconds": 100,
        "apis": [
            {"service": "resources", "api": "subs",
             "requests_sent": 44, "unexpected_errors": 0, "network_errors": 0,
             "retries_real": 0, "retries_rate_limit": 31,
             "rate_limit_wait_secs": 268, "prereq_rechecks_triggered": 0},
        ],
    })
}

#[test]
fn remediation_throttling_pulled_from_stats() {
    let source = make_source(
        Some(json!({"unexpected_errors": 0})),
        Some(stats_with_throttling()),
        None,
        vec![],
        false,
    );
    let text = rendered(&source, None, false);
    assert!(text.contains("THROTTLING"));
    assert!(text.contains("resources/subs"));
    assert!(text.contains("31× 429"));
    assert!(text.contains("268 s"));
    assert!(text.contains("concurrencyMaxWindow"));
}

#[test]
fn remediation_throttling_dedupes_stats_and_429_dump_error() {
    let source = make_source(
        Some(json!({"unexpected_errors": 0})),
        Some(stats_with_throttling()),
        None,
        vec![dump_error(
            "resources",
            "subs",
            429,
            "TooManyRequests",
            false,
        )],
        false,
    );
    let text = rendered(&source, None, false);
    // Only one row for resources/subs (stats summary wins).
    let throttle_lines: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("resources/subs"))
        .collect();
    assert_eq!(
        throttle_lines.len(),
        1,
        "must dedupe on (service, api): got {throttle_lines:?}"
    );
    assert!(throttle_lines[0].contains("31× 429"));
}

#[test]
fn remediation_throttling_429_budget_exhausted_only_when_no_stats() {
    // No stats but a 429 DumpError → render the "budget exhausted" line.
    let source = make_source(
        Some(json!({"unexpected_errors": 0})),
        None,
        None,
        vec![dump_error(
            "resources",
            "subs",
            429,
            "TooManyRequests",
            false,
        )],
        false,
    );
    let text = rendered(&source, None, false);
    assert!(text.contains("budget exhausted"));
}

// ─── EXPECTED section ────────────────────────────────────────────────────

#[test]
fn remediation_expected_default_is_summary_with_pointer() {
    let source = make_source(
        Some(json!({})),
        None,
        None,
        vec![
            dump_error("graph", "groups", 403, "Forbidden", true),
            dump_error("graph", "groups", 403, "Forbidden", true),
        ],
        false,
    );
    let text = rendered(&source, None, false);
    assert!(text.contains("EXPECTED ERRORS"));
    assert!(text.contains("2 entries declared expected"));
    assert!(text.contains("inspect hints --include-expected"));
}

#[test]
fn remediation_include_expected_lists_each_entry() {
    let source = make_source(
        Some(json!({})),
        None,
        None,
        vec![dump_error("graph", "groups", 403, "Forbidden", true)],
        false,
    );
    let text = rendered(&source, None, true);
    assert!(text.contains("EXPECTED ERRORS"));
    assert!(text.contains("graph/groups · 403 Forbidden"));
    assert!(text.contains("Declared as `expected_error_codes`"));
}

// ─── service filter ──────────────────────────────────────────────────────

#[test]
fn remediation_service_filter_narrows_all_sections() {
    let source = make_source(
        Some(json!({"unexpected_errors": 2})),
        Some(stats_with_throttling()), // resources entry
        None,
        vec![
            dump_error("graph", "users", 403, "Forbidden", false),
            dump_error("resources", "locks", 500, "Server", false),
        ],
        false,
    );
    let text = rendered(&source, Some("graph"), false);
    assert!(text.contains("graph/users"));
    assert!(
        !text.contains("resources/subs"),
        "resources throttle line must be filtered out"
    );
    assert!(
        !text.contains("resources/locks"),
        "resources unexpected line must be filtered out"
    );
}
