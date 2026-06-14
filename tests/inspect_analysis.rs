mod common;

use oradaz::collect::dump::response::DumpError;
use oradaz::inspect::analysis::{
    ErrorCategory, ServiceObjects, Verdict, aggregate_errors, compute_verdict, has_lost_data,
    objects_per_service,
};

use serde_json::json;

// ─── compute_verdict ─────────────────────────────────────────────────────

#[test]
fn verdict_interrupted_wins_over_everything() {
    // Even with auth_errors, unexpected_errors and a failed prereq, the
    // broken-archive flag must short-circuit.
    let metadata = json!({
        "auth_errors": 5,
        "unexpected_errors": 12,
        "prerequisites_errors": 1,
        "services": {"exchange": "disabled_by_prerequisite_failure"},
    });
    assert_eq!(
        compute_verdict(Some(&metadata), None, true, false),
        Verdict::Interrupted
    );
}

#[test]
fn verdict_auth_failed_wins_over_partial() {
    let metadata = json!({
        "auth_errors": 1,
        "unexpected_errors": 0,
        "prerequisites_errors": 0,
    });
    assert_eq!(
        compute_verdict(Some(&metadata), None, false, false),
        Verdict::AuthFailed
    );
}

#[test]
fn verdict_partial_from_unexpected_errors_metadata() {
    let metadata = json!({
        "unexpected_errors": 3,
        "auth_errors": 0,
        "prerequisites_errors": 0,
    });
    assert_eq!(
        compute_verdict(Some(&metadata), None, false, false),
        Verdict::Partial
    );
}

#[test]
fn verdict_partial_from_unexpected_errors_stats_fallback() {
    // Older archive: metadata lacks `unexpected_errors`; sum from stats.apis[].
    let metadata = json!({
        "auth_errors": 0,
        "prerequisites_errors": 0,
    });
    let stats = json!({
        "apis": [
            {"unexpected_errors": 2},
            {"unexpected_errors": 1},
        ]
    });
    assert_eq!(
        compute_verdict(Some(&metadata), Some(&stats), false, false),
        Verdict::Partial
    );
}

#[test]
fn verdict_complete_despite_prerequisites_errors() {
    // A non-fatal prerequisite failure (the only thing that bumps
    // `prerequisites_errors` on a completed archive) is a known scope gap, not
    // lost data: the collector finishes as COLLECTION COMPLETE, so the verdict
    // must agree — Partial is reserved for unexpected errors / lost data.
    let metadata = json!({
        "auth_errors": 0,
        "unexpected_errors": 0,
        "prerequisites_errors": 2,
    });
    assert_eq!(
        compute_verdict(Some(&metadata), None, false, false),
        Verdict::Complete
    );
}

#[test]
fn verdict_complete_when_service_disabled_by_prereq_failure() {
    // A service skipped for a failed prerequisite is surfaced in COVERAGE /
    // ATTENTION, not in the verdict badge — so the collection stays COMPLETE,
    // consistent with the collector's end-of-run summary.
    let metadata = json!({
        "auth_errors": 0,
        "unexpected_errors": 0,
        "prerequisites_errors": 0,
        "services": {
            "graph": "enabled",
            "exchange": "disabled_by_prerequisite_failure",
        },
    });
    assert_eq!(
        compute_verdict(Some(&metadata), None, false, false),
        Verdict::Complete
    );
}

#[test]
fn verdict_complete_when_only_disabled_by_config() {
    // disabled_by_config is a user choice, not a failure — still COMPLETE.
    let metadata = json!({
        "auth_errors": 0,
        "unexpected_errors": 0,
        "prerequisites_errors": 0,
        "services": {
            "graph": "enabled",
            "exchange": "disabled_by_config",
        },
    });
    assert_eq!(
        compute_verdict(Some(&metadata), None, false, false),
        Verdict::Complete
    );
}

#[test]
fn verdict_no_data_when_no_metadata() {
    // No readable metadata ⇒ NO DATA, not COMPLETE: an empty or corrupt source
    // must never be badged as a healthy collection.
    assert_eq!(compute_verdict(None, None, false, false), Verdict::NoData);
    // …unless the archive is `.broken`, which still wins as INTERRUPTED.
    assert_eq!(
        compute_verdict(None, None, true, false),
        Verdict::Interrupted
    );
}

#[test]
fn verdict_partial_from_lost_data() {
    // A run whose only failures are lost-data abandonments (status 0, no HTTP
    // code) records nothing in `unexpected_errors`, yet the collector badged it
    // PARTIAL COLLECTION. The verdict must match via the has_lost_data signal.
    let metadata = json!({
        "auth_errors": 0,
        "unexpected_errors": 0,
        "prerequisites_errors": 0,
    });
    let lost = vec![dump_error("graph", "users", 0, "ThrottleStalled", false)];
    assert!(has_lost_data(&lost));
    assert_eq!(
        compute_verdict(Some(&metadata), None, false, has_lost_data(&lost)),
        Verdict::Partial
    );
    // Without the lost-data signal the same metadata is COMPLETE.
    assert_eq!(
        compute_verdict(Some(&metadata), None, false, false),
        Verdict::Complete
    );
}

#[test]
fn has_lost_data_excludes_missing_token_for_relationships() {
    // `MissingTokenForRelationships` is status 0 but fires after the page was
    // written (only relationship expansion was skipped), so it must not count as
    // lost data nor flip the verdict.
    let only_missing_token = vec![dump_error(
        "graph",
        "",
        0,
        "MissingTokenForRelationships",
        false,
    )];
    assert!(!has_lost_data(&only_missing_token));
}

#[test]
fn verdict_labels_match_plan() {
    assert_eq!(Verdict::Complete.label(), "COMPLETE");
    assert_eq!(Verdict::Partial.label(), "PARTIAL");
    assert_eq!(Verdict::AuthFailed.label(), "AUTH FAILED");
    assert_eq!(Verdict::Interrupted.label(), "INTERRUPTED");
    assert_eq!(Verdict::NoData.label(), "NO DATA");
}

// ─── objects_per_service ─────────────────────────────────────────────────

#[test]
fn objects_per_service_groups_by_folder() {
    let metadata = json!({
        "tables": [
            {"name": "users", "folder": "graph", "file": "users", "count": 3201},
            {"name": "servicePrincipals", "folder": "graph", "file": "sp", "count": 1044},
            {"name": "subscriptions", "folder": "resources", "file": "subs", "count": 3},
            {"name": "mailboxes", "folder": "exchange", "file": "mb", "count": 7},
        ]
    });
    let agg = objects_per_service(Some(&metadata));
    assert_eq!(
        agg.get("graph"),
        Some(&ServiceObjects {
            objects: 4245,
            tables: 2
        })
    );
    assert_eq!(
        agg.get("resources"),
        Some(&ServiceObjects {
            objects: 3,
            tables: 1
        })
    );
    assert_eq!(
        agg.get("exchange"),
        Some(&ServiceObjects {
            objects: 7,
            tables: 1
        })
    );
}

#[test]
fn objects_per_service_skips_entries_without_folder() {
    let metadata = json!({
        "tables": [
            {"name": "orphan", "folder": "", "count": 99},
            {"name": "users", "folder": "graph", "count": 10},
        ]
    });
    let agg = objects_per_service(Some(&metadata));
    assert_eq!(agg.len(), 1);
    assert_eq!(agg.get("graph").unwrap().objects, 10);
}

#[test]
fn objects_per_service_empty_when_metadata_missing() {
    assert!(objects_per_service(None).is_empty());
    assert!(objects_per_service(Some(&json!({}))).is_empty());
    assert!(objects_per_service(Some(&json!({"tables": []}))).is_empty());
}

// ─── aggregate_errors ────────────────────────────────────────────────────

fn dump_error(folder: &str, file: &str, status: u16, code: &str, expected: bool) -> DumpError {
    DumpError {
        folder: folder.to_string(),
        file: file.to_string(),
        url: format!("https://example/{folder}/{file}"),
        status,
        code: code.to_string(),
        message: format!("msg for {folder}/{file} {status}"),
        expected,
        full_response: None,
        post_data: None,
    }
}

#[test]
fn aggregate_errors_groups_identical_tuples() {
    let errors = vec![
        dump_error("graph", "users", 403, "Forbidden", false),
        dump_error("graph", "users", 403, "Forbidden", false),
        dump_error("graph", "users", 404, "NotFound", false),
    ];
    let groups = aggregate_errors(&errors);
    assert_eq!(groups.len(), 2);
    // First group is the 403×2 (more frequent).
    assert_eq!(groups[0].status, 403);
    assert_eq!(groups[0].count, 2);
    assert_eq!(groups[1].status, 404);
    assert_eq!(groups[1].count, 1);
}

#[test]
fn aggregate_errors_picks_deterministic_representative_message() {
    // Same (folder, file, status, code, expected) tuple but different messages,
    // fed in two opposite orders. The representative message must be identical
    // across orders (the lexicographically smallest) so the inspect output is
    // stable regardless of the concurrent-write order of errors.json.
    let mk = |msg: &str| DumpError {
        folder: "graph".to_string(),
        file: "users".to_string(),
        url: "https://example/graph/users".to_string(),
        status: 500,
        code: "InternalServerError".to_string(),
        message: msg.to_string(),
        expected: false,
        full_response: None,
        post_data: None,
    };
    let forward = vec![mk("zeta error"), mk("alpha error"), mk("mu error")];
    let reverse = vec![mk("mu error"), mk("zeta error"), mk("alpha error")];
    let gf = aggregate_errors(&forward);
    let gr = aggregate_errors(&reverse);
    assert_eq!(gf.len(), 1);
    assert_eq!(gr.len(), 1);
    assert_eq!(
        gf[0].message, "alpha error",
        "should keep the smallest message"
    );
    assert_eq!(gf[0].message, gr[0].message, "must be order-independent");
    assert_eq!(gf[0].count, 3);
}

#[test]
fn aggregate_errors_code_tiebreak_is_deterministic() {
    // Two groups identical in (category, count, service, api, status) differing
    // only by code (the two lost-data abandonment codes) must render in a fixed
    // order regardless of the HashMap iteration order.
    let forward = vec![
        dump_error("graph", "users", 0, "ThrottleStalled", false),
        dump_error("graph", "users", 0, "NetworkStalled", false),
    ];
    let reverse = vec![
        dump_error("graph", "users", 0, "NetworkStalled", false),
        dump_error("graph", "users", 0, "ThrottleStalled", false),
    ];
    let codes = |errs: &[DumpError]| -> Vec<String> {
        aggregate_errors(errs)
            .iter()
            .map(|g| g.code.clone())
            .collect()
    };
    assert_eq!(codes(&forward), codes(&reverse), "order-independent");
    assert_eq!(codes(&forward), vec!["NetworkStalled", "ThrottleStalled"]);
}

#[test]
fn aggregate_errors_classifies_each_category() {
    let errors = vec![
        dump_error("graph", "users", 403, "Forbidden", false), // Unexpected
        dump_error("graph", "groups", 429, "TooMany", false),  // Throttling
        dump_error("graph", "audits", 403, "Forbidden", true), // Expected
    ];
    let groups = aggregate_errors(&errors);
    assert_eq!(groups.len(), 3);
    // Sort order: Unexpected > Throttling > Expected.
    assert_eq!(groups[0].category, ErrorCategory::Unexpected);
    assert_eq!(groups[1].category, ErrorCategory::Throttling);
    assert_eq!(groups[2].category, ErrorCategory::Expected);
}

#[test]
fn aggregate_errors_separates_expected_from_unexpected_with_same_status() {
    // Same (service, api, status, code) tuple but different `expected` flag →
    // two groups (an entry being expected-or-not is part of identity).
    let errors = vec![
        dump_error("graph", "users", 403, "Forbidden", false),
        dump_error("graph", "users", 403, "Forbidden", true),
    ];
    let groups = aggregate_errors(&errors);
    assert_eq!(groups.len(), 2);
    let cats: Vec<_> = groups.iter().map(|g| g.category).collect();
    assert!(cats.contains(&ErrorCategory::Unexpected));
    assert!(cats.contains(&ErrorCategory::Expected));
}

#[test]
fn aggregate_errors_severity_then_count_then_service() {
    let errors = vec![
        dump_error("resources", "z", 500, "ServerError", false), // Unexpected ×1
        dump_error("graph", "a", 500, "ServerError", false),     // Unexpected ×1
        dump_error("graph", "a", 500, "ServerError", false),     // → ×2 total
        dump_error("graph", "a", 429, "TooMany", false),         // Throttling ×1
    ];
    let groups = aggregate_errors(&errors);
    assert_eq!(groups.len(), 3);
    assert_eq!(groups[0].service, "graph"); // Unexpected, count=2 first
    assert_eq!(groups[0].count, 2);
    assert_eq!(groups[1].service, "resources"); // Unexpected, count=1
    assert_eq!(groups[2].category, ErrorCategory::Throttling); // last
}

#[test]
fn aggregate_errors_empty_input_returns_empty() {
    assert!(aggregate_errors(&[]).is_empty());
}
