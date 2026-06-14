mod common;

use crate::common::default_test_stats;
use oradaz::utils::stats::{NetworkErrorKind, Stats};

use chrono::Utc;
use serde_json::Value;
use std::sync::Arc;
use tokio::time::{Duration, advance};

/// With the ceiling left at its `0` default, liveness abandonment is disabled:
/// `liveness_should_abandon` is always `false`, regardless of elapsed time —
/// the value tests use when they don't exercise liveness.
#[tokio::test(start_paused = true)]
async fn liveness_disabled_when_ceiling_zero() {
    let stats = default_test_stats();
    assert!(!stats.liveness_should_abandon("graph", "users"));
    advance(Duration::from_secs(10_000)).await;
    assert!(!stats.liveness_should_abandon("graph", "users"));
}

/// With a ceiling set, a bucket that makes no progress is abandoned once the
/// ceiling elapses. The first call seeds the baseline (so it is never abandoned
/// on first contact), and the decision is keyed per `(service, api)`.
#[tokio::test(start_paused = true)]
async fn liveness_trips_after_ceiling_without_progress() {
    let stats = default_test_stats();
    stats.set_liveness_ceiling_secs(100);

    // First contact seeds the baseline at t=0 → not abandoned.
    assert!(!stats.liveness_should_abandon("graph", "authMethods"));

    // Still within the ceiling.
    advance(Duration::from_secs(99)).await;
    assert!(!stats.liveness_should_abandon("graph", "authMethods"));

    // Past the ceiling with no progress → abandon.
    advance(Duration::from_secs(1)).await;
    assert!(stats.liveness_should_abandon("graph", "authMethods"));

    // A sibling bucket that just made first contact is measured independently.
    assert!(!stats.liveness_should_abandon("graph", "users"));
}

/// `note_progress` (a data-writing success) resets the per-bucket timer, so an
/// actively-draining bucket is never abandoned even across long total runtime.
#[tokio::test(start_paused = true)]
async fn liveness_resets_on_progress() {
    let stats = default_test_stats();
    stats.set_liveness_ceiling_secs(100);

    stats.note_progress("graph", "authMethods"); // baseline t=0
    advance(Duration::from_secs(150)).await;
    // 150s with no further progress → stalled.
    assert!(stats.liveness_should_abandon("graph", "authMethods"));

    // A success lands: timer resets, bucket is no longer abandoned.
    stats.note_progress("graph", "authMethods");
    assert!(!stats.liveness_should_abandon("graph", "authMethods"));
}

#[test]
fn record_single_dispatch_creates_api_entry() {
    let stats = default_test_stats();
    stats.record_single_dispatch("graph", "users");
    stats.record_single_dispatch("graph", "users");

    let json: Value = serde_json::to_value(&*stats).unwrap();
    let apis = json["apis"].as_array().unwrap();
    assert_eq!(apis.len(), 1);
    assert_eq!(apis[0]["service"], "graph");
    assert_eq!(apis[0]["api"], "users");
    assert_eq!(apis[0]["requests_sent"], 2);
    assert_eq!(apis[0]["http_single_calls"], 2);
    assert_eq!(apis[0]["http_batch_calls"], 0);
    assert!(apis[0]["first_request_at"].is_string());
    assert!(apis[0]["last_request_at"].is_string());
}

#[test]
fn record_batch_dispatch_dedupes_http_batch_calls() {
    let stats = default_test_stats();
    let pairs = vec![
        ("graph".to_string(), "users".to_string()),
        ("graph".to_string(), "users".to_string()),
        ("graph".to_string(), "groups".to_string()),
    ];
    stats.record_batch_dispatch("graph", pairs);

    let json: Value = serde_json::to_value(&*stats).unwrap();
    let apis = json["apis"].as_array().unwrap();
    let users = apis.iter().find(|a| a["api"] == "users").unwrap();
    let groups = apis.iter().find(|a| a["api"] == "groups").unwrap();
    // requests_sent counts every sub-URL
    assert_eq!(users["requests_sent"], 2);
    assert_eq!(groups["requests_sent"], 1);
    // http_batch_calls is incremented once per API present in the batch
    assert_eq!(users["http_batch_calls"], 1);
    assert_eq!(groups["http_batch_calls"], 1);
    assert_eq!(users["http_single_calls"], 0);
}

#[test]
fn record_non_http_error_counts_exactly() {
    let stats = default_test_stats();
    assert_eq!(stats.non_http_errors(), 0);
    stats.record_non_http_error();
    stats.record_non_http_error();
    assert_eq!(stats.non_http_errors(), 2);
}

#[test]
fn record_response_distinguishes_expected_and_unexpected() {
    let stats = default_test_stats();
    stats.record_response("graph", "users", 200, false);
    stats.record_response("graph", "users", 200, false);
    stats.record_response("graph", "users", 404, true); // expected
    stats.record_response("graph", "users", 500, false); // unexpected
    stats.record_response("graph", "users", 429, false); // throttle, not counted in expected/unexpected

    let json: Value = serde_json::to_value(&*stats).unwrap();
    let api = &json["apis"][0];
    assert_eq!(api["responses_by_status"]["200"], 2);
    assert_eq!(api["responses_by_status"]["404"], 1);
    assert_eq!(api["responses_by_status"]["500"], 1);
    assert_eq!(api["responses_by_status"]["429"], 1);
    assert_eq!(api["expected_errors"], 1);
    assert_eq!(api["unexpected_errors"], 1);
}

#[test]
fn record_rate_limit_retry_accumulates_wait() {
    let stats = default_test_stats();
    stats.record_rate_limit_retry("graph", "users", 30);
    stats.record_rate_limit_retry("graph", "users", 15);

    let json: Value = serde_json::to_value(&*stats).unwrap();
    let api = &json["apis"][0];
    assert_eq!(api["retries_rate_limit"], 2);
    assert_eq!(api["rate_limit_wait_secs"], 45);
}

#[test]
fn record_condition_check_updates_global_and_api() {
    let stats = default_test_stats();
    stats.record_condition_check("P1", true, Some(("graph", "users")));
    stats.record_condition_check("P1", true, Some(("graph", "users")));
    stats.record_condition_check("P1", false, None);

    let json: Value = serde_json::to_value(&*stats).unwrap();
    let global = json["conditions"].as_array().unwrap();
    assert_eq!(global.len(), 1);
    assert_eq!(global[0]["name"], "P1");
    assert_eq!(global[0]["checks"], 3);
    assert_eq!(global[0]["true_count"], 2);
    assert_eq!(global[0]["false_count"], 1);

    let api = &json["apis"][0];
    let api_cond = api["condition_checks"].as_array().unwrap();
    assert_eq!(api_cond.len(), 1);
    assert_eq!(api_cond[0]["name"], "P1");
    assert_eq!(api_cond[0]["checks"], 2);
    assert_eq!(api_cond[0]["true_count"], 2);
}

#[test]
fn record_prereq_recheck_and_trigger() {
    let stats = default_test_stats();
    stats.record_prereq_trigger("graph", "users");
    stats.record_prereq_trigger("graph", "users");
    stats.record_prereq_recheck("graph");

    let json: Value = serde_json::to_value(&*stats).unwrap();
    let api = &json["apis"][0];
    assert_eq!(api["prereq_rechecks_triggered"], 2);
    assert_eq!(json["prereq_rechecks"]["graph"], 1);
}

#[test]
fn record_network_error_increments_counter() {
    let stats = default_test_stats();
    stats.record_network_error("graph", "users");
    stats.record_network_error("graph", "users");
    stats.record_network_error("exchange", "mailbox");

    let json: Value = serde_json::to_value(&*stats).unwrap();
    let apis = json["apis"].as_array().unwrap();
    let users = apis.iter().find(|a| a["api"] == "users").unwrap();
    let mailbox = apis.iter().find(|a| a["api"] == "mailbox").unwrap();
    assert_eq!(users["network_errors"], 2);
    assert_eq!(mailbox["network_errors"], 1);
}

#[test]
fn finalize_sets_ended_at_and_duration() {
    let stats = Arc::new(Stats::new());
    stats.record_single_dispatch("graph", "users");
    stats.finalize(Utc::now());

    let json: Value = serde_json::to_value(&*stats).unwrap();
    assert!(json["ended_at"].is_string());
    assert!(json["duration_seconds"].is_i64());
}

#[test]
fn services_track_http_calls_independently_from_apis() {
    let stats = default_test_stats();
    // One single call to graph/users and one batch HTTP call carrying two graph APIs.
    stats.record_single_dispatch("graph", "users");
    stats.record_batch_dispatch(
        "graph",
        vec![
            ("graph".to_string(), "users".to_string()),
            ("graph".to_string(), "groups".to_string()),
        ],
    );

    let json: Value = serde_json::to_value(&*stats).unwrap();
    let graph = &json["services"]["graph"];
    assert_eq!(graph["http_single_calls"], 1);
    // The batch is one HTTP call even though it targets two APIs.
    assert_eq!(graph["http_batch_calls"], 1);
}

#[test]
fn record_http_call_failure_counts_service_level_once() {
    let stats = default_test_stats();
    // A batch HTTP call carrying three sub-URLs fails at the network layer:
    // per-API network_errors is attributed to each sub-URL, but the service-
    // level counter only sees one failure.
    stats.record_network_error("graph", "users");
    stats.record_network_error("graph", "users");
    stats.record_network_error("graph", "groups");
    stats.record_http_call_failure("graph");

    let json: Value = serde_json::to_value(&*stats).unwrap();
    let apis = json["apis"].as_array().unwrap();
    let users = apis.iter().find(|a| a["api"] == "users").unwrap();
    let groups = apis.iter().find(|a| a["api"] == "groups").unwrap();
    assert_eq!(
        users["network_errors"], 2,
        "per-API attribution: 2 errors on graph/users"
    );
    assert_eq!(
        groups["network_errors"], 1,
        "per-API attribution: 1 error on graph/groups"
    );
    assert_eq!(
        json["services"]["graph"]["http_call_failures"], 1,
        "service-level counter records the failure exactly once"
    );
}

#[test]
fn record_upstream_error_code_surfaces_url_retry_limit() {
    // Mimics the give-up signal raised by dispatch.rs when a URL exceeds
    // urlRetryLimit: the individual failed responses were already counted in
    // unexpected_errors, but the give-up event itself goes through
    // record_upstream_error_code with the "UrlRetryLimit" sentinel so the
    // inspect view shows *which* APIs were abandoned.
    let stats = default_test_stats();
    stats.record_upstream_error_code("graph", "users", "UrlRetryLimit");
    stats.record_upstream_error_code("graph", "users", "UrlRetryLimit");

    let json: Value = serde_json::to_value(&*stats).unwrap();
    let codes = json["apis"][0]["upstream_error_codes"].as_object().unwrap();
    assert_eq!(codes["UrlRetryLimit"], 2);
}

#[test]
fn record_upstream_error_code_skips_empty_strings() {
    let stats = default_test_stats();
    stats.record_upstream_error_code("graph", "users", "UnknownError");
    stats.record_upstream_error_code("graph", "users", "UnknownError");
    stats.record_upstream_error_code("graph", "users", "");
    stats.record_upstream_error_code("graph", "users", "Forbidden");

    let json: Value = serde_json::to_value(&*stats).unwrap();
    let codes = json["apis"][0]["upstream_error_codes"].as_object().unwrap();
    assert_eq!(codes["UnknownError"], 2);
    assert_eq!(codes["Forbidden"], 1);
    assert!(!codes.contains_key(""));
}

#[test]
fn lost_data_summary_none_when_clean() {
    // An API with no lost-data records yields None (no "PARTIAL COLLECTION" row).
    let stats = default_test_stats();
    stats.record_single_dispatch("graph", "users");
    assert_eq!(stats.lost_data_summary("graph", "users"), None);
    assert_eq!(stats.lost_data_summary("graph", "unknown"), None);
}

#[test]
fn record_lost_data_totals_and_dominant_code() {
    // status==0 terminal failures bypass unexpected_errors and are tracked here.
    let stats = default_test_stats();
    stats.record_lost_data("graph", "users", "UrlRetryLimit");
    stats.record_lost_data("graph", "users", "UrlRetryLimit");
    stats.record_lost_data("graph", "users", "UrlRetryLimit");
    stats.record_lost_data("graph", "users", "NoTokenForApiCall");

    let (total, code) = stats.lost_data_summary("graph", "users").unwrap();
    assert_eq!(total, 4);
    assert_eq!(code, "UrlRetryLimit");
}

#[test]
fn lost_data_summary_dominant_tie_is_deterministic() {
    // Equal counts must resolve to the lexicographically smallest code so the
    // displayed reason is stable across runs (DashMap order is non-deterministic).
    let stats = default_test_stats();
    stats.record_lost_data("graph", "users", "UrlRetryLimit");
    stats.record_lost_data("graph", "users", "NoTokenForApiCall");

    let (total, code) = stats.lost_data_summary("graph", "users").unwrap();
    assert_eq!(total, 2);
    assert_eq!(code, "NoTokenForApiCall"); // "N..." < "U..."
}

#[test]
fn record_lost_data_skips_empty_code() {
    let stats = default_test_stats();
    stats.record_lost_data("graph", "users", "");
    assert_eq!(stats.lost_data_summary("graph", "users"), None);
}

#[test]
fn record_lost_data_serialized_per_api_and_totalled() {
    // Lost-data failures are persisted per API in stats.json (code → count map)
    // and summed by `total_lost_data` for the metadata.json run-level counter.
    let stats = default_test_stats();
    stats.record_lost_data("graph", "users", "UrlRetryLimit");
    stats.record_lost_data("graph", "users", "UrlRetryLimit");
    stats.record_lost_data("graph", "users", "ThrottleStalled");
    stats.record_lost_data("resources", "subscriptions", "NetworkStalled");

    assert_eq!(stats.total_lost_data(), 4);

    let json: Value = serde_json::to_value(&*stats).unwrap();
    let apis = json["apis"].as_array().unwrap();
    let users = apis.iter().find(|a| a["api"] == "users").unwrap();
    assert_eq!(users["lost_data_by_code"]["UrlRetryLimit"], 2);
    assert_eq!(users["lost_data_by_code"]["ThrottleStalled"], 1);
    let subs = apis.iter().find(|a| a["api"] == "subscriptions").unwrap();
    assert_eq!(subs["lost_data_by_code"]["NetworkStalled"], 1);
}

#[test]
fn lost_data_by_code_empty_map_on_clean_api() {
    // A clean API serializes an empty map (the key is always present, so jq
    // consumers can rely on it without per-field existence checks).
    let stats = default_test_stats();
    stats.record_single_dispatch("graph", "users");
    let json: Value = serde_json::to_value(&*stats).unwrap();
    let lost = &json["apis"][0]["lost_data_by_code"];
    assert!(lost.is_object());
    assert!(lost.as_object().unwrap().is_empty());
    assert_eq!(stats.total_lost_data(), 0);
}

#[test]
fn record_http_latency_tracks_service_and_api() {
    let stats = default_test_stats();
    // Two single calls (attributed to both service and API) plus one batch call
    // (service-level only, since a batch envelope's latency can't map to one API).
    stats.record_http_latency("graph", Some("users"), 100, 200);
    stats.record_http_latency("graph", Some("users"), 300, 200);
    stats.record_http_latency("graph", None, 50, 200);

    let json: Value = serde_json::to_value(&*stats).unwrap();
    let svc = &json["services"]["graph"];
    assert_eq!(svc["http_latency_count"], 3, "all 3 HTTP calls counted");
    assert_eq!(svc["http_latency_sum_ms"], 450);
    assert_eq!(svc["http_latency_max_ms"], 300);

    let api = json["apis"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["api"] == "users")
        .unwrap();
    // Only the two single calls are attributed per-API; the batch latency is not.
    assert_eq!(api["http_latency_count"], 2);
    assert_eq!(api["http_latency_sum_ms"], 400);
    assert_eq!(api["http_latency_max_ms"], 300);
}

#[test]
fn record_http_latency_splits_success_from_throttled() {
    // The all-response trio counts everything; the *_ok_* trio only 2xx, so a
    // fast 429 turnaround cannot drag down the mean of data-delivering calls.
    let stats = default_test_stats();
    stats.record_http_latency("resources", Some("subscriptions"), 800, 200);
    stats.record_http_latency("resources", Some("subscriptions"), 10, 429);
    stats.record_http_latency("resources", Some("subscriptions"), 20, 503);

    let json: Value = serde_json::to_value(&*stats).unwrap();
    let svc = &json["services"]["resources"];
    assert_eq!(svc["http_latency_count"], 3);
    assert_eq!(svc["http_latency_sum_ms"], 830);
    assert_eq!(svc["http_latency_ok_count"], 1, "only the 2xx call");
    assert_eq!(svc["http_latency_ok_sum_ms"], 800);
    assert_eq!(svc["http_latency_ok_max_ms"], 800);

    let api = json["apis"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["api"] == "subscriptions")
        .unwrap();
    assert_eq!(api["http_latency_ok_count"], 1);
    assert_eq!(api["http_latency_ok_sum_ms"], 800);
    assert_eq!(api["http_latency_count"], 3);
}

#[test]
fn record_network_error_kind_splits_by_cause() {
    let stats = default_test_stats();
    stats.record_network_error_kind("graph", NetworkErrorKind::Timeout);
    stats.record_network_error_kind("graph", NetworkErrorKind::Timeout);
    stats.record_network_error_kind("graph", NetworkErrorKind::Connect);
    stats.record_network_error_kind("graph", NetworkErrorKind::Other);

    let json: Value = serde_json::to_value(&*stats).unwrap();
    let svc = &json["services"]["graph"];
    assert_eq!(svc["network_timeout_errors"], 2);
    assert_eq!(svc["network_connect_errors"], 1);
    assert_eq!(svc["network_other_errors"], 1);
}

#[test]
fn record_backoff_wait_accumulates_per_service() {
    let stats = default_test_stats();
    stats.record_backoff_wait("graph", 250);
    stats.record_backoff_wait("graph", 500);
    stats.record_backoff_wait("exchange", 1000);

    let json: Value = serde_json::to_value(&*stats).unwrap();
    assert_eq!(json["services"]["graph"]["backoff_wait_ms_total"], 750);
    assert_eq!(json["services"]["exchange"]["backoff_wait_ms_total"], 1000);
}

#[tokio::test(start_paused = true)]
async fn service_pause_accounting_union_and_open_interval() {
    let stats = default_test_stats();

    // A second pause cause while already paused must not restart the interval,
    // and the union closes only on the final resume.
    stats.note_service_paused("graph");
    tokio::time::advance(std::time::Duration::from_secs(5)).await;
    stats.note_service_paused("graph"); // overlapping cause — idempotent
    tokio::time::advance(std::time::Duration::from_secs(5)).await;
    stats.note_service_resumed("graph");
    let pauses = stats.pause_secs_by_service();
    assert_eq!(pauses.get("graph"), Some(&10));

    // A redundant resume is a no-op.
    stats.note_service_resumed("graph");
    assert_eq!(stats.pause_secs_by_service().get("graph"), Some(&10));

    // An interval still open at read time counts up to "now" without closing.
    stats.note_service_paused("exchange");
    tokio::time::advance(std::time::Duration::from_secs(7)).await;
    let pauses = stats.pause_secs_by_service();
    assert_eq!(pauses.get("exchange"), Some(&7));
    tokio::time::advance(std::time::Duration::from_secs(3)).await;
    assert_eq!(stats.pause_secs_by_service().get("exchange"), Some(&10));
}

#[test]
fn token_refresh_and_stall_counters() {
    let stats = default_test_stats();
    stats.record_token_refresh("graph");
    stats.record_token_refresh("graph");
    stats.record_token_refresh("exchange");
    stats.record_stall();

    let refreshes = stats.token_refreshes_by_service();
    assert_eq!(refreshes.get("graph"), Some(&2));
    assert_eq!(refreshes.get("exchange"), Some(&1));
    assert_eq!(stats.stall_events(), 1);
}

#[test]
fn record_retry_after_provenance_splits_server_and_default() {
    let stats = default_test_stats();
    stats.record_retry_after_provenance("resources", Some(20));
    stats.record_retry_after_provenance("resources", Some(60));
    stats.record_retry_after_provenance("resources", None);

    let json: Value = serde_json::to_value(&*stats).unwrap();
    let svc = &json["services"]["resources"];
    assert_eq!(svc["retry_after_server_count"], 2);
    assert_eq!(svc["retry_after_default_count"], 1);
    assert_eq!(
        svc["retry_after_max_secs"], 60,
        "tracks the largest server-provided Retry-After"
    );
}

#[test]
fn record_page_followed_counts_pages_beyond_first() {
    let stats = default_test_stats();
    stats.record_page_followed("graph", "users");
    stats.record_page_followed("graph", "users");
    stats.record_page_followed("resources", "subscriptions");

    let json: Value = serde_json::to_value(&*stats).unwrap();
    let apis = json["apis"].as_array().unwrap();
    let users = apis.iter().find(|a| a["api"] == "users").unwrap();
    let subs = apis.iter().find(|a| a["api"] == "subscriptions").unwrap();
    assert_eq!(users["pages_followed"], 2);
    assert_eq!(subs["pages_followed"], 1);
}

#[test]
fn record_child_urls_generated_accumulates_and_ignores_zero() {
    let stats = default_test_stats();
    stats.record_child_urls_generated("graph", "users", 5);
    stats.record_child_urls_generated("graph", "users", 3);
    // n == 0 must neither create an entry nor change any count.
    stats.record_child_urls_generated("graph", "groups", 0);

    let json: Value = serde_json::to_value(&*stats).unwrap();
    let apis = json["apis"].as_array().unwrap();
    let users = apis.iter().find(|a| a["api"] == "users").unwrap();
    assert_eq!(users["child_urls_generated"], 8);
    assert!(
        !apis.iter().any(|a| a["api"] == "groups"),
        "a zero-count fan-out must not create an API entry"
    );
}

#[test]
fn record_batch_dispatch_accumulates_batch_subrequests_total() {
    let stats = default_test_stats();
    // Two envelopes (3 sub-URLs then 2) → 5 sub-requests across 2 batch calls.
    // Batch-fill efficiency = batch_subrequests_total / http_batch_calls = 2.5.
    stats.record_batch_dispatch(
        "graph",
        vec![
            ("graph".to_string(), "users".to_string()),
            ("graph".to_string(), "groups".to_string()),
            ("graph".to_string(), "users".to_string()),
        ],
    );
    stats.record_batch_dispatch(
        "graph",
        vec![
            ("graph".to_string(), "applications".to_string()),
            ("graph".to_string(), "servicePrincipals".to_string()),
        ],
    );

    let json: Value = serde_json::to_value(&*stats).unwrap();
    let svc = &json["services"]["graph"];
    assert_eq!(svc["http_batch_calls"], 2, "two batch envelopes");
    assert_eq!(
        svc["batch_subrequests_total"], 5,
        "3 + 2 sub-requests packed across the two envelopes"
    );
}

#[test]
fn apis_serialized_sorted_by_key() {
    let stats = default_test_stats();
    stats.record_single_dispatch("resources", "subscriptions");
    stats.record_single_dispatch("graph", "users");
    stats.record_single_dispatch("exchange", "mailboxes");

    let json: Value = serde_json::to_value(&*stats).unwrap();
    let apis = json["apis"].as_array().unwrap();
    let labels: Vec<String> = apis
        .iter()
        .map(|a| {
            format!(
                "{}/{}",
                a["service"].as_str().unwrap(),
                a["api"].as_str().unwrap()
            )
        })
        .collect();
    assert_eq!(
        labels,
        vec![
            "exchange/mailboxes".to_string(),
            "graph/users".to_string(),
            "resources/subscriptions".to_string(),
        ]
    );
}

/// Expected-error breaker: the consecutive-expected streak trips exactly once
/// at the configured threshold, only on a bucket that never wrote a page.
#[test]
fn breaker_trips_once_at_threshold() {
    let stats = Stats::new();
    stats.set_breaker_threshold(3);

    assert!(!stats.record_expected_error_streak("graph", "rsc"));
    assert!(!stats.record_expected_error_streak("graph", "rsc"));
    assert!(
        stats.record_expected_error_streak("graph", "rsc"),
        "third consecutive expected error must trip"
    );
    assert!(
        !stats.record_expected_error_streak("graph", "rsc"),
        "the breaker fires at most once per bucket"
    );
}

/// A bucket that ever wrote a page never trips, and a written page restarts
/// the streak of a not-yet-tripped bucket.
#[test]
fn breaker_disarmed_by_progress() {
    let stats = Stats::new();
    stats.set_breaker_threshold(3);

    // Progress first: the bucket is permanently exempt.
    stats.note_progress("graph", "healthy");
    for _ in 0..10 {
        assert!(!stats.record_expected_error_streak("graph", "healthy"));
    }

    // Streak interrupted by progress before the threshold: restarts from zero.
    assert!(!stats.record_expected_error_streak("graph", "other"));
    assert!(!stats.record_expected_error_streak("graph", "other"));
    stats.note_progress("graph", "other");
    for _ in 0..10 {
        assert!(
            !stats.record_expected_error_streak("graph", "other"),
            "a bucket that wrote a page must never trip"
        );
    }
}

/// Threshold 0 disables the breaker entirely.
#[test]
fn breaker_disabled_at_zero_threshold() {
    let stats = Stats::new();
    stats.set_breaker_threshold(0);
    for _ in 0..100 {
        assert!(!stats.record_expected_error_streak("graph", "rsc"));
    }
}

/// Skipped-URL accounting: per-bucket counts surface in the metadata map and
/// the tripped-bucket count, and zero-count buckets stay absent.
#[test]
fn breaker_skipped_accounting() {
    let stats = Stats::new();
    stats.set_breaker_threshold(1);
    assert!(stats.record_expected_error_streak("graph", "rsc"));

    stats.record_breaker_skipped("graph", "rsc", 5);
    stats.record_breaker_skipped("graph", "rsc", 2);
    stats.record_breaker_skipped("graph", "untripped", 0); // no-op

    let map = stats.breaker_skipped_by_api();
    assert_eq!(map.get("graph/rsc"), Some(&7));
    assert_eq!(map.len(), 1, "zero-count buckets must stay absent");
    assert_eq!(stats.breaker_tripped_count(), 1);
}
