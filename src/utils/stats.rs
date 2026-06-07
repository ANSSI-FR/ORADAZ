//! Per-API collection statistics written to `stats.json` at the end of a dump.
//!
//! `Stats` is a single shared `Arc<Stats>` updated lock-light from every actor
//! (dispatch, request, response, coordinator, condition checker). It uses
//! `DashMap` + atomics for the hot counters and `Mutex<Option<DateTime>>` for
//! the rare timestamp touches. Serialization snapshots the state into a
//! deterministic JSON layout sorted by service/api.

use crate::FL;
use crate::utils::errors::Error;
use crate::utils::writer::actor::WriterHandle;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use log::{debug, error};
use serde::{Serialize, Serializer, ser::SerializeMap, ser::SerializeSeq};
use std::collections::HashSet;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

pub struct Stats {
    /// Keyed by `"{service}/{api}"`.
    pub apis: DashMap<String, ApiStats>,
    /// Per-service HTTP call totals — one entry per HTTP request actually sent.
    /// Summing `http_batch_calls` across APIs double-counts a batch that targets
    /// several APIs; the per-service numbers reflect the real network cost and
    /// match the global "X requests" line printed at the end of a collection.
    pub services: DashMap<String, ServiceStats>,
    /// Tenant- and user-level condition evaluations (global, all APIs).
    pub conditions: DashMap<String, ConditionStats>,
    /// Number of prerequisite re-check tasks spawned, by service.
    pub prereq_rechecks: DashMap<String, AtomicUsize>,
    pub started_at: Mutex<DateTime<Utc>>,
    pub ended_at: Mutex<Option<DateTime<Utc>>>,
}

pub struct ServiceStats {
    pub http_batch_calls: AtomicUsize,
    pub http_single_calls: AtomicUsize,
    /// HTTP-call-level network failures (one per failed request, regardless of
    /// how many sub-URLs the batch carried). The per-API `network_errors` field
    /// counts attribution-per-sub-URL and therefore inflates by the batch size;
    /// this counter is the right one for the global summary line.
    pub http_call_failures: AtomicUsize,
    /// Sum of HTTP round-trip latencies (ms) for this service — `send()` through
    /// reading the response body. With `http_latency_count` it yields the mean
    /// latency; the activity window (`last − first`) cannot, as it conflates
    /// queuing and throttling with server latency. One sample per HTTP call
    /// (batch envelopes count once, not per sub-URL).
    pub http_latency_sum_ms: AtomicU64,
    /// Largest single HTTP round-trip latency (ms) observed for this service.
    pub http_latency_max_ms: AtomicU64,
    /// Number of HTTP round-trips timed for this service (the `*_sum_ms`
    /// denominator).
    pub http_latency_count: AtomicU64,
    /// Count of 429s where the server provided a parseable `Retry-After`.
    pub retry_after_server_count: AtomicU64,
    /// Count of 429s with no usable `Retry-After` — the configured default cooldown
    /// was applied. A high ratio here means `defaultRetryAfterSeconds` is load-bearing
    /// for this service and worth tuning.
    pub retry_after_default_count: AtomicU64,
    /// Largest server-provided `Retry-After` (seconds) seen for this service —
    /// reference point for sizing `defaultRetryAfterSeconds` / `rateLimitMaxWaitSecs`.
    pub retry_after_max_secs: AtomicU64,
    /// Total sub-requests packed into this service's batch envelopes (Σ of each
    /// batch's fill). Batch-fill efficiency = `batch_subrequests_total /
    /// http_batch_calls`; a value well below 20 means batches dispatched
    /// under-filled — a small dispatch frontier, or the Graph v1.0/beta envelope
    /// split halving effective fill. `0` for services that never batch.
    pub batch_subrequests_total: AtomicUsize,
}

impl ServiceStats {
    fn new() -> Self {
        Self {
            http_batch_calls: AtomicUsize::new(0),
            http_single_calls: AtomicUsize::new(0),
            http_call_failures: AtomicUsize::new(0),
            http_latency_sum_ms: AtomicU64::new(0),
            http_latency_max_ms: AtomicU64::new(0),
            http_latency_count: AtomicU64::new(0),
            retry_after_server_count: AtomicU64::new(0),
            retry_after_default_count: AtomicU64::new(0),
            retry_after_max_secs: AtomicU64::new(0),
            batch_subrequests_total: AtomicUsize::new(0),
        }
    }
}

pub struct ApiStats {
    pub service: String,
    pub api: String,
    pub requests_sent: AtomicUsize,
    pub http_batch_calls: AtomicUsize,
    pub http_single_calls: AtomicUsize,
    pub responses_by_status: DashMap<u16, AtomicUsize>,
    pub network_errors: AtomicUsize,
    pub retries_real: AtomicUsize,
    pub retries_rate_limit: AtomicUsize,
    pub rate_limit_wait_secs: AtomicU64,
    pub expected_errors: AtomicUsize,
    pub unexpected_errors: AtomicUsize,
    pub first_request_at: Mutex<Option<DateTime<Utc>>>,
    pub last_request_at: Mutex<Option<DateTime<Utc>>>,
    pub condition_checks: DashMap<String, ConditionStats>,
    pub prereq_rechecks_triggered: AtomicUsize,
    /// Per-API HTTP round-trip latency (ms): sum, max, and sample count. Recorded
    /// only for **single** (non-batch) calls — a batch envelope carries one latency
    /// for up to 20 sub-URLs, so per-endpoint latency is meaningful only for the
    /// single-call services (resources/ARG, exchange). Graph (batched) gets
    /// service-level latency via `ServiceStats` instead.
    pub http_latency_sum_ms: AtomicU64,
    pub http_latency_max_ms: AtomicU64,
    pub http_latency_count: AtomicU64,
    /// Counts of upstream error codes (the `code` field of error responses,
    /// e.g. "UnknownError", "Forbidden", "InvalidAuthenticationToken") for
    /// failed (non-2xx, non-429) responses. Used to give the inspect view
    /// actionable hints when an API is flagged as problematic.
    pub upstream_error_codes: DashMap<String, AtomicUsize>,
    /// HTTP status code breakdown for *unexpected* errors only. Unlike
    /// `responses_by_status` (which mixes expected and unexpected), this field
    /// lets the post-collection summary identify the dominant failure mode for
    /// each API without being confused by benign expected errors.
    pub unexpected_responses_by_status: DashMap<u16, AtomicUsize>,
    /// Pagination follow-ups generated for this API: one per next-page URL
    /// (`@odata.nextLink` or ARG `$skipToken`), i.e. pages **beyond the first**
    /// (`0` = single-page). A high value flags an endpoint worth a per-API
    /// `$top` to fetch larger pages and cut round-trips.
    pub pages_followed: AtomicUsize,
    /// Relationship child URLs generated from this API's response objects
    /// (request fan-out). Concentrated fan-out drives URL-pool growth (cross
    /// with `peak_pool_len`) and flags `$expand` / relationship-pruning
    /// candidates for `schema-light`.
    pub child_urls_generated: AtomicUsize,
    /// Per-code count of *lost-data* failures: `DumpError`s with `status == 0`
    /// and `expected == false` (URL abandoned via `UrlRetryLimit`, or
    /// `NoTokenForApiCall` / `nextLinkParsingError` / `MissingBatchData` / …).
    /// These never produce an HTTP status, so they bypass `unexpected_errors`;
    /// recorded at the single `write_dump_error` chokepoint to feed the
    /// end-of-collection "PARTIAL COLLECTION" summary. In-memory only — not
    /// serialized to `stats.json`.
    pub lost_data_by_code: DashMap<String, AtomicUsize>,
}

pub struct ConditionStats {
    pub checks: AtomicUsize,
    pub true_count: AtomicUsize,
    pub false_count: AtomicUsize,
}

impl ApiStats {
    fn new(service: &str, api: &str) -> Self {
        Self {
            service: service.to_string(),
            api: api.to_string(),
            requests_sent: AtomicUsize::new(0),
            http_batch_calls: AtomicUsize::new(0),
            http_single_calls: AtomicUsize::new(0),
            responses_by_status: DashMap::new(),
            network_errors: AtomicUsize::new(0),
            retries_real: AtomicUsize::new(0),
            retries_rate_limit: AtomicUsize::new(0),
            rate_limit_wait_secs: AtomicU64::new(0),
            expected_errors: AtomicUsize::new(0),
            unexpected_errors: AtomicUsize::new(0),
            first_request_at: Mutex::new(None),
            last_request_at: Mutex::new(None),
            condition_checks: DashMap::new(),
            prereq_rechecks_triggered: AtomicUsize::new(0),
            http_latency_sum_ms: AtomicU64::new(0),
            http_latency_max_ms: AtomicU64::new(0),
            http_latency_count: AtomicU64::new(0),
            upstream_error_codes: DashMap::new(),
            unexpected_responses_by_status: DashMap::new(),
            pages_followed: AtomicUsize::new(0),
            child_urls_generated: AtomicUsize::new(0),
            lost_data_by_code: DashMap::new(),
        }
    }
}

impl ConditionStats {
    fn new() -> Self {
        Self {
            checks: AtomicUsize::new(0),
            true_count: AtomicUsize::new(0),
            false_count: AtomicUsize::new(0),
        }
    }

    fn record(&self, result: bool) {
        self.checks.fetch_add(1, Ordering::Relaxed);
        if result {
            self.true_count.fetch_add(1, Ordering::Relaxed);
        } else {
            self.false_count.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn api_key(service: &str, api: &str) -> String {
    format!("{service}/{api}")
}

impl Stats {
    pub fn new() -> Self {
        Self {
            apis: DashMap::new(),
            services: DashMap::new(),
            conditions: DashMap::new(),
            prereq_rechecks: DashMap::new(),
            started_at: Mutex::new(Utc::now()),
            ended_at: Mutex::new(None),
        }
    }

    /// Mark the effective start of the dump (called by the orchestrator just
    /// before request dispatch begins so the duration excludes auth/prereqs).
    pub fn mark_started(&self, started_at: DateTime<Utc>) {
        if let Ok(mut s) = self.started_at.lock() {
            *s = started_at;
        }
    }

    fn touch_timestamps(api: &ApiStats, now: DateTime<Utc>) {
        if let Ok(mut first) = api.first_request_at.lock()
            && first.is_none()
        {
            *first = Some(now);
        }
        if let Ok(mut last) = api.last_request_at.lock() {
            *last = Some(now);
        }
    }

    fn with_api<F: FnOnce(&ApiStats)>(&self, service: &str, api: &str, f: F) {
        let key = api_key(service, api);
        let entry = self
            .apis
            .entry(key)
            .or_insert_with(|| ApiStats::new(service, api));
        f(entry.value());
    }

    fn with_service<F: FnOnce(&ServiceStats)>(&self, service: &str, f: F) {
        let entry = self
            .services
            .entry(service.to_string())
            .or_insert_with(ServiceStats::new);
        f(entry.value());
    }

    /// Record one non-batch HTTP request being sent for `(service, api)`.
    pub fn record_single_dispatch(&self, service: &str, api: &str) {
        let now = Utc::now();
        self.with_api(service, api, |stats| {
            stats.requests_sent.fetch_add(1, Ordering::Relaxed);
            stats.http_single_calls.fetch_add(1, Ordering::Relaxed);
            Self::touch_timestamps(stats, now);
        });
        self.with_service(service, |svc| {
            svc.http_single_calls.fetch_add(1, Ordering::Relaxed);
        });
    }

    /// Record one HTTP batch call dispatched. `service` identifies the service
    /// the wrapper request targets (Graph and Resources batches are always
    /// single-service); `batch_apis` enumerates the `(service, api)` pairs of
    /// the inner sub-requests. `requests_sent` is incremented for each sub-URL;
    /// per-API `http_batch_calls` is incremented once per unique API present in
    /// the batch; service-level `http_batch_calls` is incremented exactly once
    /// — even if the sub-URL list happens to be empty.
    pub fn record_batch_dispatch<I>(&self, service: &str, batch_apis: I)
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let now = Utc::now();
        let pairs: Vec<(String, String)> = batch_apis.into_iter().collect();
        for (svc, api) in &pairs {
            self.with_api(svc, api, |stats| {
                stats.requests_sent.fetch_add(1, Ordering::Relaxed);
                Self::touch_timestamps(stats, now);
            });
        }
        let mut seen: HashSet<(String, String)> = HashSet::new();
        for (svc, api) in &pairs {
            if seen.insert((svc.clone(), api.clone())) {
                self.with_api(svc, api, |stats| {
                    stats.http_batch_calls.fetch_add(1, Ordering::Relaxed);
                });
            }
        }
        self.with_service(service, |svc| {
            svc.http_batch_calls.fetch_add(1, Ordering::Relaxed);
            svc.batch_subrequests_total
                .fetch_add(pairs.len(), Ordering::Relaxed);
        });
    }

    /// Record an HTTP-call-level network failure (one per failed request).
    /// Use this in addition to per-API `record_network_error` so the summary
    /// reflects the count of actual TCP/JSON failures, not the attribution.
    pub fn record_http_call_failure(&self, service: &str) {
        self.with_service(service, |svc| {
            svc.http_call_failures.fetch_add(1, Ordering::Relaxed);
        });
    }

    /// Record a single HTTP response (or batch sub-response) being received.
    pub fn record_response(&self, service: &str, api: &str, status: u16, is_expected: bool) {
        self.with_api(service, api, |stats| {
            let entry = stats
                .responses_by_status
                .entry(status)
                .or_insert_with(|| AtomicUsize::new(0));
            entry.value().fetch_add(1, Ordering::Relaxed);
            if status >= 400 && status != 429 {
                if is_expected {
                    stats.expected_errors.fetch_add(1, Ordering::Relaxed);
                } else {
                    stats.unexpected_errors.fetch_add(1, Ordering::Relaxed);
                    let uentry = stats
                        .unexpected_responses_by_status
                        .entry(status)
                        .or_insert_with(|| AtomicUsize::new(0));
                    uentry.value().fetch_add(1, Ordering::Relaxed);
                }
            }
        });
    }

    /// Record an upstream error code (e.g. "UnknownError", "Forbidden") for a
    /// failed response. The code helps the inspect view show *why* an API is
    /// problematic, not just *that* it is.
    pub fn record_upstream_error_code(&self, service: &str, api: &str, code: &str) {
        if code.is_empty() {
            return;
        }
        self.with_api(service, api, |stats| {
            let entry = stats
                .upstream_error_codes
                .entry(code.to_string())
                .or_insert_with(|| AtomicUsize::new(0));
            entry.value().fetch_add(1, Ordering::Relaxed);
        });
    }

    /// Record a *lost-data* failure for `(service, api)`: a `DumpError` that
    /// never produced an HTTP status (`status == 0`, `expected == false`), keyed
    /// by its `code` (`UrlRetryLimit`, `NoTokenForApiCall`, …). Called once per
    /// persisted error at the `write_dump_error` chokepoint. Feeds the
    /// end-of-collection "PARTIAL COLLECTION" summary; not in `stats.json`.
    pub fn record_lost_data(&self, service: &str, api: &str, code: &str) {
        if code.is_empty() {
            return;
        }
        self.with_api(service, api, |stats| {
            let entry = stats
                .lost_data_by_code
                .entry(code.to_string())
                .or_insert_with(|| AtomicUsize::new(0));
            entry.value().fetch_add(1, Ordering::Relaxed);
        });
    }

    /// Returns the total number of lost-data failures for `(service, api)` and
    /// the dominant code, or `None` when the API collected cleanly. Used by the
    /// end-of-collection summary to flag APIs whose data is (partly) missing.
    pub fn lost_data_summary(&self, service: &str, api: &str) -> Option<(usize, String)> {
        let key = api_key(service, api);
        let entry = self.apis.get(&key)?;
        let codes = &entry.value().lost_data_by_code;
        if codes.is_empty() {
            return None;
        }
        let mut total = 0usize;
        let mut dominant: Option<(String, usize)> = None;
        for r in codes.iter() {
            let n = r.value().load(Ordering::Relaxed);
            total += n;
            // Highest count wins; ties break on the lexicographically smallest
            // code so the displayed reason is stable across runs (DashMap
            // iteration order is non-deterministic).
            match &dominant {
                Some((best_code, best_n))
                    if *best_n > n || (*best_n == n && best_code.as_str() <= r.key().as_str()) => {}
                _ => dominant = Some((r.key().clone(), n)),
            }
        }
        dominant.map(|(code, _)| (total, code))
    }

    /// Record a network/JSON error before the HTTP layer produced a status.
    pub fn record_network_error(&self, service: &str, api: &str) {
        self.with_api(service, api, |stats| {
            stats.network_errors.fetch_add(1, Ordering::Relaxed);
        });
    }

    /// Record a non-429 retry attempt against `(service, api)`.
    pub fn record_retry(&self, service: &str, api: &str) {
        self.with_api(service, api, |stats| {
            stats.retries_real.fetch_add(1, Ordering::Relaxed);
        });
    }

    /// Record a 429-induced retry and accumulate the Retry-After delay.
    pub fn record_rate_limit_retry(&self, service: &str, api: &str, wait_secs: u64) {
        self.with_api(service, api, |stats| {
            stats.retries_rate_limit.fetch_add(1, Ordering::Relaxed);
            stats
                .rate_limit_wait_secs
                .fetch_add(wait_secs, Ordering::Relaxed);
        });
    }

    /// Record one pagination follow-up for `(service, api)`: a next-page URL was
    /// generated (`@odata.nextLink` or ARG `$skipToken`). Counts pages beyond the
    /// first; both pagination mechanisms flow through `handle_next_link`.
    pub fn record_page_followed(&self, service: &str, api: &str) {
        self.with_api(service, api, |stats| {
            stats.pages_followed.fetch_add(1, Ordering::Relaxed);
        });
    }

    /// Record `n` relationship child URLs generated from `(service, api)`'s
    /// response objects (request fan-out). No-op for `n == 0` so an endpoint whose
    /// children were all filtered out by conditions is not credited with fan-out.
    pub fn record_child_urls_generated(&self, service: &str, api: &str, n: usize) {
        if n == 0 {
            return;
        }
        self.with_api(service, api, |stats| {
            stats.child_urls_generated.fetch_add(n, Ordering::Relaxed);
        });
    }

    /// Record one HTTP round-trip latency (ms). Always counts at the service level;
    /// `api` is `Some` only for single (non-batch) calls, where per-endpoint latency
    /// is meaningful (a batch envelope's latency cannot be attributed to one sub-URL).
    pub fn record_http_latency(&self, service: &str, api: Option<&str>, elapsed_ms: u64) {
        self.with_service(service, |svc| {
            svc.http_latency_sum_ms
                .fetch_add(elapsed_ms, Ordering::Relaxed);
            svc.http_latency_max_ms
                .fetch_max(elapsed_ms, Ordering::Relaxed);
            svc.http_latency_count.fetch_add(1, Ordering::Relaxed);
        });
        if let Some(api) = api {
            self.with_api(service, api, |stats| {
                stats
                    .http_latency_sum_ms
                    .fetch_add(elapsed_ms, Ordering::Relaxed);
                stats
                    .http_latency_max_ms
                    .fetch_max(elapsed_ms, Ordering::Relaxed);
                stats.http_latency_count.fetch_add(1, Ordering::Relaxed);
            });
        }
    }

    /// Record the provenance of the `Retry-After` carried by a 429 for `service`:
    /// `Some(secs)` = the server provided a usable value (count it, track the max);
    /// `None` = the configured default cooldown had to be applied. Called from the
    /// single 429 site, so single, batch-envelope, and batch sub-429s are all covered.
    pub fn record_retry_after_provenance(&self, service: &str, retry_after: Option<u64>) {
        self.with_service(service, |svc| match retry_after {
            Some(secs) => {
                svc.retry_after_server_count.fetch_add(1, Ordering::Relaxed);
                svc.retry_after_max_secs.fetch_max(secs, Ordering::Relaxed);
            }
            None => {
                svc.retry_after_default_count
                    .fetch_add(1, Ordering::Relaxed);
            }
        });
    }

    /// Record one evaluation of `condition`. `attribution` attaches the
    /// evaluation to a specific API when known.
    pub fn record_condition_check(
        &self,
        condition: &str,
        result: bool,
        attribution: Option<(&str, &str)>,
    ) {
        let entry = self
            .conditions
            .entry(condition.to_string())
            .or_insert_with(ConditionStats::new);
        entry.value().record(result);

        if let Some((service, api)) = attribution {
            self.with_api(service, api, |stats| {
                let entry = stats
                    .condition_checks
                    .entry(condition.to_string())
                    .or_insert_with(ConditionStats::new);
                entry.value().record(result);
            });
        }
    }

    /// Record that a prerequisite re-check was spawned for `service`.
    pub fn record_prereq_recheck(&self, service: &str) {
        let entry = self
            .prereq_rechecks
            .entry(service.to_string())
            .or_insert_with(|| AtomicUsize::new(0));
        entry.value().fetch_add(1, Ordering::Relaxed);
    }

    /// Record that an URL of `(service, api)` triggered a prereq re-check.
    pub fn record_prereq_trigger(&self, service: &str, api: &str) {
        self.with_api(service, api, |stats| {
            stats
                .prereq_rechecks_triggered
                .fetch_add(1, Ordering::Relaxed);
        });
    }

    /// Returns the HTTP status code that appears most often among *unexpected*
    /// errors for `(service, api)`. Used by the post-collection summary to show
    /// the dominant failure mode per API (e.g. "403 Forbidden (2 occurrences)").
    pub fn dominant_unexpected_status(&self, service: &str, api: &str) -> Option<u16> {
        let key = api_key(service, api);
        let entry = self.apis.get(&key)?;
        let codes = &entry.value().unexpected_responses_by_status;
        codes
            .iter()
            .map(|r| (*r.key(), r.value().load(Ordering::Relaxed)))
            .max_by_key(|(_, count)| *count)
            .map(|(status, _)| status)
    }

    /// Returns the most frequent upstream error code observed on
    /// `(service, api)`, ignoring the synthetic `UrlRetryLimit` marker that
    /// records the give-up event itself. Used to compose a human message when
    /// a URL exhausts its retry budget — so callers can say *why* the endpoint
    /// failed every time, not just that it did.
    pub fn dominant_upstream_code(&self, service: &str, api: &str) -> Option<String> {
        let key = api_key(service, api);
        let entry = self.apis.get(&key)?;
        let codes = &entry.value().upstream_error_codes;
        codes
            .iter()
            .filter(|r| r.key() != "UrlRetryLimit")
            .map(|r| (r.key().clone(), r.value().load(Ordering::Relaxed)))
            .max_by_key(|(_, count)| *count)
            .map(|(code, _)| code)
    }

    pub fn finalize(&self, ended_at: DateTime<Utc>) {
        if let Ok(mut e) = self.ended_at.lock() {
            *e = Some(ended_at);
        }
    }

    /// Serialize to `stats.json` at the archive root.
    pub async fn write(&self, writer: &WriterHandle) -> Result<(), Error> {
        let stats_str = match serde_json::to_string(self) {
            Err(err) => {
                error!("{:FL$}Could not convert stats to json", "Stats");
                debug!("{:FL$}Stats serialization error: {err:?}", "Stats");
                return Err(Error::StatsToJSON);
            }
            Ok(j) => j,
        };
        writer
            .write_file(String::new(), "stats.json".to_string(), stats_str)
            .await?;
        Ok(())
    }
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

fn fmt_time(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

impl Serialize for Stats {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let started_at = self
            .started_at
            .lock()
            .ok()
            .map(|g| *g)
            .unwrap_or_else(Utc::now);
        let ended_at = self.ended_at.lock().ok().and_then(|g| *g);
        let duration_seconds = ended_at.map(|e| (e - started_at).num_seconds().max(0));

        let mut map = serializer.serialize_map(Some(8))?;
        map.serialize_entry("started_at", &fmt_time(started_at))?;
        map.serialize_entry("ended_at", &ended_at.map(fmt_time))?;
        map.serialize_entry("duration_seconds", &duration_seconds)?;

        let mut service_keys: Vec<String> = self.services.iter().map(|r| r.key().clone()).collect();
        service_keys.sort();
        map.serialize_entry("services", &ServicesMap(self, &service_keys))?;

        let mut api_keys: Vec<String> = self.apis.iter().map(|r| r.key().clone()).collect();
        api_keys.sort();
        map.serialize_entry("apis", &ApisSeq(self, &api_keys))?;

        let mut cond_keys: Vec<String> = self.conditions.iter().map(|r| r.key().clone()).collect();
        cond_keys.sort();
        map.serialize_entry("conditions", &ConditionsSeq(&self.conditions, &cond_keys))?;

        let mut prereq_keys: Vec<String> = self
            .prereq_rechecks
            .iter()
            .map(|r| r.key().clone())
            .collect();
        prereq_keys.sort();
        map.serialize_entry("prereq_rechecks", &PrereqMap(self, &prereq_keys))?;

        map.end()
    }
}

struct ServicesMap<'a>(&'a Stats, &'a [String]);

impl Serialize for ServicesMap<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.1.len()))?;
        for svc in self.1 {
            if let Some(entry) = self.0.services.get(svc) {
                map.serialize_entry(svc, &ServiceStatsView(entry.value()))?;
            }
        }
        map.end()
    }
}

struct ServiceStatsView<'a>(&'a ServiceStats);

impl Serialize for ServiceStatsView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(10))?;
        map.serialize_entry(
            "http_batch_calls",
            &self.0.http_batch_calls.load(Ordering::Relaxed),
        )?;
        map.serialize_entry(
            "http_single_calls",
            &self.0.http_single_calls.load(Ordering::Relaxed),
        )?;
        map.serialize_entry(
            "http_call_failures",
            &self.0.http_call_failures.load(Ordering::Relaxed),
        )?;
        map.serialize_entry(
            "http_latency_sum_ms",
            &self.0.http_latency_sum_ms.load(Ordering::Relaxed),
        )?;
        map.serialize_entry(
            "http_latency_max_ms",
            &self.0.http_latency_max_ms.load(Ordering::Relaxed),
        )?;
        map.serialize_entry(
            "http_latency_count",
            &self.0.http_latency_count.load(Ordering::Relaxed),
        )?;
        map.serialize_entry(
            "retry_after_server_count",
            &self.0.retry_after_server_count.load(Ordering::Relaxed),
        )?;
        map.serialize_entry(
            "retry_after_default_count",
            &self.0.retry_after_default_count.load(Ordering::Relaxed),
        )?;
        map.serialize_entry(
            "retry_after_max_secs",
            &self.0.retry_after_max_secs.load(Ordering::Relaxed),
        )?;
        map.serialize_entry(
            "batch_subrequests_total",
            &self.0.batch_subrequests_total.load(Ordering::Relaxed),
        )?;
        map.end()
    }
}

struct ApisSeq<'a>(&'a Stats, &'a [String]);

impl Serialize for ApisSeq<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.1.len()))?;
        for key in self.1 {
            if let Some(entry) = self.0.apis.get(key) {
                seq.serialize_element(&ApiStatsView(entry.value()))?;
            }
        }
        seq.end()
    }
}

struct ApiStatsView<'a>(&'a ApiStats);

impl Serialize for ApiStatsView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let a = self.0;
        let first = a.first_request_at.lock().ok().and_then(|g| *g);
        let last = a.last_request_at.lock().ok().and_then(|g| *g);
        let mut status_keys: Vec<u16> = a.responses_by_status.iter().map(|r| *r.key()).collect();
        status_keys.sort();
        let mut cond_keys: Vec<String> =
            a.condition_checks.iter().map(|r| r.key().clone()).collect();
        cond_keys.sort();

        let mut map = serializer.serialize_map(Some(23))?;
        map.serialize_entry("service", &a.service)?;
        map.serialize_entry("api", &a.api)?;
        map.serialize_entry("requests_sent", &a.requests_sent.load(Ordering::Relaxed))?;
        map.serialize_entry(
            "http_batch_calls",
            &a.http_batch_calls.load(Ordering::Relaxed),
        )?;
        map.serialize_entry(
            "http_single_calls",
            &a.http_single_calls.load(Ordering::Relaxed),
        )?;
        map.serialize_entry("first_request_at", &first.map(fmt_time))?;
        map.serialize_entry("last_request_at", &last.map(fmt_time))?;
        map.serialize_entry(
            "responses_by_status",
            &StatusMap(&a.responses_by_status, &status_keys),
        )?;
        map.serialize_entry(
            "expected_errors",
            &a.expected_errors.load(Ordering::Relaxed),
        )?;
        map.serialize_entry(
            "unexpected_errors",
            &a.unexpected_errors.load(Ordering::Relaxed),
        )?;
        map.serialize_entry("network_errors", &a.network_errors.load(Ordering::Relaxed))?;
        map.serialize_entry("retries_real", &a.retries_real.load(Ordering::Relaxed))?;
        map.serialize_entry(
            "retries_rate_limit",
            &a.retries_rate_limit.load(Ordering::Relaxed),
        )?;
        map.serialize_entry(
            "rate_limit_wait_secs",
            &a.rate_limit_wait_secs.load(Ordering::Relaxed),
        )?;
        map.serialize_entry(
            "prereq_rechecks_triggered",
            &a.prereq_rechecks_triggered.load(Ordering::Relaxed),
        )?;
        map.serialize_entry(
            "http_latency_sum_ms",
            &a.http_latency_sum_ms.load(Ordering::Relaxed),
        )?;
        map.serialize_entry(
            "http_latency_max_ms",
            &a.http_latency_max_ms.load(Ordering::Relaxed),
        )?;
        map.serialize_entry(
            "http_latency_count",
            &a.http_latency_count.load(Ordering::Relaxed),
        )?;
        map.serialize_entry(
            "condition_checks",
            &ConditionsSeq(&a.condition_checks, &cond_keys),
        )?;
        let mut code_keys: Vec<String> = a
            .upstream_error_codes
            .iter()
            .map(|r| r.key().clone())
            .collect();
        code_keys.sort();
        map.serialize_entry(
            "upstream_error_codes",
            &CountMap(&a.upstream_error_codes, &code_keys),
        )?;
        let mut unexpected_status_keys: Vec<u16> = a
            .unexpected_responses_by_status
            .iter()
            .map(|r| *r.key())
            .collect();
        unexpected_status_keys.sort();
        map.serialize_entry(
            "unexpected_responses_by_status",
            &StatusMap(&a.unexpected_responses_by_status, &unexpected_status_keys),
        )?;
        map.serialize_entry("pages_followed", &a.pages_followed.load(Ordering::Relaxed))?;
        map.serialize_entry(
            "child_urls_generated",
            &a.child_urls_generated.load(Ordering::Relaxed),
        )?;
        map.end()
    }
}

struct CountMap<'a>(&'a DashMap<String, AtomicUsize>, &'a [String]);

impl Serialize for CountMap<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.1.len()))?;
        for k in self.1 {
            if let Some(entry) = self.0.get(k) {
                map.serialize_entry(k, &entry.value().load(Ordering::Relaxed))?;
            }
        }
        map.end()
    }
}

struct StatusMap<'a>(&'a DashMap<u16, AtomicUsize>, &'a [u16]);

impl Serialize for StatusMap<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.1.len()))?;
        for status in self.1 {
            if let Some(entry) = self.0.get(status) {
                map.serialize_entry(&status.to_string(), &entry.value().load(Ordering::Relaxed))?;
            }
        }
        map.end()
    }
}

struct ConditionsSeq<'a>(&'a DashMap<String, ConditionStats>, &'a [String]);

impl Serialize for ConditionsSeq<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.1.len()))?;
        for name in self.1 {
            if let Some(entry) = self.0.get(name) {
                seq.serialize_element(&ConditionView(name, entry.value()))?;
            }
        }
        seq.end()
    }
}

struct ConditionView<'a>(&'a str, &'a ConditionStats);

impl Serialize for ConditionView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry("name", self.0)?;
        map.serialize_entry("checks", &self.1.checks.load(Ordering::Relaxed))?;
        map.serialize_entry("true_count", &self.1.true_count.load(Ordering::Relaxed))?;
        map.serialize_entry("false_count", &self.1.false_count.load(Ordering::Relaxed))?;
        map.end()
    }
}

struct PrereqMap<'a>(&'a Stats, &'a [String]);

impl Serialize for PrereqMap<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.1.len()))?;
        for svc in self.1 {
            if let Some(entry) = self.0.prereq_rechecks.get(svc) {
                map.serialize_entry(svc, &entry.value().load(Ordering::Relaxed))?;
            }
        }
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_stats() -> Stats {
        Stats::new()
    }

    #[test]
    fn test_unexpected_responses_by_status_populated_on_unexpected_error() {
        let stats = make_stats();
        stats.record_response("graph", "users", 403, false);
        stats.record_response("graph", "users", 403, false);
        stats.record_response("graph", "users", 404, true); // expected — must NOT appear

        let key = api_key("graph", "users");
        let entry = stats.apis.get(&key).expect("entry should exist");
        let unexpected_by_status = &entry.value().unexpected_responses_by_status;

        let count_403 = unexpected_by_status
            .get(&403)
            .map(|v| v.load(Ordering::Relaxed))
            .unwrap_or(0);
        let count_404 = unexpected_by_status
            .get(&404)
            .map(|v| v.load(Ordering::Relaxed))
            .unwrap_or(0);

        assert_eq!(count_403, 2, "unexpected 403s should be tracked");
        assert_eq!(
            count_404, 0,
            "expected 404 must not appear in unexpected_by_status"
        );
    }

    #[test]
    fn test_dominant_unexpected_status_returns_most_frequent() {
        let stats = make_stats();
        stats.record_response("graph", "groups", 403, false);
        stats.record_response("graph", "groups", 403, false);
        stats.record_response("graph", "groups", 500, false);

        let dominant = stats.dominant_unexpected_status("graph", "groups");
        assert_eq!(dominant, Some(403));
    }

    #[test]
    fn test_dominant_unexpected_status_none_when_only_expected() {
        let stats = make_stats();
        stats.record_response("graph", "policies", 404, true);
        stats.record_response("graph", "policies", 404, true);

        let dominant = stats.dominant_unexpected_status("graph", "policies");
        assert_eq!(dominant, None);
    }

    #[test]
    fn test_dominant_unexpected_status_none_for_unknown_api() {
        let stats = make_stats();
        assert_eq!(
            stats.dominant_unexpected_status("graph", "nonexistent"),
            None
        );
    }

    #[test]
    fn test_unexpected_errors_counter_unchanged_for_expected() {
        let stats = make_stats();
        stats.record_response("resources", "roleAssignments", 403, true);
        stats.record_response("resources", "roleAssignments", 403, false);

        let key = api_key("resources", "roleAssignments");
        let entry = stats.apis.get(&key).unwrap();
        assert_eq!(entry.expected_errors.load(Ordering::Relaxed), 1);
        assert_eq!(entry.unexpected_errors.load(Ordering::Relaxed), 1);
    }
}
