use crate::FL;
use crate::collect::dump::request::BackoffGuard;

use dashmap::DashMap;
use log::{debug, trace};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::time::{Duration, Instant, sleep};

/// Hard upper bound (seconds) on a single 429 cooldown when no per-service
/// `rateLimitMaxWaitSecs` is configured (the `new` / `Default` path, used by
/// tests). Mirrors the `rateLimitMaxWaitSecs` config default so a pathological
/// or hostile `Retry-After` (e.g. an HTTP-date far in the future, or
/// `u64::MAX`) cannot freeze a whole service for hours or overflow the
/// `Instant + Duration` addition in `report_429`.
const DEFAULT_MAX_RETRY_AFTER_SECS: u64 = 900;

/// Absolute cap (milliseconds) on the forward jitter added to a 429 cooldown.
///
/// Once a worker holds its concurrency slot before waiting (see
/// `request::thread`), the at-most-`window` workers parked on a shared cooldown
/// all wake at the same `next_allowed_request`; firing in lockstep re-triggers
/// the throttle and stops the AIMD window from re-ramping. A *forward* jitter
/// (never earlier — that would 429 immediately) spread proportionally to the
/// cooldown thins that wake-up wave. Capped here (and by the headroom to the
/// service's `rateLimitMaxWaitSecs`) so it cannot push the sleep meaningfully
/// past `stallDetectionTimeout`. A few seconds is enough to decluster a window
/// of requests without materially extending a short storm cooldown.
const MAX_COOLDOWN_JITTER_MS: u64 = 2000;

/// Manages rate limiting for different services.
///
/// It tracks the next allowed request time for each service to avoid sending
/// requests too frequently after receiving a 429 (Too Many Requests) response.
///
/// Each service has its own fallback Retry-After value: the global default
/// covers any service not explicitly overridden, and per-service overrides
/// from the XML config let `resources` use a longer back-off than `graph`
/// without inflating the global default.
pub struct RateLimitManager {
    limits: Arc<DashMap<String, ServiceLimit>>,
    default_retry_after: u64,
    /// Per-service fallback Retry-After (seconds) for 429 responses that come
    /// back without an explicit `Retry-After` header. Services not in the map
    /// use `default_retry_after`.
    per_service_default: HashMap<String, u64>,
    /// Global upper bound (seconds) clamping any single 429 cooldown. A
    /// server-provided `Retry-After` larger than this is capped, so one
    /// response cannot freeze a service indefinitely (or overflow `Instant`).
    max_wait_secs: u64,
    /// Per-service override of `max_wait_secs` (the service's
    /// `rateLimitMaxWaitSecs`). Services not in the map use `max_wait_secs`.
    per_service_max_wait: HashMap<String, u64>,
}

/// State for a single service's rate limit.
struct ServiceLimit {
    /// The earliest time the next request to this service can be sent.
    next_allowed_request: Instant,
    /// Total nanoseconds this service spent under an **active** 429 cooldown,
    /// measured on a **single coalesced timeline** (the union of all
    /// `[now, next_allowed]` intervals set by `report_429`), not summed
    /// per-429. This is the telemetry denominator: compared against the
    /// per-API *intended* cooldown sum (`Stats::rate_limit_wait_secs`, which
    /// adds every 429's Retry-After), the ratio intended/active measures how
    /// many concurrent 429s piled onto the same cooldown window — i.e. how much
    /// the cooldown was bypassed under concurrency (observed in the thousands). When
    /// the cooldown is honored, the floor is **not 1** but the in-flight
    /// concurrency at the moment the window opens (≈ the AIMD window): those
    /// already-dispatched requests still 429 into the one window, so a fully
    /// honored ratio is single-digit / order of the effective window, dropping
    /// to ~1 only if AIMD collapses the window toward 1. Surfaced in
    /// `metadata.json` as `cooldown_active_secs_by_service`.
    cooldown_active_nanos: AtomicU64,
}

impl RateLimitManager {
    /// Creates a new `RateLimitManager` with a single global Retry-After fallback.
    ///
    /// The cooldown cap defaults to [`DEFAULT_MAX_RETRY_AFTER_SECS`]; use
    /// [`with_per_service_defaults`](Self::with_per_service_defaults) to wire the
    /// configured `rateLimitMaxWaitSecs` bounds.
    pub fn new(default_retry_after: u64) -> Self {
        Self {
            limits: Arc::new(DashMap::new()),
            default_retry_after,
            per_service_default: HashMap::new(),
            max_wait_secs: DEFAULT_MAX_RETRY_AFTER_SECS,
            per_service_max_wait: HashMap::new(),
        }
    }

    /// Creates a new `RateLimitManager` with per-service Retry-After fallbacks
    /// and per-service cooldown caps (`rateLimitMaxWaitSecs`).
    pub fn with_per_service_defaults(
        default_retry_after: u64,
        per_service_default: HashMap<String, u64>,
        max_wait_secs: u64,
        per_service_max_wait: HashMap<String, u64>,
    ) -> Self {
        Self {
            limits: Arc::new(DashMap::new()),
            default_retry_after,
            per_service_default,
            max_wait_secs,
            per_service_max_wait,
        }
    }

    fn default_for(&self, service: &str) -> u64 {
        self.per_service_default
            .get(service)
            .copied()
            .unwrap_or(self.default_retry_after)
    }

    /// Upper bound (seconds) on a single cooldown for `service`: its
    /// `rateLimitMaxWaitSecs` override when present, else the global cap.
    fn max_wait_for(&self, service: &str) -> u64 {
        self.per_service_max_wait
            .get(service)
            .copied()
            .unwrap_or(self.max_wait_secs)
    }

    /// Blocks until it is allowed to make a request to the specified service.
    ///
    /// **Loops, re-reading `next_allowed_request` each pass**: a 429 that lands
    /// while this task is asleep pushes the cooldown forward, and the re-read
    /// honours the freshest value instead of firing stale. The caller MUST
    /// already hold the service's concurrency slot (see `request::thread`), so
    /// at most `window` tasks wait here per service — that bound *is* the
    /// per-cooldown pacing. Without the loop, a worker that slept once would
    /// fire the moment its slot was granted even if a newer 429 had since
    /// re-armed the cooldown — the 429-storm bypass this guards against. The
    /// loop terminates because, with every slot held by a waiter, no new request
    /// can fire to extend the cooldown, so `next_allowed_request` stops moving
    /// and the next re-read falls through. Under a service throttled without
    /// let-up the cooldown can be re-extended **more than `window` times** —
    /// a worker that fires, 429s and releases its slot lets a fresh worker take
    /// the slot and 429 again — so a single park is *not* bounded by `window`.
    /// It ends when the service's other throttled URLs are abandoned by the
    /// per-bucket **liveness ceiling** (`Stats`, `livenessCeilingSecs`) and stop
    /// firing — that ceiling is what guarantees the bucket eventually drains or
    /// is dropped.
    /// Long individual parks in such a pathological run are expected; the
    /// coordinator's stall watchdog (which logs and continues, never aborts) is
    /// the outer safety net.
    pub async fn wait_if_needed(&self, service: &str) {
        loop {
            let duration = match self.limits.get(service) {
                Some(limit) => {
                    let now = Instant::now();
                    if limit.next_allowed_request > now {
                        limit.next_allowed_request - now
                    } else {
                        return;
                    }
                }
                None => return,
            };

            // Proportional *forward* jitter to desynchronise the workers that
            // wake together when a shared cooldown expires. Spread forward only
            // (never before the cooldown ends) and capped both absolutely
            // (`MAX_COOLDOWN_JITTER_MS`) and by the headroom to the service's
            // `rateLimitMaxWaitSecs`, so a near-max cooldown can't push the sleep
            // past `stallDetectionTimeout` (kept ≥ that cap by config advice).
            let duration_ms = duration.as_millis().min(u64::MAX as u128) as u64;
            let headroom_ms = self
                .max_wait_for(service)
                .saturating_mul(1000)
                .saturating_sub(duration_ms);
            let jitter_ceiling_ms = (duration_ms / 2)
                .min(MAX_COOLDOWN_JITTER_MS)
                .min(headroom_ms);
            let jitter =
                Duration::from_millis((rand::random::<f64>() * jitter_ceiling_ms as f64) as u64);
            let total = duration + jitter;
            if total >= Duration::from_secs(1) {
                debug!(
                    "{:FL$}Rate-limit cooldown {}ms for service {:?}",
                    "RateLimitManager",
                    total.as_millis(),
                    service
                );
            } else {
                trace!(
                    "{:FL$}Rate-limit cooldown {}ms for service {:?}",
                    "RateLimitManager",
                    total.as_millis(),
                    service
                );
            }
            // A rate-limit cooldown is a form of backoff: surface it in the
            // BACKOFF_ACTIVE gauge (the progress UI's "Backoff: N") so the dominant
            // `resources` stall mode — waiting out a 429 Retry-After — is visible,
            // just like the per-request retry backoff already is. The guard
            // decrements the gauge when the sleep completes (or the task is dropped).
            // Now taken *after* the slot is acquired (see `request::thread`), so the
            // gauge reflects slot-holding waiters — the real per-cooldown pacing.
            let _backoff_guard = BackoffGuard::enter();
            sleep(total).await;
        }
    }

    /// Reports a 429 response and updates the next allowed request time.
    ///
    /// If `retry_after` is provided, it uses that value. Otherwise, it defaults
    /// to the per-service fallback if defined, else to the global default.
    pub fn report_429(&self, service: &str, retry_after: Option<u64>) {
        // `effective_retry_after` resolves the fallback AND clamps to the
        // per-service cap, so `now + Duration::from_secs(delay)` below can
        // neither freeze the service for hours nor overflow.
        let delay = self.effective_retry_after(service, retry_after);
        let now = Instant::now();
        let new_allowed = now + Duration::from_secs(delay);

        let mut limit = self
            .limits
            .entry(service.to_string())
            .or_insert(ServiceLimit {
                next_allowed_request: now,
                cooldown_active_nanos: AtomicU64::new(0),
            });

        if new_allowed > limit.next_allowed_request {
            // Telemetry: accumulate this 429's *incremental* contribution to
            // the single coalesced cooldown timeline — the slice of
            // [now, new_allowed] not already covered by the prior window
            // [_, next_allowed_request]. The per-entry guard makes the window
            // **monotonically extend** under concurrency (the `>` check + the
            // write are atomic per service), so summing these slices yields the
            // union length with no segment bookkeeping. `now` is sampled before
            // the guard, so two concurrent calls may apply slightly out of
            // `now`-order — this can only *under*-count by the sub-millisecond
            // inter-sample jitter (negligible at second resolution), never
            // double-count.
            let lower = limit.next_allowed_request.max(now);
            let added = new_allowed.saturating_duration_since(lower);
            limit.cooldown_active_nanos.fetch_add(
                added.as_nanos().min(u64::MAX as u128) as u64,
                Ordering::Relaxed,
            );
            limit.next_allowed_request = new_allowed;
            debug!(
                "{:FL$}Rate-limit cooldown set to {}s for service {:?}",
                "RateLimitManager", delay, service
            );
        }
    }

    /// Resolve the effective cooldown (seconds) for a 429: the server-provided
    /// `retry_after` when present, else the per-service (or global) configured
    /// fallback, finally **clamped** to the service's `rateLimitMaxWaitSecs`
    /// cap. Centralises the "absent/unparseable Retry-After ⇒ configured
    /// default" rule so callers never pass `Some(0)` (which would defeat the
    /// fallback and disable the cooldown), and the upper clamp so a huge or
    /// hostile `Retry-After` cannot freeze the service or overflow `Instant`.
    pub fn effective_retry_after(&self, service: &str, retry_after: Option<u64>) -> u64 {
        let raw = retry_after.unwrap_or_else(|| self.default_for(service));
        let capped = raw.min(self.max_wait_for(service));
        if capped < raw {
            debug!(
                "{:FL$}Retry-After clamped from {}s to {}s for service {:?} (rateLimitMaxWaitSecs)",
                "RateLimitManager", raw, capped, service
            );
        }
        capped
    }

    /// Returns the wall-clock seconds each service spent under an **active** 429
    /// cooldown, measured on a **single coalesced timeline**, surfaced in
    /// `metadata.json` as `cooldown_active_secs_by_service`.
    /// Compared against the per-API intended cooldown sum
    /// (`Stats::rate_limit_wait_secs`), the intended/active ratio measures how
    /// many concurrent 429s piled onto the same window — the cooldown bypass
    /// signal (thousands ⇒ bypassed; single-digit / order of the effective AIMD
    /// window ⇒ honored).
    pub fn get_all_cooldown_active_secs(&self) -> HashMap<String, u64> {
        self.limits
            .iter()
            .map(|r| {
                (
                    r.key().clone(),
                    r.value().cooldown_active_nanos.load(Ordering::Relaxed) / 1_000_000_000,
                )
            })
            .collect()
    }
}

impl Default for RateLimitManager {
    fn default() -> Self {
        Self::new(5)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{advance, pause};

    /// `get_all_cooldown_active_secs` measures the cooldown timeline on a
    /// single **coalesced** axis. Covers all three interval-union cases:
    /// subsumed (adds 0), overlap-extend (adds only the incremental slice), and
    /// a fresh window after a gap (adds a full segment).
    #[tokio::test]
    async fn test_cooldown_active_secs_is_single_timeline() {
        pause();
        let manager = RateLimitManager::new(5);
        let active = |svc: &str| {
            manager
                .get_all_cooldown_active_secs()
                .get(svc)
                .copied()
                .unwrap_or(0)
        };

        // A service never throttled is absent from the map.
        assert!(!manager.get_all_cooldown_active_secs().contains_key("graph"));

        // t=0: first 429 opens a 60s window → 60s active. A second 429 with a
        // SMALLER delay is fully **subsumed** (30s < remaining 60s) → adds 0, not
        // another 60s. Summing would have given 90s.
        manager.report_429("graph", Some(60));
        manager.report_429("graph", Some(30));
        assert_eq!(active("graph"), 60, "subsumed 429 must add nothing");

        // t=30: advance into the middle of the open window, then a 429 whose own
        // window (30+60 = 90s) extends BEYOND the current end (60s). This is the
        // **overlap-extend** case — the headline behaviour — which must add only
        // the incremental slice (90−60 = 30s), NOT the full 60s (a sum) and NOT 0
        // (a max-only counter). → 90s total.
        advance(Duration::from_secs(30)).await;
        manager.report_429("graph", Some(60));
        assert_eq!(
            active("graph"),
            90,
            "overlap-extend must add only the new slice (90−60)"
        );

        // Wait the window out (advances to t=90), then a fresh 429 after the gap
        // opens a brand-new segment (+10s). → 100s total.
        manager.wait_if_needed("graph").await;
        manager.report_429("graph", Some(10));
        assert_eq!(
            active("graph"),
            100,
            "a 429 after the gap adds a full segment"
        );

        // A different service never throttled stays absent.
        assert!(
            !manager
                .get_all_cooldown_active_secs()
                .contains_key("resources")
        );
    }

    /// The keystone property of the loop: a 429 that lands **while a worker is
    /// already asleep** in `wait_if_needed` must be honoured — the worker
    /// re-reads `next_allowed_request` and keeps waiting rather than firing
    /// stale the moment its first sleep ends. This is exactly the 429-storm
    /// bypass the loop prevents: a single-sleep implementation would return at
    /// ~10s, ignoring the extension.
    #[tokio::test(start_paused = true)]
    async fn test_wait_if_needed_rehonors_extended_cooldown() {
        let manager = Arc::new(RateLimitManager::new(5));

        // Cooldown until t≈10s.
        manager.report_429("graph", Some(10));

        let m2 = Arc::clone(&manager);
        let waiter = tokio::spawn(async move {
            let start = Instant::now();
            m2.wait_if_needed("graph").await;
            start.elapsed()
        });

        // At t≈5s — mid first cooldown — extend it to t≈25s. The already-sleeping
        // waiter must pick this up on its re-read, not return at 10s.
        sleep(Duration::from_secs(5)).await;
        manager.report_429("graph", Some(20));

        let elapsed = waiter.await.expect("waiter task panicked");
        assert!(
            elapsed >= Duration::from_secs(25),
            "must re-honor the cooldown extended mid-sleep, returned after {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn test_report_429_takes_maximum() {
        pause();
        let manager = RateLimitManager::new(5);
        let service = "test_service";

        // Report 429 with 60s delay
        manager.report_429(service, Some(60));

        // Report 429 with 30s delay
        manager.report_429(service, Some(30));

        // The delay should be 60s, not 30s. wait_if_needed sleeps the cooldown
        // plus a forward jitter capped at MAX_COOLDOWN_JITTER_MS (2s), so the
        // elapsed time lands in [60s, 60s + cap].
        let start = Instant::now();
        manager.wait_if_needed(service).await;
        let elapsed = start.elapsed();

        assert!(elapsed >= Duration::from_secs(60));
        assert!(elapsed <= Duration::from_secs(60) + Duration::from_millis(MAX_COOLDOWN_JITTER_MS));
    }

    #[tokio::test]
    async fn test_report_429_default_delay() {
        pause();
        let manager = RateLimitManager::new(5);
        let service = "test_service";

        manager.report_429(service, None);

        let start = Instant::now();
        manager.wait_if_needed(service).await;
        let elapsed = start.elapsed();

        assert!(elapsed >= Duration::from_secs(2));
    }

    /// When `report_429` is called without an explicit `Retry-After`, the
    /// per-service fallback supersedes the global default — and services not
    /// listed in the map fall back to the global default.
    #[tokio::test]
    async fn test_report_429_per_service_default() {
        pause();
        let mut per_service: HashMap<String, u64> = HashMap::new();
        per_service.insert("resources".to_string(), 30);
        let manager =
            RateLimitManager::with_per_service_defaults(5, per_service, 900, HashMap::new());

        // resources uses its own 30s default.
        manager.report_429("resources", None);
        let start = Instant::now();
        manager.wait_if_needed("resources").await;
        assert!(start.elapsed() >= Duration::from_secs(30));

        // graph falls back to the global 5s default (plus the forward jitter,
        // capped at MAX_COOLDOWN_JITTER_MS).
        manager.report_429("graph", None);
        let start = Instant::now();
        manager.wait_if_needed("graph").await;
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_secs(5));
        assert!(elapsed <= Duration::from_secs(5) + Duration::from_millis(MAX_COOLDOWN_JITTER_MS));
    }

    /// A pathological `Retry-After` is clamped to the cooldown cap rather than
    /// freezing the service for hours — and `report_429(u64::MAX)` must not
    /// panic (the clamp prevents the `Instant + Duration::from_secs` overflow).
    #[test]
    fn test_huge_retry_after_is_clamped_to_cap() {
        let manager = RateLimitManager::new(5); // global cap = DEFAULT_MAX_RETRY_AFTER_SECS
        assert_eq!(
            manager.effective_retry_after("svc", Some(u64::MAX)),
            DEFAULT_MAX_RETRY_AFTER_SECS
        );
        assert_eq!(
            manager.effective_retry_after("svc", Some(86_400)),
            DEFAULT_MAX_RETRY_AFTER_SECS
        );
        // A value under the cap is returned unchanged.
        assert_eq!(manager.effective_retry_after("svc", Some(120)), 120);
        // The clamp also guards the cooldown arithmetic: a naive
        // `Instant + Duration::from_secs(u64::MAX)` would overflow, so
        // `report_429` with `u64::MAX` must not panic.
        manager.report_429("svc", Some(u64::MAX));
    }

    /// A per-service `rateLimitMaxWaitSecs` cap overrides the global cap.
    #[test]
    fn test_per_service_max_wait_overrides_global_cap() {
        let mut per_service_max: HashMap<String, u64> = HashMap::new();
        per_service_max.insert("resources".to_string(), 60);
        let manager =
            RateLimitManager::with_per_service_defaults(5, HashMap::new(), 900, per_service_max);
        // resources clamps to its own 60s cap; graph falls back to the global 900s.
        assert_eq!(manager.effective_retry_after("resources", Some(5_000)), 60);
        assert_eq!(manager.effective_retry_after("graph", Some(5_000)), 900);
    }
}
