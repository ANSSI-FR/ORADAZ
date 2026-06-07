use crate::FL;
use crate::collect::dump::request::BackoffGuard;

use dashmap::DashMap;
use log::{debug, trace};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::{Duration, Instant, sleep};

/// Hard upper bound (seconds) on a single 429 cooldown when no per-service
/// `rateLimitMaxWaitSecs` is configured (the `new` / `Default` path, used by
/// tests). Mirrors the `rateLimitMaxWaitSecs` config default so a pathological
/// or hostile `Retry-After` (e.g. an HTTP-date far in the future, or
/// `u64::MAX`) cannot freeze a whole service for hours or overflow the
/// `Instant + Duration` addition in `report_429`.
const DEFAULT_MAX_RETRY_AFTER_SECS: u64 = 900;

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
    pub async fn wait_if_needed(&self, service: &str) {
        let sleep_duration = {
            if let Some(limit) = self.limits.get(service) {
                let now = Instant::now();
                if limit.next_allowed_request > now {
                    Some(limit.next_allowed_request - now)
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some(duration) = sleep_duration {
            // Cap jitter at 100ms to avoid pushing the total sleep past
            // `stallDetectionTimeout` when `duration` is near `rateLimitMaxWaitSecs`
            // (both default to 900s): a 500ms jitter would trigger a false stall alert.
            let jitter = Duration::from_millis((rand::random::<f64>() * 100.0) as u64);
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
        // per-service cap, so `Instant::now() + Duration::from_secs(delay)`
        // below can neither freeze the service for hours nor overflow.
        let delay = self.effective_retry_after(service, retry_after);
        let new_allowed = Instant::now() + Duration::from_secs(delay);

        let mut limit = self
            .limits
            .entry(service.to_string())
            .or_insert(ServiceLimit {
                next_allowed_request: Instant::now(),
            });

        if new_allowed > limit.next_allowed_request {
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
}

impl Default for RateLimitManager {
    fn default() -> Self {
        Self::new(5)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::pause;

    #[tokio::test]
    async fn test_report_429_takes_maximum() {
        pause();
        let manager = RateLimitManager::new(5);
        let service = "test_service";

        // Report 429 with 60s delay
        manager.report_429(service, Some(60));

        // Report 429 with 30s delay
        manager.report_429(service, Some(30));

        // The delay should be 60s, not 30s.
        // wait_if_needed should sleep for approx 60s.
        let start = Instant::now();
        manager.wait_if_needed(service).await;
        let elapsed = start.elapsed();

        assert!(elapsed >= Duration::from_secs(60));
        assert!(elapsed < Duration::from_secs(61));
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

        // graph falls back to the global 5s default.
        manager.report_429("graph", None);
        let start = Instant::now();
        manager.wait_if_needed("graph").await;
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_secs(5));
        assert!(elapsed < Duration::from_secs(6));
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
