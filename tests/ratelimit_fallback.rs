// Test that when a 429 response lacks a Retry-After header, the manager falls back to the configured default (5 seconds)

#[cfg(test)]
mod tests {
    use oradaz::collect::dump::ratelimit::RateLimitManager;
    use std::collections::HashMap;
    use tokio::time::{Duration, Instant, pause};

    #[tokio::test]
    async fn test_fallback_default_retry_after() {
        pause();
        // Use the global default of 5 seconds
        let manager = RateLimitManager::new(5);
        let service = "graph";

        // Simulate a 429 response without a Retry-After header
        manager.report_429(service, None);

        let start = Instant::now();
        manager.wait_if_needed(service, &[]).await;
        let elapsed = start.elapsed();
        // 5s cooldown + a forward desync jitter (capped at 2s internally). The
        // 8s upper bound leaves headroom for the cap without masking a regression.
        assert!(elapsed >= Duration::from_secs(5));
        assert!(elapsed < Duration::from_secs(8));
    }

    #[tokio::test]
    async fn test_fallback_per_service_override() {
        pause();
        // Global default 5 seconds, but override for "resources" to 30 seconds
        let mut per_service: HashMap<String, u64> = HashMap::new();
        per_service.insert("resources".to_string(), 30);
        let manager =
            RateLimitManager::with_per_service_defaults(5, per_service, 900, HashMap::new());

        // Service with override
        manager.report_429("resources", None);
        let start = Instant::now();
        manager.wait_if_needed("resources", &[]).await;
        assert!(start.elapsed() >= Duration::from_secs(30));

        // Service without override falls back to global default (5 seconds).
        // Upper bound allows for the internal forward desync jitter (cap 2s).
        manager.report_429("graph", None);
        let start = Instant::now();
        manager.wait_if_needed("graph", &[]).await;
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_secs(5));
        assert!(elapsed < Duration::from_secs(8));
    }

    /// `effective_retry_after` returns the explicit value when present, else the
    /// per-service default, else the global default. This is the rule that keeps
    /// a header-less / unparseable 429 from collapsing to a zero cooldown.
    #[test]
    fn effective_retry_after_uses_value_or_default() {
        let mut per_service: HashMap<String, u64> = HashMap::new();
        per_service.insert("resources".to_string(), 30);
        let manager =
            RateLimitManager::with_per_service_defaults(5, per_service, 900, HashMap::new());

        assert_eq!(manager.effective_retry_after("graph", Some(42)), 42);
        assert_eq!(manager.effective_retry_after("resources", None), 30);
        assert_eq!(manager.effective_retry_after("graph", None), 5);
    }

    /// Clamp accounting: one increment per `report_429` whose cooldown was capped
    /// by `rateLimitMaxWaitSecs` — and none from the response path's standalone
    /// `effective_retry_after` calls, which compute the same value for stats and
    /// would otherwise tally a single clamp several times.
    #[test]
    fn clamped_count_increments_once_per_429_report() {
        let manager =
            RateLimitManager::with_per_service_defaults(5, HashMap::new(), 30, HashMap::new());

        // Standalone resolution (the stats path) must not count.
        assert_eq!(manager.effective_retry_after("graph", Some(100)), 30);
        assert!(
            manager
                .get_all_clamped_counts()
                .get("graph")
                .copied()
                .unwrap_or(0)
                == 0
        );

        manager.report_429("graph", Some(100)); // 100 > cap 30 → clamped
        manager.report_429("graph", Some(10)); // under the cap → not clamped
        manager.report_429("graph", Some(50)); // clamped again

        assert_eq!(manager.get_all_clamped_counts().get("graph"), Some(&2));
    }

    /// The 429 path must hand the manager the *raw* server `Retry-After`, not the
    /// already-resolved cooldown. Feeding the resolved value (what
    /// `effective_retry_after` returns) makes the manager see `raw == cap` and
    /// count no clamp, hiding the fact that the server asked for more than
    /// `rateLimitMaxWaitSecs`. The raw value is what reveals the clamp.
    #[test]
    fn clamp_is_counted_only_when_fed_the_raw_value() {
        let manager =
            RateLimitManager::with_per_service_defaults(5, HashMap::new(), 30, HashMap::new());

        // Pre-resolved value (`effective_retry_after` already clamped 100 → 30):
        // reporting it counts nothing, because 30 == cap.
        let resolved = manager.effective_retry_after("exchange", Some(100));
        assert_eq!(resolved, 30);
        manager.report_429("exchange", Some(resolved));
        assert_eq!(
            manager
                .get_all_clamped_counts()
                .get("exchange")
                .copied()
                .unwrap_or(0),
            0
        );

        // Raw server value (100 > cap 30): the clamp is observed.
        manager.report_429("exchange", Some(100));
        assert_eq!(manager.get_all_clamped_counts().get("exchange"), Some(&1));
    }
}
