use oradaz::collect::dump::build_service_aware_throttling;
use oradaz::collect::dump::concurrency::ConcurrencyController;
use oradaz::utils::config::{ServiceOverride, ServiceOverrides};

use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::{Duration, advance, pause, timeout};

#[tokio::test]
async fn test_aimd_additive_increase() {
    let controller = ConcurrencyController::new(1, 10);
    let service = "test-service";

    assert_eq!(controller.current_window(service), 10);
}

/// With slow-start enabled, a service window opens at `min_window`
/// and ramps up via AIMD on success — instead of starting at `max_window`.
#[tokio::test]
async fn slow_start_window_opens_at_min_and_ramps() {
    let controller = ConcurrencyController::new(2, 30).with_slow_start(true);
    let service = "graph";

    // Acquiring a slot materializes the window; with slow-start it opens at min (2).
    controller.acquire_slot(service).await;
    assert_eq!(
        controller.current_window(service),
        2,
        "slow-start must open the window at min_window, not max_window"
    );

    // AIMD ramps it: at window=2 one success reaches ceil(2/2)=1 → window grows to 3.
    controller.report_success(service);
    assert_eq!(
        controller.current_window(service),
        3,
        "AIMD must additively grow a slow-started window on success"
    );
    controller.release_slot(service);
}

/// Default (no slow-start): a service window opens at `max_window`, probing at
/// full concurrency immediately. Guards against an accidental default flip.
#[tokio::test]
async fn default_window_opens_at_max() {
    let controller = ConcurrencyController::new(2, 30); // slow-start defaults to false
    let service = "graph";

    controller.acquire_slot(service).await;
    assert_eq!(
        controller.current_window(service),
        30,
        "default must open the window at max_window (start-at-max preserved)"
    );
    controller.release_slot(service);
}

#[tokio::test]
async fn test_aimd_multiplicative_decrease() {
    // Coalesces 429s within a ~1s epoch into a single halving, so advance the
    // (paused) clock past the guard between each decrease to model distinct
    // congestion events.
    pause();
    let controller = ConcurrencyController::new(1, 10);
    let service = "test-service";

    controller.acquire_slot(service).await;
    controller.release_slot(service);

    // Start at 10
    assert_eq!(controller.current_window(service), 10);

    // Report 429 -> should become 5
    controller.report_429(service);
    assert_eq!(controller.current_window(service), 5);

    // Report 429 -> should become 2
    advance(Duration::from_millis(1100)).await;
    controller.report_429(service);
    assert_eq!(controller.current_window(service), 2);

    // Report 429 -> should become 1 (min_window)
    advance(Duration::from_millis(1100)).await;
    controller.report_429(service);
    assert_eq!(controller.current_window(service), 1);

    // Report 429 again -> should stay 1
    advance(Duration::from_millis(1100)).await;
    controller.report_429(service);
    assert_eq!(controller.current_window(service), 1);
}

/// T5 observability: the window records additive **increases** (the symmetric
/// companion to halvings) and the **time spent at the collapsed floor** — so a
/// window pinned at the floor is distinguishable from a brief dip.
#[tokio::test]
async fn aimd_records_increases_and_time_at_floor() {
    pause();
    let controller = ConcurrencyController::new(2, 10);
    let service = "graph";

    controller.acquire_slot(service).await;
    controller.release_slot(service);

    // Collapse to the floor: 10 → 5 → 2 (two distinct congestion epochs).
    controller.report_429(service);
    advance(Duration::from_millis(1100)).await;
    controller.report_429(service);
    assert_eq!(
        controller.current_window(service),
        2,
        "collapsed to the floor"
    );

    // Sit pinned at the floor for ~5s before any success lets it ramp.
    advance(Duration::from_secs(5)).await;

    // Successes ramp the window back up; the first leaves the floor.
    for _ in 0..4 {
        controller.report_success(service);
    }

    let increases = controller
        .get_all_increases()
        .get(service)
        .copied()
        .unwrap_or(0);
    assert!(
        increases >= 1,
        "the window must record additive increases once it recovers, got {increases}"
    );
    let at_floor = controller
        .get_all_time_at_floor_secs()
        .get(service)
        .copied()
        .unwrap_or(0);
    assert!(
        at_floor >= 5,
        "must record the ~5s the window sat collapsed at the floor, got {at_floor}s"
    );
    let decreases = controller
        .get_all_decreases()
        .get(service)
        .copied()
        .unwrap_or(0);
    assert_eq!(decreases, 2, "two halvings: 10→5→2");
}

/// A window still collapsed at the floor when the run ends still reports its
/// floor time (the open segment is closed at read time, not lost).
#[tokio::test]
async fn aimd_time_at_floor_counts_open_segment_at_end() {
    pause();
    let controller = ConcurrencyController::new(2, 10);
    let service = "graph";
    controller.acquire_slot(service).await;
    controller.release_slot(service);

    controller.report_429(service); // 10 → 5
    advance(Duration::from_millis(1100)).await;
    controller.report_429(service); // 5 → 2 (floor), never recovers
    advance(Duration::from_secs(7)).await;

    let at_floor = controller
        .get_all_time_at_floor_secs()
        .get(service)
        .copied()
        .unwrap_or(0);
    assert!(
        at_floor >= 7,
        "an unrecovered floor segment must be counted at end of run, got {at_floor}s"
    );
}

/// Within one congestion epoch, repeated `report_429` calls halve the window
/// only once; a call in a later epoch (after the guard elapses) halves again.
#[tokio::test]
async fn report_429_coalesces_within_epoch_then_halves_next_epoch() {
    pause();
    let controller = ConcurrencyController::new(1, 16);
    let service = "test-service";

    controller.acquire_slot(service).await;
    controller.release_slot(service);
    assert_eq!(controller.current_window(service), 16);

    // Same epoch: three 429s coalesce into a single halving.
    controller.report_429(service);
    controller.report_429(service);
    controller.report_429(service);
    assert_eq!(
        controller.current_window(service),
        8,
        "429s within one epoch must coalesce into a single halving (16 -> 8)"
    );

    // Next epoch (guard elapsed): a 429 halves again.
    advance(Duration::from_millis(1100)).await;
    controller.report_429(service);
    assert_eq!(
        controller.current_window(service),
        4,
        "a 429 in a new epoch must halve again (8 -> 4)"
    );
}

/// `get_all_min_windows` / `get_all_decreases` track the AIMD floor and the
/// number of effective halvings (observability for the throttling-collapse
/// signal). Coalesced 429s within one epoch count as a single collapse.
#[tokio::test]
async fn min_window_and_decrease_count_track_collapse() {
    pause();
    let controller = ConcurrencyController::new(1, 16);
    let service = "test-service";

    controller.acquire_slot(service).await;
    controller.release_slot(service);

    // No 429 yet: floor == start window, no halvings recorded.
    assert_eq!(controller.get_all_min_windows().get(service), Some(&16));
    assert_eq!(controller.get_all_decreases().get(service), Some(&0));

    // Three 429s in one epoch coalesce into a single halving (16 -> 8).
    controller.report_429(service);
    controller.report_429(service);
    controller.report_429(service);
    assert_eq!(controller.get_all_min_windows().get(service), Some(&8));
    assert_eq!(
        controller.get_all_decreases().get(service),
        Some(&1),
        "coalesced 429s within one epoch must count as a single collapse"
    );

    // Next epoch: another halving (8 -> 4), floor follows, count increments.
    advance(Duration::from_millis(1100)).await;
    controller.report_429(service);
    assert_eq!(controller.get_all_min_windows().get(service), Some(&4));
    assert_eq!(controller.get_all_decreases().get(service), Some(&2));

    // Additive increases must NOT raise the recorded floor.
    for _ in 0..40 {
        controller.report_success(service);
    }
    assert!(controller.current_window(service) > 4);
    assert_eq!(
        controller.get_all_min_windows().get(service),
        Some(&4),
        "the floor is a low-water mark and must not rise on recovery"
    );
    assert_eq!(controller.get_all_decreases().get(service), Some(&2));
}

/// A slow-start service *starts* at `min_window`, but `min_window_reached` is the
/// reduction floor: before any 429 it must read `max_window` (never collapsed),
/// not the start value — otherwise the floor would look collapsed at startup.
#[tokio::test]
async fn slow_start_floor_starts_at_max_not_min() {
    pause();
    let controller = ConcurrencyController::new(2, 30).with_slow_start(true);
    let service = "test-service";

    controller.acquire_slot(service).await;
    controller.release_slot(service);

    // Window opened at min (slow-start), but the reduction floor is the ceiling.
    assert_eq!(controller.current_window(service), 2);
    assert_eq!(
        controller.get_all_min_windows().get(service),
        Some(&30),
        "floor must start at max_window so 'floor < max' means actually reduced"
    );
    assert_eq!(controller.get_all_decreases().get(service), Some(&0));
}

#[tokio::test]
async fn test_aimd_additive_increase_after_decrease() {
    // Advance past the coalescing guard between decreases (distinct epochs).
    pause();
    let controller = ConcurrencyController::new(1, 10);
    let service = "test-service";

    controller.acquire_slot(service).await;
    controller.release_slot(service);

    // Decrease to 1 (one halving per epoch).
    controller.report_429(service); // 5
    advance(Duration::from_millis(1100)).await;
    controller.report_429(service); // 2
    advance(Duration::from_millis(1100)).await;
    controller.report_429(service); // 1
    assert_eq!(controller.current_window(service), 1);

    // 1 success should increase window to 2
    controller.report_success(service);
    assert_eq!(controller.current_window(service), 2);

    // Next 1 success should increase window to 3
    controller.report_success(service);
    assert_eq!(controller.current_window(service), 3);
}

#[tokio::test]
async fn test_per_service_isolation() {
    let controller = ConcurrencyController::new(1, 10);
    let service_a = "service-a";
    let service_b = "service-b";

    controller.acquire_slot(service_a).await;
    controller.release_slot(service_a);
    controller.acquire_slot(service_b).await;
    controller.release_slot(service_b);

    // Decrease A
    controller.report_429(service_a);
    assert_eq!(controller.current_window(service_a), 5);

    // B should remain at 10
    assert_eq!(controller.current_window(service_b), 10);
}

#[tokio::test]
async fn test_per_service_window_caps_in_flight() {
    let max_window = 2;
    let controller = Arc::new(ConcurrencyController::new(1, max_window));
    let service = "test-service";

    // Acquire 2 slots
    controller.acquire_slot(service).await;
    controller.acquire_slot(service).await;

    // Third attempt should timeout
    let result = timeout(Duration::from_millis(100), controller.acquire_slot(service)).await;
    assert!(
        result.is_err(),
        "Third acquire should time out: the per-service AIMD window (max 2) caps in-flight requests — there is no global semaphore"
    );
}

#[tokio::test]
async fn test_per_service_window_limit() {
    // A window of 1 caps in-flight at a single slot. Constructed at min=max=1
    // directly so the test doesn't depend on the AIMD decrease sequence.
    let controller = Arc::new(ConcurrencyController::new(1, 1));
    let service = "test-service";

    controller.acquire_slot(service).await;
    controller.release_slot(service);
    assert_eq!(controller.current_window(service), 1);

    // Acquire 1 slot
    controller.acquire_slot(service).await;

    // Second attempt should timeout (per-service window of 1)
    let result = timeout(Duration::from_millis(100), controller.acquire_slot(service)).await;
    assert!(
        result.is_err(),
        "Should have timed out due to per-service window"
    );

    // Release slot
    controller.release_slot(service);

    // Now we should be able to acquire again
    let result = timeout(Duration::from_millis(100), controller.acquire_slot(service)).await;
    assert!(
        result.is_ok(),
        "Should be able to acquire slot after release"
    );
}

/// Each service must respect its own `(min, max)` bounds, independent of the
/// global fallback. Verifies that a permissive `graph` override and a strict
/// `resources` override coexist on the same controller.
#[tokio::test]
async fn test_service_bounds_are_per_service() {
    // Advance past the coalescing guard between decreases (distinct epochs).
    pause();
    let mut bounds: HashMap<String, (usize, usize)> = HashMap::new();
    bounds.insert("graph".to_string(), (2, 100));
    bounds.insert("resources".to_string(), (2, 8));
    // Global fallback (used by any other service): (2, 30).
    let controller = ConcurrencyController::with_service_bounds(2, 30, bounds);

    // Initial windows should equal each service's max bound.
    assert_eq!(controller.current_window("graph"), 100);
    assert_eq!(controller.current_window("resources"), 8);
    // Unknown service falls back to the global max.
    assert_eq!(controller.current_window("exchange"), 30);

    // Force creation of the resources window so report_429 has something to act on.
    controller.acquire_slot("resources").await;
    controller.report_429("resources");
    // 8 / 2 = 4; min is 2, so still 4.
    assert_eq!(controller.current_window("resources"), 4);
    advance(Duration::from_millis(1100)).await;
    controller.report_429("resources");
    advance(Duration::from_millis(1100)).await;
    controller.report_429("resources");
    advance(Duration::from_millis(1100)).await;
    controller.report_429("resources");
    // floor to the per-service min, not the global min.
    assert_eq!(controller.current_window("resources"), 2);
    controller.release_slot("resources");

    // graph stays at 100 because it never got a 429.
    assert_eq!(controller.current_window("graph"), 100);
}

/// A *burst* of concurrent `report_429` calls from a single congestion event
/// must coalesce into a **single** halving — not one per call. The epoch CAS in
/// `report_429` lets exactly one of the burst perform the halving and the rest
/// return, so the window does not collapse straight to `min` (which would then
/// force a slow additive re-ramp). This also exercises the CAS for a clean
/// single-update under contention (no double-halving race).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_report_429_coalesce_to_single_halving() {
    use tokio::sync::Barrier;

    let controller = Arc::new(ConcurrencyController::new(1, 128));
    let service = "race-service";

    // Force window creation (opens at max=128).
    controller.acquire_slot(service).await;
    controller.release_slot(service);

    let barrier = Arc::new(Barrier::new(10));

    let handles: Vec<_> = (0..10)
        .map(|_| {
            let c = Arc::clone(&controller);
            let b = Arc::clone(&barrier);
            let svc = service.to_string();
            tokio::spawn(async move {
                b.wait().await;
                c.report_429(&svc);
            })
        })
        .collect();

    for h in handles {
        h.await.unwrap();
    }

    // All 10 fire within the same sub-second congestion epoch → exactly one halving.
    assert_eq!(
        controller.current_window(service),
        64,
        "a burst of concurrent 429s must coalesce into a single halving (128 -> 64)"
    );
}

/// Guards the `acquire_slot` lost-wakeup invariant. `release_slot` wakes
/// waiters with `notify_waiters()`, which banks no permit; `acquire_slot` must
/// therefore register its `Notified` (via `enable()`) before checking the
/// window so a release firing between the check and the park is not lost.
/// With a window of 1 and many tasks cycling acquire→release, a lost wakeup
/// would leave a task parked forever; this asserts the whole workload drains
/// within a timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acquire_release_under_contention_never_hangs() {
    let controller = Arc::new(ConcurrencyController::new(1, 1));
    let service = "race-service";

    let tasks = 16;
    let iters = 250;
    let handles: Vec<_> = (0..tasks)
        .map(|_| {
            let c = Arc::clone(&controller);
            let svc = service.to_string();
            tokio::spawn(async move {
                for _ in 0..iters {
                    c.acquire_slot(&svc).await;
                    tokio::task::yield_now().await;
                    c.release_slot(&svc);
                }
            })
        })
        .collect();

    let drain = async {
        for h in handles {
            h.await.unwrap();
        }
    };
    timeout(Duration::from_secs(10), drain)
        .await
        .expect("acquire/release workload deadlocked (lost wakeup in acquire_slot)");
}

/// `release_slot` wakes only the *released service's* waiters via a per-service
/// `Notify`, and that wake still works correctly (no lost wakeup, no cross-service
/// deadlock). A waiter parked on service A must (a) NOT acquire when a *different*
/// service B releases (per-service slot accounting), and (b) acquire promptly when
/// A itself releases. A mis-wired per-service notifier would leave the A-waiter
/// parked forever after the A release — caught by the final timeout.
#[tokio::test]
async fn release_wakes_parked_waiter_per_service() {
    // Each service capped at 1 in-flight.
    let controller = Arc::new(ConcurrencyController::new(1, 1));

    // Fill A and B (both at their window of 1).
    controller.acquire_slot("a").await;
    controller.acquire_slot("b").await;

    // Park a waiter on A (A is full).
    let c = Arc::clone(&controller);
    let waiter_a = tokio::spawn(async move { c.acquire_slot("a").await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !waiter_a.is_finished(),
        "A-waiter must park while A is full"
    );

    // Releasing B frees a B slot only — the A-waiter must not acquire (A is still
    // full); per-service slot accounting.
    controller.release_slot("b");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !waiter_a.is_finished(),
        "releasing service B must not let a waiter parked on service A acquire"
    );

    // Releasing A frees A's slot and must wake the A-waiter so it acquires.
    controller.release_slot("a");
    timeout(Duration::from_secs(5), waiter_a)
        .await
        .expect("releasing A must wake its parked waiter (per-service notify); it deadlocked")
        .expect("A-waiter task panicked");
}

/// `get_all_slot_wait_events` counts a park as cap-contention only when the
/// window is at its ceiling (`current >= max_window`). With min=max=1 the window
/// is always at its ceiling, so a second acquire parks and increments the counter.
#[tokio::test]
async fn slot_wait_events_counts_ceiling_parks() {
    let controller = Arc::new(ConcurrencyController::new(1, 1));
    let service = "race-service";

    // Fill the single slot: the window (1) is at its ceiling (max 1).
    controller.acquire_slot(service).await;

    // A second acquire parks at the ceiling → counts as cap contention.
    let c = Arc::clone(&controller);
    let svc = service.to_string();
    let waiter = tokio::spawn(async move { c.acquire_slot(&svc).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !waiter.is_finished(),
        "waiter must park while the slot is full"
    );
    assert_eq!(
        controller.get_all_slot_wait_events().get(service),
        Some(&1),
        "a park while the window is at its ceiling must count as cap contention"
    );

    // Release so the waiter wakes and the workload drains.
    controller.release_slot(service);
    timeout(Duration::from_secs(5), waiter)
        .await
        .expect("releasing must wake the ceiling-parked waiter")
        .unwrap();
}

/// The ceiling gate: a park while the window has been *reduced* by a 429 (below
/// `max_window`) is throttle-bound, not cap-bound, and must NOT count — otherwise
/// the M1 "is the ceiling binding?" signal would be polluted by throttling.
#[tokio::test]
async fn slot_wait_events_gated_off_when_window_reduced() {
    let controller = Arc::new(ConcurrencyController::new(1, 4));
    let service = "race-service";

    // Materialize then halve the window: 4 -> 2 (below the ceiling of 4).
    controller.acquire_slot(service).await;
    controller.release_slot(service);
    controller.report_429(service);
    assert_eq!(
        controller.current_window(service),
        2,
        "window halved to 2 (below max 4)"
    );

    // Fill the reduced window (2 slots), then a third acquire parks — but below
    // the ceiling, so the gate must keep the counter at zero.
    controller.acquire_slot(service).await;
    controller.acquire_slot(service).await;
    let c = Arc::clone(&controller);
    let svc = service.to_string();
    let waiter = tokio::spawn(async move { c.acquire_slot(&svc).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !waiter.is_finished(),
        "waiter must park while the reduced window is full"
    );
    assert_eq!(
        controller
            .get_all_slot_wait_events()
            .get(service)
            .copied()
            .unwrap_or(0),
        0,
        "a park on a 429-reduced window must NOT count as cap contention"
    );

    // Drain.
    controller.release_slot(service);
    timeout(Duration::from_secs(5), waiter)
        .await
        .expect("releasing must wake the parked waiter")
        .unwrap();
}

/// A misconfiguration where a service's min bound exceeds its max bound (e.g. a
/// global concurrencyMinWindow above the resources baseline of 100) must never let a
/// 429 *raise* the window. The controller clamps min to max, so the window stays at
/// max and a 429 cannot push it above (the pre-fix bug computed `(100/2).max(120)=120`).
#[tokio::test]
async fn inverted_bounds_are_clamped_so_429_cannot_raise_window() {
    let mut bounds: HashMap<String, (usize, usize)> = HashMap::new();
    bounds.insert("resources".to_string(), (120, 100)); // min > max (inverted)
    let controller = ConcurrencyController::with_service_bounds(120, 150, bounds);

    controller.acquire_slot("resources").await;
    // Window opens at the (clamped) max, not the inverted min.
    assert_eq!(controller.current_window("resources"), 100);
    // A 429 must not raise the window above max.
    controller.report_429("resources");
    assert!(
        controller.current_window("resources") <= 100,
        "a 429 must never raise the window above max even when min was misconfigured above max"
    );
    controller.release_slot("resources");
}

mod build_service_aware_throttling_tests {
    use super::*;

    mod common {
        use oradaz::utils::config::Config;

        pub fn config() -> Config {
            Config {
                tenant: "t".to_string(),
                app_id: "a".to_string(),
                services: None,
                proxy: None,
                output_files: None,
                output_mla: None,
                output: None,
                no_check: None,
                use_device_code: None,
                listener_address: None,
                listener_port: None,
                schema_file: None,
                schema_url_override: None,
                user_agent: None,
                trace_logs: None,
                use_application_credentials: None,
                application_credentials: None,
                concurrency_min_window: None,
                concurrency_max_window: None,
                dispatch_burst_cap: None,
                http_timeout_seconds: None,
                url_retry_limit: None,
                rate_limit_retry_limit: None,
                rate_limit_max_wait_secs: None,
                stall_detection_timeout: None,
                http_connect_timeout_seconds: None,
                retry_backoff_base_ms: None,
                retry_backoff_cap_ms: None,
                prereq_recheck_cache_secs: None,
                liveness_ceiling_secs: None,
                service_overrides: None,
                default_retry_after_seconds: None,
                emergency_accounts_custom_attributes: None,
                additional_mla_keys: None,
                logs_days_filter: None,
                shuffle_urls: None,
                concurrency_slow_start: None,
                response_workers_max: None,
                response_memory_budget_bytes: None,
                expected_error_breaker_threshold: None,
            }
        }
    }

    /// No config overrides at all: exchange should get the hard-coded default of 150.
    #[test]
    fn exchange_defaults_to_150_without_override() {
        let config = common::config();
        let (_, controller) = build_service_aware_throttling(&config);
        assert_eq!(controller.current_window("exchange"), 150);
    }

    /// Slow-start wiring: `concurrencySlowStart=true` makes a service window open at its
    /// `min_window`. Verified after an acquire materializes the window (before that,
    /// `current_window` reports the fallback max regardless of slow-start).
    #[tokio::test]
    async fn slow_start_config_opens_graph_at_min() {
        use oradaz::utils::config::Config;
        let mut config = common::config();
        config.concurrency_slow_start = Some(true);
        let (_, controller) = build_service_aware_throttling(&config);

        controller.acquire_slot("graph").await;
        assert_eq!(
            controller.current_window("graph"),
            Config::concurrency_min_window(&config),
            "concurrencySlowStart=true must open graph's window at min_window"
        );
        controller.release_slot("graph");
    }

    /// Default (slow-start off): graph's window still opens at its baseline max (150)
    /// once materialized — the start-at-max behavior is preserved.
    #[tokio::test]
    async fn default_config_opens_graph_at_max() {
        let config = common::config();
        let (_, controller) = build_service_aware_throttling(&config);

        controller.acquire_slot("graph").await;
        assert_eq!(
            controller.current_window("graph"),
            150,
            "without slow-start, graph's window must open at its baseline max (150)"
        );
        controller.release_slot("graph");
    }

    /// The global concurrencyMaxWindow does not raise the exchange baseline; exchange
    /// keeps 150 regardless.
    #[test]
    fn exchange_keeps_150_when_global_max_is_lower() {
        let mut config = common::config();
        config.concurrency_max_window = Some(15);
        let (_, controller) = build_service_aware_throttling(&config);
        assert_eq!(controller.current_window("exchange"), 150);
    }

    /// An explicit concurrencyMaxWindow override for exchange is respected.
    #[test]
    fn exchange_explicit_max_override_takes_precedence() {
        let mut config = common::config();
        config.service_overrides = Some(ServiceOverrides {
            services: vec![ServiceOverride {
                name: "exchange".to_string(),
                concurrency_min_window: None,
                concurrency_max_window: Some(50),
                rate_limit_retry_limit: None,
                rate_limit_max_wait_secs: None,
                default_retry_after_seconds: None,
                http_timeout_seconds: None,
            }],
        });
        let (_, controller) = build_service_aware_throttling(&config);
        assert_eq!(controller.current_window("exchange"), 50);
    }

    /// When only concurrencyMinWindow is overridden for exchange (not max), the
    /// hard-coded max of 150 still applies, and the overridden min is preserved.
    #[test]
    fn exchange_min_override_preserves_hardcoded_max() {
        let mut config = common::config();
        config.service_overrides = Some(ServiceOverrides {
            services: vec![ServiceOverride {
                name: "exchange".to_string(),
                concurrency_min_window: Some(7),
                concurrency_max_window: None,
                rate_limit_retry_limit: None,
                rate_limit_max_wait_secs: None,
                default_retry_after_seconds: None,
                http_timeout_seconds: None,
            }],
        });
        let (_, controller) = build_service_aware_throttling(&config);
        assert_eq!(controller.current_window("exchange"), 150);
    }

    /// resources gets its own built-in baseline of 100; unlisted services use the
    /// global default (30).
    #[test]
    fn resources_uses_built_in_baseline_and_others_fall_back_to_global() {
        let config = common::config();
        let (_, controller) = build_service_aware_throttling(&config);
        assert_eq!(controller.current_window("resources"), 100);
        assert_eq!(controller.current_window("directory"), 30);
    }

    /// No config overrides at all: graph gets the hard-coded default of 150.
    #[test]
    fn graph_defaults_to_150_without_override() {
        let config = common::config();
        let (_, controller) = build_service_aware_throttling(&config);
        assert_eq!(controller.current_window("graph"), 150);
    }

    /// The global concurrencyMaxWindow does not raise the graph baseline; graph
    /// keeps 150 regardless.
    #[test]
    fn graph_keeps_150_when_global_max_is_lower() {
        let mut config = common::config();
        config.concurrency_max_window = Some(15);
        let (_, controller) = build_service_aware_throttling(&config);
        assert_eq!(controller.current_window("graph"), 150);
    }

    /// An explicit concurrencyMaxWindow override for graph is respected over the
    /// baseline.
    #[test]
    fn graph_explicit_max_override_takes_precedence() {
        let mut config = common::config();
        config.service_overrides = Some(ServiceOverrides {
            services: vec![ServiceOverride {
                name: "graph".to_string(),
                concurrency_min_window: None,
                concurrency_max_window: Some(20),
                rate_limit_retry_limit: None,
                rate_limit_max_wait_secs: None,
                default_retry_after_seconds: None,
                http_timeout_seconds: None,
            }],
        });
        let (_, controller) = build_service_aware_throttling(&config);
        assert_eq!(controller.current_window("graph"), 20);
    }
}
