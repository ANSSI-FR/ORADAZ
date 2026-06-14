use oradaz::collect::dump::concurrency::ConcurrencyController;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::task;
use tokio::time::{Duration, sleep};

#[tokio::test]
async fn test_stress_concurrency_limit() {
    let max_window = 10;
    let min_window = 1;
    let controller = Arc::new(ConcurrencyController::new(min_window, max_window));
    let service = "stress-service";
    let concurrent_tasks = 100;
    let active_requests = Arc::new(AtomicUsize::new(0));
    let max_observed_active = Arc::new(AtomicUsize::new(0));

    let mut handles = vec![];

    for _ in 0..concurrent_tasks {
        let controller = Arc::clone(&controller);
        let active_requests = Arc::clone(&active_requests);
        let max_observed_active = Arc::clone(&max_observed_active);
        let service = service.to_string();

        handles.push(task::spawn(async move {
            controller.acquire_slot(&service).await;

            let current_active = active_requests.fetch_add(1, Ordering::SeqCst) + 1;

            // Update max observed active requests
            let mut current_max = max_observed_active.load(Ordering::SeqCst);
            while current_active > current_max {
                if max_observed_active
                    .compare_exchange(
                        current_max,
                        current_active,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    )
                    .is_ok()
                {
                    break;
                }
                current_max = max_observed_active.load(Ordering::SeqCst);
            }

            // Simulate some work
            sleep(Duration::from_millis(1)).await;

            active_requests.fetch_sub(1, Ordering::SeqCst);
            controller.release_slot(&service);
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    assert!(
        max_observed_active.load(Ordering::SeqCst) <= max_window,
        "Observed {} active requests, which exceeds max_window {}",
        max_observed_active.load(Ordering::SeqCst),
        max_window
    );
}

#[tokio::test]
async fn test_stress_dynamic_window_reduction() {
    let max_window = 20;
    let min_window = 1;
    let controller = Arc::new(ConcurrencyController::new(min_window, max_window));
    let service = "dynamic-service";
    let concurrent_tasks = 50;
    let active_requests = Arc::new(AtomicUsize::new(0));
    let max_observed_after_reduction = Arc::new(AtomicUsize::new(0));
    let reduction_happened = Arc::new(AtomicUsize::new(0));

    let mut handles = vec![];

    for _ in 0..concurrent_tasks {
        let controller = Arc::clone(&controller);
        let active_requests = Arc::clone(&active_requests);
        let max_observed_after_reduction = Arc::clone(&max_observed_after_reduction);
        let reduction_happened = Arc::clone(&reduction_happened);
        let service = service.to_string();

        handles.push(task::spawn(async move {
            controller.acquire_slot(&service).await;

            let current_active = active_requests.fetch_add(1, Ordering::SeqCst) + 1;

            if reduction_happened.load(Ordering::SeqCst) == 1 {
                let mut current_max = max_observed_after_reduction.load(Ordering::SeqCst);
                while current_active > current_max {
                    if max_observed_after_reduction
                        .compare_exchange(
                            current_max,
                            current_active,
                            Ordering::SeqCst,
                            Ordering::SeqCst,
                        )
                        .is_ok()
                    {
                        break;
                    }
                    current_max = max_observed_after_reduction.load(Ordering::SeqCst);
                }
            }

            sleep(Duration::from_millis(5)).await;

            active_requests.fetch_sub(1, Ordering::SeqCst);
            controller.release_slot(&service);
        }));
    }

    // Wait for some tasks to start
    sleep(Duration::from_millis(10)).await;

    // Trigger 429s to reduce the window. These fire within one congestion
    // epoch (<1s), so they coalesce into a single halving (20 -> 10) rather than
    // collapsing straight to min — the assertion below only requires that the
    // observed concurrency never exceeds max_window, which holds either way.
    controller.report_429(service);
    controller.report_429(service);
    controller.report_429(service);
    controller.report_429(service);

    // The four rapid 429s land in one congestion epoch, so they coalesce into a
    // single halving (20 -> 10) instead of collapsing to min. No report_success is
    // ever called in this test, so the window stays at 10 — pin it.
    assert_eq!(
        controller.current_window(service),
        10,
        "the four rapid 429s must coalesce into a single halving (20 -> 10)"
    );

    reduction_happened.store(1, Ordering::SeqCst);

    for handle in handles {
        handle.await.unwrap();
    }

    // After the reduction (window now 10), new acquisitions are capped at the
    // reduced window. We only assert `<= max_window` (not `<= 10`) here because
    // `active_requests` also counts tasks that acquired *before* the reduction,
    // while the window was still at its max of 20 — those are still finishing, so
    // the observed peak can legitimately exceed the post-reduction window. The
    // exact single-halving (20 -> 10) is pinned by the assertion above.

    // Let's check if it's reasonably low.
    assert!(max_observed_after_reduction.load(Ordering::SeqCst) <= max_window);
}
