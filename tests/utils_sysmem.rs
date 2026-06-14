//! Tests for `utils::sysmem` — process RSS sampling plus the in-process memory
//! gauges (URL-pool peak, response-worker count). The peaks and the worker count
//! are process-global, so assertions use `>=` / deltas to stay robust under the
//! parallel test runner.

use oradaz::utils::sysmem;

#[test]
fn rss_bytes_is_available_on_supported_platforms() {
    let rss = sysmem::rss_bytes();
    #[cfg(any(target_os = "linux", windows))]
    {
        let bytes = rss.expect("RSS must be readable on Linux/Windows");
        assert!(bytes > 0, "process RSS should be a positive byte count");
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        // Unsupported platform: the gauge degrades to None, never panics.
        let _ = rss;
    }
}

#[test]
fn response_worker_guard_tracks_inflight_count() {
    // Only this test touches the worker gauge, so the count is stable apart from
    // our own guard.
    let before = sysmem::response_workers_inflight();
    let guard = sysmem::track_response_worker();
    assert!(
        sysmem::response_workers_inflight() > before,
        "track_response_worker must increment the in-flight count"
    );
    let held = sysmem::response_workers_inflight();
    drop(guard);
    assert!(
        sysmem::response_workers_inflight() < held,
        "dropping the guard must decrement the in-flight count"
    );
}

#[test]
fn request_worker_guard_tracks_inflight_count() {
    // Only this test touches the request-worker gauge, so the count is stable apart
    // from our own guard.
    let before = sysmem::request_workers_inflight();
    let guard = sysmem::track_request_worker();
    assert!(
        sysmem::request_workers_inflight() > before,
        "track_request_worker must increment the in-flight count"
    );
    let held = sysmem::request_workers_inflight();
    drop(guard);
    assert!(
        sysmem::request_workers_inflight() < held,
        "dropping the guard must decrement the in-flight count"
    );
}

#[test]
fn record_sample_tracks_pool_peak_monotonically() {
    // A distinctive large value so a concurrent test cannot mask the assertion.
    let high = 9_000_001u64;
    sysmem::record_sample(high);
    assert!(
        sysmem::peak_pool_len() >= high,
        "peak pool length must reach the sampled value"
    );
    // A smaller subsequent sample must not lower the recorded peak.
    sysmem::record_sample(3);
    assert!(
        sysmem::peak_pool_len() >= high,
        "peak pool length must not regress on a smaller sample"
    );
}

#[test]
fn format_bytes_renders_binary_units() {
    assert_eq!(sysmem::format_bytes(0), "0 B");
    assert_eq!(sysmem::format_bytes(1024), "1.0 KiB");
    assert_eq!(sysmem::format_bytes(1024 * 1024), "1.0 MiB");
}
