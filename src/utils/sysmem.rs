//! Memory observability for large-tenant diagnosis.
//!
//! Two complementary signals, sampled periodically by the coordinator and
//! surfaced in `oradaz.log` (periodic `debug!`), the end-of-run summary, and
//! `metadata.json`:
//!
//! * **Process RSS** ([`rss_bytes`]) — OS-level resident set size, the
//!   ground-truth "are we about to OOM" number. Catches allocator overhead and
//!   transient JSON-parse spikes that the in-process gauges below cannot see.
//! * **In-process gauges** — the *direct* signal for where memory goes: the
//!   total URL-pool length (`current_urls`, sampled by the coordinator), the
//!   number of in-flight response workers ([`response_workers_inflight`]) — each
//!   owning a `Box<ResponseContent>` (a fully parsed JSON page) — and the number
//!   of in-flight request workers ([`request_workers_inflight`]), which park on an
//!   AIMD slot or a rate-limit cooldown when a service is throttled.
//!
//! A suspected — but never reproduced — large-tenant OOM motivated this module:
//! the goal is to make such a run diagnosable after the fact rather than to
//! change any collection behaviour.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Peak process RSS (bytes) observed during the dump. `0` until first sampled.
static PEAK_RSS_BYTES: AtomicU64 = AtomicU64::new(0);
/// Peak total `current_urls` length (URL pool) observed during the dump.
static PEAK_POOL_LEN: AtomicU64 = AtomicU64::new(0);
/// Response-worker tasks currently in flight. Each owns a parsed JSON page, so
/// this doubles as an in-flight parsed-payload count.
static RESPONSE_WORKERS_INFLIGHT: AtomicUsize = AtomicUsize::new(0);

// ---------------------------------------------------------------------------
// Process RSS (OS-specific, dependency-light)
// ---------------------------------------------------------------------------

/// Current process resident set size in bytes, or `None` when the platform is
/// unsupported or the query fails (never panics — observability must not break a
/// collection).
#[cfg(target_os = "linux")]
pub fn rss_bytes() -> Option<u64> {
    // `/proc/self/status` exposes `VmRSS:` directly in kB — page-size-independent
    // and dependency-free, unlike `/proc/self/statm` whose unit is pages.
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            // Format: "VmRSS:\t   12345 kB"
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb.saturating_mul(1024));
        }
    }
    None
}

/// Current process working-set size in bytes (Windows analogue of RSS).
///
/// Uses `K32GetProcessMemoryInfo` (exported by kernel32, so no psapi link step is
/// needed under the MinGW cross-compile) on the `GetCurrentProcess` pseudo-handle.
#[cfg(windows)]
pub fn rss_bytes() -> Option<u64> {
    use windows_sys::Win32::System::ProcessStatus::{
        K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    // SAFETY: an all-zero `PROCESS_MEMORY_COUNTERS` is a valid initial value (every
    // field is a plain integer); we set `cb` to the struct size as the API requires
    // before the call.
    let mut counters: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
    counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle requiring no release; we
    // pass a valid pointer to `counters` and the matching `cb` size.
    let ok = unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, counters.cb) };
    if ok != 0 {
        Some(counters.WorkingSetSize as u64)
    } else {
        None
    }
}

/// RSS is not implemented for this platform; observability degrades to the
/// in-process gauges only.
#[cfg(not(any(target_os = "linux", windows)))]
pub fn rss_bytes() -> Option<u64> {
    None
}

// ---------------------------------------------------------------------------
// Response-worker gauge
// ---------------------------------------------------------------------------

/// RAII guard tracking one in-flight response worker. Created via
/// [`track_response_worker`] at the top of a worker task; the count is
/// decremented when the guard drops (covering both normal completion and a
/// panic-unwind in debug/test builds).
pub struct ResponseWorkerGuard(());

impl Drop for ResponseWorkerGuard {
    fn drop(&mut self) {
        RESPONSE_WORKERS_INFLIGHT.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Increments the response-worker gauge and returns a guard that decrements it on
/// drop. Hold the guard for the lifetime of the worker task.
pub fn track_response_worker() -> ResponseWorkerGuard {
    RESPONSE_WORKERS_INFLIGHT.fetch_add(1, Ordering::Relaxed);
    ResponseWorkerGuard(())
}

/// Number of response-worker tasks currently in flight.
pub fn response_workers_inflight() -> usize {
    RESPONSE_WORKERS_INFLIGHT.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Request-worker gauge
// ---------------------------------------------------------------------------

/// Request-worker tasks currently in flight. A request worker is spawned per
/// `ApiCall`, then *parks* on its per-service AIMD slot and, when the service is
/// throttled, on the rate-limit cooldown — so a throttled service accumulates
/// parked request workers (each holding its `ApiCall`). Unlike response workers,
/// these had no gauge, leaving a throttle-induced backlog invisible to the memory
/// observability; this closes that gap.
static REQUEST_WORKERS_INFLIGHT: AtomicUsize = AtomicUsize::new(0);

/// RAII guard tracking one in-flight request worker. Created via
/// [`track_request_worker`] at the top of a worker task; the count is decremented
/// when the guard drops (covering normal completion and a panic-unwind in
/// debug/test builds).
pub struct RequestWorkerGuard(());

impl Drop for RequestWorkerGuard {
    fn drop(&mut self) {
        REQUEST_WORKERS_INFLIGHT.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Increments the request-worker gauge and returns a guard that decrements it on
/// drop. Hold the guard for the lifetime of the worker task.
pub fn track_request_worker() -> RequestWorkerGuard {
    REQUEST_WORKERS_INFLIGHT.fetch_add(1, Ordering::Relaxed);
    RequestWorkerGuard(())
}

/// Number of request-worker tasks currently in flight (dispatched, possibly parked
/// on an AIMD slot or a rate-limit cooldown).
pub fn request_workers_inflight() -> usize {
    REQUEST_WORKERS_INFLIGHT.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Peak tracking
// ---------------------------------------------------------------------------

/// Records one periodic sample: refreshes the pool-length and RSS peaks and
/// returns the RSS that was sampled (so the caller can log it without a second
/// OS query). `pool_len` is the current total `current_urls` length.
pub fn record_sample(pool_len: u64) -> Option<u64> {
    update_peak(&PEAK_POOL_LEN, pool_len);
    let rss = rss_bytes();
    if let Some(r) = rss {
        update_peak(&PEAK_RSS_BYTES, r);
    }
    rss
}

/// Monotonically raises `peak` to `value` if `value` is larger. Lock-free CAS so
/// it is safe to call from the coordinator without serialising on a mutex.
fn update_peak(peak: &AtomicU64, value: u64) {
    let mut cur = peak.load(Ordering::Relaxed);
    while value > cur {
        match peak.compare_exchange_weak(cur, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(actual) => cur = actual,
        }
    }
}

/// Peak process RSS (bytes) observed so far. `0` when never sampled.
pub fn peak_rss_bytes() -> u64 {
    PEAK_RSS_BYTES.load(Ordering::Relaxed)
}

/// Peak total URL-pool length observed so far.
pub fn peak_pool_len() -> u64 {
    PEAK_POOL_LEN.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

/// Renders a byte count with binary units (e.g. `412.0 MiB`) for log and summary
/// lines.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{:.1} {}", value, UNITS[unit])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_bytes_uses_binary_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(format_bytes(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }

    #[test]
    fn update_peak_is_monotonic() {
        let peak = AtomicU64::new(0);
        update_peak(&peak, 100);
        assert_eq!(peak.load(Ordering::Relaxed), 100);
        update_peak(&peak, 50); // smaller: no change
        assert_eq!(peak.load(Ordering::Relaxed), 100);
        update_peak(&peak, 250); // larger: raised
        assert_eq!(peak.load(Ordering::Relaxed), 250);
    }
}
