use crate::FL;

use dashmap::DashMap;
use log::{debug, trace};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tokio::sync::Notify;
use tokio::time::Instant;

/// Minimum interval between two AIMD window reductions for the same service.
///
/// A single congestion event throttles many in-flight requests at once; without
/// this guard each of their 429 responses would halve the window, collapsing it
/// from `max` to `min` in one burst and then forcing a slow additive re-ramp.
/// Coalescing reductions to at most one per guard keeps a congestion event to a
/// single halving, which preserves throughput on bursty throttlers (notably ARM,
/// where high concurrency is benchmark-proven beneficial).
const AIMD_DECREASE_GUARD_MS: u64 = 1000;

/// Tracks concurrency state for a specific service.
struct ServiceWindow {
    /// Current maximum number of concurrent requests allowed for this service.
    current_window: AtomicUsize,
    /// Number of successful requests since the last window increase.
    success_count: AtomicUsize,
    /// Current number of requests in flight for this service.
    in_flight: AtomicUsize,
    /// Per-service AIMD upper bound (overridable via `serviceOverrides`).
    max_window: usize,
    /// Per-service AIMD lower bound (overridable via `serviceOverrides`).
    min_window: usize,
    /// Wakes tasks waiting for a slot *in this service*. Per-service so a
    /// `release_slot` only wakes waiters that can actually use the freed slot,
    /// instead of every parked task across all services (~8192 worst case).
    slot_notifier: Notify,
    /// Monotonic baseline for `last_decrease_ms` (set at construction).
    created_at: Instant,
    /// Millis since `created_at` of the last AIMD reduction (`0` = never). Used to
    /// coalesce a burst of concurrent 429s into a single halving — see
    /// [`AIMD_DECREASE_GUARD_MS`].
    last_decrease_ms: AtomicU64,
    /// Lowest `current_window` ever reached via a 429 halving (the AIMD *floor*).
    /// Observability only. Initialised to `max_window` (the ceiling) regardless of
    /// start mode, so "floor < max" unambiguously means "was actually reduced" —
    /// otherwise a slow-start service (which *starts* at `min_window`) would report
    /// a floor of `min` it never collapsed to. Pairs with `decrease_count` (0 =
    /// never reduced).
    min_window_reached: AtomicUsize,
    /// Number of effective AIMD halvings (window actually reduced) for this
    /// service. With `min_window_reached` it tells a one-off dip from a window
    /// hammered to the floor in repeated bursts. Observability only.
    decrease_count: AtomicU64,
    /// Number of additive AIMD increases (window actually ramped up by 1) for
    /// this service. The **symmetric** companion to `decrease_count`: together
    /// they say whether the window *recovered* after a collapse (increases ≈
    /// decreases → healthy ramp) or stayed hammered down (decreases ≫ increases →
    /// stuck). The signal that verifies the cooldown-order fix actually let the
    /// window re-ramp, and a key input to the per-bucket re-key (B) decision.
    /// Observability only.
    increase_count: AtomicU64,
    /// Millis since `created_at` at which the window most recently *entered* its
    /// floor (`min_window`) via a 429 halving; `0` when not currently at the
    /// collapsed floor. Used to accumulate `time_at_floor_nanos` across
    /// floor-enter/leave transitions. A slow-start window that merely *starts* at
    /// `min` is NOT counted (only a real collapse sets this), mirroring
    /// `min_window_reached`'s init.
    floor_since_ms: AtomicU64,
    /// Total nanoseconds the window spent collapsed at its floor (`min_window`).
    /// **Duration** companion to `decrease_count` (a count) and `min_window_reached`
    /// (a depth): a window that collapses once and sits at the floor for 18 min
    /// (the run_001 pathology) looks identical to a brief dip in the count alone —
    /// this distinguishes them. The direct measure of the B-trigger symptom
    /// ("fast endpoints stuck at the floor during convergence"). Observability
    /// only, and **best-effort**: it may slightly *under*-count (never over-count)
    /// under a cross-thread enter/leave reorder — see the accumulation site in
    /// `report_success`.
    time_at_floor_nanos: AtomicU64,
    /// Number of times a request worker had to park in `acquire_slot` **while the
    /// window was at its ceiling** (`current >= max_window`). Gated on the ceiling
    /// on purpose: a raw "parked because full" fires during healthy saturation
    /// *and* mid-collapse (window halved by 429), conflating three regimes. Parking
    /// at the *ceiling* isolates "demand exceeded the maximum *allowed* concurrency"
    /// = the cap is the binding constraint — the signal that decides whether raising
    /// `concurrencyMaxWindow` would help (paired with `retries_rate_limit`: high
    /// ceiling-parks + low 429 ⇒ raise is safe). Observability only.
    slot_wait_events: AtomicU64,
    /// Total nanoseconds workers spent parked at the ceiling (same gate as
    /// `slot_wait_events`). Magnitude companion to the event count.
    slot_wait_nanos: AtomicU64,
}

impl ServiceWindow {
    /// `start_at_min` selects the initial concurrency window. When `false`
    /// (default) the window starts at `max_window`, probing the API at full
    /// concurrency immediately. When `true` it starts at `min_window` and ramps
    /// up additively via `report_success`, so the opening burst is gentle —
    /// fewer initial 429s on strict throttlers like ARM.
    fn new(min_window: usize, max_window: usize, start_at_min: bool) -> Self {
        // Defense in depth: a misconfiguration (global concurrencyMinWindow above a
        // per-service baseline max) must never yield min > max, which would let a
        // 429 *raise* the window via `report_429`'s `.max(min_window)`. Clamp here so
        // the window always stays within a sane [min, max] with min <= max.
        let min_window = min_window.min(max_window);
        let start = if start_at_min { min_window } else { max_window };
        Self {
            current_window: AtomicUsize::new(start),
            success_count: AtomicUsize::new(0),
            in_flight: AtomicUsize::new(0),
            max_window,
            min_window,
            slot_notifier: Notify::new(),
            created_at: Instant::now(),
            last_decrease_ms: AtomicU64::new(0),
            min_window_reached: AtomicUsize::new(max_window),
            decrease_count: AtomicU64::new(0),
            increase_count: AtomicU64::new(0),
            floor_since_ms: AtomicU64::new(0),
            time_at_floor_nanos: AtomicU64::new(0),
            slot_wait_events: AtomicU64::new(0),
            slot_wait_nanos: AtomicU64::new(0),
        }
    }
}

/// Manages request concurrency per-service.
///
/// It uses an Additive Increase/Multiplicative Decrease (AIMD) strategy to dynamically
/// adjust the number of concurrent requests per service based on the server's response.
/// This prevents overwhelming the API while maximizing throughput.
///
/// Each service has its own `(min, max)` bounds: a global fallback used for any
/// service not explicitly listed, plus per-service overrides supplied via
/// `serviceOverrides` in the XML config. ARM-style strict throttling on
/// `resources` and the much more permissive Microsoft Graph thus stop fighting
/// over a single global cap.
pub struct ConcurrencyController {
    /// Per-service concurrency windows.
    service_windows: DashMap<String, Arc<ServiceWindow>>,
    /// Fallback upper bound for any single service window when no override applies.
    max_window: usize,
    /// Fallback lower bound for any single service window when no override applies.
    min_window: usize,
    /// Per-service bound overrides, keyed by service name.
    service_bounds: HashMap<String, (usize, usize)>,
    /// When `true`, each service window starts at its `min_window` and ramps up
    /// via AIMD; when `false` (default) it starts at `max_window`, probing at
    /// full concurrency immediately. Set via `with_slow_start`.
    start_at_min: bool,
}

impl ConcurrencyController {
    /// Creates a new `ConcurrencyController` with no per-service overrides.
    pub fn new(min_window: usize, max_window: usize) -> Self {
        Self {
            service_windows: DashMap::new(),
            max_window,
            min_window,
            service_bounds: HashMap::new(),
            start_at_min: false,
        }
    }

    /// Creates a new `ConcurrencyController` with per-service bounds.
    ///
    /// `service_bounds` maps `service name → (min_window, max_window)`. Services
    /// not present in the map use the global `(min_window, max_window)`
    /// fallback.
    pub fn with_service_bounds(
        min_window: usize,
        max_window: usize,
        service_bounds: HashMap<String, (usize, usize)>,
    ) -> Self {
        Self {
            service_windows: DashMap::new(),
            max_window,
            min_window,
            service_bounds,
            start_at_min: false,
        }
    }

    /// Enables or disables slow-start: when enabled, each service window starts
    /// at its `min_window` and ramps up via AIMD rather than starting at
    /// `max_window`. Builder-style so the production path can opt in without
    /// changing the two constructor signatures (and their many call sites).
    /// Default is `false`.
    pub fn with_slow_start(mut self, slow_start: bool) -> Self {
        self.start_at_min = slow_start;
        self
    }

    fn bounds_for(&self, service: &str) -> (usize, usize) {
        self.service_bounds
            .get(service)
            .copied()
            .unwrap_or((self.min_window, self.max_window))
    }

    fn window_for(&self, service: &str) -> Arc<ServiceWindow> {
        if let Some(w) = self.service_windows.get(service) {
            return w.clone();
        }
        let (min_w, max_w) = self.bounds_for(service);
        let start = if self.start_at_min { min_w } else { max_w };
        self.service_windows
            .entry(service.to_string())
            .or_insert_with(|| {
                debug!(
                    "{:FL$}Initializing window for service {:?}: start={} min={} max={} slow_start={}",
                    "ConcurrencyController", service, start, min_w, max_w, self.start_at_min
                );
                Arc::new(ServiceWindow::new(min_w, max_w, self.start_at_min))
            })
            .clone()
    }

    /// Acquires a slot for the given service.
    ///
    /// Waits until the per-service in-flight count is below the current window, then
    /// increments the counter atomically.
    pub async fn acquire_slot(&self, service: &str) {
        let window = self.window_for(service);

        // Dynamic window limit per service.
        //
        // `release_slot` wakes waiters with `notify_waiters()`, which — unlike
        // `notify_one()` — does NOT bank a permit for a later `notified().await`.
        // A naive "check, then await" loop could therefore lose a release that
        // fires between the check and the park and, once the last in-flight request
        // has drained, stay parked forever. We avoid that by registering on the
        // notifier (via `enable()`) BEFORE the *final* window check whenever the
        // window looks full: any `notify_waiters()` fired after `enable()` is
        // delivered to the pending `.await`, and one fired just before it is caught
        // by the re-check. The uncontended fast path never touches the notifier.
        loop {
            // Fast path: try to claim a slot without touching the notifier.
            // A failed CAS means another task claimed it first — retry immediately.
            let in_flight = window.in_flight.load(Ordering::Acquire);
            let current = window.current_window.load(Ordering::Relaxed);
            if in_flight < current {
                if window
                    .in_flight
                    .compare_exchange(
                        in_flight,
                        in_flight + 1,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    trace!(
                        "{:FL$}Slot acquired for service {:?} ({}/{} in-flight)",
                        "ConcurrencyController",
                        service,
                        in_flight + 1,
                        current
                    );
                    return;
                }
                continue;
            }

            // Window full: register on *this service's* notifier, then re-check
            // before parking so a release between the fast-path check and `enable()`
            // is not lost.
            let notified = window.slot_notifier.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            let in_flight = window.in_flight.load(Ordering::Acquire);
            let current = window.current_window.load(Ordering::Relaxed);
            if in_flight < current {
                continue;
            }

            // Still full and we are registered: park until a slot is released.
            // Count the park as cap-contention ONLY when the window is at its
            // ceiling (`current >= max_window`): parking while the window is reduced
            // (post-429) is throttle-bound, not cap-bound, and must not pollute the
            // M1 "is the ceiling binding?" signal. See `slot_wait_events`.
            let at_ceiling = current >= window.max_window;
            trace!(
                "{:FL$}Slot parking for service {:?} (window full: {}/{}, ceiling={})",
                "ConcurrencyController", service, in_flight, current, at_ceiling
            );
            if at_ceiling {
                window.slot_wait_events.fetch_add(1, Ordering::Relaxed);
                let park_start = Instant::now();
                notified.as_mut().await;
                window.slot_wait_nanos.fetch_add(
                    park_start.elapsed().as_nanos().min(u64::MAX as u128) as u64,
                    Ordering::Relaxed,
                );
            } else {
                notified.as_mut().await;
            }
        }
    }

    /// Releases a slot for the given service.
    pub fn release_slot(&self, service: &str) {
        if let Some(window) = self.service_windows.get(service) {
            let prev = window.in_flight.fetch_sub(1, Ordering::Release);
            trace!(
                "{:FL$}Slot released for service {:?} ({} remaining in-flight)",
                "ConcurrencyController",
                service,
                prev.saturating_sub(1)
            );
            // Wake every waiter *for this service* (not just one): the freed slot
            // may be claimable by only some of them, and `notify_waiters` banks no
            // permit. Each service has its own notifier, so this wake reaches only
            // tasks waiting on this service, not parked tasks of other services.
            // `acquire_slot` registers its `Notified` via `enable()` before its
            // final window check, so this wake cannot be lost despite not banking a
            // permit. `notify_waiters` is synchronous (no await held across the
            // DashMap shard lock). No window ⇒ no prior acquire ⇒ no waiter, so
            // there is nothing to notify when absent.
            window.slot_notifier.notify_waiters();
        }
    }

    /// Reports a successful request, potentially increasing the service window.
    ///
    /// The window is increased by 1 when the number of successful requests reaches half
    /// of the current window size.
    pub fn report_success(&self, service: &str) {
        if let Some(window) = self.service_windows.get(service) {
            let count = window.success_count.fetch_add(1, Ordering::Relaxed) + 1;
            let mut current = window.current_window.load(Ordering::Relaxed);

            // Increase the window by 1 once successes reach half the current window.
            // CAS the increment (re-checking `current < max_window` against the
            // observed value) so two concurrent successes cannot both step past
            // max_window — the asymmetric sibling of the CAS in `report_429`.
            if count >= current.div_ceil(2) {
                loop {
                    if current >= window.max_window {
                        break;
                    }
                    match window.current_window.compare_exchange(
                        current,
                        current + 1,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => {
                            window.success_count.store(0, Ordering::Relaxed);
                            // Observability: an effective additive increase (the
                            // symmetric companion to `decrease_count`).
                            window.increase_count.fetch_add(1, Ordering::Relaxed);
                            // If this increment left the collapsed floor, close the
                            // open floor segment. `swap(0)` reads-and-clears
                            // atomically, so a concurrent leaver gets 0 and skips —
                            // never a double-count. `time_at_floor` is **best-effort
                            // observability**: `floor_since_ms` is a separate atomic
                            // from `current_window` with no fence between the
                            // window-CAS and the floor-flag update, so cross-thread
                            // reordering of a concurrent enter (`report_429`) and
                            // this leave can drop a floor episode's start — either
                            // here (read `0` before the enter's store lands) or at
                            // the enter (its `compare_exchange(0,…)` fails because
                            // this leave's `swap` has not cleared the prior value
                            // yet). Both only ever **under**-count, by a span bounded
                            // to that few-instruction reorder window; the metric
                            // never over-counts, panics, or corrupts. Making it exact
                            // would need a per-window lock on the hot AIMD path —
                            // not worth it for a diagnostic counter.
                            if current == window.min_window {
                                let since = window.floor_since_ms.swap(0, Ordering::AcqRel);
                                if since != 0 {
                                    let now_ms = window.created_at.elapsed().as_millis() as u64;
                                    window.time_at_floor_nanos.fetch_add(
                                        now_ms.saturating_sub(since).saturating_mul(1_000_000),
                                        Ordering::Relaxed,
                                    );
                                }
                            }
                            debug!(
                                "{:FL$}AIMD window increased to {} for service {:?}",
                                "ConcurrencyController",
                                current + 1,
                                service
                            );
                            break;
                        }
                        Err(actual) => current = actual,
                    }
                }
            }
        }
    }

    /// Reports a 429 (Too Many Requests) error, reducing the service window.
    ///
    /// The window is halved to rapidly reduce pressure on the server.
    pub fn report_429(&self, service: &str) {
        if let Some(window) = self.service_windows.get(service) {
            // A 429 always breaks the success streak, even when the reduction below
            // is coalesced into a sibling 429's halving.
            window.success_count.store(0, Ordering::Relaxed);

            // Coalesce reductions: a single congestion event throttles many
            // in-flight requests at once, but the window should halve only once per
            // event (otherwise a burst collapses it straight to `min`, then it has
            // to re-ramp additively). Claim the epoch with a CAS on
            // `last_decrease_ms` so exactly one 429 of a burst performs the halving;
            // the others return early.
            let now_ms = window.created_at.elapsed().as_millis() as u64;
            let last_ms = window.last_decrease_ms.load(Ordering::Relaxed);
            if last_ms != 0 && now_ms.saturating_sub(last_ms) < AIMD_DECREASE_GUARD_MS {
                trace!(
                    "{:FL$}AIMD reduction coalesced for service {:?} (window already halved within {}ms)",
                    "ConcurrencyController", service, AIMD_DECREASE_GUARD_MS
                );
                return;
            }
            if window
                .last_decrease_ms
                .compare_exchange(last_ms, now_ms.max(1), Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
            {
                // A concurrent 429 just claimed this epoch and will halve the window.
                trace!(
                    "{:FL$}AIMD reduction coalesced for service {:?} (lost epoch CAS)",
                    "ConcurrencyController", service
                );
                return;
            }

            let mut current = window.current_window.load(Ordering::Relaxed);
            loop {
                let new_window = (current / 2).max(window.min_window);
                match window.current_window.compare_exchange(
                    current,
                    new_window,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        // Observability: record the floor and count an effective
                        // collapse — both ONLY on an actual reduction. Only the
                        // epoch-winning 429 reaches here (coalesced siblings returned
                        // early above), so this counts congestion events, not
                        // individual 429s. A 429 while already at `min` is not a new
                        // collapse, so it touches neither (floor keeps its
                        // max_window init → "never reduced").
                        if new_window < current {
                            window
                                .min_window_reached
                                .fetch_min(new_window, Ordering::Relaxed);
                            window.decrease_count.fetch_add(1, Ordering::Relaxed);
                            // If this halving reached the collapsed floor, open a
                            // floor segment (for `time_at_floor_nanos`). `CAS(0→…)`
                            // so a window already at the floor — which cannot reach
                            // this `new_window < current` branch anyway — never
                            // restarts the clock. `.max(1)` keeps the sentinel
                            // non-zero. Leaving the floor is handled in
                            // `report_success`.
                            if new_window == window.min_window {
                                let _ = window.floor_since_ms.compare_exchange(
                                    0,
                                    now_ms.max(1),
                                    Ordering::AcqRel,
                                    Ordering::Relaxed,
                                );
                            }
                            debug!(
                                "{:FL$}AIMD window halved from {} to {} for service {:?} (429)",
                                "ConcurrencyController", current, new_window, service
                            );
                        } else {
                            debug!(
                                "{:FL$}AIMD window already at minimum ({}) for service {:?} on 429",
                                "ConcurrencyController", current, service
                            );
                        }
                        break;
                    }
                    Err(actual) => current = actual,
                }
            }
        }
    }

    /// Returns the current concurrency window size for a service.
    pub fn current_window(&self, service: &str) -> usize {
        self.service_windows
            .get(service)
            .map(|w| w.current_window.load(Ordering::Relaxed))
            .unwrap_or_else(|| self.bounds_for(service).1)
    }

    /// Returns a map of all currently tracked service windows.
    pub fn get_all_windows(&self) -> HashMap<String, usize> {
        self.service_windows
            .iter()
            .map(|r| {
                (
                    r.key().clone(),
                    r.value().current_window.load(Ordering::Relaxed),
                )
            })
            .collect()
    }

    /// Returns the current in-flight request count for every tracked service.
    pub fn get_all_in_flight(&self) -> HashMap<String, usize> {
        self.service_windows
            .iter()
            .map(|r| (r.key().clone(), r.value().in_flight.load(Ordering::Relaxed)))
            .collect()
    }

    /// Returns the lowest window each service was ever reduced to via 429 halving
    /// (the AIMD floor). Observability for the throttling-collapse signal.
    pub fn get_all_min_windows(&self) -> HashMap<String, usize> {
        self.service_windows
            .iter()
            .map(|r| {
                (
                    r.key().clone(),
                    r.value().min_window_reached.load(Ordering::Relaxed),
                )
            })
            .collect()
    }

    /// Returns the number of effective AIMD halvings per service (congestion
    /// events that actually reduced the window). Pairs with `get_all_min_windows`.
    pub fn get_all_decreases(&self) -> HashMap<String, u64> {
        self.service_windows
            .iter()
            .map(|r| {
                (
                    r.key().clone(),
                    r.value().decrease_count.load(Ordering::Relaxed),
                )
            })
            .collect()
    }

    /// Returns the number of effective AIMD additive increases per service (the
    /// symmetric companion to `get_all_decreases`): increases ≈ decreases means
    /// the window recovered after each collapse; decreases ≫ increases means it
    /// stayed hammered down. Observability for the cooldown-fix verification and
    /// the per-bucket re-key (B) decision.
    pub fn get_all_increases(&self) -> HashMap<String, u64> {
        self.service_windows
            .iter()
            .map(|r| {
                (
                    r.key().clone(),
                    r.value().increase_count.load(Ordering::Relaxed),
                )
            })
            .collect()
    }

    /// Returns the whole seconds each service's window spent collapsed at its
    /// floor (`min_window`). The **duration** of collapse — distinguishes a brief
    /// dip from a window pinned at the floor for many minutes (the run_001
    /// pathology). Closes any segment still open at end of dump. Call after the
    /// pipeline has drained (single-threaded, race-free).
    pub fn get_all_time_at_floor_secs(&self) -> HashMap<String, u64> {
        self.service_windows
            .iter()
            .map(|r| {
                let w = r.value();
                let mut nanos = w.time_at_floor_nanos.load(Ordering::Relaxed);
                // Window still at the floor when the run ended: add the open span.
                let since = w.floor_since_ms.load(Ordering::Relaxed);
                if since != 0 {
                    let now_ms = w.created_at.elapsed().as_millis() as u64;
                    nanos = nanos
                        .saturating_add(now_ms.saturating_sub(since).saturating_mul(1_000_000));
                }
                (r.key().clone(), nanos / 1_000_000_000)
            })
            .collect()
    }

    /// Returns the number of ceiling-contention parks per service (workers that
    /// blocked in `acquire_slot` while the window was at `max_window`). The direct
    /// signal that `concurrencyMaxWindow` is the binding constraint for a service.
    pub fn get_all_slot_wait_events(&self) -> HashMap<String, u64> {
        self.service_windows
            .iter()
            .map(|r| {
                (
                    r.key().clone(),
                    r.value().slot_wait_events.load(Ordering::Relaxed),
                )
            })
            .collect()
    }

    /// Returns total whole seconds spent parked at the ceiling per service
    /// (`slot_wait_nanos / 1e9`). Magnitude companion to `get_all_slot_wait_events`.
    pub fn get_all_slot_wait_secs(&self) -> HashMap<String, u64> {
        self.service_windows
            .iter()
            .map(|r| {
                (
                    r.key().clone(),
                    r.value().slot_wait_nanos.load(Ordering::Relaxed) / 1_000_000_000,
                )
            })
            .collect()
    }
}

impl Default for ConcurrencyController {
    fn default() -> Self {
        Self::new(2, 30)
    }
}
