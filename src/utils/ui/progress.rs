// Progress UI implementation for the dumper.
use crate::collect::dump::request::{BACKOFF_ACTIVE, RETRY_COUNT};
use crate::utils::logger::config::{DUMP_PAUSED, warning_count};
use crate::utils::logger::{
    LiveRegionState, PROGRESS_LINE_ACTIVE, STDOUT_LOGS_DURING_DUMP, replace_live_region,
};
use crate::utils::mutex::lock_force;
use crate::utils::ui::{Icon, UiMode, blue, dim, icon, mode};
use crate::utils::writer::actor::WriterHandle;

use std::collections::HashMap;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Holds the dynamic data displayed in the progress UI.
#[derive(Debug)]
pub struct ProgressState {
    pub sent: u64,
    pub in_flight: u64,
    pub retries: u64,
    pub warnings: u64,
    pub elapsed_secs: u64,
    /// Recent request rate (HTTP requests/second) over a short sliding window,
    /// so it reflects current throughput rather than a cumulative average that
    /// decays misleadingly during the long tail of a run.
    pub throughput: f64,
    /// Writer actor channel usage, 0–100 %. Shown only when > 0.
    pub writer_backpressure: u64,
    /// Current concurrency window for each service.
    pub concurrency_windows: HashMap<String, usize>,
    /// Number of request slots currently sleeping in a retry backoff (non-zero = degraded).
    pub backoff_active: u64,
    /// Per-second samples of the cumulative `sent` counter, used to compute the
    /// sliding-window `throughput`. Bounded to `THROUGHPUT_WINDOW_SECS + 1`.
    pub recent_sent: std::collections::VecDeque<u64>,
}

/// Sliding window (seconds) over which the request rate is averaged.
const THROUGHPUT_WINDOW_SECS: usize = 10;

impl Default for ProgressState {
    fn default() -> Self {
        Self {
            sent: 0,
            in_flight: 0,
            retries: 0,
            warnings: 0,
            elapsed_secs: 0,
            throughput: 0.0,
            writer_backpressure: 0,
            concurrency_windows: HashMap::new(),
            backoff_active: 0,
            recent_sent: std::collections::VecDeque::new(),
        }
    }
}

/// Render the progress block as a multi‑line string.
/// If verbosity >= 1, adds a line showing current concurrency windows.
pub fn render(state: &ProgressState, verbosity: u8) -> String {
    // Spinner frame based on elapsed seconds (0‑7)
    let spinner = icon(Icon::Spinner((state.elapsed_secs % 8) as u8));

    // First line – title
    let title = format!("{} {}", spinner, blue("DUMP PROGRESS"));

    // Second line – counters
    let counters = match (state.warnings > 0, state.backoff_active > 0) {
        (true, true) => format!(
            "  {} {}   {} {}   {} {}   {} {}   {} {}",
            dim("Requests:"),
            state.sent,
            dim("In‑flight:"),
            state.in_flight,
            dim("Retries:"),
            state.retries,
            dim("Warnings:"),
            state.warnings,
            dim("Backoff:"),
            state.backoff_active,
        ),
        (true, false) => format!(
            "  {} {}   {} {}   {} {}   {} {}",
            dim("Requests:"),
            state.sent,
            dim("In‑flight:"),
            state.in_flight,
            dim("Retries:"),
            state.retries,
            dim("Warnings:"),
            state.warnings
        ),
        (false, true) => format!(
            "  {} {}   {} {}   {} {}   {} {}",
            dim("Requests:"),
            state.sent,
            dim("In‑flight:"),
            state.in_flight,
            dim("Retries:"),
            state.retries,
            dim("Backoff:"),
            state.backoff_active,
        ),
        (false, false) => format!(
            "  {} {}   {} {}   {} {}",
            dim("Requests:"),
            state.sent,
            dim("In‑flight:"),
            state.in_flight,
            dim("Retries:"),
            state.retries,
        ),
    };

    // Format elapsed time as HH:MM:SS
    let hrs = state.elapsed_secs / 3600;
    let mins = (state.elapsed_secs % 3600) / 60;
    let secs = state.elapsed_secs % 60;
    let elapsed = format!("{:02}:{:02}:{:02}", hrs, mins, secs);

    // Third line – stats (includes writer backpressure when non-zero)
    let stats = if state.writer_backpressure > 0 {
        format!(
            "  {} {}   {} {:.2} req/s   {} {}%",
            dim("Elapsed:"),
            elapsed,
            dim("Rate:"),
            state.throughput,
            dim("Writer queue:"),
            state.writer_backpressure,
        )
    } else {
        format!(
            "  {} {}   {} {:.2} req/s",
            dim("Elapsed:"),
            elapsed,
            dim("Rate:"),
            state.throughput
        )
    };

    // Fourth line – concurrency windows (only if verbosity >= 1)
    let windows = if verbosity >= 1 && !state.concurrency_windows.is_empty() {
        let mut sorted_windows: Vec<_> = state.concurrency_windows.iter().collect();
        sorted_windows.sort_by_key(|(s, _)| *s);
        let window_str = sorted_windows
            .iter()
            .map(|(s, w)| format!("{}:{}", s, w))
            .collect::<Vec<_>>()
            .join(", ");
        format!("  {} {}", dim("Windows:"), window_str)
    } else {
        "".to_string()
    };

    // "Performing collect" is printed once as a static line by start_ticker()
    // before the live region is set up, so it is not included in the render.
    // A single leading blank line maintains visual separation.
    if windows.is_empty() {
        format!("\n{}\n{}\n{}", title, counters, stats)
    } else {
        format!("\n{}\n{}\n{}\n{}", title, counters, stats, windows)
    }
}

/// Starts a background ticker thread that updates the UI once per second.
///
/// * `state` – shared progress state guarded by a mutex.
/// * `stop` – atomic flag to end the thread.
/// * `paused` – when true, the ticker updates elapsed time but suppresses rendering
///   (used during interactive prerequisite re-check prompts).
/// * `writer` – optional writer handle used to sample channel backpressure.
pub fn start_ticker(
    state: Arc<Mutex<ProgressState>>,
    stop: Arc<AtomicBool>,
    // Pause *source counter*: the ticker pauses while any source holds it > 0.
    paused: Arc<AtomicUsize>,
    writer: Option<WriterHandle>,
    verbosity: u8,
) -> JoinHandle<()> {
    // Print the "Performing collect" label once as a static line, above the live region.
    // In Color mode the label starts blue; finalize_performing_collect_label() will
    // overwrite it in white at the end of the dump when no logs were displayed.
    if mode() == UiMode::Color {
        println!();
        println!("  {} {}", icon(Icon::Selected), blue("Performing collect"));
    }
    thread::spawn(move || {
        // NoColor / non-TTY runs disable the live region entirely: there is no
        // in-place region to refresh, and progress is conveyed by the per-API log
        // lines + the final summary. Skip the whole ticker so it doesn't wake
        // every second for the entire dump building render strings nobody sees.
        if mode() != UiMode::Color {
            return;
        }
        // Initial render. Only in Color mode: the live region updates in place
        // via cursor control, which is disabled in NoColor/non-TTY runs — there
        // a one-shot "Requests: 0" snapshot would just freeze in the output, so
        // we rely on the per-API log lines and the final summary instead.
        if mode() == UiMode::Color {
            let txt = {
                let s = lock_force(&state);
                render(&s, verbosity)
            };
            // Paint the first frame through the live region (not println) so it sets
            // PROGRESS_LINE_ACTIVE = true. The ticker loop reads that flag to choose
            // in-place overwrite vs. fresh print; leaving it false here would make the
            // first tick reprint a duplicate block.
            replace_live_region(&txt, false, |lines| LiveRegionState::Progress { lines });
        }
        // Ticker loop
        while !stop.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(1000));

            // Skip rendering and clock advancement while paused (a SIGINT menu or an
            // interactive prereq prompt is showing). The pause tears the live region
            // down (clearing PROGRESS_LINE_ACTIVE), which is what drives the fresh-print
            // decision below on resume. DUMP_PAUSED (process-wide stdout suppression)
            // is honored too: a fatal block raises it before printing and never
            // releases it, so the ticker must not repaint below the block — or over
            // the "Press Enter to exit" prompt — while the process waits to exit.
            if paused.load(Ordering::Relaxed) > 0 || DUMP_PAUSED.load(Ordering::Relaxed) > 0 {
                continue;
            }

            // Advance the elapsed clock, sample writer backpressure, and refresh counters.
            {
                let mut s = lock_force(&state);
                s.elapsed_secs = s.elapsed_secs.saturating_add(1);
                // Sliding-window request rate: sample `sent` once per second and
                // average the delta over the last THROUGHPUT_WINDOW_SECS samples.
                let sent_now = s.sent;
                s.recent_sent.push_back(sent_now);
                while s.recent_sent.len() > THROUGHPUT_WINDOW_SECS + 1 {
                    s.recent_sent.pop_front();
                }
                if let (Some(&oldest), Some(&newest)) =
                    (s.recent_sent.front(), s.recent_sent.back())
                {
                    let span = s.recent_sent.len().saturating_sub(1);
                    s.throughput = if span > 0 {
                        newest.saturating_sub(oldest) as f64 / span as f64
                    } else {
                        0.0
                    };
                }
                if let Some(ref w) = writer {
                    s.writer_backpressure = w.queue_usage_pct();
                }
                s.retries = RETRY_COUNT.load(std::sync::atomic::Ordering::Relaxed);
                s.warnings = warning_count();
                s.backoff_active = BACKOFF_ACTIVE.load(std::sync::atomic::Ordering::Relaxed);
            }

            let txt = {
                let s = lock_force(&state);
                render(&s, verbosity)
            };

            // `PROGRESS_LINE_ACTIVE` is the authoritative "the block is currently on
            // screen" flag: set when we paint it, cleared when a pause tears it down via
            // `clear_progress_line()`. When the block is on screen we overwrite the
            // previous frame in place (cursor-up). When a pause tore it down we must do a
            // FRESH print at the current cursor — an in-place cursor-up would walk the
            // cursor up over the log lines printed since the pause and overwrite them.
            // (Sampling `paused` cannot detect a menu opened and dismissed within a
            // single tick, which is why this uses the persistent flag instead.)
            if PROGRESS_LINE_ACTIVE.load(Ordering::Relaxed) {
                // In place: overwrite the previous frame (cursor-up by its height).
                replace_live_region(&txt, true, |lines| LiveRegionState::Progress { lines });
            } else {
                // Fresh print after a pause: paint at the current cursor without
                // moving up.
                replace_live_region(&txt, false, |lines| LiveRegionState::Progress { lines });
            }
        }
    })
}

/// In Color mode, if no logs were written to the terminal during the dump,
/// moves the cursor up one line to overwrite the "Performing collect" label
/// with the non-blue version. Must be called immediately after
/// `clear_progress_line()`, while no live region is active and the ticker
/// thread has been joined.
pub fn finalize_performing_collect_label() {
    if mode() != UiMode::Color || STDOUT_LOGS_DURING_DUMP.load(Ordering::Relaxed) {
        return;
    }
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(b"\x1b[1A\r\x1b[2K");
    let _ = out.write_all(format!("  {} Performing collect\n", icon(Icon::Selected)).as_bytes());
    let _ = out.flush();
}

#[test]
fn ticker_terminates() {
    // In Color mode (the test default) the ticker mutates the process-global
    // ACTIVE_LIVE_REGION; serialise on the shared lock so this 1.2 s test cannot
    // race the live-region tests in `logger` / `live_region`.
    let _guard = crate::utils::logger::live_region::LIVE_REGION_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let state = Arc::new(Mutex::new(ProgressState::default()));
    let stop = Arc::new(AtomicBool::new(false));
    let paused = Arc::new(AtomicUsize::new(0));
    let handle = start_ticker(
        Arc::clone(&state),
        Arc::clone(&stop),
        Arc::clone(&paused),
        None,
        0,
    );
    // Let it run for a short while
    std::thread::sleep(std::time::Duration::from_millis(1200));
    // Signal stop
    stop.store(true, Ordering::Relaxed);
    // Join should complete quickly
    let join_result = handle.join();
    assert!(join_result.is_ok());
    // Ensure elapsed increased at least 1 second
    let elapsed = lock_force(&state).elapsed_secs;
    assert!(elapsed >= 1);
}

/// render() must show "Backoff: N" only when backoff_active > 0.
#[test]
fn render_shows_backoff_when_nonzero() {
    let mut state = ProgressState {
        backoff_active: 3,
        sent: 10,
        in_flight: 5,
        retries: 2,
        ..ProgressState::default()
    };

    let txt = render(&state, 0);
    assert!(
        txt.contains("Backoff:"),
        "Backoff label must appear when backoff_active > 0"
    );
    assert!(
        txt.contains(" 3\n"),
        "Backoff value '3' must appear as a separate token"
    );

    // When backoff_active == 0, the label must be absent.
    state.backoff_active = 0;
    let txt = render(&state, 0);
    assert!(
        !txt.contains("Backoff:"),
        "Backoff label must be hidden when zero"
    );
}
