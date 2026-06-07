pub mod backend;
pub mod config;
pub mod live_region;

pub use backend::{MY_LOGGER, STDOUT_LOGS_DURING_DUMP};
pub use config::{DumpPhase, NO_COLOR, Verbosity, WARN_COUNT, should_emit};
pub use live_region::{
    ACTIVE_LIVE_REGION, LIVE_REGION_TEXT, LiveRegionState, PROGRESS_LINE_ACTIVE,
    calculate_rendered_lines, clear_live_region_lines, clear_live_region_lines_raw,
    clear_progress_line, redraw_live_region, redraw_live_region_raw, tear_down_live_region,
    update_live_region_state, update_live_region_text, with_render_lock,
};

use crate::bail_fatal;
use crate::utils::errors::{Error, FatalPresentation};
use crate::utils::logger::backend::MyLogger;
use crate::utils::logger::config::{
    current_dump_phase, current_verbosity, set_dump_phase, warning_count,
};
use crate::utils::mutex::lock_fatal;
use crate::utils::mutex::lock_force;
use crate::utils::ui::err_text;
use crate::utils::writer::actor::WriterHandle;

use std::sync::atomic::Ordering;

/// Disables ANSI color output in the terminal.
pub fn set_no_color(disable: bool) {
    config::NO_COLOR.store(disable, std::sync::atomic::Ordering::Relaxed);
    crate::utils::ui::theme::set_mode(if disable {
        crate::utils::ui::theme::UiMode::NoColor
    } else {
        crate::utils::ui::theme::UiMode::Color
    });
}

/// Initializes the global logger with an optional file writer and a verbosity level.
pub fn initialize(writer: Option<WriterHandle>, verbosity: Verbosity) {
    let mut i = lock_fatal(&MY_LOGGER.inner, Error::WriterLock);
    *i = Some(MyLogger::new(writer, verbosity));
    if let Err(err) = log::set_logger(&*MY_LOGGER) {
        eprintln!(
            "[{}] Unable to initialize the logging subsystem: {}",
            err_text("ERROR"),
            err
        );
        eprintln!("Press Enter to exit.");

        let _ = std::io::stdin().read_line(&mut String::new());
        bail_fatal!(Error::WriterLock);
    }
    log::set_max_level(log::LevelFilter::Trace);
}

/// Attaches a file writer to the global logger for persistent logging.
pub fn add_writer(writer: &WriterHandle) {
    MY_LOGGER.add_writer(writer);
}

/// Removes the file writer from the global logger.
pub fn remove_writer() {
    MY_LOGGER.remove_writer();
}

/// Writes a log entry to the file writer if one is attached.
pub fn write_log(record: String) {
    // Recover from a poisoned logger mutex instead of silently dropping the log
    // (the previous lock_warn returned None on poison). Logger state is idempotent,
    // so reading it after a panic in another thread is safe and preserves the
    // post-panic log evidence that would otherwise be lost.
    let inner = lock_force(&MY_LOGGER.inner);
    if let Some(logger) = inner.as_ref()
        && let Some(writer) = &logger.writer
    {
        writer.try_write_log(record);
    }
}

/// Returns the number of warnings/errors logged during the active dump phase.
pub fn get_warning_count() -> u64 {
    warning_count()
}

/// Sets the current dump phase. Resets `STDOUT_LOGS_DURING_DUMP` when entering
/// `DumpPhase::During` so each collection run starts with a clean slate.
pub fn set_phase(phase: DumpPhase) {
    if phase == DumpPhase::During {
        backend::STDOUT_LOGS_DURING_DUMP.store(false, Ordering::Relaxed);
    }
    set_dump_phase(phase);
}

/// Enables or disables trace-level logging.
pub fn set_trace_logs(enabled: bool) {
    config::TRACE_LOGS.store(enabled, std::sync::atomic::Ordering::Relaxed);
}

/// Returns the current dump phase.
pub fn get_phase() -> DumpPhase {
    current_dump_phase()
}

/// Returns the current verbosity level.
pub fn get_verbosity() -> Verbosity {
    current_verbosity()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    // Serialize tests that mutate the global ACTIVE_LIVE_REGION on the shared
    // live_region::LIVE_REGION_TEST_LOCK (NOT a per-module lock) so they don't
    // race with the same-global tests in `live_region` and `ui::progress`.

    #[test]
    fn test_set_and_clear_progress_line_state() {
        let _guard = live_region::LIVE_REGION_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        update_live_region_text("test message");
        update_live_region_state(LiveRegionState::Progress { lines: 1 });
        let state = *lock_force(&live_region::ACTIVE_LIVE_REGION);
        match state {
            LiveRegionState::Progress { lines } => assert_eq!(lines, 1),
            _ => panic!("Live region not set to Progress"),
        }
        clear_progress_line();
        let state = *lock_force(&live_region::ACTIVE_LIVE_REGION);
        assert_eq!(state, LiveRegionState::None);
    }

    #[test]
    fn test_should_emit_matrix() {
        use log::Level;
        let phases = [DumpPhase::Before, DumpPhase::During, DumpPhase::After];
        let verbosities = [
            Verbosity::Quiet,
            Verbosity::Normal,
            Verbosity::Verbose,
            Verbosity::Debug,
            Verbosity::Trace,
        ];
        let levels = [
            Level::Error,
            Level::Warn,
            Level::Info,
            Level::Debug,
            Level::Trace,
        ];
        for &phase in &phases {
            for &verb in &verbosities {
                for &lvl in &levels {
                    let expected = match verb {
                        Verbosity::Quiet => matches!(lvl, Level::Error),
                        Verbosity::Normal => matches!(lvl, Level::Error | Level::Warn),
                        Verbosity::Verbose => {
                            matches!(lvl, Level::Error | Level::Warn | Level::Info)
                        }
                        Verbosity::Debug => lvl != Level::Trace,
                        Verbosity::Trace => true,
                    };
                    assert_eq!(
                        should_emit(phase, verb, lvl),
                        expected,
                        "phase={:?} verb={:?} level={:?}",
                        phase,
                        verb,
                        lvl
                    );
                }
            }
        }
    }

    #[test]
    fn test_file_line_format_exact() {
        let now = Utc::now();
        let line = format!(
            "{}  |  {:5}  | hello\n",
            now.format(config::LOG_TIMESTAMP_FORMAT),
            "DEBUG",
        );
        let tail = line
            .splitn(3, "  |  ")
            .skip(1)
            .collect::<Vec<_>>()
            .join("  |  ");
        assert_eq!(tail, "DEBUG  | hello\n");
    }

    #[test]
    fn test_live_region_prereq_variant() {
        let _guard = live_region::LIVE_REGION_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *lock_force(&live_region::ACTIVE_LIVE_REGION) = LiveRegionState::Prereq { lines: 3 };
        tear_down_live_region();
        assert_eq!(
            *lock_force(&live_region::ACTIVE_LIVE_REGION),
            LiveRegionState::None
        );
    }

    #[test]
    fn test_live_region_auth_banner_variant() {
        let _guard = live_region::LIVE_REGION_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *lock_force(&live_region::ACTIVE_LIVE_REGION) = LiveRegionState::AuthBanner { lines: 7 };
        tear_down_live_region();
        assert_eq!(
            *lock_force(&live_region::ACTIVE_LIVE_REGION),
            LiveRegionState::None
        );
    }
}
