use crate::FL;
use crate::utils::errors::{Error, FatalPresentation};
use crate::utils::logger::config::{self, DumpPhase, Verbosity, should_emit};
use crate::utils::logger::{ACTIVE_LIVE_REGION, LiveRegionState};
use crate::utils::mutex::lock_force;
use crate::utils::ui::{Icon, Paint, err_text, icon, paint};
use crate::utils::writer::WriterHandle;

use chrono::Utc;
use log::{Level, Metadata, Record};
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex};

/// Set to `true` the first time a log is emitted to stdout during `DumpPhase::During`.
/// Reset to `false` when `set_phase(DumpPhase::During)` is called.
/// Used by `finalize_performing_collect_label` to decide whether to overwrite
/// the "Performing collect" label with the non-blue version at the end of the dump.
pub static STDOUT_LOGS_DURING_DUMP: AtomicBool = AtomicBool::new(false);

fn split_module_label(s: &str) -> (String, String) {
    let label: String = s.chars().take(FL).collect();
    if label.chars().count() < FL {
        (String::new(), s.to_string())
    } else {
        let message: String = s.chars().skip(FL).collect();
        (label.trim().to_string(), message.trim_start().to_string())
    }
}

fn level_glyph(level: Level) -> String {
    let no_color = config::NO_COLOR.load(Ordering::Relaxed);
    if no_color {
        // No-color stdout uses ASCII glyphs instead of raw Unicode, consistent
        // with every other no-color surface (the file log is glyph-free and
        // unaffected). Warn/Info/other route through the shared `Icon` fallbacks
        // (`!!`, `i`, `*`); Error is special-cased to a *distinct* marker because
        // `icon(Icon::Err)` and `icon(Icon::Warn)` both collapse to `!!`, which
        // would otherwise make an error line indistinguishable from a warning on
        // the sole stdout level indicator (the textual `ERROR`/`WARN` shows only
        // in the file log).
        // `config::NO_COLOR` and the `UI_MODE` that `icon()` reads are two
        // atomics, but the UI-mode setters (`theme::init`, `logger::set_no_color`)
        // always set them together, so in the
        // `no_color` branch `icon()` is guaranteed to return its NoColor variant.
        // Do not "simplify" by dropping this guard and calling `icon()`
        // unconditionally — that would also strip the colour from the Color path.
        return match level {
            Level::Error => "XX".to_string(),
            Level::Warn => icon(Icon::Warn),
            Level::Info => icon(Icon::Info),
            _ => icon(Icon::Bullet),
        };
    }
    match level {
        Level::Error => paint(Paint::Red, "✖"),
        Level::Warn => paint(Paint::Yellow, "⚠"),
        Level::Info => paint(Paint::Blue, "ℹ"),
        _ => paint(Paint::Dim, "•"),
    }
}

/// Main logger implementation that handles emission of logs to both standard output
/// and an optional file writer.
pub struct MyLogger {
    pub writer: Option<WriterHandle>,
    pub verbosity: Verbosity,
}

/// A thread-safe wrapper around `MyLogger` used as the global logger instance.
pub struct MyStaticLogger {
    pub inner: Mutex<Option<MyLogger>>,
}

pub static MY_LOGGER: LazyLock<MyStaticLogger> = LazyLock::new(|| MyStaticLogger {
    inner: Mutex::new(None),
});

impl MyLogger {
    pub fn new(writer: Option<WriterHandle>, verbosity: Verbosity) -> Self {
        MyLogger { writer, verbosity }
    }

    /// Attaches a file writer to the logger for persisting logs to disk.
    pub fn add_writer(&mut self, writer: WriterHandle) {
        self.writer = Some(writer);
    }

    /// Removes the attached file writer, disabling disk persistence.
    pub fn remove_writer(&mut self) {
        self.writer = None;
    }

    /// Determines if a log record should be processed based on its level and global trace settings.
    fn enabled(&self, metadata: &Metadata) -> bool {
        let level = metadata.level();
        if level == Level::Trace {
            return config::TRACE_LOGS.load(Ordering::Relaxed);
        }
        level <= Level::Debug
    }

    /// Processes a log record by emitting it to the file logger and, if conditions are met, to stdout.
    ///
    /// It tracks warning/error counts during the `During` dump phase to provide a summary at the end.
    fn log(&mut self, record: &Record) {
        let metadata = record.metadata();
        if self.enabled(metadata) && record.target().starts_with("oradaz") {
            let phase = config::current_dump_phase();

            if (record.level() == Level::Warn || record.level() == Level::Error)
                && phase == DumpPhase::During
            {
                config::WARN_COUNT.fetch_add(1, Ordering::Relaxed);
            }

            self.handle_stdout(record, phase);
            self.handle_file(record);
        }
    }

    /// Handles printing log records to the terminal.
    ///
    /// This method implements a "live region" mechanism: if a progress line is currently active
    /// (e.g., during a dump), it temporarily clears the progress line, prints the log message,
    /// and then restores the progress line to ensure the terminal UI remains consistent.
    fn handle_stdout(&mut self, record: &Record, phase: DumpPhase) {
        if config::DUMP_PAUSED.load(Ordering::Relaxed) > 0 {
            return;
        }
        // ERROR is surfaced in every phase (auth, prerequisites, packaging), not
        // just During: a non-fatal `error!()` raised in those phases that is not
        // routed through `bail_fatal!` would otherwise be file-only and invisible
        // to an operator watching the screen. Lower levels (incl. WARN) stay gated
        // to the dump phase to avoid cluttering / duplicating the auth &
        // prerequisite live-region UIs, which already render their own warnings as
        // structured items. The clear→write→redraw path below keeps any active
        // Before/After live region intact.
        let is_error = record.level() == Level::Error;
        if !should_emit(phase, self.verbosity, record.level())
            || (phase != DumpPhase::During && !is_error)
        {
            return;
        }

        let msg = {
            let glyph = level_glyph(record.level());
            let args_str = record.args().to_string();
            let (module_label, message) = split_module_label(&args_str);
            if module_label.is_empty() {
                format!("    {}  {}\n", glyph, message)
            } else {
                format!("    {}  {}   {}\n", glyph, module_label, message)
            }
        };

        let active_region = *lock_force(&ACTIVE_LIVE_REGION);
        let has_region = !matches!(active_region, LiveRegionState::None);

        // Hold RENDER_LOCK across the whole clear→write→redraw so a concurrent
        // progress-ticker repaint cannot interleave its cursor moves. The bail on
        // write failure is deferred until AFTER the lock is released, because
        // bail_fatal! logs (re-entering this path) and would otherwise deadlock.
        let write_result = crate::utils::logger::with_render_lock(|| {
            if has_region {
                crate::utils::logger::clear_live_region_lines_raw();
            }

            let stdout = io::stdout();
            let mut stdout_lock = stdout.lock();
            let result = stdout_lock.write_all(msg.as_bytes());
            drop(stdout_lock);

            if result.is_ok() {
                STDOUT_LOGS_DURING_DUMP.store(true, Ordering::Relaxed);
                if has_region {
                    crate::utils::logger::redraw_live_region_raw(false);
                }
            }
            result
        });

        if let Err(err) = write_result {
            // We are inside `MyStaticLogger::log`, holding the `inner` mutex (a
            // non-reentrant std::Mutex). `bail_fatal!` begins with `log::error!`,
            // which re-enters this logger and re-locks `inner` → deadlock, leaving
            // the `.mla.tmp` archive stranded and the process hung. So replicate the
            // fatal block and exit directly here, without routing through the `log`
            // facade (ui::fatal and the Error accessors do not log).
            eprintln!(
                "[{}] Unable to write to standard output: {}",
                err_text("ERROR"),
                err
            );
            let fatal_err = Error::WriterLock;
            crate::utils::ui::fatal(
                fatal_err.title(),
                fatal_err.context().as_deref(),
                fatal_err.remediation_steps(),
            );
            // Mirror bail_fatal!: suppress further stdout logs, then wait for the
            // operator on an interactive terminal before exiting.
            config::DUMP_PAUSED.fetch_add(1, Ordering::Relaxed);
            crate::utils::fatal_handling::wait_if_interactive();
            std::process::exit(1);
        }
    }

    /// Writes a log record to the configured file writer with a timestamp and log level.
    fn handle_file(&mut self, record: &Record) {
        let Some(writer) = &self.writer else { return };

        let now = Utc::now();
        let msg = format!(
            "{}  |  {:5}  | {}\n",
            now.format(config::LOG_TIMESTAMP_FORMAT),
            record.level().to_string(),
            record.args()
        );

        let w = writer.clone();
        w.try_write_log(msg);
    }

    fn flush(&mut self) {
        let _ = io::stdout().flush();
    }
}

impl log::Log for MyStaticLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let mut i = lock_force(&self.inner);
        if let Some(inner) = i.as_mut() {
            inner.log(record);
        }
    }

    fn flush(&self) {
        let mut i = lock_force(&self.inner);
        if let Some(inner) = i.as_mut() {
            inner.flush();
        }
    }
}

impl MyStaticLogger {
    pub fn add_writer(&self, writer: &WriterHandle) {
        let logger_writer = writer.clone();
        let mut i = lock_force(&self.inner);
        if let Some(logger) = i.as_mut() {
            logger.add_writer(logger_writer)
        }
    }

    pub fn remove_writer(&self) {
        let mut i = lock_force(&self.inner);
        if let Some(logger) = i.as_mut() {
            logger.remove_writer()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::ui::{UiMode, set_mode};

    // Serialises tests that mutate the process-global colour atomics so parallel
    // execution cannot observe each other's mid-test state.
    static UI_STATE_LOCK: Mutex<()> = Mutex::new(());

    /// In no-color mode the stdout glyph is the *only* level indicator (the
    /// textual `ERROR`/`WARN` appears solely in the file log), so an error line
    /// must not render identically to a warning. Guards `level_glyph` against a
    /// regression to `icon(Icon::Err)`, which equals `icon(Icon::Warn)` (`!!`) in
    /// no-color mode.
    #[test]
    fn level_glyph_distinguishes_error_from_warn_in_no_color() {
        let _guard = UI_STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let prev_no_color = config::NO_COLOR.load(Ordering::Relaxed);
        config::NO_COLOR.store(true, Ordering::Relaxed);
        set_mode(UiMode::NoColor);

        let err = level_glyph(Level::Error);
        let warn = level_glyph(Level::Warn);

        assert_ne!(
            err, warn,
            "Error and Warn glyphs must differ in no-color mode (both were {err:?})"
        );
        assert_eq!(warn, "!!", "Warn keeps the shared no-color marker");

        // Restore state for other tests in this binary.
        config::NO_COLOR.store(prev_no_color, Ordering::Relaxed);
        set_mode(UiMode::Color);
    }
}
