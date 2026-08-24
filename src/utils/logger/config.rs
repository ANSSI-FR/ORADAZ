use crate::utils::logger::MY_LOGGER;
use crate::utils::mutex::lock_force;

use log::Level;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};

pub static NO_COLOR: AtomicBool = AtomicBool::new(false);
pub static TRACE_LOGS: AtomicBool = AtomicBool::new(false);
/// Number of active pause sources (SIGINT menu, prerequisite prompt, fatal-exit wait).
/// Stdout logging is suppressed while this is `> 0`. It is a counter rather than a bool
/// so independent sources can pause/resume concurrently without one clearing another's
/// pause — pausing is `fetch_add(1)`, resuming is `fetch_sub(1)`, with no read-modify-store
/// window that could leave the flag stuck.
pub static DUMP_PAUSED: AtomicUsize = AtomicUsize::new(0);

pub const LOG_TIMESTAMP_FORMAT: &str = "%Y-%m-%d %H:%M:%S";

/// Controls the amount of information printed to the terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verbosity {
    Quiet,
    Normal,
    Verbose,
    Debug,
    Trace,
}

/// Represents the different stages of the data collection process.
/// Used to filter logs and track errors specifically during the main dump phase.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DumpPhase {
    Before = 0,
    During = 1,
    After = 2,
}

impl TryFrom<u8> for DumpPhase {
    type Error = u8;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(DumpPhase::Before),
            1 => Ok(DumpPhase::During),
            2 => Ok(DumpPhase::After),
            _ => Err(v),
        }
    }
}

/// Determines whether a log message should be printed to stdout based on the current verbosity and log level.
pub fn should_emit(_phase: DumpPhase, verbosity: Verbosity, level: Level) -> bool {
    if level == Level::Trace && verbosity != Verbosity::Trace {
        return false;
    }
    match verbosity {
        Verbosity::Quiet => level == Level::Error,
        Verbosity::Normal => level <= Level::Warn,
        Verbosity::Verbose => level <= Level::Info,
        Verbosity::Debug => level <= Level::Debug,
        Verbosity::Trace => true,
    }
}

pub static CURRENT_DUMP_PHASE: AtomicU8 = AtomicU8::new(DumpPhase::Before as u8);

pub static WARN_COUNT: AtomicU64 = AtomicU64::new(0);

/// Returns the total number of warnings and errors encountered during the `During` dump phase.
pub fn warning_count() -> u64 {
    WARN_COUNT.load(Ordering::Relaxed)
}

/// Updates the current dump phase.
pub fn set_dump_phase(phase: DumpPhase) {
    CURRENT_DUMP_PHASE.store(phase as u8, Ordering::Release);
}

/// Returns the current dump phase.
pub fn current_dump_phase() -> DumpPhase {
    DumpPhase::try_from(CURRENT_DUMP_PHASE.load(Ordering::Acquire)).unwrap_or(DumpPhase::Before)
}

/// Returns the current verbosity level.
pub fn current_verbosity() -> Verbosity {
    lock_force(&MY_LOGGER.inner)
        .as_ref()
        .map(|l| l.verbosity)
        .unwrap_or(Verbosity::Quiet)
}
