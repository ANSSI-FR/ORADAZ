use oradaz::utils::logger::{self, DumpPhase, WARN_COUNT};
use oradaz::utils::ui::dump_event::{self, DumpEvent};

use std::sync::Mutex;
use std::sync::atomic::Ordering;

/// dump_event::emit() and emit_line() write to the global WARN_COUNT, just like
/// MyLogger::log() does. These tests touch that global so they cannot run in
/// parallel — serialize them via a local mutex.
static WARN_COUNT_LOCK: Mutex<()> = Mutex::new(());

fn snapshot_warn_count() -> u64 {
    WARN_COUNT.load(Ordering::Relaxed)
}

fn make_event(level: log::Level) -> DumpEvent {
    DumpEvent {
        level,
        module_label: "TestModule".to_string(),
        service: "graph".to_string(),
        api: "users".to_string(),
        http_status: Some(404),
        upstream_code: Some("Request_ResourceNotFound".to_string()),
        url: Some("https://graph.microsoft.com/v1.0/users/x".to_string()),
        call_id: None,
        message: "Test message".to_string(),
    }
}

#[test]
fn emit_warn_during_increments_counter() {
    let _guard = WARN_COUNT_LOCK.lock().unwrap();
    logger::set_phase(DumpPhase::During);
    let before = snapshot_warn_count();
    dump_event::emit(make_event(log::Level::Warn));
    let after = snapshot_warn_count();
    assert_eq!(
        after - before,
        1,
        "Warn during During should bump WARN_COUNT"
    );
}

#[test]
fn emit_error_during_increments_counter() {
    let _guard = WARN_COUNT_LOCK.lock().unwrap();
    logger::set_phase(DumpPhase::During);
    let before = snapshot_warn_count();
    dump_event::emit(make_event(log::Level::Error));
    let after = snapshot_warn_count();
    assert_eq!(
        after - before,
        1,
        "Error during During should bump WARN_COUNT"
    );
}

#[test]
fn emit_info_during_does_not_increment_counter() {
    let _guard = WARN_COUNT_LOCK.lock().unwrap();
    logger::set_phase(DumpPhase::During);
    let before = snapshot_warn_count();
    dump_event::emit(make_event(log::Level::Info));
    dump_event::emit(make_event(log::Level::Debug));
    let after = snapshot_warn_count();
    assert_eq!(after, before, "Info/Debug must not change WARN_COUNT");
}

#[test]
fn emit_warn_outside_during_does_not_increment_counter() {
    let _guard = WARN_COUNT_LOCK.lock().unwrap();
    logger::set_phase(DumpPhase::Before);
    let before = snapshot_warn_count();
    dump_event::emit(make_event(log::Level::Warn));
    dump_event::emit(make_event(log::Level::Error));
    let after = snapshot_warn_count();
    assert_eq!(
        after, before,
        "Warn/Error outside During must not change WARN_COUNT"
    );
    logger::set_phase(DumpPhase::After);
    let before = snapshot_warn_count();
    dump_event::emit(make_event(log::Level::Warn));
    let after = snapshot_warn_count();
    assert_eq!(
        after, before,
        "Warn during After must not change WARN_COUNT"
    );
}

#[test]
fn emit_line_warn_during_increments_counter() {
    let _guard = WARN_COUNT_LOCK.lock().unwrap();
    logger::set_phase(DumpPhase::During);
    let before = snapshot_warn_count();
    dump_event::emit_line(log::Level::Warn, "TestModule", "msg");
    let after = snapshot_warn_count();
    assert_eq!(
        after - before,
        1,
        "emit_line Warn during During should bump WARN_COUNT"
    );
}

/// An event that actually reaches the terminal must record that the dump phase
/// produced stdout output. The end-of-dump "Performing collect" label is only
/// rewritten when no such output happened, so this flag stops the rewrite from
/// overwriting the last printed event line.
#[test]
fn emit_during_marks_stdout_logs() {
    use oradaz::utils::logger::STDOUT_LOGS_DURING_DUMP;
    use oradaz::utils::logger::config::DUMP_PAUSED;

    let _guard = WARN_COUNT_LOCK.lock().unwrap();
    // set_phase(During) also resets STDOUT_LOGS_DURING_DUMP to false.
    logger::set_phase(DumpPhase::During);
    DUMP_PAUSED.store(0, Ordering::Relaxed);
    assert!(!STDOUT_LOGS_DURING_DUMP.load(Ordering::Relaxed));
    // Error emits at any verbosity, so it is guaranteed to reach the terminal.
    dump_event::emit(make_event(log::Level::Error));
    assert!(
        STDOUT_LOGS_DURING_DUMP.load(Ordering::Relaxed),
        "an emitted terminal event must mark STDOUT_LOGS_DURING_DUMP"
    );
}

/// A pause (SIGINT menu / prereq prompt) suppresses only the *terminal* copy of an
/// event — the `DUMP_PAUSED` gate lives inside `write_to_terminal`, after the file
/// write and the warning-tally bump. This guards against moving that gate earlier
/// (e.g. to the top of `emit`), which would silently drop warnings from the tally
/// and lines from `oradaz.log` while paused.
#[test]
fn emit_warn_during_pause_still_bumps_counter() {
    use oradaz::utils::logger::config::DUMP_PAUSED;

    let _guard = WARN_COUNT_LOCK.lock().unwrap();
    logger::set_phase(DumpPhase::During);
    DUMP_PAUSED.store(1, Ordering::Relaxed);
    let before = snapshot_warn_count();
    dump_event::emit(make_event(log::Level::Warn));
    let after = snapshot_warn_count();
    // Reset before asserting so a failure cannot leak the paused state to other tests.
    DUMP_PAUSED.store(0, Ordering::Relaxed);
    assert_eq!(
        after - before,
        1,
        "Warn during a pause must still bump WARN_COUNT (the pause gates only stdout)"
    );
}
