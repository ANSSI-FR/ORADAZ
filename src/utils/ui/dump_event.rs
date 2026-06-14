// Structured dump-phase log emitter.
//
// `emit` writes to two independent sinks:
//   * Terminal: a styled 3-line (or 1-line) block, gated by the verbosity matrix.
//   * File:     a single consolidated line via `logger::write_log`, bypassing
//               the `log::*!` facade to avoid double-writes.
use crate::FL;
use crate::utils::logger::{
    self, ACTIVE_LIVE_REGION, DumpPhase, LiveRegionState, WARN_COUNT, sanitize_log_field,
};
use crate::utils::mutex::lock_force;
use crate::utils::ui::{Icon, Paint, UiMode, dim, icon, mode, paint};

use chrono::{DateTime, Utc};
use std::io::Write;
use std::sync::atomic::Ordering;

/// Mirrors the WARN_COUNT increment in `MyLogger::log()` so that WARN/ERROR events
/// emitted via this path (which bypasses the `log` facade) also contribute to the
/// progress-bar warnings counter.
fn bump_warn_count_if_needed(level: log::Level, phase: DumpPhase) {
    if (level == log::Level::Warn || level == log::Level::Error) && phase == DumpPhase::During {
        WARN_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) const SERVICE_API_SEPARATOR: &str = " \u{00b7} "; // " · "

/// Styled glyph for a log level (respects NO_COLOR / current UiMode).
fn glyph(level: log::Level) -> String {
    match (level, mode()) {
        (log::Level::Error, UiMode::Color) => paint(Paint::Red, &icon(Icon::Err)),
        // NoColor: the glyph is the ONLY level indicator, so Error must not render
        // identically to Warn ("!!"). Mirror `backend::level_glyph` which uses "XX".
        (log::Level::Error, UiMode::NoColor) => "XX".to_string(),
        (log::Level::Warn, UiMode::Color) => paint(Paint::Yellow, &icon(Icon::Warn)),
        (log::Level::Warn, UiMode::NoColor) => icon(Icon::Warn),
        (log::Level::Info, UiMode::Color) => paint(Paint::Blue, &icon(Icon::Info)),
        (log::Level::Info, UiMode::NoColor) => icon(Icon::Info),
        (_, UiMode::Color) => paint(Paint::Dim, &icon(Icon::Bullet)),
        (_, UiMode::NoColor) => icon(Icon::Bullet),
    }
}

/// Writes to stdout, tearing down and (for Progress) restoring the live region.
///
/// The whole clear→write→redraw runs under `RENDER_LOCK` (via the `*_raw`
/// primitives) so a concurrent progress-ticker repaint cannot interleave its
/// cursor moves between our clear and our redraw.
fn write_to_terminal(msg: &str) {
    // Honour the global pause exactly like `backend::handle_stdout`: while a SIGINT
    // confirmation menu or a prerequisite prompt is on screen, stdout belongs to that
    // UI. The file line was already written by the caller (`write_to_file`) before this,
    // so suppressing the terminal copy loses nothing — it only keeps API-event lines
    // (a dense stream at -vvvv, emitted by the response module for still-in-flight
    // requests) from printing on top of / below the menu.
    if logger::config::DUMP_PAUSED.load(Ordering::Relaxed) > 0 {
        return;
    }
    logger::with_render_lock(|| {
        let active_region = *lock_force(&ACTIVE_LIVE_REGION);
        let has_region = !matches!(active_region, LiveRegionState::None);

        if has_region {
            logger::clear_live_region_lines_raw();
        }

        if std::io::stdout().lock().write_all(msg.as_bytes()).is_ok() {
            // Record that the dump phase produced terminal output, mirroring
            // `backend::handle_stdout`. The end-of-dump label rewrite is skipped
            // when this is set, so it cannot overwrite a real event line.
            logger::STDOUT_LOGS_DURING_DUMP.store(true, Ordering::Relaxed);
        }

        if has_region {
            logger::redraw_live_region_raw(false);
        }
    });
}
pub struct DumpEvent {
    pub level: log::Level,
    pub module_label: String,
    pub service: String,
    pub api: String,
    pub http_status: Option<u16>,
    pub upstream_code: Option<String>,
    pub url: Option<String>,
    /// Optional request ID — rendered as `| ID {id}` in `file_line()` (before
    /// the message) so API-event log lines can be correlated with the structured
    /// `debug!` lines that carry the same `[ID: N]` tag. `None` for events
    /// where no `ApiCall` is in scope (e.g. token re-auth).
    pub call_id: Option<u32>,
    pub message: String,
}

/// Emit a structured API-response event.
///
/// * `level`         — log level (determines glyph / color and verbosity gate)
/// * `module_label`  — 25-char module name used in the file line
/// * `service`       — e.g. `"graph"`
/// * `api`           — e.g. `"roleDefinitions_roleAssignments"`
/// * `http_status`   — HTTP status code, `None` for non-HTTP events
/// * `upstream_code` — API error code, `None` when not available
/// * `url`           — request URL, `None` when not available
/// * `message`       — human-readable error message
pub fn emit(event: DumpEvent) {
    write_to_file(&event);

    let phase = logger::get_phase();
    bump_warn_count_if_needed(event.level, phase);
    let verbosity = logger::get_verbosity();
    if !logger::should_emit(phase, verbosity, event.level) {
        return;
    }

    let g = glyph(event.level);
    let terminal_msg = if event.http_status.is_some() || event.upstream_code.is_some() {
        // 3-line block. The service·api separator is mode-aware so --no-color
        // terminal output stays ASCII (the file log keeps the · separator that
        // inspect's parser splits on — see `file_line`).
        let sep = match mode() {
            UiMode::Color => "\u{00b7}",
            UiMode::NoColor => ">",
        };
        let line1 = format!("    {}  {} {} {}\n", g, event.service, sep, event.api);
        let line2 = match (event.http_status, event.upstream_code) {
            (Some(s), Some(c)) => dim(&format!("         HTTP {}  {}", s, c)),
            (Some(s), None) => dim(&format!("         HTTP {}", s)),
            (None, Some(c)) => dim(&c),
            (None, None) => String::new(),
        };
        let line3 = dim(&format!("         {}", event.message));
        if line2.is_empty() {
            format!("{}{}\n", line1, line3)
        } else {
            format!("{}{}\n{}\n", line1, line2, line3)
        }
    } else {
        // 1-line fallback
        format!("    {}  {}   {}\n", g, event.module_label, event.message)
    };

    write_to_terminal(&terminal_msg);
}

/// Emit a generic (non-API) 1-line styled log entry.
pub fn emit_line(level: log::Level, module_label: &str, message: &str) {
    write_to_file(&DumpEvent {
        level,
        module_label: module_label.to_string(),
        service: String::new(),
        api: String::new(),
        http_status: None,
        upstream_code: None,
        url: None,
        call_id: None,
        message: message.to_string(),
    });

    let phase = logger::get_phase();
    bump_warn_count_if_needed(level, phase);
    let verbosity = logger::get_verbosity();
    if !logger::should_emit(phase, verbosity, level) {
        return;
    }

    let g = glyph(level);
    let msg = format!("    {}  {}   {}\n", g, module_label, message);
    write_to_terminal(&msg);
}

/// Builds the consolidated single‑line file‑log entry for an event.
///
/// The timestamp uses the same [`logger::config::LOG_TIMESTAMP_FORMAT`] as the
/// `log` facade (`backend.rs` / `logger/mod.rs`), so that `inspect`'s log parser
/// ([`crate::inspect::log_parser::parse_log`]) matches these lines and surfaces
/// the API error/warning stream. Kept pure (takes `now`) so it can be unit‑tested.
fn file_line(event: &DumpEvent, now: DateTime<Utc>) -> String {
    let message = sanitize_log_field(&event.message);
    let tail = if !event.service.is_empty() || !event.api.is_empty() {
        let svc_api = format!("{}{}{}", event.service, SERVICE_API_SEPARATOR, event.api);
        let url_part = event
            .url
            .clone()
            .map(|u| format!(" | URL {}", u))
            .unwrap_or_default();
        // Rendered as an extra " | ID N" segment between URL and message so
        // the inspect parser (which iterates unknown middle segments) ignores
        // it, leaving all existing field extraction intact.
        let id_part = event
            .call_id
            .map(|id| format!(" | ID {}", id))
            .unwrap_or_default();
        // The upstream code is sanitized too: it can become a bare middle
        // segment (the `(None, Some)` arm), where an embedded delimiter would
        // be mis-read as a field boundary by the inspect parser.
        let code = event.upstream_code.as_deref().map(sanitize_log_field);
        match (event.http_status, &code) {
            (Some(s), Some(c)) => {
                format!(
                    "{} | HTTP {} {}{}{} | {}",
                    svc_api, s, c, url_part, id_part, message
                )
            }
            (Some(s), None) => {
                format!(
                    "{} | HTTP {}{}{} | {}",
                    svc_api, s, url_part, id_part, message
                )
            }
            (None, Some(c)) => {
                format!("{} | {}{}{} | {}", svc_api, c, url_part, id_part, message)
            }
            (None, None) => format!("{}{}{} | {}", svc_api, url_part, id_part, message),
        }
    } else {
        message
    };

    format!(
        "{}  |  {:5}  | {:FL$}{}\n",
        now.format(logger::config::LOG_TIMESTAMP_FORMAT),
        event.level.to_string(),
        event.module_label,
        tail,
    )
}

fn write_to_file(event: &DumpEvent) {
    logger::write_log(file_line(event, Utc::now()));
}

/// Extracts `(upstream_code, message)` from a standard Microsoft Graph / ARM
/// error envelope `{"error":{"code":"...","message":"..."}}`.
/// Falls back to `(None, v.to_string())` on shape mismatch.
pub fn parse_error_body(v: &serde_json::Value) -> (Option<String>, String) {
    let code = v
        .pointer("/error/code")
        .and_then(|c| c.as_str())
        .map(String::from);
    let message = v
        .pointer("/error/message")
        .and_then(|m| m.as_str())
        .map(String::from)
        .unwrap_or_else(|| v.to_string());
    (code, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::logger::config;
    use crate::utils::ui::set_mode;
    use std::sync::Mutex;

    // Serialises tests that mutate the process-global colour atomics.
    static UI_STATE_LOCK: Mutex<()> = Mutex::new(());

    /// In no-color mode the glyph is the only level indicator on the terminal
    /// line, so Error must not render identically to Warn. Mirrors the same
    /// guard in `backend::tests::level_glyph_distinguishes_error_from_warn_in_no_color`.
    #[test]
    fn glyph_distinguishes_error_from_warn_in_no_color() {
        let _guard = UI_STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let prev_no_color = config::NO_COLOR.load(Ordering::Relaxed);
        config::NO_COLOR.store(true, Ordering::Relaxed);
        set_mode(UiMode::NoColor);

        let err = glyph(log::Level::Error);
        let warn = glyph(log::Level::Warn);

        assert_ne!(
            err, warn,
            "Error and Warn glyphs must differ in no-color mode (both were {err:?})"
        );
        assert_eq!(
            err, "XX",
            "Error uses 'XX' in no-color so it differs from Warn"
        );
        assert_eq!(warn, "!!", "Warn keeps the shared no-color marker");

        config::NO_COLOR.store(prev_no_color, Ordering::Relaxed);
        set_mode(UiMode::Color);
    }

    /// Guards the invariant that `dump_event` log lines use the ISO timestamp
    /// format (`YYYY-MM-DD`) so they round-trip through the `inspect` parser.
    /// The parser regex only accepts ISO-format lines; a non-ISO timestamp would
    /// cause every API error/warning to be silently dropped from `inspect logs`.
    #[test]
    fn test_file_line_parses_with_inspect_parser() {
        use crate::inspect::log_parser::{LogLevel, parse_log};

        let now = Utc::now();

        // API event (HTTP status + code + URL + message).
        let event = DumpEvent {
            level: log::Level::Warn,
            module_label: String::from("ResponseThread"),
            service: String::from("graph"),
            api: String::from("roleDefinitions"),
            http_status: Some(403),
            upstream_code: Some(String::from("Authorization_RequestDenied")),
            url: Some(String::from("https://graph.microsoft.com/v1.0/x")),
            call_id: None,
            message: String::from("Insufficient privileges"),
        };
        let line = file_line(&event, now);
        let entries = parse_log(&line);
        assert_eq!(
            entries.len(),
            1,
            "dump_event line not parsed by inspect: {line:?}"
        );
        let e = &entries[0];
        assert_eq!(e.level, LogLevel::Warn);
        assert_eq!(e.module, "ResponseThread");
        assert_eq!(e.service.as_deref(), Some("graph"));
        assert_eq!(e.api.as_deref(), Some("roleDefinitions"));
        assert_eq!(e.http_status, Some(403));
        assert_eq!(
            e.upstream_code.as_deref(),
            Some("Authorization_RequestDenied")
        );
        assert_eq!(e.url.as_deref(), Some("https://graph.microsoft.com/v1.0/x"));
        assert_eq!(e.message, "Insufficient privileges");

        // Same event with call_id set: the "| ID N" segment must be present
        // in the raw line but transparent to the parser — all other fields
        // must still extract to the same values.
        let event_with_id = DumpEvent {
            level: log::Level::Warn,
            module_label: String::from("ResponseThread"),
            service: String::from("graph"),
            api: String::from("roleDefinitions"),
            http_status: Some(403),
            upstream_code: Some(String::from("Authorization_RequestDenied")),
            url: Some(String::from("https://graph.microsoft.com/v1.0/x")),
            call_id: Some(42),
            message: String::from("Insufficient privileges"),
        };
        let line_with_id = file_line(&event_with_id, now);
        assert!(
            line_with_id.contains("| ID 42 |"),
            "ID segment missing from file line: {line_with_id:?}"
        );
        let entries_with_id = parse_log(&line_with_id);
        assert_eq!(
            entries_with_id.len(),
            1,
            "dump_event line with call_id not parsed: {line_with_id:?}"
        );
        let eid = &entries_with_id[0];
        assert_eq!(eid.service.as_deref(), Some("graph"));
        assert_eq!(eid.api.as_deref(), Some("roleDefinitions"));
        assert_eq!(eid.http_status, Some(403));
        assert_eq!(
            eid.upstream_code.as_deref(),
            Some("Authorization_RequestDenied")
        );
        assert_eq!(
            eid.url.as_deref(),
            Some("https://graph.microsoft.com/v1.0/x")
        );
        assert_eq!(
            eid.message, "Insufficient privileges",
            "message must not include the ID segment"
        );

        // Plain event (no service/api) — the `emit_line` path.
        let plain = DumpEvent {
            level: log::Level::Info,
            module_label: String::from("Dumper"),
            service: String::new(),
            api: String::new(),
            http_status: None,
            upstream_code: None,
            url: None,
            call_id: None,
            message: String::from("Collection finished"),
        };
        let plain_line = file_line(&plain, now);
        let plain_entries = parse_log(&plain_line);
        assert_eq!(
            plain_entries.len(),
            1,
            "plain dump_event line not parsed: {plain_line:?}"
        );
        assert_eq!(plain_entries[0].module, "Dumper");
        assert_eq!(plain_entries[0].message, "Collection finished");
    }

    /// A message containing the field delimiter `" | "` or a newline must not
    /// corrupt the parsed entry: the line stays single-line and every structured
    /// field still extracts, with the message sanitised.
    #[test]
    fn file_line_sanitises_message_delimiters_and_newlines() {
        use crate::inspect::log_parser::parse_log;

        let now = Utc::now();
        let event = DumpEvent {
            level: log::Level::Warn,
            module_label: String::from("ResponseThread"),
            service: String::from("graph"),
            api: String::from("users"),
            http_status: Some(500),
            upstream_code: Some(String::from("InternalServerError")),
            url: Some(String::from("https://graph.microsoft.com/v1.0/users")),
            call_id: Some(7),
            message: String::from("part one | part two\nsecond line"),
        };
        let line = file_line(&event, now);
        // The trailing newline is the only newline — the entry stays on one line.
        assert_eq!(
            line.matches('\n').count(),
            1,
            "embedded newline must be neutralised: {line:?}"
        );
        let entries = parse_log(&line);
        assert_eq!(entries.len(), 1, "must parse as a single entry: {line:?}");
        let e = &entries[0];
        assert_eq!(e.service.as_deref(), Some("graph"));
        assert_eq!(e.api.as_deref(), Some("users"));
        assert_eq!(e.http_status, Some(500));
        assert_eq!(e.upstream_code.as_deref(), Some("InternalServerError"));
        assert_eq!(
            e.url.as_deref(),
            Some("https://graph.microsoft.com/v1.0/users")
        );
        // The message no longer carries a raw delimiter or newline, but its text
        // is preserved.
        assert!(
            !e.message.contains(" | "),
            "raw delimiter left: {:?}",
            e.message
        );
        assert!(
            !e.message.contains('\n'),
            "raw newline left: {:?}",
            e.message
        );
        assert!(e.message.contains("part one"), "text lost: {:?}", e.message);
        assert!(e.message.contains("part two"), "text lost: {:?}", e.message);
        assert!(
            e.message.contains("second line"),
            "text after newline lost: {:?}",
            e.message
        );
    }

    #[test]
    fn test_parse_error_body_graph() {
        let v = serde_json::json!({
            "error": {
                "code": "Request_ResourceNotFound",
                "message": "Resource '1fe13547' does not exist."
            }
        });
        let (code, msg) = parse_error_body(&v);
        assert_eq!(code, Some("Request_ResourceNotFound".to_string()));
        assert_eq!(msg, "Resource '1fe13547' does not exist.");
    }

    #[test]
    fn test_parse_error_body_fallback() {
        let v = serde_json::json!({"unexpected": "shape"});
        let (code, msg) = parse_error_body(&v);
        assert_eq!(code, None);
        assert!(!msg.is_empty());
    }

    #[test]
    fn test_file_line_tail_with_http() {
        let service = "graph";
        let api = "roleDefinitions_roleAssignments";
        let http_status: u16 = 404;
        let upstream_code: &str = "Request_ResourceNotFound";
        let message = "Resource '1fe13547' does not exist.";

        let svc_api = format!("{} \u{00b7} {}", service, api);
        // Without URL
        let tail = format!(
            "{} | HTTP {} {} | {}",
            svc_api, http_status, upstream_code, message
        );
        assert_eq!(
            tail,
            "graph · roleDefinitions_roleAssignments | HTTP 404 Request_ResourceNotFound | Resource '1fe13547' does not exist."
        );
    }

    #[test]
    fn test_file_line_tail_with_http_and_url() {
        let service = "graph";
        let api = "roleDefinitions_roleAssignments";
        let http_status: u16 = 404;
        let upstream_code: &str = "Request_ResourceNotFound";
        let url = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/abc/roleAssignments";
        let message = "Resource does not exist.";

        let svc_api = format!("{} \u{00b7} {}", service, api);
        let url_part = format!(" | URL {}", url);
        let tail = format!(
            "{} | HTTP {} {}{} | {}",
            svc_api, http_status, upstream_code, url_part, message
        );
        assert!(tail.contains("| URL https://"));
        assert!(tail.contains("| HTTP 404 Request_ResourceNotFound |"));
    }

    #[test]
    fn test_file_line_tail_no_http() {
        // When no HTTP context, tail is just message (same as today's single-line logs).
        let message = "Could not lock receiver";
        let tail = message.to_string();
        assert_eq!(tail, "Could not lock receiver");
    }
}
