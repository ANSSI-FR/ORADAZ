use crate::collect::dump::response::DumpError;
use crate::utils::ui::dump_event::SERVICE_API_SEPARATOR;

use chrono::{NaiveDateTime, NaiveTime};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

/// Verbosity / filter / layout flags for the `inspect logs` subcommand.
///
/// `Default` is implemented (every field zero/None/empty) so callers can
/// build a filter with `LogFilters { full: true, ..Default::default() }`.
#[derive(Default)]
pub struct LogFilters {
    // ─── verbosity ────────────────────────────────────────────────────
    pub warnings: bool,
    pub info: bool,
    pub debug: bool,
    /// Show each entry with HTTP response body / POST data; orthogonal to
    /// the verbosity flags above.
    pub full: bool,

    // ─── filters ──────────────────────────────────────────────────────
    /// Service filter (lower-cased). None = all.
    pub service: Option<String>,
    /// Substring match on API name (case-insensitive). None = all.
    pub api: Option<String>,
    /// HTTP status filter — exact code (`"403"`, `"429"`) or class
    /// (`"4xx"`, `"5xx"`). None = all statuses.
    pub http: Option<String>,
    /// Lower bound timestamp (`HH:MM`, `HH:MM:SS`, or full `YYYY-MM-DD HH:MM[:SS]`).
    pub since: Option<String>,
    /// Keep only the N most-recent entries (post other filters).
    pub last: Option<usize>,
    /// Include schema-declared expected errors. Hidden by default so the
    /// listing focuses on real anomalies; entries remain in `errors.json`
    /// with `expected: true`.
    pub include_expected: bool,

    // ─── layout / sort ────────────────────────────────────────────────
    /// Max groups in the grouped table (default 25). Use [`all`] to disable.
    pub limit: Option<usize>,
    /// Disable the [`limit`] cap entirely.
    pub all: bool,
    /// Sort key: `count` / `recent` / `status` (default count).
    pub sort: SortBy,
    /// Print only the COLLECTION SUMMARY + LOGS SUMMARY table and stop.
    /// Triage-flash for very large collections.
    pub summary_only: bool,

    // ─── timeline aliases (delegate to `inspect timeline`) ────────────
    pub timeline: bool,
    pub timeline_429: bool,
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortBy {
    /// Most-frequent groups first (then table name asc). Default.
    #[default]
    Count,
    /// Most-recent first-occurrence first.
    Recent,
    /// HTTP status ascending (then count desc).
    Status,
}

/// HTTP status filter — exact code or 100-class (`4xx` etc.).
pub enum HttpMatcher {
    Code(u16),
    Class(u16), // 2/3/4/5 — matches `status / 100 == class`
}

impl HttpMatcher {
    pub fn matches(&self, status: u16) -> bool {
        match self {
            HttpMatcher::Code(c) => *c == status,
            HttpMatcher::Class(c) => status / 100 == *c,
        }
    }
}

/// Parse the user-provided `--http` value: `"403"`, `"429"`, `"4xx"`, `"5xx"`,
/// `"2xx"`, `"3xx"`. Returns an error message suitable for `inspect_error`.
pub fn parse_http_filter(s: &str) -> Result<HttpMatcher, String> {
    let s_lower = s.to_lowercase();
    match s_lower.as_str() {
        "2xx" => Ok(HttpMatcher::Class(2)),
        "3xx" => Ok(HttpMatcher::Class(3)),
        "4xx" => Ok(HttpMatcher::Class(4)),
        "5xx" => Ok(HttpMatcher::Class(5)),
        _ => s_lower.parse::<u16>().map(HttpMatcher::Code).map_err(|_| {
            format!("invalid --http value '{s}' (expected NNN, 2xx, 3xx, 4xx, or 5xx)")
        }),
    }
}

/// Lower-bound timestamp filter for `--since`.
///
/// Two flavours: `FullTimestamp` (compare on the entry's full
/// `YYYY-MM-DD HH:MM:SS` stamp) and `TimeOfDay` (compare on the entry's
/// time portion only — useful when the user just types `06:57`).
pub enum SinceMatcher {
    FullTimestamp(String),
    TimeOfDay(String),
}

impl SinceMatcher {
    pub fn matches(&self, entry_ts: &str) -> bool {
        match self {
            SinceMatcher::FullTimestamp(threshold) => entry_ts >= threshold.as_str(),
            SinceMatcher::TimeOfDay(threshold) => {
                // Entry timestamps are "YYYY-MM-DD HH:MM:SS"; bytes 11..19 = "HH:MM:SS".
                // A malformed/short stamp yields "" so it fails the filter rather than
                // being compared whole against "HH:MM:SS".
                let time_slice = entry_ts.get(11..19).unwrap_or("");
                time_slice >= threshold.as_str()
            }
        }
    }
}

/// Parse the user-provided `--since` value. Accepts `HH:MM`, `HH:MM:SS`,
/// `YYYY-MM-DD HH:MM`, and `YYYY-MM-DD HH:MM:SS`. Returns an error message
/// suitable for `inspect_error`.
pub fn parse_since(s: &str) -> Result<SinceMatcher, String> {
    if NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").is_ok() {
        return Ok(SinceMatcher::FullTimestamp(s.to_string()));
    }
    if NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M").is_ok() {
        return Ok(SinceMatcher::FullTimestamp(format!("{s}:00")));
    }
    if NaiveTime::parse_from_str(s, "%H:%M:%S").is_ok() {
        return Ok(SinceMatcher::TimeOfDay(s.to_string()));
    }
    if NaiveTime::parse_from_str(s, "%H:%M").is_ok() {
        return Ok(SinceMatcher::TimeOfDay(format!("{s}:00")));
    }
    Err(format!(
        "invalid --since value '{s}' (expected HH:MM[:SS] or YYYY-MM-DD HH:MM[:SS])"
    ))
}

#[derive(PartialEq, PartialOrd, Eq, Ord, Clone, Copy, Debug)]
pub enum LogLevel {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
}

#[derive(Clone)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: LogLevel,
    pub module: String,
    pub service: Option<String>,
    pub api: Option<String>,
    pub http_status: Option<u16>,
    pub upstream_code: Option<String>,
    pub url: Option<String>,
    pub message: String,
}

/// A set of `LogEntry` values that share the same (service, api, http_status,
/// upstream_code, message) tuple, collapsed into a single display entry.
pub struct GroupedEntry {
    /// Representative entry (earliest occurrence).
    pub first: LogEntry,
    /// Total number of occurrences, including `first`.
    pub count: usize,
    /// Distinct URLs seen across all occurrences (in order of first appearance).
    pub all_urls: Vec<String>,
}

/// Groups entries with identical (service, api, http_status, upstream_code,
/// message) tuples. Entries are consumed; first-occurrence order is preserved.
pub fn group_entries(entries: Vec<LogEntry>) -> Vec<GroupedEntry> {
    // Phase 1: assign each entry to a group via borrowed references — zero
    // key-string clones. Group numbers reflect first-occurrence order.
    type BorrowedKey<'a> = (
        Option<&'a str>,
        Option<&'a str>,
        Option<u16>,
        Option<&'a str>,
        &'a str,
    );
    let mut group_index: HashMap<BorrowedKey<'_>, usize> = HashMap::new();
    let mut assignments: Vec<usize> = Vec::with_capacity(entries.len());
    for entry in &entries {
        let key: BorrowedKey<'_> = (
            entry.service.as_deref(),
            entry.api.as_deref(),
            entry.http_status,
            entry.upstream_code.as_deref(),
            entry.message.as_str(),
        );
        let next_idx = group_index.len();
        let idx = *group_index.entry(key).or_insert(next_idx);
        assignments.push(idx);
    }
    drop(group_index); // release borrows so entries can be consumed below

    // Phase 2: build GroupedEntry values by consuming the entries.
    // Per-group URL sets (parallel to `result`) for O(1) dedup membership.
    let mut result: Vec<GroupedEntry> = Vec::new();
    let mut url_sets: Vec<HashSet<String>> = Vec::new();
    for (entry, idx) in entries.into_iter().zip(assignments) {
        if idx < result.len() {
            result[idx].count += 1;
            if let Some(ref url) = entry.url
                && url_sets[idx].insert(url.clone())
            {
                result[idx].all_urls.push(url.clone());
            }
        } else {
            // idx == result.len(): first occurrence of a new group
            let mut url_set = HashSet::new();
            let all_urls = match &entry.url {
                Some(u) => {
                    url_set.insert(u.clone());
                    vec![u.clone()]
                }
                None => Vec::new(),
            };
            url_sets.push(url_set);
            result.push(GroupedEntry {
                first: entry,
                count: 1,
                all_urls,
            });
        }
    }
    result
}

// Format: "YYYY-MM-DD HH:MM:SS  |  LEVEL  | {module:<25}{tail}"
static HEADER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})\s+\|\s+(\w+)\s+\| (.*)$")
        .expect("invalid regex")
});

/// Parses the raw log text into a vector of `LogEntry` structures.
///
/// It uses a regular expression to extract the header information (date, time, level, module)
/// and then parses the remaining part of each line to identify if it is an API event or a plain message.
pub fn parse_log(text: &str) -> Vec<LogEntry> {
    text.lines()
        .filter_map(|line| {
            let caps = HEADER_RE.captures(line)?;
            let date_str = caps.get(1)?.as_str();
            let time_str = caps.get(2)?.as_str();
            let level_str = caps.get(3)?.as_str();
            let rest = caps.get(4)?.as_str();

            let timestamp = format!("{} {}", date_str, time_str);

            let level = match level_str.trim() {
                "ERROR" => LogLevel::Error,
                "WARN" => LogLevel::Warn,
                "INFO" => LogLevel::Info,
                "DEBUG" => LogLevel::Debug,
                "TRACE" => LogLevel::Trace,
                _ => LogLevel::Warn,
            };

            // Module is the first 25 chars (padded); tail follows
            let (module_end, _) = rest.char_indices().nth(25).unwrap_or((rest.len(), ' '));
            let module = rest[..module_end].trim().to_string();
            let tail = if module_end < rest.len() {
                &rest[module_end..]
            } else {
                ""
            };

            Some(parse_tail(timestamp, level, module, tail))
        })
        .collect()
}

/// Parses the "tail" part of a log entry.
///
/// If the tail contains the `SERVICE_API_SEPARATOR`, it's treated as an API event,
/// and the function attempts to extract the service, API name, HTTP status,
/// upstream code, and URL. Otherwise, it's treated as a plain log message.
fn parse_tail(timestamp: String, level: LogLevel, module: String, tail: &str) -> LogEntry {
    if let Some(dot_pos) = tail.find(SERVICE_API_SEPARATOR) {
        let service = tail[..dot_pos].trim().to_string();
        let after_dot = &tail[dot_pos + SERVICE_API_SEPARATOR.len()..];

        // Split by " | " into at most 5 parts: api | part2 | part3 | part4 | ...
        let parts: Vec<&str> = after_dot.splitn(5, " | ").collect();
        let api = parts.first().unwrap_or(&"").trim().to_string();

        let mut http_status: Option<u16> = None;
        let mut upstream_code: Option<String> = None;
        let mut url: Option<String> = None;
        let mut message = String::new();

        if parts.len() >= 2 {
            // Middle parts (between api and last) carry HTTP / URL info
            for part in &parts[1..parts.len().saturating_sub(1)] {
                if let Some(http_part) = part.strip_prefix("HTTP ") {
                    let mut it = http_part.splitn(2, ' ');
                    http_status = it.next().and_then(|s| s.parse().ok());
                    upstream_code = it.next().map(|s| s.to_string());
                } else if let Some(url_part) = part.strip_prefix("URL ") {
                    url = Some(url_part.to_string());
                } else if part.starts_with("ID ") {
                    // The dump-event " | ID N" segment is informational; ignore it
                    // (must be skipped explicitly so it is not mistaken for the bare
                    // upstream code below).
                } else if upstream_code.is_none() {
                    // A bare middle segment with no HTTP/URL/ID prefix is the upstream
                    // error code for events that have no HTTP status (e.g.
                    // MissingBatchData, NoBodyInBatchResponse). Without capturing it,
                    // http_status and upstream_code are both None and
                    // find_dump_error_in_index can only match the first DumpError in the
                    // (service, api) bucket — silently mis-attributing the entry.
                    upstream_code = Some(part.trim().to_string());
                }
            }
            message = parts.last().unwrap_or(&"").to_string();
        }

        LogEntry {
            timestamp,
            level,
            module,
            service: Some(service),
            api: Some(api),
            http_status,
            upstream_code,
            url,
            message,
        }
    } else {
        LogEntry {
            timestamp,
            level,
            module,
            service: None,
            api: None,
            http_status: None,
            upstream_code: None,
            url: None,
            message: tail.trim().to_string(),
        }
    }
}

/// Extract the last `limit` plain (non-API) `ERROR` entries from an already-parsed
/// log, together with the immediately-following `DEBUG` entry when it shares the
/// same module. The `DEBUG` follow-up is where the collector typically logs the
/// underlying cause (network timeout, response body, etc.) — surfacing it next to
/// the `ERROR` line saves the user a drill-in with `inspect logs --debug`.
///
/// Accepts pre-parsed entries so the caller controls whether to re-parse or reuse
/// an existing `Vec<LogEntry>`. Used by `inspect summary` (ATTENTION) and
/// `inspect hints` (FATAL) when the archive is `.broken` or `auth_errors > 0`.
pub fn last_plain_failure_context(entries: &[LogEntry], limit: usize) -> Vec<LogEntry> {
    if limit == 0 {
        return Vec::new();
    }
    let plain: Vec<&LogEntry> = entries.iter().filter(|e| e.service.is_none()).collect();

    let error_indices: Vec<usize> = plain
        .iter()
        .enumerate()
        .filter(|(_, e)| e.level == LogLevel::Error)
        .map(|(i, _)| i)
        .collect();

    let take_from = error_indices.len().saturating_sub(limit);
    let last_errors = &error_indices[take_from..];

    let mut chosen: Vec<LogEntry> = Vec::new();
    for &idx in last_errors {
        chosen.push(plain[idx].clone());
        // Include the very next entry when it's a DEBUG line on the same
        // module — that's the convention the collector uses to log the
        // underlying cause for an ERROR.
        if let Some(next) = plain.get(idx + 1)
            && next.level == LogLevel::Debug
            && next.module == plain[idx].module
        {
            chosen.push((*next).clone());
        }
    }
    chosen
}

/// Builds a `(folder, file)` → `[&DumpError]` index for O(1) per-entry lookup.
///
/// Pre-computing this once and then calling [`find_dump_error_in_index`] per
/// entry reduces overall complexity from O(N×M) to O(N+M) — important when
/// N (entries) and M (dump errors) are both large.
pub fn build_dump_error_index(errors: &[DumpError]) -> HashMap<(&str, &str), Vec<&DumpError>> {
    let mut index: HashMap<(&str, &str), Vec<&DumpError>> = HashMap::new();
    for de in errors {
        index
            .entry((de.folder.as_str(), de.file.as_str()))
            .or_default()
            .push(de);
    }
    index
}

/// Looks up a `DumpError` matching `entry` using a pre-built index.
///
/// Mirrors a linear `DumpError` search but uses the O(1) bucket lookup from
/// [`build_dump_error_index`] instead of scanning the full slice per entry.
pub fn find_dump_error_in_index<'a>(
    index: &HashMap<(&str, &str), Vec<&'a DumpError>>,
    entry: &LogEntry,
) -> Option<&'a DumpError> {
    let service = entry.service.as_deref()?;
    let api = entry.api.as_deref()?;
    let bucket = index.get(&(service, api))?;
    if let Some(url) = entry.url.as_deref() {
        bucket.iter().copied().find(|de| de.url == url)
    } else {
        // No URL to disambiguate: still narrow by HTTP status / upstream code
        // when the entry carries them, so an entry is not matched to an
        // unrelated `DumpError` of the same service/api (e.g. a 500 entry
        // matching a 403 *expected* error and being wrongly hidden).
        bucket.iter().copied().find(|de| {
            entry.http_status.is_none_or(|s| de.status == s)
                && entry.upstream_code.as_deref().is_none_or(|c| de.code == c)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tail_captures_bare_upstream_code_without_http_status() {
        // A dump event with no HTTP status (e.g. MissingBatchData) writes the code
        // as a bare segment "svc<SEP>api | CODE | message". parse_tail must capture
        // that segment as upstream_code; otherwise it stays None and
        // find_dump_error_in_index mis-attributes the entry.
        let tail = format!("graph{SERVICE_API_SEPARATOR}users | MissingBatchData | some message");
        let e = parse_tail(
            "2026-06-06 18:40:36".to_string(),
            LogLevel::Warn,
            "ResponseThread".to_string(),
            &tail,
        );
        assert_eq!(e.service.as_deref(), Some("graph"));
        assert_eq!(e.api.as_deref(), Some("users"));
        assert_eq!(e.http_status, None);
        assert_eq!(e.upstream_code.as_deref(), Some("MissingBatchData"));
        assert_eq!(e.message, "some message");
    }

    #[test]
    fn parse_tail_bare_code_with_url_and_id_segments() {
        // The bare code must be captured even when URL and "ID N" segments follow,
        // and the "ID N" segment must not be mistaken for the code.
        let tail = format!(
            "graph{SERVICE_API_SEPARATOR}users | MissingBatchData | URL https://example/x | ID 5 | msg"
        );
        let e = parse_tail("t".to_string(), LogLevel::Warn, "m".to_string(), &tail);
        assert_eq!(e.upstream_code.as_deref(), Some("MissingBatchData"));
        assert_eq!(e.url.as_deref(), Some("https://example/x"));
        assert_eq!(e.http_status, None);
    }

    #[test]
    fn parse_tail_http_status_and_code_still_parsed() {
        // Guard the existing HTTP path: "HTTP <status> <code>" still wins.
        let tail =
            format!("graph{SERVICE_API_SEPARATOR}users | HTTP 500 InternalServerError | msg");
        let e = parse_tail("t".to_string(), LogLevel::Error, "m".to_string(), &tail);
        assert_eq!(e.http_status, Some(500));
        assert_eq!(e.upstream_code.as_deref(), Some("InternalServerError"));
    }

    #[test]
    fn find_dump_error_in_index_no_url_narrows_by_status_and_code() {
        // Two errors for the same service/api but different status/code. A
        // URL-less log entry carrying a status/code must match the *matching*
        // DumpError, not just the first one for that service/api.
        let mk = |url: &str, status: u16, code: &str, expected: bool| DumpError {
            folder: "graph".to_string(),
            file: "users".to_string(),
            url: url.to_string(),
            status,
            code: code.to_string(),
            message: String::new(),
            expected,
            full_response: None,
            post_data: None,
        };
        let errors = vec![
            mk("u1", 403, "Forbidden", true),
            mk("u2", 500, "InternalServerError", false),
        ];
        let entry = LogEntry {
            timestamp: String::new(),
            level: LogLevel::Warn,
            module: String::new(),
            service: Some("graph".to_string()),
            api: Some("users".to_string()),
            http_status: Some(500),
            upstream_code: Some("InternalServerError".to_string()),
            url: None,
            message: String::new(),
        };
        let index = build_dump_error_index(&errors);
        let found = find_dump_error_in_index(&index, &entry).expect("should match the 500 error");
        assert_eq!(found.status, 500);
        assert!(
            !found.expected,
            "must not match the unrelated 403 expected error"
        );
    }

    #[test]
    fn test_parse_log_with_non_ascii_chars() {
        // 25 emojis (4 bytes each = 100 bytes).
        // The 26th char is the space.
        let emojis = "🌍".repeat(25);
        let log = format!(
            "2026-04-18 10:08:50  |  INFO   | {}  Tail message\n",
            emojis
        );
        let entries = parse_log(&log);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].module, emojis);
        assert_eq!(entries[0].message, "Tail message");
    }

    #[test]
    fn test_parse_log_plain_message() {
        let log = "2026-04-18 10:08:50  |  INFO   | main                     Server started\n";
        let entries = parse_log(log);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].level, LogLevel::Info);
        assert!(entries[0].service.is_none());
        assert_eq!(entries[0].message, "Server started");
        assert_eq!(entries[0].timestamp, "2026-04-18 10:08:50");
    }

    #[test]
    fn test_parse_log_api_event_with_url() {
        // "ResponseThread" = 14 chars; padded to FL=25 needs 11 spaces
        let log = "2026-04-18 10:08:50  |  WARN   | ResponseThread           graph \u{00b7} roleDefinitions | HTTP 404 Request_ResourceNotFound | URL https://example.com/api | Resource not found\n";
        let entries = parse_log(log);
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.level, LogLevel::Warn);
        assert_eq!(e.service.as_deref(), Some("graph"));
        assert_eq!(e.api.as_deref(), Some("roleDefinitions"));
        assert_eq!(e.http_status, Some(404));
        assert_eq!(e.upstream_code.as_deref(), Some("Request_ResourceNotFound"));
        assert_eq!(e.url.as_deref(), Some("https://example.com/api"));
        assert_eq!(e.message, "Resource not found");
    }

    #[test]
    fn test_parse_log_api_event_no_url() {
        let log = "2026-04-18 10:08:50  |  WARN   | ResponseThread           graph \u{00b7} users | HTTP 500 InternalError | Something went wrong\n";
        let entries = parse_log(log);
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.http_status, Some(500));
        assert!(e.url.is_none());
        assert_eq!(e.message, "Something went wrong");
    }

    #[test]
    fn test_group_entries_deduplicates() {
        // Three entries: two identical (same service/api/status/code/msg), one distinct
        let log = concat!(
            "2026-04-18 10:08:50  |  WARN   | ResponseThread           graph \u{00b7} users | HTTP 403 Authorization_RequestDenied | URL https://a.com | Denied\n",
            "2026-04-18 10:08:51  |  WARN   | ResponseThread           graph \u{00b7} users | HTTP 403 Authorization_RequestDenied | URL https://b.com | Denied\n",
            "2026-04-18 10:08:52  |  WARN   | ResponseThread           graph \u{00b7} users | HTTP 404 Request_ResourceNotFound | URL https://c.com | Not found\n",
        );
        let entries: Vec<LogEntry> = parse_log(log)
            .into_iter()
            .filter(|e| e.service.is_some())
            .collect();
        let groups = group_entries(entries);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].count, 2);
        assert_eq!(groups[0].all_urls.len(), 2);
        assert_eq!(groups[1].count, 1);
    }

    #[test]
    fn last_plain_failure_context_returns_last_n_errors_with_debug_followup() {
        let log = concat!(
            "2026-05-28 10:00:00  |  INFO   | main                     start\n",
            "2026-05-28 10:00:01  |  ERROR  | Auth                     token failed\n",
            "2026-05-28 10:00:01  |  DEBUG  | Auth                     reason: TimedOut\n",
            "2026-05-28 10:00:02  |  INFO   | main                     unrelated info\n",
            "2026-05-28 10:00:03  |  ERROR  | Tokens                   could not acquire\n",
            // No DEBUG follow-up on the same module: should not pull next line.
            "2026-05-28 10:00:03  |  TRACE  | Other                    different module\n",
        );
        let entries = parse_log(log);
        let ctx = last_plain_failure_context(&entries, 3);
        // Two ERROR entries, plus the DEBUG follow-up of the first one.
        assert_eq!(ctx.len(), 3);
        assert_eq!(ctx[0].level, LogLevel::Error);
        assert_eq!(ctx[0].module, "Auth");
        assert_eq!(ctx[1].level, LogLevel::Debug);
        assert_eq!(ctx[1].module, "Auth");
        assert!(ctx[1].message.contains("TimedOut"));
        assert_eq!(ctx[2].level, LogLevel::Error);
        assert_eq!(ctx[2].module, "Tokens");
    }

    #[test]
    fn last_plain_failure_context_caps_at_limit() {
        let log = concat!(
            "2026-05-28 10:00:01  |  ERROR  | A                        e1\n",
            "2026-05-28 10:00:02  |  ERROR  | B                        e2\n",
            "2026-05-28 10:00:03  |  ERROR  | C                        e3\n",
            "2026-05-28 10:00:04  |  ERROR  | D                        e4\n",
        );
        let entries = parse_log(log);
        let ctx = last_plain_failure_context(&entries, 2);
        // Keeps only the last 2 ERROR entries (C and D).
        assert_eq!(ctx.len(), 2);
        assert_eq!(ctx[0].module, "C");
        assert_eq!(ctx[1].module, "D");
    }

    #[test]
    fn last_plain_failure_context_skips_api_entries() {
        // API entries (service = Some) must be excluded — they belong to the
        // per-API listing, not the fatal-context surfacing.
        let log = concat!(
            "2026-05-28 10:00:01  |  ERROR  | ResponseThread           graph \u{00b7} users | HTTP 500 ServerError | URL https://x | boom\n",
            "2026-05-28 10:00:02  |  ERROR  | Auth                     token failed\n",
        );
        let entries = parse_log(log);
        let ctx = last_plain_failure_context(&entries, 5);
        assert_eq!(ctx.len(), 1);
        assert_eq!(ctx[0].module, "Auth");
    }

    #[test]
    fn last_plain_failure_context_empty_when_no_errors() {
        let log = "2026-05-28 10:00:00  |  INFO   | main                     ok\n";
        assert!(last_plain_failure_context(&parse_log(log), 3).is_empty());
    }

    #[test]
    fn last_plain_failure_context_limit_zero_returns_empty() {
        let log = "2026-05-28 10:00:00  |  ERROR  | main                     boom\n";
        assert!(last_plain_failure_context(&parse_log(log), 0).is_empty());
    }

    #[test]
    fn test_group_entries_preserves_order() {
        // First error seen should be the representative entry
        let log = concat!(
            "2026-04-18 10:08:50  |  ERROR  | ResponseThread           graph \u{00b7} users | HTTP 403 Authorization_RequestDenied | URL https://first.com | Denied\n",
            "2026-04-18 10:08:51  |  ERROR  | ResponseThread           graph \u{00b7} users | HTTP 403 Authorization_RequestDenied | URL https://second.com | Denied\n",
        );
        let entries: Vec<LogEntry> = parse_log(log)
            .into_iter()
            .filter(|e| e.service.is_some())
            .collect();
        let groups = group_entries(entries);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].first.url.as_deref(), Some("https://first.com"));
        assert_eq!(groups[0].count, 2);
    }
}
