//! Renderer for `oradaz inspect timeline`. Composes three views that all
//! depend on real time-series data oradaz actually collects:
//!
//! 1. **ERRORS & 429 OVER TIME** — the existing per-bucket frequency chart
//!    from [`super::print_timeline`], optionally filtered to 429 only and
//!    with a `--bucket` override.
//! 2. **API ACTIVITY WINDOWS** — `last_request_at − first_request_at` per
//!    API, sorted by length (uses [`super::api_activity_seconds`]).
//! 3. **PROBLEMATIC APIS (when)** — per-API severity badge (●/◐) with the
//!    `first → last` time range, so the user can correlate the chart spikes
//!    above with the APIs that produced them.

use super::{
    INDENT, api_activity_seconds, api_label, dim, fmt_duration, mid_sep, print_timeline, rule,
    section_line, section_line_with_verdict, severity_icon, str_field, transition_arrow, u64_field,
};
use crate::inspect::analysis::{compute_verdict, has_lost_data};
use crate::inspect::loader::LogSource;
use crate::inspect::log_parser::LogEntry;

use chrono::DateTime;
use serde_json::Value;

/// CLI inputs for [`print_timeline_view`].
pub struct TimelineOptions {
    /// Optional service filter (already lower-cased by the CLI validator).
    pub service: Option<String>,
    /// Restrict the chart and the problematic list to HTTP 429 only.
    pub only_429: bool,
    /// Hide the chart + activity-windows table; keep only PROBLEMATIC APIS.
    pub problematic_only: bool,
    /// Force the chart bucket in seconds (1, 10, 60). `None` = auto.
    pub bucket: Option<i64>,
}

const API_COL: usize = 80;

pub fn print_timeline_view(
    source: &LogSource,
    entries: &[LogEntry],
    opts: &TimelineOptions,
    out: &mut Vec<String>,
) {
    let verdict = compute_verdict(
        source.metadata.as_ref(),
        source.stats.as_ref(),
        source.is_broken,
        has_lost_data(&source.dump_errors),
    );

    out.push(section_line_with_verdict("TIMELINE", verdict));
    out.push(String::new());
    print_window_line(entries, opts, out);

    if !opts.problematic_only {
        out.push(String::new());
        // Reuse the same chart that powers `logs --timeline`.
        print_timeline(entries, opts.only_429, opts.bucket, out);

        out.push(String::new());
        out.push(section_line("API ACTIVITY WINDOWS", None));
        out.push(String::new());
        print_activity_windows(source.stats.as_ref(), &opts.service, out);
    }

    out.push(String::new());
    out.push(section_line("PROBLEMATIC APIS (when)", None));
    out.push(String::new());
    print_problematic_when(source.stats.as_ref(), opts, out);
}

// ─── window header ────────────────────────────────────────────────────────

fn print_window_line(entries: &[LogEntry], opts: &TimelineOptions, out: &mut Vec<String>) {
    let mut times: Vec<&str> = entries.iter().map(|e| e.timestamp.as_str()).collect();
    times.sort();
    let (start, end) = match (times.first(), times.last()) {
        (Some(s), Some(e)) => (s.to_string(), e.to_string()),
        _ => (String::new(), String::new()),
    };
    let granularity_label = match opts.bucket {
        Some(1) => "1 s",
        Some(10) => "10 s",
        Some(60) => "1 m",
        Some(_) => "custom",
        None => "auto",
    };
    if start.is_empty() {
        out.push(format!("  {}", dim("(no entries in the selected window)")));
    } else {
        out.push(format!(
            "  Window {start} {arr} {end}{sep}granularity {granularity_label}",
            arr = transition_arrow(),
            sep = mid_sep()
        ));
    }
}

// ─── API activity windows table ──────────────────────────────────────────

fn print_activity_windows(
    stats: Option<&Value>,
    service_filter: &Option<String>,
    out: &mut Vec<String>,
) {
    let Some(apis) = stats.and_then(|s| s.get("apis")).and_then(|a| a.as_array()) else {
        out.push(format!("{}(no stats.json found)", INDENT));
        return;
    };
    let mut rows: Vec<(i64, String, u64)> = apis
        .iter()
        .filter(|api| match service_filter {
            None => true,
            Some(svc) => str_field(api, "service") == Some(svc.as_str()),
        })
        .filter_map(|api| {
            let secs = api_activity_seconds(api)?;
            let label = api_label(api);
            let requests = u64_field(api, "requests_sent");
            Some((secs, label, requests))
        })
        .collect();
    rows.sort_by(|a, b| b.0.cmp(&a.0));
    if rows.is_empty() {
        out.push(format!(
            "{}(no API spanned more than a second of activity)",
            INDENT
        ));
        return;
    }
    let header = format!(
        "  {:<API_COL$} {:>14} {:>10}",
        "API", "Active window", "Requests"
    );
    out.push(dim(&header));
    out.push(dim(&format!("  {}", rule(API_COL + 14 + 10 + 2))));
    for (secs, label, requests) in rows {
        out.push(format!(
            "  {:<API_COL$} {:>14} {:>10}",
            label,
            fmt_duration(secs),
            requests
        ));
    }
}

// ─── problematic APIs with their time range ──────────────────────────────

fn print_problematic_when(stats: Option<&Value>, opts: &TimelineOptions, out: &mut Vec<String>) {
    let Some(apis) = stats.and_then(|s| s.get("apis")).and_then(|a| a.as_array()) else {
        out.push(format!("{}(no stats.json found)", INDENT));
        return;
    };
    let mut rows: Vec<ProblematicRow> = Vec::new();
    for api in apis {
        if let Some(svc) = &opts.service
            && str_field(api, "service") != Some(svc.as_str())
        {
            continue;
        }
        let Some(row) = build_problematic_row(api, opts.only_429) else {
            continue;
        };
        rows.push(row);
    }
    if rows.is_empty() {
        out.push(format!(
            "{}(no API flagged as problematic{})",
            INDENT,
            if opts.only_429 { " for 429" } else { "" }
        ));
        return;
    }
    // Critical first (●), then warnings (◐); within each, sort by severity desc.
    rows.sort_by(|a, b| {
        b.critical
            .cmp(&a.critical)
            .then_with(|| b.severity.cmp(&a.severity))
    });
    for row in rows {
        out.push(format!(
            "  {} {:<API_COL$}  {}  {}",
            row.icon,
            row.label,
            row.detail,
            dim(&row.when)
        ));
    }
}

struct ProblematicRow {
    critical: bool,
    severity: u64,
    icon: String,
    label: String,
    detail: String,
    when: String,
}

fn build_problematic_row(api: &Value, only_429: bool) -> Option<ProblematicRow> {
    let unexpected = u64_field(api, "unexpected_errors");
    let network = u64_field(api, "network_errors");
    let prereq = u64_field(api, "prereq_rechecks_triggered");
    let rl_retries = u64_field(api, "retries_rate_limit");
    let rl_wait = u64_field(api, "rate_limit_wait_secs");
    let requests = u64_field(api, "requests_sent").max(1);

    let mut critical = false;
    let mut parts: Vec<String> = Vec::new();
    if !only_429 {
        if unexpected > 0 {
            parts.push(format!("{unexpected} unexpected errors"));
            critical = true;
        }
        if network > 0 {
            parts.push(format!("{network} network errors"));
            critical = true;
        }
        if prereq > 0 {
            parts.push(format!("{prereq} prereq rechecks"));
            critical = true;
        }
    }
    if rl_wait > 60 {
        parts.push(format!("{rl_retries}× 429 ({rl_wait} s)"));
    } else if !only_429 && rl_retries * 5 > requests {
        parts.push(format!("{rl_retries}× 429"));
    } else if only_429 && rl_retries > 0 {
        parts.push(format!("{rl_retries}× 429 ({rl_wait} s)"));
    }
    if parts.is_empty() {
        return None;
    }

    let label = api_label(api);
    let detail = parts.join(mid_sep());
    let when = activity_time_range(api).unwrap_or_else(|| "(no timestamp)".to_string());
    let severity = unexpected * 1000 + network * 500 + prereq * 200 + rl_wait;
    let icon_str = severity_icon(critical);

    Some(ProblematicRow {
        critical,
        severity,
        icon: icon_str,
        label,
        detail,
        when,
    })
}

/// `"HH:MM:SS – HH:MM:SS"` from `first_request_at`/`last_request_at`.
fn activity_time_range(api: &Value) -> Option<String> {
    let first =
        str_field(api, "first_request_at").and_then(|s| DateTime::parse_from_rfc3339(s).ok())?;
    let last =
        str_field(api, "last_request_at").and_then(|s| DateTime::parse_from_rfc3339(s).ok())?;
    Some(format!(
        "{} – {}",
        first.format("%H:%M:%S"),
        last.format("%H:%M:%S")
    ))
}
