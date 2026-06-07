//! Render `stats.json` in a human-readable form for `oradaz inspect stats`.
//!
//! Highlights APIs that look problematic (unexpected errors, network errors,
//! heavy 429 throttling, prereq re-checks) so the user can target them when
//! iterating on the schema.

use super::{
    Align, INDENT, Row, branch_glyph, ellipsis, mid_sep, print_collection_summary, render_table,
    rule, section_line,
};
use crate::utils::ui::{dim, err_text, warn_text};

use chrono::DateTime;
use serde_json::Value;

const API_COL: usize = 80;

/// Friendly duration string used across multiple sections — "1 h 23 min 04 s"
/// for a long activity window, "5 s" for a short one.
pub fn fmt_duration(seconds: i64) -> String {
    let h = seconds / 3600;
    let m = (seconds % 3600) / 60;
    let s = seconds % 60;
    if h > 0 {
        format!("{h} h {m:02} min {s:02} s")
    } else if m > 0 {
        format!("{m} min {s:02} s")
    } else {
        format!("{s} s")
    }
}

pub fn u64_field(v: &Value, key: &str) -> u64 {
    v.get(key).and_then(|x| x.as_u64()).unwrap_or(0)
}

pub fn str_field<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(|x| x.as_str())
}

/// Build a one-line problem report for an API, in priority order.
///
/// `total_duration_secs` is the dump's wall-clock duration; when > 0 it
/// appends a ", cumulative" clarifier to the rate-limit wait (see
/// `wall_time_pct`), flagging APIs whose throttling wait is a large share of
/// the run — i.e. *blocking* the pipeline, not just noisy.
fn problem_summary(api: &Value, total_duration_secs: i64) -> Option<(String, bool)> {
    let unexpected = u64_field(api, "unexpected_errors");
    let network = u64_field(api, "network_errors");
    let prereq = u64_field(api, "prereq_rechecks_triggered");
    let rl_retries = u64_field(api, "retries_rate_limit");
    let rl_wait = u64_field(api, "rate_limit_wait_secs");
    let requests = u64_field(api, "requests_sent").max(1);

    let mut parts: Vec<String> = Vec::new();
    let mut critical = false;

    if unexpected > 0 {
        parts.push(format!("{unexpected} unexpected errors"));
        critical = true;
    }
    if network > 0 {
        parts.push(format!("{network} request failures"));
        critical = true;
    }
    if prereq > 0 {
        parts.push(format!("{prereq} prereq rechecks"));
        critical = true;
    }
    if rl_wait > 60 {
        parts.push(format!(
            "{rl_retries} 429 retries ({rl_wait} s wait{})",
            wall_time_pct(rl_wait, total_duration_secs)
        ));
    } else if rl_retries * 5 > requests {
        // more than 20% of requests throttled
        parts.push(format!("{rl_retries} 429 retries"));
    }

    if parts.is_empty() {
        None
    } else {
        Some((parts.join(mid_sep()), critical))
    }
}

/// Append a `, cumulative` clarifier to the throttle line when this API has a
/// non-trivial Retry-After wait during a timed run. We deliberately do NOT
/// print a "% of total wall time": the wait is summed across concurrent
/// requests and routinely exceeds wall-clock (a misleading >100 %). The raw
/// wait seconds are shown by the caller. (Name kept for call-site stability.)
fn wall_time_pct(wait_secs: u64, total_duration_secs: i64) -> String {
    if total_duration_secs <= 0 || wait_secs == 0 {
        return String::new();
    }
    ", cumulative".to_string()
}

fn severity_score(api: &Value) -> u64 {
    // Higher = more concerning. Used to sort the "problematic APIs" list.
    let unexpected = u64_field(api, "unexpected_errors");
    let network = u64_field(api, "network_errors");
    let prereq = u64_field(api, "prereq_rechecks_triggered");
    let rl_wait = u64_field(api, "rate_limit_wait_secs");
    unexpected * 1000 + network * 500 + prereq * 200 + rl_wait
}

fn success_rate_pct(api: &Value) -> Option<f64> {
    let requests = u64_field(api, "requests_sent");
    if requests == 0 {
        return None;
    }
    let unexpected = u64_field(api, "unexpected_errors");
    let network = u64_field(api, "network_errors");
    let bad = unexpected + network;
    Some((requests.saturating_sub(bad)) as f64 / requests as f64 * 100.0)
}

/// `"service/api"` label for a `stats.apis[]` entry — used by the
/// `PROBLEMATIC APIS` rows and by the new `inspect timeline` view.
pub fn api_label(api: &Value) -> String {
    let svc = str_field(api, "service").unwrap_or("?");
    let name = str_field(api, "api").unwrap_or("?");
    format!("{svc}/{name}")
}

/// Format the top N entries of a status code map (excluding 2xx/3xx success)
/// as `500×12, 502×4` for inclusion in the problematic APIs detail line.
fn top_failing_statuses(api: &Value, limit: usize) -> Option<String> {
    let map = api.get("responses_by_status")?.as_object()?;
    let mut entries: Vec<(u16, u64)> = map
        .iter()
        .filter_map(|(k, v)| {
            let status = k.parse::<u16>().ok()?;
            // Only show failures (drop 1xx/2xx/3xx — 429 has its own line).
            if (200..400).contains(&status) || status == 429 {
                return None;
            }
            Some((status, v.as_u64().unwrap_or(0)))
        })
        .filter(|(_, n)| *n > 0)
        .collect();
    if entries.is_empty() {
        return None;
    }
    entries.sort_by(|a, b| b.1.cmp(&a.1));
    let formatted: Vec<String> = entries
        .into_iter()
        .take(limit)
        .map(|(s, n)| format!("{s}×{n}"))
        .collect();
    Some(formatted.join(", "))
}

/// Format the top N upstream error codes — strings like "UnknownError",
/// "Forbidden", "InvalidAuthenticationToken" — as `UnknownError×8, Forbidden×3`.
fn top_upstream_codes(api: &Value, limit: usize) -> Option<String> {
    let map = api.get("upstream_error_codes")?.as_object()?;
    let mut entries: Vec<(&str, u64)> = map
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_u64().unwrap_or(0)))
        .filter(|(_, n)| *n > 0)
        .collect();
    if entries.is_empty() {
        return None;
    }
    entries.sort_by(|a, b| b.1.cmp(&a.1));
    let formatted: Vec<String> = entries
        .into_iter()
        .take(limit)
        .map(|(k, n)| format!("{k}×{n}"))
        .collect();
    Some(formatted.join(", "))
}

/// Activity window for an API in seconds — `last_request_at - first_request_at`.
/// Returns `None` when either timestamp is missing or unparsable, or when both
/// timestamps collapse to a single instant (a single-shot API).
pub fn api_activity_seconds(api: &Value) -> Option<i64> {
    let first =
        str_field(api, "first_request_at").and_then(|s| DateTime::parse_from_rfc3339(s).ok())?;
    let last =
        str_field(api, "last_request_at").and_then(|s| DateTime::parse_from_rfc3339(s).ok())?;
    let secs = (last - first).num_seconds();
    if secs > 0 { Some(secs) } else { None }
}

pub fn print_stats_section(
    metadata: Option<&Value>,
    config: Option<&Value>,
    stats: Option<&Value>,
    top: usize,
    all: bool,
    service: Option<&str>,
    out: &mut Vec<String>,
) {
    print_collection_summary(metadata, config, out);

    out.push(String::new());
    out.push(section_line("STATISTICS SUMMARY", None));
    out.push(String::new());

    let stats = match stats {
        Some(s) => s,
        None => {
            out.push(format!(
                "{}(no stats.json found — archive collected with an older oradaz version)",
                INDENT
            ));
            return;
        }
    };

    let duration = stats
        .get("duration_seconds")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    // The summary block intentionally stays global — `--service` only narrows
    // the per-API sections below (PROBLEMATIC APIS, TOP APIS BY *) so the user
    // keeps tenant-wide context while drilling.
    let apis: Vec<Value> = stats
        .get("apis")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let filtered_apis: Vec<Value> = match service {
        None => apis.clone(),
        Some(svc) => apis
            .iter()
            .filter(|a| str_field(a, "service") == Some(svc))
            .cloned()
            .collect(),
    };

    let total_requests: u64 = apis.iter().map(|a| u64_field(a, "requests_sent")).sum();
    // Use the per-service HTTP totals when present — summing across APIs would
    // double-count a batch HTTP call that targets several APIs.
    let services_map = stats.get("services").and_then(|v| v.as_object());
    let (total_batch, total_single): (u64, u64) = match services_map {
        Some(map) => {
            let mut b = 0u64;
            let mut s = 0u64;
            for (_, svc) in map.iter() {
                b += u64_field(svc, "http_batch_calls");
                s += u64_field(svc, "http_single_calls");
            }
            (b, s)
        }
        None => (
            apis.iter().map(|a| u64_field(a, "http_batch_calls")).sum(),
            apis.iter().map(|a| u64_field(a, "http_single_calls")).sum(),
        ),
    };
    // For the summary line, count one network error per failed HTTP call
    // (taken from the per-service `http_call_failures` if present). Summing
    // the per-API `network_errors` would inflate the figure by the batch
    // size, because a failed batch attributes the failure to every sub-URL.
    let total_network: u64 = match services_map {
        Some(map) => map
            .iter()
            .map(|(_, svc)| u64_field(svc, "http_call_failures"))
            .sum(),
        None => apis.iter().map(|a| u64_field(a, "network_errors")).sum(),
    };
    let total_unexpected: u64 = apis.iter().map(|a| u64_field(a, "unexpected_errors")).sum();
    let total_expected: u64 = apis.iter().map(|a| u64_field(a, "expected_errors")).sum();
    let total_rl_retries: u64 = apis
        .iter()
        .map(|a| u64_field(a, "retries_rate_limit"))
        .sum();
    let total_rl_wait: u64 = apis
        .iter()
        .map(|a| u64_field(a, "rate_limit_wait_secs"))
        .sum();

    out.push(format!("  {:<28}{}", "Duration", fmt_duration(duration)));
    out.push(format!(
        "  {:<28}{} (logical URLs)",
        "Total requests", total_requests
    ));
    out.push(format!(
        "  {:<28}{} ({} batched + {} single)",
        "HTTP calls",
        total_batch + total_single,
        total_batch,
        total_single
    ));
    // Per-service breakdown — matches the "Finished dump using N requests" line
    // printed at the end of a collection.
    if let Some(map) = services_map {
        let mut entries: Vec<(&String, &Value)> = map.iter().collect();
        entries.sort_by_key(|(k, _)| (*k).clone());
        for (svc, v) in entries {
            let b = u64_field(v, "http_batch_calls");
            let s = u64_field(v, "http_single_calls");
            out.push(format!(
                "  {:<28}{} ({} batched + {} single)",
                format!("  {svc}"),
                b + s,
                b,
                s
            ));
        }
    }
    // "Request failures" (not "Network errors"): this counts HTTP calls that
    // failed at transport *or* JSON-parse level (both routed through
    // `finalize_retry`), so "network errors" would be a misleading label. The figure is per failed
    // call (from per-service `http_call_failures`), not per sub-request — see the
    // note under PROBLEMATIC APIS.
    out.push(format!("  {:<28}{}", "Request failures", total_network));
    out.push(format!(
        "  {:<28}{} expected{sep}{} unexpected",
        "API errors (4xx/5xx)",
        total_expected,
        total_unexpected,
        sep = mid_sep()
    ));
    out.push(format!(
        "  {:<28}{} retries ({} s total Retry-After)",
        "429 throttling", total_rl_retries, total_rl_wait
    ));

    // Problematic APIs
    out.push(String::new());
    out.push(section_line("PROBLEMATIC APIS", None));
    out.push(String::new());
    // Reconcile the per-API view with the summary above: a failed batch call is
    // attributed to each sub-request it carried, so per-API "request failures"
    // sum higher than the per-call "Request failures" figure in the summary.
    // Only shown when such failures exist — no need to explain an absent gap.
    if filtered_apis
        .iter()
        .any(|a| u64_field(a, "network_errors") > 0)
    {
        out.push(format!(
            "  {}",
            dim("(per-API request failures are counted per sub-request; one failed batch call appears once in the summary but once per sub-request here)")
        ));
        out.push(String::new());
    }

    let mut problematic: Vec<(u64, String, String, bool)> = filtered_apis
        .iter()
        .filter_map(|a| {
            problem_summary(a, duration)
                .map(|(msg, critical)| (severity_score(a), api_label(a), msg, critical))
        })
        .collect();
    problematic.sort_by(|a, b| b.0.cmp(&a.0));

    // Re-resolve apis-by-label so each problematic entry can render the extra
    // detail lines (status code breakdown, upstream codes, retry pressure).
    let by_label: std::collections::HashMap<String, &Value> =
        filtered_apis.iter().map(|a| (api_label(a), a)).collect();

    if problematic.is_empty() {
        out.push(format!("{}(no problematic API detected)", INDENT));
    } else {
        for (_, label, msg, critical) in problematic.iter().take(top) {
            // Use the shared severity glyph (●/◐ in color, !!/! in no-color)
            // so this section and `inspect timeline` stay in lockstep.
            let badge = super::severity_icon(*critical);
            let label_padded = format!("{:<API_COL$}", label);
            let painted_label = if *critical {
                err_text(&label_padded)
            } else {
                warn_text(&label_padded)
            };
            out.push(format!("  {} {} {}", badge, painted_label, msg));

            // Second-level diagnostic lines, indented under the API entry,
            // surface the *what* and *why* behind the headline figures.
            if let Some(api) = by_label.get(label) {
                let detail_indent = "       "; // 7 spaces, like INDENT
                let br = branch_glyph();
                if let Some(statuses) = top_failing_statuses(api, 4) {
                    out.push(dim(&format!("{detail_indent}{br} statuses: {statuses}")));
                }
                if let Some(codes) = top_upstream_codes(api, 4) {
                    out.push(dim(&format!("{detail_indent}{br} codes: {codes}")));
                }
                let real_retries = u64_field(api, "retries_real");
                let prereq_triggered = u64_field(api, "prereq_rechecks_triggered");
                if real_retries > 0 || prereq_triggered > 0 {
                    let mut bits: Vec<String> = Vec::new();
                    if real_retries > 0 {
                        bits.push(format!("{real_retries} real retries"));
                    }
                    if prereq_triggered > 0 {
                        bits.push(format!("triggered {prereq_triggered} prereq re-check(s)"));
                    }
                    out.push(dim(&format!(
                        "{detail_indent}{br} {}",
                        bits.join(mid_sep())
                    )));
                }
            }
        }
        if problematic.len() > top {
            out.push(format!(
                "{}{} and {} more (use --top {} or --all to see them)",
                INDENT,
                ellipsis(),
                problematic.len() - top,
                problematic.len()
            ));
        }
    }

    // Top APIs by volume
    out.push(String::new());
    out.push(section_line("TOP APIS BY VOLUME", None));
    out.push(String::new());

    let mut by_volume: Vec<&Value> = filtered_apis.iter().collect();
    by_volume.sort_by_key(|b| std::cmp::Reverse(u64_field(b, "requests_sent")));

    let limit = if all {
        by_volume.len()
    } else {
        top.min(by_volume.len())
    };
    let mut rows: Vec<Row> = Vec::new();
    for api in by_volume.iter().take(limit) {
        let label = api_label(api);
        let requests = u64_field(api, "requests_sent");
        let batches = u64_field(api, "http_batch_calls");
        let singles = u64_field(api, "http_single_calls");
        let ok = success_rate_pct(api)
            .map(|p| format!("{p:.1}%"))
            .unwrap_or_else(|| "—".to_string());
        rows.push(Row::Cells(vec![
            label,
            requests.to_string(),
            batches.to_string(),
            singles.to_string(),
            ok,
        ]));
    }
    render_table(
        "  ",
        &["API", "req (w/retries)", "batches", "singles", "OK%"],
        &[
            Align::Left,
            Align::Right,
            Align::Right,
            Align::Right,
            Align::Right,
        ],
        &rows,
        out,
    );
    if !all && by_volume.len() > limit {
        out.push(format!(
            "{}{} {} more APIs (use --all to see them)",
            INDENT,
            ellipsis(),
            by_volume.len() - limit
        ));
    }

    // Top APIs by activity window (last_request_at - first_request_at)
    out.push(String::new());
    out.push(section_line("TOP APIS BY ACTIVITY WINDOW", None));
    out.push(String::new());

    let mut by_duration: Vec<(i64, &Value)> = filtered_apis
        .iter()
        .filter_map(|a| api_activity_seconds(a).map(|d| (d, a)))
        .collect();
    by_duration.sort_by(|a, b| b.0.cmp(&a.0));

    if by_duration.is_empty() {
        out.push(format!(
            "{}(no API spanned more than a second of activity)",
            INDENT
        ));
    } else {
        let limit_d = if all {
            by_duration.len()
        } else {
            top.min(by_duration.len())
        };
        let mut rows: Vec<Row> = Vec::new();
        for (secs, api) in by_duration.iter().take(limit_d) {
            let label = api_label(api);
            let requests = u64_field(api, "requests_sent");
            rows.push(Row::Cells(vec![
                label,
                fmt_duration(*secs),
                requests.to_string(),
            ]));
        }
        render_table(
            "  ",
            &["API", "Active window", "Requests"],
            &[Align::Left, Align::Right, Align::Right],
            &rows,
            out,
        );
        if !all && by_duration.len() > limit_d {
            out.push(format!(
                "{}{} {} more APIs (use --all to see them)",
                INDENT,
                ellipsis(),
                by_duration.len() - limit_d
            ));
        }
    }

    // Top APIs by mean HTTP latency. Per-API latency is recorded only for
    // single-call services (resources/ARG, exchange) — a batch envelope's
    // round-trip can't be attributed to one sub-URL, so batched Graph APIs are
    // absent here and surface at service granularity in the next section.
    out.push(String::new());
    out.push(section_line("TOP APIS BY LATENCY", None));
    out.push(String::new());

    let mut by_latency: Vec<(u64, &Value)> = filtered_apis
        .iter()
        .filter_map(|a| {
            let count = u64_field(a, "http_latency_count");
            if count == 0 {
                return None;
            }
            Some((u64_field(a, "http_latency_sum_ms") / count, a))
        })
        .collect();
    by_latency.sort_by(|a, b| b.0.cmp(&a.0));

    if by_latency.is_empty() {
        out.push(format!(
            "{}(no per-API latency recorded — only single-call services report it)",
            INDENT
        ));
    } else {
        let limit_l = if all {
            by_latency.len()
        } else {
            top.min(by_latency.len())
        };
        let mut rows: Vec<Row> = Vec::new();
        for (mean, api) in by_latency.iter().take(limit_l) {
            rows.push(Row::Cells(vec![
                api_label(api),
                format!("{mean} ms"),
                format!("{} ms", u64_field(api, "http_latency_max_ms")),
                u64_field(api, "http_latency_count").to_string(),
            ]));
        }
        render_table(
            "  ",
            &["API", "mean", "max", "calls"],
            &[Align::Left, Align::Right, Align::Right, Align::Right],
            &rows,
            out,
        );
        if !all && by_latency.len() > limit_l {
            out.push(format!(
                "{}{} {} more APIs (use --all to see them)",
                INDENT,
                ellipsis(),
                by_latency.len() - limit_l
            ));
        }
    }

    // Per-service HTTP latency (covers batched services, unlike the per-API table
    // above) and Retry-After provenance: how many 429s carried a server value vs
    // fell back to the configured default, and the largest server value seen.
    out.push(String::new());
    out.push(section_line("LATENCY & RETRY-AFTER BY SERVICE", None));
    out.push(String::new());

    match services_map {
        None => out.push(format!("{}(no per-service stats recorded)", INDENT)),
        Some(map) => {
            let mut entries: Vec<(&String, &Value)> = map
                .iter()
                .filter(|(svc, _)| match service {
                    None => true,
                    Some(s) => svc.as_str() == s,
                })
                .collect();
            entries.sort_by_key(|(k, _)| (*k).clone());
            let mut rows: Vec<Row> = Vec::new();
            for (svc, v) in entries {
                let count = u64_field(v, "http_latency_count");
                let (mean, max) = if count > 0 {
                    (
                        format!("{} ms", u64_field(v, "http_latency_sum_ms") / count),
                        format!("{} ms", u64_field(v, "http_latency_max_ms")),
                    )
                } else {
                    ("—".to_string(), "—".to_string())
                };
                let server = u64_field(v, "retry_after_server_count");
                let default = u64_field(v, "retry_after_default_count");
                let ra = if server + default > 0 {
                    format!(
                        "{server}/{default} (max {} s)",
                        u64_field(v, "retry_after_max_secs")
                    )
                } else {
                    "—".to_string()
                };
                rows.push(Row::Cells(vec![svc.clone(), mean, max, ra]));
            }
            if rows.is_empty() {
                out.push(format!("{}(no matching service)", INDENT));
            } else {
                render_table(
                    "  ",
                    &["Service", "lat. mean", "lat. max", "Retry-After srv/def"],
                    &[Align::Left, Align::Right, Align::Right, Align::Right],
                    &rows,
                    out,
                );
            }
        }
    }

    // Request shape / amplification: how schema endpoints turn into HTTP traffic.
    // `pages_followed` (pages beyond the first) flags per-API `$top` candidates;
    // `child_urls_generated` (relationship fan-out) flags `$expand`/pruning
    // candidates. Both default to 0 on archives collected before this telemetry.
    out.push(String::new());
    out.push(section_line("REQUEST SHAPE (PAGINATION / FAN-OUT)", None));
    out.push(String::new());

    let mut by_shape: Vec<(u64, u64, &Value)> = filtered_apis
        .iter()
        .filter_map(|a| {
            let pages = u64_field(a, "pages_followed");
            let children = u64_field(a, "child_urls_generated");
            if pages == 0 && children == 0 {
                return None;
            }
            Some((pages, children, a))
        })
        .collect();
    by_shape.sort_by(|a, b| (b.0 + b.1).cmp(&(a.0 + a.1)));

    if by_shape.is_empty() {
        out.push(format!(
            "{}(no pagination or relationship fan-out recorded)",
            INDENT
        ));
    } else {
        let limit_s = if all {
            by_shape.len()
        } else {
            top.min(by_shape.len())
        };
        let mut rows: Vec<Row> = Vec::new();
        for (pages, children, api) in by_shape.iter().take(limit_s) {
            rows.push(Row::Cells(vec![
                api_label(api),
                pages.to_string(),
                children.to_string(),
                u64_field(api, "requests_sent").to_string(),
            ]));
        }
        render_table(
            "  ",
            &["API", "pages", "fan-out", "requests"],
            &[Align::Left, Align::Right, Align::Right, Align::Right],
            &rows,
            out,
        );
        if !all && by_shape.len() > limit_s {
            out.push(format!(
                "{}{} {} more APIs (use --all to see them)",
                INDENT,
                ellipsis(),
                by_shape.len() - limit_s
            ));
        }
    }

    // Per-service batch fill: how full the up-to-20-per-envelope batches packed.
    // avg fill = batch_subrequests_total / http_batch_calls. Well below 20 means
    // a small dispatch frontier or the Graph v1.0/beta envelope split.
    out.push(String::new());
    out.push(section_line("BATCH FILL BY SERVICE", None));
    out.push(String::new());

    match services_map {
        None => out.push(format!("{}(no per-service stats recorded)", INDENT)),
        Some(map) => {
            let mut entries: Vec<(&String, &Value)> = map
                .iter()
                .filter(|(svc, _)| match service {
                    None => true,
                    Some(s) => svc.as_str() == s,
                })
                .filter(|(_, v)| u64_field(v, "http_batch_calls") > 0)
                .collect();
            entries.sort_by_key(|(k, _)| (*k).clone());
            if entries.is_empty() {
                out.push(format!("{}(no batched service)", INDENT));
            } else {
                let mut rows: Vec<Row> = Vec::new();
                for (svc, v) in entries {
                    // `http_batch_calls > 0` is guaranteed by the filter above.
                    let batches = u64_field(v, "http_batch_calls");
                    let subreqs = u64_field(v, "batch_subrequests_total");
                    // `subreqs == 0` with batches > 0 means the field was absent
                    // (archive predates this telemetry) — show "—" rather than a
                    // misleading 0.0, matching the latency section's convention.
                    let avg = if subreqs > 0 {
                        format!("{:.1}", subreqs as f64 / batches as f64)
                    } else {
                        "—".to_string()
                    };
                    rows.push(Row::Cells(vec![
                        svc.clone(),
                        batches.to_string(),
                        subreqs.to_string(),
                        avg,
                    ]));
                }
                render_table(
                    "  ",
                    &["Service", "batches", "sub-reqs", "avg fill"],
                    &[Align::Left, Align::Right, Align::Right, Align::Right],
                    &rows,
                    out,
                );
            }
        }
    }

    // Conditions
    out.push(String::new());
    out.push(section_line("CONDITIONS EVALUATED", None));
    out.push(String::new());

    let conditions: Vec<Value> = stats
        .get("conditions")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if conditions.is_empty() {
        out.push(format!("{}(no condition recorded)", INDENT));
    } else {
        let mut sorted = conditions.clone();
        sorted.sort_by_key(|b| std::cmp::Reverse(u64_field(b, "checks")));
        let mut rows: Vec<Row> = Vec::new();
        for c in &sorted {
            let name = str_field(c, "name").unwrap_or("?");
            let checks = u64_field(c, "checks");
            let true_count = u64_field(c, "true_count");
            let false_count = u64_field(c, "false_count");
            rows.push(Row::Cells(vec![
                name.to_string(),
                checks.to_string(),
                true_count.to_string(),
                false_count.to_string(),
            ]));
        }
        render_table(
            "  ",
            &["Condition", "checks", "true", "false"],
            &[Align::Left, Align::Right, Align::Right, Align::Right],
            &rows,
            out,
        );
    }

    // Prerequisite re-checks
    out.push(String::new());
    out.push(section_line("PREREQUISITE RE-CHECKS", None));
    out.push(String::new());

    let prereq = stats.get("prereq_rechecks").and_then(|v| v.as_object());
    match prereq {
        None => out.push(format!("{}(no prereq re-check recorded)", INDENT)),
        Some(map) if map.is_empty() => {
            out.push(format!("{}(no prereq re-check recorded)", INDENT));
        }
        Some(map) => {
            let header = format!("  {:<20} {:>10}", "Service", "rechecks");
            out.push(dim(&header));
            out.push(dim(&format!("  {}", rule(32))));
            let mut entries: Vec<(&String, u64)> = map
                .iter()
                .map(|(k, v)| (k, v.as_u64().unwrap_or(0)))
                .collect();
            entries.sort_by_key(|(k, _)| (*k).clone());
            for (svc, n) in entries {
                let line = format!("  {:<20} {:>10}", svc, n);
                if n > 0 {
                    out.push(warn_text(&line));
                } else {
                    out.push(line);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn wall_time_pct_empty_when_no_duration_or_no_wait() {
        assert_eq!(wall_time_pct(120, 0), "");
        assert_eq!(wall_time_pct(0, 100), "");
    }

    #[test]
    fn wall_time_pct_marks_cumulative_when_significant() {
        // Cumulative Retry-After overlaps concurrent requests and routinely
        // exceeds wall-clock, so the label shows "cumulative" rather than a
        // percentage.
        assert_eq!(wall_time_pct(30, 100), ", cumulative");
        assert_eq!(wall_time_pct(1, 10_000), ", cumulative");
    }

    /// The rate-limit detail line surfaces the "cumulative" clarifier only when
    /// the wait exceeds the headline threshold (`rl_wait > 60`). This is the
    /// signal that an API is *blocking* the pipeline, not just noisy.
    #[test]
    fn problem_summary_appends_wall_time_pct_to_rate_limit_line() {
        let api = json!({
            "service": "resources",
            "api": "subscriptions_resources_roleAssignmentSchedules",
            "requests_sent": 44,
            "retries_rate_limit": 31,
            "rate_limit_wait_secs": 268,
            "unexpected_errors": 0,
            "network_errors": 0,
            "prereq_rechecks_triggered": 0,
        });
        let (msg, critical) = problem_summary(&api, 92).expect("expected a problem report");
        assert!(!critical);
        assert!(msg.contains("31 429 retries"), "{msg}");
        assert!(msg.contains("268 s wait"), "{msg}");
        assert!(msg.contains("cumulative"), "{msg}");
    }

    #[test]
    fn problem_summary_omits_wall_time_pct_when_duration_unknown() {
        let api = json!({
            "service": "resources",
            "api": "subscriptions_resources_roleAssignmentSchedules",
            "requests_sent": 44,
            "retries_rate_limit": 31,
            "rate_limit_wait_secs": 268,
            "unexpected_errors": 0,
            "network_errors": 0,
            "prereq_rechecks_triggered": 0,
        });
        let (msg, _) = problem_summary(&api, 0).expect("expected a problem report");
        assert!(!msg.contains("cumulative"), "{msg}");
    }
}
