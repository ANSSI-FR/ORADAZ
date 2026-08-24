//! Renderer for `oradaz inspect summary` — a one-screen collection-health
//! digest. Pulls verdict / coverage / aggregated errors from
//! `inspect::analysis`, and per-service token / prerequisite info from the
//! metadata JSON.

use super::{
    Align, INDENT, Row, SERVICE_ORDER, auth_type_from_config, dim, ellipsis, format_account,
    format_bytes, format_http_counts, format_thousands, mid_sep, parse_service_statuses,
    parse_tokens, render_table, section_line, section_line_with_verdict, service_cell,
    svc_display_name, unexpected_per_service,
};
use crate::inspect::analysis::{
    ErrorCategory, Verdict, aggregate_errors, compute_verdict, has_lost_data, objects_per_service,
};
use crate::inspect::loader::LogSource;
use crate::inspect::log_parser::{last_plain_failure_context, parse_log};
use crate::utils::ui::{Icon, UiMode, err_text, icon, mode, warn_text};

use serde_json::Value;

const LABEL_W: usize = 18;

/// Render the full `summary` body into `out`. Caller takes care of printing
/// the lines and optionally writing the ANSI-stripped report file.
pub fn print_overview(source: &LogSource, out: &mut Vec<String>) {
    let verdict = compute_verdict(
        source.metadata.as_ref(),
        source.stats.as_ref(),
        source.is_broken,
        has_lost_data(&source.dump_errors),
    );

    out.push(section_line_with_verdict("COLLECTION SUMMARY", verdict));
    out.push(String::new());
    print_provenance(source, out);

    out.push(String::new());
    out.push(section_line("COVERAGE", None));
    out.push(String::new());
    print_coverage(source, out);

    out.push(String::new());
    out.push(section_line("HEALTH", None));
    out.push(String::new());
    print_health(source, out);

    out.push(String::new());
    out.push(section_line("ATTENTION", None));
    out.push(String::new());
    print_attention(source, verdict, out);
}

// ─── provenance block ────────────────────────────────────────────────────

fn print_provenance(source: &LogSource, out: &mut Vec<String>) {
    let Some(m) = source.metadata.as_ref() else {
        out.push(format!("{}(no collection metadata available)", INDENT));
        return;
    };
    if let Some(v) = m.get("tenant").and_then(|v| v.as_str()) {
        out.push(format!("  {:<LABEL_W$}{}", "Tenant", v));
    }
    if let Some(v) = m.get("collection_date").and_then(|v| v.as_str()) {
        out.push(format!("  {:<LABEL_W$}{}", "Date", v));
    }
    let dump = m.get("dump_duration_secs").and_then(|v| v.as_i64());
    let total = m.get("total_duration_secs").and_then(|v| v.as_i64());
    match (dump, total) {
        (Some(d), Some(t)) if t > 0 => out.push(format!(
            "  {:<LABEL_W$}{} s collection{sep}{} s total",
            "Duration",
            d,
            t,
            sep = mid_sep()
        )),
        (Some(d), _) => out.push(format!("  {:<LABEL_W$}{} s collection", "Duration", d)),
        _ => {}
    }
    let oradaz = m
        .get("oradaz_version")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let schema = m
        .get("schema_version")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let hash_short = m
        .get("schema_hash")
        .and_then(|v| v.as_str())
        .map(|s| s.chars().take(8).collect::<String>())
        .unwrap_or_default();
    let version_line = if hash_short.is_empty() {
        format!("{} / {}", oradaz, schema)
    } else {
        format!("{} / {} (sha {}{})", oradaz, schema, hash_short, ellipsis())
    };
    out.push(format!("  {:<LABEL_W$}{}", "ORADAZ / Schema", version_line));
    if let Some(c) = source.config.as_ref() {
        out.push(format!(
            "  {:<LABEL_W$}{}",
            "Authentication",
            auth_type_from_config(c)
        ));
    }
}

// ─── coverage table ──────────────────────────────────────────────────────

fn print_coverage(source: &LogSource, out: &mut Vec<String>) {
    let objects = objects_per_service(source.metadata.as_ref());
    let tokens = parse_tokens(source.metadata.as_ref());
    let statuses = parse_service_statuses(source.metadata.as_ref());
    let stats_services = source
        .stats
        .as_ref()
        .and_then(|s| s.get("services").and_then(|v| v.as_object()));
    let unexpected = unexpected_per_service(source.stats.as_ref());

    let mut rows: Vec<Row> = Vec::new();
    for &svc in SERVICE_ORDER {
        let status = statuses
            .get(svc)
            .map(String::as_str)
            // Fallback for older archives that lack `services`: enabled if a
            // token exists, otherwise treat as not collected.
            .unwrap_or(if tokens.contains_key(svc) {
                "enabled"
            } else {
                "unknown"
            });

        let svc_cell = service_cell(svc, status);
        let account = format_account(&tokens, svc);
        let obj_count = objects.get(svc).map(|o| o.objects).unwrap_or(0);
        let obj_str = if obj_count > 0 || status == "enabled" {
            format_thousands(obj_count)
        } else {
            "—".to_string()
        };
        let http_str = format_http_counts(stats_services, svc);
        let status_str = format_status(status, unexpected.get(svc).copied().unwrap_or(0));

        rows.push(Row::Cells(vec![
            svc_cell, account, obj_str, http_str, status_str,
        ]));
    }

    render_table(
        "  ",
        &["Service", "Account", "Objects", "HTTP calls", "Status"],
        &[
            Align::Left,
            Align::Left,
            Align::Right,
            Align::Right,
            Align::Left,
        ],
        &rows,
        out,
    );

    out.push(String::new());
    let total_objects: u64 = objects.values().map(|o| o.objects).sum();
    let total_tables: usize = objects.values().map(|o| o.tables).sum();
    let size_str = source
        .size_bytes
        .map(format_bytes)
        .unwrap_or_else(|| "—".to_string());
    let scope = if source.is_archive {
        "archive"
    } else {
        "on disk"
    };
    out.push(format!(
        "  Total: {} objects{sep}{} tables{sep}{} {}",
        format_thousands(total_objects),
        total_tables,
        size_str,
        scope,
        sep = mid_sep()
    ));
}

// ─── health counters ─────────────────────────────────────────────────────

fn print_health(source: &LogSource, out: &mut Vec<String>) {
    let m = source.metadata.as_ref();
    let auth = metadata_u64(m, "auth_errors");
    let prereq = metadata_u64(m, "prerequisites_errors");
    let expected = metadata_u64(m, "expected_errors");
    let unexpected = m
        .and_then(|m| m.get("unexpected_errors").and_then(|v| v.as_u64()))
        .unwrap_or_else(|| stats_sum(source.stats.as_ref(), "unexpected_errors"));
    let rl_retries = stats_sum(source.stats.as_ref(), "retries_rate_limit");
    let rl_wait = stats_sum(source.stats.as_ref(), "rate_limit_wait_secs");
    // Per-service `http_call_failures` (when present) avoids the per-API
    // double-counting that batched failures cause; mirrors the convention in
    // `display::stats::print_stats_section`.
    let net = source
        .stats
        .as_ref()
        .and_then(|s| s.get("services").and_then(|v| v.as_object()))
        .map(|map| {
            map.values()
                .map(|svc| {
                    svc.get("http_call_failures")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                })
                .sum()
        })
        .unwrap_or_else(|| stats_sum(source.stats.as_ref(), "network_errors"));

    out.push(format!("  {:<28}{}", "Authentication errors", auth));
    out.push(format!("  {:<28}{}", "Prerequisite errors", prereq));
    out.push(format!(
        "  {:<28}{} expected{sep}{} unexpected",
        "API errors (4xx/5xx)",
        expected,
        unexpected,
        sep = mid_sep()
    ));
    out.push(format!(
        "  {:<28}{} retries{sep}{} s waiting",
        "429 throttling",
        rl_retries,
        rl_wait,
        sep = mid_sep()
    ));
    // "Request failures" (transport- or parse-level HTTP-call failures), not
    // "Network errors" — kept consistent with the stats command's relabel.
    out.push(format!("  {:<28}{}", "Request failures", net));
    // Expected-error breaker: informative, not an attention flag — every
    // skipped URL would have returned its bucket's schema-declared expected
    // error, so nothing is missing that the tenant could have provided.
    let skipped: u64 = m
        .and_then(|m| m.get("breaker_skipped_by_api").and_then(|v| v.as_object()))
        .map(|map| map.values().filter_map(|v| v.as_u64()).sum())
        .unwrap_or(0);
    if skipped > 0 {
        let buckets = m
            .and_then(|m| m.get("breaker_skipped_by_api").and_then(|v| v.as_object()))
            .map(|map| map.len())
            .unwrap_or(0);
        out.push(format!(
            "  {:<28}{} URL(s) on {} API(s) (declared-benign failures, not losses)",
            "Skipped by breaker", skipped, buckets
        ));
    }
}

// ─── attention list + next-step pointers ─────────────────────────────────

fn print_attention(source: &LogSource, verdict: Verdict, out: &mut Vec<String>) {
    // Track emitted items via a counter; the "items" model can't carry the
    // multi-line context (bullets quoted from oradaz.log) we attach to
    // broken / auth-failed cases, so push directly.
    let initial_len = out.len();

    if source.is_broken {
        out.push(format!(
            "  {}",
            fatal_line(
                "Archive interrupted",
                "only partial data is in this archive"
            )
        ));
    }
    let auth = metadata_u64(source.metadata.as_ref(), "auth_errors");
    if auth > 0 {
        out.push(format!(
            "  {}",
            fatal_line(
                &format!("{auth} authentication error(s)"),
                "see the lines below or oradaz inspect hints"
            )
        ));
    }
    // Quote the log tail once even when both `is_broken` and `auth_errors`
    // fired — the bullets are the same in either case (the last ERROR lines
    // from oradaz.log) and printing them twice is noise.
    if source.is_broken || auth > 0 {
        push_failure_context_bullets(&source.log_text, out);
    }
    for (svc, status) in parse_service_statuses(source.metadata.as_ref()) {
        if status != "disabled_by_prerequisite_failure" {
            continue;
        }
        let err_code = source
            .prerequisites
            .as_ref()
            .and_then(|p| p.get(&svc))
            .and_then(|s| s.get("error"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        // `NoAvailableSubscription` is a benign startup skip (no Azure
        // subscription for this identity), not a mid-run prerequisite failure —
        // word it accordingly and use a warning rather than a fatal marker.
        if err_code == "NoAvailableSubscription" {
            out.push(format!(
                "  {}",
                warn_line(
                    &format!("{} skipped — no Azure subscription", svc_display_name(&svc)),
                    "NoAvailableSubscription (checked at startup)"
                )
            ));
        } else {
            out.push(format!(
                "  {}",
                fatal_line(
                    &format!("{} not collected", svc_display_name(&svc)),
                    "prerequisite failed during the run"
                )
            ));
        }
    }

    // Top unexpected (real anomalies) — up to 3.
    let groups = aggregate_errors(&source.dump_errors);
    for g in groups
        .iter()
        .filter(|g| g.category == ErrorCategory::Unexpected)
        .take(3)
    {
        // "service/api", or just "service" when the api name is empty. A
        // non-HTTP terminal failure (status 0) shows the code without a
        // misleading "HTTP 0".
        let target = if g.api.is_empty() {
            g.service.clone()
        } else {
            format!("{}/{}", g.service, g.api)
        };
        let detail = if g.status == 0 {
            format!("{}× {}", g.count, code_label(&g.code))
        } else {
            format!("{}× HTTP {} {}", g.count, g.status, code_label(&g.code))
        };
        out.push(format!("  {}", error_line(&target, &detail)));
    }

    // High-throttle APIs (transient but blocked the pipeline) — up to 2.
    for (label, msg) in heavy_throttle_apis(source.stats.as_ref(), 2) {
        out.push(format!("  {}", warn_line(&label, &msg)));
    }

    // Writer single-core saturation (debug telemetry): flagged only when
    // producers actually stalled on the 256 MiB byte budget — otherwise invisible
    // in the one-screen digest. `#[serde(default)]` → 0 on
    // older archives, so this never fires for them.
    let writer_stalls = metadata_u64(source.metadata.as_ref(), "writer_budget_blocked_count");
    if writer_stalls > 0 {
        let secs = metadata_u64(source.metadata.as_ref(), "writer_budget_blocked_secs");
        let secs_disp = if secs == 0 {
            "<1".to_string()
        } else {
            secs.to_string()
        };
        out.push(format!(
            "  {}",
            warn_line(
                "Writer saturation",
                &format!(
                    "producers blocked {secs_disp}s over {writer_stalls} stall(s) — single-core MLA write may be the bottleneck"
                )
            )
        ));
    }

    // Stall-watchdog fires: the pipeline went eventless for stallDetectionTimeout
    // with requests in flight. The run recovered (the watchdog never aborts),
    // but the log around the "Stall detected" lines is worth reading.
    let stalls = metadata_u64(source.metadata.as_ref(), "stall_events");
    if stalls > 0 {
        out.push(format!(
            "  {}",
            warn_line(
                "Pipeline stalls",
                &format!(
                    "stall watchdog fired {stalls}× — see the 'Stall detected' lines in oradaz.log"
                )
            )
        ));
    }

    if out.len() == initial_len {
        let ok_msg = match verdict {
            Verdict::Complete => "nothing requires attention — collection looks healthy",
            _ => "no specific item to surface",
        };
        out.push(format!("  {}", dim(&format!("({ok_msg})"))));
    }

    out.push(String::new());
    out.push(format!("  {}", dim("Next steps:")));
    let suggestions = if matches!(verdict, Verdict::Complete) {
        vec![
            "oradaz inspect stats     per-API volumes & throttling",
            "oradaz inspect logs      investigate individual errors",
        ]
    } else {
        vec![
            "oradaz inspect hints                 what to fix and how",
            "oradaz inspect logs --service <svc>  drill into errors",
        ]
    };
    for s in suggestions {
        out.push(format!("  {} {}", arrow_glyph(), s));
    }
}

// ─── small helpers ───────────────────────────────────────────────────────

fn format_status(status: &str, unexpected: u64) -> String {
    match status {
        "enabled" => {
            if unexpected == 0 {
                dim("ok")
            } else {
                err_text(&format!("{unexpected} unexpected"))
            }
        }
        "disabled_by_config" => dim("disabled in config"),
        "disabled_by_prerequisite_failure" => err_text("prereq failed"),
        _ => dim("—"),
    }
}

/// Top APIs with the longest accumulated `Retry-After` wait, formatted for
/// the ATTENTION list. Returns at most `limit` entries.
fn heavy_throttle_apis(stats: Option<&Value>, limit: usize) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let Some(apis) = stats.and_then(|s| s.get("apis")).and_then(|a| a.as_array()) else {
        return out;
    };
    let mut rows: Vec<(u64, String, u64)> = apis
        .iter()
        .filter_map(|api| {
            let wait = api.get("rate_limit_wait_secs").and_then(|v| v.as_u64())?;
            if wait <= 60 {
                return None;
            }
            let retries = api
                .get("retries_rate_limit")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let svc = api.get("service").and_then(|v| v.as_str()).unwrap_or("?");
            let name = api.get("api").and_then(|v| v.as_str()).unwrap_or("?");
            Some((wait, format!("{svc}/{name}"), retries))
        })
        .collect();
    rows.sort_by(|a, b| b.0.cmp(&a.0));
    for (wait, label, retries) in rows.into_iter().take(limit) {
        // Show the cumulative Retry-After, not a "% of wall time": the wait is
        // summed across concurrent requests and routinely exceeds wall-clock.
        out.push((
            label,
            format!("{retries}× 429 ({wait} s cumulative Retry-After)"),
        ));
    }
    out
}

fn metadata_u64(metadata: Option<&Value>, key: &str) -> u64 {
    metadata
        .and_then(|m| m.get(key))
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
}

fn stats_sum(stats: Option<&Value>, field: &str) -> u64 {
    stats
        .and_then(|s| s.get("apis").and_then(|a| a.as_array()))
        .map(|apis| {
            apis.iter()
                .map(|api| api.get(field).and_then(|v| v.as_u64()).unwrap_or(0))
                .sum()
        })
        .unwrap_or(0)
}

/// When the collection ended on a fatal cause (broken archive / auth
/// failure), quote the last few ERROR lines from `oradaz.log` — plus the
/// `DEBUG` follow-up that carries the real reason — so the user reads the
/// *why* directly in ATTENTION without having to chase it via
/// `inspect logs --debug`.
fn push_failure_context_bullets(log_text: &str, out: &mut Vec<String>) {
    let entries = parse_log(log_text);
    let context = last_plain_failure_context(&entries, 3);
    if context.is_empty() {
        return;
    }
    out.push(format!(
        "      {}",
        dim("Last errors logged before the abort:")
    ));
    for entry in context {
        // HH:MM:SS only to keep the bullet short.
        let time = entry
            .timestamp
            .split(' ')
            .nth(1)
            .unwrap_or(&entry.timestamp);
        let bullet = icon(Icon::Selected);
        let level_marker = match entry.level {
            crate::inspect::log_parser::LogLevel::Error => "ERROR",
            crate::inspect::log_parser::LogLevel::Debug => "  debug",
            _ => "      ",
        };
        out.push(format!(
            "      {} {} {} {}  {}",
            dim(&bullet),
            dim(time),
            dim(level_marker),
            entry.module,
            dim(&entry.message)
        ));
    }
}

fn fatal_line(subject: &str, detail: &str) -> String {
    format!(
        "{} {} — {}",
        err_text(&icon(Icon::Err)),
        subject,
        dim(detail)
    )
}

fn error_line(subject: &str, detail: &str) -> String {
    format!(
        "{} {} — {}",
        err_text(&icon(Icon::Err)),
        subject,
        dim(detail)
    )
}

fn warn_line(subject: &str, detail: &str) -> String {
    format!(
        "{} {} — {}",
        warn_text(&icon(Icon::Warn)),
        subject,
        dim(detail)
    )
}

fn arrow_glyph() -> String {
    match mode() {
        UiMode::Color => dim(&icon(Icon::Arrow)),
        UiMode::NoColor => icon(Icon::Arrow),
    }
}

/// Compact upstream code rendering: empty/`"."`/missing → empty string so the
/// final line doesn't include a trailing `.`.
fn code_label(code: &str) -> &str {
    match code {
        "" | "." => "",
        s => s,
    }
}
