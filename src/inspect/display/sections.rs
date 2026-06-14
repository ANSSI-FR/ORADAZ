use super::*;
use crate::collect::dump::response::DumpError;
use crate::inspect::analysis::{ErrorCategory, aggregate_errors, objects_per_service};
use crate::inspect::hints::get_hint;
use crate::inspect::{
    loader::LogSource,
    log_parser::{
        LogEntry, LogFilters, LogLevel, build_dump_error_index, find_dump_error_in_index,
        group_entries,
    },
};
use crate::utils::ui::{Icon, Paint, UiMode, dim, err_text, icon, paint, warn_text};

use serde_json::Value;
use std::collections::BTreeMap;

pub fn auth_type_from_config(config: &Value) -> String {
    if config
        .get("use_device_code")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        "Device code".to_string()
    } else if config
        .get("use_application_credentials")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        match config
            .get("application_credential_type")
            .and_then(|v| v.as_str())
        {
            Some(t) if t.contains("certificate") => "Client credentials (certificate)".to_string(),
            Some(t) if t.eq_ignore_ascii_case("managedIdentity") => {
                "Client credentials (managed identity)".to_string()
            }
            _ => "Client credentials (password)".to_string(),
        }
    } else {
        "Authorization code".to_string()
    }
}

/// Per-mode icon rendering for the config command's services list. The
/// services-section renderer uses [`service_cell`] from `coverage.rs` instead.
fn service_status_icon(has_token: bool) -> String {
    let glyph = if has_token { Icon::Ok } else { Icon::Err };
    let raw = icon(glyph);
    match (has_token, mode()) {
        (true, UiMode::Color) => paint(Paint::Green, &raw),
        (false, UiMode::Color) => paint(Paint::Red, &raw),
        (_, UiMode::NoColor) => raw,
    }
}

// ─── services command ──────────────────────────────────────────────────────
//
// Single coverage table (Service · Account · Objects · HTTP · Errors · Status)
// + a continuation row when a service was disabled by a failed prerequisite
// + an ISSUES BY API section listing services with unexpected errors and
// pointing the user to `inspect logs --service <svc>` for the detail.

pub fn print_services_section(
    metadata: Option<&Value>,
    config: Option<&Value>,
    prerequisites: Option<&Value>,
    stats: Option<&Value>,
    dump_errors: &[DumpError],
    service_filter: Option<&str>,
    out: &mut Vec<String>,
) {
    print_collection_summary(metadata, config, out);

    out.push(String::new());
    out.push(section_line("SERVICES", None));
    out.push(String::new());
    print_services_coverage(metadata, prerequisites, stats, service_filter, out);

    out.push(String::new());
    out.push(section_line("ISSUES BY API", None));
    out.push(String::new());
    print_services_issues(dump_errors, service_filter, out);
}

fn print_services_coverage(
    metadata: Option<&Value>,
    prerequisites: Option<&Value>,
    stats: Option<&Value>,
    service_filter: Option<&str>,
    out: &mut Vec<String>,
) {
    let objects = objects_per_service(metadata);
    let tokens = parse_tokens(metadata);
    let statuses = parse_service_statuses(metadata);
    let stats_services = stats.and_then(|s| s.get("services").and_then(|v| v.as_object()));
    let unexpected = unexpected_per_service(stats);
    let expected = expected_per_service(stats);

    let mut rows: Vec<Row> = Vec::new();
    for &svc in SERVICE_ORDER {
        if service_filter.is_some_and(|f| f != svc) {
            continue;
        }
        // Fallback for older archives missing `metadata.services`: presence of
        // a token means the service was collected.
        let status = statuses.get(svc).map(String::as_str).unwrap_or({
            if tokens.contains_key(svc) {
                "enabled"
            } else {
                "unknown"
            }
        });

        let svc_cell_str = service_cell(svc, status);
        let account = format_account(&tokens, svc);
        let obj_count = objects.get(svc).map(|o| o.objects).unwrap_or(0);
        let obj_str = if obj_count > 0 || status == "enabled" {
            format_thousands(obj_count)
        } else {
            "—".to_string()
        };
        let http_str = format_http_counts(stats_services, svc);
        let errors_str = format_errors_cell(
            unexpected.get(svc).copied().unwrap_or(0),
            expected.get(svc).copied().unwrap_or(0),
            status,
        );
        let status_str = format_svc_status(status);

        rows.push(Row::Cells(vec![
            svc_cell_str,
            account,
            obj_str,
            http_str,
            errors_str,
            status_str,
        ]));

        // Continuation row under a failed service — emitted verbatim and
        // excluded from column-width measurement (see `table::Row::Raw`).
        if status == "disabled_by_prerequisite_failure"
            && let Some(msg) = prereq_error_message(prerequisites, svc)
        {
            rows.push(Row::Raw(format!(
                "              {corner} {}",
                dim(&msg),
                corner = corner_glyph()
            )));
        }
    }

    render_table(
        "  ",
        &["Service", "Account", "Objects", "HTTP", "Errors", "Status"],
        &[
            Align::Left,
            Align::Left,
            Align::Right,
            Align::Right,
            Align::Right,
            Align::Left,
        ],
        &rows,
        out,
    );

    out.push(String::new());
    out.push(format!("  {}", dim("Errors = unexpected / expected")));
}

fn print_services_issues(
    dump_errors: &[DumpError],
    service_filter: Option<&str>,
    out: &mut Vec<String>,
) {
    let groups = aggregate_errors(dump_errors);
    let issues: Vec<_> = groups
        .iter()
        .filter(|g| g.category == ErrorCategory::Unexpected)
        .filter(|g| service_filter.is_none_or(|f| g.service == f))
        .collect();

    if issues.is_empty() {
        out.push(format!("  {}", dim("(no unexpected errors)")));
        return;
    }

    for g in issues {
        let svc = svc_display_name(&g.service);
        let code = if g.code.is_empty() {
            String::new()
        } else {
            format!(" {}", g.code)
        };
        // "svc / api", or just "svc" when the api name is empty. A non-HTTP
        // terminal failure (status 0) drops the misleading "HTTP 0" prefix.
        let target = if g.api.is_empty() {
            svc.to_string()
        } else {
            format!("{} / {}", svc, g.api)
        };
        let detail = if g.status == 0 {
            format!("{}×{}", g.count, code)
        } else {
            format!("{}× HTTP {}{}", g.count, g.status, code)
        };
        let drill = format!("{} inspect logs --service {}", icon(Icon::Arrow), g.service);
        out.push(format!("  {}   {}   {}", target, detail, dim(&drill)));
    }
}

/// `"U/E"` string, coloured red when unexpected > 0, dimmed otherwise.
/// Returns the value un-padded; `render_table` right-aligns the column.
fn format_errors_cell(unexpected: u64, expected: u64, status: &str) -> String {
    if status != "enabled" {
        return "—".to_string();
    }
    let pair = format!("{}/{}", unexpected, expected);
    if unexpected > 0 {
        err_text(&pair)
    } else {
        dim(&pair)
    }
}

fn format_svc_status(status: &str) -> String {
    match status {
        "enabled" => dim("ok"),
        "disabled_by_config" => dim("disabled in config"),
        "disabled_by_prerequisite_failure" => err_text("prereq failed"),
        _ => dim("—"),
    }
}

fn prereq_error_message(prerequisites: Option<&Value>, svc: &str) -> Option<String> {
    prerequisites
        .and_then(|p| p.get(svc))
        .and_then(|s| s.get("error"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

// ─── metadata command ────────────────────────────────────────────────────
//
// Provenance/error counters at top (the COLLECTION SUMMARY header already
// covers tenant/date/version), then a DATA MANIFEST that groups tables by
// service folder. `--top`/`--all` limit how many tables are listed under
// each service.

pub fn print_metadata_section(
    metadata: Option<&Value>,
    config: Option<&Value>,
    top: usize,
    all: bool,
    out: &mut Vec<String>,
) {
    print_collection_summary(metadata, config, out);

    out.push(String::new());
    out.push(section_line("ERROR COUNTERS", None));
    out.push(String::new());
    print_error_counters(metadata, out);

    out.push(String::new());
    out.push(section_line(
        "WRITER & THROTTLING (peak observability)",
        None,
    ));
    out.push(String::new());
    print_observability(metadata, out);

    out.push(String::new());
    out.push(section_line("DATA MANIFEST (objects per table)", None));
    out.push(String::new());
    print_data_manifest(metadata, top, all, out);
}

/// Renders the writer-saturation and AIMD-collapse peak signals (from the
/// debug-telemetry metadata fields). All `#[serde(default)]`, so older archives
/// without them render zeros — harmless.
fn print_observability(metadata: Option<&Value>, out: &mut Vec<String>) {
    let Some(m) = metadata else {
        out.push(format!("{}(no metadata available)", INDENT));
        return;
    };
    let queue_pct = u64_field(m, "peak_writer_queue_pct");
    let inflight = u64_field(m, "peak_writer_inflight_bytes");
    let blocked_secs = u64_field(m, "writer_budget_blocked_secs");
    let blocked_count = u64_field(m, "writer_budget_blocked_count");
    let send_blocked_secs = u64_field(m, "writer_send_blocked_secs");
    let send_blocked_count = u64_field(m, "writer_send_blocked_count");
    let backoff = u64_field(m, "peak_backoff_active");

    out.push(format!("  {:<27} {}%", "Writer queue peak", queue_pct));
    out.push(format!(
        "  {:<27} {}",
        "Writer bytes in-flight peak",
        crate::utils::sysmem::format_bytes(inflight)
    ));
    // `writer_budget_blocked_secs` is integer seconds; a sub-second total with
    // a non-zero count rounds to 0 — render "<1s" so "0s over N stall(s)" doesn't
    // read as self-contradictory. The count is the actual stall trigger.
    let blocked_disp = if blocked_secs == 0 && blocked_count > 0 {
        "<1s".to_string()
    } else {
        format!("{}s", blocked_secs)
    };
    out.push(format!(
        "  {:<27} {} over {} stall(s)",
        "Writer budget-blocked", blocked_disp, blocked_count
    ));
    // Channel-send blocking is the small-page complement of byte-budget blocking:
    // non-zero here with a zero byte-budget figure means the writer was the
    // bottleneck on a many-tiny-pages service.
    let send_disp = if send_blocked_secs == 0 && send_blocked_count > 0 {
        "<1s".to_string()
    } else {
        format!("{}s", send_blocked_secs)
    };
    out.push(format!(
        "  {:<27} {} over {} stall(s)",
        "Writer send-blocked", send_disp, send_blocked_count
    ));
    out.push(format!("  {:<27} {}", "Backoff slots peak", backoff));

    // Data volume + phase/runtime context: total uncompressed bytes written (the
    // writer-saturation correlate), the auth+prereq phase length (explains the
    // total−dump delta), and the available CPU parallelism (one core feeds the MLA
    // writer). All `#[serde(default)]` → 0/"n/a" on older archives.
    let total_bytes = u64_field(m, "total_bytes_written");
    let auth_prereq = u64_field(m, "auth_prereq_secs");
    let cpus = u64_field(m, "num_cpus");
    out.push(format!(
        "  {:<27} {}",
        "Total data written",
        crate::utils::sysmem::format_bytes(total_bytes)
    ));
    out.push(format!("  {:<27} {}s", "Auth+prereq phase", auth_prereq));
    out.push(format!(
        "  {:<27} {}",
        "CPU parallelism",
        if cpus > 0 {
            cpus.to_string()
        } else {
            "n/a".to_string()
        }
    ));

    // Per-service AIMD floor + collapse/recovery dynamics (services sorted; only
    // those that were actually reduced are worth showing). The halving count tells
    // how often it collapsed; the increase count whether it *recovered* (ramped
    // back up); the time-at-floor how *long* it stayed collapsed — a window pinned
    // at the floor for minutes is invisible in the count alone.
    let mins = m.get("min_window_by_service").and_then(|v| v.as_object());
    let decs = m
        .get("window_decreases_by_service")
        .and_then(|v| v.as_object());
    let incs = m
        .get("window_increases_by_service")
        .and_then(|v| v.as_object());
    let floor_secs = m
        .get("time_at_floor_secs_by_service")
        .and_then(|v| v.as_object());
    let svc_u64 = |obj: Option<&serde_json::Map<String, Value>>, svc: &str| -> u64 {
        obj.and_then(|d| d.get(svc))
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
    };
    if let Some(mins) = mins {
        let mut rows: Vec<String> = Vec::new();
        for (svc, min) in mins {
            let halvings = svc_u64(decs, svc);
            if halvings > 0 {
                let increases = svc_u64(incs, svc);
                let at_floor = svc_u64(floor_secs, svc);
                let floor_note = if at_floor > 0 {
                    format!(", {}s at floor", at_floor)
                } else {
                    String::new()
                };
                rows.push(format!(
                    "  {:<27} floor {} ({} halving{} / {} increase{}{})",
                    svc,
                    min.as_u64().unwrap_or(0),
                    halvings,
                    if halvings == 1 { "" } else { "s" },
                    increases,
                    if increases == 1 { "" } else { "s" },
                    floor_note,
                ));
            }
        }
        if !rows.is_empty() {
            out.push(format!("  {:<27}", "AIMD window collapse:"));
            rows.sort();
            out.extend(rows);
        }
    }

    // Per-service AIMD ceiling contention: workers that parked because demand
    // exceeded the *maximum allowed* concurrency (not a 429-reduced window). The
    // signal that `concurrencyMaxWindow` is the binding constraint for a service.
    let waits = m
        .get("slot_wait_events_by_service")
        .and_then(|v| v.as_object());
    let wsecs = m
        .get("slot_wait_secs_by_service")
        .and_then(|v| v.as_object());
    if let Some(waits) = waits {
        let mut rows: Vec<String> = Vec::new();
        for (svc, ev) in waits {
            let events = ev.as_u64().unwrap_or(0);
            if events > 0 {
                let secs = wsecs
                    .and_then(|w| w.get(svc))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                rows.push(format!(
                    "  {:<27} {} park(s) at ceiling ({}s)",
                    svc, events, secs
                ));
            }
        }
        if !rows.is_empty() {
            out.push(format!("  {:<27}", "AIMD ceiling contention:"));
            rows.sort();
            out.extend(rows);
        }
    }

    // Per-service active-cooldown wall-clock on a single coalesced timeline. The
    // intended cooldown (sum of Retry-After) lives per-API in stats.json; a value
    // far below the intended sum reveals many concurrent 429s piling onto the
    // same window (the cooldown bypassed under concurrency). Only services that
    // actually entered a cooldown are worth showing.
    let cooldowns = m
        .get("cooldown_active_secs_by_service")
        .and_then(|v| v.as_object());
    if let Some(cooldowns) = cooldowns {
        let mut rows: Vec<String> = Vec::new();
        for (svc, secs) in cooldowns {
            let secs = secs.as_u64().unwrap_or(0);
            if secs > 0 {
                rows.push(format!("  {:<27} {}s active", svc, secs));
            }
        }
        if !rows.is_empty() {
            out.push(format!("  {:<27}", "Cooldown active (timeline):"));
            rows.sort();
            out.extend(rows);
        }
    }

    // Per-service map sections that only matter when non-zero: cooldowns clamped
    // by rateLimitMaxWaitSecs, wall-clock paused on prereq/token gating, and
    // mid-dump token-refresh episodes. Absent on archives predating the fields.
    let map_rows = |key: &str, fmt: &dyn Fn(&str, u64) -> String| -> Vec<String> {
        let mut rows: Vec<String> = m
            .get(key)
            .and_then(|v| v.as_object())
            .map(|obj| {
                obj.iter()
                    .filter_map(|(svc, v)| {
                        let n = v.as_u64().unwrap_or(0);
                        (n > 0).then(|| fmt(svc, n))
                    })
                    .collect()
            })
            .unwrap_or_default();
        rows.sort();
        rows
    };
    let clamped = map_rows("retry_after_clamped_by_service", &|svc, n| {
        format!("  {:<27} {} clamped cooldown(s)", svc, n)
    });
    if !clamped.is_empty() {
        out.push(format!("  {:<27}", "Retry-After clamped:"));
        out.extend(clamped);
    }
    let pauses = map_rows("pause_secs_by_service", &|svc, n| {
        format!("  {:<27} {}s paused", svc, n)
    });
    if !pauses.is_empty() {
        out.push(format!("  {:<27}", "Service pauses (prereq/token):"));
        out.extend(pauses);
    }
    let refreshes = map_rows("token_refreshes_by_service", &|svc, n| {
        format!(
            "  {:<27} {} refresh{}",
            svc,
            n,
            if n == 1 { "" } else { "es" }
        )
    });
    if !refreshes.is_empty() {
        out.push(format!("  {:<27}", "Token refreshes (mid-dump):"));
        out.extend(refreshes);
    }
    let stalls = u64_field(m, "stall_events");
    if stalls > 0 {
        out.push(format!("  {:<27} {}", "Stall watchdog fired", stalls));
    }
    // Expected-error breaker: URLs skipped per bucket. Skipped ≠ lost — every
    // skipped URL would have returned the bucket's schema-declared expected
    // error, so this is informative, not a data-quality flag.
    let skipped = map_rows("breaker_skipped_by_api", &|api, n| {
        format!("  {:<27} {} URL(s) skipped", api, n)
    });
    if !skipped.is_empty() {
        out.push(format!("  {:<27}", "Expected-error breaker:"));
        out.extend(skipped);
    }
    // `$expand` parents re-fetched in full after hitting the API cap. An entry
    // means the per-object fallback recovered a possibly truncated collection —
    // informative proof of no data lost, not a quality flag. Absence means no
    // parent could have been truncated on this run.
    let expand_caps = map_rows("expand_cap_hits_by_api", &|api, n| {
        format!("  {:<27} {} parent(s) re-fetched", api, n)
    });
    if !expand_caps.is_empty() {
        out.push(format!("  {:<27}", "$expand cap re-fetches:"));
        out.extend(expand_caps);
    }
    // Buckets whose per-bucket 429 escalation engaged (consecutive-429 streak
    // reached the doubling threshold). Cross with lost_data_by_code in
    // stats.json: listed here but absent from losses = recovered by the
    // escalated pacing.
    let escalated = map_rows("cooldown_escalated_by_api", &|api, n| {
        format!("  {:<27} max streak {}", api, n)
    });
    if !escalated.is_empty() {
        out.push(format!("  {:<27}", "429 escalation engaged:"));
        out.extend(escalated);
    }
    let sem_wait_ms = u64_field(m, "resp_sem_wait_ms_total");
    if sem_wait_ms > 0 {
        out.push(format!(
            "  {:<27} {}ms total",
            "Response admission wait", sem_wait_ms
        ));
    }
    let mem_wait_ms = u64_field(m, "resp_mem_wait_ms_total");
    if mem_wait_ms > 0 {
        out.push(format!(
            "  {:<27} {}ms total",
            "Response byte-budget wait", mem_wait_ms
        ));
    }
}

fn print_error_counters(metadata: Option<&Value>, out: &mut Vec<String>) {
    let Some(m) = metadata else {
        out.push(format!("{}(no metadata available)", INDENT));
        return;
    };
    let auth = u64_field(m, "auth_errors");
    let prereq = u64_field(m, "prerequisites_errors");
    let errors_total = u64_field(m, "errors");
    let expected = u64_field(m, "expected_errors");
    let unexpected = u64_field(m, "unexpected_errors");
    // Prefer the exact `non_http_errors` counter (newer archives). Fall back to
    // the derived figure for archives predating that field — note the derivation
    // underflows (clamped to 0) when 5xx retries or batch-wrapper attribution
    // inflate the response-counted expected/unexpected sums beyond `errors`.
    let non_http = m
        .get("non_http_errors")
        .and_then(|v| v.as_u64())
        .unwrap_or_else(|| errors_total.saturating_sub(expected + unexpected));

    out.push(format!("  {:<25} {}", "Authentication errors", auth));
    out.push(format!("  {:<25} {}", "Prerequisite errors", prereq));
    out.push(format!(
        "  {:<25} {}   ({} expected{sep}{} unexpected{sep}{} non-HTTP)",
        "Errors (errors.json)",
        errors_total,
        expected,
        unexpected,
        non_http,
        sep = mid_sep()
    ));
    // Lost-data abandonments (the PARTIAL-verdict counter): a subset of the
    // non-HTTP entries above. Absent on archives predating the field — only a
    // measured value is worth a line (0 on an old archive would read as a
    // clean run when the field simply did not exist).
    if let Some(lost) = m.get("lost_data_errors").and_then(|v| v.as_u64()) {
        out.push(format!(
            "  {:<25} {}   (per-API breakdown: stats.json lost_data_by_code)",
            "Lost data (abandoned)", lost
        ));
    }
}

fn print_data_manifest(metadata: Option<&Value>, top: usize, all: bool, out: &mut Vec<String>) {
    let Some(m) = metadata else {
        out.push(format!("{}(no metadata available)", INDENT));
        return;
    };
    let Some(tables) = m.get("tables").and_then(|t| t.as_array()) else {
        out.push(format!("{}(no tables found)", INDENT));
        return;
    };
    if tables.is_empty() {
        out.push(format!("{}(no tables found)", INDENT));
        return;
    }

    // Group by `folder` (= service). Entries with empty/missing folder land
    // in an "(other)" bucket at the end — defensive for older archives.
    let mut by_folder: BTreeMap<String, Vec<&Value>> = BTreeMap::new();
    let mut other_tables: Vec<&Value> = Vec::new();
    for table in tables {
        let folder = table.get("folder").and_then(|v| v.as_str()).unwrap_or("");
        if folder.is_empty() {
            other_tables.push(table);
        } else {
            by_folder.entry(folder.to_string()).or_default().push(table);
        }
    }

    let mut first = true;
    // Canonical services first; the BTreeMap remove() leaves extras for the
    // alphabetical pass that follows.
    for &svc in SERVICE_ORDER {
        if let Some(svc_tables) = by_folder.remove(svc) {
            render_service_group(svc, &svc_tables, top, all, out, &mut first);
        }
    }
    for (svc, svc_tables) in by_folder {
        render_service_group(&svc, &svc_tables, top, all, out, &mut first);
    }
    if !other_tables.is_empty() {
        render_service_group("(other)", &other_tables, top, all, out, &mut first);
    }
}

fn render_service_group(
    svc: &str,
    tables: &[&Value],
    top: usize,
    all: bool,
    out: &mut Vec<String>,
    first: &mut bool,
) {
    if !*first {
        out.push(String::new());
    }
    *first = false;

    let total_objects: u64 = tables
        .iter()
        .map(|t| t.get("count").and_then(|c| c.as_u64()).unwrap_or(0))
        .sum();
    let total_bytes: u64 = tables
        .iter()
        .map(|t| t.get("bytes").and_then(|c| c.as_u64()).unwrap_or(0))
        .sum();
    let svc_label = if svc == "(other)" {
        "(other)".to_string()
    } else {
        svc_display_name(svc).to_string()
    };
    out.push(format!(
        "  {} — {} objects{sep}{} tables{sep}{}",
        svc_label,
        format_thousands(total_objects),
        tables.len(),
        crate::utils::sysmem::format_bytes(total_bytes),
        sep = mid_sep()
    ));

    let mut sorted: Vec<&&Value> = tables.iter().collect();
    sorted.sort_by(|a, b| {
        let ca = a.get("count").and_then(|c| c.as_u64()).unwrap_or(0);
        let cb = b.get("count").and_then(|c| c.as_u64()).unwrap_or(0);
        cb.cmp(&ca)
    });
    let limit = if all {
        sorted.len()
    } else {
        top.min(sorted.len())
    };
    for table in sorted.iter().take(limit) {
        let name = table.get("name").and_then(|n| n.as_str()).unwrap_or("?");
        let count = table.get("count").and_then(|c| c.as_u64()).unwrap_or(0);
        let bytes = table.get("bytes").and_then(|c| c.as_u64()).unwrap_or(0);
        out.push(format!(
            "      {:>9}   {:>10}   {}",
            format_thousands(count),
            crate::utils::sysmem::format_bytes(bytes),
            name
        ));
    }
    if !all && sorted.len() > limit {
        out.push(format!(
            "      {}",
            dim(&format!(
                "{} ({} more tables — use --all)",
                ellipsis(),
                sorted.len() - limit
            ))
        ));
    }
}

fn u64_field(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(|v| v.as_u64()).unwrap_or(0)
}

// ─── config command ───────────────────────────────────────────────────────
//
// Four "always shown" groups (Authentication / Services / Output & schema /
// Network) then a PERFORMANCE TUNING table that defaults to showing only the
// parameters whose effective value differs from the default. `--all`
// expands it to every parameter, marking non-defaults with `*`. Defaults
// must stay in sync with the `Config::*` impl methods in
// `src/utils/config.rs` — see the `TUNING_DEFAULTS` table below.

const PARAM_W: usize = 35;
const VALUE_W: usize = 8;
const DEFAULT_W: usize = 8;

/// Effective default values for each tuning knob — mirror of the
/// `unwrap_or(...)` literals in `src/utils/config.rs`. The
/// `tuning_defaults_match_config_unwrap_or_literals` test in
/// `tests/inspect_config.rs` asserts both sources stay in sync; update
/// together.
pub const TUNING_DEFAULTS: &[(&str, u64)] = &[
    ("concurrency_min_window", 5),
    ("concurrency_max_window", 30),
    ("default_retry_after_seconds", 5),
    ("http_timeout_seconds", 30),
    ("http_connect_timeout_seconds", 10),
    ("dispatch_burst_cap", 256),
    ("url_retry_limit", 5),
    ("rate_limit_retry_limit", 50),
    ("rate_limit_max_wait_secs", 900),
    ("stall_detection_timeout", 900),
    ("prereq_recheck_cache_secs", 90),
    ("liveness_ceiling_secs", 900),
    ("retry_backoff_base_ms", 250),
    ("retry_backoff_cap_ms", 8000),
    ("response_workers_max", 0),
    ("expected_error_breaker_threshold", 25),
];

pub fn print_config_section(
    metadata: Option<&Value>,
    config: Option<&Value>,
    all: bool,
    out: &mut Vec<String>,
) {
    print_collection_summary(metadata, config, out);

    out.push(String::new());
    out.push(section_line("CONFIGURATION", None));
    out.push(String::new());
    print_config_groups(metadata, config, out);

    out.push(String::new());
    out.push(section_line("PERFORMANCE TUNING", None));
    out.push(String::new());
    print_performance_tuning(config, all, out);
}

fn print_config_groups(metadata: Option<&Value>, config: Option<&Value>, out: &mut Vec<String>) {
    let Some(c) = config else {
        out.push(format!("{}(no configuration available)", INDENT));
        return;
    };

    // Authentication
    out.push(format!("  {}", dim("Authentication")));
    if let Some(v) = c.get("app_id").and_then(|v| v.as_str()) {
        out.push(format!("      {:<18} {}", "AppId", v));
    }
    out.push(format!("      {:<18} {}", "Flow", auth_type_from_config(c)));
    out.push(String::new());

    // Services — prefer `metadata.services` (lists every service that was
    // actually collected, including defaults) over `config.services` (which
    // only carries explicit XML overrides — a user collecting Graph with the
    // default settings has no Graph entry in config.services).
    out.push(format!("  {}", dim("Services")));
    let inline = services_inline_from_metadata(metadata).unwrap_or_else(|| {
        // Fallback for archives missing `metadata.services`.
        if let Some(svc_list) = c
            .get("services")
            .and_then(|s| s.get("service"))
            .and_then(|s| s.as_array())
        {
            svc_list
                .iter()
                .map(|svc| {
                    let name = svc.get("@name").and_then(|n| n.as_str()).unwrap_or("?");
                    let enabled = svc.get("#text").and_then(|t| t.as_bool()).unwrap_or(false);
                    format!(
                        "{} {}",
                        service_status_icon(enabled),
                        svc_display_name(name)
                    )
                })
                .collect::<Vec<_>>()
                .join("    ")
        } else {
            dim("(none listed)")
        }
    });
    out.push(format!("      {}", inline));
    out.push(String::new());

    // Output & schema
    out.push(format!("  {}", dim("Output & schema")));
    out.push(yes_no_row("Schema file", c, "use_schema_file"));
    out.push(yes_no_row("Additional MLA keys", c, "additional_mla_keys"));
    // `no_check=true` means prereq check is DISABLED → invert for display.
    let prereq_check_enabled = !c.get("no_check").and_then(|v| v.as_bool()).unwrap_or(false);
    out.push(format!(
        "      {:<18} {}",
        "Prereq check",
        if prereq_check_enabled {
            "enabled".to_string()
        } else {
            dim("disabled")
        }
    ));
    out.push(yes_no_row("Trace logs", c, "trace_logs"));
    match c.get("emergency_accounts_custom_attributes") {
        Some(Value::String(s)) if !s.is_empty() => {
            out.push(format!("      {:<18} {}", "Custom emergency attr", s));
        }
        _ => {}
    }
    out.push(String::new());

    // Network
    out.push(format!("  {}", dim("Network")));
    out.push(yes_no_row("Proxy", c, "proxy"));
    match c.get("user_agent") {
        Some(Value::String(s)) if !s.is_empty() => {
            out.push(format!("      {:<18} {}", "User agent", s));
        }
        _ => {
            out.push(format!("      {:<18} {}", "User agent", dim("default")));
        }
    }
}

/// Render the `Services` inline list from `metadata.services` (the canonical
/// post-resolution map). Returns `None` when metadata or the services map is
/// absent, so the caller can fall back to the older config-derived path.
fn services_inline_from_metadata(metadata: Option<&Value>) -> Option<String> {
    let map = metadata.and_then(|m| m.get("services").and_then(|s| s.as_object()))?;
    let canonical = ["graph", "resources", "exchange"];
    let mut ordered: Vec<(String, String)> = Vec::new();
    for svc in canonical {
        if let Some(v) = map.get(svc) {
            ordered.push((svc.to_string(), v.as_str().unwrap_or("").to_string()));
        }
    }
    let mut extras: Vec<(String, String)> = map
        .iter()
        .filter(|(k, _)| !canonical.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
        .collect();
    extras.sort_by(|a, b| a.0.cmp(&b.0));
    ordered.extend(extras);
    if ordered.is_empty() {
        return None;
    }
    Some(
        ordered
            .into_iter()
            .map(|(svc, status)| service_cell(&svc, &status))
            .collect::<Vec<_>>()
            .join("    "),
    )
}

fn yes_no_row(label: &str, config: &Value, field: &str) -> String {
    match config.get(field) {
        Some(Value::Bool(true)) => format!("      {:<18} yes", label),
        _ => format!("      {:<18} {}", label, dim("no")),
    }
}

fn print_performance_tuning(config: Option<&Value>, all: bool, out: &mut Vec<String>) {
    let c = match config {
        Some(c) => c,
        None => {
            out.push(format!("{}(no configuration available)", INDENT));
            return;
        }
    };

    let rows: Vec<TuningRow> = TUNING_DEFAULTS
        .iter()
        .map(|(field, default)| {
            let effective = c.get(field).and_then(|v| v.as_u64()).unwrap_or(*default);
            TuningRow {
                field,
                effective,
                default: *default,
            }
        })
        .collect();

    let non_default: Vec<&TuningRow> = rows.iter().filter(|r| r.effective != r.default).collect();

    if !all && non_default.is_empty() {
        out.push(format!(
            "  {}",
            dim("(all performance tuning values at defaults — use --all to list every parameter)")
        ));
        return;
    }
    if !all {
        out.push(format!(
            "  {}",
            dim("(showing only values that differ from defaults — use --all to see them all)")
        ));
        out.push(String::new());
    }

    let header = format!(
        "  {:<PARAM_W$}{:>VALUE_W$}    {:>DEFAULT_W$}",
        "Parameter", "value", "(default)"
    );
    out.push(dim(&header));
    out.push(dim(&format!(
        "  {}",
        rule(PARAM_W + VALUE_W + 4 + DEFAULT_W)
    )));

    let visible: Vec<&TuningRow> = if all {
        rows.iter().collect()
    } else {
        non_default
    };
    for r in visible {
        // Pad the value with the `*` marker BEFORE colouring; the marker is
        // emitted whenever effective ≠ default (in both default and --all
        // modes so the legend at the bottom remains accurate in --all).
        let is_diff = r.effective != r.default;
        let value_str = if is_diff {
            format!("{} *", r.effective)
        } else {
            format!("{}  ", r.effective)
        };
        let value_padded = format!("{:>VALUE_W$}", value_str);
        let default_padded = format!("{:>DEFAULT_W$}", r.default);
        let coloured_value = if is_diff {
            warn_text(&value_padded)
        } else {
            value_padded
        };
        out.push(format!(
            "  {:<PARAM_W$}{}    {}",
            r.field, coloured_value, default_padded
        ));
    }

    if all && rows.iter().any(|r| r.effective != r.default) {
        out.push(String::new());
        out.push(format!("  {}", dim("* = different from default")));
    }
}

struct TuningRow {
    field: &'static str,
    effective: u64,
    default: u64,
}

// ─── logs grouped renderer ─────────────────────────────────────────────────
//
// Default (non-`--full`) renderer for `inspect logs`. Variable columns
// (Table, Error code, Message, Hint) are capped to keep the table fitting
// comfortably in a default 80-column terminal — values exceeding the cap are
// truncated with `…`. `--limit/--all/--top` cap the number of groups;
// `--sort count|recent|status` controls ordering. A pre-flight banner is
// printed when the cap kicks in; a footer suggests drill-in commands.

/// Returns a `/`-joined list of verbosity flags that are not yet active, so
/// the "N hidden; add X to show" hint never suggests flags already in use.
fn missing_verbosity_flags(filters: &LogFilters) -> String {
    let mut flags: Vec<&str> = Vec::new();
    if !filters.warnings && !filters.info && !filters.debug {
        flags.push("--warnings");
    }
    if !filters.info && !filters.debug {
        flags.push("--info");
    }
    if !filters.debug {
        flags.push("--debug");
    }
    if flags.is_empty() {
        // All flags already active — shouldn't normally be reached, but be safe.
        "--warnings/--info/--debug".to_string()
    } else {
        flags.join("/")
    }
}

const MAX_TABLE_W: usize = 35;
const MAX_ERROR_W: usize = 25;
const MAX_MSG_W: usize = 25;
const MAX_HINT_W: usize = 20;
const DEFAULT_LIMIT: usize = 25;

pub fn print_logs_details(entries: &[LogEntry], out: &mut Vec<String>, filters: &LogFilters) {
    out.push(String::new());
    out.push(section_line("LOGS DETAILS", None));
    out.push(String::new());

    let filtered_entries: Vec<&LogEntry> = entries
        .iter()
        .filter(|e| match e.level {
            LogLevel::Error => true,
            LogLevel::Warn => filters.warnings || filters.info || filters.debug,
            LogLevel::Info => filters.info || filters.debug,
            LogLevel::Debug | LogLevel::Trace => filters.debug,
        })
        .collect();

    let total_entry_count = filtered_entries.len();
    if total_entry_count == 0 {
        if entries.is_empty() {
            out.push(format!(
                "{}(no API event log entries — 429 retries and expected errors are recorded at debug level; enable traceLogs at collection time and re-run with --debug to see them)",
                INDENT
            ));
        } else {
            // Entries exist but were all hidden by the verbosity-level filter —
            // say so and suggest only the flags that are not yet active.
            out.push(format!(
                "{}(no API event log at this level — {} hidden; add {} to show)",
                INDENT,
                entries.len(),
                missing_verbosity_flags(filters),
            ));
        }
        return;
    }

    let mut grouped = group_entries(filtered_entries.into_iter().cloned().collect());
    let total_group_count = grouped.len();
    sort_grouped(&mut grouped, filters.sort);

    let effective_limit = if filters.all {
        grouped.len()
    } else {
        filters.limit.unwrap_or(DEFAULT_LIMIT)
    };
    let truncated = total_group_count > effective_limit;
    grouped.truncate(effective_limit);

    if truncated {
        let by = match filters.sort {
            crate::inspect::log_parser::SortBy::Count => "most frequent",
            crate::inspect::log_parser::SortBy::Recent => "most recent",
            crate::inspect::log_parser::SortBy::Status => "(by status)",
        };
        out.push(format!(
            "  {} {} groups (×{} entries) — showing the {} {}.",
            info_glyph_dim(),
            total_group_count,
            total_entry_count,
            effective_limit,
            by
        ));
        out.push(format!(
            "  {}",
            dim(&format!(
                "Adjust with:  --all  {dot}  --limit N  {dot}  --since 06:57  {dot}  --sort recent",
                dot = mid_dot()
            ))
        ));
        out.push(String::new());
    }

    // Build truncated rows and headers with capped column widths.
    struct Row {
        table: String,
        count: String,
        http: String,
        error: String,
        message: String,
        hint: String,
    }
    let mut rows: Vec<Row> = Vec::with_capacity(grouped.len());
    let mut w_table = 5usize; // "Table"
    let mut w_count = 5usize; // "Count"
    let mut w_http = 4usize; // "HTTP"
    let mut w_error = 5usize; // "Error"
    let mut w_msg = 7usize; // "Message"
    let mut w_hint = 4usize; // "Hint"

    for ge in &grouped {
        let service = ge.first.service.as_deref().unwrap_or("");
        let api = ge.first.api.as_deref().unwrap_or("");
        let table_name = if service.is_empty() {
            api.to_string()
        } else {
            format!("{}_{}", service, api)
        };
        let table = truncate(&table_name, MAX_TABLE_W);
        let count = ge.count.to_string();
        let http = ge
            .first
            .http_status
            .map(|s| s.to_string())
            .unwrap_or_else(|| "—".to_string());
        let error = truncate(
            ge.first.upstream_code.as_deref().unwrap_or("—"),
            MAX_ERROR_W,
        );
        let message = truncate(&ge.first.message, MAX_MSG_W);
        let hint = match get_hint(ge.first.http_status, ge.first.upstream_code.as_deref()) {
            Some(h) => truncate(h.remediation, MAX_HINT_W),
            None => "—".to_string(),
        };

        w_table = w_table.max(table.chars().count());
        w_count = w_count.max(count.chars().count());
        w_http = w_http.max(http.chars().count());
        w_error = w_error.max(error.chars().count());
        w_msg = w_msg.max(message.chars().count());
        w_hint = w_hint.max(hint.chars().count());

        rows.push(Row {
            table,
            count,
            http,
            error,
            message,
            hint,
        });
    }

    // Header + separator
    let header = format!(
        "  {:<wt$} {:>wc$} {:>wh$} {:<we$} {:<wm$} {:<whi$}",
        "Table",
        "Count",
        "HTTP",
        "Error",
        "Message",
        "Hint",
        wt = w_table,
        wc = w_count,
        wh = w_http,
        we = w_error,
        wm = w_msg,
        whi = w_hint,
    );
    out.push(dim(&header));
    out.push(dim(&format!(
        "  {}",
        rule(w_table + w_count + w_http + w_error + w_msg + w_hint + 5)
    )));
    for r in &rows {
        out.push(format!(
            "  {:<wt$} {:>wc$} {:>wh$} {:<we$} {:<wm$} {:<whi$}",
            r.table,
            r.count,
            r.http,
            r.error,
            r.message,
            r.hint,
            wt = w_table,
            wc = w_count,
            wh = w_http,
            we = w_error,
            wm = w_msg,
            whi = w_hint,
        ));
    }

    // Footer: 2-3 drill-in pointers, dimmed.
    out.push(String::new());
    out.push(format!("  {}", dim("drill in:")));
    out.push(format!(
        "      {}",
        dim("oradaz inspect logs --full --service <svc> --api <name>")
    ));
    out.push(format!(
        "      {}",
        dim("oradaz inspect logs --http 429 --since 06:57")
    ));
    if !filters.include_expected {
        out.push(format!(
            "      {}",
            dim("oradaz inspect logs --include-expected   (also show schema-benign errors)")
        ));
    }
}

fn sort_grouped(
    grouped: &mut [crate::inspect::log_parser::GroupedEntry],
    sort: crate::inspect::log_parser::SortBy,
) {
    use crate::inspect::log_parser::SortBy;
    match sort {
        SortBy::Count => {
            grouped.sort_by(|a, b| {
                let key_a = group_table_key(a);
                let key_b = group_table_key(b);
                b.count.cmp(&a.count).then_with(|| key_a.cmp(&key_b))
            });
        }
        SortBy::Recent => {
            grouped.sort_by(|a, b| b.first.timestamp.cmp(&a.first.timestamp));
        }
        SortBy::Status => {
            grouped.sort_by(|a, b| {
                let sa = a.first.http_status.unwrap_or(0);
                let sb = b.first.http_status.unwrap_or(0);
                sa.cmp(&sb).then_with(|| b.count.cmp(&a.count))
            });
        }
    }
}

fn group_table_key(ge: &crate::inspect::log_parser::GroupedEntry) -> String {
    let service = ge.first.service.as_deref().unwrap_or("");
    let api = ge.first.api.as_deref().unwrap_or("");
    if service.is_empty() {
        api.to_string()
    } else {
        format!("{service}_{api}")
    }
}

/// `ℹ` in color mode, `i` in no-color — used by the pre-flight banner.
fn info_glyph_dim() -> String {
    match mode() {
        UiMode::Color => dim(&icon(Icon::Info)),
        UiMode::NoColor => icon(Icon::Info),
    }
}

// ─── logs --full renderer ──────────────────────────────────────────────────
//
// Entry-by-entry detail with response body + POST data for each log entry
// when --full is set.

pub fn print_all_api_errors(
    entries: &[LogEntry],
    out: &mut Vec<String>,
    source: &LogSource,
    filters: &LogFilters,
) {
    out.push(String::new());
    out.push(section_line("ENTRY DETAILS", None));
    out.push(String::new());

    let mut errors: Vec<_> = entries
        .iter()
        .filter(|e| {
            e.service.is_some()
                && match e.level {
                    LogLevel::Error => true,
                    LogLevel::Warn => filters.warnings || filters.info || filters.debug,
                    LogLevel::Info => filters.info || filters.debug,
                    LogLevel::Debug | LogLevel::Trace => filters.debug,
                }
        })
        .collect();

    if errors.is_empty() {
        if entries.is_empty() {
            out.push(format!(
                "{}(no API event log entries — 429 retries and expected errors are recorded at debug level; enable traceLogs at collection time and re-run with --debug to see them)",
                INDENT
            ));
        } else {
            out.push(format!(
                "{}(no API event log at this level — {} hidden; add {} to show)",
                INDENT,
                entries.len(),
                missing_verbosity_flags(filters),
            ));
        }
        return;
    }

    errors.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    let dump_error_index = build_dump_error_index(&source.dump_errors);
    for (i, entry) in errors.iter().enumerate() {
        let service = entry.service.as_deref().unwrap_or("");
        let api = entry.api.as_deref().unwrap_or("");
        let dump_error = find_dump_error_in_index(&dump_error_index, entry);

        out.push(format!(
            "  [{:>3}]  {}   {} / {}",
            i + 1,
            entry.timestamp,
            service,
            api
        ));

        let http_code = entry
            .http_status
            .map(|s| s.to_string())
            .unwrap_or_else(|| "—".to_string());
        let error_code = entry.upstream_code.as_deref().unwrap_or("—");
        out.push(format!("       HTTP {:<5} {:>20}", http_code, error_code));

        let url = entry
            .url
            .as_deref()
            .or(dump_error.map(|e| e.url.as_str()))
            .unwrap_or("");
        if !url.is_empty() {
            out.push(format!("       URL               {}", url));
        }
        if !entry.message.is_empty() {
            out.push(format!("       Detail            {}", entry.message));
        }

        if let Some(hint) = get_hint(entry.http_status, entry.upstream_code.as_deref()) {
            out.push(format!(
                "       {} Hint            {} {}",
                arrow_glyph_dim(),
                hint.explanation,
                dim(hint.remediation)
            ));
        }

        if let Some(de) = dump_error {
            if let Some(ref body) = de.full_response {
                push_pretty_block(out, "Response", body);
            }
            if let Some(ref data) = de.post_data {
                push_pretty_block(out, "Post data", data);
            }
        }

        out.push(String::new());
    }
}

/// Render a multi-line JSON value as a labelled block — `"Label   { ... }"`
/// on the first line, the continuation indented to line up with the value
/// column. Used by `print_all_api_errors` for `full_response` / `post_data`.
fn push_pretty_block(out: &mut Vec<String>, label: &str, value: &Value) {
    let pretty = serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string());
    let continuation = " ".repeat(7 + 18); // 7 spaces indent + 18-char label column.
    let mut lines = pretty.lines();
    if let Some(first) = lines.next() {
        out.push(format!("       {:<18}{}", label, first));
        for line in lines {
            out.push(format!("{continuation}{line}"));
        }
    }
}

/// `➜` (color, dimmed) / `>` (no-color) — small leading glyph for inline
/// hint/drill-in pointers.
fn arrow_glyph_dim() -> String {
    match mode() {
        UiMode::Color => dim(&icon(Icon::Arrow)),
        UiMode::NoColor => icon(Icon::Arrow),
    }
}
