//! Renderer for `oradaz compare <A> <B>` — side-by-side diff of two
//! collections. Five sections:
//!
//! 1. **COMPARE COLLECTIONS** — A vs B at a glance: date, verdict, duration,
//!    archive size.
//! 2. **QUALITY DELTAS** — counters that should rarely move: unexpected
//!    errors, 429 throttling, network errors, auth/prereq errors, duration.
//! 3. **COVERAGE DELTAS** — per-service object totals (from
//!    `objects_per_service`).
//! 4. **TOP TABLE MOVERS** — top N tables by absolute delta, joined on the
//!    `(folder, file)` tuple (never `name` alone — collisions possible
//!    between services).
//! 5. **CONFIG CHANGES** — boolean toggles and performance-tuning fields
//!    whose values differ between the two collections.

use super::{
    Align, INDENT, Row, delta_header, dim, ellipsis, format_thousands, render_table, section_line,
    transition_arrow, u64_field, verdict_badge,
};
use crate::inspect::analysis::{ServiceObjects, compute_verdict, objects_per_service};
use crate::inspect::loader::LogSource;
use crate::utils::ui::{UiMode, mode, warn_text};

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub fn print_compare_section(a: &LogSource, b: &LogSource, out: &mut Vec<String>) {
    print_header(a, b, out);

    out.push(String::new());
    out.push(section_line("QUALITY DELTAS", None));
    out.push(String::new());
    print_quality_deltas(a, b, out);

    out.push(String::new());
    out.push(section_line("COVERAGE DELTAS", None));
    out.push(String::new());
    print_coverage_deltas(a, b, out);

    out.push(String::new());
    out.push(section_line("TOP TABLE MOVERS", None));
    out.push(String::new());
    print_table_movers(a, b, out);

    out.push(String::new());
    out.push(section_line("CONFIG CHANGES", None));
    out.push(String::new());
    print_config_changes(a, b, out);
}

// ─── header ───────────────────────────────────────────────────────────────

fn print_header(a: &LogSource, b: &LogSource, out: &mut Vec<String>) {
    out.push(section_line("COMPARE COLLECTIONS", None));
    out.push(String::new());
    out.push(format!("  A  {}", source_summary_line(a)));
    out.push(format!("  B  {}", source_summary_line(b)));
}

fn source_summary_line(src: &LogSource) -> String {
    let date = src
        .metadata
        .as_ref()
        .and_then(|m| m.get("collection_date").and_then(|v| v.as_str()))
        .unwrap_or("?");
    let verdict = compute_verdict(src.metadata.as_ref(), src.stats.as_ref(), src.is_broken);
    let duration = src
        .metadata
        .as_ref()
        .and_then(|m| m.get("total_duration_secs").and_then(|v| v.as_i64()))
        .or_else(|| {
            src.metadata
                .as_ref()
                .and_then(|m| m.get("dump_duration_secs").and_then(|v| v.as_i64()))
        })
        .unwrap_or(0);
    let size = src
        .size_bytes
        .map(super::format_bytes)
        .unwrap_or_else(|| "?".to_string());
    format!(
        "{}  {}  ({} s)  {}",
        date,
        verdict_badge(verdict),
        duration,
        dim(&size)
    )
}

// ─── quality deltas table ─────────────────────────────────────────────────

fn print_quality_deltas(a: &LogSource, b: &LogSource, out: &mut Vec<String>) {
    let rows: Vec<DeltaRow> = vec![
        DeltaRow::counter(
            "Unexpected errors",
            unexpected_count(a),
            unexpected_count(b),
            Direction::IncreaseIsBad,
        ),
        DeltaRow::counter(
            "Expected errors",
            metadata_u64(a, "expected_errors"),
            metadata_u64(b, "expected_errors"),
            Direction::Neutral,
        ),
        DeltaRow::counter(
            "429 retries",
            stats_sum(a, "retries_rate_limit"),
            stats_sum(b, "retries_rate_limit"),
            Direction::IncreaseIsBad,
        ),
        DeltaRow::counter(
            "429 wait (s)",
            stats_sum(a, "rate_limit_wait_secs"),
            stats_sum(b, "rate_limit_wait_secs"),
            Direction::IncreaseIsBad,
        ),
        // Throttling / writer-saturation peaks from the debug-telemetry metadata
        // fields — tuning signals for slow-start, ARM-window and writer-bottleneck
        // behaviour. All `#[serde(default)]`, so older archives without them
        // simply read 0.
        DeltaRow::counter(
            "Backoff peak",
            metadata_u64(a, "peak_backoff_active"),
            metadata_u64(b, "peak_backoff_active"),
            Direction::IncreaseIsBad,
        ),
        DeltaRow::counter(
            "Writer queue peak %",
            metadata_u64(a, "peak_writer_queue_pct"),
            metadata_u64(b, "peak_writer_queue_pct"),
            Direction::IncreaseIsBad,
        ),
        DeltaRow::counter(
            "Writer blocked (s)",
            metadata_u64(a, "writer_budget_blocked_secs"),
            metadata_u64(b, "writer_budget_blocked_secs"),
            Direction::IncreaseIsBad,
        ),
        DeltaRow::counter(
            // "Request failures" (transport/parse-level), consistent with the
            // stats / summary relabel away from the inaccurate "Network errors".
            "Request failures",
            network_count(a),
            network_count(b),
            Direction::IncreaseIsBad,
        ),
        DeltaRow::counter(
            "Authentication errors",
            metadata_u64(a, "auth_errors"),
            metadata_u64(b, "auth_errors"),
            Direction::IncreaseIsBad,
        ),
        DeltaRow::counter(
            "Prerequisite errors",
            metadata_u64(a, "prerequisites_errors"),
            metadata_u64(b, "prerequisites_errors"),
            Direction::IncreaseIsBad,
        ),
        DeltaRow::counter(
            "Duration (s)",
            total_or_dump_duration_secs(a),
            total_or_dump_duration_secs(b),
            Direction::Neutral,
        ),
    ];

    let trows: Vec<Row> = rows
        .iter()
        .map(|r| {
            Row::Cells(vec![
                r.label.clone(),
                r.a.to_string(),
                r.b.to_string(),
                r.delta_str(),
            ])
        })
        .collect();
    render_table(
        "  ",
        &["Metric", "A", "B", delta_header()],
        &[Align::Left, Align::Right, Align::Right, Align::Left],
        &trows,
        out,
    );
}

// ─── per-service coverage deltas ──────────────────────────────────────────

fn print_coverage_deltas(a: &LogSource, b: &LogSource, out: &mut Vec<String>) {
    let obj_a = objects_per_service(a.metadata.as_ref());
    let obj_b = objects_per_service(b.metadata.as_ref());

    let mut services: BTreeSet<String> = BTreeSet::new();
    services.extend(obj_a.keys().cloned());
    services.extend(obj_b.keys().cloned());
    if services.is_empty() {
        out.push(format!("{}(no objects recorded in either source)", INDENT));
        return;
    }

    // Canonical order first (graph/resources/exchange), then anything else.
    let canonical = ["graph", "resources", "exchange"];
    let mut ordered: Vec<String> = Vec::new();
    for svc in canonical {
        if services.remove(svc) {
            ordered.push(svc.to_string());
        }
    }
    let mut extras: Vec<String> = services.into_iter().collect();
    extras.sort();
    ordered.extend(extras);

    let mut rows: Vec<Row> = Vec::new();
    for svc in ordered {
        let default = ServiceObjects::default();
        let av = obj_a.get(&svc).unwrap_or(&default);
        let bv = obj_b.get(&svc).unwrap_or(&default);
        let row = DeltaRow::counter(
            &pretty_service_name(&svc),
            av.objects,
            bv.objects,
            Direction::DecreaseIsBad,
        );
        let annotation = if av.objects > 0 && bv.objects == 0 {
            format!("  {}", dim("(not collected in B)"))
        } else if av.objects == 0 && bv.objects > 0 {
            format!("  {}", dim("(new in B)"))
        } else {
            String::new()
        };
        rows.push(Row::Cells(vec![
            row.label.clone(),
            format_thousands(av.objects),
            format_thousands(bv.objects),
            format!("{}{}", row.delta_str(), annotation),
        ]));
    }
    render_table(
        "  ",
        &["Service", "A", "B", delta_header()],
        &[Align::Left, Align::Right, Align::Right, Align::Left],
        &rows,
        out,
    );
}

// ─── top table movers ─────────────────────────────────────────────────────

fn print_table_movers(a: &LogSource, b: &LogSource, out: &mut Vec<String>) {
    let map_a = tables_by_folder_file(a);
    let map_b = tables_by_folder_file(b);
    let mut all: BTreeSet<(String, String)> = BTreeSet::new();
    all.extend(map_a.keys().cloned());
    all.extend(map_b.keys().cloned());
    let mut deltas: Vec<((String, String), i64, u64, u64)> = all
        .into_iter()
        .map(|key| {
            let av = *map_a.get(&key).unwrap_or(&0);
            let bv = *map_b.get(&key).unwrap_or(&0);
            let delta = (bv as i128 - av as i128).clamp(i64::MIN as i128, i64::MAX as i128) as i64;
            ((key.0, key.1), delta, av, bv)
        })
        .filter(|(_, d, _, _)| *d != 0)
        .collect();
    if deltas.is_empty() {
        out.push(format!("{}(no table changed between A and B)", INDENT));
        return;
    }
    deltas.sort_by(|a, b| b.1.abs().cmp(&a.1.abs()));
    let limit = deltas.len().min(10);
    let mut rows: Vec<Row> = Vec::new();
    for ((folder, file), delta, av, bv) in deltas.iter().take(limit) {
        // Strip the conventional `.json` suffix so the label reads as the
        // logical API table name (e.g. `graph/users` instead of
        // `graph/users.json`).
        let pretty_file = file.strip_suffix(".json").unwrap_or(file);
        let label = format!("{}/{}", folder, pretty_file);
        let row = DeltaRow {
            label: label.clone(),
            a: *av,
            b: *bv,
            direction: Direction::DecreaseIsBad,
        };
        rows.push(Row::Cells(vec![
            label,
            format_thousands(*av),
            format_thousands(*bv),
            row.delta_str_explicit(*delta),
        ]));
    }
    render_table(
        "  ",
        &["Table", "A", "B", delta_header()],
        &[Align::Left, Align::Right, Align::Right, Align::Left],
        &rows,
        out,
    );
    if deltas.len() > limit {
        out.push(format!(
            "{}{}",
            INDENT,
            dim(&format!(
                "{} and {} more changed",
                ellipsis(),
                deltas.len() - limit
            ))
        ));
    }
}

fn tables_by_folder_file(src: &LogSource) -> BTreeMap<(String, String), u64> {
    let mut out: BTreeMap<(String, String), u64> = BTreeMap::new();
    let Some(arr) = src
        .metadata
        .as_ref()
        .and_then(|m| m.get("tables").and_then(|t| t.as_array()))
    else {
        return out;
    };
    for t in arr {
        let folder = t.get("folder").and_then(|v| v.as_str()).unwrap_or("");
        let file = t.get("file").and_then(|v| v.as_str()).unwrap_or("");
        if folder.is_empty() || file.is_empty() {
            continue;
        }
        let count = t.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        *out.entry((folder.to_string(), file.to_string()))
            .or_insert(0) += count;
    }
    out
}

// ─── config changes ───────────────────────────────────────────────────────

fn print_config_changes(a: &LogSource, b: &LogSource, out: &mut Vec<String>) {
    let mut lines: Vec<String> = Vec::new();
    // Mode-aware transition arrow (`→` / `->`); inline-captured by the `{arr}`
    // in each change line below.
    let arr = transition_arrow();

    let ca = a.config.as_ref();
    let cb = b.config.as_ref();

    // Boolean toggles that materially affect collection scope.
    let toggles = &[
        "use_device_code",
        "use_application_credentials",
        "proxy",
        "use_schema_file",
        "additional_mla_keys",
        "no_check",
        "trace_logs",
        "shuffle_urls",
        "concurrency_slow_start",
    ];
    for field in toggles {
        let av = bool_field(ca, field);
        let bv = bool_field(cb, field);
        if av != bv {
            lines.push(format!(
                "  {:<28}  {} {arr} {}",
                field,
                yes_no(av),
                yes_no(bv)
            ));
        }
    }

    // Per-service enable/disable from the services list.
    let svc_a = services_state(ca);
    let svc_b = services_state(cb);
    let mut svcs: BTreeSet<String> = BTreeSet::new();
    svcs.extend(svc_a.keys().cloned());
    svcs.extend(svc_b.keys().cloned());
    for s in svcs {
        let av = svc_a.get(&s).copied().unwrap_or(false);
        let bv = svc_b.get(&s).copied().unwrap_or(false);
        if av != bv {
            lines.push(format!(
                "  {:<28}  {} {arr} {}",
                format!("services.{s}"),
                if av { "on" } else { "off" },
                if bv { "on" } else { "off" }
            ));
        }
    }

    // Performance-tuning numeric fields.
    let numeric = &[
        "concurrency_min_window",
        "concurrency_max_window",
        "default_retry_after_seconds",
        "http_timeout_seconds",
        "http_connect_timeout_seconds",
        "dispatch_burst_cap",
        "url_retry_limit",
        "rate_limit_retry_limit",
        "rate_limit_max_wait_secs",
        "stall_detection_timeout",
        "prereq_recheck_cache_secs",
        "retry_backoff_base_ms",
        "retry_backoff_cap_ms",
    ];
    for field in numeric {
        let av = ca.and_then(|c| c.get(field).and_then(|v| v.as_u64()));
        let bv = cb.and_then(|c| c.get(field).and_then(|v| v.as_u64()));
        if av != bv {
            lines.push(format!(
                "  {:<28}  {} {arr} {}",
                field,
                av.map(|n| n.to_string())
                    .unwrap_or_else(|| "null".to_string()),
                bv.map(|n| n.to_string())
                    .unwrap_or_else(|| "null".to_string())
            ));
        }
    }

    if lines.is_empty() {
        out.push(format!("  {}", dim("(no relevant config field changed)")));
    } else {
        for l in lines {
            out.push(l);
        }
    }
}

// ─── helpers ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    /// A → B going up is bad (more errors, more wait).
    IncreaseIsBad,
    /// A → B going down is bad (fewer objects collected).
    DecreaseIsBad,
    /// No value judgement.
    Neutral,
}

struct DeltaRow {
    label: String,
    a: u64,
    b: u64,
    direction: Direction,
}

impl DeltaRow {
    fn counter(label: &str, a: u64, b: u64, direction: Direction) -> Self {
        Self {
            label: label.to_string(),
            a,
            b,
            direction,
        }
    }

    fn delta_str(&self) -> String {
        let delta =
            (self.b as i128 - self.a as i128).clamp(i64::MIN as i128, i64::MAX as i128) as i64;
        self.delta_str_explicit(delta)
    }

    fn delta_str_explicit(&self, delta: i64) -> String {
        // Color shows a direction arrow + signed magnitude (▲ +N / ▼ −N).
        // NoColor uses a plain ASCII signed number (+N / -N): the arrow glyphs
        // are "+"/"-" there, so "▼ −N" would render as the redundant "- -N".
        let raw = match (delta.signum(), mode()) {
            (0, _) => "=".to_string(),
            (1, UiMode::Color) => format!("{} +{}", arrow_up(), format_thousands(delta as u64)),
            (1, UiMode::NoColor) => format!("+{}", format_thousands(delta as u64)),
            (_, UiMode::Color) => format!(
                "{} −{}",
                arrow_down(),
                format_thousands(delta.unsigned_abs())
            ),
            (_, UiMode::NoColor) => format!("-{}", format_thousands(delta.unsigned_abs())),
        };
        if delta == 0 {
            return dim(&raw);
        }
        let bad = matches!(
            (self.direction, delta.signum()),
            (Direction::IncreaseIsBad, 1) | (Direction::DecreaseIsBad, -1)
        );
        if bad { warn_text(&raw) } else { dim(&raw) }
    }
}

fn arrow_up() -> &'static str {
    match mode() {
        UiMode::Color => "▲",
        UiMode::NoColor => "+",
    }
}

fn arrow_down() -> &'static str {
    match mode() {
        UiMode::Color => "▼",
        UiMode::NoColor => "-",
    }
}

/// Read the unexpected-errors counter, with a `stats.apis[]` fallback for
/// older archives that don't carry it at metadata top-level.
///
/// **Caveat**: in mixed pairs (one archive recent, one older) the two sides
/// may resolve from different sources — the metadata counter vs. a sum across
/// `apis[]`. The two figures track the same semantic but are computed at
/// different points in the pipeline; small discrepancies are possible. Pairs
/// produced by the same oradaz version are never affected.
fn unexpected_count(src: &LogSource) -> u64 {
    src.metadata
        .as_ref()
        .and_then(|m| m.get("unexpected_errors").and_then(|v| v.as_u64()))
        .unwrap_or_else(|| stats_sum(src, "unexpected_errors"))
}

/// Same fallback caveat as [`unexpected_count`] — the per-service
/// `http_call_failures` (avoids double-counting batched failures) is used
/// when available, with a `stats.apis[].network_errors` sum otherwise.
fn network_count(src: &LogSource) -> u64 {
    src.stats
        .as_ref()
        .and_then(|s| s.get("services").and_then(|v| v.as_object()))
        .map(|map| {
            map.values()
                .map(|svc| u64_field(svc, "http_call_failures"))
                .sum()
        })
        .unwrap_or_else(|| stats_sum(src, "network_errors"))
}

fn stats_sum(src: &LogSource, field: &str) -> u64 {
    src.stats
        .as_ref()
        .and_then(|s| s.get("apis").and_then(|a| a.as_array()))
        .map(|apis| apis.iter().map(|api| u64_field(api, field)).sum())
        .unwrap_or(0)
}

fn metadata_u64(src: &LogSource, key: &str) -> u64 {
    src.metadata
        .as_ref()
        .and_then(|m| m.get(key).and_then(|v| v.as_u64()))
        .unwrap_or(0)
}

/// Total run duration, falling back to the dump duration for older archives that
/// predate `total_duration_secs` (mirrors the header in `source_summary_line`), so
/// the "Duration (s)" delta shows a real value instead of a misleading `0 -> N`.
fn total_or_dump_duration_secs(src: &LogSource) -> u64 {
    let m = src.metadata.as_ref();
    m.and_then(|m| m.get("total_duration_secs").and_then(|v| v.as_u64()))
        .or_else(|| m.and_then(|m| m.get("dump_duration_secs").and_then(|v| v.as_u64())))
        .unwrap_or(0)
}

fn bool_field(config: Option<&Value>, field: &str) -> bool {
    config
        .and_then(|c| c.get(field).and_then(|v| v.as_bool()))
        .unwrap_or(false)
}

fn yes_no(v: bool) -> &'static str {
    if v { "yes" } else { "no" }
}

fn services_state(config: Option<&Value>) -> BTreeMap<String, bool> {
    let mut out: BTreeMap<String, bool> = BTreeMap::new();
    let Some(arr) = config
        .and_then(|c| c.get("services").and_then(|s| s.get("service")))
        .and_then(|s| s.as_array())
    else {
        return out;
    };
    for svc in arr {
        let name = svc.get("@name").and_then(|n| n.as_str()).unwrap_or("");
        let enabled = svc.get("#text").and_then(|t| t.as_bool()).unwrap_or(false);
        if !name.is_empty() {
            out.insert(name.to_string(), enabled);
        }
    }
    out
}

fn pretty_service_name(svc: &str) -> String {
    match svc.to_lowercase().as_str() {
        "graph" => "Graph".to_string(),
        "resources" => "Resources".to_string(),
        "exchange" => "Exchange".to_string(),
        other => other.to_string(),
    }
}
