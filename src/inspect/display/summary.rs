use super::*;
use crate::inspect::log_parser::{LogEntry, LogLevel};
use crate::utils::ui::{Icon, Paint, UiMode, dim, icon, paint, warn_text};

use chrono::NaiveDateTime;
use serde_json::Value;
use std::collections::BTreeMap;

pub fn print_summary(
    entries: &[LogEntry],
    metadata: Option<&Value>,
    config: Option<&Value>,
    is_broken: bool,
    out: &mut Vec<String>,
) {
    // Provenance block (tenant / dates / version / auth / schema) is shared
    // with every other inspect command — delegate to keep both copies in
    // lockstep.
    print_collection_summary(metadata, config, out);

    if is_broken {
        let msg = warn_text(&format!(
            "{}  Archive is incomplete (the collection was interrupted)",
            icon(Icon::Warn)
        ));
        out.push(format!("  {}", msg));
        out.push(String::new());
    }

    // Per-service stats
    let mut stats: BTreeMap<String, (usize, usize, usize, usize, usize)> = BTreeMap::new(); // service → (err, warn, info, debug, trace)

    // Initialize from `metadata.services` first — it lists every service the
    // collector touched, including those the user left at the default
    // (config.services only lists *explicit overrides*, so a tenant collecting
    // Graph with defaults will not have Graph in config.services even though
    // it was clearly enabled and collected).
    if let Some(m) = metadata
        && let Some(map) = m.get("services").and_then(|s| s.as_object())
    {
        for (name, status) in map {
            if status.as_str() == Some("enabled") {
                stats.entry(name.to_lowercase()).or_insert((0, 0, 0, 0, 0));
            }
        }
    }
    // Then merge in the explicit config.services overrides (covers older
    // archives that lack `metadata.services`).
    if let Some(c) = config
        && let Some(svc_list) = c
            .get("services")
            .and_then(|s| s.get("service"))
            .and_then(|s| s.as_array())
    {
        for svc in svc_list {
            if let Some(name) = svc.get("@name").and_then(|n| n.as_str()) {
                let enabled = svc.get("#text").and_then(|t| t.as_bool()).unwrap_or(false);
                if enabled {
                    let name_lower = name.to_lowercase();
                    stats.entry(name_lower).or_insert((0, 0, 0, 0, 0));
                }
            }
        }
    }

    for entry in entries {
        if let Some(ref svc) = entry.service {
            let svc_lower = svc.to_lowercase();
            let s = stats.entry(svc_lower).or_insert((0, 0, 0, 0, 0));
            match entry.level {
                LogLevel::Error => s.0 += 1,
                LogLevel::Warn => s.1 += 1,
                LogLevel::Info => s.2 += 1,
                LogLevel::Debug => s.3 += 1,
                LogLevel::Trace => s.4 += 1,
            }
        }
    }

    if !stats.is_empty() {
        out.push(section_line("LOGS SUMMARY", None));
        out.push(String::new());

        let header = format!(
            "  {:<17} {:>7} {:>9} {:>7} {:>7} {:>7}",
            "Service", "Errors", "Warnings", "Info", "Debug", "Trace"
        );
        let sep = format!("  {}", rule(59));
        out.push(dim(&header));
        out.push(dim(&sep));

        for (svc, (err, warn, info, debug, trace)) in &stats {
            let display = match svc.as_str() {
                "graph" => "Graph",
                "resources" => "Resources",
                "exchange" => "Exchange",
                _ => svc,
            };
            let err_str = if *err > 0 {
                crate::utils::ui::err_text(&format!("{:>7}", err))
            } else {
                dim(&format!("{:>7}", err))
            };
            let warn_str = if *warn > 0 {
                crate::utils::ui::warn_text(&format!("{:>9}", warn))
            } else {
                dim(&format!("{:>9}", warn))
            };
            let info_str = if *info > 0 {
                format!("{:>7}", info)
            } else {
                dim(&format!("{:>7}", info))
            };
            let debug_str = if *debug > 0 {
                format!("{:>7}", debug)
            } else {
                dim(&format!("{:>7}", debug))
            };
            let trace_str = if *trace > 0 {
                format!("{:>7}", trace)
            } else {
                dim(&format!("{:>7}", trace))
            };

            out.push(format!(
                "  {:<17} {} {} {} {} {}",
                display, err_str, warn_str, info_str, debug_str, trace_str
            ));
        }
    } else {
        out.push(format!("{}(no API events found in log)", INDENT));
    }
}

/// Per-bucket frequency chart of error / 429 entries.
///
/// `bucket_override` lets callers force a granularity (in seconds — typically
/// 1, 10, or 60). When `None`, granularity is auto-picked from the time
/// span: <60 s → 1 s, <300 s → 10 s, else 60 s. The `inspect timeline`
/// command surfaces this override via `--bucket 1s|10s|1m`.
pub fn print_timeline(
    entries: &[LogEntry],
    only_429: bool,
    bucket_override: Option<i64>,
    out: &mut Vec<String>,
) {
    let interesting: Vec<&LogEntry> = entries
        .iter()
        .filter(|e| {
            if only_429 {
                e.http_status == Some(429)
            } else {
                e.http_status.is_some_and(|s| s != 200 && s != 429)
            }
        })
        .collect();

    if interesting.is_empty() {
        out.push(section_line(
            if only_429 {
                "TIMELINE (429 by minute)"
            } else {
                "TIMELINE (errors by minute)"
            },
            None,
        ));
        out.push(String::new());
        out.push(format!("{}(no relevant errors to chart)", INDENT));
        return;
    }

    // Determine duration and granularity
    let timestamps: Vec<i64> = interesting
        .iter()
        .filter_map(|e| {
            NaiveDateTime::parse_from_str(&e.timestamp, "%Y-%m-%d %H:%M:%S")
                .ok()
                .map(|dt| dt.and_utc().timestamp())
        })
        .collect();

    if timestamps.is_empty() {
        out.push(section_line(
            if only_429 {
                "TIMELINE (429 by minute)"
            } else {
                "TIMELINE (errors by minute)"
            },
            None,
        ));
        out.push(String::new());
        out.push(format!("{}(could not parse timestamps)", INDENT));
        return;
    }

    let min_ts = *timestamps.iter().min().unwrap();
    let max_ts = *timestamps.iter().max().unwrap();
    let duration = max_ts - min_ts;

    let (granularity, label_fmt) = match bucket_override {
        Some(b) if b > 0 => (b, if b < 60 { "%H:%M:%S" } else { "%H:%M" }),
        _ if duration < 60 => (1, "%H:%M:%S"),
        _ if duration < 300 => (10, "%H:%M:%S"),
        _ => (60, "%H:%M"),
    };

    let title = if only_429 {
        if granularity == 1 {
            "TIMELINE (429 by second)"
        } else if granularity == 10 {
            "TIMELINE (429 by 10s)"
        } else {
            "TIMELINE (429 by minute)"
        }
    } else if granularity == 1 {
        "TIMELINE (errors by second)"
    } else if granularity == 10 {
        "TIMELINE (errors by 10s)"
    } else {
        "TIMELINE (errors by minute)"
    };

    out.push(section_line(title, None));
    out.push(String::new());

    // bucket → (total_count, per_service_count)
    let mut by_bucket: BTreeMap<i64, (usize, BTreeMap<String, usize>)> = BTreeMap::new();

    for entry in &interesting {
        if let Ok(dt) = NaiveDateTime::parse_from_str(&entry.timestamp, "%Y-%m-%d %H:%M:%S") {
            let ts = dt.and_utc().timestamp();
            let bucket = (ts - min_ts) / granularity;
            let svc = entry.service.as_deref().unwrap_or("unknown").to_string();
            let slot = by_bucket.entry(bucket).or_insert((0, BTreeMap::new()));
            slot.0 += 1;
            *slot.1.entry(svc).or_insert(0) += 1;
        }
    }

    let max_count = by_bucket.values().map(|(c, _)| *c).max().unwrap_or(1);
    const BAR_WIDTH: usize = 20;

    for (bucket, (count, per_svc)) in &by_bucket {
        let ts = min_ts + bucket * granularity;
        let Some(dt) = chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0) else {
            continue;
        };
        let label = dt.format(label_fmt).to_string();

        let filled = if max_count == 0 {
            0
        } else {
            (count * BAR_WIDTH).div_ceil(max_count).min(BAR_WIDTH)
        };

        let bar = match mode() {
            UiMode::Color => {
                let b = format!("{}{}", "█".repeat(filled), "░".repeat(BAR_WIDTH - filled));
                paint(Paint::Red, &b)
            }
            UiMode::NoColor => {
                format!("{}{}", "X".repeat(filled), ".".repeat(BAR_WIDTH - filled))
            }
        };

        let svc_parts: Vec<String> = per_svc
            .iter()
            .map(|(svc, cnt)| format!("{} ×{}", svc, cnt))
            .collect();
        let svc_label = svc_parts.join(", ");

        let count_label = if only_429 {
            format!("{}", count)
        } else {
            format!("{} errors", count)
        };

        out.push(format!(
            "  {:<8}  {}  {}  {}",
            label,
            bar,
            count_label,
            dim(&svc_label)
        ));
    }
}
