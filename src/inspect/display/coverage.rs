//! Helpers shared by the per-service coverage tables in `overview`
//! (`summary` command) and `sections::print_services_section` (`services`
//! command). Low-level only — table layout stays in each caller.

use super::{dim, ellipsis, rule_char, strip_ansi_codes};
use crate::utils::ui::{Icon, Paint, UiMode, icon, mode, paint};

use serde_json::Value;
use std::collections::BTreeMap;

/// Canonical display order for the three top-level services.
pub const SERVICE_ORDER: &[&str] = &["graph", "resources", "exchange"];

/// Pretty-cased service label (`"graph"` → `"Graph"`).
pub fn svc_display_name(svc: &str) -> &str {
    match svc {
        "graph" => "Graph",
        "resources" => "Resources",
        "exchange" => "Exchange",
        _ => svc,
    }
}

/// Build `service → (user_principal_name, user_id)` from `metadata.tokens[]`.
/// Service names are lowercased to match SERVICE_ORDER lookups.
pub fn parse_tokens(metadata: Option<&Value>) -> BTreeMap<String, (String, String)> {
    let mut out: BTreeMap<String, (String, String)> = BTreeMap::new();
    let Some(tokens) = metadata
        .and_then(|m| m.get("tokens"))
        .and_then(|t| t.as_array())
    else {
        return out;
    };
    for t in tokens {
        let name = t.get("name").and_then(|n| n.as_str()).unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let upn = t
            .get("user_principal_name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let uid = t
            .get("user_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        out.insert(name.to_lowercase(), (upn, uid));
    }
    out
}

/// Build `service → status` from `metadata.services` map. Values are one of
/// `enabled` / `disabled_by_config` / `disabled_by_prerequisite_failure`
/// (kept verbatim — match on these in callers).
pub fn parse_service_statuses(metadata: Option<&Value>) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let Some(map) = metadata
        .and_then(|m| m.get("services"))
        .and_then(|s| s.as_object())
    else {
        return out;
    };
    for (k, v) in map {
        if let Some(s) = v.as_str() {
            out.insert(k.to_lowercase(), s.to_string());
        }
    }
    out
}

/// `"upn (uid8…)"` for present tokens, `"—"` otherwise. Truncates `user_id`
/// to its first 8 characters to keep table widths bounded.
pub fn format_account(tokens: &BTreeMap<String, (String, String)>, svc: &str) -> String {
    let Some((upn, uid)) = tokens.get(svc) else {
        return "—".to_string();
    };
    let short_id: String = uid.chars().take(8).collect();
    if upn.is_empty() && short_id.is_empty() {
        "—".to_string()
    } else if short_id.is_empty() {
        upn.to_string()
    } else if upn.is_empty() {
        format!("({short_id}{})", ellipsis())
    } else {
        format!("{upn} ({short_id}{})", ellipsis())
    }
}

/// HTTP-call breakdown from `stats.services[svc]`: `"117 batch"` /
/// `"15 single"` / `"117 batch + 15 single"` / `"—"`.
pub fn format_http_counts(services: Option<&serde_json::Map<String, Value>>, svc: &str) -> String {
    let Some(map) = services else {
        return "—".to_string();
    };
    let Some(entry) = map.get(svc) else {
        return "—".to_string();
    };
    let batch = entry
        .get("http_batch_calls")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let single = entry
        .get("http_single_calls")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    match (batch, single) {
        (0, 0) => "—".to_string(),
        (b, 0) => format!("{b} batch"),
        (0, s) => format!("{s} single"),
        (b, s) => format!("{b} batch + {s} single"),
    }
}

/// `service → unexpected error count` summed from `stats.apis[]`.
pub fn unexpected_per_service(stats: Option<&Value>) -> BTreeMap<String, u64> {
    sum_per_service_field(stats, "unexpected_errors")
}

/// `service → expected error count` summed from `stats.apis[]`.
pub fn expected_per_service(stats: Option<&Value>) -> BTreeMap<String, u64> {
    sum_per_service_field(stats, "expected_errors")
}

fn sum_per_service_field(stats: Option<&Value>, field: &str) -> BTreeMap<String, u64> {
    let mut out: BTreeMap<String, u64> = BTreeMap::new();
    let Some(apis) = stats.and_then(|s| s.get("apis")).and_then(|a| a.as_array()) else {
        return out;
    };
    for api in apis {
        let svc = api.get("service").and_then(|v| v.as_str()).unwrap_or("");
        let n = api.get(field).and_then(|v| v.as_u64()).unwrap_or(0);
        if !svc.is_empty() && n > 0 {
            *out.entry(svc.to_string()).or_insert(0) += n;
        }
    }
    out
}

/// `"icon Service"` with mode-appropriate colour. Pad to a fixed column via
/// `strip_ansi_codes(...).chars().count()` to account for ANSI escapes.
pub fn service_cell(svc: &str, status: &str) -> String {
    let name = svc_display_name(svc);
    let painted = match status {
        "enabled" => {
            let g = icon(Icon::Ok);
            match mode() {
                UiMode::Color => paint(Paint::Green, &g),
                UiMode::NoColor => g,
            }
        }
        "disabled_by_prerequisite_failure" => {
            let g = icon(Icon::Err);
            match mode() {
                UiMode::Color => paint(Paint::Red, &g),
                UiMode::NoColor => g,
            }
        }
        // disabled_by_config / unknown: dim neutral marker.
        _ => dim(&rule_char()),
    };
    format!("{} {}", painted, name)
}

/// Visible width of a (potentially ANSI-coloured) string — wrapper around the
/// shared `strip_ansi_codes` helper for callers computing per-cell padding.
pub fn visible_width(s: &str) -> usize {
    strip_ansi_codes(s).chars().count()
}
