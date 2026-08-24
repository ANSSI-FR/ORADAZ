//! Renderer for `oradaz inspect hints` — the remediation digest.
//!
//! Aggregates four categories with distinct severity / cause:
//!
//! 1. **FATAL** — what blocked part of the collection: a broken archive,
//!    authentication failures, services disabled by a failed prerequisite.
//!    These items are derived from `metadata.json` + `prerequisites.json`.
//! 2. **UNEXPECTED ERRORS** — anomalous HTTP errors recorded in
//!    `errors.json`. Each entry is joined with the `hints.rs` catalog for
//!    its remediation line.
//! 3. **THROTTLING** — APIs that hit significant 429 pressure during the
//!    run. Pulled from `stats.apis[]` (transient — successful after retries)
//!    *and* from `errors.json` entries with status 429 (rare — rate-limit
//!    budget exhausted).
//! 4. **EXPECTED ERRORS** — schema-declared benign entries, summarised by
//!    default and listed individually with `--include-expected`.

use super::{
    dim, format_thousands, mid_sep, rule, section_line_with_verdict, str_field, u64_field,
};
use crate::inspect::analysis::{ErrorCategory, aggregate_errors, compute_verdict, has_lost_data};
use crate::inspect::hints::get_hint;
use crate::inspect::loader::LogSource;
use crate::inspect::log_parser::{LogLevel, last_plain_failure_context, parse_log};
use crate::utils::ui::{Icon, UiMode, err_text, icon, mode, warn_text};

use serde_json::Value;
use std::collections::BTreeSet;

pub fn print_remediation_section(
    source: &LogSource,
    service_filter: Option<&str>,
    include_expected: bool,
    out: &mut Vec<String>,
) {
    let verdict = compute_verdict(
        source.metadata.as_ref(),
        source.stats.as_ref(),
        source.is_broken,
        has_lost_data(&source.dump_errors),
    );
    out.push(section_line_with_verdict("REMEDIATION", verdict));
    out.push(String::new());

    let fatals = collect_fatals(source, service_filter);
    let groups = aggregate_errors(&source.dump_errors);
    let unexpected: Vec<_> = groups
        .iter()
        .filter(|g| g.category == ErrorCategory::Unexpected)
        .filter(|g| service_filter.is_none_or(|s| g.service == s))
        .collect();
    let expected: Vec<_> = groups
        .iter()
        .filter(|g| g.category == ErrorCategory::Expected)
        .filter(|g| service_filter.is_none_or(|s| g.service == s))
        .collect();
    let throttling = collect_throttling(source, &groups, service_filter);

    let any_actionable = !fatals.is_empty() || !unexpected.is_empty() || !throttling.is_empty();
    if !any_actionable && expected.is_empty() {
        out.push(format!(
            "  {}",
            dim("(nothing to fix — collection looks healthy)")
        ));
        return;
    }

    let mut first_block = true;
    if !fatals.is_empty() {
        emit_block(
            out,
            &mut first_block,
            "FATAL  (blocked / disabled part of the collection)",
            &fatals,
        );
    }
    if !unexpected.is_empty() {
        let items: Vec<Item> = unexpected.iter().map(|g| unexpected_item(g)).collect();
        emit_block(
            out,
            &mut first_block,
            "UNEXPECTED ERRORS  (should investigate)",
            &items,
        );
    }
    if !throttling.is_empty() {
        emit_block(
            out,
            &mut first_block,
            "THROTTLING  (transient — succeeded after retries)",
            &throttling,
        );
    }
    emit_expected_block(out, &mut first_block, &expected, include_expected);
}

// ─── per-section item builders ───────────────────────────────────────────

/// One rendered remediation entry — header, explanation, optional bullet
/// details quoted from `oradaz.log`, then an action arrow.
struct Item {
    severity: Severity,
    /// Headline, e.g. `"graph/users · 403 Forbidden (×2)"` or
    /// `"Exchange disabled — prerequisite failed"`.
    headline: String,
    /// Plain-English explanation (one short paragraph).
    explanation: String,
    /// Optional bullet-point details — typically the last few `ERROR` lines
    /// (and their `DEBUG` follow-up) quoted from `oradaz.log` when the
    /// failure happened in the auth or run-init phase. Each string becomes
    /// one indented bullet line.
    details: Vec<String>,
    /// Suggested action; rendered after a `➜` glyph.
    action: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Severity {
    Fatal,
    Error,
    Warning,
    Info,
}

fn collect_fatals(source: &LogSource, service_filter: Option<&str>) -> Vec<Item> {
    let mut items: Vec<Item> = Vec::new();

    // Compute the log-tail bullets once and attach them to the *first*
    // init/auth fatal we emit — they're the same in either case, so
    // duplicating them on a second fatal would just print the same lines twice.
    let mut log_bullets = if (source.is_broken
        || u64_field(
            source.metadata.as_ref().unwrap_or(&Value::Null),
            "auth_errors",
        ) > 0)
        && service_filter.is_none()
    {
        failure_context_bullets(&source.log_text)
    } else {
        Vec::new()
    };
    // `take()` swaps `log_bullets` with an empty Vec — the first fatal item
    // claims the bullets, subsequent ones get a fresh empty Vec.
    let take_bullets = |bullets: &mut Vec<String>| -> Vec<String> { std::mem::take(bullets) };

    if source.is_broken && service_filter.is_none() {
        items.push(Item {
            severity: Severity::Fatal,
            headline: "Archive interrupted — collection did not complete".to_string(),
            explanation: "Only partial data is in this archive (.broken extension).".to_string(),
            details: take_bullets(&mut log_bullets),
            action: "Review the final entries in `oradaz.log` to find what triggered the abort, \
                     then re-run the collection."
                .to_string(),
        });
    }

    let auth_errors = u64_field(
        source.metadata.as_ref().unwrap_or(&Value::Null),
        "auth_errors",
    );
    if auth_errors > 0 && service_filter.is_none() {
        items.push(Item {
            severity: Severity::Fatal,
            headline: format!("{auth_errors} authentication error(s) during the run"),
            explanation: "One or more services failed to obtain a valid access token.".to_string(),
            details: take_bullets(&mut log_bullets),
            action: "Identify the failing service in the lines above (or `oradaz.log`); check \
                     the app registration credentials, then re-run."
                .to_string(),
        });
    }

    // Per-service prereq-disabled entries.
    let statuses = source
        .metadata
        .as_ref()
        .and_then(|m| m.get("services").and_then(|v| v.as_object()));
    if let Some(map) = statuses {
        let prereqs = source.prerequisites.as_ref();
        let mut svcs: Vec<&String> = map.keys().collect();
        svcs.sort();
        for svc in svcs {
            if let Some(filter) = service_filter
                && svc.to_lowercase() != filter
            {
                continue;
            }
            let status = map.get(svc).and_then(|v| v.as_str()).unwrap_or("");
            if status != "disabled_by_prerequisite_failure" {
                continue;
            }
            let err_code = prereqs
                .and_then(|p| p.get(svc))
                .and_then(|s| s.get("error"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            // `NoAvailableSubscription` is a benign *startup* skip — the identity
            // has no Azure subscription to read — not a mid-run permission
            // failure. Surface it accurately instead of telling the operator to
            // grant a missing permission.
            if err_code == "NoAvailableSubscription" {
                items.push(Item {
                    severity: Severity::Warning,
                    headline: format!(
                        "{} skipped — no Azure subscription available to this identity",
                        pretty_service_name(svc)
                    ),
                    explanation: "NoAvailableSubscription (checked at startup).".to_string(),
                    details: Vec::new(),
                    action: "Normal if the tenant has no Azure subscription. Otherwise assign \
                             the app/user a role (e.g. Reader) on the target subscription(s), \
                             then re-run."
                        .to_string(),
                });
                continue;
            }

            let detail = if err_code.is_empty() {
                "The application lacks a required permission or role.".to_string()
            } else {
                err_code.to_string()
            };
            items.push(Item {
                severity: Severity::Fatal,
                headline: format!(
                    "{} not collected — prerequisite failed",
                    pretty_service_name(svc)
                ),
                explanation: detail,
                details: Vec::new(),
                action: "Grant the missing permission/role to the app registration, then \
                         re-run the collection."
                    .to_string(),
            });
        }
    }

    items
}

fn unexpected_item(g: &crate::inspect::analysis::ErrorGroup) -> Item {
    let count_suffix = if g.count > 1 {
        format!(" (×{})", g.count)
    } else {
        String::new()
    };
    let sep = mid_sep();
    let code = if g.code.is_empty() { "—" } else { &g.code };
    // "service/api", or just "service" when the api name is empty (a per-service
    // non-HTTP event such as MissingTokenForRelationships).
    let target = if g.api.is_empty() {
        g.service.clone()
    } else {
        format!("{}/{}", g.service, g.api)
    };
    let headline = if g.status == 0 {
        // A non-HTTP terminal failure: there is no HTTP status to show. Genuine
        // lost-data abandonments get an explicit "data lost" marker;
        // MissingTokenForRelationships is excluded — its page was already written,
        // only relationship expansion was skipped.
        if g.code == "MissingTokenForRelationships" {
            format!("{target}{sep}{code}{count_suffix}")
        } else {
            format!("{target}{sep}{code} (data lost){count_suffix}")
        }
    } else {
        format!("{target}{sep}{} {code}{count_suffix}", g.status)
    };
    let (explanation, action) = match get_hint(Some(g.status), Some(g.code.as_str())) {
        Some(h) => (h.explanation.to_string(), h.remediation.to_string()),
        None => (
            g.message.clone(),
            "No catalogued remediation for this code; open the corresponding `inspect logs --full` entry."
                .to_string(),
        ),
    };
    Item {
        severity: Severity::Error,
        headline,
        explanation,
        details: Vec::new(),
        action,
    }
}

/// Build throttling items from BOTH the per-API stats (transient pressure)
/// and any 429-classified `DumpError` groups (rate-limit budget exhausted).
/// Deduplicates on `(service, api)` so an API present in both sources is
/// listed once with the stats-derived figures.
fn collect_throttling(
    source: &LogSource,
    groups: &[crate::inspect::analysis::ErrorGroup],
    service_filter: Option<&str>,
) -> Vec<Item> {
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut items: Vec<Item> = Vec::new();

    if let Some(apis) = source
        .stats
        .as_ref()
        .and_then(|s| s.get("apis").and_then(|a| a.as_array()))
    {
        for api in apis {
            let svc = str_field(api, "service").unwrap_or("").to_string();
            let name = str_field(api, "api").unwrap_or("").to_string();
            if svc.is_empty() || name.is_empty() {
                continue;
            }
            if let Some(filter) = service_filter
                && svc != filter
            {
                continue;
            }
            let retries = u64_field(api, "retries_rate_limit");
            let wait = u64_field(api, "rate_limit_wait_secs");
            let requests = u64_field(api, "requests_sent").max(1);
            let noisy = wait > 60 || (retries > 0 && retries * 5 > requests);
            if !noisy {
                continue;
            }
            seen.insert((svc.clone(), name.clone()));
            items.push(throttling_item(&svc, &name, retries, wait));
        }
    }

    for g in groups
        .iter()
        .filter(|g| g.category == ErrorCategory::Throttling)
        .filter(|g| service_filter.is_none_or(|s| g.service == s))
    {
        if seen.insert((g.service.clone(), g.api.clone())) {
            // Pure DumpError 429: budget exhausted, no stats summary available.
            items.push(Item {
                severity: Severity::Warning,
                headline: format!(
                    "{}/{}{sep}429 budget exhausted (×{})",
                    g.service,
                    g.api,
                    g.count,
                    sep = mid_sep()
                ),
                explanation: "The rate-limit retry budget was exhausted for this URL — Microsoft \
                              kept returning HTTP 429 after every retry."
                    .to_string(),
                details: Vec::new(),
                action: "Lower the request rate for this service (`concurrencyMaxWindow`) or \
                         raise `rateLimitMaxWaitSecs` to give the endpoint more time to recover."
                    .to_string(),
            });
        }
    }

    items
}

fn throttling_item(svc: &str, name: &str, retries: u64, wait: u64) -> Item {
    let headline = format!(
        "{svc}/{name}{sep}{retries}× 429 ({} s wait)",
        format_thousands(wait),
        sep = mid_sep()
    );
    Item {
        severity: Severity::Warning,
        headline,
        explanation:
            "Microsoft throttled the requests; oradaz backed off and the calls eventually succeeded."
                .to_string(),
        details: Vec::new(),
        action: format!(
            "If recurring, lower `concurrencyMaxWindow` for `{svc}` via `<serviceOverrides>` so the \
             collection paces itself below the throttling threshold."
        ),
    }
}

fn emit_block(out: &mut Vec<String>, first: &mut bool, title: &str, items: &[Item]) {
    if !*first {
        out.push(String::new());
    }
    *first = false;
    out.push(format!("  {}", dim(title)));
    out.push(format!("  {}", dim(&rule(60))));
    for item in items {
        out.push(format!(
            "  {} {}",
            severity_icon(item.severity),
            item.headline
        ));
        out.push(format!("      {}", item.explanation));
        for bullet in &item.details {
            out.push(format!("      {}", bullet));
        }
        out.push(format!("      {} {}", arrow_glyph(), dim(&item.action)));
    }
}

/// Format the last few ERROR (+ DEBUG follow-up) entries from `oradaz.log`
/// as one bullet per entry, ready to drop into `Item.details`. Returns an
/// empty Vec when no error context is available.
fn failure_context_bullets(log_text: &str) -> Vec<String> {
    let entries = parse_log(log_text);
    last_plain_failure_context(&entries, 3)
        .into_iter()
        .map(|e| {
            let time = e
                .timestamp
                .split(' ')
                .nth(1)
                .unwrap_or(&e.timestamp)
                .to_string();
            let level_marker = match e.level {
                LogLevel::Error => "ERROR",
                LogLevel::Debug => "  debug",
                _ => "      ",
            };
            format!(
                "{} {} {} {}  {}",
                dim(&icon(Icon::Selected)),
                dim(&time),
                dim(level_marker),
                e.module,
                dim(&e.message)
            )
        })
        .collect()
}

fn emit_expected_block(
    out: &mut Vec<String>,
    first: &mut bool,
    expected: &[&crate::inspect::analysis::ErrorGroup],
    include_expected: bool,
) {
    if expected.is_empty() {
        return;
    }
    let title = "EXPECTED ERRORS  (benign — no action)";
    if !*first {
        out.push(String::new());
    }
    *first = false;
    out.push(format!("  {}", dim(title)));
    out.push(format!("  {}", dim(&rule(60))));

    if include_expected {
        // Render each expected group like unexpected, but with a dim icon.
        for g in expected {
            let count_suffix = if g.count > 1 {
                format!(" (×{})", g.count)
            } else {
                String::new()
            };
            out.push(format!(
                "  {} {}/{}{sep}{} {}{count_suffix}",
                severity_icon(Severity::Info),
                g.service,
                g.api,
                g.status,
                if g.code.is_empty() { "—" } else { &g.code },
                sep = mid_sep()
            ));
            out.push(format!(
                "      {}",
                dim("Declared as `expected_error_codes` in the schema — benign.")
            ));
        }
    } else {
        let total: usize = expected.iter().map(|g| g.count).sum();
        let entries_word = if total == 1 { "entry" } else { "entries" };
        out.push(format!(
            "  {total} {entries_word} declared expected by the schema (e.g. 403 on PIM probes for non-role-assignable groups)"
        ));
        out.push(format!(
            "      {} {}",
            arrow_glyph(),
            dim("see them with: oradaz inspect hints --include-expected")
        ));
    }
}

// ─── small glyph helpers ──────────────────────────────────────────────────

fn severity_icon(s: Severity) -> String {
    match s {
        Severity::Fatal | Severity::Error => {
            let g = icon(Icon::Err);
            match mode() {
                UiMode::Color => err_text(&g),
                UiMode::NoColor => g,
            }
        }
        Severity::Warning => {
            let g = icon(Icon::Warn);
            match mode() {
                UiMode::Color => warn_text(&g),
                UiMode::NoColor => g,
            }
        }
        Severity::Info => dim(&icon(Icon::Bullet)),
    }
}

fn arrow_glyph() -> String {
    match mode() {
        UiMode::Color => dim(&icon(Icon::Arrow)),
        UiMode::NoColor => icon(Icon::Arrow),
    }
}

fn pretty_service_name(svc: &str) -> String {
    match svc.to_lowercase().as_str() {
        "graph" => "Graph".to_string(),
        "resources" => "Resources".to_string(),
        "exchange" => "Exchange".to_string(),
        other => other.to_string(),
    }
}
