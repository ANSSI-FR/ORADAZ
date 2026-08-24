//! Pure analytical helpers shared by the `oradaz inspect` subcommands.
//!
//! These functions operate on the JSON values loaded by `loader` and on the
//! `DumpError` records parsed from `errors.json`. They have no I/O and no
//! rendering concerns; rendering lives in `display::*`.

use crate::collect::dump::response::DumpError;

use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

// ─── verdict ──────────────────────────────────────────────────────────────

/// Overall quality verdict for a collection — drives the badge shown in the
/// header of `summary`, `logs`, `hints`, and `compare`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Archive `.broken` — collection was interrupted (Ctrl+C or fatal error).
    Interrupted,
    /// No readable collection metadata — empty/corrupt folder, missing
    /// `metadata.json`, or a plain log file. Distinct from `Complete` so an
    /// empty or unreadable source is never badged as a healthy collection.
    NoData,
    /// `auth_errors > 0` — authentication failed for at least one service.
    AuthFailed,
    /// Data that was meant to be collected is missing: unexpected HTTP errors
    /// or a lost-data abandonment (see [`has_lost_data`]). A service skipped by a
    /// *non-fatal* prerequisite failure is deliberately NOT Partial — the run
    /// completed and the gap is surfaced in COVERAGE / ATTENTION — so the badge
    /// stays consistent with the collector's `COLLECTION COMPLETE`.
    Partial,
    /// No anomaly recorded — proceed with downstream analysis.
    Complete,
}

impl Verdict {
    /// Short uppercase label for header rendering ("COMPLETE", "PARTIAL", …).
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Interrupted => "INTERRUPTED",
            Verdict::NoData => "NO DATA",
            Verdict::AuthFailed => "AUTH FAILED",
            Verdict::Partial => "PARTIAL",
            Verdict::Complete => "COMPLETE",
        }
    }
}

/// Compute the collection-level verdict.
///
/// Inputs are all optional so the function works on partial archives (older
/// collections may lack `stats.json`). Source of each signal:
/// - `is_broken` — file extension `.broken` (set by `loader`).
/// - `auth_errors`, `unexpected_errors` — read from `metadata.json` top-level.
/// - `stats` is a fallback for `unexpected_errors` when the metadata field is
///   absent (older archives) — summed across `apis[]`.
/// - `has_lost_data` — see [`has_lost_data`]: lost-data abandonments carry no
///   HTTP status, so they never reach `unexpected_errors`; without this signal a
///   run the collector badged PARTIAL COLLECTION would be reported `Complete`.
///
/// A service skipped by a non-fatal prerequisite failure (`prerequisites_errors`
/// / a `disabled_by_prerequisite_failure` status) is **not** treated as Partial:
/// the collector deems it a known scope gap and finishes the run as `COLLECTION
/// COMPLETE`. Matching that, the gap is surfaced in COVERAGE / ATTENTION (and
/// `hints`) instead of the verdict, so the badge agrees with the collector.
///
/// The first matching rule wins, in the order listed by the [`Verdict`] enum
/// variants.
pub fn compute_verdict(
    metadata: Option<&Value>,
    stats: Option<&Value>,
    is_broken: bool,
    has_lost_data: bool,
) -> Verdict {
    if is_broken {
        return Verdict::Interrupted;
    }
    // No readable metadata ⇒ there is no collection to vouch for.
    if metadata.is_none() {
        return Verdict::NoData;
    }
    if metadata_u64(metadata, "auth_errors") > 0 {
        return Verdict::AuthFailed;
    }
    let unexpected = metadata
        .and_then(|m| m.get("unexpected_errors").and_then(|v| v.as_u64()))
        .unwrap_or_else(|| stats_total_unexpected(stats));
    if unexpected > 0 || has_lost_data {
        Verdict::Partial
    } else {
        Verdict::Complete
    }
}

/// True when any error means data the user expected is missing from the archive
/// (`DumpError::is_lost_data`): a non-HTTP terminal abandonment such as
/// `ThrottleStalled`, `NetworkStalled`, or `UrlRetryLimit`. These carry no HTTP
/// status, so they never reach `unexpected_errors` in `metadata.json`; the
/// verdict consults the `errors.json` records directly to match the collect-time
/// PARTIAL badge.
pub fn has_lost_data(errors: &[DumpError]) -> bool {
    errors.iter().any(|e| e.is_lost_data())
}

// ─── per-service object inventory ────────────────────────────────────────

/// Per-service object aggregation derived from `metadata.tables[]`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceObjects {
    pub objects: u64,
    pub tables: usize,
}

/// Sum `metadata.tables[].count` grouped by `folder` (= service name).
///
/// Returns an empty map when metadata is missing or `tables` is absent.
/// Entries with empty/missing `folder` are skipped (defensive: very old
/// archives might not have written the field).
pub fn objects_per_service(metadata: Option<&Value>) -> BTreeMap<String, ServiceObjects> {
    let mut out: BTreeMap<String, ServiceObjects> = BTreeMap::new();
    let Some(tables) = metadata
        .and_then(|m| m.get("tables"))
        .and_then(|t| t.as_array())
    else {
        return out;
    };
    for table in tables {
        let folder = table.get("folder").and_then(|v| v.as_str()).unwrap_or("");
        if folder.is_empty() {
            continue;
        }
        let count = table.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        let entry = out.entry(folder.to_string()).or_default();
        entry.objects += count;
        entry.tables += 1;
    }
    out
}

// ─── error aggregation ───────────────────────────────────────────────────

/// Category assigned to each aggregated error group.
///
/// `Ord` is derived so that the natural ordering matches severity ascending
/// (`Expected` < `Throttling` < `Unexpected`). Reverse for severity-desc sort.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ErrorCategory {
    /// `expected==true` (declared benign by the schema).
    Expected,
    /// HTTP 429 — typically rate-limit budget exhaustion.
    Throttling,
    /// Any other HTTP error (`expected==false`, status != 429) — real anomaly.
    Unexpected,
}

/// One aggregated bucket of `DumpError`s sharing
/// `(service, api, status, code, expected)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorGroup {
    pub category: ErrorCategory,
    pub service: String,
    pub api: String,
    pub status: u16,
    pub code: String,
    /// Representative message for the group: the lexicographically smallest among
    /// the bucketed errors. Chosen for determinism — a first-seen message would
    /// depend on the concurrent-write order of `errors.json` (see the selection
    /// logic in `aggregate_errors`).
    pub message: String,
    pub count: usize,
}

/// Group and categorise `DumpError` entries.
///
/// Returns groups sorted by severity (`Unexpected` first), then count
/// descending, then `service`/`api`/`status`/`code` ascending — a total order,
/// so the output is deterministic across runs (groups originate from a
/// `HashMap`, whose iteration order is not).
pub fn aggregate_errors(errors: &[DumpError]) -> Vec<ErrorGroup> {
    type Key = (String, String, u16, String, bool);
    let mut buckets: HashMap<Key, ErrorGroup> = HashMap::new();
    for err in errors {
        let key: Key = (
            err.folder.clone(),
            err.file.clone(),
            err.status,
            err.code.clone(),
            err.expected,
        );
        buckets
            .entry(key)
            .and_modify(|g| {
                g.count += 1;
                // Keep a *deterministic* representative message: the
                // lexicographically smallest among the bucket's errors. The
                // first-seen message would otherwise depend on the
                // concurrent-write order of `errors.json` and vary between runs.
                if err.message < g.message {
                    g.message = err.message.clone();
                }
            })
            .or_insert_with(|| ErrorGroup {
                category: classify(err),
                service: err.folder.clone(),
                api: err.file.clone(),
                status: err.status,
                code: err.code.clone(),
                message: err.message.clone(),
                count: 1,
            });
    }
    let mut out: Vec<ErrorGroup> = buckets.into_values().collect();
    out.sort_by(|a, b| {
        b.category
            .cmp(&a.category)
            .then_with(|| b.count.cmp(&a.count))
            .then_with(|| a.service.cmp(&b.service))
            .then_with(|| a.api.cmp(&b.api))
            .then_with(|| a.status.cmp(&b.status))
            .then_with(|| a.code.cmp(&b.code))
    });
    out
}

// ─── private helpers ─────────────────────────────────────────────────────

fn classify(err: &DumpError) -> ErrorCategory {
    if err.expected {
        ErrorCategory::Expected
    } else if err.status == 429 {
        ErrorCategory::Throttling
    } else {
        ErrorCategory::Unexpected
    }
}

fn metadata_u64(metadata: Option<&Value>, key: &str) -> u64 {
    metadata
        .and_then(|m| m.get(key))
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
}

fn stats_total_unexpected(stats: Option<&Value>) -> u64 {
    stats
        .and_then(|s| s.get("apis"))
        .and_then(|a| a.as_array())
        .map(|apis| {
            apis.iter()
                .map(|api| {
                    api.get("unexpected_errors")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                })
                .sum()
        })
        .unwrap_or(0)
}
