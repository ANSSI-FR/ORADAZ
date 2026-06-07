// `inspect` is a read-only post-collection analysis tool: it never creates or renames
// an archive, so a panic here cannot leave a dangling `.mla.tmp`. It is therefore out
// of scope for the no-panic collection gate denied crate-wide in `lib.rs`; opt the whole
// subtree back out rather than churn its existing `unwrap`/`expect` rendering helpers.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod analysis;
pub mod display;
pub mod hints;
pub mod loader;
pub mod log_parser;
pub mod mla_reader;

pub use crate::inspect::log_parser::{LogEntry, LogFilters, LogLevel};

use crate::inspect::display::{
    TimelineOptions, print_all_api_errors, print_compare_section, print_config_section,
    print_logs_details, print_metadata_section, print_overview, print_remediation_section,
    print_services_section, print_stats_section, print_summary, print_timeline,
    print_timeline_view, strip_ansi_codes,
};
use crate::inspect::loader::load_log_source;
use crate::utils::logger;
use crate::utils::ui;
use crate::utils::ui::{Icon, err_text, icon};

use std::fs;

fn inspect_error(msg: &str) -> ! {
    // `err_text` is a no-op in NoColor mode, and `icon(Icon::Err)` already
    // returns the mode-appropriate glyph ("✖" / "!!"). One expression handles
    // both modes consistently.
    let prefix = err_text(&icon(Icon::Err));
    eprintln!("  {} Error: {}", prefix, msg);
    std::process::exit(1);
}

/// Validate a `--service <svc>` CLI value (case-insensitive). Aborts via
/// `inspect_error` on an unknown service; returns the lower-cased value on
/// success. Used by all per-collection commands that accept `--service`.
fn validate_service_filter(value: Option<&str>) -> Option<String> {
    let svc = value?;
    let lower = svc.to_lowercase();
    if !["graph", "resources", "exchange"].contains(&lower.as_str()) {
        inspect_error(
            "invalid value for option --service (expected graph, resources, or exchange)",
        );
    }
    Some(lower)
}

/// Parse a `--bucket` value (`"1s"`, `"10s"`, `"60s"`, `"1m"`) to seconds.
/// Aborts via `inspect_error` on an unsupported value.
fn validate_bucket(value: Option<&str>) -> Option<i64> {
    let v = value?;
    match v {
        "1s" => Some(1),
        "10s" => Some(10),
        "60s" | "1m" => Some(60),
        other => inspect_error(&format!(
            "invalid value for option --bucket '{other}' (expected 1s, 10s, 60s, or 1m)"
        )),
    }
}

/// Validate --mla / --folder / --key combinations. Returns the resolved source path.
fn resolve_source(
    mla: Option<String>,
    folder: Option<String>,
    key: Option<&str>,
) -> (String, Option<String>) {
    match (mla, folder) {
        (None, None) => inspect_error("option --folder or --mla must be used"),
        (Some(m), None) => {
            if key.is_none() {
                inspect_error("option --mla requires a private key (--key)");
            }
            (m, None)
        }
        (None, Some(f)) => (f, None),
        (Some(_), Some(_)) => inspect_error("use either --mla or --folder, not both"),
    }
}

/// Transliterate the width-preserving decorative Unicode glyphs the display
/// layer can emit into ASCII, so `--no-color` output stays 7-bit clean when
/// piped/redirected. Only the 1-cell→1-cell set is mapped here, so table
/// alignment is preserved even when a glyph sits inside a `render_table`
/// measured cell; the width-changing glyphs (`…`, `Δ`) are handled at the
/// source via `display::ellipsis()` / `display::delta_header()`. No-op in Color
/// mode; data values are left intact apart from these rare decorative glyphs.
fn ascii_decorative(line: &str) -> String {
    if matches!(ui::mode(), ui::UiMode::Color) {
        return line.to_string();
    }
    line.replace('\u{00d7}', "x") // × multiplication sign ("73× 429" → "73x 429")
        // em dash / en dash / minus sign → ASCII hyphen
        .replace(['\u{2014}', '\u{2013}', '\u{2212}'], "-")
}

fn write_report(path: &str, lines: &[String]) {
    let content: String = lines
        .iter()
        .map(|l| ascii_decorative(&strip_ansi_codes(l)))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    if let Err(e) = fs::write(path, &content) {
        eprintln!("Warning: could not write report to {}: {}", path, e);
    }
}

/// CLI inputs for `oradaz compare <A> <B>`. Sources A and B are
/// positional paths auto-detected (folder vs `.mla`/`.broken`) by the loader.
pub struct CompareCliOptions {
    pub source_a: String,
    pub source_b: String,
    /// Private key used to decrypt A (and B when `key_b` is `None`).
    pub key: Option<String>,
    /// Override key for B — only required when A and B don't share a key.
    pub key_b: Option<String>,
    pub report: Option<String>,
    pub no_color: bool,
}

/// Two-collection diff: header + quality deltas + coverage deltas + top
/// table movers + config changes. Auto-detects archive vs folder for each
/// source.
pub fn run_compare(opts: CompareCliOptions) {
    ui::init(opts.no_color);
    logger::set_no_color(matches!(ui::mode(), ui::UiMode::NoColor));

    // Resolve keys: B falls back to A's key if `key_b` not provided. An MLA
    // source without a key is a hard error.
    let key_for_b = opts.key_b.clone().or_else(|| opts.key.clone());
    if needs_key(&opts.source_a) && opts.key.is_none() {
        inspect_error(&format!(
            "source A '{}' looks like an MLA archive — provide --key",
            opts.source_a
        ));
    }
    if needs_key(&opts.source_b) && key_for_b.is_none() {
        inspect_error(&format!(
            "source B '{}' looks like an MLA archive — provide --key or --key-b",
            opts.source_b
        ));
    }

    let source_a = load_log_source(&opts.source_a, opts.key.as_deref());
    let source_b = load_log_source(&opts.source_b, key_for_b.as_deref());

    let mut lines: Vec<String> = vec![String::new()];
    print_compare_section(&source_a, &source_b, &mut lines);

    for line in &lines {
        println!("{}", ascii_decorative(line));
    }
    if let Some(ref report_path) = opts.report {
        write_report(report_path, &lines);
    }
}

/// Does this path look like an MLA archive (vs a folder)? Used by
/// `run_compare` to decide whether a key is required.
fn needs_key(path: &str) -> bool {
    let p = std::path::Path::new(path);
    if p.is_dir() {
        return false;
    }
    matches!(
        p.extension().and_then(|e| e.to_str()),
        Some("mla") | Some("broken") | Some("tmp")
    )
}

/// Categorised remediation digest: FATAL / UNEXPECTED / THROTTLING /
/// EXPECTED. Each item carries a short explanation + suggested action,
/// pulling from the `hints.rs` catalogue where available.
pub fn run_hints(
    mla: Option<String>,
    folder: Option<String>,
    key: Option<String>,
    report: Option<String>,
    service: Option<String>,
    include_expected: bool,
    no_color: bool,
) {
    ui::init(no_color);
    logger::set_no_color(matches!(ui::mode(), ui::UiMode::NoColor));
    let (path, _) = resolve_source(mla, folder, key.as_deref());
    let service_filter = validate_service_filter(service.as_deref());
    let source = load_log_source(&path, key.as_deref());

    let mut lines: Vec<String> = vec![String::new()];
    print_remediation_section(
        &source,
        service_filter.as_deref(),
        include_expected,
        &mut lines,
    );

    for line in &lines {
        println!("{}", ascii_decorative(line));
    }
    if let Some(ref report_path) = report {
        write_report(report_path, &lines);
    }
}

/// CLI inputs for `oradaz inspect timeline`. The raw `bucket: Option<String>`
/// is parsed to seconds by `validate_bucket` before being passed to the
/// renderer's [`TimelineOptions`].
pub struct TimelineCliOptions {
    pub mla: Option<String>,
    pub folder: Option<String>,
    pub key: Option<String>,
    pub report: Option<String>,
    pub service: Option<String>,
    pub only_429: bool,
    pub problematic_only: bool,
    pub bucket: Option<String>,
    pub no_color: bool,
}

/// Temporal analysis: error/429 chart, per-API activity windows, and
/// problematic-APIs with their time range. The chart is the same one
/// `logs --timeline` exposes as an alias.
pub fn run_timeline(opts: TimelineCliOptions) {
    ui::init(opts.no_color);
    logger::set_no_color(matches!(ui::mode(), ui::UiMode::NoColor));
    let (path, _) = resolve_source(opts.mla, opts.folder, opts.key.as_deref());
    let service_filter = validate_service_filter(opts.service.as_deref());
    let bucket_secs = validate_bucket(opts.bucket.as_deref());

    let source = load_log_source(&path, opts.key.as_deref());

    // Same per-API filtering as run_logs (service only here — the timeline
    // command intentionally doesn't expose --api/--http/--since/--last).
    let mut entries: Vec<LogEntry> = log_parser::parse_log(&source.log_text)
        .into_iter()
        .filter(|e| e.service.is_some())
        .collect();
    if let Some(ref svc) = service_filter {
        entries.retain(|e| {
            e.service
                .as_deref()
                .map(|s| s.eq_ignore_ascii_case(svc))
                .unwrap_or(false)
        });
    }

    let render_opts = TimelineOptions {
        service: service_filter,
        only_429: opts.only_429,
        problematic_only: opts.problematic_only,
        bucket: bucket_secs,
    };
    let mut lines: Vec<String> = vec![String::new()];
    print_timeline_view(&source, &entries, &render_opts, &mut lines);

    for line in &lines {
        println!("{}", ascii_decorative(line));
    }
    if let Some(ref report_path) = opts.report {
        write_report(report_path, &lines);
    }
}

/// Renders a one-screen collection-health digest — the recommended entry
/// point right after a collection. Verdict in header, per-service coverage,
/// HEALTH counters, ATTENTION callouts with next-step pointers.
pub fn run_summary(
    mla: Option<String>,
    folder: Option<String>,
    key: Option<String>,
    report: Option<String>,
    no_color: bool,
) {
    ui::init(no_color);
    logger::set_no_color(matches!(ui::mode(), ui::UiMode::NoColor));
    let (path, _) = resolve_source(mla, folder, key.as_deref());
    let source = load_log_source(&path, key.as_deref());

    let mut lines: Vec<String> = vec![String::new()];
    print_overview(&source, &mut lines);

    for line in &lines {
        println!("{}", ascii_decorative(line));
    }

    if let Some(ref report_path) = report {
        write_report(report_path, &lines);
    }
}

/// Processes and displays logs from a given source (archive or folder).
///
/// Three orthogonal axes (verbosity, full-detail, filters/limits) each map
/// to a flag on [`LogFilters`]. `--warnings`/`--info`/`--debug` work in both
/// the grouped table and the entry-detail renderer.
pub fn run_logs(
    path: Option<String>,
    mla: Option<String>,
    folder: Option<String>,
    key: Option<String>,
    report: Option<String>,
    filters: LogFilters,
    no_color: bool,
) {
    ui::init(no_color);
    logger::set_no_color(matches!(ui::mode(), ui::UiMode::NoColor));
    // A positional PATH (archive, folder, or raw oradaz.log) is an alternative to
    // --mla/--folder; `load_log_source` auto-detects which it is. Falls back to the
    // flag-based resolution when no positional is given.
    let path = match (path, mla, folder) {
        (Some(p), None, None) => p,
        (Some(_), _, _) => inspect_error("pass a PATH or --mla/--folder, not both"),
        (None, m, f) => resolve_source(m, f, key.as_deref()).0,
    };

    // Validate inputs upfront, before reading the archive.
    let service_filter = validate_service_filter(filters.service.as_deref());
    let http_matcher = match filters.http.as_deref().map(log_parser::parse_http_filter) {
        Some(Ok(m)) => Some(m),
        Some(Err(msg)) => inspect_error(&msg),
        None => None,
    };
    let since_matcher = match filters.since.as_deref().map(log_parser::parse_since) {
        Some(Ok(m)) => Some(m),
        Some(Err(msg)) => inspect_error(&msg),
        None => None,
    };

    let source = load_log_source(&path, key.as_deref());

    // Parse + sequentially filter entries.
    let mut entries: Vec<LogEntry> = log_parser::parse_log(&source.log_text)
        .into_iter()
        .filter(|e| e.service.is_some())
        .collect();

    if let Some(ref svc) = service_filter {
        entries.retain(|e| {
            e.service
                .as_deref()
                .map(|s| s.eq_ignore_ascii_case(svc))
                .unwrap_or(false)
        });
    }
    if let Some(ref api_substr) = filters.api {
        let needle = api_substr.to_lowercase();
        entries.retain(|e| {
            e.api
                .as_deref()
                .is_some_and(|a| a.to_lowercase().contains(&needle))
        });
    }
    if let Some(ref m) = http_matcher {
        entries.retain(|e| e.http_status.is_some_and(|s| m.matches(s)));
    }
    if let Some(ref m) = since_matcher {
        entries.retain(|e| m.matches(&e.timestamp));
    }
    if !filters.include_expected {
        // By default hide entries whose matching `DumpError` is declared as
        // expected in the schema (e.g. 403 on PIM probes for non-role-
        // assignable groups). Entries remain in errors.json with
        // `expected: true`; opt-in with --include-expected.
        // Build the index once to avoid an O(N×M) scan per entry.
        let dump_error_index = log_parser::build_dump_error_index(&source.dump_errors);
        entries.retain(
            |e| match log_parser::find_dump_error_in_index(&dump_error_index, e) {
                Some(de) => !de.expected,
                None => true,
            },
        );
    }
    if let Some(n) = filters.last {
        // Sort desc → take N → restore chronological order for downstream.
        entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        entries.truncate(n);
        entries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    }

    let mut out: Vec<String> = vec![String::new()];

    // COLLECTION SUMMARY + LOGS SUMMARY (per-service counts table).
    print_summary(
        &entries,
        source.metadata.as_ref(),
        source.config.as_ref(),
        source.is_broken,
        &mut out,
    );

    if filters.summary_only {
        out.push(String::new());
        out.push(format!(
            "  {}",
            crate::utils::ui::dim("(details suppressed — drop --summary-only to see them)")
        ));
    } else if filters.full {
        print_all_api_errors(&entries, &mut out, &source, &filters);
    } else {
        print_logs_details(&entries, &mut out, &filters);
    }

    // Timeline alias — same chart as `oradaz inspect timeline`.
    if filters.timeline || filters.timeline_429 {
        out.push(String::new());
        print_timeline(&entries, filters.timeline_429, None, &mut out);
    }

    for line in &out {
        println!("{}", ascii_decorative(line));
    }
    if let Some(ref report_path) = report {
        write_report(report_path, &out);
    }
}

/// Extracts and displays the status of services from an archive or folder.
pub fn run_services(
    mla: Option<String>,
    folder: Option<String>,
    key: Option<String>,
    report: Option<String>,
    service: Option<String>,
    no_color: bool,
) {
    ui::init(no_color);
    // Propagate colour setting to the logger (affects file logs)
    logger::set_no_color(matches!(ui::mode(), ui::UiMode::NoColor));
    let (path, _) = resolve_source(mla, folder, key.as_deref());
    let service_filter = validate_service_filter(service.as_deref());
    let source = load_log_source(&path, key.as_deref());

    let mut lines: Vec<String> = vec![String::new()];
    print_services_section(
        source.metadata.as_ref(),
        source.config.as_ref(),
        source.prerequisites.as_ref(),
        source.stats.as_ref(),
        &source.dump_errors,
        service_filter.as_deref(),
        &mut lines,
    );

    for line in &lines {
        println!("{}", ascii_decorative(line));
    }

    if let Some(ref report_path) = report {
        write_report(report_path, &lines);
    }
}

/// Extracts and displays the configuration used for a dump from an archive or folder.
pub fn run_config(
    mla: Option<String>,
    folder: Option<String>,
    key: Option<String>,
    report: Option<String>,
    all: bool,
    no_color: bool,
) {
    ui::init(no_color);
    // Propagate colour setting to the logger (affects file logs)
    logger::set_no_color(matches!(ui::mode(), ui::UiMode::NoColor));
    let (path, _) = resolve_source(mla, folder, key.as_deref());
    let source = load_log_source(&path, key.as_deref());

    let mut lines: Vec<String> = vec![String::new()];
    print_config_section(
        source.metadata.as_ref(),
        source.config.as_ref(),
        all,
        &mut lines,
    );

    for line in &lines {
        println!("{}", ascii_decorative(line));
    }

    if let Some(ref report_path) = report {
        write_report(report_path, &lines);
    }
}

/// Extracts and displays the metadata associated with a dump from an archive or folder.
pub fn run_metadata(
    mla: Option<String>,
    folder: Option<String>,
    key: Option<String>,
    report: Option<String>,
    top: usize,
    all: bool,
    no_color: bool,
) {
    ui::init(no_color);
    // Propagate colour setting to the logger (affects file logs)
    logger::set_no_color(matches!(ui::mode(), ui::UiMode::NoColor));
    let (path, _) = resolve_source(mla, folder, key.as_deref());
    let source = load_log_source(&path, key.as_deref());

    let mut lines: Vec<String> = vec![String::new()];
    print_metadata_section(
        source.metadata.as_ref(),
        source.config.as_ref(),
        top,
        all,
        &mut lines,
    );

    for line in &lines {
        println!("{}", ascii_decorative(line));
    }

    if let Some(ref report_path) = report {
        write_report(report_path, &lines);
    }
}

/// CLI inputs for `oradaz inspect stats`.
pub struct StatsCliOptions {
    pub mla: Option<String>,
    pub folder: Option<String>,
    pub key: Option<String>,
    pub report: Option<String>,
    pub top: usize,
    pub all: bool,
    pub service: Option<String>,
    pub no_color: bool,
}

/// Extracts and displays per-API collection statistics from an archive or folder.
pub fn run_stats(opts: StatsCliOptions) {
    ui::init(opts.no_color);
    // Propagate colour setting to the logger (affects file logs)
    logger::set_no_color(matches!(ui::mode(), ui::UiMode::NoColor));
    let (path, _) = resolve_source(opts.mla, opts.folder, opts.key.as_deref());
    let service_filter = validate_service_filter(opts.service.as_deref());
    let source = load_log_source(&path, opts.key.as_deref());

    let mut lines: Vec<String> = vec![String::new()];
    print_stats_section(
        source.metadata.as_ref(),
        source.config.as_ref(),
        source.stats.as_ref(),
        opts.top,
        opts.all,
        service_filter.as_deref(),
        &mut lines,
    );

    for line in &lines {
        println!("{}", ascii_decorative(line));
    }

    if let Some(ref report_path) = opts.report {
        write_report(report_path, &lines);
    }
}
