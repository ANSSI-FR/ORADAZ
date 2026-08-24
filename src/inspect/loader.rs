use crate::collect::dump::response::DumpError;
use crate::inspect::mla_reader;

use serde_json::Value;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Parses `errors.json` JSONL (one [`DumpError`] per line), returning the parsed
/// records and the number of **non-empty** lines that failed to parse. A truncated
/// final line — exactly what a killed / `.broken` collection leaves behind — is
/// reported through that count so callers can warn instead of silently dropping
/// the very errors the user is investigating.
pub(crate) fn parse_dump_errors_jsonl(text: &str) -> (Vec<DumpError>, usize) {
    let mut dropped = 0usize;
    let errors = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|line| match serde_json::from_str(line) {
            Ok(e) => Some(e),
            Err(_) => {
                dropped += 1;
                None
            }
        })
        .collect();
    (errors, dropped)
}

/// Whether a subcommand needs the (expensive) `oradaz.log` entry. In an
/// encrypted MLA archive the log is `start_entry`'d first and appended on every
/// API call, so its bytes are fragmented across the whole archive: reading it
/// re-decodes nearly every compression block (orders of magnitude slower than
/// any single contiguous entry). Most subcommands never render it, so they ask
/// for `Never` and skip that cost entirely.
#[derive(Clone, Copy)]
pub enum LogNeed {
    /// Subcommand never reads `log_text` (config/metadata/stats/services/compare).
    Never,
    /// Subcommand always parses the log (logs/timeline).
    Always,
    /// Subcommand quotes the last log lines only on a failed run — read the log
    /// iff the archive is broken or recorded authentication errors
    /// (summary/hints). A strict superset of their display-time condition.
    OnFailure,
}

/// Which of the two expensive entries a subcommand consumes. The four small JSON
/// entries (metadata/config/prerequisites/stats) are always read — they are
/// single-write, contiguous, and cost a few milliseconds each.
#[derive(Clone, Copy)]
pub struct ArchiveNeeds {
    /// Read + parse `errors.json` (`dump_errors`). Needed by everything that
    /// aggregates errors or computes the lost-data verdict.
    pub errors: bool,
    /// Whether/when to read `oradaz.log`.
    pub log: LogNeed,
}

/// Resolve a [`LogNeed`] against what is known once the (cheap) metadata is in
/// hand. `OnFailure` mirrors the summary/hints display gate
/// (`is_broken || auth_errors > 0`) as a superset, so the log is always present
/// when a renderer might quote it.
pub(crate) fn resolve_log_need(need: LogNeed, is_broken: bool, metadata: Option<&Value>) -> bool {
    match need {
        LogNeed::Never => false,
        LogNeed::Always => true,
        LogNeed::OnFailure => {
            is_broken
                || metadata
                    .and_then(|m| m.get("auth_errors"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
                    > 0
        }
    }
}

/// All data extracted from a log source (plain file, folder, or MLA archive).
pub struct LogSource {
    pub log_text: String,
    pub dump_errors: Vec<DumpError>,
    /// Metadata JSON from the archive or folder, if available.
    pub metadata: Option<Value>,
    /// Configuration JSON from the archive or folder, if available.
    pub config: Option<Value>,
    /// Prerequisites JSON from the archive or folder, if available.
    pub prerequisites: Option<Value>,
    /// Stats JSON from the archive or folder, if available (oradaz >= 3.x).
    pub stats: Option<Value>,
    pub is_archive: bool,
    /// True when the source is a `.broken` archive (interrupted collection).
    pub is_broken: bool,
    /// On-disk byte size of the source — the MLA archive file for archive mode,
    /// the recursive sum for folder mode, the file size for a plain log file.
    /// `None` if `std::fs::metadata` failed.
    pub size_bytes: Option<u64>,
}

/// Recursively sum the size of every regular file under `path`. Used by
/// folder-mode loading to surface a "X MiB on disk" figure in `summary`.
/// Errors are swallowed silently — a partial sum is better than no figure.
fn dir_size_bytes(path: &Path) -> u64 {
    let mut total: u64 = 0;
    let Ok(entries) = std::fs::read_dir(path) else {
        return total;
    };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            total = total.saturating_add(dir_size_bytes(&entry.path()));
        } else if file_type.is_file()
            && let Ok(meta) = entry.metadata()
        {
            total = total.saturating_add(meta.len());
        }
    }
    total
}

/// File size of `path` (used for archive and plain-log sources). `None` on
/// metadata error — callers degrade by hiding the size field.
fn file_size_bytes(path: &Path) -> Option<u64> {
    std::fs::metadata(path).ok().map(|m| m.len())
}

fn read_text_file(dir: &Path, name: &str) -> Option<String> {
    let path = dir.join(name);
    let mut f = File::open(&path).ok()?;
    let mut text = String::new();
    f.read_to_string(&mut text).ok()?;
    Some(text)
}

fn read_json_file(dir: &Path, name: &str) -> Option<Value> {
    let text = read_text_file(dir, name)?;
    serde_json::from_str(&text).ok()
}

/// Load log text and associated dump data from a file, folder, or MLA archive.
///
/// `needs` declares which expensive entries the calling subcommand actually
/// renders, so the loader can skip the fragmented `oradaz.log` (and, when
/// unused, `errors.json`) for commands that never touch them. Skipped entries
/// surface as an empty `log_text` / `dump_errors` — identical to the existing
/// "entry absent" fallback — so output is unchanged for any subcommand that
/// does not read them.
pub fn load_log_source(path: &str, key: Option<&str>, needs: &ArchiveNeeds) -> LogSource {
    let p = Path::new(path);

    if p.is_dir() {
        let folder_name = p
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        eprint!("Reading {} ... ", folder_name);
        let metadata = read_json_file(p, "metadata.json");
        let config = read_json_file(p, "config.json");
        let prerequisites = read_json_file(p, "prerequisites.json");
        let stats = read_json_file(p, "stats.json");
        // A `.broken` marker file signals an interrupted/failed folder-mode
        // collection (the `.mla` archive uses the `.broken` extension; a folder
        // has none — see `writer::file::FileWriter::mark_broken`).
        let is_broken = p.join(".broken").exists();
        // Honour `needs` even in folder mode (reads are cheap here) so the
        // `LogSource` carries the same fields populated as archive mode.
        let log_text = if resolve_log_need(needs.log, is_broken, metadata.as_ref()) {
            read_text_file(p, "oradaz.log").unwrap_or_default()
        } else {
            String::new()
        };
        // `errors.json` is written to the folder root by `FileWriter::write_file`
        // when `outputFiles=true`; parse it as JSONL (one DumpError per line),
        // tolerating blank lines and malformed entries. Without this, `inspect
        // logs --full --folder` would silently render no response bodies even
        // when the data is on disk.
        let (dump_errors, dropped_error_lines) = if needs.errors {
            parse_dump_errors_jsonl(&read_text_file(p, "errors.json").unwrap_or_default())
        } else {
            (Vec::new(), 0)
        };
        let size_bytes = Some(dir_size_bytes(p));
        eprintln!("done");
        if dropped_error_lines > 0 {
            eprintln!(
                "  warning: {dropped_error_lines} unparseable line(s) in errors.json were skipped (truncated or interrupted collection?)"
            );
        }
        return LogSource {
            log_text,
            dump_errors,
            metadata,
            config,
            prerequisites,
            stats,
            is_archive: false,
            is_broken,
            size_bytes,
        };
    }

    let ext = p.extension().and_then(|e| e.to_str());
    // `.tmp` is an in-progress or crashed archive — treat it as broken so
    // `inspect summary` never returns COMPLETE/PARTIAL for an incomplete file.
    let is_broken = matches!(ext, Some("broken") | Some("tmp"));
    let is_archive = matches!(ext, Some("mla") | Some("broken") | Some("tmp"));

    let filename = p
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();

    if is_archive {
        let key_path = match key {
            Some(k) => k,
            None => {
                eprintln!("--key <KEY_FILE> is required when inspecting an MLA archive");
                std::process::exit(1);
            }
        };
        eprintln!("Reading {} ... (decrypting)", filename);
        match mla_reader::read_archive(path, key_path, needs, is_broken) {
            Ok(c) => LogSource {
                log_text: c.log,
                dump_errors: c.errors,
                metadata: c.metadata,
                config: c.config,
                prerequisites: c.prerequisites,
                stats: c.stats,
                is_archive: true,
                is_broken,
                size_bytes: file_size_bytes(p),
            },
            Err(e) => {
                eprintln!("Failed to read archive: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        eprint!("Reading {} ... ", filename);
        let mut f = match File::open(p) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Failed to open {}: {}", path, e);
                std::process::exit(1);
            }
        };
        let mut text = String::new();
        if let Err(e) = f.read_to_string(&mut text) {
            eprintln!("Failed to read {}: {}", path, e);
            std::process::exit(1);
        }
        eprintln!("done");
        // Try to load errors.json from the same directory as the plain log file
        // so that `inspect logs --full` can display response bodies.
        let (dump_errors, dropped_error_lines) = p
            .parent()
            .and_then(|dir| std::fs::read_to_string(dir.join("errors.json")).ok())
            .map(|text| parse_dump_errors_jsonl(&text))
            .unwrap_or_default();
        if dropped_error_lines > 0 {
            eprintln!(
                "  warning: {dropped_error_lines} unparseable line(s) in errors.json were skipped (truncated or interrupted collection?)"
            );
        }
        LogSource {
            log_text: text,
            dump_errors,
            metadata: None,
            config: None,
            prerequisites: None,
            stats: None,
            is_archive: false,
            is_broken: false,
            size_bytes: file_size_bytes(p),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{LogNeed, parse_dump_errors_jsonl, resolve_log_need};

    use serde_json::json;

    #[test]
    fn resolve_log_need_truth_table() {
        let healthy = json!({"auth_errors": 0});
        let with_auth = json!({"auth_errors": 2});

        // Never / Always ignore the run state entirely.
        assert!(!resolve_log_need(LogNeed::Never, true, Some(&with_auth)));
        assert!(resolve_log_need(LogNeed::Always, false, Some(&healthy)));

        // OnFailure: read only when broken or auth_errors > 0.
        assert!(!resolve_log_need(LogNeed::OnFailure, false, Some(&healthy)));
        assert!(resolve_log_need(LogNeed::OnFailure, true, Some(&healthy)));
        assert!(resolve_log_need(
            LogNeed::OnFailure,
            false,
            Some(&with_auth)
        ));
        // Missing metadata → treated as zero auth_errors (only `is_broken` counts).
        assert!(!resolve_log_need(LogNeed::OnFailure, false, None));
        assert!(resolve_log_need(LogNeed::OnFailure, true, None));
    }

    #[test]
    fn parses_valid_lines_and_counts_unparseable_ones() {
        // A valid record, blank/whitespace lines (ignored, not counted), and a
        // truncated final line — exactly what a killed/`.broken` collection leaves.
        let text = concat!(
            r#"{"folder":"resources","file":"x","url":"u","status":404,"code":"c","message":"m"}"#,
            "\n\n   \n",
            r#"{ truncated json"#,
        );
        let (parsed, dropped) = parse_dump_errors_jsonl(text);
        assert_eq!(parsed.len(), 1, "one valid record parsed");
        assert_eq!(
            dropped, 1,
            "one malformed (non-empty) line counted as dropped"
        );
    }

    #[test]
    fn empty_input_yields_no_records_and_no_drops() {
        let (parsed, dropped) = parse_dump_errors_jsonl("");
        assert!(parsed.is_empty());
        assert_eq!(dropped, 0);
    }
}
