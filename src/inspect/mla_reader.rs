/// Module for reading and decrypting ORADAZ MLA archives.
///
/// This module handles the extraction of logs, error reports, metadata, and
/// configuration from an encrypted MLA archive using a provided private key.
use crate::collect::dump::response::DumpError;
use crate::inspect::loader::{ArchiveNeeds, resolve_log_need};
use crate::utils::errors::Error;

use mla::ArchiveReader;
use mla::config::ArchiveReaderConfig;
use mla::crypto::mlakey::*;
use mla::entry::EntryName;
use serde_json::Value;
use std::fs::File;
use std::io::Read;

/// Contents extracted from an MLA archive.
pub struct ArchiveContents {
    pub log: String,
    pub errors: Vec<DumpError>,
    pub metadata: Option<Value>,
    pub config: Option<Value>,
    pub prerequisites: Option<Value>,
    pub stats: Option<Value>,
}

/// Reads an MLA archive from the filesystem and decrypts its contents.
///
/// It expects a private key in OpenSSL 25519 format to initialize the `ArchiveReader`.
/// Always extracts the four small JSON entries (`metadata.json`, `config.json`,
/// `prerequisites.json`, `stats.json`). `errors.json` and `oradaz.log` are read
/// only when `needs` asks for them: the log is fragmented across the whole
/// archive (see [`ArchiveNeeds`]), so skipping it when a subcommand never renders
/// it avoids re-decoding nearly every compression block. `is_broken` feeds the
/// `OnFailure` log decision (see [`resolve_log_need`]).
pub fn read_archive(
    path: &str,
    key_path: &str,
    needs: &ArchiveNeeds,
    is_broken: bool,
) -> Result<ArchiveContents, Error> {
    let key_bytes = std::fs::read(key_path)
        .map_err(|e| Error::StringError(format!("Cannot read key file '{}': {}", key_path, e)))?;

    let private_key = match MLAPrivateKey::deserialize_private_key(key_bytes.as_slice()) {
        Ok(p) => {
            let (priv_dec_key, _priv_sig_key) = p.get_private_keys();
            priv_dec_key
        }
        Err(_) => {
            return Err(Error::StringError(
                "Could not deserialize private key".to_string(),
            ));
        }
    };

    let file = File::open(path)
        .map_err(|e| Error::StringError(format!("Cannot open archive '{}': {}", path, e)))?;

    let config =
        ArchiveReaderConfig::without_signature_verification().with_encryption(&[private_key]);

    let (mut reader, _signatures) =
        ArchiveReader::from_config(file, config).map_err(Error::MLAError)?;

    // Shared helper for reading one archive entry into a `String`
    // (`None` if the entry is absent). Handles the `EntryName::from_path`
    // + `get_entry` + read sequence identically for each of the six entries.
    // Entry names are hard-coded ASCII so `from_path` cannot fail in practice,
    // but the error is propagated rather than duplicated inline. Invalid UTF-8
    // is decoded leniently with a *visible* warning (corrupt archive / wrong
    // key degrades loudly, not silently).
    let mut read_entry = |name: &str| -> Result<Option<String>, Error> {
        let entry = EntryName::from_path(name).map_err(|_| {
            Error::StringError(format!("Could not create '{name}' entry for MLA archive"))
        })?;
        match reader.get_entry(entry).map_err(Error::MLAError)? {
            None => Ok(None),
            Some(mut f) => {
                let mut bytes = Vec::new();
                f.data
                    .read_to_end(&mut bytes)
                    .map_err(|e| Error::StringError(format!("Read error for {name}: {e}")))?;
                let text = match String::from_utf8(bytes) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!(
                            "  warning: '{name}' contains invalid UTF-8 (corrupt archive or wrong key?); decoding leniently"
                        );
                        String::from_utf8_lossy(&e.into_bytes()).into_owned()
                    }
                };
                Ok(Some(text))
            }
        }
    };

    // Read the small (contiguous, cheap) entries first plus `errors.json` when
    // requested; the fragmented `oradaz.log` is read last and only when needed.
    // Random access makes the read *order* free — the speed-up comes from
    // skipping the log entirely when unused, not from reading it last.
    let errors_text = if needs.errors {
        read_entry("errors.json")?.unwrap_or_default()
    } else {
        String::new()
    };
    let metadata_text = read_entry("metadata.json")?;
    let config_text = read_entry("config.json")?;
    let prerequisites_text = read_entry("prerequisites.json")?;
    let stats_text = read_entry("stats.json")?;

    let (errors, dropped_error_lines) =
        crate::inspect::loader::parse_dump_errors_jsonl(&errors_text);
    if dropped_error_lines > 0 {
        eprintln!(
            "  warning: {dropped_error_lines} unparseable line(s) in errors.json were skipped (truncated or interrupted collection?)"
        );
    }

    let metadata = metadata_text
        .as_deref()
        .and_then(|t| serde_json::from_str(t).ok());
    let config_val = config_text
        .as_deref()
        .and_then(|t| serde_json::from_str(t).ok());
    let prerequisites_val = prerequisites_text
        .as_deref()
        .and_then(|t| serde_json::from_str(t).ok());
    let stats_val = stats_text
        .as_deref()
        .and_then(|t| serde_json::from_str(t).ok());

    // The log decision uses the metadata just parsed (for `auth_errors`).
    let log = if resolve_log_need(needs.log, is_broken, metadata.as_ref()) {
        read_entry("oradaz.log")?.unwrap_or_default()
    } else {
        String::new()
    };

    Ok(ArchiveContents {
        log,
        errors,
        metadata,
        config: config_val,
        prerequisites: prerequisites_val,
        stats: stats_val,
    })
}
