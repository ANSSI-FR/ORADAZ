//! Selective archive-entry loading: an `inspect` subcommand reads the expensive
//! `oradaz.log` / `errors.json` entries only when it renders them. These tests
//! build a real encrypted MLA archive (multi-recipient: the embedded default key
//! plus a seed-derived test key we own the private half of) and verify that
//! `read_archive` honours [`ArchiveNeeds`] — skipping the fragmented log when the
//! command never displays it. A folder-mode check covers the parallel branch.

mod common;

use common::default_test_config;

use oradaz::inspect::loader::{ArchiveNeeds, LogNeed, load_log_source};
use oradaz::inspect::mla_reader::read_archive;
use oradaz::utils::config::AdditionalMlaKeys;
use oradaz::utils::writer::MlaWriter;
use oradaz::utils::writer::mla::load_mla_public_keys;

use mla::crypto::mlakey::generate_mla_keypair_from_seed;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

const LOG_LINE: &str = "2026-05-28 16:59:52  |  ERROR  | Auth                     boom\n";
const META_HEALTHY: &str = r#"{"tenant":"t","auth_errors":0}"#;
const META_AUTH_ERR: &str = r#"{"tenant":"t","auth_errors":2}"#;
const ERR_LINE: &str = r#"{"folder":"graph","file":"users","url":"https://example/u","status":403,"code":"Forbidden","message":"denied","expected":false}"#;

/// Build an encrypted archive at `<dir>/archive.mla.tmp` containing `oradaz.log`,
/// `metadata.json`, and `errors.json`, plus a private-key file the test can
/// decrypt it with. Returns `(archive_path, key_path)`.
fn build_archive(dir: &Path, metadata: &str) -> (String, String) {
    // Seed-derived keypair: the public half is added as an extra MLA recipient,
    // so the archive (also encrypted to the embedded default key) is decryptable
    // with the private half we keep.
    let (private_key, public_key) = generate_mla_keypair_from_seed([7u8; 32]);
    let mut pub_buf = Vec::new();
    public_key
        .serialize_public_key(&mut pub_buf)
        .expect("serialize public key");
    let mut priv_buf = Vec::new();
    private_key
        .serialize_private_key(&mut priv_buf)
        .expect("serialize private key");

    let mut config = default_test_config();
    config.additional_mla_keys = Some(AdditionalMlaKeys {
        key_files: None,
        keys: Some(vec![String::from_utf8(pub_buf).expect("utf-8 public key")]),
    });
    let keys = load_mla_public_keys(&config).expect("load public keys");

    let mut writer = MlaWriter::new(dir, &"archive".to_string(), &keys).expect("MlaWriter::new");
    writer.write_log(&LOG_LINE.to_string()).expect("write log");
    writer
        .write_file("metadata.json", metadata.to_string())
        .expect("write metadata");
    writer
        .write_file("errors.json", format!("{ERR_LINE}\n"))
        .expect("write errors");
    let archive_path = writer.mla_path.clone();
    writer.close().expect("finalize archive");

    let key_path = dir.join("test.mlapriv");
    fs::write(&key_path, &priv_buf).expect("write private key");
    (
        archive_path,
        key_path.to_str().expect("utf-8 key path").to_string(),
    )
}

#[test]
fn read_archive_never_skips_log_and_errors() {
    // config/metadata/stats path: neither expensive entry is read even though
    // both exist in the archive — but the small JSON is still present.
    let dir = tempdir().expect("tempdir");
    let (archive, key) = build_archive(dir.path(), META_HEALTHY);
    let c = read_archive(
        &archive,
        &key,
        &ArchiveNeeds {
            errors: false,
            log: LogNeed::Never,
        },
        false,
    )
    .expect("read_archive");
    assert!(c.log.is_empty(), "log must be skipped under LogNeed::Never");
    assert!(
        c.errors.is_empty(),
        "errors must be skipped when errors=false"
    );
    assert!(c.metadata.is_some(), "small JSON entries are always read");
}

#[test]
fn read_archive_always_reads_log_and_errors() {
    // logs/timeline path: both entries present and parsed.
    let dir = tempdir().expect("tempdir");
    let (archive, key) = build_archive(dir.path(), META_HEALTHY);
    let c = read_archive(
        &archive,
        &key,
        &ArchiveNeeds {
            errors: true,
            log: LogNeed::Always,
        },
        false,
    )
    .expect("read_archive");
    assert!(
        c.log.contains("boom"),
        "log must be read under LogNeed::Always"
    );
    assert_eq!(
        c.errors.len(),
        1,
        "errors.json must be parsed when errors=true"
    );
}

#[test]
fn read_archive_on_failure_skips_log_for_healthy_run() {
    // summary/hints on a healthy archive (auth_errors=0, not broken): the log is
    // skipped — and errors are still available for the verdict/aggregation.
    let dir = tempdir().expect("tempdir");
    let (archive, key) = build_archive(dir.path(), META_HEALTHY);
    let c = read_archive(
        &archive,
        &key,
        &ArchiveNeeds {
            errors: true,
            log: LogNeed::OnFailure,
        },
        false,
    )
    .expect("read_archive");
    assert!(
        c.log.is_empty(),
        "OnFailure must skip the log on a healthy, non-broken archive"
    );
    assert_eq!(c.errors.len(), 1, "errors are still read under OnFailure");
}

#[test]
fn read_archive_on_failure_reads_log_when_broken() {
    // The `.broken` signal flips OnFailure to read the log (failure context).
    let dir = tempdir().expect("tempdir");
    let (archive, key) = build_archive(dir.path(), META_HEALTHY);
    let c = read_archive(
        &archive,
        &key,
        &ArchiveNeeds {
            errors: true,
            log: LogNeed::OnFailure,
        },
        true, // is_broken
    )
    .expect("read_archive");
    assert!(
        c.log.contains("boom"),
        "OnFailure must read the log when the archive is broken"
    );
}

#[test]
fn read_archive_on_failure_reads_log_when_auth_errors() {
    // auth_errors > 0 in metadata (even on a non-broken archive) also triggers
    // the log read, so summary/hints can quote the failure context.
    let dir = tempdir().expect("tempdir");
    let (archive, key) = build_archive(dir.path(), META_AUTH_ERR);
    let c = read_archive(
        &archive,
        &key,
        &ArchiveNeeds {
            errors: true,
            log: LogNeed::OnFailure,
        },
        false, // not broken — the trigger is auth_errors
    )
    .expect("read_archive");
    assert!(
        c.log.contains("boom"),
        "OnFailure must read the log when metadata reports auth_errors"
    );
}

#[test]
fn folder_mode_never_skips_log_and_errors() {
    // The folder branch shares the same gating: with LogNeed::Never and
    // errors=false, neither file is loaded even when present on disk.
    let dir = tempdir().expect("tempdir");
    let p = dir.path();
    fs::write(p.join("oradaz.log"), LOG_LINE).expect("write oradaz.log");
    fs::write(p.join("errors.json"), format!("{ERR_LINE}\n")).expect("write errors.json");
    fs::write(p.join("metadata.json"), META_HEALTHY).expect("write metadata.json");

    let skipped = load_log_source(
        p.to_str().expect("utf-8 path"),
        None,
        &ArchiveNeeds {
            errors: false,
            log: LogNeed::Never,
        },
    );
    assert!(
        skipped.log_text.is_empty(),
        "folder log skipped under Never"
    );
    assert!(
        skipped.dump_errors.is_empty(),
        "folder errors skipped when errors=false"
    );

    // Same folder, asked for both → both populated, proving the gate (not a
    // missing file) caused the emptiness above.
    let loaded = load_log_source(
        p.to_str().expect("utf-8 path"),
        None,
        &ArchiveNeeds {
            errors: true,
            log: LogNeed::Always,
        },
    );
    assert!(loaded.log_text.contains("boom"));
    assert_eq!(loaded.dump_errors.len(), 1);
}
