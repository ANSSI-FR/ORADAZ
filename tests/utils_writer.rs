mod common;

use crate::common::default_test_config;
use oradaz::utils::config::{AdditionalMlaKeys, Config};
use oradaz::utils::writer::{FileWriter, MlaWriter, OradazWriter};

use mla::crypto::mlakey::generate_mla_keypair_from_seed;
use std::fs;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

fn make_mla_v2_public_key_bytes(seed: [u8; 32]) -> Vec<u8> {
    let (_private_key, public_key) = generate_mla_keypair_from_seed(seed);
    let mut buf = Vec::new();
    public_key.serialize_public_key(&mut buf).unwrap();
    buf
}

fn create_test_config() -> Config {
    let mut config = default_test_config();
    config.output_files = Some(true);
    config.output_mla = Some(false); // Start with file writer only for simpler tests
    config
}

fn create_test_config_with_mla() -> Config {
    let mut config = default_test_config();
    config.output_files = Some(false);
    config.output_mla = Some(true); // MLA writer only
    config
}

#[test]
fn test_file_writer_creates_output_directory() {
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path();
    let name = "test-output".to_string();

    let _file_writer = FileWriter::new(output_path, &name).unwrap();

    // Check that the directory was created
    let expected_path = output_path.join(&name);
    assert!(expected_path.exists());
    assert!(expected_path.is_dir());

    // Check that log file was created
    let log_path = expected_path.join("oradaz.log");
    assert!(log_path.exists());
    assert!(log_path.is_file());
}

#[test]
fn test_file_writer_write_file_creates_subdirectories() {
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path();
    let name = "test-output".to_string();

    let mut file_writer = FileWriter::new(output_path, &name).unwrap();

    // Write to a nested folder
    let folder = "graph".to_string();
    let file = "applications.json".to_string();
    let data = r#"{"test": "data"}"#.to_string();

    file_writer.write_file(&folder, &file, data).unwrap();

    // Check that subdirectory was created
    let subdir_path = output_path.join(&name).join(&folder);
    assert!(subdir_path.exists());
    assert!(subdir_path.is_dir());

    // Check that file was created with correct content
    let file_path = subdir_path.join(&file);
    assert!(file_path.exists());
    assert!(file_path.is_file());

    let content = fs::read_to_string(file_path).unwrap();
    assert_eq!(content, r#"{"test": "data"}"#);
}

#[test]
fn test_file_writer_write_log() {
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path();
    let name = "test-output".to_string();

    let mut file_writer = FileWriter::new(output_path, &name).unwrap();

    let log_entry = "Test log entry\n".to_string();
    file_writer.write_log(&log_entry).unwrap();

    // Check that log was written
    let log_path = output_path.join(&name).join("oradaz.log");
    let content = fs::read_to_string(log_path).unwrap();
    assert_eq!(content, log_entry);
}

#[test]
fn test_oradaz_writer_file_only() {
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path();
    let name = "test-output".to_string();
    let config = create_test_config();

    let mut writer = OradazWriter::new(&config, output_path, &name).unwrap();

    // Write a file
    writer
        .write_file(
            "test".to_string(),
            "test.json".to_string(),
            r#"{"test": true}"#.to_string(),
        )
        .unwrap();

    // Check that file was created
    let file_path = output_path.join(&name).join("test").join("test.json");
    assert!(file_path.exists());
    let content = fs::read_to_string(file_path).unwrap();
    assert_eq!(content, r#"{"test": true}"#);
}

#[test]
fn test_oradaz_writer_concurrent_writes() {
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path();
    let name = "test-output".to_string();
    let config = create_test_config();

    let writer = Arc::new(Mutex::new(
        OradazWriter::new(&config, output_path, &name).unwrap(),
    ));

    // Spawn multiple threads to write concurrently
    let mut handles = vec![];

    for i in 0..5 {
        let writer_clone = Arc::clone(&writer);
        let handle = std::thread::spawn(move || {
            let mut writer = oradaz::utils::mutex::lock_force(&writer_clone);
            let data = format!(r#"{{"thread": {}, "data": "test{}"}}"#, i, i);
            writer
                .write_file("concurrent".to_string(), format!("file{}.json", i), data)
                .unwrap();
        });
        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }

    // Check that all files were created
    for i in 0..5 {
        let file_path = output_path
            .join(&name)
            .join("concurrent")
            .join(format!("file{}.json", i));
        assert!(file_path.exists());
        let content = fs::read_to_string(file_path).unwrap();
        let expected = format!(r#"{{"thread": {}, "data": "test{}"}}"#, i, i);
        assert_eq!(content, expected);
    }
}

#[test]
fn test_oradaz_writer_heavy_concurrent_writes() {
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path();
    let name = "stress-concurrency".to_string();
    let config = create_test_config();

    let writer = Arc::new(Mutex::new(
        OradazWriter::new(&config, output_path, &name).unwrap(),
    ));

    let mut handles = vec![];
    for t in 0..20 {
        let w = Arc::clone(&writer);
        let handle = std::thread::spawn(move || {
            for i in 0..10 {
                let mut w = oradaz::utils::mutex::lock_force(&w);
                let data = format!(r#"{{"thread":{}, "file":{}}}"#, t, i);
                w.write_file("stress".to_string(), format!("t{}_f{}.json", t, i), data)
                    .expect("write failed");
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("thread panicked");
    }

    for t in 0..20 {
        for i in 0..10 {
            let path = output_path
                .join(&name)
                .join("stress")
                .join(format!("t{}_f{}.json", t, i));
            assert!(path.exists(), "missing {}", path.display());
        }
    }
}

#[test]
fn test_mla_writer_creation() {
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path();
    let name = "test-mla".to_string();
    let config = default_test_config();
    let keys = oradaz::utils::writer::mla::load_mla_public_keys(&config).unwrap();

    let _mla_writer = MlaWriter::new(output_path, &name, &keys).unwrap();

    // Check that MLA file was created with .tmp extension
    let mla_path = output_path.join(format!("{}.mla.tmp", name));
    assert!(mla_path.exists());
    assert!(mla_path.is_file());
}

#[test]
fn test_mla_writer_write_file() {
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path();
    let name = "test-mla".to_string();
    let config = default_test_config();
    let keys = oradaz::utils::writer::mla::load_mla_public_keys(&config).unwrap();

    let mut mla_writer = MlaWriter::new(output_path, &name, &keys).unwrap();

    // Write a file to MLA archive
    let filepath = "test/file.json";
    let data = r#"{"test": "mla_data"}"#.to_string();
    mla_writer.write_file(filepath, data).unwrap();

    // Check that file ID was stored
    assert!(mla_writer.file_ids.contains_key(filepath));
}

#[test]
fn test_mla_writer_close() {
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path();
    let name = "test-mla".to_string();
    let config = default_test_config();
    let keys = oradaz::utils::writer::mla::load_mla_public_keys(&config).unwrap();

    let mut mla_writer = MlaWriter::new(output_path, &name, &keys).unwrap();

    // Write some data
    mla_writer
        .write_file("test.json", r#"{"test": true}"#.to_string())
        .unwrap();
    mla_writer.write_log(&"Test log\n".to_string()).unwrap();

    // Close the archive
    mla_writer.close().unwrap();

    // Check that archive is finalized (mla_archive should be None)
    assert!(mla_writer.mla_archive.is_none());
}

#[test]
fn test_oradaz_writer_mla_only() {
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path();
    let name = "12345678-4321-4321-4321-123456789012_20260413-135403".to_string();
    let config = create_test_config_with_mla();

    let mut writer = OradazWriter::new(&config, output_path, &name).unwrap();

    // Write a file
    writer
        .write_file(
            "test".to_string(),
            "test.json".to_string(),
            r#"{"mla": true}"#.to_string(),
        )
        .unwrap();

    // Finalize
    writer.finalize().unwrap();

    // Check that MLA file was created and .tmp was removed
    let mla_path = output_path.join(format!("{}.mla", name));
    assert!(mla_path.exists());
    assert!(mla_path.is_file());

    // .tmp file should be gone
    let tmp_path = output_path.join(format!("{}.mla.tmp", name));
    assert!(!tmp_path.exists());
}

#[test]
fn test_oradaz_writer_set_broken_renames_to_broken() {
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path();
    let name = "12345678-4321-4321-4321-123456789012_20260413-120000".to_string();
    let config = create_test_config_with_mla();

    let mut writer = OradazWriter::new(&config, output_path, &name).unwrap();
    writer
        .write_file(
            "test".to_string(),
            "test.json".to_string(),
            r#"{"broken": true}"#.to_string(),
        )
        .unwrap();

    writer.set_broken().unwrap();

    let broken_path = output_path.join(format!("{}.mla.broken", name));
    assert!(broken_path.exists(), ".broken file must exist");

    let tmp_path = output_path.join(format!("{}.mla.tmp", name));
    assert!(!tmp_path.exists(), ".tmp file must be removed");
}

#[test]
fn test_oradaz_writer_set_broken_file_only_returns_ok() {
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path();
    let config = create_test_config();
    let name = "test-files".to_string();
    let mut writer = OradazWriter::new(&config, output_path, &name).unwrap();
    assert!(writer.set_broken().is_ok());
}

/// If the archive was already closed (e.g. `finalize()` failed after closing
/// it), `set_broken()` must still rename the `.tmp` to `.broken` rather than
/// propagating the second-close error and leaving a dangling `.tmp`.
#[test]
fn test_oradaz_writer_set_broken_after_close_still_renames() {
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path();
    let name = "12345678-4321-4321-4321-123456789012_20260413-130000".to_string();
    let config = create_test_config_with_mla();

    let mut writer = OradazWriter::new(&config, output_path, &name).unwrap();
    writer
        .write_file(
            "test".to_string(),
            "test.json".to_string(),
            r#"{"x":1}"#.to_string(),
        )
        .unwrap();

    // Simulate `finalize()` having already closed the inner archive.
    writer.mla_writer.as_mut().unwrap().close().unwrap();

    // The second (already-closed) close inside set_broken must not abort the rename.
    writer
        .set_broken()
        .expect("set_broken must still rename to .broken after a prior close");

    let broken_path = output_path.join(format!("{}.mla.broken", name));
    assert!(
        broken_path.exists(),
        ".broken file must exist even after a prior close"
    );
    let tmp_path = output_path.join(format!("{}.mla.tmp", name));
    assert!(!tmp_path.exists(), ".tmp file must be removed");
}

#[test]
fn test_load_mla_public_keys_default() {
    let config = default_test_config();
    let keys = oradaz::utils::writer::mla::load_mla_public_keys(&config).unwrap();
    assert_eq!(keys.len(), 1);
}

#[test]
fn test_load_mla_public_keys_additional_raw() {
    let mut config = default_test_config();
    let key_bytes = make_mla_v2_public_key_bytes([1u8; 32]);
    let key_str = String::from_utf8(key_bytes).unwrap();
    config.additional_mla_keys = Some(AdditionalMlaKeys {
        key_files: None,
        keys: Some(vec![key_str]),
    });

    let keys = oradaz::utils::writer::mla::load_mla_public_keys(&config).unwrap();
    assert_eq!(keys.len(), 2);
}

#[test]
fn test_load_mla_public_keys_additional_file() {
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("test.pub");
    let key_bytes = make_mla_v2_public_key_bytes([2u8; 32]);
    fs::write(&key_path, &key_bytes).unwrap();

    let mut config = default_test_config();
    config.additional_mla_keys = Some(AdditionalMlaKeys {
        key_files: Some(vec![key_path.to_str().unwrap().to_string()]),
        keys: None,
    });

    let keys = oradaz::utils::writer::mla::load_mla_public_keys(&config).unwrap();
    assert_eq!(keys.len(), 2);
}

#[test]
fn test_load_mla_public_keys_invalid_key() {
    let mut config = default_test_config();
    config.additional_mla_keys = Some(AdditionalMlaKeys {
        key_files: None,
        keys: Some(vec!["invalid key".to_string()]),
    });

    let result = oradaz::utils::writer::mla::load_mla_public_keys(&config);
    assert!(matches!(
        result,
        Err(oradaz::utils::errors::Error::MLAInvalidPubKey)
    ));
}

#[test]
fn test_load_mla_public_keys_missing_file() {
    let mut config = default_test_config();
    config.additional_mla_keys = Some(AdditionalMlaKeys {
        key_files: Some(vec!["/non/existent/path.pub".to_string()]),
        keys: None,
    });

    let result = oradaz::utils::writer::mla::load_mla_public_keys(&config);
    assert!(matches!(
        result,
        Err(oradaz::utils::errors::Error::IOError(_))
    ));
}

/// A data write failure during collection must not silently report COMPLETE.
/// The actor refuses to finalize clean and returns an error (the caller then
/// marks the archive `.broken`). The failure is forced by planting a regular
/// file where the "graph" service *folder* must be created, so the data write
/// to `graph/users.json` cannot open its path.
#[tokio::test]
async fn actor_data_write_failure_makes_finalize_report_failure() {
    let config = create_test_config(); // file output only
    let temp_dir = TempDir::new().unwrap();
    let name = "broken-run".to_string();
    let (writer, task) = oradaz::utils::writer::actor::spawn_writer_task(
        config,
        temp_dir.path().to_path_buf(),
        name.clone(),
    )
    .await
    .unwrap();

    // Plant a regular file where the "graph" service folder would go, so the
    // subsequent data write to graph/users.json fails in the actor.
    let collection_dir = temp_dir.path().join(&name);
    fs::write(collection_dir.join("graph"), b"not a directory").unwrap();

    // Enqueue a data write (returns Ok on enqueue; the failure surfaces later),
    // then finalize — which must report the accumulated data-write failure.
    writer
        .write_file(
            "graph".to_string(),
            "users.json".to_string(),
            "[]".to_string(),
        )
        .await
        .expect("enqueue should succeed; the write failure surfaces at finalize");
    let result = writer.finalize().await;

    assert!(
        matches!(result, Err(oradaz::utils::errors::Error::WriteFile)),
        "finalize must report WriteFile after a failed data write, got {result:?}"
    );

    drop(writer);
    let _ = task.await;
}

/// Control: with no write failure, finalize succeeds (guards against a
/// regression where finalize spuriously returns Err on clean runs).
#[tokio::test]
async fn actor_clean_run_finalizes_ok() {
    let config = create_test_config();
    let temp_dir = TempDir::new().unwrap();
    let (writer, task) = oradaz::utils::writer::actor::spawn_writer_task(
        config,
        temp_dir.path().to_path_buf(),
        "clean-run".to_string(),
    )
    .await
    .unwrap();

    writer
        .write_file(
            "graph".to_string(),
            "users.json".to_string(),
            "[]".to_string(),
        )
        .await
        .unwrap();
    assert!(
        writer.finalize().await.is_ok(),
        "a clean run must finalize successfully"
    );

    drop(writer);
    let _ = task.await;
}

/// `byte_budget_inflight_bytes` reports 0 on a fresh writer (full budget
/// available) and returns to 0 once queued writes drain — the gauge that backs
/// the debug memory sample's `writer_bytes` field.
#[tokio::test]
async fn actor_byte_budget_inflight_reports_zero_when_idle() {
    let config = create_test_config();
    let temp_dir = TempDir::new().unwrap();
    let (writer, task) = oradaz::utils::writer::actor::spawn_writer_task(
        config,
        temp_dir.path().to_path_buf(),
        "byte-budget".to_string(),
    )
    .await
    .unwrap();

    assert_eq!(
        writer.byte_budget_inflight_bytes(),
        0,
        "a fresh writer holds the full byte budget (nothing in flight)"
    );

    writer
        .write_file(
            "graph".to_string(),
            "users.json".to_string(),
            "[1,2,3]".to_string(),
        )
        .await
        .unwrap();
    // Finalize is FIFO after every queued write, so all permits are released by
    // the time it returns.
    writer.finalize().await.unwrap();
    assert_eq!(
        writer.byte_budget_inflight_bytes(),
        0,
        "all byte-budget permits must be released once writes drain"
    );

    drop(writer);
    let _ = task.await;
}
