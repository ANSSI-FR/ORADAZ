// Test that logs are not lost when the dump is paused.
// The pause flag only suppresses stdout printing; file logging must still happen.

use log::error;
use std::sync::atomic::Ordering;
use tempfile::tempdir;

#[tokio::test]
async fn logs_preserved_during_pause() {
    // Import required modules from the crate
    use oradaz::utils::client::OradazClient;
    use oradaz::utils::config::Config;
    use oradaz::utils::logger::config as logger_config;
    use oradaz::utils::logger::{self, Verbosity, remove_writer};
    use oradaz::utils::writer::actor::spawn_writer_task;
    use std::path::PathBuf;

    // Create a temporary output directory.
    let tmp_dir = tempdir().expect("Failed to create temp dir");
    let output_path: PathBuf = tmp_dir.path().to_path_buf();

    // Minimal configuration – all optional fields left None.
    let config = Config {
        tenant: "test-tenant".to_string(),
        app_id: "".to_string(),
        services: None,
        proxy: None,
        output_files: Some(true),
        output_mla: Some(false),
        output: None,
        no_check: None,
        use_device_code: None,
        listener_address: None,
        listener_port: None,
        schema_file: None,
        schema_url_override: None,
        user_agent: None,
        emergency_accounts_custom_attributes: None,
        additional_mla_keys: None,
        trace_logs: None,
        use_application_credentials: None,
        application_credentials: None,
        concurrency_min_window: None,
        concurrency_max_window: None,
        default_retry_after_seconds: None,
        http_timeout_seconds: None,
        dispatch_burst_cap: None,
        url_retry_limit: None,
        rate_limit_retry_limit: None,
        rate_limit_max_wait_secs: None,
        stall_detection_timeout: None,
        http_connect_timeout_seconds: None,
        retry_backoff_base_ms: None,
        retry_backoff_cap_ms: None,
        prereq_recheck_cache_secs: None,
        liveness_ceiling_secs: None,
        service_overrides: None,
        logs_days_filter: None,
        shuffle_urls: None,
        concurrency_slow_start: None,
        response_workers_max: None,
        response_memory_budget_bytes: None,
        expected_error_breaker_threshold: None,
    };

    // Create Oradaz client (required for writer initialization).
    let _client = OradazClient::new(&config).expect("Failed to create OradazClient");

    // Spawn the writer task – use a distinct folder name "pause_test".
    let (writer_handle, writer_join) = spawn_writer_task(
        config.clone(),
        output_path.clone(),
        "pause_test".to_string(),
    )
    .await
    .expect("Failed to spawn writer task");

    // Initialize the logger with the writer and Normal verbosity.
    logger::initialize(Some(writer_handle.clone()), Verbosity::Normal);

    // Simulate a pause from one source: bump the DUMP_PAUSED counter.
    logger_config::DUMP_PAUSED.store(1, Ordering::Relaxed);

    // Emit at ERROR level: `handle_stdout` surfaces errors to stdout in every phase, so
    // the DUMP_PAUSED counter is the *only* thing suppressing the stdout copy here. The
    // file copy (written by `handle_file`, which the pause flag does not gate) must still
    // be present — that is the regression this test guards.
    error!(target: "oradaz::test", "log line emitted during pause");

    // The log line is queued on the writer's channel synchronously above. Closing
    // the channel (drop both senders) and awaiting the writer task drains that
    // queue and flushes the file before the join returns — a deterministic barrier,
    // so no timed sleep (which could flake on a saturated CI runner) is needed.
    remove_writer();
    drop(writer_handle);
    let _ = writer_join.await;

    // Reset the global pause counter so this process-global state does not leak into any
    // other test that might later share this binary.
    logger_config::DUMP_PAUSED.store(0, Ordering::Relaxed);

    // Read the generated log file and assert that our line is present.
    let log_path = output_path.join("pause_test").join("oradaz.log");
    let log_contents = std::fs::read_to_string(&log_path).expect("Failed to read log file");
    assert!(
        log_contents.contains("log line emitted during pause"),
        "Log line missing from oradaz.log while paused"
    );
}
