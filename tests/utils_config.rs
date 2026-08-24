mod common;

use crate::common::default_test_config;
use oradaz::utils::config::{
    ApplicationCredentials, Config, ConfigParser, ProxyConfig, ServiceConfig, ServiceOverride,
    ServiceOverrides, ServicesConfig, StoredConfig,
};
use oradaz::utils::errors::Error;
use oradaz::utils::writer::actor::spawn_writer_task;

fn make_config_with_emergency_attr(attr: Option<String>) -> Config {
    Config {
        tenant: "test".to_string(),
        app_id: "test".to_string(),
        services: None,
        proxy: None,
        output_files: None,
        output_mla: None,
        output: None,
        no_check: None,
        use_device_code: None,
        listener_address: None,
        listener_port: None,
        schema_file: None,
        schema_url_override: None,
        user_agent: None,
        trace_logs: None,
        use_application_credentials: None,
        application_credentials: None,
        concurrency_min_window: None,
        concurrency_max_window: None,
        dispatch_burst_cap: None,
        http_timeout_seconds: None,
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
        default_retry_after_seconds: None,
        emergency_accounts_custom_attributes: attr,
        additional_mla_keys: None,
        logs_days_filter: None,
        shuffle_urls: None,
        concurrency_slow_start: None,
        response_workers_max: None,
        response_memory_budget_bytes: None,
        expected_error_breaker_threshold: None,
    }
}

use std::path::PathBuf;

fn get_fixture_path(filename: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push(filename);
    path.to_string_lossy().to_string()
}

#[test]
fn test_config_parser_valid_config() {
    let config_path = get_fixture_path("valid-config.xml");
    let parser = ConfigParser::new(&config_path).expect("Failed to create parser");
    let config = parser.deserialize().expect("Failed to deserialize config");

    assert_eq!(config.tenant, "12345678-4321-4321-4321-123456789012");
    assert_eq!(config.app_id, "12345678-1234-1234-1234-123456789012");
    assert_eq!(config.output_files, Some(true));
    assert_eq!(config.output_mla, Some(true));
}

#[test]
fn test_config_parser_valid_config_with_optional_fields() {
    let config_path = get_fixture_path("valid-config-extended.xml");
    let parser = ConfigParser::new(&config_path).expect("Failed to create parser");
    let config = parser.deserialize().expect("Failed to deserialize config");

    // Required fields
    assert_eq!(config.tenant, "12345678-4321-4321-4321-123456789012");
    assert_eq!(config.app_id, "12345678-1234-1234-1234-123456789012");

    // Output configuration
    assert_eq!(config.output_files, Some(true));
    assert_eq!(config.output_mla, Some(true));

    // Thread settings

    // Performance settings
    assert_eq!(config.concurrency_min_window, Some(5));
    assert_eq!(config.concurrency_max_window, Some(50));
    assert_eq!(config.http_timeout_seconds, Some(60));
    assert_eq!(config.default_retry_after_seconds, Some(45));
    assert_eq!(config.dispatch_burst_cap, Some(200));
    assert_eq!(config.url_retry_limit, Some(3));
    assert_eq!(config.stall_detection_timeout, Some(600));
    assert_eq!(Config::liveness_ceiling_secs(&config), 1200);
    assert_eq!(config.prereq_recheck_cache_secs, Some(15));
    assert_eq!(Config::prereq_recheck_cache_secs(&config), 15);
    // Slow-start: the `concurrencySlowStart` XML tag must deserialize (serde
    // rename), so assert both the raw field and the accessor.
    assert_eq!(config.concurrency_slow_start, Some(true));
    assert!(Config::concurrency_slow_start(&config));

    // Proxy configuration
    assert!(config.proxy.is_some());
    if let Some(proxy) = config.proxy.as_ref() {
        assert_eq!(proxy.url, "http://proxy.example.com:8080");
        assert_eq!(proxy.username, Some("proxyuser".to_string()));
        assert_eq!(proxy.password, Some("proxypass".to_string()));
    }

    // Authentication settings
    assert_eq!(config.use_device_code, Some(true));
    assert_eq!(config.no_check, Some(true));

    // Listener settings
    assert_eq!(config.listener_address, Some("127.0.0.1".to_string()));
    assert_eq!(config.listener_port, Some("8888".to_string()));

    // File and URL overrides
    assert_eq!(
        config.schema_file,
        Some("/path/to/custom/schema.json".to_string())
    );
    assert_eq!(config.user_agent, Some("OradazCustomAgent/1.0".to_string()));

    // Services configuration
    assert!(config.services.is_some());
    if let Some(services) = config.services.as_ref() {
        assert_eq!(services.services.len(), 3);
        assert!(Config::service_enable(&config, &"graph".to_string()));
        assert!(!Config::service_enable(&config, &"exchange".to_string()));
        assert!(Config::service_enable(&config, &"resources".to_string()));
    }
}

/// `<serviceOverrides>` must deserialize into a `ServiceOverrides.services` Vec
/// where each entry carries its own subset of overridable parameters. Services
/// absent from the block fall back to the global value (verified via the
/// `*_for(config, "service")` helpers).
#[test]
fn test_config_parser_service_overrides() {
    let config_path = get_fixture_path("valid-config-service-overrides.xml");
    let parser = ConfigParser::new(&config_path).expect("Failed to create parser");
    let config = parser.deserialize().expect("Failed to deserialize config");

    let overrides = config
        .service_overrides
        .as_ref()
        .expect("serviceOverrides block expected");
    assert_eq!(overrides.services.len(), 3);

    // resources: overrides concurrencyMaxWindow + both rate-limit budgets + default Retry-After.
    assert_eq!(Config::concurrency_max_window_for(&config, "resources"), 20);
    assert_eq!(Config::concurrency_max_window(&config), 30); // global still 30
    assert_eq!(
        Config::rate_limit_retry_limit_for(&config, "resources"),
        100
    );
    assert_eq!(
        Config::rate_limit_max_wait_secs_for(&config, "resources"),
        1800
    );
    assert_eq!(
        Config::default_retry_after_seconds_for(&config, "resources"),
        5
    );

    // graph: overrides concurrencyMaxWindow and rateLimitRetryLimit only;
    // other params fall back to globals.
    assert_eq!(Config::concurrency_max_window_for(&config, "graph"), 100);
    assert_eq!(Config::rate_limit_retry_limit_for(&config, "graph"), 20);
    assert_eq!(
        Config::rate_limit_max_wait_secs_for(&config, "graph"),
        Config::rate_limit_max_wait_secs(&config),
    );

    // exchange: only httpTimeoutSeconds overridden.
    assert_eq!(Config::http_timeout_seconds_for(&config, "exchange"), 60);
    // graph and resources: no service-level override; fall back to explicit global (30).
    assert_eq!(
        Config::http_timeout_seconds_for(&config, "graph"),
        Config::http_timeout_seconds(&config),
    );
    assert_eq!(
        Config::http_timeout_seconds_for(&config, "resources"),
        Config::http_timeout_seconds(&config),
    );

    // Unknown service: every helper falls back to the global value.
    assert_eq!(
        Config::concurrency_max_window_for(&config, "unknown_service"),
        Config::concurrency_max_window(&config),
    );
    assert_eq!(
        Config::rate_limit_retry_limit_for(&config, "unknown_service"),
        Config::rate_limit_retry_limit(&config),
    );

    // The override block must survive validation.
    assert!(config.validate().is_ok());
}

/// When no `httpTimeoutSeconds` is configured at either level, `resources` and
/// `exchange` must default to 60 s (ARM batches and exchange adminapi
/// responses are slow) while other services default to 30 s.
#[test]
fn test_http_timeout_seconds_for_resources_code_default() {
    // Config with no httpTimeoutSeconds at all (neither global nor per-service).
    let config = make_config_with_emergency_attr(None);
    assert_eq!(Config::http_timeout_seconds_for(&config, "resources"), 60);
    assert_eq!(Config::http_timeout_seconds_for(&config, "graph"), 30);
    assert_eq!(Config::http_timeout_seconds_for(&config, "exchange"), 60);
    assert_eq!(Config::http_timeout_seconds_for(&config, "unknown"), 30);
}

/// When the user sets a global `httpTimeoutSeconds`, that value applies to all
/// services (including `resources`) — the code default is not used.
#[test]
fn test_http_timeout_seconds_for_resources_explicit_global_overrides_code_default() {
    let mut config = make_config_with_emergency_attr(None);
    config.http_timeout_seconds = Some(30);
    assert_eq!(Config::http_timeout_seconds_for(&config, "resources"), 30);
    assert_eq!(Config::http_timeout_seconds_for(&config, "graph"), 30);
}

/// `serviceOverrides.httpTimeoutSeconds` for `resources` takes precedence over
/// both the global value and the code default.
#[test]
fn test_http_timeout_seconds_for_resources_service_override_wins() {
    use oradaz::utils::config::{ServiceOverride, ServiceOverrides};
    let mut config = make_config_with_emergency_attr(None);
    config.service_overrides = Some(ServiceOverrides {
        services: vec![ServiceOverride {
            name: "resources".to_string(),
            http_timeout_seconds: Some(90),
            ..Default::default()
        }],
    });
    assert_eq!(Config::http_timeout_seconds_for(&config, "resources"), 90);
    // other services still get the code default
    assert_eq!(Config::http_timeout_seconds_for(&config, "graph"), 30);
}

/// When no `httpTimeoutSeconds` is configured, the effective maximum timeout is
/// 60 s (the code default for the `resources` service).  A connect timeout up
/// to 60 s must therefore be accepted without requiring the user to set the
/// global `httpTimeoutSeconds` explicitly.
#[test]
fn test_config_validation_connect_timeout_respects_resources_code_default() {
    // 45 s connect timeout with no explicit httpTimeoutSeconds — must be valid
    // (effective max is 60 s from the resources code default).
    let mut config = make_config_with_emergency_attr(None);
    config.http_connect_timeout_seconds = Some(45);
    assert!(
        config.validate().is_ok(),
        "httpConnectTimeoutSeconds=45 should be accepted when httpTimeoutSeconds is not set"
    );

    // 61 s exceeds even the resources code default → must be rejected.
    config.http_connect_timeout_seconds = Some(61);
    assert!(
        config.validate().is_err(),
        "httpConnectTimeoutSeconds=61 must be rejected when httpTimeoutSeconds is not set"
    );

    // When the user explicitly sets httpTimeoutSeconds=30, the connect timeout
    // must not exceed 30 s — the code default no longer applies.
    config.http_timeout_seconds = Some(30);
    config.http_connect_timeout_seconds = Some(31);
    assert!(
        config.validate().is_err(),
        "httpConnectTimeoutSeconds=31 must be rejected when httpTimeoutSeconds=30"
    );
    config.http_connect_timeout_seconds = Some(30);
    assert!(
        config.validate().is_ok(),
        "httpConnectTimeoutSeconds=30 must be accepted when httpTimeoutSeconds=30"
    );
}

/// `serviceOverrides` must reject a per-service `concurrencyMinWindow` greater
/// than the matching `concurrencyMaxWindow`, mirroring the global invariant.
#[test]
fn test_config_validation_service_override_inverted_windows() {
    let mut config = make_config_with_emergency_attr(None);
    config.service_overrides = Some(oradaz::utils::config::ServiceOverrides {
        services: vec![oradaz::utils::config::ServiceOverride {
            name: "resources".to_string(),
            concurrency_min_window: Some(50),
            concurrency_max_window: Some(10),
            ..Default::default()
        }],
    });
    let err = config.validate().expect_err("inverted windows must fail");
    let msg = format!("{:?}", err);
    assert!(msg.contains("resources"), "{msg}");
    assert!(msg.contains("concurrencyMin"), "{msg}");
}

/// Regression: a per-service `concurrencyMinWindow` above the global default (30)
/// but within the service's built-in baseline (graph/exchange 150, resources 100)
/// must be ACCEPTED. validate() resolves a missing per-service max against the
/// service baseline, not the conservative global default — otherwise a sensible
/// min-only override (e.g. graph min=100) was wrongly rejected as "100 > 30".
#[test]
fn test_config_validation_service_override_min_only_uses_service_baseline() {
    let mut config = make_config_with_emergency_attr(None);
    config.service_overrides = Some(oradaz::utils::config::ServiceOverrides {
        services: vec![oradaz::utils::config::ServiceOverride {
            name: "graph".to_string(),
            concurrency_min_window: Some(100), // > global 30, < graph baseline 150
            concurrency_max_window: None,
            ..Default::default()
        }],
    });
    config
        .validate()
        .expect("graph min=100 must pass: resolved against the 150 baseline, not global 30");
}

/// A concurrency window of 0 stalls the dump (`acquire_slot` never satisfies
/// `in_flight < current`), and `min == 0` lets `report_429` halve the window to 0.
/// Validation must reject 0 for both the global setting and per-service overrides.
/// `livenessCeilingSecs` is the sole bound on transient (429 / network) retries;
/// `0` would let a never-draining bucket retry forever, so
/// validate() must reject it (a positive default still applies when unset).
#[test]
fn test_config_validation_rejects_zero_liveness_ceiling() {
    let mut config = make_config_with_emergency_attr(None);
    config.liveness_ceiling_secs = Some(0);
    let err = config
        .validate()
        .expect_err("zero livenessCeilingSecs must fail");
    assert!(format!("{:?}", err).contains("greater than 0"), "{err:?}");

    // Unset (None) is fine — the getter applies the 900s default.
    let mut config = make_config_with_emergency_attr(None);
    config.liveness_ceiling_secs = None;
    assert!(config.validate().is_ok());
}

#[test]
fn test_config_validation_rejects_zero_window() {
    // Global zero window.
    let mut config = make_config_with_emergency_attr(None);
    config.concurrency_min_window = Some(0);
    config.concurrency_max_window = Some(0);
    let err = config.validate().expect_err("zero global window must fail");
    assert!(format!("{:?}", err).contains("greater than 0"), "{err:?}");

    // Per-service override zero window.
    let mut config = make_config_with_emergency_attr(None);
    config.service_overrides = Some(oradaz::utils::config::ServiceOverrides {
        services: vec![oradaz::utils::config::ServiceOverride {
            name: "graph".to_string(),
            concurrency_min_window: Some(0),
            concurrency_max_window: Some(0),
            ..Default::default()
        }],
    });
    let err = config
        .validate()
        .expect_err("zero override window must fail");
    let msg = format!("{:?}", err);
    assert!(msg.contains("graph"), "{msg}");
    assert!(msg.contains("greater than 0"), "{msg}");
}

/// A global concurrencyMinWindow above a per-service built-in max baseline
/// (resources = 100) must NOT fail validation — at runtime the window is clamped to
/// the baseline and the operator is only warned. Here min=120 <= global max=150 but
/// exceeds the resources baseline of 100.
#[test]
fn test_config_validation_global_min_above_service_baseline_is_ok() {
    let mut config = make_config_with_emergency_attr(None);
    config.concurrency_min_window = Some(120);
    config.concurrency_max_window = Some(150);
    config
        .validate()
        .expect("global min above a service baseline must pass (clamped + warned, not fatal)");
}

/// A stallDetectionTimeout below rateLimitMaxWaitSecs lets the stall watchdog
/// fire while a worker waits out a legitimate 429 cooldown — a misleading
/// diagnostic, never a data loss. Validation only warns, so it must still pass.
#[test]
fn test_config_validation_stall_below_max_wait_is_ok() {
    let mut config = make_config_with_emergency_attr(None);
    config.stall_detection_timeout = Some(120);
    config.rate_limit_max_wait_secs = Some(900);
    config
        .validate()
        .expect("stallDetectionTimeout below rateLimitMaxWaitSecs must pass (warned, not fatal)");

    // Per-service override that raises rateLimitMaxWaitSecs above the global
    // stall timeout is likewise only warned.
    let mut config = make_config_with_emergency_attr(None);
    config.stall_detection_timeout = Some(300);
    config.service_overrides = Some(oradaz::utils::config::ServiceOverrides {
        services: vec![oradaz::utils::config::ServiceOverride {
            name: "graph".to_string(),
            rate_limit_max_wait_secs: Some(900),
            ..Default::default()
        }],
    });
    config.validate().expect(
        "per-service rateLimitMaxWaitSecs above stall timeout must pass (warned, not fatal)",
    );
}

#[test]
fn test_config_parser_minimal_config() {
    let config_path = get_fixture_path("minimal-config.xml");
    let parser = ConfigParser::new(&config_path).expect("Failed to create parser");
    let config = parser.deserialize().expect("Failed to deserialize config");

    assert_eq!(config.tenant, "12345678-4321-4321-4321-123456789012");
    assert_eq!(config.app_id, "12345678-1234-1234-1234-123456789012");
    assert_eq!(config.output_files, None);
    assert_eq!(config.output_mla, None);
    assert_eq!(config.prereq_recheck_cache_secs, None);
    assert_eq!(Config::prereq_recheck_cache_secs(&config), 90);
}

#[test]
fn test_config_parser_missing_tenant_defaults_to_empty() {
    use std::fs;
    use tempfile::TempDir;

    // <tenant> is optional in the XML: the CLI flag / interactive prompt supply
    // it when absent. Deserialization must succeed with an empty tenant rather
    // than fail before the CLI value is consulted.
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("no-tenant.xml");
    fs::write(
        &config_path,
        r#"<?xml version="1.0" encoding="UTF-8"?>
<config>
    <appId>12345678-1234-1234-1234-123456789012</appId>
    <outputMLA>true</outputMLA>
</config>"#,
    )
    .expect("Failed to write config");

    let parser =
        ConfigParser::new(&config_path.to_string_lossy()).expect("Failed to create parser");
    let config = parser
        .deserialize()
        .expect("a config without <tenant> must deserialize");
    assert!(config.tenant.is_empty());
}

#[test]
fn test_config_parser_file_not_found() {
    let result = ConfigParser::new("/nonexistent/config.xml");
    assert!(result.is_err());
    match result {
        Err(Error::ConfigFileNotFound) => (),
        _ => panic!("Expected ConfigFileNotFound error"),
    }
}

#[test]
fn test_service_enable_when_service_exists() {
    let service = ServiceConfig {
        name: "graph".to_string(),
        value: true,
    };
    let services = ServicesConfig {
        services: vec![service],
    };
    let config = Config {
        tenant: "test".to_string(),
        app_id: "test".to_string(),
        services: Some(services),
        proxy: None,
        output_files: Some(false),
        output_mla: Some(false),
        output: None,
        no_check: None,
        use_device_code: None,
        listener_address: None,
        listener_port: None,
        schema_file: None,
        schema_url_override: None,
        user_agent: None,
        trace_logs: None,
        use_application_credentials: None,
        application_credentials: None,
        concurrency_min_window: None,
        concurrency_max_window: None,
        dispatch_burst_cap: None,
        http_timeout_seconds: None,
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
        default_retry_after_seconds: Some(30),
        emergency_accounts_custom_attributes: None,
        additional_mla_keys: None,
        logs_days_filter: None,
        shuffle_urls: None,
        concurrency_slow_start: None,
        response_workers_max: None,
        response_memory_budget_bytes: None,
        expected_error_breaker_threshold: None,
    };

    assert!(Config::service_enable(&config, &"graph".to_string()));
}

#[test]
fn test_service_enable_when_service_disabled() {
    let service = ServiceConfig {
        name: "graph".to_string(),
        value: false,
    };
    let services = ServicesConfig {
        services: vec![service],
    };
    let config = Config {
        tenant: "test".to_string(),
        app_id: "test".to_string(),
        services: Some(services),
        proxy: None,
        output_files: Some(false),
        output_mla: Some(false),
        output: None,
        no_check: None,
        use_device_code: None,
        listener_address: None,
        listener_port: None,
        schema_file: None,
        schema_url_override: None,
        user_agent: None,
        trace_logs: None,
        use_application_credentials: None,
        application_credentials: None,
        concurrency_min_window: None,
        concurrency_max_window: None,
        dispatch_burst_cap: None,
        http_timeout_seconds: None,
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
        default_retry_after_seconds: Some(30),
        emergency_accounts_custom_attributes: None,
        additional_mla_keys: None,
        logs_days_filter: None,
        shuffle_urls: None,
        concurrency_slow_start: None,
        response_workers_max: None,
        response_memory_budget_bytes: None,
        expected_error_breaker_threshold: None,
    };

    assert!(!Config::service_enable(&config, &"graph".to_string()));
}

#[test]
fn test_service_enable_when_no_services() {
    let config = Config {
        tenant: "test".to_string(),
        app_id: "test".to_string(),
        services: None,
        proxy: None,
        output_files: Some(false),
        output_mla: Some(false),
        output: None,
        no_check: None,
        use_device_code: None,
        listener_address: None,
        listener_port: None,
        schema_file: None,
        schema_url_override: None,
        user_agent: None,
        trace_logs: None,
        use_application_credentials: None,
        application_credentials: None,
        concurrency_min_window: None,
        concurrency_max_window: None,
        dispatch_burst_cap: None,
        http_timeout_seconds: None,
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
        default_retry_after_seconds: Some(30),
        emergency_accounts_custom_attributes: None,
        additional_mla_keys: None,
        logs_days_filter: None,
        shuffle_urls: None,
        concurrency_slow_start: None,
        response_workers_max: None,
        response_memory_budget_bytes: None,
        expected_error_breaker_threshold: None,
    };

    assert!(!Config::service_enable(&config, &"graph".to_string()));
}

#[test]
fn test_force_device_code_auth_true() {
    let config = Config {
        tenant: "test".to_string(),
        app_id: "test".to_string(),
        services: None,
        proxy: None,
        output_files: Some(false),
        output_mla: Some(false),
        output: None,
        no_check: None,
        use_device_code: Some(true),
        listener_address: None,
        listener_port: None,
        schema_file: None,
        schema_url_override: None,
        user_agent: None,
        trace_logs: None,
        use_application_credentials: None,
        application_credentials: None,
        concurrency_min_window: None,
        concurrency_max_window: None,
        dispatch_burst_cap: None,
        http_timeout_seconds: None,
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
        default_retry_after_seconds: Some(30),
        emergency_accounts_custom_attributes: None,
        additional_mla_keys: None,
        logs_days_filter: None,
        shuffle_urls: None,
        concurrency_slow_start: None,
        response_workers_max: None,
        response_memory_budget_bytes: None,
        expected_error_breaker_threshold: None,
    };

    assert!(Config::force_device_code_auth(&config));
}

#[test]
fn test_force_device_code_auth_false() {
    let config = Config {
        tenant: "test".to_string(),
        app_id: "test".to_string(),
        services: None,
        proxy: None,
        output_files: Some(false),
        output_mla: Some(false),
        output: None,
        no_check: Some(true),
        use_device_code: Some(false),
        listener_address: None,
        listener_port: None,
        schema_file: None,
        schema_url_override: None,
        user_agent: None,
        trace_logs: None,
        use_application_credentials: None,
        application_credentials: None,
        concurrency_min_window: None,
        concurrency_max_window: None,
        dispatch_burst_cap: None,
        http_timeout_seconds: None,
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
        default_retry_after_seconds: Some(30),
        emergency_accounts_custom_attributes: None,
        additional_mla_keys: None,
        logs_days_filter: None,
        shuffle_urls: None,
        concurrency_slow_start: None,
        response_workers_max: None,
        response_memory_budget_bytes: None,
        expected_error_breaker_threshold: None,
    };

    assert!(!Config::force_device_code_auth(&config));
}

#[test]
fn test_force_device_code_auth_none() {
    let config = Config {
        tenant: "test".to_string(),
        app_id: "test".to_string(),
        services: None,
        proxy: None,
        output_files: Some(false),
        output_mla: Some(false),
        output: None,
        no_check: None,
        use_device_code: None,
        listener_address: None,
        listener_port: None,
        schema_file: None,
        schema_url_override: None,
        user_agent: None,
        trace_logs: None,
        use_application_credentials: None,
        application_credentials: None,
        concurrency_min_window: None,
        concurrency_max_window: None,
        dispatch_burst_cap: None,
        http_timeout_seconds: None,
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
        default_retry_after_seconds: Some(30),
        emergency_accounts_custom_attributes: None,
        additional_mla_keys: None,
        logs_days_filter: None,
        shuffle_urls: None,
        concurrency_slow_start: None,
        response_workers_max: None,
        response_memory_budget_bytes: None,
        expected_error_breaker_threshold: None,
    };

    assert!(!Config::force_device_code_auth(&config));
}

#[tokio::test]
async fn test_config_write_to_writer() {
    use std::fs;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config = Config {
        tenant: "test-tenant".to_string(),
        app_id: "test-app-id".to_string(),
        services: Some(ServicesConfig {
            services: vec![ServiceConfig {
                name: "graph".to_string(),
                value: true,
            }],
        }),
        proxy: None,
        output_files: Some(true),
        output_mla: Some(false),
        output: None,
        no_check: Some(true),
        use_device_code: Some(false),
        concurrency_min_window: Some(2),
        concurrency_max_window: Some(20),
        dispatch_burst_cap: Some(50),
        http_timeout_seconds: Some(15),
        url_retry_limit: Some(2),
        rate_limit_retry_limit: None,
        rate_limit_max_wait_secs: None,
        stall_detection_timeout: Some(120),
        listener_address: None,
        listener_port: None,
        schema_file: Some("/path/to/schema.json".to_string()),
        user_agent: Some("test-agent".to_string()),
        trace_logs: None,
        schema_url_override: None,
        use_application_credentials: None,
        application_credentials: None,
        default_retry_after_seconds: Some(30),
        emergency_accounts_custom_attributes: None,
        additional_mla_keys: None,
        logs_days_filter: None,
        shuffle_urls: None,
        concurrency_slow_start: None,
        response_workers_max: None,
        response_memory_budget_bytes: None,
        expected_error_breaker_threshold: None,
        http_connect_timeout_seconds: None,
        retry_backoff_base_ms: None,
        retry_backoff_cap_ms: None,
        prereq_recheck_cache_secs: None,
        liveness_ceiling_secs: None,
        service_overrides: None,
    };

    let (writer, _handle) = spawn_writer_task(
        config.clone(),
        temp_dir.path().to_path_buf(),
        "test-archive".to_string(),
    )
    .await
    .expect("Failed to spawn writer task");

    config.write(&writer).await.expect("Failed to write config");

    writer.finalize().await.expect("Failed to finalize writer");

    // Check that config.json was created
    let config_path = temp_dir.path().join("test-archive").join("config.json");
    assert!(config_path.exists());

    let content = fs::read_to_string(config_path).expect("Failed to read config file");
    let stored_config: StoredConfig =
        serde_json::from_str(&content).expect("Failed to parse stored config");

    assert_eq!(stored_config.tenant, "test-tenant");
    assert_eq!(stored_config.app_id, "test-app-id");
    assert!(stored_config.output_files);
    assert!(!stored_config.output_mla);
    assert_eq!(stored_config.no_check, Some(true));
    assert_eq!(stored_config.use_device_code, Some(false));
    assert_eq!(stored_config.concurrency_min_window, Some(2));
    assert_eq!(stored_config.concurrency_max_window, Some(20));
    assert_eq!(stored_config.dispatch_burst_cap, Some(50));
    assert_eq!(stored_config.http_timeout_seconds, Some(15));
    assert_eq!(stored_config.url_retry_limit, Some(2));
    assert_eq!(stored_config.stall_detection_timeout, Some(120));
    assert!(stored_config.use_schema_file);
    assert_eq!(stored_config.user_agent, Some("test-agent".to_string()));
}

#[test]
fn test_config_parser_invalid_xml_structure() {
    use std::fs;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let invalid_config_path = temp_dir.path().join("invalid.xml");
    // Malformed (not well-formed) XML: the <tenant> element is never closed.
    fs::write(&invalid_config_path, "<config><tenant>oops</config>")
        .expect("Failed to write invalid config");

    let parser =
        ConfigParser::new(&invalid_config_path.to_string_lossy()).expect("Failed to create parser");
    let result = parser.deserialize();
    assert!(result.is_err());
    match result {
        Err(Error::InvalidConfigXMLStructure(_)) => (),
        _ => panic!("Expected InvalidConfigXMLStructure error"),
    }
}

#[test]
fn test_service_enable_with_multiple_services() {
    let services = ServicesConfig {
        services: vec![
            ServiceConfig {
                name: "graph".to_string(),
                value: true,
            },
            ServiceConfig {
                name: "exchange".to_string(),
                value: false,
            },
            ServiceConfig {
                name: "resources".to_string(),
                value: true,
            },
        ],
    };
    let config = Config {
        tenant: "test".to_string(),
        app_id: "test".to_string(),
        services: Some(services),
        proxy: None,
        output_files: Some(false),
        output_mla: Some(false),
        output: None,
        no_check: None,
        use_device_code: None,
        listener_address: None,
        listener_port: None,
        schema_file: None,
        schema_url_override: None,
        user_agent: None,
        trace_logs: None,
        use_application_credentials: None,
        application_credentials: None,
        concurrency_min_window: None,
        concurrency_max_window: None,
        dispatch_burst_cap: None,
        http_timeout_seconds: None,
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
        default_retry_after_seconds: Some(30),
        emergency_accounts_custom_attributes: None,
        additional_mla_keys: None,
        logs_days_filter: None,
        shuffle_urls: None,
        concurrency_slow_start: None,
        response_workers_max: None,
        response_memory_budget_bytes: None,
        expected_error_breaker_threshold: None,
    };

    assert!(Config::service_enable(&config, &"graph".to_string()));
    assert!(!Config::service_enable(&config, &"exchange".to_string()));
    assert!(Config::service_enable(&config, &"resources".to_string()));
    assert!(!Config::service_enable(&config, &"nonexistent".to_string()));
}

#[test]
fn test_config_with_proxy() {
    let proxy = ProxyConfig {
        url: "http://proxy.example.com:8080".to_string(),
        username: Some("user".to_string()),
        password: Some("pass".to_string()),
    };
    let config = Config {
        tenant: "test".to_string(),
        app_id: "test".to_string(),
        services: None,
        proxy: Some(proxy),
        output_files: Some(false),
        output_mla: Some(false),
        output: None,
        no_check: None,
        use_device_code: None,
        listener_address: None,
        listener_port: None,
        schema_file: None,
        schema_url_override: None,
        user_agent: None,
        trace_logs: None,
        use_application_credentials: None,
        application_credentials: None,
        concurrency_min_window: None,
        concurrency_max_window: None,
        dispatch_burst_cap: None,
        http_timeout_seconds: None,
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
        default_retry_after_seconds: Some(30),
        emergency_accounts_custom_attributes: None,
        additional_mla_keys: None,
        logs_days_filter: None,
        shuffle_urls: None,
        concurrency_slow_start: None,
        response_workers_max: None,
        response_memory_budget_bytes: None,
        expected_error_breaker_threshold: None,
    };

    assert!(config.proxy.is_some());
    let proxy_config = config.proxy.unwrap();
    assert_eq!(proxy_config.url, "http://proxy.example.com:8080");
    assert_eq!(proxy_config.username, Some("user".to_string()));
    assert_eq!(proxy_config.password, Some("pass".to_string()));
}

#[test]
fn test_config_with_listener_settings() {
    let config = Config {
        tenant: "test".to_string(),
        app_id: "test".to_string(),
        services: None,
        proxy: None,
        output_files: Some(false),
        output_mla: Some(false),
        output: None,
        no_check: None,
        use_device_code: Some(true),
        listener_address: Some("127.0.0.1".to_string()),
        listener_port: Some("8080".to_string()),
        schema_file: None,
        schema_url_override: None,
        user_agent: None,
        trace_logs: None,
        use_application_credentials: None,
        application_credentials: None,
        concurrency_min_window: None,
        concurrency_max_window: None,
        dispatch_burst_cap: None,
        http_timeout_seconds: None,
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
        default_retry_after_seconds: Some(30),
        emergency_accounts_custom_attributes: None,
        additional_mla_keys: None,
        logs_days_filter: None,
        shuffle_urls: None,
        concurrency_slow_start: None,
        response_workers_max: None,
        response_memory_budget_bytes: None,
        expected_error_breaker_threshold: None,
    };

    assert_eq!(config.listener_address, Some("127.0.0.1".to_string()));
    assert_eq!(config.listener_port, Some("8080".to_string()));
}

#[test]
fn test_config_validation_invalid_windows() {
    let config = Config {
        tenant: "test".to_string(),
        app_id: "test".to_string(),
        services: None,
        proxy: None,
        output_files: None,
        output_mla: None,
        output: None,
        no_check: None,
        use_device_code: None,
        listener_address: None,
        listener_port: None,
        schema_file: None,
        schema_url_override: None,
        user_agent: None,
        trace_logs: None,
        use_application_credentials: None,
        application_credentials: None,
        concurrency_min_window: Some(100),
        concurrency_max_window: Some(10),
        dispatch_burst_cap: None,
        http_timeout_seconds: None,
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
        default_retry_after_seconds: Some(30),
        emergency_accounts_custom_attributes: None,
        additional_mla_keys: None,
        logs_days_filter: None,
        shuffle_urls: None,
        concurrency_slow_start: None,
        response_workers_max: None,
        response_memory_budget_bytes: None,
        expected_error_breaker_threshold: None,
    };

    let result = config.validate();
    assert!(result.is_err());
    if let Err(Error::InvalidConfigValue(msg)) = result {
        assert!(msg.contains("concurrencyMinWindow cannot be greater than concurrencyMaxWindow"));
    } else {
        panic!("Expected InvalidConfigValue error");
    }
}

/// A `dispatchBurstCap` of 0 must be rejected (it makes dispatch a silent
/// no-op that stalls the run).
#[test]
fn test_config_validate_dispatch_burst_cap_zero() {
    let mut config = default_test_config();
    config.dispatch_burst_cap = Some(0);
    match config.validate() {
        Err(Error::InvalidConfigValue(msg)) => {
            assert!(msg.contains("dispatchBurstCap must be greater than 0"));
        }
        other => panic!("Expected InvalidConfigValue, got {other:?}"),
    }
}

/// A `stallDetectionTimeout` of 0 must be rejected (it would trip stall
/// detection on every event wait).
#[test]
fn test_config_validate_stall_detection_timeout_zero() {
    let mut config = default_test_config();
    config.stall_detection_timeout = Some(0);
    match config.validate() {
        Err(Error::InvalidConfigValue(msg)) => {
            assert!(msg.contains("stallDetectionTimeout must be greater than 0"));
        }
        other => panic!("Expected InvalidConfigValue, got {other:?}"),
    }
}

/// The defaults (both unset ⇒ 256 / 600) validate cleanly.
#[test]
fn test_config_validate_dispatch_and_stall_defaults_ok() {
    let config = default_test_config();
    assert!(config.validate().is_ok());
}

#[test]
fn test_config_validate_emergency_attribute_absent() {
    let config = make_config_with_emergency_attr(None);
    assert!(config.validate().is_ok());
}

#[test]
fn test_config_validate_emergency_attribute_valid() {
    let config = make_config_with_emergency_attr(Some("Emergency.isEmergency".to_string()));
    assert!(config.validate().is_ok());
}

#[test]
fn test_config_validate_emergency_attribute_no_dot() {
    let config = make_config_with_emergency_attr(Some("NoDotHere".to_string()));
    let result = config.validate();
    assert!(result.is_err());
    if let Err(Error::InvalidConfigValue(msg)) = result {
        assert!(msg.contains("emergencyAccountsCustomAttributes"));
    } else {
        panic!("Expected InvalidConfigValue error");
    }
}

#[test]
fn test_config_validate_emergency_attribute_multiple_dots() {
    let config = make_config_with_emergency_attr(Some("a.b.c".to_string()));
    let result = config.validate();
    assert!(result.is_err());
    if let Err(Error::InvalidConfigValue(msg)) = result {
        assert!(msg.contains("emergencyAccountsCustomAttributes"));
    } else {
        panic!("Expected InvalidConfigValue error");
    }
}

#[test]
fn test_config_validate_emergency_attribute_empty_string() {
    let config = make_config_with_emergency_attr(Some("".to_string()));
    let result = config.validate();
    assert!(result.is_err());
    if let Err(Error::InvalidConfigValue(msg)) = result {
        assert!(msg.contains("emergencyAccountsCustomAttributes"));
    } else {
        panic!("Expected InvalidConfigValue error");
    }
}

#[test]
fn test_config_validate_emergency_attribute_only_dot() {
    // "." splits into ["", ""] — both parts empty, must be rejected.
    let config = make_config_with_emergency_attr(Some(".".to_string()));
    let result = config.validate();
    assert!(result.is_err());
    if let Err(Error::InvalidConfigValue(msg)) = result {
        assert!(msg.contains("emergencyAccountsCustomAttributes"));
    } else {
        panic!("Expected InvalidConfigValue error");
    }
}

#[test]
fn test_config_validate_emergency_attribute_leading_dot() {
    // ".attr" — set name part is empty, must be rejected.
    let config = make_config_with_emergency_attr(Some(".isEmergency".to_string()));
    let result = config.validate();
    assert!(result.is_err());
    if let Err(Error::InvalidConfigValue(msg)) = result {
        assert!(msg.contains("emergencyAccountsCustomAttributes"));
    } else {
        panic!("Expected InvalidConfigValue error");
    }
}

#[test]
fn test_config_validate_emergency_attribute_trailing_dot() {
    // "Set." — attribute name part is empty, must be rejected.
    let config = make_config_with_emergency_attr(Some("Emergency.".to_string()));
    let result = config.validate();
    assert!(result.is_err());
    if let Err(Error::InvalidConfigValue(msg)) = result {
        assert!(msg.contains("emergencyAccountsCustomAttributes"));
    } else {
        panic!("Expected InvalidConfigValue error");
    }
}

#[test]
fn test_config_parse_emergency_accounts_custom_attributes_from_xml() {
    use std::fs;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.xml");
    fs::write(
        &config_path,
        r#"<?xml version="1.0" encoding="utf-8"?>
<root>
  <tenant>12345678-4321-4321-4321-123456789012</tenant>
  <appId>12345678-1234-1234-1234-123456789012</appId>
  <emergencyAccountsCustomAttributes>Custom.breakGlass</emergencyAccountsCustomAttributes>
</root>"#,
    )
    .expect("Failed to write config");

    let parser =
        ConfigParser::new(&config_path.to_string_lossy()).expect("Failed to create parser");
    let config = parser.deserialize().expect("Failed to deserialize config");
    assert_eq!(
        config.emergency_accounts_custom_attributes,
        Some("Custom.breakGlass".to_string())
    );
}

#[test]
fn test_config_logs_days_filter_default() {
    let config = make_config_with_emergency_attr(None);
    assert_eq!(Config::logs_days_filter(&config), 7);
}

#[test]
fn test_config_logs_days_filter_override() {
    let mut config = make_config_with_emergency_attr(None);
    config.logs_days_filter = Some(30);
    assert_eq!(Config::logs_days_filter(&config), 30);
}

#[test]
fn test_config_logs_days_filter_zero_disables_filter() {
    let mut config = make_config_with_emergency_attr(None);
    config.logs_days_filter = Some(0);
    assert_eq!(Config::logs_days_filter(&config), 0);
}

#[test]
fn test_config_parse_logs_days_filter_from_xml() {
    use std::fs;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.xml");
    fs::write(
        &config_path,
        r#"<?xml version="1.0" encoding="utf-8"?>
<root>
  <tenant>12345678-4321-4321-4321-123456789012</tenant>
  <appId>12345678-1234-1234-1234-123456789012</appId>
  <logsDaysFilter>14</logsDaysFilter>
</root>"#,
    )
    .expect("Failed to write config");

    let parser =
        ConfigParser::new(&config_path.to_string_lossy()).expect("Failed to create parser");
    let config = parser.deserialize().expect("Failed to deserialize config");
    assert_eq!(config.logs_days_filter, Some(14));
    assert_eq!(Config::logs_days_filter(&config), 14);
}

// ── Managed Identity config validation ───────────────────────────────────────

fn make_config_with_app_creds(cred_type: &str, value: Option<&str>) -> Config {
    let mut config = Config {
        tenant: "test".to_string(),
        app_id: String::new(),
        services: None,
        proxy: None,
        output_files: None,
        output_mla: None,
        output: None,
        no_check: None,
        use_device_code: None,
        listener_address: None,
        listener_port: None,
        schema_file: None,
        schema_url_override: None,
        user_agent: None,
        trace_logs: None,
        use_application_credentials: Some(true),
        application_credentials: None,
        concurrency_min_window: None,
        concurrency_max_window: None,
        dispatch_burst_cap: None,
        http_timeout_seconds: None,
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
        default_retry_after_seconds: None,
        emergency_accounts_custom_attributes: None,
        additional_mla_keys: None,
        logs_days_filter: None,
        shuffle_urls: None,
        concurrency_slow_start: None,
        response_workers_max: None,
        response_memory_budget_bytes: None,
        expected_error_breaker_threshold: None,
    };
    config.application_credentials = Some(ApplicationCredentials {
        credential_type: cred_type.to_string(),
        value: value.map(|s| s.to_string()),
    });
    config
}

/// `managedIdentity` without `<value>` (system-assigned) passes validation.
#[test]
fn test_mi_config_value_optional_system_assigned() {
    let config = make_config_with_app_creds("managedIdentity", None);
    assert!(
        config.validate().is_ok(),
        "system-assigned MI (no value) should be valid"
    );
}

/// `managedIdentity` with a client ID (user-assigned) passes validation.
#[test]
fn test_mi_config_value_user_assigned() {
    let config = make_config_with_app_creds(
        "managedIdentity",
        Some("aabbccdd-0011-2233-4455-66778899aabb"),
    );
    assert!(
        config.validate().is_ok(),
        "user-assigned MI (with client_id value) should be valid"
    );
}

/// `use_managed_identity_auth` returns true only for managedIdentity type.
#[test]
fn test_use_managed_identity_auth_helper() {
    let mi_config = make_config_with_app_creds("managedIdentity", None);
    assert!(Config::use_managed_identity_auth(&mi_config));

    let pw_config = make_config_with_app_creds("password", Some("secret"));
    assert!(!Config::use_managed_identity_auth(&pw_config));

    let mut no_creds = mi_config.clone();
    no_creds.application_credentials = None;
    assert!(!Config::use_managed_identity_auth(&no_creds));
}

/// The "press Enter to fix prerequisites" prompt in
/// `Token::refresh` / `Token::renew` is suppressed (the run aborts fatally
/// instead of blocking on a TTY read) exactly when
/// `use_application_credentials_auth` is true — i.e. for password, certificate
/// AND managed-identity flows. Interactive flows keep the prompt. This pins the
/// predicate those guards key off, across all three flows.
#[test]
fn test_app_cred_auth_predicate_gates_prereq_prompt() {
    // password and managed-identity are both application-credential (non-interactive).
    let pw = make_config_with_app_creds("password", Some("secret"));
    assert!(Config::use_application_credentials_auth(&pw));
    let mi = make_config_with_app_creds("managedIdentity", None);
    assert!(Config::use_application_credentials_auth(&mi));

    // Interactive flow (no application credentials): the operator IS prompted.
    let mut interactive = pw.clone();
    interactive.use_application_credentials = None;
    interactive.application_credentials = None;
    assert!(!Config::use_application_credentials_auth(&interactive));
}

/// `password` type without `<value>` → `InvalidConfigValue`.
#[test]
fn test_password_config_requires_value() {
    let config = make_config_with_app_creds("password", None);
    let result = config.validate();
    assert!(
        matches!(result, Err(Error::InvalidConfigValue(_))),
        "password type without value should fail validation, got: {:?}",
        result
    );
}

/// `certificate` type with empty value → `InvalidConfigValue`.
#[test]
fn test_certificate_config_requires_non_empty_value() {
    let config = make_config_with_app_creds("certificate", Some(""));
    let result = config.validate();
    assert!(
        matches!(result, Err(Error::InvalidConfigValue(_))),
        "certificate type with empty value should fail validation, got: {:?}",
        result
    );
}

/// `certificateFile` type without value → `InvalidConfigValue`.
#[test]
fn test_certificate_file_config_requires_value() {
    let config = make_config_with_app_creds("certificateFile", None);
    let result = config.validate();
    assert!(
        matches!(result, Err(Error::InvalidConfigValue(_))),
        "certificateFile type without value should fail validation, got: {:?}",
        result
    );
}

/// XML config with `managedIdentity` and no `<value>` deserialises correctly.
#[test]
fn test_xml_managed_identity_no_value_parses() {
    use std::fs;
    use tempfile::TempDir;
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.xml");
    fs::write(
        &config_path,
        r#"<?xml version="1.0" encoding="utf-8"?>
<root>
  <tenant>12345678-4321-4321-4321-123456789012</tenant>
  <useApplicationCredentials>true</useApplicationCredentials>
  <applicationCredentials>
    <type>managedIdentity</type>
  </applicationCredentials>
</root>"#,
    )
    .expect("Failed to write config");

    let parser =
        ConfigParser::new(&config_path.to_string_lossy()).expect("Failed to create parser");
    let config = parser.deserialize().expect("Failed to deserialize config");
    let creds = config
        .application_credentials
        .as_ref()
        .expect("expected credentials");
    assert_eq!(creds.credential_type, "managedIdentity");
    assert!(creds.value.is_none(), "system-assigned MI has no value");
    assert!(config.validate().is_ok());
}

/// XML config with `managedIdentity` and a `<value>` (user-assigned) deserialises correctly.
#[test]
fn test_xml_managed_identity_with_value_parses() {
    use std::fs;
    use tempfile::TempDir;
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.xml");
    fs::write(
        &config_path,
        r#"<?xml version="1.0" encoding="utf-8"?>
<root>
  <tenant>12345678-4321-4321-4321-123456789012</tenant>
  <useApplicationCredentials>true</useApplicationCredentials>
  <applicationCredentials>
    <type>managedIdentity</type>
    <value>aabbccdd-0011-2233-4455-66778899aabb</value>
  </applicationCredentials>
</root>"#,
    )
    .expect("Failed to write config");

    let parser =
        ConfigParser::new(&config_path.to_string_lossy()).expect("Failed to create parser");
    let config = parser.deserialize().expect("Failed to deserialize config");
    let creds = config
        .application_credentials
        .as_ref()
        .expect("expected credentials");
    assert_eq!(creds.credential_type, "managedIdentity");
    assert_eq!(
        creds.value.as_deref(),
        Some("aabbccdd-0011-2233-4455-66778899aabb")
    );
    assert!(config.validate().is_ok());
}

// ─── validate() guards + fatal presentation ──────────────────────────────────

/// A config that produces NO output (outputMLA=false and outputFiles not
/// enabled) must be rejected, not run a full collection that writes nothing.
#[test]
fn validate_rejects_when_no_output_enabled() {
    let mut c = default_test_config();
    c.output_files = Some(false);
    c.output_mla = Some(false);
    assert!(
        matches!(c.validate(), Err(Error::InvalidConfigValue(_))),
        "both outputs disabled must be rejected by validate()"
    );
}

/// validate() accepts the normal output combinations: MLA on by default, or
/// files explicitly on with MLA off.
#[test]
fn validate_accepts_normal_output_combinations() {
    let mut mla_default = default_test_config();
    mla_default.output_files = Some(false);
    mla_default.output_mla = None; // MLA is on unless explicitly disabled
    assert!(mla_default.validate().is_ok(), "MLA-on (default) must pass");

    let mut files_only = default_test_config();
    files_only.output_files = Some(true);
    files_only.output_mla = Some(false);
    assert!(
        files_only.validate().is_ok(),
        "files-on / MLA-off must pass"
    );
}

/// An unknown `<service name>` is ignored with a warning, not a hard error,
/// to maintain forward-compatibility while surfacing the typo footgun.
#[test]
fn validate_accepts_unknown_service_name() {
    let mut c = default_test_config();
    c.services = Some(ServicesConfig {
        services: vec![ServiceConfig {
            name: "ressources".to_string(), // typo of "resources"
            value: true,
        }],
    });
    assert!(
        c.validate().is_ok(),
        "an unknown service name must warn, not fail validation"
    );
}

/// `InvalidConfigValue` must surface a specific title and actionable detail
/// via `FatalPresentation`, not the generic "Fatal error" fallback.
#[test]
fn invalid_config_value_has_fatal_context() {
    use oradaz::utils::errors::FatalPresentation;
    let err = Error::InvalidConfigValue("dispatchBurstCap must be greater than 0".to_string());
    assert_eq!(err.title(), "Invalid configuration value");
    assert_eq!(
        err.context().as_deref(),
        Some("dispatchBurstCap must be greater than 0")
    );
    assert!(
        !err.remediation_steps().is_empty(),
        "InvalidConfigValue should carry a remediation hint"
    );
}

// C4: both <useDeviceCode> and <useApplicationCredentials> set is a non-fatal
// misconfiguration (the router has a fixed precedence) → validate warns, not fails.
#[test]
fn test_config_validation_both_auth_flows_warns_not_fails() {
    let mut config = default_test_config();
    config.use_device_code = Some(true);
    config.use_application_credentials = Some(true);
    config.application_credentials = Some(ApplicationCredentials {
        credential_type: "password".to_string(),
        value: Some("secret".to_string()),
    });
    assert!(
        config.validate().is_ok(),
        "both auth flags should warn, not fail"
    );
}

// C2: defaultRetryAfterSeconds = 0 is applied verbatim by RateLimitManager (no
// runtime clamp), so a header-less 429 would get a 0-second cooldown / hot retry
// loop. validate() must reject it, like the other zero-budget values.
#[test]
fn test_config_validation_zero_default_retry_after_is_rejected() {
    let mut config = default_test_config();
    config.default_retry_after_seconds = Some(0);
    let err = config
        .validate()
        .expect_err("defaultRetryAfterSeconds=0 must be rejected");
    assert!(matches!(err, Error::InvalidConfigValue(_)));
}

// C3: a misspelled <serviceOverrides> service name parses but never applies →
// validate warns, not fails.
#[test]
fn test_config_validation_unknown_service_override_warns_not_fails() {
    let mut config = default_test_config();
    config.service_overrides = Some(ServiceOverrides {
        services: vec![ServiceOverride {
            name: "ressources".to_string(),
            concurrency_min_window: None,
            concurrency_max_window: None,
            rate_limit_retry_limit: None,
            rate_limit_max_wait_secs: None,
            default_retry_after_seconds: None,
            http_timeout_seconds: None,
        }],
    });
    assert!(
        config.validate().is_ok(),
        "unknown serviceOverride name should warn, not fail"
    );
}

#[test]
fn test_config_output_element_parsed() {
    use std::fs;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().expect("temp dir");
    let path = temp_dir.path().join("with-output.xml");
    fs::write(
        &path,
        r#"<?xml version="1.0" encoding="UTF-8"?>
<config>
    <tenant>11111111-1111-1111-1111-111111111111</tenant>
    <output>/tmp/oradaz-out</output>
    <outputMLA>true</outputMLA>
</config>"#,
    )
    .expect("write config");

    let config = ConfigParser::new(&path.to_string_lossy())
        .expect("parser")
        .deserialize()
        .expect("deserialize");
    assert_eq!(config.output.as_deref(), Some("/tmp/oradaz-out"));
}

#[test]
fn test_resolve_output_dir_precedence() {
    use oradaz::collect::resolve_output_dir;

    let mut config = default_test_config();
    config.output = Some("/from/xml".to_string());
    // CLI wins over the config value.
    assert_eq!(
        resolve_output_dir(Some("/from/cli"), &config),
        PathBuf::from("/from/cli")
    );
    // The config value is used when no CLI flag is given.
    assert_eq!(
        resolve_output_dir(None, &config),
        PathBuf::from("/from/xml")
    );
    // The current directory is the final fallback.
    config.output = None;
    assert_eq!(resolve_output_dir(None, &config), PathBuf::from("."));
}

#[test]
fn test_unknown_root_element_detected() {
    let xml =
        "<config><tenant>t</tenant><bogusTag>x</bogusTag><shuffleUrls>false</shuffleUrls></config>";
    assert_eq!(
        ConfigParser::unknown_root_elements(xml),
        vec!["bogusTag".to_string()]
    );
}

#[test]
fn test_unknown_root_elements_ignores_nested_and_root() {
    // Only direct children of the root are checked: a nested element inside
    // serviceOverrides must not be flagged, and the root element name is ignored.
    let xml = "<config><serviceOverrides><service name=\"graph\"><deepNested>1</deepNested></service></serviceOverrides></config>";
    assert!(ConfigParser::unknown_root_elements(xml).is_empty());
}

/// Drift guard between the `Config` struct's serde names and
/// `KNOWN_ROOT_ELEMENTS`. The XML below spells every root element the way serde
/// expects it; it must (a) deserialize — so a tag misspelled *here* shows up as
/// an unparsed field assertion failure — and (b) produce zero unknown-element
/// warnings — so a `KNOWN_ROOT_ELEMENTS` entry that drifts from the serde name
/// makes the corresponding tag below get flagged. A brand-new `Config` field is
/// guarded only by the discipline of adding it both here and to the list.
#[test]
fn test_complete_config_recognizes_every_known_element() {
    use std::fs;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("complete.xml");
    let content = r#"<?xml version="1.0" encoding="UTF-8"?>
<config>
    <tenant>12345678-1234-1234-1234-123456789012</tenant>
    <appId>12345678-1234-1234-1234-123456789012</appId>
    <services>
        <service name="resources">true</service>
    </services>
    <proxy>
        <url>http://127.0.0.1:8080</url>
    </proxy>
    <outputFiles>false</outputFiles>
    <outputMLA>true</outputMLA>
    <output>./oradaz-out</output>
    <noCheck>false</noCheck>
    <useDeviceCode>false</useDeviceCode>
    <listenerAddress>localhost</listenerAddress>
    <listenerPort>3003</listenerPort>
    <schemaFile>./schema.json</schemaFile>
    <schemaUrlOverride>https://example.invalid/schema.json</schemaUrlOverride>
    <userAgent>test-agent</userAgent>
    <emergencyAccountsCustomAttributes>EmergencySet.EmergencyAccount</emergencyAccountsCustomAttributes>
    <additionalMlaKeys>
        <MlaKey>not-a-real-key</MlaKey>
    </additionalMlaKeys>
    <traceLogs>false</traceLogs>
    <useApplicationCredentials>false</useApplicationCredentials>
    <applicationCredentials>
        <type>password</type>
        <value>secret</value>
    </applicationCredentials>
    <concurrencyMinWindow>5</concurrencyMinWindow>
    <concurrencyMaxWindow>30</concurrencyMaxWindow>
    <defaultRetryAfterSeconds>5</defaultRetryAfterSeconds>
    <httpTimeoutSeconds>30</httpTimeoutSeconds>
    <dispatchBurstCap>256</dispatchBurstCap>
    <urlRetryLimit>5</urlRetryLimit>
    <rateLimitRetryLimit>50</rateLimitRetryLimit>
    <rateLimitMaxWaitSecs>900</rateLimitMaxWaitSecs>
    <stallDetectionTimeout>900</stallDetectionTimeout>
    <httpConnectTimeoutSeconds>10</httpConnectTimeoutSeconds>
    <retryBackoffBaseMs>250</retryBackoffBaseMs>
    <retryBackoffCapMs>8000</retryBackoffCapMs>
    <prereqRecheckCacheSecs>90</prereqRecheckCacheSecs>
    <livenessCeilingSecs>900</livenessCeilingSecs>
    <serviceOverrides>
        <service name="resources">
            <concurrencyMaxWindow>20</concurrencyMaxWindow>
        </service>
    </serviceOverrides>
    <logsDaysFilter>7</logsDaysFilter>
    <shuffleUrls>true</shuffleUrls>
    <concurrencySlowStart>false</concurrencySlowStart>
    <responseWorkersMax>64</responseWorkersMax>
    <responseMemoryBudgetBytes>268435456</responseMemoryBudgetBytes>
    <expectedErrorBreakerThreshold>25</expectedErrorBreakerThreshold>
</config>"#;
    fs::write(&config_path, content).expect("Failed to write config");

    // Every element above must be a known root element (the scanner's only
    // input is KNOWN_ROOT_ELEMENTS, so a drifted entry flags its tag here).
    let unknown = ConfigParser::unknown_root_elements(content);
    assert!(
        unknown.is_empty(),
        "KNOWN_ROOT_ELEMENTS drifted from the Config serde names: {unknown:?}"
    );

    // And serde must actually populate the fields (ties the tags above to the
    // struct, so a tag misspelled in this test cannot pass silently). Spot
    // checks cover one field per group plus every recently added key.
    let parser =
        ConfigParser::new(&config_path.to_string_lossy()).expect("Failed to create parser");
    let config = parser.deserialize().expect("complete config deserializes");
    assert_eq!(config.tenant, "12345678-1234-1234-1234-123456789012");
    assert_eq!(config.output.as_deref(), Some("./oradaz-out"));
    assert_eq!(config.http_connect_timeout_seconds, Some(10));
    assert_eq!(config.retry_backoff_base_ms, Some(250));
    assert_eq!(config.retry_backoff_cap_ms, Some(8000));
    assert_eq!(config.liveness_ceiling_secs, Some(900));
    assert_eq!(config.shuffle_urls, Some(true));
    assert_eq!(config.concurrency_slow_start, Some(false));
    assert_eq!(config.response_workers_max, Some(64));
    assert_eq!(config.response_memory_budget_bytes, Some(268435456));
    assert_eq!(config.expected_error_breaker_threshold, Some(25));
    assert!(config.services.is_some());
    assert!(config.proxy.is_some());
    assert!(config.application_credentials.is_some());
    assert!(config.additional_mla_keys.is_some());
    assert!(config.service_overrides.is_some());
}

#[test]
fn test_extended_fixture_has_no_unknown_root_elements() {
    // Converse drift guard: the comprehensive fixture exercises most config
    // elements, so a Config field added (and exercised here) without a matching
    // KNOWN_ROOT_ELEMENTS entry would surface as an unexpected "unknown element".
    let content = std::fs::read_to_string(get_fixture_path("valid-config-extended.xml"))
        .expect("read extended fixture");
    let unknown = ConfigParser::unknown_root_elements(&content);
    assert!(
        unknown.is_empty(),
        "extended fixture has unexpected unknown root elements (drifted KNOWN_ROOT_ELEMENTS?): {unknown:?}"
    );
}

#[test]
fn test_config_validation_liveness_below_maxwait_warns_not_fails() {
    let mut config = default_test_config();
    config.liveness_ceiling_secs = Some(300);
    config.rate_limit_max_wait_secs = Some(900);
    assert!(
        config.validate().is_ok(),
        "livenessCeilingSecs below rateLimitMaxWaitSecs should warn, not fail"
    );
}

#[test]
fn test_additional_mla_keys_parsed() {
    use std::fs;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().expect("temp dir");
    let path = temp_dir.path().join("mla-keys.xml");
    fs::write(
        &path,
        r#"<?xml version="1.0" encoding="UTF-8"?>
<config>
    <tenant>11111111-1111-1111-1111-111111111111</tenant>
    <outputMLA>true</outputMLA>
    <additionalMlaKeys>
        <MlaKeyFile>/keys/a.pub</MlaKeyFile>
        <MlaKeyFile>/keys/b.pub</MlaKeyFile>
        <MlaKey>raw-public-key</MlaKey>
    </additionalMlaKeys>
</config>"#,
    )
    .expect("write config");

    let config = ConfigParser::new(&path.to_string_lossy())
        .expect("parser")
        .deserialize()
        .expect("deserialize");
    let keys = config
        .additional_mla_keys
        .expect("additionalMlaKeys block expected");
    assert_eq!(
        keys.key_files,
        Some(vec!["/keys/a.pub".to_string(), "/keys/b.pub".to_string()])
    );
    assert_eq!(keys.keys, Some(vec!["raw-public-key".to_string()]));
}
