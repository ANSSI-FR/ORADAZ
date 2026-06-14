mod common;

use std::collections::HashMap;
use std::sync::Arc;

use oradaz::collect::auth::tokens::Token;
use oradaz::collect::dump::conditions::ConditionChecker;
use oradaz::utils::client::OradazClient;
use oradaz::utils::config::Config;
use oradaz::utils::schema::Schema;
use oradaz::utils::stats::Stats;

// Helper from utils_url.rs – duplicated here to avoid cross‑file dependencies.
fn make_minimal_config() -> Config {
    Config {
        tenant: "t".to_string(),
        app_id: "a".to_string(),
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
        user_agent: None,
        trace_logs: None,
        schema_url_override: None,
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
        emergency_accounts_custom_attributes: None,
        additional_mla_keys: None,
        logs_days_filter: None,
        shuffle_urls: Some(false),
        concurrency_slow_start: None,
        response_workers_max: None,
        response_memory_budget_bytes: None,
        expected_error_breaker_threshold: None,
    }
}

fn make_checker_no_http() -> ConditionChecker {
    let cfg = make_minimal_config();
    ConditionChecker {
        client: OradazClient::new(&cfg).unwrap(),
        tenant_conditions: HashMap::new(),
        user_conditions: dashmap::DashMap::new(),
        emergency_accounts_custom_attributes: String::from("Emergency.isEmergency"),
        org_url: "https://graph.microsoft.com/v1.0/organization".to_string(),
        stats: Arc::new(Stats::new()),
        is_application_auth: false,
    }
}

#[tokio::test]
async fn test_shuffle_option_respects_order() {
    // Load the multi‑API schema fixture.
    let schema_str = common::load_fixture("tests/fixtures/schema-multi.json");
    let schema = Schema::deserialize(schema_str).expect("Schema deserialization");

    // Build a token map with a dummy token for the "graph" service.
    let token = Token {
        tenant_id: "test-tenant".to_string(),
        client_id: "cid".to_string(),
        service: "graph".to_string(),
        expires_on: 0,
        access_token: "tok".to_string(),
        refresh_token: None,
        token_type: "Bearer".to_string(),
        user_id: "uid".to_string(),
        user_principal_name: "uid@domain".to_string(),
        scopes: vec![],
    };
    let mut tokens: HashMap<Arc<str>, Token> = HashMap::new();
    tokens.insert(Arc::from("graph"), token);

    // ConditionChecker with no HTTP calls (no conditions in this fixture).
    let checker = make_checker_no_http();

    // Retrieve URLs with shuffle disabled.
    let urls_map = schema
        .get_urls("test-tenant".to_string(), &tokens, &checker, None, false)
        .await;

    let urls = urls_map.get("graph").expect("graph service present");
    // Order must match definition order: first then second.
    assert_eq!(urls.len(), 2, "Expected exactly two URLs");
    assert_eq!(urls[0].api, "first");
    assert_eq!(urls[1].api, "second");
}
