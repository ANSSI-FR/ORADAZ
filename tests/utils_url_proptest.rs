// Property-based tests for URL transform functions.
//
// Each test calls `RelationshipUrl::get_url()` directly with a generated input
// value and verifies that ORADAZ's own encoding logic produces the expected result.
use oradaz::collect::auth::tokens::Token;
use oradaz::collect::dump::conditions::ConditionChecker;
use oradaz::utils::client::OradazClient;
use oradaz::utils::config::Config;
use oradaz::utils::url::{Parameter, RelationshipUrl};

use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use dashmap::DashMap;
use proptest::prelude::TestCaseError;
use proptest::prelude::*;
use std::collections::HashMap;

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
        default_retry_after_seconds: Some(30),
        emergency_accounts_custom_attributes: None,
        additional_mla_keys: None,
        logs_days_filter: None,
        shuffle_urls: None,
        concurrency_slow_start: None,
        response_workers_max: None,
        response_memory_budget_bytes: None,
        expected_error_breaker_threshold: None,
    }
}

fn make_token() -> Token {
    Token {
        tenant_id: "test-tenant".to_string(),
        client_id: "c".to_string(),
        service: "graph".to_string(),
        expires_on: 9_999_999_999,
        access_token: "t".to_string(),
        refresh_token: None,
        token_type: "Bearer".to_string(),
        user_id: "u".to_string(),
        user_principal_name: "u@e".to_string(),
        scopes: vec![],
    }
}

fn make_checker() -> ConditionChecker {
    ConditionChecker {
        client: OradazClient::new(&make_minimal_config()).unwrap(),
        tenant_conditions: HashMap::new(),
        user_conditions: DashMap::new(),
        emergency_accounts_custom_attributes: String::from("Emergency.isEmergency"),
        org_url: "https://graph.microsoft.com/v1.0/organization".to_string(),
        stats: std::sync::Arc::new(oradaz::utils::stats::Stats::new()),
        is_application_auth: false,
    }
}

fn make_rel_url_with_transform(transform: &str) -> RelationshipUrl {
    RelationshipUrl {
        service: "graph".to_string(),
        url_scheme: "https://example.com[URI]".to_string(),
        default_api_behavior: HashMap::new(),
        default_parameters: None,
        api: "test_api".to_string(),
        name: "test_rel".to_string(),
        uri: "/path/[VAL]".to_string(),
        conditions: None,
        api_behavior: None,
        expected_error_codes: None,
        keys: Some(vec![Parameter {
            name: "[VAL]".to_string(),
            value: "field".to_string(),
            transform: Some(transform.to_string()),
            conditions: None,
        }]),
        parameters: None,
        relationships: None,
    }
}

proptest! {
    /// Verifies that ORADAZ's Base64 transform encodes the input value
    /// correctly and that the encoding is reversible (no data loss).
    #[test]
    fn proptest_base64_transform_calls_get_url(value in r"[a-zA-Z0-9@._\-]{1,128}") {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let rel = make_rel_url_with_transform("Base64");
            let token = make_token();
            let data = serde_json::json!({ "field": value });
            let checker = make_checker();

            let result = rel.get_url(&token, &data, String::new(), &checker, 0).await;

            let expected_b64 = URL_SAFE.encode(value.as_bytes());
            prop_assert!(
                result.contains(&expected_b64),
                "Expected base64 '{}' in URL, got: {}",
                expected_b64, result
            );
            // Round-trip: decode must recover the original value
            let decoded = URL_SAFE.decode(&expected_b64).unwrap();
            prop_assert_eq!(String::from_utf8(decoded).unwrap(), value);
            Ok::<(), TestCaseError>(())
        }).unwrap();

    }

    /// Verifies that ORADAZ's SplitBackslashFirstAndBase64 transform encodes
    /// the part before the backslash correctly.
    #[test]
    fn proptest_split_backslash_first_calls_get_url(
        first in r"[A-Z]{3,10}",
        second in r"[a-z]{3,10}"
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let combined = format!("{}\\{}", first, second);
            let rel = make_rel_url_with_transform("SplitBackslashFirstAndBase64");
            let token = make_token();
            let data = serde_json::json!({ "field": combined });
            let checker = make_checker();

            let result = rel.get_url(&token, &data, String::new(), &checker, 0).await;

            let expected_b64 = URL_SAFE.encode(first.as_bytes());
            prop_assert!(
                result.contains(&expected_b64),
                "Expected base64 of first part '{}' in URL, got: {}",
                expected_b64, result
            );
            let decoded = URL_SAFE.decode(&expected_b64).unwrap();
            prop_assert_eq!(String::from_utf8(decoded).unwrap(), first);
            Ok::<(), TestCaseError>(())
        }).unwrap();

    }

    /// Verifies that ORADAZ's SplitBackslashSecondAndBase64 transform encodes
    /// the part after the backslash (with leading backslash prefix) correctly.
    #[test]
    fn proptest_split_backslash_second_calls_get_url(
        first in r"[A-Z]{3,10}",
        second in r"[a-z]{3,10}"
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let combined = format!("{}\\{}", first, second);
            let rel = make_rel_url_with_transform("SplitBackslashSecondAndBase64");
            let token = make_token();
            let data = serde_json::json!({ "field": combined });
            let checker = make_checker();

            let result = rel.get_url(&token, &data, String::new(), &checker, 0).await;

            let expected_part = format!("\\{}", second);
            let expected_b64 = URL_SAFE.encode(expected_part.as_bytes());
            prop_assert!(
                result.contains(&expected_b64),
                "Expected base64 of '{}' in URL, got: {}",
                expected_b64, result
            );
            let decoded = URL_SAFE.decode(&expected_b64).unwrap();
            prop_assert_eq!(String::from_utf8(decoded).unwrap(), expected_part);
            Ok::<(), TestCaseError>(())
        }).unwrap();

    }

    /// Verifies that ORADAZ's AddBackslashAndBase64 transform prepends a
    /// backslash before encoding correctly.
    #[test]
    fn proptest_add_backslash_calls_get_url(value in r"[a-z]{3,20}") {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let rel = make_rel_url_with_transform("AddBackslashAndBase64");
            let token = make_token();
            let data = serde_json::json!({ "field": value });
            let checker = make_checker();

            let result = rel.get_url(&token, &data, String::new(), &checker, 0).await;

            let expected_part = format!("\\{}", value);
            let expected_b64 = URL_SAFE.encode(expected_part.as_bytes());
            prop_assert!(
                result.contains(&expected_b64),
                "Expected base64 of '{}' in URL, got: {}",
                expected_b64, result
            );
            let decoded = URL_SAFE.decode(&expected_b64).unwrap();
            prop_assert_eq!(String::from_utf8(decoded).unwrap(), expected_part);
            Ok::<(), TestCaseError>(())
        }).unwrap();

    }

    #[test]
    fn proptest_non_string_ignored(
        number in any::<i64>(),
        boolean in any::<bool>()
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let rel_num = make_rel_url_with_transform("Base64");
            let data_num = serde_json::json!({ "field": number });
            let checker = make_checker();
            let result_num = rel_num.get_url(&make_token(), &data_num, String::new(), &checker, 0).await;
            prop_assert_eq!(result_num, "");

            let rel_bool = make_rel_url_with_transform("Base64");
            let data_bool = serde_json::json!({ "field": boolean });
            let result_bool = rel_bool.get_url(&make_token(), &data_bool, String::new(), &checker, 0).await;
            prop_assert_eq!(result_bool, "");
            Ok::<(), TestCaseError>(())
        }).unwrap();

    }
}
