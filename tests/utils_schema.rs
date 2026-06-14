use oradaz::VERSION;
use oradaz::collect::auth::tokens::Token;
use oradaz::collect::dump::conditions::ConditionChecker;
use oradaz::utils::client::OradazClient;
use oradaz::utils::config::Config;
use oradaz::utils::errors::Error;
use oradaz::utils::schema::{
    Schema, SchemaModel, SchemaVersion, Service, validate_success_http_codes,
};
use oradaz::utils::url::{Api, Relationship};
use oradaz::utils::writer::actor::spawn_writer_task;

use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Mirrors the schema SHA-256 hashing in `Schema::deserialize` (lowercase hex).
fn digest(input: String) -> String {
    Sha256::digest(input.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn test_schema_version_creation() {
    let version = SchemaVersion {
        oradaz_version: "3.0.0".to_string(),
        schema_version: "1.0.0".to_string(),
    };

    assert_eq!(version.oradaz_version, "3.0.0");
    assert_eq!(version.schema_version, "1.0.0");
}

#[test]
fn test_schema_model_creation() {
    let services = vec![];
    let model = SchemaModel {
        oradaz_version: "3.0.0".to_string(),
        schema_version: "1.0.0".to_string(),
        services,
    };

    assert_eq!(model.oradaz_version, "3.0.0");
    assert_eq!(model.schema_version, "1.0.0");
    assert_eq!(model.services.len(), 0);
}

#[test]
fn test_schema_creation() {
    let services = vec![];
    let schema = Schema {
        oradaz_version: "3.0.0".to_string(),
        schema_hash: "abc123def456".to_string(),
        schema_version: "1.0.0".to_string(),
        services,
    };

    assert_eq!(schema.oradaz_version, "3.0.0");
    assert_eq!(schema.schema_version, "1.0.0");
    assert_eq!(schema.schema_hash, "abc123def456");
}

#[test]
fn test_schema_with_services() {
    let service = Service {
        name: "graph".to_string(),
        client_id: None,
        scopes: vec!["https://graph.microsoft.com/.default".to_string()],
        mandatory_auth: true,
        url_scheme: "https://graph.microsoft.com".to_string(),
        default_api_behavior: std::collections::HashMap::new(),
        default_parameters: None,
        apis: vec![],
    };

    let schema = Schema {
        oradaz_version: "3.0.0".to_string(),
        schema_hash: "xyz789".to_string(),
        schema_version: "1.0.0".to_string(),
        services: vec![service],
    };

    assert_eq!(schema.services.len(), 1);
    assert_eq!(schema.services[0].name, "graph");
}

#[test]
fn test_service_creation() {
    let service = Service {
        name: "exchange".to_string(),
        client_id: Some("client-123".to_string()),
        scopes: vec!["https://outlook.office365.com/.default".to_string()],
        mandatory_auth: false,
        url_scheme: "https://graph.microsoft.com".to_string(),
        default_api_behavior: std::collections::HashMap::new(),
        default_parameters: None,
        apis: vec![],
    };

    assert_eq!(service.name, "exchange");
    assert_eq!(service.client_id, Some("client-123".to_string()));
    assert!(!service.mandatory_auth);
}

#[test]
fn test_schema_hash_different_for_different_content() {
    let schema_str1 = r#"{"oradaz_version":"3.0.0","schema_version":"1.0.0","services":[]}"#;
    let schema_str2 = r#"{"oradaz_version":"3.0.0","schema_version":"1.0.1","services":[]}"#;

    let hash1 = digest(schema_str1.to_string());
    let hash2 = digest(schema_str2.to_string());

    assert_ne!(hash1, hash2);
}

#[test]
fn test_schema_hash_same_for_same_content() {
    let schema_str = r#"{"oradaz_version":"3.0.0","schema_version":"1.0.0","services":[]}"#;

    let hash1 = digest(schema_str.to_string());
    let hash2 = digest(schema_str.to_string());

    assert_eq!(hash1, hash2);
}

#[test]
fn test_schema_deserialize_valid_schema() {
    let schema_json = format!(
        r#"{{
        "oradaz_version": "{VERSION}",
        "schema_version": "1.0.0",
        "services": [
            {{
                "name": "graph",
                "scopes": ["https://graph.microsoft.com/.default"],
                "mandatory_auth": true,
                "url_scheme": "https://graph.microsoft.com",
                "default_api_behavior": {{}},
                "apis": [
                    {{
                        "name": "applications",
                        "uri": "/v1.0/applications",
                        "method": "GET",
                        "url_behavior": {{}}
                    }}
                ]
            }}
        ]
    }}"#
    );

    let schema = Schema::deserialize(schema_json).unwrap();
    assert_eq!(schema.oradaz_version, VERSION);
    assert_eq!(schema.schema_version, "1.0.0");
    assert_eq!(schema.services.len(), 1);
    assert_eq!(schema.services[0].name, "graph");
}

#[test]
fn test_schema_deserialize_wrong_version() {
    let schema_json = r#"{
        "oradaz_version": "2.0.0",
        "schema_version": "1.0.0",
        "services": []
    }"#;

    let result = Schema::deserialize(schema_json.to_string());
    assert!(result.is_err());
    if let Err(Error::NotLastVersion) = result {
        // Expected
    } else {
        panic!("Expected NotLastVersion error");
    }
}

#[test]
fn test_schema_deserialize_missing_version() {
    let schema_json = r#"{
        "schema_version": "1.0.0",
        "services": []
    }"#;

    let result = Schema::deserialize(schema_json.to_string());
    assert!(result.is_err());
    if let Err(Error::SchemaFileParsing) = result {
        // Expected
    } else {
        panic!("Expected SchemaFileParsing error");
    }
}

#[test]
fn test_schema_deserialize_invalid_json() {
    let invalid_json = r#"{"invalid": json"#;

    let result = Schema::deserialize(invalid_json.to_string());
    assert!(result.is_err());
    if let Err(Error::SchemaFileParsing) = result {
        // Expected
    } else {
        panic!("Expected SchemaFileParsing error");
    }
}

#[test]
fn test_schema_deserialize_tolerates_malformed_success_http_code() {
    // A non-numeric success_http_code must NOT reject the schema: the load-time
    // validator only warns, and the request path falls back to 200. This pins the
    // behaviour-preserving contract (and exercises the validator on the load path).
    let schema_json = format!(
        r#"{{
        "oradaz_version": "{VERSION}",
        "schema_version": "1.0.0",
        "services": [
            {{
                "name": "graph",
                "scopes": ["https://graph.microsoft.com/.default"],
                "mandatory_auth": true,
                "url_scheme": "https://graph.microsoft.com",
                "default_api_behavior": {{}},
                "apis": [
                    {{
                        "name": "applications",
                        "uri": "/v1.0/applications",
                        "api_behavior": {{ "success_http_code": "not_a_number" }}
                    }}
                ]
            }}
        ]
    }}"#
    );

    let schema = Schema::deserialize(schema_json)
        .expect("malformed success_http_code must not reject the schema");
    assert_eq!(schema.services.len(), 1);
    assert_eq!(schema.services[0].apis.len(), 1);
}

/// Builds a `Relationship` with only `name`/`uri`/`api_behavior` set.
fn rel_with_behavior(
    name: &str,
    behavior: Option<HashMap<String, String>>,
    children: Option<Vec<Relationship>>,
) -> Relationship {
    Relationship {
        name: name.to_string(),
        uri: format!("uri/{name}"),
        conditions: None,
        api_behavior: behavior,
        parameters: None,
        keys: None,
        relationships: children,
        expected_error_codes: None,
    }
}

fn behavior(code: &str) -> HashMap<String, String> {
    HashMap::from([("success_http_code".to_string(), code.to_string())])
}

#[test]
fn test_validate_success_http_codes_flags_all_levels() {
    // Malformed at the service default, at the API, and one relationship deep;
    // a valid code at the intermediate relationship must NOT be flagged.
    let nested = rel_with_behavior("child", Some(behavior("oops")), None);
    let rel = rel_with_behavior("rel", Some(behavior("201")), Some(vec![nested]));
    let service = Service {
        name: "graph".to_string(),
        client_id: None,
        scopes: vec![],
        mandatory_auth: true,
        url_scheme: "https://graph.microsoft.com".to_string(),
        default_api_behavior: behavior("bad"),
        default_parameters: None,
        apis: vec![Api {
            name: "applications".to_string(),
            uri: "/v1.0/applications".to_string(),
            conditions: None,
            api_behavior: Some(behavior("abc")),
            parameters: None,
            relationships: Some(vec![rel]),
            expected_error_codes: None,
        }],
    };

    let mut malformed = validate_success_http_codes(&[service]);
    malformed.sort();
    assert_eq!(
        malformed,
        vec![
            "graph/<default>".to_string(),
            "graph/applications".to_string(),
            "graph/applications/rel/child".to_string(),
        ]
    );
}

#[test]
fn test_validate_success_http_codes_accepts_valid_and_absent() {
    let with_valid = Api {
        name: "with_code".to_string(),
        uri: "/v1.0/x".to_string(),
        conditions: None,
        api_behavior: Some(behavior("200")),
        parameters: None,
        relationships: None,
        expected_error_codes: None,
    };
    let without = Api {
        name: "no_code".to_string(),
        uri: "/v1.0/y".to_string(),
        conditions: None,
        api_behavior: None,
        parameters: None,
        relationships: None,
        expected_error_codes: None,
    };
    let service = Service {
        name: "graph".to_string(),
        client_id: None,
        scopes: vec![],
        mandatory_auth: true,
        url_scheme: "https://graph.microsoft.com".to_string(),
        default_api_behavior: HashMap::new(),
        default_parameters: None,
        apis: vec![with_valid, without],
    };
    assert!(validate_success_http_codes(&[service]).is_empty());
}

#[tokio::test]
async fn test_schema_get_urls_with_service_filtering() {
    let services = vec![
        Service {
            name: "graph".to_string(),
            client_id: None,
            scopes: vec!["https://graph.microsoft.com/.default".to_string()],
            mandatory_auth: true,
            url_scheme: "https://graph.microsoft.com".to_string(),
            default_api_behavior: HashMap::new(),
            default_parameters: None,
            apis: vec![Api {
                name: "applications".to_string(),
                uri: "/v1.0/applications".to_string(),
                conditions: None,
                api_behavior: None,
                parameters: None,
                relationships: None,
                expected_error_codes: None,
            }],
        },
        Service {
            name: "exchange".to_string(),
            client_id: None,
            scopes: vec!["https://outlook.office365.com/.default".to_string()],
            mandatory_auth: false,
            url_scheme: "https://graph.microsoft.com".to_string(),
            default_api_behavior: HashMap::new(),
            default_parameters: None,
            apis: vec![Api {
                name: "mailboxes".to_string(),
                uri: "/v1.0/users/mailboxes".to_string(),
                conditions: None,
                api_behavior: None,
                parameters: None,
                relationships: None,
                expected_error_codes: None,
            }],
        },
    ];

    let schema = Schema {
        oradaz_version: VERSION.to_string(),
        schema_hash: "test".to_string(),
        schema_version: "1.0.0".to_string(),
        services,
    };

    let mut tokens = HashMap::new();
    tokens.insert(
        Arc::from("graph"),
        Token {
            tenant_id: "test-tenant".to_string(),
            client_id: "test-client".to_string(),
            service: "graph".to_string(),
            expires_on: 1234567890,
            access_token: "test_token".to_string(),
            refresh_token: None,
            token_type: "Bearer".to_string(),
            user_id: "user123".to_string(),
            user_principal_name: "user@example.com".to_string(),
            scopes: vec!["https://graph.microsoft.com/.default".to_string()],
        },
    );

    // Mock condition checker
    let config = Config {
        tenant: "test-tenant".to_string(),
        app_id: "test-app".to_string(),
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
    let condition_checker = ConditionChecker {
        client: OradazClient::new(&config).unwrap(),
        tenant_conditions: HashMap::new(),
        user_conditions: DashMap::new(),
        emergency_accounts_custom_attributes: String::from("Emergency.isEmergency"),
        org_url: "https://graph.microsoft.com/v1.0/organization".to_string(),
        stats: std::sync::Arc::new(oradaz::utils::stats::Stats::new()),
        is_application_auth: false,
    };

    let urls = schema
        .get_urls(
            "test-tenant".to_string(),
            &tokens,
            &condition_checker,
            None,
            true,
        )
        .await;

    // Should have entries for all services, but only graph should have URLs (has token)
    assert!(urls.contains_key("graph"));
    assert!(urls.contains_key("exchange"));
    assert!(!urls.get("graph").unwrap().is_empty()); // graph has token, should have URLs
    assert!(urls.get("exchange").unwrap().is_empty()); // exchange has no token, should have empty URLs
}

#[tokio::test]
async fn test_schema_get_urls_empty_when_no_tokens() {
    let services = vec![Service {
        name: "graph".to_string(),
        client_id: None,
        scopes: vec!["https://graph.microsoft.com/.default".to_string()],
        mandatory_auth: true,
        url_scheme: "https://graph.microsoft.com".to_string(),
        default_api_behavior: HashMap::new(),
        default_parameters: None,
        apis: vec![Api {
            name: "applications".to_string(),
            uri: "/v1.0/applications".to_string(),
            conditions: None,
            api_behavior: None,
            parameters: None,
            relationships: None,
            expected_error_codes: None,
        }],
    }];

    let schema = Schema {
        oradaz_version: VERSION.to_string(),
        schema_hash: "test".to_string(),
        schema_version: "1.0.0".to_string(),
        services,
    };

    let tokens = HashMap::new(); // No tokens

    let config = Config {
        tenant: "test-tenant".to_string(),
        app_id: "test-app".to_string(),
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
    let condition_checker = ConditionChecker {
        client: OradazClient::new(&config).unwrap(),
        tenant_conditions: HashMap::new(),
        user_conditions: DashMap::new(),
        emergency_accounts_custom_attributes: String::from("Emergency.isEmergency"),
        org_url: "https://graph.microsoft.com/v1.0/organization".to_string(),
        stats: std::sync::Arc::new(oradaz::utils::stats::Stats::new()),
        is_application_auth: false,
    };

    let urls = schema
        .get_urls(
            "test-tenant".to_string(),
            &tokens,
            &condition_checker,
            None,
            true,
        )
        .await;

    // Should have entries for all services, but all URL lists should be empty (no tokens)
    assert!(urls.contains_key("graph"));
    assert!(urls.get("graph").unwrap().is_empty());
}

// Schema::new HTTP tests
fn valid_schema_json() -> String {
    serde_json::json!({
        "oradaz_version": VERSION,
        "schema_version": "1.0.0",
        "services": []
    })
    .to_string()
}

fn make_mla_name() -> String {
    "12345678-4321-4321-4321-123456789012_20260413-120000".to_string()
}

fn make_minimal_config() -> Config {
    Config {
        tenant: "test-tenant".to_string(),
        app_id: "test-app".to_string(),
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

#[tokio::test]
async fn test_schema_new_fetches_from_http() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/schema.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(valid_schema_json()))
        .mount(&mock)
        .await;

    let temp_dir = TempDir::new().unwrap();
    let name = make_mla_name();
    let config = Config {
        output_files: Some(true),
        output_mla: Some(false),
        output: None,
        schema_url_override: Some(format!("{}/schema.json", mock.uri())),
        ..make_minimal_config()
    };
    let client = OradazClient::new(&config).unwrap();
    let (writer, _task) =
        spawn_writer_task(config.clone(), temp_dir.path().to_path_buf(), name.clone())
            .await
            .unwrap();

    let result = Schema::new(&config, &writer, &client).await;
    assert!(result.is_ok(), "Schema::new should succeed");
    assert_eq!(result.unwrap().oradaz_version, VERSION);
}

#[tokio::test]
async fn test_schema_new_http_error_returns_cannot_download() {
    let temp_dir = TempDir::new().unwrap();
    let name = make_mla_name();
    let config = Config {
        output_files: Some(false),
        output_mla: Some(false),
        output: None,
        schema_url_override: Some("http://127.0.0.1:19998/schema.json".to_string()),
        ..make_minimal_config()
    };
    let client = OradazClient::new(&config).unwrap();
    let (writer, _task) =
        spawn_writer_task(config.clone(), temp_dir.path().to_path_buf(), name.clone())
            .await
            .unwrap();
    let result = Schema::new(&config, &writer, &client).await;
    assert!(matches!(result, Err(Error::CannotDownloadSchemaFile)));
}

#[tokio::test]
async fn test_schema_new_http_500_returns_cannot_download() {
    let mock = MockServer::start().await;
    // A non-2xx response (with a non-schema body) must surface as a clear
    // download failure, not be read as schema JSON and reported as a
    // version/parse error.
    Mock::given(method("GET"))
        .and(path("/schema.json"))
        .respond_with(ResponseTemplate::new(500).set_body_string("<html>Server Error</html>"))
        .mount(&mock)
        .await;

    let temp_dir = TempDir::new().unwrap();
    let name = make_mla_name();
    let config = Config {
        output_files: Some(false),
        output_mla: Some(false),
        output: None,
        schema_url_override: Some(format!("{}/schema.json", mock.uri())),
        ..make_minimal_config()
    };
    let client = OradazClient::new(&config).unwrap();
    let (writer, _task) =
        spawn_writer_task(config.clone(), temp_dir.path().to_path_buf(), name.clone())
            .await
            .unwrap();

    let result = Schema::new(&config, &writer, &client).await;
    assert!(
        matches!(result, Err(Error::CannotDownloadSchemaFile)),
        "HTTP 500 must yield CannotDownloadSchemaFile"
    );
}

#[tokio::test]
async fn test_schema_new_retries_on_429_then_succeeds() {
    let mock = MockServer::start().await;
    // Higher priority (1 < default 5) + up_to_n_times(1): serves only the first
    // request (429), then the 200 mock below handles the retry.
    Mock::given(method("GET"))
        .and(path("/schema.json"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/schema.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(valid_schema_json()))
        .mount(&mock)
        .await;

    let temp_dir = TempDir::new().unwrap();
    let name = make_mla_name();
    let config = Config {
        output_files: Some(false),
        output_mla: Some(false),
        output: None,
        schema_url_override: Some(format!("{}/schema.json", mock.uri())),
        ..make_minimal_config()
    };
    let client = OradazClient::new(&config).unwrap();
    let (writer, _task) =
        spawn_writer_task(config.clone(), temp_dir.path().to_path_buf(), name.clone())
            .await
            .unwrap();

    let result = Schema::new(&config, &writer, &client).await;
    assert!(result.is_ok(), "Schema::new should succeed after 429 retry");
    assert_eq!(result.unwrap().oradaz_version, VERSION);
}

#[tokio::test]
async fn test_schema_new_exhausts_429_retries() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/schema.json"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
        .mount(&mock)
        .await;

    let temp_dir = TempDir::new().unwrap();
    let name = make_mla_name();
    let config = Config {
        output_files: Some(false),
        output_mla: Some(false),
        output: None,
        schema_url_override: Some(format!("{}/schema.json", mock.uri())),
        ..make_minimal_config()
    };
    let client = OradazClient::new(&config).unwrap();
    let (writer, _task) =
        spawn_writer_task(config.clone(), temp_dir.path().to_path_buf(), name.clone())
            .await
            .unwrap();

    let result = Schema::new(&config, &writer, &client).await;
    assert!(
        matches!(result, Err(Error::CannotDownloadSchemaFile)),
        "Expected CannotDownloadSchemaFile after exhausting 429 retries"
    );
}

// ── Condition placement guard (regression: object-reading conditions wired at
// key level on a `value:"id"` key receive the id *string*, so a `pointer("/…")`
// lookup always returns false and the relationship URL is never generated). The
// schema is editable out-of-band, so this test is the only thing preventing
// recurrence. Object-reading conditions must live at the relationship level
// (full parent object); only string/sub-object readers may sit at key level.
fn collect_key_level_object_conditions(
    rels: &serde_json::Value,
    path: &str,
    out: &mut Vec<String>,
) {
    // Conditions whose checker inspects fields of the full parent object.
    const OBJECT_READING: &[&str] = &[
        "UnifiedGroup",
        "IsAssignableToRole",
        "HasLicense",
        "IsFederated",
        "IsManaged",
        "IsEnabledMember",
    ];
    let Some(arr) = rels.as_array() else { return };
    for rel in arr {
        let name = rel.get("name").and_then(|n| n.as_str()).unwrap_or("?");
        let rel_path = format!("{path}/{name}");
        if let Some(keys) = rel.get("keys").and_then(|k| k.as_array()) {
            for key in keys {
                if let Some(conds) = key.get("conditions").and_then(|c| c.as_array()) {
                    for c in conds.iter().filter_map(|c| c.as_str()) {
                        if OBJECT_READING.contains(&c) {
                            out.push(format!("{rel_path} (key {:?}) -> {c}", key.get("name")));
                        }
                    }
                }
            }
        }
        if let Some(child) = rel.get("relationships") {
            collect_key_level_object_conditions(child, &rel_path, out);
        }
    }
}

#[test]
fn test_object_reading_conditions_never_at_key_level() {
    for file in ["schema.json", "schema-light.json"] {
        let full_path = format!("{}/{file}", env!("CARGO_MANIFEST_DIR"));
        let raw = std::fs::read_to_string(&full_path)
            .unwrap_or_else(|e| panic!("cannot read {full_path}: {e}"));
        let schema: serde_json::Value =
            serde_json::from_str(&raw).unwrap_or_else(|e| panic!("invalid JSON in {file}: {e}"));

        let mut offenders = Vec::new();
        if let Some(services) = schema.get("services").and_then(|s| s.as_array()) {
            for svc in services {
                let svc_name = svc.get("name").and_then(|n| n.as_str()).unwrap_or("?");
                if let Some(apis) = svc.get("apis").and_then(|a| a.as_array()) {
                    for api in apis {
                        let api_name = api.get("name").and_then(|n| n.as_str()).unwrap_or("?");
                        if let Some(rels) = api.get("relationships") {
                            collect_key_level_object_conditions(
                                rels,
                                &format!("{svc_name}/{api_name}"),
                                &mut offenders,
                            );
                        }
                    }
                }
            }
        }

        assert!(
            offenders.is_empty(),
            "{file}: object-reading conditions must be relationship-level, found at key level: {offenders:?}"
        );
    }
}

// Proves the guard above can actually go red — a regression detector only ever
// observed green is worthless. The offending condition is nested one relationship
// deep, which also verifies the walk recurses into child `relationships`.
#[test]
fn test_key_level_object_condition_detector_flags_mis_wiring() {
    let rels = serde_json::json!([
        {
            "name": "parent",
            "uri": "groups",
            "keys": [ { "name": "[1]", "value": "id" } ],
            "relationships": [
                {
                    "name": "misWiredChild",
                    "uri": "groups/[1]/permissionGrants",
                    "keys": [
                        {
                            "name": "[1]",
                            "value": "id",
                            "conditions": ["UnifiedGroup"]
                        }
                    ]
                }
            ]
        }
    ]);
    let mut out = Vec::new();
    collect_key_level_object_conditions(&rels, "graph/test", &mut out);
    assert_eq!(
        out.len(),
        1,
        "detector must flag the nested mis-wiring: {out:?}"
    );
    assert!(
        out[0].contains("misWiredChild") && out[0].contains("UnifiedGroup"),
        "offender must name the nested relationship and condition: {out:?}"
    );
}

/// The two reference schemas shipped at the repository root must deserialize
/// with the crate's parser (version lockstep with `VERSION` included), and
/// `schema-light.json` must remain a strict subset of `schema.json`: every
/// endpoint of light (apis and nested relationships, identified by their
/// table-name composition `parent_child`) exists in the full schema. A
/// light-only endpoint would collect data the reference schema cannot
/// validate against.
#[test]
fn test_root_schemas_deserialize_and_light_is_subset() {
    fn endpoints(schema: &Schema) -> std::collections::BTreeSet<String> {
        fn walk(
            prefix: &str,
            name: &str,
            rels: &Option<Vec<Relationship>>,
            out: &mut std::collections::BTreeSet<String>,
        ) {
            let label = if prefix.is_empty() {
                name.to_string()
            } else {
                format!("{prefix}_{name}")
            };
            if let Some(rels) = rels {
                for r in rels {
                    walk(&label, &r.name, &r.relationships, out);
                }
            }
            out.insert(label);
        }
        let mut out = std::collections::BTreeSet::new();
        for service in &schema.services {
            for api in &service.apis {
                walk("", &api.name, &api.relationships, &mut out);
            }
        }
        out
    }

    let root = env!("CARGO_MANIFEST_DIR");
    let full_raw = std::fs::read_to_string(format!("{root}/schema.json"))
        .expect("schema.json must exist at the repository root");
    let light_raw = std::fs::read_to_string(format!("{root}/schema-light.json"))
        .expect("schema-light.json must exist at the repository root");

    let full = Schema::deserialize(full_raw).expect("schema.json must deserialize");
    let light = Schema::deserialize(light_raw).expect("schema-light.json must deserialize");

    let full_eps = endpoints(&full);
    let light_eps = endpoints(&light);
    let light_only: Vec<&String> = light_eps.difference(&full_eps).collect();
    assert!(
        light_only.is_empty(),
        "schema-light.json has endpoints absent from schema.json: {light_only:?}"
    );
    assert!(
        light_eps.len() < full_eps.len(),
        "schema-light.json must be a strict subset of schema.json"
    );
}
