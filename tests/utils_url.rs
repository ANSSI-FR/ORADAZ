use oradaz::utils::errors::Error;
use oradaz::utils::schema::Service;
use oradaz::utils::url::{
    Api, ApiCall, ApiCallItem, BatchData, ExpectedErrorCode, GraphPostData, Parameter,
    PostBatchData, RelationshipUrl, RetryLimits, Url,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;

fn test_limits(retry: usize) -> RetryLimits {
    RetryLimits {
        retry,
        rate_limit_retry: 50,
        rate_limit_max_wait_secs: 900,
    }
}

#[test]
fn test_parameter_creation() {
    let param = Parameter {
        name: "tenant_id".to_string(),
        value: "12345678-1234-1234-1234-123456789012".to_string(),
        transform: None,
        conditions: None,
    };

    assert_eq!(param.name, "tenant_id");
    assert_eq!(param.value, "12345678-1234-1234-1234-123456789012");
    assert!(param.transform.is_none());
    assert!(param.conditions.is_none());
}

#[test]
fn test_parameter_with_transform() {
    let param = Parameter {
        name: "[BASE64_VALUE]".to_string(),
        value: "secret".to_string(),
        transform: Some("Base64".to_string()),
        conditions: None,
    };

    assert_eq!(param.transform, Some("Base64".to_string()));
}

#[test]
fn test_expected_error_code_creation() {
    let error_code = ExpectedErrorCode {
        status: 404,
        code: Some("NotFound".to_string()),
        breaker_eligible: false,
    };

    assert_eq!(error_code.status, 404);
    assert_eq!(error_code.code, Some("NotFound".to_string()));
}

#[test]
fn test_expected_error_code_without_code() {
    let error_code = ExpectedErrorCode {
        status: 429,
        code: None,
        breaker_eligible: false,
    };

    assert_eq!(error_code.status, 429);
    assert!(error_code.code.is_none());
}

#[test]
fn test_url_structure_creation() {
    let url = Url {
        service_name: "graph".to_string(),
        service_scopes: Arc::new(vec!["https://graph.microsoft.com/.default".to_string()]),
        service_mandatory_auth: true,
        api: "applications".to_string(),
        url: "https://graph.microsoft.com/v1.0/applications".to_string(),
        conditions: None,
        relationships: Arc::new(vec![]),
        api_behavior: Arc::new(HashMap::new()),
        expected_error_codes: None,
        parent: None,
        retry_number: 0,
        rate_limit_retry_number: 0,
        rate_limit_total_wait_secs: 0,
        network_retry_number: 0,
        post_body: None,
    };

    assert_eq!(url.service_name, "graph");
    assert_eq!(url.api, "applications");
    assert_eq!(url.retry_number, 0);
    assert!(url.service_mandatory_auth); // Authentication is mandatory
}

/// `Url` is embedded in `DumpError.post_data` (via `BatchData::initial_data`)
/// and so ends up serialized in `errors.json`. Older archives have payloads
/// without the new `rate_limit_*` fields; the `#[serde(default)]` annotations
/// must keep them deserializable.
#[test]
fn test_url_deserializes_without_rate_limit_fields() {
    let json = serde_json::json!({
        "service_name": "graph",
        "service_scopes": [],
        "service_mandatory_auth": true,
        "api": "users",
        "url": "https://graph.microsoft.com/v1.0/users",
        "conditions": null,
        "relationships": [],
        "api_behavior": {},
        "expected_error_codes": null,
        "parent": null,
        "retry_number": 2
    });
    let url: Url = serde_json::from_value(json).expect("Url must deserialize without new fields");
    assert_eq!(url.retry_number, 2);
    assert_eq!(url.rate_limit_retry_number, 0);
    assert_eq!(url.rate_limit_total_wait_secs, 0);
}

/// Wrapping `Url`'s static fields in `Arc` must NOT change the serialized JSON.
/// `Url` itself is never persisted (the URL pool stays in memory; `errors.json`
/// stores `serde_json::Value`, not `Url`), so this transparency is defensive
/// rather than load-bearing for any current on-disk format — it keeps a future
/// `Url` serialization byte-identical to the unwrapped form. The serde `rc`
/// feature serializes `Arc<T>` as bare `T` (and `Option<Arc<Vec>>` as
/// null/array), so the shape must be identical to the unwrapped form: bare
/// arrays/objects, no `Arc`/`Rc` wrapper.
#[test]
fn url_arc_fields_serialize_without_wrapper() {
    let mut api_behavior = HashMap::new();
    api_behavior.insert("k".to_string(), "v".to_string());
    let url = Url {
        service_name: "graph".to_string(),
        service_scopes: Arc::new(vec!["scope-a".to_string()]),
        service_mandatory_auth: true,
        api: "users".to_string(),
        url: "https://graph.microsoft.com/v1.0/users".to_string(),
        conditions: None,
        relationships: Arc::new(vec![]),
        api_behavior: Arc::new(api_behavior),
        expected_error_codes: Some(Arc::new(vec![ExpectedErrorCode {
            status: 404,
            code: Some("NotFound".to_string()),
            breaker_eligible: false,
        }])),
        parent: None,
        retry_number: 0,
        rate_limit_retry_number: 0,
        rate_limit_total_wait_secs: 0,
        network_retry_number: 0,
        post_body: None,
    };
    let v: serde_json::Value = serde_json::to_value(&url).expect("serialize");
    // Arc-wrapped fields serialize as the bare value.
    assert_eq!(v["service_scopes"], serde_json::json!(["scope-a"]));
    assert_eq!(v["relationships"], serde_json::json!([]));
    assert_eq!(v["api_behavior"], serde_json::json!({ "k": "v" }));
    assert_eq!(
        v["expected_error_codes"],
        serde_json::json!([{ "status": 404, "code": "NotFound" }])
    );
    // And the JSON round-trips back to an equal Url.
    let back: Url = serde_json::from_value(v).expect("deserialize");
    assert_eq!(*back.service_scopes, vec!["scope-a".to_string()]);
    assert_eq!(back.api_behavior.get("k"), Some(&"v".to_string()));
    assert_eq!(back.expected_error_codes.as_ref().unwrap().len(), 1);
}

#[test]
fn test_url_with_conditions() {
    let conditions = vec!["P1_License".to_string(), "PIM_Active".to_string()];
    let url = Url {
        service_name: "graph".to_string(),
        service_scopes: Arc::new(vec![]),
        service_mandatory_auth: false,
        api: "roleEligibilitySchedule".to_string(),
        url: "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules"
            .to_string(),
        conditions: Some(conditions.clone()),
        relationships: Arc::new(vec![]),
        api_behavior: Arc::new(HashMap::new()),
        expected_error_codes: None,
        parent: None,
        retry_number: 0,
        rate_limit_retry_number: 0,
        rate_limit_total_wait_secs: 0,
        network_retry_number: 0,
        post_body: None,
    };

    assert_eq!(url.conditions, Some(conditions));
}

#[test]
fn test_url_retry_increment() {
    let mut url = Url {
        service_name: "graph".to_string(),
        service_scopes: Arc::new(vec![]),
        service_mandatory_auth: false,
        api: "applications".to_string(),
        url: "https://graph.microsoft.com/v1.0/applications".to_string(),
        conditions: None,
        relationships: Arc::new(vec![]),
        api_behavior: Arc::new(HashMap::new()),
        expected_error_codes: None,
        parent: None,
        retry_number: 0,
        rate_limit_retry_number: 0,
        rate_limit_total_wait_secs: 0,
        network_retry_number: 0,
        post_body: None,
    };

    assert_eq!(url.retry_number, 0);
    url.retry_number += 1;
    assert_eq!(url.retry_number, 1);
}

#[test]
fn test_api_structure_creation() {
    let api = Api {
        name: "applications".to_string(),
        uri: "/v1.0/applications".to_string(),
        conditions: None,
        api_behavior: None,
        parameters: None,
        relationships: None,
        expected_error_codes: None,
    };

    assert_eq!(api.name, "applications");
    assert_eq!(api.uri, "/v1.0/applications");
}

#[test]
fn test_api_with_behavior() {
    let mut behavior = HashMap::new();
    behavior.insert("batch_size".to_string(), "20".to_string());

    let api = Api {
        name: "users".to_string(),
        uri: "/v1.0/users".to_string(),
        conditions: None,
        api_behavior: Some(behavior.clone()),
        parameters: None,
        relationships: None,
        expected_error_codes: None,
    };

    assert_eq!(api.api_behavior, Some(behavior));
}

#[test]
fn test_relationship_url_get_parent_with_keys() {
    let keys = vec![
        Parameter {
            name: "id".to_string(),
            value: "id".to_string(),
            transform: None,
            conditions: None,
        },
        Parameter {
            name: "displayName".to_string(),
            value: "displayName".to_string(),
            transform: None,
            conditions: None,
        },
    ];

    let relationship = RelationshipUrl {
        service: "graph".to_string(),
        url_scheme: "https://graph.microsoft.com".to_string(),
        default_api_behavior: HashMap::new(),
        default_parameters: None,
        api: "applications".to_string(),
        name: "owners".to_string(),
        uri: "/v1.0/applications/{id}/owners".to_string(),
        conditions: None,
        api_behavior: None,
        expected_error_codes: None,
        keys: Some(keys),
        parameters: None,
        relationships: None,
    };

    let parent_data = serde_json::json!({
        "id": "app-123",
        "displayName": "Test App"
    });

    let parent_keys = relationship.get_parent(&parent_data, 0);
    assert_eq!(parent_keys.get("id"), Some(&"app-123".to_string()));
    assert_eq!(
        parent_keys.get("displayName"),
        Some(&"Test App".to_string())
    );
}

// A mailbox is addressed by its unique directory identifier (`Guid`): the
// relationship key drives both the request URL and the `_ORADAZ_PARENT_` tag.
// The tag therefore carries `Guid` (the unique join key) and no other field.
#[test]
fn test_relationship_url_get_parent_mailbox_addressed_by_guid() {
    let keys = vec![Parameter {
        name: "[1]".to_string(),
        value: "Guid".to_string(),
        transform: Some("Base64".to_string()),
        conditions: None,
    }];

    let relationship = RelationshipUrl {
        service: "exchange".to_string(),
        url_scheme: "https://outlook.office365.com".to_string(),
        default_api_behavior: HashMap::new(),
        default_parameters: None,
        api: "mailboxes".to_string(),
        name: "mailboxPermissions".to_string(),
        uri: "Mailbox('[1]')/MailboxPermission".to_string(),
        conditions: None,
        api_behavior: None,
        expected_error_codes: None,
        keys: Some(keys),
        parameters: None,
        relationships: None,
    };

    let parent_data = serde_json::json!({
        "Guid": "11111111-2222-3333-4444-555555555555",
        "UserPrincipalName": "ambiguous@contoso.com"
    });

    let parent_keys = relationship.get_parent(&parent_data, 0);
    assert_eq!(
        parent_keys.get("Guid"),
        Some(&"11111111-2222-3333-4444-555555555555".to_string())
    );
    // Only the declared addressing key reaches the tag; the (possibly
    // non-unique) UPN is intentionally absent.
    assert!(!parent_keys.contains_key("UserPrincipalName"));
}

#[test]
fn test_relationship_url_get_parent_missing_key() {
    let keys = vec![
        Parameter {
            name: "id".to_string(),
            value: "id".to_string(),
            transform: None,
            conditions: None,
        },
        Parameter {
            name: "missingField".to_string(),
            value: "missingField".to_string(),
            transform: None,
            conditions: None,
        },
    ];

    let relationship = RelationshipUrl {
        service: "graph".to_string(),
        url_scheme: "https://graph.microsoft.com".to_string(),
        default_api_behavior: HashMap::new(),
        default_parameters: None,
        api: "applications".to_string(),
        name: "owners".to_string(),
        uri: "/v1.0/applications/{id}/owners".to_string(),
        conditions: None,
        api_behavior: None,
        expected_error_codes: None,
        keys: Some(keys),
        parameters: None,
        relationships: None,
    };

    let parent_data = serde_json::json!({
        "id": "app-123"
    });

    let parent_keys = relationship.get_parent(&parent_data, 0);
    assert_eq!(parent_keys.get("id"), Some(&"app-123".to_string()));
    assert!(!parent_keys.contains_key("missingField"));
}

#[test]
fn test_relationship_url_get_parent_non_string_value() {
    let keys = vec![Parameter {
        name: "count".to_string(),
        value: "count".to_string(),
        transform: None,
        conditions: None,
    }];

    let relationship = RelationshipUrl {
        service: "graph".to_string(),
        url_scheme: "https://graph.microsoft.com".to_string(),
        default_api_behavior: HashMap::new(),
        default_parameters: None,
        api: "applications".to_string(),
        name: "owners".to_string(),
        uri: "/v1.0/applications/{id}/owners".to_string(),
        conditions: None,
        api_behavior: None,
        expected_error_codes: None,
        keys: Some(keys),
        parameters: None,
        relationships: None,
    };

    let parent_data = serde_json::json!({
        "count": 42
    });

    let parent_keys = relationship.get_parent(&parent_data, 0);
    assert!(!parent_keys.contains_key("count")); // Non-string values are skipped
}

#[test]
fn test_url_pagination_nextlink_extraction() {
    // Test that nextLink URLs are properly constructed
    let _base_url = Url {
        service_name: "graph".to_string(),
        service_scopes: Arc::new(vec![]),
        service_mandatory_auth: false,
        api: "users".to_string(),
        url: "https://graph.microsoft.com/v1.0/users".to_string(),
        conditions: None,
        relationships: Arc::new(vec![]),
        api_behavior: Arc::new(HashMap::new()),
        expected_error_codes: None,
        parent: None,
        retry_number: 0,
        rate_limit_retry_number: 0,
        rate_limit_total_wait_secs: 0,
        network_retry_number: 0,
        post_body: None,
    };

    let next_link = "https://graph.microsoft.com/v1.0/users?$skiptoken=abc123";
    let paginated_url = Url {
        service_name: "graph".to_string(),
        service_scopes: Arc::new(vec![]),
        service_mandatory_auth: false,
        api: "users".to_string(),
        url: next_link.to_string(),
        conditions: None,
        relationships: Arc::new(vec![]),
        api_behavior: Arc::new(HashMap::new()),
        expected_error_codes: None,
        parent: None,
        retry_number: 0,
        rate_limit_retry_number: 0,
        rate_limit_total_wait_secs: 0,
        network_retry_number: 0,
        post_body: None,
    };

    // Verify the URL contains the pagination token
    assert!(paginated_url.url.contains("$skiptoken"));
    assert!(paginated_url.url.contains("abc123"));
}

#[test]
fn test_parameter_transform_base64() {
    let _parameter = Parameter {
        name: "[BASE64_VALUE]".to_string(),
        value: "secret".to_string(),
        transform: Some("Base64".to_string()),
        conditions: None,
    };

    // Test that base64 transform works
    let expected_b64 = URL_SAFE.encode("secret".as_bytes());
    assert_eq!(expected_b64, "c2VjcmV0");
}

#[test]
fn test_parameter_transform_split_backslash_first() {
    let _parameter = Parameter {
        name: "[FIRST_PART]".to_string(),
        value: "domain\\user".to_string(),
        transform: Some("SplitBackslashFirstAndBase64".to_string()),
        conditions: None,
    };

    // Test split and base64 transform
    let first_part = "domain\\user".split('\\').collect::<Vec<&str>>()[0];
    let expected_b64 = URL_SAFE.encode(first_part.as_bytes());
    assert_eq!(expected_b64, "ZG9tYWlu");
}

#[test]
fn test_parameter_transform_add_backslash_and_base64() {
    let _parameter = Parameter {
        name: "[WITH_BACKSLASH]".to_string(),
        value: "user".to_string(),
        transform: Some("AddBackslashAndBase64".to_string()),
        conditions: None,
    };

    // Test add backslash and base64 transform
    let with_backslash = format!("\\{}", "user");
    let expected_b64 = URL_SAFE.encode(with_backslash.as_bytes());
    assert_eq!(expected_b64, "XHVzZXI=");
}

#[test]
fn test_batch_data_creation() {
    let mut batch_data = BatchData {
        post_data: HashMap::new(),
        initial_data: HashMap::new(),
        id_field: "id".to_string(),
        body_field: "body".to_string(),
        status_field: "status".to_string(),
        retry_after_field: "headers/Retry-After".to_string(),
    };

    let url = Url {
        service_name: "resources".to_string(),
        service_scopes: Arc::new(vec![]),
        service_mandatory_auth: false,
        api: "subscriptions".to_string(),
        url: "https://management.azure.com/subscriptions".to_string(),
        conditions: None,
        relationships: Arc::new(vec![]),
        api_behavior: Arc::new(HashMap::new()),
        expected_error_codes: None,
        parent: None,
        retry_number: 0,
        rate_limit_retry_number: 0,
        rate_limit_total_wait_secs: 0,
        network_retry_number: 0,
        post_body: None,
    };

    batch_data.initial_data.insert(
        "1".to_string(),
        ApiCall {
            id: 0,
            url: url.clone(),
            success_code: 200,
            value_pointer: "/value".to_string(),
            is_batch: false,
            batch_data: None,
        },
    );

    assert_eq!(batch_data.initial_data.len(), 1);
    assert!(batch_data.initial_data.contains_key("1"));
}

#[test]
fn test_api_call_creation() {
    let url = Url {
        service_name: "graph".to_string(),
        service_scopes: Arc::new(vec![]),
        service_mandatory_auth: false,
        api: "applications".to_string(),
        url: "https://graph.microsoft.com/v1.0/applications".to_string(),
        conditions: None,
        relationships: Arc::new(vec![]),
        api_behavior: Arc::new(HashMap::new()),
        expected_error_codes: None,
        parent: None,
        retry_number: 0,
        rate_limit_retry_number: 0,
        rate_limit_total_wait_secs: 0,
        network_retry_number: 0,
        post_body: None,
    };

    let api_call = ApiCall {
        id: 0,
        url,
        success_code: 200,
        value_pointer: "/value".to_string(),
        is_batch: false,
        batch_data: None,
    };

    assert_eq!(api_call.success_code, 200);
    assert_eq!(api_call.value_pointer, "/value");
    assert!(!api_call.is_batch);
    assert!(api_call.batch_data.is_none());
}

#[test]
fn test_api_call_with_batch_data() {
    let url = Url {
        service_name: "resources".to_string(),
        service_scopes: Arc::new(vec![]),
        service_mandatory_auth: false,
        api: "subscriptions".to_string(),
        url: "https://management.azure.com/subscriptions".to_string(),
        conditions: None,
        relationships: Arc::new(vec![]),
        api_behavior: Arc::new(HashMap::new()),
        expected_error_codes: None,
        parent: None,
        retry_number: 0,
        rate_limit_retry_number: 0,
        rate_limit_total_wait_secs: 0,
        network_retry_number: 0,
        post_body: None,
    };

    let batch_data = BatchData {
        post_data: HashMap::new(),
        initial_data: HashMap::new(),
        id_field: "id".to_string(),
        body_field: "body".to_string(),
        status_field: "status".to_string(),
        retry_after_field: "headers/Retry-After".to_string(),
    };

    let api_call = ApiCall {
        id: 0,
        url,
        success_code: 200,
        value_pointer: "/responses".to_string(),
        is_batch: true,
        batch_data: Some(batch_data),
    };

    assert!(api_call.is_batch);
    assert!(api_call.batch_data.is_some());
    assert_eq!(api_call.value_pointer, "/responses");
}

// RelationshipUrl transform tests
use oradaz::collect::auth::tokens::Token;
use oradaz::collect::dump::conditions::ConditionChecker;
use oradaz::utils::client::OradazClient;
use oradaz::utils::config::Config;

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
        response_workers_max: None,
        response_memory_budget_bytes: None,
        expected_error_breaker_threshold: None,
        concurrency_slow_start: None,
    }
}

fn make_checker_no_http() -> ConditionChecker {
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

fn make_rel_url(url_scheme: &str, uri: &str) -> RelationshipUrl {
    RelationshipUrl {
        service: "graph".to_string(),
        url_scheme: url_scheme.to_string(),
        default_api_behavior: HashMap::new(),
        default_parameters: None,
        api: "test_api".to_string(),
        name: "test_rel".to_string(),
        uri: uri.to_string(),
        conditions: None,
        api_behavior: None,
        expected_error_codes: None,
        parameters: None,
        keys: None,
        relationships: None,
    }
}

fn make_token_with_tenant(tenant: &str) -> Token {
    Token {
        tenant_id: tenant.to_string(),
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

#[tokio::test]
async fn test_relationship_url_get_url_base64_transform() {
    let mut rel = make_rel_url("https://graph.microsoft.com[URI]", "/v1.0/search/[VALUE]");
    rel.keys = Some(vec![Parameter {
        name: "[VALUE]".to_string(),
        value: "userPrincipalName".to_string(),
        transform: Some("Base64".to_string()),
        conditions: None,
    }]);
    let token = make_token_with_tenant("test-tenant");
    let data = serde_json::json!({ "userPrincipalName": "user@domain.com" });
    let checker = make_checker_no_http();

    let result = rel.get_url(&token, &data, String::new(), &checker, 0).await;
    let expected = URL_SAFE.encode("user@domain.com".as_bytes());
    assert!(
        result.contains(&expected),
        "Expected base64 in URL, got: {result}"
    );
}

#[tokio::test]
async fn test_relationship_url_get_url_arg_resource_id_path_not_encoded() {
    // An ARM resource `id` used as a `[1]/...` path prefix must keep its `/`
    // separators. Encoding them yields `%2Fsubscriptions%2F...` and breaks
    // Azure Resource Graph relationships (roleManagementPolicies,
    // roleAssignments, …) with 400 InvalidBatchRequestUrl.
    let mut rel = make_rel_url(
        "https://management.azure.com[URI]",
        "[1]/providers/Microsoft.Authorization/roleManagementPolicies",
    );
    rel.keys = Some(vec![Parameter {
        name: "[1]".to_string(),
        value: "id".to_string(),
        transform: None,
        conditions: None,
    }]);
    let token = make_token_with_tenant("test-tenant");
    let data = serde_json::json!({
        "id": "/subscriptions/b7d3a8b8-be41-4cb2-b73e-e34fd09c06a4/resourceGroups/RG/providers/Microsoft.Compute/virtualMachines/vm1"
    });
    let checker = make_checker_no_http();

    let result = rel.get_url(&token, &data, String::new(), &checker, 0).await;
    assert!(
        !result.contains("%2F"),
        "Resource-id path separators must not be percent-encoded: {result}"
    );
    assert_eq!(
        result,
        "https://management.azure.com/subscriptions/b7d3a8b8-be41-4cb2-b73e-e34fd09c06a4/resourceGroups/RG/providers/Microsoft.Compute/virtualMachines/vm1/providers/Microsoft.Authorization/roleManagementPolicies"
    );
}

#[tokio::test]
async fn test_relationship_url_get_url_urlencode_transform_encodes_segment() {
    // A single-segment key that opts in via `transform: "UrlEncode"` (e.g. a
    // management-group `name`) must percent-encode path-unsafe characters so they
    // cannot break the URL structure.
    let mut rel = make_rel_url(
        "https://management.azure.com[URI]",
        "providers/Microsoft.Management/managementGroups/[1]/descendants",
    );
    rel.keys = Some(vec![Parameter {
        name: "[1]".to_string(),
        value: "name".to_string(),
        transform: Some("UrlEncode".to_string()),
        conditions: None,
    }]);
    let token = make_token_with_tenant("test-tenant");
    let data = serde_json::json!({ "name": "a/b c" });
    let checker = make_checker_no_http();

    let result = rel.get_url(&token, &data, String::new(), &checker, 0).await;
    assert!(
        result.contains("managementGroups/a%2Fb%20c/descendants"),
        "UrlEncode key must percent-encode unsafe chars: {result}"
    );
}

#[tokio::test]
async fn test_relationship_url_get_url_split_backslash_first_and_base64() {
    let mut rel = make_rel_url("https://example.com[URI]", "/search/[FIRST]");
    rel.keys = Some(vec![Parameter {
        name: "[FIRST]".to_string(),
        value: "sam".to_string(),
        transform: Some("SplitBackslashFirstAndBase64".to_string()),
        conditions: None,
    }]);
    let token = make_token_with_tenant("t");
    let data = serde_json::json!({ "sam": "DOMAIN\\user" });
    let checker = make_checker_no_http();

    let result = rel.get_url(&token, &data, String::new(), &checker, 0).await;
    let expected = URL_SAFE.encode("DOMAIN".as_bytes());
    assert!(result.contains(&expected), "Got: {result}");
}

#[tokio::test]
async fn test_relationship_url_get_url_split_backslash_second_and_base64() {
    let mut rel = make_rel_url("https://example.com[URI]", "/search/[SECOND]");
    rel.keys = Some(vec![Parameter {
        name: "[SECOND]".to_string(),
        value: "sam".to_string(),
        transform: Some("SplitBackslashSecondAndBase64".to_string()),
        conditions: None,
    }]);
    let token = make_token_with_tenant("t");
    let data = serde_json::json!({ "sam": "DOMAIN\\user" });
    let checker = make_checker_no_http();

    let result = rel.get_url(&token, &data, String::new(), &checker, 0).await;
    let expected = URL_SAFE.encode("\\user".as_bytes());
    assert!(result.contains(&expected), "Got: {result}");
}

#[tokio::test]
async fn test_relationship_url_get_url_add_backslash_and_base64() {
    let mut rel = make_rel_url("https://example.com[URI]", "/search/[BACK]");
    rel.keys = Some(vec![Parameter {
        name: "[BACK]".to_string(),
        value: "username".to_string(),
        transform: Some("AddBackslashAndBase64".to_string()),
        conditions: None,
    }]);
    let token = make_token_with_tenant("t");
    let data = serde_json::json!({ "username": "alice" });
    let checker = make_checker_no_http();

    let result = rel.get_url(&token, &data, String::new(), &checker, 0).await;
    let expected = URL_SAFE.encode("\\alice".as_bytes());
    assert!(result.contains(&expected), "Got: {result}");
}

// UnifiedGroup is an *object-reading* condition (`check_if_unified_group` reads
// `/groupTypes`), so it must sit at the **relationship** level where `get_url`
// passes the full parent object — not at key level on a `value:"id"` key (which
// would feed it the id string and make it always false). See the schema's
// `permissionGrants` (groups) relationship.
#[tokio::test]
async fn test_relationship_url_get_url_unified_group_blocks_non_unified() {
    let mut rel = make_rel_url(
        "https://graph.microsoft.com[URI]",
        "/v1.0/groups/[GID]/threads",
    );
    rel.conditions = Some(vec!["UnifiedGroup".to_string()]);
    rel.keys = Some(vec![Parameter {
        name: "[GID]".to_string(),
        value: "id".to_string(),
        transform: None,
        conditions: None,
    }]);
    let token = make_token_with_tenant("t");
    let data = serde_json::json!({ "id": "group-xyz", "groupTypes": ["Security"] });
    let checker = make_checker_no_http();

    let result = rel.get_url(&token, &data, String::new(), &checker, 0).await;
    assert_eq!(result, "", "Non-Unified group must return empty string");
}

// Positive case — the path that was silently broken when UnifiedGroup was wired
// at key level: a Unified group MUST produce the URL. This fails with the old
// key-level wiring (checker received the id string → always false).
#[tokio::test]
async fn test_relationship_url_get_url_unified_group_generates_url() {
    let mut rel = make_rel_url(
        "https://graph.microsoft.com[URI]",
        "/v1.0/groups/[GID]/threads",
    );
    rel.conditions = Some(vec!["UnifiedGroup".to_string()]);
    rel.keys = Some(vec![Parameter {
        name: "[GID]".to_string(),
        value: "id".to_string(),
        transform: None,
        conditions: None,
    }]);
    let token = make_token_with_tenant("t");
    let data = serde_json::json!({ "id": "group-xyz", "groupTypes": ["Unified"] });
    let checker = make_checker_no_http();

    let result = rel.get_url(&token, &data, String::new(), &checker, 0).await;
    assert!(
        result.contains("groups/group-xyz/threads"),
        "Unified group must produce a URL, got: {result}"
    );
}

// IsAssignableToRole is likewise an object-reading condition (reads
// `/isAssignableToRole`) and must sit at the relationship level (see the
// schema's PIM-for-groups relationships).
#[tokio::test]
async fn test_relationship_url_get_url_role_assignable_generates_url() {
    let mut rel = make_rel_url(
        "https://graph.microsoft.com[URI]",
        "/v1.0/groups/[GID]/owners",
    );
    rel.conditions = Some(vec!["IsAssignableToRole".to_string()]);
    rel.keys = Some(vec![Parameter {
        name: "[GID]".to_string(),
        value: "id".to_string(),
        transform: None,
        conditions: None,
    }]);
    let token = make_token_with_tenant("t");
    let data = serde_json::json!({ "id": "group-xyz", "isAssignableToRole": true });
    let checker = make_checker_no_http();

    let result = rel.get_url(&token, &data, String::new(), &checker, 0).await;
    assert!(
        result.contains("groups/group-xyz/owners"),
        "Role-assignable group must produce a URL, got: {result}"
    );
}

#[tokio::test]
async fn test_relationship_url_get_url_role_assignable_blocks_non_assignable() {
    let mut rel = make_rel_url(
        "https://graph.microsoft.com[URI]",
        "/v1.0/groups/[GID]/owners",
    );
    rel.conditions = Some(vec!["IsAssignableToRole".to_string()]);
    rel.keys = Some(vec![Parameter {
        name: "[GID]".to_string(),
        value: "id".to_string(),
        transform: None,
        conditions: None,
    }]);
    let token = make_token_with_tenant("t");
    let data = serde_json::json!({ "id": "group-xyz", "isAssignableToRole": false });
    let checker = make_checker_no_http();

    let result = rel.get_url(&token, &data, String::new(), &checker, 0).await;
    assert_eq!(
        result, "",
        "Non-role-assignable group must return empty string"
    );
}

#[tokio::test]
async fn test_relationship_url_get_url_multiple_parameters() {
    let mut rel = make_rel_url(
        "https://graph.microsoft.com[URI]",
        "/v1.0/groups/[GID]/members/[MID]",
    );
    rel.keys = Some(vec![
        Parameter {
            name: "[GID]".to_string(),
            value: "id".to_string(),
            transform: None,
            conditions: None,
        },
        Parameter {
            name: "[MID]".to_string(),
            value: "memberId".to_string(),
            transform: None,
            conditions: None,
        },
    ]);

    let token = make_token_with_tenant("t");
    let data = serde_json::json!({ "id": "group-xyz", "memberId": "member-456" });
    let checker = make_checker_no_http();

    let result = rel.get_url(&token, &data, String::new(), &checker, 0).await;
    assert!(
        result.contains("groups/group-xyz/members/member-456"),
        "Should generate URL when multiple parameters are substituted"
    );
}

#[tokio::test]
async fn test_relationship_url_get_url_condition_not_met() {
    let mut rel = make_rel_url(
        "https://graph.microsoft.com[URI]",
        "/v1.0/groups/[GID]/members",
    );
    rel.conditions = Some(vec!["UnifiedGroup".to_string()]);
    rel.keys = Some(vec![Parameter {
        name: "[GID]".to_string(),
        value: "id".to_string(),
        transform: None,
        conditions: None,
    }]);

    let token = make_token_with_tenant("t");
    let data = serde_json::json!({ "id": "group-xyz", "groupTypes": ["Security"] });
    let checker = make_checker_no_http();

    let result = rel.get_url(&token, &data, String::new(), &checker, 0).await;
    assert_eq!(
        result, "",
        "Should return empty when relationship condition not met"
    );
}

#[tokio::test]
async fn test_relationship_url_get_url_no_double_slash() {
    let rel = make_rel_url(
        "https://graph.microsoft.com/", // trailing slash
        "/v1.0/applications",           // leading slash
    );
    let token = make_token_with_tenant("test-tenant");
    let data = serde_json::json!({});
    let checker = make_checker_no_http();

    let result = rel.get_url(&token, &data, String::new(), &checker, 0).await;
    assert!(
        !result.contains("//v1"),
        "Double slash must be collapsed: {result}"
    );
}

#[tokio::test]
async fn test_relationship_url_get_url_tenant_substitution() {
    let rel = make_rel_url(
        "https://login.microsoftonline.com[URI]",
        "/[TENANT]/v2.0/token",
    );
    let token = make_token_with_tenant("my-tenant-id");
    let data = serde_json::json!({});
    let checker = make_checker_no_http();

    let result = rel.get_url(&token, &data, String::new(), &checker, 0).await;
    assert_eq!(
        result,
        "https://login.microsoftonline.com/my-tenant-id/v2.0/token"
    );
}

#[tokio::test]
async fn test_relationship_url_get_url_keep_url_strips_query() {
    let rel = make_rel_url(
        "https://graph.microsoft.com[KEEP_URL]?$filter=x",
        "[KEEP_URL]?$select=id",
    );
    let token = make_token_with_tenant("test-tenant");
    let previous_url =
        "https://graph.microsoft.com/v1.0/groups/grp-123/members?$top=10".to_string();
    let data = serde_json::json!({});
    let checker = make_checker_no_http();

    let result = rel.get_url(&token, &data, previous_url, &checker, 0).await;
    assert!(
        result.contains("v1.0/groups/grp-123/members"),
        "Got: {result}"
    );
    assert!(result.contains("$select=id"), "Got: {result}");
    assert!(
        !result.contains("$top=10"),
        "Query params should be stripped: {result}"
    );
}

#[tokio::test]
async fn test_relationship_url_get_url_uri_substitution() {
    let mut rel = make_rel_url(
        "https://graph.microsoft.com[URI]",
        "/v1.0/applications/[APP_ID]/owners",
    );
    rel.keys = Some(vec![Parameter {
        name: "[APP_ID]".to_string(),
        value: "id".to_string(),
        transform: None,
        conditions: None,
    }]);
    let token = make_token_with_tenant("test-tenant");
    let data = serde_json::json!({ "id": "app-abc" });
    let checker = make_checker_no_http();

    let result = rel.get_url(&token, &data, String::new(), &checker, 0).await;
    assert_eq!(
        result,
        "https://graph.microsoft.com/v1.0/applications/app-abc/owners"
    );
}

// ── IsEmergency condition in RelationshipUrl ──────────────────────────────────
// Mirrors the schema's emergencySignIns relationship:
//   - key [1]           → data["id"]                            (string → URL substitution)
//   - key [PLACEHOLDER] → data["customSecurityAttributes"]      (object → condition guard only)
// The [PLACEHOLDER] key does not appear in the URI template, so its sole role is
// to gate URL generation via the IsEmergency condition.

fn make_emergency_signin_rel() -> RelationshipUrl {
    RelationshipUrl {
        service: "graph".to_string(),
        url_scheme: "https://graph.microsoft.com[URI]".to_string(),
        default_api_behavior: HashMap::new(),
        default_parameters: None,
        api: "users".to_string(),
        name: "emergencySignIns".to_string(),
        uri: "/v1.0/auditLogs/signIns?$filter=userId eq '[1]'".to_string(),
        conditions: None,
        api_behavior: None,
        expected_error_codes: None,
        parameters: None,
        keys: Some(vec![
            Parameter {
                name: "[1]".to_string(),
                value: "id".to_string(),
                transform: None,
                conditions: None,
            },
            Parameter {
                name: "[PLACEHOLDER]".to_string(),
                value: "customSecurityAttributes".to_string(),
                transform: None,
                conditions: Some(vec!["IsEmergency".to_string()]),
            },
        ]),
        relationships: None,
    }
}

#[tokio::test]
async fn test_relationship_url_is_emergency_account_generates_url() {
    let rel = make_emergency_signin_rel();
    let token = make_token_with_tenant("test-tenant");
    let data = serde_json::json!({
        "id": "user-123",
        "customSecurityAttributes": { "Emergency": { "isEmergency": true } }
    });
    let checker = make_checker_no_http();

    let result = rel.get_url(&token, &data, String::new(), &checker, 0).await;
    assert!(
        result.contains("userId eq 'user-123'"),
        "Emergency account must produce a sign-in URL, got: {result}"
    );
}

#[tokio::test]
async fn test_relationship_url_non_emergency_account_blocks_url() {
    let rel = make_emergency_signin_rel();
    let token = make_token_with_tenant("test-tenant");
    let data = serde_json::json!({
        "id": "user-456",
        "customSecurityAttributes": { "Emergency": { "isEmergency": false } }
    });
    let checker = make_checker_no_http();

    let result = rel.get_url(&token, &data, String::new(), &checker, 0).await;
    assert_eq!(result, "", "Non-emergency account must return empty string");
}

#[tokio::test]
async fn test_relationship_url_no_custom_security_attributes_blocks_url() {
    // customSecurityAttributes key is entirely absent: the outer None branch returns "".
    let rel = make_emergency_signin_rel();
    let token = make_token_with_tenant("test-tenant");
    let data = serde_json::json!({ "id": "user-789" });
    let checker = make_checker_no_http();

    let result = rel.get_url(&token, &data, String::new(), &checker, 0).await;
    assert_eq!(
        result, "",
        "Missing customSecurityAttributes must return empty string"
    );
}

#[tokio::test]
async fn test_relationship_url_empty_custom_security_attributes_blocks_url() {
    // customSecurityAttributes is present but contains no recognised attribute set.
    let rel = make_emergency_signin_rel();
    let token = make_token_with_tenant("test-tenant");
    let data = serde_json::json!({
        "id": "user-000",
        "customSecurityAttributes": {}
    });
    let checker = make_checker_no_http();

    let result = rel.get_url(&token, &data, String::new(), &checker, 0).await;
    assert_eq!(
        result, "",
        "Empty customSecurityAttributes must return empty string"
    );
}

#[tokio::test]
async fn test_relationship_url_custom_emergency_attribute_path_generates_url() {
    // Verify that a non-default attribute path configured in ConditionChecker is respected.
    let rel = make_emergency_signin_rel();
    let token = make_token_with_tenant("test-tenant");
    let data = serde_json::json!({
        "id": "user-111",
        "customSecurityAttributes": { "Breakglass": { "isBreakglass": true } }
    });
    let config = make_minimal_config();
    let checker = ConditionChecker {
        client: OradazClient::new(&config).unwrap(),
        tenant_conditions: HashMap::new(),
        user_conditions: DashMap::new(),
        emergency_accounts_custom_attributes: "Breakglass.isBreakglass".to_string(),
        org_url: "https://graph.microsoft.com/v1.0/organization".to_string(),
        stats: std::sync::Arc::new(oradaz::utils::stats::Stats::new()),
        is_application_auth: false,
    };

    let result = rel.get_url(&token, &data, String::new(), &checker, 0).await;
    assert!(
        result.contains("userId eq 'user-111'"),
        "Custom attribute path must generate URL, got: {result}"
    );
}

// ── IsEnabledMember condition in RelationshipUrl ──────────────────────────────
// Mirrors the schema's authenticationMethods relationship: a relationship-level
// `conditions: ["IsEnabledMember"]` guard that receives the full parent user
// object, gating the per-user authentication/methods call to enabled members
// (skipping guests and disabled accounts) to reduce fan-out.

fn make_authentication_methods_rel() -> RelationshipUrl {
    RelationshipUrl {
        service: "graph".to_string(),
        url_scheme: "https://graph.microsoft.com[URI]".to_string(),
        default_api_behavior: HashMap::new(),
        default_parameters: None,
        api: "users".to_string(),
        name: "authenticationMethods".to_string(),
        uri: "users/[1]/authentication/methods".to_string(),
        conditions: Some(vec!["IsEnabledMember".to_string()]),
        api_behavior: None,
        expected_error_codes: None,
        parameters: None,
        keys: Some(vec![Parameter {
            name: "[1]".to_string(),
            value: "id".to_string(),
            transform: None,
            conditions: None,
        }]),
        relationships: None,
    }
}

#[tokio::test]
async fn test_relationship_url_enabled_member_generates_url() {
    let rel = make_authentication_methods_rel();
    let token = make_token_with_tenant("test-tenant");
    let data = serde_json::json!({
        "id": "user-123",
        "accountEnabled": true,
        "userType": "Member"
    });
    let checker = make_checker_no_http();

    let result = rel.get_url(&token, &data, String::new(), &checker, 0).await;
    assert!(
        result.contains("users/user-123/authentication/methods"),
        "Enabled member must produce an authentication methods URL, got: {result}"
    );
}

#[tokio::test]
async fn test_relationship_url_guest_blocks_url() {
    let rel = make_authentication_methods_rel();
    let token = make_token_with_tenant("test-tenant");
    let data = serde_json::json!({
        "id": "user-456",
        "accountEnabled": true,
        "userType": "Guest"
    });
    let checker = make_checker_no_http();

    let result = rel.get_url(&token, &data, String::new(), &checker, 0).await;
    assert_eq!(result, "", "Guest user must return empty string");
}

#[tokio::test]
async fn test_relationship_url_disabled_account_blocks_url() {
    let rel = make_authentication_methods_rel();
    let token = make_token_with_tenant("test-tenant");
    let data = serde_json::json!({
        "id": "user-789",
        "accountEnabled": false,
        "userType": "Member"
    });
    let checker = make_checker_no_http();

    let result = rel.get_url(&token, &data, String::new(), &checker, 0).await;
    assert_eq!(result, "", "Disabled account must return empty string");
}

fn make_permission_grants_rel() -> RelationshipUrl {
    RelationshipUrl {
        service: "graph".to_string(),
        url_scheme: "https://graph.microsoft.com[URI]".to_string(),
        default_api_behavior: HashMap::new(),
        default_parameters: None,
        api: "users".to_string(),
        name: "permissionGrants".to_string(),
        uri: "users/[1]/permissionGrants".to_string(),
        conditions: Some(vec!["HasLicense".to_string()]),
        api_behavior: None,
        expected_error_codes: None,
        parameters: None,
        keys: Some(vec![Parameter {
            name: "[1]".to_string(),
            value: "id".to_string(),
            transform: None,
            conditions: None,
        }]),
        relationships: None,
    }
}

#[tokio::test]
async fn test_relationship_url_has_license_generates_url() {
    let rel = make_permission_grants_rel();
    let token = make_token_with_tenant("test-tenant");
    let data = serde_json::json!({
        "id": "user-123",
        "assignedLicenses": [{ "skuId": "abc" }]
    });
    let checker = make_checker_no_http();

    let result = rel.get_url(&token, &data, String::new(), &checker, 0).await;
    assert!(
        result.contains("users/user-123/permissionGrants"),
        "Licensed user must produce a permissionGrants URL, got: {result}"
    );
}

#[tokio::test]
async fn test_relationship_url_no_license_blocks_url() {
    let rel = make_permission_grants_rel();
    let token = make_token_with_tenant("test-tenant");
    let data = serde_json::json!({
        "id": "user-456",
        "assignedLicenses": []
    });
    let checker = make_checker_no_http();

    let result = rel.get_url(&token, &data, String::new(), &checker, 0).await;
    assert_eq!(
        result, "",
        "Unlicensed user must not produce a permissionGrants URL"
    );
}

#[tokio::test]
async fn test_relationship_url_missing_licenses_field_blocks_url() {
    let rel = make_permission_grants_rel();
    let token = make_token_with_tenant("test-tenant");
    let data = serde_json::json!({
        "id": "user-789"
    });
    let checker = make_checker_no_http();

    let result = rel.get_url(&token, &data, String::new(), &checker, 0).await;
    assert_eq!(
        result, "",
        "User missing assignedLicenses field must not produce a permissionGrants URL"
    );
}

// Helper function to create a basic Url for batch testing
fn make_graph_url(version: &str, api_name: &str, path: &str) -> Url {
    Url {
        service_name: "graph".to_string(),
        service_scopes: Arc::new(vec!["https://graph.microsoft.com/.default".to_string()]),
        service_mandatory_auth: true,
        api: api_name.to_string(),
        url: format!("https://graph.microsoft.com/{}{}", version, path),
        conditions: None,
        relationships: Arc::new(vec![]),
        api_behavior: Arc::new(HashMap::new()),
        expected_error_codes: None,
        parent: None,
        retry_number: 0,
        rate_limit_retry_number: 0,
        rate_limit_total_wait_secs: 0,
        network_retry_number: 0,
        post_body: None,
    }
}

fn make_resource_url(api_name: &str, path: &str) -> Url {
    Url {
        service_name: "resources".to_string(),
        service_scopes: Arc::new(vec!["https://management.azure.com/.default".to_string()]),
        service_mandatory_auth: true,
        api: api_name.to_string(),
        url: format!("https://management.azure.com{}", path),
        conditions: None,
        relationships: Arc::new(vec![]),
        api_behavior: Arc::new(HashMap::new()),
        expected_error_codes: None,
        parent: None,
        retry_number: 0,
        rate_limit_retry_number: 0,
        rate_limit_total_wait_secs: 0,
        network_retry_number: 0,
        post_body: None,
    }
}

fn make_exchange_url(api_name: &str, path: &str) -> Url {
    Url {
        service_name: "exchange".to_string(),
        service_scopes: Arc::new(vec!["https://outlook.office365.com/.default".to_string()]),
        service_mandatory_auth: false,
        api: api_name.to_string(),
        url: format!(
            "https://outlook.office365.com/adminapi/beta/test-tenant{}",
            path
        ),
        conditions: None,
        relationships: Arc::new(vec![]),
        api_behavior: Arc::new(HashMap::new()),
        expected_error_codes: None,
        parent: None,
        retry_number: 0,
        rate_limit_retry_number: 0,
        rate_limit_total_wait_secs: 0,
        network_retry_number: 0,
        post_body: None,
    }
}

#[test]
fn test_get_graph_next_api_call_v1_produces_batch() {
    let mut urls = vec![
        make_graph_url("v1.0", "users", "/users"),
        make_graph_url("v1.0", "users", "/users/user2"),
    ];

    let result = ApiCall::get_graph_next_api_call(&mut urls, test_limits(5));
    assert!(result.is_ok());

    let items = result.unwrap();
    assert!(!items.is_empty());

    // Should have at least one batch call for v1.0
    let has_v1_batch = items.iter().any(|item| match item {
        ApiCallItem::ApiCall(call) => call.is_batch && call.url.url.contains("v1.0/$batch"),
        ApiCallItem::ApiCallError(_) => false,
    });
    assert!(has_v1_batch, "Expected v1.0 batch call");
}

#[test]
fn test_get_graph_next_api_call_beta_separate_batch() {
    let mut urls = vec![
        make_graph_url("beta", "applications", "/applications"),
        make_graph_url("beta", "applications", "/applications/app2"),
    ];

    let result = ApiCall::get_graph_next_api_call(&mut urls, test_limits(5));
    assert!(result.is_ok());

    let items = result.unwrap();

    // Should have at least one batch call for beta
    let has_beta_batch = items.iter().any(|item| match item {
        ApiCallItem::ApiCall(call) => call.is_batch && call.url.url.contains("beta/$batch"),
        ApiCallItem::ApiCallError(_) => false,
    });
    assert!(has_beta_batch, "Expected beta batch call");
}

#[test]
fn test_get_graph_next_api_call_mixed_two_batches() {
    let mut urls = vec![
        make_graph_url("v1.0", "users", "/users"),
        make_graph_url("beta", "applications", "/applications"),
    ];

    let result = ApiCall::get_graph_next_api_call(&mut urls, test_limits(5));
    assert!(result.is_ok());

    let items = result.unwrap();

    // Should have both v1.0 and beta batches
    let batch_count = items
        .iter()
        .filter(|item| match item {
            ApiCallItem::ApiCall(call) => call.is_batch,
            ApiCallItem::ApiCallError(_) => false,
        })
        .count();
    assert_eq!(batch_count, 2, "Expected 2 batch calls (v1.0 and beta)");
}

#[test]
fn test_get_graph_next_api_call_retry_limit_error() {
    const RETRY_LIMIT: usize = 5;
    let mut urls = vec![{
        let mut url = make_graph_url("v1.0", "users", "/users");
        url.retry_number = RETRY_LIMIT; // At retry limit
        url
    }];

    let result = ApiCall::get_graph_next_api_call(&mut urls, test_limits(5));
    assert!(result.is_ok());

    let items = result.unwrap();

    // Should have an error for the retried URL
    let has_retry_error = items
        .iter()
        .any(|item| matches!(item, ApiCallItem::ApiCallError(Error::UrlRetryLimit(_))));
    assert!(has_retry_error, "Expected UrlRetryLimit error");
}

#[test]
fn test_get_graph_next_api_call_batch_url_stripped() {
    let mut urls = vec![make_graph_url("v1.0", "users", "/users")];

    let result = ApiCall::get_graph_next_api_call(&mut urls, test_limits(5));
    assert!(result.is_ok());

    let items = result.unwrap();

    // Find the batch call and check that URLs in batch data are stripped of the base URL
    for item in items {
        if let ApiCallItem::ApiCall(call) = item
            && call.is_batch
            && let Some(batch_data) = &call.batch_data
        {
            for post_data_vec in batch_data.post_data.values() {
                for post_data in post_data_vec {
                    if let oradaz::utils::url::PostBatchData::GraphPostData(gp) = post_data {
                        // URL should be relative, not containing the full domain
                        assert!(
                            !gp.url.contains("https://"),
                            "Batch URL should be relative: {}",
                            gp.url
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn test_get_resources_next_api_call_produces_batch() {
    let mut urls = vec![
        make_resource_url("subscriptions", "/subscriptions/sub1"),
        make_resource_url("subscriptions", "/subscriptions/sub2"),
    ];

    let result = ApiCall::get_resources_next_api_call(&mut urls, test_limits(5));
    assert!(result.is_ok(), "Expected Ok result");

    let items = result.unwrap();
    assert!(!items.is_empty(), "Expected at least one item");

    // Should have at least one batch call for Azure Resources
    let has_batch = items.iter().any(|item| match item {
        ApiCallItem::ApiCall(call) => call.is_batch && call.url.url.contains("batch"),
        ApiCallItem::ApiCallError(_) => false,
    });
    assert!(has_batch, "Expected batch call for Azure Resources");
}

#[test]
fn test_get_resources_next_api_call_retry_limit() {
    const RETRY_LIMIT: usize = 5;
    // Create URLs where one has retry limit and one doesn't
    let mut urls = vec![
        {
            let mut url = make_resource_url("subscriptions", "/subscriptions/sub1");
            url.retry_number = RETRY_LIMIT;
            url
        },
        make_resource_url("subscriptions", "/subscriptions/sub2"),
    ];

    let result = ApiCall::get_resources_next_api_call(&mut urls, test_limits(5));
    assert!(result.is_ok());

    let items = result.unwrap();
    // With the mixed URLs (one at limit, one below), we should get the batch call
    // The retry-limited URL will be skipped (silently), and only the valid one batched
    assert!(!items.is_empty(), "Expected batch call");
}

#[test]
fn test_get_exchange_next_api_call_produces_batch() {
    let mut urls = vec![
        make_exchange_url(
            "mailboxPermissions",
            "/Mailbox('QQ==')/MailboxPermission?isEncoded=true",
        ),
        make_exchange_url("recipients", "/Recipient('Qg==')?isEncoded=true"),
    ];

    let items = ApiCall::get_exchange_next_api_call(&mut urls, test_limits(5)).unwrap();
    assert_eq!(items.len(), 1, "Expected exactly one batch ApiCall");

    let call = match &items[0] {
        ApiCallItem::ApiCall(call) => call,
        ApiCallItem::ApiCallError(err) => panic!("Expected ApiCall, got error: {err:?}"),
    };
    assert!(call.is_batch);
    assert_eq!(
        call.url.url,
        "https://outlook.office365.com/adminapi/beta/test-tenant/$batch"
    );
    assert_eq!(call.url.service_name, "exchange");
    assert_eq!(call.url.api, "batch");
    assert_eq!(call.success_code, 200);
    assert_eq!(call.value_pointer, "/responses");

    let batch_data = call.batch_data.as_ref().unwrap();
    assert_eq!(batch_data.id_field, "id");
    assert_eq!(batch_data.body_field, "body");
    assert_eq!(batch_data.status_field, "status");
    assert_eq!(batch_data.retry_after_field, "headers/Retry-After");
    assert_eq!(batch_data.initial_data.len(), 2);

    let posts = collect_graph_post_data(&items);
    assert_eq!(posts.len(), 2);
    for gp in &posts {
        assert_eq!(gp.method, "GET");
        assert!(
            gp.headers.is_none(),
            "Exchange sub-requests carry no headers"
        );
        assert!(
            gp.url
                .starts_with("https://outlook.office365.com/adminapi/beta/test-tenant/"),
            "Exchange sub-request URL must stay absolute: {}",
            gp.url
        );
        // id ↔ initial_data mapping: each sub-request id resolves to its original URL.
        let initial = batch_data.initial_data.get(&gp.id).unwrap();
        assert_eq!(initial.url.url, gp.url);
    }
}

#[test]
fn test_get_exchange_next_api_call_max_ten_urls() {
    let mut urls: Vec<Url> = (0..12)
        .map(|i| {
            make_exchange_url(
                "mailboxPermissions",
                &format!("/Mailbox('m{}')/MailboxPermission", i),
            )
        })
        .collect();

    let items = ApiCall::get_exchange_next_api_call(&mut urls, test_limits(5)).unwrap();
    assert_eq!(urls.len(), 2, "Only 10 URLs may be consumed per batch");
    assert_eq!(items.len(), 1);

    let posts = collect_graph_post_data(&items);
    assert_eq!(
        posts.len(),
        10,
        "Batch must contain exactly 10 sub-requests"
    );
    if let ApiCallItem::ApiCall(call) = &items[0] {
        assert_eq!(call.batch_data.as_ref().unwrap().initial_data.len(), 10);
    }
}

#[test]
fn test_get_exchange_next_api_call_retry_limit_error() {
    const RETRY_LIMIT: usize = 5;
    let mut urls = vec![{
        let mut url = make_exchange_url("mailboxes", "/Mailbox?PropertySet=All");
        url.retry_number = RETRY_LIMIT;
        url
    }];

    let items = ApiCall::get_exchange_next_api_call(&mut urls, test_limits(RETRY_LIMIT)).unwrap();
    assert_eq!(items.len(), 1);
    assert!(
        matches!(
            &items[0],
            ApiCallItem::ApiCallError(Error::UrlRetryLimit(_))
        ),
        "Expected UrlRetryLimit error"
    );
    // No empty batch envelope must be emitted alongside the error.
    assert!(
        !items
            .iter()
            .any(|item| matches!(item, ApiCallItem::ApiCall(_))),
        "No batch ApiCall expected when every URL is retry-exhausted"
    );
}

#[test]
fn test_exchange_from_routes_non_adminapi_url_single() {
    let mut url = make_exchange_url("mailboxes", "/Mailbox?PropertySet=All");
    url.url = "https://outlook.office365.com/other/path".to_string();
    let mut urls = vec![url];

    let items = ApiCall::from("exchange", &mut urls, test_limits(5)).unwrap();
    assert_eq!(items.len(), 1);
    match &items[0] {
        ApiCallItem::ApiCall(call) => {
            assert!(
                !call.is_batch,
                "Non-adminapi exchange URL must dispatch single"
            );
            assert!(call.batch_data.is_none());
            assert_eq!(call.url.url, "https://outlook.office365.com/other/path");
        }
        ApiCallItem::ApiCallError(err) => panic!("Expected ApiCall, got error: {err:?}"),
    }
}

#[test]
fn test_exchange_from_routes_post_body_url_single() {
    let mut url = make_exchange_url("mailboxes", "/Mailbox?PropertySet=All");
    url.post_body = Some(serde_json::json!({"query": "test"}));
    let mut urls = vec![url];

    let items = ApiCall::from("exchange", &mut urls, test_limits(5)).unwrap();
    assert_eq!(items.len(), 1);
    match &items[0] {
        ApiCallItem::ApiCall(call) => {
            assert!(
                !call.is_batch,
                "Exchange URL with a POST body must dispatch single"
            );
            assert!(call.url.post_body.is_some());
        }
        ApiCallItem::ApiCallError(err) => panic!("Expected ApiCall, got error: {err:?}"),
    }
}

#[test]
fn test_get_exchange_next_api_call_mixed_roots_pushes_back() {
    // `pop()` consumes from the back: tenant-a is batched first and fixes the
    // root; tenant-b must be pushed back for the next dispatch pass.
    let mut url_b = make_exchange_url("mailboxes", "/Mailbox?PropertySet=All");
    url_b.url = "https://outlook.office365.com/adminapi/beta/tenant-b/Mailbox".to_string();
    let mut url_a = make_exchange_url("mailboxes", "/Mailbox?PropertySet=All");
    url_a.url = "https://outlook.office365.com/adminapi/beta/tenant-a/Mailbox".to_string();
    let mut urls = vec![url_b, url_a];

    let items = ApiCall::get_exchange_next_api_call(&mut urls, test_limits(5)).unwrap();
    assert_eq!(
        urls.len(),
        1,
        "The mismatching-root URL must be pushed back"
    );
    assert!(urls[0].url.contains("tenant-b"));

    assert_eq!(items.len(), 1);
    match &items[0] {
        ApiCallItem::ApiCall(call) => {
            assert!(call.is_batch);
            assert_eq!(
                call.url.url,
                "https://outlook.office365.com/adminapi/beta/tenant-a/$batch"
            );
            assert_eq!(call.batch_data.as_ref().unwrap().initial_data.len(), 1);
        }
        ApiCallItem::ApiCallError(err) => panic!("Expected ApiCall, got error: {err:?}"),
    }
}

#[test]
fn test_exchange_batch_post_data_serialization() {
    let mut urls = vec![make_exchange_url("mailboxes", "/Mailbox?PropertySet=All")];

    let items = ApiCall::get_exchange_next_api_call(&mut urls, test_limits(5)).unwrap();
    let mut checked = 0;
    for item in &items {
        if let ApiCallItem::ApiCall(call) = item
            && let Some(batch_data) = &call.batch_data
        {
            let json = serde_json::to_value(&batch_data.post_data).unwrap();
            let requests = json["requests"].as_array().unwrap();
            assert_eq!(requests.len(), 1);
            for req in requests {
                assert_eq!(req["id"].as_str(), Some("1"));
                assert_eq!(req["method"].as_str(), Some("GET"));
                assert_eq!(
                    req["url"].as_str(),
                    Some(
                        "https://outlook.office365.com/adminapi/beta/test-tenant/Mailbox?PropertySet=All"
                    )
                );
                assert!(
                    req.get("headers").is_none(),
                    "Exchange batch sub-request must not serialise a headers field"
                );
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 1, "Expected exactly one serialised sub-request");
}

#[test]
fn test_exchange_batch_envelope_carries_mandatory_auth() {
    let mut urls = vec![make_exchange_url("mailboxes", "/Mailbox?PropertySet=All")];

    let items = ApiCall::get_exchange_next_api_call(&mut urls, test_limits(5)).unwrap();
    assert_eq!(items.len(), 1);
    match &items[0] {
        ApiCallItem::ApiCall(call) => {
            assert!(
                !call.url.service_mandatory_auth,
                "Envelope must carry the sub-URLs' mandatory_auth (false for exchange), not a hardcoded true"
            );
        }
        ApiCallItem::ApiCallError(err) => panic!("Expected ApiCall, got error: {err:?}"),
    }
}

/// A URL that has hit the dedicated 429 retry counter is not abandoned at
/// dispatch — throttling is bounded only by the per-bucket liveness ceiling, not
/// a fixed count. With its real-error budget untouched
/// (`retry_number = 0`) the URL must flow through as a regular `ApiCall`.
#[test]
fn test_get_default_next_api_call_does_not_skip_on_rate_limit_retry() {
    let mut url = make_resource_url("subscriptions", "/subscriptions/sub1");
    url.retry_number = 0;
    url.rate_limit_retry_number = 50;
    let mut urls = vec![url];

    let limits = RetryLimits {
        retry: 5,
        rate_limit_retry: 50,
        rate_limit_max_wait_secs: 900,
    };
    let result = ApiCall::get_default_next_api_call("resources".to_string(), &mut urls, limits);
    assert!(result.is_ok());
    let items = result.unwrap();
    assert_eq!(items.len(), 1);
    assert!(
        matches!(&items[0], ApiCallItem::ApiCall(_)),
        "a 429-exhausted URL with its real-error budget left must pass through, not be abandoned"
    );
}

/// The accumulated 429 Retry-After wait likewise does not abandon a URL at
/// dispatch — it is a metric, not a death budget.
#[test]
fn test_get_default_next_api_call_does_not_skip_on_rate_limit_wait() {
    let mut url = make_resource_url("subscriptions", "/subscriptions/sub1");
    url.retry_number = 0;
    url.rate_limit_retry_number = 5;
    url.rate_limit_total_wait_secs = 1000;
    let mut urls = vec![url];

    let limits = RetryLimits {
        retry: 5,
        rate_limit_retry: 50,
        rate_limit_max_wait_secs: 900,
    };
    let result = ApiCall::get_default_next_api_call("resources".to_string(), &mut urls, limits);
    assert!(result.is_ok());
    let items = result.unwrap();
    assert_eq!(items.len(), 1);
    assert!(
        matches!(&items[0], ApiCallItem::ApiCall(_)),
        "a URL past the rate-limit wait cap must pass through, not be abandoned"
    );
}

/// Same as the default-path test, but exercising the Graph batch handler
/// (`graph` service routes through `get_graph_next_api_call` in production):
/// a 429-exhausted URL must batch normally, never emit `UrlRetryLimit`.
#[test]
fn test_get_graph_next_api_call_does_not_skip_on_rate_limit_retry() {
    let mut url = make_graph_url("v1.0", "users", "/users");
    url.rate_limit_retry_number = 50;
    let mut urls = vec![url];

    let limits = RetryLimits {
        retry: 5,
        rate_limit_retry: 50,
        rate_limit_max_wait_secs: 900,
    };
    let result = ApiCall::get_graph_next_api_call(&mut urls, limits);
    assert!(result.is_ok());
    let items = result.unwrap();
    assert!(
        !items
            .iter()
            .any(|item| matches!(item, ApiCallItem::ApiCallError(Error::UrlRetryLimit(_)))),
        "Graph batch handler must NOT abandon a 429-exhausted URL"
    );
    assert!(
        items
            .iter()
            .any(|item| matches!(item, ApiCallItem::ApiCall(_))),
        "the 429-exhausted URL must still be batched"
    );
}

/// Same as above, but for the Resources batch handler (used in production for
/// the `resources` service).
#[test]
fn test_get_resources_next_api_call_does_not_skip_on_rate_limit_wait() {
    let mut url = make_resource_url("subscriptions", "/subscriptions/sub1");
    url.rate_limit_total_wait_secs = 1000;
    let mut urls = vec![url];

    let limits = RetryLimits {
        retry: 5,
        rate_limit_retry: 50,
        rate_limit_max_wait_secs: 900,
    };
    let result = ApiCall::get_resources_next_api_call(&mut urls, limits);
    assert!(result.is_ok());
    let items = result.unwrap();
    assert!(
        !items
            .iter()
            .any(|item| matches!(item, ApiCallItem::ApiCallError(Error::UrlRetryLimit(_)))),
        "Resources batch handler must NOT abandon a URL past the wait cap"
    );
}

/// A URL with all three counters strictly below the budgets must still flow
/// through as a regular `ApiCall`, not get skipped.
#[test]
fn test_get_default_next_api_call_passes_through_below_all_budgets() {
    let mut url = make_resource_url("subscriptions", "/subscriptions/sub1");
    url.retry_number = 4;
    url.rate_limit_retry_number = 49;
    url.rate_limit_total_wait_secs = 899;
    let mut urls = vec![url];

    let limits = RetryLimits {
        retry: 5,
        rate_limit_retry: 50,
        rate_limit_max_wait_secs: 900,
    };
    let result = ApiCall::get_default_next_api_call("resources".to_string(), &mut urls, limits);
    assert!(result.is_ok());
    let items = result.unwrap();
    assert_eq!(items.len(), 1);
    assert!(
        matches!(&items[0], ApiCallItem::ApiCall(_)),
        "URL strictly below every budget must NOT be skipped"
    );
}

#[test]
fn test_get_default_next_api_call_custom_success_code() {
    let mut url = make_graph_url("v1.0", "create", "/users");
    Arc::make_mut(&mut url.api_behavior).insert("success_http_code".to_string(), "201".to_string());

    let mut urls = vec![url];

    let result = ApiCall::get_default_next_api_call("graph".to_string(), &mut urls, test_limits(5));
    assert!(result.is_ok());

    let items = result.unwrap();

    let has_201 = items.iter().any(|item| match item {
        ApiCallItem::ApiCall(call) => call.success_code == 201,
        ApiCallItem::ApiCallError(_) => false,
    });
    assert!(has_201, "Expected success_code to be 201");
}

/// Depth-first dispatch (fixed order): the dispatcher consumes the
/// per-service queue from the *tail* (`ApiCall::from` and every per-service
/// builder `urls.pop()` from the back) and truncates by the unconsumed remainder.
/// Because `status_handlers` pushes a page's `nextLink` *before* its relationship
/// children, the children (extended onto the tail) dispatch *before* the next root
/// page — a depth-first traversal that bounds the `current_urls` pool to roughly
/// one page's frontier.
///
/// The queue is longer than `MAX_BATCH_SIZE` so `tail_start > 0`, exercising the
/// `truncate(tail_start + remainder)` round-trip (not the degenerate
/// `tail_start == 0` case). A front-consumption regression would dispatch a front
/// item *and* leave it in the queue (truncating an un-consumed tail item instead)
/// — caught by the consumed-item identity + the no-duplicate assertion. See the
/// LOAD-BEARING comments in `response/status_handlers.rs`,
/// `orchestration/dispatch.rs`, and `url/api_call.rs`.
#[test]
fn dfs_dispatch_consumes_tail_child_before_nextlink() {
    // [nextLink, child0 .. child24] — 26 entries (> MAX_BATCH_SIZE = 20).
    let mut urls = vec![make_graph_url("v1.0", "nextlink", "/users?$skiptoken=abc")];
    for i in 0..25 {
        urls.push(make_graph_url(
            "v1.0",
            &format!("child{i}"),
            &format!("/u/{i}/owners"),
        ));
    }
    let before = urls.len();

    // Replicate dispatch.rs: clone the tail (<= MAX_BATCH_SIZE), consume via the
    // default handler (pops from the back), truncate by the unconsumed remainder.
    let peek_len = urls.len().min(20);
    let tail_start = urls.len() - peek_len;
    assert!(
        tail_start > 0,
        "queue must exceed MAX_BATCH_SIZE for a non-degenerate truncate offset"
    );
    let mut urls_copy = urls[tail_start..].to_vec();
    let items =
        ApiCall::get_default_next_api_call("graph".to_string(), &mut urls_copy, test_limits(5))
            .expect("get_default_next_api_call");
    urls.truncate(tail_start + urls_copy.len());

    // The *tail* child (child24) was consumed, not a front item.
    assert_eq!(items.len(), 1);
    match &items[0] {
        ApiCallItem::ApiCall(call) => assert_eq!(
            call.url.api, "child24",
            "the tail (most-recent child) must dispatch first, not the nextLink"
        ),
        ApiCallItem::ApiCallError(_) => panic!("expected an ApiCall for the tail child"),
    }
    // Exactly one item left the queue, the consumed child is gone (no duplicate),
    // and the nextLink (root page) is still at the front — dispatched last (DFS).
    assert_eq!(urls.len(), before - 1);
    assert_eq!(urls[0].api, "nextlink");
    assert!(
        !urls.iter().any(|u| u.api == "child24"),
        "consumed tail child must not remain in the queue (front-consumption would duplicate it)"
    );
}

/// Companion for the *graph* `$batch` dispatch path: real graph dispatch routes
/// through `ApiCall::from` → the batch builder (not `get_default_next_api_call`).
/// It must also drain the tail and leave the page's `nextLink` (head) for last —
/// guarding against a regression that clones the head slice instead of the tail,
/// or batches from the front.
#[test]
fn dfs_graph_batch_keeps_nextlink_at_front() {
    let mut urls = vec![make_graph_url("v1.0", "nextlink", "/users?$skiptoken=abc")];
    for i in 0..25 {
        urls.push(make_graph_url(
            "v1.0",
            &format!("child{i}"),
            &format!("/u/{i}/owners"),
        ));
    }
    let before = urls.len();

    let peek_len = urls.len().min(20);
    let tail_start = urls.len() - peek_len;
    let mut urls_copy = urls[tail_start..].to_vec();
    let _items =
        ApiCall::from("graph", &mut urls_copy, test_limits(5)).expect("graph $batch ApiCall::from");
    urls.truncate(tail_start + urls_copy.len());

    // The tail batch consumed children; the nextLink (head) stays at the front.
    assert!(
        urls.len() < before,
        "the tail batch must consume children from the queue"
    );
    assert_eq!(
        urls[0].api, "nextlink",
        "nextLink (root page) must remain at the front after a tail batch (dispatched last)"
    );
}

/// Collects every GraphPostData from the post_data of all batch ApiCalls in `items`.
fn collect_graph_post_data(items: &[ApiCallItem]) -> Vec<GraphPostData> {
    let mut out = Vec::new();
    for item in items {
        if let ApiCallItem::ApiCall(call) = item
            && let Some(batch_data) = &call.batch_data
        {
            for posts in batch_data.post_data.values() {
                for post in posts {
                    if let PostBatchData::GraphPostData(gp) = post {
                        out.push(gp.clone());
                    }
                }
            }
        }
    }
    out
}

#[test]
fn test_graph_batch_count_url_gets_consistency_level_header() {
    let mut urls = vec![make_graph_url(
        "v1.0",
        "users",
        "/users?$count=true&$select=id",
    )];

    let items = ApiCall::get_graph_next_api_call(&mut urls, test_limits(5)).unwrap();
    let posts = collect_graph_post_data(&items);
    assert!(!posts.is_empty(), "Expected at least one GraphPostData");

    for gp in &posts {
        let headers = gp
            .headers
            .as_ref()
            .expect("URL with $count=true must have headers");
        assert_eq!(
            headers.get("ConsistencyLevel").map(String::as_str),
            Some("eventual"),
            "Expected ConsistencyLevel: eventual for $count=true URL"
        );
    }
}

#[test]
fn test_graph_batch_no_count_url_has_no_consistency_level_header() {
    let mut urls = vec![make_graph_url("v1.0", "users", "/users?$select=id")];

    let items = ApiCall::get_graph_next_api_call(&mut urls, test_limits(5)).unwrap();
    let posts = collect_graph_post_data(&items);
    assert!(!posts.is_empty(), "Expected at least one GraphPostData");

    for gp in &posts {
        assert!(
            gp.headers.is_none(),
            "URL without $count=true must not carry ConsistencyLevel header"
        );
    }
}

#[test]
fn test_graph_batch_count_header_serialized_correctly() {
    let mut urls = vec![make_graph_url(
        "v1.0",
        "users",
        "/users?$count=true&$select=id",
    )];

    let items = ApiCall::get_graph_next_api_call(&mut urls, test_limits(5)).unwrap();
    // Find the batch ApiCall and serialise its post_data to JSON
    for item in &items {
        if let ApiCallItem::ApiCall(call) = item
            && let Some(batch_data) = &call.batch_data
        {
            let json = serde_json::to_value(&batch_data.post_data).unwrap();
            let requests = json["requests"].as_array().unwrap();
            for req in requests {
                let headers = req.get("headers").expect("headers field must be present");
                assert_eq!(
                    headers["ConsistencyLevel"].as_str(),
                    Some("eventual"),
                    "Serialised batch request must include ConsistencyLevel header"
                );
            }
        }
    }
}

#[test]
fn test_graph_batch_no_count_header_omitted_from_serialization() {
    let mut urls = vec![make_graph_url("v1.0", "users", "/users?$select=id")];

    let items = ApiCall::get_graph_next_api_call(&mut urls, test_limits(5)).unwrap();
    for item in &items {
        if let ApiCallItem::ApiCall(call) = item
            && let Some(batch_data) = &call.batch_data
        {
            let json = serde_json::to_value(&batch_data.post_data).unwrap();
            let requests = json["requests"].as_array().unwrap();
            for req in requests {
                assert!(
                    req.get("headers").is_none(),
                    "Batch request without $count=true must not include headers in JSON"
                );
            }
        }
    }
}

// Api::get_url date filter tests
fn make_graph_service() -> Service {
    use std::collections::HashMap;
    Service {
        name: "graph".to_string(),
        client_id: None,
        scopes: vec!["https://graph.microsoft.com/.default".to_string()],
        mandatory_auth: true,
        url_scheme: "https://graph.microsoft.com/[API_VERSION]/[URI][PARAMS]".to_string(),
        default_api_behavior: HashMap::new(),
        default_parameters: Some(vec![
            Parameter {
                name: "[API_VERSION]".to_string(),
                value: "v1.0".to_string(),
                transform: None,
                conditions: None,
            },
            Parameter {
                name: "[PARAMS]".to_string(),
                value: String::new(),
                transform: None,
                conditions: None,
            },
        ]),
        apis: vec![],
    }
}

#[tokio::test]
async fn test_api_get_url_date_filter_applied() {
    let api = Api {
        name: "directoryAudits".to_string(),
        uri: "auditLogs/directoryAudits".to_string(),
        conditions: None,
        api_behavior: None,
        parameters: Some(vec![Parameter {
            name: "[PARAMS]".to_string(),
            value: "[LOGS_DAYS_FILTER]".to_string(),
            transform: None,
            conditions: None,
        }]),
        relationships: None,
        expected_error_codes: None,
    };
    let service = make_graph_service();
    let token = make_token_with_tenant("test-tenant");
    let checker = make_checker_no_http();
    let date_filter = "?$filter=activityDateTime ge 2025-04-22T00:00:00Z";

    let result = api
        .get_url(
            &service,
            "test-tenant".to_string(),
            &token,
            &checker,
            Some(date_filter),
        )
        .await;

    let url = result.expect("should produce a Url").url;
    assert!(
        url.contains("?$filter=activityDateTime ge 2025-04-22T00:00:00Z"),
        "URL should contain date filter: {url}"
    );
    assert!(
        url.starts_with("https://graph.microsoft.com/v1.0/auditLogs/directoryAudits"),
        "URL should have correct base path: {url}"
    );
}

#[tokio::test]
async fn test_api_get_url_date_filter_none_produces_clean_url() {
    let api = Api {
        name: "directoryAudits".to_string(),
        uri: "auditLogs/directoryAudits".to_string(),
        conditions: None,
        api_behavior: None,
        parameters: Some(vec![Parameter {
            name: "[PARAMS]".to_string(),
            value: "[LOGS_DAYS_FILTER]".to_string(),
            transform: None,
            conditions: None,
        }]),
        relationships: None,
        expected_error_codes: None,
    };
    let service = make_graph_service();
    let token = make_token_with_tenant("test-tenant");
    let checker = make_checker_no_http();

    let result = api
        .get_url(&service, "test-tenant".to_string(), &token, &checker, None)
        .await;

    let url = result.expect("should produce a Url").url;
    assert_eq!(
        url, "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits",
        "URL without filter should be the bare endpoint"
    );
}

#[tokio::test]
async fn test_api_get_url_directory_audits_top_and_date_filter_combined() {
    // Mirrors the production schema: `?$top=999` is always present, and the
    // computed `[LOGS_DAYS_FILTER]` value joins it with `&$filter=…`.
    let api = Api {
        name: "directoryAudits".to_string(),
        uri: "auditLogs/directoryAudits".to_string(),
        conditions: None,
        api_behavior: None,
        parameters: Some(vec![Parameter {
            name: "[PARAMS]".to_string(),
            value: "?$top=999[LOGS_DAYS_FILTER]".to_string(),
            transform: None,
            conditions: None,
        }]),
        relationships: None,
        expected_error_codes: None,
    };
    let service = make_graph_service();
    let token = make_token_with_tenant("test-tenant");
    let checker = make_checker_no_http();
    let date_filter = "&$filter=activityDateTime ge 2025-04-22T00:00:00Z";

    let url = api
        .get_url(
            &service,
            "test-tenant".to_string(),
            &token,
            &checker,
            Some(date_filter),
        )
        .await
        .expect("should produce a Url")
        .url;

    assert_eq!(
        url,
        "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$top=999&$filter=activityDateTime ge 2025-04-22T00:00:00Z"
    );
}

#[tokio::test]
async fn test_api_get_url_directory_audits_top_only_when_filter_disabled() {
    // With date bounding disabled the `[LOGS_DAYS_FILTER]` placeholder collapses
    // to nothing, leaving a clean `?$top=999` URL.
    let api = Api {
        name: "directoryAudits".to_string(),
        uri: "auditLogs/directoryAudits".to_string(),
        conditions: None,
        api_behavior: None,
        parameters: Some(vec![Parameter {
            name: "[PARAMS]".to_string(),
            value: "?$top=999[LOGS_DAYS_FILTER]".to_string(),
            transform: None,
            conditions: None,
        }]),
        relationships: None,
        expected_error_codes: None,
    };
    let service = make_graph_service();
    let token = make_token_with_tenant("test-tenant");
    let checker = make_checker_no_http();

    let url = api
        .get_url(&service, "test-tenant".to_string(), &token, &checker, None)
        .await
        .expect("should produce a Url")
        .url;

    assert_eq!(
        url,
        "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$top=999"
    );
}
