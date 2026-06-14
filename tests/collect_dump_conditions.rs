mod common;

use crate::common::default_test_config;
use oradaz::collect::auth::tokens::Token;
use oradaz::collect::dump::conditions::ConditionChecker;
use oradaz::collect::dump::conditions::tenant::{check_publishing_profiles, check_tenant_licenses};
use oradaz::utils::client::OradazClient;
use oradaz::utils::config::Config;

use dashmap::DashMap;
use rstest::rstest;
use serde_json::Value;
use std::collections::HashMap;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn create_test_token() -> Token {
    Token {
        tenant_id: "test-tenant".to_string(),
        client_id: "test-client".to_string(),
        service: "graph".to_string(),
        expires_on: 1234567890,
        access_token: "test_token".to_string(),
        refresh_token: Some("refresh_token".to_string()),
        token_type: "Bearer".to_string(),
        user_id: "user-123".to_string(),
        user_principal_name: "user@example.com".to_string(),
        scopes: vec!["https://graph.microsoft.com/.default".to_string()],
    }
}

fn create_test_condition_checker() -> ConditionChecker {
    let config = default_test_config();
    ConditionChecker {
        client: OradazClient::new(&config).unwrap(),
        tenant_conditions: HashMap::new(),
        user_conditions: DashMap::new(),
        emergency_accounts_custom_attributes: String::from("Emergency.isEmergency"),
        org_url: "https://graph.microsoft.com/v1.0/organization".to_string(),
        stats: std::sync::Arc::new(oradaz::utils::stats::Stats::new()),
        is_application_auth: false,
    }
}

#[test]
fn test_check_if_unified_group_true() {
    let checker = create_test_condition_checker();
    let unified_group = serde_json::json!({
        "groupTypes": ["Unified"]
    });
    assert!(checker.check_if_unified_group(&unified_group));
}

#[test]
fn test_check_if_unified_group_false_no_group_types() {
    let checker = create_test_condition_checker();
    let non_unified_group = serde_json::json!({
        "displayName": "Test Group"
    });
    assert!(!checker.check_if_unified_group(&non_unified_group));
}

#[test]
fn test_check_if_unified_group_false_group_types_null() {
    let checker = create_test_condition_checker();
    let non_unified_group = serde_json::json!({
        "groupTypes": null
    });
    assert!(!checker.check_if_unified_group(&non_unified_group));
}

#[test]
fn test_check_if_unified_group_false_empty_array() {
    let checker = create_test_condition_checker();
    let non_unified_group = serde_json::json!({
        "groupTypes": []
    });
    assert!(!checker.check_if_unified_group(&non_unified_group));
}

#[test]
fn test_check_if_unified_group_false_different_type() {
    let checker = create_test_condition_checker();
    let non_unified_group = serde_json::json!({
        "groupTypes": ["Security"]
    });
    assert!(!checker.check_if_unified_group(&non_unified_group));
}

#[rstest]
#[case("Inbox", true)]
#[case("SentItems", true)]
#[case("User Created", true)]
#[case("Archive", true)]
#[case("Files", true)]
#[case("Drafts", true)]
#[case("DeletedItems", true)]
#[case("OtherFolder", false)]
#[case("My_Folder-123 ", false)]
fn test_check_if_folder_require_permission_dump(#[case] folder_name: &str, #[case] expected: bool) {
    let checker = create_test_condition_checker();
    let folder_value = Value::String(folder_name.to_string());
    assert_eq!(
        checker.check_if_folder_require_permission_dump(&folder_value),
        expected
    );
}

#[test]
fn test_check_if_folder_require_permission_dump_non_string() {
    let checker = create_test_condition_checker();
    let number_value = Value::Number(serde_json::Number::from(123));
    assert!(!checker.check_if_folder_require_permission_dump(&number_value));
}

#[test]
fn test_check_if_role_assignable_true() {
    let checker = create_test_condition_checker();
    let group = serde_json::json!({
        "id": "g1",
        "isAssignableToRole": true,
    });
    assert!(checker.check_if_role_assignable(&group));
}

#[test]
fn test_check_if_role_assignable_false_when_false() {
    let checker = create_test_condition_checker();
    let group = serde_json::json!({
        "id": "g1",
        "isAssignableToRole": false,
    });
    assert!(!checker.check_if_role_assignable(&group));
}

#[test]
fn test_check_if_role_assignable_false_when_missing() {
    let checker = create_test_condition_checker();
    let group = serde_json::json!({ "id": "g1" });
    assert!(!checker.check_if_role_assignable(&group));
}

#[test]
fn test_check_if_role_assignable_false_when_null() {
    let checker = create_test_condition_checker();
    let group = serde_json::json!({
        "id": "g1",
        "isAssignableToRole": null,
    });
    assert!(!checker.check_if_role_assignable(&group));
}

#[tokio::test]
async fn test_condition_checker_check_p1_condition() {
    let mut checker = create_test_condition_checker();
    checker.tenant_conditions.insert("P1".to_string(), true);
    let token = create_test_token();
    assert!(checker.check(&token, "P1".to_string(), None).await);
}

#[tokio::test]
async fn test_condition_checker_check_not_p1_condition() {
    let mut checker = create_test_condition_checker();
    checker.tenant_conditions.insert("P1".to_string(), false);
    let token = create_test_token();
    assert!(checker.check(&token, "NotP1".to_string(), None).await);
}

#[tokio::test]
async fn test_condition_checker_check_p2_condition() {
    let mut checker = create_test_condition_checker();
    checker.tenant_conditions.insert("P2".to_string(), true);
    let token = create_test_token();
    assert!(checker.check(&token, "P2".to_string(), None).await);
}

#[tokio::test]
async fn test_condition_checker_check_not_p2_condition() {
    let mut checker = create_test_condition_checker();
    checker.tenant_conditions.insert("P2".to_string(), false);
    let token = create_test_token();
    assert!(checker.check(&token, "NotP2".to_string(), None).await);
}

#[tokio::test]
async fn test_condition_checker_check_intune_condition() {
    let mut checker = create_test_condition_checker();
    checker.tenant_conditions.insert("Intune".to_string(), true);
    let token = create_test_token();
    assert!(checker.check(&token, "Intune".to_string(), None).await);
}

#[tokio::test]
async fn test_condition_checker_check_invalid_condition() {
    let checker = create_test_condition_checker();
    let token = create_test_token();
    assert!(
        !checker
            .check(&token, "InvalidCondition".to_string(), None)
            .await
    );
}

#[tokio::test]
async fn test_multiple_conditions_combined() {
    let mut checker = create_test_condition_checker();
    checker.tenant_conditions.insert("P1".to_string(), true);
    checker.tenant_conditions.insert("Intune".to_string(), true);

    let unified_group = serde_json::json!({
        "groupTypes": ["Unified"],
        "id": "g1"
    });

    assert!(checker.check_if_unified_group(&unified_group));
    let token = create_test_token();
    assert!(checker.check(&token, "P1".to_string(), None).await);
    assert!(checker.check(&token, "Intune".to_string(), None).await);
}

// Wiremock-backed tests for HTTP paths
const P1_PLAN_ID: &str = "41781fb2-bc02-4b7c-bd55-b576c07bb09d";
const P2_PLAN_ID: &str = "eec0eb4f-6444-4f95-aba0-50c24d67f998";
const INTUNE_PLAN_ID: &str = "c1ec4a95-1f05-45b3-a911-aa3fa01094f5";

fn org_body_with_plan(plan_id: Vec<&str>) -> serde_json::Value {
    let plan = serde_json::json!(
        plan_id
            .iter()
            .map(|p| {
                serde_json::json!({
                    "servicePlanId": p,
                    "capabilityStatus": "Enabled"
                })
            })
            .collect::<Vec<Value>>()
    );
    serde_json::json!({
        "value": [{
            "assignedPlans": plan
        }]
    })
}

fn org_body_empty() -> serde_json::Value {
    serde_json::json!({ "value": [{ "assignedPlans": [] }] })
}

fn make_config_with_org_url(_org_url: String) -> Config {
    Config {
        tenant: "test-tenant".to_string(),
        app_id: "test-app".to_string(),
        services: None,
        proxy: None,
        output_files: Some(false),
        output_mla: Some(true),
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

fn make_graph_token() -> Token {
    Token {
        tenant_id: "test-tenant".to_string(),
        client_id: "test-client".to_string(),
        service: "graph".to_string(),
        expires_on: 9_999_999_999,
        access_token: "test_bearer_token".to_string(),
        refresh_token: None,
        token_type: "Bearer".to_string(),
        user_id: "user-123".to_string(),
        user_principal_name: "user@example.com".to_string(),
        scopes: vec![],
    }
}

#[tokio::test]
async fn test_check_tenant_for_p1_licence_plan_present() {
    let mock = MockServer::start().await;
    let org_url = format!("{}/v1.0/organization", mock.uri());

    Mock::given(method("GET"))
        .and(path("/v1.0/organization"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(org_body_with_plan(vec![P1_PLAN_ID])),
        )
        .mount(&mock)
        .await;

    let config = make_config_with_org_url(org_url.clone());
    let client = OradazClient::new(&config).unwrap();
    let token = make_graph_token();
    assert!(check_tenant_licenses(&client, &token, &org_url, 1).await.p1);
}

#[tokio::test]
async fn test_check_tenant_for_p1_licence_plan_absent() {
    let mock = MockServer::start().await;
    let org_url = format!("{}/v1.0/organization", mock.uri());

    Mock::given(method("GET"))
        .and(path("/v1.0/organization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(org_body_empty()))
        .mount(&mock)
        .await;

    let config = make_config_with_org_url(org_url.clone());
    let client = OradazClient::new(&config).unwrap();
    let token = make_graph_token();
    assert!(!check_tenant_licenses(&client, &token, &org_url, 1).await.p1);
}

#[tokio::test]
async fn test_check_tenant_for_p1_licence_http_error_returns_false() {
    let org_url = "http://127.0.0.1:19999/v1.0/organization".to_string();
    let config = make_config_with_org_url(org_url.clone());
    let client = OradazClient::new(&config).unwrap();
    let token = make_graph_token();
    assert!(!check_tenant_licenses(&client, &token, &org_url, 1).await.p1);
}

/// An HTTP 429 on `/organization` must be retried (not silently treated as
/// "undetected"), so a throttled probe still detects P1/P2/Intune. First call
/// 429 (Retry-After: 0 → immediate retry), then 200 with a P1 plan.
#[tokio::test]
async fn test_check_tenant_licenses_retries_on_429_then_succeeds() {
    let mock = MockServer::start().await;
    let org_url = format!("{}/v1.0/organization", mock.uri());

    // Higher priority (1 < default 5) + up_to_n_times(1): this mock serves only
    // the first request, then the 200 mock below takes over the retry.
    Mock::given(method("GET"))
        .and(path("/v1.0/organization"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1.0/organization"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(org_body_with_plan(vec![P1_PLAN_ID])),
        )
        .mount(&mock)
        .await;

    let config = make_config_with_org_url(org_url.clone());
    let client = OradazClient::new(&config).unwrap();
    let token = make_graph_token();
    assert!(
        check_tenant_licenses(&client, &token, &org_url, 1).await.p1,
        "a 429 must be retried so P1 is still detected, not left undetected"
    );
}

/// When `/organization` stays throttled past `MAX_CONDITION_PROBE_RETRIES`,
/// the probe gives up and returns the all-false fallback (gated APIs SKIPPED) —
/// it must not loop forever. Retry-After: 0 keeps the test fast.
#[tokio::test]
async fn test_check_tenant_licenses_429_past_budget_returns_fallback() {
    let mock = MockServer::start().await;
    let org_url = format!("{}/v1.0/organization", mock.uri());

    Mock::given(method("GET"))
        .and(path("/v1.0/organization"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
        .mount(&mock)
        .await;

    let config = make_config_with_org_url(org_url.clone());
    let client = OradazClient::new(&config).unwrap();
    let token = make_graph_token();
    let licenses = check_tenant_licenses(&client, &token, &org_url, 0).await;
    assert!(!licenses.p1);
    assert!(!licenses.p2);
    assert!(!licenses.intune);
    assert!(!licenses.is_b2c);
}

#[tokio::test]
async fn test_condition_checker_check_p1_condition_absent() {
    let mock = MockServer::start().await;
    let org_url = format!("{}/v1.0/organization", mock.uri());

    Mock::given(method("GET"))
        .and(path("/v1.0/organization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(org_body_empty()))
        .mount(&mock)
        .await;

    let config = make_config_with_org_url(org_url.clone());
    let checker = ConditionChecker {
        client: OradazClient::new(&config).unwrap(),
        tenant_conditions: HashMap::new(), // P1 absent
        user_conditions: DashMap::new(),
        emergency_accounts_custom_attributes: String::from("Emergency.isEmergency"),
        org_url,
        stats: std::sync::Arc::new(oradaz::utils::stats::Stats::new()),

        is_application_auth: false,
    };
    let token = make_graph_token();
    assert!(!checker.check(&token, "P1".to_string(), None).await);
}

#[tokio::test]
async fn test_condition_checker_check_p1_condition_dynamic_response() {
    let mock = MockServer::start().await;
    let org_url = format!("{}/v1.0/organization", mock.uri());

    Mock::given(method("GET"))
        .and(path("/v1.0/organization"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(org_body_with_plan(vec![P1_PLAN_ID])),
        )
        .mount(&mock)
        .await;

    let config = make_config_with_org_url(org_url.clone());
    let checker = ConditionChecker {
        client: OradazClient::new(&config).unwrap(),
        tenant_conditions: HashMap::from([("P1".to_string(), true)]),
        user_conditions: DashMap::new(),
        emergency_accounts_custom_attributes: String::from("Emergency.isEmergency"),
        org_url,
        stats: std::sync::Arc::new(oradaz::utils::stats::Stats::new()),

        is_application_auth: false,
    };
    let token = make_graph_token();
    assert!(checker.check(&token, "P1".to_string(), None).await);
}

#[tokio::test]
async fn test_check_tenant_for_p2_licence_returns_true() {
    let mock = MockServer::start().await;
    let org_url = format!("{}/v1.0/organization", mock.uri());

    Mock::given(method("GET"))
        .and(path("/v1.0/organization"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(org_body_with_plan(vec![P1_PLAN_ID, P2_PLAN_ID])),
        )
        .mount(&mock)
        .await;

    let config = make_config_with_org_url(org_url.clone());
    let client = OradazClient::new(&config).unwrap();
    let token = make_graph_token();
    assert!(check_tenant_licenses(&client, &token, &org_url, 1).await.p2);
}

#[tokio::test]
async fn test_check_tenant_for_p2_licence_only_p1_returns_false() {
    let mock = MockServer::start().await;
    let org_url = format!("{}/v1.0/organization", mock.uri());

    Mock::given(method("GET"))
        .and(path("/v1.0/organization"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(org_body_with_plan(vec![P1_PLAN_ID])),
        )
        .mount(&mock)
        .await;

    let config = make_config_with_org_url(org_url.clone());
    let client = OradazClient::new(&config).unwrap();
    let token = make_graph_token();
    assert!(!check_tenant_licenses(&client, &token, &org_url, 1).await.p2);
}

#[tokio::test]
async fn test_check_tenant_for_intune_licence_returns_true() {
    let mock = MockServer::start().await;
    let org_url = format!("{}/v1.0/organization", mock.uri());

    Mock::given(method("GET"))
        .and(path("/v1.0/organization"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(org_body_with_plan(vec![INTUNE_PLAN_ID])),
        )
        .mount(&mock)
        .await;

    let config = make_config_with_org_url(org_url.clone());
    let client = OradazClient::new(&config).unwrap();
    let token = make_graph_token();
    assert!(
        check_tenant_licenses(&client, &token, &org_url, 1)
            .await
            .intune
    );
}

// Helper function to create PIM role assignment response with GA role (active)
fn pim_ga_role_active_response() -> serde_json::Value {
    serde_json::json!({
        "value": [{
            "endDateTime": null,
            "roleDefinition": {
                "templateId": "62e90394-69f5-4237-9190-012177145e10"
            }
        }]
    })
}

// Helper function to create PIM role assignment response with GA role (expired)
fn pim_ga_role_expired_response() -> serde_json::Value {
    serde_json::json!({
        "value": [{
            "endDateTime": "2020-01-01T00:00:00Z",
            "roleDefinition": {
                "templateId": "62e90394-69f5-4237-9190-012177145e10"
            }
        }]
    })
}

// Helper function to create non-PIM role assignment response with GA role
fn non_pim_ga_role_response() -> serde_json::Value {
    serde_json::json!({
        "value": [{
            "roleDefinition": {
                "templateId": "62e90394-69f5-4237-9190-012177145e10"
            }
        }]
    })
}

#[tokio::test]
async fn test_check_user_for_ga_p2_pim_active_role() {
    let mock = MockServer::start().await;
    let org_url = format!("{}/v1.0/organization", mock.uri());

    // Mock organization endpoint (for P2 check)
    Mock::given(method("GET"))
        .and(path("/v1.0/organization"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(org_body_with_plan(vec![P1_PLAN_ID, P2_PLAN_ID])),
        )
        .mount(&mock)
        .await;

    // Mock PIM endpoint
    Mock::given(method("GET"))
        .and(path(
            "/v1.0/roleManagement/directory/roleAssignmentScheduleInstances",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(pim_ga_role_active_response()))
        .mount(&mock)
        .await;

    let config = make_config_with_org_url(org_url.clone());
    let client = OradazClient::new(&config).unwrap();
    let mut token = make_graph_token();
    token.user_id = "test-user-id".to_string();

    let checker = ConditionChecker {
        client,
        // PIM (roleAssignmentScheduleInstances) requires Entra ID P2; the GA
        // check branches on P2, not P1 (the org body carries P2_PLAN_ID).
        tenant_conditions: HashMap::from([("P2".to_string(), true)]),
        user_conditions: DashMap::new(),
        emergency_accounts_custom_attributes: String::from("Emergency.isEmergency"),
        org_url: org_url.clone(),
        stats: std::sync::Arc::new(oradaz::utils::stats::Stats::new()),

        is_application_auth: false,
    };

    assert!(checker.check_user_for_ga(&token).await);
}

// A PIM assignment whose endDateTime is unparseable must not short-circuit the
// scan: a later permanent GA assignment must still be recognised.
#[tokio::test]
async fn test_check_user_for_ga_p2_pim_corrupt_endtime_then_permanent() {
    let mock = MockServer::start().await;
    let org_url = format!("{}/v1.0/organization", mock.uri());

    Mock::given(method("GET"))
        .and(path("/v1.0/organization"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(org_body_with_plan(vec![P1_PLAN_ID, P2_PLAN_ID])),
        )
        .mount(&mock)
        .await;

    let corrupt_then_permanent = serde_json::json!({
        "value": [
            {
                "endDateTime": "not-a-date",
                "roleDefinition": { "templateId": "62e90394-69f5-4237-9190-012177145e10" }
            },
            {
                "endDateTime": null,
                "roleDefinition": { "templateId": "62e90394-69f5-4237-9190-012177145e10" }
            }
        ]
    });
    Mock::given(method("GET"))
        .and(path(
            "/v1.0/roleManagement/directory/roleAssignmentScheduleInstances",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(corrupt_then_permanent))
        .mount(&mock)
        .await;

    let config = make_config_with_org_url(org_url.clone());
    let client = OradazClient::new(&config).unwrap();
    let mut token = make_graph_token();
    token.user_id = "test-user-id".to_string();

    let checker = ConditionChecker {
        client,
        tenant_conditions: HashMap::from([("P2".to_string(), true)]),
        user_conditions: DashMap::new(),
        emergency_accounts_custom_attributes: String::from("Emergency.isEmergency"),
        org_url: org_url.clone(),
        stats: std::sync::Arc::new(oradaz::utils::stats::Stats::new()),
        is_application_auth: false,
    };

    assert!(
        checker.check_user_for_ga(&token).await,
        "a permanent GA after a corrupt-endDateTime instance must still be detected"
    );
}

#[tokio::test]
async fn test_check_user_for_ga_p2_pim_expired_role() {
    let mock = MockServer::start().await;
    let org_url = format!("{}/v1.0/organization", mock.uri());

    // Mock organization endpoint (for P2 check)
    Mock::given(method("GET"))
        .and(path("/v1.0/organization"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(org_body_with_plan(vec![P1_PLAN_ID, P2_PLAN_ID])),
        )
        .mount(&mock)
        .await;

    // Mock PIM endpoint with expired role
    Mock::given(method("GET"))
        .and(path(
            "/v1.0/roleManagement/directory/roleAssignmentScheduleInstances",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(pim_ga_role_expired_response()))
        .mount(&mock)
        .await;

    let config = make_config_with_org_url(org_url.clone());
    let client = OradazClient::new(&config).unwrap();
    let mut token = make_graph_token();
    token.user_id = "test-user-id".to_string();

    let checker = ConditionChecker {
        client,
        // PIM (roleAssignmentScheduleInstances) requires Entra ID P2; the GA
        // check branches on P2, not P1 (the org body carries P2_PLAN_ID).
        tenant_conditions: HashMap::from([("P2".to_string(), true)]),
        user_conditions: DashMap::new(),
        emergency_accounts_custom_attributes: String::from("Emergency.isEmergency"),
        org_url: org_url.clone(),
        stats: std::sync::Arc::new(oradaz::utils::stats::Stats::new()),

        is_application_auth: false,
    };

    assert!(!checker.check_user_for_ga(&token).await);
}

#[tokio::test]
async fn test_check_user_for_ga_no_p2_non_pim() {
    let mock = MockServer::start().await;
    let org_url = format!("{}/v1.0/organization", mock.uri());

    // Mock organization endpoint (P2 check - no P2 present)
    Mock::given(method("GET"))
        .and(path("/v1.0/organization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(org_body_empty()))
        .mount(&mock)
        .await;

    // Mock non-PIM endpoint
    Mock::given(method("GET"))
        .and(path("/v1.0/roleManagement/directory/roleAssignments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(non_pim_ga_role_response()))
        .mount(&mock)
        .await;

    let config = make_config_with_org_url(org_url.clone());
    let client = OradazClient::new(&config).unwrap();
    let mut token = make_graph_token();
    token.user_id = "test-user-id".to_string();

    let checker = ConditionChecker {
        client,
        tenant_conditions: HashMap::new(),
        user_conditions: DashMap::new(),
        emergency_accounts_custom_attributes: String::from("Emergency.isEmergency"),
        org_url: org_url.clone(),
        stats: std::sync::Arc::new(oradaz::utils::stats::Stats::new()),

        is_application_auth: false,
    };

    assert!(checker.check_user_for_ga(&token).await);
}

#[tokio::test]
async fn test_condition_checker_check_combined_not_conditions() {
    let mut checker = create_test_condition_checker();
    checker.tenant_conditions.insert("P1".to_string(), false);
    checker.tenant_conditions.insert("Intune".to_string(), true);
    let token = create_test_token();
    assert!(checker.check(&token, "NotP1".to_string(), None).await);
    assert!(checker.check(&token, "Intune".to_string(), None).await);
    assert!(!checker.check(&token, "P1".to_string(), None).await);
}

#[test]
fn test_check_if_unified_group_multiple_types() {
    let checker = create_test_condition_checker();
    let unified_group = serde_json::json!({
        "groupTypes": ["Unified", "Security"]
    });
    assert!(checker.check_if_unified_group(&unified_group));
}

#[test]
fn test_check_if_unified_group_mixed_types() {
    let checker = create_test_condition_checker();
    let mixed_group = serde_json::json!({
        "groupTypes": ["Unified", 123]
    });
    assert!(checker.check_if_unified_group(&mixed_group));
}

#[test]
fn test_check_if_unified_group_no_unified_in_mixed() {
    let checker = create_test_condition_checker();
    let mixed_group = serde_json::json!({
        "groupTypes": ["Security", 123]
    });
    assert!(!checker.check_if_unified_group(&mixed_group));
}

// ── check_if_emergency_account ────────────────────────────────────────────────
// The value passed to check_if_emergency_account is the JSON object stored at
// `customSecurityAttributes`, not the full user object.
// Default path: "Emergency.isEmergency" → looks up value["Emergency"]["isEmergency"].

#[test]
fn test_check_if_emergency_account_true() {
    let checker = create_test_condition_checker();
    let value = serde_json::json!({ "Emergency": { "isEmergency": true } });
    assert!(checker.check_if_emergency_account(&value));
}

#[test]
fn test_check_if_emergency_account_false() {
    let checker = create_test_condition_checker();
    let value = serde_json::json!({ "Emergency": { "isEmergency": false } });
    assert!(!checker.check_if_emergency_account(&value));
}

#[test]
fn test_check_if_emergency_account_string_not_bool() {
    // A string "true" is not a boolean — must return false.
    let checker = create_test_condition_checker();
    let value = serde_json::json!({ "Emergency": { "isEmergency": "true" } });
    assert!(!checker.check_if_emergency_account(&value));
}

#[test]
fn test_check_if_emergency_account_number_not_bool() {
    let checker = create_test_condition_checker();
    let value = serde_json::json!({ "Emergency": { "isEmergency": 1 } });
    assert!(!checker.check_if_emergency_account(&value));
}

#[test]
fn test_check_if_emergency_account_null() {
    let checker = create_test_condition_checker();
    let value = serde_json::json!({ "Emergency": { "isEmergency": null } });
    assert!(!checker.check_if_emergency_account(&value));
}

#[test]
fn test_check_if_emergency_account_attribute_missing() {
    // Attribute set "Emergency" present but attribute "isEmergency" absent.
    let checker = create_test_condition_checker();
    let value = serde_json::json!({ "Emergency": {} });
    assert!(!checker.check_if_emergency_account(&value));
}

#[test]
fn test_check_if_emergency_account_set_missing() {
    // Neither attribute set nor attribute is present.
    let checker = create_test_condition_checker();
    let value = serde_json::json!({});
    assert!(!checker.check_if_emergency_account(&value));
}

#[test]
fn test_check_if_emergency_account_wrong_set_name() {
    // Attribute exists under a different set name.
    let checker = create_test_condition_checker();
    let value = serde_json::json!({ "OtherSet": { "isEmergency": true } });
    assert!(!checker.check_if_emergency_account(&value));
}

#[test]
fn test_check_if_emergency_account_custom_path() {
    let config = default_test_config();
    let checker = ConditionChecker {
        client: OradazClient::new(&config).unwrap(),
        tenant_conditions: HashMap::new(),
        user_conditions: DashMap::new(),
        emergency_accounts_custom_attributes: "Breakglass.isBreakglass".to_string(),
        org_url: "https://graph.microsoft.com/v1.0/organization".to_string(),
        stats: std::sync::Arc::new(oradaz::utils::stats::Stats::new()),

        is_application_auth: false,
    };
    let value = serde_json::json!({ "Breakglass": { "isBreakglass": true } });
    assert!(checker.check_if_emergency_account(&value));
}

#[test]
fn test_check_if_emergency_account_custom_path_mismatch() {
    // Custom path configured but data uses the default set name.
    let config = default_test_config();
    let checker = ConditionChecker {
        client: OradazClient::new(&config).unwrap(),
        tenant_conditions: HashMap::new(),
        user_conditions: DashMap::new(),
        emergency_accounts_custom_attributes: "Breakglass.isBreakglass".to_string(),
        org_url: "https://graph.microsoft.com/v1.0/organization".to_string(),
        stats: std::sync::Arc::new(oradaz::utils::stats::Stats::new()),

        is_application_auth: false,
    };
    let value = serde_json::json!({ "Emergency": { "isEmergency": true } });
    assert!(!checker.check_if_emergency_account(&value));
}

// ── check_if_enabled_member ───────────────────────────────────────────────────
// The value passed is the full user object. An enabled member (not a guest, not
// disabled) is queried for per-user authentication methods; guests and disabled
// accounts are skipped. Defaults to `true` (queried) when a field is absent.

#[test]
fn test_check_if_enabled_member_enabled_member_true() {
    let checker = create_test_condition_checker();
    let value = serde_json::json!({ "id": "u1", "accountEnabled": true, "userType": "Member" });
    assert!(checker.check_if_enabled_member(&value));
}

#[test]
fn test_check_if_enabled_member_guest_false() {
    let checker = create_test_condition_checker();
    let value = serde_json::json!({ "id": "u2", "accountEnabled": true, "userType": "Guest" });
    assert!(!checker.check_if_enabled_member(&value));
}

#[test]
fn test_check_if_enabled_member_disabled_member_false() {
    let checker = create_test_condition_checker();
    let value = serde_json::json!({ "id": "u3", "accountEnabled": false, "userType": "Member" });
    assert!(!checker.check_if_enabled_member(&value));
}

#[test]
fn test_check_if_enabled_member_disabled_guest_false() {
    let checker = create_test_condition_checker();
    let value = serde_json::json!({ "id": "u4", "accountEnabled": false, "userType": "Guest" });
    assert!(!checker.check_if_enabled_member(&value));
}

#[test]
fn test_check_if_enabled_member_guest_case_insensitive_false() {
    // Graph returns "Guest"; be robust to casing variants.
    let checker = create_test_condition_checker();
    let value = serde_json::json!({ "id": "u5", "accountEnabled": true, "userType": "GUEST" });
    assert!(!checker.check_if_enabled_member(&value));
}

#[test]
fn test_check_if_enabled_member_missing_user_type_treated_as_member() {
    // Absent userType → not a guest → enabled account is queried.
    let checker = create_test_condition_checker();
    let value = serde_json::json!({ "id": "u6", "accountEnabled": true });
    assert!(checker.check_if_enabled_member(&value));
}

#[test]
fn test_check_if_enabled_member_missing_account_enabled_defaults_queried() {
    // Defensive default: when accountEnabled is absent/non-bool we still query
    // (a member) rather than silently dropping the user.
    let checker = create_test_condition_checker();
    let value = serde_json::json!({ "id": "u7", "userType": "Member" });
    assert!(checker.check_if_enabled_member(&value));
}

#[test]
fn test_check_if_enabled_member_empty_object_defaults_queried() {
    let checker = create_test_condition_checker();
    let value = serde_json::json!({});
    assert!(checker.check_if_enabled_member(&value));
}

#[tokio::test]
async fn test_condition_checker_ga_cache() {
    let mock = MockServer::start().await;
    let org_url = format!("{}/v1.0/organization", mock.uri());

    // Mock organization endpoint (no P2, so it uses non-PIM endpoint)
    Mock::given(method("GET"))
        .and(path("/v1.0/organization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(org_body_empty()))
        .mount(&mock)
        .await;

    // Mock GA role assignment endpoint
    Mock::given(method("GET"))
        .and(path("/v1.0/roleManagement/directory/roleAssignments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(non_pim_ga_role_response()))
        .mount(&mock)
        .await;

    let config = make_config_with_org_url(org_url.clone());
    let client = OradazClient::new(&config).unwrap();
    let token = make_graph_token();

    let checker = ConditionChecker {
        client,
        tenant_conditions: HashMap::new(),
        user_conditions: DashMap::new(),
        emergency_accounts_custom_attributes: String::from("Emergency.isEmergency"),
        org_url,
        stats: std::sync::Arc::new(oradaz::utils::stats::Stats::new()),

        is_application_auth: false,
    };

    // First call - should trigger HTTP request
    assert!(checker.check(&token, "GA".to_string(), None).await);
    // Second call - should use cache
    assert!(checker.check(&token, "GA".to_string(), None).await);
    // Third call - should use cache
    assert!(checker.check(&token, "GA".to_string(), None).await);
}

// ---------------------------------------------------------------------------
// GAOrApp condition
// ---------------------------------------------------------------------------

/// When `is_application_auth` is `true`, `GAOrApp` must return `true` immediately
/// without making any HTTP call (the Graph endpoint is intentionally not mocked).
#[tokio::test]
async fn test_condition_checker_ga_or_app_true_when_application_auth() {
    let config = make_config_with_org_url(String::new());
    let checker = ConditionChecker {
        client: OradazClient::new(&config).unwrap(),
        tenant_conditions: HashMap::new(),
        user_conditions: DashMap::new(),
        emergency_accounts_custom_attributes: String::from("Emergency.isEmergency"),
        org_url: "http://127.0.0.1:1".to_string(), // unreachable — should never be called
        stats: std::sync::Arc::new(oradaz::utils::stats::Stats::new()),
        is_application_auth: true,
    };
    let token = make_graph_token();
    assert!(checker.check(&token, "GAOrApp".to_string(), None).await);
}

/// When `is_application_auth` is `false` and the user is a Global Admin,
/// `GAOrApp` must return `true` (delegates to the GA check).
#[tokio::test]
async fn test_condition_checker_ga_or_app_true_when_user_is_ga() {
    let mock = MockServer::start().await;
    let org_url = format!("{}/v1.0/organization", mock.uri());

    Mock::given(method("GET"))
        .and(path("/v1.0/roleManagement/directory/roleAssignments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(non_pim_ga_role_response()))
        .mount(&mock)
        .await;

    let config = make_config_with_org_url(org_url.clone());
    let checker = ConditionChecker {
        client: OradazClient::new(&config).unwrap(),
        tenant_conditions: HashMap::new(),
        user_conditions: DashMap::new(),
        emergency_accounts_custom_attributes: String::from("Emergency.isEmergency"),
        org_url,
        stats: std::sync::Arc::new(oradaz::utils::stats::Stats::new()),
        is_application_auth: false,
    };
    let token = make_graph_token();
    assert!(checker.check(&token, "GAOrApp".to_string(), None).await);
}

/// When `is_application_auth` is `false` and the user is NOT a Global Admin,
/// `GAOrApp` must return `false`.
#[tokio::test]
async fn test_condition_checker_ga_or_app_false_when_user_not_ga() {
    let mock = MockServer::start().await;
    let org_url = format!("{}/v1.0/organization", mock.uri());

    Mock::given(method("GET"))
        .and(path("/v1.0/roleManagement/directory/roleAssignments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"value": []})))
        .mount(&mock)
        .await;

    let config = make_config_with_org_url(org_url.clone());
    let checker = ConditionChecker {
        client: OradazClient::new(&config).unwrap(),
        tenant_conditions: HashMap::new(),
        user_conditions: DashMap::new(),
        emergency_accounts_custom_attributes: String::from("Emergency.isEmergency"),
        org_url,
        stats: std::sync::Arc::new(oradaz::utils::stats::Stats::new()),
        is_application_auth: false,
    };
    let token = make_graph_token();
    assert!(!checker.check(&token, "GAOrApp".to_string(), None).await);
}

/// `GAOrApp` reuses the `"GA"` cache entry: when `GA` was already evaluated for
/// the same user, `GAOrApp` must not trigger a second HTTP request.
#[tokio::test]
async fn test_condition_checker_ga_or_app_reuses_ga_cache() {
    let mock = MockServer::start().await;
    let org_url = format!("{}/v1.0/organization", mock.uri());

    // Respond exactly once — a second call would cause the test to fail via
    // `wiremock`'s unmatched-request error on mock teardown.
    Mock::given(method("GET"))
        .and(path("/v1.0/roleManagement/directory/roleAssignments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(non_pim_ga_role_response()))
        .expect(1)
        .mount(&mock)
        .await;

    let config = make_config_with_org_url(org_url.clone());
    let checker = ConditionChecker {
        client: OradazClient::new(&config).unwrap(),
        tenant_conditions: HashMap::new(),
        user_conditions: DashMap::new(),
        emergency_accounts_custom_attributes: String::from("Emergency.isEmergency"),
        org_url,
        stats: std::sync::Arc::new(oradaz::utils::stats::Stats::new()),
        is_application_auth: false,
    };
    let token = make_graph_token();
    // First check via GA — triggers the HTTP call
    assert!(checker.check(&token, "GA".to_string(), None).await);
    // Second check via GAOrApp — must reuse the GA cache entry (no new HTTP call)
    assert!(checker.check(&token, "GAOrApp".to_string(), None).await);
}

// ---------------------------------------------------------------------------
// New tenant-capability conditions: IsB2C / HasApplicationProxy /
// HasExchangeHybrid / HasADAdministration.
// ---------------------------------------------------------------------------

fn org_body_with_tenant_type(tenant_type: Option<&str>) -> serde_json::Value {
    match tenant_type {
        Some(tt) => serde_json::json!({
            "value": [{
                "assignedPlans": [],
                "tenantType": tt
            }]
        }),
        None => serde_json::json!({ "value": [{ "assignedPlans": [] }] }),
    }
}

fn publishing_profiles_body(publishing_types: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "value": publishing_types
            .iter()
            .map(|pt| serde_json::json!({ "publishingType": pt }))
            .collect::<Vec<Value>>()
    })
}

#[tokio::test]
async fn test_check_tenant_licenses_is_b2c_true() {
    let mock = MockServer::start().await;
    let org_url = format!("{}/v1.0/organization", mock.uri());

    Mock::given(method("GET"))
        .and(path("/v1.0/organization"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(org_body_with_tenant_type(Some("AAD B2C"))),
        )
        .mount(&mock)
        .await;

    let config = make_config_with_org_url(org_url.clone());
    let client = OradazClient::new(&config).unwrap();
    let token = make_graph_token();
    assert!(
        check_tenant_licenses(&client, &token, &org_url, 1)
            .await
            .is_b2c
    );
}

#[tokio::test]
async fn test_check_tenant_licenses_is_b2c_false_when_aad() {
    let mock = MockServer::start().await;
    let org_url = format!("{}/v1.0/organization", mock.uri());

    Mock::given(method("GET"))
        .and(path("/v1.0/organization"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(org_body_with_tenant_type(Some("AAD"))),
        )
        .mount(&mock)
        .await;

    let config = make_config_with_org_url(org_url.clone());
    let client = OradazClient::new(&config).unwrap();
    let token = make_graph_token();
    assert!(
        !check_tenant_licenses(&client, &token, &org_url, 1)
            .await
            .is_b2c
    );
}

/// Older directories may omit `tenantType` entirely; the serde default must
/// keep that path safe and yield `is_b2c == false`.
#[tokio::test]
async fn test_check_tenant_licenses_is_b2c_false_when_field_missing() {
    let mock = MockServer::start().await;
    let org_url = format!("{}/v1.0/organization", mock.uri());

    Mock::given(method("GET"))
        .and(path("/v1.0/organization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(org_body_with_tenant_type(None)))
        .mount(&mock)
        .await;

    let config = make_config_with_org_url(org_url.clone());
    let client = OradazClient::new(&config).unwrap();
    let token = make_graph_token();
    assert!(
        !check_tenant_licenses(&client, &token, &org_url, 1)
            .await
            .is_b2c
    );
}

#[tokio::test]
async fn test_check_publishing_profiles_detects_each_capability() {
    let mock = MockServer::start().await;
    let url = format!("{}/beta/onPremisesPublishingProfiles", mock.uri());

    Mock::given(method("GET"))
        .and(path("/beta/onPremisesPublishingProfiles"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(publishing_profiles_body(&[
                "applicationProxy",
                "exchangeOnline",
                "adAdministration",
            ])),
        )
        .mount(&mock)
        .await;

    let config = make_config_with_org_url(url.clone());
    let client = OradazClient::new(&config).unwrap();
    let token = make_graph_token();
    let caps = check_publishing_profiles(&client, &token, &url, 1).await;
    assert!(caps.has_application_proxy);
    assert!(caps.has_exchange_hybrid);
    assert!(caps.has_ad_administration);
}

#[tokio::test]
async fn test_check_publishing_profiles_partial_response() {
    let mock = MockServer::start().await;
    let url = format!("{}/beta/onPremisesPublishingProfiles", mock.uri());

    Mock::given(method("GET"))
        .and(path("/beta/onPremisesPublishingProfiles"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(publishing_profiles_body(&["applicationProxy"])),
        )
        .mount(&mock)
        .await;

    let config = make_config_with_org_url(url.clone());
    let client = OradazClient::new(&config).unwrap();
    let token = make_graph_token();
    let caps = check_publishing_profiles(&client, &token, &url, 1).await;
    assert!(caps.has_application_proxy);
    assert!(!caps.has_exchange_hybrid);
    assert!(!caps.has_ad_administration);
}

#[tokio::test]
async fn test_check_publishing_profiles_empty_response() {
    let mock = MockServer::start().await;
    let url = format!("{}/beta/onPremisesPublishingProfiles", mock.uri());

    Mock::given(method("GET"))
        .and(path("/beta/onPremisesPublishingProfiles"))
        .respond_with(ResponseTemplate::new(200).set_body_json(publishing_profiles_body(&[])))
        .mount(&mock)
        .await;

    let config = make_config_with_org_url(url.clone());
    let client = OradazClient::new(&config).unwrap();
    let token = make_graph_token();
    let caps = check_publishing_profiles(&client, &token, &url, 1).await;
    assert!(!caps.has_application_proxy);
    assert!(!caps.has_exchange_hybrid);
    assert!(!caps.has_ad_administration);
}

#[tokio::test]
async fn test_check_publishing_profiles_http_403_returns_all_false() {
    let mock = MockServer::start().await;
    let url = format!("{}/beta/onPremisesPublishingProfiles", mock.uri());

    Mock::given(method("GET"))
        .and(path("/beta/onPremisesPublishingProfiles"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&mock)
        .await;

    let config = make_config_with_org_url(url.clone());
    let client = OradazClient::new(&config).unwrap();
    let token = make_graph_token();
    let caps = check_publishing_profiles(&client, &token, &url, 1).await;
    assert!(!caps.has_application_proxy);
    assert!(!caps.has_exchange_hybrid);
    assert!(!caps.has_ad_administration);
}

/// Network failure (unreachable URL) must fall back to all-false instead of
/// propagating an error.
#[tokio::test]
async fn test_check_publishing_profiles_network_failure_returns_all_false() {
    let url = "http://127.0.0.1:19999/beta/onPremisesPublishingProfiles".to_string();
    let config = make_config_with_org_url(url.clone());
    let client = OradazClient::new(&config).unwrap();
    let token = make_graph_token();
    let caps = check_publishing_profiles(&client, &token, &url, 1).await;
    assert!(!caps.has_application_proxy);
    assert!(!caps.has_exchange_hybrid);
    assert!(!caps.has_ad_administration);
}

/// An HTTP 429 on `onPremisesPublishingProfiles` must be retried, so a
/// throttled probe still detects the publishing capabilities instead of skipping
/// the gated APIs. First call 429 (Retry-After: 0 → immediate retry), then 200.
#[tokio::test]
async fn test_check_publishing_profiles_retries_on_429_then_succeeds() {
    let mock = MockServer::start().await;
    let url = format!("{}/beta/onPremisesPublishingProfiles", mock.uri());

    Mock::given(method("GET"))
        .and(path("/beta/onPremisesPublishingProfiles"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/beta/onPremisesPublishingProfiles"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(publishing_profiles_body(&["applicationProxy"])),
        )
        .mount(&mock)
        .await;

    let config = make_config_with_org_url(url.clone());
    let client = OradazClient::new(&config).unwrap();
    let token = make_graph_token();
    let caps = check_publishing_profiles(&client, &token, &url, 1).await;
    assert!(
        caps.has_application_proxy,
        "a 429 must be retried so the capability is still detected"
    );
}

/// When `onPremisesPublishingProfiles` stays throttled past the retry budget,
/// the probe gives up and returns all-false (gated APIs SKIPPED) — no infinite loop.
#[tokio::test]
async fn test_check_publishing_profiles_429_past_budget_returns_all_false() {
    let mock = MockServer::start().await;
    let url = format!("{}/beta/onPremisesPublishingProfiles", mock.uri());

    Mock::given(method("GET"))
        .and(path("/beta/onPremisesPublishingProfiles"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
        .mount(&mock)
        .await;

    let config = make_config_with_org_url(url.clone());
    let client = OradazClient::new(&config).unwrap();
    let token = make_graph_token();
    let caps = check_publishing_profiles(&client, &token, &url, 0).await;
    assert!(!caps.has_application_proxy);
    assert!(!caps.has_exchange_hybrid);
    assert!(!caps.has_ad_administration);
}

// ---------------------------------------------------------------------------
// Schema-level conditions: verify `ConditionChecker::check` honours the
// boolean stored in `tenant_conditions` for each new condition.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_condition_checker_is_b2c_when_true() {
    let mut tc = HashMap::new();
    tc.insert("IsB2C".to_string(), true);
    let checker = ConditionChecker {
        client: OradazClient::new(&default_test_config()).unwrap(),
        tenant_conditions: tc,
        user_conditions: DashMap::new(),
        emergency_accounts_custom_attributes: String::from("Emergency.isEmergency"),
        org_url: "https://graph.microsoft.com/v1.0/organization".to_string(),
        stats: std::sync::Arc::new(oradaz::utils::stats::Stats::new()),

        is_application_auth: false,
    };
    let token = make_graph_token();
    assert!(checker.check(&token, "IsB2C".to_string(), None).await);
    assert!(!checker.check(&token, "NotB2C".to_string(), None).await);
}

#[tokio::test]
async fn test_condition_checker_is_b2c_when_false() {
    let mut tc = HashMap::new();
    tc.insert("IsB2C".to_string(), false);
    let checker = ConditionChecker {
        client: OradazClient::new(&default_test_config()).unwrap(),
        tenant_conditions: tc,
        user_conditions: DashMap::new(),
        emergency_accounts_custom_attributes: String::from("Emergency.isEmergency"),
        org_url: "https://graph.microsoft.com/v1.0/organization".to_string(),
        stats: std::sync::Arc::new(oradaz::utils::stats::Stats::new()),

        is_application_auth: false,
    };
    let token = make_graph_token();
    assert!(!checker.check(&token, "IsB2C".to_string(), None).await);
    assert!(checker.check(&token, "NotB2C".to_string(), None).await);
}

#[tokio::test]
async fn test_condition_checker_publishing_capabilities() {
    let mut tc = HashMap::new();
    tc.insert("HasApplicationProxy".to_string(), true);
    tc.insert("HasExchangeHybrid".to_string(), false);
    tc.insert("HasADAdministration".to_string(), true);
    let checker = ConditionChecker {
        client: OradazClient::new(&default_test_config()).unwrap(),
        tenant_conditions: tc,
        user_conditions: DashMap::new(),
        emergency_accounts_custom_attributes: String::from("Emergency.isEmergency"),
        org_url: "https://graph.microsoft.com/v1.0/organization".to_string(),
        stats: std::sync::Arc::new(oradaz::utils::stats::Stats::new()),

        is_application_auth: false,
    };
    let token = make_graph_token();
    assert!(
        checker
            .check(&token, "HasApplicationProxy".to_string(), None)
            .await
    );
    assert!(
        !checker
            .check(&token, "HasExchangeHybrid".to_string(), None)
            .await
    );
    assert!(
        checker
            .check(&token, "HasADAdministration".to_string(), None)
            .await
    );
}

#[tokio::test]
async fn test_condition_checker_publishing_capabilities_absent_default_false() {
    let checker = ConditionChecker {
        client: OradazClient::new(&default_test_config()).unwrap(),
        tenant_conditions: HashMap::new(),
        user_conditions: DashMap::new(),
        emergency_accounts_custom_attributes: String::from("Emergency.isEmergency"),
        org_url: "https://graph.microsoft.com/v1.0/organization".to_string(),
        stats: std::sync::Arc::new(oradaz::utils::stats::Stats::new()),

        is_application_auth: false,
    };
    let token = make_graph_token();
    assert!(
        !checker
            .check(&token, "HasApplicationProxy".to_string(), None)
            .await
    );
    assert!(
        !checker
            .check(&token, "HasExchangeHybrid".to_string(), None)
            .await
    );
    assert!(
        !checker
            .check(&token, "HasADAdministration".to_string(), None)
            .await
    );
    assert!(!checker.check(&token, "IsB2C".to_string(), None).await);
    assert!(checker.check(&token, "NotB2C".to_string(), None).await);
}

// ---------------------------------------------------------------------------
// check_resource_supports_pim
// ---------------------------------------------------------------------------

#[rstest]
// Top-level resources: exactly 3 segments after /providers/ → PIM supported
#[case(
    "/subscriptions/abc/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/mystorage",
    true
)]
#[case(
    "/subscriptions/abc/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/myvm",
    true
)]
#[case(
    "/subscriptions/abc/resourceGroups/rg1/providers/Microsoft.Network/networkWatchers/watcher1",
    true
)]
// Subscription-scope top-level resource (no resourceGroups): 3 segments → PIM supported
#[case(
    "/subscriptions/abc/providers/Microsoft.Authorization/policyAssignments/myPolicy",
    true
)]
// Child resources: 5+ segments after /providers/ → PIM not supported
#[case(
    "/subscriptions/abc/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/mystorage/blobServices/default",
    false
)]
#[case(
    "/subscriptions/abc/resourceGroups/rg1/providers/Microsoft.Network/networkWatchers/watcher1/flowLogs/log1",
    false
)]
#[case(
    "/subscriptions/abc/resourceGroups/rg1/providers/Microsoft.Web/sites/myapp/slots/staging",
    false
)]
fn test_check_resource_supports_pim_arm_id(#[case] arm_id: &str, #[case] expected: bool) {
    let checker = create_test_condition_checker();
    let value = Value::String(arm_id.to_string());
    assert_eq!(
        checker.check_resource_supports_pim(&value),
        expected,
        "arm_id={arm_id}"
    );
}

#[test]
fn test_check_resource_supports_pim_non_string_is_conservative() {
    let checker = create_test_condition_checker();
    assert!(checker.check_resource_supports_pim(&serde_json::json!(null)));
    assert!(checker.check_resource_supports_pim(&serde_json::json!(42)));
    assert!(checker.check_resource_supports_pim(&serde_json::json!({})));
}

#[test]
fn test_check_resource_supports_pim_no_providers_segment_is_conservative() {
    let checker = create_test_condition_checker();
    let sub_id = Value::String("/subscriptions/abc".to_string());
    let rg_id = Value::String("/subscriptions/abc/resourceGroups/rg1".to_string());
    assert!(checker.check_resource_supports_pim(&sub_id));
    assert!(checker.check_resource_supports_pim(&rg_id));
}

// A transient non-2xx on /organization (even when the body would parse and carry
// P1/P2 plans) must NOT be treated as a definitive licence answer: the is_success()
// guard returns the all-false fallback so gated APIs are skipped with a warning
// rather than silently mis-detected. Without the guard this body would yield p1/p2
// = true.
#[tokio::test]
async fn test_check_tenant_licences_non_2xx_returns_all_false() {
    let mock = MockServer::start().await;
    let org_url = format!("{}/v1.0/organization", mock.uri());

    Mock::given(method("GET"))
        .and(path("/v1.0/organization"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(org_body_with_plan(vec![P1_PLAN_ID, P2_PLAN_ID])),
        )
        .mount(&mock)
        .await;

    let config = make_config_with_org_url(org_url.clone());
    let client = OradazClient::new(&config).unwrap();
    let token = make_graph_token();
    let lic = check_tenant_licenses(&client, &token, &org_url, 1).await;
    assert!(!lic.p1 && !lic.p2 && !lic.intune && !lic.is_b2c);
}

// A transient failure on the GA role-assignment probe must yield `None` (probe
// failed), NOT `Some(false)`: the caller only caches a definitive answer, so a
// transient blip must not poison the cache and silently skip GA-gated APIs for the
// rest of the run.
#[tokio::test]
async fn test_check_user_for_ga_probe_non_2xx_returns_none() {
    use oradaz::collect::dump::conditions::user::check_user_for_ga;

    let mock = MockServer::start().await;
    let org_url = format!("{}/v1.0/organization", mock.uri());

    // P2 absent => non-PIM branch => probe hits /roleManagement/directory/roleAssignments.
    Mock::given(method("GET"))
        .and(path("/v1.0/roleManagement/directory/roleAssignments"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock)
        .await;

    let config = make_config_with_org_url(org_url.clone());
    let client = OradazClient::new(&config).unwrap();
    let mut token = make_graph_token();
    token.user_id = "test-user-id".to_string();

    let checker = ConditionChecker {
        client,
        tenant_conditions: HashMap::new(),
        user_conditions: DashMap::new(),
        emergency_accounts_custom_attributes: String::from("Emergency.isEmergency"),
        org_url: org_url.clone(),
        stats: std::sync::Arc::new(oradaz::utils::stats::Stats::new()),

        is_application_auth: false,
    };

    assert_eq!(check_user_for_ga(&checker, &token).await, None);
}
