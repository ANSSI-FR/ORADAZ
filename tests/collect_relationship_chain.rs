mod common;

use crate::common::default_test_config;
use oradaz::collect::auth::tokens::{Token, TokenState};
use oradaz::collect::dump::conditions::ConditionChecker;
use oradaz::collect::dump::orchestration::events::CoordinatorEvent;
use oradaz::collect::dump::ratelimit::RateLimitManager;
use oradaz::collect::dump::response::{Response, ResponseContent, ResponseContext, ResponseThread};
use oradaz::utils::client::OradazClient;
use oradaz::utils::metadata::TableMetadata;
use oradaz::utils::url::{ApiCall, RelationshipUrl, Url as OradazUrl};
use oradaz::utils::writer::actor::spawn_writer_task;

use dashmap::DashMap;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tokio::sync::mpsc;

fn create_test_token() -> Token {
    Token {
        tenant_id: "test-tenant".to_string(),
        client_id: "test-client".to_string(),
        service: "graph".to_string(),
        expires_on: chrono::Utc::now().timestamp() + 3600,
        access_token: "test_token".to_string(),
        refresh_token: None,
        token_type: "Bearer".to_string(),
        user_id: "user-123".to_string(),
        user_principal_name: "user@example.com".to_string(),
        scopes: vec!["https://graph.microsoft.com/.default".to_string()],
    }
}

fn create_test_url() -> OradazUrl {
    OradazUrl {
        service_name: "graph".to_string(),
        service_scopes: Arc::new(vec!["https://graph.microsoft.com/.default".to_string()]),
        service_mandatory_auth: true,
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
    }
}

fn create_test_api_call(url: OradazUrl) -> ApiCall {
    ApiCall {
        id: 1,
        url,
        success_code: 200,
        batch_data: None,
        value_pointer: "/value".to_string(),
        is_batch: false,
    }
}

async fn setup_response_thread(
    api_call: ApiCall,
    response: Response,
) -> (mpsc::Receiver<CoordinatorEvent>, ResponseThread, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let mut config = default_test_config();
    config.output_files = Some(true);
    config.output_mla = Some(false);
    let (writer, _task) = spawn_writer_task(
        config.clone(),
        temp_dir.path().to_path_buf(),
        "test-run".to_string(),
    )
    .await
    .unwrap();

    let (update_tx, update_rx) = mpsc::channel::<CoordinatorEvent>(8192);
    let token = create_test_token();
    let tokens = DashMap::new();
    tokens.insert(Arc::from("graph"), Arc::new(TokenState::new(token)));

    let stats = Arc::new(oradaz::utils::stats::Stats::new());
    let condition_checker = ConditionChecker {
        client: OradazClient::new(&config).unwrap(),
        tenant_conditions: HashMap::new(),
        user_conditions: DashMap::new(),
        emergency_accounts_custom_attributes: String::from("Emergency.isEmergency"),
        org_url: String::new(),
        stats: Arc::clone(&stats),
        is_application_auth: false,
    };

    let thread = ResponseThread::new(
        update_tx,
        ResponseContext {
            writer,
            metadata: Arc::new(Mutex::new(HashMap::<String, TableMetadata>::new())),
            tokens: Arc::new(tokens),
            condition_checker: Arc::new(condition_checker),
            ratelimit_manager: Arc::new(RateLimitManager::default()),
            concurrency_controller: Arc::new(
                oradaz::collect::dump::concurrency::ConcurrencyController::default(),
            ),
            stats,
            logs_date_filter_and: None,
        },
        Box::new(ResponseContent { api_call, response }),
    );

    (update_rx, thread, temp_dir)
}

#[tokio::test]
async fn test_relationship_chain() {
    // 1. Setup API A (Users) with relationship to API B (Managers)
    let mut url_a = create_test_url();
    url_a.api = "users".to_string();
    url_a.url = "https://graph.microsoft.com/v1.0/users".to_string();

    let rel_a_to_b = RelationshipUrl {
        service: "graph".to_string(),
        url_scheme: "https://graph.microsoft.com[URI]".to_string(),
        default_api_behavior: HashMap::new(),
        default_parameters: None,
        api: "managers".to_string(),
        name: "manager".to_string(),
        uri: "/v1.0/managers/{managerId}".to_string(),
        conditions: None,
        api_behavior: None,
        expected_error_codes: None,
        parameters: None,
        keys: Some(vec![oradaz::utils::url::Parameter {
            name: "{managerId}".to_string(),
            value: "managerId".to_string(),
            transform: None,
            conditions: None,
        }]),
        relationships: Some(vec![oradaz::utils::url::Relationship {
            name: "manager_details".to_string(),
            uri: "/v1.0/managers/{managerId}/details".to_string(),
            conditions: None,
            api_behavior: None,
            parameters: None,
            keys: Some(vec![oradaz::utils::url::Parameter {
                name: "{managerId}".to_string(),
                value: "id".to_string(),
                transform: None,
                conditions: None,
            }]),
            relationships: None,
            expected_error_codes: None,
        }]),
    };
    url_a.relationships = Arc::new(vec![rel_a_to_b]);

    let api_call_a = create_test_api_call(url_a);
    let response_a = Response {
        status: 200,
        retry_after: None,
        content: json!({
            "value": [
                {"id": "u1", "managerId": "m1"},
                {"id": "u2", "managerId": "m2"}
            ]
        }),
    };

    let (_rx, thread, _dir) = setup_response_thread(api_call_a.clone(), response_a.clone()).await;

    // Process API A response
    let urls_b = thread.process_single(&response_a, &api_call_a).await;

    assert_eq!(urls_b.len(), 2, "Expected 2 manager URLs");
    assert!(urls_b.iter().any(|u| u.url.contains("m1")));
    assert!(urls_b.iter().any(|u| u.url.contains("m2")));

    // Request-shape telemetry: the two child URLs are recorded against the parent
    // API (graph/users).
    let stats_json: serde_json::Value = serde_json::to_value(&*thread.context.stats).unwrap();
    let parent_api = stats_json["apis"]
        .as_array()
        .and_then(|a| a.iter().find(|e| e["api"] == "users"))
        .expect("api stats for users");
    assert_eq!(
        parent_api["child_urls_generated"], 2,
        "relationship expansion must increment child_urls_generated"
    );

    // Verify that the generated URLs for API B also contain the nested relationship to API C
    for url_b in &urls_b {
        assert_eq!(url_b.api, "managers_manager");
        assert!(
            !url_b.relationships.is_empty(),
            "Manager URL should have nested relationship to details"
        );
        assert_eq!(url_b.relationships[0].api, "managers_manager");
    }

    // 2. Process API B response (Simulate)
    let url_b = urls_b[0].clone();
    let api_call_b = create_test_api_call(url_b);
    let response_b = Response {
        status: 200,
        retry_after: None,
        content: json!({
            "value": [
                {"id": "m1", "detailId": "d1"}
            ]
        }),
    };

    let urls_c = thread.process_single(&response_b, &api_call_b).await;

    assert!(!urls_c.is_empty(), "Expected at least one detail URL");
    assert!(urls_c[0].url.contains("m1"));
    assert!(urls_c[0].url.contains("details"));
}

/// Build a `signIns`-style relationship (per-user audit logs) that fabricates the
/// optional `[SIGNIN_FILTER]` marker in its URI to exercise the response-time
/// substitution path. The bundled schema does not carry the marker (per-user
/// sign-in date bounding is opt-in), so this is deliberately not a mirror of it.
fn signins_relationship() -> RelationshipUrl {
    RelationshipUrl {
        service: "graph".to_string(),
        url_scheme: "https://graph.microsoft.com/v1.0/[URI]".to_string(),
        default_api_behavior: HashMap::new(),
        default_parameters: None,
        api: "users".to_string(),
        name: "signIns".to_string(),
        uri: "auditLogs/signIns?$filter=userId eq '[1]'[SIGNIN_FILTER]".to_string(),
        conditions: None,
        api_behavior: None,
        expected_error_codes: None,
        parameters: None,
        keys: Some(vec![oradaz::utils::url::Parameter {
            name: "[1]".to_string(),
            value: "id".to_string(),
            transform: None,
            conditions: None,
        }]),
        relationships: None,
    }
}

async fn build_signins_urls(filter: Option<Arc<str>>) -> Vec<OradazUrl> {
    let mut url_a = create_test_url();
    url_a.relationships = Arc::new(vec![signins_relationship()]);
    let api_call = create_test_api_call(url_a);
    let response = Response {
        status: 200,
        retry_after: None,
        content: json!({ "value": [{ "id": "u1" }] }),
    };

    let (_rx, mut thread, _dir) = setup_response_thread(api_call.clone(), response.clone()).await;
    thread.context.logs_date_filter_and = filter;
    thread.process_single(&response, &api_call).await
}

#[tokio::test]
async fn test_signins_relationship_date_filter_merged() {
    // When a date bound is configured, the per-user signIns URL must merge it
    // into the existing `$filter=userId eq '…'` clause with ` and …`.
    let urls = build_signins_urls(Some(Arc::from(
        " and createdDateTime ge 2026-05-23T00:00:00Z",
    )))
    .await;
    assert_eq!(urls.len(), 1, "Expected one signIns URL");
    assert_eq!(
        urls[0].url,
        "https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=userId eq 'u1' and createdDateTime ge 2026-05-23T00:00:00Z"
    );
}

#[tokio::test]
async fn test_signins_relationship_no_date_filter_strips_placeholder() {
    // With date bounding disabled the placeholder must collapse to nothing,
    // leaving a clean, valid URL (no leftover `[SIGNIN_FILTER]`).
    let urls = build_signins_urls(None).await;
    assert_eq!(urls.len(), 1, "Expected one signIns URL");
    assert_eq!(
        urls[0].url,
        "https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=userId eq 'u1'"
    );
    assert!(!urls[0].url.contains("[SIGNIN_FILTER]"));
}

#[tokio::test]
async fn test_nested_relationship_preserves_own_conditions() {
    // A nested (level-2+) relationship must carry its **own** `conditions`,
    // not inherit the parent relationship's. Inheriting the parent's conditions
    // would silently bypass schema guards (e.g. `P2`) on level-2 endpoints,
    // dispatching them even on tenants that don't satisfy the guard.
    let mut url_a = create_test_url();

    let parent = RelationshipUrl {
        service: "graph".to_string(),
        url_scheme: "https://graph.microsoft.com[URI]".to_string(),
        default_api_behavior: HashMap::new(),
        default_parameters: None,
        api: "managers".to_string(),
        name: "manager".to_string(),
        uri: "/v1.0/managers/{managerId}".to_string(),
        // Parent relationship has NO conditions.
        conditions: None,
        api_behavior: None,
        expected_error_codes: None,
        parameters: None,
        keys: Some(vec![oradaz::utils::url::Parameter {
            name: "{managerId}".to_string(),
            value: "managerId".to_string(),
            transform: None,
            conditions: None,
        }]),
        // Nested relationship declares its OWN P2 guard.
        relationships: Some(vec![oradaz::utils::url::Relationship {
            name: "pim_eligibility".to_string(),
            uri: "/v1.0/managers/{managerId}/pim".to_string(),
            conditions: Some(vec!["P2".to_string()]),
            api_behavior: None,
            parameters: None,
            keys: Some(vec![oradaz::utils::url::Parameter {
                name: "{managerId}".to_string(),
                value: "id".to_string(),
                transform: None,
                conditions: None,
            }]),
            relationships: None,
            expected_error_codes: None,
        }]),
    };
    url_a.relationships = Arc::new(vec![parent]);

    let api_call_a = create_test_api_call(url_a);
    let response_a = Response {
        status: 200,
        retry_after: None,
        content: json!({ "value": [{ "id": "u1", "managerId": "m1" }] }),
    };

    let (_rx, thread, _dir) = setup_response_thread(api_call_a.clone(), response_a.clone()).await;
    let urls_b = thread.process_single(&response_a, &api_call_a).await;

    assert_eq!(urls_b.len(), 1, "Expected one parent (manager) URL");

    // The parent URL correctly carries the parent relationship's conditions (None).
    assert_eq!(
        urls_b[0].conditions, None,
        "Parent URL should carry the parent relationship's conditions"
    );

    // The nested relationship must keep its OWN P2 condition, not inherit the parent's
    // `None`. With the pre-fix bug this came back `None`, bypassing the guard.
    assert_eq!(
        urls_b[0].relationships.len(),
        1,
        "Parent URL should carry its nested relationship"
    );
    assert_eq!(
        urls_b[0].relationships[0].conditions,
        Some(vec!["P2".to_string()]),
        "Nested relationship must preserve its own P2 condition, not inherit the parent's None"
    );
}

#[tokio::test]
async fn relationship_real_conditioned_key_with_nonstring_value_is_skipped() {
    // A real key whose token (`[1]`) appears in the URI and which carries a
    // condition, but whose parent value is not a string, cannot be substituted.
    // The relationship must be skipped rather than dispatched with the literal
    // token still in the path. The placeholder shortcut (continue without
    // substituting) is reserved for the dedicated `[PLACEHOLDER]` key.
    let config = default_test_config();
    let condition_checker = ConditionChecker {
        client: OradazClient::new(&config).unwrap(),
        tenant_conditions: HashMap::new(),
        user_conditions: DashMap::new(),
        emergency_accounts_custom_attributes: String::from("Emergency.isEmergency"),
        org_url: String::new(),
        stats: Arc::new(oradaz::utils::stats::Stats::new()),
        is_application_auth: false,
    };
    let token = create_test_token();

    let rel = RelationshipUrl {
        service: "graph".to_string(),
        url_scheme: "https://graph.microsoft.com/v1.0/[URI]".to_string(),
        default_api_behavior: HashMap::new(),
        default_parameters: None,
        api: "things".to_string(),
        name: "thing".to_string(),
        uri: "things/[1]".to_string(),
        conditions: None,
        api_behavior: None,
        expected_error_codes: None,
        parameters: None,
        keys: Some(vec![oradaz::utils::url::Parameter {
            name: "[1]".to_string(),
            value: "id".to_string(),
            transform: None,
            conditions: Some(vec!["IsAssignableToRole".to_string()]),
        }]),
        relationships: None,
    };

    // `id` resolves to an object (satisfying the condition) rather than a string,
    // so the `[1]` token cannot be substituted.
    let url = rel
        .get_url(
            &token,
            &json!({ "id": { "isAssignableToRole": true } }),
            String::new(),
            &condition_checker,
            0,
        )
        .await;
    assert!(
        url.is_empty(),
        "expected the relationship to be skipped, got {url:?}"
    );
}
