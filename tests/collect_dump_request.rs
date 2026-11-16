mod common;

use crate::common::default_test_config;
use oradaz::collect::auth::tokens::{Token, TokenState};
use oradaz::collect::dump::concurrency::ConcurrencyController;
use oradaz::collect::dump::orchestration::events::CoordinatorEvent;
use oradaz::collect::dump::ratelimit::RateLimitManager;
use oradaz::collect::dump::request::RequestsThread;
use oradaz::collect::dump::response::ResponseMsg;
use oradaz::utils::client::OradazClient;
use oradaz::utils::url::{ApiCall, ApiCallItem, BatchData, RetryLimits, Url as OradazUrl};

use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use wiremock::matchers::{bearer_token, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn create_test_token() -> Token {
    Token {
        tenant_id: "test-tenant".to_string(),
        client_id: "test-client".to_string(),
        service: "graph".to_string(),
        expires_on: chrono::Utc::now().timestamp() + 3600, // 1 hour from now
        access_token: "test_access_token".to_string(),
        refresh_token: Some("test_refresh_token".to_string()),
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
        force_single: false,
        forced_single_tracker: None,
        post_body: None,
        timeout_strikes: 0,
    }
}

fn create_test_api_call() -> ApiCall {
    ApiCall {
        id: 0,
        url: create_test_url(),
        success_code: 200,
        value_pointer: "/value".to_string(),
        is_batch: false,
        batch_data: None,
    }
}

#[tokio::test]
async fn test_api_request_successful_response() {
    let mock_server = MockServer::start().await;

    // Mock Microsoft Graph API response
    Mock::given(method("GET"))
        .and(path("/v1.0/applications"))
        .and(bearer_token("test_access_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#applications",
            "value": [
                {
                    "id": "app-123",
                    "displayName": "Test Application",
                    "appId": "test-app-id"
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    let token = create_test_token();
    let mut api_call = create_test_api_call();
    api_call.url.url = format!("{}/v1.0/applications", mock_server.uri());

    // Create channels for communication
    let (response_tx, mut response_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (update_tx, _update_rx) = mpsc::channel::<CoordinatorEvent>(8192);

    let tokens = Arc::new(DashMap::new());
    tokens.insert(Arc::from("graph"), Arc::new(TokenState::new(token)));

    // Create and run the request thread
    let request_thread = RequestsThread::new(
        response_tx,
        update_tx,
        oradaz::collect::dump::request::RequestExecutionContext {
            oradaz_client: client,
            tokens,
            ratelimit_manager: Arc::new(RateLimitManager::default()),
            concurrency_controller: Arc::new(ConcurrencyController::default()),
            stats: Arc::new(oradaz::utils::stats::Stats::new()),
            config: Arc::new(default_test_config()),
        },
        Box::new(api_call),
    );

    request_thread.process().await;

    // Should receive a successful response
    match response_rx.try_recv() {
        Ok(ResponseMsg::ResponseData(data)) => {
            assert_eq!(data.response.status, 200);
            assert!(data.response.content.is_object());
            let obj = data.response.content.as_object().unwrap();
            assert!(obj.contains_key("@odata.context"));
            assert!(obj.contains_key("value"));
            let value = obj.get("value").unwrap().as_array().unwrap();
            assert_eq!(value.len(), 1);
            let app = value[0].as_object().unwrap();
            assert_eq!(app.get("id").unwrap(), "app-123");
        }
        _ => panic!("Expected ResponseData message for successful response"),
    }
}

/// Integration guard for the HTTP-latency wiring: driving the *real*
/// `RequestsThread::process()` for a single GET must populate the per-service
/// **and** per-API latency counters (the single-call path records both). This
/// asserts the call site, not just the `record_http_latency` method.
#[tokio::test]
async fn test_api_request_records_http_latency() {
    use std::sync::atomic::Ordering;

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1.0/applications"))
        .and(bearer_token("test_access_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "id": "app-123" }]
        })))
        .mount(&mock_server)
        .await;

    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    let token = create_test_token();
    let mut api_call = create_test_api_call();
    api_call.url.url = format!("{}/v1.0/applications", mock_server.uri());

    let (response_tx, mut response_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (update_tx, _update_rx) = mpsc::channel::<CoordinatorEvent>(8192);
    let tokens = Arc::new(DashMap::new());
    tokens.insert(Arc::from("graph"), Arc::new(TokenState::new(token)));

    // Hold the stats Arc so we can read what the request thread populated.
    let stats = Arc::new(oradaz::utils::stats::Stats::new());
    let request_thread = RequestsThread::new(
        response_tx,
        update_tx,
        oradaz::collect::dump::request::RequestExecutionContext {
            oradaz_client: client,
            tokens,
            ratelimit_manager: Arc::new(RateLimitManager::default()),
            concurrency_controller: Arc::new(ConcurrencyController::default()),
            stats: Arc::clone(&stats),
            config: Arc::new(default_test_config()),
        },
        Box::new(api_call),
    );
    request_thread.process().await;
    let _ = response_rx.try_recv(); // drain

    let svc_count = stats
        .services
        .get("graph")
        .map(|s| s.http_latency_count.load(Ordering::Relaxed))
        .unwrap_or(0);
    assert_eq!(
        svc_count, 1,
        "the request thread must record one service-level latency sample"
    );
    let api_count = stats
        .apis
        .get("graph/applications")
        .map(|a| a.http_latency_count.load(Ordering::Relaxed))
        .unwrap_or(0);
    assert_eq!(
        api_count, 1,
        "a single call must record one per-API latency sample"
    );
}

#[tokio::test]
async fn test_api_request_malformed_json_response() {
    let mock_server = MockServer::start().await;

    // Mock response with invalid JSON
    Mock::given(method("GET"))
        .and(path("/v1.0/applications"))
        .and(bearer_token("test_access_token"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"invalid": json"#))
        .mount(&mock_server)
        .await;

    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    let token = create_test_token();
    let mut api_call = create_test_api_call();
    api_call.url.url = format!("{}/v1.0/applications", mock_server.uri());

    let (response_tx, _response_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (update_tx, mut update_rx) = mpsc::channel::<CoordinatorEvent>(8192);

    let tokens = Arc::new(DashMap::new());
    tokens.insert(Arc::from("graph"), Arc::new(TokenState::new(token)));

    let request_thread = RequestsThread::new(
        response_tx,
        update_tx,
        oradaz::collect::dump::request::RequestExecutionContext {
            oradaz_client: client,
            tokens,
            ratelimit_manager: Arc::new(RateLimitManager::default()),
            concurrency_controller: Arc::new(ConcurrencyController::default()),
            stats: Arc::new(oradaz::utils::stats::Stats::new()),
            config: Arc::new(default_test_config()),
        },
        Box::new(api_call),
    );

    request_thread.process().await;

    // For malformed JSON, the code retries by sending a single RequestCompleted with the retry URL.
    match update_rx.try_recv() {
        Ok(CoordinatorEvent::RequestCompleted { count: 1, .. }) => {
            // Expected: request finished with the retry URL in new_urls
        }
        _ => panic!("Expected RequestCompleted for malformed JSON retry"),
    }
}

#[tokio::test]
async fn test_api_request_with_retry_after_header() {
    let mock_server = MockServer::start().await;

    // Mock rate limited response with Retry-After header
    Mock::given(method("GET"))
        .and(path("/v1.0/applications"))
        .and(bearer_token("test_access_token"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(serde_json::json!({
                    "error": {
                        "code": "TooManyRequests",
                        "message": "Request rate exceeded."
                    }
                }))
                .insert_header("Retry-After", "30"),
        )
        .mount(&mock_server)
        .await;

    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    let token = create_test_token();
    let mut api_call = create_test_api_call();
    api_call.url.url = format!("{}/v1.0/applications", mock_server.uri());

    // Create channels for communication
    let (response_tx, mut response_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (update_tx, _update_rx) = mpsc::channel::<CoordinatorEvent>(8192);

    let tokens = Arc::new(DashMap::new());
    tokens.insert(Arc::from("graph"), Arc::new(TokenState::new(token)));

    // Create and run the request thread
    let request_thread = RequestsThread::new(
        response_tx,
        update_tx,
        oradaz::collect::dump::request::RequestExecutionContext {
            oradaz_client: client,
            tokens,
            ratelimit_manager: Arc::new(RateLimitManager::default()),
            concurrency_controller: Arc::new(ConcurrencyController::default()),
            stats: Arc::new(oradaz::utils::stats::Stats::new()),
            config: Arc::new(default_test_config()),
        },
        Box::new(api_call),
    );

    request_thread.process().await;

    // Should receive a 429 response
    match response_rx.try_recv() {
        Ok(ResponseMsg::ResponseData(data)) => {
            assert_eq!(data.response.status, 429);
            assert!(data.response.content.is_object());
            let obj = data.response.content.as_object().unwrap();
            assert!(obj.contains_key("error"));
            let error_obj = obj.get("error").unwrap().as_object().unwrap();
            assert_eq!(error_obj.get("code").unwrap(), "TooManyRequests");
        }
        _ => panic!("Expected ResponseData message for 429 response"),
    }
}

#[tokio::test]
async fn test_api_request_retry_backoff() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1.0/applications"))
        .and(bearer_token("test_access_token"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(serde_json::json!({
                    "error": {
                        "code": "TooManyRequests",
                        "message": "Request rate exceeded."
                    }
                }))
                .insert_header("Retry-After", "1"),
        )
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1.0/applications"))
        .and(bearer_token("test_access_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{"id": "app-1"}]
        })))
        .mount(&mock_server)
        .await;

    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    let token = create_test_token();
    let mut api_call = create_test_api_call();
    api_call.url.url = format!("{}/v1.0/applications", mock_server.uri());

    let (response_tx, mut response_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (update_tx, _update_rx) = mpsc::channel::<CoordinatorEvent>(8192);

    let tokens = Arc::new(DashMap::new());
    tokens.insert(Arc::from("graph"), Arc::new(TokenState::new(token)));

    let request_thread = RequestsThread::new(
        response_tx,
        update_tx,
        oradaz::collect::dump::request::RequestExecutionContext {
            oradaz_client: client,
            tokens,
            ratelimit_manager: Arc::new(RateLimitManager::default()),
            concurrency_controller: Arc::new(ConcurrencyController::default()),
            stats: Arc::new(oradaz::utils::stats::Stats::new()),
            config: Arc::new(default_test_config()),
        },
        Box::new(api_call),
    );

    request_thread.process().await;

    match response_rx.try_recv() {
        Ok(ResponseMsg::ResponseData(data)) => {
            assert_eq!(data.response.status, 429);
        }
        _ => panic!("Expected ResponseData message for retried request"),
    }
}

#[tokio::test]
async fn test_api_request_server_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1.0/applications"))
        .and(bearer_token("test_access_token"))
        .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
            "error": {
                "code": "InternalServerError",
                "message": "Something went wrong."
            }
        })))
        .mount(&mock_server)
        .await;

    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    let token = create_test_token();
    let mut api_call = create_test_api_call();
    api_call.url.url = format!("{}/v1.0/applications", mock_server.uri());

    // Create channels for communication
    let (response_tx, mut response_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (update_tx, _update_rx) = mpsc::channel::<CoordinatorEvent>(8192);

    let tokens = Arc::new(DashMap::new());
    tokens.insert(Arc::from("graph"), Arc::new(TokenState::new(token)));

    let request_thread = RequestsThread::new(
        response_tx,
        update_tx,
        oradaz::collect::dump::request::RequestExecutionContext {
            oradaz_client: client,
            tokens,
            ratelimit_manager: Arc::new(RateLimitManager::default()),
            concurrency_controller: Arc::new(ConcurrencyController::default()),
            stats: Arc::new(oradaz::utils::stats::Stats::new()),
            config: Arc::new(default_test_config()),
        },
        Box::new(api_call),
    );

    request_thread.process().await;

    match response_rx.try_recv() {
        Ok(ResponseMsg::ResponseData(data)) => {
            assert_eq!(data.response.status, 500);
            assert!(data.response.content.is_object());
            let obj = data.response.content.as_object().unwrap();
            assert!(obj.contains_key("error"));
        }
        _ => panic!("Expected ResponseData message for 500 error"),
    }
}

#[tokio::test]
async fn test_pagination_aggregates_results() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1.0/users"))
        .and(bearer_token("test_access_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "id": "u1" }, { "id": "u2" }],
        })))
        .mount(&mock_server)
        .await;

    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    let token = create_test_token();
    let mut api_call = create_test_api_call();
    api_call.url.url = format!("{}/v1.0/users", mock_server.uri());

    let (response_tx, mut response_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (update_tx, _update_rx) = mpsc::channel::<CoordinatorEvent>(8192);

    let tokens = Arc::new(DashMap::new());
    tokens.insert(Arc::from("graph"), Arc::new(TokenState::new(token)));

    let request_thread = RequestsThread::new(
        response_tx,
        update_tx,
        oradaz::collect::dump::request::RequestExecutionContext {
            oradaz_client: client,
            tokens,
            ratelimit_manager: Arc::new(RateLimitManager::default()),
            concurrency_controller: Arc::new(ConcurrencyController::default()),
            stats: Arc::new(oradaz::utils::stats::Stats::new()),
            config: Arc::new(default_test_config()),
        },
        Box::new(api_call),
    );

    request_thread.process().await;

    match response_rx.try_recv() {
        Ok(ResponseMsg::ResponseData(data)) => {
            let values = data.response.content["value"]
                .as_array()
                .expect("value not array");
            let ids: Vec<&str> = values.iter().map(|v| v["id"].as_str().unwrap()).collect();
            assert_eq!(ids, vec!["u1", "u2"]);
        }
        _ => panic!("Expected ResponseData message for paginated results"),
    }
}

#[tokio::test]
async fn test_batch_api_request() {
    let mock_server = MockServer::start().await;

    // Mock batch API response
    Mock::given(method("POST"))
        .and(path("/v1.0/$batch"))
        .and(bearer_token("test_access_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "responses": [
                {
                    "id": "1",
                    "status": 200,
                    "body": {
                        "id": "app-123",
                        "displayName": "Test Application"
                    }
                },
                {
                    "id": "2",
                    "status": 200,
                    "body": {
                        "id": "app-456",
                        "displayName": "Another Application"
                    }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    let token = create_test_token();

    // Create batch API call
    let batch_data = BatchData {
        post_data: HashMap::new(), // Empty for this test
        initial_data: HashMap::new(),
        id_field: "id".to_string(),
        body_field: "body".to_string(),
        status_field: "status".to_string(),
        retry_after_field: "headers/Retry-After".to_string(),
    };

    let api_call = ApiCall {
        id: 0,
        url: OradazUrl {
            service_name: "graph".to_string(),
            service_scopes: Arc::new(vec!["https://graph.microsoft.com/.default".to_string()]),
            service_mandatory_auth: true,
            api: "$batch".to_string(),
            url: format!("{}/v1.0/$batch", mock_server.uri()),
            conditions: None,
            relationships: Arc::new(vec![]),
            api_behavior: Arc::new(HashMap::new()),
            expected_error_codes: None,
            parent: None,
            retry_number: 0,
            rate_limit_retry_number: 0,
            rate_limit_total_wait_secs: 0,
            network_retry_number: 0,
            force_single: false,
            forced_single_tracker: None,
            post_body: None,
            timeout_strikes: 0,
        },
        success_code: 200,
        value_pointer: "/responses".to_string(),
        is_batch: true,
        batch_data: Some(batch_data),
    };

    // Create channels for communication
    let (response_tx, mut response_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (update_tx, _update_rx) = mpsc::channel::<CoordinatorEvent>(8192);

    let tokens = Arc::new(DashMap::new());
    tokens.insert(Arc::from("graph"), Arc::new(TokenState::new(token)));

    // Create and run the request thread
    let request_thread = RequestsThread::new(
        response_tx,
        update_tx,
        oradaz::collect::dump::request::RequestExecutionContext {
            oradaz_client: client,
            tokens,
            ratelimit_manager: Arc::new(RateLimitManager::default()),
            concurrency_controller: Arc::new(ConcurrencyController::default()),
            stats: Arc::new(oradaz::utils::stats::Stats::new()),
            config: Arc::new(default_test_config()),
        },
        Box::new(api_call),
    );

    request_thread.process().await;

    // Check that we received a successful batch response
    match response_rx.try_recv() {
        Ok(ResponseMsg::ResponseData(data)) => {
            assert_eq!(data.response.status, 200);
            assert!(data.response.content.is_object());
            let obj = data.response.content.as_object().unwrap();
            assert!(obj.contains_key("responses"));
            let responses = obj.get("responses").unwrap().as_array().unwrap();
            assert_eq!(responses.len(), 2);
        }
        _ => panic!("Expected ResponseData message for batch request"),
    }
}

#[tokio::test]
async fn test_exchange_batch_api_request() {
    let mock_server = MockServer::start().await;

    // Mock Exchange admin-API batch response (OData JSON batch shape). The
    // `Accept: application/json` matcher pins the fix that makes Exchange return
    // a JSON envelope instead of its default multipart/mixed batch response: if
    // the header regresses the request will not match and the test fails.
    Mock::given(method("POST"))
        .and(path("/adminapi/beta/test-tenant/$batch"))
        .and(bearer_token("test_access_token"))
        .and(header("accept", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "responses": [
                {
                    "id": "1",
                    "status": 200,
                    "body": { "value": [ { "Identity": "m1" } ] }
                },
                {
                    "id": "2",
                    "status": 200,
                    "body": { "value": [ { "Identity": "m2" } ] }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    let mut token = create_test_token();
    token.service = "exchange".to_string();

    // Build the envelope through the real builder so the `$batch` endpoint
    // derivation from the sub-URL root is exercised end-to-end.
    let make_url = |api: &str, path: &str| OradazUrl {
        service_name: "exchange".to_string(),
        service_scopes: Arc::new(vec!["https://outlook.office365.com/.default".to_string()]),
        service_mandatory_auth: false,
        api: api.to_string(),
        url: format!("{}/adminapi/beta/test-tenant{}", mock_server.uri(), path),
        conditions: None,
        relationships: Arc::new(vec![]),
        api_behavior: Arc::new(HashMap::new()),
        expected_error_codes: None,
        parent: None,
        retry_number: 0,
        rate_limit_retry_number: 0,
        rate_limit_total_wait_secs: 0,
        network_retry_number: 0,
        force_single: false,
        forced_single_tracker: None,
        post_body: None,
        timeout_strikes: 0,
    };
    let mut urls = vec![
        make_url("mailboxes", "/Mailbox?PropertySet=All"),
        make_url("recipients", "/Recipient?PropertySet=All"),
    ];
    let limits = RetryLimits {
        retry: 5,
        rate_limit_retry: 50,
        rate_limit_max_wait_secs: 900,
    };
    let mut items = ApiCall::from("exchange", &mut urls, limits).unwrap();
    assert_eq!(items.len(), 1, "Expected one exchange batch envelope");
    let api_call = match items.pop() {
        Some(ApiCallItem::ApiCall(call)) => call,
        _ => panic!("Expected an ApiCall item"),
    };
    assert!(api_call.is_batch);
    assert_eq!(
        api_call.url.url,
        format!("{}/adminapi/beta/test-tenant/$batch", mock_server.uri())
    );

    // Create channels for communication
    let (response_tx, mut response_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (update_tx, _update_rx) = mpsc::channel::<CoordinatorEvent>(8192);

    let tokens = Arc::new(DashMap::new());
    tokens.insert(Arc::from("exchange"), Arc::new(TokenState::new(token)));

    // Create and run the request thread
    let request_thread = RequestsThread::new(
        response_tx,
        update_tx,
        oradaz::collect::dump::request::RequestExecutionContext {
            oradaz_client: client,
            tokens,
            ratelimit_manager: Arc::new(RateLimitManager::default()),
            concurrency_controller: Arc::new(ConcurrencyController::default()),
            stats: Arc::new(oradaz::utils::stats::Stats::new()),
            config: Arc::new(default_test_config()),
        },
        api_call,
    );

    request_thread.process().await;

    // Check that we received a successful batch response
    match response_rx.try_recv() {
        Ok(ResponseMsg::ResponseData(data)) => {
            assert_eq!(data.response.status, 200);
            let obj = data.response.content.as_object().unwrap();
            let responses = obj.get("responses").unwrap().as_array().unwrap();
            assert_eq!(responses.len(), 2);
        }
        _ => panic!("Expected ResponseData message for exchange batch request"),
    }
}

#[tokio::test]
async fn test_batch_api_request_with_error() {
    let mock_server = MockServer::start().await;

    // Mock batch API response with one error
    Mock::given(method("POST"))
        .and(path("/v1.0/$batch"))
        .and(bearer_token("test_access_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "responses": [
                {
                    "id": "1",
                    "status": 200,
                    "body": {
                        "id": "app-123",
                        "displayName": "Test Application"
                    }
                },
                {
                    "id": "2",
                    "status": 404,
                    "body": {
                        "error": {
                            "code": "NotFound",
                            "message": "Application not found"
                        }
                    }
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    let token = create_test_token();

    // Create batch API call
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
        url: OradazUrl {
            service_name: "graph".to_string(),
            service_scopes: Arc::new(vec!["https://graph.microsoft.com/.default".to_string()]),
            service_mandatory_auth: true,
            api: "$batch".to_string(),
            url: format!("{}/v1.0/$batch", mock_server.uri()),
            conditions: None,
            relationships: Arc::new(vec![]),
            api_behavior: Arc::new(HashMap::new()),
            expected_error_codes: None,
            parent: None,
            retry_number: 0,
            rate_limit_retry_number: 0,
            rate_limit_total_wait_secs: 0,
            network_retry_number: 0,
            force_single: false,
            forced_single_tracker: None,
            post_body: None,
            timeout_strikes: 0,
        },
        success_code: 200,
        value_pointer: "/responses".to_string(),
        is_batch: true,
        batch_data: Some(batch_data),
    };

    // Create channels for communication
    let (response_tx, mut response_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (update_tx, _update_rx) = mpsc::channel::<CoordinatorEvent>(8192);

    let tokens = Arc::new(DashMap::new());
    tokens.insert(Arc::from("graph"), Arc::new(TokenState::new(token)));

    // Create and run the request thread
    let request_thread = RequestsThread::new(
        response_tx,
        update_tx,
        oradaz::collect::dump::request::RequestExecutionContext {
            oradaz_client: client,
            tokens,
            ratelimit_manager: Arc::new(RateLimitManager::default()),
            concurrency_controller: Arc::new(ConcurrencyController::default()),
            stats: Arc::new(oradaz::utils::stats::Stats::new()),
            config: Arc::new(default_test_config()),
        },
        Box::new(api_call),
    );

    request_thread.process().await;

    // Check that we received the batch response with mixed statuses
    match response_rx.try_recv() {
        Ok(ResponseMsg::ResponseData(data)) => {
            assert_eq!(data.response.status, 200);
            let responses = data.response.content["responses"].as_array().unwrap();
            assert_eq!(responses.len(), 2);
            assert_eq!(responses[0]["status"], 200);
            assert_eq!(responses[1]["status"], 404);
        }
        _ => panic!("Expected ResponseData message for batch request with error"),
    }
}

#[tokio::test]
async fn test_request_thread_missing_token() {
    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    let api_call = create_test_api_call();

    // Create channels for communication
    let (response_tx, mut response_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (update_tx, _update_rx) = mpsc::channel::<CoordinatorEvent>(8192);

    // Empty tokens map - no token for "graph" service
    let tokens = Arc::new(DashMap::new());

    // Create and run the request thread
    let request_thread = RequestsThread::new(
        response_tx,
        update_tx,
        oradaz::collect::dump::request::RequestExecutionContext {
            oradaz_client: client,
            tokens,
            ratelimit_manager: Arc::new(RateLimitManager::default()),
            concurrency_controller: Arc::new(ConcurrencyController::default()),
            stats: Arc::new(oradaz::utils::stats::Stats::new()),
            config: Arc::new(default_test_config()),
        },
        Box::new(api_call),
    );

    request_thread.process().await;

    // Should receive an error about missing token
    match response_rx.try_recv() {
        Ok(ResponseMsg::DumpError(error, _)) => {
            assert_eq!(error.code, "NoTokenForApiCall");
            assert!(error.message.contains("Missing token for service"));
        }
        _ => panic!("Expected DumpError message for missing token"),
    }
}

/// A forced-single URL whose service has no token is abandoned as
/// `NoTokenForApiCall` with its own tracker, so the loss chokepoint closes the
/// transition.
#[tokio::test]
async fn missing_token_error_carries_forced_single_tracker() {
    use oradaz::utils::url::ForcedSingleTracker;

    let tracker = Arc::new(ForcedSingleTracker::new());
    let mut api_call = create_test_api_call();
    api_call.url.force_single = true;
    api_call.url.forced_single_tracker = Some(Arc::clone(&tracker));

    let (response_tx, mut response_rx) = mpsc::channel::<ResponseMsg>(64);
    let (update_tx, _update_rx) = mpsc::channel::<CoordinatorEvent>(64);
    let config = default_test_config();
    RequestsThread::new(
        response_tx,
        update_tx,
        oradaz::collect::dump::request::RequestExecutionContext {
            oradaz_client: OradazClient::new(&config).unwrap(),
            // No token for "graph".
            tokens: Arc::new(DashMap::new()),
            ratelimit_manager: Arc::new(RateLimitManager::default()),
            concurrency_controller: Arc::new(ConcurrencyController::default()),
            stats: Arc::new(oradaz::utils::stats::Stats::new()),
            config: Arc::new(config),
        },
        Box::new(api_call),
    )
    .process()
    .await;

    match response_rx.try_recv() {
        Ok(ResponseMsg::DumpError(error, _)) => {
            assert_eq!(error.code, "NoTokenForApiCall");
            let carried = error
                .forced_single_tracker
                .as_ref()
                .expect("the abandonment must carry the tracker");
            assert!(
                Arc::ptr_eq(carried, &tracker),
                "the abandonment must carry the URL's own tracker"
            );
        }
        _ => panic!("Expected DumpError message for missing token"),
    }
}

/// A 429 whose body is NOT valid JSON must still be routed as a throttle
/// (ResponseData with status 429 and null content), not collapsed into a
/// parse-error retry — otherwise the cooldown / AIMD backpressure is bypassed.
#[tokio::test]
async fn non_json_429_is_routed_as_throttle() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1.0/applications"))
        .and(bearer_token("test_access_token"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "12")
                .set_body_string("<html>Too Many Requests</html>"),
        )
        .mount(&mock_server)
        .await;

    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    let token = create_test_token();
    let mut api_call = create_test_api_call();
    api_call.url.url = format!("{}/v1.0/applications", mock_server.uri());

    let (response_tx, mut response_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (update_tx, _update_rx) = mpsc::channel::<CoordinatorEvent>(8192);
    let tokens = Arc::new(DashMap::new());
    tokens.insert(Arc::from("graph"), Arc::new(TokenState::new(token)));

    let request_thread = RequestsThread::new(
        response_tx,
        update_tx,
        oradaz::collect::dump::request::RequestExecutionContext {
            oradaz_client: client,
            tokens,
            ratelimit_manager: Arc::new(RateLimitManager::default()),
            concurrency_controller: Arc::new(ConcurrencyController::default()),
            stats: Arc::new(oradaz::utils::stats::Stats::new()),
            config: Arc::new(default_test_config()),
        },
        Box::new(api_call),
    );

    request_thread.process().await;

    match response_rx.try_recv() {
        Ok(ResponseMsg::ResponseData(data)) => {
            assert_eq!(
                data.response.status, 429,
                "non-JSON 429 must keep its status for throttle routing"
            );
            assert!(
                data.response.content.is_null(),
                "non-JSON body must yield null content, not a parse error"
            );
        }
        _ => panic!("Expected ResponseData(status=429) for a non-JSON throttle response"),
    }
}

/// A non-success status with a non-JSON body (e.g. a 500 HTML error page) keeps
/// its status so the response module can route/retry it, rather than being
/// swallowed as an opaque parse error.
#[tokio::test]
async fn non_json_500_is_routed_by_status() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1.0/applications"))
        .and(bearer_token("test_access_token"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&mock_server)
        .await;

    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    let token = create_test_token();
    let mut api_call = create_test_api_call();
    api_call.url.url = format!("{}/v1.0/applications", mock_server.uri());

    let (response_tx, mut response_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (update_tx, _update_rx) = mpsc::channel::<CoordinatorEvent>(8192);
    let tokens = Arc::new(DashMap::new());
    tokens.insert(Arc::from("graph"), Arc::new(TokenState::new(token)));

    let request_thread = RequestsThread::new(
        response_tx,
        update_tx,
        oradaz::collect::dump::request::RequestExecutionContext {
            oradaz_client: client,
            tokens,
            ratelimit_manager: Arc::new(RateLimitManager::default()),
            concurrency_controller: Arc::new(ConcurrencyController::default()),
            stats: Arc::new(oradaz::utils::stats::Stats::new()),
            config: Arc::new(default_test_config()),
        },
        Box::new(api_call),
    );

    request_thread.process().await;

    match response_rx.try_recv() {
        Ok(ResponseMsg::ResponseData(data)) => {
            assert_eq!(
                data.response.status, 500,
                "non-JSON 500 must keep its status"
            );
            assert!(data.response.content.is_null());
        }
        _ => panic!("Expected ResponseData(status=500) for a non-JSON server error"),
    }
}

// ─── force_single routing invariants ─────────────────────────────────────────
//
// A `Url` marked `force_single` must never enter a batch envelope: when it is
// the next LIFO candidate `ApiCall::from` dispatches it via the default single
// builder, and each batching loop stops filling the moment it pops a forced
// URL (pushing it back untouched). The queue is never scanned or reordered —
// the LIFO/DFS dispatch order is a hard invariant.

mod force_single_router {
    use super::*;
    use oradaz::utils::url::ForcedSingleTracker;

    fn limits() -> RetryLimits {
        RetryLimits {
            retry: 5,
            rate_limit_retry: 50,
            rate_limit_max_wait_secs: 900,
        }
    }

    fn make_url(service: &str, api: &str, url: &str) -> OradazUrl {
        OradazUrl {
            service_name: service.to_string(),
            service_scopes: Arc::new(vec![]),
            service_mandatory_auth: service != "exchange",
            api: api.to_string(),
            url: url.to_string(),
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
            force_single: false,
            forced_single_tracker: None,
            timeout_strikes: 0,
        }
    }

    fn forced(mut url: OradazUrl) -> OradazUrl {
        url.force_single = true;
        url.forced_single_tracker = Some(Arc::new(ForcedSingleTracker::new()));
        url
    }

    /// Splits the produced items into (single-dispatch URL strings, batch
    /// envelopes as vectors of their sub-request URL strings). Panics on an
    /// unexpected `ApiCallError`.
    fn split_items(items: &[ApiCallItem]) -> (Vec<String>, Vec<Vec<String>>) {
        let mut singles = Vec::new();
        let mut batches = Vec::new();
        for item in items {
            match item {
                ApiCallItem::ApiCall(call) if call.is_batch => {
                    let subs: Vec<String> = call
                        .batch_data
                        .as_ref()
                        .expect("batch call carries batch_data")
                        .initial_data
                        .values()
                        .map(|c| c.url.url.clone())
                        .collect();
                    batches.push(subs);
                }
                ApiCallItem::ApiCall(call) => singles.push(call.url.url.clone()),
                ApiCallItem::ApiCallError(err) => {
                    panic!("unexpected ApiCallError from router: {err:?}")
                }
            }
        }
        (singles, batches)
    }

    /// Drains `urls` through `ApiCall::from` until empty, returning all single
    /// URL strings and all batch envelopes (each as its sub-URL strings), and
    /// asserting no forced URL ever appears inside a batch.
    fn drain_all(
        service: &str,
        urls: &mut Vec<OradazUrl>,
        forced_urls: &[String],
    ) -> (Vec<String>, Vec<Vec<String>>) {
        let mut all_singles = Vec::new();
        let mut all_batches = Vec::new();
        let mut guard = 0;
        while !urls.is_empty() {
            guard += 1;
            assert!(guard <= 100, "router did not drain the queue (livelock)");
            let items = ApiCall::from(service, urls, limits()).expect("router must not fail");
            let (singles, batches) = split_items(&items);
            for batch in &batches {
                for sub in batch {
                    assert!(
                        !forced_urls.contains(sub),
                        "forced URL {sub:?} entered a batch envelope"
                    );
                }
            }
            all_singles.extend(singles);
            all_batches.extend(batches);
        }
        (all_singles, all_batches)
    }

    #[test]
    fn force_single_tail_is_dispatched_single_graph() {
        let normal = make_url("graph", "users", "https://graph.microsoft.com/v1.0/users");
        let fu = forced(make_url(
            "graph",
            "devices",
            "https://graph.microsoft.com/v1.0/devices",
        ));
        let forced_urls = vec![fu.url.clone()];
        // Tail = next LIFO candidate: [normal, forced] pops `forced` first.
        let mut urls = vec![normal.clone(), fu];
        let items = ApiCall::from("graph", &mut urls, limits()).unwrap();
        let (singles, batches) = split_items(&items);
        assert_eq!(singles, forced_urls, "forced tail must dispatch single");
        assert!(
            batches.is_empty(),
            "no batch may be built around a forced tail"
        );
        assert_eq!(urls.len(), 1, "the normal URL stays queued");
        // The remainder drains as a batch containing only the normal URL.
        let (singles2, batches2) = drain_all("graph", &mut urls, &forced_urls);
        assert!(singles2.is_empty());
        assert_eq!(batches2, vec![vec![normal.url]]);
    }

    #[test]
    fn force_single_internal_boundary_graph_v1_beta() {
        // [forced_older, normal_v1, normal_beta]: the first pass batches ONLY the
        // normal URLs (v1 and beta envelopes), leaves forced_older in place, and
        // the following dispatch is single.
        let fu = forced(make_url(
            "graph",
            "devices",
            "https://graph.microsoft.com/v1.0/devices",
        ));
        let n_v1 = make_url("graph", "users", "https://graph.microsoft.com/v1.0/users");
        let n_beta = make_url("graph", "groups", "https://graph.microsoft.com/beta/groups");
        let forced_urls = vec![fu.url.clone()];
        let mut urls = vec![fu.clone(), n_v1.clone(), n_beta.clone()];

        let items = ApiCall::from("graph", &mut urls, limits()).unwrap();
        let (singles, batches) = split_items(&items);
        assert!(singles.is_empty(), "first pass must produce batches only");
        let mut batched: Vec<String> = batches.iter().flatten().cloned().collect();
        batched.sort();
        let mut expected = vec![n_v1.url.clone(), n_beta.url.clone()];
        expected.sort();
        assert_eq!(batched, expected, "both normals batch, forced is left out");
        assert_eq!(urls.len(), 1, "forced_older must remain queued");
        assert!(urls[0].force_single);

        let items = ApiCall::from("graph", &mut urls, limits()).unwrap();
        let (singles, batches) = split_items(&items);
        assert_eq!(singles, forced_urls, "next dispatch is the forced single");
        assert!(batches.is_empty());
        assert!(urls.is_empty());
    }

    #[test]
    fn force_single_graph_cap_20_stops_at_forced() {
        // forced at the bottom, 24 normals above: 20-cap batch, then a 4-batch
        // that stops at the forced URL, then a single. Set in == set out.
        let fu = forced(make_url(
            "graph",
            "devices",
            "https://graph.microsoft.com/v1.0/devices/forced",
        ));
        let forced_urls = vec![fu.url.clone()];
        let mut urls = vec![fu];
        let mut expected_batched = Vec::new();
        for i in 0..24 {
            let u = make_url(
                "graph",
                "users",
                &format!("https://graph.microsoft.com/v1.0/users/{i}"),
            );
            expected_batched.push(u.url.clone());
            urls.push(u);
        }

        let items = ApiCall::from("graph", &mut urls, limits()).unwrap();
        let (_, batches) = split_items(&items);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 20, "first batch fills to the 20 cap");

        let (singles, mut batches2) = drain_all("graph", &mut urls, &forced_urls);
        assert_eq!(
            singles, forced_urls,
            "the forced URL dispatches single once"
        );
        assert_eq!(batches2.len(), 1, "second batch stops at the forced URL");
        assert_eq!(batches2[0].len(), 4);
        let mut all: Vec<String> = batches[0].clone();
        all.extend(batches2.remove(0));
        all.sort();
        expected_batched.sort();
        assert_eq!(all, expected_batched, "no normal URL is lost or duplicated");
    }

    #[test]
    fn force_single_resources_router_with_arg_adjacent() {
        // [forced_older, arg, normal]: batch takes only `normal`, defers the ARG
        // URL (is_arg push-back), then dispatches ARG single, then forced single.
        let fu = forced(make_url(
            "resources",
            "roleAssignments",
            "https://management.azure.com/subscriptions/sub-1/roleAssignments",
        ));
        let mut arg = make_url(
            "resources",
            "argResources",
            "https://management.azure.com/providers/Microsoft.ResourceGraph/resources",
        );
        let mut behavior = HashMap::new();
        behavior.insert("is_arg".to_string(), "true".to_string());
        arg.api_behavior = Arc::new(behavior);
        let normal = make_url(
            "resources",
            "subscriptions",
            "https://management.azure.com/subscriptions",
        );
        let forced_urls = vec![fu.url.clone()];
        let mut urls = vec![fu, arg.clone(), normal.clone()];

        let items = ApiCall::from("resources", &mut urls, limits()).unwrap();
        let (singles, batches) = split_items(&items);
        assert!(singles.is_empty());
        assert_eq!(batches, vec![vec![normal.url.clone()]]);
        assert_eq!(urls.len(), 2, "forced and ARG both remain queued");

        let items = ApiCall::from("resources", &mut urls, limits()).unwrap();
        let (singles, batches) = split_items(&items);
        assert_eq!(singles, vec![arg.url.clone()], "ARG dispatches single");
        assert!(batches.is_empty());

        let items = ApiCall::from("resources", &mut urls, limits()).unwrap();
        let (singles, batches) = split_items(&items);
        assert_eq!(singles, forced_urls, "forced URL dispatches single last");
        assert!(batches.is_empty());
        assert!(urls.is_empty());
    }

    #[test]
    fn force_single_resources_cap_20_stops_at_forced() {
        let fu = forced(make_url(
            "resources",
            "roleAssignments",
            "https://management.azure.com/subscriptions/sub-1/roleAssignments/forced",
        ));
        let forced_urls = vec![fu.url.clone()];
        let mut urls = vec![fu];
        for i in 0..24 {
            urls.push(make_url(
                "resources",
                "subscriptions",
                &format!("https://management.azure.com/subscriptions/{i}"),
            ));
        }
        let (singles, batches) = drain_all("resources", &mut urls, &forced_urls);
        assert_eq!(singles, forced_urls);
        assert_eq!(
            batches.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![20, 4],
            "20-cap batch, then a 4-batch stopping at the forced URL"
        );
    }

    #[test]
    fn force_single_exchange_router_distinct_roots() {
        // [forced_rootA, normal_rootB, normal_rootA]: root-A batch takes only
        // normal_rootA (root switch defers rootB), root-B batch stops at the
        // forced URL, then the forced URL goes single. No batch contains it.
        let fu = forced(make_url(
            "exchange",
            "mailboxes",
            "https://outlook.office365.com/adminapi/beta/tenant-a/Mailbox/forced",
        ));
        let n_b = make_url(
            "exchange",
            "recipients",
            "https://contoso.office365.com/adminapi/beta/tenant-b/Recipient?PropertySet=All",
        );
        let n_a = make_url(
            "exchange",
            "mailboxes",
            "https://outlook.office365.com/adminapi/beta/tenant-a/Mailbox?PropertySet=All",
        );
        let forced_urls = vec![fu.url.clone()];
        let mut urls = vec![fu, n_b.clone(), n_a.clone()];

        let (singles, batches) = drain_all("exchange", &mut urls, &forced_urls);
        assert_eq!(
            singles, forced_urls,
            "forced URL dispatches single exactly once"
        );
        let mut batched: Vec<String> = batches.iter().flatten().cloned().collect();
        batched.sort();
        let mut expected = vec![n_a.url, n_b.url];
        expected.sort();
        assert_eq!(batched, expected, "each root batches its own normal URL");
        assert_eq!(batches.len(), 2, "two distinct-root envelopes");
    }

    #[test]
    fn force_single_exchange_cap_10_stops_at_forced() {
        let fu = forced(make_url(
            "exchange",
            "mailboxes",
            "https://outlook.office365.com/adminapi/beta/tenant-a/Mailbox/forced",
        ));
        let forced_urls = vec![fu.url.clone()];
        let mut urls = vec![fu];
        for i in 0..12 {
            urls.push(make_url(
                "exchange",
                "recipients",
                &format!("https://outlook.office365.com/adminapi/beta/tenant-a/Recipient/{i}"),
            ));
        }
        let (singles, batches) = drain_all("exchange", &mut urls, &forced_urls);
        assert_eq!(singles, forced_urls);
        assert_eq!(
            batches.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![10, 2],
            "10-cap exchange batch, then a 2-batch stopping at the forced URL"
        );
    }

    #[test]
    fn force_single_retry_exhausted_returns_url_retry_limit() {
        // A forced URL with an exhausted real-error budget is abandoned at
        // dispatch like any other, and the UrlRetryLimit error carries the URL
        // with its flag and tracker (so the loss chokepoint can close it).
        let mut fu = forced(make_url(
            "graph",
            "devices",
            "https://graph.microsoft.com/v1.0/devices",
        ));
        fu.retry_number = 5;
        let mut urls = vec![fu];
        let items = ApiCall::from("graph", &mut urls, limits()).unwrap();
        assert_eq!(items.len(), 1);
        match &items[0] {
            ApiCallItem::ApiCallError(oradaz::utils::errors::Error::UrlRetryLimit(url)) => {
                assert!(url.force_single, "the abandoned URL keeps its flag");
                assert!(
                    url.forced_single_tracker.is_some(),
                    "the abandoned URL keeps its tracker"
                );
            }
            other => panic!(
                "expected UrlRetryLimit, got {:?}",
                std::mem::discriminant(other)
            ),
        }
        assert!(urls.is_empty());
    }
}

// ─── forced single → UrlRetryLimit loss chokepoint ───────────────────────────

mod force_single_loss {
    use super::*;
    use oradaz::collect::dump::conditions::ConditionChecker;
    use oradaz::collect::dump::response::{DumpError, ResponseContext, ResponseErrorThread};
    use oradaz::utils::metadata::TableMetadata;
    use oradaz::utils::stats::Stats;
    use oradaz::utils::url::ForcedSingleTracker;
    use oradaz::utils::writer::actor::spawn_writer_task;

    use std::sync::Mutex;
    use tempfile::TempDir;

    async fn make_context(stats: Arc<Stats>) -> (ResponseContext, TempDir) {
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
        let condition_checker = ConditionChecker {
            client: OradazClient::new(&config).unwrap(),
            tenant_conditions: HashMap::new(),
            user_conditions: DashMap::new(),
            emergency_accounts_custom_attributes: String::from("Emergency.isEmergency"),
            org_url: String::new(),
            stats: Arc::clone(&stats),
            is_application_auth: false,
        };
        let context = ResponseContext {
            writer,
            metadata: Arc::new(Mutex::new(HashMap::<String, TableMetadata>::new())),
            tokens: Arc::new(DashMap::new()),
            condition_checker: Arc::new(condition_checker),
            ratelimit_manager: Arc::new(RateLimitManager::default()),
            concurrency_controller: Arc::new(ConcurrencyController::default()),
            stats,
            logs_date_filter_and: None,
            tenant_domains: Arc::new(dashmap::DashSet::new()),
        };
        (context, temp_dir)
    }

    /// A forced-single URL abandoned as `UrlRetryLimit` (repeated 4xx until the
    /// real-error budget is exhausted, handled by dispatch) yields exactly
    /// `batch_single_fallback_lost = 1`, zero successes, and a single recorded
    /// loss.
    #[tokio::test]
    async fn force_single_url_retry_limit_records_exactly_one_loss() {
        let stats = Arc::new(Stats::new());
        let (context, _tmp) = make_context(Arc::clone(&stats)).await;
        let (update_tx, mut update_rx) = mpsc::channel::<CoordinatorEvent>(8192);

        let tracker = Arc::new(ForcedSingleTracker::new());
        let dump_error = DumpError {
            folder: "graph".to_string(),
            file: "devices".to_string(),
            url: "https://graph.microsoft.com/v1.0/devices".to_string(),
            status: 0,
            code: String::from("UrlRetryLimit"),
            message: String::from("gave up after exhausting the retry budget"),
            expected: false,
            forced_single_tracker: Some(Arc::clone(&tracker)),
            full_response: None,
            post_data: None,
        };
        ResponseErrorThread::new(update_tx, context.clone(), dump_error, 7, 1)
            .process()
            .await;
        let _ = update_rx.try_recv();

        let json: serde_json::Value = serde_json::to_value(&*stats).unwrap();
        let api = json["apis"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["api"] == "devices")
            .expect("the abandoned api is recorded")
            .clone();
        assert_eq!(
            api["batch_single_fallback_lost"], 1,
            "exactly one loss closure"
        );
        assert_eq!(
            api["batch_single_fallback_successes"], 0,
            "no success closure"
        );
        assert_eq!(
            stats.total_lost_data(),
            1,
            "the abandonment is a single recorded loss"
        );
        assert_eq!(stats.error_lines(), 1, "exactly one errors.json entry");
    }
}

mod timeout_escalation {
    use oradaz::collect::dump::request::escalated_timeout_secs;

    #[test]
    fn escalated_timeout_doubles_per_strike_up_to_cap() {
        assert_eq!(escalated_timeout_secs(30, 0, 300), 30);
        assert_eq!(escalated_timeout_secs(30, 1, 300), 60);
        assert_eq!(escalated_timeout_secs(30, 2, 300), 120);
        assert_eq!(escalated_timeout_secs(30, 3, 300), 240);
        assert_eq!(escalated_timeout_secs(30, 4, 300), 300);
        assert_eq!(escalated_timeout_secs(60, 2, 300), 240);
    }

    #[test]
    fn escalated_timeout_never_below_base() {
        // A configured timeout above the cap is kept as-is, never shortened.
        assert_eq!(escalated_timeout_secs(600, 0, 300), 600);
        assert_eq!(escalated_timeout_secs(600, 3, 300), 600);
    }

    #[test]
    fn escalated_timeout_saturates_on_huge_strike_counts() {
        assert_eq!(escalated_timeout_secs(30, usize::MAX, 300), 300);
        assert_eq!(escalated_timeout_secs(u64::MAX, 5, 300), u64::MAX);
    }

    fn hint(v: &str) -> std::collections::HashMap<String, String> {
        std::collections::HashMap::from([("http_timeout_seconds".to_string(), v.to_string())])
    }

    #[test]
    fn api_timeout_hint_raises_never_lowers() {
        use oradaz::collect::dump::request::api_timeout_base_secs;
        let none = std::collections::HashMap::new();
        assert_eq!(api_timeout_base_secs(30, [&none]), 30);
        assert_eq!(api_timeout_base_secs(30, [&hint("120")]), 120);
        assert_eq!(
            api_timeout_base_secs(30, [&hint("10")]),
            30,
            "a hint never shortens"
        );
    }

    #[test]
    fn api_timeout_hint_invalid_values_are_ignored() {
        use oradaz::collect::dump::request::api_timeout_base_secs;
        for bad in ["", "0", "abc", "-5", "1.5"] {
            assert_eq!(api_timeout_base_secs(30, [&hint(bad)]), 30, "{bad:?}");
        }
        assert_eq!(
            api_timeout_base_secs(30, [&hint(" 120 ")]),
            120,
            "surrounding spaces are tolerated"
        );
    }

    #[test]
    fn api_timeout_hint_batch_takes_the_largest() {
        use oradaz::collect::dump::request::api_timeout_base_secs;
        let none = std::collections::HashMap::new();
        assert_eq!(
            api_timeout_base_secs(30, [&none, &hint("120"), &hint("90")]),
            120
        );
        assert_eq!(api_timeout_base_secs(30, std::iter::empty()), 30);
    }
}
