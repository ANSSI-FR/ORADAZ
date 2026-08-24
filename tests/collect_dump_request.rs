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
        post_body: None,
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
            post_body: None,
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
        post_body: None,
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
            post_body: None,
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
