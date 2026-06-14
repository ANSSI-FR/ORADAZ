mod common;

use crate::common::default_test_config;
use oradaz::collect::auth::tokens::{Token, TokenState};
use oradaz::collect::dump::concurrency::ConcurrencyController;
use oradaz::collect::dump::conditions::ConditionChecker;
use oradaz::collect::dump::orchestration::events::CoordinatorEvent;
use oradaz::collect::dump::ratelimit::RateLimitManager;
use oradaz::collect::dump::response::{
    DumpError, Response, ResponseContent, ResponseContext, ResponseErrorThread, ResponseThread,
};
use oradaz::utils::client::OradazClient;
use oradaz::utils::metadata::TableMetadata;
use oradaz::utils::url::ApiCall;
use oradaz::utils::url::BatchData;
use oradaz::utils::url::Url as OradazUrl;
use oradaz::utils::writer::actor::spawn_writer_task;

use dashmap::DashMap;
use oradaz::collect::dump::orchestration::events::ProcessError;
use oradaz::collect::dump::request::RETRY_COUNT;
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
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
        id: 0,
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
async fn process_single_too_many_requests_requeues_url() {
    let api_call = create_test_api_call(create_test_url());
    let response = Response {
        status: 429,
        retry_after: Some(30),
        content: json!({}),
    };

    let (mut rx, thread, _dir) = setup_response_thread(api_call, response).await;
    let returned_urls = thread
        .process_single(
            &Response {
                status: 429,
                retry_after: Some(30),
                content: json!({}),
            },
            &create_test_api_call(create_test_url()),
        )
        .await;

    let messages: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();

    // Expect: no error events, and exactly one requeue URL returned
    let errors: Vec<_> = messages
        .iter()
        .filter(|m| matches!(m, CoordinatorEvent::NewError(..)))
        .collect();

    assert_eq!(errors.len(), 0, "Expected no error message for 429");
    assert_eq!(returned_urls.len(), 1, "Expected one requeue URL returned");
}

/// A 429 does not abandon a URL on a fixed budget. While its
/// bucket keeps making progress (or has only just been seen) it is re-queued;
/// once the bucket has written no data for the liveness ceiling it is abandoned
/// as lost data (`ThrottleStalled`) so the run can terminate — surfaced as a
/// single `NewError`, with NO `RequestCompleted` (the abandonment is
/// counter-neutral; the outer `process()` owns the one completion).
#[tokio::test(start_paused = true)]
async fn throttle_abandoned_when_bucket_stalls_past_liveness_ceiling() {
    let api_call = create_test_api_call(create_test_url());
    let response = Response {
        status: 429,
        retry_after: Some(30),
        content: json!({}),
    };
    let (mut rx, thread, _dir) = setup_response_thread(api_call, response).await;
    thread.context.stats.set_liveness_ceiling_secs(100);

    let throttle = || Response {
        status: 429,
        retry_after: Some(30),
        content: json!({}),
    };

    // First 429: bucket seen for the first time → re-queued, not abandoned.
    let urls1 = thread
        .process_single(&throttle(), &create_test_api_call(create_test_url()))
        .await;
    assert_eq!(urls1.len(), 1, "first 429 must re-queue, not abandon");

    // No data written; advance past the ceiling.
    tokio::time::advance(std::time::Duration::from_secs(101)).await;

    // Second 429 on the still-stalled bucket → abandoned (no re-queue).
    let urls2 = thread
        .process_single(&throttle(), &create_test_api_call(create_test_url()))
        .await;
    assert_eq!(
        urls2.len(),
        0,
        "a bucket stalled past the liveness ceiling must be abandoned, not re-queued"
    );

    // Abandonment surfaced as exactly one NewError, and no RequestCompleted
    // (counter-neutral: write_dump_error emits NewError only).
    let messages: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    let errors = messages
        .iter()
        .filter(|m| matches!(m, CoordinatorEvent::NewError(..)))
        .count();
    let completions = messages
        .iter()
        .filter(|m| matches!(m, CoordinatorEvent::RequestCompleted { .. }))
        .count();
    assert_eq!(errors, 1, "abandonment must emit exactly one NewError");
    assert_eq!(
        completions, 0,
        "abandonment must be counter-neutral (no RequestCompleted)"
    );
    // The status-0 abandonment entry is counted exactly once as a non-HTTP error
    // at the errors.json write chokepoint.
    assert_eq!(
        thread.context.stats.non_http_errors(),
        1,
        "a status-0 errors.json entry must be counted as one non-HTTP error"
    );
}

#[tokio::test]
async fn process_single_successful_with_next_link_sends_new_url() {
    let url = create_test_url();
    let api_call = create_test_api_call(url);

    let content = json!({
        "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users",
        "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skiptoken=abc123",
        "value": [
            {"id": "user-1", "displayName": "Alice"}
        ]
    });

    let response = Response {
        status: 200,
        retry_after: None,
        content: content.clone(),
    };

    let (_rx, thread, _dir) = setup_response_thread(api_call.clone(), response).await;

    let returned_urls = thread
        .process_single(
            &Response {
                status: 200,
                retry_after: None,
                content,
            },
            &api_call,
        )
        .await;

    let next_link_urls: Vec<_> = returned_urls
        .iter()
        .filter(|u| u.url.contains("skiptoken"))
        .collect();

    assert!(
        !next_link_urls.is_empty(),
        "Expected at least one URL from nextLink"
    );

    // Request-shape telemetry: following a nextLink increments pages_followed.
    let json: serde_json::Value = serde_json::to_value(&*thread.context.stats).unwrap();
    let api = json["apis"]
        .as_array()
        .and_then(|a| a.iter().find(|e| e["api"] == "users"))
        .expect("api stats for users");
    assert_eq!(
        api["pages_followed"], 1,
        "following a nextLink must increment pages_followed"
    );
}

/// note_progress discipline: a 2xx that wrote data resets the bucket's liveness
/// timer, so an actively-draining endpoint is never abandoned. (The converse — a
/// 429 never resets it — is covered by
/// `throttle_abandoned_when_bucket_stalls_past_liveness_ceiling`.)
#[tokio::test(start_paused = true)]
async fn successful_2xx_resets_liveness_timer() {
    let api_call = create_test_api_call(create_test_url());
    let response = Response {
        status: 200,
        retry_after: None,
        content: json!({ "value": [{ "id": "u1" }] }),
    };
    let (_rx, thread, _dir) = setup_response_thread(api_call.clone(), response.clone()).await;
    let svc = api_call.url.service_name.clone();
    let api = api_call.url.api.clone();

    thread.context.stats.set_liveness_ceiling_secs(1);
    thread.context.stats.note_progress(&svc, &api);
    tokio::time::advance(std::time::Duration::from_secs(2)).await;
    assert!(
        thread.context.stats.liveness_should_abandon(&svc, &api),
        "bucket must be stalled before the successful write"
    );

    thread.process_single(&response, &api_call).await;

    assert!(
        !thread.context.stats.liveness_should_abandon(&svc, &api),
        "a 2xx that wrote data must reset the liveness timer"
    );
}

/// The counter accounting that makes network abandonment safe: a `LostData`
/// write (`completion_count = 0`) records the error but emits NO
/// `RequestCompleted`, while a dispatch `DumpError` (`completion_count = 1`)
/// emits exactly one `RequestCompleted{count:1}`. The former is what keeps a
/// network sub-URL abandonment in `finalize_retry` from double-decrementing
/// `current_counter` (the batch's own completion already covers it).
#[tokio::test]
async fn lost_data_write_is_counter_neutral_vs_dump_error() {
    // Reuse the response harness to obtain a fully-wired ResponseContext + writer.
    let api_call = create_test_api_call(create_test_url());
    let response = Response {
        status: 200,
        retry_after: None,
        content: json!({}),
    };
    let (_rx, thread, _dir) = setup_response_thread(api_call, response).await;
    let context: ResponseContext = thread.context.clone();

    let mk_err = || DumpError {
        folder: "graph".to_string(),
        file: "users".to_string(),
        url: String::new(),
        status: 0,
        code: "NetworkStalled".to_string(),
        message: String::new(),
        expected: false,
        full_response: None,
        post_data: None,
    };

    // completion_count = 0 (LostData): writes + NewError, but NO RequestCompleted.
    let (tx0, mut rx0) = mpsc::channel::<CoordinatorEvent>(16);
    ResponseErrorThread::new(tx0, context.clone(), mk_err(), 7, 0)
        .process()
        .await;
    let msgs0: Vec<_> = std::iter::from_fn(|| rx0.try_recv().ok()).collect();
    assert_eq!(
        msgs0
            .iter()
            .filter(|m| matches!(m, CoordinatorEvent::NewError(..)))
            .count(),
        1,
        "LostData must still record the error (one NewError)"
    );
    assert_eq!(
        msgs0
            .iter()
            .filter(|m| matches!(m, CoordinatorEvent::RequestCompleted { .. }))
            .count(),
        0,
        "LostData (completion_count=0) must NOT emit RequestCompleted"
    );

    // completion_count = 1 (dispatch DumpError): one RequestCompleted{count:1}.
    let (tx1, mut rx1) = mpsc::channel::<CoordinatorEvent>(16);
    ResponseErrorThread::new(tx1, context.clone(), mk_err(), 8, 1)
        .process()
        .await;
    let msgs1: Vec<_> = std::iter::from_fn(|| rx1.try_recv().ok()).collect();
    assert_eq!(
        msgs1
            .iter()
            .filter(
                |m| matches!(m, CoordinatorEvent::RequestCompleted { count, .. } if *count == 1)
            )
            .count(),
        1,
        "DumpError (completion_count=1) must emit exactly one RequestCompleted{{count:1}}"
    );
}

#[test]
fn dump_error_serializes_correctly() {
    let err = DumpError {
        folder: "graph".to_string(),
        file: "users.json".to_string(),
        url: "https://graph.microsoft.com/v1.0/users".to_string(),
        status: 403,
        code: "Forbidden".to_string(),
        message: "Insufficient privileges".to_string(),
        expected: false,
        full_response: None,
        post_data: None,
    };

    let json = serde_json::to_string(&err).unwrap();
    assert!(json.contains("\"status\":403"));
    assert!(json.contains("\"code\":\"Forbidden\""));
    assert!(
        !json.contains("full_response"),
        "full_response should be omitted when None"
    );
    assert!(
        !json.contains("post_data"),
        "post_data should be omitted when None"
    );
}

#[test]
fn is_lost_data_classifies_terminal_failures() {
    let lost = |code: &str| DumpError {
        folder: "graph".to_string(),
        file: "users".to_string(),
        url: String::new(),
        status: 0,
        code: code.to_string(),
        message: String::new(),
        expected: false,
        full_response: None,
        post_data: None,
    };
    // status==0, non-expected, primary-data losses → counted.
    assert!(lost("UrlRetryLimit").is_lost_data());
    assert!(lost("NoTokenForApiCall").is_lost_data());
    assert!(lost("nextLinkParsingError").is_lost_data());
    assert!(lost("MissingBatchData").is_lost_data());
    assert!(lost("UnknownApiCallCreationError").is_lost_data());

    // Relationship-expansion skip: the endpoint's own data was already written,
    // so this must NOT flip the run to PARTIAL.
    assert!(!lost("MissingTokenForRelationships").is_lost_data());

    // HTTP error responses (status >= 400) are handled by unexpected_errors, not here.
    let mut http = lost("Forbidden");
    http.status = 403;
    assert!(!http.is_lost_data());

    // Expected errors never count as lost data.
    let mut expected = lost("UrlRetryLimit");
    expected.expected = true;
    assert!(!expected.is_lost_data());
}

#[test]
fn dump_error_with_full_response_serializes_it() {
    let err = DumpError {
        folder: "graph".to_string(),
        file: "groups.json".to_string(),
        url: "https://graph.microsoft.com/v1.0/groups".to_string(),
        status: 500,
        code: "InternalServerError".to_string(),
        message: "Server error".to_string(),
        expected: false,
        full_response: Some(json!({"detail": "stack trace"})),
        post_data: Some(json!({"detail": "sent data in post request"})),
    };

    let json = serde_json::to_string(&err).unwrap();
    assert!(json.contains("\"full_response\""));
    assert!(json.contains("stack trace"));
    assert!(json.contains("\"post_data\""));
    assert!(json.contains("sent data in post request"));
}

#[tokio::test]
async fn process_batch_partial_failure_requeues_only_failed_urls() {
    let url1 = create_test_url();
    let url2 = create_test_url();
    let mut url2_clone = url2.clone();
    url2_clone.api = "other".to_string();

    let api_call1 = create_test_api_call(url1.clone());
    let api_call2 = create_test_api_call(url2_clone.clone());

    let mut initial_data = HashMap::new();
    initial_data.insert("1".to_string(), api_call1.clone());
    initial_data.insert("2".to_string(), api_call2.clone());

    let batch_data = oradaz::utils::url::BatchData {
        post_data: HashMap::new(),
        id_field: "id".to_string(),
        status_field: "status".to_string(),
        retry_after_field: "retryAfter".to_string(),
        body_field: "body".to_string(),
        initial_data,
    };

    let mut batch_api_call = create_test_api_call(url1.clone());
    batch_api_call.is_batch = true;
    batch_api_call.batch_data = Some(batch_data);

    let content = json!({
        "value": [
            { "id": "1", "status": 200, "body": { "data": "ok" } },
            { "id": "2", "status": 429, "body": null, "retryAfter": "30" }
        ]
    });

    let response = Response {
        status: 200,
        retry_after: None,
        content,
    };

    let (mut rx, thread, _dir) = setup_response_thread(batch_api_call.clone(), response).await;

    let returned_urls = thread.process_batch().await;

    // Expect: only url2 should be re-queued
    assert_eq!(returned_urls.len(), 1);
    assert_eq!(returned_urls[0].url, url2_clone.url);

    // Also check that no error events were sent to coordinator for the 429 (as it's a retry)
    let messages: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    let errors: Vec<_> = messages
        .iter()
        .filter(|m| matches!(m, CoordinatorEvent::NewError(..)))
        .collect();
    assert_eq!(errors.len(), 0);
}

/// A batch sub-response missing the `status` field is removed from `initial_data`
/// before the end-of-batch sweep, so the sweep cannot re-queue it. The
/// missing-status handler must therefore re-queue it explicitly, mirroring
/// the invalid-status branch.
#[tokio::test]
async fn batch_item_missing_status_is_requeued() {
    let url1 = create_test_url();
    let api_call1 = create_test_api_call(url1.clone());

    let mut initial_data = HashMap::new();
    initial_data.insert("1".to_string(), api_call1.clone());

    let batch_data = oradaz::utils::url::BatchData {
        post_data: HashMap::new(),
        id_field: "id".to_string(),
        status_field: "status".to_string(),
        retry_after_field: "retryAfter".to_string(),
        body_field: "body".to_string(),
        initial_data,
    };

    let mut batch_api_call = create_test_api_call(url1.clone());
    batch_api_call.is_batch = true;
    batch_api_call.batch_data = Some(batch_data);

    // The sub-response for id "1" carries a body but NO `status` field.
    let content = json!({
        "value": [
            { "id": "1", "body": { "data": "ok" } }
        ]
    });
    let response = Response {
        status: 200,
        retry_after: None,
        content,
    };

    let (_rx, thread, _dir) = setup_response_thread(batch_api_call.clone(), response).await;
    let returned_urls = thread.process_batch().await;

    assert_eq!(
        returned_urls.len(),
        1,
        "a batch item missing its status must be re-queued, not silently dropped"
    );
    assert_eq!(returned_urls[0].url, url1.url);
}

#[tokio::test]
async fn exchange_batch_sub_success_with_next_link_requeues_next_page() {
    // Exchange-shaped sub-URL (service exchange, no relationships so no token
    // lookup is needed when processing the sub-response).
    let mut sub_url = create_test_url();
    sub_url.service_name = "exchange".to_string();
    sub_url.api = "mailboxes".to_string();
    sub_url.url = "https://outlook.office365.com/adminapi/beta/test-tenant/Mailbox?PropertySet=All"
        .to_string();
    let sub_api_call = create_test_api_call(sub_url.clone());

    let mut initial_data = HashMap::new();
    initial_data.insert("1".to_string(), sub_api_call);

    // Exchange BatchData: Graph/OData field names, real `headers/Retry-After` pointer.
    let batch_data = BatchData {
        post_data: HashMap::new(),
        id_field: "id".to_string(),
        status_field: "status".to_string(),
        retry_after_field: "headers/Retry-After".to_string(),
        body_field: "body".to_string(),
        initial_data,
    };

    let mut envelope_url = sub_url.clone();
    envelope_url.api = "batch".to_string();
    envelope_url.url = "https://outlook.office365.com/adminapi/beta/test-tenant/$batch".to_string();
    let mut batch_api_call = create_test_api_call(envelope_url);
    batch_api_call.is_batch = true;
    batch_api_call.value_pointer = "/responses".to_string();
    batch_api_call.batch_data = Some(batch_data);

    let next_link = "https://outlook.office365.com/adminapi/beta/test-tenant/Mailbox?PropertySet=All&$skiptoken=10";
    let content = json!({
        "responses": [
            {
                "id": "1",
                "status": 200,
                "body": {
                    "@odata.nextLink": next_link,
                    "value": [ { "Identity": "m1" } ]
                }
            }
        ]
    });
    let response = Response {
        status: 200,
        retry_after: None,
        content,
    };

    let (_rx, thread, _dir) = setup_response_thread(batch_api_call.clone(), response).await;
    let returned_urls = thread.process_batch().await;

    assert_eq!(
        returned_urls.len(),
        1,
        "the sub-response's nextLink must be re-queued"
    );
    assert_eq!(returned_urls[0].url, next_link);
    assert_eq!(returned_urls[0].service_name, "exchange");
    assert_eq!(returned_urls[0].api, "mailboxes");
}

#[tokio::test]
async fn exchange_batch_sub_429_retry_after_header_string_honoured() {
    let mut sub_url = create_test_url();
    sub_url.service_name = "exchange".to_string();
    sub_url.api = "mailboxPermissions".to_string();
    sub_url.url =
        "https://outlook.office365.com/adminapi/beta/test-tenant/Mailbox('QQ==')/MailboxPermission"
            .to_string();
    let sub_api_call = create_test_api_call(sub_url.clone());

    let mut initial_data = HashMap::new();
    initial_data.insert("1".to_string(), sub_api_call);

    let batch_data = BatchData {
        post_data: HashMap::new(),
        id_field: "id".to_string(),
        status_field: "status".to_string(),
        retry_after_field: "headers/Retry-After".to_string(),
        body_field: "body".to_string(),
        initial_data,
    };

    let mut envelope_url = sub_url.clone();
    envelope_url.api = "batch".to_string();
    envelope_url.url = "https://outlook.office365.com/adminapi/beta/test-tenant/$batch".to_string();
    let mut batch_api_call = create_test_api_call(envelope_url);
    batch_api_call.is_batch = true;
    batch_api_call.value_pointer = "/responses".to_string();
    batch_api_call.batch_data = Some(batch_data);

    // Sub-429 carrying Retry-After as a string header inside the sub-response
    // JSON (the OData JSON batch form) and no body.
    let content = json!({
        "responses": [
            { "id": "1", "status": 429, "headers": { "Retry-After": "30" } }
        ]
    });
    let response = Response {
        status: 200,
        retry_after: None,
        content,
    };

    let (_rx, thread, _dir) = setup_response_thread(batch_api_call.clone(), response).await;
    let returned_urls = thread.process_batch().await;

    assert_eq!(
        returned_urls.len(),
        1,
        "throttled sub-URL must be re-queued"
    );
    let retried = &returned_urls[0];
    assert_eq!(retried.url, sub_url.url);
    assert_eq!(
        retried.retry_number, 0,
        "a sub-429 must not consume the real-error budget"
    );
    assert_eq!(
        retried.rate_limit_retry_number, 1,
        "rate_limit_retry_number must increase on a sub-429"
    );
    assert_eq!(
        retried.rate_limit_total_wait_secs, 30,
        "the string headers/Retry-After value must be parsed and accumulated"
    );
}

/// Live Exchange serialises sub-response header keys in lowercase
/// (`retry-after`), while the production `BatchData` keeps the Graph-cased
/// pointer (`headers/Retry-After`). The lowercased-last-segment fallback in
/// `process_batch` must still pick the hint up.
#[tokio::test]
async fn exchange_batch_sub_429_lowercase_retry_after_header_honoured() {
    let mut sub_url = create_test_url();
    sub_url.service_name = "exchange".to_string();
    sub_url.api = "mailboxPermissions".to_string();
    sub_url.url =
        "https://outlook.office365.com/adminapi/beta/test-tenant/Mailbox('QQ==')/MailboxPermission"
            .to_string();
    let sub_api_call = create_test_api_call(sub_url.clone());

    let mut initial_data = HashMap::new();
    initial_data.insert("1".to_string(), sub_api_call);

    // Production exchange config: capitalised pointer, lowercase wire key.
    let batch_data = BatchData {
        post_data: HashMap::new(),
        id_field: "id".to_string(),
        status_field: "status".to_string(),
        retry_after_field: "headers/Retry-After".to_string(),
        body_field: "body".to_string(),
        initial_data,
    };

    let mut envelope_url = sub_url.clone();
    envelope_url.api = "batch".to_string();
    envelope_url.url = "https://outlook.office365.com/adminapi/beta/test-tenant/$batch".to_string();
    let mut batch_api_call = create_test_api_call(envelope_url);
    batch_api_call.is_batch = true;
    batch_api_call.value_pointer = "/responses".to_string();
    batch_api_call.batch_data = Some(batch_data);

    let content = json!({
        "responses": [
            { "id": "1", "status": 429, "headers": { "retry-after": "30" } }
        ]
    });
    let response = Response {
        status: 200,
        retry_after: None,
        content,
    };

    let (_rx, thread, _dir) = setup_response_thread(batch_api_call.clone(), response).await;
    let returned_urls = thread.process_batch().await;

    assert_eq!(
        returned_urls.len(),
        1,
        "throttled sub-URL must be re-queued"
    );
    let retried = &returned_urls[0];
    assert_eq!(
        retried.rate_limit_retry_number, 1,
        "rate_limit_retry_number must increase on a sub-429"
    );
    assert_eq!(
        retried.rate_limit_total_wait_secs, 30,
        "the lowercase retry-after header must be picked up by the fallback pointer"
    );
}

#[tokio::test]
async fn write_dump_error_persists_to_file() {
    let api_call = create_test_api_call(create_test_url());
    let response = Response {
        status: 403,
        retry_after: None,
        content: json!({"error": "forbidden"}),
    };

    let (_rx, thread, temp_dir) = setup_response_thread(api_call, response).await;

    let err = DumpError {
        folder: "graph".to_string(),
        file: "users.json".to_string(),
        url: "https://graph.microsoft.com/v1.0/users".to_string(),
        status: 403,
        code: "Forbidden".to_string(),
        message: "Insufficient privileges".to_string(),
        expected: false,
        full_response: None,
        post_data: None,
    };

    thread.write_dump_error(err).await;

    // Give the writer actor a moment to flush to disk
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let errors_file_path = temp_dir.path().join("test-run").join("errors.json");
    assert!(errors_file_path.exists(), "errors.json should be created");

    let content = std::fs::read_to_string(errors_file_path).unwrap();
    let mut errors = Vec::new();
    for line in content.lines() {
        if !line.trim().is_empty() {
            let err: oradaz::collect::dump::response::DumpError =
                serde_json::from_str(line).unwrap();
            errors.push(err);
        }
    }

    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].code, "Forbidden");
    assert_eq!(errors[0].status, 403);
}

/// A leaf endpoint (no relationships) writes its page verbatim — one JSON object
/// per line — and generates no child URLs. Pins the borrowed-records write path:
/// the records are written straight from the response without being cloned into
/// an owned vec that relationship expansion would consume.
#[tokio::test]
async fn leaf_endpoint_writes_records_verbatim_without_child_urls() {
    let api_call = create_test_api_call(create_test_url()); // relationships empty
    let response = Response {
        status: 200,
        retry_after: None,
        content: json!({"value": [{"id": "a"}, {"id": "b"}]}),
    };

    let (_rx, thread, temp_dir) = setup_response_thread(api_call.clone(), response.clone()).await;
    let new_urls = thread.process_single(&response, &api_call).await;
    assert!(
        new_urls.is_empty(),
        "a leaf endpoint generates no child URLs"
    );

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let path = temp_dir
        .path()
        .join("test-run")
        .join("graph")
        .join("users.json");
    let content = std::fs::read_to_string(path).unwrap();
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 2, "both records written, one per line");
    let v0: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    let v1: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(v0["id"], "a");
    assert_eq!(v1["id"], "b");
}

/// A 2xx response whose value array is empty is counted as an `empty_responses`
/// for that `(service, api)`: the endpoint was queried but the server held no
/// objects, which is distinct from an error.
#[tokio::test]
async fn empty_value_array_counts_as_empty_response() {
    let api_call = create_test_api_call(create_test_url());
    let response = Response {
        status: 200,
        retry_after: None,
        content: json!({"value": []}),
    };

    let (_rx, thread, _dir) = setup_response_thread(api_call.clone(), response.clone()).await;
    thread.process_single(&response, &api_call).await;

    let stats_json = serde_json::to_value(&*thread.context.stats).unwrap();
    let apis = stats_json["apis"].as_array().expect("apis array");
    let users = apis
        .iter()
        .find(|a| a["service"] == "graph" && a["api"] == "users")
        .expect("graph/users stats entry");
    assert_eq!(users["empty_responses"], 1);
}

fn create_expand_url() -> OradazUrl {
    let mut u = create_test_url();
    u.api = "users_registeredDevices".to_string();
    u.url = "https://graph.microsoft.com/v1.0/users?$top=999&$select=id&$expand=registeredDevices"
        .to_string();
    let behavior = Arc::make_mut(&mut u.api_behavior);
    behavior.insert(
        "expand_extract".to_string(),
        "registeredDevices".to_string(),
    );
    behavior.insert("expand_project".to_string(), "id,displayName".to_string());
    behavior.insert("expand_parent_key".to_string(), "id".to_string());
    behavior.insert("expand_max".to_string(), "2".to_string());
    u
}

/// An `$expand` extraction seed flattens each parent's expanded collection to its
/// own file: one projected child per line, tagged with its parent id, and the
/// parent object itself is not written.
#[tokio::test]
async fn expand_extract_flattens_children_with_parent_tag() {
    let api_call = create_test_api_call(create_expand_url());
    let response = Response {
        status: 200,
        retry_after: None,
        content: json!({"value": [
            { "id": "user-1", "registeredDevices": [ {"id": "dev-a", "displayName": "A", "extra": "x"} ] },
            { "id": "user-2", "registeredDevices": [] }
        ]}),
    };

    let (_rx, thread, temp_dir) = setup_response_thread(api_call.clone(), response.clone()).await;
    let new_urls = thread.process_single(&response, &api_call).await;
    assert!(new_urls.is_empty(), "no parent at the cap → no fallback");

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let path = temp_dir
        .path()
        .join("test-run")
        .join("graph")
        .join("users_registeredDevices.json");
    let content = std::fs::read_to_string(path).unwrap();
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 1, "only user-1's single device");
    let v: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(v["id"], "dev-a");
    assert_eq!(v["displayName"], "A");
    assert!(v.get("extra").is_none(), "projected to id,displayName only");
    assert_eq!(v["_ORADAZ_PARENT_"]["id"], "user-1");
}

/// A parent whose expanded collection reaches the cap (`expand_max`) may be
/// truncated, so instead of writing its partial rows the seed emits a per-object
/// fallback URL (re-fetching the full collection) and counts an `expand_cap_hit`.
#[tokio::test]
async fn expand_extract_at_cap_defers_to_per_object_fallback() {
    let api_call = create_test_api_call(create_expand_url()); // expand_max = 2
    let response = Response {
        status: 200,
        retry_after: None,
        content: json!({"value": [
            { "id": "user-9", "registeredDevices": [ {"id": "d1"}, {"id": "d2"} ] }
        ]}),
    };

    let (_rx, thread, temp_dir) = setup_response_thread(api_call.clone(), response.clone()).await;
    let new_urls = thread.process_single(&response, &api_call).await;

    assert_eq!(new_urls.len(), 1, "one per-object fallback URL");
    let fb = &new_urls[0];
    assert!(
        fb.url.contains("/users/user-9/registeredDevices"),
        "{}",
        fb.url
    );
    assert!(fb.url.contains("$select=id,displayName"), "{}", fb.url);
    assert_eq!(fb.api, "users_registeredDevices");
    assert_eq!(
        fb.parent.as_ref().and_then(|p| p.get("id")),
        Some(&"user-9".to_string())
    );

    // No truncated rows written for the capped parent.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let path = temp_dir
        .path()
        .join("test-run")
        .join("graph")
        .join("users_registeredDevices.json");
    assert!(
        !path.exists() || std::fs::read_to_string(&path).unwrap().trim().is_empty(),
        "capped parent's partial rows must not be written"
    );

    let stats_json = serde_json::to_value(&*thread.context.stats).unwrap();
    let apis = stats_json["apis"].as_array().expect("apis array");
    let seed = apis
        .iter()
        .find(|a| a["api"] == "users_registeredDevices")
        .expect("seed stats entry");
    assert_eq!(seed["expand_cap_hits"], 1);
}

/// A projected `$expand` extraction keeps the `@odata.type` discriminator of a
/// polymorphic child (e.g. an owner that may be a user or service principal)
/// even though it is not in the projection list — the per-object call returned
/// it too, so dropping it would lose the element's concrete type.
#[tokio::test]
async fn expand_extract_preserves_odata_type_under_projection() {
    let api_call = create_test_api_call(create_expand_url()); // projects id,displayName
    let response = Response {
        status: 200,
        retry_after: None,
        content: json!({"value": [
            { "id": "u1", "registeredDevices": [
                {"@odata.type": "#microsoft.graph.user", "id": "o1", "displayName": "A", "mail": "drop-me"}
            ] }
        ]}),
    };

    let (_rx, thread, temp_dir) = setup_response_thread(api_call.clone(), response.clone()).await;
    thread.process_single(&response, &api_call).await;

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let path = temp_dir
        .path()
        .join("test-run")
        .join("graph")
        .join("users_registeredDevices.json");
    let content = std::fs::read_to_string(path).unwrap();
    let line = content.lines().find(|l| !l.trim().is_empty()).unwrap();
    let v: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(v["id"], "o1");
    assert_eq!(v["displayName"], "A");
    assert_eq!(v["@odata.type"], "#microsoft.graph.user");
    assert!(v.get("mail").is_none(), "non-projected field is dropped");
    assert_eq!(v["_ORADAZ_PARENT_"]["id"], "u1");
}

/// A 404 outside expected_error_codes is not a permission signal: it must be
/// retried on the standard budget (retry_number incremented, URL returned for
/// re-dispatch) without emitting a PotentialPrerequisiteError, which would
/// pause the whole service for a prerequisite re-check.
#[tokio::test]
async fn unexpected_404_retries_without_prereq_failure() {
    let mut url = create_test_url();
    url.expected_error_codes = None; // no expected errors → 404 is unexpected
    url.retry_number = 0;
    let api_call = create_test_api_call(url);

    let response = Response {
        status: 404,
        retry_after: None,
        content: json!({"error": {"code": "ResourceNotFound", "message": "Not found"}}),
    };

    let (mut rx, thread, _dir) = setup_response_thread(api_call.clone(), response.clone()).await;
    let new_urls = thread.process_single(&response, &api_call).await;

    assert_eq!(
        new_urls.len(),
        1,
        "an unexpected 404 must be re-queued for a standard retry"
    );
    assert_eq!(
        new_urls[0].retry_number, 1,
        "the standard retry increments retry_number"
    );

    let events: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    let prereq = events
        .iter()
        .filter(|e| {
            matches!(
                e,
                CoordinatorEvent::NewError(_, ProcessError::PotentialPrerequisiteError(_))
            )
        })
        .count();
    assert_eq!(prereq, 0, "a 404 must not trigger a prerequisite re-check");
}

/// Same for 409 Conflict (e.g. a transiently locked exchange mailbox): standard
/// retry, no prerequisite re-check, no service pause.
#[tokio::test]
async fn unexpected_409_retries_without_prereq_failure() {
    let mut url = create_test_url();
    url.expected_error_codes = None;
    url.retry_number = 0;
    let api_call = create_test_api_call(url);

    let response = Response {
        status: 409,
        retry_after: None,
        content: json!({"error": {"code": "Conflict", "message": "Mailbox is locked"}}),
    };

    let (mut rx, thread, _dir) = setup_response_thread(api_call.clone(), response.clone()).await;
    let new_urls = thread.process_single(&response, &api_call).await;

    assert_eq!(
        new_urls.len(),
        1,
        "409 must be re-queued for a standard retry"
    );
    assert_eq!(new_urls[0].retry_number, 1);

    let events: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    let prereq = events
        .iter()
        .filter(|e| {
            matches!(
                e,
                CoordinatorEvent::NewError(_, ProcessError::PotentialPrerequisiteError(_))
            )
        })
        .count();
    assert_eq!(prereq, 0, "a 409 must not trigger a prerequisite re-check");
}

/// An undeclared 2xx (here 204, while the API declares success as 200) is a
/// status mismatch, NOT a prerequisite failure: it must be retried on the
/// standard budget (returned for re-dispatch) without emitting a
/// PotentialPrerequisiteError that would pause the whole service.
#[tokio::test]
async fn undeclared_2xx_retries_without_prereq_failure() {
    let mut url = create_test_url();
    url.expected_error_codes = None;
    url.retry_number = 0;
    let api_call = create_test_api_call(url); // success_code = 200

    let response = Response {
        status: 204,
        retry_after: None,
        content: json!({}),
    };

    let (mut rx, thread, _dir) = setup_response_thread(api_call.clone(), response.clone()).await;
    let new_urls = thread.process_single(&response, &api_call).await;

    assert_eq!(
        new_urls.len(),
        1,
        "an undeclared 2xx must be re-queued for a standard retry"
    );
    assert_eq!(
        new_urls[0].retry_number, 1,
        "the standard retry increments retry_number"
    );

    let events: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    let prereq = events
        .iter()
        .filter(|e| {
            matches!(
                e,
                CoordinatorEvent::NewError(_, ProcessError::PotentialPrerequisiteError(_))
            )
        })
        .count();
    assert_eq!(
        prereq, 0,
        "an undeclared 2xx must not trigger a prerequisite re-check"
    );
}

/// A 400 response whose error code is listed in the URL's `expected_error_codes`
/// must be written to errors.json with `expected: true`. Without that flag,
/// `inspect logs` cannot distinguish schema-declared expected errors from
/// real anomalies.
#[tokio::test]
async fn expected_error_codes_set_expected_true_in_dump_error() {
    use oradaz::utils::url::ExpectedErrorCode;

    let mut url = create_test_url();
    url.expected_error_codes = Some(Arc::new(vec![ExpectedErrorCode {
        status: 400,
        code: Some(String::from("ResourceTypeNotSupported")),
        breaker_eligible: false,
    }]));
    let api_call = create_test_api_call(url);

    let response = Response {
        status: 400,
        retry_after: None,
        content: json!({
            "error": {
                "code": "ResourceTypeNotSupported",
                "message": "Resource type not supported for onboarding",
            }
        }),
    };

    let (_rx, thread, temp_dir) = setup_response_thread(api_call.clone(), response.clone()).await;
    thread.process_single(&response, &api_call).await;

    // The DumpError must be written and carry `expected: true`.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let errors_path = temp_dir.path().join("test-run").join("errors.json");
    let errors_blob = std::fs::read_to_string(&errors_path).unwrap_or_default();
    assert!(
        errors_blob.contains("\"expected\":true"),
        "expected-coded 400 must be marked expected:true in errors.json, got: {errors_blob}"
    );
}

/// An Azure ARM-style `nextLink: null` (Value::Null in serde_json) must be treated
/// as "no more pages", not as a nextLinkParsingError.
#[tokio::test]
async fn null_next_link_is_treated_as_no_more_pages() {
    let url = create_test_url();
    let api_call = create_test_api_call(url);

    let response = Response {
        status: 200,
        retry_after: None,
        content: json!({
            "@odata.nextLink": serde_json::Value::Null,
            "value": [{"id": "x"}]
        }),
    };

    let (_rx, thread, temp_dir) = setup_response_thread(api_call.clone(), response.clone()).await;
    let returned_urls = thread.process_single(&response, &api_call).await;

    // No nextLink URL must be produced for a null link.
    let next_link_urls: Vec<_> = returned_urls
        .iter()
        .filter(|u| u.url.contains("nextLink") || u.url.contains("skiptoken"))
        .collect();
    assert!(
        next_link_urls.is_empty(),
        "null nextLink must not produce a follow-up URL"
    );

    // No DumpError must be written to errors.json on this path.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let errors_path = temp_dir.path().join("test-run").join("errors.json");
    let errors_blob = std::fs::read_to_string(&errors_path).unwrap_or_default();
    assert!(
        !errors_blob.contains("nextLinkParsingError"),
        "null nextLink must not write a nextLinkParsingError entry, got: {errors_blob}"
    );
}

/// A `value_pointer` resolving to a present-but-non-array value (a single
/// object) must be written as one record, not silently dropped.
#[tokio::test]
async fn non_array_value_pointer_writes_one_record() {
    let url = create_test_url();
    let api_call = create_test_api_call(url.clone());

    let response = Response {
        status: 200,
        retry_after: None,
        content: json!({"value": {"id": "single-obj", "displayName": "one"}}),
    };

    let (_rx, thread, temp_dir) = setup_response_thread(api_call.clone(), response.clone()).await;
    let _ = thread.process_single(&response, &api_call).await;

    // The writer is an async actor; give it a moment to flush, then check that the
    // data file (`<service>/<api>.json`) contains the wrapped single object.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let data_path = temp_dir
        .path()
        .join("test-run")
        .join(&url.service_name)
        .join(format!("{}.json", url.api));
    let blob = std::fs::read_to_string(&data_path).unwrap_or_default();
    assert!(
        blob.contains("single-obj"),
        "a non-array value must be written as one record, got: {blob:?}"
    );
}

/// A 5xx response must be re-queued via prepare_retries (no PotentialPrerequisiteError),
/// and no per-attempt DumpError must be written to errors.json.
/// `start_paused = true` makes tokio::time::sleep return immediately so the backoff
/// duration does not affect test runtime and is independent of global BACKOFF_BASE_MS.
#[tokio::test(start_paused = true)]
async fn server_error_5xx_retries_without_prereq_event() {
    let mut url = create_test_url();
    url.retry_number = 0;
    let api_call = create_test_api_call(url);

    let response = Response {
        status: 502,
        retry_after: None,
        content: json!({"error": {"code": "BadGateway", "message": "Bad gateway"}}),
    };

    let (mut rx, thread, temp_dir) =
        setup_response_thread(api_call.clone(), response.clone()).await;
    let returned_urls = thread.process_single(&response, &api_call).await;

    // Must return the URL for retry (via prepare_retries)
    assert_eq!(returned_urls.len(), 1, "Expected 1 URL returned for retry");
    assert_eq!(
        returned_urls[0].retry_number, 1,
        "retry_number should be incremented to 1"
    );

    // Must NOT emit a NewError/PotentialPrerequisiteError
    let events: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    let has_prereq_error = events.iter().any(|e| {
        matches!(
            e,
            CoordinatorEvent::NewError(_, ProcessError::PotentialPrerequisiteError(_))
        )
    });
    assert!(
        !has_prereq_error,
        "5xx must not trigger PotentialPrerequisiteError"
    );

    // Must NOT write an entry to errors.json (only UrlRetryLimit final entry would be written)
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let errors_path = temp_dir.path().join("test-run").join("errors.json");
    let errors_exist = errors_path.exists()
        && !std::fs::read_to_string(&errors_path)
            .unwrap_or_default()
            .trim()
            .is_empty();
    assert!(!errors_exist, "5xx must not write per-attempt DumpError");
}

/// A 401 response must emit TokenExpirationError, return the URL for re-dispatch,
/// and increment retry_number so the UrlRetryLimit circuit-breaker can fire if the
/// token remains invalid after repeated refreshes.
#[tokio::test]
async fn unauthorized_401_triggers_token_refresh_and_increments_retry() {
    let mut url = create_test_url();
    url.retry_number = 0;
    let api_call = create_test_api_call(url);

    let response = Response {
        status: 401,
        retry_after: None,
        content: json!({"error": {"code": "InvalidAuthenticationToken", "message": "Access token expired"}}),
    };

    let retry_count_before = RETRY_COUNT.load(Ordering::Relaxed);
    let (mut rx, thread, _dir) = setup_response_thread(api_call.clone(), response.clone()).await;
    let returned_urls = thread.process_single(&response, &api_call).await;

    // URL must be returned for re-dispatch (token will be refreshed by coordinator)
    assert_eq!(
        returned_urls.len(),
        1,
        "Expected 1 URL returned for re-dispatch"
    );
    assert_eq!(
        returned_urls[0].retry_number, 1,
        "retry_number must be incremented for 401 to cap retries"
    );

    // RETRY_COUNT must be incremented (so progress UI reflects 401 retries).
    // Use > instead of == because other tests running concurrently may also
    // increment this global counter between the two reads.
    let retry_count_after = RETRY_COUNT.load(Ordering::Relaxed);
    assert!(
        retry_count_after > retry_count_before,
        "RETRY_COUNT must increase for 401 retry (before={retry_count_before}, after={retry_count_after})"
    );

    // RETRY_COUNT must be incremented (so progress UI reflects 401 retries).
    // Per-API retries_real must also be incremented (so inspect stats reflect them).
    let retry_count_after_thread_stats = thread
        .context
        .stats
        .apis
        .get("graph/users")
        .map(|e| e.value().retries_real.load(Ordering::Relaxed))
        .unwrap_or(0);
    assert_eq!(
        retry_count_after_thread_stats, 1,
        "per-API retries_real must increase by 1 on a 401"
    );

    // Must emit TokenExpirationError
    let events: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    let has_token_error = events.iter().any(|e| {
        matches!(
            e,
            CoordinatorEvent::NewError(_, ProcessError::TokenExpirationError)
        )
    });
    assert!(has_token_error, "401 must emit TokenExpirationError");
}

/// An unexpected 403 (the "prereq" path) must increment the global RETRY_COUNT
/// and the per-API retries_real counter, in addition to emitting a
/// PotentialPrerequisiteError event.
#[tokio::test]
async fn unexpected_403_increments_retry_counters() {
    let mut url = create_test_url();
    url.expected_error_codes = None; // 403 is unexpected
    url.retry_number = 0;
    let api_call = create_test_api_call(url);

    let response = Response {
        status: 403,
        retry_after: None,
        content: json!({"error": {"code": "Authorization_RequestDenied", "message": "Forbidden"}}),
    };

    let retry_count_before = RETRY_COUNT.load(Ordering::Relaxed);
    let (mut rx, thread, _dir) = setup_response_thread(api_call.clone(), response.clone()).await;
    thread.process_single(&response, &api_call).await;

    // Global RETRY_COUNT must have increased (used by the progress UI).
    let retry_count_after = RETRY_COUNT.load(Ordering::Relaxed);
    assert!(
        retry_count_after > retry_count_before,
        "RETRY_COUNT must increase on a 4xx prereq retry (before={retry_count_before}, after={retry_count_after})"
    );

    // Per-API retries_real must have increased (used by inspect stats and stats.json).
    let api_retries_real = thread
        .context
        .stats
        .apis
        .get("graph/users")
        .map(|e| e.value().retries_real.load(Ordering::Relaxed))
        .unwrap_or(0);
    assert_eq!(
        api_retries_real, 1,
        "per-API retries_real must increase by 1 on a 4xx prereq retry"
    );

    // The PotentialPrerequisiteError must still be emitted.
    let events: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    let has_prereq_error = events.iter().any(|e| {
        matches!(
            e,
            CoordinatorEvent::NewError(_, ProcessError::PotentialPrerequisiteError(_))
        )
    });
    assert!(
        has_prereq_error,
        "unexpected 403 must still emit PotentialPrerequisiteError"
    );
}

/// A 429 response must behave exactly as before: re-queue URL, no NewError.
#[tokio::test]
async fn too_many_requests_429_unchanged() {
    let url = create_test_url();
    let api_call = create_test_api_call(url);

    let response = Response {
        status: 429,
        retry_after: Some(5),
        content: json!({}),
    };

    let (mut rx, thread, _dir) = setup_response_thread(api_call.clone(), response.clone()).await;
    let returned_urls = thread.process_single(&response, &api_call).await;

    // URL must be returned for retry
    assert_eq!(
        returned_urls.len(),
        1,
        "Expected 1 URL returned for 429 retry"
    );

    // Must not emit any NewError
    let events: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    let error_events: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, CoordinatorEvent::NewError(..)))
        .collect();
    assert!(error_events.is_empty(), "429 must not emit NewError events");
}

/// A 429 response must bump `rate_limit_retry_number` (the separate 429 budget),
/// accumulate `Retry-After` into `rate_limit_total_wait_secs`, and leave the
/// "real-error" `retry_number` budget untouched.
#[tokio::test]
async fn too_many_requests_429_uses_rate_limit_counter() {
    let url = create_test_url();
    let api_call = create_test_api_call(url);

    let response = Response {
        status: 429,
        retry_after: Some(7),
        content: json!({}),
    };

    let (_rx, thread, _dir) = setup_response_thread(api_call.clone(), response.clone()).await;
    let returned_urls = thread.process_single(&response, &api_call).await;

    assert_eq!(returned_urls.len(), 1, "Expected 1 URL returned for 429");
    let retried = &returned_urls[0];
    assert_eq!(
        retried.retry_number, 0,
        "retry_number must NOT increase for a 429 — that budget is reserved for real errors"
    );
    assert_eq!(
        retried.rate_limit_retry_number, 1,
        "rate_limit_retry_number must increase on 429"
    );
    assert_eq!(
        retried.rate_limit_total_wait_secs, 7,
        "rate_limit_total_wait_secs must accumulate the Retry-After value"
    );

    // Provenance wiring (driven through report_too_many_requests, not a direct
    // record_* call): a server-provided Retry-After counts as "server" and sets max.
    let (server_count, default_count, max_secs) = thread
        .context
        .stats
        .services
        .get("graph")
        .map(|s| {
            (
                s.retry_after_server_count.load(Ordering::Relaxed),
                s.retry_after_default_count.load(Ordering::Relaxed),
                s.retry_after_max_secs.load(Ordering::Relaxed),
            )
        })
        .unwrap_or((0, 0, 0));
    assert_eq!(
        server_count, 1,
        "a 429 carrying a Retry-After must increment retry_after_server_count"
    );
    assert_eq!(default_count, 0, "no default cooldown was applied");
    assert_eq!(
        max_secs, 7,
        "retry_after_max_secs must track the server value"
    );
}

/// Successive 429s on the same URL accumulate independently from `retry_number`.
#[tokio::test]
async fn too_many_requests_429_accumulates_across_attempts() {
    let mut url = create_test_url();
    // Simulate a URL that already absorbed 4 throttling events (5s each).
    url.rate_limit_retry_number = 4;
    url.rate_limit_total_wait_secs = 20;
    let api_call = create_test_api_call(url);

    let response = Response {
        status: 429,
        retry_after: Some(9),
        content: json!({}),
    };

    let (_rx, thread, _dir) = setup_response_thread(api_call.clone(), response.clone()).await;
    let returned_urls = thread.process_single(&response, &api_call).await;

    assert_eq!(returned_urls.len(), 1);
    let retried = &returned_urls[0];
    assert_eq!(retried.retry_number, 0);
    assert_eq!(retried.rate_limit_retry_number, 5);
    assert_eq!(retried.rate_limit_total_wait_secs, 29);
}

/// A 429 *without* a `Retry-After` (response.retry_after == None) must accumulate
/// the configured default cooldown into `rate_limit_total_wait_secs` (here the
/// manager's global default of 5), not 0. This is the end-to-end guard for the
/// `prepare_rate_limit_retries` → `effective_retry_after` wiring (finding #1): a
/// header-less 429 must still make progress toward the `rateLimitMaxWaitSecs`
/// abandon cap and not spin forever on AIMD alone.
#[tokio::test]
async fn too_many_requests_429_without_header_uses_default() {
    let url = create_test_url();
    let api_call = create_test_api_call(url);

    let response = Response {
        status: 429,
        retry_after: None,
        content: json!({}),
    };

    let (_rx, thread, _dir) = setup_response_thread(api_call.clone(), response.clone()).await;
    let returned_urls = thread.process_single(&response, &api_call).await;

    assert_eq!(returned_urls.len(), 1);
    let retried = &returned_urls[0];
    assert_eq!(
        retried.rate_limit_total_wait_secs, 5,
        "a header-less 429 must accumulate the configured default cooldown, not 0"
    );
    assert_eq!(retried.rate_limit_retry_number, 1);
    assert_eq!(
        retried.retry_number, 0,
        "429 must not consume the real-error retry budget"
    );

    // Provenance wiring: a header-less 429 must count as "default", not "server".
    let (server_count, default_count) = thread
        .context
        .stats
        .services
        .get("graph")
        .map(|s| {
            (
                s.retry_after_server_count.load(Ordering::Relaxed),
                s.retry_after_default_count.load(Ordering::Relaxed),
            )
        })
        .unwrap_or((0, 0));
    assert_eq!(
        default_count, 1,
        "a 429 without Retry-After must increment retry_after_default_count"
    );
    assert_eq!(
        server_count, 0,
        "no server-provided Retry-After was present"
    );
}

// ─── AIMD window adjusted exactly once per HTTP response ─────────────────────
// The AIMD window signal lives solely in the response module and fires once per
// response: once for a single 429, once for a 429 batch envelope, and once for
// a 2xx batch that wraps sub-429s. A request worker must never adjust the window
// directly.

async fn setup_thread_with_controller(
    api_call: ApiCall,
    response: Response,
    controller: Arc<ConcurrencyController>,
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
            concurrency_controller: controller,
            stats,
            logs_date_filter_and: None,
        },
        Box::new(ResponseContent { api_call, response }),
    );
    (update_rx, thread, temp_dir)
}

#[tokio::test]
async fn single_429_halves_concurrency_window_exactly_once() {
    let controller = Arc::new(ConcurrencyController::new(1, 20));
    controller.acquire_slot("graph").await; // create the service window at max=20
    assert_eq!(controller.current_window("graph"), 20);

    let api_call = create_test_api_call(create_test_url());
    let response = Response {
        status: 429,
        retry_after: Some(30),
        content: json!({}),
    };
    let (_rx, thread, _dir) =
        setup_thread_with_controller(api_call, response, Arc::clone(&controller)).await;
    thread.process().await;

    assert_eq!(
        controller.current_window("graph"),
        10,
        "a single 429 must halve the window once (20->10), not twice (->5)"
    );
}

#[tokio::test]
async fn batch_2xx_with_multiple_sub_429_halves_window_once() {
    let controller = Arc::new(ConcurrencyController::new(1, 20));
    controller.acquire_slot("graph").await;
    assert_eq!(controller.current_window("graph"), 20);

    // Two sub-requests, both throttled (429) inside a single 200 batch envelope.
    let mut initial = HashMap::new();
    initial.insert("0".to_string(), create_test_api_call(create_test_url()));
    initial.insert("1".to_string(), create_test_api_call(create_test_url()));
    let batch_data = BatchData {
        post_data: HashMap::new(),
        initial_data: initial,
        id_field: "id".to_string(),
        body_field: "body".to_string(),
        status_field: "status".to_string(),
        retry_after_field: "headers/Retry-After".to_string(),
    };
    let mut url = create_test_url();
    url.api = "batch".to_string();
    let batch_call = ApiCall {
        id: 1,
        url,
        success_code: 200,
        batch_data: Some(batch_data),
        value_pointer: "/responses".to_string(),
        is_batch: true,
    };
    let response = Response {
        status: 200,
        retry_after: None,
        content: json!({"responses": [
            {"id": "0", "status": 429},
            {"id": "1", "status": 429}
        ]}),
    };
    let (_rx, thread, _dir) =
        setup_thread_with_controller(batch_call, response, Arc::clone(&controller)).await;
    thread.process().await;

    assert_eq!(
        controller.current_window("graph"),
        10,
        "a 2xx batch wrapping 2 sub-429s must halve the window once (20->10), not per-sub (->5)"
    );
}

/// B-2: a 401 at the batch ENVELOPE level (the whole `$batch` POST rejected — e.g.
/// the bearer was revoked mid-run) must emit `TokenExpirationError` so the token is
/// refreshed before the re-queued sub-URLs go out again. Previously the envelope 401
/// re-queued sub-URLs with the stale token until `urlRetryLimit` and lost the batch.
#[tokio::test]
async fn batch_envelope_401_emits_token_refresh_and_requeues_subs() {
    let url1 = create_test_url();
    let mut url2 = create_test_url();
    url2.api = "other".to_string();

    let mut initial_data = HashMap::new();
    initial_data.insert("1".to_string(), create_test_api_call(url1.clone()));
    initial_data.insert("2".to_string(), create_test_api_call(url2.clone()));

    let batch_data = oradaz::utils::url::BatchData {
        post_data: HashMap::new(),
        id_field: "id".to_string(),
        status_field: "status".to_string(),
        retry_after_field: "retryAfter".to_string(),
        body_field: "body".to_string(),
        initial_data,
    };

    let mut batch_api_call = create_test_api_call(url1.clone());
    batch_api_call.is_batch = true;
    batch_api_call.batch_data = Some(batch_data);

    // Envelope-level 401 (the whole batch POST was rejected; no per-sub detail).
    let response = Response {
        status: 401,
        retry_after: None,
        content: json!({ "error": { "code": "InvalidAuthenticationToken", "message": "expired" } }),
    };

    let (mut rx, thread, _dir) = setup_response_thread(batch_api_call, response).await;
    let returned_urls = thread.process_batch().await;

    // Both sub-URLs are re-queued for re-dispatch with the refreshed token.
    assert_eq!(returned_urls.len(), 2, "both sub-URLs should be re-queued");

    // A TokenExpirationError must have been emitted so the coordinator refreshes the token.
    let messages: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    let has_token_error = messages.iter().any(|m| {
        matches!(
            m,
            CoordinatorEvent::NewError(_, ProcessError::TokenExpirationError)
        )
    });
    assert!(
        has_token_error,
        "envelope 401 must emit TokenExpirationError"
    );
}

/// Expected-error breaker gate: only declared-expected errors **flagged
/// `breaker_eligible` in the schema** feed the breaker. A bucket returning N
/// consecutive such errors with no page ever written must trip exactly once
/// (`BreakerTripped`). An unflagged expected error must NOT trip — even on the
/// same status — or data-bearing siblings of the bucket would be silently
/// skipped. The flag, not the status, is the gate (any code asserted
/// tenant-wide can drive it, not only 403).
#[tokio::test]
async fn breaker_trips_only_on_breaker_eligible_expected_errors() {
    use oradaz::utils::url::ExpectedErrorCode;

    async fn count_breaker_trips(status: u16, code: &str, breaker_eligible: bool) -> usize {
        let mut url = create_test_url();
        url.expected_error_codes = Some(Arc::new(vec![ExpectedErrorCode {
            status,
            code: Some(code.to_string()),
            breaker_eligible,
        }]));
        let api_call = create_test_api_call(url);
        let response = Response {
            status,
            retry_after: None,
            content: json!({"error": {"code": code, "message": "x"}}),
        };
        let (mut rx, thread, _dir) =
            setup_response_thread(api_call.clone(), response.clone()).await;
        thread.context.stats.set_breaker_threshold(3);
        // Feed well past the threshold; the bucket never writes a page.
        for _ in 0..5 {
            thread.process_single(&response, &api_call).await;
        }
        std::iter::from_fn(|| rx.try_recv().ok())
            .filter(|e| matches!(e, CoordinatorEvent::BreakerTripped { .. }))
            .count()
    }

    // The real users_permissionGrants case: flagged 403 → trips exactly once.
    assert_eq!(
        count_breaker_trips(403, "Forbidden", true).await,
        1,
        "consecutive flagged expected errors must trip the breaker exactly once"
    );
    // Same status, but not flagged → never trips (status alone is not enough).
    assert_eq!(
        count_breaker_trips(403, "Forbidden", false).await,
        0,
        "an unflagged expected error must never trip the breaker"
    );
    // The gate is the flag, not 403: a flagged non-403 code drives it too.
    assert_eq!(
        count_breaker_trips(400, "TenantWideDisabled", true).await,
        1,
        "any code flagged breaker_eligible drives the breaker, not only 403"
    );
}
