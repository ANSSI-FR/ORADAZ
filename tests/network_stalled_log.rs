// End-to-end check that the diagnostic lines naming failing sub-requests, the
// forced-single switch and the NetworkStalled abandonment reach a real
// `oradaz.log`. The logger is process-global, so this file holds one test.

mod common;

use crate::common::default_test_config;
use dashmap::DashMap;
use oradaz::collect::auth::tokens::{Token, TokenState};
use oradaz::collect::dump::orchestration::events::CoordinatorEvent;
use oradaz::collect::dump::request::RequestsThread;
use oradaz::collect::dump::response::ResponseMsg;
use oradaz::utils::client::OradazClient;
use oradaz::utils::logger::{self, Verbosity, remove_writer};
use oradaz::utils::url::{ApiCall, ApiCallItem, RetryLimits, Url as OradazUrl};
use oradaz::utils::writer::actor::spawn_writer_task;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn create_test_token() -> Token {
    Token {
        tenant_id: "test-tenant".to_string(),
        client_id: "test-client".to_string(),
        service: "graph".to_string(),
        expires_on: chrono::Utc::now().timestamp() + 3600,
        access_token: "test_access_token".to_string(),
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

fn make_batch_api_call(server: &str, sub_urls: &[OradazUrl]) -> ApiCall {
    use oradaz::utils::url::{BatchData, GraphPostData, PostBatchData};
    let mut batch_data = BatchData {
        post_data: HashMap::new(),
        initial_data: HashMap::new(),
        id_field: "id".to_string(),
        body_field: "body".to_string(),
        status_field: "status".to_string(),
        retry_after_field: "headers/Retry-After".to_string(),
    };
    for (i, url) in sub_urls.iter().enumerate() {
        let id = (i + 1).to_string();
        batch_data.initial_data.insert(
            id.clone(),
            ApiCall {
                id: 0,
                url: url.clone(),
                success_code: 200,
                value_pointer: "/value".to_string(),
                is_batch: false,
                batch_data: None,
            },
        );
        batch_data
            .post_data
            .entry(String::from("requests"))
            .or_default()
            .push(PostBatchData::GraphPostData(GraphPostData {
                id,
                method: "GET".to_string(),
                url: url.url.clone(),
                headers: None,
            }));
    }
    let mut envelope = create_test_url();
    envelope.api = "batch".to_string();
    envelope.url = format!("{server}/v1.0/$batch");
    ApiCall {
        id: 0,
        url: envelope,
        success_code: 200,
        value_pointer: "/responses".to_string(),
        is_batch: true,
        batch_data: Some(batch_data),
    }
}

fn make_sub_url(server: &str, api: &str, path: &str) -> OradazUrl {
    let mut url = create_test_url();
    url.api = api.to_string();
    url.url = format!("{server}{path}");
    url
}

fn make_request_thread(
    api_call: ApiCall,
    stats: Arc<oradaz::utils::stats::Stats>,
    config: oradaz::utils::config::Config,
    response_tx: mpsc::Sender<ResponseMsg>,
    update_tx: mpsc::Sender<oradaz::collect::dump::orchestration::events::CoordinatorEvent>,
) -> RequestsThread {
    let client = OradazClient::new(&config).unwrap();
    let tokens = Arc::new(DashMap::new());
    tokens.insert(
        Arc::from("graph"),
        Arc::new(TokenState::new(create_test_token())),
    );
    RequestsThread::new(
        response_tx,
        update_tx,
        oradaz::collect::dump::request::RequestExecutionContext {
            oradaz_client: client,
            tokens,
            ratelimit_manager: Arc::new(
                oradaz::collect::dump::ratelimit::RateLimitManager::default(),
            ),
            concurrency_controller: Arc::new(
                oradaz::collect::dump::concurrency::ConcurrencyController::default(),
            ),
            stats,
            config: Arc::new(config),
        },
        Box::new(api_call),
    )
}

/// Dispatches one single-request ApiCall for `url` and returns the response
/// messages and the re-queued URLs.
async fn dispatch_single(
    url: &OradazUrl,
    stats: &Arc<oradaz::utils::stats::Stats>,
    config: &oradaz::utils::config::Config,
) -> (Vec<ResponseMsg>, Vec<OradazUrl>) {
    let limits = RetryLimits {
        retry: 5,
        rate_limit_retry: 50,
        rate_limit_max_wait_secs: 900,
    };
    let mut urls = vec![url.clone()];
    let mut messages = Vec::new();
    let mut requeued = Vec::new();
    for item in ApiCall::from("graph", &mut urls, limits).unwrap() {
        let call = match item {
            ApiCallItem::ApiCall(call) => call,
            ApiCallItem::ApiCallError(err) => panic!("unexpected error item: {err:?}"),
        };
        assert!(!call.is_batch, "a forced URL must never re-enter a batch");
        let (response_tx, mut response_rx) = mpsc::channel::<ResponseMsg>(8192);
        let (update_tx, mut update_rx) = mpsc::channel::<CoordinatorEvent>(8192);
        make_request_thread(
            *call,
            Arc::clone(stats),
            config.clone(),
            response_tx,
            update_tx,
        )
        .process()
        .await;
        while let Ok(m) = response_rx.try_recv() {
            messages.push(m);
        }
        while let Ok(CoordinatorEvent::RequestCompleted { new_urls, .. }) = update_rx.try_recv() {
            requeued.extend(new_urls);
        }
    }
    (messages, requeued)
}

#[tokio::test]
async fn network_stalled_diagnostics_reach_the_log() {
    let tmp_dir = tempfile::tempdir().expect("temp dir");
    let output_path = tmp_dir.path().to_path_buf();

    let mut config = default_test_config();
    config.output_files = Some(true);
    config.output_mla = Some(false);
    config.http_timeout_seconds = Some(1);
    // The cap allows exactly one doubling of the 1 s base timeout.
    config.http_timeout_max_seconds = Some(2);

    let (writer_handle, writer_join) = spawn_writer_task(
        config.clone(),
        output_path.clone(),
        "stalled_log_test".to_string(),
    )
    .await
    .expect("writer task");
    logger::initialize(Some(writer_handle.clone()), Verbosity::Debug);

    // POST /v1.0/$batch and GET /v1.0/slow answer after 3 s (beyond both
    // the 1 s timeout and its 2 s escalation); GET /v1.0/fast answers immediately.
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1.0/$batch"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(3)))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1.0/slow"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(3)))
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1.0/fast"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "id": "fast" }]
        })))
        .mount(&mock_server)
        .await;

    let stats = Arc::new(oradaz::utils::stats::Stats::new());
    stats.set_liveness_ceiling_secs(7);
    let server = mock_server.uri();
    let slow = make_sub_url(&server, "apiSlow", "/v1.0/slow");
    let fast = make_sub_url(&server, "apiFast", "/v1.0/fast");

    // Two batch timeouts: the first only counts, the second degrades both
    // sub-URLs to single dispatch (the liveness ceiling is not reached yet).
    let mut queue = vec![slow, fast];
    for _ in 0..2 {
        let (response_tx, _response_rx) = mpsc::channel::<ResponseMsg>(8192);
        let (update_tx, mut update_rx) = mpsc::channel::<CoordinatorEvent>(8192);
        make_request_thread(
            make_batch_api_call(&server, &queue),
            Arc::clone(&stats),
            config.clone(),
            response_tx,
            update_tx,
        )
        .process()
        .await;
        queue = match update_rx.try_recv().expect("a RequestCompleted event") {
            CoordinatorEvent::RequestCompleted { new_urls, .. } => new_urls,
            _ => panic!("expected RequestCompleted after a batch timeout"),
        };
        assert_eq!(queue.len(), 2, "no abandonment while batching");
    }
    assert!(queue.iter().all(|u| u.force_single), "both are degraded");
    let fast = queue.iter().find(|u| u.api == "apiFast").unwrap().clone();
    let mut slow = queue.iter().find(|u| u.api == "apiSlow").unwrap().clone();

    // The healthy sibling answers as a single request.
    let (messages, _) = dispatch_single(&fast, &stats, &config).await;
    assert!(
        matches!(messages.as_slice(), [ResponseMsg::ResponseData(_)]),
        "the fast URL must produce data"
    );

    // The slow one keeps timing out until the liveness ceiling abandons it.
    let mut stalled_message = None;
    let mut attempts = 0usize;
    for _ in 0..6 {
        attempts += 1;
        let (messages, requeued) = dispatch_single(&slow, &stats, &config).await;
        if let Some(ResponseMsg::LostData(err, _)) = messages
            .iter()
            .find(|m| matches!(m, ResponseMsg::LostData(..)))
        {
            stalled_message = Some(err.message.clone());
            break;
        }
        slow = requeued.into_iter().next().expect("slow URL is re-queued");
    }
    let stalled_message =
        stalled_message.expect("the slow URL must be abandoned within 6 attempts");

    remove_writer();
    drop(writer_handle);
    let _ = writer_join.await;

    let log = std::fs::read_to_string(output_path.join("stalled_log_test").join("oradaz.log"))
        .expect("read oradaz.log");
    assert!(
        log.contains("transport failure (Timeout) — sub-request") && log.contains("/v1.0/slow"),
        "{log}"
    );
    assert!(
        log.contains("degrading \"graph\"/\"apiSlow\" to single dispatch"),
        "{log}"
    );
    assert!(
        log.lines().any(
            |l| l.contains("Abandoning \"graph\"/\"apiSlow\" as NetworkStalled")
                && l.contains("/v1.0/slow")
        ),
        "{log}"
    );
    assert!(log.contains("Timeout after 1s for request"), "{log}");
    assert!(
        !log.contains("Abandoning \"graph\"/\"apiFast\""),
        "the healthy sibling must not be abandoned:\n{log}"
    );
    assert!(
        log.contains("First response for service \"graph\" used HTTP/1.1"),
        "{log}"
    );
    assert!(attempts >= 2, "the escalation needs a second attempt");
    assert!(
        log.contains("Timeout escalation for \"graph\"/\"apiSlow\": next single attempt waits up to 2s (timeout #1)"),
        "{log}"
    );
    assert!(
        stalled_message.contains(&format!(
            "{attempts} single-request timeouts, last attempt timeout 2s)."
        )),
        "NetworkStalled message must count the current timeout ({attempts}): {stalled_message}"
    );
    assert!(
        log.contains(&format!(
            "{attempts} single-request timeouts, last attempt timeout 2s, forced single: true"
        )),
        "{log}"
    );
}
