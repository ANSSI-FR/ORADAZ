mod common;

use crate::common::default_test_config;
use oradaz::collect::auth::tokens::{Token, TokenState};
use oradaz::collect::dump::request::RequestsThread;
use oradaz::collect::dump::response::ResponseMsg;
use oradaz::utils::client::OradazClient;
use oradaz::utils::url::{ApiCall, Url as OradazUrl};

use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::mpsc;
use wiremock::matchers::{bearer_token, method, path};
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
async fn test_timeout_logging_and_retry() {
    let mock_server = MockServer::start().await;

    // Mock endpoint that delays beyond the client timeout
    Mock::given(method("GET"))
        .and(path("/v1.0/applications"))
        .and(bearer_token("test_access_token"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
        .mount(&mock_server)
        .await;

    // Override config to have a very short timeout (1 second)
    let mut config = default_test_config();
    config.http_timeout_seconds = Some(1); // 1 second timeout
    let client = OradazClient::new(&config).unwrap();
    let token = create_test_token();
    let mut api_call = create_test_api_call();
    api_call.url.url = format!("{}/v1.0/applications", mock_server.uri());

    let (response_tx, _response_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (update_tx, mut update_rx) =
        mpsc::channel::<oradaz::collect::dump::orchestration::events::CoordinatorEvent>(8192);

    let tokens = Arc::new(DashMap::new());
    tokens.insert(Arc::from("graph"), Arc::new(TokenState::new(token)));

    // Record current retry count
    let initial_retries = oradaz::collect::dump::request::RETRY_COUNT.load(Ordering::Relaxed);

    let stats = Arc::new(oradaz::utils::stats::Stats::new());
    let request_thread = RequestsThread::new(
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
            stats: Arc::clone(&stats),
            config: Arc::new(config),
        },
        Box::new(api_call),
    );

    request_thread.process().await;

    // Expect a RequestCompleted event re-queuing the timed-out URL as a *network*
    // retry — without consuming the real-error retry budget.
    match update_rx.try_recv() {
        Ok(oradaz::collect::dump::orchestration::events::CoordinatorEvent::RequestCompleted {
            new_urls,
            ..
        }) => {
            assert_eq!(new_urls.len(), 1, "the timed-out URL must be re-queued");
            assert_eq!(
                new_urls[0].network_retry_number, 1,
                "a transport failure increments the network-retry counter"
            );
            assert_eq!(
                new_urls[0].retry_number, 0,
                "a transport failure must not consume the real-error retry budget"
            );
        }
        _ => panic!("Expected RequestCompleted event after timeout retry"),
    }

    let final_retries = oradaz::collect::dump::request::RETRY_COUNT.load(Ordering::Relaxed);
    assert!(
        final_retries > initial_retries,
        "Retry count should have increased after timeout"
    );

    // The transport failure is a network error only — it must not pollute
    // `retries_real`, the real-error (4xx/5xx) retry metric.
    let json: serde_json::Value = serde_json::to_value(&*stats).unwrap();
    let apis = json["apis"].as_array().expect("apis array present");
    let api = apis
        .iter()
        .find(|a| a["api"] == "applications")
        .expect("the network-failed api is recorded");
    assert_eq!(api["network_errors"], 1, "one network error recorded");
    assert_eq!(
        api["retries_real"], 0,
        "network retries must not increment retries_real"
    );

    // Cause breakdown: a client timeout lands in the per-service timeout bucket,
    // and the retry's backoff sleep is accumulated as wall-clock cost.
    let svc = &json["services"]["graph"];
    assert_eq!(
        svc["network_timeout_errors"], 1,
        "the timeout must be classified in the timeout bucket"
    );
    assert_eq!(svc["network_connect_errors"], 0);
    assert!(
        svc["backoff_wait_ms_total"].as_u64().unwrap_or(0) > 0,
        "the retry backoff sleep must be accumulated"
    );
}

#[tokio::test]
async fn test_builder_error_routes_to_real_error_retry() {
    // A malformed request URL is a permanent (builder) error: retrying cannot
    // help, so it must consume the real-error retry budget (retry_number), not
    // the transport/network budget.
    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    let token = create_test_token();
    let mut api_call = create_test_api_call();
    api_call.url.url = "http://[".to_string(); // invalid URL → reqwest builder error

    let (response_tx, _response_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (update_tx, mut update_rx) =
        mpsc::channel::<oradaz::collect::dump::orchestration::events::CoordinatorEvent>(8192);

    let tokens = Arc::new(DashMap::new());
    tokens.insert(Arc::from("graph"), Arc::new(TokenState::new(token)));

    let request_thread = RequestsThread::new(
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
            stats: Arc::new(oradaz::utils::stats::Stats::new()),
            config: Arc::new(config),
        },
        Box::new(api_call),
    );

    request_thread.process().await;

    match update_rx.try_recv() {
        Ok(oradaz::collect::dump::orchestration::events::CoordinatorEvent::RequestCompleted {
            new_urls,
            ..
        }) => {
            assert_eq!(new_urls.len(), 1, "the malformed URL must be re-queued");
            assert_eq!(
                new_urls[0].retry_number, 1,
                "a builder error consumes the real-error retry budget"
            );
            assert_eq!(
                new_urls[0].network_retry_number, 0,
                "a builder error must not touch the network retry budget"
            );
        }
        _ => panic!("Expected RequestCompleted event after a builder error"),
    }
}

#[tokio::test(start_paused = true)]
async fn finalize_retry_abandons_as_network_stalled_past_liveness_ceiling() {
    // A transport failure whose (service, api) bucket has made no progress within
    // the liveness ceiling is abandoned as lost data (NetworkStalled), via the
    // counter-neutral ResponseMsg::LostData (NO extra RequestCompleted).
    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    let token = create_test_token();

    let stats = Arc::new(oradaz::utils::stats::Stats::new());
    stats.set_liveness_ceiling_secs(1);
    // Seed the bucket's baseline, then age it past the ceiling.
    stats.note_progress("graph", "applications");
    tokio::time::advance(Duration::from_secs(2)).await;

    let mut api_call = create_test_api_call();
    api_call.url.url = "http://127.0.0.1:1".to_string(); // closed port → connect error

    let (response_tx, mut response_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (update_tx, mut update_rx) =
        mpsc::channel::<oradaz::collect::dump::orchestration::events::CoordinatorEvent>(8192);
    let tokens = Arc::new(DashMap::new());
    tokens.insert(Arc::from("graph"), Arc::new(TokenState::new(token)));

    let request_thread = RequestsThread::new(
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
            stats: Arc::clone(&stats),
            config: Arc::new(config),
        },
        Box::new(api_call),
    );

    request_thread.process().await;

    // The abandoned URL is written as a counter-neutral LostData(NetworkStalled).
    match response_rx.try_recv().expect("a LostData message") {
        ResponseMsg::LostData(err, _) => {
            assert_eq!(err.status, 0);
            assert_eq!(err.code, "NetworkStalled");
            assert_eq!(err.file, "applications");
        }
        _ => panic!("expected ResponseMsg::LostData(NetworkStalled)"),
    }
    // Exactly one RequestCompleted, with the abandoned URL NOT re-queued.
    match update_rx.try_recv().expect("a RequestCompleted event") {
        oradaz::collect::dump::orchestration::events::CoordinatorEvent::RequestCompleted {
            new_urls,
            count,
            ..
        } => {
            assert_eq!(count, 1);
            assert!(
                new_urls.is_empty(),
                "an abandoned URL must not be re-queued"
            );
        }
        _ => panic!("expected RequestCompleted"),
    }
}

#[tokio::test(start_paused = true)]
async fn slot_is_held_during_cooldown_wait() {
    // Keystone order: process() acquires its AIMD slot BEFORE waiting out a 429
    // cooldown, so at most `window` workers wait per cooldown (the pacing). This
    // pins that order: the worker holds a slot WHILE in the cooldown, and no
    // request leaves until the cooldown expires. Were the order reversed, the
    // worker would wait the cooldown holding no slot (in_flight would stay 0).
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"value": []})))
        .mount(&mock)
        .await;

    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    let token = create_test_token();

    let ratelimit = Arc::new(oradaz::collect::dump::ratelimit::RateLimitManager::new(5));
    ratelimit.report_429("graph", Some(60)); // arm a 60 s cooldown
    let controller =
        Arc::new(oradaz::collect::dump::concurrency::ConcurrencyController::new(1, 30));

    let mut api_call = create_test_api_call();
    api_call.url.url = format!("{}/v1.0/applications", mock.uri());

    let (response_tx, _response_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (update_tx, _update_rx) =
        mpsc::channel::<oradaz::collect::dump::orchestration::events::CoordinatorEvent>(8192);
    let tokens = Arc::new(DashMap::new());
    tokens.insert(Arc::from("graph"), Arc::new(TokenState::new(token)));

    let request_thread = RequestsThread::new(
        response_tx,
        update_tx,
        oradaz::collect::dump::request::RequestExecutionContext {
            oradaz_client: client,
            tokens,
            ratelimit_manager: Arc::clone(&ratelimit),
            concurrency_controller: Arc::clone(&controller),
            stats: Arc::new(oradaz::utils::stats::Stats::new()),
            config: Arc::new(config),
        },
        Box::new(api_call),
    );

    let handle = tokio::spawn(async move { request_thread.process().await });

    // Let the worker acquire its slot and park on the cooldown (bounded, so a
    // reversed order — slot never held — fails rather than hangs).
    let mut in_flight = 0;
    for _ in 0..100 {
        tokio::task::yield_now().await;
        in_flight = controller
            .get_all_in_flight()
            .get("graph")
            .copied()
            .unwrap_or(0);
        if in_flight == 1 {
            break;
        }
    }
    assert_eq!(
        in_flight, 1,
        "the worker must hold its slot while waiting out the cooldown (slot-before-cooldown order)"
    );
    assert!(
        mock.received_requests().await.unwrap().is_empty(),
        "no request must leave before the cooldown expires"
    );

    // Expire the cooldown deterministically (60 s + ≤2 s forward jitter), then
    // switch back to real time BEFORE the worker performs its HTTP exchange.
    // Under auto-advancing paused time the virtual clock can jump past the
    // reqwest timeout before the wiremock socket is ever polled, failing the
    // request with a spurious virtual timeout (flaky); with time resumed, the
    // exchange runs against the real clock and completes in milliseconds.
    tokio::time::advance(std::time::Duration::from_secs(63)).await;
    tokio::time::resume();

    // The expired cooldown lets the request go out and the slot is freed.
    let _ = handle.await;
    assert_eq!(
        mock.received_requests().await.unwrap().len(),
        1,
        "the request must be sent once the cooldown expires"
    );
}
