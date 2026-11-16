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

// ─── batch timeout → forced single degradation ───────────────────────────────

/// Builds a graph batch envelope ApiCall over the given sub-URLs (ids "1"..),
/// pointing the envelope at `{server}/v1.0/$batch`. Mirrors the shape the graph
/// batch builder produces, with mock-server hosts.
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

fn fallback_transitions(stats: &oradaz::utils::stats::Stats, api: &str) -> u64 {
    let json: serde_json::Value = serde_json::to_value(stats).unwrap();
    json["apis"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["api"] == api)
        .map(|a| a["batch_single_fallbacks"].as_u64().unwrap_or(0))
        .unwrap_or(0)
}

/// First batch timeout: per-URL network counter 0→1, no transition. Second
/// batch timeout: 1→2, `force_single = true`, one transition per URL. Replaying
/// the queue then produces N single GETs exactly once and no further batch POST
/// for those URLs; the per-URL flag routes them through the default builder.
#[tokio::test]
async fn batch_timeout_second_strike_forces_single_and_replays_as_gets() {
    use oradaz::collect::dump::orchestration::events::CoordinatorEvent;
    use oradaz::utils::url::{ApiCallItem, RetryLimits};
    use wiremock::matchers::any;

    let mock_server = MockServer::start().await;
    // The batch endpoint never answers within the 1 s client timeout.
    Mock::given(method("POST"))
        .and(path("/v1.0/$batch"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(4)))
        .mount(&mock_server)
        .await;
    // The per-object endpoints answer instantly.
    for p in ["a", "b"] {
        Mock::given(method("GET"))
            .and(path(format!("/v1.0/{p}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{ "id": p }]
            })))
            .mount(&mock_server)
            .await;
    }
    // Safety net: anything else unexpectedly requested still gets an answer.
    Mock::given(any())
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_server)
        .await;

    let mut config = default_test_config();
    config.http_timeout_seconds = Some(1);
    let stats = Arc::new(oradaz::utils::stats::Stats::new());
    let server = mock_server.uri();

    let sub_a = make_sub_url(&server, "apiA", "/v1.0/a");
    let sub_b = make_sub_url(&server, "apiB", "/v1.0/b");

    // ── First batch timeout ──
    let (response_tx, _response_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (update_tx, mut update_rx) = mpsc::channel::<CoordinatorEvent>(8192);
    make_request_thread(
        make_batch_api_call(&server, &[sub_a.clone(), sub_b.clone()]),
        Arc::clone(&stats),
        config.clone(),
        response_tx,
        update_tx,
    )
    .process()
    .await;
    let first_requeue = match update_rx.try_recv().expect("a RequestCompleted event") {
        CoordinatorEvent::RequestCompleted { new_urls, .. } => new_urls,
        _ => panic!("expected RequestCompleted after the first batch timeout"),
    };
    assert_eq!(first_requeue.len(), 2);
    for url in &first_requeue {
        assert_eq!(url.network_retry_number, 1, "first strike: counter 0→1");
        assert!(!url.force_single, "one batch timeout must not force single");
        assert!(url.forced_single_tracker.is_none());
    }
    assert_eq!(fallback_transitions(&stats, "apiA"), 0, "no transition yet");
    assert_eq!(fallback_transitions(&stats, "apiB"), 0, "no transition yet");

    // ── Second batch timeout (the same envelope is rebuilt, as finalize_retry
    // re-queues the same sub-URLs) ──
    let (response_tx, _response_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (update_tx, mut update_rx) = mpsc::channel::<CoordinatorEvent>(8192);
    make_request_thread(
        make_batch_api_call(&server, &first_requeue),
        Arc::clone(&stats),
        config.clone(),
        response_tx,
        update_tx,
    )
    .process()
    .await;
    let mut second_requeue = match update_rx.try_recv().expect("a RequestCompleted event") {
        CoordinatorEvent::RequestCompleted { new_urls, .. } => new_urls,
        _ => panic!("expected RequestCompleted after the second batch timeout"),
    };
    assert_eq!(second_requeue.len(), 2);
    for url in &second_requeue {
        assert_eq!(url.network_retry_number, 2, "second strike: counter 1→2");
        assert!(url.force_single, "the second batch timeout forces single");
        assert!(url.forced_single_tracker.is_some(), "a tracker is created");
    }
    assert_eq!(
        fallback_transitions(&stats, "apiA"),
        1,
        "one transition per URL"
    );
    assert_eq!(
        fallback_transitions(&stats, "apiB"),
        1,
        "one transition per URL"
    );

    // ── Replay the queue: N single GETs exactly once, no new batch POST ──
    let limits = RetryLimits {
        retry: 5,
        rate_limit_retry: 50,
        rate_limit_max_wait_secs: 900,
    };
    let mut dispatched = 0;
    while !second_requeue.is_empty() {
        let items = ApiCall::from("graph", &mut second_requeue, limits).unwrap();
        for item in items {
            let call = match item {
                ApiCallItem::ApiCall(call) => call,
                ApiCallItem::ApiCallError(err) => panic!("unexpected error item: {err:?}"),
            };
            assert!(!call.is_batch, "a forced URL must never re-enter a batch");
            let (response_tx, mut response_rx) = mpsc::channel::<ResponseMsg>(8192);
            let (update_tx, _update_rx) = mpsc::channel::<CoordinatorEvent>(8192);
            make_request_thread(
                *call,
                Arc::clone(&stats),
                config.clone(),
                response_tx,
                update_tx,
            )
            .process()
            .await;
            match response_rx.try_recv().expect("a response message") {
                ResponseMsg::ResponseData(data) => assert_eq!(data.response.status, 200),
                _ => panic!("expected ResponseData for the single GET"),
            }
            dispatched += 1;
        }
    }
    assert_eq!(
        dispatched, 2,
        "each forced URL dispatches single exactly once"
    );

    let requests = mock_server.received_requests().await.unwrap();
    let posts = requests
        .iter()
        .filter(|r| r.method.as_str() == "POST")
        .count();
    let gets_a = requests
        .iter()
        .filter(|r| r.method.as_str() == "GET" && r.url.path() == "/v1.0/a")
        .count();
    let gets_b = requests
        .iter()
        .filter(|r| r.method.as_str() == "GET" && r.url.path() == "/v1.0/b")
        .count();
    assert_eq!(posts, 2, "no third batch POST is sent for the forced URLs");
    assert_eq!(gets_a, 1, "each identity is fetched exactly once");
    assert_eq!(gets_b, 1, "each identity is fetched exactly once");

    // Transitions did not re-count on replay.
    assert_eq!(fallback_transitions(&stats, "apiA"), 1);
    assert_eq!(fallback_transitions(&stats, "apiB"), 1);
}

/// A later timeout on an already-forced single request keeps the flag and the
/// tracker without recording another transition.
#[tokio::test]
async fn batch_timeout_then_single_timeout_keeps_flag_without_recount() {
    use oradaz::collect::dump::orchestration::events::CoordinatorEvent;
    use oradaz::utils::url::ForcedSingleTracker;

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1.0/a"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(4)))
        .mount(&mock_server)
        .await;

    let mut config = default_test_config();
    config.http_timeout_seconds = Some(1);
    let stats = Arc::new(oradaz::utils::stats::Stats::new());

    let mut url = make_sub_url(&mock_server.uri(), "apiA", "/v1.0/a");
    url.network_retry_number = 2;
    url.force_single = true;
    url.forced_single_tracker = Some(Arc::new(ForcedSingleTracker::new()));

    let (response_tx, _response_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (update_tx, mut update_rx) = mpsc::channel::<CoordinatorEvent>(8192);
    make_request_thread(
        ApiCall {
            id: 0,
            url,
            success_code: 200,
            value_pointer: "/value".to_string(),
            is_batch: false,
            batch_data: None,
        },
        Arc::clone(&stats),
        config,
        response_tx,
        update_tx,
    )
    .process()
    .await;

    match update_rx.try_recv().expect("a RequestCompleted event") {
        CoordinatorEvent::RequestCompleted { new_urls, .. } => {
            assert_eq!(new_urls.len(), 1);
            assert_eq!(new_urls[0].network_retry_number, 3);
            assert!(new_urls[0].force_single, "the flag is kept");
            assert!(
                new_urls[0].forced_single_tracker.is_some(),
                "the tracker is kept"
            );
        }
        _ => panic!("expected RequestCompleted after the single timeout"),
    }
    assert_eq!(
        fallback_transitions(&stats, "apiA"),
        0,
        "a single timeout records no transition"
    );
}

// ─── per-URL timeout escalation ──────────────────────────────────────────────

/// A single request that timed out once is retried with a doubled timeout,
/// so an endpoint answering in 1.5 s fails at 1 s and succeeds at 2 s.
#[tokio::test]
async fn single_timeout_escalates_next_attempt() {
    use oradaz::collect::dump::orchestration::events::CoordinatorEvent;
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1.0/slow"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "value": [{ "id": "x" }] }))
                .set_delay(Duration::from_millis(1500)),
        )
        .mount(&mock_server)
        .await;
    let mut config = default_test_config();
    config.http_timeout_seconds = Some(1);
    config.http_timeout_max_seconds = Some(2);
    let stats = Arc::new(oradaz::utils::stats::Stats::new());
    let url = make_sub_url(&mock_server.uri(), "apiSlow", "/v1.0/slow");
    let single = |u: OradazUrl| ApiCall {
        id: 0,
        url: u,
        success_code: 200,
        value_pointer: "/value".to_string(),
        is_batch: false,
        batch_data: None,
    };

    // Attempt 1: 1 s timeout -> requeued with one strike.
    let (response_tx, _response_rx) = mpsc::channel::<ResponseMsg>(64);
    let (update_tx, mut update_rx) = mpsc::channel::<CoordinatorEvent>(64);
    make_request_thread(
        single(url),
        Arc::clone(&stats),
        config.clone(),
        response_tx,
        update_tx,
    )
    .process()
    .await;
    let requeued = match update_rx.try_recv().expect("RequestCompleted") {
        CoordinatorEvent::RequestCompleted { new_urls, .. } => new_urls,
        _ => panic!("expected RequestCompleted"),
    };
    assert_eq!(requeued.len(), 1);
    assert_eq!(
        requeued[0].timeout_strikes, 1,
        "a single timeout is a strike"
    );

    // Attempt 2: escalated to 2 s -> the 1.5 s answer arrives.
    let (response_tx, mut response_rx) = mpsc::channel::<ResponseMsg>(64);
    let (update_tx, _update_rx) = mpsc::channel::<CoordinatorEvent>(64);
    make_request_thread(
        single(requeued[0].clone()),
        Arc::clone(&stats),
        config.clone(),
        response_tx,
        update_tx,
    )
    .process()
    .await;
    assert!(
        matches!(response_rx.try_recv(), Ok(ResponseMsg::ResponseData(_))),
        "the escalated attempt must receive the response"
    );
}

/// A URL whose API declares `http_timeout_seconds` above the service timeout
/// is sent with that timeout from the first attempt: an endpoint answering in
/// 1.5 s succeeds at once although the service timeout is 1 s.
#[tokio::test]
async fn api_timeout_hint_lets_slow_single_succeed_first_time() {
    use oradaz::collect::dump::orchestration::events::CoordinatorEvent;
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1.0/slow"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "value": [{ "id": "x" }] }))
                .set_delay(Duration::from_millis(1500)),
        )
        .mount(&mock_server)
        .await;
    let mut config = default_test_config();
    config.http_timeout_seconds = Some(1);
    let stats = Arc::new(oradaz::utils::stats::Stats::new());
    let mut url = make_sub_url(&mock_server.uri(), "apiSlow", "/v1.0/slow");
    url.api_behavior = Arc::new(HashMap::from([(
        "http_timeout_seconds".to_string(),
        "2".to_string(),
    )]));
    let (response_tx, mut response_rx) = mpsc::channel::<ResponseMsg>(64);
    let (update_tx, mut update_rx) = mpsc::channel::<CoordinatorEvent>(64);
    make_request_thread(
        ApiCall {
            id: 0,
            url,
            success_code: 200,
            value_pointer: "/value".to_string(),
            is_batch: false,
            batch_data: None,
        },
        Arc::clone(&stats),
        config,
        response_tx,
        update_tx,
    )
    .process()
    .await;
    assert!(
        matches!(response_rx.try_recv(), Ok(ResponseMsg::ResponseData(_))),
        "the declared timeout must let the first attempt succeed"
    );
    // On success the completion event is emitted by the response thread; the
    // request thread sends nothing, in particular no re-queue.
    assert!(
        update_rx.try_recv().is_err(),
        "no re-queue event expected from the request thread"
    );
}

/// A batch envelope takes the largest `http_timeout_seconds` declared by its
/// sub-URLs as its base timeout: an envelope answering in 1.5 s succeeds at the
/// first attempt although the service timeout is 1 s.
#[tokio::test]
async fn batch_envelope_uses_largest_sub_url_timeout_hint() {
    use oradaz::collect::dump::orchestration::events::CoordinatorEvent;
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1.0/$batch"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "responses": [] }))
                .set_delay(Duration::from_millis(1500)),
        )
        .mount(&mock_server)
        .await;
    let mut config = default_test_config();
    config.http_timeout_seconds = Some(1);
    let stats = Arc::new(oradaz::utils::stats::Stats::new());
    let plain = make_sub_url(&mock_server.uri(), "apiA", "/v1.0/a");
    let mut hinted = make_sub_url(&mock_server.uri(), "apiB", "/v1.0/b");
    hinted.api_behavior = Arc::new(HashMap::from([(
        "http_timeout_seconds".to_string(),
        "2".to_string(),
    )]));
    let api_call = make_batch_api_call(&mock_server.uri(), &[plain, hinted]);

    let (response_tx, mut response_rx) = mpsc::channel::<ResponseMsg>(64);
    let (update_tx, mut update_rx) = mpsc::channel::<CoordinatorEvent>(64);
    make_request_thread(api_call, stats, config, response_tx, update_tx)
        .process()
        .await;

    assert!(
        matches!(response_rx.try_recv(), Ok(ResponseMsg::ResponseData(_))),
        "the declared timeout must let the first envelope attempt succeed"
    );
    // On success the completion event is emitted by the response thread; the
    // request thread sends nothing, in particular no re-queue.
    assert!(
        update_rx.try_recv().is_err(),
        "no re-queue event expected from the request thread"
    );
}

/// A batch envelope that times out never adds a strike to its sub-URLs and is
/// never escalated: the envelope keeps the base timeout even when a
/// sub-URL already carries strikes.
#[tokio::test]
async fn batch_timeout_does_not_strike_or_escalate() {
    use oradaz::collect::dump::orchestration::events::CoordinatorEvent;
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1.0/$batch"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "responses": [] }))
                .set_delay(Duration::from_millis(1500)),
        )
        .mount(&mock_server)
        .await;
    let mut config = default_test_config();
    config.http_timeout_seconds = Some(1);
    config.http_timeout_max_seconds = Some(2);
    let stats = Arc::new(oradaz::utils::stats::Stats::new());
    let mut sub = make_sub_url(&mock_server.uri(), "apiA", "/v1.0/a");
    sub.timeout_strikes = 3;
    let mut api_call = make_batch_api_call(&mock_server.uri(), &[sub]);
    // The envelope itself carries strikes: an escalated timeout would let the slow answer through.
    api_call.url.timeout_strikes = 3;

    let (response_tx, mut response_rx) = mpsc::channel::<ResponseMsg>(64);
    let (update_tx, mut update_rx) = mpsc::channel::<CoordinatorEvent>(64);
    make_request_thread(api_call, stats, config, response_tx, update_tx)
        .process()
        .await;

    match update_rx.try_recv().expect("RequestCompleted") {
        CoordinatorEvent::RequestCompleted { new_urls, .. } => {
            assert_eq!(new_urls.len(), 1);
            assert_eq!(
                new_urls[0].timeout_strikes, 3,
                "a batch timeout adds no strike"
            );
        }
        _ => panic!("expected RequestCompleted"),
    }
    assert!(
        response_rx.try_recv().is_err(),
        "the envelope must have timed out: no response data"
    );
}

/// A connection error is not a timeout: it never adds a strike. The default
/// timeouts are kept on purpose: a refused localhost connection takes about 2 s
/// to be reported on Windows, which a 1 s timeout would turn into a Timeout.
#[tokio::test]
async fn connect_error_does_not_strike() {
    use oradaz::collect::dump::orchestration::events::CoordinatorEvent;
    let config = default_test_config();
    let stats = Arc::new(oradaz::utils::stats::Stats::new());
    let url = make_sub_url("http://127.0.0.1:1", "apiA", "/v1.0/x");

    let (response_tx, _response_rx) = mpsc::channel::<ResponseMsg>(64);
    let (update_tx, mut update_rx) = mpsc::channel::<CoordinatorEvent>(64);
    make_request_thread(
        ApiCall {
            id: 0,
            url,
            success_code: 200,
            value_pointer: "/value".to_string(),
            is_batch: false,
            batch_data: None,
        },
        stats,
        config,
        response_tx,
        update_tx,
    )
    .process()
    .await;

    match update_rx.try_recv().expect("RequestCompleted") {
        CoordinatorEvent::RequestCompleted { new_urls, .. } => {
            assert_eq!(new_urls.len(), 1);
            assert_eq!(new_urls[0].timeout_strikes, 0);
            assert_eq!(new_urls[0].network_retry_number, 1);
        }
        _ => panic!("expected RequestCompleted"),
    }
}

/// A batch transport failure whose bucket already exceeded the liveness ceiling
/// produces N `NetworkStalled` losses, zero re-emissions and zero transitions —
/// no single dispatch will ever happen for those URLs. The terminal message
/// counts the current failure ("1 network retries" on the first strike).
#[tokio::test(start_paused = true)]
async fn batch_timeout_liveness_exceeded_stalls_without_transition() {
    use oradaz::collect::dump::orchestration::events::CoordinatorEvent;

    let config = default_test_config();
    let stats = Arc::new(oradaz::utils::stats::Stats::new());
    stats.set_liveness_ceiling_secs(1);
    stats.note_progress("graph", "apiA");
    stats.note_progress("graph", "apiB");
    tokio::time::advance(Duration::from_secs(2)).await;

    // Closed port → instant connect error (works under paused time).
    let sub_a = make_sub_url("http://127.0.0.1:1", "apiA", "/v1.0/a");
    let sub_b = make_sub_url("http://127.0.0.1:1", "apiB", "/v1.0/b");
    let (response_tx, mut response_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (update_tx, mut update_rx) = mpsc::channel::<CoordinatorEvent>(8192);
    make_request_thread(
        make_batch_api_call("http://127.0.0.1:1", &[sub_a, sub_b]),
        Arc::clone(&stats),
        config,
        response_tx,
        update_tx,
    )
    .process()
    .await;

    for _ in 0..2 {
        match response_rx
            .try_recv()
            .expect("a LostData message per sub-URL")
        {
            ResponseMsg::LostData(err, _) => {
                assert_eq!(err.code, "NetworkStalled");
                assert!(
                    err.message.contains("(1 network retries,"),
                    "the terminal message must count the current failure: {}",
                    err.message
                );
            }
            _ => panic!("expected ResponseMsg::LostData(NetworkStalled)"),
        }
    }
    match update_rx.try_recv().expect("a RequestCompleted event") {
        CoordinatorEvent::RequestCompleted {
            new_urls, count, ..
        } => {
            assert_eq!(count, 1);
            assert!(new_urls.is_empty(), "zero re-emission past the ceiling");
        }
        _ => panic!("expected RequestCompleted"),
    }
    assert_eq!(fallback_transitions(&stats, "apiA"), 0, "zero transitions");
    assert_eq!(fallback_transitions(&stats, "apiB"), 0, "zero transitions");
}

/// A batch envelope that times out past the liveness ceiling reports zero
/// single-request timeouts in its `NetworkStalled` message: an envelope timeout
/// is never counted as a single-request timeout. Real time: the 1 s timeout
/// plus the backoff carries the bucket past its 1 s ceiling.
#[tokio::test]
async fn batch_envelope_timeout_stall_reports_no_single_timeouts() {
    use oradaz::collect::dump::orchestration::events::CoordinatorEvent;

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1.0/$batch"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(4)))
        .mount(&mock_server)
        .await;
    let mut config = default_test_config();
    config.http_timeout_seconds = Some(1);
    let stats = Arc::new(oradaz::utils::stats::Stats::new());
    stats.set_liveness_ceiling_secs(1);
    stats.note_progress("graph", "apiA");

    let sub = make_sub_url(&mock_server.uri(), "apiA", "/v1.0/a");
    let (response_tx, mut response_rx) = mpsc::channel::<ResponseMsg>(64);
    let (update_tx, _update_rx) = mpsc::channel::<CoordinatorEvent>(64);
    make_request_thread(
        make_batch_api_call(&mock_server.uri(), &[sub]),
        Arc::clone(&stats),
        config,
        response_tx,
        update_tx,
    )
    .process()
    .await;

    match response_rx.try_recv().expect("a LostData message") {
        ResponseMsg::LostData(err, _) => {
            assert_eq!(err.code, "NetworkStalled");
            assert!(
                err.message.contains("0 single-request timeouts"),
                "an envelope timeout is not a single-request timeout: {}",
                err.message
            );
            assert!(
                err.message.contains("last attempt timeout 1s"),
                "the envelope must have failed by timeout: {}",
                err.message
            );
        }
        _ => panic!("expected ResponseMsg::LostData(NetworkStalled)"),
    }
}

/// A forced-single URL abandoned as `NetworkStalled` hands its tracker to the
/// loss chokepoint: the `LostData` error carries the URL's own tracker.
#[tokio::test(start_paused = true)]
async fn forced_single_network_stalled_carries_tracker() {
    use oradaz::collect::dump::orchestration::events::CoordinatorEvent;
    use oradaz::utils::url::ForcedSingleTracker;

    let config = default_test_config();
    let stats = Arc::new(oradaz::utils::stats::Stats::new());
    stats.set_liveness_ceiling_secs(1);
    stats.note_progress("graph", "apiA");
    tokio::time::advance(Duration::from_secs(2)).await;

    // Closed port → instant connect error (works under paused time).
    let tracker = Arc::new(ForcedSingleTracker::new());
    let mut url = make_sub_url("http://127.0.0.1:1", "apiA", "/v1.0/a");
    url.network_retry_number = 2;
    url.force_single = true;
    url.forced_single_tracker = Some(Arc::clone(&tracker));
    let (response_tx, mut response_rx) = mpsc::channel::<ResponseMsg>(64);
    let (update_tx, _update_rx) = mpsc::channel::<CoordinatorEvent>(64);
    make_request_thread(
        ApiCall {
            id: 0,
            url,
            success_code: 200,
            value_pointer: "/value".to_string(),
            is_batch: false,
            batch_data: None,
        },
        Arc::clone(&stats),
        config,
        response_tx,
        update_tx,
    )
    .process()
    .await;

    match response_rx.try_recv().expect("a LostData message") {
        ResponseMsg::LostData(err, _) => {
            assert_eq!(err.code, "NetworkStalled");
            let carried = err
                .forced_single_tracker
                .as_ref()
                .expect("the abandonment must carry the tracker");
            assert!(
                Arc::ptr_eq(carried, &tracker),
                "the abandonment must carry the URL's own tracker"
            );
        }
        _ => panic!("expected ResponseMsg::LostData(NetworkStalled)"),
    }
}

/// Timeout escalation starts from the base timeout raised by the schema, not
/// from the service timeout: with a 1 s service timeout, a 2 s API hint and one
/// strike, the next single attempt waits 4 s, so an answer in 3 s arrives.
#[tokio::test]
async fn escalation_starts_from_schema_raised_base() {
    use oradaz::collect::dump::orchestration::events::CoordinatorEvent;
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1.0/slow"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "value": [{ "id": "x" }] }))
                .set_delay(Duration::from_secs(3)),
        )
        .mount(&mock_server)
        .await;
    let mut config = default_test_config();
    config.http_timeout_seconds = Some(1);
    config.http_timeout_max_seconds = Some(8);
    let stats = Arc::new(oradaz::utils::stats::Stats::new());
    let mut url = make_sub_url(&mock_server.uri(), "apiSlow", "/v1.0/slow");
    url.api_behavior = Arc::new(HashMap::from([(
        "http_timeout_seconds".to_string(),
        "2".to_string(),
    )]));
    url.timeout_strikes = 1;

    let (response_tx, mut response_rx) = mpsc::channel::<ResponseMsg>(64);
    let (update_tx, _update_rx) = mpsc::channel::<CoordinatorEvent>(64);
    make_request_thread(
        ApiCall {
            id: 0,
            url,
            success_code: 200,
            value_pointer: "/value".to_string(),
            is_batch: false,
            batch_data: None,
        },
        stats,
        config,
        response_tx,
        update_tx,
    )
    .process()
    .await;
    assert!(
        matches!(response_rx.try_recv(), Ok(ResponseMsg::ResponseData(_))),
        "the escalated attempt (2 s base doubled to 4 s) must receive the 3 s answer"
    );
}

// ─── deterministic end-to-end recovery ───────────────────────────────────────

/// Deterministic degradation scenario: the batch endpoint times out twice; the
/// sub-URLs switch to forced single after the second strike and every identity
/// is recovered through N single GETs — same payloads, no duplication, no third
/// batch POST, coordinator accounting back to zero, and the output finalized on
/// disk.
#[tokio::test]
async fn batch_timeout_recovery_end_to_end_writes_identities() {
    use oradaz::collect::dump::conditions::ConditionChecker;
    use oradaz::collect::dump::orchestration::events::CoordinatorEvent;
    use oradaz::collect::dump::response::{ResponseContext, ResponseThread};
    use oradaz::utils::metadata::TableMetadata;
    use oradaz::utils::url::{ApiCallItem, RetryLimits};
    use oradaz::utils::writer::actor::spawn_writer_task;
    use std::sync::Mutex;
    use tempfile::TempDir;
    use wiremock::matchers::any;

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1.0/$batch"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(4)))
        .mount(&mock_server)
        .await;
    for p in ["a", "b", "c"] {
        Mock::given(method("GET"))
            .and(path(format!("/v1.0/{p}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{ "id": format!("{p}-identity") }]
            })))
            .mount(&mock_server)
            .await;
    }
    Mock::given(any())
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_server)
        .await;

    let mut config = default_test_config();
    config.http_timeout_seconds = Some(1);
    config.output_files = Some(true);
    config.output_mla = Some(false);
    let stats = Arc::new(oradaz::utils::stats::Stats::new());
    let server = mock_server.uri();

    // Writer + response context so the recovered pages are actually written.
    let temp_dir = TempDir::new().unwrap();
    let (writer, writer_task) = spawn_writer_task(
        config.clone(),
        temp_dir.path().to_path_buf(),
        "test-run".to_string(),
    )
    .await
    .unwrap();
    let response_context = ResponseContext {
        writer: writer.clone(),
        metadata: Arc::new(Mutex::new(HashMap::<String, TableMetadata>::new())),
        tokens: Arc::new(DashMap::new()),
        condition_checker: Arc::new(ConditionChecker {
            client: OradazClient::new(&config).unwrap(),
            tenant_conditions: HashMap::new(),
            user_conditions: DashMap::new(),
            emergency_accounts_custom_attributes: String::from("Emergency.isEmergency"),
            org_url: String::new(),
            stats: Arc::clone(&stats),
            is_application_auth: false,
        }),
        ratelimit_manager: Arc::new(oradaz::collect::dump::ratelimit::RateLimitManager::default()),
        concurrency_controller: Arc::new(
            oradaz::collect::dump::concurrency::ConcurrencyController::default(),
        ),
        stats: Arc::clone(&stats),
        logs_date_filter_and: None,
        tenant_domains: Arc::new(dashmap::DashSet::new()),
    };

    let subs: Vec<OradazUrl> = ["apiA", "apiB", "apiC"]
        .iter()
        .zip(["/v1.0/a", "/v1.0/b", "/v1.0/c"])
        .map(|(api, p)| make_sub_url(&server, api, p))
        .collect();

    // Coordinator-counter accounting: +1 per dispatched item, −count per
    // RequestCompleted (whether emitted by the request or the response side).
    let mut counter: i64 = 0;

    // ── Two batch strikes ──
    let mut queue = subs.clone();
    for strike in 1..=2 {
        let (response_tx, _response_rx) = mpsc::channel::<ResponseMsg>(8192);
        let (update_tx, mut update_rx) = mpsc::channel::<CoordinatorEvent>(8192);
        counter += 1;
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
            CoordinatorEvent::RequestCompleted {
                new_urls, count, ..
            } => {
                counter -= count as i64;
                new_urls
            }
            _ => panic!("expected RequestCompleted after batch strike {strike}"),
        };
        assert_eq!(queue.len(), 3);
    }
    assert!(
        queue.iter().all(|u| u.force_single),
        "all URLs forced after strike 2"
    );

    // ── Replay: N single GETs, written through the response pipeline ──
    let limits = RetryLimits {
        retry: 5,
        rate_limit_retry: 50,
        rate_limit_max_wait_secs: 900,
    };
    while !queue.is_empty() {
        let items = ApiCall::from("graph", &mut queue, limits).unwrap();
        for item in items {
            let call = match item {
                ApiCallItem::ApiCall(call) => call,
                ApiCallItem::ApiCallError(err) => panic!("unexpected error item: {err:?}"),
            };
            assert!(!call.is_batch, "forced URLs must dispatch single");
            counter += 1;
            let (response_tx, mut response_rx) = mpsc::channel::<ResponseMsg>(8192);
            let (update_tx, mut update_rx) = mpsc::channel::<CoordinatorEvent>(8192);
            make_request_thread(
                *call,
                Arc::clone(&stats),
                config.clone(),
                response_tx,
                update_tx.clone(),
            )
            .process()
            .await;
            let data = match response_rx.try_recv().expect("a response message") {
                ResponseMsg::ResponseData(data) => data,
                _ => panic!("expected ResponseData for the single GET"),
            };
            ResponseThread::new(update_tx, response_context.clone(), data)
                .process()
                .await;
            match update_rx
                .try_recv()
                .expect("a RequestCompleted from the writer side")
            {
                CoordinatorEvent::RequestCompleted {
                    new_urls, count, ..
                } => {
                    counter -= count as i64;
                    assert!(new_urls.is_empty(), "a single page generates no new URLs");
                }
                _ => panic!("expected RequestCompleted"),
            }
        }
    }
    assert_eq!(counter, 0, "coordinator accounting must return to zero");

    // ── HTTP shape: two batch POSTs, one GET per identity, nothing else ──
    let requests = mock_server.received_requests().await.unwrap();
    let posts = requests
        .iter()
        .filter(|r| r.method.as_str() == "POST")
        .count();
    assert_eq!(posts, 2, "no third batch POST after the fallback");
    for p in ["/v1.0/a", "/v1.0/b", "/v1.0/c"] {
        let gets = requests
            .iter()
            .filter(|r| r.method.as_str() == "GET" && r.url.path() == p)
            .count();
        assert_eq!(gets, 1, "{p} must be fetched exactly once");
    }

    // ── Every transition closed as a success ──
    let json: serde_json::Value = serde_json::to_value(&*stats).unwrap();
    for api in ["apiA", "apiB", "apiC"] {
        let row = json["apis"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["api"] == api)
            .cloned()
            .unwrap_or_default();
        assert_eq!(row["batch_single_fallbacks"], 1, "{api}: one transition");
        assert_eq!(
            row["batch_single_fallback_successes"], 1,
            "{api}: recovered by its single GET"
        );
        assert_eq!(row["batch_single_fallback_lost"], 0, "{api}: no loss");
    }

    // ── Output finalized: each identity written exactly once ──
    // `finalize()` round-trips through the writer actor (FIFO), so every
    // earlier `write_file` has been flushed to disk once it returns. The actor
    // task itself is not awaited: `response_context` still holds a handle
    // clone, so the channel only closes when the test scope ends.
    writer
        .finalize()
        .await
        .expect("writer must finalize cleanly");
    let _ = &writer_task;
    let mut written = String::new();
    for entry in walkdir(temp_dir.path()) {
        written.push_str(&std::fs::read_to_string(&entry).unwrap_or_default());
    }
    for id in ["a-identity", "b-identity", "c-identity"] {
        assert_eq!(
            written.matches(id).count(),
            1,
            "{id} must be written exactly once (no loss, no duplication)"
        );
    }
}

/// Recursively lists the files under `dir` (test helper for the folder output).
fn walkdir(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        if let Ok(entries) = std::fs::read_dir(&d) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    files.push(p);
                }
            }
        }
    }
    files
}
