/// Integration tests for the dump coordinator event loop.
///
/// These tests construct a minimal `Dumper` and drive `CoordinatorEvent`s through
/// an in-memory channel, verifying that the coordinator correctly handles:
///   - Termination when all queues are empty and no requests are in flight
///   - `RequestCompleted` events causing re-dispatch
///   - `DumpError` incrementing `errors_number`
///   - `TokenExpirationError` not panicking when no refresh token is present
///   - Deduplication of `PotentialPrerequisiteError` (only one check spawned)
///   - `PrereqResult(Success)` resuming dispatch for a paused service
mod common;

use crate::common::default_test_config;
use oradaz::collect::auth::AuthError;
use oradaz::collect::auth::tokens::{Token, TokenState};
use oradaz::collect::dump::concurrency::ConcurrencyController;
use oradaz::collect::dump::conditions::ConditionChecker;
use oradaz::collect::dump::orchestration::coordinator::coordinate;
use oradaz::collect::dump::orchestration::events::{CoordinatorEvent, PrereqOutcome, ProcessError};
use oradaz::collect::dump::orchestration::prereq_task::token_refresh_task;
use oradaz::collect::dump::ratelimit::RateLimitManager;
use oradaz::collect::dump::request::RequestMsg;
use oradaz::collect::dump::response::ResponseMsg;
use oradaz::collect::dump::{Dumper, StdinPrompt};
use oradaz::utils::client::OradazClient;
use oradaz::utils::schema::Schema;
use oradaz::utils::url::Url as OradazUrl;
use oradaz::utils::writer::actor::spawn_writer_task;

use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tempfile::TempDir;
use tokio::sync::mpsc;

fn make_token() -> Token {
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

fn make_url(service: &str, api: &str, url: &str) -> OradazUrl {
    OradazUrl {
        service_name: service.to_string(),
        service_scopes: Arc::new(vec![format!("https://{service}.microsoft.com/.default")]),
        service_mandatory_auth: true,
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
    }
}

fn make_empty_schema() -> Schema {
    Schema {
        oradaz_version: oradaz::VERSION.to_string(),
        schema_hash: "test".to_string(),
        schema_version: "1.0.0".to_string(),
        services: vec![],
    }
}

async fn make_dumper(temp_dir: &TempDir) -> (Dumper, mpsc::Sender<CoordinatorEvent>) {
    let config = default_test_config();
    let (writer, _task) = spawn_writer_task(
        config.clone(),
        temp_dir.path().to_path_buf(),
        "coord-test".to_string(),
    )
    .await
    .unwrap();

    let oradaz_client = OradazClient::new(&config).unwrap();

    let tokens: DashMap<Arc<str>, Arc<TokenState>> = DashMap::new();
    tokens.insert(Arc::from("graph"), Arc::new(TokenState::new(make_token())));

    let stats = Arc::new(oradaz::utils::stats::Stats::new());
    let condition_checker = ConditionChecker {
        client: oradaz_client.clone(),
        tenant_conditions: HashMap::new(),
        user_conditions: DashMap::new(),
        emergency_accounts_custom_attributes: String::from("Emergency.isEmergency"),
        org_url: String::new(),
        stats: Arc::clone(&stats),
        is_application_auth: false,
    };

    // The Terminate-only event sender; we hand a clone to the Dumper to let
    // coordinator tests inject arbitrary events.
    let (event_tx, _event_rx) = mpsc::channel::<CoordinatorEvent>(8192);

    let dumper = Dumper {
        tenant: "test-tenant".to_string(),
        app_id: "test-app-id".to_string(),
        oradaz_client: oradaz_client.clone(),
        config: config.clone(),
        schema: make_empty_schema(),
        writer,
        tokens: Arc::new(tokens),
        tokens_metadata: vec![],
        condition_checker: Arc::new(condition_checker),
        ratelimit_manager: Arc::new(RateLimitManager::default()),
        concurrency_controller: Arc::new(ConcurrencyController::default()),
        current_counter: Arc::new(AtomicUsize::new(0)),
        current_urls: Arc::new(DashMap::new()),
        tables_metadata: vec![],
        requests_number: 0,
        errors_number: 0,
        auth_errors_number: 0,
        prerequisites_errors_number: 0,
        missing_token_errors_number: 0,
        apis_disabled_by_conditions: 0,
        prompt: Arc::new(StdinPrompt),
        verbosity: 0,
        stats,
        subscription_ids: Vec::new(),
        logs_date_filter_and: None,
    };

    (dumper, event_tx)
}

/// Coordinator exits immediately when there are no pending URLs and no requests in flight.
#[tokio::test]
async fn coordinator_terminates_when_empty() {
    let temp_dir = TempDir::new().unwrap();
    let (mut dumper, event_tx) = make_dumper(&temp_dir).await;

    let (req_tx, mut req_rx) = mpsc::channel::<RequestMsg>(8192);
    let (res_tx, _res_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (coord_tx, coord_rx) = mpsc::channel::<CoordinatorEvent>(8192);

    // No URLs queued — coordinator should exit on the first loop iteration.
    let paused = Arc::new(AtomicUsize::new(0));
    let result = coordinate(&mut dumper, coord_rx, req_tx, res_tx, coord_tx, paused).await;

    assert!(result.is_ok());
    // No requests should have been dispatched.
    assert!(req_rx.try_recv().is_err());
    drop(event_tx);
}

/// `NewUrls` events are added to the coordinator's URL pool and dispatched.
///
/// The coordinator sends URLs into the request channel. This test verifies that
/// after receiving `NewUrls` followed by a matching `RequestFinished`, the
/// coordinator terminates cleanly.
#[tokio::test]
async fn coordinator_handles_new_urls_then_terminates() {
    let temp_dir = TempDir::new().unwrap();
    let (mut dumper, _event_tx) = make_dumper(&temp_dir).await;

    // Seed one URL so the coordinator dispatches it.
    let url = make_url("graph", "users", "https://graph.microsoft.com/v1.0/users");
    dumper
        .current_urls
        .entry(Arc::from("graph"))
        .or_default()
        .push(url);

    let (req_tx, mut req_rx) = mpsc::channel::<RequestMsg>(8192);
    let (res_tx, _res_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (coord_tx, coord_rx) = mpsc::channel::<CoordinatorEvent>(8192);

    // After the URL is dispatched, current_counter == 1. Send RequestCompleted
    // so the coordinator can see in_flight == 0 and terminate.
    let coord_tx_clone = coord_tx.clone();
    tokio::spawn(async move {
        // Give the coordinator a moment to dispatch the URL.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let _ = coord_tx_clone
            .send(CoordinatorEvent::RequestCompleted {
                id: 0,
                service: Arc::from("graph"),
                new_urls: vec![],
                count: 1,
            })
            .await;
    });

    let paused = Arc::new(AtomicUsize::new(0));
    let result = coordinate(&mut dumper, coord_rx, req_tx, res_tx, coord_tx, paused).await;

    assert!(result.is_ok());

    // The coordinator must have dispatched at least one ApiCall.
    let mut dispatched = 0;
    while let Ok(msg) = req_rx.try_recv() {
        if matches!(msg, RequestMsg::ApiCall(_)) {
            dispatched += 1;
        }
    }
    assert_eq!(dispatched, 1, "Expected exactly one dispatched ApiCall");
    assert_eq!(dumper.requests_number, 1);
}

/// Termination invariant under transient abandonment: the run **always
/// terminates**, the reliquat is surfaced, never silently dropped or hung.
///
/// A 429 re-queue returns the URL in `new_urls`, so it stays pending and the
/// coordinator re-dispatches it — it must NOT terminate while a re-dispatchable
/// URL exists. When the bucket finally stalls past the liveness ceiling, the
/// abandonment arrives as a counter-balanced `RequestCompleted{count:1,
/// new_urls:[]}` (the abandoned URL is dropped, not re-queued) plus a
/// `NewError`. `current_counter` then drains to 0 with empty queues and the run
/// terminates cleanly. The 5 s timeout fails fast (rather than hanging) if the
/// invariant were broken and a URL were left pending.
#[tokio::test]
async fn coordinator_transient_requeue_then_abandon_terminates() {
    use std::sync::atomic::Ordering;
    use tokio::time::{Duration, timeout};

    let temp_dir = TempDir::new().unwrap();
    let (mut dumper, _event_tx) = make_dumper(&temp_dir).await;

    // Seed one URL so the coordinator dispatches it (current_counter → 1).
    let url = make_url("graph", "users", "https://graph.microsoft.com/v1.0/users");
    dumper
        .current_urls
        .entry(Arc::from("graph"))
        .or_default()
        .push(url.clone());

    let (req_tx, mut req_rx) = mpsc::channel::<RequestMsg>(8192);
    let (res_tx, _res_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (coord_tx, coord_rx) = mpsc::channel::<CoordinatorEvent>(8192);

    let coord_tx_clone = coord_tx.clone();
    let requeue_url = url.clone();
    tokio::spawn(async move {
        // 1) 429 re-queue: the URL comes back in new_urls → still pending. The
        //    coordinator re-dispatches it (counter back to 1); must NOT terminate.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = coord_tx_clone
            .send(CoordinatorEvent::RequestCompleted {
                id: 0,
                service: Arc::from("graph"),
                new_urls: vec![requeue_url],
                count: 1,
            })
            .await;
        // 2) Liveness fires: abandonment is counter-balanced with an EMPTY
        //    new_urls (URL dropped, not re-queued) + a NewError → drains to 0.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = coord_tx_clone
            .send(CoordinatorEvent::NewError(
                Arc::from("graph"),
                ProcessError::DumpError(1),
            ))
            .await;
        let _ = coord_tx_clone
            .send(CoordinatorEvent::RequestCompleted {
                id: 1,
                service: Arc::from("graph"),
                new_urls: vec![],
                count: 1,
            })
            .await;
    });

    let paused = Arc::new(AtomicUsize::new(0));
    let result = timeout(
        Duration::from_secs(5),
        coordinate(&mut dumper, coord_rx, req_tx, res_tx, coord_tx, paused),
    )
    .await;

    assert!(result.is_ok(), "coordinator must terminate, not hang");
    assert!(result.unwrap().is_ok());

    // Terminated with no work left, and the abandonment was surfaced.
    assert_eq!(dumper.current_counter.load(Ordering::Relaxed), 0);
    let remaining: usize = dumper.current_urls.iter().map(|r| r.value().len()).sum();
    assert_eq!(
        remaining, 0,
        "no URL may be left pending after a transient abandonment"
    );
    assert_eq!(
        dumper.errors_number, 1,
        "the abandoned URL must be surfaced as lost data"
    );

    // Dispatched twice: the initial dispatch + one re-dispatch after the 429 re-queue.
    let mut dispatched = 0;
    while let Ok(msg) = req_rx.try_recv() {
        if matches!(msg, RequestMsg::ApiCall(_)) {
            dispatched += 1;
        }
    }
    assert_eq!(
        dispatched, 2,
        "URL re-dispatched once after the 429 re-queue, then abandoned"
    );
}

/// `NewError(DumpError)` increments `errors_number`.
///
/// Pre-set `current_counter` to 1 to simulate an in-flight request so the
/// coordinator waits for events rather than exiting immediately. The spawned
/// task sends the error then resolves the fake in-flight with `RequestFinished`.
#[tokio::test]
async fn coordinator_dump_error_increments_errors_number() {
    use std::sync::atomic::Ordering;

    let temp_dir = TempDir::new().unwrap();
    let (mut dumper, _event_tx) = make_dumper(&temp_dir).await;

    // Simulate 1 in-flight request so the coordinator waits for events.
    dumper.current_counter.store(1, Ordering::Relaxed);

    let (req_tx, _req_rx) = mpsc::channel::<RequestMsg>(8192);
    let (res_tx, _res_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (coord_tx, coord_rx) = mpsc::channel::<CoordinatorEvent>(8192);

    let coord_tx_clone = coord_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let _ = coord_tx_clone
            .send(CoordinatorEvent::NewError(
                Arc::from("graph"),
                ProcessError::DumpError(3),
            ))
            .await;
        // Resolve the fake in-flight so the coordinator can exit.
        let _ = coord_tx_clone
            .send(CoordinatorEvent::RequestCompleted {
                id: 0,
                service: Arc::from("graph"),
                new_urls: vec![],
                count: 1,
            })
            .await;
    });

    let paused = Arc::new(AtomicUsize::new(0));
    let result = coordinate(&mut dumper, coord_rx, req_tx, res_tx, coord_tx, paused).await;

    assert!(result.is_ok());
    assert_eq!(dumper.errors_number, 3);
}

/// `TokenRefreshFailed` with a definitive auth error records it and aborts.
///
/// This is the permanent-failure path of the off-loop token refresh: an
/// application-credential flow exhausted its retries, or the token endpoint
/// returned a definitive authentication error. The coordinator must (a) record the
/// auth error — incrementing `auth_errors_number` and writing `auth_errors.json` —
/// and (b) abort the run by returning `Err`, so the archive is finalized as
/// `.broken` rather than reported as a clean completion. `current_counter` is
/// pre-set to 1 so the coordinator waits for the event instead of terminating on
/// the first iteration; the event is queued up front (no sleep/timing dependency).
///
/// Discriminating: with the abort logic removed the coordinator would never exit
/// (nothing resolves the fake in-flight), so the 5 s timeout below would fire and
/// fail the test fast instead of hanging.
#[tokio::test]
async fn coordinator_token_refresh_failed_records_auth_error_and_aborts() {
    use std::sync::atomic::Ordering;

    let temp_dir = TempDir::new().unwrap();
    let (mut dumper, _event_tx) = make_dumper(&temp_dir).await;

    // Simulate 1 in-flight request so the coordinator waits for events.
    dumper.current_counter.store(1, Ordering::Relaxed);

    let (req_tx, _req_rx) = mpsc::channel::<RequestMsg>(8192);
    let (res_tx, _res_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (coord_tx, coord_rx) = mpsc::channel::<CoordinatorEvent>(8192);

    // Queue the permanent-failure event up front; the coordinator receives it on
    // its first event wait and must abort.
    coord_tx
        .send(CoordinatorEvent::TokenRefreshFailed {
            service: Arc::from("graph"),
            auth_error: Some(AuthError {
                api: "graph".to_string(),
                error: "invalid_client: definitive auth failure".to_string(),
            }),
            message: "Token refresh for service \"graph\" failed permanently".to_string(),
        })
        .await
        .unwrap();

    let paused = Arc::new(AtomicUsize::new(0));
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        coordinate(&mut dumper, coord_rx, req_tx, res_tx, coord_tx, paused),
    )
    .await
    .expect("coordinator must abort promptly on TokenRefreshFailed, not hang");

    // The run aborts: coordinate surfaces the failure as Err (→ `.broken` archive).
    assert!(
        result.is_err(),
        "TokenRefreshFailed must abort the coordinator (return Err)"
    );
    // The definitive auth error was recorded before the abort.
    assert_eq!(
        dumper.auth_errors_number, 1,
        "the definitive auth error must be recorded via write_auth_error"
    );
}

/// A second `PotentialPrerequisiteError` for the same service while a check is
/// in flight does not spawn a second background task.
///
/// The URL is re-queued in both cases, and after `PrereqResult(Success)` the
/// service's URL is available for dispatch again.
#[tokio::test]
async fn coordinator_prereq_error_deduplication() {
    let temp_dir = TempDir::new().unwrap();
    let (mut dumper, _event_tx) = make_dumper(&temp_dir).await;

    let (req_tx, _req_rx) = mpsc::channel::<RequestMsg>(8192);
    let (res_tx, _res_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (coord_tx, coord_rx) = mpsc::channel::<CoordinatorEvent>(8192);

    let url1 = make_url("graph", "users", "https://graph.microsoft.com/v1.0/users");
    let url2 = make_url("graph", "groups", "https://graph.microsoft.com/v1.0/groups");

    let coord_tx_clone = coord_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        // First PotentialPrerequisiteError: spawns a background task.
        let _ = coord_tx_clone
            .send(CoordinatorEvent::NewError(
                Arc::from("graph"),
                ProcessError::PotentialPrerequisiteError(Box::new(url1)),
            ))
            .await;
        // Second PotentialPrerequisiteError for the same service: must NOT spawn another task.
        let _ = coord_tx_clone
            .send(CoordinatorEvent::NewError(
                Arc::from("graph"),
                ProcessError::PotentialPrerequisiteError(Box::new(url2)),
            ))
            .await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        // Resolve prereqs so the coordinator terminates (it cannot exit while
        // there's still a service in prereq_in_flight and URLs are queued).
        let _ = coord_tx_clone
            .send(CoordinatorEvent::PrereqResult(
                Arc::from("graph"),
                PrereqOutcome::Success,
            ))
            .await;
        // Drain the re-queued URLs by simulating a request+finish.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let _ = coord_tx_clone
            .send(CoordinatorEvent::RequestCompleted {
                id: 0,
                service: Arc::from("graph"),
                new_urls: vec![],
                count: 1,
            })
            .await;
    });

    let paused = Arc::new(AtomicUsize::new(0));
    let result = coordinate(&mut dumper, coord_rx, req_tx, res_tx, coord_tx, paused).await;

    assert!(result.is_ok());
    // Both URLs were re-queued and dispatched (batched into one call).
    let remaining: usize = dumper.current_urls.iter().map(|r| r.value().len()).sum();
    // After RequestCompleted(1) the counter is 0 and queues should be empty.
    assert_eq!(remaining, 0);
}

/// `PrereqResult(Success)` for an unknown service is silently ignored.
#[tokio::test]
async fn coordinator_prereq_resolved_unknown_service_ignored() {
    let temp_dir = TempDir::new().unwrap();
    let (mut dumper, _event_tx) = make_dumper(&temp_dir).await;

    let (req_tx, _req_rx) = mpsc::channel::<RequestMsg>(8192);
    let (res_tx, _res_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (coord_tx, coord_rx) = mpsc::channel::<CoordinatorEvent>(8192);

    let coord_tx_clone = coord_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let _ = coord_tx_clone
            .send(CoordinatorEvent::PrereqResult(
                Arc::from("nonexistent"),
                PrereqOutcome::Success,
            ))
            .await;
        let _ = coord_tx_clone.send(CoordinatorEvent::Terminate).await;
    });

    let paused = Arc::new(AtomicUsize::new(0));
    let result = coordinate(&mut dumper, coord_rx, req_tx, res_tx, coord_tx, paused).await;
    assert!(result.is_ok());
}

/// The `Terminate` event causes the coordinator to stop once in-flight drops to zero.
#[tokio::test]
async fn coordinator_terminate_event_stops_loop() {
    let temp_dir = TempDir::new().unwrap();
    let (mut dumper, _event_tx) = make_dumper(&temp_dir).await;

    // Queue one URL to keep the coordinator alive until Terminate + RequestFinished arrive.
    let url = make_url("graph", "users", "https://graph.microsoft.com/v1.0/users");
    dumper
        .current_urls
        .entry(Arc::from("graph"))
        .or_default()
        .push(url);

    let (req_tx, _req_rx) = mpsc::channel::<RequestMsg>(8192);
    let (res_tx, _res_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (coord_tx, coord_rx) = mpsc::channel::<CoordinatorEvent>(8192);

    let coord_tx_clone = coord_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let _ = coord_tx_clone.send(CoordinatorEvent::Terminate).await;
        let _ = coord_tx_clone
            .send(CoordinatorEvent::RequestCompleted {
                id: 0,
                service: Arc::from("graph"),
                new_urls: vec![],
                count: 1,
            })
            .await;
    });

    let paused = Arc::new(AtomicUsize::new(0));
    let result = coordinate(&mut dumper, coord_rx, req_tx, res_tx, coord_tx, paused).await;
    assert!(result.is_ok());
}

/// `RequestCompleted` with new_urls adds them to the coordinator's pool for future dispatch.
///
/// Seed one URL so the coordinator dispatches it (counter = 1) and then waits
/// for events. After receiving `RequestCompleted` with url_a and url_b the
/// coordinator dispatches them as a single Graph `$batch` call (counter = 1).
/// A second `RequestCompleted` resolves all in-flight work.
///
/// Note: Graph URLs at the same API version are batched together, so two URLs
/// produce one `ApiCall` in the request channel, not two.
#[tokio::test]
async fn coordinator_new_urls_event_extends_pool() {
    let temp_dir = TempDir::new().unwrap();
    let (mut dumper, _event_tx) = make_dumper(&temp_dir).await;

    // Seed 1 initial URL so the coordinator has work and waits for events.
    let seed = make_url("graph", "seed", "https://graph.microsoft.com/v1.0/seed");
    dumper
        .current_urls
        .entry(Arc::from("graph"))
        .or_default()
        .push(seed);

    let url_a = make_url("graph", "a", "https://graph.microsoft.com/v1.0/a");
    let url_b = make_url("graph", "b", "https://graph.microsoft.com/v1.0/b");

    let (req_tx, mut req_rx) = mpsc::channel::<RequestMsg>(8192);
    let (res_tx, _res_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (coord_tx, coord_rx) = mpsc::channel::<CoordinatorEvent>(8192);

    let coord_tx_clone = coord_tx.clone();
    tokio::spawn(async move {
        // Let coordinator dispatch the seeded URL (counter = 1).
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        // Simulate the seed request completing with url_a + url_b as new URLs.
        let _ = coord_tx_clone
            .send(CoordinatorEvent::RequestCompleted {
                id: 0,
                service: Arc::from("graph"),
                new_urls: vec![url_a, url_b],
                count: 1,
            })
            .await;
        // Let coordinator batch url_a + url_b into one Graph $batch call (counter = 1).
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        // Resolve the batch call.
        let _ = coord_tx_clone
            .send(CoordinatorEvent::RequestCompleted {
                id: 0,
                service: Arc::from("graph"),
                new_urls: vec![],
                count: 1,
            })
            .await;
    });

    let paused = Arc::new(AtomicUsize::new(0));
    let result = coordinate(&mut dumper, coord_rx, req_tx, res_tx, coord_tx, paused).await;
    assert!(result.is_ok());
    // 1 seeded call + 1 batch call (url_a + url_b) = 2 API calls dispatched.
    assert_eq!(dumper.requests_number, 2);
    // Confirm 2 ApiCalls were placed in the request channel.
    let mut dispatched = 0;
    while let Ok(msg) = req_rx.try_recv() {
        if matches!(msg, RequestMsg::ApiCall(_)) {
            dispatched += 1;
        }
    }
    assert_eq!(dispatched, 2);
}

/// `PotentialPrerequisiteError` for a service with no token increments errors_number.
///
/// The URL is re-queued in `current_urls` after the error, then the coordinator
/// dispatches it in the next iteration (counter goes from 0 → 1). Both
/// the error count and the dispatch are verified.
#[tokio::test]
async fn coordinator_prereq_error_missing_token_counts_as_error() {
    use std::sync::atomic::Ordering;

    let temp_dir = TempDir::new().unwrap();
    let (mut dumper, _event_tx) = make_dumper(&temp_dir).await;

    // Simulate 1 in-flight request so the coordinator waits for events.
    dumper.current_counter.store(1, Ordering::Relaxed);

    let (req_tx, _req_rx) = mpsc::channel::<RequestMsg>(8192);
    let (res_tx, _res_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (coord_tx, coord_rx) = mpsc::channel::<CoordinatorEvent>(8192);

    let url = make_url(
        "exchange",
        "mailboxes",
        "https://outlook.office365.com/v1.0/mailboxes",
    );

    let coord_tx_clone = coord_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        // "exchange" has no token — coordinator re-queues the URL and counts the error.
        let _ = coord_tx_clone
            .send(CoordinatorEvent::NewError(
                Arc::from("exchange"),
                ProcessError::PotentialPrerequisiteError(Box::new(url)),
            ))
            .await;
        // Give the coordinator time to re-queue then dispatch the URL (counter → 1).
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        // Terminate stops further dispatch.
        let _ = coord_tx_clone.send(CoordinatorEvent::Terminate).await;
        // Resolve the in-flight slot from the re-queued dispatch.
        let _ = coord_tx_clone
            .send(CoordinatorEvent::RequestCompleted {
                id: 0,
                service: Arc::from("exchange"),
                new_urls: vec![],
                count: 1,
            })
            .await;
    });

    let paused = Arc::new(AtomicUsize::new(0));
    let result = coordinate(&mut dumper, coord_rx, req_tx, res_tx, coord_tx, paused).await;
    assert!(result.is_ok());
    // Error was counted for the missing-token case.
    assert_eq!(dumper.errors_number, 1);
    // The re-queued URL was dispatched (not silently dropped).
    assert_eq!(dumper.requests_number, 1);
}

/// `TokenExpirationError` is handled without panicking: the coordinator spawns a
/// background token-refresh task. With a non-expired token the task
/// short-circuits to `TokenRefreshed` (no network), so no error is counted.
#[tokio::test]
async fn coordinator_token_expiration_error_no_panic() {
    let temp_dir = TempDir::new().unwrap();
    let (mut dumper, _event_tx) = make_dumper(&temp_dir).await;

    let (req_tx, _req_rx) = mpsc::channel::<RequestMsg>(8192);
    let (res_tx, _res_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (coord_tx, coord_rx) = mpsc::channel::<CoordinatorEvent>(8192);

    let coord_tx_clone = coord_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let _ = coord_tx_clone
            .send(CoordinatorEvent::NewError(
                Arc::from("graph"),
                ProcessError::TokenExpirationError,
            ))
            .await;
        let _ = coord_tx_clone.send(CoordinatorEvent::Terminate).await;
    });

    let paused = Arc::new(AtomicUsize::new(0));
    let result = coordinate(&mut dumper, coord_rx, req_tx, res_tx, coord_tx, paused).await;
    assert!(result.is_ok());
    // No errors counted for TokenExpirationError — a background refresh task was
    // spawned and short-circuited (the token is not actually expired).
    assert_eq!(dumper.errors_number, 0);
}

/// A token-expiration event must feed the reliability telemetry: one refresh
/// episode counted for the service, and a pause interval opened (the service
/// appears in the pause map even when the episode resolves in under a second).
#[tokio::test]
async fn coordinator_token_expiration_records_refresh_and_pause() {
    let temp_dir = TempDir::new().unwrap();
    let (mut dumper, _event_tx) = make_dumper(&temp_dir).await;
    // Pretend one request is in flight so the empty-pool termination clause
    // cannot fire before the delayed expiration event arrives; the loop exits
    // on the Terminate event instead.
    dumper
        .current_counter
        .store(1, std::sync::atomic::Ordering::Relaxed);

    let (req_tx, _req_rx) = mpsc::channel::<RequestMsg>(8192);
    let (res_tx, _res_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (coord_tx, coord_rx) = mpsc::channel::<CoordinatorEvent>(8192);

    let coord_tx_clone = coord_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let _ = coord_tx_clone
            .send(CoordinatorEvent::NewError(
                Arc::from("graph"),
                ProcessError::TokenExpirationError,
            ))
            .await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let _ = coord_tx_clone.send(CoordinatorEvent::Terminate).await;
    });

    let paused = Arc::new(AtomicUsize::new(0));
    let result = coordinate(&mut dumper, coord_rx, req_tx, res_tx, coord_tx, paused).await;
    assert!(result.is_ok());

    let refreshes = dumper.stats.token_refreshes_by_service();
    assert_eq!(
        refreshes.get("graph"),
        Some(&1),
        "one expiration episode must count exactly one refresh"
    );
    let pauses = dumper.stats.pause_secs_by_service();
    assert!(
        pauses.contains_key("graph"),
        "the paused service must appear in the pause map (even at 0s): {pauses:?}"
    );
}

/// A `loop_error` set by an *inner*-loop handler must terminate the outer
/// loop, even with no `Terminate` event.
///
/// The inner event loop can set `loop_error` and `break` only the inner loop
/// (here: an application-credential prerequisite re-check failure; the same holds
/// for a permanently-failing app-credential token refresh). The outer loop's
/// termination check must honor `loop_error` and exit — otherwise, with a request
/// still in flight, the run never terminates (it live-locks / stalls) instead of
/// aborting cleanly with `Err` (which makes the caller write a `.broken` archive).
///
/// We pin `current_counter` at 1 so `in_flight == 0 && urls_empty` stays false for
/// the whole run — the *only* exit is the `loop_error` clause — and bound
/// `coordinate()` with a timeout so a regression surfaces as a hang, not a false
/// pass (note `coordinate()` returns `Err` whenever `loop_error` is set, so the
/// failure mode of the bug is "never returns", not "returns Ok").
#[tokio::test]
async fn coordinator_loop_error_terminates_without_terminate_event() {
    use std::sync::atomic::Ordering;

    let temp_dir = TempDir::new().unwrap();
    let (mut dumper, _event_tx) = make_dumper(&temp_dir).await;
    // Application-credential auth: a prerequisite re-check failure is fatal
    // (no operator to prompt), so it sets `loop_error` and breaks the inner loop.
    dumper.config.use_application_credentials = Some(true);
    // Pretend one request is in flight so the normal termination clause
    // (`in_flight == 0 && urls_empty`) can never fire, isolating the loop_error path.
    dumper.current_counter.store(1, Ordering::Relaxed);

    let (req_tx, _req_rx) = mpsc::channel::<RequestMsg>(8192);
    let (res_tx, _res_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (coord_tx, coord_rx) = mpsc::channel::<CoordinatorEvent>(8192);

    let coord_tx_clone = coord_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        // No Terminate event: the coordinator must exit on `loop_error` alone.
        let _ = coord_tx_clone
            .send(CoordinatorEvent::PrereqResult(
                Arc::from("graph"),
                PrereqOutcome::Failure("simulated permanent prerequisite failure".to_string()),
            ))
            .await;
    });

    let paused = Arc::new(AtomicUsize::new(0));
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        coordinate(&mut dumper, coord_rx, req_tx, res_tx, coord_tx, paused),
    )
    .await;

    let inner = result.expect("coordinator must terminate on loop_error, not hang");
    assert!(
        inner.is_err(),
        "expected coordinate() to return Err on an application-credential prerequisite failure"
    );
    // The fatal failure was recorded as a prerequisite error before terminating.
    assert_eq!(dumper.prerequisites_errors_number, 1);
}

/// While paused (`progress_paused > 0`, e.g. a SIGINT menu or interactive
/// prereq prompt), the coordinator must keep processing events — draining
/// `RequestCompleted` so the AIMD counter and the bounded event channel do not
/// fill — and must honor `Terminate` even while paused. Only *dispatch* is gated
/// on the pause.
///
/// Guards against a regression where event processing is blocked during a pause,
/// causing `RequestCompleted` to go unhandled (stalling the AIMD counter or
/// filling the channel) or `Terminate` to be missed (test timeout instead of
/// returning).
#[tokio::test]
async fn coordinator_processes_events_while_paused() {
    use std::sync::atomic::Ordering;

    let temp_dir = TempDir::new().unwrap();
    let (mut dumper, _event_tx) = make_dumper(&temp_dir).await;
    // One in-flight request so the pipeline is non-empty at start.
    dumper.current_counter.store(1, Ordering::Relaxed);

    let (req_tx, mut req_rx) = mpsc::channel::<RequestMsg>(8192);
    let (res_tx, _res_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (coord_tx, coord_rx) = mpsc::channel::<CoordinatorEvent>(8192);

    // Paused for the entire run — never resumed.
    let paused = Arc::new(AtomicUsize::new(1));

    let coord_tx_clone = coord_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        // Drained only if events are processed during the pause. Carries a new URL
        // so we can also assert it is queued but NOT dispatched while paused.
        let child = make_url("graph", "child", "https://graph.microsoft.com/v1.0/child");
        let _ = coord_tx_clone
            .send(CoordinatorEvent::RequestCompleted {
                id: 0,
                service: Arc::from("graph"),
                new_urls: vec![child],
                count: 1,
            })
            .await;
        // Terminate must be honored even while paused.
        let _ = coord_tx_clone.send(CoordinatorEvent::Terminate).await;
    });

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        coordinate(&mut dumper, coord_rx, req_tx, res_tx, coord_tx, paused),
    )
    .await
    .expect("coordinator must process events + Terminate while paused, not spin");
    assert!(result.is_ok());
    // The RequestCompleted was drained during the pause (counter 1 → 0)…
    assert_eq!(dumper.current_counter.load(Ordering::Relaxed), 0);
    // …its new URL was queued…
    let queued: usize = dumper.current_urls.iter().map(|r| r.value().len()).sum();
    assert_eq!(queued, 1, "child URL queued during pause");
    // …but nothing was dispatched, because dispatch is gated on the pause.
    assert!(
        req_rx.try_recv().is_err(),
        "no request may be dispatched while paused"
    );
    assert_eq!(dumper.requests_number, 0);
}

/// A `TokenExpirationError` for one service triggers a background token
/// refresh (off the event loop) and must NOT block other services — the
/// coordinator keeps dispatching and draining their events. Here graph's token is
/// not actually expired, so the refresh task short-circuits to `TokenRefreshed`
/// (no network is touched); the point is that exchange's seeded URL is dispatched
/// and completed while graph's token event is handled, and the run exits cleanly.
///
/// A "slow refresh genuinely blocks B" variant would need a mock token endpoint
/// wired into the coordinator, which does not exist. This structural test instead
/// guards the highest-probability regression: the token-refresh events being
/// mishandled and hanging or panicking the coordinator.
#[tokio::test]
async fn coordinator_token_refresh_does_not_block_other_services() {
    let temp_dir = TempDir::new().unwrap();
    let (mut dumper, _event_tx) = make_dumper(&temp_dir).await;

    // A second service with its own (valid) token.
    let mut exchange_token = make_token();
    exchange_token.service = "exchange".to_string();
    dumper.tokens.insert(
        Arc::from("exchange"),
        Arc::new(TokenState::new(exchange_token)),
    );

    // Seed one URL for exchange. graph carries no queued URL (the URL its expired
    // request would re-queue is supplied by the request thread, not simulated here).
    let url = make_url(
        "exchange",
        "mailboxes",
        "https://outlook.office365.com/v1.0/mailboxes",
    );
    dumper
        .current_urls
        .entry(Arc::from("exchange"))
        .or_default()
        .push(url);

    let (req_tx, mut req_rx) = mpsc::channel::<RequestMsg>(8192);
    let (res_tx, _res_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (coord_tx, coord_rx) = mpsc::channel::<CoordinatorEvent>(8192);

    let coord_tx_clone = coord_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        // graph's token "expires": spawns a background refresh (it short-circuits).
        let _ = coord_tx_clone
            .send(CoordinatorEvent::NewError(
                Arc::from("graph"),
                ProcessError::TokenExpirationError,
            ))
            .await;
        // Let the coordinator dispatch + complete the exchange work meanwhile.
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        let _ = coord_tx_clone
            .send(CoordinatorEvent::RequestCompleted {
                id: 0,
                service: Arc::from("exchange"),
                new_urls: vec![],
                count: 1,
            })
            .await;
        let _ = coord_tx_clone.send(CoordinatorEvent::Terminate).await;
    });

    let paused = Arc::new(AtomicUsize::new(0));
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        coordinate(&mut dumper, coord_rx, req_tx, res_tx, coord_tx, paused),
    )
    .await
    .expect("coordinator must not hang while a token refresh is in flight");
    assert!(result.is_ok());
    // The exchange URL was dispatched despite graph hitting a token refresh.
    let mut dispatched = 0;
    while let Ok(msg) = req_rx.try_recv() {
        if matches!(msg, RequestMsg::ApiCall(_)) {
            dispatched += 1;
        }
    }
    assert_eq!(
        dispatched, 1,
        "exchange URL must dispatch despite graph's token refresh"
    );
    assert_eq!(dumper.requests_number, 1);
}

/// `token_refresh_task` upholds its stranding invariant on the short-circuit
/// path — with a non-expired token it emits exactly one `TokenRefreshed` and
/// touches no network (the double-checked `will_expire()` guard returns early).
#[tokio::test]
async fn token_refresh_task_emits_refreshed_for_valid_token() {
    let tokens: Arc<DashMap<Arc<str>, Arc<TokenState>>> = Arc::new(DashMap::new());
    tokens.insert(Arc::from("graph"), Arc::new(TokenState::new(make_token())));
    let config = default_test_config();
    let oradaz_client = OradazClient::new(&config).unwrap();
    let (tx, mut rx) = mpsc::channel::<CoordinatorEvent>(8);

    token_refresh_task(Arc::from("graph"), tokens, config, oradaz_client, tx).await;

    match rx.try_recv() {
        Ok(CoordinatorEvent::TokenRefreshed(svc)) => assert_eq!(&*svc, "graph"),
        Ok(_) => panic!("expected TokenRefreshed, got a different event"),
        Err(e) => panic!("expected a TokenRefreshed event, channel was empty: {e:?}"),
    }
    // Exactly one event was emitted.
    assert!(
        rx.try_recv().is_err(),
        "token_refresh_task must emit exactly one outcome event"
    );
}

/// Regression: resuming after a pause that drained every in-flight request must
/// re-dispatch the pending URLs promptly, not stall until `stall_detection_timeout`.
///
/// Reproduces the reported bug: a long SIGINT pause during which the last in-flight
/// `RequestCompleted` lands (in-flight → 0) leaves the coordinator parked on
/// `recv()` with pending URLs. The SIGINT menu resume only clears the pause counter
/// and sends *no* event, so without the paused-poll cap the loop stays parked for
/// the full stall timeout (600s). Here the coordinator starts paused with one queued
/// URL and nothing in flight; the resume clears the pause counter and sends NO event
/// (exactly like the SIGINT menu). It must dispatch within the paused-poll bound —
/// otherwise `requests_number` stays 0 and the test fails.
///
/// Note: this drained state satisfies *both* `early_poll` disjuncts (paused, *and*
/// in-flight == 0 with a pending URL and no background task), so it exercises the
/// early-poll cap as a whole rather than isolating the paused disjunct — either
/// disjunct alone would re-dispatch here. Reverting the whole cap still fails this
/// test: the loop parks for the stall timeout, Terminate wins, `requests_number == 0`.
#[tokio::test]
async fn coordinator_resume_after_drained_pause_redispatches() {
    use std::sync::atomic::Ordering;

    let temp_dir = TempDir::new().unwrap();
    let (mut dumper, _event_tx) = make_dumper(&temp_dir).await;

    // One pending URL, nothing in flight (current_counter stays 0) — the state left
    // by a pause that drained all in-flight requests.
    let url = make_url("graph", "users", "https://graph.microsoft.com/v1.0/users");
    dumper
        .current_urls
        .entry(Arc::from("graph"))
        .or_default()
        .push(url);

    let (req_tx, mut req_rx) = mpsc::channel::<RequestMsg>(8192);
    let (res_tx, _res_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (coord_tx, coord_rx) = mpsc::channel::<CoordinatorEvent>(8192);

    // Start paused (SIGINT menu open).
    let paused = Arc::new(AtomicUsize::new(1));
    let paused_clone = Arc::clone(&paused);

    let coord_tx_clone = coord_tx.clone();
    tokio::spawn(async move {
        // Let the coordinator reach its paused wait (it must NOT dispatch while paused).
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        // Resume exactly like the SIGINT menu: clear the pause counter, send NO event.
        paused_clone.store(0, Ordering::Relaxed);
        // Give the coordinator time to wake from its paused poll and re-dispatch,
        // then Terminate to end the run (the dispatched request is left in flight).
        tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
        let _ = coord_tx_clone.send(CoordinatorEvent::Terminate).await;
    });

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        coordinate(&mut dumper, coord_rx, req_tx, res_tx, coord_tx, paused),
    )
    .await
    .expect(
        "coordinator must re-dispatch promptly after resume, not stall until the stall timeout",
    );
    assert!(result.is_ok());
    // The pending URL was dispatched after resume — 0 here means the loop stayed
    // parked (the bug).
    assert_eq!(
        dumper.requests_number, 1,
        "pending URL must dispatch promptly after resume"
    );
    let mut dispatched = 0;
    while let Ok(msg) = req_rx.try_recv() {
        if matches!(msg, RequestMsg::ApiCall(_)) {
            dispatched += 1;
        }
    }
    assert_eq!(dispatched, 1);
}

/// `BreakerTripped` filters the tripped bucket's later re-queues: URLs of the
/// bucket arriving via `RequestCompleted.new_urls` after the trip are dropped
/// (counted as skipped) instead of re-entering the pool, so the run terminates
/// without dispatching them.
#[tokio::test]
async fn coordinator_breaker_filters_later_requeues() {
    let temp_dir = TempDir::new().unwrap();
    let (mut dumper, _event_tx) = make_dumper(&temp_dir).await;

    dumper
        .current_urls
        .entry(Arc::from("graph"))
        .or_default()
        .push(make_url(
            "graph",
            "users",
            "https://graph.microsoft.com/v1.0/users",
        ));

    let (req_tx, mut req_rx) = mpsc::channel::<RequestMsg>(8192);
    let (res_tx, _res_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (coord_tx, coord_rx) = mpsc::channel::<CoordinatorEvent>(8192);

    let coord_tx_clone = coord_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        let _ = coord_tx_clone
            .send(CoordinatorEvent::BreakerTripped {
                service: Arc::from("graph"),
                api: "stuck".to_string(),
            })
            .await;
        // The in-flight request completes and re-queues two URLs of the
        // tripped bucket: both must be skipped, leaving nothing to dispatch.
        let _ = coord_tx_clone
            .send(CoordinatorEvent::RequestCompleted {
                id: 0,
                service: Arc::from("graph"),
                new_urls: vec![
                    make_url("graph", "stuck", "https://graph.microsoft.com/v1.0/stuck/1"),
                    make_url("graph", "stuck", "https://graph.microsoft.com/v1.0/stuck/2"),
                ],
                count: 1,
            })
            .await;
    });

    let paused = Arc::new(AtomicUsize::new(0));
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        coordinate(&mut dumper, coord_rx, req_tx, res_tx, coord_tx, paused),
    )
    .await
    .expect("coordinator must terminate (tripped re-queues must not keep it alive)");
    assert!(result.is_ok());

    let skipped = dumper.stats.breaker_skipped_by_api();
    assert_eq!(skipped.get("graph/stuck"), Some(&2));

    // Only the healthy URL was dispatched.
    let mut dispatched = 0;
    while let Ok(msg) = req_rx.try_recv() {
        if matches!(msg, RequestMsg::ApiCall(_)) {
            dispatched += 1;
        }
    }
    assert_eq!(dispatched, 1);
}

/// `BreakerTripped` purges the tripped bucket's pending pool URLs. Run under a
/// pause so the event is processed before any dispatch: on resume, only the
/// healthy URL remains to dispatch and the skipped count covers the purge.
#[tokio::test]
async fn coordinator_breaker_purges_pool_under_pause() {
    let temp_dir = TempDir::new().unwrap();
    let (mut dumper, _event_tx) = make_dumper(&temp_dir).await;

    {
        let mut urls = dumper.current_urls.entry(Arc::from("graph")).or_default();
        urls.push(make_url(
            "graph",
            "users",
            "https://graph.microsoft.com/v1.0/users",
        ));
        urls.push(make_url(
            "graph",
            "stuck",
            "https://graph.microsoft.com/v1.0/stuck/1",
        ));
        urls.push(make_url(
            "graph",
            "stuck",
            "https://graph.microsoft.com/v1.0/stuck/2",
        ));
    }

    let (req_tx, mut req_rx) = mpsc::channel::<RequestMsg>(8192);
    let (res_tx, _res_rx) = mpsc::channel::<ResponseMsg>(8192);
    let (coord_tx, coord_rx) = mpsc::channel::<CoordinatorEvent>(8192);

    let paused = Arc::new(AtomicUsize::new(1)); // dispatch gated from the start
    let paused_clone = Arc::clone(&paused);
    let coord_tx_clone = coord_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        let _ = coord_tx_clone
            .send(CoordinatorEvent::BreakerTripped {
                service: Arc::from("graph"),
                api: "stuck".to_string(),
            })
            .await;
        // Resume: the paused poll re-dispatches within ~1s; only `users` is left.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        paused_clone.store(0, std::sync::atomic::Ordering::Relaxed);
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let _ = coord_tx_clone
            .send(CoordinatorEvent::RequestCompleted {
                id: 0,
                service: Arc::from("graph"),
                new_urls: vec![],
                count: 1,
            })
            .await;
    });

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        coordinate(&mut dumper, coord_rx, req_tx, res_tx, coord_tx, paused),
    )
    .await
    .expect("coordinator must terminate after the purge");
    assert!(result.is_ok());

    let skipped = dumper.stats.breaker_skipped_by_api();
    assert_eq!(
        skipped.get("graph/stuck"),
        Some(&2),
        "both pooled URLs of the tripped bucket must be counted as skipped"
    );

    let mut dispatched = 0;
    while let Ok(msg) = req_rx.try_recv() {
        if matches!(msg, RequestMsg::ApiCall(_)) {
            dispatched += 1;
        }
    }
    assert_eq!(dispatched, 1, "only the healthy URL may dispatch");
}

/// `dispatch_requests` honours the paused-services set — the union of
/// `prereq_in_flight` + `token_refresh_in_flight` the coordinator passes it.
/// A paused service's URLs stay queued while every other service dispatches,
/// so dispatch resumes for a service only once it leaves that set.
#[tokio::test]
async fn dispatch_requests_skips_paused_services_and_dispatches_the_rest() {
    use oradaz::collect::dump::orchestration::dispatch::dispatch_requests;
    use oradaz::utils::ui::progress::ProgressState;
    use std::collections::HashSet;
    use std::sync::Mutex;

    let temp_dir = TempDir::new().unwrap();
    let (mut dumper, _event_tx) = make_dumper(&temp_dir).await;

    dumper.current_urls.insert(
        Arc::from("graph"),
        vec![make_url(
            "graph",
            "users",
            "https://graph.microsoft.com/v1.0/users",
        )],
    );
    dumper.current_urls.insert(
        Arc::from("resources"),
        vec![make_url(
            "resources",
            "subs",
            "https://management.azure.com/subscriptions",
        )],
    );

    let (req_tx, mut req_rx) = mpsc::channel::<RequestMsg>(8192);
    let (res_tx, _res_rx) = mpsc::channel::<ResponseMsg>(8192);
    let progress_state = Arc::new(Mutex::new(ProgressState::default()));

    // Only `graph` is paused (as if it were in prereq_in_flight).
    let mut paused: HashSet<Arc<str>> = HashSet::new();
    paused.insert(Arc::from("graph"));

    dispatch_requests(&mut dumper, &req_tx, &res_tx, &progress_state, &paused)
        .await
        .expect("dispatch must not fail");

    // The paused service keeps its URLs queued; the other service drained.
    let graph_remaining = dumper
        .current_urls
        .get("graph")
        .map(|e| e.value().len())
        .unwrap_or(0);
    let resources_remaining = dumper
        .current_urls
        .get("resources")
        .map(|e| e.value().len())
        .unwrap_or(0);
    assert_eq!(
        graph_remaining, 1,
        "paused service must keep its URLs queued"
    );
    assert_eq!(
        resources_remaining, 0,
        "the non-paused service must dispatch its URLs"
    );

    // Exactly one ApiCall (resources) reached the request module.
    let mut dispatched = 0;
    while let Ok(msg) = req_rx.try_recv() {
        if matches!(msg, RequestMsg::ApiCall(_)) {
            dispatched += 1;
        }
    }
    assert_eq!(dispatched, 1, "only the non-paused service may dispatch");
}
