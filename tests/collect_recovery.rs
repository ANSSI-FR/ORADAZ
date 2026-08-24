mod common;

use crate::common::{default_test_config, materialize_fixture};
use oradaz::collect::auth::tokens::{Token, TokenState};
use oradaz::collect::dump::Dumper;
use oradaz::collect::dump::InteractivePrompt;
use oradaz::collect::dump::concurrency::ConcurrencyController;
use oradaz::collect::dump::orchestration::dispatch::dispatch_requests;
use oradaz::collect::dump::orchestration::events::CoordinatorEvent;
use oradaz::collect::dump::orchestration::prereq_task::prompt_and_resume_task;
use oradaz::collect::dump::ratelimit::RateLimitManager;
use oradaz::collect::dump::request::{RequestMsg, RequestsThread};
use oradaz::collect::dump::response::ResponseMsg;
use oradaz::utils::client::OradazClient;
use oradaz::utils::url::{ApiCall, Url};
use oradaz::utils::writer::actor::spawn_writer_task;

use dashmap::DashMap;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tokio::sync::mpsc;

/// Mock prompt that allows controlling the response and simulating latency.
struct MockPrompt {
    response: std::sync::Mutex<Option<String>>,
    delay: Option<std::time::Duration>,
}

impl InteractivePrompt for MockPrompt {
    fn read_line(&self) -> Pin<Box<dyn Future<Output = io::Result<String>> + Send + '_>> {
        let res = self.response.lock().unwrap().clone();
        let delay = self.delay;
        Box::pin(async move {
            if let Some(d) = delay {
                tokio::time::sleep(d).await;
            }
            res.ok_or_else(|| io::Error::other("No mock response"))
        })
    }
}

fn create_expiring_token() -> Token {
    Token {
        tenant_id: "test-tenant".to_string(),
        client_id: "test-client".to_string(),
        service: "graph".to_string(),
        expires_on: chrono::Utc::now().timestamp() + 10,
        access_token: "expiring_token".to_string(),
        refresh_token: Some("refresh_token".to_string()),
        token_type: "Bearer".to_string(),
        user_id: "user-123".to_string(),
        user_principal_name: "user@example.com".to_string(),
        scopes: vec!["https://graph.microsoft.com/.default".to_string()],
    }
}

fn create_test_url(service: &str) -> Url {
    Url {
        service_name: service.to_string(),
        service_scopes: Arc::new(vec!["https://graph.microsoft.com/.default".to_string()]),
        service_mandatory_auth: true,
        api: "applications".to_string(),
        url: format!("https://{}.microsoft.com/v1.0/applications", service),
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

#[tokio::test]
async fn test_token_expiration_recovery() {
    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    let token = create_expiring_token();
    let url = create_test_url("graph");
    let api_call = ApiCall {
        id: 123,
        url: url.clone(),
        success_code: 200,
        value_pointer: "/value".to_string(),
        is_batch: false,
        batch_data: None,
    };

    let (response_tx, _response_rx) = mpsc::channel(8192);
    let (update_tx, mut update_rx) = mpsc::channel(8192);

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

    let mut events = Vec::new();
    for _ in 0..2 {
        if let Some(event) = update_rx.recv().await {
            events.push(event);
        }
    }

    assert_eq!(events.len(), 2);

    let has_expiration_error = events.iter().any(|e| match e {
        CoordinatorEvent::NewError(
            svc,
            oradaz::collect::dump::orchestration::events::ProcessError::TokenExpirationError,
        ) => svc.as_ref() == "graph",
        _ => false,
    });
    assert!(
        has_expiration_error,
        "Should have sent TokenExpirationError"
    );

    let has_requeue = events.iter().any(|e| match e {
        CoordinatorEvent::RequestCompleted {
            service,
            new_urls,
            count,
            ..
        } => {
            service.as_ref() == "graph"
                && new_urls.len() == 1
                && new_urls[0].url == url.url
                && *count == 1
        }
        _ => false,
    });
    assert!(has_requeue, "Should have re-queued the original URL");
}

#[tokio::test]
async fn test_retry_limit_enforcement() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let schema_path = materialize_fixture("tests/fixtures/schema-minimal.json", tmp_dir.path());

    let mut config = default_test_config();
    config.schema_file = Some(schema_path.to_str().unwrap().to_string());
    config.url_retry_limit = Some(3);

    let client = OradazClient::new(&config).unwrap();
    let (writer_handle, _writer_task) = spawn_writer_task(
        config.clone(),
        tmp_dir.path().to_path_buf(),
        "test_retry".to_string(),
    )
    .await
    .unwrap();

    let tokens = Arc::new(DashMap::new());
    tokens.insert(
        Arc::from("graph"),
        Arc::new(TokenState::new(create_expiring_token())),
    );

    let mut dumper = Dumper::new_with_tokens(
        "test-tenant",
        "test-app",
        &writer_handle,
        &config,
        client,
        tokens,
        1,
    )
    .await
    .unwrap();

    dumper.current_urls.clear();

    let service_name = "test_service";
    let url = create_test_url(service_name);
    dumper
        .current_urls
        .insert(Arc::from(service_name), vec![url.clone()]);

    let (request_tx, mut request_rx) = mpsc::channel(8192);
    let (response_tx, mut response_rx) = mpsc::channel(8192);
    let progress_state = Arc::new(std::sync::Mutex::new(
        oradaz::utils::ui::progress::ProgressState::default(),
    ));
    let paused_services = HashSet::new();

    for _ in 0..3 {
        dispatch_requests(
            &mut dumper,
            &request_tx,
            &response_tx,
            &progress_state,
            &paused_services,
        )
        .await
        .unwrap();
        let msg = request_rx.recv().await.unwrap();
        if let RequestMsg::ApiCall(api_call) = msg {
            println!(
                "Recv ApiCall with retry_number: {}",
                api_call.url.retry_number
            );
            let mut retry_url = api_call.url.clone();
            retry_url.retry_number += 1;
            println!("Incrementing retry_number to {}", retry_url.retry_number);
            dumper.current_urls.get_mut(service_name).unwrap().clear();
            dumper
                .current_urls
                .get_mut(service_name)
                .unwrap()
                .push(retry_url);
        }
    }

    println!("Final dispatch");
    dispatch_requests(
        &mut dumper,
        &request_tx,
        &response_tx,
        &progress_state,
        &paused_services,
    )
    .await
    .unwrap();

    let final_msg = request_rx.try_recv();
    if final_msg.is_ok() {
        println!("Unexpected message in request_rx");
    }
    assert!(final_msg.is_err());

    let response = response_rx.recv().await.unwrap();
    println!("Final response from response_rx received");

    if let ResponseMsg::DumpError(err, _) = response {
        assert_eq!(err.code, "UrlRetryLimit");
        assert_eq!(err.folder, service_name);
    } else {
        panic!("Expected DumpError::UrlRetryLimit");
    }
}

#[tokio::test]
async fn test_prerequisite_recovery_loop() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let schema_path = materialize_fixture("tests/fixtures/schema-minimal.json", tmp_dir.path());

    let mut config = default_test_config();
    config.schema_file = Some(schema_path.to_str().unwrap().to_string());
    let client = OradazClient::new(&config).unwrap();
    let (writer_handle, _writer_task) = spawn_writer_task(
        config.clone(),
        tmp_dir.path().to_path_buf(),
        "test_prereq".to_string(),
    )
    .await
    .unwrap();

    let tokens = Arc::new(DashMap::new());
    tokens.insert(
        Arc::from("graph"),
        Arc::new(TokenState::new(create_expiring_token())),
    );

    let mut dumper = Dumper::new_with_tokens(
        "test-tenant",
        "test-app",
        &writer_handle,
        &config,
        client,
        tokens,
        1,
    )
    .await
    .unwrap();

    dumper.current_urls.clear();

    let url = create_test_url("graph");
    dumper
        .current_urls
        .insert(Arc::from("graph"), vec![url.clone()]);

    let (request_tx, mut request_rx) = mpsc::channel(8192);
    let (response_tx, _response_rx) = mpsc::channel(8192);
    let progress_state = Arc::new(std::sync::Mutex::new(
        oradaz::utils::ui::progress::ProgressState::default(),
    ));

    let mut paused_services = HashSet::new();
    paused_services.insert(Arc::from("graph"));

    dispatch_requests(
        &mut dumper,
        &request_tx,
        &response_tx,
        &progress_state,
        &paused_services,
    )
    .await
    .unwrap();
    assert!(
        request_rx.try_recv().is_err(),
        "Should not dispatch when paused"
    );

    paused_services.remove("graph");

    dispatch_requests(
        &mut dumper,
        &request_tx,
        &response_tx,
        &progress_state,
        &paused_services,
    )
    .await
    .unwrap();
    let msg = request_rx.recv().await.unwrap();
    assert!(matches!(msg, RequestMsg::ApiCall(_)));
}

#[tokio::test]
async fn test_slow_user_authentication() {
    let (event_tx, mut event_rx) = mpsc::channel(8192);
    let progress_paused = Arc::new(AtomicUsize::new(0));
    let mock_prompt = Arc::new(MockPrompt {
        response: std::sync::Mutex::new(Some("Enter".to_string())),
        delay: Some(std::time::Duration::from_millis(100)),
    });

    let service = Arc::from("graph");
    let error_msg = "Missing permission".to_string();

    let handle = tokio::spawn(async move {
        prompt_and_resume_task(service, error_msg, event_tx, progress_paused, mock_prompt).await;
    });

    let event = event_rx.recv().await.unwrap();
    assert!(matches!(event, CoordinatorEvent::ResumeService(_)));

    handle.await.unwrap();
}

/// A prereq prompt task cancelled mid-`read_line` (as the coordinator's `abort_all` does
/// on an interrupted run) must still release its pause counters via the RAII `PauseGuard`.
/// We check the local `progress_paused` Arc — not the process-global `DUMP_PAUSED`, to
/// avoid racing other tests in this binary — and the guard decrements both together, so 0
/// here proves the drop ran. With the previous manual `fetch_sub`-after-await it would
/// stay stuck at 1.
#[tokio::test]
async fn aborted_prompt_task_releases_pause_counter() {
    let (event_tx, _event_rx) = mpsc::channel(8192);
    let progress_paused = Arc::new(AtomicUsize::new(0));
    // A prompt that blocks effectively forever, so the task parks in `read_line().await`.
    let mock_prompt = Arc::new(MockPrompt {
        response: std::sync::Mutex::new(Some("Enter".to_string())),
        delay: Some(std::time::Duration::from_secs(3600)),
    });

    let pp = Arc::clone(&progress_paused);
    let handle = tokio::spawn(async move {
        prompt_and_resume_task(
            Arc::from("graph"),
            "Missing permission".to_string(),
            event_tx,
            pp,
            mock_prompt,
        )
        .await;
    });

    // Wait until the guard has incremented the pause counter (done before the awaits).
    for _ in 0..200 {
        if progress_paused.load(std::sync::atomic::Ordering::Relaxed) > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert_eq!(
        progress_paused.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "prompt task should have paused before we abort it"
    );

    // Cancel the task while it is parked in read_line(), as coordinator.abort_all() does.
    handle.abort();
    let _ = handle.await;

    assert_eq!(
        progress_paused.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "PauseGuard::drop must release progress_paused even when the task is cancelled"
    );
}

/// Token-refresh retry policy: interactive flows retry without limit (the
/// operator has no time limit to re-authenticate); application-credential flows
/// retry a *transient* failure for up to a generous wall-clock budget and then
/// abort (no user to prompt), so a brief outage is ridden out while a permanent
/// failure still aborts cleanly instead of live-locking.
#[test]
fn test_token_refresh_retry_policy() {
    use oradaz::collect::dump::should_retry_token_refresh;
    use std::time::Duration;

    let budget = Duration::from_secs(900);

    // Interactive (is_app_cred = false): always retry, regardless of elapsed time.
    assert!(should_retry_token_refresh(
        false,
        Duration::from_secs(0),
        budget
    ));
    assert!(should_retry_token_refresh(false, budget, budget));
    assert!(should_retry_token_refresh(
        false,
        Duration::from_secs(10_000),
        budget
    ));

    // Application credentials: retry while within the budget, then abort.
    assert!(should_retry_token_refresh(
        true,
        Duration::from_secs(0),
        budget
    ));
    assert!(should_retry_token_refresh(
        true,
        Duration::from_secs(899),
        budget
    ));
    assert!(!should_retry_token_refresh(true, budget, budget));
    assert!(!should_retry_token_refresh(
        true,
        Duration::from_secs(901),
        budget
    ));
}

/// When a mid-collection prereq re-check finds no token for the service (it
/// vanished from the token map), `prereq_check_task` must short-circuit to
/// `PrereqResult(Success)` so the coordinator resumes the service instead of
/// stranding it in `prereq_in_flight`. The None branch returns before any HTTP.
#[tokio::test]
async fn prereq_check_task_resumes_service_when_token_missing() {
    use oradaz::collect::dump::orchestration::events::PrereqOutcome;
    use oradaz::collect::dump::orchestration::prereq_task::prereq_check_task;

    let config = default_test_config();
    let client = OradazClient::new(&config).expect("test client");
    // Empty token map: the service has no token entry.
    let tokens: Arc<DashMap<Arc<str>, Arc<TokenState>>> = Arc::new(DashMap::new());
    let (tx, mut rx) = mpsc::channel::<CoordinatorEvent>(8);

    prereq_check_task(Arc::from("graph"), tokens, client, config, tx).await;

    match rx.try_recv() {
        Ok(CoordinatorEvent::PrereqResult(service, outcome)) => {
            assert_eq!(&*service, "graph");
            assert!(
                matches!(outcome, PrereqOutcome::Success),
                "a missing token must resume the service (Success), not strand it"
            );
        }
        Ok(_) => panic!("expected a PrereqResult event"),
        Err(e) => panic!("expected a PrereqResult event, but the channel was empty: {e:?}"),
    }
    assert!(
        rx.try_recv().is_err(),
        "exactly one event should be emitted"
    );
}
