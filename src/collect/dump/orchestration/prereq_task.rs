use crate::FL;
use crate::collect::auth::tokens::SharedTokenState;
use crate::collect::dump::orchestration::events::{CoordinatorEvent, PrereqOutcome};
use crate::collect::dump::{InteractivePrompt, should_retry_token_refresh};
use crate::collect::prerequisites::Prerequisites;
use crate::utils::client::OradazClient;
use crate::utils::config::Config;
use crate::utils::errors::Error;
use crate::utils::logger::clear_progress_line;
use crate::utils::logger::config as logger_config;
use crate::utils::ui::prereq::show_prereq_failure_ui;

use dashmap::DashMap;
use log::{debug, error, info, warn};
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use tokio::sync::mpsc::Sender;
use tokio::time::Duration;

/// Wall-clock budget for retrying a *transient* application-credential token
/// refresh (token-endpoint network blip / 5xx / throttle) before aborting. Long
/// enough to ride out a multi-minute outage of a service that is briefly
/// unavailable, so a multi-hour collection is not killed by a passing glitch; a
/// genuinely-permanent auth failure short-circuits before this budget applies.
const APP_CRED_REFRESH_MAX_WAIT: Duration = Duration::from_secs(900);

/// One-shot prerequisite check for a single service.
///
/// Performs a single check and sends `PrereqResult` with the outcome.
/// The coordinator is responsible for retrying (via `ResumeService`) and
/// for deciding whether to prompt the user or abort based on the auth mode.
pub async fn prereq_check_task(
    service: Arc<str>,
    tokens: Arc<DashMap<Arc<str>, SharedTokenState>>,
    oradaz_client: OradazClient,
    config: Config,
    sender: Sender<CoordinatorEvent>,
) {
    info!(
        "{:FL$}Starting prereq re-check for service {:?}",
        "Dumper", service
    );
    let token_opt = tokens.get(&service).map(|s| Arc::clone(s.value()));
    let token_state = match token_opt {
        Some(s) => s,
        None => {
            warn!(
                "{:FL$}Token for service {:?} not found during prereq re-check, treating as success",
                "Dumper", service
            );
            if let Err(err) = sender
                .send(CoordinatorEvent::PrereqResult(
                    Arc::clone(&service),
                    PrereqOutcome::Success,
                ))
                .await
            {
                warn!(
                    "{:FL$}Failed to send PrereqResult to coordinator: {:?}",
                    "Dumper", err
                );
            }
            return;
        }
    };

    let token = token_state.token.read().await;
    let use_app_creds = Config::use_application_credentials_auth(&config);
    let use_mi = Config::use_managed_identity_auth(&config);

    let check_result = tokio::time::timeout(
        Duration::from_secs(30),
        Prerequisites::check(
            &oradaz_client.client,
            &token,
            true, // silent — UI handled by coordinator/prompt task
            use_app_creds,
            use_mi,
            config.default_retry_after_seconds.unwrap_or(2),
        ),
    )
    .await;
    drop(token);

    let outcome = match check_result {
        Ok(Ok(_)) => {
            debug!(
                "{:FL$}Prerequisites re-verified for service {:?}",
                "Dumper", service
            );
            PrereqOutcome::Success
        }
        Ok(Err(Error::TooManyRequestsDuringPrerequisites(sec))) => {
            warn!(
                "{:FL$}Rate limited during prereq re-check for {:?}, will retry in {}s",
                "Dumper", service, sec
            );
            PrereqOutcome::Throttled(sec)
        }
        Ok(Err(err)) => {
            warn!(
                "{:FL$}Prerequisites re-check failed for service {:?}: {:?}",
                "Dumper", service, err
            );
            PrereqOutcome::Failure(format!("{err:?}"))
        }
        Err(_elapsed) => {
            warn!(
                "{:FL$}Prerequisites re-check timed out for service {:?}",
                "Dumper", service
            );
            PrereqOutcome::Failure(format!(
                "Prerequisite check timed out after 30 seconds for service '{service}'"
            ))
        }
    };

    if let Err(err) = sender
        .send(CoordinatorEvent::PrereqResult(
            Arc::clone(&service),
            outcome,
        ))
        .await
    {
        warn!(
            "{:FL$}Failed to send PrereqResult to coordinator: {:?}",
            "Dumper", err
        );
    }
}

/// RAII guard holding both pause-source counters for its lifetime: `progress_paused`
/// (gates coordinator dispatch) and `DUMP_PAUSED` (gates stdout logging). Incrementing in
/// `new` and decrementing in `Drop` guarantees the counters are released even if the
/// awaiting task is **cancelled** (the coordinator's `abort_all` on an interrupted run
/// drops this future at a `.await`); a manual decrement after the await would be skipped
/// by cancellation, stranding the counters above zero and silencing the final console logs.
struct PauseGuard {
    progress_paused: Arc<AtomicUsize>,
}

impl PauseGuard {
    fn new(progress_paused: Arc<AtomicUsize>) -> Self {
        progress_paused.fetch_add(1, Ordering::Relaxed);
        logger_config::DUMP_PAUSED.fetch_add(1, Ordering::Relaxed);
        Self { progress_paused }
    }
}

impl Drop for PauseGuard {
    fn drop(&mut self) {
        self.progress_paused.fetch_sub(1, Ordering::Relaxed);
        logger_config::DUMP_PAUSED.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Shows the failure banner, waits for the user to press Enter, then sends `ResumeService`.
///
/// Spawned by the coordinator when a prerequisite check fails in user-credential mode.
pub async fn prompt_and_resume_task(
    service: Arc<str>,
    error_msg: String,
    sender: Sender<CoordinatorEvent>,
    progress_paused: Arc<AtomicUsize>,
    prompt: Arc<dyn InteractivePrompt>,
) {
    let pseudo_error = Error::StringError(error_msg);

    // Pause dispatch + stdout logging for the duration of the prompt. The RAII guard
    // releases both counters on drop — including if this task is cancelled mid-await — so
    // a concurrent SIGINT pause/resume cannot clear this prompt's pause and an aborted run
    // cannot strand the counters above zero.
    let pause = PauseGuard::new(Arc::clone(&progress_paused));
    tokio::time::sleep(Duration::from_millis(150)).await;
    clear_progress_line();

    show_prereq_failure_ui(&service, &pseudo_error);
    info!(
        "{:FL$}Waiting for operator to acknowledge prerequisite failure for service {:?} and press Enter",
        "Dumper", service
    );
    print!("  Press Enter to re-check prerequisites and resume collection...");
    let _ = io::stdout().flush();

    let _ = prompt.read_line().await;
    info!(
        "{:FL$}Operator acknowledged prerequisite failure for service {:?} — triggering re-check",
        "Dumper", service
    );

    // Release the pause (decrement both counters) before signalling the resume, matching
    // the original ordering: the coordinator only acts on events once it is un-paused.
    drop(pause);

    if let Err(err) = sender
        .send(CoordinatorEvent::ResumeService(Arc::clone(&service)))
        .await
    {
        warn!(
            "{:FL$}Failed to send ResumeService event to coordinator: {:?}",
            "Dumper", err
        );
    }
}

/// Background token refresh for a single service.
///
/// A token refresh can take tens of seconds under application credentials and is
/// unbounded for interactive re-authentication. Running it as a background task
/// keeps the coordinator's event loop unblocked throughout. The coordinator marks
/// the service as paused (`token_refresh_in_flight`) when it spawns this, and
/// resumes it on the outcome event.
///
/// Unlike `prompt_and_resume_task`, this deliberately takes **no `PauseGuard`**:
/// every *other* service must keep dispatching during the refresh. Pausing under
/// application credentials would block the whole coordinator for the duration of
/// the refresh — potentially tens of seconds. The trade-off is that an
/// interactive re-auth prompt emitted by `Token::refresh` (device code / auth
/// URL — only when a mid-collection `refresh_token` is invalid, a rare path)
/// renders alongside live progress output rather than on its own.
///
/// INVARIANT: this task sends **exactly one** `TokenRefreshed` or
/// `TokenRefreshFailed` before returning (via the single send below over the
/// event computed by [`compute_token_refresh`]). Any path that returned without
/// sending would strand the service in `token_refresh_in_flight` forever — a
/// silent stall surfaced only every `stall_timeout`.
pub async fn token_refresh_task(
    service: Arc<str>,
    tokens: Arc<DashMap<Arc<str>, SharedTokenState>>,
    config: Config,
    oradaz_client: OradazClient,
    sender: Sender<CoordinatorEvent>,
) {
    let event = compute_token_refresh(&service, &tokens, &config, &oradaz_client).await;
    if let Err(err) = sender.send(event).await {
        warn!(
            "{:FL$}Failed to send token-refresh outcome to coordinator: {:?}",
            "Dumper", err
        );
    }
}

/// Performs the refresh and returns the outcome event. Uses double-checked
/// locking via `refresh_lock`; unlimited retries for interactive re-auth, bounded
/// for application credentials — see [`should_retry_token_refresh`]. Returns an
/// event on **every** path so the caller's single send upholds the stranding
/// invariant.
async fn compute_token_refresh(
    service: &Arc<str>,
    tokens: &Arc<DashMap<Arc<str>, SharedTokenState>>,
    config: &Config,
    oradaz_client: &OradazClient,
) -> CoordinatorEvent {
    let token_state = match tokens.get(service).map(|s| Arc::clone(s.value())) {
        Some(s) => s,
        None => {
            // Defensive: a TokenExpirationError implies the service had a token.
            // If it is somehow gone, resume the service rather than strand it.
            warn!(
                "{:FL$}No token for service {:?} during refresh, resuming without refresh",
                "Dumper", service
            );
            return CoordinatorEvent::TokenRefreshed(Arc::clone(service));
        }
    };

    // Double-checked locking: several in-flight requests for the same service can
    // each raise TokenExpirationError, but only one refresh is needed. The cheap
    // pre-lock check also short-circuits when the token is not actually expired.
    if !token_state.token.read().await.will_expire() {
        debug!(
            "{:FL$}Token for service {:?} no longer expired (refreshed by concurrent task) — skipping refresh",
            "Dumper", service
        );
        return CoordinatorEvent::TokenRefreshed(Arc::clone(service));
    }
    let _lock = token_state.refresh_lock.lock().await;
    if !token_state.token.read().await.will_expire() {
        debug!(
            "{:FL$}Token for service {:?} no longer expired (refreshed by concurrent task) — skipping refresh",
            "Dumper", service
        );
        return CoordinatorEvent::TokenRefreshed(Arc::clone(service));
    }

    // Retry loop with exponential backoff + full jitter. The policy (unlimited
    // for interactive, bounded for app-cred) is captured by
    // `should_retry_token_refresh`.
    let is_app_cred = Config::use_application_credentials_auth(config);
    // Time-based budget for transient app-cred refresh failures (see
    // APP_CRED_REFRESH_MAX_WAIT): keep retrying a brief token-endpoint outage rather
    // than aborting a long collection after a fixed handful of attempts. A definitive
    // auth error returns `Reprocess(Some)` and is handled by the dedicated arm above,
    // so a permanently-invalid secret/permission still fails fast.
    let start = Instant::now();
    let mut attempts = 0u32;
    let mut delay = Duration::from_secs(1);
    loop {
        let mut token_clone = token_state.token.read().await.clone();
        match token_clone.refresh(config, oradaz_client).await {
            Ok(()) => {
                *token_state.token.write().await = token_clone;
                info!(
                    "{:FL$}Token refreshed successfully for service {:?}",
                    "Dumper", service
                );
                return CoordinatorEvent::TokenRefreshed(Arc::clone(service));
            }
            Err(Error::Reprocess(Some(auth_error))) => {
                // Definitive authentication error: record it (via the coordinator)
                // and abort — retrying cannot help.
                return CoordinatorEvent::TokenRefreshFailed {
                    service: Arc::clone(service),
                    auth_error: Some(auth_error),
                    message: format!(
                        "Token refresh for service {service:?} failed with a definitive authentication error"
                    ),
                };
            }
            Err(e) => {
                attempts += 1;
                if !should_retry_token_refresh(
                    is_app_cred,
                    start.elapsed(),
                    APP_CRED_REFRESH_MAX_WAIT,
                ) {
                    error!(
                        "{:FL$}Token refresh for service {:?} failed after {} attempt(s) over {:?} (application credentials): {:?}",
                        "Dumper",
                        service,
                        attempts,
                        start.elapsed(),
                        e
                    );
                    return CoordinatorEvent::TokenRefreshFailed {
                        service: Arc::clone(service),
                        auth_error: None,
                        message: format!(
                            "Token refresh for service {service:?} failed permanently after {attempts} attempts over {:?} (application credentials)",
                            start.elapsed()
                        ),
                    };
                }
                let jitter: f64 = rand::random::<f64>();
                let sleep_duration = delay.mul_f64(jitter);
                warn!(
                    "{:FL$}Token refresh for service {:?} failed (attempt {}){}, retrying in {:?}: {:?}",
                    "Dumper",
                    service,
                    attempts,
                    if is_app_cred {
                        ""
                    } else {
                        " — interactive re-authentication required, no time limit"
                    },
                    sleep_duration,
                    e
                );
                tokio::time::sleep(sleep_duration).await;
                delay = (delay * 2).min(Duration::from_secs(60));
            }
        }
    }
}
