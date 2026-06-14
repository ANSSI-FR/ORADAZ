use crate::FL;
use crate::collect::auth::tokens::SharedTokenState;
use crate::collect::dump::Dumper;
use crate::collect::dump::conditions::ConditionChecker;
use crate::collect::dump::orchestration::coordinator::coordinate;
use crate::collect::dump::orchestration::events::CoordinatorEvent;
use crate::collect::dump::orchestration::sigint::handle_sigint_menu;
use crate::collect::dump::request::{
    BACKOFF_BASE_MS, BACKOFF_CAP_MS, RequestExecutionContext, RequestModule, RequestMsg,
};
use crate::collect::dump::response::ResponseContext;
use crate::collect::dump::response::{ResponseModule, ResponseMsg};
use crate::utils::config::Config;
use crate::utils::errors::Error;
use crate::utils::logger::clear_progress_line;
use crate::utils::logger::config as logger_config;
use crate::utils::metadata::TableMetadata;
use crate::utils::mutex::lock_result;
use crate::utils::writer::actor::WriterHandle;

use dashmap::DashMap;
use log::{debug, error, info, trace, warn};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::{Sender, channel};

/// Awaits the first shutdown signal: Ctrl+C (all platforms) or SIGTERM (Unix —
/// `docker stop`, systemd). Returns once either is received.
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = sigterm.recv() => {}
                }
            }
            // Cannot register SIGTERM: fall back to Ctrl+C only.
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Guards the window between archive creation and the start of the dump (schema
/// download, authentication, prerequisite checks — minutes for interactive
/// flows). A Ctrl+C or SIGTERM there would otherwise take the default action and
/// kill the process, stranding the `.mla.tmp` archive. This handler marks the
/// archive `.broken` and exits cleanly instead. Once the dump starts it sets
/// `dump_started`, after which this guard goes inert and the dump's own handlers
/// (interactive menu / SIGTERM → drain) own signal handling.
pub fn spawn_pre_dump_signal_guard(writer: WriterHandle, dump_started: Arc<AtomicBool>) {
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        if dump_started.load(Ordering::Relaxed) {
            // The dump now owns signal handling; defer to it.
            return;
        }
        warn!(
            "{:FL$}Interrupted before the collection started — writing a '.broken' archive and exiting",
            "Dumper"
        );
        let _ = writer.set_broken().await;
        std::process::exit(1);
    });
}

/// Abandons an in-progress graceful drain: finalizes the archive as `.broken`
/// with whatever has been written so far, then exits the process.
///
/// Used when the operator repeats a stop signal instead of waiting out the
/// drain — in-flight requests can legitimately hold a drain for up to a full
/// rate-limit cooldown, and once the dump owns SIGINT/SIGTERM nothing short of
/// SIGKILL could otherwise end the run early. The writer actor serialises the
/// `.broken` rename after any already-queued data writes, so the archive keeps
/// everything collected up to this point.
async fn abandon_drain_and_exit(writer: &WriterHandle) {
    warn!(
        "{:FL$}Stop signal repeated — abandoning the graceful drain and finalizing the partial '.broken' archive now",
        "Dumper"
    );
    if let Err(err) = writer.set_broken().await {
        error!("{:FL$}{:?}", "Dumper", err);
    }
    std::process::exit(1);
}

/// Orchestrates the data collection process using an asynchronous producer-consumer pipeline.
///
/// The pipeline consists of three main components running in separate tokio tasks:
/// 1. **Request Module**: Executes HTTP requests. It receives `RequestMsg` and produces
///    `ResponseMsg` (for the Response Module) and `CoordinatorEvent` (for the Coordinator).
/// 2. **Response Module**: Processes HTTP responses. It receives `ResponseMsg`, writes
///    data to the output, discovers new URLs, and produces `CoordinatorEvent` (for the Coordinator).
/// 3. **Coordinator**: Synchronizes the global state. It receives `CoordinatorEvent` to
///    maintain request counters, error lists, and the pool of URLs to collect.
///
/// The `dump` function acts as the driver, feeding `RequestMsg` into the pipeline via the coordinator.
///
/// **Termination Sequence**:
/// To ensure all data is processed and written before exiting, the modules are shut down sequentially:
/// Request Module -> Response Module.
pub async fn dump(dumper: &mut Dumper, dump_started: Arc<AtomicBool>) -> Result<(), Error> {
    debug!("{:FL$}Starting dump orchestration", "Dumper");
    // Initialise backoff config from user settings (read once, then used as globals).
    BACKOFF_BASE_MS.store(
        Config::retry_backoff_base_ms(&dumper.config),
        Ordering::Relaxed,
    );
    BACKOFF_CAP_MS.store(
        Config::retry_backoff_cap_ms(&dumper.config),
        Ordering::Relaxed,
    );
    let (s1, r1) = channel::<RequestMsg>(8192);
    let (s2, r2) = channel::<ResponseMsg>(8192);
    let (se, re) = channel::<CoordinatorEvent>(8192);

    let dumper_sender: Sender<RequestMsg> = s1;
    let response_sender: Sender<ResponseMsg> = s2;
    let coordinator_sender: Sender<CoordinatorEvent> = se;

    // Handle SIGINT (Ctrl+C) for graceful termination
    let sigint_sender = coordinator_sender.clone();
    // Pause *source counter* (not a bool): the coordinator is paused while it is
    // > 0. Each independent source — this SIGINT handler and the prerequisite
    // re-check prompt — increments on pause and decrements on resume, so one
    // source resuming cannot clear another's still-active pause.
    let sigint_paused = Arc::new(AtomicUsize::new(0));
    let sigint_paused_clone = Arc::clone(&sigint_paused);
    // Set once a stop is initiated (menu choice or SIGTERM). The graceful drain
    // that follows can last up to a full rate-limit cooldown, so both signal
    // tasks keep listening and treat any FURTHER signal as an order to abandon
    // the drain (immediate `.broken` + exit) rather than re-opening the menu.
    let stop_initiated = Arc::new(AtomicBool::new(false));
    let sigint_stop_initiated = Arc::clone(&stop_initiated);
    let sigint_writer = dumper.writer.clone();
    tokio::spawn(async move {
        while tokio::signal::ctrl_c().await.is_ok() {
            // A Ctrl+C after a stop was already initiated (by the menu or by
            // SIGTERM) abandons the drain instead of opening the menu again.
            if sigint_stop_initiated.load(Ordering::Relaxed) {
                abandon_drain_and_exit(&sigint_writer).await;
            }
            info!(
                "{:FL$}Interruption requested (Ctrl+C) — pausing for confirmation",
                "Dumper"
            );
            sigint_paused_clone.fetch_add(1, Ordering::Relaxed);
            logger_config::DUMP_PAUSED.fetch_add(1, Ordering::Relaxed);
            clear_progress_line();
            let stop = tokio::task::spawn_blocking(handle_sigint_menu)
                .await
                .unwrap_or(true);
            sigint_paused_clone.fetch_sub(1, Ordering::Relaxed);
            logger_config::DUMP_PAUSED.fetch_sub(1, Ordering::Relaxed);
            if stop {
                sigint_stop_initiated.store(true, Ordering::Relaxed);
                warn!(
                    "{:FL$}Collection interrupted by user — draining in-flight requests; a partial '.broken' archive will be written (press Ctrl+C again to abandon the drain and finalize it immediately)",
                    "Dumper"
                );
                if let Err(err) = sigint_sender.send(CoordinatorEvent::Terminate).await {
                    warn!(
                        "{:FL$}Failed to send Terminate event to coordinator: {:?}",
                        "Dumper", err
                    );
                }
                // Keep listening: the next Ctrl+C abandons the drain (above).
            } else {
                info!(
                    "{:FL$}Resuming collection (interruption cancelled by user)",
                    "Dumper"
                );
            }
        }
    });

    // SIGTERM (Unix): a non-interactive shutdown request (`docker stop`, systemd).
    // The first one drains gracefully into a `.broken` archive — no confirmation
    // menu, unlike Ctrl+C — by sending the same Terminate event; a repeated
    // signal abandons the drain (so a `docker stop` grace period is not consumed
    // by a worker parked on a rate-limit cooldown).
    #[cfg(unix)]
    {
        let term_sender = coordinator_sender.clone();
        let term_stop_initiated = Arc::clone(&stop_initiated);
        let term_writer = dumper.writer.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let Ok(mut sigterm) = signal(SignalKind::terminate()) else {
                return;
            };
            while sigterm.recv().await.is_some() {
                // `swap` both records the stop and detects a repeat: a SIGTERM
                // after a stop was already initiated (menu choice or an earlier
                // SIGTERM) abandons the drain.
                if term_stop_initiated.swap(true, Ordering::Relaxed) {
                    abandon_drain_and_exit(&term_writer).await;
                }
                warn!(
                    "{:FL$}SIGTERM received — draining in-flight requests; a partial '.broken' archive will be written (send SIGTERM or Ctrl+C again to abandon the drain and finalize it immediately)",
                    "Dumper"
                );
                if let Err(err) = term_sender.send(CoordinatorEvent::Terminate).await {
                    warn!(
                        "{:FL$}Failed to send Terminate event to coordinator on SIGTERM: {:?}",
                        "Dumper", err
                    );
                }
            }
        });
    }

    // The dump now owns signal handling: the pre-dump guard (collect::collect)
    // goes inert from here, so a signal is routed to the menu / SIGTERM drain.
    dump_started.store(true, Ordering::Relaxed);

    // Mark the effective dump start so the duration recorded in stats.json
    // excludes auth and prerequisite checks.
    dumper.stats.mark_started(chrono::Utc::now());

    trace!("{:FL$}Spawning response module", "Dumper");
    let tables: Arc<Mutex<HashMap<String, TableMetadata>>> = Arc::new(Mutex::new(HashMap::new()));
    let response_handle = tokio::spawn({
        let response_receiver = r2;
        let coordinator_sender = coordinator_sender.clone();
        let writer = dumper.writer.clone();
        let metadata: Arc<Mutex<HashMap<String, TableMetadata>>> = Arc::clone(&tables);
        let tokens: Arc<DashMap<Arc<str>, SharedTokenState>> = Arc::clone(&dumper.tokens);
        let condition_checker: Arc<ConditionChecker> = Arc::clone(&dumper.condition_checker);
        let ratelimit_manager = Arc::clone(&dumper.ratelimit_manager);
        let concurrency_controller = Arc::clone(&dumper.concurrency_controller);
        let stats = Arc::clone(&dumper.stats);
        let logs_date_filter_and = dumper.logs_date_filter_and.clone();
        let response_workers_max = Config::response_workers_max(&dumper.config);
        let response_memory_budget = Config::response_memory_budget_bytes(&dumper.config);
        async move {
            let response_module: ResponseModule = ResponseModule::new(
                response_receiver,
                coordinator_sender,
                ResponseContext {
                    writer,
                    metadata,
                    tokens,
                    condition_checker,
                    ratelimit_manager,
                    concurrency_controller,
                    stats,
                    logs_date_filter_and,
                },
                response_workers_max,
                response_memory_budget,
            );
            response_module.start().await
        }
    });

    trace!("{:FL$}Spawning request module", "Dumper");
    let request_handle = tokio::spawn({
        let request_receiver = r1;
        let request_to_response_sender = response_sender.clone();
        let coordinator_sender = coordinator_sender.clone();
        let context = RequestExecutionContext {
            oradaz_client: dumper.oradaz_client.clone(),
            tokens: Arc::clone(&dumper.tokens),
            ratelimit_manager: Arc::clone(&dumper.ratelimit_manager),
            concurrency_controller: Arc::clone(&dumper.concurrency_controller),
            stats: Arc::clone(&dumper.stats),
            config: Arc::new(dumper.config.clone()),
        };
        async move {
            let request_module: RequestModule = RequestModule::new(
                request_receiver,
                request_to_response_sender,
                coordinator_sender,
                context,
            );
            request_module.start().await
        }
    });

    let completed_normally = coordinate(
        dumper,
        re,
        dumper_sender.clone(),
        response_sender.clone(),
        coordinator_sender.clone(),
        sigint_paused,
    )
    .await?;

    debug!("{:FL$}Finishing all threads", "Dumper");
    {
        if let Err(err) = dumper_sender.send(RequestMsg::Terminate).await {
            debug!(
                "{:FL$}Terminate send to RequestModule failed (channel closed — normal on early exit): {:?}",
                "Dumper", err
            );
        };
    }
    match request_handle.await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            // The module's own `start()` returned an error (e.g. a worker panic it
            // detected). Surface it instead of silently discarding the inner Result.
            error!(
                "{:FL$}Request module reported an error: {:?}",
                "Dumper", err
            );
            return Err(err);
        }
        Err(err) => {
            error!("{:FL$}Error finishing request thread: {:?}", "Dumper", err);
            return Err(Error::StringError(format!(
                "request module task failed: {err}"
            )));
        }
    }
    drop(dumper_sender);

    {
        if let Err(err) = response_sender.send(ResponseMsg::Terminate).await {
            debug!(
                "{:FL$}Terminate send to ResponseModule failed (channel closed — normal on early exit): {:?}",
                "Dumper", err
            );
        };
    }
    match response_handle.await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            error!(
                "{:FL$}Response module reported an error: {:?}",
                "Dumper", err
            );
            return Err(err);
        }
        Err(err) => {
            error!("{:FL$}Error finishing response thread: {:?}", "Dumper", err);
            return Err(Error::StringError(format!(
                "response module task failed: {err}"
            )));
        }
    }
    drop(response_sender);

    // The coordinator stopped abnormally yet both modules shut down cleanly above, so
    // this was a user-initiated cancellation (SIGINT menu / SIGTERM) — not a module
    // failure, which would have surfaced its own error from the join handles above and
    // returned before reaching here. Report it as such; the caller marks the archive
    // '.broken' and renders the matching fatal block.
    if !completed_normally {
        return Err(Error::Cancelled);
    }

    match lock_result(
        &tables,
        "Dumper",
        "Could not lock tables for later write",
        Error::MetadataLock,
    ) {
        Ok(tables) => {
            dumper.tables_metadata = <HashMap<String, TableMetadata> as Clone>::clone(&tables)
                .into_values()
                .collect();
        }
        Err(_) => {
            error!(
                "{:FL$}Could not lock tables for later write, exiting",
                "Dumper"
            );
            dumper.exit_with_error(Error::MetadataLock).await;
            return Err(Error::MetadataLock);
        }
    }
    {
        let mut service_names: Vec<String> = dumper
            .stats
            .services
            .iter()
            .map(|r| r.key().clone())
            .collect();
        service_names.sort();
        for svc_name in &service_names {
            let object_count: usize = dumper
                .tables_metadata
                .iter()
                .filter(|t| t.folder == *svc_name)
                .map(|t| t.count)
                .sum();
            let http_calls = dumper
                .stats
                .services
                .get(svc_name)
                .map(|s| {
                    s.http_batch_calls.load(Ordering::Relaxed)
                        + s.http_single_calls.load(Ordering::Relaxed)
                })
                .unwrap_or(0);
            let unexpected_errors: usize = dumper
                .stats
                .apis
                .iter()
                .filter(|r| r.value().service == *svc_name)
                .map(|r| r.value().unexpected_errors.load(Ordering::Relaxed))
                .sum();
            if dumper.verbosity >= 3 {
                let expected_errors: usize = dumper
                    .stats
                    .apis
                    .iter()
                    .filter(|r| r.value().service == *svc_name)
                    .map(|r| r.value().expected_errors.load(Ordering::Relaxed))
                    .sum();
                info!(
                    "{:FL$}Service '{}' completed: {} objects, {} HTTP calls, {} unexpected error(s), {} expected error(s)",
                    "Dumper",
                    svc_name,
                    object_count,
                    http_calls,
                    unexpected_errors,
                    expected_errors
                );
            } else {
                info!(
                    "{:FL$}Service '{}' completed: {} objects, {} HTTP calls, {} unexpected error(s)",
                    "Dumper", svc_name, object_count, http_calls, unexpected_errors
                );
            }
        }
    }
    info!("{:FL$}Dump orchestration completed successfully", "Dumper");
    info!(
        "{:FL$}Collection summary: requests={}, errors={}, auth_errors={}, prereq_errors={}, missing_token_errors={}\n",
        "Dumper",
        dumper.requests_number,
        dumper.errors_number,
        dumper.auth_errors_number,
        dumper.prerequisites_errors_number,
        dumper.missing_token_errors_number
    );
    Ok(())
}
