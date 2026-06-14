use crate::FL;
use crate::collect::dump::Dumper;
use crate::collect::dump::orchestration::dispatch::dispatch_requests;
use crate::collect::dump::orchestration::events::{CoordinatorEvent, PrereqOutcome, ProcessError};
use crate::collect::dump::orchestration::prereq_task::{
    prereq_check_task, prompt_and_resume_task, token_refresh_task,
};
use crate::collect::dump::orchestration::process_errors::process_errors;
use crate::collect::dump::request::RequestMsg;
use crate::collect::dump::response::ResponseMsg;
use crate::utils::config::Config;
use crate::utils::errors::Error;
use crate::utils::logger::clear_progress_line;
use crate::utils::mutex::lock_force;
use crate::utils::sysmem;
use crate::utils::ui::progress::{ProgressState, finalize_performing_collect_label, start_ticker};
use crate::utils::url::Url;
use crate::utils::writer::actor::WriterHandle;

use log::{debug, error, info, trace, warn};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::io::IsTerminal;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task::JoinSet;

/// Bounded budget for consecutive throttled prerequisite re-checks of a single
/// service mid-collection. Sibling of the startup `MAX_PREREQ_RETRIES`. Kept
/// small (and deliberately NOT tied to `rateLimitRetryLimit`) because the
/// worst-case pause multiplies with `urlRetryLimit` once the service is resumed.
const MAX_PREREQ_THROTTLE_RETRIES: usize = 10;

/// Record one throttled prerequisite re-check for `service` and report whether
/// the bounded budget (`cap`) is now exhausted. On exhaustion the entry is
/// *kept* at `cap` (not removed) so the burned state persists: the
/// `PotentialPrerequisiteError` handler checks this value before spawning a
/// new task, preventing unbounded re-check episodes. The entry is cleared only
/// on `PrereqOutcome::Success` or `PrereqOutcome::Failure` (both reset the
/// budget so an interactive-prompt retry starts fresh).
fn record_prereq_throttle(
    attempts: &mut HashMap<Arc<str>, usize>,
    service: &Arc<str>,
    cap: usize,
) -> bool {
    let n = attempts.entry(Arc::clone(service)).or_insert(0);
    *n += 1;
    *n >= cap
}

/// Interval between periodic memory-observability samples during the dump.
/// Sampling is cheap (one `/proc` read or Win32 call plus a pool scan) and gated
/// to this interval so an event burst cannot flood the log.
const MEM_SAMPLE_INTERVAL: Duration = Duration::from_secs(15);

/// While the dump is paused (SIGINT menu / interactive prompt), the coordinator
/// polls the pause flag at this interval instead of parking on `recv()` for the
/// full `stall_detection_timeout`. This bounds how long a *resume* takes to
/// re-dispatch when the pause drained every in-flight request (so no event is
/// pending to wake the loop) and the un-pause sent no wake event of its own — the
/// SIGINT menu only clears the pause counter, unlike the prereq prompt which sends
/// a `ResumeService` event. Without this cap the loop would stay parked until
/// `stall_detection_timeout` (900s) after the operator resumed.
const PAUSED_POLL_SECS: u64 = 1;

/// When a `ResumeService` (throttled-prereq-recheck resumption) fires while a
/// token refresh is in flight for that service, the resume is deferred by this
/// many seconds and re-sent, so the prereq re-check runs with the fresh token
/// rather than the stale one (which could 401 → abort).
const RESUME_DEFER_SECS: u64 = 2;

/// Samples process RSS and the in-process memory gauges and logs them at `debug`.
/// The file log captures `debug` regardless of console verbosity, so this makes a
/// suspected large-tenant OOM diagnosable after the fact. Never fails: RSS is
/// best-effort (`None` renders as `n/a`).
fn sample_memory(dumper: &Dumper) {
    let pool_total: usize = dumper.current_urls.iter().map(|r| r.value().len()).sum();
    let pool_top = dumper
        .current_urls
        .iter()
        .map(|r| (r.key().clone(), r.value().len()))
        .filter(|(_, n)| *n > 0)
        .max_by_key(|(_, n)| *n)
        .map(|(s, n)| format!("{}({})", s, n))
        .unwrap_or_else(|| "none".to_string());
    let rss = sysmem::record_sample(pool_total as u64);
    let resp_inflight = sysmem::response_workers_inflight();
    let req_inflight = sysmem::request_workers_inflight();
    // Current (not peak) pipeline state: writer backpressure, throttling backoff,
    // and per-service AIMD windows / in-flight. Peaks land in metadata.json via
    // event-site gauges; this line is the *trajectory* for after-the-fact reading.
    let writer_q = dumper.writer.queue_usage_pct();
    let writer_bytes = dumper.writer.byte_budget_inflight_bytes();
    let backoff = crate::collect::dump::request::BACKOFF_ACTIVE.load(Ordering::Relaxed);
    let windows = fmt_service_map(&dumper.concurrency_controller.get_all_windows());
    let inflight = fmt_service_map(&dumper.concurrency_controller.get_all_in_flight());
    // `written=`/`written_bytes=` are cumulative totals: the delta between two
    // samples is the write throughput over that interval, which localises a
    // slowdown in time when cross-read with `windows=`/`backoff=`/`writer_q=`.
    // `resp_sem_wait=` is the cumulative wait (ms) for a response-worker permit
    // (`responseWorkersMax`); `breaker=` the number of buckets skipped by the
    // expected-error breaker so far.
    debug!(
        "{:FL$}Memory sample: RSS={} pool_total={} pool_top={} req_inflight={} resp_inflight={} writer_q={}% writer_bytes={} backoff={} windows={} inflight={} written={} written_bytes={} resp_sem_wait={} breaker={}",
        "Dumper",
        rss.map(sysmem::format_bytes)
            .unwrap_or_else(|| "n/a".to_string()),
        pool_total,
        pool_top,
        req_inflight,
        resp_inflight,
        writer_q,
        writer_bytes,
        backoff,
        windows,
        inflight,
        sysmem::written_entries(),
        sysmem::written_bytes(),
        sysmem::resp_sem_wait_ms_total(),
        dumper.stats.breaker_tripped_count()
    );
}

/// Drops from `urls` every URL of a breaker-tripped `(service, api)` bucket,
/// recording each one as skipped. Cheap no-op while no breaker has fired.
fn drop_tripped_urls(
    dumper: &Dumper,
    tripped: &HashSet<(Arc<str>, String)>,
    service: &Arc<str>,
    urls: Vec<Url>,
) -> Vec<Url> {
    if tripped.is_empty() {
        return urls;
    }
    let mut kept = Vec::with_capacity(urls.len());
    for url in urls {
        if tripped.contains(&(Arc::clone(service), url.api.clone())) {
            dumper
                .stats
                .record_breaker_skipped(&url.service_name, &url.api, 1);
        } else {
            kept.push(url);
        }
    }
    kept
}

/// Formats a per-service gauge map as `svc1:v1,svc2:v2` with services sorted, so
/// the debug `Memory sample:` line is stable across samples (DashMap iteration
/// order is otherwise non-deterministic).
fn fmt_service_map<V: std::fmt::Display>(m: &HashMap<String, V>) -> String {
    let mut entries: Vec<(&String, &V)> = m.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    entries
        .iter()
        .map(|(k, v)| format!("{k}:{v}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// The Event-Driven Coordinator for the dump process.
///
/// Manages the dispatch loop, prerequisite re-checks, token refreshes, and
/// termination. Services with in-flight prerequisite checks are kept in
/// `prereq_in_flight` and skipped by the dispatcher until `PrereqResult(Success)`
/// is received.
pub async fn coordinate(
    dumper: &mut Dumper,
    mut event_receiver: Receiver<CoordinatorEvent>,
    request_sender: Sender<RequestMsg>,
    response_sender: Sender<ResponseMsg>,
    event_sender: Sender<CoordinatorEvent>,
    // Pause *source counter*: paused while > 0 (see the SIGINT setup in `dump`).
    progress_paused: Arc<AtomicUsize>,
) -> Result<bool, Error> {
    debug!("{:FL$}Starting event-driven coordination", "Dumper");

    // Initial dispatch-pool volumetry: an info-level bookend to the end-of-collection
    // "Collection summary" line, printed once here before the progress ticker starts so
    // a standard user sees how much work the run begins with at default verbosity.
    let initial_url_count: usize = dumper.current_urls.iter().map(|e| e.value().len()).sum();
    let initial_service_count = dumper
        .current_urls
        .iter()
        .filter(|e| !e.value().is_empty())
        .count();
    info!(
        "{:FL$}Initial dispatch pool: {} URL(s) across {} service(s)",
        "Dumper", initial_url_count, initial_service_count
    );

    let progress_state = Arc::new(Mutex::new(ProgressState::default()));
    let progress_stop = Arc::new(AtomicBool::new(false));
    let ticker_handle = start_ticker(
        Arc::clone(&progress_state),
        Arc::clone(&progress_stop),
        Arc::clone(&progress_paused),
        Some(WriterHandle::clone(&dumper.writer)),
        dumper.verbosity,
    );

    let mut terminate_requested = false;
    // Holds a fatal error that broke out of the main loop early. Cleanup runs
    // unconditionally after the loop; this is returned at the end.
    let mut loop_error: Option<Error> = None;
    // Services whose prerequisites are currently being re-checked in a background
    // task. URLs for these services remain in `current_urls` but are not dispatched
    // until the check resolves.
    let mut prereq_in_flight: HashSet<Arc<str>> = HashSet::new();
    // Services whose token is being refreshed in a background task. Like
    // `prereq_in_flight`, their URLs stay in `current_urls` but are not dispatched
    // until `TokenRefreshed` arrives — otherwise they would be re-dispatched with
    // the stale token and immediately raise another expiration.
    let mut token_refresh_in_flight: HashSet<Arc<str>> = HashSet::new();
    // Timestamp of the last successful prereq re-check per service. Used to
    // short-circuit redundant re-checks when a burst of 4xx responses lands on
    // the same service within `prereqRecheckCacheSecs` of the last success.
    // When a 4xx arrives within that window, the URL keeps consuming its own
    // `urlRetryLimit` budget (and eventually hits UrlRetryLimit) instead of
    // re-spawning a check that we already know would pass.
    let mut prereq_last_success: HashMap<Arc<str>, Instant> = HashMap::new();
    // Consecutive throttled prerequisite re-checks per service. Bounds the
    // `PrereqOutcome::Throttled` retry loop so a persistently rate-limited
    // re-check cannot live-lock the run (see `record_prereq_throttle`).
    let mut prereq_throttle_attempts: HashMap<Arc<str>, usize> = HashMap::new();
    // (service, api) buckets whose expected-error breaker fired. Their pool
    // URLs were dropped when the trip event arrived; this set keeps filtering
    // the URLs that come back later (rate-limit re-queues, prereq re-queues)
    // so a tripped bucket stays skipped for the rest of the run.
    let mut tripped_apis: HashSet<(Arc<str>, String)> = HashSet::new();
    let prereq_cache = Duration::from_secs(Config::prereq_recheck_cache_secs(&dumper.config));
    // Background prerequisite re-check / prompt tasks. Invariant: every task
    // added here MUST enqueue its outcome event (`PrereqResult` / `ResumeService`)
    // before returning `Ok` — the event loop only un-pauses a service on that
    // event. A task that returns `Ok` without sending one would strand the
    // service (the panic/cancel case is caught via `join_next` below, but a
    // silent normal-return cannot be).
    let mut background_tasks = JoinSet::new();

    // Baseline memory sample at dump start; re-sampled periodically in the loop.
    sample_memory(dumper);
    let mut last_mem_sample = Instant::now();

    loop {
        // Periodic memory-observability sample (RSS + URL pool + response
        // workers), logged at debug for after-the-fact diagnosis. Gated to
        // MEM_SAMPLE_INTERVAL so it costs ~nothing during event bursts.
        if last_mem_sample.elapsed() >= MEM_SAMPLE_INTERVAL {
            last_mem_sample = Instant::now();
            sample_memory(dumper);
        }

        // 0. Events are processed every iteration, *including* while paused (a
        // SIGINT menu or an interactive prereq prompt is open). Draining
        // `RequestCompleted` during a pause keeps the AIMD concurrency counter and
        // the bounded event channel (8192) from filling up as in-flight requests
        // land — without it the producers would block and the pipeline could not
        // resume cleanly. Only *dispatch* (step 1) and *termination* (step 2) are
        // gated on the pause; the event wait in step 3 does the actual blocking.

        // 1. Dispatch pending URLs, skipping services under a prereq re-check or a
        // token refresh. Skip dispatch entirely once `loop_error` is set: an
        // inner-loop handler hit a fatal condition and we are on our way out, so
        // there is no point issuing more requests (the termination check below
        // breaks the loop). Skip while paused (`progress_paused > 0`): no new
        // requests are issued during a SIGINT menu / prereq prompt, but
        // already-dispatched ones still complete and are drained above.
        {
            // Services paused for dispatch: prereq re-check ∪ token refresh. Both
            // sets are usually empty, so borrow `prereq_in_flight` directly and
            // allocate a union only when a token refresh is in flight. Scoped to
            // this block so the borrow is released before the event handlers below
            // may mutate `prereq_in_flight` / `token_refresh_in_flight`.
            let dispatch_skip: Cow<HashSet<Arc<str>>> = if token_refresh_in_flight.is_empty() {
                Cow::Borrowed(&prereq_in_flight)
            } else {
                let mut s = prereq_in_flight.clone();
                s.extend(token_refresh_in_flight.iter().cloned());
                Cow::Owned(s)
            };
            if !terminate_requested
                && loop_error.is_none()
                && progress_paused.load(Ordering::Relaxed) == 0
                && let Err(e) = dispatch_requests(
                    dumper,
                    &request_sender,
                    &response_sender,
                    &progress_state,
                    &dispatch_skip,
                )
                .await
            {
                error!(
                    "{:FL$}Critical error during request dispatch: {:?}",
                    "Dumper", e
                );
                loop_error = Some(e);
                break;
            }
        }

        // 2. Check for termination.
        // `urls_empty` is true when every service has an empty queue. Services
        // with paused queues still have URLs, so the coordinator keeps waiting
        // for the `PrereqResult` event rather than terminating early.
        //
        // As defense-in-depth, termination is *also* gated on both paused-service
        // sets being empty. Today a paused service always has a re-queued URL (so
        // `urls_empty` is already false while a refresh/recheck is in flight),
        // making these two checks a no-op in every reachable state; pinning them
        // here means a future change to the re-queue path can't let the loop
        // terminate — and `abort_all` a live token refresh / prereq re-check — with
        // a service's work still pending (which would be silent data loss reported
        // as a normal completion). Both background tasks always emit their removal
        // event, so this can never hang.
        //
        // `loop_error` is also a termination trigger. The inner event loop can set
        // it and `break` only the *inner* loop (a permanently-failing
        // application-credential token refresh via `process_errors`, or an
        // application-credential prerequisite re-check failure), so the outer loop
        // must honor it here. Otherwise the run would live-lock (the token URL is
        // re-queued without consuming its retry budget and re-dispatched forever)
        // or stall (the failed service stays paused) instead of aborting cleanly
        // into a `.broken` archive.
        let in_flight = dumper.current_counter.load(Ordering::Acquire);
        let urls_empty = dumper.current_urls.iter().all(|r| r.value().is_empty());
        // Do not treat an idle pipeline as "done" while paused: a SIGINT menu or a
        // prereq prompt is open and the operator may still resume. A forced stop
        // sets `terminate_requested`, which is honored regardless of the pause.
        let is_paused = progress_paused.load(Ordering::Relaxed) > 0;

        if terminate_requested
            || loop_error.is_some()
            || (!is_paused
                && in_flight == 0
                && urls_empty
                && prereq_in_flight.is_empty()
                && token_refresh_in_flight.is_empty())
        {
            debug!(
                "{:FL$}Termination condition met (terminate_requested: {}, loop_error: {}, in_flight: {}, urls_empty: {}, prereq_in_flight: {}, token_refresh_in_flight: {}). Exiting.",
                "Dumper",
                terminate_requested,
                loop_error.is_some(),
                in_flight,
                urls_empty,
                prereq_in_flight.len(),
                token_refresh_in_flight.len()
            );
            break;
        }

        // 3. Wait for the next event (with stall detection).
        //
        // We also poll the background prerequisite-task JoinSet: if a task
        // panics or is cancelled before reporting its `PrereqResult`, the
        // affected service would otherwise stay in `prereq_in_flight` forever,
        // and the coordinator would wait on `recv()` indefinitely (a silent
        // stall, only surfaced every `stall_timeout` seconds). Detecting the
        // `JoinError` here turns that into a clean fatal error.
        let stall_timeout = Config::stall_detection_timeout(&dumper.config);
        // Poll at PAUSED_POLL_SECS instead of parking for the full stall timeout in
        // the two states where the loop must re-evaluate dispatch soon but no event
        // is guaranteed to wake it:
        //   1. Paused (`progress_paused > 0`): the SIGINT-menu resume only clears the
        //      pause counter and sends no event, so poll to notice the resume.
        //   2. Drained-but-pending: nothing in flight, dispatchable URLs still queued,
        //      and no background task pending. `dispatch_requests` always counts a
        //      dispatched call as in-flight, so this state is only reachable when the
        //      dispatch step above was skipped entirely — i.e. a resume that became
        //      visible *after* the dispatch gate read `progress_paused != 0` but
        //      *before* this check (a cross-thread race). With nothing in flight and
        //      no task to complete, only a poll re-dispatches; a full-stall-timeout
        //      park would delay the resume by up to `stall_timeout`.
        // `tasks_empty` is required in (2): when a refresh/recheck task IS pending its
        // completion event is the wake source, so we park on the select! below rather
        // than busy-poll for the task's whole duration. `early_poll` is captured before
        // the wait so the timeout handler tells an expected early wake from a real stall.
        let tasks_empty = background_tasks.is_empty();
        let early_poll = progress_paused.load(Ordering::Relaxed) > 0
            || (in_flight == 0 && !urls_empty && tasks_empty);
        let recv_timeout = if early_poll {
            stall_timeout.min(PAUSED_POLL_SECS)
        } else {
            stall_timeout
        };
        let recv_result = if tasks_empty {
            tokio::time::timeout(Duration::from_secs(recv_timeout), event_receiver.recv()).await
        } else {
            tokio::select! {
                biased;
                join = background_tasks.join_next() => {
                    match join {
                        Some(Err(join_err)) => {
                            error!(
                                "{:FL$}Background prerequisite task failed (panicked or cancelled): {}",
                                "Dumper", join_err
                            );
                            loop_error = Some(Error::StringError(format!(
                                "Background prerequisite task failed before reporting its result: {join_err}"
                            )));
                            break;
                        }
                        // `Some(Ok(()))`: the task completed normally and has
                        // already enqueued its `PrereqResult`/`ResumeService`
                        // event — loop around to process it. `None`: the set
                        // emptied between the `is_empty()` check and here.
                        _ => continue,
                    }
                }
                r = tokio::time::timeout(Duration::from_secs(recv_timeout), event_receiver.recv()) => r,
            }
        };

        match recv_result {
            Err(_timeout) => {
                // An early poll (we deliberately woke at PAUSED_POLL_SECS to re-check
                // dispatch — either paused, or drained-but-pending after a racing
                // resume; see `early_poll`) is expected, not a stall: loop back to
                // re-evaluate dispatch without emitting any diagnostic. This also keeps
                // the "Stall detected" error below from firing during a deliberate
                // pause.
                if early_poll {
                    continue;
                }
                let in_flight_now = dumper.current_counter.load(Ordering::Acquire);
                // Format a pause-set ("none" or a sorted comma list) for the stall
                // diagnostics below.
                let fmt_set = |set: &HashSet<Arc<str>>| -> String {
                    if set.is_empty() {
                        return "none".to_string();
                    }
                    let mut v: Vec<&str> = set.iter().map(|s| s.as_ref()).collect();
                    v.sort_unstable();
                    v.join(", ")
                };
                if in_flight_now > 0 {
                    // A real stall (requests in flight, no event): count it so the
                    // run-level `stall_events` figure in metadata.json flags runs
                    // that needed the watchdog, without grepping the log.
                    dumper.stats.record_stall();
                    let per_service = dumper.concurrency_controller.get_all_in_flight();
                    let mut active: Vec<String> = per_service
                        .iter()
                        .filter(|(_, n)| **n > 0)
                        .map(|(s, n)| format!("{}({})", s, n))
                        .collect();
                    active.sort();
                    error!(
                        "{:FL$}Stall detected ({}s, {} requests in flight). Active services: {}. Prereq-recheck in progress: {}. Token-refresh in progress: {}",
                        "Dumper",
                        stall_timeout,
                        in_flight_now,
                        if active.is_empty() {
                            "none".to_string()
                        } else {
                            active.join(", ")
                        },
                        fmt_set(&prereq_in_flight),
                        fmt_set(&token_refresh_in_flight)
                    );
                } else if !prereq_in_flight.is_empty() || !token_refresh_in_flight.is_empty() {
                    debug!(
                        "{:FL$}No event for {}s — waiting for prereq-recheck: {} / token-refresh: {}",
                        "Dumper",
                        stall_timeout,
                        fmt_set(&prereq_in_flight),
                        fmt_set(&token_refresh_in_flight)
                    );
                } else {
                    // Nothing in flight and no prereq re-check or token refresh
                    // running: the pipeline is idle, typically blocked on an
                    // interactive prompt (re-auth or a prerequisite the operator must
                    // fix). Leave a breadcrumb so a run that *looks* frozen is
                    // explained in the log instead of being silent even at TRACE.
                    debug!(
                        "{:FL$}No event for {}s with nothing in flight — pipeline idle (likely awaiting an interactive prompt)",
                        "Dumper", stall_timeout
                    );
                }
                // Do not exit: log and continue to allow recovery.
                continue;
            }
            Ok(None) => {
                error!(
                    "{:FL$}Event receiver disconnected — pipeline collapsed, aborting collection",
                    "Dumper"
                );
                loop_error = Some(Error::RecvError);
                break;
            }
            Ok(Some(event)) => {
                // Drain any immediately available events alongside the first one so
                // that a burst of completions is handled in a single coordinator
                // iteration rather than one per event.
                const MAX_DRAIN: usize = 256;
                let mut pending = Vec::with_capacity(32.min(MAX_DRAIN));
                pending.push(event);
                while pending.len() < MAX_DRAIN {
                    match event_receiver.try_recv() {
                        Ok(e) => pending.push(e),
                        Err(_) => break,
                    }
                }
                let mut pending_iter = pending.into_iter();
                while let Some(event) = pending_iter.next() {
                    match event {
                        // Prerequisite failure: re-queue the URL and, if no check is already
                        // running for this service, spawn one.
                        CoordinatorEvent::NewError(
                            service,
                            ProcessError::PotentialPrerequisiteError(url),
                        ) => {
                            trace!(
                                "{:FL$}Received PotentialPrerequisiteError for service {:?}, url {:?}",
                                "Dumper", service, url.url
                            );
                            if tripped_apis.contains(&(service.clone(), url.api.clone())) {
                                // The bucket's breaker fired: this re-queue is
                                // skipped like its pool siblings, and no
                                // prerequisite re-check is spawned for it.
                                dumper
                                    .stats
                                    .record_breaker_skipped(&url.service_name, &url.api, 1);
                                continue;
                            }
                            dumper
                                .stats
                                .record_prereq_trigger(&url.service_name, &url.api);
                            let trigger_url = url.url.clone();

                            let cache_hit = !prereq_cache.is_zero()
                                && prereq_last_success
                                    .get(&service)
                                    .is_some_and(|t| t.elapsed() < prereq_cache);

                            dumper
                                .current_urls
                                .entry(service.clone())
                                .or_default()
                                .push(*url);

                            if dumper.config.no_check.unwrap_or(false) || cache_hit {
                                if cache_hit {
                                    trace!(
                                        "{:FL$}Prereq recently re-verified for {:?} (within {}s), skipping re-check; URL will consume its own retry budget",
                                        "Dumper",
                                        service,
                                        prereq_cache.as_secs()
                                    );
                                } else {
                                    // noCheck is enabled (cache_hit is false here): the
                                    // URL is re-queued without a re-check and drains its
                                    // own retry budget. Trace it like the cache-hit branch
                                    // so the no_check path is not silent.
                                    trace!(
                                        "{:FL$}noCheck enabled: re-queued URL for {:?} without prereq re-check; URL will consume its own retry budget",
                                        "Dumper", service
                                    );
                                }
                            } else if prereq_in_flight.contains(&service)
                                || token_refresh_in_flight.contains(&service)
                            {
                                // A token refresh in flight for this service is about to
                                // resume it with a fresh token; spawning a prereq check now
                                // would race the refresh and, in the real-expiry window,
                                // could read a 401/403 and abort despite a valid refresh.
                                trace!(
                                    "{:FL$}Prereq check or token refresh already in flight for {:?}, skipping spawn",
                                    "Dumper", service
                                );
                            } else if prereq_throttle_attempts
                                .get(service.as_ref())
                                .copied()
                                .unwrap_or(0)
                                >= MAX_PREREQ_THROTTLE_RETRIES
                            {
                                // Throttle budget was exhausted in a prior episode.
                                // Skip spawning a new check; the re-queued URL will
                                // drain its own urlRetryLimit budget instead.
                                trace!(
                                    "{:FL$}Prereq throttle budget exhausted for {:?}, skipping re-check; URL will drain its own retry budget",
                                    "Dumper", service
                                );
                            } else {
                                match dumper.tokens.get(&service) {
                                    None => {
                                        warn!(
                                            "{:FL$}No token for service {:?} when handling PotentialPrerequisiteError, counting as dump error",
                                            "Dumper", service
                                        );
                                        dumper.errors_number += 1;
                                        dumper.missing_token_errors_number += 1;
                                    }
                                    Some(_) => {
                                        // Pause accounting: a service enters the paused
                                        // union when it joins either gating set while
                                        // absent from the other (overlapping causes are
                                        // one union interval).
                                        if prereq_in_flight.insert(Arc::clone(&service))
                                            && !token_refresh_in_flight.contains(&service)
                                        {
                                            dumper.stats.note_service_paused(&service);
                                        }
                                        dumper.stats.record_prereq_recheck(&service);
                                        // `warn!` (not `debug!`): a transient prerequisite
                                        // loss pauses the service for a re-check and is a
                                        // recoverable problem worth surfacing on the default
                                        // (Normal) console, not just in the file log. This
                                        // also counts toward the end-of-run warning tally.
                                        warn!(
                                            "{:FL$}Prerequisite re-check triggered for service {:?} — pausing it until the check resolves (URL: {})",
                                            "Dumper", service, trigger_url
                                        );
                                        let tokens = Arc::clone(&dumper.tokens);
                                        let oradaz_client = dumper.oradaz_client.clone();
                                        let config = dumper.config.clone();
                                        let sender = event_sender.clone();
                                        let svc = Arc::clone(&service);
                                        background_tasks.spawn(async move {
                                            prereq_check_task(
                                                svc,
                                                tokens,
                                                oradaz_client,
                                                config,
                                                sender,
                                            )
                                            .await;
                                        });
                                    }
                                }
                            }
                        }

                        // Token expired: refresh off the event loop so a slow
                        // (application-credential) or unbounded (interactive)
                        // refresh cannot freeze the coordinator. The request thread
                        // already re-queued the URL via `RequestCompleted`; pausing
                        // the service here keeps that URL from being re-dispatched
                        // with the stale token until `TokenRefreshed` arrives.
                        CoordinatorEvent::NewError(service, ProcessError::TokenExpirationError) => {
                            // `insert` returns true only the first time, so N
                            // simultaneous expirations for one service spawn exactly
                            // one refresh task (which itself double-checks under
                            // `refresh_lock`).
                            if token_refresh_in_flight.insert(Arc::clone(&service)) {
                                dumper.stats.record_token_refresh(&service);
                                if !prereq_in_flight.contains(&service) {
                                    dumper.stats.note_service_paused(&service);
                                }
                                warn!(
                                    "{:FL$}Token expired for service {:?} — refreshing in the background; pausing its dispatch until done",
                                    "Dumper", service
                                );
                                let tokens = Arc::clone(&dumper.tokens);
                                let config = dumper.config.clone();
                                let oradaz_client = dumper.oradaz_client.clone();
                                let sender = event_sender.clone();
                                let svc = Arc::clone(&service);
                                background_tasks.spawn(async move {
                                    token_refresh_task(svc, tokens, config, oradaz_client, sender)
                                        .await;
                                });
                            } else {
                                trace!(
                                    "{:FL$}Token refresh already in flight for service {:?}, skipping spawn",
                                    "Dumper", service
                                );
                            }
                        }

                        CoordinatorEvent::NewError(service, error) => {
                            trace!(
                                "{:FL$}Received NewError for service {:?}, error: {:?}",
                                "Dumper", service, error
                            );
                            match process_errors(dumper, &service, error).await {
                                Ok(Some(url)) => {
                                    let kept = drop_tripped_urls(
                                        dumper,
                                        &tripped_apis,
                                        &service,
                                        vec![url],
                                    );
                                    if !kept.is_empty() {
                                        dumper
                                            .current_urls
                                            .entry(service)
                                            .or_default()
                                            .extend(kept);
                                    }
                                }
                                Ok(None) => {}
                                Err(e) => {
                                    // Drain remaining pending events before propagating: each
                                    // unprocessed RequestCompleted would leave current_counter
                                    // inflated, causing an indefinite stall in the coordinator.
                                    for remaining in pending_iter {
                                        if let CoordinatorEvent::RequestCompleted {
                                            service,
                                            new_urls,
                                            count,
                                            id: _,
                                        } = remaining
                                        {
                                            dumper
                                                .current_counter
                                                .fetch_sub(count, Ordering::Release);
                                            if !new_urls.is_empty() {
                                                dumper
                                                    .current_urls
                                                    .entry(service)
                                                    .or_default()
                                                    .extend(new_urls);
                                            }
                                        }
                                    }
                                    loop_error = Some(e);
                                    break;
                                }
                            }
                        }

                        CoordinatorEvent::RequestCompleted {
                            service,
                            new_urls,
                            count,
                            id: _,
                        } => {
                            trace!(
                                "{:FL$}RequestCompleted for service {:?}: count={}, new_urls={}",
                                "Dumper",
                                service,
                                count,
                                new_urls.len()
                            );
                            dumper.current_counter.fetch_sub(count, Ordering::Release);
                            if !new_urls.is_empty() {
                                let new_urls =
                                    drop_tripped_urls(dumper, &tripped_apis, &service, new_urls);
                                if !new_urls.is_empty() {
                                    dumper
                                        .current_urls
                                        .entry(service)
                                        .or_default()
                                        .extend(new_urls);
                                }
                            }
                            {
                                let mut prog = lock_force(&progress_state);
                                prog.in_flight =
                                    dumper.current_counter.load(Ordering::Relaxed) as u64;
                                prog.concurrency_windows =
                                    dumper.concurrency_controller.get_all_windows();
                            }
                        }

                        CoordinatorEvent::Terminate => {
                            debug!(
                                "{:FL$}Terminate event received — stopping dispatch and draining in-flight requests",
                                "Dumper"
                            );
                            terminate_requested = true;
                            break;
                        }

                        CoordinatorEvent::BreakerTripped { service, api } => {
                            // First trip for this bucket: drop its pending pool
                            // URLs as skipped; the set keeps filtering later
                            // re-queues. URLs already in flight complete
                            // normally (their declared-expected errors are
                            // recorded as usual).
                            if tripped_apis.insert((Arc::clone(&service), api.clone())) {
                                let mut dropped: usize = 0;
                                if let Some(mut urls) = dumper.current_urls.get_mut(&service) {
                                    let before = urls.len();
                                    urls.retain(|u| u.api != api);
                                    dropped = before - urls.len();
                                }
                                dumper.stats.record_breaker_skipped(&service, &api, dropped);
                                warn!(
                                    "{:FL$}Expected-error breaker for {:?}/{:?}: {} pending URL(s) skipped; later re-queues for this API will be skipped as well",
                                    "Dumper", service, api, dropped
                                );
                            }
                        }

                        CoordinatorEvent::PrereqResult(service, outcome) => match outcome {
                            PrereqOutcome::Success => {
                                info!(
                                    "{:FL$}Prerequisites re-verified for {:?}, resuming dispatch",
                                    "Dumper", service
                                );
                                // Pause accounting: the union interval closes only when
                                // the service leaves *both* gating sets.
                                if prereq_in_flight.remove(&service)
                                    && !token_refresh_in_flight.contains(&service)
                                {
                                    dumper.stats.note_service_resumed(&service);
                                }
                                prereq_throttle_attempts.remove(&service);
                                prereq_last_success.insert(Arc::clone(&service), Instant::now());
                            }
                            PrereqOutcome::Throttled(sec) => {
                                if record_prereq_throttle(
                                    &mut prereq_throttle_attempts,
                                    &service,
                                    MAX_PREREQ_THROTTLE_RETRIES,
                                ) {
                                    // Bounded safety net: a prereq re-check that stays
                                    // throttled past the budget would otherwise loop
                                    // forever, keeping the service paused and the run
                                    // live-locked. Stop re-checking and resume dispatch.
                                    // Termination is then guaranteed by the normal
                                    // per-URL machinery: each resumed 4xx runs
                                    // `prepare_retries` (advancing `retry_number`) before
                                    // re-raising the prereq error, so every URL is
                                    // abandoned after `urlRetryLimit` (→ UrlRetryLimit
                                    // DumpError) and the queue drains; a 429 on resume
                                    // drains the rate-limit budget instead.
                                    warn!(
                                        "{:FL$}Prerequisite re-check for {:?} stayed throttled for {} attempts; abandoning the re-check and resuming dispatch (its URLs will drain their own retry budget)",
                                        "Dumper", service, MAX_PREREQ_THROTTLE_RETRIES
                                    );
                                    if prereq_in_flight.remove(&service)
                                        && !token_refresh_in_flight.contains(&service)
                                    {
                                        dumper.stats.note_service_resumed(&service);
                                    }
                                } else {
                                    debug!(
                                        "{:FL$}Prereq throttled for {:?}, sleeping {}s then retrying",
                                        "Dumper", service, sec
                                    );
                                    let sender = event_sender.clone();
                                    let svc = Arc::clone(&service);
                                    background_tasks.spawn(async move {
                                        tokio::time::sleep(Duration::from_secs(sec)).await;
                                        if let Err(err) =
                                            sender.send(CoordinatorEvent::ResumeService(svc)).await
                                        {
                                            warn!(
                                                "{:FL$}Failed to send ResumeService event to coordinator: {:?}",
                                                "Dumper", err
                                            );
                                        }
                                    });
                                }
                            }

                            PrereqOutcome::Failure(msg) => {
                                // A failure ends this throttle episode (fatal for
                                // app-cred; prompt-then-resume for interactive), so
                                // reset the budget — a fresh episode after the user
                                // fixes the issue starts from zero, like Success does.
                                prereq_throttle_attempts.remove(&service);
                                // Abort to `.broken` when there is no operator to
                                // prompt: application credentials (no interaction by
                                // design) OR a non-TTY stdin (piped/redirected, e.g. a
                                // container or CI run). Prompting a closed stdin would
                                // read EOF instantly and loop forever.
                                if Config::use_application_credentials_auth(&dumper.config)
                                    || !std::io::stdin().is_terminal()
                                {
                                    error!(
                                        "{:FL$}Prerequisite re-check failed for {:?} and cannot prompt (application credentials or non-interactive stdin): {}",
                                        "Dumper", service, msg
                                    );
                                    dumper.write_prerequisite_error(&service, &msg).await;
                                    loop_error = Some(Error::StringError(format!(
                                        "Prerequisite re-check failed: {}",
                                        msg
                                    )));
                                    break;
                                } else {
                                    info!(
                                        "{:FL$}Prerequisite check failed for {:?} — prompting user to fix and resume",
                                        "Dumper", service
                                    );
                                    let sender = event_sender.clone();
                                    let paused = Arc::clone(&progress_paused);
                                    let svc = Arc::clone(&service);
                                    let prompt = Arc::clone(&dumper.prompt);
                                    background_tasks.spawn(async move {
                                        prompt_and_resume_task(svc, msg, sender, paused, prompt)
                                            .await;
                                    });
                                }
                            }
                        },

                        CoordinatorEvent::ResumeService(service) => {
                            if token_refresh_in_flight.contains(&service) {
                                // A token refresh is in flight for this service: the
                                // prereq re-check would run with the stale token and,
                                // in the real-expiry window, could read a 401/403 and
                                // abort despite a valid refresh. Defer and re-send the
                                // resume; the service stays gated via
                                // token_refresh_in_flight meanwhile.
                                info!(
                                    "{:FL$}ResumeService for {:?} deferred: token refresh in flight",
                                    "Dumper", service
                                );
                                let sender = event_sender.clone();
                                let svc = Arc::clone(&service);
                                background_tasks.spawn(async move {
                                    tokio::time::sleep(Duration::from_secs(RESUME_DEFER_SECS))
                                        .await;
                                    if let Err(err) = sender
                                        .send(CoordinatorEvent::ResumeService(Arc::clone(&svc)))
                                        .await
                                    {
                                        // Send fails only when the coordinator has
                                        // exited (run ending) — nothing left to resume.
                                        trace!(
                                            "{:FL$}Deferred ResumeService for {:?} not delivered (coordinator gone): {:?}",
                                            "Dumper", svc, err
                                        );
                                    }
                                });
                            } else {
                                info!(
                                    "{:FL$}ResumeService for {:?} — spawning new prereq re-check",
                                    "Dumper", service
                                );
                                // Re-insert into prereq_in_flight so the service stays
                                // gated during the new check (defense-in-depth: the
                                // service should already be present in the common paths,
                                // but an unexpected remove between the Throttled sleep and
                                // this handler would otherwise open a dispatch window).
                                if prereq_in_flight.insert(Arc::clone(&service))
                                    && !token_refresh_in_flight.contains(&service)
                                {
                                    dumper.stats.note_service_paused(&service);
                                }
                                dumper.stats.record_prereq_recheck(&service);
                                let tokens = Arc::clone(&dumper.tokens);
                                let oradaz_client = dumper.oradaz_client.clone();
                                let config = dumper.config.clone();
                                let sender = event_sender.clone();
                                let svc = Arc::clone(&service);
                                background_tasks.spawn(async move {
                                    prereq_check_task(svc, tokens, oradaz_client, config, sender)
                                        .await;
                                });
                            }
                        }

                        CoordinatorEvent::TokenRefreshed(service) => {
                            info!(
                                "{:FL$}Token refreshed for service {:?} — dispatch unblocked",
                                "Dumper", service
                            );
                            if token_refresh_in_flight.remove(&service)
                                && !prereq_in_flight.contains(&service)
                            {
                                dumper.stats.note_service_resumed(&service);
                            }
                        }

                        CoordinatorEvent::TokenRefreshFailed {
                            service,
                            auth_error,
                            message,
                        } => {
                            // Permanent refresh failure — application credentials
                            // only (interactive re-auth retries without limit). Record
                            // any definitive auth error, then abort the run cleanly
                            // into a `.broken` archive, mirroring the app-cred
                            // prerequisite-failure path.
                            if token_refresh_in_flight.remove(&service)
                                && !prereq_in_flight.contains(&service)
                            {
                                dumper.stats.note_service_resumed(&service);
                            }
                            if let Some(ae) = auth_error {
                                dumper.write_auth_error(ae).await;
                            }
                            error!(
                                "{:FL$}Token refresh failed for service {:?}: {}",
                                "Dumper", service, message
                            );
                            loop_error = Some(Error::StringError(message));
                            break;
                        }
                    }
                }
            }
        }
    }

    progress_stop.store(true, Ordering::Relaxed);

    if terminate_requested || loop_error.is_some() {
        background_tasks.abort_all();
    } else {
        while background_tasks.join_next().await.is_some() {}
    }

    // Use spawn_blocking to avoid blocking a tokio worker thread while the
    // OS thread ticker joins.
    tokio::task::spawn_blocking(move || {
        let _ = ticker_handle.join();
    })
    .await
    .unwrap_or_else(|e| warn!("{:FL$}Error joining ticker thread: {:?}", "Dumper", e));
    // Final summary of network activity
    let total_calls: usize = dumper
        .stats
        .services
        .iter()
        .map(|s| {
            let svc = s.value();
            svc.http_single_calls.load(Ordering::Relaxed)
                + svc.http_batch_calls.load(Ordering::Relaxed)
        })
        .sum();
    let total_failures: usize = dumper
        .stats
        .services
        .iter()
        .map(|s| s.value().http_call_failures.load(Ordering::Relaxed))
        .sum();
    let retries = crate::collect::dump::request::RETRY_COUNT.load(Ordering::Relaxed);
    clear_progress_line();
    finalize_performing_collect_label();
    println!();
    info!(
        "{:FL$}Summary: total calls={}, successes={}, failures={}, retries={}",
        "Dumper",
        total_calls,
        total_calls.saturating_sub(total_failures),
        total_failures,
        retries
    );

    if let Some(e) = loop_error {
        return Err(e);
    }
    Ok(!terminate_requested)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    /// Guards the invariant that a panicking background prerequisite task is
    /// detected as a `JoinError` and not silently lost. Without this detection
    /// the affected service would stay in `prereq_in_flight` indefinitely.
    /// This mirrors the `biased; join_next()` vs `recv()` select arm in
    /// `coordinate()`.
    #[tokio::test]
    async fn panicking_background_task_is_detected_not_lost() {
        let mut background_tasks: JoinSet<()> = JoinSet::new();
        background_tasks.spawn(async {
            panic!("simulated prereq task panic");
        });

        // An event channel that never produces an event — without the
        // join_next() arm the coordinator would block here indefinitely.
        let (_tx, mut rx) = mpsc::channel::<u8>(1);

        tokio::select! {
            biased;
            join = background_tasks.join_next() => {
                match join {
                    Some(Err(join_err)) => {
                        assert!(join_err.is_panic(), "expected a panic JoinError");
                    }
                    other => panic!("expected Some(Err(panic)), got {other:?}"),
                }
            }
            _ = tokio::time::timeout(Duration::from_secs(5), rx.recv()) => {
                panic!("recv arm fired — the panicking task was not detected");
            }
        }
    }

    /// A normally-completing background task is reported as `Some(Ok(()))`, the
    /// case the coordinator treats as "loop around and process the event the
    /// task already enqueued" rather than a fatal error.
    #[tokio::test]
    async fn completed_background_task_reports_ok() {
        let mut background_tasks: JoinSet<()> = JoinSet::new();
        background_tasks.spawn(async {});
        match background_tasks.join_next().await {
            Some(Ok(())) => {}
            other => panic!("expected Some(Ok(())), got {other:?}"),
        }
    }

    /// `record_prereq_throttle` bounds the consecutive-throttle budget and keeps
    /// the entry at `cap` on exhaustion (burned state), so the
    /// `PotentialPrerequisiteError` handler can detect it and skip spawning a
    /// new check — preventing unbounded inter-episode re-check cycles.
    #[test]
    fn prereq_throttle_budget_is_bounded_and_stays_burned() {
        let mut attempts: HashMap<Arc<str>, usize> = HashMap::new();
        let svc: Arc<str> = Arc::from("resources");
        let cap = 3;
        assert!(!record_prereq_throttle(&mut attempts, &svc, cap)); // attempt 1
        assert!(!record_prereq_throttle(&mut attempts, &svc, cap)); // attempt 2
        assert!(record_prereq_throttle(&mut attempts, &svc, cap)); // attempt 3 → exhausted
        // Entry stays at `cap` (not removed) — the burned state persists so
        // the PotentialPrerequisiteError handler skips the next spawn.
        assert_eq!(attempts.get(svc.as_ref()).copied(), Some(cap));
        // Resetting (as Success/Failure do) allows a fresh episode.
        attempts.remove(&svc);
        assert!(!record_prereq_throttle(&mut attempts, &svc, cap)); // fresh attempt 1
    }
}
