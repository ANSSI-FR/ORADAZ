use crate::FL;
use crate::collect::dump::Dumper;
use crate::collect::dump::request::RequestMsg;
use crate::collect::dump::response::{DumpError, ResponseMsg};
use crate::utils::config::Config;
use crate::utils::errors::Error;
use crate::utils::mutex::lock_force;
use crate::utils::ui::progress::ProgressState;
use crate::utils::url::{ApiCall, ApiCallItem, RetryLimits};

use log::{debug, error, trace, warn};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::{Permit, Sender};

/// Global counter for assigning unique request IDs for traceability.
/// Matches `ApiCall.id` (`u32`); a wrap after 2^32 requests is harmless for IDs.
pub static REQUEST_ID_GEN: AtomicU32 = AtomicU32::new(1);

/// Upper bound on the number of URLs consumed by a single `ApiCall::from()` call.
/// Graph and Resources batch up to 20 URLs per call; the default handler pops exactly 1.
/// Used to limit the tail-slice clone to O(20) instead of O(N) per dispatch iteration.
const MAX_BATCH_SIZE: usize = 20;

/// Dispatches available URLs as API calls to the request module.
///
/// Services listed in `paused_services` are skipped — their URLs remain in
/// `current_urls` and will be dispatched once the corresponding
/// `CoordinatorEvent::PrereqResult` (with a successful `PrereqOutcome`) is
/// received.
pub async fn dispatch_requests(
    dumper: &mut Dumper,
    request_sender: &Sender<RequestMsg>,
    response_sender: &Sender<ResponseMsg>,
    progress_state: &Arc<Mutex<ProgressState>>,
    paused_services: &HashSet<Arc<str>>,
) -> Result<(), Error> {
    trace!("{:FL$}Dispatching requests", "Dumper");

    let mut items_sent_in_burst = 0;
    // Holds a fatal ApiCall construction error so it can be handled after the
    // DashMap iterator exits (std::sync locks must not be held across .await).
    let mut critical_error: Option<Error> = None;

    // `url_retry_limit` is a global parameter; the two rate-limit budgets are
    // per-service to let `resources` (heavy ARM throttling) carry a much larger
    // budget than `graph` without inflating the global default. Built per
    // service inside the dispatch loop below.
    let global_url_retry = Config::url_retry_limit(&dumper.config);
    let burst_cap = Config::dispatch_burst_cap(&dumper.config);

    enum SenderPermit<'a> {
        Request(Permit<'a, RequestMsg>),
        Response(Permit<'a, ResponseMsg>),
    }

    'dispatch: for mut entry in dumper.current_urls.iter_mut() {
        if items_sent_in_burst >= burst_cap {
            debug!(
                "{:FL$}dispatch_burst_cap ({}) reached at outer service loop (items_sent={})",
                "Dumper", burst_cap, items_sent_in_burst
            );
            break;
        }
        let service = entry.key().clone();
        if paused_services.contains(&service) {
            trace!(
                "{:FL$}Skipping dispatch for service {:?} (paused)",
                "Dumper", service
            );
            continue;
        }
        let urls = entry.value_mut();

        while !urls.is_empty() {
            if items_sent_in_burst >= burst_cap {
                debug!(
                    "{:FL$}dispatch_burst_cap ({}) reached at inner url loop (items_sent={})",
                    "Dumper", burst_cap, items_sent_in_burst
                );
                break;
            }

            // Clone only the tail slice that ApiCall::from() will consume (at most
            // MAX_BATCH_SIZE items) to avoid an O(N²) allocation across iterations.
            //
            // LOAD-BEARING: dispatch drains from the *tail* and `ApiCall::from`
            // pops from the back, so the most-recently-discovered URLs (a page's
            // children, extended onto the tail) go out before older ones (the page's
            // `nextLink`, pushed first — see `response/status_handlers.rs`). That
            // depth-first order bounds the `current_urls` pool. The
            // `truncate(tail_start + urls_copy.len())` below is only correct because
            // `ApiCall::from` consumes from the *back* of `urls_copy`; draining from
            // the front would keep the wrong items and corrupt the queue.
            let peek_len = urls.len().min(MAX_BATCH_SIZE);
            let tail_start = urls.len() - peek_len;
            let mut urls_copy = urls[tail_start..].to_vec();

            // Build retry budgets for *this* service so per-service overrides
            // apply. `url_retry_limit` stays global.
            let limits = RetryLimits {
                retry: global_url_retry,
                rate_limit_retry: Config::rate_limit_retry_limit_for(&dumper.config, &service),
                rate_limit_max_wait_secs: Config::rate_limit_max_wait_secs_for(
                    &dumper.config,
                    &service,
                ),
            };

            match ApiCall::from(&service, &mut urls_copy, limits) {
                Ok(items) => {
                    let mut permits = Vec::new();
                    let mut all_reserved = true;
                    let mut api_call_count = 0;

                    for item in &items {
                        match item {
                            ApiCallItem::ApiCall(_) => {
                                api_call_count += 1;
                                match request_sender.try_reserve() {
                                    Ok(p) => permits.push(SenderPermit::Request(p)),
                                    Err(_) => {
                                        all_reserved = false;
                                        break;
                                    }
                                }
                            }
                            ApiCallItem::ApiCallError(_) => match response_sender.try_reserve() {
                                Ok(p) => permits.push(SenderPermit::Response(p)),
                                Err(_) => {
                                    all_reserved = false;
                                    break;
                                }
                            },
                        }
                    }

                    if all_reserved {
                        let item_count = items.len();
                        for (item, permit) in items.into_iter().zip(permits) {
                            match (item, permit) {
                                (ApiCallItem::ApiCall(mut api_call), SenderPermit::Request(p)) => {
                                    let id = REQUEST_ID_GEN.fetch_add(1, Ordering::SeqCst);
                                    api_call.id = id;
                                    if let Some(batch_data) = &mut api_call.batch_data {
                                        for inner_call in batch_data.initial_data.values_mut() {
                                            inner_call.id = id;
                                        }
                                    }
                                    match (api_call.is_batch, &api_call.batch_data) {
                                        (true, Some(batch_data)) => {
                                            // Graph and Resources batches are
                                            // always single-service; the wrapper
                                            // URL carries that service. Pass it
                                            // explicitly so service-level counters
                                            // stay correct even if the inner map
                                            // is unexpectedly empty.
                                            let pairs: Vec<(String, String)> = batch_data
                                                .initial_data
                                                .values()
                                                .map(|inner| {
                                                    (
                                                        inner.url.service_name.clone(),
                                                        inner.url.api.clone(),
                                                    )
                                                })
                                                .collect();
                                            dumper.stats.record_batch_dispatch(
                                                &api_call.url.service_name,
                                                pairs,
                                            );
                                        }
                                        (false, _) => {
                                            dumper.stats.record_single_dispatch(
                                                &api_call.url.service_name,
                                                &api_call.url.api,
                                            );
                                        }
                                        // is_batch == true but no batch_data: the
                                        // request thread will surface a DumpError
                                        // (`MissingBatchData`) without making an
                                        // HTTP call, so don't increment counters.
                                        (true, None) => {}
                                    }
                                    trace!(
                                        "{:FL$}Dispatched api_call [ID: {}] for service {:?}",
                                        "Dumper", id, &api_call.url.service_name
                                    );
                                    p.send(RequestMsg::ApiCall(api_call));
                                }
                                (
                                    ApiCallItem::ApiCallError(Error::UrlRetryLimit(url)),
                                    SenderPermit::Response(p),
                                ) => {
                                    let id = REQUEST_ID_GEN.fetch_add(1, Ordering::SeqCst);
                                    // Lookup the dominant upstream code BEFORE
                                    // recording the synthetic "UrlRetryLimit"
                                    // marker, so that marker is filtered out
                                    // anyway in the helper but the read stays
                                    // clean even if it weren't.
                                    let dominant_code = dumper
                                        .stats
                                        .dominant_upstream_code(&url.service_name, &url.api);
                                    // `check_retry_exhaustion` only abandons on
                                    // the *permanent* budget (real 4xx/5xx in
                                    // `retry_number`); 429 / network do not
                                    // exhaust here (they are
                                    // bounded by the liveness ceiling and
                                    // abandoned as ThrottleStalled / NetworkStalled
                                    // at the re-queue sites). So a `UrlRetryLimit`
                                    // reaching this branch is always a real-error
                                    // exhaustion — never throttling.
                                    let rate_limit_exhausted = false;
                                    // Surface the give-up in stats.json so a
                                    // user inspecting an archive can see which
                                    // APIs exhausted their retry budget.
                                    dumper.stats.record_upstream_error_code(
                                        &url.service_name,
                                        &url.api,
                                        "UrlRetryLimit",
                                    );
                                    let message =
                                        crate::utils::errors::human_retry_exhaustion_message(
                                            &url,
                                            dominant_code.as_deref(),
                                            rate_limit_exhausted,
                                        );
                                    // Surface the give-up in the log (not just in
                                    // stats.json / errors.json): a URL abandoned
                                    // after exhausting its retry budget means data
                                    // was not collected — worth a warn.
                                    warn!(
                                        "{:FL$}Giving up on {}/{} after exhausting its retry budget [ID: {}]: {}",
                                        "Dumper", url.service_name, url.api, id, message
                                    );
                                    p.send(ResponseMsg::DumpError(
                                        Box::new(DumpError {
                                            folder: url.service_name.clone(),
                                            file: url.api.clone(),
                                            url: url.url.clone(),
                                            status: 0,
                                            code: String::from("UrlRetryLimit"),
                                            message,
                                            expected: false,
                                            full_response: None,
                                            post_data: None,
                                        }),
                                        id,
                                    ));
                                }
                                (ApiCallItem::ApiCallError(err), SenderPermit::Response(p)) => {
                                    let id = REQUEST_ID_GEN.fetch_add(1, Ordering::SeqCst);
                                    warn!(
                                        "{:FL$}Failed to create ApiCall for service {:?} [ID: {}]: {:?}",
                                        "Dumper", service, id, err
                                    );
                                    p.send(ResponseMsg::DumpError(Box::new(DumpError {
                                        folder: service.to_string(),
                                        file: String::new(),
                                        url: String::new(),
                                        status: 0,
                                        code: String::from("UnknownApiCallCreationError"),
                                        message: format!(
                                            "Error {:?} while getting next ApiCall for service {:?}",
                                            err, service
                                        ),
                                        expected: false,
                                        full_response: None,
                                        post_data: None,
                                    }), id));
                                }
                                // The construction loop (above) guarantees that an
                                // ApiCallItem::ApiCall is always zipped with a
                                // SenderPermit::Request, and ApiCallItem::ApiCallError
                                // with a SenderPermit::Response. This arm is therefore
                                // unreachable in correct code; returning an error here
                                // (rather than panicking) ensures the archive is
                                // properly renamed .broken if this invariant is violated.
                                (_item, _permit) => {
                                    error!(
                                        "{:FL$}BUG: unexpected (ApiCallItem, SenderPermit) combination for service {:?}",
                                        "Dumper", service
                                    );
                                    return Err(Error::StringError(
                                        "internal error: mismatched (ApiCallItem, SenderPermit) in dispatch"
                                            .into(),
                                    ));
                                }
                            }
                        }

                        urls.truncate(tail_start + urls_copy.len());
                        dumper
                            .current_counter
                            .fetch_add(item_count, Ordering::Release);
                        dumper.requests_number += api_call_count;
                        items_sent_in_burst += item_count;

                        // Refresh the progress counters on every burst so the
                        // displayed sent/in-flight counts stay current.
                        {
                            let mut prog = lock_force(progress_state);
                            prog.sent = dumper.requests_number as u64;
                            prog.in_flight = dumper.current_counter.load(Ordering::Acquire) as u64;
                        }
                    } else {
                        return Ok(());
                    }
                }
                Err(err) => {
                    // Break out of the DashMap iterator before awaiting so the
                    // shard lock is released prior to the exit_with_error call.
                    critical_error = Some(err);
                    break 'dispatch;
                }
            }
        }
    }

    if let Some(err) = critical_error {
        error!(
            "{:FL$}Fatal error building API calls during dispatch, aborting collection: {:?}",
            "Dumper", err
        );
        dumper
            .exit_with_error(Error::StringError(format!("{:?}", err)))
            .await;
        return Err(Error::ChannelError);
    }

    Ok(())
}
