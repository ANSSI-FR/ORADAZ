use crate::FL;
use crate::collect::dump::orchestration::events::{CoordinatorEvent, ProcessError};
use crate::collect::dump::request::{BackoffGuard, RETRY_COUNT, compute_backoff_ms};
use crate::collect::dump::response::single::value_handlers;
use crate::collect::dump::response::thread::ResponseThread;
use crate::collect::dump::response::{ApiCall, Response};
use crate::utils::ui::dump_event;
use crate::utils::url::Url;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

pub async fn report_too_many_requests(
    this: &ResponseThread,
    response: &Response,
    api_call: &ApiCall,
) {
    // Handle HTTP status code 429 - Too many requests. `effective` is the
    // resolved cooldown (server `Retry-After`, else the configured default,
    // clamped to `rateLimitMaxWaitSecs`) used for the logged message, so a
    // header-less 429 still reports the default it will back off by.
    //
    // The rate-limit manager is given the *raw* `response.retry_after` instead:
    // it resolves and clamps internally (yielding the same cooldown) and counts
    // each clamp. Passing the already-clamped `effective` would make its internal
    // `raw == capped`, so the clamp would never be observed.
    let effective = this
        .context
        .ratelimit_manager
        .effective_retry_after(&api_call.url.service_name, response.retry_after);
    // Provenance of the cooldown: server-provided `Retry-After` vs the configured
    // default (`response.retry_after` is the raw value, before fallback). This site
    // fires once per single 429, once per batch envelope 429, AND once per sub-429
    // inside a 2xx batch, so the split covers every 429 path. Informs
    // `defaultRetryAfterSeconds` sizing.
    this.context
        .stats
        .record_retry_after_provenance(&api_call.url.service_name, response.retry_after);
    if api_call.is_batch {
        // Batch envelope 429: service-level cooldown only. The envelope is not
        // a data bucket (its sub-requests span many APIs), so it must not feed
        // the per-bucket escalation — nothing would ever reset its streak.
        this.context
            .ratelimit_manager
            .report_429(&api_call.url.service_name, response.retry_after);
    } else {
        // Single request or batch sub-response: also count into the
        // (service, api) bucket's escalation streak, so an endpoint stuck on a
        // long-refill server quota gets paced individually.
        this.context.ratelimit_manager.report_429_bucket(
            &api_call.url.service_name,
            &api_call.url.api,
            response.retry_after,
        );
    }
    // The AIMD concurrency-window halving is intentionally NOT done here.
    // This runs once per single 429, once per batch *envelope* 429, AND once per
    // *sub*-429 inside a 2xx batch — halving here would collapse the window N
    // times for one throttled batch. The window is adjusted exactly once per HTTP
    // response by the caller: `response::thread::process` (singles) and
    // `response::batch::process_batch` (batches).
    dump_event::emit(dump_event::DumpEvent {
        level: log::Level::Debug,
        module_label: String::from("ResponseThread"),
        service: api_call.url.service_name.clone(),
        api: api_call.url.api.clone(),
        http_status: Some(429),
        upstream_code: Some(String::from("TooManyRequests")),
        url: None,
        call_id: Some(api_call.id),
        message: format!(
            "Retry-After {}s (attempt #{})",
            effective,
            api_call.url.rate_limit_retry_number + 1
        ),
    });
}

pub async fn handle_success(
    this: &ResponseThread,
    response: &Response,
    api_call: &ApiCall,
) -> Vec<Url> {
    let mut new_urls: Vec<Url> = Vec::new();

    value_handlers::log_count_if_present(response, api_call);

    // LOAD-BEARING ORDER (do not reorder): the `nextLink` (next root page) is
    // pushed *before* the relationship children below. Combined with the LIFO
    // tail-drain in `dispatch.rs` (which clones the tail and calls `ApiCall::from`,
    // popping from the *back*), this makes a page's children dispatch *before* its
    // next root page is requested — a depth-first traversal that bounds the
    // `current_urls` pool to roughly one page's frontier instead of the whole
    // tenant. Pushing children first, or switching dispatch to FIFO, would turn
    // this into a breadth-first explosion (OOM risk on large tenants). Pinned by
    // the `dfs_*` regression test in `tests/utils_url.rs`.
    if let Some(next_url) = value_handlers::handle_next_link(this, response, api_call).await {
        // Request-shape telemetry: one pagination follow-up beyond the first page
        // (covers @odata.nextLink and ARG $skipToken). Feeds per-API `pages_followed`.
        // If the subsequent `handle_values` write fails and this page is retried, the
        // retry regenerates the same nextLink and counts again — a faithful count of
        // real nextLink events, bounded by (rare) writer failures.
        this.context
            .stats
            .record_page_followed(&api_call.url.service_name, &api_call.url.api);
        new_urls.push(next_url);
    }

    // An `$expand` extraction seed flattens each parent's expanded collection to
    // its own file and returns per-object fallback URLs for any parent that hit
    // the API cap; it owns its liveness/progress accounting internally.
    if api_call.url.api_behavior.contains_key("expand_extract") {
        match value_handlers::handle_expand_extract(this, response, api_call).await {
            Ok(fallbacks) => new_urls.extend(fallbacks),
            Err(_) => new_urls.extend(this.prepare_retries(vec![api_call.url.clone()])),
        }
        return new_urls;
    }

    // Handling values
    match value_handlers::handle_values(this, response, api_call).await {
        Ok(value_field) => {
            // Liveness progress: this bucket just wrote data, so reset its
            // no-progress timer (the only transient bound). Done in the
            // write-success branch — not on mere 2xx receipt — so a 2xx whose
            // write failed (the Err arm below, which re-queues) does NOT count.
            this.context
                .stats
                .note_progress(&api_call.url.service_name, &api_call.url.api);
            // Same trigger for the 429-escalation streak: a written page proves
            // the bucket drains, so its escalated pacing is lifted.
            this.context
                .ratelimit_manager
                .note_bucket_progress(&api_call.url.service_name, &api_call.url.api);
            let relationship_urls =
                value_handlers::handle_relationships(this, api_call, value_field).await;
            new_urls.extend(relationship_urls);
        }
        Err(_) => {
            // Write error: re-queue the URL for retry
            new_urls.extend(this.prepare_retries(vec![api_call.url.clone()]));
        }
    }

    new_urls
}

pub async fn handle_too_many_requests(
    this: &ResponseThread,
    response: &Response,
    api_call: &ApiCall,
) -> Vec<Url> {
    report_too_many_requests(this, response, api_call).await;
    this.prepare_rate_limit_retries(vec![api_call.url.clone()], response.retry_after)
        .await
}

pub async fn handle_unexpected_status(
    this: &ResponseThread,
    response: &Response,
    api_call: &ApiCall,
    status: u16,
) -> Vec<Url> {
    use crate::collect::dump::response::DumpError;
    use crate::utils::url::expected_errors::{is_breaker_eligible_error, is_expected_error};
    use serde_json::Value;

    let mut dump_error: DumpError = DumpError {
        folder: api_call.url.service_name.clone(),
        file: api_call.url.api.clone(),
        url: api_call.url.url.clone(),
        status,
        code: String::from("UnexpectedHTTPStatusCode"),
        message: format!(
            "Got HTTP Status {:?} for api {:?} of service {:?}, see log file for more info",
            status,
            api_call.url.api.clone(),
            api_call.url.service_name.clone()
        ),
        // Tentatively unexpected; overridden below once `expected` is computed
        // from the schema's `expected_error_codes`.
        expected: false,
        full_response: Some(response.content.clone()),
        post_data: None,
    };
    // Parse error
    let error_code_pointer: String = match api_call.url.api_behavior.get("error_code") {
        Some(field) => format!("/{field}"),
        None => String::from("/error/code"),
    };
    let error_code_field: Option<&Value> = response.content.pointer(&error_code_pointer);
    let error_message_pointer: String = match api_call.url.api_behavior.get("error_message") {
        Some(field) => format!("/{field}"),
        None => String::from("/error/message"),
    };
    let error_message_field: Option<&Value> = response.content.pointer(&error_message_pointer);
    let expected = is_expected_error(status, error_code_field, api_call);
    if let Some(code) = error_code_field {
        match code.as_str() {
            Some(c) => dump_error.code = c.to_string(),
            None => {
                log::debug!(
                    "{:FL$}Error parsing error code for api {:?} of service {:?} [ID: {}], skipping it",
                    "ResponseThread",
                    api_call.url.api,
                    api_call.url.service_name,
                    api_call.id
                );
            }
        }
    }
    // Record the upstream code (whether expected or not) so the inspect
    // view can show *which* error code is recurring per API. We use the
    // resolved `dump_error.code` to fall back to "UnexpectedHTTPStatusCode"
    // when the response has no parseable error.code.
    this.context.stats.record_upstream_error_code(
        &api_call.url.service_name,
        &api_call.url.api,
        &dump_error.code,
    );
    if let Some(message) = error_message_field {
        match message.as_str() {
            Some(m) => dump_error.message = m.to_string(),
            None => {
                log::debug!(
                    "{:FL$}Error parsing error message for api {:?} of service {:?} [ID: {}], skipping it",
                    "ResponseThread",
                    api_call.url.api,
                    api_call.url.service_name,
                    api_call.id
                );
            }
        }
    }
    // Batch meta-URLs (api = "$batch") are not real API resources; re-queuing them
    // as PotentialPrerequisiteError would create a recursive batch cycle. When
    // batch_data is Some, sub-URLs are re-queued via prepare_retries in the batch
    // response handler; when batch_data is None, handle_missing_batch_data records
    // the error.
    // URLs to re-dispatch on the standard retry budget for an undeclared 2xx or a
    // 3xx response — not a prerequisite failure, so the service is not paused.
    let mut standard_retry_urls: Vec<Url> = Vec::new();
    if !expected && !api_call.is_batch {
        if status >= 500 {
            // Transient server error: retry directly without a prereq re-check.
            // No per-attempt DumpError write; only the final UrlRetryLimit is recorded.
            dump_event::emit(dump_event::DumpEvent {
                level: log::Level::Debug,
                module_label: String::from("ResponseThread"),
                service: api_call.url.service_name.clone(),
                api: api_call.url.api.clone(),
                http_status: Some(status),
                upstream_code: Some(dump_error.code.clone()),
                url: Some(api_call.url.url.clone()),
                call_id: Some(api_call.id),
                message: dump_error.message.clone(),
            });
            let backoff_ms = compute_backoff_ms(api_call.url.retry_number);
            let _backoff_guard = BackoffGuard::enter(); // dec BACKOFF_ACTIVE on drop
            log::debug!(
                "{:FL$}Server error backoff: {}ms for request [ID: {}] at {:?} (attempt #{})",
                "ResponseThread",
                backoff_ms,
                api_call.id,
                api_call.url.url,
                api_call.url.retry_number + 1
            );
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            return this.prepare_retries(vec![api_call.url.clone()]);
        } else if status == 401 {
            // Token likely expired server-side: trigger a refresh and re-queue.
            // retry_number is incremented so the UrlRetryLimit circuit-breaker can
            // fire if the token remains invalid after repeated refreshes.
            this.send_to_update(CoordinatorEvent::NewError(
                Arc::from(api_call.url.service_name.as_str()),
                ProcessError::TokenExpirationError,
            ))
            .await;
            dump_event::emit(dump_event::DumpEvent {
                level: log::Level::Warn,
                module_label: String::from("ResponseThread"),
                service: api_call.url.service_name.clone(),
                api: api_call.url.api.clone(),
                http_status: Some(status),
                upstream_code: Some(dump_error.code.clone()),
                url: Some(api_call.url.url.clone()),
                call_id: Some(api_call.id),
                message: dump_error.message.clone(),
            });
            let mut url = api_call.url.clone();
            url.retry_number += 1;
            RETRY_COUNT.fetch_add(1, Ordering::Relaxed);
            this.context
                .stats
                .record_retry(&api_call.url.service_name, &api_call.url.api);
            return vec![url];
        } else if status == 404 || status == 409 {
            // 404 (resource gone / not found) and 409 (state conflict, e.g. a
            // locked exchange mailbox) are never permission signals, so they
            // must not pause the whole service for a prerequisite re-check.
            // They retry on the standard budget, like undeclared 2xx/3xx.
            standard_retry_urls = this.prepare_retries(vec![api_call.url.clone()]);
        } else if status >= 400 {
            // 403 and other 4xx (401/404/409 handled above): potential
            // prerequisite failure → re-check, decrement retry budget.
            let retried_urls = this.prepare_retries(vec![api_call.url.clone()]);
            if let Some(url) = retried_urls.into_iter().next() {
                this.send_to_update(CoordinatorEvent::NewError(
                    Arc::from(api_call.url.service_name.as_str()),
                    ProcessError::PotentialPrerequisiteError(Box::new(url)),
                ))
                .await;
            }
        } else {
            // An undeclared 2xx or a 3xx for this API: not a prerequisite failure
            // and retrying the exact request rarely helps, but consume the
            // standard retry budget (urlRetryLimit) without pausing the service
            // for a permission re-check. The URLs are re-dispatched via the
            // return value; dispatch abandons them as UrlRetryLimit on exhaustion.
            standard_retry_urls = this.prepare_retries(vec![api_call.url.clone()]);
        }
    }
    // Emit structured event and write DumpError for expected errors, 4xx prereq
    // errors and undeclared 2xx/3xx statuses. Those write one entry per retry
    // attempt (useful for diagnosing error code evolution); 5xx and 401 return
    // early above and so avoid per-attempt writes (both transient, low
    // diagnostic value).
    let level = if expected {
        log::Level::Debug
    } else {
        log::Level::Warn
    };
    dump_event::emit(dump_event::DumpEvent {
        level,
        module_label: String::from("ResponseThread"),
        service: api_call.url.service_name.clone(),
        api: api_call.url.api.clone(),
        http_status: Some(status),
        upstream_code: Some(dump_error.code.clone()),
        url: Some(api_call.url.url.clone()),
        call_id: Some(api_call.id),
        message: dump_error.message.clone(),
    });
    dump_error.expected = expected;
    let error_code = dump_error.code.clone();
    this.write_dump_error(dump_error).await;

    // Expected-error breaker: count this declared-benign error into the
    // bucket's consecutive streak. When the configured threshold is reached on
    // a bucket that never wrote a page (fires at most once per bucket), ask the
    // coordinator to drop its remaining URLs as skipped.
    //
    // Only errors the schema flags `breaker_eligible` feed the breaker — a
    // tenant-wide all-or-nothing signal (every URL of the bucket returns it, so
    // the rest are wasted round-trips). Per-object expected errors (a resource
    // gone, an account type lacking a feature) are left unflagged: letting them
    // trip an API-wide skip would silently drop the data-bearing objects not yet
    // processed (e.g. resources that DO support resource-scope PIM, mixed with
    // many that 404). The opt-in is per `(status, code)`, so the schema author
    // — not a hard-coded status — decides what counts as tenant-wide.
    if !api_call.is_batch
        && is_breaker_eligible_error(status, error_code_field, api_call)
        && this
            .context
            .stats
            .record_expected_error_streak(&api_call.url.service_name, &api_call.url.api)
    {
        log::warn!(
            "{:FL$}API {:?} of service {:?} returned only declared expected errors (latest: {} {}); skipping its remaining URLs (expectedErrorBreakerThreshold)",
            "ResponseThread",
            api_call.url.api,
            api_call.url.service_name,
            status,
            error_code
        );
        this.send_to_update(CoordinatorEvent::BreakerTripped {
            service: Arc::from(api_call.url.service_name.as_str()),
            api: api_call.url.api.clone(),
        })
        .await;
    }

    standard_retry_urls
}
