use crate::FL;
use crate::collect::dump::orchestration::events::{CoordinatorEvent, ProcessError};
use crate::collect::dump::request::compute_backoff_ms;
use crate::collect::dump::request::executor::parse_retry_after_value;
use crate::collect::dump::response::thread::ResponseThread;
use crate::collect::dump::response::{DumpError, Response, status_handlers};
use crate::utils::ui::dump_event;
use crate::utils::url::{ApiCall, BatchData, Url};

use log::{debug, trace, warn};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

async fn handle_missing_batch_data(this: &ResponseThread) {
    dump_event::emit(dump_event::DumpEvent {
        level: log::Level::Warn,
        module_label: String::from("ResponseThread"),
        service: this.response_data.api_call.url.service_name.clone(),
        api: this.response_data.api_call.url.api.clone(),
        http_status: None,
        upstream_code: Some(String::from("MissingBatchData")),
        url: None,
        call_id: Some(this.response_data.api_call.id),
        message: String::from("Received batch response while ApiCall is not a batch, trying again"),
    });
    let post_data =
        serde_json::to_value(&this.response_data.api_call.batch_data).unwrap_or(json!(null));
    let _ = this
        .write_dump_error(DumpError {
            folder: this.response_data.api_call.url.service_name.clone(),
            file: this.response_data.api_call.url.api.clone(),
            url: this.response_data.api_call.url.url.clone(),
            status: 0,
            code: String::from("MissingBatchData"),
            message: format!(
                "Missing batch_data in ApiCall for service {:?}",
                this.response_data.api_call.url.service_name.clone()
            ),
            expected: false,
            full_response: None,
            post_data: Some(post_data),
        })
        .await;
}

pub async fn process_batch(this: &ResponseThread) -> Vec<Url> {
    trace!(
        "{:FL$}Processing batch response [ID: {}] for service {} status: {}",
        "ResponseThread",
        this.response_data.api_call.id,
        &this.response_data.api_call.url.service_name,
        this.response_data.response.status
    );
    let mut new_urls: Vec<Url> = Vec::new();

    match this.response_data.response.status {
        429 => {
            // Handle HTTP status code 429 - Too many requests
            status_handlers::report_too_many_requests(
                this,
                &this.response_data.response,
                &this.response_data.api_call,
            )
            .await;
            // One AIMD halving for the whole throttled envelope (report_429 was
            // removed from `report_too_many_requests`; see its note).
            this.context
                .concurrency_controller
                .report_429(&this.response_data.api_call.url.service_name);
            match &this.response_data.api_call.batch_data {
                None => {
                    handle_missing_batch_data(this).await;
                }
                Some(batch_data) => {
                    // The wrapper 429 affects every sub-URL: record it once per
                    // sub-URL so per-API counters reflect that each was throttled.
                    for inner in batch_data.initial_data.values() {
                        this.context.stats.record_response(
                            &inner.url.service_name,
                            &inner.url.api,
                            429,
                            false,
                        );
                    }
                    let sub_count = batch_data.initial_data.len();
                    new_urls.extend(
                        this.prepare_rate_limit_retries(
                            batch_data
                                .initial_data
                                .values()
                                .map(|d: &ApiCall| d.url.clone())
                                .collect(),
                            this.response_data.response.retry_after,
                        )
                        .await,
                    );
                    debug!(
                        "{:FL$}{} sub-URL(s) re-queued on 429 envelope [ID: {}] for service {:?} (Retry-After: {}s)",
                        "ResponseThread",
                        sub_count,
                        this.response_data.api_call.id,
                        this.response_data.api_call.url.service_name,
                        this.response_data.response.retry_after.unwrap_or(0)
                    );
                }
            }
        }
        x if x == this.response_data.api_call.success_code => {
            // Extract batch data
            let data: &BatchData = match &this.response_data.api_call.batch_data {
                None => {
                    handle_missing_batch_data(this).await;
                    return new_urls;
                }
                Some(batch_data) => batch_data,
            };

            // Parse responses
            let responses: &[Value] = match this
                .response_data
                .response
                .content
                .pointer(&this.response_data.api_call.value_pointer)
            {
                Some(e) => e.as_array().map(Vec::as_slice).unwrap_or(&[]),
                None => {
                    warn!(
                        "{:FL$}Received invalid response to batch request [ID: {}] for service {:?}, trying again",
                        "ResponseThread",
                        this.response_data.api_call.id,
                        this.response_data.api_call.url.service_name
                    );
                    debug!(
                        "{:FL$}Batch response content [ID: {}]: {:?}",
                        "ResponseThread",
                        this.response_data.api_call.id,
                        this.response_data.response
                    );
                    new_urls.extend(
                        this.prepare_retries(
                            data.initial_data
                                .values()
                                .map(|d: &ApiCall| d.url.clone())
                                .collect(),
                        ),
                    );
                    return new_urls;
                }
            };

            let id_pointer = format!("/{}", data.id_field);
            let status_pointer = format!("/{}", data.status_field);
            let retry_after_pointer = format!("/{}", data.retry_after_field);
            let body_pointer = format!("/{}", data.body_field);

            let mut initial_data = data.initial_data.clone();
            // AIMD: a 2xx Graph $batch envelope can still wrap 429 sub-responses
            // (the common throttle mode). Track whether ANY sub was throttled and
            // adjust the window exactly once after the loop — not per sub-429.
            let mut saw_throttle = false;
            for response in responses {
                let id: &str = match response.pointer(&id_pointer) {
                    Some(e) => match e.as_str() {
                        Some(i) => i,
                        None => {
                            warn!(
                                "{:FL$}Invalid ID field in response to batch request [ID: {}] for service {:?}, trying again",
                                "ResponseThread",
                                this.response_data.api_call.id,
                                this.response_data.api_call.url.service_name
                            );
                            debug!(
                                "{:FL$}Sub-response with invalid ID [ID: {}]: {:?}",
                                "ResponseThread", this.response_data.api_call.id, response
                            );
                            continue;
                        }
                    },
                    None => {
                        warn!(
                            "{:FL$}Received response with no ID to batch request [ID: {}] for service {:?}, trying again",
                            "ResponseThread",
                            this.response_data.api_call.id,
                            this.response_data.api_call.url.service_name
                        );
                        debug!(
                            "{:FL$}Sub-response with no ID field [ID: {}]: {:?}",
                            "ResponseThread", this.response_data.api_call.id, response
                        );
                        continue;
                    }
                };
                let api_call: ApiCall = match initial_data.remove_entry(id) {
                    Some((_, a)) => a,
                    None => {
                        warn!(
                            "{:FL$}Could not find initial ApiCall data for batch response [ID: {}] of service {:?}",
                            "ResponseThread",
                            this.response_data.api_call.id,
                            this.response_data.api_call.url.service_name
                        );
                        debug!(
                            "{:FL$}Unmatched sub-response [ID: {}]: {:?}",
                            "ResponseThread", this.response_data.api_call.id, response
                        );
                        continue;
                    }
                };
                let response_status: u16 = match response.pointer(&status_pointer) {
                    // `as u16` would silently truncate a value > 65535; route any
                    // out-of-range (or non-integer) status into the same retry path
                    // as a missing status via `try_from`.
                    Some(e) => match e.as_u64().and_then(|u| u16::try_from(u).ok()) {
                        Some(u) => u,
                        None => {
                            warn!(
                                "{:FL$}Received invalid status to batch request [ID: {}] for service {:?}, sub-API {:?} ({}), trying again",
                                "ResponseThread",
                                this.response_data.api_call.id,
                                this.response_data.api_call.url.service_name,
                                api_call.url.api,
                                api_call.url.url
                            );
                            debug!(
                                "{:FL$}Sub-response with invalid status [ID: {}]: {:?}",
                                "ResponseThread", this.response_data.api_call.id, response
                            );
                            new_urls.extend(this.prepare_retries(vec![api_call.url.clone()]));
                            continue;
                        }
                    },
                    None => {
                        warn!(
                            "{:FL$}Received response with no status to batch request [ID: {}] for service {:?}, sub-API {:?} ({}), trying again",
                            "ResponseThread",
                            this.response_data.api_call.id,
                            this.response_data.api_call.url.service_name,
                            api_call.url.api,
                            api_call.url.url
                        );
                        debug!(
                            "{:FL$}Sub-response with no status field [ID: {}]: {:?}",
                            "ResponseThread", this.response_data.api_call.id, response
                        );
                        // The item was already removed from `initial_data` above, so the
                        // end-of-batch "no response received" sweep cannot recover it.
                        // Re-queue it explicitly (mirrors the invalid-status branch) so a
                        // malformed sub-response is retried rather than silently lost.
                        new_urls.extend(this.prepare_retries(vec![api_call.url.clone()]));
                        continue;
                    }
                };
                if response_status == 429 {
                    saw_throttle = true;
                }
                // `None` (absent / unparseable) so the rate-limit manager applies
                // its configured default for this sub-429 rather than zero.
                // A string value is parsed through the shared `parse_retry_after_value`
                // so a `$batch` sub-response honours both the delta-seconds AND the
                // HTTP-date form, exactly like the top-level header path; a JSON
                // number is read directly as delta-seconds.
                let response_retry_after: Option<u64> =
                    response.pointer(&retry_after_pointer).and_then(|e| {
                        e.as_str()
                            .and_then(parse_retry_after_value)
                            .or_else(|| e.as_u64())
                    });
                let response_body: Value = match response.pointer(&body_pointer) {
                    Some(e) => e.clone(),
                    None => {
                        if response_status == 429 {
                            json!(null)
                        } else {
                            dump_event::emit(dump_event::DumpEvent {
                                level: log::Level::Warn,
                                module_label: String::from("ResponseThread"),
                                service: this.response_data.api_call.url.service_name.clone(),
                                api: api_call.url.api.clone(),
                                http_status: None,
                                upstream_code: Some(String::from("NoBodyInBatchResponse")),
                                url: None,
                                call_id: Some(api_call.id),
                                message: String::from(
                                    "Received response with no body to batch request, trying again",
                                ),
                            });
                            new_urls.extend(this.prepare_retries(vec![api_call.url.clone()]));
                            continue;
                        }
                    }
                };
                let single_urls = this
                    .process_single(
                        &Response {
                            status: response_status,
                            retry_after: response_retry_after,
                            content: response_body,
                        },
                        &api_call,
                    )
                    .await;
                new_urls.extend(single_urls);
            }
            // Re-queue URLs for which no response was received
            let missing: Vec<Url> = initial_data.values().map(|a| a.url.clone()).collect();
            if !missing.is_empty() {
                warn!(
                    "{:FL$}{} sub-URL(s) received no response in batch [ID: {}] for service {:?}, re-queuing",
                    "ResponseThread",
                    missing.len(),
                    this.response_data.api_call.id,
                    this.response_data.api_call.url.service_name
                );
            }
            new_urls.extend(this.prepare_retries(missing));
            // AIMD: one signal for the whole envelope — halve if any sub-response
            // was throttled, otherwise count the batch as a success.
            if saw_throttle {
                this.context
                    .concurrency_controller
                    .report_429(&this.response_data.api_call.url.service_name);
            } else {
                this.context
                    .concurrency_controller
                    .report_success(&this.response_data.api_call.url.service_name);
            }
        }
        x => {
            status_handlers::handle_unexpected_status(
                this,
                &this.response_data.response,
                &this.response_data.api_call,
                x,
            )
            .await;

            // Envelope-level recovery. `handle_unexpected_status` deliberately skips
            // refresh/backoff for batch meta-URLs (re-queuing the `$batch` URL itself
            // would loop), so perform the service-level actions here before the
            // sub-URLs are re-queued below.
            if x == 401 {
                // The whole `$batch` POST was rejected: the bearer is (near-)invalid.
                // Trigger a token refresh so the re-queued sub-URLs go out with a fresh
                // token instead of looping on the stale one until urlRetryLimit.
                this.send_to_update(CoordinatorEvent::NewError(
                    Arc::from(this.response_data.api_call.url.service_name.as_str()),
                    ProcessError::TokenExpirationError,
                ))
                .await;
            } else if x >= 500 {
                // Transient server error on the envelope: back off before re-queuing so
                // the batch endpoint does not hot-loop through its retry budget (mirrors
                // the single-request 5xx path).
                // The wrapper URL is reconstructed fresh each time so its own
                // `retry_number` is always 0; use the max from sub-URLs instead so
                // the backoff grows with successive failures, just like single-URL 5xx.
                let max_retry = this
                    .response_data
                    .api_call
                    .batch_data
                    .as_ref()
                    .and_then(|bd| bd.initial_data.values().map(|a| a.url.retry_number).max())
                    .unwrap_or(0);
                let backoff_ms = compute_backoff_ms(max_retry);
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            }

            match &this.response_data.api_call.batch_data {
                None => {
                    handle_missing_batch_data(this).await;
                }
                Some(batch_data) => {
                    // Wrapper failed without per-sub-URL detail: attribute the
                    // wrapper status to each sub-URL so per-API counters reflect
                    // the failure. Honour per-API expected_error_codes so that
                    // an API which declares the wrapper status as expected is
                    // not counted as having unexpected errors.
                    for inner in batch_data.initial_data.values() {
                        let is_expected =
                            crate::utils::url::expected_errors::is_expected_error(x, None, inner);
                        this.context.stats.record_response(
                            &inner.url.service_name,
                            &inner.url.api,
                            x,
                            is_expected,
                        );
                    }
                    new_urls.extend(
                        this.prepare_retries(
                            batch_data
                                .initial_data
                                .values()
                                .map(|d: &ApiCall| d.url.clone())
                                .collect(),
                        ),
                    );
                }
            }
        }
    }

    debug!(
        "{:FL$}Batch [ID: {}] complete: {} new URL(s) for service {:?}",
        "ResponseThread",
        this.response_data.api_call.id,
        new_urls.len(),
        this.response_data.api_call.url.service_name
    );
    new_urls
}
