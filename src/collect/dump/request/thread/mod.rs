use crate::FL;
use crate::collect::dump::concurrency::ConcurrencyController;
use crate::collect::dump::orchestration::events::CoordinatorEvent;
use crate::collect::dump::request::executor;
use crate::collect::dump::request::{
    BackoffGuard, RETRY_COUNT, RequestExecutionContext, compute_backoff_ms,
};
use crate::collect::dump::response::{DumpError, Response, ResponseContent, ResponseMsg};
use crate::utils::url::{ApiCall, Url};

use log::{debug, trace, warn};
use serde_json::json;
use serde_json::value::to_value;
use std::sync::{Arc, atomic::Ordering};
use std::time::Duration;
use tokio::sync::mpsc::Sender;

mod handlers;
pub use handlers::RequestHandlers;

/// RAII guard that releases a concurrency slot when dropped.
struct SlotGuard {
    controller: Arc<ConcurrencyController>,
    service: String,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.controller.release_slot(&self.service);
    }
}

/// A worker that processes a single API call request.
///
/// It handles the full lifecycle of a request: rate limit waiting, token acquisition,
/// execution, and routing the result (success or failure) to the appropriate module.
pub struct RequestsThread {
    pub response_sender: Sender<ResponseMsg>,
    pub update_sender: Sender<CoordinatorEvent>,
    pub context: RequestExecutionContext,
    pub api_call: Box<ApiCall>,
}

impl RequestsThread {
    /// URLs of every sub-request carried by this batch `ApiCall`, used to
    /// re-queue them on a batch-level failure. Empty when this is not a batch
    /// call. Factored out so both batch error arms re-derive the same list
    /// without holding the `batch_data` borrow across the whole match in
    /// `process`.
    fn batch_sub_urls(&self) -> Vec<Url> {
        self.api_call
            .batch_data
            .as_ref()
            .map(|bd| bd.initial_data.values().map(|d| d.url.clone()).collect())
            .unwrap_or_default()
    }

    async fn finalize_retry(&self, mut urls: Vec<Url>) {
        let prev_retry = urls.first().map(|u| u.retry_number).unwrap_or(0);
        let backoff_ms = compute_backoff_ms(prev_retry);
        let _backoff_guard = BackoffGuard::enter(); // dec BACKOFF_ACTIVE on drop
        debug!(
            "{:FL$}Network retry attempt #{} — backoff {}ms for request [ID: {}] at url {:?}",
            "RequestsThread",
            prev_retry + 1,
            backoff_ms,
            self.api_call.id,
            self.api_call.url.url
        );
        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
        RETRY_COUNT.fetch_add(1, Ordering::Relaxed);
        // One HTTP call failed; record it once at the service level for the
        // summary line. The per-API counter below attributes the failure to
        // every sub-URL carried by a failed batch, which is the right
        // granularity for the per-API view but would inflate the global
        // network-error figure if used naively.
        self.context
            .stats
            .record_http_call_failure(&self.api_call.url.service_name);
        for url in urls.iter_mut() {
            url.retry_number += 1;
            self.context
                .stats
                .record_network_error(&url.service_name, &url.api);
            self.context.stats.record_retry(&url.service_name, &url.api);
        }
        self.send_to_update(CoordinatorEvent::RequestCompleted {
            service: Arc::from(self.api_call.url.service_name.as_str()),
            id: self.api_call.id,
            new_urls: urls,
            count: 1,
        })
        .await;
    }

    pub fn new(
        response_sender: Sender<ResponseMsg>,
        update_sender: Sender<CoordinatorEvent>,
        context: RequestExecutionContext,
        api_call: Box<ApiCall>,
    ) -> Self {
        RequestsThread {
            response_sender,
            update_sender,
            context,
            api_call,
        }
    }

    /// Processes the API call.
    ///
    /// The flow is:
    /// 1. Wait for rate limit.
    /// 2. Acquire concurrency slot (via `SlotGuard`).
    /// 3. Acquire and validate the authentication token.
    /// 4. Execute the request (single or batch).
    /// 5. Update concurrency metrics based on the result.
    /// 6. Dispatch results to `ResponseModule` or the Coordinator.
    pub async fn process(self) {
        trace!(
            "{:FL$}Processing request [ID: {}] for url {:?} (batch: {})",
            "RequestsThread", self.api_call.id, self.api_call.url.url, self.api_call.is_batch
        );
        self.context
            .ratelimit_manager
            .wait_if_needed(&self.api_call.url.service_name)
            .await;
        trace!(
            "{:FL$}Rate limit wait finished for request [ID: {}]",
            "RequestsThread", self.api_call.id
        );

        self.context
            .concurrency_controller
            .acquire_slot(&self.api_call.url.service_name)
            .await;

        // Use SlotGuard to ensure the concurrency slot is released regardless of how the function exits.
        let _guard = SlotGuard {
            controller: Arc::clone(&self.context.concurrency_controller),
            service: self.api_call.url.service_name.clone(),
        };
        // Retrieve the token corresponding to the URL to process
        trace!(
            "{:FL$}Acquiring token for request [ID: {}]",
            "RequestsThread", self.api_call.id
        );
        let token_state = match self
            .context
            .tokens
            .get(self.api_call.url.service_name.as_str())
        {
            Some(s) => Arc::clone(s.value()),
            None => {
                self.handle_missing_token().await;
                return;
            }
        };

        let token = token_state.token.read().await.clone();

        // Update token if it will expire
        if token.will_expire() {
            self.handle_token_expiration(&token).await;
            return;
        }

        // Resolve the per-service HTTP timeout once for this request. Apply it
        // only if it differs from the client default, to avoid overriding when
        // no per-service config was supplied.
        let svc_timeout = crate::utils::config::Config::http_timeout_seconds_for(
            &self.context.config,
            &self.api_call.url.service_name,
        );
        let client_timeout =
            crate::utils::config::Config::http_timeout_seconds(&self.context.config);
        let per_req_timeout = if svc_timeout != client_timeout {
            Some(svc_timeout)
        } else {
            None
        };

        match self.api_call.is_batch {
            false => {
                trace!(
                    "{:FL$}Executing single request [ID: {}]",
                    "RequestsThread", self.api_call.id
                );
                match executor::execute_single(
                    &self.context.oradaz_client,
                    self.api_call.as_ref(),
                    &token,
                    per_req_timeout,
                )
                .await
                {
                    Err(executor::ExecutorError::Request(err)) => {
                        if err.is_timeout() {
                            debug!(
                                "{:FL$}Timeout for request [ID: {}] to url {:?}, retrying.",
                                "RequestsThread", self.api_call.id, &self.api_call.url.url
                            );
                        } else if err.is_connect() {
                            debug!(
                                "{:FL$}Network error for request [ID: {}] to url {:?}, retrying.",
                                "RequestsThread", self.api_call.id, &self.api_call.url.url
                            );
                        } else {
                            // Reached only when the error is neither a timeout nor a
                            // connect error (both handled above), so the kind is
                            // always "Other"; the full error is logged at debug.
                            warn!(
                                "{:FL$}Error performing request [ID: {}] to url {:?}, retrying. kind=Other",
                                "RequestsThread", self.api_call.id, &self.api_call.url.url
                            );
                            debug!(
                                "{:FL$}Request error [ID: {}] for url {:?}: {:?}",
                                "RequestsThread", self.api_call.id, &self.api_call.url.url, err
                            );
                        }
                        self.finalize_retry(vec![self.api_call.url.clone()]).await;
                    }
                    Ok(res) => {
                        // Per-API + service HTTP latency (single call: the URL maps
                        // to exactly one API). Recorded for every completed response
                        // regardless of status — latency is a transport property.
                        self.context.stats.record_http_latency(
                            &self.api_call.url.service_name,
                            Some(&self.api_call.url.api),
                            res.elapsed_ms,
                        );
                        // A non-JSON body keeps its HTTP status for routing, but a
                        // *success* status carries no parseable records — retry it
                        // rather than letting handle_success write a placeholder
                        // record to the archive.
                        // 429 / 4xx / 5xx fall through to the response module, where
                        // status-based routing (cooldown, refresh, retry) applies.
                        if let Some(excerpt) = &res.body_excerpt {
                            warn!(
                                "{:FL$}Non-JSON response [ID: {}] (HTTP {}, content-type {}) for url {:?}, routing by status",
                                "RequestsThread",
                                self.api_call.id,
                                res.status,
                                res.content_type.as_deref().unwrap_or("?"),
                                &self.api_call.url.url
                            );
                            debug!(
                                "{:FL$}Non-JSON body [ID: {}]: {}",
                                "RequestsThread", self.api_call.id, excerpt
                            );
                            if res.status == self.api_call.success_code {
                                self.finalize_retry(vec![self.api_call.url.clone()]).await;
                                return;
                            }
                        }
                        // AIMD window signalling is owned solely by the response
                        // module — only it sees batch sub-statuses. A Graph $batch
                        // returns a 200 envelope that can wrap 429 sub-responses;
                        // reporting success here would miss that throttling. See
                        // `response::thread::process` and `response::batch`.
                        // Move the ApiCall into the ResponseContent instead of
                        // deep-cloning it on every successful response. This is the
                        // last use of `self.api_call`, so the `Box` is moved out and
                        // the message is sent on the disjoint `response_sender` field
                        // directly — `self.send_to_response(&self)` can't be called
                        // after the partial move.
                        let content = ResponseContent {
                            api_call: *self.api_call,
                            response: Response {
                                status: res.status,
                                retry_after: res.retry_after,
                                content: res.content,
                            },
                        };
                        if let Err(err) = self
                            .response_sender
                            .send(ResponseMsg::ResponseData(Box::new(content)))
                            .await
                        {
                            trace!(
                                "{:FL$}Error sending ResponseMsg to ResponseModule (Coordinator likely exited): {:?}",
                                "RequestsThread", err
                            );
                        }
                    }
                }
            }
            true => {
                // Compute the POST body in a short-lived borrow of `batch_data`,
                // bailing with a DumpError when it is missing. Keeping the borrow
                // out of the match below lets the `Ok` arm *move* `self.api_call`
                // into the response instead of deep-cloning it. The two error
                // arms re-derive the sub-URL list via `batch_sub_urls()`.
                let post_data_value = match &self.api_call.batch_data {
                    Some(batch_data) => to_value(&batch_data.post_data).unwrap_or(json!(null)),
                    None => {
                        warn!(
                            "{:FL$}Received POST request [ID: {}] with no data for service {:?}, retrying.",
                            "RequestsThread", self.api_call.id, &self.api_call.url.service_name
                        );
                        // Send an error indicating the invalid API
                        self.send_to_response(ResponseMsg::DumpError(
                            Box::new(DumpError {
                                folder: self.api_call.url.service_name.clone(),
                                file: self.api_call.url.api.clone(),
                                url: self.api_call.url.url.clone(),
                                status: 0,
                                code: String::from("MissingBatchData"),
                                message: format!(
                                    "Missing batch_data in ApiCall for service {:?}",
                                    self.api_call.url.service_name.clone()
                                ),
                                expected: false,
                                full_response: None,
                                post_data: None,
                            }),
                            self.api_call.id,
                        ))
                        .await;
                        return;
                    }
                };
                trace!(
                    "{:FL$}Executing batch request [ID: {}]",
                    "RequestsThread", self.api_call.id
                );
                match executor::execute_batch(
                    &self.context.oradaz_client,
                    self.api_call.as_ref(),
                    &token,
                    &post_data_value,
                    per_req_timeout,
                )
                .await
                {
                    Err(executor::ExecutorError::Request(err)) => {
                        if err.is_timeout() {
                            debug!(
                                "{:FL$}Timeout for request [ID: {}] to url {:?}, retrying.",
                                "RequestsThread", self.api_call.id, &self.api_call.url.url
                            );
                        } else if err.is_connect() {
                            debug!(
                                "{:FL$}Network error for request [ID: {}] to url {:?}, retrying.",
                                "RequestsThread", self.api_call.id, &self.api_call.url.url
                            );
                        } else {
                            // Reached only when the error is neither a timeout nor a
                            // connect error (both handled above), so the kind is
                            // always "Other"; the full error is logged at debug.
                            warn!(
                                "{:FL$}Error performing batch request [ID: {}] to url {:?}, retrying. kind=Other",
                                "RequestsThread", self.api_call.id, &self.api_call.url.url
                            );
                            debug!(
                                "{:FL$}Batch request error [ID: {}] for url {:?}: {:?}",
                                "RequestsThread", self.api_call.id, &self.api_call.url.url, err
                            );
                        }
                        self.finalize_retry(self.batch_sub_urls()).await;
                    }
                    Ok(res) => {
                        // Service-level HTTP latency only: a batch envelope carries
                        // one round-trip for up to 20 sub-URLs, so the latency cannot
                        // be attributed to a single API.
                        self.context.stats.record_http_latency(
                            &self.api_call.url.service_name,
                            None,
                            res.elapsed_ms,
                        );
                        // Non-JSON batch wrapper: a *success* status has no parseable
                        // sub-responses — retry the sub-URLs instead of writing
                        // placeholders. 429 / 4xx / 5xx fall through
                        // to status-based routing in the response module.
                        if let Some(excerpt) = &res.body_excerpt {
                            warn!(
                                "{:FL$}Non-JSON batch response [ID: {}] (HTTP {}, content-type {}) for url {:?}, routing by status",
                                "RequestsThread",
                                self.api_call.id,
                                res.status,
                                res.content_type.as_deref().unwrap_or("?"),
                                &self.api_call.url.url
                            );
                            debug!(
                                "{:FL$}Non-JSON batch body [ID: {}]: {}",
                                "RequestsThread", self.api_call.id, excerpt
                            );
                            if res.status == self.api_call.success_code {
                                self.finalize_retry(self.batch_sub_urls()).await;
                                return;
                            }
                        }
                        // AIMD window signalling is owned solely by the response
                        // module — only it sees batch sub-statuses. A Graph $batch
                        // returns a 200 envelope that can wrap 429 sub-responses;
                        // reporting success here would miss that throttling. See
                        // `response::thread::process` and `response::batch`.
                        // Move the (batch) ApiCall — up to 20 sub-ApiCalls — into
                        // the response instead of deep-cloning it. Sent on the
                        // disjoint `response_sender` field after the partial move.
                        let content = ResponseContent {
                            api_call: *self.api_call,
                            response: Response {
                                status: res.status,
                                retry_after: res.retry_after,
                                content: res.content,
                            },
                        };
                        if let Err(err) = self
                            .response_sender
                            .send(ResponseMsg::ResponseData(Box::new(content)))
                            .await
                        {
                            trace!(
                                "{:FL$}Error sending ResponseMsg to ResponseModule (Coordinator likely exited): {:?}",
                                "RequestsThread", err
                            );
                        }
                    }
                }
            }
        }
    }
}
