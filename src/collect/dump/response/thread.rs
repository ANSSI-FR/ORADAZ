use crate::collect::dump::orchestration::events::{CoordinatorEvent, ProcessError};
use crate::collect::dump::request::RETRY_COUNT;
use crate::collect::dump::response::{
    DumpError, Response, ResponseContent, ResponseContext, batch, single,
};
use crate::utils::errors::FatalPresentation;
use crate::utils::url::{ApiCall, Url};
use crate::{FL, bail_fatal};

use log::{debug, trace};
use std::sync::{Arc, atomic::Ordering};
use tokio::sync::mpsc::Sender;

pub struct ResponseThread {
    sender: Sender<CoordinatorEvent>,
    pub context: ResponseContext,
    pub response_data: Box<ResponseContent>,
}

impl ResponseThread {
    pub fn new(
        sender: Sender<CoordinatorEvent>,
        context: ResponseContext,
        response_data: Box<ResponseContent>,
    ) -> Self {
        ResponseThread {
            sender,
            context,
            response_data,
        }
    }

    pub async fn send_to_update(&self, msg: CoordinatorEvent) {
        if let Err(err) = self.sender.send(msg).await {
            trace!(
                "{:FL$}Error sending CoordinatorEvent to Coordinator (Coordinator likely exited): {:?}",
                "ResponseThread", err
            );
        };
    }

    pub fn prepare_retries(&self, mut urls: Vec<Url>) -> Vec<Url> {
        if urls.is_empty() {
            return urls;
        }
        for url in urls.iter_mut() {
            RETRY_COUNT.fetch_add(1, Ordering::Relaxed);
            url.retry_number += 1;
            self.context.stats.record_retry(&url.service_name, &url.api);
            debug!(
                "{:FL$}Retry #{} scheduled for {:?}/{:?} ({})",
                "ResponseThread", url.retry_number, url.service_name, url.api, url.url
            );
        }
        urls
    }

    /// Re-queue URLs throttled by a 429 response, or abandon them when their
    /// bucket has stalled.
    ///
    /// A 429 does not abandon a URL on a fixed budget: the
    /// 429 counters become pure metrics and the **only** transient bound is the
    /// per-bucket liveness ceiling. A URL is abandoned (as lost data, code
    /// `ThrottleStalled`) only when its `(service, api)` bucket has written no
    /// data within the ceiling despite retries; otherwise it is re-queued.
    ///
    /// Counter note: abandonment uses `write_dump_error`, which emits a `NewError`
    /// but NOT a `RequestCompleted`, so it is counter-neutral — the single
    /// `RequestCompleted` from `process()` already accounts for this response's
    /// dispatched item. Returns only the URLs to re-queue.
    pub async fn prepare_rate_limit_retries(
        &self,
        urls: Vec<Url>,
        retry_after: Option<u64>,
    ) -> Vec<Url> {
        if urls.is_empty() {
            return urls;
        }
        let mut requeue: Vec<Url> = Vec::with_capacity(urls.len());
        for mut url in urls {
            if self
                .context
                .stats
                .liveness_should_abandon(&url.service_name, &url.api)
            {
                self.write_dump_error(DumpError {
                    folder: url.service_name.clone(),
                    file: url.api.clone(),
                    url: url.url.clone(),
                    status: 0,
                    code: String::from("ThrottleStalled"),
                    message: format!(
                        "Endpoint {:?} ({}) stayed throttled (429) with no successful data write within the liveness ceiling; abandoned so the run can terminate ({} 429 retries, {}s cumulative cooldown).",
                        url.api,
                        url.service_name,
                        url.rate_limit_retry_number,
                        url.rate_limit_total_wait_secs
                    ),
                    expected: false,
                    full_response: None,
                    post_data: None,
                })
                .await;
                continue;
            }
            // Accumulate the *effective* cooldown (the configured default when no
            // Retry-After was provided), so a header-less 429 still records a
            // realistic cumulative-wait metric rather than adding 0.
            let effective = self
                .context
                .ratelimit_manager
                .effective_retry_after(&url.service_name, retry_after);
            RETRY_COUNT.fetch_add(1, Ordering::Relaxed);
            url.rate_limit_retry_number += 1;
            url.rate_limit_total_wait_secs =
                url.rate_limit_total_wait_secs.saturating_add(effective);
            self.context
                .stats
                .record_rate_limit_retry(&url.service_name, &url.api, effective);
            debug!(
                "{:FL$}Rate-limit retry #{} for {:?}/{:?} ({}) — total wait {}s",
                "ResponseThread",
                url.rate_limit_retry_number,
                url.service_name,
                url.api,
                url.url,
                url.rate_limit_total_wait_secs
            );
            requeue.push(url);
        }
        requeue
    }

    pub async fn write_dump_error(&self, dump_error: DumpError) {
        if let Err(err) = self
            .context
            .write_dump_error(&dump_error, self.response_data.api_call.id)
            .await
        {
            let _ = self.context.writer.set_broken().await;
            bail_fatal!(err);
        }
        self.send_to_update(CoordinatorEvent::NewError(
            self.response_data.api_call.url.service_name.clone().into(),
            ProcessError::DumpError(1),
        ))
        .await;
    }

    pub async fn process(self) {
        trace!(
            "{:FL$}Processing response [ID: {}] for service {:?}, api {:?}",
            "ResponseThread",
            self.response_data.api_call.id,
            self.response_data.api_call.url.service_name,
            self.response_data.api_call.url.api
        );
        let service: Arc<str> = Arc::from(self.response_data.api_call.url.service_name.as_str());
        let new_urls: Vec<Url> = match self.response_data.api_call.is_batch {
            true => self.process_batch().await,
            false => {
                let urls = self
                    .process_single(&self.response_data.response, &self.response_data.api_call)
                    .await;
                // AIMD: exactly one window signal per single HTTP response. (Batch
                // envelopes are handled inside `process_batch`, which alone can see
                // the sub-statuses of a 2xx envelope.) Non-429 errors leave the
                // window unchanged.
                let status = self.response_data.response.status;
                let svc = &self.response_data.api_call.url.service_name;
                if status == 429 {
                    self.context.concurrency_controller.report_429(svc);
                } else if status == self.response_data.api_call.success_code {
                    self.context.concurrency_controller.report_success(svc);
                }
                urls
            }
        };
        self.send_to_update(CoordinatorEvent::RequestCompleted {
            service,
            id: self.response_data.api_call.id,
            new_urls,
            count: 1,
        })
        .await;
    }

    pub async fn process_batch(&self) -> Vec<Url> {
        batch::process_batch(self).await
    }

    pub async fn process_single(&self, response: &Response, api_call: &ApiCall) -> Vec<Url> {
        single::process_single(self, response, api_call).await
    }
}
