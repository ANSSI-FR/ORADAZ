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

    /// Re-queue URLs throttled by a 429 response.
    ///
    /// Increments the dedicated 429 counter and accumulates the Retry-After delay
    /// instead of bumping `retry_number`, so that transient throttling does not
    /// consume the budget reserved for real errors.
    pub fn prepare_rate_limit_retries(
        &self,
        mut urls: Vec<Url>,
        retry_after: Option<u64>,
    ) -> Vec<Url> {
        if urls.is_empty() {
            return urls;
        }
        for url in urls.iter_mut() {
            // Accumulate the *effective* cooldown (the configured default when no
            // Retry-After was provided), so a header-less 429 still progresses
            // toward the `rateLimitMaxWaitSecs` abandon cap rather than adding 0.
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
        }
        urls
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
