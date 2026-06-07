use crate::collect::dump::orchestration::events::{CoordinatorEvent, ProcessError};
use crate::collect::dump::response::{DumpError, ResponseContext};
use crate::utils::errors::{Error, FatalPresentation};
use crate::{FL, bail_fatal};

use log::{error, trace};
use tokio::sync::mpsc::Sender;
use tokio::time::{Duration, sleep};

pub struct ResponseErrorThread {
    sender: Sender<CoordinatorEvent>,
    context: ResponseContext,
    dump_error: DumpError,
    request_id: u32,
}

impl ResponseErrorThread {
    pub fn new(
        sender: Sender<CoordinatorEvent>,
        context: ResponseContext,
        dump_error: DumpError,
        request_id: u32,
    ) -> Self {
        ResponseErrorThread {
            sender,
            context,
            dump_error,
            request_id,
        }
    }

    async fn send_to_update(&self, msg: CoordinatorEvent) {
        if let Err(err) = self.sender.send(msg).await {
            trace!(
                "{:FL$}Error sending CoordinatorEvent to Coordinator (Coordinator likely exited): {:?}",
                "ResponseErrorThread", err
            );
        }
    }

    pub async fn process(&self) {
        trace!(
            "{:FL$}Processing dump error [ID: {}] for service {:?}, api {:?}",
            "ResponseErrorThread", self.request_id, self.dump_error.folder, self.dump_error.file
        );
        if self.dump_error.code == "TooManyRequests" {
            // Unreached fallback: every live 429 (single, batch wrapper, and batch
            // sub-response) already sets the cooldown with the real `Retry-After`
            // upstream in `status_handlers::report_too_many_requests`, and none of
            // those paths produce a `DumpError` with this code. The default delay
            // here is therefore acceptable; `DumpError` carries no `Retry-After`
            // field, and adding one would change `errors.json` for no live benefit.
            self.context
                .ratelimit_manager
                .report_429(&self.dump_error.folder, None);
            self.context
                .concurrency_controller
                .report_429(&self.dump_error.folder);
        }
        if let Err(err) = self
            .context
            .write_dump_error(&self.dump_error, self.request_id)
            .await
        {
            let mut last_err = err;
            let mut success = false;
            let backoffs = [
                Duration::from_millis(10),
                Duration::from_millis(50),
                Duration::from_millis(100),
            ];
            trace!(
                "{:FL$}First attempt to write dump error [ID: {}] failed: {:?}",
                "ResponseErrorThread", self.request_id, last_err
            );

            for (i, delay) in backoffs.iter().enumerate() {
                sleep(*delay).await;
                if let Err(e) = self
                    .context
                    .write_dump_error(&self.dump_error, self.request_id)
                    .await
                {
                    last_err = e;
                } else {
                    success = true;
                    break;
                }
                trace!(
                    "{:FL$}Retry {}/3 to write dump error [ID: {}] failed: {:?}",
                    "ResponseErrorThread",
                    i + 1,
                    self.request_id,
                    last_err
                );
            }

            if !success {
                error!(
                    "{:FL$}Failed to write dump error [ID: {}] to archive after 3 retries: {:?}",
                    "ResponseErrorThread", self.request_id, last_err
                );
                if let Err(e) = self.context.writer.set_broken().await {
                    error!(
                        "{:FL$}Could not mark archive broken: {:?}",
                        "ResponseErrorThread", e
                    );
                }
                bail_fatal!(Error::StringError(
                    "could not write DumpError to archive after 3 retries".into()
                ));
            }
        }
        self.send_to_update(CoordinatorEvent::NewError(
            self.dump_error.folder.clone().into(),
            ProcessError::DumpError(1),
        ))
        .await;
        self.send_to_update(CoordinatorEvent::RequestCompleted {
            service: self.dump_error.folder.clone().into(),
            id: self.request_id,
            new_urls: vec![],
            count: 1,
        })
        .await;
    }
}
