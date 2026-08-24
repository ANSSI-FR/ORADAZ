use crate::FL;
use crate::collect::auth::tokens::Token;
use crate::collect::dump::orchestration::events::{CoordinatorEvent, ProcessError};
use crate::collect::dump::request::RequestsThread;
use crate::collect::dump::response::{DumpError, ResponseMsg};
use crate::utils::url::{ApiCall, Url};

use log::{debug, trace};

/// Trait providing helper methods for handling request outcomes and errors.
pub trait RequestHandlers {
    /// Handles cases where the authentication token has expired.
    async fn handle_token_expiration(&self, t: &Token);
    /// Handles cases where no authentication token is available for the service.
    async fn handle_missing_token(&self);
    /// Dispatches a response message to the `ResponseModule`.
    async fn send_to_response(&self, msg: ResponseMsg);
    /// Dispatches an event message to the coordinator.
    async fn send_to_update(&self, msg: CoordinatorEvent);
}

impl RequestHandlers for RequestsThread {
    async fn handle_token_expiration(&self, t: &Token) {
        debug!(
            "{:FL$}Token expired for service {:?}, re-queuing api_call [ID: {}]",
            "RequestsThread", t.service, self.api_call.id
        );
        // Send an error indicating token expiration
        self.send_to_update(CoordinatorEvent::NewError(
            t.service.clone().into(),
            ProcessError::TokenExpirationError,
        ))
        .await;
        match &self.api_call.batch_data {
            Some(batch_data) => {
                // Process the URLs again as a single RequestCompleted event
                let new_urls: Vec<Url> = batch_data
                    .initial_data
                    .values()
                    .map(|d: &ApiCall| d.url.clone())
                    .collect();
                self.send_to_update(CoordinatorEvent::RequestCompleted {
                    service: self.api_call.url.service_name.clone().into(),
                    id: self.api_call.id,
                    new_urls,
                    count: 1,
                })
                .await;
            }
            None => {
                self.send_to_update(CoordinatorEvent::RequestCompleted {
                    service: self.api_call.url.service_name.clone().into(),
                    id: self.api_call.id,
                    new_urls: vec![self.api_call.url.clone()],
                    count: 1,
                })
                .await;
            }
        }
    }

    async fn handle_missing_token(&self) {
        debug!(
            "{:FL$}No token available for service {:?} [ID: {}]: {:?} {:?}",
            "RequestsThread",
            self.api_call.url.service_name,
            self.api_call.id,
            self.api_call.url.api,
            self.api_call.url.url
        );
        // Single or batch alike: re-queuing on a permanently absent token would loop
        // forever (no recovery path re-adds the token), so emit exactly one DumpError;
        // the response thread decrements the counter and records it. `post_data`
        // stays `None` for both. The batch
        // sub-URLs live in `batch_data` but are deliberately not surfaced here: they
        // are not retried (tokenless service), so the single per-batch error record
        // is the intended outcome.
        self.send_to_response(ResponseMsg::DumpError(
            Box::new(DumpError {
                folder: self.api_call.url.service_name.clone(),
                file: self.api_call.url.api.clone(),
                url: self.api_call.url.url.clone(),
                status: 0,
                code: String::from("NoTokenForApiCall"),
                message: format!(
                    "Missing token for service {:?}",
                    self.api_call.url.service_name.clone()
                ),
                expected: false,
                full_response: None,
                post_data: None,
            }),
            self.api_call.id,
        ))
        .await;
    }

    async fn send_to_response(&self, msg: ResponseMsg) {
        if let Err(err) = self.response_sender.send(msg).await {
            trace!(
                "{:FL$}Error sending ResponseMsg to ResponseModule (Coordinator likely exited): {:?}",
                "RequestsThread", err
            );
        }
    }

    async fn send_to_update(&self, msg: CoordinatorEvent) {
        if let Err(err) = self.update_sender.send(msg).await {
            trace!(
                "{:FL$}Error sending CoordinatorEvent to Coordinator (Coordinator likely exited): {:?}",
                "RequestsThread", err
            );
        }
    }
}
