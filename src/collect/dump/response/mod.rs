/// Module to write API responses to the archive.
///
/// This module receives successful API responses and writes them to the output archive.
/// After writing, it sends `CoordinatorEvent`s back to the Coordinator to report
/// completions and any new URLs discovered (pagination, relationships).
pub mod batch;
pub mod error_thread;
pub mod single;
pub mod status_handlers;
pub mod thread;

pub use error_thread::ResponseErrorThread;
pub use thread::ResponseThread;

use crate::FL;
use crate::collect::auth::tokens::SharedTokenState;
use crate::collect::dump::concurrency::ConcurrencyController;
use crate::collect::dump::conditions::ConditionChecker;
use crate::collect::dump::orchestration::events::CoordinatorEvent;
use crate::collect::dump::ratelimit::RateLimitManager;
use crate::utils::errors::Error;
use crate::utils::metadata::TableMetadata;
use crate::utils::stats::Stats;
use crate::utils::url::ApiCall;
use crate::utils::writer::actor::WriterHandle;

use dashmap::DashMap;
use log::{debug, error, trace};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task::JoinSet;

/// Details of an error encountered during the dump process that should be recorded in the archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpError {
    /// Service name (folder).
    pub folder: String,
    /// API name (file).
    pub file: String,
    /// Full URL of the failed request.
    pub url: String,
    /// HTTP status code.
    pub status: u16,
    /// Error code returned by the API.
    pub code: String,
    /// Error message returned by the API.
    pub message: String,
    /// Whether this error is declared in the schema's `expected_error_codes` for
    /// the parent endpoint, i.e. a known benign failure (e.g. 403 on PIM
    /// endpoints for non-role-assignable groups) versus a true anomaly.
    /// Defaults to `false` for errors with no HTTP status (network failures,
    /// nextLink parsing, retry-limit give-ups) and when deserializing an
    /// archive written before this field existed.
    #[serde(default)]
    pub expected: bool,
    /// Optional full response body for debugging.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_response: Option<serde_json::Value>,
    /// Optional POST data sent with the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_data: Option<serde_json::Value>,
}

impl DumpError {
    /// True when this error means data the user expected is missing from the
    /// archive: a non-HTTP terminal failure (`status == 0`, not `expected`)
    /// where the request never yielded its data — `UrlRetryLimit` (URL
    /// abandoned), `NoTokenForApiCall`, `nextLinkParsingError`,
    /// `MissingBatchData`, `UnknownApiCallCreationError`. These bypass
    /// `unexpected_errors` (which needs an HTTP status ≥ 400) and feed the
    /// end-of-collection "PARTIAL COLLECTION" summary.
    ///
    /// Excludes `MissingTokenForRelationships`: it fires *after* the endpoint's
    /// own page was already written to the archive (only relationship/child-URL
    /// expansion was skipped) and carries an empty api name, so it is neither a
    /// primary-data loss nor renderable as an API row — it must not flip the run
    /// to PARTIAL.
    pub fn is_lost_data(&self) -> bool {
        self.status == 0 && !self.expected && self.code != "MissingTokenForRelationships"
    }
}

/// Represents a raw HTTP response from an API.
#[derive(Debug, Clone)]
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// Retry-After duration in seconds. `None` when the response carried no
    /// usable `Retry-After`, so the rate-limit manager applies its configured
    /// per-service / global default.
    pub retry_after: Option<u64>,
    /// Parsed JSON body (`Value::Null` when the body was not valid JSON).
    pub content: Value,
}

/// Combines an API call with its corresponding response.
pub struct ResponseContent {
    pub api_call: ApiCall,
    pub response: Response,
}

/// Messages processed by the `ResponseModule`.
pub enum ResponseMsg {
    /// Valid response data to be written to the archive.
    ResponseData(Box<ResponseContent>),
    /// An error that should be logged in the archive's error log. Emits a
    /// `RequestCompleted` (count 1): used by dispatch, where the abandoned
    /// `ApiCallError` item was itself counted into `current_counter`.
    DumpError(Box<DumpError>, u32),
    /// Counter-**neutral** lost-data write: persisted to `errors.json` and
    /// recorded for the PARTIAL summary like `DumpError`, but emits **no**
    /// `RequestCompleted`. Used by the request thread to abandon a transient
    /// (network) sub-URL whose dispatched item is already accounted for by the
    /// batch's own single `RequestCompleted` in `finalize_retry` — so a separate
    /// completion here would double-decrement `current_counter`.
    LostData(Box<DumpError>, u32),
    /// Signal to shut down the module.
    Terminate,
}

/// Shared state and resources required by response processing threads.
#[derive(Clone)]
pub struct ResponseContext {
    /// Handle to the archive writer.
    pub writer: WriterHandle,
    /// Metadata for the tables being dumped.
    pub metadata: Arc<Mutex<HashMap<String, TableMetadata>>>,
    /// Authentication tokens for the various services.
    pub tokens: Arc<DashMap<Arc<str>, SharedTokenState>>,
    /// Logic to check if certain dump conditions are met.
    pub condition_checker: Arc<ConditionChecker>,
    /// Rate limit manager.
    pub ratelimit_manager: Arc<RateLimitManager>,
    /// Concurrency controller.
    pub concurrency_controller: Arc<ConcurrencyController>,
    /// Shared statistics counter; per-response status codes are recorded here.
    pub stats: Arc<Stats>,
    /// Pre-computed ` and createdDateTime ge <cutoff>` clause substituted for the
    /// optional `[SIGNIN_FILTER]` marker when a per-user `signIns` relationship URI
    /// carries it, bounding sign-ins to the configured `logsDaysFilter`. `None`
    /// when date bounding is disabled.
    pub logs_date_filter_and: Option<Arc<str>>,
}

impl ResponseContext {
    /// Writes a `DumpError` to the `errors.json` file in the archive.
    pub async fn write_dump_error(&self, dump_error: &DumpError, id: u32) -> Result<(), Error> {
        let string_error: String = match serde_json::to_string(dump_error) {
            Err(err) => {
                error!(
                    "{:FL$}Could not convert dump_error [ID: {}] to json, could not treat archive as broken",
                    "ResponseContext", id
                );
                debug!(
                    "{:FL$}Error serializing dump_error [ID: {}] {:?}: {:?}",
                    "ResponseContext", id, dump_error, err
                );
                return Err(Error::StringError(
                    "Failed to serialize dump_error to JSON".into(),
                ));
            }
            Ok(j) => format!("{j}\n"),
        };
        if let Err(err) = self
            .writer
            .write_file(String::new(), "errors.json".to_string(), string_error)
            .await
        {
            error!(
                "{:FL$}Error while writing DumpError [ID: {}] to archive, could not treat archive as broken",
                "ResponseContext", id
            );
            error!("{:FL$}Error [ID: {}]: {:?}", "ResponseContext", id, err);
            return Err(Error::StringError(
                "Failed to write DumpError to archive".into(),
            ));
        }
        // Record lost-data failures (data never obtained) for the end-of-collection
        // "PARTIAL COLLECTION" summary. These bypass `unexpected_errors` (which needs an
        // HTTP status ≥ 400), so without this they would be invisible in the summary.
        // Placed on the success path so a write that failed-and-retried records exactly
        // once. See `DumpError::is_lost_data` for which errors qualify.
        if dump_error.is_lost_data() {
            self.stats
                .record_lost_data(&dump_error.folder, &dump_error.file, &dump_error.code);
        }
        Ok(())
    }
}

/// The core module responsible for persisting API results.
pub struct ResponseModule {
    receiver: Receiver<ResponseMsg>,
    sender: Sender<CoordinatorEvent>,
    pub context: ResponseContext,
}

impl ResponseModule {
    pub fn new(
        receiver: Receiver<ResponseMsg>,
        sender: Sender<CoordinatorEvent>,
        context: ResponseContext,
    ) -> Self {
        ResponseModule {
            receiver,
            sender,
            context,
        }
    }

    /// Starts the response processing loop.
    ///
    /// Spawns `ResponseThread` or `ResponseErrorThread` tasks to handle incoming `ResponseMsg`.
    pub async fn start(self) -> Result<(), Error> {
        let mut receiver = self.receiver;
        let sender = self.sender;
        let context = self.context.clone();
        let mut workers = JoinSet::new();

        loop {
            trace!("{:FL$}Waiting for message from receiver", "ResponseModule");
            tokio::select! {
                biased;
                // Reap finished workers (so the JoinSet does not grow O(responses) for
                // the whole run) and detect a panicked worker: one that panics before
                // emitting its `RequestCompleted` would strand the coordinator's counter
                // and hang the run. The `if !workers.is_empty()` guard parks on `recv()`
                // when nothing is in flight.
                Some(joined) = workers.join_next(), if !workers.is_empty() => {
                    if let Err(join_err) = joined
                        && join_err.is_panic()
                    {
                        error!(
                            "{:FL$}A response worker panicked ({join_err}); aborting collection",
                            "ResponseModule"
                        );
                        // Wake the coordinator (its counter can no longer reach zero) so
                        // it drains into a clean `.broken` archive instead of stalling.
                        let _ = sender.send(CoordinatorEvent::Terminate).await;
                        return Err(Error::StringError(format!(
                            "response worker panicked: {join_err}"
                        )));
                    }
                }
                msg = receiver.recv() => match msg {
                    Some(ResponseMsg::Terminate) => {
                        break;
                    }
                    Some(ResponseMsg::ResponseData(response_data)) => {
                        workers.spawn({
                            let thread_sender = sender.clone();
                            let thread_context = context.clone();
                            async move {
                                // Tracks this worker in the response-worker gauge for
                                // memory observability (each worker holds a parsed
                                // JSON page); decremented when the guard drops.
                                let _worker_guard = crate::utils::sysmem::track_response_worker();
                                let rt: ResponseThread = ResponseThread::new(
                                    thread_sender,
                                    thread_context,
                                    response_data,
                                );
                                rt.process().await;
                            }
                        });
                    }
                    Some(ResponseMsg::DumpError(dump_error, id)) => {
                        workers.spawn({
                            let thread_sender = sender.clone();
                            let thread_context = context.clone();
                            async move {
                                // See the ResponseData arm: same response-worker
                                // gauge tracking for memory observability.
                                let _worker_guard = crate::utils::sysmem::track_response_worker();
                                // completion_count = 1: the abandoned ApiCallError
                                // item was counted into current_counter at dispatch.
                                let rt: ResponseErrorThread = ResponseErrorThread::new(
                                    thread_sender,
                                    thread_context.clone(),
                                    *dump_error,
                                    id,
                                    1,
                                );
                                rt.process().await;
                            }
                        });
                    }
                    Some(ResponseMsg::LostData(dump_error, id)) => {
                        workers.spawn({
                            let thread_sender = sender.clone();
                            let thread_context = context.clone();
                            async move {
                                let _worker_guard = crate::utils::sysmem::track_response_worker();
                                // completion_count = 0: counter-neutral. The
                                // batch's own RequestCompleted (finalize_retry)
                                // already accounts for the dispatched item.
                                let rt: ResponseErrorThread = ResponseErrorThread::new(
                                    thread_sender,
                                    thread_context.clone(),
                                    *dump_error,
                                    id,
                                    0,
                                );
                                rt.process().await;
                            }
                        });
                    }
                    None => {
                        error!(
                            "{:FL$}Could not receive a message due to disconnected channel",
                            "ResponseModule"
                        );
                        return Err(Error::RecvError);
                    }
                }
            }
        }

        drop(receiver);
        drop(sender);

        // Drain remaining workers, surfacing a panic that occurs during shutdown.
        while let Some(joined) = workers.join_next().await {
            if let Err(join_err) = joined
                && join_err.is_panic()
            {
                error!(
                    "{:FL$}A response worker panicked during shutdown drain ({join_err})",
                    "ResponseModule"
                );
                return Err(Error::StringError(format!(
                    "response worker panicked during drain: {join_err}"
                )));
            }
        }

        Ok(())
    }
}
