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
use std::time::Instant;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
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
    /// where the request never yielded its data — `UrlRetryLimit` (real-error
    /// budget exhausted), `ThrottleStalled` / `NetworkStalled` (transient 429 /
    /// network retries hit the per-bucket liveness ceiling), `NoTokenForApiCall`,
    /// `nextLinkParsingError`, `MissingBatchData`, `UnknownApiCallCreationError`.
    /// These bypass `unexpected_errors` (which needs an HTTP status ≥ 400) and
    /// feed the end-of-collection "PARTIAL COLLECTION" summary.
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
        // Count every non-HTTP (`status == 0`) entry exactly, so the inspect
        // metadata view reports the real figure rather than deriving it from
        // `errors - (expected + unexpected)`, which underflows to 0 when 5xx
        // retries or batch-wrapper attribution inflate the response-counted sums.
        if dump_error.status == 0 {
            self.stats.record_non_http_error();
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
    /// Maximum number of worker tasks processing responses concurrently
    /// (`responseWorkersMax`; 0 = unbounded). Each worker holds a parsed JSON
    /// page until it is written, so this bound caps peak memory when responses
    /// arrive faster than the single-stream archive writer drains them; the
    /// wait for a permit backpressures the request→response channel.
    workers_max: usize,
    /// Byte budget for in-flight parsed pages (`responseMemoryBudgetBytes`;
    /// 0 = disabled). Independent of `workers_max`: a worker acquires permits
    /// sized to its page before processing, so a few very large pages serialise
    /// while many small ones still run at full width — bounding peak RSS where
    /// the worker-count bound cannot (large pages, e.g. Azure Resource Graph).
    mem_budget_bytes: usize,
}

/// Waits for a worker permit when a bound is configured. Returns `None` either
/// when unbounded (no semaphore) or if the semaphore is closed — the caller
/// spawns without a permit in both cases, keeping the pipeline alive. Time
/// spent waiting is accumulated in the response-worker admission-wait counter.
async fn acquire_worker_permit(semaphore: &Option<Arc<Semaphore>>) -> Option<OwnedSemaphorePermit> {
    let sem = semaphore.as_ref()?;
    let started = Instant::now();
    match Arc::clone(sem).acquire_owned().await {
        Ok(permit) => {
            let waited = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            if waited > 0 {
                crate::utils::sysmem::record_resp_sem_wait_ms(waited);
            }
            Some(permit)
        }
        Err(_) => None,
    }
}

/// Approximate in-memory footprint of a parsed JSON page, used to weight the
/// response byte budget. Tracks the JSON text size closely enough to pace a few
/// very large pages against many small ones.
fn estimate_value_bytes(v: &Value) -> usize {
    match v {
        Value::Null | Value::Bool(_) => 4,
        Value::Number(_) => 8,
        Value::String(s) => s.len() + 2,
        Value::Array(a) => 2 + a.iter().map(estimate_value_bytes).sum::<usize>(),
        Value::Object(o) => {
            2 + o
                .iter()
                .map(|(k, val)| k.len() + 4 + estimate_value_bytes(val))
                .sum::<usize>()
        }
    }
}

/// Waits on the response byte budget when one is configured, acquiring permits
/// sized to the page (capped at the whole budget so a page larger than the
/// budget still gets admitted — serialised — rather than deadlocking on permits
/// it can never obtain, mirroring the writer byte budget). Time spent waiting is
/// accumulated in the response byte-budget admission-wait counter.
async fn acquire_mem_permit(
    budget: &Option<Arc<Semaphore>>,
    budget_cap: usize,
    content: &Value,
) -> Option<OwnedSemaphorePermit> {
    let sem = budget.as_ref()?;
    let weight = estimate_value_bytes(content).clamp(1, budget_cap.max(1)) as u32;
    let started = Instant::now();
    match Arc::clone(sem).acquire_many_owned(weight).await {
        Ok(permit) => {
            let waited = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            if waited > 0 {
                crate::utils::sysmem::record_resp_mem_wait_ms(waited);
            }
            Some(permit)
        }
        Err(_) => None,
    }
}

impl ResponseModule {
    pub fn new(
        receiver: Receiver<ResponseMsg>,
        sender: Sender<CoordinatorEvent>,
        context: ResponseContext,
        workers_max: usize,
        mem_budget_bytes: usize,
    ) -> Self {
        ResponseModule {
            receiver,
            sender,
            context,
            workers_max,
            mem_budget_bytes,
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
        // Permits are released when the worker task drops its permit, not when
        // the JoinSet reaps it — so waiting for a permit below cannot deadlock
        // even while reaping is paused.
        let semaphore: Option<Arc<Semaphore>> =
            (self.workers_max > 0).then(|| Arc::new(Semaphore::new(self.workers_max)));
        // Byte budget for in-flight parsed pages. Capped at u32::MAX so a single
        // page's permit request always fits `acquire_many`. Disabled (None) when
        // `responseMemoryBudgetBytes` is 0.
        let mem_budget_cap = self.mem_budget_bytes.min(u32::MAX as usize);
        let mem_budget: Option<Arc<Semaphore>> =
            (mem_budget_cap > 0).then(|| Arc::new(Semaphore::new(mem_budget_cap)));

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
                        let permit = acquire_worker_permit(&semaphore).await;
                        // Weighted byte-budget admission: a few large pages
                        // serialise here while small pages pass freely, bounding
                        // peak RSS. No-op when the budget is disabled.
                        let mem_permit = acquire_mem_permit(
                            &mem_budget,
                            mem_budget_cap,
                            &response_data.response.content,
                        )
                        .await;
                        workers.spawn({
                            let thread_sender = sender.clone();
                            let thread_context = context.clone();
                            async move {
                                // Holds the admission permits for the lifetime of
                                // the worker; dropping them frees a worker slot and
                                // returns the page's bytes to the budget.
                                let _permit = permit;
                                let _mem_permit = mem_permit;
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
                        let permit = acquire_worker_permit(&semaphore).await;
                        workers.spawn({
                            let thread_sender = sender.clone();
                            let thread_context = context.clone();
                            async move {
                                let _permit = permit;
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
                        let permit = acquire_worker_permit(&semaphore).await;
                        workers.spawn({
                            let thread_sender = sender.clone();
                            let thread_context = context.clone();
                            async move {
                                let _permit = permit;
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;
    use tokio::time::timeout;

    /// Unbounded mode (no semaphore): spawning requires no permit.
    #[tokio::test]
    async fn acquire_permit_unbounded_returns_none() {
        assert!(acquire_worker_permit(&None).await.is_none());
    }

    /// Bounded mode: permits cap concurrent holders, and releasing one permit
    /// unblocks the next waiter.
    #[tokio::test]
    async fn acquire_permit_bounds_concurrency() {
        let sem = Some(Arc::new(Semaphore::new(2)));
        let p1 = acquire_worker_permit(&sem).await.expect("first permit");
        let _p2 = acquire_worker_permit(&sem).await.expect("second permit");

        // A third acquisition must wait while both permits are held…
        let blocked = timeout(Duration::from_millis(50), acquire_worker_permit(&sem)).await;
        assert!(blocked.is_err(), "third permit must wait at capacity");

        // …and proceed once a permit is released.
        drop(p1);
        let p3 = timeout(Duration::from_secs(1), acquire_worker_permit(&sem))
            .await
            .expect("a released permit must unblock the waiter");
        assert!(p3.is_some());
    }

    #[test]
    fn estimate_value_bytes_tracks_payload_size() {
        use serde_json::json;
        let small = estimate_value_bytes(&json!({"a": 1}));
        let big = estimate_value_bytes(&json!({"a": "x".repeat(1000)}));
        assert!(
            big > small + 900,
            "string length must dominate the estimate: {big} vs {small}"
        );
        let arr = estimate_value_bytes(&json!(["x".repeat(100), "y".repeat(100)]));
        assert!(arr >= 200, "an array sums its elements: {arr}");
    }

    /// The byte budget admits pages weighted by size: two ~budget-sized pages
    /// cannot be in flight at once, and a page larger than the whole budget is
    /// still admitted (clamped) rather than deadlocking on permits it can never
    /// obtain.
    #[tokio::test]
    async fn mem_permit_bounds_by_bytes_and_never_deadlocks() {
        use serde_json::json;
        let cap = 64usize;
        let budget = Some(Arc::new(Semaphore::new(cap)));
        let big = json!({ "k": "x".repeat(cap) });
        let p1 = acquire_mem_permit(&budget, cap, &big)
            .await
            .expect("first budget-sized page admitted");
        let blocked = timeout(
            Duration::from_millis(50),
            acquire_mem_permit(&budget, cap, &big),
        )
        .await;
        assert!(blocked.is_err(), "a second budget-sized page must wait");
        drop(p1);
        let huge = json!({ "k": "x".repeat(cap * 10) });
        let p2 = timeout(
            Duration::from_secs(1),
            acquire_mem_permit(&budget, cap, &huge),
        )
        .await
        .expect("an over-budget page must still be admitted");
        assert!(p2.is_some());
    }

    /// A disabled budget (None) never blocks and acquires no permit.
    #[tokio::test]
    async fn mem_permit_disabled_returns_none() {
        use serde_json::json;
        assert!(
            acquire_mem_permit(&None, 0, &json!({"a": 1}))
                .await
                .is_none()
        );
    }
}
