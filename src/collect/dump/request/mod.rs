/// Module to perform requests to the Azure APIs.
///
/// This module manages a pool of worker tasks that execute API calls provided by the Dumper.
/// It coordinates concurrency limits (per-service) and rate limiting
/// before dispatching requests via the `RequestsThread`.
///
/// - Successful responses are sent to the Response module.
/// - Failures and requests requiring retries send events to the Coordinator.
pub mod executor;
mod thread;
pub use thread::RequestsThread;

use crate::FL;
use crate::collect::auth::tokens::SharedTokenState;
use crate::collect::dump::concurrency::ConcurrencyController;
use crate::collect::dump::orchestration::events::CoordinatorEvent;
use crate::collect::dump::ratelimit::RateLimitManager;
use crate::collect::dump::response::ResponseMsg;
use crate::utils::client::OradazClient;
use crate::utils::config::Config;
use crate::utils::errors::Error;
use crate::utils::stats::Stats;
use crate::utils::url::ApiCall;

use dashmap::DashMap;
use log::{debug, error, trace};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task::JoinSet;

/// Messages received by the `RequestModule` from the Dumper.
pub enum RequestMsg {
    /// A request to execute a specific API call.
    ApiCall(Box<ApiCall>),
    /// Signal to gracefully shut down the module.
    Terminate,
}

/// Global counter for requests that were retried due to transient errors.
pub static RETRY_COUNT: AtomicU64 = AtomicU64::new(0);

/// Instantaneous count of request slots currently sleeping in a retry/cooldown
/// backoff. Each counted slot holds an AIMD concurrency permit while its worker
/// waits instead of issuing a request, so a high value is a throttling/transport
/// degradation signal (surfaced as the progress UI's "Backoff: N").
pub static BACKOFF_ACTIVE: AtomicU64 = AtomicU64::new(0);

/// Peak value of [`BACKOFF_ACTIVE`] over the run — the largest number of request
/// slots ever simultaneously parked in a retry/cooldown backoff. Updated at the
/// increment site by [`BackoffGuard::enter`]; a high peak means throttling
/// degraded a large share of the pipeline at once (throttling-severity signal).
pub static PEAK_BACKOFF_ACTIVE: AtomicU64 = AtomicU64::new(0);

/// Peak simultaneous backoff-slot count observed over the run.
pub fn peak_backoff_active() -> u64 {
    PEAK_BACKOFF_ACTIVE.load(Ordering::Relaxed)
}

/// Base delay in ms for backoff, read from Config at dump start (default 250).
pub static BACKOFF_BASE_MS: AtomicU64 = AtomicU64::new(250);

/// Maximum delay cap in ms for backoff, read from Config at dump start (default 8000).
pub static BACKOFF_CAP_MS: AtomicU64 = AtomicU64::new(8000);

/// RAII guard that decrements `BACKOFF_ACTIVE` when dropped.
/// Ensures the counter is never leaked if the owning future is dropped during a backoff sleep.
pub(crate) struct BackoffGuard;

impl BackoffGuard {
    /// Enters a backoff: increments [`BACKOFF_ACTIVE`] (updating its peak) and
    /// returns a guard that decrements it on drop. Pairing the increment with the
    /// guard in one place makes an unbalanced increment impossible and is the sole
    /// update site for [`PEAK_BACKOFF_ACTIVE`].
    pub(crate) fn enter() -> Self {
        let now = BACKOFF_ACTIVE.fetch_add(1, Ordering::Relaxed) + 1;
        PEAK_BACKOFF_ACTIVE.fetch_max(now, Ordering::Relaxed);
        BackoffGuard
    }
}

impl Drop for BackoffGuard {
    fn drop(&mut self) {
        BACKOFF_ACTIVE.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Computes an exponential backoff with up to +50 % jitter.
///
/// Sequence (base=250, cap=8000 by default): 250 → 500 → 1000 → 2000 → 4000 → 8000 ms.
/// Base and cap are read from `BACKOFF_BASE_MS` / `BACKOFF_CAP_MS`, which are initialised
/// from `Config::retry_backoff_base_ms` / `Config::retry_backoff_cap_ms` at dump start.
pub fn compute_backoff_ms(retry_number: usize) -> u64 {
    let base = BACKOFF_BASE_MS.load(Ordering::Relaxed);
    let cap = BACKOFF_CAP_MS.load(Ordering::Relaxed);
    let exp = base.saturating_mul(1u64 << retry_number.min(6));
    let clamped = exp.min(cap);
    let half = clamped / 2;
    // random::<f64>() in [0, 1) → jitter in [0, half)
    let jitter = if half > 0 {
        (rand::random::<f64>() * half as f64) as u64
    } else {
        0
    };
    clamped + jitter
}

/// Shared infrastructure needed to execute a single API call.
///
/// Bundling these as one cloneable struct keeps `RequestModule::new` and
/// `RequestsThread::new` to a small number of arguments and makes the
/// per-worker clone site explicit.
#[derive(Clone)]
pub struct RequestExecutionContext {
    pub oradaz_client: OradazClient,
    pub tokens: Arc<DashMap<Arc<str>, SharedTokenState>>,
    pub ratelimit_manager: Arc<RateLimitManager>,
    pub concurrency_controller: Arc<ConcurrencyController>,
    pub stats: Arc<Stats>,
    /// Cached cloneable handle to the run configuration. Carried in the context
    /// so per-service overrides (currently: `httpTimeoutSeconds`) can be
    /// consulted inside the executor without threading `Arc<Config>` through
    /// every call site.
    pub config: Arc<Config>,
}

/// The core request dispatcher that orchestrates API call execution.
pub struct RequestModule {
    receiver: Receiver<RequestMsg>,
    response_sender: Sender<ResponseMsg>,
    update_sender: Sender<CoordinatorEvent>,
    context: RequestExecutionContext,
}

impl RequestModule {
    pub fn new(
        receiver: Receiver<RequestMsg>,
        response_sender: Sender<ResponseMsg>,
        update_sender: Sender<CoordinatorEvent>,
        context: RequestExecutionContext,
    ) -> Self {
        RequestModule {
            receiver,
            response_sender,
            update_sender,
            context,
        }
    }

    /// Starts the request processing loop.
    ///
    /// This loop waits for `RequestMsg` and spawns a `RequestsThread` for each `ApiCall`
    /// after acquiring the necessary concurrency slot.
    pub async fn start(self) -> Result<(), Error> {
        debug!(
            "{:FL$}Attempting to start async loop to perform the dump",
            "RequestModule"
        );
        let mut receiver = self.receiver;
        let response_sender = self.response_sender;
        let update_sender = self.update_sender;
        let context = self.context;
        let mut workers = JoinSet::new();

        loop {
            trace!("{:FL$}Waiting for message from receiver", "RequestModule");
            tokio::select! {
                biased;
                // Reap finished workers as they complete so the JoinSet does not
                // accumulate one entry per dispatched call for the whole run, and
                // detect a panicked worker: a worker that panics before emitting its
                // `RequestCompleted` would strand the coordinator's in-flight counter
                // and hang the run. The `if !workers.is_empty()` guard parks the loop
                // on `recv()` when nothing is in flight.
                Some(joined) = workers.join_next(), if !workers.is_empty() => {
                    if let Err(join_err) = joined
                        && join_err.is_panic()
                    {
                        error!(
                            "{:FL$}A request worker panicked ({join_err}); aborting collection",
                            "RequestModule"
                        );
                        // The coordinator's counter can no longer reach zero, so wake it
                        // to drain into a clean `.broken` archive instead of stalling.
                        let _ = update_sender.send(CoordinatorEvent::Terminate).await;
                        return Err(Error::StringError(format!(
                            "request worker panicked: {join_err}"
                        )));
                    }
                }
                msg = receiver.recv() => match msg {
                    Some(RequestMsg::Terminate) => {
                        debug!("{:FL$}Received Terminate message", "RequestModule");
                        break;
                    }
                    Some(RequestMsg::ApiCall(next_api_call)) => {
                        // Concurrency control is applied inside `RequestsThread::process`
                        // (it acquires the per-service AIMD slot there), not before the
                        // spawn — the worker parks on the slot once running.
                        workers.spawn({
                            let thread_response_sender = response_sender.clone();
                            let thread_update_sender = update_sender.clone();
                            let thread_context = context.clone();
                            async move {
                                // Track this in-flight request worker for memory
                                // observability: it parks on the per-service AIMD
                                // slot and, when throttled, on the rate-limit
                                // cooldown inside `process`, so a throttled service
                                // accumulates parked workers. The guard decrements
                                // the gauge when the worker finishes.
                                let _worker_guard =
                                    crate::utils::sysmem::track_request_worker();
                                let rt = RequestsThread::new(
                                    thread_response_sender,
                                    thread_update_sender,
                                    thread_context,
                                    next_api_call,
                                );
                                rt.process().await;
                            }
                        });
                    }
                    None => {
                        error!(
                            "{:FL$}Could not receive a message due to disconnected channel",
                            "RequestModule"
                        );
                        return Err(Error::RecvError);
                    }
                }
            }
        }

        drop(receiver);
        drop(response_sender);
        drop(update_sender);

        // Drain remaining workers, surfacing a panic that occurs during shutdown.
        while let Some(joined) = workers.join_next().await {
            if let Err(join_err) = joined
                && join_err.is_panic()
            {
                error!(
                    "{:FL$}A request worker panicked during shutdown drain ({join_err})",
                    "RequestModule"
                );
                return Err(Error::StringError(format!(
                    "request worker panicked during drain: {join_err}"
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod backoff_tests {
    use super::compute_backoff_ms;

    #[test]
    fn test_compute_backoff_ms_exponential_growth() {
        // Base is 250; without jitter the sequence is 250, 500, 1000, 2000, 4000, 8000 (cap).
        // With jitter [0, base/2) the result is in [base, base*1.5).
        let base: [u64; 7] = [250, 500, 1000, 2000, 4000, 8000, 8000];
        for (i, &b) in base.iter().enumerate() {
            let ms = compute_backoff_ms(i);
            assert!(
                ms >= b && ms < b + b / 2 + 1,
                "retry {i}: {ms} not in [{b}, {})",
                b + b / 2 + 1
            );
        }
    }

    #[test]
    fn test_compute_backoff_ms_capped_at_8000() {
        let ms = compute_backoff_ms(100);
        assert!(
            (8000..=12000).contains(&ms),
            "capped result {ms} out of range"
        );
    }
}
