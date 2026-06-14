use crate::collect::auth::AuthError;
use crate::utils::url::Url;

use std::sync::Arc;

/// Types of errors encountered during the processing of a request that may require
/// a retry or a change in the dump strategy.
#[derive(Debug, Clone)]
pub enum ProcessError {
    /// The authentication token has expired and needs renewal.
    TokenExpirationError,
    /// A general error occurred during the dump of a specific resource.
    DumpError(usize),
    /// A prerequisite for the dump is missing (e.g., a specific API endpoint is not available).
    PotentialPrerequisiteError(Box<Url>),
}

/// Outcome of a prerequisite re-check for a single service.
#[derive(Debug, Clone)]
pub enum PrereqOutcome {
    /// The check passed; the service can resume normal dispatch.
    Success,
    /// The check failed with the given error message.
    Failure(String),
    /// The service is rate-limited; wait the given number of seconds before retrying.
    Throttled(u64),
}

/// Events that trigger reactions in the coordinator.
pub enum CoordinatorEvent {
    /// Signal to stop the orchestration loop.
    Terminate,
    /// An error occurred during a request or response processing.
    NewError(Arc<str>, ProcessError),
    /// A request has finished, together with any new URLs it discovered.
    RequestCompleted {
        service: Arc<str>,
        id: u32,
        new_urls: Vec<Url>,
        count: usize,
    },
    /// The expected-error breaker fired for one `(service, api)` bucket: it
    /// accumulated the configured number of consecutive schema-declared
    /// expected errors without ever writing a page. The coordinator drops the
    /// bucket's remaining pool URLs (and any that get re-queued later) as
    /// *skipped* — every one of them would return the same declared-benign
    /// error, so they are not data losses and do not affect the verdict.
    BreakerTripped { service: Arc<str>, api: String },
    /// A background prerequisite re-check completed; contains the outcome.
    PrereqResult(Arc<str>, PrereqOutcome),
    /// Resume dispatching URLs for a service (sent after rate-limit sleep or user prompt).
    ResumeService(Arc<str>),
    /// A background token refresh completed successfully; the coordinator removes
    /// the service from `token_refresh_in_flight` so its URLs dispatch again with
    /// the fresh token.
    TokenRefreshed(Arc<str>),
    /// A background token refresh failed permanently (an application-credential
    /// flow exhausted its retries, or the token endpoint returned a definitive
    /// authentication error). `auth_error` is present in the latter case so the
    /// coordinator can record it before aborting the run into a `.broken` archive.
    TokenRefreshFailed {
        service: Arc<str>,
        auth_error: Option<AuthError>,
        message: String,
    },
}
