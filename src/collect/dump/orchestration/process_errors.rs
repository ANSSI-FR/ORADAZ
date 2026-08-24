use crate::FL;
use crate::collect::dump::Dumper;
use crate::collect::dump::orchestration::events::ProcessError;
use crate::utils::errors::Error;
use crate::utils::url::Url;

use log::{error, trace};

/// Processes `DumpError` events from the coordinator.
///
/// `PotentialPrerequisiteError` and `TokenExpirationError` are handled directly in
/// the coordinator loop (each spawns a background task and tracks in-flight state),
/// so they must not be passed here.
pub async fn process_errors(
    dumper: &mut Dumper,
    service: &str,
    error: ProcessError,
) -> Result<Option<Url>, Error> {
    match error {
        ProcessError::DumpError(en) => {
            trace!(
                "{:FL$}Adding {} to errors_number for service {:?}",
                "Dumper", en, service
            );
            dumper.errors_number += en;
            Ok(None)
        }
        ProcessError::TokenExpirationError => {
            // Should never be reached: the coordinator handles this variant directly
            // (spawns token_refresh_task) before any call to process_errors.
            // Returning an error here rather than panicking ensures the archive is
            // properly renamed .broken if this invariant is ever violated.
            error!(
                "{:FL$}BUG: TokenExpirationError reached process_errors — must be handled by coordinator",
                "Dumper"
            );
            Err(Error::StringError(
                "internal error: unexpected TokenExpirationError in process_errors".into(),
            ))
        }
        ProcessError::PotentialPrerequisiteError(_) => {
            // Should never be reached: the coordinator handles this variant directly
            // (spawns prereq_check_task) before any call to process_errors.
            // Returning an error here rather than panicking ensures the archive is
            // properly renamed .broken if this invariant is ever violated.
            error!(
                "{:FL$}BUG: PotentialPrerequisiteError reached process_errors — must be handled by coordinator",
                "Dumper"
            );
            Err(Error::StringError(
                "internal error: unexpected PotentialPrerequisiteError in process_errors".into(),
            ))
        }
    }
}
