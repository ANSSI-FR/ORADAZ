use crate::utils::errors::{Error, FatalPresentation};
use crate::{FL, bail_fatal};

use log::{error, warn};
use std::sync::{Mutex, MutexGuard};

/// Locks a mutex or terminates the process with a fatal error.
///
/// The caller must call `writer.set_broken().await` before any code path that
/// reaches this helper if an MLA archive is open.
pub fn lock_fatal<'a, T>(mutex: &'a Mutex<T>, err: Error) -> MutexGuard<'a, T> {
    mutex.lock().unwrap_or_else(|_| {
        bail_fatal!(err);
    })
}

/// Locks a mutex or logs a warning and returns None.
pub fn lock_warn<'a, T>(mutex: &'a Mutex<T>, module: &str, msg: &str) -> Option<MutexGuard<'a, T>> {
    match mutex.lock() {
        Ok(guard) => Some(guard),
        Err(e) => {
            warn!("{:FL$}{}: {}", module, msg, e);
            None
        }
    }
}

/// Locks a mutex, ignoring poisoning by recovering the inner data.
pub fn lock_force<'a, T>(mutex: &'a Mutex<T>) -> MutexGuard<'a, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// Locks a mutex or returns a specified error.
pub fn lock_result<'a, T>(
    mutex: &'a Mutex<T>,
    module: &str,
    msg: &str,
    err: Error,
) -> Result<MutexGuard<'a, T>, Error> {
    match mutex.lock() {
        Ok(guard) => Ok(guard),
        Err(e) => {
            error!("{:FL$}{}: {}", module, msg, e);
            Err(err)
        }
    }
}
