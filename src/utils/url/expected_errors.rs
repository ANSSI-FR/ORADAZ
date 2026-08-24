use crate::utils::url::ApiCall;

use serde_json::Value;

/// Checks if a received HTTP status code and optional error code are within the
/// expected error codes defined for the API call.
///
/// This is used to identify "expected" errors that should not be treated as critical failures.
///
/// The error-code comparison is **case-insensitive** (ASCII): Microsoft APIs are
/// not consistent about the casing of error codes across services and API
/// versions (e.g. `Authorization_RequestDenied` vs `authorization_requestdenied`),
/// so a byte-exact match would silently misclassify a schema-declared expected
/// error as unexpected after an upstream casing change.
pub fn is_expected_error(
    status_code: u16,
    error_code_field: Option<&Value>,
    api_call: &ApiCall,
) -> bool {
    if let Some(expected_error_codes) = &api_call.url.expected_error_codes {
        for expected_error_code in expected_error_codes.iter() {
            if expected_error_code.status != status_code {
                continue;
            }
            match &expected_error_code.code {
                Some(expected_code) => {
                    if let Some(error_code) = error_code_field
                        && let Some(c) = error_code.as_str()
                        && c.eq_ignore_ascii_case(expected_code)
                    {
                        return true;
                    }
                }
                None => {
                    return true;
                }
            }
        }
    }
    false
}

/// Whether the response matches a schema-declared expected error that is flagged
/// `breaker_eligible` — the only kind the expected-error breaker may act on.
///
/// Mirrors [`is_expected_error`]'s matching (status, then case-insensitive code,
/// with a `None` code acting as a status wildcard) but additionally requires the
/// matched entry's `breaker_eligible` flag. The flag marks a **tenant-wide
/// all-or-nothing** failure (every URL of the endpoint returns it); per-object
/// expected errors are left unflagged so they never trip an API-wide skip. The
/// schema author opts a specific `(status, code)` in — there is no hard-coded
/// status, so any code asserted tenant-wide (not only 403) can drive the breaker.
pub fn is_breaker_eligible_error(
    status_code: u16,
    error_code_field: Option<&Value>,
    api_call: &ApiCall,
) -> bool {
    let Some(expected_error_codes) = &api_call.url.expected_error_codes else {
        return false;
    };
    for expected_error_code in expected_error_codes.iter() {
        if expected_error_code.status != status_code || !expected_error_code.breaker_eligible {
            continue;
        }
        match &expected_error_code.code {
            Some(expected_code) => {
                if let Some(error_code) = error_code_field
                    && let Some(c) = error_code.as_str()
                    && c.eq_ignore_ascii_case(expected_code)
                {
                    return true;
                }
            }
            None => {
                return true;
            }
        }
    }
    false
}
