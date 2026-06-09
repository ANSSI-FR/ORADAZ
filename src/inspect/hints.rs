pub struct Hint {
    pub explanation: &'static str,
    pub remediation: &'static str,
}

static HINTS: &[(u16, &str, &str, &str)] = &[
    (
        401,
        "InvalidAuthenticationToken",
        "The authentication token is invalid or has expired.",
        "Rerun the collection. If the issue persists, check credentials and system clock synchronization.",
    ),
    (
        401,
        "Unauthorized",
        "Authentication failed.",
        "Verify the app registration credentials and that the token endpoint is reachable.",
    ),
    (
        403,
        "Authorization_RequestDenied",
        "The application lacks a required Microsoft Graph API permission.",
        "Add the missing permission in the Azure app registration, grant admin consent, then rerun.",
    ),
    (
        403,
        "Forbidden",
        "Access denied by the Microsoft API.",
        "Verify the app registration permissions and that admin consent has been granted.",
    ),
    (
        403,
        "InsufficientPrivileges",
        "The authenticated principal lacks the required role.",
        "Ensure the account has the required Azure AD administrative roles for this collection.",
    ),
    (
        404,
        "Request_ResourceNotFound",
        "The resource does not exist in this tenant.",
        "This is often expected for optional features. If it affects a required object, verify the tenant configuration.",
    ),
    (
        429,
        "",
        "Microsoft throttled the request (too many concurrent calls).",
        "Lower the concurrency window in the config (concurrencyMaxWindow), or add a serviceOverrides entry for the throttled service (e.g. resources), then retry.",
    ),
    (
        500,
        "",
        "A server-side error occurred on Microsoft's infrastructure.",
        "This may be transient. Retry the collection and check the Microsoft 365 service health dashboard.",
    ),
    (
        503,
        "",
        "The Microsoft service is temporarily unavailable.",
        "Retry later and check the Microsoft 365 service health dashboard.",
    ),
    // Lost-data causes (status `0` = no HTTP response; the URL was abandoned).
    // Keyed on the synthetic status `0` that `DumpError` carries for these.
    // The per-bucket liveness ceiling produces the first two; they are
    // rare and high-signal (an endpoint genuinely stuck past `livenessCeilingSecs`).
    (
        0,
        "ThrottleStalled",
        "The endpoint stayed throttled (HTTP 429) with no successful data write within the liveness ceiling, so it was abandoned to keep the run terminating. Its data is incomplete.",
        "This endpoint is rate-limited below the configured pace. Lower `concurrencyMaxWindow` (or add a `serviceOverrides` entry) for its service, and/or raise `livenessCeilingSecs`, then re-run.",
    ),
    (
        0,
        "NetworkStalled",
        "The endpoint kept failing at the transport layer (timeout / dropped connection / DNS) with no successful data write within the liveness ceiling, so it was abandoned. Its data is incomplete.",
        "Check network connectivity and any proxy configuration to the Microsoft endpoint, then re-run.",
    ),
    (
        0,
        "UrlRetryLimit",
        "The endpoint returned real errors (4xx/5xx) on every attempt until its `urlRetryLimit` budget was exhausted. Its data is incomplete.",
        "Open `oradaz inspect logs --service <service>` to see the failing status (permission, deleted resource, or persistent 5xx), fix the cause, then re-run.",
    ),
];

/// Returns a remediation hint for a known Microsoft API error, if one exists.
///
/// Matches by HTTP status first, then by upstream error code. An empty code in the
/// table acts as a wildcard (matches any code for that status).
pub fn get_hint(http_status: Option<u16>, upstream_code: Option<&str>) -> Option<Hint> {
    let status = http_status?;
    let code = upstream_code.unwrap_or("");
    HINTS
        .iter()
        .find(|(h_status, h_code, _, _)| {
            *h_status == status && (h_code.is_empty() || *h_code == code)
        })
        .map(|(_, _, explanation, remediation)| Hint {
            explanation,
            remediation,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hint_exact_code_match() {
        let h = get_hint(Some(403), Some("Authorization_RequestDenied"));
        assert!(h.is_some());
        assert!(h.unwrap().explanation.contains("permission"));
    }

    #[test]
    fn test_hint_wildcard_status() {
        // 429 has an empty code, should match any upstream code
        let h = get_hint(Some(429), Some("TooManyRequests"));
        assert!(h.is_some());
        let h2 = get_hint(Some(429), None);
        assert!(h2.is_some());
    }

    #[test]
    fn test_hint_unknown_status() {
        assert!(get_hint(Some(418), Some("ImATeapot")).is_none());
    }

    /// Lost-data causes are keyed on the synthetic status `0` carried by their
    /// `DumpError`s, with a code-specific remediation (throttle / network /
    /// permanent split).
    #[test]
    fn test_hint_lost_data_causes() {
        let throttle = get_hint(Some(0), Some("ThrottleStalled")).expect("ThrottleStalled hint");
        assert!(throttle.explanation.contains("throttled"));
        assert!(throttle.remediation.contains("concurrencyMaxWindow"));

        let network = get_hint(Some(0), Some("NetworkStalled")).expect("NetworkStalled hint");
        assert!(network.explanation.contains("transport"));

        let permanent = get_hint(Some(0), Some("UrlRetryLimit")).expect("UrlRetryLimit hint");
        assert!(permanent.explanation.contains("4xx/5xx"));

        // An unknown lost-data code still has no catalogued hint.
        assert!(get_hint(Some(0), Some("SomethingElse")).is_none());
    }

    #[test]
    fn test_hint_no_status() {
        assert!(get_hint(None, Some("Authorization_RequestDenied")).is_none());
    }
}
