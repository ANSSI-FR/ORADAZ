//! Log-line builders for transport failures seen by the request thread.
//! Pure functions so the wording an operator greps for in `oradaz.log` is
//! pinned by tests; call sites only choose the level.

use crate::utils::stats::NetworkErrorKind;
use crate::utils::url::Url;

/// DEBUG line naming one sub-request of a batch envelope that failed at the
/// transport layer (`index` is 1-based).
pub(super) fn batch_sub_request_line(
    batch_id: u32,
    kind: NetworkErrorKind,
    index: usize,
    total: usize,
    url: &Url,
) -> String {
    format!(
        "Batch [ID: {batch_id}] transport failure ({kind:?}) — sub-request {index}/{total}: {}/{} url {:?}",
        url.service_name, url.api, url.url
    )
}

/// WARN line emitted when a sub-URL is switched to single dispatch.
pub(super) fn degrade_line(url: &Url, network_errors: usize, batch_id: u32) -> String {
    format!(
        "Batch kept failing at the transport layer; degrading {:?}/{:?} to single dispatch ({} network errors) — url {:?} [ID: {}]",
        url.service_name, url.api, network_errors, url.url, batch_id
    )
}

/// DEBUG line emitted when a single request's next attempt gets a longer
/// timeout. `url.timeout_strikes` already includes the current timeout.
pub(super) fn escalation_line(url: &Url, next_timeout_secs: u64, call_id: u32) -> String {
    format!(
        "Timeout escalation for {:?}/{:?}: next single attempt waits up to {}s (timeout #{}) — url {:?} [ID: {}]",
        url.service_name, url.api, next_timeout_secs, url.timeout_strikes, url.url, call_id
    )
}

/// WARN line emitted when a URL is abandoned as `NetworkStalled`. Both counters
/// include the failure being handled.
pub(super) fn network_stalled_line(
    url: &Url,
    network_errors: usize,
    single_timeouts: usize,
    last_timeout_secs: u64,
    call_id: u32,
) -> String {
    format!(
        "Abandoning {:?}/{:?} as NetworkStalled: no data written within the liveness ceiling ({} network errors, {} single-request timeouts, last attempt timeout {}s, forced single: {}) — url {:?} [ID: {}]",
        url.service_name,
        url.api,
        network_errors,
        single_timeouts,
        last_timeout_secs,
        url.force_single,
        url.url,
        call_id
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url() -> Url {
        let mut u: Url = serde_json::from_value(serde_json::json!({
            "service_name": "graph",
            "service_scopes": [],
            "service_mandatory_auth": false,
            "api": "signIns",
            "url": "https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=userId eq 'u1'",
            "conditions": null,
            "relationships": [],
            "api_behavior": {},
            "expected_error_codes": null,
            "parent": null,
            "retry_number": 0
        }))
        .unwrap();
        u.timeout_strikes = 4;
        u.force_single = true;
        u
    }

    #[test]
    fn sub_request_line_names_api_and_url() {
        let l = batch_sub_request_line(857, NetworkErrorKind::Timeout, 3, 17, &url());
        assert!(
            l.contains("Batch [ID: 857] transport failure (Timeout)"),
            "{l}"
        );
        assert!(l.contains("sub-request 3/17: graph/signIns"), "{l}");
        assert!(
            l.contains("auditLogs/signIns?$filter=userId eq 'u1'"),
            "{l}"
        );
    }

    #[test]
    fn degrade_line_carries_the_url() {
        let l = degrade_line(&url(), 2, 857);
        assert!(
            l.contains("degrading \"graph\"/\"signIns\" to single dispatch (2 network errors)"),
            "{l}"
        );
        assert!(l.contains("auditLogs/signIns"), "{l}");
    }

    #[test]
    fn escalation_line_reports_next_timeout_and_count() {
        let l = escalation_line(&url(), 240, 912);
        assert!(l.contains("waits up to 240s (timeout #4)"), "{l}");
    }

    #[test]
    fn network_stalled_line_reports_every_counter() {
        let l = network_stalled_line(&url(), 6, 4, 240, 1001);
        assert!(l.contains("as NetworkStalled"), "{l}");
        assert!(l.contains("6 network errors, 4 single-request timeouts, last attempt timeout 240s, forced single: true"), "{l}");
        assert!(l.contains("auditLogs/signIns"), "{l}");
    }
}
