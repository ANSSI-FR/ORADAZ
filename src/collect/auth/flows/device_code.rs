/// Module to manage Device Code Flow authentication features.
use crate::FL;
use crate::collect::auth::tokens::Token;
use crate::collect::auth::tokens::response::{
    InitialTokenResponse, TokenEndpointResponse, oauth_error_summary, transport_error_summary,
};
use crate::utils::client::OradazClient;
use crate::utils::errors::Error;
use crate::utils::ui::auth_banner::AuthBanner;

use log::{debug, error, trace, warn};
use serde::Deserialize;
use std::time::Duration;

/// Device authorization endpoint response.
#[derive(Deserialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    /// Minimum polling interval in seconds (RFC 8628 §3.2, default 5).
    #[serde(default)]
    interval: Option<u64>,
}

/// Error response from the token endpoint during device code polling (RFC 8628 §3.5).
#[derive(Deserialize)]
struct PollingErrorResponse {
    error: String,
}

/// Errors that can occur during device code polling.
pub enum DeviceCodePollError {
    /// Device code expired before the user authenticated (recoverable: request fresh code).
    ExpiredToken,
    /// Terminal server error (access denied, unknown error).
    Terminal(String),
    /// HTTP transport error.
    Transport(reqwest::Error),
}

/// Utility for performing authentication using the Device Code flow.
pub struct DeviceCodeAuth {}

impl DeviceCodeAuth {
    /// Performs Azure authentication using the Device Code flow.
    ///
    /// This flow is used for devices that are input-constrained or lack a browser.
    /// It involves:
    /// 1. Requesting a device code and verification URI.
    /// 2. Displaying the URI and user code via a banner.
    /// 3. Polling the token endpoint until the user completes the authentication on their device.
    /// 4. Parsing the resulting token response.
    pub async fn get_token(
        oradaz_client: &OradazClient,
        tenant: String,
        service: String,
        client_id: String,
        scopes: Vec<String>,
    ) -> Result<Token, Error> {
        debug!(
            "{:FL$}Acquiring token for scopes '{}' using device code flow",
            "DeviceCodeAuth",
            scopes.join(" ")
        );

        let devicecode_endpoint =
            format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode");
        let token_endpoint =
            format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token");
        let scope_str = scopes.join(" ");

        // Live authentication banner (ticker starts on the first device code).
        let mut banner = AuthBanner::new();
        let mut banner_started = false;

        // Re-request a fresh device code whenever the previous one expires (the
        // user took too long to authenticate). Device-code expiry never aborts
        // the collection: only terminal errors (access denied, network failure)
        // bubble up. On expiry we swap the displayed code in place rather than
        // tearing down and reprinting the banner.
        let token_response: InitialTokenResponse = loop {
            // Request a device code.
            debug!("{:FL$}Getting code for device code flow", "DeviceCodeAuth");
            let dc_resp = match Self::request_device_code(
                &oradaz_client.client,
                &devicecode_endpoint,
                &client_id,
                &scope_str,
                &service,
            )
            .await
            {
                Ok(response) => response,
                Err(err) => {
                    if banner_started {
                        banner.failure("Device code flow authentication failed");
                    }
                    return Err(err);
                }
            };

            // Show the banner the first time; afterwards swap the code in place.
            if banner_started {
                banner.update_code(&dc_resp.user_code);
            } else {
                banner.begin(
                    &service,
                    &dc_resp.verification_uri,
                    &dc_resp.user_code,
                    "Device code",
                );
                banner_started = true;
            }

            // Poll the token endpoint (RFC 8628 §3.5).
            debug!("{:FL$}Exchanging code for token", "DeviceCodeAuth");
            match Self::poll_for_token(
                &oradaz_client.client,
                &token_endpoint,
                &client_id,
                &dc_resp.device_code,
                dc_resp.interval.unwrap_or(5),
            )
            .await
            {
                Ok(t) => break t,
                Err(err) if Self::is_device_code_expired(&err) => {
                    // The user did not authenticate in time. Loop and request a
                    // fresh device code; keep the banner up (debug-level only,
                    // no console clutter, collection is not interrupted).
                    debug!(
                        "{:FL$}Device code expired for service {:?}, requesting a new one",
                        "DeviceCodeAuth", service
                    );
                    continue;
                }
                Err(err) => {
                    let detail = match err {
                        DeviceCodePollError::Terminal(message) => message,
                        DeviceCodePollError::Transport(_) => {
                            "device code polling transport error".to_string()
                        }
                        DeviceCodePollError::ExpiredToken => {
                            // Should never be reached: the outer arm
                            // `Err(err) if Self::is_device_code_expired(&err)`
                            // catches all ExpiredToken errors before they arrive here.
                            // Returning an auth error (rather than panicking) ensures
                            // the archive is properly renamed .broken if this
                            // invariant is ever violated.
                            "device code authentication failed".to_string()
                        }
                    };
                    error!(
                        "{:FL$}Device code authentication failed for service {:?}: {}",
                        "DeviceCodeAuth", service, detail
                    );

                    // Clear the live banner with a failure message
                    banner.failure("Device code flow authentication failed");
                    return Err(Error::DeviceCodeFlowAuthentication(detail));
                }
            };
        };

        // Parse the token response. On success, clear the banner.
        let token = token_response.parse(tenant, service.clone(), client_id, scopes)?;
        // Record completed service for final banner
        banner.add_completed(&service);
        banner.success();
        Ok(token)
    }

    async fn request_device_code(
        client: &reqwest::Client,
        devicecode_endpoint: &str,
        client_id: &str,
        scope_str: &str,
        service: &str,
    ) -> Result<DeviceCodeResponse, Error> {
        let response = match client
            .post(devicecode_endpoint)
            .form(&[("client_id", client_id), ("scope", scope_str)])
            .send()
            .await
        {
            Ok(response) => response,
            Err(err) => {
                let detail = format!(
                    "device code creation transport error: {}",
                    transport_error_summary(&err)
                );
                error!(
                    "{:FL$}Device code creation failed for service {:?}: {}",
                    "DeviceCodeAuth", service, detail
                );
                return Err(Error::DeviceCodeFlowCreation(detail));
            }
        };

        let status = response.status();
        let bytes = match response.bytes().await {
            Ok(bytes) => bytes,
            Err(err) => {
                let detail = format!(
                    "HTTP {status}: device code creation response unreadable: {}",
                    transport_error_summary(&err)
                );
                error!(
                    "{:FL$}Device code creation failed for service {:?}: {}",
                    "DeviceCodeAuth", service, detail
                );
                return Err(Error::DeviceCodeFlowCreation(detail));
            }
        };

        if !status.is_success() {
            let summary = oauth_error_summary(status, &bytes, &[]);
            error!(
                "{:FL$}Device code creation rejected for service {:?}: {}",
                "DeviceCodeAuth", service, summary
            );
            return Err(Error::DeviceCodeFlowCreation(summary));
        }

        match serde_json::from_slice::<DeviceCodeResponse>(&bytes) {
            Ok(device_code) => Ok(device_code),
            Err(_) => {
                let detail = format!("HTTP {status}: invalid device code creation response");
                error!(
                    "{:FL$}Device code creation failed for service {:?}: {}",
                    "DeviceCodeAuth", service, detail
                );
                Err(Error::DeviceCodeFlowCreation(detail))
            }
        }
    }

    /// RFC 8628 §3.5 polling loop. Polls `token_endpoint` with `device_code` until
    /// either a token is returned or a terminal/expiry error occurs.
    async fn poll_for_token(
        client: &reqwest::Client,
        token_endpoint: &str,
        client_id: &str,
        device_code: &str,
        initial_interval_secs: u64,
    ) -> Result<InitialTokenResponse, DeviceCodePollError> {
        // A transient failure (a transport blip during the minutes-long user
        // sign-in, a 5xx, or `temporarily_unavailable`) must not abort the flow:
        // retry after the interval. Bound the *consecutive* count so a persistent
        // outage cannot spin forever; any normal poll response (authorization_pending
        // / slow_down) resets it. The device-code expiry remains the natural
        // overall bound when the server is reachable.
        const MAX_CONSECUTIVE_POLL_FAILURES: u32 = 10;
        let mut interval_secs = initial_interval_secs;
        let mut consecutive_failures: u32 = 0;
        loop {
            tokio::time::sleep(Duration::from_secs(interval_secs)).await;

            let resp = match client
                .post(token_endpoint)
                .form(&[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("device_code", device_code),
                    ("client_id", client_id),
                ])
                .send()
                .await
            {
                Ok(r) => r,
                Err(err) => {
                    consecutive_failures += 1;
                    if consecutive_failures > MAX_CONSECUTIVE_POLL_FAILURES {
                        return Err(DeviceCodePollError::Transport(err));
                    }
                    warn!(
                        "{:FL$}Device code poll transport error (attempt {}/{}), retrying: {:?}",
                        "DeviceCodeAuth", consecutive_failures, MAX_CONSECUTIVE_POLL_FAILURES, err
                    );
                    continue;
                }
            };

            let status = resp.status();
            let bytes = match resp.bytes().await {
                Ok(b) => b,
                Err(err) => {
                    consecutive_failures += 1;
                    if consecutive_failures > MAX_CONSECUTIVE_POLL_FAILURES {
                        return Err(DeviceCodePollError::Transport(err));
                    }
                    warn!(
                        "{:FL$}Device code poll read error (attempt {}/{}), retrying: {:?}",
                        "DeviceCodeAuth", consecutive_failures, MAX_CONSECUTIVE_POLL_FAILURES, err
                    );
                    continue;
                }
            };

            if status.is_success() {
                let body =
                    serde_json::from_slice::<TokenEndpointResponse>(&bytes).map_err(|_| {
                        DeviceCodePollError::Terminal(format!(
                            "HTTP {status}: invalid device code token response"
                        ))
                    })?;
                return Ok(InitialTokenResponse { token: body });
            }

            // A 5xx is a transient server-side error: retry like a transport blip.
            if status.is_server_error() {
                consecutive_failures += 1;
                if consecutive_failures > MAX_CONSECUTIVE_POLL_FAILURES {
                    return Err(DeviceCodePollError::Terminal(format!(
                        "device code token endpoint returned HTTP {status} repeatedly"
                    )));
                }
                warn!(
                    "{:FL$}Device code poll: server error HTTP {} (attempt {}/{}), retrying",
                    "DeviceCodeAuth", status, consecutive_failures, MAX_CONSECUTIVE_POLL_FAILURES
                );
                continue;
            }

            // Non-success: try to parse as a polling error response.
            match serde_json::from_slice::<PollingErrorResponse>(&bytes) {
                Ok(err_resp) => match err_resp.error.as_str() {
                    "authorization_pending" => {
                        consecutive_failures = 0;
                        trace!(
                            "{:FL$}Device code poll: authorization_pending",
                            "DeviceCodeAuth"
                        );
                        continue;
                    }
                    "slow_down" => {
                        consecutive_failures = 0;
                        // RFC 8628 §3.5: add 5 s on each slow_down. Cap the interval
                        // so a misbehaving server cannot push it arbitrarily high and
                        // delay expiry detection.
                        interval_secs = (interval_secs + 5).min(60);
                        trace!(
                            "{:FL$}Device code poll: slow_down, interval now {}s",
                            "DeviceCodeAuth", interval_secs
                        );
                        continue;
                    }
                    "temporarily_unavailable" => {
                        // RFC 8628 / OAuth: a transient server condition; retry.
                        consecutive_failures += 1;
                        if consecutive_failures > MAX_CONSECUTIVE_POLL_FAILURES {
                            return Err(DeviceCodePollError::Terminal(
                                "device code token endpoint temporarily_unavailable repeatedly"
                                    .to_string(),
                            ));
                        }
                        warn!(
                            "{:FL$}Device code poll: temporarily_unavailable (attempt {}/{}), retrying",
                            "DeviceCodeAuth", consecutive_failures, MAX_CONSECUTIVE_POLL_FAILURES
                        );
                        continue;
                    }
                    "expired_token" => return Err(DeviceCodePollError::ExpiredToken),
                    _ => {
                        return Err(DeviceCodePollError::Terminal(oauth_error_summary(
                            status,
                            &bytes,
                            &[device_code],
                        )));
                    }
                },
                Err(_) => {
                    // A 429 without a parseable OAuth error body (a throttle from a
                    // gateway in front of the token endpoint) is transient: retry at
                    // the poll interval instead of aborting the sign-in. A 429 whose
                    // body does parse (e.g. `slow_down`) is routed by its error code
                    // above and never reaches this arm.
                    if status.as_u16() == 429 {
                        consecutive_failures += 1;
                        if consecutive_failures > MAX_CONSECUTIVE_POLL_FAILURES {
                            return Err(DeviceCodePollError::Terminal(
                                "device code token endpoint throttled (HTTP 429) repeatedly"
                                    .to_string(),
                            ));
                        }
                        warn!(
                            "{:FL$}Device code poll: throttled HTTP 429 (attempt {}/{}), retrying",
                            "DeviceCodeAuth", consecutive_failures, MAX_CONSECUTIVE_POLL_FAILURES
                        );
                        continue;
                    }
                    return Err(DeviceCodePollError::Terminal(oauth_error_summary(
                        status,
                        &bytes,
                        &[device_code],
                    )));
                }
            }
        }
    }

    /// Returns `true` when device code polling failed because the device code expired.
    ///
    /// Such failures are recoverable by requesting a fresh device code, so they
    /// must not abort the collection. Other errors (`Terminal`, `Transport`) are
    /// non-recoverable.
    pub fn is_device_code_expired(err: &DeviceCodePollError) -> bool {
        matches!(err, DeviceCodePollError::ExpiredToken)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn request_device_code_with_response(
        response: ResponseTemplate,
    ) -> Result<DeviceCodeResponse, Error> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(response)
            .mount(&server)
            .await;

        DeviceCodeAuth::request_device_code(
            &reqwest::Client::new(),
            &format!("{}/devicecode", server.uri()),
            "client-id",
            "offline_access https://graph.microsoft.com/.default",
            "graph",
        )
        .await
    }

    fn creation_error(result: Result<DeviceCodeResponse, Error>) -> String {
        match result {
            Err(Error::DeviceCodeFlowCreation(message)) => message,
            Err(error) => panic!("unexpected device code creation error: {error:?}"),
            Ok(_) => panic!("expected device code creation failure"),
        }
    }

    #[tokio::test]
    async fn device_code_creation_preserves_oauth_description() {
        let message = creation_error(
            request_device_code_with_response(ResponseTemplate::new(400).set_body_json(
                serde_json::json!({
                    "error": "unauthorized_client",
                    "error_description": "synthetic refusal"
                }),
            ))
            .await,
        );

        assert_eq!(
            message,
            "HTTP 400 Bad Request: unauthorized_client: synthetic refusal"
        );
    }

    #[tokio::test]
    async fn device_code_creation_non_success_is_not_accepted_as_success() {
        let message = creation_error(
            request_device_code_with_response(ResponseTemplate::new(500).set_body_json(
                serde_json::json!({
                    "device_code": "DEVICE_SENTINEL",
                    "user_code": "USER_SENTINEL",
                    "verification_uri": "https://example.test"
                }),
            ))
            .await,
        );

        assert_eq!(
            message,
            "HTTP 500 Internal Server Error: invalid OAuth error response"
        );
        assert!(!message.contains("DEVICE_SENTINEL"));
        assert!(!message.contains("USER_SENTINEL"));
    }

    #[tokio::test]
    async fn device_code_creation_non_json_rejection_does_not_copy_body() {
        let message = creation_error(
            request_device_code_with_response(
                ResponseTemplate::new(502).set_body_string("<html>HTML_SENTINEL</html>"),
            )
            .await,
        );

        assert_eq!(
            message,
            "HTTP 502 Bad Gateway: invalid OAuth error response"
        );
        assert!(!message.contains("HTML_SENTINEL"));
    }

    #[tokio::test]
    async fn device_code_creation_malformed_success_response_is_safe() {
        for body in [
            serde_json::json!({
                "user_code": "ABCD-EFGH",
                "verification_uri": "https://microsoft.com/devicelogin"
            }),
            serde_json::json!({
                "device_code": "device-code",
                "user_code": "ABCD-EFGH",
                "verification_uri": "https://microsoft.com/devicelogin",
                "interval": "SECRET_SENTINEL"
            }),
        ] {
            let message = creation_error(
                request_device_code_with_response(ResponseTemplate::new(200).set_body_json(body))
                    .await,
            );

            assert_eq!(
                message,
                "HTTP 200 OK: invalid device code creation response"
            );
            assert!(!message.contains("SECRET_SENTINEL"));
        }
    }

    #[tokio::test]
    async fn device_code_creation_success_defaults_absent_interval() {
        let result = request_device_code_with_response(ResponseTemplate::new(200).set_body_json(
            serde_json::json!({
                "device_code": "device-code",
                "user_code": "ABCD-EFGH",
                "verification_uri": "https://microsoft.com/devicelogin"
            }),
        ))
        .await;

        let response = match result {
            Ok(response) => response,
            Err(error) => panic!("device code request must succeed: {error:?}"),
        };
        assert_eq!(response.interval, None);
    }

    #[tokio::test]
    async fn device_code_poll_terminal_preserves_description() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "access_denied",
                "error_description": "synthetic refusal"
            })))
            .mount(&server)
            .await;

        let result = DeviceCodeAuth::poll_for_token(
            &reqwest::Client::new(),
            &server.uri(),
            "client-id",
            "device-code-secret",
            0,
        )
        .await;

        match result {
            Err(DeviceCodePollError::Terminal(message)) => assert_eq!(
                message,
                "HTTP 400 Bad Request: access_denied: synthetic refusal"
            ),
            Err(_) => panic!("unexpected polling error category"),
            Ok(_) => panic!("expected terminal polling rejection"),
        }
    }

    #[tokio::test]
    async fn device_code_poll_malformed_success_is_safe() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": {"secret": "SECRET_SENTINEL"}
            })))
            .mount(&server)
            .await;

        let result = DeviceCodeAuth::poll_for_token(
            &reqwest::Client::new(),
            &server.uri(),
            "client-id",
            "device-code-secret",
            0,
        )
        .await;

        match result {
            Err(DeviceCodePollError::Terminal(message)) => {
                assert_eq!(message, "HTTP 200 OK: invalid device code token response");
                assert!(!message.contains("SECRET_SENTINEL"));
            }
            Err(_) => panic!("unexpected polling error category"),
            Ok(_) => panic!("expected malformed token response failure"),
        }
    }

    #[tokio::test]
    async fn device_code_poll_expired_token_keeps_recoverable_category() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(serde_json::json!({"error": "expired_token"})),
            )
            .mount(&server)
            .await;

        let result = DeviceCodeAuth::poll_for_token(
            &reqwest::Client::new(),
            &server.uri(),
            "client-id",
            "device-code-secret",
            0,
        )
        .await;

        assert!(matches!(result, Err(DeviceCodePollError::ExpiredToken)));
    }

    #[tokio::test(start_paused = true)]
    async fn device_code_poll_slow_down_then_success_stays_recoverable() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(400).set_body_json(serde_json::json!({"error": "slow_down"})),
            )
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"access_token": "the-token"})),
            )
            .with_priority(2)
            .mount(&server)
            .await;

        let result = DeviceCodeAuth::poll_for_token(
            &reqwest::Client::new(),
            &server.uri(),
            "client-id",
            "device-code-secret",
            0,
        )
        .await;

        let response = match result {
            Ok(response) => response,
            Err(_) => panic!("poll must succeed after slow_down"),
        };
        assert_eq!(response.token.access_token, "the-token");
    }

    #[tokio::test]
    async fn request_device_code_sends_current_two_field_form() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "device_code": "device-code",
                "user_code": "ABCD-EFGH",
                "verification_uri": "https://microsoft.com/devicelogin",
                "interval": 7
            })))
            .mount(&server)
            .await;

        let response = DeviceCodeAuth::request_device_code(
            &reqwest::Client::new(),
            &format!("{}/devicecode", server.uri()),
            "client+id&with=reserved%characters",
            "offline_access https://graph.microsoft.com/.default",
            "graph",
        )
        .await;

        let response = match response {
            Ok(response) => response,
            Err(err) => panic!("device code request must succeed: {err:?}"),
        };
        assert_eq!(response.device_code, "device-code");
        assert_eq!(response.user_code, "ABCD-EFGH");
        assert_eq!(
            response.verification_uri,
            "https://microsoft.com/devicelogin"
        );
        assert_eq!(response.interval, Some(7));

        let requests = server.received_requests().await.expect("recorded requests");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method.as_str(), "POST");
        let pairs: Vec<(String, String)> = url::form_urlencoded::parse(&requests[0].body)
            .into_owned()
            .collect();
        assert_eq!(pairs.len(), 2, "no additional or duplicate form field");
        let form: BTreeMap<String, String> = pairs.into_iter().collect();
        let expected = BTreeMap::from([
            (
                "client_id".to_string(),
                "client+id&with=reserved%characters".to_string(),
            ),
            (
                "scope".to_string(),
                "offline_access https://graph.microsoft.com/.default".to_string(),
            ),
        ]);
        assert_eq!(form, expected);
    }

    /// A transient 5xx, then `authorization_pending`, then success: the poll loop
    /// must ride through the transient failure instead of aborting on it.
    #[tokio::test]
    async fn poll_rides_through_transient_5xx_then_pending() {
        let server = MockServer::start().await;
        // First poll → 503 (transient server error).
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        // Second poll → authorization_pending.
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(serde_json::json!({ "error": "authorization_pending" })),
            )
            .up_to_n_times(1)
            .with_priority(2)
            .mount(&server)
            .await;
        // Third poll → success.
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "access_token": "the-token" })),
            )
            .with_priority(3)
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let result = DeviceCodeAuth::poll_for_token(
            &client,
            &server.uri(),
            "client-id",
            "device-code",
            0, // no inter-poll delay in the test
        )
        .await;

        let resp = match result {
            Ok(r) => r,
            Err(_) => panic!("poll must succeed after a transient 5xx and pending"),
        };
        assert_eq!(resp.token.access_token, "the-token");
    }
}
