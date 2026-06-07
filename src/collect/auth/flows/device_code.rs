/// Module to manage Device Code Flow authentication features.
use crate::FL;
use crate::collect::auth::tokens::Token;
use crate::collect::auth::tokens::response::{InitialTokenResponse, TokenEndpointResponse};
use crate::utils::client::OradazClient;
use crate::utils::errors::Error;
use crate::utils::ui::auth_banner::AuthBanner;

use log::{debug, error, trace};
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
            trace!("{:FL$}Getting code for device code flow", "DeviceCodeAuth");
            let dc_resp: DeviceCodeResponse = match oradaz_client
                .client
                .post(&devicecode_endpoint)
                .form(&[("client_id", client_id.as_str()), ("scope", &scope_str)])
                .send()
                .await
            {
                Ok(resp) => match resp.json::<DeviceCodeResponse>().await {
                    Ok(d) => d,
                    Err(err) => {
                        error!(
                            "{:FL$}Error requesting device code for scopes '{}' for service {:?}",
                            "DeviceCodeAuth",
                            scopes.join(" "),
                            &service
                        );
                        debug!(
                            "{:FL$}Device authorization response parse error for service {:?}: {:?}",
                            "DeviceCodeAuth", service, err
                        );
                        if banner_started {
                            banner.failure("Device code flow authentication failed");
                        }
                        return Err(Error::DeviceCodeFlowAuthentication);
                    }
                },
                Err(err) => {
                    error!(
                        "{:FL$}Error requesting device code for scopes '{}' for service {:?}",
                        "DeviceCodeAuth",
                        scopes.join(" "),
                        &service
                    );
                    debug!(
                        "{:FL$}Device authorization request error for service {:?}: {:?}",
                        "DeviceCodeAuth", service, err
                    );

                    if banner_started {
                        banner.failure("Device code flow authentication failed");
                    }
                    return Err(Error::DeviceCodeFlowAuthentication);
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
            trace!("{:FL$}Exchanging code for token", "DeviceCodeAuth");
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
                    error!(
                        "{:FL$}Error while refreshing token for scopes '{}' for service {:?}",
                        "DeviceCodeAuth",
                        scopes.join(" "),
                        &service
                    );
                    match &err {
                        DeviceCodePollError::Terminal(msg) => {
                            debug!(
                                "{:FL$}Device token exchange error for service {:?}: {:?}",
                                "DeviceCodeAuth", service, msg
                            );
                        }
                        DeviceCodePollError::Transport(e) => {
                            debug!(
                                "{:FL$}Device token exchange error for service {:?}: {:?}",
                                "DeviceCodeAuth", service, e
                            );
                        }
                        DeviceCodePollError::ExpiredToken => {
                            // Should never be reached: the outer arm
                            // `Err(err) if Self::is_device_code_expired(&err)`
                            // catches all ExpiredToken errors before they arrive here.
                            // Returning an auth error (rather than panicking) ensures
                            // the archive is properly renamed .broken if this
                            // invariant is ever violated.
                            return Err(Error::DeviceCodeFlowAuthentication);
                        }
                    }

                    // Clear the live banner with a failure message
                    banner.failure("Device code flow authentication failed");
                    return Err(Error::DeviceCodeFlowAuthentication);
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

    /// RFC 8628 §3.5 polling loop. Polls `token_endpoint` with `device_code` until
    /// either a token is returned or a terminal/expiry error occurs.
    async fn poll_for_token(
        client: &reqwest::Client,
        token_endpoint: &str,
        client_id: &str,
        device_code: &str,
        initial_interval_secs: u64,
    ) -> Result<InitialTokenResponse, DeviceCodePollError> {
        let mut interval_secs = initial_interval_secs;
        loop {
            tokio::time::sleep(Duration::from_secs(interval_secs)).await;

            let resp = client
                .post(token_endpoint)
                .form(&[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("device_code", device_code),
                    ("client_id", client_id),
                ])
                .send()
                .await
                .map_err(DeviceCodePollError::Transport)?;

            let status = resp.status();
            let bytes = resp.bytes().await.map_err(DeviceCodePollError::Transport)?;

            if status.is_success() {
                let body = serde_json::from_slice::<TokenEndpointResponse>(&bytes)
                    .map_err(|e| DeviceCodePollError::Terminal(e.to_string()))?;
                return Ok(InitialTokenResponse { token: body });
            }

            // Non-success: try to parse as a polling error response.
            match serde_json::from_slice::<PollingErrorResponse>(&bytes) {
                Ok(err_resp) => match err_resp.error.as_str() {
                    "authorization_pending" => {
                        trace!(
                            "{:FL$}Device code poll: authorization_pending",
                            "DeviceCodeAuth"
                        );
                        continue;
                    }
                    "slow_down" => {
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
                    "expired_token" => return Err(DeviceCodePollError::ExpiredToken),
                    other => {
                        return Err(DeviceCodePollError::Terminal(other.to_string()));
                    }
                },
                Err(_) => {
                    debug!(
                        "{:FL$}Device code poll: unparseable error body (HTTP {}): {:?}",
                        "DeviceCodeAuth",
                        status,
                        String::from_utf8_lossy(&bytes)
                    );
                    return Err(DeviceCodePollError::Terminal(format!("HTTP {status}")));
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
