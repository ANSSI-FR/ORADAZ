/// Module to handle OAuth2 token responses.
use crate::FL;
use crate::collect::auth::tokens::entity::Token;
use crate::collect::prerequisites::jwt_claims::decode_jwt_segment;
use crate::utils::errors::Error;

use chrono::Utc;
use log::{debug, error, trace};
use serde::Deserialize;

/// Raw token endpoint JSON response, shared across all auth flows.
#[derive(Deserialize)]
pub struct TokenEndpointResponse {
    pub access_token: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub token_type: Option<String>,
}

#[derive(Deserialize)]
struct OAuthErrorResponse {
    error: String,
    error_description: Option<String>,
}

/// Reports fixed HTTP failure categories without exposing request URLs or error sources.
pub(crate) fn transport_error_summary(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "request timed out"
    } else if error.is_connect() {
        "connection failed (DNS, TCP, TLS or proxy)"
    } else if error.is_body() || error.is_decode() {
        "body transfer failed"
    } else {
        "request failed"
    }
}

/// Formats selected OAuth fields without copying an unknown response body.
pub(crate) fn oauth_error_summary(
    status: reqwest::StatusCode,
    body: &[u8],
    secrets: &[&str],
) -> String {
    let parsed = serde_json::from_slice::<OAuthErrorResponse>(body);
    let mut detail = match parsed {
        Ok(error) if !error.error.trim().is_empty() => {
            match error
                .error_description
                .filter(|value| !value.trim().is_empty())
            {
                Some(description) => format!("{}: {}", error.error, description),
                None => error.error,
            }
        }
        _ => return format!("HTTP {status}: invalid OAuth error response"),
    };
    // Mask known request secrets before normalization or truncation.
    for secret in secrets.iter().copied().filter(|value| !value.is_empty()) {
        detail = detail.replace(secret, "[REDACTED]");
    }
    let normalized: String = detail
        .chars()
        .map(|ch| {
            if ch.is_control() || ch.is_whitespace() {
                ' '
            } else {
                ch
            }
        })
        .collect();
    let one_line = normalized.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut chars = one_line.chars();
    let mut bounded: String = chars.by_ref().take(2048).collect();
    if chars.next().is_some() {
        bounded.push('…');
    }
    format!("HTTP {status}: {bounded}")
}

impl std::fmt::Debug for TokenEndpointResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenEndpointResponse")
            .field("access_token", &"***REDACTED***")
            .field("expires_in", &self.expires_in)
            .field(
                "refresh_token",
                &if self.refresh_token.is_some() {
                    Some("***REDACTED***")
                } else {
                    None
                },
            )
            .field("token_type", &self.token_type)
            .finish()
    }
}

/// Internal representation of the claims found in the access token's JWT payload.
#[derive(Clone, Deserialize)]
struct PartialAccessToken {
    /// The Object Identifier (OID) of the user or service principal.
    pub oid: String,
    /// The User Principal Name (`upn` claim, present on v1.0 access tokens for
    /// delegated users). This is the real UPN.
    #[serde(default)]
    pub upn: Option<String>,
    /// The preferred username (`preferred_username` claim, present on v2.0
    /// access tokens for delegated users); typically equals the UPN.
    #[serde(default)]
    pub preferred_username: Option<String>,
    /// The display name (`name` claim). NOT the UPN — used only as a last
    /// resort and absent in app-only tokens.
    #[serde(default)]
    pub name: String,
}

impl PartialAccessToken {
    /// Resolves the user principal name from the available identity claims,
    /// preferring the real UPN (`upn` / `preferred_username`) and falling back
    /// to the display `name`. Empty for app-only tokens that carry none.
    fn user_principal_name(&self) -> String {
        self.upn
            .clone()
            .filter(|s| !s.is_empty())
            .or_else(|| self.preferred_username.clone().filter(|s| !s.is_empty()))
            .unwrap_or_else(|| self.name.clone())
    }
}

/// A wrapper around a raw token endpoint response, used by every auth flow.
pub struct InitialTokenResponse {
    pub token: TokenEndpointResponse,
}

impl std::fmt::Debug for InitialTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitialTokenResponse")
            .field("token", &self.token)
            .finish()
    }
}

impl InitialTokenResponse {
    /// Parses the OAuth2 token response into a `Token` entity.
    ///
    /// This method calculates the expiration timestamp and decodes the base64-encoded
    /// JWT payload of the access token to extract the user's identity information (OID and name).
    pub fn parse(
        self,
        tenant: String,
        service: String,
        client_id: String,
        scopes: Vec<String>,
    ) -> Result<Token, Error> {
        trace!(
            "{:FL$}Parsing token response for service {:?}",
            "InitialTokenResponse", service
        );
        let expires_on: i64 = match self.token.expires_in {
            Some(secs) => Utc::now().timestamp() + secs as i64,
            None => {
                debug!(
                    "{:FL$}expires_in absent from token response for service {:?}, defaulting to 3600s",
                    "InitialTokenResponse", service
                );
                Utc::now().timestamp() + (60 * 60) as i64
            }
        };
        let access_token: String = self.token.access_token.clone();
        let payload_part = match access_token.split('.').nth(1) {
            Some(p) => p.to_string(),
            None => {
                error!(
                    "{:FL$}Access token for service {:?} is not a valid JWT (missing payload)",
                    "TokenResponse", service
                );
                return Err(Error::AccessTokenParsing);
            }
        };
        let refresh_token: Option<String> = self.token.refresh_token.clone();
        let token_type: String = self
            .token
            .token_type
            .clone()
            .unwrap_or_else(|| String::from("Bearer"));
        match decode_jwt_segment(&payload_part) {
            Ok(bytes) => {
                let token_str = String::from_utf8_lossy(&bytes);
                match serde_json::from_str::<PartialAccessToken>(&token_str) {
                    Ok(j) => {
                        let user_principal_name = j.user_principal_name();
                        debug!(
                            "{:FL$}Token parsed for service {:?}: oid={:?}, upn={:?}, expires_in={}s",
                            "InitialTokenResponse",
                            service,
                            j.oid,
                            user_principal_name,
                            self.token.expires_in.unwrap_or(3600)
                        );
                        Ok(Token {
                            tenant_id: tenant,
                            client_id,
                            service,
                            access_token,
                            refresh_token,
                            token_type,
                            expires_on,
                            user_id: j.oid,
                            user_principal_name,
                            scopes,
                        })
                    }
                    Err(err) => {
                        error!(
                            "{:FL$}Error while parsing new access token for service {:?}",
                            "TokenResponse", service
                        );
                        debug!(
                            "{:FL$}Access token JSON parse error for service {:?}: {:?}",
                            "TokenResponse", service, err
                        );

                        Err(Error::AccessTokenParsing)
                    }
                }
            }
            Err(err) => {
                error!(
                    "{:FL$}Error while decoding new access token for service {:?}",
                    "TokenResponse", service
                );
                debug!(
                    "{:FL$}Access token base64 decode error for service {:?}: {:?}",
                    "TokenResponse", service, err
                );

                Err(Error::AccessTokenParsing)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::oauth_error_summary;
    use reqwest::StatusCode;

    #[test]
    fn oauth_summary_keeps_status_code_and_description() {
        let summary = oauth_error_summary(
            StatusCode::BAD_REQUEST,
            br#"{"error":"invalid_grant","error_description":"synthetic refusal"}"#,
            &[],
        );

        assert_eq!(
            summary,
            "HTTP 400 Bad Request: invalid_grant: synthetic refusal"
        );
    }

    #[test]
    fn oauth_summary_accepts_absent_or_null_description() {
        for body in [
            br#"{"error":"invalid_grant"}"#.as_slice(),
            br#"{"error":"invalid_grant","error_description":null}"#.as_slice(),
            br#"{"error":"invalid_grant","error_description":""}"#.as_slice(),
            br#"{"error":"invalid_grant","error_description":" \t\r\n"}"#.as_slice(),
        ] {
            assert_eq!(
                oauth_error_summary(StatusCode::BAD_REQUEST, body, &[]),
                "HTTP 400 Bad Request: invalid_grant"
            );
        }
    }

    #[test]
    fn oauth_summary_does_not_copy_unknown_body() {
        for (body, sentinel) in [
            (b"<html>HTML_SENTINEL</html>".as_slice(), "HTML_SENTINEL"),
            (b"TEXT_SENTINEL".as_slice(), "TEXT_SENTINEL"),
            (
                br#"{"access_token":"MISSING_ERROR_SENTINEL","unexpected":true}"#.as_slice(),
                "MISSING_ERROR_SENTINEL",
            ),
            (
                br#"{"error":{"secret":"INVALID_TYPE_SENTINEL"}}"#.as_slice(),
                "INVALID_TYPE_SENTINEL",
            ),
        ] {
            let summary = oauth_error_summary(StatusCode::BAD_GATEWAY, body, &[]);

            assert_eq!(
                summary,
                "HTTP 502 Bad Gateway: invalid OAuth error response"
            );
            assert!(!summary.contains(sentinel));
        }
    }

    #[test]
    fn oauth_summary_ignores_extra_token_fields() {
        let summary = oauth_error_summary(
            StatusCode::UNAUTHORIZED,
            br#"{"error":"invalid_client","error_description":"synthetic refusal","access_token":"ACCESS_SENTINEL","refresh_token":"REFRESH_SENTINEL"}"#,
            &[],
        );

        assert_eq!(
            summary,
            "HTTP 401 Unauthorized: invalid_client: synthetic refusal"
        );
        assert!(!summary.contains("ACCESS_SENTINEL"));
        assert!(!summary.contains("REFRESH_SENTINEL"));
    }

    #[test]
    fn oauth_summary_is_bounded_single_line() {
        let description = format!("first\r\n\t\u{1b}second {}", "é".repeat(2_100));
        let body = serde_json::json!({
            "error": "invalid_request",
            "error_description": description,
        })
        .to_string();

        let summary = oauth_error_summary(StatusCode::BAD_REQUEST, body.as_bytes(), &[]);
        let detail = summary
            .strip_prefix("HTTP 400 Bad Request: ")
            .expect("summary must retain the HTTP status");

        assert!(detail.starts_with("invalid_request: first second "));
        assert!(detail.chars().all(|ch| !ch.is_control()));
        assert_eq!(detail.chars().count(), 2_049);
        assert!(detail.ends_with('…'));
    }

    #[test]
    fn oauth_summary_masks_known_request_secrets() {
        let refresh_token = "REFRESH\nSECRET";
        let device_code = "DEVICE-CODE-SECRET";
        let body = serde_json::json!({
            "error": "invalid_grant",
            "error_description": format!(
                "refresh={refresh_token}; device={device_code}"
            ),
        })
        .to_string();

        let summary = oauth_error_summary(
            StatusCode::BAD_REQUEST,
            body.as_bytes(),
            &[refresh_token, device_code],
        );

        assert_eq!(
            summary,
            "HTTP 400 Bad Request: invalid_grant: refresh=[REDACTED]; device=[REDACTED]"
        );
        assert!(!summary.contains(refresh_token));
        assert!(!summary.contains(device_code));
    }
}
