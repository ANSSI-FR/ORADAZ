/// Module containing the Token entity and its logic.
use crate::FL;
use crate::collect::auth::tokens::response::{
    InitialTokenResponse, TokenEndpointResponse, oauth_error_summary, transport_error_summary,
};
use crate::collect::auth::{Auth, AuthError};
use crate::collect::prerequisites::Prerequisites;
use crate::utils::client::OradazClient;
use crate::utils::config::Config;
use crate::utils::errors::Error;
use crate::utils::ui::{self, dump_event};

use log::{self, debug, error, info, trace, warn};
use std::io::{self, IsTerminal};
use std::time::Duration;

/// Time window (in seconds) before token expiration when a refresh should be triggered.
pub const REFRESH_TOKEN_EXPIRATION_THRESHOLD: i64 = 600;

/// Waits for the operator to press Enter after fixing a prerequisite, but
/// distinguishes a genuine keypress from end-of-input. When stdin is not
/// interactive (EOF — e.g. piped/non-interactive run), `read_line` returns
/// `Ok(0)` immediately; we log that no interactive resume is possible instead
/// of silently swallowing the EOF and pretending the user acted.
async fn wait_for_enter_or_eof(service: &str) {
    match tokio::task::spawn_blocking(|| {
        let mut buf = String::new();
        io::stdin().read_line(&mut buf).map(|n| (n, buf))
    })
    .await
    {
        Ok(Ok((0, _))) => {
            warn!(
                "{:FL$}No interactive input available (EOF) while waiting to resume service {:?}; cannot wait for a permission fix",
                "Token", service
            );
        }
        Ok(Ok(_)) => {}
        Ok(Err(err)) => {
            warn!(
                "{:FL$}Could not read stdin while waiting to resume service {:?}: {}",
                "Token", service, err
            );
        }
        Err(err) => {
            warn!(
                "{:FL$}Input task failed while waiting to resume service {:?}: {}",
                "Token", service, err
            );
        }
    }
}

/// Maximum attempts for the *defensive* post-(re)acquisition prerequisite
/// re-check before proceeding with the freshly-obtained token regardless.
///
/// The token itself refreshed successfully; this re-check only confirms the app
/// still holds its permissions. It must never abort or stall a long-running
/// collection on a transient failure (HTTP 429 / 5xx / timeout / network):
/// after a few quick attempts we proceed with the new token, and a genuine
/// permission loss resurfaces through the normal per-URL
/// `PotentialPrerequisiteError` path (itself bounded and throttle-aware). Only a
/// definitive `MissingAppPermission` verdict is treated as fatal.
const MAX_REFRESH_PREREQ_ATTEMPTS: u32 = 5;

/// Classification of a post-refresh prerequisite re-check result, used by
/// [`recheck_prerequisites_after_refresh`]. Extracted as a pure function so the
/// fatal-vs-transient decision (the crux of the non-aborting behaviour) is unit
/// testable without an HTTP round-trip.
#[derive(Debug, PartialEq, Eq)]
enum RefreshPrereqDecision {
    /// Permissions confirmed — proceed with the new token.
    Proceed,
    /// Definitive missing-permission verdict — surface to the caller (abort under
    /// application credentials, prompt under interactive).
    Surface,
    /// Transient failure (429 / 5xx / timeout / network / role lookup) — retry,
    /// then proceed with the new token once the attempt budget is exhausted.
    Retry,
}

/// Maps a prerequisite re-check result to a [`RefreshPrereqDecision`]. Only the
/// definitive, HTTP-free `MissingAppPermission` verdict is fatal; every other
/// error is treated as transient, so a briefly-unavailable service never aborts a
/// long collection on a defensive re-check.
fn classify_refresh_prereq_result(result: &Result<(), Error>) -> RefreshPrereqDecision {
    match result {
        Ok(()) => RefreshPrereqDecision::Proceed,
        Err(Error::MissingAppPermission) => RefreshPrereqDecision::Surface,
        Err(_) => RefreshPrereqDecision::Retry,
    }
}

/// Re-verifies prerequisites after a successful token (re-)acquisition.
///
/// Returns `Ok(())` to proceed with the new token. Transient failures (HTTP 429,
/// 5xx, timeout, network, role lookup) are retried up to
/// [`MAX_REFRESH_PREREQ_ATTEMPTS`] with a short backoff and then **tolerated**
/// (the collection continues) — this re-check never aborts or loops forever, so a
/// service that is briefly unavailable mid-collection cannot strand the run
/// (it would otherwise hang on a persistent 429, or abort to `.broken` on a
/// transient 5xx under application credentials). Only `Error::MissingAppPermission`
/// (a definitive, HTTP-free verdict from the token's roles/scopes claim) is
/// propagated, so the caller can abort (application credentials) or prompt the
/// operator (interactive).
async fn recheck_prerequisites_after_refresh(
    service: &str,
    token: &Token,
    config: &Config,
    oradaz_client: &OradazClient,
) -> Result<(), Error> {
    let mut attempts: u32 = 0;
    loop {
        debug!(
            "{:FL$}Re-checking prerequisites after token (re)acquisition for service {:?}",
            "Token", service
        );
        let result = Prerequisites::check(
            &oradaz_client.client,
            token,
            false,
            Config::use_application_credentials_auth(config),
            Config::use_managed_identity_auth(config),
            config.default_retry_after_seconds.unwrap_or(2),
        )
        .await;
        match classify_refresh_prereq_result(&result) {
            RefreshPrereqDecision::Proceed => {
                debug!(
                    "{:FL$}Prerequisites re-verified after token (re)acquisition for service {:?}",
                    "Token", service
                );
                return Ok(());
            }
            // Definitive permission verdict (token roles/scopes claim, no HTTP
            // call): surface it so the caller can abort or prompt the operator.
            RefreshPrereqDecision::Surface => return Err(Error::MissingAppPermission),
            // Any other failure (429 / 5xx / timeout / network / role lookup) is
            // transient: retry a few times, then proceed with the new token.
            RefreshPrereqDecision::Retry => {
                attempts = attempts.saturating_add(1);
                if attempts >= MAX_REFRESH_PREREQ_ATTEMPTS {
                    warn!(
                        "{:FL$}Prerequisite re-check for service {:?} kept failing after token (re)acquisition ({} attempts, last: {:?}); proceeding with the refreshed token — a genuine permission loss will resurface via API calls",
                        "Token", service, attempts, result
                    );
                    return Ok(());
                }
                // Short bounded backoff (2,4,8,16s). We deliberately do NOT honour
                // a long 429 `Retry-After` here: the check is skippable, so a quick
                // retry then proceed is preferable to stalling the whole service.
                let wait = 1u64 << attempts.min(4);
                warn!(
                    "{:FL$}Prerequisite re-check for service {:?} failed after token (re)acquisition (attempt {}, {:?}); retrying in {}s — collection continues",
                    "Token", service, attempts, result, wait
                );
                tokio::time::sleep(Duration::from_secs(wait)).await;
            }
        }
    }
}

/// Handles a definitive missing-permission verdict from the post-refresh
/// prerequisite re-check. Under application/managed-identity credentials there is
/// no operator to fix it, so it **fails fast**: returns `Err(Reprocess(Some))`,
/// which `compute_token_refresh` routes straight to `TokenRefreshFailed` (rather
/// than the transient `Reprocess(None)` path that is retried for the app-cred
/// budget). Under interactive auth it prompts the operator to fix the permission,
/// then returns `Err(Reprocess(None))` so the refresh is retried after the fix.
async fn handle_missing_permission_after_refresh(
    service: &str,
    config: &Config,
) -> Result<(), Error> {
    // Fail fast when there is no operator to fix the permission: application
    // credentials (no interaction by design) OR a non-TTY stdin (piped/redirected,
    // e.g. a container or CI run). `Reprocess(Some)` routes straight to
    // `TokenRefreshFailed` in `compute_token_refresh`, unlike the transient
    // `Reprocess(None)` path which is retried without limit — prompting a closed
    // stdin would read EOF instantly and loop forever.
    if Config::use_application_credentials_auth(config) || !io::stdin().is_terminal() {
        error!(
            "{:FL$}Prerequisite check failed for service {:?} after token (re)acquisition and cannot prompt (application credentials or non-interactive stdin) — aborting collection",
            "Token", service
        );
        return Err(Error::Reprocess(Some(AuthError {
            api: service.to_string(),
            error: "Missing required permission (no interactive operator to fix it)".to_string(),
        })));
    }
    error!(
        "{}{}{}",
        ui::err_text("Please fix the above error in prerequisite check for service '"),
        ui::err_text(service),
        ui::err_text("' and press Enter to continue dump")
    );
    wait_for_enter_or_eof(service).await;
    Err(Error::Reprocess(None))
}

/// Represents an OAuth2 authentication token and its associated context.
#[derive(Clone)]
pub struct Token {
    pub tenant_id: String,
    pub client_id: String,
    pub service: String,
    pub expires_on: i64,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub user_id: String,
    pub user_principal_name: String,
    pub scopes: Vec<String>,
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Token")
            .field("tenant_id", &self.tenant_id)
            .field("client_id", &self.client_id)
            .field("service", &self.service)
            .field("expires_on", &self.expires_on)
            .field("access_token", &"***REDACTED***")
            .field(
                "refresh_token",
                &if self.refresh_token.is_some() {
                    Some("***REDACTED***")
                } else {
                    None
                },
            )
            .field("token_type", &self.token_type)
            .field("user_id", &self.user_id)
            .field("user_principal_name", &self.user_principal_name)
            .field("scopes", &self.scopes)
            .finish()
    }
}

impl Token {
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now().timestamp() >= self.expires_on
    }

    pub fn will_expire(&self) -> bool {
        chrono::Utc::now().timestamp() + REFRESH_TOKEN_EXPIRATION_THRESHOLD >= self.expires_on
    }

    /// Replace this token with a freshly-acquired one, preserving the existing
    /// refresh token when the new response did not carry one. Azure rotates the
    /// refresh token on most refresh responses but is not contractually required
    /// to return one every time; dropping it would force a full interactive
    /// re-authentication on the next expiry.
    fn adopt(&mut self, mut new: Token) {
        if new.refresh_token.is_none() {
            new.refresh_token = self.refresh_token.take();
        }
        *self = new;
    }

    /// Refreshes the token if it is expired or near expiration, ensuring it remains valid for use.
    ///
    /// If a refresh token is available, it attempts to use it. Otherwise, it performs
    /// a full renewal (re-authentication). It also verifies that the new token
    /// passes prerequisite checks.
    pub async fn refresh(
        &mut self,
        config: &Config,
        oradaz_client: &OradazClient,
    ) -> Result<(), Error> {
        debug!(
            "{:FL$}Refreshing token for service {:?}",
            "Token", self.service
        );
        match &self.refresh_token {
            None => {
                // Client-credential flows never return a refresh token, so
                // re-acquiring is the normal hourly renewal there (debug). For an
                // interactive flow a missing refresh token is unusual and triggers
                // a re-authentication prompt (warn).
                if Config::use_application_credentials_auth(config) {
                    debug!(
                        "{:FL$}No refresh token for service {:?} (application credentials), re-acquiring",
                        "Token", self.service
                    );
                } else {
                    warn!(
                        "{:FL$}No refresh token for service {:?}, performing new authentication",
                        "Token", self.service
                    );
                }
                self.renew(config, oradaz_client).await
            }
            Some(_) => match self
                .refresh_for_scope(
                    config,
                    oradaz_client,
                    self.tenant_id.clone(),
                    self.service.clone(),
                    self.client_id.clone(),
                    self.scopes.clone(),
                )
                .await
            {
                Err(e) => {
                    debug!(
                        "{:FL$}Token refresh failed for service {:?} ({:?}), falling back to full re-authentication",
                        "Token", self.service, e
                    );
                    self.renew(config, oradaz_client).await
                }
                Ok(token) => {
                    if config.no_check.unwrap_or(false) {
                        self.adopt(token);
                        Ok(())
                    } else {
                        match recheck_prerequisites_after_refresh(
                            &self.service,
                            &token,
                            config,
                            oradaz_client,
                        )
                        .await
                        {
                            Ok(()) => {
                                debug!("{:FL$}Successfully refreshed token", "Token");
                                self.adopt(token);
                                Ok(())
                            }
                            Err(_) => {
                                handle_missing_permission_after_refresh(&self.service, config).await
                            }
                        }
                    }
                }
            },
        }
    }

    /// Uses the current refresh token to acquire a new token for the specified scopes.
    pub async fn refresh_for_scope(
        &self,
        _config: &Config,
        oradaz_client: &OradazClient,
        tenant: String,
        service: String,
        client_id: String,
        scopes: Vec<String>,
    ) -> Result<Token, Error> {
        debug!(
            "{:FL$}Acquiring new token for scopes '{}' based on refresh token",
            "Token",
            scopes.join(" ")
        );
        let refresh_token = match self.refresh_token.clone() {
            Some(refresh_token) => refresh_token,
            None => {
                warn!(
                    "{:FL$}Missing refresh token for service {:?}, performing new authentication",
                    "Token", &service
                );
                return Err(Error::RefreshTokenNewScope(
                    "no refresh token available for this token".to_string(),
                ));
            }
        };

        let token_url = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token");
        let scope_str = scopes.join(" ");

        trace!(
            "{:FL$}Exchanging token for service {} using refresh token ",
            "Token", &service
        );
        let token_response = exchange_refresh_token(
            &oradaz_client.client,
            &token_url,
            &refresh_token,
            &client_id,
            &scope_str,
            &service,
        )
        .await?;
        token_response.parse(tenant, service, client_id, scopes)
    }

    /// Performs a full re-authentication flow to acquire a new valid token.
    ///
    /// This is used when no refresh token is available or when a refresh attempt fails.
    /// It ensures that the user authenticating is the same as the original user.
    pub async fn renew(
        &mut self,
        config: &Config,
        oradaz_client: &OradazClient,
    ) -> Result<(), Error> {
        info!(
            "{:FL$}The token for service {:?} is expired and no refresh token is available. A new authentication is required.",
            "Token", self.service
        );
        let renew_message = if Config::use_application_credentials_auth(config) {
            "Token expired — re-acquiring with application credentials"
        } else {
            "Token expired — a new interactive authentication is required for this service"
        };
        dump_event::emit(dump_event::DumpEvent {
            level: log::Level::Warn,
            module_label: String::from("Token"),
            service: self.service.clone(),
            api: String::from("re-authentication"),
            http_status: None,
            upstream_code: None,
            url: None,
            call_id: None,
            message: String::from(renew_message),
        });
        match Auth::acquire_new_token(
            config,
            oradaz_client,
            self.tenant_id.to_string(),
            self.service.clone(),
            self.client_id.to_string(),
            self.scopes.clone(),
        )
        .await
        {
            Err(Error::AuthorizationCodeFlowCreation)
            | Err(Error::AuthorizationCodeFlowAuthentication)
            | Err(Error::DeviceCodeFlowCreation(_))
            | Err(Error::DeviceCodeFlowAuthentication(_))
            | Err(Error::DeviceCodeFlowUnexpectedEnd)
            | Err(Error::ClientCredentialsFlowCreation(_))
            | Err(Error::ClientCredentialsFlowAuthentication(_)) => {
                error!("{:FL$}Error while reauthenticating, retrying", "Token");
                Err(Error::Reprocess(None))
            }
            Err(err) => {
                debug!(
                    "{:FL$}An error occured while renewing token for service {:?}, will reprocess: {:?}",
                    "Token", self.service, err
                );
                Err(Error::Reprocess(Some(AuthError {
                    api: self.service.clone(),
                    error: err.to_string(),
                })))
            }
            Ok(token) => {
                // The new token is parsed from a fresh sign-in; its user identity
                // is read from the JWT, so a mismatch means re-authentication
                // landed on a different account (the tenant/client are inputs, not
                // re-derived, so comparing them would always pass).
                if token.user_id != self.user_id
                    || token.user_principal_name != self.user_principal_name
                {
                    error!(
                        "{:FL$}Token identity mismatch after re-authentication for service {:?}: expected user={}",
                        "Token", self.service, self.user_id
                    );
                    Err(Error::Reprocess(None))
                } else if let Some(true) = config.no_check {
                    debug!(
                        "{:FL$}Successfully renewed token for service {:?}, skipping checks",
                        "Token", self.service
                    );
                    self.adopt(token);
                    Ok(())
                } else {
                    match recheck_prerequisites_after_refresh(
                        &self.service,
                        &token,
                        config,
                        oradaz_client,
                    )
                    .await
                    {
                        Ok(()) => {
                            debug!(
                                "{:FL$}Successfully renewed token for service {:?}",
                                "Token", self.service
                            );
                            self.adopt(token);
                            Ok(())
                        }
                        Err(_) => {
                            handle_missing_permission_after_refresh(&self.service, config).await
                        }
                    }
                }
            }
        }
    }
}

async fn exchange_refresh_token(
    client: &reqwest::Client,
    token_url: &str,
    refresh_token: &str,
    client_id: &str,
    scope_str: &str,
    service: &str,
) -> Result<InitialTokenResponse, Error> {
    let response = match client
        .post(token_url)
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client_id),
            ("scope", scope_str),
        ])
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => {
            let detail = format!(
                "token refresh transport error: {}",
                transport_error_summary(&err)
            );
            error!(
                "{:FL$}Token refresh failed for service {:?}: {}",
                "Token", service, detail
            );
            return Err(Error::RefreshTokenNewScope(detail));
        }
    };

    let status = response.status();
    let bytes = match response.bytes().await {
        Ok(bytes) => bytes,
        Err(err) => {
            let detail = format!(
                "HTTP {status}: token refresh response unreadable: {}",
                transport_error_summary(&err)
            );
            error!(
                "{:FL$}Token refresh failed for service {:?}: {}",
                "Token", service, detail
            );
            return Err(Error::RefreshTokenNewScope(detail));
        }
    };

    if !status.is_success() {
        let summary = oauth_error_summary(status, &bytes, &[refresh_token]);
        error!(
            "{:FL$}Token refresh rejected for service {:?}: {}",
            "Token", service, summary
        );
        return Err(Error::RefreshTokenNewScope(summary));
    }

    match serde_json::from_slice::<TokenEndpointResponse>(&bytes) {
        Ok(body) => Ok(InitialTokenResponse { token: body }),
        Err(_) => {
            let detail = format!("HTTP {status}: invalid token refresh response");
            error!(
                "{:FL$}Token refresh failed for service {:?}: {}",
                "Token", service, detail
            );
            Err(Error::RefreshTokenNewScope(detail))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn exchange_with_response(
        response: ResponseTemplate,
        refresh_token: &str,
    ) -> Result<InitialTokenResponse, Error> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(response)
            .mount(&server)
            .await;

        exchange_refresh_token(
            &reqwest::Client::new(),
            &format!("{}/token", server.uri()),
            refresh_token,
            "client-id",
            "offline_access https://graph.microsoft.com/.default",
            "graph",
        )
        .await
    }

    fn refresh_error(result: Result<InitialTokenResponse, Error>) -> String {
        match result {
            Err(Error::RefreshTokenNewScope(message)) => message,
            Err(error) => panic!("unexpected refresh error: {error:?}"),
            Ok(_) => panic!("expected refresh exchange failure"),
        }
    }

    #[tokio::test]
    async fn refresh_body_transfer_error_keeps_status_without_exposing_contents() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let count = stream.read(&mut buffer).await.unwrap();
                assert!(count > 0);
                request.extend_from_slice(&buffer[..count]);
                if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..end]);
                    let length: usize = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse().unwrap())
                        })
                        .unwrap();
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 256\r\nConnection: close\r\n\r\nBODY_SECRET_SENTINEL",
            ).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let message = refresh_error(
            exchange_refresh_token(
                &client,
                &format!("http://{address}/token?secret=URL_SECRET_SENTINEL"),
                "REFRESH_SECRET_SENTINEL",
                "client-id",
                "offline_access",
                "graph",
            )
            .await,
        );
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .expect("local response server timed out")
            .expect("local response server panicked");

        assert!(message.contains("HTTP 200 OK"));
        assert!(message.contains("body transfer failed"), "{message}");
        assert!(!message.contains("SECRET_SENTINEL"));
    }

    #[tokio::test]
    async fn refresh_rejection_preserves_oauth_description() {
        let message = refresh_error(
            exchange_with_response(
                ResponseTemplate::new(400).set_body_json(serde_json::json!({
                    "error": "invalid_grant",
                    "error_description": "synthetic refusal"
                })),
                "refresh-secret",
            )
            .await,
        );

        assert_eq!(
            message,
            "HTTP 400 Bad Request: invalid_grant: synthetic refusal"
        );
    }

    #[tokio::test]
    async fn refresh_non_success_status_is_not_accepted_as_success() {
        let message = refresh_error(
            exchange_with_response(
                ResponseTemplate::new(500).set_body_json(serde_json::json!({
                    "access_token": "ACCESS_SENTINEL",
                    "refresh_token": "REFRESH_SENTINEL"
                })),
                "refresh-secret",
            )
            .await,
        );

        assert_eq!(
            message,
            "HTTP 500 Internal Server Error: invalid OAuth error response"
        );
        assert!(!message.contains("ACCESS_SENTINEL"));
        assert!(!message.contains("REFRESH_SENTINEL"));
    }

    #[tokio::test]
    async fn refresh_non_json_rejection_does_not_copy_body() {
        let message = refresh_error(
            exchange_with_response(
                ResponseTemplate::new(502).set_body_string("<html>HTML_SENTINEL</html>"),
                "refresh-secret",
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
    async fn refresh_malformed_success_response_is_safe() {
        for body in [
            serde_json::json!({"refresh_token": "rotated-token"}),
            serde_json::json!({
                "access_token": "access-token",
                "expires_in": "SECRET_SENTINEL"
            }),
        ] {
            let message = refresh_error(
                exchange_with_response(
                    ResponseTemplate::new(200).set_body_json(body),
                    "refresh-secret",
                )
                .await,
            );

            assert_eq!(message, "HTTP 200 OK: invalid token refresh response");
            assert!(!message.contains("SECRET_SENTINEL"));
        }
    }

    #[tokio::test]
    async fn refresh_request_has_exact_form_and_parses_token() {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let payload = URL_SAFE_NO_PAD.encode(br#"{"oid":"user-1","upn":"alice@example.test"}"#);
        let jwt = format!("e30.{payload}.signature");
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": jwt,
                "refresh_token": "rotated-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let scopes = vec![
            "offline_access".to_string(),
            "https://graph.microsoft.com/.default".to_string(),
        ];
        let response = exchange_refresh_token(
            &reqwest::Client::new(),
            &format!("{}/token", server.uri()),
            "refresh+token&with=reserved%characters",
            "client-id",
            &scopes.join(" "),
            "graph",
        )
        .await
        .expect("refresh exchange must succeed");
        let token = response
            .parse(
                "tenant-id".to_string(),
                "graph".to_string(),
                "client-id".to_string(),
                scopes.clone(),
            )
            .expect("the returned token must parse");
        assert_eq!(token.refresh_token.as_deref(), Some("rotated-token"));
        assert_eq!(token.user_id, "user-1");
        assert_eq!(token.scopes, scopes);

        let requests = server.received_requests().await.expect("recorded requests");
        assert_eq!(requests.len(), 1);
        let pairs: Vec<(String, String)> = url::form_urlencoded::parse(&requests[0].body)
            .into_owned()
            .collect();
        assert_eq!(pairs.len(), 4, "no additional or duplicate form field");
        let form: BTreeMap<String, String> = pairs.into_iter().collect();
        let expected = BTreeMap::from([
            ("grant_type".to_string(), "refresh_token".to_string()),
            (
                "refresh_token".to_string(),
                "refresh+token&with=reserved%characters".to_string(),
            ),
            ("client_id".to_string(), "client-id".to_string()),
            ("scope".to_string(), scopes.join(" ")),
        ]);
        assert_eq!(form, expected);
        assert!(!form.contains_key("redirect_uri"));
    }

    /// The post-refresh prerequisite re-check is non-fatal on transient
    /// failures — only a definitive `MissingAppPermission` surfaces (→ abort under
    /// app credentials / prompt under interactive); every other error is retried
    /// then tolerated. This guards that classification, which is the crux of the
    /// "a briefly-unavailable service never aborts a long collection" behaviour.
    #[test]
    fn classify_refresh_prereq_result_only_missing_permission_surfaces() {
        assert_eq!(
            classify_refresh_prereq_result(&Ok(())),
            RefreshPrereqDecision::Proceed
        );
        assert_eq!(
            classify_refresh_prereq_result(&Err(Error::MissingAppPermission)),
            RefreshPrereqDecision::Surface
        );
        // Everything else is transient → retry (then proceed once the budget is
        // exhausted): throttling, generic HTTP/network errors, and the reprocess
        // signal all classify as Retry, never Surface.
        for transient in [
            Error::TooManyRequestsDuringPrerequisites(30),
            Error::StringError("connection reset by peer".to_string()),
            Error::Reprocess(None),
        ] {
            assert_eq!(
                classify_refresh_prereq_result(&Err(transient)),
                RefreshPrereqDecision::Retry
            );
        }
    }

    fn token_with_refresh(rt: Option<&str>) -> Token {
        Token {
            tenant_id: "t".to_string(),
            client_id: "c".to_string(),
            service: "graph".to_string(),
            expires_on: 0,
            access_token: "at".to_string(),
            refresh_token: rt.map(str::to_string),
            token_type: "Bearer".to_string(),
            user_id: "u".to_string(),
            user_principal_name: "u@example.test".to_string(),
            scopes: vec![],
        }
    }

    #[test]
    fn adopt_preserves_refresh_token_when_new_response_omits_it() {
        let mut existing = token_with_refresh(Some("old-rt"));
        // A refresh response that did not carry a new refresh_token.
        existing.adopt(token_with_refresh(None));
        assert_eq!(existing.refresh_token.as_deref(), Some("old-rt"));
    }

    #[test]
    fn adopt_takes_new_refresh_token_when_present() {
        let mut existing = token_with_refresh(Some("old-rt"));
        existing.adopt(token_with_refresh(Some("new-rt")));
        assert_eq!(existing.refresh_token.as_deref(), Some("new-rt"));
    }
}
