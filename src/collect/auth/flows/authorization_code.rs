/// Module to manage Authorization Code Flow authentication.
///
/// This flow requires a redirection URL for the application, typically configured
/// as a "Mobile and desktop applications" URL in the Azure portal.
use crate::FL;
use crate::collect::auth::tokens::Token;
use crate::collect::auth::tokens::response::{InitialTokenResponse, TokenEndpointResponse};
use crate::utils::client::OradazClient;
use crate::utils::config::Config;
use crate::utils::errors::Error;
use crate::utils::ui::auth_banner::AuthBanner;

use base64::prelude::*;
use log::{debug, error, trace};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use url::Url;
use uuid::Uuid;

/// Upper bound on the bytes read for a connection's HTTP request line, so a
/// client on the loopback interface cannot grow the buffer without limit.
const MAX_REQUEST_LINE_BYTES: u64 = 8 * 1024;

/// Per-connection deadline for receiving the request line. Connections are
/// handled one at a time, so a peer that completes the TCP handshake but never
/// sends anything (a browser preconnect socket, a local port scanner) would
/// otherwise block the loop while the genuine OAuth redirect waits in the
/// accept backlog. A real redirect arrives within milliseconds; 10 s is
/// generous for it and short enough that sign-in is not noticeably delayed.
const REQUEST_LINE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Utility for performing authentication using the Authorization Code flow.
pub struct AuthorizationCodeAuth {}

/// Sends a minimal plain-text HTTP/1.1 response to the browser and asks it to
/// close the connection. Errors are returned to the caller, which treats a
/// failed write to a transient/stray connection as non-fatal.
async fn respond(stream: &mut TcpStream, status: &str, body: &str) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await
}

/// Generates a PKCE verifier (random base64url) and its S256 challenge.
fn generate_pkce() -> (String, String) {
    let bytes = rand::random::<[u8; 32]>();
    let verifier = BASE64_URL_SAFE_NO_PAD.encode(bytes);
    // SHA-256 of the verifier bytes → base64url (the PKCE S256 challenge).
    let challenge = BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

/// Waits for the OAuth redirect on the already-bound `listener` and returns the
/// `code` and `state` query parameters from the browser's redirect request.
///
/// Fully async (tokio): `accept`/`read`/`write` yield the task to the runtime
/// while waiting for the browser, so no worker thread is blocked during the
/// (potentially long) interactive sign-in. `listener_address`/`listener_port`
/// are passed only to preserve the operator-facing error message.
async fn wait_for_redirect(
    listener: TcpListener,
    listener_address: &str,
    listener_port: &str,
) -> Result<(String, String), Error> {
    // The browser may open several connections to the loopback redirect URI
    // (speculative/preconnect sockets, a favicon request, …) around the real
    // OAuth redirect. Keep accepting until one carries the authorization `code`,
    // answering and ignoring the others, so a stray connection cannot abort
    // interactive sign-in. There is no deadline here: the wait lasts as long as
    // the user takes, and the operator interrupts with Ctrl+C.
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(err) => {
                debug!(
                    "{:FL$}Transient TCP accept error on {}:{}, waiting for the next connection: {:?}",
                    "AuthorizationCodeAuth", listener_address, listener_port, err
                );
                continue;
            }
        };

        // Read only the request line, capped so a hostile client cannot grow the
        // buffer without limit and bounded in time so a silent held-open
        // connection cannot stall the loop. A read error, a timeout or an empty
        // line is a stray/aborted connection: drop it and wait for the next one.
        let mut request_line = String::new();
        {
            let mut reader = BufReader::new(&mut stream).take(MAX_REQUEST_LINE_BYTES);
            match tokio::time::timeout(REQUEST_LINE_TIMEOUT, reader.read_line(&mut request_line))
                .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(err)) => {
                    debug!(
                        "{:FL$}Ignoring connection with unreadable request line: {:?}",
                        "AuthorizationCodeAuth", err
                    );
                    continue;
                }
                Err(_) => {
                    debug!(
                        "{:FL$}Ignoring connection that sent no request line within {}s",
                        "AuthorizationCodeAuth",
                        REQUEST_LINE_TIMEOUT.as_secs()
                    );
                    continue;
                }
            }
        }

        // The request target is the second whitespace-separated token of e.g.
        // "GET /redirect?code=...&state=... HTTP/1.1".
        let url = match request_line
            .split_whitespace()
            .nth(1)
            .and_then(|path| Url::parse(&format!("http://localhost{path}")).ok())
        {
            Some(u) => u,
            None => {
                debug!(
                    "{:FL$}Ignoring connection with no parseable request target on {}:{}",
                    "AuthorizationCodeAuth", listener_address, listener_port
                );
                let _ = respond(
                    &mut stream,
                    "400 Bad Request",
                    "Waiting for the OAuth redirect...",
                )
                .await;
                continue;
            }
        };

        let find_param = |name: &str| {
            url.query_pairs()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.into_owned())
        };

        // An explicit `error` parameter means the identity provider rejected the
        // request (most often the user denied consent): a definitive failure,
        // reported to both the browser and the operator.
        if let Some(error_code) = find_param("error") {
            let description = find_param("error_description").unwrap_or_default();
            error!(
                "{:FL$}Authorization request rejected by the identity provider: {} {}",
                "AuthorizationCodeAuth", error_code, description
            );
            let _ = respond(
                &mut stream,
                "200 OK",
                "Authentication failed, please go back to ORADAZ",
            )
            .await;
            return Err(Error::AuthorizationCodeFlowAuthentication);
        }

        // A `code` identifies the genuine OAuth redirect. The `state` is returned
        // as-is and validated against the CSRF token by the caller. A failed
        // write of the confirmation page does not invalidate the received code —
        // authentication proceeds; the browser just shows no confirmation.
        if let Some(code) = find_param("code") {
            let state = find_param("state").unwrap_or_default();
            if let Err(err) = respond(
                &mut stream,
                "200 OK",
                "Authentication successful, please go back to ORADAZ",
            )
            .await
            {
                debug!(
                    "{:FL$}Could not write the success page to the browser (authentication continues): {:?}",
                    "AuthorizationCodeAuth", err
                );
            }
            return Ok((code, state));
        }

        // Neither `code` nor `error`: a stray connection (preconnect, favicon, …).
        // Answer politely and keep waiting for the real redirect.
        debug!(
            "{:FL$}Ignoring non-redirect request on {}:{}",
            "AuthorizationCodeAuth", listener_address, listener_port
        );
        let _ = respond(
            &mut stream,
            "404 Not Found",
            "Waiting for the OAuth redirect...",
        )
        .await;
    }
}

impl AuthorizationCodeAuth {
    /// Performs Azure authentication using the Authorization Code flow with PKCE.
    ///
    /// The process involves:
    /// 1. Generating a PKCE challenge and an authorization URL.
    /// 2. Displaying the URL to the user.
    /// 3. Starting a local TCP listener to intercept the redirect containing the authorization code.
    /// 4. Verifying the CSRF state.
    /// 5. Exchanging the authorization code for an access token.
    pub async fn get_token(
        config: &Config,
        oradaz_client: &OradazClient,
        tenant: String,
        service: String,
        client_id: String,
        scopes: Vec<String>,
    ) -> Result<Token, Error> {
        debug!(
            "{:FL$}Acquiring token for scopes '{}' using authorization code flow",
            "AuthorizationCodeAuth",
            scopes.join(" ")
        );

        let auth_endpoint =
            format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize");
        let token_endpoint =
            format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token");
        let listener_address: String = config
            .listener_address
            .clone()
            .unwrap_or(String::from("localhost"));
        let listener_port: String = config.listener_port.clone().unwrap_or(String::from("3003"));
        let redirect_uri = format!("http://{listener_address}:{listener_port}/redirect");

        // Generate PKCE and CSRF token.
        let (pkce_verifier, pkce_challenge) = generate_pkce();
        let csrf_token = Uuid::new_v4().to_string();

        // Build the authorization URL.
        let mut auth_url = match Url::parse(&auth_endpoint) {
            Ok(u) => u,
            Err(err) => {
                error!(
                    "{:FL$}Error starting authorization code flow for service {:?}. Use the --debug option for more information.",
                    "AuthorizationCodeAuth", service
                );
                debug!(
                    "{:FL$}AuthUrl construction error: {:?}",
                    "AuthorizationCodeAuth", err
                );
                return Err(Error::AuthorizationCodeFlowCreation);
            }
        };
        auth_url
            .query_pairs_mut()
            .append_pair("client_id", &client_id)
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("scope", &scopes.join(" "))
            .append_pair("state", &csrf_token)
            .append_pair("code_challenge", &pkce_challenge)
            .append_pair("code_challenge_method", "S256");

        // Show authentication URL via live-region banner.
        let mut banner = AuthBanner::new();
        banner.begin(&service, auth_url.as_str(), "", "Authorization code");

        trace!(
            "{:FL$}Starting TCP listener on address {:?} and port {:?}.",
            "AuthorizationCodeAuth", listener_address, listener_port
        );
        let listener: TcpListener = match TcpListener::bind(format!(
            "{listener_address}:{listener_port}"
        ))
        .await
        {
            Ok(t) => t,
            Err(err) => {
                error!(
                    "{:FL$}Error starting TCP listener on address {:?} and port {:?}. Options 'listenerAddress' and 'listenerPort' can be used in config file to change this.",
                    "AuthorizationCodeAuth", listener_address, listener_port
                );
                debug!(
                    "{:FL$}TCP listener bind error: {:?}",
                    "AuthorizationCodeAuth", err
                );

                return Err(Error::AuthorizationCodeFlowCreation);
            }
        };

        let (code, state) = wait_for_redirect(listener, &listener_address, &listener_port).await?;

        if state != csrf_token {
            error!(
                "{:FL$}Error during authorization code flow for service {:?} that may indicate a CSRF attack.",
                "AuthorizationCodeAuth", service
            );
            banner.failure("Authorization code flow creation failed");
            return Err(Error::AuthorizationCodeFlowCreation);
        }

        // Exchange the authorization code for a token.
        let scope_str = scopes.join(" ");
        let fields: Vec<(&str, &str)> = vec![
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("code_verifier", &pkce_verifier),
            ("client_id", &client_id),
            ("redirect_uri", &redirect_uri),
            ("scope", &scope_str),
        ];

        let token_response: InitialTokenResponse = match oradaz_client
            .client
            .post(&token_endpoint)
            .form(&fields)
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                let body_bytes = match resp.bytes().await {
                    Ok(b) => b,
                    Err(err) => {
                        error!(
                            "{:FL$}Error reading token response body for service {:?}. Use the --debug option for more information.",
                            "AuthorizationCodeAuth", service
                        );
                        debug!(
                            "{:FL$}Body read error (HTTP {status}): {:?}",
                            "AuthorizationCodeAuth", err
                        );
                        banner.failure("Authorization code flow authentication failed");
                        return Err(Error::AuthorizationCodeFlowAuthentication);
                    }
                };
                match serde_json::from_slice::<TokenEndpointResponse>(&body_bytes) {
                    Ok(body) => InitialTokenResponse { token: body },
                    Err(err) => {
                        error!(
                            "{:FL$}Error while retrieving token from authorization code for service {:?}. Use the --debug option for more information.",
                            "AuthorizationCodeAuth", service
                        );
                        debug!(
                            "{:FL$}Token response parse error (HTTP {status}) for service {:?}: {:?}",
                            "AuthorizationCodeAuth", service, err
                        );
                        // Log only a bounded prefix: a parse failure means the body is
                        // not a valid token response, but a partial write or an
                        // intermediary error page could still carry credential
                        // fragments — cap it rather than persisting the full body.
                        let raw_body = String::from_utf8_lossy(&body_bytes);
                        let raw_preview: String = raw_body.chars().take(128).collect();
                        trace!(
                            "{:FL$}Raw token response body (first 128 chars): {:?}",
                            "AuthorizationCodeAuth", raw_preview
                        );
                        banner.failure("Authorization code flow authentication failed");
                        return Err(Error::AuthorizationCodeFlowAuthentication);
                    }
                }
            }
            Err(err) => {
                error!(
                    "{:FL$}Error while retrieving token from authorization code for service {:?}. Use the --debug option for more information.",
                    "AuthorizationCodeAuth", service
                );
                debug!(
                    "{:FL$}Token exchange error: {:?}",
                    "AuthorizationCodeAuth", err
                );

                banner.failure("Authorization code flow authentication failed");
                return Err(Error::AuthorizationCodeFlowAuthentication);
            }
        };

        let token = token_response.parse(tenant, service.clone(), client_id, scopes)?;
        // Record completed service for final banner
        banner.add_completed(&service);
        banner.success();
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::wait_for_redirect;
    use crate::utils::errors::Error;

    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    /// The async listener extracts `code` and `state` from a browser redirect.
    #[tokio::test]
    async fn wait_for_redirect_extracts_code_and_state() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(wait_for_redirect(listener, "127.0.0.1", "0"));

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(
                b"GET /redirect?code=the-code&state=the-state HTTP/1.1\r\nHost: localhost\r\n\r\n",
            )
            .await
            .unwrap();

        let (code, state) = server.await.unwrap().unwrap();
        assert_eq!(code, "the-code");
        assert_eq!(state, "the-state");
    }

    /// A stray connection that opens and closes without sending the redirect
    /// (e.g. a browser preconnect socket) must be skipped, after which the real
    /// redirect on a later connection still succeeds.
    #[tokio::test]
    async fn wait_for_redirect_skips_stray_connection_then_succeeds() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(wait_for_redirect(listener, "127.0.0.1", "0"));

        // Open then immediately close a connection without sending anything.
        let stray = TcpStream::connect(addr).await.unwrap();
        drop(stray);

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET /redirect?code=real-code&state=real-state HTTP/1.1\r\n\r\n")
            .await
            .unwrap();

        let (code, state) = server.await.unwrap().unwrap();
        assert_eq!(code, "real-code");
        assert_eq!(state, "real-state");
    }

    /// A consent denial redirects with an `error` parameter (and no `code`): a
    /// definitive failure, distinct from a stray connection that is skipped.
    #[tokio::test]
    async fn wait_for_redirect_reports_provider_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(wait_for_redirect(listener, "127.0.0.1", "0"));

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(
                b"GET /redirect?error=access_denied&error_description=denied HTTP/1.1\r\n\r\n",
            )
            .await
            .unwrap();

        // The dedicated authentication-failure variant distinguishes a consent
        // denial from a stray connection (which is skipped, not an error).
        assert!(matches!(
            server.await.unwrap(),
            Err(Error::AuthorizationCodeFlowAuthentication)
        ));
    }
}
