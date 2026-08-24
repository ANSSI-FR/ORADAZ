/// Module to manage Client Credentials Flow authentication.
use crate::FL;
use crate::collect::auth::tokens::entity::Token;
use crate::utils::client::OradazClient;
use crate::utils::config::Config;
use crate::utils::errors::Error;

use base64::prelude::*;
use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use log::{debug, error, trace};
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};
use std::error::Error as StdError;
use std::fs;
use uuid::Uuid;

use crate::collect::auth::tokens::response::{InitialTokenResponse, TokenEndpointResponse};

/// IMDS token response — `expires_on` and `expires_in` may be strings or numbers
/// depending on the Azure execution environment.
#[derive(Deserialize)]
struct ImdsTokenResponse {
    access_token: String,
    /// Absolute epoch timestamp (preferred). Typically returned as a numeric string.
    expires_on: Option<serde_json::Value>,
    /// Relative seconds to expiry; used as fallback when `expires_on` is absent.
    expires_in: Option<serde_json::Value>,
    token_type: Option<String>,
}

impl ImdsTokenResponse {
    fn expires_on_timestamp(&self) -> i64 {
        fn coerce_i64(v: &serde_json::Value) -> Option<i64> {
            match v {
                serde_json::Value::Number(n) => n.as_i64(),
                serde_json::Value::String(s) => s.parse().ok(),
                _ => None,
            }
        }
        if let Some(v) = &self.expires_on
            && let Some(ts) = coerce_i64(v)
        {
            return ts;
        }
        let secs = self
            .expires_in
            .as_ref()
            .and_then(coerce_i64)
            .unwrap_or(3600);
        Utc::now().timestamp() + secs
    }
}

/// IMDS endpoint variant, detected from the Azure execution environment.
pub(crate) enum ImdsVariant {
    /// App Service / Azure Container Apps: uses `IDENTITY_ENDPOINT` and
    /// `IDENTITY_HEADER` environment variables.
    AppService { endpoint: String, header: String },
    /// Azure Arc: `IMDS_ENDPOINT` is set (not yet supported).
    AzureArc,
    /// VM / ACI / VMSS: standard link-local IMDS on `169.254.169.254`.
    Standard,
}

/// Detects which IMDS variant the current Azure execution environment provides.
pub(crate) fn detect_imds_variant() -> ImdsVariant {
    if let (Ok(ep), Ok(hdr)) = (
        std::env::var("IDENTITY_ENDPOINT"),
        std::env::var("IDENTITY_HEADER"),
    ) {
        return ImdsVariant::AppService {
            endpoint: ep,
            header: hdr,
        };
    }
    if std::env::var("IMDS_ENDPOINT").is_ok() {
        return ImdsVariant::AzureArc;
    }
    ImdsVariant::Standard
}

/// Extracts the v1 IMDS resource audience from a list of OAuth2 scopes.
///
/// Strips `/.default` from the first non-`offline_access` scope ending with
/// `/.default`, yielding the v1 resource URL expected by IMDS.
fn resource_from_scopes(scopes: &[String]) -> Option<String> {
    scopes
        .iter()
        .find(|s| s.as_str() != "offline_access" && s.ends_with("/.default"))
        .map(|s| s.trim_end_matches(".default").to_string())
}

/// Claims for a client assertion JWT (used by certificate flow).
#[derive(Serialize)]
struct ClientAssertionClaims {
    aud: String,
    exp: i64,
    iss: String,
    jti: String,
    nbf: i64,
    sub: String,
}

/// Joins an error with its full `source()` chain into one string, so the
/// concrete root cause (e.g. `Connection refused (os error 111)`) is surfaced
/// instead of a generic top-level message like "Request failed".
fn error_chain<E: StdError>(err: &E) -> String {
    let mut parts = vec![err.to_string()];
    let mut src = err.source();
    while let Some(e) = src {
        let msg = e.to_string();
        if parts.last().map(|p| p != &msg).unwrap_or(true) {
            parts.push(msg);
        }
        src = e.source();
    }
    parts.join(": ")
}

/// Utility for performing authentication using the Client Credentials flow.
pub struct ClientCredentialsAuth {}

impl ClientCredentialsAuth {
    /// Acquires a token using the OAuth 2.0 client credentials grant.
    ///
    /// Dispatches to the appropriate sub-flow based on `config.application_credentials.credential_type`:
    /// - `password` — client secret via a direct `reqwest` POST
    /// - `certificate` / `certificateFile` — signed JWT client assertion (RS256)
    pub async fn get_token(
        config: &Config,
        oradaz_client: &OradazClient,
        tenant: String,
        service: String,
        client_id: String,
        scopes: Vec<String>,
    ) -> Result<Token, Error> {
        let credentials = match &config.application_credentials {
            Some(c) => c,
            None => {
                error!(
                    "{:FL$}useApplicationCredentials is true but applicationCredentials is missing in config",
                    "ClientCredentialsAuth"
                );
                return Err(Error::InvalidApplicationCredentials);
            }
        };

        match credentials.credential_type.as_str() {
            "password" => {
                Self::get_token_password(
                    oradaz_client,
                    tenant,
                    service,
                    client_id,
                    scopes,
                    credentials.value.clone().unwrap_or_default(),
                )
                .await
            }
            "certificate" | "certificateFile" => {
                // `pem_content` comes from `value` (raw content or file path).
                let value = credentials.value.clone().unwrap_or_default();
                let pem_content = if credentials.credential_type == "certificateFile" {
                    match fs::read_to_string(&value) {
                        Ok(s) => s,
                        Err(err) => {
                            error!(
                                "{:FL$}Certificate file read error for service {:?}",
                                "ClientCredentialsAuth", service
                            );
                            debug!(
                                "{:FL$}Certificate file read error for service {:?}: {:?}",
                                "ClientCredentialsAuth", service, err
                            );
                            return Err(Error::ClientCredentialsFlowCreation(format!(
                                "Cannot read certificate file '{value}': {err}"
                            )));
                        }
                    }
                } else {
                    value
                };

                Self::get_token_certificate(
                    oradaz_client,
                    tenant,
                    service,
                    client_id,
                    scopes,
                    &pem_content,
                )
                .await
            }
            "managedIdentity" => {
                let mi_client_id = credentials.value.clone().unwrap_or_default();
                Self::get_token_managed_identity(
                    oradaz_client,
                    tenant,
                    service,
                    mi_client_id,
                    scopes,
                    None,
                )
                .await
            }
            other => {
                error!(
                    "{:FL$}Unknown applicationCredentials type {:?} for service {:?}",
                    "ClientCredentialsAuth", other, &service
                );
                Err(Error::ClientCredentialsFlowCreation(format!(
                    "Unknown applicationCredentials type '{other}'. Expected: password, certificate, certificateFile, or managedIdentity."
                )))
            }
        }
    }

    /// Client credentials flow using a client secret (password).
    async fn get_token_password(
        oradaz_client: &OradazClient,
        tenant: String,
        service: String,
        client_id: String,
        scopes: Vec<String>,
        client_secret: String,
    ) -> Result<Token, Error> {
        debug!(
            "{:FL$}Acquiring token for service {:?} using client secret",
            "ClientCredentialsAuth", service
        );
        let token_url = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token");
        let scope_str = scopes.join(" ");

        trace!(
            "{:FL$}Exchanging client credentials for service {:?}",
            "ClientCredentialsAuth", service
        );
        let token_response = match oradaz_client
            .client
            .post(&token_url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", &client_id),
                ("client_secret", &client_secret),
                ("scope", &scope_str),
            ])
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                match resp.json::<TokenEndpointResponse>().await {
                    Ok(body) => InitialTokenResponse { token: body },
                    Err(err) => {
                        error!(
                            "{:FL$}Error acquiring client credentials token for service {:?}",
                            "ClientCredentialsAuth", service
                        );
                        debug!(
                            "{:FL$}Client credentials token response parse error (HTTP {status}) for service {:?}: {:?}",
                            "ClientCredentialsAuth", service, err
                        );
                        return Err(Error::ClientCredentialsFlowAuthentication(format!(
                            "Failed to parse token response for service '{service}' using client secret (HTTP {status}): {err}"
                        )));
                    }
                }
            }
            Err(err) => {
                error!(
                    "{:FL$}Error acquiring client credentials token for service {:?}",
                    "ClientCredentialsAuth", service
                );
                debug!(
                    "{:FL$}Client credentials token exchange error for service {:?}: {:?}",
                    "ClientCredentialsAuth", service, err
                );

                return Err(Error::ClientCredentialsFlowAuthentication(format!(
                    "Failed to acquire token for service '{service}' using client secret: {}",
                    error_chain(&err)
                )));
            }
        };

        token_response.parse(tenant, service, client_id, scopes)
    }

    /// Client credentials flow using a certificate-based JWT client assertion (RS256).
    ///
    /// `pem_content` — PEM content containing the RSA private key (used for signing) and the certificate (used for thumbprint computation).
    async fn get_token_certificate(
        oradaz_client: &OradazClient,
        tenant: String,
        service: String,
        client_id: String,
        scopes: Vec<String>,
        pem_content: &str,
    ) -> Result<Token, Error> {
        debug!(
            "{:FL$}Acquiring token for service {:?} using certificate assertion",
            "ClientCredentialsAuth", service
        );

        // Detect a missing private key before attempting to parse, so the error
        // message is actionable rather than a cryptic parse failure.
        let has_private_key = pem_content.contains("-----BEGIN PRIVATE KEY-----")
            || pem_content.contains("-----BEGIN RSA PRIVATE KEY-----")
            || pem_content.contains("-----BEGIN EC PRIVATE KEY-----");
        if !has_private_key {
            error!(
                "{:FL$}No private key found in PEM content for service {:?}",
                "ClientCredentialsAuth", service
            );
            return Err(Error::ClientCredentialsFlowCreation(format!(
                "No private key found in the PEM provided for service '{service}'. \
                 A certificate file (.cer) contains only the public certificate, not the private key. \
                 Use <keyFile> or <key> in the config to supply the private key separately."
            )));
        }

        // ORADAZ signs the client assertion with RS256 and `from_rsa_pem` only
        // accepts RSA keys. Reject an EC key up front with an actionable message
        // rather than letting it fall through to a cryptic RSA parse failure.
        if pem_content.contains("-----BEGIN EC PRIVATE KEY-----") {
            error!(
                "{:FL$}EC private key rejected for service {:?}: RS256 (RSA) required",
                "ClientCredentialsAuth", service
            );
            return Err(Error::ClientCredentialsFlowCreation(format!(
                "An EC private key was provided for service '{service}', but ORADAZ signs the \
                 client assertion with RS256 and only supports RSA keys. Supply an RSA private \
                 key (PKCS#8 'BEGIN PRIVATE KEY' or PKCS#1 'BEGIN RSA PRIVATE KEY')."
            )));
        }

        // Build the signing key from the PEM private key.
        let encoding_key = match EncodingKey::from_rsa_pem(pem_content.as_bytes()) {
            Ok(k) => k,
            Err(err) => {
                error!(
                    "{:FL$}Failed to parse RSA private key from PEM for service {:?}",
                    "ClientCredentialsAuth", service
                );
                debug!(
                    "{:FL$}RSA private key parse error for service {:?}: {:?}",
                    "ClientCredentialsAuth", service, err
                );

                return Err(Error::ClientCredentialsFlowCreation(format!(
                    "Failed to parse the RSA private key from PEM for service '{service}'. \
                     Ensure the key is in PKCS#8 (BEGIN PRIVATE KEY) or PKCS#1 (BEGIN RSA PRIVATE KEY) format: {err}"
                )));
            }
        };

        // Extract the certificate DER bytes to compute the x5t#S256 thumbprint.
        let x5t_s256 = match Self::compute_x5t_s256(pem_content) {
            Ok(t) => t,
            Err(err) => {
                error!(
                    "{:FL$}Failed to compute certificate thumbprint for service {:?}",
                    "ClientCredentialsAuth", service
                );
                debug!(
                    "{:FL$}Certificate thumbprint computation error for service {:?}: {:?}",
                    "ClientCredentialsAuth", service, err
                );

                return Err(Error::ClientCredentialsFlowCreation(format!(
                    "Failed to compute certificate thumbprint for service '{service}': {err}"
                )));
            }
        };

        let assertion = Self::build_client_assertion(
            &tenant,
            &client_id,
            encoding_key,
            Algorithm::RS256,
            Some(x5t_s256),
        )?;

        Self::post_client_assertion(oradaz_client, tenant, service, client_id, scopes, assertion)
            .await
    }

    /// Computes the SHA-256 thumbprint (x5t#S256) of the first certificate in the PEM string.
    fn compute_x5t_s256(pem_content: &str) -> Result<String, Box<dyn StdError>> {
        // Find the certificate block in the PEM.
        let cert_start = pem_content
            .find("-----BEGIN CERTIFICATE-----")
            .ok_or("No certificate block found in PEM")?
            + "-----BEGIN CERTIFICATE-----".len();
        let cert_end = pem_content[cert_start..]
            .find("-----END CERTIFICATE-----")
            .ok_or("No certificate end marker found in PEM")?
            + cert_start;

        // Strip whitespace from the base64 body and decode to DER bytes.
        let b64_body: String = pem_content[cert_start..cert_end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let der_bytes = BASE64_STANDARD.decode(b64_body)?;

        // SHA-256 hash of the DER-encoded certificate (x5t#S256), base64url-encoded.
        let hash_bytes = Sha256::digest(der_bytes.as_slice());

        Ok(BASE64_URL_SAFE_NO_PAD.encode(hash_bytes))
    }

    /// Builds a signed JWT client assertion.
    fn build_client_assertion(
        tenant: &str,
        client_id: &str,
        encoding_key: EncodingKey,
        algorithm: Algorithm,
        x5t_s256: Option<String>,
    ) -> Result<String, Error> {
        let now = Utc::now().timestamp();
        let mut header = Header::new(algorithm);
        header.x5t_s256 = x5t_s256;

        let claims = ClientAssertionClaims {
            aud: format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"),
            exp: now + 600,
            iss: client_id.to_string(),
            jti: Uuid::new_v4().to_string(),
            // Back-date `nbf` by 5 minutes to tolerate clock skew between this
            // host and Microsoft's token endpoint; `nbf = now` can otherwise be
            // rejected as "used before valid" when their clock is slightly behind.
            nbf: now - 300,
            sub: client_id.to_string(),
        };

        match jsonwebtoken::encode(&header, &claims, &encoding_key) {
            Ok(jwt) => Ok(jwt),
            Err(err) => {
                error!(
                    "{:FL$}Failed to sign client assertion JWT",
                    "ClientCredentialsAuth"
                );
                debug!(
                    "{:FL$}Client assertion signing error: {:?}",
                    "ClientCredentialsAuth", err
                );

                Err(Error::ClientCredentialsFlowCreation(format!(
                    "Failed to sign client assertion JWT: {err}"
                )))
            }
        }
    }

    /// POSTs a client assertion to the token endpoint and parses the response.
    async fn post_client_assertion(
        oradaz_client: &OradazClient,
        tenant: String,
        service: String,
        client_id: String,
        scopes: Vec<String>,
        client_assertion: String,
    ) -> Result<Token, Error> {
        let token_url = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token");
        let scope_str = scopes.join(" ");

        trace!(
            "{:FL$}POSTing client assertion to token endpoint for service {:?}",
            "ClientCredentialsAuth", service
        );
        let response = match oradaz_client
            .client
            .post(&token_url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", &client_id),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
                ("client_assertion", &client_assertion),
                ("scope", &scope_str),
            ])
            .send()
            .await
        {
            Ok(r) => r,
            Err(err) => {
                error!(
                    "{:FL$}HTTP error posting client assertion for service {:?}",
                    "ClientCredentialsAuth", service
                );
                debug!(
                    "{:FL$}Client assertion POST error for service {:?}: {:?}",
                    "ClientCredentialsAuth", service, err
                );

                return Err(Error::ClientCredentialsFlowAuthentication(format!(
                    "HTTP error posting client assertion for service '{service}': {}",
                    error_chain(&err)
                )));
            }
        };

        let status = response.status();
        let body: TokenEndpointResponse = match response.json().await {
            Ok(b) => b,
            Err(err) => {
                error!(
                    "{:FL$}Failed to parse token endpoint response for service {:?}",
                    "ClientCredentialsAuth", service
                );
                debug!(
                    "{:FL$}Token endpoint response parse error (HTTP {status}) for service {:?}: {:?}",
                    "ClientCredentialsAuth", service, err
                );

                return Err(Error::ClientCredentialsFlowAuthentication(format!(
                    "Failed to parse token endpoint response for service '{service}' (HTTP {status}): {err}"
                )));
            }
        };

        let expires_on = Utc::now().timestamp() + body.expires_in.unwrap_or(3600) as i64;

        // Parse OID and identity from the JWT payload. Client-credentials tokens
        // are app-only and carry no UPN, so this falls back to `app_displayname`.
        let (user_id, user_principal_name) =
            Self::parse_identity_from_jwt(&body.access_token, &service);
        debug!(
            "{:FL$}Token acquired for service {:?}: oid={:?} identity={:?}",
            "ClientCredentialsAuth", service, user_id, user_principal_name
        );

        Ok(Token {
            tenant_id: tenant,
            client_id,
            service,
            expires_on,
            access_token: body.access_token,
            refresh_token: body.refresh_token,
            token_type: body.token_type.unwrap_or_else(|| String::from("Bearer")),
            user_id,
            user_principal_name,
            scopes,
        })
    }

    /// Acquires a token from the Azure Instance Metadata Service (IMDS).
    ///
    /// `mi_client_id` — client ID of a user-assigned managed identity; pass an
    /// empty string for system-assigned.
    ///
    /// `imds_url_override` — test hook: replaces the auto-detected IMDS endpoint
    /// with a custom URL (forces Standard variant behaviour); pass `None` in
    /// production.
    pub async fn get_token_managed_identity(
        oradaz_client: &OradazClient,
        tenant: String,
        service: String,
        mi_client_id: String,
        scopes: Vec<String>,
        imds_url_override: Option<&str>,
    ) -> Result<Token, Error> {
        // mi_client_id is empty for system-assigned managed identity.
        // For user-assigned, it is the managed identity's client_id (not object_id).
        debug!(
            "{:FL$}Acquiring token for service {:?} using managed identity ({})",
            "ClientCredentialsAuth",
            service,
            if mi_client_id.is_empty() {
                "system-assigned"
            } else {
                "user-assigned"
            }
        );

        let resource = match resource_from_scopes(&scopes) {
            Some(r) => r,
            None => {
                error!(
                    "{:FL$}Cannot determine IMDS resource for service {:?}: no /.default scope found",
                    "ClientCredentialsAuth", service
                );
                return Err(Error::ClientCredentialsFlowCreation(format!(
                    "Cannot determine IMDS resource for service '{service}': \
                     no '/.default' scope found in {scopes:?}"
                )));
            }
        };

        // When a URL override is provided (test hook), skip env detection and use Standard.
        let variant = if imds_url_override.is_some() {
            ImdsVariant::Standard
        } else {
            // App Service / Container Apps set IDENTITY_ENDPOINT *and*
            // IDENTITY_HEADER; exactly one of them present is a misconfiguration
            // that would otherwise fall through to the VM link-local Standard
            // variant and time out instead of giving a clear error. We only
            // diagnose that here when IMDS_ENDPOINT is *absent*: if it is set this
            // is an Azure Arc (or Arc-like) environment — including a real Arc
            // server, which sets IDENTITY_ENDPOINT + IMDS_ENDPOINT but no
            // IDENTITY_HEADER — so we defer to detect_imds_variant, which
            // classifies it as AzureArc and returns its own clear "unsupported"
            // error rather than this App-Service-centric message.
            if std::env::var("IDENTITY_ENDPOINT").is_ok()
                && std::env::var("IDENTITY_HEADER").is_err()
                && std::env::var("IMDS_ENDPOINT").is_err()
            {
                return Err(Error::ClientCredentialsFlowCreation(format!(
                    "IDENTITY_ENDPOINT is set but IDENTITY_HEADER is missing for service \
                     '{service}'. On App Service and Container Apps both environment \
                     variables must be present for managed identity authentication."
                )));
            }
            // Symmetric case: IDENTITY_HEADER without IDENTITY_ENDPOINT (same
            // IMDS_ENDPOINT-absent rule as the guard above).
            if std::env::var("IDENTITY_HEADER").is_ok()
                && std::env::var("IDENTITY_ENDPOINT").is_err()
                && std::env::var("IMDS_ENDPOINT").is_err()
            {
                return Err(Error::ClientCredentialsFlowCreation(format!(
                    "IDENTITY_HEADER is set but IDENTITY_ENDPOINT is missing for service \
                     '{service}'. On App Service and Container Apps both environment \
                     variables must be present for managed identity authentication."
                )));
            }
            detect_imds_variant()
        };
        debug!(
            "{:FL$}IMDS variant for service {:?}: {}",
            "ClientCredentialsAuth",
            service,
            match &variant {
                ImdsVariant::AppService { endpoint, .. } => format!("AppService ({})", endpoint),
                ImdsVariant::AzureArc => "AzureArc (unsupported)".to_string(),
                ImdsVariant::Standard => "Standard (VM/ACI link-local)".to_string(),
            }
        );

        let (url, header_name, header_value) = match &variant {
            ImdsVariant::AzureArc => {
                error!(
                    "{:FL$}Azure Arc managed identity is not yet supported for service {:?}",
                    "ClientCredentialsAuth", service
                );
                return Err(Error::ClientCredentialsFlowCreation(format!(
                    "Azure Arc managed identity is not yet supported (service '{service}'). \
                     IMDS_ENDPOINT is set, but Azure Arc requires a challenge-response \
                     protocol not implemented in this version."
                )));
            }
            ImdsVariant::AppService { endpoint, header } => {
                let mut ep = format!("{endpoint}?api-version=2019-08-01&resource={resource}");
                if !mi_client_id.is_empty() {
                    ep.push_str(&format!("&client_id={mi_client_id}"));
                }
                (ep, "X-IDENTITY-HEADER".to_string(), header.clone())
            }
            ImdsVariant::Standard => {
                let base = imds_url_override.unwrap_or("http://169.254.169.254");
                let mut ep = format!(
                    "{base}/metadata/identity/oauth2/token\
                     ?api-version=2018-02-01&resource={resource}"
                );
                if !mi_client_id.is_empty() {
                    ep.push_str(&format!("&client_id={mi_client_id}"));
                }
                (ep, "Metadata".to_string(), "true".to_string())
            }
        };

        trace!(
            "{:FL$}Calling IMDS endpoint for service {:?}",
            "ClientCredentialsAuth", service
        );
        let response = match oradaz_client
            .client
            .get(&url)
            .header(header_name.as_str(), header_value.as_str())
            .send()
            .await
        {
            Ok(r) => r,
            Err(err) => {
                error!(
                    "{:FL$}IMDS request failed for service {:?}",
                    "ClientCredentialsAuth", service
                );
                debug!(
                    "{:FL$}IMDS request error for service {:?}: {:?}",
                    "ClientCredentialsAuth", service, err
                );
                return Err(Error::ClientCredentialsFlowAuthentication(format!(
                    "IMDS request failed for service '{service}': {}",
                    error_chain(&err)
                )));
            }
        };

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            error!(
                "{:FL$}IMDS returned HTTP {} for service {:?}",
                "ClientCredentialsAuth", status, service
            );
            debug!(
                "{:FL$}IMDS error body for service {:?}: {}",
                "ClientCredentialsAuth", service, body
            );
            return Err(Error::ClientCredentialsFlowAuthentication(format!(
                "IMDS returned HTTP {status} for service '{service}'"
            )));
        }

        let body: ImdsTokenResponse = match response.json().await {
            Ok(b) => b,
            Err(err) => {
                error!(
                    "{:FL$}Failed to parse IMDS response for service {:?}",
                    "ClientCredentialsAuth", service
                );
                debug!(
                    "{:FL$}IMDS response parse error for service {:?}: {:?}",
                    "ClientCredentialsAuth", service, err
                );
                return Err(Error::ClientCredentialsFlowAuthentication(format!(
                    "Failed to parse IMDS response for service '{service}': {err}"
                )));
            }
        };

        let expires_on = body.expires_on_timestamp();
        let (user_id, user_principal_name) =
            Self::parse_identity_from_jwt(&body.access_token, &service);

        Ok(Token {
            tenant_id: tenant,
            client_id: mi_client_id,
            service,
            expires_on,
            access_token: body.access_token,
            refresh_token: None,
            token_type: body.token_type.unwrap_or_else(|| String::from("Bearer")),
            user_id,
            user_principal_name,
            scopes,
        })
    }

    /// Extracts `oid` and an identity label from the JWT payload, returning
    /// empty strings on failure. Prefers a real UPN (`upn` / `preferred_username`)
    /// when present, falling back to `app_displayname` for app-only tokens.
    fn parse_identity_from_jwt(access_token: &str, service: &str) -> (String, String) {
        #[derive(Deserialize)]
        struct JwtClaims {
            #[serde(default)]
            oid: String,
            #[serde(default)]
            upn: Option<String>,
            #[serde(default)]
            preferred_username: Option<String>,
            #[serde(default)]
            app_displayname: String,
        }

        impl JwtClaims {
            fn identity(&self) -> String {
                self.upn
                    .clone()
                    .filter(|s| !s.is_empty())
                    .or_else(|| self.preferred_username.clone().filter(|s| !s.is_empty()))
                    .unwrap_or_else(|| self.app_displayname.clone())
            }
        }

        let payload = match access_token.split('.').nth(1) {
            Some(p) => p,
            None => {
                debug!(
                    "{:FL$}Access token for service {:?} has no JWT payload; identity fields will be empty",
                    "ClientCredentialsAuth", service
                );
                return (String::new(), String::new());
            }
        };

        match BASE64_URL_SAFE_NO_PAD.decode(payload) {
            Ok(bytes) => {
                let s = String::from_utf8_lossy(&bytes);
                match serde_json::from_str::<JwtClaims>(&s) {
                    Ok(c) => {
                        let identity = c.identity();
                        debug!(
                            "{:FL$}JWT claims resolved for service {:?}: oid={:?} identity={:?}",
                            "ClientCredentialsAuth", service, c.oid, identity
                        );
                        (c.oid, identity)
                    }
                    Err(err) => {
                        debug!(
                            "{:FL$}JWT claims parse failed for service {:?}: {:?}",
                            "ClientCredentialsAuth", service, err
                        );
                        (String::new(), String::new())
                    }
                }
            }
            Err(err) => {
                debug!(
                    "{:FL$}JWT payload base64 decode failed for service {:?}: {:?}",
                    "ClientCredentialsAuth", service, err
                );
                (String::new(), String::new())
            }
        }
    }
}
