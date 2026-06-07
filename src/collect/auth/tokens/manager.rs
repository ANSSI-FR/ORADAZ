/// Token initialization: acquires one access token per enabled service and stores them in a shared map.
use crate::FL;
use crate::collect::auth::tokens::entity::Token;
use crate::collect::auth::tokens::state::{SharedTokenState, TokenState};
use crate::collect::auth::{Auth, AuthError};
use crate::utils::client::OradazClient;
use crate::utils::config::Config;
use crate::utils::errors::Error;
use crate::utils::schema::Schema;
use crate::utils::writer::actor::WriterHandle;

use dashmap::DashMap;
use log::{debug, error, warn};
use std::sync::Arc;

/// Bounded retry attempts for managed-identity (IMDS) token acquisition at startup.
/// IMDS is known to fail transiently at VM boot, during live-migration, and under
/// load, so a single transient failure should not abort the whole collection.
const MAX_IMDS_TOKEN_ATTEMPTS: u32 = 5;

pub struct Tokens {}

impl Tokens {
    /// Initializes authentication tokens for all services enabled in the configuration or marked as mandatory.
    ///
    /// This process starts by acquiring a primary token for the Microsoft Graph API.
    /// It then uses this token's refresh token to acquire tokens for other services specified in the schema.
    /// Any authentication failures are collected and written to `auth_errors.json` in the output archive.
    pub async fn initialize(
        config: &Config,
        oradaz_client: &OradazClient,
        tenant: &str,
        app_id: &str,
        schema: &Schema,
        writer: &WriterHandle,
    ) -> Result<DashMap<Arc<str>, SharedTokenState>, Error> {
        debug!(
            "{:FL$}Initializing tokens for all enabled services",
            "Tokens"
        );
        let tokens = DashMap::new();
        let mut auth_errors: Vec<AuthError> = Vec::new();

        // Client credentials flow: each service gets an independent direct token request.
        // There is no bootstrap graph token or refresh-token fan-out.
        if Config::use_application_credentials_auth(config) {
            for service in &schema.services {
                if service.mandatory_auth || Config::service_enable(config, &service.name) {
                    debug!(
                        "{:FL$}Acquiring client credentials token for service {:?}.",
                        "Tokens", &service.name
                    );
                    // IMDS (managed identity) can fail transiently at VM boot, during
                    // live-migration, or under load. Retry a bounded number of times
                    // with exponential backoff so a transient blip on a mandatory
                    // service does not abort the whole collection. Other
                    // client-credential sub-types are tried once: a bad secret/cert
                    // will not recover by retrying.
                    let max_attempts = if Config::use_managed_identity_auth(config) {
                        MAX_IMDS_TOKEN_ATTEMPTS
                    } else {
                        1
                    };
                    let mut attempt: u32 = 0;
                    let acquired = loop {
                        attempt += 1;
                        match Auth::acquire_new_token(
                            config,
                            oradaz_client,
                            tenant.to_string(),
                            service.name.clone(),
                            app_id.to_string(),
                            service.scopes.clone(),
                        )
                        .await
                        {
                            Ok(token) => break Ok(token),
                            Err(err) if attempt < max_attempts => {
                                let backoff = 2u64.saturating_pow(attempt - 1).min(8);
                                warn!(
                                    "{:FL$}Managed-identity token acquisition for service {:?} failed (attempt {}/{}): {} — retrying in {}s",
                                    "Tokens", &service.name, attempt, max_attempts, err, backoff
                                );
                                tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
                            }
                            Err(err) => break Err(err),
                        }
                    };
                    match acquired {
                        Err(err) => {
                            warn!(
                                "{:FL$}Authentication error while acquiring client credentials token for service {:?}: {}",
                                "Tokens", &service.name, err
                            );
                            auth_errors.push(AuthError {
                                api: service.name.clone(),
                                error: err.to_string(),
                            });
                            if service.mandatory_auth {
                                return Err(err);
                            }
                        }
                        Ok(token) => {
                            tokens.insert(
                                Arc::from(service.name.as_str()),
                                Arc::new(TokenState::new(token)),
                            );
                        }
                    }
                }
            }

            debug!(
                "{:FL$}Token initialization complete: {} token(s) acquired, {} service(s) with errors",
                "Tokens",
                tokens.len(),
                auth_errors.len()
            );
            if !auth_errors.is_empty() {
                let mut multiline_string: String = String::new();
                for error in auth_errors {
                    match serde_json::to_string(&error) {
                        Err(err) => {
                            error!("{:FL$}Could not convert auth_errors to json", "Tokens");
                            debug!(
                                "{:FL$}Auth errors JSON serialization error: {:?}",
                                "Tokens", err
                            );
                            return Err(Error::AuthErrorsToJSON);
                        }
                        Ok(j) => multiline_string = format!("{multiline_string}{j}\n"),
                    };
                }
                writer
                    .write_file(
                        String::new(),
                        "auth_errors.json".to_string(),
                        multiline_string,
                    )
                    .await?;
            }
            return Ok(tokens);
        }

        debug!("{:FL$}Acquiring token for service graph.", "Tokens",);
        let initial_token: Token = match Auth::acquire_new_token(
            config,
            oradaz_client,
            tenant.to_string(),
            String::from("graph"),
            app_id.to_string(),
            vec![
                String::from("https://graph.microsoft.com/.default"),
                String::from("offline_access"),
            ],
        )
        .await
        {
            Err(err) => {
                warn!(
                    "{:FL$}Authentication error while acquiring token for service graph: {}",
                    "Tokens", err
                );
                auth_errors.push(AuthError {
                    api: String::from("graph"),
                    error: err.to_string(),
                });
                return Err(Error::TokenAcquisitionError);
            }
            Ok(token) => token,
        };

        for service in &schema.services {
            if service.mandatory_auth || Config::service_enable(config, &service.name) {
                debug!(
                    "{:FL$}Acquiring new token for service {:?} based on graph token.",
                    "Tokens", &service.name
                );
                match initial_token
                    .refresh_for_scope(
                        config,
                        oradaz_client,
                        tenant.to_string(),
                        service.name.clone(),
                        app_id.to_string(),
                        service.scopes.clone(),
                    )
                    .await
                {
                    Err(err) => {
                        warn!(
                            "{:FL$}Authentication error while refreshing token for service {:?}: {}",
                            "Tokens", &service.name, err
                        );
                        auth_errors.push(AuthError {
                            api: service.name.clone(),
                            error: err.to_string(),
                        });
                        if service.mandatory_auth {
                            return Err(Error::TokenAcquisitionError);
                        }
                    }
                    Ok(token) => {
                        tokens.insert(
                            Arc::from(service.name.as_str()),
                            Arc::new(TokenState::new(token)),
                        );
                    }
                };
            }
        }

        debug!(
            "{:FL$}Token initialization complete: {} token(s) acquired, {} service(s) with errors",
            "Tokens",
            tokens.len(),
            auth_errors.len()
        );
        if !auth_errors.is_empty() {
            let mut multiline_string: String = String::new();
            for error in auth_errors {
                match serde_json::to_string(&error) {
                    Err(err) => {
                        error!("{:FL$}Could not convert auth_errors to json", "Tokens");
                        debug!(
                            "{:FL$}Auth errors JSON serialization error: {:?}",
                            "Tokens", err
                        );

                        return Err(Error::AuthErrorsToJSON);
                    }
                    Ok(j) => multiline_string = format!("{multiline_string}{j}\n"),
                };
            }
            writer
                .write_file(
                    String::new(),
                    "auth_errors.json".to_string(),
                    multiline_string,
                )
                .await?;
        }
        Ok(tokens)
    }
}
