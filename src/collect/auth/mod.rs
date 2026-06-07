/// Module to manage authentication features.
pub mod flows;
pub mod tokens;

use crate::FL;
use crate::collect::auth::flows::authorization_code::AuthorizationCodeAuth;
use crate::collect::auth::flows::client_credentials::ClientCredentialsAuth;
use crate::collect::auth::flows::device_code::DeviceCodeAuth;
use crate::collect::auth::tokens::Token;
use crate::utils::client::OradazClient;
use crate::utils::config::Config;
use crate::utils::errors::Error;

use log::debug;
use serde::Serialize;

/// Represents an error encountered during the authentication process for a specific API.
#[derive(Debug, Serialize)]
pub struct AuthError {
    /// The API that failed to authenticate.
    pub api: String,
    /// The error message describing the failure.
    pub error: String,
}

/// Utility for managing authentication tokens.
pub struct Auth {}

impl Auth {
    /// Acquires a new authentication token for a given service.
    ///
    /// Depending on the configuration, it will use either the Device Code flow
    /// or the Authorization Code flow to obtain the token.
    pub async fn acquire_new_token(
        config: &Config,
        oradaz_client: &OradazClient,
        tenant: String,
        service: String,
        client_id: String,
        scopes: Vec<String>,
    ) -> Result<Token, Error> {
        if Config::use_application_credentials_auth(config) {
            debug!(
                "{:FL$}Using client credentials flow for service {:?}",
                "Auth", service
            );
            ClientCredentialsAuth::get_token(
                config,
                oradaz_client,
                tenant,
                service,
                client_id,
                scopes,
            )
            .await
        } else if Config::force_device_code_auth(config) {
            debug!(
                "{:FL$}Using device code flow for service {:?}",
                "Auth", service
            );
            DeviceCodeAuth::get_token(oradaz_client, tenant, service, client_id, scopes).await
        } else {
            debug!(
                "{:FL$}Using authorization code flow for service {:?}",
                "Auth", service
            );
            AuthorizationCodeAuth::get_token(
                config,
                oradaz_client,
                tenant,
                service,
                client_id,
                scopes,
            )
            .await
        }
    }
}
