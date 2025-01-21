use crate::config::Config;
use crate::errors::Error;
use crate::schema::Schema;
use crate::writer::OradazWriter;

use ansi_term::Colour::{Red, White};
use azure_core::{auth::Secret, new_http_client};
use azure_identity::device_code_flow::{
    start, DeviceCodeAuthorization, DeviceCodeErrorResponse, DeviceCodePhaseOneResponse,
};
use azure_identity::refresh_token::exchange;
use base64::prelude::*;
use chrono::Utc;
use futures::StreamExt;
use log::{debug, error};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const FL: usize = crate::FL;

pub struct Auth {
    pub authorization: DeviceCodeAuthorization,
}

impl Auth {
    #[tokio::main]
    pub async fn new(
        tenant: &str,
        client_id: &str,
        scopes: &[String],
        description: &String,
    ) -> Result<Self, Error> {
        /*
        Perform Azure authentication by device code flow.
        */
        println!(
            "{}",
            White.on(Red).paint(
                "  / \\                                |  Authentication for                      "
            )
        );
        println!(
            "{}",
            White.on(Red).paint(format!(
                " / ! \\   INTERACTION REQUIRED!!!     |  {:40}",
                description
            ))
        );
        println!(
            "{}",
            White.on(Red).paint(
                "/_____\\                              |  REST API                                "
            )
        );
        let http_client = new_http_client();
        let scopes_str: Vec<&str> = scopes.iter().map(String::as_str).collect();
        let token: DeviceCodePhaseOneResponse =
            match start(http_client.clone(), tenant, client_id, &scopes_str).await {
                Ok(a) => a,
                Err(err) => {
                    error!("{:FL$}Error starting device code flow", "Auth");
                    debug!("{}", err);
                    return Err(Error::DeviceCodeFlowCreation);
                }
            };
        println!("{}\n", token.message());
        let authorization: DeviceCodeAuthorization = loop {
            match token.stream().next().await {
                Some(Ok(authorization)) => break authorization,
                Some(Err(err)) => {
                    if let Some(error_rsp) = err.downcast_ref::<DeviceCodeErrorResponse>() {
                        if error_rsp.error == "authorization_pending" {
                            continue;
                        }
                        error!(
                            "{:FL$}Error while logging: {}",
                            "Auth", error_rsp.error_description
                        );
                        debug!("{}", error_rsp.error);
                        return Err(Error::DeviceCodeFlowAuthentication);
                    }
                }
                None => {
                    error!("{:FL$}Device flow stream ended unexpectedly", "Auth");
                    return Err(Error::DeviceCodeFlowUnexpectedEnd);
                }
            }
        };

        Ok(Auth { authorization })
    }

    pub fn get_token(
        self,
        tenant: String,
        client_id: String,
        service: String,
    ) -> Result<Token, Error> {
        /*
        Parse Auth structure to obtain Token
        */
        let expires_on: i64 = Utc::now().timestamp() + self.authorization.expires_in as i64;
        let parts: Vec<&str> = self
            .authorization
            .access_token()
            .secret()
            .split('.')
            .collect();
        match BASE64_URL_SAFE_NO_PAD.decode(parts[1]) {
            Ok(bytes) => {
                let token_str = String::from_utf8_lossy(&bytes);
                let refresh_token: Option<Secret> = self.authorization.refresh_token().cloned();
                let access_token: Secret = self.authorization.access_token().clone();
                let token_type: String = self.authorization.token_type;
                match serde_json::from_str::<PartialAccessToken>(&token_str) {
                    Ok(j) => Ok(Token {
                        tenant_id: tenant,
                        client_id,
                        service,
                        access_token,
                        refresh_token,
                        token_type,
                        expires_on,
                        user_id: j.oid,
                        user_principal_name: j.name,
                    }),
                    Err(err) => {
                        error!(
                            "{:FL$}Error while parsing new access token for service {:?}",
                            "Auth", service
                        );
                        debug!("{}", err);
                        Err(Error::AccessTokenParsing)
                    }
                }
            }
            Err(err) => {
                error!(
                    "{:FL$}Error while decoding new access token for service {:?}",
                    "Auth", service
                );
                debug!("{}", err);
                Err(Error::AccessTokenParsing)
            }
        }
    }
}

#[derive(Serialize)]
pub struct AuthError {
    pub api: String,
    pub error: String,
}

#[derive(Clone)]
pub struct Token {
    pub tenant_id: String,
    pub client_id: String,
    pub service: String,
    pub expires_on: i64,
    pub access_token: Secret,
    pub refresh_token: Option<Secret>,
    pub token_type: String,
    pub user_id: String,
    pub user_principal_name: String,
}

impl Token {
    #[tokio::main]
    pub async fn refresh_token(token: Token) -> Result<Token, Error> {
        /*
        Refresh a token to obtain a new one
        */
        debug!(
            "{:FL$}Refreshing token for service {:?}",
            "Token", token.service
        );
        let http_client = new_http_client();
        let refresh_token: &Secret = match &token.refresh_token {
            Some(t) => t,
            None => {
                // If there is no refresh token, return with error indicating
                // to perform a new authentication
                return Err(Error::NewAuthRequired);
            }
        };
        match exchange(
            http_client,
            &token.tenant_id,
            &token.client_id,
            None,
            refresh_token,
        )
        .await
        {
            Err(err) => {
                error!(
                    "{:FL$}Error while refreshing token for service {:?}",
                    "Token", token.service
                );
                debug!("{}", err);
                // TODO: try to send real error depending on refresh error ?
                return Err(Error::NewAuthRequired);
            }
            Ok(t) => Ok(Token {
                tenant_id: token.tenant_id,
                client_id: token.client_id,
                service: token.service,
                expires_on: Utc::now().timestamp() + t.expires_in() as i64,
                access_token: t.access_token().clone(),
                refresh_token: Some(t.refresh_token().clone()),
                token_type: t.token_type().to_string(),
                user_id: token.user_id,
                user_principal_name: token.user_principal_name,
            }),
        }
    }
}

#[derive(Clone, Deserialize)]
pub struct PartialAccessToken {
    pub oid: String,
    pub name: String,
}

pub struct Tokens {}

impl Tokens {
    pub fn initialize(
        tenant: &str,
        app_id: &str,
        config: &Config,
        schema: &Schema,
        writer: &Arc<Mutex<OradazWriter>>,
    ) -> Result<HashMap<String, Token>, Error> {
        /*
        Get a token for each service enabled in config (or mandatory)
        */
        let mut tokens: HashMap<String, Token> = HashMap::new();
        let mut auth_errors: Vec<AuthError> = Vec::new();
        for service in &schema.services {
            if service.mandatory_auth || Config::service_enable(config, &service.name) {
                let client_id: &str = match &service.client_id {
                    Some(c) => c,
                    None => app_id, // Use provided appId if not defined in schema
                };
                match Auth::new(tenant, client_id, &service.scopes, &service.description) {
                    Err(err) => {
                        auth_errors.push(AuthError {
                            api: service.name.clone(),
                            error: err.to_string(),
                        });
                        if service.mandatory_auth {
                            // If service is mandatory, stop here as we could not obtain a valid token
                            return Err(err);
                        }
                    }
                    Ok(a) => {
                        match a.get_token(
                            tenant.to_string(),
                            client_id.to_string(),
                            service.name.clone(),
                        ) {
                            Ok(t) => {
                                tokens.insert(service.name.clone(), t);
                            }
                            Err(err) => {
                                auth_errors.push(AuthError {
                                    api: service.name.clone(),
                                    error: err.to_string(),
                                });
                                if service.mandatory_auth {
                                    // If service is mandatory, stop here as we could not obtain a valid token
                                    return Err(err);
                                }
                            }
                        };
                    }
                };
            }
        }

        // Write authentication errors to "auth_errors.json" file
        if !auth_errors.is_empty() {
            let mut multiline_string: String = String::new();
            for error in auth_errors {
                match serde_json::to_string(&error) {
                    Err(err) => {
                        error!("{:FL$}Could not convert auth_errors to json", "Tokens");
                        debug!("{}", err);
                        return Err(Error::AuthErrorsToJSON);
                    }
                    Ok(j) => multiline_string = format!("{}{}\n", multiline_string, j),
                };
            }
            match writer.lock() {
                Ok(mut w) => {
                    w.write_file(
                        String::new(),
                        "auth_errors.json".to_string(),
                        multiline_string,
                    )?;
                }
                Err(err) => {
                    error!(
                        "{:FL$}Error while locking Writer to write auth errors",
                        "Tokens"
                    );
                    debug!("{}", err);
                    return Err(Error::WriterLock);
                }
            }
        }
        Ok(tokens)
    }
}
