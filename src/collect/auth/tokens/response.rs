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
