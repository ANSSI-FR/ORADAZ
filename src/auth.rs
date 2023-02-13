use crate::config;
use crate::errors::Error;

use ansi_term::Colour::{Red, White};
use chrono::Utc;
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{thread, time};


const FL: usize = crate::FL;

#[derive(Clone, Deserialize)]
pub struct PartialAccessToken {
    #[serde(default)]
    pub oid: String,
    #[serde(default)]
    pub name: String,
}

#[derive(Deserialize)]
struct TenantDiscoveryResponse {
    authorization_endpoint: String,
    token_endpoint: String,
}

#[derive(Clone, Deserialize)]
pub struct DeviceCodeFlow {
    pub user_code: String,
    pub device_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: u64,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TokenResponseV1 {
    pub expires_in: Option<String>,
    pub ext_expires_in: Option<String>,
    pub expires_on: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,

    // Error
    pub error: Option<String>,
    pub error_description: Option<String>,
    pub error_codes: Option<Vec<usize>>,
    pub timestamp: Option<String>,
    pub trace_id: Option<String>,
    pub correlation_id: Option<String>,
    pub oradaz_error: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TokenResponse {
    pub expires_in: Option<u64>,
    pub ext_expires_in: Option<u64>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    
    // Custom fields
    #[serde(default)]
    pub expires_on: i64,
    #[serde(default)]
    pub api: String,
    #[serde(default)]
    pub oid: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub authority_url: String,
    #[serde(default)]
    pub scopes: String,
    #[serde(default)]
    pub client_id: String,

    // Error
    pub error: Option<String>,
    pub error_description: Option<String>,
    pub error_codes: Option<Vec<usize>>,
    pub timestamp: Option<String>,
    pub trace_id: Option<String>,
    pub correlation_id: Option<String>,
    pub oradaz_error: Option<String>,
}

impl TokenResponse {
    pub fn refresh_token(&mut self, client: &reqwest::blocking::Client) -> Result<(), Error> {
        match &self.refresh_token {
            Some(r) => {
                info!("{:FL$}Refreshing token for api {}", "refresh_token", self.api);
                let params: Vec<(&str, &str)> = vec![
                    ("client_id", &self.client_id),
                    ("grant_type", "refresh_token"),
                    ("scope", &self.scopes),
                    ("refresh_token", r)
                ];
    
                let authority = match Authority::new(&self.authority_url, client) {
                    Ok(a) => a,
                    Err(_e) => return Err(Error::InvalidAuthorityUrlError)
                };
    
                let response = http_post(&authority.token_endpoint, &params, client).unwrap();
    
                let mut json_response: TokenResponse = response.json().unwrap();

                match json_response.error.as_deref() {
                    None => {
                        let expires_on: i64 = match json_response.expires_in {
                            Some(t) => Utc::now().timestamp() + t as i64,
                            _ => {
                                error!("{:FL$}Error while trying to refresh token for api {}", "refresh_token", self.api);
                                json_response.oradaz_error = Some(String::from("CannotRefreshTokenError"));
                                let j = match serde_json::to_string(&json_response) {
                                    Err(_e) =>  {
                                        return Err(Error::CannotRefreshTokenError);
                                    },
                                    Ok(j) => j
                                };
                                return Err(Error::StringError(j));
                            }
                        };
                        self.expires_on = expires_on;
                        self.access_token = json_response.access_token;
                        self.refresh_token = json_response.refresh_token;
                        self.expires_in = json_response.expires_in;
                        self.ext_expires_in = json_response.ext_expires_in;
                        self.id_token = json_response.id_token;
                    },
                    _ => {
                        error!("{:FL$}Error while trying to refresh token for api {}", "refresh_token", self.api);
                        json_response.oradaz_error = Some(String::from("CannotRefreshTokenError"));
                        let j = match serde_json::to_string(&json_response) {
                            Err(_e) =>  {
                                return Err(Error::CannotRefreshTokenError);
                            },
                            Ok(j) => j
                        };
                        return Err(Error::StringError(j));
                    },
                }
            },
            None => {
                error!("{:FL$}Error while trying to refresh token for api {}: no refresh token", "refresh_token", self.api);
                return Err(Error::MissingRefreshTokenError)
            }
        };
        Ok(())
    }

    pub fn refresh_token_for_resource(&mut self, resource: &str, client: &reqwest::blocking::Client) -> Result<(), Error> {
        match &self.refresh_token {
            Some(r) => {
                let params: Vec<(&str, &str)> = vec![
                    ("client_id", &self.client_id),
                    ("grant_type", "refresh_token"),
                    ("scope", &self.scopes),
                    ("refresh_token", r),
                    ("resource", resource)
                ];
    
                let authority = match AuthorityV1::new(&self.authority_url, client) {
                    Ok(a) => a,
                    Err(_e) => return Err(Error::InvalidAuthorityUrlError)
                };
    
                let response = http_post(&authority.token_endpoint, &params, client).unwrap();
    
                let mut json_response: TokenResponseV1 = response.json().unwrap();

                match json_response.error.as_deref() {
                    None => {
                        self.expires_on = match &json_response.expires_on {
                            Some(t) => match t.parse() {
                                Ok(e) => e,
                                _ => {
                                    error!("{:FL$}Error while trying to refresh token for api {}", "refresh_token_for_resource", self.api);
                                    json_response.oradaz_error = Some(String::from("CannotRefreshTokenError"));
                                    let j = match serde_json::to_string(&json_response) {
                                        Err(_e) =>  {
                                            return Err(Error::CannotRefreshTokenError);
                                        },
                                        Ok(j) => j
                                    };
                                    return Err(Error::StringError(j));
                                }
                            },
                            _ => {
                                error!("{:FL$}Error while trying to refresh token for api {}", "refresh_token_for_resource", self.api);
                                json_response.oradaz_error = Some(String::from("CannotRefreshTokenError"));
                                let j = match serde_json::to_string(&json_response) {
                                    Err(_e) =>  {
                                        return Err(Error::CannotRefreshTokenError);
                                    },
                                    Ok(j) => j
                                };
                                return Err(Error::StringError(j));
                            }
                        };
                        self.access_token = json_response.access_token;
                        self.refresh_token = json_response.refresh_token;
                        self.id_token = json_response.id_token;
                    },
                    _ => {
                        error!("{:FL$}Error while trying to refresh token for api {}", "refresh_token_for_resource", self.api);
                        json_response.oradaz_error = Some(String::from("CannotRefreshTokenError"));
                        let j = match serde_json::to_string(&json_response) {
                            Err(_e) =>  {
                                return Err(Error::CannotRefreshTokenError);
                            },
                            Ok(j) => j
                        };
                        return Err(Error::StringError(j));
                    },
                }
            },
            None => {
                error!("{:FL$}Error while trying to refresh token for api {}: no refresh token", "refresh_token_for_resource", self.api);
                return Err(Error::MissingRefreshTokenError)
            }
        };
        Ok(())
    }
}

pub struct Authority {
    pub authority_url: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub device_code_endpoint: String,
}

impl Authority {
    pub fn new(authority_url: &str, client: &reqwest::blocking::Client) -> Result<Self, Error> {
        let tenant_discovery_response = match Self::tenant_discovery(authority_url, client){
            Ok(t) => t,
            Err(e) => {
                error!("{:FL$}Invalid tenant id provided", "tenant_discovery");
                return Err(e)
            }
        };

        Ok(Authority {
            authority_url: authority_url.to_string(),
            authorization_endpoint: tenant_discovery_response.authorization_endpoint,
            token_endpoint: tenant_discovery_response.token_endpoint.clone(),
            device_code_endpoint: tenant_discovery_response
                .token_endpoint
                .replace("token", "devicecode"),
        })
    }

    fn tenant_discovery(authority_url: &str, client: &reqwest::blocking::Client) -> Result<TenantDiscoveryResponse, Error> {
        let response = http_get(&format!("{}/v2.0/.well-known/openid-configuration", authority_url), client);
        let response = response.unwrap();
        let response = match response.json::<TenantDiscoveryResponse>() {
            Err(_e) => return Err(Error::InvalidAuthorityUrlError),
            Ok(j) => j
        };
        Ok(response)
    }
}

pub struct AuthorityV1 {
    pub authority_url: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub device_code_endpoint: String,
}

impl AuthorityV1 {
    pub fn new(authority_url: &str, client: &reqwest::blocking::Client) -> Result<Self, Error> {
        let tenant_discovery_response = match Self::tenant_discovery(authority_url, client){
            Ok(t) => t,
            Err(e) => {
                error!("{:FL$}Invalid tenant id provided", "tenant_discovery");
                return Err(e)
            }
        };

        Ok(AuthorityV1 {
            authority_url: authority_url.to_string(),
            authorization_endpoint: tenant_discovery_response.authorization_endpoint,
            token_endpoint: tenant_discovery_response.token_endpoint.clone(),
            device_code_endpoint: tenant_discovery_response
                .token_endpoint
                .replace("token", "devicecode"),
        })
    }

    fn tenant_discovery(authority_url: &str, client: &reqwest::blocking::Client) -> Result<TenantDiscoveryResponse, Error> {
        let response = http_get(&format!("{}/.well-known/openid-configuration", authority_url), client);
        let response = response.unwrap();
        let response = match response.json::<TenantDiscoveryResponse>() {
            Err(_e) => return Err(Error::InvalidAuthorityUrlError),
            Ok(j) => j
        };
        Ok(response)
    }
}

pub struct PublicClientApplication {
    pub client_id: String,
    authority: Authority,
}

impl PublicClientApplication {
    pub fn new(client_id: &str, authority_url: &str, client: &reqwest::blocking::Client) -> Result<PublicClientApplication, Error> {
        let authority = match Authority::new(authority_url, client) {
            Ok(a) => a,
            Err(_e) => return Err(Error::InvalidAuthorityUrlError)
        };
        let client_id = String::from(client_id);
        Ok(PublicClientApplication {
            client_id,
            authority,
        })
    }
    
    pub fn initiate_device_flow(&self, scopes: &[&str], client: &reqwest::blocking::Client) -> Result<DeviceCodeFlow, Error> {
        let scopes: &str = &format!("{} openid offline_access", scopes.join(" "));
        let params: Vec<(&str, &str)> = vec![("client_id", &self.client_id), ("scope", scopes)];

        let device_code_flow = match http_post(&self.authority.device_code_endpoint, &params, client) {
            Err(_e) => {
                error!("{:FL$}Could not acquire device flow for scopes {}", "initiate_device_flow", &scopes);
                return Err(Error::CannotAcquireDeviceCodeFlowError)
            },
            Ok(flow) => {
                flow
            }
        };
        let flow = match device_code_flow.json::<DeviceCodeFlow>() {
            Err(_e) => {
                error!("{:FL$}Invalid application ID", "initiate_device_flow");
                return Err(Error::InvalidAppId)
            },
            Ok(flow) => {
                flow
            }
        };
        Ok(flow)
    }
    
    pub fn acquire_token_by_device_flow(&self, api: &str, authority_url: &str, scopes: &[&str], flow: &DeviceCodeFlow, client: &reqwest::blocking::Client) -> Result<TokenResponse, Error> {
        let scopes: &str = &format!("{} openid offline_access", scopes.join(" "));
        let params: Vec<(&str, &str)> = vec![
            ("client_id", &self.client_id),
            ("grant_type", "device_code"),
            ("device_code", &flow.device_code)
        ];

        let device_code_expiration = flow.expires_in + SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        loop {
            if device_code_expiration < SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() {
                error!("{:FL$}Device code flow authentication process expired", "acquire_token_by_device_flow");
                return Err(Error::ExpiredDeciveCodeError);
            }

            let response = http_post(&self.authority.token_endpoint, &params, client).unwrap();

            let mut json_response: TokenResponse = response.json().unwrap();

            match json_response.error.as_deref() {
                Some("authorization_pending") => (),
                None => {
                    let expires_on: i64 = match json_response.expires_in {
                        Some(t) => Utc::now().timestamp() + t as i64,
                        _ => {
                            error!("{:FL$}Error while trying to authenticate.", "acquire_token_by_device_flow");
                            json_response.oradaz_error = Some(String::from("DeviceCodeFlowAuthenticationError"));
                            let j = match serde_json::to_string(&json_response) {
                                Err(_e) =>  {
                                    return Err(Error::DeviceCodeFlowAuthenticationError);
                                },
                                Ok(j) => j
                            };
                            return Err(Error::StringError(j));
                        }
                    };
                    let access_token: &str = match &json_response.access_token {
                        Some(ref t) => t,
                        _ => {
                            error!("{:FL$}Error while trying to authenticate.", "acquire_token_by_device_flow");
                            json_response.oradaz_error = Some(String::from("DeviceCodeFlowAuthenticationError"));
                            let j = match serde_json::to_string(&json_response) {
                                Err(_e) =>  {
                                    return Err(Error::DeviceCodeFlowAuthenticationError);
                                },
                                Ok(j) => j
                            };
                            return Err(Error::StringError(j));
                        }
                    };
                    let parts: Vec<&str> = access_token.split('.').collect();
                    let bytes = base64::decode(parts[1]).unwrap();
                    let token = String::from_utf8_lossy(&bytes);
                    let j: PartialAccessToken = serde_json::from_str(&token).unwrap();
                    json_response.name = j.name;
                    json_response.oid = j.oid;
                    json_response.expires_on = expires_on;
                    json_response.api = api.to_string();
                    json_response.authority_url = authority_url.to_string();
                    json_response.scopes = scopes.to_string();
                    json_response.client_id = self.client_id.clone();
                    return Ok(json_response)
                },
                _ => {
                    error!("{:FL$}Error while trying to authenticate. Exception is the following: {}", "acquire_token_by_device_flow", json_response.error_description.unwrap());
                    return Err(Error::DeviceCodeFlowAuthenticationError);
                },
            }

            thread::sleep(time::Duration::from_secs(flow.interval))
        }
    }
}

fn http_get(url: &str, client: &reqwest::blocking::Client) -> Result<reqwest::blocking::Response, Error> {
    match client.get(url).send() {
        Ok(r) => Ok(r),
        Err(e) => {
            error!("{:FL$}Could not check prerequisites.", "http_get");
            error!("{:FL$}\t{}", "", e);
            return Err(Error::PrerequisitesCheckError);
        }
    }
}

fn http_post(url: &str, params: &[(&str, &str)], client: &reqwest::blocking::Client) -> Result<reqwest::blocking::Response, Error> {
    match client.post(url).form(&params).send() {
        Ok(r) => Ok(r),
        Err(e) => {
            error!("{:FL$}Could not check prerequisites.", "http_post");
            error!("{:FL$}\t{}", "", e);
            return Err(Error::PrerequisitesCheckError);
        }
    }
}

pub fn get_token(service: &config::Service, tenant: &str, app_id: &str, client: &reqwest::blocking::Client) -> Result<TokenResponse, Error> {
    let mut do_loop = true;
    let mut token:TokenResponse = Default::default();
    let description = format!(" / ! \\   INTERACTION REQUIRED!!!     |  {:40}", &service.description);
    println!("{}", White.on(Red).paint("  / \\                                |  Authentication for:                     "));
    println!("{}", White.on(Red).paint(description));
    println!("{}", White.on(Red).paint("/_____\\                              |  REST API                                "));
    while do_loop {
        let authority_url: &str = &format!("https://login.microsoftonline.com/{}", tenant);
        let mut api_client_id: &str = &service.client_id;
        if api_client_id.is_empty() {
            api_client_id = app_id;
        };
        let scope: &str = &format!("{}.default", service.base_url);
        let scopes: Vec<&str> = vec![scope];
        let pca = match PublicClientApplication::new(api_client_id, authority_url, client){
            Ok(p) => p,
            Err(e) => return Err(e)
        };
        let flow = match pca.initiate_device_flow(&scopes, client) {
            Err(e) => return Err(e),
            Ok(flow) => {
                println!("{}", flow.message);
                flow
            }
        };
        match pca.acquire_token_by_device_flow(&service.name, authority_url, &scopes, &flow, client) {
            Err(Error::ExpiredDeciveCodeError) => {
                info!("{:FL$}Performing a new authentication request for API {}", "get_token", &service.name);
            }
            Err(e) => {
                error!("{:FL$}Could not acquire token for API {}", "get_token", &service.name); 
                return Err(e)
            },
            Ok(token_value) => {
                token = token_value;
                do_loop = false;
            }
        };
    }
    if service.resource.is_empty() {
        Ok(token)
    } else {
        match token.refresh_token_for_resource(&service.resource, client) {
            Err(e) => {
                error!("{:FL$}Could not refresh token for API {} and resource {}", "get_token", &service.name, &service.resource); 
                Err(e)
            },
            Ok(()) => {
                Ok(token)
            }
        }
    }
}
