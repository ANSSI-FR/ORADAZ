use crate::config::Config;
use crate::errors::Error;
use crate::Cli;

use reqwest::blocking::Client;
use reqwest::{Proxy, Url};

use log::{error, info};

const FL: usize = crate::FL;
static APP_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

#[derive(Clone)]
pub struct Requests {
    pub client: Client,
}

impl Requests {
    pub fn new(config: &Config, cli: &Cli) -> Result<Self, Error> {
        /*
        Initialize Requests structure with client corresponding to config / cli options
        */
        let mut proxy_username = "";
        let mut proxy_password = "";
        let proxy = match cli.proxy.as_deref() {
            // Proxy defined in cli arguments
            Some(p) => {
                if let Some(u) = cli.proxy_username.as_deref() {
                    proxy_username = u;
                };
                if let Some(p) = cli.proxy_password.as_deref() {
                    proxy_password = p;
                };
                p
            }
            None => {
                match &config.proxy {
                    // Proxy defined in config file
                    Some(p) => {
                        if let Some(u) = &p.username {
                            proxy_username = u
                        };
                        if let Some(p) = &p.password {
                            proxy_password = p
                        };
                        &p.url
                    }
                    // No proxy
                    None => "",
                }
            }
        };

        let client: Client = match proxy.trim().is_empty() {
            false => {
                let url = match Url::parse(proxy) {
                    Ok(u) => u,
                    Err(err) => {
                        error!("{:FL$}Invalid proxy URL", "Requests");
                        error!("{}", err);
                        return Err(Error::InvalidProxyURL);
                    }
                };
                let prox: Proxy = match Proxy::all(url) {
                    Ok(p) => {
                        if !proxy_username.trim().is_empty() && !proxy_password.trim().is_empty() {
                            info!(
                                "{:FL$}Using proxy at url {} with Basic authentication",
                                "Requests", proxy
                            );
                            p.basic_auth(proxy_username, proxy_password)
                        } else {
                            info!(
                                "{:FL$}Using proxy at url {} without authentication",
                                "Requests", proxy
                            );
                            p
                        }
                    }
                    Err(err) => {
                        error!("{:FL$}Error while creating proxy", "Requests");
                        error!("{}", err);
                        return Err(Error::ProxyCreation);
                    }
                };
                let c: Client = match Client::builder()
                    .user_agent(APP_USER_AGENT)
                    .proxy(prox)
                    .build()
                {
                    Ok(cl) => cl,
                    Err(err) => {
                        error!("{:FL$}Could not create client with a proxy", "Requests");
                        error!("{}", err);
                        return Err(Error::CannotCreateClient);
                    }
                };
                c
            }
            true => {
                let c: Client = match Client::builder().user_agent(APP_USER_AGENT).build() {
                    Ok(cl) => cl,
                    Err(err) => {
                        error!("{:FL$}Could not create client with no proxy", "Requests");
                        error!("{}", err);
                        return Err(Error::CannotCreateClient);
                    }
                };
                c
            }
        };

        Ok(Self { client })
    }
}
