/// HTTP client configured from the application configuration file.
/// Supports direct (no proxy) and proxied connections with optional Basic authentication.
use crate::utils::config::Config;
use crate::utils::errors::Error;
use crate::{APP_USER_AGENT, FL};

use log::{debug, error};
use reqwest::Client;
use reqwest::{Proxy, Url};
use std::time::Duration;

#[derive(Clone)]
pub struct OradazClient {
    pub client: Client,
}

/// Hosts that must bypass any configured proxy: the link-local IMDS endpoint, the
/// loopback addresses, and (on App Service / Container Apps) the host of the
/// localhost `IDENTITY_ENDPOINT`. IMDS is only reachable directly.
fn imds_no_proxy() -> Option<reqwest::NoProxy> {
    let mut hosts = String::from("169.254.169.254,localhost,127.0.0.1");
    if let Ok(endpoint) = std::env::var("IDENTITY_ENDPOINT")
        && let Ok(parsed) = Url::parse(&endpoint)
        && let Some(host) = parsed.host_str()
    {
        hosts.push(',');
        hosts.push_str(host);
    }
    reqwest::NoProxy::from_string(&hosts)
}

impl OradazClient {
    pub fn new(config: &Config) -> Result<Self, Error> {
        let mut proxy_username = "";
        let mut proxy_password = "";
        let proxy = match &config.proxy {
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
        };
        let user_agent: &str = match &config.user_agent {
            Some(s) => s,
            None => APP_USER_AGENT,
        };

        let client: Client = match proxy.trim().is_empty() {
            false => {
                let url = match Url::parse(proxy) {
                    Ok(u) => u,
                    Err(err) => {
                        error!("{:FL$}Invalid proxy URL", "Requests");
                        debug!("{:FL$}URL parse error: {:?}", "Requests", err);
                        return Err(Error::InvalidProxyURL);
                    }
                };
                let prox: Proxy = match Proxy::all(url) {
                    Ok(p) => {
                        let p = if !proxy_username.trim().is_empty()
                            && !proxy_password.trim().is_empty()
                        {
                            debug!(
                                "{:FL$}Using proxy at url {:?} with Basic authentication",
                                "OradazClient", proxy
                            );
                            p.basic_auth(proxy_username, proxy_password)
                        } else {
                            debug!(
                                "{:FL$}Using proxy at url {:?} without authentication",
                                "OradazClient", proxy
                            );
                            p
                        };
                        // Never route the instance metadata service (IMDS) or the
                        // App Service localhost IDENTITY_ENDPOINT through the proxy:
                        // the link-local 169.254.169.254 and loopback endpoints are
                        // unreachable via any proxy, which would break managed
                        // identity behind a corporate proxy.
                        p.no_proxy(imds_no_proxy())
                    }
                    Err(err) => {
                        error!("{:FL$}Error while creating proxy", "OradazClient");
                        debug!("{:FL$}Proxy creation error: {:?}", "OradazClient", err);
                        return Err(Error::ProxyCreation);
                    }
                };
                let c: Client = match Client::builder()
                    .user_agent(user_agent)
                    .proxy(prox)
                    .timeout(Duration::from_secs(Config::http_timeout_seconds(config)))
                    .connect_timeout(Duration::from_secs(Config::http_connect_timeout_seconds(
                        config,
                    )))
                    .build()
                {
                    Ok(cl) => cl,
                    Err(err) => {
                        error!("{:FL$}Could not create client with a proxy", "OradazClient");
                        debug!(
                            "{:FL$}Client build error (with proxy): {:?}",
                            "OradazClient", err
                        );
                        return Err(Error::CannotCreateClient);
                    }
                };
                c
            }
            true => {
                let c: Client = match Client::builder()
                    .user_agent(user_agent)
                    .no_proxy()
                    .timeout(Duration::from_secs(Config::http_timeout_seconds(config)))
                    .connect_timeout(Duration::from_secs(Config::http_connect_timeout_seconds(
                        config,
                    )))
                    .build()
                {
                    Ok(cl) => cl,
                    Err(err) => {
                        error!(
                            "{:FL$}Could not create client with no proxy",
                            "OradazClient"
                        );
                        debug!(
                            "{:FL$}Client build error (no proxy): {:?}",
                            "OradazClient", err
                        );
                        return Err(Error::CannotCreateClient);
                    }
                };
                c
            }
        };

        Ok(Self { client })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::config::ProxyConfig;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn create_test_config() -> Config {
        Config {
            tenant: "test-tenant".to_string(),
            app_id: "test-app-id".to_string(),
            services: None,
            proxy: None,
            output_files: Some(false),
            output_mla: Some(false),
            output: None,
            no_check: None,
            use_device_code: None,
            listener_address: None,
            listener_port: None,
            schema_file: None,
            user_agent: Some("test-agent/1.0".to_string()),
            trace_logs: None,
            schema_url_override: None,
            use_application_credentials: None,
            application_credentials: None,
            concurrency_min_window: None,
            concurrency_max_window: None,
            dispatch_burst_cap: None,
            http_timeout_seconds: None,
            url_retry_limit: None,
            rate_limit_retry_limit: None,
            rate_limit_max_wait_secs: None,
            stall_detection_timeout: None,
            http_connect_timeout_seconds: None,
            retry_backoff_base_ms: None,
            retry_backoff_cap_ms: None,
            prereq_recheck_cache_secs: None,
            liveness_ceiling_secs: None,
            service_overrides: None,
            default_retry_after_seconds: None,
            emergency_accounts_custom_attributes: None,
            additional_mla_keys: None,
            shuffle_urls: None,
            concurrency_slow_start: None,
            response_workers_max: None,
            response_memory_budget_bytes: None,
            expected_error_breaker_threshold: None,
            logs_days_filter: None,
        }
    }

    fn create_test_config_with_proxy(proxy_url: &str) -> Config {
        Config {
            tenant: "test-tenant".to_string(),
            app_id: "test-app-id".to_string(),
            services: None,
            proxy: Some(ProxyConfig {
                url: proxy_url.to_string(),
                username: Some("proxyuser".to_string()),
                password: Some("proxypass".to_string()),
            }),
            output_files: Some(false),
            output_mla: Some(false),
            output: None,
            no_check: None,
            use_device_code: None,
            listener_address: None,
            listener_port: None,
            schema_file: None,
            user_agent: Some("test-agent/1.0".to_string()),
            trace_logs: None,
            schema_url_override: None,
            use_application_credentials: None,
            application_credentials: None,
            concurrency_min_window: None,
            concurrency_max_window: None,
            dispatch_burst_cap: None,
            http_timeout_seconds: None,
            url_retry_limit: None,
            rate_limit_retry_limit: None,
            rate_limit_max_wait_secs: None,
            stall_detection_timeout: None,
            http_connect_timeout_seconds: None,
            retry_backoff_base_ms: None,
            retry_backoff_cap_ms: None,
            prereq_recheck_cache_secs: None,
            liveness_ceiling_secs: None,
            service_overrides: None,
            default_retry_after_seconds: None,
            emergency_accounts_custom_attributes: None,
            additional_mla_keys: None,
            shuffle_urls: None,
            concurrency_slow_start: None,
            response_workers_max: None,
            response_memory_budget_bytes: None,
            expected_error_breaker_threshold: None,
            logs_days_filter: None,
        }
    }

    #[test]
    fn test_oradaz_client_creation_without_proxy() {
        let config = create_test_config();
        let client = OradazClient::new(&config).unwrap();

        // Client should be created successfully
        assert!(client.client.get("https://httpbin.org/get").build().is_ok());
    }

    #[test]
    fn test_oradaz_client_creation_with_invalid_proxy_url() {
        let config = create_test_config_with_proxy("invalid-url");
        let result = OradazClient::new(&config);

        assert!(result.is_err());
        // Should return InvalidProxyURL error
        match result {
            Err(Error::InvalidProxyURL) => (),
            _ => panic!("Expected InvalidProxyURL error"),
        }
    }

    #[tokio::test]
    async fn test_oradaz_client_with_mocked_http_request() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/test"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "success",
                "data": "test response"
            })))
            .mount(&mock_server)
            .await;

        let config = create_test_config();
        let client = OradazClient::new(&config).unwrap();

        // Make a request to the mock server
        let url = format!("{}/test", mock_server.uri());
        let response = client.client.get(&url).send().await.unwrap();

        assert_eq!(response.status(), 200);

        let json: serde_json::Value = response.json().await.unwrap();
        assert_eq!(json["status"], "success");
        assert_eq!(json["data"], "test response");
    }

    #[tokio::test]
    async fn test_oradaz_client_user_agent() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/user-agent"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "user_agent": "test-agent/1.0"
            })))
            .mount(&mock_server)
            .await;

        let config = create_test_config();
        let client = OradazClient::new(&config).unwrap();

        let url = format!("{}/user-agent", mock_server.uri());
        let response = client.client.get(&url).send().await.unwrap();

        assert_eq!(response.status(), 200);
    }

    #[test]
    fn test_oradaz_client_creation_with_default_user_agent() {
        let mut config = create_test_config();
        config.user_agent = None; // Use default

        let client = OradazClient::new(&config).unwrap();
        // Should use the default APP_USER_AGENT
        assert!(client.client.get("https://httpbin.org/get").build().is_ok());
    }
}
