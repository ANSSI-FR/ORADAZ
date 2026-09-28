mod common;

use crate::common::default_test_config;
use oradaz::collect::auth::flows::device_code::DeviceCodeAuth;
use oradaz::collect::auth::tokens::{Token, Tokens};
use oradaz::utils::client::OradazClient;
use oradaz::utils::config::{Config, ProxyConfig};
use oradaz::utils::errors::{Error, FatalPresentation};
use oradaz::utils::schema::Schema;
use oradaz::utils::writer::actor::spawn_writer_task;
use serde_json::Value;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::timeout;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const TRANSPORT_CAUSE: &str =
    "device code creation transport error: connection failed (DNS, TCP, TLS or proxy)";

async fn spawn_connect_refusing_proxy() -> (String, JoinHandle<String>) {
    spawn_connect_proxy(false).await
}

async fn spawn_connect_proxy(stall: bool) -> (String, JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local HTTP proxy");
    let address = listener.local_addr().expect("local HTTP proxy address");
    let task = tokio::spawn(async move {
        timeout(TEST_TIMEOUT, async move {
            let (mut stream, _) = listener.accept().await.expect("accept proxy connection");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];

            loop {
                let bytes_read = stream
                    .read(&mut buffer)
                    .await
                    .expect("read CONNECT request");
                assert!(
                    bytes_read > 0,
                    "proxy connection closed before HTTP headers"
                );
                request.extend_from_slice(&buffer[..bytes_read]);
                assert!(
                    request.len() <= 16 * 1024,
                    "CONNECT headers are unexpectedly large"
                );
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }

            if stall {
                let mut byte = [0_u8; 1];
                let _ = stream.read(&mut byte).await;
            } else {
                stream
                    .write_all(
                        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .expect("write proxy rejection");
                stream.shutdown().await.expect("close proxy connection");
            }

            String::from_utf8(request).expect("CONNECT request is valid UTF-8")
        })
        .await
        .expect("local proxy interaction timed out")
    });

    (format!("http://{address}"), task)
}

fn device_code_config(proxy_url: String) -> Config {
    let mut config = default_test_config();
    config.use_device_code = Some(true);
    config.output_files = Some(true);
    config.output_mla = Some(false);
    config.proxy = Some(ProxyConfig {
        url: proxy_url,
        username: None,
        password: None,
    });
    config.http_timeout_seconds = Some(3);
    config.http_connect_timeout_seconds = Some(3);
    config
}

fn empty_schema() -> Schema {
    Schema {
        oradaz_version: oradaz::VERSION.to_string(),
        schema_hash: "integration-test-schema".to_string(),
        schema_version: "integration-test".to_string(),
        services: Vec::new(),
    }
}

fn expired_graph_token() -> Token {
    Token {
        tenant_id: "test-tenant".to_string(),
        client_id: "test-app-id".to_string(),
        service: "graph".to_string(),
        expires_on: 0,
        access_token: "expired-access-token".to_string(),
        refresh_token: None,
        token_type: "Bearer".to_string(),
        user_id: "test-user-id".to_string(),
        user_principal_name: "user@example.test".to_string(),
        scopes: vec![
            "https://graph.microsoft.com/.default".to_string(),
            "offline_access".to_string(),
        ],
    }
}

async fn assert_device_code_connect(proxy_task: JoinHandle<String>) {
    let request = timeout(TEST_TIMEOUT, proxy_task)
        .await
        .expect("local proxy task timed out")
        .expect("local proxy task panicked");
    assert!(
        request.starts_with("CONNECT login.microsoftonline.com:443 HTTP/1.1\r\n"),
        "authentication must reach only the local proxy as an HTTPS CONNECT request: {request:?}"
    );
}

async fn assert_transport_error_categories(refresh: bool) {
    for (stall, category) in [
        (false, "connection failed (DNS, TCP, TLS or proxy)"),
        (true, "request timed out"),
    ] {
        let (proxy_url, proxy_task) = spawn_connect_proxy(stall).await;
        let mut config = device_code_config(proxy_url);
        config.http_timeout_seconds = Some(1);
        config.http_connect_timeout_seconds = Some(1);
        let client = OradazClient::new(&config).expect("create proxied client");
        let mut token = expired_graph_token();
        token.tenant_id = "TENANT_URL_SENTINEL".to_string();
        token.refresh_token = Some("REFRESH_SENTINEL".to_string());
        let result = timeout(TEST_TIMEOUT, async {
            if refresh {
                token
                    .refresh_for_scope(
                        &config,
                        &client,
                        token.tenant_id.clone(),
                        token.service.clone(),
                        token.client_id.clone(),
                        token.scopes.clone(),
                    )
                    .await
            } else {
                DeviceCodeAuth::get_token(
                    &client,
                    token.tenant_id.clone(),
                    token.service.clone(),
                    token.client_id.clone(),
                    token.scopes.clone(),
                )
                .await
            }
        })
        .await
        .expect("authentication transport test timed out");
        assert_device_code_connect(proxy_task).await;
        let error = result.expect_err("local proxy must prevent authentication");
        let message = error.to_string();
        assert!(
            message.contains(category),
            "missing transport category: {message}"
        );
        assert!(message.contains(if refresh {
            "token refresh"
        } else {
            "device code creation"
        }));
        assert!(!message.contains("TENANT_URL_SENTINEL"));
        assert!(!message.contains("REFRESH_SENTINEL"));
        assert!(!message.contains("login.microsoftonline.com"));
    }
}

#[tokio::test]
async fn device_code_transport_errors_distinguish_timeout_from_connection_failure() {
    assert_transport_error_categories(false).await;
}

#[tokio::test]
async fn refresh_transport_errors_distinguish_timeout_from_connection_failure() {
    assert_transport_error_categories(true).await;
}

#[tokio::test]
async fn initial_device_code_transport_error_reaches_fatal_context_and_auth_errors_jsonl() {
    let temp_dir = TempDir::new().expect("create temporary output directory");
    let collection_name = "auth-diagnostics";
    let (proxy_url, proxy_task) = spawn_connect_refusing_proxy().await;
    let config = device_code_config(proxy_url);
    let client = OradazClient::new(&config).expect("create proxied client");
    let (writer, writer_task) = spawn_writer_task(
        config.clone(),
        temp_dir.path().to_path_buf(),
        collection_name.to_string(),
    )
    .await
    .expect("start file writer");

    let result = timeout(
        TEST_TIMEOUT,
        Tokens::initialize(
            &config,
            &client,
            "test-tenant",
            "test-app-id",
            &empty_schema(),
            &writer,
        ),
    )
    .await
    .expect("token initialization timed out");
    assert_device_code_connect(proxy_task).await;
    timeout(TEST_TIMEOUT, writer.finalize())
        .await
        .expect("writer finalization timed out")
        .expect("finalize file writer");
    drop(writer);
    timeout(TEST_TIMEOUT, writer_task)
        .await
        .expect("writer task join timed out")
        .expect("writer task panicked");

    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("initial device-code authentication must fail through the proxy"),
    };
    let fatal_context = error.context();

    let jsonl_path = temp_dir
        .path()
        .join(collection_name)
        .join("auth_errors.json");
    let jsonl = std::fs::read_to_string(&jsonl_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", jsonl_path.display()));
    let entries: Vec<Value> = jsonl
        .lines()
        .map(|line| serde_json::from_str(line).expect("valid AuthError JSON line"))
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "one Graph authentication error is persisted"
    );
    assert_eq!(entries[0]["api"], "graph");
    let persisted_cause = entries[0]["error"]
        .as_str()
        .expect("AuthError.error is a string");
    assert_eq!(persisted_cause, TRANSPORT_CAUSE);

    let fatal_context = fatal_context.expect("fatal authentication error must expose its cause");
    assert!(
        fatal_context.contains("service graph"),
        "fatal context must identify the Graph bootstrap service: {fatal_context:?}"
    );
    assert!(
        fatal_context.contains(TRANSPORT_CAUSE),
        "fatal context must preserve the device-code transport cause: {fatal_context:?}"
    );
    assert!(
        fatal_context.contains(persisted_cause),
        "fatal context and JSONL must carry the same transport cause"
    );
}

#[tokio::test]
async fn device_code_renew_transport_error_stays_reprocess_none() {
    let (proxy_url, proxy_task) = spawn_connect_refusing_proxy().await;
    let config = device_code_config(proxy_url);
    let client = OradazClient::new(&config).expect("create proxied client");
    let mut token = expired_graph_token();

    let result = timeout(TEST_TIMEOUT, token.renew(&config, &client))
        .await
        .expect("token renewal timed out");
    assert_device_code_connect(proxy_task).await;

    assert!(
        matches!(&result, Err(Error::Reprocess(None))),
        "device-code transport failure must remain transient Reprocess(None), got {result:?}"
    );
}
