mod common;

use crate::common::default_test_config;
use oradaz::collect::auth::flows::client_credentials::ClientCredentialsAuth;
use oradaz::utils::client::OradazClient;
use oradaz::utils::config::{ApplicationCredentials, ProxyConfig};
use oradaz::utils::errors::Error;

use wiremock::matchers::{header, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Serializes process-environment access across the tests of this binary.
/// `env::set_var`/`remove_var` are `unsafe` precisely because a concurrent
/// `env::var` read from another test thread (e.g. `OradazClient::new`'s IMDS
/// no-proxy lookup) races on the shared environ block. Every write — and every
/// read that can run concurrently with one — must hold this lock; a poisoned
/// lock is recovered since the guarded sections only touch the environment.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn lock_env() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

/// Serializes the managed-identity *env-detection* tests against each other.
/// `lock_env()` only guards the brief set/remove sections, but the detection
/// read happens later, inside `get_token`'s `.await`; two such tests running in
/// parallel can therefore stomp each other's IDENTITY_ENDPOINT / IDENTITY_HEADER
/// / IMDS_ENDPOINT mid-flight. A tokio mutex — legal to hold across `.await`,
/// unlike `ENV_LOCK` — gives each detection test an exclusive serial slot for its
/// whole body.
static MI_ENV_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn make_client() -> OradazClient {
    OradazClient::new(&default_test_config()).expect("Failed to create test OradazClient")
}

fn make_config_with_credentials(cred_type: &str, value: &str) -> oradaz::utils::config::Config {
    let mut config = default_test_config();
    config.use_application_credentials = Some(true);
    config.application_credentials = Some(ApplicationCredentials {
        credential_type: cred_type.to_string(),
        value: Some(value.to_string()),
    });
    config
}

fn make_mi_config(mi_client_id: Option<&str>) -> oradaz::utils::config::Config {
    let mut config = default_test_config();
    config.use_application_credentials = Some(true);
    config.application_credentials = Some(ApplicationCredentials {
        credential_type: "managedIdentity".to_string(),
        value: mi_client_id.map(|s| s.to_string()),
    });
    config
}

/// A minimal RSA PKCS#8 private key + self-signed certificate in PEM format.
/// Generated with: openssl req -x509 -newkey rsa:2048 -keyout - -out - -days 3650 -nodes -subj "/CN=test"
/// Used only for structural tests (never contacts a real endpoint).
const TEST_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDvuG0TcOyWa/4F
854a2+uhMO/7XgRhuwM7RxNHTtrA/waBAFHOJTAiFYvEK0U0FFYEKIm+ZmlNVunz
FH7UPxjlE42DtuzXxIz/jLdeqSzsOSXtdlK8MfSo18Pwm3aVVl+QdgN2bhGLeh8o
LtfKwi6mxlcKY+PeVBa3HZG7tERQOvBTjJpZv2I/i7grET+x4cSQ7Q2BN2WBrUDH
iWX1/xaxINJN02cE6ZjcdJRqXGwNvIV3+IUrjovuv9sK6xDmx/PNKLNoCGRSOzur
xokNaeitllbhEUfKOAiGv8bpA+MBUNkrieJRL1ktvP4a7zER1yIgo2bXOgGocfgz
qWoTu5AjAgMBAAECgf97mz78drL9VEmkESIO3rCa89O2GgYZewgmvM1GTZV+gidy
HWYep/iWxJmsaUM3jT9vqeEeWmnHwQ8zhaOvX7JZXXB7BQZRCXv+oqKSngJj9FYf
n5QcpDKC1RAKNOfQlGA0ZX5rtS+0PP0J/kStyrEVXzw5Nai3+TIvD47OgGWJvdK6
K24X5VT7UKbnVyqVBJ90esMXH098S8ri8nTJKJ1LCFA8BIjkKVEht05dWkQ44F0h
GenYGtuenuQj6Q2BbGsgXyVO8rOXUC3EBB0xq3UxaV8ZN48MabjBmkL2C7LupU/M
QqJzNSfDjpZ6UPXIMZftiNyB2ncQOKZ7nAPIo5ECgYEA+VgMWlQcLfS3sqZld0dm
cb6wlFonMmJRakcU1zQ5wSmYCniVMJ35rlFw5KemdbzZ9aLZaaEtAT4DIt2egndh
VcVpAq3cqZbYI9m6f4+cik7g8QfXLuD9nJCJC7ImvmAx9yUdu/Lziz4LiF6XZ+Wh
Uo9WhrA1PHIp6v1JxekD6TMCgYEA9h6c9/yaBZHZBrsQhjuhg1TrHhfZgVbYK+up
JKgYaXfSYJSweLjQssEZN48c2P+fL0eMvJuZeSo+t6fOj194ZK5tYua83T8UrBw6
ARSNZMMRzXYXfUIKtO3Kov4T9JqacP1tbhs0vuRqN5VPmEMjU2Mx4xp5OKMJdGcW
Xv+cHVECgYEAgB7xAf0UGb0UIxUDMB4dErdELoaAe5Ave2eY2te4EXwY5tB9AGU8
JYktdCB9FSR77o7GHlO2N1ww6lpsF2fWOOdeBQVnTDD5ULqQ7PjTG/JZ/R/lPu5X
Anr2IG9jHxF4uyB0Pd4hrFuuO103eShyE2UZtc2XHT8gMOIDZVFNNCcCgYEAnKGm
6/uKWfkT0UDDp2nTxC0K5L/w4GtQb8MuhfGkd5qV/HkkRe/4gYp6be1aQo+L0x8J
5g5wgbfs6hyVTJFJoWmQm9yUXYmDsnTURVO7GGE8tzFsiX66KaMbztc8A/NQTpA6
UFRoIQRkxLL1UMWJecwrN4jllLHNlpL0nci2pcECgYB4G9816G6cjyyr1/x0Z6Nn
+6474hj3nPYqzQ01U6kcoTO8KFv6ixP9yhF4slFR1WNYDG9N5tBUx2aOypo1HNxk
RI05xQ/ojKyyWNzxixMVlBhy//HmvQcmTo8mvCJyMbAu4nmdBkPM2CdTEZGZ6wt0
VoozUPGHy7TzYLDi9DCQ+A==
-----END PRIVATE KEY-----
";

const TEST_CERTIFICATE_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIC/zCCAeegAwIBAgIUdsVCMs/zqOHwjV7fXr4Ke2RY4Q4wDQYJKoZIhvcNAQEL
BQAwDzENMAsGA1UEAwwEdGVzdDAeFw0yNjA0MjgxNzUyNDVaFw0zNjA0MjUxNzUy
NDVaMA8xDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDvuG0TcOyWa/4F854a2+uhMO/7XgRhuwM7RxNHTtrA/waBAFHOJTAiFYvE
K0U0FFYEKIm+ZmlNVunzFH7UPxjlE42DtuzXxIz/jLdeqSzsOSXtdlK8MfSo18Pw
m3aVVl+QdgN2bhGLeh8oLtfKwi6mxlcKY+PeVBa3HZG7tERQOvBTjJpZv2I/i7gr
ET+x4cSQ7Q2BN2WBrUDHiWX1/xaxINJN02cE6ZjcdJRqXGwNvIV3+IUrjovuv9sK
6xDmx/PNKLNoCGRSOzurxokNaeitllbhEUfKOAiGv8bpA+MBUNkrieJRL1ktvP4a
7zER1yIgo2bXOgGocfgzqWoTu5AjAgMBAAGjUzBRMB0GA1UdDgQWBBTgvni0Zy6C
ieAPeezgzLH5rXSk9TAfBgNVHSMEGDAWgBTgvni0Zy6CieAPeezgzLH5rXSk9TAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBcw+5q+sObfD7jKCjf
YCoMIrzPDDF+AlpuM6xjWPQcMF9Buokq7wA3TbL3f3Wc5xzaNaY7g4YdrOAG70jh
n8f2pZ0a4Pbwis8sXIKAtycqW4AX4KW6KA3MRHP35KORSQcL9Odqec84fZSmdWn6
IlRQ1l2wYKme571m5htsjK7d5dPPkUBEJElMMTep1SlHNuA0TU1CbiwfnJ3/s7Uv
19H7pVIM286P6d+38DhvG7otQOot8rr1DKa7uGLesnaSOHyx0M2ZFWzvq6TguUQA
Tw2+2TqQ6TPiHzkRSNzl13wwQGq+ak4hEltWETEBZluM87Y6/ytUr66nvjTJ0PFb
lyHV
-----END CERTIFICATE-----
";

// ── get_token: config validation ─────────────────────────────────────────────

/// Missing `applicationCredentials` block in config → `InvalidApplicationCredentials`.
#[tokio::test]
async fn get_token_missing_credentials_returns_invalid_credentials() {
    let mut config = default_test_config();
    config.use_application_credentials = Some(true);
    // application_credentials is None
    let client = make_client();
    let result = ClientCredentialsAuth::get_token(
        &config,
        &client,
        "test-tenant".to_string(),
        "graph".to_string(),
        "test-app-id".to_string(),
        vec!["https://graph.microsoft.com/.default".to_string()],
    )
    .await;
    assert!(
        matches!(result, Err(Error::InvalidApplicationCredentials)),
        "Expected InvalidApplicationCredentials, got: {:?}",
        result
    );
}

/// Unknown credential type → `ClientCredentialsFlowCreation`.
#[tokio::test]
async fn get_token_unknown_type_returns_creation_error() {
    let config = make_config_with_credentials("foobar", "some-value");
    let client = make_client();
    let result = ClientCredentialsAuth::get_token(
        &config,
        &client,
        "test-tenant".to_string(),
        "graph".to_string(),
        "test-app-id".to_string(),
        vec!["https://graph.microsoft.com/.default".to_string()],
    )
    .await;
    assert!(
        matches!(result, Err(Error::ClientCredentialsFlowCreation(_))),
        "Expected ClientCredentialsFlowCreation, got: {:?}",
        result
    );
}

// ── get_token_certificate: PEM validation (no network required) ──────────────

/// PEM contains only a certificate (no private key block) → `ClientCredentialsFlowCreation`.
#[tokio::test]
async fn certificate_flow_cert_only_pem_returns_creation_error() {
    let config = make_config_with_credentials("certificate", TEST_CERTIFICATE_PEM);
    let client = make_client();
    let result = ClientCredentialsAuth::get_token(
        &config,
        &client,
        "test-tenant".to_string(),
        "graph".to_string(),
        "test-app-id".to_string(),
        vec!["https://graph.microsoft.com/.default".to_string()],
    )
    .await;
    assert!(
        matches!(result, Err(Error::ClientCredentialsFlowCreation(_))),
        "Expected ClientCredentialsFlowCreation (no private key in PEM), got: {:?}",
        result
    );
}

/// PEM has a private key block but it contains garbage (not a real RSA key)
/// → `ClientCredentialsFlowCreation`.
#[tokio::test]
async fn certificate_flow_invalid_key_returns_creation_error() {
    let garbage_pem = "-----BEGIN PRIVATE KEY-----\nnotvalidbase64!@#$\n-----END PRIVATE KEY-----\n\
                       -----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n";
    let config = make_config_with_credentials("certificate", garbage_pem);
    let client = make_client();
    let result = ClientCredentialsAuth::get_token(
        &config,
        &client,
        "test-tenant".to_string(),
        "graph".to_string(),
        "test-app-id".to_string(),
        vec!["https://graph.microsoft.com/.default".to_string()],
    )
    .await;
    assert!(
        matches!(result, Err(Error::ClientCredentialsFlowCreation(_))),
        "Expected ClientCredentialsFlowCreation (invalid RSA key), got: {:?}",
        result
    );
}

/// PEM carries an EC private key — unsupported, ORADAZ signs the assertion with
/// RS256 — so it must fail with a clear message naming EC/RS256, not an opaque
/// RSA parse error.
#[tokio::test]
async fn certificate_flow_ec_key_returns_clear_error() {
    let ec_pem = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIAAAAAAAAAAAAAAAAAAA\n-----END EC PRIVATE KEY-----\n\
                  -----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n";
    let config = make_config_with_credentials("certificate", ec_pem);
    let client = make_client();
    let result = ClientCredentialsAuth::get_token(
        &config,
        &client,
        "test-tenant".to_string(),
        "graph".to_string(),
        "test-app-id".to_string(),
        vec!["https://graph.microsoft.com/.default".to_string()],
    )
    .await;
    match result {
        Err(Error::ClientCredentialsFlowCreation(msg)) => {
            assert!(
                msg.contains("EC") && msg.contains("RS256"),
                "EC error should name EC and RS256, got: {msg}"
            );
        }
        other => {
            panic!("Expected a clear ClientCredentialsFlowCreation for an EC key, got: {other:?}")
        }
    }
}

/// Valid RSA key but no certificate block in PEM → `ClientCredentialsFlowCreation`
/// (thumbprint computation fails).
#[tokio::test]
async fn certificate_flow_key_only_no_cert_returns_creation_error() {
    let config = make_config_with_credentials("certificate", TEST_PRIVATE_KEY_PEM);
    let client = make_client();
    let result = ClientCredentialsAuth::get_token(
        &config,
        &client,
        "test-tenant".to_string(),
        "graph".to_string(),
        "test-app-id".to_string(),
        vec!["https://graph.microsoft.com/.default".to_string()],
    )
    .await;
    assert!(
        matches!(result, Err(Error::ClientCredentialsFlowCreation(_))),
        "Expected ClientCredentialsFlowCreation (no cert block for thumbprint), got: {:?}",
        result
    );
}

/// Valid RSA key + valid certificate → JWT assembly succeeds; the only
/// remaining failure is the network POST to the token endpoint.
/// We verify the error is `ClientCredentialsFlowAuthentication` (network
/// stage), not a creation-time error, which proves all pre-network
/// validation passed (key parsing, thumbprint computation, JWT signing).
///
/// Note: this test makes an outbound HTTPS request to
/// `login.microsoftonline.com` and expects a 4xx response since the
/// credentials are synthetic. Skip in air-gapped CI by setting
/// `ORADAZ_SKIP_NETWORK_TESTS=1`.
#[tokio::test]
async fn certificate_flow_valid_key_and_cert_fails_at_network_stage() {
    if std::env::var("ORADAZ_SKIP_NETWORK_TESTS").is_ok() {
        return;
    }

    let combined_pem = format!("{}{}", TEST_PRIVATE_KEY_PEM, TEST_CERTIFICATE_PEM);
    let config = make_config_with_credentials("certificate", &combined_pem);
    let client = make_client();
    let result = ClientCredentialsAuth::get_token(
        &config,
        &client,
        "test-tenant".to_string(),
        "graph".to_string(),
        "test-app-id".to_string(),
        vec!["https://graph.microsoft.com/.default".to_string()],
    )
    .await;

    // Pre-network validation (key parsing, thumbprint, JWT signing) must have passed.
    // The error we get back should be a network/auth stage error, not a creation error.
    assert!(
        !matches!(result, Err(Error::ClientCredentialsFlowCreation(_))),
        "Pre-network validation unexpectedly failed: {:?}",
        result
    );
}

// ── Managed Identity flow ─────────────────────────────────────────────────────

/// Fake JWT for IMDS responses: header.payload.sig where the payload encodes a
/// minimal set of claims (`oid`, `app_displayname`). `parse_identity_from_jwt`
/// will decode it and populate `user_id` and `user_principal_name`.
fn imds_test_jwt() -> String {
    // Payload: {"oid":"mi-oid","app_displayname":"test-mi"}
    // We encode inline so the test doesn't depend on an external base64 crate.
    let payload = oradaz_test_b64_url(br#"{"oid":"mi-oid","app_displayname":"test-mi"}"#);
    let header = oradaz_test_b64_url(br#"{"alg":"none"}"#);
    format!("{header}.{payload}.fakesig")
}

fn oradaz_test_b64_url(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 {
            chunk[1] as usize
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            chunk[2] as usize
        } else {
            0
        };
        out.push(ALPHABET[b0 >> 2] as char);
        out.push(ALPHABET[((b0 & 3) << 4) | (b1 >> 4)] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((b1 & 0xf) << 2) | (b2 >> 6)] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[b2 & 0x3f] as char);
        }
    }
    out
}

fn imds_success_body(expires_on: Option<&str>, expires_in: Option<u64>) -> serde_json::Value {
    let access_token = imds_test_jwt();
    let mut body = serde_json::json!({
        "access_token": access_token,
        "token_type": "Bearer"
    });
    if let Some(ts) = expires_on {
        body["expires_on"] = serde_json::json!(ts);
    }
    if let Some(secs) = expires_in {
        body["expires_in"] = serde_json::json!(secs);
    }
    body
}

/// System-assigned MI: IMDS returns 200, token is built with correct fields.
#[tokio::test]
async fn mi_system_assigned_success() {
    let server = MockServer::start().await;
    let far_future = chrono::Utc::now().timestamp() + 3600;
    Mock::given(method("GET"))
        .and(header("Metadata", "true"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(imds_success_body(Some(&far_future.to_string()), None)),
        )
        .mount(&server)
        .await;

    let client = make_client();
    let result = ClientCredentialsAuth::get_token_managed_identity(
        &client,
        "test-tenant".to_string(),
        "graph".to_string(),
        String::new(), // system-assigned: no client_id
        vec!["https://graph.microsoft.com/.default".to_string()],
        Some(&server.uri()),
    )
    .await;

    let token = result.expect("Expected Ok(Token) for system-assigned MI");
    assert_eq!(token.tenant_id, "test-tenant");
    assert_eq!(token.client_id, ""); // system-assigned has no explicit client_id
    assert_eq!(token.service, "graph");
    assert_eq!(token.expires_on, far_future);
    assert!(
        token.refresh_token.is_none(),
        "MI tokens have no refresh token"
    );
    assert_eq!(token.user_id, "mi-oid");
    assert_eq!(token.user_principal_name, "test-mi");
}

/// Managed identity must bypass a configured proxy when reaching IMDS: the
/// loopback metadata endpoint is not reachable through a proxy. With the proxy
/// pointing at a closed port, the IMDS call (on 127.0.0.1) must still succeed
/// thanks to the no_proxy exemption.
#[tokio::test]
async fn mi_bypasses_proxy_for_imds() {
    let server = MockServer::start().await;
    let far_future = chrono::Utc::now().timestamp() + 3600;
    Mock::given(method("GET"))
        .and(header("Metadata", "true"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(imds_success_body(Some(&far_future.to_string()), None)),
        )
        .mount(&server)
        .await;

    // A proxy pointing at a closed port: any request actually routed through it
    // would fail to connect.
    let mut config = default_test_config();
    config.proxy = Some(ProxyConfig {
        url: "http://127.0.0.1:1".to_string(),
        username: None,
        password: None,
    });
    // Client construction reads IDENTITY_ENDPOINT (IMDS no-proxy lookup): hold
    // the env lock so it cannot race the Arc-variant test's env writes.
    let client = {
        let _env = lock_env();
        OradazClient::new(&config).expect("client with proxy")
    };

    let result = ClientCredentialsAuth::get_token_managed_identity(
        &client,
        "test-tenant".to_string(),
        "graph".to_string(),
        String::new(),
        vec!["https://graph.microsoft.com/.default".to_string()],
        Some(&server.uri()),
    )
    .await;

    assert!(
        result.is_ok(),
        "IMDS must bypass the configured proxy and succeed: {result:?}"
    );
}

/// User-assigned MI: token is built with the provided client_id.
#[tokio::test]
async fn mi_user_assigned_success() {
    let server = MockServer::start().await;
    let far_future = chrono::Utc::now().timestamp() + 3600;
    Mock::given(method("GET"))
        .and(header("Metadata", "true"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(imds_success_body(Some(&far_future.to_string()), None)),
        )
        .mount(&server)
        .await;

    let client = make_client();
    let mi_id = "aabbccdd-0011-2233-4455-66778899aabb";
    let result = ClientCredentialsAuth::get_token_managed_identity(
        &client,
        "test-tenant".to_string(),
        "graph".to_string(),
        mi_id.to_string(),
        vec!["https://graph.microsoft.com/.default".to_string()],
        Some(&server.uri()),
    )
    .await;

    let token = result.expect("Expected Ok(Token) for user-assigned MI");
    assert_eq!(token.client_id, mi_id);
    assert!(token.refresh_token.is_none());
}

/// IMDS returns HTTP 500 → `ClientCredentialsFlowAuthentication`.
#[tokio::test]
async fn mi_imds_http_500_returns_auth_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let client = make_client();
    let result = ClientCredentialsAuth::get_token_managed_identity(
        &client,
        "test-tenant".to_string(),
        "graph".to_string(),
        String::new(),
        vec!["https://graph.microsoft.com/.default".to_string()],
        Some(&server.uri()),
    )
    .await;
    assert!(
        matches!(result, Err(Error::ClientCredentialsFlowAuthentication(_))),
        "Expected ClientCredentialsFlowAuthentication on HTTP 500, got: {:?}",
        result
    );
}

/// IMDS returns HTTP 400 → `ClientCredentialsFlowAuthentication`.
#[tokio::test]
async fn mi_imds_http_400_returns_auth_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(serde_json::json!({"error": "invalid_request"})),
        )
        .mount(&server)
        .await;

    let client = make_client();
    let result = ClientCredentialsAuth::get_token_managed_identity(
        &client,
        "test-tenant".to_string(),
        "resources".to_string(),
        String::new(),
        vec!["https://management.azure.com/.default".to_string()],
        Some(&server.uri()),
    )
    .await;
    assert!(
        matches!(result, Err(Error::ClientCredentialsFlowAuthentication(_))),
        "Expected ClientCredentialsFlowAuthentication on HTTP 400, got: {:?}",
        result
    );
}

/// Scopes contain only `offline_access` (no `/.default` scope) → `ClientCredentialsFlowCreation`.
#[tokio::test]
async fn mi_no_default_scope_returns_creation_error() {
    let client = make_client();
    let result = ClientCredentialsAuth::get_token_managed_identity(
        &client,
        "test-tenant".to_string(),
        "graph".to_string(),
        String::new(),
        vec!["offline_access".to_string()],
        None, // no mock needed — fails before any HTTP call
    )
    .await;
    assert!(
        matches!(result, Err(Error::ClientCredentialsFlowCreation(_))),
        "Expected ClientCredentialsFlowCreation for missing /.default scope, got: {:?}",
        result
    );
}

/// IMDS returns `expires_on` as a numeric string → timestamp parsed correctly.
#[tokio::test]
async fn mi_string_expires_on_parsed_correctly() {
    let server = MockServer::start().await;
    let expected_ts: i64 = 1_700_000_000;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(imds_success_body(Some(&expected_ts.to_string()), None)),
        )
        .mount(&server)
        .await;

    let client = make_client();
    let result = ClientCredentialsAuth::get_token_managed_identity(
        &client,
        "test-tenant".to_string(),
        "graph".to_string(),
        String::new(),
        vec!["https://graph.microsoft.com/.default".to_string()],
        Some(&server.uri()),
    )
    .await;
    let token = result.expect("Expected Ok(Token)");
    assert_eq!(token.expires_on, expected_ts);
}

/// IMDS returns only `expires_in` (string) → expiry is approximately `now + expires_in`.
#[tokio::test]
async fn mi_string_expires_in_fallback() {
    let server = MockServer::start().await;
    let secs: u64 = 3600;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(imds_success_body(None, Some(secs))))
        .mount(&server)
        .await;

    let before = chrono::Utc::now().timestamp();
    let client = make_client();
    let result = ClientCredentialsAuth::get_token_managed_identity(
        &client,
        "test-tenant".to_string(),
        "graph".to_string(),
        String::new(),
        vec!["https://graph.microsoft.com/.default".to_string()],
        Some(&server.uri()),
    )
    .await;
    let after = chrono::Utc::now().timestamp();
    let token = result.expect("Expected Ok(Token)");
    let expected_min = before + secs as i64;
    let expected_max = after + secs as i64;
    assert!(
        token.expires_on >= expected_min && token.expires_on <= expected_max,
        "expires_on={} not in [{}, {}]",
        token.expires_on,
        expected_min,
        expected_max
    );
}

/// Azure Arc variant (IMDS_ENDPOINT set) returns an unsupported error.
///
/// Uses a RAII guard to ensure the environment variable is removed even if
/// the test panics, preventing state leakage to other tests in the same process.
#[tokio::test]
async fn mi_arc_variant_returns_unsupported_error() {
    let _serial = MI_ENV_SERIAL.lock().await;
    struct EnvGuard(&'static str);
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            let _env = lock_env();
            unsafe { std::env::remove_var(self.0) };
        }
    }

    let _guard = EnvGuard("IMDS_ENDPOINT");
    {
        let _env = lock_env();
        unsafe { std::env::set_var("IMDS_ENDPOINT", "http://localhost:12345/imds") };
    }

    let client = make_client();
    let config = make_mi_config(None);
    let result = ClientCredentialsAuth::get_token(
        &config,
        &client,
        "test-tenant".to_string(),
        "graph".to_string(),
        String::new(),
        vec!["https://graph.microsoft.com/.default".to_string()],
    )
    .await;

    assert!(
        matches!(result, Err(Error::ClientCredentialsFlowCreation(_))),
        "Expected ClientCredentialsFlowCreation for Azure Arc variant, got: {:?}",
        result
    );
}

/// Inverse IMDS misconfiguration: IDENTITY_HEADER set without IDENTITY_ENDPOINT
/// (and no IMDS_ENDPOINT) must fail fast with a clear error naming the missing
/// endpoint, instead of silently falling through to the VM link-local Standard
/// variant and timing out.
#[tokio::test]
async fn mi_identity_header_without_endpoint_returns_clear_error() {
    let _serial = MI_ENV_SERIAL.lock().await;
    struct EnvGuard;
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            let _env = lock_env();
            unsafe { std::env::remove_var("IDENTITY_HEADER") };
        }
    }

    let _guard = EnvGuard;
    {
        let _env = lock_env();
        unsafe {
            std::env::remove_var("IDENTITY_ENDPOINT");
            std::env::remove_var("IMDS_ENDPOINT");
            std::env::set_var("IDENTITY_HEADER", "secret-header-value");
        }
    }

    let client = make_client();
    let config = make_mi_config(None);
    let result = ClientCredentialsAuth::get_token(
        &config,
        &client,
        "test-tenant".to_string(),
        "graph".to_string(),
        String::new(),
        vec!["https://graph.microsoft.com/.default".to_string()],
    )
    .await;

    match result {
        Err(Error::ClientCredentialsFlowCreation(msg)) => assert!(
            msg.contains("IDENTITY_ENDPOINT"),
            "error should name the missing IDENTITY_ENDPOINT, got: {msg}"
        ),
        other => panic!(
            "expected ClientCredentialsFlowCreation naming IDENTITY_ENDPOINT, got: {other:?}"
        ),
    }
}

/// Direct IMDS misconfiguration: IDENTITY_ENDPOINT set without IDENTITY_HEADER
/// (and no IMDS_ENDPOINT) must fail fast with a clear error naming the missing
/// header, instead of silently falling through to the VM link-local Standard
/// variant and timing out. Mirror of
/// `mi_identity_header_without_endpoint_returns_clear_error` for the opposite
/// guard; the `IMDS_ENDPOINT.is_err()` clause keeps a real Azure Arc environment
/// (which also sets IDENTITY_ENDPOINT) out of this App-Service-centric guard.
#[tokio::test]
async fn mi_identity_endpoint_without_header_returns_clear_error() {
    let _serial = MI_ENV_SERIAL.lock().await;
    struct EnvGuard;
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            let _env = lock_env();
            unsafe { std::env::remove_var("IDENTITY_ENDPOINT") };
        }
    }

    let _guard = EnvGuard;
    {
        let _env = lock_env();
        unsafe {
            std::env::remove_var("IDENTITY_HEADER");
            std::env::remove_var("IMDS_ENDPOINT");
            std::env::set_var("IDENTITY_ENDPOINT", "https://example.local/msi/token");
        }
    }

    let client = make_client();
    let config = make_mi_config(None);
    let result = ClientCredentialsAuth::get_token(
        &config,
        &client,
        "test-tenant".to_string(),
        "graph".to_string(),
        String::new(),
        vec!["https://graph.microsoft.com/.default".to_string()],
    )
    .await;

    match result {
        Err(Error::ClientCredentialsFlowCreation(msg)) => assert!(
            msg.contains("IDENTITY_HEADER is missing"),
            "error should name the missing IDENTITY_HEADER, got: {msg}"
        ),
        other => {
            panic!("expected ClientCredentialsFlowCreation naming IDENTITY_HEADER, got: {other:?}")
        }
    }
}

/// A *real* Azure Arc-enabled server sets IDENTITY_ENDPOINT + IMDS_ENDPOINT but
/// NOT IDENTITY_HEADER. It must reach the "Azure Arc not yet supported" error,
/// not be misdiagnosed as an App Service misconfiguration. Both are the same
/// `ClientCredentialsFlowCreation` variant, so this asserts on the message text,
/// not just the variant.
#[tokio::test]
async fn mi_real_arc_env_returns_arc_unsupported_not_appservice_misconfig() {
    let _serial = MI_ENV_SERIAL.lock().await;
    struct EnvGuard;
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            let _env = lock_env();
            unsafe {
                std::env::remove_var("IDENTITY_ENDPOINT");
                std::env::remove_var("IMDS_ENDPOINT");
            }
        }
    }

    let _guard = EnvGuard;
    {
        let _env = lock_env();
        unsafe {
            std::env::remove_var("IDENTITY_HEADER");
            std::env::set_var(
                "IDENTITY_ENDPOINT",
                "http://localhost:40342/metadata/identity/oauth2/token",
            );
            std::env::set_var("IMDS_ENDPOINT", "http://localhost:40342");
        }
    }

    let client = make_client();
    let config = make_mi_config(None);
    let result = ClientCredentialsAuth::get_token(
        &config,
        &client,
        "test-tenant".to_string(),
        "graph".to_string(),
        String::new(),
        vec!["https://graph.microsoft.com/.default".to_string()],
    )
    .await;

    match result {
        Err(Error::ClientCredentialsFlowCreation(msg)) => {
            assert!(
                msg.contains("Azure Arc") && msg.contains("not yet supported"),
                "a real Arc environment must reach the Arc-unsupported error, got: {msg}"
            );
            assert!(
                !msg.contains("IDENTITY_HEADER"),
                "a real Arc environment must not be misdiagnosed as an App Service misconfig, got: {msg}"
            );
        }
        other => panic!("expected ClientCredentialsFlowCreation, got: {other:?}"),
    }
}
