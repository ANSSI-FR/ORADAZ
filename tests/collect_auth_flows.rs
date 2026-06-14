use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use oradaz::collect::auth::flows::device_code::{DeviceCodeAuth, DeviceCodePollError};
use oradaz::collect::auth::tokens::{InitialTokenResponse, TokenEndpointResponse};

/// Build a minimal fake JWT whose payload decodes to the given JSON string.
fn fake_jwt(payload_json: &str) -> String {
    let encoded = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
    format!("eyJhbGciOiJSUzI1NiJ9.{encoded}.fake_signature")
}

fn make_token_response(access_token: &str) -> InitialTokenResponse {
    InitialTokenResponse {
        token: TokenEndpointResponse {
            access_token: access_token.to_string(),
            token_type: Some("Bearer".to_string()),
            expires_in: Some(3600),
            refresh_token: None,
        },
    }
}

#[test]
fn initial_token_response_parses_valid_jwt() {
    let jwt = fake_jwt(r#"{"oid":"user-oid-abc","name":"Alice Dupont"}"#);
    let resp = make_token_response(&jwt);

    let token = resp
        .parse(
            "my-tenant".to_string(),
            "graph".to_string(),
            "client-123".to_string(),
            vec!["https://graph.microsoft.com/.default".to_string()],
        )
        .expect("parse should succeed");

    assert_eq!(token.user_id, "user-oid-abc");
    assert_eq!(token.user_principal_name, "Alice Dupont");
    assert_eq!(token.tenant_id, "my-tenant");
    assert_eq!(token.service, "graph");
    assert_eq!(token.client_id, "client-123");
    assert!(!token.is_expired(), "Fresh token should not be expired");
}

#[test]
fn initial_token_response_prefers_upn_over_name() {
    // Real UPN must win over the display `name` claim: when a token carries
    // both a UPN claim (`upn`/`preferred_username`) and `name`, the UPN is used.
    let jwt = fake_jwt(
        r#"{"oid":"oid-1","name":"FNU LNU","upn":"alice@contoso.com","preferred_username":"alice_pref@contoso.com"}"#,
    );
    let token = make_token_response(&jwt)
        .parse(
            "t".to_string(),
            "graph".to_string(),
            "c".to_string(),
            vec![],
        )
        .expect("parse should succeed");
    assert_eq!(token.user_principal_name, "alice@contoso.com");
}

#[test]
fn initial_token_response_falls_back_to_preferred_username() {
    // v2.0 tokens have no `upn`; use `preferred_username` before `name`.
    let jwt =
        fake_jwt(r#"{"oid":"oid-2","name":"FNU LNU","preferred_username":"bob@contoso.com"}"#);
    let token = make_token_response(&jwt)
        .parse(
            "t".to_string(),
            "graph".to_string(),
            "c".to_string(),
            vec![],
        )
        .expect("parse should succeed");
    assert_eq!(token.user_principal_name, "bob@contoso.com");
}

#[test]
fn initial_token_response_handles_padded_jwt_payload() {
    // Standard Azure access tokens use unpadded base64url, but some tokens in
    // the wild pad the payload segment. The identity parser must accept those
    // too — it shares the padded-fallback decoder with prerequisite grant
    // inspection (jwt_claims::decode_jwt_segment), so the two cannot drift.
    use base64::engine::general_purpose::URL_SAFE;
    let payload = r#"{"oid":"oid-padded","name":"Padded User"}"#;
    let encoded = URL_SAFE.encode(payload.as_bytes());
    assert!(
        encoded.contains('='),
        "test precondition: the payload must be padded to exercise the fallback"
    );
    let jwt = format!("eyJhbGciOiJSUzI1NiJ9.{encoded}.fake_signature");

    let token = make_token_response(&jwt)
        .parse(
            "t".to_string(),
            "graph".to_string(),
            "c".to_string(),
            vec![],
        )
        .expect("a padded JWT payload should still parse");
    assert_eq!(token.user_id, "oid-padded");
    assert_eq!(token.user_principal_name, "Padded User");
}

#[test]
fn initial_token_response_fails_on_malformed_jwt() {
    // Access token with only one part (no dots) — can't split into 3 parts
    let resp = make_token_response("not_a_jwt");

    let result = resp.parse(
        "tenant".to_string(),
        "graph".to_string(),
        "client".to_string(),
        vec![],
    );

    assert!(
        result.is_err(),
        "Parsing an access token that isn't a JWT should fail"
    );
}

#[test]
fn initial_token_response_fails_on_invalid_base64_payload() {
    // JWT with invalid base64 in the payload (middle) part
    let resp = make_token_response("header.!!!invalid-base64!!!.sig");

    let result = resp.parse(
        "tenant".to_string(),
        "graph".to_string(),
        "client".to_string(),
        vec![],
    );

    assert!(result.is_err(), "Invalid base64 payload should fail");
}

#[test]
fn initial_token_response_fails_when_payload_missing_oid() {
    // Valid base64, valid JSON, but missing required "oid" field
    let jwt = fake_jwt(r#"{"name":"Bob"}"#);
    let resp = make_token_response(&jwt);

    let result = resp.parse(
        "tenant".to_string(),
        "graph".to_string(),
        "client".to_string(),
        vec![],
    );

    assert!(
        result.is_err(),
        "JWT payload missing 'oid' field should fail"
    );
}

#[test]
fn is_device_code_expired_true_on_expired_token() {
    let err = DeviceCodePollError::ExpiredToken;
    assert!(
        DeviceCodeAuth::is_device_code_expired(&err),
        "ExpiredToken must be classified as expired"
    );
}

#[test]
fn is_device_code_expired_false_on_terminal_error() {
    let err = DeviceCodePollError::Terminal("access_denied".to_string());
    assert!(
        !DeviceCodeAuth::is_device_code_expired(&err),
        "Terminal(access_denied) is not an expiry"
    );
}

#[test]
fn initial_token_response_sets_expiration_from_expires_in() {
    let jwt = fake_jwt(r#"{"oid":"u","name":"U"}"#);
    let resp = make_token_response(&jwt);

    let before = chrono::Utc::now().timestamp();
    let token = resp
        .parse("t".to_string(), "g".to_string(), "c".to_string(), vec![])
        .unwrap();
    let after = chrono::Utc::now().timestamp();

    // Token should expire approximately 3600 seconds from now
    assert!(token.expires_on >= before + 3590);
    assert!(token.expires_on <= after + 3610);
}
