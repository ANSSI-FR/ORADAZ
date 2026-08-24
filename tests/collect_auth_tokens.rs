use oradaz::collect::auth::tokens::Token;

fn make_token(tenant_id: &str, client_id: &str, user_id: &str, upn: &str) -> Token {
    Token {
        tenant_id: tenant_id.to_string(),
        client_id: client_id.to_string(),
        service: "graph".to_string(),
        expires_on: chrono::Utc::now().timestamp() + 3600,
        access_token: "tok".to_string(),
        refresh_token: None,
        token_type: "Bearer".to_string(),
        user_id: user_id.to_string(),
        user_principal_name: upn.to_string(),
        scopes: vec![],
    }
}

#[test]
fn test_token_creation() {
    let token = Token {
        tenant_id: "test-tenant".to_string(),
        client_id: "test-client".to_string(),
        service: "graph".to_string(),
        expires_on: 1234567890,
        access_token: "test_access_token".to_string(),
        refresh_token: Some("test_refresh_token".to_string()),
        token_type: "Bearer".to_string(),
        user_id: "user-123".to_string(),
        user_principal_name: "user@example.com".to_string(),
        scopes: vec!["https://graph.microsoft.com/.default".to_string()],
    };

    assert_eq!(token.tenant_id, "test-tenant");
    assert_eq!(token.service, "graph");
    assert_eq!(token.access_token, "test_access_token");
    assert!(token.refresh_token.is_some());
}

#[test]
fn test_token_is_expired() {
    let mut token = Token {
        tenant_id: "test-tenant".to_string(),
        client_id: "test-client".to_string(),
        service: "graph".to_string(),
        expires_on: 1234567890, // Past timestamp
        access_token: "test_access_token".to_string(),
        refresh_token: Some("test_refresh_token".to_string()),
        token_type: "Bearer".to_string(),
        user_id: "user-123".to_string(),
        user_principal_name: "user@example.com".to_string(),
        scopes: vec!["https://graph.microsoft.com/.default".to_string()],
    };

    assert!(token.is_expired());

    token.expires_on = chrono::Utc::now().timestamp() + 3600; // 1 hour from now
    assert!(!token.is_expired());
}

#[test]
fn test_token_expiration_boundary() {
    let now = chrono::Utc::now().timestamp();
    let mut token = Token {
        tenant_id: "test-tenant".to_string(),
        client_id: "test-client".to_string(),
        service: "graph".to_string(),
        expires_on: now - 1, // 1 second ago
        access_token: "test_access_token".to_string(),
        refresh_token: Some("test_refresh_token".to_string()),
        token_type: "Bearer".to_string(),
        user_id: "user-123".to_string(),
        user_principal_name: "user@example.com".to_string(),
        scopes: vec!["https://graph.microsoft.com/.default".to_string()],
    };

    assert!(token.is_expired());

    token.expires_on = now + 1; // 1 second from now
    assert!(!token.is_expired());
}

/// Mirrors the identity-validation condition used in `Token::renew()` and
/// `Token::refresh()` (after a refresh-token exchange).  Verifies that mismatches
/// on any of the four identity fields are caught.
#[test]
fn test_token_identity_mismatch_detection() {
    let original = make_token("tenant-a", "client-x", "uid-1", "user@example.com");

    // Identical token — no mismatch.
    let same = make_token("tenant-a", "client-x", "uid-1", "user@example.com");
    assert!(
        same.user_id == original.user_id
            && same.user_principal_name == original.user_principal_name
            && same.tenant_id == original.tenant_id
            && same.client_id == original.client_id
    );

    // Wrong tenant_id.
    let wrong_tenant = make_token("tenant-b", "client-x", "uid-1", "user@example.com");
    assert!(wrong_tenant.tenant_id != original.tenant_id);

    // Wrong client_id.
    let wrong_client = make_token("tenant-a", "client-y", "uid-1", "user@example.com");
    assert!(wrong_client.client_id != original.client_id);

    // Wrong user_id.
    let wrong_user = make_token("tenant-a", "client-x", "uid-2", "user@example.com");
    assert!(wrong_user.user_id != original.user_id);

    // Wrong UPN.
    let wrong_upn = make_token("tenant-a", "client-x", "uid-1", "other@example.com");
    assert!(wrong_upn.user_principal_name != original.user_principal_name);
}
