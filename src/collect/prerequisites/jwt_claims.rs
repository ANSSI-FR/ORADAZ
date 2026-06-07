//! JWT claim inspection helpers used by prerequisite checks.
//!
//! Microsoft identity platform access tokens are JWTs whose payload carries
//! the as-granted permissions:
//!
//! - `roles` (array of strings) — application permissions actually consented
//!   for an app-only token (client credentials flow).
//! - `scp` (space-separated string) — delegated scopes actually consented for
//!   a user token (authorization code / device code flows).
//! - `oid` (string) — object id of the principal (user or service principal)
//!   the token was issued for.
//!
//! Inspecting these claims is strictly more reliable than reading the
//! application registration's `requiredResourceAccess`, which only reflects
//! the declared permissions and does not prove admin consent.

use crate::FL;

use base64::prelude::*;
use log::debug;
use serde::Deserialize;

/// As-granted information extracted from a Microsoft identity access token.
#[derive(Debug, Default, Clone)]
pub struct TokenGrants {
    /// Application permissions actually granted (`roles` claim).
    pub roles: Vec<String>,
    /// Delegated scopes actually granted (`scp` claim, split on whitespace).
    pub scp: Vec<String>,
    /// Object id (`oid` claim).
    pub oid: String,
}

impl TokenGrants {
    /// Returns true if the `roles` claim contains the given application
    /// permission name (case-sensitive — Microsoft uses PascalCase).
    pub fn has_role(&self, name: &str) -> bool {
        self.roles.iter().any(|r| r == name)
    }

    /// Returns true if the `scp` claim contains the given delegated scope.
    pub fn has_scope(&self, name: &str) -> bool {
        self.scp.iter().any(|s| s == name)
    }
}

#[derive(Deserialize)]
struct JwtPayload {
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    scp: Option<String>,
    #[serde(default)]
    oid: String,
}

/// Decodes the payload of a JWT access token and extracts the grant-related
/// claims used by prerequisite verification. Returns an empty `TokenGrants`
/// on any parse failure (caller treats this as "no grants").
pub fn parse_token_grants(access_token: &str) -> TokenGrants {
    let payload_b64 = match access_token.split('.').nth(1) {
        Some(p) => p,
        None => {
            debug!(
                "{:FL$}Access token has no JWT payload segment; treating as no grants",
                "JwtClaims"
            );
            return TokenGrants::default();
        }
    };

    // JWT payloads use base64url without padding, but some tokens in the wild
    // pad the segment. Try the unpadded decoder first, then fall back to the
    // padded one after re-adding padding bytes.
    let decoded = BASE64_URL_SAFE_NO_PAD.decode(payload_b64).or_else(|_| {
        let mut padded = payload_b64.to_string();
        while padded.len() % 4 != 0 {
            padded.push('=');
        }
        BASE64_URL_SAFE.decode(padded.as_bytes())
    });

    let bytes = match decoded {
        Ok(b) => b,
        Err(err) => {
            debug!(
                "{:FL$}Failed to base64-decode JWT payload: {:?}",
                "JwtClaims", err
            );
            return TokenGrants::default();
        }
    };

    let payload_str = String::from_utf8_lossy(&bytes);
    let parsed: JwtPayload = match serde_json::from_str(&payload_str) {
        Ok(p) => p,
        Err(err) => {
            debug!(
                "{:FL$}Failed to parse JWT payload as JSON: {:?}",
                "JwtClaims", err
            );
            return TokenGrants::default();
        }
    };

    let scp = parsed
        .scp
        .as_deref()
        .map(|s| s.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();

    TokenGrants {
        roles: parsed.roles,
        scp,
        oid: parsed.oid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_jwt(payload_json: &str) -> String {
        let header_b64 = BASE64_URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload_b64 = BASE64_URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        format!("{header_b64}.{payload_b64}.sig")
    }

    #[test]
    fn parses_app_only_roles_and_oid() {
        let jwt =
            make_jwt(r#"{"roles":["Exchange.ManageAsApp","User.Read.All"],"oid":"sp-oid-1234"}"#);
        let g = parse_token_grants(&jwt);
        assert_eq!(g.oid, "sp-oid-1234");
        assert!(g.has_role("Exchange.ManageAsApp"));
        assert!(g.has_role("User.Read.All"));
        assert!(!g.has_role("Directory.Read.All"));
        assert!(g.scp.is_empty());
    }

    #[test]
    fn parses_delegated_scp_split() {
        let jwt = make_jwt(
            r#"{"scp":"Exchange.Manage User.Read.All AccessReview.Read.All","oid":"user-oid"}"#,
        );
        let g = parse_token_grants(&jwt);
        assert_eq!(g.oid, "user-oid");
        assert!(g.has_scope("Exchange.Manage"));
        assert!(g.has_scope("User.Read.All"));
        assert!(g.has_scope("AccessReview.Read.All"));
        assert!(g.roles.is_empty());
    }

    #[test]
    fn empty_on_invalid_token() {
        let g = parse_token_grants("not-a-jwt");
        assert!(g.roles.is_empty());
        assert!(g.scp.is_empty());
        assert!(g.oid.is_empty());
    }

    #[test]
    fn empty_on_invalid_base64_payload() {
        let g = parse_token_grants("aaa.@@not-base64@@.sig");
        assert!(g.roles.is_empty());
        assert!(g.scp.is_empty());
    }

    #[test]
    fn handles_padded_payload() {
        let payload_b64 = BASE64_URL_SAFE.encode(br#"{"roles":["X"],"oid":"o"}"#);
        let jwt = format!("hdr.{payload_b64}.sig");
        let g = parse_token_grants(&jwt);
        assert_eq!(g.oid, "o");
        assert!(g.has_role("X"));
    }
}
