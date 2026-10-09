//! Resolve the DNS issuers present in collected identities without inferring
//! an authentication provider from a user's mail address or directory role.

use crate::utils::url::{ExpectedErrorCode, Url};
use dashmap::DashSet;
use serde_json::Value;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

pub(super) fn enabled(source: &Url) -> bool {
    source
        .api_behavior
        .get("resolve_tenant_domains")
        .is_some_and(|value| value == "true")
}

/// Accept only DNS names that can be embedded as an OData string literal.
/// Social-provider issuers are not Entra tenant domains for their users.
fn issuer_domain(issuer: &str) -> Option<String> {
    let domain = issuer
        .strip_suffix('.')
        .unwrap_or(issuer)
        .to_ascii_lowercase();
    if domain.len() > 253
        || !domain.contains('.')
        || domain.parse::<IpAddr>().is_ok()
        || matches!(domain.as_str(), "google.com" | "facebook.com")
    {
        return None;
    }
    if domain.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
    }) {
        return None;
    }
    Some(domain)
}

/// Reserve each domain once across concurrent pages and return normal collector
/// URLs. Retries operate on those URLs directly and never consult this set.
pub(super) fn lookup_urls(
    source: &Url,
    users: &[Value],
    scheduled_domains: &DashSet<String>,
) -> Vec<Url> {
    if !enabled(source) {
        return Vec::new();
    }
    let mut endpoint = match url::Url::parse(&source.url) {
        Ok(url) => url,
        Err(error) => {
            log::warn!("Cannot build tenant lookups from collector URL: {error}");
            return Vec::new();
        }
    };
    endpoint.set_query(None);
    endpoint.set_fragment(None);
    let mut urls = Vec::new();
    for identity in users
        .iter()
        .filter_map(|user| user.get("identities").and_then(Value::as_array))
        .flatten()
    {
        let Some(domain) = identity
            .get("issuer")
            .and_then(Value::as_str)
            .and_then(issuer_domain)
        else {
            continue;
        };
        if !scheduled_domains.insert(domain.clone()) {
            continue;
        }
        endpoint.set_path(&format!(
            "/v1.0/tenantRelationships/findTenantInformationByDomainName(domainName='{domain}')"
        ));
        urls.push(Url {
            service_name: source.service_name.clone(),
            service_scopes: Arc::clone(&source.service_scopes),
            service_mandatory_auth: source.service_mandatory_auth,
            api: "tenantInformationByDomainName".to_string(),
            url: endpoint.to_string(),
            conditions: None,
            relationships: Arc::new(Vec::new()),
            api_behavior: Arc::new(HashMap::new()),
            // A missing domain is recorded in errors.json and remains unknown.
            // It must not trip the tenant-wide expected-error breaker.
            expected_error_codes: Some(Arc::new(vec![ExpectedErrorCode {
                status: 404,
                code: None,
                breaker_eligible: false,
            }])),
            parent: Some(HashMap::from([("domainName".to_string(), domain)])),
            retry_number: 0,
            rate_limit_retry_number: 0,
            rate_limit_total_wait_secs: 0,
            network_retry_number: 0,
            post_body: None,
        });
    }
    urls
}
