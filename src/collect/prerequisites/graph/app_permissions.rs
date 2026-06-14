use crate::FL;
use crate::collect::auth::tokens::Token;
use crate::collect::prerequisites::graph::constants::{
    GRAPH_API_APP_ONLY_PERMISSIONS, GRAPH_API_PERMISSIONS,
};
use crate::collect::prerequisites::handle_429;
use crate::collect::prerequisites::jwt_claims::parse_token_grants;
use crate::collect::prerequisites::models::AppRoleAssignmentResponse;
use crate::utils::errors::Error;

use log::{debug, error, warn};
use reqwest::Client;
use std::collections::HashSet;

/// Verifies that the Microsoft Graph access token issued to the current user
/// carries every delegated scope listed in `GRAPH_API_PERMISSIONS`.
///
/// The check inspects the `scp` claim of the Graph access token (the
/// as-granted scopes) rather than the application registration's declared
/// `requiredResourceAccess`, since only the former proves admin consent.
pub fn check_app_permissions(token: &Token, silent: bool) -> Result<(), (Error, Vec<String>)> {
    debug!(
        "{:FL$}Checking Microsoft Graph delegated scopes from access token",
        "Prerequisites"
    );
    let grants = parse_token_grants(&token.access_token);

    let missing_names: Vec<String> = GRAPH_API_PERMISSIONS
        .values()
        .filter(|name| !grants.has_scope(name))
        .map(|name| (*name).to_string())
        .collect();

    if missing_names.is_empty() {
        if !silent {
            debug!(
                "{:FL$}Microsoft Graph token carries all required delegated scopes",
                "Prerequisites"
            );
        }
        return Ok(());
    }

    if silent {
        debug!(
            "{:FL$}Missing required delegated scope(s) on Microsoft Graph token:",
            "Prerequisites"
        );
        for name in &missing_names {
            debug!("{:FL$}\t- {}", "", name);
        }
    } else {
        error!(
            "{:FL$}Missing required delegated scope(s) on Microsoft Graph token:",
            "Prerequisites"
        );
        for name in &missing_names {
            error!("{:FL$}\t- {}", "", name);
        }
    }
    Err((Error::MissingAppPermission, missing_names))
}

/// Verifies that the app-only Microsoft Graph access token carries every
/// application permission listed in `GRAPH_API_APP_ONLY_PERMISSIONS`.
///
/// Inspects the `roles` claim of the token (the as-granted application
/// permissions) instead of the declared `requiredResourceAccess`.
pub fn check_app_permissions_for_client_credentials(
    token: &Token,
    silent: bool,
) -> Result<(), (Error, Vec<String>)> {
    debug!(
        "{:FL$}Checking Microsoft Graph application permissions from access token",
        "Prerequisites"
    );
    let grants = parse_token_grants(&token.access_token);

    let missing_names: Vec<String> = GRAPH_API_APP_ONLY_PERMISSIONS
        .values()
        .filter(|name| !grants.has_role(name))
        .map(|name| (*name).to_string())
        .collect();

    if missing_names.is_empty() {
        if !silent {
            debug!(
                "{:FL$}Microsoft Graph token carries all required application permissions",
                "Prerequisites"
            );
        }
        return Ok(());
    }

    if silent {
        debug!(
            "{:FL$}Missing required application permission(s) on Microsoft Graph token:",
            "Prerequisites"
        );
        for name in &missing_names {
            debug!("{:FL$}\t- {}", "", name);
        }
    } else {
        error!(
            "{:FL$}Missing required application permission(s) on Microsoft Graph token:",
            "Prerequisites"
        );
        for name in &missing_names {
            error!("{:FL$}\t- {}", "", name);
        }
    }
    Err((Error::MissingAppPermission, missing_names))
}

/// Checks Graph application permissions for managed identity service principals.
///
/// System-assigned managed identity tokens issued by IMDS do not carry the
/// `roles` claim even when the SP has app role assignments — so JWT inspection
/// is unreliable. This function queries `servicePrincipals/{oid}/appRoleAssignments`
/// directly via Graph API and checks the returned role IDs against the required set.
pub async fn check_app_permissions_for_managed_identity(
    client: &Client,
    token: &Token,
    silent: bool,
    graph_base_url: &str,
    default_retry_after: u64,
) -> Result<(), (Error, Vec<String>)> {
    debug!(
        "{:FL$}Checking Graph application permissions via API for managed identity",
        "Prerequisites"
    );

    if token.user_id.is_empty() {
        error!(
            "{:FL$}Cannot check application permissions: service principal OID is missing from token",
            "Prerequisites"
        );
        return Err((Error::MissingServicePrincipalObjectId, vec![]));
    }

    // Bounded so a cyclic or pathological `@odata.nextLink` cannot loop forever —
    // exit must not depend solely on the server (mirrors the subscriptions probe).
    const MAX_APP_ROLE_PAGES: usize = 1000;
    let mut granted_ids: HashSet<String> = HashSet::new();
    let mut next_url: Option<String> = Some(format!(
        "{graph_base_url}/v1.0/servicePrincipals/{}/appRoleAssignments",
        token.user_id
    ));
    let mut page_count: usize = 0;

    while let Some(url_str) = next_url {
        page_count += 1;
        if page_count > MAX_APP_ROLE_PAGES {
            warn!(
                "{:FL$}Stopped paginating appRoleAssignments after {} pages (possible cyclic nextLink); proceeding with the assignments gathered so far",
                "Prerequisites", MAX_APP_ROLE_PAGES
            );
            break;
        }
        let url = match url::Url::parse(&url_str) {
            Ok(u) => u,
            Err(err) => {
                error!("{:FL$}Cannot parse appRoleAssignments URL", "Prerequisites");
                debug!("{:FL$}URL parse error: {:?}", "Prerequisites", err);
                return Err((Error::UrlCreation, vec![]));
            }
        };
        let res = match client
            .get(url)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", token.access_token),
            )
            .send()
            .await
        {
            Ok(r) => r,
            Err(err) => {
                error!(
                    "{:FL$}Error querying appRoleAssignments for managed identity",
                    "Prerequisites"
                );
                debug!("{:FL$}HTTP error: {:?}", "Prerequisites", err);
                return Err((Error::CannotRetrieveAppRoleAssignments, vec![]));
            }
        };
        let res = handle_429(res, default_retry_after).map_err(|e| (e, vec![]))?;
        let status = res.status();
        let body = match res.text().await {
            Ok(s) => s,
            Err(err) => {
                error!(
                    "{:FL$}Error reading appRoleAssignments response",
                    "Prerequisites"
                );
                debug!("{:FL$}{err:?}", "Prerequisites");
                return Err((Error::CannotRetrieveAppRoleAssignments, vec![]));
            }
        };
        let page: AppRoleAssignmentResponse = match serde_json::from_str(&body) {
            Ok(p) => p,
            Err(err) => {
                if !silent {
                    error!(
                        "{:FL$}Error parsing appRoleAssignments response (HTTP {})",
                        "Prerequisites", status
                    );
                }
                debug!("{:FL$}{status}: {body}", "Prerequisites");
                debug!("{:FL$}{err:?}", "Prerequisites");
                return Err((Error::CannotRetrieveAppRoleAssignments, vec![]));
            }
        };
        for item in page.value {
            granted_ids.insert(item.app_role_id);
        }
        next_url = page.next_link;
    }

    let mut missing_names: Vec<String> = GRAPH_API_APP_ONLY_PERMISSIONS
        .iter()
        .filter(|(id, _)| {
            let s: &str = id;
            !granted_ids.contains(s)
        })
        .map(|(_, name)| (*name).to_string())
        .collect();
    missing_names.sort();

    if missing_names.is_empty() {
        if !silent {
            debug!(
                "{:FL$}Managed identity has all required Graph application permissions",
                "Prerequisites"
            );
        }
        return Ok(());
    }

    if silent {
        debug!(
            "{:FL$}Managed identity is missing required Graph application permission(s):",
            "Prerequisites"
        );
    } else {
        error!(
            "{:FL$}Managed identity is missing required Graph application permission(s):",
            "Prerequisites"
        );
    }
    for name in &missing_names {
        if silent {
            debug!("{:FL$}\t- {}", "", name);
        } else {
            error!("{:FL$}\t- {}", "", name);
        }
    }
    Err((Error::MissingAppPermission, missing_names))
}
