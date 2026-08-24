//! Directory role verification for application service principals.
//!
//! When ORADAZ authenticates with client credentials, prerequisites must
//! verify that the application's service principal holds the
//! `Global Reader` Entra ID role. This module mirrors the user-facing
//! `user_roles.rs` logic (PIM-aware) but queries against the SP's object id
//! (parsed from the access token's `oid` claim).

use crate::FL;
use crate::collect::auth::tokens::{REFRESH_TOKEN_EXPIRATION_THRESHOLD, Token};
use crate::collect::prerequisites::graph::pim_enabled_for_tenant;
use crate::collect::prerequisites::handle_429;
use crate::collect::prerequisites::models::{
    PIMRoleAssignmentScheduleInstancesResponse, RoleAssignmentResponse,
};
use crate::utils::errors::Error;

use chrono::{DateTime, Utc};
use log::{debug, error, warn};
use reqwest::Client;
use std::cmp::min;
use url::Url;

const GLOBAL_READER_TEMPLATE_ID: &str = "f2ef992c-3afb-46b9-b7cf-a126ee74c451";
const GLOBAL_READER_ROLE_NAME: &str = "Global Reader";
const REFRESH_TOKEN_PIM_DELAY: i64 = 30;

/// Checks that the application's service principal holds the Global Reader
/// Entra directory role. PIM-aware: if PIM is enabled on the tenant, uses
/// `roleAssignmentScheduleInstances`; otherwise queries `roleAssignments`.
///
/// Returns `(Some(new_expires_on), "Global Reader")` if a PIM assignment is
/// shorter-lived than the current token, so the caller can adjust the
/// refresh deadline.
pub async fn check_sp_global_reader_role(
    client: &Client,
    token: &Token,
    silent: bool,
    graph_base_url: &str,
    default_retry_after: u64,
) -> Result<(Option<i64>, String), Error> {
    debug!(
        "{:FL$}Checking Global Reader role for application service principal",
        "Prerequisites"
    );
    if token.user_id.is_empty() {
        error!(
            "{:FL$}Cannot resolve service principal object id from access token (oid claim missing)",
            "Prerequisites"
        );
        return Err(Error::MissingServicePrincipalObjectId);
    }

    let pim =
        pim_enabled_for_tenant(client, token, silent, graph_base_url, default_retry_after).await?;
    if pim {
        check_sp_global_reader_role_with_pim(
            client,
            token,
            silent,
            graph_base_url,
            default_retry_after,
        )
        .await
    } else {
        check_sp_global_reader_role_without_pim(
            client,
            token,
            silent,
            graph_base_url,
            default_retry_after,
        )
        .await
        .map(|()| (None, GLOBAL_READER_ROLE_NAME.to_string()))
    }
}

async fn check_sp_global_reader_role_with_pim(
    client: &Client,
    token: &Token,
    silent: bool,
    graph_base_url: &str,
    default_retry_after: u64,
) -> Result<(Option<i64>, String), Error> {
    debug!(
        "{:FL$}Checking SP Global Reader role through PIM active assignments",
        "Prerequisites"
    );
    let string_url = format!(
        "{}/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$select=endDateTime,roleDefinition&$expand=roleDefinition($select=templateId)&$filter=(principalId eq '{}')",
        graph_base_url, token.user_id
    );
    let url: Url = match Url::parse(&string_url) {
        Ok(u) => u,
        Err(err) => {
            error!(
                "{:FL$}Cannot create url to retrieve SP PIM active assignments",
                "Prerequisites"
            );
            debug!("{:FL$}URL parse error: {:?}", "Prerequisites", err);
            return Err(Error::UrlCreation);
        }
    };
    let res = match client
        .get(url)
        .header(
            reqwest::header::AUTHORIZATION,
            &format!("Bearer {}", token.access_token),
        )
        .send()
        .await
    {
        Err(err) => {
            error!(
                "{:FL$}Error performing request to retrieve PIM active assignments for service principal",
                "Prerequisites"
            );
            debug!("{:FL$}HTTP request error: {:?}", "Prerequisites", err);
            return Err(Error::CannotRetrieveServicePrincipalPIMEntraRoles);
        }
        Ok(res) => res,
    };
    let res = handle_429(res, default_retry_after)?;
    let status = res.status();
    let response: String = match res.text().await {
        Ok(s) => s,
        Err(err) => {
            if silent {
                debug!(
                    "{:FL$}Error reading response body for SP PIM active assignments",
                    "Prerequisites"
                );
            } else {
                error!(
                    "{:FL$}Error reading response body for SP PIM active assignments",
                    "Prerequisites"
                );
            }
            debug!("{:FL$}Response text error: {:?}", "Prerequisites", err);
            return Err(Error::CannotRetrieveServicePrincipalPIMEntraRoles);
        }
    };

    let role_assignments: PIMRoleAssignmentScheduleInstancesResponse =
        match serde_json::from_str(&response) {
            Ok(r) => r,
            Err(err) => {
                error!(
                    "{:FL$}Error parsing PIM role assignments for service principal",
                    "Prerequisites"
                );
                debug!("{:FL$}{} - {}", "Prerequisites", status, response);
                debug!("{:FL$}JSON parse error: {:?}", "Prerequisites", err);
                return Err(Error::CannotRetrieveServicePrincipalPIMEntraRoles);
            }
        };

    let mut role_expiration: Option<i64> = None;
    let mut found = false;
    for role in role_assignments.value.iter() {
        if role.role_definition.template_id != GLOBAL_READER_TEMPLATE_ID {
            continue;
        }
        match &role.end_date_time {
            None => {
                // Permanent assignment.
                found = true;
                role_expiration = None;
                break;
            }
            Some(end_date_time) => match end_date_time.parse::<DateTime<Utc>>() {
                Err(err) => {
                    warn!(
                        "{:FL$}Error parsing endDateTime for SP PIM role assignment; treating role as inactive: {:?}",
                        "Prerequisites", err
                    );
                    debug!(
                        "{:FL$}Parse error for endDateTime {}: {:?}",
                        "Prerequisites", end_date_time, err
                    );
                }
                Ok(d) => {
                    if d.timestamp() > Utc::now().timestamp() + REFRESH_TOKEN_PIM_DELAY {
                        found = true;
                        let ts = d.timestamp();
                        role_expiration = Some(match role_expiration {
                            None => ts,
                            Some(prev) => min(prev, ts),
                        });
                    }
                }
            },
        }
    }

    if !found {
        if silent {
            debug!(
                "{:FL$}Service principal is missing the Global Reader role (PIM active assignments did not include it)",
                "Prerequisites"
            );
        } else {
            error!(
                "{:FL$}Service principal is missing the Global Reader role (assign Global Reader through PIM to fix the issue)",
                "Prerequisites"
            );
        }
        return Err(Error::MissingGlobalReaderRoleForApplication);
    }

    let new_expires_on = role_expiration.and_then(|exp| {
        if exp < token.expires_on {
            Some(exp + REFRESH_TOKEN_EXPIRATION_THRESHOLD - REFRESH_TOKEN_PIM_DELAY)
        } else {
            None
        }
    });

    debug!(
        "{:FL$}Service principal has Global Reader (PIM)",
        "Prerequisites"
    );
    Ok((new_expires_on, GLOBAL_READER_ROLE_NAME.to_string()))
}

async fn check_sp_global_reader_role_without_pim(
    client: &Client,
    token: &Token,
    silent: bool,
    graph_base_url: &str,
    default_retry_after: u64,
) -> Result<(), Error> {
    debug!(
        "{:FL$}Checking SP Global Reader role through direct role assignments",
        "Prerequisites"
    );
    let string_url = format!(
        "{}/v1.0/roleManagement/directory/roleAssignments?$select=roleDefinition&$expand=roleDefinition($select=templateId)&$filter=(principalId eq '{}') and (roleDefinition/templateId eq '{}')",
        graph_base_url, token.user_id, GLOBAL_READER_TEMPLATE_ID
    );
    let url: Url = match Url::parse(&string_url) {
        Ok(u) => u,
        Err(err) => {
            error!(
                "{:FL$}Cannot create url to retrieve SP Entra roles",
                "Prerequisites"
            );
            debug!("{:FL$}URL parse error: {:?}", "Prerequisites", err);
            return Err(Error::UrlCreation);
        }
    };
    let res = match client
        .get(url)
        .header(
            reqwest::header::AUTHORIZATION,
            &format!("Bearer {}", token.access_token),
        )
        .send()
        .await
    {
        Err(err) => {
            error!(
                "{:FL$}Cannot retrieve Entra role assignments for service principal",
                "Prerequisites"
            );
            debug!("{:FL$}HTTP request error: {:?}", "Prerequisites", err);
            return Err(Error::CannotRetrieveServicePrincipalEntraRoles);
        }
        Ok(res) => res,
    };
    let res = handle_429(res, default_retry_after)?;
    let status = res.status();
    let response: String = match res.text().await {
        Ok(s) => s,
        Err(err) => {
            if silent {
                debug!(
                    "{:FL$}Error reading response body for SP role assignments",
                    "Prerequisites"
                );
            } else {
                error!(
                    "{:FL$}Error reading response body for SP role assignments",
                    "Prerequisites"
                );
            }
            debug!("{:FL$}Response text error: {:?}", "Prerequisites", err);
            return Err(Error::CannotRetrieveServicePrincipalEntraRoles);
        }
    };

    let role_assignments: RoleAssignmentResponse = match serde_json::from_str(&response) {
        Ok(r) => r,
        Err(err) => {
            error!(
                "{:FL$}Error parsing role assignments for service principal",
                "Prerequisites"
            );
            debug!("{:FL$}{} - {}", "Prerequisites", status, response);
            debug!("{:FL$}JSON parse error: {:?}", "Prerequisites", err);
            return Err(Error::CannotRetrieveServicePrincipalEntraRoles);
        }
    };

    if role_assignments
        .value
        .iter()
        .any(|r| r.role_definition.template_id == GLOBAL_READER_TEMPLATE_ID)
    {
        debug!(
            "{:FL$}Service principal has Global Reader role",
            "Prerequisites"
        );
        return Ok(());
    }

    if silent {
        debug!(
            "{:FL$}Service principal is missing the Global Reader role",
            "Prerequisites"
        );
    } else {
        error!(
            "{:FL$}Service principal is missing the Global Reader role (assign Global Reader directory role to fix the issue)",
            "Prerequisites"
        );
    }
    Err(Error::MissingGlobalReaderRoleForApplication)
}
