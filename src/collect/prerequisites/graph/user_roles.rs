use crate::FL;
use crate::collect::auth::tokens::{REFRESH_TOKEN_EXPIRATION_THRESHOLD, Token};
use crate::collect::prerequisites::graph::constants::{ENTRA_ROLE_NAMES, REQUIRED_ENTRA_ROLES};
use crate::collect::prerequisites::handle_429;
use crate::collect::prerequisites::models::{
    PIMRoleAssignmentScheduleInstancesResponse, RoleAssignmentResponse,
};
use crate::utils::errors::Error;

use chrono::{DateTime, Utc};
use log::{debug, error, warn};
use reqwest::Client;
use std::cmp::{max, min};
use url::Url;

/// Finds the required role combination that the user is closest to satisfying and returns the
/// names of the roles that are still missing from that combination.
fn find_best_missing_roles(user_role_ids: &[&str]) -> Vec<String> {
    REQUIRED_ENTRA_ROLES
        .iter()
        .map(|combo| {
            combo
                .iter()
                .filter(|&&id| !user_role_ids.contains(&id))
                .map(|&id| ENTRA_ROLE_NAMES.get(id).copied().unwrap_or(id).to_string())
                .collect::<Vec<_>>()
        })
        .min_by_key(Vec::len)
        .unwrap_or_default()
}

const REFRESH_TOKEN_PIM_DELAY: i64 = 30;

/// Checks if the current user has the required Entra roles when PIM (Privileged Identity Management) is enabled.
///
/// This function retrieves active PIM role assignments and calculates the expiration date of the
/// user's authorization based on the required role combinations.
pub async fn check_entra_roles_for_graph_with_pim(
    client: &Client,
    token: &Token,
    silent: bool,
    graph_base_url: &str,
    default_retry_after: u64,
) -> Result<(Option<i64>, String), (Error, Vec<String>)> {
    debug!(
        "{:FL$}Checking curent user Entra roles for Graph API while PIM is enabled",
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
                "{:FL$}Cannot create url to retrieve current user PIM active assignments",
                "Prerequisites"
            );
            debug!("{:FL$}URL parse error: {:?}", "Prerequisites", err);
            return Err((Error::UrlCreation, vec![]));
        }
    };
    let res = match client
        .get(url.clone())
        .header(
            reqwest::header::AUTHORIZATION,
            &format!("Bearer {}", token.access_token),
        )
        .send()
        .await
    {
        Err(err) => {
            error!(
                "{:FL$}Error performing request to retrieve PIM active assignments for current user",
                "Prerequisites"
            );
            debug!("{:FL$}HTTP request error: {:?}", "Prerequisites", err);
            return Err((Error::CannotRetrieveCurrentUserPIMEntraRoles, vec![]));
        }
        Ok(res) => res,
    };
    let res = crate::collect::prerequisites::handle_429(res, default_retry_after)
        .map_err(|e| (e, vec![]))?;
    let status = res.status();
    let response: String = match res.text().await {
        Ok(s) => s,
        Err(err) => {
            if silent {
                debug!(
                    "{:FL$}Error getting text response from request to retrieve PIM active assignments for current user",
                    "Prerequisites"
                );
            } else {
                error!(
                    "{:FL$}Error getting text response from request to retrieve PIM active assignments for current user",
                    "Prerequisites"
                );
            }
            debug!("{:FL$}Response text error: {:?}", "Prerequisites", err);
            return Err((Error::CannotRetrieveCurrentUserPIMEntraRoles, vec![]));
        }
    };

    match serde_json::from_str::<PIMRoleAssignmentScheduleInstancesResponse>(&response) {
        Ok(role_assignments) => {
            // Determine the overall expiration of the user's authorization based on the required Entra roles.
            // REQUIRED_ENTRA_ROLES is a list of role combinations.
            // The user is authorized if they possess at least one complete combination of roles.
            let mut min_expiration: i64 = 0;
            let mut matched_combo: Option<&Vec<&'static str>> = None;

            for requirement in REQUIRED_ENTRA_ROLES.iter() {
                // Find the role in the combination that expires first.
                let mut min_expiration_for_group_combination: i64 = token.expires_on;
                let all_match = requirement.iter().all(|&x| {
                    for role in role_assignments.value.iter() {
                        if role.role_definition.template_id == x {
                            match &role.end_date_time {
                                None => return true, // Permanent assignment
                                Some(end_date_time) => {
                                    match end_date_time.parse::<DateTime<Utc>>() {
                                        Err(err) => {
                                            warn!("{:FL$}Error parsing endDateTime value for PIM role assignments for current user; treating role as inactive: {:?}", "Prerequisites", err);
                                            debug!("{:FL$}Parse error for endDateTime {}: {:?}", "Prerequisites", end_date_time, err);
                                            return false;
                                        }
                                        Ok(d) => {
                                            // Role must be active and not expiring immediately
                                            if d.timestamp() > Utc::now().timestamp() + REFRESH_TOKEN_PIM_DELAY {
                                                min_expiration_for_group_combination = min(d.timestamp(), min_expiration_for_group_combination);
                                                return true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    false
                });
                if all_match {
                    // User meets this combination. Overall expiration is the maximum of all valid combinations.
                    min_expiration = max(min_expiration, min_expiration_for_group_combination);
                    matched_combo = Some(requirement);
                    break;
                }
            }

            let combo = match matched_combo {
                None => {
                    if silent {
                        debug!(
                            "{:FL$}User is missing a required Entra role (assign Global Reader, Security Reader and Attribute Assignment Reader roles to fix the issue)",
                            "Prerequisites"
                        );
                    } else {
                        error!(
                            "{:FL$}User is missing a required Entra role (assign Global Reader, Security Reader and Attribute Assignment Reader roles to fix the issue)",
                            "Prerequisites"
                        );
                    }
                    let active_role_ids: Vec<&str> = role_assignments
                        .value
                        .iter()
                        .filter_map(|role| {
                            let id = role.role_definition.template_id.as_str();
                            match &role.end_date_time {
                                None => Some(id),
                                Some(end_date_time) => {
                                    end_date_time.parse::<DateTime<Utc>>().ok().and_then(|d| {
                                        if d.timestamp()
                                            > Utc::now().timestamp() + REFRESH_TOKEN_PIM_DELAY
                                        {
                                            Some(id)
                                        } else {
                                            None
                                        }
                                    })
                                }
                            }
                        })
                        .collect();
                    let missing = find_best_missing_roles(&active_role_ids);
                    return Err((Error::MissingEntraRoles, missing));
                }
                Some(c) => c,
            };

            let role_info = combo
                .iter()
                .map(|&id| ENTRA_ROLE_NAMES.get(id).copied().unwrap_or(id))
                .collect::<Vec<_>>()
                .join(" + ");

            if min_expiration < token.expires_on {
                debug!(
                    "{:FL$}PIM role assignment will expire before token, updating expires_on",
                    "Prerequisites"
                );
                return Ok((
                    Some(
                        min_expiration + REFRESH_TOKEN_EXPIRATION_THRESHOLD
                            - REFRESH_TOKEN_PIM_DELAY,
                    ),
                    role_info,
                ));
            }

            debug!(
                "{:FL$}Current user has required Entra roles",
                "Prerequisites"
            );
            Ok((None, role_info))
        }
        Err(err) => {
            error!(
                "{:FL$}Error parsing PIM role assignments for current user",
                "Prerequisites"
            );
            debug!("{:FL$}{} - {}", "Prerequisites", status, response);
            debug!("{:FL$}JSON parse error: {:?}", "Prerequisites", err);
            Err((Error::CannotRetrieveCurrentUserPIMEntraRoles, vec![]))
        }
    }
}

/// Checks if the current user has the required Entra roles when PIM is disabled.
///
/// This function performs a direct check for role assignments without considering PIM activation schedules.
pub async fn check_entra_roles_for_graph_without_pim(
    client: &Client,
    token: &Token,
    silent: bool,
    graph_base_url: &str,
    default_retry_after: u64,
) -> Result<String, (Error, Vec<String>)> {
    debug!(
        "{:FL$}Checking curent user Entra roles for Graph API while PIM is disabled",
        "Prerequisites"
    );
    let roles: String = REQUIRED_ENTRA_ROLES
        .iter()
        .fold(Vec::<&str>::new(), |mut acc, r| {
            acc.extend(r);
            acc
        })
        .join("', '");
    let string_url = format!(
        "{}/v1.0/roleManagement/directory/roleAssignments?$select=roleDefinition&$expand=roleDefinition($select=templateId)&$filter=(principalId eq '{}') and (roleDefinition/templateId in ('{}'))",
        graph_base_url, token.user_id, roles
    );
    let url: Url = match Url::parse(&string_url) {
        Ok(u) => u,
        Err(err) => {
            error!(
                "{:FL$}Cannot create url to retrieve current user Entra roles",
                "Prerequisites"
            );
            debug!("{:FL$}URL parse error: {:?}", "Prerequisites", err);
            return Err((Error::UrlCreation, vec![]));
        }
    };
    let res = match client
        .get(url.clone())
        .header(
            reqwest::header::AUTHORIZATION,
            &format!("Bearer {}", token.access_token),
        )
        .send()
        .await
    {
        Err(err) => {
            error!(
                "{:FL$}Cannot retrieve Entra role assignments for current user",
                "Prerequisites"
            );
            debug!("{:FL$}HTTP request error: {:?}", "Prerequisites", err);
            return Err((Error::CannotRetrieveCurrentUserEntraRoles, vec![]));
        }
        Ok(res) => res,
    };
    let res = handle_429(res, default_retry_after).map_err(|e| (e, vec![]))?;
    let status = res.status();
    let response: String = match res.text().await {
        Ok(s) => s,
        Err(err) => {
            if silent {
                debug!(
                    "{:FL$}Error getting text response from request to retrieve Entra role assignments for current user",
                    "Prerequisites"
                );
            } else {
                error!(
                    "{:FL$}Error getting text response from request to retrieve Entra role assignments for current user",
                    "Prerequisites"
                );
            }
            debug!("{:FL$}Response text error: {:?}", "Prerequisites", err);
            return Err((Error::CannotRetrieveCurrentUserEntraRoles, vec![]));
        }
    };

    match serde_json::from_str::<RoleAssignmentResponse>(&response) {
        Ok(role_assignments) => {
            let matched = REQUIRED_ENTRA_ROLES.iter().find(|requirement| {
                requirement.iter().all(|&x| {
                    role_assignments
                        .value
                        .iter()
                        .any(|role| role.role_definition.template_id == x)
                })
            });

            let combo = match matched {
                None => {
                    if silent {
                        debug!(
                            "{:FL$}User is missing a required Entra role (assign Global Reader, Security Reader and Attribute Assignment Reader roles to fix the issue)",
                            "Prerequisites"
                        );
                    } else {
                        error!(
                            "{:FL$}User is missing a required Entra role (assign Global Reader, Security Reader and Attribute Assignment Reader roles to fix the issue)",
                            "Prerequisites"
                        );
                    }
                    let active_role_ids: Vec<&str> = role_assignments
                        .value
                        .iter()
                        .map(|r| r.role_definition.template_id.as_str())
                        .collect();
                    let missing = find_best_missing_roles(&active_role_ids);
                    return Err((Error::MissingEntraRoles, missing));
                }
                Some(c) => c,
            };

            let role_info = combo
                .iter()
                .map(|&id| ENTRA_ROLE_NAMES.get(id).copied().unwrap_or(id))
                .collect::<Vec<_>>()
                .join(" + ");

            if !silent {
                debug!(
                    "{:FL$}Current user has required Entra roles",
                    "Prerequisites"
                );
            }
            Ok(role_info)
        }
        Err(err) => {
            error!(
                "{:FL$}Error parsing role assignments for current user",
                "Prerequisites"
            );
            debug!("{:FL$}{} - {}", "Prerequisites", status, response);
            debug!("{:FL$}JSON parse error: {:?}", "Prerequisites", err);
            Err((Error::CannotRetrieveCurrentUserEntraRoles, vec![]))
        }
    }
}
