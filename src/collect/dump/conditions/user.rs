use crate::FL;
use crate::collect::auth::tokens::Token;
use crate::collect::dump::conditions::ConditionChecker;
use crate::collect::prerequisites::PIMRoleAssignmentScheduleInstancesResponse;

use chrono::{DateTime, Utc};
use log::{debug, error, warn};
use url::Url;

/// Checks if the given user has the Global Administrator role.
///
/// If the tenant has PIM (Privileged Identity Management) available — which
/// requires an Entra ID Premium **P2** licence — it checks active role
/// assignment schedule instances. Otherwise it checks standard permanent role
/// assignments. (The PIM endpoint is only available on tenants with Entra ID
/// Premium P2; on a P1-only tenant it is unavailable, and a permanent GA would
/// be missed.)
pub async fn check_user_for_ga(checker: &ConditionChecker, token: &Token) -> Option<bool> {
    debug!("{:FL$}Checking if user is Global Admin", "ConditionChecker");
    let p2_enabled = checker
        .tenant_conditions
        .get("P2")
        .copied()
        .unwrap_or(false);
    if p2_enabled {
        // Tenant has Entra ID Premium P2 licence, meaning PIM is available
        // Extract base URL from org_url (e.g., https://graph.microsoft.com/v1.0 from https://graph.microsoft.com/v1.0/organization)
        let base_url = checker.org_url.trim_end_matches("/organization");
        let string_url: String = format!(
            "{}/roleManagement/directory/roleAssignmentScheduleInstances?$select=endDateTime,roleDefinition&$expand=roleDefinition($select=templateId)&$filter=(principalId eq '{}')",
            base_url, token.user_id
        );
        let url: Url = match Url::parse(&string_url) {
            Ok(u) => u,
            Err(err) => {
                debug!(
                    "{:FL$}Cannot create url to retrieve current user PIM role assignments: {err:?}",
                    "ConditionChecker"
                );
                return None;
            }
        };
        let response = match checker
            .client
            .client
            .get(url)
            .header(
                reqwest::header::AUTHORIZATION,
                &format!("Bearer {}", token.access_token),
            )
            .send()
            .await
        {
            Err(err) => {
                warn!(
                    "{:FL$}Could not query current user PIM role assignments to determine Global Admin status; GA-gated APIs may be skipped this evaluation (will re-probe).",
                    "ConditionChecker"
                );
                debug!(
                    "{:FL$}GA PIM probe request error: {err:?}",
                    "ConditionChecker"
                );
                return None;
            }
            Ok(res) => res,
        };

        if !response.status().is_success() {
            warn!(
                "{:FL$}GA PIM role-assignment probe returned HTTP {}; cannot determine Global Admin status this evaluation (will re-probe).",
                "ConditionChecker",
                response.status()
            );
            return None;
        }

        match response
            .json::<PIMRoleAssignmentScheduleInstancesResponse>()
            .await
        {
            Ok(role_assignments) => {
                for role in role_assignments.value.iter() {
                    if role.role_definition.template_id == "62e90394-69f5-4237-9190-012177145e10" {
                        match &role.end_date_time {
                            None => return Some(true),
                            Some(end_date_time) => match end_date_time.parse::<DateTime<Utc>>() {
                                Err(err) => {
                                    // Treat an unparseable bound as "this assignment
                                    // inactive" and keep scanning — a later permanent
                                    // or still-valid GA assignment must still win,
                                    // rather than caching a definitive `false`.
                                    warn!(
                                        "{:FL$}Error parsing endDateTime {end_date_time:?} for a PIM role assignment, skipping it: {err:?}",
                                        "ConditionChecker"
                                    );
                                    continue;
                                }
                                Ok(d) => {
                                    if d.timestamp() > Utc::now().timestamp() {
                                        return Some(true);
                                    }
                                }
                            },
                        }
                    }
                }
                Some(false)
            }
            Err(err) => {
                warn!(
                    "{:FL$}Could not parse current user PIM role assignments; cannot determine Global Admin status this evaluation (will re-probe).",
                    "ConditionChecker"
                );
                debug!(
                    "{:FL$}GA PIM probe parse error: {err:?}",
                    "ConditionChecker"
                );
                None
            }
        }
    } else {
        let base_url = checker.org_url.trim_end_matches("/organization");
        let string_url = format!(
            "{}/roleManagement/directory/roleAssignments?$select=roleDefinition&$expand=roleDefinition($select=templateId)&$filter=(principalId eq '{}') and (roleDefinition/templateId eq '62e90394-69f5-4237-9190-012177145e10')",
            base_url, token.user_id
        );
        let url: Url = match Url::parse(&string_url) {
            Ok(u) => u,
            Err(err) => {
                debug!(
                    "{:FL$}Cannot create url to retrieve current user role assignments: {err:?}",
                    "ConditionChecker"
                );
                return None;
            }
        };
        let response = match checker
            .client
            .client
            .get(url)
            .header(
                reqwest::header::AUTHORIZATION,
                &format!("Bearer {}", token.access_token),
            )
            .send()
            .await
        {
            Err(err) => {
                warn!(
                    "{:FL$}Could not query current user role assignments to determine Global Admin status; GA-gated APIs may be skipped this evaluation (will re-probe).",
                    "ConditionChecker"
                );
                debug!("{:FL$}GA probe request error: {err:?}", "ConditionChecker");
                return None;
            }
            Ok(res) => res,
        };
        if !response.status().is_success() {
            warn!(
                "{:FL$}GA role-assignment probe returned HTTP {}; cannot determine Global Admin status this evaluation (will re-probe).",
                "ConditionChecker",
                response.status()
            );
            return None;
        }
        match response
            .json::<PIMRoleAssignmentScheduleInstancesResponse>()
            .await
        {
            Ok(role_assignments) => {
                for role in role_assignments.value.iter() {
                    if role.role_definition.template_id == "62e90394-69f5-4237-9190-012177145e10" {
                        return Some(true);
                    }
                }
                Some(false)
            }
            Err(err) => {
                warn!(
                    "{:FL$}Could not parse current user role assignments; cannot determine Global Admin status this evaluation (will re-probe).",
                    "ConditionChecker"
                );
                debug!("{:FL$}GA probe parse error: {err:?}", "ConditionChecker");
                None
            }
        }
    }
}

/// Checks if the given user has the customSecurityAttributes of an emergency account.
pub fn check_if_emergency_account(checker: &ConditionChecker, value: &serde_json::Value) -> bool {
    let parts: Vec<&str> = checker
        .emergency_accounts_custom_attributes
        .split('.')
        .collect();
    if parts.len() != 2 || parts.iter().any(|p| p.is_empty()) {
        error!(
            "{:FL$}emergencyAccountsCustomAttributes is malformed (expected '<set>.<name>'): '{}'",
            "ConditionChecker", checker.emergency_accounts_custom_attributes
        );
        return false;
    }
    match value.get(parts[0]) {
        None => false,
        Some(data) => match data.get(parts[1]) {
            None => false,
            Some(val) => val.as_bool().unwrap_or_default(),
        },
    }
}
