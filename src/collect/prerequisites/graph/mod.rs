pub mod app_permissions;
pub mod constants;
pub mod sp_roles;
pub mod user_roles;

pub use app_permissions::{
    check_app_permissions, check_app_permissions_for_client_credentials,
    check_app_permissions_for_managed_identity,
};
pub use sp_roles::check_sp_global_reader_role;
pub use user_roles::{
    check_entra_roles_for_graph_with_pim, check_entra_roles_for_graph_without_pim,
};

use crate::FL;
use crate::collect::auth::tokens::Token;
use crate::collect::prerequisites::handle_429;
use crate::collect::prerequisites::models::OrganizationResponse;
use crate::utils::errors::Error;

use log::{debug, error};
use reqwest::Client;

const PIM_SERVICE_PLAN_ID: &str = "eec0eb4f-6444-4f95-aba0-50c24d67f998";

/// Validates that the current user possesses the necessary Microsoft Entra roles for the Graph API.
///
/// It first checks if Privileged Identity Management (PIM) is enabled for the organization.
/// Based on this, it delegates the check to either the PIM-aware or the standard role verification logic.
pub async fn check_entra_roles_for_graph(
    client: &Client,
    token: &Token,
    silent: bool,
    graph_base_url: &str,
    default_retry_after: u64,
) -> Result<(Option<i64>, String), (Error, Vec<String>)> {
    let pim = pim_enabled_for_tenant(client, token, silent, graph_base_url, default_retry_after)
        .await
        .map_err(|e| (e, vec![]))?;
    if pim {
        check_entra_roles_for_graph_with_pim(
            client,
            token,
            silent,
            graph_base_url,
            default_retry_after,
        )
        .await
    } else {
        check_entra_roles_for_graph_without_pim(
            client,
            token,
            silent,
            graph_base_url,
            default_retry_after,
        )
        .await
        .map(|name| (None, name))
    }
}

/// Returns `true` when the tenant has Privileged Identity Management (PIM)
/// activated, by inspecting the `assignedPlans` of `/v1.0/organization`.
pub async fn pim_enabled_for_tenant(
    client: &Client,
    token: &Token,
    silent: bool,
    graph_base_url: &str,
    default_retry_after: u64,
) -> Result<bool, Error> {
    debug!("{:FL$}Checking PIM status for tenant", "Prerequisites");
    let string_url = format!("{}/v1.0/organization", graph_base_url);
    let url = match url::Url::parse(&string_url) {
        Ok(u) => u,
        Err(err) => {
            error!(
                "{:FL$}Cannot create url to retrieve current organization",
                "Prerequisites"
            );
            debug!("{:FL$}{:?}", "Prerequisites", err);
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
                "{:FL$}Cannot retrieve organization to check PIM status",
                "Prerequisites"
            );
            debug!("{:FL$}{:?}", "Prerequisites", err);
            return Err(Error::CannotRetrieveOrganization);
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
                    "{:FL$}Error getting text response from request to retrieve organization to check PIM status",
                    "Prerequisites"
                );
            } else {
                error!(
                    "{:FL$}Error getting text response from request to retrieve organization to check PIM status",
                    "Prerequisites"
                );
            }
            debug!("{:FL$}{:?}", "Prerequisites", err);
            return Err(Error::CannotRetrieveOrganization);
        }
    };

    match serde_json::from_str::<OrganizationResponse>(&response) {
        Ok(organization) => {
            let pim_enabled = organization.value.into_iter().any(|org| {
                org.assigned_plans.iter().any(|x| {
                    x.capability_status == "Enabled" && x.service_plan_id == PIM_SERVICE_PLAN_ID
                })
            });
            debug!(
                "{:FL$}PIM enabled for tenant: {}",
                "Prerequisites", pim_enabled
            );
            Ok(pim_enabled)
        }
        Err(err) => {
            error!("{:FL$}Error parsing organization", "Prerequisites");
            debug!("{:FL$}{} - {}", "Prerequisites", status, response);
            debug!("{:FL$}{:?}", "Prerequisites", err);
            Err(Error::CannotRetrieveOrganization)
        }
    }
}
