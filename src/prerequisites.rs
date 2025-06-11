use crate::auth::Token;
use crate::errors::Error;
use crate::writer::OradazWriter;

use chrono::{DateTime, Utc};
use lazy_static::lazy_static;
use log::{debug, error, info, warn};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::{max, min};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use url::Url;

const FL: usize = crate::FL;
const REFRESH_TOKEN_EXPIRATION_THRESHOLD: i64 =
    crate::threading::REFRESH_TOKEN_EXPIRATION_THRESHOLD;
const REFRESH_TOKEN_PIM_DELAY: i64 = 30;

lazy_static! {
    static ref REQUIRED_ENTRA_ROLES: Vec<Vec<&'static str>> = vec![
        vec!["62e90394-69f5-4237-9190-012177145e10"], // Global Administrator
        vec![
            "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
            "5d6b6bb7-de71-4623-b4af-96380a352509",
        ], // Global Reader & Security Reader
    ];

    static ref GRAPH_API_PERMISSIONS: HashMap<&'static str, &'static str> = vec![
        (
            "ebfcd32b-babb-40f4-a14b-42706e83bd28",
            "AccessReview.Read.All",
        ),
        (
            "1b6ff35f-31df-4332-8571-d31ea5a4893f",
            "APIConnectors.Read.All",
        ),
        (
            "af281d3a-030d-4122-886e-146fb30a0413",
            "AppCertTrustConfiguration.Read.All",
        ),
        ("e4c9e354-4dc5-45b8-9e7c-e1393b0b1a20", "AuditLog.Read.All"),
        (
            "b46ffa80-fe3d-4822-9a1a-c200932d54d0",
            "CustomSecAttributeAssignment.Read.All",
        ),
        (
            "ce026878-a0ff-4745-a728-d4fedd086c07",
            "CustomSecAttributeDefinition.Read.All",
        ),
        (
            "0c0064ea-477b-4130-82a5-4c2cc4ff68aa",
            "DelegatedAdminRelationship.Read.All",
        ),
        (
            "4edf5f54-4666-44af-9de9-0144fb4b6e8c",
            "DeviceManagementApps.Read.All",
        ),
        (
            "f1493658-876a-4c87-8fa7-edb559b3476a",
            "DeviceManagementConfiguration.Read.All",
        ),
        (
            "314874da-47d6-4978-88dc-cf0d37f0bb82",
            "DeviceManagementManagedDevices.Read.All",
        ),
        (
            "49f0cc30-024c-4dfd-ab3e-82e137ee5431",
            "DeviceManagementRBAC.Read.All",
        ),
        ("06da0dbc-49e2-44d2-8312-53f166ab848a", "Directory.Read.All"),
        ("2f9ee017-59c1-4f1d-9472-bd5529a7b311", "Domain.Read.All"),
        (
            "5449aa12-1393-4ea2-a7c7-d0e06c1a56b2",
            "EntitlementManagement.Read.All",
        ),
        (
            "43781733-b5a7-4d1b-98f4-e8edff23e1a9",
            "IdentityProvider.Read.All",
        ),
        (
            "8f6a01e7-0391-4ee5-aa22-a3af122cef27",
            "IdentityRiskEvent.Read.All",
        ),
        (
            "ea5c4ab0-5a73-4f35-8272-5d5337884e5d",
            "IdentityRiskyServicePrincipal.Read.All",
        ),
        (
            "d04bb851-cb7c-4146-97c7-ca3e71baf56c",
            "IdentityRiskyUser.Read.All",
        ),
        (
            "2903d63d-4611-4d43-99ce-a33f3f52e343",
            "IdentityUserFlow.Read.All",
        ),
        (
            "526aa72a-5878-49fe-bf4e-357973af9b06",
            "MultiTenantOrganization.Read.All",
        ),
        (
            "f6609722-4100-44eb-b747-e6ca0536989d",
            "OnPremDirectorySynchronization.Read.All",
        ),
        (
            "4908d5b9-3fb2-4b1e-9336-1888b7937185",
            "Organization.Read.All",
        ),
        ("572fea84-0151-49b2-9301-11cb16974376", "Policy.Read.All"),
        (
            "414de6ea-2d92-462f-b120-6e2a809a6d01",
            "Policy.Read.PermissionGrant",
        ),
        (
            "b3a539c9-59cb-4ad5-825a-041ddbdc2bdb",
            "PrivilegedAccess.Read.AzureAD",
        ),
        (
            "d329c81c-20ad-4772-abf9-3f6fdb7e5988",
            "PrivilegedAccess.Read.AzureADGroup",
        ),
        (
            "1d89d70c-dcac-4248-b214-903c457af83a",
            "PrivilegedAccess.Read.AzureResources",
        ),
        (
            "02a32cc4-7ab5-4b58-879a-0586e0f7c495",
            "PrivilegedAssignmentSchedule.Read.AzureADGroup"
        ),
        (
            "8f44f93d-ecef-46ae-a9bf-338508d44d6b",
            "PrivilegedEligibilitySchedule.Read.AzureADGroup"
        ),
        (
            "04a4b2a2-3f26-4fc8-87ee-9c46e68db175",
            "PublicKeyInfrastructure.Read.All",
        ),
        ("02e97553-ed7b-43d0-ab3c-f8bace0d040c", "Reports.Read.All"),
        (
            "f1d91a8f-88e7-4774-8401-b668d5bca0c5",
            "ResourceSpecificPermissionGrant.ReadForUser",
        ),
        (
            "344a729c-0285-42c6-9014-f12b9b8d6129",
            "RoleAssignmentSchedule.Read.Directory",
        ),
        (
            "eb0788c2-6d4e-4658-8c9e-c0fb8053f03d",
            "RoleEligibilitySchedule.Read.Directory",
        ),
        (
            "48fec646-b2ba-4019-8681-8eb31435aded",
            "RoleManagement.Read.All",
        ),
        (
            "7e26fdff-9cb1-4e56-bede-211fe0e420e8",
            "RoleManagementPolicy.Read.AzureADGroup"
        ),
        (
            "64733abd-851e-478a-bffb-e47a14b18235",
            "SecurityEvents.Read.All",
        ),
        ("a154be20-db9c-4678-8ab7-66f6cc099a59", "User.Read.All"),
        (
            "aec28ec7-4d02-4e8c-b864-50163aea77eb",
            "UserAuthenticationMethod.Read.All",
        ),
    ]
    .iter()
    .copied()
    .collect();
}

#[derive(Deserialize)]
struct ResourceAccess {
    id: String,
    #[serde(rename = "type")]
    _scope: String,
}

#[derive(Deserialize)]
struct AppPerm {
    #[serde(rename = "resourceAppId")]
    resource_app_id: String,
    #[serde(rename = "resourceAccess")]
    resource_access: Vec<ResourceAccess>,
}

#[derive(Deserialize)]
struct ApplicationPermission {
    #[serde(rename = "requiredResourceAccess")]
    required_resource_access: Vec<AppPerm>,
}

#[derive(Deserialize)]
struct ApplicationResponse {
    #[serde(rename = "@odata.context")]
    _context: Option<String>,
    value: Option<Vec<ApplicationPermission>>,
}

#[derive(Deserialize)]
pub struct PIMRoleDefinitionTemplateId {
    #[serde(rename = "templateId")]
    pub template_id: String,
}

#[derive(Deserialize)]
pub struct PIMRoleDefinition {
    #[serde(rename = "endDateTime")]
    pub end_date_time: Option<String>,
    #[serde(rename = "roleDefinition")]
    pub role_definition: PIMRoleDefinitionTemplateId,
}

#[derive(Deserialize)]
pub struct PIMRoleAssignmentScheduleInstancesResponse {
    pub value: Vec<PIMRoleDefinition>,
}

#[derive(Deserialize)]
struct RoleDefinitionTemplateId {
    #[serde(rename = "templateId")]
    template_id: String,
}

#[derive(Deserialize)]
struct RoleDefinition {
    #[serde(rename = "roleDefinition")]
    role_definition: RoleDefinitionTemplateId,
}

#[derive(Deserialize)]
struct RoleAssignmentResponse {
    value: Vec<RoleDefinition>,
}

#[derive(Deserialize)]
struct InternalRoleAssignmentResponse {
    value: Vec<Value>,
}

#[derive(Deserialize)]
pub struct AssignedPlan {
    #[serde(rename = "servicePlanId")]
    pub service_plan_id: String,
    #[serde(rename = "capabilityStatus")]
    pub capability_status: String,
}

#[derive(Deserialize)]
pub struct Organization {
    #[serde(rename = "assignedPlans")]
    pub assigned_plans: Vec<AssignedPlan>,
}

#[derive(Deserialize)]
pub struct OrganizationResponse {
    pub value: Vec<Organization>,
}

#[derive(Deserialize)]
struct Subscription {
    #[serde(rename = "displayName")]
    display_name: String,
}

#[derive(Debug, Deserialize)]
struct Count {
    #[serde(rename = "type")]
    _count_type: Option<String>,
    #[serde(rename = "value")]
    _value: i32,
}

#[derive(Deserialize)]
struct SubscriptionResponse {
    #[serde(rename = "count")]
    _count: Option<Count>,
    value: Option<Vec<Subscription>>,
}

#[derive(Deserialize)]
struct Mailbox {
    #[serde(rename = "UserPrincipalName")]
    user_principal_name: String,
}

#[derive(Deserialize)]
struct MailboxResponse {
    value: Option<Vec<Mailbox>>,
}

#[derive(Deserialize)]
struct RecipientPermissionResponse {
    #[serde(rename = "@odata.id")]
    id: Option<String>,
}

#[derive(Serialize)]
pub struct PrerequisitesMetadata {
    pub api: String,
    pub error: String,
}

pub struct Prerequisites {}

impl Prerequisites {
    fn print_error(silent: bool, msg: String) {
        if silent {
            debug!("{}", msg);
        } else {
            error!("{}", msg);
        }
    }

    fn print_info(silent: bool, msg: String) {
        if silent {
            debug!("{}", msg);
        } else {
            info!("{}", msg);
        }
    }

    fn check_app_permissions(
        client: &Client,
        token: &mut Token,
        skip_resources: bool,
        silent: bool,
    ) -> Result<(), Error> {
        /*
        Check if application provided to authenticate for "graph" and "resources" services
        have the required permissions
        */
        debug!("{:FL$}Checking application permissions", "Prerequisites");

        // Retrieve application permissions
        let string_url = format!(
            "https://graph.microsoft.com/v1.0/applications?$filter=appId eq '{}'&$select=requiredResourceAccess", token.client_id);
        let url: Url = match Url::parse(&string_url) {
            Ok(u) => u,
            Err(err) => {
                Prerequisites::print_error(
                    silent,
                    format!(
                    "{:FL$}Cannot create url to retrieve custom application to check permissions", 
                    "Prerequisites"
                ),
                );
                debug!("{}", err);
                return Err(Error::UrlCreation);
            }
        };
        let res = match client
            .get(url)
            .header(
                reqwest::header::AUTHORIZATION,
                &format!("Bearer {}", token.access_token.secret()),
            )
            .send()
        {
            Err(err) => {
                Prerequisites::print_error(
                    silent,
                    format!(
                        "{:FL$}Cannot retrieve custom application to check permissions",
                        "Prerequisites"
                    ),
                );
                debug!("{}", err);
                return Err(Error::CannotRetrieveApp);
            }
            Ok(res) => res,
        };
        let status = res.status();
        let response: String = match res.text() {
            Ok(s) => s,
            Err(err) => {
                Prerequisites::print_error(silent, format!(
                    "{:FL$}Error getting text response from request retrieve custom application to check permissions",
                    "Prerequisites"
                ));
                debug!("{}", err);
                return Err(Error::CannotRetrieveApp);
            }
        };

        // Check if permitions match required ones
        match serde_json::from_str::<ApplicationResponse>(&response) {
            Ok(application) => match &application.value {
                None => {
                    Prerequisites::print_error(silent, format!(
                        "{:FL$}Missing required permission for Microsoft Graph API to read application",
                        "Prerequisites"
                    ));
                    return Err(Error::MissingAppPermission);
                }
                Some(value) => {
                    if !(skip_resources
                        || value.iter().any(|app| {
                            app.required_resource_access.iter().any(|access| {
                                // Azure Service Management
                                access.resource_app_id == "797f4846-ba00-4fd7-ba43-dac1f8f63013"
                                    && access.resource_access.iter().any(|perm| {
                                        // user_impersonation
                                        perm.id == "41094075-9dad-400e-a0bd-54e686782033"
                                    })
                            })
                        }))
                    {
                        Prerequisites::print_error(silent, format!(
                            "{:FL$}Missing user_impersonation permission for Azure Service Management API",
                            "Prerequisites"
                        ));
                        return Err(Error::MissingAppPermission);
                    }

                    let matched: Vec<String> = value.iter().fold(Vec::new(), |mut acc, app| {
                        acc.extend(app.required_resource_access.iter().fold(
                            Vec::new(),
                            |mut acc2, access| {
                                match &access.resource_app_id {
                                    // Microsoft Graph
                                    x if x == "00000003-0000-0000-c000-000000000000" => {
                                        acc2.extend(access.resource_access.iter().fold(
                                            Vec::new(),
                                            |mut acc3, perm| {
                                                let perm_id: String = perm.id.to_string();
                                                debug!("{:FL$}\t{}", "Prerequisites", perm_id);
                                                if GRAPH_API_PERMISSIONS
                                                    .contains_key(perm_id.as_str())
                                                {
                                                    acc3.push(perm_id)
                                                }
                                                acc3
                                            },
                                        ));
                                    }
                                    _ => {}
                                }
                                acc2
                            },
                        ));
                        acc
                    });
                    if GRAPH_API_PERMISSIONS.keys().len() != matched.len() {
                        Prerequisites::print_error(silent, format!(
                            "{:FL$}Missing required delegated permission(s) for Microsoft Graph API:",
                            "Prerequisites"
                        ));
                        for (perm_id, perm_name) in GRAPH_API_PERMISSIONS.clone().into_iter() {
                            if !matched.contains(&(&perm_id).to_string()) {
                                Prerequisites::print_error(
                                    silent,
                                    format!("{:FL$}\t- {}", "", perm_name),
                                );
                            }
                        }
                        return Err(Error::MissingAppPermission);
                    }
                }
            },
            Err(err) => {
                Prerequisites::print_error(
                    silent,
                    format!(
                        "{:FL$}Error parsing application to check for app permissions",
                        "Prerequisites"
                    ),
                );
                debug!("{} - {}", status, response);
                debug!("{}", err);
                return Err(Error::CannotRetrieveApp);
            }
        }
        debug!(
            "{:FL$}Custom application permissions match required ones",
            "Prerequisites"
        );
        Ok(())
    }

    fn check_entra_roles_for_graph_with_pim(
        client: &Client,
        token: &mut Token,
        silent: bool,
    ) -> Result<(), Error> {
        /*
        Check if curent user have the required roles when PIM is enabled in the tenant
        Fucking complex function due to MS Graph PIM API behavior that sucks
        */
        debug!(
            "{:FL$}Checking curent user Entra roles for Graph API while PIM is enabled",
            "Prerequisites"
        );
        // Note: cannot filter on required roles because the API does not return the endDateTime anymore for whatever reason
        let string_url: String = format!("https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$select=endDateTime,roleDefinition&$expand=roleDefinition($select=templateId)&$filter=(principalId eq '{}')", token.user_id);
        let url: Url = match Url::parse(&string_url) {
            Ok(u) => u,
            Err(err) => {
                Prerequisites::print_error(
                    silent,
                    format!(
                        "{:FL$}Cannot create url to retrieve current user PIM active assignments",
                        "Prerequisites"
                    ),
                );
                debug!("{}", err);
                return Err(Error::UrlCreation);
            }
        };
        let res = match client
            .get(url)
            .header(
                reqwest::header::AUTHORIZATION,
                &format!("Bearer {}", token.access_token.secret()),
            )
            .send()
        {
            Err(err) => {
                Prerequisites::print_error(silent, format!(
                    "{:FL$}Error performing request to retrieve PIM active assignments for current user",
                    "Prerequisites"
                ));
                debug!("{}", err);
                return Err(Error::CannotRetrieveCurrentUserPIMEntraRoles);
            }
            Ok(res) => res,
        };
        let status = res.status();
        let response: String = match res.text() {
            Ok(s) => s,
            Err(err) => {
                Prerequisites::print_error(silent, format!(
                    "{:FL$}Error getting text response from request to retrieve PIM active assignments for current user",
                    "Prerequisites"
                ));
                debug!("{}", err);
                return Err(Error::CannotRetrieveCurrentUserPIMEntraRoles);
            }
        };

        match serde_json::from_str::<PIMRoleAssignmentScheduleInstancesResponse>(&response) {
            Ok(role_assignments) => {
                let mut min_expiration: i64 = 0;
                if !REQUIRED_ENTRA_ROLES.clone().into_iter().any(|requirement| {
                    // Get the first expiration between token and roles in combination
                    let mut min_expiration_for_group_combination: i64 = token.expires_on;
                    let resp: bool = requirement.iter().all(|&x| {
                        for role in role_assignments.value.iter() {
                            if role.role_definition.template_id == x {
                                match &role.end_date_time {
                                    None => return true,
                                    Some(end_date_time) => {
                                        match end_date_time.parse::<DateTime<Utc>>() {
                                            Err(err) => {
                                                Prerequisites::print_error(silent, format!(
                                                    "{:FL$}Error parsing endDateTime value for PIM role assignments for current user",
                                                    "Prerequisites"
                                                ));
                                                debug!("{} - {}", end_date_time, err);
                                                return false
                                            }
                                            Ok(d) => {
                                                if d.timestamp() > Utc::now().timestamp() + REFRESH_TOKEN_PIM_DELAY {
                                                    min_expiration_for_group_combination =
                                                        min(d.timestamp(), min_expiration_for_group_combination);
                                                    return true
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        false
                    });
                    if resp {
                        // Expiration will be set to the maximum of possible role combination
                        min_expiration =
                            max(min_expiration, min_expiration_for_group_combination);
                    }
                    resp
                }) {
                    Prerequisites::print_error(silent, format!(
                        "{:FL$}User is missing a required Entra role (Security Reader or Global Reader)",
                        "Prerequisites"
                    ));
                    return Err(Error::MissingEntraRoles);
                }

                if min_expiration < token.expires_on {
                    debug!("PIM role assignment will expire before token, updating expires_on");
                    // Add REFRESH_TOKEN_EXPIRATION_THRESHOLD to renew token at time of expiration (with REFRESH_TOKEN_PIM_DELAY delay)
                    token.expires_on = min_expiration + REFRESH_TOKEN_EXPIRATION_THRESHOLD
                        - REFRESH_TOKEN_PIM_DELAY;
                }
            }
            Err(err) => {
                Prerequisites::print_error(
                    silent,
                    format!(
                        "{:FL$}Error parsing PIM role assignments for current user",
                        "Prerequisites"
                    ),
                );
                debug!("{} - {}", status, response);
                debug!("{}", err);
                return Err(Error::CannotRetrieveCurrentUserPIMEntraRoles);
            }
        }

        debug!(
            "{:FL$}Current user has required Entra roles",
            "Prerequisites"
        );
        Ok(())
    }

    fn check_entra_roles_for_graph_without_pim(
        client: &Client,
        token: &mut Token,
        silent: bool,
    ) -> Result<(), Error> {
        /*
        Check if curent user have the required roles when PIM is not enabled in the tenant
        */
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
            "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$select=roleDefinition&$expand=roleDefinition($select=templateId)&$filter=(principalId eq '{}') and (roleDefinition/templateId in ('{}'))",
            token.user_id, roles
        );
        let url: Url = match Url::parse(&string_url) {
            Ok(u) => u,
            Err(err) => {
                Prerequisites::print_error(
                    silent,
                    format!(
                        "{:FL$}Cannot create url to retrieve current user Entra roles",
                        "Prerequisites"
                    ),
                );
                debug!("{}", err);
                return Err(Error::UrlCreation);
            }
        };
        let res = match client
            .get(url)
            .header(
                reqwest::header::AUTHORIZATION,
                &format!("Bearer {}", token.access_token.secret()),
            )
            .send()
        {
            Err(err) => {
                Prerequisites::print_error(
                    silent,
                    format!(
                        "{:FL$}Cannot retrieve Entra role assignments for current user",
                        "Prerequisites"
                    ),
                );
                debug!("{}", err);
                return Err(Error::CannotRetrieveCurrentUserEntraRoles);
            }
            Ok(res) => res,
        };
        let status = res.status();
        let response: String = match res.text() {
            Ok(s) => s,
            Err(err) => {
                Prerequisites::print_error(silent, format!(
                    "{:FL$}Error getting text response from request to retrieve Entra role assignments for current user",
                    "Prerequisites"
                ));
                debug!("{}", err);
                return Err(Error::CannotRetrieveCurrentUserEntraRoles);
            }
        };

        match serde_json::from_str::<RoleAssignmentResponse>(&response) {
            Ok(role_assignments) => {
                if !REQUIRED_ENTRA_ROLES.clone().into_iter().any(|requirement| {
                    requirement.iter().all(|&x| {
                        role_assignments
                            .value
                            .iter()
                            .any(|role| role.role_definition.template_id == x)
                    })
                }) {
                    Prerequisites::print_error(silent, format!(
                        "{:FL$}User is missing a required Entra role (Security Reader or Global Reader)",
                        "Prerequisites"
                    ));
                    return Err(Error::MissingEntraRoles);
                }
            }
            Err(err) => {
                Prerequisites::print_error(
                    silent,
                    format!(
                        "{:FL$}Error parsing role assignments for current user",
                        "Prerequisites"
                    ),
                );
                debug!("{} - {}", status, response);
                debug!("{}", err);
                return Err(Error::CannotRetrieveCurrentUserEntraRoles);
            }
        }
        debug!(
            "{:FL$}Current user has required Entra roles",
            "Prerequisites"
        );
        Ok(())
    }

    fn check_entra_roles_for_graph(
        client: &Client,
        token: &mut Token,
        silent: bool,
    ) -> Result<(), Error> {
        /*
        Check if curent user have the required roles
        */
        debug!("{:FL$}Checking PIM status for tenant", "Prerequisites");
        let string_url: String = String::from("https://graph.microsoft.com/v1.0/organization");
        let url: Url = match Url::parse(&string_url) {
            Ok(u) => u,
            Err(err) => {
                Prerequisites::print_error(
                    silent,
                    format!(
                        "{:FL$}Cannot create url to retrieve current organization",
                        "Prerequisites"
                    ),
                );
                debug!("{}", err);
                return Err(Error::UrlCreation);
            }
        };
        let res = match client
            .get(url)
            .header(
                reqwest::header::AUTHORIZATION,
                &format!("Bearer {}", token.access_token.secret()),
            )
            .send()
        {
            Err(err) => {
                Prerequisites::print_error(
                    silent,
                    format!(
                        "{:FL$}Cannot retrieve organization to check PIM status",
                        "Prerequisites"
                    ),
                );
                debug!("{}", err);
                return Err(Error::CannotRetrieveOrganization);
            }
            Ok(res) => res,
        };
        let status = res.status();
        let response: String = match res.text() {
            Ok(s) => s,
            Err(err) => {
                Prerequisites::print_error(silent, format!(
                    "{:FL$}Error getting text response from request to retrieve organization to check PIM status",
                    "Prerequisites"
                ));
                debug!("{}", err);
                return Err(Error::CannotRetrieveOrganization);
            }
        };

        match serde_json::from_str::<OrganizationResponse>(&response) {
            Ok(organization) => {
                if organization.value.into_iter().any(|org| {
                    org.assigned_plans.iter().any(|x| {
                        // Tenant has Entra ID Premium P2 licence, meaning PIM is enabled
                        &x.capability_status == "Enabled"
                            && &x.service_plan_id == "eec0eb4f-6444-4f95-aba0-50c24d67f998"
                    })
                }) {
                    Prerequisites::check_entra_roles_for_graph_with_pim(client, token, silent)
                } else {
                    Prerequisites::check_entra_roles_for_graph_without_pim(client, token, silent)
                }
            }
            Err(err) => {
                Prerequisites::print_error(
                    silent,
                    format!("{:FL$}Error parsing organization", "Prerequisites"),
                );
                debug!("{} - {}", status, response);
                debug!("{}", err);
                Err(Error::CannotRetrieveOrganization)
            }
        }
    }

    fn check_entra_roles_for_internal(
        client: &Client,
        token: &mut Token,
        silent: bool,
    ) -> Result<(), Error> {
        /*
        Check if curent user have the required roles
        */
        debug!(
            "{:FL$}Checking curent user Entra roles for Internal API",
            "Prerequisites"
        );

        let string_url = format!(
            "https://graph.windows.net/{}/me/transitiveMemberOf?api-version=1.61-internal",
            token.tenant_id
        );
        let url: Url = match Url::parse(&string_url) {
            Ok(u) => u,
            Err(err) => {
                Prerequisites::print_error(
                    silent,
                    format!(
                        "{:FL$}Cannot create url to retrieve current user Entra roles",
                        "Prerequisites"
                    ),
                );
                debug!("{}", err);
                return Err(Error::UrlCreation);
            }
        };
        let res = match client
            .get(url)
            .header(
                reqwest::header::AUTHORIZATION,
                &format!("Bearer {}", token.access_token.secret()),
            )
            .send()
        {
            Err(err) => {
                Prerequisites::print_error(
                    silent,
                    format!(
                        "{:FL$}Cannot retrieve Entra role assignments for current user",
                        "Prerequisites"
                    ),
                );
                debug!("{}", err);
                return Err(Error::CannotRetrieveCurrentUserEntraRoles);
            }
            Ok(res) => res,
        };
        let status = res.status();
        let response: String = match res.text() {
            Ok(s) => s,
            Err(err) => {
                Prerequisites::print_error(silent, format!(
                    "{:FL$}Error getting text response from request to retrieve Entra role assignments for current user",
                    "Prerequisites"
                ));
                debug!("{}", err);
                return Err(Error::CannotRetrieveCurrentUserEntraRoles);
            }
        };

        match serde_json::from_str::<InternalRoleAssignmentResponse>(&response) {
            Ok(role_assignments) => {
                if !REQUIRED_ENTRA_ROLES.clone().into_iter().any(|requirement| {
                    requirement.iter().all(|&x| {
                        role_assignments.value.iter().any(|role| {
                            if let Some(role_template_id) = role.pointer("/roleTemplateId") {
                                match role_template_id.as_str() {
                                    Some(f) => return f == x,
                                    None => {
                                        return false;
                                    }
                                }
                            };
                            false
                        })
                    })
                }) {
                    Prerequisites::print_error(silent, format!(
                        "{:FL$}User is missing a required Entra role (Security Reader or Global Reader)",
                        "Prerequisites"
                    ));
                    return Err(Error::MissingEntraRoles);
                }
            }
            Err(err) => {
                Prerequisites::print_error(
                    silent,
                    format!(
                        "{:FL$}Error parsing role assignments for current user using internal API",
                        "Prerequisites"
                    ),
                );
                debug!("{} - {}", status, response);
                debug!("{}", err);
                return Err(Error::CannotRetrieveCurrentUserEntraRoles);
            }
        }
        debug!(
            "{:FL$}Current user has required Entra roles",
            "Prerequisites"
        );
        Ok(())
    }

    fn check_available_subscriptions(
        client: &Client,
        token: &mut Token,
        silent: bool,
    ) -> Result<(), Error> {
        /*
        Check the subscriptions the current user has access to
        */
        debug!(
            "{:FL$}Checking available subscriptions for current user",
            "Prerequisites"
        );
        let string_url =
            String::from("https://management.azure.com/subscriptions?api-version=2020-08-01");
        let url: Url = match Url::parse(&string_url) {
            Ok(u) => u,
            Err(err) => {
                Prerequisites::print_error(
                    silent,
                    format!(
                        "{:FL$}Cannot create url to retrieve available subscriptions",
                        "Prerequisites"
                    ),
                );
                debug!("{}", err);
                return Err(Error::UrlCreation);
            }
        };
        let res = match client
            .get(url)
            .header(
                reqwest::header::AUTHORIZATION,
                &format!("Bearer {}", token.access_token.secret()),
            )
            .send()
        {
            Err(err) => {
                Prerequisites::print_error(
                    silent,
                    format!(
                        "{:FL$}Cannot retrieve available subscriptions",
                        "Prerequisites"
                    ),
                );
                debug!("{}", err);
                return Err(Error::CannotRetrieveSubscriptions);
            }
            Ok(res) => res,
        };
        let status = res.status();
        let response: String = match res.text() {
            Ok(s) => s,
            Err(err) => {
                Prerequisites::print_error(silent, format!(
                    "{:FL$}Error getting text response from request to retrieve available subscriptions",
                    "Prerequisites"
                ));
                debug!("{}", err);
                return Err(Error::CannotRetrieveSubscriptions);
            }
        };

        match serde_json::from_str::<SubscriptionResponse>(&response) {
            Ok(subscriptions) => match &subscriptions.value {
                None => {
                    Prerequisites::print_error(
                        silent,
                        format!("{:FL$}Cannot retrieve subscriptions", "Prerequisites"),
                    );
                    return Err(Error::CannotRetrieveSubscriptions);
                }
                Some(subs) => {
                    if subs.is_empty() {
                        Prerequisites::print_error(
                            silent,
                            format!(
                                "{:FL$}User has no read permission on any subscription",
                                "Prerequisites"
                            ),
                        );
                        return Err(Error::NoAvailableSubscription);
                    } else {
                        Prerequisites::print_info(silent, format!(
                                "{:FL$}Reader role has been provided to the following subscriptions which will be audited:", "Prerequisites"
                            ));
                        for sub in subs {
                            Prerequisites::print_info(
                                silent,
                                format!("{:FL$}\t- {}", "", sub.display_name),
                            );
                        }
                    }
                }
            },
            Err(err) => {
                Prerequisites::print_error(
                    silent,
                    format!(
                        "{:FL$}Error parsing available subscriptions",
                        "Prerequisites"
                    ),
                );
                debug!("{} - {}", status, response);
                debug!("{}", err);
                return Err(Error::CannotRetrieveSubscriptions);
            }
        }
        Ok(())
    }

    fn check_exchange_permissions(
        client: &Client,
        token: &mut Token,
        silent: bool,
    ) -> Result<(), Error> {
        /*
        Check that current user can retrieve exchange delegations
        TODO : check if not possible to do that without retrieving the mailboxes
        */
        debug!(
            "{:FL$}Checking Exchange Online permissions for current user",
            "Prerequisites"
        );
        let string_url = format!(
            "https://outlook.office365.com/adminapi/beta/{}/Mailbox?$top=1&$select=UserPrincipalName", token.tenant_id
        );
        let url: Url = match Url::parse(&string_url) {
            Ok(u) => u,
            Err(err) => {
                Prerequisites::print_error(silent, format!(
                    "{:FL$}Cannot create url to retrieve Exchange Online mailbox to check permissions",
                    "Prerequisites"
                ));
                debug!("{}", err);
                return Err(Error::UrlCreation);
            }
        };
        let res = match client
            .get(url)
            .header(
                reqwest::header::AUTHORIZATION,
                &format!("Bearer {}", token.access_token.secret()),
            )
            .send()
        {
            Err(err) => {
                Prerequisites::print_error(
                    silent,
                    format!(
                        "{:FL$}Cannot retrieve Exchange Online mailbox to check permissions",
                        "Prerequisites"
                    ),
                );
                debug!("{}", err);
                return Err(Error::CannotRetrieveMailboxes);
            }
            Ok(res) => res,
        };
        let status = res.status();
        let response: String = match res.text() {
            Ok(s) => s,
            Err(err) => {
                Prerequisites::print_error(silent, format!(
                    "{:FL$}Error getting text response from request to retrieve available subscriptions",
                    "Prerequisites"
                ));
                debug!("{}", err);
                return Err(Error::CannotRetrieveMailboxes);
            }
        };

        match serde_json::from_str::<MailboxResponse>(&response) {
            Ok(mailboxes) => match &mailboxes.value {
                None => {
                    Prerequisites::print_error(silent, format!(
                            "{:FL$}Cannot retrieve Exchange Online mailbox to check ability to retrieve recipients", "Prerequisites"
                        ));
                    return Err(Error::CannotRetrieveMailboxes);
                }
                Some(mails) => {
                    if mails.is_empty() {
                        Prerequisites::print_error(
                            silent,
                            format!("{:FL$}No mailbox could be found", "Prerequisites"),
                        );
                        return Err(Error::CannotRetrieveMailboxes);
                    } else if let Some(mailbox) = mails.iter().next() {
                        let username: &str = &mailbox.user_principal_name;
                        let string_url = format!(
                                "https://outlook.office365.com/adminapi/beta/{}/Recipient('{}')?$expand=RecipientPermission", token.tenant_id, &username
                            );
                        let url: Url = match Url::parse(&string_url) {
                            Ok(u) => u,
                            Err(err) => {
                                Prerequisites::print_error(silent, format!(
                                        "{:FL$}Cannot create url to retrieve Exchange Online mailbox recipients to check permissions",
                                        "Prerequisites"
                                    ));
                                debug!("{}", err);
                                return Err(Error::UrlCreation);
                            }
                        };
                        let res2 = match client
                            .get(url)
                            .header(
                                reqwest::header::AUTHORIZATION,
                                &format!("Bearer {}", token.access_token.secret()),
                            )
                            .send()
                        {
                            Err(err) => {
                                Prerequisites::print_error(
                                    silent,
                                    format!(
                                        "{:FL$}Cannot retrieve Exchange Online mailbox recipients",
                                        "Prerequisites"
                                    ),
                                );
                                debug!("{}", err);
                                return Err(Error::CannotRetrieveMailboxesRecipients);
                            }
                            Ok(res) => res,
                        };
                        let status2 = res2.status();
                        let response2: String = match res2.text() {
                            Ok(s) => s,
                            Err(err) => {
                                Prerequisites::print_error(silent, format!(
                                    "{:FL$}Error getting text response from request to retrieve available subscriptions",
                                    "Prerequisites"
                                ));
                                debug!("{}", err);
                                return Err(Error::CannotRetrieveMailboxesRecipients);
                            }
                        };

                        match serde_json::from_str::<RecipientPermissionResponse>(&response2) {
                            Ok(permissions) => match &permissions.id {
                                None => {
                                    Prerequisites::print_error(
                                        silent,
                                        format!(
                                        "{:FL$}Missing permission to retrieve mailbox recipients",
                                        "Prerequisites"
                                    ),
                                    );
                                    return Err(Error::MissingExchangeOnlinePermissions);
                                }
                                Some(_e) => {
                                    debug!(
                                        "{:FL$}Current user has correct permissions to audit Exchange Online",
                                        "Prerequisites"
                                    );
                                }
                            },
                            Err(err) => {
                                Prerequisites::print_error(
                                    silent,
                                    format!(
                                        "{:FL$}Error parsing mailbox recipients",
                                        "Prerequisites"
                                    ),
                                );
                                debug!("{} - {}", status2, response2);
                                debug!("{}", err);
                                return Err(Error::CannotRetrieveMailboxesRecipients);
                            }
                        }
                    }
                }
            },
            Err(err) => {
                Prerequisites::print_error(
                    silent,
                    format!("{:FL$}Error parsing mailboxes", "Prerequisites"),
                );
                debug!("{} - {}", status, response);
                debug!("{}", err);
                return Err(Error::CannotRetrieveMailboxes);
            }
        }
        Ok(())
    }

    pub fn check(
        client: &Client,
        token: &mut Token,
        skip_resources: bool,
        silent: bool,
    ) -> Result<(), Error> {
        match &token.service.clone() {
            s if s == "graph" => {
                Prerequisites::check_app_permissions(client, token, skip_resources, silent)?;
                Prerequisites::check_entra_roles_for_graph(client, token, silent)
            }
            s if s == "internal" => {
                Prerequisites::check_entra_roles_for_internal(client, token, silent)
            }
            s if s == "resources" => {
                Prerequisites::check_available_subscriptions(client, token, silent)
            }
            s if s == "exchange" => {
                Prerequisites::check_exchange_permissions(client, token, silent)
            }
            s => {
                Prerequisites::print_error(
                    silent,
                    format!(
                        "{:FL$}Invalid token provided for prerequisites check: {:?}",
                        "Prerequisites", s
                    ),
                );
                Err(Error::InvalidTokenToCheck)
            }
        }
    }

    pub fn check_all(
        writer: &Arc<Mutex<OradazWriter>>,
        client: &Client,
        tokens: &mut HashMap<String, Token>,
    ) -> Result<(), Error> {
        /*
        Check all the prerequisites for the services where a token has been obtained
        */
        info!("{:FL$}Checking prerequisites", "Prerequisites");
        let mut prerequisites_metadata: Vec<PrerequisitesMetadata> = Vec::new();

        // Checking Microsoft Graph API requirements
        let mut skip_resources = true;
        if tokens.get("resources").is_some() {
            skip_resources = false
        }
        let silent: bool = false;
        match tokens.get_mut("graph") {
            None => {
                error!(
                    "{:FL$}Missing Graph API token to check prerequisites",
                    "Prerequisites"
                );
                let metadata = PrerequisitesMetadata {
                    api: String::from("graph"),
                    error: Error::MissingGraphApiToken.to_string(),
                };
                prerequisites_metadata.push(metadata);
                return Err(Error::MissingGraphApiToken);
            }
            Some(token) => {
                // Checking custom application permissions
                if let Err(err) = Prerequisites::check(client, token, skip_resources, silent) {
                    let metadata = PrerequisitesMetadata {
                        api: String::from("graph"),
                        error: err.to_string(),
                    };
                    prerequisites_metadata.push(metadata);
                    return Err(err);
                };
            }
        }

        // Checking Internal API requirements
        match tokens.get_mut("internal") {
            None => {
                error!(
                    "{:FL$}Missing Internal API token to check prerequisites",
                    "Prerequisites"
                );
                let metadata = PrerequisitesMetadata {
                    api: String::from("internal"),
                    error: Error::MissingInternalApiToken.to_string(),
                };
                prerequisites_metadata.push(metadata);
                return Err(Error::MissingInternalApiToken);
            }
            Some(token) => {
                // Checking custom application permissions
                if let Err(err) = Prerequisites::check(client, token, skip_resources, silent) {
                    let metadata = PrerequisitesMetadata {
                        api: String::from("internal"),
                        error: err.to_string(),
                    };
                    prerequisites_metadata.push(metadata);
                    return Err(err);
                };
            }
        }

        // Checking Resources API requirements
        match tokens.get_mut("resources") {
            None => {
                warn!(
                    "{:FL$}Missing Resources API token to check prerequisites. Azure subscriptions will not be audited. If you want to audit them, ensure 'resources' service is set to 1 in config file",
                    "Prerequisites"
                );
                let metadata = PrerequisitesMetadata {
                    api: String::from("resources"),
                    error: Error::MissingResourcesApiToken.to_string(),
                };
                prerequisites_metadata.push(metadata);
                // return Err(Error::MissingResourcesApiToken);
            }
            Some(token) => {
                // Checking custom application permissions
                if let Err(err) = Prerequisites::check(client, token, skip_resources, silent) {
                    let metadata = PrerequisitesMetadata {
                        api: String::from("resources"),
                        error: err.to_string(),
                    };
                    prerequisites_metadata.push(metadata);
                    tokens.remove("resources");
                    warn!(
                        "{:FL$}Subscriptions audit will be skipped due to missing prerequisites",
                        "Prerequisites"
                    );
                    // return Err(err);
                };
            }
        }

        // Checking Exchange Online API requirements
        match tokens.get_mut("exchange") {
            None => {
                warn!(
                    "{:FL$}Missing Exchange Online API token to check prerequisites. Exchange Online will not be audited. If you want to audit it, ensure 'exchange' service is set to 1 in config file",
                    "Prerequisites"
                );
                let metadata = PrerequisitesMetadata {
                    api: String::from("exchange"),
                    error: Error::MissingExchangeApiToken.to_string(),
                };
                prerequisites_metadata.push(metadata);
                // return Err(Error::MissingResourcesApiToken);
            }
            Some(token) => {
                // Checking custom application permissions
                if let Err(err) = Prerequisites::check(client, token, skip_resources, silent) {
                    let metadata = PrerequisitesMetadata {
                        api: String::from("exchange"),
                        error: err.to_string(),
                    };
                    prerequisites_metadata.push(metadata);
                    tokens.remove("exchange");
                    warn!(
                        "{:FL$}Exchange Online audit will be skipped due to missing prerequisites",
                        "Prerequisites"
                    );
                    // return Err(err);
                };
            }
        }

        // Store prerequisites errors in "prerequisites_errors.json" file
        if !prerequisites_metadata.is_empty() {
            let prerequisites_errors_str = match serde_json::to_string(&prerequisites_metadata) {
                Err(err) => {
                    error!(
                        "{:FL$}Could not convert prerequisites_errors to json",
                        "Prerequisites"
                    );
                    debug!("{}", err);
                    return Err(Error::PrerequisitesErrorsToJSON);
                }
                Ok(j) => j,
            };
            match writer.lock() {
                Ok(mut w) => {
                    w.write_file(
                        String::new(),
                        "prerequisites_errors.json".to_string(),
                        prerequisites_errors_str,
                    )?;
                }
                Err(err) => {
                    error!(
                        "{:FL$}Error while locking Writer to write prerequisites errors",
                        "Prerequisites"
                    );
                    debug!("{}", err);
                    return Err(Error::WriterLock);
                }
            }
        }
        Ok(())
    }
}
