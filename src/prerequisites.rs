use crate::auth;
use crate::errors::Error;
use crate::metadata::PrerequisitesMetadata;

use log::{error, warn, info, debug};
use serde::Deserialize;
use std::collections::HashMap;

const FL: usize = crate::FL;

#[derive(Deserialize)]
struct ResourceAccess {
    id: String,
    #[serde(rename = "type")]
    _scope: String
}

#[derive(Deserialize)]
struct AppPerm {
    #[serde(rename = "resourceAppId")]
    resource_app_id: String,
    #[serde(rename = "resourceAccess")]
    resource_access: Vec<ResourceAccess>
}

#[derive(Deserialize)]
struct ApplicationPermission {
    #[serde(rename = "requiredResourceAccess")]
    required_resource_access: Vec<AppPerm>
}

#[derive(Deserialize)]
struct ApplicationResponse {
    #[serde(rename = "@odata.context")]
    _context: Option<String>,
    value: Option<Vec<ApplicationPermission>>,
}

#[derive(Deserialize)]
struct MeResponse {
    #[serde(rename = "@odata.context")]
    _context: Option<String>,
    id: Option<String>,
}

#[derive(Deserialize)]
struct RoleDefinitionId {
    #[serde(rename = "roleDefinitionId")]
    role_definition_id: String,
}

#[derive(Deserialize)]
struct RoleAssignmentResponse {
    #[serde(rename = "@odata.context")]
    _context: Option<String>,
    value: Option<Vec<RoleDefinitionId>>,
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

fn http_get(url: &str, access_token: &str, client: &reqwest::blocking::Client) -> Result<reqwest::blocking::Response, Error> {
    match client.get(url).header(reqwest::header::AUTHORIZATION, &format!("Bearer {}", access_token)).send() {
        Ok(r) => Ok(r),
        Err(e) => {
            error!("{:FL$}Could not check prerequisites.", "http_get");
            error!("{:FL$}\t{}", "", e);
            return Err(Error::PrerequisitesCheckError);
        }
    }
}

fn check_app_permissions(tokens: &HashMap<String, auth::TokenResponse>, app_id: &str, client: &reqwest::blocking::Client) -> Result<(), Error> {
    let grap_api_permissions = HashMap::from([
        ("ebfcd32b-babb-40f4-a14b-42706e83bd28", "AccessReview.Read.All"),
        ("1b6ff35f-31df-4332-8571-d31ea5a4893f", "APIConnectors.Read.All"),
        ("e4c9e354-4dc5-45b8-9e7c-e1393b0b1a20", "AuditLog.Read.All"),
        ("b46ffa80-fe3d-4822-9a1a-c200932d54d0", "CustomSecAttributeAssignment.Read.All"),
        ("ce026878-a0ff-4745-a728-d4fedd086c07", "CustomSecAttributeDefinition.Read.All"),
        ("06da0dbc-49e2-44d2-8312-53f166ab848a", "Directory.Read.All"),
        ("2f9ee017-59c1-4f1d-9472-bd5529a7b311", "Domain.Read.All"),
        ("5449aa12-1393-4ea2-a7c7-d0e06c1a56b2", "EntitlementManagement.Read.All"),
        ("43781733-b5a7-4d1b-98f4-e8edff23e1a9", "IdentityProvider.Read.All"),
        ("8f6a01e7-0391-4ee5-aa22-a3af122cef27", "IdentityRiskEvent.Read.All"),
        ("ea5c4ab0-5a73-4f35-8272-5d5337884e5d", "IdentityRiskyServicePrincipal.Read.All"),
        ("d04bb851-cb7c-4146-97c7-ca3e71baf56c", "IdentityRiskyUser.Read.All"),
        ("2903d63d-4611-4d43-99ce-a33f3f52e343", "IdentityUserFlow.Read.All"),
        ("f6609722-4100-44eb-b747-e6ca0536989d", "OnPremDirectorySynchronization.Read.All"),
        ("4908d5b9-3fb2-4b1e-9336-1888b7937185", "Organization.Read.All"),
        ("572fea84-0151-49b2-9301-11cb16974376", "Policy.Read.All"),
        ("414de6ea-2d92-462f-b120-6e2a809a6d01", "Policy.Read.PermissionGrant"),
        ("b3a539c9-59cb-4ad5-825a-041ddbdc2bdb", "PrivilegedAccess.Read.AzureAD"),
        ("d329c81c-20ad-4772-abf9-3f6fdb7e5988", "PrivilegedAccess.Read.AzureADGroup"),
        ("1d89d70c-dcac-4248-b214-903c457af83a", "PrivilegedAccess.Read.AzureResources"),
        ("02e97553-ed7b-43d0-ab3c-f8bace0d040c", "Reports.Read.All"),
        ("344a729c-0285-42c6-9014-f12b9b8d6129", "RoleAssignmentSchedule.Read.Directory"),
        ("eb0788c2-6d4e-4658-8c9e-c0fb8053f03d", "RoleEligibilitySchedule.Read.Directory"),
        ("48fec646-b2ba-4019-8681-8eb31435aded", "RoleManagement.Read.All"),
        ("64733abd-851e-478a-bffb-e47a14b18235", "SecurityEvents.Read.All"),
        ("a154be20-db9c-4678-8ab7-66f6cc099a59", "User.Read.All"),
        ("aec28ec7-4d02-4e8c-b864-50163aea77eb", "UserAuthenticationMethod.Read.All")
    ]);
    info!("{:FL$}Checking application permissions", "check_app_permissions");
    match tokens.get("graphAPI") {
        None => {
            error!("{:FL$}Missing Graph API token to check prerequisites", "check_app_permissions");
            return Err(Error::MissingApiTokenError)
        },
        Some(token) => {
            match &token.access_token {
                None => {
                    error!("{:FL$}Missing Graph API token to check prerequisites", "check_app_permissions");
                    return Err(Error::MissingApiTokenError)
                },
                Some(access_token) => {
                    let response = match http_get(&format!("https://graph.microsoft.com/v1.0/applications?$filter=appId eq '{}'&$select=requiredResourceAccess", app_id), access_token, client) {
                        Err(_e) => {
                            error!("{:FL$}Cannot retrieve custom application to check permissions", "check_app_permissions");
                            return Err(Error::CannotRetrieveAppError);
                        },
                        Ok(res) => res
                    };
                    let application: ApplicationResponse = response.json().unwrap();
                    match &application.value {
                        None => {
                            error!("{:FL$}Missing required permission for Microsoft Graph API to read application", "check_app_permissions");
                            return Err(Error::MissingAppPermissionError);
                        },
                        Some(value) => {
                            for app in value {
                                for access in &app.required_resource_access {
                                    if access.resource_app_id == "797f4846-ba00-4fd7-ba43-dac1f8f63013" {
                                        let mut found: bool = false;
                                        for perm in &access.resource_access {
                                            if perm.id == "41094075-9dad-400e-a0bd-54e686782033" {
                                                found = true;
                                            }
                                        }
                                        if !found {
                                            error!("{:FL$}Missing user_impersonation for Azure Service Management API", "check_app_permissions");
                                            return Err(Error::MissingAppPermissionError);
                                        }
                                    } else if access.resource_app_id == "00000003-0000-0000-c000-000000000000" {
                                        let mut matched: Vec<String> = Vec::new();
                                        for perm in &access.resource_access {
                                            let perm_id: &str = &perm.id;
                                            if grap_api_permissions.contains_key(&perm_id) {
                                                // info!("{:FL$}\t- {} OK", "", &perm_id);
                                                matched.push((&perm_id).to_string());
                                            }
                                        }
                                        if grap_api_permissions.keys().len() != matched.len() {
                                            error!("{:FL$}Missing required delegated permission(s) for Microsoft Graph API:", "check_app_permissions");
                                            for (perm_id, perm_name) in grap_api_permissions.into_iter() {
                                                if !matched.contains(&(&perm_id).to_string()){
                                                    error!("{:FL$}\t- {}", "", perm_name);
                                                }
                                            }
                                            return Err(Error::MissingAppPermissionError);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            };
        }
    }
    Ok(())
}

fn check_aad_permissions(tokens: &HashMap<String, auth::TokenResponse>, client: &reqwest::blocking::Client) -> Result<(), Error> {
    // TODO: Check by permissions instead of role
    let matching_roles: Vec<Vec<&str>> = vec![
        vec!["62e90394-69f5-4237-9190-012177145e10"], // Global Administrator
        vec!["f2ef992c-3afb-46b9-b7cf-a126ee74c451", "5d6b6bb7-de71-4623-b4af-96380a352509"], // Global Reader & Security Reader
    ];
    info!("{:FL$}Checking user roles", "check_aad_permissions");

    match tokens.get("graphAPI") {
        None => {
            error!("{:FL$}Missing Graph API token to check prerequisites", "check_aad_permissions");
            return Err(Error::MissingApiTokenError)
        },
        Some(token) => {
            match &token.access_token {
                None => {
                    error!("{:FL$}Missing Graph API token to check prerequisites", "check_aad_permissions");
                    return Err(Error::MissingApiTokenError)
                },
                Some(access_token) => {
                    let response = match http_get("https://graph.microsoft.com/v1.0/me?$select=id", access_token, client) {
                        Err(_e) => {
                            error!("{:FL$}Cannot retrieve custom application to check permissions", "check_aad_permissions");
                            return Err(Error::CannotRetrieveAppError);
                        },
                        Ok(res) => res
                    };
                    let me: MeResponse = response.json().unwrap();
                    match me.id {
                        None => {
                            error!("{:FL$}Cannot retrieve current user to check role", "check_aad_permissions");
                            return Err(Error::CannotRetrieveCurrentUserError);
                        },
                        Some(id) => {
                            let response = match http_get(&format!("https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?&$filter=principalId eq '{}'&$select=roleDefinitionId", &id), access_token, client) {
                                Err(_e) => {
                                    error!("{:FL$}Cannot retrieve role assignments for current user", "check_aad_permissions");
                                    return Err(Error::CannotRetrieveCurrentUserRolesError);
                                },
                                Ok(res) => res
                            };
                            let role_assignments: RoleAssignmentResponse = response.json().unwrap();
                            match &role_assignments.value {
                                None => {
                                    error!("{:FL$}Cannot retrieve role assignments for current user", "check_aad_permissions");
                                    return Err(Error::CannotRetrieveCurrentUserRolesError);
                                },
                                Some(value) => {
                                    let mut found: bool = false;
                                    for requirement in &matching_roles {
                                        if requirement.iter().all(|&x| value.iter().any(|role| role.role_definition_id == x)) {
                                            found = true;
                                        }
                                    }
                                    if !found {
                                        error!("{:FL$}User is missing a role (Security Reader or Global Reader)", "check_aad_permissions");
                                        return Err(Error::MissingAzureAdRoleError);
                                    }
                                }
                            }
                        }
                    }
                }
            };
        }
    }
    Ok(())
}

fn check_available_subscriptions(tokens: &HashMap<String, auth::TokenResponse>, client: &reqwest::blocking::Client) -> Result<(), Error> {
    info!("{:FL$}Checking available subscriptions", "check_available_subscriptions");
    match tokens.get("mgmtAPI") {
        None => {
            debug!("{:FL$}No token for Azure Resource Management, no subscription will be audited", "check_available_subscriptions");
            return Err(Error::ApiNotInSchemaError)
        },
        Some(token) => {
            match &token.access_token {
                None => {
                    error!("{:FL$}No token for Azure Resource Management, no subscription will be audited", "check_available_subscriptions");
                    return Err(Error::MissingApiTokenError)
                },
                Some(access_token) => {
                    let response = match http_get("https://management.azure.com/subscriptions?api-version=2020-08-01", access_token, client) {
                        Err(_e) => {
                            error!("{:FL$}Cannot retrieve subscriptions", "check_available_subscriptions");
                            return Err(Error::CannotRetrieveSubscriptionsError);
                        },
                        Ok(res) => res
                    };
                    let subscriptions: SubscriptionResponse = response.json().unwrap();
                    match &subscriptions.value {
                        None => {
                            error!("{:FL$}Cannot retrieve subscriptions", "check_available_subscriptions");
                            return Err(Error::CannotRetrieveSubscriptionsError);
                        },
                        Some(subs) => {
                            if subs.is_empty() {
                                warn!("{:FL$}User has no read permission on any subscription", "check_available_subscriptions");
                                return Err(Error::NoSubscriptionError);
                            } else {
                                info!("{:FL$}Reader role has been provided to the following subscriptions which will be audited:", "check_available_subscriptions");
                                for sub in subs {
                                    info!("{:FL$}\t- {}", "", sub.display_name);
                                }
                            }
                        }
                    };
                }
            };
        }
    }
    Ok(())
}

fn check_outlook_permissions(tokens: &HashMap<String, auth::TokenResponse>, tenant: &str, client: &reqwest::blocking::Client) -> Result<(), Error> {
    info!("{:FL$}Checking outlook permissions", "check_outlook_permissions");
    // TODO: find a better way to do this
    match tokens.get("outlookAPI") {
        None => {
            debug!("{:FL$}No token for Exchange Online API, mailbox delegations will not be audited", "check_outlook_permissions");
            return Err(Error::ApiNotInSchemaError);
        },
        Some(token) => {
            match &token.access_token {
                None => {
                    error!("{:FL$}No token for Exchange Online API, mailbox delegations will not be audited", "check_outlook_permissions");
                    return Err(Error::MissingApiTokenError);
                },
                Some(access_token) => {
                    let response = match http_get(&format!("https://outlook.office365.com/adminapi/beta/{}/Mailbox?$top=1&$select=UserPrincipalName", tenant), access_token, client) {
                        Err(_e) => {
                            error!("{:FL$}Cannot retrieve mailboxes", "check_outlook_permissions");
                            return Err(Error::CannotRetrieveMailboxesError);
                        },
                        Ok(res) => res
                    };
                    let mailboxes: MailboxResponse = response.json().unwrap();
                    match &mailboxes.value {
                        None => {
                            error!("{:FL$}Cannot retrieve mailboxes", "check_outlook_permissions");
                            return Err(Error::CannotRetrieveMailboxesError);
                        },
                        Some(mailboxes) => {
                            if mailboxes.is_empty() {
                                error!("{:FL$}Cannot retrieve mailboxes", "check_outlook_permissions");
                                return Err(Error::CannotRetrieveMailboxesError)
                            } else if let Some(mailbox) = mailboxes.iter().next() {
                                let username: &str = &mailbox.user_principal_name;
                                let response = match http_get(&format!("https://outlook.office365.com/adminapi/beta/{}/Recipient('{}')?$expand=RecipientPermission", tenant, &username), access_token, client) {
                                    Err(_e) => {
                                        error!("{:FL$}Missing permission to retrieve mailbox recipients", "check_outlook_permissions");
                                        return Err(Error::MissingExchangeOnlinePermissionsError);
                                    },
                                    Ok(res) => res
                                };
                                let permissions: RecipientPermissionResponse = response.json().unwrap();
                                match &permissions.id {
                                    None => {
                                        error!("{:FL$}Missing permission to retrieve mailbox recipients", "check_outlook_permissions");
                                        return Err(Error::MissingExchangeOnlinePermissionsError);
                                    },
                                    Some(_e) => ()
                                }
                            }
                        }
                    };
                }
            };
        }
    }
    info!("{:FL$}OK", "check_outlook_permissions");
    Ok(())
}

pub fn check(tokens: &mut HashMap<String, auth::TokenResponse>, tenant: &str, app_id: &str, client: &reqwest::blocking::Client) -> Result<Vec<PrerequisitesMetadata>, Error> {
    let mut prerequisites_metadata: Vec<PrerequisitesMetadata> = Vec::new();

    // Checking custom application permissions
    match check_app_permissions(tokens, app_id, client) {
        Ok(()) => info!("{:FL$}Custom application permissions match required ones", "check"),
        Err(e) => {
            error!("{:FL$}Please add the required permission for the application", "check");
            return Err(e)
        }
    }

    // Checking that current user has required Azure AD permissions
    match check_aad_permissions(tokens, client) {
        Ok(()) => info!("{:FL$}Current user has required permissions over Azure AD", "check"),
        Err(e) => {
            error!("{:FL$}Please verify the roles of the user and perform another the dump", "check");
            return Err(e)
        }
    }

    // Check subscriptions that will be audited
    match check_available_subscriptions(tokens, client) {
        Ok(()) => info!("{:FL$}The available subscriptions will be audited", "check"),
        Err(e) => {
            match e {
                Error::ApiNotInSchemaError => (),
                Error::MissingApiTokenError => (),
                _ => error!("{:FL$}Missing permissions to audit Azure resource. If you want to audit a subscription, add the Reader role on it to your user. Skipping this part for now", "check")
            };
            let metadata = PrerequisitesMetadata {
                name: String::from("mgmtAPI"),
                error: format!("{}", e)
            };
            prerequisites_metadata.push(metadata);
            //tokens.remove_entry("mgmtAPI");
        }
    }
    

    // Check if Get-RecipientPermission permissions has been provided
    match check_outlook_permissions(tokens, tenant, client) {
        Ok(()) => info!("{:FL$}Current user has required Exchange Online permissions", "check"),
        Err(e) => {
            match e {
                Error::ApiNotInSchemaError => (),
                Error::MissingApiTokenError => (),
                _ => error!("{:FL$}Missing permissions to audit Exchange Online, skipping it", "check")
            };
            let metadata = PrerequisitesMetadata {
                name: String::from("outlookAPI"),
                error: format!("{}", e)
            };
            prerequisites_metadata.push(metadata);
            tokens.remove_entry("outlookAPI");
        }
    }

    Ok(prerequisites_metadata)
}