use crate::auth::Token;
use crate::prerequisites::{OrganizationResponse, PIMRoleAssignmentScheduleInstancesResponse};

use chrono::{DateTime, Utc};
use log::{debug, warn};
use reqwest::blocking::Client;
use serde_json::Value;
use url::Url;

const FL: usize = crate::FL;

pub struct Conditions {}

impl Conditions {
    pub fn check(client: &Client, token: &Token, condition: String) -> bool {
        match condition {
            c if &c == "P1" => Conditions::check_tenant_for_p1_licence(client, token),
            c if &c == "NotP1" => !Conditions::check_tenant_for_p1_licence(client, token),
            c if &c == "P2" => Conditions::check_tenant_for_p2_licence(client, token),
            c if &c == "NotP2" => !Conditions::check_tenant_for_p2_licence(client, token),
            c if &c == "Intune" => Conditions::check_tenant_for_intune_licence(client, token),
            c if &c == "GA" => Conditions::check_user_for_ga(client, token),
            c => {
                warn!(
                    "{:FL$}Invalid condition {:?} in schema file. Considering condition as not meet.",
                    "Conditions", c
                );
                false
            }
        }
    }

    pub fn check_tenant_for_p1_licence(client: &Client, token: &Token) -> bool {
        /*
        Check if tenant has a P1 (or P2) Entra ID licence
        */
        debug!(
            "{:FL$}Checking if tenant has a P1 (or P2) Entra ID licence",
            "Conditions"
        );
        let string_url: String = String::from("https://graph.microsoft.com/v1.0/organization");
        let url: Url = match Url::parse(&string_url) {
            Ok(u) => u,
            Err(err) => {
                debug!(
                    "{:FL$}Cannot create url to retrieve current organization",
                    "Conditions"
                );
                debug!("{}", err);
                return false;
            }
        };
        let response = match client
            .get(url)
            .header(
                reqwest::header::AUTHORIZATION,
                &format!("Bearer {}", token.access_token.secret()),
            )
            .send()
        {
            Err(err) => {
                debug!(
                    "{:FL$}Cannot retrieve organization to check P1 licence",
                    "Conditions"
                );
                debug!("{}", err);
                return false;
            }
            Ok(res) => res,
        };

        match response.json::<OrganizationResponse>() {
            Ok(organization) => {
                if organization.value.into_iter().any(|org| {
                    org.assigned_plans.iter().any(|x| {
                        // Tenant has Entra ID Premium P1 licence
                        &x.capability_status == "Enabled"
                            && &x.service_plan_id == "41781fb2-bc02-4b7c-bd55-b576c07bb09d"
                    })
                }) {
                    true
                } else {
                    false
                }
            }
            Err(err) => {
                debug!("{:FL$}Error parsing organization", "Conditions");
                debug!("{}", err);
                false
            }
        }
    }

    pub fn check_tenant_for_p2_licence(client: &Client, token: &Token) -> bool {
        /*
        Check if tenant has a P2 Entra ID licence
        */
        debug!(
            "{:FL$}Checking if tenant has a P2 Entra ID licence",
            "Conditions"
        );
        let string_url: String = String::from("https://graph.microsoft.com/v1.0/organization");
        let url: Url = match Url::parse(&string_url) {
            Ok(u) => u,
            Err(err) => {
                debug!(
                    "{:FL$}Cannot create url to retrieve current organization",
                    "Conditions"
                );
                debug!("{}", err);
                return false;
            }
        };
        let response = match client
            .get(url)
            .header(
                reqwest::header::AUTHORIZATION,
                &format!("Bearer {}", token.access_token.secret()),
            )
            .send()
        {
            Err(err) => {
                debug!(
                    "{:FL$}Cannot retrieve organization to check P2 licence",
                    "Conditions"
                );
                debug!("{}", err);
                return false;
            }
            Ok(res) => res,
        };

        match response.json::<OrganizationResponse>() {
            Ok(organization) => {
                if organization.value.into_iter().any(|org| {
                    org.assigned_plans.iter().any(|x| {
                        // Tenant has Entra ID Premium P2 licence
                        &x.capability_status == "Enabled"
                            && &x.service_plan_id == "eec0eb4f-6444-4f95-aba0-50c24d67f998"
                    })
                }) {
                    true
                } else {
                    false
                }
            }
            Err(err) => {
                debug!("{:FL$}Error parsing organization", "Conditions");
                debug!("{}", err);
                false
            }
        }
    }

    pub fn check_tenant_for_intune_licence(client: &Client, token: &Token) -> bool {
        /*
        Check if tenant has an Intune Plan 1 licence
        */
        debug!(
            "{:FL$}Checking if tenant has an Intune Plan 1 licence",
            "Conditions"
        );
        let string_url: String = String::from("https://graph.microsoft.com/v1.0/organization");
        let url: Url = match Url::parse(&string_url) {
            Ok(u) => u,
            Err(err) => {
                debug!(
                    "{:FL$}Cannot create url to retrieve current organization",
                    "Conditions"
                );
                debug!("{}", err);
                return false;
            }
        };
        let response = match client
            .get(url)
            .header(
                reqwest::header::AUTHORIZATION,
                &format!("Bearer {}", token.access_token.secret()),
            )
            .send()
        {
            Err(err) => {
                debug!(
                    "{:FL$}Cannot retrieve organization to check Intune licence",
                    "Conditions"
                );
                debug!("{}", err);
                return false;
            }
            Ok(res) => res,
        };

        match response.json::<OrganizationResponse>() {
            Ok(organization) => {
                if organization.value.into_iter().any(|org| {
                    org.assigned_plans.iter().any(|x| {
                        // Tenant has an Intune Plan 1 licence
                        &x.capability_status == "Enabled"
                            && &x.service_plan_id == "c1ec4a95-1f05-45b3-a911-aa3fa01094f5"
                    })
                }) {
                    true
                } else {
                    false
                }
            }
            Err(err) => {
                debug!("{:FL$}Error parsing organization", "Conditions");
                debug!("{}", err);
                false
            }
        }
    }

    pub fn check_user_for_ga(client: &Client, token: &Token) -> bool {
        /*
        Check if current user is Global Administrator
        */
        debug!(
            "{:FL$}Checking if current user is Global Administrator",
            "Conditions"
        );
        if Conditions::check_tenant_for_p2_licence(client, token) {
            // Tenant has Entra ID Premium P2 licence, meaning PIM is enabled
            let string_url: String = format!("https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$select=endDateTime,roleDefinition&$expand=roleDefinition($select=templateId)&$filter=(principalId eq '{}')", token.user_id);
            let url: Url = match Url::parse(&string_url) {
                Ok(u) => u,
                Err(err) => {
                    debug!(
                        "{:FL$}Cannot create url to retrieve current user PIM role assignments",
                        "Conditions"
                    );
                    debug!("{}", err);
                    return false;
                }
            };
            let response = match client
                .get(url)
                .header(
                    reqwest::header::AUTHORIZATION,
                    &format!("Bearer {}", token.access_token.secret()),
                )
                .send()
            {
                Err(err) => {
                    debug!(
                        "{:FL$}Cannot retrieve current user PIM role assignments",
                        "Conditions"
                    );
                    debug!("{}", err);
                    return false;
                }
                Ok(res) => res,
            };

            match response.json::<PIMRoleAssignmentScheduleInstancesResponse>() {
                Ok(role_assignments) => {
                    for role in role_assignments.value.iter() {
                        if role.role_definition.template_id
                            == "62e90394-69f5-4237-9190-012177145e10"
                        {
                            match &role.end_date_time {
                                None => return true,
                                Some(end_date_time) => {
                                    match end_date_time.parse::<DateTime<Utc>>() {
                                        Err(err) => {
                                            debug!(
                                                "{:FL$}Error parsing endDateTime value for PIM role assignments for current user",
                                                "Conditions"
                                            );
                                            debug!("{} - {}", end_date_time, err);
                                            return false;
                                        }
                                        Ok(d) => {
                                            if d.timestamp() > Utc::now().timestamp() {
                                                return true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    false
                }
                Err(err) => {
                    debug!(
                        "{:FL$}Error parsing current user PIM role assignments",
                        "Conditions"
                    );
                    debug!("{}", err);
                    false
                }
            }
        } else {
            let string_url = format!(
                "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$select=roleDefinition&$expand=roleDefinition($select=templateId)&$filter=(principalId eq '{}') and (roleDefinition/templateId eq '62e90394-69f5-4237-9190-012177145e10')",
                token.user_id
            );
            let url: Url = match Url::parse(&string_url) {
                Ok(u) => u,
                Err(err) => {
                    debug!(
                        "{:FL$}Cannot create url to retrieve current user role assignments",
                        "Conditions"
                    );
                    debug!("{}", err);
                    return false;
                }
            };
            let response = match client
                .get(url)
                .header(
                    reqwest::header::AUTHORIZATION,
                    &format!("Bearer {}", token.access_token.secret()),
                )
                .send()
            {
                Err(err) => {
                    debug!(
                        "{:FL$}Cannot retrieve current user role assignments",
                        "Conditions"
                    );
                    debug!("{}", err);
                    return false;
                }
                Ok(res) => res,
            };
            match response.json::<PIMRoleAssignmentScheduleInstancesResponse>() {
                Ok(role_assignments) => {
                    for role in role_assignments.value.iter() {
                        if role.role_definition.template_id
                            == "62e90394-69f5-4237-9190-012177145e10"
                        {
                            return true;
                        }
                    }
                    false
                }
                Err(err) => {
                    debug!(
                        "{:FL$}Error parsing current user role assignments",
                        "Conditions"
                    );
                    debug!("{}", err);
                    false
                }
            }
        }
    }

    pub fn check_if_unified_group(value: &Value) -> bool {
        /*
        Check in value if group is a Unified group
        */
        debug!("{:FL$}Checking if group is a Unified group", "Conditions");
        if let Some(grouptypes_field) = value.pointer("/groupTypes") {
            match grouptypes_field.as_array() {
                None => {
                    debug!(
                        "{:FL$}groupTypes field is not a valid array, considering as not Unified",
                        "Conditions"
                    );
                    return false;
                }
                Some(gt) => {
                    return gt
                        .iter()
                        .map(|v| v.to_string())
                        .collect::<Vec<String>>()
                        .contains(&String::from("Unified"));
                }
            }
        };
        debug!(
            "{:FL$}Missing groupTypes field to check, considering as not Unified",
            "Conditions"
        );
        false
    }
}
