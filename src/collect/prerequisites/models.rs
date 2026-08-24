/// Response structs used by prerequisites and conditions modules.
use serde::{Deserialize, Serialize};

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
pub(crate) struct RoleDefinitionTemplateId {
    #[serde(rename = "templateId")]
    pub(crate) template_id: String,
}

#[derive(Deserialize)]
pub(crate) struct RoleDefinition {
    #[serde(rename = "roleDefinition")]
    pub(crate) role_definition: RoleDefinitionTemplateId,
}

#[derive(Deserialize)]
pub(crate) struct RoleAssignmentResponse {
    pub(crate) value: Vec<RoleDefinition>,
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
    #[serde(default, rename = "tenantType")]
    pub tenant_type: Option<String>,
}

#[derive(Deserialize)]
pub struct OrganizationResponse {
    pub value: Vec<Organization>,
}

#[derive(Deserialize)]
pub(crate) struct AppRoleAssignmentItem {
    #[serde(rename = "appRoleId")]
    pub(crate) app_role_id: String,
}

#[derive(Deserialize)]
pub(crate) struct AppRoleAssignmentResponse {
    pub(crate) value: Vec<AppRoleAssignmentItem>,
    #[serde(default, rename = "@odata.nextLink")]
    pub(crate) next_link: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct Subscription {
    #[serde(rename = "displayName")]
    pub(crate) display_name: String,
    #[serde(rename = "subscriptionId")]
    pub(crate) subscription_id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Count {
    #[serde(rename = "type")]
    pub(crate) _count_type: Option<String>,
    #[serde(rename = "value")]
    pub(crate) _value: i32,
}

#[derive(Deserialize)]
pub(crate) struct SubscriptionResponse {
    #[serde(rename = "count")]
    pub(crate) _count: Option<Count>,
    pub(crate) value: Option<Vec<Subscription>>,
    /// ARM paginates the subscriptions list via a top-level `nextLink` (not
    /// `@odata.nextLink`); absent on the last page.
    #[serde(default, rename = "nextLink")]
    pub(crate) next_link: Option<String>,
}

#[derive(Serialize)]
pub struct PrerequisitesMetadata {
    pub api: String,
    pub error: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ServicePrereqInfo {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
