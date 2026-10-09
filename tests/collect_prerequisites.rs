// Tests for Prerequisites checks
mod common;

use crate::common::default_test_config;
use base64::prelude::*;
use oradaz::collect::auth::tokens::Token;
use oradaz::collect::prerequisites::graph::{
    check_app_permissions, check_app_permissions_for_client_credentials,
    check_app_permissions_for_managed_identity,
};
use oradaz::collect::prerequisites::resources::check_available_subscriptions;
use oradaz::collect::prerequisites::{PrereqCheckOptions, Prerequisites, UrlOverrides};
use oradaz::utils::client::OradazClient;
use oradaz::utils::errors::Error;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Required delegated Graph scopes (values of `GRAPH_API_PERMISSIONS` in
/// src/collect/prerequisites/graph/constants.rs). Kept here verbatim so
/// the test breaks loudly if the constant drifts.
const REQUIRED_GRAPH_DELEGATED_SCOPES: &[&str] = &[
    "AccessReview.Read.All",
    "APIConnectors.Read.All",
    "AppCertTrustConfiguration.Read.All",
    "AuditLog.Read.All",
    "CustomSecAttributeAssignment.Read.All",
    "CustomSecAttributeDefinition.Read.All",
    "CrossTenantInformation.ReadBasic.All",
    "DelegatedAdminRelationship.Read.All",
    "DeviceManagementApps.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementRBAC.Read.All",
    "Directory.Read.All",
    "Domain.Read.All",
    "EntitlementManagement.Read.All",
    "IdentityProvider.Read.All",
    "IdentityRiskEvent.Read.All",
    "IdentityRiskyServicePrincipal.Read.All",
    "IdentityRiskyUser.Read.All",
    "IdentityUserFlow.Read.All",
    "MultiTenantOrganization.Read.All",
    "OnPremDirectorySynchronization.Read.All",
    "Organization.Read.All",
    "Policy.Read.All",
    "Policy.Read.PermissionGrant",
    "PrivilegedAccess.Read.AzureAD",
    "PrivilegedAccess.Read.AzureADGroup",
    "PrivilegedAccess.Read.AzureResources",
    "PrivilegedAssignmentSchedule.Read.AzureADGroup",
    "PrivilegedEligibilitySchedule.Read.AzureADGroup",
    "PublicKeyInfrastructure.Read.All",
    "Reports.Read.All",
    "ResourceSpecificPermissionGrant.ReadForUser",
    "RoleAssignmentSchedule.Read.Directory",
    "RoleEligibilitySchedule.Read.Directory",
    "RoleManagementPolicy.Read.AzureADGroup",
    "RoleManagement.Read.All",
    "SecurityEvents.Read.All",
    "UserAuthenticationMethod.Read.All",
    "User.Read.All",
];

/// Required application permissions (values of `GRAPH_API_APP_ONLY_PERMISSIONS`).
const REQUIRED_GRAPH_APP_ROLES: &[&str] = &[
    "AccessReview.Read.All",
    "APIConnectors.Read.All",
    "AuditLog.Read.All",
    "CustomSecAttributeAssignment.Read.All",
    "CustomSecAttributeDefinition.Read.All",
    "CrossTenantInformation.ReadBasic.All",
    "DelegatedAdminRelationship.Read.All",
    "DeviceManagementApps.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementRBAC.Read.All",
    "Directory.Read.All",
    "Domain.Read.All",
    "EntitlementManagement.Read.All",
    "IdentityProvider.Read.All",
    "IdentityRiskEvent.Read.All",
    "IdentityRiskyServicePrincipal.Read.All",
    "IdentityRiskyUser.Read.All",
    "IdentityUserFlow.Read.All",
    "MultiTenantOrganization.Read.All",
    "OnPremDirectorySynchronization.Read.All",
    "Organization.Read.All",
    "Policy.Read.All",
    "Policy.Read.PermissionGrant",
    "PrivilegedAccess.Read.AzureAD",
    "PrivilegedAccess.Read.AzureADGroup",
    "PrivilegedAccess.Read.AzureResources",
    "PrivilegedAssignmentSchedule.Read.AzureADGroup",
    "PrivilegedEligibilitySchedule.Read.AzureADGroup",
    "PublicKeyInfrastructure.Read.All",
    "Reports.Read.All",
    "ResourceSpecificPermissionGrant.ReadForUser.All",
    "RoleAssignmentSchedule.Read.Directory",
    "RoleEligibilitySchedule.Read.Directory",
    "RoleManagementPolicy.Read.AzureADGroup",
    "RoleManagement.Read.All",
    "SecurityEvents.Read.All",
    "UserAuthenticationMethod.Read.All",
    "User.Read.All",
];

/// Required application role IDs returned by the managed-identity
/// `appRoleAssignments` endpoint. These literals stay independent from the
/// production map so a missing or incorrect required role is observable.
const REQUIRED_GRAPH_APP_ROLE_IDS: &[&str] = &[
    "d07a8cc0-3d51-4b77-b3b0-32704d1f69fa",
    "b86848a7-d5b1-41eb-a9b4-54a4e6306e97",
    "b0afded3-3588-46d8-8b3d-9842eff778da",
    "3b37c5a4-1226-493d-bec3-5d6c6b866f3f",
    "b185aa14-d8d2-42c1-a685-0f5596613624",
    "cac88765-0581-4025-9725-5ebc13f729ee",
    "f6e9e124-4586-492f-adc0-c6f96e4823fd",
    "7a6ee1e7-141e-4cec-ae74-d9db155731ff",
    "dc377aa6-52d8-4e23-b271-2a7ae04cedf3",
    "2f51be20-0bb4-4fed-bf7b-db946066c75e",
    "58ca0d9a-1575-47e1-a3cb-007ef2e4583b",
    "7ab1d382-f21e-4acd-a863-ba3e13f7da61",
    "dbb9058a-0e50-45d7-ae91-66909b5d4664",
    "c74fd47d-ed3c-45c3-9a9e-b8676de685d2",
    "e321f0bb-e7f7-481e-bb28-e3b0b32d4bd0",
    "6e472fd1-ad78-48da-a0f0-97ab2c6b769e",
    "607c7344-0eed-41e5-823a-9695ebe1b7b0",
    "dc5007c0-2d7d-4c42-879c-2dab87571379",
    "1b0c317f-dd31-4305-9932-259a8b6e8099",
    "4f994bc0-31bb-44bb-b480-7a7c1be8c02e",
    "bb70e231-92dc-4729-aff5-697b3f04be95",
    "498476ce-e0fe-48b0-b801-37ba7e2685c6",
    "246dd0d5-5bd0-4def-940b-0421030a5b68",
    "9e640839-a198-48fb-8b9a-013fd6f6cbcd",
    "4cdc2547-9148-4295-8d11-be0db1391d6b",
    "01e37dc9-c035-40bd-b438-b2879c4870a6",
    "5df6fe86-1be0-44eb-b916-7bd443a71236",
    "cd4161cb-f098-48f8-a884-1eda9a42434c",
    "edb419d6-7edc-42a3-9345-509bfdf5d87c",
    "214fda0c-514a-4650-b037-b562b1a66124",
    "230c1aed-a721-4c5d-9cb4-a90514e508ef",
    "acfca4d5-f49f-40ed-9648-84068b474c73",
    "d5fe8ce8-684c-4c83-a52c-46e882ce4be1",
    "ff278e11-4a33-4d0c-83d2-d01dc58929a5",
    "69e67828-780e-47fd-b28c-7b27d14864e6",
    "c7fbd983-d9aa-4fa7-84b8-17382c103bc4",
    "bf394140-e372-4bf9-a898-299cfc7564e5",
    "38d9df27-64da-44fd-b7c5-a6fbac20248f",
    "df021288-bdef-4463-88db-98f22de89214",
];

fn fake_jwt(payload: &serde_json::Value) -> String {
    let header = BASE64_URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
    let body = BASE64_URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
    format!("{header}.{body}.sig")
}

fn make_token(service: &str, access_token: String) -> Token {
    Token {
        tenant_id: "test-tenant".to_string(),
        client_id: "test-client".to_string(),
        service: service.to_string(),
        expires_on: 9_999_999_999,
        access_token,
        refresh_token: None,
        token_type: "Bearer".to_string(),
        user_id: "sp-oid-1234".to_string(),
        user_principal_name: String::new(),
        scopes: vec![],
    }
}

fn token_with_scopes(service: &str, scopes: &[&str]) -> Token {
    let payload = serde_json::json!({
        "scp": scopes.join(" "),
        "oid": "user-oid",
    });
    make_token(service, fake_jwt(&payload))
}

fn token_with_roles(service: &str, roles: &[&str]) -> Token {
    let payload = serde_json::json!({
        "roles": roles,
        "oid": "sp-oid-1234",
    });
    make_token(service, fake_jwt(&payload))
}

fn options_with_overrides(
    overrides: UrlOverrides,
    use_application_credentials: bool,
) -> PrereqCheckOptions {
    PrereqCheckOptions {
        silent: true,
        overrides,
        use_application_credentials,
        use_managed_identity: false,
        default_retry_after: 0,
    }
}

// --- Invalid service ---

#[tokio::test]
async fn test_prerequisites_check_invalid_service_returns_err() {
    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    let token = token_with_scopes("invalid_service", &[]);

    let result = Prerequisites::check(&client.client, &token, true, false, false, 0).await;
    assert!(matches!(result, Err(Error::InvalidTokenToCheck)));
}

// --- Graph (delegated) ---

#[tokio::test]
async fn test_graph_delegated_missing_scope_returns_err() {
    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    // Token carries no scp at all → all Graph scopes are missing.
    let token = token_with_scopes("graph", &[]);

    let result = Prerequisites::check_with_overrides(
        &client.client,
        &token,
        options_with_overrides(
            UrlOverrides {
                graph: None,
                resources: None,
                exchange: None,
            },
            false,
        ),
    )
    .await;
    assert!(
        matches!(result, Err(Error::MissingAppPermission)),
        "Expected MissingAppPermission, got: {result:?}"
    );
}

#[test]
fn test_graph_delegated_missing_only_cross_tenant_information_returns_err() {
    let scopes: Vec<&str> = REQUIRED_GRAPH_DELEGATED_SCOPES
        .iter()
        .copied()
        .filter(|scope| *scope != "CrossTenantInformation.ReadBasic.All")
        .collect();
    let token = token_with_scopes("graph", &scopes);

    let result = check_app_permissions(&token, true);

    assert!(
        matches!(result, Err((Error::MissingAppPermission, ref missing))
            if missing == &["CrossTenantInformation.ReadBasic.All"]),
        "Expected only CrossTenantInformation.ReadBasic.All to be missing, got: {result:?}"
    );
}

#[tokio::test]
async fn test_graph_delegated_all_scopes_present_returns_ok() {
    let mock = MockServer::start().await;

    // PIM disabled
    Mock::given(method("GET"))
        .and(path("/v1.0/organization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "assignedPlans": [] }]
        })))
        .mount(&mock)
        .await;

    // Global Administrator role assignment for the user
    Mock::given(method("GET"))
        .and(path("/v1.0/roleManagement/directory/roleAssignments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "roleDefinition": { "templateId": "62e90394-69f5-4237-9190-012177145e10" }
            }]
        })))
        .mount(&mock)
        .await;

    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    let token = token_with_scopes("graph", REQUIRED_GRAPH_DELEGATED_SCOPES);

    let result = Prerequisites::check_with_overrides(
        &client.client,
        &token,
        options_with_overrides(
            UrlOverrides {
                graph: Some(mock.uri()),
                resources: None,
                exchange: None,
            },
            false,
        ),
    )
    .await;
    assert!(result.is_ok(), "Expected Ok(()), got: {result:?}");
}

// --- Graph (client credentials) ---

#[tokio::test]
async fn test_graph_client_credentials_missing_role_returns_err() {
    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    let token = token_with_roles("graph", &[]);

    let result = Prerequisites::check_with_overrides(
        &client.client,
        &token,
        options_with_overrides(
            UrlOverrides {
                graph: None,
                resources: None,
                exchange: None,
            },
            true,
        ),
    )
    .await;
    assert!(
        matches!(result, Err(Error::MissingAppPermission)),
        "Expected MissingAppPermission, got: {result:?}"
    );
}

#[test]
fn test_graph_client_credentials_missing_only_cross_tenant_information_returns_err() {
    let roles: Vec<&str> = REQUIRED_GRAPH_APP_ROLES
        .iter()
        .copied()
        .filter(|role| *role != "CrossTenantInformation.ReadBasic.All")
        .collect();
    let token = token_with_roles("graph", &roles);

    let result = check_app_permissions_for_client_credentials(&token, true);

    assert!(
        matches!(result, Err((Error::MissingAppPermission, ref missing))
            if missing == &["CrossTenantInformation.ReadBasic.All"]),
        "Expected only CrossTenantInformation.ReadBasic.All to be missing, got: {result:?}"
    );
}

// --- Graph (managed identity) ---

#[tokio::test]
async fn test_graph_managed_identity_missing_only_cross_tenant_information_returns_err() {
    let mock = MockServer::start().await;
    let assignments: Vec<serde_json::Value> = REQUIRED_GRAPH_APP_ROLE_IDS
        .iter()
        .copied()
        .filter(|id| *id != "cac88765-0581-4025-9725-5ebc13f729ee")
        .map(|app_role_id| serde_json::json!({ "appRoleId": app_role_id }))
        .collect();

    Mock::given(method("GET"))
        .and(path(
            "/v1.0/servicePrincipals/sp-oid-1234/appRoleAssignments",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": assignments
        })))
        .mount(&mock)
        .await;

    let token = token_with_roles("graph", &[]);
    let result = check_app_permissions_for_managed_identity(
        &reqwest::Client::new(),
        &token,
        true,
        &mock.uri(),
        0,
    )
    .await;

    assert!(
        matches!(result, Err((Error::MissingAppPermission, ref missing))
            if missing == &["CrossTenantInformation.ReadBasic.All"]),
        "Expected only CrossTenantInformation.ReadBasic.All to be missing, got: {result:?}"
    );
}

#[tokio::test]
async fn test_graph_managed_identity_all_permissions_present_returns_ok() {
    let mock = MockServer::start().await;
    let assignments: Vec<serde_json::Value> = REQUIRED_GRAPH_APP_ROLE_IDS
        .iter()
        .map(|app_role_id| serde_json::json!({ "appRoleId": app_role_id }))
        .collect();

    Mock::given(method("GET"))
        .and(path(
            "/v1.0/servicePrincipals/sp-oid-1234/appRoleAssignments",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": assignments
        })))
        .mount(&mock)
        .await;

    let token = token_with_roles("graph", &[]);
    let result = check_app_permissions_for_managed_identity(
        &reqwest::Client::new(),
        &token,
        true,
        &mock.uri(),
        0,
    )
    .await;

    assert!(result.is_ok(), "Expected Ok(()), got: {result:?}");
}

#[tokio::test]
async fn test_graph_client_credentials_missing_global_reader_role_returns_err() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1.0/organization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "assignedPlans": [] }]
        })))
        .mount(&mock)
        .await;

    // SP has no Global Reader assignment.
    Mock::given(method("GET"))
        .and(path("/v1.0/roleManagement/directory/roleAssignments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": []
        })))
        .mount(&mock)
        .await;

    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    let token = token_with_roles("graph", REQUIRED_GRAPH_APP_ROLES);

    let result = Prerequisites::check_with_overrides(
        &client.client,
        &token,
        options_with_overrides(
            UrlOverrides {
                graph: Some(mock.uri()),
                resources: None,
                exchange: None,
            },
            true,
        ),
    )
    .await;
    assert!(
        matches!(result, Err(Error::MissingGlobalReaderRoleForApplication)),
        "Expected MissingGlobalReaderRoleForApplication, got: {result:?}"
    );
}

#[tokio::test]
async fn test_graph_client_credentials_with_global_reader_returns_ok() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1.0/organization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "assignedPlans": [] }]
        })))
        .mount(&mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1.0/roleManagement/directory/roleAssignments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "roleDefinition": { "templateId": "f2ef992c-3afb-46b9-b7cf-a126ee74c451" }
            }]
        })))
        .mount(&mock)
        .await;

    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    let token = token_with_roles("graph", REQUIRED_GRAPH_APP_ROLES);

    let result = Prerequisites::check_with_overrides(
        &client.client,
        &token,
        options_with_overrides(
            UrlOverrides {
                graph: Some(mock.uri()),
                resources: None,
                exchange: None,
            },
            true,
        ),
    )
    .await;
    assert!(result.is_ok(), "Expected Ok(()), got: {result:?}");
}

#[tokio::test]
async fn test_graph_client_credentials_global_reader_via_pim_returns_ok() {
    let mock = MockServer::start().await;

    // PIM enabled.
    Mock::given(method("GET"))
        .and(path("/v1.0/organization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "assignedPlans": [{
                    "servicePlanId": "eec0eb4f-6444-4f95-aba0-50c24d67f998",
                    "capabilityStatus": "Enabled"
                }]
            }]
        })))
        .mount(&mock)
        .await;

    // Permanent SP Global Reader through PIM (no endDateTime).
    Mock::given(method("GET"))
        .and(path(
            "/v1.0/roleManagement/directory/roleAssignmentScheduleInstances",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "roleDefinition": { "templateId": "f2ef992c-3afb-46b9-b7cf-a126ee74c451" }
            }]
        })))
        .mount(&mock)
        .await;

    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    let token = token_with_roles("graph", REQUIRED_GRAPH_APP_ROLES);

    let result = Prerequisites::check_with_overrides(
        &client.client,
        &token,
        options_with_overrides(
            UrlOverrides {
                graph: Some(mock.uri()),
                resources: None,
                exchange: None,
            },
            true,
        ),
    )
    .await;
    assert!(result.is_ok(), "Expected Ok(()), got: {result:?}");
}

// --- Resources ---

#[tokio::test]
async fn test_resources_delegated_missing_user_impersonation_returns_err() {
    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    // Token has no `user_impersonation` scope in scp.
    let token = token_with_scopes("resources", &["Directory.Read.All"]);

    let result = Prerequisites::check_with_overrides(
        &client.client,
        &token,
        options_with_overrides(
            UrlOverrides {
                graph: None,
                resources: None,
                exchange: None,
            },
            false,
        ),
    )
    .await;
    assert!(
        matches!(result, Err(Error::MissingAzureUserImpersonationScope)),
        "Expected MissingAzureUserImpersonationScope, got: {result:?}"
    );
}

#[tokio::test]
async fn test_resources_delegated_subscriptions_present_returns_ok() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/subscriptions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "displayName": "Production Subscription",
                "subscriptionId": "00000000-0000-0000-0000-000000000001"
            }]
        })))
        .mount(&mock)
        .await;

    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    let token = token_with_scopes("resources", &["user_impersonation"]);

    let result = Prerequisites::check_with_overrides(
        &client.client,
        &token,
        options_with_overrides(
            UrlOverrides {
                graph: None,
                resources: Some(mock.uri()),
                exchange: None,
            },
            false,
        ),
    )
    .await;
    assert!(result.is_ok(), "Expected Ok(()), got: {result:?}");
}

#[tokio::test]
async fn test_resources_no_subscriptions_returns_err() {
    let mock = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/subscriptions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": []
        })))
        .mount(&mock)
        .await;

    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    let token = token_with_scopes("resources", &["user_impersonation"]);

    let result = Prerequisites::check_with_overrides(
        &client.client,
        &token,
        options_with_overrides(
            UrlOverrides {
                graph: None,
                resources: Some(mock.uri()),
                exchange: None,
            },
            false,
        ),
    )
    .await;
    assert!(
        matches!(result, Err(Error::NoAvailableSubscription)),
        "Expected NoAvailableSubscription, got: {result:?}"
    );
}

/// ARM paginates the subscriptions list via a top-level `nextLink`; the prereq
/// check must follow it and aggregate every page (the IDs feed the ARG
/// `subscriptions` body). A non-paginating reader would return only page 1's
/// subscription, silently dropping the rest.
#[tokio::test]
async fn test_subscriptions_pagination_aggregates_all_pages() {
    let mock = MockServer::start().await;
    // Page 1: one subscription + a nextLink to page 2.
    Mock::given(method("GET"))
        .and(path("/subscriptions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "displayName": "Sub One", "subscriptionId": "sub-1" }],
            "nextLink": format!("{}/subscriptions-page2", mock.uri())
        })))
        .mount(&mock)
        .await;
    // Page 2: a second subscription, no nextLink (last page).
    Mock::given(method("GET"))
        .and(path("/subscriptions-page2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "displayName": "Sub Two", "subscriptionId": "sub-2" }]
        })))
        .mount(&mock)
        .await;

    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    let token = token_with_scopes("resources", &["user_impersonation"]);

    let pairs = check_available_subscriptions(&client.client, &token, true, &mock.uri(), 0)
        .await
        .expect("pagination should aggregate both pages");

    let ids: Vec<&str> = pairs.iter().map(|(_, id)| id.as_str()).collect();
    assert_eq!(
        pairs.len(),
        2,
        "both pages' subscriptions must be returned, got {ids:?}"
    );
    assert!(ids.contains(&"sub-1") && ids.contains(&"sub-2"));
}

// --- Exchange (delegated) ---

#[tokio::test]
async fn test_exchange_delegated_missing_scope_returns_err() {
    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    let token = token_with_scopes("exchange", &[]);

    let result = Prerequisites::check_with_overrides(
        &client.client,
        &token,
        options_with_overrides(
            UrlOverrides {
                graph: None,
                resources: None,
                exchange: None,
            },
            false,
        ),
    )
    .await;
    assert!(
        matches!(result, Err(Error::MissingExchangeManageScope)),
        "Expected MissingExchangeManageScope, got: {result:?}"
    );
}

#[tokio::test]
async fn test_exchange_delegated_with_scope_returns_ok() {
    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    let token = token_with_scopes("exchange", &["Exchange.Manage"]);

    let result = Prerequisites::check_with_overrides(
        &client.client,
        &token,
        options_with_overrides(
            UrlOverrides {
                graph: None,
                resources: None,
                exchange: None,
            },
            false,
        ),
    )
    .await;
    assert!(result.is_ok(), "Expected Ok(()), got: {result:?}");
}

// --- Exchange (client credentials) ---

#[tokio::test]
async fn test_exchange_client_credentials_missing_role_returns_err() {
    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    let token = token_with_roles("exchange", &["Directory.Read.All"]);

    let result = Prerequisites::check_with_overrides(
        &client.client,
        &token,
        options_with_overrides(
            UrlOverrides {
                graph: None,
                resources: None,
                exchange: None,
            },
            true,
        ),
    )
    .await;
    assert!(
        matches!(result, Err(Error::MissingExchangeManageAsApp)),
        "Expected MissingExchangeManageAsApp, got: {result:?}"
    );
}

#[tokio::test]
async fn test_exchange_client_credentials_with_role_returns_ok() {
    let config = default_test_config();
    let client = OradazClient::new(&config).unwrap();
    let token = token_with_roles("exchange", &["Exchange.ManageAsApp"]);

    let result = Prerequisites::check_with_overrides(
        &client.client,
        &token,
        options_with_overrides(
            UrlOverrides {
                graph: None,
                resources: None,
                exchange: None,
            },
            true,
        ),
    )
    .await;
    assert!(result.is_ok(), "Expected Ok(()), got: {result:?}");
}
