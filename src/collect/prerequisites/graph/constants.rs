use std::collections::HashMap;
use std::sync::LazyLock;

pub static REQUIRED_ENTRA_ROLES: LazyLock<Vec<Vec<&'static str>>> = LazyLock::new(|| {
    vec![
        vec![
            "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
            "5d6b6bb7-de71-4623-b4af-96380a352509",
            "ffd52fa5-98dc-465c-991d-fc073eb59f8f",
        ], // Global Reader & Security Reader & Attribute Assignment Reader
        vec![
            "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
            "5f2222b1-57c3-48ba-8ad5-d4759f1fde6f",
            "ffd52fa5-98dc-465c-991d-fc073eb59f8f",
        ], // Global Reader & Security Operator & Attribute Assignment Reader
        vec![
            "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
            "194ae4cb-b126-40b2-bd5b-6091b380977d",
            "ffd52fa5-98dc-465c-991d-fc073eb59f8f",
        ], // Global Reader & Security Administrator & Attribute Assignment Reader
        vec![
            "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
            "5d6b6bb7-de71-4623-b4af-96380a352509",
            "58a13ea3-c632-46ae-9ee0-9c0d43cd7f3d",
        ], // Global Reader & Security Reader & Attribute Assignment Administrator
        vec![
            "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
            "5f2222b1-57c3-48ba-8ad5-d4759f1fde6f",
            "58a13ea3-c632-46ae-9ee0-9c0d43cd7f3d",
        ], // Global Reader & Security Operator & Attribute Assignment Administrator
        vec![
            "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
            "194ae4cb-b126-40b2-bd5b-6091b380977d",
            "58a13ea3-c632-46ae-9ee0-9c0d43cd7f3d",
        ], // Global Reader & Security Administrator & Attribute Assignment Administrator
        vec!["62e90394-69f5-4237-9190-012177145e10"], // Global Administrator
    ]
});

pub static ENTRA_ROLE_NAMES: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    [
        (
            "62e90394-69f5-4237-9190-012177145e10",
            "Global Administrator",
        ),
        ("f2ef992c-3afb-46b9-b7cf-a126ee74c451", "Global Reader"),
        ("5d6b6bb7-de71-4623-b4af-96380a352509", "Security Reader"),
        ("5f2222b1-57c3-48ba-8ad5-d4759f1fde6f", "Security Operator"),
        (
            "194ae4cb-b126-40b2-bd5b-6091b380977d",
            "Security Administrator",
        ),
        (
            "ffd52fa5-98dc-465c-991d-fc073eb59f8f",
            "Attribute Assignment Reader",
        ),
        (
            "58a13ea3-c632-46ae-9ee0-9c0d43cd7f3d",
            "Attribute Assignment Administrator",
        ),
    ]
    .iter()
    .copied()
    .collect()
});

pub static GRAPH_API_APP_ONLY_PERMISSIONS: LazyLock<HashMap<&'static str, &'static str>> =
    LazyLock::new(|| {
        [
            (
                "d07a8cc0-3d51-4b77-b3b0-32704d1f69fa",
                "AccessReview.Read.All",
            ),
            (
                "b86848a7-d5b1-41eb-a9b4-54a4e6306e97",
                "APIConnectors.Read.All",
            ),
            ("b0afded3-3588-46d8-8b3d-9842eff778da", "AuditLog.Read.All"),
            (
                "3b37c5a4-1226-493d-bec3-5d6c6b866f3f",
                "CustomSecAttributeAssignment.Read.All",
            ),
            (
                "b185aa14-d8d2-42c1-a685-0f5596613624",
                "CustomSecAttributeDefinition.Read.All",
            ),
            (
                "f6e9e124-4586-492f-adc0-c6f96e4823fd",
                "DelegatedAdminRelationship.Read.All",
            ),
            (
                "7a6ee1e7-141e-4cec-ae74-d9db155731ff",
                "DeviceManagementApps.Read.All",
            ),
            (
                "dc377aa6-52d8-4e23-b271-2a7ae04cedf3",
                "DeviceManagementConfiguration.Read.All",
            ),
            (
                "2f51be20-0bb4-4fed-bf7b-db946066c75e",
                "DeviceManagementManagedDevices.Read.All",
            ),
            (
                "58ca0d9a-1575-47e1-a3cb-007ef2e4583b",
                "DeviceManagementRBAC.Read.All",
            ),
            ("7ab1d382-f21e-4acd-a863-ba3e13f7da61", "Directory.Read.All"),
            ("dbb9058a-0e50-45d7-ae91-66909b5d4664", "Domain.Read.All"),
            (
                "c74fd47d-ed3c-45c3-9a9e-b8676de685d2",
                "EntitlementManagement.Read.All",
            ),
            (
                "e321f0bb-e7f7-481e-bb28-e3b0b32d4bd0",
                "IdentityProvider.Read.All",
            ),
            (
                "6e472fd1-ad78-48da-a0f0-97ab2c6b769e",
                "IdentityRiskEvent.Read.All",
            ),
            (
                "607c7344-0eed-41e5-823a-9695ebe1b7b0",
                "IdentityRiskyServicePrincipal.Read.All",
            ),
            (
                "dc5007c0-2d7d-4c42-879c-2dab87571379",
                "IdentityRiskyUser.Read.All",
            ),
            (
                "1b0c317f-dd31-4305-9932-259a8b6e8099",
                "IdentityUserFlow.Read.All",
            ),
            (
                "4f994bc0-31bb-44bb-b480-7a7c1be8c02e",
                "MultiTenantOrganization.Read.All",
            ),
            (
                "bb70e231-92dc-4729-aff5-697b3f04be95",
                "OnPremDirectorySynchronization.Read.All",
            ),
            (
                "498476ce-e0fe-48b0-b801-37ba7e2685c6",
                "Organization.Read.All",
            ),
            ("246dd0d5-5bd0-4def-940b-0421030a5b68", "Policy.Read.All"),
            (
                "9e640839-a198-48fb-8b9a-013fd6f6cbcd",
                "Policy.Read.PermissionGrant",
            ),
            (
                "4cdc2547-9148-4295-8d11-be0db1391d6b",
                "PrivilegedAccess.Read.AzureAD",
            ),
            (
                "01e37dc9-c035-40bd-b438-b2879c4870a6",
                "PrivilegedAccess.Read.AzureADGroup",
            ),
            (
                "5df6fe86-1be0-44eb-b916-7bd443a71236",
                "PrivilegedAccess.Read.AzureResources",
            ),
            (
                "cd4161cb-f098-48f8-a884-1eda9a42434c",
                "PrivilegedAssignmentSchedule.Read.AzureADGroup",
            ),
            (
                "edb419d6-7edc-42a3-9345-509bfdf5d87c",
                "PrivilegedEligibilitySchedule.Read.AzureADGroup",
            ),
            (
                "214fda0c-514a-4650-b037-b562b1a66124",
                "PublicKeyInfrastructure.Read.All",
            ),
            ("230c1aed-a721-4c5d-9cb4-a90514e508ef", "Reports.Read.All"),
            (
                "acfca4d5-f49f-40ed-9648-84068b474c73",
                "ResourceSpecificPermissionGrant.ReadForUser.All",
            ),
            (
                "d5fe8ce8-684c-4c83-a52c-46e882ce4be1",
                "RoleAssignmentSchedule.Read.Directory",
            ),
            (
                "ff278e11-4a33-4d0c-83d2-d01dc58929a5",
                "RoleEligibilitySchedule.Read.Directory",
            ),
            (
                "69e67828-780e-47fd-b28c-7b27d14864e6",
                "RoleManagementPolicy.Read.AzureADGroup",
            ),
            (
                "c7fbd983-d9aa-4fa7-84b8-17382c103bc4",
                "RoleManagement.Read.All",
            ),
            (
                "bf394140-e372-4bf9-a898-299cfc7564e5",
                "SecurityEvents.Read.All",
            ),
            (
                "38d9df27-64da-44fd-b7c5-a6fbac20248f",
                "UserAuthenticationMethod.Read.All",
            ),
            ("df021288-bdef-4463-88db-98f22de89214", "User.Read.All"),
        ]
        .iter()
        .copied()
        .collect()
    });

pub static GRAPH_API_PERMISSIONS: LazyLock<HashMap<&'static str, &'static str>> =
    LazyLock::new(|| {
        vec![
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
                "PrivilegedAssignmentSchedule.Read.AzureADGroup",
            ),
            (
                "8f44f93d-ecef-46ae-a9bf-338508d44d6b",
                "PrivilegedEligibilitySchedule.Read.AzureADGroup",
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
                "7e26fdff-9cb1-4e56-bede-211fe0e420e8",
                "RoleManagementPolicy.Read.AzureADGroup",
            ),
            (
                "48fec646-b2ba-4019-8681-8eb31435aded",
                "RoleManagement.Read.All",
            ),
            (
                "64733abd-851e-478a-bffb-e47a14b18235",
                "SecurityEvents.Read.All",
            ),
            (
                "aec28ec7-4d02-4e8c-b864-50163aea77eb",
                "UserAuthenticationMethod.Read.All",
            ),
            ("a154be20-db9c-4678-8ab7-66f6cc099a59", "User.Read.All"),
        ]
        .iter()
        .copied()
        .collect()
    });
