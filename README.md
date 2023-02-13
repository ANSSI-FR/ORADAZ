# ORADAZ
~~ Outil de Récupération Automatique des Données AZure ~~

This tool helps dumping Azure data via REST API to assist security audit assignments. 

## Configuration

Edit `config-oradaz.xml`.

## Prerequisites

* An account with Global Reader and Security Reader roles;
* If management groups are used, Management Group Reader and Reader roles on the root management group, else Reader role on each subscription;
* An application allowed for public client flows and having the following delegated permissions:
    * Azure Service Management API:
        * user_impersonation
    * Microsoft Graph API:
        * AccessReview.Read.All
        * APIConnectors.Read.All
        * AuditLog.Read.All
        * CustomSecAttributeAssignment.Read.All
        * CustomSecAttributeDefinition.Read.All
        * DelegatedAdminRelationship.Read.All
        * Directory.Read.All
        * Domain.Read.All
        * EntitlementManagement.Read.All
        * IdentityProvider.Read.All
        * IdentityRiskEvent.Read.All
        * IdentityRiskyServicePrincipal.Read.All
        * IdentityRiskyUser.Read.All
        * IdentityUserFlow.Read.All
        * OnPremDirectorySynchronization.Read.All
        * Organization.Read.All
        * Policy.Read.All
        * Policy.Read.PermissionGrant
        * PrivilegedAccess.Read.AzureAD
        * PrivilegedAccess.Read.AzureADGroup
        * PrivilegedAccess.Read.AzureResources
        * Reports.Read.All
        * RoleAssignmentSchedule.Read.Directory
        * RoleEligibilitySchedule.Read.Directory
        * RoleManagement.Read.All
        * SecurityEvents.Read.All
        * User.Read.All
        * UserAuthenticationMethod.Read.All
* Addition of the Get-RecipientPermission privilege for the View-Only Organization Management Exchange group (see [here](https://docs.microsoft.com/en-us/answers/questions/327977/get-recipientpermission-andgetexorecipientpermis.html) for more information about this)


## Usage

`oradaz.exe -t <tenant_id> -a <app_id>`

The configuration is read from `config-oradaz.xml` which must be stored next to `oradaz.exe`.