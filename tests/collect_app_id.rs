mod common;

use crate::common::default_test_config;
use oradaz::collect::resolve_app_id;
use oradaz::utils::config::ApplicationCredentials;

fn managed_identity(value: Option<&str>) -> ApplicationCredentials {
    ApplicationCredentials {
        credential_type: "managedIdentity".to_string(),
        value: value.map(str::to_string),
    }
}

fn password() -> ApplicationCredentials {
    ApplicationCredentials {
        credential_type: "password".to_string(),
        value: Some("secret".to_string()),
    }
}

/// Managed identity (system-assigned): no `appId` in config and none on the CLI →
/// resolves to an empty string. It MUST NOT prompt (Ok(None)) and MUST NOT error.
#[test]
fn managed_identity_system_assigned_resolves_empty_without_prompt_or_error() {
    let mut config = default_test_config();
    config.app_id = String::new(); // no <appId> in the config file
    config.use_application_credentials = Some(true);
    config.application_credentials = Some(managed_identity(None));

    let resolved = resolve_app_id(&config, None).expect("managed identity must not error");
    assert_eq!(
        resolved,
        Some(String::new()),
        "system-assigned managed identity resolves to an empty client ID, not a prompt"
    );
}

/// Managed identity (user-assigned): the client ID comes from
/// `applicationCredentials.value`, still without prompting or erroring.
#[test]
fn managed_identity_user_assigned_uses_value() {
    let mut config = default_test_config();
    config.app_id = String::new();
    config.use_application_credentials = Some(true);
    config.application_credentials = Some(managed_identity(Some("user-assigned-client-id")));

    let resolved = resolve_app_id(&config, None).expect("managed identity must not error");
    assert_eq!(resolved, Some("user-assigned-client-id".to_string()));
}

/// Managed identity ignores a CLI `--app-id` (the identity is fixed by the host).
#[test]
fn managed_identity_ignores_cli_app_id() {
    let mut config = default_test_config();
    config.app_id = String::new();
    config.use_application_credentials = Some(true);
    config.application_credentials = Some(managed_identity(None));

    let resolved = resolve_app_id(&config, Some("ignored-cli-id")).unwrap();
    assert_eq!(resolved, Some(String::new()));
}

/// Non-managed application credentials (password) with no `appId` anywhere is a
/// fatal misconfiguration — NOT a stdin prompt (an unattended run would hang).
#[test]
fn password_without_app_id_is_error_not_prompt() {
    let mut config = default_test_config();
    config.app_id = String::new();
    config.use_application_credentials = Some(true);
    config.application_credentials = Some(password());

    assert!(
        resolve_app_id(&config, None).is_err(),
        "password flow without appId must be a fatal error, never a prompt"
    );
}

/// Non-managed application credentials with an `appId` in config → resolves to it.
#[test]
fn password_with_config_app_id_resolves() {
    let mut config = default_test_config(); // app_id = "test-app-id"
    config.use_application_credentials = Some(true);
    config.application_credentials = Some(password());

    assert_eq!(
        resolve_app_id(&config, None).unwrap(),
        Some("test-app-id".to_string())
    );
}

/// A CLI `--app-id` is used for an interactive flow with an empty config `appId`.
#[test]
fn cli_app_id_is_used_for_interactive_flow() {
    let mut config = default_test_config();
    config.app_id = String::new();

    let resolved = resolve_app_id(&config, Some("cli-app-id")).unwrap();
    assert_eq!(resolved, Some("cli-app-id".to_string()));
}

/// Interactive flow (no application credentials) with no `appId` anywhere →
/// `Ok(None)`, i.e. the caller prompts on stdin.
#[test]
fn interactive_without_app_id_requests_prompt() {
    let mut config = default_test_config();
    config.app_id = String::new();

    assert_eq!(resolve_app_id(&config, None).unwrap(), None);
}
