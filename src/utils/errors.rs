/// Module that provides custom errors for ORADAZ.
use crate::collect::auth::AuthError;
use crate::utils::url::Url;

use mla::errors::Error as MLAError;
use std::error;
use std::fmt;
use std::io;

/// Trait for presenting fatal errors uniformly in the user interface.
pub trait FatalPresentation {
    /// Returns a short, user-friendly title for the error.
    fn title(&self) -> &'static str;
    /// Returns optional structured context extracted from the error (shown below the title).
    fn context(&self) -> Option<String> {
        None
    }
    /// Returns zero or more actionable remedy steps shown as bullet points.
    fn remediation_steps(&self) -> &'static [&'static str] {
        &[]
    }
}

impl FatalPresentation for Error {
    fn title(&self) -> &'static str {
        match self {
            Error::ConfigFileNotFound => "Configuration file not found",
            Error::InvalidConfigXMLStructure(_) => "Invalid config XML structure",
            Error::FolderCreation => "Output folder is not usable",
            Error::SchemaFileNotFound => "Schema file not found",
            Error::TokenAcquisitionError => "Authentication token acquisition failed",
            Error::ClientCredentialsFlowCreation(_)
            | Error::ClientCredentialsFlowAuthentication(_) => {
                "Client credentials authentication failed"
            }
            Error::InvalidApplicationCredentials => "Invalid application credentials configuration",
            Error::RefreshToken => "Token refresh failed",
            Error::WriterLock => "Writer lock error",
            Error::MissingExchangeManageAsApp => {
                "Missing Exchange.ManageAsApp application permission"
            }
            Error::MissingGlobalReaderRoleForApplication => {
                "Application is missing the Global Reader Entra role"
            }
            Error::MissingServicePrincipalObjectId => {
                "Cannot resolve service principal object id from access token"
            }
            Error::MissingAzureUserImpersonationScope => {
                "Missing user_impersonation scope on Azure Service Management token"
            }
            Error::MissingExchangeManageScope => {
                "Missing Exchange.Manage scope on Exchange Online token"
            }
            Error::Cancelled => "Dump cancelled by user",
            Error::MLAError(_) => "MLA processing error",
            Error::InvalidConfigValue(_) => "Invalid configuration value",
            Error::WriteFile => "Incomplete archive: a data file could not be written",
            _ => "Fatal error",
        }
    }

    fn context(&self) -> Option<String> {
        match self {
            Error::StringError(msg) => Some(msg.clone()),
            Error::ClientCredentialsFlowCreation(msg)
            | Error::ClientCredentialsFlowAuthentication(msg) => Some(msg.clone()),
            Error::InvalidConfigXMLStructure(detail) => detail.clone(),
            Error::InvalidConfigValue(detail) => Some(detail.clone()),
            Error::WriteFile => Some(
                "One or more collected response files failed to write to the output. The archive \
                 is incomplete and has been marked '.broken' so it is not mistaken for a complete \
                 collection."
                    .to_string(),
            ),
            _ => None,
        }
    }

    fn remediation_steps(&self) -> &'static [&'static str] {
        match self {
            Error::ConfigFileNotFound => &["Ensure the config file exists at the provided path."],
            Error::InvalidConfigXMLStructure(_) => &[
                "Check that the config XML follows the expected schema.",
                "Note: <proxy> must be nested, e.g. <proxy><url>http://host:port</url></proxy> (optionally with <username>/<password>), not a plain string.",
            ],
            Error::FolderCreation => &[
                "Check the --output path: the parent directory must exist and be writable.",
                "ORADAZ creates the output folder if missing; verify filesystem permissions.",
            ],
            Error::ClientCredentialsFlowCreation(_)
            | Error::ClientCredentialsFlowAuthentication(_) => &[
                "Check network connectivity and proxy settings (a refused/timed-out connection surfaces here).",
                "Verify the tenant, application (client) id and credential (secret/certificate) are correct.",
            ],
            Error::SchemaFileNotFound => {
                &["Provide a valid schema file or ensure network access to download it."]
            }
            Error::TokenAcquisitionError => &["Check network connectivity and client credentials."],
            Error::RefreshToken => &["Verify the refresh token is valid or re-authenticate."],
            Error::MissingExchangeManageAsApp => &[
                "Grant the Exchange.ManageAsApp application permission on the Office 365 Exchange Online API.",
                "Resource app ID: 00000002-0000-0ff1-ce00-000000000000",
                "Obtain admin consent for the application.",
            ],
            Error::MissingGlobalReaderRoleForApplication => {
                &["Assign the Global Reader directory role to the application's service principal."]
            }
            Error::MissingServicePrincipalObjectId => &[
                "Verify the application registration — the issued token is missing the `oid` claim.",
                "Re-authenticate after fixing the registration.",
            ],
            Error::MissingAzureUserImpersonationScope => &[
                "Grant the user_impersonation scope on the Azure Service Management API to the application.",
                "Obtain admin consent for the application.",
            ],
            Error::MissingExchangeManageScope => &[
                "Grant the Exchange.Manage delegated permission on the Office 365 Exchange Online API.",
                "Obtain admin consent for the application.",
            ],
            Error::Cancelled => &["The collection process was stopped by the user."],
            Error::InvalidConfigValue(_) => {
                &["Review the flagged configuration value in your config XML and correct it."]
            }
            Error::WriteFile => &[
                "Check free disk space and write permissions on the output path.",
                "Re-run the collection; the '.broken' archive can be inspected to see what was captured.",
            ],
            _ => &[],
        }
    }
}

#[derive(Debug)]
/// Central error type for the ORADAZ application.
///
/// This enum consolidates errors from various subsystems, including authentication,
/// configuration, URL management, request execution, and the MLA archive writer.
pub enum Error {
    /// Generic string-based error.
    StringError(String),
    /// Standard IO error.
    IOError(io::Error),
    /// Failed to construct a valid URL.
    UrlCreation,
    /// Error during communication over unbounded channels.
    ChannelError,
    /// Failed to compile a regular expression.
    RegexError,

    /// --- Auth errors ---
    /// Failed to acquire a new authentication token.
    TokenAcquisitionError,
    /// Error during the creation phase of the authorization code flow.
    AuthorizationCodeFlowCreation,
    /// Error during the authentication phase of the authorization code flow.
    AuthorizationCodeFlowAuthentication,
    /// Error during the creation phase of the device code flow.
    DeviceCodeFlowCreation,
    /// Error during the authentication phase of the device code flow.
    DeviceCodeFlowAuthentication,
    /// The device flow stream ended unexpectedly.
    DeviceCodeFlowUnexpectedEnd,
    /// Error during the creation phase of the client credentials flow.
    ClientCredentialsFlowCreation(String),
    /// Error during the authentication phase of the client credentials flow.
    ClientCredentialsFlowAuthentication(String),
    /// Invalid or missing applicationCredentials configuration.
    InvalidApplicationCredentials,
    /// Failed to parse the access token (e.g., invalid JWT).
    AccessTokenParsing,
    /// Failed to serialize authentication errors to JSON.
    AuthErrorsToJSON,
    /// General token refresh failure.
    RefreshToken,
    /// Error while refreshing a token to obtain a new scope.
    RefreshTokenNewScope,
    /// Signal to reprocess a token update, optionally including the cause.
    Reprocess(Option<AuthError>),

    /// --- Config errors ---
    /// The specified configuration file was not found.
    ConfigFileNotFound,
    /// The configuration file contains invalid XML. Carries the underlying
    /// parser detail (which element failed) when available, so the user-facing
    /// message can name the offending element instead of being generic.
    InvalidConfigXMLStructure(Option<String>),
    /// Failed to serialize configuration options to JSON for the archive.
    ConfigToJSON,
    /// One or more configuration values are invalid.
    InvalidConfigValue(String),

    /// --- ConditionChecker errors ---
    /// The Graph API token required to check tenant conditions is missing.
    MissingGraphApiTokenForConditionChecker,

    /// --- Url errors ---
    /// No URLs were provided for processing.
    EmptyUrlsVector,
    /// One or more of the provided URLs are malformed.
    InvalidUrls,
    /// A URL failed after the maximum number of retries.
    UrlRetryLimit(Box<Url>),

    /// --- Requests errors ---
    /// The provided proxy URL is invalid.
    InvalidProxyURL,
    /// Failed to initialize the proxy client.
    ProxyCreation,
    /// Failed to initialize the HTTP client.
    CannotCreateClient,

    /// --- Schema errors ---
    /// The schema file was not found.
    SchemaFileNotFound,
    /// Failed to download the schema file from GitHub.
    CannotDownloadSchemaFile,
    /// The current version of ORADAZ is not the latest available.
    NotLastVersion,
    /// Failed to parse the schema file.
    SchemaFileParsing,
    /// Error during the generation of URLs from the schema.
    UrlsGeneration,

    /// --- Prerequisites errors ---
    /// Graph API token missing for prerequisite checks.
    MissingGraphApiToken,
    /// Resources API token missing for prerequisite checks.
    MissingResourcesApiToken,
    /// Exchange Online API token missing for prerequisite checks.
    MissingExchangeApiToken,
    /// Failed to retrieve the custom application identity.
    CannotRetrieveApp,
    /// The application lacks a required permission for the requested dump.
    MissingAppPermission,
    /// Failed to serialize prerequisite errors to JSON.
    PrerequisitesErrorsToJSON,
    /// The token provided for prerequisite checks is invalid.
    InvalidTokenToCheck,
    /// Failed to retrieve organization details for PIM status check.
    CannotRetrieveOrganization,
    /// Failed to retrieve Entra ID roles for the current user.
    CannotRetrieveCurrentUserEntraRoles,
    /// The current user lacks the necessary Entra ID roles.
    MissingEntraRoles,
    /// Failed to retrieve PIM role assignments for the current user.
    CannotRetrieveCurrentUserPIMEntraRoles,
    /// Failed to retrieve Azure subscriptions.
    CannotRetrieveSubscriptions,
    /// No Azure subscriptions were found for the current user.
    NoAvailableSubscription,
    /// The application lacks the `Exchange.ManageAsApp` application permission
    /// on Office 365 Exchange Online (client credentials flow).
    MissingExchangeManageAsApp,
    /// The application's service principal is missing the `Global Reader`
    /// Entra ID role (client credentials flow).
    MissingGlobalReaderRoleForApplication,
    /// The service principal object id could not be resolved from the access
    /// token (missing `oid` JWT claim). Prevents the Global Reader role check.
    MissingServicePrincipalObjectId,
    /// Failed to retrieve directory role assignments for the application's
    /// service principal.
    CannotRetrieveServicePrincipalEntraRoles,
    /// Failed to retrieve PIM role assignments for the application's service
    /// principal.
    CannotRetrieveServicePrincipalPIMEntraRoles,
    /// Failed to retrieve app role assignments for the managed identity's
    /// service principal via `servicePrincipals/{oid}/appRoleAssignments`.
    CannotRetrieveAppRoleAssignments,
    /// The Azure Resources access token lacks the `user_impersonation` scope.
    MissingAzureUserImpersonationScope,
    /// The Exchange Online access token lacks the `Exchange.Manage` scope.
    MissingExchangeManageScope,
    /// Too many requests sent to the API during prerequisite checks.
    TooManyRequestsDuringPrerequisites(u64),

    /// --- Writer errors ---
    /// Failed to write a file to the output destination.
    WriteFile,
    /// The provided MLA path contains invalid characters.
    InvalidMlaPath,
    /// Failed to create the MLA file.
    MLACreateFile,
    /// The provided MLA public key is invalid.
    MLAInvalidPubKey,
    /// Failed to create the MLA archive.
    MLACreateArchive,
    /// Failed to create the log file within the MLA archive.
    MLACreateLogFile,
    /// Failed to finalize the log file in the MLA archive.
    MLAEndLogFile,
    /// Failed to finalize a file in the MLA archive.
    MLAEndFile,
    /// Failed to finalize the MLA archive itself.
    MLAFinalizeArchive,
    /// Failed to write a log entry to the MLA archive.
    MLAWriteLog,
    /// Failed to append data to a file in the MLA archive.
    MLAAppendDataToFile,
    /// Wrapper for errors originating from the `mla` crate.
    MLAError(MLAError),
    /// Failed to create the output folder.
    FolderCreation,
    /// Failed to create the log file in the output directory.
    FolderCreateLogFile,
    /// Failed to write the log file to the output directory.
    FolderWriteLog,
    /// The output path for an XML file is invalid.
    FolderInvalidFilePath,
    /// Failed to rename the final MLA archive.
    ArchiveRenaming,
    /// Failed to acquire the lock on the writer.
    WriterLock,

    /// --- Metadata errors ---
    /// Failed to serialize metadata to JSON.
    MetadataToJSON,

    /// --- Stats errors ---
    /// Failed to serialize stats to JSON.
    StatsToJSON,

    /// --- Threading errors ---
    /// Failed to initialize the thread pool for the dump process.
    ThreadPoolBuilderCreation,
    /// An unexpected HTTP code was received during prerequisite checks.
    ErrorCodeDueToPrerequisites,

    /// --- Dumper errors ---
    /// Failed to lock the unbounded channel sender.
    SenderLock,
    /// Failed to lock the unbounded channel receiver.
    ReceiverLock,
    /// Failed to lock the metadata mutex.
    MetadataLock,
    /// The dump was cancelled by the user.
    Cancelled,
    /// Failed to lock the request counter mutex.
    MutexLock,
    /// Failed to receive a message from a tokio channel.
    RecvError,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::ClientCredentialsFlowCreation(msg)
            | Error::ClientCredentialsFlowAuthentication(msg) => write!(f, "{msg}"),
            _ => write!(f, "{self:?}"),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self {
            Error::IOError(err) => Some(err),
            Error::MLAError(err) => Some(err),
            _ => None,
        }
    }
}

/// Returns a human-readable, actionable message describing *why* a URL has
/// exhausted its retry budget. Driven by:
///   * `rate_limit_exhausted` — true iff the *rate-limit* budget (either the
///     429-retry count or the cumulative Retry-After wait) was the limiting
///     factor (decided by the caller, which knows the per-service limits),
///   * the dominant upstream error code observed for this (service, api) pair,
///     as recorded by `Stats::dominant_upstream_code`.
///
/// Specific codes get a tailored message; everything else falls back to a
/// generic line that still names the last code. Note: a URL may carry a
/// non-zero `rate_limit_retry_number` even when the *real-error* retry budget
/// was the actual cause — a transient 429 followed by repeated 4xx failures.
/// Relying on the URL counters alone would emit a misleading "throttled"
/// message in that case, hence the explicit flag from the caller.
pub fn human_retry_exhaustion_message(
    url: &Url,
    dominant_code: Option<&str>,
    rate_limit_exhausted: bool,
) -> String {
    let api = &url.api;
    let service = &url.service_name;
    let attempts = url.retry_number.max(1);

    if rate_limit_exhausted {
        return format!(
            "Endpoint {api:?} ({service}) remained throttled past the rate-limit budget ({}s cumulative across {} 429 retries). Consider raising rateLimitRetryLimit / rateLimitMaxWaitSecs (globally or via serviceOverrides), or lowering concurrencyMaxWindow for this service.",
            url.rate_limit_total_wait_secs, url.rate_limit_retry_number
        );
    }

    match dominant_code {
        Some("Authorization_RequestDenied") | Some("Forbidden") => format!(
            "Endpoint {api:?} ({service}) returned 403 on every attempt — the authenticated principal lacks the specific permission for this endpoint, even though the global prerequisites passed."
        ),
        Some("InvalidAuthenticationToken") => format!(
            "Endpoint {api:?} ({service}) failed token validation repeatedly — token refresh did not recover. Check clock skew or revoked tokens."
        ),
        Some("Request_ResourceNotFound") | Some("NotFound") | Some("ResourceNotFound") => format!(
            "Endpoint {api:?} ({service}) returned 404 on every attempt — the resource may have been deleted between enumeration and read."
        ),
        Some("InternalServerError")
        | Some("ServiceUnavailable")
        | Some("BadGateway")
        | Some("GatewayTimeout") => format!(
            "Endpoint {api:?} ({service}) returned server errors on every attempt. The Azure backend appears degraded for this resource; try again later."
        ),
        Some(code) => format!(
            "Endpoint {api:?} ({service}) exhausted its retry budget after {attempts} attempts (last upstream code: {code})."
        ),
        None => format!(
            "Endpoint {api:?} ({service}) exhausted its retry budget after {attempts} attempts."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::error::Error as StdError;
    use std::sync::Arc;

    #[test]
    fn test_error_display_string_error() {
        let err = Error::StringError("test error".to_string());
        let display = format!("{}", err);
        assert!(display.contains("StringError"));
    }

    #[test]
    fn test_error_display_url_creation() {
        let err = Error::UrlCreation;
        let display = format!("{}", err);
        assert!(display.contains("UrlCreation"));
    }

    #[test]
    fn test_error_display_config_file_not_found() {
        let err = Error::ConfigFileNotFound;
        let display = format!("{}", err);
        assert!(display.contains("ConfigFileNotFound"));
    }

    #[test]
    fn test_error_source_io_error() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let err = Error::IOError(io_err);
        assert!(StdError::source(&err).is_some());
    }

    #[test]
    fn test_error_source_none_for_simple_errors() {
        let err = Error::UrlCreation;
        assert!(StdError::source(&err).is_none());
    }

    #[test]
    fn test_error_debug_format() {
        let err = Error::InvalidConfigXMLStructure(None);
        let debug = format!("{:?}", err);
        assert_eq!(debug, "InvalidConfigXMLStructure(None)");
    }

    #[test]
    fn test_error_token_acquisition_error() {
        let err = Error::TokenAcquisitionError;
        let display = format!("{}", err);
        assert!(display.contains("TokenAcquisitionError"));
    }

    #[test]
    fn test_error_schema_file_not_found() {
        let err = Error::SchemaFileNotFound;
        let display = format!("{}", err);
        assert!(display.contains("SchemaFileNotFound"));
    }

    #[test]
    fn test_error_missing_app_permission() {
        let err = Error::MissingAppPermission;
        let display = format!("{}", err);
        assert!(display.contains("MissingAppPermission"));
    }

    #[test]
    fn test_error_reprocess_with_auth_error_payload() {
        let auth_err = AuthError {
            api: "graph".to_string(),
            error: "token parsing failed".to_string(),
        };
        let err = Error::Reprocess(Some(auth_err));
        let display = format!("{}", err);
        assert!(display.contains("Reprocess"));
    }

    #[test]
    fn test_error_reprocess_without_payload() {
        let err = Error::Reprocess(None);
        let display = format!("{}", err);
        assert!(display.contains("Reprocess"));
    }

    #[test]
    fn test_error_url_retry_limit_display() {
        let url = Url {
            service_name: "graph".to_string(),
            service_scopes: Arc::new(vec!["https://graph.microsoft.com/.default".to_string()]),
            service_mandatory_auth: true,
            api: "users".to_string(),
            url: "https://graph.microsoft.com/v1.0/users".to_string(),
            conditions: None,
            relationships: Arc::new(vec![]),
            api_behavior: Arc::new(HashMap::new()),
            expected_error_codes: None,
            parent: None,
            retry_number: 5,
            rate_limit_retry_number: 0,
            rate_limit_total_wait_secs: 0,
            post_body: None,
        };
        let err = Error::UrlRetryLimit(Box::new(url));
        let display = format!("{}", err);
        assert!(display.contains("UrlRetryLimit"));
    }

    fn url_with_counters(retry: usize, rl_retry: usize, rl_wait: u64) -> Url {
        Url {
            service_name: "graph".to_string(),
            service_scopes: Arc::new(vec![]),
            service_mandatory_auth: true,
            api: "users".to_string(),
            url: "https://graph.microsoft.com/v1.0/users".to_string(),
            conditions: None,
            relationships: Arc::new(vec![]),
            api_behavior: Arc::new(HashMap::new()),
            expected_error_codes: None,
            parent: None,
            retry_number: retry,
            rate_limit_retry_number: rl_retry,
            rate_limit_total_wait_secs: rl_wait,
            post_body: None,
        }
    }

    #[test]
    fn human_message_403_mentions_permission_specificity() {
        let url = url_with_counters(3, 0, 0);
        let msg = human_retry_exhaustion_message(&url, Some("Authorization_RequestDenied"), false);
        assert!(msg.contains("403"), "{msg}");
        assert!(msg.contains("permission"), "{msg}");
    }

    #[test]
    fn human_message_404_mentions_deleted_resource() {
        let url = url_with_counters(3, 0, 0);
        let msg = human_retry_exhaustion_message(&url, Some("Request_ResourceNotFound"), false);
        assert!(msg.contains("404"), "{msg}");
        assert!(msg.contains("deleted"), "{msg}");
    }

    #[test]
    fn human_message_5xx_mentions_backend_degraded() {
        let url = url_with_counters(5, 0, 0);
        let msg = human_retry_exhaustion_message(&url, Some("InternalServerError"), false);
        assert!(msg.contains("server error"), "{msg}");
        assert!(msg.contains("degraded"), "{msg}");
    }

    #[test]
    fn human_message_rate_limit_mentions_budget() {
        let url = url_with_counters(0, 50, 900);
        // The rate-limit branch ignores upstream_code even if one is provided.
        let msg = human_retry_exhaustion_message(&url, Some("InternalServerError"), true);
        assert!(msg.contains("throttled"), "{msg}");
        assert!(msg.contains("rateLimitMaxWaitSecs"), "{msg}");
        assert!(msg.contains("rateLimitRetryLimit"), "{msg}");
    }

    /// A URL that exhausted its *real-error* budget after a single transient 429
    /// must NOT be reported as throttled. The caller (dispatch.rs) computes
    /// `rate_limit_exhausted` and passes it as a boolean so the helper never
    /// inspects URL counters directly — a non-zero `rate_limit_retry_number`
    /// alone does not imply the cause was throttling.
    #[test]
    fn human_message_mixed_429_plus_real_errors_is_not_throttled() {
        // 1 transient 429 (recovered) + 3 unexpected 4xx that exhausted the
        // real-error budget.
        let url = url_with_counters(3, 1, 5);
        let msg = human_retry_exhaustion_message(&url, Some("Authorization_RequestDenied"), false);
        assert!(
            !msg.contains("throttled"),
            "real-error exhaustion must not surface as throttling; got: {msg}"
        );
        assert!(msg.contains("403"), "{msg}");
    }

    #[test]
    fn human_message_unknown_code_falls_back_to_generic() {
        let url = url_with_counters(5, 0, 0);
        let msg = human_retry_exhaustion_message(&url, Some("SomeWeirdCode"), false);
        assert!(msg.contains("SomeWeirdCode"), "{msg}");
        assert!(msg.contains("retry budget"), "{msg}");
    }

    #[test]
    fn human_message_no_code_still_useful() {
        let url = url_with_counters(5, 0, 0);
        let msg = human_retry_exhaustion_message(&url, None, false);
        assert!(msg.contains("retry budget"), "{msg}");
        assert!(msg.contains("users"), "{msg}");
        assert!(msg.contains("graph"), "{msg}");
    }

    // --- FatalPresentation ---

    #[test]
    fn fatal_context_string_error_returns_message() {
        let msg = "something went wrong".to_string();
        let err = Error::StringError(msg.clone());
        assert_eq!(err.context(), Some(msg));
    }

    #[test]
    fn fatal_context_client_credentials_flow_creation() {
        let msg = "cert parse error".to_string();
        let err = Error::ClientCredentialsFlowCreation(msg.clone());
        assert_eq!(err.context(), Some(msg));
    }

    #[test]
    fn fatal_context_client_credentials_flow_authentication() {
        let msg = "auth failed".to_string();
        let err = Error::ClientCredentialsFlowAuthentication(msg.clone());
        assert_eq!(err.context(), Some(msg));
    }

    #[test]
    fn fatal_context_none_for_simple_error() {
        assert_eq!(Error::UrlCreation.context(), None);
        assert_eq!(Error::ConfigFileNotFound.context(), None);
        assert_eq!(Error::MissingExchangeManageAsApp.context(), None);
    }

    #[test]
    fn fatal_remediation_steps_missing_exchange_manage_as_app_has_three_steps() {
        let steps = Error::MissingExchangeManageAsApp.remediation_steps();
        assert_eq!(steps.len(), 3);
        assert!(steps[0].contains("Exchange.ManageAsApp"));
        assert!(steps[1].contains("00000002-0000-0ff1-ce00-000000000000"));
        assert!(steps[2].contains("admin consent"));
    }

    #[test]
    fn fatal_remediation_steps_missing_exchange_manage_scope_has_two_steps() {
        let steps = Error::MissingExchangeManageScope.remediation_steps();
        assert_eq!(steps.len(), 2);
        assert!(steps[0].contains("Exchange.Manage"));
        assert!(steps[1].contains("admin consent"));
    }

    #[test]
    fn fatal_remediation_steps_empty_for_unhandled_variants() {
        assert_eq!(Error::UrlCreation.remediation_steps(), &[] as &[&str]);
        assert_eq!(Error::WriterLock.remediation_steps(), &[] as &[&str]);
    }

    #[test]
    fn fatal_title_string_error_falls_back_to_generic() {
        assert_eq!(Error::StringError("x".into()).title(), "Fatal error");
    }

    #[test]
    fn fatal_title_missing_exchange_manage_as_app() {
        assert_eq!(
            Error::MissingExchangeManageAsApp.title(),
            "Missing Exchange.ManageAsApp application permission"
        );
    }
}
