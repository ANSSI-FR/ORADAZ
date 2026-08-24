pub mod exchange;
pub mod graph;
pub mod jwt_claims;
pub mod models;
pub mod resources;

pub use crate::collect::prerequisites::models::*;

use crate::FL;
use crate::collect::auth::tokens::{SharedTokenState, Token};
use crate::utils::errors::Error;
use crate::utils::ui::prereq::{Outcome, PrereqItem};
use crate::utils::writer::actor::WriterHandle;

use dashmap::DashMap;
use log::{debug, error, info, trace, warn};
use reqwest::Client;
use std::collections::BTreeMap;
use std::sync::Arc;

pub struct UrlOverrides {
    pub graph: Option<String>,
    pub resources: Option<String>,
    pub exchange: Option<String>,
}

pub struct PrereqCheckOptions {
    pub silent: bool,
    pub overrides: UrlOverrides,
    pub use_application_credentials: bool,
    /// `true` when the current auth flow is managed identity (system or user-assigned).
    /// When set, the Graph application-permissions check queries the API directly
    /// instead of relying on the `roles` JWT claim, which IMDS omits for system-assigned MIs.
    pub use_managed_identity: bool,
    pub default_retry_after: u64,
}

pub struct Prerequisites {}

impl Prerequisites {
    fn create_ok_item(name: &str, detail: String, sub_bullets: Vec<String>) -> PrereqItem {
        PrereqItem {
            name: name.to_string(),
            outcome: Outcome::Ok { detail },
            sub_bullets,
            nested_bullets: false,
        }
    }

    fn create_warn_item(name: &str, detail: String, sub_bullets: Vec<String>) -> PrereqItem {
        PrereqItem {
            name: name.to_string(),
            outcome: Outcome::Warn { detail },
            sub_bullets,
            nested_bullets: false,
        }
    }

    fn create_err_item(name: &str, detail: String, sub_bullets: Vec<String>) -> PrereqItem {
        PrereqItem {
            name: name.to_string(),
            outcome: Outcome::Err { detail },
            sub_bullets,
            nested_bullets: false,
        }
    }

    /// Verifies a single token for its corresponding service, allowing URL overrides for testing.
    pub async fn check_with_overrides(
        client: &Client,
        token: &Token,
        options: PrereqCheckOptions,
    ) -> Result<(), Error> {
        let service = token.service.as_str();
        let graph_base_url = options
            .overrides
            .graph
            .as_deref()
            .unwrap_or("https://graph.microsoft.com");
        let resources_base_url = options
            .overrides
            .resources
            .as_deref()
            .unwrap_or("https://management.azure.com");

        match service {
            "graph" => {
                if options.use_application_credentials {
                    if options.use_managed_identity {
                        graph::check_app_permissions_for_managed_identity(
                            client,
                            token,
                            options.silent,
                            graph_base_url,
                            options.default_retry_after,
                        )
                        .await
                        .map_err(|(e, _)| e)?;
                    } else {
                        graph::check_app_permissions_for_client_credentials(token, options.silent)
                            .map_err(|(e, _)| e)?;
                    }
                    graph::check_sp_global_reader_role(
                        client,
                        token,
                        options.silent,
                        graph_base_url,
                        options.default_retry_after,
                    )
                    .await
                    .map(|_| ())
                } else {
                    graph::check_app_permissions(token, options.silent).map_err(|(e, _)| e)?;
                    graph::check_entra_roles_for_graph(
                        client,
                        token,
                        options.silent,
                        graph_base_url,
                        options.default_retry_after,
                    )
                    .await
                    .map(|_| ())
                    .map_err(|(e, _)| e)
                }
            }
            "resources" => {
                if !options.use_application_credentials {
                    resources::check_user_impersonation_scope(token, options.silent)?;
                }
                resources::check_available_subscriptions(
                    client,
                    token,
                    options.silent,
                    resources_base_url,
                    options.default_retry_after,
                )
                .await
                .map(|_| ())
            }
            "exchange" => {
                if options.use_application_credentials {
                    exchange::check_exchange_manage_as_app(token, options.silent)
                } else {
                    exchange::check_exchange_manage_scope(token, options.silent)
                }
            }
            _ => Err(Error::InvalidTokenToCheck),
        }
    }

    /// Verifies a single token for its corresponding service.
    pub async fn check(
        client: &Client,
        token: &Token,
        silent: bool,
        use_application_credentials: bool,
        use_managed_identity: bool,
        default_retry_after: u64,
    ) -> Result<(), Error> {
        Self::check_with_overrides(
            client,
            token,
            PrereqCheckOptions {
                silent,
                overrides: UrlOverrides {
                    graph: None,
                    resources: None,
                    exchange: None,
                },
                use_application_credentials,
                use_managed_identity,
                default_retry_after,
            },
        )
        .await
    }

    async fn check_graph_async(
        client: Client,
        tokens: Arc<DashMap<Arc<str>, SharedTokenState>>,
        use_application_credentials: bool,
        use_managed_identity: bool,
        silent: bool,
        default_retry_after: u64,
    ) -> Result<(Vec<PrereqItem>, Option<i64>, Option<String>), (Error, Vec<PrereqItem>, Vec<String>)>
    {
        let state = match tokens.get("graph") {
            None => return Err((Error::MissingGraphApiToken, vec![], vec![])),
            Some(s) => s.value().clone(),
        };
        let token = state.token.read().await;
        let graph_base_url = "https://graph.microsoft.com";

        if use_application_credentials {
            if use_managed_identity {
                if let Err((err, missing)) = graph::check_app_permissions_for_managed_identity(
                    &client,
                    &token,
                    silent,
                    graph_base_url,
                    default_retry_after,
                )
                .await
                {
                    return Err((err, vec![], missing));
                }
            } else if let Err((err, missing)) =
                graph::check_app_permissions_for_client_credentials(&token, silent)
            {
                return Err((err, vec![], missing));
            }
            trace!(
                "{:FL$}Checking Global Reader role for service principal",
                "Prerequisites"
            );
            match graph::check_sp_global_reader_role(
                &client,
                &token,
                silent,
                graph_base_url,
                default_retry_after,
            )
            .await
            {
                Ok((new_exp, role_info)) => Ok((
                    vec![Self::create_ok_item(
                        "Microsoft Graph API",
                        "".to_string(),
                        vec![role_info.clone()],
                    )],
                    new_exp,
                    Some(role_info),
                )),
                Err(err) => Err((err, vec![], vec![])),
            }
        } else {
            if let Err((err, missing)) = graph::check_app_permissions(&token, silent) {
                return Err((err, vec![], missing));
            }
            trace!("{:FL$}Checking Graph Entra roles", "Prerequisites");
            match graph::check_entra_roles_for_graph(
                &client,
                &token,
                silent,
                graph_base_url,
                default_retry_after,
            )
            .await
            {
                Ok((new_exp, role_info)) => Ok((
                    vec![Self::create_ok_item(
                        "Microsoft Graph API",
                        "".to_string(),
                        vec![role_info.clone()],
                    )],
                    new_exp,
                    Some(role_info),
                )),
                Err((err, missing_roles)) => Err((err, vec![], missing_roles)),
            }
        }
    }

    async fn check_resources_async(
        client: Client,
        tokens: Arc<DashMap<Arc<str>, SharedTokenState>>,
        use_application_credentials: bool,
        silent: bool,
        default_retry_after: u64,
    ) -> (
        Vec<PrereqItem>,
        Option<PrerequisitesMetadata>,
        Option<Error>,
        Option<usize>,
        Vec<String>,
    ) {
        match tokens.get("resources") {
            None => {
                warn!(
                    "{:FL$}Missing Resources API token to check prerequisites. Azure subscriptions will not be audited. If you want to audit them, ensure 'resources' service is set to 1 in config file",
                    "Prerequisites"
                );
                (
                    vec![Self::create_warn_item(
                        "Azure resources",
                        "service not enabled (skipped)".to_string(),
                        vec![],
                    )],
                    Some(PrerequisitesMetadata {
                        api: "resources".to_string(),
                        error: Error::MissingResourcesApiToken.to_string(),
                    }),
                    None,
                    None,
                    vec![],
                )
            }
            Some(state) => {
                let token_state = state.value().clone();
                drop(state);
                let token = token_state.token.read().await;

                if !use_application_credentials
                    && let Err(err) = resources::check_user_impersonation_scope(&token, silent)
                {
                    return (
                        vec![Self::create_warn_item(
                            "Azure resources",
                            "Missing Azure Resource Manager permission".to_string(),
                            vec!["user_impersonation (Delegated)".to_string()],
                        )],
                        Some(PrerequisitesMetadata {
                            api: "resources".to_string(),
                            error: err.to_string(),
                        }),
                        Some(err),
                        None,
                        vec![],
                    );
                }

                match resources::check_available_subscriptions(
                    &client,
                    &token,
                    silent,
                    "https://management.azure.com",
                    default_retry_after,
                )
                .await
                {
                    Ok(pairs) => {
                        let count = pairs.len();
                        let mut sub_bullets = vec![format!(
                            "{} subscription{}",
                            count,
                            if count == 1 { "" } else { "s" }
                        )];
                        sub_bullets.extend(pairs.iter().map(|(name, _id)| name.clone()));
                        let ids: Vec<String> = pairs.into_iter().map(|(_name, id)| id).collect();
                        (
                            {
                                let mut item = Self::create_ok_item(
                                    "Azure resources",
                                    "".to_string(),
                                    sub_bullets,
                                );
                                item.nested_bullets = true;
                                vec![item]
                            },
                            None,
                            None,
                            Some(count),
                            ids,
                        )
                    }
                    Err(err) => {
                        let (detail, sub_bullets) = if matches!(err, Error::NoAvailableSubscription)
                        {
                            (
                                "No available subscription".to_string(),
                                vec!["Missing Reader role ?".to_string()],
                            )
                        } else {
                            (format!("{} (skipped)", err), vec![])
                        };
                        (
                            vec![Self::create_warn_item(
                                "Azure resources",
                                detail,
                                sub_bullets,
                            )],
                            Some(PrerequisitesMetadata {
                                api: "resources".to_string(),
                                error: err.to_string(),
                            }),
                            Some(err),
                            None,
                            vec![],
                        )
                    }
                }
            }
        }
    }

    async fn check_exchange_async(
        tokens: Arc<DashMap<Arc<str>, SharedTokenState>>,
        use_application_credentials: bool,
        silent: bool,
    ) -> (
        Vec<PrereqItem>,
        Option<PrerequisitesMetadata>,
        Option<Error>,
    ) {
        match tokens.get("exchange") {
            None => {
                warn!(
                    "{:FL$}Missing Exchange Online API token to check prerequisites. Exchange Online will not be audited. If you want to audit it, ensure 'exchange' service is set to 1 in config file",
                    "Prerequisites"
                );
                (
                    vec![Self::create_warn_item(
                        "Exchange Online",
                        "service not enabled (skipped)".to_string(),
                        vec![],
                    )],
                    Some(PrerequisitesMetadata {
                        api: "exchange".to_string(),
                        error: Error::MissingExchangeApiToken.to_string(),
                    }),
                    None,
                )
            }
            Some(state) => {
                let token_state = state.value().clone();
                drop(state);
                let token = token_state.token.read().await;

                let (result, missing_detail): (Result<(), Error>, Vec<String>) =
                    if use_application_credentials {
                        let r = exchange::check_exchange_manage_as_app(&token, silent);
                        (r, vec!["Exchange.ManageAsApp (Application)".to_string()])
                    } else {
                        let r = exchange::check_exchange_manage_scope(&token, silent);
                        (r, vec!["Exchange.Manage (Delegated)".to_string()])
                    };

                match result {
                    Ok(()) => (
                        vec![Self::create_ok_item(
                            "Exchange Online",
                            "".to_string(),
                            vec![],
                        )],
                        None,
                        None,
                    ),
                    Err(err) => {
                        let detail = "Missing Office 365 Exchange Online permission".to_string();
                        (
                            vec![Self::create_warn_item(
                                "Exchange Online",
                                detail,
                                missing_detail,
                            )],
                            Some(PrerequisitesMetadata {
                                api: "exchange".to_string(),
                                error: err.to_string(),
                            }),
                            Some(err),
                        )
                    }
                }
            }
        }
    }

    /// Orchestrates the prerequisite checks for all enabled services.
    ///
    /// The third value of the success tuple is the list of Azure subscription
    /// IDs the caller (Dumper) needs to populate the `subscriptions` array of
    /// Azure Resource Graph requests. It is empty when the resources service
    /// is disabled or the prereq check failed.
    pub async fn check_all(
        writer: &WriterHandle,
        client: &Client,
        tokens: Arc<DashMap<Arc<str>, SharedTokenState>>,
        use_application_credentials: bool,
        use_managed_identity: bool,
        default_retry_after: u64,
    ) -> Result<(usize, Vec<PrereqItem>, Vec<String>), (Error, Vec<PrereqItem>)> {
        info!("{:FL$}Checking prerequisites", "Prerequisites");
        debug!(
            "{:FL$}Starting comprehensive prerequisite verification",
            "Prerequisites"
        );
        let mut prerequisites_metadata: Vec<PrerequisitesMetadata> = Vec::new();
        let mut prereq_items: Vec<PrereqItem> = Vec::new();

        let resources_initially_enabled = tokens.contains_key("resources");
        let exchange_initially_enabled = tokens.contains_key("exchange");
        let silent: bool = false;

        let client_clone = client.clone();
        let tokens_clone = Arc::clone(&tokens);
        let use_app_clone = use_application_credentials;
        let use_mi_clone = use_managed_identity;
        let retry_clone = default_retry_after;

        let graph_handle = tokio::spawn(async move {
            Self::check_graph_async(
                client_clone,
                tokens_clone,
                use_app_clone,
                use_mi_clone,
                silent,
                retry_clone,
            )
            .await
        });

        let client_clone = client.clone();
        let tokens_clone = Arc::clone(&tokens);
        let use_app_clone = use_application_credentials;
        let retry_clone = default_retry_after;
        let res_handle = tokio::spawn(async move {
            Self::check_resources_async(
                client_clone,
                tokens_clone,
                use_app_clone,
                silent,
                retry_clone,
            )
            .await
        });

        let tokens_clone = Arc::clone(&tokens);
        let use_app_clone = use_application_credentials;
        let ex_handle = tokio::spawn(async move {
            Self::check_exchange_async(tokens_clone, use_app_clone, silent).await
        });

        let graph_res = graph_handle.await.map_err(|e| {
            error!(
                "{:FL$}Graph prerequisite task panicked: {:?}",
                "Prerequisites", e
            );
            (
                Error::StringError("Graph prerequisite task panicked".to_string()),
                prereq_items.clone(),
            )
        })?;
        let res_res = res_handle.await.map_err(|e| {
            error!(
                "{:FL$}Resources prerequisite task panicked: {:?}",
                "Prerequisites", e
            );
            (
                Error::StringError("Resources prerequisite task panicked".to_string()),
                prereq_items.clone(),
            )
        })?;
        let ex_res = ex_handle.await.map_err(|e| {
            error!(
                "{:FL$}Exchange prerequisite task panicked: {:?}",
                "Prerequisites", e
            );
            (
                Error::StringError("Exchange prerequisite task panicked".to_string()),
                prereq_items.clone(),
            )
        })?;

        let graph_role_info: Option<String>;
        match graph_res {
            Ok((items, new_exp, role_info)) => {
                graph_role_info = role_info;
                // Idempotent on retry: `new_exp = pim_end + THRESHOLD - DELAY`
                // is strictly greater than `pim_end` as long as `THRESHOLD >
                // DELAY` (currently 600 > 30 in user_roles/sp_roles), so the
                // `new_exp < token.expires_on` check inside PIM logic keeps
                // converging on the same value across attempts.
                if let Some(exp) = new_exp
                    && let Some(state) = tokens.get("graph")
                {
                    let token_state = state.value().clone();
                    drop(state);
                    token_state.token.write().await.expires_on = exp;
                }
                prereq_items.extend(items);
            }
            Err((err, _items, missing)) => {
                let (detail, sub_bullets) =
                    if matches!(err, Error::MissingEntraRoles) && !missing.is_empty() {
                        ("Missing Entra ID Role(s)".to_string(), missing)
                    } else if matches!(
                        err,
                        Error::MissingEntraRoles | Error::MissingGlobalReaderRoleForApplication
                    ) {
                        (
                            "Missing Entra ID Role(s)".to_string(),
                            vec!["Global Reader".to_string()],
                        )
                    } else if !missing.is_empty() {
                        let detail = "Missing Microsoft Graph API permission".to_string();
                        let suffix = if use_application_credentials {
                            " (Application)"
                        } else {
                            " (Delegated)"
                        };
                        let sub_bullets = missing
                            .into_iter()
                            .map(|m| format!("{}{}", m, suffix))
                            .collect();
                        (detail, sub_bullets)
                    } else {
                        (err.to_string(), vec![])
                    };
                prereq_items.push(Self::create_err_item(
                    "Microsoft Graph API",
                    detail,
                    sub_bullets,
                ));
                prerequisites_metadata.push(PrerequisitesMetadata {
                    api: "graph".to_string(),
                    error: err.to_string(),
                });
                // Graph API is critical
                return Err((err, prereq_items));
            }
        }

        let (res_items, res_meta, res_err, res_sub_count, subscription_ids) = res_res;
        // A 429 during the subscriptions probe is transient and must trigger
        // the outer retry loop in dump/mod.rs rather than silently disabling
        // the audit. Escalate before consuming the warn-item.
        if let Some(Error::TooManyRequestsDuringPrerequisites(sec)) = res_err.as_ref() {
            prereq_items.extend(res_items);
            return Err((
                Error::TooManyRequestsDuringPrerequisites(*sec),
                prereq_items,
            ));
        }
        prereq_items.extend(res_items);
        let resources_error_text: Option<String> = res_err.as_ref().map(|e| e.to_string());
        let resources_had_error = res_err.is_some();
        if let Some(meta) = res_meta {
            prerequisites_metadata.push(meta);
        }
        if let Some(_err) = res_err {
            drop(tokens.remove("resources"));
            warn!(
                "{:FL$}Subscriptions audit will be skipped due to missing prerequisites",
                "Prerequisites"
            );
        }

        let (ex_items, ex_meta, ex_err) = ex_res;
        // Exchange is JWT-only today so 429 cannot originate here, but match
        // for symmetry in case a future HTTP probe is reintroduced.
        if let Some(Error::TooManyRequestsDuringPrerequisites(sec)) = ex_err.as_ref() {
            prereq_items.extend(ex_items);
            return Err((
                Error::TooManyRequestsDuringPrerequisites(*sec),
                prereq_items,
            ));
        }
        prereq_items.extend(ex_items);
        let exchange_error_text: Option<String> = ex_err.as_ref().map(|e| e.to_string());
        let exchange_had_error = ex_err.is_some();
        if let Some(meta) = ex_meta {
            prerequisites_metadata.push(meta);
        }
        if let Some(err) = ex_err {
            drop(tokens.remove("exchange"));
            match err {
                Error::MissingExchangeManageAsApp => warn!(
                    "{:FL$}Exchange Online audit will be skipped — application is missing the Exchange.ManageAsApp permission on Office 365 Exchange Online API",
                    "Prerequisites"
                ),
                Error::MissingExchangeManageScope => warn!(
                    "{:FL$}Exchange Online audit will be skipped — token is missing the Exchange.Manage delegated scope",
                    "Prerequisites"
                ),
                _ => warn!(
                    "{:FL$}Exchange Online audit will be skipped due to missing prerequisites",
                    "Prerequisites"
                ),
            }
        }

        // Build and write prerequisites.json
        let mut prereq_map: BTreeMap<String, ServicePrereqInfo> = BTreeMap::new();
        prereq_map.insert(
            "graph".to_string(),
            ServicePrereqInfo {
                status: "ok".to_string(),
                info: graph_role_info,
                error: None,
            },
        );
        prereq_map.insert(
            "resources".to_string(),
            if !resources_initially_enabled {
                ServicePrereqInfo {
                    status: "disabled".to_string(),
                    info: None,
                    error: Some("Disabled in config".to_string()),
                }
            } else if resources_had_error {
                ServicePrereqInfo {
                    status: "error".to_string(),
                    info: None,
                    error: resources_error_text,
                }
            } else {
                let count = res_sub_count.unwrap_or(0);
                ServicePrereqInfo {
                    status: "ok".to_string(),
                    info: Some(format!(
                        "{} subscription{}",
                        count,
                        if count == 1 { "" } else { "s" }
                    )),
                    error: None,
                }
            },
        );
        prereq_map.insert(
            "exchange".to_string(),
            if !exchange_initially_enabled {
                ServicePrereqInfo {
                    status: "disabled".to_string(),
                    info: None,
                    error: Some("Disabled in config".to_string()),
                }
            } else if exchange_had_error {
                ServicePrereqInfo {
                    status: "error".to_string(),
                    info: None,
                    error: exchange_error_text,
                }
            } else {
                ServicePrereqInfo {
                    status: "ok".to_string(),
                    info: None,
                    error: None,
                }
            },
        );
        match serde_json::to_string(&prereq_map) {
            Ok(j) => {
                if let Err(err) = writer
                    .write_file(String::new(), "prerequisites.json".to_string(), j)
                    .await
                {
                    error!(
                        "{:FL$}Error while writing prerequisites.json: {:?}",
                        "Prerequisites", err
                    );
                    return Err((Error::WriterLock, prereq_items));
                }
            }
            Err(err) => {
                error!(
                    "{:FL$}Could not convert prerequisites to json: {:?}",
                    "Prerequisites", err
                );
                return Err((Error::PrerequisitesErrorsToJSON, prereq_items));
            }
        }

        if !prerequisites_metadata.is_empty() {
            let mut multiline_string = String::new();
            for meta in &prerequisites_metadata {
                match serde_json::to_string(meta) {
                    Ok(j) => multiline_string.push_str(&format!("{j}\n")),
                    Err(err) => {
                        error!(
                            "{:FL$}Could not convert prerequisite error to json",
                            "Prerequisites"
                        );
                        debug!(
                            "{:FL$}JSON serialization error for prerequisites metadata: {:?}",
                            "Prerequisites", err
                        );
                        return Err((Error::PrerequisitesErrorsToJSON, prereq_items));
                    }
                }
            }
            if let Err(err) = writer
                .write_file(
                    String::new(),
                    "prerequisites_errors.json".to_string(),
                    multiline_string,
                )
                .await
            {
                error!(
                    "{:FL$}Error while writing prerequisites errors: {:?}",
                    "Prerequisites", err
                );
                return Err((Error::WriterLock, prereq_items));
            }
        }

        debug!(
            "{:FL$}Prerequisites complete: graph=ok resources={} exchange={} subscription_ids={}",
            "Prerequisites",
            if !resources_initially_enabled {
                "disabled"
            } else if resources_had_error {
                "error"
            } else {
                "ok"
            },
            if !exchange_initially_enabled {
                "disabled"
            } else if exchange_had_error {
                "error"
            } else {
                "ok"
            },
            subscription_ids.len()
        );
        Ok((prerequisites_metadata.len(), prereq_items, subscription_ids))
    }
}

/// Handles HTTP 429 (Too Many Requests) responses during prerequisite checks.
pub fn handle_429(
    res: reqwest::Response,
    default_retry_after: u64,
) -> Result<reqwest::Response, Error> {
    if res.status().as_u16() == 429 {
        // Reuse the main pipeline's parser so a prereq 429 honours both the
        // delta-seconds and HTTP-date Retry-After formats (was delta-only).
        let sec: u64 = crate::collect::dump::request::executor::parse_retry_after(res.headers())
            .unwrap_or(default_retry_after);
        debug!(
            "{:FL$}Too many requests while checking prerequisites. Retry-After: {}s",
            "Prerequisites", sec
        );
        return Err(Error::TooManyRequestsDuringPrerequisites(sec));
    }
    Ok(res)
}
