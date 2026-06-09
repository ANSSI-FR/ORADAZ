use crate::FL;
use crate::collect::auth::tokens::{SharedTokenState, Token};
use crate::utils::client::OradazClient;
use crate::utils::config::Config;
use crate::utils::errors::Error;
use crate::utils::stats::Stats;

use dashmap::DashMap;
use log::{debug, error, trace, warn};
use std::collections::HashMap;
use std::sync::Arc;

pub mod tenant;
pub mod user;
pub mod value;

/// Checks if certain conditions (tenant or user based) are met to decide whether to dump specific data.
#[derive(Clone)]
pub struct ConditionChecker {
    pub client: OradazClient,
    /// Cached results of tenant-level conditions (e.g., license types).
    pub tenant_conditions: HashMap<String, bool>,
    /// Cached results of user-level conditions, keyed by (user_id, condition_name).
    pub user_conditions: DashMap<(String, String), bool>,
    /// Configured custom security attribute to identify emergency accounts
    pub emergency_accounts_custom_attributes: String,
    pub org_url: String,
    /// Shared statistics counter; condition evaluations are recorded here.
    pub stats: Arc<Stats>,
    /// `true` when the collection is running under client credentials (application)
    /// authentication. Used to short-circuit the `GAOrApp` condition without
    /// making an additional Graph API call.
    pub is_application_auth: bool,
}

impl ConditionChecker {
    /// Initializes a new `ConditionChecker` by fetching and caching immutable tenant-level conditions.
    pub async fn new(
        client: &OradazClient,
        config: &Config,
        tokens: &DashMap<Arc<str>, SharedTokenState>,
        stats: Arc<Stats>,
    ) -> Result<ConditionChecker, Error> {
        debug!(
            "{:FL$}Initializing ConditionChecker by checking immutable conditions",
            "ConditionChecker"
        );
        let mut tenant_conditions: HashMap<String, bool> = HashMap::new();
        let graph_token = match tokens.get("graph") {
            Some(s) => s.token.read().await.clone(),
            None => {
                error!(
                    "{:FL$}Missing graph token to check for immutable conditions, aborting",
                    "ConditionChecker"
                );
                return Err(Error::MissingGraphApiTokenForConditionChecker);
            }
        };
        let org_url = "https://graph.microsoft.com/v1.0/organization".to_string();
        let licenses = tenant::check_tenant_licenses(
            client,
            &graph_token,
            &org_url,
            Config::default_retry_after_seconds(config),
        )
        .await;
        let publishing = tenant::check_publishing_profiles(
            client,
            &graph_token,
            tenant::PUBLISHING_PROFILES_URL,
            Config::default_retry_after_seconds(config),
        )
        .await;
        tenant_conditions.insert("P1".to_string(), licenses.p1);
        tenant_conditions.insert("P2".to_string(), licenses.p2);
        tenant_conditions.insert("Intune".to_string(), licenses.intune);
        tenant_conditions.insert("IsB2C".to_string(), licenses.is_b2c);
        tenant_conditions.insert(
            "HasApplicationProxy".to_string(),
            publishing.has_application_proxy,
        );
        tenant_conditions.insert(
            "HasExchangeHybrid".to_string(),
            publishing.has_exchange_hybrid,
        );
        tenant_conditions.insert(
            "HasADAdministration".to_string(),
            publishing.has_ad_administration,
        );
        debug!(
            "{:FL$}Tenant conditions: P1={} P2={} Intune={} IsB2C={} AppProxy={} ExchHybrid={} ADAdmin={}",
            "ConditionChecker",
            licenses.p1,
            licenses.p2,
            licenses.intune,
            licenses.is_b2c,
            publishing.has_application_proxy,
            publishing.has_exchange_hybrid,
            publishing.has_ad_administration
        );

        let emergency_accounts_custom_attributes = config
            .emergency_accounts_custom_attributes
            .clone()
            .unwrap_or(String::from("Emergency.isEmergency"));
        Ok(ConditionChecker {
            client: client.clone(),
            tenant_conditions,
            user_conditions: DashMap::new(),
            emergency_accounts_custom_attributes,
            org_url,
            stats,
            is_application_auth: Config::use_application_credentials_auth(config),
        })
    }

    /// Evaluates a given condition string.
    ///
    /// Tenant-level conditions (P1, P2, Intune) are checked against the cached `tenant_conditions`.
    /// User-level conditions (e.g., GA) are checked and cached in `user_conditions`.
    /// `attribution` is `Some((service, api))` when the evaluation is attributable
    /// to a specific API URL (initial URL build, relationship resolution, value
    /// handler), enabling per-API condition counts in `stats.json`.
    pub async fn check(
        &self,
        token: &Token,
        condition: String,
        attribution: Option<(&str, &str)>,
    ) -> bool {
        let result = match condition.as_str() {
            "P1" => self.tenant_conditions.get("P1").copied().unwrap_or(false),
            "NotP1" => !self.tenant_conditions.get("P1").copied().unwrap_or(false),
            "P2" => self.tenant_conditions.get("P2").copied().unwrap_or(false),
            "NotP2" => !self.tenant_conditions.get("P2").copied().unwrap_or(false),
            "Intune" => self
                .tenant_conditions
                .get("Intune")
                .copied()
                .unwrap_or(false),
            "IsB2C" => self
                .tenant_conditions
                .get("IsB2C")
                .copied()
                .unwrap_or(false),
            "NotB2C" => !self
                .tenant_conditions
                .get("IsB2C")
                .copied()
                .unwrap_or(false),
            "HasApplicationProxy" => self
                .tenant_conditions
                .get("HasApplicationProxy")
                .copied()
                .unwrap_or(false),
            "HasExchangeHybrid" => self
                .tenant_conditions
                .get("HasExchangeHybrid")
                .copied()
                .unwrap_or(false),
            "HasADAdministration" => self
                .tenant_conditions
                .get("HasADAdministration")
                .copied()
                .unwrap_or(false),
            "GA" => {
                let cache_key = (token.user_id.clone(), condition.clone());
                if let Some(cached) = self.user_conditions.get(&cache_key) {
                    *cached
                } else {
                    // Only cache a *definitive* answer. A transient probe failure
                    // (None) is treated as not-GA for this evaluation but left
                    // uncached so the next GA-gated API re-probes instead of
                    // silently skipping GA-gated APIs for the rest of the run.
                    match user::check_user_for_ga(self, token).await {
                        Some(result) => {
                            self.user_conditions.insert(cache_key, result);
                            result
                        }
                        None => false,
                    }
                }
            }
            "GAOrApp" => {
                if self.is_application_auth {
                    true
                } else {
                    // Reuse the GA cache entry: the user-side check is identical
                    // to GA, so we avoid a redundant Graph API call when both
                    // conditions are evaluated for the same user.
                    let cache_key = (token.user_id.clone(), "GA".to_string());
                    if let Some(cached) = self.user_conditions.get(&cache_key) {
                        *cached
                    } else {
                        match user::check_user_for_ga(self, token).await {
                            Some(result) => {
                                self.user_conditions.insert(cache_key, result);
                                result
                            }
                            None => false,
                        }
                    }
                }
            }
            other => {
                warn!(
                    "{:FL$}Invalid condition {:?} in schema file. Considering condition as not meet.",
                    "ConditionChecker", other
                );
                false
            }
        };
        trace!(
            "{:FL$}Condition {:?}: {}",
            "ConditionChecker", condition, result
        );
        self.stats
            .record_condition_check(&condition, result, attribution);
        result
    }

    /// Checks if the provided JSON value represents a unified group.
    pub fn check_if_unified_group(&self, value: &serde_json::Value) -> bool {
        value::check_if_unified_group(value)
    }

    /// Checks if the provided JSON value represents a role-assignable group.
    pub fn check_if_role_assignable(&self, value: &serde_json::Value) -> bool {
        value::check_if_role_assignable(value)
    }

    /// Determines if a folder requires a permission dump based on its properties.
    pub fn check_if_folder_require_permission_dump(&self, value: &serde_json::Value) -> bool {
        value::check_if_folder_require_permission_dump(value)
    }

    /// Checks if a specific user meets the "GA" (General Availability) condition.
    pub async fn check_user_for_ga(&self, token: &Token) -> bool {
        user::check_user_for_ga(self, token).await.unwrap_or(false)
    }

    /// Checks if a specific user has the customSecurityAttributes of an emergency account.
    pub fn check_if_emergency_account(&self, value: &serde_json::Value) -> bool {
        user::check_if_emergency_account(self, value)
    }

    /// Returns `true` if the ARM resource ID is for a top-level resource
    /// that supports the PIM API at resource scope.
    pub fn check_resource_supports_pim(&self, value: &serde_json::Value) -> bool {
        value::check_resource_supports_pim(value)
    }

    /// Checks if the user has at least one license assigned.
    pub fn check_has_license(&self, value: &serde_json::Value) -> bool {
        value::check_has_license(value)
    }

    pub fn check_if_federated(&self, value: &serde_json::Value) -> bool {
        value::check_if_federated(value)
    }

    pub fn check_if_managed(&self, value: &serde_json::Value) -> bool {
        value::check_if_managed(value)
    }

    /// Checks if the user is an enabled member (not a guest, not disabled).
    /// Used to skip per-user `authentication/methods` calls for guests and
    /// disabled accounts, reducing fan-out on that rate-limited endpoint.
    pub fn check_if_enabled_member(&self, value: &serde_json::Value) -> bool {
        value::check_if_enabled_member(value)
    }
}
