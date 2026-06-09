use crate::FL;
use crate::collect::auth::tokens::Token;
use crate::collect::dump::conditions::ConditionChecker;
use crate::utils::url::transform::apply_transform;
use crate::utils::url::types::RelationshipUrl;

use log::{debug, trace, warn};
use serde_json::Value;
use std::collections::HashMap;

/// Sentinel key name used in the schema for a condition-only guard key — one
/// whose `conditions` gate the relationship (e.g. `IsEmergency` on
/// `customSecurityAttributes`) but whose value is never substituted into the
/// URL. Such keys are skipped during parent-parameter extraction.
const PLACEHOLDER_KEY: &str = "[PLACEHOLDER]";

impl RelationshipUrl {
    /// Returns `true` if every condition in `conditions` is satisfied for `data_value`.
    ///
    /// Each named condition is dispatched in the `match` below: specialised
    /// value-level checks are handled inline, and any other name is delegated to
    /// the tenant-level `ConditionChecker::check`. Returns `false` early on the
    /// first failing condition so the caller can skip the relationship entirely.
    ///
    /// `data_value` is whatever the caller passes: `get_url` passes the **full
    /// parent object** for a relationship-level condition (`self.conditions`) but
    /// only `data.get(key.value)` for a key-level one (`key.conditions`). This
    /// matters per check: *object-reading* checks (those that `pointer("/field")`
    /// into the value — `UnifiedGroup`, `IsAssignableToRole`, `HasLicense`,
    /// `IsFederated`, `IsManaged`, `IsEnabledMember`) only work at the
    /// relationship level; *string/sub-object* readers (`SupportsResourcePIM` on
    /// an ARM id, `IsEmergency` / `FolderTypeWithPermissions`) are meant for
    /// key-level use. A key-level object-reading check on a `value:"id"` key would
    /// receive the id string and always return `false` (guarded by
    /// `tests/utils_schema.rs::test_object_reading_conditions_never_at_key_level`).
    async fn key_passes_conditions(
        &self,
        condition_checker: &ConditionChecker,
        token: &Token,
        conditions: &[String],
        data_value: &serde_json::Value,
        request_id: u32,
    ) -> bool {
        for condition in conditions.iter() {
            match condition.as_str() {
                "UnifiedGroup" => {
                    if !condition_checker.check_if_unified_group(data_value) {
                        return false;
                    }
                }
                "IsAssignableToRole" => {
                    if !condition_checker.check_if_role_assignable(data_value) {
                        return false;
                    }
                }
                "FolderTypeWithPermissions" => {
                    if !condition_checker.check_if_folder_require_permission_dump(data_value) {
                        return false;
                    }
                }
                "IsEmergency" => {
                    if !condition_checker.check_if_emergency_account(data_value) {
                        return false;
                    }
                }
                "IsEnabledMember" => {
                    if !condition_checker.check_if_enabled_member(data_value) {
                        return false;
                    }
                }
                "SupportsResourcePIM" => {
                    if !condition_checker.check_resource_supports_pim(data_value) {
                        return false;
                    }
                }
                "HasLicense" => {
                    if !condition_checker.check_has_license(data_value) {
                        return false;
                    }
                }
                "IsFederated" => {
                    if !condition_checker.check_if_federated(data_value) {
                        return false;
                    }
                }
                "IsManaged" => {
                    if !condition_checker.check_if_managed(data_value) {
                        return false;
                    }
                }
                c => {
                    trace!(
                        "{:FL$}Checking condition {:?} for relationship {:?} of API {:?} for service {:?} (id: {}).",
                        "RelationshipUrl", c, &self.name, &self.api, &self.service, request_id
                    );
                    if !condition_checker
                        .check(token, c.to_string(), Some((&self.service, &self.api)))
                        .await
                    {
                        return false;
                    }
                }
            }
        }
        true
    }

    /// Extracts key-value pairs from the parent object's data to be used in the relationship URL.
    pub fn get_parent(&self, data: &Value, request_id: u32) -> HashMap<String, String> {
        let mut res: HashMap<String, String> = HashMap::new();
        if let Some(keys) = &self.keys {
            for key in keys {
                // Condition-only guard keys are not URL parameters; their value
                // (often a non-string object such as customSecurityAttributes)
                // is intentionally not extracted, and emitting a "could not
                // convert" line for every parent would be pure noise.
                if key.name == PLACEHOLDER_KEY {
                    continue;
                }
                match data.get(key.value.as_str()) {
                    Some(data_value) => match data_value.as_str() {
                        Some(v) => {
                            res.insert(key.value.clone(), v.to_string());
                        }
                        None => debug!(
                            "{:FL$}Could not convert parent key {:?} to str for relationship {:?} of API {:?} for service {:?} (id: {})",
                            "RelationshipUrl",
                            &key.name,
                            &self.name,
                            &self.api,
                            &self.service,
                            request_id
                        ),
                    },
                    None => {
                        debug!(
                            "{:FL$}Trying to insert parent key {:?} for relationship {:?} of API {:?} for service {:?} while data does not contain it (id: {})",
                            "RelationshipUrl",
                            &key.name,
                            &self.name,
                            &self.api,
                            &self.service,
                            request_id
                        );
                    }
                }
            }
        }
        res
    }

    /// Constructs the target URL for a relationship, resolving keys and parameters from the source data.
    ///
    /// This method handles complex logic for resolving dynamic values from the parent object,
    /// applying transformations, and verifying conditions (including specialized checks like `UnifiedGroup`).
    pub async fn get_url(
        &self,
        token: &Token,
        data: &Value,
        previous_url: String,
        condition_checker: &ConditionChecker,
        request_id: u32,
    ) -> String {
        if let Some(conditions) = &self.conditions
            && !self
                .key_passes_conditions(condition_checker, token, conditions, data, request_id)
                .await
        {
            return String::new();
        }

        let mut url: String = self.url_scheme.clone();

        if url.contains("[KEEP_URL]") {
            url = self.uri.replace(
                "[KEEP_URL]",
                previous_url.split('?').next().unwrap_or(&previous_url),
            );
        }

        url = url.replace("[URI]", &self.uri);

        let mut done: Vec<String> = Vec::new();
        if let Some(keys) = &self.keys {
            for key in keys {
                match data.get(key.value.as_str()) {
                    Some(data_value) => {
                        match data_value.as_str() {
                            Some(v) => {
                                if url.contains(&key.name) {
                                    if let Some(c) = &key.conditions
                                        && !self
                                            .key_passes_conditions(
                                                condition_checker,
                                                token,
                                                c,
                                                data_value,
                                                request_id,
                                            )
                                            .await
                                    {
                                        // Skip relationship if data does not match condition
                                        trace!(
                                            "{:FL$}Condition {:?}, is not met for key {:?} for relationship {:?} of API {:?} for service {:?} (id: {}) - {:?}",
                                            "RelationshipUrl",
                                            c,
                                            &key.name,
                                            &self.name,
                                            &self.api,
                                            &self.service,
                                            request_id,
                                            data_value
                                        );
                                        return String::new();
                                    }
                                    let substituted = match apply_transform(
                                        v,
                                        key.transform.as_deref(),
                                    ) {
                                        Some(transformed) => transformed,
                                        None => {
                                            warn!(
                                                "{:FL$}Invalid transform {:?} in schema file for key {:?} for relationship {:?} of API {:?} for service {:?}. Skipping transformation.",
                                                "RelationshipUrl",
                                                key.transform,
                                                &key.name,
                                                &self.name,
                                                &self.api,
                                                &self.service
                                            );
                                            v.to_string()
                                        }
                                    };
                                    if substituted.is_empty() {
                                        // An empty key value would collapse the path
                                        // (e.g. `managementGroups//descendants`) into a
                                        // valid-looking but wrong URL once
                                        // `collapse_path_double_slashes` runs; skip the
                                        // relationship instead of dispatching a request
                                        // against the wrong resource.
                                        trace!(
                                            "{:FL$}Empty value for key {:?} of relationship {:?} of API {:?} for service {:?} (id: {}), skipping relationship",
                                            "RelationshipUrl",
                                            &key.name,
                                            &self.name,
                                            &self.api,
                                            &self.service,
                                            request_id
                                        );
                                        return String::new();
                                    }
                                    // Substitute the (already-transformed) value
                                    // raw. Per-segment percent-encoding is opt-in
                                    // via `transform: "UrlEncode"` on keys that are
                                    // a single path segment and may carry unsafe
                                    // characters (management-group `name`,
                                    // ADHybridHealthService `serviceName`). Keys
                                    // whose value is a full resource path (an ARM
                                    // `id` used as a `[1]/providers/...` prefix) keep
                                    // their `/` separators intact — encoding them
                                    // would yield `%2Fsubscriptions%2F...` and break
                                    // every Azure Resource Graph relationship URL.
                                    url = url.replace(&key.name, &substituted);
                                    done.push(key.name.clone());
                                } else if !done.contains(&key.name) {
                                    if let Some(c) = &key.conditions
                                        && !self
                                            .key_passes_conditions(
                                                condition_checker,
                                                token,
                                                c,
                                                data_value,
                                                request_id,
                                            )
                                            .await
                                    {
                                        // Skip relationship if data does not match condition
                                        return String::new();
                                    }
                                    debug!(
                                        "{:FL$}Trying to replace invalid key {:?} for relationship {:?} of API {:?} for service {:?} (id: {})",
                                        "RelationshipUrl",
                                        &key.name,
                                        &self.name,
                                        &self.api,
                                        &self.service,
                                        request_id
                                    );
                                }
                            }
                            None => {
                                if let Some(c) = &key.conditions {
                                    // Allow for placeholder keys if required to check a condition
                                    if !self
                                        .key_passes_conditions(
                                            condition_checker,
                                            token,
                                            c,
                                            data_value,
                                            request_id,
                                        )
                                        .await
                                    {
                                        // Skip relationship if data does not match condition
                                        trace!(
                                            "{:FL$}Condition {:?} is not met for placeholder key {:?} for relationship {:?} of API {:?} for service {:?} (id: {}) - {:?}",
                                            "RelationshipUrl",
                                            c,
                                            &key.name,
                                            &self.name,
                                            &self.api,
                                            &self.service,
                                            request_id,
                                            data_value
                                        );
                                        return String::new();
                                    }
                                } else {
                                    debug!(
                                        "{:FL$}Could not convert url key {:?} to str for relationship {:?} of API {:?} for service {:?} (id: {})",
                                        "RelationshipUrl",
                                        &key.name,
                                        &self.name,
                                        &self.api,
                                        &self.service,
                                        request_id
                                    );
                                    return String::new();
                                }
                            }
                        }
                    }
                    None => {
                        debug!(
                            "{:FL$}Trying to replace key {:?} for relationship {:?} of API {:?} for service {:?} while data does not contain it (id: {})",
                            "RelationshipUrl",
                            &key.name,
                            &self.name,
                            &self.api,
                            &self.service,
                            request_id
                        );
                        return String::new();
                    }
                }
            }
        }

        if let Some(parameters) = &self.parameters {
            for parameter in parameters {
                if url.contains(&parameter.name) {
                    match &parameter.conditions {
                        None => {}
                        Some(c) => {
                            let mut condition_failed = false;
                            for condition in c.iter() {
                                trace!(
                                    "{:FL$}Checking condition {:?} for url {:?} (API value) (id: {}).",
                                    "RelationshipUrl", condition, url, request_id
                                );
                                if !condition_checker
                                    .check(
                                        token,
                                        condition.clone(),
                                        Some((&self.service, &self.api)),
                                    )
                                    .await
                                {
                                    debug!(
                                        "{:FL$}Parameter {:?} for relationship {:?} of API {:?} for service {:?} does not meet condition {:?} (id: {})",
                                        "RelationshipUrl",
                                        &parameter.name,
                                        &self.name,
                                        &self.api,
                                        &self.service,
                                        condition,
                                        request_id
                                    );
                                    condition_failed = true;
                                    break;
                                }
                            }
                            if condition_failed {
                                continue;
                            }
                        }
                    }
                    match apply_transform(&parameter.value, parameter.transform.as_deref()) {
                        Some(transformed) => url = url.replace(&parameter.name, &transformed),
                        None => {
                            warn!(
                                "{:FL$}Invalid transform {:?} in schema file for parameter {:?} for relationship {:?} of API {:?} for service {:?} (id: {}). Skipping transformation.",
                                "RelationshipUrl",
                                parameter.transform,
                                &parameter.name,
                                &self.name,
                                &self.api,
                                &self.service,
                                request_id
                            );
                            url = url.replace(&parameter.name, &parameter.value);
                        }
                    };
                    done.push(parameter.name.clone());
                } else if !done.contains(&parameter.name) {
                    debug!(
                        "{:FL$}Trying to replace invalid api parameter {:?} for relationship {:?} of API {:?} for service {:?} (id: {})",
                        "RelationshipUrl",
                        &parameter.name,
                        &self.name,
                        &self.api,
                        &self.service,
                        request_id
                    );
                }
            }
        }

        if let Some(parameters) = &self.default_parameters {
            for parameter in parameters {
                if url.contains(&parameter.name) {
                    match &parameter.conditions {
                        None => {}
                        Some(c) => {
                            let mut condition_failed = false;
                            for condition in c.iter() {
                                trace!(
                                    "{:FL$}Checking condition {:?} for url {:?} (default value) (id: {}).",
                                    "RelationshipUrl", condition, url, request_id
                                );
                                if !condition_checker
                                    .check(
                                        token,
                                        condition.clone(),
                                        Some((&self.service, &self.api)),
                                    )
                                    .await
                                {
                                    debug!(
                                        "{:FL$}Default parameter {:?} for relationship {:?} of API {:?} for service {:?} does not meet condition {:?} (id: {})",
                                        "RelationshipUrl",
                                        &parameter.name,
                                        &self.name,
                                        &self.api,
                                        &self.service,
                                        condition,
                                        request_id
                                    );
                                    condition_failed = true;
                                    break;
                                }
                            }
                            if condition_failed {
                                continue;
                            }
                        }
                    }
                    match apply_transform(&parameter.value, parameter.transform.as_deref()) {
                        Some(transformed) => url = url.replace(&parameter.name, &transformed),
                        None => {
                            warn!(
                                "{:FL$}Invalid transform {:?} in schema file for default parameter {:?} for relationship {:?} of API {:?} for service {:?} (id: {}). Skipping transformation.",
                                "RelationshipUrl",
                                parameter.transform,
                                &parameter.name,
                                &self.name,
                                &self.api,
                                &self.service,
                                request_id
                            );
                            url = url.replace(&parameter.name, &parameter.value);
                        }
                    };
                    done.push(parameter.name.clone());
                } else if !done.contains(&parameter.name) {
                    debug!(
                        "{:FL$}Trying to replace invalid default parameter {:?} for relationship {:?} of API {:?} for service {:?} (id: {})",
                        "RelationshipUrl",
                        &parameter.name,
                        &self.name,
                        &self.api,
                        &self.service,
                        request_id
                    );
                }
            }
        }

        if url.contains("[TENANT]") {
            url = url.replace("[TENANT]", &token.tenant_id);
        }

        // Collapse accidental double slashes in the URL path only, preserving
        // the scheme and query string (see `collapse_path_double_slashes`).
        url = crate::utils::url::collapse_path_double_slashes(&url);

        url
    }
}
