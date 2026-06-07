use crate::FL;

use log::{debug, trace};
use serde_json::Value;

/// Compact identifier for trace logging — the value's `id`, else the value as a
/// short string, else a placeholder. Used instead of `{:?}`-dumping whole Graph
/// objects (PII + log bloat) on every per-entity condition check.
fn value_id(value: &Value) -> &str {
    value
        .get("id")
        .and_then(|v| v.as_str())
        .or_else(|| value.as_str())
        .unwrap_or("<unknown>")
}

/// Checks if the given JSON value represents a group eligible for Entra ID role
/// assignment (PIM for groups) by inspecting the `isAssignableToRole` boolean.
///
/// Returns `false` when the field is absent or non-boolean: PIM for groups returns
/// `400 ResourceTypeNotSupported` on these groups, so skipping the call avoids
/// the predictable error without losing data.
pub fn check_if_role_assignable(value: &Value) -> bool {
    trace!(
        "{:FL$}Checking id={}",
        "check_if_role_assignable",
        value_id(value)
    );
    match value.pointer("/isAssignableToRole") {
        Some(field) => field.as_bool().unwrap_or(false),
        None => false,
    }
}

/// Checks if the given JSON value represents a Unified group by inspecting the `groupTypes` field.
pub fn check_if_unified_group(value: &Value) -> bool {
    trace!(
        "{:FL$}Checking id={}",
        "check_if_unified_group",
        value_id(value)
    );
    if let Some(grouptypes_field) = value.pointer("/groupTypes") {
        match grouptypes_field.as_array() {
            None => {
                debug!(
                    "{:FL$}groupTypes field is not a valid array, considering as not Unified: {:?}",
                    "ConditionChecker", value
                );
                return false;
            }
            Some(gt) => {
                return gt
                    .iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<&str>>()
                    .contains(&"Unified");
            }
        }
    };
    false
}

/// Returns `true` if the ARM resource ID corresponds to a top-level resource
/// that is expected to support the PIM API at resource scope.
///
/// Child resources (those with a sub-type path after the main resource type,
/// i.e. more than 3 segments after `/providers/`) do not expose PIM at
/// resource scope. Defaults conservatively to `true` when the value is not a
/// string or the expected `/providers/` marker is absent, so the call proceeds
/// and any resulting 400 is handled by `expected_error_codes`.
pub fn check_resource_supports_pim(value: &Value) -> bool {
    let id = match value.as_str() {
        Some(s) => s,
        None => return true,
    };
    let after_providers = match id.find("/providers/") {
        Some(pos) => &id[pos + "/providers/".len()..],
        None => return true,
    };
    // Top-level resource: namespace/type/name = 3 segments.
    // Each child nesting adds 2 more: childType/childName.
    after_providers.split('/').count() <= 3
}

/// Determines if the provided folder name is one of the specific folders that require a permission dump.
pub fn check_if_folder_require_permission_dump(value: &Value) -> bool {
    trace!(
        "{:FL$}Checking id={}",
        "check_if_folder_require_permission_dump",
        value_id(value)
    );
    match value.as_str() {
        None => false,
        Some(ft) => [
            "Inbox",
            "Outbox",
            "SentItems",
            "User Created",
            "Archive",
            "Files",
            "Drafts",
            "DeletedItems",
        ]
        .contains(&ft),
    }
}

/// Checks if the user has at least one license assigned by inspecting the `assignedLicenses` field.
/// This is used to avoid 403 errors when fetching permission grants for unlicensed users.
pub fn check_has_license(value: &Value) -> bool {
    trace!("{:FL$}Checking id={}", "check_has_license", value_id(value));
    match value.pointer("/assignedLicenses") {
        Some(licenses) => {
            if let Some(list) = licenses.as_array() {
                !list.is_empty()
            } else {
                false
            }
        }
        None => false,
    }
}

pub fn check_if_federated(value: &Value) -> bool {
    trace!(
        "{:FL$}Checking id={}",
        "check_if_federated",
        value_id(value)
    );
    match value.pointer("/authenticationType") {
        Some(field) => field.as_str() == Some("Federated"),
        None => false,
    }
}

pub fn check_if_managed(value: &Value) -> bool {
    trace!("{:FL$}Checking id={}", "check_if_managed", value_id(value));
    match value.pointer("/authenticationType") {
        Some(field) => field.as_str() == Some("Managed"),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::value_id;
    use serde_json::json;

    #[test]
    fn value_id_prefers_id_then_string_then_placeholder() {
        // Object with an id → the id (compact, correlatable, no full-object dump).
        assert_eq!(
            value_id(&json!({"id": "u-123", "displayName": "Alice"})),
            "u-123"
        );
        // A bare string value (e.g. a mail-folder name) → the string itself.
        assert_eq!(value_id(&json!("Inbox")), "Inbox");
        // Object without an id, or a non-string scalar → placeholder.
        assert_eq!(value_id(&json!({"displayName": "no id here"})), "<unknown>");
        assert_eq!(value_id(&json!(42)), "<unknown>");
    }
}
