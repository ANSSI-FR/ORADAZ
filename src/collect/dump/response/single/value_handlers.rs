use crate::FL;
use crate::collect::dump::response::thread::ResponseThread;
use crate::collect::dump::response::{DumpError, Response, TableMetadata};
use crate::utils::errors::Error;
use crate::utils::mutex::lock_fatal;
use crate::utils::url::{ApiCall, ExpectedErrorCode, RelationshipUrl, Url};

use log::{debug, info, trace, warn};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;

/// Logs `@odata.count` from the response at `info` level for the first page of APIs
/// that explicitly requested it with `$count=true`. For Azure Resource Graph
/// (`post_body` set), logs the response's `totalRecords` on the first page
/// instead (no `$skipToken` injected yet).
///
/// Guard on `$count=true`: some Graph endpoints (e.g. Intune beta) include
/// `@odata.count` in every response by default, without being asked. Without this
/// guard, those APIs would also produce a count log entry, which is misleading.
pub fn log_count_if_present(response: &Response, api_call: &ApiCall) {
    // ARG: log `totalRecords` once, on the first page (body has no
    // `options.$skipToken` yet — see `build_arg_next_url`).
    if let Some(body) = api_call.url.post_body.as_ref()
        && body.pointer("/options/$skipToken").is_none()
    {
        if let Some(n) = response
            .content
            .get("totalRecords")
            .and_then(|v| v.as_u64())
        {
            info!(
                "{:FL$}{:?}/{:?} total: {} objects",
                "ResponseThread", api_call.url.service_name, api_call.url.api, n
            );
        }
        return;
    }
    if let Some(count_val) = response.content.pointer("/@odata.count")
        && let Some(n) = count_val.as_u64()
        && api_call.url.url.contains("$count=true")
        && !api_call.url.url.contains("$skiptoken")
    {
        info!(
            "{:FL$}{:?}/{:?} total: {} objects",
            "ResponseThread", api_call.url.service_name, api_call.url.api, n
        );
    }
}

/// Builds the next-page URL for an Azure Resource Graph request by injecting
/// the response's `$skipToken` into a copy of the original POST body. Returns
/// `None` when the response holds no `$skipToken` (last page).
pub fn build_arg_next_url(response: &Response, api_call: &ApiCall) -> Option<Url> {
    let skip_token = response
        .content
        .get("$skipToken")
        .and_then(|v| v.as_str())?;
    let mut new_body = api_call.url.post_body.clone()?;
    // Azure Resource Graph reads the continuation token from `options.$skipToken`
    // (the response returns it at the top level, read above). Writing it anywhere
    // else makes ARG ignore it and re-serve page 1 — an infinite pagination loop
    // on any tenant whose ARG query exceeds one page. `index_or_insert` (serde_json)
    // creates the `options` object when it is absent.
    new_body["options"]["$skipToken"] = Value::String(skip_token.to_string());
    debug!(
        "{:FL$}ARG next page for {:?}/{:?} [ID: {}] via $skipToken",
        "ResponseThread", api_call.url.service_name, api_call.url.api, api_call.id
    );
    Some(Url {
        service_name: api_call.url.service_name.clone(),
        service_scopes: api_call.url.service_scopes.clone(),
        service_mandatory_auth: api_call.url.service_mandatory_auth,
        api: api_call.url.api.clone(),
        url: api_call.url.url.clone(),
        conditions: api_call.url.conditions.clone(),
        relationships: api_call.url.relationships.clone(),
        api_behavior: api_call.url.api_behavior.clone(),
        expected_error_codes: api_call.url.expected_error_codes.clone(),
        parent: api_call.url.parent.clone(),
        retry_number: 0,
        rate_limit_retry_number: 0,
        rate_limit_total_wait_secs: 0,
        network_retry_number: 0,
        post_body: Some(new_body),
    })
}

pub async fn handle_next_link(
    this: &ResponseThread,
    response: &Response,
    api_call: &ApiCall,
) -> Option<Url> {
    // Azure Resource Graph paginates via the `$skipToken` field of the response
    // body, not via `@odata.nextLink`. Detect it by the presence of a POST body
    // on the URL and short-circuit to the dedicated builder.
    if api_call.url.post_body.is_some() {
        return build_arg_next_url(response, api_call);
    }
    let next_link_pointer: String = match api_call.url.api_behavior.get("next_link_field") {
        Some(field) => format!("/{field}"),
        None => String::from("/@odata.nextLink"),
    };
    if let Some(next_link_field) = response.content.pointer(&next_link_pointer) {
        if next_link_field.is_null() {
            // Azure ARM and several other APIs emit an explicit `nextLink: null` to
            // mark the last page. Treat it exactly like a missing field — no more
            // pages, no error.
            debug!(
                "{:FL$}nextLink is null for api {:?} (id: {}) of service {:?}, treating as no more pages",
                "ResponseThread", api_call.url.api, api_call.id, api_call.url.service_name
            );
            return None;
        }
        match next_link_field.as_str() {
            Some(f) => {
                debug!(
                    "{:FL$}Following nextLink for {:?}/{:?} [ID: {}]",
                    "ResponseThread", api_call.url.service_name, api_call.url.api, api_call.id
                );
                return Some(Url {
                    service_name: api_call.url.service_name.clone(),
                    service_scopes: api_call.url.service_scopes.clone(),
                    service_mandatory_auth: api_call.url.service_mandatory_auth,
                    api: api_call.url.api.clone(),
                    url: f.to_string(),
                    conditions: api_call.url.conditions.clone(),
                    relationships: api_call.url.relationships.clone(),
                    api_behavior: api_call.url.api_behavior.clone(),
                    expected_error_codes: api_call.url.expected_error_codes.clone(),
                    parent: api_call.url.parent.clone(),
                    retry_number: 0,
                    rate_limit_retry_number: 0,
                    rate_limit_total_wait_secs: 0,
                    network_retry_number: 0,
                    post_body: None,
                });
            }
            None => {
                debug!(
                    "{:FL$}Found unparseable nextLink (not a string) for api {:?} (id: {}) of service {:?}, skipping it",
                    "ResponseThread", api_call.url.api, api_call.id, api_call.url.service_name
                );
                let _ = this
                    .write_dump_error(DumpError {
                        folder: api_call.url.service_name.clone(),
                        file: api_call.url.api.clone(),
                        url: api_call.url.url.clone(),
                        status: 0,
                        code: String::from("nextLinkParsingError"),
                        message: format!(
                            "Found unparseable nextLink (not a string) for api {:?} of service {:?}, skipping it",
                            api_call.url.api, api_call.url.service_name
                        ),
                        expected: false,
                        full_response: None,
                        post_data: None,
                    })
                    .await;
            }
        }
    }
    None
}

pub async fn handle_values(
    this: &ResponseThread,
    response: &Response,
    api_call: &ApiCall,
) -> Result<Vec<Value>, Error> {
    let value_field: Vec<Value> = match response.content.pointer(&api_call.value_pointer) {
        // The pointer resolved to an array: use it as-is.
        Some(Value::Array(r)) => r.clone(),
        // A present-but-`null` field carries no records.
        Some(Value::Null) => Vec::new(),
        // A present non-array value (single object or scalar) is one record —
        // wrap it instead of silently dropping it (`as_array()` would have
        // yielded an empty vec, losing the data with no error).
        Some(Value::Object(o)) => vec![Value::Object(o.clone())],
        Some(other) => vec![json!({"result": other.clone()})],
        // The pointer did not resolve: fall back to the whole response body.
        None => match &response.content {
            Value::Array(r) => r.clone(),
            Value::Object(o) => vec![Value::Object(o.clone())],
            _ => vec![json!({"result": response.content.clone()})],
        },
    };

    if value_field.is_empty() {
        return Ok(Vec::new());
    }

    // Create a multiline string from vector of json data
    let parent_ref = api_call.url.parent.as_ref();
    let multiline_string: String = value_field
        .iter()
        .map(|x| match parent_ref {
            Some(parent) => {
                let mut data = x.clone();
                data["_ORADAZ_PARENT_"] = json!(parent);
                format!("{data}\n")
            }
            None => format!("{x}\n"),
        })
        .collect();
    // Capture the uncompressed byte length before `multiline_string` is moved into
    // `write_file`; accumulated per table for data-volume analysis (writer-saturation
    // correlation §3.8 and heavy-table identification → `$select` candidates).
    let written_bytes = multiline_string.len();

    // Write the string to the correct file
    if let Err(err) = this
        .context
        .writer
        .write_file(
            api_call.url.service_name.clone(),
            format!("{}.json", api_call.url.api.clone()),
            multiline_string,
        )
        .await
    {
        warn!(
            "{:FL$}Error writing response to file {:?} (id: {}) in folder {:?}, trying to process the URL again",
            "ResponseThread", api_call.url.api, api_call.id, api_call.url.service_name
        );
        debug!(
            "{:FL$}File write error [ID: {}]: {:?}",
            "ResponseThread", api_call.id, err
        );
        return Err(Error::WriteFile);
    }

    trace!(
        "{:FL$}{} object(s) written to {:?}/{:?} [ID: {}]",
        "ResponseThread",
        value_field.len(),
        api_call.url.service_name,
        api_call.url.api,
        api_call.id
    );

    // Update Metadata
    {
        let mut metadata = lock_fatal(&this.context.metadata, Error::MetadataLock);
        let entry = metadata
            .entry(format!(
                "{}_{}",
                api_call.url.service_name, api_call.url.api
            ))
            .or_insert(TableMetadata {
                name: format!("{}_{}", api_call.url.service_name, api_call.url.api),
                folder: api_call.url.service_name.clone(),
                file: format!("{}.json", api_call.url.api),
                count: 0,
                bytes: 0,
            });
        entry.count += value_field.len();
        entry.bytes += written_bytes;
    }

    Ok(value_field)
}

pub async fn handle_relationships(
    this: &ResponseThread,
    api_call: &ApiCall,
    value_field: Vec<Value>,
) -> Vec<Url> {
    if value_field.is_empty() {
        return Vec::new();
    }

    if api_call.url.relationships.is_empty() {
        return Vec::new();
    }

    let mut new_urls: Vec<Url> = Vec::new();
    let token = this
        .context
        .tokens
        .get(api_call.url.service_name.as_str())
        .map(|t| Arc::clone(t.value()));
    match token {
        Some(t) => {
            let token_val = t.token.read().await.clone();

            // Precompute, once per relationship, the child-`Url` fields that depend
            // only on the relationship (not on the per-object `data`): the API name,
            // conditions, and the Arc-shared `api_behavior` / `relationships`
            // sub-template / `expected_error_codes`. Hoisted out of the `for data`
            // loop so they are built once and Arc-shared across every child of
            // the same relationship instead of deep-cloned per object. Indexed
            // by relationship position so the per-object loop below keeps its
            // original data-major `new_urls` ordering via `.enumerate()`.
            struct ChildTemplate {
                api: String,
                conditions: Option<Vec<String>>,
                api_behavior: Arc<HashMap<String, String>>,
                relationships: Arc<Vec<RelationshipUrl>>,
                expected_error_codes: Option<Arc<Vec<ExpectedErrorCode>>>,
            }
            let templates: Vec<ChildTemplate> = api_call
                .url
                .relationships
                .iter()
                .map(|relationship_url| {
                    let api = format!("{}_{}", &relationship_url.api, &relationship_url.name);
                    let mut api_behavior: HashMap<String, String> =
                        relationship_url.default_api_behavior.clone();
                    if let Some(a) = &relationship_url.api_behavior {
                        for (k, v) in a {
                            api_behavior.insert(k.clone(), v.clone());
                        }
                    }
                    let mut relationships: Vec<RelationshipUrl> = Vec::new();
                    if let Some(r) = &relationship_url.relationships {
                        for relationship in r {
                            relationships.push(RelationshipUrl {
                                service: api_call.url.service_name.clone(),
                                url_scheme: relationship_url.url_scheme.clone(),
                                default_api_behavior: relationship_url.default_api_behavior.clone(),
                                default_parameters: relationship_url.default_parameters.clone(),
                                api: api.clone(),
                                name: relationship.name.clone(),
                                uri: relationship.uri.clone(),
                                conditions: relationship.conditions.clone(),
                                api_behavior: relationship.api_behavior.clone(),
                                expected_error_codes: relationship.expected_error_codes.clone(),
                                keys: relationship.keys.clone(),
                                parameters: relationship.parameters.clone(),
                                relationships: relationship.relationships.clone(),
                            });
                        }
                    }
                    ChildTemplate {
                        api,
                        conditions: relationship_url.conditions.clone(),
                        api_behavior: Arc::new(api_behavior),
                        relationships: Arc::new(relationships),
                        expected_error_codes: relationship_url
                            .expected_error_codes
                            .clone()
                            .map(Arc::new),
                    }
                })
                .collect();

            for data in value_field {
                for (i, relationship_url) in api_call.url.relationships.iter().enumerate() {
                    // Check if RelationshipUrl match condition
                    let url = relationship_url
                        .get_url(
                            &token_val,
                            &data,
                            api_call.url.url.clone(),
                            &this.context.condition_checker,
                            api_call.id,
                        )
                        .await;
                    // Substitute the audit-log date bound (`[SIGNIN_FILTER]`)
                    // carried by the per-user `signIns` relationship URI. Done here
                    // rather than inside `get_url` because the cutoff is a run-time
                    // value threaded through the response context, not part of the
                    // schema. Collapses to an empty string when date bounding is off.
                    let url = if url.contains("[SIGNIN_FILTER]") {
                        url.replace(
                            "[SIGNIN_FILTER]",
                            this.context.logs_date_filter_and.as_deref().unwrap_or(""),
                        )
                    } else {
                        url
                    };

                    if !url.is_empty() {
                        // All relationship-invariant fields come from the precomputed
                        // template (Arc-shared); only `url` and `parent` are derived
                        // from the per-object `data`.
                        let template = &templates[i];
                        let parent: HashMap<String, String> =
                            relationship_url.get_parent(&data, api_call.id);
                        let new_url: Url = Url {
                            service_name: api_call.url.service_name.clone(),
                            service_scopes: Arc::clone(&api_call.url.service_scopes),
                            service_mandatory_auth: api_call.url.service_mandatory_auth,
                            api: template.api.clone(),
                            url,
                            conditions: template.conditions.clone(),
                            relationships: Arc::clone(&template.relationships),
                            api_behavior: Arc::clone(&template.api_behavior),
                            expected_error_codes: template.expected_error_codes.clone(),
                            parent: Some(parent),
                            retry_number: 0,
                            rate_limit_retry_number: 0,
                            rate_limit_total_wait_secs: 0,
                            network_retry_number: 0,
                            post_body: None,
                        };
                        new_urls.push(new_url);
                    }
                }
            }
        }
        None => {
            warn!(
                "{:FL$}Missing token to get relationships URLs for service {:?} [ID: {}], skipping",
                "ResponseThread", api_call.url.service_name, api_call.id
            );
            let _ = this
                .write_dump_error(DumpError {
                    folder: api_call.url.service_name.clone(),
                    file: String::new(),
                    url: String::new(),
                    status: 0,
                    code: String::from("MissingTokenForRelationships"),
                    message: format!(
                        "Missing token to get relationships URLs for service {:?}, skipping them",
                        api_call.url.service_name
                    ),
                    expected: false,
                    full_response: None,
                    post_data: None,
                })
                .await;
        }
    }

    // Request-shape telemetry: relationship fan-out for this endpoint. Feeds
    // per-API `child_urls_generated` (no-op when nothing was generated).
    this.context.stats.record_child_urls_generated(
        &api_call.url.service_name,
        &api_call.url.api,
        new_urls.len(),
    );
    debug!(
        "{:FL$}{} child URL(s) generated from {:?}/{:?} [ID: {}]",
        "ResponseThread",
        new_urls.len(),
        api_call.url.service_name,
        api_call.url.api,
        api_call.id
    );
    new_urls
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_response(content: serde_json::Value) -> Response {
        Response {
            status: 200,
            retry_after: None,
            content,
        }
    }

    fn make_api_call(url: &str) -> ApiCall {
        ApiCall {
            id: 0,
            url: Url {
                service_name: "graph".to_string(),
                service_scopes: Arc::new(vec![]),
                service_mandatory_auth: true,
                api: "users".to_string(),
                url: url.to_string(),
                conditions: None,
                relationships: Arc::new(vec![]),
                api_behavior: Arc::new(HashMap::new()),
                expected_error_codes: None,
                parent: None,
                retry_number: 0,
                rate_limit_retry_number: 0,
                rate_limit_total_wait_secs: 0,
                network_retry_number: 0,
                post_body: None,
            },
            success_code: 200,
            value_pointer: "/value".to_string(),
            is_batch: false,
            batch_data: None,
        }
    }

    #[test]
    fn test_log_count_all_conditions_met() {
        // All four guards pass → info log produced (no panic).
        let response = make_response(json!({ "@odata.count": 42, "value": [] }));
        let api_call = make_api_call("https://graph.microsoft.com/v1.0/users?$count=true");
        log_count_if_present(&response, &api_call);
    }

    #[test]
    fn test_log_count_absent_from_response() {
        // @odata.count not present → first guard fails, no log.
        let response = make_response(json!({ "value": [] }));
        let api_call = make_api_call("https://graph.microsoft.com/v1.0/users?$count=true");
        log_count_if_present(&response, &api_call);
    }

    #[test]
    fn test_log_count_url_missing_count_param() {
        // API returns @odata.count spontaneously without being asked → third guard fails, no log.
        let response = make_response(json!({ "@odata.count": 100, "value": [] }));
        let api_call = make_api_call("https://graph.microsoft.com/v1.0/users");
        log_count_if_present(&response, &api_call);
    }

    #[test]
    fn test_log_count_skiptoken_page() {
        // Subsequent pagination page → fourth guard fails, no duplicate count log.
        let response = make_response(json!({ "@odata.count": 42, "value": [] }));
        let api_call =
            make_api_call("https://graph.microsoft.com/v1.0/users?$count=true&$skiptoken=abc123");
        log_count_if_present(&response, &api_call);
    }

    #[test]
    fn test_log_count_value_not_numeric() {
        // @odata.count present but not a valid u64 → second guard fails, no log.
        let response = make_response(json!({ "@odata.count": "not-a-number", "value": [] }));
        let api_call = make_api_call("https://graph.microsoft.com/v1.0/users?$count=true");
        log_count_if_present(&response, &api_call);
    }
}
