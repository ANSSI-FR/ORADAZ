use crate::FL;
use crate::collect::dump::response::thread::ResponseThread;
use crate::collect::dump::response::{DumpError, Response, TableMetadata};
use crate::utils::errors::Error;
use crate::utils::mutex::lock_fatal;
use crate::utils::url::{ApiCall, ExpectedErrorCode, RelationshipUrl, Url};

use log::{debug, info, trace, warn};
use serde_json::{Value, json};
use std::borrow::Cow;
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

/// Serialise each record as a single JSON line for the archive, tagging it with
/// its parent reference when the relationship carries one.
///
/// An object (or null) record receives the `_ORADAZ_PARENT_` field by direct
/// assignment — a null is promoted to an object holding just that field. A scalar
/// or array record (possible if an endpoint returns an array of primitives) is
/// instead wrapped in a `{"result": …}` object so the tag has somewhere to live:
/// string-indexing those JSON values would otherwise panic.
fn records_to_lines(value_field: &[Value], parent: Option<&HashMap<String, String>>) -> String {
    value_field
        .iter()
        .map(|x| match parent {
            Some(parent) => match x {
                Value::Object(_) | Value::Null => {
                    let mut data = x.clone();
                    data["_ORADAZ_PARENT_"] = json!(parent);
                    format!("{data}\n")
                }
                _ => format!("{}\n", json!({ "result": x, "_ORADAZ_PARENT_": parent })),
            },
            None => format!("{x}\n"),
        })
        .collect()
}

pub async fn handle_values(
    this: &ResponseThread,
    response: &Response,
    api_call: &ApiCall,
) -> Result<Vec<Value>, Error> {
    // Resolve the records to write. The common case — a JSON array at the value
    // pointer — is borrowed straight from the response: writing the page and
    // counting its rows need only a shared view. The rarer single-object,
    // scalar, or whole-body fallback shapes are wrapped into a one-element owned
    // vec (a present non-array value is one record — wrapping it avoids silently
    // dropping it, which `as_array()` would do).
    let records: Cow<[Value]> = match response.content.pointer(&api_call.value_pointer) {
        Some(Value::Array(r)) => Cow::Borrowed(r.as_slice()),
        // A present-but-`null` field carries no records.
        Some(Value::Null) => Cow::Owned(Vec::new()),
        Some(Value::Object(o)) => Cow::Owned(vec![Value::Object(o.clone())]),
        Some(other) => Cow::Owned(vec![json!({"result": other.clone()})]),
        // The pointer did not resolve: fall back to the whole response body.
        None => match &response.content {
            Value::Array(r) => Cow::Borrowed(r.as_slice()),
            Value::Object(o) => Cow::Owned(vec![Value::Object(o.clone())]),
            _ => Cow::Owned(vec![json!({"result": response.content.clone()})]),
        },
    };

    if records.is_empty() {
        // A 2xx response with no objects: the endpoint answered but the server
        // held nothing for it. Counted so per-API yield (objects written /
        // requests sent) distinguishes a legitimately empty endpoint from one
        // that errored.
        this.context
            .stats
            .record_empty_response(&api_call.url.service_name, &api_call.url.api);
        return Ok(Vec::new());
    }

    // Create a multiline string from vector of json data
    let parent_ref = api_call.url.parent.as_ref();
    let multiline_string: String = records_to_lines(&records, parent_ref);
    // Capture the uncompressed byte length before `multiline_string` is moved into
    // `write_file`; accumulated per table for data-volume analysis (writer-saturation
    // correlation and heavy-table identification → `$select` candidates).
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
        records.len(),
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
        entry.count += records.len();
        entry.bytes += written_bytes;
    }
    // Cumulative write-throughput gauges sampled by the periodic
    // `Memory sample:` line (trajectory companion to the per-table totals).
    crate::utils::sysmem::record_written(records.len() as u64, written_bytes as u64);

    // Relationship expansion consumes an owned record list; a leaf endpoint (no
    // relationships) never needs one, so it returns empty and skips cloning the
    // borrowed page out of the response.
    if api_call.url.relationships.is_empty() {
        Ok(Vec::new())
    } else {
        Ok(records.into_owned())
    }
}

/// Projects an expanded child to the requested fields (or keeps it whole when no
/// projection is configured) and tags it with its parent's key, matching the
/// `_ORADAZ_PARENT_` shape produced by the relationship writer.
///
/// The `@odata.type` discriminator is always preserved when present, even under a
/// field projection: a polymorphic collection (e.g. an object's `owners`, which
/// may be users or service principals) carries it to identify each element's
/// concrete type, and the server returns it automatically alongside an explicit
/// `$select` — so dropping it would lose the element type the per-object call kept.
fn project_child(
    child: &Value,
    project: Option<&[&str]>,
    parent_key: &str,
    parent_id: &str,
) -> Value {
    let mut obj = match project {
        Some(fields) => {
            let mut m = serde_json::Map::new();
            for f in fields {
                if let Some(v) = child.get(*f) {
                    m.insert((*f).to_string(), v.clone());
                }
            }
            if let Some(t) = child.get("@odata.type") {
                m.insert("@odata.type".to_string(), t.clone());
            }
            m
        }
        None => match child {
            Value::Object(o) => o.clone(),
            other => {
                let mut m = serde_json::Map::new();
                m.insert("result".to_string(), other.clone());
                m
            }
        },
    };
    obj.insert(
        "_ORADAZ_PARENT_".to_string(),
        json!({ parent_key: parent_id }),
    );
    Value::Object(obj)
}

/// Builds the per-object fallback URL for a parent whose `$expand`ed collection
/// hit the API cap. The seed URL is `<base>/<entity>?…&$expand=<extract>`; the
/// fallback re-fetches that one parent's collection paginably as
/// `<base>/<entity>/<parent id>/<extract>?$top=999[&$select=…]`. Its
/// `api_behavior` is empty so it flows through the standard value handler (it
/// returns a flat `value[]`, not parents-with-expand), writing to the same file.
fn build_expand_fallback(
    seed: &Url,
    parent_id: &str,
    parent_key: &str,
    extract: &str,
    project: Option<&[&str]>,
) -> Url {
    let base = seed.url.split('?').next().unwrap_or(seed.url.as_str());
    let select = project.map(|p| p.join(",")).unwrap_or_default();
    let url = if select.is_empty() {
        format!("{base}/{parent_id}/{extract}?$top=999")
    } else {
        format!("{base}/{parent_id}/{extract}?$top=999&$select={select}")
    };
    let mut parent = HashMap::new();
    parent.insert(parent_key.to_string(), parent_id.to_string());
    Url {
        service_name: seed.service_name.clone(),
        service_scopes: seed.service_scopes.clone(),
        service_mandatory_auth: seed.service_mandatory_auth,
        api: seed.api.clone(),
        url,
        conditions: None,
        relationships: Arc::new(vec![]),
        api_behavior: Arc::new(HashMap::new()),
        expected_error_codes: seed.expected_error_codes.clone(),
        parent: Some(parent),
        retry_number: 0,
        rate_limit_retry_number: 0,
        rate_limit_total_wait_secs: 0,
        network_retry_number: 0,
        post_body: None,
    }
}

/// Handles an `$expand` extraction seed: each top-level object carries an
/// expanded child collection (`api_behavior.expand_extract`) which is flattened
/// to this API's file — one projected child per line, tagged with its parent's
/// key. `$expand` on directory-object relationships silently caps the collection
/// (20 for directory objects; 100 only for `/users?$expand=registeredDevices`),
/// so a parent at the cap (`expand_max`) may be
/// truncated: instead of writing its partial rows, the child is re-fetched in
/// full through a per-object fallback URL (returned for dispatch), guaranteeing
/// no child is lost. Returns the fallback URLs to dispatch.
pub async fn handle_expand_extract(
    this: &ResponseThread,
    response: &Response,
    api_call: &ApiCall,
) -> Result<Vec<Url>, Error> {
    let behavior = &api_call.url.api_behavior;
    let extract = match behavior.get("expand_extract") {
        Some(e) if !e.is_empty() => e.as_str(),
        _ => return Ok(Vec::new()),
    };
    let parent_key = behavior
        .get("expand_parent_key")
        .map(|s| s.as_str())
        .unwrap_or("id");
    let project: Option<Vec<&str>> = behavior.get("expand_project").map(|s| {
        s.split(',')
            .map(|f| f.trim())
            .filter(|f| !f.is_empty())
            .collect()
    });
    let expand_max: usize = behavior
        .get("expand_max")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(usize::MAX);

    let parents = match response
        .content
        .pointer(&api_call.value_pointer)
        .and_then(|v| v.as_array())
    {
        Some(p) => p,
        None => return Ok(Vec::new()),
    };

    let service = &api_call.url.service_name;
    let api = &api_call.url.api;

    let mut multiline = String::new();
    let mut written = 0usize;
    let mut fallbacks: Vec<Url> = Vec::new();

    for parent in parents {
        let Some(parent_id) = parent.get(parent_key).and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(children) = parent.get(extract).and_then(|v| v.as_array()) else {
            continue;
        };
        if children.len() >= expand_max {
            this.context.stats.record_expand_cap_hit(service, api);
            fallbacks.push(build_expand_fallback(
                &api_call.url,
                parent_id,
                parent_key,
                extract,
                project.as_deref(),
            ));
            continue;
        }
        for child in children {
            let record = project_child(child, project.as_deref(), parent_key, parent_id);
            multiline.push_str(&format!("{record}\n"));
            written += 1;
        }
    }

    if written > 0 {
        let written_bytes = multiline.len();
        if let Err(err) = this
            .context
            .writer
            .write_file(service.clone(), format!("{api}.json"), multiline)
            .await
        {
            warn!(
                "{:FL$}Error writing $expand extraction to {:?} (id: {}) in folder {:?}, retrying the page",
                "ResponseThread", api, api_call.id, service
            );
            debug!(
                "{:FL$}File write error [ID: {}]: {:?}",
                "ResponseThread", api_call.id, err
            );
            return Err(Error::WriteFile);
        }
        {
            let mut metadata = lock_fatal(&this.context.metadata, Error::MetadataLock);
            let entry = metadata
                .entry(format!("{service}_{api}"))
                .or_insert(TableMetadata {
                    name: format!("{service}_{api}"),
                    folder: service.clone(),
                    file: format!("{api}.json"),
                    count: 0,
                    bytes: 0,
                });
            entry.count += written;
            entry.bytes += written_bytes;
        }
        crate::utils::sysmem::record_written(written as u64, written_bytes as u64);
    }

    if written > 0 || !fallbacks.is_empty() {
        // The page made progress (wrote children, or deferred full re-fetches),
        // so reset the bucket's liveness timer; the fallbacks write into the same
        // bucket and reset it again as they complete.
        this.context.stats.note_progress(service, api);
        if written > 0 {
            this.context
                .ratelimit_manager
                .note_bucket_progress(service, api);
        }
    } else {
        // No children on any parent this page: a genuine empty page (yield).
        this.context.stats.record_empty_response(service, api);
    }

    Ok(fallbacks)
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

    fn parent_map() -> HashMap<String, String> {
        HashMap::from([("id".to_string(), "parent-id".to_string())])
    }

    #[test]
    fn records_to_lines_tags_object_records_inline() {
        let parent = parent_map();
        let records = vec![json!({ "id": "a" })];
        let out = records_to_lines(&records, Some(&parent));
        let parsed: Value = serde_json::from_str(out.trim()).expect("one JSON line");
        assert_eq!(parsed["id"], json!("a"));
        assert_eq!(parsed["_ORADAZ_PARENT_"]["id"], json!("parent-id"));
    }

    #[test]
    fn records_to_lines_wraps_scalar_records_without_panicking() {
        // An array of primitives must not panic when a parent tag is injected:
        // each scalar is wrapped in `{"result": …, "_ORADAZ_PARENT_": …}`.
        let parent = parent_map();
        let records = vec![json!("scalar"), json!(7)];
        let out = records_to_lines(&records, Some(&parent));
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: Value = serde_json::from_str(lines[0]).expect("valid JSON line");
        assert_eq!(first["result"], json!("scalar"));
        assert_eq!(first["_ORADAZ_PARENT_"]["id"], json!("parent-id"));
        let second: Value = serde_json::from_str(lines[1]).expect("valid JSON line");
        assert_eq!(second["result"], json!(7));
    }

    #[test]
    fn records_to_lines_tags_null_record_inline() {
        // A null record is promoted to an object carrying only the parent tag,
        // matching serde_json's index-assignment on a null value.
        let parent = parent_map();
        let out = records_to_lines(&[Value::Null], Some(&parent));
        let parsed: Value = serde_json::from_str(out.trim()).expect("one JSON line");
        assert!(parsed.get("result").is_none());
        assert_eq!(parsed["_ORADAZ_PARENT_"]["id"], json!("parent-id"));
    }

    #[test]
    fn records_to_lines_without_parent_is_verbatim() {
        let records = vec![json!({ "id": "a" }), json!("scalar")];
        let out = records_to_lines(&records, None);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines, vec![r#"{"id":"a"}"#, r#""scalar""#]);
    }
}
