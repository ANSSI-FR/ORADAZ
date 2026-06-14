use crate::FL;
use crate::utils::errors::Error;
use crate::utils::url::types::{
    ApiCall, ApiCallItem, BatchData, GraphPostData, PostBatchData, ResourcesPostData, RetryLimits,
    Url,
};

use log::{debug, error, warn};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

/// Returns `ConsistencyLevel: eventual` headers when `$count=true` is present in the URL,
/// and `None` otherwise. Graph requires this header for accurate `@odata.count` results.
fn consistency_level_headers(url: &str) -> Option<HashMap<String, String>> {
    if url.contains("$count=true") {
        let mut headers = HashMap::new();
        headers.insert("ConsistencyLevel".to_string(), "eventual".to_string());
        Some(headers)
    } else {
        None
    }
}

/// Maximum number of sub-requests per Exchange admin-API `$batch` POST.
const EXCHANGE_BATCH_SIZE: usize = 10;

/// Derives the Exchange admin-API batch root — `https://<host>/adminapi/<version>/<tenant>`,
/// without trailing slash — from an absolute URL, or `None` when the URL does not
/// follow that layout (the caller then dispatches the URL as a single request).
fn exchange_batch_root(url: &str) -> Option<String> {
    let marker = "/adminapi/";
    let marker_pos = url.find(marker)?;
    // A `?` or `#` before the marker means "/adminapi/" was matched inside a
    // query string or fragment, not in the path.
    if url.get(..marker_pos)?.contains(['?', '#']) {
        return None;
    }
    let start = marker_pos + marker.len();
    let rest = url.get(start..)?;
    // Skip the version segment then the tenant segment; both must be non-empty
    // and free of `?`/`#` (a query string or fragment before the
    // tenant-terminating `/` means the URL does not follow the
    // `<version>/<tenant>/<uri>` layout).
    let version_end = rest.find('/')?;
    let version = rest.get(..version_end)?;
    if version.is_empty() || version.contains(['?', '#']) {
        return None;
    }
    let after_version = rest.get(version_end + 1..)?;
    let tenant_end = after_version.find('/')?;
    let tenant = after_version.get(..tenant_end)?;
    if tenant.is_empty() || tenant.contains(['?', '#']) {
        return None;
    }
    url.get(..start + version_end + 1 + tenant_end)
        .map(str::to_string)
}

/// Checks whether a URL has exhausted any of its retry budgets and, if so,
/// emits the "Skipping" log and returns the corresponding `ApiCallError`.
///
/// Returns `Some(item)` when the URL must be dropped (caller should append it
/// to the result and continue), `None` when the URL still has budget left.
fn check_retry_exhaustion(url: &Url, limits: &RetryLimits) -> Option<ApiCallItem> {
    // Only the *permanent* budget (real 4xx-prereq / 5xx errors, counted in
    // `retry_number`) abandons a URL at dispatch. Transient causes — 429
    // throttling and transport failures — are not killed on a fixed count here;
    // their sole bound is the per-bucket liveness ceiling (`Stats`),
    // applied at the re-queue sites (`prepare_rate_limit_retries` for throttle,
    // `finalize_retry` for network). The `rate_limit_*` fields of `limits` are
    // therefore intentionally unused here.
    if url.retry_number < limits.retry {
        return None;
    }
    // Logged at debug, not warn: the canonical (de-duplicated) give-up warning is
    // emitted once in `dispatch.rs` when the resulting `UrlRetryLimit` becomes a
    // DumpError. This detection can fire repeatedly for a single URL under
    // send-permit backpressure, so keep its more granular cause here in the file log.
    debug!(
        "{:FL$}Skipping api {:?} for service {:?} (URL {}) because it has exhausted its retry limit ({} attempts)",
        "ApiCall", url.api, url.service_name, url.url, limits.retry
    );
    Some(ApiCallItem::ApiCallError(Error::UrlRetryLimit(Box::new(
        url.clone(),
    ))))
}

/// Resolves the per-URL success HTTP code (`api_behavior.success_http_code`,
/// default 200) and JSON value pointer (`/<api_behavior.value_field>`, default
/// `/value`) from the schema. Centralised so the four `ApiCall::from` builders
/// (default / graph / resources / exchange) stay in sync.
fn success_code_and_value_pointer(url: &Url) -> (u16, String) {
    let success_http_code: u16 = match url.api_behavior.get("success_http_code") {
        Some(field) => field.parse().unwrap_or_else(|err| {
            // A malformed value is surfaced once, up front, at schema-load time
            // (`schema::validate_success_http_codes`). Keep this at debug so the
            // same schema defect is not re-warned for every URL of the affected
            // API during collection; the run continues with the 200 fallback.
            debug!(
                "{:FL$}Falling back to success_http_code 200 for unparseable value {:?}: {:?}",
                "ApiCall", field, err
            );
            200
        }),
        None => 200,
    };
    let value_pointer: String = match url.api_behavior.get("value_field") {
        Some(field) => format!("/{field}"),
        None => String::from("/value"),
    };
    (success_http_code, value_pointer)
}

impl ApiCall {
    /// Dispatches the creation of the next API call to the appropriate service handler.
    ///
    /// Depending on the service name ("graph", "resources", "exchange", or others), it uses
    /// a specific logic to determine if the request can be batched or must be sent
    /// individually.
    pub fn from(
        service: &str,
        urls: &mut Vec<Url>,
        limits: RetryLimits,
    ) -> Result<Vec<ApiCallItem>, Error> {
        let api_call = match service {
            "graph" => ApiCall::get_graph_next_api_call(urls, limits)?,
            "resources" => {
                // Azure Resource Graph URLs use a POST endpoint and must not be
                // wrapped in an ARM `$batch` request. Detect them via the
                // `is_arg` schema flag (not via `post_body.is_some()`, so the
                // routing is correct even when subscription IDs have not been
                // injected yet — e.g. `noCheck=true`).
                let next_is_arg = urls
                    .last()
                    .map(|u| {
                        u.api_behavior
                            .get("is_arg")
                            .map(|v| v == "true")
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);
                if next_is_arg {
                    ApiCall::get_default_next_api_call("resources".to_string(), urls, limits)?
                } else {
                    ApiCall::get_resources_next_api_call(urls, limits)?
                }
            }
            "exchange" => {
                // Exchange URLs are batched only when their absolute URL follows
                // the admin-API `…/adminapi/<version>/<tenant>/…` layout and
                // carries no POST body. Pre-check the *next* URL (the one the
                // builder pops first) so the builder's first pop is always
                // batchable — the other half of the push-back guard in
                // `get_exchange_next_api_call` (same two-sided pattern as the
                // resources `is_arg` routing above).
                let next_not_batchable = urls
                    .last()
                    .map(|u| u.post_body.is_some() || exchange_batch_root(&u.url).is_none())
                    .unwrap_or(false);
                if next_not_batchable {
                    ApiCall::get_default_next_api_call("exchange".to_string(), urls, limits)?
                } else {
                    ApiCall::get_exchange_next_api_call(urls, limits)?
                }
            }
            _ => ApiCall::get_default_next_api_call(service.to_string(), urls, limits)?,
        };
        Ok(api_call)
    }

    /// Creates a standard single API call for services that do not support batching.
    ///
    /// It pops the last URL from the provided vector and constructs an `ApiCall` item.
    /// If the URL has reached the retry limit, it returns a `UrlRetryLimit` error.
    pub fn get_default_next_api_call(
        service: String,
        urls: &mut Vec<Url>,
        limits: RetryLimits,
    ) -> Result<Vec<ApiCallItem>, Error> {
        // `pop()` consumes from the *back* (LIFO). This is load-bearing for the
        // depth-first dispatch order (see `handle_success` in
        // `response/status_handlers.rs`): the dispatcher clones the queue tail and
        // truncates by the unconsumed remainder, so consuming from the front would
        // both reorder dispatch (breadth-first → OOM risk) and corrupt the queue.
        match urls.pop() {
            Some(url) => {
                if let Some(skip_item) = check_retry_exhaustion(&url, &limits) {
                    return Ok(Vec::from([skip_item]));
                }
                // Success code + value pointer from the schema (default 200 / /value).
                let (success_http_code, value_pointer) = success_code_and_value_pointer(&url);

                Ok(Vec::from([ApiCallItem::ApiCall(Box::new(ApiCall {
                    id: 0,
                    url: url.clone(),
                    success_code: success_http_code,
                    value_pointer,
                    is_batch: false,
                    batch_data: None,
                }))]))
            }
            None => {
                error!(
                    "{:FL$}Received empty URL vector while trying to construct next ApiCall for service {:?}",
                    "ApiCall", service
                );
                Err(Error::EmptyUrlsVector)
            }
        }
    }

    /// Creates a batched API call for the Microsoft Graph REST API.
    ///
    /// It aggregates up to 20 URLs into a single `$batch` request, separating them
    /// by API version (v1.0 vs beta).
    pub fn get_graph_next_api_call(
        urls: &mut Vec<Url>,
        limits: RetryLimits,
    ) -> Result<Vec<ApiCallItem>, Error> {
        let mut res: Vec<ApiCallItem> = Vec::new();
        // Get batch size
        let batch_size = match [urls.len(), 20].iter().min() {
            Some(m) if *m != 0 => *m,
            _ => {
                error!(
                    "{:FL$}Received empty URL vector while trying to construct next ApiCall for service graph",
                    "ApiCall"
                );
                return Err(Error::EmptyUrlsVector);
            }
        };
        // Construct batch data
        let mut v1_batch_data: BatchData = BatchData {
            post_data: HashMap::new(),
            initial_data: HashMap::new(),
            id_field: "id".to_string(),
            body_field: "body".to_string(),
            status_field: "status".to_string(),
            retry_after_field: "headers/Retry-After".to_string(),
        };
        let mut v1_count: usize = 1;
        let mut beta_batch_data: BatchData = BatchData {
            post_data: HashMap::new(),
            initial_data: HashMap::new(),
            id_field: "id".to_string(),
            body_field: "body".to_string(),
            status_field: "status".to_string(),
            retry_after_field: "headers/Retry-After".to_string(),
        };
        let mut beta_count: usize = 1;
        for _ in 0..batch_size {
            match urls.pop() {
                Some(url) => {
                    if let Some(skip_item) = check_retry_exhaustion(&url, &limits) {
                        res.push(skip_item);
                        continue;
                    }
                    // Success code + value pointer from the schema (default 200 / /value).
                    let (success_http_code, value_pointer) = success_code_and_value_pointer(&url);
                    if url.url.contains("https://graph.microsoft.com/v1.0") {
                        let headers = consistency_level_headers(&url.url);
                        v1_batch_data.initial_data.insert(
                            v1_count.to_string(),
                            ApiCall {
                                id: 0,
                                url: url.clone(),
                                success_code: success_http_code,
                                value_pointer,
                                is_batch: false,
                                batch_data: None,
                            },
                        );
                        v1_batch_data
                            .post_data
                            .entry(String::from("requests"))
                            .and_modify(|v| {
                                v.push(PostBatchData::GraphPostData(GraphPostData {
                                    id: v1_count.to_string(),
                                    method: "GET".to_string(),
                                    url: url
                                        .url
                                        .clone()
                                        .replace("https://graph.microsoft.com/v1.0", ""),
                                    headers: headers.clone(),
                                }))
                            })
                            .or_insert(Vec::from([PostBatchData::GraphPostData(GraphPostData {
                                id: v1_count.to_string(),
                                method: "GET".to_string(),
                                url: url
                                    .url
                                    .clone()
                                    .replace("https://graph.microsoft.com/v1.0", ""),
                                headers,
                            })]));
                        v1_count += 1;
                    } else if url.url.contains("https://graph.microsoft.com/beta") {
                        let headers = consistency_level_headers(&url.url);
                        beta_batch_data.initial_data.insert(
                            beta_count.to_string(),
                            ApiCall {
                                id: 0,
                                url: url.clone(),
                                success_code: success_http_code,
                                value_pointer,
                                is_batch: false,
                                batch_data: None,
                            },
                        );
                        beta_batch_data
                            .post_data
                            .entry(String::from("requests"))
                            .and_modify(|v| {
                                v.push(PostBatchData::GraphPostData(GraphPostData {
                                    id: beta_count.to_string(),
                                    method: "GET".to_string(),
                                    url: url
                                        .url
                                        .clone()
                                        .replace("https://graph.microsoft.com/beta", ""),
                                    headers: headers.clone(),
                                }))
                            })
                            .or_insert(Vec::from([PostBatchData::GraphPostData(GraphPostData {
                                id: beta_count.to_string(),
                                method: "GET".to_string(),
                                url: url
                                    .url
                                    .clone()
                                    .replace("https://graph.microsoft.com/beta", ""),
                                headers,
                            })]));
                        beta_count += 1;
                    } else {
                        warn!(
                            "{:FL$}URL for Microsoft Graph batch is neither v1.0 nor beta — skipping URL: {:?}",
                            "ApiCall", url.url
                        );
                        // Report as a per-URL error instead of aborting the entire
                        // collection. The URL was already popped from `urls`; adding an
                        // ApiCallError lets dispatch route it to a DumpError and continue.
                        // Embed the URL in the error so it surfaces in the DumpError message
                        // (the URL object is consumed here and won't reach dispatch.rs).
                        res.push(ApiCallItem::ApiCallError(Error::StringError(format!(
                            "URL {:?} is not a valid Graph batch endpoint (expected v1.0 or beta)",
                            url.url
                        ))));
                        continue;
                    }
                }
                None => {
                    // Unreachable in single-threaded dispatch: `batch_size` is
                    // `min(urls.len(), 20)`, so the loop pops at most as many URLs
                    // as the vector held on entry. Reaching here means that
                    // invariant was violated.
                    error!(
                        "{:FL$}Internal invariant violated: URL vector exhausted before reaching batch_size while constructing next ApiCall for service graph",
                        "ApiCall"
                    );
                    return Err(Error::EmptyUrlsVector);
                }
            };
        }
        if !v1_batch_data.post_data.is_empty() {
            res.push(ApiCallItem::ApiCall(Box::new(ApiCall {
                id: 0,
                url: Url {
                    service_name: String::from("graph"),
                    service_scopes: Arc::new(Vec::new()),
                    service_mandatory_auth: true,
                    api: String::from("batch"),
                    url: String::from("https://graph.microsoft.com/v1.0/$batch"),
                    conditions: None,
                    relationships: Arc::new(Vec::new()),
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
                value_pointer: "/responses".to_string(),
                is_batch: true,
                batch_data: Some(v1_batch_data),
            })))
        }
        if !beta_batch_data.post_data.is_empty() {
            res.push(ApiCallItem::ApiCall(Box::new(ApiCall {
                id: 0,
                url: Url {
                    service_name: String::from("graph"),
                    service_scopes: Arc::new(Vec::new()),
                    service_mandatory_auth: true,
                    api: String::from("batch"),
                    url: String::from("https://graph.microsoft.com/beta/$batch"),
                    conditions: None,
                    relationships: Arc::new(Vec::new()),
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
                value_pointer: "/responses".to_string(),
                is_batch: true,
                batch_data: Some(beta_batch_data),
            })))
        }
        Ok(res)
    }

    /// Creates a batched API call for the Azure Resources REST API.
    ///
    /// It aggregates up to 20 URLs into a single `/batch` request, using unique GUIDs
    /// to identify each sub-request within the batch.
    pub fn get_resources_next_api_call(
        urls: &mut Vec<Url>,
        limits: RetryLimits,
    ) -> Result<Vec<ApiCallItem>, Error> {
        let mut res: Vec<ApiCallItem> = Vec::new();
        // Get batch size
        let batch_size = match [urls.len(), 20].iter().min() {
            Some(m) if *m != 0 => *m,
            _ => {
                error!(
                    "{:FL$}Received empty URL vector while trying to construct next ApiCall for service resources",
                    "ApiCall"
                );
                return Err(Error::EmptyUrlsVector);
            }
        };
        // Construct batch data
        let mut batch_data: BatchData = BatchData {
            post_data: HashMap::new(),
            initial_data: HashMap::new(),
            id_field: "name".to_string(),
            body_field: "content".to_string(),
            status_field: "httpStatusCode".to_string(),
            retry_after_field: "headers/Retry-After".to_string(),
        };
        for _ in 0..batch_size {
            match urls.pop() {
                Some(url) => {
                    // ARG URLs must not enter the ARM `$batch`: push the URL
                    // back and break so the next dispatch iteration routes it
                    // via `get_default_next_api_call`. Use the `is_arg` flag
                    // rather than `post_body.is_some()`, so this guard also
                    // catches ARG URLs whose body has not been injected yet
                    // (e.g. `noCheck=true`).
                    if url
                        .api_behavior
                        .get("is_arg")
                        .map(|v| v == "true")
                        .unwrap_or(false)
                    {
                        urls.push(url);
                        break;
                    }
                    if let Some(skip_item) = check_retry_exhaustion(&url, &limits) {
                        res.push(skip_item);
                        continue;
                    }
                    // Create the guid that identifies the request
                    let guid: String = Uuid::new_v4().to_string();
                    // Success code + value pointer from the schema (default 200 / /value).
                    let (success_http_code, value_pointer) = success_code_and_value_pointer(&url);
                    batch_data.initial_data.insert(
                        guid.clone(),
                        ApiCall {
                            id: 0,
                            url: url.clone(),
                            success_code: success_http_code,
                            value_pointer,
                            is_batch: false,
                            batch_data: None,
                        },
                    );
                    batch_data
                        .post_data
                        .entry(String::from("requests"))
                        .and_modify(|v| {
                            v.push(PostBatchData::ResourcesPostData(ResourcesPostData {
                                name: guid.clone(),
                                http_method: "GET".to_string(),
                                url: url.url.clone(),
                            }))
                        })
                        .or_insert(Vec::from([PostBatchData::ResourcesPostData(
                            ResourcesPostData {
                                name: guid.clone(),
                                http_method: "GET".to_string(),
                                url: url.url.clone(),
                            },
                        )]));
                }
                None => {
                    // Unreachable in single-threaded dispatch: `batch_size` is
                    // `min(urls.len(), 20)`, so the loop pops at most as many URLs
                    // as the vector held on entry (the `is_arg` push-back breaks
                    // without consuming one). Reaching here means that invariant
                    // was violated.
                    error!(
                        "{:FL$}Internal invariant violated: URL vector exhausted before reaching batch_size while constructing next ApiCall for service resources",
                        "ApiCall"
                    );
                    return Err(Error::EmptyUrlsVector);
                }
            };
        }
        if batch_data.post_data.is_empty() {
            // No batchable requests left in this pass, but `res` may still hold
            // `UrlRetryLimit` errors emitted by `check_retry_exhaustion` above.
            // Returning `Vec::new()` here would silently drop them; return `res`
            // so each exhausted URL gets recorded as a DumpError downstream.
            return Ok(res);
        }
        res.push(ApiCallItem::ApiCall(Box::new(ApiCall {
            id: 0,
            url: Url {
                service_name: String::from("resources"),
                service_scopes: Arc::new(Vec::new()),
                service_mandatory_auth: true,
                api: String::from("batch"),
                url: String::from("https://management.azure.com/batch?api-version=2020-06-01"),
                conditions: None,
                relationships: Arc::new(Vec::new()),
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
            value_pointer: "/responses".to_string(),
            is_batch: true,
            batch_data: Some(batch_data),
        })));
        Ok(res)
    }

    /// Creates a batched API call for the Exchange Online admin API.
    ///
    /// It aggregates up to 10 URLs sharing one
    /// `https://<host>/adminapi/<version>/<tenant>` root into a single OData
    /// JSON `$batch` POST (`{root}/$batch`). Sub-request URLs are sent in
    /// absolute form (like the ARM batch); ids are 1-based counter strings and
    /// the response is parsed with the Graph field names (`id` / `status` /
    /// `body` / `headers/Retry-After` — the OData JSON batch shape).
    pub fn get_exchange_next_api_call(
        urls: &mut Vec<Url>,
        limits: RetryLimits,
    ) -> Result<Vec<ApiCallItem>, Error> {
        let mut res: Vec<ApiCallItem> = Vec::new();
        // Get batch size
        let batch_size = match [urls.len(), EXCHANGE_BATCH_SIZE].iter().min() {
            Some(m) if *m != 0 => *m,
            _ => {
                error!(
                    "{:FL$}Received empty URL vector while trying to construct next ApiCall for service exchange",
                    "ApiCall"
                );
                return Err(Error::EmptyUrlsVector);
            }
        };
        // Construct batch data
        let mut batch_data: BatchData = BatchData {
            post_data: HashMap::new(),
            initial_data: HashMap::new(),
            id_field: "id".to_string(),
            body_field: "body".to_string(),
            status_field: "status".to_string(),
            retry_after_field: "headers/Retry-After".to_string(),
        };
        // Root shared by every URL of this batch, fixed by the first batched
        // URL, together with its `service_mandatory_auth` — carried onto the
        // envelope (exchange is not mandatory_auth, unlike graph/resources).
        let mut batch_root: Option<(String, bool)> = None;
        let mut count: usize = 1;
        for _ in 0..batch_size {
            match urls.pop() {
                Some(url) => {
                    // A URL that cannot join this batch — POST body, underivable
                    // admin-API root, or a root differing from the batch's — is
                    // pushed back so the next dispatch pass handles it (single
                    // dispatch via the `ApiCall::from` pre-check, or its own
                    // batch for a different root). That pre-check guarantees the
                    // FIRST pop is always batchable, so every invocation consumes
                    // at least one URL — no dispatch livelock. Guard placed
                    // before `check_retry_exhaustion` so a pushed-back URL leaves
                    // intact (mirrors the resources `is_arg` guard).
                    let root = match exchange_batch_root(&url.url) {
                        Some(root)
                            if url.post_body.is_none()
                                && batch_root.as_ref().is_none_or(|(r, _)| *r == root) =>
                        {
                            root
                        }
                        _ => {
                            debug!(
                                "{:FL$}Deferring exchange URL to the next dispatch pass (POST body, underivable admin-API root, or root differing from the current batch): {:?}",
                                "ApiCall", url.url
                            );
                            urls.push(url);
                            break;
                        }
                    };
                    if let Some(skip_item) = check_retry_exhaustion(&url, &limits) {
                        res.push(skip_item);
                        continue;
                    }
                    if batch_root.is_none() {
                        batch_root = Some((root, url.service_mandatory_auth));
                    }
                    // Success code + value pointer from the schema (default 200 / /value).
                    let (success_http_code, value_pointer) = success_code_and_value_pointer(&url);
                    batch_data.initial_data.insert(
                        count.to_string(),
                        ApiCall {
                            id: 0,
                            url: url.clone(),
                            success_code: success_http_code,
                            value_pointer,
                            is_batch: false,
                            batch_data: None,
                        },
                    );
                    batch_data
                        .post_data
                        .entry(String::from("requests"))
                        .and_modify(|v| {
                            v.push(PostBatchData::GraphPostData(GraphPostData {
                                id: count.to_string(),
                                method: "GET".to_string(),
                                url: url.url.clone(),
                                headers: None,
                            }))
                        })
                        .or_insert(Vec::from([PostBatchData::GraphPostData(GraphPostData {
                            id: count.to_string(),
                            method: "GET".to_string(),
                            url: url.url.clone(),
                            headers: None,
                        })]));
                    count += 1;
                }
                None => {
                    // Unreachable in single-threaded dispatch: `batch_size` is
                    // `min(urls.len(), 10)`, so the loop pops at most as many URLs
                    // as the vector held on entry (the push-back guard breaks
                    // without consuming one). Reaching here means that invariant
                    // was violated.
                    error!(
                        "{:FL$}Internal invariant violated: URL vector exhausted before reaching batch_size while constructing next ApiCall for service exchange",
                        "ApiCall"
                    );
                    return Err(Error::EmptyUrlsVector);
                }
            };
        }
        if batch_data.post_data.is_empty() {
            // No batchable requests left in this pass, but `res` may still hold
            // `UrlRetryLimit` errors emitted by `check_retry_exhaustion` above.
            // Returning `Vec::new()` here would silently drop them; return `res`
            // so each exhausted URL gets recorded as a DumpError downstream.
            return Ok(res);
        }
        // `post_data` is non-empty, so at least one URL was batched and
        // `batch_root` was set; the `else` arm is unreachable belt-and-braces
        // (the deny lints forbid `unwrap`).
        let Some((root, service_mandatory_auth)) = batch_root else {
            return Ok(res);
        };
        res.push(ApiCallItem::ApiCall(Box::new(ApiCall {
            id: 0,
            url: Url {
                service_name: String::from("exchange"),
                service_scopes: Arc::new(Vec::new()),
                service_mandatory_auth,
                api: String::from("batch"),
                url: format!("{root}/$batch"),
                conditions: None,
                relationships: Arc::new(Vec::new()),
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
            value_pointer: "/responses".to_string(),
            is_batch: true,
            batch_data: Some(batch_data),
        })));
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::{consistency_level_headers, exchange_batch_root};

    #[test]
    fn consistency_level_headers_present_only_with_count() {
        let with_count = consistency_level_headers(
            "https://graph.microsoft.com/v1.0/groups?$count=true&$top=999",
        );
        assert_eq!(
            with_count
                .and_then(|h| h.get("ConsistencyLevel").cloned())
                .as_deref(),
            Some("eventual"),
            "ConsistencyLevel: eventual expected when $count=true is present"
        );
        assert!(
            consistency_level_headers("https://graph.microsoft.com/v1.0/groups?$top=999").is_none(),
            "no header without $count=true"
        );
    }

    #[test]
    fn exchange_batch_root_derives_root_from_path() {
        assert_eq!(
            exchange_batch_root("https://outlook.office365.com/adminapi/v1.0/tenant-id/recipients"),
            Some("https://outlook.office365.com/adminapi/v1.0/tenant-id".to_string())
        );
        // A query string after the tenant terminator does not affect the root.
        assert_eq!(
            exchange_batch_root(
                "https://outlook.office365.com/adminapi/beta/tid/recipients?$top=10"
            ),
            Some("https://outlook.office365.com/adminapi/beta/tid".to_string())
        );
    }

    #[test]
    fn exchange_batch_root_rejects_malformed_urls() {
        // No "/adminapi/" marker at all.
        assert_eq!(
            exchange_batch_root("https://graph.microsoft.com/v1.0/users"),
            None
        );
        // Marker present only inside a query string (a `?` precedes it).
        assert_eq!(
            exchange_batch_root("https://host/redir?next=/adminapi/v1.0/t/u"),
            None
        );
        // Marker present only inside a fragment (a `#` precedes it).
        assert_eq!(
            exchange_batch_root("https://host/page#/adminapi/v1.0/t/u"),
            None
        );
        // Empty version segment.
        assert_eq!(
            exchange_batch_root("https://host/adminapi//tenant/uri"),
            None
        );
        // Version segment polluted by a query char.
        assert_eq!(
            exchange_batch_root("https://host/adminapi/v1?0/tenant/uri"),
            None
        );
        // No terminating slash after the tenant (no `<uri>` segment).
        assert_eq!(
            exchange_batch_root("https://host/adminapi/v1.0/tenant-id"),
            None
        );
    }
}
