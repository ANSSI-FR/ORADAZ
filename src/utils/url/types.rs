use crate::utils::errors::Error;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Represents a URL to be collected, including its service context,
/// API endpoint, and associated metadata for the collection process.
///
/// The schema-static fields shared by every `Url` of the same API
/// (`service_scopes`, `relationships`, `api_behavior`, `expected_error_codes`) are
/// wrapped in `Arc` so cloning a child `Url` — of which there can be millions on a
/// large tenant — is a pointer bump rather than a deep copy. `Arc` is
/// transparent to serde, so the serialised wire form is unchanged.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Url {
    pub service_name: String,
    pub service_scopes: Arc<Vec<String>>,
    pub service_mandatory_auth: bool,
    pub api: String,
    pub url: String,
    pub conditions: Option<Vec<String>>,
    pub relationships: Arc<Vec<RelationshipUrl>>,
    pub api_behavior: Arc<HashMap<String, String>>,
    pub expected_error_codes: Option<Arc<Vec<ExpectedErrorCode>>>,
    pub parent: Option<HashMap<String, String>>,
    pub retry_number: usize,
    /// Retries triggered by HTTP 429 responses; tracked separately from
    /// `retry_number` so that throttling does not consume the per-URL retry
    /// budget reserved for real errors.
    #[serde(default)]
    pub rate_limit_retry_number: usize,
    /// Total seconds accumulated from 429 Retry-After headers for this URL.
    /// Combined with `rate_limit_retry_number`, gates the rate-limit retry
    /// budget so a permanently throttled URL is eventually abandoned.
    #[serde(default)]
    pub rate_limit_total_wait_secs: u64,
    /// JSON body sent as a POST instead of a GET. Set for Azure Resource Graph
    /// (and any future POST-style endpoint); skipped from the serialised form
    /// when absent so GET-only URLs remain wire-compatible with prior versions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_body: Option<serde_json::Value>,
}

/// Describes a relationship between a collected object and another URL
/// that should be explored.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RelationshipUrl {
    pub service: String,
    pub url_scheme: String,
    pub default_api_behavior: HashMap<String, String>,
    pub default_parameters: Option<Vec<Parameter>>,
    pub api: String,
    pub name: String,
    pub uri: String,
    pub conditions: Option<Vec<String>>,
    pub api_behavior: Option<HashMap<String, String>>,
    pub expected_error_codes: Option<Vec<ExpectedErrorCode>>,
    pub parameters: Option<Vec<Parameter>>,
    pub keys: Option<Vec<Parameter>>,
    pub relationships: Option<Vec<Relationship>>,
}

/// Defines a relationship between two objects in the collected data.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Relationship {
    pub name: String,
    pub uri: String,
    pub conditions: Option<Vec<String>>,
    pub api_behavior: Option<HashMap<String, String>>,
    pub parameters: Option<Vec<Parameter>>,
    pub keys: Option<Vec<Parameter>>,
    pub relationships: Option<Vec<Relationship>>,
    pub expected_error_codes: Option<Vec<ExpectedErrorCode>>,
}

/// Specifies an expected HTTP error status and optional error code
/// that should be handled during collection.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExpectedErrorCode {
    pub status: u16,
    pub code: Option<String>,
}

/// Represents a parameter to be passed to an API call, potentially
/// requiring a transformation before transmission.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Parameter {
    pub name: String,
    pub value: String,
    pub transform: Option<String>,
    pub conditions: Option<Vec<String>>,
}

/// A simplified representation of an API endpoint used for internal mapping.
#[derive(Clone, Deserialize)]
pub struct Api {
    pub name: String,
    pub uri: String,
    pub conditions: Option<Vec<String>>,
    pub api_behavior: Option<HashMap<String, String>>,
    pub parameters: Option<Vec<Parameter>>,
    pub relationships: Option<Vec<Relationship>>,
    pub expected_error_codes: Option<Vec<ExpectedErrorCode>>,
}

/// Data structure for a Microsoft Graph batch request item.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GraphPostData {
    pub id: String,
    pub method: String,
    pub url: String,
    /// Per-sub-request headers (e.g. `ConsistencyLevel: eventual` when `$count=true` is used).
    /// Omitted from the serialised JSON when absent so the wire format is unchanged for other requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
}

/// Data structure for an Azure Resource Manager batch request item.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResourcesPostData {
    pub name: String,
    #[serde(rename = "httpMethod")]
    pub http_method: String,
    pub url: String,
}

/// A tagged union representing batch data for either Resources or Graph APIs.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PostBatchData {
    ResourcesPostData(ResourcesPostData),
    GraphPostData(GraphPostData),
}

/// Configuration for executing API calls in batch mode, including
/// request mapping and response field identifiers.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BatchData {
    pub post_data: HashMap<String, Vec<PostBatchData>>,
    pub initial_data: HashMap<String, ApiCall>,
    pub id_field: String,
    pub body_field: String,
    pub status_field: String,
    pub retry_after_field: String,
}

/// Represents a specific API call to be executed, linking a `Url`
/// to its expected response format and behavior.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiCall {
    pub id: u32,
    pub url: Url,
    pub success_code: u16,
    pub value_pointer: String,
    pub is_batch: bool,
    pub batch_data: Option<BatchData>,
}

/// Retry budgets applied when a URL is about to be dispatched.
///
/// `retry` counts real errors (4xx prereq, 5xx) and is the main circuit breaker.
/// `rate_limit_retry` and `rate_limit_max_wait_secs` form a separate budget for
/// HTTP 429 throttling, which can persist for many cycles without indicating an
/// actual error.
#[derive(Debug, Clone, Copy)]
pub struct RetryLimits {
    pub retry: usize,
    pub rate_limit_retry: usize,
    pub rate_limit_max_wait_secs: u64,
}

/// An item in the API call queue, which can either be a successful
/// `ApiCall` configuration or an `Error` encountered during its creation.
pub enum ApiCallItem {
    ApiCall(Box<ApiCall>),
    ApiCallError(Error),
}
