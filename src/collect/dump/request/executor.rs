use crate::FL;
use crate::collect::auth::tokens::Token;
use crate::utils::client::OradazClient;
use crate::utils::url::ApiCall;

use log::trace;

use chrono::Utc;
use reqwest::RequestBuilder;
use serde_json::Value;
use std::time::{Duration, Instant};

/// Errors that can occur during the execution of an API request.
#[derive(Debug)]
pub enum ExecutorError {
    /// Error occurring during the network request or while reading the response
    /// body (connection reset, timeout, TLS error, …). Retried as a transient
    /// network failure. A body that is received in full but is not valid JSON is
    /// NOT an error here — it is returned as an `ExecutionResult` with a `None`
    /// `content` and a `body_excerpt`, so the HTTP status is preserved for
    /// status-based routing (429 cooldown, 401 refresh, 5xx retry).
    Request(reqwest::Error),
}

/// The result of an API request execution, containing the HTTP status, any
/// rate-limit retry delay, and the response body.
pub struct ExecutionResult {
    pub status: u16,
    /// Parsed `Retry-After`, in seconds. `None` when the header is absent or
    /// unparseable, so downstream code applies the configured per-service /
    /// global default instead of treating it as zero (which would disable the
    /// cooldown entirely).
    pub retry_after: Option<u64>,
    /// Parsed JSON body, or `Value::Null` when the body was not valid JSON.
    pub content: Value,
    /// Response `Content-Type`, when present (diagnostics only).
    pub content_type: Option<String>,
    /// `Some(_)` iff the body could not be parsed as JSON; holds a bounded,
    /// single-line preview of the raw body for logging (never archived).
    pub body_excerpt: Option<String>,
    /// HTTP round-trip latency in milliseconds: from just before `send()` through
    /// reading the full response body. The body download dominates on large pages,
    /// so it is deliberately inside the span. Recorded into per-service / per-API
    /// stats for slow-endpoint identification.
    pub elapsed_ms: u64,
}

/// Apply a per-request timeout override if one was supplied. Without an
/// override, the client's default timeout (built at startup) applies.
/// `reqwest::RequestBuilder::timeout` replaces the client default, so we only
/// call it when there is something to override.
fn with_timeout(b: RequestBuilder, timeout_secs: Option<u64>) -> RequestBuilder {
    match timeout_secs {
        Some(secs) if secs > 0 => b.timeout(Duration::from_secs(secs)),
        _ => b,
    }
}

/// Executes a single HTTP request, optionally with a per-service timeout
/// override.
///
/// When `api_call.url.post_body` is `Some`, sends a POST with that JSON body
/// (used by Azure Resource Graph). Otherwise sends a GET.
pub async fn execute_single(
    client: &OradazClient,
    api_call: &ApiCall,
    token: &Token,
    timeout_secs: Option<u64>,
) -> Result<ExecutionResult, ExecutorError> {
    if let Some(body) = &api_call.url.post_body {
        trace!(
            "{:FL$}POST {} (ARG) [ID: {}]",
            "Executor", &api_call.url.url, api_call.id
        );
        let builder = client
            .client
            .post(&api_call.url.url)
            .header(
                reqwest::header::AUTHORIZATION,
                &format!("{} {}", token.token_type, token.access_token),
            )
            .json(body);
        let started = Instant::now();
        let res = with_timeout(builder, timeout_secs)
            .send()
            .await
            .map_err(ExecutorError::Request)?;
        return handle_response(res, started).await;
    }

    trace!(
        "{:FL$}GET {} [ID: {}]",
        "Executor", &api_call.url.url, api_call.id
    );
    let mut builder = client.client.get(&api_call.url.url).header(
        reqwest::header::AUTHORIZATION,
        &format!("{} {}", token.token_type, token.access_token),
    );
    // $count=true requires ConsistencyLevel: eventual for accurate @odata.count results
    if api_call.url.url.contains("$count=true") {
        builder = builder.header("ConsistencyLevel", "eventual");
    }
    let started = Instant::now();
    let res = with_timeout(builder, timeout_secs)
        .send()
        .await
        .map_err(ExecutorError::Request)?;

    handle_response(res, started).await
}

/// Executes a batch HTTP POST request, optionally with a per-service timeout
/// override.
pub async fn execute_batch(
    client: &OradazClient,
    api_call: &ApiCall,
    token: &Token,
    post_data: &Value,
    timeout_secs: Option<u64>,
) -> Result<ExecutionResult, ExecutorError> {
    trace!(
        "{:FL$}POST (batch) {} [ID: {}]",
        "Executor", &api_call.url.url, api_call.id
    );
    let builder = client
        .client
        .post(&api_call.url.url)
        .header(
            reqwest::header::AUTHORIZATION,
            &format!("{} {}", token.token_type, token.access_token),
        )
        .json(post_data);
    let started = Instant::now();
    let res = with_timeout(builder, timeout_secs)
        .send()
        .await
        .map_err(ExecutorError::Request)?;

    handle_response(res, started).await
}

async fn handle_response(
    res: reqwest::Response,
    started: Instant,
) -> Result<ExecutionResult, ExecutorError> {
    let status = res.status().as_u16();
    trace!("{:FL$}HTTP {}", "Executor", status);
    let retry_after = parse_retry_after(res.headers());
    let content_type = res
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // Read the body as bytes first: a failure here is a genuine transport error
    // (e.g. the connection dropped mid-body) and is surfaced as a retryable
    // `Request` error. A body that is simply not JSON must NOT collapse the HTTP
    // status — we keep the status (and Retry-After) so the response module can
    // route a non-JSON 429 → cooldown, 401 → refresh, 5xx → retry, and expose a
    // bounded excerpt for diagnostics, instead of losing all of it to an opaque
    // parse error.
    let bytes = res.bytes().await.map_err(ExecutorError::Request)?;
    // Latency covers send→body so large-page download time is included.
    let elapsed_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;

    match serde_json::from_slice::<Value>(&bytes) {
        Ok(content) => Ok(ExecutionResult {
            status,
            retry_after,
            content,
            content_type,
            body_excerpt: None,
            elapsed_ms,
        }),
        Err(_) => Ok(ExecutionResult {
            status,
            retry_after,
            content: Value::Null,
            content_type,
            body_excerpt: Some(bounded_excerpt(&bytes)),
            elapsed_ms,
        }),
    }
}

/// Parse the `Retry-After` header into seconds. Supports both the delta-seconds
/// form (`"120"`) and the HTTP-date form (RFC 7231 §7.1.3). Returns `None` when
/// the header is absent or unparseable so the rate-limit manager applies its
/// configured default rather than treating the value as zero.
///
/// `pub(crate)` so the prerequisite-check 429 handler reuses it instead of its
/// own delta-only parser (keeps both paths honouring the same two formats).
pub(crate) fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    let raw = headers.get(reqwest::header::RETRY_AFTER)?.to_str().ok()?;
    parse_retry_after_value(raw)
}

/// Parse a `Retry-After` **value string** into seconds: the delta-seconds form
/// (`"120"`) or the HTTP-date form (RFC 7231 §7.1.3). Empty / unparseable ⇒
/// `None` so the caller applies its configured default rather than zero.
///
/// `pub(crate)` and value-based (not header-based) so the Graph `$batch`
/// sub-response path — which carries `Retry-After` as a JSON field, not an HTTP
/// header — can reuse the exact same two-format parsing as the header path.
pub(crate) fn parse_retry_after_value(raw: &str) -> Option<u64> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if let Ok(secs) = raw.parse::<u64>() {
        trace!("{:FL$}Retry-After: {}s (delta)", "Executor", secs);
        return Some(secs);
    }
    let result = parse_http_date_secs(raw);
    if let Some(secs) = result {
        trace!(
            "{:FL$}Retry-After: {}s (HTTP-date {:?})",
            "Executor", secs, raw
        );
    }
    result
}

/// Parse an HTTP-date (RFC 7231 §7.1.1.1, any of the three permitted formats)
/// and return the non-negative number of seconds until that instant. Returns
/// `None` when the value is unparseable or already in the past, so the caller
/// falls back to the configured default cooldown.
fn parse_http_date_secs(raw: &str) -> Option<u64> {
    use chrono::NaiveDateTime;
    // IMF-fixdate (preferred), RFC 850, and asctime forms.
    const FORMATS: [&str; 3] = [
        "%a, %d %b %Y %H:%M:%S GMT",
        "%A, %d-%b-%y %H:%M:%S GMT",
        "%a %b %e %H:%M:%S %Y",
    ];
    for fmt in FORMATS {
        if let Ok(naive) = NaiveDateTime::parse_from_str(raw, fmt) {
            let delta = naive
                .and_utc()
                .signed_duration_since(Utc::now())
                .num_seconds();
            return u64::try_from(delta).ok();
        }
    }
    None
}

/// Build a single-line, length-bounded excerpt of a non-JSON response body for
/// diagnostic logging (never written to the archive).
fn bounded_excerpt(bytes: &[u8]) -> String {
    const MAX: usize = 256;
    let end = bytes.len().min(MAX);
    let mut excerpt = String::from_utf8_lossy(&bytes[..end]).replace(['\n', '\r', '\t'], " ");
    if bytes.len() > MAX {
        excerpt.push_str("...");
    }
    excerpt.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue, RETRY_AFTER};

    #[test]
    fn retry_after_absent_is_none() {
        assert_eq!(parse_retry_after(&HeaderMap::new()), None);
    }

    #[test]
    fn retry_after_delta_seconds() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("120"));
        assert_eq!(parse_retry_after(&headers), Some(120));
    }

    #[test]
    fn retry_after_unparseable_is_none() {
        // An unparseable value must yield None (→ configured default), never 0.
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("soon"));
        assert_eq!(parse_retry_after(&headers), None);
    }

    #[test]
    fn retry_after_http_date_future_is_positive() {
        let mut headers = HeaderMap::new();
        headers.insert(
            RETRY_AFTER,
            HeaderValue::from_static("Wed, 21 Oct 2099 07:28:00 GMT"),
        );
        let secs = parse_retry_after(&headers).expect("future http-date should parse");
        assert!(secs > 0);
    }

    #[test]
    fn retry_after_http_date_past_is_none() {
        // A past HTTP-date has no positive delta → fall back to the default.
        let mut headers = HeaderMap::new();
        headers.insert(
            RETRY_AFTER,
            HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT"),
        );
        assert_eq!(parse_retry_after(&headers), None);
    }

    // The shared value parser reused by the Graph `$batch` sub-response path:
    // both delta-seconds and HTTP-date strings parse identically to the header
    // path, and empty/unparseable yields None (→ configured default, not 0).
    #[test]
    fn retry_after_value_parses_delta_and_http_date() {
        assert_eq!(parse_retry_after_value("120"), Some(120));
        assert_eq!(parse_retry_after_value("  90 "), Some(90));
        assert_eq!(parse_retry_after_value(""), None);
        assert_eq!(parse_retry_after_value("soon"), None);
        assert!(
            parse_retry_after_value("Wed, 21 Oct 2099 07:28:00 GMT")
                .expect("future http-date should parse")
                > 0
        );
        assert_eq!(
            parse_retry_after_value("Wed, 21 Oct 2015 07:28:00 GMT"),
            None
        );
    }

    #[test]
    fn content_type_header_is_read() {
        // Sanity: the same HeaderMap accessor used by handle_response.
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/html"));
        let ct = headers
            .get(CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());
        assert_eq!(ct.as_deref(), Some("text/html"));
    }

    #[test]
    fn bounded_excerpt_is_single_line_and_capped() {
        let ex = bounded_excerpt(b"line1\nline2\tend");
        assert!(!ex.contains('\n') && !ex.contains('\t'));
        assert_eq!(ex, "line1 line2 end");

        let long = vec![b'a'; 1000];
        let ex2 = bounded_excerpt(&long);
        assert!(ex2.ends_with("..."));
        assert!(ex2.len() <= 256 + 3);
    }
}
