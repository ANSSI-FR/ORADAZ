mod common;

use crate::common::default_test_config;
use oradaz::collect::auth::tokens::{Token, TokenState};
use oradaz::collect::dump::conditions::ConditionChecker;
use oradaz::collect::dump::orchestration::events::CoordinatorEvent;
use oradaz::collect::dump::ratelimit::RateLimitManager;
use oradaz::collect::dump::response::single::value_handlers::build_arg_next_url;
use oradaz::collect::dump::response::{Response, ResponseContent, ResponseContext, ResponseThread};
use oradaz::collect::dump::{
    audit_logs_date_filters, expand_partition_seeds, inject_arg_post_body,
};
use oradaz::utils::client::OradazClient;
use oradaz::utils::metadata::TableMetadata;
use oradaz::utils::url::{ApiCall, Url as OradazUrl};
use oradaz::utils::writer::actor::spawn_writer_task;

use dashmap::DashMap;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tokio::sync::mpsc;

fn create_arg_token() -> Token {
    Token {
        tenant_id: "test-tenant".to_string(),
        client_id: "test-client".to_string(),
        service: "resources".to_string(),
        expires_on: chrono::Utc::now().timestamp() + 3600,
        access_token: "test_token".to_string(),
        refresh_token: None,
        token_type: "Bearer".to_string(),
        user_id: "user-123".to_string(),
        user_principal_name: "user@example.com".to_string(),
        scopes: vec!["https://management.azure.com/.default".to_string()],
    }
}

fn create_arg_url(base: &str) -> OradazUrl {
    OradazUrl {
        service_name: "resources".to_string(),
        service_scopes: Arc::new(vec!["https://management.azure.com/.default".to_string()]),
        service_mandatory_auth: true,
        api: "resourcegraph_resources".to_string(),
        url: format!(
            "{}/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01",
            base
        ),
        conditions: None,
        relationships: Arc::new(vec![]),
        api_behavior: Arc::new({
            let mut m = HashMap::new();
            m.insert("is_arg".to_string(), "true".to_string());
            m.insert("value_field".to_string(), "data".to_string());
            m
        }),
        expected_error_codes: None,
        parent: None,
        retry_number: 0,
        rate_limit_retry_number: 0,
        rate_limit_total_wait_secs: 0,
        network_retry_number: 0,
        post_body: Some(json!({"query": "Resources", "subscriptions": ["sub-1"]})),
    }
}

fn create_arg_api_call(url: OradazUrl) -> ApiCall {
    ApiCall {
        id: 1,
        url,
        success_code: 200,
        value_pointer: "/data".to_string(),
        is_batch: false,
        batch_data: None,
    }
}

async fn setup_arg_response_thread(
    api_call: ApiCall,
    response: Response,
) -> (mpsc::Receiver<CoordinatorEvent>, ResponseThread, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let mut config = default_test_config();
    config.output_files = Some(true);
    config.output_mla = Some(false);
    let (writer, _task) = spawn_writer_task(
        config.clone(),
        temp_dir.path().to_path_buf(),
        "test-run".to_string(),
    )
    .await
    .unwrap();

    let (update_tx, update_rx) = mpsc::channel::<CoordinatorEvent>(8192);
    let token = create_arg_token();
    let tokens = DashMap::new();
    tokens.insert(Arc::from("resources"), Arc::new(TokenState::new(token)));

    let stats = Arc::new(oradaz::utils::stats::Stats::new());
    let condition_checker = ConditionChecker {
        client: OradazClient::new(&config).unwrap(),
        tenant_conditions: HashMap::new(),
        user_conditions: DashMap::new(),
        emergency_accounts_custom_attributes: String::from("Emergency.isEmergency"),
        org_url: String::new(),
        stats: Arc::clone(&stats),
        is_application_auth: false,
    };

    let thread = ResponseThread::new(
        update_tx,
        ResponseContext {
            writer,
            metadata: Arc::new(Mutex::new(HashMap::<String, TableMetadata>::new())),
            tokens: Arc::new(tokens),
            condition_checker: Arc::new(condition_checker),
            ratelimit_manager: Arc::new(RateLimitManager::default()),
            concurrency_controller: Arc::new(
                oradaz::collect::dump::concurrency::ConcurrencyController::default(),
            ),
            stats,
            logs_date_filter_and: None,
        },
        Box::new(ResponseContent { api_call, response }),
    );

    (update_rx, thread, temp_dir)
}

// --- unit tests for build_arg_next_url ---

#[test]
fn test_build_arg_next_url_returns_none_when_no_skip_token() {
    let url = create_arg_url("https://management.azure.com");
    let api_call = create_arg_api_call(url);
    let response = Response {
        status: 200,
        retry_after: None,
        content: json!({"data": [{"id": "vm-1"}], "totalRecords": 1}),
    };
    let result = build_arg_next_url(&response, &api_call);
    assert!(result.is_none(), "No $skipToken means last page");
}

#[test]
fn test_build_arg_next_url_injects_skip_token_into_body() {
    let url = create_arg_url("https://management.azure.com");
    let api_call = create_arg_api_call(url);
    let response = Response {
        status: 200,
        retry_after: None,
        content: json!({"data": [{"id": "vm-1"}], "totalRecords": 5, "$skipToken": "tok-abc"}),
    };
    let result = build_arg_next_url(&response, &api_call).expect("Should produce next URL");
    let body = result.post_body.as_ref().expect("post_body must be set");
    // ARG expects the continuation token under `options.$skipToken`, never top-level.
    assert_eq!(body["options"]["$skipToken"], json!("tok-abc"));
    assert!(
        body.get("$skipToken").is_none(),
        "token must live under options, not at the body top level"
    );
    assert_eq!(body["query"], json!("Resources"));
    assert_eq!(body["subscriptions"], json!(["sub-1"]));
    assert_eq!(result.api, "resourcegraph_resources");
    assert_eq!(result.retry_number, 0);
}

#[test]
fn test_build_arg_next_url_preserves_subscriptions_across_pages() {
    let mut url = create_arg_url("https://management.azure.com");
    // Second page: body already has options.$skipToken from the previous page
    let body = url.post_body.as_mut().unwrap();
    body["options"]["$skipToken"] = json!("tok-page2");
    let api_call = create_arg_api_call(url);
    let response = Response {
        status: 200,
        retry_after: None,
        content: json!({"data": [{"id": "vm-2"}], "$skipToken": "tok-page3"}),
    };
    let result = build_arg_next_url(&response, &api_call).expect("Third page URL");
    let body = result.post_body.as_ref().unwrap();
    assert_eq!(body["options"]["$skipToken"], json!("tok-page3"));
    assert_eq!(body["subscriptions"], json!(["sub-1"]));
}

// --- integration test: process_single generates next-page ARG URL ---

#[tokio::test]
async fn test_arg_process_single_pagination_generates_next_url() {
    let url = create_arg_url("https://management.azure.com");
    let api_call = create_arg_api_call(url);

    let content = json!({
        "data": [{"id": "vm-1", "name": "my-vm", "type": "microsoft.compute/virtualmachines"}],
        "totalRecords": 2,
        "$skipToken": "skip-tok-xyz"
    });
    let response = Response {
        status: 200,
        retry_after: None,
        content: content.clone(),
    };

    let (_rx, thread, _dir) = setup_arg_response_thread(api_call.clone(), response).await;

    let returned_urls = thread
        .process_single(
            &Response {
                status: 200,
                retry_after: None,
                content,
            },
            &api_call,
        )
        .await;

    let next_urls: Vec<_> = returned_urls
        .iter()
        .filter(|u| {
            u.post_body
                .as_ref()
                .map(|b| b.pointer("/options/$skipToken").is_some())
                .unwrap_or(false)
        })
        .collect();

    assert_eq!(next_urls.len(), 1, "Expected exactly one ARG next-page URL");
    assert_eq!(
        next_urls[0].post_body.as_ref().unwrap()["options"]["$skipToken"],
        json!("skip-tok-xyz")
    );
}

#[tokio::test]
async fn test_arg_process_single_last_page_no_next_url() {
    let url = create_arg_url("https://management.azure.com");
    let api_call = create_arg_api_call(url);

    let content = json!({
        "data": [{"id": "vm-last", "name": "last-vm"}],
        "totalRecords": 1
    });
    let response = Response {
        status: 200,
        retry_after: None,
        content: content.clone(),
    };

    let (_rx, thread, _dir) = setup_arg_response_thread(api_call.clone(), response).await;

    let returned_urls = thread
        .process_single(
            &Response {
                status: 200,
                retry_after: None,
                content,
            },
            &api_call,
        )
        .await;

    let next_urls: Vec<_> = returned_urls
        .iter()
        .filter(|u| {
            u.post_body
                .as_ref()
                .map(|b| b.pointer("/options/$skipToken").is_some())
                .unwrap_or(false)
        })
        .collect();

    assert!(
        next_urls.is_empty(),
        "Last ARG page should produce no next-page URL"
    );
}

// --- unit tests for inject_arg_post_body ---

fn arg_url_without_body() -> OradazUrl {
    let mut u = create_arg_url("https://management.azure.com");
    u.post_body = None;
    u
}

fn non_arg_url() -> OradazUrl {
    let mut u = create_arg_url("https://management.azure.com");
    u.api = "subscriptions".to_string();
    Arc::make_mut(&mut u.api_behavior).remove("is_arg");
    u.post_body = None;
    u
}

fn partition_url() -> OradazUrl {
    OradazUrl {
        service_name: "exchange".to_string(),
        service_scopes: Arc::new(vec![]),
        service_mandatory_auth: true,
        api: "recipients".to_string(),
        url: "https://outlook.office365.com/adminapi/beta/tid/Recipient?PropertySet=All&$top=1000"
            .to_string(),
        conditions: None,
        relationships: Arc::new(vec![]),
        api_behavior: Arc::new({
            let mut m = HashMap::new();
            m.insert(
                "partition_field".to_string(),
                "RecipientTypeDetails".to_string(),
            );
            m.insert(
                "partition_values".to_string(),
                "UserMailbox,SharedMailbox".to_string(),
            );
            m
        }),
        expected_error_codes: None,
        parent: None,
        retry_number: 0,
        rate_limit_retry_number: 0,
        rate_limit_total_wait_secs: 0,
        network_retry_number: 0,
        post_body: None,
    }
}

#[test]
fn test_expand_partition_seeds_disjoint_plus_catchall() {
    let urls = Arc::new(DashMap::new());
    urls.insert(Arc::from("exchange"), vec![partition_url()]);

    expand_partition_seeds(&urls);

    let bucket = urls.get::<Arc<str>>(&Arc::from("exchange")).unwrap();
    // Two per-type `eq` seeds plus one catch-all.
    assert_eq!(bucket.len(), 3);
    // Spaces are %20-encoded: these exchange seeds dispatch through the `$batch`
    // path, which embeds the URL verbatim (no client-side normalisation).
    assert!(bucket.iter().any(|u| {
        u.url
            .contains("$filter=RecipientTypeDetails%20eq%20'UserMailbox'")
    }));
    assert!(bucket.iter().any(|u| {
        u.url
            .contains("$filter=RecipientTypeDetails%20eq%20'SharedMailbox'")
    }));
    // Catch-all: the `ne`-conjunction of every declared value (collects any
    // value outside the list, so the partition stays exhaustive).
    assert!(bucket.iter().any(|u| u.url.contains(
        "$filter=RecipientTypeDetails%20ne%20'UserMailbox'%20and%20RecipientTypeDetails%20ne%20'SharedMailbox'"
    )));
    // Base query preserved on every seed; the table stays `recipients`.
    assert!(bucket.iter().all(|u| u.url.contains("PropertySet=All")));
    assert!(bucket.iter().all(|u| u.api == "recipients"));
}

#[test]
fn test_expand_partition_seeds_leaves_unpartitioned_untouched() {
    let mut u = partition_url();
    Arc::make_mut(&mut u.api_behavior).remove("partition_field");
    let urls = Arc::new(DashMap::new());
    urls.insert(Arc::from("exchange"), vec![u]);

    expand_partition_seeds(&urls);

    let bucket = urls.get::<Arc<str>>(&Arc::from("exchange")).unwrap();
    assert_eq!(bucket.len(), 1);
    assert!(!bucket[0].url.contains("$filter"));
}

#[test]
fn test_inject_arg_post_body_sets_body_when_ids_present() {
    let urls = Arc::new(DashMap::new());
    urls.insert(
        Arc::from("resources"),
        vec![arg_url_without_body(), non_arg_url()],
    );

    inject_arg_post_body(&urls, &["sub-A".to_string(), "sub-B".to_string()]);

    let bucket = urls.get::<Arc<str>>(&Arc::from("resources")).unwrap();
    let arg = bucket
        .iter()
        .find(|u| {
            u.api_behavior
                .get("is_arg")
                .map(|v| v == "true")
                .unwrap_or(false)
        })
        .expect("ARG URL still present");
    let body = arg.post_body.as_ref().expect("post_body injected");
    assert_eq!(body["query"], json!("Resources"));
    assert_eq!(body["subscriptions"], json!(["sub-A", "sub-B"]));
    // Non-ARG URL untouched
    let non_arg = bucket.iter().find(|u| u.api == "subscriptions").unwrap();
    assert!(non_arg.post_body.is_none());
}

#[test]
fn test_inject_arg_post_body_removes_arg_when_ids_empty() {
    let urls = Arc::new(DashMap::new());
    urls.insert(
        Arc::from("resources"),
        vec![arg_url_without_body(), non_arg_url()],
    );

    inject_arg_post_body(&urls, &[]);

    let bucket = urls.get::<Arc<str>>(&Arc::from("resources")).unwrap();
    assert_eq!(bucket.len(), 1);
    assert_eq!(bucket[0].api, "subscriptions");
}

#[test]
fn test_inject_arg_post_body_honours_arg_query_override() {
    let mut url = arg_url_without_body();
    Arc::make_mut(&mut url.api_behavior)
        .insert("arg_query".to_string(), "Resources | take 5".to_string());
    let urls = Arc::new(DashMap::new());
    urls.insert(Arc::from("resources"), vec![url]);

    inject_arg_post_body(&urls, &["sub-X".to_string()]);

    let bucket = urls.get::<Arc<str>>(&Arc::from("resources")).unwrap();
    let body = bucket[0].post_body.as_ref().unwrap();
    assert_eq!(body["query"], json!("Resources | take 5"));
}

#[test]
fn test_inject_arg_post_body_sets_options_top_when_arg_top_present() {
    // S3: `arg_top` in the schema must surface as `options.$top` so ARG caps
    // each page; the rest of the body (query/subscriptions) is unaffected.
    let mut url = arg_url_without_body();
    Arc::make_mut(&mut url.api_behavior).insert("arg_top".to_string(), "1000".to_string());
    let urls = Arc::new(DashMap::new());
    urls.insert(Arc::from("resources"), vec![url]);

    inject_arg_post_body(&urls, &["sub-X".to_string()]);

    let bucket = urls.get::<Arc<str>>(&Arc::from("resources")).unwrap();
    let body = bucket[0].post_body.as_ref().unwrap();
    assert_eq!(body["options"]["$top"], json!(1000));
    assert_eq!(body["query"], json!("Resources"));
    assert_eq!(body["subscriptions"], json!(["sub-X"]));
}

#[test]
fn test_inject_arg_post_body_no_options_when_arg_top_absent() {
    // Backward compatibility: without `arg_top` the body carries no `options`,
    // so first-page detection (`options/$skipToken` absent) keeps working.
    let urls = Arc::new(DashMap::new());
    urls.insert(Arc::from("resources"), vec![arg_url_without_body()]);

    inject_arg_post_body(&urls, &["sub-X".to_string()]);

    let bucket = urls.get::<Arc<str>>(&Arc::from("resources")).unwrap();
    let body = bucket[0].post_body.as_ref().unwrap();
    assert!(body.get("options").is_none());
}

#[test]
fn test_inject_arg_post_body_ignores_non_numeric_arg_top() {
    // A malformed `arg_top` must not inject a bogus option (it is skipped).
    let mut url = arg_url_without_body();
    Arc::make_mut(&mut url.api_behavior).insert("arg_top".to_string(), "not-a-number".to_string());
    let urls = Arc::new(DashMap::new());
    urls.insert(Arc::from("resources"), vec![url]);

    inject_arg_post_body(&urls, &["sub-X".to_string()]);

    let bucket = urls.get::<Arc<str>>(&Arc::from("resources")).unwrap();
    let body = bucket[0].post_body.as_ref().unwrap();
    assert!(body.get("options").is_none());
}

// --- unit tests for audit_logs_date_filters (S1/S2 date bounding) ---

#[test]
fn test_audit_logs_date_filters_enabled() {
    let mut config = default_test_config();
    config.logs_days_filter = Some(7);
    let (directory_audits, signins) = audit_logs_date_filters(&config);

    let directory_audits = directory_audits.expect("directoryAudits clause present");
    let signins = signins.expect("signIns clause present");
    // directoryAudits joins after the existing `?$top=999` with `&`.
    assert!(
        directory_audits.starts_with("&$filter=activityDateTime ge "),
        "got: {directory_audits}"
    );
    // signIns merges into the existing `$filter=userId eq …` with ` and `.
    assert!(
        signins.starts_with(" and createdDateTime ge "),
        "got: {signins}"
    );
}

#[test]
fn test_audit_logs_date_filters_disabled() {
    let mut config = default_test_config();
    config.logs_days_filter = Some(0);
    let (directory_audits, signins) = audit_logs_date_filters(&config);
    assert!(directory_audits.is_none());
    assert!(signins.is_none());
}
