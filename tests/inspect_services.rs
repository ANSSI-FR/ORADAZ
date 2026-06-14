mod common;

use oradaz::VERSION;
use oradaz::collect::dump::response::DumpError;
use oradaz::inspect::display::{auth_type_from_config, print_services_section, strip_ansi_codes};

use serde_json::{Value, json};

// ─── strip_ansi_codes ─────────────────────────────────────────────────────────

#[test]
fn test_strip_ansi_codes_plain_text() {
    assert_eq!(strip_ansi_codes("hello world"), "hello world");
}

#[test]
fn test_strip_ansi_codes_removes_color_sequences() {
    let colored = "\x1b[32mGreen text\x1b[0m";
    assert_eq!(strip_ansi_codes(colored), "Green text");
}

#[test]
fn test_strip_ansi_codes_removes_multiple_sequences() {
    let s = "\x1b[1m\x1b[31mBold Red\x1b[0m normal";
    assert_eq!(strip_ansi_codes(s), "Bold Red normal");
}

#[test]
fn test_strip_ansi_codes_empty_string() {
    assert_eq!(strip_ansi_codes(""), "");
}

// ─── auth_type_from_config ────────────────────────────────────────────────────

#[test]
fn test_auth_type_device_code() {
    let config = json!({"use_device_code": true});
    assert_eq!(auth_type_from_config(&config), "Device code");
}

#[test]
fn test_auth_type_authorization_code() {
    let config = json!({"use_device_code": null, "use_application_credentials": null});
    assert_eq!(auth_type_from_config(&config), "Authorization code");
}

#[test]
fn test_auth_type_client_credentials_certificate() {
    let config = json!({
        "use_application_credentials": true,
        "application_credential_type": "certificate"
    });
    assert_eq!(
        auth_type_from_config(&config),
        "Client credentials (certificate)"
    );
}

#[test]
fn test_auth_type_client_credentials_password() {
    let config = json!({
        "use_application_credentials": true,
        "application_credential_type": "password"
    });
    assert_eq!(
        auth_type_from_config(&config),
        "Client credentials (password)"
    );
}

// ─── print_services_section ───────────────────────────────────────────────────

fn make_metadata() -> Value {
    json!({
        "tenant": "test-tenant-id",
        "collection_date": "2026-04-29 17:43:31",
        "dump_duration_secs": 10,
        "oradaz_version": VERSION,
        "schema_version": VERSION,
        "schema_hash": "abcdef1234567890",
        "services": {
            "graph": "enabled",
            "resources": "enabled",
            "exchange": "disabled_by_config",
        },
        "tokens": [
            {"name": "graph", "user_id": "862900b4-226b-46b7-bee0-2230f208bbb8",
             "user_principal_name": "admin@example.com", "client_id": "c"},
            {"name": "resources", "user_id": "862900b4-226b-46b7-bee0-2230f208bbb8",
             "user_principal_name": "admin@example.com", "client_id": "c"},
        ],
        "tables": [
            {"name": "users", "folder": "graph", "file": "users", "count": 100},
            {"name": "subs",  "folder": "resources", "file": "subs", "count": 3},
        ],
    })
}

fn make_config() -> Value {
    json!({"use_device_code": null, "use_application_credentials": null})
}

fn make_prereq() -> Value {
    json!({
        "graph": {"status": "ok", "info": "Global Reader + Security Reader"},
        "resources": {"status": "ok", "info": "3 subscriptions"},
        "exchange": {"status": "disabled", "error": "Disabled in config"},
    })
}

fn make_stats() -> Value {
    json!({
        "services": {
            "graph": {"http_batch_calls": 117, "http_single_calls": 0, "http_call_failures": 0},
            "resources": {"http_batch_calls": 45, "http_single_calls": 0, "http_call_failures": 0},
        },
        "apis": [
            {"service": "graph", "api": "users", "unexpected_errors": 2, "expected_errors": 1},
            {"service": "resources", "api": "subs", "unexpected_errors": 0, "expected_errors": 0},
        ],
    })
}

fn rendered(
    metadata: Option<&Value>,
    config: Option<&Value>,
    prerequisites: Option<&Value>,
    stats: Option<&Value>,
    errors: &[DumpError],
    service: Option<&str>,
) -> String {
    let mut lines: Vec<String> = vec![];
    print_services_section(
        metadata,
        config,
        prerequisites,
        stats,
        errors,
        service,
        &mut lines,
    );
    lines
        .iter()
        .map(|l| strip_ansi_codes(l))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn services_section_renders_header_and_collection_summary() {
    let metadata = make_metadata();
    let config = make_config();
    let prereq = make_prereq();
    let stats = make_stats();
    let text = rendered(
        Some(&metadata),
        Some(&config),
        Some(&prereq),
        Some(&stats),
        &[],
        None,
    );
    assert!(text.contains("COLLECTION SUMMARY"));
    assert!(text.contains("test-tenant-id"));
    assert!(text.contains("Authorization code"));
    assert!(text.contains("SERVICES"));
    assert!(text.contains("ISSUES BY API"));
}

#[test]
fn services_section_coverage_table_columns_present() {
    let metadata = make_metadata();
    let config = make_config();
    let prereq = make_prereq();
    let stats = make_stats();
    let text = rendered(
        Some(&metadata),
        Some(&config),
        Some(&prereq),
        Some(&stats),
        &[],
        None,
    );
    // Header columns
    assert!(text.contains("Service"));
    assert!(text.contains("Account"));
    assert!(text.contains("Objects"));
    assert!(text.contains("HTTP"));
    assert!(text.contains("Errors"));
    assert!(text.contains("Status"));
    assert!(text.contains("Errors = unexpected / expected"));
}

#[test]
fn services_section_row_renders_objects_and_http() {
    let metadata = make_metadata();
    let config = make_config();
    let prereq = make_prereq();
    let stats = make_stats();
    let text = rendered(
        Some(&metadata),
        Some(&config),
        Some(&prereq),
        Some(&stats),
        &[],
        None,
    );
    // Graph row: 100 objects, 117 batch calls
    assert!(text.contains("Graph"));
    assert!(text.contains("100"));
    assert!(text.contains("117 batch"));
    // Resources row: 3 objects, 45 batch
    assert!(text.contains("Resources"));
    assert!(text.contains("45 batch"));
    // Exchange row: disabled-in-config — no HTTP, dim status
    assert!(text.contains("Exchange"));
    assert!(text.contains("disabled in config"));
}

#[test]
fn services_section_errors_cell_shows_unexpected_over_expected() {
    let metadata = make_metadata();
    let stats = make_stats();
    let text = rendered(Some(&metadata), None, None, Some(&stats), &[], None);
    // Graph: 2 unexpected / 1 expected
    assert!(
        text.contains("2/1"),
        "expected 2/1 in errors cell, got:\n{text}"
    );
    // Resources: 0/0
    assert!(text.contains("0/0"));
}

#[test]
fn services_section_prereq_failed_shows_continuation_row() {
    let mut metadata = make_metadata();
    metadata["services"]["exchange"] = json!("disabled_by_prerequisite_failure");
    let prereq = json!({
        "exchange": {"status": "error", "error": "missing role: Exchange Administrator"},
    });
    let text = rendered(Some(&metadata), None, Some(&prereq), None, &[], None);
    assert!(text.contains("prereq failed"));
    assert!(text.contains("└ missing role: Exchange Administrator"));
}

#[test]
fn services_section_issues_lists_unexpected_errors() {
    let errors = vec![
        DumpError {
            folder: "graph".to_string(),
            file: "users".to_string(),
            url: "https://example/u".to_string(),
            status: 403,
            code: "Forbidden".to_string(),
            message: "Access denied".to_string(),
            expected: false,
            full_response: None,
            post_data: None,
        },
        DumpError {
            folder: "graph".to_string(),
            file: "users".to_string(),
            url: "https://example/u2".to_string(),
            status: 403,
            code: "Forbidden".to_string(),
            message: "Access denied".to_string(),
            expected: false,
            full_response: None,
            post_data: None,
        },
    ];
    let metadata = make_metadata();
    let text = rendered(Some(&metadata), None, None, None, &errors, None);
    assert!(text.contains("Graph / users"));
    assert!(text.contains("2× HTTP 403"));
    assert!(text.contains("Forbidden"));
    assert!(text.contains("--service graph"));
}

#[test]
fn services_section_issues_empty_when_no_unexpected() {
    let metadata = make_metadata();
    let text = rendered(Some(&metadata), None, None, None, &[], None);
    assert!(text.contains("(no unexpected errors)"));
}

#[test]
fn services_section_service_filter_narrows_coverage_and_issues() {
    let errors = vec![
        DumpError {
            folder: "graph".to_string(),
            file: "users".to_string(),
            url: "u".to_string(),
            status: 403,
            code: "Forbidden".to_string(),
            message: "x".to_string(),
            expected: false,
            full_response: None,
            post_data: None,
        },
        DumpError {
            folder: "resources".to_string(),
            file: "subs".to_string(),
            url: "u".to_string(),
            status: 500,
            code: "Err".to_string(),
            message: "x".to_string(),
            expected: false,
            full_response: None,
            post_data: None,
        },
    ];
    let metadata = make_metadata();
    let text = rendered(Some(&metadata), None, None, None, &errors, Some("graph"));
    // Graph row appears
    assert!(text.contains(" Graph "));
    // Resources row does NOT (filter narrows coverage table too)
    let coverage_section = text.split("ISSUES BY API").next().unwrap_or(&text);
    assert!(
        !coverage_section.contains(" Resources "),
        "filter graph should hide Resources row, got:\n{coverage_section}"
    );
    // ISSUES section shows only graph
    let issues_section = text.split("ISSUES BY API").nth(1).unwrap_or("");
    assert!(issues_section.contains("Graph / users"));
    assert!(!issues_section.contains("Resources / subs"));
}

#[test]
fn services_section_no_metadata_still_renders() {
    let text = rendered(None, None, None, None, &[], None);
    assert!(text.contains("COLLECTION SUMMARY"));
    assert!(text.contains("no collection metadata available"));
    assert!(text.contains("SERVICES"));
}

#[test]
fn services_section_account_shows_upn_and_short_id() {
    let metadata = make_metadata();
    let text = rendered(Some(&metadata), None, None, None, &[], None);
    assert!(text.contains("admin@example.com"));
    assert!(text.contains("862900b4"));
}
