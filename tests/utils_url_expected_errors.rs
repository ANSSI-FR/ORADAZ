use oradaz::utils::url::{ApiCall, ExpectedErrorCode, Url};

use std::collections::HashMap;
use std::sync::Arc;

fn make_api_call(expected_error_codes: Option<Vec<ExpectedErrorCode>>) -> ApiCall {
    ApiCall {
        id: 0,
        url: Url {
            service_name: "graph".to_string(),
            service_scopes: Arc::new(vec![]),
            service_mandatory_auth: true,
            api: "test".to_string(),
            url: "https://graph.microsoft.com/v1.0/test".to_string(),
            conditions: None,
            relationships: Arc::new(vec![]),
            api_behavior: Arc::new(HashMap::new()),
            expected_error_codes: expected_error_codes.map(Arc::new),
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

/// No expected_error_codes configured → never expected.
#[test]
fn no_expected_error_codes_returns_false() {
    let call = make_api_call(None);
    let result = oradaz::utils::url::expected_errors::is_expected_error(404, None, &call);
    assert!(!result);
}

/// Empty list of expected codes → never expected.
#[test]
fn empty_expected_error_codes_returns_false() {
    let call = make_api_call(Some(vec![]));
    let result = oradaz::utils::url::expected_errors::is_expected_error(404, None, &call);
    assert!(!result);
}

/// Status matches but no `code` constraint → expected (any error body counts).
#[test]
fn matching_status_no_code_constraint_returns_true() {
    let call = make_api_call(Some(vec![ExpectedErrorCode {
        status: 404,
        code: None,
        breaker_eligible: false,
    }]));
    let result = oradaz::utils::url::expected_errors::is_expected_error(404, None, &call);
    assert!(result);
}

/// Status matches and error code matches → expected.
#[test]
fn matching_status_and_matching_code_returns_true() {
    let call = make_api_call(Some(vec![ExpectedErrorCode {
        status: 403,
        code: Some("Authorization_RequestDenied".to_string()),
        breaker_eligible: false,
    }]));
    let code_value = serde_json::json!("Authorization_RequestDenied");
    let result =
        oradaz::utils::url::expected_errors::is_expected_error(403, Some(&code_value), &call);
    assert!(result);
}

/// The error-code match is case-insensitive (ASCII): Microsoft APIs are not
/// consistent about error-code casing across services/versions, so a casing-only
/// difference must still be recognised as the schema-declared expected error.
#[test]
fn matching_status_code_differs_only_in_case_returns_true() {
    let call = make_api_call(Some(vec![ExpectedErrorCode {
        status: 403,
        code: Some("Authorization_RequestDenied".to_string()),
        breaker_eligible: false,
    }]));
    for variant in [
        "authorization_requestdenied",
        "AUTHORIZATION_REQUESTDENIED",
        "Authorization_RequestDenied",
    ] {
        let code_value = serde_json::json!(variant);
        assert!(
            oradaz::utils::url::expected_errors::is_expected_error(403, Some(&code_value), &call),
            "case-insensitive match should accept {variant:?}"
        );
    }
}

/// Status matches but error code doesn't match → not expected.
#[test]
fn matching_status_wrong_code_returns_false() {
    let call = make_api_call(Some(vec![ExpectedErrorCode {
        status: 403,
        code: Some("Authorization_RequestDenied".to_string()),
        breaker_eligible: false,
    }]));
    let code_value = serde_json::json!("Something_Else");
    let result =
        oradaz::utils::url::expected_errors::is_expected_error(403, Some(&code_value), &call);
    assert!(!result);
}

/// Status matches with code constraint but no code provided in response → not expected.
#[test]
fn matching_status_code_required_but_absent_returns_false() {
    let call = make_api_call(Some(vec![ExpectedErrorCode {
        status: 403,
        code: Some("Authorization_RequestDenied".to_string()),
        breaker_eligible: false,
    }]));
    let result = oradaz::utils::url::expected_errors::is_expected_error(403, None, &call);
    assert!(!result);
}

/// Status does not match → not expected, regardless of code.
#[test]
fn non_matching_status_returns_false() {
    let call = make_api_call(Some(vec![ExpectedErrorCode {
        status: 404,
        code: None,
        breaker_eligible: false,
    }]));
    let result = oradaz::utils::url::expected_errors::is_expected_error(403, None, &call);
    assert!(!result);
}

/// Multiple entries — first non-matching, second matching → expected.
#[test]
fn multiple_entries_second_matches_returns_true() {
    let call = make_api_call(Some(vec![
        ExpectedErrorCode {
            status: 500,
            code: None,
            breaker_eligible: false,
        },
        ExpectedErrorCode {
            status: 403,
            code: Some("Forbidden".to_string()),
            breaker_eligible: false,
        },
    ]));
    let code_value = serde_json::json!("Forbidden");
    let result =
        oradaz::utils::url::expected_errors::is_expected_error(403, Some(&code_value), &call);
    assert!(result);
}

/// Multiple entries — none match → not expected.
#[test]
fn multiple_entries_none_match_returns_false() {
    let call = make_api_call(Some(vec![
        ExpectedErrorCode {
            status: 500,
            code: None,
            breaker_eligible: false,
        },
        ExpectedErrorCode {
            status: 404,
            code: Some("NotFound".to_string()),
            breaker_eligible: false,
        },
    ]));
    let result = oradaz::utils::url::expected_errors::is_expected_error(403, None, &call);
    assert!(!result);
}

/// `is_breaker_eligible_error` matches only entries flagged `breaker_eligible`,
/// independent of HTTP status, and requires the same status+code match as
/// `is_expected_error`.
#[test]
fn breaker_eligible_requires_the_flag_not_a_specific_status() {
    use oradaz::utils::url::expected_errors::is_breaker_eligible_error;

    // An expected, but UNFLAGGED, 403 → expected yet not breaker-eligible.
    let unflagged = make_api_call(Some(vec![ExpectedErrorCode {
        status: 403,
        code: Some("Forbidden".to_string()),
        breaker_eligible: false,
    }]));
    let forbidden = serde_json::json!("Forbidden");
    assert!(oradaz::utils::url::expected_errors::is_expected_error(
        403,
        Some(&forbidden),
        &unflagged
    ));
    assert!(
        !is_breaker_eligible_error(403, Some(&forbidden), &unflagged),
        "an unflagged expected error must not be breaker-eligible"
    );

    // A FLAGGED 403 → breaker-eligible (case-insensitive code match preserved).
    let flagged = make_api_call(Some(vec![ExpectedErrorCode {
        status: 403,
        code: Some("Forbidden".to_string()),
        breaker_eligible: true,
    }]));
    let lower = serde_json::json!("forbidden");
    assert!(is_breaker_eligible_error(403, Some(&lower), &flagged));
    // Wrong status / wrong code / missing code → not eligible.
    assert!(!is_breaker_eligible_error(404, Some(&forbidden), &flagged));
    assert!(!is_breaker_eligible_error(
        403,
        Some(&serde_json::json!("Other")),
        &flagged
    ));
    assert!(!is_breaker_eligible_error(403, None, &flagged));

    // The flag is status-independent: a flagged non-403 code is eligible.
    let flagged400 = make_api_call(Some(vec![ExpectedErrorCode {
        status: 400,
        code: Some("TenantWideDisabled".to_string()),
        breaker_eligible: true,
    }]));
    assert!(is_breaker_eligible_error(
        400,
        Some(&serde_json::json!("TenantWideDisabled")),
        &flagged400
    ));

    // Absent expected_error_codes → never eligible.
    assert!(!is_breaker_eligible_error(
        403,
        Some(&forbidden),
        &make_api_call(None)
    ));
}
