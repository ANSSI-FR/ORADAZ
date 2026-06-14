mod common;

use crate::common::{default_test_config, load_fixture};
use dashmap::DashMap;
use oradaz::collect::auth::tokens::Token;
use oradaz::collect::dump::Dumper;
use oradaz::utils::client::OradazClient;
use oradaz::utils::writer::actor::spawn_writer_task;
use serde_json::json;
use std::fs;
use std::sync::Arc;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_full_relationship_chain_collection() {
    // 1. Start Mock Server
    let server = MockServer::start().await;
    let server_url = server.uri();
    println!("Mock server started at: {}", server_url);

    // 2. Setup Mocks
    // Mock /v1.0/users
    Mock::given(method("GET"))
        .and(path("/v1.0/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [
                {"id": "u1", "managerId": "m1"}
            ]
        })))
        .mount(&server)
        .await;

    // Mock /v1.0/managers/m1
    Mock::given(method("GET"))
        .and(path("/v1.0/managers/m1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [
                {"id": "m1", "detailId": "d1"}
            ]
        })))
        .mount(&server)
        .await;

    // Mock /v1.0/managers/m1/details
    Mock::given(method("GET"))
        .and(path("/v1.0/managers/m1/details"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [
                {"id": "d1", "info": "some detail"}
            ]
        })))
        .mount(&server)
        .await;

    // 3. Setup Config and Environment
    let temp_dir = TempDir::new().unwrap();
    let mut config = default_test_config();
    config.output_files = Some(true);
    config.output_mla = Some(false);
    config.no_check = Some(true);

    // Create a temporary schema file to avoid mutating the fixture.
    // `load_fixture` substitutes `{{ORADAZ_VERSION}}` so the schema stays
    // valid when the crate version bumps; `{{SERVER_URL}}` is test-local.
    let schema_path = temp_dir.path().join("relationship_chain.json");
    let schema_content = load_fixture("tests/fixtures/schemas/relationship_chain.json");
    let updated_schema = schema_content.replace("{{SERVER_URL}}", &server_url);
    fs::write(&schema_path, updated_schema).unwrap();
    println!(
        "Schema written to {:?} with content: {}",
        schema_path,
        fs::read_to_string(&schema_path).unwrap()
    );
    config.schema_file = Some(schema_path.to_str().unwrap().to_string());

    let (writer, _writer_task) = spawn_writer_task(
        config.clone(),
        temp_dir.path().to_path_buf(),
        "test-run".to_string(),
    )
    .await
    .unwrap();

    let oradaz_client = OradazClient::new(&config).unwrap();

    // 4. Create Tokens
    let tokens = Arc::new(DashMap::new());
    let token = Token {
        tenant_id: "test-tenant".to_string(),
        client_id: "test-client".to_string(),
        service: "graph_mock".to_string(),
        expires_on: chrono::Utc::now().timestamp() + 3600,
        access_token: "test_token".to_string(),
        refresh_token: None,
        token_type: "Bearer".to_string(),
        user_id: "user-123".to_string(),
        user_principal_name: "user@example.com".to_string(),
        scopes: vec!["https://graph.microsoft.com/.default".to_string()],
    };
    tokens.insert(
        Arc::from("graph_mock"),
        Arc::new(oradaz::collect::auth::tokens::state::TokenState::new(token)),
    );

    // 5. Run Dumper
    let mut dumper = Dumper::new_with_tokens(
        "test-tenant",
        "test-app-id",
        &writer,
        &config,
        oradaz_client,
        tokens,
        0,
    )
    .await
    .expect("Failed to create dumper");

    dumper
        .dump(std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
            false,
        )))
        .await
        .expect("Dump failed");

    // 6. Verify Results
    // Check if files were created in the temp directory
    let output_path = temp_dir.path().join("test-run/graph_mock");
    if !output_path.exists() {
        println!(
            "Temp dir contents: {:?}",
            fs::read_dir(temp_dir.path()).unwrap().collect::<Vec<_>>()
        );
        if let Ok(run_dir) = fs::read_dir(temp_dir.path().join("test-run")) {
            println!("test-run contents: {:?}", run_dir.collect::<Vec<_>>());
        }
        let errors_file = temp_dir.path().join("test-run/errors.json");
        if errors_file.exists() {
            println!(
                "Errors file content:\n{}",
                fs::read_to_string(errors_file).unwrap()
            );
        }
        let log_file = temp_dir.path().join("test-run/oradaz.log");
        if log_file.exists() {
            println!(
                "Log file content:\n{}",
                fs::read_to_string(log_file).unwrap()
            );
        }
    }
    assert!(
        output_path.exists(),
        "Output directory for graph_mock should exist"
    );

    let users_file = output_path.join("users.json");
    let managers_file = output_path.join("users_manager.json");
    let details_file = output_path.join("users_manager_details.json");

    assert!(users_file.exists(), "users.json should have been collected");
    assert!(
        managers_file.exists(),
        "managers.json should have been collected"
    );
    assert!(
        details_file.exists(),
        "manager_details.json should have been collected"
    );

    let users_content = fs::read_to_string(users_file).unwrap();
    assert!(users_content.contains("u1"));

    let managers_content = fs::read_to_string(managers_file).unwrap();
    assert!(managers_content.contains("m1"));

    let details_content = fs::read_to_string(details_file).unwrap();
    assert!(details_content.contains("d1"));
}
