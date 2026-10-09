mod common;

use common::default_test_config;
use dashmap::DashMap;
use oradaz::collect::auth::tokens::{Token, TokenState};
use oradaz::collect::dump::Dumper;
use oradaz::utils::client::OradazClient;
use oradaz::utils::writer::actor::spawn_writer_task;
use serde_json::{Value, json};
use std::fs;
use std::sync::{Arc, atomic::AtomicBool};
use std::time::Duration;
use tempfile::TempDir;
use wiremock::matchers::{bearer_token, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn tenant_resolution_collects_mapping_and_failure_through_the_pipeline() {
    let run_name = "11111111-1111-4111-8111-111111111111_20261008-120000";
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1.0/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "@odata.nextLink": format!("{}/v1.0/users-next", server.uri()),
            "value": [
                {"id": "guest", "userType": "Guest", "identities": [{"issuer": "PARTNER.EXAMPLE"}]},
                {"id": "unresolved", "identities": [{"issuer": "missing.example"}]}
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1.0/users-next"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [
                {"id": "external-member", "userType": "Member", "identities": [{"issuer": "partner.example"}]},
                {"id": "google", "identities": [{"issuer": "google.com"}]}
            ]
        })))
        .expect(1)
        .mount(&server).await;
    Mock::given(method("GET"))
        .and(path("/v1.0/tenantRelationships/findTenantInformationByDomainName(domainName='partner.example')"))
        .and(bearer_token("synthetic-test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tenantId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "defaultDomainName": "partner.onmicrosoft.com",
            "displayName": "Partner", "federationBrandName": null
        })))
        .expect(1)
        .mount(&server).await;
    Mock::given(method("GET"))
        .and(path("/v1.0/tenantRelationships/findTenantInformationByDomainName(domainName='missing.example')"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": {"code": "Request_ResourceNotFound", "message": "No matching tenant"}
        })))
        .expect(1)
        .mount(&server).await;

    let dir = TempDir::new().unwrap();
    let schema_path = dir.path().join("schema.json");
    fs::write(
        &schema_path,
        json!({
            "oradaz_version": oradaz::VERSION, "schema_version": "test",
            "services": [{
                "name": "graph_mock", "scopes": [], "mandatory_auth": true,
                "url_scheme": format!("{}[URI]", server.uri()),
                "default_api_behavior": {},
                "apis": [{
                    "name": "users", "uri": "/v1.0/users",
                    "api_behavior": {"resolve_tenant_domains": "true"}
                }]
            }]
        })
        .to_string(),
    )
    .unwrap();
    let mut config = default_test_config();
    config.output_files = Some(true);
    config.output_mla = Some(true);
    config.no_check = Some(true);
    config.schema_file = Some(schema_path.to_str().unwrap().to_string());
    let (writer, _writer_task) = spawn_writer_task(
        config.clone(),
        dir.path().to_path_buf(),
        run_name.to_string(),
    )
    .await
    .unwrap();
    let tokens = Arc::new(DashMap::new());
    tokens.insert(
        Arc::from("graph_mock"),
        Arc::new(TokenState::new(Token {
            tenant_id: "test-tenant".to_string(),
            client_id: "test-client".to_string(),
            service: "graph_mock".to_string(),
            expires_on: chrono::Utc::now().timestamp() + 3600,
            access_token: "synthetic-test-token".to_string(),
            refresh_token: None,
            token_type: "Bearer".to_string(),
            user_id: "test-user".to_string(),
            user_principal_name: "test@example.com".to_string(),
            scopes: vec![],
        })),
    );
    let mut dumper = Dumper::new_with_tokens(
        "test-tenant",
        "test-client",
        &writer,
        &config,
        OradazClient::new(&config).unwrap(),
        tokens,
        0,
    )
    .await
    .unwrap();
    tokio::time::timeout(
        Duration::from_secs(30),
        dumper.dump(Arc::new(AtomicBool::new(false))),
    )
    .await
    .expect("collection must terminate")
    .unwrap();
    writer.finalize().await.unwrap();
    let run = dir.path().join(run_name);
    let mappings: Vec<Value> =
        fs::read_to_string(run.join("graph_mock/tenantInformationByDomainName.json"))
            .expect("the collector must write the tenant resolution table")
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
    assert_eq!(mappings.len(), 1);
    assert_eq!(
        mappings[0]["tenantId"],
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    );
    assert_eq!(
        mappings[0]["_ORADAZ_PARENT_"]["domainName"],
        "partner.example"
    );
    let errors: Vec<Value> = fs::read_to_string(run.join("errors.json"))
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0]["status"], 404);
    assert!(
        errors[0]["url"]
            .as_str()
            .unwrap()
            .contains("missing.example")
    );
    assert_eq!(
        fs::read_to_string(run.join("graph_mock/users.json"))
            .unwrap()
            .lines()
            .count(),
        4
    );
    let names: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        names.iter().any(|n| n.ends_with(".mla")),
        "the collection must finalize its archive"
    );
    assert!(
        !names
            .iter()
            .any(|n| n.ends_with(".mla.tmp") || n.ends_with(".mla.broken"))
    );
    server.verify().await;
}
