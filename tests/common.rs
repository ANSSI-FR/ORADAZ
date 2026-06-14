use oradaz::utils::config::Config;
use oradaz::utils::stats::Stats;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Substitue les placeholders dynamiques dans le contenu d'une fixture.
///
/// Pour l'instant, seul `{{ORADAZ_VERSION}}` est géré : il est remplacé par
/// `oradaz::VERSION` pour que les fixtures restent compatibles quand la
/// constante de version évolue. Ajoute d'autres remplacements ici si besoin.
fn substitute_placeholders(content: &str) -> String {
    content.replace("{{ORADAZ_VERSION}}", oradaz::VERSION)
}

/// Lit une fixture sur disque et applique les substitutions de placeholders.
#[allow(dead_code)]
pub fn load_fixture(relative_path: impl AsRef<Path>) -> String {
    let path = relative_path.as_ref();
    let content = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read fixture {}: {e}", path.display()));
    substitute_placeholders(&content)
}

/// Lit une fixture, applique les substitutions, écrit le résultat dans
/// `dest_dir` et renvoie le chemin obtenu — utile pour les tests qui
/// passent la fixture via `config.schema_file` (que `Schema::new` ouvre
/// elle-même, sans passer par notre helper).
#[allow(dead_code)]
pub fn materialize_fixture(relative_path: impl AsRef<Path>, dest_dir: &Path) -> PathBuf {
    let path = relative_path.as_ref();
    let file_name = path
        .file_name()
        .unwrap_or_else(|| panic!("fixture path has no file name: {}", path.display()));
    let dest = dest_dir.join(file_name);
    fs::write(&dest, load_fixture(path)).unwrap_or_else(|e| {
        panic!(
            "Failed to write materialized fixture {}: {e}",
            dest.display()
        )
    });
    dest
}

/// Retourne un `Arc<Stats>` neuf pour les tests qui construisent un
/// `ConditionChecker`, un `ResponseContext` ou un `Dumper` à la main.
#[allow(dead_code)]
pub fn default_test_stats() -> Arc<Stats> {
    Arc::new(Stats::new())
}

/// Retourne une configuration minimale valide pour les tests unitaires.
#[allow(dead_code)]
pub fn default_test_config() -> Config {
    Config {
        tenant: "test-tenant".to_string(),
        app_id: "test-app-id".to_string(),
        services: None,
        proxy: None,
        output_files: Some(false),
        output_mla: Some(true),
        output: None,
        no_check: None,
        use_device_code: None,
        listener_address: None,
        listener_port: None,
        schema_file: None,
        schema_url_override: None,
        user_agent: None,
        trace_logs: None,
        use_application_credentials: None,
        application_credentials: None,
        concurrency_min_window: None,
        concurrency_max_window: None,
        dispatch_burst_cap: None,
        http_timeout_seconds: None,
        url_retry_limit: None,
        rate_limit_retry_limit: None,
        rate_limit_max_wait_secs: None,
        stall_detection_timeout: None,
        http_connect_timeout_seconds: None,
        retry_backoff_base_ms: None,
        retry_backoff_cap_ms: None,
        prereq_recheck_cache_secs: None,
        liveness_ceiling_secs: None,
        service_overrides: None,
        default_retry_after_seconds: Some(30),
        emergency_accounts_custom_attributes: None,
        additional_mla_keys: None,
        logs_days_filter: None,
        shuffle_urls: None,
        concurrency_slow_start: None,
        response_workers_max: None,
        response_memory_budget_bytes: None,
        expected_error_breaker_threshold: None,
    }
}
