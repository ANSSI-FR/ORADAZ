/// Metadata written to `metadata.json` at the end of a successful dump.
use crate::FL;
use crate::collect::dump::Dumper;
use crate::utils::config::Config;
use crate::utils::errors::Error;
use crate::utils::writer::actor::WriterHandle;

use log::{debug, error};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ServiceCollectionStatus {
    Enabled,
    DisabledByConfig,
    DisabledByPrerequisiteFailure,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TableMetadata {
    pub name: String,
    pub folder: String,
    pub file: String,
    pub count: usize,
    /// Total uncompressed JSON bytes written for this table (sum of all pages).
    /// Pairs with `count` for data-volume analysis: heavy tables are `$select`
    /// candidates, and the total feeds the writer-saturation correlation (§3.8).
    #[serde(default)]
    pub bytes: usize,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TokenMetadata {
    pub name: String,
    pub user_id: String,
    pub user_principal_name: String,
    pub client_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct Metadata {
    tenant: String,
    collection_date: String,
    oradaz_version: String,
    schema_version: String,
    schema_hash: String,
    /// Wall-clock seconds spent in the dump phase only (API collection),
    /// excluding auth, prerequisite checks, and packaging. See
    /// `total_duration_secs` for the end-to-end runtime.
    dump_duration_secs: i64,
    /// Wall-clock seconds for the whole run, from process start to packaging
    /// (auth + prerequisites + dump + packaging).
    #[serde(default)]
    total_duration_secs: i64,
    database: String,
    services: HashMap<String, ServiceCollectionStatus>,
    tokens: Vec<TokenMetadata>,
    tables: Vec<TableMetadata>,
    /// Total number of error entries written to `errors.json` during the dump.
    /// Includes both HTTP errors (4xx/5xx, expected or not) and non-HTTP
    /// entries (nextLink parsing, retry-budget exhaustion, missing-token, etc.).
    /// As a result, `errors >= expected_errors + unexpected_errors`; the
    /// difference is the count of non-HTTP entries.
    errors: usize,
    /// HTTP errors (status ≥ 400 except 429) whose status/code matched a
    /// declared `expected_error_codes` entry. Benign: PIM probes on
    /// non-role-assignable groups, 404 on optional sub-resources, etc.
    /// Sourced from `Stats::record_response` per-API counters.
    #[serde(default)]
    expected_errors: usize,
    /// HTTP errors (status ≥ 400 except 429) that did NOT match an
    /// `expected_error_codes` entry. These are the entries actually worth
    /// investigating. Sourced from `Stats::record_response` per-API counters.
    #[serde(default)]
    unexpected_errors: usize,
    auth_errors: usize,
    prerequisites_errors: usize,
    /// Peak process RSS (bytes) observed during the dump, or 0 when unavailable
    /// (unsupported platform / query failure). Ground-truth memory figure for
    /// diagnosing large-tenant runs after the fact. See `utils::sysmem`.
    #[serde(default)]
    peak_rss_bytes: u64,
    /// Peak total `current_urls` length (URL pool) observed during the dump — the
    /// direct in-process signal for pool growth. See `utils::sysmem`.
    #[serde(default)]
    peak_pool_len: u64,
    /// Peak writer-channel message saturation (0–100 %) observed during the dump.
    /// With the byte-budget figures below, the signal for MLA single-core write
    /// saturation. See `utils::writer::actor`.
    #[serde(default)]
    peak_writer_queue_pct: u64,
    /// Peak bytes queued-or-in-flight against the writer byte budget (≤ 256 MiB).
    /// Approaching the budget means producers blocked in `write_file`.
    #[serde(default)]
    peak_writer_inflight_bytes: u64,
    /// Total seconds producers spent blocked on the writer byte budget — the
    /// *direct* evidence that single-core MLA compression was the bottleneck
    /// (0 = the writer kept up). See `utils::writer::actor`.
    #[serde(default)]
    writer_budget_blocked_secs: u64,
    /// Number of `write_file` calls that stalled on the writer byte budget; pairs
    /// with `writer_budget_blocked_secs` (one long stall vs many short).
    #[serde(default)]
    writer_budget_blocked_count: u64,
    /// Peak simultaneous request slots parked in a retry/cooldown backoff — the
    /// throttling-severity signal. See `collect::dump::request::BACKOFF_ACTIVE`.
    #[serde(default)]
    peak_backoff_active: u64,
    /// Per-service AIMD floor: the lowest concurrency window each service was
    /// reduced to via 429 halving. See `collect::dump::concurrency`.
    #[serde(default)]
    min_window_by_service: BTreeMap<String, usize>,
    /// Per-service count of effective AIMD halvings (congestion events that
    /// reduced the window). With `min_window_by_service`, characterises whether
    /// the window collapsed repeatedly ("en rafale") versus dipped once.
    #[serde(default)]
    window_decreases_by_service: BTreeMap<String, u64>,
    /// Per-service count of effective AIMD additive increases — the **symmetric**
    /// companion to `window_decreases_by_service`. increases ≈ decreases ⇒ the
    /// window recovered after each collapse; decreases ≫ increases ⇒ it stayed
    /// hammered down. Verifies the cooldown-order fix let the window re-ramp, and
    /// feeds the per-bucket re-key (B) decision. From `collect::dump::concurrency`.
    #[serde(default)]
    window_increases_by_service: BTreeMap<String, u64>,
    /// Per-service whole seconds the AIMD window spent collapsed at its floor
    /// (`min_window`). The **duration** of collapse: a window pinned at the floor
    /// for minutes (the run_001 pathology) is invisible in the halving *count*
    /// alone — this is the direct measure of the B-trigger symptom ("fast
    /// endpoints stuck at the floor during convergence"). From
    /// `collect::dump::concurrency`.
    #[serde(default)]
    time_at_floor_secs_by_service: BTreeMap<String, u64>,
    /// Total uncompressed JSON bytes written across all tables (Σ `tables[].bytes`).
    /// The data-volume figure: byte throughput (`/ dump_duration_secs`) and the
    /// writer-saturation correlation (§3.8) read from here.
    #[serde(default)]
    total_bytes_written: u64,
    /// Per-service count of "parked at the AIMD ceiling" events — request workers
    /// that blocked because demand exceeded the *maximum allowed* concurrency
    /// (`current >= max_window`), not because the window was reduced by 429. The
    /// direct signal that `concurrencyMaxWindow` is the binding constraint: high
    /// here + low `retries_rate_limit` ⇒ raising the cap is safe (M1).
    #[serde(default)]
    slot_wait_events_by_service: BTreeMap<String, u64>,
    /// Per-service whole seconds spent parked at the ceiling (magnitude companion
    /// to `slot_wait_events_by_service`).
    #[serde(default)]
    slot_wait_secs_by_service: BTreeMap<String, u64>,
    /// Per-service wall-clock seconds spent under an **active** 429 cooldown,
    /// measured on a **single coalesced timeline** (union of the cooldown
    /// windows, not summed per-429). Compared against the per-API
    /// *intended* cooldown sum (`stats.json` `rate_limit_wait_secs`, which adds
    /// every 429's Retry-After), the intended/active ratio measures how many
    /// concurrent 429s piled onto the same window — i.e. how much the cooldown
    /// is bypassed under concurrency (the request-thread orders the cooldown
    /// wait before the concurrency slot, so a parked worker reads a stale
    /// `next_allowed_request`). Thousands ⇒ bypassed; the honored floor is the
    /// in-flight concurrency at window-open (≈ the AIMD window), i.e.
    /// single-digit, not 1. See `collect::dump::ratelimit`.
    #[serde(default)]
    cooldown_active_secs_by_service: BTreeMap<String, u64>,
    /// Wall-clock seconds from process start to the start of the dump phase
    /// (authentication + prerequisite checks + initial URL build). Explains the
    /// `total_duration_secs − dump_duration_secs` delta (§3.1).
    #[serde(default)]
    auth_prereq_secs: i64,
    /// Available CPU parallelism observed at packaging time (`0` when unavailable).
    /// Context for the single-core MLA writer: "N cores available, one used for
    /// compression" sizes the cost of moving compression off the tokio runtime (§3.8).
    #[serde(default)]
    num_cpus: u64,
}

impl Metadata {
    /// Creates a new `Metadata` instance by aggregating data from the dumper and configuration.
    pub fn new(
        dumper: &Dumper,
        config: &Config,
        collection_date: String,
        database: String,
        dump_duration_secs: i64,
        total_duration_secs: i64,
        auth_prereq_secs: i64,
    ) -> Metadata {
        let mut services: HashMap<String, ServiceCollectionStatus> = HashMap::new();
        for service in &dumper.schema.services {
            let is_config_enabled =
                service.mandatory_auth || Config::service_enable(config, &service.name);
            let status = if !is_config_enabled {
                ServiceCollectionStatus::DisabledByConfig
            } else if dumper.tokens.contains_key(service.name.as_str()) {
                ServiceCollectionStatus::Enabled
            } else {
                ServiceCollectionStatus::DisabledByPrerequisiteFailure
            };
            services.insert(service.name.clone(), status);
        }
        // Sum per-API expected/unexpected error counts from the stats actor.
        // `Stats::record_response` distinguishes them based on the schema's
        // `expected_error_codes`, so this gives a faithful split independent of
        // the `errors_number` counter (which counts expected and unexpected errors together).
        let mut expected_errors: usize = 0;
        let mut unexpected_errors: usize = 0;
        for entry in dumper.stats.apis.iter() {
            let api = entry.value();
            expected_errors += api
                .expected_errors
                .load(std::sync::atomic::Ordering::Relaxed);
            unexpected_errors += api
                .unexpected_errors
                .load(std::sync::atomic::Ordering::Relaxed);
        }
        Metadata {
            tenant: dumper.tenant.clone(),
            collection_date,
            oradaz_version: dumper.schema.oradaz_version.clone(),
            schema_version: dumper.schema.schema_version.clone(),
            schema_hash: dumper.schema.schema_hash.clone(),
            dump_duration_secs,
            total_duration_secs,
            database,
            services,
            tokens: dumper.tokens_metadata.clone(),
            tables: dumper.tables_metadata.clone(),
            errors: dumper.errors_number,
            expected_errors,
            unexpected_errors,
            auth_errors: dumper.auth_errors_number,
            prerequisites_errors: dumper.prerequisites_errors_number,
            peak_rss_bytes: crate::utils::sysmem::peak_rss_bytes(),
            peak_pool_len: crate::utils::sysmem::peak_pool_len(),
            peak_writer_queue_pct: crate::utils::writer::actor::peak_writer_queue_pct(),
            peak_writer_inflight_bytes: crate::utils::writer::actor::peak_writer_inflight_bytes(),
            writer_budget_blocked_secs: crate::utils::writer::actor::writer_budget_blocked_nanos()
                / 1_000_000_000,
            writer_budget_blocked_count: crate::utils::writer::actor::writer_budget_blocked_count(),
            peak_backoff_active: crate::collect::dump::request::peak_backoff_active(),
            min_window_by_service: dumper
                .concurrency_controller
                .get_all_min_windows()
                .into_iter()
                .collect(),
            window_decreases_by_service: dumper
                .concurrency_controller
                .get_all_decreases()
                .into_iter()
                .collect(),
            window_increases_by_service: dumper
                .concurrency_controller
                .get_all_increases()
                .into_iter()
                .collect(),
            time_at_floor_secs_by_service: dumper
                .concurrency_controller
                .get_all_time_at_floor_secs()
                .into_iter()
                .collect(),
            total_bytes_written: dumper.tables_metadata.iter().map(|t| t.bytes as u64).sum(),
            slot_wait_events_by_service: dumper
                .concurrency_controller
                .get_all_slot_wait_events()
                .into_iter()
                .collect(),
            slot_wait_secs_by_service: dumper
                .concurrency_controller
                .get_all_slot_wait_secs()
                .into_iter()
                .collect(),
            cooldown_active_secs_by_service: dumper
                .ratelimit_manager
                .get_all_cooldown_active_secs()
                .into_iter()
                .collect(),
            auth_prereq_secs,
            num_cpus: std::thread::available_parallelism()
                .map(|n| n.get() as u64)
                .unwrap_or(0),
        }
    }

    /// Serializes the metadata to JSON and writes it to the `metadata.json` file in the archive.
    pub async fn write(&self, writer: &WriterHandle) -> Result<(), Error> {
        let metadata_str = match serde_json::to_string(&self) {
            Err(err) => {
                error!("{:FL$}Could not convert metadata to json", "Metadata");
                debug!("{:FL$}Metadata serialization error: {err:?}", "Metadata");
                return Err(Error::MetadataToJSON);
            }
            Ok(j) => j,
        };
        writer
            .write_file(String::new(), "metadata.json".to_string(), metadata_str)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    /// Collection durations spanning midnight must be positive: `DateTime<Utc>`
    /// subtraction produces the correct elapsed seconds, whereas `NaiveTime`
    /// subtraction wraps at 00:00 and would yield a large negative value.
    #[test]
    fn test_duration_diff_across_midnight_is_positive() {
        let start = Utc.with_ymd_and_hms(2026, 5, 27, 23, 59, 50).unwrap();
        let end = Utc.with_ymd_and_hms(2026, 5, 28, 0, 0, 20).unwrap();
        let secs = (end - start).num_seconds();
        assert_eq!(secs, 30, "DateTime diff must span midnight correctly");

        // NaiveTime wraps at midnight: verify the invariant holds.
        let naive_secs = (end.time() - start.time()).num_seconds();
        assert!(naive_secs < 0, "NaiveTime wraps at midnight as expected");
    }

    #[test]
    fn test_table_metadata_creation() {
        let table = TableMetadata {
            name: "applications".to_string(),
            folder: "graph".to_string(),
            file: "applications.json".to_string(),
            count: 42,
            bytes: 4096,
        };
        assert_eq!(table.name, "applications");
        assert_eq!(table.folder, "graph");
        assert_eq!(table.file, "applications.json");
        assert_eq!(table.count, 42);
        assert_eq!(table.bytes, 4096);
    }

    #[test]
    fn test_token_metadata_creation() {
        let token = TokenMetadata {
            name: "graph".to_string(),
            user_id: "user-id-123".to_string(),
            user_principal_name: "user@example.com".to_string(),
            client_id: "client-id-456".to_string(),
        };
        assert_eq!(token.name, "graph");
        assert_eq!(token.user_id, "user-id-123");
        assert_eq!(token.user_principal_name, "user@example.com");
        assert_eq!(token.client_id, "client-id-456");
    }

    #[test]
    fn test_metadata_serialization_deserialize() {
        let metadata = Metadata {
            tenant: "test-tenant".to_string(),
            collection_date: "2026-04-13".to_string(),
            oradaz_version: "3.0.0".to_string(),
            schema_version: "1.0.0".to_string(),
            schema_hash: "abc123".to_string(),
            dump_duration_secs: 1200,
            total_duration_secs: 1260,
            database: "test-db".to_string(),
            services: HashMap::new(),
            tokens: vec![],
            tables: vec![],
            errors: 5,
            expected_errors: 3,
            unexpected_errors: 2,
            auth_errors: 2,
            prerequisites_errors: 1,
            peak_rss_bytes: 0,
            peak_pool_len: 0,
            peak_writer_queue_pct: 0,
            peak_writer_inflight_bytes: 0,
            writer_budget_blocked_secs: 0,
            writer_budget_blocked_count: 0,
            peak_backoff_active: 0,
            min_window_by_service: BTreeMap::new(),
            window_decreases_by_service: BTreeMap::new(),
            window_increases_by_service: BTreeMap::new(),
            time_at_floor_secs_by_service: BTreeMap::new(),
            total_bytes_written: 0,
            slot_wait_events_by_service: BTreeMap::new(),
            slot_wait_secs_by_service: BTreeMap::new(),
            cooldown_active_secs_by_service: BTreeMap::new(),
            auth_prereq_secs: 0,
            num_cpus: 0,
        };

        let json_str = serde_json::to_string(&metadata).expect("Failed to serialize");
        assert!(json_str.contains("test-tenant"));
        assert!(json_str.contains("3.0.0"));
        assert!(json_str.contains("1200"));
        // The memory-observability fields are part of the metadata schema.
        assert!(json_str.contains("peak_rss_bytes"));
        assert!(json_str.contains("peak_pool_len"));
    }

    #[test]
    fn test_service_collection_status_serialization() {
        let mut services: HashMap<String, ServiceCollectionStatus> = HashMap::new();
        services.insert("graph".to_string(), ServiceCollectionStatus::Enabled);
        services.insert(
            "exchange".to_string(),
            ServiceCollectionStatus::DisabledByConfig,
        );
        services.insert(
            "resources".to_string(),
            ServiceCollectionStatus::DisabledByPrerequisiteFailure,
        );

        let json_str = serde_json::to_string(&services).expect("Failed to serialize");
        assert!(json_str.contains("\"enabled\""));
        assert!(json_str.contains("\"disabled_by_config\""));
        assert!(json_str.contains("\"disabled_by_prerequisite_failure\""));

        let deserialized: HashMap<String, ServiceCollectionStatus> =
            serde_json::from_str(&json_str).expect("Failed to deserialize");
        assert_eq!(
            deserialized.get("graph"),
            Some(&ServiceCollectionStatus::Enabled)
        );
        assert_eq!(
            deserialized.get("exchange"),
            Some(&ServiceCollectionStatus::DisabledByConfig)
        );
        assert_eq!(
            deserialized.get("resources"),
            Some(&ServiceCollectionStatus::DisabledByPrerequisiteFailure)
        );
    }

    #[test]
    fn test_metadata_with_multiple_tokens() {
        let tokens: Vec<TokenMetadata> = vec![
            TokenMetadata {
                name: "graph".to_string(),
                user_id: "user1".to_string(),
                user_principal_name: "user1@example.com".to_string(),
                client_id: "client1".to_string(),
            },
            TokenMetadata {
                name: "exchange".to_string(),
                user_id: "user2".to_string(),
                user_principal_name: "user2@example.com".to_string(),
                client_id: "client2".to_string(),
            },
        ];

        let metadata = Metadata {
            tenant: "test".to_string(),
            collection_date: "2026-04-13".to_string(),
            oradaz_version: "3.0.0".to_string(),
            schema_version: "1.0.0".to_string(),
            schema_hash: "def456".to_string(),
            dump_duration_secs: 5000,
            total_duration_secs: 5100,
            database: "test-db".to_string(),
            services: HashMap::new(),
            tokens,
            tables: vec![],
            errors: 0,
            expected_errors: 0,
            unexpected_errors: 0,
            auth_errors: 0,
            prerequisites_errors: 0,
            peak_rss_bytes: 0,
            peak_pool_len: 0,
            peak_writer_queue_pct: 0,
            peak_writer_inflight_bytes: 0,
            writer_budget_blocked_secs: 0,
            writer_budget_blocked_count: 0,
            peak_backoff_active: 0,
            min_window_by_service: BTreeMap::new(),
            window_decreases_by_service: BTreeMap::new(),
            window_increases_by_service: BTreeMap::new(),
            time_at_floor_secs_by_service: BTreeMap::new(),
            total_bytes_written: 0,
            slot_wait_events_by_service: BTreeMap::new(),
            slot_wait_secs_by_service: BTreeMap::new(),
            cooldown_active_secs_by_service: BTreeMap::new(),
            auth_prereq_secs: 0,
            num_cpus: 0,
        };

        assert_eq!(metadata.tokens.len(), 2);
        assert_eq!(metadata.tokens[0].name, "graph");
        assert_eq!(metadata.tokens[1].name, "exchange");
    }

    #[test]
    fn test_metadata_with_error_counters() {
        let metadata = Metadata {
            tenant: "test".to_string(),
            collection_date: "2026-04-13".to_string(),
            oradaz_version: "3.0.0".to_string(),
            schema_version: "1.0.0".to_string(),
            schema_hash: "ghi789".to_string(),
            dump_duration_secs: 3600,
            total_duration_secs: 3700,
            database: "test-db".to_string(),
            services: HashMap::new(),
            tokens: vec![],
            tables: vec![],
            errors: 10,
            expected_errors: 4,
            unexpected_errors: 6,
            auth_errors: 3,
            prerequisites_errors: 2,
            peak_rss_bytes: 0,
            peak_pool_len: 0,
            peak_writer_queue_pct: 0,
            peak_writer_inflight_bytes: 0,
            writer_budget_blocked_secs: 0,
            writer_budget_blocked_count: 0,
            peak_backoff_active: 0,
            min_window_by_service: BTreeMap::new(),
            window_decreases_by_service: BTreeMap::new(),
            window_increases_by_service: BTreeMap::new(),
            time_at_floor_secs_by_service: BTreeMap::new(),
            total_bytes_written: 0,
            slot_wait_events_by_service: BTreeMap::new(),
            slot_wait_secs_by_service: BTreeMap::new(),
            cooldown_active_secs_by_service: BTreeMap::new(),
            auth_prereq_secs: 0,
            num_cpus: 0,
        };

        assert_eq!(metadata.errors, 10);
        assert_eq!(metadata.expected_errors, 4);
        assert_eq!(metadata.unexpected_errors, 6);
        assert_eq!(metadata.auth_errors, 3);
        assert_eq!(metadata.prerequisites_errors, 2);
    }
}
