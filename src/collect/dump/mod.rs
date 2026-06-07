/// Main module for the dump.
///
/// Acts as the entry point for the data collection process. Owns the `Dumper`
/// struct, handles authentication, prerequisite checks, and delegates to the
/// three-actor pipeline (coordinator, request module, response module).
pub mod concurrency;
pub mod conditions;
pub mod orchestration;
pub mod ratelimit;
pub mod request;
pub mod response;

use crate::collect::auth::AuthError;
use crate::collect::auth::tokens::{SharedTokenState, Tokens};
use crate::collect::dump::concurrency::ConcurrencyController;
use crate::collect::dump::conditions::ConditionChecker;
use crate::collect::dump::orchestration::dump::dump as process_dump;
use crate::collect::dump::ratelimit::RateLimitManager;
use crate::collect::prerequisites::Prerequisites;
use crate::collect::prerequisites::PrerequisitesMetadata;
use crate::utils::client::OradazClient;
use crate::utils::config::Config;
use crate::utils::errors::Error;
use crate::utils::errors::FatalPresentation;
use crate::utils::metadata::{TableMetadata, TokenMetadata};
use crate::utils::schema::Schema;
use crate::utils::stats::Stats;
use crate::utils::ui::{self, Icon, icon};
use crate::utils::url::Url;
use crate::utils::writer::actor::WriterHandle;
use crate::{FL, bail_fatal};

use chrono::Utc;
use dashmap::DashMap;
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

/// An abstraction over interactive user input, enabling test injection.
pub trait InteractivePrompt: Send + Sync {
    fn read_line(&self) -> Pin<Box<dyn Future<Output = io::Result<String>> + Send + '_>>;
}

/// Default implementation that reads from stdin.
pub struct StdinPrompt;

impl InteractivePrompt for StdinPrompt {
    fn read_line(&self) -> Pin<Box<dyn Future<Output = io::Result<String>> + Send + '_>> {
        Box::pin(async {
            use tokio::io::AsyncBufReadExt;
            let mut reader = tokio::io::BufReader::new(tokio::io::stdin());
            let mut line = String::new();
            reader.read_line(&mut line).await?;
            Ok(line)
        })
    }
}

pub struct Dumper {
    pub tenant: String,
    pub app_id: String,
    pub oradaz_client: OradazClient,
    pub config: Config,
    pub verbosity: u8,
    pub schema: Schema,
    pub writer: WriterHandle,
    pub tokens: Arc<DashMap<Arc<str>, SharedTokenState>>,
    pub tokens_metadata: Vec<TokenMetadata>,
    pub condition_checker: Arc<ConditionChecker>,
    pub ratelimit_manager: Arc<RateLimitManager>,
    pub concurrency_controller: Arc<ConcurrencyController>,
    pub current_counter: Arc<AtomicUsize>,
    pub current_urls: Arc<DashMap<Arc<str>, Vec<Url>>>,
    pub tables_metadata: Vec<TableMetadata>,
    pub requests_number: usize,
    pub errors_number: usize,
    pub auth_errors_number: usize,
    pub prerequisites_errors_number: usize,
    pub missing_token_errors_number: usize,
    pub apis_disabled_by_conditions: usize,
    pub prompt: Arc<dyn InteractivePrompt>,
    pub stats: Arc<Stats>,
    /// Azure subscription IDs collected during the resources prereq check.
    /// Used to populate the `subscriptions` body of Azure Resource Graph
    /// requests. Empty when `noCheck=true` or the resources service is
    /// disabled.
    pub subscription_ids: Vec<String>,
    /// Pre-computed ` and createdDateTime ge <cutoff>` clause used to substitute
    /// the optional `[SIGNIN_FILTER]` marker. When a schema's per-user `signIns`
    /// relationship URI carries that marker, the clause is spliced in at response
    /// time so sign-ins stay bounded to the configured `logsDaysFilter` window
    /// (the bundled schema does not, so it is a no-op there). `None` when date
    /// bounding is disabled (`logsDaysFilter == 0`).
    pub logs_date_filter_and: Option<Arc<str>>,
}

/// Injects the Azure Resource Graph POST body on every `is_arg` URL of the
/// `resources` bucket using the subscription IDs collected during the prereq
/// check. When `subscription_ids` is empty, the ARG URLs are removed from the
/// dispatch pool and a warning is emitted — POST-ing an empty `subscriptions`
/// array would be rejected by ARG and consume the retry budget for no gain.
pub fn inject_arg_post_body(
    current_urls: &Arc<DashMap<Arc<str>, Vec<Url>>>,
    subscription_ids: &[String],
) {
    let Some(mut res_urls) = current_urls.get_mut::<Arc<str>>(&Arc::from("resources")) else {
        return;
    };
    if subscription_ids.is_empty() {
        let before = res_urls.len();
        res_urls.retain(|url| {
            !url.api_behavior
                .get("is_arg")
                .map(|v| v == "true")
                .unwrap_or(false)
        });
        let removed = before - res_urls.len();
        if removed > 0 {
            warn!(
                "{:FL$}Skipping {} Azure Resource Graph URL(s): no subscription IDs available (noCheck=true or resources prerequisites skipped)",
                "Dumper", removed
            );
        }
        return;
    }
    let mut injected = 0usize;
    for url in res_urls.iter_mut() {
        if !url
            .api_behavior
            .get("is_arg")
            .map(|v| v == "true")
            .unwrap_or(false)
        {
            continue;
        }
        let query = url
            .api_behavior
            .get("arg_query")
            .cloned()
            .unwrap_or_else(|| "Resources".to_string());
        let mut body = serde_json::json!({
            "query": query,
            "subscriptions": subscription_ids,
        });
        // Optional page-size bound: when the schema sets `arg_top`, pass it as
        // `options.$top` so Azure Resource Graph caps each page (oradaz then makes
        // fewer paginated requests against the tenant). ARG reads the option from
        // `options` — the same object `build_arg_next_url` writes `$skipToken` into
        // on subsequent pages, so the bound is preserved across the whole query.
        if let Some(top) = url.api_behavior.get("arg_top")
            && let Ok(top) = top.parse::<u64>()
        {
            body["options"]["$top"] = serde_json::json!(top);
        }
        url.post_body = Some(body);
        injected += 1;
    }
    if injected > 0 {
        debug!(
            "{:FL$}Injected ARG post_body on {} URL(s) ({} subscription ID(s))",
            "Dumper",
            injected,
            subscription_ids.len()
        );
    }
}

/// Computes the audit-log date-filter substitution strings from the configured
/// `logsDaysFilter`, returning `(directory_audits_clause, signins_and_clause)`.
///
/// Both clauses bound audit/sign-in queries to the last `logsDaysFilter` days so
/// the collection does not pull the entire tenant history. They differ only in
/// how they join the surrounding query, because the two endpoints already carry
/// different query strings in the schema:
/// - `[LOGS_DAYS_FILTER]`     → `&$filter=activityDateTime ge <cutoff>`, appended
///   after the `?$top=999` already present on `directoryAudits`.
/// - `[SIGNIN_FILTER]` → ` and createdDateTime ge <cutoff>`, merged into
///   the existing `$filter=userId eq '…'` of the per-user `signIns` relationship.
///
/// Both are `None` when `logsDaysFilter == 0` (date bounding disabled), in which
/// case the placeholders collapse to empty strings.
pub fn audit_logs_date_filters(config: &Config) -> (Option<String>, Option<String>) {
    let logs_days_filter = Config::logs_days_filter(config);
    if logs_days_filter == 0 {
        return (None, None);
    }
    let cutoff = Utc::now() - chrono::Duration::days(logs_days_filter as i64);
    let cutoff = cutoff.format("%Y-%m-%dT%H:%M:%SZ");
    (
        Some(format!("&$filter=activityDateTime ge {cutoff}")),
        Some(format!(" and createdDateTime ge {cutoff}")),
    )
}

/// Decides whether a failed token-refresh attempt should be retried.
///
/// Interactive flows (device-code / authorization-code) retry **without limit**
/// (`is_app_cred == false`): each attempt re-issues a fresh code/URL, giving the
/// operator unlimited time to re-authenticate. Application-credential flows have
/// no user to prompt, so they keep retrying a *transient* failure (a token-endpoint
/// network blip / 5xx / throttle) for up to `max_wait` of wall-clock — generous
/// enough to ride out a multi-minute outage of a service that is "down for a
/// while", so a long collection is not killed by a passing glitch — and then
/// abort. A *definitive* auth failure (a bad secret surfaced as `Reprocess(Some)`,
/// or a missing application permission) short-circuits before reaching this
/// decision, so it still fails fast.
pub fn should_retry_token_refresh(
    is_app_cred: bool,
    elapsed: std::time::Duration,
    max_wait: std::time::Duration,
) -> bool {
    !is_app_cred || elapsed < max_wait
}

/// Build the per-service-aware [`RateLimitManager`] and [`ConcurrencyController`]
/// for the current run.
///
/// Services explicitly listed under `<serviceOverrides>` in the XML config get
/// their own bounds; anything else falls back to the global `concurrency*Window`
/// and `defaultRetryAfterSeconds` values.
///
/// Service-specific baselines override the conservative global default (30):
/// - `graph` and `exchange`: max window of **150**. Graph tolerates high
///   concurrency and Exchange has no batch API (every mailbox is an individual
///   request), so both parallelise well above the ARM-tuned global default.
/// - `resources` (ARM): max window of **100**. Benchmark testing showed that
///   raising from 30 to 100 cuts throttling retries by ~99 % on tenants with
///   many subscriptions without exhausting ARM limits.
///
/// An explicit `<serviceOverrides>` entry for `concurrencyMaxWindow` always
/// takes precedence over these built-in baselines.
pub fn build_service_aware_throttling(
    config: &Config,
) -> (Arc<RateLimitManager>, Arc<ConcurrencyController>) {
    let mut concurrency_bounds: HashMap<String, (usize, usize)> = HashMap::new();
    let mut ratelimit_defaults: HashMap<String, u64> = HashMap::new();
    // Per-service cooldown caps (`rateLimitMaxWaitSecs`) used by the
    // `RateLimitManager` to clamp a single 429 cooldown — see `report_429`.
    let mut ratelimit_max_wait: HashMap<String, u64> = HashMap::new();
    if let Some(overrides) = &config.service_overrides {
        for ov in &overrides.services {
            // Resolve min/max for this service: use the override if present,
            // else fall back to the global. Store only when at least one bound
            // is overridden, to keep the bounds map minimal.
            if ov.concurrency_min_window.is_some() || ov.concurrency_max_window.is_some() {
                concurrency_bounds.insert(
                    ov.name.clone(),
                    (
                        Config::concurrency_min_window_for(config, &ov.name),
                        Config::concurrency_max_window_for(config, &ov.name),
                    ),
                );
            }
            if let Some(retry_after) = ov.default_retry_after_seconds {
                ratelimit_defaults.insert(ov.name.clone(), retry_after);
            }
            if let Some(max_wait) = ov.rate_limit_max_wait_secs {
                ratelimit_max_wait.insert(ov.name.clone(), max_wait);
            }
        }
    }

    // Hard-coded baseline for Microsoft Graph: a higher concurrency max window
    // than the conservative global default. Benchmark-validated at 150 concurrent
    // requests. An explicit serviceOverride for concurrencyMaxWindow on "graph"
    // still takes precedence.
    if Config::service_override(config, "graph")
        .and_then(|o| o.concurrency_max_window)
        .is_none()
    {
        let min = Config::concurrency_min_window_for(config, "graph");
        concurrency_bounds.insert(
            "graph".to_string(),
            (min, Config::GRAPH_MAX_WINDOW_BASELINE),
        );
    }

    // Hard-coded baseline for Exchange Online: higher concurrency max window.
    // Exchange has no batch API — each mailbox is an individual request — and
    // tolerates aggressive parallelism well. Benchmark-validated at 150. An
    // explicit serviceOverride for concurrencyMaxWindow on "exchange" still
    // takes precedence.
    if Config::service_override(config, "exchange")
        .and_then(|o| o.concurrency_max_window)
        .is_none()
    {
        let min = Config::concurrency_min_window_for(config, "exchange");
        concurrency_bounds.insert(
            "exchange".to_string(),
            (min, Config::EXCHANGE_MAX_WINDOW_BASELINE),
        );
    }

    // Hard-coded baseline for Azure Resource Manager (`resources`): benchmark
    // testing showed that raising the window from the conservative global
    // default (30) to 100 reduces ARM throttling retries by ~99% and cuts
    // collection time by ~70% on tenants with many subscriptions. An explicit
    // serviceOverride for concurrencyMaxWindow on "resources" still takes
    // precedence.
    if Config::service_override(config, "resources")
        .and_then(|o| o.concurrency_max_window)
        .is_none()
    {
        let min = Config::concurrency_min_window_for(config, "resources");
        concurrency_bounds.insert(
            "resources".to_string(),
            (min, Config::RESOURCES_MAX_WINDOW_BASELINE),
        );
    }

    let ratelimit_manager = Arc::new(RateLimitManager::with_per_service_defaults(
        Config::default_retry_after_seconds(config),
        ratelimit_defaults,
        Config::rate_limit_max_wait_secs(config),
        ratelimit_max_wait,
    ));
    let concurrency_controller = Arc::new(
        ConcurrencyController::with_service_bounds(
            Config::concurrency_min_window(config),
            Config::concurrency_max_window(config),
            concurrency_bounds,
        )
        .with_slow_start(Config::concurrency_slow_start(config)),
    );
    (ratelimit_manager, concurrency_controller)
}

impl Dumper {
    pub async fn new(
        tenant: &str,
        app_id: &str,
        writer: &WriterHandle,
        config: &Config,
        oradaz_client: OradazClient,
        verbosity: u8,
    ) -> Result<Self, Error> {
        // Parse schema file
        let schema: Schema = Schema::new(config, writer, &oradaz_client).await?;

        // Authenticate for the different services
        let tokens_dashmap = Arc::new(
            Tokens::initialize(config, &oradaz_client, tenant, app_id, &schema, writer).await?,
        );

        // Print the white "Authentication" label in Color mode right after auth completes.
        // Cursor sits at the top of the auth live region (teardown already ran inside the
        // auth flow), so this overwrites the former blue label in-place.
        let auth_label = if Config::use_application_credentials_auth(config) {
            "application credentials"
        } else if Config::force_device_code_auth(config) {
            "device code"
        } else {
            "authorization code"
        };
        println!("{}", icon(Icon::UpOrBottomBoldTable).repeat(71));
        println!(
            "  {} Authentication   ({})",
            ui::icon(ui::Icon::Selected),
            auth_label
        );

        // Check prerequisites
        let (prerequisites_errors_number, subscription_ids): (usize, Vec<String>) = match config
            .no_check
        {
            Some(true) => {
                info!(
                    "{:FL$}Skipping prerequisites checks due to config file option noCheck",
                    "Dumper"
                );
                (0, Vec::new())
            }
            _ => {
                // Wrapped in `Option` so the live region (with its spinner ticker
                // thread) can be torn down before printing a retry warning —
                // otherwise the ticker repaints over it within 500 ms and the
                // user has no visible feedback during the throttle sleep.
                let mut live: Option<ui::prereq::PrereqLive> =
                    Some(ui::prereq::PrereqLive::start());
                let mut retries = 0;
                const MAX_PREREQ_RETRIES: usize = 10;
                let (errors, items, sub_ids) = loop {
                    match Prerequisites::check_all(
                        writer,
                        &oradaz_client.client,
                        Arc::clone(&tokens_dashmap),
                        Config::use_application_credentials_auth(config),
                        Config::use_managed_identity_auth(config),
                        Config::default_retry_after_seconds(config),
                    )
                    .await
                    {
                        Ok(res) => break res,
                        Err((Error::TooManyRequestsDuringPrerequisites(sec), _)) => {
                            retries += 1;
                            if retries > MAX_PREREQ_RETRIES {
                                drop(live.take());
                                return Err(Error::StringError(format!(
                                    "Reached maximum retries ({}) for prerequisites check due to rate limiting",
                                    MAX_PREREQ_RETRIES
                                )));
                            }
                            // Tear down the spinner before the warn so it
                            // survives on screen, and respawn a fresh one
                            // after the sleep.
                            drop(live.take());
                            warn!(
                                "{:FL$}Too many requests during prerequisites check. Retrying in {} seconds... (Attempt {}/{})",
                                "Dumper", sec, retries, MAX_PREREQ_RETRIES
                            );
                            tokio::time::sleep(std::time::Duration::from_secs(sec)).await;
                            live = Some(ui::prereq::PrereqLive::start());
                        }
                        Err((err, partial_items)) => {
                            if let Some(mut l) = live.take() {
                                for item in partial_items.iter() {
                                    l.report(item.clone());
                                }
                                l.finalize(partial_items);
                            }
                            return Err(err);
                        }
                    }
                };
                if let Some(mut l) = live.take() {
                    for item in items.iter() {
                        l.report(item.clone());
                    }
                    l.finalize(items);
                }
                (errors, sub_ids)
            }
        };

        // Shared statistics collected throughout the dump and written to stats.json.
        let stats: Arc<Stats> = Arc::new(Stats::new());

        // Init condition checker
        let step = ui::StepLive::start("Conditions");
        let condition_checker: ConditionChecker =
            ConditionChecker::new(&oradaz_client, config, &tokens_dashmap, Arc::clone(&stats))
                .await?;
        step.finalize();
        let (ratelimit_manager, concurrency_controller) = build_service_aware_throttling(config);

        // Counter of in-flight requests still waiting for an answer.
        let current_counter = Arc::new(AtomicUsize::new(0));
        // A snapshot of the per-service tokens, keyed by service name.
        let mut tokens_map = HashMap::new();
        for r in tokens_dashmap.iter() {
            tokens_map.insert(r.key().clone(), r.value().token.read().await.clone());
        }
        let (date_filter_string, date_filter_and) = audit_logs_date_filters(config);
        debug!(
            "{:FL$}Audit logs date filters: directoryAudits={:?}, signIns={:?}",
            "Dumper", date_filter_string, date_filter_and
        );
        let logs_date_filter_and: Option<Arc<str>> = date_filter_and.map(Arc::from);
        let initial_urls: HashMap<String, Vec<Url>> = schema
            .get_urls(
                tenant.to_string(),
                &tokens_map,
                &condition_checker,
                date_filter_string.as_deref(),
                Config::shuffle_urls(config),
            )
            .await;
        let total_possible: usize = schema
            .services
            .iter()
            .filter(|s| tokens_map.contains_key(s.name.as_str()))
            .map(|s| s.apis.len())
            .sum();
        let initial_url_total: usize = initial_urls.values().map(|v| v.len()).sum();
        let apis_disabled_by_conditions = total_possible.saturating_sub(initial_url_total);
        if apis_disabled_by_conditions > 0 {
            info!(
                "{:FL$}{} API(s) disabled by tenant conditions out of {} possible",
                "Dumper", apis_disabled_by_conditions, total_possible
            );
        }
        let current_urls = Arc::new(DashMap::new());
        for (s, v) in initial_urls {
            current_urls.insert(Arc::from(s.as_str()), v);
        }
        for entry in current_urls.iter() {
            debug!(
                "{:FL$}Initial URL pool: service {:?} — {} URL(s)",
                "Dumper",
                entry.key(),
                entry.value().len()
            );
        }

        // Inject Azure Resource Graph `post_body` on `is_arg` URLs of the
        // resources service. When no subscription IDs are available (e.g.
        // `noCheck=true` skipped the resources prereq), drop the ARG URLs
        // rather than POST an invalid body — ARG requires a non-empty
        // `subscriptions` array.
        inject_arg_post_body(&current_urls, &subscription_ids);

        // Updating token metadata
        let mut tokens_metadata: Vec<TokenMetadata> = Vec::new();
        for r in tokens_dashmap.iter() {
            let name = r.key().to_string();
            let token = r.value().token.read().await;
            tokens_metadata.push(TokenMetadata {
                name,
                user_id: token.user_id.clone(),
                user_principal_name: token.user_principal_name.clone(),
                client_id: token.client_id.clone(),
            });
        }
        let tokens = Arc::clone(&tokens_dashmap);

        Ok(Self {
            tenant: tenant.to_string(),
            app_id: app_id.to_string(),
            oradaz_client,
            config: config.clone(),
            verbosity,
            schema,
            writer: writer.clone(),
            tokens,
            tokens_metadata,
            condition_checker: Arc::new(condition_checker),
            ratelimit_manager,
            concurrency_controller,
            current_counter,
            current_urls,
            tables_metadata: Vec::new(),
            requests_number: 0,
            errors_number: 0,
            auth_errors_number: 0,
            prerequisites_errors_number,
            missing_token_errors_number: 0,
            apis_disabled_by_conditions,
            prompt: Arc::new(StdinPrompt),
            stats,
            subscription_ids,
            logs_date_filter_and,
        })
    }

    /// Constructs a `Dumper` with pre-built tokens, skipping authentication.
    /// Intended for tests that need a fully initialised `Dumper` without OAuth2.
    pub async fn new_with_tokens(
        tenant: &str,
        app_id: &str,
        writer: &WriterHandle,
        config: &Config,
        oradaz_client: OradazClient,
        tokens: Arc<DashMap<Arc<str>, SharedTokenState>>,
        verbosity: u8,
    ) -> Result<Self, Error> {
        let schema = Schema::new(config, writer, &oradaz_client).await?;
        let stats: Arc<Stats> = Arc::new(Stats::new());

        let condition_checker =
            ConditionChecker::new(&oradaz_client, config, &tokens, Arc::clone(&stats))
                .await
                .unwrap_or_else(|_| ConditionChecker {
                    client: oradaz_client.clone(),
                    tenant_conditions: HashMap::new(),
                    user_conditions: DashMap::new(),
                    emergency_accounts_custom_attributes: config
                        .emergency_accounts_custom_attributes
                        .clone()
                        .unwrap_or(String::from("Emergency.isEmergency")),
                    org_url: "https://graph.microsoft.com/v1.0/organization".to_string(),
                    stats: Arc::clone(&stats),
                    is_application_auth: Config::use_application_credentials_auth(config),
                });

        let (ratelimit_manager, concurrency_controller) = build_service_aware_throttling(config);

        let current_counter = Arc::new(AtomicUsize::new(0));

        let mut tokens_map = HashMap::new();
        for r in tokens.iter() {
            tokens_map.insert(r.key().clone(), r.value().token.read().await.clone());
        }
        let (date_filter_string, date_filter_and) = audit_logs_date_filters(config);
        let logs_date_filter_and: Option<Arc<str>> = date_filter_and.map(Arc::from);
        let initial_urls = schema
            .get_urls(
                tenant.to_string(),
                &tokens_map,
                &condition_checker,
                date_filter_string.as_deref(),
                Config::shuffle_urls(config),
            )
            .await;
        let total_possible: usize = schema
            .services
            .iter()
            .filter(|s| tokens_map.contains_key(s.name.as_str()))
            .map(|s| s.apis.len())
            .sum();
        let initial_url_total: usize = initial_urls.values().map(|v| v.len()).sum();
        let apis_disabled_by_conditions = total_possible.saturating_sub(initial_url_total);
        if apis_disabled_by_conditions > 0 {
            info!(
                "{:FL$}{} API(s) disabled by tenant conditions out of {} possible",
                "Dumper", apis_disabled_by_conditions, total_possible
            );
        }
        let current_urls = Arc::new(DashMap::new());
        for (s, v) in initial_urls {
            current_urls.insert(Arc::from(s.as_str()), v);
        }

        let mut tokens_metadata = Vec::new();
        for r in tokens.iter() {
            let name = r.key().to_string();
            let token = r.value().token.read().await;
            tokens_metadata.push(TokenMetadata {
                name,
                user_id: token.user_id.clone(),
                user_principal_name: token.user_principal_name.clone(),
                client_id: token.client_id.clone(),
            });
        }

        Ok(Self {
            tenant: tenant.to_string(),
            app_id: app_id.to_string(),
            oradaz_client,
            config: config.clone(),
            verbosity,
            schema,
            writer: writer.clone(),
            tokens,
            tokens_metadata,
            condition_checker: Arc::new(condition_checker),
            ratelimit_manager,
            concurrency_controller,
            current_counter,
            current_urls,
            tables_metadata: Vec::new(),
            requests_number: 0,
            errors_number: 0,
            auth_errors_number: 0,
            prerequisites_errors_number: 0,
            missing_token_errors_number: 0,
            apis_disabled_by_conditions,
            prompt: Arc::new(StdinPrompt),
            stats,
            subscription_ids: Vec::new(),
            logs_date_filter_and,
        })
    }

    pub async fn exit_with_error(&self, error: Error) {
        if let Err(err) = self.writer.set_broken().await {
            error!("{:FL$}{:?}", "Dumper", err);
        }
        bail_fatal!(error);
    }

    pub async fn write_auth_error(&mut self, auth_error: AuthError) {
        self.auth_errors_number += 1;
        let string_error: String = match serde_json::to_string(&auth_error) {
            Err(err) => {
                error!("{:FL$}Could not convert auth_errors to json", "Dumper");
                debug!("{:FL$}auth_errors serialization error: {err:?}", "Dumper");
                self.exit_with_error(Error::AuthErrorsToJSON).await;
                String::new()
            }
            Ok(j) => format!("{j}\n"),
        };
        if let Err(err) = self
            .writer
            .write_file(String::new(), "auth_errors.json".to_string(), string_error)
            .await
        {
            error!("{:FL$}Error while writing auth error to archive", "Dumper");
            error!("{:FL$}{:?}", "Dumper", err);
            self.exit_with_error(Error::WriterLock).await;
        }
    }

    pub async fn write_prerequisite_error(&mut self, service: &str, error: &str) {
        self.prerequisites_errors_number += 1;
        let metadata = PrerequisitesMetadata {
            api: service.to_string(),
            error: error.to_string(),
        };
        let string_error = match serde_json::to_string(&metadata) {
            Ok(j) => format!("{j}\n"),
            Err(err) => {
                error!(
                    "{:FL$}Could not convert prerequisite error to json",
                    "Dumper"
                );
                debug!(
                    "{:FL$}prerequisite error serialization error: {err:?}",
                    "Dumper"
                );
                self.exit_with_error(Error::StringError(format!("JSON error: {err}")))
                    .await;
                String::new()
            }
        };
        if let Err(err) = self
            .writer
            .write_file(
                String::new(),
                "prerequisites_errors.json".to_string(),
                string_error,
            )
            .await
        {
            error!(
                "{:FL$}Error while writing prerequisite error to archive",
                "Dumper"
            );
            error!("{:FL$}{:?}", "Dumper", err);
            self.exit_with_error(Error::WriterLock).await;
        }
    }

    pub async fn dump(&mut self) -> Result<(), Error> {
        process_dump(self).await
    }
}
