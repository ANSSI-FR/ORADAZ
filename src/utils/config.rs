/// Module to manage the parsing and storage of the application configuration.
use crate::FL;
use crate::utils::errors::Error;
use crate::utils::writer::actor::WriterHandle;

use log::{debug, error, warn};
use serde::{Deserialize, Serialize};
use std::fs::{self};

/// Configuration for a single service, specifying if it is enabled for the dump.
#[derive(Clone, Deserialize, Serialize)]
pub struct ServiceConfig {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "#text")]
    pub value: bool,
}

/// Collection of service configurations.
#[derive(Clone, Deserialize, Serialize)]
pub struct ServicesConfig {
    #[serde(rename = "service")]
    pub services: Vec<ServiceConfig>,
}

/// Credentials used for the client credentials authentication flow.
#[derive(Clone, Deserialize)]
pub struct ApplicationCredentials {
    /// Credential type: "password", "certificate", "certificateFile", "managedIdentity".
    #[serde(rename = "type")]
    pub credential_type: String,
    /// The credential value.
    /// - `password`: client secret string.
    /// - `certificate` / `certificateFile`: raw PEM content or file path.
    /// - `managedIdentity`: optional client ID of a user-assigned managed identity.
    ///   Absent or empty means system-assigned.
    #[serde(default)]
    pub value: Option<String>,
}

/// Configuration for an HTTP proxy.
#[derive(Clone, Deserialize)]
pub struct ProxyConfig {
    pub url: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Additional public keys used for MLA archive encryption.
#[derive(Clone, Deserialize)]
pub struct AdditionalMlaKeys {
    #[serde(rename = "MlaKeyFile")]
    pub key_files: Option<Vec<String>>,
    #[serde(rename = "MlaKey")]
    pub keys: Option<Vec<String>>,
}

/// Per-service override of throughput-sensitive parameters. Any field left as
/// `None` falls back to the global value. The same parameter names as on
/// `Config` are accepted; only the parameters listed here are overridable
/// per-service (others stay global by nature — they govern the dispatcher or
/// the pipeline as a whole, not per-API request behaviour).
#[derive(Clone, Deserialize, Serialize, Debug, Default)]
pub struct ServiceOverride {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "concurrencyMinWindow")]
    pub concurrency_min_window: Option<usize>,
    #[serde(rename = "concurrencyMaxWindow")]
    pub concurrency_max_window: Option<usize>,
    #[serde(rename = "rateLimitRetryLimit")]
    pub rate_limit_retry_limit: Option<usize>,
    #[serde(rename = "rateLimitMaxWaitSecs")]
    pub rate_limit_max_wait_secs: Option<u64>,
    #[serde(rename = "defaultRetryAfterSeconds")]
    pub default_retry_after_seconds: Option<u64>,
    #[serde(rename = "httpTimeoutSeconds")]
    pub http_timeout_seconds: Option<u64>,
}

/// XML wrapper around `<serviceOverrides>` so each `<service>` entry deserialises
/// into a `ServiceOverride`.
#[derive(Clone, Deserialize, Serialize, Debug, Default)]
pub struct ServiceOverrides {
    #[serde(rename = "service", default)]
    pub services: Vec<ServiceOverride>,
}

/// Application configuration parsed from the XML config file.
#[derive(Clone, Deserialize)]
pub struct Config {
    pub tenant: String,
    #[serde(rename = "appId", default)]
    pub app_id: String,
    pub services: Option<ServicesConfig>,
    pub proxy: Option<ProxyConfig>,
    #[serde(rename = "outputFiles")]
    pub output_files: Option<bool>,
    #[serde(rename = "outputMLA")]
    pub output_mla: Option<bool>,
    #[serde(rename = "noCheck")]
    pub no_check: Option<bool>,
    #[serde(rename = "useDeviceCode")]
    pub use_device_code: Option<bool>,
    #[serde(rename = "listenerAddress")]
    pub listener_address: Option<String>,
    #[serde(rename = "listenerPort")]
    pub listener_port: Option<String>,
    #[serde(rename = "schemaFile")]
    pub schema_file: Option<String>,
    #[serde(rename = "schemaUrlOverride")]
    pub schema_url_override: Option<String>,
    #[serde(rename = "userAgent")]
    pub user_agent: Option<String>,
    #[serde(rename = "emergencyAccountsCustomAttributes")]
    pub emergency_accounts_custom_attributes: Option<String>,

    #[serde(rename = "additionalMlaKeys")]
    pub additional_mla_keys: Option<AdditionalMlaKeys>,

    #[serde(rename = "traceLogs")]
    pub trace_logs: Option<bool>,

    #[serde(rename = "useApplicationCredentials")]
    pub use_application_credentials: Option<bool>,
    #[serde(rename = "applicationCredentials")]
    pub application_credentials: Option<ApplicationCredentials>,
    /// Minimum AIMD concurrency window per service (default: 5).
    #[serde(rename = "concurrencyMinWindow")]
    pub concurrency_min_window: Option<usize>,
    /// Maximum AIMD concurrency window per service (default: 30).
    #[serde(rename = "concurrencyMaxWindow")]
    pub concurrency_max_window: Option<usize>,
    /// Default wait time in seconds when a rate limit (HTTP 429) is encountered without a Retry-After header (default: 5).
    #[serde(rename = "defaultRetryAfterSeconds")]
    pub default_retry_after_seconds: Option<u64>,
    /// HTTP request timeout in seconds (default: 30).
    #[serde(rename = "httpTimeoutSeconds")]
    pub http_timeout_seconds: Option<u64>,
    /// Maximum number of API calls dispatched in one batch to the RequestModule (default: 256).
    #[serde(rename = "dispatchBurstCap")]
    pub dispatch_burst_cap: Option<usize>,
    /// Maximum number of retries per URL before marking it as an error (default: 5).
    /// Counts only "real" errors (4xx prereq, 5xx). 429 retries are tracked separately
    /// via `rate_limit_retry_limit` and do not consume this budget.
    #[serde(rename = "urlRetryLimit")]
    pub url_retry_limit: Option<usize>,
    /// Maximum number of 429 (Too Many Requests) retries per URL before marking it as
    /// rate-limit-exhausted (default: 50). Throttling is a transient condition that
    /// can persist for many cycles, so this budget is intentionally much higher than
    /// `url_retry_limit`. Capped also by `rate_limit_max_wait_secs`.
    #[serde(rename = "rateLimitRetryLimit")]
    pub rate_limit_retry_limit: Option<usize>,
    /// Maximum total wait time (seconds) per URL accumulated from 429 Retry-After
    /// headers, before marking the URL as rate-limit-exhausted (default: 900 = 15 min).
    /// Acts as a temporal safety net against indefinite throttling loops.
    #[serde(rename = "rateLimitMaxWaitSecs")]
    pub rate_limit_max_wait_secs: Option<u64>,
    /// Time in seconds before the Coordinator marks the pipeline as stalled (default: 900).
    #[serde(rename = "stallDetectionTimeout")]
    pub stall_detection_timeout: Option<u64>,
    /// TCP connect timeout in seconds, separate from the overall request timeout (default: 10).
    #[serde(rename = "httpConnectTimeoutSeconds")]
    pub http_connect_timeout_seconds: Option<u64>,
    /// Base delay in milliseconds for the first retry backoff step (default: 250).
    #[serde(rename = "retryBackoffBaseMs")]
    pub retry_backoff_base_ms: Option<u64>,
    /// Maximum delay cap in milliseconds for retry backoff (default: 8000).
    #[serde(rename = "retryBackoffCapMs")]
    pub retry_backoff_cap_ms: Option<u64>,
    /// Time window in seconds during which a successful prereq re-check is trusted:
    /// if another URL of the same service hits a 4xx within this window, no new
    /// re-check is spawned (the URL consumes its own retry budget instead).
    /// Default: 90 s. Set to 0 to disable the cache and re-check on every 4xx.
    #[serde(rename = "prereqRecheckCacheSecs")]
    pub prereq_recheck_cache_secs: Option<u64>,
    /// Per-bucket liveness ceiling (seconds, default 900 = 15 min). This is the
    /// sole bound on transient (429 / network) retries, which are not abandoned
    /// on a fixed count: a `(service, api)` bucket that has written no
    /// data for this long despite retrying is abandoned (lost data,
    /// `ThrottleStalled` / `NetworkStalled`) so the run always terminates. A
    /// draining bucket keeps resetting it and is never dropped. Keep
    /// **≥ `rateLimitMaxWaitSecs`** so a single honoured cooldown can't trip it.
    /// Must be > 0 (0 would re-introduce unbounded transient retries).
    #[serde(rename = "livenessCeilingSecs")]
    pub liveness_ceiling_secs: Option<u64>,
    /// Per-service overrides for throughput-sensitive parameters. See
    /// `ServiceOverride` for the list of fields. Services not listed here use
    /// the global values.
    #[serde(rename = "serviceOverrides")]
    pub service_overrides: Option<ServiceOverrides>,
    /// Number of days to look back when collecting `auditLogs/directoryAudits` (default: 7).
    /// Set to 0 to disable the temporal filter and collect all available records (up to
    /// the Microsoft retention limit of 30 days for P1/P2, 7 days for free tenants).
    #[serde(rename = "logsDaysFilter")]
    pub logs_days_filter: Option<u32>,
    /// If true, URLs are shuffled before being dispatched (default: true).
    /// Set to false via CLI `--no-shuffle` or in the XML configuration.
    #[serde(rename = "shuffleUrls")]
    pub shuffle_urls: Option<bool>,
    /// If true, each service's AIMD concurrency window starts at `min_window` and
    /// ramps up on success (slow-start), instead of starting at `max_window`
    /// (default: false). Gentler opening burst on strict throttlers (e.g. ARM).
    #[serde(rename = "concurrencySlowStart")]
    pub concurrency_slow_start: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct StoredConfig {
    pub tenant: String,
    pub app_id: String,
    pub services: Option<ServicesConfig>,
    pub proxy: bool,
    pub output_files: bool,
    pub output_mla: bool,
    pub no_check: Option<bool>,
    pub use_device_code: Option<bool>,
    pub use_schema_file: bool,
    pub user_agent: Option<String>,
    pub additional_mla_keys: bool,
    pub trace_logs: bool,
    pub use_application_credentials: Option<bool>,
    pub application_credential_type: Option<String>,
    pub concurrency_min_window: Option<usize>,
    pub concurrency_max_window: Option<usize>,
    pub default_retry_after_seconds: Option<u64>,
    pub http_timeout_seconds: Option<u64>,
    pub dispatch_burst_cap: Option<usize>,
    pub url_retry_limit: Option<usize>,
    pub rate_limit_retry_limit: Option<usize>,
    pub rate_limit_max_wait_secs: Option<u64>,
    pub stall_detection_timeout: Option<u64>,
    pub emergency_accounts_custom_attributes: Option<String>,
    pub http_connect_timeout_seconds: Option<u64>,
    pub retry_backoff_base_ms: Option<u64>,
    pub retry_backoff_cap_ms: Option<u64>,
    pub prereq_recheck_cache_secs: Option<u64>,
    pub liveness_ceiling_secs: Option<u64>,
    pub service_overrides: Option<ServiceOverrides>,
    pub logs_days_filter: Option<u32>,
    pub shuffle_urls: Option<bool>,
    pub concurrency_slow_start: Option<bool>,
}

impl Config {
    /// Checks if a service with the given name is enabled in the configuration.
    pub fn service_enable(config: &Config, name: &String) -> bool {
        match &config.services {
            Some(services) => {
                for service in &services.services {
                    if &service.name == name && service.value {
                        return true;
                    }
                }
            }
            None => return false,
        }
        false
    }

    /// Returns `true` if the configuration selects the client credentials authentication flow.
    pub fn use_application_credentials_auth(config: &Config) -> bool {
        Some(true) == config.use_application_credentials
    }

    /// Returns `true` if the configuration forces the use of the Device Code authentication flow.
    pub fn force_device_code_auth(config: &Config) -> bool {
        Some(true) == config.use_device_code
    }

    /// Returns `true` if the configuration selects the Managed Identity authentication flow.
    pub fn use_managed_identity_auth(config: &Config) -> bool {
        Config::use_application_credentials_auth(config)
            && config
                .application_credentials
                .as_ref()
                .map(|c| c.credential_type == "managedIdentity")
                .unwrap_or(false)
    }

    /// Returns the override block declared for `service`, if any.
    pub fn service_override<'a>(config: &'a Config, service: &str) -> Option<&'a ServiceOverride> {
        config
            .service_overrides
            .as_ref()?
            .services
            .iter()
            .find(|s| s.name == service)
    }

    pub fn concurrency_min_window(config: &Config) -> usize {
        config.concurrency_min_window.unwrap_or(5)
    }

    /// Per-service variant of [`Self::concurrency_min_window`].
    pub fn concurrency_min_window_for(config: &Config, service: &str) -> usize {
        Self::service_override(config, service)
            .and_then(|o| o.concurrency_min_window)
            .unwrap_or_else(|| Self::concurrency_min_window(config))
    }

    pub fn concurrency_max_window(config: &Config) -> usize {
        config.concurrency_max_window.unwrap_or(30)
    }

    /// Per-service variant of [`Self::concurrency_max_window`].
    pub fn concurrency_max_window_for(config: &Config, service: &str) -> usize {
        Self::service_override(config, service)
            .and_then(|o| o.concurrency_max_window)
            .unwrap_or_else(|| Self::concurrency_max_window(config))
    }

    /// Built-in per-service maximum AIMD window baselines, applied by
    /// `build_service_aware_throttling` when no explicit `concurrencyMaxWindow`
    /// override is set. Graph and Exchange tolerate high concurrency; ARM
    /// (`resources`) is a stricter throttler. Exposed so `validate()` checks a
    /// min-only override against the window that actually applies at runtime, not
    /// the conservative global default.
    pub const GRAPH_MAX_WINDOW_BASELINE: usize = 150;
    pub const EXCHANGE_MAX_WINDOW_BASELINE: usize = 150;
    pub const RESOURCES_MAX_WINDOW_BASELINE: usize = 100;

    /// Effective `concurrencyMaxWindow` baseline for a service *before* an
    /// explicit per-service override: the built-in baseline for
    /// graph/exchange/resources, else the global `concurrencyMaxWindow`.
    pub fn service_max_window_baseline(config: &Config, service: &str) -> usize {
        match service {
            "graph" => Self::GRAPH_MAX_WINDOW_BASELINE,
            "exchange" => Self::EXCHANGE_MAX_WINDOW_BASELINE,
            "resources" => Self::RESOURCES_MAX_WINDOW_BASELINE,
            _ => Self::concurrency_max_window(config),
        }
    }

    pub fn default_retry_after_seconds(config: &Config) -> u64 {
        config.default_retry_after_seconds.unwrap_or(5)
    }

    /// Per-service variant of [`Self::default_retry_after_seconds`].
    pub fn default_retry_after_seconds_for(config: &Config, service: &str) -> u64 {
        Self::service_override(config, service)
            .and_then(|o| o.default_retry_after_seconds)
            .unwrap_or_else(|| Self::default_retry_after_seconds(config))
    }

    pub fn http_timeout_seconds(config: &Config) -> u64 {
        config.http_timeout_seconds.unwrap_or(30)
    }

    /// Per-service variant of [`Self::http_timeout_seconds`].
    ///
    /// Priority: service override → explicit global → code default.
    /// The code default for `"resources"` is 60 s because ARM batch requests
    /// can be slow (e.g. provider registration lists, PIM policies); all other
    /// services default to 30 s.
    pub fn http_timeout_seconds_for(config: &Config, service: &str) -> u64 {
        if let Some(v) =
            Self::service_override(config, service).and_then(|o| o.http_timeout_seconds)
        {
            return v;
        }
        if let Some(v) = config.http_timeout_seconds {
            return v;
        }
        if service == "resources" { 60 } else { 30 }
    }

    pub fn dispatch_burst_cap(config: &Config) -> usize {
        config.dispatch_burst_cap.unwrap_or(256)
    }

    pub fn url_retry_limit(config: &Config) -> usize {
        config.url_retry_limit.unwrap_or(5)
    }

    pub fn rate_limit_retry_limit(config: &Config) -> usize {
        config.rate_limit_retry_limit.unwrap_or(50)
    }

    /// Per-service variant of [`Self::rate_limit_retry_limit`].
    pub fn rate_limit_retry_limit_for(config: &Config, service: &str) -> usize {
        Self::service_override(config, service)
            .and_then(|o| o.rate_limit_retry_limit)
            .unwrap_or_else(|| Self::rate_limit_retry_limit(config))
    }

    pub fn rate_limit_max_wait_secs(config: &Config) -> u64 {
        config.rate_limit_max_wait_secs.unwrap_or(900)
    }

    /// Per-service variant of [`Self::rate_limit_max_wait_secs`].
    pub fn rate_limit_max_wait_secs_for(config: &Config, service: &str) -> u64 {
        Self::service_override(config, service)
            .and_then(|o| o.rate_limit_max_wait_secs)
            .unwrap_or_else(|| Self::rate_limit_max_wait_secs(config))
    }

    /// Watchdog timeout: how long the coordinator may wait without receiving
    /// any event before it logs a stall diagnostic. It only *logs and
    /// continues* — it never aborts the run. For coherence keep
    /// `rateLimitMaxWaitSecs` ≤ this value: a legitimate single 429 cooldown is
    /// bounded by `rateLimitMaxWaitSecs`, so a smaller stall timeout would flag
    /// that legitimate wait as a false stall. This relationship is a
    /// configuration guideline only — it is intentionally **not** enforced in
    /// code. Default `900` (equal to the `rateLimitMaxWaitSecs` default).
    pub fn stall_detection_timeout(config: &Config) -> u64 {
        config.stall_detection_timeout.unwrap_or(900)
    }

    pub fn http_connect_timeout_seconds(config: &Config) -> u64 {
        config.http_connect_timeout_seconds.unwrap_or(10)
    }

    pub fn retry_backoff_base_ms(config: &Config) -> u64 {
        config.retry_backoff_base_ms.unwrap_or(250)
    }

    pub fn retry_backoff_cap_ms(config: &Config) -> u64 {
        config.retry_backoff_cap_ms.unwrap_or(8000)
    }

    pub fn prereq_recheck_cache_secs(config: &Config) -> u64 {
        config.prereq_recheck_cache_secs.unwrap_or(90)
    }

    /// Per-bucket liveness ceiling (seconds). The sole bound on transient (429 /
    /// network) retries, which are not abandoned on a fixed count — a bucket with
    /// no data written for this long is abandoned so the run terminates. Default
    /// 900 (= 15 min).
    pub fn liveness_ceiling_secs(config: &Config) -> u64 {
        config.liveness_ceiling_secs.unwrap_or(900)
    }

    pub fn logs_days_filter(config: &Config) -> u32 {
        config.logs_days_filter.unwrap_or(7)
    }

    /// Returns whether URLs should be shuffled before dispatch (default = true).
    pub fn shuffle_urls(config: &Config) -> bool {
        config.shuffle_urls.unwrap_or(true)
    }

    /// Returns whether the AIMD concurrency window should slow-start at
    /// `min_window` and ramp up (default = false → start at `max_window`).
    pub fn concurrency_slow_start(config: &Config) -> bool {
        config.concurrency_slow_start.unwrap_or(false)
    }

    /// Validates the configuration parameters to ensure they are within acceptable bounds.
    pub fn validate(&self) -> Result<(), Error> {
        // Producing no output at all is almost always a misconfiguration: the
        // collection would still authenticate, hit the tenant, and write nothing.
        // MLA is on unless explicitly disabled; files are off unless explicitly
        // enabled — reject the combination that yields neither.
        let files_on = self.output_files == Some(true);
        let mla_on = self.output_mla != Some(false);
        if !files_on && !mla_on {
            return Err(Error::InvalidConfigValue(
                "no output enabled: <outputMLA> is false and <outputFiles> is not enabled — the collection would produce no output".to_string(),
            ));
        }
        // Warn (don't fail) when two mutually-exclusive auth flows are both
        // requested. The router prefers application credentials over device code
        // (see `auth::Auth::get_token`), so this is not fatal — but the operator
        // most likely did not intend to set both.
        if self.use_device_code == Some(true) && self.use_application_credentials == Some(true) {
            warn!(
                "{:FL$}Both <useDeviceCode> and <useApplicationCredentials> are set to true; application credentials take precedence and the device code flow will be ignored.",
                "Config"
            );
        }
        // Warn (don't fail) on unknown <service name="…"> values: serde-xml-rs
        // silently keeps a misspelled name (e.g. "ressources"), so the service
        // just never runs with no feedback. The valid set is exactly the known
        // trio, so this has zero false positives. A bare warn (not an error)
        // preserves forward-compatibility if the trio ever grows.
        if let Some(services) = &self.services {
            const KNOWN_SERVICES: [&str; 2] = ["resources", "exchange"];
            for svc in &services.services {
                if !KNOWN_SERVICES.contains(&svc.name.as_str()) {
                    warn!(
                        "{:FL$}Unknown service '{}' in <services> config — ignored. Known services: resources, exchange.",
                        "Config", svc.name
                    );
                }
            }
        }
        if Config::concurrency_min_window(self) > Config::concurrency_max_window(self) {
            return Err(Error::InvalidConfigValue(
                "concurrencyMinWindow cannot be greater than concurrencyMaxWindow".to_string(),
            ));
        }
        // A window of 0 stalls the dump: `acquire_slot` never satisfies
        // `in_flight < current`, so no request for that service is ever dispatched.
        // `min == 0` is equally unsafe — `report_429` halves the window down to
        // `min`, so a 0 floor lets throttling drive it to 0. Both must be >= 1.
        if Config::concurrency_min_window(self) == 0 || Config::concurrency_max_window(self) == 0 {
            return Err(Error::InvalidConfigValue(
                "concurrencyMinWindow and concurrencyMaxWindow must be greater than 0".to_string(),
            ));
        }
        // Advisory: a global concurrencyMinWindow above a per-service built-in max
        // baseline (graph/exchange 150, resources 100) would otherwise yield an
        // inverted (min > max) window for that service. The ConcurrencyController
        // clamps min to max at runtime, so this is not fatal, but warn so the
        // operator knows the service will be capped at its baseline rather than the
        // requested min. Services carrying an explicit concurrencyMaxWindow override
        // are validated separately below.
        let global_min = Config::concurrency_min_window(self);
        for service in ["graph", "exchange", "resources"] {
            let has_max_override = Config::service_override(self, service)
                .and_then(|o| o.concurrency_max_window)
                .is_some();
            if !has_max_override {
                let baseline = Config::service_max_window_baseline(self, service);
                if global_min > baseline {
                    warn!(
                        "{:FL$}concurrencyMinWindow ({}) exceeds the built-in max window for service '{}' ({}); that service's window will be clamped to {} (min == max)",
                        "Config", global_min, service, baseline, baseline
                    );
                }
            }
        }
        // Validate per-service overrides on the same invariants as the globals
        // (windows ordered, non-zero timeouts and budgets). Reject early so the
        // operator gets a clear message instead of a runtime panic later.
        if let Some(overrides) = &self.service_overrides {
            for ov in &overrides.services {
                // Warn on a misspelled override service name: it parses fine but
                // silently never applies. Unlike <services>, graph is overridable
                // here, so the known set includes it.
                const KNOWN_OVERRIDE_SERVICES: [&str; 3] = ["graph", "resources", "exchange"];
                if !KNOWN_OVERRIDE_SERVICES.contains(&ov.name.as_str()) {
                    warn!(
                        "{:FL$}Unknown service '{}' in <serviceOverrides> — this override will never apply. Known services: graph, resources, exchange.",
                        "Config", ov.name
                    );
                }
                let min_w = ov
                    .concurrency_min_window
                    .unwrap_or_else(|| Config::concurrency_min_window(self));
                // Fall back to the per-service built-in baseline (graph/exchange 150,
                // resources 100), not the global default, so a min-only override is
                // checked against the window that actually applies at runtime — see
                // build_service_aware_throttling.
                let max_w = ov
                    .concurrency_max_window
                    .unwrap_or_else(|| Config::service_max_window_baseline(self, &ov.name));
                if min_w == 0 || max_w == 0 {
                    return Err(Error::InvalidConfigValue(format!(
                        "serviceOverrides[{}]: concurrencyMinWindow and concurrencyMaxWindow must be greater than 0",
                        ov.name
                    )));
                }
                if min_w > max_w {
                    return Err(Error::InvalidConfigValue(format!(
                        "serviceOverrides[{}]: concurrencyMinWindow ({min_w}) cannot exceed concurrencyMaxWindow ({max_w})",
                        ov.name
                    )));
                }
                if ov.rate_limit_retry_limit == Some(0) {
                    return Err(Error::InvalidConfigValue(format!(
                        "serviceOverrides[{}]: rateLimitRetryLimit must be greater than 0",
                        ov.name
                    )));
                }
                if ov.rate_limit_max_wait_secs == Some(0) {
                    return Err(Error::InvalidConfigValue(format!(
                        "serviceOverrides[{}]: rateLimitMaxWaitSecs must be greater than 0",
                        ov.name
                    )));
                }
                if ov.http_timeout_seconds == Some(0) {
                    return Err(Error::InvalidConfigValue(format!(
                        "serviceOverrides[{}]: httpTimeoutSeconds must be greater than 0",
                        ov.name
                    )));
                }
                if ov.default_retry_after_seconds == Some(0) {
                    return Err(Error::InvalidConfigValue(format!(
                        "serviceOverrides[{}]: defaultRetryAfterSeconds must be greater than 0",
                        ov.name
                    )));
                }
            }
        }
        if self.http_timeout_seconds.unwrap_or(30) == 0 {
            return Err(Error::InvalidConfigValue(
                "httpTimeoutSeconds must be greater than 0".to_string(),
            ));
        }
        let connect_timeout = self.http_connect_timeout_seconds.unwrap_or(10);
        if connect_timeout == 0 {
            return Err(Error::InvalidConfigValue(
                "httpConnectTimeoutSeconds must be greater than 0".to_string(),
            ));
        }
        // When no explicit httpTimeoutSeconds is set, the effective maximum
        // default is 60 s (the code default for the "resources" service).
        // Validate against that wider bound so that connect timeouts up to 60 s
        // are accepted even without an explicit global timeout configuration.
        let effective_max_timeout = self.http_timeout_seconds.unwrap_or(60);
        if connect_timeout > effective_max_timeout {
            return Err(Error::InvalidConfigValue(
                "httpConnectTimeoutSeconds must not exceed httpTimeoutSeconds".to_string(),
            ));
        }
        if self.retry_backoff_base_ms == Some(0) {
            return Err(Error::InvalidConfigValue(
                "retryBackoffBaseMs must be greater than 0".to_string(),
            ));
        }
        if self.retry_backoff_cap_ms == Some(0) {
            return Err(Error::InvalidConfigValue(
                "retryBackoffCapMs must be greater than 0".to_string(),
            ));
        }
        // A zero retry budget short-circuits dispatch — every URL is abandoned
        // before its first attempt — which is almost certainly a misconfiguration.
        if self.url_retry_limit == Some(0) {
            return Err(Error::InvalidConfigValue(
                "urlRetryLimit must be greater than 0".to_string(),
            ));
        }
        if self.rate_limit_retry_limit == Some(0) {
            return Err(Error::InvalidConfigValue(
                "rateLimitRetryLimit must be greater than 0".to_string(),
            ));
        }
        if self.rate_limit_max_wait_secs == Some(0) {
            return Err(Error::InvalidConfigValue(
                "rateLimitMaxWaitSecs must be greater than 0".to_string(),
            ));
        }
        // A 0 fallback is harmful, not harmless: `RateLimitManager` clamps the
        // cooldown only on the upper bound (`rateLimitMaxWaitSecs`), never on a
        // floor, so a 429 that arrives without a `Retry-After` header would get a
        // 0-second cooldown — i.e. an immediate hot retry loop. Reject it like
        // the other zero-budget values.
        if self.default_retry_after_seconds == Some(0) {
            return Err(Error::InvalidConfigValue(
                "defaultRetryAfterSeconds must be greater than 0 (a 0 fallback disables the cooldown on header-less 429 responses, causing a hot retry loop)".to_string(),
            ));
        }
        // Compare effective (defaulted) values so partial configs are caught too
        // (e.g. cap=Some(5) with base unset defaults to base=250 > cap=5).
        if Config::retry_backoff_base_ms(self) > Config::retry_backoff_cap_ms(self) {
            return Err(Error::InvalidConfigValue(
                "retryBackoffBaseMs must not exceed retryBackoffCapMs".to_string(),
            ));
        }
        if let Some(attr) = &self.emergency_accounts_custom_attributes {
            let parts = attr.split('.').collect::<Vec<&str>>();
            if parts.len() != 2 || parts.iter().any(|p| p.is_empty()) {
                return Err(Error::InvalidConfigValue(
                    "emergencyAccountsCustomAttributes must have the format <Attribute set name>.<Attribute name>".to_string(),
                ));
            }
        }
        if let Some(creds) = &self.application_credentials
            && matches!(
                creds.credential_type.as_str(),
                "password" | "certificate" | "certificateFile"
            )
            && creds.value.as_ref().map(|v| v.is_empty()).unwrap_or(true)
        {
            return Err(Error::InvalidConfigValue(format!(
                "applicationCredentials.value is required for credential type '{}'",
                creds.credential_type
            )));
        }
        // A dispatch burst cap of 0 makes dispatch a silent no-op: the
        // `items_sent_in_burst >= cap` guard in `dispatch_requests` is already
        // satisfied on entry, so no URL is ever sent and the run stalls with no
        // panic and no error. Reject it like the other zero budgets.
        if self.dispatch_burst_cap == Some(0) {
            return Err(Error::InvalidConfigValue(
                "dispatchBurstCap must be greater than 0".to_string(),
            ));
        }
        // A stall-detection timeout of 0 turns the coordinator's
        // `tokio::time::timeout(Duration::from_secs(0), …)` into an immediate
        // timeout on every event wait, spuriously tripping stall detection.
        if self.stall_detection_timeout == Some(0) {
            return Err(Error::InvalidConfigValue(
                "stallDetectionTimeout must be greater than 0".to_string(),
            ));
        }
        // The liveness ceiling is the ONLY bound on transient (429 / network)
        // retries; `0` would let a never-draining bucket retry forever and the
        // run never terminate.
        if self.liveness_ceiling_secs == Some(0) {
            return Err(Error::InvalidConfigValue(
                "livenessCeilingSecs must be greater than 0".to_string(),
            ));
        }
        Ok(())
    }

    /// Serializes a sanitized version of the configuration and writes it to the archive.
    pub async fn write(&self, writer: &WriterHandle) -> Result<(), Error> {
        let config: StoredConfig = StoredConfig {
            tenant: self.tenant.clone(),
            app_id: self.app_id.clone(),
            services: self.services.clone(),
            proxy: self.proxy.is_some(),
            output_files: Some(true) == self.output_files,
            // Mirror the writer gate (`writer/mod.rs`), which is default-ON:
            // an MLA archive is produced unless `outputMLA` is explicitly false.
            // `Some(true) == self.output_mla` would record the default (`None`)
            // run as `false` even though a `.mla` was written.
            output_mla: self.output_mla != Some(false),
            no_check: self.no_check,
            use_device_code: self.use_device_code,
            use_schema_file: self.schema_file.is_some(),
            user_agent: self.user_agent.clone(),
            additional_mla_keys: self.additional_mla_keys.is_some(),
            trace_logs: Some(true) == self.trace_logs,
            use_application_credentials: self.use_application_credentials,
            application_credential_type: self
                .application_credentials
                .as_ref()
                .map(|c| c.credential_type.clone()),
            concurrency_min_window: self.concurrency_min_window,
            concurrency_max_window: self.concurrency_max_window,
            default_retry_after_seconds: self.default_retry_after_seconds,
            http_timeout_seconds: self.http_timeout_seconds,
            dispatch_burst_cap: self.dispatch_burst_cap,
            url_retry_limit: self.url_retry_limit,
            rate_limit_retry_limit: self.rate_limit_retry_limit,
            rate_limit_max_wait_secs: self.rate_limit_max_wait_secs,
            stall_detection_timeout: self.stall_detection_timeout,
            emergency_accounts_custom_attributes: self.emergency_accounts_custom_attributes.clone(),
            http_connect_timeout_seconds: self.http_connect_timeout_seconds,
            retry_backoff_base_ms: self.retry_backoff_base_ms,
            retry_backoff_cap_ms: self.retry_backoff_cap_ms,
            prereq_recheck_cache_secs: self.prereq_recheck_cache_secs,
            liveness_ceiling_secs: self.liveness_ceiling_secs,
            service_overrides: self.service_overrides.clone(),
            logs_days_filter: self.logs_days_filter,
            shuffle_urls: self.shuffle_urls,
            concurrency_slow_start: self.concurrency_slow_start,
        };
        let config_str = match serde_json::to_string(&config) {
            Err(err) => {
                error!("{:FL$}Could not convert config to json", "Config");
                debug!("{:FL$}Config JSON serialization error: {:?}", "Config", err);
                return Err(Error::ConfigToJSON);
            }
            Ok(j) => j,
        };
        writer
            .write_file(String::new(), "config.json".to_string(), config_str)
            .await?;
        Ok(())
    }
}

/// Parser for the XML configuration file.
pub struct ConfigParser {
    config_file: String,
}

impl ConfigParser {
    /// Creates a new `ConfigParser` for the specified file path.
    pub fn new(config_file: &str) -> Result<ConfigParser, Error> {
        if fs::metadata(config_file).is_err() {
            error!("{:FL$}Invalid config file provided", "ConfigParser");
            return Err(Error::ConfigFileNotFound);
        }

        Ok(ConfigParser {
            config_file: config_file.to_string(),
        })
    }

    /// Reads and deserializes the XML configuration file into a `Config` structure.
    pub fn deserialize(self) -> Result<Config, Error> {
        let config_str: String = match fs::read_to_string(&self.config_file) {
            Err(err) => {
                error!(
                    "{:FL$}Cannot open config file {:?}.",
                    "ConfigParser", &self.config_file
                );
                debug!(
                    "{:FL$}IO error reading config file: {:?}",
                    "ConfigParser", err
                );
                return Err(Error::IOError(err));
            }
            Ok(res) => res,
        };
        match serde_xml_rs::from_str::<Config>(&config_str) {
            Ok(config) => {
                config.validate()?;
                Ok(config)
            }
            Err(err) => {
                error!("{:FL$}Could not parse config file: {}", "ConfigParser", err);
                debug!("{:FL$}XML parsing error: {:?}", "ConfigParser", err);
                Err(Error::InvalidConfigXMLStructure(Some(err.to_string())))
            }
        }
    }
}
