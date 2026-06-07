//! Schema parsing and URL generation.
//!
//! # Authoring the schema (`schema.json`)
//!
//! Each service has a `url_scheme` with substitution tokens filled per API:
//! - `[URI]` — the API's `uri`.
//! - `[API_VERSION]` — `v1.0` by default; an API may override it (e.g. `beta`).
//!   Beware: pinning it to the default (`v1.0`) just duplicates the v1.0 call.
//! - `[PARAMS]` — the API's `parameters` value (query string, e.g.
//!   `?$count=true&$select=...`). Multiple `[PARAMS]` variants may be gated by
//!   `conditions` (e.g. `P1`/`NotP1`) to select different `$select` sets.
//! - `[LOGS_DAYS_FILTER]`, `[SIGNIN_FILTER]`, `[TENANT]`, `[KEEP_URL]` — computed
//!   substitutions (the date filters are bounded by `logsDaysFilter`).
//!   `[LOGS_DAYS_FILTER]` appends `&$filter=activityDateTime ge …` to
//!   `directoryAudits` and is substituted in `url::api` at URL-construction time.
//!   `[SIGNIN_FILTER]` is an *optional* marker an author may add to the per-user
//!   `signIns` relationship URI to bound it the same way: when present it is
//!   replaced with ` and createdDateTime ge …` in
//!   `collect::dump::response::single::value_handlers` at response time. The
//!   bundled schema does not carry it, so per-user sign-in collection is unbounded
//!   by default.
//!
//! `conditions` on an API/parameter are *tenant-level* gates (licences, tenant
//! type, capabilities) resolved by `ConditionChecker`. `keys` on a relationship
//! are *value-level*: each maps a token (e.g. `[1]`) to a field of the parent
//! object, optionally with its own `conditions` and a `transform`. A key named
//! `[PLACEHOLDER]` is a condition-only guard (its value is never substituted
//! into the URL) — see `url::relationship`.
//!
//! Practical notes:
//! - `$top` is only honoured by collection endpoints that accept advanced
//!   queries; directory-role/template collections reject it
//!   (`Request_UnsupportedQuery`). Scope page-size tuning accordingly.
//! - Adding/removing any API changes the schema SHA-256 recorded in metadata;
//!   bump `oradaz_version`/`schema_version` to match `crate::VERSION`.
use crate::collect::auth::tokens::Token;
use crate::collect::dump::conditions::ConditionChecker;
use crate::collect::dump::request::executor::parse_retry_after;
use crate::utils::client::OradazClient;
use crate::utils::config::Config;
use crate::utils::errors::Error;
use crate::utils::url::{Api, Parameter, Url};
use crate::utils::writer::WriterHandle;
use crate::{FL, SCHEMA_URL, VERSION};

use log::{debug, error, info, warn};
use rand::{rng, seq::SliceRandom};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self};
use std::sync::Arc;
use std::time::Duration;

const SCHEMA_RATE_LIMIT_RETRY_MAX: u32 = 5;
const SCHEMA_NETWORK_RETRY_MAX: u32 = 3;
const SCHEMA_NETWORK_RETRY_BASE_MS: u64 = 200;

#[derive(Clone, Deserialize)]
pub struct Service {
    pub name: String,
    pub client_id: Option<String>,
    pub scopes: Vec<String>,
    pub mandatory_auth: bool,
    pub url_scheme: String,
    pub default_api_behavior: HashMap<String, String>,
    pub default_parameters: Option<Vec<Parameter>>,
    pub apis: Vec<Api>,
}

#[derive(Clone, Deserialize)]
pub struct SchemaModel {
    pub oradaz_version: String,
    pub schema_version: String,
    pub services: Vec<Service>,
}

#[derive(Clone, Deserialize)]
pub struct SchemaVersion {
    pub oradaz_version: String,
    pub schema_version: String,
}

#[derive(Clone, Deserialize)]
pub struct Schema {
    pub oradaz_version: String,
    pub schema_hash: String,
    pub schema_version: String,
    pub services: Vec<Service>,
}

impl Schema {
    pub async fn new(
        config: &Config,
        writer: &WriterHandle,
        oradaz_client: &OradazClient,
    ) -> Result<Schema, Error> {
        let schema_str: String = Schema::get_content(config, writer, oradaz_client).await?;
        let schema = Schema::deserialize(schema_str)?;
        Ok(schema)
    }

    async fn get_content(
        config: &Config,
        writer: &WriterHandle,
        oradaz_client: &OradazClient,
    ) -> Result<String, Error> {
        let schema_file = match config.schema_file.as_deref() {
            Some(s) => s.to_string(),
            None => String::new(),
        };
        let schema_str: String = if !schema_file.is_empty() {
            info!(
                "{:FL$}Loading schema from local file {:?}",
                "Schema", schema_file
            );
            if fs::metadata(&schema_file).is_err() {
                error!("{:FL$}Invalid schema file provided", "Schema");
                return Err(Error::SchemaFileNotFound);
            }

            match fs::read_to_string(&schema_file) {
                Err(err) => {
                    error!(
                        "{:FL$}Cannot open schema file {:?}.",
                        "Schema", &schema_file
                    );
                    debug!("{:FL$}IO error reading schema file: {:?}", "Schema", err);
                    return Err(Error::IOError(err));
                }
                Ok(res) => res,
            }
        } else {
            let schema_url = config.schema_url_override.as_deref().unwrap_or(SCHEMA_URL);
            info!("{:FL$}Downloading schema from {:?}", "Schema", schema_url);
            let default_retry_after = Config::default_retry_after_seconds(config);
            let mut rate_limit_retries: u32 = 0;
            let mut network_retries: u32 = 0;
            loop {
                let res = match oradaz_client.client.get(schema_url).send().await {
                    Err(err) => {
                        if network_retries < SCHEMA_NETWORK_RETRY_MAX {
                            network_retries += 1;
                            let delay_ms = SCHEMA_NETWORK_RETRY_BASE_MS << (network_retries - 1);
                            warn!(
                                "{:FL$}Schema download failed (network error, attempt {}/{}), retrying in {}ms",
                                "Schema",
                                network_retries,
                                SCHEMA_NETWORK_RETRY_MAX + 1,
                                delay_ms
                            );
                            debug!("{:FL$}Network error: {:?}", "Schema", err);
                            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                            continue;
                        }
                        error!(
                            "{:FL$}Cannot retrieve schema file from {:?}",
                            "Schema", schema_url
                        );
                        debug!(
                            "{:FL$}HTTP request error retrieving schema: {:?}",
                            "Schema", err
                        );
                        return Err(Error::CannotDownloadSchemaFile);
                    }
                    Ok(r) => r,
                };
                let status = res.status();
                if status.as_u16() == 429 {
                    if rate_limit_retries < SCHEMA_RATE_LIMIT_RETRY_MAX {
                        rate_limit_retries += 1;
                        let retry_after =
                            parse_retry_after(res.headers()).unwrap_or(default_retry_after);
                        warn!(
                            "{:FL$}Schema download throttled (attempt {}/{}), retrying in {}s",
                            "Schema",
                            rate_limit_retries,
                            SCHEMA_RATE_LIMIT_RETRY_MAX + 1,
                            retry_after
                        );
                        tokio::time::sleep(Duration::from_secs(retry_after)).await;
                        continue;
                    }
                    error!(
                        "{:FL$}Schema download from {:?} still throttled after {} attempt(s)",
                        "Schema",
                        schema_url,
                        rate_limit_retries + 1
                    );
                    return Err(Error::CannotDownloadSchemaFile);
                }
                // Check the HTTP status before reading the body: a 404/500 or
                // an HTML error page from GitHub would otherwise be parsed as
                // schema JSON and surface as a misleading version/parse error
                // instead of a clear download failure.
                if !status.is_success() {
                    error!(
                        "{:FL$}Schema download from {:?} returned HTTP {}",
                        "Schema",
                        schema_url,
                        status.as_u16()
                    );
                    return Err(Error::CannotDownloadSchemaFile);
                }
                match res.text().await {
                    Ok(t) => break t,
                    Err(err) => {
                        error!(
                            "{:FL$}Cannot parse read while retrieving schema file from {:?}",
                            "Schema", schema_url
                        );
                        debug!(
                            "{:FL$}Response text error retrieving schema: {:?}",
                            "Schema", err
                        );
                        return Err(Error::CannotDownloadSchemaFile);
                    }
                }
            }
        };
        writer
            .write_file(String::new(), "schema.json".to_string(), schema_str.clone())
            .await?;
        Ok(schema_str)
    }

    pub fn deserialize(schema_str: String) -> Result<Schema, Error> {
        let schema_hash: String = Sha256::digest(schema_str.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        debug!("{:FL$}Schema SHA-256: {}", "Schema", schema_hash);
        match serde_json::from_str::<SchemaVersion>(&schema_str) {
            Ok(e) => {
                if e.oradaz_version != VERSION {
                    error!(
                        "{:FL$}This is not the last version of ORADAZ. Please download the last available release and ensure there are no new prerequisites.",
                        "Schema"
                    );
                    return Err(Error::NotLastVersion);
                }
                match serde_json::from_str::<SchemaModel>(&schema_str) {
                    Ok(e) => {
                        let total_apis: usize = e.services.iter().map(|s| s.apis.len()).sum();
                        info!(
                            "{:FL$}Schema loaded: version {:?}, {} service(s), {} API(s)",
                            "Schema",
                            e.schema_version,
                            e.services.len(),
                            total_apis
                        );
                        Ok(Schema {
                            oradaz_version: e.oradaz_version,
                            schema_hash,
                            schema_version: e.schema_version,
                            services: e.services,
                        })
                    }
                    Err(err) => {
                        error!("{:FL$}Could not parse schema file", "Schema");
                        debug!("{:FL$}JSON parse error (model): {:?}", "Schema", err);
                        Err(Error::SchemaFileParsing)
                    }
                }
            }
            Err(err) => {
                error!("{:FL$}Could not parse schema file", "Schema");
                debug!("{:FL$}JSON parse error (version): {:?}", "Schema", err);
                Err(Error::SchemaFileParsing)
            }
        }
    }

    pub async fn get_urls(
        &self,
        tenant: String,
        tokens: &HashMap<Arc<str>, Token>,
        condition_checker: &ConditionChecker,
        logs_days_filter: Option<&str>,
        shuffle: bool,
    ) -> HashMap<String, Vec<Url>> {
        let mut final_urls: HashMap<String, Vec<Url>> = HashMap::new();
        for service in &self.services {
            let mut urls: Vec<Url> = Vec::new();
            // Only get URLs for services where we are authenticated
            if let Some(token) = tokens.get(service.name.as_str()) {
                debug!(
                    "{:FL$}Getting URLs for service {:?}",
                    "Schema", service.name
                );
                let mut skipped_names: Vec<&str> = Vec::new();
                for api in &service.apis {
                    // Get URL for this api
                    let url: Option<Url> = api
                        .clone()
                        .get_url(
                            service,
                            tenant.clone(),
                            token,
                            condition_checker,
                            logs_days_filter,
                        )
                        .await;

                    if let Some(u) = url {
                        urls.push(u);
                    } else {
                        skipped_names.push(api.name.as_str());
                    }
                }
                if !skipped_names.is_empty() {
                    // Info, not debug: this explains at default verbosity why
                    // some endpoints produced no data (gated out by tenant
                    // conditions/licences), without needing -v or trace logs.
                    info!(
                        "{:FL$}{} API(s) skipped by conditions for service {:?}",
                        "Schema",
                        skipped_names.len(),
                        service.name
                    );
                    // Debug: name the skipped endpoints so a log reader sees
                    // exactly which were gated out, not just the count.
                    debug!(
                        "{:FL$}Skipped APIs for service {:?}: {}",
                        "Schema",
                        service.name,
                        skipped_names.join(", ")
                    );
                }
            }
            if shuffle {
                urls.shuffle(&mut rng());
            }
            final_urls.insert(service.name.clone(), urls);
        }
        final_urls
    }
}
