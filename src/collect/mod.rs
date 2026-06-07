pub mod auth;
pub mod dump;
pub mod prerequisites;

use crate::collect::dump::Dumper;
use crate::utils::client::OradazClient;
use crate::utils::config::{Config, ConfigParser};
use crate::utils::errors::{Error, FatalPresentation};
use crate::utils::logger::{self, DumpPhase, Verbosity};
use crate::utils::metadata::Metadata;
use crate::utils::ui::collection_summary::{
    CollectionSummaryData, IncompleteApi, ServiceRowData, ServiceStatus, UnexpectedApiError,
    print_collection_summary,
};
use crate::utils::ui::{self, Icon};
use crate::utils::writer::actor::spawn_writer_task;
use crate::{FL, VERSION, bail_fatal};

use chrono::prelude::DateTime;
use chrono::{Datelike, Timelike, Utc};
use log::{debug, error, info, warn};
use regex::Regex;
use serde_json::Value;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// Resolves the application (client) ID to use for the run.
///
/// Returns:
/// - `Ok(Some(id))` — a usable value. For **managed identity** this may be an
///   empty string: a system-assigned identity needs no client ID, and a
///   user-assigned one carries it in `applicationCredentials.value`. Managed
///   identity therefore never prompts and never errors on a missing `appId`.
/// - `Ok(None)` — no `appId` anywhere and the flow is interactive → the caller
///   should prompt the operator on stdin.
/// - `Err(_)` — a non-interactive credentials flow (password / certificate /
///   certificateFile) with no `appId` → fatal misconfiguration (an unattended
///   run would otherwise block on stdin).
///
/// Resolution order: managed identity → CLI `--app-id` → config `<appId>` →
/// fatal/prompt (interactive flows).
pub fn resolve_app_id(config: &Config, cli_app_id: Option<&str>) -> Result<Option<String>, Error> {
    if Config::use_managed_identity_auth(config) {
        return Ok(Some(
            config
                .application_credentials
                .as_ref()
                .and_then(|c| c.value.clone())
                .unwrap_or_default(),
        ));
    }
    if let Some(a) = cli_app_id {
        return Ok(Some(a.to_string()));
    }
    if !config.app_id.is_empty() {
        return Ok(Some(config.app_id.clone()));
    }
    if Config::use_application_credentials_auth(config) {
        return Err(Error::InvalidConfigValue(
            "useApplicationCredentials is set but no application (client) ID was provided — pass --app-id or set <appId> in the config file.".to_string(),
        ));
    }
    Ok(None)
}

/// Orchestrates the overall collection process.
///
/// This function initializes the environment (logging, UI), validates and resolves the target
/// Azure tenant and application ID, sets up the output archive, and triggers the data collection
/// process via the `Dumper`.
///
/// # Arguments
/// * `config_file` - Path to the configuration file.
/// * `tenant` - Optional tenant ID or domain name.
/// * `app_id` - Optional application ID.
/// * `output` - Optional output directory.
/// * `verbosity` - Logging verbosity level.
/// * `no_color` - Flag to disable color output in the UI.
pub async fn collect(
    config_file: String,
    tenant: Option<String>,
    app_id: Option<String>,
    output: Option<String>,
    verbosity: u8,
    no_color: bool,
) {
    let cli_verbosity = match verbosity {
        0 => Verbosity::Quiet,
        1 => Verbosity::Normal,
        2 => Verbosity::Verbose,
        3 => Verbosity::Debug,
        _ => Verbosity::Trace,
    };
    // Captured at the very start so we can report the full end-to-end runtime
    // (auth + prerequisites + dump + packaging) as `total_duration_secs`.
    let program_start: DateTime<Utc> = Utc::now();
    ui::init(no_color);
    logger::set_no_color(matches!(ui::mode(), ui::UiMode::NoColor));
    logger::initialize(None, cli_verbosity);
    logger::set_phase(DumpPhase::Before);
    println!(
        "\n{}{} ORADAZ {} {}{}",
        ui::icon(Icon::LeftUpTable),
        ui::icon(Icon::UpOrBottomTable),
        ui::blue(VERSION),
        ui::icon(Icon::UpOrBottomTable).repeat(50),
        ui::icon(Icon::RightUpTable),
    );
    println!(
        "{}  Azure tenant configuration collector {} ANSSI-FR                    {}",
        ui::icon(Icon::LeftOrRightTable),
        ui::icon(Icon::Bullet),
        ui::icon(Icon::LeftOrRightTable)
    );
    println!(
        "{}{}{}",
        ui::icon(Icon::LeftBottomTable),
        ui::icon(Icon::UpOrBottomTable).repeat(69),
        ui::icon(Icon::RightBottomTable)
    );

    let output = match output.as_deref() {
        Some(o) => Path::new(o),
        None => Path::new("."),
    };
    // Create the output folder if it does not exist (idempotent), then confirm
    // it is a usable directory.
    if !output.is_dir()
        && let Err(err) = std::fs::create_dir_all(output)
    {
        error!(
            "{:FL$}Could not create output folder {:?}: {}",
            "collect", output, err
        );
        bail_fatal!(Error::FolderCreation);
    }

    let config_parser: ConfigParser = match ConfigParser::new(&config_file) {
        Ok(o) => o,
        Err(error) => {
            bail_fatal!(error);
        }
    };
    let mut config: Config = match config_parser.deserialize() {
        Ok(config) => config,
        Err(error) => {
            bail_fatal!(error);
        }
    };

    if cli_verbosity == Verbosity::Trace {
        config.trace_logs = Some(true);
    }

    logger::set_trace_logs(Some(true) == config.trace_logs);

    let oradaz_client: OradazClient = match OradazClient::new(&config) {
        Ok(r) => r,
        Err(err) => {
            bail_fatal!(Error::StringError(err.to_string()));
        }
    };

    let schema_source: &str = if let Some(ref file) = config.schema_file {
        file.as_str()
    } else {
        "GitHub"
    };
    let proxy_status: &str = if let Some(proxy_conf) = &config.proxy {
        let has_auth = if let (Some(pw), Some(un)) = (&proxy_conf.password, &proxy_conf.username) {
            !pw.trim().is_empty() && !un.trim().is_empty()
        } else {
            false
        };
        if has_auth {
            "Enabled (Basic auth)"
        } else {
            "Enabled (no auth)"
        }
    } else {
        "Disabled"
    };
    let output_str = output.display().to_string();
    let resolved_tenant = tenant.clone().unwrap_or_else(|| config.tenant.clone());
    let summary_fields = [
        (Icon::Info, "Tenant", resolved_tenant.as_str()),
        (Icon::Info, "Config file", config_file.as_str()),
        (Icon::Info, "Schema source", schema_source),
        (Icon::Info, "Output folder", output_str.as_str()),
        (Icon::Info, "Proxy", proxy_status),
    ];
    println!("\n{}\n", ui::startup_summary(&summary_fields));

    let now: DateTime<Utc> = Utc::now();
    let (_, year) = now.year_ce();
    let mut tenant: String = match &tenant.as_deref() {
        Some(t) => t.to_string(),
        None => {
            if !&config.tenant.is_empty() {
                config.tenant.clone()
            } else {
                let mut tid: String = String::new();
                println!("Enter your tenant ID :");
                let _ = io::stdin().read_line(&mut tid);
                tid = tid
                    .strip_suffix("\r\n")
                    .or_else(|| tid.strip_suffix('\n'))
                    .unwrap_or(&tid)
                    .to_string();
                tid
            }
        }
    };

    // Resolve the tenant identifier to a valid GUID.
    // If the provided identifier is not a GUID, it's treated as a domain name and
    // resolved via the Microsoft Federation Provider API.
    let expected_format: Regex =
        match Regex::new(r"(?i)^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$") {
            Ok(re) => re,
            Err(_) => {
                bail_fatal!(Error::RegexError);
            }
        };
    if !expected_format.is_match(&tenant) {
        // Resolve domain name to tenant GUID using the Microsoft Federation Provider API.
        let send_result = tokio::time::timeout(
            Duration::from_secs(30),
            oradaz_client
                .client
                .get(format!(
                    "https://odc.officeapps.live.com/odc/v2.1/federationprovider?domain={tenant}"
                ))
                .send(),
        )
        .await;
        match send_result {
            Err(_timeout) => {
                bail_fatal!(Error::StringError(format!(
                    "Tenant resolution timed out after 30 seconds for tenant {}",
                    tenant
                )));
            }
            Ok(Err(_)) => {
                bail_fatal!(Error::StringError(format!(
                    "Provided tenant {} is not a tenant ID and no associated tenant guid could be retrieved",
                    tenant
                )));
            }
            Ok(Ok(res)) => match res.status().as_u16() {
                200 => {
                    // Extract the tenantId from the JSON response.
                    let response: Value = match res.json::<Value>().await {
                        Ok(v) => v,
                        Err(err) => {
                            bail_fatal!(Error::StringError(format!(
                                "Error retrieving tenant guid {}",
                                err
                            )));
                        }
                    };
                    match response.pointer("/tenantId") {
                        Some(s) => match s.as_str() {
                            Some(t) => {
                                // Validate that the retrieved ID is indeed a valid GUID.
                                if !expected_format.is_match(t) {
                                    bail_fatal!(Error::StringError(format!(
                                        "Invalid tenant ID {} retrieved from config for tenant {}",
                                        t, tenant
                                    )));
                                }
                                tenant = t.to_string()
                            }
                            None => {
                                bail_fatal!(Error::StringError(format!(
                                    "No tenant ID retrieved from config for tenant {}",
                                    tenant
                                )));
                            }
                        },
                        None => {
                            bail_fatal!(Error::StringError(format!(
                                "Error getting tenant ID from config for tenant {}",
                                tenant
                            )));
                        }
                    }
                }
                c => {
                    bail_fatal!(Error::StringError(format!(
                        "Provided tenant {} is not a tenant ID and no configuration could be retrieved (HTTP code {c})",
                        tenant
                    )));
                }
            },
        };
    }

    let archive_name: String = format!(
        "{}_{}{:02}{:02}-{:02}{:02}{:02}",
        tenant,
        year,
        now.month(),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );

    let app_id: String = match resolve_app_id(&config, app_id.as_deref()) {
        Ok(Some(id)) => id,
        Err(err) => bail_fatal!(err),
        Ok(None) => {
            // Interactive flow with no appId supplied: prompt the operator. (A
            // non-interactive credentials flow returns Err above instead of
            // blocking here; managed identity returns Ok(Some) and never reaches
            // this arm.)
            let mut aid: String = String::new();
            println!("Enter your application AppID :");
            let _ = io::stdin().read_line(&mut aid);
            aid.strip_suffix("\r\n")
                .or_else(|| aid.strip_suffix('\n'))
                .unwrap_or(&aid)
                .to_string()
        }
    };

    let (writer, _writer_task) =
        match spawn_writer_task(config.clone(), output.to_path_buf(), archive_name.clone()).await {
            Ok(res) => res,
            Err(err) => {
                bail_fatal!(Error::StringError(err.to_string()));
            }
        };
    logger::add_writer(&writer);
    info!(
        "{:FL$}Output archive: {:?}",
        "collect",
        output.join(format!("{archive_name}.mla"))
    );
    debug!(
        "{:FL$}Writer initialized for ORADAZ version {}",
        "collect", VERSION
    );

    if let Err(err) = config.write(&writer).await {
        let _ = writer.set_broken().await;
        bail_fatal!(Error::StringError(err.to_string()));
    };

    let mut dumper: Dumper =
        match Dumper::new(&tenant, &app_id, &writer, &config, oradaz_client, verbosity).await {
            Err(error) => {
                let _ = writer.set_broken().await;
                bail_fatal!(error);
            }
            Ok(d) => {
                info!("{:FL$}Successfully created dumper", "collect");
                d
            }
        };

    ui::prereq::print_conditions_summary(
        &dumper.condition_checker.tenant_conditions,
        dumper.apis_disabled_by_conditions,
    );

    if ui::mode() == ui::UiMode::NoColor {
        println!("\n{}", ui::section_sub("Performing collect"));
    }
    {
        let total_urls: usize = dumper.current_urls.iter().map(|r| r.value().len()).sum();
        let mut per_service: Vec<(String, usize)> = dumper
            .current_urls
            .iter()
            .filter(|r| !r.value().is_empty())
            .map(|r| (r.key().to_string(), r.value().len()))
            .collect();
        per_service.sort_by(|a, b| a.0.cmp(&b.0));
        let breakdown = per_service
            .iter()
            .map(|(s, n)| format!("{}: {}", s, n))
            .collect::<Vec<_>>()
            .join(", ");
        info!(
            "{:FL$}Starting dump: {} initial URLs ({}). Relationship URLs will be added dynamically. This can take a while, do not close the window",
            "collect", total_urls, breakdown
        );
    }

    logger::set_phase(DumpPhase::During);
    // Full `DateTime<Utc>` (not `.time()`): a `NaiveTime` diff wraps at midnight
    // and would report a wrong/negative duration for collections crossing 00:00.
    let start: DateTime<Utc> = Utc::now();
    if let Err(error) = dumper.dump().await {
        let _ = writer.set_broken().await;
        bail_fatal!(error);
    };

    let end: DateTime<Utc> = Utc::now();
    logger::set_phase(DumpPhase::After);
    info!(
        "{:FL$}Finished dump using {} requests in {:02}:{:02}:{:02}",
        "collect",
        dumper.requests_number,
        (end - start).num_hours(),
        (end - start).num_minutes() % 60,
        (end - start).num_seconds() % 60
    );
    // Surface any log lines dropped under writer backpressure (try_write_log drops
    // by design when the channel is full). Emitted here — after the progress live
    // region is gone (DumpPhase::After) and before the packaging step — so it lands
    // in oradaz.log + stderr cleanly. Collected data is unaffected; only the log is.
    let dropped_logs = crate::utils::writer::actor::dropped_log_count();
    if dropped_logs > 0 {
        warn!(
            "{:FL$}{} log line(s) were dropped due to writer backpressure during the collection; oradaz.log is incomplete (collected data is unaffected).",
            "collect", dropped_logs
        );
    }
    // Surface the peak memory observed during the dump (process RSS ground-truth
    // + URL-pool gauge). Emitted at info so it lands in oradaz.log at any
    // verbosity; metadata.json keeps the same figures for `inspect`.
    let peak_rss = crate::utils::sysmem::peak_rss_bytes();
    let peak_pool = crate::utils::sysmem::peak_pool_len();
    if peak_rss > 0 || peak_pool > 0 {
        info!(
            "{:FL$}Peak memory during dump: RSS {}, URL pool {} entries",
            "collect",
            if peak_rss > 0 {
                crate::utils::sysmem::format_bytes(peak_rss)
            } else {
                "n/a".to_string()
            },
            peak_pool
        );
    }
    // Writer/throttling peaks at debug (kept off the info console line so the
    // user-facing output is unchanged): the §writer-saturation and §AIMD-collapse
    // observability signals. The same figures are persisted in metadata.json.
    let blocked_secs = crate::utils::writer::actor::writer_budget_blocked_nanos() / 1_000_000_000;
    let blocked_count = crate::utils::writer::actor::writer_budget_blocked_count();
    // Integer seconds: a sub-second total with stalls rounds to 0 — show "<1s".
    let blocked_disp = if blocked_secs == 0 && blocked_count > 0 {
        "<1s".to_string()
    } else {
        format!("{blocked_secs}s")
    };
    debug!(
        "{:FL$}Peak writer/throttle during dump: queue {}%, in-flight {}, budget-blocked {} over {} stall(s), backoff peak {}",
        "collect",
        crate::utils::writer::actor::peak_writer_queue_pct(),
        crate::utils::sysmem::format_bytes(
            crate::utils::writer::actor::peak_writer_inflight_bytes()
        ),
        blocked_disp,
        blocked_count,
        crate::collect::dump::request::peak_backoff_active()
    );
    if ui::mode() == ui::UiMode::NoColor {
        println!("\n{}", ui::section_sub("Packaging results"));
    }
    let step_packaging = ui::StepLive::start("Packaging results");
    let collection_date: String = format!(
        "{}-{:02}-{:02} {:02}:{:02}:{:02}",
        year,
        now.month(),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );
    let metadata: Metadata = Metadata::new(
        &dumper,
        &config,
        collection_date,
        archive_name.clone(),
        (end - start).num_seconds(),
        (Utc::now() - program_start).num_seconds(),
        // Auth + prerequisites + initial URL build: process start → dump start.
        (start - program_start).num_seconds(),
    );
    match metadata.write(&writer).await {
        Err(error) => {
            let _ = writer.set_broken().await;
            bail_fatal!(error);
        }
        Ok(s) => s,
    };

    dumper.stats.finalize(Utc::now());
    if let Err(error) = dumper.stats.write(&writer).await {
        let _ = writer.set_broken().await;
        bail_fatal!(error);
    }

    // Gather per-service summary data before finalizing the writer.
    let mut service_rows: Vec<ServiceRowData> = dumper
        .schema
        .services
        .iter()
        .map(|svc| {
            let is_config_enabled =
                svc.mandatory_auth || Config::service_enable(&config, &svc.name);
            let status = if !is_config_enabled {
                ServiceStatus::DisabledByConfig
            } else if dumper.tokens.contains_key(svc.name.as_str()) {
                ServiceStatus::Enabled
            } else {
                ServiceStatus::DisabledByPrerequisiteFailure
            };
            let objects: usize = dumper
                .tables_metadata
                .iter()
                .filter(|t| t.folder == svc.name)
                .map(|t| t.count)
                .sum();
            let svc_stats = dumper.stats.services.get(&svc.name);
            let batch_calls = svc_stats
                .as_ref()
                .map(|s| s.http_batch_calls.load(Ordering::Relaxed))
                .unwrap_or(0);
            let single_calls = svc_stats
                .as_ref()
                .map(|s| s.http_single_calls.load(Ordering::Relaxed))
                .unwrap_or(0);
            ServiceRowData {
                name: svc.name.clone(),
                status,
                objects,
                batch_calls,
                single_calls,
            }
        })
        .collect();
    service_rows.sort_by(|a, b| a.name.cmp(&b.name));

    let mut total_unexpected: usize = 0;
    let mut total_expected: usize = 0;
    let mut error_details: Vec<UnexpectedApiError> = Vec::new();
    // APIs whose data is (partly) missing: URLs abandoned with a non-HTTP terminal
    // failure (UrlRetryLimit / missing token / …). These never increment
    // `unexpected_errors`, so they are gathered separately from `lost_data_summary`.
    let mut incomplete_apis: Vec<IncompleteApi> = Vec::new();
    for entry in dumper.stats.apis.iter() {
        let api = entry.value();
        let unexpected = api.unexpected_errors.load(Ordering::Relaxed);
        let expected = api.expected_errors.load(Ordering::Relaxed);
        total_unexpected += unexpected;
        total_expected += expected;
        if unexpected > 0 {
            let dominant_status = dumper
                .stats
                .dominant_unexpected_status(&api.service, &api.api);
            error_details.push(UnexpectedApiError {
                service: api.service.clone(),
                api: api.api.clone(),
                dominant_status,
                count: unexpected,
            });
        }
        if let Some((count, code)) = dumper.stats.lost_data_summary(&api.service, &api.api) {
            incomplete_apis.push(IncompleteApi {
                service: api.service.clone(),
                api: api.api.clone(),
                count,
                code,
            });
        }
    }
    error_details.sort_by(|a, b| a.service.cmp(&b.service).then(a.api.cmp(&b.api)));
    incomplete_apis.sort_by(|a, b| a.service.cmp(&b.service).then(a.api.cmp(&b.api)));

    logger::remove_writer();
    // Time the MLA finalize (single-core compression flush): excluded from
    // `total_duration_secs` (measured before this) and from metadata.json (written
    // above). A non-trivial value on a large archive is part of the §3.8
    // writer-bottleneck picture, so surface it at debug in oradaz.log.
    let finalize_start = std::time::Instant::now();
    if let Err(err) = writer.finalize().await {
        let _ = writer.set_broken().await;
        bail_fatal!(Error::StringError(err.to_string()));
    }
    debug!(
        "{:FL$}Finalize (MLA compression flush) took {}s",
        "collect",
        finalize_start.elapsed().as_secs()
    );
    let final_path = writer
        .final_mla_path()
        .await
        .unwrap_or_else(|| format!("{archive_name}.mla"));
    let size_mib = fs::metadata(&final_path)
        .map(|m| m.len() as f64 / 1_048_576.0)
        .unwrap_or(0.0);
    let duration_secs = (end - start).num_seconds();

    step_packaging.finalize();
    print_collection_summary(&CollectionSummaryData {
        service_rows: &service_rows,
        unexpected_errors: total_unexpected,
        expected_errors: total_expected,
        error_details: &error_details,
        incomplete_apis: &incomplete_apis,
        archive_path: &final_path,
        size_mib,
        duration_secs,
        total_http_requests: dumper.requests_number,
        verbosity,
    });
}
