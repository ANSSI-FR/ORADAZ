pub mod auth;
pub mod conditions;
pub mod config;
pub mod dumper;
pub mod errors;
pub mod logger;
pub mod metadata;
pub mod prerequisites;
pub mod requests;
pub mod schema;
pub mod threading;
pub mod writer;

use crate::dumper::Dumper;
use crate::errors::Error;
use crate::metadata::Metadata;
use crate::requests::Requests;
use crate::writer::OradazWriter;

use ansi_term::Style;
use chrono::prelude::DateTime;
use chrono::{Datelike, Timelike, Utc};
use clap::Parser;
use log::{debug, error, info};
use regex::Regex;
use serde_json::Value;
use std::path::Path;
use std::process;
use std::sync::{Arc, Mutex};

pub const FL: usize = 25;
pub const VERSION: &str = "2.0.01.28";
pub const SCHEMA_URL: &str = "https://raw.githubusercontent.com/ANSSI-FR/ORADAZ/master/schema.json";

#[derive(Parser)]
#[command(name = "ORADAZ")]
#[command(version = VERSION)]
#[command(about = "Collect the configuration of an Azure tenant", long_about = None)]
pub struct Cli {
    /// Config file
    #[arg(
        short,
        long,
        value_name = "FILE",
        default_value_t = String::from("config-oradaz.xml")
    )]
    config_file: String,

    /// Tenant GUID [if not set, will look in config file, then prompt the user]
    #[arg(short, long)]
    tenant: Option<String>,

    /// AppId to use for the Graph and Management API [if not set, will look in config file, then prompt the user]
    #[arg(short, long)]
    app_id: Option<String>,

    /// Output folder [default: current folder]
    #[arg(short, long, value_name = "FOLDER")]
    output: Option<String>,

    /// Optional: proxy address
    #[arg(short, long, value_name = "PROXY_ADDRESS")]
    proxy: Option<String>,

    /// Optional: proxy username
    #[arg(short = 'u', long)]
    proxy_username: Option<String>,

    /// Optional: proxy password
    #[arg(short = 'w', long)]
    proxy_password: Option<String>,

    /// Optional: file where the schema is defined [default: download from GitHub]
    #[arg(short, long, value_name = "FILE")]
    schema_file: Option<String>,

    /// Do not print anything except errors
    #[arg(short, long)]
    quiet: bool,

    /// Raise the logging level to debug
    #[arg(short, long)]
    debug: bool,
}

fn exit() {
    eprintln!("Press Enter to exit.");
    let _ = std::io::stdin().read_line(&mut String::new());
    process::exit(1);
}

fn main() {
    // Enable colors for Windows
    #[cfg(target_os = "windows")]
    let _ = ansi_term::enable_ansi_support();

    // Parse args
    let cli: Cli = Cli::parse();

    // Initialize logging
    logger::initialize(None, cli.quiet, cli.debug);

    // Check if output folder exists
    let output = match cli.output.as_deref() {
        Some(o) => Path::new(o),
        None => Path::new("."),
    };
    if !output.is_dir() {
        error!("{:FL$}Output folder {} does not exist. Create it or change the output folder in the arguments.", "main", output.display());
        return exit();
    }

    // Parse configuration
    let config_parser = match config::ConfigParser::new(&cli.config_file) {
        Err(error) => {
            error!("{:FL$}{}", "main", error);
            return exit();
        }
        Ok(o) => o,
    };
    let config = match config_parser.deserialize() {
        Err(error) => {
            error!("{:FL$}{}", "main", error);
            return exit();
        }
        Ok(config) => config,
    };

    // Client for HTTP(S) requests
    let requests: Requests = match Requests::new(&config, &cli) {
        Ok(r) => r,
        Err(err) => {
            error!("{:FL$}{}", "main", err);
            return exit();
        }
    };

    // Check if tenant and app_id are in option, then config file, then prompt user
    let now: DateTime<Utc> = Utc::now();
    let (_is_common_era, year) = now.year_ce();
    let mut tenant: String = match &cli.tenant.as_deref() {
        Some(t) => t.to_string(),
        None => {
            if !&config.tenant.is_empty() {
                config.app_id.clone()
            } else {
                let mut tid: String = String::new();
                println!("Enter your tenant ID :");
                let _ = std::io::stdin().read_line(&mut tid);
                tid = tid
                    .strip_suffix("\r\n")
                    .or_else(|| tid.strip_suffix('\n'))
                    .unwrap_or(&tid)
                    .to_string();
                tid
            }
        }
    };

    // Validate given tenant is a tenant ID or get a tenant ID considering input as a domain name
    let expected_format: Regex =
        match Regex::new(r"^.*[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$") {
            Ok(re) => re,
            Err(err) => {
                error!(
                    "{:FL$}Could not compute regex to validate tenant name.",
                    "main"
                );
                error!("{:FL$}{}", "main", Error::RegexError);
                debug!("{}", err);
                return exit();
            }
        };
    if !expected_format.is_match(&tenant) {
        match requests
            .client
            .get(format!(
                "https://odc.officeapps.live.com/odc/v2.1/federationprovider?domain={}",
                tenant
            ))
            .send()
        {
            Err(err) => {
                error!(
                        "{:FL$}Provided tenant {:?} is not a tenant ID and an error occured while trying to retrieve one from given tenant",
                        "main", tenant
                    );
                error!("{}", err);
                return exit();
            }
            Ok(res) => {
                // Parse response
                match res.status().as_u16() {
                    200 => {
                        let response: Value = match res.json::<Value>() {
                            Ok(v) => v,
                            Err(err) => {
                                error!(
                                    "{:FL$}Error getting config for tenant {:?}",
                                    "main", tenant
                                );
                                error!("{}", err);
                                return exit();
                            }
                        };
                        match response.pointer("/tenantId") {
                            Some(s) => match s.as_str() {
                                Some(t) => {
                                    if !expected_format.is_match(t) {
                                        error!(
                                            "{:FL$}Invalid tenant ID {:?} retrieved from config for tenant {:?}",
                                            "main", t, tenant
                                        );
                                        return exit();
                                    }
                                    tenant = t.to_string()
                                }
                                None => {
                                    error!(
                                        "{:FL$}Invalid tenant ID retrieved from config for tenant {:?}",
                                        "main", tenant
                                    );
                                    return exit();
                                }
                            },
                            None => {
                                error!(
                                    "{:FL$}Error getting tenant ID from config for tenant {:?}",
                                    "main", tenant
                                );
                                return exit();
                            }
                        }
                    }
                    c => {
                        error!(
                                "{:FL$}Provided tenant {:?} is not a tenant ID and no configuration could be retrieved",
                                "main", tenant
                            );
                        error!("HTTP code {}", c);
                        return exit();
                    }
                }
            }
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

    let app_id: String = match &cli.app_id.as_deref() {
        Some(a) => a.to_string(),
        None => {
            if !&config.app_id.is_empty() {
                config.app_id.clone()
            } else {
                let mut aid: String = String::new();
                println!("Enter your application AppID :");
                let _ = std::io::stdin().read_line(&mut aid);
                aid = aid
                    .strip_suffix("\r\n")
                    .or_else(|| aid.strip_suffix('\n'))
                    .unwrap_or(&aid)
                    .to_string();
                aid
            }
        }
    };

    // Create Writer based on config and add it to logging
    let writer: Arc<Mutex<OradazWriter>> = match OradazWriter::new(&config, output, &archive_name) {
        Ok(w) => Arc::new(Mutex::new(w)),
        Err(err) => {
            error!("{:FL$}{}", "main", err);
            return exit();
        }
    };
    logger::add_writer(&writer);
    debug!(
        "{:FL$}Successfully added writer for ORADAZ version {}",
        "main", VERSION
    );

    // Write config options (with the exception of credentials)
    if let Err(err) = config.write(&writer) {
        error!("{:FL$}{}", "main", err);
        return exit();
    };

    // Create dumper (parse schema file, authenticate, check prerequisites, etc.)
    let mut dumper: Dumper = match Dumper::new(&tenant, &app_id, &writer, &config, &cli, requests) {
        Err(error) => {
            error!("{:FL$}{}", "main", error);
            match writer.lock() {
                Ok(mut w) => {
                    if let Err(err) = w.set_broken() {
                        error!("{:FL$}{}", "main", err);
                    };
                }
                Err(err) => {
                    error!(
                        "{:FL$}Error while locking Writer, could not treat archive as broken",
                        "main"
                    );
                    error!("{:FL$}{}", "main", Error::WriterLock);
                    debug!("{}", err);
                }
            }
            return exit();
        }
        Ok(d) => {
            println!("\n");
            info!("{:FL$}Successfully created dumper", "main");
            d
        }
    };

    // Begin dump
    info!(
        "{:FL$}Starting dump. {}",
        "main",
        Style::new()
            .bold()
            .paint("This can take a while, do not close the window")
    );
    let start = Utc::now().time();
    let requests_count: usize = match dumper.dump() {
        Ok(rc) => rc,
        Err(error) => {
            error!("{:FL$}{}", "main", error);
            match writer.lock() {
                Ok(mut w) => {
                    if let Err(err) = w.set_broken() {
                        error!("{:FL$}{}", "main", err);
                    };
                }
                Err(err) => {
                    error!(
                        "{:FL$}Error while locking Writer, could not treat archive as broken",
                        "main"
                    );
                    error!("{:FL$}{}", "main", Error::WriterLock);
                    debug!("{}", err);
                }
            }
            return exit();
        }
    };
    let end = Utc::now().time();
    info!(
        "{:FL$}Finished dump using {} requests in {:02}:{:02}:{:02}",
        "main",
        requests_count,
        (end - start).num_hours(),
        (end - start).num_minutes() % 60,
        (end - start).num_seconds() % 60
    );

    // Write metadata
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
    );
    match metadata.write(&writer) {
        Err(error) => {
            error!("{:FL$}{}", "main", error);
            match writer.lock() {
                Ok(mut w) => {
                    if let Err(err) = w.set_broken() {
                        error!("{:FL$}{}", "main", err);
                    };
                }
                Err(err) => {
                    error!(
                        "{:FL$}Error while locking Writer, could not treat archive as broken",
                        "main"
                    );
                    error!("{:FL$}{}", "main", Error::WriterLock);
                    debug!("{}", err);
                }
            }
            return exit();
        }
        Ok(s) => s,
    };

    // Finalize MLA archive
    match writer.lock() {
        Ok(mut w) => {
            if let Err(err) = w.finalize() {
                error!("{:FL$}{}", "main", err);
                exit();
            };
        }
        Err(err) => {
            error!(
                "{:FL$}Error while locking Writer, could not treat archive as broken",
                "main"
            );
            error!("{:FL$}{}", "main", Error::WriterLock);
            debug!("{}", err);
            exit();
        }
    }

    println!("\n");
    info!("Dump finished correctly, please send the mla file '{}.mla' without renaming or encrypting it (it is already encrypted).", archive_name);
}
