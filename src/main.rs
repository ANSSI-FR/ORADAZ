mod prerequisites;
mod logger;

pub mod auth;
pub mod config;
use crate::config::Service;
pub mod dumper;
pub mod errors;
use crate::errors::Error;
pub mod metadata;
use crate::metadata::{PrerequisitesMetadata, TokensMetadata};

use chrono::{Datelike, Timelike, Utc};
use clap::{App, Arg};
use curve25519_parser::parse_openssl_25519_pubkey;
use log::{error, warn, info};
use std::collections::HashMap;
use mla::ArchiveWriter;
use mla::config::ArchiveWriterConfig;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;

pub const FL: usize = 35;
pub const VERSION: &str = "1.0.08.05";
pub const SCHEMA_URL: &str = "https://raw.githubusercontent.com/ANSSI-FR/ORADAZ/master/schema.xml"; 
const PUB_KEY: &[u8] = include_bytes!("./mlakey.pub");


#[derive(Serialize, Deserialize)]
pub struct AuthError {
    api: String,
    error: String
}

pub fn exit<'a>(log_file_path: &PathBuf, mla_archive: &mut Option<ArchiveWriter<'a, &File>>, output_folder: Option<&str>) {
    let filename: &str = &format!("{}", &log_file_path.display());
    let f = File::open(log_file_path).unwrap_or_else(|_| panic!("Cannot open file {}", filename));
    if let Some(mla) = mla_archive {
        if let Err(e) = mla.add_file(filename, f.metadata().unwrap().len() as u64, f) {
            error!("{:FL$}Could not add log file to archive", "main"); 
            error!("{:FL$}{}", "", Error::MLAError(e));
        };
        mla.finalize().unwrap();
    };
    let _ = fs::remove_file(filename);
    if let Some(o) = output_folder {
        let _ = fs::remove_file(o);
    }
    eprintln!("Press Enter to exit.");
    let _ = std::io::stdin().read_line(&mut String::new()).unwrap();
    process::exit(1);
}

fn main() {
    let matches = App::new("ORADAZ")
        .version(VERSION)
        .about("Collect the configuration of an Azure tenant")
        .arg(
            Arg::new("config_file")
                .short('c')
                .long("config_file")
                .takes_value(true)
                .help("Config file (default: config-oradaz.xml)"),
        )
        .arg(
            Arg::new("tenant")
                .short('t')
                .long("tenant")
                .takes_value(true)
                .help("Tenant GUID (if not set, will look in config file, then prompt the user)"),
        )
        .arg(
            Arg::new("app_id")
                .short('a')
                .long("app_id")
                .takes_value(true)
                .help("AppId to use for the Graph and Management API (if not set, will look in config file, then prompt the user)"),
        )
        .arg(
            Arg::new("schema_file")
                .short('s')
                .long("schema_file")
                .takes_value(true)
                .help("File where the schema is defined (default: download from GitHub)"),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .takes_value(true)
                .help("Output folder (default: current folder)"),
        )
        .arg(
            Arg::new("quiet")
                .short('q')
                .long("quiet")
                .takes_value(false)
                .help("Do not print anything except errors"),
        )
        .arg(
            Arg::new("debug")
                .short('d')
                .long("debug")
                .takes_value(false)
                .help("Raise the logging level to debug"),
        )
        .get_matches();

    let mut tenant: &str = matches.value_of("tenant").unwrap_or("");
    let mut app_id: &str = matches.value_of("app_id").unwrap_or("");
    let config_file: &str = matches.value_of("config_file").unwrap_or("config-oradaz.xml");
    let schema_file: &str = matches.value_of("schema_file").unwrap_or("");
    let quiet: bool = matches.is_present("quiet");
    let debug: bool = matches.is_present("debug");
        
    let output = Path::new(matches.value_of("output").unwrap_or("."));
    if !output.is_dir(){
        eprintln!("[ERROR] Output folder {} does not exist. Create it or change the output folder in the arguments.", output.display());
        eprintln!("Press Enter to exit.");
        let _ = std::io::stdin().read_line(&mut String::new()).unwrap();
        process::exit(1);
    }

    let now = Utc::now();
    let (_is_common_era, year) = now.year_ce();
    let collection_date = format!("{}-{:02}-{:02} {:02}:{:02}:{:02}", year, now.month(), now.day(), now.hour(), now.minute(), now.second());

    // Initialize logging
    #[cfg(target_os = "windows")]
    ansi_term::enable_ansi_support();
    let log_file_path = output.join("oradaz.log");
    logger::initialize(
        &log_file_path,
        quiet,
        debug,
    );

    // Parse config file
    let config_parser = match config::ConfigParser::new(config_file) {
        Err(err) => {
            error!("{:FL$}{}", "", err);
            return exit(&log_file_path, &mut None, None);
        },
        Ok(o) => o
    };
    let config = match config_parser.deserialize() {
        Err(err) => {
            error!("{:FL$}{}", "", err);
            return exit(&log_file_path, &mut None, None);
        },
        Ok(config) => config
    };
    let mut services_metadata: HashMap<String, bool> = HashMap::new();
    match &config.services {
        Some(s) => {
            for service in &s.services {
                services_metadata.insert(service.name.to_string().to_string(), service.value);
            };
        },
        None => {
            warn!("{:FL$}Services not defined in config file, will audit all services", "main");
        }
    };
    
    // Check if tenant and app_id are in option, then config file, then prompt user
    let mut tid = String::new();
    if tenant.is_empty() {
        if !&config.tenant.is_empty() {
            tenant = &config.tenant;
        } else {
            println!("Enter your tenant ID :");
            let _s = std::io::stdin().read_line(&mut tid).unwrap();
            tid = tid.strip_suffix("\r\n").or_else(|| tid.strip_suffix('\n')).unwrap_or(&tid).to_string();
            tenant = &tid;
        }
    };
    let tenant_with_time = format!("{}_{}{:02}{:02}-{:02}{:02}{:02}", tenant, year, now.month(), now.day(), now.hour(), now.minute(), now.second());
    let mut aid = String::new();
    if app_id.is_empty() {
        if !&config.app_id.is_empty() {
            app_id = &config.app_id;
        } else {
            println!("Enter your application AppID :");
            let _s = std::io::stdin().read_line(&mut aid).unwrap();
            aid = aid.strip_suffix("\r\n").or_else(|| aid.strip_suffix('\n')).unwrap_or(&aid).to_string();
            app_id = &aid;
        }
    };

    // Create MLA archive if outputMLA set to 1
    let mla_path = output.join(&format!("{}.mla", tenant_with_time));
    let mla_file = match File::create(&mla_path) {
        Err(err) => {
            error!("{:FL$}Could not create output archive {}", "main", mla_path.display());
            error!("{:FL$}{}", "", Error::IOError(err)); 
            return exit(&log_file_path, &mut None, None);
        },
        Ok(f) => f
    };
    let mut mla_archive: Option<ArchiveWriter<&File>> = match config.output_mla {
        true => {
            let public_key = match parse_openssl_25519_pubkey(PUB_KEY) {
                Err(err) => {
                    error!("{:FL$}Invalid public key", "main");
                    error!("{:FL$}{}", "", err); 
                    return exit(&log_file_path, &mut None, None);
                },
                Ok(p) => p
            };
            let mut mla_config = ArchiveWriterConfig::default();
            mla_config.add_public_keys(&[public_key]);
            let mla_archive = match ArchiveWriter::from_config(&mla_file, mla_config) {
                Ok(mla) => mla,
                Err(err) => {
                    error!("{:FL$}Could not create output archive {} from config", "main", mla_path.display()); 
                    error!("{:FL$}{}", "", Error::MLAError(err)); 
                    return exit(&log_file_path, &mut None, None);
                }
            };
            info!("{:FL$}Output archive: {}", "main", mla_path.display());
            Some(mla_archive)
        },
        false => {
            if let Err(err) = fs::remove_file(&mla_path) {
                error!("{:FL$}Cannot remove file {} - {}", "main", mla_path.display(), err);
            };
            None
        }
    };

    // Create output folder if outputFiles is set to 1
    let output_folder = format!("{}", output.join(&tenant_with_time).display());
    if config.output_files {
        if let Err(err) = fs::create_dir(&output_folder) {
            error!("{:FL$}Cannot create directory {} - {}", "main", mla_path.display(), err);
            return exit(&log_file_path, &mut mla_archive, Some(&output_folder));
        };
    }

    // Get and parse schema
    let schema_parser = match config::SchemaParser::new(schema_file, &config, &mut mla_archive, &output_folder) {
        Err(err) => {
            error!("{:FL$}{}", "", err);
            return exit(&log_file_path, &mut mla_archive, Some(&output_folder));
        },
        Ok(o) => o
    };
    let schema = match schema_parser.deserialize(&config) {
        Err(err) => {
            error!("{:FL$}{}", "", err);
            return exit(&log_file_path, &mut mla_archive, Some(&output_folder));
        },
        Ok(schema) => schema
    };

    // Get tokens for each API
    let mut tokens = HashMap::new();
    let mut auth_errors: Vec<AuthError> = Vec::new();
    let services: &Vec<Service> = &schema.services;
    for s in services.iter() {
        match auth::get_token(s, tenant, app_id) {
            Err(Error::StringError(err)) => {
                auth_errors.push(AuthError{
                    api: s.name.clone(),
                    error: err.clone()
                });
                None
            },
            Err(err) => {
                auth_errors.push(AuthError{
                    api: s.name.clone(),
                    error: err.to_string()
                });
                None
            },
            Ok(token) => tokens.insert(s.name.to_string().to_string(), token)
        };
    };
    let mut token_metadata: Vec<TokensMetadata> = Vec::new();
    for (key, value) in &tokens {
        let tm: TokensMetadata = TokensMetadata {
            name: key.to_string(),
            user_id: value.oid.clone(),
            user_principal_name: value.name.clone(),
        };
        token_metadata.push(tm);
        continue;
    };  
    // Write errors
    let j = match serde_json::to_string(&auth_errors) {
        Err(_e) =>  {
            error!("{:FL$}Could not convert auth errors to json", "main"); 
            error!("{:FL$}{}", "", Error::ErrorsToJSONError);
            return exit(&log_file_path, &mut mla_archive, Some(&output_folder));
        },
        Ok(j) => j
    };
    if let Some(ref mut mla) = mla_archive {
        if let Err(e) = mla.add_file("auth_errors.json", j.len() as u64, j.as_bytes()) {
            error!("{:FL$}Could not add auth errors file to archive", "main"); 
            error!("{:FL$}{}", "", Error::MLAError(e));
            return exit(&log_file_path, &mut mla_archive, Some(&output_folder));
        };
    };
    if config.output_files {
        let mut errors_file = match File::create(&format!("{}/auth_errors.json", output_folder)) {
            Err(e) => {
                error!("{:FL$}Could not create auth_errors file in unencrypted folder", "main"); 
                error!("{:FL$}{}", "", Error::IOError(e));
                return exit(&log_file_path, &mut mla_archive, Some(&output_folder));
            },
            Ok(f) => f,
        };
        if let Err(e) = errors_file.write_all(j.as_bytes()) {
            error!("{:FL$}Could not write auth_errors file in unencrypted folder", "main"); 
            error!("{:FL$}{}", "", Error::IOError(e));
            return exit(&log_file_path, &mut mla_archive, Some(&output_folder));
        }
    }

    // Check if the prerequisites are met
    let total_start = Utc::now().time();
    let mut prerequisites_metadata: Vec<PrerequisitesMetadata> = Vec::new();
    match &config.no_check {
        Some(nc) => {
            if !*nc {
                prerequisites_metadata = match prerequisites::check(&mut tokens, tenant, app_id) {
                    Err(err) => {
                        error!("{:FL$}{}", "", err);
                        return exit(&log_file_path, &mut mla_archive, Some(&output_folder));
                    },
                    Ok(p) => p
                };
            }
        },
        None => {
            prerequisites_metadata = match prerequisites::check(&mut tokens, tenant, app_id) {
                Err(err) => {
                    error!("{:FL$}{}", "", err);
                    return exit(&log_file_path, &mut mla_archive, Some(&output_folder));
                },
                Ok(p) => p
            };
        }
    }

    // Perform the dump 
    let mut keys: Vec<String> = Vec::new();
    for key in tokens.keys() {
        keys.push(key.to_string().to_string())
    }
    let mut dumper = dumper::Dumper::new(&keys, &config, schema, tenant);
    info!("{:FL$}Successfully created dumper", "main");
    info!("{:FL$}Starting dump, this can take a while, do not close the window", "main");
    let start = Utc::now().time();
    dumper.dump(&mut tokens, &mut mla_archive, config.output_files, &output_folder, &log_file_path);
    let end = Utc::now().time();
    info!("{:FL$}Finished dump using {} requests in {:02}:{:02}:{:02}", "main", dumper.request_count, (end - start).num_hours(), (end - start).num_minutes() % 60, (end - start).num_seconds() % 60);
    let error_length = dumper.errors.len();

    // Write errors
    let j = match serde_json::to_string(&dumper.errors) {
        Err(_e) =>  {
            error!("{:FL$}Could not convert errors to json", "main"); 
            error!("{:FL$}{}", "", Error::ErrorsToJSONError);
            return exit(&log_file_path, &mut mla_archive, Some(&output_folder));
        },
        Ok(j) => j
    };
    if let Some(ref mut mla) = mla_archive {
        if let Err(e) = mla.add_file("errors.json", j.len() as u64, j.as_bytes()) {
            error!("{:FL$}Could not add errors file to archive", "main"); 
            error!("{:FL$}{}", "", Error::MLAError(e));
            return exit(&log_file_path, &mut mla_archive, Some(&output_folder));
        };
    };
    if config.output_files {
        let mut errors_file = match File::create(&format!("{}/errors.json", output_folder)) {
            Err(e) => {
                error!("{:FL$}Could not create errors file in unencrypted folder", "main"); 
                error!("{:FL$}{}", "", Error::IOError(e));
                return exit(&log_file_path, &mut mla_archive, Some(&output_folder));
            },
            Ok(f) => f,
        };
        if let Err(e) = errors_file.write_all(j.as_bytes()) {
            error!("{:FL$}Could not write errors file in unencrypted folder", "main"); 
            error!("{:FL$}{}", "", Error::IOError(e));
            return exit(&log_file_path, &mut mla_archive, Some(&output_folder));
        }
    }

    // Write metadata
    let total_end = Utc::now().time();
    let metadata = metadata::Metadata::new(&collection_date, &tenant_with_time, VERSION, (end - start).num_seconds(), (total_end - total_start).num_seconds(), error_length, token_metadata, dumper.tables, prerequisites_metadata, services_metadata);
    if let Err(err) = metadata.add_to_output(&mut mla_archive, config.output_files, &output_folder) {
        error!("{:FL$}{}", "", err);
        return exit(&log_file_path, &mut mla_archive, Some(&output_folder));
    };
    
    // Add log file in output
    let filename: &str = &format!("{}", &log_file_path.display());
    let f = File::open(log_file_path).unwrap_or_else(|_| panic!("Cannot open file {}", filename));
    if let Some(mut mla) = mla_archive {
        if let Err(e) = mla.add_file(filename, f.metadata().unwrap().len() as u64, f) {
            error!("{:FL$}Could not add log file to archive", "main"); 
            error!("{:FL$}{}", "", Error::MLAError(e));
        };
        mla.finalize().unwrap();
    };
    if config.output_files {
        if let Err(e) = fs::copy(filename, &format!("{}/oradad.log", output_folder)) {
            error!("{:FL$}Could not copy log file to unencrypted folder", "main"); 
            error!("{:FL$}{}", "", Error::IOError(e));
        };
    }
    if let Err(err) = fs::remove_file(filename) {
        error!("{:FL$}Cannot remove file {} - {}", "main", filename, err);
    };
}
