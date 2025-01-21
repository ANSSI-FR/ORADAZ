use crate::errors::Error;
use crate::writer::OradazWriter;

use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use std::fs::{self};
use std::sync::{Arc, Mutex};

const FL: usize = crate::FL;

#[derive(Clone, Deserialize, Serialize)]
pub struct ServiceConfig {
    pub name: String,
    #[serde(rename = "$value")]
    pub value: bool,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ServicesConfig {
    #[serde(rename = "$value")]
    pub services: Vec<ServiceConfig>,
}

#[derive(Clone, Deserialize)]
pub struct ProxyConfig {
    pub url: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Clone, Deserialize)]
pub struct Config {
    pub tenant: String,
    pub app_id: String,
    pub services: Option<ServicesConfig>,
    pub proxy: Option<ProxyConfig>,
    #[serde(rename = "outputFiles")]
    pub output_files: bool,
    #[serde(rename = "outputMLA")]
    pub output_mla: bool,
    #[serde(rename = "noCheck")]
    pub no_check: Option<bool>,
    #[serde(rename = "requestsThreads")]
    pub requests_threads: Option<usize>,
    #[serde(rename = "writerThreads")]
    pub writer_threads: Option<usize>,
}

#[derive(Serialize)]
struct StoredConfig {
    pub tenant: String,
    pub app_id: String,
    pub services: Option<ServicesConfig>,
    pub proxy: bool,
    #[serde(rename = "outputFiles")]
    pub output_files: bool,
    #[serde(rename = "outputMLA")]
    pub output_mla: bool,
    #[serde(rename = "noCheck")]
    pub no_check: Option<bool>,
    #[serde(rename = "requestsThreads")]
    pub requests_threads: Option<usize>,
    #[serde(rename = "writerThreads")]
    pub writer_threads: Option<usize>,
}

impl Config {
    pub fn service_enable(config: &Config, name: &String) -> bool {
        /*
        Check if service with given name is enabled in config file
        */
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

    pub fn write(&self, writer: &Arc<Mutex<OradazWriter>>) -> Result<(), Error> {
        /*
        Write configuration options in archive, with the exception of credentials
        */
        let config: StoredConfig = StoredConfig {
            tenant: self.tenant.clone(),
            app_id: self.app_id.clone(),
            services: self.services.clone(),
            proxy: self.proxy.is_some(),
            output_files: self.output_files,
            output_mla: self.output_mla,
            no_check: self.no_check,
            requests_threads: self.requests_threads,
            writer_threads: self.writer_threads,
        };
        let config_str = match serde_json::to_string(&config) {
            Err(err) => {
                error!("{:FL$}Could not convert config to json", "Config");
                debug!("{}", err);
                return Err(Error::ConfigToJSON);
            }
            Ok(j) => j,
        };
        match writer.lock() {
            Ok(mut w) => {
                w.write_file(String::new(), "config.json".to_string(), config_str)?;
            }
            Err(err) => {
                error!("{:FL$}Error while locking Writer to write config", "Config");
                debug!("{}", err);
                return Err(Error::WriterLock);
            }
        }
        Ok(())
    }
}

pub struct ConfigParser {
    config_file: String,
}

impl ConfigParser {
    pub fn new(config_file: &str) -> Result<ConfigParser, Error> {
        /*
        Create new parser for provided config file
        */
        if fs::metadata(config_file).is_err() {
            error!("{:FL$}Invalid config file provided", "ConfigParser");
            return Err(Error::ConfigFileNotFound);
        }
        info!("{:FL$}Using config file {}", "ConfigParser", config_file);
        Ok(ConfigParser {
            config_file: config_file.to_string(),
        })
    }

    pub fn deserialize(self) -> Result<Config, Error> {
        /*
        Parse config file into Config structure
        */
        let config_str: String = match fs::read_to_string(&self.config_file) {
            Err(err) => {
                error!(
                    "{:FL$}Cannot open config file {}.",
                    "ConfigParser", &self.config_file
                );
                debug!("{}", err);
                return Err(Error::IOError(err));
            }
            Ok(res) => res,
        };
        match serde_xml_rs::from_str::<Config>(&config_str) {
            Ok(config) => Ok(config),
            Err(err) => {
                error!("{:FL$}Could not parse config file", "ConfigParser");
                debug!("{}", err);
                Err(Error::InvalidConfigXMLStructure)
            }
        }
    }
}
