use crate::errors::Error;

use log::{error, info};
use mla::ArchiveWriter;
use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, Write};

const FL: usize = crate::FL;
const SCHEMA_URL: &str = crate::SCHEMA_URL;
const VERSION: &str = crate::VERSION;

#[derive(Clone, Deserialize)]
pub struct Attribute {
    pub name: String,
}

#[derive(Clone, Deserialize)]
pub struct RelationshipName {
    pub name: String,
}

#[derive(Clone, Deserialize)]
pub struct Request {
    pub name: String,
    pub uri: String,
    #[serde(default)]
    pub api_version: String,
    #[serde(default)]
    pub mandatory: bool,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_select")]
    pub select: Vec<String>,
    #[serde(default)]
    pub param: String,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_keys")]
    pub keys: Vec<Key>,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_relationship_name")]
    pub relationships: Vec<String>,
}

#[derive(Clone, Deserialize)]
pub struct Key {
    #[serde(rename = "$value")]
    pub value: String,
    pub name: String,
    #[serde(default)]
    pub encoded: bool,
}

#[derive(Clone, Deserialize)]
pub struct Condition {
    pub parameter: String,
    pub operator: String,
    pub value: String,
}

#[derive(Clone, Deserialize)]
pub struct Relationship {
    pub name: String,
    pub uri: String,
    #[serde(deserialize_with = "deserialize_keys")]
    pub keys: Vec<Key>,
    #[serde(default)]
    pub api_version: String,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_select")]
    pub select: Vec<String>,
    #[serde(default)]
    pub param: String,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_conditions")]
    pub conditions: Vec<Condition>,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_relationship_name")]
    pub relationships: Vec<String>,
}

#[derive(Clone, Deserialize)]
pub struct Service {
    pub name: String,
    pub description: String,
    pub base_url: String,
    pub uri_scheme: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub resource: String,
    pub api_version: String,
    pub error_code: String,
    pub error_message: String,
    pub next_link: String,
    #[serde(deserialize_with = "deserialize_requests")]
    pub requests: Vec<Request>,
    #[serde(deserialize_with = "deserialize_relationships")]
    pub relationships: Vec<Relationship>,
}

#[derive(Clone, Deserialize)]
pub struct Schema {
    #[serde(rename = "$value")]
    pub services: Vec<Service>,
    pub oradaz_version: String,
    pub schema_version: String
}

fn deserialize_requests<'de, D>(d: D) -> Result<Vec<Request>, D::Error>
where
    D: Deserializer<'de>,
{
    let request_raw: HashMap<String, Vec<Request>> = Deserialize::deserialize(d)?;
    let mut request: Vec<Request> = Vec::new();
    for v in request_raw.values() {
        for r in v.iter() {
            request.push(r.clone());
        }
    };
    Ok(request)
}

fn deserialize_relationships<'de, D>(d: D) -> Result<Vec<Relationship>, D::Error>
where
    D: Deserializer<'de>,
{
    let relationship_raw: HashMap<String, Vec<Relationship>> = Deserialize::deserialize(d)?;
    let mut relationship: Vec<Relationship> = Vec::new();
    for v in relationship_raw.values() {
        for r in v.iter() {
            relationship.push(r.clone());
        }
    };
    Ok(relationship)
}

fn deserialize_keys<'de, D>(d: D) -> Result<Vec<Key>, D::Error>
where
    D: Deserializer<'de>,
{
    let key_raw: HashMap<String, Vec<Key>> = Deserialize::deserialize(d)?;
    let mut key: Vec<Key> = Vec::new();
    for v in key_raw.values() {
        for r in v.iter() {
            key.push(r.clone());
        }
    };
    Ok(key)
}

fn deserialize_relationship_name<'de, D>(d: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let relationship_name_raw: HashMap<String, Vec<RelationshipName>> = Deserialize::deserialize(d)?;
    let mut relationship_name: Vec<String> = Vec::new();
    for v in relationship_name_raw.values() {
        for r in v.iter() {
            let tmp = r.clone();
            relationship_name.push(tmp.name);
        }
    };
    Ok(relationship_name)
}

fn deserialize_conditions<'de, D>(d: D) -> Result<Vec<Condition>, D::Error>
where
    D: Deserializer<'de>,
{
    let condition_raw: HashMap<String, Vec<Condition>> = Deserialize::deserialize(d)?;
    let mut conditions: Vec<Condition> = Vec::new();
    for v in condition_raw.values() {
        for r in v.iter() {
            conditions.push(r.clone());
        }
    };
    Ok(conditions)
}

fn deserialize_select<'de, D>(d: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let select_raw: HashMap<String, Vec<Attribute>> = Deserialize::deserialize(d)?;
    let mut select: Vec<String> = Vec::new();
    for v in select_raw.values() {
        for r in v.iter() {
            let tmp = r.clone();
            select.push(tmp.name);
        }
    };
    Ok(select)
}

pub struct SchemaParser {
    schema: String
}

impl<'a> SchemaParser {
    pub fn new(schema_file: &str, config: &Config, mla_archive: &mut Option<ArchiveWriter<'a, &'a File>>, output_folder: &str, client: &reqwest::blocking::Client) -> Result<SchemaParser, Error> {
        let f: String;
        if schema_file != "" {
            if fs::metadata(schema_file).is_err() {
                error!("{:FL$}Invalid schema file provided", "SchemaParser");
                return Err(Error::SchemaFileNotFoundError);
            }
            info!("{:FL$}Using schema file {}", "SchemaParser", schema_file);
            f = match fs::read_to_string(schema_file) {
                Err(e) => {
                    error!("{:FL$}Cannot open schema file {}.", "SchemaParser", schema_file);
                    return Err(Error::IOError(e));
                },
                Ok(res) => res
            };
        } else {
            f = match client.get(SCHEMA_URL).send() {
                Err(e) => {
                    error!("{:FL$}Cannot retrieve schema file from {}.", "SchemaParser", SCHEMA_URL);
                    error!("{:FL$}\t{}", "", e);
                    return Err(Error::CannotDownloadSchemaFileError);
                },
                Ok(res) => res.text().unwrap()
            };
        }
        if let Some(mla) = mla_archive {
            if let Err(e) = mla.add_file("schema.xml", f.len() as u64, f.as_bytes()) {
                error!("{:FL$}Could not add schema file to archive", "SchemaParser"); 
                return Err(Error::MLAError(e));
            };
        };
        if config.output_files {
            let mut file = match File::create(&format!("{}/schema.xml", output_folder)) {
                Err(e) => {
                    error!("{:FL$}Could not add schema file to unencrypted folder", "SchemaParser"); 
                    return Err(Error::IOError(e));
                },
                Ok(f) => f
            };
            if let Err(e) = file.write_all(f.as_bytes()) {
                error!("{:FL$}Could not add schema file to unencrypted folder", "SchemaParser"); 
                return Err(Error::IOError(e));
            };
        }

        Ok(SchemaParser {
            schema: f
        })
    }

    pub fn deserialize(self, config: &Config) -> Result<Schema, Error> {
        let schema: Result<Schema, _> = serde_xml_rs::from_str(&self.schema);
        match schema {
            Err(e) => {
                error!("{:FL$}Could not parse schema file - {}", "deserialize", e); 
                Err(Error::InvalidSchemaXMLStructureError)
            },
            Ok(schema) => {
                if &schema.oradaz_version != VERSION{
                    error!("{:FL$}This is not the last version of ORADAZ. Please download the last available release.", ""); 
                    return Err(Error::NotLastVersionError);
                }

                let mut services: Vec<Service> = Vec::new();
                let default_services = vec!["graphAPI".to_string(), "intAPI".to_string(), "mainAPI".to_string()];
                for s in &schema.services {
                    if default_services.contains(&s.name) {
                        services.push(s.clone());
                    } else if s.name == "mgmtAPI" {
                        match &config.services {
                            Some(sc) => {
                                for c in &sc.services {
                                    if c.name == "azure_resources" && c.value {
                                        services.push(s.clone());
                                    } else if c.name == "azure_resources" && !c.value {
                                        let mut mandatory_requests: Vec<Request> = Vec::new();
                                        for r in &s.requests {
                                            if r.mandatory {
                                                mandatory_requests.push(r.clone())
                                            }
                                        }
                                        services.push(Service{
                                            name: s.name.clone(),
                                            description: s.description.clone(),
                                            base_url: s.base_url.clone(),
                                            uri_scheme: s.uri_scheme.clone(),
                                            client_id: s.client_id.clone(),
                                            resource: s.resource.clone(),
                                            api_version: s.api_version.clone(),
                                            error_code: s.error_code.clone(),
                                            error_message: s.error_message.clone(),
                                            next_link: s.next_link.clone(),
                                            requests: mandatory_requests,
                                            relationships: s.relationships.clone(),
                                        });

                                    }
                                }
                            },
                            None => ()
                        }
                    } else if s.name == "outlookAPI" {
                        match &config.services {
                            Some(sc) => {
                                for c in &sc.services {
                                    if c.name == "exchange_online" && c.value {
                                        services.push(s.clone());
                                    }
                                }
                            },
                            None => ()
                        }
                    }
                }

                Ok(Schema {
                    oradaz_version: schema.oradaz_version,
                    schema_version: schema.schema_version,
                    services
                })
            }
        }
    }
}


#[derive(Deserialize)]
pub struct ServiceConfig {
    pub name: String,
    #[serde(rename = "$value")]
    pub value: bool,
}

#[derive(Deserialize)]
pub struct ServicesConfig {
    #[serde(rename = "$value")]
    pub services: Vec<ServiceConfig>,
}

#[derive(Deserialize)]
pub struct ProxyConfig {
    pub url: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Deserialize)]
pub struct Config {
    pub tenant: String,
    pub app_id: String,
    pub threads: usize,
    pub services: Option<ServicesConfig>,
    pub proxy: Option<ProxyConfig>,
    #[serde(rename = "outputFiles")]
    pub output_files: bool,
    #[serde(rename = "outputMLA")]
    pub output_mla: bool,
    #[serde(rename = "noCheck")]
    pub no_check: Option<bool>,
}


pub struct ConfigParser {
    config_file: String
}

impl ConfigParser {
    pub fn new(config_file: &str) -> Result<ConfigParser, Error> {
        if fs::metadata(config_file).is_err() {
            error!("{:FL$}Invalid config file provided", "ConfigParser");
            return Err(Error::ConfigFileNotFoundError);
        }
        info!("{:FL$}Using config file {}", "ConfigParser", config_file);
        let config = String::from(config_file);
        Ok(ConfigParser {
            config_file: config
        })
    }

    pub fn deserialize(self) -> Result<Config, Error> {
        let f = fs::File::open(&self.config_file).unwrap_or_else(|_| panic!("Cannot open file {}", &self.config_file));
        let r = BufReader::new(f);
        let jd = &mut serde_xml_rs::de::Deserializer::new_from_reader(r);
        let config: Result<Config, _> = serde_path_to_error::deserialize(jd);
        match config {
            Err(e) => {
                error!("{:FL$}Could not parse config file - {}", "deserialize", e); 
                Err(Error::InvalidConfigXMLStructureError)
            },
            Ok(config) => {
                Ok(config)
            }
        }
    }
}
