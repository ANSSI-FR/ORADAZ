use crate::auth::TokenResponse;
use crate::errors::Error;
use crate::config::{Config, Condition, Key, Request, Service, Schema};
use crate::metadata::TablesMetadata;
use crate::exit;

use chrono::Utc;
use log::{error, warn, info, debug};
use mla::{ArchiveFileID, ArchiveWriter};
use rand::{seq::SliceRandom, thread_rng};
use rayon::ThreadPoolBuilder;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{sync, thread, time};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

const FL: usize = crate::FL;

#[derive(Serialize, Deserialize)]
pub struct DumpError {
    filename: String,
    url: String,
    status: String,
    code: String,
    message: String,
}

#[derive(Clone)]
struct Relationship {
    filename: String,
    url: String,
    keys: Vec<Key>,
    conditions: Vec<Condition>,
    relationships: Vec<Relationship>,
}

#[derive(Clone)]
struct Url {
    api: String,
    filename: String,
    url: String,
    error_code: String,
    error_message: String,
    next_link: String,
    relationships: Vec<Relationship>,
    keys: Vec<Key>,
}

pub struct Dumper {
    urls: Vec<Url>,
    pub errors: Vec<DumpError>,
    pub tables: Vec<TablesMetadata>,
    threads: usize,
    pub request_count: usize,
    client: reqwest::blocking::Client
}

impl Dumper {
    pub fn new(token_keys: &[String], config: &Config, schema: &Schema, tenant: &str) -> Self {
        let mut urls = Vec::new();
        let services: &Vec<Service> = &schema.services;
        for s in services.iter() {
            if !token_keys.contains(&s.name) {
                continue;
            }
            let base_url = &s.base_url;
            let uri_scheme = &s.uri_scheme;
            let default_api_version = &s.api_version;
            let requests: &Vec<Request> = &s.requests;
            for request in requests.iter() {
                let url_string = get_url(tenant, base_url, uri_scheme, default_api_version, &request.uri, &request.api_version, &request.select, &request.param, &request.keys);
                let relationships_names: &Vec<String> = &request.relationships;
                let relationships: Vec<Relationship> = get_relationships(tenant, s, relationships_names);
                let keys: Vec<Key> = Vec::new();
                let url: Url = Url {
                    api: s.name.to_string().to_string(),
                    filename: request.name.to_string().to_string(),
                    url: url_string,
                    error_code: s.error_code.to_string().to_string(),
                    error_message: s.error_message.to_string().to_string(),
                    next_link: s.next_link.to_string().to_string(),
                    relationships,
                    keys
                };
                urls.push(url);
            }
        };
        urls.shuffle(&mut thread_rng());
        let client = reqwest::blocking::Client::new();

        Self {
            urls,
            errors: Vec::new(),
            tables: Vec::new(),
            threads: config.threads,
            request_count: 0,
            client,
        }
    }

    pub fn dump<'a>(&mut self, tokens: &mut HashMap<String, TokenResponse>, mla_archive: &mut Option<ArchiveWriter<'a, &File>>, config_output_files: bool, output_folder: &str, log_file_path: &PathBuf) {
        let pool = match ThreadPoolBuilder::new().num_threads(self.threads).build() {
            Ok(p) => p,
            Err(_e) => {
                error!("{:FL$}Cannot create multithread pool to perform the dump", "dump");
                error!("{:FL$}{}", "", Error::ThreadPoolBuilderCreationError);
                return exit(&log_file_path, mla_archive, Some(&output_folder));
            }
        };

        let mut request_count: usize = 0;
        let mut new_urls: Vec<Url> = Vec::new();
        let mut files: HashMap<String, ArchiveFileID> = HashMap::new();
        let mut tables: HashMap<String, TablesMetadata> = HashMap::new();
        
        if config_output_files {
            if let Err(err) = fs::create_dir(&format!("{}/objects", output_folder)) {
                error!("{:FL$}Cannot create directory {}/objects - {}", "main", output_folder, err);
                return exit(&log_file_path, mla_archive, Some(&output_folder));
            };
        };

        let mut wait = false;
        while !self.urls.is_empty() {
            request_count += self.urls.len();
            let (tx, rx) = sync::mpsc::channel();

            if wait {
                info!("{:FL$}Waiting 2 seconds due to error code 429", "dump");
                thread::sleep(time::Duration::from_millis(2000));
            };
            wait = false;

            self.urls.iter().for_each(|url| {
                let tx = tx.clone();
                let thread_api = url.api.clone();
                let mut thread_token: TokenResponse;
                if let Some(token) = tokens.get_mut(&thread_api) {
                        thread_token = token.clone();
                } else {
                    error!("{:FL$}Missing token for api {}", "dump", thread_api);
                    error!("{:FL$}{}", "", Error::MissingApiTokenError);
                    return exit(&log_file_path, mla_archive, Some(&output_folder));
                };
                if thread_token.expires_on - Utc::now().timestamp() < 600 {
                    if let Err(e) = thread_token.refresh_token() {
                        error!("{:FL$}{}", "", e);
                        return exit(&log_file_path, mla_archive, Some(&output_folder));
                    };
                    let new_token = thread_token.clone();
                    tokens.insert(thread_api.to_string(), new_token);
                }
                let access_token = match &thread_token.access_token {
                    None => String::from(""),
                    Some(access_token) => access_token.clone()
                };
                if access_token == *"" {
                    error!("{:FL$}Missing token for api {}", "dump", thread_api);
                    error!("{:FL$}{}", "", Error::MissingApiTokenError);
                    return exit(&log_file_path, mla_archive, Some(&output_folder));
                } else {
                    let mut thread_url = url.clone();
                    thread_url.url = thread_url.url.replace("//", "/").replace("https:/", "https://");
                    let thread_client = self.client.clone();
                    pool.spawn(move || {
                        match ApiRequest::new(&thread_url, &access_token, &thread_client) {
                            Ok(resp) => tx.send(ApiResponse::ApiRequest(Box::new(resp))).unwrap(),
                            Err(_e) => tx.send(ApiResponse::Url(thread_url)).unwrap(),
                        };
                    });
                }
            });
            drop(tx);
            rx.into_iter().for_each(|resp| {
                match resp {
                    ApiResponse::ApiRequest(r) => {
                        if r.response.status().as_u16() == 429 {
                            debug!("{:FL$}Error 429 for API {} with url {}", "dump", r.url.api, r.url.url);
                            new_urls.push(r.url);
                            wait = true;
                        } else if !r.response.status().is_success() {
                            let filename: &str = &r.url.filename.clone();
                            match r.handle_error(filename) {
                                Ok(e) => self.errors.push(e),
                                Err(e) => {
                                    error!("{:FL$}{}", "", e);
                                    return exit(&log_file_path, mla_archive, Some(&output_folder));
                                }
                            }
                        } else {
                            let filename: &str = &r.url.filename.clone();
                            let url = r.url.clone();
                            match r.handle_success() {
                                Ok((nl, nu, data)) => {
                                    if let Some(n) = nl {
                                        new_urls.push(n);
                                    };
                                    let mut relationships = nu;
                                    new_urls.append(&mut relationships);
                                    let mut data_count = data.len();
                                    match tables.get(filename) {
                                        None => (),
                                        Some(t) => data_count += t.count,
                                    }
                                    tables.insert(filename.to_string(), TablesMetadata {
                                        file: format!("objects\\{}.json", filename),
                                        table_name: filename.to_string(),
                                        count: data_count,
                                    });
                                    for d in data {
                                        let to_write = format!("{}\n", d);
                                        match files.get(filename) {
                                            None => {
                                                if let Some(mla) = mla_archive {
                                                    let id_file = mla.start_file(&format!("objects/{}.json", filename)).unwrap();
                                                    files.insert(filename.to_string(), id_file);
                                                    mla.append_file_content(id_file, to_write.len() as u64, to_write.as_bytes()).unwrap();
                                                };
                                                if config_output_files {
                                                    let mut data_file = match File::create(&format!("{}/objects/{}.json", output_folder, filename)) {
                                                        Err(e) => {
                                                            error!("{:FL$}Could not create output file {} in unencrypted folder", "dump", filename); 
                                                            error!("{:FL$}{}", "", Error::IOError(e));
                                                            return exit(&log_file_path, mla_archive, Some(&output_folder));
                                                        },
                                                        Ok(f) => f,
                                                    };
                                                    if let Err(e) = data_file.write_all(to_write.as_bytes()) {
                                                        error!("{:FL$}Could not write data to output file {} in unencrypted folder", "dump", filename); 
                                                        error!("{:FL$}{}", "", Error::IOError(e));
                                                        return exit(&log_file_path, mla_archive, Some(&output_folder));
                                                    };
                                                };
                                            },
                                            Some(id) => {
                                                if let Some(mla) = mla_archive {
                                                    mla.append_file_content(*id, to_write.len() as u64, to_write.as_bytes()).unwrap();
                                                };
                                                if config_output_files {
                                                    let mut data_file = match OpenOptions::new().write(true).append(true).open(&format!("{}/objects/{}.json", output_folder, filename)) {
                                                        Err(e) => {
                                                            error!("{:FL$}Could not open output file {} in unencrypted folder", "dump", filename); 
                                                            error!("{:FL$}{}", "", Error::IOError(e));
                                                            return exit(&log_file_path, mla_archive, Some(&output_folder));
                                                        },
                                                        Ok(f) => f,
                                                    };
                                                    if let Err(e) = data_file.write_all(to_write.as_bytes()) {
                                                        error!("{:FL$}Could not write data to output file {} in unencrypted folder", "dump", filename); 
                                                        error!("{:FL$}{}", "", Error::IOError(e));
                                                        return exit(&log_file_path, mla_archive, Some(&output_folder));
                                                    };
                                                }
                                            },
                                        }
                                    }
                                },
                                Err(e) => {
                                    error!("{:FL$}{}", "", e);
                                    new_urls.push(url);
                                }
                            }
                        };
                    },
                    ApiResponse::Url(url) => {
                        new_urls.push(url);
                    },
                }
            });
            // Priority to nextlink urls
            if new_urls.len() <= self.threads {
                self.urls = new_urls.clone();
                new_urls = Vec::new();
            } else {
                let tmp_urls = new_urls.clone();
                let (left, right) = tmp_urls.split_at(self.threads);
                self.urls = left.to_vec().clone();
                new_urls = right.to_vec().clone();
            }
        }
        for (_filename, id) in files {
            if let Some(mla) = mla_archive {
                mla.end_file(id).unwrap();
            }
        }
        self.tables = tables.values().cloned().collect();
        self.request_count = request_count;
    }
}

enum ApiResponse {
    Url(Url),
    ApiRequest(Box<ApiRequest>),
}

struct ApiRequest {
    url: Url,
    response: reqwest::blocking::Response,
}

impl ApiRequest {
    pub fn new(url: &Url, access_token: &str, client: &reqwest::blocking::Client) -> Result<Self, Error> {
        let response = match client.get(&url.url)
            .header(reqwest::header::AUTHORIZATION, &format!("Bearer {}", access_token))
            .header("x-ms-client-request-id", "5b565221-a13a-4b72-a77f-7d055c91f0ab") // Random request id for unsupported main API
            .header("x-ms-client-session-id", "f87c8a7bf35d4a55b9644065931fb92a") // Random session id for unsupported main API
            .send() {
            Err(e) => {
                warn!("{:FL$}Cannot perform request to url {}. Will retry later.", "ApiRequest", url.url);
                warn!("{:FL$}\t{}", "", e);
                return Err(Error::InvalidRequestError);
            },
            Ok(res) => res
        };
        Ok(Self {
            url: url.clone(),
            response,
        })
    }

    pub fn handle_error(self, filename: &str) -> Result<DumpError, Error> {
        warn!("{:FL$}An error occured for url {}", "dump", self.url.url);
        let status = String::from(self.response.status().as_str());
        let response = &self.response.text().unwrap();
        let mut code: String = String::from("Unknown");
        let message: String;
        let error: Result<Value, serde_json::Error> = serde_json::from_str(response);
        match error {
            Ok(e) => {
                code = match e.pointer(&format!("/{}", self.url.error_code)) {
                    Some(v) => v.as_str().unwrap().to_string(),
                    None => String::from("Unknown"),
                };
                message = match e.pointer(&format!("/{}", self.url.error_message)) {
                    Some(v) => v.as_str().unwrap().to_string(),
                    None => String::from("Unknown"),
                };
            },
            Err(_) => {
                message = response.to_string();
            },
        };
        warn!("{:FL$}\t{} - {} - {}", "", status, code, message);

        Ok(DumpError {
            filename: filename.to_string(),
            url: self.url.url,
            status,
            code,
            message,
        })
    }

    pub fn handle_success(self) -> Result<(Option<Url>, Vec<Url>, Vec<Value>), Error> {
        let mut new_urls: Vec<Url> = Vec::new();
        
        let response_text = match self.response.text() {
            Ok(e) => e,
            Err(_e) => {
                error!("{:FL$}Cannot parse response for request to url {}", "handle_success", self.url.url);
                return Err(Error::ParsingError);
            },
        };
        let response: Value = match serde_json::from_str(response_text.as_str()) {
            Ok(e) => e,
            Err(_e) => {
                error!("{:FL$}Cannot parse response for request to url {}", "handle_success", self.url.url);
                return Err(Error::ParsingError);
            },
        };
        let next_links: Option<Url> = match response.pointer(&format!("/{}", self.url.next_link)) {
            Some(e) => {
                let mut new_url = self.url.clone();
                if new_url.api == "intAPI" {
                    let next_link = e.as_str().unwrap().to_string();
                    if next_link.starts_with("https://") {
                        new_url.url = format!("{}&api-version=1.61-internal", next_link);
                    } else if next_link.starts_with("directoryObjects") {
                        let url_parts: Vec<String> = new_url.url.split('/').map(|s| s.to_string()).collect();
                        let url_start = &url_parts[0..4].join("/");
                        new_url.url = format!("{}/{}&api-version=1.61-internal", url_start, next_link);
                    } else {
                        let url_parts: Vec<String> = new_url.url.split('/').map(|s| s.to_string()).collect();
                        let useful_len = url_parts.len() - 1;
                        let url_start = &url_parts[0..useful_len].join("/");
                        new_url.url = format!("{}/{}&api-version=1.61-internal", url_start, next_link);
                    }
                    Some(new_url)
                } else {
                    match e.as_str() {
                        None => None,
                        Some(a) => {
                            new_url.url = a.to_string();
                            Some(new_url)
                        },
                    }
                }
            },
            None => None,
        };
        let initial_data: Vec<Value> = match response.pointer("/value") {
            Some(e) => e.as_array().unwrap().to_vec(),
            None => {
                match response {
                    Value::Array(r) => r,
                    Value::Object(o) => vec![Value::Object(o)],
                    _ => vec![json!({"result": response.clone()})]
                }
            },
        };
        let mut data: Vec<Value> = Vec::new();
        for d in initial_data {
            let mut elmt: Value = d.clone();
            for key in &self.url.keys {
                elmt[&format!("_parentObject_{}", key.name)] = json!(key.value.clone());
            }
            data.push(elmt);
        };

        for obj in data.clone() {
            let relationships = self.url.relationships.clone();
            for relationship in relationships {
                if !relationship.conditions.is_empty() {
                    let mut matched_conditions = true;
                    for c in relationship.conditions {
                        let operator: &str = &c.operator;
                        match operator {
                            "contains" => {
                                let v: Vec<String> = match obj.pointer(&format!("/{}", c.parameter)) {
                                    Some(e) => {
                                        let mut res: Vec<String> = Vec::new();
                                        for i in e.as_array().unwrap() {
                                            res.push(i.to_string());
                                        }
                                        res
                                    },
                                    None => {
                                        error!("{:FL$}Cannot find parameter {} in response to url {}", "handle_success", c.parameter, self.url.url);
                                        error!("{:FL$}{}", "handle_success", obj);
                                        return Err(Error::ParsingError);
                                    },
                                };
                                if !v.contains(&c.value) {
                                    matched_conditions = false;
                                }
                            },
                            _ => {
                                error!("{:FL$}Operator {} not yet implemented for conditional relationships", "handle_success", c.operator);
                                return Err(Error::OperatorNotImplementedError);
                            }
                        }
                    }
                    if !matched_conditions {
                        continue;
                    }
                }
                let mut new_url = self.url.clone();
                new_url.filename = relationship.filename.clone();
                new_url.relationships = relationship.relationships.clone();
                let mut url: String = relationship.url.clone();
                let mut new_keys: Vec<Key> = Vec::new();
                for key in relationship.keys {
                    if key.name == "[URL]" {
                        let mut previous_url: &str = new_url.url.as_str();
                        previous_url = previous_url.split('?').collect::<Vec<&str>>()[0];
                        let mut part_url: &str = url.as_str();
                        part_url = part_url.split("[URL]").collect::<Vec<&str>>()[1];
                        let replaced: String = format!("{}{}", previous_url, part_url);
                        url = replaced.clone();
                        continue;
                    };
                    let mut v: String = match obj.pointer(&format!("/{}", key.value)) {
                        Some(e) => e.as_str().unwrap().to_string(),
                        None => {
                            error!("{:FL$}Cannot find key {} in response to url {}", "handle_success", key.value, self.url.url);
                            error!("{:FL$}{}", "handle_success", obj);
                            return Err(Error::ParsingError);
                        },
                    };
                    new_keys.push(Key{
                        name: key.value.clone(),
                        value: v.clone(),
                        encoded: false
                    });
                    if key.encoded {
                        let to_encode = v.as_bytes();
                        v = base64::encode(to_encode);
                    } 
                    let replaced: String = (&url.replace(&key.name, &v)).to_string();
                    url = replaced.clone();
                };
                new_url.url = url;
                new_url.keys = new_keys;
                new_urls.push(new_url);
            }
        }

        Ok((next_links, new_urls, data))
    }
}

fn get_url(tenant: &str, base_url: &str, uri_scheme: &str, default_api_version: &str, uri: &str, api_version: &str, attributes: &[String], param: &str, keys: &Vec<Key>) -> String {
    let mut version = default_api_version;
    if !api_version.is_empty() {
        version = api_version;
    }
    let mut parameters: String = String::from("");
    if !attributes.is_empty() {
        if uri_scheme.contains('?') {
            parameters = format!("&$select={}", attributes.join(","));
        } else {
            parameters = format!("?$select={}", attributes.join(","));
        }
    }
    if !param.is_empty() {
        if uri_scheme.contains('?') {
            parameters = format!("{}&{}", parameters, param);
        } else {
            parameters = format!("?{}", param);
        }
    }

    let mut url_string = format!("{}{}", base_url, uri_scheme);
    
    for key in keys {
        url_string = (&url_string.replace(&key.name, &key.value)).to_string();
    };

    url_string = url_string.replace("[VERSION]", version)
        .replace("[URI]", uri)
        .replace("[TENANT]", tenant)
        .replace("[PARAMS]", &parameters)
        ;
    
    url_string
}

fn get_relationships(tenant: &str, service: &Service, names: &[String]) -> Vec<Relationship> {
    let mut relationships = Vec::new();
    let base_url = &service.base_url;
    let uri_scheme = &service.uri_scheme;
    let default_api_version = &service.api_version;
    for r in &service.relationships {
        if !names.contains(&r.name) {
            continue;
        }
        let tmp = Vec::new();
        let url_string = get_url(tenant, base_url, uri_scheme, default_api_version, &r.uri, &r.api_version, &r.select, &r.param, &tmp);
        let mut keys: Vec<Key> = Vec::new();
        for k in &r.keys {
            keys.push(k.clone());
        }
        let relationships_names: &Vec<String> = &r.relationships;
        let new_relationships: Vec<Relationship> = get_relationships(tenant, service, relationships_names);
        let relationship: Relationship = Relationship {
            filename: r.name.to_string().to_string(),
            url: url_string,
            keys,
            relationships: new_relationships,
            conditions: r.conditions.clone()
        };
        relationships.push(relationship);
    }
    relationships
} 
