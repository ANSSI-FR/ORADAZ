use crate::auth::Token;
use crate::conditions::Conditions;
use crate::errors::Error;
use crate::requests::Requests;
use crate::writer::OradazWriter;
use crate::Cli;

use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use log::{debug, error, info, warn};
use rand::{seq::SliceRandom, thread_rng};
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::Value;
use sha256::digest;
use std::collections::HashMap;
use std::fs::{self};
use std::sync::{Arc, Mutex};

const FL: usize = crate::FL;
const VERSION: &str = crate::VERSION;
const SCHEMA_URL: &str = "https://raw.githubusercontent.com/ANSSI-FR/ORADAZ/master/schema.json";

#[derive(Clone, Deserialize)]
pub struct Url {
    pub service_name: String,
    pub service_scopes: Vec<String>,
    pub service_description: String,
    pub service_mandatory_auth: bool,
    pub api: String,
    pub url: String,
    pub conditions: Option<Vec<String>>,
    pub relationships: Vec<RelationshipUrl>,
    pub api_behavior: HashMap<String, String>,
    pub expected_error_codes: Option<Vec<ExpectedErrorCode>>,
    pub parent: Option<HashMap<String, String>>,
}

#[derive(Clone, Deserialize)]
pub struct RelationshipUrl {
    pub service: String,
    pub url_scheme: String,
    pub default_api_behavior: HashMap<String, String>,
    pub default_parameters: Option<Vec<Parameter>>,
    pub api: String,
    pub name: String,
    pub uri: String,
    pub conditions: Option<Vec<String>>,
    pub api_behavior: Option<HashMap<String, String>>,
    pub expected_error_codes: Option<Vec<ExpectedErrorCode>>,
    pub parameters: Option<Vec<Parameter>>,
    pub keys: Option<Vec<Parameter>>,
    pub relationships: Option<Vec<Relationship>>,
}

impl RelationshipUrl {
    pub fn get_parent(&self, data: Value) -> HashMap<String, String> {
        /*
        Get the value of the key fields from the parent object
        */
        let mut res: HashMap<String, String> = HashMap::new();
        if let Some(keys) = &self.keys {
            for key in keys {
                match data.get(key.value.clone()) {
                    Some(data_value) => {
                        match data_value.as_str() {
                            Some(v) => {
                                res.insert(key.value.clone(), v.to_string());
                            },
                            None => debug!(
                                "{:FL$}Could not convert key {:?} to str for relationship {:?} of API {:?} for service {:?}",
                                "RelationshipUrl", &key.name, &self.name, &self.api, &self.service
                            )
                        }
                    }
                    None => {
                        debug!(
                            "{:FL$}Trying to insert parent key {:?} for relationship {:?} of API {:?} for service {:?} while data does not contain it",
                            "RelationshipUrl", &key.name, &self.name, &self.api, &self.service
                        );
                    }
                }
            }
        }
        res
    }

    pub fn get_url(
        &self, 
        client: &Client, 
        token: &Token, 
        tenant: String, 
        data: Value, 
        previous_url: String
    ) -> String {
        /*
        Construct URL to be processed
        */
        let mut url: String = self.url_scheme.clone();

        // Replace KEEP_URL with previous URL without parameters (erase url_scheme)
        if url.contains("[KEEP_URL]") {
            url = self.uri.replace(
                "[KEEP_URL]",
                previous_url.split('?').collect::<Vec<&str>>()[0],
            );
        }

        // Replace URI
        url = url.replace("[URI]", &self.uri);

        // Replacing keys with the results of the previous API call
        let mut done: Vec<String> = Vec::new();
        if let Some(keys) = &self.keys {
            for key in keys {
                match data.get(key.value.clone()) {
                    Some(data_value) => {
                        match data_value.as_str() {
                            Some(v) => {
                                if url.contains(&key.name) {
                                    match &key.conditions {
                                        None => {}, 
                                        Some(c) => {
                                            let mut ok: bool = true;
                                            for condition in c.iter() {
                                                match condition {
                                                    c if c == "UnifiedGroup" => {
                                                        if !Conditions::check_if_unified_group(data_value) {
                                                            debug!(
                                                                "{:FL$}Key {:?} for relationship {:?} of API {:?} for service {:?} does not meet condition {:?}, skipping it",
                                                                "RelationshipUrl", &key.name, &self.name, &self.api, &self.service, condition
                                                            );
                                                            // Skip relationship if data does not match condition
                                                            return String::new();
                                                        }
                                                    },
                                                    c if c == "FolderTypeWithPermissions" => {
                                                        if !Conditions::check_if_folder_require_permission_dump(data_value) {
                                                            debug!(
                                                                "{:FL$}Key {:?} for relationship {:?} of API {:?} for service {:?} does not meet condition {:?}, skipping it",
                                                                "RelationshipUrl", &key.name, &self.name, &self.api, &self.service, condition
                                                            );
                                                            // Skip relationship if data does not match condition
                                                            return String::new();
                                                        }
                                                    },
                                                    c => {
                                                        if !Conditions::check(client, token, c.clone()) {
                                                            debug!(
                                                                "{:FL$}Key {:?} for relationship {:?} of API {:?} for service {:?} does not meet condition {:?}, skipping it",
                                                                "RelationshipUrl", &key.name, &self.name, &self.api, &self.service, condition
                                                            );
                                                            ok = false;
                                                        }
                                                    }
                                                }
                                            }
                                            if !ok {
                                                continue
                                            }
                                        }
                                    }
                                    match &key.transform {
                                        None => {
                                            url = url.replace(&key.name, v);
                                        },
                                        Some(t) if t == "Base64" => {
                                            url = url.replace(&key.name, &URL_SAFE.encode(v.as_bytes()));
                                        },
                                        Some(t) if t == "SplitBackslashFirstAndBase64" => {
                                            url = url.replace(&key.name, &URL_SAFE.encode(v.split("\\").collect::<Vec<&str>>()[0].as_bytes()));
                                        },
                                        Some(t) if t == "SplitBackslashSecondAndBase64" => {
                                            url = url.replace(&key.name, &URL_SAFE.encode(format!("\\{}", v.split("\\").collect::<Vec<&str>>()[1]).as_bytes()));
                                        },
                                        Some(t) => {
                                            warn!(
                                                "{:FL$}Invalid transform {:?} in schema file for key {:?} for relationship {:?} of API {:?} for service {:?}. Skipping transformation.",
                                                "RelationshipUrl", t, &key.name, &self.name, &self.api, &self.service
                                            );
                                            url = url.replace(&key.name, v);
                                        }
                                    };
                                    done.push(key.name.clone());
                                } else if !done.contains(&key.name) {
                                    match &key.conditions {
                                        None => {}, 
                                        Some(c) => {
                                            let mut ok: bool = true;
                                            for condition in c.iter() {
                                                match condition {
                                                    c if c == "UnifiedGroup" => {
                                                        if !Conditions::check_if_unified_group(data_value) {
                                                            debug!(
                                                                "{:FL$}Key {:?} for relationship {:?} of API {:?} for service {:?} does not meet condition {:?}, skipping it",
                                                                "RelationshipUrl", &key.name, &self.name, &self.api, &self.service, condition
                                                            );
                                                            // Skip relationship if data does not match condition
                                                            return String::new();
                                                        }
                                                    },
                                                    c if c == "FolderTypeWithPermissions" => {
                                                        if !Conditions::check_if_folder_require_permission_dump(data_value) {
                                                            debug!(
                                                                "{:FL$}Key {:?} for relationship {:?} of API {:?} for service {:?} does not meet condition {:?}, skipping it",
                                                                "RelationshipUrl", &key.name, &self.name, &self.api, &self.service, condition
                                                            );
                                                            // Skip relationship if data does not match condition
                                                            return String::new();
                                                        }
                                                    },
                                                    c => {
                                                        if !Conditions::check(client, token, c.clone()) {
                                                            debug!(
                                                                "{:FL$}Key {:?} for relationship {:?} of API {:?} for service {:?} does not meet condition {:?}, skipping it",
                                                                "RelationshipUrl", &key.name, &self.name, &self.api, &self.service, condition
                                                            );
                                                            ok = false;
                                                        }
                                                    }
                                                }
                                            }
                                            if !ok {
                                                continue
                                            }
                                        }
                                    }
                                    debug!(
                                        "{:FL$}Trying to replace invalid key {:?} for relationship {:?} of API {:?} for service {:?}",
                                        "RelationshipUrl", &key.name, &self.name, &self.api, &self.service
                                    );
                                }
                            },
                            None => debug!(
                                "{:FL$}Could not convert key {:?} to str for relationship {:?} of API {:?} for service {:?}",
                                "RelationshipUrl", &key.name, &self.name, &self.api, &self.service
                            )
                        }
                    }
                    None => {
                        debug!(
                            "{:FL$}Trying to replace key {:?} for relationship {:?} of API {:?} for service {:?} while data does not contain it",
                            "RelationshipUrl", &key.name, &self.name, &self.api, &self.service
                        );
                    }
                }
            }
        }

        // Replacing parameters with the API specific value
        if let Some(parameters) = &self.parameters {
            for parameter in parameters {
                if url.contains(&parameter.name) {
                    url = url.replace(&parameter.name, &parameter.value);
                    match &parameter.conditions {
                        None => {}, 
                        Some(c) => {
                            if c.iter().any(|condition| {
                                let ok = !Conditions::check(client, token, condition.clone());
                                if ! ok {
                                    debug!(
                                        "{:FL$}Parameter {:?} for relationship {:?} of API {:?} for service {:?} does not meet condition {:?}, skipping it",
                                        "RelationshipUrl", &parameter.name, &self.name, &self.api, &self.service, condition
                                    );
                                }
                                ok
                            }) {
                                continue
                            }
                        }
                    }
                    match &parameter.transform {
                        None => {
                            url = url.replace(&parameter.name, &parameter.value);
                        }
                        Some(t) if t == "Base64" => {
                            url = url.replace(
                                &parameter.name,
                                &URL_SAFE.encode(parameter.value.as_bytes()),
                            );
                        }
                        Some(t) if t == "SplitBackslashFirstAndBase64" => {
                            url = url.replace(&parameter.name, &URL_SAFE.encode(parameter.value.split("\\").collect::<Vec<&str>>()[0].as_bytes()));
                        },
                        Some(t) if t == "SplitBackslashSecondAndBase64" => {
                            url = url.replace(&parameter.name, &URL_SAFE.encode(format!("\\{}", parameter.value.split("\\").collect::<Vec<&str>>()[1]).as_bytes()));
                        },
                        Some(t) => {
                            warn!(
                                "{:FL$}Invalid transform {:?} in schema file for parameter {:?} for relationship {:?} of API {:?} for service {:?}. Skipping transformation.",
                                "RelationshipUrl", t, &parameter.name, &self.name, &self.api, &self.service
                            );
                            url = url.replace(&parameter.name, &parameter.value);
                        }
                    };
                    done.push(parameter.name.clone());
                } else if !done.contains(&parameter.name) {
                    debug!(
                        "{:FL$}Trying to replace invalid api parameter {:?} for relationship {:?} of API {:?} for service {:?}",
                        "RelationshipUrl", &parameter.name, &self.name, &self.api, &self.service
                    );
                }
            }
        }

        // Replacing parameters with the service default value
        if let Some(parameters) = &self.default_parameters {
            for parameter in parameters {
                if url.contains(&parameter.name) {
                    match &parameter.conditions {
                        None => {}, 
                        Some(c) => {
                            if c.iter().any(|condition| {
                                let ok = !Conditions::check(client, token, condition.clone());
                                if ! ok {
                                    debug!(
                                        "{:FL$}Default parameter {:?} for relationship {:?} of API {:?} for service {:?} does not meet condition {:?}, skipping it",
                                        "RelationshipUrl", &parameter.name, &self.name, &self.api, &self.service, condition
                                    );
                                }
                                ok
                            }) {
                                continue
                            }
                        }
                    }
                    match &parameter.transform {
                        None => {
                            url = url.replace(&parameter.name, &parameter.value);
                        }
                        Some(t) if t == "Base64" => {
                            url = url.replace(
                                &parameter.name,
                                &URL_SAFE.encode(parameter.value.as_bytes()),
                            );
                        }
                        Some(t) if t == "SplitBackslashFirstAndBase64" => {
                            url = url.replace(&parameter.name, &URL_SAFE.encode(parameter.value.split("\\").collect::<Vec<&str>>()[0].as_bytes()));
                        },
                        Some(t) if t == "SplitBackslashSecondAndBase64" => {
                            url = url.replace(&parameter.name, &URL_SAFE.encode(format!("\\{}", parameter.value.split("\\").collect::<Vec<&str>>()[1]).as_bytes()));
                        },
                        Some(t) => {
                            warn!(
                                "{:FL$}Invalid transform {:?} in schema file for default parameter {:?} for relationship {:?} of API {:?} for service {:?}. Skipping transformation.",
                                "RelationshipUrl", t, &parameter.name, &self.name, &self.api, &self.service
                            );
                            url = url.replace(&parameter.name, &parameter.value);
                        }
                    };
                } else if !done.contains(&parameter.name) {
                    debug!(
                        "{:FL$}Trying to replace invalid default parameter {:?} for relationship {:?} of API {:?} for service {:?}",
                        "RelationshipUrl", &parameter.name, &self.name, &self.api, &self.service
                    );
                }
            }
        }

        // Replacing remaining parameters
        if url.contains("[TENANT]") {
            url = url.replace("[TENANT]", &tenant);
        }

        url
    }
}

#[derive(Clone, Deserialize)]
pub struct Relationship {
    pub name: String,
    pub uri: String,
    pub conditions: Option<Vec<String>>,
    pub api_behavior: Option<HashMap<String, String>>,
    pub parameters: Option<Vec<Parameter>>,
    pub keys: Option<Vec<Parameter>>,
    pub relationships: Option<Vec<Relationship>>,
    pub expected_error_codes: Option<Vec<ExpectedErrorCode>>,
}

#[derive(Clone, Deserialize)]
pub struct ExpectedErrorCode {
    pub status: u16,
    pub code: Option<String>,
}

#[derive(Clone, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub value: String,
    pub transform: Option<String>,
    pub conditions: Option<Vec<String>>,
}

#[derive(Clone, Deserialize)]
pub struct Api {
    pub name: String,
    pub uri: String,
    pub conditions: Option<Vec<String>>,
    pub api_behavior: Option<HashMap<String, String>>,
    pub parameters: Option<Vec<Parameter>>,
    pub relationships: Option<Vec<Relationship>>,
    pub expected_error_codes: Option<Vec<ExpectedErrorCode>>,
}

impl Api {
    pub fn get_url(
        self,
        client: &Client,
        token: &Token,
        tenant: String,
        url_scheme: String,
        default_parameters: Option<Vec<Parameter>>,
    ) -> String {
        /*
        Construct URL to be processed
        */
        let mut url: String = url_scheme.replace("[URI]", &self.uri);

        // Replacing parameters with the API specific value
        let mut done: Vec<String> = Vec::new();
        if let Some(parameters) = self.parameters {
            for parameter in &parameters {
                if url.contains(&parameter.name) {
                    match &parameter.conditions {
                        None => {}, 
                        Some(c) => {
                            if c.iter().any(|condition| {
                                let ok = !Conditions::check(client, token, condition.clone());
                                if ! ok {
                                    debug!(
                                        "{:FL$}Parameter {:?} for API {:?} does not meet condition {:?}, skipping it",
                                        "Api", &parameter.name, &self.name, condition
                                    );
                                }
                                ok
                            }) {
                                continue
                            }
                        }
                    }
                    match &parameter.transform {
                        None => {
                            url = url.replace(&parameter.name, &parameter.value);
                        }
                        Some(t) if t == "Base64" => {
                            url = url.replace(
                                &parameter.name,
                                &URL_SAFE.encode(parameter.value.as_bytes()),
                            );
                        }
                        Some(t) if t == "SplitBackslashFirstAndBase64" => {
                            url = url.replace(&parameter.name, &URL_SAFE.encode(parameter.value.split("\\").collect::<Vec<&str>>()[0].as_bytes()));
                        },
                        Some(t) if t == "SplitBackslashSecondAndBase64" => {
                            url = url.replace(&parameter.name, &URL_SAFE.encode(format!("\\{}", parameter.value.split("\\").collect::<Vec<&str>>()[1]).as_bytes()));
                        },
                        Some(t) => {
                            warn!(
                                "{:FL$}Invalid transform {:?} in schema file for parameter {:?} for API {:?}. Skipping transformation.",
                                "Api", t, &parameter.name, &self.name
                            );
                            url = url.replace(&parameter.name, &parameter.value);
                        }
                    };
                    done.push(parameter.name.clone());
                } else if !done.contains(&parameter.name) {
                    debug!(
                        "{:FL$}Trying to replace invalid api parameter {:?} for API {:?}",
                        "Api", &parameter.name, &self.name
                    );
                }
            }
        }

        // Replacing parameters with the service default value
        if let Some(parameters) = default_parameters {
            for parameter in &parameters {
                if url.contains(&parameter.name) {
                    match &parameter.conditions {
                        None => {}, 
                        Some(c) => {
                            if c.iter().any(|condition| {
                                let ok = !Conditions::check(client, token, condition.clone());
                                if ! ok {
                                    debug!(
                                        "{:FL$}Parameter {:?} for API {:?} does not meet condition {:?}, skipping it",
                                        "Api", &parameter.name, &self.name, condition
                                    );
                                }
                                ok
                            }) {
                                continue
                            }
                        }
                    }
                    match &parameter.transform {
                        None => {
                            url = url.replace(&parameter.name, &parameter.value);
                        }
                        Some(t) if t == "Base64" => {
                            url = url.replace(
                                &parameter.name,
                                &URL_SAFE.encode(parameter.value.as_bytes()),
                            );
                        }
                        Some(t) if t == "SplitBackslashFirstAndBase64" => {
                            url = url.replace(&parameter.name, &URL_SAFE.encode(parameter.value.split("\\").collect::<Vec<&str>>()[0].as_bytes()));
                        },
                        Some(t) if t == "SplitBackslashSecondAndBase64" => {
                            url = url.replace(&parameter.name, &URL_SAFE.encode(format!("\\{}", parameter.value.split("\\").collect::<Vec<&str>>()[1]).as_bytes()));
                        },
                        Some(t) => {
                            warn!(
                                "{:FL$}Invalid transform {:?} in schema file for default parameter {:?} for API {:?}. Skipping transformation.",
                                "Api", t, &parameter.name, &self.name
                            );
                            url = url.replace(&parameter.name, &parameter.value);
                        }
                    };
                } else if !done.contains(&parameter.name) {
                    debug!(
                        "{:FL$}Trying to replace invalid default parameter {:?} for API {:?}",
                        "Api", &parameter.name, &self.name
                    );
                }
            }
        }

        // Replacing remaining parameters
        if url.contains("[TENANT]") {
            url = url.replace("[TENANT]", &tenant);
        }

        url
    }
}

#[derive(Clone, Deserialize)]
pub struct Service {
    pub name: String,
    pub description: String,
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
pub struct Schema {
    pub oradaz_version: String,
    pub schema_hash: String,
    pub schema_version: String,
    pub services: Vec<Service>,
}

impl Schema {
    pub fn new(
        cli: &Cli,
        writer: &Arc<Mutex<OradazWriter>>,
        requests: &Requests,
    ) -> Result<Schema, Error> {
        /*
        Initialize Schema structure
        */
        let schema_str: String =Schema::get_content(cli, writer, requests)?;
        let schema = Schema::deserialize(schema_str)?; 
        Ok(schema)
    }

    fn get_content(
        cli: &Cli,
        writer: &Arc<Mutex<OradazWriter>>,
        requests: &Requests,
    ) -> Result<String, Error> {
        /*
        Retrieve schema content from Github or provided file
        */
        let schema_file = match cli.schema_file.as_deref() {
            Some(s) => s.to_string(),
            None => String::new(),
        };
        let schema_str: String = if !schema_file.is_empty() {
            if fs::metadata(&schema_file).is_err() {
                error!("{:FL$}Invalid schema file provided", "Schema");
                return Err(Error::SchemaFileNotFound);
            }
            info!("{:FL$}Using schema file {}", "Schema", &schema_file);
            match fs::read_to_string(&schema_file) {
                Err(err) => {
                    error!("{:FL$}Cannot open schema file {}.", "Schema", &schema_file);
                    debug!("{}", err);
                    return Err(Error::IOError(err));
                }
                Ok(res) => res,
            }
        } else {
            match requests.client.get(SCHEMA_URL).send() {
                Err(err) => {
                    error!(
                        "{:FL$}Cannot retrieve schema file from {}",
                        "Schema", SCHEMA_URL
                    );
                    debug!("{}", err);
                    return Err(Error::CannotDownloadSchemaFile);
                }
                Ok(res) => match res.text() {
                    Ok(t) => t,
                    Err(err) => {
                        error!(
                            "{:FL$}Cannot parse read while retrieving schema file from {}",
                            "Schema", SCHEMA_URL
                        );
                        debug!("{}", err);
                        return Err(Error::CannotDownloadSchemaFile);
                    }
                },
            }
        };
        match writer.lock() {
            Ok(mut w) => {
                w.write_file(
                    String::new(),
                    "schema.json".to_string(),
                    schema_str.clone(),
                )?;
            }
            Err(err) => {
                error!(
                    "{:FL$}Error while locking Writer to write schema",
                    "Schema"
                );
                debug!("{}", err);
                return Err(Error::WriterLock);
            }
        }
        Ok(schema_str)
    }

    fn deserialize(schema_str: String) -> Result<Schema, Error> {
        /*
        Parse schema file content into Schema structure
        */
        let schema_hash: String = digest(schema_str.clone());
        match serde_json::from_str::<SchemaModel>(&schema_str) {
            Ok(e) => {
                if e.oradaz_version != VERSION {
                    error!("{:FL$}This is not the last version of ORADAZ. Please download the last available release.", "Schema");
                    return Err(Error::NotLastVersion);
                }
                Ok(Schema {
                    oradaz_version: e.oradaz_version,
                    schema_hash,
                    schema_version: e.schema_version,
                    services: e.services,
                })
            }
            Err(err) => {
                error!("{:FL$}Could not parse schema file", "Schema");
                debug!("{}", err);
                Err(Error::SchemaFileParsing)
            }
        }
    }

    pub fn get_urls(
        self,
        tenant: String,
        tokens: &HashMap<String, Token>,
        client: &Client
    ) -> Result<Vec<Url>, Error> {
        /*
        Retrieve all base URLs for services with previously obtained token
        */
        let mut urls: Vec<Url> = Vec::new();
        for service in self.services {
            // Only get URLs for services where we are authenticated
            if let Some(token) = tokens.get(&service.name) {
                debug!(
                    "{:FL$}Getting URLs for service {}",
                    "Schema", service.description
                );
                for api in service.apis {
                    let api_name: String = api.name.clone();
                    let api_conditions: Option<Vec<String>> = api.conditions.clone();

                    // Add API behavior
                    let mut api_behavior: HashMap<String, String> =
                        service.default_api_behavior.clone();
                    if let Some(a) = api.api_behavior.clone() {
                        for (k, v) in a {
                            api_behavior.insert(k, v);
                        }
                    }

                    // Expected error codes
                    let expected_error_codes: Option<Vec<ExpectedErrorCode>> = api.expected_error_codes.clone();

                    // Add relationships for this api
                    let mut relationships: Vec<RelationshipUrl> = Vec::new();
                    if let Some(r) = api.relationships.clone() {
                        for relationship in &r {
                            relationships.push(RelationshipUrl {
                                service: service.name.clone(),
                                url_scheme: service.url_scheme.clone(),
                                default_api_behavior: service.default_api_behavior.clone(),
                                default_parameters: service.default_parameters.clone(),
                                api: api_name.clone(),
                                name: relationship.name.clone(),
                                uri: relationship.uri.clone(),
                                conditions: relationship.conditions.clone(),
                                api_behavior: relationship.api_behavior.clone(),
                                expected_error_codes: relationship.expected_error_codes.clone(),
                                keys: relationship.keys.clone(),
                                parameters: relationship.parameters.clone(),
                                relationships: relationship.relationships.clone(),
                            })
                        }
                    }

                    // Get URL for this api
                    let url: String = api.get_url(
                        client,
                        token,
                        tenant.clone(),
                        service.url_scheme.clone(),
                        service.default_parameters.clone(),
                    );

                    urls.push(Url {
                        service_name: service.name.clone(),
                        service_scopes: service.scopes.clone(),
                        service_description: service.description.clone(),
                        service_mandatory_auth: service.mandatory_auth,
                        api: api_name,
                        url,
                        conditions: api_conditions,
                        relationships,
                        api_behavior,
                        expected_error_codes,
                        parent: None,
                    })
                }
            }
        }
        urls.shuffle(&mut thread_rng());
        Ok(urls)
    }
}
