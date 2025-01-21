use crate::config::Config;
use crate::dumper::{Dumper, Table};
use crate::errors::Error;
use crate::writer::OradazWriter;

use log::{debug, error};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const FL: usize = crate::FL;

#[derive(Serialize, Deserialize)]
pub struct Token {
    pub name: String,
    pub user_id: String,
    pub user_principal_name: String,
    pub client_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct Metadata {
    tenant: String,
    collection_date: String,
    oradaz_version: String,
    schema_version: String,
    schema_hash: String,
    process_time: i64,
    database: String,
    services: HashMap<String, bool>,
    tokens: Vec<Token>,
    tables: Vec<Table>,
    errors: usize,
    condition_errors: usize,
}

impl Metadata {
    pub fn new(
        dumper: &Dumper,
        config: &Config,
        collection_date: String,
        database: String,
        process_time: i64,
    ) -> Metadata {
        /*
        Initialize Metadata structure with final values
        */
        let mut tokens: Vec<Token> = Vec::new();
        for (name, token) in dumper.tokens.iter() {
            tokens.push(Token {
                name: name.clone(),
                user_id: token.user_id.clone(),
                user_principal_name: token.user_principal_name.clone(),
                client_id: token.client_id.clone(),
            })
        }
        let mut services: HashMap<String, bool> = HashMap::new();
        if let Some(s) = &config.services {
            for service in &s.services {
                services.insert(service.name.clone(), service.value);
            }
        };
        Metadata {
            tenant: dumper.tenant.clone(),
            collection_date,
            oradaz_version: dumper.schema.oradaz_version.clone(),
            schema_version: dumper.schema.schema_version.clone(),
            schema_hash: dumper.schema.schema_hash.clone(),
            process_time,
            database,
            services,
            tokens,
            tables: dumper.tables.clone(),
            errors: dumper.errors,
            condition_errors: dumper.condition_errors,
        }
    }

    pub fn write(&self, writer: &Arc<Mutex<OradazWriter>>) -> Result<(), Error> {
        /*
        Write metadata to "metadata.json" file
        */
        let metadata_str = match serde_json::to_string(&self) {
            Err(err) => {
                error!("{:FL$}Could not convert metadata to json", "Metadata");
                debug!("{}", err);
                return Err(Error::MetadataToJSON);
            }
            Ok(j) => j,
        };
        match writer.lock() {
            Ok(mut w) => {
                w.write_file(String::new(), "metadata.json".to_string(), metadata_str)?;
            }
            Err(err) => {
                error!(
                    "{:FL$}Error while locking Writer to write metadata",
                    "Metadata"
                );
                debug!("{}", err);
                return Err(Error::WriterLock);
            }
        }
        Ok(())
    }
}
