use crate::errors::Error;

use log::error;
use mla::ArchiveWriter;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;

const FL: usize = crate::FL;

#[derive(Serialize, Deserialize)]
pub struct PrerequisitesMetadata {
    pub name: String,
    pub error: String,
}

#[derive(Serialize, Deserialize)]
pub struct TokensMetadata {
    pub name: String,
    pub user_id: String,
    pub user_principal_name: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TablesMetadata {
    pub file: String,
    pub table_name: String,
    pub count: usize,
}

#[derive(Serialize, Deserialize)]
pub struct Metadata {
    oradaz_version: String,
    oradaz_processtime: i64,
    oradaz_total_processtime: i64,
    collection_date: String,
    database_name: String,
    tokens: Vec<TokensMetadata>,
    tables: Vec<TablesMetadata>,
    errors: usize,
    prerequisites: Vec<PrerequisitesMetadata>,
    services: HashMap<String, bool>,
}

impl Metadata {
    pub fn new(collection_date: &str, database_name: &str, version: &str, oradaz_processtime: i64, oradaz_total_processtime: i64, 
        errors: usize, tokens: Vec<TokensMetadata>, tables: Vec<TablesMetadata>, 
        prerequisites: Vec<PrerequisitesMetadata>, services: HashMap<String, bool>
    ) -> Metadata {
        let collection_date = String::from(collection_date);
        let database_name = String::from(database_name);
        let oradaz_version = String::from(version);
        Metadata {
            oradaz_version,
            oradaz_processtime,
            oradaz_total_processtime,
            collection_date,
            database_name,
            tokens,
            tables,
            errors,
            prerequisites,
            services,
        }
    }

    pub fn add_to_output<'a>(&self, mla_archive: &mut Option<ArchiveWriter<'a, &File>>, config_output_files: bool, output_folder: &str) -> Result<(), Error> {
        let j = match serde_json::to_string(&self) {
            Err(_e) =>  {
                error!("{:FL$}Could not convert metadata to json", "mla_archive_add_metadata"); 
                return Err(Error::MetadataToJSONError);
            },
            Ok(j) => j
        };
        if let Some(mla) = mla_archive {
            if let Err(e) = mla.add_file("metadata.json", j.len() as u64, j.as_bytes()) {
                error!("{:FL$}Could not add metadata file to archive", "mla_archive_add_metadata"); 
                return Err(Error::MLAError(e));
            };
        };
        if config_output_files {
            let mut metadata_file = match File::create(&format!("{}/metadata.json", output_folder)) {
                Err(e) => {
                    error!("{:FL$}Could not create metadata file in unencrypted folder", "SchemaParser"); 
                    return Err(Error::IOError(e));
                },
                Ok(f) => f,
            };
            if let Err(e) = metadata_file.write_all(j.as_bytes()) {
                error!("{:FL$}Could not write metadata file in unencrypted folder", "SchemaParser"); 
                return Err(Error::IOError(e));
            }
        };
        Ok(())
    }
}
