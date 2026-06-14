/// Module to write data in encrypted MLA archives.
use crate::utils::errors::Error;
use crate::{FL, PUB_KEY};

use log::{debug, error};
use mla::ArchiveWriter;
use mla::config::ArchiveWriterConfig;
use mla::crypto::mlakey::*;
use mla::entry::{ArchiveEntryId, EntryName};
use std::collections::HashMap;
use std::fs::{self, File};
use std::path::Path;

/// Loads and validates all public keys for MLA archive encryption.
/// This includes the default hardcoded key and any additional keys from the config.
pub fn load_mla_public_keys(
    config: &crate::utils::config::Config,
) -> Result<Vec<MLAEncryptionPublicKey>, Error> {
    let mut public_keys = Vec::new();

    // 1. Load default hardcoded key
    let default_key = match MLAPublicKey::deserialize_public_key(PUB_KEY) {
        Ok(p) => {
            let (pub_enc_key, _pub_sig_verif_key) = p.get_public_keys();
            pub_enc_key
        }
        Err(err) => {
            error!(
                "{:FL$}MLAInvalidPubKey: Invalid default public key: {}",
                "MlaWriter", err
            );
            return Err(Error::MLAInvalidPubKey);
        }
    };
    public_keys.push(default_key);

    // 2. Load additional keys from config
    if let Some(additional) = &config.additional_mla_keys {
        // Keys from files
        if let Some(files) = &additional.key_files {
            for file_path in files {
                let key_content = fs::read(file_path).map_err(|err| {
                    error!(
                        "{:FL$}Could not read MLA public key file '{}': {}",
                        "MlaWriter", file_path, err
                    );
                    Error::IOError(err)
                })?;
                let key = match MLAPublicKey::deserialize_public_key(key_content.as_slice()) {
                    Ok(p) => {
                        let (pub_enc_key, _pub_sig_verif_key) = p.get_public_keys();
                        pub_enc_key
                    }
                    Err(err) => {
                        error!(
                            "{:FL$}Invalid public key in file '{}': {}",
                            "MlaWriter", file_path, err
                        );
                        return Err(Error::MLAInvalidPubKey);
                    }
                };
                public_keys.push(key);
            }
        }
        // Keys provided directly
        if let Some(keys) = &additional.keys {
            for key_str in keys {
                let key = match MLAPublicKey::deserialize_public_key(key_str.as_bytes()) {
                    Ok(p) => {
                        let (pub_enc_key, _pub_sig_verif_key) = p.get_public_keys();
                        pub_enc_key
                    }
                    Err(err) => {
                        error!(
                            "{:FL$}Invalid public key provided in config: {}",
                            "MlaWriter", err
                        );
                        return Err(Error::MLAInvalidPubKey);
                    }
                };
                public_keys.push(key);
            }
        }
    }

    Ok(public_keys)
}

pub struct MlaWriter {
    pub mla_path: String,
    pub mla_archive: Option<ArchiveWriter<'static, File>>,
    pub log_file_id: ArchiveEntryId,
    pub file_ids: HashMap<String, ArchiveEntryId>,
}

impl MlaWriter {
    pub fn new(
        output: &Path,
        name: &String,
        public_keys: &[MLAEncryptionPublicKey],
    ) -> Result<Self, Error> {
        // Use ".tmp" to ensure dump interruption is visible in file name
        let mla_path = output.join(format!("{name}.mla.tmp"));
        let mla_path_string: String = match mla_path.clone().into_os_string().into_string() {
            Ok(p) => p,
            Err(ostr) => {
                error!("{:FL$}Invalid MLA path {:?}", "MlaWriter", ostr);
                return Err(Error::InvalidMlaPath);
            }
        };
        let mla_file: File = match File::create(&mla_path) {
            Err(err) => {
                error!("{:FL$}Could not create output archive", "MlaWriter");
                debug!("{:FL$}File creation error: {:?}", "MlaWriter", err);
                return Err(Error::MLACreateFile);
            }
            Ok(f) => f,
        };
        let mla_config = ArchiveWriterConfig::with_encryption_without_signature(public_keys)
            .map_err(|err| {
                error!("{:FL$}ArchiveWriter config error: {:?}", "MlaWriter", err);
                Error::MLACreateArchive
            })?;
        let mut mla_archive: ArchiveWriter<File> =
            match ArchiveWriter::from_config(mla_file, mla_config) {
                Ok(mla) => mla,
                Err(err) => {
                    error!(
                        "{:FL$}Could not create output archive from config",
                        "MlaWriter"
                    );
                    debug!("{:FL$}ArchiveWriter config error: {:?}", "MlaWriter", err);
                    return Err(Error::MLACreateArchive);
                }
            };
        let log_file_entry = match EntryName::from_path("oradaz.log") {
            Ok(l) => l,
            Err(err) => {
                error!(
                    "{:FL$}Could not create log file entry for MLA archive",
                    "MlaWriter"
                );
                debug!(
                    "{:FL$}Log file entry creation error: {:?}",
                    "MlaWriter", err
                );
                return Err(Error::MLACreateLogFile);
            }
        };
        let log_file_id = match mla_archive.start_entry(log_file_entry) {
            Err(err) => {
                error!(
                    "{:FL$}Could not create log file in MLA archive",
                    "MlaWriter"
                );
                debug!("{:FL$}Log file start error: {:?}", "MlaWriter", err);
                return Err(Error::MLACreateLogFile);
            }
            Ok(f) => f,
        };

        Ok(MlaWriter {
            mla_path: mla_path_string,
            mla_archive: Some(mla_archive),
            log_file_id,
            file_ids: HashMap::new(),
        })
    }

    pub fn close(&mut self) -> Result<(), Error> {
        if let Some(archive) = &mut self.mla_archive {
            if let Err(err) = archive.end_entry(self.log_file_id) {
                error!(
                    "{:FL$}Could not finalize log file in MLA archive",
                    "MlaWriter"
                );
                debug!("{:FL$}Log file end error: {:?}", "MlaWriter", err);
                return Err(Error::MLAEndLogFile);
            }

            for (filename, file_id) in self.file_ids.clone() {
                if let Err(err) = archive.end_entry(file_id) {
                    error!(
                        "{:FL$}Could not finalize file {:?} in MLA archive",
                        "MlaWriter", filename
                    );
                    debug!("{:FL$}File end error: {:?}", "MlaWriter", err);
                    return Err(Error::MLAEndFile);
                }
            }
        }

        let archive = match self.mla_archive.take() {
            Some(a) => a,
            None => {
                error!(
                    "{:FL$}Could not finalize MLA archive due to ownership issue",
                    "MlaWriter"
                );
                return Err(Error::MLAEndFile);
            }
        };

        if let Err(err) = archive.finalize() {
            error!("{:FL$}Could not finalize MLA archive", "MlaWriter");
            debug!("{:FL$}Archive finalize error: {:?}", "MlaWriter", err);
            return Err(Error::MLAFinalizeArchive);
        }

        Ok(())
    }

    pub fn write_log(&mut self, record: &String) -> Result<(), Error> {
        match self.mla_archive.as_mut() {
            Some(a) => {
                if let Err(err) =
                    a.append_entry_content(self.log_file_id, record.len() as u64, record.as_bytes())
                {
                    debug!("{:FL$}Log content append error: {:?}", "MlaWriter", err);
                    return Err(Error::MLAWriteLog);
                };
            }
            None => {
                error!("{:FL$}Ownership issue while writing log file", "MlaWriter");
                return Err(Error::MLAWriteLog);
            }
        }
        Ok(())
    }

    pub fn write_file(&mut self, filepath: &str, data: String) -> Result<(), Error> {
        if !self.file_ids.contains_key(filepath) {
            match self.mla_archive.as_mut() {
                Some(a) => {
                    let file_entry = match EntryName::from_path(filepath) {
                        Ok(l) => l,
                        Err(err) => {
                            error!(
                                "{:FL$}Could not create entry for file '{}' in MLA archive",
                                "MlaWriter", filepath
                            );
                            debug!(
                                "{:FL$}Data file entry creation error: {:?}",
                                "MlaWriter", err
                            );
                            return Err(Error::MLACreateDataFile);
                        }
                    };
                    match a.start_entry(file_entry) {
                        Err(err) => {
                            error!(
                                "{:FL$}Could not create file '{}' to archive",
                                "MlaWriter", filepath
                            );
                            debug!("{:FL$}File start error: {:?}", "MlaWriter", err);
                            return Err(Error::MLAError(err));
                        }
                        Ok(file_id) => {
                            // The `!contains_key` guard above guarantees there is no
                            // prior entry for this path, so this records the id of a
                            // freshly started entry. Each id is `end_entry`'d once at
                            // archive close; overwriting a live id here would orphan its
                            // started-but-never-finalized entry and fail `finalize`.
                            self.file_ids.insert(String::from(filepath), file_id);
                        }
                    }
                }
                None => {
                    error!(
                        "{:FL$}Ownership issue while creating data file '{}' in archive",
                        "MlaWriter", filepath
                    );
                    return Err(Error::MLAWriteDataFile);
                }
            };
        }
        match self.file_ids.get(filepath) {
            Some(&file_id) => {
                match self.mla_archive.as_mut() {
                    Some(a) => {
                        if let Err(err) =
                            a.append_entry_content(file_id, data.len() as u64, data.as_bytes())
                        {
                            error!(
                                "{:FL$}Could not add data to file '{}' in archive",
                                "MlaWriter", filepath
                            );
                            debug!("{:FL$}File content append error: {:?}", "MlaWriter", err);
                            return Err(Error::MLAError(err));
                        };
                    }
                    None => {
                        error!(
                            "{:FL$}Ownership issue while writing data file '{}' in archive",
                            "MlaWriter", filepath
                        );
                        return Err(Error::MLAWriteDataFile);
                    }
                };
            }
            None => {
                error!(
                    "{:FL$}Could not find file '{}' in archive while trying to add data in it",
                    "MlaWriter", filepath
                );
                return Err(Error::MLAAppendDataToFile);
            }
        }
        Ok(())
    }
}
