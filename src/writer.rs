use crate::config::Config;
use crate::errors::Error;
use crate::logger;

use curve25519_parser::parse_openssl_25519_pubkey;
use log::{debug, error};
use mla::config::ArchiveWriterConfig;
use mla::{ArchiveFileID, ArchiveWriter};
use regex::Regex;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;

const FL: usize = crate::FL;
const PUB_KEY: &[u8] = include_bytes!("./mlakey.pub");

pub struct OradazWriter {
    pub file_writer: Option<FileWriter>,
    pub mla_writer: Option<MlaWriter>,
}

pub struct FileWriter {
    pub path: String,
    pub log_file: File,
}

pub struct MlaWriter {
    pub mla_path: String,
    pub mla_archive: ArchiveWriter<'static, File>,
    pub log_file_id: ArchiveFileID,
    pub file_ids: HashMap<String, ArchiveFileID>,
}

impl OradazWriter {
    pub fn new(config: &Config, output: &Path, name: &String) -> Result<Self, Error> {
        /*
        Initialize OradazWriter with direct file writing and/or MLA writing based on configuration
        */
        let mla_writer: Option<MlaWriter> = match config.output_mla {
            true => match MlaWriter::new(output, name) {
                Ok(m) => Some(m),
                Err(err) => return Err(err),
            },
            false => None,
        };
        let file_writer: Option<FileWriter> = match config.output_files {
            true => match FileWriter::new(output, name) {
                Ok(m) => Some(m),
                Err(err) => return Err(err),
            },
            false => None,
        };

        Ok(OradazWriter {
            file_writer,
            mla_writer,
        })
    }

    pub fn finalize(&mut self) -> Result<(), Error> {
        /*
        Close MLA archive
        */
        if let Some(mla_writer) = &mut self.mla_writer {
            mla_writer.close()?;
            // Remove ".tmp" from file name
            let expected_format: Regex = match Regex::new(
                r"^.*[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}_[0-9]{8}-[0-9]{6}\.mla\.tmp$",
            ) {
                Ok(re) => re,
                Err(err) => {
                    error!(
                        "{:FL$}Could not compute regex to validate archive name.",
                        "OradazWriter"
                    );
                    debug!("{}", err);
                    return Err(Error::RegexError);
                }
            };
            if expected_format.is_match(&mla_writer.mla_path) {
                let mut new_path: String = mla_writer.mla_path.clone();
                new_path.truncate(new_path.len() - 4);
                if let Err(err) = fs::rename(&mla_writer.mla_path, new_path) {
                    error!(
                        "{:FL$}Could not remove '.tmp' extension to MLA file. Please remove it yourself before submitting the file.",
                        "OradazWriter"
                    );
                    debug!("{}", err);
                    return Err(Error::ArchiveRenaming);
                }
            } else {
                error!(
                    "{:FL$}Could not remove '.tmp' extension to MLA file. Please remove it yourself before submitting the file.",
                    "OradazWriter"
                );
                return Err(Error::ArchiveRenaming);
            }
        };
        Ok(())
    }

    pub fn set_broken(&mut self) -> Result<(), Error> {
        /*
        Close MLA archive
        */
        if let Some(mla_writer) = &mut self.mla_writer {
            mla_writer.close()?;
            // Replace ".tmp" with ".broken"
            let expected_format: Regex = match Regex::new(
                r"^.*[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}_[0-9]{8}-[0-9]{6}\.mla\.tmp$",
            ) {
                Ok(re) => re,
                Err(err) => {
                    error!(
                        "{:FL$}Could not compute regex to validate archive name.",
                        "OradazWriter"
                    );
                    debug!("{}", err);
                    return Err(Error::RegexError);
                }
            };
            if expected_format.is_match(&mla_writer.mla_path) {
                let mut new_path: String = mla_writer.mla_path.clone();
                new_path.truncate(new_path.len() - 4);
                if let Err(err) = fs::rename(&mla_writer.mla_path, format!("{}.broken", new_path)) {
                    error!(
                        "{:FL$}Could not replace '.tmp' extension with '.broken' one in MLA file.",
                        "OradazWriter"
                    );
                    debug!("{}", err);
                    return Err(Error::ArchiveRenaming);
                }
            } else {
                error!(
                    "{:FL$}Could not replace '.tmp' extension with '.broken' one in MLA file.",
                    "OradazWriter"
                );
                return Err(Error::ArchiveRenaming);
            }
        };
        Ok(())
    }

    pub fn write_log(&mut self, record: String) -> Result<(), Error> {
        /*
        Write log to "oradaz.log" file in enabled outputs
        */
        if let Some(mla_writer) = &mut self.mla_writer {
            mla_writer.write_log(&record)?;
        };
        if let Some(file_writer) = &mut self.file_writer {
            file_writer.write_log(&record)?;
        };
        Ok(())
    }

    pub fn write_file(&mut self, folder: String, file: String, data: String) -> Result<(), Error> {
        /*
        Add data to file in enabled outputs
        */
        match Path::new(&folder).join(&file).to_str() {
            Some(filepath) => {
                if let Some(mla_writer) = &mut self.mla_writer {
                    mla_writer.write_file(filepath, data.clone())?;
                };
                if let Some(file_writer) = &mut self.file_writer {
                    file_writer.write_file(&folder, &file, data.clone())?;
                };
            }
            None => {
                error!(
                    "{:FL$}Error writing file '{}' to results folder '{}'",
                    "OradazWriter", file, folder
                );
                return Err(Error::WriteFile);
            }
        }
        Ok(())
    }
}

impl MlaWriter {
    pub fn new(output: &Path, name: &String) -> Result<Self, Error> {
        /*
        Create a MlaWriter structure permitting to write the results in a MLA archive
        */
        // Use ".tmp" to ensure dump interruption is visible in file name
        let mla_path = output.join(format!("{}.mla.tmp", name));
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
                debug!("{}", err);
                return Err(Error::MLACreateFile);
            }
            Ok(f) => f,
        };
        let public_key: curve25519_parser::PublicKey = match parse_openssl_25519_pubkey(PUB_KEY) {
            Err(err) => {
                error!("{:FL$}Invalid public key", "MlaWriter");
                debug!("{}", err);
                return Err(Error::MLAInvalidPubKey);
            }
            Ok(p) => p,
        };
        let mut mla_config: ArchiveWriterConfig = ArchiveWriterConfig::default();
        mla_config.add_public_keys(&[public_key]);
        let mut mla_archive: ArchiveWriter<File> =
            match ArchiveWriter::from_config(mla_file, mla_config) {
                Ok(mla) => mla,
                Err(err) => {
                    error!(
                        "{:FL$}Could not create output archive from config",
                        "MlaWriter"
                    );
                    debug!("{}", err);
                    return Err(Error::MLACreateArchive);
                }
            };
        let log_file_id: u64 = match mla_archive.start_file("oradaz.log") {
            Err(err) => {
                error!(
                    "{:FL$}Could not create log file in MLA archive",
                    "MlaWriter"
                );
                debug!("{}", err);
                return Err(Error::MLACreateLogFile);
            }
            Ok(f) => f,
        };

        Ok(MlaWriter {
            mla_path: mla_path_string,
            mla_archive,
            log_file_id,
            file_ids: HashMap::new(),
        })
    }

    pub fn close(&mut self) -> Result<(), Error> {
        /*
        Close the MLA archive
        */
        if let Err(err) = self.mla_archive.end_file(self.log_file_id) {
            error!("{:FL$}Could finalize log file in mla archive", "MlaWriter");
            debug!("{}", err);
            return Err(Error::MLAEndLogFile);
        };
        for (filename, file_id) in self.file_ids.clone() {
            if let Err(err) = self.mla_archive.end_file(file_id) {
                error!(
                    "{:FL$}Could finalize file {:?} in mla archive",
                    "MlaWriter", filename
                );
                debug!("{}", err);
                return Err(Error::MLAEndFile);
            };
        }
        if let Err(err) = self.mla_archive.finalize() {
            error!("{:FL$}Could not finalize mla archive", "MlaWriter");
            debug!("{}", err);
            return Err(Error::MLAFinalizeArchive);
        };
        logger::remove_writer();
        Ok(())
    }

    pub fn write_log(&mut self, record: &String) -> Result<(), Error> {
        /*
        Add a log in "oradaz.log" inside MLA archive
        */
        if let Err(err) = self.mla_archive.append_file_content(
            self.log_file_id,
            record.len() as u64,
            record.as_bytes(),
        ) {
            debug!("{}", err);
            return Err(Error::MLAWriteLog);
        };
        Ok(())
    }

    pub fn write_file(&mut self, filepath: &str, data: String) -> Result<(), Error> {
        /*
        Append data to the file inside MLA archive
        */
        if !self.file_ids.contains_key(filepath) {
            match self.mla_archive.start_file(filepath) {
                Err(err) => {
                    error!(
                        "{:FL$}Could not create file '{}' to archive",
                        "MlaWriter", filepath
                    );
                    debug!("{}", err);
                    return Err(Error::MLAError(err));
                }
                Ok(file_id) => {
                    if let Some(old_file_id) = self.file_ids.insert(String::from(filepath), file_id)
                    {
                        // If for any reason (that should never happen) we erased the entry, revert the change
                        debug!(
                            "{:FL$}Reverting the erased entry for file {}",
                            "MlaWriter", filepath
                        );
                        self.file_ids.insert(String::from(filepath), old_file_id);
                    }
                }
            };
        }
        match self.file_ids.get(filepath) {
            Some(&file_id) => {
                if let Err(err) = self.mla_archive.append_file_content(
                    file_id,
                    data.len() as u64,
                    data.as_bytes(),
                ) {
                    error!(
                        "{:FL$}Could not add data to file '{}' in archive",
                        "MlaWriter", filepath
                    );
                    debug!("{}", err);
                    return Err(Error::MLAError(err));
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

impl FileWriter {
    pub fn new(output: &Path, name: &String) -> Result<Self, Error> {
        /*
        Create a FileWriter structure permitting to write the results directly in the output folder
        */
        let path = format!("{}", output.join(name).display());
        if let Err(err) = fs::create_dir(&path) {
            error!("{:FL$}Cannot create directory {}", "FileWriter", path);
            debug!("{}", err);
            return Err(Error::FolderCreation);
        };
        let log_file = match File::create(format!("{}/oradaz.log", path)) {
            Err(err) => {
                error!(
                    "{:FL$}Could not create log file in unencrypted folder",
                    "FileWriter"
                );
                debug!("{}", err);
                return Err(Error::FolderCreateLogFile);
            }
            Ok(f) => f,
        };
        Ok(FileWriter { path, log_file })
    }

    pub fn write_log(&mut self, record: &String) -> Result<(), Error> {
        /*
        Add a log entry in the "oradaz.log" file
        */
        if let Err(err) = self.log_file.write_all(record.as_bytes()) {
            debug!("{}", err);
            return Err(Error::FolderWriteLog);
        };
        Ok(())
    }

    pub fn write_file(&mut self, folder: &str, filepath: &str, data: String) -> Result<(), Error> {
        /*
        Append data to the file
        */
        if !Path::new(&self.path).join(folder).exists() {
            match Path::new(&self.path).join(folder).to_str() {
                Some(p) => {
                    if let Err(err) = fs::create_dir_all(p) {
                        error!(
                            "{:FL$}Could not create folder '{}' to unencrypted folder",
                            "FileWriter", folder
                        );
                        debug!("{}", err);
                        return Err(Error::IOError(err));
                    }
                }
                None => {
                    error!("{:FL$}Invalid path for file '{}'", "FileWriter", filepath);
                    return Err(Error::FolderInvalidFilePath);
                }
            }
        }

        match Path::new(&self.path).join(folder).join(filepath).to_str() {
            Some(p) => match OpenOptions::new().create(true).append(true).open(p) {
                Ok(mut file) => {
                    if let Err(err) = file.write_all(data.as_bytes()) {
                        error!(
                                "{:FL$}Could not write to file {:?} in folder {:?} to unencrypted folder",
                                "FileWriter", filepath, folder
                            );
                        debug!("{}", err);
                        return Err(Error::IOError(err));
                    };
                }
                Err(err) => {
                    error!(
                        "{:FL$}Could not open file {:?} in folder {:?} to unencrypted folder",
                        "FileWriter", filepath, folder
                    );
                    debug!("{}", err);
                    return Err(Error::IOError(err));
                }
            },
            None => {
                error!("{:FL$}Invalid path for file '{}'", "FileWriter", filepath);
                return Err(Error::FolderInvalidFilePath);
            }
        }
        Ok(())
    }
}
