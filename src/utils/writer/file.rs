/// Module to write data in cleartext folders.
use crate::FL;
use crate::utils::errors::Error;

use log::{debug, error};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

pub struct FileWriter {
    pub path: String,
    pub log_file: File,
    /// Cache of open per-table output file handles, keyed by full path. Avoids an
    /// open()+close() syscall pair on every record write at 100k+ records; the
    /// handle count is bounded by the number of schema tables (~hundreds), not by
    /// object count. All writes funnel through the single writer actor, so this
    /// map is never accessed concurrently. Handles close when the FileWriter drops.
    files: HashMap<String, File>,
}

impl FileWriter {
    pub fn new(output: &Path, name: &String) -> Result<Self, Error> {
        let path = format!("{}", output.join(name).display());
        if let Err(err) = fs::create_dir(&path) {
            error!("{:FL$}Cannot create directory {:?}", "FileWriter", path);
            debug!("{:FL$}Directory creation error: {:?}", "FileWriter", err);
            return Err(Error::FolderCreation);
        };
        let log_file = match File::create(format!("{path}/oradaz.log")) {
            Err(err) => {
                error!(
                    "{:FL$}Could not create log file in unencrypted folder",
                    "FileWriter"
                );
                debug!("{:FL$}Log file creation error: {:?}", "FileWriter", err);
                return Err(Error::FolderCreateLogFile);
            }
            Ok(f) => f,
        };
        Ok(FileWriter {
            path,
            log_file,
            files: HashMap::new(),
        })
    }

    /// Writes an empty `.broken` marker into the collection folder so `inspect`
    /// can detect an interrupted/failed folder-mode collection. An `.mla` archive
    /// signals this via its file extension; a folder has none. Best-effort — a
    /// failure here must not mask the original error that triggered set_broken.
    pub fn mark_broken(&self) {
        let marker = Path::new(&self.path).join(".broken");
        if let Err(err) = File::create(&marker) {
            debug!(
                "{:FL$}Could not write .broken marker to {:?}: {:?}",
                "FileWriter", marker, err
            );
        }
    }

    pub fn write_log(&mut self, record: &String) -> Result<(), Error> {
        if let Err(err) = self.log_file.write_all(record.as_bytes()) {
            debug!("{:FL$}Log file write error: {:?}", "FileWriter", err);
            return Err(Error::FolderWriteLog);
        };
        Ok(())
    }

    pub fn write_file(&mut self, folder: &str, filepath: &str, data: String) -> Result<(), Error> {
        if !Path::new(&self.path).join(folder).exists() {
            match Path::new(&self.path).join(folder).to_str() {
                Some(p) => {
                    if let Err(err) = fs::create_dir_all(p) {
                        error!(
                            "{:FL$}Could not create folder '{}' to unencrypted folder",
                            "FileWriter", folder
                        );
                        debug!("{:FL$}Folder creation error: {:?}", "FileWriter", err);
                        return Err(Error::IOError(err));
                    }
                }
                None => {
                    error!("{:FL$}Invalid path for file '{}'", "FileWriter", filepath);
                    return Err(Error::FolderInvalidFilePath);
                }
            }
        }

        let full_path = match Path::new(&self.path).join(folder).join(filepath).to_str() {
            Some(p) => p.to_string(),
            None => {
                error!("{:FL$}Invalid path for file '{}'", "FileWriter", filepath);
                return Err(Error::FolderInvalidFilePath);
            }
        };

        // Reuse a cached handle for this path; open (create + append) only on first use.
        let file = match self.files.entry(full_path.clone()) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => {
                match fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&full_path)
                {
                    Ok(f) => e.insert(f),
                    Err(err) => {
                        error!(
                            "{:FL$}Could not open file {:?} in folder {:?} to unencrypted folder",
                            "FileWriter", filepath, folder
                        );
                        debug!("{:FL$}File open error: {:?}", "FileWriter", err);
                        return Err(Error::IOError(err));
                    }
                }
            }
        };

        if let Err(err) = file.write_all(data.as_bytes()) {
            error!(
                "{:FL$}Could not write to file {:?} in folder {:?} to unencrypted folder",
                "FileWriter", filepath, folder
            );
            debug!("{:FL$}File write error: {:?}", "FileWriter", err);
            return Err(Error::IOError(err));
        }
        Ok(())
    }
}
