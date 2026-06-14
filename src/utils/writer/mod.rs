/// Module to write data in the archive.
///
/// According to the configuration file, the output data
/// are written in an encrypted MLA archive, in cleartext
/// in a folder, or both.
pub mod actor;
mod file;
pub mod mla;

pub use actor::WriterHandle;
pub use file::FileWriter;
pub use mla::MlaWriter;

use crate::FL;
use crate::utils::config::Config;
use crate::utils::errors::Error;
use crate::utils::writer::mla::load_mla_public_keys;

use log::{debug, error};
use regex::Regex;
use std::fs;
use std::path::Path;

const TMP_MLA_REGEX: &str =
    r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}_[0-9]{8}-[0-9]{6}\.mla\.tmp$";

pub struct OradazWriter {
    pub file_writer: Option<FileWriter>,
    pub mla_writer: Option<MlaWriter>,
}

impl OradazWriter {
    /// Initializes a new `OradazWriter` based on the provided configuration.
    ///
    /// It determines whether to enable MLA encrypted output, cleartext file output, or both,
    /// as specified in the `Config`.
    pub fn new(config: &Config, output: &Path, name: &String) -> Result<Self, Error> {
        // MLA output is enabled by default unless explicitly disabled in config
        let mla_writer: Option<MlaWriter> = match config.output_mla {
            Some(false) => None,
            _ => {
                let public_keys = load_mla_public_keys(config)?;
                match MlaWriter::new(output, name, &public_keys) {
                    Ok(m) => Some(m),
                    Err(err) => return Err(err),
                }
            }
        };
        // File output is disabled by default for security reasons
        let file_writer: Option<FileWriter> = match config.output_files {
            Some(true) => match FileWriter::new(output, name) {
                Ok(m) => Some(m),
                Err(err) => return Err(err),
            },
            _ => None,
        };

        Ok(OradazWriter {
            file_writer,
            mla_writer,
        })
    }

    /// Returns the final `.mla` path (without the `.tmp` suffix).
    /// Returns `None` when MLA output is disabled.
    pub fn final_mla_path(&self) -> Option<String> {
        self.mla_writer.as_ref().map(|m| {
            if m.mla_path.ends_with(".tmp") {
                m.mla_path[..m.mla_path.len() - 4].to_string()
            } else {
                m.mla_path.clone()
            }
        })
    }

    fn rename_mla_archive(&mut self, suffix: &str, error_msg: &str) -> Result<(), Error> {
        if let Some(mla_writer) = &mut self.mla_writer {
            let expected_format: Regex = match Regex::new(TMP_MLA_REGEX) {
                Ok(re) => re,
                Err(err) => {
                    error!(
                        "{:FL$}Could not compute regex to validate archive name.",
                        "OradazWriter"
                    );
                    debug!("{:FL$}Regex creation error: {:?}", "OradazWriter", err);
                    return Err(Error::RegexError);
                }
            };
            if expected_format.is_match(&mla_writer.mla_path) {
                let mut new_path: String = mla_writer.mla_path.clone();
                new_path.truncate(new_path.len() - 4);
                let final_path = if suffix.is_empty() {
                    new_path
                } else {
                    format!("{new_path}{suffix}")
                };
                if let Err(err) = fs::rename(&mla_writer.mla_path, &final_path) {
                    error!("{:FL$}{}", "OradazWriter", error_msg);
                    debug!(
                        "{:FL$}Failed to rename archive {:?} -> {:?}: {:?}",
                        "OradazWriter", mla_writer.mla_path, final_path, err
                    );
                    return Err(Error::ArchiveRenaming);
                }
            } else {
                error!("{:FL$}{}", "OradazWriter", error_msg);
                debug!(
                    "{:FL$}Archive path {:?} does not match the expected .mla.tmp format; cannot rename",
                    "OradazWriter", mla_writer.mla_path
                );
                return Err(Error::ArchiveRenaming);
            }
        }
        Ok(())
    }

    /// Finalizes the MLA archive and removes the `.tmp` extension from the output file.
    pub fn finalize(&mut self) -> Result<(), Error> {
        if let Some(mla_writer) = &mut self.mla_writer {
            mla_writer.close()?;
        }
        self.rename_mla_archive(
            "",
            "Could not remove '.tmp' extension to MLA file. Please remove it yourself before submitting the file.",
        )?;
        if let Some(final_path) = self.final_mla_path() {
            debug!("{:FL$}Archive finalized: {:?}", "OradazWriter", final_path);
        }
        Ok(())
    }

    /// Finalizes the MLA archive and marks it as `.broken` to indicate an interrupted or failed dump.
    pub fn set_broken(&mut self) -> Result<(), Error> {
        if let Some(mla_writer) = &mut self.mla_writer {
            // Best-effort close. The archive may already be closed — e.g. this is
            // the recovery path after `finalize()` failed, which had already taken
            // the archive handle. A close error here must NOT abort the rename:
            // otherwise the `.mla.tmp` is left dangling with no `.broken` marker
            // signalling the collection failed. `rename_mla_archive` only needs the
            // stored `.tmp` path, which is still valid after a failed/duplicate close.
            if let Err(err) = mla_writer.close() {
                debug!(
                    "{:FL$}MLA close during set_broken failed (archive may already be closed); proceeding with .broken rename: {:?}",
                    "OradazWriter", err
                );
            }
        }
        // Folder output has no extension to flip to `.broken`: drop a marker file
        // so `inspect`'s loader can flag the folder collection as interrupted.
        if let Some(file_writer) = &self.file_writer {
            file_writer.mark_broken();
        }
        self.rename_mla_archive(
            ".broken",
            "Could not replace '.tmp' extension with '.broken' one in MLA file.",
        )
    }

    /// Writes a log entry to all enabled output destinations (MLA archive and/or cleartext file).
    pub fn write_log(&mut self, record: String) -> Result<(), Error> {
        if let Some(mla_writer) = &mut self.mla_writer {
            mla_writer.write_log(&record)?;
        };
        if let Some(file_writer) = &mut self.file_writer {
            file_writer.write_log(&record)?;
        };
        Ok(())
    }

    /// Writes data to a specified file in all enabled output destinations.
    pub fn write_file(&mut self, folder: String, file: String, data: String) -> Result<(), Error> {
        match Path::new(&folder).join(&file).to_str() {
            Some(filepath) => {
                // This is the hottest write path (one call per collected response).
                // Only clone the payload when both outputs are enabled; when a single
                // output is active (the common case) move it straight into that
                // consumer with no copy.
                match (&mut self.mla_writer, &mut self.file_writer) {
                    (Some(mla_writer), Some(file_writer)) => {
                        mla_writer.write_file(filepath, data.clone())?;
                        file_writer.write_file(&folder, &file, data)?;
                    }
                    (Some(mla_writer), None) => {
                        mla_writer.write_file(filepath, data)?;
                    }
                    (None, Some(file_writer)) => {
                        file_writer.write_file(&folder, &file, data)?;
                    }
                    (None, None) => {}
                }
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
