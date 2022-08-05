//! Logger which logs messages to a file and to the standard output
use ansi_term::Colour::{Blue, Red, Yellow};
use chrono::{Datelike, Timelike, Utc};
use lazy_static::lazy_static;
use log::{Level};
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::process::exit;
use std::sync::Mutex;


struct MyLogger {
    log_file: File,
    is_quiet: bool,
    is_debug: bool,
}

/// Wraps MyLogger in order to allow a static variable
struct MyStaticLogger {
    inner: Mutex<Option<MyLogger>>,
}

lazy_static! {
    static ref MY_LOGGER: MyStaticLogger = MyStaticLogger {
        inner: Mutex::new(None),
    };
}

impl MyLogger {
    fn new<P: AsRef<Path>>(log_file: P, is_quiet: bool, is_debug: bool) -> Self {
        match File::create(&log_file) {
            Ok(log_file) => MyLogger {
                log_file, // Do NOT wrap the log file into a BufWriter, as write() is expected to be atomic.
                is_quiet,
                is_debug,
            },
            Err(err) => {
                eprintln!(
                    "[ERROR] Unable to open log file {}: {}",
                    log_file.as_ref().display(),
                    err
                );
                eprintln!("Press Enter to exit.");
                let _ = std::io::stdin().read_line(&mut String::new()).unwrap();
                exit(2); // TODO : real error number
            }
        }
    }

    fn enabled(&self, metadata: &log::Metadata) -> bool {
        if self.is_debug {
            metadata.level() <= log::Level::Debug
        } else {
            metadata.level() <= log::Level::Info
        }
    }

    fn log(&mut self, record: &log::Record) {
        let metadata = record.metadata();
        if self.enabled(metadata) {
            if !self.is_quiet || metadata.level() <= log::Level::Warn {
                // println!() is not atomic, as it calls write_all on all bytes.
                // Use format!()+lock()+write_all() instead
                let msg = match record.level() {
                    Level::Error => format!("[{:5}]\t\t{}\n", Red.paint(record.level().to_string()), record.args()),
                    Level::Warn => format!("[{:5}]\t\t{}\n", Yellow.paint(record.level().to_string()), record.args()),
                    Level::Info => format!("[{:5}]\t\t{}\n", Blue.blink().paint(record.level().to_string()), record.args()),
                    _ => format!("[{:5}]\t\t{}\n", record.level(), record.args())
                };
                let result = {
                    let stdout = io::stdout();
                    let mut stdout_lock = stdout.lock();
                    stdout_lock.write_all(msg.as_bytes())
                };
                if let Err(err) = result {
                    eprintln!("[ERROR] Unable to write to standard output: {}", err);
                    eprintln!("Press Enter to exit.");
                    let _ = std::io::stdin().read_line(&mut String::new()).unwrap();
                    exit(1);
                }
            }
            let now = Utc::now();
            let (_is_common_era, year) = now.year_ce();
            let msg = format!(
                "{:02}/{:02}/{} {:02}:{:02}:{:02}\t\t[{:5}]\t\t{}\n",
                now.day(),
                now.month(),
                year,
                now.hour(),
                now.minute(),
                now.second(),
                record.level().to_string(),
                record.args()
            );
            // Use write and not a macro in order to make sure the write() syscall is called directly
            if let Err(err) = self.log_file.write_all(msg.as_bytes()) {
                // Being unable to write to the log file is fatal
                eprintln!("[ERROR] Unable to write to log file: {}", err);
                eprintln!("Press Enter to exit.");
                let _ = std::io::stdin().read_line(&mut String::new()).unwrap();
                exit(1);
            }
        }
    }

    fn flush(&mut self) {
        let _ = io::stdout().flush();
        let _ = self.log_file.flush();
    }
}

impl log::Log for MyStaticLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }
    fn log(&self, record: &log::Record) {
        if let Some(inner) = self.inner.lock().unwrap().as_mut() {
            inner.log(record);
        }
    }
    fn flush(&self) {
        if let Some(inner) = self.inner.lock().unwrap().as_mut() {
            inner.flush();
        }
    }
}

/// Initialize the logging subsystem
pub fn initialize<P: AsRef<Path>>(log_file_path: P, is_quiet: bool, is_debug: bool) {
    *MY_LOGGER.inner.lock().unwrap() = Some(MyLogger::new(log_file_path, is_quiet, is_debug));
    if let Err(err) = log::set_logger(&*MY_LOGGER) {
        eprintln!("[ERROR] Unable to initialize the logging subsystem: {}", err);
        eprintln!("Press Enter to exit.");
        let _ = std::io::stdin().read_line(&mut String::new()).unwrap();
        exit(1);
    }
    if is_debug {
        log::set_max_level(log::LevelFilter::Debug);
    } else {
        log::set_max_level(log::LevelFilter::Info);
    }
}