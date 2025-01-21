use crate::exit;
use crate::writer::OradazWriter;

use ansi_term::Colour::{Blue, Red, Yellow};
use chrono::{Datelike, Timelike, Utc};
use lazy_static::lazy_static;
use log::{Level, LevelFilter, Metadata, Record};
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

struct MyLogger {
    writer: Option<Arc<Mutex<OradazWriter>>>,
    is_quiet: bool,
    is_debug: bool,
}

struct MyStaticLogger {
    inner: Mutex<Option<MyLogger>>,
}

lazy_static! {
    static ref MY_LOGGER: MyStaticLogger = MyStaticLogger {
        inner: Mutex::new(None),
    };
}

impl MyLogger {
    fn new(writer: Option<Arc<Mutex<OradazWriter>>>, is_quiet: bool, is_debug: bool) -> Self {
        MyLogger {
            writer,
            is_quiet,
            is_debug,
        }
    }

    fn add_writer(&mut self, writer: Arc<Mutex<OradazWriter>>) {
        self.writer = Some(writer);
    }

    fn remove_writer(&mut self) {
        self.writer = None;
    }

    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Debug
    }

    fn log(&mut self, record: &Record) {
        let metadata = record.metadata();
        // Only log records coming from ORADAZ
        if self.enabled(metadata) && record.target().starts_with("oradaz") {
            if self.is_debug
                || (!self.is_quiet && record.level() <= Level::Info)
                || record.level() <= Level::Warn
            {
                // Write to output with color in any case
                let msg: String = match record.level() {
                    Level::Error => format!(
                        "[{}]\t\t{}\n",
                        Red.paint(record.level().to_string()),
                        record.args()
                    ),
                    Level::Warn => format!(
                        "[{} ]\t\t{}\n",
                        Yellow.paint(record.level().to_string()),
                        record.args()
                    ),
                    Level::Info => format!(
                        "[{} ]\t\t{}\n",
                        Blue.blink().paint(record.level().to_string()),
                        record.args()
                    ),
                    _ => format!("[{:5}]\t\t{}\n", record.level(), record.args()),
                };
                let result = {
                    let stdout = io::stdout();
                    let mut stdout_lock = stdout.lock();
                    stdout_lock.write_all(msg.as_bytes())
                };
                if let Err(err) = result {
                    eprintln!(
                        "[{}] Unable to write to standard output: {}",
                        Red.paint("ERROR"),
                        err
                    );
                    eprintln!("Press Enter to exit.");
                    let _ = io::stdin().read_line(&mut String::new());
                    exit();
                }
            }

            // Send to ORADAZ writer if any
            if let Some(writer) = &self.writer {
                let now = Utc::now();
                let (_is_common_era, year) = now.year_ce();
                let msg: String = format!(
                    "{:02}/{:02}/{} {:02}:{:02}:{:02}  |  {:5}  | {}\n",
                    now.day(),
                    now.month(),
                    year,
                    now.hour(),
                    now.minute(),
                    now.second(),
                    record.level().to_string(),
                    record.args()
                );

                match writer.lock() {
                    Ok(mut w) => {
                        if let Err(err) = w.write_log(msg) {
                            eprintln!(
                                "[{}] Unable to write to log file: {}",
                                Red.paint("ERROR"),
                                err
                            );
                            eprintln!("Press Enter to exit.");
                            let _ = std::io::stdin().read_line(&mut String::new());
                            exit();
                        }
                    }
                    Err(err) => {
                        eprintln!(
                            "[{}] Unable to lock writer to write log file: {}",
                            Red.paint("ERROR"),
                            err
                        );
                        eprintln!("Press Enter to exit.");
                        let _ = std::io::stdin().read_line(&mut String::new());
                        exit();
                    }
                }
            }
        }
    }

    fn flush(&mut self) {
        let _ = io::stdout().flush();
    }
}

impl log::Log for MyStaticLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        match self.inner.lock() {
            Ok(mut i) => {
                if let Some(inner) = i.as_mut() {
                    inner.log(record);
                }
            }
            Err(err) => {
                eprintln!(
                    "[{}] Unable to lock MyStaticLogger to write log: {}",
                    Red.paint("ERROR"),
                    err
                );
                eprintln!("Press Enter to exit.");
                let _ = std::io::stdin().read_line(&mut String::new());
                exit();
            }
        }
    }

    fn flush(&self) {
        match self.inner.lock() {
            Ok(mut i) => {
                if let Some(inner) = i.as_mut() {
                    inner.flush();
                }
            }
            Err(err) => {
                eprintln!(
                    "[{}] Unable to lock MyStaticLogger to flush: {}",
                    Red.paint("ERROR"),
                    err
                );
                eprintln!("Press Enter to exit.");
                let _ = std::io::stdin().read_line(&mut String::new());
                exit();
            }
        }
    }
}

impl MyStaticLogger {
    fn add_writer(&self, writer: &Arc<Mutex<OradazWriter>>) {
        let logger_writer: Arc<Mutex<OradazWriter>> = Arc::clone(writer);
        match self.inner.lock() {
            Ok(mut i) => {
                if let Some(logger) = i.as_mut() {
                    logger.add_writer(logger_writer)
                }
            }
            Err(err) => {
                eprintln!(
                    "[{}] Unable to lock MyStaticLogger to add writer: {}",
                    Red.paint("ERROR"),
                    err
                );
                eprintln!("Press Enter to exit.");
                let _ = std::io::stdin().read_line(&mut String::new());
                exit();
            }
        }
    }

    fn remove_writer(&self) {
        match self.inner.lock() {
            Ok(mut i) => {
                if let Some(logger) = i.as_mut() {
                    logger.remove_writer()
                }
            }
            Err(err) => {
                eprintln!(
                    "[{}] Unable to lock MyStaticLogger to remove writer: {}",
                    Red.paint("ERROR"),
                    err
                );
                eprintln!("Press Enter to exit.");
                let _ = std::io::stdin().read_line(&mut String::new());
                exit();
            }
        }
    }
}

/// Initialize the logging subsystem
pub fn initialize(writer: Option<Arc<Mutex<OradazWriter>>>, is_quiet: bool, is_debug: bool) {
    match MY_LOGGER.inner.lock() {
        Ok(mut i) => *i = Some(MyLogger::new(writer, is_quiet, is_debug)),
        Err(err) => {
            eprintln!(
                "[{}] Unable to lock logger to initialize the logging subsystem: {}",
                Red.paint("ERROR"),
                err
            );
            eprintln!("Press Enter to exit.");
            let _ = io::stdin().read_line(&mut String::new());
            exit();
        }
    }
    if let Err(err) = log::set_logger(&*MY_LOGGER) {
        eprintln!(
            "[{}] Unable to initialize the logging subsystem: {}",
            Red.paint("ERROR"),
            err
        );
        eprintln!("Press Enter to exit.");
        let _ = io::stdin().read_line(&mut String::new());
        exit();
    }
    log::set_max_level(LevelFilter::Debug);
}

pub fn add_writer(writer: &Arc<Mutex<OradazWriter>>) {
    MY_LOGGER.add_writer(writer);
}

pub fn remove_writer() {
    MY_LOGGER.remove_writer();
}
