use crate::auth::{AuthError, Token, Tokens};
use crate::config::Config;
use crate::errors::Error;
use crate::exit;
use crate::prerequisites::Prerequisites;
use crate::requests::Requests;
use crate::schema::{Schema, Url};
use crate::threading::{
    ConditionError, DumpError, RequestMsg, RequestsHandler, WriterHandler, WriterMsg,
};
use crate::writer::OradazWriter;
use crate::Cli;

use crossbeam::channel::{unbounded, Receiver, Sender};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::{thread, time::Duration};

const FL: usize = crate::FL;

pub enum ThreadError {
    AuthError(AuthError),
    ConditionError(ConditionError),
    DumpError(DumpError),
    BlockingError(Error),
}

pub enum MainMsg {
    Finished(usize),
    NewUrl(Url),
    ThreadError(ThreadError),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Table {
    pub name: String,
    pub folder: String,
    pub file: String,
    pub count: usize,
}

pub struct Dumper {
    pub tenant: String,
    pub app_id: String,
    pub requests: Requests,
    pub config: Config,
    pub schema: Schema,
    pub writer: Arc<Mutex<OradazWriter>>,
    pub tokens: HashMap<String, Token>,
    pub requests_threads: usize,
    pub writer_threads: usize,
    pub tables: Vec<Table>,
    pub errors: usize,
    pub condition_errors: usize,
}

impl Dumper {
    pub fn new(
        tenant: &str,
        app_id: &str,
        writer: &Arc<Mutex<OradazWriter>>,
        config: &Config,
        cli: &Cli,
        requests: Requests,
    ) -> Result<Self, Error> {
        /*
        Create new Dumper
        */
        // Parse schema file
        let schema: Schema = Schema::new(cli, writer, &requests)?;

        // Authenticate for the different services
        let mut tokens: HashMap<String, Token> =
            Tokens::initialize(tenant, app_id, config, &schema, writer)?;

        // Check prerequisites
        match config.no_check {
            Some(true) => info!(
                "{:FL$}Skipping prerequisites checks dur to config file option noCheck",
                "Dumper"
            ),
            _ => {
                Prerequisites::check_all(writer, &requests.client, &mut tokens)?;
            }
        };

        // Default number of requests threads is 100
        let requests_threads: usize = config.requests_threads.unwrap_or(100);
        // Default number of requests threads is 5
        let writer_threads: usize = config.writer_threads.unwrap_or(100);

        Ok(Self {
            tenant: tenant.to_string(),
            app_id: app_id.to_string(),
            requests,
            config: config.clone(),
            schema,
            writer: Arc::clone(writer),
            tokens,
            requests_threads,
            writer_threads,
            tables: Vec::new(),
            errors: 0,
            condition_errors: 0,
        })
    }

    pub fn write_dump_error(&mut self, message: String, url: Url) {
        /*
        Write a dump error in archive
        */
        // Add to errors.json
        self.errors += 1;
        let dump_error = DumpError {
            folder: url.service_name,
            file: url.api,
            url: url.url,
            status: 0,
            code: String::from("SendRequestMsgFromInitialUrlError"),
            message,
        };
        let string_error: String = match serde_json::to_string(&dump_error) {
            Err(err) => {
                error!("{:FL$}Could not convert dump_error to json", "Dumper");
                debug!("{}", err);
                match self.writer.lock() {
                    Ok(mut w) => {
                        if let Err(error) = w.set_broken() {
                            error!("{:FL$}{}", "Dumper", error);
                        };
                    }
                    Err(err) => {
                        error!(
                            "{:FL$}Error while locking Writer, could not treat archive as broken",
                            "Dumper"
                        );
                        error!("{:FL$}{}", "Dumper", Error::WriterLock);
                        debug!("{}", err);
                    }
                }
                exit();
                String::new()
            }
            Ok(j) => format!("{}\n", j),
        };
        match self.writer.lock() {
            Ok(mut w) => {
                if let Err(err) =
                    w.write_file(String::new(), "errors.json".to_string(), string_error)
                {
                    error!("{:FL$}{}", "Dumper", err);
                    exit()
                };
            }
            Err(err) => {
                error!("{:FL$}Error while locking Writer to write errors", "Dumper");
                error!("{:FL$}{}", "Dumper", Error::WriterLock);
                debug!("{}", err);
                exit()
            }
        }
    }

    pub fn dump(&mut self) -> Result<usize, Error> {
        /*
        Perform the dump based on the schema file
        */
        // Construct urls
        let u: Result<Vec<Url>, Error> =
            self.schema
                .clone()
                .get_urls(self.tenant.clone(), &self.tokens, &self.requests.client);
        let urls: Vec<Url> = match u {
            Ok(urls) => urls,
            Err(err) => {
                return Err(err);
            }
        };

        // Create unbounded channels to send and receive messages between threads
        // Dumper ---s1/r1---> RequestThread
        let (s1, r1) = unbounded::<RequestMsg>();
        // RequestThread ---s2/r2---> WriterThread
        let (s2, r2) = unbounded::<WriterMsg>();
        // WriterThread ---s3/r3---> Dumper
        let (s3, r3) = unbounded::<MainMsg>();

        // Pushing the channels in Arc Mutex
        let main_sender: Arc<Mutex<Sender<RequestMsg>>> = Arc::new(Mutex::new(s1));
        let requests_receiver: Arc<Mutex<Receiver<RequestMsg>>> = Arc::new(Mutex::new(r1));
        let requests_sender: Arc<Mutex<Sender<WriterMsg>>> = Arc::new(Mutex::new(s2));
        let writer_receiver: Arc<Mutex<Receiver<WriterMsg>>> = Arc::new(Mutex::new(r2));
        let writer_sender: Arc<Mutex<Sender<MainMsg>>> = Arc::new(Mutex::new(s3));

        // Thread to handle the processing of the requests
        let requests_count: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
        let tokens: Arc<Mutex<HashMap<String, Token>>> = Arc::new(Mutex::new(self.tokens.clone()));
        let requests_handle = thread::spawn({
            let requests_count: Arc<Mutex<usize>> = Arc::clone(&requests_count);
            let requests_receiver: Arc<Mutex<Receiver<RequestMsg>>> =
                Arc::clone(&requests_receiver);
            let requests_sender: Arc<Mutex<Sender<WriterMsg>>> = Arc::clone(&requests_sender);
            let writer_sender: Arc<Mutex<Sender<MainMsg>>> = Arc::clone(&writer_sender);
            let main_sender: Arc<Mutex<Sender<RequestMsg>>> = Arc::clone(&main_sender);
            let tokens_sender: Arc<Mutex<HashMap<String, Token>>> = Arc::clone(&tokens);
            let client = self.requests.clone().client;
            let requests_threads: usize = self.requests_threads;
            let requests_config: Config = self.config.clone();
            move || {
                let rh = RequestsHandler::new(
                    requests_config,
                    requests_threads,
                    requests_receiver,
                    requests_sender,
                    writer_sender,
                    main_sender,
                    client,
                    tokens_sender,
                    requests_count,
                );
                rh.start()
            }
        });

        // Thread to handle writing the results
        let tables: Arc<Mutex<HashMap<String, Table>>> = Arc::new(Mutex::new(HashMap::new()));
        let writer_handle = thread::spawn({
            let oradaz_writer: Arc<Mutex<OradazWriter>> = Arc::clone(&self.writer);
            let thread_tables: Arc<Mutex<HashMap<String, Table>>> = Arc::clone(&tables);
            let writer_receiver: Arc<Mutex<Receiver<WriterMsg>>> = Arc::clone(&writer_receiver);
            let writer_sender: Arc<Mutex<Sender<MainMsg>>> = Arc::clone(&writer_sender);
            let main_sender: Arc<Mutex<Sender<RequestMsg>>> = Arc::clone(&main_sender);
            let tokens_sender: Arc<Mutex<HashMap<String, Token>>> = Arc::clone(&tokens);
            let writer_threads: usize = self.writer_threads;
            let tenant_threads: String = self.tenant.clone();
            let client = self.requests.clone().client;
            move || {
                let rh = WriterHandler::new(
                    tenant_threads,
                    writer_threads,
                    writer_receiver,
                    writer_sender,
                    main_sender,
                    oradaz_writer,
                    thread_tables,
                    client,
                    tokens_sender,
                );
                match rh.start() {
                    Ok(r) => r,
                    Err(err) => return Err(err),
                };
                Ok(())
            }
        });

        // Send the URLs to be processed
        let mut counter = 0;
        let main_sender: Arc<Mutex<Sender<RequestMsg>>> = Arc::clone(&main_sender);
        for url in urls {
            counter += 1;
            match main_sender.lock() {
                Ok(s) => {
                    if let Err(err) = s.send(RequestMsg::Url(url.clone())) {
                        warn!("{:FL$}Error sending initial URL to RequestThread", "Dumper");
                        debug!(
                            "Skipping data for service {:?}: {:?} - {:?}",
                            url.service_name, url.api, url.url
                        );
                        debug!("{}", err);
                        self.write_dump_error(err.to_string(), url);
                        counter -= 1;
                    };
                }
                Err(err) => {
                    error!(
                        "{:FL$}Error while locking Dumper sender to send URLs to be processed",
                        "Dumper"
                    );
                    error!("{:FL$}{}", "Dumper", Error::SenderLock);
                    debug!("{}", err);
                    exit()
                }
            }
        }

        // Wait response and send new urls if any
        while counter > 0 {
            // Timeout after 5 minutes in case of missing message to decrease counter
            match r3.recv_timeout(Duration::from_secs(300)) {
                Ok(msg) => match msg {
                    MainMsg::Finished(i) => {
                        // A URL has been processed correctly
                        counter -= i;
                    }
                    MainMsg::NewUrl(url) => {
                        // A new URL need to be processed
                        counter += 1;
                        match main_sender.lock() {
                            Ok(s) => {
                                if let Err(err) = s.send(RequestMsg::Url(url.clone())) {
                                    warn!("{:FL$}Error sending new URL to RequestThread", "Dumper");
                                    debug!(
                                        "Skipping data for service {:?}: {:?} - {:?}",
                                        url.service_name, url.api, url.url
                                    );
                                    debug!("{}", err);
                                    self.write_dump_error(err.to_string(), url);
                                    counter -= 1;
                                };
                            }
                            Err(err) => {
                                error!(
                                    "{:FL$}Error while locking Dumper sender to send new URLs to be processed",
                                    "Dumper"
                                );
                                error!("{:FL$}{}", "Dumper", Error::SenderLock);
                                debug!("{}", err);
                                exit()
                            }
                        }
                    }
                    MainMsg::ThreadError(thread_error) => match thread_error {
                        // An error occured while processing a URL
                        ThreadError::AuthError(auth_error) => {
                            // Write authentication error to auth_errors.json
                            let string_error: String = match serde_json::to_string(&auth_error) {
                                Err(err) => {
                                    error!("{:FL$}Could not convert auth_error to json", "Dumper");
                                    debug!("{}", err);
                                    match self.writer.lock() {
                                        Ok(mut w) => {
                                            if let Err(error) = w.set_broken() {
                                                error!("{:FL$}{}", "Dumper", error);
                                            };
                                        }
                                        Err(err) => {
                                            error!("{:FL$}Error while locking Writer, could not treat archive as broken", "Dumper");
                                            error!("{:FL$}{}", "Dumper", Error::WriterLock);
                                            debug!("{}", err);
                                        }
                                    }
                                    exit();
                                    String::new()
                                }
                                Ok(j) => format!("{}\n", j),
                            };
                            match self.writer.lock() {
                                Ok(mut w) => {
                                    if let Err(err) = w.write_file(
                                        String::new(),
                                        "auth_errors.json".to_string(),
                                        string_error,
                                    ) {
                                        error!("{:FL$}{}", "Dumper", err);
                                        exit()
                                    };
                                }
                                Err(err) => {
                                    error!(
                                        "{:FL$}Error while locking Writer to write auth errors",
                                        "Dumper"
                                    );
                                    error!("{:FL$}{}", "Dumper", Error::WriterLock);
                                    debug!("{}", err);
                                    exit()
                                }
                            }
                        }
                        ThreadError::DumpError(dump_error) => {
                            // Write dump error to errors.json
                            self.errors += 1;
                            let string_error: String = match serde_json::to_string(&dump_error) {
                                Err(err) => {
                                    error!("{:FL$}Could not convert dump_error to json", "Dumper");
                                    debug!("{}", err);
                                    match self.writer.lock() {
                                        Ok(mut w) => {
                                            if let Err(error) = w.set_broken() {
                                                error!("{:FL$}{}", "Dumper", error);
                                            };
                                        }
                                        Err(err) => {
                                            error!("{:FL$}Error while locking Writer, could not treat archive as broken", "Dumper");
                                            error!("{:FL$}{}", "Dumper", Error::WriterLock);
                                            debug!("{}", err);
                                        }
                                    }
                                    exit();
                                    String::new()
                                }
                                Ok(j) => format!("{}\n", j),
                            };
                            match self.writer.lock() {
                                Ok(mut w) => {
                                    if let Err(err) = w.write_file(
                                        String::new(),
                                        "errors.json".to_string(),
                                        string_error,
                                    ) {
                                        error!("{:FL$}{}", "Dumper", err);
                                        exit()
                                    };
                                }
                                Err(err) => {
                                    error!(
                                        "{:FL$}Error while locking Writer to write dump errors",
                                        "Dumper"
                                    );
                                    error!("{:FL$}{}", "Dumper", Error::WriterLock);
                                    debug!("{}", err);
                                    exit()
                                }
                            }
                        }
                        ThreadError::ConditionError(condition_error) => {
                            // Write condition error to condition_errors.json
                            self.condition_errors += 1;
                            let string_error: String = match serde_json::to_string(&condition_error)
                            {
                                Err(err) => {
                                    error!(
                                        "{:FL$}Could not convert condition_error to json",
                                        "Dumper"
                                    );
                                    debug!("{}", err);
                                    match self.writer.lock() {
                                        Ok(mut w) => {
                                            if let Err(error) = w.set_broken() {
                                                error!("{:FL$}{}", "Dumper", error);
                                            };
                                        }
                                        Err(err) => {
                                            error!("{:FL$}Error while locking Writer, could not treat archive as broken", "Dumper");
                                            error!("{:FL$}{}", "Dumper", Error::WriterLock);
                                            debug!("{}", err);
                                        }
                                    }
                                    exit();
                                    String::new()
                                }
                                Ok(j) => format!("{}\n", j),
                            };
                            match self.writer.lock() {
                                Ok(mut w) => {
                                    if let Err(err) = w.write_file(
                                        String::new(),
                                        "condition_errors.json".to_string(),
                                        string_error,
                                    ) {
                                        error!("{:FL$}{}", "Dumper", err);
                                        exit()
                                    };
                                }
                                Err(err) => {
                                    error!(
                                        "{:FL$}Error while locking Writer to write condition errors",
                                        "Dumper"
                                    );
                                    error!("{:FL$}{}", "Dumper", Error::WriterLock);
                                    debug!("{}", err);
                                    exit()
                                }
                            }
                        }
                        ThreadError::BlockingError(err) => {
                            // Received error indicating to stop the dump
                            error!("{:FL$}{}", "Dumper", err);
                            match self.writer.lock() {
                                Ok(mut w) => {
                                    if let Err(error) = w.set_broken() {
                                        error!("{:FL$}{}", "Dumper", error);
                                    };
                                }
                                Err(err) => {
                                    error!("{:FL$}Error while locking Writer, could not treat archive as broken", "Dumper");
                                    error!("{:FL$}{}", "Dumper", Error::WriterLock);
                                    debug!("{}", err);
                                }
                            }
                            exit()
                        }
                    },
                },
                Err(err) => {
                    error!(
                        "{:FL$}Timeout while waiting data from WriterThread",
                        "Dumper"
                    );
                    debug!("{}", err);
                    debug!("Counter is still {}", counter);
                    match self.writer.lock() {
                        Ok(mut w) => {
                            if let Err(error) = w.set_broken() {
                                error!("{:FL$}{}", "Dumper", error);
                            };
                        }
                        Err(err) => {
                            error!("{:FL$}Error while locking Writer, could not treat archive as broken", "Dumper");
                            error!("{:FL$}{}", "Dumper", Error::WriterLock);
                            debug!("{}", err);
                        }
                    }
                    exit()
                }
            }
        }

        // No more urls to process, finishing all threads
        debug!("Finishing all threads");
        for _ in 0..self.requests_threads {
            match main_sender.lock() {
                Ok(s) => {
                    if let Err(err) = s.send(RequestMsg::Terminate) {
                        error!(
                            "{:FL$}Error sending finish request to RequestThread",
                            "Dumper"
                        );
                        debug!("{}", err);
                    };
                }
                Err(err) => {
                    error!(
                        "{:FL$}Error while locking Dumper sender to send finish requests to RequestThreads",
                        "Dumper"
                    );
                    error!("{:FL$}{}", "Dumper", Error::SenderLock);
                    debug!("{}", err);
                }
            }
        }
        let requests_sender: Arc<Mutex<Sender<WriterMsg>>> = Arc::clone(&requests_sender);
        for _ in 0..self.writer_threads {
            match requests_sender.lock() {
                Ok(s) => {
                    if let Err(err) = s.send(WriterMsg::Terminate) {
                        error!(
                            "{:FL$}Error sending finish request to WriterThread",
                            "Dumper"
                        );
                        debug!("{}", err);
                    };
                }
                Err(err) => {
                    error!(
                        "{:FL$}Error while locking Dumper sender to send finish requests to WriterThreads",
                        "Dumper"
                    );
                    error!("{:FL$}{}", "Dumper", Error::SenderLock);
                    debug!("{}", err);
                }
            }
        }

        thread::sleep(Duration::from_secs(2));
        drop(main_sender);
        drop(r3);
        if requests_handle.join().is_err() {
            error!("{:FL$}Error finishing request thread", "Dumper");
        };
        if writer_handle.join().is_err() {
            error!("{:FL$}Error finishing writer thread", "Dumper");
        };

        // Storing metadata
        match tables.lock() {
            Ok(tables) => {
                self.tables = <HashMap<String, Table> as Clone>::clone(&tables)
                    .into_values()
                    .collect();
            }
            Err(err) => {
                error!(
                    "{:FL$}Could not lock tables for later write, exiting",
                    "Dumper"
                );
                debug!("{}", err);
                exit();
            }
        }

        match Arc::clone(&requests_count).lock() {
            Ok(c) => Ok(*c),
            Err(err) => {
                warn!(
                    "{:FL$}Could not return requests counts, returning 0 instead",
                    "Dumper"
                );
                debug!("{}", err);
                Ok(0)
            }
        }
    }
}
