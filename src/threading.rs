use crate::auth::{Auth, AuthError, Token};
use crate::conditions::Conditions;
use crate::config::Config;
use crate::dumper::{MainMsg, Table, ThreadError};
use crate::errors::Error;
use crate::exit;
use crate::prerequisites::Prerequisites;
use crate::schema::{RelationshipUrl, Url};
use crate::writer::OradazWriter;

use ansi_term::Colour::{Red, White};
use chrono::Utc;
use crossbeam::channel::{Receiver, Sender};
use log::{debug, error, info, warn};
use rayon::ThreadPoolBuilder;
use reqwest::blocking::{Client, Response};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::{thread, time::Duration};

const FL: usize = crate::FL;
pub const REFRESH_TOKEN_EXPIRATION_THRESHOLD: i64 = 600;

pub struct Terminate {}

#[derive(Serialize)]
pub struct ConditionError {
    pub folder: String,
    pub file: String,
    pub url: String,
    pub condition: String,
    pub status: u16,
    pub code: String,
    pub message: String,
}

#[derive(Serialize)]
pub struct DumpError {
    pub folder: String,
    pub file: String,
    pub url: String,
    pub status: u16,
    pub code: String,
    pub message: String,
}

pub struct ResponseData {
    pub folder: String,
    pub file: String,
    pub data: Vec<Value>,
    pub url: Url,
}

pub enum RequestMsg {
    Url(Url),
    Terminate,
    Sleep,
}

pub enum WriterMsg {
    ResponseData(ResponseData),
    Terminate,
}

pub struct RequestsHandler {
    config: Config,
    thread_limit: usize,
    receiver: Arc<Mutex<Receiver<RequestMsg>>>,
    sender: Arc<Mutex<Sender<WriterMsg>>>,
    writer_sender: Arc<Mutex<Sender<MainMsg>>>,
    main_sender: Arc<Mutex<Sender<RequestMsg>>>,
    client: Client,
    tokens: Arc<Mutex<HashMap<String, Token>>>,
    requests_count: Arc<Mutex<usize>>,
}

impl RequestsHandler {
    pub fn new(
        config: Config,
        thread_limit: usize,
        receiver: Arc<Mutex<Receiver<RequestMsg>>>,
        sender: Arc<Mutex<Sender<WriterMsg>>>,
        writer_sender: Arc<Mutex<Sender<MainMsg>>>,
        main_sender: Arc<Mutex<Sender<RequestMsg>>>,
        client: Client,
        tokens: Arc<Mutex<HashMap<String, Token>>>,
        requests_count: Arc<Mutex<usize>>,
    ) -> Self {
        /*
        Initialize RequestHandler
        */
        RequestsHandler {
            config,
            thread_limit,
            receiver,
            sender,
            writer_sender,
            main_sender,
            client,
            tokens,
            requests_count,
        }
    }

    pub fn start(self) -> Result<(), Error> {
        /*
        Create a ThreadPool to handle received RequestMsg
        For each RequestMsg::Url, spawn a RequestThread in the ThreadPool
        */
        let pool = match ThreadPoolBuilder::new()
            .num_threads(self.thread_limit)
            .build()
        {
            Ok(p) => {
                debug!(
                    "{:FL$}Successfully created multithread pool with {} request threads",
                    "RequestsHandler", self.thread_limit
                );
                p
            }
            Err(err) => {
                error!(
                    "{:FL$}Cannot create multithread pool to perform the dump",
                    "RequestsHandler"
                );
                debug!("{}", err);
                return Err(Error::ThreadPoolBuilderCreation);
            }
        };
        let tokens_to_update: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

        match self.receiver.lock() {
            Ok(receiver) => {
                loop {
                    if let Ok(msg) = receiver.recv() {
                        match msg {
                            RequestMsg::Terminate => {
                                // Received a message requesting thread termination
                                break;
                            }
                            RequestMsg::Sleep => {
                                // Received a message requesting a thread sleep to handle HTTP status coe 429
                                thread::sleep(Duration::from_secs(2));
                            }
                            RequestMsg::Url(url) => {
                                // Received a valid URL, creating a thread to perform request
                                pool.spawn({
                                    let thread_sender: Arc<Mutex<Sender<WriterMsg>>> =
                                        Arc::clone(&self.sender);
                                    let writer_sender: Arc<Mutex<Sender<MainMsg>>> =
                                        Arc::clone(&self.writer_sender);
                                    let main_sender: Arc<Mutex<Sender<RequestMsg>>> =
                                        Arc::clone(&self.main_sender);
                                    let thread_tokens: Arc<Mutex<HashMap<String, Token>>> =
                                        Arc::clone(&self.tokens);
                                    let thread_tokens_to_update: Arc<Mutex<HashSet<String>>> =
                                        Arc::clone(&tokens_to_update);
                                    let requests_count: Arc<Mutex<usize>> =
                                        Arc::clone(&self.requests_count);
                                    let config = self.config.clone();
                                    let client: Client = self.client.clone();
                                    move || {
                                        let rt: RequestsThread = RequestsThread::new(
                                            config,
                                            client,
                                            thread_tokens,
                                            url,
                                            thread_sender,
                                            writer_sender,
                                            main_sender,
                                            requests_count,
                                            thread_tokens_to_update,
                                        );
                                        rt.process();
                                    }
                                });
                            }
                        }
                    }
                }
            }
            Err(err) => {
                error!(
                    "{:FL$}Could not lock receiver while starting multithread pool loop to perform the dump",
                    "RequestsHandler"
                );
                debug!("{}", err);
                return Err(Error::ReceiverLock);
            }
        }

        drop(self.receiver);
        drop(self.sender);
        Ok(())
    }
}

pub struct RequestsThread {
    config: Config,
    client: Client,
    tokens: Arc<Mutex<HashMap<String, Token>>>,
    url: Url,
    sender: Arc<Mutex<Sender<WriterMsg>>>,
    writer_sender: Arc<Mutex<Sender<MainMsg>>>,
    main_sender: Arc<Mutex<Sender<RequestMsg>>>,
    requests_count: Arc<Mutex<usize>>,
    tokens_to_update: Arc<Mutex<HashSet<String>>>,
}

impl RequestsThread {
    pub fn new(
        config: Config,
        client: Client,
        tokens: Arc<Mutex<HashMap<String, Token>>>,
        url: Url,
        sender: Arc<Mutex<Sender<WriterMsg>>>,
        writer_sender: Arc<Mutex<Sender<MainMsg>>>,
        main_sender: Arc<Mutex<Sender<RequestMsg>>>,
        requests_count: Arc<Mutex<usize>>,
        tokens_to_update: Arc<Mutex<HashSet<String>>>,
    ) -> Self {
        /*
        Initialize RequestThread
        */
        RequestsThread {
            config,
            client,
            tokens,
            url,
            sender,
            writer_sender,
            main_sender,
            requests_count,
            tokens_to_update,
        }
    }

    fn send_to_dumper(&self, msg: MainMsg) {
        /*
        Send a MainMsg to Dumper
        */
        match self.writer_sender.lock() {
            Ok(sender) => {
                if let Err(err) = sender.send(msg) {
                    error!(
                        "{:FL$}Error sending data to Dumper, exiting",
                        "RequestThread"
                    );
                    debug!("{}", err);
                    exit();
                };
            }
            Err(err) => {
                error!(
                    "{:FL$}Error locking sender to send data to Dumper, exiting",
                    "RequestThread"
                );
                error!("{:FL$}{}", "RequestThread", Error::SenderLock);
                debug!("{}", err);
                exit();
            }
        }
    }

    fn send_to_request(&self, msg: RequestMsg) {
        /*
        Send a RequestMsg to RequestHandler
        */
        match self.main_sender.lock() {
            Ok(sender) => {
                if let Err(err) = sender.send(msg) {
                    error!(
                        "{:FL$}Error sending data to RequestHandler",
                        "RequestThread"
                    );
                    debug!("{}", err);
                    self.send_to_dumper(MainMsg::ThreadError(ThreadError::BlockingError(
                        Error::ChannelError,
                    )));
                };
            }
            Err(err) => {
                error!(
                    "{:FL$}Error locking sender to send data to RequestHandler",
                    "RequestThread"
                );
                error!("{:FL$}{}", "RequestThread", Error::SenderLock);
                debug!("{}", err);
                self.send_to_dumper(MainMsg::ThreadError(ThreadError::BlockingError(
                    Error::ChannelError,
                )));
            }
        }
    }

    fn send_to_writer(&self, msg: WriterMsg) {
        /*
        Send a WriterMsg to WriterHandler
        */
        match self.sender.lock() {
            Ok(sender) => {
                if let Err(err) = sender.send(msg) {
                    error!("{:FL$}Error sending data to WriterHandler", "RequestThread");
                    debug!("{}", err);
                    self.send_to_dumper(MainMsg::ThreadError(ThreadError::BlockingError(
                        Error::ChannelError,
                    )));
                };
            }
            Err(err) => {
                error!(
                    "{:FL$}Error locking sender to send data to WriterHandler",
                    "RequestThread"
                );
                error!("{:FL$}{}", "RequestThread", Error::SenderLock);
                debug!("{}", err);
                self.send_to_dumper(MainMsg::ThreadError(ThreadError::BlockingError(
                    Error::ChannelError,
                )));
            }
        }
    }

    pub fn process(self) {
        /*
        Process the URL.
        If success, send the results to WriterHandler.
        If new URL to be processed, send them to Dumper for later processing.
        If error, either reprocess the URL or send a message to Dumper
        */

        // Retrieve the token corresponding to the URL to process
        let token: Option<Token> = match self.tokens.lock() {
            Ok(mut tokens) => {
                match tokens.get_mut(&self.url.service_name) {
                    Some(t) => {
                        // Update token if it will expire
                        match self.tokens_to_update.lock() {
                            Ok(mut tokens_to_update) => {
                                if tokens_to_update.contains(&self.url.service_name.clone())
                                    || t.expires_on - Utc::now().timestamp()
                                        < REFRESH_TOKEN_EXPIRATION_THRESHOLD
                                {
                                    if let Err(Error::Reprocess) = self.update_token(t) {
                                        // Send the URL to be processed again
                                        self.send_to_request(RequestMsg::Url(self.url.clone()));
                                        return;
                                    }
                                    tokens_to_update.remove(&self.url.service_name.clone());
                                }
                            }
                            Err(err) => {
                                error!(
                                    "{:FL$}Could not lock tokens to update while processing api request {:?} for service {:?}, retrying later",
                                    "RequestThread", self.url.api, self.url.service_name
                                );
                                debug!("{}", err);
                                // Send the URL to be processed again
                                self.send_to_request(RequestMsg::Url(self.url.clone()));
                                return;
                            }
                        }
                        Some(t.clone())
                    }
                    None => {
                        error!(
                            "{:FL$}Received api request {:?} for invalid service {:?}",
                            "RequestThread", self.url.api, self.url.service_name
                        );
                        debug!(
                            "Received api for service {:?} in request thread: {:?} - {:?}",
                            self.url.service_name, self.url.api, self.url.url
                        );
                        self.send_to_dumper(MainMsg::Finished(1));
                        None
                    }
                }
            }
            Err(err) => {
                error!(
                    "{:FL$}Could not lock tokens while processing api request {:?} for service {:?}, retrying later",
                    "RequestThread", self.url.api, self.url.service_name
                );
                debug!("{}", err);
                // Send the URL to be processed again
                self.send_to_request(RequestMsg::Url(self.url.clone()));
                return;
            }
        };

        // Continue outside of previous match to free use of tokens
        if let Some(t) = token {
            // Skip Url if any condition is not met
            match &self.url.conditions {
                None => {}
                Some(c) => {
                    for condition in c.iter() {
                        if !Conditions::check(&self.client, &t, condition.clone()) {
                            debug!(
                                "{:FL$}API {:?} for service {:?} does not meet condition {:?}, skipping it",
                                "RequestThread", &self.url.api, &self.url.service_name, condition
                            );
                            // Add to condition errors
                            self.send_to_dumper(MainMsg::ThreadError(ThreadError::ConditionError(ConditionError{
                                folder: self.url.service_name.clone(),
                                file: self.url.api.clone(),
                                url: self.url.url.clone(),
                                condition: condition.clone(),
                                status: 0,
                                code: String::from("conditionNotMet"),
                                message: format!(
                                    "{:FL$}API {:?} for service {:?} does not meet condition {:?}, skipping it",
                                    "RequestThread", &self.url.api, &self.url.service_name, condition
                                )
                            })));
                            // Skip Url
                            // Indicate that processing of this URL is finished
                            self.send_to_dumper(MainMsg::Finished(1));
                            return;
                        }
                    }
                }
            }

            // Perform request
            match self.requests_count.lock() {
                Ok(mut requests_count) => {
                    *requests_count += 1;
                }
                Err(err) => {
                    warn!(
                        "{:FL$}Could not increase request counts due to lock failure. Displayed requests count will not be accurate.", 
                        "RequestThread"
                    );
                    debug!("{}", err);
                }
            }
            match self
                .client
                .get(&self.url.url)
                .header(
                    reqwest::header::AUTHORIZATION,
                    &format!("{} {}", t.token_type, t.access_token.secret()),
                )
                .send()
            {
                Err(err) => {
                    if err.is_timeout() {
                        debug!(
                            "{:FL$}Timeout for request to url {:?}, retrying.",
                            "RequestThread", &self.url.url
                        )
                    } else if err.is_connect() {
                        debug!(
                            "{:FL$}Network error for request to url {:?}, retrying.",
                            "RequestThread", &self.url.url
                        )
                    } else {
                        warn!(
                            "{:FL$}Error performing request to url {:?}, retrying.",
                            "RequestThread", &self.url.url
                        );
                        debug!("{}", err);
                    }
                    // Send the URL to be processed again
                    self.send_to_request(RequestMsg::Url(self.url.clone()));
                }
                Ok(res) => {
                    // Parse response
                    if let Err(Error::ErrorCodeDueToPrerequisites) =
                        self.parse_response(&mut t.clone(), res)
                    {
                        // Send the URL to be processed again
                        self.send_to_request(RequestMsg::Url(self.url.clone()));
                    };
                }
            };
        }
    }

    fn update_token(&self, t: &mut Token) -> Result<(), Error> {
        /*
        Refresh the tokens if a refresh token is available
        Perform new authentication otherwise
        */
        match Token::refresh_token(t.clone()) {
            Err(Error::NewAuthRequired) => {
                // Perform new authentication as no refresh token is available
                info!(
                    "{:FL$}The token for service {:?} is expired and no refresh token is available. A new authentication is required.",
                    "RequestThread", t.service
                );
                if let Err(err) = match Auth::new(
                    &t.tenant_id,
                    &t.client_id,
                    &self.url.service_scopes.clone(),
                    &self.url.service_description.clone(),
                ) {
                    Err(err) => Err(err),
                    Ok(a) => match a.get_token(
                        t.tenant_id.clone(),
                        t.client_id.clone(),
                        self.url.service_name.clone(),
                    ) {
                        Ok(mut j) => {
                            if j.user_id != t.user_id
                                || j.user_principal_name != t.user_principal_name
                            {
                                error!(
                                        "{:FL$}The user you authenticated with is not the same as before, reauthenticate with the same user",
                                        "RequestThread"
                                    );
                                Err(Error::DeviceCodeFlowUnexpectedEnd)
                            } else if let Some(true) = self.config.no_check {
                                t.expires_on = j.expires_on;
                                t.access_token = j.access_token;
                                t.refresh_token = j.refresh_token;
                                t.token_type = j.token_type;
                                t.user_id = j.user_id;
                                t.user_principal_name = j.user_principal_name;
                                Ok(())
                            } else {
                                let mut retry: bool = true;
                                let mut res: Result<(), Error> = Ok(());
                                while retry {
                                    match Prerequisites::check(&self.client, &mut j, true, false) {
                                        Err(Error::TooManyRequestsDuringPrerequisites) => {
                                            // Too many requests, sleep for 2 seconds and retry
                                            thread::sleep(Duration::from_secs(2));
                                        }
                                        Err(_) => {
                                            retry = false;
                                            println!("\n\n");
                                            error!(
                                                "{}{}{}",
                                                White
                                                    .on(Red)
                                                    .paint("Please fix the above error in prerequisite check for service '"),
                                                White.on(Red).paint(&t.service),
                                                White.on(Red).paint("' and press Enter to continue dump")
                                            );
                                            let _ = std::io::stdin().read_line(&mut String::new());
                                            res = Err(Error::DeviceCodeFlowUnexpectedEnd);
                                        }
                                        Ok(()) => {
                                            retry = false;
                                            t.expires_on = j.expires_on;
                                            t.access_token = j.access_token.clone();
                                            t.refresh_token = j.refresh_token.clone();
                                            t.token_type = j.token_type.clone();
                                            t.user_id = j.user_id.clone();
                                            t.user_principal_name = j.user_principal_name.clone();
                                        }
                                    }
                                }
                                res
                            }
                        }
                        Err(err) => Err(err),
                    },
                } {
                    match err {
                        Error::DeviceCodeFlowCreation
                        | Error::DeviceCodeFlowAuthentication
                        | Error::DeviceCodeFlowUnexpectedEnd => {
                            // Error while reauthenticating, do the URL again so that it reauthenticates
                            error!("{:FL$}Error while reauthenticating", "RequestThread");
                            self.send_to_request(RequestMsg::Url(self.url.clone()));
                            return Err(Error::Reprocess);
                        }
                        _ => {
                            // Any other error
                            // Send Auth error to dumper for writing in auth_errrors file
                            self.send_to_dumper(MainMsg::ThreadError(ThreadError::AuthError(
                                AuthError {
                                    api: self.url.service_name.clone(),
                                    error: err.to_string(),
                                },
                            )));
                            // If service is required, return blocking error to main
                            if self.url.service_mandatory_auth {
                                self.send_to_dumper(MainMsg::ThreadError(
                                    ThreadError::BlockingError(err),
                                ));
                            }
                            return Err(Error::Reprocess);
                        }
                    }
                }
            }
            Err(err) => {
                // Send Auth error to dumper for writing
                self.send_to_dumper(MainMsg::ThreadError(ThreadError::AuthError(AuthError {
                    api: self.url.service_name.clone(),
                    error: err.to_string(),
                })));
                // If service is required, return blocking error to main
                if self.url.service_mandatory_auth {
                    self.send_to_dumper(MainMsg::ThreadError(ThreadError::BlockingError(err)));
                }
                return Err(Error::Reprocess);
            }
            Ok(mut new_token) => {
                if self.config.no_check != Some(true) {
                    loop {
                        match Prerequisites::check(&self.client, &mut new_token, true, false) {
                            Err(Error::TooManyRequestsDuringPrerequisites) => {
                                // Too many requests, sleep for 2 seconds and retry
                                thread::sleep(Duration::from_secs(2));
                            }
                            Err(_) => {
                                println!("\n\n");
                                error!(
                                    "{}{}{}",
                                    White.on(Red).paint(
                                        "Please fix the above error in prerequisite check for service '"
                                    ),
                                    White.on(Red).paint(&t.service),
                                    White.on(Red).paint("' and press Enter to continue dump")
                                );
                                let _ = std::io::stdin().read_line(&mut String::new());
                                self.send_to_request(RequestMsg::Url(self.url.clone()));
                                return Err(Error::Reprocess);
                            }
                            Ok(()) => {
                                t.tenant_id = new_token.tenant_id.clone();
                                t.client_id = new_token.client_id.clone();
                                t.expires_on = new_token.expires_on;
                                t.access_token = new_token.access_token.clone();
                                t.refresh_token = new_token.refresh_token.clone();
                                t.token_type = new_token.token_type.clone();
                                t.user_id = new_token.user_id.clone();
                                t.user_principal_name = new_token.user_principal_name.clone();
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn parse_response(&self, token: &mut Token, res: Response) -> Result<(), Error> {
        /*
        Parse the response received for the URL
        If HTTP code 429 => sleep and reprocess the URL
        If success => send response to writer
        If error => handle the errors (debug! if expected, warn! if unexpected)
        */

        // Retrieve HTTP success code for the URL from schema, 200 is the default
        let success_http_code: u16 = match self.url.api_behavior.get("success_http_code") {
            Some(field) => match field.parse() {
                Ok(i) => i,
                Err(err) => {
                    warn!(
                        "{:FL$}Error converting success_http_code value {:?} to int, using 200",
                        "RequestThread", field
                    );
                    debug!("{}", err);
                    200
                }
            },
            None => 200,
        };
        match res.status().as_u16() {
            429 => {
                // Handle HTTP status code 429 - Too many requests
                debug!(
                    "Got error code 429 for service {:?} with api {:?}",
                    self.url.service_name, self.url.api
                );
                // // 1. Indicate to RequestHandler to sleep for a bit (TODO: ensure usefull even if this message will probably be received later ??)
                // self.send_to_request(RequestMsg::Sleep);
                // 2. Indicate to RequestHandler to do the Url again
                self.send_to_request(RequestMsg::Url(self.url.clone()));
                // 3. Sleep for a bit
                thread::sleep(Duration::from_secs(2));
            }
            x if x == success_http_code => {
                // Parsing response as JSON object
                let response: Value = match res.json::<Value>() {
                    Ok(e) => e,
                    Err(err) => {
                        warn!(
                            "{:FL$}Error parsing response for request to url {:?}, trying again",
                            "RequestThread", &self.url.url
                        );
                        debug!("{}", err);
                        // Indicate to RequestHandler to do the Url again and stop here
                        self.send_to_request(RequestMsg::Url(self.url.clone()));
                        return Ok(());
                    }
                };

                // Handle next link
                let next_link_pointer: String = match self.url.api_behavior.get("next_link_field") {
                    Some(field) => format!("/{}", field),
                    None => String::from("/@odata.nextLink"),
                };
                if let Some(next_link_field) = response.pointer(&next_link_pointer) {
                    match next_link_field.as_str() {
                        Some(f) => {
                            // Send next url to Dumper for later processing
                            self.send_to_dumper(MainMsg::NewUrl(Url {
                                service_name: self.url.service_name.clone(),
                                service_scopes: self.url.service_scopes.clone(),
                                service_description: self.url.service_description.clone(),
                                service_mandatory_auth: self.url.service_mandatory_auth,
                                api: self.url.api.clone(),
                                url: f.to_string(),
                                conditions: self.url.conditions.clone(),
                                relationships: self.url.relationships.clone(),
                                api_behavior: self.url.api_behavior.clone(),
                                expected_error_codes: self.url.expected_error_codes.clone(),
                                parent: self.url.parent.clone(),
                            }));
                        }
                        None => {
                            debug!(
                                "{:FL$}Found null nextlink for api {:?} of service {:?}, skipping it",
                                "RequestThread", self.url.api, self.url.service_name
                            );
                            // Add to dump errors
                            self.send_to_dumper(MainMsg::ThreadError(ThreadError::DumpError(DumpError{
                                folder: self.url.service_name.clone(),
                                file: self.url.api.clone(),
                                url: self.url.url.clone(),
                                status: 0,
                                code: String::from("nextLinkParsingError"),
                                message: format!("Found null nextlink for api {:?} of service {:?}, skipping it", self.url.api, self.url.service_name)
                            })));
                        }
                    }
                };

                // Handling values
                let value_pointer: String = match self.url.api_behavior.get("value_field") {
                    Some(field) => format!("/{}", field),
                    None => String::from("/value"),
                };
                let initial_data: Vec<Value> = match response.pointer(&value_pointer) {
                    Some(e) => e.as_array().unwrap_or(&Vec::new()).to_vec(),
                    None => match response {
                        Value::Array(r) => r,
                        Value::Object(o) => vec![Value::Object(o)],
                        _ => vec![json!({"result": response.clone()})],
                    },
                };

                // Send data for writing
                self.send_to_writer(WriterMsg::ResponseData(ResponseData {
                    folder: self.url.service_name.clone(),
                    file: self.url.api.clone(),
                    data: initial_data.clone(),
                    url: self.url.clone(),
                }));
            }
            x => {
                // Construct DumpError
                let mut dump_error: DumpError = DumpError {
                    folder: self.url.service_name.clone(),
                    file: self.url.api.clone(),
                    url: self.url.url.clone(),
                    status: x,
                    code: String::from("UnexpectedHTTPStatusCode"),
                    message: format!(
                        "Got HTTP Status {:?} for api {:?} of service {:?}",
                        x,
                        self.url.api.clone(),
                        self.url.service_name.clone()
                    ),
                };

                // Parse error
                match res.json::<Value>() {
                    Ok(response) => {
                        let error_code_pointer: String =
                            match self.url.api_behavior.get("error_code") {
                                Some(field) => format!("/{}", field),
                                None => String::from("/error/code"),
                            };
                        let error_code_field: Option<&Value> =
                            response.pointer(&error_code_pointer);
                        let error_message_pointer: String =
                            match self.url.api_behavior.get("error_message") {
                                Some(field) => format!("/{}", field),
                                None => String::from("/error/message"),
                            };
                        let error_message_field: Option<&Value> =
                            response.pointer(&error_message_pointer);
                        match self.handle_expected_errors(token, x, error_code_field) {
                            Err(err) => {
                                return Err(err);
                            }
                            Ok(expected) => {
                                if let Some(code) = error_code_field {
                                    match code.as_str() {
                                        Some(c) => dump_error.code = c.to_string(),
                                        None => {
                                            debug!(
                                                "{:FL$}Error parsing error code for api {:?} of service {:?}, skipping it",
                                                "RequestThread", self.url.api, self.url.service_name
                                            );
                                            debug!("{}", response.to_string());
                                        }
                                    }
                                }
                                if let Some(message) = error_message_field {
                                    match message.as_str() {
                                        Some(m) => dump_error.message = m.to_string(),
                                        None => {
                                            debug!(
                                                "{:FL$}Error parsing error message for api {:?} of service {:?}, skipping it",
                                                "RequestThread", self.url.api, self.url.service_name
                                            );
                                            debug!("{}", response.to_string());
                                        }
                                    }
                                }
                                if !expected {
                                    info!(
                                        "{:FL$}{} - {}",
                                        "RequestThread", dump_error.code, dump_error.message
                                    );
                                }
                            }
                        }
                    }
                    Err(err) => {
                        debug!(
                            "{:FL$}Could not parse response received for api {:?} of service {:?}",
                            "RequestThread",
                            self.url.api.clone(),
                            self.url.service_name.clone()
                        );
                        debug!("{}", err);
                    }
                };

                // Send to Dumper for writing in errors.json file
                self.send_to_dumper(MainMsg::ThreadError(ThreadError::DumpError(dump_error)));
                // Indicate that processing of this URL is finished
                self.send_to_dumper(MainMsg::Finished(1));
            }
        }
        Ok(())
    }

    pub fn handle_expected_errors(
        &self,
        token: &mut Token,
        status_code: u16,
        error_code_field: Option<&Value>,
    ) -> Result<bool, Error> {
        /*
        Check received HTTTP Status code regarding of expected codes for the API
        (i.e. error codes that are not really errors)
        */
        let mut expected: bool = false;
        let mut code: String = String::new();
        if let Some(expected_error_codes) = &self.url.expected_error_codes {
            for expected_error_code in expected_error_codes.iter() {
                if expected_error_code.status != status_code {
                    continue;
                }
                match &expected_error_code.code {
                    Some(expected_code) => {
                        if let Some(error_code) = error_code_field {
                            if let Some(c) = error_code.as_str() {
                                code = format!(" with code {:?}", c);
                                if c == expected_code {
                                    expected = true;
                                    break;
                                }
                            }
                        }
                    }
                    None => {
                        expected = true;
                        break;
                    }
                }
            }
        }
        if !expected {
            // Unexpected error codes
            if self.config.no_check != Some(true) {
                if let Ok(mut t) = self.tokens_to_update.lock() {
                    // Lock the tokens to update during check
                    if Prerequisites::check(&self.client, token, true, true).is_err() {
                        // Error seems to be due to missing prerequisites
                        // Indicate to update the token
                        t.insert(token.service.clone());
                        return Err(Error::ErrorCodeDueToPrerequisites);
                    }
                }
            }
            warn!(
                "{:FL$}Got HTTP Status {:?}{} for api {:?} of service {:?}",
                "RequestThread",
                status_code,
                code,
                self.url.api.clone(),
                self.url.service_name.clone()
            );
        } else {
            // Expected error codes
            debug!(
                "{:FL$}Got HTTP Status {:?}{} for api {:?} of service {:?}",
                "RequestThread",
                status_code,
                code,
                self.url.api.clone(),
                self.url.service_name.clone()
            );
        }
        Ok(expected)
    }
}

pub struct WriterHandler {
    tenant: String,
    thread_limit: usize,
    receiver: Arc<Mutex<Receiver<WriterMsg>>>,
    sender: Arc<Mutex<Sender<MainMsg>>>,
    main_sender: Arc<Mutex<Sender<RequestMsg>>>,
    oradaz_writer: Arc<Mutex<OradazWriter>>,
    metadata: Arc<Mutex<HashMap<String, Table>>>,
    client: Client,
    tokens: Arc<Mutex<HashMap<String, Token>>>,
}

impl WriterHandler {
    pub fn new(
        tenant: String,
        thread_limit: usize,
        receiver: Arc<Mutex<Receiver<WriterMsg>>>,
        sender: Arc<Mutex<Sender<MainMsg>>>,
        main_sender: Arc<Mutex<Sender<RequestMsg>>>,
        oradaz_writer: Arc<Mutex<OradazWriter>>,
        metadata: Arc<Mutex<HashMap<String, Table>>>,
        client: Client,
        tokens: Arc<Mutex<HashMap<String, Token>>>,
    ) -> Self {
        /*
        Initialize WriterHandler
        */
        WriterHandler {
            tenant,
            thread_limit,
            receiver,
            sender,
            main_sender,
            oradaz_writer,
            metadata,
            client,
            tokens,
        }
    }

    pub fn start(self) -> Result<(), Error> {
        /*
        Create a ThreadPool to handle received WriterMsg
        For each WriterMsg::ResponseData, spawn a WriterThread in the ThreadPool
        */
        let pool = match ThreadPoolBuilder::new()
            .num_threads(self.thread_limit)
            .build()
        {
            Ok(p) => {
                debug!(
                    "{:FL$}Successfully created multithread pool with {} writer threads",
                    "WriterHandler", self.thread_limit
                );
                p
            }
            Err(err) => {
                error!(
                    "{:FL$}Cannot create multithread pool to perform the dump",
                    "WriterHandler"
                );
                debug!("{}", err);
                return Err(Error::ThreadPoolBuilderCreation);
            }
        };

        match self.receiver.lock() {
            Ok(receiver) => {
                loop {
                    if let Ok(msg) = receiver.recv() {
                        match msg {
                            WriterMsg::Terminate => {
                                // Received a message requesting thread termination
                                break;
                            }
                            WriterMsg::ResponseData(resp) => {
                                pool.spawn({
                                    let thread_oradaz_writer: Arc<Mutex<OradazWriter>> =
                                        Arc::clone(&self.oradaz_writer);
                                    let thread_sender: Arc<Mutex<Sender<MainMsg>>> =
                                        Arc::clone(&self.sender);
                                    let main_sender: Arc<Mutex<Sender<RequestMsg>>> =
                                        Arc::clone(&self.main_sender);
                                    let thread_metadata: Arc<Mutex<HashMap<String, Table>>> =
                                        Arc::clone(&self.metadata);
                                    let thread_tokens: Arc<Mutex<HashMap<String, Token>>> =
                                        Arc::clone(&self.tokens);
                                    let thread_tenant = self.tenant.clone();
                                    let client: Client = self.client.clone();
                                    move || {
                                        let rt: WriterThread = WriterThread::new(
                                            client,
                                            thread_tokens,
                                            thread_tenant,
                                            thread_oradaz_writer,
                                            resp,
                                            thread_sender,
                                            main_sender,
                                            thread_metadata,
                                        );
                                        rt.process();
                                    }
                                });
                            }
                        }
                    }
                }
            }
            Err(err) => {
                error!(
                    "{:FL$}Could not lock receiver while starting multithread pool loop to perform the dump",
                    "WriterHandler"
                );
                debug!("{}", err);
                return Err(Error::ReceiverLock);
            }
        }

        drop(self.receiver);
        drop(self.sender);
        Ok(())
    }
}

pub struct WriterThread {
    client: Client,
    tokens: Arc<Mutex<HashMap<String, Token>>>,
    tenant: String,
    writer: Arc<Mutex<OradazWriter>>,
    resp: ResponseData,
    sender: Arc<Mutex<Sender<MainMsg>>>,
    main_sender: Arc<Mutex<Sender<RequestMsg>>>,
    metadata: Arc<Mutex<HashMap<String, Table>>>,
}

impl WriterThread {
    pub fn new(
        client: Client,
        tokens: Arc<Mutex<HashMap<String, Token>>>,
        tenant: String,
        writer: Arc<Mutex<OradazWriter>>,
        resp: ResponseData,
        sender: Arc<Mutex<Sender<MainMsg>>>,
        main_sender: Arc<Mutex<Sender<RequestMsg>>>,
        metadata: Arc<Mutex<HashMap<String, Table>>>,
    ) -> Self {
        /*
        Initialize WriterThread
        */
        WriterThread {
            client,
            tokens,
            tenant,
            writer,
            resp,
            sender,
            main_sender,
            metadata,
        }
    }

    fn send_to_dumper(&self, msg: MainMsg) {
        /*
        Send a MainMsg to Dumper
        */
        match self.sender.lock() {
            Ok(sender) => {
                if let Err(err) = sender.send(msg) {
                    error!(
                        "{:FL$}Error sending data to Dumper, exiting",
                        "WriterThread"
                    );
                    debug!("{}", err);
                    exit();
                };
            }
            Err(err) => {
                error!(
                    "{:FL$}Error locking sender to send data to Dumper, exiting",
                    "WriterThread"
                );
                error!("{:FL$}{}", "WriterThread", Error::SenderLock);
                debug!("{}", err);
                exit();
            }
        }
    }

    fn send_to_request(&self, msg: RequestMsg) {
        /*
        Send a RequestMsg to RequestHandler
        */
        match self.main_sender.lock() {
            Ok(sender) => {
                if let Err(err) = sender.send(msg) {
                    error!("{:FL$}Error sending data to RequestHandler", "WriterThread");
                    debug!("{}", err);
                    self.send_to_dumper(MainMsg::ThreadError(ThreadError::BlockingError(
                        Error::ChannelError,
                    )));
                };
            }
            Err(err) => {
                error!(
                    "{:FL$}Error locking sender to send data to RequestHandler",
                    "WriterThread"
                );
                error!("{:FL$}{}", "WriterThread", Error::SenderLock);
                debug!("{}", err);
                self.send_to_dumper(MainMsg::ThreadError(ThreadError::BlockingError(
                    Error::ChannelError,
                )));
            }
        }
    }

    pub fn process(self) {
        /*
        Send data to ORADAZ Writer as a multiline string
        */
        if !self.resp.data.is_empty() {
            // Create a multiline string from vector of json data
            let multiline_string: String = self
                .resp
                .data
                .iter()
                .map(|x| match self.resp.url.parent.clone() {
                    Some(parent) => {
                        // Add parent data for every json
                        let mut data = x.clone();
                        data["_ORADAZ_PARENT_"] = json!(parent);
                        format!("{}\n", data)
                    }
                    None => format!("{}\n", x),
                })
                .collect();

            // Write the string to the correct file
            match self.writer.lock() {
                Ok(mut w) => {
                    if let Err(err) = w.write_file(
                        self.resp.folder.clone(),
                        format!("{}.json", self.resp.file.clone()),
                        multiline_string,
                    ) {
                        warn!(
                            "{:FL$}Error writing response to file {:?} in folder {:?}, trying to process the URL again",
                            "WriterThread", self.resp.file, self.resp.folder
                        );
                        debug!("{}", err);
                        // Indicate to RequestHandler to do the Url again
                        return self.send_to_request(RequestMsg::Url(self.resp.url.clone()));
                    };
                }
                Err(err) => {
                    error!(
                        "{:FL$}Error while locking Writer to write response to file {:?} in folder {:?}, trying to process the URL again",
                        "WriterThread", self.resp.file, self.resp.folder
                    );
                    debug!("{}", err);
                    // Indicate to RequestHandler to do the Url again
                    return self.send_to_request(RequestMsg::Url(self.resp.url.clone()));
                }
            }
            // Update Metadata
            match self.metadata.lock() {
                Ok(mut metadata) => {
                    metadata
                        .entry(format!(
                            "{}_{}",
                            self.resp.folder.clone(),
                            self.resp.file.clone()
                        ))
                        .or_insert(Table {
                            name: format!(
                                "{}_{}",
                                self.resp.folder.clone(),
                                self.resp.file.clone()
                            ),
                            folder: self.resp.folder.clone(),
                            file: format!("{}.json", self.resp.file.clone()),
                            count: 0,
                        })
                        .count += self.resp.data.len();
                }
                Err(err) => {
                    error!(
                        "{:FL$}Error locking metadata for update, exiting",
                        "WriterThread"
                    );
                    error!("{:FL$}{}", "WriterThread", Error::MetadataLock);
                    debug!("{}", err);
                    exit();
                }
            }

            // Construct NewURLs based on relationship and send them to Dumper
            let service_name: String = self.resp.url.service_name.clone();
            let service_scopes: Vec<String> = self.resp.url.service_scopes.clone();
            let service_description: String = self.resp.url.service_description.clone();
            let service_mandatory_auth: bool = self.resp.url.service_mandatory_auth;
            let url_relationships = self.resp.url.relationships.clone();
            let token: Option<Token> = match self.tokens.lock() {
                Ok(tokens) => tokens.get(&service_name).cloned(),
                Err(err) => {
                    error!(
                        "{:FL$}Error locking tokens to get relationships URLs",
                        "WriterThread"
                    );
                    debug!("{}", err);
                    None
                }
            };
            if let Some(t) = token {
                for data in &self.resp.data {
                    for relationship_url in url_relationships.clone() {
                        // Get the URL of the relationship
                        let url: String = relationship_url.get_url(
                            &self.client,
                            &t,
                            self.tenant.clone(),
                            data.clone(),
                            self.resp.url.url.clone(),
                        );
                        if !url.is_empty() {
                            // Add API behavior
                            let mut api_behavior: HashMap<String, String> =
                                relationship_url.default_api_behavior.clone();
                            if let Some(a) = relationship_url.api_behavior.clone() {
                                for (k, v) in a {
                                    api_behavior.insert(k, v);
                                }
                            }

                            // Add relationships for this api
                            let api: String =
                                format!("{}_{}", &relationship_url.api, &relationship_url.name);
                            let mut relationships: Vec<RelationshipUrl> = Vec::new();
                            if let Some(r) = relationship_url.relationships.clone() {
                                for relationship in &r {
                                    relationships.push(RelationshipUrl {
                                        service: service_name.clone(),
                                        url_scheme: relationship_url.url_scheme.clone(),
                                        default_api_behavior: relationship_url
                                            .default_api_behavior
                                            .clone(),
                                        default_parameters: relationship_url
                                            .default_parameters
                                            .clone(),
                                        api: api.clone(),
                                        name: relationship.name.clone(),
                                        uri: relationship.uri.clone(),
                                        conditions: relationship_url.conditions.clone(),
                                        api_behavior: relationship.api_behavior.clone(),
                                        expected_error_codes: relationship
                                            .expected_error_codes
                                            .clone(),
                                        keys: relationship.keys.clone(),
                                        parameters: relationship.parameters.clone(),
                                        relationships: relationship.relationships.clone(),
                                    })
                                }
                            }
                            let parent: HashMap<String, String> =
                                relationship_url.get_parent(data.clone());
                            self.send_to_dumper(MainMsg::NewUrl(Url {
                                service_name: service_name.clone(),
                                service_scopes: service_scopes.clone(),
                                service_description: service_description.clone(),
                                service_mandatory_auth,
                                api,
                                url,
                                conditions: relationship_url.conditions.clone(),
                                relationships,
                                api_behavior,
                                expected_error_codes: relationship_url.expected_error_codes.clone(),
                                parent: Some(parent),
                            }));
                        }
                    }
                }
            } else {
                error!(
                    "{:FL$}Missing token to get relationships URLs for api {:?} of service {:?}, skipping them",
                    "RequestThread", service_name, self.resp.file
                );
                // Send to Dumper for writing in errors.json file
                self.send_to_dumper(MainMsg::ThreadError(ThreadError::DumpError(DumpError {
                    folder: self.resp.folder.clone(),
                    file: self.resp.file.clone(),
                    url: self.resp.url.url.clone(),
                    status: 0,
                    code: String::from("MissingTokenForRelationships"),
                    message: format!(
                        "Missing token to get relationships URLs for api {:?} of service {:?}, skipping them",
                        service_name, self.resp.file
                    ),
                })));
            }
        }

        // Telling Dumper that everythin went correctly for this URL
        self.send_to_dumper(MainMsg::Finished(1));
    }
}
