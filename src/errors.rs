use mla::errors::Error as MLAError;
use std::error;
use std::fmt;
use std::io;

#[derive(Debug)]
pub enum Error {
    /// Custom errors
    StringError(String),
    /// IO Error (not enough data, etc.)
    IOError(io::Error),
    /// MLA Error
    MLAError(MLAError),
    /// Provided config file does not exists
    ConfigFileNotFoundError,
    /// The version of the dumper is not the last available 
    NotLastVersionError,
    /// Provided config file is not a valid XML file
    InvalidConfigXMLStructureError,
    /// Provided schema file does not exists
    SchemaFileNotFoundError,
    /// Provided proxy URL is invalid
    InvalidProxyURLError,
    /// Could not create reqwest client 
    CannotCreateClientError,
    /// Could not retrieve schema file from GitHub
    CannotDownloadSchemaFileError,
    /// Provided schema file is not a valid XML file
    InvalidSchemaXMLStructureError,
    /// Invalid tenant provided as argument
    InvalidAuthorityUrlError,
    /// Invalid client id provided as argument
    InvalidAppId,
    /// Error while trying to convert metadata to json
    MetadataToJSONError,
    /// Error while trying to convert errors to json
    ErrorsToJSONError,
    /// Error while trying to check the prerequisites
    PrerequisitesCheckError,

    /// Could not retrieve token metadata
    RetrieveTokenMetadataError,
    /// Device code has expired while waiting for user interaction
    ExpiredDeciveCodeError,
    /// Error during the device code flow authentication process
    DeviceCodeFlowAuthenticationError,
    /// Cannot get device code flow to acquire token
    CannotAcquireDeviceCodeFlowError,
    /// Token cannot be retrieved for an API
    CannotAcquireTokenError,
    /// Cannot retrieve the custom application to check if permissions match requirements
    CannotRetrieveAppError,
    /// Cannot retrieve current user to check if required Global Reader role is assigned
    CannotRetrieveCurrentUserError,
    /// Cannot retrieve current user roles assignments to check if required Global Reader role is assigned
    CannotRetrieveCurrentUserRolesError,
    /// Cannot retrieve the subscriptions that will be audited
    CannotRetrieveSubscriptionsError,
    /// Cannot retrieve the mailboxes
    CannotRetrieveMailboxesError,
    /// No privilegege to read any subscription
    NoSubscriptionError,
    /// Missing api definition in schema
    ApiNotInSchemaError,
    /// Missing required token
    MissingApiTokenError,
    /// Missing required permission for the dump
    MissingAppPermissionError,
    /// Missing required Azure AD Role to perform the dump
    MissingAzureAdRoleError,
    /// Missing required Exchange Online to perform the dump
    MissingExchangeOnlinePermissionsError,
    
    /// Cannnot create the dumper 
    DumperCreationError,
    /// Cannnot create thread pool builder to perform the dump
    ThreadPoolBuilderCreationError,
    /// Cannnot refresh an expired access token
    CannotRefreshTokenError,
    /// Missing refresh token
    MissingRefreshTokenError,
    /// Invalid request sent to the server
    InvalidRequestError,
    /// Error while parsing the data received
    ParsingError,
    /// Operator not yet implemented for conditional relationships
    OperatorNotImplementedError,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // For now, use the debug derived version
        write!(f, "{:?}", self)
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match &self {
            Error::IOError(err) => Some(err),
            Error::MLAError(err) => Some(err),
            _ => None,
        }
    }
}