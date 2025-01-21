use mla::errors::Error as MLAError;
use std::error;
use std::fmt;
use std::io;

#[derive(Debug)]
pub enum Error {
    /// Generic errors
    /// Custom errors
    StringError(String),
    /// IO Error (not enough data, etc.)
    IOError(io::Error),
    /// Error while creating url
    UrlCreation,
    /// Error occured while sending / receiving messages over unbounded channels
    ChannelError,
    /// Error while creating Regex
    RegexError,

    /// Auth errors
    /// Error when strating device code flow
    DeviceCodeFlowCreation,
    /// Error during device code flow authentication
    DeviceCodeFlowAuthentication,
    /// Device flow stream ended unexpectedly
    DeviceCodeFlowUnexpectedEnd,
    /// Error while parsing access token
    AccessTokenParsing,
    /// Error while converting auth_errors to json
    AuthErrorsToJSON,
    /// Error while refreshing a token : no refresh token
    MissingRefreshToken,
    /// Error while exchanging a refresh token
    ExchangeRefreshToken,
    /// New authentication required
    NewAuthRequired,

    /// Config errors
    /// Provided config file does not exists
    ConfigFileNotFound,
    /// Provided config file is not a valid XML file
    InvalidConfigXMLStructure,
    /// Error while writing config options to archive
    ConfigToJSON,

    /// Requests errors
    /// Provided proxy URL is invalid
    InvalidProxyURL,
    /// Proxy creation error
    ProxyCreation,
    /// Could not create reqwest client
    CannotCreateClient,
    /// Error to indicate to reprocess the URL later
    Reprocess,

    /// Schema errors
    /// Provided schema file does not exists
    SchemaFileNotFound,
    /// Could not retrieve schema file from GitHub
    CannotDownloadSchemaFile,
    /// The version of the dumper is not the last available
    NotLastVersion,
    /// Schema file parsing error
    SchemaFileParsing,
    /// Error while constructing urls from schema file
    UrlsGeneration,

    /// Prerequisites errors
    /// Missing Graph API token to check prerequisites
    MissingGraphApiToken,
    /// Missing Internal API token to check prerequisites
    MissingInternalApiToken,
    /// Missing Resources API token to check prerequisites
    MissingResourcesApiToken,
    /// Missing Exchange Online API token to check prerequisites
    MissingExchangeApiToken,
    /// Cannot retrieve custom application to check permissions
    CannotRetrieveApp,
    /// Missing required permission for the dump
    MissingAppPermission,
    /// Error while converting prerequisites errors to json
    PrerequisitesErrorsToJSON,
    /// Invalid token has been provided to check prerequisites
    InvalidTokenToCheck,
    /// Cannot retrieve the organization to check PIM status
    CannotRetrieveOrganization,
    /// Cannot retrieve the Entra roles for the current user
    CannotRetrieveCurrentUserEntraRoles,
    /// The current user is missing required Entra roles
    MissingEntraRoles,
    /// Cannot retrieve the PIM Entra roles assignments for the current user
    CannotRetrieveCurrentUserPIMEntraRoles,
    /// Cannot retrieve available subscriptions
    CannotRetrieveSubscriptions,
    /// No available subscriptions for current user
    NoAvailableSubscription,
    /// Cannot retrieve a mailbox to check the ability to retrieve recipients
    CannotRetrieveMailboxes,
    /// Cannot retrieve recipients for the mailboxes
    CannotRetrieveMailboxesRecipients,
    /// The current user cannot retrieve mailbox recipients
    MissingExchangeOnlinePermissions,

    /// Writer errors
    /// Error writing file to result
    WriteFile,
    /// Invalid characters in MLA path
    InvalidMlaPath,
    /// MLA file creation error
    MLACreateFile,
    /// MLA PubKey error
    MLAInvalidPubKey,
    /// MLA archive creation error
    MLACreateArchive,
    /// MLA log file creation error
    MLACreateLogFile,
    /// Error while ending log file in MLA archive
    MLAEndLogFile,
    /// Error while ending file in MLA archive
    MLAEndFile,
    /// Error while finalizing MLA archive
    MLAFinalizeArchive,
    /// Error while writing log file in MLA archive
    MLAWriteLog,
    /// Error while adding data to file in MLA archive
    MLAAppendDataToFile,
    /// MLA Error
    MLAError(MLAError),
    /// Error while creating folder in which to output the results
    FolderCreation,
    /// Error while creating log file in output directory
    FolderCreateLogFile,
    /// Error while writing log file in output directory
    FolderWriteLog,
    /// Invalid path while writing an XML file
    FolderInvalidFilePath,
    /// Error while trying to rename the MLA archive
    ArchiveRenaming,
    /// Error while locking writer to use it
    WriterLock,

    /// Metadata errors
    /// Error while trying to convert metadata to json
    MetadataToJSON,

    /// Threading errors
    /// Cannnot create thread pool builder to perform the dump
    ThreadPoolBuilderCreation,
    /// Prerequisites check failed after unexpected HTTP code from API
    ErrorCodeDueToPrerequisites,

    /// Dumper errors
    /// Error while locking unbounded channel sender
    SenderLock,
    /// Error while locking unbounded channel receiver
    ReceiverLock,
    /// Error while locking metadata mutex
    MetadataLock,
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
