use crate::FL;
use crate::collect::auth::tokens::Token;
use crate::collect::prerequisites::jwt_claims::parse_token_grants;
use crate::utils::errors::Error;

use log::{debug, warn};

/// Application permission required on the Office 365 Exchange Online API for
/// the client credentials flow.
const EXCHANGE_MANAGE_AS_APP_ROLE: &str = "Exchange.ManageAsApp";

/// Delegated scope required on the Office 365 Exchange Online API for the
/// authorization code / device code flows.
const EXCHANGE_MANAGE_SCOPE: &str = "Exchange.Manage";

/// Verifies that the Exchange Online access token issued in client
/// credentials mode carries the `Exchange.ManageAsApp` application
/// permission. Inspects the JWT `roles` claim — no HTTP request needed.
pub fn check_exchange_manage_as_app(token: &Token, silent: bool) -> Result<(), Error> {
    debug!(
        "{:FL$}Checking Exchange.ManageAsApp application permission on Exchange Online token",
        "Prerequisites"
    );
    let grants = parse_token_grants(&token.access_token);
    if grants.has_role(EXCHANGE_MANAGE_AS_APP_ROLE) {
        debug!(
            "{:FL$}Exchange Online token carries Exchange.ManageAsApp",
            "Prerequisites"
        );
        return Ok(());
    }
    if silent {
        debug!(
            "{:FL$}Exchange Online token is missing the Exchange.ManageAsApp application permission (token roles: {:?})",
            "Prerequisites", grants.roles
        );
    } else {
        warn!(
            "{:FL$}Exchange Online token is missing the Exchange.ManageAsApp application permission",
            "Prerequisites"
        );
        debug!(
            "{:FL$}Exchange Online token roles claim: {:?}",
            "Prerequisites", grants.roles
        );
    }
    Err(Error::MissingExchangeManageAsApp)
}

/// Verifies that the Exchange Online access token issued in delegated mode
/// carries the `Exchange.Manage` scope. Inspects the JWT `scp` claim.
pub fn check_exchange_manage_scope(token: &Token, silent: bool) -> Result<(), Error> {
    debug!(
        "{:FL$}Checking Exchange.Manage delegated scope on Exchange Online token",
        "Prerequisites"
    );
    let grants = parse_token_grants(&token.access_token);
    if grants.has_scope(EXCHANGE_MANAGE_SCOPE) {
        debug!(
            "{:FL$}Exchange Online token carries the Exchange.Manage scope",
            "Prerequisites"
        );
        return Ok(());
    }
    if silent {
        debug!(
            "{:FL$}Exchange Online token is missing the Exchange.Manage scope (token scp: {:?})",
            "Prerequisites", grants.scp
        );
    } else {
        warn!(
            "{:FL$}Exchange Online token is missing the Exchange.Manage scope",
            "Prerequisites"
        );
        debug!(
            "{:FL$}Exchange Online token scp claim: {:?}",
            "Prerequisites", grants.scp
        );
    }
    Err(Error::MissingExchangeManageScope)
}
