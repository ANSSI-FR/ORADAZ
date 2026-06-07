use crate::FL;
use crate::collect::auth::tokens::Token;
use crate::collect::prerequisites::handle_429;
use crate::collect::prerequisites::jwt_claims::parse_token_grants;
use crate::collect::prerequisites::models::SubscriptionResponse;
use crate::utils::errors::Error;

use log::{debug, info, warn};
use reqwest::Client;
use url::Url;

const USER_IMPERSONATION_SCOPE: &str = "user_impersonation";

/// Verifies that the Azure Service Management access token (delegated flow)
/// carries the `user_impersonation` scope, by inspecting the JWT `scp` claim.
pub fn check_user_impersonation_scope(token: &Token, silent: bool) -> Result<(), Error> {
    debug!(
        "{:FL$}Checking user_impersonation scope on Azure Service Management token",
        "Prerequisites"
    );
    let grants = parse_token_grants(&token.access_token);
    if grants.has_scope(USER_IMPERSONATION_SCOPE) {
        debug!(
            "{:FL$}Azure Service Management token carries the user_impersonation scope",
            "Prerequisites"
        );
        return Ok(());
    }
    if silent {
        debug!(
            "{:FL$}Azure Service Management token is missing the user_impersonation scope",
            "Prerequisites"
        );
    } else {
        warn!(
            "{:FL$}Azure Service Management token is missing the user_impersonation scope",
            "Prerequisites"
        );
    }
    Err(Error::MissingAzureUserImpersonationScope)
}

/// Verifies that the current user has read access to at least one Azure subscription.
///
/// Returns the (display name, subscription id) pairs of the subscriptions that
/// will be audited. The IDs are propagated to the Dumper so it can populate the
/// `subscriptions` body of Azure Resource Graph requests.
pub async fn check_available_subscriptions(
    client: &Client,
    token: &Token,
    silent: bool,
    resources_base_url: &str,
    default_retry_after: u64,
) -> Result<Vec<(String, String)>, Error> {
    debug!(
        "{:FL$}Checking available subscriptions for current user",
        "Prerequisites"
    );

    // ARM paginates the subscriptions list via a top-level `nextLink`; follow it
    // so tenants with more than one page are fully enumerated (the IDs also feed
    // the ARG `subscriptions` body). Bounded by `MAX_SUBSCRIPTION_PAGES` so a
    // cyclic or pathological `nextLink` cannot loop forever — exit must not
    // depend solely on the server.
    const MAX_SUBSCRIPTION_PAGES: usize = 1000;
    let mut next_url: Option<String> = Some(format!(
        "{}/subscriptions?api-version=2020-08-01",
        resources_base_url
    ));
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut page: usize = 0;

    while let Some(string_url) = next_url.take() {
        page += 1;
        if page > MAX_SUBSCRIPTION_PAGES {
            warn!(
                "{:FL$}Stopped paginating subscriptions after {} pages (possible cyclic nextLink)",
                "Prerequisites", MAX_SUBSCRIPTION_PAGES
            );
            break;
        }
        let url: Url = match Url::parse(&string_url) {
            Ok(u) => u,
            Err(err) => {
                warn!(
                    "{:FL$}Cannot create url to retrieve available subscriptions",
                    "Prerequisites"
                );
                debug!("{:FL$}URL parse error: {:?}", "Prerequisites", err);
                return Err(Error::UrlCreation);
            }
        };
        let res = match client
            .get(url)
            .header(
                reqwest::header::AUTHORIZATION,
                &format!("Bearer {}", token.access_token),
            )
            .send()
            .await
        {
            Err(err) => {
                warn!(
                    "{:FL$}Cannot retrieve available subscriptions",
                    "Prerequisites"
                );
                debug!("{:FL$}HTTP request error: {:?}", "Prerequisites", err);
                return Err(Error::CannotRetrieveSubscriptions);
            }
            Ok(res) => res,
        };
        // A 429 mid-pagination propagates `TooManyRequestsDuringPrerequisites`
        // and aborts the whole enumeration (same as the single-page behavior).
        let res = handle_429(res, default_retry_after)?;
        let status = res.status();
        let response: String = match res.text().await {
            Ok(s) => s,
            Err(err) => {
                if silent {
                    debug!(
                        "{:FL$}Error getting text response from request to retrieve available subscriptions",
                        "Prerequisites"
                    );
                } else {
                    warn!(
                        "{:FL$}Error getting text response from request to retrieve available subscriptions",
                        "Prerequisites"
                    );
                }
                debug!("{:FL$}Response text error: {:?}", "Prerequisites", err);
                return Err(Error::CannotRetrieveSubscriptions);
            }
        };

        match serde_json::from_str::<SubscriptionResponse>(&response) {
            Ok(parsed) => {
                match parsed.value {
                    Some(subs) => {
                        pairs.extend(
                            subs.into_iter()
                                .map(|s| (s.display_name, s.subscription_id)),
                        );
                    }
                    None => {
                        // A missing `value` on the FIRST page is a malformed
                        // response (preserves the original error). On a later
                        // page, treat it as end-of-pages rather than an error.
                        if page == 1 {
                            if silent {
                                debug!("{:FL$}Cannot retrieve subscriptions", "Prerequisites");
                            } else {
                                warn!("{:FL$}Cannot retrieve subscriptions", "Prerequisites");
                            }
                            return Err(Error::CannotRetrieveSubscriptions);
                        }
                    }
                }
                next_url = parsed.next_link.filter(|l| !l.is_empty());
            }
            Err(err) => {
                warn!(
                    "{:FL$}Error parsing available subscriptions",
                    "Prerequisites"
                );
                debug!("{:FL$}{:?} - {}", "Prerequisites", status, response);
                debug!("{:FL$}JSON parse error: {:?}", "Prerequisites", err);
                return Err(Error::CannotRetrieveSubscriptions);
            }
        }
    }

    if pairs.is_empty() {
        if silent {
            debug!(
                "{:FL$}User has no read permission on any subscription",
                "Prerequisites"
            );
        } else {
            warn!(
                "{:FL$}User has no read permission on any subscription",
                "Prerequisites"
            );
        }
        return Err(Error::NoAvailableSubscription);
    }

    if silent {
        debug!(
            "{:FL$}Reader role has been provided to the following subscriptions which will be audited:",
            "Prerequisites"
        );
    } else {
        info!(
            "{:FL$}Reader role has been provided to the following subscriptions which will be audited:",
            "Prerequisites"
        );
        for (name, _id) in &pairs {
            info!("{:FL$}\t- {}", "", name);
        }
    }
    Ok(pairs)
}
