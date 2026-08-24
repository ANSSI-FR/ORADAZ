use crate::FL;
use crate::collect::auth::tokens::Token;
use crate::collect::dump::request::executor;
use crate::collect::prerequisites::OrganizationResponse;
use crate::utils::client::OradazClient;

use log::{debug, warn};
use serde::Deserialize;
use std::time::Duration;
use url::Url;

/// Maximum number of times a tenant-condition probe (`/organization`,
/// `/onPremisesPublishingProfiles`) is retried on HTTP 429 before falling back to
/// "undetected" (all-`false`). Kept small: these are one-shot startup probes, so a
/// persistently throttled probe should degrade gracefully rather than stall the
/// whole startup. The wait between retries comes from the response `Retry-After`
/// (delta-seconds or HTTP-date, via `executor::parse_retry_after`), falling back
/// to the per-call `retry_after_secs` when the header is absent.
const MAX_CONDITION_PROBE_RETRIES: u32 = 5;

/// Represents the license status of the tenant.
pub struct TenantLicenses {
    pub p1: bool,
    pub p2: bool,
    pub intune: bool,
    pub is_b2c: bool,
}

/// Capability flags inferred from a single GET on `onPremisesPublishingProfiles`.
/// All three default to `false` on any failure to read the endpoint. Because the
/// schema gates the related APIs *positively* on these flags, a probe failure
/// causes those APIs to be **skipped** (not "tried as before"); the failure is
/// therefore logged at `warn` so the operator can re-run if the tenant is
/// expected to expose them.
pub struct PublishingProfileCapabilities {
    pub has_application_proxy: bool,
    pub has_exchange_hybrid: bool,
    pub has_ad_administration: bool,
}

#[derive(Deserialize)]
struct PublishingProfile {
    #[serde(rename = "publishingType")]
    publishing_type: Option<String>,
}

#[derive(Deserialize)]
struct PublishingProfilesResponse {
    value: Vec<PublishingProfile>,
}

/// Checks the tenant's licenses and type by querying the Microsoft Graph API.
///
/// It verifies if the tenant has enabled plans for P1, P2, and Intune licenses
/// based on their respective service plan IDs, and reads `tenantType` to derive
/// the `IsB2C` flag used by the schema.
pub async fn check_tenant_licenses(
    client: &OradazClient,
    token: &Token,
    org_url: &str,
    retry_after_secs: u64,
) -> TenantLicenses {
    debug!("{:FL$}Checking tenant licenses", "ConditionChecker");
    let fallback = TenantLicenses {
        p1: false,
        p2: false,
        intune: false,
        is_b2c: false,
    };
    let url: Url = match Url::parse(org_url) {
        Ok(u) => u,
        Err(err) => {
            debug!(
                "{:FL$}Cannot create url to retrieve current organization: {err:?}",
                "ConditionChecker"
            );
            return fallback;
        }
    };
    // Send the probe, retrying on HTTP 429 so transient throttling does not
    // silently leave P1/P2/Intune/IsB2C undetected — which would SKIP the gated
    // security APIs (PIM, risk, Intune, B2C). Non-429 responses fall through to
    // the status/parse handling below unchanged.
    let mut attempt: u32 = 0;
    let response = loop {
        let response = match client
            .client
            .get(url.clone())
            .header(
                reqwest::header::AUTHORIZATION,
                &format!("Bearer {}", token.access_token),
            )
            .send()
            .await
        {
            Err(err) => {
                warn!(
                    "{:FL$}Could not query /organization to detect tenant licences (P1/P2/Intune) and type; APIs gated by these conditions (PIM, risk, Intune, B2C) will be SKIPPED this run — re-run if the tenant is expected to expose them.",
                    "ConditionChecker"
                );
                debug!(
                    "{:FL$}Organization request error: {err:?}",
                    "ConditionChecker"
                );
                return fallback;
            }
            Ok(res) => res,
        };

        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS
            && attempt < MAX_CONDITION_PROBE_RETRIES
        {
            attempt += 1;
            let wait = executor::parse_retry_after(response.headers()).unwrap_or(retry_after_secs);
            warn!(
                "{:FL$}/organization throttled (HTTP 429), retry {}/{} in {}s",
                "ConditionChecker", attempt, MAX_CONDITION_PROBE_RETRIES, wait
            );
            tokio::time::sleep(Duration::from_secs(wait)).await;
            continue;
        }

        break response;
    };

    if !response.status().is_success() {
        warn!(
            "{:FL$}/organization returned HTTP {}; tenant licences (P1/P2/Intune) and type left undetected — gated APIs (PIM, risk, Intune, B2C) will be SKIPPED this run.",
            "ConditionChecker",
            response.status()
        );
        return fallback;
    }

    match response.json::<OrganizationResponse>().await {
        Ok(organization) => {
            let mut p1 = false;
            let mut p2 = false;
            let mut intune = false;
            let mut is_b2c = false;

            for org in organization.value {
                // Microsoft Graph defines `tenantType` as one of "AAD",
                // "AAD B2C", or "CIAM" (External ID). Only "AAD B2C" gates
                // the b2cAuthenticationMethodsPolicy API; CIAM tenants are
                // intentionally treated as NotB2C.
                if let Some(tt) = &org.tenant_type
                    && tt.eq_ignore_ascii_case("AAD B2C")
                {
                    is_b2c = true;
                }
                for plan in org.assigned_plans {
                    if plan.capability_status == "Enabled" {
                        match plan.service_plan_id.as_str() {
                            "41781fb2-bc02-4b7c-bd55-b576c07bb09d" => p1 = true,
                            "eec0eb4f-6444-4f95-aba0-50c24d67f998" => p2 = true,
                            "c1ec4a95-1f05-45b3-a911-aa3fa01094f5" => intune = true,
                            _ => {}
                        }
                    }
                }
            }
            TenantLicenses {
                p1,
                p2,
                intune,
                is_b2c,
            }
        }
        Err(err) => {
            warn!(
                "{:FL$}Could not parse /organization response; tenant licences (P1/P2/Intune) and type left undetected — gated APIs will be SKIPPED this run.",
                "ConditionChecker"
            );
            debug!(
                "{:FL$}Organization parse error: {err:?}",
                "ConditionChecker"
            );
            fallback
        }
    }
}

/// Default endpoint used by `check_publishing_profiles` in production.
pub const PUBLISHING_PROFILES_URL: &str =
    "https://graph.microsoft.com/beta/onPremisesPublishingProfiles";

/// Probes Microsoft Graph for the configured `onPremisesPublishingProfiles` to
/// detect Application Proxy / Exchange Hybrid / AD Administration usage.
///
/// A single `GET` call returns all profiles (one per publishing type). Any
/// read or parse failure yields all-`false`, which **skips** the positively-gated
/// Application Proxy / Exchange Hybrid / AD Administration APIs; the failure is
/// logged at `warn` so the operator can re-run if the tenant should expose them.
/// The URL is passed in so tests can point at a mock server.
pub async fn check_publishing_profiles(
    client: &OradazClient,
    token: &Token,
    profiles_url: &str,
    retry_after_secs: u64,
) -> PublishingProfileCapabilities {
    debug!(
        "{:FL$}Checking onPremisesPublishingProfiles capabilities",
        "ConditionChecker"
    );
    let fallback = PublishingProfileCapabilities {
        has_application_proxy: false,
        has_exchange_hybrid: false,
        has_ad_administration: false,
    };
    let url: Url = match Url::parse(profiles_url) {
        Ok(u) => u,
        Err(err) => {
            debug!(
                "{:FL$}Cannot create url to retrieve onPremisesPublishingProfiles: {err:?}",
                "ConditionChecker"
            );
            return fallback;
        }
    };
    // Send the probe, retrying on HTTP 429 so transient throttling does not
    // silently leave the publishing-profile capabilities undetected — which would
    // SKIP the gated Application Proxy / Exchange-hybrid / AD-administration APIs.
    // Non-429 responses fall through to the status/parse handling below unchanged.
    let mut attempt: u32 = 0;
    let response = loop {
        let response = match client
            .client
            .get(url.clone())
            .header(
                reqwest::header::AUTHORIZATION,
                &format!("Bearer {}", token.access_token),
            )
            .send()
            .await
        {
            Err(err) => {
                warn!(
                    "{:FL$}Could not query onPremisesPublishingProfiles; Application Proxy / Exchange-hybrid / AD-administration APIs will be SKIPPED this run — re-run if the tenant is expected to expose them.",
                    "ConditionChecker"
                );
                debug!(
                    "{:FL$}onPremisesPublishingProfiles request error: {err:?}",
                    "ConditionChecker"
                );
                return fallback;
            }
            Ok(res) => res,
        };

        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS
            && attempt < MAX_CONDITION_PROBE_RETRIES
        {
            attempt += 1;
            let wait = executor::parse_retry_after(response.headers()).unwrap_or(retry_after_secs);
            warn!(
                "{:FL$}onPremisesPublishingProfiles throttled (HTTP 429), retry {}/{} in {}s",
                "ConditionChecker", attempt, MAX_CONDITION_PROBE_RETRIES, wait
            );
            tokio::time::sleep(Duration::from_secs(wait)).await;
            continue;
        }

        break response;
    };

    if !response.status().is_success() {
        warn!(
            "{:FL$}onPremisesPublishingProfiles returned HTTP {}; Application Proxy / Exchange-hybrid / AD-administration APIs will be SKIPPED this run.",
            "ConditionChecker",
            response.status()
        );
        return fallback;
    }

    match response.json::<PublishingProfilesResponse>().await {
        Ok(profiles) => {
            let mut caps = PublishingProfileCapabilities {
                has_application_proxy: false,
                has_exchange_hybrid: false,
                has_ad_administration: false,
            };
            for p in profiles.value {
                match p.publishing_type.as_deref() {
                    Some("applicationProxy") => caps.has_application_proxy = true,
                    Some("exchangeOnline") => caps.has_exchange_hybrid = true,
                    Some("adAdministration") => caps.has_ad_administration = true,
                    _ => {}
                }
            }
            caps
        }
        Err(err) => {
            warn!(
                "{:FL$}Could not parse onPremisesPublishingProfiles response; Application Proxy / Exchange-hybrid / AD-administration APIs will be SKIPPED this run.",
                "ConditionChecker"
            );
            debug!(
                "{:FL$}onPremisesPublishingProfiles parse error: {err:?}",
                "ConditionChecker"
            );
            fallback
        }
    }
}
