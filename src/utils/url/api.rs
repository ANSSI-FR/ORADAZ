use crate::FL;
use crate::collect::auth::tokens::Token;
use crate::collect::dump::conditions::ConditionChecker;
use crate::utils::schema::Service;
use crate::utils::url::transform::apply_transform;
use crate::utils::url::types::{Api, ExpectedErrorCode, RelationshipUrl, Url};

use log::{debug, trace, warn};
use std::collections::HashMap;
use std::sync::Arc;

impl Api {
    /// Resolves an API definition into a collectable `Url`, applying conditions and service contexts.
    ///
    /// It verifies that all API-level conditions are met before constructing the URL and
    /// resolving associated relationships.
    pub async fn get_url(
        self,
        service: &Service,
        tenant: String,
        token: &Token,
        condition_checker: &ConditionChecker,
        logs_days_filter: Option<&str>,
    ) -> Option<Url> {
        let api_name: String = self.name.clone();
        let api_conditions: Option<Vec<String>> = self.conditions.clone();
        if let Some(c) = &api_conditions {
            for condition in c {
                trace!(
                    "{:FL$}Checking condition {:?} for api {:?}.",
                    "Api", condition, api_name
                );
                if !condition_checker
                    .check(token, condition.clone(), Some((&service.name, &api_name)))
                    .await
                {
                    debug!(
                        "{:FL$}API {:?} of service {:?} does not meet condition {:?}, skipping it",
                        "Api", &self.name, token.service, condition
                    );
                    return None;
                }
            }
        }

        // Resolve API behavior from service defaults and API-specific overrides
        let mut api_behavior: HashMap<String, String> = service.default_api_behavior.clone();
        if let Some(a) = self.api_behavior.clone() {
            for (k, v) in a {
                api_behavior.insert(k, v);
            }
        }

        // Resolve expected error codes
        let expected_error_codes: Option<Vec<ExpectedErrorCode>> =
            self.expected_error_codes.clone();

        // Resolve relationships for this API
        let mut relationships: Vec<RelationshipUrl> = Vec::new();
        if let Some(r) = self.relationships.clone() {
            for relationship in &r {
                relationships.push(RelationshipUrl {
                    service: service.name.clone(),
                    url_scheme: service.url_scheme.clone(),
                    default_api_behavior: service.default_api_behavior.clone(),
                    default_parameters: service.default_parameters.clone(),
                    api: api_name.clone(),
                    name: relationship.name.clone(),
                    uri: relationship.uri.clone(),
                    conditions: relationship.conditions.clone(),
                    api_behavior: relationship.api_behavior.clone(),
                    expected_error_codes: relationship.expected_error_codes.clone(),
                    keys: relationship.keys.clone(),
                    parameters: relationship.parameters.clone(),
                    relationships: relationship.relationships.clone(),
                })
            }
        }

        // Construct the final URL string
        let service_name = service.name.clone();
        let url: String = self
            .construct_url(
                token,
                tenant.clone(),
                service,
                condition_checker,
                Some((service_name.as_str(), api_name.as_str())),
                logs_days_filter,
            )
            .await;

        Some(Url {
            service_name: service.name.clone(),
            service_scopes: Arc::new(service.scopes.clone()),
            service_mandatory_auth: service.mandatory_auth,
            api: api_name,
            url,
            conditions: api_conditions,
            relationships: Arc::new(relationships),
            api_behavior: Arc::new(api_behavior),
            expected_error_codes: expected_error_codes.map(Arc::new),
            parent: None,
            retry_number: 0,
            rate_limit_retry_number: 0,
            rate_limit_total_wait_secs: 0,
            post_body: None,
        })
    }

    /// Constructs the final URL by replacing placeholders with values and applying transformations.
    ///
    /// Placeholders are replaced in the following priority:
    /// 1. API-specific parameters
    /// 2. Service default parameters
    /// 3. Tenant identifier
    /// 4. Date filter (`[LOGS_DAYS_FILTER]`)
    pub async fn construct_url(
        self,
        token: &Token,
        tenant: String,
        service: &Service,
        condition_checker: &ConditionChecker,
        attribution: Option<(&str, &str)>,
        logs_days_filter: Option<&str>,
    ) -> String {
        let mut url: String = service.url_scheme.replace("[URI]", &self.uri);

        // Replacing parameters with the API specific value
        let mut done: Vec<String> = Vec::new();
        if let Some(parameters) = self.parameters {
            for parameter in &parameters {
                if url.contains(&parameter.name) {
                    if let Some(c) = &parameter.conditions {
                        let mut meet_conditions = true;
                        for condition in c {
                            trace!(
                                "{:FL$}Checking condition {:?} for url {:?} (API value).",
                                "Api", condition, url
                            );
                            if !condition_checker
                                .check(token, condition.clone(), attribution)
                                .await
                            {
                                debug!(
                                    "{:FL$}Parameter {:?} for API {:?} of service {:?} does not meet condition {:?}, skipping it",
                                    "Api", &parameter.name, &self.name, token.service, condition
                                );
                                meet_conditions = false;
                                break;
                            }
                        }
                        if !meet_conditions {
                            continue;
                        }
                    }
                    match apply_transform(&parameter.value, parameter.transform.as_deref()) {
                        Some(transformed) => url = url.replace(&parameter.name, &transformed),
                        None => {
                            warn!(
                                "{:FL$}Invalid transform {:?} in schema file for parameter {:?} for API {:?} of service {:?}. Skipping transformation.",
                                "Api",
                                parameter.transform,
                                &parameter.name,
                                &self.name,
                                token.service
                            );
                            url = url.replace(&parameter.name, &parameter.value);
                        }
                    };
                    done.push(parameter.name.clone());
                } else if !done.contains(&parameter.name) {
                    debug!(
                        "{:FL$}Trying to replace invalid api parameter {:?} for API {:?} of service {:?}",
                        "Api", &parameter.name, &self.name, token.service
                    );
                }
            }
        }

        // Replacing parameters with the service default value
        if let Some(parameters) = service.default_parameters.clone() {
            for parameter in &parameters {
                if url.contains(&parameter.name) {
                    if let Some(c) = &parameter.conditions {
                        let mut meet_conditions = true;
                        for condition in c {
                            trace!(
                                "{:FL$}Checking condition {:?} for url {:?} (Default value).",
                                "Api", condition, url
                            );
                            if !condition_checker
                                .check(token, condition.clone(), attribution)
                                .await
                            {
                                debug!(
                                    "{:FL$}Parameter {:?} for API {:?} of service {:?} does not meet condition {:?}, skipping it",
                                    "Api", &parameter.name, &self.name, token.service, condition
                                );
                                meet_conditions = false;
                                break;
                            }
                        }
                        if !meet_conditions {
                            continue;
                        }
                    }
                    match apply_transform(&parameter.value, parameter.transform.as_deref()) {
                        Some(transformed) => url = url.replace(&parameter.name, &transformed),
                        None => {
                            warn!(
                                "{:FL$}Invalid transform {:?} in schema file for default parameter {:?} for API {:?} of service {:?}. Skipping transformation.",
                                "Api",
                                parameter.transform,
                                &parameter.name,
                                &self.name,
                                token.service
                            );
                            url = url.replace(&parameter.name, &parameter.value);
                        }
                    };
                } else if !done.contains(&parameter.name) {
                    debug!(
                        "{:FL$}Trying to replace invalid default parameter {:?} for API {:?} of service {:?}",
                        "Api", &parameter.name, &self.name, token.service
                    );
                }
            }
        }

        // Replacing remaining parameters
        if url.contains("[TENANT]") {
            url = url.replace("[TENANT]", &tenant);
        }

        // Replace the logs days filter placeholder with the computed cutoff date string
        // or an empty string when no filter is configured (logs_days_filter == 0).
        if url.contains("[LOGS_DAYS_FILTER]") {
            url = url.replace("[LOGS_DAYS_FILTER]", logs_days_filter.unwrap_or(""));
        }

        // Collapse accidental double slashes in the URL *path* only, preserving
        // the scheme and the query string (a query value may legitimately
        // contain "//", e.g. an embedded URL passed as a filter parameter).
        url = crate::utils::url::collapse_path_double_slashes(&url);

        url
    }
}
