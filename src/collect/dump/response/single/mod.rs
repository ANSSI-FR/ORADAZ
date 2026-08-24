pub mod value_handlers;

use crate::FL;
use crate::collect::dump::response::thread::ResponseThread;
use crate::collect::dump::response::{ApiCall, Response, status_handlers};
use crate::utils::url::Url;
use crate::utils::url::expected_errors::is_expected_error;

use log::trace;

pub async fn process_single(
    this: &ResponseThread,
    response: &Response,
    api_call: &ApiCall,
) -> Vec<Url> {
    trace!(
        "{:FL$}Processing single response for url {:?} (id: {}), status: {}",
        "process_single", api_call.url.url, api_call.id, response.status
    );

    // Record this response in the per-API statistics. For unexpected statuses,
    // is_expected_error needs the upstream error code if present.
    let is_expected = if response.status >= 400 && response.status != 429 {
        let error_code_pointer = match api_call.url.api_behavior.get("error_code") {
            Some(field) => format!("/{field}"),
            None => String::from("/error/code"),
        };
        let error_code_field = response.content.pointer(&error_code_pointer);
        is_expected_error(response.status, error_code_field, api_call)
    } else {
        false
    };
    this.context.stats.record_response(
        &api_call.url.service_name,
        &api_call.url.api,
        response.status,
        is_expected,
    );

    match response.status {
        429 => status_handlers::handle_too_many_requests(this, response, api_call).await,
        x if x == api_call.success_code => {
            status_handlers::handle_success(this, response, api_call).await
        }
        x => status_handlers::handle_unexpected_status(this, response, api_call, x).await,
    }
}
