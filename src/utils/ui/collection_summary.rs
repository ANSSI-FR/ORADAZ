// Post-collection summary printed to the terminal after a successful dump.
use crate::utils::ui::{Paint, UiMode, dim, mode, paint};

/// Width of the title text used for the box header padding (raw text, before
/// any ANSI styling is applied).
const HEADER_COMPLETE: &str = "  COLLECTION COMPLETE";
const HEADER_PARTIAL: &str = "  PARTIAL COLLECTION";

/// Width of the summary box interior (excluding the two border characters).
const INNER_WIDTH: usize = 69;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceStatus {
    Enabled,
    DisabledByConfig,
    DisabledByPrerequisiteFailure,
}

pub struct ServiceRowData {
    pub name: String,
    pub status: ServiceStatus,
    pub objects: usize,
    pub batch_calls: usize,
    pub single_calls: usize,
}

pub struct UnexpectedApiError {
    pub service: String,
    pub api: String,
    /// Most common HTTP status code among unexpected errors for this API.
    pub dominant_status: Option<u16>,
    /// Total count of unexpected errors for this API.
    pub count: usize,
}

/// An API whose data was (partly) never obtained: one or more of its URLs were
/// abandoned with a non-HTTP terminal failure (`status == 0`), e.g. retry budget
/// exhausted (`UrlRetryLimit`) or a missing token. Distinct from
/// [`UnexpectedApiError`], which records HTTP error *responses*.
pub struct IncompleteApi {
    pub service: String,
    pub api: String,
    /// Total number of URLs not collected for this API.
    pub count: usize,
    /// Dominant lost-data code (e.g. `"UrlRetryLimit"`), mapped to a human
    /// reason by [`lost_reason`] at render time.
    pub code: String,
}

/// Render an incomplete API as `service / api`, or just `service` when the api
/// name is empty (e.g. `UnknownApiCallCreationError`, which has no api) so the
/// summary never prints a dangling `service /  : …`.
fn incomplete_label(item: &IncompleteApi) -> String {
    if item.api.is_empty() {
        item.service.clone()
    } else {
        format!("{} / {}", item.service, item.api)
    }
}

/// Map a lost-data `DumpError` code to a short human-readable cause.
pub fn lost_reason(code: &str) -> &'static str {
    match code {
        "UrlRetryLimit" => "retry budget exhausted — network/throttling",
        "NoTokenForApiCall" => "authentication token unavailable",
        "MissingTokenForRelationships" => "token unavailable for relationships",
        "nextLinkParsingError" => "pagination interrupted",
        "MissingBatchData" => "internal batch error",
        "UnknownApiCallCreationError" => "request could not be built",
        _ => "not collected",
    }
}

pub struct CollectionSummaryData<'a> {
    pub service_rows: &'a [ServiceRowData],
    pub unexpected_errors: usize,
    pub expected_errors: usize,
    pub error_details: &'a [UnexpectedApiError],
    /// APIs whose data is (partly) missing because URLs were abandoned. When
    /// non-empty, the summary header reads "PARTIAL COLLECTION".
    pub incomplete_apis: &'a [IncompleteApi],
    pub archive_path: &'a str,
    pub size_mib: f64,
    pub duration_secs: i64,
    pub total_http_requests: usize,
    /// CLI verbosity level (0 = quiet, 1 = -v, …)
    pub verbosity: u8,
}

/// Format a non-negative integer with a space as the thousands separator.
pub fn format_number(n: usize) -> String {
    if n < 1_000 {
        n.to_string()
    } else if n < 1_000_000 {
        format!("{} {:03}", n / 1_000, n % 1_000)
    } else if n < 1_000_000_000 {
        format!(
            "{} {:03} {:03}",
            n / 1_000_000,
            (n / 1_000) % 1_000,
            n % 1_000
        )
    } else {
        format!(
            "{} {:03} {:03} {:03}",
            n / 1_000_000_000,
            (n / 1_000_000) % 1_000,
            (n / 1_000) % 1_000,
            n % 1_000,
        )
    }
}

/// Format a duration in seconds as a human-readable string.
pub fn format_duration(secs: i64) -> String {
    if secs <= 0 {
        return "0s".to_string();
    }
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m {}s", secs / 3600, (secs / 60) % 60, secs % 60)
    }
}

/// Return the canonical HTTP reason phrase for a status code.
pub fn status_reason(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Unknown",
    }
}

/// Build the HTTP-call part of a service summary row.
pub fn service_call_summary(batch: usize, single: usize) -> String {
    match (batch, single) {
        (0, 0) => String::new(),
        (b, 0) => format!("{} batch", format_number(b)),
        (0, s) => format!("{} single", format_number(s)),
        (b, s) => format!("{} batch, {} single", format_number(b), format_number(s)),
    }
}

/// Print the full collection summary to stdout.
pub fn print_collection_summary(data: &CollectionSummaryData<'_>) {
    println!();
    match mode() {
        UiMode::Color => print_color(data),
        UiMode::NoColor => print_no_color(data),
    }
}

// ─── Color rendering ─────────────────────────────────────────────────────────

fn print_color(data: &CollectionSummaryData<'_>) {
    // Box header — "PARTIAL COLLECTION" (yellow + bold) when data is missing.
    println!("┌{}┐", "─".repeat(INNER_WIDTH));
    let partial = !data.incomplete_apis.is_empty();
    let title = if partial {
        HEADER_PARTIAL
    } else {
        HEADER_COMPLETE
    };
    // Padding is computed from the raw title length; the ANSI styling is applied
    // afterwards so the escape bytes do not break the box alignment.
    let padding = INNER_WIDTH.saturating_sub(title.len());
    let rendered_title = if partial {
        paint(Paint::YellowBold, title)
    } else {
        title.to_string()
    };
    println!("│{}{}│", rendered_title, " ".repeat(padding));
    println!("└{}┘", "─".repeat(INNER_WIDTH));

    // Service rows
    let name_width = data
        .service_rows
        .iter()
        .map(|r| r.name.len())
        .max()
        .unwrap_or(8)
        .max(8);
    let obj_width = data
        .service_rows
        .iter()
        .filter(|r| r.status == ServiceStatus::Enabled)
        .map(|r| format_number(r.objects).len())
        .max()
        .unwrap_or(1);

    for row in data.service_rows {
        print_service_row_color(row, name_width, obj_width);
    }

    // Separator after services
    println!("  {}", dim("─"));

    // Incomplete-collection block (data never obtained) — shown first as the
    // headline signal that the archive is partial.
    if !data.incomplete_apis.is_empty() {
        print_incomplete_block_color(data);
        println!("  {}", dim("─"));
    }

    // Unexpected error block (always shown when errors exist)
    if data.unexpected_errors > 0 {
        print_error_block_color(data);
        println!("  {}", dim("─"));
    }

    // Archive, duration, and request count
    println!(
        "  Archive    : {} ({:.1} MiB)",
        data.archive_path, data.size_mib
    );
    println!("  Duration   : {}", format_duration(data.duration_secs));
    println!("  Requests   : {}", format_number(data.total_http_requests));
    println!(
        "  {}",
        dim("Send this file as-is. Do not rename or re-encrypt — it is already encrypted.")
    );
}

fn print_service_row_color(row: &ServiceRowData, name_width: usize, obj_width: usize) {
    match row.status {
        ServiceStatus::Enabled => {
            let icon = paint(Paint::Green, "✓");
            let obj_str = format_number(row.objects);
            let call_str = service_call_summary(row.batch_calls, row.single_calls);
            let calls_part = if call_str.is_empty() {
                String::new()
            } else {
                format!("  {}", dim(&call_str))
            };
            println!(
                "  {}  {:<name_width$}  {:>obj_width$} objects    {}",
                icon,
                row.name,
                obj_str,
                calls_part,
                name_width = name_width,
                obj_width = obj_width,
            );
        }
        ServiceStatus::DisabledByConfig => {
            println!(
                "  {}  {:<name_width$}  {}",
                dim("─"),
                dim(&row.name),
                dim("(disabled by config)"),
                name_width = name_width,
            );
        }
        ServiceStatus::DisabledByPrerequisiteFailure => {
            let icon = paint(Paint::Red, "✖");
            println!(
                "  {}  {:<name_width$}  {}",
                icon,
                row.name,
                dim("(prerequisite failure)"),
                name_width = name_width,
            );
        }
    }
}

fn print_incomplete_block_color(data: &CollectionSummaryData<'_>) {
    let warn_icon = paint(Paint::Yellow, "⚠");
    println!(
        "  {}  {}",
        warn_icon,
        paint(
            Paint::YellowBold,
            &format!(
                "Partial collection: {} API(s) not fully collected — data is missing",
                format_number(data.incomplete_apis.len())
            )
        )
    );

    for item in data.incomplete_apis {
        println!(
            "\n     {} : {} request(s) not collected ({})",
            incomplete_label(item),
            format_number(item.count),
            lost_reason(&item.code)
        );
    }

    println!(
        "\n     {}",
        dim("These endpoints were abandoned before their data could be collected.")
    );
    println!(
        "     {}  Re-run the collection to fill the gaps, or inspect details: {}",
        dim("→"),
        dim("oradaz inspect logs --http 0")
    );
}

fn print_error_block_color(data: &CollectionSummaryData<'_>) {
    let warn_icon = paint(Paint::Yellow, "⚠");

    // First line: unexpected count (+ expected count at -v)
    let expected_suffix = if data.verbosity >= 1 && data.expected_errors > 0 {
        format!(
            " {} {} expected errors (masked)",
            dim("—"),
            format_number(data.expected_errors)
        )
    } else {
        String::new()
    };
    println!(
        "  {}  {} unexpected error(s){}",
        warn_icon,
        format_number(data.unexpected_errors),
        expected_suffix
    );

    // Per-API detail (always shown when there are unexpected errors)
    for detail in data.error_details {
        let status_str = match detail.dominant_status {
            Some(s) => format!("{} {} ", s, status_reason(s)),
            None => String::new(),
        };
        println!(
            "\n     {} / {} : {}({} occurrence(s))",
            detail.service,
            detail.api,
            status_str,
            format_number(detail.count)
        );
    }

    // Informational message and inspect hint
    println!(
        "\n     {}",
        dim("The archive is still valid. If useful data is missing, the report will flag it.")
    );
    if data.verbosity >= 1 {
        println!(
            "     {}  For details about the errors: {}",
            dim("→"),
            dim("oradaz inspect logs --full")
        );
    } else {
        println!(
            "     {}  For details about the errors: {}",
            dim("→"),
            dim("oradaz inspect logs")
        );
    }
}

// ─── No-color rendering ───────────────────────────────────────────────────────

fn print_no_color(data: &CollectionSummaryData<'_>) {
    println!("{}", "-".repeat(INNER_WIDTH + 2));
    if data.incomplete_apis.is_empty() {
        println!("{}", HEADER_COMPLETE);
    } else {
        println!("{}", HEADER_PARTIAL);
    }
    println!("{}", "-".repeat(INNER_WIDTH + 2));

    let name_width = data
        .service_rows
        .iter()
        .map(|r| r.name.len())
        .max()
        .unwrap_or(8)
        .max(8);
    let obj_width = data
        .service_rows
        .iter()
        .filter(|r| r.status == ServiceStatus::Enabled)
        .map(|r| format_number(r.objects).len())
        .max()
        .unwrap_or(1);

    for row in data.service_rows {
        print_service_row_no_color(row, name_width, obj_width);
    }

    println!("  ---");

    if !data.incomplete_apis.is_empty() {
        print_incomplete_block_no_color(data);
        println!("  ---");
    }

    if data.unexpected_errors > 0 {
        print_error_block_no_color(data);
        println!("  ---");
    }

    println!(
        "  Archive    : {} ({:.1} MiB)",
        data.archive_path, data.size_mib
    );
    println!("  Duration   : {}", format_duration(data.duration_secs));
    println!("  Requests   : {}", format_number(data.total_http_requests));
    println!("  Send this file as-is. Do not rename or re-encrypt -- it is already encrypted.");
}

fn print_service_row_no_color(row: &ServiceRowData, name_width: usize, obj_width: usize) {
    match row.status {
        ServiceStatus::Enabled => {
            let obj_str = format_number(row.objects);
            let call_str = service_call_summary(row.batch_calls, row.single_calls);
            let calls_part = if call_str.is_empty() {
                String::new()
            } else {
                format!("  {}", call_str)
            };
            println!(
                "  [OK] {:<name_width$}  {:>obj_width$} objects    {}",
                row.name,
                obj_str,
                calls_part,
                name_width = name_width,
                obj_width = obj_width,
            );
        }
        ServiceStatus::DisabledByConfig => {
            println!(
                "  [--] {:<name_width$}  (disabled by config)",
                row.name,
                name_width = name_width,
            );
        }
        ServiceStatus::DisabledByPrerequisiteFailure => {
            println!(
                "  [!!] {:<name_width$}  (prerequisite failure)",
                row.name,
                name_width = name_width,
            );
        }
    }
}

fn print_incomplete_block_no_color(data: &CollectionSummaryData<'_>) {
    println!(
        "  [!] Partial collection: {} API(s) not fully collected -- data is missing",
        format_number(data.incomplete_apis.len())
    );

    for item in data.incomplete_apis {
        println!(
            "\n      {} : {} request(s) not collected ({})",
            incomplete_label(item),
            format_number(item.count),
            lost_reason(&item.code)
        );
    }

    println!("\n      These endpoints were abandoned before their data could be collected.");
    println!(
        "      -> Re-run the collection to fill the gaps, or inspect details: oradaz inspect logs --http 0"
    );
}

fn print_error_block_no_color(data: &CollectionSummaryData<'_>) {
    let expected_suffix = if data.verbosity >= 1 && data.expected_errors > 0 {
        format!(
            " -- {} expected errors (masked)",
            format_number(data.expected_errors)
        )
    } else {
        String::new()
    };
    println!(
        "  [!] {} unexpected error(s){}",
        format_number(data.unexpected_errors),
        expected_suffix
    );

    for detail in data.error_details {
        let status_str = match detail.dominant_status {
            Some(s) => format!("{} {} ", s, status_reason(s)),
            None => String::new(),
        };
        println!(
            "\n      {} / {} : {}({} occurrence(s))",
            detail.service,
            detail.api,
            status_str,
            format_number(detail.count)
        );
    }

    println!(
        "\n      The archive is still valid. If useful data is missing, the report will flag it."
    );
    if data.verbosity >= 1 {
        println!("      -> For details about the errors: oradaz inspect logs --full");
    } else {
        println!("      -> For details about the errors: oradaz inspect logs");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_number_below_thousand() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(1), "1");
        assert_eq!(format_number(999), "999");
    }

    #[test]
    fn test_format_number_thousands() {
        assert_eq!(format_number(1_000), "1 000");
        assert_eq!(format_number(2_341), "2 341");
        assert_eq!(format_number(42_000), "42 000");
        assert_eq!(format_number(999_999), "999 999");
    }

    #[test]
    fn test_format_number_millions() {
        assert_eq!(format_number(1_000_000), "1 000 000");
        assert_eq!(format_number(1_234_567), "1 234 567");
        assert_eq!(format_number(999_999_999), "999 999 999");
    }

    #[test]
    fn test_format_number_billions() {
        assert_eq!(format_number(1_000_000_000), "1 000 000 000");
        assert_eq!(format_number(1_234_567_890), "1 234 567 890");
        assert_eq!(format_number(12_345_678_901), "12 345 678 901");
    }

    #[test]
    fn test_obj_width_dynamic() {
        // With a large and a small service, the smaller one should be padded
        // to match the larger one's formatted width.
        let large = format_number(1_234_567_890); // "1 234 567 890" = 13 chars
        let small = format_number(42); // "42" = 2 chars
        let obj_width = large.len().max(small.len());
        let padded_small = format!("{:>obj_width$}", small, obj_width = obj_width);
        assert_eq!(padded_small.len(), large.len());
        assert_eq!(padded_small, "           42");
    }

    #[test]
    fn test_format_duration_seconds() {
        assert_eq!(format_duration(0), "0s");
        assert_eq!(format_duration(-5), "0s");
        assert_eq!(format_duration(1), "1s");
        assert_eq!(format_duration(59), "59s");
    }

    #[test]
    fn test_format_duration_minutes() {
        assert_eq!(format_duration(60), "1m 0s");
        assert_eq!(format_duration(90), "1m 30s");
        assert_eq!(format_duration(3599), "59m 59s");
    }

    #[test]
    fn test_format_duration_hours() {
        assert_eq!(format_duration(3600), "1h 0m 0s");
        assert_eq!(format_duration(3661), "1h 1m 1s");
        assert_eq!(format_duration(7322), "2h 2m 2s");
    }

    #[test]
    fn test_status_reason_known() {
        assert_eq!(status_reason(403), "Forbidden");
        assert_eq!(status_reason(404), "Not Found");
        assert_eq!(status_reason(500), "Internal Server Error");
        assert_eq!(status_reason(503), "Service Unavailable");
    }

    #[test]
    fn test_status_reason_unknown() {
        assert_eq!(status_reason(418), "Unknown");
        assert_eq!(status_reason(999), "Unknown");
    }

    #[test]
    fn test_service_call_summary_both() {
        assert_eq!(service_call_summary(118, 34), "118 batch, 34 single");
    }

    #[test]
    fn test_service_call_summary_batch_only() {
        assert_eq!(service_call_summary(47, 0), "47 batch");
    }

    #[test]
    fn test_service_call_summary_single_only() {
        assert_eq!(service_call_summary(0, 15), "15 single");
    }

    #[test]
    fn test_service_call_summary_none() {
        assert_eq!(service_call_summary(0, 0), "");
    }

    #[test]
    fn test_lost_reason_known_codes() {
        assert_eq!(
            lost_reason("UrlRetryLimit"),
            "retry budget exhausted — network/throttling"
        );
        assert_eq!(
            lost_reason("NoTokenForApiCall"),
            "authentication token unavailable"
        );
        assert_eq!(
            lost_reason("MissingTokenForRelationships"),
            "token unavailable for relationships"
        );
        assert_eq!(
            lost_reason("nextLinkParsingError"),
            "pagination interrupted"
        );
        assert_eq!(lost_reason("MissingBatchData"), "internal batch error");
        assert_eq!(
            lost_reason("UnknownApiCallCreationError"),
            "request could not be built"
        );
    }

    #[test]
    fn test_lost_reason_unknown_code_falls_back() {
        assert_eq!(lost_reason("SomeFutureCode"), "not collected");
        assert_eq!(lost_reason(""), "not collected");
    }

    #[test]
    fn test_incomplete_label_with_and_without_api() {
        let with_api = IncompleteApi {
            service: "graph".to_string(),
            api: "users".to_string(),
            count: 3,
            code: "UrlRetryLimit".to_string(),
        };
        assert_eq!(incomplete_label(&with_api), "graph / users");

        // UnknownApiCallCreationError carries no api name → render service alone,
        // never a dangling "graph / ".
        let no_api = IncompleteApi {
            service: "graph".to_string(),
            api: String::new(),
            count: 1,
            code: "UnknownApiCallCreationError".to_string(),
        };
        assert_eq!(incomplete_label(&no_api), "graph");
    }
}
