// No-panic gate for the binary crate (CLI dispatch layer). The same block lives in
// `src/lib.rs` for the `collect` + `utils` code; crate-root attributes govern only
// their own crate, so the bin needs its own copy. See `src/lib.rs` for the rationale.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented
)]

use mimalloc::MiMalloc;
use oradaz::VERSION;
use oradaz::collect::collect;
use oradaz::inspect::{
    CompareCliOptions, LogFilters, StatsCliOptions, TimelineCliOptions, run_compare, run_config,
    run_hints, run_logs, run_metadata, run_services, run_stats, run_summary, run_timeline,
};

use clap::{Args, Parser, Subcommand};

/// Default config file name. Shared between the clap default on `CollectArgs`
/// and the default collection performed when no subcommand is given.
const DEFAULT_CONFIG_FILE: &str = "config-oradaz.xml";

/// Options for a collection run. Flattened at the top level (so a bare
/// invocation can carry collect options without the `collect` keyword) and
/// also carried by the explicit `collect` subcommand.
#[derive(Args, Debug)]
pub struct CollectArgs {
    /// Config file
    #[arg(
        short,
        long,
        value_name = "FILE",
        default_value_t = String::from(DEFAULT_CONFIG_FILE)
    )]
    config_file: String,

    /// Tenant GUID [if not set, will look in config file, then prompt the user]
    #[arg(short, long)]
    tenant: Option<String>,

    /// AppId to use for the Graph and Management API [if not set, will look in config file, then prompt the user]
    #[arg(short, long)]
    app_id: Option<String>,

    /// Output folder [default: current folder]
    #[arg(short, long, value_name = "FOLDER")]
    output: Option<String>,

    /// Increase verbosity (can be used multiple times)
    #[arg(short='v', long, action = clap::ArgAction::Count, default_value_t = 0, help = "Increase verbosity (default errors only): -v warnings, -vv info, -vvv debug, -vvvv trace")]
    verbosity: u8,
}

#[derive(Subcommand, Debug)]
// `Inspect` wraps the large `InspectCommands` enum, so the size gap to the
// other variants trips `large_enum_variant`. This enum is parsed once at
// startup — its size is irrelevant — and clap's derive does not support boxing
// a `#[command(subcommand)]` field, so suppress the lint here.
#[allow(clippy::large_enum_variant)]
pub enum Commands {
    /// Collect a new tenant configuration (default command)
    Collect(CollectArgs),
    /// Inspect a dump archive or folder
    Inspect {
        #[command(subcommand)]
        sub: InspectCommands,
    },
    /// Diff two collections (verdict, coverage, top table movers, config changes)
    Compare {
        /// First collection (path to MLA archive or folder, auto-detected)
        #[arg(value_name = "A")]
        source_a: String,
        /// Second collection (path to MLA archive or folder, auto-detected)
        #[arg(value_name = "B")]
        source_b: String,
        /// Private key for A (and B if --key-b is not given)
        #[arg(short = 'k', long, value_name = "KEY_FILE")]
        key: Option<String>,
        /// Private key for B when different from --key
        #[arg(long, value_name = "KEY_FILE")]
        key_b: Option<String>,
        /// Write report to file in addition to terminal output
        #[arg(long, value_name = "FILE")]
        report: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum InspectCommands {
    /// One-screen collection-health digest (run this first after a collection).
    Summary {
        /// Path to MLA archive (.mla/.broken)
        #[arg(long, value_name = "ARCHIVE")]
        mla: Option<String>,
        /// Path to a plain output folder
        #[arg(long, value_name = "FOLDER")]
        folder: Option<String>,
        /// Private key file for decrypting an MLA archive
        #[arg(short = 'k', long, value_name = "KEY_FILE")]
        key: Option<String>,
        /// Write report to file in addition to terminal output
        #[arg(long, value_name = "FILE")]
        report: Option<String>,
    },
    /// Filtered log viewer (grouped table by default, per-entry detail with --full).
    Logs {
        /// Archive (.mla/.broken), folder, or raw oradaz.log file (auto-detected).
        /// Positional alternative to --mla/--folder.
        #[arg(value_name = "PATH")]
        path: Option<String>,
        /// Path to MLA archive (.mla/.broken)
        #[arg(long, value_name = "ARCHIVE")]
        mla: Option<String>,
        /// Path to a plain output folder
        #[arg(long, value_name = "FOLDER")]
        folder: Option<String>,
        /// Private key file for decrypting an MLA archive
        #[arg(short = 'k', long, value_name = "KEY_FILE")]
        key: Option<String>,
        /// Write report to file in addition to terminal output
        #[arg(long, value_name = "FILE")]
        report: Option<String>,
        /// Show each entry with HTTP response body and POST data
        #[arg(long)]
        full: bool,
        /// Include warning-level entries
        #[arg(long)]
        warnings: bool,
        /// Include info-level entries (and warnings)
        #[arg(long)]
        info: bool,
        /// Include debug/trace-level entries (and info + warnings)
        #[arg(long)]
        debug: bool,
        /// Include schema-declared expected errors (hidden by default)
        #[arg(long)]
        include_expected: bool,
        /// Filter by service: graph, resources, or exchange
        #[arg(long, value_name = "SERVICE")]
        service: Option<String>,
        /// Filter by API name (case-insensitive substring match)
        #[arg(long, value_name = "SUBSTR")]
        api: Option<String>,
        /// Filter by HTTP status: exact code (403, 429) or class (4xx, 5xx)
        #[arg(long, value_name = "CODE")]
        http: Option<String>,
        /// Keep entries at or after this timestamp (HH:MM[:SS] or YYYY-MM-DD HH:MM[:SS])
        #[arg(long, value_name = "TIME")]
        since: Option<String>,
        /// Keep only the N most-recent entries (applied after other filters)
        #[arg(long, value_name = "N")]
        last: Option<usize>,
        /// Max number of groups in the grouped table (default 25)
        #[arg(long, value_name = "N")]
        limit: Option<usize>,
        /// Alias of --limit
        #[arg(long, value_name = "N")]
        top: Option<usize>,
        /// Show every group with no limit (overrides --limit/--top)
        #[arg(long)]
        all: bool,
        /// Sort key: count (default), recent, or status
        #[arg(long, value_name = "KEY", default_value = "count")]
        sort: String,
        /// Print only the COLLECTION SUMMARY + LOGS SUMMARY (no details)
        #[arg(long)]
        summary_only: bool,
        /// Per-minute timeline chart (alias of `oradaz inspect timeline`)
        #[arg(long)]
        timeline: bool,
        /// Restrict the timeline chart to HTTP 429 only
        #[arg(long)]
        timeline_429: bool,
    },
    /// Coverage by service: account, objects, HTTP, errors, and unexpected-error drill-down
    Services {
        /// Path to MLA archive (.mla/.broken)
        #[arg(long, value_name = "ARCHIVE")]
        mla: Option<String>,
        /// Path to a plain output folder
        #[arg(long, value_name = "FOLDER")]
        folder: Option<String>,
        /// Private key file for decrypting an MLA archive
        #[arg(short = 'k', long, value_name = "KEY_FILE")]
        key: Option<String>,
        /// Write report to file in addition to terminal output
        #[arg(long, value_name = "FILE")]
        report: Option<String>,
        /// Only show entries for this service (graph, resources, or exchange)
        #[arg(long, value_name = "SERVICE")]
        service: Option<String>,
    },
    /// Configuration used during collection (grouped + performance tuning deltas)
    Config {
        /// Path to MLA archive (.mla/.broken)
        #[arg(long, value_name = "ARCHIVE")]
        mla: Option<String>,
        /// Path to a plain output folder
        #[arg(long, value_name = "FOLDER")]
        folder: Option<String>,
        /// Private key file for decrypting an MLA archive
        #[arg(short = 'k', long, value_name = "KEY_FILE")]
        key: Option<String>,
        /// Write report to file in addition to terminal output
        #[arg(long, value_name = "FILE")]
        report: Option<String>,
        /// Show every performance-tuning parameter (default: only those that
        /// differ from the built-in defaults)
        #[arg(long)]
        all: bool,
    },
    /// Provenance + per-service data manifest (objects per table)
    Metadata {
        /// Path to MLA archive (.mla/.broken)
        #[arg(long, value_name = "ARCHIVE")]
        mla: Option<String>,
        /// Path to a plain output folder
        #[arg(long, value_name = "FOLDER")]
        folder: Option<String>,
        /// Private key file for decrypting an MLA archive
        #[arg(short = 'k', long, value_name = "KEY_FILE")]
        key: Option<String>,
        /// Write report to file in addition to terminal output
        #[arg(long, value_name = "FILE")]
        report: Option<String>,
        /// Number of tables listed under each service (defaults to 10)
        #[arg(long, default_value_t = 10)]
        top: usize,
        /// List every table, no truncation per service
        #[arg(long)]
        all: bool,
    },
    /// Categorised remediation: FATAL / UNEXPECTED / THROTTLING / EXPECTED with action hints
    Hints {
        /// Path to MLA archive (.mla/.broken)
        #[arg(long, value_name = "ARCHIVE")]
        mla: Option<String>,
        /// Path to a plain output folder
        #[arg(long, value_name = "FOLDER")]
        folder: Option<String>,
        /// Private key file for decrypting an MLA archive
        #[arg(short = 'k', long, value_name = "KEY_FILE")]
        key: Option<String>,
        /// Write report to file in addition to terminal output
        #[arg(long, value_name = "FILE")]
        report: Option<String>,
        /// Only show items for this service (graph, resources, or exchange)
        #[arg(long, value_name = "SERVICE")]
        service: Option<String>,
        /// List each expected error individually (default: summary line)
        #[arg(long)]
        include_expected: bool,
    },
    /// Temporal analysis: error/429 chart, API activity windows, problematic-APIs with time range
    Timeline {
        /// Path to MLA archive (.mla/.broken)
        #[arg(long, value_name = "ARCHIVE")]
        mla: Option<String>,
        /// Path to a plain output folder
        #[arg(long, value_name = "FOLDER")]
        folder: Option<String>,
        /// Private key file for decrypting an MLA archive
        #[arg(short = 'k', long, value_name = "KEY_FILE")]
        key: Option<String>,
        /// Write report to file in addition to terminal output
        #[arg(long, value_name = "FILE")]
        report: Option<String>,
        /// Only show entries for this service (graph, resources, or exchange)
        #[arg(long, value_name = "SERVICE")]
        service: Option<String>,
        /// Restrict the chart and problematic list to HTTP 429 only
        #[arg(long)]
        only_429: bool,
        /// Hide the chart + activity-windows table; keep only PROBLEMATIC APIS
        #[arg(long)]
        problematic_only: bool,
        /// Force chart granularity: 1s | 10s | 60s | 1m (default: auto)
        #[arg(long, value_name = "GRAIN")]
        bucket: Option<String>,
    },
    /// Per-API collection statistics, problematic APIs, throttling, activity windows
    Stats {
        /// Path to MLA archive (.mla/.broken)
        #[arg(long, value_name = "ARCHIVE")]
        mla: Option<String>,
        /// Path to a plain output folder
        #[arg(long, value_name = "FOLDER")]
        folder: Option<String>,
        /// Private key file for decrypting an MLA archive
        #[arg(short = 'k', long, value_name = "KEY_FILE")]
        key: Option<String>,
        /// Write report to file in addition to terminal output
        #[arg(long, value_name = "FILE")]
        report: Option<String>,
        /// Number of APIs to highlight in problematic / top lists
        #[arg(long, default_value_t = 10)]
        top: usize,
        /// Show statistics for every API (not just summary and top N)
        #[arg(long)]
        all: bool,
        /// Narrow PROBLEMATIC APIS / TOP BY * sections to one service
        /// (graph, resources, or exchange). The STATISTICS SUMMARY block
        /// remains tenant-wide for context.
        #[arg(long, value_name = "SERVICE")]
        service: Option<String>,
    },
}

#[derive(Parser)]
#[command(name = "ORADAZ")]
#[command(version = VERSION)]
#[command(about = "Collect the configuration of an Azure tenant", long_about = None)]
pub struct Cli {
    /// Subcommand to run; when omitted, a collection is performed.
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Disable coloured output (and decorative Unicode) for clean redirection
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Collect options (also usable without the `collect` keyword)
    #[command(flatten)]
    pub collect: CollectArgs,
}

/// Combine collect options given before the `collect` keyword (parsed into the
/// flattened top-level args) with those given after it (parsed into the
/// subcommand). The explicit subcommand value wins when set; otherwise the
/// top-level value is used, so neither placement is silently dropped.
fn merge_collect_args(mut explicit: CollectArgs, top_level: CollectArgs) -> CollectArgs {
    explicit.tenant = explicit.tenant.or(top_level.tenant);
    explicit.app_id = explicit.app_id.or(top_level.app_id);
    explicit.output = explicit.output.or(top_level.output);
    // `config_file` always has a value (clap fills its default), so "still at the
    // default" is the only signal that the subcommand did not set it explicitly.
    if explicit.config_file == DEFAULT_CONFIG_FILE {
        explicit.config_file = top_level.config_file;
    }
    explicit.verbosity = explicit.verbosity.max(top_level.verbosity);
    explicit
}

/// Resolve the command to run from the optional subcommand and the flattened
/// top-level collect options. A missing subcommand (or one carrying only collect
/// options) runs a collection; an explicit `collect` subcommand is merged with
/// the top-level options.
fn resolve_command(command: Option<Commands>, collect_args: CollectArgs) -> Commands {
    match command {
        Some(Commands::Collect(args)) => Commands::Collect(merge_collect_args(args, collect_args)),
        Some(other) => other,
        None => Commands::Collect(collect_args),
    }
}

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[tokio::main]
async fn main() {
    let Cli {
        command,
        no_color,
        collect: collect_args,
    } = Cli::parse();
    // A bare invocation (or one carrying only collect options) runs a
    // collection, exactly like the explicit `collect` subcommand.
    let command = resolve_command(command, collect_args);
    match command {
        Commands::Collect(args) => {
            collect(
                args.config_file,
                args.tenant,
                args.app_id,
                args.output,
                args.verbosity,
                no_color,
            )
            .await
        }
        Commands::Compare {
            source_a,
            source_b,
            key,
            key_b,
            report,
        } => {
            run_compare(CompareCliOptions {
                source_a,
                source_b,
                key,
                key_b,
                report,
                no_color,
            });
        }
        Commands::Inspect { sub } => match sub {
            InspectCommands::Summary {
                mla,
                folder,
                key,
                report,
            } => {
                run_summary(mla, folder, key, report, no_color);
            }
            InspectCommands::Logs {
                path,
                mla,
                folder,
                key,
                report,
                full,
                warnings,
                info,
                debug,
                include_expected,
                service,
                api,
                http,
                since,
                last,
                limit,
                top,
                all,
                sort,
                summary_only,
                timeline,
                timeline_429,
            } => {
                // --top is an alias for --limit; --top wins when both
                // are supplied so the more explicit "top N" terminology
                // is preserved.
                let effective_limit = top.or(limit);
                let parsed_sort = match sort.to_lowercase().as_str() {
                    "count" => oradaz::inspect::log_parser::SortBy::Count,
                    "recent" => oradaz::inspect::log_parser::SortBy::Recent,
                    "status" => oradaz::inspect::log_parser::SortBy::Status,
                    other => {
                        eprintln!(
                            "Error: invalid --sort value '{other}' (expected count, recent, or status)"
                        );
                        std::process::exit(1);
                    }
                };
                run_logs(
                    path,
                    mla,
                    folder,
                    key,
                    report,
                    LogFilters {
                        full,
                        warnings,
                        info,
                        debug,
                        include_expected,
                        service,
                        api,
                        http,
                        since,
                        last,
                        limit: effective_limit,
                        all,
                        sort: parsed_sort,
                        summary_only,
                        timeline,
                        timeline_429,
                    },
                    no_color,
                );
            }
            InspectCommands::Services {
                mla,
                folder,
                key,
                report,
                service,
            } => {
                run_services(mla, folder, key, report, service, no_color);
            }
            InspectCommands::Config {
                mla,
                folder,
                key,
                report,
                all,
            } => {
                run_config(mla, folder, key, report, all, no_color);
            }
            InspectCommands::Metadata {
                mla,
                folder,
                key,
                report,
                top,
                all,
            } => {
                run_metadata(mla, folder, key, report, top, all, no_color);
            }
            InspectCommands::Hints {
                mla,
                folder,
                key,
                report,
                service,
                include_expected,
            } => {
                run_hints(
                    mla,
                    folder,
                    key,
                    report,
                    service,
                    include_expected,
                    no_color,
                );
            }
            InspectCommands::Timeline {
                mla,
                folder,
                key,
                report,
                service,
                only_429,
                problematic_only,
                bucket,
            } => {
                run_timeline(TimelineCliOptions {
                    mla,
                    folder,
                    key,
                    report,
                    service,
                    only_429,
                    problematic_only,
                    bucket,
                    no_color,
                });
            }
            InspectCommands::Stats {
                mla,
                folder,
                key,
                report,
                top,
                all,
                service,
            } => {
                run_stats(StatsCliOptions {
                    mla,
                    folder,
                    key,
                    report,
                    top,
                    all,
                    service,
                    no_color,
                });
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, Commands, InspectCommands, resolve_command};

    use clap::{CommandFactory, Parser};

    #[test]
    fn cli_structure_is_valid() {
        // clap validates the command tree (duplicate ids, global/local clashes)
        // at parser-construction time, not at compile time — assert it here.
        Cli::command().debug_assert();
    }

    #[test]
    fn bare_invocation_has_no_subcommand() {
        let cli = Cli::try_parse_from(["oradaz"]).unwrap();
        assert!(cli.command.is_none());
    }

    #[test]
    fn bare_invocation_accepts_collect_options() {
        let cli = Cli::try_parse_from(["oradaz", "--tenant", "abc", "-vvv"]).unwrap();
        assert!(cli.command.is_none());
        assert_eq!(cli.collect.tenant.as_deref(), Some("abc"));
        assert_eq!(cli.collect.verbosity, 3);
    }

    #[test]
    fn collect_subcommand_parses() {
        let cli = Cli::try_parse_from(["oradaz", "collect"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Collect(_))));
    }

    #[test]
    fn collect_options_before_keyword_are_merged() {
        // `oradaz --tenant x -vvv collect`: options precede the explicit
        // subcommand and must still reach the collection.
        let cli = Cli::try_parse_from(["oradaz", "--tenant", "x", "-vvv", "collect"]).unwrap();
        match resolve_command(cli.command, cli.collect) {
            Commands::Collect(args) => {
                assert_eq!(args.tenant.as_deref(), Some("x"));
                assert_eq!(args.verbosity, 3);
            }
            other => panic!("expected Collect, got {other:?}"),
        }
    }

    #[test]
    fn collect_config_file_before_keyword_is_used() {
        let cli = Cli::try_parse_from(["oradaz", "-c", "custom.xml", "collect"]).unwrap();
        match resolve_command(cli.command, cli.collect) {
            Commands::Collect(args) => assert_eq!(args.config_file, "custom.xml"),
            other => panic!("expected Collect, got {other:?}"),
        }
    }

    #[test]
    fn explicit_collect_value_wins_over_top_level() {
        // A value attached to the explicit subcommand takes precedence over the
        // same option given before the keyword.
        let cli = Cli::try_parse_from([
            "oradaz", "--tenant", "before", "collect", "--tenant", "after",
        ])
        .unwrap();
        match resolve_command(cli.command, cli.collect) {
            Commands::Collect(args) => assert_eq!(args.tenant.as_deref(), Some("after")),
            other => panic!("expected Collect, got {other:?}"),
        }
    }

    #[test]
    fn inspect_logs_top_overrides_limit() {
        // `--top` is an alias for `--limit`; when both are given, `--top` wins
        // (the dispatcher applies `top.or(limit)`).
        let cli = Cli::try_parse_from(["oradaz", "inspect", "logs", "--limit", "5", "--top", "10"])
            .unwrap();
        match cli.command {
            Some(Commands::Inspect {
                sub: InspectCommands::Logs { limit, top, .. },
            }) => {
                assert_eq!(top.or(limit), Some(10), "--top must win over --limit");
            }
            other => panic!("expected inspect logs, got {other:?}"),
        }
    }

    #[test]
    fn compare_is_top_level() {
        let cli = Cli::try_parse_from(["oradaz", "compare", "a", "b"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Compare { .. })));
    }

    #[test]
    fn no_color_is_global() {
        // The global flag must be accepted everywhere: standalone, after
        // collect, after inspect, and after compare.
        assert!(
            Cli::try_parse_from(["oradaz", "--no-color"])
                .unwrap()
                .no_color
        );
        assert!(
            Cli::try_parse_from(["oradaz", "collect", "--no-color"])
                .unwrap()
                .no_color
        );
        assert!(
            Cli::try_parse_from(["oradaz", "inspect", "summary", "--no-color"])
                .unwrap()
                .no_color
        );
        assert!(
            Cli::try_parse_from(["oradaz", "compare", "a", "b", "--no-color"])
                .unwrap()
                .no_color
        );
    }
}
