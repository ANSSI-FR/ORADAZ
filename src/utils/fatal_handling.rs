/// Utility for handling fatal errors uniformly.
///
/// The `bail_fatal!` macro logs the error, displays a consistent UI fatal block,
/// and exits the process.
///
/// The caller is responsible for calling `writer.set_broken().await` before invoking
/// this macro if an MLA archive is in progress, so the `.mla.tmp` file is correctly
/// renamed to `.mla.broken`.
///
/// Usage:
/// ```
/// // let err = Error::StringError("something".into());
/// // oradaz::bail_fatal!(err);
/// ```
#[macro_export]
macro_rules! bail_fatal {
    ($err:expr) => {{
        // Log the error BEFORE pausing stdout logging, so the error line itself
        // still reaches the console.
        ::log::error!("{:width$}{}", "main", $err, width = $crate::FL);

        // Suppress further stdout logs and pause the progress ticker BEFORE
        // printing the fatal block: a ticker frame painted after the block (or
        // after the "Press Enter" prompt below) would otherwise repaint over
        // them. The process is about to exit, so this pause source is
        // intentionally never decremented.
        $crate::utils::logger::config::DUMP_PAUSED
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Display UI fatal block
        let title = $err.title();
        let context = $err.context();
        let steps = $err.remediation_steps();
        $crate::utils::ui::fatal(title, context.as_deref(), steps);

        // Wait for user if interactive
        $crate::utils::fatal_handling::wait_if_interactive();
        // Exit the process
        std::process::exit(1);
    }};
}

/// Blocks until the user presses Enter, but only when running on a fully interactive
/// terminal (both stdin and stdout are TTYs). Requiring stdin to be a TTY avoids hanging
/// a pipeline that redirects stdin from a file or `/dev/null`; requiring stdout to be a
/// TTY avoids a spurious wait when output is piped (e.g. `oradaz | tee`).
pub fn wait_if_interactive() {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        println!("\nPress Enter to exit...");
        let mut buffer = String::new();
        let _ = std::io::stdin().read_line(&mut buffer);
    }
}

// Re-export the macro for external modules
