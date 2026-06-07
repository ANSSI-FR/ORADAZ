// Authentication banner live region implementation
// Provides a continuously refreshed banner while the user completes a device or
// authorization code flow. The banner is cleared automatically on success or
// failure.
use crate::utils::logger::{
    LiveRegionState, calculate_rendered_lines, redraw_live_region, tear_down_live_region,
    update_live_region_state, update_live_region_text,
};
use crate::utils::mutex::lock_force;
use crate::utils::ui::{Icon, UiMode, blink_red_bold, blue, err_text, icon, mode};

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// AuthBanner handles rendering a live authentication banner.
pub struct AuthBanner {
    service: String,
    authentication_uri: String,
    user_code: Arc<Mutex<String>>,
    flow_label: String,
    completed: Arc<Mutex<Vec<String>>>, // services that have succeeded
    pending: Arc<Mutex<Vec<String>>>,   // services whose auth is still in progress
    start: Instant,
    stop_flag: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>, // ticker thread
}

impl Default for AuthBanner {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthBanner {
    /// Create a new banner (fields will be set on `begin`).
    pub fn new() -> Self {
        AuthBanner {
            service: String::new(),
            authentication_uri: String::new(),
            user_code: Arc::new(Mutex::new(String::new())),
            flow_label: String::new(),
            completed: Arc::new(Mutex::new(Vec::new())),
            pending: Arc::new(Mutex::new(Vec::new())),
            start: Instant::now(),
            stop_flag: Arc::new(AtomicBool::new(true)), // stopped by default
            handle: None,
        }
    }

    /// Start the ticker and render the banner. Must be called after we have the
    /// service name, authentication URL and user code.
    pub fn begin(
        &mut self,
        service: &str,
        authentication_uri: &str,
        user_code: &str,
        flow_label: &str,
    ) {
        self.service = service.to_string();
        self.authentication_uri = authentication_uri.to_string();
        *lock_force(&self.user_code) = user_code.to_string();
        self.flow_label = flow_label.to_string();
        self.start = Instant::now();

        // No-color / non-interactive mode: the live region is disabled, so the
        // animated banner would never reach the screen and the user would never
        // see the URL/code (making interactive auth impossible under `--no-color`,
        // `NO_COLOR`, or a redirected/non-TTY stdout). Instead, print a STATIC,
        // append-only block once — no spinner, no elapsed timer, no cursor
        // movement (nothing is ever rewritten). A renewed code (on expiry) prints
        // a fresh block via `update_code`.
        if mode() != UiMode::Color {
            println!(
                "{}",
                render_static_auth_banner(authentication_uri, user_code, flow_label, false)
            );
            return;
        }

        self.stop_flag.store(false, Ordering::Relaxed);

        let stop = Arc::clone(&self.stop_flag);
        let uri = self.authentication_uri.clone();
        let code = Arc::clone(&self.user_code);
        let label = self.flow_label.clone();
        let pending = Arc::clone(&self.pending);
        let start_time = self.start;

        // Initial paint
        let initial_text = render_banner(
            &uri,
            &lock_force(&code),
            &label,
            &lock_force(&pending),
            "00:00:00",
            0,
        );

        {
            update_live_region_text(&initial_text);
            update_live_region_state(LiveRegionState::AuthBanner {
                lines: calculate_rendered_lines(&initial_text),
            });
        }
        redraw_live_region(false);

        let handle = thread::spawn(move || {
            let mut frame = 0;
            while !stop.load(Ordering::Relaxed) {
                let elapsed = Instant::now().duration_since(start_time);
                let elapsed_str = format!(
                    "{:02}:{:02}:{:02}",
                    elapsed.as_secs() / 3600,
                    (elapsed.as_secs() / 60) % 60,
                    elapsed.as_secs() % 60
                );
                frame = (frame + 1) % 8;

                let text = render_banner(
                    &uri,
                    &lock_force(&code),
                    &label,
                    &lock_force(&pending),
                    &elapsed_str,
                    frame,
                );

                update_live_region_text(&text);
                redraw_live_region(true);
                update_live_region_state(LiveRegionState::AuthBanner {
                    lines: calculate_rendered_lines(&text),
                });
                thread::sleep(Duration::from_millis(300));
            }
        });
        self.handle = Some(handle);
    }

    /// Update the displayed user code when a device code expires and a fresh one
    /// is requested.
    ///
    /// In color mode the ticker thread reads the shared code each frame, so the
    /// on-screen code updates in place (the elapsed timer keeps counting total
    /// wait time). In no-color mode there is no ticker, so a fresh STATIC block is
    /// appended announcing the new code — the previous block is left intact (no
    /// line is ever rewritten).
    pub fn update_code(&self, new_code: &str) {
        *lock_force(&self.user_code) = new_code.to_string();
        if mode() != UiMode::Color {
            println!(
                "{}",
                render_static_auth_banner(
                    &self.authentication_uri,
                    new_code,
                    &self.flow_label,
                    true,
                )
            );
        }
    }

    /// Mark a service as ready – removes it from the pending list.
    pub fn mark_service_ready(&self, service: &str) {
        let mut pending = lock_force(&self.pending);
        pending.retain(|s| s != service);
    }

    /// Record a completed service for the final success line.
    pub fn add_completed(&self, service: &str) {
        let mut completed = lock_force(&self.completed);
        if !completed.contains(&service.to_string()) {
            completed.push(service.to_string());
        }
    }

    /// Stop the ticker, clear the banner and print a success line.
    pub fn success(&mut self) {
        self.finish(true, "");
    }

    /// Stop the ticker, clear the banner and print an error line.
    pub fn failure(&mut self, err: &str) {
        self.finish(false, err);
    }

    fn finish(&mut self, ok: bool, err_msg: &str) {
        // Signal thread to stop
        self.stop_flag.store(true, Ordering::Relaxed);
        // Wait for thread to finish
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        // Ensure banner cleared
        tear_down_live_region();
        // Reset live region state
        update_live_region_state(LiveRegionState::None);
        // Print final line
        if !ok {
            println!("{}", err_text(err_msg));
        }
    }
}

/// Renders the full banner content as a string.
fn render_banner(
    authentication_uri: &str,
    user_code: &str,
    flow_label: &str,
    pending_vec: &[String],
    elapsed_str: &str,
    frame: u8,
) -> String {
    let mut lines = Vec::new();
    if mode() == UiMode::Color {
        lines.push(format!(
            "  {} {}",
            icon(Icon::Selected),
            blue("Authentication")
        ));
    }
    let warn_icon = icon(Icon::Warn);
    let header_text = if mode() == UiMode::Color {
        blink_red_bold("AUTHENTICATION REQUIRED")
    } else {
        String::from("AUTHENTICATION REQUIRED")
    };
    let header = format!(
        "  {}  {}                       {:>20}",
        warn_icon, header_text, flow_label
    );
    lines.push(icon(Icon::UpOrBottomBoldTable).repeat(71));
    lines.push(header);
    lines.push(icon(Icon::UpOrBottomBoldTable).repeat(71));
    lines.push(String::new());
    let authentication_line = format!("  Open   {}  {}", icon(Icon::Arrow), authentication_uri);
    lines.push(authentication_line);
    if !user_code.is_empty() {
        lines.push(format!(
            "            {}{}{}",
            icon(Icon::LeftUpBoldTable),
            icon(Icon::UpOrBottomBoldTable).repeat(13),
            icon(Icon::RightUpBoldTable)
        ));
        lines.push(format!(
            "  Code   {}  {}  {}  {}",
            icon(Icon::Arrow),
            icon(Icon::LeftOrRightBoldTable),
            user_code,
            icon(Icon::LeftOrRightBoldTable)
        ));
        lines.push(format!(
            "            {}{}{}",
            icon(Icon::LeftBottomBoldTable),
            icon(Icon::UpOrBottomBoldTable).repeat(13),
            icon(Icon::RightBottomBoldTable)
        ));
    }
    lines.push(String::new());
    lines.push(format!(
        "  {}  Waiting for you to authenticate (elapsed: {})",
        icon(Icon::Spinner(frame)),
        elapsed_str
    ));
    if !pending_vec.is_empty() {
        let pending_str = pending_vec.join(", ");
        lines.push(format!("Pending: {}", pending_str));
    }
    lines.join("\n")
}

/// Renders the authentication banner as a STATIC, append-only block for no-color /
/// non-interactive output.
///
/// Unlike [`render_banner`], this has **no spinner and no elapsed timer**: it is
/// printed once and never rewritten (no cursor movement), so it is safe for
/// `--no-color`, `NO_COLOR`, piped, or redirected output. On a code renewal
/// (`renewed == true`) a fresh block is printed announcing the new code rather
/// than rewriting the previous one. The layout is pure ASCII regardless of the
/// global UI mode, so the output is deterministic.
fn render_static_auth_banner(
    authentication_uri: &str,
    user_code: &str,
    flow_label: &str,
    renewed: bool,
) -> String {
    let border = "-".repeat(72);
    let mut lines = Vec::new();
    lines.push(border.clone());
    if renewed {
        lines
            .push("  !!  AUTHENTICATION - previous code expired, a new one was issued".to_string());
    } else {
        // Right-align the flow label within the 72-char border ("  !!  " prefix is
        // 6 chars, leaving an inner width of 66). A fixed-width title field
        // overflowed the border for the longest labels ("Authorization code" /
        // "Client credentials", 18 chars). `saturating_sub` keeps it panic-safe.
        let title = "AUTHENTICATION REQUIRED";
        let pad = 66usize.saturating_sub(title.len() + flow_label.len());
        lines.push(format!("  !!  {title}{}{flow_label}", " ".repeat(pad)));
    }
    lines.push(border);
    lines.push(format!("  Open  >  {authentication_uri}"));
    if !user_code.is_empty() {
        lines.push("           +-----------+".to_string());
        lines.push(format!("  Code  >  | {user_code} |"));
        lines.push("           +-----------+".to_string());
    }
    lines.push(String::new());
    lines.push("  Waiting for you to authenticate...".to_string());
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::render_static_auth_banner;

    #[test]
    fn static_banner_shows_url_and_code_without_ansi_or_timer() {
        let s = render_static_auth_banner(
            "https://microsoft.com/devicelogin",
            "GP32772HP",
            "Device code",
            false,
        );
        assert!(s.contains("https://microsoft.com/devicelogin"));
        assert!(s.contains("GP32772HP"));
        assert!(s.contains("AUTHENTICATION REQUIRED"));
        assert!(s.contains("Waiting for you to authenticate"));
        // Append-only / no-rewrite contract: no ANSI escapes, no spinner, no timer.
        assert!(
            !s.contains('\u{1b}'),
            "static banner must not contain ANSI escape sequences"
        );
        assert!(
            !s.contains("elapsed"),
            "static banner must not show an elapsed timer"
        );
    }

    // U3: the longest flow labels ("Authorization code" / "Client credentials",
    // 18 chars) must not overflow the 72-char border of the header line.
    #[test]
    fn static_banner_header_never_exceeds_border_width() {
        for label in ["Device code", "Authorization code", "Client credentials"] {
            let s = render_static_auth_banner("https://login.example/redirect", "", label, false);
            let header = s
                .lines()
                .find(|l| l.contains("AUTHENTICATION REQUIRED"))
                .expect("header line present");
            assert!(
                header.chars().count() <= 72,
                "header for flow '{label}' is {} chars (exceeds the 72-char border): {header:?}",
                header.chars().count()
            );
            assert!(
                header.contains(label),
                "header must still show the flow label '{label}'"
            );
        }
    }

    #[test]
    fn static_banner_renewal_announces_expiry_and_new_code() {
        let s = render_static_auth_banner(
            "https://microsoft.com/devicelogin",
            "K7QW2R9XM",
            "Device code",
            true,
        );
        assert!(s.contains("K7QW2R9XM"));
        assert!(s.to_lowercase().contains("expired"));
    }

    #[test]
    fn static_banner_omits_code_line_when_empty() {
        // Authorization-code flow passes an empty user code (only the URL matters).
        let s = render_static_auth_banner(
            "https://example.test/authorize",
            "",
            "Authorization code",
            false,
        );
        assert!(s.contains("https://example.test/authorize"));
        assert!(!s.contains("Code  >"));
    }
}
