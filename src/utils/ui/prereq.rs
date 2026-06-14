// Live-region UI for the prerequisites phase.
// Modeled after auth_banner.rs — spawns a ticker thread that updates an
// elapsed counter in-place, then tears down and prints a static summary block.
use crate::utils::errors::{Error, FatalPresentation};
use crate::utils::logger::{
    LiveRegionState, replace_live_region, tear_down_live_region, update_live_region_state,
};
use crate::utils::mutex::lock_force;
use crate::utils::ui::{Icon, UiMode, blue, dim, err_text, icon, mode, success, warn_text};

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const DETAIL_COL: usize = 46;

#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Ok { detail: String },
    Warn { detail: String },
    Err { detail: String },
}

#[derive(Debug, Clone)]
pub struct PrereqItem {
    pub name: String,
    pub outcome: Outcome,
    pub sub_bullets: Vec<String>,
    pub nested_bullets: bool,
}

/// Transient 429 cooldown notice rendered inside the live region while the
/// startup prerequisite retry loop (`Dumper::new`) waits out a `Retry-After`.
#[derive(Debug, Clone, Copy)]
struct ThrottleNotice {
    until: Instant,
    attempt: usize,
    max_attempts: usize,
}

/// Seconds left before `until`, rounded up so the countdown starts at the full
/// cooldown value and never displays a lingering `0s` while still waiting.
fn throttle_remaining_secs(until: Instant, now: Instant) -> u64 {
    let remaining = until.saturating_duration_since(now);
    remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0)
}

/// Renders the full prerequisites live region content.
/// `throttle` is `(remaining_secs, attempt, max_attempts)` when a 429 cooldown
/// is in progress.
fn render_prereq_banner(
    frame: u8,
    elapsed_str: &str,
    items: &[PrereqItem],
    throttle: Option<(u64, usize, usize)>,
) -> String {
    let mut lines = Vec::new();
    if mode() == UiMode::Color {
        lines.push(format!(
            "  {} {}",
            icon(Icon::Selected),
            blue("Prerequisites")
        ));
    }
    lines.push(format!(
        "  {}  Checking prerequisites (elapsed: {})",
        icon(Icon::Spinner(frame)),
        elapsed_str
    ));
    for item in items {
        lines.push(render_item_line(item).trim_end().to_string());
    }
    if let Some((remaining_secs, attempt, max_attempts)) = throttle {
        lines.push(warn_text(&format!(
            "    {}  Too many requests, retrying in {}s (attempt {}/{})",
            icon(Icon::Warn),
            remaining_secs,
            attempt,
            max_attempts
        )));
    }
    lines.join("\n")
}

pub struct PrereqLive {
    stop_flag: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    // Items reported so far (for the static spinner sub-lines).
    items: Arc<Mutex<Vec<PrereqItem>>>,
    // Active 429 cooldown notice, if any (rendered by the ticker).
    throttle: Arc<Mutex<Option<ThrottleNotice>>>,
    start: Instant,
}

impl Drop for PrereqLive {
    fn drop(&mut self) {
        // `finalize` calls `handle.take()`, leaving it `None`.
        // A `Some` handle here means we're being dropped in an error path without
        // `finalize` having run — stop the thread and clear the live region so the
        // spinner doesn't keep overwriting terminal output (e.g. a fatal error block).
        if self.handle.is_some() {
            self.stop_flag.store(true, Ordering::Relaxed);
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
            tear_down_live_region();
            update_live_region_state(LiveRegionState::None);
        }
    }
}

impl PrereqLive {
    /// Print the live spinner header and spawn the ticker thread.
    pub fn start() -> Self {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let items: Arc<Mutex<Vec<PrereqItem>>> = Arc::new(Mutex::new(Vec::new()));
        let throttle: Arc<Mutex<Option<ThrottleNotice>>> = Arc::new(Mutex::new(None));
        let start = Instant::now();

        let initial_text = render_prereq_banner(0, "00:00:00", &[], None);

        println!();
        println!();
        replace_live_region(&initial_text, false, |lines| LiveRegionState::Prereq {
            lines,
        });

        let stop = Arc::clone(&stop_flag);
        let items_clone = Arc::clone(&items);
        let throttle_clone = Arc::clone(&throttle);
        let mut frame: u8 = 0;

        let handle = thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(500));
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let now = Instant::now();
                let elapsed = now.duration_since(start);
                let elapsed_str = format!(
                    "{:02}:{:02}:{:02}",
                    elapsed.as_secs() / 3600,
                    (elapsed.as_secs() / 60) % 60,
                    elapsed.as_secs() % 60
                );
                frame = (frame + 1) % 8;

                let reported = lock_force(&items_clone).clone();
                let throttle_line = lock_force(&throttle_clone).map(|n| {
                    (
                        throttle_remaining_secs(n.until, now),
                        n.attempt,
                        n.max_attempts,
                    )
                });
                let text = render_prereq_banner(frame, &elapsed_str, &reported, throttle_line);

                replace_live_region(&text, true, |lines| LiveRegionState::Prereq { lines });
            }
        });

        PrereqLive {
            stop_flag,
            handle: Some(handle),
            items,
            throttle,
            start,
        }
    }

    /// Append a completed item under the spinner (will be redrawn on next tick).
    pub fn report(&mut self, item: PrereqItem) {
        let mut v = lock_force(&self.items);
        v.push(item);
    }

    /// Show a 429 cooldown countdown under the spinner (cleared with
    /// `clear_throttle_notice`). The live region must stay up across startup
    /// prerequisite retries: tearing it down and respawning it reprints the
    /// `start()` blank separator lines on every retry, shifting the display
    /// down — and the retry `warn!` is file-only outside the dump phase, so
    /// the operator would otherwise watch a blank screen during the cooldown.
    /// In NoColor mode the live region is never rendered, so print a static,
    /// append-only notice instead (same strategy as the auth banner).
    pub fn set_throttle_notice(&self, retry_after_secs: u64, attempt: usize, max_attempts: usize) {
        if mode() == UiMode::NoColor {
            println!(
                "    {}  Too many requests, retrying in {}s (attempt {}/{})",
                icon(Icon::Warn),
                retry_after_secs,
                attempt,
                max_attempts
            );
            return;
        }
        let now = Instant::now();
        // checked_add: `Instant + Duration` panics on overflow, and the
        // collection path must stay panic-free. Unreachable with a sane
        // `rateLimitMaxWaitSecs` clamp; degrade to an already-elapsed
        // countdown (0s) rather than aborting the run.
        let until = now
            .checked_add(Duration::from_secs(retry_after_secs))
            .unwrap_or(now);
        let mut t = lock_force(&self.throttle);
        *t = Some(ThrottleNotice {
            until,
            attempt,
            max_attempts,
        });
    }

    /// Remove the 429 cooldown notice (redrawn away on the next tick).
    pub fn clear_throttle_notice(&self) {
        let mut t = lock_force(&self.throttle);
        *t = None;
    }

    /// Stop the ticker, tear down the live region, and print the static summary.
    pub fn finalize(mut self, items: Vec<PrereqItem>) {
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }

        tear_down_live_region();
        update_live_region_state(LiveRegionState::None);

        let elapsed = Instant::now().duration_since(self.start);
        let elapsed_str = format!(
            "{:02}:{:02}:{:02}",
            elapsed.as_secs() / 3600,
            (elapsed.as_secs() / 60) % 60,
            elapsed.as_secs() % 60
        );

        // Cursor sits at the live region's first-line position after teardown.
        // The 2 blank lines above were printed as static output before the live
        // region started, so they persist and the white label lands at the same
        // screen position as the blue label.
        println!(
            "  {} Prerequisites   ({})",
            icon(Icon::Selected),
            dim(&elapsed_str)
        );

        for item in &items {
            println!("{}", render_item_full(item));
        }
    }
}

/// Prints a prerequisite failure banner during the dump phase.
///
/// Called by the background prereq re-check task when a mid-dump permission
/// check fails. Clears the progress region before calling this.
pub fn show_prereq_failure_ui(service: &str, error: &Error) {
    let line = match mode() {
        UiMode::Color => "──────────────────────────────────────────────────────────────────────",
        UiMode::NoColor => "--------------------------------------------------------------------",
    };
    println!(
        "\n  {} Prerequisite failure: {}",
        icon(Icon::Selected),
        service
    );
    println!("{}", line);
    let item = PrereqItem {
        name: service.to_string(),
        outcome: Outcome::Err {
            detail: error.to_string(),
        },
        sub_bullets: vec![],
        nested_bullets: false,
    };
    print!("{}", render_item_full(&item));
    for step in error.remediation_steps() {
        println!("       {}  {}", icon(Icon::Bullet), dim(step));
    }
    println!("{}", line);
}

/// Print the conditions summary block after the prerequisites section.
pub fn print_conditions_summary(conditions: &HashMap<String, bool>, disabled_count: usize) {
    // Ordered display: (condition key, display name)
    let ordered: [(&str, &str); 7] = [
        ("P1", "P1"),
        ("P2", "P2"),
        ("Intune", "Intune"),
        ("IsB2C", "B2C"),
        ("HasApplicationProxy", "AppProxy"),
        ("HasExchangeHybrid", "ExchangeHybrid"),
        ("HasADAdministration", "ADAdmin"),
    ];

    // In Color mode the "Conditions" label is already printed by StepLive::finalize,
    // so only add the blank line separator before the grid. In NoColor mode (where
    // StepLive is a no-op), print the full header as before.
    if mode() == UiMode::NoColor {
        println!("\n  {} Conditions", icon(Icon::Selected));
    }

    let render_item = |key: &str, display: &str| -> String {
        let val = conditions.get(key).copied().unwrap_or(false);
        match mode() {
            UiMode::Color => format!(
                "{}  {}",
                if val { success("✔") } else { err_text("✗") },
                display
            ),
            UiMode::NoColor => format!("{}  {}", if val { "[+]" } else { "[-]" }, display),
        }
    };

    // Row 1: P1, P2, Intune, B2C
    let row1: Vec<String> = ordered[..4]
        .iter()
        .map(|(k, d)| render_item(k, d))
        .collect();
    println!("    {}", row1.join("   "));

    // Row 2: AppProxy, ExchangeHybrid, ADAdmin
    let row2: Vec<String> = ordered[4..]
        .iter()
        .map(|(k, d)| render_item(k, d))
        .collect();
    println!("    {}", row2.join("   "));

    println!();

    if disabled_count > 0 {
        println!("    {} API(s) skipped by conditions", disabled_count);
        println!();
    }
}

/// Single-line rendering used inside the live spinner (compact, no sub-bullets).
fn render_item_line(item: &PrereqItem) -> String {
    let (icon_str, colorize): (String, fn(&str) -> String) = match &item.outcome {
        Outcome::Ok { .. } => (icon(Icon::Ok), |s: &str| success(s)),
        Outcome::Warn { .. } => (icon(Icon::Warn), |s: &str| warn_text(s)),
        Outcome::Err { .. } => (icon(Icon::Err), |s: &str| err_text(s)),
    };
    let detail = match &item.outcome {
        Outcome::Ok { detail } | Outcome::Warn { detail } | Outcome::Err { detail } => {
            detail.as_str()
        }
    };

    let left = format!("    {}  {}", icon_str, item.name);
    if detail.is_empty() {
        return format!("{}\n", left);
    }

    let left_len = left.chars().count();
    let separator = match mode() {
        UiMode::Color => " ─────── ",
        UiMode::NoColor => " ----- ",
    };
    let right_len = detail.chars().count();
    let space = if DETAIL_COL > left_len + right_len + separator.chars().count() {
        DETAIL_COL - left_len - separator.chars().count()
    } else {
        1
    };

    let line = format!("{}{}{}{}", left, " ".repeat(space), separator, detail);
    match mode() {
        UiMode::Color => format!("{}\n", colorize(&line)),
        UiMode::NoColor => format!("{}\n", line),
    }
}

/// Full rendering used in `finalize` — includes sub-bullets.
fn render_item_full(item: &PrereqItem) -> String {
    let mut out = render_item_line(item);
    // Strip trailing newline to append bullets cleanly
    if out.ends_with('\n') {
        out.pop();
    }
    let hierarchy = match mode() {
        UiMode::Color => "└─ ",
        UiMode::NoColor => "|-- ",
    };
    for (i, bullet) in item.sub_bullets.iter().enumerate() {
        let indent = if item.nested_bullets && i > 0 {
            "    "
        } else {
            ""
        };
        out.push_str(&format!("\n       {}{}{} ", indent, hierarchy, dim(bullet)));
    }
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_item(name: &str, detail: &str) -> PrereqItem {
        PrereqItem {
            name: name.to_string(),
            outcome: Outcome::Ok {
                detail: detail.to_string(),
            },
            sub_bullets: vec![],
            nested_bullets: false,
        }
    }

    fn warn_item(name: &str, detail: &str) -> PrereqItem {
        PrereqItem {
            name: name.to_string(),
            outcome: Outcome::Warn {
                detail: detail.to_string(),
            },
            sub_bullets: vec![],
            nested_bullets: false,
        }
    }

    fn err_item(name: &str, detail: &str) -> PrereqItem {
        PrereqItem {
            name: name.to_string(),
            outcome: Outcome::Err {
                detail: detail.to_string(),
            },
            sub_bullets: vec![],
            nested_bullets: false,
        }
    }

    #[test]
    fn render_all_ok() {
        let items = vec![
            ok_item("Graph API", "permissions verified"),
            ok_item("Subscription Reader role", "2 subscriptions"),
        ];
        // Just verify it doesn't panic and produces non-empty output.
        for item in &items {
            let line = render_item_full(item);
            assert!(!line.is_empty());
            assert!(line.contains(&item.name));
        }
    }

    #[test]
    fn render_mixed() {
        let mut sub_item = ok_item("Subscription Reader role", "2 subscriptions");
        sub_item.sub_bullets = vec!["Subscription1".to_string(), "Subscription2".to_string()];
        let full = render_item_full(&sub_item);
        assert!(full.contains("Subscription1"));
        assert!(full.contains("Subscription2"));
        assert!(full.contains("2 subscriptions"));
    }

    #[test]
    fn render_all_fail() {
        let items = [
            err_item("Graph API", "Missing permissions"),
            warn_item("Exchange Online", "Access denied (skipped)"),
        ];
        for item in &items {
            let line = render_item_full(item);
            assert!(line.contains(&item.name));
        }
    }

    #[test]
    fn render_banner_includes_throttle_notice() {
        // Substring assertions are mode-independent (no icon/colour checked) so
        // a concurrent test toggling the global UI mode cannot flake this one.
        let text = render_prereq_banner(0, "00:00:05", &[], Some((42, 1, 10)));
        assert!(text.contains("retrying in 42s"));
        assert!(text.contains("(attempt 1/10)"));

        let text = render_prereq_banner(0, "00:00:05", &[], None);
        assert!(!text.contains("retrying in"));
    }

    #[test]
    fn throttle_remaining_secs_rounds_up_and_saturates() {
        let now = Instant::now();
        // 41.5s left rounds up to 42 so the countdown opens at the full value.
        assert_eq!(
            throttle_remaining_secs(now + Duration::from_millis(41_500), now),
            42
        );
        // Exact whole seconds are not inflated.
        assert_eq!(
            throttle_remaining_secs(now + Duration::from_secs(10), now),
            10
        );
        // A deadline in the past shows 0, not an underflow.
        assert_eq!(
            throttle_remaining_secs(now, now + Duration::from_secs(5)),
            0
        );
    }

    #[test]
    fn conditions_summary_all_true() {
        let mut conditions = HashMap::new();
        for key in &[
            "P1",
            "P2",
            "Intune",
            "IsB2C",
            "HasApplicationProxy",
            "HasExchangeHybrid",
            "HasADAdministration",
        ] {
            conditions.insert(key.to_string(), true);
        }
        // Verify it doesn't panic with all-true conditions.
        print_conditions_summary(&conditions, 0);
    }

    #[test]
    fn conditions_summary_with_disabled() {
        let mut conditions = HashMap::new();
        conditions.insert("P1".to_string(), true);
        conditions.insert("IsB2C".to_string(), false);
        // Verify it doesn't panic with partial conditions and a disabled count.
        print_conditions_summary(&conditions, 3);
    }
}
