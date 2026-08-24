// Generic step-label live region — shows the step name in blue with a spinner
// while the step runs, then tears down and prints the label in default color.
// Color mode only: in NoColor mode, start() returns a no-op stub.
use crate::utils::logger::{
    LiveRegionState, calculate_rendered_lines, redraw_live_region, tear_down_live_region,
    update_live_region_state, update_live_region_text,
};
use crate::utils::ui::{Icon, UiMode, blue, icon, mode};

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

struct StepLiveInner {
    stop_flag: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

pub struct StepLive {
    inner: Option<StepLiveInner>,
    label: String,
}

fn render_step(frame: u8, label: &str) -> String {
    format!("\n  {}  {}", icon(Icon::Spinner(frame)), blue(label))
}

impl Drop for StepLive {
    fn drop(&mut self) {
        if let Some(mut inner) = self.inner.take() {
            inner.stop_flag.store(true, Ordering::Relaxed);
            if let Some(h) = inner.handle.take() {
                let _ = h.join();
            }
            tear_down_live_region();
            update_live_region_state(LiveRegionState::None);
        }
    }
}

impl StepLive {
    /// Start a live step label. In Color mode, draws a blue spinning indicator and
    /// spawns a ticker thread. In NoColor mode, returns a no-op stub.
    pub fn start(label: &str) -> Self {
        if mode() != UiMode::Color {
            return Self {
                inner: None,
                label: label.to_string(),
            };
        }

        let stop_flag = Arc::new(AtomicBool::new(false));
        let initial_text = render_step(0, label);

        update_live_region_text(&initial_text);
        update_live_region_state(LiveRegionState::Step {
            lines: calculate_rendered_lines(&initial_text),
        });
        redraw_live_region(false);

        let stop = Arc::clone(&stop_flag);
        let label_clone = label.to_string();
        let mut frame: u8 = 0;

        let handle = thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(100));
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                frame = (frame + 1) % 8;
                let text = render_step(frame, &label_clone);
                update_live_region_text(&text);
                redraw_live_region(true);
                update_live_region_state(LiveRegionState::Step {
                    lines: calculate_rendered_lines(&text),
                });
            }
        });

        Self {
            inner: Some(StepLiveInner {
                stop_flag,
                handle: Some(handle),
            }),
            label: label.to_string(),
        }
    }

    /// Stop the ticker, tear down the live region, and print the label in default color.
    /// In NoColor mode this is a no-op.
    pub fn finalize(mut self) {
        if let Some(mut inner) = self.inner.take() {
            inner.stop_flag.store(true, Ordering::Relaxed);
            if let Some(h) = inner.handle.take() {
                let _ = h.join();
            }
            tear_down_live_region();
            update_live_region_state(LiveRegionState::None);
            println!("\n  {} {}", icon(Icon::Selected), self.label);
        }
    }
}
