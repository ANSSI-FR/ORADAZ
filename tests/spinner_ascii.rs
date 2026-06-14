// Test that the spinner displays ASCII frames in NoColor mode.

use oradaz::utils::ui::theme::{self, Icon, icon};

#[test]
fn spinner_ascii_frames_no_color() {
    // Force NoColor mode for the duration of the test.
    theme::force_no_color();

    let expected = ["|", "/", "-", "\\", "|", "/", "-", "\\"]; // two cycles
    for (i, &exp) in expected.iter().enumerate() {
        let frame = icon(Icon::Spinner(i as u8));
        assert_eq!(frame, exp, "spinner frame {} mismatch", i);
    }
}
