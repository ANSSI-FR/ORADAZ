#[cfg(windows)]
pub fn enable_vt_processing() {
    // Enable Virtual Terminal processing so ANSI escape sequences work on Windows consoles,
    // via the Win32 API exposed by the `windows-sys` crate. The UI and logs write to stdout,
    // but the logger's error/fatal fallbacks emit coloured ANSI to stderr — a separate console
    // handle with its own mode — so both handles are enabled.
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Console::{
        ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode, GetStdHandle, STD_ERROR_HANDLE,
        STD_OUTPUT_HANDLE, SetConsoleMode,
    };

    unsafe {
        for std_handle in [STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            let handle = GetStdHandle(std_handle);
            if handle == INVALID_HANDLE_VALUE {
                continue;
            }
            let mut mode = 0;
            if GetConsoleMode(handle, &mut mode) == 0 {
                continue;
            }
            // Add the VT flag while preserving existing mode bits.
            let _ = SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }
}

#[cfg(not(windows))]
pub fn enable_vt_processing() {
    // No-op on non-Windows platforms.
}
