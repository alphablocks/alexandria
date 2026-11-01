#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
#[cfg(any(target_os = "macos", windows))]
mod app;
#[cfg(any(target_os = "macos", windows))]
mod platform;
fn main() {
    #[cfg(any(target_os = "macos", windows))]
    app::run();
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        eprintln!("Native vault targets Windows and macOS. Run core tests here; no plaintext fallback is provided.");
        std::process::exit(1);
    }
}
