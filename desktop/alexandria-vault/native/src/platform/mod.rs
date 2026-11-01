#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::Platform;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::Platform;
