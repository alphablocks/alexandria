fn main() {
    #[cfg(any(target_os = "macos", windows))]
    tauri_build::build();
}
