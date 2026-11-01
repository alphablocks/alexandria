#![cfg(windows)]
use alexandria_windows::{credentials, fs, hello, identity, monitor, pipe};
use std::{
    io::{Read, Write},
    sync::{atomic::AtomicBool, Arc},
};
#[test]
fn dpapi_roundtrip_tampering_and_private_files() {
    let d = tempfile::tempdir().unwrap();
    let dir = d.path().join("private");
    fs::private_dir(&dir).unwrap();
    assert!(fs::dacl_is_private(&dir).unwrap());
    let plain = b"synthetic-nonproduction-key-123456";
    let cipher = credentials::protect(plain).unwrap();
    assert!(!cipher.windows(plain.len()).any(|w| w == plain));
    assert_eq!(credentials::unprotect(&cipher).unwrap().as_slice(), plain);
    let mut bad = cipher.to_vec();
    let i = bad.len() / 2;
    bad[i] ^= 0x80;
    assert!(credentials::unprotect(&bad).is_err());
    let path = dir.join("test-key.dpapi");
    credentials::save_vault(&path, plain).unwrap();
    assert!(fs::dacl_is_private(&path).unwrap());
    assert_eq!(credentials::load_vault(&path).unwrap().as_slice(), plain);
    assert!(credentials::save_vault(&path, b"overwrite").is_err());
}
#[test]
fn credential_manager_has_separate_installation_entries() {
    let id = format!("test-{}-isolated", std::process::id());
    struct Cleanup(String);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = credentials::delete_connector(&self.0);
        }
    }
    let _cleanup = Cleanup(id.clone());
    credentials::set_connector(&id, b"synthetic-connector-only").unwrap();
    assert_eq!(
        credentials::connector(&id).unwrap().as_slice(),
        b"synthetic-connector-only"
    );
    assert!(credentials::connector(&(id.clone() + "-other")).is_err());
    credentials::delete_connector(&id).unwrap();
    assert!(credentials::connector(&id).is_err());
}
#[test]
fn local_named_pipe_request_and_duplicate_listener_rejected() {
    let mut listener = pipe::Listener::bind().unwrap();
    assert!(pipe::Listener::bind().is_err());
    let thread = std::thread::spawn(move || {
        let mut p = listener.accept().unwrap();
        let mut request = [0; 4];
        p.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"ping");
    });
    let mut client = pipe::Pipe::connect().unwrap();
    client.write_all(b"ping").unwrap();
    thread.join().unwrap();
}
#[test]
fn session_events_and_invalid_owner_window_fail_closed() {
    use windows_sys::Win32::UI::WindowsAndMessaging::*;
    assert!(monitor::is_lock_event(
        WM_WTSSESSION_CHANGE,
        WTS_SESSION_LOCK as usize
    ));
    assert!(monitor::is_lock_event(
        WM_POWERBROADCAST,
        PBT_APMSUSPEND as usize
    ));
    assert!(!monitor::is_lock_event(
        WM_WTSSESSION_CHANGE,
        WTS_SESSION_UNLOCK as usize
    ));
    let signals = monitor::Signals::new(Arc::new(AtomicBool::new(false)));
    assert!(!signals.ready.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        hello::verify_owner(0).unwrap_err().0,
        "OWNER_VERIFICATION_UNAVAILABLE"
    );
    assert!(identity::current_sid().unwrap().starts_with("S-1-"));
    assert!(identity::check_process(std::process::id()).is_ok());
}
