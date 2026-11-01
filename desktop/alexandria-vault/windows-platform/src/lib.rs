//! Windows trust boundary. No dependency on the vault/database or renderer.
#![cfg(windows)]
pub mod credentials;
pub mod fs;
pub mod hello;
pub mod identity;
pub mod monitor;
pub mod pipe;
use std::fmt;
#[derive(Debug)]
pub struct Error(pub &'static str);
pub type Result<T> = std::result::Result<T, Error>;
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self("IO_ERROR")
    }
}
impl From<windows::core::Error> for Error {
    fn from(_: windows::core::Error) -> Self {
        Self("WINDOWS_SECURITY_ERROR")
    }
}
pub(crate) fn check(ok: bool, code: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error(code))
    }
}
pub(crate) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
