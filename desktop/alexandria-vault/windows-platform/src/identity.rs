use crate::{check, wide, Error, Result};
use std::{ffi::c_void, ptr};
use windows_sys::Win32::{
    Foundation::{CloseHandle, LocalFree, HANDLE},
    Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    },
    Security::{GetTokenInformation, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER},
    System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    },
};

/// A local allocation holding an absolute/relative Windows security descriptor.
pub struct Descriptor(*mut c_void);
impl Descriptor {
    pub fn owner_only(inherit: bool) -> Result<Self> {
        let sid = current_sid()?;
        let flags = if inherit { "OICI" } else { "" };
        // Protected DACL: no inherited Everyone/Users/Administrators entries.
        let text = wide(&format!("O:{sid}D:P(A;{flags};GA;;;{sid})"));
        let mut p = ptr::null_mut();
        unsafe {
            check(
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    1,
                    &mut p,
                    ptr::null_mut(),
                ) != 0,
                "WINDOWS_SECURITY_ERROR",
            )?;
        }
        Ok(Self(p))
    }
    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }
    pub fn as_ptr(&self) -> *mut c_void {
        self.0
    }
}
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn process_sid(process: HANDLE) -> Result<String> {
    unsafe {
        let mut token = ptr::null_mut();
        check(
            OpenProcessToken(process, TOKEN_QUERY, &mut token) != 0,
            "DENIED",
        )?;
        let result = (|| {
            let mut size = 0;
            GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut size);
            check(size > 0 && size <= 65536, "DENIED")?;
            let mut buf = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
            check(
                GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), size, &mut size)
                    != 0,
                "DENIED",
            )?;
            let user = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut text = ptr::null_mut();
            check(
                ConvertSidToStringSidW(user.User.Sid, &mut text) != 0,
                "DENIED",
            )?;
            let mut len = 0;
            while *text.add(len) != 0 && len < 256 {
                len += 1;
            }
            let sid = String::from_utf16(std::slice::from_raw_parts(text, len))
                .map_err(|_| Error("DENIED"));
            LocalFree(text.cast());
            sid
        })();
        CloseHandle(token);
        result
    }
}
pub fn current_sid() -> Result<String> {
    unsafe { process_sid(GetCurrentProcess()) }
}
pub fn check_process(pid: u32) -> Result<()> {
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        check(!process.is_null(), "DENIED")?;
        let other = process_sid(process);
        CloseHandle(process);
        check(other? == current_sid()?, "DENIED")
    }
}
