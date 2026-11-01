use crate::{check, wide, Result};
use std::{
    io::{Read, Write},
    path::Path,
    ptr,
};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::{Credentials::*, Cryptography::*},
};
use zeroize::{Zeroize, Zeroizing};
pub fn protect(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    crypt(bytes, false)
}
pub fn unprotect(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    crypt(bytes, true)
}
fn crypt(bytes: &[u8], decrypt: bool) -> Result<Zeroizing<Vec<u8>>> {
    check(!bytes.is_empty() && bytes.len() <= 16384, "INVALID_INPUT")?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr() as *mut u8,
    };
    let mut output: CRYPT_INTEGER_BLOB = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        if decrypt {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptProtectData(
                &input,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    check(ok != 0, "WINDOWS_SECURITY_ERROR")?;
    unsafe {
        let data = Zeroizing::new(
            std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec(),
        );
        std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize).zeroize();
        LocalFree(output.pbData.cast());
        Ok(data)
    }
}
pub fn save_vault(path: &Path, bytes: &[u8]) -> Result<()> {
    let encrypted = protect(bytes)?;
    let mut f = crate::fs::create_private(path)?;
    let result = (|| {
        f.write_all(&encrypted)?;
        f.sync_all()?;
        Ok(())
    })();
    drop(f);
    if result.is_err() {
        let _ = std::fs::remove_file(path);
    }
    result
}
/// Caller must verify native owner presence first. Not an IPC/adapter operation.
pub fn load_vault(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    crate::fs::reject_reparse(path)?;
    let mut bytes = Zeroizing::new(vec![]);
    std::fs::File::open(path)?
        .take(16385)
        .read_to_end(&mut bytes)?;
    check(bytes.len() <= 16384, "LIMIT_EXCEEDED")?;
    unprotect(&bytes)
}
fn target(cid: &str) -> Result<Vec<u16>> {
    check(
        !cid.is_empty()
            && cid.len() <= 128
            && cid.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "INVALID_INPUT",
    )?;
    Ok(wide(&format!("org.alexandria.vault/connector/{cid}")))
}
pub fn set_connector(cid: &str, bytes: &[u8]) -> Result<()> {
    check(!bytes.is_empty() && bytes.len() <= 512, "INVALID_INPUT")?;
    let target = target(cid)?;
    let mut c: CREDENTIALW = unsafe { std::mem::zeroed() };
    c.Type = CRED_TYPE_GENERIC;
    c.TargetName = target.as_ptr() as *mut _;
    c.Persist = CRED_PERSIST_LOCAL_MACHINE;
    c.CredentialBlob = bytes.as_ptr() as *mut u8;
    c.CredentialBlobSize = bytes.len() as u32;
    unsafe { check(CredWriteW(&c, 0) != 0, "WINDOWS_SECURITY_ERROR") }
}
pub fn connector(cid: &str) -> Result<Zeroizing<Vec<u8>>> {
    let target = target(cid)?;
    let mut c = ptr::null_mut();
    unsafe {
        check(
            CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut c) != 0,
            "DENIED",
        )?;
        let n = (*c).CredentialBlobSize as usize;
        if n == 0 || n > 512 {
            CredFree(c.cast());
            return Err(crate::Error("DENIED"));
        }
        let bytes = Zeroizing::new(std::slice::from_raw_parts((*c).CredentialBlob, n).to_vec());
        std::slice::from_raw_parts_mut((*c).CredentialBlob, n).zeroize();
        CredFree(c.cast());
        Ok(bytes)
    }
}
pub fn delete_connector(cid: &str) -> Result<()> {
    unsafe {
        check(
            CredDeleteW(target(cid)?.as_ptr(), CRED_TYPE_GENERIC, 0) != 0,
            "WINDOWS_SECURITY_ERROR",
        )
    }
}
