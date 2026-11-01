//! Owner-only creation is atomic: no permissive create-then-chmod window.
use crate::{check, identity::Descriptor, Result};
use std::{
    fs::File,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Path, PathBuf},
    ptr,
};
use windows_sys::Win32::{
    Foundation::INVALID_HANDLE_VALUE,
    Security::{
        SetFileSecurityW, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION,
    },
    Storage::FileSystem::*,
};
fn path_wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}
pub fn reject_reparse(path: &Path) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    for component in path.ancestors() {
        if component.exists() {
            check(
                std::fs::symlink_metadata(component)?.file_attributes()
                    & FILE_ATTRIBUTE_REPARSE_POINT
                    == 0,
                "UNSAFE_PATH",
            )?;
        }
    }
    Ok(())
}
pub fn private_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        if let Some(parent) = path.parent() {
            check(parent.is_dir(), "UNSAFE_PATH")?;
            reject_reparse(parent)?;
        }
        let sd = Descriptor::owner_only(true)?;
        let sa = sd.attributes();
        unsafe {
            check(
                CreateDirectoryW(path_wide(path).as_ptr(), &sa) != 0,
                "IO_ERROR",
            )?;
        }
    }
    reject_reparse(path)?;
    check(path.is_dir(), "UNSAFE_PATH")?;
    let sd = Descriptor::owner_only(true)?;
    unsafe {
        check(
            SetFileSecurityW(
                path_wide(path).as_ptr(),
                DACL_SECURITY_INFORMATION
                    | OWNER_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION,
                sd.as_ptr(),
            ) != 0,
            "WINDOWS_SECURITY_ERROR",
        )?;
    }
    Ok(())
}
pub fn data_dir() -> Result<PathBuf> {
    // A shell-known-folder API, not an environment variable controlled by a caller.
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath, KF_FLAG_DEFAULT};
    let p = unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, KF_FLAG_DEFAULT, None)? };
    let value = unsafe { p.to_string() };
    unsafe {
        CoTaskMemFree(Some(p.0.cast()));
    }
    let path = PathBuf::from(value.map_err(|_| crate::Error("UNSAFE_PATH"))?).join("Alexandria");
    private_dir(&path)?;
    Ok(path)
}
pub fn create_private(path: &Path) -> Result<File> {
    if let Some(parent) = path.parent() {
        reject_reparse(parent)?;
    }
    let sd = Descriptor::owner_only(false)?;
    let sa = sd.attributes();
    let h = unsafe {
        CreateFileW(
            path_wide(path).as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            0,
            &sa,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    check(h != INVALID_HANDLE_VALUE, "IO_ERROR")?;
    let file = unsafe { File::from_raw_handle(h) };
    let private = match dacl_private_handle(&file) {
        Ok(value) => value,
        Err(error) => {
            drop(file);
            let _ = std::fs::remove_file(path);
            return Err(error);
        }
    };
    if !private {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(crate::Error("WINDOWS_SECURITY_ERROR"));
    }
    Ok(file)
}
pub fn dacl_is_private(path: &Path) -> Result<bool> {
    use std::os::windows::fs::OpenOptionsExt;
    reject_reparse(path)?;
    // Opening a directory for descriptor inspection requires backup semantics.
    // This flag permits opening directories; it does not enable a privilege.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .access_mode(READ_CONTROL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    dacl_private_handle(&file)
}
fn dacl_private_handle(file: &File) -> Result<bool> {
    // Compare binary SIDs and ACEs, not SDDL text. Windows serializes some
    // account SIDs as aliases (e.g. LA); string matching rejects valid owners.
    use windows_sys::Win32::{
        Foundation::{LocalFree, GENERIC_ALL},
        Security::{
            Authorization::{ConvertStringSidToSidW, GetSecurityInfo, SE_FILE_OBJECT},
            *,
        },
        System::SystemServices::ACCESS_ALLOWED_ACE_TYPE,
    };
    let mut sd = ptr::null_mut();
    unsafe {
        check(
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut sd,
            ) == 0,
            "WINDOWS_DACL_READ_ERROR",
        )?;
        let result = (|| {
            let mut owner = ptr::null_mut();
            let mut defaulted = 0;
            check(
                GetSecurityDescriptorOwner(sd, &mut owner, &mut defaulted) != 0,
                "WINDOWS_DACL_READ_ERROR",
            )?;
            let mut control = 0;
            let mut revision = 0;
            check(
                GetSecurityDescriptorControl(sd, &mut control, &mut revision) != 0,
                "WINDOWS_DACL_READ_ERROR",
            )?;
            let mut present = 0;
            let mut acl = ptr::null_mut();
            check(
                GetSecurityDescriptorDacl(sd, &mut present, &mut acl, &mut defaulted) != 0,
                "WINDOWS_DACL_READ_ERROR",
            )?;
            if present == 0 || acl.is_null() || owner.is_null() || control & SE_DACL_PROTECTED == 0
            {
                return Ok(false);
            }
            let mut info: ACL_SIZE_INFORMATION = std::mem::zeroed();
            check(
                GetAclInformation(
                    acl,
                    (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                    std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                ) != 0,
                "WINDOWS_DACL_READ_ERROR",
            )?;
            if info.AceCount != 1 {
                return Ok(false);
            }
            let mut ace = ptr::null_mut();
            check(GetAce(acl, 0, &mut ace) != 0, "WINDOWS_DACL_READ_ERROR")?;
            let header = &*(ace as *const ACE_HEADER);
            let offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
            if header.AceType as u32 != ACCESS_ALLOWED_ACE_TYPE
                || header.AceFlags as u32 & INHERITED_ACE != 0
                || (header.AceSize as usize) < offset + 8
            {
                return Ok(false);
            }
            let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
            if allowed.Mask != FILE_ALL_ACCESS && allowed.Mask != GENERIC_ALL {
                return Ok(false);
            }
            let sid = (ace as *const u8).add(offset) as *mut std::ffi::c_void;
            if IsValidSid(sid) == 0
                || IsValidSid(owner) == 0
                || GetLengthSid(sid) as usize > header.AceSize as usize - offset
                || EqualSid(sid, owner) == 0
            {
                return Ok(false);
            }
            let mut expected = ptr::null_mut();
            check(
                ConvertStringSidToSidW(
                    crate::wide(&crate::identity::current_sid()?).as_ptr(),
                    &mut expected,
                ) != 0,
                "WINDOWS_DACL_READ_ERROR",
            )?;
            let matches = EqualSid(sid, expected) != 0;
            LocalFree(expected);
            Ok(matches)
        })();
        LocalFree(sd);
        result
    }
}
