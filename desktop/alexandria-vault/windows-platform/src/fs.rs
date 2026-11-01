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
    if !dacl_private_handle(&file)? {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(crate::Error("WINDOWS_SECURITY_ERROR"));
    }
    Ok(file)
}
pub fn dacl_is_private(path: &Path) -> Result<bool> {
    dacl_private_handle(&File::open(path)?)
}
fn dacl_private_handle(file: &File) -> Result<bool> {
    // Tests inspect the actual descriptor using a handle, not source-string matching.
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SE_FILE_OBJECT,
        },
    };
    let mut sd = ptr::null_mut();
    unsafe {
        check(
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut sd,
            ) == 0,
            "WINDOWS_SECURITY_ERROR",
        )?;
        let mut text = ptr::null_mut();
        let ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd,
            1,
            DACL_SECURITY_INFORMATION,
            &mut text,
            ptr::null_mut(),
        ) != 0;
        LocalFree(sd);
        check(ok, "WINDOWS_SECURITY_ERROR")?;
        let mut n = 0;
        while *text.add(n) != 0 {
            n += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(text, n));
        LocalFree(text.cast());
        Ok(s.contains(&crate::identity::current_sid()?)
            && !s.contains(";;;WD)")
            && !s.contains(";;;BU)")
            && !s.contains(";;;AU)")
            && s.matches("(A;").count() == 1)
    }
}
