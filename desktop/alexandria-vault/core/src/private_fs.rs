use crate::model::*;
use std::{fs::File, path::Path};
pub fn create_private(path: &Path) -> Result<File> {
    #[cfg(windows)]
    {
        Ok(alexandria_windows::fs::create_private(path)?)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        Ok(std::fs::OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?)
    }
}
