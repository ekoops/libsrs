use rustix::fs::{self, Stat};
use std::ffi::CStr;
use std::io;

/// File metadata.
pub struct Metadata(Stat);

/// Unix-specific extensions to [`Metadata`].
pub trait MetadataExt {
    /// Returns the inode number.
    fn ino(&self) -> u64;
}

impl MetadataExt for Metadata {
    fn ino(&self) -> u64 {
        self.0.st_ino
    }
}

/// Reads metadata associated with `path`.
pub fn read_metadata(path: &CStr) -> io::Result<Metadata> {
    let stat = fs::stat(path)?;
    Ok(Metadata(stat))
}
