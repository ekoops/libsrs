use rustix::fs::{self, Dir, Mode, OFlags, Stat, CWD};
use std::ffi::CStr;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

/// Invokes `openat(2)` system call.
///
/// Arguments have the same semantic of the underlying system call. Returns the open file
/// descriptor.
///
/// # Errors
///
/// Returns an [`io::Error`] (sourced from errno) if the underlying `openat(2)` system call fails.
fn openat<Fd: AsFd>(fd: Fd, path: &CStr, flags: OFlags, mode: Mode) -> io::Result<OwnedFd> {
    fs::openat(fd, path, flags, mode).map_err(Into::into)
}

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

/// Directory entry.
pub struct DirEntry<'a> {
    fd: BorrowedFd<'a>,
    entry: fs::DirEntry,
}

/// Iterates over the entries of the directory at `path`, executing `process` for each entry.
///
/// Entries for the current and parent directories (typically `.` and `..`) are skipped.
///
/// The `process` closure can return an [io::Result] to handle errors or abort the iteration early.
pub fn scan_dir<P>(path: &CStr, mut process: P) -> io::Result<()>
where
    P: FnMut(&DirEntry<'_>) -> io::Result<()>,
{
    let dir_fd = openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    for dir_entry in Dir::read_from(dir_fd.as_fd())? {
        let dir_entry = dir_entry?;
        let name_bytes = dir_entry.file_name().to_bytes();
        if name_bytes == b"." || name_bytes == b".." {
            continue;
        }
        let dir_entry = DirEntry {
            fd: dir_fd.as_fd(),
            entry: dir_entry,
        };
        process(&dir_entry)?;
    }
    Ok(())
}
