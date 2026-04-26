use rustix::fs;
use rustix::fs::{Dir, Mode, OFlags, CWD};
use std::ffi::{CStr, OsStr};
use std::fs as std_fs;
use std::io;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::ffi::OsStrExt;

pub type File = std_fs::File;

/// Create a [File] for `path`.
///
/// `path` is the non-NUL-terminated binary string representation of a file path.
pub fn open(path: &[u8]) -> io::Result<File> {
    let path = OsStr::from_bytes(path);
    File::open(path)
}

/// Read the target of the symbolic link at `path` into `buff`, returning the strictly positive
/// number of bytes written.
///
/// This is a thin wrapper around `readlinkat(2)` system call. The result is **not**
/// null-terminated.
///
/// # Truncation
///
/// If the link target is longer than `buff.len()`, the target is silently truncated to fit. Callers
/// that need to detect truncation should check whether the returned length equals `buff.len()` and
/// retry with a larger buffer.
///
/// # Errors
///
/// Returns an [`io::Error`] (sourced from errno) if the underlying `readlinkat(2)` system call
/// fails (e.g. `path` does not exist, is not a symbolic link, `buff.len()` is zero, or a permission
/// error occurs).
pub fn readlinkat<Fd: AsFd>(fd: Fd, path: &CStr, buff: &mut [u8]) -> io::Result<usize> {
    fs::readlinkat_raw(fd, path, buff).map_err(Into::into)
}

/// Read the target of the symbolic link at `path` into `buff`, returning the strictly positive
/// number of bytes written.
///
/// This is a thin wrapper around `readlink(2)` system call. The result is **not** null-terminated.
///
/// # Truncation
///
/// If the link target is longer than `buff.len()`, the target is silently truncated to fit. Callers
/// that need to detect truncation should check whether the returned length equals `buff.len()` and
/// retry with a larger buffer.
///
/// # Errors
///
/// Returns an [`io::Error`] (sourced from errno) if the underlying `readlink(2)` system call fails
/// (e.g. `path` does not exist, is not a symbolic link, `buff.len()` is zero, or a permission error
/// occurs).
pub fn readlink(path: &CStr, buff: &mut [u8]) -> io::Result<usize> {
    readlinkat(CWD, path, buff)
}

pub type Metadata = std_fs::Metadata;

/// Return metadata associated with `path`.
///
/// `path` is the non-NUL-terminated binary string representation of a file path.
pub fn metadata(path: &[u8]) -> io::Result<Metadata> {
    let path = OsStr::from_bytes(path);
    std_fs::metadata(path)
}

pub struct DirEntry<'a> {
    fd: BorrowedFd<'a>,
    entry: fs::DirEntry,
}

impl<'a> DirEntry<'a> {
    pub fn resolve(&self, buff: &mut [u8]) -> io::Result<usize> {
        readlinkat(self.fd, self.entry.file_name(), buff)
    }
}

/// Iterate over the entries of the directory at `path`, executing `process` for each entry.
///
/// `path` is the non-NUL-terminated binary string representation of a directory path.
///
/// The `process` closure can return an [io::Result] to handle errors or abort the iteration
/// early.
pub fn scan_dir<P>(path: &[u8], mut process: P) -> io::Result<()>
where
    P: FnMut(&DirEntry<'_>) -> io::Result<()>,
{
    // todo(ekoops): passing path as &[u8] leads to allocation.
    let dir_fd = fs::openat(
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
