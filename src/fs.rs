use rustix::fs::{self, Dir, Mode, OFlags, Stat, CWD};
use std::ffi::CStr;
use std::fs as std_fs;
use std::io;
use std::os::fd::{AsFd, BorrowedFd};

pub type File = std_fs::File;

/// Create a [File] for `path`.
///
/// The file is opened read-only.
pub fn open_rd(path: &CStr) -> io::Result<File> {
    let fd = fs::open(path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())?;
    Ok(File::from(fd))
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

/// Return metadata associated with `path`.
pub fn metadata(path: &CStr) -> io::Result<Metadata> {
    let stat = fs::stat(path)?;
    Ok(Metadata(stat))
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
