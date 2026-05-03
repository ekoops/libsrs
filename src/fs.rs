use rustix::fs::{self, AtFlags, Dir, Mode, OFlags, Stat, CWD};
use std::ffi::CStr;
use std::fs as std_fs;
use std::io;
use std::io::Read;
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

/// Invokes `readlinkat(2)` system call.
///
/// Arguments have the same semantic of the underlying system call. Returns the strictly positive
/// number of bytes written.
///
/// # Errors
///
/// Returns an [`io::Error`] (sourced from errno) if the underlying `readlinkat(2)` system call
/// fails.
fn readlinkat<Fd: AsFd>(fd: Fd, path: &CStr, buff: &mut [u8]) -> io::Result<usize> {
    fs::readlinkat_raw(fd, path, buff).map_err(Into::into)
}

/// Invokes `fstatat(2)` system call.
///
/// Arguments have the same semantic of the underlying system call. Returns information about a
/// file.
///
/// # Errors
///
/// Returns an [`io::Error`] (sourced from errno) if the underlying `fstatat(2)` system call fails.
fn fstatat<Fd: AsFd>(fd: Fd, path: &CStr, flags: AtFlags) -> io::Result<Stat> {
    fs::statat(fd, path, flags).map_err(Into::into)
}

/// Reads the target of the symbolic link at `path` into `buff`, returning the strictly positive
/// number of bytes written.
///
/// The result is not NUL-terminated. If the link target is longer than `buff.len()`, the target is
/// silently truncated to fit.
///
/// If `path` is relative, it is assumed relative to the current working directory. An empty `path`
/// results in an error.
pub fn read_symlink_target(path: &CStr, buff: &mut [u8]) -> io::Result<usize> {
    readlinkat(CWD, path, buff)
}

/// An object providing access to an open file on the filesystem.
pub struct File(std_fs::File);

impl Read for File {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

/// Creates a read-only [File] for `path`.
///
/// If `path` is relative, it is assumed relative to the current working directory. An empty `path`
/// results in an error.
pub fn open_file_rdonly(path: &CStr) -> io::Result<File> {
    let fd = openat(CWD, path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())?;
    Ok(File(std_fs::File::from(fd)))
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
///
/// If `path` is relative, it is assumed relative to the current working directory. An empty `path`
/// results in an error.
pub fn read_metadata(path: &CStr) -> io::Result<Metadata> {
    let stat = fstatat(CWD, path, AtFlags::empty())?;
    Ok(Metadata(stat))
}

/// Directory entry.
pub struct DirEntry<'a> {
    fd: BorrowedFd<'a>,
    entry: fs::DirEntry,
}

impl<'a> DirEntry<'a> {
    /// Reads the target of the symbolic link into `buff`, returning the strictly positive number of
    /// bytes written.
    ///
    /// The result is not NUL-terminated. If the link target is longer than `buff.len()`, the target
    /// is silently truncated to fit. The user must ensure that the directory entry is a symbolic
    /// link.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying system call fails (including invocation on a directory
    /// entry that is not a symbolic link).
    pub fn read_symlink_target(&self, buff: &mut [u8]) -> io::Result<usize> {
        readlinkat(self.fd, self.entry.file_name(), buff)
    }
}

/// Iterates over the entries of the directory at `path`, executing `process` for each entry.
///
/// If `path` is relative, it is assumed relative to the current working directory. An empty `path`
/// results in an error.
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
