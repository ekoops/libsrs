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

/// Represents a file system location.
#[derive(Debug, Copy, Clone)]
pub struct Location<'fd, 'path> {
    fd: BorrowedFd<'fd>,
    path: &'path CStr,
}

impl<'fd, 'path> Location<'fd, 'path> {
    /// Creates a new location from `path`. If `path` is relative, it is assumed relative to the
    /// current working directory.
    pub fn new(path: &'path CStr) -> Self {
        Self { fd: CWD, path }
    }

    /// Creates a new location from `fd` and `path`. If path is absolute, `fd` is ignored by any
    /// operation using this location.
    pub fn new_with_fd(fd: BorrowedFd<'fd>, path: &'path CStr) -> Self {
        Self { fd, path }
    }

    /// Returns the location's file descriptor.
    pub fn fd(&self) -> BorrowedFd<'fd> {
        self.fd
    }

    /// Returns the location's path.
    pub fn path(&self) -> &'path CStr {
        self.path
    }
}

/// Reads the target of the symbolic link at `loc` into `buff`, returning the strictly positive
/// number of bytes written.
///
/// The result is not NUL-terminated. If the link target is longer than `buff.len()`, the target is
/// silently truncated to fit.
pub fn read_symlink_target(loc: Location<'_, '_>, buff: &mut [u8]) -> io::Result<usize> {
    readlinkat(loc.fd, loc.path, buff)
}

/// An object providing access to an open file on the filesystem.
pub struct File(std_fs::File);

impl Read for File {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

/// Creates a read-only [File] for `loc`.
pub fn open_file_rdonly(loc: Location<'_, '_>) -> io::Result<File> {
    let fd = openat(
        loc.fd,
        loc.path,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    Ok(File(std_fs::File::from(fd)))
}

/// File type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileType {
    RegularFile,
    Directory,
    Symlink,
    Fifo,
    Socket,
    CharacterDevice,
    BlockDevice,
    Unknown,
}

impl From<fs::FileType> for FileType {
    fn from(value: fs::FileType) -> Self {
        match value {
            fs::FileType::RegularFile => FileType::RegularFile,
            fs::FileType::Directory => FileType::Directory,
            fs::FileType::Symlink => FileType::Symlink,
            fs::FileType::Fifo => FileType::Fifo,
            fs::FileType::Socket => FileType::Socket,
            fs::FileType::CharacterDevice => FileType::CharacterDevice,
            fs::FileType::BlockDevice => FileType::BlockDevice,
            _ => FileType::Unknown,
        }
    }
}

impl From<fs::RawMode> for FileType {
    fn from(value: fs::RawMode) -> Self {
        fs::FileType::from_raw_mode(value).into()
    }
}

/// File metadata.
pub struct Metadata(Stat);

/// Unix-specific extensions to [`Metadata`].
pub trait MetadataExt {
    /// Returns the inode number.
    fn ino(&self) -> u64;
    /// Returns the file type.
    fn file_type(&self) -> FileType;
}

impl MetadataExt for Metadata {
    fn ino(&self) -> u64 {
        self.0.st_ino
    }

    fn file_type(&self) -> FileType {
        self.0.st_mode.into()
    }
}

/// Reads metadata associated with `path`.
pub fn read_metadata(loc: Location<'_, '_>) -> io::Result<Metadata> {
    let stat = fstatat(loc.fd, loc.path, AtFlags::empty())?;
    Ok(Metadata(stat))
}

/// Directory entry.
pub struct DirEntry<'a> {
    fd: BorrowedFd<'a>,
    entry: fs::DirEntry,
}

impl<'a> DirEntry<'a> {
    /// Returns the file name of this directory entry.
    pub fn file_name(&self) -> &CStr {
        self.entry.file_name()
    }

    /// Returns the inode number.
    pub fn ino(&self) -> u64 {
        self.entry.ino()
    }

    fn location(&self) -> Location<'_, '_> {
        Location::new_with_fd(self.fd, self.entry.file_name())
    }

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
        let loc = self.location();
        read_symlink_target(loc, buff)
    }

    /// Reads the metadata of this directory entry.
    fn read_metadata(&self) -> io::Result<Metadata> {
        let loc = self.location();
        read_metadata(loc)
    }

    /// Reads the file type of this directory entry.
    pub fn read_file_type(&self) -> io::Result<FileType> {
        Ok(match self.entry.file_type().into() {
            FileType::Unknown => self.read_metadata()?.file_type(),
            ft => ft,
        })
    }
}

/// Iterates over the entries of the directory at `path`, executing `process` for each entry.
///
/// Entries for the current and parent directories (typically `.` and `..`) are skipped.
///
/// The `process` closure can return an [io::Result] to handle errors or abort the iteration early.
pub fn scan_dir<P>(loc: Location<'_, '_>, mut process: P) -> io::Result<()>
where
    P: FnMut(&DirEntry<'_>) -> io::Result<()>,
{
    let dir_fd = openat(
        loc.fd,
        loc.path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    for dir_entry in Dir::read_from(dir_fd.as_fd())? {
        // todo(ekoops): maybe we should continue on error...?
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
