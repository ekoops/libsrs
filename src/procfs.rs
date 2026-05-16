use crate::buffer_writer::FromBufferWriter;
use crate::fs::{self, DirEntry, File, Location, Metadata, MetadataExt};
use crate::read::LineProcessor;
use crate::task::{Cmdline, Comm, Environ, OsPath};
use crate::{parse, read, write};
use lexical_core::FormattedSize;
use std::ffi::{CStr, CString, NulError, OsString};
use std::io;
use std::num::NonZeroU32;
use std::ops::ControlFlow;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use thiserror::Error;

/// Error returned by [MountPath::new].
#[derive(Debug, Clone, Error)]
pub enum MountPathError {
    #[error("procfs mount path too long (greater than {})", MountPath::MAX_LEN)]
    TooLong,
    #[error("procfs mount path cannot be empty")]
    Empty,
    #[error(transparent)]
    NulError(#[from] NulError),
}

/// A procfs mount path with a max length of [MountPath::MAX_LEN].
#[derive(Debug)]
pub struct MountPath(CString);

impl MountPath {
    /// Max allowed procfs mount path length.
    pub const MAX_LEN: usize = 256;

    /// Creates a new [MountPath] from `path`.
    pub fn new(path: OsString) -> Result<Self, MountPathError> {
        let mut path_bytes = path.as_bytes();
        if path_bytes.is_empty() {
            return Err(MountPathError::Empty);
        }

        if path_bytes.last() == Some(&b'/') {
            path_bytes = &path_bytes[..path_bytes.len() - 1];
        }
        if path_bytes.len() > Self::MAX_LEN {
            Err(MountPathError::TooLong)
        } else {
            Ok(Self(CString::new(path_bytes)?))
        }
    }
}

/// An abstraction for filesystem accesses required by [Procfs].
///
/// This allows to easily mock file system accesses in tests.
pub trait Driver {
    type DirHandle;
    type Reader: io::Read;
    type Metadata: MetadataExt;
    type DirEntry<'a>;

    /// Creates a [Self::DirHandle] for `dir_handle` + `path`.
    fn open_dir(
        &self,
        dir_handle: Option<&Self::DirHandle>,
        path: &CStr,
    ) -> io::Result<Self::DirHandle>;

    /// Creates a [Self::Reader] for `dir_handle` + `path`.
    fn open(&self, dir_handle: Option<&Self::DirHandle>, path: &CStr) -> io::Result<Self::Reader>;

    /// Reads the content of the symbolic link at `dir_handle` + `path` and stores it in `buff`.
    ///
    /// Returns the number of bytes read.
    fn read_symlink(
        &self,
        dir_handle: Option<&Self::DirHandle>,
        path: &CStr,
        buff: &mut [u8],
    ) -> io::Result<usize>;

    /// Reads metadata associated with `dir_handle` + `path`.
    fn read_metadata(
        &self,
        dir_handle: Option<&Self::DirHandle>,
        path: &CStr,
    ) -> io::Result<Self::Metadata>;

    /// Iterates over the entries of the directory at `dir_handle` + `path`, executing `process` for
    /// each entry but `.` and `..`.
    ///
    /// The `process` closure can return an [io::Result] to handle errors or abort the iteration
    /// early.
    fn scan_dir<P>(
        &self,
        dir_handle: Option<&Self::DirHandle>,
        path: &CStr,
        process: P,
    ) -> io::Result<()>
    where
        P: FnMut(&Self::DirEntry<'_>) -> io::Result<()>;
}

/// The canonical [Driver] implementation.
pub struct RealDriver;

impl RealDriver {
    /// Creates a new file system location from the provided `dir_handle` (if any) and `path`.
    fn new_location<'fd, 'path>(
        dir_handle: Option<&'fd OwnedFd>,
        path: &'path CStr,
    ) -> Location<'fd, 'path> {
        match dir_handle {
            Some(fd) => Location::new_with_fd(fd.as_fd(), path),
            None => Location::new(path),
        }
    }
}

impl Driver for RealDriver {
    type DirHandle = OwnedFd;
    type Reader = File;
    type Metadata = Metadata;
    type DirEntry<'a> = DirEntry<'a>;

    #[inline(always)]
    fn open_dir(&self, dir_handle: Option<&OwnedFd>, path: &CStr) -> io::Result<OwnedFd> {
        let loc = Self::new_location(dir_handle, path);
        fs::open_dir_for_traversal(loc)
    }

    #[inline(always)]
    fn open(&self, dir_handle: Option<&OwnedFd>, path: &CStr) -> io::Result<File> {
        let loc = Self::new_location(dir_handle, path);
        fs::open_file_rdonly(loc)
    }

    #[inline(always)]
    fn read_symlink(
        &self,
        dir_handle: Option<&OwnedFd>,
        path: &CStr,
        buff: &mut [u8],
    ) -> io::Result<usize> {
        let loc = Self::new_location(dir_handle, path);
        fs::read_symlink_target(loc, buff)
    }

    #[inline(always)]
    fn read_metadata(&self, dir_handle: Option<&OwnedFd>, path: &CStr) -> io::Result<Metadata> {
        let loc = Self::new_location(dir_handle, path);
        fs::read_metadata(loc)
    }

    #[inline(always)]
    fn scan_dir<P>(&self, dir_handle: Option<&OwnedFd>, path: &CStr, process: P) -> io::Result<()>
    where
        P: FnMut(&DirEntry<'_>) -> io::Result<()>,
    {
        let loc = Self::new_location(dir_handle, path);
        fs::scan_dir(loc, process)
    }
}

/// A helper type allowing to extract data from procfs. If unspecified, it leverages [RealDriver]
/// for filesystem accesses.
#[derive(Debug)]
pub struct Procfs<D: Driver = RealDriver> {
    mount_path: MountPath,
    driver: D,
}

impl Procfs<RealDriver> {
    /// Creates a new [Procfs] instance from the specified procfs `mount_path`.
    pub fn new(mount_path: MountPath) -> Self {
        Self {
            mount_path,
            driver: RealDriver,
        }
    }
}

// note: the following constants are defined outside the impl block because Rust doesn't allow to
// use constants defined in a generic impl block.

/// Max length of the string representation of `<pid>`.
const MAX_PID_LEN: usize = u32::FORMATTED_SIZE_DECIMAL;
/// Max allowed length for a suffix after `<procfs_mount_path>/<pid>/` (see [PATH_BUFF_SIZE]).
const MAX_SUFFIX_LEN: usize = 32;
/// Safety margin accounting for `/`s and trailing zeros in procfs path (see [PATH_BUFF_SIZE]).
const PADDING: usize = 16;
/// The size of the buffer used to construct procfs file paths. The buffer content is structured
/// in the following way: `<procfs_mount_path>/<pid>/<suffix><zero_pad>`.
const PATH_BUFF_SIZE: usize = MountPath::MAX_LEN + MAX_PID_LEN + MAX_SUFFIX_LEN + PADDING;

impl<D: Driver> Procfs<D> {
    /// Creates a new [Procfs] instance from the specified procfs `mount_path` leveraging the
    /// specified `driver` to perform file system accesses.
    pub fn new_with_driver(mount_path: MountPath, driver: D) -> Self {
        Self { mount_path, driver }
    }

    /// Creates a new path buffer that can be used to build a path.
    #[inline]
    fn new_path_buff() -> [u8; PATH_BUFF_SIZE] {
        [0u8; PATH_BUFF_SIZE]
    }

    /// Writes the mount path, `pid` and `filename` into `buff`, separating them with `/`s, and
    /// and returns a [CStr] view of it.
    fn write_proc_file_path<'a>(
        &self,
        path_buff: &'a mut [u8],
        pid: u32,
        suffix: &CStr,
    ) -> &'a CStr {
        let buff = &mut &mut path_buff[..];
        let mut written_bytes = write::next_bytes(buff, self.mount_path.0.to_bytes());
        written_bytes += write::next_bytes(buff, b"/");
        written_bytes += write::next_dec(buff, pid);
        written_bytes += write::next_bytes(buff, b"/");
        written_bytes += write::next_bytes(buff, suffix.to_bytes_with_nul());
        // SAFETY: write::next_bytes(buff, filename.to_bytes_with_nul()) guarantees that a trailing
        // NUL byte is written into the buffer.
        unsafe { CStr::from_bytes_with_nul_unchecked(&path_buff[..written_bytes]) }
    }

    /// Opens the `<procfs_mount_path>/<pid>` process' procfs subtree and returns a [ProcView] of
    /// it.
    ///
    /// Use [Self::proc_ref] if you need to perform just a single operation on a subtree.
    pub fn open_proc(&self, pid: NonZeroU32) -> io::Result<ProcView<'_, D>> {
        let mut path_buff = Self::new_path_buff();
        let path = self.write_proc_file_path(&mut path_buff, pid.get(), c"");
        let dir_handle = self.driver.open_dir(None, path)?;
        Ok(ProcView {
            procfs: self,
            proc_ref: ProcRef::Anchored(dir_handle),
        })
    }

    /// Returns a [ProcView] that references the `<procfs_mount_path>/<pid>` process' procfs
    /// subtree.
    ///
    /// Use [Self::open_proc] if you need to perform multiple operations on the same subtree.
    pub fn proc_ref(&self, pid: NonZeroU32) -> ProcView<'_, D> {
        ProcView {
            procfs: self,
            proc_ref: ProcRef::Pid(pid),
        }
    }

    /// Creates a reader for the `path`.
    ///
    /// `path` is relative to the process' procfs subtree identified by `proc_ref`.
    fn open(&self, proc_ref: &ProcRef<D::DirHandle>, path: &CStr) -> io::Result<D::Reader> {
        match proc_ref {
            ProcRef::Pid(pid) => {
                let mut path_buff = Self::new_path_buff();
                let path = self.write_proc_file_path(&mut path_buff, pid.get(), path);
                self.driver.open(None, path)
            }
            ProcRef::Anchored(fd) => self.driver.open(Some(fd), path),
        }
    }

    /// Returns metadata associated with `path`.
    ///
    /// `path` is relative to the process' procfs subtree identified by `proc_ref`.
    fn read_metadata(
        &self,
        proc_ref: &ProcRef<D::DirHandle>,
        path: &CStr,
    ) -> io::Result<D::Metadata> {
        match proc_ref {
            ProcRef::Pid(pid) => {
                let mut path_buff = Self::new_path_buff();
                let path = self.write_proc_file_path(&mut path_buff, pid.get(), path);
                self.driver.read_metadata(None, path)
            }
            ProcRef::Anchored(fd) => self.driver.read_metadata(Some(fd), path),
        }
    }

    /// Returns the content of the symbolic link `path`.
    ///
    /// `path` is relative to the process' procfs subtree identified by `proc_ref`.
    fn read_symlink(&self, proc_ref: &ProcRef<D::DirHandle>, path: &CStr) -> io::Result<OsPath> {
        OsPath::from_buffer_writer(|buff: &mut [u8]| -> io::Result<usize> {
            match proc_ref {
                ProcRef::Pid(pid) => {
                    let mut path_buff = Self::new_path_buff();
                    let path = self.write_proc_file_path(&mut path_buff, pid.get(), path);
                    self.driver.read_symlink(None, path, buff)
                }
                ProcRef::Anchored(fd) => self.driver.read_symlink(Some(fd), path, buff),
            }
        })
    }

    /// Iterates over the entries in `path`, invoking `process` for each of them.
    ///
    /// `path` is relative to the process' procfs subtree identified by `proc_ref`.
    /// `process` is not invoked for `.` and `..` entries.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be opened or if the callback returns an error.
    fn scan_dir<P>(
        &self,
        proc_ref: &ProcRef<D::DirHandle>,
        path: &CStr,
        process: P,
    ) -> io::Result<()>
    where
        P: FnMut(&D::DirEntry<'_>) -> io::Result<()>,
    {
        match proc_ref {
            ProcRef::Pid(pid) => {
                let mut path_buff = Self::new_path_buff();
                let path = self.write_proc_file_path(&mut path_buff, pid.get(), path);
                self.driver.scan_dir(None, path, process)
            }
            ProcRef::Anchored(fd) => self.driver.scan_dir(Some(fd), path, process),
        }
    }
}

/// A reference to a `<procfs_mount_path>/<pid>` process' procfs subtree.
#[derive(Debug)]
enum ProcRef<A> {
    Pid(NonZeroU32),
    Anchored(A),
}

/// A view of a `<procfs_mount_path>/<pid>` process' procfs subtree, allowing to extract information
/// from it.
#[derive(Debug)]
pub struct ProcView<'procfs, D: Driver> {
    procfs: &'procfs Procfs<D>,
    proc_ref: ProcRef<D::DirHandle>,
}

// note: the following constants are defined outside the impl block because Rust doesn't allow to
// use constants defined in a generic impl block.

/// The size of the stack-allocated scratch buffer used to read the content of status files (i.e.:
/// `<procfs_mount_path>/<pid>/status`).
const STATUS_SCAN_BUFF_SIZE: usize = 4 * 1024;
/// The size of the stack-allocated scratch buffer used to read the content of socket table files
/// (e.g.: `<procfs_mount_path>/<pid>/net/tcp`).
const SOCKET_TABLE_SCAN_BUFF_SIZE: usize = 32 * 1024;

macro_rules! scan_impl {
    ($fn_name:ident, $path:literal, $buff_size:ident) => {
        #[doc = concat!("Scans each line of `<procfs_mount_path>/<pid>/", $path,
                                                            "` and passes it to `line_processor`.")]
        pub fn $fn_name<P>(&self, line_processor: P) -> io::Result<ControlFlow<()>>
        where
            P: LineProcessor,
        {
            const _: () = {
                assert!(
                    $path.len() <= MAX_SUFFIX_LEN,
                    concat!("Path '", $path, "' exceeds ", stringify!(MAX_SUFFIX_LEN))
                );
            };
            // Convert path to &CStr at compile time.
            const PATH_CSTR: &CStr =
                match CStr::from_bytes_with_nul(concat!($path, "\0").as_bytes()) {
                    Ok(cstr) => cstr,
                    Err(_) => panic!(concat!("path '", $path, "' contains interior NUL bytes")),
                };
            let mut reader = self.procfs.open(&self.proc_ref, PATH_CSTR)?;
            let mut buff = [0u8; $buff_size];
            read::scan_lines(&mut reader, &mut buff, line_processor)
        }
    };
}

impl<D: Driver> ProcView<'_, D> {
    /// Iterates over the entries in `<procfs_mount_path>/<pid>/fd`, invoking `process` for each of
    /// them.
    ///
    /// `process` is not invoked for `.` and `..` entries.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be opened or if the callback returns an error.
    pub fn scan_fd_dir<P>(&self, process: P) -> io::Result<()>
    where
        P: FnMut(&D::DirEntry<'_>) -> io::Result<()>,
    {
        self.procfs.scan_dir(&self.proc_ref, c"fd", process)
    }

    /// Returns the content read from `<procfs_mount_path>/<pid>/comm`.
    pub fn read_comm(&self) -> io::Result<Comm> {
        let mut reader = self.procfs.open(&self.proc_ref, c"comm")?;
        Comm::from_buffer_writer(|buff: &mut [u8]| -> io::Result<usize> {
            let mut read_bytes = read::exact(&mut reader, buff)?;
            if read_bytes > 0 && buff[read_bytes - 1] == b'\n' {
                read_bytes -= 1;
            }
            Ok(read_bytes)
        })
    }

    /// Returns the content read from `<procfs_mount_path>/<pid>/environ`.
    pub fn read_environ(&self) -> io::Result<Environ> {
        let mut reader = self.procfs.open(&self.proc_ref, c"environ")?;
        Environ::from_buffer_writer(|buff: &mut [u8]| -> io::Result<usize> {
            read::exact(&mut reader, buff)
        })
    }

    /// Returns the content read from `<procfs_mount_path>/<pid>/cmdline`.
    pub fn read_cmdline(&self) -> io::Result<Cmdline> {
        let mut reader = self.procfs.open(&self.proc_ref, c"cmdline")?;
        Cmdline::from_buffer_writer(|buff: &mut [u8]| -> io::Result<usize> {
            read::exact(&mut reader, buff)
        })
    }

    /// Returns the content read from `<procfs_mount_path>/<pid>/loginuid`.
    pub fn read_loginuid(&self) -> io::Result<u32> {
        let mut reader = self.procfs.open(&self.proc_ref, c"loginuid")?;
        let mut buff = [0u8; u32::FORMATTED_SIZE_DECIMAL];
        let mut read_bytes = read::exact(&mut reader, &mut buff)?;
        if read_bytes > 0 && buff[read_bytes - 1] == b'\n' {
            read_bytes -= 1;
        }
        parse::dec_strict(&buff[..read_bytes])
    }

    /// Returns the inode number of `<procfs_mount_path>/<pid>/ns/net`.
    pub fn read_netns_ino(&self) -> io::Result<u64> {
        let metadata = self.procfs.read_metadata(&self.proc_ref, c"ns/net")?;
        Ok(metadata.ino())
    }

    /// Returns the content of the symbolic link `<procfs_mount_path>/<pid>/exe`.
    pub fn read_exe(&self) -> io::Result<OsPath> {
        self.procfs.read_symlink(&self.proc_ref, c"exe")
    }

    /// Returns the content of the symbolic link `<procfs_mount_path>/<pid>/cwd`.
    pub fn read_cwd(&self) -> io::Result<OsPath> {
        self.procfs.read_symlink(&self.proc_ref, c"cwd")
    }

    /// Returns the content of the symbolic link `<procfs_mount_path>/<pid>/root`.
    pub fn read_root(&self) -> io::Result<OsPath> {
        self.procfs.read_symlink(&self.proc_ref, c"root")
    }

    scan_impl!(scan_status, "status", STATUS_SCAN_BUFF_SIZE);
    scan_impl!(scan_net_tcp, "net/tcp", SOCKET_TABLE_SCAN_BUFF_SIZE);
    scan_impl!(scan_net_udp, "net/udp", SOCKET_TABLE_SCAN_BUFF_SIZE);
    scan_impl!(scan_net_raw, "net/raw", SOCKET_TABLE_SCAN_BUFF_SIZE);
    scan_impl!(scan_net_tcp6, "net/tcp6", SOCKET_TABLE_SCAN_BUFF_SIZE);
    scan_impl!(scan_net_udp6, "net/udp6", SOCKET_TABLE_SCAN_BUFF_SIZE);
    scan_impl!(scan_net_raw6, "net/raw6", SOCKET_TABLE_SCAN_BUFF_SIZE);
    scan_impl!(scan_net_unix, "net/unix", SOCKET_TABLE_SCAN_BUFF_SIZE);
    scan_impl!(scan_net_netlink, "net/netlink", SOCKET_TABLE_SCAN_BUFF_SIZE);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::FileType;
    use std::collections::{HashMap, HashSet};
    use std::ffi::OsStr;
    use std::io::Cursor;
    use std::ops::ControlFlow;

    const PID: NonZeroU32 = NonZeroU32::new(100).unwrap();

    #[test]
    fn test_mount_path_new_happy_path() {
        let path = MountPath::new("/proc".into()).unwrap();
        assert_eq!(path.0.as_bytes(), b"/proc");
    }

    #[test]
    fn test_mount_path_new_strips_trailing_slash() {
        let path = MountPath::new("/proc/".into()).unwrap();
        assert_eq!(path.0.as_bytes(), b"/proc");
    }

    #[test]
    fn test_mount_path_new_fails_on_empty() {
        let err = MountPath::new("".into()).unwrap_err();
        assert!(matches!(err, MountPathError::Empty));
    }

    #[test]
    fn test_mount_path_new_fails_on_too_long() {
        let long_path = "a".repeat(MountPath::MAX_LEN + 1);
        let err = MountPath::new(long_path.into()).unwrap_err();
        assert!(matches!(err, MountPathError::TooLong));
    }

    #[test]
    fn test_mount_path_new_fails_on_nul_byte() {
        let err = MountPath::new("/proc\0".into()).unwrap_err();
        assert!(matches!(err, MountPathError::NulError(..)));
    }

    /// A mock implementation of [DirEntry].
    #[derive(Debug, Clone, Eq, PartialEq)]
    struct MockDirEntry {
        file_name: OsString,
        ino: u64,
    }

    /// A mock implementation of [Metadata].
    #[derive(Debug, Clone, Eq, PartialEq)]
    struct MockMetadata {
        ino: u64,
        file_type: FileType,
    }

    impl MetadataExt for MockMetadata {
        fn ino(&self) -> u64 {
            self.ino
        }

        fn file_type(&self) -> FileType {
            self.file_type
        }
    }

    /// A mock implementation of [Driver] that serves data from memory.
    #[derive(Debug, Default)]
    struct MockDriver {
        /// Set of full directory paths (bytes) that can be opened via [Driver::open_dir].
        dirs: HashSet<Vec<u8>>,
        /// Map full file paths (bytes) to file content.
        files: HashMap<Vec<u8>, Vec<u8>>,
        /// Map full symlink paths (bytes) to target paths.
        symlinks: HashMap<Vec<u8>, Vec<u8>>,
        /// Map full directory paths (bytes) to lists of directory entries.
        dir_entries: HashMap<Vec<u8>, Vec<MockDirEntry>>,
        /// Map full file paths (bytes) to file metadata.
        metadatas: HashMap<Vec<u8>, MockMetadata>,
    }

    impl MockDriver {
        fn new() -> Self {
            Self::default()
        }

        fn add_dir(&mut self, path: impl Into<Vec<u8>>) {
            self.dirs.insert(path.into());
        }

        fn add_file(&mut self, path: impl Into<Vec<u8>>, content: impl Into<Vec<u8>>) {
            self.files.insert(path.into(), content.into());
        }

        fn add_symlink(&mut self, path: impl Into<Vec<u8>>, target: impl Into<Vec<u8>>) {
            self.symlinks.insert(path.into(), target.into());
        }

        fn add_metadata(&mut self, path: impl Into<Vec<u8>>, metadata: MockMetadata) {
            self.metadatas.insert(path.into(), metadata);
        }

        fn add_dir_entry(&mut self, path: impl Into<Vec<u8>>, dir_entry: MockDirEntry) {
            let list = self.dir_entries.entry(path.into()).or_default();
            list.push(dir_entry);
        }

        fn resolve_path(dir_handle: Option<&Vec<u8>>, path: &CStr) -> Vec<u8> {
            let mut prefix = match dir_handle {
                Some(v) => v.clone(),
                None => Vec::new(),
            };
            let suffix = path.to_bytes();
            let need_slash = !prefix.ends_with(b"/") && !suffix.starts_with(b"/");
            if need_slash {
                prefix.push(b'/');
            }
            prefix.extend_from_slice(suffix);
            prefix
        }
    }

    impl Driver for MockDriver {
        type DirHandle = Vec<u8>;
        type Reader = Cursor<Vec<u8>>;
        type Metadata = MockMetadata;
        type DirEntry<'a> = MockDirEntry;

        fn open_dir(
            &self,
            dir_handle: Option<&Vec<u8>>,
            path: &CStr,
        ) -> io::Result<Self::DirHandle> {
            let path = Self::resolve_path(dir_handle, path);
            if !self.dirs.contains(path.as_slice()) {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "Mock dir not found: {:?}",
                        String::from_utf8_lossy(path.as_slice())
                    ),
                ));
            }
            Ok(path)
        }

        fn open(&self, dir_handle: Option<&Vec<u8>>, path: &CStr) -> io::Result<Self::Reader> {
            let path = Self::resolve_path(dir_handle, path);
            let path_bytes = path.as_slice();
            match self.files.get(path_bytes) {
                Some(content) => Ok(Cursor::new(content.clone())),
                None => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "Mock file not found: {:?}",
                        String::from_utf8_lossy(path_bytes)
                    ),
                )),
            }
        }

        fn read_symlink(
            &self,
            dir_handle: Option<&Vec<u8>>,
            path: &CStr,
            buff: &mut [u8],
        ) -> io::Result<usize> {
            let path = Self::resolve_path(dir_handle, path);
            let path_bytes = path.as_slice();
            match self.symlinks.get(path_bytes) {
                Some(target) => {
                    if target.len() > buff.len() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "Mock symlink target too long for buffer",
                        ));
                    }
                    buff[..target.len()].copy_from_slice(target);
                    Ok(target.len())
                }
                None => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Mock symlink not found: {:?}", path),
                )),
            }
        }

        fn read_metadata(
            &self,
            dir_handle: Option<&Vec<u8>>,
            path: &CStr,
        ) -> io::Result<Self::Metadata> {
            let path = Self::resolve_path(dir_handle, path);
            let path_bytes = path.as_slice();
            match self.metadatas.get(path_bytes) {
                Some(content) => Ok(content.clone()),
                None => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "Mock metadata not found: {:?}",
                        String::from_utf8_lossy(path_bytes)
                    ),
                )),
            }
        }

        fn scan_dir<P>(
            &self,
            dir_handle: Option<&Vec<u8>>,
            path: &CStr,
            mut process: P,
        ) -> io::Result<()>
        where
            P: FnMut(&Self::DirEntry<'_>) -> io::Result<()>,
        {
            let path = Self::resolve_path(dir_handle, path);
            let path_bytes = path.as_slice();
            let Some(dir_entries) = self.dir_entries.get(path_bytes) else {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "Mock dir entries not found: {:?}",
                        String::from_utf8_lossy(path_bytes)
                    ),
                ));
            };

            for dir_entry in dir_entries {
                process(dir_entry)?;
            }
            Ok(())
        }
    }

    #[test]
    fn test_read_comm_strips_newline() {
        let mut driver = MockDriver::new();
        driver.add_file(b"/proc/100/comm", b"content\n");
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        let comm = procfs.proc_ref(PID).read_comm().unwrap();
        assert_eq!(comm.as_os_str(), OsStr::new("content"));
    }

    #[test]
    fn test_read_comm_no_newline() {
        let mut driver = MockDriver::new();
        driver.add_file(b"/proc/100/comm", b"content");
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        let comm = procfs.proc_ref(PID).read_comm().unwrap();
        assert_eq!(comm.as_os_str(), OsStr::new("content"));
    }

    #[test]
    fn test_read_comm_truncates_too_long() {
        let mut driver = MockDriver::new();
        let long_comm = b"very_long_process_comm_that_truncates\n";
        driver.add_file(b"/proc/100/comm", long_comm);
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        let comm = procfs.proc_ref(PID).read_comm().unwrap();
        let comm_str = comm.as_os_str().to_string_lossy();
        assert_eq!(comm_str.len(), Comm::MAX_LEN);
        let truncated_comm = String::from_utf8_lossy(&long_comm[..Comm::MAX_LEN]);
        assert_eq!(comm_str, truncated_comm);
    }

    #[test]
    fn test_read_cmdline_happy_path() {
        let mut driver = MockDriver::new();
        let content = b"argv0\0argv1\0";
        driver.add_file(b"/proc/100/cmdline", content);
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        let cmdline = procfs.proc_ref(PID).read_cmdline().unwrap();
        assert_eq!(cmdline.as_bytes(), content);
    }

    #[test]
    fn test_read_cmdline_fails_on_not_found() {
        let driver = MockDriver::new();
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        let err = procfs.proc_ref(PID).read_cmdline().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn test_read_environ_happy_path() {
        let mut driver = MockDriver::new();
        let content = b"FOO=BAR\0BAZ=QUX\0";
        driver.add_file(b"/proc/100/environ", content);
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        let env = procfs.proc_ref(PID).read_environ().unwrap();
        assert_eq!(env.as_bytes(), content);
    }

    #[test]
    fn test_read_environ_fails_on_not_found() {
        let driver = MockDriver::new();
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        let err = procfs.proc_ref(PID).read_environ().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn test_read_loginuid_happy_path() {
        let mut driver = MockDriver::new();
        driver.add_file(b"/proc/100/loginuid", b"1000");
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        assert_eq!(procfs.proc_ref(PID).read_loginuid().unwrap(), 1000);
    }

    #[test]
    fn test_read_loginuid_strips_newline() {
        let mut driver = MockDriver::new();
        driver.add_file(b"/proc/100/loginuid", b"1000\n");
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        assert_eq!(procfs.proc_ref(PID).read_loginuid().unwrap(), 1000);
    }

    #[test]
    fn test_read_loginuid_fails_on_non_numeric() {
        let mut driver = MockDriver::new();
        driver.add_file(b"/proc/100/loginuid", b"invalid");
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        assert!(procfs.proc_ref(PID).read_loginuid().is_err());
    }

    #[test]
    fn test_read_netns_ino_happy_path() {
        let mut driver = MockDriver::new();
        let ino = 1234;
        let file_type = FileType::Symlink;
        driver.add_metadata(b"/proc/100/ns/net", MockMetadata { ino, file_type });
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        assert_eq!(procfs.proc_ref(PID).read_netns_ino().unwrap(), ino);
    }

    #[test]
    fn test_read_netns_ino_fails_on_not_found() {
        let driver = MockDriver::new();
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        let err = procfs.proc_ref(PID).read_netns_ino().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn test_symlink_reads_happy_path() {
        let mut driver = MockDriver::new();
        driver.add_symlink(b"/proc/100/exe", "target_exe");
        driver.add_symlink(b"/proc/100/cwd", "target_cwd");
        driver.add_symlink(b"/proc/100/root", "target_root");
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        let proc_ref = procfs.proc_ref(PID);
        assert_eq!(
            proc_ref.read_exe().unwrap().as_os_str(),
            OsStr::new("target_exe")
        );
        assert_eq!(
            proc_ref.read_cwd().unwrap().as_os_str(),
            OsStr::new("target_cwd")
        );
        assert_eq!(
            proc_ref.read_root().unwrap().as_os_str(),
            OsStr::new("target_root")
        );
    }

    #[test]
    fn test_symlink_reads_fail_on_not_found() {
        let driver = MockDriver::new();
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        let proc_ref = procfs.proc_ref(PID);
        assert_eq!(
            proc_ref.read_exe().unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            proc_ref.read_cwd().unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            proc_ref.read_root().unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn test_scans_happy_path() {
        struct Collector {
            lines: Vec<String>,
        }
        impl LineProcessor for &mut Collector {
            fn process(&mut self, line: &[u8]) -> io::Result<ControlFlow<()>> {
                self.lines.push(String::from_utf8_lossy(line).into_owned());
                Ok(ControlFlow::Continue(()))
            }
        }

        macro_rules! check {
            ($method:ident, $rel_path:expr, $content:expr, $expected:expr) => {{
                let mut driver = MockDriver::new();
                let mut path = b"/proc/100/".to_vec();
                path.extend($rel_path);
                driver.add_file(path, $content);
                let mount_path = MountPath::new("/proc".into()).unwrap();
                let procfs = Procfs::new_with_driver(mount_path, driver);
                let mut collector = Collector { lines: Vec::new() };
                let cf = procfs.proc_ref(PID).$method(&mut collector).unwrap();
                assert!(cf.is_continue());

                assert_eq!(
                    collector.lines.as_slice(),
                    $expected,
                    "Mismatch for {}",
                    String::from_utf8_lossy($rel_path)
                );
            }};
        }

        check!(scan_status, b"status", "status\ntrunc", ["status"]);
        check!(scan_net_tcp, b"net/tcp", "tcp\ntrunc", ["tcp"]);
        check!(scan_net_udp, b"net/udp", "udp\ntrunc", ["udp"]);
        check!(scan_net_raw, b"net/raw", "raw\ntrunc", ["raw"]);
        check!(scan_net_tcp6, b"net/tcp6", "tcp6\ntrunc", ["tcp6"]);
        check!(scan_net_udp6, b"net/udp6", "udp6\ntrunc", ["udp6"]);
        check!(scan_net_raw6, b"net/raw6", "raw6\ntrunc", ["raw6"]);
        check!(scan_net_unix, b"net/unix", "unix\ntrunc", ["unix"]);
        check!(scan_net_netlink, b"net/netlink", "nl\ntrunc", ["nl"]);
    }

    #[test]
    fn test_scan_fd_dir_happy_path() {
        let mut driver = MockDriver::new();
        let dir_entry = MockDirEntry {
            file_name: OsString::from("0"),
            ino: 12345,
        };
        driver.add_dir_entry(b"/proc/100/fd", dir_entry.clone());
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        let mut entries = Vec::new();
        procfs
            .proc_ref(PID)
            .scan_fd_dir(|entry| {
                entries.push(entry.clone());
                Ok(())
            })
            .unwrap();
        assert_eq!(entries, vec![dir_entry]);
    }

    #[test]
    fn test_open_proc_fails_on_missing_dir() {
        let driver = MockDriver::new();
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        let err = procfs.open_proc(PID).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    /// Tests that operations involving opening files for reading the content are equivalent on
    /// [ProcView]s returned by both [Procfs::proc_ref] and [Procfs::open_proc].
    #[test]
    fn test_proc_views_open_file_equivalent() {
        let mut driver = MockDriver::new();
        driver.add_dir(b"/proc/100/");
        driver.add_file(b"/proc/100/comm", b"content\n");
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        let proc_ref = procfs.proc_ref(PID);
        let open_proc = procfs.open_proc(PID).unwrap();
        let proc_ref_comm = proc_ref.read_comm().unwrap();
        let open_proc_comm = open_proc.read_comm().unwrap();
        assert_eq!(proc_ref_comm.as_os_str(), open_proc_comm.as_os_str());
        assert_eq!(proc_ref_comm.as_os_str(), OsStr::new("content"));
    }

    /// Tests that operations involving reading file metadata are equivalent on [ProcView]s returned
    /// by both [Procfs::proc_ref] and [Procfs::open_proc].
    #[test]
    fn test_proc_views_read_metadata_equivalent() {
        let mut driver = MockDriver::new();
        driver.add_dir(b"/proc/100/");
        driver.add_metadata(
            b"/proc/100/ns/net",
            MockMetadata {
                ino: 4242,
                file_type: FileType::Symlink,
            },
        );
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        let proc_ref = procfs.proc_ref(PID);
        let open_proc = procfs.open_proc(PID).unwrap();
        let proc_ref_netns_ino = proc_ref.read_netns_ino().unwrap();
        let open_proc_netns_ino = open_proc.read_netns_ino().unwrap();
        assert_eq!(proc_ref_netns_ino, open_proc_netns_ino);
        assert_eq!(proc_ref_netns_ino, 4242);
    }

    /// Tests that operations involving reading symlink targets are equivalent on [ProcView]s
    /// returned by both [Procfs::proc_ref] and [Procfs::open_proc].
    #[test]
    fn test_proc_views_read_symlink_equivalent() {
        let mut driver = MockDriver::new();
        driver.add_dir(b"/proc/100/");
        driver.add_symlink(b"/proc/100/exe", "target_exe");
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        let proc_ref = procfs.proc_ref(PID);
        let open_proc = procfs.open_proc(PID).unwrap();
        let proc_ref_exe = proc_ref.read_exe().unwrap();
        let open_proc_exe = open_proc.read_exe().unwrap();
        assert_eq!(proc_ref_exe.as_os_str(), open_proc_exe.as_os_str());
        assert_eq!(proc_ref_exe.as_os_str(), OsStr::new("target_exe"));
    }

    /// Tests that operations involving scanning directory entries are equivalent on [ProcView]s
    /// returned by both [Procfs::proc_ref] and [Procfs::open_proc].
    #[test]
    fn test_proc_views_scan_dir_equivalent() {
        let mut driver = MockDriver::new();
        driver.add_dir(b"/proc/100/");
        let dir_entry = MockDirEntry {
            file_name: OsString::from("0"),
            ino: 12345,
        };
        driver.add_dir_entry(b"/proc/100/fd", dir_entry.clone());
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        let proc_ref = procfs.proc_ref(PID);
        let open_proc = procfs.open_proc(PID).unwrap();

        let mut proc_ref_entries = Vec::new();
        proc_ref
            .scan_fd_dir(|e| {
                proc_ref_entries.push(e.clone());
                Ok(())
            })
            .unwrap();

        let mut open_proc_entries = Vec::new();
        open_proc
            .scan_fd_dir(|e| {
                open_proc_entries.push(e.clone());
                Ok(())
            })
            .unwrap();

        assert_eq!(proc_ref_entries, open_proc_entries);
        assert_eq!(proc_ref_entries, vec![dir_entry]);
    }
}
