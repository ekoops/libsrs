use crate::buffer_writer::FromBufferWriter;
use crate::read::LineProcessor;
use crate::task::{Cmdline, Comm, Environ, OsPath};
use crate::{parse, read};
use lexical_core::FormattedSize;
use std::ffi::{CStr, CString, NulError, OsStr, OsString};
use std::fs::{DirEntry, File, Metadata};
use std::ops::ControlFlow;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::{fs, io};
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

    /// Create a new [MountPath] from `path`.
    pub fn new(path: OsString) -> Result<Self, MountPathError> {
        let mut path_bytes = path.as_bytes();
        if path_bytes.len() == 0 {
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
    type Reader: io::Read;
    type DirEntry;
    type Metadata: MetadataExt;

    /// Create a [Self::Reader] for `path`.
    ///
    /// `path` is the non-NUL-terminated binary string representation of a file path.
    fn open(&self, path: &[u8]) -> io::Result<Self::Reader>;

    /// Read the content of the symbolic link at `path` and store it in `buff`.
    ///
    /// Return the number of bytes read. `path` is the NUL-terminated binary string representation
    /// of a file path.
    fn read_symlink(&self, path: &CStr, buff: &mut [u8]) -> io::Result<usize>;

    /// Return metadata associated with `path`.
    ///
    /// `path` is the non-NUL-terminated binary string representation of a file path.
    fn get_metadata(&self, path: &[u8]) -> io::Result<Self::Metadata>;

    /// Iterate over the entries of the directory at `path`, executing `process` for each entry.
    ///
    /// `path` is the non-NUL-terminated binary string representation of a directory path.
    ///
    /// The `process` closure can return an [io::Result] to handle errors or abort the iteration
    /// early.
    fn scan_dir<P>(&self, path: &[u8], process: P) -> io::Result<()>
    where
        P: FnMut(&Self::DirEntry) -> io::Result<()>;
}

/// The canonical [Driver] implementation.
pub struct RealDriver;

impl Driver for RealDriver {
    type Reader = File;
    type DirEntry = DirEntry;
    type Metadata = Metadata;

    #[inline(always)]
    fn open(&self, path: &[u8]) -> io::Result<Self::Reader> {
        let path = OsStr::from_bytes(path);
        File::open(path)
    }

    #[inline(always)]
    fn read_symlink(&self, path: &CStr, buff: &mut [u8]) -> io::Result<usize> {
        read::link(path, buff)
    }

    #[inline(always)]
    fn get_metadata(&self, path: &[u8]) -> io::Result<Metadata> {
        let path = OsStr::from_bytes(path);
        fs::metadata(path)
    }

    #[inline(always)]
    fn scan_dir<P>(&self, path: &[u8], mut process: P) -> io::Result<()>
    where
        P: FnMut(&Self::DirEntry) -> io::Result<()>,
    {
        let path = OsStr::from_bytes(path);
        for dir_entry in fs::read_dir(path)? {
            let dir_entry = dir_entry?;
            process(&dir_entry)?;
        }
        Ok(())
    }
}

/// A helper type allowing to extract data from procfs. If unspecified, it leverages [RealDriver]
/// for filesystem accesses.
pub struct Procfs<D: Driver = RealDriver> {
    mount_path: MountPath,
    driver: D,
}

impl Procfs<RealDriver> {
    /// Create a new [Procfs] instance from the specified procfs `mount_path`.
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
/// Max allowed length for a suffix after `<mount_path>/<pid>/` (see [PATH_BUFF_SIZE]).
const MAX_SUFFIX_LEN: usize = 32;
/// Safety margin accounting for `/`s and trailing zeros in procfs path (see [PATH_BUFF_SIZE]).
const PADDING: usize = 16;
/// The size of the buffer used to construct procfs file paths. The buffer content is structured
/// in the following way: `<mount_path>/<pid>/<suffix><zero_pad>`.
const PATH_BUFF_SIZE: usize = MountPath::MAX_LEN + MAX_PID_LEN + MAX_SUFFIX_LEN + PADDING;

/// The size of the stack-allocated scratch buffer used to read the content of status files (i.e.:
/// `/proc/<pid>/status`).
const STATUS_SCAN_BUFF_SIZE: usize = 4 * 1024;
/// The size of the stack-allocated scratch buffer used to read the content of socket table files
/// (e.g.: `/proc/<pid>/net/tcp`).
const SOCKET_TABLE_SCAN_BUFF_SIZE: usize = 32 * 1024;

macro_rules! scan_impl {
    ($fn_name:ident, $path:literal, $buff_size:ident) => {
        #[doc = concat!("Scan each line of `<procfs_mount_path>/<pid>/", $path,
                                                    "` for `pid` and pass it to `line_processor`.")]
        pub fn $fn_name<P>(&self, pid: u32, line_processor: P) -> io::Result<ControlFlow<()>>
        where
            P: LineProcessor,
        {
            let mut reader = self.open(pid, $path.as_bytes())?;
            let mut buff = [0u8; $buff_size];
            read::scan_lines(&mut reader, &mut buff, line_processor)
        }
    };
}

impl<D: Driver> Procfs<D> {
    /// Create a new [Procfs] instance from the specified procfs `mount_path` leveraging the
    /// specified `driver` to perform file system accesses.
    pub fn new_with_driver(mount_path: MountPath, driver: D) -> Self {
        Self { mount_path, driver }
    }

    /// Create a new path buffer that can be used to build a path.
    #[inline]
    fn new_path_buff() -> [u8; PATH_BUFF_SIZE] {
        [0u8; PATH_BUFF_SIZE]
    }

    /// Update `*buff` to point to `len` bytes forward.
    #[inline]
    fn advance_buff(buff: &mut &mut [u8], len: usize) {
        let (_, new_buff) = std::mem::take(buff).split_at_mut(len);
        *buff = new_buff;
    }

    /// Write `bytes` in `*buff` and return `bytes.len()`. Update `*buff` to point to the first
    /// unwritten byte.
    #[inline(always)]
    fn write_bytes(buff: &mut &mut [u8], bytes: &[u8]) -> usize {
        let bytes_len = bytes.len();
        buff[..bytes_len].copy_from_slice(bytes);
        Self::advance_buff(buff, bytes_len);
        bytes_len
    }

    /// Write the string representation of `pid` into `buff` and return the number of bytes written.
    fn write_pid<'a, 'b: 'a>(buff: &'a mut &'b mut [u8], pid: u32) -> usize {
        let pid_bytes = lexical_core::write(pid, *buff);
        let written_bytes = pid_bytes.len();
        Self::advance_buff(buff, written_bytes);
        written_bytes
    }

    /// Write the mount path, `pid` and `filename` into `buff`, separating them with `/`s, and
    /// return the number of bytes written.
    fn write_proc_file_path(&self, mut buff: &mut [u8], pid: u32, filename: &[u8]) -> usize {
        let mut written_bytes = Self::write_bytes(&mut buff, self.mount_path.0.as_bytes());
        written_bytes += Self::write_bytes(&mut buff, b"/");
        written_bytes += Self::write_pid(&mut buff, pid);
        written_bytes += Self::write_bytes(&mut buff, b"/");
        written_bytes += Self::write_bytes(&mut buff, filename);
        written_bytes
    }

    /// Create a reader for `<procfs_mount_path>/<pid>/<filename>`.
    ///
    /// `filename` is the binary string representation of `<filename>`.
    fn open(&self, pid: u32, filename: &[u8]) -> io::Result<D::Reader> {
        let mut path_buff = Self::new_path_buff();
        let written_bytes = self.write_proc_file_path(&mut path_buff[..], pid, filename);
        let path = &path_buff[..written_bytes];
        self.driver.open(path)
    }

    /// Return metadata associated with `<procfs_mount_path>/<pid>/<path>`.
    ///
    /// `path` is the binary string representation of `<path>`.
    fn get_metadata(&self, pid: u32, path: &[u8]) -> io::Result<D::Metadata> {
        let mut path_buff = Self::new_path_buff();
        let written_bytes = self.write_proc_file_path(&mut path_buff[..], pid, path);
        let path = &path_buff[..written_bytes];
        self.driver.get_metadata(path)
    }

    /// Iterate over the entries in `<procfs_mount_path>/<pid>/<dirname>`.
    ///
    /// `dirname` is the binary string representation of the subdirectory (e.g., `b"fd"`).
    /// The `process` callback is invoked for each directory entry found.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be opened or if the callback returns an error.
    pub fn scan_dir<P>(&self, pid: u32, dirname: &[u8], process: P) -> io::Result<()>
    where
        P: FnMut(&D::DirEntry) -> io::Result<()>,
    {
        let mut path_buff = Self::new_path_buff();
        let written_bytes = self.write_proc_file_path(&mut path_buff[..], pid, dirname);
        let path = &path_buff[..written_bytes];
        self.driver.scan_dir(path, process)
    }

    /// Return the content read from `<procfs_mount_path>/<pid>/comm` for `pid`.
    pub fn read_comm(&self, pid: u32) -> io::Result<Comm> {
        let mut reader = self.open(pid, b"comm")?;
        Comm::from_buffer_writer(|buff: &mut [u8]| -> io::Result<usize> {
            let mut read_bytes = read::exact(&mut reader, buff)?;
            if read_bytes > 0 && buff[read_bytes - 1] == b'\n' {
                read_bytes -= 1;
            }
            Ok(read_bytes)
        })
    }

    /// Return the content read from `<procfs_mount_path>/<pid>/environ` for `pid`.
    pub fn read_environ(&self, pid: u32) -> io::Result<Environ> {
        let mut reader = self.open(pid, b"environ")?;
        Environ::from_buffer_writer(|buff: &mut [u8]| -> io::Result<usize> {
            read::exact(&mut reader, buff)
        })
    }

    /// Return the content read from `<procfs_mount_path>/<pid>/cmdline` for `pid`.
    pub fn read_cmdline(&self, pid: u32) -> io::Result<Cmdline> {
        let mut reader = self.open(pid, b"cmdline")?;
        Cmdline::from_buffer_writer(|buff: &mut [u8]| -> io::Result<usize> {
            read::exact(&mut reader, buff)
        })
    }

    /// Return the content read from `<procfs_mount_path>/<pid>/loginuid` for `pid`.
    pub fn read_loginuid(&self, pid: u32) -> io::Result<u32> {
        let mut reader = self.open(pid, b"loginuid")?;
        let mut buff = [0u8; u32::FORMATTED_SIZE_DECIMAL];
        let mut read_bytes = read::exact(&mut reader, &mut buff)?;
        if read_bytes > 0 && buff[read_bytes - 1] == b'\n' {
            read_bytes -= 1;
        }
        parse::dec_strict(&buff[..read_bytes])
    }

    /// Return the inode number of `<procfs_mount_path>/<pid>/ns/net` for `pid`.
    pub fn read_netns_ino(&self, pid: u32) -> io::Result<u64> {
        let metadata = self.get_metadata(pid, b"ns/net")?;
        Ok(metadata.ino())
    }

    /// Return the content of the symbolic link `<procfs_mount_path>/<pid>/<filename>` for `pid`.
    ///
    /// `filename` is the binary string representation of `<filename>`.
    fn read_symlink(&self, pid: u32, filename: &[u8]) -> io::Result<OsPath> {
        let mut path_buff = Self::new_path_buff();
        // -1 ensures that at least a trailing zero will be present after the write operation.
        let max_len = path_buff.len() - 1;
        let written_bytes = self.write_proc_file_path(&mut path_buff[..max_len], pid, filename);
        // +1 includes one trailing zero.
        let path = CStr::from_bytes_until_nul(&path_buff[..written_bytes + 1])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        OsPath::from_buffer_writer(|buff: &mut [u8]| -> io::Result<usize> {
            self.driver.read_symlink(&path, buff)
        })
    }

    /// Return the content of the symbolic link `<procfs_mount_path>/<pid>/exe` for `pid`.
    pub fn read_exe(&self, pid: u32) -> io::Result<OsPath> {
        self.read_symlink(pid, b"exe")
    }

    /// Return the content of the symbolic link `<procfs_mount_path>/<pid>/cwd` for `pid`.
    pub fn read_cwd(&self, pid: u32) -> io::Result<OsPath> {
        self.read_symlink(pid, b"cwd")
    }

    /// Return the content of the symbolic link `<procfs_mount_path>/<pid>/root` for `pid`.
    pub fn read_root(&self, pid: u32) -> io::Result<OsPath> {
        self.read_symlink(pid, b"root")
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
    use std::collections::HashMap;
    use std::io::Cursor;
    use std::ops::ControlFlow;

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
    }

    macro_rules! unimplemented_metadata_methods {
        ($($name:ident -> $ret:ty),*) => {
            $(
                fn $name(&self) -> $ret {
                    unimplemented!(concat!(stringify!($name),
                        " is not implemented for MockMetadata"))
                }
            )*
        };
    }
    impl MetadataExt for MockMetadata {
        fn ino(&self) -> u64 {
            self.ino
        }

        // Generate the rest in a single line
        unimplemented_metadata_methods!(
            dev -> u64, mode -> u32, nlink -> u64, uid -> u32, gid -> u32, rdev -> u64, size -> u64,
            atime -> i64, atime_nsec -> i64, mtime -> i64, mtime_nsec -> i64, ctime -> i64,
            ctime_nsec -> i64, blksize -> u64, blocks -> u64
        );
    }

    /// A mock implementation of [Driver] that serves data from memory.
    #[derive(Default)]
    struct MockDriver {
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
            let list = self.dir_entries.entry(path.into()).or_insert(Vec::new());
            list.push(dir_entry);
        }
    }

    impl Driver for MockDriver {
        type Reader = Cursor<Vec<u8>>;
        type DirEntry = MockDirEntry;
        type Metadata = MockMetadata;

        fn open(&self, path: &[u8]) -> io::Result<Self::Reader> {
            match self.files.get(path) {
                Some(content) => Ok(Cursor::new(content.clone())),
                None => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Mock file not found: {:?}", String::from_utf8_lossy(path)),
                )),
            }
        }

        fn read_symlink(&self, path: &CStr, buff: &mut [u8]) -> io::Result<usize> {
            let path_bytes = path.to_bytes();
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

        fn get_metadata(&self, path: &[u8]) -> io::Result<Self::Metadata> {
            match self.metadatas.get(path) {
                Some(content) => Ok(content.clone()),
                None => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "Mock metadata not found: {:?}",
                        String::from_utf8_lossy(path)
                    ),
                )),
            }
        }

        fn scan_dir<P>(&self, path: &[u8], mut process: P) -> io::Result<()>
        where
            P: FnMut(&Self::DirEntry) -> io::Result<()>,
        {
            let Some(dir_entries) = self.dir_entries.get(path) else {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "Mock dir entries not found: {:?}",
                        String::from_utf8_lossy(path)
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
        let comm = procfs.read_comm(100).unwrap();
        assert_eq!(comm.as_os_str(), OsStr::new("content"));
    }

    #[test]
    fn test_read_comm_no_newline() {
        let mut driver = MockDriver::new();
        driver.add_file(b"/proc/100/comm", b"content");
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        let comm = procfs.read_comm(100).unwrap();
        assert_eq!(comm.as_os_str(), OsStr::new("content"));
    }

    #[test]
    fn test_read_comm_truncates_too_long() {
        let mut driver = MockDriver::new();
        let long_comm = b"very_long_process_comm_that_truncates\n";
        driver.add_file(b"/proc/100/comm", long_comm);
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        let comm = procfs.read_comm(100).unwrap();
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
        let cmdline = procfs.read_cmdline(100).unwrap();
        assert_eq!(cmdline.as_bytes(), content);
    }

    #[test]
    fn test_read_cmdline_fails_on_not_found() {
        let driver = MockDriver::new();
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        let err = procfs.read_cmdline(100).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn test_read_environ_happy_path() {
        let mut driver = MockDriver::new();
        let content = b"FOO=BAR\0BAZ=QUX\0";
        driver.add_file(b"/proc/100/environ", content);
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        let env = procfs.read_environ(100).unwrap();
        assert_eq!(env.as_bytes(), content);
    }

    #[test]
    fn test_read_environ_fails_on_not_found() {
        let driver = MockDriver::new();
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        let err = procfs.read_environ(100).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn test_read_loginuid_happy_path() {
        let mut driver = MockDriver::new();
        driver.add_file(b"/proc/100/loginuid", b"1000");
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        assert_eq!(procfs.read_loginuid(100).unwrap(), 1000);
    }

    #[test]
    fn test_read_loginuid_strips_newline() {
        let mut driver = MockDriver::new();
        driver.add_file(b"/proc/100/loginuid", b"1000\n");
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        assert_eq!(procfs.read_loginuid(100).unwrap(), 1000);
    }

    #[test]
    fn test_read_loginuid_fails_on_non_numeric() {
        let mut driver = MockDriver::new();
        driver.add_file(b"/proc/100/loginuid", b"invalid");
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        assert!(procfs.read_loginuid(100).is_err());
    }

    #[test]
    fn test_read_netns_ino_happy_path() {
        let mut driver = MockDriver::new();
        let ino = 1234;
        driver.add_metadata(b"/proc/100/ns/net", MockMetadata { ino });
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        assert_eq!(procfs.read_netns_ino(100).unwrap(), ino);
    }

    #[test]
    fn test_read_netns_ino_fails_on_not_found() {
        let driver = MockDriver::new();
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        let err = procfs.read_netns_ino(100).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn test_symlink_reads_happy_path() {
        let mut driver = MockDriver::new();
        let symlinks: Vec<(
            &[u8],
            &str,
            fn(&Procfs<MockDriver>, u32) -> io::Result<OsPath>,
        )> = vec![
            (b"/proc/100/exe", "target_exe", Procfs::read_exe),
            (b"/proc/100/cwd", "target_cwd", Procfs::read_cwd),
            (b"/proc/100/root", "target_root", Procfs::read_root),
        ];
        for (path, target, _) in &symlinks {
            driver.add_symlink(*path, *target);
        }
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        for (_, expected_target, get_target) in &symlinks {
            let target = get_target(&procfs, 100).unwrap();
            assert_eq!(target.as_os_str(), OsStr::new(expected_target));
        }
    }

    #[test]
    fn test_symlink_reads_fail_on_not_found() {
        let driver = MockDriver::new();
        let mount_path = MountPath::new("/proc".into()).unwrap();
        let procfs = Procfs::new_with_driver(mount_path, driver);
        let get_target_helpers: Vec<fn(&Procfs<MockDriver>, u32) -> io::Result<OsPath>> =
            vec![Procfs::read_exe, Procfs::read_cwd, Procfs::read_root];
        for get_target in get_target_helpers {
            let err = get_target(&procfs, 100).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::NotFound);
        }
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
                let cf = procfs.$method(100, &mut collector).unwrap();
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
    fn test_scan_dir_happy_path() {
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
            .scan_dir(100, b"fd", |entry| {
                entries.push(entry.clone());
                Ok(())
            })
            .unwrap();
        assert_eq!(entries, vec![dir_entry]);
    }
}
