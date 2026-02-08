use crate::buffer_writer::FromBufferWriter;
use crate::read::LineProcessor;
use crate::task::{Cmdline, Comm, Environ, OsPath};
use crate::{parse, read};
use lexical_core::FormattedSize;
use std::ffi::{CStr, CString, NulError, OsStr, OsString};
use std::fs::File;
use std::io;
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
pub trait Driver {
    type Reader: io::Read;

    /// Create a [Self::Reader] for `path`.
    ///
    /// `path` is the non-NUL-terminated binary string representation of a file path.
    fn open(&self, path: &[u8]) -> io::Result<Self::Reader>;

    /// Return the content of the symbolic link at `path` and store it in `buff`.
    ///
    /// `path` is the NUL-terminated binary string representation of a file path.
    fn read_symlink(&self, path: &CStr, buff: &mut [u8]) -> io::Result<usize>;
}

/// The canonical [Driver] implementation.
pub struct RealDriver;

impl Driver for RealDriver {
    type Reader = File;

    #[inline(always)]
    fn open(&self, path: &[u8]) -> io::Result<Self::Reader> {
        let path = OsStr::from_bytes(path);
        File::open(path)
    }

    #[inline(always)]
    fn read_symlink(&self, path: &CStr, buff: &mut [u8]) -> io::Result<usize> {
        read::link(path, buff)
    }
}

/// A helper type allowing to extract data from procfs. If unspecified, it leverages [ReadDriver]
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

/// Max length of the string representation of <pid>.
const MAX_PID_LEN: usize = u32::FORMATTED_SIZE_DECIMAL;
/// Max allowed length for a suffix after <mount_path>/<pid>/ (see [PATH_BUFF_SIZE]).
const MAX_SUFFIX_LEN: usize = 32;
/// Safety margin accounting for `/`s and trailing zeros in procfs path (see [PATH_BUFF_SIZE]).
const PADDING: usize = 16;
/// The size of the buffer used to construct procfs file paths. The buffer content is structured
/// in the following way: <mount_path>/<pid>/<suffix><zero_pad>.
const PATH_BUFF_SIZE: usize = MountPath::MAX_LEN + MAX_PID_LEN + MAX_SUFFIX_LEN + PADDING;

/// The size of the stack-allocated scratch buffer used to read the content of status files (i.e.:
/// /proc/<pid>/status).
const STATUS_SCAN_BUFF_SIZE: usize = 4 * 1024;
/// The size of the stack-allocated scratch buffer used to read the content of socket table files
/// (e.g.: /proc/<pid>/net/tcp).
const SOCKET_TABLE_SCAN_BUFF_SIZE: usize = 32 * 1024;

macro_rules! scan_impl {
    ($fn_name:ident, $path:literal, $buff_size:ident) => {
        #[doc = concat!("Scan each line of `<procfs_mount_path>/<pid>/", $path,
                                                    "` for `pid` and pass it to `line_processor`.")]
        pub fn $fn_name<P>(&self, pid: u32, line_processor: P) -> io::Result<()>
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

// todo: the following tests are not written well. It's just a shallow way of verifying that
//   implementations don't panic on common scenarios. Add comprehensive tests.
#[cfg(test)]
mod tests {
    use super::*;
    use std::process;

    fn procfs() -> Procfs {
        let mount_path = MountPath::new(OsString::from("/proc")).unwrap();
        Procfs::new(mount_path)
    }

    #[test]
    fn read_comm() {
        let procfs = procfs();
        let pid = process::id();
        let _comm = procfs.read_comm(pid).unwrap();
    }

    #[test]
    fn read_exe() {
        let procfs = procfs();
        let pid = process::id();
        let _exe = procfs.read_exe(pid).unwrap();
    }

    #[test]
    fn read_cwd() {
        let procfs = procfs();
        let pid = process::id();
        let _cwd = procfs.read_cwd(pid).unwrap();
    }

    #[test]
    fn read_root() {
        let procfs = procfs();
        let pid = process::id();
        let _root = procfs.read_root(pid).unwrap();
    }

    #[test]
    fn read_loginuid() {
        let procfs = procfs();
        let pid = process::id();
        let _loginuid = procfs.read_loginuid(pid).unwrap() as i32;
    }

    #[test]
    fn read_cmdline() {
        let procfs = procfs();
        let pid = process::id();
        let _cmdline = procfs.read_cmdline(pid).unwrap();
    }

    #[test]
    fn scan_status() {
        let procfs = procfs();
        let pid = process::id();
        struct Counter {
            counter: usize,
        }
        impl LineProcessor for &mut Counter {
            fn process(&mut self, _: &[u8]) {
                self.counter += 1;
            }
        }
        let mut counter = Counter { counter: 0 };
        procfs.scan_status(pid, &mut counter).unwrap();
    }
}
