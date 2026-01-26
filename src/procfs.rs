use crate::task::{Comm, OsPath};
use std::ffi::{CStr, CString, NulError, OsStr, OsString};
use std::fs::File;
use std::io::{self, Cursor, Write};
use std::os::unix::ffi::OsStrExt;
use thiserror::Error;

/// Error returned by [Procfs::new].
#[derive(Debug, Clone, Error)]
pub enum ProcfsMountPathError {
    #[error(
        "procfs mount path too long (greater than {})",
        ProcfsMountPath::MAX_LEN
    )]
    TooLong,
    #[error(transparent)]
    NulError(#[from] NulError),
}

/// A procfs mount path with max length with a max length of [ProcfsMountPath::MAX_LEN].
pub struct ProcfsMountPath(CString);

impl ProcfsMountPath {
    /// Max allowed procfs mount path length.
    pub const MAX_LEN: usize = 256;

    /// Create a new [ProcfsMountPath] from the specified path.
    pub fn new(path: OsString) -> Result<Self, ProcfsMountPathError> {
        let mut path_bytes = path.as_bytes();
        if path_bytes.last() == Some(&b'/') {
            path_bytes = &path_bytes[..path_bytes.len() - 1];
        }

        if path_bytes.len() > Self::MAX_LEN {
            Err(ProcfsMountPathError::TooLong)
        } else {
            Ok(Self(CString::new(path_bytes)?))
        }
    }
}

/// A helper type allowing to extract data from procfs.
pub struct Procfs {
    mount_path: ProcfsMountPath,
}

impl Procfs {
    /// Create a new [Procfs] instance from the specified procfs `mount_path`.
    pub fn new(mount_path: ProcfsMountPath) -> Self {
        Self { mount_path }
    }

    /// Max length of the string representation of <pid>.
    const MAX_PID_LEN: usize = 10;
    /// Max allowed length for a suffix after <mount_path>/<pid>/ (see [PATH_BUFF_SIZE]).
    const MAX_SUFFIX_LEN: usize = 32;
    /// Safety margin accounting for '/'s and trailing zeros in procfs path (see [PATH_BUFF_SIZE]).
    const PADDING: usize = 16;
    /// The size of the buffer used to construct procfs file paths. The buffer content is structured
    /// in the following way: <mount_path>/<pid>/<suffix><zero_pad>.
    const PATH_BUFF_SIZE: usize =
        ProcfsMountPath::MAX_LEN + Self::MAX_PID_LEN + Self::MAX_SUFFIX_LEN + Self::PADDING;

    /// Create a new path buffer.
    #[inline]
    fn new_path_buff() -> [u8; Self::PATH_BUFF_SIZE] {
        [0u8; Self::PATH_BUFF_SIZE]
    }

    /// Write the mount path into the `cursor`.
    fn write_mount_path(&self, cursor: &mut Cursor<&mut [u8]>) -> io::Result<()> {
        let prefix_bytes = self.mount_path.0.as_bytes();
        cursor.write_all(prefix_bytes)
    }

    /// Write the string representation of `pid` into `cursor`.
    fn write_pid(cursor: &mut Cursor<&mut [u8]>, pid: u32) -> io::Result<()> {
        let mut fmt_buff = itoa::Buffer::new();
        let pid_str = fmt_buff.format(pid);
        cursor.write_all(pid_str.as_bytes())
    }

    /// Write the mount path and `pid` into `cursor`, separating them with a `/`.
    fn write_mount_path_and_pid(&self, cursor: &mut Cursor<&mut [u8]>, pid: u32) -> io::Result<()> {
        self.write_mount_path(cursor)?;
        cursor.write_all(b"/")?;
        Self::write_pid(cursor, pid)
    }

    /// Return the content read from `<procfs_mount_path>/<pid>/comm` for `pid`.
    pub fn read_comm(&self, pid: u32) -> io::Result<Comm> {
        let mut path_buff = Self::new_path_buff();
        let mut cursor = Cursor::new(&mut path_buff[..]);
        self.write_mount_path_and_pid(&mut cursor, pid)?;
        cursor.write_all(b"/comm")?;
        let written_bytes = cursor.position() as usize;
        let path = OsStr::from_bytes(&path_buff[..written_bytes]);
        let mut file = File::open(path)?;
        Comm::from_writer(|buff| -> io::Result<usize> {
            let mut read_bytes = crate::read::read_exact(&mut file, buff)?;
            if read_bytes > 0 && buff[read_bytes - 1] == b'\n' {
                read_bytes -= 1;
            }
            Ok(read_bytes)
        })
    }

    /// Return the content of the symbolic link `<procfs_mount_path>/<pid>/exe` for `pid`.
    pub fn read_exe(&self, pid: u32) -> io::Result<OsPath> {
        let mut path_buff = Self::new_path_buff();
        let mut cursor = Cursor::new(&mut path_buff[..]);
        self.write_mount_path_and_pid(&mut cursor, pid)?;
        cursor.write_all(b"/exe")?;
        let path = CStr::from_bytes_until_nul(&path_buff)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        OsPath::from_writer(|buff| -> io::Result<usize> {
            return crate::read::readlink(path, buff);
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn procfs() -> Procfs {
        let mount_path = ProcfsMountPath::new(OsString::from("/proc")).unwrap();
        Procfs::new(mount_path)
    }

    #[test]
    fn read_comm() {
        let procfs = procfs();
        let pid = std::process::id();
        let _comm = procfs.read_comm(pid).unwrap();
    }

    #[test]
    fn read_exe() {
        let procfs = procfs();
        let pid = std::process::id();
        let _exe = procfs.read_exe(pid).unwrap();
    }
}
