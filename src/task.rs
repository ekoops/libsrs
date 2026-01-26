use std::ffi::{OsStr, OsString};
use std::io;
use std::ops::Deref;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

const TASK_COMM_LEN: usize = 16;

/// Represent the `comm` value for a task. It is encoded as a pascal string of maximum
/// [TASK_COMM_LEN] - 1 bytes.
#[derive(Copy, Clone, Default)]
pub struct Comm([u8; TASK_COMM_LEN]);

impl Comm {
    /// Create a [Comm] by providing a scratch buffer to `writer`. `writer` must return the amount
    /// of bytes written into the received buffer.
    pub fn from_writer<F>(writer: F) -> io::Result<Self>
    where
        F: FnOnce(&mut [u8]) -> io::Result<usize>,
    {
        let mut comm = Self::default();
        let buff = &mut comm.0[1..];
        let written_bytes = writer(buff)?;
        // Cap written bytes to be sure it is not bigger than buffer size.
        let capped_written_bytes = std::cmp::min(written_bytes, buff.len());
        comm.0[0] = capped_written_bytes as u8;
        Ok(comm)
    }

    pub fn as_os_str(&self) -> &OsStr {
        let len = self.0[0] as usize;
        OsStr::from_bytes(&self.0[1..1 + len])
    }
}

/// A wrapper around [PathBuf] representing a path with a max length of [OsPath::MAX_LEN].
#[derive(Clone, Default)]
pub struct OsPath(PathBuf);

impl OsPath {
    /// Max path length.
    const MAX_LEN: usize = 4096;

    /// Create an [OsPath] by providing a scratch buffer to `writer`. `writer` must return the
    /// amount of bytes written into the received buffer.
    pub fn from_writer<F>(writer: F) -> io::Result<Self>
    where
        F: FnOnce(&mut [u8]) -> io::Result<usize>,
    {
        let mut buff = [0u8; Self::MAX_LEN];
        let written_bytes = writer(&mut buff)?;
        // Cap written bytes to be sure it is not bigger than buffer size.
        let written_bytes = std::cmp::min(written_bytes, buff.len());
        let os_str = OsStr::from_bytes(&buff[..written_bytes]);
        Ok(Self(PathBuf::from(os_str)))
    }

    pub fn as_os_str(&self) -> &OsStr {
        self.0.as_os_str()
    }
}

impl Deref for OsPath {
    type Target = PathBuf;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A wrapper around [OsString] representing the environ content for a process with a max length of
/// [Environ::MAX_LEN].
#[derive(Clone, Default)]
pub struct Environ(OsString);

impl Environ {
    /// Max environ length.
    const MAX_LEN: usize = 4096;

    /// Create an [Environ] by providing a scratch buffer to `writer`. `writer` must return the
    /// amount of bytes written into the received buffer.
    pub fn from_writer<F>(writer: F) -> io::Result<Self>
    where
        F: FnOnce(&mut [u8]) -> io::Result<usize>,
    {
        let mut buff = [0u8; Self::MAX_LEN];
        let written_bytes = writer(&mut buff)?;
        // Cap written bytes to be sure it is not bigger than buffer size.
        let written_bytes = std::cmp::min(written_bytes, buff.len());
        let os_str = OsStr::from_bytes(&buff[..written_bytes]);
        Ok(Self(OsString::from(os_str)))
    }

    pub fn as_os_str(&self) -> &OsStr {
        self.0.as_os_str()
    }
}

impl Deref for Environ {
    type Target = OsString;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Represent a Linux task.
#[derive(Clone)]
pub struct Task {
    _comm: Comm,
    _exe: OsPath,
    _cwd: OsPath,
    _root: OsPath,
    _environ: Environ,
    _loginuid: i32,
}
