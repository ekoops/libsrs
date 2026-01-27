use crate::buffer_writer::{BufferWriter, FromBufferWriter};
use std::ffi::{OsStr, OsString};
use std::io;
use std::ops::Deref;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use crate::capped_os_string::CappedOsString;

const TASK_COMM_LEN: usize = 16;

/// Represent the `comm` value for a task. It is encoded as a pascal string of maximum
/// [TASK_COMM_LEN] - 1 bytes.
#[derive(Copy, Clone, Default)]
pub struct Comm([u8; TASK_COMM_LEN]);

impl Comm {
    pub fn as_os_str(&self) -> &OsStr {
        let len = self.0[0] as usize;
        OsStr::from_bytes(&self.0[1..1 + len])
    }
}

impl FromBufferWriter for Comm {
    fn from_buffer_writer<W: BufferWriter>(writer: W) -> io::Result<Self> {
        let mut comm = Self::default();
        let buff = &mut comm.0[1..];
        let written_bytes = writer.write(buff)?;
        // Cap written bytes to be sure it is not bigger than buffer size.
        let capped_written_bytes = std::cmp::min(written_bytes, buff.len());
        comm.0[0] = capped_written_bytes as u8;
        Ok(comm)
    }
}

/// A wrapper around [PathBuf] representing a path with a max length of [OsPath::MAX_LEN].
#[derive(Clone, Default)]
pub struct OsPath(PathBuf);

impl OsPath {
    /// Max path length.
    const MAX_LEN: usize = 4096;

    pub fn as_os_str(&self) -> &OsStr {
        self.0.as_os_str()
    }
}

impl FromBufferWriter for OsPath {
    fn from_buffer_writer<W: BufferWriter>(writer: W) -> io::Result<Self> {
        let mut buff = [0u8; Self::MAX_LEN];
        let written_bytes = writer.write(&mut buff)?;
        // Cap written bytes to be sure it is not bigger than buffer size.
        let written_bytes = std::cmp::min(written_bytes, buff.len());
        let os_str = OsStr::from_bytes(&buff[..written_bytes]);
        Ok(Self(PathBuf::from(os_str)))
    }
}

impl Deref for OsPath {
    type Target = PathBuf;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

const MAX_ENVIRON_LEN: usize = 4096;

/// A wrapper around [CappedOsString<MAX_ENVIRON_LEN>] representing the environ content for a
/// process.
#[derive(Clone, Default)]
pub struct Environ(CappedOsString<MAX_ENVIRON_LEN>);

impl FromBufferWriter for Environ {
    fn from_buffer_writer<W: BufferWriter>(writer: W) -> io::Result<Self> {
        let capped_os_string = CappedOsString::from_buffer_writer(writer)?;
        Ok(Self(capped_os_string))
    }
}

impl Deref for Environ {
    type Target = OsString;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

const MAX_CMDLINE_LEN: usize = 4096;

/// A wrapper around [CappedOsString<MAX_CMDLINE_LEN>] representing the cmdline content for a
/// process.
#[derive(Clone, Default)]
pub struct Cmdline(CappedOsString<MAX_CMDLINE_LEN>);

impl FromBufferWriter for Cmdline {
    fn from_buffer_writer<W: BufferWriter>(writer: W) -> io::Result<Self> {
        let capped_os_string = CappedOsString::from_buffer_writer(writer)?;
        Ok(Self(capped_os_string))
    }
}

impl Deref for Cmdline {
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
    _cmdline: Cmdline,
    _loginuid: i32,
}
