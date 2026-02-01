use crate::buffer_writer::{BufferWriter, FromBufferWriter};
use crate::capped_os_string::CappedOsString;
use std::cmp;
use std::ffi::{OsStr, OsString};
use std::io;
use std::ops::Deref;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

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

impl FromBufferWriter<u8> for Comm {
    fn from_buffer_writer<W: BufferWriter<u8>>(writer: W) -> io::Result<Self> {
        let mut comm = Self::default();
        let buff = &mut comm.0[1..];
        let written_bytes = writer.write(buff)?;
        // Cap written bytes to be sure it is not bigger than buffer size.
        let capped_written_bytes = cmp::min(written_bytes, buff.len());
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

impl FromBufferWriter<u8> for OsPath {
    fn from_buffer_writer<W: BufferWriter<u8>>(writer: W) -> io::Result<Self> {
        let mut buff = vec![0u8; Self::MAX_LEN];
        let written_bytes = writer.write(&mut buff)?;
        // Cap written bytes to be sure it is not bigger than buffer size.
        let written_bytes = cmp::min(written_bytes, buff.len());
        buff.truncate(written_bytes);
        let os_string = OsString::from_vec(buff);
        Ok(Self(PathBuf::from(os_string)))
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

impl FromBufferWriter<u8> for Environ {
    fn from_buffer_writer<W: BufferWriter<u8>>(writer: W) -> io::Result<Self> {
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

impl FromBufferWriter<u8> for Cmdline {
    fn from_buffer_writer<W: BufferWriter<u8>>(writer: W) -> io::Result<Self> {
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

/// A hierarchical stack of IDs representing the process in different PID namespaces.
///
/// The IDs are ordered from the one in outermost PID namespace to the one in the innermost one. The
/// maximum number of IDs is capped by the Linux kernel's `MAX_PID_NS_LEVEL` value, fixed at 32.
#[derive(Copy, Clone, Default)]
pub struct PidNamespaceIds {
    ids: [u32; 32],
    len: u8,
}

impl FromBufferWriter<u32> for PidNamespaceIds {
    fn from_buffer_writer<W: BufferWriter<u32>>(writer: W) -> io::Result<Self> {
        let mut ns_ids = Self::default();
        let ids = &mut ns_ids.ids[..];
        let written_ids = writer.write(ids)?;
        // Cap written IDs to be sure it is not bigger than maximum number of supported IDs.
        let written_ids = cmp::min(written_ids, ids.len());
        if written_ids == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "must have at least one ID",
            ));
        }
        ns_ids.len = written_ids as u8;
        Ok(ns_ids)
    }
}

impl PidNamespaceIds {
    #[inline]
    pub fn as_slice(&self) -> &[u32] {
        &self.ids[..self.len as usize]
    }

    /// Return the ID seen from the outermost PID namespace.
    #[inline]
    pub fn root(&self) -> u32 {
        self.ids[0]
    }

    /// Return the ID seen from the process's current (innermost) PID namespace.
    #[inline]
    pub fn current(&self) -> u32 {
        self.ids[self.len as usize - 1]
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
    _ns_tgids: PidNamespaceIds,
    _ns_pids: PidNamespaceIds,
    _ns_pgids: PidNamespaceIds,
    _loginuid: i32,
}
