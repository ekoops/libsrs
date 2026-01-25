use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;

const TASK_COMM_LEN: usize = 16;

/// Represent the `comm` value for a task. It is encoded as a pascal string of maximum
/// [TASK_COMM_LEN] - 1 bytes.
#[derive(Copy, Clone, Default)]
pub struct Comm([u8; TASK_COMM_LEN]);

impl Comm {
    pub fn from_writer<F: FnOnce(&mut [u8]) -> io::Result<usize>>(writer: F) -> io::Result<Self> {
        let mut comm = Self::default();
        let buff_to_write = &mut comm.0[1..];
        let written_bytes = writer(buff_to_write)?;
        // Cap the written bytes to be sure it is not bigger than size of the buffer.
        let written_bytes  = std::cmp::min(written_bytes, buff_to_write.len());
        comm.0[0] = written_bytes as u8;
        Ok(comm)
    }

    pub fn as_os_str(&self) -> &OsStr {
        let len = self.0[0] as usize;
        OsStr::from_bytes(&self.0[1..1 + len])
    }
}

/// Represent a Linux task.
#[derive(Copy, Clone)]
pub struct Task {
    _comm: Comm,
}
