use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt;

const TASK_COMM_LEN: usize = 16;

/// Represent the `comm` value for a task. It is encoded as a pascal string of maximum
/// [TASK_COMM_LEN] - 1 bytes.
#[derive(Copy, Clone, Default)]
pub struct Comm([u8; TASK_COMM_LEN]);

impl Comm {
    pub fn from_file(mut file: File) -> io::Result<Self> {
        let mut comm = Comm::default();
        let mut read_bytes = crate::read::read_exact(&mut file, &mut comm.0[1..])?;
        if read_bytes > 0 && comm.0[read_bytes] == b'\n' {
            read_bytes -= 1;
        }
        comm.0[0] = read_bytes as u8;
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn comm_from_file() {
        let file = File::open("/proc/self/comm").unwrap();
        let _comm = Comm::from_file(file).unwrap();
    }
}
