use crate::buffer_writer::{BufferWriter, FromBufferWriter};
use crate::capped_os_string::CappedOsString;
use crate::parse;
use crate::procfs::Procfs;
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

/// Maximum number of nested PID namespaces. Taken from Linux kernel:
/// https://elixir.bootlin.com/linux/v6.18.6/source/include/linux/pid_namespace.h#L15
const MAX_PID_NS_LEVEL: usize = 32;

/// A hierarchical stack of IDs representing the process in different PID namespaces.
///
/// The IDs are ordered from the one in outermost PID namespace to the one in the innermost one. The
/// maximum number of IDs is capped by the Linux kernel's `MAX_PID_NS_LEVEL` value, fixed at 32.
#[derive(Copy, Clone, Default)]
pub struct PidNamespaceIds {
    ids: [u32; MAX_PID_NS_LEVEL],
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

/// Container for data taken from procfs' status file.
#[allow(dead_code)]
#[derive(Default)]
struct TaskProcfsStatus {
    tgid: u32,
    ruid: u32,
    euid: u32,
    suid: u32,
    fsuid: u32,
    rgid: u32,
    egid: u32,
    sgid: u32,
    fsgid: u32,
    cap_inh: u64,
    cap_prm: u64,
    cap_eff: u64,
    ppid: u32,
    vm_size_kb: u64,
    vm_rss_kb: u64,
    vm_swap_kb: u64,
    ns_pids: PidNamespaceIds,
    ns_pgids: PidNamespaceIds,
    ns_tgids: PidNamespaceIds,
}

impl TaskProcfsStatus {
    fn parse_pids_from_line(mut line: &[u8]) -> io::Result<PidNamespaceIds> {
        PidNamespaceIds::from_buffer_writer(|buff: &mut [u32]| {
            let mut num_pids = 0;
            while let Ok(pid) = parse::next_dec(&mut line) {
                if num_pids == MAX_PID_NS_LEVEL {
                    break;
                }
                buff[num_pids] = pid;
                num_pids += 1;
            }
            Ok(num_pids)
        })
    }

    /// Parse a single line from procfs' status file and updates the corresponding field.
    fn update_from_line(&mut self, line: &[u8]) -> io::Result<()> {
        let Some(&first_char) = line.first() else {
            return Ok(());
        };

        match first_char {
            b'T' => {
                if let Some(line) = line.strip_prefix(b"Tgid:") {
                    self.tgid = parse::dec(line)?;
                }
            }
            b'U' => {
                if let Some(mut line) = line.strip_prefix(b"Uid:") {
                    self.ruid = parse::next_dec(&mut line)?;
                    self.euid = parse::next_dec(&mut line)?;
                    self.suid = parse::next_dec(&mut line)?;
                    self.fsuid = parse::next_dec(&mut line)?;
                }
            }
            b'G' => {
                if let Some(mut line) = line.strip_prefix(b"Gid:") {
                    self.rgid = parse::next_dec(&mut line)?;
                    self.egid = parse::next_dec(&mut line)?;
                    self.sgid = parse::next_dec(&mut line)?;
                    self.fsgid = parse::next_dec(&mut line)?;
                }
            }
            b'C' => {
                let Some(line) = line.strip_prefix(b"Cap") else {
                    return Ok(());
                };
                if let Some(line) = line.strip_prefix(b"Inh:") {
                    self.cap_inh = parse::hex(line)?;
                } else if let Some(line) = line.strip_prefix(b"Prm:") {
                    self.cap_prm = parse::hex(line)?;
                } else if let Some(line) = line.strip_prefix(b"Eff:") {
                    self.cap_eff = parse::hex(line)?;
                }
            }
            b'P' => {
                if let Some(line) = line.strip_prefix(b"PPid:") {
                    self.ppid = parse::dec(line)?;
                }
            }
            b'V' => {
                let Some(line) = line.strip_prefix(b"Vm") else {
                    return Ok(());
                };
                if let Some(line) = line.strip_prefix(b"Size:") {
                    self.vm_size_kb = parse::dec(line)?;
                } else if let Some(line) = line.strip_prefix(b"RSS:") {
                    self.vm_rss_kb = parse::dec(line)?;
                } else if let Some(line) = line.strip_prefix(b"Swap:") {
                    self.vm_swap_kb = parse::dec(line)?;
                }
            }
            b'N' => {
                let Some(line) = line.strip_prefix(b"NS") else {
                    return Ok(());
                };
                if let Some(mut line) = line.strip_prefix(b"pid:") {
                    self.ns_pids = Self::parse_pids_from_line(&mut line)?;
                } else if let Some(mut line) = line.strip_prefix(b"pgid:") {
                    self.ns_pgids = Self::parse_pids_from_line(&mut line)?;
                } else if let Some(mut line) = line.strip_prefix(b"tgid:") {
                    self.ns_tgids = Self::parse_pids_from_line(&mut line)?;
                }
            }
            _ => return Ok(()),
        };
        Ok(())
    }
}

/// Represent a Linux task.
#[allow(dead_code)]
#[derive(Clone)]
pub struct Task {
    comm: Comm,
    exe: OsPath,
    cwd: OsPath,
    root: OsPath,
    environ: Environ,
    cmdline: Cmdline,
    loginuid: i32,
    tgid: u32,
    ruid: u32,
    euid: u32,
    suid: u32,
    fsuid: u32,
    rgid: u32,
    egid: u32,
    sgid: u32,
    fsgid: u32,
    cap_inh: u64,
    cap_prm: u64,
    cap_eff: u64,
    ppid: u32,
    vm_size_kb: u64,
    vm_rss_kb: u64,
    vm_swap_kb: u64,
    ns_pids: PidNamespaceIds,
    ns_pgids: PidNamespaceIds,
    ns_tgids: PidNamespaceIds,
}

impl Task {
    /// Create [Self] for `pid` by gathering data from `procfs`.
    pub fn from_procfs(procfs: &Procfs, pid: u32) -> io::Result<Self> {
        let mut procfs_status = TaskProcfsStatus::default();
        procfs.scan_status(pid, |line: &[u8]| {
            // todo: extend LineProcessor to allow to return an io::Result
            procfs_status.update_from_line(line).unwrap()
        })?;
        let task = Self {
            comm: procfs.read_comm(pid)?,
            exe: procfs.read_exe(pid)?,
            cwd: procfs.read_cwd(pid)?,
            root: procfs.read_root(pid)?,
            environ: procfs.read_environ(pid)?,
            cmdline: procfs.read_cmdline(pid)?,
            loginuid: procfs.read_loginuid(pid)? as i32,
            tgid: procfs_status.tgid,
            ruid: procfs_status.ruid,
            euid: procfs_status.euid,
            suid: procfs_status.suid,
            fsuid: procfs_status.fsuid,
            rgid: procfs_status.rgid,
            egid: procfs_status.egid,
            sgid: procfs_status.sgid,
            fsgid: procfs_status.fsgid,
            cap_inh: procfs_status.cap_inh,
            cap_prm: procfs_status.cap_prm,
            cap_eff: procfs_status.cap_eff,
            ppid: procfs_status.ppid,
            vm_size_kb: procfs_status.vm_size_kb,
            vm_rss_kb: procfs_status.vm_rss_kb,
            vm_swap_kb: procfs_status.vm_swap_kb,
            ns_pids: procfs_status.ns_pids,
            ns_pgids: procfs_status.ns_pgids,
            ns_tgids: procfs_status.ns_tgids,
        };
        Ok(task)
    }
}
