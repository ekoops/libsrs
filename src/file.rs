use crate::buffer_writer::FromBufferWriter;
use crate::file::sockets::SocketCollector;
use crate::procfs::Procfs;
use crate::task::{FdTable, OsPath, OpenFile};
use crate::{parse, read};
use libc::{S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFMT, S_IFREG, S_IFSOCK};
use std::ffi::CStr;
use std::io;
use std::net::{SocketAddrV4, SocketAddrV6};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// `AF_INET`/`AF_INET6` socket's layer-4 protocol.
#[derive(Debug, Copy, Clone)]
pub enum L4Protocol {
    Tcp,
    Udp,
    Raw,
}

/// An `AF_INET` socket.
#[derive(Debug, Copy, Clone)]
pub struct InetSocket {
    l4_proto: L4Protocol,
    local_addr: SocketAddrV4,
    remote_addr: SocketAddrV4,
}

impl InetSocket {
    /// Creates a new [Self] with a specific layer-4 protocol, and specific local and remote
    /// addresses.
    pub fn new(l4_proto: L4Protocol, local_addr: SocketAddrV4, remote_addr: SocketAddrV4) -> Self {
        Self {
            l4_proto,
            local_addr,
            remote_addr,
        }
    }

    /// Returns the socket's layer-4 protocol.
    pub fn l4_proto(&self) -> L4Protocol {
        self.l4_proto
    }

    /// Returns the socket's local address.
    pub fn local_addr(&self) -> SocketAddrV4 {
        self.local_addr
    }

    /// Returns the socket's remote address.
    pub fn remote_addr(&self) -> SocketAddrV4 {
        self.remote_addr
    }
}

/// An `AF_INET6` socket.
#[derive(Debug, Copy, Clone)]
pub struct Inet6Socket {
    l4_proto: L4Protocol,
    local_addr: SocketAddrV6,
    remote_addr: SocketAddrV6,
}

impl Inet6Socket {
    /// Creates a new [Self] with a specific layer-4 protocol, and specific local and remote
    /// addresses.
    pub fn new(l4_proto: L4Protocol, local_addr: SocketAddrV6, remote_addr: SocketAddrV6) -> Self {
        Self {
            l4_proto,
            local_addr,
            remote_addr,
        }
    }

    /// Returns the socket's layer-4 protocol.
    pub fn l4_proto(&self) -> L4Protocol {
        self.l4_proto
    }

    /// Returns the socket's local address.
    pub fn local_addr(&self) -> SocketAddrV6 {
        self.local_addr
    }

    /// Returns the socket's remote address.
    pub fn remote_addr(&self) -> SocketAddrV6 {
        self.remote_addr
    }
}

/// An `AF_UNIX` socket.
#[derive(Debug, Clone)]
pub struct UnixSocket {
    path: Option<OsPath>,
    ptr: u64,
    peer_ptr: Option<u64>,
}

impl UnixSocket {
    /// Creates a new [Self] with a specific pointer, peer pointer (if present) and path (if
    /// present).
    pub fn new(path: Option<OsPath>, ptr: u64, peer_ptr: Option<u64>) -> Self {
        Self {
            path,
            ptr,
            peer_ptr,
        }
    }

    /// Returns the socket's path (if present).
    pub fn path(&self) -> Option<&OsPath> {
        self.path.as_ref()
    }

    /// Returns the socket's pointer.
    pub fn ptr(&self) -> u64 {
        self.ptr
    }

    /// Returns the socket's peer pointer (if present).
    pub fn peer_ptr(&self) -> Option<u64> {
        self.peer_ptr
    }
}

/// An `AF_NETLINK` socket.
#[derive(Debug, Copy, Clone)]
pub struct NetlinkSocket;

impl NetlinkSocket {
    /// Creates a new [Self].
    pub fn new() -> Self {
        Self
    }
}

/// A socket.
#[derive(Debug, Clone)]
pub enum Socket {
    /// `AF_INET` socket.
    Inet(InetSocket),
    /// `AF_INET6` socket.
    Inet6(Inet6Socket),
    /// `AF_UNIX` socket.
    Unix(UnixSocket),
    /// `AF_NETLINK` socket.
    Netlink(NetlinkSocket),
}

impl From<InetSocket> for Socket {
    fn from(value: InetSocket) -> Self {
        Self::Inet(value)
    }
}

impl From<Inet6Socket> for Socket {
    fn from(value: Inet6Socket) -> Self {
        Self::Inet6(value)
    }
}

impl From<UnixSocket> for Socket {
    fn from(value: UnixSocket) -> Self {
        Self::Unix(value)
    }
}

impl From<NetlinkSocket> for Socket {
    fn from(value: NetlinkSocket) -> Self {
        Self::Netlink(value)
    }
}

/// A pipe file.
#[derive(Debug, Clone)]
pub struct Pipe {
    path: OsPath,
}

/// Error returned by [Pipe::new].
#[derive(Debug, Clone, thiserror::Error)]
#[error("unexpected path for a pipe")]
pub struct PipeError;

impl Pipe {
    /// Creates a new [Self] with the specified path. `path` must be in the form
    /// `pipe:[<inode_num>]`.
    pub fn new(path: OsPath) -> Result<Self, PipeError> {
        const PIPE_PREFIX: &[u8] = b"pipe:[";
        const PIPE_SUFFIX: &[u8] = b"]";
        const MIN_PATH_LEN: usize = PIPE_PREFIX.len() + PIPE_SUFFIX.len() + 1;
        let path_bytes = path.as_os_str().as_bytes();
        if path_bytes.len() < MIN_PATH_LEN
            || !path_bytes.starts_with(PIPE_PREFIX)
            || !path_bytes.ends_with(PIPE_SUFFIX)
        {
            return Err(PipeError);
        }
        Ok(Self { path })
    }

    /// Returns the pipe's path in the form `pipe:[<inode_num>]`.
    pub fn path(&self) -> &OsPath {
        &self.path
    }
}

/// A memfd file.
#[derive(Debug, Clone)]
pub struct MemFdFile {
    path: OsPath,
}

impl MemFdFile {
    /// Creates a new [Self] with the specified path. `path` must be in the form `/memfd:<name>`.
    /// Returns `Err(path)` if the path does not match the expected form.
    pub fn new(path: OsPath) -> Result<Self, OsPath> {
        const MEMFD_PREFIX: &[u8] = b"/memfd:";
        const MIN_PATH_LEN: usize = MEMFD_PREFIX.len() + 1;
        let path_bytes = path.as_os_str().as_bytes();
        if path_bytes.len() < MIN_PATH_LEN || !path_bytes.starts_with(MEMFD_PREFIX) {
            return Err(path);
        }
        Ok(Self { path })
    }

    /// Returns the memfd file's path in the form `/memfd:<name>`.
    pub fn path(&self) -> &OsPath {
        &self.path
    }
}

/// A regular file.
#[derive(Debug, Clone)]
pub struct RegularFile {
    path: OsPath,
}

impl RegularFile {
    /// Creates a new [Self] with the specified path.
    pub fn new(path: OsPath) -> Self {
        Self { path }
    }

    /// Returns the regular file's path.
    pub fn path(&self) -> &OsPath {
        &self.path
    }
}

/// A directory file.
#[derive(Debug, Clone)]
pub struct Directory {
    path: OsPath,
}

impl Directory {
    /// Creates a new [Self] with the specified path.
    pub fn new(path: OsPath) -> Self {
        Self { path }
    }

    /// Returns the directory's path.
    pub fn path(&self) -> &OsPath {
        &self.path
    }
}

/// File data that depends on the specific file type.
#[derive(Debug, Clone)]
pub enum FileData {
    Socket(Socket),
    Pipe(Pipe),
    MemFd(MemFdFile),
    Regular(RegularFile),
    Directory(Directory),
    EventFd,
    SignalFd,
    EventPoll,
    Inotify,
    TimerFd,
    IoUring,
    UserFaultFd,
    PidFd,
    Bpf,
    Unsupported,
}

/// A generic file representation.
#[derive(Debug, Clone)]
pub struct File {
    file_data: FileData,
    ino: u64,
}

impl File {
    /// Creates a new [Self] with the provided file data and inode number.
    pub fn new(file_data: FileData, ino: u64) -> Self {
        Self { file_data, ino }
    }

    /// Returns the file's type-specific data.
    pub fn data(&self) -> &FileData {
        &self.file_data
    }

    /// Returns the file's inode number.
    pub fn ino(&self) -> u64 {
        self.ino
    }
}

#[inline(always)]
fn inv_data_err(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn read_link(path: &Path, target_buff: &mut [u8]) -> io::Result<usize> {
    // Use a stack-allocated buffer to store a NUL-terminated version of path. This is required by
    // `read::link()`.
    let path_bytes = path.as_os_str().as_bytes();
    let path_bytes_len = path_bytes.len();
    const PATH_BUFF_SIZE: usize = 4096;
    if path_bytes_len >= PATH_BUFF_SIZE {
        return Err(inv_data_err("path too long"));
    }

    let mut path_buff = [0u8; PATH_BUFF_SIZE];
    path_buff[..path_bytes_len].copy_from_slice(path_bytes);
    path_buff[path_bytes_len] = 0;
    let path = unsafe { CStr::from_bytes_with_nul_unchecked(&path_buff[..=path_bytes_len]) };
    read::link(&path, target_buff)
}

fn parse_pipe(fd_table: &mut FdTable, path: &Path, fd: u32, ino: u64) -> io::Result<()> {
    let path = OsPath::from_buffer_writer(|buff: &mut [u8]| read_link(&path, buff))?;
    let pipe = Pipe::new(path).map_err(|e| inv_data_err(e.to_string().as_str()))?;
    let file_data = FileData::Pipe(pipe);
    let file = File::new(file_data, ino);
    fd_table.insert(OpenFile::new(fd, file));
    Ok(())
}

fn parse_regular_file(fd_to_file: &mut FdTable, path: &Path, fd: u32, ino: u64) -> io::Result<()> {
    let path = OsPath::from_buffer_writer(|buff: &mut [u8]| read_link(&path, buff))?;
    let file_data = match MemFdFile::new(path) {
        Ok(memfd_file) => FileData::MemFd(memfd_file),
        Err(path) => {
            // todo(ekoops): add flags handling.
            let reg_file = RegularFile::new(path);
            FileData::Regular(reg_file)
        }
    };
    let file = File::new(file_data, ino);
    fd_to_file.insert(OpenFile::new(fd, file));
    Ok(())
}

fn parse_directory(fd_to_file: &mut FdTable, path: &Path, fd: u32, ino: u64) -> io::Result<()> {
    let path = OsPath::from_buffer_writer(|buff: &mut [u8]| read_link(&path, buff))?;
    let dir = Directory::new(path);
    let file_data = FileData::Directory(dir);
    let file = File::new(file_data, ino);
    fd_to_file.insert(OpenFile::new(fd, file));
    Ok(())
}

fn add_socket(
    fd_to_file: &mut FdTable,
    path: &Path,
    fd: u32,
    ino: u64,
    sock: Socket,
) -> io::Result<()> {
    // todo(ekoops): we should store the socket name (socket[ino]) somewhere...
    let _path = OsPath::from_buffer_writer(|buff: &mut [u8]| read_link(path, buff))?;
    let file_data = FileData::Socket(sock);
    let file = File::new(file_data, ino);
    fd_to_file.insert(OpenFile::new(fd, file));
    Ok(())
}

fn parse_anon_inode_file(fd_to_file: &mut FdTable, name: &[u8], fd: u32, ino: u64) {
    // The following are DJB2 hashes (i.e.: hash = 5381; foreach c: hash = ((hash << 5) + hash) + c;)
    // used to quickly classify an anon inode file based on the hash of its name.
    const HASH_EVENTFD: u32 = 4283080137; // [eventfd]
    const HASH_EVENTPOLL: u32 = 4247027542; // [eventpoll]
    const HASH_INOTIFY: u32 = 2668889575; // inotify
    const HASH_SIGNALFD: u32 = 3769938309; // [signalfd]
    const HASH_TIMERFD: u32 = 7753960; // [timerfd]
    const HASH_IO_URING: u32 = 2266470649; // [io_uring]
    const HASH_USERFAULTFD: u32 = 3373497826; // [userfaultfd]
    const HASH_PIDFD: u32 = 1838784100; // [pidfd]
    const HASH_BPF_MAP: u32 = 2283598536; // bpf-map
    const HASH_BPF_PROG: u32 = 2344434050; // bpf-prog
    const HASH_BPF_LINK: u32 = 2344280472; // bpf-link
    const HASH_BPF_ITER: u32 = 2403480400; // bpf_iter
    const HASH_PERF_EVENT: u32 = 915066027; // [perf_event]

    fn djb2_hash(data: &[u8]) -> u32 {
        data.iter().fold(5381u32, |acc, &x| {
            acc.wrapping_shl(5).wrapping_add(acc).wrapping_add(x as u32)
        })
    }

    let hash = djb2_hash(name);
    let file_data = match hash {
        HASH_EVENTFD => FileData::EventFd,
        HASH_EVENTPOLL => FileData::EventPoll,
        HASH_INOTIFY => FileData::Inotify,
        HASH_SIGNALFD => FileData::SignalFd,
        HASH_TIMERFD => FileData::TimerFd,
        HASH_IO_URING => FileData::IoUring,
        HASH_USERFAULTFD => FileData::UserFaultFd,
        HASH_PIDFD => FileData::PidFd,
        HASH_BPF_MAP | HASH_BPF_PROG | HASH_BPF_LINK | HASH_BPF_ITER => FileData::Bpf,
        HASH_PERF_EVENT => FileData::Unsupported, // Not supported yet.
        _ => FileData::Unsupported,
    };
    let file = File::new(file_data, ino);
    fd_to_file.insert(OpenFile::new(fd, file));
}

fn parse_unsupported_file(
    fd_to_file: &mut FdTable,
    path: &Path,
    fd: u32,
    ino: u64,
) -> io::Result<()> {
    let mut buff = [0u8; 32];
    let bytes_read = read_link(&path, &mut buff[..])?;
    let target = &buff[..bytes_read];

    const ANON_INODE_FILE_PREFIX: &[u8] = b"anon_inode:";
    match target.strip_prefix(ANON_INODE_FILE_PREFIX) {
        Some(name) => parse_anon_inode_file(fd_to_file, name, fd, ino),
        None => {
            let file_data = FileData::Unsupported;
            let file = File::new(file_data, ino);
            fd_to_file.insert(OpenFile::new(fd, file));
        }
    }
    Ok(())
}

mod sockets;

pub fn get_proc_files(
    procfs: &Procfs,
    pid: u32,
    collector: &mut SocketCollector,
) -> io::Result<FdTable> {
    let mut fd_to_file = FdTable::new();
    let mut deferred_sockets: Vec<(u32, u64, PathBuf)> = Vec::new();

    // todo(ekoops): don't stop scanning if an error occurs.
    procfs.scan_dir(pid, b"fd", |dir_entry| {
        let path = dir_entry.path();

        // Get fd.
        let fd = match path.file_name() {
            Some(fd_str) => parse::dec_strict::<u32>(fd_str.as_bytes()),
            None => Err(inv_data_err("cannot extract filename from directory entry")),
        }?;

        let metadata = dir_entry.metadata()?;
        let ino = metadata.ino();
        match metadata.mode() & S_IFMT {
            S_IFIFO => parse_pipe(&mut fd_to_file, &path, fd, ino),
            S_IFREG | S_IFBLK | S_IFCHR | S_IFLNK => {
                parse_regular_file(&mut fd_to_file, &path, fd, ino)
            }
            S_IFDIR => parse_directory(&mut fd_to_file, &path, fd, ino),
            S_IFSOCK => {
                // Socket parsing is deferred after all socket inodes are collected.
                deferred_sockets.push((fd, ino, path));
                Ok(())
            }
            _ => parse_unsupported_file(&mut fd_to_file, &path, fd, ino),
        }
    })?;

    if !deferred_sockets.is_empty() {
        // Retrieve process' network namespace inode number.
        let netns_ino = procfs
            .read_netns_ino(pid)
            .map_err(|_| inv_data_err("cannot gather network namespace inode"))?;

        collector.ensure_populated(
            netns_ino,
            procfs,
            pid,
            deferred_sockets.iter().map(|&(_, ino, _)| ino),
        )?;

        for (fd, sock_ino, path) in deferred_sockets {
            let sock = collector
                .get_socket(netns_ino, sock_ino)
                .ok_or_else(|| inv_data_err("cannot find socket by inode"))?;
            add_socket(&mut fd_to_file, &path, fd, sock_ino, sock)?;
        }
    }

    Ok(fd_to_file)
}
