use crate::buffer_writer::FromBufferWriter;
use crate::fs::{DirEntry, FileType, OpenFlags};
use crate::parse;
use crate::procfs::ProcView;
use crate::task::{FdTable, OpenFile, OsPath};
use std::io;
use std::net::{SocketAddrV4, SocketAddrV6};
use std::ops::ControlFlow;
use std::os::unix::ffi::OsStrExt;

pub use crate::file::sockets::{SocketCollectionStrategy, SocketCollector};

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
#[derive(Default, Debug, Copy, Clone)]
pub struct NetlinkSocket;

impl NetlinkSocket {
    /// Creates a new [Self].
    pub fn new() -> Self {
        Default::default()
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
    flags: OpenFlags,
    mount_id: u32,
}

impl RegularFile {
    /// Creates a new [Self] with the specified path, open flags and mount id.
    pub fn new(path: OsPath, flags: OpenFlags, mount_id: u32) -> Self {
        Self {
            path,
            flags,
            mount_id,
        }
    }

    /// Returns the regular file's path.
    pub fn path(&self) -> &OsPath {
        &self.path
    }

    /// Returns the regular file's open flags.
    pub fn flags(&self) -> OpenFlags {
        self.flags
    }

    /// Returns the regular file's mount id.
    pub fn mount_id(&self) -> u32 {
        self.mount_id
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

fn read_symlink_target(dir_entry: &DirEntry) -> io::Result<OsPath> {
    OsPath::from_buffer_writer(|buff: &mut [u8]| dir_entry.read_symlink_target(buff))
}

fn inv_data_err(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Adds the open pipe file represented by `fd` and `dir_entry` to `fd_table`.
fn add_pipe(fd_table: &mut FdTable, fd: u32, dir_entry: &DirEntry) -> io::Result<()> {
    let path = read_symlink_target(dir_entry)?;
    let pipe = Pipe::new(path).map_err(|e| inv_data_err(e.to_string().as_str()))?;
    let file_data = FileData::Pipe(pipe);
    let file = File::new(file_data, dir_entry.ino());
    fd_table.insert(OpenFile::new(fd, file));
    Ok(())
}

/// Parses the provided raw open flags.
fn parse_regular_file_flags(flags: u64) -> OpenFlags {
    OpenFlags::from_bits_truncate(flags as _)
}

/// Extracts information from procfs about the open regular file represented by `fd`.
fn read_regular_file_data(proc_view: &ProcView<'_>, fd: u32, path: OsPath) -> io::Result<FileData> {
    let (mut flags, mut mount_id) = (None, None);
    // note: explicitly ignore the returned control flow.
    let _ = proc_view.scan_fdinfo_fd(fd, |line: &[u8]| {
        let Some(&first_byte) = line.first() else {
            return Ok(ControlFlow::Continue(()));
        };
        match first_byte {
            b'f' => {
                if let Some(line) = line.strip_prefix(b"flags:") {
                    flags = Some(parse_regular_file_flags(parse::oct(line)?));
                }
            }
            b'm' => {
                if let Some(line) = line.strip_prefix(b"mnt_id:") {
                    mount_id = Some(parse::dec(line)?);
                }
            }
            _ => return Ok(ControlFlow::Continue(())),
        }
        if flags.is_some() && mount_id.is_some() {
            Ok(ControlFlow::Break(()))
        } else {
            Ok(ControlFlow::Continue(()))
        }
    })?;
    let (flags, mount_id) = (
        flags.unwrap_or(OpenFlags::empty()),
        mount_id.unwrap_or_default(),
    );
    let reg_file = RegularFile::new(path, flags, mount_id);
    Ok(FileData::Regular(reg_file))
}

/// Adds the open regular file represented by `fd` and `dir_entry` to `fd_table`.
fn add_regular_file(
    fd_table: &mut FdTable,
    proc_view: &ProcView<'_>,
    fd: u32,
    dir_entry: &DirEntry,
) -> io::Result<()> {
    let path = read_symlink_target(dir_entry)?;
    let file_data = match MemFdFile::new(path) {
        Ok(memfd_file) => FileData::MemFd(memfd_file),
        Err(path) => read_regular_file_data(proc_view, fd, path)?,
    };
    let file = File::new(file_data, dir_entry.ino());
    fd_table.insert(OpenFile::new(fd, file));
    Ok(())
}

/// Adds the open directory file represented by `fd` and `dir_entry` to `fd_table`.
fn add_directory(fd_table: &mut FdTable, fd: u32, dir_entry: &DirEntry) -> io::Result<()> {
    let path = read_symlink_target(dir_entry)?;
    let dir = Directory::new(path);
    let file_data = FileData::Directory(dir);
    let file = File::new(file_data, dir_entry.ino());
    fd_table.insert(OpenFile::new(fd, file));
    Ok(())
}

/// Adds the open socket file represented by `fd` and `dir_entry` to `fd_table`.
fn add_socket(
    fd_table: &mut FdTable,
    fd: u32,
    ino: u64,
    _path: OsPath, // todo(ekoops): we should store the socket path (socket[ino]) somewhere...
    sock: Socket,
) -> io::Result<()> {
    let file_data = FileData::Socket(sock);
    let file = File::new(file_data, ino);
    fd_table.insert(OpenFile::new(fd, file));
    Ok(())
}

/// Adds the open anon inode file represented by `fd` to `fd_table`. `file_type` is obtained by
/// stripping the `anon_inode:` prefix to the symbolic link pointing to the file. `ino` is the
/// file's inode number.
fn add_anon_inode_file(fd_table: &mut FdTable, fd: u32, file_type: &[u8], ino: u64) {
    // Use DJB2 hashes (i.e.: hash = 5381; foreach c: hash = ((hash << 5) + hash) + c;) to quickly
    // classify an anon inode file based on the hash of its "file type". The following are
    // pre-computed hashes for well-known anon inode file types.
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

    let hash = djb2_hash(file_type);
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
    fd_table.insert(OpenFile::new(fd, file));
}

/// Adds the open unsupported file represented by `dir_entry` to `fd_table`.
fn add_unsupported_file(fd_table: &mut FdTable, fd: u32, dir_entry: &DirEntry) -> io::Result<()> {
    let mut buff = [0u8; 32];
    let bytes_read = dir_entry.read_symlink_target(&mut buff[..])?;
    let target = &buff[..bytes_read];
    let ino = dir_entry.ino();

    const ANON_INODE_FILE_PREFIX: &[u8] = b"anon_inode:";
    match target.strip_prefix(ANON_INODE_FILE_PREFIX) {
        Some(file_type) => add_anon_inode_file(fd_table, fd, file_type, ino),
        None => {
            let file_data = FileData::Unsupported;
            let file = File::new(file_data, ino);
            fd_table.insert(OpenFile::new(fd, file));
        }
    }
    Ok(())
}

/// Represents a socket whose addition to the fd table has been deferred.
#[derive(Debug, Clone)]
struct DeferredSocket {
    fd: u32,
    ino: u64,
    path: OsPath,
}

/// Adds the open socket file represented by `fd` and `dir_entry` to `deferred_sockets`.
fn defer_socket(
    deferred_sockets: &mut Vec<DeferredSocket>,
    fd: u32,
    dir_entry: &DirEntry,
) -> io::Result<()> {
    let path = read_symlink_target(dir_entry)?;
    let ino = dir_entry.ino();
    deferred_sockets.push(DeferredSocket { fd, ino, path });
    Ok(())
}

mod sockets;

/// Retrieves the fd table of the process associated with `proc_view`. The set of retrieved sockets,
/// whose collection is managed by `collector`, is limited to the ones belonging to the current
/// network namespace of the process' main task.
pub fn get_proc_files(
    proc_view: &ProcView<'_>,
    collector: &mut SocketCollector,
) -> io::Result<FdTable> {
    let mut fd_table = FdTable::new();
    // Socket parsing is deferred after all socket inodes are collected.
    let mut deferred_sockets: Vec<DeferredSocket> = Vec::new();

    // todo(ekoops): don't stop scanning if an error occurs.
    proc_view.scan_fd_dir(|dir_entry| {
        // Extract fd and file type.
        let fd = parse::dec_strict::<u32>(dir_entry.file_name().to_bytes())?;
        let file_type = dir_entry.read_file_type()?;
        match file_type {
            FileType::Fifo => add_pipe(&mut fd_table, fd, dir_entry),
            FileType::RegularFile
            | FileType::BlockDevice
            | FileType::CharacterDevice
            | FileType::Symlink => add_regular_file(&mut fd_table, proc_view, fd, dir_entry),
            FileType::Directory => add_directory(&mut fd_table, fd, dir_entry),
            FileType::Socket => defer_socket(&mut deferred_sockets, fd, dir_entry),
            _ => add_unsupported_file(&mut fd_table, fd, dir_entry),
        }
    })?;

    if deferred_sockets.is_empty() {
        return Ok(fd_table);
    }

    // Retrieve process' network namespace inode number.
    let netns_ino = proc_view
        .read_netns_ino()
        .map_err(|_| inv_data_err("cannot gather network namespace inode"))?;

    collector.ensure_populated(
        netns_ino,
        proc_view,
        deferred_sockets.iter().map(|sock| sock.ino),
    )?;

    for DeferredSocket { fd, ino, path } in deferred_sockets {
        let sock = collector
            .get_socket(netns_ino, ino)
            .ok_or_else(|| inv_data_err("cannot find socket by inode"))?;
        add_socket(&mut fd_table, fd, ino, path, sock)?;
    }

    Ok(fd_table)
}
