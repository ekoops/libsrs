use crate::task::OsPath;
use std::net::{SocketAddrV4, SocketAddrV6};
use std::os::unix::ffi::OsStrExt;

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
