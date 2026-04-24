use crate::file::{Inet6Socket, InetSocket, L4Protocol, NetlinkSocket, Socket, UnixSocket};
use crate::parse;
use crate::procfs::Procfs;
use crate::read::LineProcessor;
use crate::task::OsPath;
use std::collections::{hash_map, HashMap, HashSet};
use std::ffi::OsStr;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::ops::ControlFlow;
use std::os::unix::ffi::OsStrExt;
use std::{io, mem};

type InodeToSocketMap = HashMap<u64, Socket>;
type NetnsSocketsMap = HashMap<u64, InodeToSocketMap>;

/// The outcome of evaluating a socket inode, used to guide the parsing flow.
#[derive(Copy, Clone)]
enum Verdict {
    /// Parse the item.
    Parse,
    /// Skip the item.
    Skip,
    /// Abort the parsing process.
    Abort,
}

impl Verdict {
    /// Converts [self] into a [ControlFlow] value to be propagated, or `None` if parsing should
    /// proceed normally.
    fn into_control_flow(self) -> Option<ControlFlow<()>> {
        match self {
            Verdict::Parse => None,
            Verdict::Skip => Some(ControlFlow::Continue(())),
            Verdict::Abort => Some(ControlFlow::Break(())),
        }
    }
}

/// Returns an iterator over chunks of `bytes` obtained by splitting it by ASCII whitespaces. Empty
/// chunks are discarded.
fn split_by_ascii_whitespace(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes
        .split(u8::is_ascii_whitespace)
        .filter(|chunk| !chunk.is_empty())
}

/// Constructs a [SocketAddrV4] from the `<hex_ipv4_address>:<hex_port>` inet socket table string
/// representation of it.
fn parse_inet_socket_table_ipv4_addr(buff: &[u8]) -> io::Result<SocketAddrV4> {
    let mut fields = buff.split(|&b| b == b':');

    // Collect fields.
    let ip_field = fields.next().ok_or(io::ErrorKind::InvalidData)?;
    let port_field = fields.next().ok_or(io::ErrorKind::InvalidData)?;

    // Parse fields.
    let ip = parse::hex_strict::<u32>(ip_field)?;
    let ip = Ipv4Addr::from(ip.to_ne_bytes());
    let port = parse::hex_strict::<u16>(port_field)?;

    Ok(SocketAddrV4::new(ip, port))
}

/// Parses a line from an inet socket table (e.g.: `/proc/<pid>/net/{tcp,udp,raw}`) and adds the
/// obtained socket information to `sockets`. `eval_sock_ino` determines if the socket should be
/// parsed or not, depending on its inode number.
fn parse_inet_socket_table_line(
    sockets: &mut InodeToSocketMap,
    proto: L4Protocol,
    eval_sock_ino: &mut impl FnMut(u64) -> Verdict,
    line: &[u8],
) -> io::Result<ControlFlow<()>> {
    let mut fields = split_by_ascii_whitespace(line);

    // Collect fields.
    // Skip `sl` field and take `local_address` and `remote_address`. Skip `st`, `tx_queue`, `tr`,
    // `retrnsmt`, `uid` and `timeout` fields and take `inode`.
    let local_address_field = fields.nth(1).ok_or(io::ErrorKind::InvalidData)?;
    let remote_address_field = fields.next().ok_or(io::ErrorKind::InvalidData)?;
    let inode_field = fields.nth(6).ok_or(io::ErrorKind::InvalidData)?;

    // Parse inode number first to determine if this is a socket to take into consideration.
    let ino = parse::dec_strict::<u64>(inode_field)?;
    if let Some(cf) = eval_sock_ino(ino).into_control_flow() {
        return Ok(cf);
    }

    // Parse remaining fields.
    let local_address = parse_inet_socket_table_ipv4_addr(local_address_field)?;
    let remote_address = parse_inet_socket_table_ipv4_addr(remote_address_field)?;

    let in_sock = InetSocket::new(proto, local_address, remote_address);
    sockets.insert(ino, in_sock.into());
    Ok(ControlFlow::Continue(()))
}

/// Constructs a [SocketAddrV6] from the `<hex_ipv6_address>:<hex_port>` inet6 socket table string
/// representation of it.
fn parse_inet6_socket_table_ipv6_addr(buff: &[u8]) -> io::Result<SocketAddrV6> {
    let mut fields = buff.split(|&b| b == b':');

    // Collect fields.
    let ip_field = fields.next().ok_or(io::ErrorKind::InvalidData)?;
    let port_field = fields.next().ok_or(io::ErrorKind::InvalidData)?;

    // IPv6 address must be made of 32 hex characters.
    if ip_field.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid IPv6 address",
        ));
    }

    // Parse the IPv6 address in 4 distinct 32-bit chunks.
    let mut octets = [0u8; 16];
    for i in 0..4 {
        let chunk = &ip_field[i * 8..(i + 1) * 8];
        let group = parse::hex_strict::<u32>(chunk)?;
        octets[i * 4..(i + 1) * 4].copy_from_slice(&group.to_ne_bytes());
    }

    let ip = Ipv6Addr::from(octets);
    let port = parse::hex_strict::<u16>(port_field)?;

    // flowinfo and scope_id are not used and set to zero.
    Ok(SocketAddrV6::new(ip, port, 0, 0))
}

/// Parses a line from an inet6 socket table (e.g.: `/proc/<pid>/net/{tcp6,udp6,raw6`}) and adds the
/// obtained socket information to `sockets`. `eval_sock_ino` determines if the socket should be
/// parsed or not, depending on its inode number.
fn parse_inet6_socket_table_line(
    sockets: &mut InodeToSocketMap,
    proto: L4Protocol,
    eval_sock_ino: &mut impl FnMut(u64) -> Verdict,
    line: &[u8],
) -> io::Result<ControlFlow<()>> {
    let mut fields = split_by_ascii_whitespace(line);

    // Collect fields.
    // Skip `sl` field and take `local_address` and `remote_address`. Skip `st`, `tx_queue`, `tr`,
    // `retrnsmt`, `uid` and `timeout` fields and take `inode`.
    let local_address_field = fields.nth(1).ok_or(io::ErrorKind::InvalidData)?;
    let remote_address_field = fields.next().ok_or(io::ErrorKind::InvalidData)?;
    let inode_field = fields.nth(6).ok_or(io::ErrorKind::InvalidData)?;

    // Parse inode number first to determine if this is a socket to take into consideration.
    let ino = parse::dec_strict::<u64>(inode_field)?;
    if let Some(cf) = eval_sock_ino(ino).into_control_flow() {
        return Ok(cf);
    }

    // Parse remaining fields.
    let local_address = parse_inet6_socket_table_ipv6_addr(local_address_field)?;
    let remote_address = parse_inet6_socket_table_ipv6_addr(remote_address_field)?;

    let in6_sock = Inet6Socket::new(proto, local_address, remote_address);
    sockets.insert(ino, in6_sock.into());
    Ok(ControlFlow::Continue(()))
}

/// Parses a line from a unix socket table (i.e.: `/proc/<pid>/net/unix`) and adds the obtained
/// socket information to `sockets`. `eval_sock_ino` determines if the socket should be parsed or
/// not, depending on its inode number.
fn parse_unix_socket_table_line(
    sockets: &mut InodeToSocketMap,
    eval_sock_ino: &mut impl FnMut(u64) -> Verdict,
    line: &[u8],
) -> io::Result<ControlFlow<()>> {
    let mut fields = split_by_ascii_whitespace(line);

    // Collect fields.
    // Take `Num` field representing the source pointer. Skip `RefCount`, `Protocol`, `Flags`,
    // `Type` and `St` fields and take `Inode` field and the `Path` one (if present).
    let num_field = fields.next().ok_or(io::ErrorKind::InvalidData)?;
    let inode_field = fields.nth(5).ok_or(io::ErrorKind::InvalidData)?;
    let path_field = fields.next();

    // Parse inode number first to determine if this is a socket to take into consideration.
    let ino = parse::dec_strict::<u64>(inode_field)?;
    if let Some(cf) = eval_sock_ino(ino).into_control_flow() {
        return Ok(cf);
    }

    // Parse remaining fields.
    let num_field = num_field
        .strip_suffix(b":")
        .ok_or(io::ErrorKind::InvalidData)?;
    let ptr = parse::hex_strict::<u64>(num_field)?;
    let peer_ptr = None; // We do not have access to the peer pointer here.
    let path = path_field
        .map(|p| OsPath::new(OsStr::from_bytes(p)))
        .transpose()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let un_sock = UnixSocket::new(path, ptr, peer_ptr);
    sockets.insert(ino, un_sock.into());
    Ok(ControlFlow::Continue(()))
}

/// Parses a line from a netlink socket table (i.e.: `/proc/<pid>/net/netlink`) and adds the
/// obtained socket information to `sockets`. `eval_sock_ino` determines if the socket should be
/// parsed or not, depending on its inode number.
fn parse_netlink_socket_table_line(
    sockets: &mut InodeToSocketMap,
    eval_sock_ino: &mut impl FnMut(u64) -> Verdict,
    line: &[u8],
) -> io::Result<ControlFlow<()>> {
    let mut fields = split_by_ascii_whitespace(line);

    // Skip `sk`, `Eth`, `Pid`, `Groups`, `Rmem`, `Wmem`, `Dump`, `Locks`, `Drops` and take `Inode`
    // field.
    let inode_field = fields.nth(9).ok_or(io::ErrorKind::InvalidData)?;

    // Parse inode number first to determine if this is a socket to take into consideration.
    let ino = parse::dec_strict::<u64>(inode_field)?;
    if let Some(cf) = eval_sock_ino(ino).into_control_flow() {
        return Ok(cf);
    }

    let nl_sock = NetlinkSocket::new();
    sockets.insert(ino, nl_sock.into());
    Ok(ControlFlow::Continue(()))
}

/// Returns a [LineProcessor] that skips the first (header) line and delegates the rest to `inner`.
fn parse_sock_table<P: LineProcessor>(mut inner: P) -> impl LineProcessor {
    let mut is_header = true;
    move |line: &[u8]| -> io::Result<ControlFlow<()>> {
        if mem::take(&mut is_header) {
            return Ok(ControlFlow::Continue(()));
        }
        inner.process(line)
    }
}

/// Returns sockets belonging to the network namespace of the process identified by `pid`, indexed
/// by inode number. `eval_sock_ino` is used to determine if a socket must be added or not, as well
/// as if the collection procedure should terminate early.
fn get_by_inode(
    procfs: &Procfs,
    pid: u32,
    eval_sock_ino: &mut impl FnMut(u64) -> Verdict,
) -> io::Result<InodeToSocketMap> {
    let mut sockets = InodeToSocketMap::new();

    macro_rules! scan_or_return {
        ($result:expr) => {
            if $result?.is_break() {
                return Ok(sockets);
            }
        };
    }

    // AF_INET sockets.
    scan_or_return!(procfs.scan_net_tcp(
        pid,
        parse_sock_table(|line: &[u8]| {
            parse_inet_socket_table_line(&mut sockets, L4Protocol::Tcp, eval_sock_ino, line)
        }),
    ));
    scan_or_return!(procfs.scan_net_udp(
        pid,
        parse_sock_table(|line: &[u8]| {
            parse_inet_socket_table_line(&mut sockets, L4Protocol::Udp, eval_sock_ino, line)
        }),
    ));
    scan_or_return!(procfs.scan_net_raw(
        pid,
        parse_sock_table(|line: &[u8]| {
            parse_inet_socket_table_line(&mut sockets, L4Protocol::Raw, eval_sock_ino, line)
        }),
    ));

    // AF_INET6 sockets.
    scan_or_return!(procfs.scan_net_tcp6(
        pid,
        parse_sock_table(|line: &[u8]| {
            parse_inet6_socket_table_line(&mut sockets, L4Protocol::Tcp, eval_sock_ino, line)
        }),
    ));
    scan_or_return!(procfs.scan_net_udp6(
        pid,
        parse_sock_table(|line: &[u8]| {
            parse_inet6_socket_table_line(&mut sockets, L4Protocol::Udp, eval_sock_ino, line)
        }),
    ));
    scan_or_return!(procfs.scan_net_raw6(
        pid,
        parse_sock_table(|line: &[u8]| {
            parse_inet6_socket_table_line(&mut sockets, L4Protocol::Raw, eval_sock_ino, line)
        }),
    ));

    // AF_UNIX sockets.
    scan_or_return!(procfs.scan_net_unix(
        pid,
        parse_sock_table(|line: &[u8]| {
            parse_unix_socket_table_line(&mut sockets, eval_sock_ino, line)
        }),
    ));

    // AF_NETLINK sockets.
    scan_or_return!(procfs.scan_net_netlink(
        pid,
        parse_sock_table(|line: &[u8]| {
            parse_netlink_socket_table_line(&mut sockets, eval_sock_ino, line)
        }),
    ));

    Ok(sockets)
}

/// Strategy used by [SocketCollector] to determine which sockets to collect.
#[derive(Copy, Clone)]
pub enum SocketCollectionStrategy {
    /// Collects all sockets for the network namespace on first discovery.
    AllProcesses,
    /// Collects only this process' sockets, filtering by the process' socket inodes.
    SingleProcess,
    /// Collects only a single socket, filtering by its inode.
    SingleFile,
}

/// An abstraction allowing to gather information about sockets. [SocketCollector::ensure_populated]
/// ensures sockets information is available for a specific network namespace by lazily collecting
/// it the first time the network namespace is discovered. Once socket information becomes
/// available, it can be retrieved by leveraging [SocketCollector::get_socket].
///
/// # Implementation details
/// Sockets are organized by network namespace and, in the context of a network namespace, they are
/// indexed by their inode number.
pub struct SocketCollector {
    sockets: NetnsSocketsMap,
    strategy: SocketCollectionStrategy,
}

impl SocketCollector {
    /// Creates a new [SocketCollector] with the given `strategy`.
    pub fn new(strategy: SocketCollectionStrategy) -> Self {
        Self {
            sockets: NetnsSocketsMap::new(),
            strategy,
        }
    }

    /// Returns sockets belonging to the network namespace of the process identified by `pid`, whose
    /// inode numbers are in `sock_inos`. Scanning stops early once all requested inodes have been
    /// found.
    fn get_sockets_by_inodes(
        procfs: &Procfs,
        pid: u32,
        sock_inos: &HashSet<u64>,
    ) -> io::Result<InodeToSocketMap> {
        let mut sockets_left = sock_inos.len();
        get_by_inode(procfs, pid, &mut |ino| {
            if sockets_left == 0 {
                return Verdict::Abort;
            }
            if sock_inos.contains(&ino) {
                sockets_left -= 1;
                Verdict::Parse
            } else {
                Verdict::Skip
            }
        })
    }

    /// Returns all sockets belonging to the network namespace of the process identified by `pid`.
    fn get_all_sockets(procfs: &Procfs, pid: u32) -> io::Result<InodeToSocketMap> {
        get_by_inode(procfs, pid, &mut |_| Verdict::Parse)
    }

    /// Ensures the inode-to-socket map for `netns_ino` is populated. Depending on the configured
    /// strategy, `sock_inos` can be used internally to filter the list of sockets to collect.
    pub fn ensure_populated(
        &mut self,
        netns_ino: u64,
        procfs: &Procfs,
        pid: u32,
        sock_inos: impl Iterator<Item = u64>,
    ) -> io::Result<()> {
        let hash_map::Entry::Vacant(e) = self.sockets.entry(netns_ino) else {
            return Ok(());
        };

        let netns_sockets = match self.strategy {
            SocketCollectionStrategy::AllProcesses => Self::get_all_sockets(procfs, pid),
            SocketCollectionStrategy::SingleProcess => {
                let sock_inos: HashSet<_> = sock_inos.collect();
                Self::get_sockets_by_inodes(procfs, pid, &sock_inos)
            }
            SocketCollectionStrategy::SingleFile => {
                let sock_inos: HashSet<_> = sock_inos.collect();
                // In this case, `sock_inos` should only contain a single socket inode.
                if sock_inos.len() != 1 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "there must be just a single socket inode",
                    ));
                }
                Self::get_sockets_by_inodes(procfs, pid, &sock_inos)
            }
        }?;
        e.insert(netns_sockets);
        Ok(())
    }

    /// Returns a clone of the socket for `sock_ino` in the map for `netns_ino`.
    pub fn get_socket(&self, netns_ino: u64, sock_ino: u64) -> Option<Socket> {
        self.sockets.get(&netns_ino)?.get(&sock_ino).cloned()
    }
}
