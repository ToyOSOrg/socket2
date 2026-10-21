// Copyright 2015 The Rust Project Developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! ToyOS platform implementation for socket2.
//!
//! ToyOS's network server is the `netstack` program. A connected or accepted
//! socket here is std's `TcpStream`, and a listening one std's `TcpListener`:
//! std holds a process's stream ends, one per stream however many handles
//! reach it, so this module reaches netstack through std and holds no stream
//! state of its own. What std has no word for, an unconnected socket's
//! options before its connect, is kept here.
//!
//! A socket's number is a descriptor in the process's one table
//! (`toyos::fd`), naming an object of this module's own: its word is the
//! socket's key here, and the socket goes when no descriptor names it. So
//! `try_clone` is a second descriptor on the same socket, as `dup` is.


use std::collections::HashMap;
use std::io::{self, IoSlice, Read, Write};
use std::marker::PhantomData;
use std::mem::{self, MaybeUninit};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use crate::{SockAddr, TcpKeepalive};

// ---------------------------------------------------------------------------
// Public type aliases
// ---------------------------------------------------------------------------

pub(crate) use std::ffi::c_int;

pub(crate) type Bool = c_int;
pub(crate) type RawSocket = c_int;
pub(crate) type socklen_t = u32;
pub(crate) type sa_family_t = u16;

// ---------------------------------------------------------------------------
// Address family constants
// ---------------------------------------------------------------------------

pub(crate) const AF_INET: c_int = 2;
pub(crate) const AF_INET6: c_int = 10;
pub(crate) const AF_UNIX: c_int = 1;

// ---------------------------------------------------------------------------
// Socket type constants
// ---------------------------------------------------------------------------

pub(crate) const SOCK_STREAM: c_int = 1;
pub(crate) const SOCK_DGRAM: c_int = 2;
pub(crate) const SOCK_RAW: c_int = 3;
pub(crate) const SOCK_SEQPACKET: c_int = 5;

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

pub(crate) const IPPROTO_IP: c_int = 0;
pub(crate) const IPPROTO_TCP: c_int = 6;
pub(crate) const IPPROTO_UDP: c_int = 17;
pub(crate) const IPPROTO_IPV6: c_int = 41;
pub(crate) const IPPROTO_ICMP: c_int = 1;
pub(crate) const IPPROTO_ICMPV6: c_int = 58;

// ---------------------------------------------------------------------------
// Socket-level option constants
// ---------------------------------------------------------------------------

pub(crate) const SOL_SOCKET: c_int = 1;
pub(crate) const SO_BROADCAST: c_int = 6;
pub(crate) const SO_ERROR: c_int = 4;
pub(crate) const SO_KEEPALIVE: c_int = 9;
pub(crate) const SO_LINGER: c_int = 13;
pub(crate) const SO_RCVBUF: c_int = 8;
pub(crate) const SO_RCVTIMEO: c_int = 20;
pub(crate) const SO_REUSEADDR: c_int = 2;
pub(crate) const SO_SNDBUF: c_int = 7;
pub(crate) const SO_SNDTIMEO: c_int = 21;
pub(crate) const SO_TYPE: c_int = 3;
pub(crate) const SO_OOBINLINE: c_int = 10;

// ---------------------------------------------------------------------------
// TCP option constants
// ---------------------------------------------------------------------------

pub(crate) const TCP_NODELAY: c_int = 1;

// ---------------------------------------------------------------------------
// IP option constants
// ---------------------------------------------------------------------------

pub(crate) const IP_TTL: c_int = 2;
pub(crate) const IP_TOS: c_int = 1;
pub(crate) const IP_MULTICAST_TTL: c_int = 33;
pub(crate) const IP_MULTICAST_LOOP: c_int = 34;
pub(crate) const IP_ADD_MEMBERSHIP: c_int = 35;
pub(crate) const IP_DROP_MEMBERSHIP: c_int = 36;
pub(crate) const IP_MULTICAST_IF: c_int = 32;
pub(crate) const IP_HDRINCL: c_int = 3;

// ---------------------------------------------------------------------------
// IPv6 option constants
// ---------------------------------------------------------------------------

pub(crate) const IPV6_UNICAST_HOPS: c_int = 16;
pub(crate) const IPV6_V6ONLY: c_int = 26;
pub(crate) const IPV6_MULTICAST_LOOP: c_int = 19;
pub(crate) const IPV6_MULTICAST_HOPS: c_int = 18;
pub(crate) const IPV6_MULTICAST_IF: c_int = 17;
pub(crate) const IPV6_ADD_MEMBERSHIP: c_int = 20;
pub(crate) const IPV6_DROP_MEMBERSHIP: c_int = 21;
pub(crate) const IPV6_RECVHOPLIMIT: c_int = 51;

// ---------------------------------------------------------------------------
// Message flag constants
// ---------------------------------------------------------------------------

pub(crate) const MSG_PEEK: c_int = 2;
pub(crate) const MSG_OOB: c_int = 1;
pub(crate) const MSG_TRUNC: c_int = 0x20;

// ---------------------------------------------------------------------------
// Struct types (layout-compatible with POSIX, no libc dependency)
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct in_addr {
    pub s_addr: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct sockaddr_in {
    pub sin_family: sa_family_t,
    pub sin_port: u16,
    pub sin_addr: in_addr,
    pub sin_zero: [u8; 8],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct in6_addr {
    pub s6_addr: [u8; 16],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct sockaddr_in6 {
    pub sin6_family: sa_family_t,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct sockaddr_storage {
    pub ss_family: sa_family_t,
    _padding: [u8; 126],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct linger {
    pub l_onoff: c_int,
    pub l_linger: c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct IpMreq {
    pub imr_multiaddr: in_addr,
    pub imr_interface: in_addr,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct Ipv6Mreq {
    pub ipv6mr_multiaddr: in6_addr,
    pub ipv6mr_interface: u32,
}

// ---------------------------------------------------------------------------
// MaybeUninitSlice (no libc iovec, just a pointer+len pair)
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct MaybeUninitSlice<'a> {
    ptr: *mut u8,
    len: usize,
    _lifetime: PhantomData<&'a mut [MaybeUninit<u8>]>,
}

unsafe impl<'a> Send for MaybeUninitSlice<'a> {}
unsafe impl<'a> Sync for MaybeUninitSlice<'a> {}

impl<'a> MaybeUninitSlice<'a> {
    pub(crate) fn new(buf: &'a mut [MaybeUninit<u8>]) -> MaybeUninitSlice<'a> {
        MaybeUninitSlice {
            ptr: buf.as_mut_ptr().cast(),
            len: buf.len(),
            _lifetime: PhantomData,
        }
    }

    pub(crate) fn as_slice(&self) -> &[MaybeUninit<u8>] {
        unsafe { std::slice::from_raw_parts(self.ptr.cast(), self.len) }
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [MaybeUninit<u8>] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.cast(), self.len) }
    }
}

// ---------------------------------------------------------------------------
// msghdr (POSIX-compatible layout for MsgHdr/MsgHdrMut in lib.rs)
// ---------------------------------------------------------------------------

#[repr(C)]
pub(crate) struct msghdr {
    pub msg_name: *mut u8,
    pub msg_namelen: u32,
    _pad0: u32,
    pub msg_iov: *mut IoSlice<'static>,
    pub msg_iovlen: usize,
    pub msg_control: *mut u8,
    pub msg_controllen: usize,
    pub msg_flags: c_int,
}

unsafe impl Send for msghdr {}
unsafe impl Sync for msghdr {}

pub(crate) fn set_msghdr_name(msg: &mut msghdr, name: &crate::SockAddr) {
    msg.msg_name = name.as_ptr() as *mut _;
    msg.msg_namelen = name.len();
}

pub(crate) fn set_msghdr_iov(msg: &mut msghdr, ptr: *mut IoSlice<'static>, len: usize) {
    msg.msg_iov = ptr;
    msg.msg_iovlen = len;
}

pub(crate) fn set_msghdr_control(msg: &mut msghdr, ptr: *mut u8, len: usize) {
    msg.msg_control = ptr;
    msg.msg_controllen = len;
}

pub(crate) fn set_msghdr_flags(msg: &mut msghdr, flags: c_int) {
    msg.msg_flags = flags;
}

pub(crate) fn msghdr_flags(msg: &msghdr) -> crate::RecvFlags {
    crate::RecvFlags(msg.msg_flags)
}

pub(crate) fn msghdr_control_len(msg: &msghdr) -> usize {
    msg.msg_controllen
}

// ---------------------------------------------------------------------------
// RecvFlags Debug
// ---------------------------------------------------------------------------

impl std::fmt::Debug for crate::RecvFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecvFlags")
            .field("truncated", &self.is_truncated())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// impl_debug macros for Domain, Type, Protocol
// ---------------------------------------------------------------------------

impl std::fmt::Debug for crate::Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            AF_INET => f.write_str("AF_INET"),
            AF_INET6 => f.write_str("AF_INET6"),
            n => write!(f, "{n}"),
        }
    }
}

impl std::fmt::Debug for crate::Type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            SOCK_STREAM => f.write_str("SOCK_STREAM"),
            SOCK_DGRAM => f.write_str("SOCK_DGRAM"),
            n => write!(f, "{n}"),
        }
    }
}

impl std::fmt::Debug for crate::Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            IPPROTO_TCP => f.write_str("IPPROTO_TCP"),
            IPPROTO_UDP => f.write_str("IPPROTO_UDP"),
            n => write!(f, "{n}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal state machine
// ---------------------------------------------------------------------------

/// A socket's key here: one of `KEYS` beside a tag no other library's object
/// word carries.
const TAG: u64 = 0x736f_636b_3200_0000;
const KEYS: u64 = 0xff_ffff;
/// Where the search for a free key starts.
static NEXT_KEY: AtomicU64 = AtomicU64::new(0);

fn sockets() -> &'static Mutex<HashMap<u64, SocketState>> {
    static SOCKETS: OnceLock<Mutex<HashMap<u64, SocketState>>> = OnceLock::new();
    SOCKETS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// `state` as a socket: the lowest free descriptor, not inherited, as unix's
/// socket is made `SOCK_CLOEXEC`, naming it. A key is reused once its socket
/// is gone; the search ends, since a process's table holds far fewer
/// descriptors than there are keys.
fn install(state: SocketState) -> io::Result<RawSocket> {
    let mut map = sockets().lock().unwrap();
    let key = loop {
        let key = TAG | (NEXT_KEY.fetch_add(1, Ordering::Relaxed) & KEYS);
        if !map.contains_key(&key) {
            break key;
        }
    };
    map.insert(key, state);
    drop(map);
    // On a full table the object is let go, and with it the socket.
    toyos::fd::install(toyos::fd::Object::opaque(key, release), false, 0)
        .map_err(|_| io::Error::new(io::ErrorKind::QuotaExceeded, "the descriptor table is full"))
}

/// A socket no descriptor names any more.
extern "C" fn release(key: u64) {
    let gone = sockets().lock().unwrap().remove(&key);
    drop(gone);
}

/// The socket descriptor `fd` names: its key, or `None` for a descriptor that
/// names no socket of this module's.
fn key(fd: RawSocket) -> Option<u64> {
    let word = toyos::fd::with(fd, |o| o.release.map(|_| o.word)).ok().flatten()?;
    (word & !KEYS == TAG).then_some(word)
}

enum SocketState {
    /// Created but not yet connected or bound.
    Unconnected {
        domain: c_int,
        sock_type: c_int,
        nonblocking: bool,
        nodelay: bool,
        reuse_addr: bool,
        recv_timeout: Option<Duration>,
        send_timeout: Option<Duration>,
        bind_addr: Option<([u8; 4], u16)>,
    },
    /// TCP stream, connected or accepted.
    Connected(Arc<TcpStream>),
    /// TCP listener, bound and listening.
    Listening(Arc<TcpListener>),
}

/// The socket `fd` names, as the state it is in.
fn state<T>(fd: RawSocket, f: impl FnOnce(&mut SocketState) -> io::Result<T>) -> io::Result<T> {
    let key = key(fd).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid socket fd"))?;
    let mut map = sockets().lock().unwrap();
    let state = map.get_mut(&key).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid socket fd"))?;
    f(state)
}

/// The stream `fd` names, outside the table's lock.
fn stream(fd: RawSocket) -> io::Result<Arc<TcpStream>> {
    state(fd, |state| match state {
        SocketState::Connected(stream) => Ok(stream.clone()),
        _ => Err(io::ErrorKind::NotConnected.into()),
    })
}

// ---------------------------------------------------------------------------
// Address extraction from SockAddr
// ---------------------------------------------------------------------------

fn sockaddr_to_v4(addr: &SockAddr) -> io::Result<([u8; 4], u16)> {
    if addr.family() != AF_INET as sa_family_t {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "only IPv4 is supported",
        ));
    }
    let sin = unsafe { &*(addr.as_ptr() as *const sockaddr_in) };
    let ip = sin.sin_addr.s_addr.to_ne_bytes();
    let port = u16::from_be(sin.sin_port);
    Ok((ip, port))
}

fn make_sockaddr_v4(ip: [u8; 4], port: u16) -> SockAddr {
    let addr = std::net::SocketAddrV4::new(Ipv4Addr::from(ip), port);
    SockAddr::from(std::net::SocketAddr::V4(addr))
}

// ---------------------------------------------------------------------------
// Socket type (owned handle with Drop)
// ---------------------------------------------------------------------------

pub(crate) struct Socket(c_int);

impl Drop for Socket {
    fn drop(&mut self) {
        let _ = toyos::fd::close(self.0);
    }
}

// ---------------------------------------------------------------------------
// Raw socket handle functions
// ---------------------------------------------------------------------------

pub(crate) unsafe fn socket_from_raw(fd: RawSocket) -> Socket {
    Socket(fd)
}

pub(crate) fn socket_as_raw(socket: &Socket) -> RawSocket {
    socket.0
}

pub(crate) fn socket_into_raw(socket: Socket) -> RawSocket {
    let fd = socket.0;
    mem::forget(socket);
    fd
}

// ---------------------------------------------------------------------------
// Core socket operations
// ---------------------------------------------------------------------------

pub(crate) fn socket(family: c_int, ty: c_int, _protocol: c_int) -> io::Result<RawSocket> {
    install(SocketState::Unconnected {
        domain: family,
        sock_type: ty,
        nonblocking: false,
        nodelay: false,
        reuse_addr: false,
        recv_timeout: None,
        send_timeout: None,
        bind_addr: None,
    })
}

pub(crate) fn bind(fd: RawSocket, addr: &SockAddr) -> io::Result<()> {
    let (ip, port) = sockaddr_to_v4(addr)?;
    state(fd, |state| match state {
        SocketState::Unconnected { bind_addr, .. } => {
            *bind_addr = Some((ip, port));
            Ok(())
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket already connected or listening",
        )),
    })
}

pub(crate) fn connect(fd: RawSocket, addr: &SockAddr) -> io::Result<()> {
    let (ip, port) = sockaddr_to_v4(addr)?;
    let (nonblocking, nodelay, recv_timeout, send_timeout) = state(fd, |state| match state {
        SocketState::Unconnected { nonblocking, nodelay, recv_timeout, send_timeout, .. } => {
            Ok((*nonblocking, *nodelay, *recv_timeout, *send_timeout))
        }
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "socket already connected")),
    })?;
    let stream = TcpStream::connect_timeout(&SocketAddr::from((ip, port)), Duration::from_secs(30))?;
    stream.set_nonblocking(nonblocking)?;
    stream.set_nodelay(nodelay)?;
    stream.set_read_timeout(recv_timeout)?;
    stream.set_write_timeout(send_timeout)?;
    state(fd, |state| {
        *state = SocketState::Connected(Arc::new(stream));
        Ok(())
    })
}

pub(crate) fn poll_connect(socket: &crate::Socket, _timeout: Duration) -> io::Result<()> {
    // On ToyOS, connect is synchronous — if we're Connected, it succeeded.
    stream(socket.as_raw()).map(drop)
}

pub(crate) fn listen(fd: RawSocket, _backlog: c_int) -> io::Result<()> {
    let (ip, port, nonblocking) = state(fd, |state| match state {
        SocketState::Unconnected { bind_addr, nonblocking, .. } => {
            let (ip, port) = bind_addr.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "socket not bound"))?;
            Ok((ip, port, *nonblocking))
        }
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "socket already connected or listening")),
    })?;
    let listener = TcpListener::bind(SocketAddr::from((ip, port)))?;
    listener.set_nonblocking(nonblocking)?;
    state(fd, |state| {
        *state = SocketState::Listening(Arc::new(listener));
        Ok(())
    })
}

pub(crate) fn accept(fd: RawSocket) -> io::Result<(RawSocket, SockAddr)> {
    let listener = state(fd, |state| match state {
        SocketState::Listening(listener) => Ok(listener.clone()),
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "socket not listening")),
    })?;
    let (accepted, peer) = listener.accept()?;
    Ok((install(SocketState::Connected(Arc::new(accepted)))?, SockAddr::from(peer)))
}

pub(crate) fn getsockname(fd: RawSocket) -> io::Result<SockAddr> {
    state(fd, |state| match state {
        SocketState::Connected(stream) => stream.local_addr().map(SockAddr::from),
        SocketState::Listening(listener) => listener.local_addr().map(SockAddr::from),
        SocketState::Unconnected { bind_addr, .. } => match bind_addr {
            Some((ip, port)) => Ok(make_sockaddr_v4(*ip, *port)),
            None => Ok(make_sockaddr_v4([0, 0, 0, 0], 0)),
        },
    })
}

pub(crate) fn getpeername(fd: RawSocket) -> io::Result<SockAddr> {
    stream(fd)?.peer_addr().map(SockAddr::from)
}

/// A second descriptor on the same socket, not inherited, as unix's
/// `F_DUPFD_CLOEXEC` makes.
pub(crate) fn try_clone(fd: RawSocket) -> io::Result<RawSocket> {
    key(fd).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid socket fd"))?;
    toyos::fd::dup(fd, 0, false).map_err(|_| io::Error::new(io::ErrorKind::QuotaExceeded, "the descriptor table is full"))
}

pub(crate) fn set_nonblocking(fd: RawSocket, nonblocking: bool) -> io::Result<()> {
    state(fd, |state| match state {
        SocketState::Unconnected { nonblocking: nb, .. } => {
            *nb = nonblocking;
            Ok(())
        }
        SocketState::Connected(stream) => stream.set_nonblocking(nonblocking),
        SocketState::Listening(listener) => listener.set_nonblocking(nonblocking),
    })
}

pub(crate) fn shutdown(fd: RawSocket, how: Shutdown) -> io::Result<()> {
    stream(fd)?.shutdown(how)
}

// ---------------------------------------------------------------------------
// Data transfer
// ---------------------------------------------------------------------------

pub(crate) fn recv(
    fd: RawSocket,
    buf: &mut [MaybeUninit<u8>],
    _flags: c_int,
) -> io::Result<usize> {
    let stream = stream(fd)?;
    // SAFETY: MaybeUninit<u8> has the same layout as u8, and a read only
    // writes what it answers.
    let raw_buf = unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<u8>(), buf.len()) };
    (&*stream).read(raw_buf)
}

pub(crate) fn send(fd: RawSocket, buf: &[u8], _flags: c_int) -> io::Result<usize> {
    (&*stream(fd)?).write(buf)
}

pub(crate) fn recv_from(
    fd: RawSocket,
    buf: &mut [MaybeUninit<u8>],
    flags: c_int,
) -> io::Result<(usize, SockAddr)> {
    // TCP only — recv_from returns the peer address
    let n = recv(fd, buf, flags)?;
    let peer = getpeername(fd)?;
    Ok((n, peer))
}

pub(crate) fn send_to(
    fd: RawSocket,
    buf: &[u8],
    _addr: &SockAddr,
    flags: c_int,
) -> io::Result<usize> {
    // TCP only — send_to ignores the address
    send(fd, buf, flags)
}

pub(crate) fn peek_sender(fd: RawSocket) -> io::Result<SockAddr> {
    getpeername(fd)
}

// ---------------------------------------------------------------------------
// Socket options
// ---------------------------------------------------------------------------

pub(crate) unsafe fn getsockopt<T: Copy>(
    fd: RawSocket,
    opt: c_int,
    val: c_int,
) -> io::Result<T> {
    let map = sockets().lock().unwrap();
    let state = map
        .get(&key(fd).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid socket fd"))?)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid socket fd"))?;

    // Most options return c_int (0 or 1 for booleans, actual value otherwise)
    macro_rules! ret {
        ($v:expr) => {{
            let v: c_int = $v;
            let mut result = MaybeUninit::<T>::zeroed();
            let src = &v as *const c_int as *const u8;
            let dst = result.as_mut_ptr() as *mut u8;
            let len = std::cmp::min(mem::size_of::<T>(), mem::size_of::<c_int>());
            std::ptr::copy_nonoverlapping(src, dst, len);
            return Ok(result.assume_init());
        }};
    }

    match (opt, val) {
        (SOL_SOCKET, SO_ERROR) => ret!(0),
        (SOL_SOCKET, SO_TYPE) => match state {
            SocketState::Unconnected { sock_type, .. } => ret!(*sock_type),
            SocketState::Connected(_) | SocketState::Listening(_) => ret!(SOCK_STREAM),
        },
        (SOL_SOCKET, SO_KEEPALIVE) => ret!(0),
        (SOL_SOCKET, SO_BROADCAST) => ret!(0),
        (SOL_SOCKET, SO_REUSEADDR) => match state {
            SocketState::Unconnected { reuse_addr, .. } => ret!(if *reuse_addr { 1 } else { 0 }),
            _ => ret!(0),
        },
        (SOL_SOCKET, SO_RCVBUF) => ret!(65536),
        (SOL_SOCKET, SO_SNDBUF) => ret!(65536),
        (SOL_SOCKET, SO_LINGER) => {
            let l = linger {
                l_onoff: 0,
                l_linger: 0,
            };
            let mut result = MaybeUninit::<T>::zeroed();
            let len = std::cmp::min(mem::size_of::<T>(), mem::size_of::<linger>());
            std::ptr::copy_nonoverlapping(
                &l as *const linger as *const u8,
                result.as_mut_ptr() as *mut u8,
                len,
            );
            return Ok(result.assume_init());
        }
        (IPPROTO_TCP, TCP_NODELAY) => match state {
            SocketState::Unconnected { nodelay, .. } => ret!(if *nodelay { 1 } else { 0 }),
            SocketState::Connected(stream) => ret!(if stream.nodelay()? { 1 } else { 0 }),
            SocketState::Listening(_) => ret!(0),
        },
        (IPPROTO_IP, IP_TTL) | (IPPROTO_IPV6, IPV6_UNICAST_HOPS) => ret!(64),
        (IPPROTO_IP, IP_MULTICAST_TTL) | (IPPROTO_IPV6, IPV6_MULTICAST_HOPS) => ret!(1),
        (IPPROTO_IP, IP_MULTICAST_LOOP) | (IPPROTO_IPV6, IPV6_MULTICAST_LOOP) => ret!(1),
        (IPPROTO_IPV6, IPV6_V6ONLY) => ret!(0),
        _ => ret!(0),
    }
}

pub(crate) unsafe fn setsockopt<T>(
    fd: RawSocket,
    opt: c_int,
    val: c_int,
    payload: T,
) -> io::Result<()> {
    let value = if mem::size_of::<T>() >= mem::size_of::<c_int>() {
        *(&payload as *const T as *const c_int)
    } else {
        0
    };

    let mut map = sockets().lock().unwrap();
    let state = map
        .get_mut(&key(fd).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid socket fd"))?)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid socket fd"))?;

    match (opt, val) {
        (SOL_SOCKET, SO_REUSEADDR) => {
            if let SocketState::Unconnected { reuse_addr, .. } = state {
                *reuse_addr = value != 0;
            }
        }
        (SOL_SOCKET, SO_KEEPALIVE) => {} // no-op
        (SOL_SOCKET, SO_BROADCAST) => {} // no-op
        (SOL_SOCKET, SO_RCVBUF) => {}    // no-op
        (SOL_SOCKET, SO_SNDBUF) => {}    // no-op
        (SOL_SOCKET, SO_LINGER) => {}    // no-op
        (IPPROTO_TCP, TCP_NODELAY) => match state {
            SocketState::Unconnected { nodelay, .. } => *nodelay = value != 0,
            SocketState::Connected(stream) => stream.set_nodelay(value != 0)?,
            SocketState::Listening(_) => {}
        },
        (IPPROTO_IP, IP_TTL) | (IPPROTO_IPV6, IPV6_UNICAST_HOPS) => {} // no-op
        (IPPROTO_IP, IP_MULTICAST_TTL) => {}                            // no-op
        (IPPROTO_IP, IP_MULTICAST_LOOP) | (IPPROTO_IPV6, IPV6_MULTICAST_LOOP) => {} // no-op
        (IPPROTO_IPV6, IPV6_V6ONLY) => {}                               // no-op
        (IPPROTO_IP, IP_ADD_MEMBERSHIP) | (IPPROTO_IP, IP_DROP_MEMBERSHIP) => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "multicast not supported",
            ));
        }
        (IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP) | (IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP) => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "multicast not supported",
            ));
        }
        _ => {} // unknown options are silently ignored
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Timeout helpers
// ---------------------------------------------------------------------------

pub(crate) fn timeout_opt(
    fd: RawSocket,
    _opt: c_int,
    val: c_int,
) -> io::Result<Option<Duration>> {
    let map = sockets().lock().unwrap();
    let state = map
        .get(&key(fd).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid socket fd"))?)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid socket fd"))?;

    let timeout = match state {
        SocketState::Unconnected { recv_timeout, send_timeout, .. } => {
            if val == SO_RCVTIMEO {
                *recv_timeout
            } else {
                *send_timeout
            }
        }
        SocketState::Connected(stream) if val == SO_RCVTIMEO => stream.read_timeout()?,
        SocketState::Connected(stream) => stream.write_timeout()?,
        SocketState::Listening(_) => None,
    };
    Ok(timeout)
}

pub(crate) fn set_timeout_opt(
    fd: RawSocket,
    _opt: c_int,
    val: c_int,
    duration: Option<Duration>,
) -> io::Result<()> {
    let mut map = sockets().lock().unwrap();
    let state = map
        .get_mut(&key(fd).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid socket fd"))?)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid socket fd"))?;

    match state {
        SocketState::Unconnected { recv_timeout, send_timeout, .. } => {
            if val == SO_RCVTIMEO {
                *recv_timeout = duration;
            } else {
                *send_timeout = duration;
            }
        }
        SocketState::Connected(stream) if val == SO_RCVTIMEO => stream.set_read_timeout(duration)?,
        SocketState::Connected(stream) => stream.set_write_timeout(duration)?,
        SocketState::Listening(_) => {}
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TCP keepalive (no-op on ToyOS)
// ---------------------------------------------------------------------------

pub(crate) fn tcp_keepalive_time(_fd: RawSocket) -> io::Result<Duration> {
    // ToyOS doesn't support TCP keepalive, return a sensible default
    Ok(Duration::from_secs(7200))
}

pub(crate) fn set_tcp_keepalive(
    _fd: RawSocket,
    _keepalive: &TcpKeepalive,
) -> io::Result<()> {
    Ok(())
}

// ---------------------------------------------------------------------------
// Address conversion helpers
// ---------------------------------------------------------------------------

pub(crate) const fn to_in_addr(addr: &Ipv4Addr) -> in_addr {
    in_addr {
        s_addr: u32::from_ne_bytes(addr.octets()),
    }
}

pub(crate) fn from_in_addr(addr: in_addr) -> Ipv4Addr {
    Ipv4Addr::from(addr.s_addr.to_ne_bytes())
}

pub(crate) const fn to_in6_addr(addr: &Ipv6Addr) -> in6_addr {
    in6_addr {
        s6_addr: addr.octets(),
    }
}

pub(crate) fn from_in6_addr(addr: in6_addr) -> Ipv6Addr {
    Ipv6Addr::from(addr.s6_addr)
}

// ---------------------------------------------------------------------------
// Vectored I/O
// ---------------------------------------------------------------------------

pub(crate) fn recv_vectored(
    fd: RawSocket,
    bufs: &mut [crate::MaybeUninitSlice<'_>],
    flags: c_int,
) -> io::Result<(usize, crate::RecvFlags)> {
    let total: usize = bufs.iter().map(|b| b.len()).sum();
    let mut tmp = vec![MaybeUninit::uninit(); total];
    let n = recv(fd, &mut tmp, flags)?;
    // Scatter into iovecs
    let mut offset = 0;
    for buf in bufs.iter_mut() {
        let slice: &mut [MaybeUninit<u8>] = buf;
        let to_copy = (n - offset).min(slice.len());
        if to_copy == 0 {
            break;
        }
        slice[..to_copy].copy_from_slice(&tmp[offset..offset + to_copy]);
        offset += to_copy;
    }
    Ok((n, crate::RecvFlags(0)))
}

pub(crate) fn recv_from_vectored(
    fd: RawSocket,
    bufs: &mut [crate::MaybeUninitSlice<'_>],
    flags: c_int,
) -> io::Result<(usize, crate::RecvFlags, crate::SockAddr)> {
    let (n, rflags) = recv_vectored(fd, bufs, flags)?;
    let peer = getpeername(fd)?;
    Ok((n, rflags, peer))
}

pub(crate) fn recvmsg(
    fd: RawSocket,
    msg: &mut crate::MsgHdrMut<'_, '_, '_>,
    flags: c_int,
) -> io::Result<usize> {
    let iov_count = msg.inner.msg_iovlen;
    if iov_count == 0 {
        return Ok(0);
    }
    let bufs = unsafe {
        std::slice::from_raw_parts_mut(msg.inner.msg_iov as *mut crate::MaybeUninitSlice<'_>, iov_count)
    };
    let (n, rflags) = recv_vectored(fd, bufs, flags)?;
    msg.inner.msg_flags = rflags.0;
    Ok(n)
}

pub(crate) fn send_vectored(
    fd: RawSocket,
    bufs: &[IoSlice<'_>],
    flags: c_int,
) -> io::Result<usize> {
    if bufs.len() == 1 {
        return send(fd, &bufs[0], flags);
    }
    let total: usize = bufs.iter().map(|b| b.len()).sum();
    let mut tmp = Vec::with_capacity(total);
    for buf in bufs {
        tmp.extend_from_slice(buf);
    }
    send(fd, &tmp, flags)
}

pub(crate) fn send_to_vectored(
    fd: RawSocket,
    bufs: &[IoSlice<'_>],
    _addr: &crate::SockAddr,
    flags: c_int,
) -> io::Result<usize> {
    send_vectored(fd, bufs, flags)
}

pub(crate) fn sendmsg(
    fd: RawSocket,
    msg: &crate::MsgHdr<'_, '_, '_>,
    flags: c_int,
) -> io::Result<usize> {
    let iov_count = msg.inner.msg_iovlen;
    if iov_count == 0 {
        return Ok(0);
    }
    let bufs = unsafe { std::slice::from_raw_parts(msg.inner.msg_iov, iov_count) };
    send_vectored(fd, bufs, flags)
}

// ---------------------------------------------------------------------------
// Standard fd trait implementations
// ---------------------------------------------------------------------------

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

impl AsFd for crate::Socket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        unsafe { BorrowedFd::borrow_raw(self.as_raw()) }
    }
}

impl AsRawFd for crate::Socket {
    fn as_raw_fd(&self) -> RawFd {
        self.as_raw()
    }
}

impl From<crate::Socket> for OwnedFd {
    fn from(sock: crate::Socket) -> OwnedFd {
        unsafe { OwnedFd::from_raw_fd(sock.into_raw()) }
    }
}

impl IntoRawFd for crate::Socket {
    fn into_raw_fd(self) -> RawFd {
        self.into_raw()
    }
}

impl From<OwnedFd> for crate::Socket {
    fn from(fd: OwnedFd) -> crate::Socket {
        unsafe { crate::Socket::from_raw_fd(fd.into_raw_fd()) }
    }
}

impl FromRawFd for crate::Socket {
    unsafe fn from_raw_fd(fd: RawFd) -> crate::Socket {
        crate::Socket::from_raw(fd)
    }
}
