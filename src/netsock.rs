//! Socket facade: a thin, protocol-free shim over the kernel IPC layer.
//!
//! Rynex deliberately keeps TCP/IP **out** of the kernel. netd is a user-space
//! service that owns the virtio-net device, the ARP/IP/TCP/UDP/ICMP stack and
//! the DHCP lease; the kernel has no business re-implementing any of it.
//!
//! But ordinary programs do not know that. busybox `wget`/`nc`/`nslookup` are
//! static musl binaries that reach the network the ordinary way — `socket(2)`,
//! `connect(2)`, `sendto(2)`, `recvfrom(2)`, `close(2)` — which on x86-64 are
//! syscalls 41/42/44/45/3. Without a kernel-side implementation they get
//! -ENOSYS and no program can use the network at all.
//!
//! This module is the seam between those two worlds, and it holds **no
//! protocol state**. A "socket" here is just a slot pairing an fd in the
//! caller's fd table with netd's own socket id. Every operation on that fd is
//! marshalled into one IPC request to netd's proxy, which does the real work
//! and replies with the syscall's return value. The kernel's total
//! contribution is the fd plumbing and the marshalling.
//!
//! The cost is therefore one IPC round trip per syscall (see the module docs
//! in `ipc.rs` for what that costs). That is the price of keeping the stack in
//! user space, and it is paid happily: it buys isolation — a protocol bug in
//! netd cannot corrupt the kernel — and it buys the ability to replace the
//! whole stack without touching the kernel.
//!
//! fd integration mirrors the pipe design exactly: pipes reserve a pseudo
//! inode range at the top of the inode table (`task::PIPE_INODE_BASE`) and
//! `sys_read`/`sys_write`/`sys_close` dispatch on it. Sockets reserve the range
//! immediately below it and are dispatched the same way, so they inherit fd
//! lifetime, `fork` and `dup` for free.

use crate::ipc;
use crate::task;

/// How many sockets a single boot can hold open, kernel-wide.
pub const SOCK_MAX: usize = 8;

/// Pseudo-inode range reserved for sockets, immediately below the pipe range.
///
/// Pipes take `PIPE_INODE_BASE .. MAX_INODES` (two inodes per pipe, one per
/// end); sockets take the `SOCK_MAX` indices just under that, one inode per
/// socket since a socket has no read/write end split.
pub const SOCK_INODE_BASE: usize = task::PIPE_INODE_BASE - SOCK_MAX;

/// Wire opcodes. These are the kernel↔netd ABI and are mirrored in netd; keep
/// the two in step.
const OP_SOCKET: u8 = 1;
const OP_CONNECT: u8 = 2;
const OP_SEND: u8 = 3;
const OP_RECV: u8 = 4;
const OP_CLOSE: u8 = 5;
const OP_SHUTDOWN: u8 = 6;
const OP_BIND: u8 = 7;
const OP_LISTEN: u8 = 8;
const OP_ACCEPT: u8 = 9;

/// Request header, little-endian, packed:
///
/// ```text
///  0  op        u8
///  1  reserved  u8
///  2  flags     u16   (send flags / listen backlog / shutdown how)
///  4  sock_id   u32   (netd's id for this socket; 0 for OP_SOCKET)
///  8  addr      u32   (IPv4, network byte order)
/// 12  port      u16   (host byte order)
/// 14  reserved  u16
/// 16  len       u32   (payload length for OP_SEND; max read for OP_RECV)
/// 20  payload   [u8; len]
/// ```
const REQ_HDR: usize = 20;

/// Reply header:
///
/// ```text
///  0  ret       i64   (the syscall's return value, or -errno)
///  8  payload   [u8; ret]   (OP_RECV data, OP_ACCEPT's new sock id)
/// ```
const REP_HDR: usize = 8;

/// Largest payload we will move in one syscall. Bounded by the MSS so a send
/// never needs segmentation, and comfortably under `IPC_MSG_MAX - REQ_HDR`
/// (4064 - 20 = 4044), which is the real ceiling on how much one IPC message
/// can carry.
const MAX_XFER: usize = 1460;

#[derive(Clone, Copy)]
struct SockSlot {
    used: bool,
    /// netd's own socket id; the kernel never interprets it.
    netd_id: u32,
}

impl SockSlot {
    const fn empty() -> Self {
        SockSlot { used: false, netd_id: 0 }
    }
}

static mut SOCKS: [SockSlot; SOCK_MAX] = [SockSlot::empty(); SOCK_MAX];

/// Resolve a pseudo-inode to a socket slot, mirroring `task::pipe_idx_of`.
pub fn sock_idx_of(inode: usize) -> Option<usize> {
    if inode >= SOCK_INODE_BASE && inode < task::PIPE_INODE_BASE {
        Some(inode - SOCK_INODE_BASE)
    } else {
        None
    }
}

fn slot_of(fd: u32) -> Option<usize> {
    let desc = crate::vfs::fd_to_inode(fd as usize)?;
    let idx = sock_idx_of(desc.inode_idx)?;
    let s = unsafe { &SOCKS[idx] };
    if s.used { Some(idx) } else { None }
}

fn alloc_slot(netd_id: u32) -> Option<usize> {
    let socks = unsafe { &mut SOCKS };
    for (i, s) in socks.iter_mut().enumerate() {
        if !s.used {
            s.used = true;
            s.netd_id = netd_id;
            return Some(i);
        }
    }
    None
}

fn free_slot(idx: usize) {
    let s = unsafe { &mut SOCKS[idx] };
    s.used = false;
    s.netd_id = 0;
}

/// Cache of netd's IPC port. netd may not be up when the first syscall
/// arrives, so a failed lookup is retried on the next call rather than
/// latching a failure forever.
static mut NETD_PORT: u64 = 0;

fn netd_port() -> Option<u64> {
    let cached = unsafe { NETD_PORT };
    if cached != 0 {
        return Some(cached);
    }
    // `ipc_connect` takes a raw slice without a user-range check, so a kernel
    // string literal is fine here.
    let name = b"netsock";
    let id = ipc::ipc_connect(name.as_ptr(), name.len());
    if id < 0 {
        return None;
    }
    unsafe { NETD_PORT = id as u64 };
    Some(id as u64)
}

/// Forget the cached port (netd restarted or vanished).
fn drop_port() {
    unsafe { NETD_PORT = 0 }
}

/// Marshal one request to netd and unpack its reply.
///
/// Returns the reply's `ret` (the syscall's own return value, already
/// negative-on-error), or a negative IPC-layer errno if the round trip itself
/// failed. `out` receives the reply payload after the 8-byte `ret` header.
#[inline(never)]
fn netd_call(
    op: u8,
    sock_id: u32,
    addr: u32,
    port: u16,
    flags: u16,
    payload: &[u8],
    out: &mut [u8],
) -> i64 {
    let port_id = match netd_port() {
        Some(p) => p,
        None => return -task::ENETDOWN,
    };

    let mut req = [0u8; REQ_HDR + MAX_XFER];
    req[0] = op;
    req[1] = 0;
    req[2..4].copy_from_slice(&flags.to_le_bytes());
    req[4..8].copy_from_slice(&sock_id.to_le_bytes());
    req[8..12].copy_from_slice(&addr.to_be_bytes());
    req[12..14].copy_from_slice(&port.to_le_bytes());
    let n = core::cmp::min(payload.len(), MAX_XFER);
    req[16..20].copy_from_slice(&(n as u32).to_le_bytes());
    req[REQ_HDR..REQ_HDR + n].copy_from_slice(&payload[..n]);

    // The reply lands in a scratch buffer so the caller's `out` only sees the
    // payload, never the `ret` header.
    let mut rep = [0u8; REP_HDR + MAX_XFER];
    let got = ipc::ipc_call_internal(
        port_id,
        req.as_ptr(),
        REQ_HDR + n,
        rep.as_mut_ptr(),
        rep.len(),
    );

    if got < 0 {
        // The port is stale (netd went away). Drop the cache so the next call
        // rediscovers it instead of failing identically forever.
        drop_port();
        return got;
    }
    if (got as usize) < REP_HDR {
        return -task::EIO;
    }
    let mut ret = [0u8; 8];
    ret.copy_from_slice(&rep[..8]);
    let ret = i64::from_le_bytes(ret);
    if ret > 0 {
        let take = core::cmp::min(ret as usize, out.len());
        let avail = core::cmp::min(got as usize - REP_HDR, take);
        out[..avail].copy_from_slice(&rep[REP_HDR..REP_HDR + avail]);
    }
    ret
}

/// `socket(2)`. Allocates a kernel slot plus an fd, and asks netd for a
/// matching socket id. Only `AF_INET` + `SOCK_STREAM`/`SOCK_DGRAM` reach netd;
/// everything else is rejected here so the error is cheap and immediate.
#[inline(never)]
pub fn sock_socket(domain: i32, ty: i32, _proto: i32) -> i64 {
    const AF_INET: i32 = 2;
    const SOCK_STREAM: i32 = 1;
    const SOCK_DGRAM: i32 = 2;
    if domain != AF_INET {
        return -task::EAFNOSUPPORT;
    }
    if ty != SOCK_STREAM && ty != SOCK_DGRAM {
        return -task::ESOCKTYPE;
    }

    let mut out = [0u8; 0];
    let ret = netd_call(OP_SOCKET, 0, 0, 0, ty as u16, &[], &mut out);
    if ret < 0 {
        return ret;
    }
    let netd_id = ret as u32;

    let idx = match alloc_slot(netd_id) {
        Some(i) => i,
        None => {
            // Roll back netd's slot so the two tables cannot drift apart.
            let mut sink = [0u8; 0];
            netd_call(OP_CLOSE, netd_id, 0, 0, 0, &[], &mut sink);
            return -task::EMFILE;
        }
    };

    // O_RDWR | O_NONBLOCK-ish: sockets take a dedicated flag word so poll can
    // tell them apart from files without re-entering the VFS.
    match crate::vfs::alloc_fd(SOCK_INODE_BASE + idx, task::FD_SOCK) {
        Some(fd) => fd as i64,
        None => {
            free_slot(idx);
            let mut sink = [0u8; 0];
            netd_call(OP_CLOSE, netd_id, 0, 0, 0, &[], &mut sink);
            -task::EMFILE
        }
    }
}

/// `connect(2)` on an IPv4 address.
pub fn sock_connect(fd: u32, addr: u32, port: u16) -> i64 {
    let idx = match slot_of(fd) {
        Some(i) => i,
        None => return -task::EBADF,
    };
    let netd_id = unsafe { SOCKS[idx].netd_id };
    let mut out = [0u8; 0];
    netd_call(OP_CONNECT, netd_id, addr, port, 0, &[], &mut out)
}

/// `sendto(2)` with no destination (connected socket).
pub fn sock_send(fd: u32, buf: *const u8, len: usize, flags: u16) -> i64 {
    if buf.is_null() || len == 0 {
        return 0;
    }
    if !task::user_range_valid(buf as u64, len, false) {
        return -task::EFAULT;
    }
    let idx = match slot_of(fd) {
        Some(i) => i,
        None => return -task::EBADF,
    };
    let netd_id = unsafe { SOCKS[idx].netd_id };
    let data = unsafe { core::slice::from_raw_parts(buf, len) };
    let mut out = [0u8; 0];
    netd_call(OP_SEND, netd_id, 0, 0, flags, data, &mut out)
}

/// `recvfrom(2)` on a connected socket. `from`/`fromlen` are ignored for now:
/// netd's proxy does not report peer addresses back through the facade.
pub fn sock_recv(fd: u32, buf: *mut u8, len: usize, _flags: u16) -> i64 {
    if buf.is_null() || len == 0 {
        return 0;
    }
    if !task::user_range_valid(buf as u64, len, true) {
        return -task::EFAULT;
    }
    let idx = match slot_of(fd) {
        Some(i) => i,
        None => return -task::EBADF,
    };
    let netd_id = unsafe { SOCKS[idx].netd_id };
    let want = core::cmp::min(len, MAX_XFER);
    let mut out = [0u8; MAX_XFER];
    // The max read rides in the flags word (u16, and MAX_XFER = 1460 fits);
    // the request carries no payload, so the header's len field is 0.
    let ret = netd_call(OP_RECV, netd_id, 0, 0, want as u16, &[], &mut out);
    if ret <= 0 {
        return ret;
    }
    let n = core::cmp::min(ret as usize, want);
    unsafe {
        core::ptr::copy_nonoverlapping(out.as_ptr(), buf, n);
    }
    n as i64
}

/// `shutdown(2)`.
pub fn sock_shutdown(fd: u32, how: u32) -> i64 {
    let idx = match slot_of(fd) {
        Some(i) => i,
        None => return -task::EBADF,
    };
    let netd_id = unsafe { SOCKS[idx].netd_id };
    let mut out = [0u8; 0];
    netd_call(OP_SHUTDOWN, netd_id, 0, 0, how as u16, &[], &mut out)
}

/// `bind(2)`. Not yet wired to netd's listener table; present so a program
/// that probes for it gets a coherent answer rather than -ENOSYS.
pub fn sock_bind(fd: u32, addr: u32, port: u16) -> i64 {
    let idx = match slot_of(fd) {
        Some(i) => i,
        None => return -task::EBADF,
    };
    let netd_id = unsafe { SOCKS[idx].netd_id };
    let mut out = [0u8; 0];
    netd_call(OP_BIND, netd_id, addr, port, 0, &[], &mut out)
}

/// `listen(2)`.
pub fn sock_listen(fd: u32, backlog: u32) -> i64 {
    let idx = match slot_of(fd) {
        Some(i) => i,
        None => return -task::EBADF,
    };
    let netd_id = unsafe { SOCKS[idx].netd_id };
    let mut out = [0u8; 0];
    netd_call(OP_LISTEN, netd_id, 0, 0, backlog as u16, &[], &mut out)
}

/// `accept(2)`. netd replies with the new socket's id; a kernel slot and fd
/// are allocated to match.
pub fn sock_accept(fd: u32) -> i64 {
    let idx = match slot_of(fd) {
        Some(i) => i,
        None => return -task::EBADF,
    };
    let netd_id = unsafe { SOCKS[idx].netd_id };
    let mut out = [0u8; 8];
    let ret = netd_call(OP_ACCEPT, netd_id, 0, 0, 0, &[], &mut out);
    if ret < 0 {
        return ret;
    }
    let new_id = ret as u32;
    let nidx = match alloc_slot(new_id) {
        Some(i) => i,
        None => {
            let mut sink = [0u8; 0];
            netd_call(OP_CLOSE, new_id, 0, 0, 0, &[], &mut sink);
            return -task::EMFILE;
        }
    };
    match crate::vfs::alloc_fd(SOCK_INODE_BASE + nidx, task::FD_SOCK) {
        Some(nfd) => nfd as i64,
        None => {
            free_slot(nidx);
            let mut sink = [0u8; 0];
            netd_call(OP_CLOSE, new_id, 0, 0, 0, &[], &mut sink);
            -task::EMFILE
        }
    }
}

/// Release a socket held by pseudo-inode `inode`.
///
/// Called from `vfs::close_fd`, which is the single choke point for descriptor
/// release — both `close(2)` and task exit go through it, exactly as pipe ends
/// are released there. netd is told to tear the connection down, but the
/// kernel slot is freed even if that round trip fails: a dead netd must not
/// leak slots, or the next `socket()` fails for reasons the caller cannot see
/// or fix.
pub fn sock_close_inode(inode: usize) {
    let idx = match sock_idx_of(inode) {
        Some(i) => i,
        None => return,
    };
    let socks = unsafe { &SOCKS };
    if !socks[idx].used {
        return;
    }
    let netd_id = socks[idx].netd_id;
    let mut out = [0u8; 0];
    netd_call(OP_CLOSE, netd_id, 0, 0, 0, &[], &mut out);
    free_slot(idx);
}

