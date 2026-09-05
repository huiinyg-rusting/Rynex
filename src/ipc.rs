//! General microkernel IPC: named ports with mailbox queues.
//!
//! This replaces the old fixed-64-byte, single-partner shared-memory + futex
//! design with a message-passing model suitable for kernel services:
//!
//!   * A *port* is a named mailbox. A service `ipc_create(name)`s a port and
//!     serves it; clients `ipc_connect(name)` to obtain the port id.
//!   * Messages are variable-length (up to 4 KiB - header), copied through a
//!     shared page, so there is no fixed slot size and no single-partner
//!     binding.  Many senders may post to one port; many receivers may drain.
//!   * `ipc_send` blocks when the mailbox is full; `ipc_recv` blocks when
//!     empty.  Both integrate with the kernel scheduler via a per-port futex
//!     wake word.
//!
//! All message buffers live in pages allocated from the buddy allocator, so
//! payloads are never copied twice and never touch user address spaces.
//!
//! Locking: The whole port table (PORTS), the next-id counter and the reply
//! slots (REPLIES) are guarded by a single `IPC_LOCK` RawSpin. Every state
//! mutation (enqueue / dequeue / port create+close / reply alloc+free+fill)
//! happens under `IPC_LOCK`. Because `ipc_send` / `ipc_recv` / `ipc_call` block
//! on futexes, they must never hold `IPC_LOCK` across the block: each loop
//! releases the lock, blocks on the (stable) wake word, and re-checks the state
//! under the lock on wakeup. Futex wakes are issued with the lock released.
//!
//! Lock order: IPC_LOCK -> BUDDY_LOCK (message / reply pages are allocated and
//! freed while holding IPC_LOCK). Nothing takes BUDDY_LOCK and then IPC_LOCK.

use crate::spinlock::RawSpin;

pub const MAX_PORTS: usize = 32;
pub const PORT_SLOTS: usize = 64;
pub const NAME_LEN: usize = 16;
pub const IPC_MSG_HEADER: u64 = 32;
pub const IPC_MSG_MAX: usize = 4096 - IPC_MSG_HEADER as usize;

/// Header at the start of every message page.
#[repr(C)]
struct MsgHeader {
    src_pid: u64,
    /// Reply token set by `ipc_call`; the service posts its reply to this
    /// token via `ipc_reply`. 0 means fire-and-forget (no reply expected).
    reply_id: u64,
    msg_type: u32,
    len: u32,
    _pad: u32,
    _pad2: u32,
}

#[derive(Clone, Copy)]
struct Port {
    used: bool,
    id: u64,
    name: [u8; NAME_LEN],
    // Physical pages, one per queued message.
    slots: [u64; PORT_SLOTS],
    head: usize,
    count: usize,
    // Futex wake words for blocked senders / receivers.
    wake_recv: u32,
    wake_send: u32,
}

impl Port {
    const fn empty() -> Self {
        Port {
            used: false,
            id: 0,
            name: [0; NAME_LEN],
            slots: [0; PORT_SLOTS],
            head: 0,
            count: 0,
            wake_recv: 0,
            wake_send: 0,
        }
    }
}

static mut PORTS: [Port; MAX_PORTS] = [Port::empty(); MAX_PORTS];
static mut NEXT_PORT_ID: u64 = 1;
static IPC_LOCK: RawSpin = RawSpin::new();

fn port_ref(idx: usize) -> &'static mut Port {
    unsafe { &mut PORTS[idx] }
}

fn reply_ref(idx: usize) -> &'static mut ReplySlot {
    unsafe { &mut REPLIES[idx] }
}

fn msg_hdr_ref(page: u64) -> &'static MsgHeader {
    unsafe { &*(page as *const MsgHeader) }
}

fn msg_hdr_mut(page: u64) -> &'static mut MsgHeader {
    unsafe { &mut *(page as *mut MsgHeader) }
}

fn alloc_page() -> Option<u64> {
    let alloc = { &mut *crate::memory::allocator() };
    let phys = alloc.alloc(0)?;
    unsafe { core::ptr::write_bytes(phys as *mut u8, 0, 4096); }
    Some(phys)
}

fn free_page(phys: u64) {
    let alloc = { &mut *crate::memory::allocator() };
    alloc.free(phys, 0);
}

// ── Port table lookups (IPC_LOCK must be held) ────────────────────

fn port_idx_by_id_locked(id: u64) -> Option<usize> {
    for i in 0..MAX_PORTS {
        if port_ref(i).used && port_ref(i).id == id {
            return Some(i);
        }
    }
    None
}

/// Exact-name lookup. IPC_LOCK must be held.
fn port_idx_by_name_locked(name: &[u8]) -> Option<usize> {
    if name.len() > NAME_LEN {
        return None;
    }
    for i in 0..MAX_PORTS {
        if !port_ref(i).used { continue; }
        let mut ok = true;
        for (j, &c) in name.iter().enumerate() {
            if port_ref(i).name[j] != c { ok = false; break; }
        }
        if ok && (name.len() == NAME_LEN || port_ref(i).name[name.len()] == 0) {
            return Some(i);
        }
    }
    None
}

// ── Reply channels ────────────────────────────────────────────────
// A synchronous request/reply call allocates a reply slot. The token is
// embedded in the request header; the service answers via `ipc_reply`, which
// writes into the slot's page and wakes the blocked caller.

const MAX_REPLIES: usize = 64;

#[derive(Clone, Copy)]
struct ReplySlot {
    used: bool,
    page: u64,
    len: u32,
    done: bool,
    wake: u32,
}

impl ReplySlot {
    const fn empty() -> Self {
        ReplySlot { used: false, page: 0, len: 0, done: false, wake: 0 }
    }
}

static mut REPLIES: [ReplySlot; MAX_REPLIES] = [ReplySlot::empty(); MAX_REPLIES];

fn reply_alloc() -> Option<u64> {
    let _g = RawSpin::lock(&IPC_LOCK);
    reply_alloc_locked()
}

/// IPC_LOCK must be held.
fn reply_alloc_locked() -> Option<u64> {
    let page = alloc_page()?;
    // Slot 0 is reserved: reply_id 0 means fire-and-forget (no reply
    // expected), so a real synchronous reply token must never be 0.
    for i in 1..MAX_REPLIES {
        if !reply_ref(i).used {
            let r = reply_ref(i);
            r.used = true;
            r.page = page;
            r.len = 0;
            r.done = false;
            r.wake = 0;
            return Some(i as u64);
        }
    }
    free_page(page);
    None
}

fn reply_free(id: u64) {
    let _g = RawSpin::lock(&IPC_LOCK);
    reply_free_locked(id);
}

/// IPC_LOCK must be held.
fn reply_free_locked(id: u64) {
    if id < MAX_REPLIES as u64 && reply_ref(id as usize).used {
        let s = reply_ref(id as usize);
        if s.page != 0 {
            free_page(s.page);
            s.page = 0;
        }
        s.used = false;
    }
}

/// Synchronous call: post `buf` to `port_id` and block until the service
/// replies (via `ipc_reply`). The reply payload is copied into `out` (up to
/// `out_len` bytes) and the length is returned; errors are negative errnos.
///
/// `buf`/`out` are validated as user-space pointers (default).
pub fn ipc_call(port_id: u64, buf: *const u8, len: usize, out: *mut u8, out_len: usize) -> i64 {
    ipc_call_impl(port_id, buf, len, out, out_len, false)
}

/// In-kernel variant: request/out buffers live in kernel space, so the
/// user-range check is skipped. Used only by kernel tasks (services/clients).
pub fn ipc_call_internal(
    port_id: u64, buf: *const u8, len: usize, out: *mut u8, out_len: usize,
) -> i64 {
    ipc_call_impl(port_id, buf, len, out, out_len, true)
}

fn ipc_call_impl(
    port_id: u64, buf: *const u8, len: usize, out: *mut u8, out_len: usize,
    kernel_buf: bool,
) -> i64 {
    if len > IPC_MSG_MAX { return -crate::task::EMSGSIZE; }
    let reply_id = match reply_alloc() {
        Some(id) => id,
        None => return -crate::task::ENOMEM,
    };
    let src = crate::task::current_task_id();

    // Post the request message to the mailbox (block while it is full).
    loop {
        let (free_slot, wake_addr) = {
            let _g = RawSpin::lock(&IPC_LOCK);
            let idx = match port_idx_by_id_locked(port_id) {
                Some(i) => i,
                None => { reply_free_locked(reply_id); return -crate::task::ESRCH; }
            };
            let port = port_ref(idx);
            if port.count < PORT_SLOTS {
                let page = match alloc_page() {
                    Some(p) => p,
                    None => { reply_free_locked(reply_id); return -crate::task::ENOMEM; }
                };
                let hdr = msg_hdr_mut(page);
                hdr.src_pid = src;
                hdr.reply_id = reply_id;
                hdr.msg_type = 0;
                hdr.len = len as u32;
                if len > 0 {
                    if !kernel_buf && !crate::task::user_range_valid(buf as u64, len, false) {
                        free_page(page);
                        reply_free_locked(reply_id);
                        return -crate::task::EFAULT;
                    }
                    unsafe {
                        core::ptr::copy_nonoverlapping(buf, (page as *mut u8).add(IPC_MSG_HEADER as usize), len);
                    }
                }
                let i2 = (port.head + port.count) % PORT_SLOTS;
                port.slots[i2] = page;
                port.count += 1;
                (true, &raw const port.wake_recv as *const u32)
            } else {
                (false, &raw const port.wake_send as *const u32)
            }
        };

        if free_slot {
            // Wake one blocked receiver, then wait for the reply.
            crate::task::futex_wake(wake_addr, 1);
            break;
        }
        if !crate::task::block_on_futex(wake_addr) {
            reply_free(reply_id);
            return -crate::task::EAGAIN;
        }
    }

    // Wait for the reply on our slot. Poll `done` before each block so a reply
    // that landed between the send and the block is not lost.
    let page;
    loop {
        let (exists, done, slot_page, wake_addr) = {
            let _g = RawSpin::lock(&IPC_LOCK);
            if reply_id < MAX_REPLIES as u64 && reply_ref(reply_id as usize).used {
                let s = reply_ref(reply_id as usize);
                (true, s.done, s.page, &raw const s.wake as *const u32)
            } else {
                (false, false, 0, core::ptr::null())
            }
        };
        if !exists {
            reply_free(reply_id);
            return -crate::task::ESRCH;
        }
        if done {
            page = slot_page;
            break;
        }
        if !crate::task::block_on_futex(wake_addr) {
            reply_free(reply_id);
            return -crate::task::EAGAIN;
        }
    }
    let len = {
        let _g = RawSpin::lock(&IPC_LOCK);
        reply_ref(reply_id as usize).len as usize
    };
    let rlen = core::cmp::min(len, out_len);
    if rlen > 0 && !out.is_null() {
        unsafe {
            core::ptr::copy_nonoverlapping(page as *const u8, out, rlen);
        }
    }
    reply_free(reply_id);
    len as i64
}

/// Answer a `ipc_call` from a service: copy `buf` into the reply slot and wake
/// the blocked caller. Returns 0 on success, -ESRCH if the token is stale.
/// Idempotent: a second reply to an already-answered token is ignored so that
/// handlers which answer directly and `handle_with_reply`'s auto-answer don't
/// clobber each other.
pub fn ipc_reply(reply_id: u64, buf: *const u8, len: usize) -> i64 {
    let (n, wake_addr) = {
        let _g = RawSpin::lock(&IPC_LOCK);
        if reply_id >= MAX_REPLIES as u64 || !reply_ref(reply_id as usize).used {
            return -crate::task::ESRCH;
        }
        let s = reply_ref(reply_id as usize);
        if s.done {
            return 0;
        }
        let page = s.page;
        let n = core::cmp::min(len, IPC_MSG_MAX);
        if n > 0 && !buf.is_null() {
            unsafe { core::ptr::copy_nonoverlapping(buf, page as *mut u8, n); }
        }
        s.len = n as u32;
        s.done = true;
        (n, &raw const s.wake as *const u32)
    };
    crate::task::futex_wake(wake_addr, 1);
    n as i64
}

/// Create a named port (service side). Returns the port id.
pub fn ipc_create(name_ptr: *const u8, name_len: usize) -> i64 {
    if name_ptr.is_null() || name_len == 0 || name_len > NAME_LEN {
        return -crate::task::EINVAL;
    }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len) };
    let _g = RawSpin::lock(&IPC_LOCK);
    // Reject duplicate names.
    if port_idx_by_name_locked(name).is_some() {
        return -crate::task::EEXIST;
    }
    for i in 0..MAX_PORTS {
        if !port_ref(i).used {
            let p = port_ref(i);
            p.used = true;
            p.id = unsafe { NEXT_PORT_ID };
            unsafe { NEXT_PORT_ID += 1; }
            for (j, &c) in name.iter().enumerate() {
                p.name[j] = c;
            }
            p.head = 0;
            p.count = 0;
            p.wake_recv = 0;
            p.wake_send = 0;
            crate::serial::write_str("IPC: create port ");
            crate::serial::write_str(&alloc::format!("{}", core::str::from_utf8(name).unwrap_or("?")));
            crate::serial::write_str(" id=");
            crate::serial::write_dec(p.id);
            crate::serial::write_str("\n");
            return p.id as i64;
        }
    }
    -crate::task::ENOMEM
}

/// Connect to a named port (client side). Returns the port id or -ESRCH.
pub fn ipc_connect(name_ptr: *const u8, name_len: usize) -> i64 {
    if name_ptr.is_null() || name_len == 0 || name_len > NAME_LEN {
        return -crate::task::EINVAL;
    }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len) };
    let _g = RawSpin::lock(&IPC_LOCK);
    match port_idx_by_name_locked(name) {
        Some(i) => port_ref(i).id as i64,
        None => -crate::task::ESRCH,
    }
}

/// Post a message to a port. Blocks while the mailbox is full.
pub fn ipc_send(port_id: u64, buf: *const u8, len: usize, msg_type: u32) -> i64 {
    if len > IPC_MSG_MAX {
        return -crate::task::EMSGSIZE;
    }
    let src = crate::task::current_task_id();

    loop {
        let (free_slot, wake_addr) = {
            let _g = RawSpin::lock(&IPC_LOCK);
            let idx = match port_idx_by_id_locked(port_id) {
                Some(i) => i,
                None => return -crate::task::ESRCH,
            };
            let port = port_ref(idx);
            if port.count < PORT_SLOTS {
                let page = match alloc_page() {
                    Some(p) => p,
                    None => return -crate::task::ENOMEM,
                };
                let hdr = msg_hdr_mut(page);
                hdr.src_pid = src;
                hdr.msg_type = msg_type;
                hdr.len = len as u32;
                if len > 0 {
                    if !crate::task::user_range_valid(buf as u64, len, false) {
                        free_page(page);
                        return -crate::task::EFAULT;
                    }
                    unsafe {
                        core::ptr::copy_nonoverlapping(buf, (page as *mut u8).add(IPC_MSG_HEADER as usize), len);
                    }
                }
                let i2 = (port.head + port.count) % PORT_SLOTS;
                port.slots[i2] = page;
                port.count += 1;
                (true, &raw const port.wake_recv as *const u32)
            } else {
                (false, &raw const port.wake_send as *const u32)
            }
        };

        if free_slot {
            // Wake one blocked receiver.
            crate::task::futex_wake(wake_addr, 1);
            return 0;
        }
        // Mailbox full: block on the send wake word.
        if !crate::task::block_on_futex(wake_addr) {
            return -crate::task::EAGAIN;
        }
    }
}

/// Receive a message from a port into `buf`. Blocks while the mailbox is empty.
/// Returns the message length (bytes) or a negative error.
pub fn ipc_recv(port_id: u64, buf: *mut u8, max_len: usize) -> i64 {
    let page = loop {
        let (got, pg, wake_addr) = {
            let _g = RawSpin::lock(&IPC_LOCK);
            let idx = match port_idx_by_id_locked(port_id) {
                Some(i) => i,
                None => return -crate::task::ESRCH,
            };
            let port = port_ref(idx);
            if port.count > 0 {
                let i2 = port.head;
                let p = port.slots[i2];
                port.head = (i2 + 1) % PORT_SLOTS;
                port.count -= 1;
                (true, p, &raw const port.wake_send as *const u32)
            } else {
                (false, 0, &raw const port.wake_recv as *const u32)
            }
        };
        if got {
            crate::task::futex_wake(wake_addr, 1);
            break pg;
        }
        if !crate::task::block_on_futex(wake_addr) {
            return -crate::task::EAGAIN;
        }
    };

    let hdr = msg_hdr_ref(page);
    let len = hdr.len as usize;
    let out_len = core::cmp::min(len, max_len);
    if out_len > 0 && !buf.is_null() {
        if !crate::task::user_range_valid(buf as u64, out_len, true) {
            free_page(page);
            return -crate::task::EFAULT;
        }
        unsafe {
            core::ptr::copy_nonoverlapping((page as *const u8).add(IPC_MSG_HEADER as usize), buf, out_len);
        }
    }
    free_page(page);
    len as i64
}

/// Non-blocking receive that also returns the reply token.
/// Returns (length, reply_id); length is 0 when the mailbox is empty.
/// `buf` is validated as a user-space pointer (default). Kernel tasks should
/// use `ipc_peek_ex_internal` so their kernel-stack buffers are accepted.
pub fn ipc_peek_ex(port_id: u64, buf: *mut u8, max_len: usize) -> (i64, u64) {
    ipc_peek_ex_impl(port_id, buf, max_len, false)
}

/// In-kernel variant of `ipc_peek_ex`: `buf` lives in kernel space, so the
/// user-range check is skipped. Used by kernel service loops.
pub fn ipc_peek_ex_internal(port_id: u64, buf: *mut u8, max_len: usize) -> (i64, u64) {
    ipc_peek_ex_impl(port_id, buf, max_len, true)
}

fn ipc_peek_ex_impl(port_id: u64, buf: *mut u8, max_len: usize, kernel_buf: bool) -> (i64, u64) {
    let page = {
        let _g = RawSpin::lock(&IPC_LOCK);
        let idx = match port_idx_by_id_locked(port_id) {
            Some(i) => i,
            None => return (-crate::task::ESRCH, 0),
        };
        let port = port_ref(idx);
        if port.count == 0 { return (0, 0); }
        let i2 = port.head;
        let pg = port.slots[i2];
        port.head = (i2 + 1) % PORT_SLOTS;
        port.count -= 1;
        let ws = &raw const port.wake_send as *const u32;
        crate::task::futex_wake(ws, 1);
        pg
    };

    let hdr = msg_hdr_ref(page);
    let len = hdr.len as usize;
    let reply_id = hdr.reply_id;
    let out_len = core::cmp::min(len, max_len);
    if out_len > 0 && !buf.is_null() {
        if !kernel_buf && !crate::task::user_range_valid(buf as u64, out_len, true) {
            free_page(page);
            return (-crate::task::EFAULT, 0);
        }
        unsafe {
            core::ptr::copy_nonoverlapping((page as *const u8).add(IPC_MSG_HEADER as usize), buf, out_len);
        }
    }
    free_page(page);
    (len as i64, reply_id)
}

/// Receive a message from a port, also returning the reply token from the
/// message header (0 for fire-and-forget). Returns (length, reply_id). `buf`
/// is validated as a user-space pointer (default); kernel tasks should use
/// `ipc_recv_ex_internal`.
pub fn ipc_recv_ex(port_id: u64, buf: *mut u8, max_len: usize) -> (i64, u64) {
    ipc_recv_ex_impl(port_id, buf, max_len, false)
}

/// User-space syscall wrapper for `ipc_recv_ex`: packs (len, reply_id) into
/// a single i64 so the syscall ABI (single return register) can carry both.
/// The reply token is returned in the high 32 bits, the length in the low 32.
pub fn ipc_recv_ex_user(port_id: u64, buf: *mut u8, max_len: usize) -> i64 {
    let (len, reply_id) = ipc_recv_ex_impl(port_id, buf, max_len, false);
    if len < 0 {
        return len;
    }
    let rl = if len > i64::from(u32::MAX) { u32::MAX as i64 } else { len };
    let rid = (reply_id & 0xFFFF_FFFF) << 32;
    rid as i64 | rl
}

/// In-kernel variant of `ipc_recv_ex`: `buf` lives in kernel space, so the
/// user-range check is skipped. Used by kernel service tasks.
pub fn ipc_recv_ex_internal(port_id: u64, buf: *mut u8, max_len: usize) -> (i64, u64) {
    ipc_recv_ex_impl(port_id, buf, max_len, true)
}

fn ipc_recv_ex_impl(port_id: u64, buf: *mut u8, max_len: usize, kernel_buf: bool) -> (i64, u64) {
    let page = loop {
        let (got, pg, wake_addr) = {
            let _g = RawSpin::lock(&IPC_LOCK);
            let idx = match port_idx_by_id_locked(port_id) {
                Some(i) => i,
                None => return (-crate::task::ESRCH, 0),
            };
            let port = port_ref(idx);
            if port.count > 0 {
                let i2 = port.head;
                let p = port.slots[i2];
                port.head = (i2 + 1) % PORT_SLOTS;
                port.count -= 1;
                (true, p, &raw const port.wake_send as *const u32)
            } else {
                (false, 0, &raw const port.wake_recv as *const u32)
            }
        };
        if got {
            crate::task::futex_wake(wake_addr, 1);
            break pg;
        }
        if !crate::task::block_on_futex(wake_addr) {
            return (-crate::task::EAGAIN, 0);
        }
    };

    let hdr = msg_hdr_ref(page);
    let len = hdr.len as usize;
    let reply_id = hdr.reply_id;
    let out_len = core::cmp::min(len, max_len);
    if out_len > 0 && !buf.is_null() {
        if !kernel_buf && !crate::task::user_range_valid(buf as u64, out_len, true) {
            free_page(page);
            return (-crate::task::EFAULT, 0);
        }
        unsafe {
            core::ptr::copy_nonoverlapping((page as *const u8).add(IPC_MSG_HEADER as usize), buf, out_len);
        }
    }
    free_page(page);
    (len as i64, reply_id)
}

/// Non-blocking receive: returns 0 if the mailbox is empty (rather than
/// blocking), the message length on success, or a negative error.
pub fn ipc_peek(port_id: u64, buf: *mut u8, max_len: usize) -> i64 {
    let page = {
        let _g = RawSpin::lock(&IPC_LOCK);
        let idx = match port_idx_by_id_locked(port_id) {
            Some(i) => i,
            None => return -crate::task::ESRCH,
        };
        let port = port_ref(idx);
        if port.count == 0 { return 0; }
        let i2 = port.head;
        let pg = port.slots[i2];
        port.head = (i2 + 1) % PORT_SLOTS;
        port.count -= 1;
        // Wake one blocked sender.
        let ws = &raw const port.wake_send as *const u32;
        crate::task::futex_wake(ws, 1);
        pg
    };

    let hdr = msg_hdr_ref(page);
    let len = hdr.len as usize;
    let out_len = core::cmp::min(len, max_len);
    if out_len > 0 && !buf.is_null() {
        if !crate::task::user_range_valid(buf as u64, out_len, true) {
            free_page(page);
            return -crate::task::EFAULT;
        }
        unsafe {
            core::ptr::copy_nonoverlapping((page as *const u8).add(IPC_MSG_HEADER as usize), buf, out_len);
        }
    }
    free_page(page);
    len as i64
}

/// Destroy a port and free any queued messages.
pub fn ipc_close(port_id: u64) -> i64 {
    let _g = RawSpin::lock(&IPC_LOCK);
    for i in 0..MAX_PORTS {
        let p = port_ref(i);
        if p.used && p.id == port_id {
            for j in 0..p.count {
                let idx = (p.head + j) % PORT_SLOTS;
                if p.slots[idx] != 0 {
                    free_page(p.slots[idx]);
                    p.slots[idx] = 0;
                }
            }
            // Wake any blocked parties so they can observe ESRCH/retry.
            crate::task::futex_wake(&raw const p.wake_recv as *const u32, u32::MAX);
            crate::task::futex_wake(&raw const p.wake_send as *const u32, u32::MAX);
            *p = Port::empty();
            return 0;
        }
    }
    -crate::task::ESRCH
}

// ── Legacy shared-memory shim (kept ABI-compatible) ─────────────
// The old shm_* API was single-partner shared memory. It is retained as a thin
// shim on top of a fixed port so existing callers keep working while new
// clients migrate to the port API.

pub const IPC_VADDR: u64 = 0x6000_0000_0000;

/// Map the shm port for a process. Because the new IPC copies through kernel
/// pages there is no shared mapping needed; this returns success for
/// compatibility.
pub fn shm_setup(partner_id: u64, _vaddr: u64) -> i64 {
    // New IPC needs no setup: keep a placeholder port-name binding by pid so
    // the old syscall numbers remain harmless no-ops rather than failures.
    if partner_id == 0 { return -crate::task::EINVAL; }
    if crate::task::current_task_id() == 0 { return -crate::task::EINVAL; }
    0
}

pub fn shm_notify(_partner_id: u64) -> i64 { 0 }
pub fn shm_wait(_timeout_ms: u64) -> i64 { 0 }
pub fn shm_teardown(_partner_id: u64) -> i64 { 0 }

// Register a kernel service under a well-known name. Returns 0 on success.
pub fn register_service(name: &[u8]) -> i64 {
    ipc_create(name.as_ptr(), name.len())
}

pub fn init() {
    // Nothing to init: ports are created on demand by services.
}
