//! In-kernel service layer.
//!
//! Rynex is being decomposed into a microkernel: drivers and filesystems run
//! as *services* that communicate over the kernel's message-passing IPC
//! (`ipc.rs`). In this phase the services still live inside the kernel address
//! space (so they can touch I/O ports / page tables directly), but they are
//! already addressable as named IPC ports, which is the seam that lets each
//! service be moved into a user-space process later without changing its
//! interface.
//!
//! Registered services (phase 1):
//!   - `vfs`    — filesystem operations (ramfs, ext3)
//!   - `console`— /dev/tty0, VGA text output, termios
//!   - `kbd`    — keyboard input stream
//!
//! Each service is a `Service` with a name and a `handle` function. The IPC
//! bridge (`service_dispatch`) receives a request message on the service port,
//! decodes the operation, calls the handler, and posts the reply back.

use crate::ipc;
use crate::serial;
use crate::vfs_core::VnodeOps;

pub const MAX_SERVICES: usize = 8;
pub const NAME_LEN: usize = 16;
pub const MAX_REQUEST: usize = 4096;

/// A kernel service: a named mailbox + a message handler.
#[derive(Clone, Copy)]
struct Service {
    name: [u8; NAME_LEN],
    name_len: usize,
    port_id: u64,
    handle: fn(&[u8]) -> i64,
}

static mut SERVICES: [Service; MAX_SERVICES] = [Service {
    name: [0; NAME_LEN],
    name_len: 0,
    port_id: 0,
    handle: |_| -1,
}; MAX_SERVICES];
static mut SERVICE_COUNT: usize = 0;

/// Register a service under `name`. The service must have been created as an
/// IPC port (via `ipc::ipc_create`) so clients can connect by name. Returns 0.
pub fn register(name: &[u8], handle: fn(&[u8]) -> i64) -> i64 {
    if name.is_empty() || name.len() > NAME_LEN {
        return -crate::task::EINVAL;
    }
    // Create (or reuse) the named port.
    let port = ipc::ipc_create(name.as_ptr(), name.len());
    if port < 0 {
        // Already exists: reuse it.
        let existing = ipc::ipc_connect(name.as_ptr(), name.len());
        if existing < 0 { return existing; }
        return attach(name, existing as u64, handle);
    }
    attach(name, port as u64, handle)
}

fn attach(name: &[u8], port_id: u64, handle: fn(&[u8]) -> i64) -> i64 {
    unsafe {
        for i in 0..MAX_SERVICES {
            if SERVICES[i].port_id == port_id {
                return 0; // already registered
            }
        }
        if SERVICE_COUNT >= MAX_SERVICES {
            return -crate::task::ENOMEM;
        }
        let s = &mut SERVICES[SERVICE_COUNT];
        for (j, &c) in name.iter().enumerate() {
            s.name[j] = c;
        }
        s.name_len = name.len();
        s.port_id = port_id;
        s.handle = handle;
        SERVICE_COUNT += 1;
    }
    serial::write_str("SVC: registered '");
    serial::write_str(&alloc::format!("{}", core::str::from_utf8(name).unwrap_or("?")));
    serial::write_str("' port=");
    serial::write_dec(port_id);
    serial::write_str("\n");
    0
}

/// Look up a service's port id by name.
pub fn lookup(name: &[u8]) -> Option<u64> {
    ipc::ipc_connect(name.as_ptr(), name.len()).try_into().ok()
}

/// Service request/response protocol.
///
/// A request message is laid out as:
///   [0..8)   opcode (u64, little-endian)
///   [8..16)  inode/vnode id (u64)
///   [16..24) offset (u64)
///   [24..32) flags/mode (u64)
///   [32..)   payload bytes
///
/// The handler returns an i64 result.
pub fn service_call(port_id: u64, request: &[u8]) -> i64 {
    // Find handler by port.
    unsafe {
        for i in 0..MAX_SERVICES {
            if SERVICES[i].port_id == port_id {
                return (SERVICES[i].handle)(request);
            }
        }
    }
    -crate::task::ENOSYS
}

/// Poll a single port and handle any pending request. Non-blocking; a service
/// loop calls this repeatedly. Returns the number of requests handled.
pub fn poll(port_id: u64) -> usize {
    let mut handled = 0;
    loop {
        let mut buf = [0u8; 512];
        match ipc::ipc_peek(port_id, buf.as_mut_ptr(), buf.len()) {
            0 => break,
            n if n < 0 => break,
            n => {
                service_call(port_id, &buf[..n as usize]);
                handled += 1;
            }
        }
    }
    handled
}

/// Background service loop for a name. Blocks on the service port and handles
/// each request as it arrives. Used for services that run as their own task.
pub fn serve(name: &[u8]) -> ! {
    let port = match ipc::ipc_connect(name.as_ptr(), name.len()) {
        p if p >= 0 => p as u64,
        _ => {
            serial::write_str("SVC: no port for '");
            serial::write_str(&alloc::format!("{}", core::str::from_utf8(name).unwrap_or("?")));
            serial::write_str("'\n");
            loop { unsafe { core::arch::asm!("hlt", options(nostack, nomem)); } }
        }
    };
    loop {
        let mut buf = [0u8; MAX_REQUEST];
        let n = ipc::ipc_recv(port, buf.as_mut_ptr(), MAX_REQUEST);
        if n < 0 { continue; }
        service_call(port, &buf[..n as usize]);
    }
}

// ── Built-in handlers ────────────────────────────────────────────
// These are the phase-1 in-kernel implementations of each service. Each maps
// the IPC request wire format to the existing subsystem (vfs_core, tty).

/// VFS service handler. Request layout:
///   [0..8)  VfsOp discriminant (u64)
///   [8..16) extra1 / vnode id
///   [16..24) offset / request
///   [24..32) data_len / mode
///   [32..)   path or payload
pub fn vfs_handler(req: &[u8]) -> i64 {
    use crate::vfs_core::VfsOp;
    if req.len() < 32 { return -crate::task::EINVAL; }
    let op = read_u64(req, 0);
    let extra1 = read_u64(req, 8);
    let offset = read_u64(req, 16);
    let mode = read_u64(req, 24);
    let payload = &req[32..];

    let mut msg = crate::vfs_core::VfsMessage::new();
    msg.op = match op {
        0 => VfsOp::Read, 1 => VfsOp::Write, 2 => VfsOp::Lookup,
        3 => VfsOp::ReadDir, 4 => VfsOp::Create, 5 => VfsOp::MkDir,
        6 => VfsOp::Remove, 7 => VfsOp::RmDir, 8 => VfsOp::Stat,
        9 => VfsOp::Open, 10 => VfsOp::Ioctl, 11 => VfsOp::Truncate,
        _ => return -crate::task::EINVAL,
    };
    msg.extra1 = extra1;
    msg.offset = offset;
    msg.mode = mode as u32;
    msg.data_len = payload.len();
    // Point data into the request payload (borrowed, valid during dispatch).
    msg.data = payload.as_ptr() as *mut u8;
    let path_len = core::cmp::min(payload.len(), crate::vfs_core::types::MAX_PATH);
    for (i, &b) in payload[..path_len].iter().enumerate() {
        msg.path_buf[i] = b;
    }
    msg.path_len = path_len;

    crate::vfs_core::dispatch(&mut msg);
    msg.result
}

/// Console / TTY service handler. Write payload bytes to the console.
pub fn console_handler(req: &[u8]) -> i64 {
    if req.len() < 32 { return -crate::task::EINVAL; }
    let op = read_u64(req, 0);
    let payload = &req[32..];
    match op {
        0 => {
            // write to console
            crate::tty::TTY_DEVICE.write(0, 0, payload).map(|n| n as i64).unwrap_or(-1)
        }
        1 => {
            // read from console (blocking, canonical)
            let mut out = [0u8; 256];
            let n = crate::tty::TTY_DEVICE.read(0, 0, &mut out).unwrap_or(0);
            // Copy read bytes back into the reply is not possible without a
            // reply channel; phase-1 in-kernel clients read directly. Return 0.
            let _ = n;
            0
        }
        _ => -crate::task::EINVAL,
    }
}

/// Keyboard service handler: return the next buffered character or 0 if none.
pub fn kbd_handler(req: &[u8]) -> i64 {
    if req.len() < 32 { return -crate::task::EINVAL; }
    let op = read_u64(req, 0);
    match op {
        0 => match crate::keyboard::pop_char() {
            Some(c) => c as i64,
            None => 0,
        },
        _ => -crate::task::EINVAL,
    }
}

fn read_u64(buf: &[u8], off: usize) -> u64 {
    if off + 8 > buf.len() { return 0; }
    let mut v = [0u8; 8];
    v.copy_from_slice(&buf[off..off + 8]);
    u64::from_le_bytes(v)
}
