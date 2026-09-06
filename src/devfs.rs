//! devfs: kernel device registry.
//!
//! Devices register themselves (a name, a device-specific inode number, a
//! major/minor pair and a `VnodeOps` implementation) via `devfs_register`, and
//! `devfs_init` materialises `/dev/<name>` entries for every registered device
//! at boot. This replaces the previous hardcoded, copy-pasted block in
//! `task::boot_userland`.
//!
//! This is the kernel-side *plumbing* (device registry + `/dev` population).
//! For every node it materialises, `devfs_init` also enqueues a Linux-style
//! "add" uevent (NUL-separated `KEY=VALUE` records) on the `/dev/uevent`
//! pseudo-device. A user-space eudev `udevd` reads those records and runs the
//! real rules engine over them; the registry stays the single source of truth
//! so `/dev` never goes stale.

use crate::spinlock::Mutex;
use crate::vfs_core::types::*;
use crate::vfs_core::VnodeOps;
use core::sync::atomic::{AtomicU64, Ordering};

/// Maximum number of registered character devices.
const MAX_DEVICES: usize = 32;
/// Maximum device name length.
const NAME_LEN: usize = 32;

/// /dev/uevent queue capacity (oldest records are dropped when full).
const UEVENT_QUEUE_CAP: usize = 64;
/// Maximum length of a single uevent record (including trailing NUL).
const UEVENT_MAX_LEN: usize = 512;

/// Ring buffer of kernel uevents handed to the user-space udev daemon.
struct UeventQueue {
    slots: [[u8; UEVENT_MAX_LEN]; UEVENT_QUEUE_CAP],
    lens: [usize; UEVENT_QUEUE_CAP],
    head: usize,
    count: usize,
}

impl UeventQueue {
    const fn empty() -> Self {
        UeventQueue {
            slots: [[0; UEVENT_MAX_LEN]; UEVENT_QUEUE_CAP],
            lens: [0; UEVENT_QUEUE_CAP],
            head: 0,
            count: 0,
        }
    }

    /// Append one uevent record. When the queue is full the oldest record is
    /// dropped so a slow reader can never stall the boot-time producers.
    fn push(&mut self, msg: &[u8]) {
        if msg.is_empty() || msg.len() > UEVENT_MAX_LEN {
            return;
        }
        if self.count == UEVENT_QUEUE_CAP {
            self.head = (self.head + 1) % UEVENT_QUEUE_CAP;
            self.count -= 1;
        }
        let tail = (self.head + self.count) % UEVENT_QUEUE_CAP;
        self.slots[tail][..msg.len()].copy_from_slice(msg);
        self.lens[tail] = msg.len();
        self.count += 1;
    }

    /// Pop the oldest uevent record into `buf`. `Ok(0)` means the queue is
    /// empty. Returns `Err("EINVAL")` (and drops the record) if the caller's
    /// buffer is too small for the record.
    fn pop(&mut self, buf: &mut [u8]) -> Result<usize, &'static str> {
        if self.count == 0 {
            return Ok(0);
        }
        let len = self.lens[self.head];
        if len > buf.len() {
            self.head = (self.head + 1) % UEVENT_QUEUE_CAP;
            self.count -= 1;
            return Err("EINVAL");
        }
        buf[..len].copy_from_slice(&self.slots[self.head][..len]);
        self.head = (self.head + 1) % UEVENT_QUEUE_CAP;
        self.count -= 1;
        Ok(len)
    }
}

static UEVENT_QUEUE: Mutex<UeventQueue> = Mutex::new(UeventQueue::empty());
static UEVENT_SEQ: AtomicU64 = AtomicU64::new(0);

/// Provides the sequence numbers used in emitted uevents.
fn uevent_next_seq() -> u64 {
    UEVENT_SEQ.fetch_add(1, Ordering::SeqCst) + 1
}

/// Write `v` as decimal ASCII into `buf`, returning the used slice.
fn dec_buf(mut v: u64, buf: &mut [u8; 24]) -> &[u8] {
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    &buf[i..]
}

/// Enqueue a Linux-style "add" uevent for a freshly materialised `/dev` node.
/// The record is NUL-separated `KEY=VALUE` pairs, NUL-terminated, exactly the
/// format `udev_device_new_from_nulstr` (eudev) parses.
fn uevent_emit(action: &[u8], sysname: &[u8], subsystem: &[u8], major: u64, minor: u64) {
    let mut msg = [0u8; UEVENT_MAX_LEN];
    let mut p = 0usize;

    macro_rules! ap {
        ($s:expr) => {{
            let s: &[u8] = $s;
            if p + s.len() + 1 <= UEVENT_MAX_LEN {
                msg[p..p + s.len()].copy_from_slice(s);
                p += s.len();
                msg[p] = 0;
                p += 1;
            }
        }};
    }

    ap!(b"ACTION=");
    ap!(action);
    ap!(b"DEVPATH=/devices/rynex/");
    ap!(sysname);
    ap!(b"SUBSYSTEM=");
    ap!(subsystem);
    ap!(b"DEVNAME=/dev/");
    ap!(sysname);
    let mut nb = [0u8; 24];
    ap!(b"MAJOR=");
    ap!(dec_buf(major, &mut nb));
    ap!(b"MINOR=");
    ap!(dec_buf(minor, &mut nb));
    ap!(b"SEQNUM=");
    ap!(dec_buf(uevent_next_seq(), &mut nb));

    if p == 0 {
        return;
    }

    UEVENT_QUEUE.lock().push(&msg[..p]);

    crate::serial::write_str("devfs: uevent '");
    crate::serial::write_str(core::str::from_utf8(action).unwrap_or("?"));
    crate::serial::write_str("' for '");
    crate::serial::write_str(core::str::from_utf8(sysname).unwrap_or("?"));
    crate::serial::write_str("' (major=");
    crate::serial::write_dec(major);
    crate::serial::write_str(",minor=");
    crate::serial::write_dec(minor);
    crate::serial::write_str(")\n");
}

/// /dev/uevent: kernel -> user-space udev bridge. A read() returns one complete
/// uevent record, blocking (with yields) while the queue is empty.
struct UeventDevice;

impl VnodeOps for UeventDevice {
    fn read(&self, _ino: u64, _offset: u64, buf: &mut [u8]) -> Result<usize, &'static str> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut wait: u64 = 0;
        loop {
            {
                let mut q = UEVENT_QUEUE.lock();
                match q.pop(buf) {
                    Ok(0) => {}
                    Ok(n) => return Ok(n),
                    Err(e) => return Err(e),
                }
            }
            // Queue empty. Yields so the scheduler runs other tasks; we
            // re-check on every resume (same pattern as the TTY devices).
            wait += 1;
            if wait % 100000 == 0 {
                crate::task::yield_now_force();
            }
        }
    }
    fn write(&self, _ino: u64, _offset: u64, buf: &[u8]) -> Result<usize, &'static str> {
        Err("EPERM")
    }
    fn lookup(&self, _parent_ino: u64, _name: &[u8]) -> Result<u64, &'static str> {
        Err("not a directory")
    }
    fn readdir(&self, _dir_ino: u64, _offset: u64, _buf: &mut [Dirent]) -> Result<usize, &'static str> {
        Err("not a directory")
    }
    fn create(&self, _parent_ino: u64, _name: &[u8], _mode: FileMode) -> Result<u64, &'static str> {
        Err("not a directory")
    }
    fn mkdir(&self, _parent_ino: u64, _name: &[u8], _mode: FileMode) -> Result<u64, &'static str> {
        Err("not a directory")
    }
    fn remove(&self, _parent_ino: u64, _name: &[u8]) -> Result<(), &'static str> {
        Err("not a directory")
    }
    fn rmdir(&self, _parent_ino: u64, _name: &[u8]) -> Result<(), &'static str> {
        Err("not a directory")
    }
    fn stat(&self, _ino: u64) -> Result<Stat, &'static str> {
        Err("not supported")
    }
    fn readlink(&self, _ino: u64) -> Result<&[u8], &'static str> {
        Err("not a symlink")
    }
    fn symlink(&self, _parent_ino: u64, _name: &[u8], _target: &[u8]) -> Result<u64, &'static str> {
        Err("not a directory")
    }
    fn rename(&self, _old_parent: u64, _old_name: &[u8], _new_parent: u64, _new_name: &[u8]) -> Result<(), &'static str> {
        Err("not a directory")
    }
    fn setattr(&self, _ino: u64, _attr: &Attr) -> Result<(), &'static str> {
        Err("not supported")
    }
    fn getxattr(&self, _ino: u64, _name: &[u8], _value: &mut [u8]) -> Result<usize, &'static str> {
        Err("not supported")
    }
    fn setxattr(&self, _ino: u64, _name: &[u8], _value: &[u8]) -> Result<(), &'static str> {
        Err("not supported")
    }
    fn listxattr(&self, _ino: u64, _buf: &mut [u8]) -> Result<usize, &'static str> {
        Err("not supported")
    }
    fn truncate(&self, _ino: u64, _size: u64) -> Result<(), &'static str> {
        Err("not supported")
    }
    fn ioctl(&self, _ino: u64, _request: u64, _arg: u64) -> Result<usize, &'static str> {
        Err("not supported")
    }
}

static UEVENT_DEVICE: UeventDevice = UeventDevice;

#[derive(Clone, Copy)]
struct DevEntry {
    name: [u8; NAME_LEN],
    name_len: usize,
    /// Device-specific inode number handed to the device's `VnodeOps`.
    dev_ino: u64,
    major: u64,
    minor: u64,
    ops: &'static dyn VnodeOps,
    used: bool,
}

impl DevEntry {
    const fn empty() -> Self {
        DevEntry {
            name: [0; NAME_LEN],
            name_len: 0,
            dev_ino: 0,
            major: 0,
            minor: 0,
            ops: &crate::vfs_core::NOP_VNODE,
            used: false,
        }
    }
}

/// Safety: DevEntry fields are all Copy-safe; the name byte array is plain data.
unsafe impl Send for DevEntry {}
unsafe impl Sync for DevEntry {}

static mut DEVS: [DevEntry; MAX_DEVICES] = [DevEntry::empty(); MAX_DEVICES];
static mut DEV_COUNT: usize = 0;

/// Register a character device. `name` is the `/dev` node name (e.g. `b"console"`),
/// `dev_ino` is the inode number passed to the device's `VnodeOps`, and `ops`
/// implements the device's read/write/ioctl behaviour.
///
/// The device node is only materialised in `/dev` when `devfs_init` runs, so
/// drivers must register before that (or call `devfs_add_node` explicitly).
pub fn devfs_register(name: &[u8], dev_ino: u64, major: u64, minor: u64, ops: &'static dyn VnodeOps) {
    if name.is_empty() || name.len() > NAME_LEN {
        return;
    }
    unsafe {
        for i in 0..MAX_DEVICES {
            if DEVS[i].used {
                // Replace an existing registration with the same name.
                let same = DEVS[i].name_len == name.len()
                    && DEVS[i].name[..DEVS[i].name_len] == *name;
                if same {
                    DEVS[i].dev_ino = dev_ino;
                    DEVS[i].major = major;
                    DEVS[i].minor = minor;
                    DEVS[i].ops = ops;
                    return;
                }
            }
        }
        for i in 0..MAX_DEVICES {
            if !DEVS[i].used {
                for (j, &c) in name.iter().enumerate() {
                    DEVS[i].name[j] = c;
                }
                DEVS[i].name_len = name.len();
                DEVS[i].dev_ino = dev_ino;
                DEVS[i].major = major;
                DEVS[i].minor = minor;
                DEVS[i].ops = ops;
                DEVS[i].used = true;
                DEV_COUNT += 1;
                return;
            }
        }
    }
}

/// Query a device's `VnodeOps` by its `/dev` node name. Returns `None` if not
/// registered. Used by the user-space udev daemon bridge.
pub fn devfs_lookup(name: &[u8]) -> Option<&'static dyn VnodeOps> {
    unsafe {
        for i in 0..MAX_DEVICES {
            if DEVS[i].used && DEVS[i].name_len == name.len()
                && DEVS[i].name[..DEVS[i].name_len] == *name
            {
                return Some(DEVS[i].ops);
            }
        }
    }
    None
}

/// Number of registered devices (used for audit / udev introspection).
pub fn devfs_count() -> usize {
    unsafe { DEV_COUNT }
}

/// Create the `/dev` mount and materialise a node for every registered device,
/// enqueuing a "add" uevent for each on `/dev/uevent`. Idempotent: existing
/// `/dev` nodes are left untouched.
pub fn devfs_init() {
    // Register the kernel -> user-space uevent bridge before materialising so
    // /dev/uevent appears alongside the boot devices themselves.
    devfs_register(b"uevent", 7, 0, 0, &UEVENT_DEVICE);

    // Ensure /dev exists.
    if crate::vfs::find_inode(b"/dev").is_none() {
        let _ = crate::vfs_core::mkdir(
            b"/dev",
            crate::vfs_core::types::S_IRUSR
                | crate::vfs_core::types::S_IWUSR
                | crate::vfs_core::types::S_IXUSR
                | crate::vfs_core::types::S_IRGRP
                | crate::vfs_core::types::S_IXGRP
                | crate::vfs_core::types::S_IROTH,
        );
    }

    unsafe {
        for i in 0..MAX_DEVICES {
            if !DEVS[i].used {
                continue;
            }
            let mut path = [0u8; NAME_LEN + 6]; // "/dev/" + name
            path[..5].copy_from_slice(b"/dev/");
            path[5..5 + DEVS[i].name_len].copy_from_slice(&DEVS[i].name[..DEVS[i].name_len]);
            let plen = 5 + DEVS[i].name_len;
            let path = &path[..plen];

            if crate::vfs::find_inode(path).is_some() {
                continue;
            }

            let name_is_uevent = DEVS[i].name_len == b"uevent".len()
                && DEVS[i].name[..DEVS[i].name_len] == *b"uevent";

            let vn_id = crate::vfs_core::vnode_alloc(DEVS[i].dev_ino, 0, 0, DEVS[i].ops);
            if let Some(vn_id) = vn_id {
                let _ = crate::vfs_core::create(path, crate::vfs_core::types::S_IFCHR | 0o666);
                let _ = crate::vfs::create_file(path, b"");
                if let Some(idx) = crate::vfs::find_inode(path) {
                    crate::vfs::INODES[idx].vnode_id = vn_id;
                }
                crate::serial::write_str("devfs: created '");
                crate::serial::write_str(core::str::from_utf8(&path[1..]).unwrap_or("?"));
                crate::serial::write_str("' (major=");
                crate::serial::write_dec(DEVS[i].major);
                crate::serial::write_str(",minor=");
                crate::serial::write_dec(DEVS[i].minor);
                crate::serial::write_str(")\n");

                // Notify the user-space udev daemon about every boot device
                // (the /dev/uevent bridge itself gets no event).
                if !name_is_uevent {
                    uevent_emit(
                        b"add",
                        &DEVS[i].name[..DEVS[i].name_len],
                        b"rynex",
                        DEVS[i].major,
                        DEVS[i].minor,
                    );
                }
            }
        }
    }
}
