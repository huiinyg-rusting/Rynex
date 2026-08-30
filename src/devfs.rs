//! devfs: kernel device registry.
//!
//! Devices register themselves (a name, a device-specific inode number, a
//! major/minor pair and a `VnodeOps` implementation) via `devfs_register`, and
//! `devfs_init` materialises `/dev/<name>` entries for every registered device
//! at boot. This replaces the previous hardcoded, copy-pasted block in
//! `task::boot_userland`.
//!
//! This is the kernel-side *plumbing* (device registry + `/dev` population).
//! A user-space `udev` daemon may later attach over the IPC to add policy
//! (naming rules, symlinks, permissions) on top; the registry stays the single
//! source of truth so `/dev` never goes stale.

use crate::vfs_core::VnodeOps;

/// Maximum number of registered character devices.
const MAX_DEVICES: usize = 32;
/// Maximum device name length.
const NAME_LEN: usize = 32;

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

/// Create the `/dev` mount and materialise a node for every registered device.
/// Idempotent: existing `/dev` nodes are left untouched.
pub fn devfs_init() {
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
            }
        }
    }
}
