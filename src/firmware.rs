//! Firmware blob registry.
//!
//! Firmware images are shipped inside the boot ISO as (non-ELF) multiboot2
//! modules. `task::boot_userland` copies each non-ELF module into this table,
//! keyed by its GRUB cmdline basename (e.g. `test.bin`). Userspace programs
//! fetch a blob by name through the `rynex_request_firmware` syscall.
//!
//! Layout: modules that do NOT begin with the ELF magic are treated as firmware
//! blobs, so the existing /bin module indices (0..n ELF binaries) are never
//! disturbed — firmware simply rides along as extra trailing modules. The
//! backing memory is a permanent GRUB module, so entries store raw pointer +
//! length instead of copying.

use crate::task::{EFAULT, EINVAL, ENOENT, ENOMEM};

pub const MAX_FIRMWARE: usize = 16;
pub const NAME_LEN: usize = 64;

#[derive(Copy, Clone)]
struct Entry {
    name: [u8; NAME_LEN],
    name_len: usize,
    base: usize,
    len: usize,
}

static mut FIRMWARE: [Entry; MAX_FIRMWARE] = [Entry {
    name: [0; NAME_LEN],
    name_len: 0,
    base: 0,
    len: 0,
}; MAX_FIRMWARE];
static mut FIRMWARE_COUNT: usize = 0;

/// Register a firmware blob under `name` (exact, NUL-free). The backing memory
/// must outlive the kernel (a GRUB module does). Returns 0 on success.
pub fn register(name: &[u8], data: &[u8]) -> i64 {
    if name.is_empty() || name.len() > NAME_LEN || data.is_empty() {
        return -EINVAL;
    }
    unsafe {
        for i in 0..FIRMWARE_COUNT {
            let e = &FIRMWARE[i];
            if e.name_len == name.len() && &e.name[..name.len()] == name {
                return 0; // already registered
            }
        }
        if FIRMWARE_COUNT >= MAX_FIRMWARE {
            return -ENOMEM;
        }
        let e = &mut FIRMWARE[FIRMWARE_COUNT];
        for (j, &c) in name.iter().enumerate() {
            e.name[j] = c;
        }
        e.name_len = name.len();
        e.base = data.as_ptr() as usize;
        e.len = data.len();
        FIRMWARE_COUNT += 1;
    }
    crate::serial::write_str("FW: registered '");
    crate::serial::write_str(&alloc::format!("{}", core::str::from_utf8(name).unwrap_or("?")));
    crate::serial::write_str("' len=");
    crate::serial::write_dec(data.len() as u64);
    crate::serial::write_str("\n");
    0
}

/// Look up a registered blob by exact name.
fn lookup(name: &[u8]) -> Option<&'static [u8]> {
    unsafe {
        for i in 0..FIRMWARE_COUNT {
            let e = &FIRMWARE[i];
            if e.name_len == name.len() && &e.name[..name.len()] == name {
                let slice: &'static [u8] =
                    core::slice::from_raw_parts(e.base as *const u8, e.len);
                return Some(slice);
            }
        }
    }
    None
}

/// syscall `rynex_request_firmware(name_ptr, name_len, out_ptr, out_cap)`.
///
/// On success returns 0 and writes the blob length (u64, little-endian) at
/// `out_ptr[0..8]`, then copies up to `out_cap - 8` blob bytes at
/// `out_ptr[8..]`. Returns `-ENOENT` if the name is unknown, `-EFAULT` on bad
/// user buffers, `-EINVAL` on invalid arguments.
pub fn sys_request_firmware(
    name_ptr: *const u8,
    name_len: usize,
    out_ptr: *mut u8,
    out_cap: usize,
) -> i64 {
    if name_ptr.is_null() || name_len == 0 || name_len > NAME_LEN {
        return -EINVAL;
    }
    if out_ptr.is_null() || out_cap < 8 {
        return -EINVAL;
    }
    if !crate::task::user_range_valid(name_ptr as u64, name_len, false) {
        return -EFAULT;
    }
    if !crate::task::user_range_valid(out_ptr as u64, out_cap, true) {
        return -EFAULT;
    }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len) };
    let blob = match lookup(name) {
        Some(b) => b,
        None => return -ENOENT,
    };
    let len_bytes = (blob.len() as u64).to_le_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(len_bytes.as_ptr(), out_ptr, 8);
        let n = core::cmp::min(blob.len(), out_cap - 8);
        if n > 0 {
            core::ptr::copy_nonoverlapping(blob.as_ptr(), out_ptr.add(8), n);
        }
    }
    0
}