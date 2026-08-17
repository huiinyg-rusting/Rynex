// User-space filesystem bridge (P1-C).
//
// The kernel keeps only the mount table, fd table and path resolution. All
// vnode operations for a userfs mount are forwarded over IPC to a registered
// user-space FS service port. This is the microkernel seam: the real data
// lives in a user-space process, not in the kernel.
//
// Message layout (request, big-endian-free little-endian u64 fields):
//   [0..8)    op
//   [8..16)   ino
//   [16..24)  offset
//   [24..32)  len / mode
//   [32..40)  flags
//   [40..)    name / payload (u8s)
//
// Reply layout:
//   [0..8)    result (>=0 ok, <0 errno as i64)
//   [8..)     payload (u8s)
//
// Ops are a small integer protocol understood by both the kernel bridge and
// the user-space FS service.

pub const OP_READ: u64 = 1;
pub const OP_WRITE: u64 = 2;
pub const OP_LOOKUP: u64 = 3;
pub const OP_READDIR: u64 = 4;
pub const OP_CREATE: u64 = 5;
pub const OP_MKDIR: u64 = 6;
pub const OP_REMOVE: u64 = 7;
pub const OP_RMDIR: u64 = 8;
pub const OP_STAT: u64 = 9;
pub const OP_READLINK: u64 = 10;
pub const OP_SYMLINK: u64 = 11;
pub const OP_RENAME: u64 = 12;
pub const OP_SETATTR: u64 = 13;
pub const OP_TRUNCATE: u64 = 14;

const MAX_REQ: usize = 4096 - 32;

/// Registered user-space FS service port (0 = none).
static SERVICE_PORT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The bridge implements VnodeOps by forwarding to the user-space service.
pub struct UserFs;

/// Set the port id of the user-space FS service. Must be called before any
/// userfs mount is used.
pub fn set_service_port(port_id: u64) {
    SERVICE_PORT.store(port_id, core::sync::atomic::Ordering::SeqCst);
}

fn service_port() -> Option<u64> {
    let p = SERVICE_PORT.load(core::sync::atomic::Ordering::SeqCst);
    if p == 0 { None } else { Some(p) }
}

fn do_call(op: u64, ino: u64, offset: u64, len: u64, flags: u64, name: &[u8], payload: &[u8]) -> Result<(i64, [u8; MAX_REQ]), i64> {
    let port = service_port().ok_or(-crate::task::ENODEV)?;
    let mut req = [0u8; MAX_REQ];
    if name.len() + payload.len() + 40 > MAX_REQ {
        return Err(-crate::task::EINVAL);
    }
    req[0..8].copy_from_slice(&op.to_le_bytes());
    req[8..16].copy_from_slice(&ino.to_le_bytes());
    req[16..24].copy_from_slice(&offset.to_le_bytes());
    req[24..32].copy_from_slice(&len.to_le_bytes());
    req[32..40].copy_from_slice(&flags.to_le_bytes());
    let mut pos = 40;
    req[pos..pos + name.len()].copy_from_slice(name);
    pos += name.len();
    req[pos..pos + payload.len()].copy_from_slice(payload);
    let req_len = pos + payload.len();

    let mut out = [0u8; MAX_REQ];
    let n = crate::ipc::ipc_call_internal(port, req.as_ptr(), req_len, out.as_mut_ptr(), out.len());
    if n < 0 {
        return Err(n);
    }
    if n < 8 {
        return Err(-crate::task::EINVAL);
    }
    let result = i64::from_le_bytes(out[0..8].try_into().unwrap());
    Ok((result, out))
}

impl super::VnodeOps for UserFs {
    fn read(&self, ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize, &'static str> {
        let (result, out) = do_call(OP_READ, ino, offset, buf.len() as u64, 0, b"", b"").map_err(|_| "userfs read")?;
        if result < 0 {
            return Err("userfs read");
        }
        let n = result as usize;
        if n > buf.len() { return Err("userfs read"); }
        buf[..n].copy_from_slice(&out[8..8 + n]);
        Ok(n)
    }

    fn write(&self, ino: u64, offset: u64, buf: &[u8]) -> Result<usize, &'static str> {
        let (result, _) = do_call(OP_WRITE, ino, offset, buf.len() as u64, 0, b"", buf).map_err(|_| "userfs write")?;
        if result < 0 {
            return Err("userfs write");
        }
        Ok(result as usize)
    }

    fn lookup(&self, parent_ino: u64, name: &[u8]) -> Result<u64, &'static str> {
        let (result, _) = do_call(OP_LOOKUP, parent_ino, 0, 0, 0, name, b"").map_err(|_| "userfs lookup")?;
        if result < 0 {
            return Err("userfs lookup");
        }
        Ok(result as u64)
    }

    fn readdir(&self, dir_ino: u64, offset: u64, _buf: &mut [super::Dirent]) -> Result<usize, &'static str> {
        // Directory listing is returned as NUL-separated names in the payload;
        // the user-space service owns the format.
        let (result, out) = do_call(OP_READDIR, dir_ino, offset, 0, 0, b"", b"").map_err(|_| "userfs readdir")?;
        if result < 0 {
            return Err("userfs readdir");
        }
        Ok(result as usize)
    }

    fn create(&self, parent_ino: u64, name: &[u8], mode: super::FileMode) -> Result<u64, &'static str> {
        let (result, _) = do_call(OP_CREATE, parent_ino, 0, mode as u64, 0, name, b"").map_err(|_| "userfs create")?;
        if result < 0 {
            return Err("userfs create");
        }
        Ok(result as u64)
    }

    fn mkdir(&self, parent_ino: u64, name: &[u8], mode: super::FileMode) -> Result<u64, &'static str> {
        let (result, _) = do_call(OP_MKDIR, parent_ino, 0, mode as u64, 0, name, b"").map_err(|_| "userfs mkdir")?;
        if result < 0 {
            return Err("userfs mkdir");
        }
        Ok(result as u64)
    }

    fn remove(&self, parent_ino: u64, name: &[u8]) -> Result<(), &'static str> {
        let (result, _) = do_call(OP_REMOVE, parent_ino, 0, 0, 0, name, b"").map_err(|_| "userfs remove")?;
        if result < 0 {
            return Err("userfs remove");
        }
        Ok(())
    }

    fn rmdir(&self, parent_ino: u64, name: &[u8]) -> Result<(), &'static str> {
        let (result, _) = do_call(OP_RMDIR, parent_ino, 0, 0, 0, name, b"").map_err(|_| "userfs rmdir")?;
        if result < 0 {
            return Err("userfs rmdir");
        }
        Ok(())
    }

    fn stat(&self, ino: u64) -> Result<super::Stat, &'static str> {
        let (result, out) = do_call(OP_STAT, ino, 0, 0, 0, b"", b"").map_err(|_| "userfs stat")?;
        if result < 0 {
            return Err("userfs stat");
        }
        let mut st = super::Stat::empty();
        // Minimal: ino + size only for now. Extend as user-space stat grows.
        st.ino = ino;
        st.size = result as u64;
        Ok(st)
    }

    fn readlink(&self, ino: u64) -> Result<&[u8], &'static str> {
        let (result, out) = do_call(OP_READLINK, ino, 0, 0, 0, b"", b"").map_err(|_| "userfs readlink")?;
        if result < 0 {
            return Err("userfs readlink");
        }
        let n = result as usize;
        // Leak a small copy so the returned slice stays alive.
        let boxed = alloc::boxed::Box::from(&out[8..8 + n]);
        Ok(alloc::boxed::Box::leak(boxed))
    }

    fn symlink(&self, parent_ino: u64, name: &[u8], target: &[u8]) -> Result<u64, &'static str> {
        let (result, _) = do_call(OP_SYMLINK, parent_ino, 0, 0, 0, name, target).map_err(|_| "userfs symlink")?;
        if result < 0 {
            return Err("userfs symlink");
        }
        Ok(result as u64)
    }

    fn rename(&self, old_parent: u64, old_name: &[u8], new_parent: u64, new_name: &[u8]) -> Result<(), &'static str> {
        let mut payload = [0u8; MAX_REQ - 48];
        let mut pos = 0;
        payload[pos..pos + old_name.len()].copy_from_slice(old_name);
        pos += old_name.len();
        payload[pos] = 0;
        pos += 1;
        payload[pos..pos + new_name.len()].copy_from_slice(new_name);
        pos += new_name.len();
        let (result, _) = do_call(OP_RENAME, old_parent, new_parent, 0, 0, &payload[..pos], b"").map_err(|_| "userfs rename")?;
        if result < 0 {
            return Err("userfs rename");
        }
        Ok(())
    }

    fn setattr(&self, ino: u64, _attr: &super::Attr) -> Result<(), &'static str> {
        let (result, _) = do_call(OP_SETATTR, ino, 0, 0, 0, b"", b"").map_err(|_| "userfs setattr")?;
        if result < 0 {
            return Err("userfs setattr");
        }
        Ok(())
    }

    fn truncate(&self, ino: u64, size: u64) -> Result<(), &'static str> {
        let (result, _) = do_call(OP_TRUNCATE, ino, size, 0, 0, b"", b"").map_err(|_| "userfs truncate")?;
        if result < 0 {
            return Err("userfs truncate");
        }
        Ok(())
    }

    fn getxattr(&self, _ino: u64, _name: &[u8], _value: &mut [u8]) -> Result<usize, &'static str> {
        Err("userfs getxattr")
    }

    fn setxattr(&self, _ino: u64, _name: &[u8], _value: &[u8]) -> Result<(), &'static str> {
        Err("userfs setxattr")
    }

    fn listxattr(&self, _ino: u64, _buf: &mut [u8]) -> Result<usize, &'static str> {
        Err("userfs listxattr")
    }

    fn ioctl(&self, _ino: u64, _request: u64, _arg: u64) -> Result<usize, &'static str> {
        Err("userfs ioctl")
    }
}
