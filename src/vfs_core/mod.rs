pub mod types;
pub mod xattr;
pub mod ext3;
pub mod ramfs;

use crate::spinlock::Mutex;
use crate::serial;
use core::alloc::Layout;
use types::*;

pub const MAX_MOUNTS: usize = 16;
pub const MAX_VNODES: usize = 256;
pub const MAX_FDS_PER_TASK: usize = 16;
pub const PATH_SEPARATOR: u8 = b'/';

pub enum VfsOp {
    Read,
    Write,
    Lookup,
    ReadDir,
    Create,
    MkDir,
    Remove,
    RmDir,
    Stat,
    ReadLink,
    SymLink,
    Rename,
    SetAttr,
    GetXattr,
    SetXattr,
    ListXattr,
    Open,
    Close,
    Seek,
    Truncate,
    Ioctl,
    FSync,
}

pub struct VfsMessage {
    pub op: VfsOp,
    pub path_buf: [u8; MAX_PATH],
    pub path_len: usize,
    pub data: *mut u8,
    pub data_len: usize,
    pub offset: u64,
    pub mode: u32,
    pub flags: u32,
    pub result: i64,
    pub extra1: u64,
    pub extra2: u64,
}

impl VfsMessage {
    pub const fn new() -> Self {
        VfsMessage {
            op: VfsOp::Read,
            path_buf: [0; MAX_PATH],
            path_len: 0,
            data: core::ptr::null_mut(),
            data_len: 0,
            offset: 0,
            mode: 0,
            flags: 0,
            result: 0,
            extra1: 0,
            extra2: 0,
        }
    }
}

pub trait VnodeOps: Sync {
    fn read(&self, ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize, &'static str>;
    fn write(&self, ino: u64, offset: u64, buf: &[u8]) -> Result<usize, &'static str>;
    fn lookup(&self, parent_ino: u64, name: &[u8]) -> Result<u64, &'static str>;
    fn readdir(&self, dir_ino: u64, offset: u64, buf: &mut [Dirent]) -> Result<usize, &'static str>;
    fn create(&self, parent_ino: u64, name: &[u8], mode: FileMode) -> Result<u64, &'static str>;
    fn mkdir(&self, parent_ino: u64, name: &[u8], mode: FileMode) -> Result<u64, &'static str>;
    fn remove(&self, parent_ino: u64, name: &[u8]) -> Result<(), &'static str>;
    fn rmdir(&self, parent_ino: u64, name: &[u8]) -> Result<(), &'static str>;
    fn stat(&self, ino: u64) -> Result<Stat, &'static str>;
    fn readlink(&self, ino: u64) -> Result<&[u8], &'static str>;
    fn symlink(&self, parent_ino: u64, name: &[u8], target: &[u8]) -> Result<u64, &'static str>;
    fn rename(&self, old_parent: u64, old_name: &[u8], new_parent: u64, new_name: &[u8]) -> Result<(), &'static str>;
    fn setattr(&self, ino: u64, attr: &Attr) -> Result<(), &'static str>;
    fn getxattr(&self, ino: u64, name: &[u8], value: &mut [u8]) -> Result<usize, &'static str>;
    fn setxattr(&self, ino: u64, name: &[u8], value: &[u8]) -> Result<(), &'static str>;
    fn listxattr(&self, ino: u64, buf: &mut [u8]) -> Result<usize, &'static str>;
    fn truncate(&self, ino: u64, size: u64) -> Result<(), &'static str>;
    fn ioctl(&self, ino: u64, request: u64, arg: u64) -> Result<usize, &'static str>;
}

#[derive(Clone, Copy)]
pub struct Vnode {
    pub ino: u64,
    pub fs_id: FsId,
    pub mount_id: u64,
    pub ops: &'static dyn VnodeOps,
    pub used: bool,
}

impl Vnode {
    pub const fn empty() -> Self {
        Vnode {
            ino: 0,
            fs_id: 0,
            mount_id: 0,
            ops: &NOP_VNODE,
            used: false,
        }
    }
}

pub struct NopVnode;
impl VnodeOps for NopVnode {
    fn read(&self, _ino: u64, _offset: u64, _buf: &mut [u8]) -> Result<usize, &'static str> { Err("no fs") }
    fn write(&self, _ino: u64, _offset: u64, _buf: &[u8]) -> Result<usize, &'static str> { Err("no fs") }
    fn lookup(&self, _parent_ino: u64, _name: &[u8]) -> Result<u64, &'static str> { Err("no fs") }
    fn readdir(&self, _dir_ino: u64, _offset: u64, _buf: &mut [Dirent]) -> Result<usize, &'static str> { Err("no fs") }
    fn create(&self, _parent_ino: u64, _name: &[u8], _mode: FileMode) -> Result<u64, &'static str> { Err("no fs") }
    fn mkdir(&self, _parent_ino: u64, _name: &[u8], _mode: FileMode) -> Result<u64, &'static str> { Err("no fs") }
    fn remove(&self, _parent_ino: u64, _name: &[u8]) -> Result<(), &'static str> { Err("no fs") }
    fn rmdir(&self, _parent_ino: u64, _name: &[u8]) -> Result<(), &'static str> { Err("no fs") }
    fn stat(&self, _ino: u64) -> Result<Stat, &'static str> { Err("no fs") }
    fn readlink(&self, _ino: u64) -> Result<&[u8], &'static str> { Err("no fs") }
    fn symlink(&self, _parent_ino: u64, _name: &[u8], _target: &[u8]) -> Result<u64, &'static str> { Err("no fs") }
    fn rename(&self, _old_parent: u64, _old_name: &[u8], _new_parent: u64, _new_name: &[u8]) -> Result<(), &'static str> { Err("no fs") }
    fn setattr(&self, _ino: u64, _attr: &Attr) -> Result<(), &'static str> { Err("no fs") }
    fn getxattr(&self, _ino: u64, _name: &[u8], _value: &mut [u8]) -> Result<usize, &'static str> { Err("no fs") }
    fn setxattr(&self, _ino: u64, _name: &[u8], _value: &[u8]) -> Result<(), &'static str> { Err("no fs") }
    fn listxattr(&self, _ino: u64, _buf: &mut [u8]) -> Result<usize, &'static str> { Err("no fs") }
    fn truncate(&self, _ino: u64, _size: u64) -> Result<(), &'static str> { Err("no fs") }
    fn ioctl(&self, _ino: u64, _request: u64, _arg: u64) -> Result<usize, &'static str> { Err("ENOTTY") }
}

pub static NOP_VNODE: NopVnode = NopVnode;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileDesc {
    pub vnode_id: u16,
    pub ino: u64,
    pub offset: u64,
    pub flags: OpenFlags,
    pub used: bool,
}

impl FileDesc {
    pub const fn empty() -> Self {
        FileDesc {
            vnode_id: 0,
            ino: 0,
            offset: 0,
            flags: O_RDONLY,
            used: false,
        }
    }
}

#[repr(C)]
pub struct FdTable {
    pub fds: [FileDesc; MAX_FDS_PER_TASK],
}

impl FdTable {
    pub const fn new() -> Self {
        FdTable {
            fds: [FileDesc::empty(); MAX_FDS_PER_TASK],
        }
    }

    pub fn alloc_fd(&mut self, vnode_id: u16, ino: u64, flags: OpenFlags) -> Option<usize> {
        for i in 0..MAX_FDS_PER_TASK {
            if !self.fds[i].used {
                self.fds[i].used = true;
                self.fds[i].vnode_id = vnode_id;
                self.fds[i].ino = ino;
                self.fds[i].offset = 0;
                self.fds[i].flags = flags;
                return Some(i);
            }
        }
        None
    }

    pub fn get_fd(&mut self, fd: usize) -> Option<&mut FileDesc> {
        if fd < MAX_FDS_PER_TASK && self.fds[fd].used {
            Some(&mut self.fds[fd])
        } else {
            None
        }
    }

    pub fn close_fd(&mut self, fd: usize) -> bool {
        if fd < MAX_FDS_PER_TASK && self.fds[fd].used {
            self.fds[fd].used = false;
            true
        } else {
            false
        }
    }
}

#[derive(Clone, Copy)]
pub struct MountEntry {
    pub mount_point: [u8; MAX_PATH],
    pub mp_len: usize,
    pub fs_id: FsId,
    pub root_ino: u64,
    pub ops: &'static dyn VnodeOps,
    pub flags: u32,
    pub used: bool,
}

impl MountEntry {
    pub const fn empty() -> Self {
        MountEntry {
            mount_point: [0; MAX_PATH],
            mp_len: 0,
            fs_id: 0,
            root_ino: 0,
            ops: &NOP_VNODE,
            flags: 0,
            used: false,
        }
    }
}

static VNODE_TABLE: Mutex<VnodeTableInner> = Mutex::new(VnodeTableInner::new());
static MOUNT_TABLE: Mutex<MountTableInner> = Mutex::new(MountTableInner::new());

struct VnodeTableInner {
    vnodes: [Vnode; MAX_VNODES],
    count: usize,
}

impl VnodeTableInner {
    const fn new() -> Self {
        VnodeTableInner {
            vnodes: [Vnode::empty(); MAX_VNODES],
            count: 0,
        }
    }

    fn alloc(&mut self, ino: u64, fs_id: FsId, mount_id: u64, ops: &'static dyn VnodeOps) -> Option<u16> {
        for i in 0..MAX_VNODES {
            if !self.vnodes[i].used {
                self.vnodes[i] = Vnode {
                    ino,
                    fs_id,
                    mount_id,
                    ops,
                    used: true,
                };
                self.count += 1;
                return Some(i as u16);
            }
        }
        None
    }

    fn get(&self, id: u16) -> Option<&Vnode> {
        let i = id as usize;
        if i < MAX_VNODES && self.vnodes[i].used {
            Some(&self.vnodes[i])
        } else {
            None
        }
    }

    fn free(&mut self, id: u16) -> bool {
        let i = id as usize;
        if i < MAX_VNODES && self.vnodes[i].used {
            self.vnodes[i].used = false;
            self.count -= 1;
            true
        } else {
            false
        }
    }
}

struct MountTableInner {
    mounts: [MountEntry; MAX_MOUNTS],
    count: usize,
}

impl MountTableInner {
    const fn new() -> Self {
        MountTableInner {
            mounts: [MountEntry::empty(); MAX_MOUNTS],
            count: 0,
        }
    }

    fn alloc(&mut self, mp: &[u8], fs_id: FsId, root_ino: u64, ops: &'static dyn VnodeOps) -> Option<usize> {
        if self.count >= MAX_MOUNTS {
            return None;
        }
        for i in 0..MAX_MOUNTS {
            if !self.mounts[i].used {
                let mut entry = MountEntry::empty();
                let len = mp.len().min(MAX_PATH - 1);
                entry.mount_point[..len].copy_from_slice(&mp[..len]);
                entry.mp_len = len;
                entry.fs_id = fs_id;
                entry.root_ino = root_ino;
                entry.ops = ops;
                entry.used = true;
                self.mounts[i] = entry;
                self.count += 1;
                return Some(i);
            }
        }
        None
    }

    fn find_mount(&self, path: &[u8]) -> Option<(&MountEntry, usize)> {
        let mut best_idx = None;
        let mut best_len = 0;
        for i in 0..MAX_MOUNTS {
            if !self.mounts[i].used { continue; }
            let mp = &self.mounts[i].mount_point[..self.mounts[i].mp_len];
            if path.len() < mp.len() { continue; }
            if &path[..mp.len()] == mp {
                let after_mp = if path.len() == mp.len() {
                    0
                } else if mp.len() == 1 && mp[0] == b'/' {
                    path.len() - 1
                } else {
                    path.len() - mp.len()
                };
                if mp.len() > best_len {
                    best_len = mp.len();
                    best_idx = Some(i);
                }
            }
        }
        best_idx.map(|i| (&self.mounts[i], i))
    }

    fn unmount(&mut self, idx: usize) -> bool {
        if idx < MAX_MOUNTS && self.mounts[idx].used {
            self.mounts[idx].used = false;
            self.count -= 1;
            true
        } else {
            false
        }
    }
}

pub fn init() {
    serial::write_str("VFS: initializing IPC-style vnode layer\n");
    xattr::init();
}

pub fn mount_root() -> Result<u16, &'static str> {
    let mut mt = MOUNT_TABLE.lock();
    let mut vt = VNODE_TABLE.lock();

    let fs_id = alloc_fsid();
    let ops: &'static dyn VnodeOps = &crate::vfs_core::ramfs::RAMFS;
    let root_ino = ops.lookup(0, b"/")?;

    let mount_id = mt.alloc(b"/", fs_id, root_ino, ops).ok_or("mount table full")?;
    let vnode_id = vt.alloc(root_ino, fs_id, mount_id as u64, ops).ok_or("vnode table full")?;

    serial::write_str("VFS: root mounted (vnode_id=");
    serial::write_dec(vnode_id as u64);
    serial::write_str(")\n");
    Ok(vnode_id)
}

pub fn mount_ext3(_device_read: fn(u64) -> Option<*mut u8>, _device_write: fn(u64, &[u8]) -> bool, _mount_mp: &[u8]) -> Result<u16, &'static str> {
    Err("ext3 not yet implemented as VnodeOps")
}

pub fn path_to_vnode(path: &[u8]) -> Result<u16, &'static str> {
    let mt = MOUNT_TABLE.lock();
    let mut vt = VNODE_TABLE.lock();

    let (mnt, _) = mt.find_mount(path).ok_or("no mount for path")?;
    let rel_path = if path.len() == mnt.mp_len {
        b"."
    } else if mnt.mp_len == 1 && mnt.mp_len < path.len() {
        &path[1..]
    } else {
        &path[mnt.mp_len..]
    };

    let mut current_ino = mnt.root_ino;
    let ops = mnt.ops;

    if rel_path == b"." || rel_path.is_empty() {
        let vnode_idx = vt.alloc(current_ino, mnt.fs_id, 0, ops).ok_or("vnode table full")?;
        return Ok(vnode_idx);
    }

    let trimmed = rel_path.trim_ascii();
    let mut pos = 0;
    while pos < trimmed.len() {
        if trimmed[pos] == b'/' {
            pos += 1;
            continue;
        }
        let end = trimmed[pos..].iter().position(|&c| c == b'/')
            .map(|e| pos + e)
            .unwrap_or(trimmed.len());
        let component = &trimmed[pos..end];
        if component.is_empty() {
            pos = end + 1;
            continue;
        }
        match ops.lookup(current_ino, component) {
            Ok(next_ino) => current_ino = next_ino,
            Err(e) => return Err(e),
        }
        pos = end;
    }

    let vnode_idx = vt.alloc(current_ino, mnt.fs_id, 0, ops).ok_or("vnode table full")?;
    Ok(vnode_idx)
}

pub fn resolve_ino(path: &[u8]) -> Result<u64, &'static str> {
    path_resolve(path).map(|(ino, _)| ino)
}

pub fn path_resolve(path: &[u8]) -> Result<(u64, &'static dyn VnodeOps), &'static str> {
    let mt = MOUNT_TABLE.lock();
    let (mnt, _) = mt.find_mount(path).ok_or("no mount for path")?;

    let rel_path = if path.len() == mnt.mp_len {
        b"."
    } else if mnt.mp_len == 1 && mnt.mp_len < path.len() {
        &path[1..]
    } else {
        &path[mnt.mp_len..]
    };

    let mut current_ino = mnt.root_ino;
    let ops = mnt.ops;

    if rel_path == b"." || rel_path.is_empty() {
        return Ok((mnt.root_ino, ops));
    }

    let trimmed = rel_path.trim_ascii();
    let mut pos = 0;
    while pos < trimmed.len() {
        if trimmed[pos] == b'/' {
            pos += 1;
            continue;
        }
        let end = trimmed[pos..].iter().position(|&c| c == b'/')
            .map(|e| pos + e)
            .unwrap_or(trimmed.len());
        let component = &trimmed[pos..end];
        if component.is_empty() {
            pos = end + 1;
            continue;
        }
        match ops.lookup(current_ino, component) {
            Ok(next_ino) => current_ino = next_ino,
            Err(e) => return Err(e),
        }
        pos = end;
    }

    Ok((current_ino, ops))
}

trait AsciiTrim {
    fn trim_ascii(&self) -> &[u8];
}
impl AsciiTrim for [u8] {
    fn trim_ascii(&self) -> &[u8] {
        let s = self.iter().position(|&c| c != b' ' && c != b'\t' && c != b'\n' && c != b'\r').unwrap_or(self.len());
        let e = self.iter().rposition(|&c| c != b' ' && c != b'\t' && c != b'\n' && c != b'\r').map(|p| p + 1).unwrap_or(s);
        &self[s..e]
    }
}

pub fn parent_path(path: &[u8]) -> &[u8] {
    if path.is_empty() || path == b"/" {
        return b"/";
    }
    let trimmed = if path.last() == Some(&b'/') {
        &path[..path.len() - 1]
    } else {
        path
    };
    let last_slash = trimmed.iter().rposition(|&c| c == b'/');
    match last_slash {
        Some(0) => b"/",
        Some(pos) => &path[..pos],
        None => b"/",
    }
}

pub fn file_name(path: &[u8]) -> &[u8] {
    if path.is_empty() || path == b"/" {
        return path;
    }
    let trimmed = if path.last() == Some(&b'/') {
        &path[..path.len() - 1]
    } else {
        path
    };
    let last_slash = trimmed.iter().rposition(|&c| c == b'/');
    match last_slash {
        Some(pos) => &trimmed[pos + 1..],
        None => trimmed,
    }
}

pub fn vnode_release(id: u16) {
    VNODE_TABLE.lock().free(id);
}

pub fn vnode_get(id: u16) -> Option<&'static Vnode> {
    let vt = VNODE_TABLE.lock();
    let v = vt.get(id)?;
    let ptr: *const Vnode = v;
    unsafe { Some(&*ptr) }
}

#[allow(invalid_reference_casting)]
pub fn vnode_get_mut(id: u16) -> Option<&'static mut Vnode> {
    let mut vt = VNODE_TABLE.lock();
    let v = vt.get(id)?;
    let ptr = v as *const Vnode as *mut Vnode;
    unsafe { Some(&mut *ptr) }
}

pub fn vnode_alloc(ino: u64, fs_id: FsId, mount_id: u64, ops: &'static dyn VnodeOps) -> Option<u16> {
    VNODE_TABLE.lock().alloc(ino, fs_id, mount_id, ops)
}

pub fn dispatch(msg: &mut VfsMessage) -> i64 {
    match msg.op {
        VfsOp::Open => {
            match path_to_vnode(&msg.path_buf[..msg.path_len]) {
                Ok(vn_id) => msg.result = vn_id as i64,
                Err(e) => msg.result = -1,
            }
        }
        VfsOp::Read => {
            let vnode = match vnode_get(msg.extra1 as u16) {
                Some(v) => v,
                None => { msg.result = -1; return -1; }
            };
            let buf = unsafe { core::slice::from_raw_parts_mut(msg.data as *mut u8, msg.data_len) };
            match vnode.ops.read(vnode.ino, msg.offset, buf) {
                Ok(n) => msg.result = n as i64,
                Err(_) => msg.result = -1,
            }
        }
        VfsOp::Write => {
            let vnode = match vnode_get(msg.extra1 as u16) {
                Some(v) => v,
                None => { msg.result = -1; return -1; }
            };
            let buf = unsafe { core::slice::from_raw_parts(msg.data as *const u8, msg.data_len) };
            match vnode.ops.write(vnode.ino, msg.offset, buf) {
                Ok(n) => msg.result = n as i64,
                Err(_) => msg.result = -1,
            }
        }
        VfsOp::Stat => {
            let vnode = match vnode_get(msg.extra1 as u16) {
                Some(v) => v,
                None => { msg.result = -1; return -1; }
            };
            match vnode.ops.stat(vnode.ino) {
                Ok(st) => unsafe {
                    core::ptr::write(msg.data as *mut Stat, st);
                    msg.result = 0;
                }
                Err(_) => msg.result = -1,
            }
        }
        VfsOp::ReadDir => {
            let vnode = match vnode_get(msg.extra1 as u16) {
                Some(v) => v,
                None => { msg.result = -1; return -1; }
            };
            let buf = unsafe { core::slice::from_raw_parts_mut(msg.data as *mut Dirent, msg.data_len / core::mem::size_of::<Dirent>()) };
            match vnode.ops.readdir(vnode.ino, msg.offset, buf) {
                Ok(n) => msg.result = n as i64,
                Err(_) => msg.result = -1,
            }
        }
        VfsOp::Lookup => {
            let vnode = match vnode_get(msg.extra1 as u16) {
                Some(v) => v,
                None => { msg.result = -1; return -1; }
            };
            let name = &msg.path_buf[..msg.path_len];
            match vnode.ops.lookup(vnode.ino, name) {
                Ok(ino) => msg.result = ino as i64,
                Err(_) => msg.result = -1,
            }
        }
        VfsOp::Create => {
            let parent = parent_path(&msg.path_buf[..msg.path_len]);
            let name = file_name(&msg.path_buf[..msg.path_len]);
            let mode = msg.mode;
            match path_resolve(parent) {
                Ok((pino, ops)) => match ops.create(pino, name, mode) {
                    Ok(ino) => msg.result = ino as i64,
                    Err(_) => msg.result = -1,
                }
                Err(_) => msg.result = -1,
            }
        }
        VfsOp::MkDir => {
            let parent = parent_path(&msg.path_buf[..msg.path_len]);
            let name = file_name(&msg.path_buf[..msg.path_len]);
            let mode = msg.mode;
            match path_resolve(parent) {
                Ok((pino, ops)) => match ops.mkdir(pino, name, mode) {
                    Ok(ino) => msg.result = ino as i64,
                    Err(_) => msg.result = -1,
                }
                Err(_) => msg.result = -1,
            }
        }
        VfsOp::Remove => {
            let parent = parent_path(&msg.path_buf[..msg.path_len]);
            let name = file_name(&msg.path_buf[..msg.path_len]);
            match path_resolve(parent) {
                Ok((pino, ops)) => match ops.remove(pino, name) {
                    Ok(()) => msg.result = 0,
                    Err(_) => msg.result = -1,
                }
                Err(_) => msg.result = -1,
            }
        }
        VfsOp::RmDir => {
            let parent = parent_path(&msg.path_buf[..msg.path_len]);
            let name = file_name(&msg.path_buf[..msg.path_len]);
            match path_resolve(parent) {
                Ok((pino, ops)) => match ops.rmdir(pino, name) {
                    Ok(()) => msg.result = 0,
                    Err(_) => msg.result = -1,
                }
                Err(_) => msg.result = -1,
            }
        }
        VfsOp::ReadLink => {
            let vnode = match vnode_get(msg.extra1 as u16) {
                Some(v) => v,
                None => { msg.result = -1; return -1; }
            };
            match vnode.ops.readlink(vnode.ino) {
                Ok(target) => {
                    let len = target.len().min(msg.data_len);
                    unsafe {
                        core::ptr::copy_nonoverlapping(target.as_ptr(), msg.data as *mut u8, len);
                    }
                    msg.result = len as i64;
                }
                Err(_) => msg.result = -1,
            }
        }
        VfsOp::SymLink => {
            let parent = parent_path(&msg.path_buf[..msg.path_len]);
            let name = file_name(&msg.path_buf[..msg.path_len]);
            let target = unsafe { core::slice::from_raw_parts(msg.data as *const u8, msg.data_len) };
            match path_resolve(parent) {
                Ok((pino, ops)) => match ops.symlink(pino, name, target) {
                    Ok(_) => msg.result = 0,
                    Err(_) => msg.result = -1,
                }
                Err(_) => msg.result = -1,
            }
        }
        VfsOp::GetXattr => {
            let vnode = match vnode_get(msg.extra1 as u16) {
                Some(v) => v,
                None => { msg.result = -1; return -1; }
            };
            let name = &msg.path_buf[..msg.path_len];
            let buf = unsafe { core::slice::from_raw_parts_mut(msg.data as *mut u8, msg.data_len) };
            match vnode.ops.getxattr(vnode.ino, name, buf) {
                Ok(n) => msg.result = n as i64,
                Err(_) => msg.result = -1,
            }
        }
        VfsOp::SetXattr => {
            let vnode = match vnode_get(msg.extra1 as u16) {
                Some(v) => v,
                None => { msg.result = -1; return -1; }
            };
            let name = &msg.path_buf[..msg.path_len];
            let value = unsafe { core::slice::from_raw_parts(msg.data as *const u8, msg.data_len) };
            match vnode.ops.setxattr(vnode.ino, name, value) {
                Ok(()) => msg.result = 0,
                Err(_) => msg.result = -1,
            }
        }
        VfsOp::ListXattr => {
            let vnode = match vnode_get(msg.extra1 as u16) {
                Some(v) => v,
                None => { msg.result = -1; return -1; }
            };
            let buf = unsafe { core::slice::from_raw_parts_mut(msg.data as *mut u8, msg.data_len) };
            match vnode.ops.listxattr(vnode.ino, buf) {
                Ok(n) => msg.result = n as i64,
                Err(_) => msg.result = -1,
            }
        }
        VfsOp::Close => {
            let vnode_id = msg.extra1 as u16;
            vnode_release(vnode_id);
            msg.result = 0;
        }
        VfsOp::Seek => {
            let vnode = match vnode_get(msg.extra1 as u16) {
                Some(v) => v,
                None => { msg.result = -1; return -1; }
            };
            let st = match vnode.ops.stat(vnode.ino) {
                Ok(s) => s,
                Err(_) => { msg.result = -1; return -1; }
            };
            msg.result = msg.offset as i64;
        }
        VfsOp::Truncate => {
            let vnode = match vnode_get(msg.extra1 as u16) {
                Some(v) => v,
                None => { msg.result = -1; return -1; }
            };
            match vnode.ops.truncate(vnode.ino, msg.offset) {
                Ok(()) => msg.result = 0,
                Err(_) => msg.result = -1,
            }
        }
        VfsOp::Ioctl => {
            let vnode = match vnode_get(msg.extra1 as u16) {
                Some(v) => v,
                None => { msg.result = -1; return -1; }
            };
            match vnode.ops.ioctl(vnode.ino, msg.offset, msg.data as u64) {
                Ok(n) => msg.result = n as i64,
                Err(_) => msg.result = -1,
            }
        }
        _ => msg.result = -1,
    }
    msg.result
}

pub fn open(path: &[u8], _flags: OpenFlags) -> Result<u16, &'static str> {
    path_to_vnode(path)
}

pub fn close(vnode_id: u16) {
    vnode_release(vnode_id);
}

pub fn read(vnode_id: u16, offset: u64, buf: &mut [u8]) -> Result<usize, &'static str> {
    crate::serial::write_str("[VFS_CORE_READ] vnode_id=");
    crate::serial::write_dec(vnode_id as u64);
    crate::serial::write_str("\n");
    let vnode = vnode_get(vnode_id).ok_or("bad vnode")?;
    crate::serial::write_str("[VFS_CORE_READ] vnode ptr=");
    crate::serial::write_hex(vnode as *const _ as u64);
    crate::serial::write_str("\n");
    crate::serial::write_str("[VFS_CORE_READ] calling ops.read\n");
    vnode.ops.read(vnode.ino, offset, buf)
}

pub fn write(vnode_id: u16, offset: u64, buf: &[u8]) -> Result<usize, &'static str> {
    let vnode = vnode_get(vnode_id).ok_or("bad vnode")?;
    vnode.ops.write(vnode.ino, offset, buf)
}

pub fn readdir(vnode_id: u16, offset: u64, buf: &mut [Dirent]) -> Result<usize, &'static str> {
    let vnode = vnode_get(vnode_id).ok_or("bad vnode")?;
    vnode.ops.readdir(vnode.ino, offset, buf)
}

pub fn stat(vnode_id: u16) -> Result<Stat, &'static str> {
    let vnode = vnode_get(vnode_id).ok_or("bad vnode")?;
    vnode.ops.stat(vnode.ino)
}

pub fn create(path: &[u8], mode: FileMode) -> Result<u64, &'static str> {
    let parent = parent_path(path);
    let name = file_name(path);
    let (pino, ops) = path_resolve(parent)?;
    ops.create(pino, name, mode)
}

pub fn mkdir(path: &[u8], mode: FileMode) -> Result<u64, &'static str> {
    let parent = parent_path(path);
    let name = file_name(path);
    let (pino, ops) = path_resolve(parent)?;
    ops.mkdir(pino, name, mode)
}

pub fn remove(path: &[u8]) -> Result<(), &'static str> {
    let parent = parent_path(path);
    let name = file_name(path);
    let (pino, ops) = path_resolve(parent)?;
    ops.remove(pino, name)
}

pub fn rmdir(path: &[u8]) -> Result<(), &'static str> {
    let parent = parent_path(path);
    let name = file_name(path);
    let (pino, ops) = path_resolve(parent)?;
    ops.rmdir(pino, name)
}

pub fn rename(old_path: &[u8], new_path: &[u8]) -> Result<(), &'static str> {
    let old_parent_path = parent_path(old_path);
    let old_name = file_name(old_path);
    let new_parent_path = parent_path(new_path);
    let new_name = file_name(new_path);
    let (old_pino, ops) = path_resolve(old_parent_path)?;
    if old_parent_path == new_parent_path {
        ops.rename(old_pino, old_name, old_pino, new_name)
    } else {
        let (new_pino, _) = path_resolve(new_parent_path)?;
        ops.rename(old_pino, old_name, new_pino, new_name)
    }
}

pub fn readlink(vnode_id: u16) -> Result<&'static [u8], &'static str> {
    let vnode = vnode_get(vnode_id).ok_or("bad vnode")?;
    vnode.ops.readlink(vnode.ino)
}

pub fn getxattr(vnode_id: u16, name: &[u8], value: &mut [u8]) -> Result<usize, &'static str> {
    let vnode = vnode_get(vnode_id).ok_or("bad vnode")?;
    vnode.ops.getxattr(vnode.ino, name, value)
}

pub fn setxattr(vnode_id: u16, name: &[u8], value: &[u8]) -> Result<(), &'static str> {
    let vnode = vnode_get(vnode_id).ok_or("bad vnode")?;
    vnode.ops.setxattr(vnode.ino, name, value)
}

pub fn init_fd_table() -> &'static mut FdTable {
    unsafe {
        let ptr = alloc::alloc::alloc(Layout::new::<FdTable>()) as *mut FdTable;
        if ptr.is_null() {
            panic!("VFS: failed to allocate fd table");
        }
        ptr.write(FdTable::new());
        &mut *ptr
    }
}
