use crate::serial;
use crate::vfs_core::ramfs;
use crate::vfs_core::VnodeOps;
use core::sync::atomic::{AtomicU64, Ordering, AtomicBool};

pub const MAX_INODES: usize = 256;
pub const MAX_FDS_PER_TASK: usize = 16;

static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy)]
pub struct Inode {
    pub name: [u8; 32],
    pub data_ptr: *mut u8,
    pub size: usize,
    pub used: bool,
    pub vnode_id: u16,
}

impl Inode {
    pub const fn empty() -> Self {
        Inode {
            name: [0; 32],
            data_ptr: core::ptr::null_mut(),
            size: 0,
            used: false,
            vnode_id: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub struct FileDesc {
    pub inode_idx: usize,
    pub pos: usize,
    pub used: bool,
    pub flags: i32,
}

impl FileDesc {
    pub const fn empty() -> Self {
        FileDesc {
            inode_idx: 0,
            pos: 0,
            used: false,
            flags: 0,
        }
    }
}

pub static mut INODES: [Inode; MAX_INODES] = [Inode::empty(); MAX_INODES];
static mut FD_TABLES: [[FileDesc; MAX_FDS_PER_TASK]; super::task::MAX_TASKS] =
    [[FileDesc::empty(); MAX_FDS_PER_TASK]; super::task::MAX_TASKS];

static NEXT_FLAT_INODE: AtomicU64 = AtomicU64::new(1);

fn alloc_flat_inode(name: &[u8], size: usize) -> Option<usize> {
    unsafe {
        for i in 0..MAX_INODES {
            if !INODES[i].used {
                INODES[i] = Inode::empty();
                INODES[i].used = true;
                let name_len = core::cmp::min(name.len(), 31);
                for j in 0..name_len {
                    INODES[i].name[j] = name[j];
                }
                INODES[i].name[name_len] = 0;
                INODES[i].size = size;
                INODES[i].data_ptr = core::ptr::null_mut();
                return Some(i);
            }
        }
        None
    }
}

pub fn init() {
    if DEBUG_ENABLED.load(Ordering::Relaxed) {
    serial::write_str("VFS: compatibility layer init\n");
}
}

/// Canonicalize `input` against the current task's working directory into `out`.
/// Handles absolute and relative paths, `.` and `..` segments, and duplicate
/// slashes. Returns the length of the canonical absolute path, or None on
/// overflow.
pub fn normalize_path(input: &[u8], out: &mut [u8]) -> Option<usize> {
    if input.is_empty() {
        return Some(0);
    }
    let cwd = crate::task::get_cwd_bytes();
    let cap = out.len();
    let mut len = 0usize;
    let absolute = input[0] == b'/';
    if !absolute {
        for &c in cwd {
            if len >= cap { return None; }
            out[len] = c;
            len += 1;
        }
        if len == 0 || out[len - 1] != b'/' {
            if len >= cap { return None; }
            out[len] = b'/';
            len += 1;
        }
    } else {
        if len >= cap { return None; }
        out[len] = b'/';
        len += 1;
    }
    let rest = if absolute { &input[1..] } else { input };
    for &c in rest {
        if len >= cap { return None; }
        out[len] = c;
        len += 1;
    }

    let src = out.as_ptr();
    let mut seg_start = [0usize; 64];
    let mut seg_end = [0usize; 64];
    let mut nseg = 0usize;
    let mut i = 0usize;
    while i < len {
        if unsafe { *src.add(i) } == b'/' {
            i += 1;
            continue;
        }
        let start = i;
        while i < len && unsafe { *src.add(i) } != b'/' {
            i += 1;
        }
        let sl = i - start;
        if sl == 1 && unsafe { *src.add(start) } == b'.' {
            continue;
        }
        if sl == 2 && unsafe { *src.add(start) } == b'.' && unsafe { *src.add(start + 1) } == b'.' {
            if nseg > 0 {
                nseg -= 1;
            }
            continue;
        }
        if nseg >= 64 {
            return None;
        }
        seg_start[nseg] = start;
        seg_end[nseg] = i;
        nseg += 1;
    }

    let dst = out.as_mut_ptr();
    let mut o = 0usize;
    if nseg == 0 {
        if o >= cap { return None; }
        unsafe { *dst.add(o) = b'/'; }
        o += 1;
        return Some(o);
    }
    for k in 0..nseg {
        if o >= cap { return None; }
        unsafe { *dst.add(o) = b'/'; }
        o += 1;
        let sl = seg_end[k] - seg_start[k];
        if o + sl > cap { return None; }
        unsafe {
            core::ptr::copy_nonoverlapping(src.add(seg_start[k]), dst.add(o), sl);
        }
        o += sl;
    }
    Some(o)
}

pub fn resolve_or_register(name: &[u8]) -> Option<usize> {
    let mut buf = [0u8; 512];
    let norm_len = normalize_path(name, &mut buf).unwrap_or(0);
    let norm = if norm_len > 0 { &buf[..norm_len] } else { name };
    find_inode(norm).or_else(|| {
        // Dynamic procfs PID files: /proc/<pid>/stat, /proc/<pid>/cmdline.
        if let Some(idx) = maybe_bind_proc_pid(norm) {
            return Some(idx);
        }
        let flat_idx = alloc_flat_inode(norm, 0)?;
        // If this inode already has a vnode_id (e.g., char device), use it
        let vn_id = unsafe {
            if INODES[flat_idx].vnode_id != 0 {
                INODES[flat_idx].vnode_id
            } else {
                let mode = crate::vfs_core::types::S_IFREG
                    | crate::vfs_core::types::S_IRUSR
                    | crate::vfs_core::types::S_IWUSR
                    | crate::vfs_core::types::S_IRGRP
                    | crate::vfs_core::types::S_IROTH;
                let ino = crate::vfs_core::resolve_ino(norm).ok()?;
                crate::vfs_core::vnode_alloc(ino, 0, 0, &ramfs::RAMFS)?
            }
        };
        unsafe { INODES[flat_idx].vnode_id = vn_id; }
        Some(flat_idx)
    })
}

/// Create a symlink `path -> target` in the real VFS and register a flat
/// inode bound to it so execve/stat/getdents can find it by name.
pub fn create_symlink(path: &[u8], target: &[u8]) -> Option<usize> {
    crate::vfs_core::symlink(path, target).ok()?;
    resolve_or_register(path)
}

pub fn create_file(name: &[u8], data: &[u8]) -> Option<usize> {
    let flat_idx = alloc_flat_inode(name, data.len())?;

    let mode = crate::vfs_core::types::S_IFREG
        | crate::vfs_core::types::S_IRUSR
        | crate::vfs_core::types::S_IWUSR
        | crate::vfs_core::types::S_IXUSR
        | crate::vfs_core::types::S_IRGRP
        | crate::vfs_core::types::S_IXGRP
        | crate::vfs_core::types::S_IROTH
        | crate::vfs_core::types::S_IXOTH;

    match crate::vfs_core::create(name, mode) {
        Ok(ino) => {
            match crate::vfs_core::vnode_alloc(ino, 0, 0, &ramfs::RAMFS) {
                Some(vn_id) => {
                    unsafe { INODES[flat_idx].vnode_id = vn_id; }
                    if !data.is_empty() {
                        match crate::vfs_core::write(vn_id, 0, data) {
                            Ok(n) if n == data.len() => {}
                            _ => {
if DEBUG_ENABLED.load(Ordering::Relaxed) {
                            serial::write_str("VFS: write failed for '");
                            for &c in name { serial::write_char(c as char); }
                            serial::write_str("'\n");
                        }
                                unsafe { INODES[flat_idx].used = false; }
                                return None;
                            }
                        }
                    }
                    if DEBUG_ENABLED.load(Ordering::Relaxed) {
                        serial::write_str("VFS: created '");
                        for &c in name { serial::write_char(c as char); }
                        serial::write_str("' (");
                        serial::write_dec(data.len() as u64);
                        serial::write_str(" bytes)\n");
                    }
                    Some(flat_idx)
                }
                None => {
                    unsafe { INODES[flat_idx].used = false; }
                    None
                }
            }
        }
        Err(_) => {
            unsafe { INODES[flat_idx].used = false; }
            None
        }
    }
}

pub fn create_external_file(name: &[u8], data: *mut u8, size: usize) -> Option<usize> {
    let flat_idx = alloc_flat_inode(name, size)?;
    unsafe { INODES[flat_idx].data_ptr = data; }

    let data_slice = unsafe { core::slice::from_raw_parts(data, size) };
    let mode = crate::vfs_core::types::S_IFREG
        | crate::vfs_core::types::S_IRUSR
        | crate::vfs_core::types::S_IWUSR
        | crate::vfs_core::types::S_IRGRP
        | crate::vfs_core::types::S_IROTH;

    match crate::vfs_core::create(name, mode) {
        Ok(ino) => {
            match crate::vfs_core::vnode_alloc(ino, 0, 0, &ramfs::RAMFS) {
                Some(vn_id) => {
                    unsafe { INODES[flat_idx].vnode_id = vn_id; }
                    if !data_slice.is_empty() {
                        let _ = crate::vfs_core::write(vn_id, 0, data_slice);
                    }
                    if DEBUG_ENABLED.load(Ordering::Relaxed) {
                    serial::write_str("VFS: created external '");
                    for &c in name { serial::write_char(c as char); }
                    serial::write_str("'\n");
                }
                    Some(flat_idx)
                }
                None => {
                    unsafe { INODES[flat_idx].used = false; }
                    None
                }
            }
        }
        Err(_) => {
            unsafe { INODES[flat_idx].used = false; }
            None
        }
    }
}

pub fn find_inode(name: &[u8]) -> Option<usize> {
    let mut buf = [0u8; 512];
    let norm_len = normalize_path(name, &mut buf).unwrap_or(0);
    let norm = if norm_len > 0 { &buf[..norm_len] } else { name };
    unsafe {
        for i in 0..MAX_INODES {
            if !INODES[i].used { continue; }
            let mut matches = true;
            let mut j = 0;
            while j < norm.len() && j < 31 {
                if INODES[i].name[j] != norm[j] { matches = false; break; }
                j += 1;
            }
            if matches && (j == norm.len() || norm.len() == 0) && (j >= INODES[i].name.len() || INODES[i].name[j] == 0) {
                return Some(i);
            }
        }
    }
    None
}

pub fn inode_vnode_id(idx: usize) -> Option<u16> {
    unsafe {
        if idx >= MAX_INODES || !INODES[idx].used {
            return None;
        }
        Some(INODES[idx].vnode_id)
    }
}

pub fn inode_size(idx: usize) -> Option<usize> {
    unsafe {
        if idx >= MAX_INODES || !INODES[idx].used {
            return None;
        }
        Some(INODES[idx].size)
    }
}

pub fn inode_read(idx: usize, pos: usize, buf: &mut [u8]) -> Option<usize> {
    unsafe {
        if idx >= MAX_INODES || !INODES[idx].used {
            return None;
        }
        let inode = &INODES[idx];
        if inode.data_ptr.is_null() && inode.vnode_id == 0 {
            return None;
        }
        if inode.data_ptr.is_null() {
            match crate::vfs_core::read(inode.vnode_id, pos as u64, buf) {
                Ok(n) => return Some(n),
                Err(_) => return None,
            }
        }
        if pos >= inode.size {
            return Some(0);
        }
        let to_read = core::cmp::min(buf.len(), inode.size - pos);
        core::ptr::copy_nonoverlapping(inode.data_ptr.add(pos), buf.as_mut_ptr(), to_read);
        Some(to_read)
    }
}

pub fn inode_write(idx: usize, pos: usize, buf: &[u8]) -> Option<usize> {
    unsafe {
        if idx >= MAX_INODES || !INODES[idx].used {
            return None;
        }
        let inode = &INODES[idx];
        if inode.vnode_id != 0 {
            match crate::vfs_core::write(inode.vnode_id, pos as u64, buf) {
                Ok(n) => {
                    if pos + n > inode.size {
                        INODES[idx].size = pos + n;
                    }
                    return Some(n);
                }
                Err(_) => return None,
            }
        }
        if inode.data_ptr.is_null() {
            return None;
        }
        if pos > inode.size {
            return None;
        }
        let to_write = core::cmp::min(buf.len(), inode.size - pos);
        core::ptr::copy_nonoverlapping(buf.as_ptr(), inode.data_ptr.add(pos), to_write);
        Some(to_write)
    }
}

pub fn get_fd_table() -> Option<&'static mut [FileDesc; MAX_FDS_PER_TASK]> {
    let id = super::task::current_task_id();
    if id == 0 { return None; }
    let idx = (id % super::task::MAX_TASKS as u64) as usize;
    unsafe { Some(&mut FD_TABLES[idx]) }
}

pub fn fd_table_for(task_id: u64) -> &'static mut [FileDesc; MAX_FDS_PER_TASK] {
    let idx = (task_id % super::task::MAX_TASKS as u64) as usize;
    unsafe { &mut FD_TABLES[idx] }
}

pub fn alloc_fd(inode_idx: usize, flags: i32) -> Option<usize> {
    let table = get_fd_table()?;
    for i in 0..MAX_FDS_PER_TASK {
        if !table[i].used {
            table[i] = FileDesc {
                inode_idx,
                pos: 0,
                used: true,
                flags,
            };
            return Some(i);
        }
    }
    None
}

pub fn fd_to_inode(fd: usize) -> Option<&'static mut FileDesc> {
    let table = get_fd_table()?;
    if fd >= MAX_FDS_PER_TASK || !table[fd].used {
        return None;
    }
    Some(&mut table[fd])
}

pub fn close_fd(fd: usize) -> bool {
    let table = match get_fd_table() {
        Some(t) => t,
        None => return false,
    };
    if fd >= MAX_FDS_PER_TASK || !table[fd].used {
        return false;
    }
    table[fd].used = false;
    true
}

pub fn alloc_fd_for_task(task_id: u64, inode_idx: usize, flags: i32) -> Option<usize> {
    let idx = (task_id % super::task::MAX_TASKS as u64) as usize;
    unsafe {
        let table = &mut FD_TABLES[idx];
        for i in 0..MAX_FDS_PER_TASK {
            if !table[i].used {
                table[i] = FileDesc {
                    inode_idx,
                    pos: 0,
                    used: true,
                    flags,
                };
                return Some(i);
            }
        }
    }
    None
}

/// Register a flat inode for `name` bound to an existing vnode_id without
/// going through vfs_core::create (which read-only filesystems reject). The
/// resulting inode has data_ptr == null and vnode_id set, so inode_read
/// delegates into vfs_core::read -> the bound VnodeOps.
pub fn bind_vnode_inode(name: &[u8], vnode_id: u16) -> Option<usize> {
    let flat_idx = alloc_flat_inode(name, 0)?;
    unsafe {
        INODES[flat_idx].vnode_id = vnode_id;
    }
    Some(flat_idx)
}

/// If `name` is a dynamic /proc/<pid>/stat|cmdline path, bind it to a procfs
/// vnode so the pid files work even when the process was spawned after boot.
/// Returns the flat inode idx when handled, None otherwise.
fn maybe_bind_proc_pid(name: &[u8]) -> Option<usize> {
    let prefix = b"/proc/";
    if !name.starts_with(prefix) { return None; }
    let rest = &name[prefix.len()..];
    let slash = rest.iter().position(|&c| c == b'/');
    let (pid_str, file) = match slash {
        Some(s) => rest.split_at(s),
        None => (rest, &[][..]),
    };
    let file = if slash.is_some() { &file[1..] } else { file };
    if pid_str.is_empty() || !pid_str.iter().all(|&c| c >= b'0' && c <= b'9') {
        return None;
    }
    let mut pid = 0u64;
    for &c in pid_str { pid = pid * 10 + (c - b'0') as u64; }
    let ino = if file.is_empty() {
        crate::vfs_core::procfs::pid_dir_ino(pid)
    } else {
        match file {
            b"stat" => crate::vfs_core::procfs::pid_stat_ino(pid),
            b"cmdline" => crate::vfs_core::procfs::pid_cmdline_ino(pid),
            _ => return None,
        }
    };
    let ops: &'static dyn crate::vfs_core::VnodeOps = &crate::vfs_core::procfs::PROCFS;
    let fs_id = crate::vfs_core::types::alloc_fsid();
    let vn_id = crate::vfs_core::vnode_alloc(ino, fs_id, 0, ops)?;
    bind_vnode_inode(name, vn_id)
}

/// Force the vnode_id of an existing flat inode (by normalized path).
pub fn rebind_inode_vnode(name: &[u8], vnode_id: u16) -> Option<usize> {
    let idx = find_inode(name)?;
    unsafe { INODES[idx].vnode_id = vnode_id; }
    Some(idx)
}
