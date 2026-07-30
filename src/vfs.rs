use crate::serial;
use crate::vfs_core::ramfs;
use crate::vfs_core::VnodeOps;
use core::sync::atomic::{AtomicU64, Ordering};

pub const MAX_INODES: usize = 256;
pub const MAX_FDS_PER_TASK: usize = 16;

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
    serial::write_str("VFS: compatibility layer init\n");
}

pub fn resolve_or_register(name: &[u8]) -> Option<usize> {
    find_inode(name).or_else(|| {
        let mode = crate::vfs_core::types::S_IFREG
            | crate::vfs_core::types::S_IRUSR
            | crate::vfs_core::types::S_IWUSR
            | crate::vfs_core::types::S_IRGRP
            | crate::vfs_core::types::S_IROTH;
        let ino = crate::vfs_core::resolve_ino(name).ok()?;
        let vn_id = crate::vfs_core::vnode_alloc(ino, 0, 0, &ramfs::RAMFS)?;
        let flat_idx = alloc_flat_inode(name, 0)?;
        unsafe { INODES[flat_idx].vnode_id = vn_id; }
        Some(flat_idx)
    })
}

pub fn create_file(name: &[u8], data: &[u8]) -> Option<usize> {
    let flat_idx = alloc_flat_inode(name, data.len())?;

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
                    if !data.is_empty() {
                        match crate::vfs_core::write(vn_id, 0, data) {
                            Ok(n) if n == data.len() => {}
                            _ => {
                                serial::write_str("VFS: write failed for '");
                                for &c in name { serial::write_char(c as char); }
                                serial::write_str("'\n");
                                unsafe { INODES[flat_idx].used = false; }
                                return None;
                            }
                        }
                    }
                    serial::write_str("VFS: created '");
                    for &c in name { serial::write_char(c as char); }
                    serial::write_str("' (");
                    serial::write_dec(data.len() as u64);
                    serial::write_str(" bytes)\n");
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
                    serial::write_str("VFS: created external '");
                    for &c in name { serial::write_char(c as char); }
                    serial::write_str("'\n");
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
    unsafe {
        for i in 0..MAX_INODES {
            if !INODES[i].used { continue; }
            let mut matches = true;
            let mut j = 0;
            while j < name.len() && j < 31 {
                if INODES[i].name[j] != name[j] { matches = false; break; }
                j += 1;
            }
            if matches && (j == name.len() || name.len() == 0) && (j >= INODES[i].name.len() || INODES[i].name[j] == 0) {
                return Some(i);
            }
        }
    }
    None
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
