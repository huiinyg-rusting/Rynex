use crate::serial;

const DATA_POOL_SIZE: usize = 4 * 1024 * 1024; // 4 MiB
static mut DATA_POOL: [u8; DATA_POOL_SIZE] = [0; DATA_POOL_SIZE];
static mut POOL_OFFSET: usize = 0;

fn pool_alloc(size: usize) -> Option<*mut u8> {
    unsafe {
        let aligned = (POOL_OFFSET + 15) & !15;
        if aligned + size > DATA_POOL_SIZE {
            return None;
        }
        POOL_OFFSET = aligned + size;
        Some(DATA_POOL.as_mut_ptr().add(aligned))
    }
}

#[derive(Clone, Copy)]
pub struct Inode {
    pub name: [u8; 32],
    pub data_ptr: *mut u8,
    pub size: usize,
    pub used: bool,
}

impl Inode {
    pub const fn empty() -> Self {
        Inode {
            name: [0; 32],
            data_ptr: core::ptr::null_mut(),
            size: 0,
            used: false,
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

pub const MAX_INODES: usize = 32;
pub const MAX_FDS_PER_TASK: usize = 16;

pub static mut INODES: [Inode; MAX_INODES] = [Inode::empty(); MAX_INODES];

pub fn init() {
    serial::write_str("VFS: init\n");
}

pub fn create_file(name: &[u8], data: &[u8]) -> Option<usize> {
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

                let data_ptr = pool_alloc(data.len())?;
                core::ptr::copy_nonoverlapping(data.as_ptr(), data_ptr, data.len());
                INODES[i].data_ptr = data_ptr;
                INODES[i].size = data.len();

                serial::write_str("VFS: created file '");
                let mut j = 0;
                while j < 31 && INODES[i].name[j] != 0 {
                    serial::write_char(INODES[i].name[j] as char);
                    j += 1;
                }
                serial::write_str("' (");
                serial::write_dec(data.len() as u64);
                serial::write_str(" bytes)\n");
                return Some(i);
            }
        }
        None
    }
}

pub fn create_external_file(name: &[u8], data: *mut u8, size: usize) -> Option<usize> {
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

                INODES[i].data_ptr = data;
                INODES[i].size = size;

                serial::write_str("VFS: created external file '");
                let mut j = 0;
                while j < 31 && INODES[i].name[j] != 0 {
                    serial::write_char(INODES[i].name[j] as char);
                    j += 1;
                }
                serial::write_str("' (");
                serial::write_dec(size as u64);
                serial::write_str(" bytes)\n");
                return Some(i);
            }
        }
        None
    }
}

pub fn find_inode(name: &[u8]) -> Option<usize> {
    unsafe {
        for i in 0..MAX_INODES {
            if !INODES[i].used { continue; }
            let iname = core::str::from_utf8(&INODES[i].name).unwrap_or("");
            let iname_bytes = iname.as_bytes();
            let l = core::cmp::min(name.len(), iname_bytes.len());
            if &name[..l] == &iname_bytes[..l] {
                let remaining = &iname_bytes[l..];
                if remaining.iter().all(|&c| c == 0) {
                    return Some(i);
                }
            }
        }
        None
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
        if pos >= inode.size || inode.data_ptr.is_null() {
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
        let inode = &mut INODES[idx];
        if pos > inode.size || inode.data_ptr.is_null() {
            return None;
        }
        let to_write = core::cmp::min(buf.len(), inode.size - pos);
        core::ptr::copy_nonoverlapping(buf.as_ptr(), inode.data_ptr.add(pos), to_write);
        Some(to_write)
    }
}

static mut FD_TABLES: [[FileDesc; MAX_FDS_PER_TASK]; super::task::MAX_TASKS] =
    [[FileDesc::empty(); MAX_FDS_PER_TASK]; super::task::MAX_TASKS];

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
