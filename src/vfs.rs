use crate::serial;

// ── Inode (file) ──────────────────────────────────────────────────

#[derive(Clone, Copy)]
pub struct Inode {
    pub name: [u8; 32],
    pub data: [u8; 8192],
    pub size: usize,
    pub used: bool,
}

impl Inode {
    pub const fn empty() -> Self {
        Inode {
            name: [0; 32],
            data: [0; 8192],
            size: 0,
            used: false,
        }
    }
}

// ── File descriptor ───────────────────────────────────────────────

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

// ── RamFS ─────────────────────────────────────────────────────────

pub static mut INODES: [Inode; MAX_INODES] = [Inode::empty(); MAX_INODES];

pub fn init() {
    serial::write_str("VFS: init\n");
}

/// Create a file in the ramfs. Returns the inode index.
pub fn create_file(name: &[u8], data: &[u8]) -> Option<usize> {
    unsafe {
        for i in 0..MAX_INODES {
            if !INODES[i].used {
                // Clear the inode
                INODES[i] = Inode::empty();
                INODES[i].used = true;

                // Copy name directly into the inode
                let name_len = core::cmp::min(name.len(), 31);
                for j in 0..name_len {
                    INODES[i].name[j] = name[j];
                }
                INODES[i].name[name_len] = 0;

                // Copy data directly into the inode
                let data_len = core::cmp::min(data.len(), 8192);
                for j in 0..data_len {
                    INODES[i].data[j] = data[j];
                }
                INODES[i].size = data_len;

                serial::write_str("VFS: created file '");
                let mut j = 0;
                while j < 31 && INODES[i].name[j] != 0 {
                    serial::write_char(INODES[i].name[j] as char);
                    j += 1;
                }
                serial::write_str("' (");
                serial::write_dec(data_len as u64);
                serial::write_str(" bytes)\n");
                return Some(i);
            }
        }
        None
    }
}

/// Find an inode by name. Returns the index or None.
pub fn find_inode(name: &[u8]) -> Option<usize> {
    unsafe {
        for i in 0..MAX_INODES {
            if !INODES[i].used { continue; }
            let iname = core::str::from_utf8(&INODES[i].name).unwrap_or("");
            let iname_bytes = iname.as_bytes();
            // Compare up to the shorter length
            let l = core::cmp::min(name.len(), iname_bytes.len());
            if &name[..l] == &iname_bytes[..l] {
                // Check that remaining bytes in iname are null (end of string)
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
        if pos >= inode.size {
            return Some(0);
        }
        let to_read = core::cmp::min(buf.len(), inode.size - pos);
        buf[..to_read].copy_from_slice(&inode.data[pos..pos + to_read]);
        Some(to_read)
    }
}

pub fn inode_write(idx: usize, pos: usize, buf: &[u8]) -> Option<usize> {
    unsafe {
        if idx >= MAX_INODES || !INODES[idx].used {
            return None;
        }
        let inode = &mut INODES[idx];
        if pos > 8192 {
            return None;
        }
        let to_write = core::cmp::min(buf.len(), 8192 - pos);
        inode.data[pos..pos + to_write].copy_from_slice(&buf[..to_write]);
        if pos + to_write > inode.size {
            inode.size = pos + to_write;
        }
        Some(to_write)
    }
}

// ── Per-task file descriptors ─────────────────────────────────────

// Per-task FD tables stored in a global array indexed by task ID
static mut FD_TABLES: [[FileDesc; MAX_FDS_PER_TASK]; super::task::MAX_TASKS] =
    [[FileDesc::empty(); MAX_FDS_PER_TASK]; super::task::MAX_TASKS];

pub fn get_fd_table() -> Option<&'static mut [FileDesc; MAX_FDS_PER_TASK]> {
    let id = super::task::current_task_id();
    if id == 0 { return None; }
    let idx = (id % super::task::MAX_TASKS as u64) as usize;
    unsafe { Some(&mut FD_TABLES[idx]) }
}

/// Allocate a new FD for the current task pointing to the given inode.
/// Returns the FD number (0-based index into the FD table).
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
