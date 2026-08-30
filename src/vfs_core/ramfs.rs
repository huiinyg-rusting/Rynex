use crate::serial;
use crate::memory;
use crate::spinlock::Mutex;
use super::types::*;
use super::VnodeOps;

pub const MAX_INODES: usize = 256;
pub const MAX_DIRENTS: usize = 64;
pub const RAMFS_BLOCK: usize = 4096;
pub const MAX_BLOCKS_PER_INODE: usize = 512;
pub const MAX_SYMLINK_LEN: usize = 256;

const FT_REG_FILE: u8 = 1;
const FT_DIR: u8 = 2;
const FT_SYMLINK: u8 = 7;

#[derive(Clone, Copy)]
struct RamDirent {
    ino: u64,
    name: [u8; MAX_NAME],
    name_len: u16,
    file_type: u8,
    used: bool,
}

unsafe impl Send for RamDirent {}
unsafe impl Sync for RamDirent {}

impl RamDirent {
    const fn empty() -> Self {
        RamDirent {
            ino: 0,
            name: [0; MAX_NAME],
            name_len: 0,
            file_type: 0,
            used: false,
        }
    }

    fn set(&mut self, ino: u64, name: &[u8], ftype: u8) {
        self.ino = ino;
        self.name_len = name.len() as u16;
        self.file_type = ftype;
        let len = name.len().min(MAX_NAME);
        self.name[..len].copy_from_slice(&name[..len]);
        self.used = true;
    }
}

#[derive(Clone, Copy)]
struct RamInode {
    mode: FileMode,
    uid: Uid,
    gid: Gid,
    size: Size,
    nlink: u32,
    blocks: [*mut u8; MAX_BLOCKS_PER_INODE],
    block_count: usize,
    used: bool,
    symlink_target: [u8; MAX_SYMLINK_LEN],
    symlink_len: usize,
    xattr: super::xattr::XattrBlock,
    dirents: [RamDirent; MAX_DIRENTS],
    dirent_count: usize,
}

unsafe impl Send for RamInode {}
unsafe impl Sync for RamInode {}

impl RamInode {
    const fn empty() -> Self {
        RamInode {
            mode: 0,
            uid: 0, gid: 0, size: 0, nlink: 0,
            blocks: [core::ptr::null_mut(); MAX_BLOCKS_PER_INODE],
            block_count: 0,
            used: false,
            symlink_target: [0; MAX_SYMLINK_LEN],
            symlink_len: 0,
            xattr: super::xattr::XattrBlock::empty(),
            dirents: [RamDirent::empty(); MAX_DIRENTS],
            dirent_count: 0,
        }
    }
}

static INODES: Mutex<[RamInode; MAX_INODES]> = Mutex::new([RamInode::empty(); MAX_INODES]);

fn alloc_inode() -> Option<u64> {
    let mut inodes = INODES.lock();
    for i in 0..MAX_INODES {
        if !inodes[i].used {
            inodes[i].used = true;
            inodes[i].mode = 0;
            inodes[i].uid = ROOT_UID;
            inodes[i].gid = ROOT_GID;
            inodes[i].size = 0;
            inodes[i].nlink = 1;
            inodes[i].block_count = 0;
            inodes[i].symlink_len = 0;
            inodes[i].dirent_count = 0;
            inodes[i].xattr = super::xattr::XattrBlock::empty();
            for j in 0..MAX_BLOCKS_PER_INODE {
                inodes[i].blocks[j] = core::ptr::null_mut();
            }
            return Some(i as u64);
        }
    }
    None
}

fn free_inode_blocks(inode: &mut RamInode) {
    for i in 0..inode.block_count {
        let ptr = inode.blocks[i];
        if !ptr.is_null() {
            { memory::allocator().free(ptr as u64, 0); }
            inode.blocks[i] = core::ptr::null_mut();
        }
    }
    inode.block_count = 0;
}

fn get_ino(ino: u64) -> Option<*mut RamInode> {
    let i = ino as usize;
    if i < MAX_INODES {
        let mut inodes = INODES.lock();
        if inodes[i].used {
            unsafe { return Some(inodes.as_mut_ptr().add(i)); }
        }
    }
    None
}

fn ensure_block(inode: &mut RamInode, block_idx: usize) -> Result<*mut u8, &'static str> {
    if block_idx >= MAX_BLOCKS_PER_INODE {
        return Err("ramfs: too many blocks");
    }
    if inode.blocks[block_idx].is_null() {
        let ptr = memory::allocator().alloc(0).unwrap_or(0) as *mut u8;
        if ptr.is_null() {
            return Err("ramfs: oom");
        }
        unsafe { core::ptr::write_bytes(ptr, 0, RAMFS_BLOCK); }
        inode.blocks[block_idx] = ptr;
        if block_idx >= inode.block_count {
            inode.block_count = block_idx + 1;
        }
    }
    Ok(inode.blocks[block_idx])
}

pub struct RamFs;

impl VnodeOps for RamFs {
    fn read(&self, ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize, &'static str> {
        let inode_ptr = get_ino(ino).ok_or("bad ino")?;
        let inode = unsafe { &mut *inode_ptr };
        if offset >= inode.size {
            return Ok(0);
        }
        let to_read = (inode.size - offset).min(buf.len() as u64) as usize;
        let mut read_bytes = 0;
        let mut pos = offset;
        while read_bytes < to_read {
            let block_idx = (pos / RAMFS_BLOCK as u64) as usize;
            let block_off = (pos % RAMFS_BLOCK as u64) as usize;
            if block_idx >= inode.block_count || inode.blocks[block_idx].is_null() {
                break;
            }
            let avail = RAMFS_BLOCK - block_off;
            let chunk = (to_read - read_bytes).min(avail);
            unsafe {
                core::ptr::copy_nonoverlapping(inode.blocks[block_idx].add(block_off), buf.as_mut_ptr().add(read_bytes), chunk);
            }
            read_bytes += chunk;
            pos += chunk as u64;
        }
        Ok(read_bytes)
    }

    fn write(&self, ino: u64, offset: u64, buf: &[u8]) -> Result<usize, &'static str> {
        let inode_ptr = get_ino(ino).ok_or("bad ino")?;
        let inode = unsafe { &mut *inode_ptr };
        let end = offset + buf.len() as u64;
        if end > inode.size {
            inode.size = end;
        }
        let mut written = 0;
        let mut pos = offset;
        while written < buf.len() {
            let block_idx = (pos / RAMFS_BLOCK as u64) as usize;
            let block_off = (pos % RAMFS_BLOCK as u64) as usize;
            let ptr = ensure_block(inode, block_idx)?;
            let avail = RAMFS_BLOCK - block_off;
            let chunk = (buf.len() - written).min(avail);
            unsafe {
                core::ptr::copy_nonoverlapping(buf.as_ptr().add(written), ptr.add(block_off), chunk);
            }
            written += chunk;
            pos += chunk as u64;
        }
        Ok(written)
    }

    fn lookup(&self, parent_ino: u64, name: &[u8]) -> Result<u64, &'static str> {
        if parent_ino == 0 && name == b"/" {
            return Ok(0);
        }
        let inode_ptr = get_ino(parent_ino).ok_or("bad ino")?;
        let inode = unsafe { &mut *inode_ptr };
        for i in 0..inode.dirent_count {
            let d = &inode.dirents[i];
            if !d.used { continue; }
            if d.name_len as usize == name.len() && &d.name[..d.name_len as usize] == name {
                return Ok(d.ino);
            }
        }
        Err("ramfs: not found")
    }

    fn readdir(&self, dir_ino: u64, offset: u64, buf: &mut [Dirent]) -> Result<usize, &'static str> {
        let inode_ptr = get_ino(dir_ino).ok_or("bad ino")?;
        let inode = unsafe { &mut *inode_ptr };
        let start = offset as usize;
        let mut emitted = 0;
        let mut idx = 0;
        while idx < inode.dirent_count && emitted < buf.len() {
            let d = &inode.dirents[idx];
            if d.used && idx >= start {
                buf[emitted] = Dirent::empty();
                buf[emitted].ino = d.ino;
                buf[emitted].offset = idx as u64;
                buf[emitted].namelen = d.name_len;
                buf[emitted].type_ = d.file_type;
                let len = d.name_len as usize;
                buf[emitted].name[..len].copy_from_slice(&d.name[..len]);
                emitted += 1;
            }
            idx += 1;
        }
        Ok(emitted)
    }

    fn create(&self, parent_ino: u64, name: &[u8], mode: FileMode) -> Result<u64, &'static str> {
        let parent_ptr = get_ino(parent_ino).ok_or("bad parent")?;
        let parent = unsafe { &mut *parent_ptr };
        let ino = alloc_inode().ok_or("ramfs: no inodes")?;
        let child_ptr = get_ino(ino).ok_or("bad child")?;
        let child = unsafe { &mut *child_ptr };
        child.mode = mode | S_IFREG;

        if parent.dirent_count >= MAX_DIRENTS {
            free_inode_blocks(child);
            child.used = false;
            return Err("ramfs: dirents full");
        }
        let de = &mut parent.dirents[parent.dirent_count];
        de.set(ino, name, FT_REG_FILE);
        parent.dirent_count += 1;
        child.nlink = 1;
        Ok(ino)
    }

    fn mkdir(&self, parent_ino: u64, name: &[u8], mode: FileMode) -> Result<u64, &'static str> {
        let parent_ptr = get_ino(parent_ino).ok_or("bad parent")?;
        let parent = unsafe { &mut *parent_ptr };
        let ino = alloc_inode().ok_or("ramfs: no inodes")?;
        let child_ptr = get_ino(ino).ok_or("bad child")?;
        let child = unsafe { &mut *child_ptr };
        child.mode = mode | S_IFDIR;
        child.nlink = 1;

        if parent.dirent_count >= MAX_DIRENTS {
            child.used = false;
            return Err("ramfs: dirents full");
        }
        let de = &mut parent.dirents[parent.dirent_count];
        de.set(ino, name, FT_DIR);
        parent.dirent_count += 1;
        Ok(ino)
    }

    fn remove(&self, parent_ino: u64, name: &[u8]) -> Result<(), &'static str> {
        let parent_ptr = get_ino(parent_ino).ok_or("bad parent")?;
        let parent = unsafe { &mut *parent_ptr };
        for i in 0..parent.dirent_count {
            let d = &parent.dirents[i];
            if d.used && d.name_len as usize == name.len() && &d.name[..d.name_len as usize] == name {
                let target_ino = d.ino;
                parent.dirents[i].used = false;
                if let Some(tgt) = get_ino(target_ino) {
                    let tgt = unsafe { &mut *tgt };
                    free_inode_blocks(tgt);
                    tgt.used = false;
                }
                return Ok(());
            }
        }
        Err("ramfs: not found")
    }

    fn rmdir(&self, parent_ino: u64, name: &[u8]) -> Result<(), &'static str> {
        self.remove(parent_ino, name)
    }

    fn stat(&self, ino: u64) -> Result<Stat, &'static str> {
        let inode_ptr = get_ino(ino).ok_or("bad ino")?;
        let inode = unsafe { &mut *inode_ptr };
        Ok(Stat {
            dev: 0, ino,
            mode: inode.mode,
            nlink: inode.nlink,
            uid: inode.uid, gid: inode.gid,
            rdev: 0, size: inode.size,
            blksize: RAMFS_BLOCK as u64,
            blocks: inode.block_count as u64,
            atime: 0, mtime: 0, ctime: 0,
        })
    }

    fn readlink(&self, ino: u64) -> Result<&[u8], &'static str> {
        let inode_ptr = get_ino(ino).ok_or("bad ino")?;
        let inode = unsafe { &mut *inode_ptr };
        if inode.symlink_len == 0 {
            return Err("not a symlink");
        }
        Ok(&inode.symlink_target[..inode.symlink_len])
    }

    fn symlink(&self, parent_ino: u64, name: &[u8], target: &[u8]) -> Result<u64, &'static str> {
        let parent_ptr = get_ino(parent_ino).ok_or("bad parent")?;
        let parent = unsafe { &mut *parent_ptr };
        let ino = alloc_inode().ok_or("ramfs: no inodes")?;
        let child_ptr = get_ino(ino).ok_or("bad child")?;
        let child = unsafe { &mut *child_ptr };
        child.mode = S_IFLNK | 0o777;
        child.symlink_len = target.len().min(MAX_SYMLINK_LEN);
        child.symlink_target[..child.symlink_len].copy_from_slice(&target[..child.symlink_len]);

        if parent.dirent_count >= MAX_DIRENTS { child.used = false; return Err("ramfs: dirents full"); }
        let de = &mut parent.dirents[parent.dirent_count];
        de.set(ino, name, FT_SYMLINK);
        parent.dirent_count += 1;
        Ok(ino)
    }

    fn rename(&self, old_parent: u64, old_name: &[u8], new_parent: u64, new_name: &[u8]) -> Result<(), &'static str> {
        let old_ptr = get_ino(old_parent).ok_or("bad old parent")?;
        let old = unsafe { &mut *old_ptr };
        let mut found_idx = None;
        for i in 0..old.dirent_count {
            let d = &old.dirents[i];
            if d.used && d.name_len as usize == old_name.len() && &d.name[..d.name_len as usize] == old_name {
                found_idx = Some(i);
                break;
            }
        }
        let idx = found_idx.ok_or("ramfs: not found")?;
        let ino = old.dirents[idx].ino;
        let ftype = old.dirents[idx].file_type;
        old.dirents[idx].used = false;

        let new_ptr = get_ino(new_parent).ok_or("bad new parent")?;
        let new = unsafe { &mut *new_ptr };
        if new.dirent_count >= MAX_DIRENTS { return Err("ramfs: dirents full"); }
        let de = &mut new.dirents[new.dirent_count];
        de.set(ino, new_name, ftype);
        new.dirent_count += 1;
        Ok(())
    }

    fn setattr(&self, ino: u64, attr: &Attr) -> Result<(), &'static str> {
        let inode_ptr = get_ino(ino).ok_or("bad ino")?;
        let inode = unsafe { &mut *inode_ptr };
        inode.mode = attr.mode;
        inode.uid = attr.uid;
        inode.gid = attr.gid;
        Ok(())
    }

    fn getxattr(&self, ino: u64, name: &[u8], value: &mut [u8]) -> Result<usize, &'static str> {
        let inode_ptr = get_ino(ino).ok_or("bad ino")?;
        let inode = unsafe { &mut *inode_ptr };
        let entry = inode.xattr.get(name).ok_or("xattr not found")?;
        let len = entry.value_len as usize;
        if len > value.len() { return Err("buf too small"); }
        let data_block = inode.xattr.data_block;
        if data_block == 0 { return Err("no xattr data"); }
        unsafe {
            core::ptr::copy_nonoverlapping((data_block as *const u8).add(entry.value_off as usize), value.as_mut_ptr(), len);
        }
        Ok(len)
    }

    fn setxattr(&self, ino: u64, name: &[u8], value: &[u8]) -> Result<(), &'static str> {
        let inode_ptr = get_ino(ino).ok_or("bad ino")?;
        let inode = unsafe { &mut *inode_ptr };
        if inode.xattr.data_block == 0 {
            let ptr = memory::allocator().alloc(0).unwrap_or(0) as *mut u8;
            if ptr.is_null() { return Err("oom"); }
            unsafe { core::ptr::write_bytes(ptr, 0, super::xattr::XATTR_SIZE_MAX); }
            inode.xattr.data_block = ptr as u64;
        }
        let idx = inode.xattr.set(name, value)?;
        unsafe {
            core::ptr::copy_nonoverlapping(value.as_ptr(), (inode.xattr.data_block as *mut u8).add(inode.xattr.entries[idx].value_off as usize), value.len());
        }
        Ok(())
    }

    fn listxattr(&self, ino: u64, buf: &mut [u8]) -> Result<usize, &'static str> {
        let inode_ptr = get_ino(ino).ok_or("bad ino")?;
        let inode = unsafe { &mut *inode_ptr };
        let mut pos = 0;
        for i in 0..inode.xattr.count as usize {
            let e = &inode.xattr.entries[i];
            let n = &e.name[..e.name_len as usize];
            if pos + n.len() + 1 > buf.len() { break; }
            buf[pos..pos + n.len()].copy_from_slice(n);
            pos += n.len();
            buf[pos] = 0;
            pos += 1;
        }
        Ok(pos)
    }

    fn truncate(&self, ino: u64, size: u64) -> Result<(), &'static str> {
        let inode_ptr = get_ino(ino).ok_or("bad ino")?;
        let inode = unsafe { &mut *inode_ptr };
        let new_blocks = ((size + RAMFS_BLOCK as u64 - 1) / RAMFS_BLOCK as u64) as usize;
        for i in new_blocks..inode.block_count {
            if !inode.blocks[i].is_null() {
                { memory::allocator().free(inode.blocks[i] as u64, 0); }
                inode.blocks[i] = core::ptr::null_mut();
            }
        }
        inode.block_count = new_blocks;
        inode.size = size;
        Ok(())
    }

    fn ioctl(&self, _ino: u64, _request: u64, _arg: u64) -> Result<usize, &'static str> {
        Err("ENOTTY")
    }
}

pub static RAMFS: RamFs = RamFs;

pub fn init() {
    serial::write_str("RAMFS: initializing\n");

    let root_ino = alloc_inode().expect("RAMFS: no root inode");
    let root_ptr = get_ino(root_ino).unwrap();
    let root = unsafe { &mut *root_ptr };
    root.mode = S_IFDIR
        | S_IRUSR | S_IWUSR | S_IXUSR
        | S_IRGRP | S_IXGRP
        | S_IROTH | S_IXOTH;
    root.uid = ROOT_UID;
    root.gid = ROOT_GID;
    root.nlink = 2;

    let bin_ptr = alloc_inode().expect("RAMFS: no bin inode");
    let bin = unsafe { &mut *get_ino(bin_ptr).unwrap() };
    bin.mode = S_IFDIR
        | S_IRUSR | S_IWUSR | S_IXUSR
        | S_IRGRP | S_IXGRP
        | S_IROTH | S_IXOTH;
    bin.uid = ROOT_UID;
    bin.gid = ROOT_GID;
    bin.nlink = 2;

    root.dirents[0].set(bin_ptr, b"bin", FT_DIR);
    root.dirent_count = 1;

    let lib_ptr = alloc_inode().expect("RAMFS: no lib inode");
    let lib = unsafe { &mut *get_ino(lib_ptr).unwrap() };
    lib.mode = S_IFDIR
        | S_IRUSR | S_IWUSR | S_IXUSR
        | S_IRGRP | S_IXGRP
        | S_IROTH | S_IXOTH;
    lib.uid = ROOT_UID;
    lib.gid = ROOT_GID;
    lib.nlink = 2;

    root.dirents[1].set(lib_ptr, b"lib", FT_DIR);
    root.dirent_count = 2;

    serial::write_str("RAMFS: initialized\n");
}
