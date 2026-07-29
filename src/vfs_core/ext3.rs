use crate::serial;
use crate::memory::allocator;
use super::types::*;

pub const EXT3_SUPER_MAGIC: u16 = 0xEF53;
pub const EXT3_ROOT_INO: u32 = 2;
pub const EXT3_BLOCK_SIZE: u64 = 4096;
pub const EXT3_INODE_SIZE: u64 = 128;
pub const EXT3_INODES_PER_BLOCK: u64 = EXT3_BLOCK_SIZE / EXT3_INODE_SIZE;
pub const EXT3_SB_OFFSET: u64 = 1024;
pub const EXT3_FEATURE_INCOMPAT_FILE_TYPE: u32 = 0x0002;
pub const EXT3_FEATURE_INCOMPAT_EXTENTS: u32 = 0x0040;
pub const EXT3_FEATURE_INCOMPAT_FLEX_BG: u32 = 0x0200;
pub const EXT3_FEATURE_RO_COMPAT_SPARSE_SUPER: u32 = 0x0001;
pub const EXT3_FEATURE_RO_COMPAT_LARGE_FILE: u32 = 0x0002;

pub const EXT3_FT_UNKNOWN: u8 = 0;
pub const EXT3_FT_REG_FILE: u8 = 1;
pub const EXT3_FT_DIR: u8 = 2;
pub const EXT3_FT_CHRDEV: u8 = 3;
pub const EXT3_FT_BLKDEV: u8 = 4;
pub const EXT3_FT_FIFO: u8 = 5;
pub const EXT3_FT_SOCK: u8 = 6;
pub const EXT3_FT_SYMLINK: u8 = 7;

pub const EXT3_S_IXOTH: u16 = 0o001;
pub const EXT3_S_IWOTH: u16 = 0o002;
pub const EXT3_S_IROTH: u16 = 0o004;
pub const EXT3_S_IXGRP: u16 = 0o010;
pub const EXT3_S_IWGRP: u16 = 0o020;
pub const EXT3_S_IRGRP: u16 = 0o040;
pub const EXT3_S_IXUSR: u16 = 0o100;
pub const EXT3_S_IWUSR: u16 = 0o200;
pub const EXT3_S_IRUSR: u16 = 0o400;
pub const EXT3_S_ISVTX: u16 = 0o1000;
pub const EXT3_S_ISGID: u16 = 0o2000;
pub const EXT3_S_ISUID: u16 = 0o4000;
pub const EXT3_S_IFMT: u16 = 0xF000;
pub const EXT3_S_IFSOCK: u16 = 0xC000;
pub const EXT3_S_IFLNK: u16 = 0xA000;
pub const EXT3_S_IFREG: u16 = 0x8000;
pub const EXT3_S_IFBLK: u16 = 0x6000;
pub const EXT3_S_IFDIR: u16 = 0x4000;
pub const EXT3_S_IFCHR: u16 = 0x2000;
pub const EXT3_S_IFIFO: u16 = 0x1000;

pub const EXT3_N_BLOCKS: usize = 15;
pub const EXT3_TIND_BLOCK: usize = 14;
pub const EXT3_DIND_BLOCK: usize = 13;
pub const EXT3_IND_BLOCK: usize = 12;

pub const EXT3_XATTR_MAGIC: u32 = 0xEA020000;
pub const EXT3_XATTR_REFCOUNT_INIT: u32 = 1;

#[repr(C, packed)]
pub struct Ext3Superblock {
    pub inodes_count: u32,
    pub blocks_count_lo: u32,
    pub r_blocks_count_lo: u32,
    pub free_blocks_count_lo: u32,
    pub free_inodes_count_lo: u32,
    pub first_data_block: u32,
    pub log_block_size: u32,
    pub log_cluster_size: u32,
    pub blocks_per_group: u32,
    pub clusters_per_group: u32,
    pub inodes_per_group: u32,
    pub mount_time: u32,
    pub write_time: u32,
    pub mount_count: u16,
    pub max_mount_count: u16,
    pub magic: u16,
    pub state: u16,
    pub errors: u16,
    pub minor_rev_level: u16,
    pub lastcheck: u32,
    pub checkinterval: u32,
    pub creator_os: u32,
    pub rev_level: u32,
    pub def_resuid: u16,
    pub def_resgid: u16,
    pub first_ino: u32,
    pub inode_size: u16,
    pub block_group_nr: u16,
    pub feature_compat: u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    pub uuid: [u8; 16],
    pub volume_name: [u8; 16],
    pub last_mounted: [u8; 64],
    pub algorithm_usage_bitmap: u32,
    pub prealloc_blocks: u8,
    pub prealloc_dir_blocks: u8,
    pub reserved_gdt_blocks: u16,
    pub journal_uuid: [u8; 16],
    pub journal_inum: u32,
    pub journal_dev: u32,
    pub last_orphan: u32,
    pub hash_seed: [u32; 4],
    pub def_hash_version: u8,
    pub jnl_backup_type: u8,
    pub desc_size: u16,
    pub default_mount_opts: u32,
    pub first_meta_bg: u32,
    pub mkfs_time: u32,
    pub jnl_blocks: [u32; 17],
    pub blocks_count_hi: u32,
    pub r_blocks_count_hi: u32,
    pub free_blocks_count_hi: u32,
    pub min_extra_isize: u16,
    pub want_extra_isize: u16,
    pub flags: u32,
    pub raid_stride: u16,
    pub mmp_interval: u16,
    pub mmp_block: u64,
    pub raid_stripe_width: u32,
    pub log_groups_per_flex: u8,
    pub checksum_type: u8,
    pub encryption_level: u8,
    pub reserved_padding: u8,
    pub kbytes_written: u64,
    pub snapshot_inum: u32,
    pub snapshot_id: u32,
    pub snapshot_r_blocks: u64,
    pub snapshot_list: u32,
    pub error_count: u32,
    pub first_error_time: u32,
    pub first_error_ino: u32,
    pub first_error_block: u64,
    pub first_error_func: [u8; 32],
    pub first_error_line: u32,
    pub last_error_time: u32,
    pub last_error_ino: u32,
    pub last_error_line: u32,
    pub last_error_block: u64,
    pub last_error_func: [u8; 32],
    pub mount_opts: [u8; 64],
    pub usr_quota_inum: u32,
    pub grp_quota_inum: u32,
    pub overhead_blocks: u32,
    pub backup_bgs: [u32; 2],
    pub encrypt_algos: [u8; 4],
    pub encrypt_pw_salt: [u8; 16],
    pub lpf_ino: u32,
    pub prj_quota_inum: u32,
    pub checksum_seed: u32,
    pub reserved: [u8; 98],
}

#[repr(C, packed)]
pub struct Ext3GroupDesc {
    pub block_bitmap_lo: u32,
    pub inode_bitmap_lo: u32,
    pub inode_table_lo: u32,
    pub free_blocks_count_lo: u16,
    pub free_inodes_count_lo: u16,
    pub used_dirs_count_lo: u16,
    pub flags: u16,
    pub exclude_bitmap_lo: u32,
    pub block_bitmap_csum_lo: u16,
    pub inode_bitmap_csum_lo: u16,
    pub itable_unused_lo: u16,
    pub checksum: u16,
    pub block_bitmap_hi: u32,
    pub inode_bitmap_hi: u32,
    pub inode_table_hi: u32,
    pub free_blocks_count_hi: u16,
    pub free_inodes_count_hi: u16,
    pub used_dirs_count_hi: u16,
    pub itable_unused_hi: u16,
    pub exclude_bitmap_hi: u32,
    pub block_bitmap_csum_hi: u16,
    pub inode_bitmap_csum_hi: u16,
    pub reserved: u32,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Ext3Inode {
    pub mode: u16,
    pub uid: u16,
    pub size_lo: u32,
    pub atime: u32,
    pub ctime: u32,
    pub mtime: u32,
    pub dtime: u32,
    pub gid: u16,
    pub links_count: u16,
    pub blocks_lo: u32,
    pub flags: u32,
    pub osd1: u32,
    pub block: [u32; EXT3_N_BLOCKS],
    pub generation: u32,
    pub file_acl_lo: u32,
    pub size_hi: u32,
    pub obso_faddr: u32,
    pub osd2: [u32; 3],
    pub extra_isize: u16,
    pub checksum_hi: u16,
    pub ctime_extra: u32,
    pub mtime_extra: u32,
    pub atime_extra: u32,
    pub crtime: u32,
    pub crtime_extra: u32,
    pub version_hi: u32,
    pub projid: u32,
}

#[repr(C, packed)]
pub struct Ext3DirEntry {
    pub inode: u32,
    pub rec_len: u16,
    pub name_len: u16,
    pub file_type: u8,
}

#[repr(C)]
pub struct Ext3DirEntry2 {
    pub inode: u32,
    pub rec_len: u16,
    pub name_len: u8,
    pub file_type: u8,
}

#[repr(C, packed)]
pub struct Ext3XattrHeader {
    pub magic: u32,
    pub refcount: u32,
    pub blocks: u32,
    pub hash: u32,
    pub checksum: u32,
    pub reserved: [u32; 3],
}

#[repr(C, packed)]
pub struct Ext3XattrEntry {
    pub name_len: u8,
    pub name_index: u8,
    pub value_off: u16,
    pub value_block: u32,
    pub value_size: u32,
    pub hash: u32,
}

pub struct Ext3Fs {
    pub sb: *mut Ext3Superblock,
    pub block_size: u64,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub inode_size: u16,
    pub group_count: u32,
    pub block_size_bits: u32,
    pub block_bitmap: *mut u8,
    pub inode_bitmap: *mut u8,
    pub inode_table: *mut u8,
    pub groups: *mut Ext3GroupDesc,
    pub group_count_alloc: u32,
    pub device_block: fn(u64) -> Option<*mut u8>,
    pub device_write: fn(u64, &[u8]) -> bool,
}

impl Ext3Fs {
    pub fn new() -> Self {
        Ext3Fs {
            sb: core::ptr::null_mut(),
            block_size: EXT3_BLOCK_SIZE,
            blocks_per_group: 0,
            inodes_per_group: 0,
            inode_size: 0,
            group_count: 0,
            block_size_bits: 0,
            block_bitmap: core::ptr::null_mut(),
            inode_bitmap: core::ptr::null_mut(),
            inode_table: core::ptr::null_mut(),
            groups: core::ptr::null_mut(),
            group_count_alloc: 0,
            device_block: |_| None,
            device_write: |_, _| false,
        }
    }

    pub fn mount(&mut self, read_block: fn(u64) -> Option<*mut u8>, write_block: fn(u64, &[u8]) -> bool) -> Result<(), &'static str> {
        self.device_block = read_block;
        self.device_write = write_block;

        let sb_block = (read_block)(0).ok_or("can't read superblock")? as *const Ext3Superblock;
        self.sb = sb_block as *mut Ext3Superblock;

        unsafe {
            let sb = &*self.sb;
            if sb.magic != EXT3_SUPER_MAGIC {
                return Err("bad ext3 magic");
            }

            self.block_size = 1024 << sb.log_block_size;
            self.blocks_per_group = sb.blocks_per_group;
            self.inodes_per_group = sb.inodes_per_group;
            self.inode_size = sb.inode_size;
            self.block_size_bits = (sb.log_block_size + 10) as u32;

            let total_blocks = (sb.blocks_count_lo as u64) | ((sb.blocks_count_hi as u64) << 32);
            self.group_count = ((total_blocks + self.blocks_per_group as u64 - 1) / self.blocks_per_group as u64) as u32;

            serial::write_str("EXT3: blocks=");
            serial::write_dec(total_blocks);
            serial::write_str(" groups=");
            serial::write_dec(self.group_count as u64);
            serial::write_str(" bsize=");
            serial::write_dec(self.block_size);
            serial::write_str("\n");

            let gd_block = if self.block_size == 1024 { 2 } else { 1 };
            let gd_per_block = self.block_size / core::mem::size_of::<Ext3GroupDesc>() as u64;
            let gd_blocks = ((self.group_count as u64) + gd_per_block - 1) / gd_per_block;

            let gd_alloc_blocks = gd_blocks * self.block_size;
            self.groups = (read_block)(gd_block).ok_or("can't read group desc")? as *mut Ext3GroupDesc;
            self.group_count_alloc = self.group_count;

            serial::write_str("EXT3: mounted OK\n");
        }
        Ok(())
    }

    pub fn group_for_block(&self, block: u64) -> u32 {
        (block / self.blocks_per_group as u64) as u32
    }

    pub fn group_for_inode(&self, inode: u32) -> u32 {
        ((inode - 1) / self.inodes_per_group) as u32
    }

    pub fn inode_index_in_group(&self, inode: u32) -> u32 {
        (inode - 1) % self.inodes_per_group
    }

    pub fn block_group_start(&self, group: u32) -> u64 {
        group as u64 * self.blocks_per_group as u64
    }

    pub fn read_block(&self, block: u64) -> Option<*mut u8> {
        let block_size = self.block_size;
        let dev_block = block * block_size / EXT3_BLOCK_SIZE;
        (self.device_block)(dev_block)
    }

    pub fn write_block(&self, block: u64, data: &[u8]) -> bool {
        let block_size = self.block_size;
        let dev_block = block * block_size / EXT3_BLOCK_SIZE;
        (self.device_write)(dev_block, data)
    }

    pub fn read_inode(&self, inode: u32) -> Result<Ext3Inode, &'static str> {
        let group = self.group_for_inode(inode);
        let index = self.inode_index_in_group(inode);
        let gd = self.get_group(group);
        if gd.is_null() {
            return Err("bad group");
        }
        let inode_table = unsafe { (*gd).inode_table_lo as u64 };
        let inode_byte = index as u64 * self.inode_size as u64;
        let inode_block = inode_table + inode_byte / self.block_size;
        let inode_offset = (inode_byte % self.block_size) as usize;

        let block = self.read_block(inode_block).ok_or("can't read inode block")?;
        unsafe {
            let ptr = block.add(inode_offset) as *const Ext3Inode;
            Ok(core::ptr::read(ptr))
        }
    }

    pub fn write_inode(&self, inode: u32, ino: &Ext3Inode) -> Result<(), &'static str> {
        let group = self.group_for_inode(inode);
        let index = self.inode_index_in_group(inode);
        let gd = self.get_group(group);
        if gd.is_null() {
            return Err("bad group");
        }
        let inode_table = unsafe { (*gd).inode_table_lo as u64 };
        let inode_byte = index as u64 * self.inode_size as u64;
        let inode_block = inode_table + inode_byte / self.block_size;
        let inode_offset = (inode_byte % self.block_size) as usize;

        let block = self.read_block(inode_block).ok_or("can't read inode block")?;
        unsafe {
            let ptr = block.add(inode_offset) as *mut Ext3Inode;
            core::ptr::write(ptr, *ino);
        }
        Ok(())
    }

    pub fn get_group(&self, group: u32) -> *mut Ext3GroupDesc {
        if group >= self.group_count_alloc {
            return core::ptr::null_mut();
        }
        unsafe { self.groups.add(group as usize) }
    }

    pub fn block_to_abs(&self, block: u32) -> u64 {
        let group = self.group_for_block(block as u64);
        let group_start = self.block_group_start(group);
        let index_in_group = block as u64 - group_start;
        let abs_block = self.block_group_start(group) + index_in_group;
        abs_block
    }

    pub fn alloc_block(&self) -> Result<u64, &'static str> {
        unsafe {
            let alloc = &mut *allocator();
            for g in 0..self.group_count as u64 {
                let gd = self.get_group(g as u32);
                if gd.is_null() { continue; }
                let free = (*gd).free_blocks_count_lo;
                if free == 0 { continue; }

                let bitmap_block = (*gd).block_bitmap_lo as u64;
                let bm = self.read_block(bitmap_block).ok_or("can't read bitmap")?;
                let bm_bytes = self.block_size as usize;

                for byte_off in 0..bm_bytes {
                    let byte = *bm.add(byte_off);
                    if byte != 0xFF {
                        for bit in 0..8 {
                            if byte & (1 << bit) == 0 {
                                let block_in_group = (byte_off * 8 + bit) as u64;
                                if block_in_group >= self.blocks_per_group as u64 {
                                    continue;
                                }
                                let abs_block = self.block_group_start(g as u32) + block_in_group;
                                *bm.add(byte_off) |= 1 << bit;
                                self.write_block(bitmap_block, unsafe {
                                    core::slice::from_raw_parts(bm, bm_bytes)
                                });
                                (*gd).free_blocks_count_lo -= 1;
                                return Ok(abs_block);
                            }
                        }
                    }
                }
            }
        }
        Err("no free blocks")
    }
}

pub fn mode_to_ext3(mode: FileMode) -> u16 {
    let mut m = 0u16;
    if mode & S_IXOTH != 0 { m |= EXT3_S_IXOTH; }
    if mode & S_IWOTH != 0 { m |= EXT3_S_IWOTH; }
    if mode & S_IROTH != 0 { m |= EXT3_S_IROTH; }
    if mode & S_IXGRP != 0 { m |= EXT3_S_IXGRP; }
    if mode & S_IWGRP != 0 { m |= EXT3_S_IWGRP; }
    if mode & S_IRGRP != 0 { m |= EXT3_S_IRGRP; }
    if mode & S_IXUSR != 0 { m |= EXT3_S_IXUSR; }
    if mode & S_IWUSR != 0 { m |= EXT3_S_IWUSR; }
    if mode & S_IRUSR != 0 { m |= EXT3_S_IRUSR; }
    if mode & S_ISVTX != 0 { m |= EXT3_S_ISVTX; }
    if mode & S_ISGID != 0 { m |= EXT3_S_ISGID; }
    if mode & S_ISUID != 0 { m |= EXT3_S_ISUID; }

    let ft = mode & S_IFMT;
    if ft == S_IFSOCK { m |= EXT3_S_IFSOCK; }
    else if ft == S_IFLNK { m |= EXT3_S_IFLNK; }
    else if ft == S_IFREG { m |= EXT3_S_IFREG; }
    else if ft == S_IFBLK { m |= EXT3_S_IFBLK; }
    else if ft == S_IFDIR { m |= EXT3_S_IFDIR; }
    else if ft == S_IFCHR { m |= EXT3_S_IFCHR; }
    else if ft == S_IFIFO { m |= EXT3_S_IFIFO; }

    m
}

pub fn ext3_to_mode(ext3_mode: u16) -> FileMode {
    let mut m = 0;
    if ext3_mode & EXT3_S_IXOTH != 0 { m |= S_IXOTH; }
    if ext3_mode & EXT3_S_IWOTH != 0 { m |= S_IWOTH; }
    if ext3_mode & EXT3_S_IROTH != 0 { m |= S_IROTH; }
    if ext3_mode & EXT3_S_IXGRP != 0 { m |= S_IXGRP; }
    if ext3_mode & EXT3_S_IWGRP != 0 { m |= S_IWGRP; }
    if ext3_mode & EXT3_S_IRGRP != 0 { m |= S_IRGRP; }
    if ext3_mode & EXT3_S_IXUSR != 0 { m |= S_IXUSR; }
    if ext3_mode & EXT3_S_IWUSR != 0 { m |= S_IWUSR; }
    if ext3_mode & EXT3_S_IRUSR != 0 { m |= S_IRUSR; }
    if ext3_mode & EXT3_S_ISVTX != 0 { m |= S_ISVTX; }
    if ext3_mode & EXT3_S_ISGID != 0 { m |= S_ISGID; }
    if ext3_mode & EXT3_S_ISUID != 0 { m |= S_ISUID; }

    let ft = ext3_mode & EXT3_S_IFMT;
    m |= match ft {
        EXT3_S_IFSOCK => S_IFSOCK,
        EXT3_S_IFLNK => S_IFLNK,
        EXT3_S_IFREG => S_IFREG,
        EXT3_S_IFBLK => S_IFBLK,
        EXT3_S_IFDIR => S_IFDIR,
        EXT3_S_IFCHR => S_IFCHR,
        EXT3_S_IFIFO => S_IFIFO,
        _ => S_IFREG,
    };

    m
}

pub fn stat_from_ext3(ino: &Ext3Inode, ino_num: u32) -> Stat {
    let mut st = Stat::empty();
    st.ino = ino_num as u64;
    st.mode = ext3_to_mode(ino.mode);
    st.nlink = ino.links_count as u32;
    st.uid = ino.uid as u32;
    st.gid = ino.gid as u32;
    st.size = (ino.size_lo as u64) | ((ino.size_hi as u64) << 32);
    st.blocks = ino.blocks_lo as u64;
    st.blksize = 512;
    st.atime = ino.atime as u64;
    st.mtime = ino.mtime as u64;
    st.ctime = ino.ctime as u64;
    st
}
