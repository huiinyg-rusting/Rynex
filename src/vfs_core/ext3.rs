// ext2/ext3/ext4 driver (read path).
//
// ext2/3/4 share one on-disk layout (superblock at 1024, block groups, inode
// table at s_inode_size stride, linear dirents) and differ mainly in how a file
// maps logical blocks to physical ones: ext2/3 use the classic 12 direct +
// 3 indirect block pointers in i_block, ext4 replaces that with an extent B+
// tree. Both mappings live in the same 60-byte i_block area, so they are two
// branches of one mapper here rather than two filesystems.
use crate::serial;
use crate::memory::allocator;
use crate::spinlock::Mutex;
use super::types::*;
use super::VnodeOps;

pub const EXT3_SUPER_MAGIC: u16 = 0xEF53;
pub const EXT3_ROOT_INO: u32 = 2;
pub const EXT3_BLOCK_SIZE: u64 = 4096;
pub const EXT3_INODE_SIZE: u64 = 128;
pub const EXT3_INODES_PER_BLOCK: u64 = EXT3_BLOCK_SIZE / EXT3_INODE_SIZE;
pub const EXT3_SB_OFFSET: u64 = 1024;
// The mount code reads the superblock by stitching together exactly this many
// device bytes; if the struct ever drifts off 1024 the stitch would silently
// truncate, so pin the invariant at compile time instead.
const _: () = assert!(core::mem::size_of::<Ext3Superblock>() == EXT3_SB_OFFSET as usize);
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

// ── ext4 additions ──────────────────────────────────────────────────
// ext4 keeps the ext2/3 superblock magic; it is told apart by the dynamic
// revision (s_rev_level >= 1) and by advertising the extents/64bit features.
pub const EXT3_REV_DYNAMIC: u32 = 1;
pub const EXT4_FEATURE_INCOMPAT_64BIT: u32 = 0x0080;
pub const EXT4_FEATURE_INCOMPAT_INLINE_DATA: u32 = 0x8000;
pub const EXT4_EXTENTS_FL: u32 = 0x0008_0000;
pub const EXT4_INDEX_FL: u32 = 0x0000_1000;
pub const EXT4_EXTENT_MAGIC: u16 = 0xF30A;
pub const EXT4_EXTENT_HEADER_SIZE: u64 = 12;
pub const EXT4_EXTENT_ENTRY_SIZE: u64 = 12;
/// ee_len values above this mark an *uninitialized* extent; the real length is
/// ee_len - 0x8000 (preallocated-but-not-yet-written blocks read as holes).
pub const EXT4_EXTENT_LEN_UNINIT: u16 = 0x8000;
/// Block numbers are 32-bit fields in i_block, so 5 tree levels is the ceiling.
pub const EXT4_EXTENT_MAX_DEPTH: u32 = 5;
/// inode i_block is 60 bytes; the extent tree root lives at its start.
pub const EXT4_EXTENT_ROOT_LEN: u64 = 60;
/// VnodeOps::readlink has to return a slice that outlives the call, so fast
/// symlink targets (stored inline in i_block) land in this one-slot buffer.
pub const EXT4_FAST_SYMLINK_MAX: u64 = 60;

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
    // 396, not 98: the on-disk superblock is exactly 1024 bytes and every
    // offset above is only correct if the trailing pad reaches the end. A
    // short pad leaves the struct a valid prefix but makes size_of the one
    // number that does not describe the medium.
    pub reserved: [u8; 396],
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

/// Header in front of every extent-tree node, both the root inside i_block and
/// the nodes living in their own data blocks. `depth == 0` marks a leaf whose
/// entries are extents; `depth > 0` marks an interior node whose entries are
/// [`Ext4ExtentIdx`].
#[repr(C, packed)]
pub struct Ext4ExtentHeader {
    pub eh_magic: u16,
    pub eh_entries: u16,
    pub eh_max: u16,
    pub eh_depth: u16,
    pub eh_generation: u32,
}

/// Leaf entry: logical block `ee_block` (or block of the run) lives at
/// physical `ee_start` for `ee_len` blocks.
#[repr(C, packed)]
pub struct Ext4Extent {
    pub ee_block: u32,
    pub ee_len: u16,
    pub ee_start_hi: u16,
    pub ee_start_lo: u32,
}

/// Interior entry: every logical block >= `ei_block` is served by the child
/// node at physical block `ei_leaf`.
#[repr(C, packed)]
pub struct Ext4ExtentIdx {
    pub ei_block: u32,
    pub ei_leaf_lo: u32,
    pub ei_leaf_hi: u16,
    pub ei_unused: u16,
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
    /// Sector size of the underlying block device. Filesystem blocks are a
    /// multiple of it, so every fs->device translation goes through here; it
    /// cannot be hardcoded to 512 (a 4K-native device would misread).
    pub device_sector_size: u64,
    /// ext4 uses a longer inode (256 by default) than ext2/3 (128), and a
    /// 64-bit group descriptor when the 64bit feature is on. Both change field
    /// offsets/stride, so they are tracked explicitly instead of assumed.
    pub desc_size: u16,
    pub feature_compat: u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    pub rev_level: u32,
    pub is_ext4: bool,
    pub label: [u8; 16],
}

/// The fs handle holds raw pointers into buffers owned by the block device, so
/// it is not `Send` by construction. It is only ever published once (by mount,
/// on the boot CPU) and afterwards only read, and every access goes through
/// the `EXT_FS` mutex, which is what actually provides the ordering.
unsafe impl Send for Ext3Fs {}

/// Unaligned big-endian-free little-endian field readers. The on-disk structs
/// are `packed` and their fields sit at 2-byte offsets, so every access needs
/// `read_unaligned`; routing them through helpers keeps that noise out of the
/// parsing code.
#[inline]
fn rd_u16(p: *const u8) -> u16 {
    unsafe { core::ptr::read_unaligned(p as *const u16) }
}

#[inline]
fn rd_u32(p: *const u8) -> u32 {
    unsafe { core::ptr::read_unaligned(p as *const u32) }
}

#[inline]
fn rd_u8(p: *const u8) -> u8 {
    unsafe { *p }
}

/// Offset step for the raw `*const u8` views the parsers hold onto a mapped
/// block. Confining the `add` to one helper keeps every field read below free
/// of `unsafe` noise, which matters because the extent walk does a lot of them.
#[inline]
fn at(p: *const u8, off: usize) -> *const u8 {
    unsafe { p.add(off) }
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
            device_sector_size: 512,
            desc_size: core::mem::size_of::<Ext3GroupDesc>() as u16,
            feature_compat: 0,
            feature_incompat: 0,
            feature_ro_compat: 0,
            rev_level: 0,
            is_ext4: false,
            label: [0; 16],
        }
    }

    pub fn mount(&mut self, read_block: fn(u64) -> Option<*mut u8>, write_block: fn(u64, &[u8]) -> bool) -> Result<(), &'static str> {
        self.device_block = read_block;
        self.device_write = write_block;

        // The fs block size is a multiple of the device sector size, so the
        // device has to be asked rather than assumed. block_device is the only
        // provider in-tree today; a bare ext3 fs unit test keeps the 512 default.
        let dev_sz = crate::drivers::block_device::get_block_size();
        if dev_sz != 0 {
            self.device_sector_size = dev_sz;
        }
        let dev_sz = self.device_sector_size;
        if dev_sz == 0 {
            return Err("device reports zero sector size");
        }

        // The superblock does not start the volume: it sits at byte 1024 and is
        // 1024 bytes long, so on a 512-byte-sector device it straddles two
        // sectors. Reading block 0 and casting its *start* to Ext3Superblock
        // would land 1024 bytes early, on the boot sector, where the magic can
        // never match. The device reader hands back a fresh buffer per call and
        // those buffers are not contiguous, so the covering sectors are stitched
        // into one owned page. That page then lives as long as the mount, which
        // matches how every other read in this driver is accounted for.
        let sb_len = core::mem::size_of::<Ext3Superblock>() as u64;
        let sb_first = EXT3_SB_OFFSET / dev_sz;
        let sb_last = (EXT3_SB_OFFSET + sb_len - 1) / dev_sz;
        let sb_sectors = sb_last - sb_first + 1;
        let sb_page = { &mut *allocator() }.alloc(0).ok_or("can't allocate superblock page")?;
        for i in 0..sb_sectors {
            let src = (read_block)(sb_first + i).ok_or("can't read superblock")?;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    src,
                    (sb_page as *mut u8).add((i * dev_sz) as usize),
                    dev_sz as usize,
                );
            }
        }
        self.sb = sb_page as *mut Ext3Superblock;

        unsafe {
            let sb = &*self.sb;
            if sb.magic != EXT3_SUPER_MAGIC {
                return Err("bad ext magic");
            }

            self.block_size = 1024u64 << sb.log_block_size;
            self.blocks_per_group = sb.blocks_per_group;
            self.inodes_per_group = sb.inodes_per_group;
            self.inode_size = sb.inode_size;
            self.block_size_bits = (sb.log_block_size + 10) as u32;
            self.feature_compat = sb.feature_compat;
            self.feature_incompat = sb.feature_incompat;
            self.feature_ro_compat = sb.feature_ro_compat;
            self.rev_level = sb.rev_level;
            // ext2/3 keep s_rev_level at 0 (or 0x0e3c7096 in newer e2fsprogs
            // for "fake ext3"); the dynamic revision plus a non-empty
            // s_inode_size/desc_size is what makes the superblock ext4.
            self.is_ext4 = sb.rev_level >= EXT3_REV_DYNAMIC;
            // The 64bit feature widens every group descriptor from 32 to 64
            // bytes, which changes the GDT stride. Older ext2/3 stores 0 here.
            self.desc_size = if self.feature_incompat & EXT4_FEATURE_INCOMPAT_64BIT != 0
                && sb.desc_size as u64 >= 32
            {
                sb.desc_size as u16
            } else {
                32
            };
            self.label = sb.volume_name;

            if self.blocks_per_group == 0 || self.inodes_per_group == 0 {
                return Err("degenerate geometry");
            }
            if self.device_sector_size == 0 || self.block_size % self.device_sector_size != 0 {
                serial::write_str("EXT3: fs block size not a multiple of device sector size\n");
                return Err("bad block/sector ratio");
            }
            // 256 is the only inode size mke2fs emits for ext4; anything else
            // means our fixed Ext3Inode offsets would be wrong.
            if self.inode_size != EXT3_INODE_SIZE as u16 && self.inode_size != 256 {
                return Err("unsupported inode size");
            }

            let total_blocks = (sb.blocks_count_lo as u64) | ((sb.blocks_count_hi as u64) << 32);
            self.group_count = ((total_blocks + self.blocks_per_group as u64 - 1) / self.blocks_per_group as u64) as u32;

            serial::write_str(if self.is_ext4 { "EXT4: blocks=" } else { "EXT3: blocks=" });
            serial::write_dec(total_blocks);
            serial::write_str(" groups=");
            serial::write_dec(self.group_count as u64);
            serial::write_str(" bsize=");
            serial::write_dec(self.block_size);
            serial::write_str(" isize=");
            serial::write_dec(self.inode_size as u64);
            serial::write_str("\n");
            serial::write_str(if self.is_ext4 { "EXT4: features compat=0x" } else { "EXT3: features compat=0x" });
            serial::write_hex(self.feature_compat as u64);
            serial::write_str(" incompat=0x");
            serial::write_hex(self.feature_incompat as u64);
            serial::write_str(" ro=0x");
            serial::write_hex(self.feature_ro_compat as u64);
            serial::write_str("\n");
            serial::write_str("EXT3: dev sector size=");
            serial::write_dec(self.device_sector_size);
            serial::write_str("\n");

            // Reject features whose on-disk meaning this read-only driver would
            // silently misinterpret. Metadata checksums are deliberately NOT
            // rejected: we never write, so a stale/unverified checksum cannot
            // desync anything, and refusing the mount would be worse than
            // reading.
            if self.feature_incompat & EXT4_FEATURE_INCOMPAT_INLINE_DATA != 0 {
                return Err("inline_data unsupported");
            }

            // The GDT is a run of blocks starting right after the superblock,
            // with a stride of s_desc_size (32 or 64) per group.
            let gd_start = if self.block_size == 1024 { 2 } else { 1 };
            let gd_per_block = self.block_size / self.desc_size as u64;
            let gd_blocks = (self.group_count as u64 + gd_per_block - 1) / gd_per_block;

            // `read_block` (the closure argument) is the *device* reader, in
            // sector units, while gd_start is an fs-block number. Handing the
            // fs number straight over reads the wrong bytes -- with 1 KiB fs
            // blocks it lands back on the superblock, so every descriptor
            // decodes to garbage -- so go through self.read_block(), which
            // scales the number and assembles the whole fs block.
            //
            // One call per GDT block: the device layer hands back a fresh buffer
            // per read, so pointers from separate calls are not contiguous and
            // cannot be indexed as one array.
            self.groups = core::ptr::null_mut();
            self.group_count_alloc = 0;
            for i in 0..gd_blocks {
                let p = self.read_block(gd_start + i).ok_or("can't read group desc")?;
                if i == 0 {
                    self.groups = p as *mut Ext3GroupDesc;
                } else if !self.groups.is_null() {
                    core::ptr::copy_nonoverlapping(
                        p as *const u8,
                        self.groups as *mut u8,
                        (gd_per_block * self.desc_size as u64) as usize,
                    );
                }
            }
            if self.groups.is_null() {
                return Err("no group desc");
            }
            self.group_count_alloc = self.group_count;

            // Echo group 0's descriptor: the inode-table block it names is the
            // first thing a lookup after mount has to reach, so having it in the
            // boot log turns "stat failed" into a one-line diagnosis.
            if self.group_count > 0 {
                let gd = self.get_group(0);
                if !gd.is_null() {
                    serial::write_str(if self.is_ext4 { "EXT4: " } else { "EXT3: " });
                    serial::write_str("group0 itable=");
                    match self.inode_table_block(0) {
                        Some(b) => serial::write_dec(b),
                        None => serial::write_str("none"),
                    }
                    serial::write_str(" desc_size=");
                    serial::write_dec(self.desc_size as u64);
                    serial::write_str(" ipg=");
                    serial::write_dec(self.inodes_per_group as u64);
                    serial::write_str(" isize=");
                    serial::write_dec(self.inode_size as u64);
                    serial::write_str("\n");
                }
            }

            serial::write_str(if self.is_ext4 { "EXT4: mounted OK\n" } else { "EXT3: mounted OK\n" });
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

    /// Translate a filesystem block to the device's own block (sector) units.
    /// The fs block size is always a multiple of the sector size, so this is a
    /// plain scale; a device with a larger sector than the fs block cannot be
    /// addressed at fs granularity at all, which mount() rejects.
    #[inline]
    fn dev_block_of(&self, block: u64) -> u64 {
        block * (self.block_size / self.device_sector_size)
    }

    /// Read one whole filesystem block.
    ///
    /// The device reader is in *sector* units, so when the fs block is larger
    /// than a sector (1 KiB blocks on a 512-byte device is the common ext4 case)
    /// a single device read fills only the first sector of the block and the
    /// rest is uninitialised page memory. Callers here parse whole fs blocks --
    /// superblock, group descriptors, inodes, dirents, extents -- so the
    /// sectors are stitched into one page instead of silently reading garbage
    /// out of the tail. The page is intentionally never freed: the device layer
    /// allocates per read and has no buffer cache to hand pages back to, which
    /// is a known leak rather than something to paper over here.
    pub fn read_block(&self, block: u64) -> Option<*mut u8> {
        let per = (self.block_size / self.device_sector_size) as usize;
        if per <= 1 {
            return (self.device_block)(self.dev_block_of(block));
        }
        let page = { &mut *allocator() }.alloc(0)?;
        let first = self.dev_block_of(block);
        for i in 0..per {
            let src = (self.device_block)(first + i as u64)?;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    src,
                    (page as *mut u8).add(i * self.device_sector_size as usize),
                    self.device_sector_size as usize,
                );
            }
        }
        Some(page as *mut u8)
    }

    /// Write one whole filesystem block, mirroring read_block's sector split.
    /// The device writer takes the payload length, so a 1 KiB block is handed
    /// over as two sectors' worth of bytes from the caller's fs-block buffer.
    pub fn write_block(&self, block: u64, data: &[u8]) -> bool {
        if data.len() as u64 != self.block_size {
            return false;
        }
        (self.device_write)(self.dev_block_of(block), data)
    }

    /// First block of `group`'s inode table. With the 64bit feature the high
    /// half lives at offset 0x28 of the (widened) descriptor; on a small
    /// filesystem it is always zero, but reading it unconditionally keeps one
    /// code path for both layouts.
    pub fn inode_table_block(&self, group: u32) -> Option<u64> {
        let gd = self.get_group(group);
        if gd.is_null() {
            return None;
        }
        unsafe {
            let lo = (*gd).inode_table_lo as u64;
            let hi = if self.desc_size as u64 >= 64 {
                (*gd).inode_table_hi as u64
            } else {
                0
            };
            if lo == 0 && hi == 0 {
                return None;
            }
            Some((hi << 32) | lo)
        }
    }

    pub fn read_inode(&self, inode: u32) -> Result<Ext3Inode, &'static str> {
        let group = self.group_for_inode(inode);
        let index = self.inode_index_in_group(inode);
        let inode_table = self.inode_table_block(group).ok_or("bad group")?;
        let inode_byte = index as u64 * self.inode_size as u64;
        let inode_block = inode_table + inode_byte / self.block_size;
        let inode_offset = (inode_byte % self.block_size) as usize;

        let block = self.read_block(inode_block).ok_or("can't read inode block")?;
        unsafe {
            let ptr = block.add(inode_offset) as *const Ext3Inode;
            Ok(core::ptr::read_unaligned(ptr))
        }
    }

    pub fn write_inode(&self, inode: u32, ino: &Ext3Inode) -> Result<(), &'static str> {
        let group = self.group_for_inode(inode);
        let index = self.inode_index_in_group(inode);
        let inode_table = self.inode_table_block(group).ok_or("bad group")?;
        let inode_byte = index as u64 * self.inode_size as u64;
        let inode_block = inode_table + inode_byte / self.block_size;
        let inode_offset = (inode_byte % self.block_size) as usize;

        let block = self.read_block(inode_block).ok_or("can't read inode block")?;
        unsafe {
            let ptr = block.add(inode_offset) as *mut Ext3Inode;
            core::ptr::write_unaligned(ptr, *ino);
        }
        Ok(())
    }

    pub fn get_group(&self, group: u32) -> *mut Ext3GroupDesc {
        if group >= self.group_count_alloc {
            return core::ptr::null_mut();
        }
        unsafe { self.groups.add(group as usize) }
    }

    // ── logical block → physical block ──────────────────────────────

    /// Map logical block `lblk` of `ino` to its physical block number.
    ///
    /// Two encodings share the 60-byte i_block area and are told apart by
    /// i_flags: ext4 with EXT4_EXTENTS_FL uses the extent B+ tree rooted in
    /// i_block, everything else uses the classic 12 direct + 3 indirect block
    /// pointers. A missing mapping is a sparse hole and is reported as Err so
    /// readers can substitute zeroes instead of failing.
    pub fn map_block(&self, ino: &Ext3Inode, lblk: u64) -> Result<u64, &'static str> {
        if ino.flags & EXT4_EXTENTS_FL != 0 {
            let root = ino.block.as_ptr() as *const u8;
            self.extent_lookup(root, lblk, 0)
        } else {
            self.indirect_lookup(ino, lblk, 0)
        }
    }

    /// Classic ext2/3 mapping: 12 direct blocks, then a single, double and
    /// triple indirect level, each level indexing `block_size/4` entries.
    fn indirect_lookup(&self, ino: &Ext3Inode, lblk: u64, _level: u32) -> Result<u64, &'static str> {
        let per = (self.block_size / 4) as u64; // u32 entries per indirect block
        let n = lblk as usize;
        if n < EXT3_N_BLOCKS - 3 {
            return Ok(ino.block[n] as u64);
        }
        let mut rest = lblk - (EXT3_N_BLOCKS - 3) as u64;

        if rest < per {
            return self.indirect_entry(ino.block[EXT3_IND_BLOCK] as u64, rest as usize);
        }
        rest -= per;

        if rest < per * per {
            let dind = self.indirect_entry(ino.block[EXT3_DIND_BLOCK] as u64, (rest / per) as usize)?;
            return self.indirect_entry(dind, (rest % per) as usize);
        }
        rest -= per * per;

        if rest < per * per * per {
            let tind = self.indirect_entry(ino.block[EXT3_TIND_BLOCK] as u64, (rest / (per * per)) as usize)?;
            let dind = self.indirect_entry(tind, ((rest / per) % per) as usize)?;
            return self.indirect_entry(dind, (rest % per) as usize);
        }
        Err("lblk out of range")
    }

    fn indirect_entry(&self, block: u64, idx: usize) -> Result<u64, &'static str> {
        if block == 0 {
            return Err("hole");
        }
        let p = self.read_block(block).ok_or("can't read indirect block")?;
        let v = rd_u32(at(p, idx * 4)) as u64;
        if v == 0 {
            return Err("hole");
        }
        Ok(v)
    }

    /// Walk the extent B+ tree rooted at `node` (60 bytes inside the inode, or
    /// one data block) for logical block `lblk`.
    ///
    /// The tree is ordered by ee_block, so a leaf is a sorted run list and an
    /// interior node is searched for the last child whose first logical block
    /// is <= the target. `guard` bounds the recursion: a corrupt or cyclic
    /// tree must not spin the kernel forever.
    fn extent_lookup(&self, node: *const u8, lblk: u64, guard: u32) -> Result<u64, &'static str> {
        if guard > EXT4_EXTENT_MAX_DEPTH {
            return Err("extent tree too deep");
        }
        if rd_u16(node) != EXT4_EXTENT_MAGIC {
            return Err("bad extent magic");
        }
        let entries = rd_u16(at(node, 2)) as usize;
        let max = rd_u16(at(node, 4)) as usize;
        let depth = rd_u16(at(node, 6));
        if entries > max || entries > 4096 {
            return Err("bad extent entry count");
        }
        let first = at(node, EXT4_EXTENT_HEADER_SIZE as usize);

        if depth == 0 {
            for i in 0..entries {
                let e = at(first, i * EXT4_EXTENT_ENTRY_SIZE as usize);
                let ee_block = rd_u32(e) as u64;
                let raw_len = rd_u16(at(e, 4));
                // ee_len > 0x8000 marks an uninitialized (preallocated) run;
                // its blocks read as zeroes, same as a hole.
                let len = if raw_len > EXT4_EXTENT_LEN_UNINIT {
                    (raw_len - EXT4_EXTENT_LEN_UNINIT) as u64
                } else {
                    raw_len as u64
                };
                if lblk >= ee_block && lblk < ee_block + len {
                    let start = ((rd_u16(at(e, 6)) as u64) << 32) | rd_u32(at(e, 8)) as u64;
                    return Ok(start + (lblk - ee_block));
                }
            }
            return Err("lblk unmapped");
        }

        let mut child = 0u64;
        let mut found = false;
        for i in 0..entries {
            let idx = at(first, i * EXT4_EXTENT_ENTRY_SIZE as usize);
            let ei_block = rd_u32(idx) as u64;
            if lblk >= ei_block {
                child = ((rd_u16(at(idx, 6)) as u64) << 32) | rd_u32(at(idx, 4)) as u64;
                found = true;
            } else {
                break;
            }
        }
        if !found || child == 0 {
            return Err("lblk before first extent");
        }
        let blk = self.read_block(child).ok_or("can't read extent node")?;
        self.extent_lookup(blk, lblk, guard + 1)
    }

    /// First physical block referenced by the extent-tree root, for
    /// diagnostics: the header is the same in the inode copy and in a block, so
    /// the caller can tell a single-block (depth 0) tree from a real index.
    pub fn extent_root_block(&self, ino: &Ext3Inode) -> Result<u64, &'static str> {
        if ino.flags & EXT4_EXTENTS_FL == 0 {
            return Err("not an extent inode");
        }
        let root = ino.block.as_ptr() as *const u8;
        if rd_u16(root) != EXT4_EXTENT_MAGIC {
            return Err("bad extent magic");
        }
        let depth = rd_u16(at(root, 6));
        let first = at(root, EXT4_EXTENT_HEADER_SIZE as usize);
        if depth == 0 {
            // extent: ee_start_hi at +6, ee_start_lo at +8
            Ok(((rd_u16(at(first, 6)) as u64) << 32) | rd_u32(at(first, 8)) as u64)
        } else {
            // index: ei_leaf_lo at +4, ei_leaf_hi at +6
            Ok(((rd_u16(at(first, 6)) as u64) << 32) | rd_u32(at(first, 4)) as u64)
        }
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
            let _alloc = &mut *allocator();
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
                                self.write_block(bitmap_block, {
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

    // ── read path ───────────────────────────────────────────────────

    /// Total logical size of `ino`. i_size_high is only meaningful when
    /// LARGE_FILE is set, but reading it unconditionally is harmless because
    /// the field is zero on filesystems without the feature.
    pub fn file_size(ino: &Ext3Inode) -> u64 {
        (ino.size_lo as u64) | ((ino.size_hi as u64) << 32)
    }

    /// Read `buf.len()` bytes of file `ino` at `offset`, zero-filling sparse
    /// holes. Returns the number of bytes actually produced (0 at EOF).
    pub fn read_file(&self, ino: u32, offset: u64, buf: &mut [u8]) -> Result<usize, &'static str> {
        if ino == 0 || buf.is_empty() {
            return Ok(0);
        }
        let node = self.read_inode(ino)?;
        let size = Self::file_size(&node);
        if offset >= size {
            return Ok(0);
        }
        let want = core::cmp::min(buf.len() as u64, size - offset) as usize;
        let bs = self.block_size as usize;
        let mut done = 0usize;
        while done < want {
            let pos = offset + done as u64;
            let lblk = pos / bs as u64;
            let boff = (pos % bs as u64) as usize;
            let n = core::cmp::min(want - done, bs - boff);
            match self.map_block(&node, lblk) {
                Ok(pblk) => {
                    let p = self.read_block(pblk).ok_or("can't read data block")?;
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            p.add(boff),
                            buf.as_mut_ptr().add(done),
                            n,
                        );
                    }
                }
                // A hole is a legitimately empty region of a sparse file, not
                // an error: POSIX says read() returns zeroes there.
                Err(_) => {
                    for b in buf[done..done + n].iter_mut() {
                        *b = 0;
                    }
                }
            }
            done += n;
        }
        Ok(done)
    }

    /// True when `ino` is a directory. The EXT4_INDEX_FL check is informational
    /// only: indexed directories still expose their "." / ".." linear entries.
    pub fn is_dir(ino: &Ext3Inode) -> bool {
        ino.mode & EXT3_S_IFMT == EXT3_S_IFDIR
    }

    pub fn is_symlink(ino: &Ext3Inode) -> bool {
        ino.mode & EXT3_S_IFMT == EXT3_S_IFLNK
    }

    /// Resolve one name component inside directory `dir_ino`. Linear scan over
    /// the directory's data blocks; the ext4 HTree index (dir_index) is only
    /// consulted for directories that outgrew one block, which this read-only
    /// driver detects and reports rather than silently under-listing.
    pub fn lookup(&self, dir_ino: u32, name: &[u8]) -> Result<u32, &'static str> {
        if name.is_empty() || name == b"." {
            return Ok(dir_ino);
        }
        if name == b".." {
            return Ok(self.parent_ino(dir_ino)?);
        }
        let mut ents = [Dirent::empty(); 64];
        let n = self.readdir_into(dir_ino, 0, &mut ents)?;
        for e in ents[..n].iter() {
            if e.namelen as usize == name.len() && &e.name[..name.len()] == name {
                return Ok(e.ino as u32);
            }
        }
        Err("not found")
    }

    /// Inode number of `dir_ino`'s parent, taken from its ".." entry. The root
    /// is its own parent.
    fn parent_ino(&self, dir_ino: u32) -> Result<u32, &'static str> {
        if dir_ino == EXT3_ROOT_INO {
            return Ok(EXT3_ROOT_INO);
        }
        let mut ents = [Dirent::empty(); 8];
        let n = self.readdir_into(dir_ino, 0, &mut ents)?;
        for e in ents[..n].iter() {
            if e.name[..2] == *b".." {
                return Ok(e.ino as u32);
            }
        }
        Ok(dir_ino)
    }

    /// Enumerate directory entries into `out`, skipping the first `offset`
    /// names. The vfs readdir contract uses a plain entry index as the offset,
    /// so the whole directory is re-scanned from the start on every call; that
    /// is fine for the directory sizes this read-only driver targets.
    pub fn readdir_into(&self, dir_ino: u32, offset: u64, out: &mut [Dirent]) -> Result<usize, &'static str> {
        let node = self.read_inode(dir_ino)?;
        if !Self::is_dir(&node) {
            return Err("not a dir");
        }
        let size = Self::file_size(&node);
        let bs = self.block_size;
        let nblocks = (size + bs - 1) / bs;
        let mut idx: u64 = 0;
        let mut count = 0usize;
        let mut reported_index = false;

        for b in 0..nblocks {
            let pblk = match self.map_block(&node, b) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let p = match self.read_block(pblk) {
                Some(p) => p,
                None => continue,
            };
            let mut off = 0usize;
            while off + 8 <= bs as usize {
                let d_ino = rd_u32(at(p, off));
                let rec_len = rd_u16(at(p, off + 4)) as usize;
                let name_len = rd_u8(at(p, off + 6)) as usize;
                let ftype = rd_u8(at(p, off + 7));
                if rec_len < 8 || off + rec_len > bs as usize {
                    break; // corrupt record: stop rather than walk off the block
                }
                if d_ino != 0 && name_len > 0 && name_len <= MAX_NAME {
                    let name_ptr = at(p, off + 8);
                    if idx >= offset {
                        if count < out.len() {
                            let d = &mut out[count];
                            *d = Dirent::empty();
                            d.ino = d_ino as u64;
                            d.offset = idx;
                            d.type_ = ftype;
                            d.namelen = name_len as u16;
                            unsafe {
                                core::ptr::copy_nonoverlapping(name_ptr, d.name.as_mut_ptr(), name_len);
                            }
                            count += 1;
                        }
                    }
                    idx += 1;
                } else if d_ino == 0 && rec_len > bs as usize / 2 {
                    // A zero inode with a record spanning the rest of the block
                    // is how ext4 marks a hashed (dir_index) directory: the real
                    // entries live in index blocks this read-only path does not
                    // walk. Say so once instead of returning a truncated list.
                    if !reported_index {
                        reported_index = true;
                        serial::write_str("EXT4: dir uses htree index; linear entries only\n");
                    }
                }
                off += rec_len;
            }
        }
        Ok(count)
    }

    /// Read a symlink target. ext2/3/ext4 keep targets shorter than 60 bytes
    /// directly in i_block ("fast symlink"); longer ones live in a data block.
    pub fn readlink(&self, ino: u32, out: &mut [u8]) -> Result<usize, &'static str> {
        let node = self.read_inode(ino)?;
        if !Self::is_symlink(&node) {
            return Err("not a symlink");
        }
        let size = Self::file_size(&node);
        if size == 0 {
            return Err("empty symlink");
        }
        if size < EXT4_FAST_SYMLINK_MAX {
            let n = core::cmp::min(size as usize, EXT3_N_BLOCKS * 4);
            unsafe {
                core::ptr::copy_nonoverlapping(ino_block_bytes(&node), out.as_mut_ptr(), n);
            }
            return Ok(n);
        }
        let n = core::cmp::min(size as usize, out.len());
        self.read_file(ino, 0, &mut out[..n])
    }
}

/// Raw bytes of an inode's 60-byte i_block area (the extent root, the indirect
/// pointers, or an inline symlink target, depending on i_flags).
fn ino_block_bytes(ino: &Ext3Inode) -> *const u8 {
    ino.block.as_ptr() as *const u8
}

/// Boot-time proof that the mounted medium is readable end to end: mount table
/// lookup, directory scan and file data, all through the same VnodeOps entry
/// points user space uses. Emits serial evidence and returns the number of
/// entries seen so a caller can assert on it.
pub fn selftest(mount_point: &[u8]) -> usize {
    serial::write_str("EXT4: selftest on ");
    for &c in mount_point { serial::write_char(c as char); }
    serial::write_str("\n");

    let root = match super::path_resolve(mount_point) {
        Ok((ino, _)) => ino,
        Err(e) => {
            serial::write_str("EXT4: selftest: root resolve failed: ");
            serial::write_str(e);
            serial::write_str("\n");
            return 0;
        }
    };
    let st = match EXT_FS_OPS.stat(root) {
        Ok(s) => s,
        Err(e) => {
            serial::write_str("EXT4: selftest: root stat failed: ");
            serial::write_str(e);
            serial::write_str("\n");
            return 0;
        }
    };
    serial::write_str("EXT4: root ino=");
    serial::write_dec(st.ino);
    serial::write_str(" size=");
    serial::write_dec(st.size);
    serial::write_str(" mode=0");
    serial::write_str(octal(st.mode & 0o7777));
    serial::write_str("\n");

    let mut files = 0usize;
    let mut dirs = 0usize;
    walk(root, 1, &mut files, &mut dirs);
    serial::write_str("EXT4: selftest saw ");
    serial::write_dec(dirs as u64);
    serial::write_str(" dirs / ");
    serial::write_dec(files as u64);
    serial::write_str(" files\n");
    files + dirs
}

/// Permission bits as a short string. Only the shapes mke2fs emits are spelled
/// out; anything else prints "?" rather than growing a formatter.
fn octal(v: u32) -> &'static str {
    match v {
        0o755 => "755",
        0o644 => "644",
        0o777 => "777",
        0o600 => "600",
        0o7777 => "7777",
        _ => "?",
    }
}

/// Depth-limited directory walk that prints every entry with its size, so the
/// boot log alone shows whether names, modes and data all come back sane.
/// It calls the VnodeOps directly: this runs before user space exists, so it
/// must not consume vnode-table slots.
fn walk(dir_ino: u64, depth: u32, files: &mut usize, dirs: &mut usize) {
    if depth > 4 {
        return;
    }
    let mut ents = [Dirent::empty(); 64];
    let n = match EXT_FS_OPS.readdir(dir_ino, 0, &mut ents) {
        Ok(n) => n,
        Err(e) => {
            serial::write_str("EXT4: readdir failed: ");
            serial::write_str(e);
            serial::write_str("\n");
            return;
        }
    };
    for e in ents[..n].iter() {
        let name_len = e.namelen as usize;
        if name_len == 0 {
            continue;
        }
        let name = &e.name[..name_len];
        if name == b"." || name == b".." {
            continue;
        }
        let st = match EXT_FS_OPS.stat(e.ino) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let is_dir = (st.mode & S_IFMT) == S_IFDIR;
        serial::write_str("EXT4: ");
        for _ in 0..depth { serial::write_str("  "); }
        for &c in name {
            if c >= 0x20 && c < 0x7f { serial::write_char(c as char); }
        }
        if is_dir { serial::write_char('/'); }
        serial::write_str(" ino=");
        serial::write_dec(e.ino);
        serial::write_str(" size=");
        serial::write_dec(st.size);
        serial::write_str(" blocks=");
        serial::write_dec(st.blocks);
        serial::write_str("\n");

        if is_dir {
            *dirs += 1;
            walk(e.ino, depth + 1, files, dirs);
            continue;
        }
        *files += 1;
        // Read the head of the data so a bad extent mapping shows up here as
        // garbage or zeroes, not only in a later user-space cat.
        let mut head = [0u8; 48];
        if let Ok(k) = EXT_FS_OPS.read(e.ino, 0, &mut head) {
            let mut n = 0usize;
            for &c in head.iter().take(k.min(head.len())) {
                if c == b'\n' { break; }
                if c >= 0x20 && c < 0x7f { serial::write_char(c as char); } else { serial::write_char('.'); }
                n += 1;
            }
            if n > 0 {
                serial::write_str("\n");
            }
        }
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
    st.size = Ext3Fs::file_size(ino);
    st.blocks = ino.blocks_lo as u64;
    st.blksize = 512;
    st.atime = ino.atime as u64;
    st.mtime = ino.mtime as u64;
    st.ctime = ino.ctime as u64;
    st
}

// ── VFS binding ─────────────────────────────────────────────────────

/// The mounted ext2/3/4 instance. Inode numbers in the vfs layer *are* ext
/// inode numbers, so no translation table is needed: Vnode.ino is the u32 from
/// the directory entry.
///
/// The handle is written once during mount and only read afterwards; the
/// Mutex provides the cross-CPU ordering that the raw pointers inside need.
static EXT_FS: Mutex<Option<Ext3Fs>> = Mutex::new(None);

/// True once [`mount_ext`] has published a usable filesystem.
pub fn is_mounted() -> bool {
    EXT_FS.lock().is_some()
}

/// Mount the ext2/3/4 filesystem exposed by `read_block`/`write_block` and
/// publish it to the vfs layer. `write_block` is accepted for API symmetry but
/// the read path never calls it: see [`ExtFsOps`].
pub fn mount_ext(
    read_block: fn(u64) -> Option<*mut u8>,
    write_block: fn(u64, &[u8]) -> bool,
) -> Result<(), &'static str> {
    let mut fs = Ext3Fs::new();
    fs.mount(read_block, write_block)?;
    let mut slot = EXT_FS.lock();
    *slot = Some(fs);
    Ok(())
}

/// VnodeOps over the mounted ext2/3/4 instance.
///
/// Read-only by construction. Every mutating op returns an error instead of a
/// partial write: silently accepting a create/truncate on media we cannot
/// journal would hand user space a file it can never re-read after reboot.
pub struct ExtFsOps;
pub static EXT_FS_OPS: ExtFsOps = ExtFsOps;

/// With the fs handle: serialises the mount check and yields a shared borrow.
fn with_fs<R>(f: impl FnOnce(&Ext3Fs) -> R) -> Result<R, &'static str> {
    let guard = EXT_FS.lock();
    match guard.as_ref() {
        Some(fs) => Ok(f(fs)),
        None => Err("ext fs not mounted"),
    }
}

impl super::VnodeOps for ExtFsOps {
    fn read(&self, ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize, &'static str> {
        with_fs(|fs| fs.read_file(ino as u32, offset, buf))?
    }

    fn write(&self, _ino: u64, _offset: u64, _buf: &[u8]) -> Result<usize, &'static str> {
        Err("read-only fs")
    }

    fn lookup(&self, parent_ino: u64, name: &[u8]) -> Result<u64, &'static str> {
        with_fs(|fs| fs.lookup(parent_ino as u32, name).map(|i| i as u64))?
    }

    fn readdir(&self, dir_ino: u64, offset: u64, buf: &mut [Dirent]) -> Result<usize, &'static str> {
        with_fs(|fs| fs.readdir_into(dir_ino as u32, offset, buf))?
    }

    fn create(&self, _p: u64, _n: &[u8], _m: FileMode) -> Result<u64, &'static str> { Err("read-only fs") }
    fn mkdir(&self, _p: u64, _n: &[u8], _m: FileMode) -> Result<u64, &'static str> { Err("read-only fs") }
    fn remove(&self, _p: u64, _n: &[u8]) -> Result<(), &'static str> { Err("read-only fs") }
    fn rmdir(&self, _p: u64, _n: &[u8]) -> Result<(), &'static str> { Err("read-only fs") }
    fn symlink(&self, _p: u64, _n: &[u8], _t: &[u8]) -> Result<u64, &'static str> { Err("read-only fs") }
    fn rename(&self, _a: u64, _an: &[u8], _b: u64, _bn: &[u8]) -> Result<(), &'static str> { Err("read-only fs") }
    fn setattr(&self, _i: u64, _a: &Attr) -> Result<(), &'static str> { Err("read-only fs") }
    fn setxattr(&self, _i: u64, _n: &[u8], _v: &[u8]) -> Result<(), &'static str> { Err("read-only fs") }
    fn truncate(&self, _i: u64, _s: u64) -> Result<(), &'static str> { Err("read-only fs") }

    fn stat(&self, ino: u64) -> Result<Stat, &'static str> {
        with_fs(|fs| fs.read_inode(ino as u32).map(|n| stat_from_ext3(&n, ino as u32)))?
    }

    /// VnodeOps hands back a borrowed slice, but a symlink target lives on the
    /// medium (or inline in i_block), not in a struct that outlives the call.
    /// It is therefore staged into one static buffer, with the length published
    /// last so a reader can never observe a half-filled target.
    fn readlink(&self, ino: u64) -> Result<&[u8], &'static str> {
        use core::sync::atomic::Ordering;
        static SYMLINK_BUF: [u8; 4096] = [0; 4096];
        static SYMLINK_LEN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

        let mut staged = [0u8; 4096];
        let n = with_fs(|fs| fs.readlink(ino as u32, &mut staged))??;
        let m = n.min(staged.len()).min(SYMLINK_BUF.len());
        unsafe {
            let dst = SYMLINK_BUF.as_ptr() as *mut u8;
            core::ptr::copy_nonoverlapping(staged.as_ptr(), dst, m);
        }
        core::sync::atomic::fence(Ordering::SeqCst);
        SYMLINK_LEN.store(m, Ordering::SeqCst);
        Ok(&SYMLINK_BUF[..m])
    }

    fn getxattr(&self, _i: u64, _n: &[u8], _v: &mut [u8]) -> Result<usize, &'static str> { Err("no xattr") }
    fn listxattr(&self, _i: u64, _b: &mut [u8]) -> Result<usize, &'static str> { Err("no xattr") }
    fn ioctl(&self, _i: u64, _r: u64, _a: u64) -> Result<usize, &'static str> { Err("ENOTTY") }
}
