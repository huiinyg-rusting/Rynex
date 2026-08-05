use core::sync::atomic::{AtomicU64, Ordering};

pub const MAX_NAME: usize = 255;
pub const MAX_PATH: usize = 4096;
pub const MAX_SYMLINKS: u32 = 40;
pub const ROOT_UID: u32 = 0;
pub const ROOT_GID: u32 = 0;

pub type Mode = u32;
pub type Uid = u32;
pub type Gid = u32;
pub type Ino = u64;
pub type BlockNo = u64;
pub type Off = i64;
pub type Size = u64;
pub type FileMode = u32;
pub type OpenFlags = u32;

pub const O_RDONLY: OpenFlags = 0;
pub const O_WRONLY: OpenFlags = 1;
pub const O_RDWR: OpenFlags = 2;
pub const O_CREAT: OpenFlags = 0x40;
pub const O_EXCL: OpenFlags = 0x80;
pub const O_TRUNC: OpenFlags = 0x200;
pub const O_APPEND: OpenFlags = 0x400;
pub const O_DIRECTORY: OpenFlags = 0x10000;

pub const S_IXOTH: FileMode = 0o001;
pub const S_IWOTH: FileMode = 0o002;
pub const S_IROTH: FileMode = 0o004;
pub const S_IXGRP: FileMode = 0o010;
pub const S_IWGRP: FileMode = 0o020;
pub const S_IRGRP: FileMode = 0o040;
pub const S_IXUSR: FileMode = 0o100;
pub const S_IWUSR: FileMode = 0o200;
pub const S_IRUSR: FileMode = 0o400;
pub const S_ISVTX: FileMode = 0o1000;
pub const S_ISGID: FileMode = 0o2000;
pub const S_ISUID: FileMode = 0o4000;
pub const S_IFMT: FileMode = 0xF000;
pub const S_IFSOCK: FileMode = 0xC000;
pub const S_IFLNK: FileMode = 0xA000;
pub const S_IFREG: FileMode = 0x8000;
pub const S_IFBLK: FileMode = 0x6000;
pub const S_IFDIR: FileMode = 0x4000;
pub const S_IFCHR: FileMode = 0x2000;
pub const S_IFIFO: FileMode = 0x1000;

#[derive(Clone, Copy)]
pub struct Stat {
    pub dev: u64,
    pub ino: Ino,
    pub mode: FileMode,
    pub nlink: u32,
    pub uid: Uid,
    pub gid: Gid,
    pub rdev: u64,
    pub size: Size,
    pub blksize: u64,
    pub blocks: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
}

impl Stat {
    pub const fn empty() -> Self {
        Stat {
            dev: 0, ino: 0, mode: 0, nlink: 0,
            uid: 0, gid: 0, rdev: 0, size: 0,
            blksize: 0, blocks: 0, atime: 0, mtime: 0, ctime: 0,
        }
    }
}

pub struct Dirent {
    pub ino: Ino,
    pub offset: u64,
    pub namelen: u16,
    pub type_: u8,
    pub name: [u8; MAX_NAME],
}

impl Dirent {
    pub const fn empty() -> Self {
        Dirent {
            ino: 0, offset: 0, namelen: 0, type_: 0,
            name: [0; MAX_NAME],
        }
    }
}

pub struct TimeSpec {
    pub sec: i64,
    pub nsec: i64,
}

pub struct Attr {
    pub mode: FileMode,
    pub uid: Uid,
    pub gid: Gid,
    pub size: Size,
    pub atime: TimeSpec,
    pub mtime: TimeSpec,
    pub ctime: TimeSpec,
    pub blksize: u32,
    pub blocks: u64,
}

pub type FsId = u64;
static NEXT_FSID: AtomicU64 = AtomicU64::new(1);

// Procfs filesystem ID (set when procfs is mounted)
static PROCFS_FSID: AtomicU64 = AtomicU64::new(0);

pub fn alloc_fsid() -> FsId {
    NEXT_FSID.fetch_add(1, Ordering::SeqCst)
}

pub fn set_procfs_fsid(fs_id: FsId) {
    PROCFS_FSID.store(fs_id, Ordering::SeqCst);
}

pub fn get_proc_fsid() -> FsId {
    PROCFS_FSID.load(Ordering::SeqCst)
}

pub const S_BLKSIZE: u64 = 4096;
