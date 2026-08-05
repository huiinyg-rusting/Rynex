use crate::serial;
use crate::vfs_core::{VnodeOps, Stat, FileMode, Dirent};
use crate::vfs_core::types::*;

pub const PROC_ROOT_INO: u64 = 1;
pub const PROC_UPTIME: u64 = 2;
pub const PROC_MEMINFO: u64 = 3;
pub const PROC_VERSION: u64 = 4;

// PID directory /and pid sub-file inodes live above the fixed files.
pub const PID_DIR_INO: u64 = 0x100000;
pub const PID_STAT_INO: u64 = 0x200000;
pub const PID_CMDLINE_INO: u64 = 0x300000;

pub fn pid_dir_ino(pid: u64) -> u64 { PID_DIR_INO + pid }
pub fn pid_stat_ino(pid: u64) -> u64 { PID_STAT_INO + pid }
pub fn pid_cmdline_ino(pid: u64) -> u64 { PID_CMDLINE_INO + pid }

/// Enumerate every live task id (state != Empty, id != 0) into `out`.
/// Returns the number of pids written.
fn live_pids(out: &mut [u64]) -> usize {
    let mut n = 0usize;
    let max_tasks = crate::task::MAX_TASKS as u64;
    for id in 1..=max_tasks {
        if n >= out.len() { break; }
        if let Some(t) = crate::task::task_by_id(id) {
            if t.state != crate::task::TaskState::Empty
                && t.state != crate::task::TaskState::Exited
                && t.state != crate::task::TaskState::Zombie
            {
                out[n] = id;
                n += 1;
            }
        }
    }
    n
}

fn pid_comm(pid: u64) -> [u8; 16] {
    match crate::task::task_by_id(pid) {
        Some(t) => t.comm,
        None => *b"unknown         ",
    }
}

pub struct ProcFs;
pub static PROCFS: ProcFs = ProcFs;

impl ProcFs {
    fn uptime_text(&self, buf: &mut [u8]) -> usize {
        let ticks = crate::pit::TICKS.load(core::sync::atomic::Ordering::Relaxed);
        let secs = ticks / 100;
        let frac = ticks % 100;
        let mut n = 0usize;
        if secs == 0 {
            if n < buf.len() { buf[n] = b'0'; n += 1; }
        } else {
            let mut s = secs;
            let mut digits = [0u8; 20];
            let mut d = 0usize;
            while s > 0 { digits[d] = b'0' + (s % 10) as u8; s /= 10; d += 1; }
            for i in (0..d).rev() { if n < buf.len() { buf[n] = digits[i]; n += 1; } }
        }
        if n < buf.len() { buf[n] = b'.'; n += 1; }
        let d1 = (frac / 10) as u8;
        let d0 = (frac % 10) as u8;
        if n < buf.len() { buf[n] = b'0' + d1; n += 1; }
        if n < buf.len() { buf[n] = b'0' + d0; n += 1; }
        let s = b" secs\n";
        let l = s.len().min(buf.len().saturating_sub(n));
        buf[n..n + l].copy_from_slice(&s[..l]);
        n + l
    }

    fn meminfo_text(&self, buf: &mut [u8]) -> usize {
        let s = b"MemTotal:       64000 kB\n";
        let l = s.len().min(buf.len());
        buf[..l].copy_from_slice(&s[..l]);
        l
    }

    fn version_text(&self, buf: &mut [u8]) -> usize {
        let s = b"Rynex 0.0.1-alpha\n";
        let l = s.len().min(buf.len());
        buf[..l].copy_from_slice(&s[..l]);
        l
    }

    fn stat_text(&self, pid: u64, buf: &mut [u8]) -> usize {
        // Linux /proc/<pid>/stat format (52 fields, busybox parses by offset):
        // 1. pid %d
        // 2. comm %s (in parentheses)
        // 3. state %c
        // 4. ppid %d
        // 5. pgrp %d
        // 6. session %d
        // 7. tty_nr %d
        // 8. tpgid %d
        // 9. flags %u
        // 10. minflt %lu
        // 11. cminflt %lu
        // 12. majflt %lu
        // 13. cmajflt %lu
        // 14. utime %lu
        // 15. stime %lu
        // 16. cutime %ld
        // 17. cstime %ld
        // 18. priority %ld
        // 19. nice %ld
        // 20. num_threads %ld
        // 21. itrealvalue %ld
        // 22. starttime %llu
        // 23. vsize %lu
        // 24. rss %ld
        // 25. rsslim %lu
        // 26. startcode %lu
        // 27. endcode %lu
        // 28. startstack %lu
        // 29. kstkesp %lu
        // 30. kstkeip %lu
        // 31. signal %lu
        // 32. blocked %lu
        // 33. sigignore %lu
        // 34. sigcatch %lu
        // 35. wchan %lu
        // 36. nswap %lu
        // 37. cnswap %lu
        // 38. exit_signal %d
        // 39. processor %d
        // 40. rt_priority %u
        // 41. policy %u
        // 42. delayacct_blkio_ticks %llu
        // 43. guest_time %lu
        // 44. cguest_time %ld
        // 45. start_data %lu
        // 46. end_data %lu
        // 47. start_brk %lu
        // 48. arg_start %lu
        // 49. arg_end %lu
        // 50. env_start %lu
        // 51. env_end %lu
        // 52. exit_code %d
        let mut n = 0usize;
        // pid
        let mut digits = [0u8; 20];
        let mut d = 0;
        let mut s = pid;
        while s > 0 { digits[d] = b'0' + (s % 10) as u8; s /= 10; d += 1; }
        for i in (0..d).rev() { if n < buf.len() { buf[n] = digits[i]; n += 1; } }
        let comm = pid_comm(pid);
        let ms = b" (";
        for &c in ms { if n < buf.len() { buf[n] = c; n += 1; } }
        for &c in comm.iter() {
            if c == 0 { break; }
            if n < buf.len() { buf[n] = c; n += 1; }
        }
        // State, ppid, pgrp, session, tty_nr, tpgid, flags,
        // minflt, cminflt, majflt, cmajflt,
        // utime, stime, cutime, cstime,
        // priority, nice, num_threads, itrealvalue,
        // starttime, vsize, rss, rsslim,
        // startcode, endcode, startstack, kstkesp, kstkeip,
        // signal, blocked, sigignore, sigcatch,
        // wchan, nswap, cnswap, exit_signal, processor,
        // rt_priority, policy, delayacct_blkio_ticks,
        // guest_time, cguest_time,
        // start_data, end_data, start_brk, arg_start, arg_end, env_start, env_end, exit_code
        let me = b") S 1 1 1 0 -1 4202496 0 0 0 0 0 0 0 0 20 0 1 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n";
        for &c in me { if n < buf.len() { buf[n] = c; n += 1; } }
        n
    }

    fn cmdline_text(&self, pid: u64, buf: &mut [u8]) -> usize {
        let comm = pid_comm(pid);
        let mut n = 0usize;
        for &c in comm.iter() {
            if c == 0 { break; }
            if n < buf.len() { buf[n] = c; n += 1; }
        }
        if n < buf.len() { buf[n] = 0; n += 1; }
        n
    }
}

impl VnodeOps for ProcFs {
    fn read(&self, ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize, &'static str> {
        let content_len = match ino {
            PROC_UPTIME => self.uptime_text(buf),
            PROC_MEMINFO => self.meminfo_text(buf),
            PROC_VERSION => self.version_text(buf),
            i if i >= PID_CMDLINE_INO => self.cmdline_text(i - PID_CMDLINE_INO, buf),
            i if i >= PID_STAT_INO => self.stat_text(i - PID_STAT_INO, buf),
            _ => return Err("not found"),
        };
        let off = offset as usize;
        if off >= content_len { return Ok(0); }
        let end = content_len.min(off + buf.len());
        if off > 0 {
            // Shift the already-rendered text to the requested offset.
            buf.copy_within(off..end, 0);
        }
        Ok(end - off)
    }

    fn write(&self, _ino: u64, _offset: u64, _buf: &[u8]) -> Result<usize, &'static str> {
        Err("read-only")
    }

    fn lookup(&self, parent_ino: u64, name: &[u8]) -> Result<u64, &'static str> {
        if parent_ino == PROC_ROOT_INO {
            return match name {
                b"uptime" => Ok(PROC_UPTIME),
                b"meminfo" => Ok(PROC_MEMINFO),
                b"version" => Ok(PROC_VERSION),
                _ => {
                    // Numeric name -> a /proc/<pid> directory.
                    if !name.is_empty() && name.iter().all(|&c| c >= b'0' && c <= b'9') {
                        let mut pid = 0u64;
                        for &c in name { pid = pid * 10 + (c - b'0') as u64; }
                        return Ok(pid_dir_ino(pid));
                    }
                    Err("not found")
                }
            };
        }
        // Inside a /proc/<pid> directory: stat, cmdline.
        if parent_ino >= PID_DIR_INO {
            let pid = parent_ino - PID_DIR_INO;
            return match name {
                b"stat" => Ok(pid_stat_ino(pid)),
                b"cmdline" => Ok(pid_cmdline_ino(pid)),
                _ => Err("not found"),
            };
        }
        Err("not found")
    }

    fn readdir(&self, dir_ino: u64, offset: u64, entries: &mut [Dirent]) -> Result<usize, &'static str> {
        if dir_ino == PROC_ROOT_INO {
            let files: &[(u64, &[u8])] = &[
                (PROC_UPTIME, b"uptime"),
                (PROC_MEMINFO, b"meminfo"),
                (PROC_VERSION, b"version"),
            ];
            let mut count = 0usize;
            let mut idx = 0usize;
            // Static files first.
            for &(ino, name) in files.iter() {
                let i = idx; idx += 1;
                if i < offset as usize { continue; }
                if count >= entries.len() { break; }
                let d = &mut entries[count];
                *d = Dirent::empty();
                d.ino = ino;
                d.type_ = 1; // DT_REG
                let s = name.len().min(d.name.len());
                d.name[..s].copy_from_slice(&name[..s]);
                d.namelen = s as u16;
                count += 1;
            }
            // Then numeric PID directories.
            let mut pids = [0u64; crate::task::MAX_TASKS];
            let np = live_pids(&mut pids);
            for p in pids[..np].iter() {
                let i = idx; idx += 1;
                if i < offset as usize { continue; }
                if count >= entries.len() { break; }
                let mut nm = [0u8; 8];
                let mut d = 0; let mut s = *p;
                while s > 0 { nm[d] = b'0' + (s % 10) as u8; s /= 10; d += 1; }
                let r = &mut entries[count];
                *r = Dirent::empty();
                r.ino = pid_dir_ino(*p);
                r.type_ = 2; // DT_DIR
                for j in 0..d { r.name[j] = nm[d - 1 - j]; }
                r.namelen = d as u16;
                count += 1;
            }
            return Ok(count);
        }
        // A /proc/<pid> directory contains stat and cmdline.
        if dir_ino >= PID_DIR_INO {
            let pid = dir_ino - PID_DIR_INO;
            let kids: &[(u64, &[u8])] = &[
                (pid_stat_ino(pid), b"stat"),
                (pid_cmdline_ino(pid), b"cmdline"),
            ];
            let mut count = 0usize;
            for (i, &(ino, name)) in kids.iter().enumerate() {
                if i < offset as usize { continue; }
                if count >= entries.len() { break; }
                let d = &mut entries[count];
                *d = Dirent::empty();
                d.ino = ino;
                let s = name.len().min(d.name.len());
                d.name[..s].copy_from_slice(&name[..s]);
                d.namelen = s as u16;
                count += 1;
            }
            return Ok(count);
        }
        Err("not a directory")
    }

    fn stat(&self, ino: u64) -> Result<Stat, &'static str> {
        let (mode, size) = if ino == PROC_ROOT_INO {
            (S_IFDIR | 0o555, 0)
        } else if ino >= PID_DIR_INO && ino < PID_STAT_INO {
            (S_IFDIR | 0o555, 0)
        } else if ino == PROC_UPTIME || ino == PROC_MEMINFO || ino == PROC_VERSION
            || (ino >= PID_STAT_INO) {
            (S_IFREG | 0o444, 0)
        } else {
            (S_IFREG | 0o444, 0)
        };
        Ok(Stat {
            dev: 0, ino, mode, nlink: 1, uid: 0, gid: 0,
            rdev: 0, size, blksize: 4096, blocks: 0,
            atime: 0, mtime: 0, ctime: 0,
        })
    }

    fn readlink(&self, _ino: u64) -> Result<&[u8], &'static str> { Err("not a symlink") }
    fn symlink(&self, _parent_ino: u64, _name: &[u8], _target: &[u8]) -> Result<u64, &'static str> { Err("read-only") }
    fn create(&self, _parent_ino: u64, _name: &[u8], _mode: FileMode) -> Result<u64, &'static str> { Err("read-only") }
    fn mkdir(&self, _parent_ino: u64, _name: &[u8], _mode: FileMode) -> Result<u64, &'static str> { Err("read-only") }
    fn remove(&self, _parent_ino: u64, _name: &[u8]) -> Result<(), &'static str> { Err("read-only") }
    fn rmdir(&self, _parent_ino: u64, _name: &[u8]) -> Result<(), &'static str> { Err("read-only") }
    fn rename(&self, _old_parent: u64, _old_name: &[u8], _new_parent: u64, _new_name: &[u8]) -> Result<(), &'static str> { Err("read-only") }
    fn setattr(&self, _ino: u64, _attr: &crate::vfs_core::Attr) -> Result<(), &'static str> { Ok(()) }
    fn getxattr(&self, _ino: u64, _name: &[u8], _value: &mut [u8]) -> Result<usize, &'static str> { Err("not supported") }
    fn setxattr(&self, _ino: u64, _name: &[u8], _value: &[u8]) -> Result<(), &'static str> { Err("read-only") }
    fn listxattr(&self, _ino: u64, _buf: &mut [u8]) -> Result<usize, &'static str> { Err("not supported") }
    fn truncate(&self, _ino: u64, _size: u64) -> Result<(), &'static str> { Err("read-only") }
    fn ioctl(&self, _ino: u64, _request: u64, _arg: u64) -> Result<usize, &'static str> { Err("not supported") }
}

/// Dynamically bind /proc/<pid>/stat and /proc/<pid>/cmdline for a new task.
/// Called when a task is created after procfs is mounted.
pub fn bind_task_procfs(pid: u64) {
    let fs_id = crate::vfs_core::get_proc_fsid();
    if fs_id == 0 {
        return;
    }
    let ops: &'static dyn crate::vfs_core::VnodeOps = &crate::vfs_core::procfs::PROCFS;
    let mut dbuf = [0u8; 24];
    let mut d = 0; let mut s = pid;
    while s > 0 { dbuf[d] = b'0' + (s % 10) as u8; s /= 10; d += 1; }
    let mut path = [0u8; 40];
    let p1 = b"/proc/";
    path[..p1.len()].copy_from_slice(p1);
    let mut off = p1.len();
    for j in (0..d).rev() { path[off] = dbuf[j]; off += 1; }
    let p2 = b"/stat";
    path[off..off + p2.len()].copy_from_slice(p2);
    off += p2.len();
    let stat_path = &path[..off];
    if let Some(vn_id) = crate::vfs_core::vnode_alloc(pid_stat_ino(pid), fs_id, 0, ops) {
        crate::vfs::bind_vnode_inode(stat_path, vn_id);
    }
    let p3 = b"/cmdline";
    let mut path2 = [0u8; 40];
    path2[..p1.len()].copy_from_slice(p1);
    let mut off2 = p1.len();
    for j in (0..d).rev() { path2[off2] = dbuf[j]; off2 += 1; }
    path2[off2..off2 + p3.len()].copy_from_slice(p3);
    off2 += p3.len();
    if let Some(vn_id) = crate::vfs_core::vnode_alloc(pid_cmdline_ino(pid), fs_id, 0, ops) {
        crate::vfs::bind_vnode_inode(&path2[..off2], vn_id);
    }
}

pub fn init() {
    serial::write_str("PROCFS: initializing\n");
}

pub fn mount_proc() {
    let fs_id = crate::vfs_core::alloc_fsid();
    crate::vfs_core::set_procfs_fsid(fs_id);
    let ops: &'static dyn crate::vfs_core::VnodeOps = &crate::vfs_core::procfs::PROCFS;
    if crate::vfs_core::mount(b"/proc", fs_id, PROC_ROOT_INO, ops).is_err() {
        serial::write_str("PROCFS: mount failed\n");
        return;
    }
    serial::write_str("PROCFS: mounted at /proc\n");

    // Bind the /proc directory itself so opendir/getdents delegate to the
    // procfs readdir (returns uptime/meminfo/version + PID directories).
    if let Some(vn_id) = crate::vfs_core::vnode_alloc(PROC_ROOT_INO, fs_id, 0, ops) {
        crate::vfs::bind_vnode_inode(b"/proc", vn_id);
    }

    // Bind each /proc file to a procfs vnode so the legacy flat-inode read
    // path (crate::vfs::inode_read with data_ptr == null, vnode_id != 0)
    // delegates into the VnodeOps::read above instead of a static buffer.
    let files: &[(u64, &[u8])] = &[
        (PROC_UPTIME, b"uptime"),
        (PROC_MEMINFO, b"meminfo"),
        (PROC_VERSION, b"version"),
    ];
    for &(ino, name) in files {
        // Build the full path "/proc/<name>".
        let mut path = [0u8; 32];
        let prefix = b"/proc/";
        path[..prefix.len()].copy_from_slice(prefix);
        let nl = name.len().min(32 - prefix.len());
        path[prefix.len()..prefix.len() + nl].copy_from_slice(&name[..nl]);
        let path = &path[..prefix.len() + nl];

        let vn_id = match crate::vfs_core::vnode_alloc(ino, fs_id, 0, ops) {
            Some(v) => v,
            None => continue,
        };
        crate::vfs::bind_vnode_inode(path, vn_id);
    }

    // Bind /proc/<pid>/stat and /proc/<pid>/cmdline for every live task.
    let mut pids = [0u64; crate::task::MAX_TASKS];
    let np = live_pids(&mut pids);
    for &pid in pids[..np].iter() {
        let mut dbuf = [0u8; 24];
        let mut d = 0; let mut s = pid;
        while s > 0 { dbuf[d] = b'0' + (s % 10) as u8; s /= 10; d += 1; }
        let mut path = [0u8; 40];
        let p1 = b"/proc/";
        path[..p1.len()].copy_from_slice(p1);
        let mut off = p1.len();
        for j in (0..d).rev() { path[off] = dbuf[j]; off += 1; }
        let p2 = b"/stat";
        path[off..off + p2.len()].copy_from_slice(p2);
        off += p2.len();
        let stat_path = &path[..off];
        if let Some(vn_id) = crate::vfs_core::vnode_alloc(pid_stat_ino(pid), fs_id, 0, ops) {
            crate::vfs::bind_vnode_inode(stat_path, vn_id);
        }
        let p3 = b"/cmdline";
        let mut path2 = [0u8; 40];
        path2[..p1.len()].copy_from_slice(p1);
        let mut off2 = p1.len();
        for j in (0..d).rev() { path2[off2] = dbuf[j]; off2 += 1; }
        path2[off2..off2 + p3.len()].copy_from_slice(p3);
        off2 += p3.len();
        if let Some(vn_id) = crate::vfs_core::vnode_alloc(pid_cmdline_ino(pid), fs_id, 0, ops) {
            crate::vfs::bind_vnode_inode(&path2[..off2], vn_id);
        }
    }
}