use core::mem;

const TAG_MMAP: u32 = 6;
const TAG_MODULE: u32 = 3;
const TAG_END: u32 = 0;
const MMAP_USABLE: u32 = 1;

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct Info {
    total_size: u32,
    _reserved: u32,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct TagHeader {
    typ: u32,
    size: u32,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct ModuleTag {
    typ: u32,
    size: u32,
    mod_start: u32,
    mod_end: u32,
    cmdline: [u8; 1],
}

#[derive(Clone, Copy, Debug)]
pub struct ModuleInfo {
    pub start: u64,
    pub end: u64,
    /// Basename of the module's cmdline (e.g. "/boot/wthit" -> "wthit").
    /// NUL-terminated; empty if no cmdline was provided.
    pub name: [u8; 64],
}

pub fn find_modules(info_addr: u32, out: &mut [ModuleInfo]) -> usize {
    let total = unsafe { (*(info_addr as *const Info)).total_size };
    let mut count = 0;
    let mut offset = mem::size_of::<Info>() as u32;

    while offset + 8 <= total {
        let p = (info_addr as u64 + offset as u64) as *const u8;
        let typ = unsafe { core::ptr::read_unaligned(p as *const u32) };
        if typ == TAG_END {
            break;
        }
        let size = unsafe { core::ptr::read_unaligned(p.add(4) as *const u32) };
        if size < 8 {
            break;
        }
        if typ == TAG_MODULE && count < out.len() {
            let start = unsafe { core::ptr::read_unaligned(p.add(8) as *const u32) } as u64;
            let end = unsafe { core::ptr::read_unaligned(p.add(12) as *const u32) } as u64;
            let mut name = [0u8; 64];
            // cmdline string follows mod_end at offset 16 within the tag.
            let cmd = unsafe { p.add(16) };
            let mut ci = 0usize;
            while ci < 63 {
                let c = unsafe { core::ptr::read_volatile(cmd.add(ci)) };
                if c == 0 { break; }
                name[ci] = c;
                ci += 1;
            }
            // Reduce to basename (strip everything up to the last '/').
            let mut base_start = 0usize;
            for (j, &c) in name.iter().enumerate() {
                if c == 0 { break; }
                if c == b'/' { base_start = j + 1; }
            }
            let mut n = 0usize;
            for j in base_start..64 {
                let c = name[j];
                if c == 0 { break; }
                name[n] = c;
                n += 1;
            }
            for j in n..64 { name[j] = 0; }
            out[count] = ModuleInfo { start, end, name };
            count += 1;
        }
        offset += size;
        offset = (offset + 7) & !7;
    }
    count
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct MmapTag {
    _typ: u32,
    _size: u32,
    entry_size: u32,
    entry_version: u32,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct MmapEntry {
    base: u64,
    len: u64,
    typ: u32,
    _reserved: u32,
}

#[derive(Clone, Copy)]
pub struct MemRegion {
    pub base: u64,
    pub len: u64,
}

pub fn memory_regions(info_addr: u32, out: &mut [MemRegion]) -> usize {
    let info = info_addr as *const Info;
    let total = unsafe { (*info).total_size };
    let mut count = 0;
    let mut offset = mem::size_of::<Info>() as u32;

    while offset + 8 <= total {
        let p = (info_addr as u64 + offset as u64) as *const u8;
        let typ = unsafe { core::ptr::read_unaligned(p as *const u32) };

        if typ == TAG_END {
            break;
        }

        let size = unsafe { core::ptr::read_unaligned(p.add(4) as *const u32) };
        if size < 8 {
            break;
        }

        if typ == TAG_MMAP {
            let entry_size = unsafe {
                core::ptr::read_unaligned(p.add(8) as *const u32)
            };
            if entry_size < 20 {
                return count;
            }

            let mut entry_off = offset + 16;
            let entries_end = offset + size;

            while entry_off + entry_size <= entries_end && count < out.len() {
                let ep = (info_addr as u64 + entry_off as u64) as *const u8;
                let base = unsafe { core::ptr::read_unaligned(ep as *const u64) };
                let len = unsafe { core::ptr::read_unaligned(ep.add(8) as *const u64) };
                let etyp = unsafe { core::ptr::read_unaligned(ep.add(16) as *const u32) };
                if etyp == MMAP_USABLE && len > 0 {
                    out[count] = MemRegion { base, len };
                    count += 1;
                }
                entry_off += entry_size;
            }
            return count;
        }

        offset += size;
        offset = (offset + 7) & !7;
    }

    count
}
