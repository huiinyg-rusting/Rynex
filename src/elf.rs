use crate::serial;
use crate::paging::{PageTableManager, PTE_PRESENT, PTE_WRITABLE, PTE_USER, PTE_NO_EXECUTE};
use crate::paging::{PTE_ADDR_MASK, KERNEL_PML4};

pub const USER_STACK_TOP: u64 = 0x0000_7FFF_FFFF_F000;
pub const USER_STACK_PAGES: usize = 4;

#[repr(C)]
struct Elf64Header {
    ident: [u8; 16],
    type_: u16,
    machine: u16,
    version: u32,
    entry: u64,
    phoff: u64,
    shoff: u64,
    flags: u32,
    ehsize: u16,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
}

#[repr(C)]
struct Elf64ProgramHeader {
    type_: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    paddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

const PT_NULL: u32 = 0;
const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const PT_PHDR: u32 = 6;
const PT_DYNAMIC: u32 = 2;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_RELAENT: u64 = 9;
const R_X86_64_RELATIVE: u64 = 8;

#[derive(Clone, Copy)]
#[repr(C)]
struct Elf64Rela {
    r_offset: u64,
    r_info: u64,
    r_addend: i64,
}

fn apply_rela_relocations(data: &[u8], load_addr: u64, pml4: u64, max_end: u64) -> Result<u64, &'static str> {
    let hdr = unsafe { &*(data.as_ptr() as *const Elf64Header) };
    let phoff = hdr.phoff as usize;
    let phentsize = hdr.phentsize as usize;
    let phnum = hdr.phnum as usize;

    let mut dynamic_offset = 0usize;
    let mut dynamic_filesz = 0usize;
    let mut found_dynamic = false;

    for i in 0..phnum {
        let phdr = unsafe {
            let p = data.as_ptr().add(phoff + i * phentsize) as *const Elf64ProgramHeader;
            &*p
        };
        if phdr.type_ == PT_DYNAMIC {
            dynamic_offset = phdr.offset as usize;
            dynamic_filesz = phdr.filesz as usize;
            found_dynamic = true;
            break;
        }
    }

    if !found_dynamic {
        return Ok(max_end);
    }

    if dynamic_offset + dynamic_filesz > data.len() {
        return Err("DYNAMIC segment out of bounds");
    }

    let dyn_data = &data[dynamic_offset..dynamic_offset + dynamic_filesz];
    let mut rela_addr = 0u64;
    let mut rela_size = 0u64;
    let mut rela_ent = 0u64;

    for i in (0..dyn_data.len()).step_by(16) {
        if i + 16 > dyn_data.len() {
            break;
        }
        let tag = u64::from_le_bytes(dyn_data[i..i+8].try_into().unwrap());
        let val = u64::from_le_bytes(dyn_data[i+8..i+16].try_into().unwrap());

        match tag {
            DT_RELA => rela_addr = val + load_addr,
            DT_RELASZ => rela_size = val,
            DT_RELAENT => rela_ent = val,
            _ => {}
        }
    }

    if rela_addr == 0 || rela_size == 0 || rela_ent == 0 {
        return Ok(max_end);
    }

    let num_entries = (rela_size / rela_ent) as usize;
    if num_entries == 0 {
        return Ok(max_end);
    }

    let total_bytes = num_entries * 24;
    let pages_needed = (total_bytes + 0xFFF) / 0x1000;
    let mut relbuf_order = 0;
    while (4096usize << relbuf_order) < pages_needed * 4096 && relbuf_order < 10 {
        relbuf_order += 1;
    }
    let alloc = unsafe { &mut *crate::memory::allocator() };
    let relabuf_phys = match alloc.alloc(relbuf_order) {
        Some(p) => p,
        None => return Err("OOM for RELA buffer"),
    };
    let relabuf = unsafe { core::slice::from_raw_parts_mut(relabuf_phys as *mut u8, total_bytes) };

    // Copy the RELA table from the freshly mapped user pages into a kernel buffer.
    // This must NOT use `alloc.free` on a partial order (we free the exact order
    // we allocated above).
    let mut copied = 0usize;
    while copied < total_bytes {
        let page_va = (rela_addr + copied as u64) & !0xFFF;
        let offset = ((rela_addr + copied as u64) & 0xFFF) as u64;
        let phys = crate::paging::PageTableManager::resolve_phys(pml4, page_va).ok_or("RELA page not mapped")?;
        let src = (phys + offset) as *const u8;
        let dst = unsafe { relabuf.as_mut_ptr().add(copied) };
        let to_copy = core::cmp::min(4096 - offset as usize, total_bytes - copied);
        unsafe { core::ptr::copy_nonoverlapping(src, dst, to_copy) };
        copied += to_copy;
    }

    for i in 0..num_entries {
        let rela = unsafe { &*(relabuf.as_ptr().add(i * 24) as *const Elf64Rela) };
        let rel_type = rela.r_info & 0xFFFFFFFF;
        if rel_type == R_X86_64_RELATIVE {
            let target_va = rela.r_offset + load_addr;
            let value = load_addr as i64 + rela.r_addend;
            let target_phys = crate::paging::PageTableManager::resolve_phys(pml4, target_va).ok_or("Relocation target not mapped")?;
            unsafe { core::ptr::write((target_phys + (target_va & 0xFFF)) as *mut u64, value as u64); }
        }
    }

    alloc.free(relabuf_phys, relbuf_order);
    Ok(max_end)
}
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

pub struct ElfLoadInfo {
    pub entry: u64,
    pub pml4: u64,
    pub stack_top: u64,
    pub is_dynamic: bool,
    pub interp_path: [u8; 64],
    pub interp_path_len: usize,
    pub phdr_user: u64,
    pub phnum: u16,
    pub phentsize: u16,
    pub brk_base: u64,
}

fn page_align_up(addr: u64) -> u64 {
    (addr + 4095) & !4095
}

fn page_align_down(addr: u64) -> u64 {
    addr & !4095
}

fn alloc_page() -> Option<u64> {
    let alloc = unsafe { &mut *crate::memory::allocator() };
    alloc.alloc(0)
}

fn pt_flags(elf_flags: u32) -> u64 {
    let mut f = PTE_PRESENT | PTE_USER;
    if elf_flags & PF_W != 0 {
        f |= PTE_WRITABLE;
    }
    if elf_flags & PF_X == 0 {
        f |= PTE_NO_EXECUTE;
    }
    f
}

fn map_page_into(pml4: u64, virt: u64, phys: u64, flags: u64) -> Result<(), &'static str> {
    PageTableManager::map_into(pml4, virt, phys, flags)
}

pub fn load_elf(data: &[u8]) -> Result<ElfLoadInfo, &'static str> {
    if data.len() >= 16 {
        let e_type = u16::from_le_bytes([data[16], data[17]]);
        if e_type == 3 {
            // Load PIE binaries above the kernel image/BSS (which is identity
            // mapped in the low VA range). 0x400000 overlaps the kernel BSS
            // (RAMFS inode table lives around 0x3C2898-0xA23098), so user
            // segments there would shadow kernel statics and break RAMFS.
            return load_elf_at(data, 0x1000000, None);
        }
    }
    load_elf_at(data, 0, None)
}

pub fn load_elf_at(data: &[u8], load_addr: u64, existing_pml4: Option<u64>) -> Result<ElfLoadInfo, &'static str> {
    if data.len() < 64 {
        return Err("ELF too small");
    }

    let hdr = unsafe { &*(data.as_ptr() as *const Elf64Header) };

    // Validate ELF magic

    if hdr.ident[0..4] != ELF_MAGIC {
        return Err("bad ELF magic");
    }
    if hdr.ident[4] != 2 {
        return Err("not 64-bit");
    }
    if hdr.ident[5] != 1 {
        return Err("not little-endian");
    }
    if hdr.machine != 0x3E {
        return Err("not x86_64");
    }

    let phoff = hdr.phoff as usize;
    let phentsize = hdr.phentsize as usize;
    let phnum = hdr.phnum as usize;

    if phoff + phentsize * phnum > data.len() {
        return Err("PHdr out of bounds");
    }

    // Clone kernel page tables for the new process, or use an existing PML4
    let pml4 = if let Some(existing) = existing_pml4 {
        existing
    } else {
        let p = match alloc_page() {
            Some(p) => p,
            None => return Err("OOM for PML4"),
        };
        let new_pt = unsafe { &mut *(p as *mut crate::paging::PageTable) };
        let kernel_pml4 = KERNEL_PML4.load(core::sync::atomic::Ordering::SeqCst);
        let old_pt = unsafe { &*(kernel_pml4 as *const crate::paging::PageTable) };
        new_pt.0 = old_pt.0; // shallow copy all entries

        // Deep-copy the identity-map PDPT (PML4[0] → PDPT → PD → PT).
        // This gives us private copies of the PD and PDPT so map_into can modify them.
        if new_pt.0[0] & crate::paging::PTE_PRESENT != 0 {
            let old_pdpt = (new_pt.0[0] & crate::paging::PTE_ADDR_MASK) as *const crate::paging::PageTable;
            let new_pdpt = alloc_page().ok_or("OOM: PDPT clone")?;
            unsafe {
                core::ptr::copy(old_pdpt as *const u8, new_pdpt as *mut u8, 4096);
        let pdpt = &mut *(new_pdpt as *mut crate::paging::PageTable);
        for i in 0..512 {
            if pdpt.0[i] & crate::paging::PTE_PRESENT != 0 {
                if pdpt.0[i] & crate::paging::PTE_HUGE != 0 {
                    // 1G huge page — keep as-is (don't deep-copy)
                    continue;
                }
                let old_pd = (pdpt.0[i] & crate::paging::PTE_ADDR_MASK) as *const crate::paging::PageTable;
                let new_pd = alloc_page().ok_or("OOM: PD clone")?;
                unsafe { core::ptr::copy(old_pd as *const u8, new_pd as *mut u8, 4096); }
                pdpt.0[i] = new_pd | (pdpt.0[i] & !crate::paging::PTE_ADDR_MASK);
            }
        }
            }
            // Set PTE_USER on PML4[0] and all PDPT/PD entries so user mode can walk them
            new_pt.0[0] = (new_pdpt | (new_pt.0[0] & !crate::paging::PTE_ADDR_MASK)) | crate::paging::PTE_USER;
            unsafe {
                let pdpt = &mut *(new_pdpt as *mut crate::paging::PageTable);
                for i in 0..512 {
                    if pdpt.0[i] & crate::paging::PTE_PRESENT != 0 {
                        pdpt.0[i] |= crate::paging::PTE_USER;
                        if pdpt.0[i] & crate::paging::PTE_HUGE != 0 {
                            // 1G huge page — no PD to walk
                            continue;
                        }
                        let pd_addr = pdpt.0[i] & crate::paging::PTE_ADDR_MASK;
                        // PD entries (2MB identity hugepages) stay NON-USER so user
                        // mode cannot access VA==phys (which would alias buddy-allocated
                        // pages with their identity VA and corrupt heap/LDSO memory).
                        // map_into replaces the specific PD entries it needs with USER PTs.
                    }
                }
                // Map VA 0x0-0xFFF to a zero page so musl's guard read at p->mem[-1]
                // returns 0 instead of silently reading firmware data from physical page 0.
                // We must NOT clear PD[0] entirely because that unmaps VA 0x100000
                // (the kernel itself, loaded at physical 1 MB via identity map).
                if pdpt.0[0] & crate::paging::PTE_PRESENT != 0 && pdpt.0[0] & crate::paging::PTE_HUGE == 0 {
                    let pd0_addr = pdpt.0[0] & crate::paging::PTE_ADDR_MASK;
                    let pd0 = &mut *(pd0_addr as *mut crate::paging::PageTable);
                    let pde0 = pd0.0[0];
                    if pde0 & crate::paging::PTE_PRESENT != 0 {
                        let zero_page = alloc_page().ok_or("OOM: zero page")?;
                        unsafe { core::ptr::write_bytes(zero_page as *mut u8, 0, 4096); }
                        if pde0 & crate::paging::PTE_HUGE != 0 {
                            // 2 MB huge page – split into 4 KB pages
                            let huge_phys = pde0 & crate::paging::PTE_ADDR_MASK;
                            let new_pt = alloc_page().ok_or("OOM: null PT split")?;
                            unsafe { core::ptr::write_bytes(new_pt as *mut u8, 0, 4096); }
                            let pt = unsafe { &mut *(new_pt as *mut crate::paging::PageTable) };
                            for i in 0..512 {
                                // Identity sub-pages stay kernel-only (non-USER) to prevent
                                // user-mode aliasing of physical memory via VA==phys.
                                let flags = crate::paging::PTE_PRESENT | crate::paging::PTE_WRITABLE;
                                pt.0[i] = (huge_phys + (i as u64) * 4096) | flags;
                            }
                            pt.0[0] = zero_page | crate::paging::PTE_PRESENT | crate::paging::PTE_USER | crate::paging::PTE_NO_EXECUTE;
                            let flags = crate::paging::PTE_PRESENT | crate::paging::PTE_WRITABLE | crate::paging::PTE_USER | crate::paging::PTE_ACCESSED | crate::paging::PTE_DIRTY;
                            pd0.0[0] = new_pt | flags;
                        } else {
                            // Already 4 KB pages – redirect PT[0] to zero page
                            let pt_addr = pde0 & crate::paging::PTE_ADDR_MASK;
                            let pt = unsafe { &mut *(pt_addr as *mut crate::paging::PageTable) };
                            pt.0[0] = zero_page | crate::paging::PTE_PRESENT | crate::paging::PTE_USER | crate::paging::PTE_NO_EXECUTE;
                        }
                    }
                }
            }
        }
        p
    };

    // Highest mapped address (for stack placement)
    let mut max_end = 0u64;
    let mut interp_path = [0u8; 64];
    let mut interp_path_len = 0usize;
    let mut is_dynamic = false;

    // First pass: detect PT_INTERP
    serial::write_str("ELF: scanning program headers\n");
    for i in 0..phnum {
        let phdr = unsafe {
            let p = data.as_ptr().add(phoff + i * phentsize) as *const Elf64ProgramHeader;
            &*p
        };
        serial::write_str("ELF: phdr type=");
        serial::write_hex(phdr.type_ as u64);
        serial::write_str(" vaddr=0x");
        serial::write_hex(phdr.vaddr);
        serial::write_str(" memsz=0x");
        serial::write_hex(phdr.memsz);
        serial::write_str("\n");
        if phdr.type_ == PT_INTERP {
            let off = phdr.offset as usize;
            let sz = phdr.filesz as usize;
            if off + sz <= data.len() && sz > 0 && sz < 64 {
                let path = &data[off..off + sz - 1]; // exclude null terminator
                let len = core::cmp::min(path.len(), 63);
                interp_path[..len].copy_from_slice(&path[..len]);
                interp_path_len = len;
                is_dynamic = true;
            }
        }
    }

    // Load each PT_LOAD segment
    serial::write_str("ELF: loading PT_LOAD segments\n");
    for i in 0..phnum {
        let phdr = unsafe {
            let p = data.as_ptr().add(phoff + i * phentsize) as *const Elf64ProgramHeader;
            &*p
        };
        serial::write_str("ELF: phdr type=");
        serial::write_hex(phdr.type_ as u64);
        serial::write_str(" vaddr=0x");
        serial::write_hex(phdr.vaddr);
        serial::write_str(" memsz=0x");
        serial::write_hex(phdr.memsz);
        serial::write_str("\n");

        if phdr.type_ != PT_LOAD {
            continue;
        }

        let vaddr_base = phdr.vaddr + load_addr;
        let seg_start = page_align_down(vaddr_base);
        let seg_end = page_align_up(vaddr_base + phdr.memsz);
        let offset_in_page = vaddr_base - seg_start;

        let flags = pt_flags(phdr.flags);

        // Map pages for this segment
        let mut addr = seg_start;
        while addr < seg_end {
            let phys = match alloc_page() {
                Some(p) => p,
                None => return Err("OOM for segment page"),
            };
            // Zero the entire page before copying file data (important for BSS)
            unsafe { core::ptr::write_bytes(phys as *mut u8, 0, 4096); }
            map_page_into(pml4, addr, phys, flags)?;

            // Copy file data
            let page_off = if addr == seg_start { offset_in_page } else { 0 };
            let copy_start = addr + page_off;
            let file_end_va = vaddr_base + phdr.filesz;
            let copy_size = if file_end_va > addr + 4096 {
                addr + 4096 - copy_start
            } else {
                file_end_va.saturating_sub(copy_start)
            };

            if copy_size > 0 {
                let file_off = (copy_start - vaddr_base) as usize;
                if (phdr.offset as usize + file_off + copy_size as usize) <= data.len() {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            data.as_ptr().add(phdr.offset as usize + file_off),
                            (phys + page_off) as *mut u8,
                            copy_size as usize,
                        );
                    }
                }
            }

            addr += 4096;
        }

        if phdr.vaddr + load_addr + phdr.memsz > max_end {
            max_end = phdr.vaddr + load_addr + phdr.memsz;
        }
    }

    // No kernel-side RELA relocation. musl's rcrt1.o self-relocates static PIE
    // binaries at _start, and ld-musl relocates dynamic binaries at startup.
    // Applying relocations here would double-relocate and corrupt the image.

    // PHDR is within a PT_LOAD segment — compute its user-space VA.
    let mut phdr_user = 0u64;
    for i in 0..phnum {
        let phdr = unsafe {
            let p = data.as_ptr().add(phoff + i * phentsize) as *const Elf64ProgramHeader;
            &*p
        };
        if phdr.type_ == PT_LOAD
            && hdr.phoff >= phdr.offset
            && hdr.phoff < phdr.offset + phdr.filesz
        {
            phdr_user = load_addr + phdr.vaddr + (hdr.phoff - phdr.offset);
            break;
        }
    }

    // Allocate user stack at USER_STACK_TOP (only when creating new PML4)
    if existing_pml4.is_none() {
        let stack_start = USER_STACK_TOP - (USER_STACK_PAGES as u64 * 4096);
        let mut addr = stack_start;
        while addr < USER_STACK_TOP {
            let phys = match alloc_page() {
                Some(p) => p,
                None => return Err("OOM for stack"),
            };
            unsafe { core::ptr::write_bytes(phys as *mut u8, 0, 4096); }
            let flags = PTE_PRESENT | PTE_WRITABLE | PTE_USER | PTE_NO_EXECUTE;
            map_page_into(pml4, addr, phys, flags)?;
            addr += 4096;
        }
    }

    let entry = hdr.entry + load_addr;

    // Set up initial stack (only when creating new PML4)
    if existing_pml4.is_none() {
        let last_stack_vaddr = USER_STACK_TOP - 8;
        let last_stack_phys = {
            let vpn3 = ((last_stack_vaddr) >> 12) & 0x1FF;
            let vpn2 = ((last_stack_vaddr) >> 21) & 0x1FF;
            let vpn1 = ((last_stack_vaddr) >> 30) & 0x1FF;
            let vpn0 = ((last_stack_vaddr) >> 39) & 0x1FF;
            let pml4 = pml4 as *const crate::paging::PageTable;
            let pml4e = unsafe { (*pml4).0[vpn0 as usize] };
            if pml4e & PTE_PRESENT == 0 { return Err("stack PTE not found"); }
            let pdpt = (pml4e & PTE_ADDR_MASK) as *const crate::paging::PageTable;
            let pdpte = unsafe { (*pdpt).0[vpn1 as usize] };
            if pdpte & PTE_PRESENT == 0 { return Err("stack PTE not found"); }
            let pd = (pdpte & PTE_ADDR_MASK) as *const crate::paging::PageTable;
            let pde = unsafe { (*pd).0[vpn2 as usize] };
            if pde & PTE_PRESENT == 0 { return Err("stack PTE not found"); }
            let pt = (pde & PTE_ADDR_MASK) as *const crate::paging::PageTable;
            let pte = unsafe { (*pt).0[vpn3 as usize] };
            if pte & PTE_PRESENT == 0 { return Err("stack PTE not found"); }
            pte & PTE_ADDR_MASK
        };
        let page_off = last_stack_vaddr & 0xFFF;
        unsafe {
            let phys = last_stack_phys + page_off;
            crate::serial::write_str("  stack: last_stack_vaddr=0x");
            crate::serial::write_hex(last_stack_vaddr);
            crate::serial::write_str(" phys=0x");
            crate::serial::write_hex(phys);
            crate::serial::write_str("\n");
            core::ptr::write((phys - 8) as *mut u64, 0);
            core::ptr::write(phys as *mut u64, 0);
        }
    }

    Ok(ElfLoadInfo {
        entry,
        pml4,
        stack_top: USER_STACK_TOP - 16,
        is_dynamic,
        interp_path,
        interp_path_len,
        phdr_user,
        phnum: phnum as u16,
        phentsize: phentsize as u16,
        brk_base: page_align_up(max_end),
    })
}
