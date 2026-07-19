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
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

pub struct ElfLoadInfo {
    pub entry: u64,
    pub pml4: u64,
    pub stack_top: u64,
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

    // Clone kernel page tables for the new process
    let pml4 = match alloc_page() {
        Some(p) => p,
        None => return Err("OOM for PML4"),
    };
    let new_pt = unsafe { &mut *(pml4 as *mut crate::paging::PageTable) };
    let kernel_pml4 = KERNEL_PML4.load(core::sync::atomic::Ordering::SeqCst);
    let old_pt = unsafe { &*(kernel_pml4 as *const crate::paging::PageTable) };
    new_pt.0 = old_pt.0;

    // Highest mapped address (for stack placement)
    let mut max_end = 0u64;

    // Load each PT_LOAD segment
    for i in 0..phnum {
        let phdr = unsafe {
            let p = data.as_ptr().add(phoff + i * phentsize) as *const Elf64ProgramHeader;
            &*p
        };

        if phdr.type_ != PT_LOAD {
            continue;
        }

        if phdr.vaddr < 0x10000 {
            return Err("segment too low");
        }

        let seg_start = page_align_down(phdr.vaddr);
        let seg_end = page_align_up(phdr.vaddr + phdr.memsz);
        let offset_in_page = phdr.vaddr - seg_start;

        let flags = pt_flags(phdr.flags);

        serial::write_str("  PHDR: vaddr=0x");
        serial::write_hex(phdr.vaddr);
        serial::write_str(" memsz=0x");
        serial::write_hex(phdr.memsz);
        serial::write_str(" filesz=0x");
        serial::write_hex(phdr.filesz);
        serial::write_str(" flags=");
        serial::write_dec(phdr.flags as u64);
        serial::write_str("\n");

        // Map pages for this segment
        let mut addr = seg_start;
        while addr < seg_end {
            let phys = match alloc_page() {
                Some(p) => p,
                None => return Err("OOM for segment page"),
            };
            map_page_into(pml4, addr, phys, flags)?;

            // Copy file data or zero-fill
            let page_off = if addr == seg_start { offset_in_page } else { 0 };
            let copy_start = phdr.vaddr + page_off;
            let copy_size = if copy_start + phdr.filesz > addr + 4096 {
                addr + 4096 - copy_start
            } else {
                phdr.filesz.saturating_sub(copy_start - phdr.vaddr)
            };

            if copy_size > 0 {
                let file_off = (copy_start - phdr.vaddr) as usize;
                if (phdr.offset as usize + file_off + copy_size as usize) <= data.len() {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            data.as_ptr().add(phdr.offset as usize + file_off),
                            phys as *mut u8,
                            copy_size as usize,
                        );
                    }
                }
            }

            addr += 4096;
        }

        if phdr.vaddr + phdr.memsz > max_end {
            max_end = phdr.vaddr + phdr.memsz;
        }
    }

    // Allocate user stack at USER_STACK_TOP
    let stack_start = USER_STACK_TOP - (USER_STACK_PAGES as u64 * 4096);
    let mut addr = stack_start;
    while addr < USER_STACK_TOP {
        let phys = match alloc_page() {
            Some(p) => p,
            None => return Err("OOM for stack"),
        };
        // Clear stack page
        unsafe { core::ptr::write_bytes(phys as *mut u8, 0, 4096); }
        let flags = PTE_PRESENT | PTE_WRITABLE | PTE_USER | PTE_NO_EXECUTE;
        map_page_into(pml4, addr, phys, flags)?;
        addr += 4096;
    }

    let entry = hdr.entry;

    // Set up initial stack (x86_64 SysV ABI):
    //   RSP → argc (8 bytes) at USER_STACK_TOP - 16
    //         argv[0] = NULL  at USER_STACK_TOP - 8
    //   (16 bytes total, RSP is 16-byte aligned since USER_STACK_TOP % 16 == 0)

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

    // The last stack page's offset within the page
    let page_off = last_stack_vaddr & 0xFFF;
    unsafe {
        let phys = last_stack_phys + page_off;
        // phys maps to USER_STACK_TOP - 8; phys - 8 maps to USER_STACK_TOP - 16
        core::ptr::write((phys - 8) as *mut u64, 0);  // argc = 0 at USER_STACK_TOP - 16
        core::ptr::write(phys as *mut u64, 0);         // argv = NULL at USER_STACK_TOP - 8
    }

    serial::write_str("ELF: loaded entry=0x");
    serial::write_hex(entry);
    serial::write_str(" stack RSP=0x");
    serial::write_hex(USER_STACK_TOP - 16);
    serial::write_str("\n");

    Ok(ElfLoadInfo {
        entry,
        pml4,
        stack_top: USER_STACK_TOP - 16,
    })
}
