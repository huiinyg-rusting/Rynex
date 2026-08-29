use x86_64::{
    PhysAddr, VirtAddr,
    structures::paging::{
        PageTable, OffsetPageTable, PhysFrame, FrameAllocator, Size4KiB,
        Mapper, Page, PageTableFlags as Flags, Translate,
    },
};

use crate::memory::BuddyAllocator;

unsafe impl FrameAllocator<Size4KiB> for BuddyAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        self.alloc(0).map(|addr| PhysFrame::containing_address(PhysAddr::new(addr)))
    }
}

pub fn mapper() -> OffsetPageTable<'static> {
    let pml4_addr = active_pml4_phys();
    let pml4 = unsafe { &mut *(pml4_addr as *mut PageTable) };
    unsafe { OffsetPageTable::new(pml4, VirtAddr::new(0)) }
}

pub fn active_pml4_phys() -> u64 {
    let cr3: u64;
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3); }
    cr3 & 0x000F_FFFF_FFFF_F000
}

pub fn switch_to(pml4: &PageTable) {
    let phys = pml4 as *const _ as u64;
    unsafe {
        core::arch::asm!("mov cr3, {}", in(reg) phys, options(nostack, nomem));
    }
}

pub fn flush_tlb(virt: Option<VirtAddr>) {
    match virt {
        Some(v) => unsafe {
            core::arch::asm!("invlpg [{}]", in(reg) v.as_u64(), options(nostack, nomem));
        },
        None => {
            let cr3: u64;
            unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3); }
            unsafe { core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, nomem)); }
        },
    }
}

pub fn init() {
    let alloc = crate::memory::allocator();
    let vaddr = VirtAddr::new(0x1_0000);
    let page = Page::<Size4KiB>::containing_address(vaddr);
    let paddr = PhysAddr::new(0x1_0000);
    let frame = PhysFrame::containing_address(paddr);

    let result = {
        let mut m = mapper();
        unsafe { m.map_to(page, frame, Flags::PRESENT | Flags::WRITABLE, alloc) }
    };

    match result {
        Ok(mf) => {
            mf.flush();
            let m = mapper();
            let t = m.translate(vaddr);
            use x86_64::structures::paging::mapper::TranslateResult;
            match t {
                TranslateResult::Mapped { frame, .. } => {
                    let paddr = match frame {
                        x86_64::structures::paging::mapper::MappedFrame::Size4KiB(f) => f.start_address(),
                        x86_64::structures::paging::mapper::MappedFrame::Size2MiB(f) => f.start_address(),
                        x86_64::structures::paging::mapper::MappedFrame::Size1GiB(f) => f.start_address(),
                    };
                    crate::serial::write_str("PAGING: translate OK, phys=");
                    crate::serial::write_dec(paddr.as_u64());
                    crate::serial::write_str("\n");
                }
                _ => {
                    crate::serial::write_str("PAGING: translate failed\n");
                }
            }
            crate::vga::write_str("PAGING: OK\n");
        }
        Err(_) => {
            crate::serial::write_str("PAGING: map_to failed\n");
        }
    }
}
