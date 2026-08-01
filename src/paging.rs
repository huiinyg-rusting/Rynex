use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering, AtomicBool};

pub const PAGE_SIZE_4K: u64 = 4096;
pub const PAGE_SIZE_2M: u64 = 2 * 1024 * 1024;
pub const PAGE_SIZE_1G: u64 = 1024 * 1024 * 1024;

pub const PTE_PRESENT: u64 = 1 << 0;

// 调试开关
static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);
pub const PTE_WRITABLE: u64 = 1 << 1;
pub const PTE_USER: u64 = 1 << 2;
pub const PTE_WRITE_THROUGH: u64 = 1 << 3;
pub const PTE_CACHE_DISABLE: u64 = 1 << 4;
pub const PTE_ACCESSED: u64 = 1 << 5;
pub const PTE_DIRTY: u64 = 1 << 6;
pub const PTE_HUGE: u64 = 1 << 7;
pub const PTE_GLOBAL: u64 = 1 << 8;
pub const PTE_NO_EXECUTE: u64 = 1 << 63;
pub const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

pub static KERNEL_PML4: AtomicU64 = AtomicU64::new(0);

#[repr(C, align(4096))]
pub struct PageTable(pub [u64; 512]);

impl PageTable {
    fn get(&self, idx: usize) -> u64 {
        self.0[idx]
    }

    fn set(&mut self, idx: usize, val: u64) {
        self.0[idx] = val;
    }

    fn clear(&mut self) {
        self.0 = [0; 512];
    }
}

pub struct PageTableManager {
    kernel_pml4: u64,
}

impl PageTableManager {
    const fn new() -> Self {
        PageTableManager { kernel_pml4: 0 }
    }

    fn alloc_page_table(&mut self) -> Option<u64> {
        let alloc = unsafe { &mut *crate::memory::allocator() };
        alloc.alloc(0).map(|addr| {
            unsafe { ptr::write_bytes(addr as *mut u8, 0, 4096); }
            addr
        })
    }

    fn get_pml4(&self) -> &PageTable {
        unsafe { &*(self.kernel_pml4 as *const PageTable) }
    }

    fn get_pml4_mut(&mut self) -> &mut PageTable {
        unsafe { &mut *(self.kernel_pml4 as *mut PageTable) }
    }

    fn walk_create(&mut self, virt: u64) -> Option<*mut PageTable> {
        let vpn = [
            ((virt >> 39) & 0x1FF) as usize,
            ((virt >> 30) & 0x1FF) as usize,
            ((virt >> 21) & 0x1FF) as usize,
        ];

        let pml4 = self.kernel_pml4 as *mut PageTable;
        let pml4e = unsafe { (*pml4).0[vpn[0]] };
        let pdpt = if pml4e & PTE_PRESENT != 0 {
            (pml4e & PTE_ADDR_MASK) as *mut PageTable
        } else {
            let new_pt = self.alloc_page_table()?;
            let pml4e = new_pt | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
            unsafe { (*pml4).0[vpn[0]] = pml4e; }
            new_pt as *mut PageTable
        };

        let pdpte = unsafe { (*pdpt).0[vpn[1]] };
        let pd = if pdpte & PTE_PRESENT != 0 {
            (pdpte & PTE_ADDR_MASK) as *mut PageTable
        } else {
            let new_pt = self.alloc_page_table()?;
            let pdpte = new_pt | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
            unsafe { (*pdpt).0[vpn[1]] = pdpte; }
            new_pt as *mut PageTable
        };

        Some(pd)
    }

    pub fn map_into(pml4: u64, virt: u64, phys: u64, flags: u64) -> Result<(), &'static str> {
        let vpn = [
            ((virt >> 39) & 0x1FF) as usize,
            ((virt >> 30) & 0x1FF) as usize,
            ((virt >> 21) & 0x1FF) as usize,
            ((virt >> 12) & 0x1FF) as usize,
        ];

        let pml4e = unsafe { (*(pml4 as *mut PageTable)).0[vpn[0]] };
        let pdpt: *mut PageTable = if pml4e & PTE_PRESENT != 0 {
            (pml4e & PTE_ADDR_MASK) as *mut PageTable
        } else {
            let new_pt = Self::alloc_page()?;
            unsafe { core::ptr::write_bytes(new_pt as *mut u8, 0, 4096); }
            unsafe { (*(pml4 as *mut PageTable)).0[vpn[0]] = new_pt | PTE_PRESENT | PTE_WRITABLE | PTE_USER; }
            new_pt as *mut PageTable
        };

        let pdpte = unsafe { (*pdpt).0[vpn[1]] };
        let pd: *mut PageTable = if pdpte & PTE_PRESENT != 0 && pdpte & PTE_HUGE == 0 {
            (pdpte & PTE_ADDR_MASK) as *mut PageTable
        } else {
            let new_pd = Self::alloc_page()?;
            unsafe { core::ptr::write_bytes(new_pd as *mut u8, 0, 4096); }
            if pdpte & PTE_HUGE != 0 {
                let gb_base = pdpte & (0xFFFFFFFFFF << 30);
                let gb_flags = ((pdpte & !PTE_ADDR_MASK) | PTE_HUGE) & !PTE_USER;
                let pd_arr = unsafe { &mut *(new_pd as *mut PageTable) };
                for i in 0..512u64 {
                    pd_arr.0[i as usize] = (gb_base + i * 0x200000) | gb_flags;
                }
            }
            unsafe { (*pdpt).0[vpn[1]] = new_pd | PTE_PRESENT | PTE_WRITABLE | PTE_USER; }
            new_pd as *mut PageTable
        };

        let pde = unsafe { (*pd).0[vpn[2]] };
        let pt: *mut PageTable = if pde & PTE_PRESENT != 0 && pde & PTE_HUGE == 0 {
            (pde & PTE_ADDR_MASK) as *mut PageTable
        } else {
            let new_pt = Self::alloc_page()?;
            unsafe { core::ptr::write_bytes(new_pt as *mut u8, 0, 4096); }
            // If we are splitting a 2MB huge page, preserve the existing mapping
            // by filling the new PT with the huge page's physical addresses.
            if pde & PTE_HUGE != 0 {
                let huge_base = pde & (0xFFFFFFFFFF << 21);
                // Clear USER so identity sub-pages aren't reachable from user mode.
                let huge_flags = (pde & 0x7F) & !PTE_USER;
                let pt_arr = unsafe { &mut *(new_pt as *mut PageTable) };
                for i in 0..512u64 {
                    pt_arr.0[i as usize] = (huge_base + i * 4096) | huge_flags;
                }
            }
            let pde_val = new_pt | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
            unsafe { (*pd).0[vpn[2]] = pde_val; }
            new_pt as *mut PageTable
        };

        unsafe { (*pt).0[vpn[3]] = phys | flags | PTE_PRESENT; }
        Ok(())
    }

    pub fn resolve_phys(pml4: u64, virt: u64) -> Option<u64> {
        let vpn = [
            ((virt >> 39) & 0x1FF) as usize,
            ((virt >> 30) & 0x1FF) as usize,
            ((virt >> 21) & 0x1FF) as usize,
            ((virt >> 12) & 0x1FF) as usize,
        ];
        unsafe {
            let pml4e = (*(pml4 as *const PageTable)).0[vpn[0]];
            if pml4e & PTE_PRESENT == 0 { return None; }
            let pdpt = (pml4e & PTE_ADDR_MASK) as *const PageTable;
            let pdpte = (*pdpt).0[vpn[1]];
            if pdpte & PTE_PRESENT == 0 { return None; }
            let pd = (pdpte & PTE_ADDR_MASK) as *const PageTable;
            let pde = (*pd).0[vpn[2]];
            if pde & PTE_PRESENT == 0 { return None; }
            if pde & PTE_HUGE != 0 {
                return Some((pde & PTE_ADDR_MASK) | (virt & (PAGE_SIZE_2M - 1)));
            }
            let pt = (pde & PTE_ADDR_MASK) as *const PageTable;
            let pte = (*pt).0[vpn[3]];
            if pte & PTE_PRESENT == 0 { return None; }
            Some((pte & PTE_ADDR_MASK) | (virt & (PAGE_SIZE_4K - 1)))
        }
    }

    fn alloc_page() -> Result<u64, &'static str> {
        let alloc = unsafe { &mut *crate::memory::allocator() };
        alloc.alloc(0).ok_or("OOM")
    }

    // Map a page in kernel page tables (without PTE_USER on intermediate tables)
    pub fn map_kernel_page(virt: u64, phys: u64, flags: u64) -> Result<(), &'static str> {
        let vpn = [
            ((virt >> 39) & 0x1FF) as usize,
            ((virt >> 30) & 0x1FF) as usize,
            ((virt >> 21) & 0x1FF) as usize,
            ((virt >> 12) & 0x1FF) as usize,
        ];

        let pml4 = KERNEL_PML4.load(Ordering::Relaxed) as *mut PageTable;
        if pml4.is_null() {
            return Err("kernel PML4 not set");
        }

        // PML4
        let pml4e = unsafe { (*pml4).0[vpn[0]] };
        let pdpt = if pml4e & PTE_PRESENT != 0 {
            (pml4e & PTE_ADDR_MASK) as *mut PageTable
        } else {
            let alloc = unsafe { &mut *crate::memory::allocator() };
            let new_pt = alloc.alloc(0).ok_or("OOM: PDPT")?;
            unsafe { core::ptr::write_bytes(new_pt as *mut u8, 0, 4096); }
            let pml4e_val = new_pt | PTE_PRESENT | PTE_WRITABLE;
            unsafe { (*pml4).0[vpn[0]] = pml4e_val; }
            new_pt as *mut PageTable
        };

        // PDPT
        let pdpte = unsafe { (*pdpt).0[vpn[1]] };
        let pd = if pdpte & PTE_PRESENT != 0 {
            (pdpte & PTE_ADDR_MASK) as *mut PageTable
        } else {
            let alloc = unsafe { &mut *crate::memory::allocator() };
            let new_pt = alloc.alloc(0).ok_or("OOM: PD")?;
            unsafe { core::ptr::write_bytes(new_pt as *mut u8, 0, 4096); }
            let pdpte_val = new_pt | PTE_PRESENT | PTE_WRITABLE;
            unsafe { (*pdpt).0[vpn[1]] = pdpte_val; }
            new_pt as *mut PageTable
        };

        // PD
        let pde = unsafe { (*pd).0[vpn[2]] };
        let pt = if pde & PTE_PRESENT != 0 {
            (pde & PTE_ADDR_MASK) as *mut PageTable
        } else {
            let alloc = unsafe { &mut *crate::memory::allocator() };
            let new_pt = alloc.alloc(0).ok_or("OOM: PT")?;
            unsafe { core::ptr::write_bytes(new_pt as *mut u8, 0, 4096); }
            let pde_val = new_pt | PTE_PRESENT | PTE_WRITABLE;
            unsafe { (*pd).0[vpn[2]] = pde_val; }
            new_pt as *mut PageTable
        };

        // PT
        let pte = unsafe { (*pt).0[vpn[3]] };
        if pte & PTE_PRESENT != 0 {
            return Err("already mapped");
        }
        unsafe { (*pt).0[vpn[3]] = phys | flags | PTE_PRESENT; }
        Ok(())
    }

    pub fn map_page(&mut self, virt: u64, phys: u64, flags: u64) -> Result<(), &'static str> {
        let vpn = [
            ((virt >> 39) & 0x1FF) as usize,
            ((virt >> 30) & 0x1FF) as usize,
            ((virt >> 21) & 0x1FF) as usize,
            ((virt >> 12) & 0x1FF) as usize,
        ];

        let pd = self.walk_create(virt).ok_or("OOM: no PD")?;

        let pde = unsafe { (*pd).0[vpn[2]] };
        let pt = if pde & PTE_PRESENT != 0 {
            (pde & PTE_ADDR_MASK) as *mut PageTable
        } else {
            let new_pt = self.alloc_page_table().ok_or("OOM: no PT")?;
            let pde = new_pt | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
            unsafe { (*pd).0[vpn[2]] = pde; }
            new_pt as *mut PageTable
        };

        let pte = unsafe { (*pt).0[vpn[3]] };
        if pte & PTE_PRESENT != 0 {
            return Err("page already mapped");
        }
        unsafe { (*pt).0[vpn[3]] = phys | flags | PTE_PRESENT; }

        Ok(())
    }

    pub fn map_2m(&mut self, virt: u64, phys: u64, flags: u64) -> Result<(), &'static str> {
        let vpn = [
            ((virt >> 39) & 0x1FF) as usize,
            ((virt >> 30) & 0x1FF) as usize,
            ((virt >> 21) & 0x1FF) as usize,
        ];

        let pd = self.walk_create(virt).ok_or("OOM: no PD")?;
        let pde = unsafe { (*pd).0[vpn[2]] };
        if pde & PTE_PRESENT != 0 {
            return Err("2M page already mapped");
        }
        unsafe { (*pd).0[vpn[2]] = phys | flags | PTE_PRESENT | PTE_HUGE; }
        Ok(())
    }

    pub fn unmap_page(&mut self, virt: u64) -> Result<(), &'static str> {
        let vpn = [
            ((virt >> 39) & 0x1FF) as usize,
            ((virt >> 30) & 0x1FF) as usize,
            ((virt >> 21) & 0x1FF) as usize,
            ((virt >> 12) & 0x1FF) as usize,
        ];

        let pml4 = self.get_pml4_mut();
        let pml4e = pml4.get(vpn[0]);
        if pml4e & PTE_PRESENT == 0 { return Err("not mapped"); }
        let pdpt = unsafe { &mut *((pml4e & PTE_ADDR_MASK) as *mut PageTable) };

        let pdpte = pdpt.get(vpn[1]);
        if pdpte & PTE_PRESENT == 0 { return Err("not mapped"); }
        let pd = unsafe { &mut *((pdpte & PTE_ADDR_MASK) as *mut PageTable) };

        let pde = pd.get(vpn[2]);
        if pde & PTE_PRESENT == 0 { return Err("not mapped"); }
        if pde & PTE_HUGE != 0 { return Err("2M page - use unmap_2m"); }
        let pt = unsafe { &mut *((pde & PTE_ADDR_MASK) as *mut PageTable) };

        let pte = pt.get(vpn[3]);
        if pte & PTE_PRESENT == 0 { return Err("not mapped"); }
        pt.set(vpn[3], 0);

        Ok(())
    }

    pub fn unmap_2m(&mut self, virt: u64) -> Result<(), &'static str> {
        let vpn = [
            ((virt >> 39) & 0x1FF) as usize,
            ((virt >> 30) & 0x1FF) as usize,
            ((virt >> 21) & 0x1FF) as usize,
        ];

        let pml4 = self.get_pml4_mut();
        let pml4e = pml4.get(vpn[0]);
        if pml4e & PTE_PRESENT == 0 { return Err("not mapped"); }
        let pdpt = unsafe { &mut *((pml4e & PTE_ADDR_MASK) as *mut PageTable) };

        let pdpte = pdpt.get(vpn[1]);
        if pdpte & PTE_PRESENT == 0 { return Err("not mapped"); }
        let pd = unsafe { &mut *((pdpte & PTE_ADDR_MASK) as *mut PageTable) };

        let pde = pd.get(vpn[2]);
        if pde & PTE_PRESENT == 0 || pde & PTE_HUGE == 0 { return Err("not a 2M page"); }
        pd.set(vpn[2], 0);
        Ok(())
    }

    pub fn translate(&self, virt: u64) -> Option<u64> {
        let vpn = [
            ((virt >> 39) & 0x1FF) as usize,
            ((virt >> 30) & 0x1FF) as usize,
            ((virt >> 21) & 0x1FF) as usize,
            ((virt >> 12) & 0x1FF) as usize,
        ];

        let pml4 = self.get_pml4();
        let pml4e = pml4.get(vpn[0]);
        if pml4e & PTE_PRESENT == 0 { return None; }

        let pdpt = unsafe { &*((pml4e & PTE_ADDR_MASK) as *const PageTable) };
        let pdpte = pdpt.get(vpn[1]);
        if pdpte & PTE_PRESENT == 0 { return None; }

        let pd = unsafe { &*((pdpte & PTE_ADDR_MASK) as *const PageTable) };
        let pde = pd.get(vpn[2]);
        if pde & PTE_PRESENT == 0 { return None; }

        if pde & PTE_HUGE != 0 {
            return Some((pde & PTE_ADDR_MASK) | (virt & (PAGE_SIZE_2M - 1)));
        }

        let pt = unsafe { &*((pde & PTE_ADDR_MASK) as *const PageTable) };
        let pte = pt.get(vpn[3]);
        if pte & PTE_PRESENT == 0 { return None; }

        Some((pte & PTE_ADDR_MASK) | (virt & (PAGE_SIZE_4K - 1)))
    }

    pub fn clone_kernel(&mut self) -> Option<u64> {
        let new_pml4 = self.alloc_page_table()?;
        let new_pt = unsafe { &mut *(new_pml4 as *mut PageTable) };
        let old_pt = self.get_pml4();
        new_pt.0 = old_pt.0;
        Some(new_pml4)
    }

    pub fn switch_to(&self, pml4: u64) {
        unsafe {
            core::arch::asm!("mov cr3, {}", in(reg) pml4, options(nostack, nomem));
        }
    }

    pub fn kernel_pml4(&self) -> u64 {
        self.kernel_pml4
    }
}

pub fn kernel_pml4() -> u64 {
    KERNEL_PML4.load(Ordering::SeqCst)
}

static mut PT_MGR: PageTableManager = PageTableManager::new();

pub fn pt_mgr() -> &'static mut PageTableManager {
    unsafe { &mut PT_MGR }
}

pub const KERNEL_BASE: u64 = 0xFFFF_8000_0000_0000;
pub const USER_BASE: u64 = 0x0000_0000_0000_0000;
pub const USER_STACK_TOP: u64 = 0x0000_7FFF_FFFF_F000;

pub fn default_flags(user: bool) -> u64 {
    let mut f = PTE_WRITABLE | PTE_ACCESSED | PTE_DIRTY;
    if user {
        f |= PTE_USER;
    }
    f
}

pub fn init() {
    unsafe {
        let alloc = &mut *crate::memory::allocator();
        PT_MGR.kernel_pml4 = alloc.alloc(0).unwrap();
        KERNEL_PML4.store(PT_MGR.kernel_pml4, Ordering::SeqCst);
        let pml4 = unsafe { &mut *(PT_MGR.kernel_pml4 as *mut PageTable) };
        pml4.clear();

        // Preserve the bootloader identity mapping (0-1GB) so the kernel
        // and all buddy-allocated pages stay accessible after we switch cr3.
        let old_pml4: u64;
        core::arch::asm!("mov {}, cr3", out(reg) old_pml4);
        let old_pt = &*(old_pml4 as *const PageTable);
        pml4.0 = old_pt.0;
    }
    crate::serial::write_str("PAGING: init done\n");
    // Dump first few PML4 entries  
    let pml4_addr = kernel_pml4();
    let pt = unsafe { &*(pml4_addr as *const PageTable) };
    for i in 0..4 {
        let e = pt.0[i];
        if e & PTE_PRESENT != 0 {
            crate::serial::write_str("  PML4[");
            crate::serial::write_dec(i as u64);
            crate::serial::write_str("]=");
            crate::serial::write_hex(e);
            if e & PTE_HUGE != 0 { crate::serial::write_str(" [HUGEPAGE]"); }
            crate::serial::write_str("\n");
        }
    }
    // Dump PDPT[0] entries
    if pt.0[0] & PTE_PRESENT != 0 {
        let pdpt = unsafe { &*((pt.0[0] & PTE_ADDR_MASK) as *const PageTable) };
        for i in 0..4 {
            let e = pdpt.0[i];
            if e & PTE_PRESENT != 0 {
                crate::serial::write_str("    PDPT[");
                crate::serial::write_dec(i as u64);
                crate::serial::write_str("]=");
                crate::serial::write_hex(e);
                if e & PTE_HUGE != 0 { crate::serial::write_str(" [1G HUGEPAGE]"); }
                crate::serial::write_str("\n");
            }
        }
    }
}

pub fn get_pte_in(pml4: u64, virt: u64) -> Option<&'static mut u64> {
    let vpn = [
        ((virt >> 39) & 0x1FF) as usize,
        ((virt >> 30) & 0x1FF) as usize,
        ((virt >> 21) & 0x1FF) as usize,
        ((virt >> 12) & 0x1FF) as usize,
    ];

    let pml4e = unsafe { (*(pml4 as *const PageTable)).0[vpn[0]] };
    if pml4e & PTE_PRESENT == 0 { return None; }

    let pdpt = (pml4e & PTE_ADDR_MASK) as *const PageTable;
    let pdpte = unsafe { (*pdpt).0[vpn[1]] };
    if pdpte & PTE_PRESENT == 0 { return None; }

    let pd = (pdpte & PTE_ADDR_MASK) as *const PageTable;
    let pde = unsafe { (*pd).0[vpn[2]] };
    if pde & PTE_PRESENT == 0 { return None; }
    if pde & PTE_HUGE != 0 { return None; }

    let pt = (pde & PTE_ADDR_MASK) as *const PageTable;
    let pte = unsafe { (*pt).0[vpn[3]] };
    if pte & PTE_PRESENT == 0 { return None; }

    let pt_mut = (pde & PTE_ADDR_MASK) as *mut PageTable;
    Some(unsafe { &mut (*pt_mut).0[vpn[3]] })
}

pub fn get_pte(virt: u64) -> Option<&'static mut u64> {
    let kernel_pml4 = KERNEL_PML4.load(Ordering::SeqCst);
    get_pte_in(kernel_pml4, virt)
}

pub fn is_user_addr(addr: u64) -> bool {
    addr < 0x0000_8000_0000_0000
}

/// Copy user page mappings from `src_pml4` to `dst_pml4`
pub fn merge_user_pml4(src_pml4: u64, dst_pml4: u64) -> Result<(), &'static str> {
    let alloc = unsafe { &mut *crate::memory::allocator() };
    let src = unsafe { &*(src_pml4 as *const PageTable) };
    let dst = unsafe { &mut *(dst_pml4 as *mut PageTable) };
    for pml4_idx in 0..256 {
        let src_pml4e = src.0[pml4_idx];
        if src_pml4e & PTE_PRESENT == 0 { continue; }
        let dst_pml4e = dst.0[pml4_idx];
        if dst_pml4e & PTE_PRESENT == 0 {
            dst.0[pml4_idx] = src_pml4e;
            continue;
        }
        // Both present — merge PDPT entries
        let src_pdpt = (src_pml4e & PTE_ADDR_MASK) as *const PageTable;
        let dst_pdpt = (dst_pml4e & PTE_ADDR_MASK) as *mut PageTable;
        let src_pdpt_ref = unsafe { &*src_pdpt };
        let dst_pdpt_ref = unsafe { &mut *dst_pdpt };
        for pdpt_idx in 0..512 {
            let src_pdpte = src_pdpt_ref.0[pdpt_idx];
            if src_pdpte & PTE_PRESENT == 0 { continue; }
            let dst_pdpte = dst_pdpt_ref.0[pdpt_idx];
            if dst_pdpte & PTE_PRESENT == 0 {
                dst_pdpt_ref.0[pdpt_idx] = src_pdpte;
                continue;
            }
            // Both present — merge PD entries
            let src_pd = (src_pdpte & PTE_ADDR_MASK) as *const PageTable;
            let dst_pd = (dst_pdpte & PTE_ADDR_MASK) as *mut PageTable;
            let src_pd_ref = unsafe { &*src_pd };
            let dst_pd_ref = unsafe { &mut *dst_pd };
            for pd_idx in 0..512 {
                let src_pde = src_pd_ref.0[pd_idx];
                if src_pde & PTE_PRESENT == 0 { continue; }
                let dst_pde = dst_pd_ref.0[pd_idx];
                if dst_pde & PTE_PRESENT == 0 {
                    dst_pd_ref.0[pd_idx] = src_pde;
                    continue;
                }
                if src_pde & PTE_HUGE != 0 || dst_pde & PTE_HUGE != 0 {
                    continue;
                }
                // Both present — merge PT entries
                let src_pt = (src_pde & PTE_ADDR_MASK) as *const PageTable;
                let dst_pt = (dst_pde & PTE_ADDR_MASK) as *mut PageTable;
                let src_pt_ref = unsafe { &*src_pt };
                let dst_pt_ref = unsafe { &mut *dst_pt };
                for pt_idx in 0..512 {
                    let src_pte = src_pt_ref.0[pt_idx];
                    if src_pte & PTE_PRESENT == 0 { continue; }
                    if dst_pt_ref.0[pt_idx] & PTE_PRESENT == 0 {
                        dst_pt_ref.0[pt_idx] = src_pte;
                    }
                }
            }
        }
    }
    Ok(())
}

// Clone the current process's PML4 for fork.
// Creates a new PML4 with private (deep-copied) user page tables.
// User 4K pages are shared with COW (read-only in child, read-only in parent too).
// 2M/1G huge pages (kernel identity map) stay shared writable.
pub fn cow_fork_pml4(old_pml4: u64) -> Option<u64> {
    let alloc = unsafe { &mut *crate::memory::allocator() };
    let new_pml4 = alloc.alloc(0)?;
    unsafe { core::ptr::write_bytes(new_pml4 as *mut u8, 0, 4096); }

    let old_table = unsafe { &*(old_pml4 as *const PageTable) };
    let new_table = unsafe { &mut *(new_pml4 as *mut PageTable) };

    // Copy kernel PML4 entries (indices 256-511)
    let kernel_pml4_val = KERNEL_PML4.load(Ordering::Relaxed);
    let kernel_pt = unsafe { &*(kernel_pml4_val as *const PageTable) };
    for i in 256..512 {
        new_table.0[i] = kernel_pt.0[i];
    }

    // Walk old PML4 user entries (0..256) to deep-copy page tables.
    // PML4[255] may hold user stack (0x7FFFFFFFBxxx), so we must clone all user entries.
    for pml4_idx in 0..256 {
        let pml4e = old_table.0[pml4_idx];
        if pml4e & PTE_PRESENT == 0 { continue; }

        let old_pdpt_phys = pml4e & PTE_ADDR_MASK;
        let old_pdpt = unsafe { &*(old_pdpt_phys as *const PageTable) };

        // Deep-copy the PDPT
        let new_pdpt_phys = alloc.alloc(0)?;
        unsafe { core::ptr::write_bytes(new_pdpt_phys as *mut u8, 0, 4096); }
        let new_pdpt = unsafe { &mut *(new_pdpt_phys as *mut PageTable) };

        for pdpt_idx in 0..512 {
            let pdpte = old_pdpt.0[pdpt_idx];
            if pdpte & PTE_PRESENT == 0 { continue; }

            if pdpte & PTE_HUGE != 0 {
                // 1G page (kernel identity) — keep writable, shallow copy
                new_pdpt.0[pdpt_idx] = pdpte;
                continue;
            }

            let old_pd_phys = pdpte & PTE_ADDR_MASK;
            let old_pd = unsafe { &*(old_pd_phys as *const PageTable) };

            // Deep-copy the PD
            let new_pd_phys = alloc.alloc(0)?;
            unsafe { core::ptr::write_bytes(new_pd_phys as *mut u8, 0, 4096); }
            let new_pd = unsafe { &mut *(new_pd_phys as *mut PageTable) };

            for pd_idx in 0..512 {
                let pde = old_pd.0[pd_idx];
                if pde & PTE_PRESENT == 0 { continue; }

                if pde & PTE_HUGE != 0 {
                    // 2M page (kernel identity) — keep writable, shallow copy
                    new_pd.0[pd_idx] = pde;
                    continue;
                }

                // 4K page — deep-copy PT
                let old_pt_phys = pde & PTE_ADDR_MASK;
                let old_pt = unsafe { &*(old_pt_phys as *const PageTable) };

                let new_pt_phys = alloc.alloc(0)?;
                unsafe { core::ptr::write_bytes(new_pt_phys as *mut u8, 0, 4096); }
                let new_pt = unsafe { &mut *(new_pt_phys as *mut PageTable) };

                for pt_idx in 0..512 {
                    let pte = old_pt.0[pt_idx];
                    if pte & PTE_PRESENT == 0 { continue; }

                    // COW: share physical page, child gets read-only
                    let cow_flags = pte & !(PTE_ADDR_MASK | PTE_WRITABLE);
                    new_pt.0[pt_idx] = (pte & PTE_ADDR_MASK) | cow_flags;

                    // Parent: also remove writable for COW
                    let src_pt = unsafe { &mut *(old_pt_phys as *mut PageTable) };
                    src_pt.0[pt_idx] = pte & !PTE_WRITABLE;
                }

                let pde_flags = pde & !PTE_ADDR_MASK;
                new_pd.0[pd_idx] = new_pt_phys | pde_flags;
            }

            let pdpt_flags = pdpte & !PTE_ADDR_MASK;
            new_pdpt.0[pdpt_idx] = new_pd_phys | pdpt_flags;
        }

        let pml4e_flags = pml4e & !PTE_ADDR_MASK;
        new_table.0[pml4_idx] = new_pdpt_phys | pml4e_flags;
    }

    // Flush TLB for old PML4 since we modified its PTEs
    unsafe {
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack));
        core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, nomem));
    }

    Some(new_pml4)
}

pub fn cow_remap_in(pml4: u64, virt: u64) -> bool {
    let pte = match get_pte_in(pml4, virt) {
        Some(p) => p,
        None => return false,
    };

    if *pte & PTE_PRESENT == 0 { return false; }
    if *pte & PTE_WRITABLE != 0 { return false; }

    let old_phys = *pte & PTE_ADDR_MASK;
    let flags = *pte & !PTE_ADDR_MASK;

    let alloc = unsafe { &mut *crate::memory::allocator() };
    // Reserve old meta phys page so buddy never reuses it
    if virt == 0x500000 {
        alloc.reserve(old_phys);
        if DEBUG_ENABLED.load(Ordering::Relaxed) {
            crate::serial::write_str("  COW: reserved old meta phys=0x");
            crate::serial::write_hex(old_phys);
            crate::serial::write_str("\n");
        }
    }

    let new_phys = match alloc.alloc(0) {
        Some(p) => p,
        None => return false,
    };

    // Copy old page content
    unsafe {
        core::ptr::copy_nonoverlapping(
            old_phys as *const u8,
            new_phys as *mut u8,
            4096,
        );
    }

    // Reserve meta-area phys page so buddy never reuses it
    if virt == 0x500000 {
        alloc.reserve(new_phys);
        if DEBUG_ENABLED.load(Ordering::Relaxed) {
            crate::serial::write_str("  COW: reserved meta phys=0x");
            crate::serial::write_hex(new_phys);
            crate::serial::write_str("\n");
        }
    }

    // Update PTE: new phys + writable
    *pte = new_phys | flags | PTE_WRITABLE;
    unsafe { core::arch::asm!("invlpg [{}]", in(reg) virt, options(nostack, preserves_flags)); }
    true
}

pub fn cow_remap(virt: u64) -> bool {
    cow_remap_in(KERNEL_PML4.load(Ordering::SeqCst), virt)
}

pub fn page_fault_resolve(cr2: u64, code_bits: u64, cpl: u64) -> bool {
    let is_write = code_bits & 2 != 0;
    let is_present = code_bits & 1 != 0;

    // Get the faulting task's PML4
    let task_pml4 = crate::task::current_task_pml4();
    if task_pml4 == 0 {
        return false;
    }

    // Write to a read-only page → COW (handle both user and kernel mode,
    // since CR0.WP=1 prevents kernel writes to read-only pages too)
    if is_write && is_present {
        if cow_remap_in(task_pml4, cr2) {
            if DEBUG_ENABLED.load(Ordering::Relaxed) {
                crate::serial::write_str("  COW: copied page for 0x");
                crate::serial::write_hex(cr2);
                crate::serial::write_str("\n");
            }
            return true;
        }
    }

    // Page not present → demand paging (mmap'd/brk pages)
    if cpl == 3 && !is_present {
        // Check if this address is in an mmap'd region
        if crate::task::handle_demand_page(task_pml4, cr2) {
            return true;
        }
        return false;
    }

    false
}

pub fn test() {
    let mgr = pt_mgr();

    let alloc = unsafe { &mut *crate::memory::allocator() };
    let p = alloc.alloc(0).expect("OOM");
    mgr.map_page(0x4000_0000, p, PTE_PRESENT | PTE_WRITABLE).expect("map failed");

    let phys = mgr.translate(0x4000_0000).expect("translate failed");
    assert_eq!(phys, p);
    crate::serial::write_str("PAGING: map/translate 4K OK\n");

    let p2 = alloc.alloc(0).expect("OOM");
    mgr.map_2m(0x5000_0000, p2, PTE_PRESENT | PTE_WRITABLE).expect("map 2M failed");
    let phys2 = mgr.translate(0x5000_0000).expect("translate 2M failed");
    assert_eq!(phys2, p2);
    crate::serial::write_str("PAGING: map/translate 2M OK\n");

    mgr.unmap_page(0x4000_0000).expect("unmap failed");
    assert!(mgr.translate(0x4000_0000).is_none());
    crate::serial::write_str("PAGING: unmap 4K OK\n");

    mgr.unmap_2m(0x5000_0000).expect("unmap 2M failed");
    assert!(mgr.translate(0x5000_0000).is_none());
    crate::serial::write_str("PAGING: unmap 2M OK\n");

    let cloned = mgr.clone_kernel().expect("clone failed");
    crate::serial::write_str("PAGING: clone_kernel OK\n");
    mgr.switch_to(cloned);
    crate::serial::write_str("PAGING: switch_to OK\n");
    mgr.switch_to(mgr.kernel_pml4());
    crate::serial::write_str("PAGING: switch back OK\n");

    crate::serial::write_str("PAGING: all tests passed\n");
}