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

// ── COW reference counting ────────────────────────────────────────
// Each 4K user leaf shared between a parent and its fork children gets a
// refcount. A COW fault on a page with refcount > 0 copies the page (the
// faulting task drops one reference and owns a fresh private copy). A COW
// fault on a page with refcount == 0 just flips the PTE writable — the
// other owner(s) are gone, so copying would orphan the old physical page
// (leak). free_address_space drops one reference per shared leaf instead of
// freeing it; private leaves (refcount 0) are freed outright.
const MAX_REFC_PAGES: usize = 1 << 21; // up to 8 GiB of physical pages
static mut PAGE_REFC: [u8; MAX_REFC_PAGES] = [0; MAX_REFC_PAGES];

fn refc_idx(phys: u64) -> usize {
    (phys >> 12) as usize
}

fn refc_get(phys: u64) -> u8 {
    let i = refc_idx(phys);
    if i < MAX_REFC_PAGES {
        unsafe { PAGE_REFC[i] }
    } else {
        0
    }
}

fn refc_inc(phys: u64) {
    let i = refc_idx(phys);
    if i < MAX_REFC_PAGES {
        unsafe {
            PAGE_REFC[i] = PAGE_REFC[i].saturating_add(1);
        }
    }
}

fn refc_dec(phys: u64) {
    let i = refc_idx(phys);
    if i < MAX_REFC_PAGES {
        unsafe {
            if PAGE_REFC[i] > 0 {
                PAGE_REFC[i] -= 1;
            }
        }
    }
}

/// Record a new COW reference to a shared page at fork time, accounting for the
/// parent's pre-existing ownership. A page with refc==0 is exclusively owned by
/// the parent but its reference was never recorded (allocations don't bump the
/// COW refcount), so bump it to 2 (parent + child). Otherwise just add one.
fn fork_share_refc(phys: u64) {
    // The page is now referenced by this child; mark it used so that
    // free_address_space's guards don't misfire (FAS: BAD PDPT/PD/PT/UNUSED),
    // then account for the parent's pre-existing ownership.
    crate::memory::buddy::mark_page_used(phys);
    if refc_get(phys) == 0 {
        refc_inc(phys);
        refc_inc(phys);
    } else {
        refc_inc(phys);
    }
}

fn fork_share_pte_refc(phys: u64) {
    crate::memory::buddy::mark_page_used(phys);
    if crate::memory::buddy::pte_refc_get(phys) == 0 {
        crate::memory::buddy::pte_refc_inc(phys);
        crate::memory::buddy::pte_refc_inc(phys);
    } else {
        crate::memory::buddy::pte_refc_inc(phys);
    }
}

#[repr(C, align(4096))]
pub struct PageTable(pub [u64; 512]);

// With CR0.WP=1, a supervisor write to a read-only page faults. Resolve it by
// making the covering identity-map entry writable IF it is a non-user page.
// Returns true if handled (page made writable, faulting instruction retries).
pub fn kernel_ro_write_resolve(cr2: u64) -> bool {
    let pml4 = crate::task::current_task_pml4();
    if pml4 == 0 {
        return false;
    }
    let vpn = [
        ((cr2 >> 39) & 0x1FF) as usize,
        ((cr2 >> 30) & 0x1FF) as usize,
        ((cr2 >> 21) & 0x1FF) as usize,
        ((cr2 >> 12) & 0x1FF) as usize,
    ];
    unsafe {
        let pml4t = &*(pml4 as *const PageTable);
        if pml4t.0[vpn[0]] & PTE_PRESENT == 0 { return false; }
        let pdpt = &*((pml4t.0[vpn[0]] & PTE_ADDR_MASK) as *const PageTable);
        if pdpt.0[vpn[1]] & PTE_PRESENT == 0 { return false; }
        if pdpt.0[vpn[1]] & PTE_HUGE != 0 {
            if pdpt.0[vpn[1]] & PTE_USER != 0 { return false; }
            let e = &mut *((pml4t.0[vpn[0]] & PTE_ADDR_MASK) as *mut PageTable);
            e.0[vpn[1]] |= PTE_WRITABLE;
            return true;
        }
        let pd = &*((pdpt.0[vpn[1]] & PTE_ADDR_MASK) as *const PageTable);
        if pd.0[vpn[2]] & PTE_PRESENT == 0 { return false; }
        if pd.0[vpn[2]] & PTE_HUGE != 0 {
            if pd.0[vpn[2]] & PTE_USER != 0 { return false; }
            let e = &mut *((pdpt.0[vpn[1]] & PTE_ADDR_MASK) as *mut PageTable);
            e.0[vpn[2]] |= PTE_WRITABLE;
            return true;
        }
        let pt = &*((pd.0[vpn[2]] & PTE_ADDR_MASK) as *const PageTable);
        if pt.0[vpn[3]] & PTE_PRESENT == 0 { return false; }
        if pt.0[vpn[3]] & PTE_USER != 0 { return false; }
        let e = &mut *((pd.0[vpn[2]] & PTE_ADDR_MASK) as *mut PageTable);
        e.0[vpn[3]] |= PTE_WRITABLE;
        true
    }
}impl PageTable {
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
        // Page-table pages are tracked as PTE pages and must go through the
        // quarantine/refcount lifecycle used by all PT/PD/PT/PML4 allocations.
        alloc.alloc_zeroed_page()
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

    /// Unmap a single 4K page from an arbitrary PML4 (user task). Returns the
    /// previously mapped physical address, or Err if not mapped.
    pub fn unmap_into(pml4: u64, virt: u64) -> Result<u64, &'static str> {
        let vpn = [
            ((virt >> 39) & 0x1FF) as usize,
            ((virt >> 30) & 0x1FF) as usize,
            ((virt >> 21) & 0x1FF) as usize,
            ((virt >> 12) & 0x1FF) as usize,
        ];
        let pml4e = unsafe { (*(pml4 as *mut PageTable)).0[vpn[0]] };
        if pml4e & PTE_PRESENT == 0 { return Err("no pml4e"); }
        let pdpt = (pml4e & PTE_ADDR_MASK) as *mut PageTable;
        let pdpte = unsafe { (*pdpt).0[vpn[1]] };
        if pdpte & PTE_PRESENT == 0 { return Err("no pdpte"); }
        if pdpte & PTE_HUGE != 0 { return Err("huge pdpte"); }
        let pd = (pdpte & PTE_ADDR_MASK) as *mut PageTable;
        let pde = unsafe { (*pd).0[vpn[2]] };
        if pde & PTE_PRESENT == 0 { return Err("no pde"); }
        if pde & PTE_HUGE != 0 { return Err("huge pde"); }
        let pt = (pde & PTE_ADDR_MASK) as *mut PageTable;
        let pte = unsafe { (*pt).0[vpn[3]] };
        if pte & PTE_PRESENT == 0 { return Err("no pte"); }
        let phys = pte & PTE_ADDR_MASK;
        unsafe { (*pt).0[vpn[3]] = 0; }
        Ok(phys)
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
        // Intermediate paging structures are page-table pages, not generic data.
        alloc.alloc_zeroed_page().ok_or("OOM")
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
            let new_pt = alloc.alloc_zeroed_page().ok_or("OOM: PDPT")?;
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
            let new_pt = alloc.alloc_zeroed_page().ok_or("OOM: PD")?;
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
            let new_pt = alloc.alloc_zeroed_page().ok_or("OOM: PT")?;
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
        PT_MGR.kernel_pml4 = alloc.alloc_zeroed_page().unwrap();
        KERNEL_PML4.store(PT_MGR.kernel_pml4, Ordering::SeqCst);
        let pml4 = unsafe { &mut *(PT_MGR.kernel_pml4 as *mut PageTable) };
        pml4.clear();

        // Preserve the bootloader identity mapping (0-1GB) so the kernel
        // and all buddy-allocated pages stay accessible after we switch cr3.
        let old_pml4: u64;
        core::arch::asm!("mov {}, cr3", out(reg) old_pml4);
        let old_pt = &*(old_pml4 as *const PageTable);
        pml4.0 = old_pt.0;
        
        // Switch to new PML4 before mapping LAPIC
        core::arch::asm!("mov cr3, {}", in(reg) PT_MGR.kernel_pml4, options(nostack, nomem));
    }
    // Map trampoline page (0x7000) - required for AP startup
    map_trampoline_page();
    
    // Map LAPIC region (0xFEE00000, 4KB) - required for xAPIC access
    map_lapic_region();
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

// Map the trampoline page (physical 0x7000) and stack pages (0x8000-0xC000) in kernel page tables.
// Maps BOTH the high canonical address (0xFFFF_8000_0000_7000) and the low identity address (0x7000),
// because the AP trampoline runs with CS.base=0 in long mode and uses absolute low addresses.
fn map_trampoline_page() {
    const TRAMPOLINE_PHYS: u64 = 0x7000;
    const STACK_PHYS: u64 = 0x8000;
    const TRAMPOLINE_VIRT: u64 = 0xFFFF_8000_0000_7000; // Kernel direct map
    const STACK_VIRT: u64 = 0xFFFF_8000_0000_8000; // Kernel direct map
    // Map with: Present | Writable | Global | No-Execute
    const FLAGS: u64 = 0x83; // P | W | G | NX (bit 63)

    let pml4 = crate::paging::KERNEL_PML4.load(core::sync::atomic::Ordering::Relaxed) as *mut crate::paging::PageTable;
    if pml4.is_null() {
        return;
    }

    // Map a single 4KB page at `virt` -> `phys` in the kernel PML4 (get-or-allocate page tables).
    fn map_one(pml4: *mut crate::paging::PageTable, virt: u64, phys: u64) {
        let v = [
            ((virt >> 39) & 0x1FF) as usize,
            ((virt >> 30) & 0x1FF) as usize,
            ((virt >> 21) & 0x1FF) as usize,
            ((virt >> 12) & 0x1FF) as usize,
        ];
        let alloc_pt = || -> u64 {
            let alloc = unsafe { &mut *crate::memory::allocator() };
            match alloc.alloc_zeroed_page() {
                Some(p) => p,
                None => 0,
            }
        };
        // PML4
        let e = unsafe { (*pml4).0[v[0]] };
        let pdpt = if e & 1 != 0 {
            (e & 0xFFFF_FFFF_FFFF_F000) as *mut crate::paging::PageTable
        } else {
            let p = alloc_pt();
            if p == 0 { return; }
            unsafe { (*pml4).0[v[0]] = p | 3; }
            p as *mut crate::paging::PageTable
        };
        // PDPT
        let e = unsafe { (*pdpt).0[v[1]] };
        let pd = if e & 1 != 0 {
            (e & 0xFFFF_FFFF_FFFF_F000) as *mut crate::paging::PageTable
        } else {
            let p = alloc_pt();
            if p == 0 { return; }
            unsafe { (*pdpt).0[v[1]] = p | 3; }
            p as *mut crate::paging::PageTable
        };
        // PD
        let e = unsafe { (*pd).0[v[2]] };
        let pt = if e & 1 != 0 {
            (e & 0xFFFF_FFFF_FFFF_F000) as *mut crate::paging::PageTable
        } else {
            let p = alloc_pt();
            if p == 0 { return; }
            unsafe { (*pd).0[v[2]] = p | 3; }
            p as *mut crate::paging::PageTable
        };
        // PT
        unsafe { (*pt).0[v[3]] = phys | FLAGS; }
        unsafe { core::arch::asm!("invlpg [{}]", in(reg) virt, options(nostack, preserves_flags)); }
    }

    // Trampoline: high + identity (low) address
    map_one(pml4, TRAMPOLINE_VIRT, TRAMPOLINE_PHYS);
    map_one(pml4, TRAMPOLINE_PHYS, TRAMPOLINE_PHYS);
    // Stack: high + identity (low) address, 4 pages (0x8000-0xC000)
    for i in 0..4u64 {
        let phys = STACK_PHYS + i * 0x1000;
        map_one(pml4, STACK_VIRT + i * 0x1000, phys);
        map_one(pml4, phys, phys);
    }
}

// Map the LAPIC region (0xFEE00000, 4KB) in kernel page tables
fn map_lapic_region() {
    const LAPIC_PHYS: u64 = 0xFEE00000;
    const LAPIC_VIRT: u64 = 0xFFFF_8000_FEE0_0000; // Kernel direct map
    // Map with: Present | Writable | Global | No-Execute
    let flags = 0x83; // P | W | G | NX (bit 63)
    
    let vpn = [
        ((LAPIC_VIRT >> 39) & 0x1FF) as usize,
        ((LAPIC_VIRT >> 30) & 0x1FF) as usize,
        ((LAPIC_VIRT >> 21) & 0x1FF) as usize,
        ((LAPIC_VIRT >> 12) & 0x1FF) as usize,
    ];

    let pml4 = crate::paging::KERNEL_PML4.load(core::sync::atomic::Ordering::Relaxed) as *mut crate::paging::PageTable;
    if pml4.is_null() {
        return;
    }

    // PML4
    let pml4e = unsafe { (*pml4).0[vpn[0]] };
    let pdpt = if pml4e & 1 != 0 {
        (pml4e & 0xFFFF_FFFF_FFFF_F000) as *mut crate::paging::PageTable
    } else {
        let alloc = unsafe { &mut *crate::memory::allocator() };
        let new_pt = match alloc.alloc_zeroed_page() {
            Some(p) => p,
            None => return,
        };
        unsafe { core::ptr::write_bytes(new_pt as *mut u8, 0, 4096); }
        unsafe { (*pml4).0[vpn[0]] = new_pt | 3; } // P | W
        new_pt as *mut crate::paging::PageTable
    };

    // PDPT
    let pdpte = unsafe { (*pdpt).0[vpn[1]] };
    let pd = if pdpte & 1 != 0 {
        (pdpte & 0xFFFF_FFFF_FFFF_F000) as *mut crate::paging::PageTable
    } else {
        let alloc = unsafe { &mut *crate::memory::allocator() };
        let new_pt = match alloc.alloc_zeroed_page() {
            Some(p) => p,
            None => return,
        };
        unsafe { core::ptr::write_bytes(new_pt as *mut u8, 0, 4096); }
        unsafe { (*pdpt).0[vpn[1]] = new_pt | 3; }
        new_pt as *mut crate::paging::PageTable
    };

    // PD
    let pde = unsafe { (*pd).0[vpn[2]] };
    let pt = if pde & 1 != 0 {
        (pde & 0xFFFF_FFFF_FFFF_F000) as *mut crate::paging::PageTable
    } else {
        let alloc = unsafe { &mut *crate::memory::allocator() };
        let new_pt = match alloc.alloc_zeroed_page() {
            Some(p) => p,
            None => return,
        };
        unsafe { core::ptr::write_bytes(new_pt as *mut u8, 0, 4096); }
        unsafe { (*pd).0[vpn[2]] = new_pt | 3; }
        new_pt as *mut crate::paging::PageTable
    };

    // PT
    unsafe { (*pt).0[vpn[3]] = LAPIC_PHYS | flags; }
    
    // Flush TLB for the new mapping
    unsafe { core::arch::asm!("invlpg [{}]", in(reg) LAPIC_VIRT, options(nostack, preserves_flags)); }
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

/// Resolve a virtual address to its (physical, flags) pair, transparently
/// handling 2M huge pages. Returns None if not present.
pub fn resolve_phys_flags(pml4: u64, virt: u64) -> Option<(u64, u64)> {
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
            let phys = (pde & PTE_ADDR_MASK) | (virt & (PAGE_SIZE_2M - 1));
            return Some((phys, pde));
        }
        let pt = (pde & PTE_ADDR_MASK) as *const PageTable;
        let pte = (*pt).0[vpn[3]];
        if pte & PTE_PRESENT == 0 { return None; }
        let phys = (pte & PTE_ADDR_MASK) | (virt & (PAGE_SIZE_4K - 1));
        Some((phys, pte))
    }
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

// Free a task's user address space: all user page-table pages and, depending
// on `free_ro`, the leaf pages. `free_ro` should be true for exec'd children
// (fresh pml4 — every user page is owned by the child) and false for
// COW-forked children that never exec'd (read-only pages are shared with the
// parent). Kernel half (PML4 entries 256..512) and kernel-identity huge pages
// are never touched.
pub fn free_address_space(pml4: u64, free_ro: bool) {
    let alloc = unsafe { &mut *crate::memory::allocator() };
    let base = crate::memory::buddy::alloc_base();
    let end = base + crate::memory::buddy::alloc_pages() * crate::memory::buddy::PAGE_SIZE;
    // Guard against walking a bogus pml4: it must be a real allocated page
    // within the managed range and marked used by the buddy. A corrupted
    // TASKS[idx].pml4 (e.g. pointing into the module/ramfs area) would make
    // this walk read arbitrary data as page tables and free pages that were
    // never allocated, corrupting the buddy free lists (the DOUBLE-FREE bug).
    if pml4 < base || pml4 >= end {
        crate::klog::begin(crate::klog::LOG_ERR, crate::klog::FAC_PAGING);
        crate::klog::s("FAS BADPML4 pml4=0x");
        crate::klog::hex(pml4);
        crate::klog::s(" used=");
        crate::klog::dec(if crate::memory::buddy::page_is_used(pml4) { 1 } else { 0 });
        crate::klog::s(" type=");
        crate::klog::dec(crate::memory::buddy::page_type_get(pml4) as u64);
        crate::klog::s(" resv=");
        crate::klog::dec(if crate::memory::buddy::is_reserved_page(pml4) { 1 } else { 0 });
        {
            let mut cr3: u64 = 0;
            unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, nomem)); }
            crate::klog::s(" cr3=0x");
            crate::klog::hex(cr3);
            crate::klog::s(" same=");
            crate::klog::dec(if cr3 == pml4 { 1 } else { 0 });
        }
        let (fc, ft, fo) = crate::memory::buddy::df_info(pml4);
        crate::klog::s(" freed_by=0x");
        crate::klog::hex(fc as u64);
        crate::klog::s(" tick=");
        crate::klog::dec(ft as u64);
        crate::klog::s(" order=");
        crate::klog::dec(fo as u64);
        crate::klog::s(" task=");
        crate::klog::dec(crate::task::current_task_id());
        // Safety-scanned free lists: is this page on any order's list?
        {
            let lpidx = (pml4 >> 12) as u64;
            let mut found = false;
            for lo in 0..=10 {
                let mut c = crate::memory::buddy::free_list_head(lo);
                let mut steps = 0u32;
                while c != 0 && steps < 100000 {
                    if (c >> 12) == lpidx {
                        crate::klog::s(" in_order=");
                        crate::klog::dec(lo as u64);
                        found = true;
                        break;
                    }
                    unsafe { c = *((c + 8) as *const u64); }
                    steps += 1;
                }
                if found { break; }
            }
            if !found {
                crate::klog::s(" not_in_any_list");
            }
        }
        crate::klog::end();
        if pml4 >= base && pml4 < end {
            unsafe {
                let t = &*(pml4 as *const PageTable);
                for i in 0..8 {
                    crate::klog::begin(crate::klog::LOG_ERR, crate::klog::FAC_PAGING);
                    crate::klog::s("FAS: pml4e[");
                    crate::klog::dec(i as u64);
                    crate::klog::s("]=0x");
                    crate::klog::hex(t.0[i]);
                    crate::klog::end();
                }
            }
        }
        return;
    }
    unsafe {
        // Track visited page table pages to prevent double-free when the same
        // physical page table page is reachable through multiple paths.
        let mut visited_pt: [u64; 2048] = [0; 2048];
        let mut visited_count: usize = 0;

        let table = &*(pml4 as *const PageTable);
        for pml4_idx in 0..256 {
            let pml4e = table.0[pml4_idx];
            if pml4e & PTE_PRESENT == 0 { continue; }
            let pdpt = (pml4e & PTE_ADDR_MASK) as *mut PageTable;

let mut pdpt_user = false;
            for pdpt_idx in 0..512 {
                let pdpte = (*pdpt).0[pdpt_idx];
                if pdpte & PTE_PRESENT == 0 { continue; }
                if pdpte & PTE_HUGE != 0 { continue; } // 1G kernel identity
                let pdpt_phys = pdpte & PTE_ADDR_MASK;
                if pdpt_phys < base || pdpt_phys >= end {
                    crate::klog::begin(crate::klog::LOG_ERR, crate::klog::FAC_PAGING);
                    crate::klog::s("FAS: BAD PDPT pml4=0x");
                    crate::klog::hex(pml4);
                    crate::klog::s(" pdpt_idx=");
                    crate::klog::dec(pdpt_idx as u64);
                    crate::klog::s(" pdpt_phys=0x");
                    crate::klog::hex(pdpt_phys);
                    crate::klog::end();
                    continue;
                }
                // In-range page-table page: mark used so buddy bookkeeping stays
                // consistent (some allocation paths don't set the used bit).
                crate::memory::buddy::mark_page_used(pdpt_phys);
                // Track visited PDPT to prevent double-free
                if visited_count < 2048 {
                    let mut found = false;
                    for i in 0..visited_count {
                        if visited_pt[i] == pdpt_phys {
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        visited_pt[visited_count] = pdpt_phys;
                        visited_count += 1;
                    }
                }
                let pd = pdpt_phys as *mut PageTable;

                let mut pd_user = false;
                for pd_idx in 0..512 {
                    let pde = (*pd).0[pd_idx];
                    if pde & PTE_PRESENT == 0 { continue; }
                    if pde & PTE_HUGE != 0 { continue; } // 2M kernel identity
                    let pd_phys = pde & PTE_ADDR_MASK;
                    if pd_phys < base || pd_phys >= end {
                        crate::klog::begin(crate::klog::LOG_ERR, crate::klog::FAC_PAGING);
                        crate::klog::s("FAS: BAD PD pml4=0x");
                        crate::klog::hex(pml4);
                        crate::klog::s(" pdpt_idx=");
                        crate::klog::dec(pdpt_idx as u64);
                        crate::klog::s(" pd_idx=");
                        crate::klog::dec(pd_idx as u64);
                        crate::klog::s(" pd_phys=0x");
                        crate::klog::hex(pd_phys);
                        crate::klog::end();
                        continue;
                    }
                    crate::memory::buddy::mark_page_used(pd_phys);
                    // Track visited PD to prevent double-free
                    if visited_count < 2048 {
                        let mut found = false;
                        for i in 0..visited_count {
                            if visited_pt[i] == pd_phys {
                                found = true;
                                break;
                            }
                        }
                        if !found {
                            visited_pt[visited_count] = pd_phys;
                            visited_count += 1;
                        }
                    }
                    let pt = pd_phys as *mut PageTable;

                    let mut pt_user = false;
                    for pt_idx in 0..512 {
                        let pte = (*pt).0[pt_idx];
                        if pte & PTE_PRESENT == 0 { continue; }
                        // Only user pages are owned by the task; kernel identity
                        // sub-pages (non-USER) map physical memory and are shared.
                        if pte & PTE_USER != 0 {
                            let phys = pte & PTE_ADDR_MASK;
                            // DOUBLE-FREE/pml4-corruption diagnostics:
                            // detect pages that are out of the managed RAM range
                            // (garbage PTE) or in range but never marked used.
                            if phys < base || phys >= end {
                                crate::klog::begin(crate::klog::LOG_ERR, crate::klog::FAC_PAGING);
                                crate::klog::s("FAS: OOB PTE pml4=0x");
                                crate::klog::hex(pml4);
                                crate::klog::s(" pos=");
                                crate::klog::dec(pml4_idx as u64);
                                crate::klog::s("/");
                                crate::klog::dec(pdpt_idx as u64);
                                crate::klog::s("/");
                                crate::klog::dec(pd_idx as u64);
                                crate::klog::s("/");
                                crate::klog::dec(pt_idx as u64);
                                crate::klog::s(" pte=0x");
                                crate::klog::hex(pte);
                                crate::klog::s(" phys=0x");
                                crate::klog::hex(phys);
                                crate::klog::s(" task=");
                                crate::klog::dec(crate::task::current_task_id());
                                crate::klog::end();
                                continue;
                            }
                            let pidx = (phys >> 12) as usize;
                            if phys < base || phys >= end {
                                crate::klog::begin(crate::klog::LOG_ERR, crate::klog::FAC_PAGING);
                                crate::klog::s("FAS: UNUSED pml4=0x");
                                crate::klog::hex(pml4);
                                crate::klog::s(" pos=");
                                crate::klog::dec(pml4_idx as u64);
                                crate::klog::s("/");
                                crate::klog::dec(pdpt_idx as u64);
                                crate::klog::s("/");
                                crate::klog::dec(pd_idx as u64);
                                crate::klog::s("/");
                                crate::klog::dec(pt_idx as u64);
                                crate::klog::s(" phys=0x");
                                crate::klog::hex(phys);
                                crate::klog::s(" pidx=");
                                crate::klog::dec(pidx as u64);
                                crate::klog::s(" pte=0x");
                                crate::klog::hex(pte);
                                let (fc, ft, fo) = crate::memory::buddy::df_info(phys);
                                crate::klog::s(" first_caller=0x");
                                crate::klog::hex(fc as u64);
                                crate::klog::s(" first_tick=");
                                crate::klog::dec(ft as u64);
                                crate::klog::s(" first_order=");
                                crate::klog::dec(fo as u64);
                                crate::klog::s(" task=");
                                crate::klog::dec(crate::task::current_task_id());
                                crate::klog::end();
                            }
                            if pte & PTE_WRITABLE != 0 || free_ro {
                                // Release this reference: if the page is still
                                // shared with another task, drop our refcount;
                                // otherwise free it outright.
                                if refc_get(phys) > 0 {
                                    refc_dec(phys);
                                } else {
                                    // Guard: skip free if phys is OOB or never marked used
                                    if phys >= base && phys < end {
                                        alloc.free(phys, 0);
                                    }
                                }
                            } else if refc_get(phys) > 0 {
                                // Read-only leaf in a fork clone being torn down
                                // (exec): the parent still owns it. Drop the
                                // child's reference without freeing the page.
                                refc_dec(phys);
                            } else {
                                // Read-only leaf with no remaining COW refs: the
                                // other owner already copied it away (e.g. the
                                // parent un-COW'd its copy), so this page is
                                // orphaned. Free it.
                                if phys >= base && phys < end {
                                    alloc.free(phys, 0);
                                }
                            }
                            pt_user = true;
                        }
                    }
                    if pt_user {
                        // PT page: if still shared (fork partner references it),
                        // drop our reference; otherwise it is ours to free.
                        let pt_phys = pde & PTE_ADDR_MASK;
                        // Track visited PT to prevent double-free
                        if visited_count < 2048 {
                            let mut found = false;
                            for i in 0..visited_count {
                                if visited_pt[i] == pt_phys {
                                    found = true;
                                    break;
                                }
                            }
                            if !found {
                                visited_pt[visited_count] = pt_phys;
                                visited_count += 1;
                            }
                        }
                        if crate::memory::buddy::pte_refc_dec(pt_phys) {
                                if pt_phys >= base && pt_phys < end {
                                alloc.free(pt_phys, 0);
                            }
                        }
                        pd_user = true;
                    }
                }
                if pd_user {
                    let pd_phys = pdpte & PTE_ADDR_MASK;
                    // Track visited PD to prevent double-free
                    if visited_count < 2048 {
                        let mut found = false;
                        for i in 0..visited_count {
                            if visited_pt[i] == pd_phys {
                                found = true;
                                break;
                            }
                        }
                        if !found {
                            visited_pt[visited_count] = pd_phys;
                            visited_count += 1;
                        }
                    }
                    if crate::memory::buddy::pte_refc_dec(pd_phys) {
                            if pd_phys >= base && pd_phys < end {
                            alloc.free(pd_phys, 0);
                        }
                    }
                    pdpt_user = true;
                }
            }
            if pdpt_user {
                let pdpt_phys = pml4e & PTE_ADDR_MASK;
                // Track visited PDPT to prevent double-free
                if visited_count < 2048 {
                    let mut found = false;
                    for i in 0..visited_count {
                        if visited_pt[i] == pdpt_phys {
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        visited_pt[visited_count] = pdpt_phys;
                        visited_count += 1;
                    }
                }
                if crate::memory::buddy::pte_refc_dec(pdpt_phys) {
                    if pdpt_phys >= base && pdpt_phys < end {
                        alloc.free(pdpt_phys, 0);
                    }
                }
            }
        }
        // Track PML4 to prevent double-free
        if visited_count < 2048 {
            let mut found = false;
            for i in 0..visited_count {
                if visited_pt[i] == pml4 {
                    found = true;
                    break;
                }
            }
            if !found {
                visited_pt[visited_count] = pml4;
                visited_count += 1;
            }
        }
        // Guard PML4 free
        if pml4 >= base && pml4 < end {
            alloc.free(pml4, 0);
        }
    }
}

// Clone the current process's PML4 for fork.
// Lazy sharing: only a new PML4 is allocated; user page tables (PDPT/PD/PT)
// are shared with the child and reference-counted. All user 4K PTEs are marked
// read-only (COW) in both parent and child. 2M/1G huge pages (kernel identity
// map) stay shared writable.
pub fn cow_fork_pml4(old_pml4: u64) -> Option<u64> {
    let alloc = unsafe { &mut *crate::memory::allocator() };
    let new_pml4 = alloc.alloc_zeroed_page()?;
    unsafe { core::ptr::write_bytes(new_pml4 as *mut u8, 0, 4096); }
    // The page may have been reclaimed from the quarantine, so its used bit /
    // double-free-tracker entry are stale. Mark it allocated so that
    // free_address_space's guards don't misfire (FAS BADPML4) and so the page
    // is not double-freed later.
    crate::memory::buddy::mark_page_used(new_pml4);

    let old_table = unsafe { &*(old_pml4 as *const PageTable) };
    let new_table = unsafe { &mut *(new_pml4 as *mut PageTable) };

    // Copy kernel PML4 entries: low identity map (indices 0-1 for first 1GB
    // where kernel lives at 0x100000) AND high half (256-511).
    let kernel_pml4_val = KERNEL_PML4.load(Ordering::Relaxed);
    let kernel_pt = unsafe { &*(kernel_pml4_val as *const PageTable) };
    for i in 0..2 {
        new_table.0[i] = kernel_pt.0[i];
    }
    for i in 256..512 {
        new_table.0[i] = kernel_pt.0[i];
    }

    // Lazy sharing: share all user page table pages (PDPT/PD/PT) with the child.
    // Only a new PML4 is allocated. All user PTEs are marked read-only (COW)
    // in both parent and child. Physical page reference counts are incremented
    // so cow_remap_in knows which pages are shared.
    for pml4_idx in 0..256 {
        let pml4e = old_table.0[pml4_idx];
        if pml4e & PTE_PRESENT == 0 { continue; }

        // Share the PDPT with the child
        new_table.0[pml4_idx] = pml4e;

        let old_pdpt_phys = pml4e & PTE_ADDR_MASK;
        // Page-table page: both parent and child now reference it.
        fork_share_pte_refc(old_pdpt_phys);
        let old_pdpt = unsafe { &mut *(old_pdpt_phys as *mut PageTable) };

        for pdpt_idx in 0..512 {
            let pdpte = old_pdpt.0[pdpt_idx];
            if pdpte & PTE_PRESENT == 0 { continue; }

            if pdpte & PTE_HUGE != 0 {
                // 1G huge page — mark as COW in both parent and child.
                // Kernel identity huge pages (USER=0) stay shared writable:
                // marking them RO would trap every kernel write AND the PD/PT
                // pages under them, deadlocking the PF handler.
                if pdpte & PTE_USER != 0 {
                    fork_share_refc(pdpte & PTE_ADDR_MASK);
                    old_pdpt.0[pdpt_idx] = pdpte & !PTE_WRITABLE;
                }
                continue;
            }

            let old_pd_phys = pdpte & PTE_ADDR_MASK;
            // Page-table page: shared between parent and child.
            fork_share_pte_refc(old_pd_phys);
            let old_pd = unsafe { &mut *(old_pd_phys as *mut PageTable) };

            for pd_idx in 0..512 {
                let pde = old_pd.0[pd_idx];
                if pde & PTE_PRESENT == 0 { continue; }

                if pde & PTE_HUGE != 0 {
                    // 2M huge page — mark as COW in both parent and child.
                    // Kernel identity huge pages (USER=0) stay shared writable.
                    if pde & PTE_USER != 0 {
                        fork_share_refc(pde & PTE_ADDR_MASK);
                        old_pd.0[pd_idx] = pde & !PTE_WRITABLE;
                    }
                    continue;
                }

                // 4K page — mark all user PTEs as read-only (COW)
let old_pt_phys = pde & PTE_ADDR_MASK;
            // Page-table page: shared between parent and child.
            fork_share_pte_refc(old_pt_phys);
            let old_pt = unsafe { &mut *(old_pt_phys as *mut PageTable) };

                for pt_idx in 0..512 {
                    let pte = old_pt.0[pt_idx];
                    if pte & PTE_PRESENT == 0 { continue; }
                    // Kernel identity pages (USER cleared) belong to the kernel and
                    // must stay writable (PF/DF stacks, BSS, page tables). Only COW
                    // user pages so the parent/child share stays correct.
                    if pte & PTE_USER == 0 { continue; }
                    fork_share_refc(pte & PTE_ADDR_MASK);
                    if pte & PTE_WRITABLE == 0 { continue; }
                    old_pt.0[pt_idx] = pte & !PTE_WRITABLE;
                }
            }
        }
    }

    // Flush TLB for old PML4 since we modified its PTEs
    unsafe {
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack));
        core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, nomem));
    }

    Some(new_pml4)
}

// Walk to the leaf PTE for `virt`, ensuring every page-table page along the
// way (PDPT/PD/PT) is private to this task. Shared page-table pages (those
// refcounted by a fork partner) are copied on write, dropping our reference
// to the shared original. Returns a mutable reference to the leaf PTE, or
// None if the mapping is absent or a huge page is in the way.
fn cow_walk_pte(pml4: u64, virt: u64) -> Option<&'static mut u64> {
    let vpn = [
        ((virt >> 39) & 0x1FF) as usize,
        ((virt >> 30) & 0x1FF) as usize,
        ((virt >> 21) & 0x1FF) as usize,
        ((virt >> 12) & 0x1FF) as usize,
    ];
    let alloc = unsafe { &mut *crate::memory::allocator() };

    // PML4 is always private (each task owns its own).
    let pml4_tbl = unsafe { &mut *(pml4 as *mut PageTable) };
    let pml4e = pml4_tbl.0[vpn[0]];
    if pml4e & PTE_PRESENT == 0 { return None; }
    let mut pdpt_phys = pml4e & PTE_ADDR_MASK;

    // PDPT: copy if shared with a fork partner (refcount > 1 means our own
    // reference plus at least one other holder).
    if crate::memory::buddy::pte_refc_get(pdpt_phys) > 1 {
        let new_pdpt = alloc.alloc_zeroed_page()?;
        unsafe { core::ptr::copy_nonoverlapping(pdpt_phys as *const u8, new_pdpt as *mut u8, 4096); }
        crate::memory::buddy::pte_refc_dec(pdpt_phys);
        pml4_tbl.0[vpn[0]] = new_pdpt | (pml4e & !PTE_ADDR_MASK);
        pdpt_phys = new_pdpt;
    }

    let pdpt_tbl = unsafe { &mut *(pdpt_phys as *mut PageTable) };
    let pdpte = pdpt_tbl.0[vpn[1]];
    if pdpte & PTE_PRESENT == 0 { return None; }
    if pdpte & PTE_HUGE != 0 { return None; }
    let mut pd_phys = pdpte & PTE_ADDR_MASK;

    // PD: copy if shared.
    if crate::memory::buddy::pte_refc_get(pd_phys) > 1 {
        let new_pd = alloc.alloc_zeroed_page()?;
        unsafe { core::ptr::copy_nonoverlapping(pd_phys as *const u8, new_pd as *mut u8, 4096); }
        crate::memory::buddy::pte_refc_dec(pd_phys);
        pdpt_tbl.0[vpn[1]] = new_pd | (pdpte & !PTE_ADDR_MASK);
        pd_phys = new_pd;
    }

    let pd_tbl = unsafe { &mut *(pd_phys as *mut PageTable) };
    let pde = pd_tbl.0[vpn[2]];
    if pde & PTE_PRESENT == 0 { return None; }
    if pde & PTE_HUGE != 0 { return None; }
    let mut pt_phys = pde & PTE_ADDR_MASK;

    // PT: copy if shared.
    if crate::memory::buddy::pte_refc_get(pt_phys) > 1 {
        let new_pt = alloc.alloc_zeroed_page()?;
        unsafe { core::ptr::copy_nonoverlapping(pt_phys as *const u8, new_pt as *mut u8, 4096); }
        crate::memory::buddy::pte_refc_dec(pt_phys);
        pd_tbl.0[vpn[2]] = new_pt | (pde & !PTE_ADDR_MASK);
        pt_phys = new_pt;
    }

    let pt_tbl = unsafe { &mut *(pt_phys as *mut PageTable) };
    Some(&mut pt_tbl.0[vpn[3]])
}

pub fn cow_remap_in(pml4: u64, virt: u64) -> bool {
    let pte = match cow_walk_pte(pml4, virt) {
        Some(p) => p,
        None => return false,
    };

    if *pte & PTE_PRESENT == 0 { return false; }
    if *pte & PTE_WRITABLE != 0 { return false; }

     let old_phys = *pte & PTE_ADDR_MASK;
     let flags = *pte & !PTE_ADDR_MASK;
 
     let alloc = unsafe { &mut *crate::memory::allocator() };

    // The mallocng meta page must always have a private physical page reserved
    // (it may be aliased via the identity map and must never be handed out by
    // the buddy again). The brk path already reserves the private page before
    // mapping it, so a private meta page just becomes writable in place. A
    // shared meta page (COW fork of the shell's heap) needs a fresh reserved
    // copy for the faulting task.
    if virt == 0x500000 {
        if refc_get(old_phys) == 0 {
            *pte = old_phys | flags | PTE_WRITABLE;
            unsafe { core::arch::asm!("invlpg [{}]", in(reg) virt, options(nostack, preserves_flags)); }
            return true;
        }
        refc_dec(old_phys);
        alloc.reserve(old_phys);
        if DEBUG_ENABLED.load(Ordering::Relaxed) {
            crate::serial::write_str("  COW: reserved old meta phys=0x");
            crate::serial::write_hex(old_phys);
            crate::serial::write_str("\n");
        }
let new_phys = match alloc.alloc_zeroed_page() {
            Some(p) => p,
            None => return false,
        };
        unsafe {
            core::ptr::copy_nonoverlapping(old_phys as *const u8, new_phys as *mut u8, 4096);
        }
        alloc.reserve(new_phys);
        if DEBUG_ENABLED.load(Ordering::Relaxed) {
            crate::serial::write_str("  COW: reserved meta phys=0x");
            crate::serial::write_hex(new_phys);
            crate::serial::write_str("\n");
        }
        *pte = new_phys | flags | PTE_WRITABLE;
        unsafe { core::arch::asm!("invlpg [{}]", in(reg) virt, options(nostack, preserves_flags)); }
        return true;
    }

    // If no other task still references this page, it is private: make it
    // writable in place. Copying here would orphan the old page (leak).
    if refc_get(old_phys) == 0 {
        *pte = old_phys | flags | PTE_WRITABLE;
        unsafe { core::arch::asm!("invlpg [{}]", in(reg) virt, options(nostack, preserves_flags)); }
        return true;
    }

    // Shared: copy the page and drop our reference to the shared original.
    refc_dec(old_phys);
    let new_phys = match alloc.alloc_zeroed_page() {
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
    let p = alloc.alloc_zeroed_page().expect("OOM");
    mgr.map_page(0x4000_0000, p, PTE_PRESENT | PTE_WRITABLE).expect("map failed");

    let phys = mgr.translate(0x4000_0000).expect("translate failed");
    assert_eq!(phys, p);
    crate::serial::write_str("PAGING: map/translate 4K OK\n");

    let p2 = alloc.alloc_zeroed_page().expect("OOM");
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