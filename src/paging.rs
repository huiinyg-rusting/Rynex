use core::ptr;

pub const PAGE_SIZE_4K: u64 = 4096;
pub const PAGE_SIZE_2M: u64 = 2 * 1024 * 1024;
pub const PAGE_SIZE_1G: u64 = 1024 * 1024 * 1024;

pub const PTE_PRESENT: u64 = 1 << 0;
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

#[repr(C, align(4096))]
pub struct PageTable([u64; 512]);

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
}

pub fn get_pte(virt: u64) -> Option<&'static mut u64> {
    let vpn = [
        ((virt >> 39) & 0x1FF) as usize,
        ((virt >> 30) & 0x1FF) as usize,
        ((virt >> 21) & 0x1FF) as usize,
        ((virt >> 12) & 0x1FF) as usize,
    ];

    let pml4 = pt_mgr().kernel_pml4() as *const PageTable;
    let pml4e = unsafe { (*pml4).0[vpn[0]] };
    if pml4e & PTE_PRESENT == 0 { return None; }

    let pdpt = (pml4e & PTE_ADDR_MASK) as *const PageTable;
    let pdpte = unsafe { (*pdpt).0[vpn[1]] };
    if pdpte & PTE_PRESENT == 0 { return None; }

    let pd = (pdpte & PTE_ADDR_MASK) as *const PageTable;
    let pde = unsafe { (*pd).0[vpn[2]] };
    if pde & PTE_PRESENT == 0 { return None; }
    if pde & PTE_HUGE != 0 { return None; }

    let pt = (pde & PTE_ADDR_MASK) as *const PageTable;
    let pte = unsafe { &(*pt).0[vpn[3]] };
    if *pte & PTE_PRESENT == 0 { return None; }

    let pt_mut = (pde & PTE_ADDR_MASK) as *mut PageTable;
    Some(unsafe { &mut (*pt_mut).0[vpn[3]] })
}

pub fn is_user_addr(addr: u64) -> bool {
    addr < 0x0000_8000_0000_0000
}

pub fn cow_remap(virt: u64) -> bool {
    let pte = match get_pte(virt) {
        Some(p) => p,
        None => return false,
    };

    if *pte & PTE_PRESENT == 0 { return false; }
    if *pte & PTE_WRITABLE != 0 { return false; }

    let old_phys = *pte & PTE_ADDR_MASK;
    let flags = *pte & !PTE_ADDR_MASK;

    let alloc = unsafe { &mut *crate::memory::allocator() };
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

    // Update PTE: new phys + writable
    *pte = new_phys | flags | PTE_WRITABLE;
    unsafe { core::arch::asm!("invlpg [{}]", in(reg) virt, options(nostack, preserves_flags)); }
    true
}

pub fn page_fault_resolve(frame: &x86_64::structures::idt::InterruptStackFrame,
                          code: x86_64::structures::idt::PageFaultErrorCode, cr2: u64) -> bool {
    let cpl = frame.code_segment.bits() & 3;
    let is_write = code.contains(x86_64::structures::idt::PageFaultErrorCode::CAUSED_BY_WRITE);
    let is_viol = code.contains(x86_64::structures::idt::PageFaultErrorCode::PROTECTION_VIOLATION);

    // Write to a read-only user page → COW
    if cpl == 3 && is_write && is_viol {
        if cow_remap(cr2) {
            crate::serial::write_str("  COW: copied page for 0x");
            crate::serial::write_hex(cr2);
            crate::serial::write_str("\n");
            return true;
        }
    }

    // User page not present → TODO: demand paging
    if cpl == 3 && !is_viol {
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