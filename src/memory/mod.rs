pub mod buddy;
pub mod paging;

use buddy::BuddyAllocator;
use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

const MAX_REGIONS: usize = 32;

// The bootloader (GRUB) identity-maps only the first 1 GiB of physical
// memory, and the kernel addresses every physical page through that identity
// map. Pages above 1 GiB have no PTE at boot, so handing them to the buddy
// would fault while writing free-list headers during init. Clamp the managed
// range here; raising the ceiling requires extending the identity map first.
const IDENTITY_LIMIT: u64 = 1 << 30;

// Module regions that must never be allocated by the buddy (GRUB loads them
// and the kernel must treat them as reserved). Filled at init time.
// Stored as compile-time constants after init for O(1) checks.
const MAX_MODULE_REGIONS: usize = 16;
static mut MODULE_REGIONS: [(u64, u64); MAX_MODULE_REGIONS] = [(0, 0); MAX_MODULE_REGIONS];
static mut MODULE_REGIONS_COUNT: usize = 0;

#[inline(always)]
fn is_in_module_region(addr: u64) -> bool {
    unsafe {
        for i in 0..MODULE_REGIONS_COUNT {
            let (start, end) = MODULE_REGIONS[i];
            if addr >= start && addr < end {
                return true;
            }
        }
    }
    false
}

/// Public wrapper for module-region checks from other modules (e.g., paging).
#[inline(always)]
pub fn page_in_module_region(addr: u64) -> bool {
    is_in_module_region(addr)
}

extern "Rust" {
    static _kernel_start: u64;
    static _kernel_end: u64;
}

static mut ALLOC: BuddyAllocator = BuddyAllocator::new();
pub static TOTAL_PAGES: AtomicU64 = AtomicU64::new(0);

pub fn init(info_addr: u32) {
    let mut regions = [crate::multiboot2::MemRegion { base: 0, len: 0 }; MAX_REGIONS];
    let count = crate::multiboot2::memory_regions(info_addr, &mut regions);

    if count == 0 {
        return;
    }

    let mut best = 0;
    let mut best_idx = 0;
    for i in 0..count {
        let r = &regions[i];
        let end = r.base + r.len;
        let a_start = buddy::page_align_up(r.base);
        let a_end = buddy::page_align_down(end);
        let usable = if a_end > a_start { a_end - a_start } else { 0 };
        if usable > best {
            best = usable;
            best_idx = i;
        }
    }

    if best < buddy::PAGE_SIZE {
        return;
    }

    let region = &regions[best_idx];
    let base = buddy::page_align_up(region.base);
    let end = buddy::page_align_down(region.base + region.len);
    let mut pages = (end - base) / buddy::PAGE_SIZE;

    // Clamp to the identity-map ceiling (see IDENTITY_LIMIT above). Also
    // refuse a region that starts above the ceiling entirely.
    if base >= IDENTITY_LIMIT {
        return;
    }
    let max_pages = (IDENTITY_LIMIT - base) / buddy::PAGE_SIZE;
    if pages > max_pages {
        pages = max_pages;
    }

    unsafe {
        ALLOC.init(base, pages);
    }

    let kstart = unsafe { &_kernel_start as *const _ as u64 };
    let kend = unsafe { &_kernel_end as *const _ as u64 };
    let ks = buddy::page_align_down(kstart);
    let ke = buddy::page_align_up(kend);

    // Find modules first so we can exclude their pages from free regions
    let mut modules = [crate::multiboot2::ModuleInfo { start: 0, end: 0, name: [0; 64] }; 8];
    let nmodules = crate::multiboot2::find_modules(info_addr, &mut modules);
    for i in 0..nmodules {
        crate::serial::write_str("MEM: module ");
        crate::serial::write_dec(i as u64);
        crate::serial::write_str(" 0x");
        crate::serial::write_hex(modules[i].start);
        crate::serial::write_str(" - 0x");
        crate::serial::write_hex(modules[i].end);
        crate::serial::write_str("\n");
    }

    // Populate module regions for runtime checks (sanitization, guards)
    unsafe {
        MODULE_REGIONS_COUNT = nmodules.min(MAX_MODULE_REGIONS);
        for i in 0..nmodules {
            let ms = buddy::page_align_down(modules[i].start);
            let me = buddy::page_align_up(modules[i].end);
            MODULE_REGIONS[i] = (ms, me);
        }
    }

    let info_page = buddy::page_align_down(info_addr as u64);

    // Reserve the gap between kernel end and first module (if any) so the
    // buddy doesn't hand out pages from the kernel-module gap for pml4s.
    let mut first_module_start = base + pages * buddy::PAGE_SIZE;
    for i in 0..nmodules {
        let ms = buddy::page_align_down(modules[i].start);
        if ms < first_module_start {
            first_module_start = ms;
        }
    }

    unsafe {
        if ks >= base && ks < base + pages * buddy::PAGE_SIZE {
            let adj_start = ks;
            let adj_end = if ke > base + pages * buddy::PAGE_SIZE {
                base + pages * buddy::PAGE_SIZE
            } else {
                ke
            };
            // lower region: base -> adj_start, skipping module + info pages
            add_free_region_skipping(base, adj_start, &modules, nmodules, info_page);
            ALLOC.mark_allocated(adj_start, adj_end - adj_start);

            // Also mark the gap between kernel end and first module as allocated
            // to prevent the buddy from using the kernel-module gap for pml4s.
            if adj_end < first_module_start {
                ALLOC.mark_allocated(adj_end, first_module_start - adj_end);
            }

            // upper region: first_module_start -> end (skip kernel-module gap entirely)
            if first_module_start < base + pages * buddy::PAGE_SIZE {
                add_free_region_skipping(first_module_start, base + pages * buddy::PAGE_SIZE, &modules, nmodules, info_page);
            }
        } else {
            add_free_region_skipping(base, base + pages * buddy::PAGE_SIZE, &modules, nmodules, info_page);
        }
    }

    TOTAL_PAGES.store(pages, Ordering::SeqCst);
    crate::serial::write_str("MEM: base=0x");
    crate::serial::write_hex(base);
    crate::serial::write_str(" pages=");
    crate::serial::write_dec(pages);
    crate::serial::write_str("\n");

    // Sanitize all existing tasks' pml4: any pointing into module regions
    // are legacy corruption from before the allocator fix; clear them to 0
    // so free_address_space won't walk garbage.
    crate::task::sanitize_task_pml4s();
}

unsafe fn add_free_region_skipping(start: u64, end: u64,
    modules: &[crate::multiboot2::ModuleInfo], nmodules: usize, info_page: u64)
{
    // Build a sorted list of reserved intervals [start, end) within [start, end)
    let mut reserved = [(0u64, 0u64); 32]; // kernel + modules + info_page
    let mut rcount = 0;

    // Kernel is already marked allocated separately, but add it as reserved here
    // for completeness in this region-splitting logic.
    // Note: the actual kernel pages are marked via mark_allocated() separately.

    // Add module regions (page-aligned)
    for i in 0..nmodules {
        let ms = buddy::page_align_down(modules[i].start);
        let me = buddy::page_align_up(modules[i].end);
        if ms < end && me > start {
            let rs = ms.max(start);
            let re = me.min(end);
            if rs < re {
                reserved[rcount] = (rs, re);
                rcount += 1;
            }
        }
    }

    // Add info page
    if info_page >= start && info_page < end {
        reserved[rcount] = (info_page, info_page + buddy::PAGE_SIZE);
        rcount += 1;
    }

    // Sort reserved intervals by start
    for i in 0..rcount {
        for j in i + 1..rcount {
            if reserved[j].0 < reserved[i].0 {
                reserved.swap(i, j);
            }
        }
    }

    // Merge overlapping/adjacent reserved intervals
    let mut merged = [(0u64, 0u64); 32];
    let mut mcount = 0;
    for i in 0..rcount {
        let (rs, re) = reserved[i];
        if mcount == 0 || rs > merged[mcount - 1].1 {
            merged[mcount] = (rs, re);
            mcount += 1;
        } else if re > merged[mcount - 1].1 {
            merged[mcount - 1].1 = re;
        }
    }

    // Add the gaps between reserved intervals as free regions
    let mut cur = start;
    for i in 0..mcount {
        let (rs, re) = merged[i];
        if cur < rs {
            ALLOC.add_region(cur, rs - cur);
        }
        cur = cur.max(re);
    }
    if cur < end {
        ALLOC.add_region(cur, end - cur);
    }
}



#[global_allocator]
static GLOBAL_ALLOCATOR: GlobalBuddyAllocator = GlobalBuddyAllocator;

pub struct GlobalBuddyAllocator;

unsafe impl GlobalAlloc for GlobalBuddyAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let layout = Layout::from_size_align_unchecked(
            (layout.size() + 4095) & !4095,
            layout.align().max(4096),
        );
        
        let order = {
            let _size = layout.size();
            let mut o = 0;
            while (4096 << o) < layout.size() && o < 10 {
                o += 1;
            }
            o
        };
        
        let alloc = unsafe { &mut ALLOC };
        alloc.alloc(order).map(|p| p as *mut u8).unwrap_or(ptr::null_mut())
    }
    
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let size = layout.size();
        let _size = (size + 4095) & !4095;
        let order = {
            let size = layout.size();
            let _size = (size + 4095) & !4095;
            let mut o = 0;
            while (4096 << o) < layout.size() && o < 10 {
                o += 1;
            }
            o
        };
        
        let alloc = unsafe { &mut ALLOC };
        alloc.free(ptr as u64, order);
    }
}

pub fn allocator() -> &'static mut BuddyAllocator {
    unsafe { &mut ALLOC }
}