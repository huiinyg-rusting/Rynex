pub mod buddy;
pub mod paging;

use buddy::BuddyAllocator;
use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

const MAX_REGIONS: usize = 32;

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
    let pages = (end - base) / buddy::PAGE_SIZE;

    unsafe {
        ALLOC.init(base, pages);
    }

    let kstart = unsafe { &_kernel_start as *const _ as u64 };
    let kend = unsafe { &_kernel_end as *const _ as u64 };
    let ks = buddy::page_align_down(kstart);
    let ke = buddy::page_align_up(kend);
    crate::serial::write_str("MEMDBG: base=0x");
    crate::serial::write_hex(base);
    crate::serial::write_str(" kstart=0x");
    crate::serial::write_hex(ks);
    crate::serial::write_str(" kend=0x");
    crate::serial::write_hex(ke);
    crate::serial::write_str(" region_end=0x");
    crate::serial::write_hex(end);
    crate::serial::write_str("\n");

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

    let info_page = buddy::page_align_down(info_addr as u64);

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
            // upper region: adj_end -> end
            if adj_end < base + pages * buddy::PAGE_SIZE {
                add_free_region_skipping(adj_end, base + pages * buddy::PAGE_SIZE, &modules, nmodules, info_page);
            }
        } else {
            add_free_region_skipping(base, base + pages * buddy::PAGE_SIZE, &modules, nmodules, info_page);
        }
    }

    TOTAL_PAGES.store(pages, Ordering::SeqCst);
}

unsafe fn add_free_region_skipping(start: u64, end: u64,
    modules: &[crate::multiboot2::ModuleInfo], nmodules: usize, info_page: u64)
{
    let mut cur = start;
    while cur < end {
        // Find the next reserved page that intersects [cur, end)
        let mut next_reserved = end;
        if info_page >= cur && info_page < end {
            next_reserved = info_page;
        }
        for i in 0..nmodules {
            let ms = buddy::page_align_down(modules[i].start);
            let me = buddy::page_align_up(modules[i].end);
            if ms >= cur && ms < end && ms < next_reserved {
                next_reserved = ms;
            }
        }
        if next_reserved > cur {
            ALLOC.add_region(cur, next_reserved - cur);
        }
        // skip the reserved block
        let reserved_end = end;
        let mut skip_to = next_reserved + buddy::PAGE_SIZE;
        if info_page >= next_reserved && info_page < reserved_end {
            skip_to = skip_to.max(info_page + buddy::PAGE_SIZE);
        }
        for i in 0..nmodules {
            let ms = buddy::page_align_down(modules[i].start);
            let me = buddy::page_align_up(modules[i].end);
            if ms >= next_reserved && ms < reserved_end && me > skip_to {
                skip_to = me;
            }
        }
        cur = skip_to;
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
            let size = layout.size();
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
        let size = (size + 4095) & !4095;
        let order = {
            let size = layout.size();
            let size = (size + 4095) & !4095;
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