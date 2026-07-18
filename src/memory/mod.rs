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

    unsafe {
        if ks >= base && ks < base + pages * buddy::PAGE_SIZE {
            let adj_start = ks;
            let adj_end = if ke > base + pages * buddy::PAGE_SIZE {
                base + pages * buddy::PAGE_SIZE
            } else {
                ke
            };
            ALLOC.add_region(base, adj_start - base);
            ALLOC.mark_allocated(adj_start, adj_end - adj_start);
            if adj_end < base + pages * buddy::PAGE_SIZE {
                ALLOC.add_region(adj_end, base + pages * buddy::PAGE_SIZE - adj_end);
            }
        } else {
            ALLOC.add_region(base, pages * buddy::PAGE_SIZE);
        }
    }

    let ia = buddy::page_align_down(info_addr as u64);
    if ia >= ks && ia < ke {
    } else if ia >= base && ia < base + pages * buddy::PAGE_SIZE {
        unsafe {
            ALLOC.mark_allocated(ia, buddy::PAGE_SIZE);
        }
    }

    if 0 == base {
        unsafe {
            ALLOC.mark_allocated(0, buddy::PAGE_SIZE);
        }
    }

    TOTAL_PAGES.store(pages, Ordering::SeqCst);
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