use core::ptr;
use core::sync::atomic::Ordering;
use crate::spinlock::RawSpin;

/// Global lock serializing all buddy operations. Every entry point that touches
/// the free lists / global tracking arrays takes this lock; internal helpers
/// (`*_nolock`) must only be called with it already held.
static BUDDY_LOCK: RawSpin = RawSpin::new();

const MAGIC: u32 = 0xDEADBEEF;
const AUDIT_PERIOD: u64 = 8;

pub const PAGE_SIZE: u64 = 4096;
pub const MAX_ORDER: usize = 10;
const MAX_RESERVED: usize = 2048;

static mut BUDDY_AUDIT_COUNTER: u64 = 0;
static mut AUDIT_ACTIVE: bool = false;

// Global free tracking to catch double-free at allocator level
const FREED_PAGES_CAP: usize = 1 << 16; // 65536 pages
static mut FREED_PAGES: [u64; FREED_PAGES_CAP] = [0; FREED_PAGES_CAP];
static mut FREED_COUNT: usize = 0;

fn track_freed_page(addr: u64) -> bool {
    let idx = phys_to_idx(addr) as usize;
    if idx >= MAX_REFC_PAGES { return false; }
    unsafe {
        for i in 0..FREED_COUNT {
            if FREED_PAGES[i] == addr {
                // Double-free detected at allocator level
                let caller = core::intrinsics::return_address() as u64;
                crate::serial::write_str("\n=== ALLOCATOR DOUBLE-FREE ===\n");
                crate::serial::write_str("addr=0x");
                crate::serial::write_hex(addr);
                crate::serial::write_str(" caller=0x");
                crate::serial::write_hex(caller);
                crate::serial::write_str("\n");
                return true;
            }
        }
        if FREED_COUNT < FREED_PAGES_CAP {
            FREED_PAGES[FREED_COUNT] = addr;
            FREED_COUNT += 1;
        }
    }
    false
}

fn untrack_freed_page(addr: u64) {
    let idx = phys_to_idx(addr) as usize;
    if idx >= MAX_REFC_PAGES { return; }
    unsafe {
        for i in 0..FREED_COUNT {
            if FREED_PAGES[i] == addr {
                // Remove by swapping with last element
                FREED_PAGES[i] = FREED_PAGES[FREED_COUNT - 1];
                FREED_COUNT -= 1;
                return;
            }
        }
    }
}

/// Convert a physical address into the base-relative page index used by the
/// buddy bitmap and page-type arrays (addr >> 12 is NOT the bitmap index
/// unless the allocator base is 0).
fn phys_to_idx(phys: u64) -> u64 {
    let base = alloc_base();
    if phys < base {
        return u64::MAX; // not tracked
    }
    (phys - base) >> 12
}

/// Mark a freshly allocated page as used in the allocator bookkeeping and drop
/// any stale double-free-tracker entry. Needed because reclaim-from-quarantine
/// (`alloc_zeroed_page` -> `q_pop`) returns a page whose used bit / tracker
/// entry were cleared when it was originally freed. Callers that allocate a
/// page-table root this way (e.g. COW fork) must re-mark it so
/// `free_address_space`'s guards don't misfire (FAS BADPML4) and so the page is
/// not double-freed later.
pub fn mark_page_used(phys: u64) {
    let _g = BUDDY_LOCK.lock();
    let pidx = phys_to_idx(phys);
    if pidx != u64::MAX {
        used_mark(pidx);
    }
    untrack_freed_page(phys);
}

/// Query helper for paging.rs walk diagnostics: is this physical page marked
/// used in the buddy bitmap? (page not tracked -> false)
pub fn page_is_used(phys: u64) -> bool {
    used_set(phys_to_idx(phys))
}

// ── Page type tracking (2 bits per page, separate array) ────────────────────
// Sized for up to 8 GiB of RAM (2^21 pages = 2,097,152)
const MAX_REFC_PAGES: usize = 1 << 21;
static mut PAGE_TYPE: [u8; MAX_REFC_PAGES] = [0; MAX_REFC_PAGES];

pub const PAGE_TYPE_FREE: u8 = 0;      // on free list
pub const PAGE_TYPE_PTE: u8 = 1;       // page table page (PML4/PDPT/PD/PT)
pub const PAGE_TYPE_DATA: u8 = 2;      // general data page
pub const PAGE_TYPE_STACK: u8 = 3;     // kernel stack page

// ── PTE_REFC: independent lifecycle refcount for page-table pages ───────────
// Separate from COW's PAGE_REFC; tracks PTE page lifecycle (alloc/free/quarantine)
static mut PTE_REFC: [u16; MAX_REFC_PAGES] = [0; MAX_REFC_PAGES];

#[inline(always)]
pub fn pte_refc_inc(addr: u64) {
    let idx = phys_to_idx(addr) as usize;
    if idx < MAX_REFC_PAGES {
        unsafe { PTE_REFC[idx] = PTE_REFC[idx].saturating_add(1); }
    }
}

#[inline(always)]
pub fn pte_refc_dec(addr: u64) -> bool {
    let idx = phys_to_idx(addr) as usize;
    if idx < MAX_REFC_PAGES {
        unsafe {
            if PTE_REFC[idx] > 0 { PTE_REFC[idx] -= 1; }
            PTE_REFC[idx] == 0
        }
    } else { true }
}

#[inline(always)]
pub fn pte_refc_get(addr: u64) -> u16 {
    let idx = phys_to_idx(addr) as usize;
    if idx < MAX_REFC_PAGES { unsafe { PTE_REFC[idx] } } else { 0 }
}

#[inline(always)]
pub fn page_type_get(addr: u64) -> u8 {
    let idx = phys_to_idx(addr) as usize;
    if idx < MAX_REFC_PAGES {
        unsafe { PAGE_TYPE[idx] }
    } else {
        PAGE_TYPE_FREE
    }
}

pub fn page_type_set(addr: u64, t: u8) {
    let idx = phys_to_idx(addr) as usize;
    if idx < MAX_REFC_PAGES {
        unsafe { PAGE_TYPE[idx] = t; }
    }
}

fn page_type_assert(addr: u64, expected: u8, context: &str) {
    let actual = page_type_get(addr);
    if actual != expected {
        crate::serial::write_str("\n=== PAGE TYPE MISMATCH ===\n");
        crate::serial::write_str("addr=0x");
        crate::serial::write_hex(addr);
        crate::serial::write_str(" expected=");
        crate::serial::write_dec(expected as u64);
        crate::serial::write_str(" actual=");
        crate::serial::write_dec(actual as u64);
        crate::serial::write_str(" ctx=");
        crate::serial::write_str(context);
        crate::serial::write_str(" cr3=0x");
        crate::serial::write_hex(crate::task::current_task_pml4());
        crate::serial::write_str(" task=");
        crate::serial::write_dec(crate::task::current_task_id());
        crate::serial::write_str("\n");
    }
}

// ── Quarantine for freed page-table pages (breaks free→realloc cycle) ──────
const QUARANTINE_INIT_CAP: usize = 256;    // 初始容量
const QUARANTINE_MAX_CAP: usize = 1024;    // 最大扩容上限

static mut QUARANTINE: [u64; QUARANTINE_MAX_CAP] = [0; QUARANTINE_MAX_CAP];
static mut QUARANTINE_CAP: usize = QUARANTINE_INIT_CAP;
static mut QUARANTINE_HEAD: usize = 0;
static mut QUARANTINE_COUNT: usize = 0;
static mut QUARANTINE_FULL_COUNT: u64 = 0;

fn q_push(addr: u64) {
    unsafe {
        if QUARANTINE_COUNT < QUARANTINE_CAP {
            QUARANTINE[QUARANTINE_HEAD] = addr;
            QUARANTINE_HEAD = (QUARANTINE_HEAD + 1) % QUARANTINE_CAP;
            QUARANTINE_COUNT += 1;
        } else {
            // 隔离区满：记录并丢弃（直接丢弃该页，不回收）
            QUARANTINE_FULL_COUNT += 1;
            if QUARANTINE_FULL_COUNT <= 10 || QUARANTINE_FULL_COUNT % 100 == 0 {
                q_log_full();
            }
            // 动态扩容（仅前几次，且未达上限）
            if QUARANTINE_CAP < QUARANTINE_MAX_CAP && QUARANTINE_FULL_COUNT <= 5 {
                QUARANTINE_CAP = (QUARANTINE_CAP * 2).min(QUARANTINE_MAX_CAP);
                crate::serial::write_str("QUARANTINE: expanded to ");
                crate::serial::write_dec(QUARANTINE_CAP as u64);
                crate::serial::write_str("\n");
            }
        }
    }
}

fn q_pop() -> Option<u64> {
    unsafe {
        if QUARANTINE_COUNT == 0 { return None; }
        let idx = (QUARANTINE_HEAD + QUARANTINE_MAX_CAP - QUARANTINE_COUNT) % QUARANTINE_MAX_CAP;
        let addr = QUARANTINE[idx];
        QUARANTINE_COUNT -= 1;
        pte_refc_inc(addr);
        Some(addr)
    }
}

fn q_log_full() {
    crate::serial::write_str("\n=== QUARANTINE FULL ===\n");
    crate::serial::write_str("count=");
    crate::serial::write_dec(unsafe { QUARANTINE_COUNT as u64 });
    crate::serial::write_str(" capacity=");
    crate::serial::write_dec(unsafe { QUARANTINE_CAP as u64 });
    crate::serial::write_str(" full_count=");
    crate::serial::write_dec(unsafe { QUARANTINE_FULL_COUNT as u64 });
    crate::serial::write_str(" cr3=0x");
    crate::serial::write_hex(crate::task::current_task_pml4());
    crate::serial::write_str(" task=");
    crate::serial::write_dec(crate::task::current_task_id());
    crate::serial::write_str("\n");
}

fn log_double_free(addr: u64, ctx: &str, order: usize, caller: u64) {
    crate::serial::write_str("\n=== DOUBLE-FREE DETECTED ===\n");
    crate::serial::write_str(" base=0x");
    crate::serial::write_hex(alloc_base());
    crate::serial::write_str(" pidx=");
    crate::serial::write_dec(phys_to_idx(addr));
    crate::serial::write_str(" addr=0x");
    crate::serial::write_hex(addr);
    crate::serial::write_str(" order=");
    crate::serial::write_dec(order as u64);
    crate::serial::write_str(" caller=0x");
    crate::serial::write_hex(caller);
    crate::serial::write_str(" ctx=");
    crate::serial::write_str(ctx);
    crate::serial::write_str(" type=");
    crate::serial::write_dec(page_type_get(addr) as u64);
    crate::serial::write_str(" used=");
    crate::serial::write_dec(used_set(phys_to_idx(addr)) as u64);
    crate::serial::write_str(" cr3=0x");
    crate::serial::write_hex(crate::task::current_task_pml4());
    crate::serial::write_str(" task=");
    crate::serial::write_dec(crate::task::current_task_id());
    let pidx = phys_to_idx(addr);
    if (pidx as usize) < DF_MAX_PAGES {
        crate::serial::write_str(" first_caller=0x");
        unsafe { crate::serial::write_hex(DF_LAST_CALLER[pidx as usize] as u64); }
        crate::serial::write_str(" first_order=");
        unsafe { crate::serial::write_dec(DF_LAST_ORDER[pidx as usize] as u64); }
    }
    crate::serial::write_str("\n");
}

// Per-page record of the MOST RECENT free. When a page is freed twice without
// an intervening alloc (used_clear sees an already-clear bit), the latch fires
// and dumps the first free site so the DOUBLE-FREE root cause can be found.
// Sized to cover the test rig (uses -m 512M -> ~130k pages); USED_BMP covers 8 GiB.
const DF_MAX_PAGES: usize = 1 << 18;
static mut DF_LAST_CALLER: [u32; DF_MAX_PAGES] = [0; DF_MAX_PAGES];
static mut DF_LAST_TICK: [u32; DF_MAX_PAGES] = [0; DF_MAX_PAGES];
static mut DF_LAST_ORDER: [u8; DF_MAX_PAGES] = [0; DF_MAX_PAGES];

fn df_record(pidx: u64, caller: u64, order: usize) {
    if (pidx as usize) >= DF_MAX_PAGES { return; }
    unsafe {
        DF_LAST_CALLER[pidx as usize] = caller as u32;
        DF_LAST_TICK[pidx as usize] = crate::pit::TICKS.load(Ordering::Relaxed) as u32;
        DF_LAST_ORDER[pidx as usize] = order as u8;
    }
}

fn df_latch(pidx: u64, caller: u64, order: usize) {
    unsafe {
        crate::serial::write_str("\n=== DOUBLE-FREE LATCH ===\n");
        crate::serial::write_str("page=0x");
        crate::serial::write_hex(pidx << 12);
        crate::serial::write_str(" pidx=");
        crate::serial::write_dec(pidx);
        crate::serial::write_str(" order=");
        crate::serial::write_dec(order as u64);
        crate::serial::write_str(" tick=");
        crate::serial::write_dec(crate::pit::TICKS.load(Ordering::Relaxed));
        crate::serial::write_str(" this_caller=0x");
        crate::serial::write_hex(caller);
        if (pidx as usize) < DF_MAX_PAGES {
            crate::serial::write_str(" first_caller=0x");
            crate::serial::write_hex(DF_LAST_CALLER[pidx as usize] as u64);
            crate::serial::write_str(" first_tick=");
            crate::serial::write_dec(DF_LAST_TICK[pidx as usize] as u64);
            crate::serial::write_str(" first_order=");
            crate::serial::write_dec(DF_LAST_ORDER[pidx as usize] as u64);
        }
        crate::serial::write_str(" cr3=0x");
        crate::serial::write_hex(crate::task::current_task_pml4());
        crate::serial::write_str(" task=");
        crate::serial::write_dec(crate::task::current_task_id());
        crate::serial::write_str("\n");
    }
}

/// Query helper: last recorded free site for a physical page.
pub fn df_info(phys: u64) -> (u32, u32, u8) {
    let pidx = phys_to_idx(phys) as usize;
    unsafe {
        if pidx < DF_MAX_PAGES {
            (DF_LAST_CALLER[pidx], DF_LAST_TICK[pidx], DF_LAST_ORDER[pidx])
        } else {
            (0, 0, 0)
        }
    }
}

/// Check if a physical page is in the reserved array.
pub fn is_reserved_page(addr: u64) -> bool {
    unsafe {
        let alloc = &*crate::memory::allocator();
        for i in 0..alloc.reserved_count {
            if alloc.reserved[i] == addr {
                return true;
            }
        }
        false
    }
}

/// Get the head of a free list for a given order.
pub fn free_list_head(order: usize) -> u64 {
    unsafe { crate::memory::allocator().free_lists[order] as u64 }
}

pub fn alloc_base() -> u64 {
    crate::memory::allocator().base
}

pub fn alloc_pages() -> u64 {
    crate::memory::allocator().pages
}

#[repr(C)]
struct Block {
    magic: u32,
    order: u32,
    next: *mut Block,
}

pub struct BuddyAllocator {
    base: u64,
    pages: u64,
    free_lists: [*mut Block; MAX_ORDER + 1],
    reserved: [u64; MAX_RESERVED],
    reserved_count: usize,
}

// The used-page bitmap tracks one bit per 4K physical page. It is sized for
// up to 8 GiB of RAM (2^21 pages); beyond that the helpers below degrade
// gracefully (skip tracking) instead of indexing out of bounds.
const USED_BMP_WORDS: usize = (1 << 21) / 64; // 32768 words = 8 GiB
static mut USED_BMP: [u64; USED_BMP_WORDS] = [0; USED_BMP_WORDS];

fn used_word(page: u64) -> (usize, u64) {
    ((page as usize) >> 6, 1u64 << ((page as usize) & 63))
}

fn used_set(page: u64) -> bool {
    let (w, b) = used_word(page);
    if w >= USED_BMP_WORDS { return false; }
    unsafe { (USED_BMP[w] & b) != 0 }
}

fn used_mark(page: u64) {
    let (w, b) = used_word(page);
    if w >= USED_BMP_WORDS { return; }
    unsafe { USED_BMP[w] |= b; }
}

fn used_clear(page: u64) {
    let (w, b) = used_word(page);
    if w >= USED_BMP_WORDS { return; }
    unsafe { USED_BMP[w] &= !b; }
}

impl BuddyAllocator {
    pub const fn new() -> Self {
        BuddyAllocator {
            base: 0,
            pages: 0,
            free_lists: [ptr::null_mut(); MAX_ORDER + 1],
            reserved: [0; MAX_RESERVED],
            reserved_count: 0,
        }
    }

    pub fn init(&mut self, base: u64, pages: u64) {
        self.base = base;
        self.pages = pages;
    }

    fn maybe_audit(&mut self) {
        unsafe {
            BUDDY_AUDIT_COUNTER += 1;
            if BUDDY_AUDIT_COUNTER % AUDIT_PERIOD == 0 {
                let _ = self.audit_free_lists();
            }
        }
    }

    fn audit_free_lists(&mut self) -> bool {
        unsafe {
            if AUDIT_ACTIVE {
                return true;
            }
            AUDIT_ACTIVE = true;
        }
        // Walk free lists and verify magic/order on each block
        for order in 0..=MAX_ORDER {
            let mut curr = self.free_lists[order];
            while !curr.is_null() {
                let block = unsafe { &*curr };
                if block.magic != MAGIC || block.order != order as u32 {
                    unsafe { AUDIT_ACTIVE = false; }
                    return false;
                }
                curr = block.next;
            }
        }
        unsafe { AUDIT_ACTIVE = false; }
        true
    }

    fn page_index(&self, addr: u64) -> u64 {
        (addr - self.base) / PAGE_SIZE
    }

    fn block_size(order: usize) -> u64 {
        PAGE_SIZE << order
    }

    fn addr_to_idx(&self, addr: u64) -> u64 {
        (addr - self.base) / PAGE_SIZE
    }

    fn idx_to_addr(&self, idx: u64) -> u64 {
        self.base + idx * PAGE_SIZE
    }

    fn is_managed(&self, addr: u64) -> bool {
        addr >= self.base && addr + PAGE_SIZE <= self.base + self.pages * PAGE_SIZE
    }

    pub fn add_region(&mut self, start: u64, size: u64) {
        let mut addr = start;
        let end = start + size;
        while addr + PAGE_SIZE <= end {
            let rem = end - addr;
            let order = max_order_for(addr, rem);
            self.free_one(addr, order);
            addr += Self::block_size(order as usize);
        }
    }


    /// Check if a block at addr with given order is currently on the free list.
    fn is_on_free_list(&self, addr: u64, order: usize) -> bool {
        let mut curr = self.free_lists[order];
        while !curr.is_null() {
            if curr as u64 == addr {
                return true;
            }
            unsafe { curr = (*curr).next; }
        }
        false
    }

    fn free_one(&mut self, addr: u64, order: u8) {
        if !self.is_managed(addr) { return; }
        // PTE 页 order=0：直接入 free list，不合并
        if order == 0 && page_type_get(addr) == PAGE_TYPE_PTE {
            unsafe {
                let h = &mut *(addr as *mut Block);
                h.magic = MAGIC;
                h.order = 0;
                h.next = self.free_lists[0];
                self.free_lists[0] = h;
            }
            return;
        }
        let mut cur = addr;
        let mut o = order;

        loop {
            if o as usize >= MAX_ORDER {
                break;
            }
            let buddy = cur ^ Self::block_size(o as usize);
            if !self.is_managed(buddy) {
                break;
            }
            unsafe {
                let h = &mut *(buddy as *mut Block);
                if h.magic == MAGIC && h.order == o as u32 && self.is_on_free_list(buddy, o as usize) {
                    self.remove_from_list(o as usize, h);
                    cur = if cur < buddy { cur } else { buddy };
                    o += 1;
                    continue;
                }
            }
            break;
        }

        unsafe {
            if self.is_on_free_list(cur, o as usize) {
                return;
            }
            let h = &mut *(cur as *mut Block);
            h.magic = MAGIC;
            h.order = o as u32;
            h.next = self.free_lists[o as usize];
            self.free_lists[o as usize] = h;
        }
    }

    pub fn alloc(&mut self, order: usize) -> Option<u64> {
        let _g = BUDDY_LOCK.lock();
        self.alloc_nolock(order)
    }

    fn alloc_nolock(&mut self, order: usize) -> Option<u64> {
        for o in order..=MAX_ORDER {
            let block = self.free_lists[o];
            if !block.is_null() {
                let addr = block as u64;
                let next = unsafe { (*block).next };
                if self.is_reserved(addr) {
                    self.free_lists[o] = next;
                    if !next.is_null() {
                        continue;
                    }
                    break;
                }
                unsafe {
                    let h = &mut *(addr as *mut Block);
                    h.magic = 0;
                    h.order = 0;
                    h.next = ptr::null_mut();
                }
                let pidx = self.page_index(addr);
                used_mark(pidx);
                crate::memory::buddy::untrack_freed_page(addr);
                self.free_lists[o] = next;

                for so in (order..o).rev() {
                    let buddy = addr + Self::block_size(so);
                    if !self.is_reserved(buddy) {
                        unsafe {
                            let h = &mut *(buddy as *mut Block);
                            h.magic = MAGIC;
                            h.order = so as u32;
                            h.next = self.free_lists[so];
                            self.free_lists[so] = h;
                        }
                    }
                }

                // 通用数据页标记
                page_type_set(addr, PAGE_TYPE_DATA);
                return Some(addr);
            }
        }
        None
    }

    /// Allocate a zeroed page (order 0) for page tables, guaranteeing clean PTEs.
    /// First tries to reclaim from quarantine (FIFO), otherwise allocates fresh.
    pub fn alloc_zeroed_page(&mut self) -> Option<u64> {
        let _g = BUDDY_LOCK.lock();
        // Try to reclaim from quarantine first (breaks free→realloc cycle)
        if let Some(addr) = q_pop() {
            unsafe { core::ptr::write_bytes(addr as *mut u8, 0, PAGE_SIZE as usize); }
            page_type_set(addr, PAGE_TYPE_PTE);
            pte_refc_inc(addr);
            // The page was previously freed (recorded in the double-free
            // tracker); reclaiming it makes a future free legitimate, so drop
            // the stale tracker entry to avoid a false ALLOCATOR DOUBLE-FREE.
            untrack_freed_page(addr);
            return Some(addr);
        }
        // Fallback: fresh allocation
        self.alloc_nolock(0).map(|addr| {
            unsafe { core::ptr::write_bytes(addr as *mut u8, 0, PAGE_SIZE as usize); }
            page_type_set(addr, PAGE_TYPE_PTE);
            pte_refc_inc(addr);
            addr
        })
    }

    pub fn free(&mut self, addr: u64, order: usize) {
        let _g = BUDDY_LOCK.lock();
        // Global double-free detection at allocator level
        if crate::memory::buddy::track_freed_page(addr) {
            return; // Double-free detected, silently return
        }

        // If the page was reserved, unreserve it first so it can be properly freed.
        // This handles the mallocng meta page which is reserved to prevent buddy
        // from reusing it during its lifetime, but must be freed when the task exits.
        if self.is_reserved(addr) {
            self.unreserve(addr);
        }
        let pidx = self.page_index(addr);
        let caller = core::intrinsics::return_address() as u64;
        let old_type = page_type_get(addr);
        if !used_set(pidx) || old_type == PAGE_TYPE_FREE {
            df_latch(pidx, caller, order);
            log_double_free(addr, "free", order, caller);
            return;
        }
        used_clear(pidx);
        page_type_set(addr, PAGE_TYPE_FREE);
        df_record(pidx, caller, order);

        // PTE 页：走引用计数，归零才真正释放（入隔离区）
        if order == 0 && old_type == PAGE_TYPE_PTE {
            if pte_refc_dec(addr) {
                q_push(addr);
            }
        } else {
            self.free_one(addr, order as u8);
        }
        self.maybe_audit();
    }

    pub fn mark_allocated(&mut self, start: u64, size: u64) {
        let _g = BUDDY_LOCK.lock();
        let mut addr = start;
        let end = start + size;
        while addr < end {
            let rem = end - addr;
            let order = max_order_for(addr, rem);
            self.remove_if_free(addr, order);
            addr += Self::block_size(order as usize);
        }
    }

    fn remove_if_free(&mut self, addr: u64, order: u8) {
        let block = addr as *mut Block;
        unsafe {
            if (*block).magic == MAGIC && (*block).order == order as u32 {
                self.remove_from_list(order as usize, &mut *block);
            }
        }
    }

    fn remove_from_list(&mut self, order: usize, target: &mut Block) {
        let mut curr = &mut self.free_lists[order];
        while !(*curr).is_null() {
            if *curr as *mut Block == target as *mut Block {
                *curr = (*target).next;
                target.magic = 0;
                return;
            }
            unsafe { curr = &mut (**curr).next; }
        }
    }

    pub fn total_pages(&self) -> u64 {
        self.pages
    }

    pub fn free_page_count(&self) -> u64 {
        let mut total = 0u64;
        for o in 0..=MAX_ORDER {
            let mut curr = self.free_lists[o];
            while !curr.is_null() {
                total += (1u64 << o) * (4096 / 4096);
                unsafe { curr = (*curr).next; }
            }
        }
        total
    }

    pub fn free_pages_by_order(&self) -> [u64; MAX_ORDER + 1] {
        let mut counts = [0u64; MAX_ORDER + 1];
        for o in 0..=MAX_ORDER {
            let mut curr = self.free_lists[o];
            while !curr.is_null() {
                counts[o] += 1;
                unsafe { curr = (*curr).next; }
            }
        }
        counts
    }

    pub fn used_page_count(&self) -> u64 {
        let mut total = 0u64;
        let end = ((self.base + self.pages * PAGE_SIZE - 1) / PAGE_SIZE) as usize + 1;
        for w in 0..USED_BMP_WORDS {
            let base_page = w as u64 * 64;
            if base_page >= end as u64 { break; }
            unsafe { total += USED_BMP[w].count_ones() as u64; }
        }
        total
    }

    pub fn reserved_count(&self) -> u64 {
        self.reserved_count as u64
    }

    pub fn reserve(&mut self, addr: u64) {
        // Idempotent: the same page may be reserved multiple times (e.g. the
        // mallocng meta page shared across fork COW copies).
        for i in 0..self.reserved_count {
            if self.reserved[i] == addr {
                return;
            }
        }
        if self.reserved_count < MAX_RESERVED {
            self.reserved[self.reserved_count] = addr;
            self.reserved_count += 1;
            // Also ensure it's not in free lists and mark it used so a later
            // used_clear (via free/free_reserved) won't report a false DOUBLE-FREE.
            self.mark_allocated(addr, PAGE_SIZE);
            let pidx = self.page_index(addr);
            if used_set(pidx) {
                // If it was already marked used, it was genuinely in use; keep as is.
            } else {
                used_mark(pidx);
            }
        }
    }

    /// Reserve a page to prevent it from being allocated. The page must already be allocated
    /// (i.e., removed from free lists and marked as used). This is used to pin pages
    /// for specific purposes like AP stacks before they are actually used.
    pub fn reserve_page(&mut self, addr: u64) {
        if !self.is_managed(addr) { return; }
        // Ensure the page is marked as used and not on free lists
        let pidx = self.page_index(addr);
        used_mark(pidx);
        page_type_set(addr, PAGE_TYPE_DATA);
        // Reserve it so it won't be freed accidentally
        self.reserve(addr);
    }

    /// Remove a page from the reserved list so it can be freed or reallocated.
    /// Returns true if the page was found and removed.
    pub fn unreserve(&mut self, addr: u64) -> bool {
        for i in 0..self.reserved_count {
            if self.reserved[i] == addr {
                // Remove by shifting remaining elements
                for j in i..self.reserved_count - 1 {
                    self.reserved[j] = self.reserved[j + 1];
                }
                self.reserved_count -= 1;
                self.reserved[self.reserved_count] = 0;
                return true;
            }
        }
        false
    }

    pub fn free_reserved(&mut self, addr: u64, order: usize) -> bool {
        let _g = BUDDY_LOCK.lock();
        if self.unreserve(addr) {
            let pidx = self.page_index(addr);
            let caller = core::intrinsics::return_address() as u64;
            let old_type = page_type_get(addr);
            if !used_set(pidx) || old_type == PAGE_TYPE_FREE {
                df_latch(pidx, caller, order);
                log_double_free(addr, "free_reserved", order, caller);
                return true;
            }
            used_clear(pidx);
            page_type_set(addr, PAGE_TYPE_FREE);
            df_record(pidx, caller, order);
            if order == 0 && old_type == PAGE_TYPE_PTE {
                if pte_refc_dec(addr) {
                    q_push(addr);
                }
            } else {
                self.free_one(addr, order as u8);
            }
            true
        } else {
            false
        }
    }

    pub fn is_reserved(&self, addr: u64) -> bool {
        for i in 0..self.reserved_count {
            if self.reserved[i] == addr {
                return true;
            }
        }
        false
    }
}

fn max_order_for(addr: u64, size: u64) -> u8 {
    let mut o = MAX_ORDER as u8;
    while o > 0 {
        let bs = BuddyAllocator::block_size(o as usize);
        if (addr & (bs - 1)) == 0 && bs <= size {
            return o;
        }
        o -= 1;
    }
    0
}

pub fn page_align_down(addr: u64) -> u64 {
    addr & !(PAGE_SIZE - 1)
}

pub fn page_align_up(addr: u64) -> u64 {
    (addr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

pub fn test(alloc: &mut BuddyAllocator) {
    let a0 = alloc.alloc(0);
    let a1 = alloc.alloc(1);
    let a2 = alloc.alloc(2);

    if let Some(addr) = a0 {
        alloc.free(addr, 0);
    }
    if let Some(addr) = a2 {
        alloc.free(addr, 2);
    }
    if let Some(addr) = a1 {
        alloc.free(addr, 1);
    }

    let big = alloc.alloc(4);
    if big.is_some() {
        alloc.free(big.unwrap(), 4);
    }

    let fail = alloc.alloc(11);
    if fail.is_none() {
        crate::serial::write_str("BUDDY: alloc > MAX_ORDER returns None (OK)\n");
    }
}