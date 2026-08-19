use core::ptr;

pub const PAGE_SIZE: u64 = 4096;
pub const MAX_ORDER: usize = 10;
const MAX_RESERVED: usize = 2048;

const MAGIC: u32 = 0xDEADBEEF;

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
        for o in order..=MAX_ORDER {
            let block = self.free_lists[o];
            if !block.is_null() {
                let addr = block as u64;
                let next = unsafe { (*block).next };
                if self.is_reserved(addr) {
                    // Skip reserved pages that somehow ended up in free lists.
                    // Advance to the next block in the same order list instead
                    // of skipping the rest of this order.
                    self.free_lists[o] = next;
                    if !next.is_null() {
                        continue;
                    }
                    break;
                }
                // Clear the header of the allocated block so it won't be mistaken for free during coalescing.
                unsafe {
                    let h = &mut *(addr as *mut Block);
                    h.magic = 0;
                    h.order = 0;
                    h.next = ptr::null_mut();
                }
                let pidx = self.page_index(addr);
                used_mark(pidx);
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

                return Some(addr);
            }
        }
        None
    }

    pub fn free(&mut self, addr: u64, order: usize) {
        // If the page was reserved, unreserve it first so it can be properly freed.
        // This handles the mallocng meta page which is reserved to prevent buddy
        // from reusing it during its lifetime, but must be freed when the task exits.
        if self.is_reserved(addr) {
            self.unreserve(addr);
        }
        let pidx = self.page_index(addr);
        used_clear(pidx);
        self.free_one(addr, order as u8);
    }

    pub fn mark_allocated(&mut self, start: u64, size: u64) {
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

    /// Remove a page from the reserved list and free it.
    /// Returns true if the page was reserved and has been freed.
    pub fn free_reserved(&mut self, addr: u64, order: usize) -> bool {
        if self.unreserve(addr) {
            let pidx = self.page_index(addr);
            used_clear(pidx);
            self.free_one(addr, order as u8);
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