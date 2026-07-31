use core::ptr;

pub const PAGE_SIZE: u64 = 4096;
pub const MAX_ORDER: usize = 10;
const MAX_RESERVED: usize = 32;

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
                if h.magic == MAGIC && h.order == o as u32 {
                    self.remove_from_list(o as usize, h);
                    cur = if cur < buddy { cur } else { buddy };
                    o += 1;
                    continue;
                }
            }
            break;
        }

        unsafe {
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
                self.free_lists[o] = unsafe { (*block).next };
                let addr = block as u64;

                for so in (order..o).rev() {
                    let buddy = addr + Self::block_size(so);
                    unsafe {
                        let h = &mut *(buddy as *mut Block);
                        h.magic = MAGIC;
                        h.order = so as u32;
                        h.next = self.free_lists[so];
                        self.free_lists[so] = h;
                    }
                }

                return Some(addr);
            }
        }
        None
    }

    pub fn free(&mut self, addr: u64, order: usize) {
        if self.is_reserved(addr) {
            return;
        }
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

    pub fn reserve(&mut self, addr: u64) {
        if self.reserved_count < MAX_RESERVED {
            self.reserved[self.reserved_count] = addr;
            self.reserved_count += 1;
            // Also ensure it's not in free lists
            self.mark_allocated(addr, PAGE_SIZE);
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