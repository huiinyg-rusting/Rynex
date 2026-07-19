use core::sync::atomic::Ordering;
use crate::serial;
use crate::paging::{PageTableManager, PTE_PRESENT, PTE_WRITABLE, PTE_USER, PTE_NO_EXECUTE};

pub const IPC_VADDR: u64 = 0x6000_0000_0000;
pub const IPC_MSG_SIZE: usize = 64;
pub const IPC_SLOTS: usize = 63;

#[repr(C)]
struct IpcHeader {
    producer_seq: u32,
    consumer_seq: u32,
    flags: u32,
    msg_size: u32,
    partner_pid: u64,
    _reserved: [u8; 40],
}

#[repr(C)]
struct IpcMessage {
    msg_type: u32,
    length: u32,
    payload: [u8; 56],
}

fn ipc_header(phys: u64) -> &'static mut IpcHeader {
    unsafe { &mut *(phys as *mut IpcHeader) }
}

fn ipc_slot(phys: u64, slot: usize) -> &'static mut IpcMessage {
    unsafe {
        let addr = phys + 64 + (slot as u64) * (IPC_MSG_SIZE as u64);
        &mut *(addr as *mut IpcMessage)
    }
}

fn alloc_ipc_page() -> Option<u64> {
    let alloc = unsafe { &mut *crate::memory::allocator() };
    let phys = alloc.alloc(0)?;
    unsafe { core::ptr::write_bytes(phys as *mut u8, 0, 4096); }
    Some(phys)
}

fn free_ipc_page(phys: u64) {
    let alloc = unsafe { &mut *crate::memory::allocator() };
    alloc.free(phys, 0);
}

fn map_ipc_page(pml4: u64, phys: u64, vaddr: u64) -> Result<(), &'static str> {
    let flags = PTE_PRESENT | PTE_WRITABLE | PTE_USER | PTE_NO_EXECUTE;
    crate::paging::PageTableManager::map_into(pml4, vaddr, phys, flags)
}

fn unmap_ipc_page(pml4: u64, vaddr: u64) -> Result<(), &'static str> {
    // Directly update the page table via raw PML4 access
    // For now, just invalidate by clearing PTE
    let vpn = [
        ((vaddr >> 39) & 0x1FF) as usize,
        ((vaddr >> 30) & 0x1FF) as usize,
        ((vaddr >> 21) & 0x1FF) as usize,
        ((vaddr >> 12) & 0x1FF) as usize,
    ];

    let pml4 = pml4 as *mut crate::paging::PageTable;
    let pml4e = unsafe { (*pml4).0[vpn[0]] };
    if pml4e & PTE_PRESENT == 0 { return Err("not mapped"); }

    let pdpt = (pml4e & crate::paging::PTE_ADDR_MASK) as *mut crate::paging::PageTable;
    let pdpte = unsafe { (*pdpt).0[vpn[1]] };
    if pdpte & PTE_PRESENT == 0 { return Err("not mapped"); }

    let pd = (pdpte & crate::paging::PTE_ADDR_MASK) as *mut crate::paging::PageTable;
    let pde = unsafe { (*pd).0[vpn[2]] };
    if pde & PTE_PRESENT == 0 { return Err("not mapped"); }
    if pde & crate::paging::PTE_HUGE != 0 { return Err("huge page"); }

    let pt = (pde & crate::paging::PTE_ADDR_MASK) as *mut crate::paging::PageTable;
    unsafe { (*pt).0[vpn[3]] = 0; }
    Ok(())
}

pub fn shm_setup(partner_id: u64, vaddr: u64) -> i64 {
    let current = crate::task::current_task_id();
    if current == 0 || partner_id == 0 || current == partner_id {
        return -crate::task::EINVAL;
    }

    let partner = match crate::task::task_by_id(partner_id) {
        Some(t) => t,
        None => return -crate::task::ESRCH,
    };

    let cur_task = match crate::task::current_task() {
        Some(t) => t,
        None => return -crate::task::ESRCH,
    };

    if cur_task.ipc_partner != 0 || partner.ipc_partner != 0 {
        return -crate::task::EBUSY;
    }

    let phys = match alloc_ipc_page() {
        Some(p) => p,
        None => return -crate::task::ENOMEM,
    };

    if let Err(_) = map_ipc_page(partner.pml4, phys, vaddr) {
        free_ipc_page(phys);
        return -crate::task::EFAULT;
    }

    if let Err(_) = map_ipc_page(cur_task.pml4, phys, vaddr) {
        unmap_ipc_page(partner.pml4, vaddr).ok();
        free_ipc_page(phys);
        return -crate::task::EFAULT;
    }

    {
        let hdr = ipc_header(phys);
        hdr.partner_pid = partner_id;
    }

    cur_task.ipc_partner = partner_id;
    cur_task.ipc_phys = phys;
    cur_task.ipc_vaddr = vaddr;
    partner.ipc_partner = current;
    partner.ipc_phys = phys;
    partner.ipc_vaddr = vaddr;

    serial::write_str("IPC: shm_setup pid=");
    serial::write_dec(current);
    serial::write_str(" <-> pid=");
    serial::write_dec(partner_id);
    serial::write_str(" phys=0x");
    serial::write_hex(phys);
    serial::write_str(" vaddr=0x");
    serial::write_hex(vaddr);
    serial::write_str("\n");

    0
}

pub fn shm_notify(partner_id: u64) -> i64 {
    let current = crate::task::current_task_id();
    if current == 0 { return -crate::task::EINVAL; }

    let cur_task = match crate::task::current_task() {
        Some(t) => t,
        None => return -crate::task::ESRCH,
    };

    if cur_task.ipc_partner != partner_id {
        return -crate::task::EPERM;
    }

    // Wake partner by triggering futex_wake on the producer_seq field
    let vaddr = cur_task.ipc_vaddr;
    if vaddr == 0 {
        return -crate::task::EINVAL;
    }

    // Wake up to 1 task waiting on the IPC page
    let addr = vaddr as *const u32;
    crate::task::futex_wake(addr, 1);

    serial::write_str("IPC: shm_notify pid=");
    serial::write_dec(current);
    serial::write_str(" -> pid=");
    serial::write_dec(partner_id);
    serial::write_str("\n");

    0
}

pub fn shm_wait(timeout_ms: u64) -> i64 {
    let current = crate::task::current_task_id();
    if current == 0 { return -crate::task::EINVAL; }

    let cur_task = match crate::task::current_task() {
        Some(t) => t,
        None => return -crate::task::ESRCH,
    };

    let vaddr = cur_task.ipc_vaddr;
    if vaddr == 0 {
        return -crate::task::EINVAL;
    }

    let hdr = ipc_header(cur_task.ipc_phys);

    // Check if data already available
    if hdr.producer_seq != hdr.consumer_seq {
        return 0;
    }

    // Check if timeout = 0 (poll)
    if timeout_ms == 0 {
        return -crate::task::EAGAIN;
    }

    // Block on the producer_seq address using futex mechanism
    // We save the current consumer_seq - when it changes we wake up
    let saved_consumer = hdr.consumer_seq;
    let uaddr = vaddr as *const u32;

    let cur_task2 = crate::task::current_task().unwrap();
    cur_task2.blocked_on = uaddr as u64;
    cur_task2.state = crate::task::TaskState::Blocked;

    crate::task::schedule();

    0
}

pub fn shm_teardown(partner_id: u64) -> i64 {
    let current = crate::task::current_task_id();
    if current == 0 { return -crate::task::EINVAL; }

    let cur_task = match crate::task::current_task() {
        Some(t) => t,
        None => return -crate::task::ESRCH,
    };

    if cur_task.ipc_partner != partner_id {
        return -crate::task::EPERM;
    }

    let phys = cur_task.ipc_phys;
    let vaddr = cur_task.ipc_vaddr;

    if let Some(partner) = crate::task::task_by_id(partner_id) {
        if partner.ipc_phys == phys {
            unmap_ipc_page(partner.pml4, vaddr).ok();
            partner.ipc_partner = 0;
            partner.ipc_phys = 0;
            partner.ipc_vaddr = 0;
        }
    }

    unmap_ipc_page(cur_task.pml4, vaddr).ok();
    free_ipc_page(phys);

    cur_task.ipc_partner = 0;
    cur_task.ipc_phys = 0;
    cur_task.ipc_vaddr = 0;

    serial::write_str("IPC: shm_teardown pid=");
    serial::write_dec(current);
    serial::write_str("\n");

    0
}
