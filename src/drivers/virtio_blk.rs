// virtio-blk driver (kernel temporary, will move to userspace later)
// Supports virtio 1.0 spec (modern) + legacy virtqueue

use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

extern crate alloc;
use alloc::boxed::Box;

use crate::memory::buddy::PAGE_SIZE;
use crate::serial;
use crate::task;

// Kernel-level PCI config read — bypasses privilege checks because this runs
// during kernel init (task 0) which has no user-space privileges.
const PCI_ADDR: u16 = 0xCF8;
const PCI_DATA: u16 = 0xCFC;

fn kernel_pci_read(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let addr: u32 = 0x8000_0000
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | (offset as u32 & 0xFC);
    let value: u32;
    unsafe {
        core::arch::asm!(
            "mov edx, {addr_port}",
            "out dx, eax",
            "mov edx, {data_port}",
            "in eax, dx",
            addr_port = const PCI_ADDR,
            data_port = const PCI_DATA,
            in("eax") addr,
            lateout("eax") value,
            options(nostack, nomem, preserves_flags)
        );
    }
    value
}

pub const VIRTIO_BLK_T_IN: u32 = 0;
pub const VIRTIO_BLK_T_OUT: u32 = 1;
pub const VIRTIO_BLK_T_FLUSH: u32 = 4;
pub const VIRTIO_BLK_S_OK: u8 = 0;
pub const VIRTIO_BLK_S_IOERR: u8 = 1;
pub const VIRTIO_BLK_S_UNSUPP: u8 = 2;

const VIRTIO_PCI_CAP_COMMON: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY: u8 = 2;
const VIRTIO_PCI_CAP_DEVICE: u8 = 4;

#[repr(C, packed)]
struct VirtioPciCap {
    cap_vndr: u8,
    cap_next: u8,
    cap_len: u8,
    cfg_type: u8,
    bar: u8,
    padding: [u8; 3],
    offset: u32,
    length: u32,
}

#[repr(C)]
struct VirtioPciCommonCfg {
    device_feature_select: u32,
    device_feature: u32,
    driver_feature_select: u32,
    driver_feature: u32,
    msix_config: u16,
    num_queues: u16,
    device_status: u8,
    config_generation: u8,
    queue_select: u16,
    queue_size: u16,
    queue_msix_vector: u16,
    queue_enable: u16,
    queue_notify_off: u16,
    queue_desc: u64,
    queue_driver: u64,
    queue_device: u64,
}

#[repr(C, packed)]
struct VirtioBlkConfig {
    capacity: u64,
    size_max: u32,
    seg_max: u32,
    geometry: VirtioBlkGeometry,
    blk_size: u32,
    topology: VirtioBlkTopology,
    writeback: u8,
    padding: [u8; 3],
    max_discard_sectors: u32,
    max_discard_seg: u32,
    discard_sector_alignment: u32,
    max_write_zeroes_sectors: u32,
    max_write_zeroes_seg: u32,
    write_zeroes_may_unmap: u8,
    padding2: [u8; 3],
}

#[repr(C, packed)]
struct VirtioBlkGeometry {
    cylinders: u16,
    heads: u8,
    sectors: u8,
}

#[repr(C, packed)]
struct VirtioBlkTopology {
    physical_block_exp: u8,
    alignment_offset: u8,
    min_io_size: u16,
    opt_io_size: u32,
}

#[repr(C, packed)]
struct VirtioBlkReq {
    type_: u32,
    ioprio: u32,
    sector: u64,
}

#[repr(C)]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;
const VIRTQ_DESC_F_INDIRECT: u16 = 4;

#[repr(C)]
struct VirtqAvail {
    flags: u16,
    idx: u16,
    ring: [u16; 0],
}

#[repr(C)]
struct VirtqUsedElem {
    id: u32,
    len: u32,
}

#[repr(C)]
struct VirtqUsed {
    flags: u16,
    idx: u16,
    ring: [VirtqUsedElem; 0],
}

const MAX_QUEUE_SIZE: usize = 256;

struct VirtQueue {
    queue_size: u16,
    desc: *mut VirtqDesc,
    avail: *mut VirtqAvail,
    used: *mut VirtqUsed,
    desc_phys: u64,
    avail_phys: u64,
    used_phys: u64,
    last_used_idx: u16,
    num_free: u16,
    free_list: [u16; MAX_QUEUE_SIZE],
    notify_off: u16,
    notify_base: *mut u8,
}

impl VirtQueue {
    fn new(common_cfg: *mut VirtioPciCommonCfg, queue_sel: u16, notify_base: *mut u8) -> Option<Self> {
        unsafe {
            (*common_cfg).queue_select = queue_sel;
            let queue_size = (*common_cfg).queue_size;
            if queue_size == 0 || queue_size as usize > MAX_QUEUE_SIZE {
                return None;
            }

            let alloc = crate::memory::allocator();
            let desc_pages = ((queue_size as usize * core::mem::size_of::<VirtqDesc>()) + PAGE_SIZE as usize - 1) / PAGE_SIZE as usize;
            let avail_pages = ((core::mem::size_of::<VirtqAvail>() + queue_size as usize * 2) + PAGE_SIZE as usize - 1) / PAGE_SIZE as usize;
            let used_pages = ((core::mem::size_of::<VirtqUsed>() + queue_size as usize * core::mem::size_of::<VirtqUsedElem>()) + PAGE_SIZE as usize - 1) / PAGE_SIZE as usize;

            let desc_phys = alloc.alloc(desc_pages)?;
            let avail_phys = alloc.alloc(avail_pages)?;
            let used_phys = alloc.alloc(used_pages)?;

            let desc = desc_phys as *mut VirtqDesc;
            let avail = avail_phys as *mut VirtqAvail;
            let used = used_phys as *mut VirtqUsed;

            core::ptr::write_bytes(desc as *mut u8, 0, desc_pages * PAGE_SIZE as usize);
            core::ptr::write_bytes(avail as *mut u8, 0, avail_pages * PAGE_SIZE as usize);
            core::ptr::write_bytes(used as *mut u8, 0, used_pages * PAGE_SIZE as usize);

            (*common_cfg).queue_desc = desc_phys;
            (*common_cfg).queue_driver = avail_phys;
            (*common_cfg).queue_device = used_phys;
            (*common_cfg).queue_enable = 1;

            let mut free_list = [0u16; MAX_QUEUE_SIZE];
            for i in 0..queue_size as usize {
                free_list[i] = i as u16;
            }

            let notify_off = (*common_cfg).queue_notify_off;

            Some(Self {
                queue_size,
                desc,
                avail,
                used,
                desc_phys,
                avail_phys,
                used_phys,
                last_used_idx: 0,
                num_free: queue_size,
                free_list,
                notify_off,
                notify_base: notify_base.add((*common_cfg).queue_notify_off as usize * 2),
            })
        }
    }

    fn allocate_desc(&mut self) -> Option<u16> {
        if self.num_free == 0 {
            return None;
        }
        let idx = self.free_list[(self.queue_size as usize - self.num_free as usize) as usize];
        self.num_free -= 1;
        Some(idx)
    }

    fn free_desc_chain(&mut self, mut head: u16) {
        unsafe {
            loop {
                let desc = &mut *self.desc.add(head as usize);
                let next = desc.next;
                self.free_list[(self.queue_size as usize - self.num_free as usize) as usize] = head;
                self.num_free += 1;
                if desc.flags & VIRTQ_DESC_F_NEXT == 0 {
                    break;
                }
                head = next;
            }
        }
    }

    fn add_buf(&mut self, head: u16, writable: bool, len: u32) {
        unsafe {
            let desc = &mut *self.desc.add(head as usize);
            desc.len = len;
            desc.flags = if writable { VIRTQ_DESC_F_WRITE } else { 0 };
        }
    }

    fn chain_desc(&mut self, head: u16, next: u16) {
        unsafe {
            let desc = &mut *self.desc.add(head as usize);
            desc.flags |= VIRTQ_DESC_F_NEXT;
            desc.next = next;
        }
    }

    fn kick(&self) {
        unsafe {
            core::arch::asm!(
                "mov dx, {0:x}",
                "mov ax, {1:x}",
                "out dx, ax",
                in(reg) self.notify_base as u16,
                in(reg) 0u16,
                options(nostack, preserves_flags)
            );
        }
    }

    fn get_used(&mut self) -> Option<(u16, u32)> {
        unsafe {
            let used = &*self.used;
            let idx = used.idx;
            if idx == self.last_used_idx {
                return None;
            }
            let ring_idx = (self.last_used_idx % self.queue_size) as usize;
            let elem = &(*self.used).ring[ring_idx];
            self.last_used_idx = self.last_used_idx.wrapping_add(1);
            Some((elem.id as u16, elem.len))
        }
    }
}

pub struct VirtioBlk {
    pci_bus: u8,
    pci_dev: u8,
    pci_func: u8,
    bar0: u64,
    bar0_len: u64,
    common_cfg: *mut VirtioPciCommonCfg,
    notify_base: *mut u8,
    device_cfg: *mut VirtioBlkConfig,
    queues: [Option<VirtQueue>; 2],
    capacity: u64,
    blk_size: u32,
    legacy_mode: bool,
    legacy_bar: u64,
    legacy_bar_port: u16,
    legacy_desc_phys: u64,
    legacy_avail_phys: u64,
    legacy_used_phys: u64,
    legacy_queue_size: u16,
    legacy_last_used_idx: u16,
    legacy_num_free: u16,
    legacy_free_list: [u16; MAX_QUEUE_SIZE],
}

static BLK_DEVICE: AtomicU64 = AtomicU64::new(0);

impl VirtioBlk {
    fn probe(bus: u8, dev: u8, func: u8) -> Option<Self> {
        let raw = kernel_pci_read(bus, dev, func, 0);
        let vendor = raw as u16;
        let device = (raw >> 16) as u16;
        if vendor != 0x1AF4 || (device != 0x1001 && device != 0x1042) {
            return None;
        }

        

        let bar0_raw = kernel_pci_read(bus, dev, func, 0x10);
        let bar0 = (bar0_raw as u64) & 0xFFFFFFF0;
        let bar0_len = 4096;

        let mut blk = VirtioBlk {
            pci_bus: bus,
            pci_dev: dev,
            pci_func: func,
            bar0,
            bar0_len,
            common_cfg: ptr::null_mut(),
            notify_base: ptr::null_mut(),
            device_cfg: ptr::null_mut(),
            queues: [None, None],
            capacity: 0,
            blk_size: 512,
            legacy_mode: false,
            legacy_bar: 0,
            legacy_bar_port: 0,
            legacy_desc_phys: 0,
            legacy_avail_phys: 0,
            legacy_used_phys: 0,
            legacy_queue_size: 0,
            legacy_last_used_idx: 0,
            legacy_num_free: 0,
            legacy_free_list: [0; MAX_QUEUE_SIZE],
        };

        if blk.init() {
            Some(blk)
        } else {
            None
        }
    }

    fn init(&mut self) -> bool {
        unsafe {
            // Parse PCI capability list to find virtio capabilities
            let mut cap_ptr = (kernel_pci_read(self.pci_bus, self.pci_dev, self.pci_func, 0x34) & 0xFF) as u8;
            
            while cap_ptr != 0 {
                let cap_dword = kernel_pci_read(self.pci_bus, self.pci_dev, self.pci_func, cap_ptr as u8);
                let cap_id = (cap_dword & 0xFF) as u8;
                let cap_next = ((cap_dword >> 8) & 0xFF) as u8;
                
                serial::write_str("virtio-blk: cap_ptr=");
                serial::write_hex(cap_ptr as u64);
                serial::write_str(" cap_id=");
                serial::write_hex(cap_id as u64);
                serial::write_str(" cap_next=");
                serial::write_hex(cap_next as u64);
                serial::write_str("\n");
                
if cap_id == 0x09 { // PCI_CAP_ID_VENDOR_SPECIFIC
                    // PCI vendor-specific capability (0x09) for virtio 1.0:
                    // Byte 0: cap_id (0x09)
                    // Byte 1: next_ptr
                    // Byte 2: length
                    // Byte 3: vendor-specific ID (0x02 for virtio)
                    // Byte 4: cfg_type
                    // Byte 5-7: BAR (3 bytes, low byte = BAR number)
                    // Byte 8-11: offset (4 bytes)
                    // Byte 12-15: length (4 bytes)
                    let aligned_ptr = cap_ptr & !3;
                    let cap_dword = kernel_pci_read(self.pci_bus, self.pci_dev, self.pci_func, aligned_ptr);
                    let vndr_id = ((cap_dword >> 24) & 0xFF) as u8;
                    let _cap_id_check = (cap_dword & 0xFF) as u8;
                    let _cap_next_check = ((cap_dword >> 8) & 0xFF) as u8;
                    
                    if vndr_id == 0x02 { // VIRTIO_PCI_CAP_VENDOR_SPECIFIC
                        let dword1 = kernel_pci_read(self.pci_bus, self.pci_dev, self.pci_func, (aligned_ptr + 4) as u8);
                        let cfg_type = (dword1 & 0xFF) as u8;
                        let bar = ((dword1 >> 8) & 0xFF) as u8;
                        let offset = kernel_pci_read(self.pci_bus, self.pci_dev, self.pci_func, (aligned_ptr + 8) as u8);
                        let length = kernel_pci_read(self.pci_bus, self.pci_dev, self.pci_func, (aligned_ptr + 12) as u8);
                        
                        serial::write_str("virtio-blk: found virtio cap, cfg_type=");
                        serial::write_hex(cfg_type as u64);
                        serial::write_str(" bar=");
                        serial::write_hex(bar as u64);
                        serial::write_str(" offset=");
                        serial::write_hex(offset as u64);
                        serial::write_str(" length=");
                        serial::write_dec(length as u64);
                        serial::write_str("\n");
                        serial::write_hex(cfg_type as u64);
                        serial::write_str(" bar=");
                        serial::write_hex(bar as u64);
                        serial::write_str(" offset=");
                        serial::write_hex(offset as u64);
                        serial::write_str(" length=");
                        serial::write_dec(length as u64);
                        serial::write_str("\n");
                        
                        let bar_addr = kernel_pci_read(self.pci_bus, self.pci_dev, self.pci_func, 0x10 + bar * 4) as u64 & 0xFFFFFFF0;
                        let base = (bar_addr + offset as u64) as *mut u8;
                        
                        match cfg_type {
                            VIRTIO_PCI_CAP_COMMON => {
                                self.common_cfg = base as *mut VirtioPciCommonCfg;
                                serial::write_str("virtio-blk: common_cfg found\n");
                            }
                            VIRTIO_PCI_CAP_NOTIFY => {
                                self.notify_base = base;
                                serial::write_str("virtio-blk: notify_base found\n");
                            }
                            VIRTIO_PCI_CAP_DEVICE => {
                                self.device_cfg = base as *mut VirtioBlkConfig;
                                serial::write_str("virtio-blk: device_cfg found\n");
                            }
                            _ => {}
                        }
                    }
                }
                
                cap_ptr = cap_next;
            }

            if self.common_cfg.is_null() || self.device_cfg.is_null() || self.notify_base.is_null() {
                
                return self.init_legacy();
            }

            (*self.common_cfg).device_status = 1;
            (*self.common_cfg).device_status = 3;
            (*self.common_cfg).device_feature_select = 0;
            let features = (*self.common_cfg).device_feature;
            serial::write_str("virtio-blk: device features = 0x");
            serial::write_hex(features as u64);
            serial::write_str("\n");

            (*self.common_cfg).driver_feature_select = 0;
            (*self.common_cfg).driver_feature = features;

            (*self.common_cfg).device_status = 7;

            let num_queues = (*self.common_cfg).num_queues;
            serial::write_str("virtio-blk: num_queues = ");
            serial::write_dec(num_queues as u64);
            serial::write_str("\n");

            let queues_to_use = core::cmp::min(num_queues, 2) as u16;
            for i in 0..queues_to_use {
                if let Some(vq) = VirtQueue::new(self.common_cfg, i, self.notify_base) {
                    self.queues[i as usize] = Some(vq);
                    serial::write_str("virtio-blk: queue ");
                    serial::write_dec(i as u64);
                    serial::write_str(" size=");
                    serial::write_dec((*self.common_cfg).queue_size as u64);
                    serial::write_str("\n");
                }
            }

            let cfg = &*self.device_cfg;
            self.capacity = cfg.capacity;
            self.blk_size = if cfg.blk_size == 0 { 512 } else { cfg.blk_size };

            serial::write_str("virtio-blk: capacity=");
            serial::write_dec(self.capacity);
            serial::write_str(" sectors, blk_size=");
            serial::write_dec(self.blk_size as u64);
            serial::write_str("\n");

            (*self.common_cfg).device_status = 15;

            true
        }
    }

    fn init_legacy(&mut self) -> bool {
        unsafe {
            
            
            let bar0_raw = kernel_pci_read(self.pci_bus, self.pci_dev, self.pci_func, 0x10);
            let bar0_raw_u64 = bar0_raw as u64;
            let bar0 = bar0_raw_u64 & 0xFFFFFFF0;
            
            let is_io = (bar0_raw & 1) != 0;
            let bar_addr = if is_io { bar0_raw_u64 & 0xFFFC } else { bar0 };
            
            if bar_addr == 0 {
                serial::write_str("virtio-blk: legacy BAR not configured\n");
                return false;
            }
            
            serial::write_str("virtio-blk: legacy BAR at ");
            serial::write_hex(bar_addr);
            serial::write_str(" (");
            serial::write_str(if is_io { "I/O" } else { "memory" });
            serial::write_str(")\n");
            
            let _bar_ptr = bar_addr as *mut u8;
            let bar_port = bar_addr as u16;
            
            // Reset device
            core::arch::asm!("out dx, al", in("dx") (bar_port + 0x12) as u16, in("al") 0u8, options(nostack, nomem, preserves_flags));
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            
            // Set ACKNOWLEDGE status
            core::arch::asm!("out dx, al", in("dx") (bar_port + 0x12) as u16, in("al") 1u8, options(nostack, nomem, preserves_flags));
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            
            // Set DRIVER status
            core::arch::asm!("out dx, al", in("dx") (bar_port + 0x12) as u16, in("al") 3u8, options(nostack, nomem, preserves_flags));
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            
            // Read device features
            let features = {
                let mut val: u32;
                core::arch::asm!("in eax, dx", in("dx") bar_port, lateout("eax") val, options(nostack, nomem, preserves_flags));
                val
            };
            
            
            // Acknowledge features. Mask off VIRTIO_F_EVENT_IDX (bit 29) so the
            // device uses the standard virtqueue layout (avail ring has no
            // used_event tail field), keeping our descriptor-area math in sync.
            let features = features & !(1u32 << 29);
            core::arch::asm!("out dx, eax", in("dx") (bar_port + 0x04) as u16, in("eax") features, options(nostack, nomem, preserves_flags));
            
            // Set FEATURES_OK status (before queue setup)
            core::arch::asm!("out dx, al", in("dx") (bar_port + 0x12) as u16, in("al") 7u8, options(nostack, nomem, preserves_flags));
            
            // Read config space for capacity from I/O port
            let capacity_port = (bar_addr + 20) as u16;
            let capacity_low = {
                let mut val: u32;
                core::arch::asm!("in eax, dx", in("dx") capacity_port, lateout("eax") val, options(nostack, nomem, preserves_flags));
                val
            };
            let capacity_high = {
                let mut val: u32;
                let port = capacity_port + 4;
                core::arch::asm!("in eax, dx", in("dx") port, lateout("eax") val, options(nostack, nomem, preserves_flags));
                val
            };
            self.capacity = ((capacity_high as u64) << 32) | (capacity_low as u64);
            self.blk_size = 512;
            
            
            
            if self.setup_legacy_virtqueue(bar_port).is_err() {
                return false;
            }
            
            // Set DRIVER_OK status (after queue setup per virtio spec)
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            core::arch::asm!("out dx, al", in("dx") (bar_port + 0x12) as u16, in("al") 15u8, options(nostack, nomem, preserves_flags));
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            
            // Verify DRIVER_OK was accepted
            let verify_status = {
                let mut val: u8;
                core::arch::asm!("in al, dx", 
                    in("dx") (bar_port + 0x12) as u16, 
                    lateout("al") val, 
                    options(nostack, nomem, preserves_flags));
                val
            };
            serial::write_str("virtio-blk: DRIVER_OK status = 0x");
            serial::write_hex(verify_status as u64);
            serial::write_str("\n");
            
            // Read queue address register to verify
            let qaddr_lo = {
                let mut val: u32;
                core::arch::asm!("in eax, dx", 
                    in("dx") (bar_port + 0x08) as u16, 
                    lateout("eax") val, 
                    options(nostack, nomem, preserves_flags));
                val
            };
            serial::write_str("virtio-blk: QueueAddress low = 0x");
            serial::write_hex(qaddr_lo as u64);
            serial::write_str("\n");
            
            self.legacy_mode = true;
            self.legacy_bar = bar_addr;
            self.legacy_bar_port = bar_port;
            
            
            true
        }
    }

    fn setup_legacy_virtqueue(&mut self, bar_port: u16) -> Result<(), &'static str> {
        unsafe {
            // Select queue 0
            core::arch::asm!("out dx, al", in("dx") (bar_port + 0x0E) as u16, in("al") 0u8, options(nostack, nomem, preserves_flags));
            
            // Read queue size
            let queue_size = {
                let mut val: u16;
                core::arch::asm!("in ax, dx", in("dx") (bar_port + 0x0C) as u16, lateout("ax") val, options(nostack, nomem, preserves_flags));
                val
            };
            
            if queue_size == 0 {
                return Err("queue size is 0");
            }
            
            let alloc = crate::memory::allocator();
            let queue_size = queue_size as usize;
            
            // For legacy virtio, the entire virtqueue must be a single contiguous region:
            // - Descriptor table: queue_size * 16 bytes
            // - Avail ring: 4 + queue_size * 2 bytes (4-byte header: flags + idx)
            // - Used ring: 4 + queue_size * 8 bytes (4-byte header: flags + idx)
            let desc_size = queue_size * 16;
            let avail_size = 4 + queue_size * 2;
            let used_size = 4 + queue_size * 8;

            // Legacy virtio layout (single shared region):
            // - Descriptor table: queue_size * 16 bytes (16-byte aligned)
            // - Available ring: 4 + queue_size*2 bytes, starts right after desc
            // - Used ring: MUST be aligned to a page (4096) boundary
            let avail_offset = desc_size as u64; // desc_size is a multiple of 16
            let used_offset = (((avail_offset + avail_size as u64) + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)) as u64;
            let total_size = used_offset + used_size as u64;

            let pages = ((total_size + PAGE_SIZE - 1) / PAGE_SIZE) as usize;
            let base_phys = alloc.alloc(pages).ok_or("failed to alloc virtqueue")?;
            core::ptr::write_bytes(base_phys as *mut u8, 0, pages * PAGE_SIZE as usize);
            
            let desc_phys = base_phys;
            let avail_phys = base_phys + avail_offset;
            let used_phys = base_phys + used_offset;

            // Initialize avail ring header
            let avail = avail_phys as *mut VirtqAvail;
            (*avail).flags = 0;
            (*avail).idx = 0;
            
            // Initialize used ring header
            let used = used_phys as *mut VirtqUsed;
            (*used).flags = 0;
            (*used).idx = 0;
            
            // Write queue address to device. Legacy virtio QueueAddress register
            // expects a PFN (physical page frame number), NOT a byte address:
            // the device computes the descriptor-table physical address as
            // (value << 12). Pass desc_phys >> 12.
            let queue_pfn = ((desc_phys >> 12) & 0xFFFFFFFF) as u32;
            core::arch::asm!("out dx, eax", in("dx") (bar_port + 0x08) as u16, in("eax") queue_pfn, options(nostack, nomem, preserves_flags));
            
            // Store virtqueue info
            self.legacy_desc_phys = desc_phys;
            self.legacy_avail_phys = avail_phys;
            self.legacy_used_phys = used_phys;
            self.legacy_queue_size = queue_size as u16;
            self.legacy_last_used_idx = 0;
            self.legacy_num_free = queue_size as u16;
            for i in 0..queue_size {
                self.legacy_free_list[i] = i as u16;
            }
            
            
            Ok(())
        }
    }
}

pub fn init_virtio_blk() {
    for bus in 0..=255 {
        for dev in 0..32 {
            for func in 0..8 {
                if let Some(blk) = VirtioBlk::probe(bus, dev, func) {
                    let ptr = Box::into_raw(Box::new(blk));
                    BLK_DEVICE.store(ptr as u64, Ordering::SeqCst);
                    serial::write_str("virtio-blk: initialized\n");
                    return;
                }
            }
        }
    }
    serial::write_str("virtio-blk: no device found\n");
}

pub fn virtio_blk_read(sector: u64, buf: *mut u8, count: u32) -> Result<u32, i64> {
    let ptr = BLK_DEVICE.load(Ordering::SeqCst);
    if ptr == 0 {
        return Err(-1);
    }
    let blk = unsafe { &mut *(ptr as *mut VirtioBlk) };
    blk.read_sector(sector, buf, count)
}

pub fn virtio_blk_write(sector: u64, buf: *const u8, count: u32) -> Result<u32, i64> {
    let ptr = BLK_DEVICE.load(Ordering::SeqCst);
    if ptr == 0 {
        return Err(-1);
    }
    let blk = unsafe { &mut *(ptr as *mut VirtioBlk) };
    blk.write_sector(sector, buf, count)
}

pub fn virtio_blk_capacity() -> u64 {
    let ptr = BLK_DEVICE.load(Ordering::SeqCst);
    if ptr == 0 {
        return 0;
    }
    let blk = unsafe { &*(ptr as *const VirtioBlk) };
    blk.capacity
}

pub fn virtio_blk_block_size() -> u32 {
    let ptr = BLK_DEVICE.load(Ordering::SeqCst);
    if ptr == 0 {
        return 512;
    }
    let blk = unsafe { &*(ptr as *const VirtioBlk) };
    blk.blk_size
}

impl VirtioBlk {
    fn submit_req(&mut self, queue_idx: usize, type_: u32, sector: u64, data: *mut u8, len: u32, writable: bool) -> Option<u16> {
        if self.legacy_mode {
            return None;
        }
        let vq = self.queues[queue_idx].as_mut()?;
        let head = vq.allocate_desc()?;

        let req_phys = unsafe {
            let alloc = crate::memory::allocator();
            let phys = alloc.alloc(0)?;
            let req = phys as *mut VirtioBlkReq;
            (*req).type_ = type_;
            (*req).ioprio = 0;
            (*req).sector = sector;
            phys
        };

        vq.add_buf(head, false, core::mem::size_of::<VirtioBlkReq>() as u32);
        unsafe {
            let desc = &mut *vq.desc.add(head as usize);
            desc.addr = req_phys;
        }

        let data_head = if len > 0 {
            let data_idx = vq.allocate_desc()?;
            vq.add_buf(data_idx, writable, len);
            unsafe {
                let desc = &mut *vq.desc.add(data_idx as usize);
                desc.addr = data as u64;
            }
            vq.chain_desc(head, data_idx);
            data_idx
        } else {
            head
        };

        let status_phys = unsafe {
            let alloc = crate::memory::allocator();
            let phys = alloc.alloc(0)?;
            core::ptr::write_bytes(phys as *mut u8, 0xFF, 1);
            phys
        };
        let status_idx = vq.allocate_desc()?;
        vq.add_buf(status_idx, true, 1);
        unsafe {
            let desc = &mut *vq.desc.add(status_idx as usize);
            desc.addr = status_phys;
        }
        vq.chain_desc(data_head, status_idx);

        unsafe {
            (*vq.avail).ring[(*vq.avail).idx as usize % vq.queue_size as usize] = head;
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            (*vq.avail).idx = (*vq.avail).idx.wrapping_add(1);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        vq.kick();

        Some(head)
    }

    pub fn read_sector(&mut self, sector: u64, buf: *mut u8, count: u32) -> Result<u32, i64> {
        if self.legacy_mode {
            return self.legacy_read_sector(sector, buf, count);
        }
        let head = self.submit_req(0, VIRTIO_BLK_T_IN, sector, buf, count * self.blk_size, true)
            .ok_or(-1)?;

        loop {
            if let Some((id, _len)) = self.queues[0].as_mut().and_then(|vq| vq.get_used()) {
                if id == head {
                    let vq = self.queues[0].as_mut().unwrap();
                    vq.free_desc_chain(head);
                    return Ok(count);
                }
            }
            task::yield_now();
        }
    }

    pub fn write_sector(&mut self, sector: u64, buf: *const u8, count: u32) -> Result<u32, i64> {
        if self.legacy_mode {
            return self.legacy_write_sector(sector, buf, count);
        }
        let head = self.submit_req(0, VIRTIO_BLK_T_OUT, sector, buf as *mut u8, count * self.blk_size, false)
            .ok_or(-1)?;

        loop {
            if let Some((id, _len)) = self.queues[0].as_mut().and_then(|vq| vq.get_used()) {
                if id == head {
                    let vq = self.queues[0].as_mut().unwrap();
                    vq.free_desc_chain(head);
                    return Ok(count);
                }
            }
            task::yield_now();
        }
    }

    fn legacy_read_sector(&mut self, sector: u64, buf: *mut u8, count: u32) -> Result<u32, i64> {
        self.legacy_submit_req(VIRTIO_BLK_T_IN, sector, buf, count * self.blk_size, true)
    }

    fn legacy_write_sector(&mut self, sector: u64, buf: *const u8, count: u32) -> Result<u32, i64> {
        self.legacy_submit_req(VIRTIO_BLK_T_OUT, sector, buf as *mut u8, count * self.blk_size, false)
    }

    fn legacy_submit_req(&mut self, type_: u32, sector: u64, data: *mut u8, len: u32, writable: bool) -> Result<u32, i64> {
        unsafe {
            let _bar_port = self.legacy_bar_port;
            
            let alloc = crate::memory::allocator();
            let req_phys = alloc.alloc(0).ok_or(-1)?;
            let req = req_phys as *mut VirtioBlkReq;
            (*req).type_ = type_;
            (*req).ioprio = 0;
            (*req).sector = sector;
            
            let data_phys = if len > 0 {
                let phys = alloc.alloc(0).ok_or(-1)?;
                core::ptr::copy_nonoverlapping(data, phys as *mut u8, len as usize);
                phys
            } else {
                0
            };
            
            let status_phys = alloc.alloc(0).ok_or(-1)?;
            core::ptr::write_bytes(status_phys as *mut u8, 0xFF, 1);
            
            let head = self.legacy_allocate_desc().ok_or(-1)?;
            let mut current = head;
            
            // Request descriptor
            {
                let desc = self.legacy_get_desc(current);
                (*desc).addr = req_phys;
                (*desc).len = core::mem::size_of::<VirtioBlkReq>() as u32;
                (*desc).flags = 0;
            }
            
            let mut last = current;
            current = self.legacy_allocate_desc().ok_or(-1)?;
            self.legacy_chain_desc(last, current);
            
            if len > 0 {
                {
                    let desc = self.legacy_get_desc(current);
                    (*desc).addr = data_phys;
                    (*desc).len = len;
                    (*desc).flags = if writable { VIRTQ_DESC_F_WRITE } else { 0 };
                }
                last = current;
                current = self.legacy_allocate_desc().ok_or(-1)?;
                self.legacy_chain_desc(last, current);
            }
            
            // Status descriptor
            {
                let desc = self.legacy_get_desc(current);
                (*desc).addr = status_phys;
                (*desc).len = 1;
                (*desc).flags = VIRTQ_DESC_F_WRITE;
            }
            
            // Add to avail ring
            {
                let avail = self.legacy_avail_phys as *mut VirtqAvail;
                let idx = (*avail).idx as usize % self.legacy_queue_size as usize;
                let ring_ptr = (avail as *mut u8).add(4) as *mut u16; // skip flags (2) + idx (2) = 4
                { *ring_ptr.add(idx) = head; }
                core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
                (*avail).idx = (*avail).idx.wrapping_add(1);
            }
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

            // Kick the queue
            core::arch::asm!("out dx, ax", in("dx") (self.legacy_bar_port + 0x10) as u16, in("ax") 0u16, options(nostack, nomem, preserves_flags));

            let mut timeout = 1000000;
            loop {
                if let Some((id, _len)) = self.legacy_get_used() {
                    if id == head {
                        // For read requests the device wrote the data into the
                        // kernel page at data_phys; copy it back to the caller buf.
                        if writable && len > 0 {
                            core::ptr::copy_nonoverlapping(data_phys as *mut u8, data, len as usize);
                        }
                        self.legacy_free_desc_chain(head);
                        let alloc = crate::memory::allocator();
                        alloc.free(req_phys, 0);
                        if len > 0 {
                            alloc.free(data_phys, 0);
                        }
                        alloc.free(status_phys, 0);
                        return Ok(len);
                    }
                }
                task::yield_now();
                timeout -= 1;
                if timeout == 0 {
                    serial::write_str("virtio-blk: legacy timeout waiting for completion\n");
                    return Err(-1);
                }
            }
        }
    }

    fn legacy_allocate_desc(&mut self) -> Option<u16> {
        if self.legacy_num_free == 0 {
            return None;
        }
        let idx = self.legacy_free_list[(self.legacy_queue_size as usize - self.legacy_num_free as usize) as usize];
        self.legacy_num_free -= 1;
        Some(idx)
    }

    fn legacy_get_desc(&self, idx: u16) -> *mut VirtqDesc {
        (self.legacy_desc_phys + (idx as u64 * 16)) as *mut VirtqDesc
    }

    fn legacy_chain_desc(&mut self, head: u16, next: u16) {
        unsafe {
            let desc = self.legacy_get_desc(head);
            (*desc).flags |= VIRTQ_DESC_F_NEXT;
            (*desc).next = next;
        }
    }

    fn legacy_free_desc_chain(&mut self, mut head: u16) {
        unsafe {
            loop {
                let desc = self.legacy_get_desc(head);
                let next = (*desc).next;
                self.legacy_free_list[(self.legacy_queue_size as usize - self.legacy_num_free as usize) as usize] = head;
                self.legacy_num_free += 1;
                if (*desc).flags & VIRTQ_DESC_F_NEXT == 0 {
                    break;
                }
                head = next;
            }
        }
    }

    fn legacy_get_used(&mut self) -> Option<(u16, u32)> {
        unsafe {
            let used = self.legacy_used_phys as *mut VirtqUsed;
            let idx = (*used).idx;
            if idx == self.legacy_last_used_idx {
                return None;
            }
            let ring_idx = (self.legacy_last_used_idx % self.legacy_queue_size) as usize;
            // Used ring: 6 bytes header (flags:2, idx:2, padding:2) + 8 bytes per element
            let ring_ptr = (used as *mut u8).add(4) as *mut VirtqUsedElem;
            let elem = { &*ring_ptr.add(ring_idx) };
            self.legacy_last_used_idx = self.legacy_last_used_idx.wrapping_add(1);
            Some((elem.id as u16, elem.len))
        }
    }
}
