// Block device abstraction layer
// Provides a simple interface for filesystems (ext3, etc.) to read/write blocks
// Backed by virtio-blk driver

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use crate::drivers::virtio_blk;
use crate::serial;

static BLOCK_DEVICE_READY: AtomicBool = AtomicBool::new(false);
static BLOCK_SIZE: AtomicU64 = AtomicU64::new(512);
static TOTAL_BLOCKS: AtomicU64 = AtomicU64::new(0);

/// Initialize the block device layer using virtio-blk
pub fn init_block_device() -> Result<(), &'static str> {
    virtio_blk::init_virtio_blk();
    
    let capacity = virtio_blk::virtio_blk_capacity();
    let blk_size = virtio_blk::virtio_blk_block_size();
    
    if capacity == 0 {
        return Err("No block device found");
    }
    
    TOTAL_BLOCKS.store(capacity, Ordering::SeqCst);
    BLOCK_SIZE.store(blk_size as u64, Ordering::SeqCst);
    BLOCK_DEVICE_READY.store(true, Ordering::SeqCst);
    
    serial::write_str("block: device ready, ");
    serial::write_dec(capacity);
    serial::write_str(" blocks of ");
    serial::write_dec(blk_size as u64);
    serial::write_str(" bytes\n");
    
    Ok(())
}

/// Read a block from the block device
/// Returns a pointer to the block data (valid until next read/write)
pub fn block_read(block: u64) -> Option<*mut u8> {
    if !BLOCK_DEVICE_READY.load(Ordering::SeqCst) {
        return None;
    }
    
    let _blk_size = BLOCK_SIZE.load(Ordering::SeqCst);
    if block >= TOTAL_BLOCKS.load(Ordering::SeqCst) {
        return None;
    }
    
    // Allocate a buffer for this block
    // In a real implementation, we'd use a buffer cache
    let alloc = unsafe { &mut *crate::memory::allocator() };
    let phys = alloc.alloc(0)?;
    
    let count = (BLOCK_SIZE.load(Ordering::SeqCst) / 512) as u32;
    match virtio_blk::virtio_blk_read(block * count as u64, phys as *mut u8, count) {
        Ok(_) => Some(phys as *mut u8),
        Err(_) => {
            let alloc = unsafe { &mut *crate::memory::allocator() };
            alloc.free(phys, 0);
            None
        }
    }
}

/// Write a block to the block device
pub fn block_write(block: u64, data: &[u8]) -> bool {
    if !BLOCK_DEVICE_READY.load(Ordering::SeqCst) {
        return false;
    }
    
    if block >= TOTAL_BLOCKS.load(Ordering::SeqCst) {
        return false;
    }
    
    let blk_size = BLOCK_SIZE.load(Ordering::SeqCst);
    let count = ((data.len() as u64 + blk_size - 1) / blk_size) as u32;
    
    virtio_blk::virtio_blk_write(block * count as u64, data.as_ptr(), count).is_ok()
}

/// Get the block size
pub fn get_block_size() -> u64 {
    BLOCK_SIZE.load(Ordering::SeqCst)
}

/// Get the total number of blocks
pub fn get_total_blocks() -> u64 {
    TOTAL_BLOCKS.load(Ordering::SeqCst)
}

/// Check if block device is ready
pub fn is_block_device_ready() -> bool {
    BLOCK_DEVICE_READY.load(Ordering::SeqCst)
}