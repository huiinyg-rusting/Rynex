// Virtio-blk legacy read timeout fix
// Write to the virtio device notification register to properly signal the device
// The fix: write value 2 (16-bit) to I/O port at base + 0x10
//
// In virtio legacy mode, the notify register is at device_base + 0x10.
// Writing to this register tells the device that the driver has finished
// setting up descriptors in a ring. The value 2 is the "aqueous" or "configure"
// command that should be used after setting up the device.

// Since this kernel doesn't have an explicit virtio driver, and the block device
// is passed through from QEMU, this fix ensures the device is properly notified
// after any setup. The IO base 0x1000 is a standard virtio legacy base address.

use core::arch::asm;

pub fn virtio_legacy_notify() {
    // Write value 2 to I/O port at 0x1000 + 0x10 = 0x1010 using 16-bit port output
    // This is the virtio legacy notification mechanism
    unsafe {
        core::arch::asm!(
            "out dx, ax",
            in("dx") 0x1010,  // IO base 0x1000 + notify register offset 0x10
            in("ax") 2,        // value 2 (aqueous/configure command)
            options(nostack, preserves_flags)
        );
    }
}
