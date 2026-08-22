use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

const LAPIC_VIRT: u64 = 0xFFFF_8000_FEE0_0000;

static TIMER_CALIBRATED: AtomicBool = AtomicBool::new(false);
static TICKS_PER_MS: AtomicU32 = AtomicU32::new(0);

#[inline]
unsafe fn lapic_base() -> u64 {
    LAPIC_VIRT
}

pub unsafe fn init_lapic() {
    let mut low: u32 = 0;
    let mut high: u32 = 0;
    core::arch::asm!(
        "mov ecx, 0x1B",
        "rdmsr",
        out("eax") low,
        out("edx") high,
        out("ecx") _,
        options(nostack, preserves_flags)
    );
    // Verify base matches our mapping
    let base = ((high as u64) << 32) | (low as u64);
    let expected = base & 0xFFFF_FFFF_FFFF_F000;
    if expected != 0xFEE00000 {
        crate::serial::write_str("WARNING: LAPIC base mismatch!\n");
    }
    // Enable LAPIC: set Software Enable bit (bit 8) in Spurious Vector Register
    write_reg(0xF0, read_reg(0xF0) | (1 << 8));
}

#[inline]
pub unsafe fn read_reg(offset: u32) -> u32 {
    core::ptr::read_volatile((lapic_base() + offset as u64) as *const u32)
}

#[inline]
pub unsafe fn write_reg(offset: u32, val: u32) {
    core::ptr::write_volatile((lapic_base() + offset as u64) as *mut u32, val);
}

pub unsafe fn eoi() {
    write_reg(0xB0, 0);
}

pub unsafe fn init_timer() {
    if TIMER_CALIBRATED.load(Ordering::SeqCst) {
        return;
    }
    write_reg(0x3E0, 0x3);
    write_reg(0x380, 0xFFFF_FFFF);
    write_reg(0x320, (1 << 17) | 0x20);
    crate::pit::wait_ms(10);
    let cur = read_reg(0x390);
    let elapsed = 0xFFFF_FFFFu32.wrapping_sub(cur);
    let per_ms = (elapsed / 10).max(1);
    TICKS_PER_MS.store(per_ms, Ordering::SeqCst);
    write_reg(0x380, per_ms);
    TIMER_CALIBRATED.store(true, Ordering::SeqCst);
}

pub fn ticks_per_ms() -> u32 {
    TICKS_PER_MS.load(Ordering::SeqCst)
}

pub unsafe fn send_ipi(apic_id: u32, delivery_mode: u32, vector: u32, level: u32, trigger: u32) {
    crate::serial::write_str("APIC: sending IPI to ");
    crate::serial::write_hex(apic_id as u64);
    crate::serial::write_str(" mode=0x");
    crate::serial::write_hex(delivery_mode as u64);
    crate::serial::write_str(" vector=0x");
    crate::serial::write_hex(vector as u64);
    crate::serial::write_str(" level=");
    crate::serial::write_hex(level as u64);
    crate::serial::write_str(" trigger=");
    crate::serial::write_hex(trigger as u64);
    crate::serial::write_str("\n");
    
    // apic_id == 0xFFFF_FFFF => broadcast to all excluding self (destination shorthand)
    if apic_id == 0xFFFF_FFFF {
        write_reg(0x310, 0);
        let icr = delivery_mode | vector | (level & 0x1) << 14 | (trigger & 0x1) << 15 | (2 << 18);
        crate::serial::write_str("APIC: ICR=0x");
        crate::serial::write_hex(icr as u64);
        crate::serial::write_str("\n");
        write_reg(0x300, icr);
    } else {
        write_reg(0x310, apic_id << 24);
        let icr = delivery_mode | vector | (level & 0x1) << 14 | (trigger & 0x1) << 15;
        crate::serial::write_str("APIC: ICR=0x");
        crate::serial::write_hex(icr as u64);
        crate::serial::write_str("\n");
        write_reg(0x300, icr);
    }
    crate::serial::write_str("APIC: IPI sent\n");
    let _ = crate::pit::wait_us(1);
}

pub unsafe fn bsp_apic_id() -> u32 {
    read_reg(0x20) >> 24
}