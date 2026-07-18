use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

const PIT_CH0: u16 = 0x40;
const PIT_CMD: u16 = 0x43;

pub const TIMER_IRQ: u8 = 0;

pub static TICKS: AtomicU64 = AtomicU64::new(0);

pub fn init(freq: u32) {
    let divisor = 1193180u32 / freq;
    unsafe {
        asm!(
            "mov al, 0x36",
            "out dx, al",
            in("dx") PIT_CMD,
            options(nostack, preserves_flags)
        );
        asm!(
            "out dx, al",
            in("al") (divisor as u8),
            in("dx") PIT_CH0,
            options(nostack, preserves_flags)
        );
        asm!(
            "out dx, al",
            in("al") ((divisor >> 8) as u8),
            in("dx") PIT_CH0,
            options(nostack, preserves_flags)
        );
    }
}
