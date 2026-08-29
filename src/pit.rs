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

// PIT channel 0 is initialized at 100 Hz, so one tick = 10000 µs. The delay is
// therefore us/10000 ticks. (Previously the formula used us*100/1000, which is a
// 1000x overestimate, making every wait_ms wait ~1000x too long — the SMP INIT/SIPI
// sequence alone took ~13 s instead of ~40 ms.)
pub fn wait_us(us: u32) {
    let start = TICKS.load(Ordering::Relaxed);
    let target = start + ((us as u64) / 10000).max(1);
    while TICKS.load(Ordering::Relaxed) < target {
        core::hint::spin_loop();
    }
}

pub fn wait_ms(ms: u32) {
    wait_us(ms * 1000);
}

pub fn mask_all() {
    // PIT channel 0 already runs; nothing to mask here (PIC handles IRQ0).
}
