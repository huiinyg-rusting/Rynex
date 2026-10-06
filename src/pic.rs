use core::arch::asm;

pub const PIC1_CMD: u16 = 0x20;
pub const PIC1_DATA: u16 = 0x21;
pub const PIC2_CMD: u16 = 0xA0;
pub const PIC2_DATA: u16 = 0xA1;

pub const ICW1_ICW4: u8 = 0x01;
pub const ICW1_INIT: u8 = 0x10;
pub const ICW4_8086: u8 = 0x01;

pub const IRQ_BASE: u8 = 0x30;

unsafe fn outb(port: u16, val: u8) {
    asm!("out dx, al", in("dx") port, in("al") val, options(nostack, preserves_flags));
}

unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    asm!("in al, dx", in("dx") port, out("al") val, options(nostack, preserves_flags));
    val
}

pub fn remap(offset1: u8, offset2: u8) {
    let a1 = unsafe { inb(PIC1_DATA) };
    let a2 = unsafe { inb(PIC2_DATA) };

    unsafe {
        outb(PIC1_CMD, ICW1_INIT | ICW1_ICW4);
        outb(PIC2_CMD, ICW1_INIT | ICW1_ICW4);
        outb(PIC1_DATA, offset1);
        outb(PIC2_DATA, offset2);
        outb(PIC1_DATA, 4);
        outb(PIC2_DATA, 2);
        outb(PIC1_DATA, ICW4_8086);
        outb(PIC2_DATA, ICW4_8086);
        outb(PIC1_DATA, a1);
        outb(PIC2_DATA, a2);
    }
}

pub fn mask_all() {
    unsafe {
        outb(PIC1_DATA, 0xFF);
        outb(PIC2_DATA, 0xFF);
    }
}

/// Unmask `irq`, and for a slave line also open the master's cascade input.
///
/// IRQ2 on the master is the cascade line the slave drives its requests onto.
/// A slave request reaches the CPU only through that line, and the master drops
/// it while IMR bit 2 is set. Boot masks every line and then unmasks IRQ 0 and
/// IRQ 1, so without this the cascade stays shut for the whole run and *no*
/// device IRQ in 8..16 can ever be delivered -- the slave's request just sits
/// there with its IRR bit set.
///
/// Measured signature of that state, which is what made this worth chasing
/// through the IOAPIC first: IRQ 0 and IRQ 1 work, IRQ 11 never fires its stub
/// even once, `driver_irq_edge` is never entered, and every `rynex_irq_wait`
/// expires on its 1000ms timeout with the interrupt counter still zero.
///
/// Ordering note: the slave is updated before the cascade is opened, so the
/// line is never briefly open onto a still-masked slave.
pub fn unmask(irq: u8) {
    unsafe {
        if irq >= 8 {
            outb(PIC2_DATA, inb(PIC2_DATA) & !(1 << (irq % 8)));
            outb(PIC1_DATA, inb(PIC1_DATA) & !(1 << 2));
        } else {
            outb(PIC1_DATA, inb(PIC1_DATA) & !(1 << irq));
        }
    }
}

/// Edge/Level Control Register, one bit per line per chip.
pub const PIC1_ELCR: u16 = 0x4D0;
pub const PIC2_ELCR: u16 = 0x4D1;

/// Switch `irq` from edge- to level-triggered mode.
///
/// This exists to make masking and not-missing-a-wakeup compatible, which
/// edge-triggered lines cannot be. `driver_irq_edge` masks the line to stop the
/// re-latch flood (the device holds INTA# until its ISR is read, and the 8259's
/// request latch outlives the EOI), but under edge triggering any edge raised
/// inside that mask window is simply discarded: the PIC latches transitions, not
/// levels, so reopening the line later re-latches nothing and the driver sleeps
/// through the very packet that woke it. Measured signature: `driver_irq_edge`
/// fires and the wait returns via its counter check, but the intervals in
/// between sit out the full 1000ms timeout while `rx_used` climbs the whole
/// time, holding ICMP RTT at 120-240ms.
///
/// Under level triggering the PIC keeps the request latched for as long as the
/// device holds the line, so an unmask while INTA# is still asserted delivers
/// immediately. Combined with masking in the handler that is the behaviour a
/// driver actually wants: at most one delivery per wait, and none ever lost.
pub fn set_level_triggered(irq: u8) {
    unsafe {
        let (port, bit) = if irq >= 8 {
            (PIC2_ELCR, 1u8 << (irq % 8))
        } else {
            (PIC1_ELCR, 1u8 << irq)
        };
        outb(port, inb(port) | bit);
    }
}

/// Read back a line's edge/level configuration. Truth is in the bit, not in the
/// write having appeared to succeed.
pub fn elcr_state() -> (u8, u8) {
    unsafe { (inb(PIC1_ELCR), inb(PIC2_ELCR)) }
}

pub fn mask(irq: u8) {
    unsafe {
        if irq >= 8 {
            outb(PIC2_DATA, inb(PIC2_DATA) | (1 << (irq % 8)));
            // Re-close the cascade only once every slave line is masked again;
            // shutting it while another slave IRQ is still open would silently
            // disable that one too.
            if inb(PIC2_DATA) == 0xFF {
                outb(PIC1_DATA, inb(PIC1_DATA) | (1 << 2));
            }
        } else {
            outb(PIC1_DATA, inb(PIC1_DATA) | (1 << irq));
        }
    }
}

/// Master/slave mask, request and in-service registers, for diagnosis.
///
/// The IRR is the interesting one: a set bit with nothing being delivered is
/// the difference between "the device never asserted" and "the PIC swallowed
/// it", which look identical from a driver's polling loop.
/// Caveat on the readback: on this QEMU the OCW3 select bits do not behave as
/// documented, so the returned irr/isr are not real readings -- they come back
/// equal to the corresponding imr. Only `imr` is trustworthy here, and it is
/// the one that matters: it is the cascade bit that decides whether a slave
/// IRQ can be delivered at all. Reported as DEBUG so it stays out of normal
/// logs, where a bogus irr/isr would read as evidence.
pub fn dump_state(tag: &str) {
    crate::klog::begin(crate::klog::LOG_DEBUG, crate::klog::FAC_SCHED);
    crate::klog::s("[PIC] ");
    crate::klog::s(tag);
    unsafe {
        // OCW3 select register, one bit pair: bit0 = next read is IRR, bit1 = next
        // read is ISR. Both are *sticky* -- they select the next DATA-port read
        // and stay selected until changed. So reading ISR/IRR here and walking
        // away leaves the chip pointed at the wrong register, and every later
        // `inb(PIC*_DATA)` in `mask`/`unmask` -- which are read-modify-write on
        // the IMR -- would then operate on ISR instead. One stray read can
        // re-mask the timer and keyboard, or open the cascade unexpectedly.
        //
        // Clearing the select (OCW3 with no bits set) restores DATA to meaning
        // IMR, which is what the rest of this file assumes. This has to happen
        // on the way out, not just at init, because this function runs from
        // `sys_irq_register` -- a live path, not a boot-time one.
        let rd = |cmd: u16, data: u16, sel: u8| -> u8 {
            outb(cmd, sel);
            inb(data)
        };
        let m_imr = inb(PIC1_DATA);
        let s_imr = inb(PIC2_DATA);
        let m_irr = rd(PIC1_CMD, PIC1_DATA, 0x0A);
        let s_irr = rd(PIC2_CMD, PIC2_DATA, 0x0A);
        let m_isr = rd(PIC1_CMD, PIC1_DATA, 0x0B);
        let s_isr = rd(PIC2_CMD, PIC2_DATA, 0x0B);
        outb(PIC1_CMD, 0x00); // null OCW3: clear the select, DATA reads IMR again
        outb(PIC2_CMD, 0x00);
        crate::klog::s(" master imr=0x");
        crate::klog::hex(m_imr as u64);
        crate::klog::s(" irr=0x");
        crate::klog::hex(m_irr as u64);
        crate::klog::s(" isr=0x");
        crate::klog::hex(m_isr as u64);
        crate::klog::s(" slave imr=0x");
        crate::klog::hex(s_imr as u64);
        crate::klog::s(" irr=0x");
        crate::klog::hex(s_irr as u64);
        crate::klog::s(" isr=0x");
        crate::klog::hex(s_isr as u64);
    }
    crate::klog::end();
}

pub fn send_eoi(irq: u8) {
    if irq >= 8 {
        unsafe { outb(PIC2_CMD, 0x20); }
    }
    unsafe { outb(PIC1_CMD, 0x20); }
}
