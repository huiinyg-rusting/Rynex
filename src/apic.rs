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
    calibrate_once();
    let per_ms = TICKS_PER_MS.load(Ordering::SeqCst);
    write_reg(0x380, per_ms);
    write_reg(0x320, (1 << 17) | 0x20);
}

/// Measure the LAPIC timer rate and store the per-ms count in the global
/// TICKS_PER_MS. Does NOT start/arm the local LAPIC timer (the BSP quite
/// deliberately does not arm it — it uses the shared PIT). The AP arms its own
/// timer via init_ap_timer after this calibration has run.
pub unsafe fn calibrate_once() {
    if TIMER_CALIBRATED.load(Ordering::SeqCst) {
        return;
    }
    write_reg(0x3E0, 0x3);
    write_reg(0x380, 0xFFFF_FFFF);
    crate::pit::wait_ms(10);
    let cur = read_reg(0x390);
    let elapsed = 0xFFFF_FFFFu32.wrapping_sub(cur);
    let per_ms = (elapsed / 10).max(1);
    TICKS_PER_MS.store(per_ms, Ordering::SeqCst);
    TIMER_CALIBRATED.store(true, Ordering::SeqCst);
}

pub fn ticks_per_ms() -> u32 {
    TICKS_PER_MS.load(Ordering::SeqCst)
}

/// Program an AP's LAPIC timer as a periodic ~100Hz preemption/wakeup source on
/// the timer vector (0x20), matching the BSP's shared PIT rate. Calibration is
/// global (done once on the BSP); every LAPIC shares the same bus speed, so we
/// reuse TICKS_PER_MS. The BSP does NOT use this (it uses the PIT).
pub unsafe fn init_ap_timer() {
    let per_ms = TICKS_PER_MS.load(Ordering::SeqCst);
    if per_ms == 0 {
        return;
    }
    // ~100Hz => 10ms interval. Vector 0x21 = dedicated AP timer vector (its
    // handler is ap_timer_irq: EOI + return). Vector 0x20 is the BSP's PIT.
    let count = per_ms * 10;
    write_reg(0x3E0, 0x3);                    // divide by 1
    write_reg(0x380, count);                   // initial count
    write_reg(0x320, (1 << 17) | 0x21);        // periodic, unmasked, vector 0x21
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

// ── IOAPIC ───────────────────────────────────────────────────────────
//
// PCI interrupts must not be routed through the 8259. The PIC latches only a
// low-to-high transition, but a PCI device holds its interrupt line asserted
// until the driver clears the device's cause -- for virtio that means reading
// the ISR. So an edge-triggered 8259 in front of a virtio device either loses
// the very first interrupt (device asserted before the line was unmasked, so
// there is no edge to catch) or, once the line is high, re-latches that same
// high level back to back into a storm that livelocks the driver before it can
// run and read the ISR. Measured on this machine, not theorised: with the
// slave cascade fixed, netd wedges after its first transmit and the IRQ
// counter climbs past 47 while netd never gets scheduled again.
//
// The IOAPIC is the standard answer. Its redirection entries are level
// sensitive and are not re-delivered until the device drops the line, which is
// exactly the semantics a PCI device has, so the storm cannot form in the
// first place. QEMU has provided an IOAPIC all along; this kernel simply never
// touched it.

/// The IOAPIC's fixed physical window, mapped to `IOAPIC_BASE` by
/// `paging::map_ioapic_region`.
///
/// This is reached by memory access, exactly like the LAPIC. QEMU's
/// `info mtree` lists it the same way it lists the LAPIC
/// (`fec00000-fec00fff (prio 0, i/o): ioapic` next to
/// `fee00000-... (prio 4096, i/o): apic-msi`), and the `(i/o)` annotation
/// describes the *kind* of region -- one whose accesses go to device callbacks
/// rather than to RAM -- not the instruction class used to reach it. Reading it
/// with `in`/`out` on port 0xfec00000 returns all zeros, which is what briefly
/// made this look like a machine with no IOAPIC at all. There is no such split
/// between the two APIC components.
const IOAPIC_BASE: u64 = 0xFFFF_8000_FEC0_0000;

const IOAPIC_REG_ID: u32 = 0x00;
const IOAPIC_REG_VER: u32 = 0x01;
/// Redirection entries start at offset 0x10, 16 bytes each (low word, high word).
const IOAPIC_REG_REDIR: u32 = 0x10;

#[inline]
unsafe fn ioapic_rd(offset: u32) -> u32 {
    core::ptr::read_volatile((IOAPIC_BASE + offset as u64) as *const u32)
}

#[inline]
unsafe fn ioapic_wr(offset: u32, val: u32) {
    core::ptr::write_volatile((IOAPIC_BASE + offset as u64) as *mut u32, val);
}

/// Probe whether the IOAPIC can actually be programmed, by round-tripping a
/// pattern through a redirection entry rather than trusting the version
/// register.
///
/// The version register reads as zero here, and "version 0 means absent" is
/// exactly the conclusion this function was originally built on. That inference
/// does not hold: an absent device and a device we cannot reach look identical
/// in a register read, and there is no trustworthy second opinion available --
/// QEMU's monitor is not one, because `xp` reads the LAPIC ID register as
/// 0xffffffff, which no real LAPIC returns, so it plainly does not dispatch
/// MMIO the way the CPU does.
///
/// What *is* trustworthy is the kernel's own MMIO path, because it is already
/// proven good by an unrelated route: the boot log shows the LAPIC handing back
/// an interrupt command byte-for-byte after a write ("APIC: ICR=0x...4607").
/// So probe the way you would test a device rather than a datasheet field.
pub fn ioapic_present() -> bool {
    // Gated, because this is not a passive read.
    //
    // Answering the question means writing to things a wrong guess damages:
    // it maps a physical page into the kernel address space and never unmaps it
    // (so a page the PMM may later hand out gets aliased forever), it writes
    // the LAPIC TPR, and it pokes I/O ports 0x22/0x23 -- which on real hardware
    // are the ACPI PM1 event/control block, not an IOAPIC index window. On this
    // QEMU they are harmless; on a machine with a PM timer they are not.
    //
    // None of that is needed to make a routing decision. The IOAPIC is either
    // usable or it is not, and when it is not the 8259 route is already the
    // correct one -- so the default answer is "not present" and the probe only
    // runs for someone who has explicitly asked for diagnostics.
    //
    // Verified on the target platform: the window at 0xFEC00000 reads back all
    // zeros and writes do not land, on both `pc` and `q35`, so this probe can
    // only ever return false here. It is retained rather than deleted because
    // the MMIO question it asks is real and unanswered on other machines.
    if !crate::DEBUG_ENABLED.load(core::sync::atomic::Ordering::Relaxed) {
        return false;
    }
    unsafe {
        // Two facts have to be separated before anything else: does the
        // higher-half walk reach ordinary RAM, and does it reach a device
        // region? Both APIC components returning zero is equally consistent
        // with "the IOAPIC is absent" and "no MMIO works in this kernel", and
        // the second is much worse -- it would mean the LAPIC EOI has been a
        // no-op all along and the 8259 has been carrying the whole kernel.
        // Note that the boot log's "APIC: ICR=..." lines prove nothing here:
        // they print the value computed locally, before the write.
        crate::serial::write_str("APIC: MMIO diag\n");
        // 1) RAM through the same direct-map walk. 0x18000000 is ordinary RAM
        //    on a 512M machine and needs no devicestate.
        const RAM_VIRT: u64 = 0xFFFF_8000_1800_0000;
        const RAM_PHYS: u64 = 0x1800_0000;
        const RAM_PAT: u64 = 0xDEAD_BEEF_CAFE_F00D;
        if crate::paging::PageTableManager::map_kernel_page(RAM_VIRT, RAM_PHYS, 0x83).is_ok() {
            let p = RAM_VIRT as *mut u64;
            unsafe {
                let orig = core::ptr::read_volatile(p);
                core::ptr::write_volatile(p, RAM_PAT);
                let got = core::ptr::read_volatile(p);
                core::ptr::write_volatile(p, orig);
                crate::serial::write_str("APIC: diag RAM orig=0x");
                crate::serial::write_hex(orig);
                crate::serial::write_str(" wrote=0x");
                crate::serial::write_hex(RAM_PAT);
                crate::serial::write_str(" read=0x");
                crate::serial::write_hex(got);
                crate::serial::write_str(if got == RAM_PAT { " OK\n" } else { " MISMATCH\n" });
            }
        } else {
            crate::serial::write_str("APIC: diag RAM map failed\n");
        }
        // 2) A device region: the LAPIC's task-priority register, safe to write
        //    because it only gates interrupt delivery the kernel is not
        //    currently relying on at this point in boot.
        unsafe {
            let tpr_before = read_reg(0x80);
            write_reg(0x80, 0xA5);
            let tpr_after = read_reg(0x80);
            write_reg(0x80, tpr_before);
            crate::serial::write_str("APIC: diag LAPIC TPR before=0x");
            crate::serial::write_hex(tpr_before as u64);
            crate::serial::write_str(" wrote=0xa5 read=0x");
            crate::serial::write_hex(tpr_after as u64);
            crate::serial::write_str(if tpr_after == 0xA5 { " OK\n" } else { " MISMATCH\n" });
        }

        // 3) A second device, at a different address, with a config register
        //    whose value is unmistakable: the HPET at 0xFED00000. If the IOAPIC
        //    reads zero but the HPET reads its real capability bits, the fault
        //    is specific to that one region; if the HPET is zero too, something
        //    is shadowing the whole band below the LAPIC.
        const HPET: u64 = 0xFFFF_8000_FED0_0000;
        if crate::paging::PageTableManager::map_kernel_page(HPET, 0xFED0_0000, 0x83).is_ok() {
            unsafe {
                let cfg = core::ptr::read_volatile(HPET as *const u64);
                crate::serial::write_str("APIC: diag HPET cfg=0x");
                crate::serial::write_hex(cfg);
                crate::serial::write_str(if cfg != 0 { " NONZERO\n" } else { " ZERO\n" });
            }
        } else {
            crate::serial::write_str("APIC: diag HPET map failed\n");
        }
        // 4) The architectural index/data port window for the IOAPIC, which is
        //    a different path to the same registers. If the memory window is
        //    dead but this one answers, the device is fine and only the MMIO
        //    view of it is.
        unsafe {
            let outb = |p: u16, v: u8| {
                core::arch::asm!("out dx, al", in("dx") p, in("al") v, options(nostack, nomem, preserves_flags));
            };
            let inb = |p: u16| -> u8 {
                let v: u8;
                core::arch::asm!("in al, dx", in("dx") p, out("al") v, options(nostack, nomem, preserves_flags));
                v
            };
            outb(0x22, 0x01); // index = REGVER
            let pv = inb(0x23);
            outb(0x22, 0x10); // index = REDIR[0].low
            let r0 = inb(0x23);
            outb(0x22, 0x00); // index = REGID
            let id = inb(0x23);
            crate::serial::write_str("APIC: diag port-window REGVER=0x");
            crate::serial::write_hex(pv as u64);
            crate::serial::write_str(" REDIR0=0x");
            crate::serial::write_hex(r0 as u64);
            crate::serial::write_str(" REGID=0x");
            crate::serial::write_hex(id as u64);
            crate::serial::write_str("\n");
        }

        // 5) Access size. If the region rejects or mis-decomposes 32 bit accesses,
        //    single byte accesses at the same offsets will still round-trip,
        //    and the fix is simply to talk to it a byte at a time.
        unsafe {
            let rb = |o: u64| core::ptr::read_volatile((IOAPIC_BASE + o) as *const u8);
            let wb = |o: u64, v: u8| core::ptr::write_volatile((IOAPIC_BASE + o) as *mut u8, v);
            let s0 = rb(IOAPIC_REG_REDIR as u64);
            wb(IOAPIC_REG_REDIR as u64, 0x7B);
            let g0 = rb(IOAPIC_REG_REDIR as u64);
            wb(IOAPIC_REG_REDIR as u64, s0);
            crate::serial::write_str("APIC: diag IOAPIC byte +0x10 saved=0x");
            crate::serial::write_hex(s0 as u64);
            crate::serial::write_str(" wrote=0x7b read=0x");
            crate::serial::write_hex(g0 as u64);
            crate::serial::write_str(if g0 == 0x7B { " ROUNDTRIP\n" } else { " NO\n" });
            // REGVER's low byte sits at offset 1; if the version field is real it
            // must be non-zero there.
            let v = rb(1);
            crate::serial::write_str("APIC: diag IOAPIC REGVER low byte=0x");
            crate::serial::write_hex(v as u64);
            crate::serial::write_str("\n");
        }

        // The redirection table's stride is not something to assume. Two
        // plausible layouts give completely different behaviour, and picking
        // the wrong one produces an offset past the end of the table, where
        // the device neither stores nor returns anything -- which looks
        // exactly like "the IOAPIC is absent". So write a distinct masked
        // pattern at each of the first four words of the table, read them all
        // back, and let the hardware say which offsets are real.
        //
        // Every pattern sets bit 16 (interrupt_mask), so nothing is delivered
        // while the table is being poked, and all four words are restored
        // afterwards. Entries 0 and 1 are ISA IRQs 0 and 1; masked for the
        // duration of a few hundred instructions at init time, that costs
        // nothing.
        const PAT: [u32; 4] = [0x0001_0101, 0x0001_0202, 0x0001_0303, 0x0001_0404];
        let mut save = [0u32; 4];
        for i in 0..4 {
            let off = IOAPIC_REG_REDIR + i as u32 * 4;
            save[i] = ioapic_rd(off);
            ioapic_wr(off, PAT[i]);
        }
        let mut hits = 0u32;
        crate::serial::write_str("APIC: IOAPIC table probe:");
        for i in 0..4 {
            let off = IOAPIC_REG_REDIR + i as u32 * 4;
            let got = ioapic_rd(off);
            crate::serial::write_str(" +");
            crate::serial::write_hex((i * 4) as u64);
            crate::serial::write_str("=0x");
            crate::serial::write_hex(got as u64);
            if got == PAT[i] {
                hits += 1;
            }
            ioapic_wr(off, save[i]);
        }
        crate::serial::write_str(" hits=");
        crate::serial::write_dec(hits as u64);
        crate::serial::write_str("\n");

        // The version register lives at byte offset 1, not on a 4 byte boundary,
        // so read it byte by byte; a 32 bit load there is split into four byte
        // accesses by the access-size logic and reassembles into nonsense.
        crate::serial::write_str("APIC: IOAPIC REGVER bytes:");
        for b in 1..5u64 {
            let v = core::ptr::read_volatile((IOAPIC_BASE + b) as *const u8);
            crate::serial::write_str(" 0x");
            crate::serial::write_hex(v as u64);
        }
        crate::serial::write_str("\n");
        crate::serial::write_str("APIC: IOAPIC REGID byte0=0x");
        crate::serial::write_hex(core::ptr::read_volatile(IOAPIC_BASE as *const u8) as u64);
        crate::serial::write_str("\n");

        // Reachability = a word of the table actually stored what was written.
        // Comparing against the pre-write read would be trivially true on a
        // window that reads as zero, which is exactly the case being
        // diagnosed.
        let ok = hits > 0;
        if !ok {
            crate::serial::write_str(
                "APIC: IOAPIC probe FAILED, redirection table unreachable; device IRQs stay on the 8259\n",
            );
        }
        ok
    }
}

/// Destination mode: match the entry against the target's logical APIC id.
const IOAPIC_DM_LOGICAL: u32 = 1 << 11;
/// Delivery mode 0 = Fixed, one interrupt to one destination.
const IOAPIC_DELIVERY_FIXED: u32 = 0 << 8;
/// Polarity 0 = active high.
const IOAPIC_POLARITY_HIGH: u32 = 0 << 13;
/// Trigger mode 1 = level sensitive. The reason this whole path exists: a PCI
/// device holds its line high until the driver clears it, which only a level
/// sensitive entry models correctly.
const IOAPIC_TRIGGER_LEVEL: u32 = 1 << 15;
/// Interrupt mask 0 = deliver.
const IOAPIC_UNMASKED: u32 = 0 << 16;

/// Number of redirection entries to program.
///
/// The hardware reports this in REGVER, but that field reads zero on this
/// machine (measured), so it is reported for information only and the standard
/// 24 entries of the `pc` machine are used. Gating routing on the reported
/// value would disable every interrupt here for the same reason the probe does
/// not trust it.
pub fn ioapic_entry_count() -> usize {
    unsafe {
        let ver = ioapic_rd(IOAPIC_REG_VER);
        let reported = (ver & 0xFF) as usize + 1;
        if reported > 24 {
            reported
        } else {
            24
        }
    }
}

/// Read the delivery-status bit of one redirection entry: the field the IOAPIC
/// sets on the entry it is currently sending an interrupt for.
///
/// Bit 12 lives in the **low** word of the entry, not the high one -- the low
/// word holds vector, delivery mode, destination mode, this bit, polarity,
/// trigger mode and the mask.
pub unsafe fn ioapic_entry_pending(idx: usize) -> bool {
    (ioapic_rd(IOAPIC_REG_REDIR + (idx as u32) * 16) >> 12) & 1 != 0
}

/// Route GSI `gsi` to `vector` through the IOAPIC: level sensitive, active high,
/// unmasked, delivered to the calling CPU's logical APIC id.
///
/// The bit layout is the IOAPIC redirection table entry as a 64 bit value, so
/// note where the register boundary falls: `interrupt_mask` is bit 16, which is
/// the top bit of the LOW 32 bit register, and `destination` is bits 56-63,
/// which is the top byte of the HIGH register. Getting that wrong writes the
/// mask into the delivery mode and delivers to APIC 0 by accident.
pub unsafe fn ioapic_route_gsi(gsi: usize, vector: u8) -> bool {
    if gsi >= ioapic_entry_count() {
        return false;
    }
    let dest_apic_id = (read_reg(0x20) >> 24) as u32 & 0xFF;

    let low = (vector as u32 & 0xFF)
        | IOAPIC_DELIVERY_FIXED
        | IOAPIC_DM_LOGICAL
        | IOAPIC_POLARITY_HIGH
        | IOAPIC_TRIGGER_LEVEL
        | IOAPIC_UNMASKED;

    let high = (dest_apic_id & 0xFF) << 24;

    // Entry n occupies 16 bytes: the low word at +0, the high word at +8. With
    // memory-mapped access there is no index register to latch, so the two
    // writes are independent; the low word is read first only because the
    // delivery-status bit in it is worth logging.
    let off = IOAPIC_REG_REDIR + (gsi as u32) * 16;
    ioapic_wr(off, low);
    ioapic_wr(off + 8, high);
    true
}

/// Acknowledge an IOAPIC-sourced interrupt. Unlike the PIC there is no EOI for
/// the IOAPIC itself; the LAPIC EOI is what clears it, which `apic::eoi` does.
pub unsafe fn ioapic_eoi() {
    eoi();
}