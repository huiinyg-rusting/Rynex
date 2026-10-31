//! Enough ACPI to answer one question: which IOAPIC redirection entry carries
//! a given legacy IRQ.
//!
//! This is not general ACPI support. It parses exactly the two MADT structure
//! types that matter for interrupt routing and nothing else:
//!
//!   Type 2, I/O APIC structure -- where this IOAPIC's inputs start in global
//!     system interrupt (GSI) numbering. `gsi_base` is at byte offset 8.
//!   Type 3, Interrupt Source Override -- the exceptions to the assumption that
//!     legacy IRQ n is GSI n. `source` is at byte offset 3 and the GSI it is
//!     redirected to is a u32 at byte offset 4.
//!
//! Why this matters: the IOAPIC numbers its redirection entries in GSI space,
//! which is independent of the 8259's IRQ numbering. Identity holds only for
//! IRQs the firmware did not override, and PCI devices sit at GSIs of their own
//! entirely. Programming entry `irq` and assuming it is that device's wire is
//! the kind of assumption that produces a machine which boots, passes every log
//! assertion, and then silently never delivers an interrupt.

use core::sync::atomic::{AtomicU64, Ordering};

/// Physical address of the ACPI 2.0+ RSDP, 0 if not found.
static RSDP: AtomicU64 = AtomicU64::new(0);
/// Physical address of the ACPI 1.0 RSDP, 0 if not found. Needed because GRUB on
/// a BIOS boot supplies only this one, and it reaches the tables through a 32
/// bit RSDT rather than an XSDT.
static RSDP_LEGACY: AtomicU64 = AtomicU64::new(0);

/// GSI that each legacy IRQ 0..16 is redirected to. Defaults to identity
/// (GSI == IRQ), which is the ACPI default and what applies when no override
/// structure is present.
static GSI_FOR_IRQ: [AtomicU64; 16] = [const { AtomicU64::new(0) }; 16];

/// GSI base of the first IOAPIC, and whether one was described.
static IOAPIC_GSI_BASE: AtomicU64 = AtomicU64::new(0);
static IOAPIC_FOUND: AtomicU64 = AtomicU64::new(0);

const MADT_HEADER_LEN: u64 = 44;
/// Stop walking on a malformed table rather than spinning: no real MADT has
/// anywhere near this many structures.
const MADT_MAX_STRUCTS: u64 = 512;
/// Likewise a bound on the XSDT pointer array.
const XSDT_MAX_ENTRIES: u64 = 256;

#[inline]
unsafe fn rd8(a: u64) -> u8 {
    core::ptr::read_volatile(a as *const u8)
}
#[inline]
unsafe fn rd16(a: u64) -> u16 {
    core::ptr::read_volatile(a as *const u16)
}
#[inline]
unsafe fn rd32(a: u64) -> u32 {
    core::ptr::read_volatile(a as *const u32)
}
#[inline]
unsafe fn rd64(a: u64) -> u64 {
    core::ptr::read_volatile(a as *const u64)
}

/// Read an ACPI signature (four ASCII bytes) as a u32 so it can be compared
/// against a packed constant.
#[inline]
fn sig4(a: u64) -> u32 {
    unsafe {
        u32::from_le_bytes([rd8(a), rd8(a + 1), rd8(a + 2), rd8(a + 3)])
    }
}

const SIG_APIC: u32 = u32::from_le_bytes([b'A', b'P', b'I', b'C']);

/// Record where the RSDP copies are: `rsdp_new` is the ACPI 2.0+ copy (with a
/// 64 bit XSDT pointer at offset 24), `rsdp_old` the 1.0 copy (with a 32 bit RSDT
/// pointer at the same offset). Both are kept because which one GRUB supplies
/// depends on the handoff, and the legacy one is the usual case on a BIOS boot.
pub fn set_rsdp(rsdp_new: u64, rsdp_old: u64) {
    RSDP.store(rsdp_new, Ordering::SeqCst);
    RSDP_LEGACY.store(rsdp_old, Ordering::SeqCst);
}

/// Parse the MADT and fill in the IRQ -> GSI map. Safe to call once; a machine
/// with no usable ACPI tables simply leaves everything at identity, which is
/// what the code did before this existed.
pub fn parse_madt() {
    let rsdp_new = RSDP.load(Ordering::Relaxed);
    let rsdp_old = RSDP_LEGACY.load(Ordering::Relaxed);
    if rsdp_new == 0 && rsdp_old == 0 {
        crate::serial::write_str("ACPI: no RSDP, IRQ routing assumes GSI == IRQ\n");
        return;
    }

    // Both RSDP revisions put a root-table pointer at offset 24; what differs is
    // its width and the table it names (XSDT vs RSDT). Try the 2.0+ copy first,
    // then the 1.0 copy -- a BIOS handoff supplies only the latter, so that is
    // the normal path here rather than an edge case.
    let mut found = false;
    for (rsdp, is_v2) in [(rsdp_new, true), (rsdp_old, false)] {
        if rsdp == 0 {
            continue;
        }
        unsafe {
            // "RSD PTR " occupies bytes 0..8, as two ASCII u32s.
            if sig4(rsdp) != u32::from_le_bytes([b'R', b'S', b'D', b' '])
                || rd32(rsdp + 4) != u32::from_le_bytes([b'P', b'T', b'R', b' '])
            {
                crate::serial::write_str("ACPI: RSDP signature bad at ");
                crate::serial::write_hex(rsdp);
                crate::serial::write_str(" got ");
                crate::serial::write_hex(sig4(rsdp) as u64);
                crate::serial::write_str("/");
                crate::serial::write_hex(rd32(rsdp + 4) as u64);
                crate::serial::write_str("\n");
                continue;
            }
            let (root, root_sig, ptr_size) = if is_v2 {
                (rd64(rsdp + 24), *b"XSDT", 8u64)
            } else {
                (rd32(rsdp + 24) as u64, *b"RSDT", 4u64)
            };
            if root == 0 || sig4(root) != u32::from_le_bytes(root_sig) {
                crate::serial::write_str("ACPI: root table pointer missing or bad\n");
                continue;
            }
            if scan_root_table(root, ptr_size) {
                found = true;
                break;
            }
        }
    }

    if !found {
        crate::serial::write_str("ACPI: no MADT found, IRQ routing assumes GSI == IRQ\n");
    }
}

/// Walk a root table (XSDT or RSDT) looking for the MADT. `ptr_size` is 8 for
/// XSDT entries and 4 for RSDT ones. Returns true if the MADT was found.
unsafe fn scan_root_table(root: u64, ptr_size: u64) -> bool {
    // Both root table headers are 36 bytes, followed by an array of pointers.
    let len = rd32(root + 4) as u64;
    if len < 36 {
        return false;
    }
    let n = ((len - 36) / ptr_size).min(XSDT_MAX_ENTRIES);
    let mut i = 0u64;
    while i < n {
        let addr = if ptr_size == 8 {
            rd64(root + 36 + i * 8)
        } else {
            rd32(root + 36 + i * 4) as u64
        };
        if addr == 0 {
            break;
        }
        if sig4(addr) == SIG_APIC {
            crate::serial::write_str("ACPI: found MADT at ");
            crate::serial::write_hex(addr);
            crate::serial::write_str("\n");
            parse_madt_body(addr);
            return true;
        }
        i += 1;
    }
    crate::serial::write_str("ACPI: no MADT in root table at ");
    crate::serial::write_hex(root);
    crate::serial::write_str("\n");
    false
}

fn parse_madt_body(madt: u64) {
    let len = unsafe { rd32(madt + 4) as u64 };
    if len < MADT_HEADER_LEN {
        return;
    }
    let end = madt + len;
    let mut off = madt + MADT_HEADER_LEN;
    let mut count = 0u64;
    let mut overrides = 0u64;

    while off + 2 <= end && count < MADT_MAX_STRUCTS {
        count += 1;
        let typ = unsafe { rd8(off) };
        let slen = unsafe { rd8(off + 1) } as u64;
        // A zero or over-long structure length would make the walk go backwards
        // or off the end; the spec guarantees 8..255.
        if slen < 2 || off + slen > end {
            crate::serial::write_str("ACPI: MADT structure length bad, stopping\n");
            break;
        }
        match typ {
            2 => {
                // I/O APIC structure: gsi_base at offset 8.
                if slen >= 12 {
                    let gsi_base = unsafe { rd32(off + 8) } as u64;
                    if IOAPIC_FOUND.swap(1, Ordering::SeqCst) == 0 {
                        IOAPIC_GSI_BASE.store(gsi_base, Ordering::SeqCst);
                    }
                    crate::serial::write_str("ACPI: MADT IOAPIC gsi_base=");
                    crate::serial::write_dec(gsi_base);
                    crate::serial::write_str("\n");
                }
            }
            3 => {
                // Interrupt Source Override: source u8 at 3, GSI u32 at 4.
                if slen >= 8 {
                    let src = unsafe { rd8(off + 3) } as usize;
                    let gsi = unsafe { rd32(off + 4) } as u64;
                    if src < 16 {
                        GSI_FOR_IRQ[src].store(gsi, Ordering::SeqCst);
                        overrides += 1;
                        crate::serial::write_str("ACPI: MADT override IRQ");
                        crate::serial::write_dec(src as u64);
                        crate::serial::write_str(" -> GSI");
                        crate::serial::write_dec(gsi);
                        crate::serial::write_str("\n");
                    }
                }
            }
            _ => {}
        }
        off += slen;
    }

    // Identity is the ACPI default, so fill in the IRQs nothing overrode.
    for i in 0..16 {
        if GSI_FOR_IRQ[i].load(Ordering::Relaxed) == 0 && i != 0 {
            GSI_FOR_IRQ[i].store(i as u64, Ordering::SeqCst);
        }
    }
    crate::serial::write_str("ACPI: MADT walked ");
    crate::serial::write_dec(count);
    crate::serial::write_str(" structures, ");
    crate::serial::write_dec(overrides);
    crate::serial::write_str(" IRQ overrides\n");
}

/// The redirection entry index (GSI) a legacy IRQ is delivered through.
/// Returns `irq` itself when ACPI says nothing different, which is the correct
/// answer for the identity-mapped ISA interrupts.
pub fn gsi_for_irq(irq: u8) -> usize {
    let i = irq as usize;
    if i >= 16 {
        return i;
    }
    let g = GSI_FOR_IRQ[i].load(Ordering::Relaxed);
    if g == 0 && i == 0 {
        0
    } else {
        g as usize
    }
}

/// GSI base of the IOAPIC MADT described, or 0 when none was.
pub fn ioapic_gsi_base() -> usize {
    IOAPIC_GSI_BASE.load(Ordering::Relaxed) as usize
}