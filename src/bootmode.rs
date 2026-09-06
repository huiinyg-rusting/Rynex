//! Boot-mode handoff bookkeeping.
//!
//! Decides, from the Multiboot2 info structure, whether the kernel was handed
//! off by UEFI (GRUB/EFI) or by the legacy BIOS path, and whether GRUB
//! provided a linear framebuffer. Also installs the framebuffer console
//! (crate::fb) when a usable framebuffer tag is present.
//!
//! UEFI detection uses the EFI tags of the Multiboot2 spec 2.0 (which is what
//! GRUB implements): EFI system-table pointers (11/12), EFI memory map (17),
//! EFI boot services not terminated (18) and EFI image handles (19/20).
//! None of those is ever set on a legacy BIOS boot, so the flag cannot
//! false-positive on the BIOS/gfxpayload path.

use core::sync::atomic::{AtomicBool, Ordering};

static UEFI_HANDOFF: AtomicBool = AtomicBool::new(false);
static ACPI_OLD: AtomicBool = AtomicBool::new(false);
static ACPI_NEW: AtomicBool = AtomicBool::new(false);

/// Parse the MBI once at kernel entry. Called single-threaded, very early,
/// before the banner is drawn (so the banner can already go to the fb).
pub fn init(info_addr: u32) {
    crate::multiboot2::dump_tag_types(info_addr);

    let uefi = crate::multiboot2::uefi_handoff(info_addr);
    UEFI_HANDOFF.store(uefi, Ordering::SeqCst);
    if uefi {
        crate::serial::write_str("BOOT: UEFI handoff (EFI tags present)\n");
    } else {
        crate::serial::write_str("BOOT: legacy BIOS handoff\n");
    }

    let (old, new) = crate::multiboot2::acpi_tags(info_addr);
    ACPI_OLD.store(old, Ordering::SeqCst);
    ACPI_NEW.store(new, Ordering::SeqCst);
    if old || new {
        crate::serial::write_str("BOOT: ACPI RSDP ");
        if old { crate::serial::write_str("old "); }
        if new { crate::serial::write_str("new "); }
        crate::serial::write_str("present\n");
    }

    if let Some(fbinfo) = crate::multiboot2::find_framebuffer(info_addr) {
        crate::serial::write_str("BOOT: framebuffer tag: ");
        crate::serial::write_dec(fbinfo.width as u64);
        crate::serial::write_char('x');
        crate::serial::write_dec(fbinfo.height as u64);
        crate::serial::write_char('x');
        crate::serial::write_dec(fbinfo.bpp as u64);
        crate::serial::write_str(" pitch=");
        crate::serial::write_dec(fbinfo.pitch as u64);
        crate::serial::write_str(" addr=0x");
        crate::serial::write_hex(fbinfo.addr);
        crate::serial::write_str(" type=");
        crate::serial::write_dec(fbinfo.fb_type as u64);
        crate::serial::write_str("\n");
        let fb = crate::fb::FbInfo {
            addr: fbinfo.addr,
            pitch: fbinfo.pitch,
            width: fbinfo.width,
            height: fbinfo.height,
            bpp: fbinfo.bpp,
            fb_type: fbinfo.fb_type,
            red_pos: fbinfo.red_pos,
            red_mask: fbinfo.red_mask,
            green_pos: fbinfo.green_pos,
            green_mask: fbinfo.green_mask,
            blue_pos: fbinfo.blue_pos,
            blue_mask: fbinfo.blue_mask,
        };
        crate::fb::init(&fb);
    } else {
        crate::serial::write_str("BOOT: no framebuffer tag; VGA text (0xB8000) fallback\n");
    }
}

/// Turn the validated, pending framebuffer into an active console. Must be
/// called AFTER paging::init(): fb::init merely validated and stored the tag,
/// but an LFB at ~0xFD000000 lies beyond the 1 GiB boot identity map and can
/// only be written once the kernel page tables can map it into the direct map.
pub fn install_framebuffer() {
    let ok = crate::fb::enable_console();
    if ok {
        crate::serial::write_str("BOOT: framebuffer console installed\n");
    }
}

/// True when the kernel was loaded through UEFI (GRUB EFI tags present).
pub fn is_uefi() -> bool {
    UEFI_HANDOFF.load(Ordering::Relaxed)
}

/// True when a linear framebuffer console is active (fb was found AND passed
/// validation AND was mapped in by install_framebuffer()).
pub fn has_framebuffer() -> bool {
    crate::fb::active()
}

/// ACPI RSDP copies supplied by GRUB: (old v1, new v2). Informational only.
pub fn acpi_rsdp() -> (bool, bool) {
    (ACPI_OLD.load(Ordering::Relaxed), ACPI_NEW.load(Ordering::Relaxed))
}