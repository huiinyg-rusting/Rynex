use core::mem;

const TAG_MMAP: u32 = 6;
const TAG_MODULE: u32 = 3;
const TAG_END: u32 = 0;
const MMAP_USABLE: u32 = 1;

// Boot-information tag types (Multiboot2 spec 2.0, section 3.6).
const TAG_FRAMEBUFFER: u32 = 8;
// Framebuffer color formats
pub const FB_TYPE_INDEXED: u8 = 0;
pub const FB_TYPE_RGB: u8 = 1;
pub const FB_TYPE_EGA_TEXT: u8 = 2;

// EFI-related MBI tags. A UEFI handoff is signaled by the EFI system-table
// pointers (11/12), the EFI memory map (17), "EFI boot services not
// terminated" (18) and the EFI image handles (19/20). These are only ever
// set by GRUB when the kernel was loaded via UEFI; under legacy BIOS boot
// none of them is present.
const TAG_EFI32_SYS_TABLE: u32 = 11;
const TAG_EFI64_SYS_TABLE: u32 = 12;
const TAG_EFI_MMAP: u32 = 17;
const TAG_EFI_BS: u32 = 18;
const TAG_EFI32_IMAGE_HANDLE: u32 = 19;
const TAG_EFI64_IMAGE_HANDLE: u32 = 20;

// ACPI copies: tag 14 = ACPI old RSDP (v1), tag 15 = ACPI new RSDP (v2).
// Neither alone proves a UEFI handoff (BIOS GRUB supplies them too); they are
// exposed for informational logging only.
const TAG_ACPI_OLD: u32 = 14;
const TAG_ACPI_NEW: u32 = 15;

/// Structured framebuffer information parsed from tag 8.
#[derive(Clone, Copy)]
pub struct FramebufferInfo {
    /// Physical address of the linear framebuffer.
    pub addr: u64,
    /// Bytes per scanline.
    pub pitch: u32,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Bits per pixel.
    pub bpp: u8,
    /// 0 = indexed, 1 = direct RGB, 2 = EGA text.
    pub fb_type: u8,
    pub red_pos: u8,
    pub red_mask: u8,
    pub green_pos: u8,
    pub green_mask: u8,
    pub blue_pos: u8,
    pub blue_mask: u8,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct Info {
    total_size: u32,
    _reserved: u32,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct TagHeader {
    typ: u32,
    size: u32,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct ModuleTag {
    typ: u32,
    size: u32,
    mod_start: u32,
    mod_end: u32,
    cmdline: [u8; 1],
}

#[derive(Clone, Copy, Debug)]
pub struct ModuleInfo {
    pub start: u64,
    pub end: u64,
    /// Basename of the module's cmdline (e.g. "/boot/wthit" -> "wthit").
    /// NUL-terminated; empty if no cmdline was provided.
    pub name: [u8; 64],
}

pub fn find_modules(info_addr: u32, out: &mut [ModuleInfo]) -> usize {
    let total = unsafe { (*(info_addr as *const Info)).total_size };
    let mut count = 0;
    let mut offset = mem::size_of::<Info>() as u32;

    while offset + 8 <= total {
        let p = (info_addr as u64 + offset as u64) as *const u8;
        let typ = unsafe { core::ptr::read_unaligned(p as *const u32) };
        if typ == TAG_END {
            break;
        }
        let size = unsafe { core::ptr::read_unaligned(p.add(4) as *const u32) };
        if size < 8 {
            break;
        }
        if typ == TAG_MODULE && count < out.len() {
            let start = unsafe { core::ptr::read_unaligned(p.add(8) as *const u32) } as u64;
            let end = unsafe { core::ptr::read_unaligned(p.add(12) as *const u32) } as u64;
            let mut name = [0u8; 64];
            // cmdline string follows mod_end at offset 16 within the tag.
            let cmd = unsafe { p.add(16) };
            let mut ci = 0usize;
            while ci < 63 {
                let c = unsafe { core::ptr::read_volatile(cmd.add(ci)) };
                if c == 0 { break; }
                name[ci] = c;
                ci += 1;
            }
            // Reduce to basename (strip everything up to the last '/').
            let mut base_start = 0usize;
            for (j, &c) in name.iter().enumerate() {
                if c == 0 { break; }
                if c == b'/' { base_start = j + 1; }
            }
            let mut n = 0usize;
            for j in base_start..64 {
                let c = name[j];
                if c == 0 { break; }
                name[n] = c;
                n += 1;
            }
            for j in n..64 { name[j] = 0; }
            out[count] = ModuleInfo { start, end, name };
            count += 1;
        }
        offset += size;
        offset = (offset + 7) & !7;
    }
    count
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct MmapTag {
    _typ: u32,
    _size: u32,
    entry_size: u32,
    entry_version: u32,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct MmapEntry {
    base: u64,
    len: u64,
    typ: u32,
    _reserved: u32,
}

#[derive(Clone, Copy)]
pub struct MemRegion {
    pub base: u64,
    pub len: u64,
}

pub fn memory_regions(info_addr: u32, out: &mut [MemRegion]) -> usize {
    let info = info_addr as *const Info;
    let total = unsafe { (*info).total_size };
    let mut count = 0;
    let mut offset = mem::size_of::<Info>() as u32;

    while offset + 8 <= total {
        let p = (info_addr as u64 + offset as u64) as *const u8;
        let typ = unsafe { core::ptr::read_unaligned(p as *const u32) };

        if typ == TAG_END {
            break;
        }

        let size = unsafe { core::ptr::read_unaligned(p.add(4) as *const u32) };
        if size < 8 {
            break;
        }

        if typ == TAG_MMAP {
            let entry_size = unsafe {
                core::ptr::read_unaligned(p.add(8) as *const u32)
            };
            if entry_size < 20 {
                return count;
            }

            let mut entry_off = offset + 16;
            let entries_end = offset + size;

            while entry_off + entry_size <= entries_end && count < out.len() {
                let ep = (info_addr as u64 + entry_off as u64) as *const u8;
                let base = unsafe { core::ptr::read_unaligned(ep as *const u64) };
                let len = unsafe { core::ptr::read_unaligned(ep.add(8) as *const u64) };
                let etyp = unsafe { core::ptr::read_unaligned(ep.add(16) as *const u32) };
                if etyp == MMAP_USABLE && len > 0 {
                    out[count] = MemRegion { base, len };
                    count += 1;
                }
                entry_off += entry_size;
            }
            return count;
        }

        offset += size;
        offset = (offset + 7) & !7;
    }

    count
}

// ── Boot-mode handoff tags ────────────────────────────────────────────────

/// Parse tag 8 (framebuffer info). Returns None when no usable (or no)
/// framebuffer tag is present.
///
/// GRUB emits a packed `struct multiboot_tag_framebuffer`; the RGB color
/// descriptors start immediately after bpp/fb_type at tag byte offset 30.
/// We read them from both the GRUB-packed offset and the spec-padded offset
/// (the spec lists a reserved byte at 30, which some loaders honour) and
/// prefer the descriptor whose field values are self-consistent (mask sizes
/// 1..=8 and positions within the bpp), so either layout parses correctly.
pub fn find_framebuffer(info_addr: u32) -> Option<FramebufferInfo> {
    let total = unsafe { (*(info_addr as *const Info)).total_size };
    let mut offset = mem::size_of::<Info>() as u32;

    while offset + 8 <= total {
        let p = (info_addr as u64 + offset as u64) as *const u8;
        let typ = unsafe { core::ptr::read_unaligned(p as *const u32) };
        if typ == TAG_END {
            break;
        }
        let size = unsafe { core::ptr::read_unaligned(p.add(4) as *const u32) };
        if size < 8 {
            break;
        }
        if typ == TAG_FRAMEBUFFER && size >= 30 {
            let addr = unsafe { core::ptr::read_unaligned(p.add(8) as *const u64) };
            let pitch = unsafe { core::ptr::read_unaligned(p.add(16) as *const u32) };
            let width = unsafe { core::ptr::read_unaligned(p.add(20) as *const u32) };
            let height = unsafe { core::ptr::read_unaligned(p.add(24) as *const u32) };
            let bpp = unsafe { core::ptr::read_unaligned(p.add(28) as *const u8) };
            let fb_type = unsafe { core::ptr::read_unaligned(p.add(29) as *const u8) };

            // RGB descriptor candidates (see comment above).
            let rgb30 = read_rgb(p, 30);
            let rgb32 = read_rgb(p, 32);
            let rgb = if rgb30.is_sane(bpp) {
                rgb30
            } else if rgb32.is_sane(bpp) {
                rgb32
            } else {
                // No valid direct-RGB descriptor: rely on bpp defaults.
                default_rgb(bpp)
            };
            return Some(FramebufferInfo {
                addr,
                pitch,
                width,
                height,
                bpp,
                fb_type,
                red_pos: rgb.red_pos,
                red_mask: rgb.red_mask,
                green_pos: rgb.green_pos,
                green_mask: rgb.green_mask,
                blue_pos: rgb.blue_pos,
                blue_mask: rgb.blue_mask,
            });
        }
        offset += size;
        offset = (offset + 7) & !7;
    }
    None
}

#[derive(Clone, Copy)]
struct RgbDesc {
    red_pos: u8,
    red_mask: u8,
    green_pos: u8,
    green_mask: u8,
    blue_pos: u8,
    blue_mask: u8,
}

impl RgbDesc {
    fn is_sane(&self, bpp: u8) -> bool {
        let fields = [
            (self.red_pos, self.red_mask),
            (self.green_pos, self.green_mask),
            (self.blue_pos, self.blue_mask),
        ];
        let mut offs = [false; 32];
        for &(pos, mask) in &fields {
            if mask == 0 || mask > 8 {
                return false;
            }
            let top = pos as u32 + mask as u32;
            if top > 32 {
                return false;
            }
            // Fields must not overlap each other.
            for bit in pos..(pos + mask) {
                if offs[bit as usize] {
                    return false;
                }
                offs[bit as usize] = true;
            }
        }
        // Sanity: a field must not extend past the pixel width.
        self.red_pos + self.red_mask <= bpp
            && self.green_pos + self.green_mask <= bpp
            && self.blue_pos + self.blue_mask <= bpp
    }
}

fn read_rgb(p: *const u8, off: usize) -> RgbDesc {
    RgbDesc {
        red_pos: unsafe { core::ptr::read_unaligned(p.add(off) as *const u8) },
        red_mask: unsafe { core::ptr::read_unaligned(p.add(off + 1) as *const u8) },
        green_pos: unsafe { core::ptr::read_unaligned(p.add(off + 2) as *const u8) },
        green_mask: unsafe { core::ptr::read_unaligned(p.add(off + 3) as *const u8) },
        blue_pos: unsafe { core::ptr::read_unaligned(p.add(off + 4) as *const u8) },
        blue_mask: unsafe { core::ptr::read_unaligned(p.add(off + 5) as *const u8) },
    }
}

fn default_rgb(bpp: u8) -> RgbDesc {
    match bpp {
        15 => RgbDesc { red_pos: 10, red_mask: 5, green_pos: 5, green_mask: 5, blue_pos: 0, blue_mask: 5 },
        16 => RgbDesc { red_pos: 11, red_mask: 5, green_pos: 5, green_mask: 6, blue_pos: 0, blue_mask: 5 },
        24 => RgbDesc { red_pos: 16, red_mask: 8, green_pos: 8, green_mask: 8, blue_pos: 0, blue_mask: 8 },
        _ => RgbDesc { red_pos: 16, red_mask: 8, green_pos: 8, green_mask: 8, blue_pos: 0, blue_mask: 8 },
    }
}

/// True when the kernel was handed off through UEFI (EFI tags present in the
/// MBI). See constants above; tag numbers follow Multiboot2 spec 2.0 / GRUB.
pub fn uefi_handoff(info_addr: u32) -> bool {
    let total = unsafe { (*(info_addr as *const Info)).total_size };
    let mut offset = mem::size_of::<Info>() as u32;
    while offset + 8 <= total {
        let p = (info_addr as u64 + offset as u64) as *const u8;
        let typ = unsafe { core::ptr::read_unaligned(p as *const u32) };
        if typ == TAG_END {
            break;
        }
        let size = unsafe { core::ptr::read_unaligned(p.add(4) as *const u32) };
        if size < 8 {
            break;
        }
        match typ {
            TAG_EFI32_SYS_TABLE | TAG_EFI64_SYS_TABLE | TAG_EFI_MMAP
            | TAG_EFI_BS | TAG_EFI32_IMAGE_HANDLE | TAG_EFI64_IMAGE_HANDLE => {
                return true;
            }
            _ => {}
        }
        offset += size;
        offset = (offset + 7) & !7;
    }
    false
}

/// Report which ACPI RSDP copies GRUB supplied: (acpi_old, acpi_new).
/// Informational only — not a UEFI signal by itself.
pub fn acpi_tags(info_addr: u32) -> (bool, bool) {
    let total = unsafe { (*(info_addr as *const Info)).total_size };
    let mut offset = mem::size_of::<Info>() as u32;
    let mut old = false;
    let mut new = false;
    while offset + 8 <= total {
        let p = (info_addr as u64 + offset as u64) as *const u8;
        let typ = unsafe { core::ptr::read_unaligned(p as *const u32) };
        if typ == TAG_END {
            break;
        }
        let size = unsafe { core::ptr::read_unaligned(p.add(4) as *const u32) };
        if size < 8 {
            break;
        }
        match typ {
            TAG_ACPI_OLD => old = true,
            TAG_ACPI_NEW => new = true,
            _ => {}
        }
        offset += size;
        offset = (offset + 7) & !7;
    }
    (old, new)
}

/// Dump the raw tag table (types) to the serial port at boot, so the actual
/// handoff mode is visible in the log. Debug aid for UEFI/fb bring-up.
pub fn dump_tag_types(info_addr: u32) {
    crate::serial::write_str("MBI tags: ");
    let total = unsafe { (*(info_addr as *const Info)).total_size };
    let mut offset = mem::size_of::<Info>() as u32;
    while offset + 8 <= total {
        let p = (info_addr as u64 + offset as u64) as *const u8;
        let typ = unsafe { core::ptr::read_unaligned(p as *const u32) };
        if typ == TAG_END {
            break;
        }
        let size = unsafe { core::ptr::read_unaligned(p.add(4) as *const u32) };
        if size < 8 {
            break;
        }
        crate::serial::write_dec(typ as u64);
        crate::serial::write_char(' ');
        offset += size;
        offset = (offset + 7) & !7;
    }
    crate::serial::write_str("(end)\n");
}
