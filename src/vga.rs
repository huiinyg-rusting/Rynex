// Legacy VGA text-mode console (0xB8000) plus the console facade.
//
// This module is the single entry point for screen output. When a linear
// framebuffer was handed over by GRUB (see crate::fb / crate::bootmode) it
// routes every call to the framebuffer console; otherwise it keeps the
// original 0xB8000 text path untouched (BIOS/legacy regression is
// bit-for-bit the old behaviour).
//
// All ANSI CSI parsing (SGR colour, ED-erase, CUP-home) lives here; fb.rs
// only exposes the low-level text/drawing primitives.

const VGA_BUF: *mut u8 = 0xB8000 as *mut u8;
const WIDTH: usize = 80;
const HEIGHT: usize = 25;

static mut COL: usize = 0;
static mut ROW: usize = 0;

static mut FG: u8 = 0x0F;
static mut BG: u8 = 0x00;

fn using_fb() -> bool {
    crate::fb::active()
}

/// Translate a VGA 4-bit palette attribute to a 24-bit RGB value for the
/// framebuffer console (standard VGA palette; bright bit brightens).
fn vga_rgb(attr: u8) -> u32 {
    const BASE: [(u32, u32, u32); 8] = [
        (0x00, 0x00, 0x00),
        (0x00, 0x00, 0xAA),
        (0x00, 0xAA, 0x00),
        (0x00, 0xAA, 0xAA),
        (0xAA, 0x00, 0x00),
        (0xAA, 0x00, 0xAA),
        (0xAA, 0x55, 0x00),
        (0xAA, 0xAA, 0xAA),
    ];
    let i = (attr & 0x0F) as usize;
    let (mut r, mut g, mut b) = BASE[i & 7];
    if i & 8 != 0 {
        r = r.saturating_add(0x55).min(0xFF);
        g = g.saturating_add(0x55).min(0xFF);
        b = b.saturating_add(0x55).min(0xFF);
    }
    (r << 16) | (g << 8) | b
}

fn apply_fb_colors() {
    if using_fb() {
        crate::fb::set_color(vga_rgb(unsafe { FG }), vga_rgb(unsafe { BG }));
    }
}

pub fn write_char(c: char) {
    if using_fb() {
        crate::fb::write_char(c);
        return;
    }
    let b = if c.is_ascii() { c as u8 } else { b'?' };
    vga_put(b);
}

pub fn set_color(fg: u8, bg: u8) {
    unsafe {
        FG = fg & 0x0F;
        BG = bg & 0x0F;
    }
    apply_fb_colors();
}

fn color_attr() -> u8 {
    unsafe { (BG << 4) | FG }
}

pub fn clear() {
    if using_fb() {
        crate::fb::clear();
        return;
    }
    for y in 0..HEIGHT {
        for x in 0..WIDTH {
            let offset = (y * WIDTH + x) * 2;
            unsafe {
                VGA_BUF.add(offset).write_volatile(b' ');
                VGA_BUF.add(offset + 1).write_volatile(0x0F);
            }
        }
    }
    unsafe {
        COL = 0;
        ROW = 0;
    }
}

pub fn write_str(s: &str) {
    let mut cs = s.chars();
    while let Some(c) = cs.next() {
        if c == '\x1b' && cs.clone().next() == Some('[') {
            // ANSI CSI sequence: ESC [ params... final. final is the first
            // byte in 0x40..=0x7E after the '[' that starts the sequence.
            cs.next(); // consume '['
            let mut params: [u8; 64] = [0; 64];
            let mut plen = 0;
            let mut finalc = 0u8;
            loop {
                match cs.next() {
                    Some(nc) => {
                        let v = nc as u32;
                        if (0x40..=0x7E).contains(&v) {
                            finalc = v as u8;
                            break;
                        } else if plen < params.len() && v < 0x80 {
                            params[plen] = v as u8;
                            plen += 1;
                        }
                    }
                    None => {
                        // Truncated sequence: treat as SGR (harmless reset).
                        finalc = b'm';
                        break;
                    }
                }
            }
            let p = &params[..plen];
            if finalc == b'm' {
                parse_sgr(p);
            } else if finalc == b'J' {
                // Erase display: ESC[J / ESC[0J = to bottom, ESC[2J = all
                if p.is_empty() || p == b"0" {
                    erase_to_bottom();
                } else if p == b"2" {
                    clear_screen();
                }
            } else if finalc == b'H' {
                // Cursor home
                if using_fb() {
                    crate::fb::home();
                } else {
                    unsafe { COL = 0; ROW = 0; }
                    sync_cursor();
                }
            }
            continue;
        }
        match c {
            '\n' => {
                if using_fb() {
                    crate::fb::newline();
                } else {
                    vga_newline();
                }
            }
            '\r' => {
                if using_fb() {
                    crate::fb::carriage_return();
                } else {
                    unsafe { COL = 0; }
                    sync_cursor();
                }
            }
            '\x08' => {
                // Backspace: move cursor one column left and clear the cell.
                if using_fb() {
                    crate::fb::backspace();
                } else {
                    unsafe {
                        if COL > 0 {
                            COL -= 1;
                            let offset = (ROW * WIDTH + COL) * 2;
                            VGA_BUF.add(offset).write_volatile(b' ');
                            VGA_BUF.add(offset + 1).write_volatile(color_attr());
                            sync_cursor();
                        }
                    }
                }
            }
            '\t' => {
                let spaces = 4 - (unsafe { COL } % 4);
                for _ in 0..spaces {
                    write_char(' ');
                }
            }
            _ => write_char(c),
        }
    }
}

fn clear_screen() {
    if using_fb() {
        crate::fb::clear();
        return;
    }
    for y in 0..HEIGHT {
        for x in 0..WIDTH {
            let offset = (y * WIDTH + x) * 2;
            unsafe {
                VGA_BUF.add(offset).write_volatile(b' ');
                VGA_BUF.add(offset + 1).write_volatile(color_attr());
            }
        }
    }
}

fn erase_to_bottom() {
    if using_fb() {
        crate::fb::erase_to_bottom();
        return;
    }
    unsafe {
        let start = ROW * WIDTH + COL;
        for i in start..(HEIGHT * WIDTH) {
            let offset = i * 2;
            VGA_BUF.add(offset).write_volatile(b' ');
            VGA_BUF.add(offset + 1).write_volatile(color_attr());
        }
    }
}

fn sync_cursor() {
    unsafe {
        let pos = (ROW * WIDTH + COL) as u16;
        core::arch::asm!("out dx, al", in("dx") 0x3D4, in("al") 0x0Eu8, options(nostack, nomem));
        core::arch::asm!("out dx, al", in("dx") 0x3D5, in("al") (pos >> 8) as u8, options(nostack, nomem));
        core::arch::asm!("out dx, al", in("dx") 0x3D4, in("al") 0x0Fu8, options(nostack, nomem));
        core::arch::asm!("out dx, al", in("dx") 0x3D5, in("al") pos as u8, options(nostack, nomem));
    }
}

// Parse ANSI SGR (Select Graphic Rendition) parameters.
// Supported: 0 reset, 1 bold, 7 reverse, 30-37 fg, 90-97 bright fg,
// 40-47 bg, 100-107 bright bg, 39 default fg, 49 default bg.
fn parse_sgr(params: &[u8]) {
    if params.is_empty() {
        // ESC[m is equivalent to ESC[0m
        reset_color();
        return;
    }
    for p in params.split(|&b| b == b';') {
        if p.is_empty() {
            continue;
        }
        let mut num: u16 = 0;
        for &b in p {
            if b.is_ascii_digit() {
                num = num * 10 + (b - b'0') as u16;
            }
        }
        match num {
            0 => reset_color(),
            1 => unsafe { FG = FG | 0x08; },
            7 => {
                // Swap foreground and background (reverse video)
                unsafe {
                    let t = FG;
                    FG = BG;
                    BG = t;
                }
            }
            30..=37 => unsafe { FG = (num as u8) - 30; },
            39 => unsafe { FG = 0x07; },
            40..=47 => unsafe { BG = (num as u8) - 40; },
            49 => unsafe { BG = 0x00; },
            90..=97 => unsafe { FG = ((num as u8) - 90) | 0x08; },
            100..=107 => unsafe { BG = ((num as u8) - 100) | 0x08; },
            _ => {}
        }
    }
    apply_fb_colors();
}

fn reset_color() {
    unsafe {
        FG = 0x07;
        BG = 0x00;
    }
    apply_fb_colors();
}

pub fn write_dec(val: u64) {
    if val == 0 {
        write_char('0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 20;
    let mut v = val;
    while v > 0 {
        i -= 1;
        buf[i] = (v % 10) as u8 + b'0';
        v /= 10;
    }
    for &b in &buf[i..] {
        write_char(b as char);
    }
}

// ── VGA text-mode primitives (legacy path only) ───────────────────────────

fn vga_put(c: u8) {
    unsafe {
        let offset = (ROW * WIDTH + COL) * 2;
        VGA_BUF.add(offset).write_volatile(c);
        VGA_BUF.add(offset + 1).write_volatile(color_attr());
        COL += 1;
        if COL >= WIDTH {
            vga_newline();
        } else {
            sync_cursor();
        }
    }
}

fn vga_newline() {
    unsafe {
        COL = 0;
        ROW += 1;
        if ROW >= HEIGHT {
            vga_scroll();
            ROW = HEIGHT - 1;
        }
        sync_cursor();
    }
}

fn vga_scroll() {
    for y in 1..HEIGHT {
        for x in 0..WIDTH {
            let src = (y * WIDTH + x) * 2;
            let dst = ((y - 1) * WIDTH + x) * 2;
            unsafe {
                VGA_BUF.add(dst).write_volatile(VGA_BUF.add(src).read_volatile());
                VGA_BUF.add(dst + 1).write_volatile(VGA_BUF.add(src + 1).read_volatile());
            }
        }
    }
    for x in 0..WIDTH {
        let offset = ((HEIGHT - 1) * WIDTH + x) * 2;
        unsafe {
            VGA_BUF.add(offset).write_volatile(b' ');
            VGA_BUF.add(offset + 1).write_volatile(0x0F);
        }
    }
}