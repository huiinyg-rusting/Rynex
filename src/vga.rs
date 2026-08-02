const VGA_BUF: *mut u8 = 0xB8000 as *mut u8;
const WIDTH: usize = 80;
const HEIGHT: usize = 25;

static mut COL: usize = 0;
static mut ROW: usize = 0;

static mut FG: u8 = 0x0F;
static mut BG: u8 = 0x00;

pub fn write_char(c: char) {
    put_char(c as u8);
}

pub fn set_color(fg: u8, bg: u8) {
    unsafe {
        FG = fg & 0x0F;
        BG = bg & 0x0F;
    }
}

fn color_attr() -> u8 {
    unsafe { (BG << 4) | FG }
}

pub fn clear() {
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
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        if byte == 0x1B && i + 1 < bytes.len() && bytes[i + 1] == b'[' {
            // ANSI CSI sequence: ESC [ params... final
            i += 2;
            let start = i;
            while i < bytes.len() && !(0x40..=0x7E).contains(&bytes[i]) {
                i += 1;
            }
            if i < bytes.len() {
                let final_char = bytes[i];
                let params = &bytes[start..i];
                if final_char == b'm' {
                    parse_sgr(params);
                } else if final_char == b'J' {
                    // Erase display: ESC[J / ESC[0J = to bottom, ESC[2J = all
                    if params.is_empty() || params == b"0" {
                        erase_to_bottom();
                    } else if params == b"2" {
                        clear_screen();
                    }
                } else if final_char == b'H' {
                    // Cursor home
                    unsafe { COL = 0; ROW = 0; }
                    sync_cursor();
                }
                i += 1;
            }
            continue;
        }
        match byte {
            b'\n' => newline(),
            b'\r' => {
                unsafe { COL = 0; }
                sync_cursor();
            }
            b'\x08' => {
                // Backspace: move cursor one column left and clear the cell.
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
            b'\t' => {
                let spaces = 4 - (unsafe { COL } % 4);
                for _ in 0..spaces {
                    put_char(b' ');
                }
            }
            _ => put_char(byte),
        }
        i += 1;
    }
}

fn clear_screen() {
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
}

fn reset_color() {
    unsafe {
        FG = 0x07;
        BG = 0x00;
    }
}

pub fn write_dec(val: u64) {
    if val == 0 {
        put_char(b'0');
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
        put_char(b);
    }
}

fn put_char(c: u8) {
    unsafe {
        let offset = (ROW * WIDTH + COL) * 2;
        VGA_BUF.add(offset).write_volatile(c);
        VGA_BUF.add(offset + 1).write_volatile(color_attr());
        COL += 1;
        if COL >= WIDTH {
            newline();
        } else {
            sync_cursor();
        }
    }
}

fn newline() {
    unsafe {
        COL = 0;
        ROW += 1;
        if ROW >= HEIGHT {
            scroll();
            ROW = HEIGHT - 1;
        }
        sync_cursor();
    }
}

fn scroll() {
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
