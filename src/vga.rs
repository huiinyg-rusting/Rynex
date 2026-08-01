const VGA_BUF: *mut u8 = 0xB8000 as *mut u8;
const WIDTH: usize = 80;
const HEIGHT: usize = 25;

static mut COL: usize = 0;
static mut ROW: usize = 0;

pub fn write_char(c: char) {
    put_char(c as u8);
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
    for &byte in s.as_bytes() {
        match byte {
            b'\n' => newline(),
            b'\r' => unsafe { COL = 0; },
            b'\t' => {
                let spaces = 4 - (unsafe { COL } % 4);
                for _ in 0..spaces {
                    put_char(b' ');
                }
            }
            _ => put_char(byte),
        }
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
        VGA_BUF.add(offset + 1).write_volatile(0x0F);
        COL += 1;
        if COL >= WIDTH {
            newline();
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
