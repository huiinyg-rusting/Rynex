const COM1: u16 = 0x3F8;

fn outb(port: u16, val: u8) {
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nostack, nomem)); }
}

fn inb(port: u16) -> u8 {
    let val: u8;
    unsafe { core::arch::asm!("in al, dx", in("dx") port, out("al") val, options(nostack, nomem)); }
    val
}

pub fn init() {
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x80);
    outb(COM1 + 0, 0x01);
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03);
    outb(COM1 + 2, 0xC7);
    outb(COM1 + 4, 0x0B);
}

pub fn write_byte(byte: u8) {
    while (inb(COM1 + 5) & 0x20) == 0 {
        unsafe { core::arch::asm!("pause", options(nostack, nomem)); }
    }
    outb(COM1, byte);
}

pub fn write_str(s: &str) {
    for &b in s.as_bytes() {
        write_byte(b);
    }
}

pub fn write_dec(val: u64) {
    if val == 0 {
        write_byte(b'0');
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
        write_byte(b);
    }
}

pub fn write_hex(val: u64) {
    let hex = b"0123456789ABCDEF";
    for i in (0..16).rev() {
        let nibble = ((val >> (i * 4)) & 0xF) as usize;
        write_byte(hex[nibble]);
    }
}
