const COM1: u16 = 0x3F8;

use crate::spinlock::RawSpin;

// Serial output is written byte-by-byte from both CPUs (BSP kernel threads and
// AP kernel tasks share the one MMIO/port). Without mutual exclusion the two
// CPUs interleave mid-message and garble each other's lines, so every write
// takes this lock (it also masks local IRQs, preventing reentrancy).
static SERIAL_LOCK: RawSpin = RawSpin::new();

fn outb(port: u16, val: u8) {
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nostack, nomem)); }
}

fn inb(port: u16) -> u8 {
    let val: u8;
    unsafe { core::arch::asm!("in al, dx", in("dx") port, out("al") val, options(nostack, nomem)); }
    val
}

fn cpu_pause() {
    unsafe { core::arch::asm!("pause", options(nostack, nomem)); }
}

pub fn init() {
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x80);
    outb(COM1 + 0, 0x01);
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03);
    outb(COM1 + 2, 0xC7);
    outb(COM1 + 4, 0x0B);
    // Drain any stale input
    while inb(COM1 + 5) & 1 != 0 { inb(COM1); }
}

// Raw, unlocked byte write. Callers must hold SERIAL_LOCK.
fn write_byte_unlocked(byte: u8) {
    while (inb(COM1 + 5) & 0x20) == 0 {
        cpu_pause();
    }
    outb(COM1, byte);
}

pub fn write_byte(byte: u8) {
    let _g = SERIAL_LOCK.lock();
    write_byte_unlocked(byte);
}

pub fn write_str(s: &str) {
    let _g = SERIAL_LOCK.lock();
    for &b in s.as_bytes() {
        write_byte_unlocked(b);
    }
}

pub fn write_char(c: char) {
    let _g = SERIAL_LOCK.lock();
    let mut buf = [0u8; 4];
    let encoded = c.encode_utf8(&mut buf);
    for &b in encoded.as_bytes() {
        write_byte_unlocked(b);
    }
}

pub fn write_dec(val: u64) {
    let _g = SERIAL_LOCK.lock();
    if val == 0 {
        write_byte_unlocked(b'0');
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
        write_byte_unlocked(b);
    }
}

pub fn write_hex(val: u64) {
    let _g = SERIAL_LOCK.lock();
    let hex = b"0123456789ABCDEF";
    for i in (0..16).rev() {
        let nibble = ((val >> (i * 4)) & 0xF) as usize;
        write_byte_unlocked(hex[nibble]);
    }
}

pub fn receive_ready() -> bool {
    inb(COM1 + 5) & 1 != 0
}

pub fn read_byte() -> u8 {
    while !receive_ready() {
        cpu_pause();
    }
    inb(COM1)
}

pub fn read_byte_nonblocking() -> Option<u8> {
    if receive_ready() {
        Some(inb(COM1))
    } else {
        None
    }
}
