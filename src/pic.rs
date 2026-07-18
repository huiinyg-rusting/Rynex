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

pub fn unmask(irq: u8) {
    let port = if irq < 8 { PIC1_DATA } else { PIC2_DATA };
    let actual = irq % 8;
    unsafe {
        let val = inb(port) & !(1 << actual);
        outb(port, val);
    }
}

pub fn mask(irq: u8) {
    let port = if irq < 8 { PIC1_DATA } else { PIC2_DATA };
    let actual = irq % 8;
    unsafe {
        let val = inb(port) | (1 << actual);
        outb(port, val);
    }
}

pub fn send_eoi(irq: u8) {
    if irq >= 8 {
        unsafe { outb(PIC2_CMD, 0x20); }
    }
    unsafe { outb(PIC1_CMD, 0x20); }
}
