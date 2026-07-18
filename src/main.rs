#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]
#![feature(alloc_error_handler)]
#![feature(allocator_api)]
#![feature(panic_info_message)]
#![feature(naked_functions)]

extern crate alloc;

mod vga;
mod serial;
mod gdt;
mod idt;
mod interrupts;
mod memory;
mod multiboot2;
mod task;
mod paging;

use core::alloc::Layout;
use core::panic::PanicInfo;

core::arch::global_asm!(include_str!("context_switch.asm"));

#[no_mangle]
pub extern "C" fn kernel_main(_magic: u32, _info: u32) -> ! {
    serial::init();
    serial::write_str("Niobix v0.1.0\n");
    vga::clear();

    vga::write_str("Niobix v0.1.0\n");
    vga::write_str("Booting...\n");

    gdt::init();
    vga::write_str("GDT: OK\n");
    serial::write_str("GDT: OK\n");

    idt::init();
    vga::write_str("IDT: OK\n");
    serial::write_str("IDT: OK\n");

    unsafe {
        core::arch::asm!("mov al, 0xFF", "out 0x21, al", options(nostack, nomem, preserves_flags));
        core::arch::asm!("mov al, 0xFF", "out 0xA1, al", options(nostack, nomem, preserves_flags));
    }
    serial::write_str("PIC: masked\n");

    memory::init(_info);
    paging::init();
    let pages = memory::TOTAL_PAGES.load(core::sync::atomic::Ordering::SeqCst);
    vga::write_str("MEM: ");
    vga::write_dec(pages / 256);
    vga::write_str(" MB\n");
    serial::write_str("MEM: ");
    serial::write_dec(pages / 256);
    serial::write_str(" MB\n");

    task::init_scheduler();
    task::test();

    vga::write_str("\nSystem halted.\n");
    serial::write_str("System halted.\n");

    loop {
        unsafe { core::arch::asm!("hlt", options(nostack, nomem)); }
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial::write_str("\nPANIC\n");
    vga::write_str("\nKERNEL PANIC\n");
    if let Some(loc) = info.location() {
        serial::write_str(loc.file());
        serial::write_str(":");
        serial::write_dec(loc.line() as u64);
    }
    loop {
        unsafe { core::arch::asm!("hlt", options(nostack, nomem)); }
    }
}

#[alloc_error_handler]
fn alloc_error(layout: Layout) -> ! {
    serial::write_str("ALLOC ERROR: ");
    serial::write_dec(layout.size() as u64);
    serial::write_str(" bytes, align ");
    serial::write_hex(layout.align() as u64);
    serial::write_str("\n");
    loop {
        unsafe { core::arch::asm!("hlt", options(nostack, nomem)); }
    }
}