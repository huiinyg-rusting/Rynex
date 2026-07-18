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
mod pic;
mod pit;

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

    pic::remap(pic::IRQ_BASE, pic::IRQ_BASE + 8);
    pic::mask_all();
    idt::register_irq(task::TIMER_IRQ_VECTOR, task::timer_interrupt_handler as u64);
    pic::unmask(0);
    vga::write_str("PIC: OK\n");
    serial::write_str("PIC: OK\n");

    pit::init(100);
    vga::write_str("PIT: OK\n");
    serial::write_str("PIT: OK\n");

    memory::init(_info);
    // Enable NX (No-Execute) in EFER MSR and setup syscall MSRs
    unsafe {
        let mut efer: u64;
        // Enable NXE (bit 11)
        core::arch::asm!(
            "mov ecx, 0xC0000080",
            "rdmsr",
            "or eax, 0x800",
            "wrmsr",
            inout("eax") efer as u32,
            inout("edx") (efer >> 32) as u32,
            out("ecx") _,
            options(nostack, preserves_flags)
        );
        // Setup syscall MSRs
        // STAR: [63:48] = user CS, [47:32] = kernel CS
        let star: u64 = (task::USER_CODE_SELECTOR as u64) << 48 | (task::KERNEL_CODE_SELECTOR as u64) << 32;
        core::arch::asm!(
            "mov ecx, 0xC0000081",
            "wrmsr",
            in("eax") (star & 0xFFFFFFFF) as u32,
            in("edx") (star >> 32) as u32,
            options(nostack, preserves_flags)
        );
        // LSTAR: RIP of syscall entry
        core::arch::asm!(
            "mov ecx, 0xC0000082",
            "wrmsr",
            in("eax") (task::syscall_entry as u64 & 0xFFFFFFFF) as u32,
            in("edx") (task::syscall_entry as u64 >> 32) as u32,
            options(nostack, preserves_flags)
        );
        // FMASK: flags to clear on syscall (clear IF)
        core::arch::asm!(
            "mov ecx, 0xC0000084",
            "wrmsr",
            in("eax") 0x200u32,
            in("edx") 0u32,
            options(nostack, preserves_flags)
        );
        // Enable SCE bit (bit 0) in EFER
        efer |= 1;
        core::arch::asm!(
            "mov ecx, 0xC0000080",
            "wrmsr",
            in("eax") efer as u32,
            in("edx") (efer >> 32) as u32,
            options(nostack, preserves_flags)
        );
    }
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