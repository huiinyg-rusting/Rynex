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
mod klog;
mod gdt;
mod idt;
mod interrupts;
mod memory;
mod multiboot2;
mod task;
mod paging;
mod pic;
mod pit;
mod ipc;
mod elf;
mod spinlock;
mod vfs_core;
mod vfs;
mod keyboard;
mod tty;
mod services;

use core::alloc::Layout;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);

extern "C" {
    fn syscall_entry();
}

core::arch::global_asm!(include_str!("context_switch.asm"));

pub static MULTIBOOT_INFO: AtomicU64 = AtomicU64::new(0);

#[no_mangle]
pub extern "C" fn kernel_main(_magic: u32, _info: u32) -> ! {
    MULTIBOOT_INFO.store(_info as u64, Ordering::SeqCst);

    serial::init();
    // Console log level. DEBUG traces (SYS>, [RSM:], mmap VMA/MMAP/CTX, execve
    // markers) are *always* captured in the klog ring buffer (queryable via
    // klog::dump() on a fault); they are mirrored to the serial port only when
    // the level is DEBUG. Set to LOG_DEBUG here (and reflash) to see them live.
    klog::set_console_level(klog::LOG_INFO);
    if DEBUG_ENABLED.load(Ordering::Relaxed) {
        serial::write_str("Rynex kernel v0.0.1 Alpha\n");
    }
    vga::clear();

    vga::set_color(0x0C, 0x00);
    vga::write_str("Rynex kernel v0.0.1 Alpha\n");
    vga::set_color(0x0A, 0x00);
    vga::write_str("Booting...\n");
    vga::set_color(0x0F, 0x00);

    gdt::init();
    vga::write_str("GDT: OK\n");
    if DEBUG_ENABLED.load(Ordering::Relaxed) {
        serial::write_str("GDT: OK\n");
    }

    idt::init();
    vga::write_str("IDT: OK\n");
    if DEBUG_ENABLED.load(Ordering::Relaxed) {
        serial::write_str("IDT: OK\n");
    }

    pic::remap(pic::IRQ_BASE, pic::IRQ_BASE + 8);
    pic::mask_all();
    pic::unmask(0);
    pic::unmask(1);
    vga::write_str("PIC: OK\n");
    if DEBUG_ENABLED.load(Ordering::Relaxed) {
        serial::write_str("PIC: OK\n");
    }

    // Initialize keyboard BEFORE timer so UART input during boot isn't lost
    keyboard::init();
    let kbd_vec = pic::IRQ_BASE + 1;
    idt::register_irq(kbd_vec, keyboard::keyboard_interrupt_handler as u64);
    vga::write_str("KBD: OK\n");
    if DEBUG_ENABLED.load(Ordering::Relaxed) {
        serial::write_str("KBD: OK\n");
    }

    pit::init(100);
    vga::write_str("PIT: OK\n");
    if DEBUG_ENABLED.load(Ordering::Relaxed) {
        serial::write_str("PIT: OK\n");
    };

memory::init(_info);
    // Enable SSE (required by libc/musl which uses SSE instructions)
    unsafe {
        let mut cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nostack, nomem));
        cr4 |= 0x600; // OSFXSR (bit 9) + OSXMMEXCPT (bit 10)
        core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nostack, nomem));
    }
    // Enable NX (No-Execute) in EFER MSR and setup syscall MSRs
    unsafe {
        // Read current EFER
        let mut efer: u64 = 0;
        let mut efer_low: u32 = 0;
        let mut efer_high: u32 = 0;
        core::arch::asm!(
            "mov ecx, 0xC0000080",
            "rdmsr",
            out("eax") efer_low,
            out("edx") efer_high,
            out("ecx") _,
            options(nostack, preserves_flags)
        );
        efer = ((efer_high as u64) << 32) | (efer_low as u64);
        // Enable NXE (bit 11)
        efer |= 0x800;
        let efer_low = efer as u32;
        let efer_high = (efer >> 32) as u32;
        core::arch::asm!(
            "mov ecx, 0xC0000080",
            "wrmsr",
            in("eax") efer_low,
            in("edx") efer_high,
            out("ecx") _,
            options(nostack, preserves_flags)
        );
        // Setup syscall MSRs
        // STAR: [63:48] = user CS, [47:32] = kernel CS
        // SYSCALL (user→kernel): CS = STAR[47:32], SS = STAR[47:32] + 8
        // SYSRETQ (kernel→user): CS = (STAR[63:48] + 16) | 3, SS = (STAR[63:48] + 8) | 3
        //
        // iretq and SYSRETQ must produce the same CS/SS so the GDT descriptors
        // are re-checked correctly on interrupt→iretq transitions.
        //
        // GDT layout:
        //   0x08: ring0 code  (DPL=0)  ← SYSCALL CS
        //   0x10: ring0 data  (DPL=0)  ← SYSCALL SS
        //   0x18: ring3 data  (DPL=3)  ← SYSRETQ SS  (STAR[63:48]=0x10 → 0x10+8=0x18, |3→0x1B)
        //   0x20: ring3 code  (DPL=3)  ← SYSRETQ CS  (STAR[63:48]=0x10 → 0x10+16=0x20, |3→0x23)
        //   TSS low/high at 0x28/0x30
        //
        // STAR[47:32] = KERNEL_CODE_SELECTOR (0x08) for SYSCALL
        // STAR[63:48] = KERNEL_DATA_SELECTOR (0x10) for SYSRETQ
        let star: u64 = (task::KERNEL_DATA_SELECTOR as u64) << 48
                      | (task::KERNEL_CODE_SELECTOR as u64) << 32;
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
            in("eax") (syscall_entry as u64 & 0xFFFFFFFF) as u32,
            in("edx") (syscall_entry as u64 >> 32) as u32,
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
        let mut efer2 = efer | 1;
        let efer2_low = efer2 as u32;
        let efer2_high = (efer2 >> 32) as u32;
        core::arch::asm!(
            "mov ecx, 0xC0000080",
            "wrmsr",
            in("eax") efer2_low,
            in("edx") efer2_high,
            out("ecx") _,
            options(nostack, preserves_flags)
        );
    }
    paging::init();
    let pages = memory::TOTAL_PAGES.load(core::sync::atomic::Ordering::SeqCst);
    vga::write_str("MEM: ");
    vga::write_dec(pages / 256);
    vga::write_str(" MB\n");
    if DEBUG_ENABLED.load(Ordering::Relaxed) {
        serial::write_str("MEM: ");
        serial::write_dec(pages / 256);
        serial::write_str(" MB\n");
    }

    vfs_core::ramfs::init();
    vfs_core::init();
    let _root_vnode = vfs_core::mount_root();

    // Register kernel services as named IPC ports. Clients connect to these by
    // name; in this phase the services remain in-kernel (see services.rs).
    services::register(b"vfs", services::vfs_handler);
    services::register(b"console", services::console_handler);
    services::register(b"kbd", services::kbd_handler);

    // Register /proc and mount it so busybox ps works. This runs while the
    // kernel still has full control (before the scheduler hands off to init).
    crate::vfs_core::procfs::init();
    crate::vfs_core::procfs::mount_proc();
    crate::services::register(b"proc", services::proc_handler);

    task::init_scheduler();

    // Service-ification self-test: run a kernel service (ping) as its own task
    // and a kernel client task that performs synchronous request/reply IPC.
    // This exercises ipc_call/ipc_reply between separate kernel tasks.
    services::register(b"ping", services::ping_handler);
    let _ = task::create_kernel_task(services::ping_server_task as u64);
    let _ = task::create_kernel_task(services::ipc_roundtrip_selftest as u64);

    task::test();

    vga::write_str("\nSystem halted.\n");
    if DEBUG_ENABLED.load(Ordering::Relaxed) {
        serial::write_str("System halted.\n");
    }

    loop {
        unsafe { core::arch::asm!("hlt", options(nostack, nomem)); }
    }
}

extern "C" fn kernel_probe() -> ! {
    crate::serial::write_str("KPROBE: kernel task alive\n");
    loop { crate::task::yield_now(); }
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
    serial::write_str("\n");
    klog::dump();
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