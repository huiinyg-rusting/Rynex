use x86_64::structures::idt::{InterruptStackFrame, PageFaultErrorCode};

fn halt() -> ! {
    loop {
        unsafe { core::arch::asm!("hlt", options(nostack, nomem)); }
    }
}

// Handlers that return ()
pub extern "x86-interrupt" fn divide_error(_frame: InterruptStackFrame) {
    crate::serial::write_str("EXC: Divide Error\n");
    crate::vga::write_str("EXC: Divide Error\n");
    halt();
}

pub extern "x86-interrupt" fn debug(_frame: InterruptStackFrame) {
    crate::serial::write_str("EXC: Debug\n");
    crate::vga::write_str("EXC: Debug\n");
    halt();
}

pub extern "x86-interrupt" fn nmi(_frame: InterruptStackFrame) {
    crate::serial::write_str("EXC: NMI\n");
    crate::vga::write_str("EXC: NMI\n");
    halt();
}

pub extern "x86-interrupt" fn breakpoint(_frame: InterruptStackFrame) {
    crate::serial::write_str("EXC: Breakpoint\n");
    crate::vga::write_str("EXC: Breakpoint\n");
    halt();
}

pub extern "x86-interrupt" fn overflow(_frame: InterruptStackFrame) {
    crate::serial::write_str("EXC: Overflow\n");
    crate::vga::write_str("EXC: Overflow\n");
    halt();
}

pub extern "x86-interrupt" fn bound_range(_frame: InterruptStackFrame) {
    crate::serial::write_str("EXC: Bound Range\n");
    crate::vga::write_str("EXC: Bound Range\n");
    halt();
}

pub extern "x86-interrupt" fn invalid_opcode(_frame: InterruptStackFrame) {
    crate::serial::write_str("EXC: Invalid Opcode\n");
    crate::vga::write_str("EXC: Invalid Opcode\n");
    halt();
}

pub extern "x86-interrupt" fn device_not_available(_frame: InterruptStackFrame) {
    crate::serial::write_str("EXC: Device Not Available\n");
    crate::vga::write_str("EXC: Device Not Available\n");
    halt();
}

pub extern "x86-interrupt" fn x87_fp(_frame: InterruptStackFrame) {
    crate::serial::write_str("EXC: x87 FP\n");
    crate::vga::write_str("EXC: x87 FP\n");
    halt();
}

pub extern "x86-interrupt" fn simd_fp(_frame: InterruptStackFrame) {
    crate::serial::write_str("EXC: SIMD FP\n");
    crate::vga::write_str("EXC: SIMD FP\n");
    halt();
}

pub extern "x86-interrupt" fn virtualization(_frame: InterruptStackFrame) {
    crate::serial::write_str("EXC: Virtualization\n");
    crate::vga::write_str("EXC: Virtualization\n");
    halt();
}

// Handlers with error code that return ()
pub extern "x86-interrupt" fn invalid_tss(_frame: InterruptStackFrame, _code: u64) {
    crate::serial::write_str("EXC: Invalid TSS\n");
    crate::vga::write_str("EXC: Invalid TSS\n");
    halt();
}

pub extern "x86-interrupt" fn segment_not_present(_frame: InterruptStackFrame, _code: u64) {
    crate::serial::write_str("EXC: Segment Not Present\n");
    crate::vga::write_str("EXC: Segment Not Present\n");
    halt();
}

pub extern "x86-interrupt" fn stack_fault(_frame: InterruptStackFrame, _code: u64) {
    crate::serial::write_str("EXC: Stack Fault\n");
    crate::vga::write_str("EXC: Stack Fault\n");
    halt();
}

pub extern "x86-interrupt" fn general_protection(_frame: InterruptStackFrame, code: u64) {
    crate::serial::write_str("EXC: General Protection Fault code=");
    crate::serial::write_hex(code);
    crate::serial::write_str("\n");
    crate::vga::write_str("EXC: General Protection Fault\n");
    halt();
}

pub extern "x86-interrupt" fn alignment_check(_frame: InterruptStackFrame, _code: u64) {
    crate::serial::write_str("EXC: Alignment Check\n");
    crate::vga::write_str("EXC: Alignment Check\n");
    halt();
}

// Page fault - special handler with PageFaultErrorCode
pub extern "x86-interrupt" fn page_fault(frame: InterruptStackFrame, code: PageFaultErrorCode) {
    let cr2: u64;
    unsafe { core::arch::asm!("mov {}, cr2", out(reg) cr2); }
    crate::serial::write_str("EXC: Page Fault code=");
    crate::serial::write_hex(code.bits());
    crate::serial::write_str(" addr=");
    crate::serial::write_hex(cr2);
    crate::serial::write_str(" rip=");
    crate::serial::write_hex(frame.instruction_pointer.as_u64());
    crate::serial::write_str("\n");
    crate::vga::write_str("EXC: Page Fault\n");
    halt();
}

// Handlers that must diverge (!)
pub extern "x86-interrupt" fn double_fault(_frame: InterruptStackFrame, _code: u64) -> ! {
    crate::serial::write_str("EXC: Double Fault\n");
    crate::vga::write_str("EXC: Double Fault\n");
    halt();
}

pub extern "x86-interrupt" fn machine_check(_frame: InterruptStackFrame) -> ! {
    crate::serial::write_str("EXC: Machine Check\n");
    crate::vga::write_str("EXC: Machine Check\n");
    halt();
}