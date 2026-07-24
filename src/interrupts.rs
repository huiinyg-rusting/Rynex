use x86_64::structures::idt::{InterruptStackFrame, PageFaultErrorCode};

fn halt() -> ! {
    loop {
        unsafe { core::arch::asm!("hlt", options(nostack, nomem)); }
    }
}

fn exit_user_task(frame: &InterruptStackFrame, name: &str, extra: &[(&str, u64)]) {
    if frame.code_segment.rpl() == x86_64::PrivilegeLevel::Ring3 {
        crate::serial::write_str("EXC: ");
        crate::serial::write_str(name);
        crate::serial::write_str(" (user task)\n");
        crate::serial::write_str("  rip=0x");
        crate::serial::write_hex(frame.instruction_pointer.as_u64());
        crate::serial::write_str(" cs=0x");
        crate::serial::write_hex(frame.code_segment.rpl() as u64);
        for (label, val) in extra {
            crate::serial::write_str(" ");
            crate::serial::write_str(label);
            crate::serial::write_str("=0x");
            crate::serial::write_hex(*val);
        }
        crate::serial::write_str("\n");
        crate::task::exit_task(-6);
    }
}

fn from_user(frame: &InterruptStackFrame) -> bool {
    frame.code_segment.rpl() == x86_64::PrivilegeLevel::Ring3
}

fn decode_pf(code: PageFaultErrorCode) -> [&'static str; 8] {
    let mut s = [""; 8];
    let mut i = 0;
    if !code.contains(PageFaultErrorCode::PROTECTION_VIOLATION) {
        s[i] = "NOT-PRESENT"; i += 1;
    } else {
        s[i] = "PROT-VIOLATION"; i += 1;
    }
    if code.contains(PageFaultErrorCode::CAUSED_BY_WRITE) {
        s[i] = "WRITE"; i += 1;
    } else {
        s[i] = "READ"; i += 1;
    }
    if code.contains(PageFaultErrorCode::USER_MODE) {
        s[i] = "USER"; i += 1;
    } else {
        s[i] = "SUPERVISOR"; i += 1;
    }
    if code.contains(PageFaultErrorCode::MALFORMED_TABLE) {
        s[i] = "RSVD-BITS"; i += 1;
    }
    if code.contains(PageFaultErrorCode::INSTRUCTION_FETCH) {
        s[i] = "FETCH"; i += 1;
    }
    if code.contains(PageFaultErrorCode::PROTECTION_KEY) {
        s[i] = "PKU"; i += 1;
    }
    if code.contains(PageFaultErrorCode::SHADOW_STACK) {
        s[i] = "SHSTK"; i += 1;
    }
    s[i] = "";
    s
}

fn dump_pf(frame: &InterruptStackFrame, code: PageFaultErrorCode, cr2: u64) {
    let flags = decode_pf(code);
    let cs: u16;
    unsafe { core::arch::asm!("mov {}, cs", out(reg) cs, options(nostack, nomem, preserves_flags)); }
    let cpl = (cs & 3) as u64;
    crate::serial::write_str("EXC: PAGE_FAULT\n");
    crate::serial::write_str("  addr: 0x");
    crate::serial::write_hex(cr2);
    crate::serial::write_str(" rip: 0x");
    crate::serial::write_hex(frame.instruction_pointer.as_u64());
    crate::serial::write_str("\n  code: 0x");
    crate::serial::write_hex(code.bits());
    crate::serial::write_str(" [");
    for f in flags {
        if f.is_empty() { break; }
        crate::serial::write_str(f);
        crate::serial::write_str(" ");
    }
    crate::serial::write_str("] CPL=");
    crate::serial::write_dec(cpl as u64);
    crate::serial::write_str("\n");
}

// Handlers that return ()
pub extern "x86-interrupt" fn divide_error(frame: InterruptStackFrame) {
    exit_user_task(&frame, "Divide Error", &[]);
    crate::serial::write_str("EXC: Divide Error\n");
    halt();
}

pub extern "x86-interrupt" fn debug(_frame: InterruptStackFrame) {
    crate::serial::write_str("EXC: Debug\n");
    halt();
}

pub extern "x86-interrupt" fn nmi(_frame: InterruptStackFrame) {
    crate::serial::write_str("EXC: NMI\n");
    halt();
}

pub extern "x86-interrupt" fn breakpoint(frame: InterruptStackFrame) {
    exit_user_task(&frame, "Breakpoint", &[]);
    crate::serial::write_str("EXC: Breakpoint\n");
    halt();
}

pub extern "x86-interrupt" fn overflow(frame: InterruptStackFrame) {
    exit_user_task(&frame, "Overflow", &[]);
    crate::serial::write_str("EXC: Overflow\n");
    halt();
}

pub extern "x86-interrupt" fn bound_range(frame: InterruptStackFrame) {
    exit_user_task(&frame, "Bound Range", &[]);
    crate::serial::write_str("EXC: Bound Range\n");
    halt();
}

pub extern "x86-interrupt" fn invalid_opcode(frame: InterruptStackFrame) {
    exit_user_task(&frame, "Invalid Opcode", &[]);
    crate::serial::write_str("EXC: Invalid Opcode rip=0x");
    crate::serial::write_hex(frame.instruction_pointer.as_u64());
    crate::serial::write_str(" cs=0x");
    let cs: u16;
    unsafe { core::arch::asm!("mov {}, cs", out(reg) cs, options(nostack, nomem, preserves_flags)); }
    crate::serial::write_hex(cs as u64);
    crate::serial::write_str("\n");
    halt();
}

pub extern "x86-interrupt" fn device_not_available(_frame: InterruptStackFrame) {
    crate::serial::write_str("EXC: Device Not Available\n");
    halt();
}

pub extern "x86-interrupt" fn x87_fp(frame: InterruptStackFrame) {
    exit_user_task(&frame, "x87 FP", &[]);
    crate::serial::write_str("EXC: x87 FP\n");
    halt();
}

pub extern "x86-interrupt" fn simd_fp(frame: InterruptStackFrame) {
    exit_user_task(&frame, "SIMD FP", &[]);
    crate::serial::write_str("EXC: SIMD FP\n");
    halt();
}

pub extern "x86-interrupt" fn virtualization(_frame: InterruptStackFrame) {
    crate::serial::write_str("EXC: Virtualization\n");
    halt();
}

// Handlers with error code that return ()
pub extern "x86-interrupt" fn invalid_tss(frame: InterruptStackFrame, code: u64) {
    exit_user_task(&frame, "Invalid TSS", &[("code", code)]);
    crate::serial::write_str("EXC: Invalid TSS code=0x");
    crate::serial::write_hex(code);
    crate::serial::write_str("\n");
    halt();
}

pub extern "x86-interrupt" fn segment_not_present(frame: InterruptStackFrame, code: u64) {
    exit_user_task(&frame, "Segment Not Present", &[("code", code)]);
    crate::serial::write_str("EXC: Segment Not Present code=0x");
    crate::serial::write_hex(code);
    crate::serial::write_str("\n");
    halt();
}

pub extern "x86-interrupt" fn stack_fault(frame: InterruptStackFrame, code: u64) {
    exit_user_task(&frame, "Stack Fault", &[("code", code)]);
    crate::serial::write_str("EXC: Stack Fault code=0x");
    crate::serial::write_hex(code);
    crate::serial::write_str("\n");
    halt();
}

pub extern "x86-interrupt" fn general_protection(frame: InterruptStackFrame, code: u64) {
    exit_user_task(&frame, "GPF", &[("code", code)]);
    let cs: u16;
    unsafe { core::arch::asm!("mov {}, cs", out(reg) cs, options(nostack, nomem, preserves_flags)); }
    crate::serial::write_str("EXC: GPF code=0x");
    crate::serial::write_hex(code);
    crate::serial::write_str(" rip=0x");
    crate::serial::write_hex(frame.instruction_pointer.as_u64());
    crate::serial::write_str(" cs=0x");
    crate::serial::write_hex(cs as u64);
    crate::serial::write_str(" rsp=0x");
    crate::serial::write_hex(frame.stack_pointer.as_u64());
    crate::serial::write_str("\n");
    halt();
}

pub extern "x86-interrupt" fn alignment_check(frame: InterruptStackFrame, code: u64) {
    exit_user_task(&frame, "Alignment Check", &[("code", code)]);
    crate::serial::write_str("EXC: Alignment Check\n");
    halt();
}

// Page fault — enhanced handler
pub extern "x86-interrupt" fn page_fault(frame: InterruptStackFrame, code: PageFaultErrorCode) {
    let cr2: u64;
    unsafe { core::arch::asm!("mov {}, cr2", out(reg) cr2); }

    dump_pf(&frame, code, cr2);

    if crate::paging::page_fault_resolve(cr2, code.bits() as u64, frame.code_segment.rpl() as u64) {
        crate::serial::write_str("  resolved\n");
        return;
    }

    exit_user_task(&frame, "Page Fault", &[("addr", cr2), ("pf_code", code.bits())]);
    crate::vga::write_str("EXC: Page Fault\n");
    halt();
}

// Handlers that must diverge (!)
pub extern "x86-interrupt" fn double_fault(frame: InterruptStackFrame, _code: u64) -> ! {
    let cr2: u64;
    unsafe { core::arch::asm!("mov {}, cr2", out(reg) cr2, options(nostack, nomem, preserves_flags)); }
    let cs: u16;
    unsafe { core::arch::asm!("mov {}, cs", out(reg) cs, options(nostack, nomem, preserves_flags)); }
    crate::serial::write_str("EXC: Double Fault\n");
    crate::serial::write_str("  rip=0x");
    crate::serial::write_hex(frame.instruction_pointer.as_u64());
    crate::serial::write_str(" cs=0x");
    crate::serial::write_hex(cs as u64);
    crate::serial::write_str(" rsp=0x");
    crate::serial::write_hex(frame.stack_pointer.as_u64());
    crate::serial::write_str(" cr2=0x");
    crate::serial::write_hex(cr2);
    crate::serial::write_str("\n");
    halt();
}

pub extern "x86-interrupt" fn machine_check(_frame: InterruptStackFrame) -> ! {
    crate::serial::write_str("EXC: Machine Check\n");
    halt();
}