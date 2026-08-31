use x86_64::structures::idt::{InterruptStackFrame, PageFaultErrorCode};

// AP LAPIC timer (vector 0x21): wakes the AP and services its per-CPU needs.
// It EOIs, then wakes any sleeping tasks whose time-based wakeup has arrived so
// user/kernel tasks blocked on the AP resume (the BSP PIT timer does the same,
// serialized by TIMER_WAKE_LOCK). It deliberately does NOT do the serial/keyboard
// poll or the global preempt (PREEMPT_SCRATCH is a single global, so AP and BSP
// must not preempt concurrently) — the AP cooperatively schedules via schedule().
pub extern "x86-interrupt" fn ap_timer_irq(_frame: InterruptStackFrame) {
    unsafe { crate::apic::eoi(); }
    crate::task::wakeup_expired_sleepers();
}

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
        crate::serial::write_hex(frame.code_segment.0 as u64);
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
    unsafe { core::arch::asm!("mov {0:r}, cs", out(reg) cs, options(nostack, nomem, preserves_flags)); }
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

pub extern "x86-interrupt" fn debug(mut frame: InterruptStackFrame) {
    unsafe {
        let dr6: u64;
        core::arch::asm!("mov {}, dr6", out(reg) dr6, options(nostack, nomem, preserves_flags));
        if dr6 & 0xF != 0 {
            static WBCNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
            let wbn = WBCNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            if wbn < 48 {
                crate::serial::write_str("  WB# rip=0x");
                crate::serial::write_hex(frame.instruction_pointer.as_u64());
                crate::serial::write_str(" B=0x");
                crate::serial::write_hex(dr6 & 0xF);
                crate::serial::write_str(" n=");
                crate::serial::write_dec(wbn as u64);
                crate::serial::write_str("\n");
            }
            core::arch::asm!("mov {}, dr6", in(reg) (dr6 & !0xF), options(nostack, nomem));
        }
        // clear TF
        let v = frame.as_mut();
        let mut inner = v.read();
        inner.cpu_flags.remove(x86_64::registers::rflags::RFlags::TRAP_FLAG);
    }
    return;
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
    let cs: u16;
    unsafe { core::arch::asm!("mov {0:r}, cs", out(reg) cs, options(nostack, nomem, preserves_flags)); }
    crate::serial::write_str("EXC: Invalid Opcode rip=0x");
    crate::serial::write_hex(frame.instruction_pointer.as_u64());
    crate::serial::write_str(" cs=0x");
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

#[allow(invalid_reference_casting)]
pub extern "x86-interrupt" fn general_protection(frame: InterruptStackFrame, code: u64) {
    // Read raw values from the interrupt frame on the stack
    let raw_rip: u64 = unsafe { core::ptr::read_volatile(&frame as *const InterruptStackFrame as *const u64) };
    let raw_cs_val: u64 = unsafe { core::ptr::read_volatile((&frame as *const InterruptStackFrame as *const u64).add(1)) };
    crate::serial::write_str("EXC: GPF code=0x");
    crate::serial::write_hex(code);
    crate::serial::write_str(" rip=0x");
    crate::serial::write_hex(raw_rip);
    crate::serial::write_str(" cs_raw=0x");
    crate::serial::write_hex(raw_cs_val & 0xFFFF);
    crate::serial::write_str(" rsp=0x");
    let raw_rsp: u64 = unsafe { core::ptr::read_volatile((&frame as *const InterruptStackFrame as *const u64).add(3)) };
    crate::serial::write_hex(raw_rsp);

    // Detect musl a_crash (hlt in user mode) — musl uses HLT as abort
    let is_user = (raw_cs_val & 3) == 3;
    if is_user {
        // Check RIP is canonical before reading it
        let rip_valid = (raw_rip >> 47) == 0 || (raw_rip >> 47) == 0x1FFFF;
        if rip_valid {
            let opcode: u8 = unsafe { core::ptr::read_volatile(raw_rip as *const u8) };
            if opcode == 0xF4 {
                crate::serial::write_str(" (a_crash)\n");
                let ret_addr: u64 = unsafe { core::ptr::read_volatile(raw_rsp as *const u64) };
                crate::serial::write_str("  ret_addr=0x");
                crate::serial::write_hex(ret_addr);
                crate::serial::write_str("\n");
                crate::serial::write_str("\n");
                crate::task::exit_task(0);
                halt();
            }
        }
        crate::serial::write_str("\n");
    }
    crate::serial::write_str("\n");
    exit_user_task_early(code, raw_rip, raw_rsp, "GPF");
    halt();
}

fn exit_user_task_early(code: u64, rip: u64, rsp: u64, name: &str) {
    let cs: u16;
    unsafe { core::arch::asm!("mov {0:r}, cs", out(reg) cs, options(nostack, nomem, preserves_flags)); }
    if cs & 3 == 3 {
        crate::serial::write_str("EXC: ");
        crate::serial::write_str(name);
        crate::serial::write_str(" (user task)\n");
        crate::serial::write_str("  rip=0x");
        crate::serial::write_hex(rip);
        crate::serial::write_str(" rsp=0x");
        crate::serial::write_hex(rsp);
        crate::serial::write_str(" code=0x");
        crate::serial::write_hex(code);
        crate::serial::write_str("\n");
        crate::task::exit_task(-6);
    }
}

pub extern "x86-interrupt" fn alignment_check(frame: InterruptStackFrame, code: u64) {
    exit_user_task(&frame, "Alignment Check", &[("code", code)]);
    crate::serial::write_str("EXC: Alignment Check\n");
    halt();
}

// Raw probe: write '!' to COM1 before any prologue.
// If the CPU dispatches to this handler, we will see it.
#[unsafe(naked)]
pub unsafe extern "C" fn page_fault_probe() {
    core::arch::naked_asm!(
        "push rax",
        "mov al, 0x21",
        "mov dx, 0x3f8",
        "out dx, al",
        "pop rax",
        "jmp {}",
        sym page_fault_real,
    );
}


pub extern "x86-interrupt" fn page_fault_real(frame: InterruptStackFrame, code: PageFaultErrorCode) {
    let cr2: u64;
    unsafe { core::arch::asm!("mov {}, cr2", out(reg) cr2); }
    let rip = frame.instruction_pointer.as_u64();
    let rsp = frame.stack_pointer.as_u64();
    let cs_val = frame.code_segment.0 as u64;

    // Supervisor write to a read-only page: with CR0.WP=1 these fault. Resolve
    // non-user (identity) pages by marking them writable; for user COW pages
    // fall through to the normal handler.
    if (cs_val & 3) == 0 && (code.bits() & 2) != 0 && (code.bits() & 1) != 0 {
        if crate::paging::kernel_ro_write_resolve(cr2) {
            return;
        }
    }
    if crate::paging::page_fault_resolve(cr2, code.bits() as u64, frame.code_segment.rpl() as u64) {
        return;
    }
    crate::klog::begin(crate::klog::LOG_ERR, crate::klog::FAC_PAGING);
    crate::klog::s("EXC: PAGE_FAULT rip=0x");
    crate::klog::hex(rip);
    crate::klog::s(" cs=0x");
    crate::klog::hex(cs_val);
    crate::klog::s(" rsp=0x");
    crate::klog::hex(rsp);
    crate::klog::s(" intr_rsp=0x");
    crate::klog::hex(frame.stack_pointer.as_u64());
    crate::klog::s(" cr2=0x");
    crate::klog::hex(cr2);
    crate::klog::s(" code=0x");
    crate::klog::hex(code.bits() as u64);
    crate::klog::s("\n");
    crate::klog::end();

    crate::paging::dump_fault_walk(crate::task::current_task_pml4(), cr2);

    exit_user_task(&frame, "Page Fault", &[("addr", cr2), ("pf_code", code.bits())]);
    crate::vga::write_str("EXC: Page Fault\n");
    crate::klog::dump();
    halt();
}

// Handlers that must diverge (!)
pub extern "x86-interrupt" fn double_fault(frame: InterruptStackFrame, _code: u64) -> ! {
    let cr2: u64;
    unsafe { core::arch::asm!("mov {}, cr2", out(reg) cr2, options(nostack, nomem, preserves_flags)); }
    let cs: u16;
    unsafe { core::arch::asm!("mov {0:r}, cs", out(reg) cs, options(nostack, nomem, preserves_flags)); }
    // Read TSS.rsp0
    let rsp0 = crate::gdt::get_tss_rsp0();
    // Read cr3
    let cr3_val: u64;
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3_val, options(nostack, nomem, preserves_flags)); }
    crate::serial::write_str("EXC: Double Fault\n");
    crate::serial::write_str("  rip=0x");
    crate::serial::write_hex(frame.instruction_pointer.as_u64());
    crate::serial::write_str(" cs=0x");
    crate::serial::write_hex(cs as u64);
    crate::serial::write_str(" rsp=0x");
    crate::serial::write_hex(frame.stack_pointer.as_u64());
    crate::serial::write_str(" cr2=0x");
    crate::serial::write_hex(cr2);
    crate::serial::write_str(" cr3=0x");
    crate::serial::write_hex(cr3_val);
    crate::serial::write_str(" tss.rsp0=0x");
    crate::serial::write_hex(rsp0);
    crate::serial::write_str("\n");
    crate::klog::dump();
    halt();
}

pub extern "x86-interrupt" fn machine_check(_frame: InterruptStackFrame) -> ! {
    crate::serial::write_str("EXC: Machine Check\n");
    halt();
}