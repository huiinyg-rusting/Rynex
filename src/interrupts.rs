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
        // Check RIP is canonical (bits 48-63 must be copies of bit 47) before reading
        let rip_valid = (raw_rip >> 47) == 0 || (raw_rip >> 47) == 0x1FFFF;
        if rip_valid {
            let opcode: u8 = unsafe { core::ptr::read_volatile(raw_rip as *const u8) };
            if opcode == 0xF4 {
                crate::serial::write_str(" (a_crash)\n");
                let usp = raw_rsp;
                // Read return address at the top of the stack (pushed by call a_crash)
                let ret_addr: u64 = unsafe { core::ptr::read_volatile(usp as *const u64) };
                crate::serial::write_str("  ret_addr=0x");
                crate::serial::write_hex(ret_addr);
                crate::serial::write_str("\n");
                // enframe locals: push at offsets 0x10(p), 0x0c(n), 0x20(addr)
                // after call a_crash: enframe_RSP = raw_rsp + 8
                let p_val: u64 = unsafe { core::ptr::read_volatile((usp + 0x18) as *const u64) };
                let n_val: u32 = unsafe { core::ptr::read_volatile((usp + 0x14) as *const u32) };
                let addr_val: u64 = unsafe { core::ptr::read_volatile((usp + 0x28) as *const u64) };
                let stride_val: u64 = unsafe { core::ptr::read_volatile((usp + 0x30) as *const u64) };
                // Also read arg3 (size) and arg4 from the caller's stack frame
                let size_val: u64 = unsafe { core::ptr::read_volatile((usp + 0x08) as *const u64) };
                crate::serial::write_str("  p=0x");
                crate::serial::write_hex(p_val);
                crate::serial::write_str(" n=");
                crate::serial::write_dec(n_val as u64);
                crate::serial::write_str(" stride=0x");
                crate::serial::write_hex(stride_val);
                crate::serial::write_str(" addr=0x");
                crate::serial::write_hex(addr_val);
                crate::serial::write_str(" size=0x");
                crate::serial::write_hex(size_val);
                let off_byte: u8 = unsafe { core::ptr::read_volatile((addr_val.wrapping_sub(4)) as *const u8) };
                crate::serial::write_str(" [addr-4]=0x");
                crate::serial::write_hex(off_byte as u64);
                // Also read the p->off field at p+0x10
                let poff: u64 = unsafe { core::ptr::read_volatile((p_val.wrapping_add(0x10)) as *const u64) };
                crate::serial::write_str(" p->off=0x");
                crate::serial::write_hex(poff);
                // Read p+0x20 (stride metadata)
                let p_idx: u64 = unsafe { core::ptr::read_volatile((p_val.wrapping_add(0x20)) as *const u64) };
                crate::serial::write_str(" p+0x20=0x");
                crate::serial::write_hex(p_idx);
                // Dump meta struct contents (8 u64 at offsets 0x00-0x38)
                for i in 0..8 {
                    let off = i * 8;
                    let v: u64 = unsafe { core::ptr::read_volatile((p_val.wrapping_add(off)) as *const u64) };
                    if i == 0 { crate::serial::write_str("\n  meta: "); }
                    crate::serial::write_str("+0x");
                    crate::serial::write_hex(off);
                    crate::serial::write_str("=0x");
                    crate::serial::write_hex(v);
                }
                // Dump next meta struct too (might be overlap issue)
                let next_p = p_val.wrapping_add(0x28);
                for i in 0..4 {
                    let off = i * 8;
                    let v: u64 = unsafe { core::ptr::read_volatile((next_p.wrapping_add(off)) as *const u64) };
                    if i == 0 { crate::serial::write_str("\n  next: "); }
                    crate::serial::write_str("+0x");
                    crate::serial::write_hex(off);
                    crate::serial::write_str("=0x");
                    crate::serial::write_hex(v);
                }
                // Dump physical page vs virtual page content to detect stale TLB/PTE
                let gpf_cr3: u64;
                unsafe { core::arch::asm!("mov {}, cr3", out(reg) gpf_cr3, options(nostack, nomem, preserves_flags)); }
                let page_phys = crate::paging::PageTableManager::resolve_phys(gpf_cr3, p_val & !0xFFF).unwrap_or(0);
                crate::serial::write_str("\n  page_phys=0x");
                crate::serial::write_hex(page_phys);
                if page_phys != 0 {
                    for i in 0..8 {
                        let off = i * 8;
                        let v: u64 = unsafe { core::ptr::read_volatile((page_phys.wrapping_add(off)) as *const u64) };
                        if i == 0 { crate::serial::write_str("\n  phys: "); }
                        crate::serial::write_str("+0x");
                        crate::serial::write_hex(off);
                        crate::serial::write_str("=0x");
                        crate::serial::write_hex(v);
                    }
                }
                // Dump the page content at the p offset range (offset 0x2C0 to 0x300)
                let virt_page = p_val & !0xFFF;
                let p_off = p_val & 0xFFF;
                crate::serial::write_str("\n  p_off=0x");
                crate::serial::write_hex(p_off);
                for i in 0..10 {
                    let off = p_off + i * 8;
                    let v: u64 = unsafe { core::ptr::read_volatile((virt_page.wrapping_add(off)) as *const u64) };
                    if i == 0 { crate::serial::write_str("\n  p_area: "); }
                    crate::serial::write_str("+0x");
                    crate::serial::write_hex(off);
                    crate::serial::write_str("=0x");
                    crate::serial::write_hex(v);
                }
                crate::serial::write_str("\n");
                crate::task::exit_task(0);
                loop { unsafe { core::arch::asm!("cli; hlt"); } }
            }
        }
    }
    crate::serial::write_str("\n");
    exit_user_task_early(code, raw_rip, raw_rsp, "GPF");
    halt();
}

fn exit_user_task_early(code: u64, rip: u64, rsp: u64, name: &str) {
    let cs: u16;
    unsafe { core::arch::asm!("mov {}, cs", out(reg) cs, options(nostack, nomem, preserves_flags)); }
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
    crate::serial::write_str("EXC: PF rip=0x");
    crate::serial::write_hex(rip);
    crate::serial::write_str(" cs=0x");
    crate::serial::write_hex(cs_val);
    crate::serial::write_str(" rsp=0x");
    crate::serial::write_hex(rsp);
    crate::serial::write_str(" cr2=0x");
    crate::serial::write_hex(cr2);
    crate::serial::write_str(" code=0x");
    crate::serial::write_hex(code.bits() as u64);
    crate::serial::write_str("\n");

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
    halt();
}

pub extern "x86-interrupt" fn machine_check(_frame: InterruptStackFrame) -> ! {
    crate::serial::write_str("EXC: Machine Check\n");
    halt();
}