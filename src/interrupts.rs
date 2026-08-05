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
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, nomem, preserves_flags));
        if let Some(phys) = crate::paging::PageTableManager::resolve_phys(cr3, 0x500000) {
            let flags = crate::paging::PTE_PRESENT | crate::paging::PTE_USER
                | crate::paging::PTE_NO_EXECUTE;
            let _ = crate::paging::PageTableManager::map_into(cr3, 0x500000, phys, flags);
            core::arch::asm!("invlpg [0x500000]", options(nostack));
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
                let get_meta_p: u64 = unsafe { core::ptr::read_volatile((usp + 0x08) as *const u64) };
                let get_meta_caller: u64 = unsafe { core::ptr::read_volatile((usp + 0x40) as *const u64) };
                let realloc_ret: u64 = unsafe { core::ptr::read_volatile((usp + 0xB0) as *const u64) };
                let wrapper_ret: u64 = unsafe { core::ptr::read_volatile((usp + 0xC0) as *const u64) };
                crate::serial::write_str("  get_meta_p=0x");
                crate::serial::write_hex(get_meta_p);
                crate::serial::write_str(" caller=0x");
                crate::serial::write_hex(get_meta_caller);
                crate::serial::write_str(" realloc_ret=0x");
                crate::serial::write_hex(realloc_ret);
                crate::serial::write_str(" wrapper_ret=0x");
                crate::serial::write_hex(wrapper_ret);
                crate::serial::write_str("\n");
                crate::serial::write_str("  META-WRITES (rip,cr2):\n");
                for i in 0..16usize {
                    let (r, c) = unsafe { META_WR[i] };
                    crate::serial::write_str("    [");
                    crate::serial::write_dec(i as u64);
                    crate::serial::write_str("] rip=0x");
                    crate::serial::write_hex(r);
                    crate::serial::write_str(" cr2=0x");
                    crate::serial::write_hex(c);
                    crate::serial::write_str("\n");
                }
                for i in 0..24 {
                    let v: u64 = unsafe { core::ptr::read_volatile((usp + 0xA0 + i * 8) as *const u64) };
                    crate::serial::write_str("  usp+0x");
                    crate::serial::write_hex(0xA0 + i * 8);
                    crate::serial::write_str("=0x");
                    crate::serial::write_hex(v);
                }
                crate::serial::write_str("\n");
                for i in 0..32 {
                    let v: u64 = unsafe { core::ptr::read_volatile((usp + 0x1A0 + i * 8) as *const u64) };
                    crate::serial::write_str("  usp+0x");
                    crate::serial::write_hex(0x1A0 + i * 8);
                    crate::serial::write_str("=0x");
                    crate::serial::write_hex(v);
                }
                crate::serial::write_str("\n");
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
                crate::serial::write_str(" gpf_cr3=0x");
                crate::serial::write_hex(gpf_cr3);
                let page_phys = crate::paging::PageTableManager::resolve_phys(gpf_cr3, p_val & !0xFFF).unwrap_or(0);
                // Also resolve the stack address to compare
                let stack_phys = crate::paging::PageTableManager::resolve_phys(gpf_cr3, raw_rsp & !0xFFF).unwrap_or(0);
                crate::serial::write_str(" stack_page_phys=0x");
                crate::serial::write_hex(stack_phys);
                crate::serial::write_str("\n  page_phys=0x");
                crate::serial::write_hex(page_phys);
                if page_phys != 0 {
                    for i in 0..64 {
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
                let grp = addr_val & !0x0;
                if (grp >> 47) == 0 || (grp >> 47) == 0x1FFFF {
                    let gphys = crate::paging::PageTableManager::resolve_phys(gpf_cr3, grp).unwrap_or(0);
                    crate::serial::write_str("  group_v=0x");
                    crate::serial::write_hex(grp);
                    crate::serial::write_str(" gphys=0x");
                    crate::serial::write_hex(gphys);
                    if gphys != 0 {
                        for i in 0..4 {
                            let v: u64 = unsafe { core::ptr::read_volatile((gphys.wrapping_add(i * 8)) as *const u64) };
                            crate::serial::write_str(" g+0x");
                            crate::serial::write_hex(i * 8);
                            crate::serial::write_str("=0x");
                            crate::serial::write_hex(v);
                        }
                    }
                    crate::serial::write_str("\n");
                }
                // Dump the group struct for the first meta slot (mem at phys page +0x28)
                if page_phys != 0 {
                    let first_mem: u64 = unsafe { core::ptr::read_volatile((page_phys.wrapping_add(0x28)) as *const u64) };
                    crate::serial::write_str("  slots[0].mem=0x");
                    crate::serial::write_hex(first_mem);
                    let first_gphys = crate::paging::PageTableManager::resolve_phys(gpf_cr3, first_mem).unwrap_or(0);
                    crate::serial::write_str(" gphys=0x");
                    crate::serial::write_hex(first_gphys);
                    if first_gphys != 0 {
                        for i in 0..4 {
                            let v: u64 = unsafe { core::ptr::read_volatile((first_gphys.wrapping_add(i * 8)) as *const u64) };
                            crate::serial::write_str(" g+0x");
                            crate::serial::write_hex(i * 8);
                            crate::serial::write_str("=0x");
                            crate::serial::write_hex(v);
                        }
                    }
                    crate::serial::write_str("\n");
                }
                // Dump malloc context at libc 0xE9B00 (loaded at 0x100000)
                let ctx_v = 0x100000E9B00u64;
                crate::serial::write_str("  ctx: ");
                for i in 0..10 {
                    let v: u64 = unsafe { core::ptr::read_volatile((ctx_v + i * 8) as *const u64) };
                    crate::serial::write_str("+0x");
                    crate::serial::write_hex(i * 8);
                    crate::serial::write_str("=0x");
                    crate::serial::write_hex(v);
                    if i == 9 { crate::serial::write_str("\n"); }
                }
                crate::serial::write_str("  active: ");
                for i in 0..48 {
                    let v: u64 = unsafe { core::ptr::read_volatile((ctx_v + 0x50 + i * 8) as *const u64) };
                    crate::serial::write_str("[");
                    crate::serial::write_dec(i as u64);
                    crate::serial::write_str("]=");
                    crate::serial::write_hex(v);
                    if (i & 7) == 7 { crate::serial::write_str("\n  active: "); }
                }
                // Decode meta slots 0..24 in the meta area page at VA 0x500000
                crate::serial::write_str("\n  metas: ");
                for k in 0..40u64 {
                    let base = 0x500018u64 + k * 0x28;
                    let mem: u64 = unsafe { core::ptr::read_volatile((base + 0x10) as *const u64) };
                    let avail: u32 = unsafe { core::ptr::read_volatile((base + 0x18) as *const u32) };
                    let freed: u32 = unsafe { core::ptr::read_volatile((base + 0x1C) as *const u32) };
                    let packed: u64 = unsafe { core::ptr::read_volatile((base + 0x20) as *const u64) };
                    let last_idx = packed & 31;
                    let freeable = (packed >> 5) & 1;
                    let sc = (packed >> 6) & 63;
                    crate::serial::write_str("\n  m[");
                    crate::serial::write_dec(k);
                    crate::serial::write_str("]@0x");
                    crate::serial::write_hex(base);
                    crate::serial::write_str(" mem=0x");
                    crate::serial::write_hex(mem);
                    crate::serial::write_str(" a=");
                    crate::serial::write_hex(avail as u64);
                    crate::serial::write_str(" f=");
                    crate::serial::write_hex(freed as u64);
                    crate::serial::write_str(" li=");
                    crate::serial::write_dec(last_idx);
                    crate::serial::write_str(" fr=");
                    crate::serial::write_dec(freeable);
                    crate::serial::write_str(" sc=");
                    crate::serial::write_dec(sc);
                    crate::serial::write_str(" mp=");
                    crate::serial::write_dec(packed >> 12);
                }
                crate::serial::write_str("\n");
                for probe in [0x6Cu64, 0x2Cu64, 0x4FE280u64, 0x4FE270u64, 0x4FE000u64, 0x10000EC0D0u64, 0x10000EC000u64, 0x500000u64, 0x70000000u64, 0x4FF000u64] {
                    let pp = crate::paging::PageTableManager::resolve_phys(gpf_cr3, probe).unwrap_or(0);
                    crate::serial::write_str("  probe 0x");
                    crate::serial::write_hex(probe);
                    crate::serial::write_str(" phys=0x");
                    crate::serial::write_hex(pp);
                    if pp != 0 {
                        for i in 0..4 {
                            let v: u64 = unsafe { core::ptr::read_volatile((pp.wrapping_add(i * 8)) as *const u64) };
                            crate::serial::write_str(" +");
                            crate::serial::write_hex(i * 8);
                            crate::serial::write_str("=0x");
                            crate::serial::write_hex(v);
                        }
                    }
                    crate::serial::write_str("\n");
                }
                // Full alias scan: find any phys page mapped at 2+ distinct user VAs
                const MAX_ALIAS: usize = 2048;
                static mut ALIAS_TBL: [u64; MAX_ALIAS * 3] = [0; MAX_ALIAS * 3];
                let mut ac = 0usize;
                for pm in 0..512u64 {
                    let pmle = unsafe { core::ptr::read_volatile((gpf_cr3 + pm * 8) as *const u64) };
                    if pmle & 1 == 0 { continue; }
                    let pdptp = pmle & 0xFFFFFFFFFF000;
                    for pt_ in 0..512u64 {
                        let pdpte = unsafe { core::ptr::read_volatile((pdptp + pt_ * 8) as *const u64) };
                        if pdpte & 1 == 0 { continue; }
                        if pdpte & (1 << 7) != 0 {
                            if ac < MAX_ALIAS {
                                unsafe {
                                    ALIAS_TBL[ac * 3] = pdpte & 0xFFFFFFFFFF000;
                                    ALIAS_TBL[ac * 3 + 1] = (pm << 39) | (pt_ << 30);
                                    ALIAS_TBL[ac * 3 + 2] = pdpte & 0xFFF;
                                }
                                ac += 1;
                            }
                            continue;
                        }
                        let pdp = pdpte & 0xFFFFFFFFFF000;
                        for pd_ in 0..512u64 {
                            let pde = unsafe { core::ptr::read_volatile((pdp + pd_ * 8) as *const u64) };
                            if pde & 1 == 0 { continue; }
                            if pde & (1 << 7) != 0 {
                                if ac < MAX_ALIAS {
                                    unsafe {
                                        ALIAS_TBL[ac * 3] = pde & 0xFFFFFFFFFF000;
                                        ALIAS_TBL[ac * 3 + 1] = (pm << 39) | (pt_ << 30) | (pd_ << 21);
                                        ALIAS_TBL[ac * 3 + 2] = pde & 0xFFF;
                                    }
                                    ac += 1;
                                }
                                continue;
                            }
                            let ptp = pde & 0xFFFFFFFFFF000;
                            for pte_ in 0..512u64 {
                                let pte = unsafe { core::ptr::read_volatile((ptp + pte_ * 8) as *const u64) };
                                if pte & 1 == 0 { continue; }
                                if ac < MAX_ALIAS {
                                    unsafe {
                                        ALIAS_TBL[ac * 3] = pte & 0xFFFFFFFFFF000;
                                        ALIAS_TBL[ac * 3 + 1] = (pm << 39) | (pt_ << 30) | (pd_ << 21) | (pte_ << 12);
                                        ALIAS_TBL[ac * 3 + 2] = pte & 0xFFF;
                                    }
                                    ac += 1;
                                }
                            }
                        }
                    }
                }
                crate::serial::write_str("  aliases(");
                crate::serial::write_dec(ac as u64);
                crate::serial::write_str("):\n");
                let mut any = false;
                for i in 0..ac {
                    for j in (i + 1)..ac {
                        unsafe {
                            if ALIAS_TBL[i * 3] != 0 && ALIAS_TBL[i * 3] == ALIAS_TBL[j * 3] {
                                let u1 = (ALIAS_TBL[i * 3 + 2] & 4) != 0;
                                let u2 = (ALIAS_TBL[j * 3 + 2] & 4) != 0;
                                let w1 = (ALIAS_TBL[i * 3 + 2] & 2) != 0;
                                let w2 = (ALIAS_TBL[j * 3 + 2] & 2) != 0;
                                crate::serial::write_str("    phys=0x");
                                crate::serial::write_hex(ALIAS_TBL[i * 3]);
                                crate::serial::write_str(" va1=0x");
                                crate::serial::write_hex(ALIAS_TBL[i * 3 + 1]);
                                crate::serial::write_str(" fl1=");
                                if u1 { crate::serial::write_str("USR"); } else { crate::serial::write_str("---"); }
                                if w1 { crate::serial::write_str("|WR"); }
                                crate::serial::write_str(" va2=0x");
                                crate::serial::write_hex(ALIAS_TBL[j * 3 + 1]);
                                crate::serial::write_str(" fl2=");
                                if u2 { crate::serial::write_str("USR"); } else { crate::serial::write_str("---"); }
                                if w2 { crate::serial::write_str("|WR"); }
                                crate::serial::write_str("\n");
                                any = true;
                            }
                        }
                    }
                }
                if !any { crate::serial::write_str("    none\n"); }
                // Phys layout of key user VAs + identity-mapping check
                for probe in [0x4FE000u64, 0x4FE280u64, 0x4FF000u64, 0x500000u64,
                    0x70000000u64, 0x70001000u64, 0x70003000u64, 0x70011000u64,
                    0x100000AB000u64, 0x100000E9B00u64, 0x3A2A000u64] {
                    let pp = crate::paging::PageTableManager::resolve_phys(gpf_cr3, probe).unwrap_or(0);
                    crate::serial::write_str("  UVA 0x");
                    crate::serial::write_hex(probe);
                    crate::serial::write_str(" -> phys=0x");
                    crate::serial::write_hex(pp);
                    if pp != 0 {
                        let ident = crate::paging::PageTableManager::resolve_phys(gpf_cr3, pp).unwrap_or(0);
                        crate::serial::write_str(" ident(VA=phys)=0x");
                        crate::serial::write_hex(ident);
                        if ident == pp {
                            crate::serial::write_str(" [IDMAP]");
                        } else {
                            crate::serial::write_str(" [NO]");
                        }
                    }
                    crate::serial::write_str("\n");
                }
                crate::task::exit_task(0);
                loop { unsafe { core::arch::asm!("cli; hlt"); } }
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

// Watchdog ring for writes to the mallocng meta page (VA 0x500000)
static mut META_WR: [(u64, u64); 16] = [(0, 0); 16];
static mut MWI: usize = 0;

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
    // Watchdog ring: record every write to the mallocng meta page (VA 0x500000)
    if cr2 >= 0x500000 && cr2 < 0x501000 && (code.bits() & 2) != 0 {
        unsafe {
            META_WR[MWI] = (rip, cr2);
            MWI = (MWI + 1) & 15;
        }
        if crate::paging::page_fault_resolve(cr2, code.bits() as u64, frame.code_segment.rpl() as u64) {
            return;
        }
    }
    // Low-VA write trap: catch corrupt mallocng group writes into the VA 0x0 page
    if cr2 < 0x1000 && (code.bits() & 2) != 0 {
        crate::klog::begin(crate::klog::LOG_WARNING, crate::klog::FAC_PAGING);
        crate::klog::s("LOWWR: rip=0x");
        crate::klog::hex(rip);
        crate::klog::s(" rsp=0x");
        crate::klog::hex(rsp);
        crate::klog::s(" cr2=0x");
        crate::klog::hex(cr2);
        crate::klog::s(" code=0x");
        crate::klog::hex(code.bits() as u64);
        crate::klog::s("\n");
        if let Some(mpp) = crate::paging::PageTableManager::resolve_phys(
            crate::task::current_task_pml4(),
            0x500000,
        ) {
            for k in [17u64, 18, 19] {
                let base = mpp + 0x18 + k * 0x28;
                let mem: u64 = unsafe { core::ptr::read_volatile((base + 0x10) as *const u64) };
                let packed: u64 = unsafe { core::ptr::read_volatile((base + 0x20) as *const u64) };
                crate::klog::s("  m[");
                crate::klog::dec(k);
                crate::klog::s("] mem=0x");
                crate::klog::hex(mem);
                crate::klog::s(" sc=");
                crate::klog::dec((packed >> 6) & 63);
                crate::klog::s("\n");
            }
        }
        crate::klog::end();
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
    if cs_val == 8 {
        // Identify the task and its kernel stack before dumping
        let tid = crate::task::current_task_id();
        crate::klog::s("  task=");
        crate::klog::dec(tid);
        crate::klog::s(" kstack=0x");
        crate::klog::hex(crate::task::task_kernel_stack_by_id(tid));
        crate::klog::s(" regs.rip=0x");
        crate::klog::hex(crate::task::current_task_regs_rip());
        crate::klog::s("\n");
        // Dump the interrupted kernel stack for a backtrace (from the faulting
        // rsp — may be garbage, so also dump the known-good region below).
        let base = frame.stack_pointer.as_u64();
        crate::klog::s("  stack[");
        for i in 0..32u64 {
            let p = (base + i * 8) as *const u64;
            let v = unsafe { core::ptr::read_volatile(p) };
            if i % 4 == 0 { crate::klog::s("\n   "); }
            crate::klog::hex(v);
            crate::klog::s(" ");
        }
        crate::klog::s("\n");
        // Dump the syscall-entry frame (the 11 callee-saved regs + CPU retaddr
        // that syscall_return pops + sysretq) and the call chain below the
        // saved resume rsp. These live at the top of the task's kernel stack.
        let kstack = crate::task::task_kernel_stack_by_id(tid);
        crate::klog::s("  kframe[kstack-0x60..kstack]:");
        for i in 0..12u64 {
            let p = (kstack - 0x60 + i * 8) as *const u64;
            let v = unsafe { core::ptr::read_volatile(p) };
            if i % 4 == 0 { crate::klog::s("\n   "); }
            crate::klog::hex(v);
            crate::klog::s(" ");
        }
        crate::klog::s("\n");
        let rsp = crate::task::current_task_regs_rsp();
        crate::klog::s("  kchain[regs.rsp..] rsp=0x");
        crate::klog::hex(rsp);
        crate::klog::s("\n");
        let mut addr = rsp;
        for _ in 0..40usize {
            if addr >= kstack - 0x60 { break; }
            let v = unsafe { core::ptr::read_volatile(addr as *const u64) };
            crate::klog::s("   0x");
            crate::klog::hex(addr);
            crate::klog::s(" 0x");
            crate::klog::hex(v);
            crate::klog::s("\n");
            addr += 8;
        }
    } else if (cs_val & 3) == 3 && cr2 == rip && (code.bits() & 0x14) == 0x14 {
        // User-mode instruction fetch fault (NX / execute of stack/data):
        // dump the user stack to trace the corrupted return-address chain.
        let base = frame.stack_pointer.as_u64();
        crate::klog::s("  ustack[");
        for i in 0..32u64 {
            let p = (base + i * 8) as *const u64;
            let v = unsafe { core::ptr::read_volatile(p) };
            if i % 4 == 0 { crate::klog::s("\n   "); }
            crate::klog::hex(v);
            crate::klog::s(" ");
        }
        crate::klog::s("\n");
    }
    crate::klog::end();

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
    crate::klog::dump();
    halt();
}

pub extern "x86-interrupt" fn machine_check(_frame: InterruptStackFrame) -> ! {
    crate::serial::write_str("EXC: Machine Check\n");
    halt();
}