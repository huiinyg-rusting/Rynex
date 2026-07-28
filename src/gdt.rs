#![allow(static_mut_refs)]
use core::mem::size_of;

#[repr(C, packed)]
struct Gdtr {
    limit: u16,
    base: u64,
}

#[repr(C, packed)]
struct TaskStateSegment {
    reserved1: u32,
    rsp: [u64; 3],
    reserved2: u64,
    ist: [u64; 7],
    reserved3: u64,
    reserved4: u16,
    io_map_base: u16,
}

fn make_tss_descriptor(addr: u64, limit: u32) -> (u64, u64) {
    let low = (limit as u64 & 0xFFFF)
        | ((addr & 0xFFFF) << 16)
        | ((addr & 0xFF0000) << 16)
        | (0x89u64 << 40)
        | (((limit >> 16) as u64 & 0xF) << 48)
        | (((addr >> 24) & 0xFF) << 56);
    let high = addr >> 32;
    (low, high)
}

static mut DF_STACK: [u8; 4096] = [0; 4096];
static mut TIMER_STACK: [u8; 4096] = [0; 4096];
static mut SYSCALL_STACK: [u8; 4096] = [0; 4096];
static mut PF_STACK: [u8; 4096] = [0; 4096];
static mut GDT: [u64; 7] = [
    0,                              // 0x00: null
    0x00209A0000000000,             // 0x08: ring0 code (64-bit, DPL=0)
    0x0000920000000000,             // 0x10: ring0 data (DPL=0)
    0x0000F20000000000,             // 0x18: ring3 data (DPL=3)
    0x0020FA0000000000,             // 0x20: ring3 code (64-bit, DPL=3)
    0,                              // 0x28: TSS low (filled in init)
    0,                              // 0x30: TSS high (filled in init)
];
static mut TSS: TaskStateSegment = TaskStateSegment {
    reserved1: 0,
    rsp: [0; 3],
    reserved2: 0,
    ist: [0; 7],
    reserved3: 0,
    reserved4: 0,
    io_map_base: 0,
};

pub fn set_tss_rsp0(rsp0: u64) {
    unsafe { TSS.rsp[0] = rsp0; }
}

pub fn get_tss_rsp0() -> u64 {
    unsafe { TSS.rsp[0] }
}

pub fn init() {
    unsafe {
        let df_top = DF_STACK.as_ptr() as u64 + DF_STACK.len() as u64;
        let timer_top = TIMER_STACK.as_ptr() as u64 + TIMER_STACK.len() as u64;
        let syscall_top = SYSCALL_STACK.as_ptr() as u64 + SYSCALL_STACK.len() as u64;
        let pf_top = PF_STACK.as_ptr() as u64 + PF_STACK.len() as u64;
        
        TSS.ist[0] = df_top;        // IST 1: Double Fault
        TSS.ist[1] = timer_top;     // IST 2: Timer
        TSS.ist[2] = syscall_top;   // IST 3: Syscall
        TSS.ist[3] = pf_top;        // IST 4: Page Fault

        crate::serial::write_str("GDT: DF_STACK top=0x");
        crate::serial::write_hex(df_top);
        crate::serial::write_str(" PF_STACK top=0x");
        crate::serial::write_hex(pf_top);
        crate::serial::write_str(" TSS.ist[0]=0x");
        crate::serial::write_hex(TSS.ist[0]);
        crate::serial::write_str(" TSS.ist[3]=0x");
        crate::serial::write_hex(TSS.ist[3]);
        crate::serial::write_str("\n");

        let tss_addr = &TSS as *const _ as u64;
        let (tsk_low, tss_high) = make_tss_descriptor(tss_addr, size_of::<TaskStateSegment>() as u32 - 1);
        GDT[5] = tsk_low;
        GDT[6] = tss_high;

        let gdtr = Gdtr {
            limit: (size_of::<[u64; 7]>() - 1) as u16,
            base: &GDT as *const _ as u64,
        };

        core::arch::asm!(
            "lgdt [{0}]",
            in(reg) &gdtr,
            options(nostack, preserves_flags)
        );

        core::arch::asm!(
            "mov r8, 0x10",
            "push 0x08",
            "lea rax, [rip + 2f]",
            "push rax",
            "retfq",
            "2:",
            "mov ds, r8w",
            "mov es, r8w",
            "mov ss, r8w",
            "xor ecx, ecx",
            "mov fs, cx",
            "mov gs, cx",
            "mov r8w, 0x28",
            "ltr r8w",
            out("rax") _,
            out("rcx") _,
            out("r8") _,
            options(nostack)
        );
    }
}
