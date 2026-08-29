#![allow(static_mut_refs)]
use core::mem::size_of;

#[repr(C, packed)]
struct Gdtr {
    limit: u16,
    base: u64,
}

#[repr(C, packed)]
pub struct TaskStateSegment {
    pub reserved1: u32,
    pub rsp: [u64; 3],
    pub reserved2: u64,
    pub ist: [u64; 7],
    pub reserved3: u64,
    pub reserved4: u16,
    pub io_map_base: u16,
}

impl TaskStateSegment {
    pub const fn new() -> Self {
        TaskStateSegment {
            reserved1: 0,
            rsp: [0; 3],
            reserved2: 0,
            ist: [0; 7],
            reserved3: 0,
            reserved4: 0,
            io_map_base: 0,
        }
    }
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

/// Top of the *current* task's kernel stack. syscall_entry (context_switch.asm)
/// loads RSP from here so each task runs its syscalls on its OWN kernel stack.
/// A shared syscall stack is unsafe: a task suspended mid-syscall (e.g. blocked
/// in waitpid) would have its saved return frame clobbered by another task's
/// deeper syscalls (e.g. execve's 4KB argv_buf) running on the same stack.
///
/// syscall_entry (reached via SYSCALL/SWAPGS) must use the syscall stack of the
/// CPU it is running on, so it reads SYSCALL_STACK_TOPS indexed by LAPIC id
/// rather than this single global. Index 0 = BSP; index i = APIC/cpu i.
#[no_mangle]
pub static mut CURRENT_SYSCALL_STACK_TOP: u64 = 0;

/// Per-CPU syscall-stack tops indexed by LAPIC id (== cpu index). Kept in sync
/// with the TSS.rsp[0] each CPU installs as its syscall target: set_tss_rsp0
/// records the current task's kernel stack here on every context switch, so
/// syscall_entry on any CPU picks up the stack of the task it is running.
#[no_mangle]
pub static mut SYSCALL_STACK_TOPS: [u64; crate::percpu::MAX_CPUS] = [0; crate::percpu::MAX_CPUS];

pub fn set_tss_rsp0(rsp0: u64) {
    // Per-CPU: may run on the AP as well as the BSP. Every CPU installs the
    // current task's kernel stack into its own per-CPU TSS.rsp[0] (the HW stack
    // for an interrupt entry) and into SYSCALL_STACK_TOPS[cpu] for syscall_entry.
    let cpu = crate::task::current_cpu();
    unsafe {
        crate::percpu::percpu(cpu as u32).tss.rsp[0] = rsp0;
        SYSCALL_STACK_TOPS[cpu as usize] = rsp0;
    }
    if cpu == 0 {
        // Keep the legacy global in sync for any readers (diagnostics). The
        // BSP also uses the shared TSS for its hardware interrupt stack.
        unsafe {
            TSS.rsp[0] = rsp0;
            CURRENT_SYSCALL_STACK_TOP = rsp0;
        }
    }
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

pub const KERNEL_CODE: u64 = 0x00209A0000000000;
pub const KERNEL_DATA: u64 = 0x0000920000000000;
pub const USER_DATA: u64 = 0x0000F20000000000;
pub const USER_CODE: u64 = 0x0020FA0000000000;

pub fn setup_percpu_gdt(gdt: &mut [u64; 7], tss: &mut TaskStateSegment, ist_stacks: [u64; 4]) {
    tss.ist[0] = ist_stacks[0];
    tss.ist[1] = ist_stacks[1];
    tss.ist[2] = ist_stacks[2];
    tss.ist[3] = ist_stacks[3];

    gdt[0] = 0;
    gdt[1] = KERNEL_CODE;
    gdt[2] = KERNEL_DATA;
    gdt[3] = USER_DATA;
    gdt[4] = USER_CODE;
    let (tsk_low, tsk_high) = make_tss_descriptor(tss as *mut _ as u64, size_of::<TaskStateSegment>() as u32 - 1);
    gdt[5] = tsk_low;
    gdt[6] = tsk_high;
}

pub fn load_percpu_gdt(gdt: &[u64; 7]) {
    let gdtr = Gdtr {
        limit: (size_of::<[u64; 7]>() - 1) as u16,
        base: gdt as *const _ as u64,
    };
    unsafe {
        core::arch::asm!(
            "lgdt [{0}]",
            in(reg) &gdtr,
            options(nostack, preserves_flags)
        );
        core::arch::asm!(
            "mov rax, 0x10",
            "push 0x08",
            "lea rcx, [rip + 2f]",
            "push rcx",
            "retfq",
            "2:",
            "mov ds, ax",
            "mov es, ax",
            "mov ss, ax",
            "xor edx, edx",
            "mov fs, dx",
            "mov gs, dx",
            "mov ax, 0x28",
            "ltr ax",
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            options(nostack)
        );
    }
}
