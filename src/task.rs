use core::sync::atomic::{AtomicU64, Ordering};

use alloc::vec::Vec;

use crate::memory::buddy::PAGE_SIZE;
use crate::paging::PageTableManager;
use crate::serial;

pub const MAX_TASKS: usize = 64;
pub const KERNEL_STACK_PAGES: usize = 2;
pub const USER_STACK_PAGES: usize = 8;
pub const IRQ_BASE: u8 = 0x30;
pub const TIMER_IRQ_VECTOR: u8 = IRQ_BASE + 0;

// Segment selectors (GDT indices with RPL)
pub const KERNEL_CODE_SELECTOR: u64 = 0x08;
pub const KERNEL_DATA_SELECTOR: u64 = 0x10;
pub const USER_CODE_SELECTOR: u64 = 0x18;
pub const USER_DATA_SELECTOR: u64 = 0x20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TaskState {
    Empty = 0,
    Ready = 1,
    Running = 2,
    Blocked = 3,
    Exited = 4,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Registers {
    pub rax: u64, pub rbx: u64, pub rcx: u64, pub rdx: u64,
    pub rsi: u64, pub rdi: u64, pub rbp: u64, pub rsp: u64,
    pub r8: u64, pub r9: u64, pub r10: u64, pub r11: u64,
    pub r12: u64, pub r13: u64, pub r14: u64, pub r15: u64,
    pub rip: u64, pub rflags: u64,
    pub cs: u64, pub ss: u64,
}

impl Registers {
    pub fn new_kernel(entry: u64, stack_top: u64) -> Self {
        Registers {
            rax: 0, rbx: 0, rcx: 0, rdx: 0,
            rsi: 0, rdi: 0, rbp: 0, rsp: stack_top - 8,
            r8: 0, r9: 0, r10: 0, r11: 0,
            r12: 0, r13: 0, r14: 0, r15: 0,
            rip: entry, rflags: 0x202,
            cs: KERNEL_CODE_SELECTOR, ss: KERNEL_DATA_SELECTOR,
        }
    }

    pub fn new_user(entry: u64, stack_top: u64) -> Self {
        Registers {
            rax: 0, rbx: 0, rcx: 0, rdx: 0,
            rsi: 0, rdi: 0, rbp: 0, rsp: stack_top,
            r8: 0, r9: 0, r10: 0, r11: 0,
            r12: 0, r13: 0, r14: 0, r15: 0,
            rip: entry, rflags: 0x202,
            cs: USER_CODE_SELECTOR | 3, ss: USER_DATA_SELECTOR | 3,
        }
    }
}

#[derive(Copy, Clone)]
pub struct Task {
    pub id: u64,
    pub state: TaskState,
    pub regs: Registers,
    pub kernel_stack: u64,
    pub user_stack: u64,
    pub pml4: u64,
    pub parent: Option<u64>,
    pub exit_code: i32,
}

impl Task {
    pub const fn empty() -> Self {
        Task {
            id: 0,
            state: TaskState::Empty,
            regs: Registers {
                rax: 0, rbx: 0, rcx: 0, rdx: 0,
                rsi: 0, rdi: 0, rbp: 0, rsp: 0,
                r8: 0, r9: 0, r10: 0, r11: 0,
                r12: 0, r13: 0, r14: 0, r15: 0,
                rip: 0, rflags: 0, cs: 0, ss: 0,
            },
            kernel_stack: 0,
            user_stack: 0,
            pml4: 0,
            parent: None,
            exit_code: 0,
        }
    }
}

static mut TASKS: [Task; MAX_TASKS] = [Task::empty(); MAX_TASKS];
static CURRENT_TASK: AtomicU64 = AtomicU64::new(0);
static NEXT_TID: AtomicU64 = AtomicU64::new(1);

pub fn current_task_id() -> u64 {
    CURRENT_TASK.load(Ordering::SeqCst)
}

pub fn current_task() -> Option<&'static mut Task> {
    let id = CURRENT_TASK.load(Ordering::SeqCst);
    if id == 0 { return None; }
    unsafe { Some(&mut TASKS[(id % MAX_TASKS as u64) as usize]) }
}

pub fn task_by_id(id: u64) -> Option<&'static mut Task> {
    if id == 0 { return None; }
    unsafe { Some(&mut TASKS[(id % MAX_TASKS as u64) as usize]) }
}

fn alloc_stack(pages: usize) -> Option<u64> {
    let alloc = unsafe { &mut *crate::memory::allocator() };
    alloc.alloc(pages).map(|p| p + pages as u64 * PAGE_SIZE)
}

fn free_stack(base: u64, pages: usize) {
    let alloc = unsafe { &mut *crate::memory::allocator() };
    let addr = base - pages as u64 * PAGE_SIZE;
    alloc.free(addr, pages);
}

pub fn create_kernel_task(entry: u64) -> Option<u64> {
    let tid = NEXT_TID.fetch_add(1, Ordering::SeqCst);
    let kernel_stack = alloc_stack(KERNEL_STACK_PAGES)?;
    
    let task = unsafe { &mut TASKS[(tid % MAX_TASKS as u64) as usize] };
    task.id = tid;
    task.state = TaskState::Ready;
    task.regs = Registers::new_kernel(entry, kernel_stack);
    task.kernel_stack = kernel_stack;
    task.user_stack = 0;
    task.pml4 = pt_mgr().kernel_pml4();
    task.parent = None;
    task.exit_code = 0;

    serial::write_str("TASK: created kernel task ");
    serial::write_dec(tid);
    serial::write_str("\n");
    Some(tid)
}

pub fn create_user_task(entry: u64, pml4: u64, user_stack_top: u64) -> Option<u64> {
    let tid = NEXT_TID.fetch_add(1, Ordering::SeqCst);
    let kernel_stack = alloc_stack(KERNEL_STACK_PAGES)?;
    
    let task = unsafe { &mut TASKS[(tid % MAX_TASKS as u64) as usize] };
    task.id = tid;
    task.state = TaskState::Ready;
    task.regs = Registers::new_user(entry, user_stack_top);
    task.kernel_stack = kernel_stack;
    task.user_stack = user_stack_top;
    task.pml4 = pml4;
    task.parent = Some(current_task_id());
    task.exit_code = 0;

    serial::write_str("TASK: created user task ");
    serial::write_dec(tid);
    serial::write_str("\n");
    Some(tid)
}

pub fn init_scheduler() {
    serial::write_str("SCHED: initialized\n");
}

pub fn schedule() {
    unsafe { core::arch::asm!("cli", options(nostack, nomem, preserves_flags)); }

    let current = CURRENT_TASK.load(Ordering::SeqCst);
    let mut next_id = 0;

    for i in 1..=MAX_TASKS {
        let idx = ((current + i as u64 - 1) % MAX_TASKS as u64) + 1;
        let task = unsafe { &TASKS[(idx % MAX_TASKS as u64) as usize] };
        if task.state == TaskState::Ready && task.id != 0 {
            next_id = task.id;
            break;
        }
    }

    if next_id == 0 {
        unsafe { core::arch::asm!("sti", options(nostack, nomem, preserves_flags)); }
        return;
    }

    let old = CURRENT_TASK.swap(next_id, Ordering::SeqCst);
    if old == next_id {
        unsafe { core::arch::asm!("sti", options(nostack, nomem, preserves_flags)); }
        return;
    }

    let old_task = unsafe { &mut TASKS[(old % MAX_TASKS as u64) as usize] };
    let new_task = unsafe { &mut TASKS[(next_id % MAX_TASKS as u64) as usize] };

    if old_task.state == TaskState::Running {
        old_task.state = TaskState::Ready;
    }
    new_task.state = TaskState::Running;

    pt_mgr().switch_to(new_task.pml4);

    serial::write_str("SCHED: switching to task ");
    serial::write_dec(next_id);
    serial::write_str(" rip=");
    serial::write_hex(new_task.regs.rip);
    serial::write_str(" rsp=");
    serial::write_hex(new_task.regs.rsp);
    serial::write_str(" cs=");
    serial::write_hex(new_task.regs.cs);
    serial::write_str(" ss=");
    serial::write_hex(new_task.regs.ss);
    serial::write_str("\n");

    unsafe {
        let old_ptr = &mut old_task.regs as *mut Registers;
        let new_ptr = &new_task.regs as *const Registers;
        core::arch::asm!(
            "mov rdi, {old}",
            "mov rsi, {new}",
            "call {context_switch}",
            old = in(reg) old_ptr,
            new = in(reg) new_ptr,
            context_switch = sym context_switch,
            clobber_abi("C"),
        );
    }
}

pub fn yield_now() {
    schedule();
}

pub fn exit_task(code: i32) {
    let id = CURRENT_TASK.load(Ordering::SeqCst);
    let task = unsafe { &mut TASKS[(id % MAX_TASKS as u64) as usize] };
    task.state = TaskState::Exited;
    task.exit_code = code;
    
    free_stack(task.kernel_stack, KERNEL_STACK_PAGES);
    if task.user_stack != 0 {
        free_stack(task.user_stack, USER_STACK_PAGES);
    }
    
    schedule();
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn context_switch(old: *mut Registers, new: *const Registers) -> ! {
    core::arch::naked_asm!(
        "pop qword ptr [rdi + 0x80]",
        "mov [rdi + 0x00], rax",
        "mov [rdi + 0x08], rbx",
        "mov [rdi + 0x10], rcx",
        "mov [rdi + 0x18], rdx",
        "mov [rdi + 0x20], rsi",
        "mov [rdi + 0x28], rdi",
        "mov [rdi + 0x30], rbp",
        "mov [rdi + 0x38], rsp",
        "mov [rdi + 0x40], r8",
        "mov [rdi + 0x48], r9",
        "mov [rdi + 0x50], r10",
        "mov [rdi + 0x58], r11",
        "mov [rdi + 0x60], r12",
        "mov [rdi + 0x68], r13",
        "mov [rdi + 0x70], r14",
        "mov [rdi + 0x78], r15",
        "pushfq",
        "pop rax",
        "or rax, 0x200",
        "and rax, 0xFFFFFFFFFFFFFEFF",
        "mov [rdi + 0x88], rax",
        "mov [rdi + 0x90], cs",
        "mov [rdi + 0x98], ss",
        "mov rsp, [rsi + 0x38]",
        "add rsp, 16",
        "mov rax, [rsi + 0x00]",
        "mov rbx, [rsi + 0x08]",
        "mov rcx, [rsi + 0x10]",
        "mov rdx, [rsi + 0x18]",
        "mov rdi, [rsi + 0x28]",
        "mov rbp, [rsi + 0x30]",
        "mov r8,  [rsi + 0x40]",
        "mov r9,  [rsi + 0x48]",
        "mov r10, [rsi + 0x50]",
        "mov r11, [rsi + 0x58]",
        "mov r12, [rsi + 0x60]",
        "mov r13, [rsi + 0x68]",
        "mov r14, [rsi + 0x70]",
        "mov r15, [rsi + 0x78]",
        "push qword ptr [rsi + 0x98]",
        "push qword ptr [rsi + 0x38]",
        "push qword ptr [rsi + 0x88]",
        "push qword ptr [rsi + 0x90]",
        "push qword ptr [rsi + 0x80]",
        "mov rsi, [rsi + 0x20]",
        "iretq",
    )
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn timer_interrupt_handler() -> ! {
    core::arch::naked_asm!(
        "cld",
        // With IST, CPU already switched to kernel stack and pushed interrupt frame
        // Frame on stack (top to bottom = low to high addr):
        //   SS, RSP, RFLAGS, CS, RIP (pushed by CPU)
        
        // Save RBP as frame pointer
        "push rbp",
        "mov rbp, rsp",       // RBP points to saved RBP; interrupt frame at RBP+8
        
        // Save GP registers (except RSP which is in frame)
        "push rax",
        "push rbx",
        "push rcx",
        "push rdx",
        "push rsi",
        "push rdi",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        
        // RBP points to saved RBP; interrupt frame is at RBP+8
        // Frame layout at RBP+8: [SS] [RSP] [RFLAGS] [CS] [RIP]
        "mov rdi, rbp",
        "add rdi, 8",         // RDI = pointer to interrupt frame (SS at [rdi])
        "call {save_context}",
        
        // Call scheduler - keep kernel CR3 active for timer_schedule
        "call {timer_schedule}",
        
        // timer_schedule returns new task's stack pointer in RAX
        // (already switched CR3 to new task's page tables)
        "mov rsp, rax",
        
        // Restore registers from new task
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r13",
        "pop r12",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "pop rbx",
        "pop rax",
        
        // The interrupt frame (SS, RSP, RFLAGS, CS, RIP) is now at top of stack
        // iretq will restore everything and return to the new task
        "iretq",
        
        save_context = sym save_interrupt_context,
        timer_schedule = sym timer_schedule,
    )
}

static SWITCH_TARGET_ID: AtomicU64 = AtomicU64::new(0);

static mut TMP_REGS: Registers = Registers {
    rax: 0, rbx: 0, rcx: 0, rdx: 0, rsi: 0, rdi: 0, rbp: 0, rsp: 0,
    r8: 0, r9: 0, r10: 0, r11: 0, r12: 0, r13: 0, r14: 0, r15: 0,
    rip: 0, rflags: 0, cs: 0, ss: 0,
};

extern "C" fn resume_switch() -> ! {
    unsafe { core::arch::asm!("cli", options(nostack, nomem)); }
    let next_id = SWITCH_TARGET_ID.swap(0, Ordering::SeqCst);
    let next_task = unsafe { &mut TASKS[(next_id % MAX_TASKS as u64) as usize] };
    unsafe {
        context_switch(&mut TMP_REGS, &next_task.regs);
    }
}

#[no_mangle]
pub extern "C" fn save_interrupt_context(frame: *mut u64) {
    // `frame` points to the interrupt frame on the stack (user SS at offset 0).
    // The GP registers were pushed before the frame, so they're at negative offsets.
    // Stack layout at entry to this function (from frame = RBP+8):
    //   frame[-15] = RAX, frame[-14] = RBX, frame[-13] = RCX, frame[-12] = RDX,
    //   frame[-11] = RSI, frame[-10] = RDI, frame[-9] = RBP, frame[-8] = R8,
    //   frame[-7] = R9, frame[-6] = R10, frame[-5] = R11, frame[-4] = R12,
    //   frame[-3] = R13, frame[-2] = R14, frame[-1] = R15
    //   frame[0] = SS, frame[1] = RSP, frame[2] = RFLAGS, frame[3] = CS, frame[4] = RIP
    unsafe {
        let current = CURRENT_TASK.load(Ordering::SeqCst);
        if current == 0 {
            return;
        }
        let task = &mut TASKS[(current % MAX_TASKS as u64) as usize];
        let regs = &mut task.regs;

        // GP registers are at frame[-15] .. frame[-1]
        let gp = frame.sub(15);
        regs.rax = *gp.add(0);
        regs.rbx = *gp.add(1);
        regs.rcx = *gp.add(2);
        regs.rdx = *gp.add(3);
        regs.rsi = *gp.add(4);
        regs.rdi = *gp.add(5);
        regs.rbp = *gp.add(6);
        regs.r8  = *gp.add(7);
        regs.r9  = *gp.add(8);
        regs.r10 = *gp.add(9);
        regs.r11 = *gp.add(10);
        regs.r12 = *gp.add(11);
        regs.r13 = *gp.add(12);
        regs.r14 = *gp.add(13);
        regs.r15 = *gp.add(14);

        // Interrupt frame at frame[0..4]: SS, RSP, RFLAGS, CS, RIP
        regs.ss    = *frame.add(0);
        regs.rsp   = *frame.add(1);
        regs.rflags = *frame.add(2);
        regs.cs    = *frame.add(3);
        regs.rip   = *frame.add(4);
    }
}

#[no_mangle]
pub extern "C" fn inc_ticks() {
    crate::pit::TICKS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn timer_schedule() -> u64 {
    crate::pic::send_eoi(0);

    let current = CURRENT_TASK.load(Ordering::SeqCst);
    if current == 0 {
        return 0;
    }

    let task = unsafe { &mut TASKS[(current % MAX_TASKS as u64) as usize] };

    if task.state != TaskState::Running {
        return task.kernel_stack;
    }

    let mut next_id = 0;
    for i in 1..=MAX_TASKS {
        let idx = ((current + i as u64 - 1) % MAX_TASKS as u64) + 1;
        let t = unsafe { &TASKS[(idx % MAX_TASKS as u64) as usize] };
        if t.state == TaskState::Ready && t.id != 0 {
            next_id = t.id;
            break;
        }
    }

    if next_id == 0 || next_id == current {
        return task.kernel_stack;
    }

    task.state = TaskState::Ready;
    let next_task = unsafe { &mut TASKS[(next_id % MAX_TASKS as u64) as usize] };
    next_task.state = TaskState::Running;
    CURRENT_TASK.store(next_id, Ordering::SeqCst);

    // Switch page tables
    pt_mgr().switch_to(next_task.pml4);
    // Update TSS for the new task
    crate::gdt::set_tss_rsp0(next_task.kernel_stack);

    // Build the full context frame on the new task's kernel stack
    // Stack layout (growing down, RSP points to lowest address):
    // offset 0:   R15
    // offset 8:   R14
    // offset 16:  R13
    // offset 24:  R12
    // offset 32:  R11
    // offset 40:  R10
    // offset 48:  R9
    // offset 56:  R8
    // offset 64:  RDI
    // offset 72:  RSI
    // offset 80:  RDX
    // offset 88:  RCX
    // offset 96:  RBX
    // offset 104: RAX
    // offset 112: RIP
    // offset 120: CS
    // offset 128: RFLAGS
    // offset 136: RSP
    // offset 144: SS
    // Total: 19 qwords = 152 bytes
    // RSP will point to offset 0 (R15) after setup
    let stack_ptr = next_task.kernel_stack;
    unsafe {
        let sp = (stack_ptr as *mut u64).sub(19); // 14 GP regs + 5 iretq frame = 19 qwords
        
        // GP registers in pop order (handler pops: R15, R14, ..., RAX)
        *sp.add(0)  = next_task.regs.r15;
        *sp.add(1)  = next_task.regs.r14;
        *sp.add(2)  = next_task.regs.r13;
        *sp.add(3)  = next_task.regs.r12;
        *sp.add(4)  = next_task.regs.r11;
        *sp.add(5)  = next_task.regs.r10;
        *sp.add(6)  = next_task.regs.r9;
        *sp.add(7)  = next_task.regs.r8;
        *sp.add(8)  = next_task.regs.rdi;
        *sp.add(9)  = next_task.regs.rsi;
        *sp.add(10) = next_task.regs.rdx;
        *sp.add(11) = next_task.regs.rcx;
        *sp.add(12) = next_task.regs.rbx;
        *sp.add(13) = next_task.regs.rax;
        
        // iretq frame (popped by iretq instruction)
        *sp.add(14) = next_task.regs.rip;
        *sp.add(15) = next_task.regs.cs;
        *sp.add(16) = next_task.regs.rflags;
        *sp.add(17) = next_task.regs.rsp;
        *sp.add(18) = next_task.regs.ss;
        
        sp as u64
    }
}

#[no_mangle]
pub extern "C" fn syscall_handler(
    syscall_num: u64,
    arg1: u64, arg2: u64, arg3: u64,
    arg4: u64, arg5: u64, arg6: u64
) -> i64 {
    // Simple syscall dispatcher
    match syscall_num {
        0 => sys_exit(arg1 as i32),
        1 => sys_write(arg1 as u32, arg2 as *const u8, arg3 as usize),
        2 => sys_get_ticks(),
        3 => sys_yield(),
        _ => -ENOSYS,
    }
}

fn sys_exit(status: i32) -> i64 {
    crate::serial::write_str("SYS_EXIT: ");
    crate::serial::write_dec(status as u64);
    crate::serial::write_str("\n");
    
    // Mark current task as exited
    let id = crate::task::CURRENT_TASK.load(core::sync::atomic::Ordering::SeqCst);
    if id != 0 {
        let task = unsafe { &mut crate::task::TASKS[(id % crate::task::MAX_TASKS as u64) as usize] };
        task.state = crate::task::TaskState::Exited;
        task.exit_code = status;
    }
    
    // Yield to next task
    crate::task::yield_now();
    
    // Should not reach here
    0
}

fn sys_write(fd: u32, buf: *const u8, count: usize) -> i64 {
    // Only support stdout (fd == 1) for now, writing to serial
    if fd == 1 && !buf.is_null() && count > 0 {
        // Copy the string from user space to kernel space temporarily
        // This is unsafe but OK for demo - in real OS we'd need proper copying
        let mut total = 0;
        while total < count {
            let c = unsafe { *buf.add(total) };
            if c == 0 {
                break; // null terminator
            }
            crate::serial::write_char(c as char);
            total += 1;
        }
        total as i64
    } else {
        -EBADF
    }
}

fn sys_get_ticks() -> i64 {
    // Return a simple tick count
    unsafe { crate::pit::TICKS.load(core::sync::atomic::Ordering::Relaxed) as i64 }
}

fn sys_yield() -> i64 {
    crate::task::yield_now();
    0
}

// Error constants
const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const ESRCH: i64 = -3;
const EINTR: i64 = -4;
const EIO: i64 = -5;
const ENXIO: i64 = -6;
const E2BIG: i64 = -7;
const ENOEXEC: i64 = -8;
const EBADF: i64 = -9;
const ECHILD: i64 = -10;
const EAGAIN: i64 = -11;
const ENOMEM: i64 = -12;
const EACCES: i64 = -13;
const EFAULT: i64 = -14;
const ENOTBLK: i64 = -15;
const EBUSY: i64 = -16;
const EEXIST: i64 = -17;
const EXDEV: i64 = -18;
const ENODEV: i64 = -19;
const ENOTDIR: i64 = -20;
const EISDIR: i64 = -21;
const EINVAL: i64 = -22;
const ENFILE: i64 = -23;
const EMFILE: i64 = -24;
const ENOTTY: i64 = -25;
const ETXTBSY: i64 = -26;
const EFBIG: i64 = -27;
const ENOSPC: i64 = -28;
const ESPIPE: i64 = -29;
const EROFS: i64 = -30;
const EMLINK: i64 = -31;
const EPIPE: i64 = -32;
const EDOM: i64 = -33;
const ERANGE: i64 = -34;
const ENOSYS: i64 = -38; // Function not implemented

pub fn pt_mgr() -> &'static mut PageTableManager {
    crate::paging::pt_mgr()
}

extern "C" fn task_a() -> ! {
    serial::write_str("TASK A: START\n");
    for i in 0..5 {
        serial::write_str("TASK A: ");
        serial::write_dec(i);
        serial::write_str("\n");
        yield_now();
    }
    loop { unsafe { core::arch::asm!("pause", options(nostack, nomem)); } }
}

extern "C" fn task_b() -> ! {
    serial::write_str("TASK B: START\n");
    for i in 0..5 {
        serial::write_str("TASK B: ");
        serial::write_dec(i);
        serial::write_str("\n");
        yield_now();
    }
    loop { unsafe { core::arch::asm!("pause", options(nostack, nomem)); } }
}

pub fn test() {
    unsafe { core::arch::asm!("cli"); }

    serial::write_str("TASK: testing kernel task creation...\n");

    let tid1 = create_kernel_task(task_a as u64);
    let tid2 = create_kernel_task(task_b as u64);

    serial::write_str("TASK: task IDs: ");
    serial::write_dec(tid1.unwrap());
    serial::write_str(", ");
    serial::write_dec(tid2.unwrap());
    serial::write_str("\n");

    // Set USER on kernel PML4 entries used by user space (PML4 indices 0-255)
    {
        let pml4 = pt_mgr().kernel_pml4() as *mut u64;
        for i in 0..256 {
            let entry = unsafe { *pml4.add(i) };
            if entry & crate::paging::PTE_PRESENT != 0 {
                unsafe { *pml4.add(i) = entry | crate::paging::PTE_USER; }
            }
        }
        // Flush TLB for the entire user range
        unsafe { core::arch::asm!("mov rax, cr3", "mov cr3, rax", out("rax") _, options(nostack)); }
    }

    // Create user task (kernel PML4)
    serial::write_str("TASK: creating user task...\n");
    let entry = 0x4000_0000u64; // 1 GB
    let alloc = unsafe { &mut *crate::memory::allocator() };
    let code_phys = alloc.alloc(0).expect("code page");
    
    // Simple user program that writes "Hello from user mode!\n" via syscall and exits
    // x86-64 syscall: rax = syscall number, rdi, rsi, rdx, r10, r8, r9 = args
    // sys_write: rax = 1, rdi = fd (1 for stdout), rsi = buf, rdx = count
    // sys_exit: rax = 60, rdi = exit code
    let message = b"Hello from user mode!\n";
    let msg_ptr = message.as_ptr() as u64;
    let msg_len = message.len();
    
    // Machine code for:
    // mov eax, 1          ; sys_write
    // mov edi, 1          ; fd = stdout
    // lea rsi, [rip+msg]  ; message address
    // mov edx, len        ; message length
    // syscall             ; make syscall
    // mov eax, 60         ; sys_exit
    // xor edi, edi        ; exit code = 0
    // syscall             ; make syscall
    // msg:
    // .string "Hello from user mode!\n"
    let mut code: Vec<u8> = Vec::new();
    code.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
    code.extend_from_slice(&[0xBF, 0x01, 0x00, 0x00, 0x00]); // mov edi, 1
    // lea rsi, [rip+msg] - we'll fix this up after we know the msg address
    code.extend_from_slice(&[0x48, 0x8D, 0x35, 0x00, 0x00, 0x00, 0x00]); // lea rsi, [rip+0x00000000]
    code.extend_from_slice(&[0xBA, 0x00, 0x00, 0x00, 0x00]); // mov edx, 0 (length placeholder)
    code.extend_from_slice(&[0x0F, 0x05]); // syscall
    code.extend_from_slice(&[0xB8, 0x3C, 0x00, 0x00, 0x00]); // mov eax, 60
    code.extend_from_slice(&[0x31, 0xFF]); // xor edi, edi
    code.extend_from_slice(&[0x0F, 0x05]); // syscall
    
    // Now we need to place the message and fix up the addresses
    let msg_offset = code.len();
    code.extend_from_slice(message);
    
    // Fix up the lea rsi, [rip+msg] instruction
    // The instruction is at offset 7 in our code (after mov eax,1; mov edi,1;)
    // It's a 7-byte instruction: 48 8D 35 xx xx xx xx
    // We need to set the offset field (bytes 3-6) to: msg_addr - (addr_of_next_instruction)
    let lea_offset = 7usize;
    let rip_after_lea = (lea_offset + 7) as isize;
    let msg_addr = msg_offset as isize;
    let rel_offset = msg_addr - rip_after_lea;
    
    // Write the offset into the instruction (little-endian)
    code[lea_offset + 3] = (rel_offset & 0xFF) as u8;
    code[lea_offset + 4] = ((rel_offset >> 8) & 0xFF) as u8;
    code[lea_offset + 5] = ((rel_offset >> 16) & 0xFF) as u8;
    code[lea_offset + 6] = ((rel_offset >> 24) & 0xFF) as u8;
    
    // Fix up the mov edx, length instruction
    // This is at offset 16 in our code (after the syscall instruction)
    // It's a 5-byte instruction: B8 xx xx xx xx
    let len_offset = 16usize;
    code[len_offset + 1] = (msg_len & 0xFF) as u8;
    code[len_offset + 2] = ((msg_len >> 8) & 0xFF) as u8;
    code[len_offset + 3] = ((msg_len >> 16) & 0xFF) as u8;
    code[len_offset + 4] = ((msg_len >> 24) & 0xFF) as u8;
    
    unsafe { core::ptr::write_bytes(code_phys as *mut u8, 0, 4096); }
    unsafe { core::ptr::copy_nonoverlapping(code.as_ptr() as *const u8, code_phys as *mut u8, code.len()); }
    // Map user code via map_page
    pt_mgr().map_page(entry, code_phys, crate::paging::PTE_PRESENT|crate::paging::PTE_USER|crate::paging::PTE_WRITABLE).expect("map code");
    unsafe { core::arch::asm!("invlpg [{}]", in(reg) entry, options(nostack, preserves_flags)); }

// Map user stack (256 pages)
    let ustack_top = crate::paging::USER_STACK_TOP;
    let ustack_base = ustack_top - (1 << USER_STACK_PAGES) * crate::paging::PAGE_SIZE_4K;
    for i in 0..(1usize << USER_STACK_PAGES) {
        let phys = alloc.alloc(0).expect("stack page");
        let virt = ustack_base + i as u64 * crate::paging::PAGE_SIZE_4K;
        // Map in user page tables (with PTE_USER for user access)
        pt_mgr().map_page(virt, phys, crate::paging::PTE_PRESENT|crate::paging::PTE_USER|crate::paging::PTE_WRITABLE|crate::paging::PTE_NO_EXECUTE).expect("map stack user");
        // Kernel can access these pages too since user PML4 = kernel PML4
    }
    create_user_task(entry, pt_mgr().kernel_pml4(), ustack_top).expect("create user task");

    let task0 = unsafe { &mut TASKS[0] };
    task0.id = 0;
    task0.state = TaskState::Running;
    task0.kernel_stack = alloc_stack(KERNEL_STACK_PAGES).expect("task0 stack");
    task0.regs = Registers::new_kernel(continue_after_schedule as u64, task0.kernel_stack);
    task0.pml4 = pt_mgr().kernel_pml4();
    CURRENT_TASK.store(0, Ordering::SeqCst);

    unsafe {
        core::arch::asm!("mov rsp, {}", in(reg) task0.kernel_stack);
    }

    serial::write_str("TASK: switching to task 1...\n");

    unsafe { core::arch::asm!("cli"); }

    let new_task = unsafe { &mut TASKS[(1 % MAX_TASKS as u64) as usize] };
    new_task.state = TaskState::Running;
    CURRENT_TASK.store(1, Ordering::SeqCst);
    pt_mgr().switch_to(new_task.pml4);
    unsafe {
        let old_ptr = &mut TASKS[0].regs as *mut Registers;
        let new_ptr = &new_task.regs as *const Registers;
        core::arch::asm!(
            "mov rdi, {old}",
            "mov rsi, {new}",
            "call {context_switch}",
            old = in(reg) old_ptr,
            new = in(reg) new_ptr,
            context_switch = sym context_switch,
            clobber_abi("C"),
        );
    }

    serial::write_str("TASK: back in task 0\n");
    loop {
        unsafe { core::arch::asm!("hlt", options(nostack, nomem)); }
    }
}

extern "C" fn continue_after_schedule() {
    serial::write_str("TASK: all tasks exited\n");
    loop {
        unsafe { core::arch::asm!("hlt", options(nostack, nomem)); }
    }
}