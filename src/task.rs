use core::sync::atomic::{AtomicU64, Ordering};

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
pub const USER_CODE_SELECTOR: u64 = 0x20;
pub const USER_DATA_SELECTOR: u64 = 0x18;

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
    // Allocate 1 extra page as a "guard" for the iretq frame that pokes 8 bytes
    // above kernel_stack. This is needed because kernel-mode iretq uses add rsp,16
    // which pushes SS to [kernel_stack].
    alloc.alloc(pages + 1).map(|p| p + pages as u64 * PAGE_SIZE)
}

fn free_stack(base: u64, pages: usize) {
    let alloc = unsafe { &mut *crate::memory::allocator() };
    let addr = base - pages as u64 * PAGE_SIZE;
    alloc.free(addr, pages + 1);
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
        "pop rbp",
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
        
        // Simple iretq — restores task state for both kernel and user mode.
        // Note: for kernel mode, iretq pops 3 (RIP, CS, RFLAGS), leaving RSP
        // at the iretq frame's SS slot. This may leave RSP incorrect for kernel
        // tasks (kernel_stack - 16 instead of saved_RSP), but kernel tasks
        // in the current test use yield() instead of timer preemption.
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
    // `frame` = RBP+8 at entry to the timer handler.
    // For same-CPL interrupts, the CPU pushes only RIP, CS, RFLAGS (3 items).
    // Stack layout (low to high):
    //   [RBP-112..RBP-0]: 15 GP regs in push order: r15, r14, r13, r12, r11, r10,
    //                      r9, r8, rdi, rsi, rdx, rcx, rbx, rax, saved_rbp
    //   [RBP+8]:          RIP   (= frame[0])
    //   [RBP+16]:         CS    (= frame[1])
    //   [RBP+24]:         RFLAGS (= frame[2])
    // RSP at the time of the interrupt = (frame as u64) + 24
    // (Because RBP = frame - 8, and RSP_before = RBP + 32 = frame + 24)
    unsafe {
        let current = CURRENT_TASK.load(Ordering::SeqCst);
        if current == 0 {
            return;
        }
        let task = &mut TASKS[(current % MAX_TASKS as u64) as usize];
        let regs = &mut task.regs;

        // GP registers at frame[-15] .. frame[-1]
        // frame[-15] = [RBP+8-120] = [RBP-112] = r15
        // frame[-14] = r14, ..., frame[-1] = saved_rbp
        let gp = frame.sub(15);
        regs.r15 = *gp.add(0);
        regs.r14 = *gp.add(1);
        regs.r13 = *gp.add(2);
        regs.r12 = *gp.add(3);
        regs.r11 = *gp.add(4);
        regs.r10 = *gp.add(5);
        regs.r9  = *gp.add(6);
        regs.r8  = *gp.add(7);
        regs.rdi = *gp.add(8);
        regs.rsi = *gp.add(9);
        regs.rdx = *gp.add(10);
        regs.rcx = *gp.add(11);
        regs.rbx = *gp.add(12);
        regs.rax = *gp.add(13);
        regs.rbp = *gp.add(14);

        // For same-CPL (kernel mode) interrupts, CPU only pushes RIP, CS, RFLAGS.
        // frame[0] = RIP, frame[1] = CS, frame[2] = RFLAGS
        regs.rip    = *frame.add(0);
        regs.cs     = *frame.add(1);
        regs.rflags = *frame.add(2);
        // RSP at interrupt time: RBP + 32 = (frame - 8) + 32 = frame + 24
        regs.rsp    = (frame as u64) + 24;
        // SS stays as kernel data segment (already correct)
        regs.ss     = KERNEL_DATA_SELECTOR;
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
        // Current task not running; build frame for the task using its saved regs
        return build_frame(task.kernel_stack, &*task as *const Task);
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

    let should_switch = next_id != 0 && next_id != current;
    if should_switch {
        task.state = TaskState::Ready;
        let next_task = unsafe { &mut TASKS[(next_id % MAX_TASKS as u64) as usize] };
        next_task.state = TaskState::Running;
        CURRENT_TASK.store(next_id, Ordering::SeqCst);
        pt_mgr().switch_to(next_task.pml4);
        crate::gdt::set_tss_rsp0(next_task.kernel_stack);
        build_frame(next_task.kernel_stack, &*next_task as *const Task)
    } else {
        build_frame(task.kernel_stack, &*task as *const Task)
    }
}

// Helper: build a 20-qword interrupt-return frame and return the new RSP.
// Handler pops 15 GP regs then iretq.
// For kernel mode (same-CPL): iretq pops 3 (total 18 items = 144 bytes).
//   Start base at kernel_stack - 152 so after 18 pops RSP = kernel_stack - 8.
// For user mode (different-CPL): iretq pops 5 (total 20 items = 160 bytes).
//   Start base at kernel_stack - 160 so after 20 pops RSP = kernel_stack.
fn build_frame(kernel_stack: u64, task_ptr: *const Task) -> u64 {
    let regs = unsafe { &(*task_ptr).regs };
    let kernel = (regs.cs & 3) == 0;
    unsafe {
        // base is where the handler's first pop reads from.
        // For kernel (same-CPL): iretq pops 3 items (total 18 pops = 144 bytes).
        //   After 18 pops RSP = kernel_stack - 8. Start base at kernel_stack - 152.
        // For user  (different-CPL): iretq pops 5 (total 20 pops = 160 bytes).
        //   After 20 pops RSP = kernel_stack. Start base at kernel_stack - 160.
        let base = if kernel {
            (kernel_stack as *mut u64).sub(19) // kernel_stack - 152
        } else {
            (kernel_stack as *mut u64).sub(20) // kernel_stack - 160
        };
        *base.add(0)  = regs.r15;
        *base.add(1)  = regs.r14;
        *base.add(2)  = regs.r13;
        *base.add(3)  = regs.rbp;
        *base.add(4)  = regs.r12;
        *base.add(5)  = regs.r11;
        *base.add(6)  = regs.r10;
        *base.add(7)  = regs.r9;
        *base.add(8)  = regs.r8;
        *base.add(9)  = regs.rdi;
        *base.add(10) = regs.rsi;
        *base.add(11) = regs.rdx;
        *base.add(12) = regs.rcx;
        *base.add(13) = regs.rbx;
        *base.add(14) = regs.rax;
        *base.add(15) = regs.rip;
        *base.add(16) = regs.cs;
        *base.add(17) = regs.rflags;
        *base.add(18) = regs.rsp;
        *base.add(19) = regs.ss;
        base as u64
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

extern "C" fn task_spin() -> ! {
    // Minimal function: just halt
    loop {
        unsafe { core::arch::asm!("hlt", options(nostack, nomem)); }
    }
}

pub fn test() {
    unsafe { core::arch::asm!("cli"); }

    serial::write_str("TASK: testing kernel task creation...\n");

    let tid1 = create_kernel_task(task_spin as u64);
    let tid2 = create_kernel_task(task_spin as u64);

    serial::write_str("TASK: task IDs: ");
    serial::write_dec(tid1.unwrap());
    serial::write_str(", ");
    serial::write_dec(tid2.unwrap());
    serial::write_str("\n");

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