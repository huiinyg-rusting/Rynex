use core::sync::atomic::{AtomicU64, Ordering};

use crate::memory::buddy::PAGE_SIZE;
use crate::paging::PageTableManager;
use crate::serial;

pub const MAX_TASKS: usize = 64;
pub const KERNEL_STACK_PAGES: usize = 2;
pub const USER_STACK_PAGES: usize = 8;
pub const IRQ_BASE: u8 = 0x30;
pub const TIMER_IRQ_VECTOR: u8 = IRQ_BASE + 0;

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
            cs: 0x08, ss: 0x10,
        }
    }

    pub fn new_user(entry: u64, stack_top: u64) -> Self {
        Registers {
            rax: 0, rbx: 0, rcx: 0, rdx: 0,
            rsi: 0, rdi: 0, rbp: 0, rsp: stack_top,
            r8: 0, r9: 0, r10: 0, r11: 0,
            r12: 0, r13: 0, r14: 0, r15: 0,
            rip: entry, rflags: 0x202,
            cs: 0x1B, ss: 0x23,
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
        "push rax",
        "push rcx",
        "push rdx",
        "push rbx",
        "push rbp",
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
        "mov rdi, rsp",
        "call timer_schedule",
        "xchg rsp, rax",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rdi",
        "pop rsi",
        "pop rbp",
        "pop rbx",
        "pop rdx",
        "pop rcx",
        "pop rax",
        "iretq",
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
pub extern "C" fn timer_schedule(saved: *mut u64) -> u64 {
    crate::pic::send_eoi(0);

    let current = CURRENT_TASK.load(Ordering::SeqCst);
    if current == 0 {
        return saved as u64;
    }

    let task = unsafe { &mut TASKS[(current % MAX_TASKS as u64) as usize] };

    if task.state != TaskState::Running {
        return saved as u64;
    }

    let original_rsp = (saved as u64) + 18 * 8;

    unsafe {
        let regs = &mut task.regs;
        let s = saved;
        regs.r15 = *s.add(0);
        regs.r14 = *s.add(1);
        regs.r13 = *s.add(2);
        regs.r12 = *s.add(3);
        regs.r11 = *s.add(4);
        regs.r10 = *s.add(5);
        regs.r9  = *s.add(6);
        regs.r8  = *s.add(7);
        regs.rdi = *s.add(8);
        regs.rsi = *s.add(9);
        regs.rbp = *s.add(10);
        regs.rbx = *s.add(11);
        regs.rdx = *s.add(12);
        regs.rcx = *s.add(13);
        regs.rax = *s.add(14);
        regs.rip = *s.add(15);
        regs.cs  = *s.add(16);
        regs.rflags = *s.add(17);
        regs.rsp = original_rsp;
        regs.ss  = 0x10;
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
        return saved as u64;
    }

    task.state = TaskState::Ready;
    let next_task = unsafe { &mut TASKS[(next_id % MAX_TASKS as u64) as usize] };
    next_task.state = TaskState::Running;
    CURRENT_TASK.store(next_id, Ordering::SeqCst);

    SWITCH_TARGET_ID.store(next_id, Ordering::SeqCst);
    unsafe {
        *saved.add(15) = resume_switch as *const () as u64;
    }

    saved as u64
}

#[no_mangle]
pub extern "C" fn syscall_handler(rsp: *mut u8) -> ! {
    serial::write_str("SYSCALL: received (stub)\n");
    // TODO: implement syscall dispatch
    loop {
        unsafe { core::arch::asm!("hlt", options(nostack, nomem)); }
    }
}

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