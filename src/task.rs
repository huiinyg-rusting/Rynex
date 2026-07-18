use core::sync::atomic::{AtomicU64, Ordering};

use crate::memory::buddy::PAGE_SIZE;
use crate::paging::PageTableManager;
use crate::serial;

pub const MAX_TASKS: usize = 64;
pub const KERNEL_STACK_PAGES: usize = 2;
pub const USER_STACK_PAGES: usize = 8;

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
        return;
    }
    
    let old = CURRENT_TASK.swap(next_id, Ordering::SeqCst);
    if old == next_id {
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
        context_switch(&mut old_task.regs, &new_task.regs);
    }
    serial::write_str("SCHED: returned from context_switch\n");
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
        "and rax, 0xFFFFFFFFFFFFFEFF",
        "mov [rdi + 0x88], rax",
        "mov [rdi + 0x90], cs",
        "mov [rdi + 0x98], ss",
        "mov rsp, [rsi + 0x38]",
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
        "push qword ptr [rsi + 0x80]",
        "push qword ptr [rsi + 0x88]",
        "mov rsi, [rsi + 0x20]",
        "popfq",
        "ret",
    )
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

    let new_task = unsafe { &mut TASKS[(1 % MAX_TASKS as u64) as usize] };
    new_task.state = TaskState::Running;
    pt_mgr().switch_to(new_task.pml4);
    unsafe {
        context_switch(&mut TASKS[0].regs, &new_task.regs);
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