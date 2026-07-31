use core::sync::atomic::{AtomicU64, Ordering};

use crate::memory::buddy::PAGE_SIZE;
use crate::paging::PageTableManager;
use crate::paging::PAGE_SIZE_4K;
use crate::serial;

pub const MAX_TASKS: usize = 64;
pub const KERNEL_STACK_PAGES: usize = 2;
pub const USER_STACK_PAGES: usize = 8;
pub const IRQ_BASE: u8 = 0x30;
pub const TIMER_IRQ_VECTOR: u8 = IRQ_BASE + 0;

// Virtual address for the user TLS/TCB page (one page below user stack)
pub const USER_TLS_VADDR: u64 = 0x0000_7FFF_FFFF_A000;

pub const KERNEL_CODE_SELECTOR: u64 = 0x08;
pub const KERNEL_DATA_SELECTOR: u64 = 0x10;
pub const USER_CODE_SELECTOR: u64 = 0x20;
pub const USER_DATA_SELECTOR: u64 = 0x18;

// Priority: internal 0..39 maps to Linux nice -20..19
pub const PRIORITY_LEVELS: usize = 40;
pub const PRIORITY_HIGHEST: u8 = 0;
pub const PRIORITY_LOWEST: u8 = 39;
pub const PRIORITY_DEFAULT_NICE: i32 = 0;
pub const PRIORITY_DEFAULT: u8 = 20;

pub const fn nice_to_prio(nice: i32) -> u8 {
    (nice + 20) as u8
}

pub const fn prio_to_nice(prio: u8) -> i32 {
    (prio as i32) - 20
}

fn initial_time_slice(prio: u8) -> u32 {
    let t = 8u32.saturating_sub((prio as u32) * 5 / 40);
    if t < 2 { 2 } else { t }
}

#[no_mangle]
pub extern "C" fn debug_print_hex(val: u64) {
    serial::write_str(".");
    serial::write_hex(val);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TaskState {
    Empty = 0,
    Ready = 1,
    Running = 2,
    Blocked = 3,
    Exited = 4,
    Zombie = 5,
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
    pub fs_base: u64,
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
            fs_base: 0,
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
            fs_base: 0,
        }
    }
}

#[derive(Copy, Clone)]
pub struct Vma {
    pub start: u64,
    pub end: u64,
    pub flags: u64,
}

pub const MAX_VMAS: usize = 16;

#[derive(Copy, Clone)]
pub struct Task {
    pub id: u64,
    pub tgid: u64,
    pub state: TaskState,

    pub regs: Registers,
    pub kernel_stack: u64,
    pub user_stack: u64,
    pub pml4: u64,

    // Linux task_struct scheduling fields
    pub static_prio: u8,
    pub normal_prio: u8,
    pub prio: u8,
    pub time_slice: u32,

    pub parent: Option<u64>,
    pub children_head: Option<u64>,
    pub sibling_next: Option<u64>,

    pub blocked_on: u64,
    pub pi_boosted: bool,

    pub runqueue_next: Option<u64>,

    pub ipc_partner: u64,
    pub ipc_phys: u64,
    pub ipc_vaddr: u64,

    pub exit_code: i32,

    // brk / heap
    pub brk_start: u64,
    pub brk_end: u64,

    // VMAs for mmap/demand paging
    pub vmas: [Vma; MAX_VMAS],

    // For sleep syscall
    pub wakeup_tick: u64,
}

impl Task {
    pub const fn empty() -> Self {
        Task {
            id: 0,
            tgid: 0,
            state: TaskState::Empty,
            regs: Registers {
                rax: 0, rbx: 0, rcx: 0, rdx: 0,
                rsi: 0, rdi: 0, rbp: 0, rsp: 0,
                r8: 0, r9: 0, r10: 0, r11: 0,
                r12: 0, r13: 0, r14: 0, r15: 0,
                rip: 0, rflags: 0, cs: 0, ss: 0,
                fs_base: 0,
            },
            kernel_stack: 0,
            user_stack: 0,
            pml4: 0,
            static_prio: PRIORITY_DEFAULT,
            normal_prio: PRIORITY_DEFAULT,
            prio: PRIORITY_DEFAULT,
            time_slice: 0,
            parent: None,
            children_head: None,
            sibling_next: None,
            blocked_on: 0,
            pi_boosted: false,
            runqueue_next: None,
            ipc_partner: 0,
            ipc_phys: 0,
            ipc_vaddr: 0,
            exit_code: 0,
            brk_start: 0,
            brk_end: 0,
            vmas: [Vma { start: 0, end: 0, flags: 0 }; MAX_VMAS],
            wakeup_tick: 0,
        }
    }
}

// 40-level bitmap + per-level singly-linked list runqueue
struct RunQueue {
    bitmap: u64,
    heads: [Option<u64>; PRIORITY_LEVELS],
    tails: [Option<u64>; PRIORITY_LEVELS],
    nr_running: u32,
}

impl RunQueue {
    const fn new() -> Self {
        RunQueue {
            bitmap: 0,
            heads: [None; PRIORITY_LEVELS],
            tails: [None; PRIORITY_LEVELS],
            nr_running: 0,
        }
    }
}

static mut TASKS: [Task; MAX_TASKS] = [Task::empty(); MAX_TASKS];
static mut RUNQUEUE: RunQueue = RunQueue::new();
static CURRENT_TASK: AtomicU64 = AtomicU64::new(0);
static NEXT_TID: AtomicU64 = AtomicU64::new(1);

// Debug: count context switches
static SWITCH_COUNT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

// Scratch buffer for timer interrupt frame (kernel tasks only).
// build_frame writes 20×8 = 160 bytes. Kernel tasks use this instead of
// writing to kernel_stack-160, which would corrupt the call chain.
static mut TIMER_FRAME_SCRATCH: [u64; 20] = [0; 20];

// Scratch area for kernel→kernel preemption trampoline.
// Stores [real_rax, real_rdx, real_rip] for the task being resumed.
static mut PREEMPT_SCRATCH: [u64; 3] = [0; 3];

pub fn current_task_id() -> u64 {
    CURRENT_TASK.load(Ordering::SeqCst)
}

fn task_idx(id: u64) -> usize {
    (id % MAX_TASKS as u64) as usize
}

pub fn current_task() -> Option<&'static mut Task> {
    let id = CURRENT_TASK.load(Ordering::SeqCst);
    if id == 0 { return None; }
    unsafe { Some(&mut TASKS[task_idx(id)]) }
}

pub fn task_by_id(id: u64) -> Option<&'static mut Task> {
    if id == 0 { return None; }
    unsafe { Some(&mut TASKS[task_idx(id)]) }
}

// ── Runqueue operations ──────────────────────────────────────────

fn enqueue_task(tid: u64, prio: u8) {
    unsafe {
        let rq = &mut RUNQUEUE;
        let idx = task_idx(tid);
        TASKS[idx].runqueue_next = None;

        let p = prio as usize;
        if rq.tails[p].is_none() {
            rq.heads[p] = Some(tid);
            rq.tails[p] = Some(tid);
            rq.bitmap |= 1u64 << p;
        } else {
            let tail_id = rq.tails[p].unwrap();
            TASKS[task_idx(tail_id)].runqueue_next = Some(tid);
            rq.tails[p] = Some(tid);
        }
        rq.nr_running += 1;
    }
}

fn dequeue_task() -> Option<u64> {
    unsafe {
        let rq = &mut RUNQUEUE;
        if rq.bitmap == 0 {
            return None;
        }
        let p = rq.bitmap.trailing_zeros() as usize;
        let tid = rq.heads[p].take()?;
        let idx = task_idx(tid);
        rq.heads[p] = TASKS[idx].runqueue_next;
        TASKS[idx].runqueue_next = None;
        if rq.heads[p].is_none() {
            rq.tails[p] = None;
            rq.bitmap &= !(1u64 << p);
        }
        rq.nr_running -= 1;
        Some(tid)
    }
}

fn remove_from_runqueue(tid: u64) -> bool {
    unsafe {
        let rq = &mut RUNQUEUE;
        let idx = task_idx(tid);
        let prio = TASKS[idx].prio as usize;

        let mut prev: Option<u64> = None;
        let mut curr = rq.heads[prio];
        while let Some(cid) = curr {
            if cid == tid {
                if let Some(pid) = prev {
                    TASKS[task_idx(pid)].runqueue_next = TASKS[idx].runqueue_next;
                } else {
                    rq.heads[prio] = TASKS[idx].runqueue_next;
                }
                if rq.tails[prio] == Some(tid) {
                    rq.tails[prio] = prev;
                }
                TASKS[idx].runqueue_next = None;
                if rq.heads[prio].is_none() {
                    rq.bitmap &= !(1u64 << prio);
                }
                rq.nr_running -= 1;
                return true;
            }
            prev = curr;
            curr = TASKS[task_idx(cid)].runqueue_next;
        }
        false
    }
}

fn requeue_current() {
    let id = CURRENT_TASK.load(Ordering::SeqCst);
    if id == 0 { return; }
    unsafe {
        let idx = task_idx(id);
        if TASKS[idx].state == TaskState::Running || TASKS[idx].state == TaskState::Ready {
            TASKS[idx].state = TaskState::Ready;
            enqueue_task(id, TASKS[idx].prio);
        }
    }
}

// ── Stack management ─────────────────────────────────────────────

fn alloc_stack(pages: usize) -> Option<u64> {
    let alloc = unsafe { &mut *crate::memory::allocator() };
    alloc.alloc(pages + 1).map(|p| p + pages as u64 * PAGE_SIZE)
}

fn free_stack(base: u64, pages: usize) {
    let alloc = unsafe { &mut *crate::memory::allocator() };
    let addr = base - pages as u64 * PAGE_SIZE;
    alloc.free(addr, pages + 1);
}

// ── Task creation ────────────────────────────────────────────────

pub fn create_kernel_task(entry: u64) -> Option<u64> {
    create_kernel_task_prio(entry, PRIORITY_DEFAULT_NICE)
}

pub fn create_kernel_task_prio(entry: u64, nice: i32) -> Option<u64> {
    let tid = NEXT_TID.fetch_add(1, Ordering::SeqCst);
    let kernel_stack = alloc_stack(KERNEL_STACK_PAGES)?;

    let task = unsafe { &mut TASKS[task_idx(tid)] };
    task.id = tid;
    task.tgid = tid;
    task.state = TaskState::Ready;
    task.regs = Registers::new_kernel(entry, kernel_stack);
    task.kernel_stack = kernel_stack;
    task.user_stack = 0;
    task.pml4 = pt_mgr().kernel_pml4();
    task.static_prio = nice_to_prio(nice);
    task.normal_prio = task.static_prio;
    task.prio = task.static_prio;
    task.time_slice = initial_time_slice(task.prio);
    task.parent = None;

    enqueue_task(tid, task.prio);

    serial::write_str("TASK: created kernel task ");
    serial::write_dec(tid);
    serial::write_str(" nice=");
    if nice < 0 {
        serial::write_char('-');
        serial::write_dec((-nice) as u64);
    } else {
        serial::write_dec(nice as u64);
    }
    serial::write_str("\n");
    Some(tid)
}

pub fn create_user_task(entry: u64, pml4: u64, user_stack_top: u64) -> Option<u64> {
    create_user_task_prio(entry, pml4, user_stack_top, PRIORITY_DEFAULT_NICE)
}

pub fn create_user_task_prio(entry: u64, pml4: u64, user_stack_top: u64, nice: i32) -> Option<u64> {
    let tid = NEXT_TID.fetch_add(1, Ordering::SeqCst);
    let kernel_stack = alloc_stack(KERNEL_STACK_PAGES)?;

    // Set up TLS/TCB page for musl (minimal — __init_tp fills the rest)
    //   [tp+0x00] = self pointer (struct pthread *)
    let tls_phys = unsafe { &mut *crate::memory::allocator() }.alloc(0)?;
    unsafe {
        core::ptr::write_bytes(tls_phys as *mut u8, 0, 4096);
        core::ptr::write((tls_phys + 0x00) as *mut u64, USER_TLS_VADDR as u64);
    }
    let tls_flags = crate::paging::PTE_PRESENT
        | crate::paging::PTE_WRITABLE
        | crate::paging::PTE_USER
        | crate::paging::PTE_NO_EXECUTE;
    if PageTableManager::map_into(pml4, USER_TLS_VADDR, tls_phys, tls_flags).is_err() {
        return None;
    }

    let task = unsafe { &mut TASKS[task_idx(tid)] };
    task.id = tid;
    task.tgid = tid;
    task.state = TaskState::Ready;
    task.regs = Registers::new_user(entry, user_stack_top);
    task.regs.fs_base = USER_TLS_VADDR;
    serial::write_str("USER_TASK[");
    serial::write_dec(tid);
    serial::write_str("].cs=0x");
    serial::write_hex(task.regs.cs);
    serial::write_str(" ss=0x");
    serial::write_hex(task.regs.ss);
    serial::write_str(" entry=0x");
    serial::write_hex(entry);
    serial::write_str("\n");
    task.kernel_stack = kernel_stack;
    task.user_stack = user_stack_top;
    task.pml4 = pml4;
    task.static_prio = nice_to_prio(nice);
    task.normal_prio = task.static_prio;
    task.prio = task.static_prio;
    task.time_slice = initial_time_slice(task.prio);
    task.parent = Some(current_task_id());

    enqueue_task(tid, task.prio);

    serial::write_str("TASK: created user task ");
    serial::write_dec(tid);
    serial::write_str(" nice=");
    if nice < 0 {
        serial::write_char('-');
        serial::write_dec((-nice) as u64);
    } else {
        serial::write_dec(nice as u64);
    }
    serial::write_str("\n");
    Some(tid)
}

// ── Scheduler core ───────────────────────────────────────────────

pub fn init_scheduler() {
    serial::write_str("SCHED: initialized (priority runqueue)\n");
}

pub fn schedule() {
    unsafe { core::arch::asm!("cli", options(nostack, nomem, preserves_flags)); }

    let current = CURRENT_TASK.load(Ordering::SeqCst);

    // Pick a different task. If the highest-priority task IS current,
    // remove it from the queue and look for another one.
    let next_id = 'pick: {
        let first = dequeue_task();
        match first {
            Some(id) if id != current => break 'pick id,
            Some(_) => {
                let second = dequeue_task();
                match second {
                    Some(other) if other != current => break 'pick other,
                    Some(other) => unsafe { enqueue_task(other, TASKS[task_idx(other)].prio); },
                    None => {}
                }
                unsafe {
                    enqueue_task(current, TASKS[task_idx(current)].prio);
                    TASKS[task_idx(current)].state = TaskState::Running;
                }
                unsafe { core::arch::asm!("sti", options(nostack, nomem, preserves_flags)); }
                return;
            }
            None => {
                unsafe { core::arch::asm!("sti", options(nostack, nomem, preserves_flags)); }
                return;
            }
        }
    };

    // Enqueue current task (if still active) before switching
    if current != 0 {
        let cur_idx = task_idx(current);
        let state = unsafe { TASKS[cur_idx].state };
        if state == TaskState::Ready {
            let prio = unsafe { TASKS[cur_idx].prio };
            unsafe { enqueue_task(current, prio); }
        }
    }

    let new_idx = task_idx(next_id);

    let sc = SWITCH_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if sc % 1000 == 0 {
        crate::serial::write_str("SW#");
        crate::serial::write_dec(sc);
        crate::serial::write_str("\n");
    }

    unsafe { crate::gdt::set_tss_rsp0(TASKS[new_idx].kernel_stack); }

    let old = CURRENT_TASK.swap(next_id, Ordering::SeqCst);

    unsafe {
        TASKS[new_idx].state = TaskState::Running;
        pt_mgr().switch_to(TASKS[new_idx].pml4);

        let old_idx = task_idx(old);
        let old_ptr = &mut TASKS[old_idx].regs as *mut Registers;
        let new_ptr = &TASKS[new_idx].regs as *const Registers;

        // Restore FS base for the new task
        let fs_base = TASKS[new_idx].regs.fs_base;
        core::arch::asm!(
            "mov ecx, 0xC0000100",
            "wrmsr",
            in("eax") (fs_base as u32),
            in("edx") ((fs_base >> 32) as u32),
            out("ecx") _,
            options(nostack, preserves_flags)
        );

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
    let id = CURRENT_TASK.load(Ordering::SeqCst);
    if id == 0 { return; }

    unsafe {
        let idx = task_idx(id);
        if TASKS[idx].state == TaskState::Running {
            TASKS[idx].state = TaskState::Ready;
            TASKS[idx].time_slice = initial_time_slice(TASKS[idx].prio);
        }
    }

    schedule();
}

pub fn exit_task(code: i32) {
    let id = CURRENT_TASK.load(Ordering::SeqCst);
    if id == 0 { return; }

    unsafe {
        let idx = task_idx(id);
        TASKS[idx].state = TaskState::Zombie;
        TASKS[idx].exit_code = code;

        // Parent (or any task waiting on this PID) will free stacks via waitpid
        // Wake parent if it's blocked waiting for this child
        if let Some(parent_id) = TASKS[idx].parent {
            let pidx = task_idx(parent_id);
            if TASKS[pidx].state == TaskState::Blocked
                && (TASKS[pidx].blocked_on == id || TASKS[pidx].blocked_on == u64::MAX)
            {
                TASKS[pidx].state = TaskState::Ready;
                TASKS[pidx].blocked_on = 0;
                enqueue_task(parent_id, TASKS[pidx].prio);
            }
        }
    }

    schedule();
}

// ── Context switch assembly ──────────────────────────────────────

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
        "mov [rdi + 0x40], r8",
        "mov [rdi + 0x48], r9",
        "mov [rdi + 0x50], r10",
        "mov [rdi + 0x58], r11",
        "mov [rdi + 0x60], r12",
        "mov [rdi + 0x68], r13",
        "mov [rdi + 0x70], r14",
        "mov [rdi + 0x78], r15",
        "mov [rdi + 0x38], rsp",
        "pushfq",
        "pop rax",
        "or rax, 0x200",
        "and rax, 0xFFFFFFFFFFFFFEFF",
        "mov [rdi + 0x88], rax",
        "mov [rdi + 0x90], cs",
        "mov [rdi + 0x98], ss",
        // Check if target is user or kernel mode by examining CS.RPL
        "mov rbx, [rsi + 0x90]",
        "test bl, 3",
        "jnz 1f",
        // Kernel→kernel: load new RSP, push RIP, sti, and ret.
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
        "mov rsi, [rsi + 0x20]",
        "sti",
        "ret",
        // Kernel→user: build iretq frame on kernel stack
        "1: push qword ptr [rsi + 0x98]",     // SS
        "push qword ptr [rsi + 0x38]",        // RSP (user stack)
        "push qword ptr [rsi + 0x88]",        // RFLAGS
        "push qword ptr [rsi + 0x90]",        // CS (0x23)
        "push qword ptr [rsi + 0x80]",        // RIP
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
        "mov rsi, [rsi + 0x20]",
        "iretq",
    )
}

// ── Timer interrupt handling ─────────────────────────────────────

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn timer_interrupt_handler() -> ! {
    core::arch::naked_asm!(
        "cld",
        "push rbp",
        "mov rbp, rsp",
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
        "sub rsp, 256",
        "mov rdi, rbp",
        "add rdi, 8",
        "call {save_context}",
        "call {inc_ticks}",
        "call {timer_schedule}",
        // RAX = frame address from timer_schedule.
        // If zero (kernel task), restore GP regs from the stack and return
        // using the CPU-pushed interrupt frame directly.
        "test rax, rax",
        "jnz 2f",
        // Kernel task: no frame manipulation, just restore and return
        "add rsp, 256",
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
        "pop rdx",
        "pop rcx",
        "pop rbx",
        "pop rax",
        "pop rbp",
        // RSP now points at CPU-pushed frame: RIP, CS, RFLAGS
        // Kernel→kernel return: iretq restores RIP, CS, RFLAGS from the
        // CPU-saved frame without clobbering any GP registers.
        "iretq",
        // User task or preemption: use build_frame result
        "2: mov rsp, rax",
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
        "pop rdx",
        "pop rcx",
        "pop rbx",
        "pop rax",
        "pop rbp",
        "test byte ptr [rsp + 8], 3",
        "jnz 3f",
        "mov rdx, [rsp + 24]",
        "mov rax, [rsp + 0]",
        "mov rsp, rdx",
        "push rax",
        "ret",
        "3: iretq",

        save_context = sym save_interrupt_context,
        inc_ticks = sym inc_ticks,
        timer_schedule = sym timer_schedule,
    )
}

#[no_mangle]
pub extern "C" fn save_interrupt_context(frame: *mut u64) {
    unsafe {
        let current = CURRENT_TASK.load(Ordering::SeqCst);
        if current == 0 {
            return;
        }
        let idx = task_idx(current);
        let regs = &mut TASKS[idx].regs;

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

        // Save FS base MSR
        let fs_base_low: u32;
        let fs_base_high: u32;
        core::arch::asm!(
            "mov ecx, 0xC0000100",
            "rdmsr",
            out("eax") fs_base_low,
            out("edx") fs_base_high,
            out("ecx") _,
            options(nostack, preserves_flags)
        );
        regs.fs_base = (fs_base_high as u64) << 32 | fs_base_low as u64;

        // Detect user→kernel vs kernel→kernel by checking CS.RPL at frame+1:
        //   frame[0] = RIP   (lowest address, always present)
        //   frame[1] = CS    (CS.RPL = 3 for user, 0 for kernel)
        //   frame[2] = RFLAGS
        //   frame[3] = RSP_user   (only for CPL change or IST)
        //   frame[4] = SS         (only for CPL change or IST)
        if (*frame.add(1) & 3) == 3 {
            // User → kernel: CPU pushed SS, RSP, RFLAGS, CS, RIP
            regs.rip    = *frame.add(0);
            regs.cs     = *frame.add(1);
            regs.rflags = *frame.add(2);
            regs.rsp    = *frame.add(3);
            regs.ss     = *frame.add(4);
        } else {
            // Kernel → kernel: CPU pushed RFLAGS, CS, RIP.
            // RSP at interrupt time = frame + 24 (3 items * 8 bytes).
            // Always use the real interrupted RSP — the build_frame + iretq
            // restore path will return here correctly regardless of whether
            // this is a kernel task or a user task in a syscall.
            regs.rip    = *frame.add(0);
            regs.cs     = *frame.add(1);
            regs.rflags = *frame.add(2);
            regs.rsp    = frame as u64 + 24;
            regs.ss     = KERNEL_DATA_SELECTOR;
        }
    }
}

#[no_mangle]
pub extern "C" fn inc_ticks() {
    crate::pit::TICKS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

#[no_mangle]
static SCHED_CALLS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

pub extern "C" fn timer_schedule() -> u64 {
    crate::pic::send_eoi(0);
    // Poll UART for serial input and feed into keyboard buffer
    while let Some(c) = crate::serial::read_byte_nonblocking() {
        crate::keyboard::push_char(c);
    }

    // Wake up sleeping tasks whose wakeup tick has arrived
    let now = crate::pit::TICKS.load(core::sync::atomic::Ordering::Relaxed);
    unsafe {
        for i in 0..MAX_TASKS {
            if TASKS[i].state == TaskState::Blocked
                && TASKS[i].wakeup_tick > 0
                && TASKS[i].wakeup_tick <= now
                && TASKS[i].id != 0
            {
                TASKS[i].state = TaskState::Ready;
                TASKS[i].wakeup_tick = 0;
                enqueue_task(TASKS[i].id, TASKS[i].prio);
            }
        }
    }

    let current = CURRENT_TASK.load(Ordering::SeqCst);
    if current == 0 {
        return 0;
    }

    unsafe {
        let idx = task_idx(current);

        // Kernel tasks: return 0 to signal handler to use CPU-pushed frame directly
        if TASKS[idx].user_stack == 0 {
            return 0;
        }

        // User task interrupted in kernel mode (during a syscall): build a
        // self-frame on the per-task kernel_stack. After iretq, RSP is restored
        // to regs.rsp (the syscall_stack address saved by save_interrupt_context),
        // so the interrupted call chain is preserved.
        if TASKS[idx].user_stack != 0 && (TASKS[idx].regs.cs & 3) == 0 {
            return build_kernel_preempt_frame(TASKS[idx].kernel_stack, &raw const TASKS[idx]);
        }

        // Decrement time slice
        if TASKS[idx].time_slice > 0 {
            TASKS[idx].time_slice -= 1;
        }

        // If task not running, don't reschedule — just build frame from saved regs
        if TASKS[idx].state != TaskState::Running {
            return build_kernel_preempt_frame(TASKS[idx].kernel_stack, &raw const TASKS[idx]);
        }

        // Time slice still positive → keep running current task
        if TASKS[idx].time_slice > 0 {
            return build_kernel_preempt_frame(TASKS[idx].kernel_stack, &raw const TASKS[idx]);
        }

        // Time slice expired — give a fresh time slice
        TASKS[idx].time_slice = initial_time_slice(TASKS[idx].prio);

        // Try to find a different task; if only current task is waiting, just keep running
        let next_id = match dequeue_task() {
            Some(id) => id,
            None => {
                TASKS[idx].state = TaskState::Running;
                return build_kernel_preempt_frame(TASKS[idx].kernel_stack, &raw const TASKS[idx]);
            }
        };

        if next_id == current {
            TASKS[idx].state = TaskState::Running;
            return build_kernel_preempt_frame(TASKS[idx].kernel_stack, &raw const TASKS[idx]);
        }

        // Switch to a different task — requeue current first
        TASKS[idx].state = TaskState::Ready;
        enqueue_task(current, TASKS[idx].prio);

        let new_idx = task_idx(next_id);
        TASKS[new_idx].state = TaskState::Running;
        CURRENT_TASK.store(next_id, Ordering::SeqCst);
        pt_mgr().switch_to(TASKS[new_idx].pml4);
        crate::gdt::set_tss_rsp0(TASKS[new_idx].kernel_stack);
        build_kernel_preempt_frame(TASKS[new_idx].kernel_stack, &raw const TASKS[new_idx])
    }
}

/// Build frame into the static scratch buffer (for kernel tasks, avoiding
/// corrupting their own kernel stack call chain).
fn build_frame_scratch(task_ptr: *const Task) -> u64 {
    let regs = unsafe { &(*task_ptr).regs };
    unsafe {
        // Restore FS base for this task
        core::arch::asm!(
            "mov ecx, 0xC0000100",
            "wrmsr",
            in("eax") (regs.fs_base as u32),
            in("edx") ((regs.fs_base >> 32) as u32),
            out("ecx") _,
            options(nostack, preserves_flags)
        );
        let base = &raw mut TIMER_FRAME_SCRATCH as *mut u64;
        write_frame(base, regs);
        base as u64
    }
}

/// Build a frame for kernel→kernel preemption.
/// Stores the real RAX/RDX/RIP in PREEMPT_SCRATCH and redirects
/// the frame's RIP through a trampoline that restores them after
/// the push+ret clobbers RAX and RDX.
fn build_kernel_preempt_frame(kernel_stack: u64, task_ptr: *const Task) -> u64 {
    let regs = unsafe { &(*task_ptr).regs };
    unsafe {
        // Restore FS base for this task
        core::arch::asm!(
            "mov ecx, 0xC0000100",
            "wrmsr",
            in("eax") (regs.fs_base as u32),
            in("edx") ((regs.fs_base >> 32) as u32),
            out("ecx") _,
            options(nostack, preserves_flags)
        );
        let base = (kernel_stack as *mut u64).sub(20);
        write_frame(base, regs);
        if (regs.cs & 3) == 0 {
            PREEMPT_SCRATCH[0] = regs.rax;
            PREEMPT_SCRATCH[1] = regs.rdx;
            PREEMPT_SCRATCH[2] = regs.rip;
            *base.add(15) = preempt_trampoline as u64;
        }
        base as u64
    }
}

/// Trampoline for kernel→kernel preemption.
/// Called when a kernel task is resumed from timer preemption.
/// The handler's push+ret clobbers RAX and RDX; this trampoline
/// restores them from PREEMPT_SCRATCH and jumps to the real RIP.
#[unsafe(naked)]
pub unsafe extern "C" fn preempt_trampoline() -> ! {
    core::arch::naked_asm!(
        "mov rax, [{scratch} + 0]",
        "mov rdx, [{scratch} + 8]",
        "jmp [{scratch} + 16]",
        scratch = sym PREEMPT_SCRATCH,
    )
}

fn write_frame(base: *mut u64, regs: &Registers) {
    unsafe {
        *base.add(0)  = regs.r15;
        *base.add(1)  = regs.r14;
        *base.add(2)  = regs.r13;
        *base.add(3)  = regs.r12;
        *base.add(4)  = regs.r11;
        *base.add(5)  = regs.r10;
        *base.add(6)  = regs.r9;
        *base.add(7)  = regs.r8;
        *base.add(8)  = regs.rdi;
        *base.add(9)  = regs.rsi;
        *base.add(10) = regs.rdx;
        *base.add(11) = regs.rcx;
        *base.add(12) = regs.rbx;
        *base.add(13) = regs.rax;
        *base.add(14) = regs.rbp;
        *base.add(15) = regs.rip;
        *base.add(16) = regs.cs;
        *base.add(17) = regs.rflags;
        *base.add(18) = regs.rsp;
        *base.add(19) = regs.ss;
    }
}



// ── Syscalls (Linux x86_64 compatible) ───────────────────────────

// Linux x86_64 syscall numbers
pub const SYS_read: u64 = 0;
pub const SYS_write: u64 = 1;
pub const SYS_open: u64 = 2;
pub const SYS_close: u64 = 3;
pub const SYS_stat: u64 = 4;
pub const SYS_fstat: u64 = 5;
pub const SYS_lstat: u64 = 6;
pub const SYS_mmap: u64 = 9;
pub const SYS_mprotect: u64 = 10;
pub const SYS_munmap: u64 = 11;
pub const SYS_brk: u64 = 12;
pub const SYS_rt_sigaction: u64 = 13;
pub const SYS_rt_sigprocmask: u64 = 14;
pub const SYS_rt_sigreturn: u64 = 15;
pub const SYS_ioctl: u64 = 16;
pub const SYS_access: u64 = 21;
pub const SYS_pipe: u64 = 22;
pub const SYS_sched_yield: u64 = 24;
pub const SYS_dup: u64 = 32;
pub const SYS_dup2: u64 = 33;
pub const SYS_nanosleep: u64 = 35;
pub const SYS_getpid: u64 = 39;
pub const SYS_clone: u64 = 56;
pub const SYS_fork: u64 = 57;
pub const SYS_vfork: u64 = 58;
pub const SYS_execve: u64 = 59;
pub const SYS_exit: u64 = 60;
pub const SYS_wait4: u64 = 61;
pub const SYS_kill: u64 = 62;
pub const SYS_uname: u64 = 63;
pub const SYS_fcntl: u64 = 72;
pub const SYS_getcwd: u64 = 79;
pub const SYS_chdir: u64 = 80;
pub const SYS_fchdir: u64 = 81;
pub const SYS_rename: u64 = 82;
pub const SYS_mkdir: u64 = 83;
pub const SYS_rmdir: u64 = 84;
pub const SYS_unlink: u64 = 87;
pub const SYS_readlink: u64 = 89;
pub const SYS_gettimeofday: u64 = 96;
pub const SYS_getuid: u64 = 102;
pub const SYS_getgid: u64 = 104;
pub const SYS_geteuid: u64 = 107;
pub const SYS_getegid: u64 = 108;
pub const SYS_arch_prctl: u64 = 158;
pub const SYS_reboot: u64 = 169;
pub const SYS_openat: u64 = 257;
pub const SYS_getdents64: u64 = 217;
pub const SYS_poll: u64 = 7;
pub const SYS_lseek: u64 = 8;
pub const SYS_readv: u64 = 19;
pub const SYS_writev: u64 = 20;
pub const SYS_gettid: u64 = 186;
pub const SYS_tkill: u64 = 200;
pub const SYS_sched_getaffinity: u64 = 204;
pub const SYS_set_tid_address: u64 = 218;
pub const SYS_clock_gettime: u64 = 228;
pub const SYS_clock_nanosleep: u64 = 230;
pub const SYS_exit_group: u64 = 231;
pub const SYS_set_robust_list: u64 = 274;
pub const SYS_getppid: u64 = 110;
pub const SYS_getpgid: u64 = 121;
pub const SYS_sigaltstack: u64 = 131;
pub const SYS_setpgid: u64 = 109;
pub const SYS_getpgrp: u64 = 111;
pub const SYS_setsid: u64 = 112;
pub const SYS_getrandom: u64 = 318;

// Niobix-specific (high numbers, no Linux conflict)
pub const SYS_niobix_get_ticks: u64 = 2000;
pub const SYS_niobix_futex: u64 = 2001;
pub const SYS_niobix_shm_setup: u64 = 2002;
pub const SYS_niobix_shm_notify: u64 = 2003;
pub const SYS_niobix_shm_wait: u64 = 2004;
pub const SYS_niobix_shm_teardown: u64 = 2005;
pub const SYS_niobix_spawn: u64 = 2006;
pub const SYS_niobix_getppid: u64 = 2007;
pub const SYS_niobix_sleep: u64 = 2008;
pub const SYS_niobix_yield: u64 = 2009;

pub const ARCH_SET_FS: u64 = 0x1002;
pub const ARCH_GET_FS: u64 = 0x1003;

pub const INTERP_BASE: u64 = 0x100_0000_0000;

pub const WNOHANG: u32 = 1;

#[no_mangle]
pub extern "C" fn syscall_handler(
    syscall_num: u64,
    arg1: u64, arg2: u64, arg3: u64,
    arg4: u64, arg5: u64, arg6: u64
) -> i64 {
    static SC_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    let scn = SC_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    if scn < 30 {
        let id = CURRENT_TASK.load(Ordering::SeqCst);
        if id != 0 {
            let cr3 = unsafe { TASKS[task_idx(id)].pml4 };
            let mpage = crate::paging::PageTableManager::resolve_phys(cr3, 0x500000).unwrap_or(0);
            crate::serial::write_str("SC#");
            crate::serial::write_dec(scn as u64);
            crate::serial::write_str(" num=");
            crate::serial::write_dec(syscall_num);
            crate::serial::write_str(" m[0]=0x");
            if mpage != 0 {
                let mem: u64 = unsafe { core::ptr::read_volatile((mpage + 0x28) as *const u64) };
                crate::serial::write_hex(mem);
                crate::serial::write_str(" m[2]=0x");
                let mem2: u64 = unsafe { core::ptr::read_volatile((mpage + 0x28 + 0x50) as *const u64) };
                crate::serial::write_hex(mem2);
                crate::serial::write_str(" m[8]=0x");
                let mem8: u64 = unsafe { core::ptr::read_volatile((mpage + 0x28 + 0x140) as *const u64) };
                crate::serial::write_hex(mem8);
            }
            crate::serial::write_str("\n");
        }
    }
    match syscall_num {
        SYS_read => sys_read(arg1 as u32, arg2 as *mut u8, arg3 as usize),
        SYS_write => sys_write(arg1 as u32, arg2 as *const u8, arg3 as usize),
        SYS_open => sys_open(arg1 as *const u8, arg2 as i32),
        SYS_close => sys_close(arg1 as u32),
        SYS_stat => sys_stat(arg1 as *const u8, arg2 as *mut u8),
        SYS_fstat => sys_fstat(arg1 as u32, arg2 as *mut u8),
        SYS_lstat => sys_stat(arg1 as *const u8, arg2 as *mut u8), // lstat = stat in flat fs
        SYS_mmap => sys_mmap(arg1 as *mut u8, arg2 as usize, arg3 as i32, arg4 as i32, arg5 as i32, arg6 as u64),
        SYS_mprotect => sys_mprotect(arg1 as u64, arg2 as usize, arg3 as i32),
        SYS_munmap => sys_munmap(arg1 as u64, arg2 as usize),
        SYS_brk => sys_brk(arg1 as u64),
        SYS_ioctl => sys_ioctl(arg1 as u32, arg2 as u64, arg3 as u64),
        SYS_access => sys_access(arg1 as *const u8, arg2 as i32),
        SYS_pipe => sys_pipe(arg1 as *mut u32),
        SYS_dup2 => sys_dup2(arg1 as u32, arg2 as u32),
        SYS_nanosleep => sys_nanosleep(arg1 as *const u64, arg2 as *mut u64),
        SYS_arch_prctl => sys_arch_prctl(arg1 as u64, arg2 as u64),
        SYS_getpid => sys_getpid(),
        SYS_fork => sys_fork(),
        SYS_execve => sys_execve(arg1 as *const u8, arg2 as u64, arg3 as u64),
        SYS_exit => sys_exit(arg1 as i32),
        SYS_wait4 => sys_wait4(arg1 as i64, arg2 as *mut i32, arg3 as i32, arg4 as u64),
        SYS_kill => sys_kill(arg1 as i64, arg2 as i32),
        SYS_uname => sys_uname(arg1 as *mut u8),
        SYS_fcntl => sys_fcntl(arg1 as u32, arg2 as i32, arg3 as u64),
        SYS_getcwd => sys_getcwd(arg1 as *mut u8, arg2 as usize),
        SYS_chdir => sys_chdir(arg1 as *const u8),
        SYS_gettimeofday => sys_gettimeofday(arg1 as *mut u64, arg2 as *mut u64),
        SYS_getuid => 0,
        SYS_getgid => 0,
        SYS_geteuid => 0,
        SYS_getegid => 0,
        SYS_getdents64 => sys_getdents64(arg1 as u32, arg2 as *mut u8, arg3 as usize),
        SYS_mkdir => sys_mkdir(arg1 as *const u8, arg2 as u32),
        SYS_rmdir => sys_rmdir(arg1 as *const u8),
        SYS_unlink => sys_unlink(arg1 as *const u8),
        SYS_rename => sys_rename(arg1 as *const u8, arg2 as *const u8),
        SYS_openat => sys_openat(arg1 as i32, arg2 as *const u8, arg3 as i32, arg4 as u32),
        SYS_readlink => sys_readlink(arg1 as *const u8, arg2 as *mut u8, arg3 as usize),
        SYS_clone => sys_fork(), // clone → fork for now
        SYS_vfork => sys_fork(), // vfork → fork
        SYS_dup => sys_dup2(arg1 as u32, arg1 as u32), // dup → dup2(fd, fd)
        SYS_fchdir => sys_chdir_from_fd(arg1 as u32),
        SYS_poll => sys_poll(arg1 as u64, arg2 as u64, arg3 as i32),
        SYS_lseek => sys_lseek(arg1 as u32, arg2 as i64, arg3 as i32),
        SYS_readv => sys_readv(arg1 as u32, arg2 as u64, arg3 as i32),
        SYS_writev => sys_writev(arg1 as u32, arg2 as u64, arg3 as i32),
        SYS_gettid => CURRENT_TASK.load(Ordering::SeqCst) as i64,
        SYS_tkill => sys_tkill(arg1 as i64, arg2 as i32),
        SYS_sched_getaffinity => 0,
        SYS_set_tid_address => CURRENT_TASK.load(Ordering::SeqCst) as i64,
        SYS_clock_gettime => sys_clock_gettime(arg1 as u64, arg2 as *mut u8),
        SYS_clock_nanosleep => sys_clock_gettime(0, core::ptr::null_mut()), // stub
        SYS_exit_group => sys_exit(arg1 as i32),
        SYS_set_robust_list => 0,
        SYS_getrandom => sys_getrandom(arg1 as *mut u8, arg2 as usize, arg3 as u32),
        SYS_rt_sigaction => 0,
        SYS_rt_sigprocmask => 0,
        SYS_rt_sigreturn => 0,
        SYS_sigaltstack => 0,
        SYS_setpgid => sys_setpgid(arg1 as i32, arg2 as i32),
        SYS_getppid => sys_getppid(),
        SYS_getpgid => sys_getpgid(arg1 as i32),
        SYS_getpgrp => sys_getpgrp(),
        SYS_setsid => sys_setsid(),
        SYS_sched_yield => sys_niobix_yield(),
        // Niobix-specific
        SYS_niobix_get_ticks => sys_get_ticks(),
        SYS_niobix_futex => sys_futex(arg1 as *const u32, arg2 as i32, arg3 as u32,
                                        arg4 as *const u32, arg5 as u32),
        SYS_niobix_shm_setup => crate::ipc::shm_setup(arg1, arg2),
        SYS_niobix_shm_notify => crate::ipc::shm_notify(arg1),
        SYS_niobix_shm_wait => crate::ipc::shm_wait(arg1),
        SYS_niobix_shm_teardown => crate::ipc::shm_teardown(arg1),
        SYS_niobix_spawn => sys_spawn(arg1 as *const u8, arg2 as usize),
        SYS_niobix_getppid => sys_getppid(),
        SYS_niobix_sleep => sys_sleep(arg1 as u64),
        SYS_niobix_yield => sys_niobix_yield(),
        SYS_reboot => sys_reboot(arg1 as u32, arg2 as u32, arg3 as u32),
        _ => {
            // Print first unknown syscall
            static ONCE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
            if !ONCE.swap(true, core::sync::atomic::Ordering::Relaxed) {
                serial::write_str("SYS: unknown ");
                serial::write_dec(syscall_num);
                serial::write_str(" arg1=0x");
                serial::write_hex(arg1);
                serial::write_str("\n");
            }
            -ENOSYS
        },
    }
}

fn sys_reboot(magic1: u32, magic2: u32, cmd: u32) -> i64 {
    const LINUX_REBOOT_MAGIC1: u32 = 0xFEE1DEAD;
    const LINUX_REBOOT_MAGIC2: u32 = 0x28121969;
    const LINUX_REBOOT_CMD_RESTART: u32 = 0x01234567;
    const LINUX_REBOOT_CMD_POWER_OFF: u32 = 0x4321FEDC;
    const LINUX_REBOOT_CMD_HALT: u32 = 0xCDEF0123;
    if magic1 != LINUX_REBOOT_MAGIC1 || (magic2 != LINUX_REBOOT_MAGIC2 && magic2 != 0x0A1B2C3D) {
        return -EINVAL;
    }
    match cmd {
        LINUX_REBOOT_CMD_HALT | LINUX_REBOOT_CMD_POWER_OFF => {
            loop { unsafe { core::arch::asm!("cli; hlt"); } }
        }
        LINUX_REBOOT_CMD_RESTART => {
            // Triple fault to reboot
            unsafe { core::arch::asm!("int3"); }
            loop {}
        }
        _ => 0, // CAD on/off etc — just return success
    }
}

fn sys_exit(status: i32) -> i64 {
    serial::write_str("SYS_EXIT: ");
    serial::write_dec(status as u64);
    serial::write_str("\n");
    exit_task(status);
    // If no other task to schedule, halt
    let id = CURRENT_TASK.load(Ordering::SeqCst);
    if id == 0 || unsafe { TASKS[task_idx(id)].state } == TaskState::Zombie {
        serial::write_str("SYS_EXIT: no more tasks, halting\n");
        unsafe { core::arch::asm!("cli; hlt", options(noreturn)); }
    }
    0
}

fn sys_write(fd: u32, buf: *const u8, count: usize) -> i64 {
    if fd == 1 || fd == 2 {
        if buf.is_null() || count == 0 { return 0; }
        let slice = unsafe { core::slice::from_raw_parts(buf, count) };
        for &c in slice {
            if c == 0 { break; }
            serial::write_char(c as char);
        }
        count as i64
    } else {
        let inode_fd = match crate::vfs::fd_to_inode(fd as usize) {
            Some(f) => f,
            None => return -EBADF,
        };
        // Pipe write end?
        if inode_fd.inode_idx == crate::vfs::MAX_INODES - 2 {
            let slice = unsafe { core::slice::from_raw_parts(buf, count) };
            unsafe {
                for &c in slice {
                    if c == 0 { break; }
                    if PIPE_WPOS < 4096 {
                        PIPE_BUF[PIPE_WPOS] = c;
                        PIPE_WPOS += 1;
                    }
                }
            }
            slice.len() as i64
        } else {
            let slice = unsafe { core::slice::from_raw_parts(buf, count) };
            match crate::vfs::inode_write(inode_fd.inode_idx, inode_fd.pos, slice) {
                Some(n) => {
                    inode_fd.pos += n;
                    n as i64
                }
                None => -EIO,
            }
        }
    }
}

fn sys_get_ticks() -> i64 {
    unsafe { crate::pit::TICKS.load(core::sync::atomic::Ordering::Relaxed) as i64 }
}

fn sys_niobix_yield() -> i64 {
    yield_now();
    0
}

fn sys_spawn(elf_addr: *const u8, elf_size: usize) -> i64 {
    if elf_addr.is_null() || elf_size < 64 {
        return -EINVAL;
    }

    let data = unsafe { core::slice::from_raw_parts(elf_addr, elf_size) };

    match crate::elf::load_elf(data) {
        Ok(info) => {
            match create_user_task(info.entry, info.pml4, info.stack_top) {
                Some(tid) => {
                    serial::write_str("SYS_SPAWN: task ");
                    serial::write_dec(tid);
                    serial::write_str(" entry=0x");
                    serial::write_hex(info.entry);
                    serial::write_str(" stack=0x");
                    serial::write_hex(info.stack_top);
                    serial::write_str("\n");
                    tid as i64
                }
                None => -ENOMEM,
            }
        }
        Err(e) => {
            serial::write_str("SYS_SPAWN: ELF load failed: ");
            // Write error string
            let mut i = 0;
            while i < 40 {
                let c = e.as_bytes().get(i).copied().unwrap_or(0);
                if c == 0 { break; }
                serial::write_char(c as char);
                i += 1;
            }
            serial::write_str("\n");
            -ENOEXEC
        }
    }
}

// ── Futex ────────────────────────────────────────────────────────

const FUTEX_WAIT: i32 = 0;
const FUTEX_WAKE: i32 = 1;
const FUTEX_LOCK_PI: i32 = 6;
const FUTEX_UNLOCK_PI: i32 = 7;

const FUTEX_WAITERS: u32 = 0x8000_0000;

fn sys_futex(uaddr: *const u32, op: i32, val: u32,
             _uaddr2: *const u32, _val3: u32) -> i64 {
    match op {
        FUTEX_WAIT => futex_wait(uaddr, val),
        FUTEX_WAKE => futex_wake(uaddr, val),
        FUTEX_LOCK_PI => futex_lock_pi(uaddr),
        FUTEX_UNLOCK_PI => futex_unlock_pi(uaddr),
        _ => -ENOSYS,
    }
}

fn futex_wait(uaddr: *const u32, val: u32) -> i64 {
    let actual = unsafe { core::ptr::read_volatile(uaddr) };
    if actual != val {
        return -EAGAIN;
    }

    let id = CURRENT_TASK.load(Ordering::SeqCst);
    if id == 0 { return -EINVAL; }

    unsafe {
        let idx = task_idx(id);
        TASKS[idx].blocked_on = uaddr as u64;
        TASKS[idx].state = TaskState::Blocked;
    }

    schedule();
    0
}

pub fn futex_wake(uaddr: *const u32, max_wake: u32) -> i64 {
    let mut woken = 0i64;
    unsafe {
        for i in 0..MAX_TASKS {
            if woken >= max_wake as i64 { break; }
            if TASKS[i].state == TaskState::Blocked
                && TASKS[i].blocked_on == uaddr as u64
                && TASKS[i].id != 0
            {
                TASKS[i].state = TaskState::Ready;
                TASKS[i].blocked_on = 0;
                enqueue_task(TASKS[i].id, TASKS[i].prio);
                woken += 1;
            }
        }
    }
    woken
}

fn futex_lock_pi(uaddr: *const u32) -> i64 {
    let id = CURRENT_TASK.load(Ordering::SeqCst);
    if id == 0 { return -EINVAL; }

    unsafe {
        // Try cmpxchg: if *uaddr == 0, set to our pid (tid)
        let tid = id as u32;
        let mut prev: u32;
        core::arch::asm!(
            "mov eax, 0",
            "lock cmpxchg [{addr}], {new:e}",
            "mov {prev:e}, eax",
            addr = in(reg) uaddr,
            new = in(reg) tid,
            prev = out(reg) prev,
            options(nostack, preserves_flags),
        );

        if prev == 0 {
            return 0;
        }

        // Lock held — set FUTEX_WAITERS flag if not already
        let owner_tid = (prev & !FUTEX_WAITERS) as u64;
        let owner_idx = task_idx(owner_tid);
        let our_idx = task_idx(id);

        // Try to set FUTEX_WAITERS flag
        let mut cur = prev;
        if cur & FUTEX_WAITERS == 0 {
            let new = cur | FUTEX_WAITERS;
            let mut tmp: u32;
            core::arch::asm!(
                "mov eax, {cur:e}",
                "lock cmpxchg [{addr}], {new:e}",
                "mov {tmp:e}, eax",
                addr = in(reg) uaddr,
                new = in(reg) new,
                cur = in(reg) cur,
                tmp = out(reg) tmp,
                options(nostack, preserves_flags),
            );
            cur = prev; // Use original prev for owner_tid
        }

        // Priority inheritance: boost owner if it has lower priority
        if TASKS[owner_idx].state != TaskState::Empty
            && TASKS[owner_idx].prio > TASKS[our_idx].prio
        {
            let boosted_prio = TASKS[our_idx].prio;
            remove_from_runqueue(owner_tid);
            TASKS[owner_idx].prio = boosted_prio;
            TASKS[owner_idx].pi_boosted = true;
            if TASKS[owner_idx].state == TaskState::Ready {
                enqueue_task(owner_tid, boosted_prio);
            }
        }

        // Block current task on the futex
        TASKS[our_idx].blocked_on = uaddr as u64;
        TASKS[our_idx].state = TaskState::Blocked;
    }

    schedule();
    0
}

fn futex_unlock_pi(uaddr: *const u32) -> i64 {
    let id = CURRENT_TASK.load(Ordering::SeqCst);
    if id == 0 { return -EINVAL; }

    unsafe {
        let idx = task_idx(id);

        // Restore original priority if we were PI boosted
        if TASKS[idx].pi_boosted {
            TASKS[idx].pi_boosted = false;
            let old_prio = TASKS[idx].prio;
            TASKS[idx].prio = TASKS[idx].static_prio;
            if TASKS[idx].state == TaskState::Ready && old_prio != TASKS[idx].prio {
                remove_from_runqueue(id);
                enqueue_task(id, TASKS[idx].prio);
            }
        }

        // Scan for the highest-priority waiter on this futex
        let mut best_waiter: Option<u64> = None;
        let mut best_prio: u8 = PRIORITY_LOWEST;
        for i in 0..MAX_TASKS {
            if TASKS[i].state == TaskState::Blocked
                && TASKS[i].blocked_on == uaddr as u64
                && TASKS[i].id != 0
            {
                if best_waiter.is_none() || TASKS[i].prio < best_prio {
                    best_waiter = Some(TASKS[i].id);
                    best_prio = TASKS[i].prio;
                }
            }
        }

        if let Some(waiter_id) = best_waiter {
            // Transfer ownership to the waiter
            let new_val = waiter_id as u32 | FUTEX_WAITERS;
            core::ptr::write_volatile(uaddr as *mut u32, new_val);

            // Wake the waiter
            let w_idx = task_idx(waiter_id);
            TASKS[w_idx].state = TaskState::Ready;
            TASKS[w_idx].blocked_on = 0;
            enqueue_task(waiter_id, TASKS[w_idx].prio);
        } else {
            // No waiters — unlock
            core::ptr::write_volatile(uaddr as *mut u32, 0u32);
        }
    }

    0
}

// ── Error constants ──────────────────────────────────────────────

pub const EPERM: i64 = -1;
pub const ENOENT: i64 = -2;
pub const ESRCH: i64 = -3;
pub const EINTR: i64 = -4;
pub const EIO: i64 = -5;
pub const ENXIO: i64 = -6;
pub const E2BIG: i64 = -7;
pub const ENOEXEC: i64 = -8;
pub const EBADF: i64 = -9;
pub const ECHILD: i64 = -10;
pub const EAGAIN: i64 = -11;
pub const ENOMEM: i64 = -12;
pub const EACCES: i64 = -13;
pub const EFAULT: i64 = -14;
pub const ENOTBLK: i64 = -15;
pub const EBUSY: i64 = -16;
pub const EEXIST: i64 = -17;
pub const EXDEV: i64 = -18;
pub const ENODEV: i64 = -19;
pub const ENOTDIR: i64 = -20;
pub const EISDIR: i64 = -21;
pub const EINVAL: i64 = -22;
pub const ENFILE: i64 = -23;
pub const EMFILE: i64 = -24;
pub const ENOTTY: i64 = -25;
pub const ETXTBSY: i64 = -26;
pub const EFBIG: i64 = -27;
pub const ENOSPC: i64 = -28;
pub const ESPIPE: i64 = -29;
pub const EROFS: i64 = -30;
pub const EMLINK: i64 = -31;
pub const EPIPE: i64 = -32;
pub const EDOM: i64 = -33;
pub const ERANGE: i64 = -34;
pub const ENAMETOOLONG: i64 = -36;
pub const ENOSYS: i64 = -38;
pub const ENOTEMPTY: i64 = -39;

// ── Helpers ──────────────────────────────────────────────────────

fn sys_waitpid(pid: i64, status_ptr: *mut i32, flags: u32) -> i64 {
    let current = current_task_id();
    if current == 0 { return -ECHILD; }

    unsafe {
        loop {
            let mut found_child = false;
            for i in 0..MAX_TASKS {
                let child = &TASKS[i];
                if child.id == 0 { continue; }
                if child.parent != Some(current) { continue; }

                // Filter by pid
                if pid > 0 && child.id as i64 != pid { continue; }
                if pid == 0 { continue; }
                found_child = true;

                if child.state == TaskState::Zombie {
                    let exit_code = child.exit_code;
                    let child_id = child.id;
                    let child_ks = child.kernel_stack;
                    let child_us = child.user_stack;

                    if !status_ptr.is_null() {
                        core::ptr::write_volatile(status_ptr, (exit_code & 0xFF) << 8);
                    }
                    free_stack(child_ks, KERNEL_STACK_PAGES);
                    if child_us != 0 {
                        free_stack(child_us, USER_STACK_PAGES);
                    }
                    TASKS[i] = Task::empty();
                    return child_id as i64;
                }
            }

            if !found_child {
                return -ECHILD;
            }

            if flags & WNOHANG != 0 {
                return 0;
            }

            // No zombie yet — yield and retry
            yield_now();
        }
    }
}

fn sys_read(fd: u32, buf: *mut u8, count: usize) -> i64 {
    if fd == 0 {
        if buf.is_null() || count == 0 { return 0; }
        let mut written = 0usize;
        // Non-blocking read from serial
        while written < count {
            match crate::serial::read_byte_nonblocking() {
                Some(c) => {
                    unsafe { *buf.add(written) = c; }
                    written += 1;
                    if c == b'\n' || c == b'\r' { break; }
                }
                None => {
                    if written > 0 { return written as i64; }
                    return 0; // No data available
                }
            }
        }
        return written as i64;
    } else {
        let inode_fd = match crate::vfs::fd_to_inode(fd as usize) {
            Some(f) => f,
            None => return -EBADF,
        };
        // Pipe read end?
        if inode_fd.inode_idx == crate::vfs::MAX_INODES - 1 {
            unsafe {
                let mut written = 0usize;
                loop {
                    if PIPE_RPOS < PIPE_WPOS {
                        let avail = PIPE_WPOS - PIPE_RPOS;
                        let to_read = core::cmp::min(count - written, avail);
                        core::ptr::copy_nonoverlapping(PIPE_BUF.as_ptr().add(PIPE_RPOS), buf.add(written), to_read);
                        PIPE_RPOS += to_read;
                        written += to_read;
                        if written > 0 {
                            if PIPE_RPOS == PIPE_WPOS { PIPE_RPOS = 0; PIPE_WPOS = 0; }
                            return written as i64;
                        }
                    }
                    // No data - block
                    let addr = &raw mut PIPE_BUF as u64;
                    let idx = task_idx(current_task_id());
                    TASKS[idx].blocked_on = addr;
                    TASKS[idx].state = TaskState::Blocked;
                    schedule();
                }
            }
        } else {
            let slice = unsafe { core::slice::from_raw_parts_mut(buf, count) };
            match crate::vfs::inode_read(inode_fd.inode_idx, inode_fd.pos, slice) {
                Some(n) => {
                    inode_fd.pos += n;
                    n as i64
                }
                None => -EIO,
            }
        }
    }
}

fn sys_openat(dirfd: i32, pathname: *const u8, flags: i32, mode: u32) -> i64 {
    let _ = (dirfd, mode);
    sys_open(pathname, flags)
}

fn sys_open(pathname: *const u8, flags: i32) -> i64 {
    if pathname.is_null() { return -EFAULT; }
    let name = unsafe { cstr_from_ptr(pathname) };
    if name.is_empty() { return -ENOENT; }
    let _ = flags;
    match crate::vfs::resolve_or_register(name) {
        Some(flat_idx) => {
            match crate::vfs::alloc_fd(flat_idx, flags) {
                Some(fd) => fd as i64,
                None => -EMFILE,
            }
        }
        None => -ENOENT,
    }
}

fn sys_mkdir(pathname: *const u8, mode: u32) -> i64 {
    if pathname.is_null() { return -EFAULT; }
    let name = unsafe { cstr_from_ptr(pathname) };
    if name.is_empty() { return -ENOENT; }
    match crate::vfs_core::mkdir(name, mode) {
        Ok(_) => 0,
        Err(_) => -EACCES,
    }
}

fn sys_rmdir(pathname: *const u8) -> i64 {
    if pathname.is_null() { return -EFAULT; }
    let name = unsafe { cstr_from_ptr(pathname) };
    if name.is_empty() { return -ENOENT; }
    match crate::vfs_core::rmdir(name) {
        Ok(()) => 0,
        Err(_) => -ENOTEMPTY,
    }
}

fn sys_unlink(pathname: *const u8) -> i64 {
    if pathname.is_null() { return -EFAULT; }
    let name = unsafe { cstr_from_ptr(pathname) };
    if name.is_empty() { return -ENOENT; }
    match crate::vfs_core::remove(name) {
        Ok(()) => 0,
        Err(_) => -EACCES,
    }
}

fn sys_rename(oldpath: *const u8, newpath: *const u8) -> i64 {
    if oldpath.is_null() || newpath.is_null() { return -EFAULT; }
    let old = unsafe { cstr_from_ptr(oldpath) };
    let new = unsafe { cstr_from_ptr(newpath) };
    if old.is_empty() || new.is_empty() { return -ENOENT; }
    match crate::vfs_core::rename(old, new) {
        Ok(()) => 0,
        Err(_) => -EACCES,
    }
}

fn sys_readlink(pathname: *const u8, buf: *mut u8, bufsiz: usize) -> i64 {
    if pathname.is_null() || buf.is_null() { return -EFAULT; }
    let name = unsafe { cstr_from_ptr(pathname) };
    if name.is_empty() { return -ENOENT; }
    match crate::vfs_core::open(name, crate::vfs_core::types::O_RDONLY) {
        Ok(vn_id) => {
            match crate::vfs_core::readlink(vn_id) {
                Ok(target) => {
                    let len = target.len().min(bufsiz);
                    unsafe { core::ptr::copy_nonoverlapping(target.as_ptr(), buf, len); }
                    len as i64
                }
                Err(_) => -EINVAL,
            }
        }
        Err(_) => -ENOENT,
    }
}

fn sys_access(pathname: *const u8, _mode: i32) -> i64 {
    if pathname.is_null() { return -EFAULT; }
    let name = unsafe { cstr_from_ptr(pathname) };
    if name.is_empty() { return -ENOENT; }
    if crate::vfs::resolve_or_register(name).is_some() { 0 } else { -ENOENT }
}

// ── Mmap ──────────────────────────────────────────────────────────

const PROT_READ: i32 = 1;
const PROT_WRITE: i32 = 2;
const PROT_EXEC: i32 = 4;
const MAP_SHARED: i32 = 1;
const MAP_PRIVATE: i32 = 2;
const MAP_ANONYMOUS: i32 = 32;

fn sys_mmap(addr: *mut u8, length: usize, prot: i32, flags: i32, fd: i32, _offset: u64) -> i64 {
    if fd != -1 && (flags & MAP_ANONYMOUS) == 0 {
        return -ENOSYS; // File-backed mmap not yet supported
    }
    if (flags & MAP_SHARED) != 0 {
        return -ENOSYS; // Shared mmap not yet supported
    }

    let id = CURRENT_TASK.load(Ordering::SeqCst);
    if id == 0 { return -EINVAL; }
    serial::write_str("MMAP addr=0x");
    serial::write_hex(addr as u64);
    serial::write_str(" len=0x");
    serial::write_hex(length as u64);
    serial::write_str(" prot=0x");
    serial::write_hex(prot as u64);
    serial::write_str(" flags=0x");
    serial::write_hex(flags as u64);
    serial::write_str(" fd=");
    serial::write_dec(fd as u64);
    serial::write_str("\n");
    // Dump musl reclaim/VMA-tracking struct (app.5 @ libc 0x100000EB940)
    {
        let mlog_cr3 = unsafe { TASKS[task_idx(id)].pml4 };
        let app_va: u64 = 0x100000_EB940;
        if let Some(app_p) = crate::paging::PageTableManager::resolve_phys(mlog_cr3, app_va) {
            let rd = |o: u64| -> u64 { unsafe { core::ptr::read_volatile((app_p + o) as *const u64) } };
            let base = rd(0x0);
            let vlist = rd(0x28);
            let count = unsafe { core::ptr::read_volatile((app_p + 0x30) as *const u32) } as u32;
            let c_lo = rd(0x120);
            let c_hi = rd(0x128);
            crate::serial::write_str("  APP base=0x");
            crate::serial::write_hex(base);
            crate::serial::write_str(" vlist=0x");
            crate::serial::write_hex(vlist);
            crate::serial::write_str(" cnt=");
            crate::serial::write_dec(count as u64);
            crate::serial::write_str(" clamp=0x");
            crate::serial::write_hex(c_lo);
            crate::serial::write_str("-0x");
            crate::serial::write_hex(c_hi);
            crate::serial::write_str("\n");
            for vi in 0..count.min(8) as u64 {
                let vp = crate::paging::PageTableManager::resolve_phys(mlog_cr3, vlist + vi * 0x40).unwrap_or(0);
                if vp == 0 { continue; }
                let ty: u32 = unsafe { core::ptr::read_volatile((vp + 0x0) as *const u32) };
                let fl: u32 = unsafe { core::ptr::read_volatile((vp + 0x4) as *const u32) };
                let vb: u64 = unsafe { core::ptr::read_volatile((vp + 0x10) as *const u64) };
                let vs: u64 = unsafe { core::ptr::read_volatile((vp + 0x28) as *const u64) };
                crate::serial::write_str("    VMA[");
                crate::serial::write_dec(vi);
                crate::serial::write_str("] type=");
                crate::serial::write_dec(ty as u64);
                crate::serial::write_str(" fl=0x");
                crate::serial::write_hex(fl as u64);
                crate::serial::write_str(" 0x");
                crate::serial::write_hex(vb);
                crate::serial::write_str("-0x");
                crate::serial::write_hex(vb.wrapping_add(vs));
                crate::serial::write_str("\n");
            }
        }
    }
    // Dump meta area slots 0..8 to observe group creation order
    static META_LOG_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    if META_LOG_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed) < 25 {
        let mlog_cr3 = unsafe { TASKS[task_idx(id)].pml4 };
        let mpage = crate::paging::PageTableManager::resolve_phys(mlog_cr3, 0x500000).unwrap_or(0);
        crate::serial::write_str("  metapage=0x");
        crate::serial::write_hex(mpage);
        crate::serial::write_str(" m: ");        for mk in 0..8u64 {
            let base = mpage.wrapping_add(0x18 + mk * 0x28);
            let mem: u64 = unsafe { core::ptr::read_volatile((base + 0x10) as *const u64) };
            let avail: u32 = unsafe { core::ptr::read_volatile((base + 0x18) as *const u32) };
            let packed: u64 = unsafe { core::ptr::read_volatile((base + 0x20) as *const u64) };
            crate::serial::write_str("[");
            crate::serial::write_dec(mk);
            crate::serial::write_str("]=0x");
            crate::serial::write_hex(mem);
            crate::serial::write_str("a");
            crate::serial::write_hex(avail as u64);
            crate::serial::write_str("s");
            crate::serial::write_dec((packed >> 6) & 63);
            crate::serial::write_str(" ");
        }
        crate::serial::write_str("\n");
    }

    let page_addr = if addr.is_null() {
        0 // We'll pick an address
    } else {
        (addr as u64) & !0xFFF
    };

    let size = ((length + 0xFFF) & !0xFFF) as u64;

    // Build PTE flags from prot
    let mut pte_flags = crate::paging::PTE_PRESENT | crate::paging::PTE_USER;
    if (prot & PROT_WRITE) != 0 {
        pte_flags |= crate::paging::PTE_WRITABLE;
    }
    if (prot & PROT_EXEC) == 0 {
        pte_flags |= crate::paging::PTE_NO_EXECUTE;
    }

    unsafe {
        let idx = task_idx(id);
        let pml4 = TASKS[idx].pml4;

        // Find a free address if none specified
        let final_addr = if page_addr == 0 {
            // Scan for a free hole: start at 0x7000000000 (high enough to avoid ELF/stack)
            let mut candidate = 0x7000_0000u64;
            let mut found = false;
            'search: while candidate + size <= 0x0000_7FFF_FFFF_F000 {
                // Check if candidate overlaps with any VMA
                let mut overlap = false;
                for vma in &TASKS[idx].vmas {
                    if vma.start == 0 && vma.end == 0 { continue; }
                    if candidate < vma.end && candidate + size > vma.start {
                        overlap = true;
                        candidate = vma.end;
                        continue 'search;
                    }
                }
                if !overlap {
                    found = true;
                    break 'search;
                }
                candidate += PAGE_SIZE_4K;
            }
            if !found {
                serial::write_str("MMAP -> -ENOMEM\n");
                return -ENOMEM;
            }
            candidate
        } else {
            page_addr
        };
        serial::write_str("MMAP -> 0x");
        serial::write_hex(final_addr);
        serial::write_str("\n");

        // Register VMA for demand paging
        let mut vma_added = false;
        for vma in TASKS[idx].vmas.iter_mut() {
            if vma.start == 0 && vma.end == 0 {
                vma.start = final_addr;
                vma.end = final_addr + size;
                vma.flags = pte_flags;
                vma_added = true;
                break;
            }
        }
        if !vma_added {
            serial::write_str("MMAP -> -ENOMEM (vma)\n");
            return -ENOMEM; // Too many VMAs
        }

        // Dump meta slots after the mmap completes (before returning to user)
        if let Some(mpage) = crate::paging::PageTableManager::resolve_phys(pml4, 0x500000) {
            crate::serial::write_str("  POST-MMAP m[0]=0x");
            let m0: u64 = unsafe { core::ptr::read_volatile((mpage + 0x28) as *const u64) };
            crate::serial::write_hex(m0);
            crate::serial::write_str(" m[8]=0x");
            let m8: u64 = unsafe { core::ptr::read_volatile((mpage + 0x28 + 0x140) as *const u64) };
            crate::serial::write_hex(m8);
            crate::serial::write_str(" m[11]=0x");
            let m11: u64 = unsafe { core::ptr::read_volatile((mpage + 0x28 + 0x28 * 11) as *const u64) };
            crate::serial::write_hex(m11);
            crate::serial::write_str("\n");
        }
        // Dump malloc_context.active[] and usage_by_class[] early
        if let Some(cphys) = crate::paging::PageTableManager::resolve_phys(pml4, 0x100000E9B50) {
            crate::serial::write_str("  CTX-ACTIVE: ");
            for ck in 0..8usize {
                let a: u64 = unsafe { core::ptr::read_volatile((cphys + (ck as u64) * 8) as *const u64) };
                crate::serial::write_dec(ck as u64);
                crate::serial::write_str("=");
                crate::serial::write_hex(a);
                crate::serial::write_str(" ");
            }
            crate::serial::write_str("\n");
        }
        if let Some(uphys) = crate::paging::PageTableManager::resolve_phys(pml4, 0x100000E9CD0) {
            crate::serial::write_str("  CTX-USAGE: ");
            for ck in 0..8usize {
                let u: u64 = unsafe { core::ptr::read_volatile((uphys + (ck as u64) * 8) as *const u64) };
                crate::serial::write_dec(ck as u64);
                crate::serial::write_str("=");
                crate::serial::write_hex(u);
                crate::serial::write_str(" ");
            }
            crate::serial::write_str("\n");
        }
        return final_addr as i64;
    }
}

fn sys_mprotect(addr: u64, len: usize, prot: i32) -> i64 {
    let id = CURRENT_TASK.load(Ordering::SeqCst);
    if id == 0 { return -EINVAL; }
    serial::write_str("MPROT addr=0x");
    serial::write_hex(addr);
    serial::write_str(" len=0x");
    serial::write_hex(len as u64);
    serial::write_str(" prot=0x");
    serial::write_hex(prot as u64);
    serial::write_str("\n");
    static MPROT_LOG: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    if MPROT_LOG.fetch_add(1, core::sync::atomic::Ordering::Relaxed) < 3 {
        let mlog_cr3 = unsafe { TASKS[task_idx(id)].pml4 };
        for (tag, app_va) in [("APP", 0x100000_EB940u64), ("LDSO", 0x100000_EB6A0u64)] {
            if let Some(app_p) = crate::paging::PageTableManager::resolve_phys(mlog_cr3, app_va) {
                let rd = |o: u64| -> u64 { unsafe { core::ptr::read_volatile((app_p + o) as *const u64) } };
                let base = rd(0x0);
                let vlist = rd(0x28);
                let count = unsafe { core::ptr::read_volatile((app_p + 0x30) as *const u32) } as u32;
                let c_lo = rd(0x120);
                let c_hi = rd(0x128);
                crate::serial::write_str("  ");
                crate::serial::write_str(tag);
                crate::serial::write_str(" base=0x");
                crate::serial::write_hex(base);
                crate::serial::write_str(" vlist=0x");
                crate::serial::write_hex(vlist);
                crate::serial::write_str(" cnt=");
                crate::serial::write_dec(count as u64);
                crate::serial::write_str(" clamp=0x");
                crate::serial::write_hex(c_lo);
                crate::serial::write_str("-0x");
                crate::serial::write_hex(c_hi);
                crate::serial::write_str("\n");
                for vi in 0..count.min(10) as u64 {
                    let vp = crate::paging::PageTableManager::resolve_phys(mlog_cr3, vlist + vi * 0x40).unwrap_or(0);
                    if vp == 0 { continue; }
                    let ty: u32 = unsafe { core::ptr::read_volatile((vp + 0x0) as *const u32) };
                    let fl: u32 = unsafe { core::ptr::read_volatile((vp + 0x4) as *const u32) };
                    let vb: u64 = unsafe { core::ptr::read_volatile((vp + 0x10) as *const u64) };
                    let vs: u64 = unsafe { core::ptr::read_volatile((vp + 0x28) as *const u64) };
                    crate::serial::write_str("    VMA[");
                    crate::serial::write_dec(vi);
                    crate::serial::write_str("] type=");
                    crate::serial::write_dec(ty as u64);
                    crate::serial::write_str(" fl=0x");
                    crate::serial::write_hex(fl as u64);
                    crate::serial::write_str(" 0x");
                    crate::serial::write_hex(vb);
                    crate::serial::write_str("-0x");
                    crate::serial::write_hex(vb.wrapping_add(vs));
                    crate::serial::write_str("\n");
                }
            }
        }
        let mpage = crate::paging::PageTableManager::resolve_phys(mlog_cr3, 0x500000).unwrap_or(0);
        crate::serial::write_str("  META m: ");
        for mk in 0..14u64 {
            let base = mpage.wrapping_add(0x18 + mk * 0x28);
            let mem: u64 = unsafe { core::ptr::read_volatile((base + 0x10) as *const u64) };
            let packed: u64 = unsafe { core::ptr::read_volatile((base + 0x20) as *const u64) };
            crate::serial::write_str("[");
            crate::serial::write_dec(mk);
            crate::serial::write_str("]=0x");
            crate::serial::write_hex(mem);
            crate::serial::write_str("(");
            crate::serial::write_hex(packed);
            crate::serial::write_str(") ");
        }
        crate::serial::write_str("\n");
    }
    unsafe {
        let idx = task_idx(id);
        let pml4 = TASKS[idx].pml4;
        let start = addr & !0xFFF;
        let end = ((addr + len as u64 + 0xFFF) & !0xFFF);
        let mut pte_flags = crate::paging::PTE_PRESENT | crate::paging::PTE_USER;
        if (prot & 2) != 0 { pte_flags |= crate::paging::PTE_WRITABLE; }
        if (prot & 4) == 0 { pte_flags |= crate::paging::PTE_NO_EXECUTE; }
        let mut page = start;
        while page < end {
            if let Some(phys) = crate::paging::PageTableManager::resolve_phys(pml4, page) {
                let _ = crate::paging::PageTableManager::map_into(pml4, page, phys, pte_flags);
            }
            page += 4096;
        }
    }
    0
}

fn sys_munmap(_addr: u64, _len: usize) -> i64 {
    0
}

// ── Fork ──────────────────────────────────────────────────────────

fn sys_fork() -> i64 {
    let id = CURRENT_TASK.load(Ordering::SeqCst);
    if id == 0 { return -EINVAL; }

    unsafe {
        let child_tid = NEXT_TID.fetch_add(1, Ordering::SeqCst);
        let child_idx = task_idx(child_tid);

        // Ensure slot is free
        if TASKS[child_idx].id != 0 && TASKS[child_idx].state != TaskState::Empty {
            return -ENOMEM;
        }

        let parent_idx = task_idx(id);
        let parent = &TASKS[parent_idx];
        let kernel_stack = match alloc_stack(KERNEL_STACK_PAGES) {
            Some(s) => s,
            None => return -ENOMEM,
        };

        // Clone PML4 with COW
        let child_pml4 = match crate::paging::cow_fork_pml4(parent.pml4) {
            Some(p) => p,
            None => {
                free_stack(kernel_stack, KERNEL_STACK_PAGES);
                return -ENOMEM;
            }
        };

        // Set up child task: copy register state but set rax=0 (return value)
        let mut child_regs = parent.regs;
        child_regs.rax = 0; // Child gets 0 from fork

        let child = &mut TASKS[child_idx];
        *child = Task {
            id: child_tid,
            tgid: child_tid,
            state: TaskState::Ready,
            regs: child_regs,
            kernel_stack,
            user_stack: parent.user_stack,
            pml4: child_pml4,
            static_prio: parent.static_prio,
            normal_prio: parent.normal_prio,
            prio: parent.prio,
            time_slice: initial_time_slice(parent.prio),
            parent: Some(id),
            children_head: None,
            sibling_next: None,
            blocked_on: 0,
            pi_boosted: false,
            runqueue_next: None,
            ipc_partner: 0,
            ipc_phys: 0,
            ipc_vaddr: 0,
            exit_code: 0,
            brk_start: parent.brk_start,
            brk_end: parent.brk_end,
            vmas: parent.vmas,
            wakeup_tick: 0,
        };

        enqueue_task(child_tid, child.prio);

        serial::write_str("SYS_FORK: child ");
        serial::write_dec(child_tid);
        serial::write_str(" (parent ");
        serial::write_dec(id);
        serial::write_str(")\n");

        child_tid as i64
    }
}

// ── Execve ────────────────────────────────────────────────────────

fn sys_execve(pathname: *const u8, argv: u64, _envp: u64) -> i64 {
    crate::serial::write_str("sys_execve called\n");
    let id = CURRENT_TASK.load(Ordering::SeqCst);
    if id == 0 { return -EINVAL; }

    if pathname.is_null() {
        return -EFAULT;
    }

    // Read path string from user space
    let mut path_buf = [0u8; 256];
    let mut len = 0;
    loop {
        let c = unsafe { *pathname.add(len) };
        if c == 0 { break; }
        if len >= 255 { return -ENAMETOOLONG; }
        path_buf[len] = c;
        len += 1;
    }
    let path = &path_buf[..len];

    // Look up the file in VFS
    let inode_idx = match crate::vfs::find_inode(path) {
        Some(idx) => idx,
        None => {
            serial::write_str("SYS_EXECVE: file not found\n");
            return -ENOENT;
        }
    };

    // Read ELF data from the inode
    let elf_size = match crate::vfs::inode_size(inode_idx) {
        Some(sz) => sz,
        None => { serial::write_str("SYS_EXECVE: no size\n"); return -EIO; }
    };
    if elf_size < 64 || elf_size > 1024 * 1024 * 16 {
        return -EINVAL;
    }

    let alloc = unsafe { &mut *crate::memory::allocator() };
    let pages_needed = (elf_size + 0xFFF) / 0x1000;
    let mut elford = 0;
    while (4096usize << elford) < pages_needed * 4096 && elford < 10 {
        elford += 1;
    }
    let buffer_phys = match alloc.alloc(elford) {
        Some(p) => p,
        None => return -ENOMEM,
    };
    let buffer = unsafe { core::slice::from_raw_parts_mut(buffer_phys as *mut u8, elf_size) };
    match crate::vfs::inode_read(inode_idx, 0, buffer) {
        Some(n) if n == elf_size => {}
        _ => {
            alloc.free(buffer_phys, elford);
            return -EIO;
        }
    }

    // Load the ELF
    match crate::elf::load_elf(buffer) {
        Ok(info) => {

            unsafe {
                let idx = task_idx(id);
                let old_pml4 = TASKS[idx].pml4;

                // If dynamic: load interpreter
                let mut interp_info = None;
                if info.is_dynamic {
                    let interp_path = core::str::from_utf8_unchecked(
                        core::slice::from_raw_parts(info.interp_path.as_ptr(), info.interp_path_len)
                    );

                    // Look up interpreter in VFS
                    let interp_name = interp_path.as_bytes();
                    let interp_inode = match crate::vfs::find_inode(interp_name) {
                        Some(ino) => ino,
                        None => {
                            alloc.free(buffer_phys, elford);
                            return -ENOENT;
                        }
                    };
                    let interp_size = match crate::vfs::inode_size(interp_inode) {
                        Some(sz) => sz,
                        None => { alloc.free(buffer_phys, elford); return -EIO; }
                    };
                    if interp_size > 1024 * 1024 * 16 {
                        alloc.free(buffer_phys, elford);
                        return -EINVAL;
                    }
                    let interp_pages = (interp_size + 0xFFF) / 0x1000;
                    let mut interp_ord = 0;
                    while (4096usize << interp_ord) < interp_pages * 4096 && interp_ord < 10 {
                        interp_ord += 1;
                    }
                    let interp_phys = match alloc.alloc(interp_ord) {
                        Some(p) => p,
                        None => { alloc.free(buffer_phys, elford); return -ENOMEM; }
                    };
                    let interp_buf = unsafe {
                        core::slice::from_raw_parts_mut(interp_phys as *mut u8, interp_size)
                    };
                    match crate::vfs::inode_read(interp_inode, 0, interp_buf) {
                        Some(n) if n == interp_size => {}
                        _ => {
                            alloc.free(buffer_phys, elford);
                            alloc.free(interp_phys, interp_ord);
                            return -EIO;
                        }
                    }

                    // Load interpreter at a PIC base into the same PML4
                    match crate::elf::load_elf_at(interp_buf, INTERP_BASE, Some(info.pml4)) {
                        Ok(ii) => interp_info = Some(ii),
                        Err(e) => {
                            alloc.free(buffer_phys, elford);
                            alloc.free(interp_phys, interp_ord);
                            serial::write_str("SYS_EXECVE: interp load failed: ");
                            serial::write_str(e);
                            serial::write_str("\n");
                            return -ENOEXEC;
                        }
                    }
                }

                // Determine entry point and final stack layout
                let final_entry = match &interp_info {
                    Some(ii) => ii.entry,
                    None => info.entry,
                };

                // ── Stack layout (high to low) ──
                // [argv strings at top]
                // [random 16 bytes]
                // [AUX vectors (key+val pairs)]
                // [envp NULL]
                // [argv pointers + NULL]
                // [argc]  ← SP
                //
                // This follows Linux ABI: SP→argc, SP+8→argv[0], etc.
                let mut sp = info.stack_top;

                // ── Read argv into kernel buffers ──
                // argv is a user pointer in the calling task's address space
                // (current PML4).  We read it into a kernel buffer now, before
                // switching to the new PML4 below.
                let mut argc: usize = 0;
                let mut arg_ptrs = [0u64; 64];
                let mut argv_buf = [0u8; 4096];
                let mut argv_offsets = [0u64; 64];
                let mut argv_buf_len = 0usize;
                if argv != 0 {
                    let mut pos = 0usize;
                    loop {
                        let ptr: u64 = core::ptr::read_volatile((argv as *const u64).add(argc));
                        if ptr == 0 { break; }
                        let mut s = 0usize;
                        loop {
                            if pos + s >= argv_buf.len() { break; }
                            let c = *(ptr as *const u8).add(s);
                            if c == 0 { break; }
                            argv_buf[pos + s] = c;
                            s += 1;
                        }
                        if pos + s < argv_buf.len() {
                            argv_buf[pos + s] = 0;
                        }
                        argv_offsets[argc] = pos as u64;
                        pos += s + 1;
                        argc += 1;
                        if argc >= 64 { break; }
                    }
                    argv_buf_len = pos;
                }

                // ── Switch to the new PML4 ──
                // All subsequent stack writes use the new address space.
                pt_mgr().switch_to(info.pml4);
                crate::gdt::set_tss_rsp0(TASKS[idx].kernel_stack);

                // ── Write argv strings from kernel buffer to user stack ──
                if argv != 0 && argc > 0 {
                    let total_aligned = (argv_buf_len + 7) & !7;
                    sp -= total_aligned as u64;
                    let mut string_pos = sp;
                    for i in 0..argc {
                        arg_ptrs[i] = string_pos;
                        let off = argv_offsets[i] as usize;
                        let mut s = 0usize;
                        loop {
                            let c = argv_buf[off + s];
                            if c == 0 { break; }
                            unsafe { core::ptr::write_volatile((string_pos + s as u64) as *mut u8, c); }
                            s += 1;
                        }
                        unsafe { core::ptr::write_volatile((string_pos + s as u64) as *mut u8, 0u8); }
                        string_pos += s as u64 + 1;
                    }
                }

                if info.is_dynamic {
                    // Build stack from bottom: random data, AUX, envp, argv, argc
                    use core::ptr::write_volatile as wv;

                    macro_rules! aux {
                        ($key:expr, $val:expr) => {
                            sp -= 16;
                            wv(sp as *mut u64, $key);
                            wv((sp + 8) as *mut u64, $val);
                        }
                    }

                    // 1. Random data
                    sp -= 16;
                    let random_data = sp;
                    {
                        let cr3: u64;
                        unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, nomem, preserves_flags)); }
                        let phys_addr = PageTableManager::resolve_phys(cr3, sp).unwrap_or(0);
                        crate::serial::write_str("  random_dataD: cr3=0x");
                        crate::serial::write_hex(cr3);
                        crate::serial::write_str(" sp=0x");
                        crate::serial::write_hex(sp);
                        crate::serial::write_str(" phys=0x");
                        crate::serial::write_hex(phys_addr);
                        crate::serial::write_str("\n");
                    }
                    wv(sp as *mut u64, 0x1111222233334444u64);
                    wv((sp + 8) as *mut u64, 0x5555666677778888u64);

                    // 2. AUX vectors (go downward; first written is at the highest mem).
                    // AT_NULL must be written FIRST so it ends up at the highest address
                    // in the aux range; the remaining entries are written after (below) it.
                    // This way, when _dlstart_c iterates forward from argv/envp, it sees
                    // actual aux entries before hitting AT_NULL as the terminator.
                    aux!(0, 0u64);             // AT_NULL
                    aux!(16, 0x0u64);          // AT_HWCAP
                    aux!(26, 16u64);           // AT_RANDOM length
                    aux!(25, random_data);     // AT_RANDOM
                    aux!(23, 0u64);            // AT_SECURE
                    aux!(17, 100u64);          // AT_CLKTCK
                    aux!(14, 0u64);            // AT_EGID
                    aux!(13, 0u64);            // AT_GID
                    aux!(12, 0u64);            // AT_EUID
                    aux!(11, 0u64);            // AT_UID
                    aux!(9, info.entry);       // AT_ENTRY
                    aux!(8, 0u64);             // AT_FLAGS
                    aux!(7, INTERP_BASE);      // AT_BASE
                    aux!(6, 4096u64);          // AT_PAGESZ
                    aux!(5, info.phnum as u64); // AT_PHNUM
                    aux!(4, info.phentsize as u64); // AT_PHENT
                    aux!(3, info.phdr_user);   // AT_PHDR

                    // 3. envp NULL
                    sp -= 8;
                    wv(sp as *mut u64, 0u64);

                    // 4. argv pointers + NULL
                    sp -= ((argc + 1) * 8) as u64;
                    for i in 0..argc {
                        wv((sp + i as u64 * 8) as *mut u64, arg_ptrs[i]);
                    }
                    wv((sp + argc as u64 * 8) as *mut u64, 0u64);

                    // 5. argc
                    sp -= 8;
                    wv(sp as *mut u64, argc as u64);
                } else {
                    // Static: need AUX vectors too (musl reads them)
                    use core::ptr::write_volatile as wv;

                    macro_rules! aux {
                        ($key:expr, $val:expr) => {
                            sp -= 16;
                            wv(sp as *mut u64, $key);
                            wv((sp + 8) as *mut u64, $val);
                        }
                    }

                    // 1. Random data
                    sp -= 16;
                    let random_data = sp;
                    {
                        let cr3: u64;
                        unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, nomem, preserves_flags)); }
                        let phys_addr = PageTableManager::resolve_phys(cr3, sp).unwrap_or(0);
                        crate::serial::write_str("  random_dataS: cr3=0x");
                        crate::serial::write_hex(cr3);
                        crate::serial::write_str(" sp=0x");
                        crate::serial::write_hex(sp);
                        crate::serial::write_str(" phys=0x");
                        crate::serial::write_hex(phys_addr);
                        crate::serial::write_str("\n");
                    }
                    wv(sp as *mut u64, 0xdeadbeefcafebabeu64);
                    wv((sp + 8) as *mut u64, 0x123456789abcdef0u64);

                    // 2. AUX vectors
                    aux!(0, 0u64);             // AT_NULL
                    aux!(16, 0x0u64);          // AT_HWCAP
                    aux!(26, 16u64);           // AT_RANDOM length
                    aux!(25, random_data);     // AT_RANDOM
                    aux!(23, 0u64);            // AT_SECURE
                    aux!(17, 100u64);          // AT_CLKTCK
                    aux!(14, 0u64);            // AT_EGID
                    aux!(13, 0u64);            // AT_GID
                    aux!(12, 0u64);            // AT_EUID
                    aux!(11, 0u64);            // AT_UID
                    aux!(9, info.entry);       // AT_ENTRY
                    aux!(8, 0u64);             // AT_FLAGS
                    aux!(6, 4096u64);          // AT_PAGESZ
                    aux!(5, info.phnum as u64); // AT_PHNUM
                    aux!(4, info.phentsize as u64); // AT_PHENT
                    aux!(3, info.phdr_user);   // AT_PHDR

                    // 3. envp NULL
                    sp -= 8;
                    wv(sp as *mut u64, 0u64);

                    // 4. argv pointers + NULL
                    sp -= ((argc + 1) * 8) as u64;
                    for i in 0..argc {
                        wv((sp + i as u64 * 8) as *mut u64, arg_ptrs[i]);
                    }
                    wv((sp + argc as u64 * 8) as *mut u64, 0u64);

                    // 5. argc
                    sp -= 8;
                    wv(sp as *mut u64, argc as u64);
                }

                TASKS[idx].regs = Registers::new_user(final_entry, sp);
                // Allocate TLS page for musl.  __init_tp will fill self/tid/cancel;
                // we just need a self-pointer so __get_tp() doesn't return 0.
                if info.is_dynamic {
                    let tls_phys = match alloc.alloc(0) {
                        Some(p) => p,
                        None => { alloc.free(old_pml4, 0); alloc.free(buffer_phys, elford); return -ENOMEM; }
                    };
                    unsafe { core::ptr::write_bytes(tls_phys as *mut u8, 0, 4096); }
                    unsafe {
                        core::ptr::write_volatile(tls_phys as *mut u64, USER_TLS_VADDR);
                    }

                    let tls_flags = crate::paging::PTE_PRESENT
                        | crate::paging::PTE_WRITABLE
                        | crate::paging::PTE_USER
                        | crate::paging::PTE_NO_EXECUTE;
                    if PageTableManager::map_into(info.pml4, USER_TLS_VADDR, tls_phys, tls_flags).is_err() {
                        alloc.free(old_pml4, 0);
                        alloc.free(buffer_phys, elford);
                        return -ENOMEM;
                    }
                    TASKS[idx].regs.fs_base = USER_TLS_VADDR;
                }
                TASKS[idx].pml4 = info.pml4;
                // Switch to the new page table so the iretq finds the user mappings

                pt_mgr().switch_to(info.pml4);
                TASKS[idx].user_stack = info.stack_top;
                TASKS[idx].brk_start = info.brk_base;
                TASKS[idx].brk_end = info.brk_base;
                TASKS[idx].vmas = [Vma { start: 0, end: 0, flags: 0 }; MAX_VMAS];

                alloc.free(old_pml4, 0);


                // Naked trampoline: loads GP regs from Registers and iretqs
                unsafe {
                    let r_ptr = &TASKS[idx].regs as *const Registers;
                    // Set FS base before jumping to user space
                    let fs_base = TASKS[idx].regs.fs_base;
                    core::arch::asm!(
                        "mov ecx, 0xC0000100",
                        "wrmsr",
                        in("eax") (fs_base as u32),
                        in("edx") ((fs_base >> 32) as u32),
                        out("ecx") _,
                        options(nostack, preserves_flags)
                    );
                    #[unsafe(naked)]
                    unsafe extern "C" fn iretq_trampoline(_regs: *const Registers) -> ! {
                        core::arch::naked_asm!(
                            "push qword ptr [rdi + 0x98]",
                            "push qword ptr [rdi + 0x38]",
                            "push qword ptr [rdi + 0x88]",
                            "push qword ptr [rdi + 0x90]",
                            "push qword ptr [rdi + 0x80]",
                            "mov rax, [rdi + 0x00]",
                            "mov rbx, [rdi + 0x08]",
                            "mov rcx, [rdi + 0x10]",
                            "mov rdx, [rdi + 0x18]",
                            "mov rsi, [rdi + 0x20]",
                            "mov rbp, [rdi + 0x30]",
                            "mov r8,  [rdi + 0x40]",
                            "mov r9,  [rdi + 0x48]",
                            "mov r10, [rdi + 0x50]",
                            "mov r11, [rdi + 0x58]",
                            "mov r12, [rdi + 0x60]",
                            "mov r13, [rdi + 0x68]",
                            "mov r14, [rdi + 0x70]",
                            "mov r15, [rdi + 0x78]",
                            "mov rdi, [rdi + 0x28]",
                            "iretq",
                        )
                    }
                    iretq_trampoline(r_ptr);
                }
            } // unsafe
        }
        Err(e) => {
            alloc.free(buffer_phys, elford);
            serial::write_str("SYS_EXECVE: ELF load failed [");
            let mut i = 0;
            while i < 40 {
                let c = e.as_bytes().get(i).copied().unwrap_or(0);
                if c == 0 { break; }
                serial::write_char(c as char);
                i += 1;
            }
            serial::write_str("]\n");
            -ENOEXEC
        }
    }
}

// ── Get PID / PPID ───────────────────────────────────────────────

fn sys_getpid() -> i64 {
    let id = CURRENT_TASK.load(Ordering::SeqCst);
    id as i64
}

fn sys_getppid() -> i64 {
    let id = CURRENT_TASK.load(Ordering::SeqCst);
    if id == 0 { return 0; }
    unsafe {
        match TASKS[task_idx(id)].parent {
            Some(pid) => pid as i64,
            None => 0,
        }
    }
}

fn sys_arch_prctl(code: u64, addr: u64) -> i64 {
    match code {
        ARCH_SET_FS => {
            let id = CURRENT_TASK.load(Ordering::SeqCst);
            if id == 0 { return -EINVAL; }
            unsafe {
                let idx = task_idx(id);
                TASKS[idx].regs.fs_base = addr;
            }
            unsafe {
                core::arch::asm!(
                    "mov ecx, 0xC0000100",
                    "wrmsr",
                    in("eax") (addr as u32),
                    in("edx") ((addr >> 32) as u32),
                    out("ecx") _,
                    options(nostack, preserves_flags)
                );
            }
            0
        }
        ARCH_GET_FS => {
            let id = CURRENT_TASK.load(Ordering::SeqCst);
            if id == 0 { return -EINVAL; }
            unsafe {
                let idx = task_idx(id);
                let val = TASKS[idx].regs.fs_base;
                if addr != 0 {
                    core::ptr::write_volatile(addr as *mut u64, val);
                }
            }
            0
        }
        _ => -EINVAL,
    }
}

// ── Sleep ─────────────────────────────────────────────────────────

fn sys_sleep(ticks: u64) -> i64 {
    let id = CURRENT_TASK.load(Ordering::SeqCst);
    if id == 0 { return -EINVAL; }

    let now = unsafe { crate::pit::TICKS.load(core::sync::atomic::Ordering::Relaxed) };

    unsafe {
        let idx = task_idx(id);
        TASKS[idx].wakeup_tick = now + ticks;
        TASKS[idx].state = TaskState::Blocked;
    }

    schedule();
    0
}

// ── Brk ───────────────────────────────────────────────────────────

fn sys_brk(addr: u64) -> i64 {
    let id = CURRENT_TASK.load(Ordering::SeqCst);
    if id == 0 { return -EINVAL; }

    unsafe {
        let idx = task_idx(id);
        serial::write_str("BRK addr=0x");
        serial::write_hex(addr);
        serial::write_str(" cur=0x");
        serial::write_hex(TASKS[idx].brk_end);
        serial::write_str("\n");

        // If addr is 0, return current brk_end (SYS_brk(0) query)
        if addr == 0 {
            return TASKS[idx].brk_end as i64;
        }

        let vma = &mut TASKS[idx].vmas;
        let brk_start = if TASKS[idx].brk_start == 0 {
            // First brk call: use addr as start
            TASKS[idx].brk_start = addr;
            TASKS[idx].brk_end = addr;
            addr
        } else {
            TASKS[idx].brk_start
        };

        // Ensure VMA exists for the brk range
        let mut vma_found = false;
        for v in vma.iter() {
            if v.start == brk_start {
                vma_found = true;
                break;
            }
        }
        if !vma_found {
            for v in vma.iter_mut() {
                if v.start == 0 && v.end == 0 {
                    v.start = brk_start;
                    v.end = brk_start;
                    v.flags = crate::paging::PTE_PRESENT
                        | crate::paging::PTE_WRITABLE
                        | crate::paging::PTE_USER
                        | crate::paging::PTE_NO_EXECUTE;
                    break;
                }
            }
        }

        if addr < brk_start {
            // Can't shrink below start
            return TASKS[idx].brk_end as i64;
        }

        let old_end = TASKS[idx].brk_end;
        TASKS[idx].brk_end = addr;

        // Update VMA end
        for v in vma.iter_mut() {
            if v.start == brk_start {
                v.end = addr;
                break;
            }
        }

        // Pre-allocate zeroed pages for the extended brk range to overwrite
        // stale identity-map PTEs inherited from the bootloader (PML4[0]).
        if addr > old_end {
            let cr3: u64;
            core::arch::asm!("mov {}, cr3", out(reg) cr3);
            let start_page = crate::memory::buddy::page_align_down(old_end);
            let end_page = crate::memory::buddy::page_align_up(addr);
            crate::serial::write_str("  BRK: pre-zero pages 0x");
            crate::serial::write_hex(start_page);
            crate::serial::write_str("-0x");
            crate::serial::write_hex(end_page);
            crate::serial::write_str(" cr3=0x");
            crate::serial::write_hex(cr3);
            crate::serial::write_str("\n");
            let mut page = start_page;
            while page < end_page {
                let phys = {
                    let alloc = &mut *crate::memory::allocator();
                    alloc.alloc(0)
                };
                if let Some(phys) = phys {
                    core::ptr::write_bytes(phys as *mut u8, 0, 4096);
                    // Force compiler to emit the write by reading back
                    let zero_check = core::ptr::read_volatile(phys as *const u64);
                    // Verify with multiple reads
                    let zero_check2 = core::ptr::read_volatile((phys + 0x310) as *const u64);
                    crate::serial::write_str("  BRK: phys=0x");
                    crate::serial::write_hex(phys);
                    crate::serial::write_str(" zero=0x");
                    crate::serial::write_hex(zero_check);
                    crate::serial::write_str(" z310=0x");
                    crate::serial::write_hex(zero_check2);
                    let flags = crate::paging::PTE_PRESENT
                        | crate::paging::PTE_WRITABLE
                        | crate::paging::PTE_USER
                        | crate::paging::PTE_NO_EXECUTE;
                    // Trap writes to the mallocng meta-area page (VA 0x500000)
                    let flags = if page == 0x500000 { flags & !crate::paging::PTE_WRITABLE } else { flags };
                    let res = crate::paging::PageTableManager::map_into(
                        cr3, page, phys, flags
                    );
                    if res.is_ok() {
                        core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, nomem));
                    }
                    // Verify the mapping
                    let verify = crate::paging::PageTableManager::resolve_phys(cr3, page).unwrap_or(!0);
                    crate::serial::write_str(" map=0x");
                    crate::serial::write_hex(page);
                    crate::serial::write_str(" phys=0x");
                    crate::serial::write_hex(phys);
                    crate::serial::write_str(" resolve=0x");
                    crate::serial::write_hex(verify);
                    if res.is_ok() {
                        crate::serial::write_str(" OK");
                    } else {
                        crate::serial::write_str(" FAIL");
                    }
                    if verify != phys {
                        crate::serial::write_str(" MISMATCH!");
                    }
                    crate::serial::write_str("\n");
                }
                page += 4096;
            }
        }

        addr as i64
    }
}

// ── Close ──────────────────────────────────────────────────────────

fn sys_close(fd: u32) -> i64 {
    if crate::vfs::close_fd(fd as usize) { 0 } else { -EBADF }
}

// ── Pipe ───────────────────────────────────────────────────────────

static mut PIPE_BUF: [u8; 4096] = [0; 4096];
static mut PIPE_RPOS: usize = 0;
static mut PIPE_WPOS: usize = 0;
static mut PIPE_OPEN: bool = false;

fn sys_pipe(pipefd: *mut u32) -> i64 {
    if pipefd.is_null() { return -EFAULT; }
    unsafe {
        if PIPE_OPEN { return -EMFILE; }
        PIPE_RPOS = 0;
        PIPE_WPOS = 0;
        PIPE_OPEN = true;
        // Create pseudo-inodes for pipe read/write ends
        // We use inode index crate::vfs::MAX_INODES-1 and crate::vfs::MAX_INODES-2 as pipe markers
        let r_fd = crate::vfs::alloc_fd(crate::vfs::MAX_INODES - 1, 0); // read end
        let w_fd = crate::vfs::alloc_fd(crate::vfs::MAX_INODES - 2, 0); // write end
        match (r_fd, w_fd) {
            (Some(r), Some(w)) => {
                core::ptr::write_volatile(pipefd, r as u32);
                core::ptr::write_volatile(pipefd.add(1), w as u32);
                0
            }
            _ => -EMFILE,
        }
    }
}

// Override pipe read/write in the syscall handlers
// We handle pipes in sys_read/sys_write instead
// ── Dup2 ───────────────────────────────────────────────────────────

fn sys_dup2(oldfd: u32, newfd: u32) -> i64 {
    let table = match crate::vfs::get_fd_table() {
        Some(t) => t,
        None => return -EBADF,
    };
    unsafe {
        if (oldfd as usize) >= crate::vfs::MAX_FDS_PER_TASK || !table[oldfd as usize].used {
            return -EBADF;
        }
        if oldfd == newfd { return newfd as i64; }
        if (newfd as usize) < crate::vfs::MAX_FDS_PER_TASK {
            table[newfd as usize] = table[oldfd as usize];
            table[newfd as usize].pos = 0;
        }
        newfd as i64
    }
}

// ── Nanosleep ──────────────────────────────────────────────────────

fn sys_nanosleep(req: *const u64, _rem: *mut u64) -> i64 {
    if req.is_null() { return -EFAULT; }
    let ns = unsafe { core::ptr::read_volatile(req) };
    // PIT ticks are ~20ms each (50Hz)
    let ticks = (ns + 19_999_999) / 20_000_000; // ceiling division
    if ticks > 0 {
        sys_sleep(ticks);
    }
    0
}

// ── Process groups (stubs) ──────────────────────────────────────────

fn sys_setpgid(_pid: i32, _pgid: i32) -> i64 { 0 }
fn sys_getpgid(_pid: i32) -> i64 {
    let id = current_task_id();
    if id == 0 { return -EINVAL; }
    unsafe { TASKS[task_idx(id)].id as i64 } // return own PID as PGID
}
fn sys_getpgrp() -> i64 {
    let id = current_task_id();
    if id == 0 { return -EINVAL; }
    unsafe { TASKS[task_idx(id)].id as i64 }
}
fn sys_setsid() -> i64 {
    let id = current_task_id();
    if id == 0 { return -EINVAL; }
    unsafe { TASKS[task_idx(id)].id as i64 }
}

// ── Wait4 ──────────────────────────────────────────────────────────

fn sys_wait4(pid: i64, status_ptr: *mut i32, _options: i32, _rusage: u64) -> i64 {
    // Reuse existing waitpid logic; WNOHANG in options corresponds to flags
    let wnohang = if _options & 1 != 0 { WNOHANG } else { 0 };
    sys_waitpid(pid, status_ptr, wnohang)
}

// ── Kill ───────────────────────────────────────────────────────────

fn sys_kill(pid: i64, sig: i32) -> i64 {
    if sig == 0 { return 0; }
    handle_default_signal(pid, sig);
    0
}
fn sys_tkill(tid: i64, sig: i32) -> i64 {
    if sig == 0 { return 0; }
    handle_default_signal(tid, sig);
    0
}

fn handle_default_signal(target: i64, sig: i32) {
    let id = CURRENT_TASK.load(Ordering::SeqCst);
    if id == 0 { return; }
    if target == 0 || target == id as i64 || target == -1 || target == -(id as i64) {
        match sig {
            2 | 3 | 6 | 9 | 15 => {
                serial::write_str("SYS:KILL signal ");
                serial::write_dec(sig as u64);
                serial::write_str(" -> exit\n");
                exit_task(128 + sig);
            }
            _ => {}
        }
    }
}

// ── Uname ──────────────────────────────────────────────────────────

fn sys_uname(buf: *mut u8) -> i64 {
    if buf.is_null() { return -EFAULT; }
    let utsname = [
        b'N', b'i', b'o', b'b', b'i', b'x', 0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, // 65th byte
    ];
    unsafe {
        core::ptr::copy_nonoverlapping(utsname.as_ptr(), buf, 65);
    }
    0
}

// ── Ioctl ──────────────────────────────────────────────────────────

fn sys_ioctl(_fd: u32, request: u64, arg3: u64) -> i64 {
    const TCGETS: u64 = 0x5401;
    const TCSETS: u64 = 0x5402;
    const TCSETSW: u64 = 0x5403;
    const TCSETSF: u64 = 0x5404;
    const TIOCGWINSZ: u64 = 0x5413;
    const TIOCSPGRP: u64 = 0x5410;
    const TIOCGPGRP: u64 = 0x540F;
    match request {
        TCGETS => {
            let ptr = arg3 as *mut u8;
            if ptr.is_null() { return -EFAULT; }
            unsafe {
                core::ptr::write_volatile(ptr.add(0) as *mut u32, 0x0006);
                core::ptr::write_volatile(ptr.add(4) as *mut u32, 0x0005);
                core::ptr::write_volatile(ptr.add(8) as *mut u32, 0x00000BFD);
                core::ptr::write_volatile(ptr.add(12) as *mut u32, 0x00000CF5);
                for i in 16..48 { core::ptr::write_volatile(ptr.add(i), 0); }
                core::ptr::write_volatile(ptr.add(16), 3);
                core::ptr::write_volatile(ptr.add(17), 28);
                core::ptr::write_volatile(ptr.add(18), 127);
                core::ptr::write_volatile(ptr.add(19), 21);
                core::ptr::write_volatile(ptr.add(20), 4);
                core::ptr::write_volatile(ptr.add(21), 23);
                core::ptr::write_volatile(ptr.add(48) as *mut u32, 0x0F);
                core::ptr::write_volatile(ptr.add(52) as *mut u32, 0x0F);
            }
            0
        }
        TCSETS | TCSETSW | TCSETSF => 0,
        TIOCGWINSZ => {
            let ws = arg3 as *mut u16;
            if ws.is_null() { return -EFAULT; }
            unsafe {
                core::ptr::write_volatile(ws, 25);
                core::ptr::write_volatile(ws.add(1), 80);
                core::ptr::write_volatile(ws.add(2), 0);
                core::ptr::write_volatile(ws.add(3), 0);
            }
            0
        }
        TIOCSPGRP => 0,
        TIOCGPGRP => {
            let pgrp = arg3 as *mut i32;
            if pgrp.is_null() { return -EFAULT; }
            let id = current_task_id();
            unsafe {
                let idx = task_idx(id);
                core::ptr::write_volatile(pgrp, TASKS[idx].id as i32);
            }
            0
        }
        _ => -ENOTTY,
    }
}

// ── Fcntl ──────────────────────────────────────────────────────────

fn sys_fcntl(fd: u32, cmd: i32, _arg: u64) -> i64 {
    match cmd {
        0 => sys_dup2(fd, fd),
        1 => 0,  // F_GETFD
        2 => 0,  // F_SETFD
        3 => 2,  // F_GETFL → return O_RDWR (2)
        4 => 0,  // F_SETFL
        _ => -EINVAL,
    }
}

// ── Getcwd ─────────────────────────────────────────────────────────

static mut CWD_BUF: [u8; 256] = [0; 256];
static mut CWD_LEN: usize = 0;
static CWD_INIT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn get_cwd_bytes() -> &'static [u8] {
    unsafe {
        if !CWD_INIT.load(core::sync::atomic::Ordering::Relaxed) {
            CWD_BUF[0] = b'/';
            CWD_LEN = 1;
            CWD_INIT.store(true, core::sync::atomic::Ordering::Relaxed);
        }
        &CWD_BUF[..CWD_LEN]
    }
}

fn sys_getcwd(buf: *mut u8, size: usize) -> i64 {
    if buf.is_null() { return -EFAULT; }
    let cwd = get_cwd_bytes();
    if size < cwd.len() + 1 { return -ERANGE; }
    unsafe {
        core::ptr::copy_nonoverlapping(cwd.as_ptr(), buf, cwd.len());
        core::ptr::write_volatile(buf.add(cwd.len()), 0);
    }
    cwd.len() as i64
}

// ── Chdir ──────────────────────────────────────────────────────────

fn sys_chdir_from_fd(fd: u32) -> i64 {
    let table = match crate::vfs::get_fd_table() {
        Some(t) => t,
        None => return -EBADF,
    };
    if (fd as usize) >= crate::vfs::MAX_FDS_PER_TASK || !table[fd as usize].used {
        return -EBADF;
    }
    sys_chdir_from_fd_inner(fd)
}

fn sys_chdir_from_fd_inner(_fd: u32) -> i64 {
    0
}

fn sys_chdir(path: *const u8) -> i64 {
    if path.is_null() { return -EFAULT; }
    let name = unsafe { cstr_from_ptr(path) };
    if name.is_empty() { return -ENOENT; }
    match crate::vfs_core::resolve_ino(name) {
        Ok(_) => {
            unsafe {
                let l = core::cmp::min(name.len(), 255);
                CWD_BUF[..l].copy_from_slice(&name[..l]);
                CWD_LEN = l;
            }
            0
        }
        Err(_) => -ENOENT,
    }
}

// ── Getdents64 ─────────────────────────────────────────────────────

#[repr(packed)]
struct LinuxDirent64 {
    d_ino: u64,
    d_off: u64,
    d_reclen: u16,
    d_type: u8,
    d_name: [u8; 0], // flexible, we manage manually
}

fn sys_getdents64(fd: u32, buf: *mut u8, count: usize) -> i64 {
    if buf.is_null() { return -EFAULT; }
    let table = match crate::vfs::get_fd_table() {
        Some(t) => t,
        None => return -EBADF,
    };
    let flat_idx;
    let pos;
    unsafe {
        if (fd as usize) >= crate::vfs::MAX_FDS_PER_TASK || !table[fd as usize].used {
            return -EBADF;
        }
        flat_idx = table[fd as usize].inode_idx;
        pos = table[fd as usize].pos;
    }
    if flat_idx >= crate::vfs::MAX_INODES - 2 {
        return -ENOTDIR;
    }
    let vn_id = unsafe { crate::vfs::INODES[flat_idx].vnode_id };
    let vn_id = if vn_id != 0 { vn_id } else { return 0 };

    let mut dirent_buf = [
        crate::vfs_core::types::Dirent::empty(),
        crate::vfs_core::types::Dirent::empty(),
        crate::vfs_core::types::Dirent::empty(),
        crate::vfs_core::types::Dirent::empty(),
        crate::vfs_core::types::Dirent::empty(),
        crate::vfs_core::types::Dirent::empty(),
        crate::vfs_core::types::Dirent::empty(),
        crate::vfs_core::types::Dirent::empty(),
        crate::vfs_core::types::Dirent::empty(),
        crate::vfs_core::types::Dirent::empty(),
    ];

    let mut written = 0usize;
    let mut off = pos;
    loop {
        let n = match crate::vfs_core::readdir(vn_id, off as u64, &mut dirent_buf) {
            Ok(n) => n,
            Err(_) => break,
        };
        if n == 0 { break; }
        for i in 0..n {
            let d = &dirent_buf[i];
            let nlen = d.namelen as usize;
            if nlen == 0 { continue; }
            let reclen: usize = (19 + nlen + 1 + 7) & !7; // +1 for null terminator
            if written + reclen > count { break; }
            unsafe {
                let ent = buf.add(written) as *mut LinuxDirent64;
                core::ptr::write_volatile(core::ptr::addr_of_mut!((*ent).d_ino), d.ino);
                core::ptr::write_volatile(core::ptr::addr_of_mut!((*ent).d_off), reclen as u64);
                core::ptr::write_volatile(core::ptr::addr_of_mut!((*ent).d_reclen), reclen as u16);
                let dtype = match d.type_ {
                    1 => 8,  // DT_REG
                    2 => 4,  // DT_DIR
                    7 => 10, // DT_LNK
                    _ => 0,
                };
                core::ptr::write_volatile(core::ptr::addr_of_mut!((*ent).d_type), dtype);
                let name_ptr = buf.add(written + 19) as *mut u8;
                core::ptr::copy_nonoverlapping(d.name.as_ptr(), name_ptr, nlen);
                core::ptr::write_volatile(name_ptr.add(nlen), 0);
            }
            written += reclen;
            off += 1;
        }
    }
    unsafe { table[fd as usize].pos = off; }
    written as i64
}

// ── Gettimeofday ───────────────────────────────────────────────────

fn sys_gettimeofday(tv: *mut u64, _tz: *mut u64) -> i64 {
    if tv.is_null() { return -EFAULT; }
    let ticks = unsafe { crate::pit::TICKS.load(core::sync::atomic::Ordering::Relaxed) };
    // Each tick is ~20ms (50Hz PIT)
    let secs = (ticks * 20_000_000) / 1_000_000_000_000; // not precise, placeholder
    let usecs = ((ticks * 20_000_000) / 1000) % 1_000_000;
    unsafe {
        core::ptr::write_volatile(tv, secs);
        core::ptr::write_volatile(tv.add(1), usecs);
    }
    0
}

// ── Stat/Fstat/Lstat ───────────────────────────────────────────────

#[repr(C)]
struct LinuxStat {
    st_dev: u64,
    st_ino: u64,
    st_nlink: u64,
    st_mode: u32,
    st_uid: u32,
    st_gid: u32,
    _pad0: u32,
    st_rdev: u64,
    st_size: i64,
    st_blksize: i64,
    st_blocks: i64,
    st_atime: i64,
    st_atime_nsec: i64,
    st_mtime: i64,
    st_mtime_nsec: i64,
    st_ctime: i64,
    st_ctime_nsec: i64,
    _unused: [i64; 3],
}

const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IRWXU: u32 = 0o700;
const S_IRUSR: u32 = 0o400;

fn fill_stat_from_vnode(vnode_id: u16, statbuf: *mut u8) -> i64 {
    let st = match crate::vfs_core::stat(vnode_id) {
        Ok(s) => s,
        Err(_) => return -EIO,
    };
    unsafe {
        let dst = statbuf as *mut LinuxStat;
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*dst).st_dev), 0);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*dst).st_ino), st.ino);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*dst).st_nlink), st.nlink as u64);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*dst).st_mode), st.mode);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*dst).st_uid), st.uid);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*dst).st_gid), st.gid);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*dst).st_rdev), st.rdev);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*dst).st_size), st.size as i64);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*dst).st_blksize), st.blksize as i64);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*dst).st_blocks), st.blocks as i64);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*dst).st_atime), st.atime as i64);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*dst).st_atime_nsec), 0);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*dst).st_mtime), st.mtime as i64);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*dst).st_mtime_nsec), 0);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*dst).st_ctime), st.ctime as i64);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*dst).st_ctime_nsec), 0);
    }
    0
}

fn sys_stat(pathname: *const u8, statbuf: *mut u8) -> i64 {
    if pathname.is_null() || statbuf.is_null() { return -EFAULT; }
    let name = unsafe { cstr_from_ptr(pathname) };
    if name.is_empty() { return -ENOENT; }
    match crate::vfs::resolve_or_register(name) {
        Some(flat_idx) => {
            let vn_id = unsafe { crate::vfs::INODES[flat_idx].vnode_id };
            if vn_id != 0 {
                fill_stat_from_vnode(vn_id, statbuf)
            } else {
                fill_stat_from_vnode(0, statbuf) // fallback
            }
        }
        None => -ENOENT,
    }
}

fn sys_fstat(fd: u32, statbuf: *mut u8) -> i64 {
    if statbuf.is_null() { return -EFAULT; }
    let fdesc = match crate::vfs::fd_to_inode(fd as usize) {
        Some(f) => f,
        None => return -EBADF,
    };
    let vn_id = unsafe { crate::vfs::INODES[fdesc.inode_idx].vnode_id };
    if vn_id != 0 {
        fill_stat_from_vnode(vn_id, statbuf)
    } else {
        fill_stat_from_vnode(0, statbuf)
    }
}

// ── Helper ─────────────────────────────────────────────────────────

fn cstr_from_ptr(ptr: *const u8) -> &'static [u8] {
    unsafe {
        let mut len = 0usize;
        while core::ptr::read_volatile(ptr.add(len)) != 0 && len < 4096 { len += 1; }
        core::slice::from_raw_parts(ptr, len)
    }
}

pub fn current_task_pml4() -> u64 {
    let id = CURRENT_TASK.load(Ordering::SeqCst);
    if id == 0 { return 0; }
    unsafe { TASKS[task_idx(id)].pml4 }
}

/// Handle demand paging for mmap'd (or brk) regions.
/// Returns true if the page was allocated and mapped.
pub fn handle_demand_page(pml4: u64, cr2: u64) -> bool {
    let id = CURRENT_TASK.load(Ordering::SeqCst);
    if id == 0 { return false; }
    unsafe {
        let idx = task_idx(id);
        for vma in &TASKS[idx].vmas {
            if vma.start == 0 && vma.end == 0 { continue; }
            if cr2 >= vma.start && cr2 < vma.end {
                let alloc = &mut *crate::memory::allocator();
                let phys = match alloc.alloc(0) {
                    Some(p) => p,
                    None => return false,
                };
                // Zero the page so heap metadata (musl malloc) works correctly
                core::ptr::write_bytes(phys as *mut u8, 0, 4096);
                let page_addr = cr2 & !0xFFF;
                if crate::paging::PageTableManager::map_into(pml4, page_addr, phys, vma.flags).is_err() {
                    return false;
                }
                crate::serial::write_str("  DMD: allocated page for 0x");
                crate::serial::write_hex(page_addr);
                crate::serial::write_str(" phys=0x");
                crate::serial::write_hex(phys);
                crate::serial::write_str("\n");
                return true;
            }
        }
    }
    false
}

pub fn pt_mgr() -> &'static mut PageTableManager {
    crate::paging::pt_mgr()
}

fn sys_poll(_fds: u64, _nfds: u64, _timeout: i32) -> i64 {
    0
}

fn sys_lseek(_fd: u32, _offset: i64, _whence: i32) -> i64 {
    -ENOSYS
}

fn sys_readv(_fd: u32, _iov: u64, _iovcnt: i32) -> i64 {
    -ENOSYS
}

fn sys_writev(fd: u32, iov: u64, iovcnt: i32) -> i64 {
    if fd != 1 && fd != 2 { return -ENOSYS; }
    if iovcnt <= 0 { return 0; }
    let mut total = 0i64;
    for i in 0..iovcnt as usize {
        let base: u64;
        let len: usize;
        unsafe {
            base = core::ptr::read_volatile((iov + i as u64 * 16) as *const u64);
            len = core::ptr::read_volatile((iov + i as u64 * 16 + 8) as *const usize);
        }
        if base == 0 || len == 0 { continue; }
        let slice = unsafe { core::slice::from_raw_parts(base as *const u8, len) };
        for &c in slice {
            if c == 0 { break; }
            serial::write_char(c as char);
        }
        total += len as i64;
    }
    if total > 0 { serial::write_str("\n"); }
    total
}

fn sys_clock_gettime(_clk_id: u64, tp: *mut u8) -> i64 {
    if tp.is_null() { return -EFAULT; }
    let ns = unsafe { crate::pit::TICKS.load(core::sync::atomic::Ordering::Relaxed) as u64 * 20_000_000 };
    unsafe {
        core::ptr::write_volatile(tp as *mut u64, ns / 1_000_000_000);
        core::ptr::write_volatile((tp as *mut u64).add(1), ns % 1_000_000_000);
    }
    0
}

fn sys_getrandom(buf: *mut u8, len: usize, _flags: u32) -> i64 {
    if buf.is_null() { return -EFAULT; }
    unsafe {
        for i in 0..len {
            core::ptr::write_volatile(buf.add(i), (i * 0x9E) as u8);
        }
    }
    len as i64
}

// ── Test / Demo ──────────────────────────────────────────────────

pub fn test() {
    unsafe { core::arch::asm!("cli"); }

    // Load user ELF modules from multiboot2
    let info_addr = crate::MULTIBOOT_INFO.load(Ordering::SeqCst) as u32;
    let mut init_tid = 0u64;
    if info_addr != 0 {
        let mut modules = [crate::multiboot2::ModuleInfo { start: 0, end: 0 }; 8];
        let n = crate::multiboot2::find_modules(info_addr, &mut modules);
        for i in 0..n {
            let mod_data = unsafe {
                core::slice::from_raw_parts(
                    modules[i].start as *const u8,
                    (modules[i].end - modules[i].start) as usize,
                )
            };
            if mod_data.len() >= 4 && mod_data[0] == 0x7f && mod_data[1] == b'E'
                && mod_data[2] == b'L' && mod_data[3] == b'F'
            {
                match i {
                    0 => {
                        crate::vfs::create_file(b"/bin/init", mod_data);
                        match crate::elf::load_elf(mod_data) {
                            Ok(elf_info) => {
                                if let Some(tid) = create_user_task(elf_info.entry, elf_info.pml4, elf_info.stack_top) {
                                    init_tid = tid;
                                }
                            }
                            Err(e) => {
                                serial::write_str("TASK: ELF load failed: ");
                                serial::write_str(e);
                                serial::write_str("\n");
                            }
                        }
                    }
                    1 => {
                        crate::vfs::create_file(b"/bin/hello", mod_data);
                    }
                    2 => {
                        crate::vfs::create_file(b"/bin/shell", mod_data);
                    }
                    3 => {
                        crate::vfs::create_external_file(b"/lib/libc.so", modules[i].start as *mut u8, mod_data.len());
                        crate::vfs::create_external_file(b"/lib/ld-musl-x86_64.so.1", modules[i].start as *mut u8, mod_data.len());
                    }
                    4 => {
                        crate::vfs::create_file(b"/bin/hello_dynamic", mod_data);
                    }
                    5 => {
                        crate::vfs::create_file(b"/bin/busybox", mod_data);
                    }
                    _ => {}
                }
            }
        }
    }

    // Create /dev/null for musl __init_libc
    if crate::vfs::find_inode(b"/dev/null").is_none() {
        let _ = crate::vfs_core::mkdir(b"/dev", crate::vfs_core::types::S_IRUSR | crate::vfs_core::types::S_IWUSR | crate::vfs_core::types::S_IXUSR | crate::vfs_core::types::S_IRGRP | crate::vfs_core::types::S_IXGRP | crate::vfs_core::types::S_IROTH);
        // Use the flat VFS to create an empty file
        crate::vfs::create_file(b"/dev/null", b"");
        serial::write_str("VFS: created '/dev/null'\n");
    }

    let task0 = unsafe { &mut TASKS[0] };
    task0.id = 0;
    task0.state = TaskState::Running;
    task0.kernel_stack = alloc_stack(KERNEL_STACK_PAGES).expect("task0 stack");
    task0.regs = Registers::new_kernel(continue_after_schedule as u64, task0.kernel_stack);
    task0.pml4 = pt_mgr().kernel_pml4();
    task0.static_prio = nice_to_prio(19);
    task0.normal_prio = task0.static_prio;
    task0.prio = task0.static_prio;
    CURRENT_TASK.store(0, Ordering::SeqCst);

    unsafe {
        core::arch::asm!("mov rsp, {}", in(reg) task0.kernel_stack);
    }

    serial::write_str("TASK: switching to task ");
    serial::write_dec(init_tid);
    serial::write_str("...\n");

    // Dequeue init task so it's not in the runqueue twice
    remove_from_runqueue(init_tid);

    let new_task = unsafe { &mut TASKS[task_idx(init_tid)] };
    new_task.state = TaskState::Running;
    CURRENT_TASK.store(init_tid, Ordering::SeqCst);

    unsafe { crate::gdt::set_tss_rsp0(new_task.kernel_stack); }
    pt_mgr().switch_to(new_task.pml4);
    unsafe {
        // Restore FS base for the new task (same as schedule() does)
        let fs_base = new_task.regs.fs_base;
        core::arch::asm!(
            "mov ecx, 0xC0000100",
            "wrmsr",
            in("eax") (fs_base as u32),
            in("edx") ((fs_base >> 32) as u32),
            out("ecx") _,
            options(nostack, preserves_flags)
        );
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
