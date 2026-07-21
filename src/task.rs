use core::sync::atomic::{AtomicU64, Ordering};

use crate::memory::buddy::PAGE_SIZE;
use crate::paging::PageTableManager;
use crate::serial;

pub const MAX_TASKS: usize = 64;
pub const KERNEL_STACK_PAGES: usize = 2;
pub const USER_STACK_PAGES: usize = 8;
pub const IRQ_BASE: u8 = 0x30;
pub const TIMER_IRQ_VECTOR: u8 = IRQ_BASE + 0;

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

    let task = unsafe { &mut TASKS[task_idx(tid)] };
    task.id = tid;
    task.tgid = tid;
    task.state = TaskState::Ready;
    task.regs = Registers::new_user(entry, user_stack_top);
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

    if current != 0 {
        unsafe {
            let idx = task_idx(current);
            if TASKS[idx].state == TaskState::Running {
                TASKS[idx].state = TaskState::Ready;
                enqueue_task(current, TASKS[idx].prio);
            }
        }
    }

    let next_id = 'pick: {
        let picked = dequeue_task();
        match picked {
            Some(id) if id == current => {
                unsafe { enqueue_task(current, TASKS[task_idx(current)].prio); }
                let prio = unsafe { TASKS[task_idx(current)].prio as usize };
                unsafe { RUNQUEUE.bitmap &= !(1u64 << prio); }
                let next = dequeue_task();
                unsafe { RUNQUEUE.bitmap |= 1u64 << prio; }
                match next {
                    Some(id2) => { break 'pick id2; }
                    None => {
                        crate::serial::write_str(" schedule: only current task\n");
                        unsafe { core::arch::asm!("sti", options(nostack, nomem, preserves_flags)); }
                        return;
                    }
                }
            }
            Some(id) => { break 'pick id; }
            None => {
                crate::serial::write_str(" schedule: no tasks\n");
                unsafe { core::arch::asm!("sti", options(nostack, nomem, preserves_flags)); }
                return;
            }
        }
    };

    let new_idx = task_idx(next_id);
    crate::serial::write_str(" sched ");
    crate::serial::write_dec(current);
    crate::serial::write_str("->");
    crate::serial::write_dec(next_id);
    crate::serial::write_str(" pml4=0x");
    crate::serial::write_hex(unsafe { TASKS[new_idx].pml4 });
    crate::serial::write_str("\n");

    unsafe { crate::gdt::set_tss_rsp0(TASKS[new_idx].kernel_stack); }

    let old = CURRENT_TASK.swap(next_id, Ordering::SeqCst);

    unsafe {
        TASKS[new_idx].state = TaskState::Running;
        pt_mgr().switch_to(TASKS[new_idx].pml4);
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3);
        crate::serial::write_str(" cr3=0x");
        crate::serial::write_hex(cr3);
        crate::serial::write_str(" ok ks=0x");
        crate::serial::write_hex(TASKS[new_idx].kernel_stack);
        crate::serial::write_str("\n");

        let old_idx = task_idx(old);
        let old_ptr = &mut TASKS[old_idx].regs as *mut Registers;
        let new_ptr = &TASKS[new_idx].regs as *const Registers;

        // Debug: test write to user stack before context switch
        let user_rsp = (*new_ptr).rsp;
        crate::serial::write_str("  debug: new.rsp=0x");
        crate::serial::write_hex(user_rsp);
        crate::serial::write_str("\n");
        let test_addr = user_rsp - 40;
        unsafe {
            core::ptr::write_volatile(test_addr as *mut u64, 0x42);
            let val = core::ptr::read_volatile(test_addr as *const u64);
            crate::serial::write_str("  debug: user stack RW test at 0x");
            crate::serial::write_hex(test_addr);
            crate::serial::write_str(" val=0x");
            crate::serial::write_hex(val);
            crate::serial::write_str("\n");
        }

        crate::serial::write_str("  dbg: oldp=0x");
        crate::serial::write_hex(old_ptr as u64);
        crate::serial::write_str(" newp=0x");
        crate::serial::write_hex(new_ptr as u64);
        crate::serial::write_str(" cs=0x");
        crate::serial::write_hex((*new_ptr).cs);
        crate::serial::write_str(" rip=0x");
        crate::serial::write_hex((*new_ptr).rip);
        crate::serial::write_str(" rsp=0x");
        crate::serial::write_hex((*new_ptr).rsp);
        crate::serial::write_str(" ss=0x");
        crate::serial::write_hex((*new_ptr).ss);
        crate::serial::write_str("\n");

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
            enqueue_task(id, TASKS[idx].prio);
        }
    }

    schedule();
}

pub fn exit_task(code: i32) {
    let id = CURRENT_TASK.load(Ordering::SeqCst);
    if id == 0 { return; }

    unsafe {
        let idx = task_idx(id);
        TASKS[idx].state = TaskState::Exited;
        TASKS[idx].exit_code = code;

        free_stack(TASKS[idx].kernel_stack, KERNEL_STACK_PAGES);
        if TASKS[idx].user_stack != 0 {
            free_stack(TASKS[idx].user_stack, USER_STACK_PAGES);
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
        // Check if target is user or kernel mode by examining CS.RPL
        "mov rbx, [rsi + 0x90]",
        "test bl, 3",
        "jnz 1f",
        // Kernel→kernel: push RIP and ret (1 pop = correct RSP alignment)
        "push qword ptr [rsi + 0x80]",
        "mov rsi, [rsi + 0x20]",
        "ret",
        // Kernel→user: push full iretq frame (5 pops)
        "1: push qword ptr [rsi + 0x98]",
        "push qword ptr [rsi + 0x38]",
        "push qword ptr [rsi + 0x88]",
        "push qword ptr [rsi + 0x90]",
        "push qword ptr [rsi + 0x80]",
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
        "mov rdi, rbp",
        "add rdi, 8",
        "call {save_context}",
        "call {timer_schedule}",
        "test rax, rax",
        "jz 3f",
        "mov rsp, rax",
        "3:",
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
        "iretq",

        save_context = sym save_interrupt_context,
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
        let regs = &mut TASKS[task_idx(current)].regs;

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

        regs.rip    = *frame.add(0);
        regs.cs     = *frame.add(1);
        regs.rflags = *frame.add(2);
        if (*frame.add(1) & 3) == 3 {
            // User → kernel: CPU pushed SS and RSP onto kernel stack
            regs.rsp = *frame.add(3);
            regs.ss  = *frame.add(4);
        } else {
            // Kernel → kernel: only RIP, CS, RFLAGS pushed
            regs.rsp = frame as u64 + 24;
            regs.ss  = KERNEL_DATA_SELECTOR;
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
    let c = SCHED_CALLS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    if c < 3 {
        crate::serial::write_str("SCHED: call ");
        crate::serial::write_dec(c);
        crate::serial::write_str("\n");
    }
    crate::pic::send_eoi(0);

    let current = CURRENT_TASK.load(Ordering::SeqCst);
    if current == 0 {
        return 0;
    }

    unsafe {
        let idx = task_idx(current);

        // Decrement time slice
        if TASKS[idx].time_slice > 0 {
            TASKS[idx].time_slice -= 1;
        }

        // If task not running, don't reschedule — just build frame from saved regs
        if TASKS[idx].state != TaskState::Running {
            return build_frame(TASKS[idx].kernel_stack, &raw const TASKS[idx]);
        }

        // Time slice still positive → keep running current task
        if TASKS[idx].time_slice > 0 {
            return build_frame(TASKS[idx].kernel_stack, &raw const TASKS[idx]);
        }

        // Time slice expired — requeue and pick next
        crate::serial::write_str("SCHED: expire ");
        crate::serial::write_dec(current);
        crate::serial::write_str("\n");
        TASKS[idx].state = TaskState::Ready;
        TASKS[idx].time_slice = initial_time_slice(TASKS[idx].prio);
        enqueue_task(current, TASKS[idx].prio);

        let next_id = match dequeue_task() {
            Some(id) => id,
            None => {
                crate::serial::write_str("SCHED: no task\n");
                TASKS[idx].state = TaskState::Running;
                return build_frame(TASKS[idx].kernel_stack, &raw const TASKS[idx]);
            }
        };

        if next_id == current {
            crate::serial::write_str("SCHED: same ");
            crate::serial::write_dec(next_id);
            crate::serial::write_str("\n");
            TASKS[idx].state = TaskState::Running;
            return build_frame(TASKS[idx].kernel_stack, &raw const TASKS[idx]);
        }

        let new_idx = task_idx(next_id);
        crate::serial::write_str("SCHED: ");
        crate::serial::write_dec(current);
        crate::serial::write_str(" -> ");
        crate::serial::write_dec(next_id);
        crate::serial::write_str(" (pml4=0x");
        crate::serial::write_hex(TASKS[new_idx].pml4);
        crate::serial::write_str(")\n");
        TASKS[new_idx].state = TaskState::Running;
        CURRENT_TASK.store(next_id, Ordering::SeqCst);
        pt_mgr().switch_to(TASKS[new_idx].pml4);
        crate::gdt::set_tss_rsp0(TASKS[new_idx].kernel_stack);
        build_frame(TASKS[new_idx].kernel_stack, &raw const TASKS[new_idx])
    }
}

fn build_frame(kernel_stack: u64, task_ptr: *const Task) -> u64 {
    let regs = unsafe { &(*task_ptr).regs };
    unsafe {
        let base = (kernel_stack as *mut u64).sub(20);
        // Must match pop order in timer_interrupt_handler:
        // pop r15, r14, r13, r12, r11, r10, r9, r8, rdi, rsi, rdx, rcx, rbx, rax, rbp
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
        base as u64
    }
}

// ── Syscalls ─────────────────────────────────────────────────────

pub const SYS_exit: u64 = 0;
pub const SYS_write: u64 = 1;
pub const SYS_get_ticks: u64 = 2;
pub const SYS_yield: u64 = 3;
pub const SYS_futex: u64 = 4;
pub const SYS_shm_setup: u64 = 5;
pub const SYS_shm_notify: u64 = 6;
pub const SYS_shm_wait: u64 = 7;
pub const SYS_shm_teardown: u64 = 8;
pub const SYS_spawn: u64 = 9;

#[no_mangle]
pub extern "C" fn syscall_handler(
    syscall_num: u64,
    arg1: u64, arg2: u64, arg3: u64,
    arg4: u64, arg5: u64, _arg6: u64
) -> i64 {
    match syscall_num {
        SYS_exit => sys_exit(arg1 as i32),
        SYS_write => sys_write(arg1 as u32, arg2 as *const u8, arg3 as usize),
        SYS_get_ticks => sys_get_ticks(),
        SYS_yield => sys_yield(),
        SYS_futex => sys_futex(arg1 as *const u32, arg2 as i32, arg3 as u32,
                                arg4 as *const u32, arg5 as u32),
        SYS_shm_setup => crate::ipc::shm_setup(arg1, arg2),
        SYS_shm_notify => crate::ipc::shm_notify(arg1),
        SYS_shm_wait => crate::ipc::shm_wait(arg1),
        SYS_shm_teardown => crate::ipc::shm_teardown(arg1),
        SYS_spawn => sys_spawn(arg1 as *const u8, arg2 as usize),
        _ => -ENOSYS,
    }
}

fn sys_exit(status: i32) -> i64 {
    serial::write_str("SYS_EXIT: ");
    serial::write_dec(status as u64);
    serial::write_str("\n");
    exit_task(status);
    0
}

fn sys_write(fd: u32, buf: *const u8, count: usize) -> i64 {
    if fd == 1 && !buf.is_null() && count > 0 {
        let mut total = 0;
        while total < count {
            let c = unsafe { *buf.add(total) };
            if c == 0 { break; }
            serial::write_char(c as char);
            total += 1;
        }
        total as i64
    } else {
        -EBADF
    }
}

fn sys_get_ticks() -> i64 {
    unsafe { crate::pit::TICKS.load(core::sync::atomic::Ordering::Relaxed) as i64 }
}

fn sys_yield() -> i64 {
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
pub const ENOSYS: i64 = -38;

// ── Helpers ──────────────────────────────────────────────────────

pub fn pt_mgr() -> &'static mut PageTableManager {
    crate::paging::pt_mgr()
}

// ── Test / Demo ──────────────────────────────────────────────────

extern "C" fn task_spin() -> ! {
    let mut count = 0u64;
    loop {
        if count < 3 {
            crate::serial::write_str("TASK: spin ");
            crate::serial::write_dec(count);
            crate::serial::write_str(" (tid=");
            crate::serial::write_dec(current_task_id());
            crate::serial::write_str(")\n");
            count += 1;
        }
        sys_yield();
    }
}

pub fn test() {
    unsafe { core::arch::asm!("cli"); }

    serial::write_str("TASK: testing kernel task creation...\n");

    let tid1 = create_kernel_task_prio(task_spin as *const () as u64, -10);
    let tid2 = create_kernel_task_prio(task_spin as *const () as u64, 5);

    serial::write_str("TASK: task IDs: ");
    serial::write_dec(tid1.unwrap());
    serial::write_str(", ");
    serial::write_dec(tid2.unwrap());
    serial::write_str("\n");

    // Load user ELF from multiboot2 module
    let info_addr = crate::MULTIBOOT_INFO.load(Ordering::SeqCst) as u32;
    if info_addr != 0 {
        let mut modules = [crate::multiboot2::ModuleInfo { start: 0, end: 0 }; 4];
        let n = crate::multiboot2::find_modules(info_addr, &mut modules);
        if n > 0 {
            let mod_data = unsafe {
                core::slice::from_raw_parts(
                    modules[0].start as *const u8,
                    (modules[0].end - modules[0].start) as usize,
                )
            };
            serial::write_str("TASK: loading user ELF from module (");
            serial::write_dec(mod_data.len() as u64);
            serial::write_str(" bytes @ 0x");
            serial::write_hex(modules[0].start);
            serial::write_str(")\n");
            // Debug: print first 16 bytes
            let first_bytes = &mod_data[..16.min(mod_data.len())];
            for &b in first_bytes {
                serial::write_hex(b as u64);
                serial::write_char(' ');
            }
            serial::write_str("\n");
            match crate::elf::load_elf(mod_data) {
                Ok(elf_info) => {
                    if let Some(tid) = create_user_task(elf_info.entry, elf_info.pml4, elf_info.stack_top) {
                        serial::write_str("TASK: created user task ");
                        serial::write_dec(tid);
                        serial::write_str(" entry=0x");
                        serial::write_hex(elf_info.entry);
                        serial::write_str("\n");
                    }
                }
                Err(e) => {
                    serial::write_str("TASK: ELF load failed: ");
                    serial::write_str(e);
                    serial::write_str("\n");
                }
            }
        }
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

    serial::write_str("TASK: switching to task 1...\n");

    // Dequeue task 1 so it's not in the runqueue twice
    remove_from_runqueue(1);

    unsafe { core::arch::asm!("sti"); }

    let new_task = unsafe { &mut TASKS[task_idx(1)] };
    new_task.state = TaskState::Running;
    CURRENT_TASK.store(1, Ordering::SeqCst);
    pt_mgr().switch_to(new_task.pml4);
    unsafe {
        let old_ptr = &mut TASKS[0].regs as *mut Registers;
        let new_ptr = &new_task.regs as *const Registers;
        serial::write_str("  dbg_init: oldp=0x");
        serial::write_hex(old_ptr as u64);
        serial::write_str(" newp=0x");
        serial::write_hex(new_ptr as u64);
        serial::write_str(" cs=0x");
        serial::write_hex((*new_ptr).cs);
        serial::write_str(" ss=0x");
        serial::write_hex((*new_ptr).ss);
        serial::write_str(" rsp=0x");
        serial::write_hex((*new_ptr).rsp);
        serial::write_str(" rip=0x");
        serial::write_hex((*new_ptr).rip);
        serial::write_str("\n");
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
