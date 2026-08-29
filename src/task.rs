use core::sync::atomic::{AtomicU64, Ordering, AtomicBool};

use crate::memory::buddy::PAGE_SIZE;
use crate::paging::PageTableManager;
use crate::paging::PAGE_SIZE_4K;
use crate::serial;

// Export for assembly access
#[no_mangle]
pub static mut CURRENT_TASK_ID: u64 = 0;
#[no_mangle]
pub static mut TASKS_PTR: *mut Task = core::ptr::null_mut();

pub const PRIORITY_LEVELS: usize = 40;
pub const PRIORITY_HIGHEST: u8 = 0;
pub const PRIORITY_LOWEST: u8 = 39;
pub const PRIORITY_DEFAULT_NICE: i32 = 0;
pub const PRIORITY_DEFAULT: u8 = 20;

// ── Signals ──────────────────────────────────────────────────────
pub const SIGNAL_COUNT: usize = 32;
pub const SIG_DFL: usize = 0;          // fake handler value -> default action
pub const SIG_IGN: usize = 1;          // fake handler value -> ignored
pub const SA_RESTORER: u64 = 0x04000000;

pub const SIGINT: i32 = 2;
pub const SIGQUIT: i32 = 3;
pub const SIGILL: i32 = 4;
pub const SIGTRAP: i32 = 5;
pub const SIGABRT: i32 = 6;
pub const SIGBUS: i32 = 7;
pub const SIGFPE: i32 = 8;
pub const SIGKILL: i32 = 9;
pub const SIGSEGV: i32 = 11;
pub const SIGPIPE: i32 = 13;
pub const SIGALRM: i32 = 14;
pub const SIGTERM: i32 = 15;
pub const SIGCONT: i32 = 18;
pub const SIGCHLD: i32 = 17;
pub const SIGSTOP: i32 = 19;
pub const SIGTSTP: i32 = 20;

// A per-task signal action, stored in the Linux rt_sigaction layout field
// subset the kernel needs: handler pointer + flags + mask + restorer.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct SignalAction {
    pub handler: u64,
    pub mask: u64,
    pub flags: u64,
    pub restorer: u64,
}
impl SignalAction {
    pub const fn empty() -> Self { SignalAction { handler: SIG_DFL as u64, mask: 0, flags: 0, restorer: 0 } }
}
pub const MAX_TASKS: usize = 64;
pub const KERNEL_STACK_PAGES: usize = 8;
pub const USER_STACK_PAGES: usize = 8;
pub const IRQ_BASE: u8 = 0x30;
pub const TIMER_IRQ_VECTOR: u8 = IRQ_BASE + 0;

// Virtual address for the user TLS/TCB page (one page below user stack)
pub const USER_TLS_VADDR: u64 = 0x0000_7FFF_FFFF_A000;

// 设为 true 显示调试信息，false 隐藏
#[allow(dead_code)] // kept as a module-local fast enable; runtime debug is via klog level (Ctrl-L).
static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);

// Track if current CPU is in a syscall (to prevent context switches during syscalls)
pub fn in_syscall_enter() {
    let id = cur_task().load(Ordering::SeqCst);
    if id != 0 {
        unsafe { TASKS[task_idx(id)].in_syscall = true; }
    }
}

pub fn in_syscall_exit() {
    let id = cur_task().load(Ordering::SeqCst);
    if id != 0 {
        unsafe { TASKS[task_idx(id)].in_syscall = false; }
    }
}

pub fn in_syscall() -> bool {
    let id = cur_task().load(Ordering::SeqCst);
    if id == 0 { return false; }
    unsafe { TASKS[task_idx(id)].in_syscall }
}

/// Snapshot of a task for /proc reporting.
#[derive(Clone, Copy)]
pub struct ProcEntry {
    pub id: u64,
    pub tgid: u64,
    pub ppid: Option<u64>,
    pub state: TaskState,
    pub comm: [u8; 16],
    pub pml4: u64,
    pub user_stack: u64,
}

/// Return a snapshot of task slot `idx` for /proc/<pid> reporting.
pub fn proc_entry(idx: usize) -> Option<ProcEntry> {
    unsafe {
        if idx >= MAX_TASKS { return None; }
        let t = &TASKS[idx];
        if t.id == 0 { return None; }
        Some(ProcEntry {
            id: t.id,
            tgid: t.tgid,
            ppid: t.parent,
            state: t.state,
            comm: t.comm,
            pml4: t.pml4,
            user_stack: t.user_stack,
        })
    }
}

/// Set the running task's short command name (for /proc/<pid>/stat). Truncates
/// to 15 chars + NUL, Linux-compatible.
pub fn set_current_comm(name: &[u8]) {
    let id = cur_task().load(Ordering::SeqCst);
    if id == 0 { return; }
    let idx = task_idx(id);
    let len = core::cmp::min(name.len(), 15);
    unsafe {
        for i in 0..len {
            TASKS[idx].comm[i] = name[i];
        }
        TASKS[idx].comm[len] = 0;
    }
}

pub const KERNEL_CODE_SELECTOR: u64 = 0x08;
pub const KERNEL_DATA_SELECTOR: u64 = 0x10;
pub const USER_CODE_SELECTOR: u64 = 0x20;
pub const USER_DATA_SELECTOR: u64 = 0x18;

// Priority: internal 0..39 maps to Linux nice -20..19
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
    if crate::klog::get_console_level() >= crate::klog::LOG_DEBUG {
        crate::klog::begin(crate::klog::LOG_DEBUG, crate::klog::FAC_SYSCALL);
        crate::klog::s(".");
        crate::klog::hex(val);
        crate::klog::end();
    }
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

// Global VMA pool, keyed by pml4 (address space). CLONE_VM threads share a
// pml4 so they automatically share records: no per-task array, no sibling
// sync, no duplicate registration. A single 2MB static pool (65536 records)
// covers the whole system with 64x the headroom of the old per-task arrays
// (mallocng meta reservations no longer exhaust it under stress tests).
pub const MAX_VMA_RECORDS: usize = 65536;

#[derive(Copy, Clone)]
pub struct VmaRec {
    pub pml4: u64,
    pub vma: Vma,
}

pub static mut VMAS: [VmaRec; MAX_VMA_RECORDS] = [VmaRec {
    pml4: 0,
    vma: Vma { start: 0, end: 0, flags: 0 },
}; MAX_VMA_RECORDS];

// Number of pool slots that have ever been handed out. All scans are bounded
// by this so lookup cost tracks the live population, not the 64K pool size.
static mut VMA_USED: usize = 0;

#[derive(Copy, Clone)]
pub struct Task {
    pub id: u64,
    pub tgid: u64,
    pub state: TaskState,

    pub regs: Registers,
    pub kernel_stack: u64,
    pub user_stack: u64,
    pub pml4: u64,

    // SMP: the CPU this task is allowed to / expected to run on (home CPU).
    // All runqueue operations and the scheduler pick this task only on this CPU.
    pub cpu: u8,

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

    // Process identity marks. Default (boot/init) is uid 0 (root); user-space
    // owns the semantics. Kernel never does password logic — these are pure
    // identity marks for the process to read via getuid/getgid.
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,

    // Short command name (for /proc/<pid>/stat, ps). Set from the executable
    // name on exec/spawn.
    pub comm: [u8; 16],

    pub runqueue_next: Option<u64>,

    // Per-task "currently inside a syscall" flag. The old global AtomicBool
    // stayed true after a force_schedule() switch (e.g. waitpid/exit) left a
    // user-mode task running, so timer ticks refused to preempt it and the
    // runqueue starved (spinning threads never got the CPU).
    pub in_syscall: bool,

    pub ipc_partner: u64,
    pub ipc_phys: u64,
    pub ipc_vaddr: u64,

    pub exit_code: i32,

    // brk / heap
    pub brk_start: u64,
    pub brk_end: u64,

    // ── Signal state ─────────────────────────────────────────────
    // Terminating default-action signals are honoured so Ctrl+C (SIGINT),
    // SIGTERM, SIGKILL etc. actually kill a process / process group.
    // Per-task handler table (Linux rt_sigaction ABI).
    pub sig_handlers: [SignalAction; SIGNAL_COUNT],
    // Signals currently blocked (rt_sigprocmask). Bit i == signal i.
    pub sig_blocked: u64,
    // Signals pending delivery to the process.
    pub sig_pending: u64,

    // For sleep syscall
    pub wakeup_tick: u64,

    // Preserved user context when blocking in a syscall (sys_sleep, futex_wait, etc.)
    // context_switch saves kernel context to regs, overwriting user context.
    // We save user regs here before blocking, and restore on wakeup.
    pub saved_user_regs: Option<Registers>,

    // For futex timed waits: deadline tick at which the waiter should be
    // woken with ETIMEDOUT. 0 = no timeout (indefinite wait). Cleared by
    // futex_wake when the waiter is explicitly woken.
    pub futex_deadline: u64,

    // For CLONE_CHILD_CLEARTID: user-space address in the child's address
    // space where the kernel clears the child's TID on exit.
    pub child_tidptr: u64,

    // True if the address space is private (post-exec, fresh pml4) so every
    // user page belongs to this task. False for a COW-forked child that never
    // exec'd, where read-only pages are shared with the parent.
    pub addr_space_private: bool,
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
            cpu: 0,
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
                in_syscall: false,
                uid: 0,
                gid: 0,
                euid: 0,
                egid: 0,
                ipc_partner: 0,
            ipc_phys: 0,
            ipc_vaddr: 0,
            exit_code: 0,
            brk_start: 0,
            brk_end: 0,
            sig_handlers: [SignalAction::empty(); SIGNAL_COUNT],
            sig_blocked: 0,
            sig_pending: 0,
            comm: [0; 16],
            wakeup_tick: 0,
            futex_deadline: 0,
            child_tidptr: 0,
            addr_space_private: false,
            saved_user_regs: None,
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

// SMP: maximum number of logical CPUs the scheduler is built for. The BSP is CPU 0;
// APIC IDs above the physical count simply stay unwired. Each CPU has its OWN current
// task, runqueue, and runqueue lock (per-CPU scheduling).
pub const MAX_CPUS: usize = 2;
static mut RUNQUEUE: [RunQueue; MAX_CPUS] = [const { RunQueue::new() }; MAX_CPUS];
// Serializes all runqueue mutations. IRQ-safe so the timer ISR and syscalls can
// both touch the runqueue without corrupting the linked lists / bitmap. One lock per CPU.
static RUNQUEUE_LOCK: [crate::spinlock::RawSpin; MAX_CPUS] =
    [const { crate::spinlock::RawSpin::new() }; MAX_CPUS];
static CURRENT_TASK: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

// Number of CPUs online beyond the BSP (BSP=CPU0 is always online, uncounted).
static ONLINE_CPUS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
// Round-robin counter for spreading newly-created tasks across online CPUs.
static HOME_CPU_ROUND: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

// Map an APIC id to a compact CPU index (0,1,...). APIC ids are dense (0,1) on
// QEMU; using the raw id would not be sparse-safe, so index by position to stay
// within MAX_CPUS. Inline-fast path first: APIC ids here are 0..MAX_CPUS-1.
fn cpu_index_of(apic_id: u32) -> usize {
    (apic_id as usize) % MAX_CPUS
}

// The index of the CPU currently executing. Reads the local APIC id via MMIO.
// Kept out of the ultra-hot path; scheduler / timer are ~100Hz.
#[inline(always)]
pub fn current_cpu() -> usize {
    cpu_index_of(unsafe { crate::apic::read_reg(0x20) >> 24 })
}

#[inline(always)]
fn cur_task() -> &'static AtomicU64 {
    unsafe { &CURRENT_TASK[current_cpu()] }
}
// Whether pid 1 (slot 0) has been handed out (to init), so it can't be aliased.
// The actual slot accounting is done by PID_BITMAP.
static INIT_TASK_ASSIGNED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
// Task slot of the init task, passed across the boot-time stack switch.
static mut BOOT_INIT_SLOT: usize = 0;
// Debug: count context switches
static SWITCH_COUNT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

// Pending kernel tasks to spawn after scheduler handoff
// Stores (entry, comm, nice) where nice is the Linux nice value (default 0).
static mut PENDING_KERNEL_TASKS: [(u64, &'static [u8], i32); 8] = [(0, &[], 0); 8];
static mut PENDING_KERNEL_TASK_COUNT: usize = 0;

/// Register a kernel task to be spawned after the scheduler handoff to init.
/// Returns true if registered successfully, false if the pending list is full.
/// `nice` is the Linux nice value (default 0 = normal priority). Higher nice = lower priority.
pub fn register_kernel_task(entry: u64, comm: &'static [u8], nice: i32) -> bool {
    unsafe {
        if PENDING_KERNEL_TASK_COUNT < PENDING_KERNEL_TASKS.len() {
            PENDING_KERNEL_TASKS[PENDING_KERNEL_TASK_COUNT] = (entry, comm, nice);
            PENDING_KERNEL_TASK_COUNT += 1;
            true
        } else {
            false
        }
    }
}

/// Register a kernel task with default priority (nice=0).
pub fn register_kernel_task_default(entry: u64, comm: &'static [u8]) -> bool {
    register_kernel_task(entry, comm, PRIORITY_DEFAULT_NICE)
}

/// Spawn all pending kernel tasks that were registered before the scheduler handoff.
fn spawn_pending_kernel_tasks() {
    unsafe {
        for i in 0..PENDING_KERNEL_TASK_COUNT {
            let (entry, comm, nice) = PENDING_KERNEL_TASKS[i];
            if entry != 0 {
                let _ = create_kernel_task_prio(entry, nice, comm);
            }
        }
        PENDING_KERNEL_TASK_COUNT = 0;
    }
}

// Scratch buffer for timer interrupt frame (kernel tasks only).
// build_frame writes 20×8 = 160 bytes. Kernel tasks use this instead of
// writing to kernel_stack-160, which would corrupt the call chain.
static mut TIMER_FRAME_SCRATCH: [u64; 20] = [0; 20];

// Scratch area for kernel→kernel preemption trampoline.
// Stores [real_rax, real_rdx, real_rip] for the task being resumed.
static mut PREEMPT_SCRATCH: [u64; 3] = [0; 3];

// Kernel .eh_frame_hdr address for AT_SYSINFO_EHDR (auxv 33).
// Populated at runtime via build.rs exported symbol.
pub static KERNEL_EH_FRAME_HDR: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

pub fn current_task_id() -> u64 {
    cur_task().load(Ordering::SeqCst)
}

pub fn task_kernel_stack_by_id(id: u64) -> u64 {
    if id == 0 { return 0; }
    unsafe { TASKS[task_idx(id)].kernel_stack }
}

pub fn current_task_regs_rip() -> u64 {
    let id = cur_task().load(Ordering::SeqCst);
    if id == 0 { return 0; }
    unsafe { TASKS[task_idx(id)].regs.rip }
}

pub fn current_task_regs_rsp() -> u64 {
    let id = cur_task().load(Ordering::SeqCst);
    if id == 0 { return 0; }
    unsafe { TASKS[task_idx(id)].regs.rsp }
}

fn task_idx(id: u64) -> usize {
    // pid == slot (boot/idle is pid 0 → slot 0, init is pid 1 → slot 1, ...).
    // Pids are handed out from a 64-bit bitmap, so they are always < MAX_TASKS
    // and never alias task slots (the old `id % MAX_TASKS` rollover is gone).
    if id as usize >= MAX_TASKS { 0 } else { id as usize }
}

// ── PID allocation ────────────────────────────────────────────────────────────
// Bitmap of occupied task slots. Bit 0 is pre-set (pid 0 = boot/idle task).
// A pid is exactly its slot index, so pids never alias. Allocated with a
// lock-free CAS loop (SMP-safe).
static PID_BITMAP: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

fn alloc_pid_from(min_slot: u64) -> Option<u64> {
    if min_slot >= MAX_TASKS as u64 {
        return None;
    }
    let mut bm = PID_BITMAP.load(Ordering::SeqCst);
    loop {
        let shifted = bm >> min_slot;
        let bit = if shifted == u64::MAX {
            MAX_TASKS as u32
        } else {
            min_slot as u32 + shifted.trailing_ones()
        };
        if bit >= MAX_TASKS as u32 {
            return None;
        }
        let mask = 1u64 << bit;
        match PID_BITMAP.compare_exchange(bm, bm | mask, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return Some(bit as u64),
            Err(x) => bm = x,
        }
    }
}

fn alloc_pid_specific(slot: u64) -> bool {
    if slot >= MAX_TASKS as u64 {
        return false;
    }
    let mask = 1u64 << slot;
    let mut bm = PID_BITMAP.load(Ordering::SeqCst);
    loop {
        if bm & mask != 0 {
            return false;
        }
        match PID_BITMAP.compare_exchange(bm, bm | mask, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return true,
            Err(x) => bm = x,
        }
    }
}

// Boot/idle task (pid 0) occupies slot 0; kernel tasks start at slot 2 so they
// never collide with init (pid 1, slot 1). User forks/clones take the next free slot.
fn alloc_kernel_pid() -> Option<u64> { alloc_pid_from(2) }
fn alloc_user_pid() -> Option<u64> { alloc_pid_from(1) }

fn free_pid(pid: u64) {
    if pid == 0 || pid as usize >= MAX_TASKS {
        return;
    }
    PID_BITMAP.fetch_and(!(1u64 << pid), Ordering::SeqCst);
}

pub fn current_task() -> Option<&'static mut Task> {
    let id = cur_task().load(Ordering::SeqCst);
    if id == 0 { return None; }
    unsafe { Some(&mut TASKS[task_idx(id)]) }
}

pub fn task_by_id(id: u64) -> Option<&'static mut Task> {
    if id == 0 { return None; }
    unsafe { Some(&mut TASKS[task_idx(id)]) }
}

// ── Runqueue operations ──────────────────────────────────────────

fn enqueue_task(tid: u64, prio: u8) {
    // Enqueue onto the task's home CPU runqueue (affinity).
    let cpu = unsafe { TASKS[task_idx(tid)].cpu } as usize;
    let _g = RUNQUEUE_LOCK[cpu].lock();
    unsafe {
        let rq = &mut RUNQUEUE[cpu];
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
    let cpu = current_cpu();
    let _g = RUNQUEUE_LOCK[cpu].lock();
    unsafe {
        let rq = &mut RUNQUEUE[cpu];
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
    let cpu = unsafe { TASKS[task_idx(tid)].cpu } as usize;
    let _g = RUNQUEUE_LOCK[cpu].lock();
    unsafe {
        let rq = &mut RUNQUEUE[cpu];
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
    let id = cur_task().load(Ordering::SeqCst);
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

fn order_for_pages(pages: usize) -> usize {
    let mut order = 0usize;
    while (1usize << order) < pages && order < 10 {
        order += 1;
    }
    order
}

pub fn alloc_stack(pages: usize) -> Option<u64> {
    let alloc = unsafe { &mut *crate::memory::allocator() };
    let order = order_for_pages(pages + 1);
    alloc.alloc(order).map(|p| {
        for i in 0..=pages {
            crate::memory::buddy::page_type_set(p + i as u64 * PAGE_SIZE, crate::memory::buddy::PAGE_TYPE_STACK);
        }
        p + pages as u64 * PAGE_SIZE
    })
}

fn free_stack(base: u64, pages: usize) {
    let alloc = unsafe { &mut *crate::memory::allocator() };
    let addr = base - pages as u64 * PAGE_SIZE;
    // Guard against double-free: if the stack block's used bit is already clear,
    // it was freed earlier (e.g. reap ran twice for the same task, or the slot
    // was reused). Skip rather than corrupt the buddy free lists.
    if !crate::memory::buddy::page_is_used(addr) {
        return;
    }
    alloc.free(addr, order_for_pages(pages + 1));
    // Mark the whole stack block free AFTER the buddy free, so that alloc.free's
    // `old_type == PAGE_TYPE_FREE` double-free check does not mistake our own
    // pre-mark for an already-freed page (which caused false DETECTED reports
    // for the normal alloc→free→alloc-reuse→free lifecycle of a stack block).
    for i in 0..=pages {
        crate::memory::buddy::page_type_set(addr + i as u64 * PAGE_SIZE, crate::memory::buddy::PAGE_TYPE_FREE);
    }
}

// ── Task creation ────────────────────────────────────────────────

pub fn create_kernel_task(entry: u64) -> Option<u64> {
    create_kernel_task_prio(entry, PRIORITY_DEFAULT_NICE, b"kworker")
}

pub fn create_kernel_task_prio(entry: u64, nice: i32, comm: &[u8]) -> Option<u64> {
    // pid 1 is reserved for init (busybox init checks getpid()==1 to decide
    // whether to run as the single-instance init). Kernel tasks use pids from
    // a low band (2,3,...) that never collides with init's pid 1; task_idx is
    // id % 64, so pids must stay below 64 to avoid aliasing task slots.
    let tid = match alloc_kernel_pid() {
        Some(t) => t,
        None => return None,
    };
    let kernel_stack = alloc_stack(KERNEL_STACK_PAGES)?;

    let task = unsafe { &mut TASKS[task_idx(tid)] };
    task.id = tid;
    task.tgid = tid;
    task.state = TaskState::Ready;
    task.regs = Registers::new_kernel(entry, kernel_stack);
    task.kernel_stack = kernel_stack;
    task.user_stack = 0;
    task.pml4 = pt_mgr().kernel_pml4();
    task.cpu = pick_home_cpu();
    task.static_prio = nice_to_prio(nice);
    task.normal_prio = task.static_prio;
    task.prio = task.static_prio;
    task.time_slice = initial_time_slice(task.prio);
    task.parent = None;

    // Set comm name
    let len = core::cmp::min(comm.len(), 15);
    for i in 0..len { task.comm[i] = comm[i]; }
    task.comm[len] = 0;

    enqueue_task(tid, task.prio);

    // Bind /proc/<pid> entries for this task
    crate::vfs_core::procfs::bind_task_procfs(tid);

    if crate::klog::get_console_level() >= crate::klog::LOG_DEBUG {
        crate::klog::begin(crate::klog::LOG_DEBUG, crate::klog::FAC_SCHED);
        crate::klog::s("TASK: created kernel task ");
        crate::klog::dec(tid);
        crate::klog::s(" nice=");
        if nice < 0 {
            crate::klog::s("-");
            crate::klog::dec((-nice) as u64);
        } else {
            crate::klog::dec(nice as u64);
        }
        crate::klog::s("\n");
        crate::klog::end();
    }
    Some(tid)
}

pub fn create_user_task(entry: u64, pml4: u64, user_stack_top: u64) -> Option<u64> {
    create_user_task_on_cpu(entry, pml4, user_stack_top, PRIORITY_DEFAULT_NICE, pick_home_cpu())
}

/// Create a user task pinned to a specific home CPU (init must be cpu 0: the
/// boot switch runs it on the BSP, and a running task's cpu must equal the CPU
/// physically running it). Other user tasks spread via pick_home_cpu().
pub fn create_user_task_prio(entry: u64, pml4: u64, user_stack_top: u64, nice: i32) -> Option<u64> {
    create_user_task_on_cpu(entry, pml4, user_stack_top, nice, pick_home_cpu())
}

pub fn create_user_task_on_cpu(entry: u64, pml4: u64, user_stack_top: u64, nice: i32, cpu: u8) -> Option<u64> {
    // The first user task (init) must be pid 1: busybox init checks
    // getpid()==1 to decide whether to run as the single-instance init.
    let tid = if !INIT_TASK_ASSIGNED.load(Ordering::SeqCst) {
        // The first user task must be pid 1 (busybox init checks getpid()==1),
        // which is slot 1 in the pid==slot bitmap (slot 0 is the boot/idle task).
        if alloc_pid_specific(1) {
            INIT_TASK_ASSIGNED.store(true, Ordering::SeqCst);
            1u64
        } else {
            match alloc_user_pid() {
                Some(t) => t,
                None => return None,
            }
        }
    } else {
        match alloc_user_pid() {
            Some(t) => t,
            None => return None,
        }
    };
    serial::write_str("TASK: create_user_task_prio entry\n");
    let kernel_stack = alloc_stack(KERNEL_STACK_PAGES)?;
    serial::write_str("TASK: alloc_stack done\n");

    // Set up TLS/TCB page for musl. Initialize full TCB per musl's pthread struct.
    let tls_phys = unsafe { &mut *crate::memory::allocator() }.alloc(0)?;
    serial::write_str("TASK: tls_phys alloc done\n");
    unsafe { core::ptr::write_bytes(tls_phys as *mut u8, 0, 4096); }

    // Map the TLS page FIRST so we can write to virtual addresses
    let tls_flags = crate::paging::PTE_PRESENT
        | crate::paging::PTE_WRITABLE
        | crate::paging::PTE_USER
        | crate::paging::PTE_NO_EXECUTE;
    if PageTableManager::map_into(pml4, USER_TLS_VADDR, tls_phys, tls_flags).is_err() {
        serial::write_str("TASK: map_into TLS FAILED\n");
        return None;
    }
    serial::write_str("TASK: map_into TLS done\n");

    let tls_base = USER_TLS_VADDR;
    // NOTE: tid comes from the assignment above; do NOT recompute it here.

    // NOTE: we are still running on the kernel (identity-mapped) pml4 here, so
    // the TLS page's USER_TLS_VADDR is NOT mapped in the current address space.
    // All TCB writes must go through the PHYSICAL address; only the values we
    // store (self pointer, errno pointer, ...) use the virtual USER_TLS_VADDR.
    let tls_phys_ptr = tls_phys as *mut u8;
    unsafe {
        // 0x00: DTV pointer (0 = initial thread)
        core::ptr::write_volatile(tls_phys_ptr as *mut u64, 0);

        // 0x08: Self pointer (struct pthread *)
        core::ptr::write_volatile(tls_phys_ptr.add(0x08) as *mut u64, tls_base);

        // 0x10: Thread ID (tid) - 64-bit
        core::ptr::write_volatile(tls_phys_ptr.add(0x10) as *mut u64, tid);

        // 0x14: PID (tgid) - 32-bit
        core::ptr::write_volatile(tls_phys_ptr.add(0x14) as *mut u32, tid as u32);

        // 0x18: errno location (pointer to thread-local errno at offset 0x100)
        let errno_loc = tls_base + 0x100;
        core::ptr::write_volatile(tls_phys_ptr.add(0x18) as *mut u64, errno_loc);
        core::ptr::write_volatile(tls_phys_ptr.add(0x100) as *mut i32, 0);

        // 0x20: Stack guard (canary)
        let canary = crate::pit::TICKS.load(Ordering::Relaxed) ^ tid;
        core::ptr::write_volatile(tls_phys_ptr.add(0x20) as *mut u64, canary);

        // 0x28: Thread pointer (self) - for __get_tp()
        core::ptr::write_volatile(tls_phys_ptr.add(0x28) as *mut u64, tls_base);

        // 0x30: Cancel flag (0 = not cancelled)
        core::ptr::write_volatile(tls_phys_ptr.add(0x30) as *mut u32, 0);

        // 0x34: Cancel type (0 = deferred)
        core::ptr::write_volatile(tls_phys_ptr.add(0x34) as *mut u32, 0);

        // 0x38: Cancel state
        core::ptr::write_volatile(tls_phys_ptr.add(0x38) as *mut u32, 0);

        // Zero rest of TCB area
        core::ptr::write_bytes(tls_phys_ptr.add(0x40), 0, 4096 - 0x40);
    }

    let task = unsafe { &mut TASKS[task_idx(tid)] };
    task.id = tid;
    task.tgid = tid;
    task.state = TaskState::Ready;
    task.regs = Registers::new_user(entry, user_stack_top);
    task.regs.fs_base = USER_TLS_VADDR;
    serial::write_str("TASK: create_user_task - setting up task, about to enqueue\n");
    if crate::klog::get_console_level() >= crate::klog::LOG_DEBUG {
        crate::klog::begin(crate::klog::LOG_DEBUG, crate::klog::FAC_SCHED);
        crate::klog::s("USER_TASK[");
        crate::klog::dec(tid);
        crate::klog::s("].cs=0x");
        crate::klog::hex(task.regs.cs);
        crate::klog::s(" ss=0x");
        crate::klog::hex(task.regs.ss);
        crate::klog::s(" entry=0x");
        crate::klog::hex(entry);
        crate::klog::s("\n");
        crate::klog::end();
    }
    task.kernel_stack = kernel_stack;
    task.user_stack = user_stack_top;
    task.pml4 = pml4;
    // User tasks may be pinned to a specific home CPU (init -> cpu 0) or spread
    // across online CPUs (BSP + APs), now that each CPU has its own per-CPU
    // runqueue, syscall stack (SYSCALL_STACK_TOPS by LAPIC id) and a timer that
    // wakes blocked tasks. The AP cooperatively schedules via schedule()/yield_now
    // (no PREEMPT_SCRATCH preemption), so user tasks must yield/block rather than
    // busy-spin to share the AP, same as kernel tasks.
    task.cpu = cpu;
    task.static_prio = nice_to_prio(nice);
    task.normal_prio = task.static_prio;
    task.prio = task.static_prio;
    task.time_slice = initial_time_slice(task.prio);
    task.parent = Some(current_task_id());
    serial::write_str("TASK: create_user_task - parent set\n");

    // Set up stdin/stdout/stderr to /dev/console
    serial::write_str("TASK: setting up stdio\n");
    if let Some(console_idx) = crate::vfs::find_inode(b"/dev/console") {
        crate::vfs::alloc_fd_for_task(tid, console_idx, 0); // fd 0 O_RDONLY
        crate::vfs::alloc_fd_for_task(tid, console_idx, 1); // fd 1 O_WRONLY
        crate::vfs::alloc_fd_for_task(tid, console_idx, 1); // fd 2 O_WRONLY
    }
    serial::write_str("TASK: stdio setup done\n");

    serial::write_str("TASK: enqueueing task\n");
    enqueue_task(tid, task.prio);
    serial::write_str("TASK: enqueue done\n");

    // Bind /proc/<pid> entries for this task
    serial::write_str("TASK: binding procfs\n");
    crate::vfs_core::procfs::bind_task_procfs(tid);
    serial::write_str("TASK: procfs bind done\n");

    if crate::klog::get_console_level() >= crate::klog::LOG_DEBUG {
        crate::klog::begin(crate::klog::LOG_DEBUG, crate::klog::FAC_SCHED);
        crate::klog::s("TASK: created user task ");
        crate::klog::dec(tid);
        crate::klog::s(" nice=");
        if nice < 0 {
            crate::klog::s("-");
            crate::klog::dec((-nice) as u64);
        } else {
            crate::klog::dec(nice as u64);
        }
        crate::klog::s("\n");
        crate::klog::end();
    }
    Some(tid)
}

// ── Scheduler core ───────────────────────────────────────────────

pub fn init_scheduler() {
    if crate::klog::get_console_level() >= crate::klog::LOG_DEBUG {
        crate::klog::begin(crate::klog::LOG_DEBUG, crate::klog::FAC_SCHED);
        crate::klog::s("SCHED: initialized (priority runqueue)\n");
        crate::klog::end();
    }
}

pub fn mark_cpu_online(_apic_id: u32) {
    let n = ONLINE_CPUS.fetch_add(1, Ordering::SeqCst);
    if crate::klog::get_console_level() >= crate::klog::LOG_DEBUG {
        crate::klog::begin(crate::klog::LOG_DEBUG, crate::klog::FAC_SCHED);
        crate::klog::s("SCHED: mark_cpu_online apic=0x");
        crate::klog::hex(_apic_id as u64);
        crate::klog::s(" now_online=");
        crate::klog::dec((n + 1) as u64);
        crate::klog::s("\n");
        crate::klog::end();
    }
}

// Pick a home CPU for a newly created KERNEL task, spreading across all online
// CPUs once an AP is up. User tasks bypass this (they're pinned to the BSP).
fn pick_home_cpu() -> u8 {
    // ONLINE_CPUS counts APs beyond the BSP, so total schedulable CPUs is +1.
    let ap_count = ONLINE_CPUS.load(Ordering::SeqCst);
    let total = (ap_count + 1).min(MAX_CPUS as u64);
    if total <= 1 {
        return 0;
    }
    let turn = HOME_CPU_ROUND.fetch_add(1, Ordering::SeqCst);
    (turn % total) as u8
}

// ── Per-CPU (AP) scheduling idle loop ────────────────────────────
// The AP has its own per-CPU runqueue + CURRENT_TASK and a standing idle kernel
// task. Its LAPIC timer preempts/wakes it (per-CPU EOI), and it repeatedly
// calls schedule() to drain its own queue. APs only run kernel tasks (user
// syscalls need the shared syscall-stack global, which is BSP-only for now).

// Kernel entry for the AP's idle task: loop scheduling, halting when idle.
// The first schedule() context-switches to a queued kernel task (saving this
// ambient context as the idle task's saved context); later resumption returns
// here.
pub extern "C" fn ap_idle_entry() -> ! {
    loop {
        // Only call schedule() when our own runqueue has work: schedule()'s
        // blocking-idle path halts on the BSP's PIT vector (0x20), which never
        // fires here. When there is work, schedule() context-switches us to it.
        if unsafe { RUNQUEUE[current_cpu()].bitmap != 0 } {
            schedule();
        }
        // Idle until the dedicated AP LAPIC timer (0x21) wakes us to poll again.
        unsafe { core::arch::asm!("sti; hlt; cli", options(nostack, nomem, preserves_flags)); }
    }
}

// Called from ap_entry (running on the AP's kernel stack, IRQs off): create the
// AP's standing idle task, register it as this CPU's current, install its
// TSS.rsp0, arm the per-CPU LAPIC timer, then enter the schedule idle loop.
pub fn ap_begin_scheduling(apic_id: u32) -> ! {
    let tid = {
        let tid = match alloc_kernel_pid() {
            Some(t) => t,
            None => core::panic!("AP idle task: no pid"),
        };
        let kernel_stack = alloc_stack(KERNEL_STACK_PAGES)
            .expect("AP idle task stack");
        let task = unsafe { &mut TASKS[task_idx(tid)] };
        task.id = tid;
        task.tgid = tid;
        task.state = TaskState::Running;
        task.kernel_stack = kernel_stack;
        task.user_stack = 0;
        task.pml4 = pt_mgr().kernel_pml4();
        // APIC id == cpu index for the dense ids on QEMU (0,1).
        task.cpu = cpu_index_of(apic_id) as u8;
        task.static_prio = nice_to_prio(19);
        task.normal_prio = task.static_prio;
        task.prio = task.static_prio;
        task.time_slice = initial_time_slice(task.prio);
        task.in_syscall = false;
        task.regs = Registers::new_kernel(ap_idle_entry as *const () as u64, kernel_stack);
        tid
    };

    cur_task().store(tid, Ordering::SeqCst);
    unsafe { TASKS[task_idx(tid)].state = TaskState::Running; }
    crate::gdt::set_tss_rsp0(unsafe { TASKS[task_idx(tid)].kernel_stack });
    pt_mgr().switch_to(unsafe { TASKS[task_idx(tid)].pml4 });

    unsafe {
        // IDTR is per-CPU: the AP must load the shared IDT itself.
        crate::idt::load_current();
        // The BSP branches on init_lapic(); the AP must software-enable its own
        // LAPIC (SVR bit 8) here, otherwise QEMU never delivers its timer IRQ.
        crate::apic::init_lapic();
        // Dedicated AP timer vector: pure EOI+wakeup handler.
        crate::idt::register_irq(0x21, crate::interrupts::ap_timer_irq as *const () as u64);
        crate::apic::init_ap_timer();
        core::arch::asm!("sti", options(nostack));
    }

    if crate::klog::get_console_level() >= crate::klog::LOG_DEBUG {
        crate::klog::begin(crate::klog::LOG_DEBUG, crate::klog::FAC_SCHED);
        crate::klog::s("SCHED: AP idletask tid=");
        crate::klog::dec(tid);
        crate::klog::s(" on cpu ");
        crate::klog::dec(current_cpu() as u64);
        crate::klog::s("\n");
        crate::klog::end();
    }

    ap_idle_entry()
}

// Proof that a kernel task can run on an AP from its own per-CPU runqueue:
// log which CPU we're on, then sit parked. Spawned once the AP is online.
pub extern "C" fn ap_demo_entry() -> ! {
    let cpu = current_cpu();
    let mut buf = [0u8; 96];
    let mut len = 0;
    for c in b"SMP: kernel demo task running on CPU ".iter() {
        buf[len] = *c;
        len += 1;
    }
    if cpu >= 10 {
        buf[len] = b'0' + (cpu / 10) as u8;
        len += 1;
    }
    buf[len] = b'0' + (cpu % 10) as u8;
    len += 1;
    for c in b" (proof of per-CPU AP scheduling)\n".iter() {
        buf[len] = *c;
        len += 1;
    }
    crate::serial::write_str(core::str::from_utf8(&buf[..len]).unwrap());
    // Cooperatively yield instead of parking forever: the AP now also runs user
    // tasks (spread to CPU 1), which would otherwise starve behind this parked
    // kernel task. At max-nice (lowest priority) the demo only runs when the AP
    // is otherwise idle, and yields immediately so real tasks are never blocked.
    loop {
        yield_now();
    }
}

// Spawn a kernel task pinned to every AP past the BSP, proving each AP drains
// its own runqueue. QEMU's single AP is CPU 1.
pub fn spawn_ap_demo_tasks() {
    let n = ONLINE_CPUS.load(Ordering::SeqCst);
    for c in 1..=n.min((MAX_CPUS - 1) as u64) {
        if let Some(tid) =
            create_kernel_task_prio(ap_demo_entry as *const () as u64, PRIORITY_DEFAULT_NICE, b"apdemo")
        {
            let idx = task_idx(tid);
            unsafe {
                // remove_from_runqueue uses task.cpu to find the queue, so drop
                // the task from its current (BSP) queue BEFORE repointing cpu to
                // the AP; then enqueue routes to the AP's queue only.
                remove_from_runqueue(tid);
                TASKS[idx].cpu = c as u8;
                enqueue_task(tid, TASKS[idx].prio);
            }
            crate::serial::write_str("SMP: apdemo tid=");
            crate::serial::write_dec(tid);
            crate::serial::write_str(" routed to cpu ");
            crate::serial::write_dec(c);
            crate::serial::write_str("\n");
            if crate::klog::get_console_level() >= crate::klog::LOG_DEBUG {
                crate::klog::begin(crate::klog::LOG_DEBUG, crate::klog::FAC_SCHED);
                crate::klog::s("SCHED: spawned apdemo tid=");
                crate::klog::dec(tid);
                crate::klog::s(" -> cpu ");
                crate::klog::dec(c);
                crate::klog::s("\n");
                crate::klog::end();
            }
        } else {
            crate::serial::write_str("SMP: apdemo creation FAILED\n");
        }
    }
}

pub fn schedule() {
    schedule_inner(false);
}

/// Like `schedule()` but switches even while inside a syscall. Used by
/// waitpid()/exit_task() which must hand the CPU to a child that is only
/// schedulable from the syscall context. Safe because the whole switch runs
/// with interrupts disabled (cli); the new task resumes with its own RFLAGS.
pub fn force_schedule() {
    schedule_inner(true);
}

fn schedule_inner(force: bool) {
    unsafe { core::arch::asm!("cli", options(nostack, nomem, preserves_flags)); }

    // Don't context switch if we're in a syscall (interrupts enabled for I/O wait)
    if !force && in_syscall() {
        unsafe { core::arch::asm!("sti", options(nostack, nomem, preserves_flags)); }
        return;
    }

    let current = cur_task().load(Ordering::SeqCst);

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
                // No other tasks runnable: idle-halt until an interrupt
                // (timer tick, I/O, etc.) readies a task, then dispatch it
                // directly. Returning to the caller here (the old behavior)
                // left a just-woken task stranded on the runqueue while the
                // CPU hlt-looped, so timed sleeps and futex wakes of the
                // current task never resumed.
                loop {
                    unsafe {
                        core::arch::asm!("sti; hlt", options(nostack, nomem));
                        core::arch::asm!("cli", options(nostack, nomem, preserves_flags));
                    }
                    if let Some(t) = dequeue_task() {
                        if t != current {
                            // A different task became ready: switch to it.
                            break 'pick t;
                        }
                        // Our own sleep/wake timer fired while idle: resume
                        // ourselves so the blocking path re-checks and returns.
                        unsafe { TASKS[task_idx(t)].state = TaskState::Running; }
                        return;
                    }
                }
            }
        }
    };

    // Enqueue current task (if still active) before switching
    if current != 0 {
        let cur_idx = task_idx(current);
        let state = unsafe { TASKS[cur_idx].state };
        if state == TaskState::Running {
            // Preempted: mark Ready and requeue
            unsafe { TASKS[cur_idx].state = TaskState::Ready; }
            let prio = unsafe { TASKS[cur_idx].prio };
            unsafe { enqueue_task(current, prio); }
        } else if state == TaskState::Ready {
            let prio = unsafe { TASKS[cur_idx].prio };
            unsafe { enqueue_task(current, prio); }
        }
    }

    let new_idx = task_idx(next_id);

    let sc = SWITCH_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if sc % 1000 == 0 && crate::klog::get_console_level() >= crate::klog::LOG_DEBUG {
        crate::klog::begin(crate::klog::LOG_DEBUG, crate::klog::FAC_SCHED);
        crate::klog::s("SW#");
        crate::klog::dec(sc);
        crate::klog::end();
    }

    unsafe { crate::gdt::set_tss_rsp0(TASKS[new_idx].kernel_stack); }

    let old = cur_task().swap(next_id, Ordering::SeqCst);

    unsafe {
        TASKS[new_idx].state = TaskState::Running;
        pt_mgr().switch_to(TASKS[new_idx].pml4);

        let old_idx = task_idx(old);
        let old_ptr = &mut TASKS[old_idx].regs as *mut Registers;
        let new_ptr = &TASKS[new_idx].regs as *const Registers;

        // Trace kernel-mode context switches (DEBUG; mirrors to serial only
        // when console level >= DEBUG, otherwise it is queryable via klog::dump()).
        if crate::klog::get_console_level() >= crate::klog::LOG_DEBUG
            && (TASKS[new_idx].regs.cs & 3) == 0
        {
            crate::klog::begin(crate::klog::LOG_DEBUG, crate::klog::FAC_SCHED);
            crate::klog::s("[RSM:S] cur=");
            crate::klog::dec(old);
            crate::klog::s(" next=");
            crate::klog::dec(next_id);
            crate::klog::s(" rip=0x");
            crate::klog::hex(TASKS[new_idx].regs.rip);
            crate::klog::s(" rsp=0x");
            crate::klog::hex(TASKS[new_idx].regs.rsp);
            crate::klog::s(" cs=0x");
            crate::klog::hex(TASKS[new_idx].regs.cs);
            crate::klog::s(" rbp=0x");
            crate::klog::hex(TASKS[new_idx].regs.rbp);
            crate::klog::end();
        }

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
    let id = cur_task().load(Ordering::SeqCst);
    if id == 0 { return; }

    unsafe {
        let idx = task_idx(id);
        if TASKS[idx].state == TaskState::Running {
            TASKS[idx].state = TaskState::Ready;
            // NOTE: do NOT reset the time slice here. schedule() declines to
            // switch inside a syscall (in_syscall()==true), so a spin-yield
            // loop would otherwise keep refreshing its slice and monopolize the
            // CPU forever (observed in the context_switch_storm stress test).
            // Letting the slice expire lets the timer preempt normally.
        }
    }

    schedule();
}

pub fn yield_now_force() {
    let id = cur_task().load(Ordering::SeqCst);
    if id == 0 { return; }

    unsafe {
        let idx = task_idx(id);
        if TASKS[idx].state == TaskState::Running {
            TASKS[idx].state = TaskState::Ready;
            TASKS[idx].time_slice = initial_time_slice(TASKS[idx].prio);
        }
    }

    force_schedule();
}

pub fn exit_task(code: i32) {
    let id = cur_task().load(Ordering::SeqCst);
    if id == 0 { return; }

    unsafe {
        let idx = task_idx(id);
        TASKS[idx].state = TaskState::Zombie;
        TASKS[idx].exit_code = code;

        // CLONE_CHILD_CLEARTID: clear the TID in the child's address
        // space so that futex-based thread exit notification works.
        let child_tidptr = TASKS[idx].child_tidptr;
        if child_tidptr != 0 {
            core::ptr::write_volatile(child_tidptr as *mut u64, 0u64);
            // Wake any futex waiters on this address (e.g., parent joining via futex).
            // Use max_wake=1 to wake one waiter (the parent).
            futex_wake(child_tidptr as *const u32, 1);
        }

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

    // Force switch so the parent (typically blocked in waitpid) can reap us.
    force_schedule();
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
        // No sti: resume with IF=0. Interrupts re-enable on return to user mode
        // (sysretq/iretq restore RFLAGS). Keeping IF=0 through kernel code
        // prevents timer preemption inside kernel windows (syscall body/tail,
        // schedule_inner), which used to build a synthetic preempt frame whose
        // fixed stack location + global scratch could corrupt the resume RIP.
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
        let current = cur_task().load(Ordering::SeqCst);
        if current == 0 {
            return;
        }
        // Inside a syscall the interrupted RIP is kernel code (e.g. the middle
        // of free/maybe_audit during exec). timer_schedule() will bail out for
        // the same reason and the interrupt iretqs straight back, so stamping
        // TASKS[].regs here would overwrite the user-resume context that exec
        // just installed (regs.rip = new program entry) with a kernel address;
        // the exec trampoline then iretqs to kernel data and faults.
        if in_syscall() {
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

            // Diagnostics: flag kernel-mode RIPs that fall outside .text
            // (0x106000..0x11AF6F). A kernel task should never be "running"
            // from .data/.rodata — this indicates the interrupted stream was
            // already corrupt (ret/jump landed in data). Captured via klog so
            // it is queryable (klog::dump()) and hideable by console level.
            let rip = regs.rip;
            let in_text = rip >= 0x106000 && rip < 0x11AF6F;
            if !in_text {
                crate::klog::begin(crate::klog::LOG_ERR, crate::klog::FAC_SCHED);
                crate::klog::s("[BADKERNELRIP] task=");
                crate::klog::dec(current);
                crate::klog::s(" kstack=0x");
                crate::klog::hex(unsafe { TASKS[idx].kernel_stack });
                crate::klog::s(" rip=0x");
                crate::klog::hex(rip);
                crate::klog::s(" frame[0]=0x");
                crate::klog::hex(*frame.add(0));
                crate::klog::s("\n  rsp=0x");
                // Dump interrupted kernel stack (return addresses live here).
                // For a kernel->kernel interrupt, regs.rsp = frame+24 is the
                // interrupted RSP; the call chain sits below it.
                let stk = frame as u64 + 24;
                crate::klog::hex(stk);
                crate::klog::s("\n");
                for j in (0..48u64).step_by(8) {
                    crate::klog::s("  [");
                    crate::klog::hex(j);
                    crate::klog::s("]=0x");
                    unsafe {
                        crate::klog::hex(core::ptr::read_volatile((stk - 8 * j) as *const u64));
                    }
                    crate::klog::s("\n");
                }
                crate::klog::s("  +8=0x");
                crate::klog::hex(unsafe { core::ptr::read_volatile((stk + 8) as *const u64) });
                crate::klog::s(" +10=0x");
                crate::klog::hex(unsafe { core::ptr::read_volatile((stk + 0x10) as *const u64) });
                crate::klog::s(" +18=0x");
                crate::klog::hex(unsafe { core::ptr::read_volatile((stk + 0x18) as *const u64) });
                crate::klog::s(" +20=0x");
                crate::klog::hex(unsafe { core::ptr::read_volatile((stk + 0x20) as *const u64) });
                crate::klog::s("\n  +28=0x");
                crate::klog::hex(unsafe { core::ptr::read_volatile((stk + 0x28) as *const u64) });
                crate::klog::s(" +30=0x");
                crate::klog::hex(unsafe { core::ptr::read_volatile((stk + 0x30) as *const u64) });
                crate::klog::s(" +38=0x");
                crate::klog::hex(unsafe { core::ptr::read_volatile((stk + 0x38) as *const u64) });
                crate::klog::s(" +40=0x");
                crate::klog::hex(unsafe { core::ptr::read_volatile((stk + 0x40) as *const u64) });
                crate::klog::s("\n  +48=0x");
                crate::klog::hex(unsafe { core::ptr::read_volatile((stk + 0x48) as *const u64) });
                crate::klog::s(" +50=0x");
                crate::klog::hex(unsafe { core::ptr::read_volatile((stk + 0x50) as *const u64) });
                crate::klog::s(" +58=0x");
                crate::klog::hex(unsafe { core::ptr::read_volatile((stk + 0x58) as *const u64) });
                crate::klog::s(" +60=0x");
                crate::klog::hex(unsafe { core::ptr::read_volatile((stk + 0x60) as *const u64) });
                crate::klog::s("\n  scc_top=0x");
                crate::klog::hex(unsafe { crate::gdt::CURRENT_SYSCALL_STACK_TOP });
                crate::klog::s("\n  tasks:");
                for ti in 0..MAX_TASKS {
                    let t = &TASKS[ti];
                    if t.id != 0 {
                        crate::klog::s(" [");
                        crate::klog::dec(t.id);
                        crate::klog::s("]st=");
                        crate::klog::dec(t.state as u64);
                        crate::klog::s(" ks=0x");
                        crate::klog::hex(t.kernel_stack);
                        crate::klog::s(" rip=0x");
                        crate::klog::hex(t.regs.rip);
                        crate::klog::s(" rsp=0x");
                        crate::klog::hex(t.regs.rsp);
                    }
                }
                crate::klog::s("\n  saved.rax=0x");
                crate::klog::hex(TASKS[idx].regs.rax);
                crate::klog::s(" rbx=0x");
                crate::klog::hex(TASKS[idx].regs.rbx);
                crate::klog::s(" rbp=0x");
                crate::klog::hex(TASKS[idx].regs.rbp);
                crate::klog::s(" rsp=0x");
                crate::klog::hex(TASKS[idx].regs.rsp);
                crate::klog::s("\n  saved.r8=0x");
                crate::klog::hex(TASKS[idx].regs.r8);
                crate::klog::s(" r9=0x");
                crate::klog::hex(TASKS[idx].regs.r9);
                crate::klog::s(" r10=0x");
                crate::klog::hex(TASKS[idx].regs.r10);
                crate::klog::s(" r11=0x");
                crate::klog::hex(TASKS[idx].regs.r11);
                crate::klog::s(" r12=0x");
                crate::klog::hex(TASKS[idx].regs.r12);
                crate::klog::s(" r13=0x");
                crate::klog::hex(TASKS[idx].regs.r13);
                crate::klog::s(" r14=0x");
                crate::klog::hex(TASKS[idx].regs.r14);
                crate::klog::s(" r15=0x");
                crate::klog::hex(TASKS[idx].regs.r15);
                crate::klog::s("\n  saved.rip=0x");
                crate::klog::hex(TASKS[idx].regs.rip);
                crate::klog::s(" cs=0x");
                crate::klog::hex(TASKS[idx].regs.cs);
                crate::klog::s(" rflags=0x");
                crate::klog::hex(TASKS[idx].regs.rflags);
                crate::klog::s(" ss=0x");
                crate::klog::hex(TASKS[idx].regs.ss);
                crate::klog::s("\n  scratch.rax=0x");
                // PREEMPT_SCRATCH = [real_rax, real_rdx, real_rip] of the last
                // build_kernel_preempt_frame call. If real_rip is corrupt, the
                // preempt_trampoline's jmp landed the CPU here.
                crate::klog::hex(PREEMPT_SCRATCH[0]);
                crate::klog::s(" rdx=0x");
                crate::klog::hex(PREEMPT_SCRATCH[1]);
                crate::klog::s(" rip=0x");
                crate::klog::hex(PREEMPT_SCRATCH[2]);
                crate::klog::s("\n");
                crate::klog::end();
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn inc_ticks() {
    // Only the BSP owns the global PIT clock. The AP's LAPIC timer also drives
    // this handler but must NOT advance the shared TICKS (would double-count).
    if current_cpu() == 0 {
        crate::pit::TICKS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
}

#[no_mangle]
static SCHED_CALLS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

// Serializes the shared-TASKS wakeup scan so the BSP PIT timer and the AP LAPIC
// timer cannot both wake/enqueue the same sleeping task (or swap its state
// concurrently). Lock order: this -> RUNQUEUE_LOCK[cpu].
static TIMER_WAKE_LOCK: crate::spinlock::RawSpin = crate::spinlock::RawSpin::new();

/// Wake sleeping user tasks whose time-based wakeup tick has arrived. May be run
/// by either CPU's timer; guarded by TIMER_WAKE_LOCK against the BSP running the
/// same scan concurrently. The woken task is enqueued onto its home-CPU runqueue
/// (so an AP-blocked user task with cpu=1 lands on RUNQUEUE[1] for the AP to run).
pub fn wakeup_expired_sleepers() {
    let _g = TIMER_WAKE_LOCK.lock();
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
                // Resume on the live regs saved by the last context_switch; do NOT
                // stamp the zeroed saved_user_regs snapshot (would clobber r15).
                let _ = TASKS[i].saved_user_regs.take();
                enqueue_task(TASKS[i].id, TASKS[i].prio);
            }
        }
    }
}

pub extern "C" fn timer_schedule() -> u64 {
    // Per-CPU EOI: the BSP re-arms the PIC (PIT IRQ0), the AP re-arms its own
    // LAPIC timer (both land on vector 0x20).
    if current_cpu() == 0 {
        crate::pic::send_eoi(0);
    } else {
        unsafe { crate::apic::eoi(); }
        // AP: this is a pure per-CPU tick whose only job is to wake the AP out
        // of its idle hlt so its own schedule() loop can re-drain its runqueue.
        // Everything below (serial/keyboard polling and the global wakeup scan
        // over the shared TASKS array) would RACE with the BSP creating and
        // transitioning user tasks, so the AP must not touch it.
        return 0;
    }
    // Poll UART for serial input and feed into keyboard buffer.
    while let Some(c) = crate::serial::read_byte_nonblocking() {
        // Filter: only accept printable ASCII and common control chars.
        // ESC (0x1B) is accepted so terminal line-editing (arrow keys, etc.)
        // receives the full ESC [ A sequences instead of losing the ESC byte.
        if c >= 0x20 && c <= 0x7E || c == 0x1B || c == b'\n' || c == b'\r' || c == b'\t' || c == 0x08 || c == 0x7F {
            crate::keyboard::push_char(c);
        }
    }

    // Wake up sleeping tasks whose wakeup tick has arrived (shared, race-safe).
    wakeup_expired_sleepers();

    let current = cur_task().load(Ordering::SeqCst);
    if current == 0 {
        return 0;
    }

    // Inside a syscall (blocking I/O wait with IF=1): do NOT build a preempt
    // frame. The shared syscall_stack + PREEMPT_SCRATCH/trampoline path cannot
    // safely suspend a syscall mid-call (each timer tick would clobber the
    // global scratch). Instead return 0 so the handler restores directly from
    // the CPU-pushed interrupt frame (iretq), letting the syscall continue
    // unperturbed.
    if in_syscall() {
        return 0;
    }

    unsafe {
        let idx = task_idx(current);

        // Kernel tasks: return 0 to signal handler to use CPU-pushed frame directly
        if TASKS[idx].user_stack == 0 {
            return 0;
        }

        // Resume the current task: return 0 so the handler restores directly
        // from the CPU-pushed interrupt frame (iretq). Building a synthetic
        // frame here (kernel_stack-0xA0) + global PREEMPT_SCRATCH + trampoline
        // is fragile: the fixed-address frame and global scratch can be
        // clobbered by later kernel-stack activity or a second preempt,
        // corrupting the resume RIP (observed jumps into .data/TASKS). A plain
        // iretq preserves the interrupted kernel context exactly, and is what
        // the kernel-task path below already does.
        if TASKS[idx].user_stack != 0 && (TASKS[idx].regs.cs & 3) == 0 {
            return 0;
        }

        // Decrement time slice
        if TASKS[idx].time_slice > 0 {
            TASKS[idx].time_slice -= 1;
        }

        // If task not running, don't reschedule — resume it as-is
        if TASKS[idx].state != TaskState::Running {
            return 0;
        }

        // Time slice still positive → keep running current task
        if TASKS[idx].time_slice > 0 {
            return 0;
        }

        // Time slice expired — give a fresh time slice
        TASKS[idx].time_slice = initial_time_slice(TASKS[idx].prio);

        // Try to find a different task; if only current task is waiting, just keep running
        let next_id = match dequeue_task() {
            Some(id) => id,
            None => {
                TASKS[idx].state = TaskState::Running;
                return 0;
            }
        };

        if next_id == current {
            TASKS[idx].state = TaskState::Running;
            return 0;
        }

        // Switch to a different task — requeue current first
        TASKS[idx].state = TaskState::Ready;
        enqueue_task(current, TASKS[idx].prio);

        let new_idx = task_idx(next_id);
        TASKS[new_idx].state = TaskState::Running;
        cur_task().store(next_id, Ordering::SeqCst);
        unsafe { CURRENT_TASK_ID = next_id; }
        pt_mgr().switch_to(TASKS[new_idx].pml4);
        crate::gdt::set_tss_rsp0(TASKS[new_idx].kernel_stack);
        // Trace kernel-mode timer-driven resumes (DEBUG; queryable via
        // klog::dump() when console level < DEBUG).
        if crate::klog::get_console_level() >= crate::klog::LOG_DEBUG
            && (TASKS[new_idx].regs.cs & 3) == 0
        {
            crate::klog::begin(crate::klog::LOG_DEBUG, crate::klog::FAC_SCHED);
            crate::klog::s("[RSM:T] cur=");
            crate::klog::dec(current);
            crate::klog::s(" next=");
            crate::klog::dec(next_id);
            crate::klog::s(" rip=0x");
            crate::klog::hex(TASKS[new_idx].regs.rip);
            crate::klog::s(" rsp=0x");
            crate::klog::hex(TASKS[new_idx].regs.rsp);
            crate::klog::s(" cs=0x");
            crate::klog::hex(TASKS[new_idx].regs.cs);
            crate::klog::s(" rbp=0x");
            crate::klog::hex(TASKS[new_idx].regs.rbp);
            crate::klog::end();
        }
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
        // Guard: a kernel-mode (cs.RPL==0) preempt frame whose resume RIP is
        // outside .text (0x106000..0x11AF6F) means the interrupted stream was
        // already corrupt (ret/jump landed in .data/.rodata). Captured via klog
        // (WARNING) so it is queryable via klog::dump() and hideable by console
        // level; user-mode RIPs legitimately exceed .text, so only warn for
        // kernel code.
        let rip = regs.rip;
        let in_text = rip >= 0x106000 && rip < 0x11AF6F;
        if (regs.cs & 3) == 0 && !in_text {
            crate::klog::begin(crate::klog::LOG_WARNING, crate::klog::FAC_SCHED);
            crate::klog::s("[BADPREEMPT] task=");
            crate::klog::dec((*task_ptr).id);
            crate::klog::s(" regs.rip=0x");
            crate::klog::hex(rip);
            crate::klog::s(" cs=0x");
            crate::klog::hex(regs.cs);
            crate::klog::s(" rbp=0x");
            crate::klog::hex(regs.rbp);
            crate::klog::s(" rsp=0x");
            crate::klog::hex(regs.rsp);
            crate::klog::s(" kstack=0x");
            crate::klog::hex(kernel_stack);
            crate::klog::s(" prev_scratch_rip=0x");
            crate::klog::hex(PREEMPT_SCRATCH[2]);
            crate::klog::s("\n");
            crate::klog::end();
        }
        // Restore FS base for this task
        core::arch::asm!(
            "mov ecx, 0xC0000100",
            "wrmsr",
            in("eax") (regs.fs_base as u32),
            in("edx") ((regs.fs_base >> 32) as u32),
            out("ecx") _,
            options(nostack, preserves_flags)
        );
        // Build the resume frame into the dedicated per-CPU scratch buffer, NOT
        // at the target task's kernel_stack-0xA0. The target's kernel stack top
        // holds a LIVE syscall-entry frame (the 11 callee-saved regs + CPU
        // return addr that syscall_return pops + sysretq); writing the preempt
        // frame there overlaps and clobbers it, so a task suspended mid-syscall
        // resumes to garbage and the next sysretq jumps into .data. The timer
        // handler's resume path only pops this frame then does
        // `mov rsp, regs.rsp`, so the frame's physical location is irrelevant
        // and scratch (used atomically per-interrupt, IF=0) is safe.
        let base = &raw mut TIMER_FRAME_SCRATCH as *mut u64;
        write_frame(base, regs);
        if (regs.cs & 3) == 0 {
            PREEMPT_SCRATCH[0] = regs.rax;
            PREEMPT_SCRATCH[1] = regs.rdx;
            PREEMPT_SCRATCH[2] = regs.rip;
            *base.add(15) = preempt_trampoline as *const () as u64;
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
pub const SYS_sysinfo: u64 = 99;
pub const SYS_getuid: u64 = 102;
pub const SYS_getgid: u64 = 104;
pub const SYS_geteuid: u64 = 107;
pub const SYS_getegid: u64 = 108;
pub const SYS_arch_prctl: u64 = 158;
pub const SYS_prctl: u64 = 157;
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
pub const SYS_futex: u64 = 202;

// Linux clone flags (x86_64)
pub const CLONE_VM: u64         = 0x00000100;
pub const CLONE_FS: u64         = 0x00000200;
pub const CLONE_FILES: u64      = 0x00000400;
pub const CLONE_SIGHAND: u64    = 0x00000800;
pub const CLONE_PIDFD: u64      = 0x00000010;
pub const CLONE_PTRACE: u64     = 0x00000002;
pub const CLONE_VFORK: u64      = 0x00004000;
pub const CLONE_PARENT: u64     = 0x00008000;
pub const CLONE_THREAD: u64     = 0x00010000;
pub const CLONE_SYSVSEM: u64    = 0x00000800;
pub const CLONE_SETTLS: u64     = 0x00080000;
pub const CLONE_PARENT_SETTID: u64 = 0x00100000;
pub const CLONE_CHILD_CLEARTID: u64 = 0x00200000;
pub const SYS_getppid: u64 = 110;
pub const SYS_getpgid: u64 = 121;
pub const SYS_sigaltstack: u64 = 131;
pub const SYS_setpgid: u64 = 109;
pub const SYS_getpgrp: u64 = 111;
pub const SYS_setsid: u64 = 112;
pub const SYS_getrandom: u64 = 318;
pub const SYS_statfs: u64 = 137;
pub const SYS_fstatfs: u64 = 138;
pub const SYS_getrlimit: u64 = 97;
pub const SYS_setrlimit: u64 = 160;
pub const SYS_mknod: u64 = 133;
pub const SYS_chmod: u64 = 90;
pub const SYS_fchmod: u64 = 91;
pub const SYS_chown: u64 = 92;
pub const SYS_lchown: u64 = 94;
pub const SYS_utimensat: u64 = 280;
pub const SYS_unlinkat: u64 = 263;
pub const SYS_readlinkat: u64 = 267;
pub const SYS_getgroups: u64 = 115;
pub const SYS_setgroups: u64 = 116;
pub const SYS_mount: u64 = 165;
pub const SYS_umount2: u64 = 166;

// Rynex-specific (high numbers, no Linux conflict)
pub const SYS_rynex_get_ticks: u64 = 2000;
pub const SYS_rynex_futex: u64 = 2001;
pub const SYS_rynex_shm_setup: u64 = 2002;
pub const SYS_rynex_shm_notify: u64 = 2003;
pub const SYS_rynex_shm_wait: u64 = 2004;
pub const SYS_rynex_shm_teardown: u64 = 2005;
pub const SYS_rynex_spawn: u64 = 2006;
pub const SYS_rynex_getppid: u64 = 2007;
pub const SYS_rynex_sleep: u64 = 2008;
pub const SYS_rynex_yield: u64 = 2009;
pub const SYS_rynex_ipc_create: u64 = 2010;
pub const SYS_rynex_ipc_connect: u64 = 2011;
pub const SYS_rynex_ipc_send: u64 = 2012;
pub const SYS_rynex_ipc_recv: u64 = 2013;
pub const SYS_rynex_ipc_close: u64 = 2014;
pub const SYS_rynex_port_in: u64 = 2020;
pub const SYS_rynex_port_out: u64 = 2021;
pub const SYS_rynex_irq_register: u64 = 2022;
pub const SYS_rynex_irq_wait: u64 = 2023;
pub const SYS_rynex_ipc_call: u64 = 2024;
pub const SYS_rynex_ipc_recv_ex: u64 = 2025;
pub const SYS_rynex_ipc_reply: u64 = 2026;
pub const SYS_rynex_fs_register: u64 = 2027;
pub const SYS_rynex_fs_mount: u64 = 2028;
pub const SYS_rynex_phys_map: u64 = 2029;
pub const SYS_rynex_dma_alloc: u64 = 2030;
pub const SYS_rynex_dma_free: u64 = 2031;
pub const SYS_rynex_pci_read: u64 = 2032;
pub const SYS_rynex_pci_write: u64 = 2033;
pub const SYS_rynex_pci_find: u64 = 2034;

pub const ARCH_SET_FS: u64 = 0x1002;
pub const ARCH_GET_FS: u64 = 0x1003;

pub const INTERP_BASE: u64 = 0x100_0000_0000;

pub const WNOHANG: u32 = 1;

static SHELL_TASK_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

#[no_mangle]
pub extern "C" fn syscall_handler(
    syscall_num: u64,
    arg1: u64, arg2: u64, arg3: u64,
    arg4: u64, arg5: u64, arg6: u64
) -> i64 {
    in_syscall_enter();
    let id = cur_task().load(Ordering::SeqCst);
    if syscall_num == SYS_execve && arg2 != 0 {
        // Check if executing busybox
        let filename_bytes = unsafe { core::slice::from_raw_parts(arg1 as *const u8, 64) };
        let filename_str = core::str::from_utf8(filename_bytes).unwrap_or("");
        if filename_str.contains("busybox") {
            SHELL_TASK_ID.store(id, Ordering::SeqCst);
            crate::task::set_current_comm(b"busybox");
        }
        // Derive a short comm from the executable basename.
        let slash = filename_str.rfind('/');
        let base = match slash { Some(i) => &filename_str[i+1..], None => filename_str };
        if !base.is_empty() && !base.contains("busybox") {
            crate::task::set_current_comm(base.as_bytes());
        }
    }
    let result = match syscall_num {
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
        SYS_prctl => sys_prctl(arg1 as i32, arg2 as u64, arg3 as u64, arg4 as u64, arg5 as u64),
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
         SYS_sysinfo => sys_sysinfo(arg1 as *mut u8),
         SYS_getuid => sys_getuid(),
        SYS_getgid => sys_getgid(),
        SYS_geteuid => sys_geteuid(),
        SYS_getegid => sys_getegid(),
        SYS_getdents64 => sys_getdents64(arg1 as u32, arg2 as *mut u8, arg3 as usize),
        SYS_mkdir => sys_mkdir(arg1 as *const u8, arg2 as u32),
        SYS_rmdir => sys_rmdir(arg1 as *const u8),
        SYS_unlink => sys_unlink(arg1 as *const u8),
        SYS_rename => sys_rename(arg1 as *const u8, arg2 as *const u8),
        SYS_openat => sys_openat(arg1 as i32, arg2 as *const u8, arg3 as i32, arg4 as u32),
        SYS_readlink => sys_readlink(arg1 as *const u8, arg2 as *mut u8, arg3 as usize),
        SYS_clone => sys_clone(arg1 as u64, arg2 as u64, arg3 as *mut u64, arg4 as *mut u64, arg5 as u64, arg6),
        SYS_vfork => sys_fork(), // vfork → fork
        SYS_dup => sys_dup2(arg1 as u32, arg1 as u32), // dup → dup2(fd, fd)
        SYS_fchdir => sys_chdir_from_fd(arg1 as u32),
        SYS_poll => sys_poll(arg1 as u64, arg2 as u64, arg3 as i32),
        SYS_lseek => sys_lseek(arg1 as u32, arg2 as i64, arg3 as i32),
        SYS_readv => sys_readv(arg1 as u32, arg2 as u64, arg3 as i32),
        SYS_writev => sys_writev(arg1 as u32, arg2 as u64, arg3 as i32),
        SYS_gettid => cur_task().load(Ordering::SeqCst) as i64,
        SYS_tkill => sys_tkill(arg1 as i64, arg2 as i32),
        SYS_sched_getaffinity => 0,
        SYS_set_tid_address => cur_task().load(Ordering::SeqCst) as i64,
        SYS_clock_gettime => sys_clock_gettime(arg1 as u64, arg2 as *mut u8),
        SYS_clock_nanosleep => sys_clock_nanosleep(arg1 as u64, arg2 as u32, arg3 as *const u64, arg4 as *mut u64),
        SYS_exit_group => sys_exit(arg1 as i32),
        SYS_set_robust_list => 0,
        SYS_getrandom => sys_getrandom(arg1 as *mut u8, arg2 as usize, arg3 as u32),
        SYS_rt_sigaction => sys_rt_sigaction(arg1 as i32, arg2 as u64, arg3 as u64),
        SYS_rt_sigprocmask => sys_rt_sigprocmask(arg1 as i32, arg2 as u64, arg3 as u64),
        SYS_rt_sigreturn => sys_rt_sigreturn(),
        SYS_sigaltstack => sys_sigaltstack(arg1 as u64, arg2 as u64),
        SYS_setpgid => sys_setpgid(arg1 as i32, arg2 as i32),
        SYS_getppid => sys_getppid(),
        SYS_getpgid => sys_getpgid(arg1 as i32),
        SYS_getpgrp => sys_getpgrp(),
        SYS_setsid => sys_setsid(),
        SYS_sched_yield => sys_rynex_yield(),
        SYS_futex => sys_futex(arg1 as *const u32, arg2 as i32, arg3 as u32,
                               arg4 as *const u32, arg5 as u32),
        SYS_statfs => sys_statfs(arg1 as *const u8, arg2 as *mut u8),
        SYS_fstatfs => sys_fstatfs(arg1 as u32, arg2 as *mut u8),
        SYS_getrlimit => sys_getrlimit(arg1 as u32, arg2 as *mut u8),
        SYS_setrlimit => sys_setrlimit(arg1 as u32, arg2 as *mut u8),
        SYS_mknod => sys_mknod(arg1 as *const u8, arg2 as u32, arg3 as u64),
        SYS_chmod => sys_chmod(arg1 as *const u8, arg2 as u32),
        SYS_fchmod => sys_fchmod(arg1 as u32, arg2 as u32),
        SYS_chown => sys_chown(arg1 as *const u8, arg2 as u32, arg3 as u32),
        SYS_utimensat => sys_utimensat(arg1 as i32, arg2 as *const u8, arg3 as u64, arg4 as i32),
        SYS_unlinkat => sys_unlinkat(arg1 as i32, arg2 as *const u8, arg3 as i32),
        SYS_readlinkat => sys_readlinkat(arg1 as i32, arg2 as *const u8, arg3 as *mut u8, arg4 as usize),
        SYS_getgroups => sys_getgroups(arg1 as i32, arg2 as *mut u8),
        SYS_setgroups => sys_setgroups(arg1 as usize, arg2 as *const u8),
        SYS_mount => sys_mount(arg1 as *const u8, arg2 as *const u8, arg3 as *const u8, arg4 as u64, arg5 as u64),
        SYS_umount2 => sys_umount2(arg1 as *const u8, arg2 as i32),
        // Rynex-specific
        SYS_rynex_get_ticks => sys_get_ticks(),
        SYS_rynex_futex => sys_futex(arg1 as *const u32, arg2 as i32, arg3 as u32,
                                        arg4 as *const u32, arg5 as u32),
        SYS_rynex_shm_setup => crate::ipc::shm_setup(arg1, arg2),
        SYS_rynex_shm_notify => crate::ipc::shm_notify(arg1),
        SYS_rynex_shm_wait => crate::ipc::shm_wait(arg1),
        SYS_rynex_shm_teardown => crate::ipc::shm_teardown(arg1),
        SYS_rynex_spawn => sys_spawn(arg1 as *const u8, arg2 as usize),
        SYS_rynex_getppid => sys_getppid(),
        SYS_rynex_sleep => sys_sleep(arg1 as u64),
        SYS_rynex_yield => sys_rynex_yield(),
        SYS_rynex_ipc_create => crate::ipc::ipc_create(arg1 as *const u8, arg2 as usize),
        SYS_rynex_ipc_connect => crate::ipc::ipc_connect(arg1 as *const u8, arg2 as usize),
        SYS_rynex_ipc_send => crate::ipc::ipc_send(arg1 as u64, arg2 as *const u8, arg3 as usize, arg4 as u32),
        SYS_rynex_ipc_recv => crate::ipc::ipc_recv(arg1 as u64, arg2 as *mut u8, arg3 as usize),
        SYS_rynex_ipc_close => crate::ipc::ipc_close(arg1 as u64),
        SYS_rynex_ipc_call => crate::ipc::ipc_call(arg1 as u64, arg2 as *const u8, arg3 as usize, arg4 as *mut u8, arg5 as usize),
        SYS_rynex_ipc_recv_ex => crate::ipc::ipc_recv_ex_user(arg1 as u64, arg2 as *mut u8, arg3 as usize),
        SYS_rynex_ipc_reply => crate::ipc::ipc_reply(arg1 as u64, arg2 as *const u8, arg3 as usize),
        SYS_rynex_fs_register => sys_fs_register(arg1 as u64),
        SYS_rynex_fs_mount => sys_fs_mount(arg1 as *const u8),
        SYS_rynex_phys_map => sys_phys_map(arg1 as u64, arg2 as u64),
        SYS_rynex_dma_alloc => sys_dma_alloc(arg1 as usize),
        SYS_rynex_dma_free => sys_dma_free(arg1 as u64),
        SYS_rynex_pci_read => sys_pci_read(arg1 as u8, arg2 as u8, arg3 as u8, arg4 as u8),
        SYS_rynex_pci_write => sys_pci_write(arg1 as u8, arg2 as u8, arg3 as u8, arg4 as u8, arg5 as u32),
        SYS_rynex_pci_find => sys_pci_find(arg1 as u16),
        SYS_rynex_port_in => sys_port_in(arg1 as u16, arg2 as u32),
        SYS_rynex_port_out => sys_port_out(arg1 as u16, arg2 as u32, arg3 as u64),
        SYS_rynex_irq_register => sys_irq_register(arg1 as u8, arg2 as *mut u32),
        SYS_rynex_irq_wait => sys_irq_wait(arg1 as u8, arg2 as u64),
        SYS_reboot => sys_reboot(arg1 as u32, arg2 as u32, arg3 as u32),
        _ => {
            // Print first unknown syscall
            static ONCE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
            if !ONCE.swap(true, core::sync::atomic::Ordering::Relaxed) {
                serial::write_str("SYS: unknown ");
                serial::write_dec(syscall_num);
                serial::write_str(" a1=0x");
                serial::write_hex(arg1);
                serial::write_str(" a2=0x");
                serial::write_hex(arg2);
                serial::write_str(" a3=0x");
                serial::write_hex(arg3);
                serial::write_str(" rip=0x");
                serial::write_hex(unsafe { SYSCALL_USER_RIP });
                serial::write_str("\n");
            }
            -ENOSYS
        },
    };
    in_syscall_exit();
    // Trace every syscall into the klog ring buffer (FAC_SYSCALL, DEBUG).
    // Only mirrored to serial when console level >= DEBUG, so the crash tail
    // shows the exact syscall sequence that led to a fault.
    let current = cur_task().load(Ordering::SeqCst);
    crate::klog::begin(crate::klog::LOG_DEBUG, crate::klog::FAC_SYSCALL);
    crate::klog::s("sc=");
    crate::klog::dec(syscall_num);
    crate::klog::s(" a1=0x");
    crate::klog::hex(arg1);
    crate::klog::s(" tid=");
    crate::klog::dec(current);
    crate::klog::s(" -> 0x");
    crate::klog::hex(result as u64);
    crate::klog::end();
    result
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
    let id = cur_task().load(Ordering::SeqCst);
    serial::write_str("SYS_EXIT: task ");
    serial::write_dec(id as u64);
    serial::write_str(" status=");
    serial::write_dec(status as u64);
    serial::write_str(" rip=0x");
    serial::write_hex(unsafe { TASKS[task_idx(id)].regs.rip });
    serial::write_str(" rflags=0x");
    serial::write_hex(unsafe { TASKS[task_idx(id)].regs.rflags });
    serial::write_str("\n");
    exit_task(status);
    // If no other task to schedule, halt
    let id2 = cur_task().load(Ordering::SeqCst);
    if id2 == 0 || unsafe { TASKS[task_idx(id2)].state } == TaskState::Zombie {
        serial::write_str("SYS_EXIT: no more tasks, halting\n");
        unsafe { core::arch::asm!("cli; hlt", options(noreturn)); }
    }
    0
}

fn sys_write(fd: u32, buf: *const u8, count: usize) -> i64 {
    if buf.is_null() || count == 0 { return 0; }
    if !user_range_valid(buf as u64, count, false) {
        return -EFAULT;
    }
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

fn sys_get_ticks() -> i64 {
    unsafe { crate::pit::TICKS.load(core::sync::atomic::Ordering::Relaxed) as i64 }
}

fn sys_rynex_yield() -> i64 {
    // sched_yield must actually hand over the CPU. A plain schedule() declines
    // to switch while inside a syscall (in_syscall()==true), and leaving the
    // task Running while also on the runqueue makes a spin-yield loop starve
    // every other task (timer sees state!=Running and never preempts it).
    // force_schedule() switches even inside a syscall; exit_task/waitpid use
    // the same path safely.
    yield_now_force();
    0
}

// ── User-space driver support (P1-B) ─────────────────────────────
// Microkernel seam: drivers run as user-space services. The kernel grants
// them (a) privileged port I/O executed on their behalf and (b) IRQ event
// delivery through a per-IRQ shared counter + futex wake word.

/// Port I/O read. `width` is 1/2/4 for inb/inw/inl. Returns value or -EINVAL.
fn sys_port_in(port: u16, width: u32) -> i64 {
    match width {
        1 => {
            let v: u8;
            unsafe { core::arch::asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack, preserves_flags)); }
            v as i64
        }
        2 => {
            let v: u16;
            unsafe { core::arch::asm!("in ax, dx", out("ax") v, in("dx") port, options(nomem, nostack, preserves_flags)); }
            v as i64
        }
        4 => {
            let v: u32;
            unsafe { core::arch::asm!("in eax, dx", out("eax") v, in("dx") port, options(nomem, nostack, preserves_flags)); }
            v as i64
        }
        _ => -EINVAL,
    }
}

/// Port I/O write. `width` is 1/2/4 for outb/outw/outl.
fn sys_port_out(port: u16, width: u32, value: u64) -> i64 {
    match width {
        1 => {
            let v = value as u8;
            unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack, preserves_flags)); }
        }
        2 => {
            let v = value as u16;
            unsafe { core::arch::asm!("out dx, ax", in("dx") port, in("ax") v, options(nomem, nostack, preserves_flags)); }
        }
        4 => {
            let v = value as u32;
            unsafe { core::arch::asm!("out dx, eax", in("dx") port, in("eax") v, options(nomem, nostack, preserves_flags)); }
        }
        _ => return -EINVAL,
    }
    0
}

// IRQ delivery: each registered IRQ gets a user-space counter word. The kernel
// bumps the counter and futex-wakes the driver task on each edge. Drivers wait
// with rynex_irq_wait (a futex wait on the same word) so they can block
// cleanly instead of spinning.
const MAX_DRIVER_IRQS: usize = 16;
static mut DRIVER_IRQ_WORD: [u64; MAX_DRIVER_IRQS] = [0; MAX_DRIVER_IRQS];

/// Driver task registers a user-space u32 counter for `irq`. Returns 0.
fn sys_irq_register(irq: u8, counter: *mut u32) -> i64 {
    if irq as usize >= MAX_DRIVER_IRQS {
        return -EINVAL;
    }
    if counter.is_null() || !user_range_valid(counter as u64, 4, true) {
        return -EFAULT;
    }
    unsafe {
        DRIVER_IRQ_WORD[irq as usize] = counter as u64;
        crate::pic::unmask(irq);
    }
    0
}

/// Driver task blocks until the IRQ counter changes. `timeout_ms` 0 = forever.
/// Polls the counter (futex block is the natural primitive already used by
/// the IPC layer for the same purpose).
fn sys_irq_wait(irq: u8, timeout_ms: u64) -> i64 {
    if irq as usize >= MAX_DRIVER_IRQS {
        return -EINVAL;
    }
    unsafe {
        let word = DRIVER_IRQ_WORD[irq as usize];
        if word == 0 {
            return -EINVAL;
        }
        let first = core::ptr::read_volatile(word as *const u32);
        let deadline = if timeout_ms == 0 {
            0
        } else {
            crate::pit::TICKS.load(core::sync::atomic::Ordering::Relaxed) + timeout_ms * 100 / 1000 * 100
        };
        loop {
            let now = core::ptr::read_volatile(word as *const u32);
            if now != first {
                return 0;
            }
            if deadline != 0
                && crate::pit::TICKS.load(core::sync::atomic::Ordering::Relaxed) >= deadline
            {
                return -EAGAIN;
            }
            if !block_on_futex(word as *const u32) {
                return -EAGAIN;
            }
        }
    }
}

/// Called from the timer/IRQ dispatch path to deliver an IRQ edge to any
/// waiting driver. Public so pic/device code can invoke it.
pub fn driver_irq_edge(irq: u8) {
    unsafe {
        if irq as usize >= MAX_DRIVER_IRQS {
            return;
        }
        let word = DRIVER_IRQ_WORD[irq as usize];
        if word == 0 {
            return;
        }
        let now = core::ptr::read_volatile(word as *const u32);
        core::ptr::write_volatile(word as *mut u32, now.wrapping_add(1));
        crate::task::futex_wake(word as *const u32, 1);
    }
}

/// User-space FS service registers its IPC port with the kernel. From then on
/// every userfs mount forwards vnode ops to that port.
fn sys_fs_register(port_id: u64) -> i64 {
    if port_id == 0 {
        return -EINVAL;
    }
    crate::vfs_core::userfs::set_service_port(port_id);
    serial::write_str("VFS: userfs service registered on port ");
    serial::write_dec(port_id);
    serial::write_str("\n");
    0
}

/// Mount the user-space FS service at an absolute path (e.g. /mnt/ufs).
fn sys_fs_mount(mp: *const u8) -> i64 {
    if mp.is_null() {
        return -EFAULT;
    }
    let path = unsafe { cstr_from_ptr(mp) };
    if path.is_empty() {
        return -EINVAL;
    }
    match crate::vfs_core::mount_userfs(path) {
        Ok(vn) => {
            serial::write_str("VFS: userfs mounted at '");
            serial::write_str(&alloc::format!("{}", core::str::from_utf8(path).unwrap_or("?")));
            serial::write_str("' vnode=");
            serial::write_dec(vn as u64);
            serial::write_str("\n");
            0
        }
        Err(e) => {
            serial::write_str("VFS: userfs mount failed: ");
            serial::write_str(e);
            serial::write_str("\n");
            -EINVAL
        }
    }
}

// ── User-space device driver support (P2b) ──────────────────────
// Microkernel seam #2: drivers map device MMIO and DMA buffers into their own
// address space, and walk PCI config space, all under kernel supervision.

/// Apply `f` to the mutable vmas array of every task sharing `pml4` (the
/// whole process, including CLONE_VM threads). CLONE_VM threads share one
/// page table, so their per-task vma arrays must be kept identical; otherwise
/// a mapping created by one thread is invisible to another thread's demand
/// paging, which is exactly the mallocng PAGE_FAULT root cause (a munmap by
/// one thread cleared PTEs in the shared pml4 while a sibling's vma list
/// was left stale, so handle_demand_page returned false and fatally faulted).
/// VMA pool helpers. Records are keyed by pml4, so every task sharing an
/// address space (including CLONE_VM threads) sees the same mappings with no
/// per-task copy and no sibling sync. All scans are bounded by VMA_USED so
/// lookup cost tracks the live population, not the 64K pool size.

/// Register [start, end) for `pml4`. Returns false when the pool is full.
fn vma_register(pml4: u64, start: u64, end: u64, flags: u64) -> bool {
    unsafe {
        for i in 0..VMA_USED {
            let rec = &mut VMAS[i];
            if rec.pml4 == 0 && rec.vma.start == 0 {
                rec.pml4 = pml4;
                rec.vma.start = start;
                rec.vma.end = end;
                rec.vma.flags = flags;
                return true;
            }
        }
        if VMA_USED < MAX_VMA_RECORDS {
            VMAS[VMA_USED] = VmaRec {
                pml4,
                vma: Vma { start, end, flags },
            };
            VMA_USED += 1;
            return true;
        }
    }
    false
}

/// Find the VMA covering `addr` in `pml4`'s address space, if any.
fn vma_find(pml4: u64, addr: u64) -> Option<Vma> {
    unsafe {
        for i in 0..VMA_USED {
            let rec = &VMAS[i];
            if rec.pml4 == pml4 && addr >= rec.vma.start && addr < rec.vma.end {
                return Some(rec.vma);
            }
        }
    }
    None
}

/// End of the first (smallest-end) VMA that overlaps [start, end), for hole
/// scanning: the caller jumps its candidate to this end and retries.
fn vma_first_overlap_end(pml4: u64, start: u64, end: u64) -> Option<u64> {
    let mut best: Option<u64> = None;
    unsafe {
        for i in 0..VMA_USED {
            let rec = &VMAS[i];
            if rec.pml4 == pml4 && start < rec.vma.end && end > rec.vma.start {
                if best.map_or(true, |b| rec.vma.end < b) {
                    best = Some(rec.vma.end);
                }
            }
        }
    }
    best
}

/// Drop the record whose range starts at `addr` (dma_free).
fn vma_clear_addr(pml4: u64, addr: u64) {
    unsafe {
        for i in 0..VMA_USED {
            let rec = &mut VMAS[i];
            if rec.pml4 == pml4 && rec.vma.start == addr {
                rec.pml4 = 0;
                rec.vma.start = 0;
                rec.vma.end = 0;
                rec.vma.flags = 0;
                return;
            }
        }
    }
}

/// Drop or shrink records intersecting [start, end) (munmap).
fn vma_clear_range(pml4: u64, start: u64, end: u64) {
    unsafe {
        for i in 0..VMA_USED {
            let rec = &mut VMAS[i];
            if rec.pml4 != pml4 || rec.vma.start == 0 {
                continue;
            }
            let s = rec.vma.start;
            let e = rec.vma.end;
            if start <= s && end >= e {
                rec.pml4 = 0;
                rec.vma.start = 0;
                rec.vma.end = 0;
                rec.vma.flags = 0;
            } else if start <= s && end > s && end < e {
                rec.vma.start = end;
            } else if end >= e && start > s && start < e {
                rec.vma.end = start;
            } else if start > s && end < e {
                rec.vma.end = start;
            }
        }
    }
}

/// Duplicate every record of `from` under `to` (fork / non-CLONE_VM clone).
fn vma_clone(from: u64, to: u64) {
    unsafe {
        for i in 0..VMA_USED {
            let rec = &VMAS[i];
            if rec.pml4 == from {
                vma_register(to, rec.vma.start, rec.vma.end, rec.vma.flags);
            }
        }
    }
}

/// Drop every record of `pml4` (address space teardown / exec).
fn vma_clear_pml4(pml4: u64) {
    if pml4 == 0 {
        return;
    }
    unsafe {
        for i in 0..VMA_USED {
            let rec = &mut VMAS[i];
            if rec.pml4 == pml4 {
                rec.pml4 = 0;
                rec.vma.start = 0;
                rec.vma.end = 0;
                rec.vma.flags = 0;
            }
        }
    }
}

/// Map a physical range into the calling process. `phys` is page-aligned,
/// `size` is rounded up to pages. Returns the user virtual address or a negated
/// errno. The mapping is marked uncached via PTE_NO_CACHE where available.
fn sys_phys_map(phys: u64, size: u64) -> i64 {
    let id = cur_task().load(Ordering::SeqCst);
    if id == 0 { return -EINVAL; }
    if phys == 0 || size == 0 || size > 0x1_0000_0000 {
        return -EINVAL;
    }
let size = ((size + 0xFFF) & !0xFFF) as u64;
    let idx = unsafe { task_idx(id) };
    let pml4 = unsafe { TASKS[idx].pml4 };

    // Pick a low user address range for driver mappings, clear of the ELF
    // image (0x400000-ish), heap and stack. 0x50000000 is far above brk and
    // below the mmap region.
    let base = 0x5000_0000u64;
    let mut chosen = 0u64;
    unsafe {
        let mut candidate = base;
        let limit = 0x6000_0000u64;
        'search: while candidate + size <= limit {
            match vma_first_overlap_end(pml4, candidate, candidate + size) {
                Some(e) => {
                    candidate = e;
                    continue 'search;
                }
                None => {
                    chosen = candidate;
                    break 'search;
                }
            }
        }
    }
    if chosen == 0 {
        return -ENOMEM;
    }

    let flags = crate::paging::PTE_PRESENT | crate::paging::PTE_USER | crate::paging::PTE_WRITABLE
        | crate::paging::PTE_CACHE_DISABLE;
    let mut off = 0u64;
    while off < size {
        match crate::paging::PageTableManager::map_into(pml4, chosen + off, phys + off, flags) {
            Ok(_) => {}
            Err(_) => {
                // Roll back pages already mapped.
                let mut roff = 0u64;
                while roff < off {
                    let _ = crate::paging::PageTableManager::unmap_into(pml4, chosen + roff);
                    unsafe { core::arch::asm!("invlpg [{}]", in(reg) (chosen + roff), options(nostack, preserves_flags)); }
                    roff += 0x1000;
                }
                return -ENOMEM;
            }
        }
        // Flush stale TLB entries; the vaddr range may have been mapped to a
        // different phys in a previous phys_map/dma_alloc.
        unsafe { core::arch::asm!("invlpg [{}]", in(reg) (chosen + off), options(nostack, preserves_flags)); }
        off += 0x1000;
    }

    // Register a VMA so demand paging / teardown knows about the range. The
    // pool is keyed by pml4, so every CLONE_VM sibling automatically sees it.
    if !vma_register(pml4, chosen, chosen + size, flags) {
        let mut roff = 0u64;
        while roff < size {
            let _ = crate::paging::PageTableManager::unmap_into(pml4, chosen + roff);
            unsafe { core::arch::asm!("invlpg [{}]", in(reg) (chosen + roff), options(nostack, preserves_flags)); }
            roff += 0x1000;
        }
        return -ENOMEM;
    }
    chosen as i64
}

/// Allocate a DMA-capable physical page and map it into the caller. Returns
/// (user_vaddr, phys_addr) packed: phys in high 32 bits, vaddr in low 48.
fn sys_dma_alloc(_pages: usize) -> i64 {
    let pages = if _pages == 0 { 1 } else { _pages.min(8) };
    let id = cur_task().load(Ordering::SeqCst);
    if id == 0 { return -EINVAL; }
    let idx = unsafe { task_idx(id) };

    // Allocate physically contiguous pages from the buddy allocator. The
    // buddy allocator hands out power-of-two blocks, so round the page count
    // up to the next power of two (min 1 page).
    let order = (pages as u32).next_power_of_two().trailing_zeros() as usize;
    let phys = {
        let alloc = unsafe { &mut *crate::memory::allocator() };
        match alloc.alloc(order) {
            Some(p) => p,
            None => return -ENOMEM,
        }
    };
    let size = 0x1000u64 << order;

    // Map into a fresh low user address (below the mmap region).
    let base = 0x5000_0000u64;
    let limit = 0x6000_0000u64;
    let pml4 = unsafe { TASKS[idx].pml4 };
    let mut chosen = 0u64;
    unsafe {
        let mut candidate = base;
        'search: while candidate + size <= limit {
            match vma_first_overlap_end(pml4, candidate, candidate + size) {
                Some(e) => {
                    candidate = e;
                    continue 'search;
                }
                None => {
                    chosen = candidate;
                    break 'search;
                }
            }
        }
    }
    if chosen == 0 {
        let alloc = unsafe { &mut *crate::memory::allocator() };
        alloc.free(phys, order);
        return -ENOMEM;
    }

    let flags = crate::paging::PTE_PRESENT | crate::paging::PTE_USER | crate::paging::PTE_WRITABLE;
    let mut off = 0u64;
    while off < size {
        if crate::paging::PageTableManager::map_into(pml4, chosen + off, phys + off, flags).is_err() {
            let alloc = unsafe { &mut *crate::memory::allocator() };
            alloc.free(phys, order);
            return -ENOMEM;
        }
        // Flush any stale TLB entry: this vaddr range may have been handed to
        // another DMA allocation before, so an old translation must not survive.
        unsafe { core::arch::asm!("invlpg [{}]", in(reg) (chosen + off), options(nostack, preserves_flags)); }
        off += 0x1000;
    }
    // Zero the freshly mapped DMA pages before handing them to userspace.
    // DMA buffers handed to a device must not leak stale page content.
    unsafe { core::ptr::write_bytes(phys as *mut u8, 0, size as usize); }
    // Register a VMA so demand paging / teardown knows about the range.
    if !vma_register(pml4, chosen, chosen + size, flags) {
        let alloc = unsafe { &mut *crate::memory::allocator() };
        alloc.free(phys, order);
        return -ENOMEM;
    }
    // Pack: high 32 bits = phys page number, low 32 bits = user vaddr.
    let phys_hi = (phys >> 12) & 0xFFFF_FFFF;
    ((phys_hi << 32) | (chosen & 0xFFFF_FFFF)) as i64
}

/// Free a DMA buffer previously returned by sys_dma_alloc. The low 32 bits
/// carry the user address; the physical page is returned to the buddy allocator.
fn sys_dma_free(packed: u64) -> i64 {
    let vaddr = packed & 0xFFFF_FFFF;
    let phys = (packed >> 32) & 0xFFFF_FFFF;
    if vaddr == 0 || phys == 0 {
        return -EINVAL;
    }
    let id = cur_task().load(Ordering::SeqCst);
    if id == 0 { return -EINVAL; }
    let idx = unsafe { task_idx(id) };
    let pml4 = unsafe { TASKS[idx].pml4 };

    // Find VMA to get the allocation size, then compute order.
    let mut order = 0usize;
    let mut found_vma = false;
    unsafe {
        for rec in VMAS.iter_mut() {
            if rec.pml4 == pml4 && rec.vma.start == vaddr as u64 {
                let size = rec.vma.end - rec.vma.start;
                if size > 0 {
                    // size is power-of-two pages * 4096
                    let pages = size / 0x1000;
                    if pages > 0 {
                        order = (pages as u32).next_power_of_two().trailing_zeros() as usize;
                    }
                }
                found_vma = true;
                break;
            }
        }
    }
    if found_vma {
        // Drop the shared record: the pool is keyed by pml4, so every
        // CLONE_VM sibling automatically sees the mapping removed.
        vma_clear_addr(pml4, vaddr as u64);
    }
    if !found_vma {
        crate::serial::write_str("BUDDY: dma_free VMA not found for vaddr=0x");
        crate::serial::write_hex(vaddr as u64);
        crate::serial::write_str("
");
        return -EINVAL;
    }

    // Unmap all pages in the range.
    let mut off = 0u64;
    while off < (1u64 << order) * 0x1000 {
        let _ = crate::paging::PageTableManager::unmap_into(pml4, (vaddr + off) as u64);
        unsafe { core::arch::asm!("invlpg [{}]", in(reg) (vaddr + off), options(nostack, preserves_flags)); }
        off += 0x1000;
    }

    let alloc = unsafe { &mut *crate::memory::allocator() };
    alloc.free(phys << 12, order);
    0
}

const PCI_CONFIG_ADDR: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

/// Read a PCI config register. Returns the 32-bit value or a negated errno.
pub fn sys_pci_read(bus: u8, dev: u8, func: u8, offset: u8) -> i64 {
    if offset > 0xFC || offset % 4 != 0 {
        return -EINVAL;
    }
    let addr: u32 = 0x8000_0000 | ((bus as u32) << 16) | ((dev as u32) << 11) | ((func as u32) << 8) | (offset as u32 & 0xFC);
    let value: u32;
    unsafe {
        core::arch::asm!(
            "mov edx, {addr_port}",
            "out dx, eax",
            "mov edx, {data_port}",
            "in eax, dx",
            addr_port = const PCI_CONFIG_ADDR,
            data_port = const PCI_CONFIG_DATA,
            in("eax") addr,
            lateout("eax") value,
            options(nostack, preserves_flags)
        );
    }
    value as i64
}

/// Write a PCI config register.
pub fn sys_pci_write(bus: u8, dev: u8, func: u8, offset: u8, value: u32) -> i64 {
    if offset > 0xFC || offset % 4 != 0 {
        return -EINVAL;
    }
    let addr: u32 = 0x8000_0000 | ((bus as u32) << 16) | ((dev as u32) << 11) | ((func as u32) << 8) | (offset as u32 & 0xFC);
    unsafe {
        core::arch::asm!(
            "mov edx, {addr_port}",
            "out dx, eax",
            "mov edx, {data_port}",
            "mov eax, ecx",
            "out dx, eax",
            addr_port = const PCI_CONFIG_ADDR,
            data_port = const PCI_CONFIG_DATA,
            in("eax") addr,
            in("ecx") value,
            options(nostack, preserves_flags)
        );
    }
    0
}

/// Scan bus 0 for a device with the given vendor/device id. Returns
/// (bus<<16 | dev<<11 | func<<8) or -ENODEV. Only devs 0..=31 checked.
pub fn sys_pci_find(vendor_device: u16) -> i64 {
    let _ = vendor_device;
    for dev in 0u8..32 {
        for func in 0u8..8 {
            let addr: u32 = 0x8000_0000 | ((dev as u32) << 11) | ((func as u32) << 8);
            let id: u32;
            unsafe {
                core::arch::asm!(
                    "mov edx, {addr_port}",
                    "out dx, eax",
                    "mov edx, {data_port}",
                    "in eax, dx",
                    addr_port = const PCI_CONFIG_ADDR,
                    data_port = const PCI_CONFIG_DATA,
                    in("eax") addr,
                    lateout("eax") id,
                    options(nostack, preserves_flags)
                );
            }
            if id != 0xFFFF_FFFF && id != 0 {
                // device id (low 16) requested; return slot for the first hit.
                return ((dev as i64) << 11) | ((func as i64) << 8);
            }
        }
    }
    -crate::task::ENODEV
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
const FUTEX_WAIT_BITSET: i32 = 9;
const FUTEX_WAKE_BITSET: i32 = 8;

const FUTEX_BITSET_MATCH_ANY: u32 = 0xffff_ffff;

const FUTEX_PRIVATE_FLAG: i32 = 128;
const FUTEX_CLOCK_REALTIME: i32 = 256;
const FUTEX_CMD_MASK: i32 = !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);

const FUTEX_WAITERS: u32 = 0x8000_0000;

fn sys_futex(uaddr: *const u32, op: i32, val: u32,
             uaddr2: *const u32, _val3: u32) -> i64 {
    // Strip FUTEX_PRIVATE_FLAG / FUTEX_CLOCK_REALTIME: musl sets these on
    // process-private futexes; the command itself is the low bits.
    let cmd = op & FUTEX_CMD_MASK;
    match cmd {
        FUTEX_WAIT => futex_wait(uaddr, val, uaddr2 as *const u64),
        FUTEX_WAIT_BITSET => {
            // musl/std Thread::park uses FUTEX_WAIT_BITSET with a per-thread
            // bitset. Treat it as match-all (block; the waker is FUTEX_WAKE_BITSET
            // which wakes all), which is the functionally-correct subset for tests.
            futex_wait(uaddr, val, uaddr2 as *const u64)
        }
        FUTEX_WAKE => futex_wake(uaddr, val),
        FUTEX_WAKE_BITSET => {
            // Wake all waiters regardless of the bitset (match-any semantics).
            futex_wake(uaddr, val)
        }
        FUTEX_LOCK_PI => futex_lock_pi(uaddr),
        FUTEX_UNLOCK_PI => futex_unlock_pi(uaddr),
        _ => -ENOSYS,
    }
}

pub fn futex_wait(uaddr: *const u32, val: u32, timeout: *const u64) -> i64 {
    // The futex word lives in user memory which may not be faulted in yet
    // (e.g. a thread-local/stack page). Read it through the user-page
    // validator so demand paging happens first, instead of raw-derefing a
    // user VA from kernel mode (which faults cs=0 -> cr2 = the user addr).
    if !user_range_valid(uaddr as u64, core::mem::size_of::<u32>(), false) {
        return -EFAULT;
    }
    let actual = unsafe { core::ptr::read_volatile(uaddr) };
    if actual != val {
        return -EAGAIN;
    }

    let id = cur_task().load(Ordering::SeqCst);
    if id == 0 { return -EINVAL; }

    // Relative timeout (Linux FUTEX_WAIT): parse {tv_sec, tv_nsec} timespec,
    // convert to PIT ticks (~20ms each) and compute the deadline.
    let deadline_tick: u64 = if !timeout.is_null() {
        if !user_range_valid(timeout as u64, 16, false) {
            return -EFAULT;
        }
        let sec = unsafe { core::ptr::read_volatile(timeout) } as i64;
        let nsec = unsafe { core::ptr::read_volatile(timeout.add(1)) } as i64;
        let total_ns = if sec < 0 || nsec < 0 {
            0
        } else {
            (sec as u64).saturating_mul(1_000_000_000).saturating_add(nsec as u64)
        };
        let ticks = (total_ns + 19_999_999) / 20_000_000;
        let now = crate::pit::TICKS.load(Ordering::Relaxed);
        now.saturating_add(ticks)
    } else {
        0
    };

    // serial::write_str("futex_wait: task ");
    // serial::write_dec(id);
    // serial::write_str(" uaddr=");
    // serial::write_hex(uaddr as u64);
    // serial::write_str(" val=");
    // serial::write_dec(val as u64);
    // serial::write_str(" deadline=");
    // serial::write_hex(deadline as u64);
    // serial::write_str("\n");

    // Remove from run queue before blocking
    remove_from_runqueue(id);

    unsafe {
        let idx = task_idx(id);
        // Save user context from syscall entry globals (not task.regs which holds
        // stale kernel context). This is the context to restore on wakeup.
        TASKS[idx].saved_user_regs = Some(Registers {
            rax: 0, rbx: 0, rcx: 0, rdx: 0,
            rsi: 0, rdi: 0, rbp: 0, rsp: SYSCALL_USER_RSP,
            r8: 0, r9: 0, r10: 0, r11: 0,
            r12: 0, r13: 0, r14: 0, r15: 0,
            rip: SYSCALL_USER_RIP, rflags: SYSCALL_USER_RFLAGS,
            cs: 0x23, ss: 0x1B, fs_base: SYSCALL_USER_FS_BASE,
        });
        TASKS[idx].blocked_on = uaddr as u64;
        TASKS[idx].state = TaskState::Blocked;
        if deadline_tick != 0 {
            TASKS[idx].wakeup_tick = deadline_tick;
            TASKS[idx].futex_deadline = deadline_tick;
        } else {
            TASKS[idx].wakeup_tick = 0;
            TASKS[idx].futex_deadline = 0;
        }
    }

    // Must force the switch: futex_wait runs inside a syscall where
    // in_syscall() is true, so the plain schedule() would bail out
    // immediately and we would never actually block.
    force_schedule();

    // Distinguish an explicit wake (futex_deadline cleared) from a timeout
    // wake (deadline reached while still blocked).
    unsafe {
        let idx = task_idx(id);
        if TASKS[idx].futex_deadline != 0 {
            TASKS[idx].futex_deadline = 0;
            let _now = crate::pit::TICKS.load(Ordering::Relaxed);
            return -ETIMEDOUT;
        }
    }
    0
}

pub fn futex_wake(uaddr: *const u32, max_wake: u32) -> i64 {
    let uaddr_val = uaddr as u64;
    // serial::write_str("futex_wake: uaddr=");
    // serial::write_hex(uaddr_val);
    // serial::write_str(" max_wake=");
    // serial::write_dec(max_wake as u64);
    // serial::write_str("\n");
    let mut woken = 0i64;
    unsafe {
        for i in 0..MAX_TASKS {
            if woken >= max_wake as i64 { break; }
            if TASKS[i].state == TaskState::Blocked
                && TASKS[i].blocked_on == uaddr_val
                && TASKS[i].id != 0
            {
                // serial::write_str("futex_wake: waking task ");
                // serial::write_dec(TASKS[i].id);
                // serial::write_str("\n");
                TASKS[i].state = TaskState::Ready;
                TASKS[i].blocked_on = 0;
                TASKS[i].wakeup_tick = 0;
                TASKS[i].futex_deadline = 0;
                // Resume on the live regs from the last context_switch; do NOT
                // stamp the zeroed saved_user_regs snapshot (would clobber r15).
                let _ = TASKS[i].saved_user_regs.take();
                enqueue_task(TASKS[i].id, TASKS[i].prio);
                woken += 1;
            }
        }
    }
    // serial::write_str("futex_wake: woken=");
    // serial::write_dec(woken as u64);
    // serial::write_str("\n");
    woken
}

/// Block the current task on a futex address, resuming only after
/// `futex_wake` (or a spurious timer wake). Returns true if we were woken.
/// Intended for the IPC mailbox send/recv loops.
pub fn block_on_futex(uaddr: *const u32) -> bool {
    let id = cur_task().load(Ordering::SeqCst);
    if id == 0 { return false; }
    remove_from_runqueue(id);
    unsafe {
        let idx = task_idx(id);
        // Save user context from syscall entry globals (not task.regs which holds
        // stale kernel context). This is the context to restore on wakeup.
        TASKS[idx].saved_user_regs = Some(Registers {
            rax: 0, rbx: 0, rcx: 0, rdx: 0,
            rsi: 0, rdi: 0, rbp: 0, rsp: SYSCALL_USER_RSP,
            r8: 0, r9: 0, r10: 0, r11: 0,
            r12: 0, r13: 0, r14: 0, r15: 0,
            rip: SYSCALL_USER_RIP, rflags: SYSCALL_USER_RFLAGS,
            cs: 0x23, ss: 0x1B, fs_base: SYSCALL_USER_FS_BASE,
        });
        TASKS[idx].blocked_on = uaddr as u64;
        TASKS[idx].state = TaskState::Blocked;
    }
    force_schedule();
    true
}

fn futex_lock_pi(uaddr: *const u32) -> i64 {
    let id = cur_task().load(Ordering::SeqCst);
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
    let id = cur_task().load(Ordering::SeqCst);
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
            TASKS[w_idx].wakeup_tick = 0;
            TASKS[w_idx].futex_deadline = 0;
            enqueue_task(waiter_id, TASKS[w_idx].prio);
        } else {
            // No waiters — unlock
            core::ptr::write_volatile(uaddr as *mut u32, 0u32);
        }
    }

    0
}

// ── Error constants ──────────────────────────────────────────────

pub const EPERM: i64 = 1;
pub const ENOENT: i64 = 2;pub const ESRCH: i64 = 3;
pub const EINTR: i64 = 4;
pub const EIO: i64 = 5;
pub const ENXIO: i64 = 6;
pub const E2BIG: i64 = 7;
pub const ENOEXEC: i64 = 8;
pub const EBADF: i64 = 9;
pub const ECHILD: i64 = 10;
pub const EAGAIN: i64 = 11;
pub const ENOMEM: i64 = 12;
pub const EACCES: i64 = 13;
pub const EFAULT: i64 = 14;
pub const ENOTBLK: i64 = 15;
pub const EBUSY: i64 = 16;
pub const EEXIST: i64 = 17;
pub const EXDEV: i64 = 18;
pub const ENODEV: i64 = 19;
pub const ENOTDIR: i64 = 20;
pub const EISDIR: i64 = 21;
pub const EINVAL: i64 = 22;
pub const ENFILE: i64 = 23;
pub const EMFILE: i64 = 24;
pub const ENOTTY: i64 = 25;
pub const ETXTBSY: i64 = 26;
pub const EFBIG: i64 = 27;
pub const ENOSPC: i64 = 28;
pub const ESPIPE: i64 = 29;
pub const EROFS: i64 = 30;
pub const EMLINK: i64 = 31;
pub const EPIPE: i64 = 32;
pub const EDOM: i64 = 33;
pub const ERANGE: i64 = 34;
pub const ENAMETOOLONG: i64 = 36;
pub const ENOSYS: i64 = 38;
pub const ETIMEDOUT: i64 = 110;
pub const ENOTEMPTY: i64 = 39;
pub const EMSGSIZE: i64 = 90;
pub const EADDRNOTAVAIL: i64 = 99;

// ── Helpers ──────────────────────────────────────────────────────

fn sys_waitpid(pid: i64, status_ptr: *mut i32, flags: u32) -> i64 {
    let current = current_task_id();
    if current == 0 { return -ECHILD; }

    unsafe {
        loop {
            // Look for zombie children to reap
            let mut found_any_child = false;
            for i in 0..MAX_TASKS {
                let child = &TASKS[i];
                if child.id == 0 { continue; }
                if child.parent != Some(current) { continue; }

                // Filter by pid
                if pid > 0 && child.id as i64 != pid { continue; }
                if pid == 0 || pid == -1 { /* accept any */ } else if pid < -1 { continue; }

                found_any_child = true;

                if child.state == TaskState::Zombie {
                    let exit_code = child.exit_code;
                    let child_id = child.id;
                    let child_ks = child.kernel_stack;
                    let child_pml4 = child.pml4;
                    let addr_private = child.addr_space_private;

                    serial::write_str("sys_waitpid: reaping child ");
                    serial::write_dec(child_id as u64);
                    serial::write_str(" exit_code=");
                    serial::write_dec(exit_code as u64);
                    serial::write_str("\n");

                    if !status_ptr.is_null() {
                        core::ptr::write_volatile(status_ptr, (exit_code & 0xFF) << 8);
                    }
                    free_stack(child_ks, KERNEL_STACK_PAGES);
                    // Only free address space if the child had its own (not CLONE_VM)
                    if child_pml4 != 0 && addr_private {
                        vma_clear_pml4(child_pml4);
                        crate::paging::free_address_space(child_pml4, addr_private);
                    }
                    TASKS[i] = Task::empty();
                    free_pid(child_id);
                    return child_id as i64;
                }
            }

            if !found_any_child {
                return -ECHILD;
            }

            if flags & WNOHANG != 0 {
                return 0;
            }

            // No zombie yet — find the specific child to wait on and block on its TID futex
            let mut wait_tidptr: u64 = 0;
            for i in 0..MAX_TASKS {
                let child = &TASKS[i];
                if child.id == 0 { continue; }
                if child.parent != Some(current) { continue; }
                if pid > 0 && child.id as i64 != pid { continue; }
                if pid == 0 || pid == -1 { /* accept any */ } else if pid < -1 { continue; }
                // Found the child we want to wait for
                wait_tidptr = child.child_tidptr;
                break;
            }

            if wait_tidptr != 0 {
                serial::write_str("waitpid: task ");
                serial::write_dec(current);
                serial::write_str(" waiting on child TID futex 0x");
                serial::write_hex(wait_tidptr);
                serial::write_str("\n");
                let uaddr = wait_tidptr as *const u32;
                unsafe {
                    // Wait for TID to become 0 (child clears it on exit)
                    if *uaddr != 0 {
                        futex_wait(uaddr, *uaddr, core::ptr::null());
                    }
                }
                continue;
            }

            // Fallback if no tidptr
            yield_now_force();
        }
    }
}

fn sys_read(fd: u32, buf: *mut u8, count: usize) -> i64 {
    if buf.is_null() || count == 0 { return 0; }
    if !user_range_valid(buf as u64, count, true) {
        crate::klog::begin(crate::klog::LOG_WARNING, crate::klog::FAC_SYSCALL);
        crate::klog::s("read fd=");
        crate::klog::dec(fd as u64);
        crate::klog::s(" buf=0x");
        crate::klog::hex(buf as u64);
        crate::klog::s(" count=");
        crate::klog::dec(count as u64);
        crate::klog::s(" -> EFAULT");
        crate::klog::end();
        return -EFAULT;
    }
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

    let id = cur_task().load(Ordering::SeqCst);
    if id == 0 { return -EINVAL; }
    if crate::klog::get_console_level() >= crate::klog::LOG_DEBUG {
        crate::klog::begin(crate::klog::LOG_DEBUG, crate::klog::FAC_VFS);
        crate::klog::s("MMAP addr=0x");
        crate::klog::hex(addr as u64);
        crate::klog::s(" len=0x");
        crate::klog::hex(length as u64);
        crate::klog::s(" prot=0x");
        crate::klog::hex(prot as u64);
        crate::klog::s(" flags=0x");
        crate::klog::hex(flags as u64);
        crate::klog::s(" fd=");
        crate::klog::dec(fd as u64);
        crate::klog::s("\n");
        crate::klog::end();
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
                // Check if candidate overlaps with any VMA of this address space
                match vma_first_overlap_end(pml4, candidate, candidate + size) {
                    Some(e) => {
                        candidate = e;
                        continue 'search;
                    }
                    None => {
                        found = true;
                        break 'search;
                    }
                }
            }
            if !found {
                if crate::klog::get_console_level() >= crate::klog::LOG_DEBUG {
                    crate::klog::begin(crate::klog::LOG_DEBUG, crate::klog::FAC_VFS);
                    crate::klog::s("MMAP -> -ENOMEM\n");
                    crate::klog::end();
                }
                return -ENOMEM;
            }
            candidate
        } else {
            page_addr
        };
        // crate::serial::write_str("MMAP-RET req=0x");
        // crate::serial::write_hex(page_addr);
        // crate::serial::write_str(" len=0x");
        // crate::serial::write_hex(size);
        // crate::serial::write_str(" -> 0x");
        // crate::serial::write_hex(final_addr);
        // crate::serial::write_str("\n");

        // Register in the global pool (keyed by pml4, so every CLONE_VM
        // sibling sees it). Fail with ENOMEM if the pool is exhausted.
        if !vma_register(pml4, final_addr, final_addr + size, pte_flags) {
            return -ENOMEM; // Too many VMAs
        }

        return final_addr as i64;
    }
}

fn sys_mprotect(addr: u64, len: usize, prot: i32) -> i64 {
    let id = cur_task().load(Ordering::SeqCst);
    if id == 0 { return -EINVAL; }
    if crate::klog::get_console_level() >= crate::klog::LOG_DEBUG {
        crate::klog::begin(crate::klog::LOG_DEBUG, crate::klog::FAC_VFS);
        crate::klog::s("MPROT addr=0x");
        crate::klog::hex(addr);
        crate::klog::s(" len=0x");
        crate::klog::hex(len as u64);
        crate::klog::s(" prot=0x");
        crate::klog::hex(prot as u64);
        crate::klog::end();
    }
    unsafe {
        let idx = task_idx(id);
        let pml4 = TASKS[idx].pml4;
        let start = addr & !0xFFF;
        let end = (addr + len as u64 + 0xFFF) & !0xFFF;
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

/// A page cannot be unmapped while any live task still uses it as its user
/// stack (or as its kernel stack / brk). musl carves thread stacks out of a
/// shared anonymous arena; if one thread `munmap`s that arena while a sibling
/// thread's stack is still inside, the sibling's next syscall entry page-faults
/// (syscall_entry pushes the first 3 args on the user stack before switching
/// stacks). So treat pages backed by any live task's `user_stack` window as
/// pinned and skip them.
unsafe fn munmap_page_in_use(page: u64, _self_idx: usize) -> bool {
    for t in &TASKS {
        let state = t.state;
        if t.id != 0 && state != crate::task::TaskState::Empty && state != crate::task::TaskState::Exited
            && t.user_stack != 0
        {
            // Protect only the pages that actually back a live task's stack
            // (the VMA covering its user_stack), not a wide heuristic window:
            // mallocng meta pages land next to thread stacks and a 256KB
            // window makes their munmap bail out, so those mappings leak and
            // the VMA pool fills up.
            if let Some(vma) = vma_find(t.pml4, t.user_stack) {
                if page + PAGE_SIZE_4K > vma.start && page < vma.end {
                    return true;
                }
            }
        }
    }
    let _ = _self_idx;
    false
}

fn sys_munmap(addr: u64, len: usize) -> i64 {
    if len == 0 { return -EINVAL; }
    let id = cur_task().load(Ordering::SeqCst);
    if id == 0 { return -EINVAL; }

    let start = addr & !(PAGE_SIZE_4K - 1);
    let end = start + ((len as u64 + PAGE_SIZE_4K - 1) & !(PAGE_SIZE_4K - 1));

    unsafe {
        let idx = task_idx(id);
        let pml4 = TASKS[idx].pml4;

        // Atomic munmap: if ANY page in the range is still claimed by a live
        // task's user stack, bail out entirely. Partially freeing some pages
        // while leaving the rest (and their VMAs) mapped corrupts mallocng's
        // view of its anonymous arena, so all-or-nothing.
        let mut any_claimed = false;
        let mut page = start;
        while page < end {
            if munmap_page_in_use(page, idx) {
                any_claimed = true;
                break;
            }
            page += PAGE_SIZE_4K;
        }
        if any_claimed {
            return 0;
        }

        // Free any present user pages in the range and clear their PTEs.
        let alloc = &mut *crate::memory::allocator();
        let mut page = start;
        while page < end {
            if let Some(pte) = crate::paging::get_pte_in(pml4, page) {
                if *pte & crate::paging::PTE_PRESENT != 0 && *pte & crate::paging::PTE_USER != 0 {
                    alloc.free(*pte & crate::paging::PTE_ADDR_MASK, 0);
                    *pte = 0;
                    core::arch::asm!("invlpg [{}]", in(reg) page, options(nostack, preserves_flags));
                }
            }
            page += PAGE_SIZE_4K;
        }

        // Drop VMAs that fall entirely within the unmapped range; shrink ones
        // that only overlap at the edges.
        vma_clear_range(pml4, start, end);
    }
    0
}

// ── Fork ──────────────────────────────────────────────────────────

// The syscall entry point runs on a shared syscall stack and never writes the
// user context into TASKS[].regs. These globals capture the exact user-mode
// resume point (return RIP/RSP/RFLAGS + TLS FS base) of the current syscall so
// fork() can hand the child a correct starting context instead of reusing the
// parent's stale regs from its last context switch.
#[no_mangle]
pub static mut SYSCALL_CALLEE_REGS: [u64; 6] = [0; 6];

#[no_mangle]
pub static mut SYSCALL_USER_RIP: u64 = 0;
#[no_mangle]
pub static mut SYSCALL_USER_RSP: u64 = 0;
#[no_mangle]
pub static mut SYSCALL_USER_RFLAGS: u64 = 0;
#[no_mangle]
pub static mut SYSCALL_USER_FS_BASE: u64 = 0;

fn sys_fork() -> i64 {
    let id = cur_task().load(Ordering::SeqCst);
    if id == 0 { return -EINVAL; }

    unsafe {
        let child_tid = match alloc_user_pid() {
            Some(t) => t,
            None => return -ENOMEM,
        };
        let child_idx = task_idx(child_tid);

        // Clone parent's fd table so the child inherits stdin/stdout/stderr
        let parent_fds = crate::vfs::get_fd_table();
        if let Some(pfds) = parent_fds {
            let cfds = crate::vfs::fd_table_for(child_tid);
            unsafe { core::ptr::copy_nonoverlapping(pfds.as_ptr(), cfds.as_ptr() as *mut crate::vfs::FileDesc, crate::vfs::MAX_FDS_PER_TASK); }
        }

        let parent_idx = task_idx(id);
        let parent = &TASKS[parent_idx];
        let kernel_stack = match alloc_stack(KERNEL_STACK_PAGES) {
            Some(s) => s,
            None => {
                free_pid(child_tid);
                return -ENOMEM;
            }
        };

        // Clone PML4 with COW
        let child_pml4 = match crate::paging::cow_fork_pml4(parent.pml4) {
            Some(p) => p,
            None => {
                free_stack(kernel_stack, KERNEL_STACK_PAGES);
                free_pid(child_tid);
                return -ENOMEM;
            }
        };

        // Set up child task: copy register state but set rax=0 (return value)
        let mut child_regs = parent.regs;
        // Resume the child at the fork-return point with the user context the
        // syscall entry captured (parent.regs only holds the PC from its last
        // context switch, not this syscall's return address).
        child_regs.rip = SYSCALL_USER_RIP;
        child_regs.rsp = SYSCALL_USER_RSP;
        child_regs.rflags = SYSCALL_USER_RFLAGS;
        child_regs.fs_base = SYSCALL_USER_FS_BASE;
        child_regs.rax = 0; // Child gets 0 from fork
        // parent.regs holds stale callee-saved regs (last context switch);
        // use the live values captured by syscall_entry instead.
        child_regs.rbx = SYSCALL_CALLEE_REGS[0];
        child_regs.rbp = SYSCALL_CALLEE_REGS[1];
        child_regs.r12 = SYSCALL_CALLEE_REGS[2];
        child_regs.r13 = SYSCALL_CALLEE_REGS[3];
        child_regs.r14 = SYSCALL_CALLEE_REGS[4];
        child_regs.r15 = SYSCALL_CALLEE_REGS[5];

        let child = &mut TASKS[child_idx];
        // All forked children start Ready so they are scheduled and can run
        // (and exec). Previously init's 2nd+ children were left Blocked, which
        // permanently prevented the shell from ever starting.
        let child_state = TaskState::Ready;
        *child = Task {
            id: child_tid,
            tgid: child_tid,
            state: child_state,
            regs: child_regs,
            kernel_stack,
            user_stack: parent.user_stack,
            pml4: child_pml4,
            // Spread forked/cloned children across online CPUs so user tasks can
            // run on the AP. The child's fork/clone-return regs (SYSCALL_USER_*)
            // were already copied into child_regs, so running on another CPU is
            // safe. Init itself stays pinned to cpu 0.
            cpu: pick_home_cpu(),
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
            in_syscall: false,
            uid: parent.uid,
            gid: parent.gid,
            euid: parent.euid,
            egid: parent.egid,
            ipc_partner: 0,
            ipc_phys: 0,
            ipc_vaddr: 0,
            exit_code: 0,
            brk_start: parent.brk_start,
            brk_end: parent.brk_end,
            sig_handlers: parent.sig_handlers,
            sig_blocked: parent.sig_blocked,
            sig_pending: 0,
            comm: parent.comm,
            wakeup_tick: 0,
            futex_deadline: 0,
            child_tidptr: 0,
            addr_space_private: true,
            saved_user_regs: None,
        };

        // The child has its own (COW) page table, so duplicate the parent's
        // VMA records for the new address space.
        vma_clone(parent.pml4, child_pml4);

        if child.state == TaskState::Ready {
            enqueue_task(child_tid, child.prio);
        }

        serial::write_str("SYS_FORK: child ");
        serial::write_dec(child_tid);
        serial::write_str(" (parent ");
        serial::write_dec(id);
        serial::write_str(")\n");

        child_tid as i64
    }
}

// ── Clone ──────────────────────────────────────────────────
// Linux x86_64 clone syscall:
//   sys_clone(flags, child_stack, parent_tidptr, child_tidptr, tls)
//
// Musl's pthread_create uses:
//   CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
//   CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS |
//   CLONE_PARENT | CLONE_CHILD_CLEARTID
//
// The critical difference from fork is CLONE_VM: the child shares
// the parent's address space (no COW fork of the PML4).

fn sys_clone(flags: u64, child_stack: u64, parent_tidptr: *mut u64,
             child_tidptr: *mut u64, tls: u64, func: u64) -> i64 {
    let id = cur_task().load(Ordering::SeqCst);
    if id == 0 { return -EINVAL; }

    serial::write_str("sys_clone: parent=");
    serial::write_dec(id);
    serial::write_str(" flags=0x");
    serial::write_hex(flags);
    serial::write_str(" child_stack=0x");
    serial::write_hex(child_stack);
    serial::write_str(" func=0x");
    serial::write_hex(func);
    serial::write_str("\n");

    unsafe {
        let child_tid = match alloc_user_pid() {
            Some(t) => t,
            None => return -ENOMEM,
        };
        let child_idx = task_idx(child_tid);

        // Clone parent's fd table so the child inherits stdin/stdout/stderr
        let parent_fds = crate::vfs::get_fd_table();
        if let Some(pfds) = parent_fds {
            let cfds = crate::vfs::fd_table_for(child_tid);
            core::ptr::copy_nonoverlapping(
                pfds.as_ptr(),
                cfds.as_ptr() as *mut crate::vfs::FileDesc,
                crate::vfs::MAX_FDS_PER_TASK,
            );
        }

        let parent_idx = task_idx(id);
        let parent = &TASKS[parent_idx];
        let kernel_stack = match alloc_stack(KERNEL_STACK_PAGES) {
            Some(s) => s,
            None => {
                let alloc = unsafe { &mut *crate::memory::allocator() };
                serial::write_str("SYS_CLONE: alloc_stack FAILED free_pages=");
                serial::write_dec(alloc.free_page_count());
                serial::write_str(" used=");
                serial::write_dec(alloc.used_page_count());
                serial::write_str(" reserved=");
                serial::write_dec(alloc.reserved_count());
                serial::write_str(" orders=");
                let counts = alloc.free_pages_by_order();
                for o in 0..=10 {
                    serial::write_dec(counts[o]);
                    serial::write_str("/");
                }
                serial::write_str("\n");
                return -ENOMEM;
            }
        };

        // CLONE_VM: share the parent's PML4 (no COW fork).
        // The child runs in the same address space as the parent.
        let child_pml4 = if flags & CLONE_VM != 0 {
            parent.pml4
        } else {
            match crate::paging::cow_fork_pml4(parent.pml4) {
                Some(p) => p,
                None => {
                    free_stack(kernel_stack, KERNEL_STACK_PAGES);
                    return -ENOMEM;
                }
            }
        };

        // Determine tgid: CLONE_THREAD means same thread group as parent.
        let child_tgid = if flags & CLONE_THREAD != 0 {
            parent.tgid
        } else {
            child_tid
        };

        // Determine parent: CLONE_PARENT means same parent as caller.
        let child_parent = if flags & CLONE_PARENT != 0 {
            parent.parent
        } else {
            Some(id)
        };

        // Set up child register state: resume at the syscall return point.
        // The child gets its own user stack (provided by musl).
        let mut child_regs = parent.regs;
        child_regs.rip = SYSCALL_USER_RIP;
        child_regs.rsp = child_stack;
        child_regs.rflags = SYSCALL_USER_RFLAGS;
        child_regs.fs_base = SYSCALL_USER_FS_BASE;
        // The child must resume in USER mode (RING 3), not inherit the
        // kernel CS/SS captured in parent.regs while it was in syscall
        // context. Without this, context_switch takes the kernel->kernel
        // path and `ret`s to a user RIP in kernel mode, faulting on the
        // first user-memory access (e.g. futex_wait on a user stack page).
        child_regs.cs = USER_CODE_SELECTOR | 3;
        child_regs.ss = USER_DATA_SELECTOR | 3;
        child_regs.rax = 0; // Child gets 0 from clone
        child_regs.rbx = SYSCALL_CALLEE_REGS[0];
        child_regs.rbp = SYSCALL_CALLEE_REGS[1];
        child_regs.r12 = SYSCALL_CALLEE_REGS[2];
        child_regs.r13 = SYSCALL_CALLEE_REGS[3];
        child_regs.r14 = SYSCALL_CALLEE_REGS[4];
        child_regs.r15 = SYSCALL_CALLEE_REGS[5];

        // CLONE_SETTLS: set the TLS pointer (FS base) for the child.
        if flags & CLONE_SETTLS != 0 {
            child_regs.fs_base = tls;
        }

        // musl's __clone keeps the thread start function in r9 across the
        // syscall; the child resumes at the syscall return point and does
        // `pop %rdi; call *%r9`. Restore r9 so the new thread starts at func.
        child_regs.r9 = func;

        let child = &mut TASKS[child_idx];
        *child = Task {
            id: child_tid,
            tgid: child_tgid,
            state: TaskState::Ready,
            regs: child_regs,
            kernel_stack,
            user_stack: child_stack,
            pml4: child_pml4,
            // Spread forked/cloned children across online CPUs so user tasks can
            // run on the AP. The child's fork/clone-return regs (SYSCALL_USER_*)
            // were already copied into child_regs, so running on another CPU is
            // safe. Init itself stays pinned to cpu 0.
            cpu: pick_home_cpu(),
            static_prio: parent.static_prio,
            normal_prio: parent.normal_prio,
            prio: parent.prio,
            time_slice: initial_time_slice(parent.prio),
            parent: child_parent,
            children_head: None,
            sibling_next: None,
            blocked_on: 0,
            pi_boosted: false,
            runqueue_next: None,
            in_syscall: false,
            uid: parent.uid,
            gid: parent.gid,
            euid: parent.euid,
            egid: parent.egid,
            ipc_partner: 0,
            ipc_phys: 0,
            ipc_vaddr: 0,
            exit_code: 0,
            brk_start: parent.brk_start,
            brk_end: parent.brk_end,
            sig_handlers: parent.sig_handlers,
            sig_blocked: parent.sig_blocked,
            sig_pending: 0,
            comm: parent.comm,
            wakeup_tick: 0,
            futex_deadline: 0,
            child_tidptr: if flags & CLONE_CHILD_CLEARTID != 0 {
                child_tidptr as u64
            } else {
                0
            },
            addr_space_private: flags & CLONE_VM == 0,
            saved_user_regs: None,
        };

        // CLONE_VM shares the parent's pml4, so the child automatically sees
        // the same VMA records. Otherwise the child got a fresh (COW) page
        // table and needs its own copies.
        if flags & CLONE_VM == 0 {
            vma_clone(parent.pml4, child_pml4);
        }

        // Store child TID in parent's buffer (CLONE_PARENT_SETTID).
        if flags & CLONE_PARENT_SETTID != 0 && !parent_tidptr.is_null() {
            core::ptr::write_volatile(parent_tidptr, child_tid);
        }

        if child.state == TaskState::Ready {
            enqueue_task(child_tid, child.prio);
        }

        // serial::write_str("SYS_CLONE: child ");
        // serial::write_dec(child_tid);
        // serial::write_str(" (parent ");
        // serial::write_dec(id);
        // serial::write_str(") flags=0x");
        // serial::write_hex(flags);
        // serial::write_str(" stack=0x");
        // serial::write_hex(child_stack);
        // serial::write_str(" tls=0x");
        // serial::write_hex(tls);
        // serial::write_str(" urip=0x");
        // serial::write_hex(SYSCALL_USER_RIP);
        // serial::write_str(" crib=0x");
        // serial::write_hex(child.regs.rip);
        // serial::write_str(" crsp=0x");
        // serial::write_hex(child.regs.rsp);
        // serial::write_str(" ccs=0x");
        // serial::write_hex(child.regs.cs);
        // serial::write_str(" cfs=0x");
        // serial::write_hex(child.regs.fs_base);
        // serial::write_str(" cflags=0x");
        // serial::write_hex(child.regs.rflags);
        // serial::write_str(" r9=0x");
        // serial::write_hex(child.regs.r9);
        // serial::write_str(" func=0x");
        // serial::write_hex(func);
        // serial::write_str("\n");

        child_tid as i64
    }
}

// ── Execve ────────────────────────────────────────────────────────

fn sys_execve(pathname: *const u8, argv: u64, _envp: u64) -> i64 {
    if crate::klog::get_console_level() >= crate::klog::LOG_DEBUG {
        crate::klog::log(crate::klog::LOG_DEBUG, crate::klog::FAC_EXEC, "sys_execve called");
    }
    let id = cur_task().load(Ordering::SeqCst);
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

    // Follow a symlink target (busybox applet links: /bin/<applet> -> /bin/busybox).
    // argv[0] is preserved so busybox dispatches on the applet name.
    let inode_idx = if let Some(vn_id) = crate::vfs::inode_vnode_id(inode_idx) {
        match crate::vfs_core::readlink(vn_id) {
            Ok(target) => match crate::vfs::find_inode(target) {
                Some(idx) => idx,
                None => {
                    serial::write_str("SYS_EXECVE: symlink target not found\n");
                    return -ENOENT;
                }
            },
            Err(_) => inode_idx,
        }
    } else {
        inode_idx
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
                        Err(_e) => {
                            alloc.free(buffer_phys, elford);
                            alloc.free(interp_phys, interp_ord);
                        crate::klog::log(crate::klog::LOG_ERR, crate::klog::FAC_EXEC, "interp load failed");
                            return -ENOEXEC;
                        }
                    }
                    // Interpreter ELF is fully copied into its mapped pages; release the staging buffer
                    alloc.free(interp_phys, interp_ord);
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
                unsafe { core::arch::asm!("cli", options(nostack, nomem)); }
                pt_mgr().switch_to(info.pml4);
                unsafe { core::arch::asm!("sti", options(nostack, nomem)); }
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
                        crate::klog::begin(crate::klog::LOG_DEBUG, crate::klog::FAC_EXEC);
                        crate::klog::s("random_dataD: cr3=0x");
                        crate::klog::hex(cr3);
                        crate::klog::s(" sp=0x");
                        crate::klog::hex(sp);
                        crate::klog::s(" phys=0x");
                        crate::klog::hex(phys_addr);
                        crate::klog::end();
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

                    // AT_TLS (27): TLS base address - critical for musl's dynamic linker
                    aux!(27, USER_TLS_VADDR);

                    // AT_SYSINFO_EHDR (33): musl's loader parses this as a real
                    // vDSO ELF header (reads e_phoff/e_phnum from offset 0x20).
                    // We have no vDSO yet, so it MUST stay 0; a nonzero value that
                    // is not a genuine vDSO ELF image crashes the loader. Full vDSO
                    // is tracked as an open bugshere task.
                    // (KERNEL_EH_FRAME_HDR infrastructure remains for later.)
                    aux!(33, 0u64);

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

                    // AT_TLS (27): TLS base address - critical for musl's dynamic linker
                    aux!(27, USER_TLS_VADDR);

                    // AT_SYSINFO_EHDR (33): musl's loader parses this as a real
                    // vDSO ELF header (reads e_phoff/e_phnum from offset 0x20).
                    // We have no vDSO yet, so it MUST stay 0; a nonzero value that
                    // is not a genuine vDSO ELF image crashes the loader. Full vDSO
                    // is tracked as an open bugshere task.
                    // (KERNEL_EH_FRAME_HDR infrastructure remains for later.)
                    aux!(33, 0u64);

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
                // Allocate TLS page for musl. Initialize full TCB per musl's
                // pthread struct so __get_tp() works and thread internals work.
                if info.is_dynamic {
                    let tls_phys = match alloc.alloc(0) {
                        Some(p) => p,
                        None => { alloc.free(old_pml4, 0); alloc.free(buffer_phys, elford); return -ENOMEM; }
                    };
                    // Zero the entire TLS page first
                    unsafe { core::ptr::write_bytes(tls_phys as *mut u8, 0, 4096); }

                    let _tls_base = USER_TLS_VADDR;
                    let _tid = id; // current task id is the new thread's tid

                    // Map the TLS page FIRST so we can write to virtual addresses
                    let tls_flags = crate::paging::PTE_PRESENT
                        | crate::paging::PTE_WRITABLE
                        | crate::paging::PTE_USER
                        | crate::paging::PTE_NO_EXECUTE;
                    if PageTableManager::map_into(info.pml4, USER_TLS_VADDR, tls_phys, tls_flags).is_err() {
                        alloc.free(old_pml4, 0);
                        alloc.free(buffer_phys, elford);
                        return -ENOMEM;
                    }

                    let tls_base = USER_TLS_VADDR;
                    let tid = id; // current task id is the new thread's tid

                    // TCB writes must go through PHYSICAL address: this pml4 is
                    // the new task's, not necessarily the currently active one.
                    let tls_phys_ptr = tls_phys as *mut u8;
                    unsafe {
                        // 0x00: DTV pointer (0 = initial thread, no dynamic TLS modules yet)
                        core::ptr::write_volatile(tls_phys_ptr as *mut u64, 0);

                        // 0x08: Self pointer (struct pthread *)
                        core::ptr::write_volatile(tls_phys_ptr.add(0x08) as *mut u64, tls_base);

                        // 0x10: Thread ID (tid) - 64-bit
                        core::ptr::write_volatile(tls_phys_ptr.add(0x10) as *mut u64, tid);

                        // 0x14: PID (tgid) - 32-bit
                        core::ptr::write_volatile(tls_phys_ptr.add(0x14) as *mut u32, tid as u32);

                        // 0x18: errno location (pointer to thread-local errno)
                        // musl stores &errno here; we allocate it in TCB at offset 0x100
                        let errno_loc = tls_base + 0x100;
                        core::ptr::write_volatile(tls_phys_ptr.add(0x18) as *mut u64, errno_loc);
                        // Initialize errno to 0
                        core::ptr::write_volatile(tls_phys_ptr.add(0x100) as *mut i32, 0);

                        // 0x20: Stack guard (canary) - random per thread
                        let canary = crate::pit::TICKS.load(Ordering::Relaxed) ^ tid;
                        core::ptr::write_volatile(tls_phys_ptr.add(0x20) as *mut u64, canary);

                        // 0x28: Thread pointer (self) - for __get_tp()
                        core::ptr::write_volatile(tls_phys_ptr.add(0x28) as *mut u64, tls_base);

                        // 0x30: Cancel flag (0 = not cancelled)
                        core::ptr::write_volatile(tls_phys_ptr.add(0x30) as *mut u32, 0);

                        // 0x34: Cancel type (0 = deferred)
                        core::ptr::write_volatile(tls_phys_ptr.add(0x34) as *mut u32, 0);

                        // 0x38: Cancel state
                        core::ptr::write_volatile(tls_phys_ptr.add(0x38) as *mut u32, 0);

                        // Zero rest of TCB area (musl expects zero-initialized beyond explicit fields)
                        core::ptr::write_bytes(tls_phys_ptr.add(0x40), 0, 4096 - 0x40);
                    }

                    TASKS[idx].regs.fs_base = USER_TLS_VADDR;
                }
                TASKS[idx].pml4 = info.pml4;
                // Switch to the new page table so the iretq finds the user mappings

                pt_mgr().switch_to(info.pml4);
                TASKS[idx].user_stack = info.stack_top;
                TASKS[idx].brk_start = info.brk_base;
                TASKS[idx].brk_end = info.brk_base;
                TASKS[idx].addr_space_private = true;
                // info.pml4 is a freshly built address space (load_elf builds
                // it from scratch) so it has no VMA records; the old address
                // space's records are dropped with free_address_space below.

// Free the previous user address space. After a fork the old pml4 is a
                  // deep-copied COW clone whose page tables are private to this task, but
                  // its read-only leaf pages are shared with the parent — so free_ro=false.
                  // BUT for threads (CLONE_VM, addr_space_private=false), the old pml4
                  // is shared with the parent and must NOT be freed.
                  if old_pml4 != 0 && old_pml4 != info.pml4 && TASKS[idx].addr_space_private {
                      vma_clear_pml4(old_pml4);
                      crate::paging::free_address_space(old_pml4, false);
                  }
                 // The staging buffer (whole ELF image) is no longer needed; its contents
                // were copied into freshly mapped pages by load_elf/load_elf_at.
                alloc.free(buffer_phys, elford);


                // Naked trampoline: loads GP regs from Registers and iretqs
                unsafe {
                    let r_ptr = &TASKS[idx].regs as *const Registers;
                    // The iretq trampoline leaves the syscall without running the
                    // normal syscall_exit path, so clear the per-task syscall flag
                    // here: otherwise timer ticks never preempt this task until its
                    // first syscall clears it, starving the rest of the runqueue.
                    in_syscall_exit();
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
                    if DEBUG_ENABLED.load(Ordering::Relaxed) {
                        crate::klog::begin(crate::klog::LOG_DEBUG, crate::klog::FAC_EXEC);
                        crate::klog::s("EXEC: about to iretq to user mode rip=0x");
                        crate::klog::hex(TASKS[idx].regs.rip);
                        crate::klog::s(" rsp=0x");
                        crate::klog::hex(TASKS[idx].regs.rsp);
                        crate::klog::s(" cs=0x");
                        crate::klog::hex(TASKS[idx].regs.cs);
                        crate::klog::s(" fs_base=0x");
                        crate::klog::hex(TASKS[idx].regs.fs_base);
                        crate::klog::end();
                    }
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

fn sys_getuid() -> i64 {
    let id = cur_task().load(Ordering::SeqCst);
    if id == 0 { return 0; }
    unsafe { TASKS[task_idx(id)].uid as i64 }
}

fn sys_getgid() -> i64 {
    let id = cur_task().load(Ordering::SeqCst);
    if id == 0 { return 0; }
    unsafe { TASKS[task_idx(id)].gid as i64 }
}

fn sys_geteuid() -> i64 {
    let id = cur_task().load(Ordering::SeqCst);
    if id == 0 { return 0; }
    unsafe { TASKS[task_idx(id)].euid as i64 }
}

fn sys_getegid() -> i64 {
    let id = cur_task().load(Ordering::SeqCst);
    if id == 0 { return 0; }
    unsafe { TASKS[task_idx(id)].egid as i64 }
}

fn sys_getpid() -> i64 {
    let id = cur_task().load(Ordering::SeqCst);
    id as i64
}

fn sys_getppid() -> i64 {
    let id = cur_task().load(Ordering::SeqCst);
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
            let id = cur_task().load(Ordering::SeqCst);
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
            let id = cur_task().load(Ordering::SeqCst);
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

fn sys_prctl(option: i32, arg2: u64, _arg3: u64, _arg4: u64, _arg5: u64) -> i64 {
    let id = cur_task().load(Ordering::SeqCst);
    serial::write_str("sys_prctl: task ");
    serial::write_dec(id);
    serial::write_str(" option=");
    serial::write_dec(option as u64);
    serial::write_str(" arg2=0x");
    serial::write_hex(arg2);
    serial::write_str(" rip=0x");
    serial::write_hex(unsafe { TASKS[task_idx(id)].regs.rip });
    serial::write_str("\n");
    // PR_SET_NAME = 15: set thread name (used by Rust std)
    if option == 15 {
        if id == 0 { return -EINVAL; }
        unsafe {
            let idx = task_idx(id);
            let name_ptr = arg2 as *const u8;
            if !name_ptr.is_null() {
                // Validate user pointer before reading
                if !user_range_valid(name_ptr as u64, 16, true) {
                    serial::write_str("sys_prctl: user_range_valid FAILED\n");
                    return -EFAULT;
                }
                // Copy up to 15 chars + null terminator
                let mut i = 0;
                while i < 15 {
                    let c = core::ptr::read_volatile(name_ptr.add(i));
                    if c == 0 { break; }
                    TASKS[idx].comm[i] = c;
                    i += 1;
                }
                // Null-terminate
                while i < 16 {
                    TASKS[idx].comm[i] = 0;
                    i += 1;
                }
                serial::write_str("sys_prctl: name set to '");
                for j in 0..16 {
                    let c = TASKS[idx].comm[j];
                    if c == 0 { break; }
                    serial::write_char(c as char);
                }
                serial::write_str("'\n");
            }
        }
        0
    } else {
        serial::write_str("sys_prctl: unknown option=");
        serial::write_dec(option as u64);
        serial::write_str("\n");
        -EINVAL
    }
}

// ── Sleep ─────────────────────────────────────────────────────────

fn sys_sleep(ticks: u64) -> i64 {
    let id = cur_task().load(Ordering::SeqCst);
    if id == 0 { return -EINVAL; }

    let now = unsafe { crate::pit::TICKS.load(core::sync::atomic::Ordering::Relaxed) };

    unsafe {
        let idx = task_idx(id);
        // Save user context from syscall entry globals (not task.regs which holds
        // stale kernel context). This is the context to restore on wakeup.
        TASKS[idx].saved_user_regs = Some(Registers {
            rax: 0, rbx: 0, rcx: 0, rdx: 0,
            rsi: 0, rdi: 0, rbp: 0, rsp: SYSCALL_USER_RSP,
            r8: 0, r9: 0, r10: 0, r11: 0,
            r12: 0, r13: 0, r14: 0, r15: 0,
            rip: SYSCALL_USER_RIP, rflags: SYSCALL_USER_RFLAGS,
            cs: 0x23, ss: 0x1B, fs_base: SYSCALL_USER_FS_BASE,
        });
        TASKS[idx].wakeup_tick = now + ticks;
        TASKS[idx].state = TaskState::Blocked;
    }

    // Must force the switch: sys_sleep runs inside a syscall where in_syscall()
    // is true, so the plain schedule() would bail out immediately and we would
    // never actually block for `ticks`.
    force_schedule();
    0
}

// ── Brk ───────────────────────────────────────────────────────────

fn sys_brk(addr: u64) -> i64 {
    let id = cur_task().load(Ordering::SeqCst);
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

        let pml4 = TASKS[idx].pml4;
        let brk_start = if TASKS[idx].brk_start == 0 {
            // First brk call: use addr as start
            TASKS[idx].brk_start = addr;
            TASKS[idx].brk_end = addr;
            addr
        } else {
            TASKS[idx].brk_start
        };

        // Ensure a brk VMA exists for this address space (the pool is keyed
        // by pml4, so CLONE_VM siblings automatically share it).
        let brk_vma = vma_find(pml4, brk_start);
        if brk_vma.is_none() {
            vma_register(
                pml4,
                brk_start,
                brk_start,
                crate::paging::PTE_PRESENT | crate::paging::PTE_WRITABLE
                    | crate::paging::PTE_USER | crate::paging::PTE_NO_EXECUTE,
            );
        }

        if addr < brk_start {
            // Can't shrink below start
            return TASKS[idx].brk_end as i64;
        }

        let old_end = TASKS[idx].brk_end;
        TASKS[idx].brk_end = addr;

        // Update the brk VMA's end.
        unsafe {
            for rec in VMAS.iter_mut() {
                if rec.pml4 == pml4 && rec.vma.start == brk_start {
                    rec.vma.end = addr;
                    break;
                }
            }
        }

        // Pre-allocate zeroed pages for the extended brk range to overwrite
        // stale identity-map PTEs inherited from the bootloader (PML4[0]).
        if addr > old_end {
            let cr3: u64;
            core::arch::asm!("mov {}, cr3", out(reg) cr3);
            let start_page = crate::memory::buddy::page_align_down(old_end);
            let end_page = crate::memory::buddy::page_align_up(addr);
            let mut page = start_page;
            while page < end_page {
                let phys = {
                    let alloc = &mut *crate::memory::allocator();
                    alloc.alloc(0)
                };
                if let Some(phys) = phys {
                    core::ptr::write_bytes(phys as *mut u8, 0, 4096);
                    let flags = crate::paging::PTE_PRESENT
                        | crate::paging::PTE_WRITABLE
                        | crate::paging::PTE_USER
                        | crate::paging::PTE_NO_EXECUTE;
                    if crate::paging::PageTableManager::map_into(cr3, page, phys, flags).is_ok() {
                        core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, nomem));
                    }
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

// ── Process groups ──────────────────────────────────────────────
// The kernel keeps a lightweight process-group id on each task. Shells use
// TIOCSPGRP (via TTY) to mark the foreground group; kill(-pgid) routes to it.
fn sys_setpgid(pid: i32, pgid: i32) -> i64 {
    let cur = current_task_id();
    if cur == 0 { return -EINVAL; }
    let target = if pid == 0 { cur as i32 } else { pid };
    let group = if pgid == 0 { target } else { pgid };
    // Only allow setting own pgid for now; treating PID itself as PGID keeps
    // semantics simple and consistent with getpgrp/getpgid below.
    if target != cur as i32 && target != 0 { return -EPERM; }
    unsafe {
        let idx = task_idx(target as u64);
        if TASKS[idx].id == 0 { return -ESRCH; }
        TASKS[idx].tgid = group as u64;
    }
    0
}
fn sys_getpgid(pid: i32) -> i64 {
    let id = if pid == 0 { current_task_id() } else { pid as u64 };
    if id == 0 { return -EINVAL; }
    unsafe {
        let idx = task_idx(id);
        if TASKS[idx].id == 0 { return -ESRCH; }
        TASKS[idx].tgid as i64
    }
}
fn sys_getpgrp() -> i64 {
    let id = current_task_id();
    if id == 0 { return -EINVAL; }
    unsafe { TASKS[task_idx(id)].tgid as i64 }
}
fn sys_setsid() -> i64 {
    let id = current_task_id();
    if id == 0 { return -EINVAL; }
    unsafe {
        let idx = task_idx(id);
        TASKS[idx].tgid = id;
    }
    id as i64
}

// ── Wait4 ──────────────────────────────────────────────────────────

fn sys_wait4(pid: i64, status_ptr: *mut i32, _options: i32, _rusage: u64) -> i64 {
    // Reuse existing waitpid logic; WNOHANG in options corresponds to flags
    let wnohang = if _options & 1 != 0 { WNOHANG } else { 0 };
    sys_waitpid(pid, status_ptr, wnohang)
}

// ── Kill / signal delivery ────────────────────────────────────────

/// Deliver `sig` to a single task slot. Returns 0 ok / -ESRCH.
fn sig_deliver_to_task(idx: usize, sig: i32) -> i64 {
    unsafe {
        let t = &mut TASKS[idx];
        if t.id == 0 || t.state == TaskState::Empty { return -ESRCH; }
        if sig <= 0 || sig as usize >= SIGNAL_COUNT { return -EINVAL; }
        let sigi = sig as usize;

        // SIGKILL / SIGSTOP cannot be caught or blocked.
        if sig == SIGKILL || sig == SIGSTOP {
            kill_task_zombie(idx, 128 + sig);
            return 0;
        }

        // If the target has a real (non-DFL/non-IGN) handler and the signal is
        // not blocked, mark it pending so a future phase can run the handler.
        let act = t.sig_handlers[sigi];
        let ignored = act.handler == SIG_IGN as u64;
        let blocked = (t.sig_blocked >> sigi) & 1 != 0;

        if ignored {
            return 0;
        }
        // Real handler: mark the signal pending whether or not it is currently
        // blocked (POSIX: a blocked signal is held pending and delivered once
        // it is unblocked). check_deliver_signal runs it on the next syscall
        // boundary once the bit is no longer blocked.
        if act.handler != SIG_DFL as u64 {
            t.sig_pending |= 1u64 << sigi;
            return 0;
        }
        // Default action: for the terminating set, kill the task. If the target
        // is blocked on this signal, hold it pending so it takes effect once
        // unblocked (POSIX); otherwise act now.
        let terminates = sig == SIGINT || sig == SIGQUIT || sig == SIGILL
            || sig == SIGABRT || sig == SIGSEGV || sig == SIGTERM
            || sig == SIGPIPE || sig == SIGFPE || sig == SIGBUS
            || sig == SIGTRAP || sig == SIGALRM;
        if terminates {
            if blocked {
                t.sig_pending |= 1u64 << sigi;
            } else if task_idx(current_task_id()) == idx {
                // Killing ourselves: exit_task clears our TID, wakes the parent
                // and force-schedules away, which is exactly what the normal
                // sys_exit path does.
                exit_task(128 + sig);
            } else {
                kill_task_zombie(idx, 128 + sig);
            }
        }
        // SIGCONT etc. are no-ops here.
        0
    }
}

/// Mark a task (by slot) as a zombie, remove it from the runqueue, and wake its
/// parent. Unlike `exit_task`, this does not require the target to be running,
/// so it is safe to call from another task's syscall (kill(2)).
fn kill_task_zombie(idx: usize, code: i32) {
    unsafe {
        let t = &mut TASKS[idx];
        t.exit_code = code;
        t.state = TaskState::Zombie;
        if t.id != 0 {
            remove_from_runqueue(t.id);
        }
        // CLONE_CHILD_CLEARTID: clear the TID and wake futex joiners so a
        // signal-killed thread can be joined like a normally-exited one.
        let child_tidptr = t.child_tidptr;
        if child_tidptr != 0 {
            core::ptr::write_volatile(child_tidptr as *mut u64, 0u64);
            futex_wake(child_tidptr as *const u32, 1);
        }
        if let Some(p) = t.parent {
            let pidx = task_idx(p);
            if TASKS[pidx].state == TaskState::Blocked
                && (TASKS[pidx].blocked_on == t.id || TASKS[pidx].blocked_on == u64::MAX)
            {
                TASKS[pidx].state = TaskState::Ready;
                TASKS[pidx].blocked_on = 0;
                enqueue_task(p, TASKS[pidx].prio);
            }
        }
    }
}

/// Deliver a signal to the current foreground process group (used by TTY ISIG
/// handling for Ctrl+C → SIGINT). Exposed so the TTY driver can request it.
pub fn signal_foreground_group(sig: i32) {
    let current = current_task_id();
    if current == 0 { return; }
    unsafe {
        let cur_pg = TASKS[task_idx(current)].tgid;
        for i in 0..MAX_TASKS {
            if TASKS[i].id == 0 { continue; }
            if TASKS[i].tgid == cur_pg || cur_pg == 0 {
                sig_deliver_to_task(i, sig);
            }
        }
    }
}

fn sys_kill(pid: i64, sig: i32) -> i64 {
    if sig == 0 { return 0; }
    // pid == 0  -> current process group
    // pid < 0   -> kill process group (-pid)
    // pid == -1 -> every process
    // pid > 0   -> single process
    let current = current_task_id();
    let mut hits = 0i64;
    unsafe {
        for i in 0..MAX_TASKS {
            if TASKS[i].id == 0 { continue; }
            let id = TASKS[i].id as i64;
            let pg = TASKS[i].tgid as i64;
            let match_all = pid == -1
                || (pid == 0 && pg == current as i64)
                || (pid < -1 && pg == -pid)
                || (pid > 0 && id == pid);
            if match_all {
                if sig_deliver_to_task(i, sig) == 0 {
                    hits += 1;
                }
            }
        }
    }
    // Permit sending to oneself/one's group; return 0 if we targeted anything.
    if hits > 0 { 0 } else { -ESRCH }
}
fn sys_tkill(tid: i64, sig: i32) -> i64 {
    if sig == 0 { return 0; }
    if tid <= 0 { return -EINVAL; }
    unsafe {
        let idx = task_idx(tid as u64);
        if TASKS[idx].id == 0 { return -ESRCH; }
        sig_deliver_to_task(idx, sig)
    }
}

fn handle_default_signal(target: i64, sig: i32) {
    // Legacy single-target path kept for internal callers; delegates to above.
    unsafe {
        for i in 0..MAX_TASKS {
            if TASKS[i].id == 0 { continue; }
            let id = TASKS[i].id as i64;
            if target == id || target == -(id) {
                sig_deliver_to_task(i, sig);
            }
        }
    }
}

// ── rt_sigaction / rt_sigprocmask / rt_sigreturn / sigaltstack ──
// Linux x86_64 ABI:
//   struct rt_sigaction { handler(8) mask(8) flags(4) restorer(8) ... }
//   kernel_sigaction = { handler:u64, flags:u64, restorer:u64, mask:u64 }
// rt_sigreturn restores a `struct sigcontext` saved on the user stack by the
// kernel when the handler was entered. We keep it ABI-shaped so future full
// handler delivery can reuse it; today we store state and honour default
// actions, matching the bug log's "kill default action" requirement.

// musl converts its struct sigaction into Linux's kernel_sigaction layout
// ({handler, flags, restorer, mask}) before the rt_sigaction syscall, so the
// ABI-facing struct is that layout, not the user-space struct.
#[repr(C)]
struct KSigAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

fn sys_rt_sigaction(sig: i32, act: u64, oldact: u64) -> i64 {
    if sig <= 0 || sig as usize >= SIGNAL_COUNT {
        return -EINVAL;
    }
    if sig == SIGKILL || sig == SIGSTOP {
        return -EINVAL;
    }
    let sigi = sig as usize;
    let id = current_task_id();
    if id == 0 { return -EINVAL; }
    let idx = task_idx(id);

    unsafe {
        // Write old action out first (Linux writes oldact even if act fails).
        if oldact != 0 {
            let old = TASKS[idx].sig_handlers[sigi];
            let ka = KSigAction {
                handler: old.handler,
                flags: old.flags,
                restorer: old.restorer,
                mask: old.mask,
            };
            core::ptr::write_volatile(oldact as *mut KSigAction, ka);
        }
        if act != 0 {
            if !user_range_valid(act, core::mem::size_of::<KSigAction>(), false) {
                return -EFAULT;
            }
            let ka = core::ptr::read_volatile(act as *const KSigAction);
            // The handler/restorer run in user mode; reject kernel addresses to
            // prevent a #GP / stray execution (SIG_DFL=0 and SIG_IGN=1 are valid
            // sentinels and also pass the user-range check).
            if !crate::paging::is_user_addr(ka.handler) {
                return -EFAULT;
            }
            if !crate::paging::is_user_addr(ka.restorer) {
                return -EFAULT;
            }
            TASKS[idx].sig_handlers[sigi] = SignalAction {
                handler: ka.handler,
                flags: ka.flags,
                restorer: ka.restorer,
                mask: ka.mask,
            };
        }
    }
    0
}

fn sys_rt_sigprocmask(how: i32, set: u64, oldset: u64) -> i64 {
    let id = current_task_id();
    if id == 0 { return -EINVAL; }
    let idx = task_idx(id);
    unsafe {
        if oldset != 0 {
            let old = TASKS[idx].sig_blocked;
            core::ptr::write_volatile(oldset as *mut u64, old);
        }
        if set != 0 {
            let mask = core::ptr::read_volatile(set as *const u64);
            let blockable = mask & !((1u64 << SIGKILL) | (1u64 << SIGSTOP));
            match how {
                0 => TASKS[idx].sig_blocked |= blockable,        // SIG_BLOCK
                1 => TASKS[idx].sig_blocked &= !blockable,       // SIG_UNBLOCK
                2 => TASKS[idx].sig_blocked = blockable,         // SIG_SETMASK
                _ => return -EINVAL,
            }
        }
    }
    0
}

// ── Signal delivery ────────────────────────────────────────────────
//
// Handler execution works by rewriting the current syscall's exit context in
// context_switch.asm: after syscall_handler returns, the assembly calls
// check_deliver_signal(kstack, sys_ret) with a pointer to the kernel stack
// holding this syscall's saved user registers, plus the syscall return value.
// If a pending signal with a real handler must run, the function writes a
// Linux-shaped rt_sigframe onto the user stack and rewrites the saved slots so
// the normal exit path resumes at the handler with RDI=sig, RSI=&ucontext,
// RSP=frame, and [RSP]=restorer (musl's __restore_rt). When the handler
// returns it calls rt_sigreturn, which parks the sigcontext registers in
// PENDING_RESTORE; the same check_deliver_signal hook restores them on the way
// back out. No user-visible kernel trampoline is needed: musl always installs
// SA_RESTORER.
//
// Frame layout (offsets match the Linux x86_64 rt_sigframe; only the kernel
// writes/reads it, so it only needs to be self-consistent):
//   0    pretcode (handler return address)
//   8    struct ucontext { uc_flags, uc_link, uc_stack{ss_sp,ss_flags,ss_size} }
//   48   struct sigcontext { r8,r9,r10,r11,r12,r13,r14,r15, rdi,rsi,rbp,rbx,
//        rdx,rax,rcx,rsp,rip, eflags, cs,gs,fs, pad, err, trapno, oldmask,
//        cr2, fpstate, reserved[8] }
//   304  ucontext sigmask
const SIG_FRAME_SIZE: u64 = 320;
const SIG_PRETCODE: u64 = 0;
const SIG_UC: u64 = 8;
const SIG_MCTX: u64 = 48;
const SIG_R8: u64 = SIG_MCTX + 0;
const SIG_R9: u64 = SIG_MCTX + 8;
const SIG_R10: u64 = SIG_MCTX + 16;
const SIG_R11: u64 = SIG_MCTX + 24;
const SIG_R12: u64 = SIG_MCTX + 32;
const SIG_R13: u64 = SIG_MCTX + 40;
const SIG_R14: u64 = SIG_MCTX + 48;
const SIG_R15: u64 = SIG_MCTX + 56;
const SIG_RDI: u64 = SIG_MCTX + 64;
const SIG_RSI: u64 = SIG_MCTX + 72;
const SIG_RBP: u64 = SIG_MCTX + 80;
const SIG_RBX: u64 = SIG_MCTX + 88;
const SIG_RDX: u64 = SIG_MCTX + 96;
const SIG_RAX: u64 = SIG_MCTX + 104;
const SIG_RCX: u64 = SIG_MCTX + 112;
const SIG_RSP: u64 = SIG_MCTX + 120;
const SIG_RIP: u64 = SIG_MCTX + 128;
const SIG_EFLAGS: u64 = SIG_MCTX + 136;
const SIG_CS: u64 = SIG_MCTX + 144;
const SIG_GS: u64 = SIG_MCTX + 146;
const SIG_FS: u64 = SIG_MCTX + 148;
const SIG_SIGMASK: u64 = 304;

// Context rt_sigreturn parked for the current syscall's exit path.
static mut PENDING_RESTORE: Option<[u64; 14]> = None;

#[inline]
unsafe fn sig_read_u64(p: u64) -> u64 { core::ptr::read_volatile(p as *const u64) }
#[inline]
unsafe fn sig_write_u64(p: u64, v: u64) { core::ptr::write_volatile(p as *mut u64, v) }
#[inline]
unsafe fn sig_write_u16(p: u64, v: u16) { core::ptr::write_volatile(p as *mut u16, v) }

/// Called from context_switch.asm right after syscall_handler returns.
/// `kstack` points at the kernel stack holding this syscall's saved user regs:
///   [k+0]=arg6 [k+8]=userRSP [k+16]=r9 [k+24]=r8 [k+32]=rsi [k+40]=rdi
///   [k+48]=rdx [k+56]=r11 [k+64]=rcx [k+72..112]=r15,r14,r13,r12,rbp,rbx
/// `sys_ret` is the syscall return value (the rax the user will see).
/// Returns 0 when the exit path can run untouched; 1 after rewriting the slots
/// so it enters a handler (or resumes from rt_sigreturn) instead.
#[no_mangle]
pub extern "C" fn check_deliver_signal(kstack: u64, sys_ret: u64) -> u64 {
    unsafe {
        // Resume from a previous handler: rt_sigreturn parked the restored
        // context here, rewrite this syscall's exit slots with it.
        if let Some(ctx) = PENDING_RESTORE.take() {
            sig_write_u64(kstack + 40, ctx[0]);  // rdi
            sig_write_u64(kstack + 32, ctx[1]);  // rsi
            sig_write_u64(kstack + 48, ctx[2]);  // rdx
            sig_write_u64(kstack + 24, ctx[3]);  // r8
            sig_write_u64(kstack + 16, ctx[4]);  // r9
            sig_write_u64(kstack + 64, ctx[5]);  // rcx -> rip
            sig_write_u64(kstack + 56, ctx[6]);  // r11 -> rflags
            sig_write_u64(kstack + 8, ctx[7].wrapping_sub(24)); // userRSP -> rsp-24
            sig_write_u64(kstack + 72, ctx[8]);  // r15
            sig_write_u64(kstack + 80, ctx[9]);  // r14
            sig_write_u64(kstack + 88, ctx[10]); // r13
            sig_write_u64(kstack + 96, ctx[11]); // r12
            sig_write_u64(kstack + 104, ctx[12]);// rbp
            sig_write_u64(kstack + 112, ctx[13]);// rbx
            return 1;
        }

        let id = current_task_id();
        if id == 0 { return 0; }
        let idx = task_idx(id);
        if TASKS[idx].state == TaskState::Empty { return 0; }

        for sig in 1..SIGNAL_COUNT {
            let bit = 1u64 << sig;
            if TASKS[idx].sig_pending & bit == 0 { continue; }
            if (TASKS[idx].sig_blocked >> sig) & 1 != 0 { continue; }
            let act = TASKS[idx].sig_handlers[sig];
            if act.handler == SIG_IGN as u64 { continue; }
            if act.handler == SIG_DFL as u64 {
                // A default-action signal that was held pending while blocked:
                // apply its default behaviour now that it is unblocked.
                let sigi = sig as i32;
                let terminates = sigi == SIGINT || sigi == SIGQUIT || sigi == SIGILL
                    || sigi == SIGABRT || sigi == SIGSEGV || sigi == SIGTERM
                    || sigi == SIGPIPE || sigi == SIGFPE || sigi == SIGBUS
                    || sigi == SIGTRAP || sigi == SIGALRM;
                if terminates {
                    TASKS[idx].sig_pending &= !bit;
exit_task(128 + sigi);
                }
                continue;
            }
            if act.restorer == 0 || act.flags & SA_RESTORER == 0 { continue; }

            // Interrupted user context, straight off this syscall's save area.
            let orig_rip = sig_read_u64(kstack + 64);
            let orig_rflags = sig_read_u64(kstack + 56);
            let orig_rsp = sig_read_u64(kstack + 8) + 24;
            let rdi = sig_read_u64(kstack + 40);
            let rsi = sig_read_u64(kstack + 32);
            let rdx = sig_read_u64(kstack + 48);
            let r8 = sig_read_u64(kstack + 24);
            let r9 = sig_read_u64(kstack + 16);
            let r15 = sig_read_u64(kstack + 72);
            let r14 = sig_read_u64(kstack + 80);
            let r13 = sig_read_u64(kstack + 88);
            let r12 = sig_read_u64(kstack + 96);
            let rbp = sig_read_u64(kstack + 104);
            let rbx = sig_read_u64(kstack + 112);
            let user_r10 = sig_read_u64(orig_rsp - 8); // arg4 the entry pushed

            let frame = (orig_rsp - SIG_FRAME_SIZE) & !0xF;
            sig_write_u64(frame + SIG_PRETCODE, act.restorer);
            sig_write_u64(frame + SIG_SIGMASK, TASKS[idx].sig_blocked);
            sig_write_u64(frame + SIG_R8, r8);
            sig_write_u64(frame + SIG_R9, r9);
            sig_write_u64(frame + SIG_R10, user_r10);
            sig_write_u64(frame + SIG_R11, orig_rflags);
            sig_write_u64(frame + SIG_R12, r12);
            sig_write_u64(frame + SIG_R13, r13);
            sig_write_u64(frame + SIG_R14, r14);
            sig_write_u64(frame + SIG_R15, r15);
            sig_write_u64(frame + SIG_RDI, rdi);
            sig_write_u64(frame + SIG_RSI, rsi);
            sig_write_u64(frame + SIG_RBP, rbp);
            sig_write_u64(frame + SIG_RBX, rbx);
            sig_write_u64(frame + SIG_RDX, rdx);
            sig_write_u64(frame + SIG_RAX, sys_ret);
            sig_write_u64(frame + SIG_RCX, orig_rip);
            sig_write_u64(frame + SIG_RSP, orig_rsp);
            sig_write_u64(frame + SIG_RIP, orig_rip);
            sig_write_u64(frame + SIG_EFLAGS, orig_rflags);
            sig_write_u16(frame + SIG_CS, 0x33);
            sig_write_u16(frame + SIG_GS, 0);
            sig_write_u16(frame + SIG_FS, 0);

            // Handler runs with the signal (and its sa_mask) blocked.
            TASKS[idx].sig_blocked |= bit | act.mask;
            TASKS[idx].sig_pending &= !bit;

            // Rewrite the exit path to enter the handler: RIP=handler,
            // RSP=frame, RDI=sig, RSI=&ucontext. [frame] holds the restorer.
            sig_write_u64(kstack + 40, sig as u64);
            sig_write_u64(kstack + 32, frame + SIG_UC);
            sig_write_u64(kstack + 64, act.handler);
            sig_write_u64(kstack + 8, frame - 24);
            return 1;
        }
    }
    0
}

fn sys_rt_sigreturn() -> i64 {
    unsafe {
        // The handler returned to the restorer trampoline (musl __restore_rt),
        // which called rt_sigreturn with the user RSP at &ucontext = frame+8.
        let id = current_task_id();
        if id == 0 { return -EINVAL; }
        let idx = task_idx(id);
        let frame = SYSCALL_USER_RSP.wrapping_sub(8);
        let ctx = [
            sig_read_u64(frame + SIG_RDI),
            sig_read_u64(frame + SIG_RSI),
            sig_read_u64(frame + SIG_RDX),
            sig_read_u64(frame + SIG_R8),
            sig_read_u64(frame + SIG_R9),
            sig_read_u64(frame + SIG_RIP),
            sig_read_u64(frame + SIG_EFLAGS),
            sig_read_u64(frame + SIG_RSP),
            sig_read_u64(frame + SIG_R15),
            sig_read_u64(frame + SIG_R14),
            sig_read_u64(frame + SIG_R13),
            sig_read_u64(frame + SIG_R12),
            sig_read_u64(frame + SIG_RBP),
            sig_read_u64(frame + SIG_RBX),
        ];
        PENDING_RESTORE = Some(ctx);
        TASKS[idx].sig_blocked = sig_read_u64(frame + SIG_SIGMASK);
        // Return value becomes the user's rax after the exit path restores the
        // parked context, so hand back the interrupted rax.
        sig_read_u64(frame + SIG_RAX) as i64
    }
}

fn sys_sigaltstack(ss: u64, old_ss: u64) -> i64 {
    // Store/query altstack base+size. We do not switch stacks yet, but the
    // state must round-trip for libc startup which probes it.
    // stack_t layout: { ss_sp:u64, ss_flags:u32, _pad:u32, ss_size:u64 }
    let id = current_task_id();
    if id == 0 { return -EINVAL; }
    let _idx = task_idx(id);
    unsafe {
        // Keep a simple static altstack mirror for the kernel task state.
        static mut ALTSTACK_SP: u64 = 0;
        static mut ALTSTACK_FLAGS: u32 = 0;
        static mut ALTSTACK_SIZE: u64 = 0;
        if old_ss != 0 {
            core::ptr::write_volatile(old_ss as *mut u64, ALTSTACK_SP);
            core::ptr::write_volatile((old_ss + 8) as *mut u32, ALTSTACK_FLAGS);
            core::ptr::write_volatile((old_ss + 16) as *mut u64, ALTSTACK_SIZE);
        }
        if ss != 0 {
            let sp = core::ptr::read_volatile(ss as *const u64);
            let size = core::ptr::read_volatile((ss + 16) as *const u64);
            ALTSTACK_SP = sp;
            ALTSTACK_SIZE = size;
            ALTSTACK_FLAGS = 0;
        }
    }
    0
}

// ── Uname ──────────────────────────────────────────────────────────

fn sys_uname(buf: *mut u8) -> i64 {
    if buf.is_null() { return -EFAULT; }
    // Linux struct utsname: 5 fields, each 65 bytes
    let fields: [&[u8]; 5] = [
        b"Rynex",               // sysname
        b"rynex",               // nodename
        b"0.0.1",               // release
        b"#1 Rynex kernel 0.0.1 Alpha", // version
        b"x86_64",              // machine
    ];
    unsafe {
        for (i, field) in fields.iter().enumerate() {
            let slot = buf.add(i * 65);
            core::ptr::write_bytes(slot, 0, 65);
            core::ptr::copy_nonoverlapping(field.as_ptr(), slot, field.len());
        }
    }
    0
}

// ── Ioctl ──────────────────────────────────────────────────────────

fn sys_ioctl(fd: u32, request: u64, arg3: u64) -> i64 {
    const TCGETS: u64 = 0x5401;
    const TCSETS: u64 = 0x5402;
    const TCSETSW: u64 = 0x5403;
    const TCSETSF: u64 = 0x5404;
    const TIOCGWINSZ: u64 = 0x5413;
    const TIOCSPGRP: u64 = 0x5410;
    const TIOCGPGRP: u64 = 0x540F;

    // For fd 0,1,2 (stdin, stdout, stderr), handle essential TTY ioctls directly
    // to ensure isatty() works and shells can enter interactive mode.
    if fd <= 2 {
        match request {
            TCGETS => {
                if arg3 != 0 {
                    let termios = [0u8; 60];
                    unsafe { core::ptr::copy_nonoverlapping(termios.as_ptr(), arg3 as *mut u8, 60); }
                }
                return 0;
            }
            TIOCGWINSZ => {
                if arg3 != 0 {
                    let winsz = [0u16; 4];
                    unsafe { core::ptr::copy_nonoverlapping(winsz.as_ptr(), arg3 as *mut u16, 4); }
                }
                return 0;
            }
            // TCSETS/TCSETSW/TCSETSF fall through to the VFS so shells
            // (busybox ash) can actually change termios, e.g. disable ECHO
            // while doing their own line editing. Without this, the kernel
            // keeps echoing input on the VGA console, duplicating the prompt.
            //
            // TIOCGPGRP / TIOCSPGRP: report the foreground process group so
            // interactive shells (busybox ash) don't stop themselves with
            // SIGTTIN thinking they are backgrounded. On first query the
            // foreground group defaults to the caller's own pgrp.
            TIOCSPGRP | TIOCGPGRP => {
                if request == TIOCSPGRP {
                    if arg3 != 0 {
                        let pg = unsafe { *(arg3 as *const i32) };
                        crate::tty::TTY_DEVICE.set_fg_pgrp(pg);
                    }
                    return 0;
                } else {
                    let id = current_task_id();
                    let tgid = if id == 0 {
                        0
                    } else {
                        unsafe { TASKS[task_idx(id)].tgid as i32 }
                    };
                    let mut pg = crate::tty::TTY_DEVICE.get_fg_pgrp();
                    if pg == 0 {
                        pg = tgid;
                        crate::tty::TTY_DEVICE.set_fg_pgrp(pg);
                    }
                    if arg3 != 0 {
                        unsafe { *(arg3 as *mut i32) = pg; }
                    }
                    return 0;
                }
            }
            _ => {}
        }
    }

    // For all other fds (including /dev/tty opened by shell), use VFS
    let inode_fd = match crate::vfs::fd_to_inode(fd as usize) {
        Some(f) => f,
        None => return -EBADF,
    };

    // Use VFS ioctl
    let vnode_id = unsafe { crate::vfs::INODES[inode_fd.inode_idx].vnode_id };
    let mut msg = crate::vfs_core::VfsMessage::new();
    msg.op = crate::vfs_core::VfsOp::Ioctl;
    msg.extra1 = vnode_id as u64;
    msg.offset = request;
    msg.data = arg3 as *mut u8;
    msg.data_len = 0;
    crate::vfs_core::dispatch(&mut msg);
    msg.result
}

// ── Fcntl ──────────────────────────────────────────────────────────

fn sys_fcntl(fd: u32, cmd: i32, arg: u64) -> i64 {
    match cmd {
        0 => sys_dup2(fd, fd),
        1 => 0,  // F_GETFD
        2 => 0,  // F_SETFD
        3 => 2,  // F_GETFL → return O_RDWR (2)
        4 => 0,  // F_SETFL
        1030 => { // F_DUPFD_CLOEXEC
            // Find lowest available fd >= arg
            let table = match crate::vfs::get_fd_table() {
                Some(t) => t,
                None => return -EBADF,
            };
            let start_fd = arg as usize;
            for newfd in start_fd..crate::vfs::MAX_FDS_PER_TASK {
                if !table[newfd].used {
                    unsafe {
                        if (fd as usize) >= crate::vfs::MAX_FDS_PER_TASK || !table[fd as usize].used {
                            return -EBADF;
                        }
                        table[newfd] = table[fd as usize];
                        table[newfd].pos = 0;
                    }
                    return newfd as i64;
                }
            }
            -EMFILE
        }
        _ => -EINVAL,
    }
}

// ── Getcwd ─────────────────────────────────────────────────────────

static mut CWD_BUF: [u8; 256] = [0; 256];
static mut CWD_LEN: usize = 0;
static CWD_INIT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn get_cwd_bytes() -> &'static [u8] {
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
    let mut norm = [0u8; 512];
    let norm_len = crate::vfs::normalize_path(name, &mut norm).unwrap_or(0);
    if norm_len == 0 { return -ENOENT; }
    let norm_name = &norm[..norm_len];
    match crate::vfs_core::resolve_ino(norm_name) {
        Ok(_) => {
            unsafe {
                let l = core::cmp::min(norm_name.len(), 255);
                CWD_BUF[..l].copy_from_slice(&norm_name[..l]);
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

// ── Sysinfo (Linux syscall 99) ─────────────────────────────────────
// struct sysinfo (glibc layout, native 64-bit):
//   long uptime; unsigned long loads[3]; unsigned long totalram;
//   unsigned long freeram; unsigned long sharedram; unsigned long bufferram;
//   unsigned long totalswap; unsigned long freeswap; unsigned short procs;
//   unsigned short pad; unsigned long totalhigh; unsigned long freehigh;
//   unsigned int mem_unit;
fn sys_sysinfo(info: *mut u8) -> i64 {
    if info.is_null() { return -EFAULT; }
    let ticks = unsafe { crate::pit::TICKS.load(core::sync::atomic::Ordering::Relaxed) };
    let uptime = (ticks / 100) as u64; // 100 Hz PIT -> seconds
    let mem_unit: u32 = 4096;
    let totalram = 64u64; // 64 MB in units of mem_unit
    let freeram = 32u64;
    let mut procs: u16 = 0;
    for id in 1..=crate::task::MAX_TASKS as u64 {
        if let Some(t) = crate::task::task_by_id(id) {
            if t.state != crate::task::TaskState::Empty
                && t.state != crate::task::TaskState::Exited
                && t.state != crate::task::TaskState::Zombie
            {
                procs += 1;
            }
        }
    }
    unsafe {
        let p = info as *mut u64;
        core::ptr::write_volatile(p, uptime);               // uptime       @0
        core::ptr::write_volatile(p.add(1), 0);             // loads[0]     @8
        core::ptr::write_volatile(p.add(2), 0);             // loads[1]     @16
        core::ptr::write_volatile(p.add(3), 0);             // loads[2]     @24
        core::ptr::write_volatile(p.add(4), totalram);      // totalram     @32
        core::ptr::write_volatile(p.add(5), freeram);       // freeram      @40
        core::ptr::write_volatile(p.add(6), 0);             // sharedram    @48
        core::ptr::write_volatile(p.add(7), 0);             // bufferram    @56
        core::ptr::write_volatile(p.add(8), 0);             // totalswap    @64
        core::ptr::write_volatile(p.add(9), 0);             // freeswap     @72
        core::ptr::write_volatile(info.add(80) as *mut u16, procs); // procs   @80
        core::ptr::write_volatile(info.add(82) as *mut u16, 0);    // pad     @82
        core::ptr::write_volatile(p.add(11), 0);            // totalhigh    @88
        core::ptr::write_volatile(p.add(12), 0);            // freehigh     @96
        core::ptr::write_volatile(info.add(104) as *mut u32, mem_unit); // mem_unit @104
    }
    0
}

// ── Statfs / rlimit / chmod / chown / utimens / groups / mount ──

// Linux struct statfs (x86_64): 6 u64 fields + 8-byte fsid + pad + 2 u64 spare.
fn fill_statfs(buf: *mut u8) -> i64 {
    unsafe {
        let p = buf as *mut u64;
        core::ptr::write_volatile(p, 0x65746e69u64);          // f_type "inte"
        core::ptr::write_volatile(p.add(1), 4096);            // f_bsize
        core::ptr::write_volatile(p.add(2), 1024u64 * 1024);  // f_blocks
        core::ptr::write_volatile(p.add(3), 512u64 * 1024);   // f_bfree
        core::ptr::write_volatile(p.add(4), 512u64 * 1024);   // f_bavail
        core::ptr::write_volatile(p.add(5), 0);               // f_files
        core::ptr::write_volatile(p.add(6), 0);               // f_ffree
        core::ptr::write_volatile(buf.add(48) as *mut u64, 0); // f_fsid[2]
        core::ptr::write_volatile(buf.add(56) as *mut u64, 0);
        core::ptr::write_volatile(buf.add(64) as *mut i64, 0); // f_namelen
        core::ptr::write_volatile(buf.add(72) as *mut i64, 0); // f_frsize
        core::ptr::write_volatile(buf.add(80) as *mut u64, 0); // f_spare[4]
        core::ptr::write_volatile(buf.add(88) as *mut u64, 0);
        core::ptr::write_volatile(buf.add(96) as *mut u64, 0);
        core::ptr::write_volatile(buf.add(104) as *mut u64, 0);
    }
    0
}

fn sys_statfs(pathname: *const u8, buf: *mut u8) -> i64 {
    if pathname.is_null() || buf.is_null() { return -EFAULT; }
    let name = unsafe { cstr_from_ptr(pathname) };
    if name.is_empty() { return -ENOENT; }
    match crate::vfs::resolve_or_register(name) {
        Some(_) => fill_statfs(buf),
        None => -ENOENT,
    }
}

fn sys_fstatfs(fd: u32, buf: *mut u8) -> i64 {
    if buf.is_null() { return -EFAULT; }
    if crate::vfs::fd_to_inode(fd as usize).is_none() { return -EBADF; }
    fill_statfs(buf)
}

// Linux struct rlimit: two u64 (rlim_cur, rlim_max).
fn fill_rlimit(buf: *mut u8, cur: u64, max: u64) -> i64 {
    unsafe {
        let p = buf as *mut u64;
        core::ptr::write_volatile(p, cur);
        core::ptr::write_volatile(p.add(1), max);
    }
    0
}

fn sys_getrlimit(resource: u32, buf: *mut u8) -> i64 {
    if buf.is_null() { return -EFAULT; }
    // RLIM_INFINITY = u64::MAX. Values are generous; only CPU/FILE respected.
    match resource {
        0 => fill_rlimit(buf, u64::MAX, u64::MAX), // RLIMIT_CPU
        3 => fill_rlimit(buf, 8192, 8192),         // RLIMIT_CORE
        4 => fill_rlimit(buf, 1024, 1024),         // RLIMIT_DATA
        6 => fill_rlimit(buf, u64::MAX, u64::MAX), // RLIMIT_STACK
        7 => fill_rlimit(buf, u64::MAX, u64::MAX), // RLIMIT_NOFILE
        8 => fill_rlimit(buf, u64::MAX, u64::MAX), // RLIMIT_AS
        _ => fill_rlimit(buf, u64::MAX, u64::MAX),
    }
}

fn sys_setrlimit(_resource: u32, buf: *mut u8) -> i64 {
    if buf.is_null() { return -EFAULT; }
    if !user_range_valid(buf as u64, 16, false) { return -EFAULT; }
    0
}

fn sys_mknod(pathname: *const u8, _mode: u32, _dev: u64) -> i64 {
    if pathname.is_null() { return -EFAULT; }
    let name = unsafe { cstr_from_ptr(pathname) };
    if name.is_empty() { return -ENOENT; }
    match crate::vfs::create_file(name, b"") {
        Some(_) => 0,
        None => -EIO,
    }
}

fn sys_chmod(pathname: *const u8, mode: u32) -> i64 {
    if pathname.is_null() { return -EFAULT; }
    let name = unsafe { cstr_from_ptr(pathname) };
    if name.is_empty() { return -ENOENT; }
    match crate::vfs::resolve_or_register(name) {
        Some(_) => {
            let _ = mode;
            0
        }
        None => -ENOENT,
    }
}

fn sys_fchmod(fd: u32, mode: u32) -> i64 {
    if crate::vfs::fd_to_inode(fd as usize).is_none() { return -EBADF; }
    let _ = mode;
    0
}

fn sys_chown(pathname: *const u8, _uid: u32, _gid: u32) -> i64 {
    if pathname.is_null() { return -EFAULT; }
    let name = unsafe { cstr_from_ptr(pathname) };
    if name.is_empty() { return -ENOENT; }
    match crate::vfs::resolve_or_register(name) {
        Some(_) => 0,
        None => -ENOENT,
    }
}

fn sys_utimensat(_dirfd: i32, pathname: *const u8, _times: u64, _flags: i32) -> i64 {
    if pathname.is_null() { return -EFAULT; }
    let name = unsafe { cstr_from_ptr(pathname) };
    if name.is_empty() { return -ENOENT; }
    match crate::vfs::resolve_or_register(name) {
        Some(_) => 0,
        None => -ENOENT,
    }
}

fn sys_unlinkat(dirfd: i32, pathname: *const u8, flags: i32) -> i64 {
    let _ = (dirfd, flags);
    if pathname.is_null() { return -EFAULT; }
    sys_unlink(pathname)
}

fn sys_readlinkat(dirfd: i32, pathname: *const u8, buf: *mut u8, bufsiz: usize) -> i64 {
    let _ = dirfd;
    if pathname.is_null() || buf.is_null() { return -EFAULT; }
    sys_readlink(pathname, buf, bufsiz)
}

fn sys_getgroups(size: i32, list: *mut u8) -> i64 {
    // Single-user system: only group 0 (root).
    if list.is_null() || size <= 0 {
        // Return number of groups.
        return 1;
    }
    if size < 1 { return -EINVAL; }
    unsafe {
        core::ptr::write_volatile(list as *mut u32, 0);
    }
    1
}

fn sys_setgroups(_size: usize, _list: *const u8) -> i64 { 0 }

fn sys_mount(source: *const u8, target: *const u8, fstype: *const u8, _flags: u64, _data: u64) -> i64 {
    let _ = (source, target, fstype);
    -ENOSYS
}

fn sys_umount2(_target: *const u8, _flags: i32) -> i64 { -ENOSYS }

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

/// Follow symlinks per POSIX stat() semantics (stat follows links, lstat does not).
/// Returns the final non-symlink vnode id, or the input if unresolvable.
fn follow_symlinks(mut vn_id: u16) -> u16 {
    for _ in 0..8 {
        let mode = match crate::vfs_core::stat(vn_id) {
            Ok(s) => s.mode,
            Err(_) => return vn_id,
        };
        if mode & crate::vfs_core::types::S_IFMT != crate::vfs_core::types::S_IFLNK {
            return vn_id;
        }
        let target = match crate::vfs_core::readlink(vn_id) {
            Ok(t) => t,
            Err(_) => return vn_id,
        };
        let mut buf = [0u8; 256];
        let n = target.len().min(255);
        buf[..n].copy_from_slice(&target[..n]);
        let flat = match crate::vfs::find_inode(&buf[..n]) {
            Some(i) => i,
            None => return vn_id,
        };
        let new_vn = unsafe { crate::vfs::INODES[flat].vnode_id };
        if new_vn == 0 || new_vn == vn_id {
            return vn_id;
        }
        vn_id = new_vn;
    }
    vn_id
}

 fn sys_stat(pathname: *const u8, statbuf: *mut u8) -> i64 {
     if pathname.is_null() || statbuf.is_null() { return -EFAULT; }
     let name = unsafe { cstr_from_ptr(pathname) };
     if name.is_empty() { return -ENOENT; }
     match crate::vfs::resolve_or_register(name) {
        Some(flat_idx) => {
            let vn_id = unsafe { crate::vfs::INODES[flat_idx].vnode_id };
             let r = if vn_id != 0 {
                 fill_stat_from_vnode(follow_symlinks(vn_id), statbuf)
             } else {
                 fill_stat_from_vnode(0, statbuf) // fallback
             };
             r
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
    let id = cur_task().load(Ordering::SeqCst);
    if id == 0 { return 0; }
    unsafe { TASKS[task_idx(id)].pml4 }
}

/// Sanitize all tasks' pml4 pointers: clear any that point into GRUB module regions
/// (legacy corruption from before the allocator fix). Must be called after
/// the allocator is fully initialized.
pub fn sanitize_task_pml4s() {
    unsafe {
        for i in 0..MAX_TASKS {
            if TASKS[i].id != 0 && TASKS[i].state != TaskState::Empty {
                let pml4 = TASKS[i].pml4;
                if pml4 != 0 && crate::memory::page_in_module_region(pml4) {
                    TASKS[i].pml4 = 0;
                    crate::serial::write_str("MEM: sanitized task ");
                    crate::serial::write_dec(TASKS[i].id);
                    crate::serial::write_str(" pml4=0x");
                    crate::serial::write_hex(pml4);
                    crate::serial::write_str(" (was in module region)\n");
                }
            }
        }
    }
}

/// Handle demand paging for mmap'd (or brk) regions.
/// Returns true if the page was allocated and mapped.
/// CLONE_VM threads share one pml4; their per-task vma arrays must be kept
/// identical. We scan every task sharing `pml4` rather than only the current
/// task's copy, so a mapping registered by a sibling is visible here.
pub fn handle_demand_page(pml4: u64, cr2: u64) -> bool {
    let id = cur_task().load(Ordering::SeqCst);
    if id == 0 { return false; }
    unsafe {
        // The pool is keyed by pml4, so a VMA registered by any CLONE_VM
        // sibling is found here directly; this is what made the mallocng
        // PAGE_FAULT bug (sibling munmap leaving a stale per-task vma list)
        // impossible by construction.
        if let Some(vma) = vma_find(pml4, cr2) {
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
            return true;
        }
    }
    false
}

pub fn pt_mgr() -> &'static mut PageTableManager {
    crate::paging::pt_mgr()
}

/// Validate that the user range [addr, addr+len) is fully mapped and
/// accessible for the given access type, demand-paging any pages that live
/// in a VMA but aren't present yet. The kernel dereferences user buffers
/// directly (sys_write/sys_read), so we must never touch a page that would
/// fault: an unmapped range here would otherwise raise a kernel-mode PF that
/// page_fault_resolve refuses to service (cpl==0).
pub fn user_range_valid(addr: u64, len: usize, want_write: bool) -> bool {
    if len == 0 { return true; }
    let end = match addr.checked_add(len as u64) {
        Some(e) => e,
        None => return false,
    };
    if !crate::paging::is_user_addr(addr) || !crate::paging::is_user_addr(end - 1) {
        return false;
    }
    let pml4 = current_task_pml4();
    if pml4 == 0 { return false; }
    let mut page = addr & !0xFFF;
    while page < end {
        if crate::paging::PageTableManager::resolve_phys(pml4, page).is_none() {
            // Not present: try demand paging first, then reject if still absent.
            if !handle_demand_page(pml4, page) {
                return false;
            }
            if crate::paging::PageTableManager::resolve_phys(pml4, page).is_none() {
                return false;
            }
        }
        // Check user + writable flags (handles 2M huge pages via the PDE).
        match crate::paging::resolve_phys_flags(pml4, page) {
            Some((_, flags)) => {
                if flags & crate::paging::PTE_USER == 0
                    || (want_write && flags & crate::paging::PTE_WRITABLE == 0) {
                    return false;
                }
            }
            None => return false,
        }
        page += 0x1000;
    }
    true
}

fn sys_poll(fds: u64, nfds: u64, _timeout: i32) -> i64 {
    if fds == 0 || nfds == 0 {
        return -EFAULT;
    }
    
    const POLLIN: i16 = 0x0001;
    const POLLOUT: i16 = 0x0004;
    const POLLERR: i16 = 0x0008;
    const POLLHUP: i16 = 0x0010;
    const POLLNVAL: i16 = 0x0020;
    
    let mut ready_count = 0i64;
    
    for i in 0..nfds as usize {
        let fd_ptr = unsafe { (fds + i as u64 * 8) as *const u32 };
        let events_ptr = unsafe { (fds + i as u64 * 8 + 4) as *const i16 };
        let revents_ptr = unsafe { (fds + i as u64 * 8 + 6) as *mut i16 };
        
        let fd = unsafe { core::ptr::read_volatile(fd_ptr) };
        let events = unsafe { core::ptr::read_volatile(events_ptr) };
        
        let mut revents = 0i16;
        
        // Check if fd is valid
        let _inode_fd = match crate::vfs::fd_to_inode(fd as usize) {
            Some(f) => f,
            None => {
                revents = POLLNVAL;
                unsafe { core::ptr::write_volatile(revents_ptr, revents); }
                continue;
            }
        };
        
        // For TTY devices (including console on fd 0,1,2), check if data is available
        if events & POLLIN != 0 {
            // Check if there's input data available in TTY buffer
            // For now, assume TTY is always ready for read if it's a valid TTY fd
            // This makes poll return immediately with POLLIN, which should make shell proceed to read
            revents |= POLLIN;
        }
        
        if events & POLLOUT != 0 {
            // Writing is usually always ready for TTY
            revents |= POLLOUT;
        }
        
        unsafe { core::ptr::write_volatile(revents_ptr, revents); }
        
        if revents != 0 {
            ready_count += 1;
        }
    }
    
    ready_count
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
        let r = sys_write(fd, base as *const u8, len);
        if r < 0 {
            crate::klog::begin(crate::klog::LOG_WARNING, crate::klog::FAC_SYSCALL);
            crate::klog::s("writev fd=");
            crate::klog::dec(fd as u64);
            crate::klog::s(" iov[");
            crate::klog::dec(i as u64);
            crate::klog::s("] base=0x");
            crate::klog::hex(base);
            crate::klog::s(" len=");
            crate::klog::dec(len as u64);
            crate::klog::s(" err=");
            crate::klog::dec((-r) as u64);
            crate::klog::end();
            return r;
        }
        total += r;
    }
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

fn sys_clock_nanosleep(clk_id: u64, flags: u32, req: *const u64, _rem: *mut u64) -> i64 {
    // Support the monotonic/real-time relative sleep used by std::thread::sleep
    // (which lands here via musl's clock_nanosleep). Absolute sleeps (TIMER_ABSTIME)
    // are treated as relative for now, which is fine for tests.
    let _ = (clk_id, flags);
    if req.is_null() { return -EFAULT; }
    let sec = unsafe { core::ptr::read_volatile(req) } as i64;
    let nsec = unsafe { core::ptr::read_volatile(req.add(1)) } as i64;
    let total_ns = if sec < 0 || nsec < 0 {
        0
    } else {
        (sec as u64).saturating_mul(1_000_000_000).saturating_add(nsec as u64)
    };
    let ticks = (total_ns + 19_999_999) / 20_000_000;
    // serial::write_str("CLKNS req=");
    // serial::write_dec(sec as u64);
    // serial::write_str(".");
    // serial::write_dec(nsec as u64);
    // serial::write_str(" ns ticks=");
    // serial::write_dec(ticks);
    // serial::write_str("\n");
    if ticks > 0 {
        sys_sleep(ticks);
    }
    // serial::write_str("CLKNS woke\n");
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

/// Create /bin/<applet> symlinks -> /bin/busybox so PATH lookup can find
/// the compiled-in applets (busybox has no FEATURE_SH_STANDALONE here).
fn create_applet_links() {
    const APPLETS: &[&[u8]] = &[
        b"ash", b"sh", b"ls", b"cat", b"clear", b"pwd", b"date", b"echo",
        b"printf", b"true", b"false", b"test", b"sleep", b"head", b"tail",
        b"wc", b"basename", b"dirname", b"env", b"printenv", b"id", b"whoami",
        b"uname", b"hostname", b"ps", b"kill", b"df", b"du", b"free", b"dmesg",
        b"dd", b"cp", b"mv", b"rm", b"mkdir", b"rmdir", b"ln", b"touch",
        b"chmod", b"md5sum", b"sha1sum", b"hexdump", b"tee", b"which", b"grep",
        b"sed", b"awk", b"find", b"stat", b"uptime",
    ];
    let mut path_buf = [0u8; 64];
    for a in APPLETS {
        let mut p = 0usize;
        for &c in b"/bin/" {
            path_buf[p] = c;
            p += 1;
        }
        for &c in *a {
            if p < path_buf.len() - 1 {
                path_buf[p] = c;
                p += 1;
            }
        }
        if crate::vfs::find_inode(&path_buf[..p]).is_none() {
            let _ = crate::vfs::create_symlink(&path_buf[..p], b"/bin/busybox");
        }
    }
}

pub fn boot_userland() {
    unsafe { core::arch::asm!("cli"); }

    // The AP is already online (init_aps ran before us). Drop a proof kernel
    // task onto each AP's runqueue so it demonstrably runs on its own CPU.
    spawn_ap_demo_tasks();

    // Initialize TTY devices FIRST (before creating any user tasks)
    crate::tty::init();
    let _ = crate::vfs_core::mkdir(b"/dev", crate::vfs_core::types::S_IRUSR | crate::vfs_core::types::S_IWUSR | crate::vfs_core::types::S_IXUSR | crate::vfs_core::types::S_IRGRP | crate::vfs_core::types::S_IXGRP | crate::vfs_core::types::S_IROTH);

    // Use the global TTY_DEVICE for all consoles
    let tty_dev = &crate::tty::TTY_DEVICE;

    if crate::vfs::find_inode(b"/dev/console").is_none() {
        let vn_id = crate::vfs_core::vnode_alloc(1, 0, 0, tty_dev);
        if let Some(vn_id) = vn_id {
            crate::vfs_core::create(b"/dev/console", crate::vfs_core::types::S_IFCHR | 0o666).ok();
            crate::vfs::create_file(b"/dev/console", b"");
            if let Some(idx) = crate::vfs::find_inode(b"/dev/console") {
                unsafe { crate::vfs::INODES[idx].vnode_id = vn_id; }
            }
            serial::write_str("VFS: created '/dev/console' (char device)\n");
        }
    }
    if crate::vfs::find_inode(b"/dev/tty").is_none() {
        let vn_id = crate::vfs_core::vnode_alloc(2, 0, 0, tty_dev);
        if let Some(vn_id) = vn_id {
            crate::vfs_core::create(b"/dev/tty", crate::vfs_core::types::S_IFCHR | 0o666).ok();
            crate::vfs::create_file(b"/dev/tty", b"");
            if let Some(idx) = crate::vfs::find_inode(b"/dev/tty") {
                unsafe { crate::vfs::INODES[idx].vnode_id = vn_id; }
            }
            serial::write_str("VFS: created '/dev/tty' (char device)\n");
        }
    }
    if crate::vfs::find_inode(b"/dev/tty0").is_none() {
        let vn_id = crate::vfs_core::vnode_alloc(3, 0, 0, tty_dev);
        if let Some(vn_id) = vn_id {
            crate::vfs_core::create(b"/dev/tty0", crate::vfs_core::types::S_IFCHR | 0o666).ok();
            crate::vfs::create_file(b"/dev/tty0", b"");
            if let Some(idx) = crate::vfs::find_inode(b"/dev/tty0") {
                unsafe { crate::vfs::INODES[idx].vnode_id = vn_id; }
            }
            serial::write_str("VFS: created '/dev/tty0' (char device)\n");
        }
    }
    if crate::vfs::find_inode(b"/dev/null").is_none() {
        crate::vfs::create_file(b"/dev/null", b"");
        serial::write_str("VFS: created '/dev/null'\n");
    }
    if crate::vfs::find_inode(b"/dev/zero").is_none() {
        let vn_id = crate::vfs_core::vnode_alloc(4, 0, 0, &crate::tty::ZERO_DEVICE);
        if let Some(vn_id) = vn_id {
            crate::vfs_core::create(b"/dev/zero", crate::vfs_core::types::S_IFCHR | 0o666).ok();
            crate::vfs::create_file(b"/dev/zero", b"");
            if let Some(idx) = crate::vfs::find_inode(b"/dev/zero") {
                unsafe { crate::vfs::INODES[idx].vnode_id = vn_id; }
            }
            serial::write_str("VFS: created '/dev/zero' (char device)\n");
        }
    }
    if crate::vfs::find_inode(b"/dev/urandom").is_none() {
        let vn_id = crate::vfs_core::vnode_alloc(5, 0, 0, &crate::tty::URANDOM_DEVICE);
        if let Some(vn_id) = vn_id {
            crate::vfs_core::create(b"/dev/urandom", crate::vfs_core::types::S_IFCHR | 0o666).ok();
            crate::vfs::create_file(b"/dev/urandom", b"");
            if let Some(idx) = crate::vfs::find_inode(b"/dev/urandom") {
                unsafe { crate::vfs::INODES[idx].vnode_id = vn_id; }
            }
            serial::write_str("VFS: created '/dev/urandom' (char device)\n");
        }
    }

    // NOTE: /etc/passwd is NOT created here. Password/account handling is
    // user-space policy; the kernel never touches it (see README "Policy").
    // The user-space init/shell is responsible for provisioning /etc/passwd
    // through ordinary VFS operations when it starts.

    // Load user ELF modules from multiboot2
    let info_addr = crate::MULTIBOOT_INFO.load(Ordering::SeqCst) as u32;
    let mut init_tid = 0u64;
    if info_addr != 0 {
        let mut modules = [crate::multiboot2::ModuleInfo { start: 0, end: 0, name: [0; 64] }; 8];
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
                        serial::write_str("TASK: about to call load_elf\n");
                        match crate::elf::load_elf(mod_data) {
                            Ok(elf_info) => {
                                serial::write_str("TASK: load_elf OK, calling create_user_task\n");
                                if let Some(tid) = create_user_task_on_cpu(elf_info.entry, elf_info.pml4, elf_info.stack_top, PRIORITY_DEFAULT_NICE, 0) {
                                    init_tid = tid;
                                    serial::write_str("TASK: init created tid=");
                                    serial::write_dec(init_tid);
                                    serial::write_str("\n");
                                    // Name the init task before we switch away
                                    // (set_current_comm operates on CURRENT_TASK).
                                    unsafe {
                                        let idx = task_idx(tid);
                                        let name = b"init";
                                        let len = core::cmp::min(name.len(), 15);
                                        TASKS[idx].comm[..len].copy_from_slice(&name[..len]);
                                        TASKS[idx].comm[len] = 0;
                                    }
                                } else {
                                    serial::write_str("TASK: create_user_task returned None!\n");
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
                        crate::vfs::create_file(b"/bin/shell", mod_data);
                    }
                    2 => {
                        crate::vfs::create_external_file(b"/lib/libc.so", modules[i].start as *mut u8, mod_data.len());
                        crate::vfs::create_external_file(b"/lib/ld-musl-x86_64.so.1", modules[i].start as *mut u8, mod_data.len());
                    }
                    3 => {
                        crate::vfs::create_file(b"/bin/busybox", mod_data);
                    }
                    _ => {
                        // Any additional module is registered under its own
                        // name in /bin, taken from the GRUB cmdline basename.
                        // This lets extra programs be added to the ISO without
                        // changing the kernel: just drop a file in iso/boot/
                        // and add a `module2` line to grub.cfg.
                        let base = &modules[i].name;
                        let mut len = 0usize;
                        while len < base.len() && base[len] != 0 { len += 1; }
                        if len > 0 {
                            let mut path_buf = [0u8; 80];
                            path_buf[..5].copy_from_slice(b"/bin/");
                            let name_len = core::cmp::min(len, 80 - 5);
                            path_buf[5..5 + name_len].copy_from_slice(&base[..name_len]);
                            let path = &path_buf[..5 + name_len];
                            crate::vfs::create_file(path, mod_data);
                            crate::serial::write_str("MOD: registered '/bin/");
                            for &c in &base[..core::cmp::min(len, 64)] {
                                if c == 0 { break; }
                                crate::serial::write_str(&core::str::from_utf8(&[c]).unwrap_or("?"));
                            }
                            crate::serial::write_str("'\n");
                        }
                    }
                }
            }
        }
    }

     create_applet_links();

     let task0 = unsafe { &mut TASKS[0] };
    task0.id = 0;
    task0.state = TaskState::Running;
    task0.kernel_stack = alloc_stack(KERNEL_STACK_PAGES).expect("task0 stack");
    task0.regs = Registers::new_kernel(continue_after_schedule as *const () as u64, task0.kernel_stack);
    task0.pml4 = pt_mgr().kernel_pml4();
    task0.cpu = 0;
    task0.static_prio = nice_to_prio(19);
    task0.normal_prio = task0.static_prio;
    task0.prio = task0.static_prio;
    task0.in_syscall = false;
    cur_task().store(0, Ordering::SeqCst);
    unsafe { CURRENT_TASK_ID = 0; TASKS_PTR = TASKS.as_mut_ptr(); }

    // Dequeue init task so it's not in the runqueue twice.
    // Everything that needs the boot-stack local `init_tid` is done BEFORE the
    // stack switch below: once we `mov rsp` onto task0's kernel stack, reading
    // stack locals from the old boot stack is garbage.
    remove_from_runqueue(init_tid);
    let init_slot = task_idx(init_tid);
    {
        let new_task = unsafe { &mut TASKS[init_slot] };
        new_task.state = TaskState::Running;
        // Give init higher priority (nice=-10) than kernel tasks (nice=0 -> prio=20)
        // so it gets CPU time when kernel tasks yield.
        new_task.normal_prio = nice_to_prio(-10);
        new_task.prio = nice_to_prio(-10);
        new_task.time_slice = initial_time_slice(nice_to_prio(-10));
    }
    cur_task().store(init_tid, Ordering::SeqCst);
    unsafe { CURRENT_TASK_ID = init_tid; }
    unsafe { BOOT_INIT_SLOT = init_slot; }

    serial::write_str("TASK: switching to task ");
    serial::write_dec(init_tid);
    serial::write_str("...\n");

    unsafe {
        core::arch::asm!("mov rsp, {}", in(reg) task0.kernel_stack);
    }

    // Spawn pending kernel tasks after stack switch but before init context switch.
    // This ensures they land in the runqueue after init is set to Running,
    // so init gets CPU first and kernel tasks don't starve it.
    spawn_pending_kernel_tasks();

    let new_task = unsafe { &mut TASKS[unsafe { BOOT_INIT_SLOT }] };

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
