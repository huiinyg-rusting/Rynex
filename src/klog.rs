//! Structured kernel logging, rsyslog-style.
//!
//! Every log line is stamped with a facility, a severity level and a
//! monotonic tick, appended to a fixed-size ring buffer (so the tail of the
//! log survives a crash) and optionally mirrored to the serial console subject
//! to a runtime level threshold and per-facility mask.
//!
//! Levels follow syslog: lower number = more severe. Facilities group messages
//! by subsystem. The console threshold / facility mask can be changed at
//! runtime (e.g. to enable DEBUG facility spam only while chasing a bug) and
//! are read lock-free via atomics.
//!
//! Message construction is manual (no_std): use `log()` for a single static
//! string, or `begin()`/`s()`/`dec()`/`hex()`/`end()` to build a line from
//! parts, mirroring the old `serial::write_*` idioms.

use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

// ── Severity levels (syslog semantics) ───────────────────────────
pub const LOG_EMERG: u8 = 0;
pub const LOG_ALERT: u8 = 1;
pub const LOG_CRIT: u8 = 2;
pub const LOG_ERR: u8 = 3;
pub const LOG_WARNING: u8 = 4;
pub const LOG_NOTICE: u8 = 5;
pub const LOG_INFO: u8 = 6;
pub const LOG_DEBUG: u8 = 7;

const LEVEL_NAMES: [&str; 8] = [
    "EMERG", "ALERT", "CRIT", "ERR", "WARNING", "NOTICE", "INFO", "DEBUG",
];

// ── Facilities (subsystems) ──────────────────────────────────────
pub const FAC_KERN: u8 = 0;
pub const FAC_SCHED: u8 = 1;
pub const FAC_MEM: u8 = 2;
pub const FAC_VFS: u8 = 3;
pub const FAC_TTY: u8 = 4;
pub const FAC_SYSCALL: u8 = 5;
pub const FAC_EXEC: u8 = 6;
pub const FAC_MM: u8 = 7;
pub const FAC_PAGING: u8 = 8;
pub const FAC_GDT: u8 = 9;
pub const FAC_IDT: u8 = 10;
pub const FAC_ELF: u8 = 11;
pub const FAC_IPC: u8 = 12;
pub const FAC_FORK: u8 = 13;
pub const FAC_COUNT: usize = 14;

const FAC_NAMES: [&str; FAC_COUNT] = [
    "KERN", "SCHED", "MEM", "VFS", "TTY", "SYSCALL", "EXEC", "MM",
    "PAGING", "GDT", "IDT", "ELF", "IPC", "FORK",
];

// ── Ring buffer ──────────────────────────────────────────────────
const LOG_MSG_MAX: usize = 160;
const LOG_RING_CAP: usize = 128;

#[derive(Clone, Copy)]
struct LogEntry {
    level: u8,
    facility: u8,
    tick: u64,
    len: u16,
    msg: [u8; LOG_MSG_MAX],
}

const EMPTY_ENTRY: LogEntry = LogEntry {
    level: 0,
    facility: 0,
    tick: 0,
    len: 0,
    msg: [0; LOG_MSG_MAX],
};

static mut RING: [LogEntry; LOG_RING_CAP] = [EMPTY_ENTRY; LOG_RING_CAP];
static mut RING_HEAD: usize = 0; // next write slot
static mut RING_LEN: usize = 0;  // entries currently held (<= CAP)

// ── Runtime filters ──────────────────────────────────────────────
static CONSOLE_LEVEL: AtomicU8 = AtomicU8::new(LOG_WARNING);
static FACILITY_MASK: AtomicU32 = AtomicU32::new(u32::MAX);

pub fn set_console_level(level: u8) {
    CONSOLE_LEVEL.store(level.min(LOG_DEBUG), Ordering::Relaxed);
}

pub fn set_facility_mask(mask: u32) {
    FACILITY_MASK.store(mask, Ordering::Relaxed);
}

pub fn get_console_level() -> u8 {
    CONSOLE_LEVEL.load(Ordering::Relaxed)
}

// ── Line builder (static, single-core; interrupts disabled while in use) ──
static mut LINE_ACTIVE: bool = false;
static mut LINE_LEVEL: u8 = 0;
static mut LINE_FAC: u8 = 0;
static mut LINE_LEN: usize = 0;
static mut LINE: [u8; LOG_MSG_MAX] = [0; LOG_MSG_MAX];

fn irq_save_and_disable() -> u64 {
    let flags: u64;
    unsafe { core::arch::asm!("pushfq", "pop rax", out("rax") flags, options(nostack)); }
    unsafe { core::arch::asm!("cli", options(nostack)); }
    flags
}

fn irq_restore(flags: u64) {
    unsafe { core::arch::asm!("push rax", "popfq", in("rax") flags, options(nostack)); }
}

fn now_tick() -> u64 {
    crate::pit::TICKS.load(Ordering::Relaxed)
}

fn append_bytes(data: &[u8]) {
    unsafe {
        for &b in data {
            if b == b'\n' || b == b'\r' {
                continue;
            }
            if LINE_LEN < LOG_MSG_MAX {
                LINE[LINE_LEN] = b;
                LINE_LEN += 1;
            }
        }
    }
}

fn append_dec(mut v: u64) {
    if v == 0 {
        append_bytes(b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 20;
    while v > 0 {
        i -= 1;
        buf[i] = (v % 10) as u8 + b'0';
        v /= 10;
    }
    append_bytes(&buf[i..]);
}

fn append_hex(v: u64) {
    let hex = b"0123456789ABCDEF";
    let mut buf = [0u8; 16];
    for i in 0..16 {
        let nibble = ((v >> ((15 - i) * 4)) & 0xF) as usize;
        buf[i] = hex[nibble];
    }
    append_bytes(&buf);
}

// ── Public API ───────────────────────────────────────────────────

/// Log a single pre-formatted string line.
pub fn log(level: u8, facility: u8, msg: &str) {
    begin(level, facility);
    s(msg);
    end();
}

/// Start building a log line. Must be paired with `end()`.
pub fn begin(level: u8, facility: u8) {
    unsafe {
        let flags = irq_save_and_disable();
        LINE_ACTIVE = true;
        LINE_LEVEL = level;
        LINE_FAC = facility;
        LINE_LEN = 0;
        irq_restore(flags);
    }
}

pub fn s(text: &str) {
    unsafe {
        let flags = irq_save_and_disable();
        if LINE_ACTIVE {
            append_bytes(text.as_bytes());
        }
        irq_restore(flags);
    }
}

pub fn dec(v: u64) {
    unsafe {
        let flags = irq_save_and_disable();
        if LINE_ACTIVE {
            append_dec(v);
        }
        irq_restore(flags);
    }
}

pub fn hex(v: u64) {
    unsafe {
        let flags = irq_save_and_disable();
        if LINE_ACTIVE {
            append_hex(v);
        }
        irq_restore(flags);
    }
}

/// Commit the pending line to the ring buffer and, if it passes the console
/// filter, mirror it to the serial port with a [tick][FAC][LEVEL] prefix.
pub fn end() {
    unsafe {
        let flags = irq_save_and_disable();
        if !LINE_ACTIVE {
            irq_restore(flags);
            return;
        }
        LINE_ACTIVE = false;
        let level = LINE_LEVEL;
        let facility = LINE_FAC;
        let len = LINE_LEN;

        // Always keep the line in the ring (crash tail survives).
        RING[RING_HEAD] = LogEntry {
            level,
            facility,
            tick: now_tick(),
            len: len as u16,
            msg: LINE,
        };
        RING_HEAD = (RING_HEAD + 1) % LOG_RING_CAP;
        if RING_LEN < LOG_RING_CAP {
            RING_LEN += 1;
        }

        let fac_enabled = ((FACILITY_MASK.load(Ordering::Relaxed) >> facility) & 1) != 0;
        let lvl_ok = level <= CONSOLE_LEVEL.load(Ordering::Relaxed);
        if fac_enabled && lvl_ok {
            crate::serial::write_str("[");
            crate::serial::write_dec(now_tick());
            crate::serial::write_str("][");
            crate::serial::write_str(FAC_NAMES[facility.min(FAC_COUNT as u8 - 1) as usize]);
            crate::serial::write_str("][");
            crate::serial::write_str(LEVEL_NAMES[level.min(LOG_DEBUG) as usize]);
            crate::serial::write_str("] ");
            for i in 0..len {
                crate::serial::write_byte(LINE[i]);
            }
            crate::serial::write_str("\n");
        }
        irq_restore(flags);
    }
}

/// Dump the whole ring buffer to the serial console, oldest first.
/// Intended for panic / fault handlers (post-mortem tail).
pub fn dump() {
    unsafe {
        let flags = irq_save_and_disable();
        let len = RING_LEN;
        let head = RING_HEAD;
        crate::serial::write_str("==== klog ring buffer (");
        crate::serial::write_dec(len as u64);
        crate::serial::write_str(" entries) ====\n");
        let start = (head + LOG_RING_CAP - len) % LOG_RING_CAP;
        for i in 0..len {
            let e = &RING[(start + i) % LOG_RING_CAP];
            crate::serial::write_str("[");
            crate::serial::write_dec(e.tick);
            crate::serial::write_str("][");
            let fac = e.facility.min(FAC_COUNT as u8 - 1) as usize;
            crate::serial::write_str(FAC_NAMES[fac]);
            crate::serial::write_str("][");
            crate::serial::write_str(LEVEL_NAMES[e.level.min(LOG_DEBUG) as usize]);
            crate::serial::write_str("] ");
            for j in 0..(e.len as usize) {
                crate::serial::write_byte(e.msg[j]);
            }
            crate::serial::write_str("\n");
        }
        crate::serial::write_str("==== end of klog ring ====\n");
        irq_restore(flags);
    }
}

/// Diagnostic hook: convert the current line buffer into a &str for tools that
/// need a peek at the partially-built line (unused in normal operation).
#[allow(dead_code)]
pub fn debug_current() -> &'static str {
    unsafe {
        let flags = irq_save_and_disable();
        let len = LINE_LEN;
        irq_restore(flags);
        core::str::from_utf8(&LINE[..len]).unwrap_or("")
    }
}
