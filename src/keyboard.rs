use core::sync::atomic::{AtomicU64, Ordering, AtomicBool};

const KEYBOARD_DATA: u16 = 0x60;
const KEYBOARD_STATUS: u16 = 0x64;

const BUFFER_SIZE: usize = 256;

pub static mut RING_BUF: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];
static mut RING_HEAD: usize = 0;
static mut RING_TAIL: usize = 0;
pub static KEY_COUNT: AtomicU64 = AtomicU64::new(0);

static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);

fn inb(port: u16) -> u8 {
    let val: u8;
    unsafe { core::arch::asm!("in al, dx", in("dx") port, out("al") val, options(nostack, preserves_flags)); }
    val
}

fn outb(port: u16, val: u8) {
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nostack, preserves_flags)); }
}

fn cpu_pause() {
    unsafe { core::arch::asm!("pause", options(nostack, nomem)); }
}

struct KbState {
    shift: bool,
    capslock: bool,
    ctrl: bool,
    extended: bool,
    break_pending: bool,
}

static mut KB_STATE: KbState = KbState {
    shift: false,
    capslock: false,
    ctrl: false,
    extended: false,
    break_pending: false,
};

fn kb_state() -> &'static mut KbState {
    unsafe { &mut KB_STATE }
}

fn ring_push(c: u8) {
    unsafe {
        let next = (RING_HEAD + 1) % BUFFER_SIZE;
        if next != RING_TAIL {
            RING_BUF[RING_HEAD] = c;
            RING_HEAD = next;
        } else {
            RING_TAIL = (RING_TAIL + 1) % BUFFER_SIZE;
            RING_BUF[RING_HEAD] = c;
            RING_HEAD = next;
        }
    }
}

fn ring_pop() -> Option<u8> {
    unsafe {
        if RING_HEAD == RING_TAIL {
            None
        } else {
            let c = RING_BUF[RING_TAIL];
            RING_TAIL = (RING_TAIL + 1) % BUFFER_SIZE;
            Some(c)
        }
    }
}

fn ring_reset() {
    unsafe {
        RING_HEAD = 0;
        RING_TAIL = 0;
    }
}

// Simple US keyboard layout: scancode set 1
// Scancode set 1 tables — exactly 128 entries each (indices 0x00-0x7F)
static SCANCODE_MAP: [u8; 128] = [
    0,                  // 0x00
    27,                 // 0x01 Escape
    b'1',b'2',b'3',b'4',b'5',b'6',b'7',b'8',b'9',b'0',b'-',b'=', // 0x02-0x0D
    0x08,               // 0x0E Backspace
    b'\t',              // 0x0F Tab
    b'q',b'w',b'e',b'r',b't',b'y',b'u',b'i',b'o',b'p',b'[',b']', // 0x10-0x1B
    b'\n',              // 0x1C Enter
    0,                  // 0x1D Left Ctrl
    b'a',b's',b'd',b'f',b'g',b'h',b'j',b'k',b'l',b';',b'\'', // 0x1E-0x28
    b'`',               // 0x29
    0,                  // 0x2A Left Shift
    b'\\',              // 0x2B
    b'z',b'x',b'c',b'v',b'b',b'n',b'm',b',',b'.',b'/', // 0x2C-0x35
    0,                  // 0x36 Right Shift
    b'*',               // 0x37 Keypad *
    0,                  // 0x38 Left Alt
    b' ',               // 0x39 Space
    0,                  // 0x3A Caps Lock
    // 0x3B-0x7F = 69 unused keys, all 0
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,
];

static SCANCODE_SHIFT_MAP: [u8; 128] = [
    0,                  // 0x00
    27,                 // 0x01 Escape
    b'!',b'@',b'#',b'$',b'%',b'^',b'&',b'*',b'(',b')',b'_',b'+', // 0x02-0x0D
    0x08,               // 0x0E Backspace
    b'\t',              // 0x0F Tab
    b'Q',b'W',b'E',b'R',b'T',b'Y',b'U',b'I',b'O',b'P',b'{',b'}', // 0x10-0x1B
    b'\n',              // 0x1C Enter
    0,                  // 0x1D Left Ctrl
    b'A',b'S',b'D',b'F',b'G',b'H',b'J',b'K',b'L',b':',b'"', // 0x1E-0x28
    b'~',               // 0x29
    0,                  // 0x2A Left Shift
    b'|',               // 0x2B
    b'Z',b'X',b'C',b'V',b'B',b'N',b'M',b'<',b'>',b'?', // 0x2C-0x35
    0,                  // 0x36 Right Shift
    b'*',               // 0x37 Keypad *
    0,                  // 0x38 Left Alt
    b' ',               // 0x39 Space
    0,                  // 0x3A Caps Lock
    // 0x3B-0x7F = 69 unused keys, all 0
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,
];

pub fn push_char(c: u8) {
    ring_push(c);
    KEY_COUNT.fetch_add(1, Ordering::SeqCst);
    // Also push to TTY device for /dev/tty, /dev/console
    crate::tty::push_key(c);
    // Wake up any task blocked on stdin
    let addr = &raw const RING_BUF as u64;
    crate::task::futex_wake(addr as *const u32, 1);
}

/// Push a multi-byte escape sequence (e.g. arrow keys) into the input buffer,
/// byte by byte, so consumers see the full ANSI sequence.
fn push_seq(bytes: &[u8]) {
    for &c in bytes {
        push_char(c);
    }
}

pub fn pop_char() -> Option<u8> {
    let c = ring_pop()?;
    KEY_COUNT.fetch_sub(1, Ordering::SeqCst);
    Some(c)
}

pub fn read_char() -> u8 {
    loop {
        if let Some(c) = pop_char() {
            return c;
        }
        // Yield until input arrives
        crate::task::yield_now();
    }
}

pub fn read_line(buf: &mut [u8]) -> usize {
    let mut i = 0;
    loop {
        let c = read_char();
        match c {
            b'\n' | b'\r' => {
                if i < buf.len() {
                    buf[i] = b'\n';
                    i += 1;
                }
                return i;
            }
            0x08 | 0x7F => {
                // Backspace: go back if possible
                if i > 0 {
                    i -= 1;
                    crate::serial::write_str("\x08 \x08");
                }
            }
            _ => {
                if i < buf.len() - 1 {
                    buf[i] = c;
                    i += 1;
                    // Echo
                    crate::serial::write_char(c as char);
                }
            }
        }
    }
}

// ── Modifier / state tracking ────────────────────────────────────
// The 8042 (in translation mode = scancode set 1) emits a single make byte
// on press and a byte with bit 7 set on release. Extended keys (arrows,
// keypad) are prefixed with 0xE0. We keep state across interrupts here.
static mut SHIFT: bool = false;
static mut CAPSLOCK: bool = false;
static mut CTRL: bool = false;
static mut EXTENDED: bool = false;
// Scancode set 2 (translation OFF) prefixes a release with 0xF0 followed by the
// make code. With translation enabled (set 1) breaks use bit 7 and 0xF0 never
// appears, so this flag is inert there; it makes the handler correct for either
// mode (robust to a controller that isn't translating despite our command byte).
static mut BREAK_PENDING: bool = false;

const E0_UP: u16 = 0x48;
const E0_DOWN: u16 = 0x50;
const E0_LEFT: u16 = 0x4B;
const E0_RIGHT: u16 = 0x4D;
const E0_HOME: u16 = 0x47;
const E0_END: u16 = 0x4F;
const E0_PGUP: u16 = 0x49;
const E0_PGDN: u16 = 0x51;

fn key_char(sc: u16) -> u8 {
    let idx = sc as usize;
    if idx >= 128 { return 0; }
    let s = kb_state();
    let shifted = s.shift;
    let base = if shifted {
        SCANCODE_SHIFT_MAP[idx]
    } else {
        SCANCODE_MAP[idx]
    };
    // Apply Caps Lock: toggle case on letter keys (does not affect digits/symbols).
    if s.capslock {
        return base.to_ascii_uppercase();
    }
    base
}

/// Handle an extended (0xE0-prefixed) scancode. Modifier pills (Extended Ctrl/Alt)
/// and arrow/navigation keys mapped to ANSI escape sequences.
fn handle_extended(sc: u8) {
    let idx = sc as u16;
    let released = sc & 0x80 != 0;
    let make = idx & 0x7F;
    if released {
        return;
    }
    match make {
        E0_UP => push_seq(b"\x1b[A"),
        E0_DOWN => push_seq(b"\x1b[B"),
        E0_RIGHT => push_seq(b"\x1b[C"),
        E0_LEFT => push_seq(b"\x1b[D"),
        E0_HOME => push_seq(b"\x1b[H"),
        E0_END => push_seq(b"\x1b[F"),
        E0_PGUP => push_seq(b"\x1b[5~"),
        E0_PGDN => push_seq(b"\x1b[6~"),
        _ => {}
    }
}

#[no_mangle]
pub extern "x86-interrupt" fn keyboard_interrupt_handler(_frame: x86_64::structures::idt::InterruptStackFrame) {
    let status = inb(KEYBOARD_STATUS);
    if status & 1 != 0 {
        let sc = inb(KEYBOARD_DATA);

        // 0xF0 prefix (scancode set 2 break). If pending, the next byte is the
        // release code — ignore it but reset our modifier state for it.
        if sc == 0xF0 {
            kb_state().break_pending = true;
            crate::pic::send_eoi(1);
            return;
        }
        if kb_state().break_pending {
            kb_state().break_pending = false;
            // Mark the (already released) key's modifier bit cleared.
            match sc & 0x7F {
                0x2A | 0x36 => kb_state().shift = false,
                0x1D => kb_state().ctrl = false,
                _ => {}
            }
            crate::pic::send_eoi(1);
            return;
        }

        let released = sc & 0x80 != 0;
        let make = sc & 0x7F;

        // Track the 0xE0 prefix (extended key) first.
        if sc == 0xE0 {
            kb_state().extended = true;
            crate::pic::send_eoi(1);
            return;
        }

        if kb_state().extended {
            kb_state().extended = false;
            handle_extended(sc);
            crate::pic::send_eoi(1);
            return;
        }

        // Update modifier state on both press and release.
        match make {
            0x2A | 0x36 => kb_state().shift = !released, // Left/Right Shift
            0x1D => kb_state().ctrl = !released,          // Ctrl
            0x38 => { /* Alt — no layout impact here */ }
            _ => {}
        }

        if released {
            crate::pic::send_eoi(1);
            return;
        }

        // Caps Lock: toggle on press and consume.
        if make == 0x3A {
            let s = kb_state();
            s.capslock = !s.capslock;
            crate::pic::send_eoi(1);
            return;
        }

        if make < 128 {
            // Ctrl+letter → control character (e.g. Ctrl+C = 0x03). The TTY
            // uses ISIG to turn ^C into SIGINT; raw control codes still get
            // passed through so non-canonical readers can see them.
            let ctrl = kb_state().ctrl;
            if ctrl {
                let ch = key_char(make as u16);
                if ch.is_ascii_alphabetic() {
                    push_char(ch & 0x1F);
                    crate::pic::send_eoi(1);
                    return;
                }
            }
            let c = key_char(make as u16);
            if c != 0 {
                push_char(c);
            }
        }
    }
    crate::pic::send_eoi(1);
}

pub fn init() {
    if DEBUG_ENABLED.load(Ordering::Relaxed) {
        crate::serial::write_str("KBD: init\n");
    }
    // Wait for input buffer to be empty
    while inb(KEYBOARD_STATUS) & 0x02 != 0 {
        cpu_pause();
    }
    // Disable keyboard (command 0xAD)
    outb(KEYBOARD_STATUS, 0xAD);
    // Flush output buffer
    while inb(KEYBOARD_STATUS) & 0x01 != 0 {
        let _ = inb(KEYBOARD_DATA);
    }
    // Set command byte: enable IRQ1 (bit 0), translation (bit 6)
    while inb(KEYBOARD_STATUS) & 0x02 != 0 {
        cpu_pause();
    }
    outb(KEYBOARD_STATUS, 0x20); // Read command byte
    while inb(KEYBOARD_STATUS) & 0x01 == 0 {
        cpu_pause();
    }
    let mut cmd = inb(KEYBOARD_DATA);
    cmd |= 0x01; // Enable IRQ1
    cmd |= 0x40; // Translation
    while inb(KEYBOARD_STATUS) & 0x02 != 0 {
        cpu_pause();
    }
    outb(KEYBOARD_STATUS, 0x60); // Write command byte
    while inb(KEYBOARD_STATUS) & 0x02 != 0 {
        cpu_pause();
    }
    outb(KEYBOARD_DATA, cmd);
    // Enable keyboard (command 0xAE)
    while inb(KEYBOARD_STATUS) & 0x02 != 0 {
        cpu_pause();
    }
    outb(KEYBOARD_STATUS, 0xAE);
    // Reset keyboard (command 0xFF)
    while inb(KEYBOARD_STATUS) & 0x02 != 0 {
        cpu_pause();
    }
    outb(KEYBOARD_DATA, 0xFF);
    // Wait for ACK (0xFA) and BAT completion (0xAA)
    loop {
        while inb(KEYBOARD_STATUS) & 0x01 == 0 {
            cpu_pause();
        }
        let resp = inb(KEYBOARD_DATA);
        if resp == 0xFA { break; } // ACK
    }
    loop {
        while inb(KEYBOARD_STATUS) & 0x01 == 0 {
            cpu_pause();
        }
        let resp = inb(KEYBOARD_DATA);
        if resp == 0xAA { break; } // BAT success
    }
    // Flush any remaining
    while inb(KEYBOARD_STATUS) & 0x01 != 0 {
        let _ = inb(KEYBOARD_DATA);
    }

    ring_reset();
    KEY_COUNT.store(0, core::sync::atomic::Ordering::SeqCst);
    if DEBUG_ENABLED.load(Ordering::Relaxed) {
        crate::serial::write_str("KBD: OK\n");
    }
}
