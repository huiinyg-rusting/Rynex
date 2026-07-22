use core::sync::atomic::{AtomicU64, Ordering};

const KEYBOARD_DATA: u16 = 0x60;
const KEYBOARD_STATUS: u16 = 0x64;

const BUFFER_SIZE: usize = 256;

pub static mut RING_BUF: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];
static mut RING_HEAD: usize = 0;
static mut RING_TAIL: usize = 0;
pub static KEY_COUNT: AtomicU64 = AtomicU64::new(0);

fn inb(port: u16) -> u8 {
    let val: u8;
    unsafe { core::arch::asm!("in al, dx", in("dx") port, out("al") val, options(nostack, preserves_flags)); }
    val
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
    unsafe {
        let next = (RING_HEAD + 1) % BUFFER_SIZE;
        if next != RING_TAIL {
            RING_BUF[RING_HEAD] = c;
            RING_HEAD = next;
        } else {
            // Buffer full: overwrite oldest
            RING_TAIL = (RING_TAIL + 1) % BUFFER_SIZE;
            RING_BUF[RING_HEAD] = c;
            RING_HEAD = next;
        }
    }
    KEY_COUNT.fetch_add(1, Ordering::SeqCst);
    // Wake up any task blocked on stdin
    let addr = &raw const RING_BUF as u64;
    crate::task::futex_wake(addr as *const u32, 1);
}

pub fn pop_char() -> Option<u8> {
    unsafe {
        if RING_HEAD == RING_TAIL {
            None
        } else {
            let c = RING_BUF[RING_TAIL];
            RING_TAIL = (RING_TAIL + 1) % BUFFER_SIZE;
            KEY_COUNT.fetch_sub(1, Ordering::SeqCst);
            Some(c)
        }
    }
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

#[no_mangle]
pub extern "x86-interrupt" fn keyboard_interrupt_handler(_frame: x86_64::structures::idt::InterruptStackFrame) {
    let status = inb(KEYBOARD_STATUS);
    if status & 1 != 0 {
        let scancode = inb(KEYBOARD_DATA);
        if scancode & 0x80 == 0 {
            // Key press (not release)
            let idx = scancode as usize;
            if idx < 128 {
                let c = SCANCODE_MAP[idx];
                if c != 0 {
                    push_char(c);
                }
            }
        }
    }
    crate::pic::send_eoi(1);
}

pub fn init() {
    crate::serial::write_str("KBD: init\n");
    // Clear stale scancodes left by keyboard controller initialization
    unsafe {
        RING_HEAD = 0;
        RING_TAIL = 0;
    }
    KEY_COUNT.store(0, core::sync::atomic::Ordering::SeqCst);
}
