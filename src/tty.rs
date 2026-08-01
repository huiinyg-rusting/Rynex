use crate::spinlock::Mutex;
use crate::vfs_core::types::*;
use crate::vfs_core::VnodeOps;
use crate::serial;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

const TTY_BUFFER_SIZE: usize = 4096;
const VGA_WIDTH: usize = 80;
const VGA_HEIGHT: usize = 25;

static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);

macro_rules! debug {
    ($($arg:tt)*) => {
        if DEBUG_ENABLED.load(Ordering::Relaxed) {
            serial::write_str("[TTY] ");
            serial::write_str(&alloc::format!($($arg)*));
            serial::write_str("\n");
        }
    };
}

pub struct TtyDevice {
    input_buf: Mutex<InputBuffer>,
    output_buf: Mutex<OutputBuffer>,
    termios: Mutex<Termios>,
    winsize: Mutex<Winsize>,
    fg_pgrp: Mutex<i32>,
    read_futex: AtomicU32,
}

struct InputBuffer {
    buf: [u8; TTY_BUFFER_SIZE],
    head: usize,
    tail: usize,
    count: usize,
    line_ready: bool,
    echo: bool,
    canonical: bool,
}

struct OutputBuffer {
    buf: [u8; TTY_BUFFER_SIZE],
    head: usize,
    tail: usize,
}

struct Termios {
    c_iflag: u32,
    c_oflag: u32,
    c_cflag: u32,
    c_lflag: u32,
    c_cc: [u8; 32],
}

struct Winsize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

impl TtyDevice {
    pub const fn new() -> Self {
        TtyDevice {
            input_buf: Mutex::new(InputBuffer {
                buf: [0; TTY_BUFFER_SIZE],
                head: 0,
                tail: 0,
                count: 0,
                line_ready: false,
                echo: true,
                canonical: true,
            }),
            output_buf: Mutex::new(OutputBuffer {
                buf: [0; TTY_BUFFER_SIZE],
                head: 0,
                tail: 0,
            }),
            termios: Mutex::new(Termios {
                c_iflag: 0,
                c_oflag: 0,
                c_cflag: 0,
                c_lflag: ICANON | ECHO | ECHOE | ISIG,
                c_cc: [0; 32],
            }),
            winsize: Mutex::new(Winsize {
                ws_row: VGA_HEIGHT as u16,
                ws_col: VGA_WIDTH as u16,
                ws_xpixel: 0,
                ws_ypixel: 0,
            }),
            fg_pgrp: Mutex::new(1),
            read_futex: AtomicU32::new(0),
        }
    }

    fn push_input(&self, c: u8) {
        let echo: bool;
        let canonical: bool;
        {
            let input = self.input_buf.lock();
            let termios = self.termios.lock();
            echo = termios.c_lflag & ECHO != 0 && input.echo;
            canonical = termios.c_lflag & ICANON != 0;
        }

        let mut input = self.input_buf.lock();

        if input.count >= TTY_BUFFER_SIZE {
            return;
        }

        if canonical {
            if c == b'\n' || c == b'\r' {
                input.line_ready = true;
            }
        }

        if echo {
            self.put_char_raw(c);
        }

        let head = input.head;
        input.buf[head] = c;
        input.head = (head + 1) % TTY_BUFFER_SIZE;
        input.count += 1;

        // Wake up any task blocked on read
        self.read_futex.store(1, Ordering::SeqCst);
        let futex_addr = &self.read_futex as *const AtomicU32 as *const u32;
        crate::task::futex_wake(futex_addr, 1);
    }

    fn pop_input(&self, buf: &mut [u8]) -> usize {
        let canonical = {
            let termios = self.termios.lock();
            termios.c_lflag & ICANON != 0
        };

        let mut input = self.input_buf.lock();

        if input.count == 0 {
            return 0;
        }

        if canonical && !input.line_ready {
            return 0;
        }

        let mut read = 0;
        while read < buf.len() && input.count > 0 {
            let tail = input.tail;
            let c = input.buf[tail];
            buf[read] = c;
            input.tail = (tail + 1) % TTY_BUFFER_SIZE;
            input.count -= 1;
            read += 1;

            if canonical && (c == b'\n' || c == b'\r') {
                input.line_ready = false;
                break;
            }
        }
        read
    }

    fn put_char_raw(&self, c: u8) {
        match c {
            b'\n' => crate::vga::write_str("\n"),
            b'\r' => crate::vga::write_str("\r"),
            b'\t' => crate::vga::write_str("    "),
            b'\x08' | 0x7F => crate::vga::write_str("\x08 \x08"),
            c if c >= 0x20 && c <= 0x7E => crate::vga::write_char(c as char),
            _ => {}
        }
    }

    fn write_output(&self, data: &[u8]) -> usize {
        let mut written = 0;
        for &c in data {
            self.put_char_raw(c);
            // Also output to serial for debugging
            crate::serial::write_char(c as char);
            written += 1;
        }
        written
    }

    fn get_termios(&self, buf: &mut [u8]) -> Result<usize, &'static str> {
        let termios = self.termios.lock();
        if buf.len() < core::mem::size_of::<Termios>() {
            return Err("buffer too small");
        }
        unsafe {
            core::ptr::copy_nonoverlapping(
                &*termios as *const Termios as *const u8,
                buf.as_mut_ptr(),
                core::mem::size_of::<Termios>()
            );
        }
        Ok(core::mem::size_of::<Termios>())
    }

    fn set_termios(&self, buf: &[u8]) -> Result<usize, &'static str> {
        if buf.len() < core::mem::size_of::<Termios>() {
            return Err("buffer too small");
        }
        let mut termios = self.termios.lock();
        unsafe {
            core::ptr::copy_nonoverlapping(
                buf.as_ptr(),
                &mut *termios as *mut Termios as *mut u8,
                core::mem::size_of::<Termios>()
            );
        }
        let mut input = self.input_buf.lock();
        input.echo = termios.c_lflag & ECHO != 0;
        input.canonical = termios.c_lflag & ICANON != 0;
        Ok(core::mem::size_of::<Termios>())
    }

    fn get_winsize(&self, buf: &mut [u8]) -> Result<usize, &'static str> {
        let ws = self.winsize.lock();
        if buf.len() < core::mem::size_of::<Winsize>() {
            return Err("buffer too small");
        }
        unsafe {
            core::ptr::copy_nonoverlapping(
                &*ws as *const Winsize as *const u8,
                buf.as_mut_ptr(),
                core::mem::size_of::<Winsize>()
            );
        }
        Ok(core::mem::size_of::<Winsize>())
    }

    fn set_fg_pgrp(&self, pgrp: i32) {
        *self.fg_pgrp.lock() = pgrp;
    }

    fn get_fg_pgrp(&self) -> i32 {
        *self.fg_pgrp.lock()
    }
}

const TCGETS: u64 = 0x5401;
const TCSETS: u64 = 0x5402;
const TCSETSW: u64 = 0x5403;
const TCSETSF: u64 = 0x5404;
const TIOCGWINSZ: u64 = 0x5413;
const TIOCSWINSZ: u64 = 0x5414;
const TIOCGPGRP: u64 = 0x540F;
const TIOCSPGRP: u64 = 0x5410;
const TCFLSH: u64 = 0x540B;

const ICANON: u32 = 0x00000002;
const ECHO: u32 = 0x00000008;
const ECHOE: u32 = 0x00000010;
const ISIG: u32 = 0x00000001;

impl VnodeOps for TtyDevice {
    fn read(&self, _ino: u64, _offset: u64, buf: &mut [u8]) -> Result<usize, &'static str> {
        if buf.is_empty() {
            return Ok(0);
        }
        debug!("read called, buf_len={}", buf.len());
        loop {
            let n = self.pop_input(buf);
            if n > 0 {
                debug!("read: got {} bytes", n);
                return Ok(n);
            }
            // No input available, check serial port for input (for -serial stdio)
            if let Some(c) = crate::serial::read_byte_nonblocking() {
                // Echo to output
                self.put_char_raw(c);
                // Add to input buffer
                self.push_input(c);
                continue;
            }
            // No input available, wait for interrupt
            unsafe {
                core::arch::asm!("sti; hlt; cli", options(nostack, preserves_flags));
            }
        }
    }

    fn write(&self, _ino: u64, _offset: u64, buf: &[u8]) -> Result<usize, &'static str> {
        if buf.is_empty() {
            return Ok(0);
        }
        debug!("write called, buf_len={}", buf.len());
        let n = self.write_output(buf);
        Ok(n)
    }

    fn ioctl(&self, _ino: u64, request: u64, arg: u64) -> Result<usize, &'static str> {
        debug!("ioctl request=0x{:x} arg=0x{:x}", request, arg);
        match request {
            TCGETS => {
                if arg == 0 {
                    return Err("EFAULT");
                }
                let mut termios = [0u8; core::mem::size_of::<Termios>()];
                self.get_termios(&mut termios)?;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        termios.as_ptr(),
                        arg as *mut u8,
                        termios.len()
                    );
                }
                Ok(0)
            }
            TCSETS | TCSETSW | TCSETSF => {
                if arg == 0 {
                    return Err("EFAULT");
                }
                let mut termios = [0u8; core::mem::size_of::<Termios>()];
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        arg as *const u8,
                        termios.as_mut_ptr(),
                        termios.len()
                    );
                }
                self.set_termios(&termios)?;
                Ok(0)
            }
            TIOCGWINSZ => {
                if arg == 0 {
                    return Err("EFAULT");
                }
                let mut ws = [0u8; core::mem::size_of::<Winsize>()];
                self.get_winsize(&mut ws)?;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        ws.as_ptr(),
                        arg as *mut u8,
                        ws.len()
                    );
                }
                Ok(0)
            }
            TIOCSWINSZ => {
                if arg == 0 {
                    return Err("EFAULT");
                }
                let mut ws = [0u8; core::mem::size_of::<Winsize>()];
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        arg as *const u8,
                        ws.as_mut_ptr(),
                        ws.len()
                    );
                }
                let mut winsize = self.winsize.lock();
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        ws.as_ptr(),
                        &mut *winsize as *mut Winsize as *mut u8,
                        ws.len()
                    );
                }
                Ok(0)
            }
            TIOCGPGRP => {
                if arg == 0 {
                    return Err("EFAULT");
                }
                let pgrp = self.get_fg_pgrp();
                unsafe {
                    *(arg as *mut i32) = pgrp;
                }
                Ok(0)
            }
            TIOCSPGRP => {
                if arg == 0 {
                    return Err("EFAULT");
                }
                let pgrp = unsafe { *(arg as *const i32) };
                self.set_fg_pgrp(pgrp);
                Ok(0)
            }
            TCFLSH => {
                let mut input = self.input_buf.lock();
                input.head = 0;
                input.tail = 0;
                input.count = 0;
                input.line_ready = false;
                Ok(0)
            }
            _ => {
                debug!("unsupported ioctl 0x{:x}", request);
                Err("ENOTTY")
            }
        }
    }

    fn lookup(&self, _parent_ino: u64, _name: &[u8]) -> Result<u64, &'static str> {
        Err("ENOTDIR")
    }

    fn readdir(&self, _dir_ino: u64, _offset: u64, _buf: &mut [Dirent]) -> Result<usize, &'static str> {
        Err("ENOTDIR")
    }

    fn create(&self, _parent_ino: u64, _name: &[u8], _mode: FileMode) -> Result<u64, &'static str> {
        Err("EPERM")
    }

    fn mkdir(&self, _parent_ino: u64, _name: &[u8], _mode: FileMode) -> Result<u64, &'static str> {
        Err("EPERM")
    }

    fn remove(&self, _parent_ino: u64, _name: &[u8]) -> Result<(), &'static str> {
        Err("EPERM")
    }

    fn rmdir(&self, _parent_ino: u64, _name: &[u8]) -> Result<(), &'static str> {
        Err("EPERM")
    }

    fn stat(&self, _ino: u64) -> Result<Stat, &'static str> {
        Ok(Stat {
            dev: 5,
            ino: 1,
            mode: S_IFCHR | 0o666,
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: (5 << 8) | 0,
            size: 0,
            blksize: 0,
            blocks: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
        })
    }

    fn readlink(&self, _ino: u64) -> Result<&[u8], &'static str> {
        Err("EINVAL")
    }

    fn symlink(&self, _parent_ino: u64, _name: &[u8], _target: &[u8]) -> Result<u64, &'static str> {
        Err("EPERM")
    }

    fn rename(&self, _old_parent: u64, _old_name: &[u8], _new_parent: u64, _new_name: &[u8]) -> Result<(), &'static str> {
        Err("EPERM")
    }

    fn setattr(&self, _ino: u64, _attr: &Attr) -> Result<(), &'static str> {
        Err("EPERM")
    }

    fn getxattr(&self, _ino: u64, _name: &[u8], _value: &mut [u8]) -> Result<usize, &'static str> {
        Err("ENOTSUP")
    }

    fn setxattr(&self, _ino: u64, _name: &[u8], _value: &[u8]) -> Result<(), &'static str> {
        Err("ENOTSUP")
    }

    fn listxattr(&self, _ino: u64, _buf: &mut [u8]) -> Result<usize, &'static str> {
        Err("ENOTSUP")
    }

    fn truncate(&self, _ino: u64, _size: u64) -> Result<(), &'static str> {
        Err("EINVAL")
    }
}

pub static TTY_DEVICE: TtyDevice = TtyDevice::new();

pub fn push_key(c: u8) {
    TTY_DEVICE.push_input(c);
}

pub fn init() {
    debug!("TTY initialized");
}