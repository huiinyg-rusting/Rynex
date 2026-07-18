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
    // In a real OS, we'd properly clean up the task
    // For now, just halt the current task
    crate::serial::write_str("SYS_EXIT: ");
    crate::serial::write_dec(status as i64);
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
const EAGAIN: i64 = -35;
const EWOULDBLOCK: i64 = EAGAIN;
const EINPROGRESS: i64 = -36;
const EALREADY: i64 = -37;
const ENOTSOCK: i64 = -38;
const EDESTADDRREQ: i64 = -39;
const EMSGSIZE: i64 = -40;
const EPROTOTYPE: i64 = -41;
const ENOPROTOOPT: i64 = -42;
const EPROTONOSUPPORT: i64 = -43;
const ESOCKTNOSUPPORT: i64 = -44;
const EOPNOTSUPP: i64 = -45;
const EPFNOSUPPORT: i64 = -46;
const EAFNOSUPPORT: i64 = -47;
const EADDRINUSE: i64 = -48;
const EADDRNOTAVAIL: i64 = -49;
const ENETDOWN: i64 = -50;
const ENETUNREACH: i64 = -51;
const ENETRESET: i64 = -52;
const ECONNABORTED: i64 = -53;
const ECONNRESET: i64 = -54;
const ENOBUFS: i64 = -55;
const EISCONN: i64 = -56;
const ENOTCONN: i64 = -57;
const ESHUTDOWN: i64 = -58;
const ETOOMANYREFS: i64 = -59;
const ETIMEDOUT: i64 = -60;
const ECONNREFUSED: i64 = -61;
const EHOSTDOWN: i64 = -62;
const EHOSTUNREACH: i64 = -63;
const EINPROGRESS: i64 = -36;
const EALREADY: i64 = -37;
const EDESTADDRREQ: i64 = -39;
const EMSGSIZE: i64 = -40;
const EPROTOTYPE: i64 = -41;
const ENOPROTOOPT: i64 = -42;
const ENOSR: i64 = -64;
const ENONET: i64 = -65;
const ENOPKG: i64 = -66;
const EREMOTE: i64 = -67;
const ENOLINK: i64 = -68;
const EADV: EADV = i64 = -69;
const ESRMNT: i64 = -70;
const ECOMM: i64 = -71;
const EPROTO: i64 = -72;
const EMULTIHOP: i64 = -73;
const EDOTDOT: i64 = -74;
const EREMOTEIO: i64 = -75;
const EDQUOT: i64 = -76;
const ENOMEDIUM: i64 = -77;
const EMEDIUMTYPE: i64 = -78;
const ECANCELED: i64 = -79;
const ENOKEY: i64 = -80;
const EKEYEXPIRED: i64 = -81;
const EKEYREVOKED: i64 = -82;
const EKEYREJECTED: i64 = -83;
const EOWNERDEAD: i64 = -84;
const ENOTRECOVERABLE: i64 = -85;
const ERFKILL: i64 = -86;
const EHWPOISON: i64 = -87;

// For simplicity, just define the ones we need
const ENOSYS: i64 = -38; // Function not implemented