use core::sync::atomic::{AtomicBool, Ordering};
use core::cell::UnsafeCell;

/// Save the current interrupt state and disable interrupts.
/// Returns the saved RFLAGS so it can be restored later with `irq_restore`.
/// Safe to call when interrupts are already disabled (returns the prior state).
#[inline(always)]
pub fn irq_save() -> u64 {
    let flags: u64;
    unsafe {
        core::arch::asm!("pushfq; pop {}", out(reg) flags, options(nomem, preserves_flags));
        core::arch::asm!("cli", options(nomem, preserves_flags));
    }
    flags
}

/// Restore a previously saved interrupt state.
#[inline(always)]
pub fn irq_restore(flags: u64) {
    unsafe {
        core::arch::asm!("push {}; popfq", in(reg) flags, options(nomem, preserves_flags));
    }
}

/// A spin lock that disables interrupts (on the local CPU) while held.
///
/// On a uniprocessor build disabling interrupts alone is sufficient to make a
/// critical section atomic. On SMP the `AtomicBool` provides cross-CPU mutual
/// exclusion: a CPU spins until the lock is free. Interrupts are always disabled
/// while held so the critical section cannot be re-entered by an IRQ on the same
/// CPU (the lock is non-reentrant; do not call code that re-takes it).
pub struct RawSpin {
    locked: AtomicBool,
}

unsafe impl Send for RawSpin {}
unsafe impl Sync for RawSpin {}

impl RawSpin {
    pub const fn new() -> Self {
        RawSpin { locked: AtomicBool::new(false) }
    }

    pub fn lock(&self) -> RawSpinGuard<'_> {
        let was = irq_save();
        while self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        RawSpinGuard { lock: self, was }
    }

    #[inline(always)]
    fn unlock(&self, was: u64) {
        self.locked.store(false, Ordering::Release);
        irq_restore(was);
    }
}

pub struct RawSpinGuard<'a> {
    lock: &'a RawSpin,
    was: u64,
}

impl<'a> Drop for RawSpinGuard<'a> {
    fn drop(&mut self) {
        self.lock.unlock(self.was);
    }
}

/// A data-protecting spin lock (irq-safe). Use instead of `static mut` for any
/// shared mutable state touched from both syscalls and interrupts / multiple CPUs.
pub struct Mutex<T: ?Sized> {
    lock: AtomicBool,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Send for Mutex<T> {}
unsafe impl<T: Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    pub const fn new(data: T) -> Self {
        Mutex {
            lock: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    pub fn lock(&self) -> MutexGuard<'_, T> {
        let was = irq_save();
        while self
            .lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        MutexGuard { mutex: self, was }
    }
}

pub struct MutexGuard<'a, T: ?Sized> {
    mutex: &'a Mutex<T>,
    was: u64,
}

impl<'a, T: ?Sized> core::ops::Deref for MutexGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.mutex.data.get() }
    }
}

impl<'a, T: ?Sized> core::ops::DerefMut for MutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<'a, T: ?Sized> Drop for MutexGuard<'a, T> {
    fn drop(&mut self) {
        self.mutex.lock.store(false, Ordering::Release);
        irq_restore(self.was);
    }
}
