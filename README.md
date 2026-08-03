# Rynex kernel

A hobby x86_64 microkernel written in Rust (monolithic core, IPC-based user-space services planned).

- Version: 0.0.1 Alpha
- Target: x86_64 (multiboot2)
- Toolchain: nightly (see `rust-toolchain.toml`)

## Build

```sh
cargo +nightly build --release --target x86_64-unknown-none
# output: target/x86_64-unknown-none/release/rynex-kernel
```

The kernel crate is self-contained (linker script in `build.rs`/`linker.ld`,
boot assembly in `src/boot.asm`).

## Layout

- `src/` — kernel sources (memory, paging, scheduling, VFS, drivers)
- `src/boot.asm` — multiboot2 entry

The distro (user-space, busybox, initramfs, ISO) lives in the separate
**rynex-original** repository.
