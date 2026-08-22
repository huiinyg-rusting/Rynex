# Bug Log / 漏洞记录

记录安全/稳定性问题。状态：`CONFIRMED`(代码核实属实) / `PARTIAL`(部分属实) /
`SINGLE-CORE-OK`(仅 SMP 下成立，当前单核内核不构成利用) / `FIXED` / `OPEN`。

> 内核当前为**单核**实现（无 AP/LAPIC/ACPI/SMP 基础设施）。报告中的大量"竞态"
> 仅在多 CPU 并发下才真实成立；但其中多数同样需要加锁才能支持 SMP。本日志同时
> 记录"已落实 SMP"后的修复。

---

## 已修复（含历史）

- [FIXED] legacy virtio-blk 启动失败：描述符环头偏移(4B)、used 环页对齐、队列地址写
  PFN、设备状态寄存器 0x12、ISR 寄存器 0x13、特性协商屏蔽 EVENT_IDX、读路径回拷数据。
  （commit 89cd609）
- [FIXED] buddy `free` 双重释放**误报**：`free_stack` 在 `alloc.free` 前把栈块标
  `PAGE_TYPE_FREE`，触发 `alloc.free` 的 `old_type==FREE` 检查误判正常
  alloc→free→复用→free 生命周期。改为 free 后再标；诊断 `used` 索引改用 `phys_to_idx`。
  （commit 89cd609）
- [FIXED] buddy 双重释放检测 `DF_MAX_PAGES` 过小（64MiB）导致首释放调用方记录被数组
  越界丢弃；扩到 1<<18 覆盖 -m 512M。（commit 89cd609）
- [FIXED] **init 的第 2 个及以后子进程永不启动（无 ash）**：`sys_fork`
  (`src/task.rs:3643` 旧 "Hack") 对 `id==1` 的 fork 只把第一个子进程置 `Ready`，
  其余置 `Blocked` 且从未被唤醒。runit 先 fork dummy（第 1 个→能跑），
  再 fork shell（第 2 个→永久 Blocked）→ shell 进程永不被调度，`run-gui`/serial
  都看不到 ash。改为所有 fork 子进程均 `Ready`。
- [FIXED] `TIOCGPGRP` 不写回前台进程组（`src/task.rs:5377` 原 `return 0`），
  导致 busybox ash 自认后台、对自己发 `SIGTTIN` 自我停止。已让 `TIOCGPGRP` 返回
  调用者 pgrp、`TIOCSPGRP` 存储之（配合 `tty.rs` 既有 `fg_pgrp`）。
- [CONFIRMED][P1] 释放 fork 子进程地址空间时 `free_address_space` 报
  `FAS BADPML4 pml4=0x17D0000 used=0`：fork 用 `alloc_zeroed_page` 分配的子 pml4
  页经 `page_is_used` 判定为"未使用"，使守卫提前 return（旧地址空间泄漏），且暗示
  buddy 对已分配页的 used 位记录与 free 路径不一致（存在重复分配同页风险）。
  需审计 `alloc`/`free` 与 `used_mark`/`used_clear` 的一致性。

---

## 严重 / P0

### [FIXED] PID 槽位别名（提权）
- 位置：`src/task.rs` `task_idx(id)=id%MAX_TASKS`；`NEXT_TID` 单调递增。`MAX_TASKS=64`。
- 现象：PID 越过 64 后 `task_idx` 取模回绕，PID 65 映射到 slot 1（init）。
  runit 反复重启 dummy 会使 PID 持续增长 → 最终别名 init 槽位，造成任务混淆/提权。
- 修复：改为基于 64 位槽位位图的 PID 分配（pid==slot，boot=0/init=1/kernel>=2，
  `alloc_kernel_pid`/`alloc_user_pid`/`alloc_pid_specific`，waitpid 回收 `free_pid`）。
  **注意**：初版误把 init 放在 slot 0（与 boot 任务同槽），导致 `TASKS[0]` 被覆盖、内核在
  首次切到 init 后挂死；现改为 boot 占 slot 0、init 占 slot 1，已验证 `make run-gui` 进入 ash 正常。

### [CONFIRMED] 信号处理 handler 未校验地址
- 位置：`src/task.rs:5024 sys_rt_sigaction` 校验了 `act` 指针落在用户空间，但未校验
  `handler`/`restorer` 本身是否为用户地址（可设为内核地址）。
- 影响：handler 在用户态执行，内核地址会 #GP（非直接内核执行任意代码，但属缺失校验）。
- 修复：对 `handler`/`restorer` 做 `is_user_addr` 校验（保留 SIG_DFL/SIG_IGN 特殊值）。

### [CONFIRMED] Vnode Use-After-Free / 生命周期错误
- 位置：`src/vfs_core/mod.rs:553 vnode_get`、`:559 vnode_get_mut`
  （`#[allow(invalid_reference_casting)]`），在 `VNODE_TABLE.lock()` 的 guard 释放后返回
  `&'static`/`&'static mut Vnode`。
- 影响：SMP 下返回引用与锁无关，并发访问=数据竞争。
- 修复：返回持有锁的 guard（Deref/DerefMut），或改为每-vnode 自旋锁。

---

## 高 / P1

### [CONFIRMED] 运行队列无同步
- 位置：`src/task.rs:499 enqueue_task`、`:519 dequeue_task`、`:539 remove_from_runqueue`
  直接 `unsafe` 操作 `static mut RUNQUEUE`，无锁。
- 影响：SMP 下定时器中断 + 系统调用并发修改链表 → 链表损坏/panic。单核下若中断在
  临界区触发且中断也操作 runqueue 同样损坏。
- 修复：RUNQUEUE 加 IRQ 保存自旋锁。

### [CONFIRMED] Buddy 分配器完全无锁
- 位置：`src/memory/buddy.rs:324 BuddyAllocator`（`free_lists` 裸指针数组，无同步）。
- 影响：SMP 下并发 alloc/free → 空闲链表损坏、双重分配/释放。
- 修复：分配器内部加 IRQ 保存自旋锁（alloc/free/mark_allocated/free_reserved 等）。

### [CONFIRMED] 全局定时器/抢占暂存区
- 位置：`src/task.rs:451 TIMER_FRAME_SCRATCH`、`:455 PREEMPT_SCRATCH`、`:5138 PENDING_RESTORE`、
  `:5293 ALTSTACK_*`。多任务/多 CPU 共享同一暂存区。
- 影响：SMP 下并发定时器中断互相覆盖抢占帧 → RIP 跳转错误/上下文错乱。
- 修复：per-CPU 化（或抢占期间关中断 + 单核下已安全；SMP 下需 per-CPU）。

### [CONFIRMED] COW fork 缺 PTE 引用计数（报告 2.1）
- 位置：`src/paging.rs cow_fork_pml4` 共享父页表页但 `free_address_space` 在首任务退出时
  释放。当前实现有 `pte_refc_*` 计数，但 SMP/并发 fork+pagefault 下非原子
  （`cow_walk_pte` check-then-act）。
- 修复：refcount 操作加锁/原子；fork 与 page fault 临界区互斥。

### [CONFIRMED] map_into 无参数校验
- 位置：`src/paging.rs:180 map_into`：未校验 `phys` 在 buddy 管理范围、未做重叠检查、
  未在设置 `PTE_USER` 时校验 `virt` 在用户空间。
- 影响：可映射任意物理内存到用户空间。
- 修复：校验 phys 范围、virt 用户空间、overlap。

---

## 中 / P2

### [CONFIRMED] ELF phnum 边界检查顺序
- 位置：`src/elf.rs:223` 先读 `phoff/phentsize/phnum` 再做边界检查；乘法在 64 位下不溢出
  但应先 `checked_mul` 加固。
- 修复：`checked_mul` + 早返回。

### [CONFIRMED] 隔离区满静默泄漏物理页
- 位置：`src/memory/buddy.rs:162 q_push`：隔离区满时直接丢弃页（`QUARANTINE_FULL_COUNT++`），
  页不归还 buddy → 内存泄漏 DoS。
- 修复：满时直接 `free_one` 归还 buddy（或阻塞），不再泄漏。

### [CONFIRMED] 双重释放检测 O(n) 线性扫描
- 位置：`src/memory/buddy.rs:19 track_freed_page` 每次 free 扫 `FREED_PAGES`（最高 65536）。
- 影响：DoS 向量（每次 free 线性开销）。
- 修复：改为哈希/小集合或 per-page 位（已有 `FREED_PAGES` 环形，可缩小或换结构）。

### [PARTIAL] Futex TOCTOU
- 位置：`src/task.rs:2773 futex_wait`：读 `uaddr` 与阻塞非原子。
- 影响：单核下若临界区关中断则安全；SMP 下需 `AtomicU32` + 内核侧 cmpxchg。

### [PARTIAL] VMA 池无锁 / O(n)
- 位置：`src/task.rs:2281 vma_register` 等：`static mut VMAS` 无锁，线性扫描，固定 65536。
- 影响：SMP 下损坏；DoS（大量小 mmap）。

### [OPEN] IPC 端口名截断匹配 / 邮箱无锁 / 回复槽无锁
- 位置：`src/ipc.rs:96 port_id_by_name`、`:367 mailbox`、`:137 REPLIES`。
- 影响：端口劫持、消息丢失/重复、槽位泄漏（SMP）。

### [OPEN] 信号投递 `sig_pending` 竞态 / 组投递遍历
- 位置：`src/task.rs:4832 sig_deliver_to_task`、`:4930`。

### [OPEN] waitpid/exit、kill_task_zombie 竞态
- 位置：`src/task.rs:1014 exit_task`、`:3090 sys_waitpid`、`:4900`。
  （孤儿任务栈泄漏、child_tidptr 陈旧 VA 写入。）

### [PARTIAL] `general_protection` 压制引用检查（`interrupts.rs:204`、`#[allow(invalid_reference_casting)]`×2）

### [OPEN] 栈固定地址无 ASLR（`elf.rs:461`）、`sys_phys_map`/`sys_dma_alloc`/`sys_pci_*` 缺校验
  （`task.rs:2410,:2484,:2618`）

---

## 代码质量 / 结构性
- 96 个 `static mut`、200+ `unsafe`、8 个 >100 行函数（`sys_execve` 544 行等）、
  硬编码魔法数字、TLS 初始化 14 个手写 `write_volatile` 偏移。
- 安全机制被故意关闭：`#[allow(invalid_reference_casting)]`×2。

---

## 修复优先级（落实 SMP 后）
1. P0：PID 槽位别名、信号 handler 校验、Vnode 生命周期、运行队列加锁、Buddy 加锁
2. P1：定时器/抢占 per-CPU 暂存区、COW refcount 原子化、map_into 校验
3. P2：ELF 边界、隔离区泄漏、双重释放检测 O(n)、Futex 原子、VMA 锁、IPC 锁
