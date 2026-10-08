# 01 — Kernel primitives on FW 12.02

## Privilege stack

```
ring 3   userland  (games, homebrew, elfldr payloads)
ring 0   guest kernel (Prospero / FreeBSD 11 fork)   <- KELF gadget chains run here
ring -1  hypervisor (SVM host, HV-owned memory)      <- never reached by any of this
```

Nothing in our stack executes code inside the hypervisor. The HV's
protections stay fully intact at all times, which is precisely why the
architecture below is designed to never need a kernel `.text` write.

## kread/kwrite mechanics [verified-in-tree]

Reference implementation: `ps5-payload-sdk/crt/kernel.c` (local checkout
`engineering/ps5debug-NG/ps5-payload-sdk/`; upstream ps5-payload-dev/sdk).

elfldr passes every payload ELF a `payload_args` block:

- `rwpair[2]` — master/victim socketpair descriptors
- `rwpipe[2]` — pipe descriptors
- `kpipe_addr` — kernel address of a pipe structure
- `kdata_base_addr` — kernel data base (KASLR resolved at load time)

Two primitives build on it:

1. **`kernel_write(addr, data)`** — the `setsockopt(IPPROTO_IPV6,
   IPV6_PKTINFO)` write on the master/victim socketpair. Two socket
   calls make the kernel store controlled qwords at an arbitrary kernel
   address. Firmware-stable.
2. **`kernel_copyin` / `kernel_copyout`** — corrupts the pipe at
   `kpipe_addr` via `kernel_write` (set the direct-copy flag bits, set
   the pipe's data address to the target `kaddr`), then a plain
   `write()`/`read()` on the pipe fds streams bytes between userland
   and kernel memory.

### Scope

- **Works on**: every RW mapping in the kernel's view — `.data`,
  `.bss`, heap, page tables, and (by walking a target's
  `vmspace`/`pmap`/`filedesc`/`ucred`) other processes' userland memory.
- **Blocked on**: kernel `.text` — no read, no write (see
  `02-xom-npt.md`).

## Page-table access [verified-in-tree]

- Guest page tables are ordinary kernel data → reachable with kread/
  kwrite.
- **Walk**: `vtophys_custom` style — 4-level walk from a CR3, entries
  read through the kernel direct map (`dmap = pm_pml4 - pm_cr3` of the
  kernel pmap; `pa_to_dmap(pa) = dmap + pa`).
- **Build**: `install_page`-style PTE construction (allocate a
  userland page, fault it in, `vtophys` it, write PTEs through dmap at
  every level).
- **Products of this fact**:
  - kstuff's UELF — a hand-built CR3 whose page tables map kernel
    physical pages RW *and* user-accessible (per-FW flag spelling,
    non-global direct-map entries to avoid stale TLB translations).
  - ps5debug-NG's `TSE_ALIASING` turbo-scan — "guarded page-table
    writes" aliasing a target's physical pages into the server's
    address space for DRAM-bandwidth reads, with a guard-miss fallback
    to the slow path.
- **Ceiling**: guest PTEs control VA→GPA only. The NPT (GPA→SPA) is
  HV-owned. PTE edits grant arbitrary guest-visible remapping of
  anything the NPT already permits, and cannot grant anything the NPT
  denies. Active cat-and-mouse surface: the HV validates guest mappings
  to varying degrees per FW, hence the "guarded"/"validated" design
  discipline in every shipped implementation.

## Kernel-mode execution without text writes

- **KELF (ring 0, gadget chains)**: control-flow data (trap frames,
  saved contexts, function pointers — all kernel data) is corrupted so
  kernel execution enters *existing* `.text` instructions with chosen
  register state; chains are advanced via #DB single-step capture.
  Per-FW validated entries (kstuff 1.11: `mov_rax_cr0`, `cpu_switch`
  tail, `wrmsr` argument area, scalar `mov [rdi], rax` store helper).
  Even "KELF 8-byte writes" are a store *gadget*, not new code.
- **UELF (ring 3, custom CR3)**: kstuff's own code runs in a private
  user-mode context whose page tables map kernel physical memory RW.
  Bulk kernel-memory work (fake-key PFS/XTS/HMAC crypto) happens here
  with zero per-access ring transitions.
- **CR0.TS / FPU machinery** (kstuff 1.11): the UELF's SIMD crypto needs
  CR0.TS cleared and kernel FPU state saved (XSAVEC/XSAVE selected via
  CPUID 0xD + XCR0 validation, restore via XRSTOR); entry is a
  per-kernel-gadget chain with no legacy fallback — failure is
  reported, never ignored, because corrupt kernel FPU state = console
  crash.

## Multi-Firmware dispatch [verified-in-tree]

- `kernel_get_fw_version()` = `sysctl` `kern.sdk_version` (mib `{1,46}`),
  read at runtime.
- Per-FW symbol/offset tables compiled in from offline analysis (text
  is unreadable at runtime — see `03-evolution-pre761.md` for where the
  tables come from):
  - ps5-payload-sdk `crt/kernel.c` switch populates `KERNEL_ADDRESS_*`
    (allproc, prison0, rootvnode, security_flags, qa_flags, ...) and
    `KERNEL_OFFSET_*` struct layouts per FW family.
  - ps5debug-NG `installer/source/main.c` kpatch table — data-flag
    patch addresses per FW, 3.xx–13.xx.
  - kstuff per-FW kernel layouts incl. validated gadget entries.
- **Lapy's trick** (`PS5-Lapy-JB-Daemon/source/offsets_v940.cpp`):
  libhijacker's vanilla `offsets.cpp` hardcodes 9.40; Lapy links an
  override *before* `-lhijacker` that converts the SDK's
  runtime-resolved `KERNEL_ADDRESS_*` VAs into libhijacker's offset
  namespace — multi-FW by construction, clean NULL-attach failure on
  unknown FW.
- **Runtime layout preflight** (Lapy `owned_root_daemon.c`): the table
  is never trusted blindly on an untested FW — `validate_group_layout`
  / `validate_root_reference_layout` check the assumed layout against
  live *data* behavior (disposable `rfork` donor child, native
  `getgroups`) before touching a real target; abort on mismatch.
