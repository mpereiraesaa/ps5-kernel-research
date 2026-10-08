# 07 — Console evidence log

Chronological record of console experiments. Format per `AGENTS.md`:
date, FW, payload identity, expected observation, actual observation,
recovery state. Epistemic label: `[verified-on-console]` (see README).

## 2026-10-08 — kdata_probe (route step 1, first validation)

- **Payload**: `engineering/payloads/kdata_probe/kdata_probe.elf`
  — sha256 `16d378f3e8eea94b7c0fb7a5a252167426c5d32cea5d106ae990d4a31d901327`,
  113,504 bytes.
- **Delivery**: elfldr TCP 9021 (`send_elf.py --wait-response
  --expect-response "kdata_probe OK"`). Response verbatim on the same
  socket.
- **FW**: `kernel_get_fw_version() = 0x12020000` (12.02).

### Expected

- `fw=0x12020000`; non-null SDK-resolved `KERNEL_ADDRESS_*`;
  `kernel_copyout` of one page at `allproc` returns 0; 16 bytes readable
  at the ps5debug-NG FW 12.x kpatch address with byte[1] bits 0b11 set
  (jailbreak applied state).

### Observed [verified-on-console]

```
kdata_probe fw=0x12020000
ktext_base  =0xffffffffd7750000
kdata_base  =0xffffffffd84a0000
allproc     =0xffffffffdad25e00
prison0     =0xffffffffda3c29f0
rootvnode   =0xffffffffdb577510
sec_flags   =0xffffffffd9223064
utoken_flags=0xffffffffd92230f0
qa_flags    =0xffffffffd9223088
proc_p_pid_off=0xbc
copyout allproc page rc=0
(allproc page hexdump: kernel heap pointers 0xffffa465..., kernel
 image pointers 0xffffffffd88fb9bf / 0xffffffffd88d18f3, zeroed tail)
copyout kpatch rc=0
ffffffffd9223088  00 03 01 00 00 00 00 00 00 00 00 00 00 00 00 00
kpatch byte[1]=0x03
kdata_probe OK
```

### Cross-checks

- **SDK 12.x table matches live memory** [verified-on-console]:
  `allproc − kdata_base = 0x2885E00` and
  `ktext_base − kdata_base = −0xD50000` — both equal the SDK
  `crt/kernel.c` FW 12.x entries.
- **ps5debug-NG kpatch target is `.data`** [verified-on-console]:
  `kdata+0xD83088 = 0xffffffffd9223088 = security_flags (0xffffffffd9223064) + 0x24`
  — the FW 12.x kpatch target lies inside the security-flags area, deep
  in `.data`, as claimed in `02-xom-npt.md`.
- **Jailbreak data-flag state** [verified-on-console]: kpatch byte[1] =
  `0x03` — bits 0b11 set; matches ps5debug-NG's "already set by
  jailbreak" branch. The probe did not write it.
- **allproc page plausibility** [inference]: the page contains kernel
  heap pointers and pointers into the kernel image range — consistent
  with the `proclist` head region. No semantics were assumed; the full
  dump + structural derivation (route step 1 remainder) will verify.

### Recovery state

Probe is read-only; no kernel memory written; no restore needed;
console untouched.

## 2026-10-08 — kdata_dump sequential read: KERNEL PANIC (negative result)

- **Payload**: `engineering/payloads/kdata_dump/kdata_dump.elf`
  (sha256 `91e4a0756aea89fc8f83924f257e8ec8d51c1963f77f890203a185577ed5b7f6`,
  file-mode build), sent via elfldr 9021, FW 12.02.
- **Expected**: sequential `kernel_copyout` of 134 MiB from `kdata_base`
  in 4 KiB pages, with unmapped pages failing gracefully and being
  counted as zero-filled holes.
- **Actual**: dump progressed normally (holes=0 for the first ~28+ MiB
  observed; 1 MiB writes to `/data/homebrew/kdata_dump.bin` healthy),
  then the console suffered a **kernel panic and powered off** mid-run.
  No title was running; the payload never wrote kernel memory; the
  partial `/data` file is harmless (next run opens `O_TRUNC`).
  Recovery: normal boot; the whole kstuff chain reloads at boot.
- **Finding** [verified-on-console, negative]: the kstuff loader-pipe
  `kernel_copyout` primitive is **not fault-tolerant on unmapped kernel
  addresses** — reading past the mapped extent of the data segment
  page-faults the kernel in the corrupted-pipe read path and panics,
  instead of returning an error. "Hole-tolerant" sequential dumping
  across unknown-mappedness memory is unsafe with this primitive.
- **Root cause of the attempt**: the design assumed graceful failure
  from prior field evidence — but that evidence (kdata_probe, Lapy,
  porting_tool) only ever exercised *mapped* pages. This experiment was
  exactly the crash-risk class `AGENTS.md` requires explicit owner
  approval and a recovery plan for; the recovery plan existed (reboot,
  nothing at risk) but the crash-risk itself was under-assessed.
- **Fix**: panic-safe dumping must gate every page through a guest
  page-table walk first (PML4 of the kernel pmap, PTEs read through the
  direct map — itself mapped memory) and only `kernel_copyout` pages
  whose PTE is present; everything else is a recorded hole. This also
  yields the exact mapped extent of the data segment.
- Also observed the same session: outbound `connect()` from the elfldr
  payload context is dead across the board (router, console-local,
  PC targets all ETIMEDOUT; `payloads/port_probe/`), while inbound
  listeners keep working — hence the /data + FTP-pull transport
  (`kdata_fetch.py`). Root cause of the outbound breakage still unknown;
  ps5log-based payload runs connected fine earlier the same morning.

## 2026-10-08 — port_probe: outbound connects dead from payload context

- **Payload**: `engineering/payloads/port_probe/port_probe.elf`,
  read-only, FW 12.02, elfldr 9021.
- **Observed** [verified-on-console]: blocking `sceNetConnect` from the
  elfldr payload context to **every** target timed out (errno 60): PC
  9300 (ps5logd, listening, had accepted console connections the same
  morning), PC 9301, router 53/80, console-local 3232. PC-originated
  connections to the console (elfldr 9021, ftpsrv 2121) work fine.
- ufw on the PC is **inactive** (Status: inactive, 2026-10-08) —
  exonerated. PC Wi-Fi (wlp0s20f3) active; PC↔console ICMP works.
- **Status**: unresolved; suspected console-side sceNet/outbound state
  degradation after the morning game session. The /data + FTP transport
  bypasses it (inbound only).

## 2026-10-08 — vm_map gating: static image has no vm_map entries (negative result, safe abort)

- **Payload**: `kdata_dump.elf` (vm_map-gated build, sha256
  `5592fda04b5d7163693ed9241ae85d2ae5d96c08d89c7a96522c826d54480a9c`),
  read-only, FW 12.02, elfldr 9021.
- **Design**: walk proc 0's vm_map RB-tree (ps5-payload-sdk
  `kernel_get_vmem_entry` layout) and dump only the contiguous mapped run
  from `kdata_base`.
- **Observed** [verified-on-console]: `vm_map intervals=0` — no vm_map
  entry intersects the window; clean abort, no panic (the gate worked).
- **Finding** [inference + FreeBSD semantics]: the static kernel image
  (text/rodata/data/bss) is mapped by `pmap_bootstrap` before any vm_map
  exists — vm_map entries only describe dynamic kmem allocations, so
  vm_map gating is the wrong oracle for the image. (Corroborated by
  `vmspace+0x1d0` on 12.x reading as the vm_map RB root — a
  ps5-linux-loader-style pmap-pointer assumption at that slot returns a
  user VA at `+0x20`, failing validation safely.)
- Follow-up: gate on the page tables instead (see next entry).

## 2026-10-08 — PTE-gated 64 MiB kernel-data dump: SUCCESS + derivations

- **Payload**: `engineering/payloads/kdata_dump/kdata_dump.elf` (PTE-gated
  build, sha256
  `613cbdad48379ac739d5ed06e0f79ec73dbc5f333317fd9bc863bd07a44253ef` at
  134 MiB cap; the successful 64 MiB run used the same source with
  `KDATA_DUMP_SIZE` capped), read-only, FW 12.02, elfldr 9021.
- **pmap discovery** [verified-on-console] — port of ps5debug-NG
  `proc_ptwalk.c` `ptw_discover` into the payload: scan
  `vmspace[0x100..0x400)` for a `{pm_pml4, cr3}` pair, arithmetic
  validation, then a round-trip through the payload's own known global
  (`g_gt`) before any use. Found at **`vmspace+0x308`** on FW 12.02.
- **Finding** [verified-on-console]: the direct-map base on this console
  is **`dmap = 0xffffa39900000000`** — NOT the FreeBSD 11 constant
  `0xffff900000000000` (a constant-based v3 build failed validation
  safely on exactly this). The pair's `cr3` differs per elfldr payload
  run (each payload is a fresh process with its own pmap).
- **Dump** [verified-on-console]: 64 MiB window from `kdata_base`, zero
  holes, every page PTE-present (the full image data segment through
  `rootvnode+0x30D7510` with margin). File fetched over ftpsrv 2121
  (`kdata_fetch.py`), manifest:
  `sha256 197d0e04d1e9cab0c22358ecbb688fdde9170071ac7c89f2cc63b522fe3a1c41`,
  67,108,864 bytes, 3.7 s transfer.
- **Derivations** [verified-on-console] — sleirsgoevy porting_tool
  method, run by `kdata_derive.py` over the dump (all offsets
  kdata-relative, FW 12.02):
  - `idt = 0x2e88300` (independent derivation)
  - `gdt_array = 0x2e895e0` (independent derivation)
  - `tss_array = 0x2e8afe0` (first TSS VA `0xffffffffd9ebafe0`)
  - `kernel_pmap_store = 0x2e1cfb8` (independent derivation)
  - `allproc` SDK value `0x2885e00` semantically plausible (nonzero
    kernel heap pointer at the offset)
  - `security_flags+0x24` (ps5debug-NG FW 12.x kpatch target) byte[1] =
    `0x03` — bits 0b11, jailbreak applied state, read from the dump
- **Open**: `rootvnode` independent cross-derivation FAILED — the method
  needs kernel-heap namecache strings ('mini-syscore.elf', 'system', ...)
  that live beyond the 64 MiB image window. The SDK value `0x30D7510`
  remains `[verified-in-tree]` only.

## 2026-10-08 — 134 MiB gated run: console down again mid-dump (second boundary event)

- **Payload**: same PTE-gated build at the 134 MiB cap (sha256
  `613cbdad48379ac739d5ed06e0f79ec73dbc5f333317fd9bc863bd07a44253ef`),
  FW 12.02, elfldr 9021.
- **Observed**: `ptw discover OK` printed, then the elfldr echo went
  silent and the console became unreachable (no ping, no listeners). No
  FAIL line — the payload died mid-dump. Console on-screen state was not
  observed (panic vs rest mode unconfirmed at record time).
- **Boundary refinement** [inference, strong]: the 64 MiB window is
  proven safe end-to-end, so the fatal page lies in **(64, 134] MiB** of
  the window (progress-filter analysis narrows to (64, 100] MiB). The
  PTE gate was active and reads were filtered to present AND
  cacheable (PCD/PWT clear) pages — so the fatality is NOT the unmapped
  read class from the first panic. Candidate mechanisms: GPU/GARLIC
  memory mapped into kernel KVA (present+cacheable-looking PTE, but
  a corrupted-pipe kernel read of it faults), or an NPT-restricted
  region whose guest read fault is fatal rather than graceful.
- **Constraint for future dumps** [inference]: any read primitive in our
  stack (SDK `kernel_copyout`, ps5debug-NG `kernel_copyout_fast` — same
  loader-pipe mechanism) presumably hits the same fatal page. Probing
  the (64, 134] MiB region costs one console reboot per attempt;
  requires a deliberate session. The 64 MiB cap covers every SDK 12.x
  symbol we currently use.
- **Recovery state**: console off/unreachable; normal boot restores the
  chain (proven after the first panic event). The 64 MiB dump + derived
  offsets are already safe on the PC (previous entry).
