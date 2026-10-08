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
- **RESOLVED — measurement bug, not an outage** [verified-on-console,
  same day]: every probe (BSD and sceNet variants) filled `sin_addr`
  with `(a<<24)|(b<<16)|(c<<8)|d` — which packs the octets into the u32
  **big-endian**, reversing the address in the little-endian `s_addr`
  field (192.168.0.187 was dialed as 187.168.0.192). The field-proven
  `hello_log` payload (byte-wise fill, `ps5log__fill_ipv4`) connected
  fine all along; a bisect payload (`payloads/port_probe/hello_probe.c`)
  that ran a verbatim copy of `ps5log__open_channel` next to the
  hand-written connect made the differing sockaddr bytes visible.
  With byte-wise `sin_addr` filling, all four targets connect: PC
  ps5logd 9300, router 53, console-local klog 3232, PC kdata receiver
  9301 — **payload-context outbound networking over POSIX sockets works
  normally**. sceNet* from the payload context was never actually tested
  with a correct address (all sceNet attempts had the same bug);
  `ps5log.h` uses POSIX defaults for payloads by design regardless.
- **Lessons recorded**: (1) fill `sockaddr_in.sin_addr` byte-wise
  (network order in memory), never by packing octots into a u32;
  (2) before concluding a console-side outage, validate the measurement
  path against a field-proven instrument (`hello_log` did this and the
  initial interpretation still took hours — the alternation of verbatim
  vs hand-written code in one process was the decisive instrument).

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

## 2026-10-08 — gpa_map blind sweep: console WEDGED (third down event — experiment design flaw)

- **Payload**: `engineering/payloads/gpa_map/gpa_map.elf` (v2, slots
  0..504), FW 12.02, elfldr 9021. Phase B experiment #1.
- **Design**: alias-probe the first page of every 2 MiB region from GPA 0
  upward, classifying readable / `SEGV_ACCERR` / `SEGV_MAPERR`.
- **Observed**: `ptw discover OK`, arena setup OK, then the payload went
  silent and the console became fully unreachable (ping 100% loss, no
  listeners) — no fault, no crash: a **wedge**, consistent with a hung
  uncached load on a device-MMIO region (bus stall), not a kernel panic.
- **Root cause — my error** [inference, strong]: raw guest-physical space
  includes **MMIO holes** (device registers). The alias reader makes
  NPT-denied pages fault recoverably, but a read of actual device MMIO
  can **stall the CPU/bus indefinitely** — the "all faults recoverable"
  model from kernel-VA probing does not transfer to blind GPA sweeps.
  Classic mistake: probing physical space bottom-up walks straight into
  low MMIO.
- **Recovery**: hard power cycle. No data at risk; nothing else running.
- **v2 design (zero-console-risk first)**: before probing anything, mine
  the kernel's own RAM map (`phys_avail`/boot-provided region list) from
  our **existing** kdata dump — the HV/PSP carve-outs appear as *gaps in
  the kernel's RAM list*, answering the "where are the hidden regions"
  question host-side with no console run at all. Only boundary pages of
  those gaps (RAM-adjacent, provably not MMIO) would ever be probed, and
  only if the host-side map leaves questions open. Lesson recorded:
  **never blind-probe GPA space; derive the RAM map first.**

## 2026-10-08 — kalias_sweep: alias engine shipped; (64, 134] MiB mystery RESOLVED; rootvnode CLOSED

- **Payload**: `engineering/payloads/kalias_sweep/kalias_sweep.elf`
  (sha256 `1ff357b00f248d16762a669e01d042327d2a2233542328cc93d39c827fd9769a`),
  read-only, FW 12.02, elfldr 9021. Route step 2.
- **Technique** [verified-on-console]: PTE-aliasing reader ported from
  ps5debug-NG `scan_alias.c` — mmap an untouched arena; per 2 MiB span
  touch only page 511 (allocates the PT, slots 0..510 stay not-present
  and TLB-clean); resolve target phys via page-table walks (pipe reads
  of PT RAM only); pipe-write `phys|P|RW|USER` into not-present slots;
  read as normal userland memory with SIGSEGV/SIGBUS caught per page;
  restore the original PT page. Self-verify before sweeping: alias read
  of `kdata+0` == pipe read.
- **Result** [verified-on-console]: full 134 MiB window swept flat —
  `read_ok=21366, absent=12938, ucskipped=0, faulted=0` (mapped extent
  ≈ 83 MiB this boot; manifest sha256
  `222bed173183ac5981557840816ca2efa4c7d8b95fde780a475533b18928cdee`).
  **Zero faults, zero uncacheable leaves**: every page in the (64, 134]
  MiB region that is fatal to the corrupted-pipe kernel read reads fine
  as userland memory through the alias.
- **Resolution of the second boundary finding** [inference, strong]:
  the pipe fatality is **kernel-context-specific, not a property of the
  pages** (present, cacheable PTEs, readable in user context). Combined
  with `ucskipped=0`, the earlier GPU/NPT-page theories are weakened;
  the mechanism lives in the corrupted-pipe read path itself. The
  alias reader is the correct tool for dynamic/unknown kernel memory.
- **Cross-boot offset reproduction** [verified-on-console]: IDT
  `0x2e88300`, GDT `0x2e895e0`, TSS `0x2e8afe0`,
  kernel_pmap_store `0x2e1cfb8` — identical kdata-relative values on
  two different KASLR boots (earlier PTE-gated dump vs this alias
  sweep), and the SDK-table checks (allproc nonzero pointer,
  security_flags byte[1]=0x03) pass on both. kdata-relative offsets are
  boot-stable on this FW.
- **rootvnode CLOSED** [verified-on-console]: the alias dump's qword at
  SDK offset `0x30D7510` is `0xffff89a103356760`, and a live
  `kernel_get_root_vnode()` read on the same boot returns exactly
  `0xffff89a103356760` — independent-path agreement. The porting_tool
  namecache-string derivation does not apply on 12.02 (the root-name
  strings are not within the swept window; the kernel heap holding them
  lives elsewhere in KVA — future work: kernel-half page-table
  enumeration).
- **New per-boot facts** [verified-on-console]: pmap pair again at
  `vmspace+0x308`; `dmap=0xffff89a100000000` this boot vs
  `0xffffa39900000000` on the previous boot — **dmap is randomized per
  boot**; the kernel KASLR slide range is wide (kdata seen at
  `0xffffffffd84a0000`, `0xffffffffd7030000`, `0xffffffff89210000`
  across three boots).
- **Bugs found and fixed en route** (lessons): the ported walkers must
  mask `table = entry & PHYS_MASK` (a raw PTE value trips the
  phys-bound check); a span maps at most 511 target pages (slot 511 is
  the touch page), so the target cursor must advance by pages dumped,
  not by SPAN — otherwise the flat file drifts 4 KiB per span (observed
  as a 0x17000 symbol shift, diagnosed from the cross-boot offset
  mismatch); read the round-trip global BEFORE walking it (untouched
  .data pages have no PTE).

## 2026-10-08 (late) — host-side dump mining: SoC physical band table + aperture table

Zero-console-risk analysis of the existing 134 MiB alias dump
(`payloads/gpa_map/phys_avail_hunt.py` + direct decoding). Findings
[verified-on-dump, host-side]:

1. **SoC physical band table @ kdata+0x36c410** (boot .data): 15
   boundary constants decoding as consecutive bands covering the whole
   0..1.56 TiB physical address space — 0 | 4G | 16G | 36G | 64G |
   100G | 144G | 196G | 256G | 400G | 484G | 576G | 784G | 1T |
   1.25T | 1.56T boundaries. Known anchors land in-band: this boot's
   `cr3 0xd2e0000` in 0..4G; the payload `.data` phys (`g_gt`,
   0x43c22c000 = 17.2 GiB) in the 16..36G band — resolving the earlier
   ">16 GiB?!" observation: **RAM spans multiple bands; guest physical
   space is multi-window, not a flat 16 GiB.**
2. **4-GiB-strided aperture table @ kdata+0xc880f0**: monotonic
   0x1b0/0x2b0/0x3b0/.../0xa00 × 0x100000000 — GPUVM-aperture-class
   layout constants (~4 GiB each).
3. **Propagated 16 GiB descriptors** (0..4G + 4..16G pair) at five
   independent dump locations — a widely-copied machine-layout
   structure.
4. **False-positive lesson**: an adjacent u32-pair table decodes as a
   smooth geometric curve (~0.866 ratio/step, 31 entries) — a
   power-management-class LUT, not memory accounting. Structure alone
   can mislead; arithmetic validation (sums, ratios) is mandatory.
5. True `phys_avail` (RAM availability with carve-outs) not yet
   definitively identified; the 12.3-GiB-coverage candidate family
   near kdata+0xbff178 is the next discriminator target, as is
   locating `vm_page_array`.

Implication for the (parked) GPA sweep: any physical probing must be
band-aware and derived from in-band anchors — never blind from 0.
