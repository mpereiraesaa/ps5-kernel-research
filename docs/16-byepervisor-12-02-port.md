# The Byepervisor-Reborn port plan for 12.02

**Status: ACTIVE (implementation phase)** — the route's public reference
implementation is in hand; this doc maps it onto our 12.02 console and
holdings. Supersedes the r0gdb-stepping dependency for the launch chain
(the freeze saga is retired from the critical path).

Reference material (public, cloned read-only in the lab third-party area —
reference only, never run as-is on our console):

- `PS5Dev/Byepervisor-Reborn` — the working payload (13.60/13.20/13.00)
- `soniciso1/ps5-hv-writeups` — the mechanism writeup (the S3-resume
  `khv_startup_mp` AP-launch bug)

## The reference mechanism, as read from their source [public-consensus]

The full chain from a compromised kernel (their `main.c`/`khook.c`):

1. **Pre-rest, from userland with kernel R/W** (our pipe/kwrite20
   primitives cover all of this):
   - pin to the hook core, stage the AP payload into a kernel data
     cave, clear NX on the carrier page (`0x3FFFF000`) in the guest
     pmap, clear xotext + set RW on kernel `.text` pages in the guest
     pmap (takes effect the moment NP is off)
2. **The khook arm** (their `kh_install` + `kh_trigger`):
   - saves the IDT **#DB gate (vector 1)** + the chosen TSS **IST slot**;
     validates both (gate present, handler in kernel text, TSS RSP0
     kernel-shaped) — the same IDT/TSS patching class as our r0gdb,
     with the validation lessons we learned the hard way
   - builds three chains in the scratch cave: the **arm chain** (calls
     the kernel's debug-register restore path — their
     `KERNEL_GADGET_DBREG_RESUME` (the `resumectx` tail that loads
     DR7!) with `DR7 = BP0-execute-enable on the hook target`, then
     iretq back to userland), the **dispatch stub** (an IST pivot), and
     the **big chain** (saves the faulted context's rsi/rdi/rdx, runs
     the handler ROP, then the resume tail: writes `resume_rip` into
     the fault frame, **one-shot disarms DR7**, sets the chosen resume
     registers, then iretq through the original fault frame)
   - arms it **from userland**: a self-induced #DB (TF + a nop) → their
     patched gate → the arm chain → DR7 now armed on the hook target
3. **The wait**: the kernel trips the #DB itself when it executes the
   hook target (their 13.60: `HV_MP_STARTUP_CALL`, the kernel's own
   startup_mp call site in the resume path) → the big chain runs at
   CPL0 on the IST — **no session, no stepping, no gdb protocol** (the
   entire r0gdb freeze class does not exist here) — it replaces the
   fault frame's **rsi/rdx with our carrier-page RIP and CR3**, then
   resumes the kernel, which then makes the HCALL 0x0f **with our
   arguments**
4. **The AP payload at root 0** (`break_hv.c`, 36 lines): walks
   `pcpus[]`, converts HV-virtual to physical via the live heap offset
   global, and for each of the 16 VMCBs **clears bit 0 of
   `NESTED_CTRL` (+0x90) — disabling nested paging — and zeroes
   `VMCB_CLEAN` (+0xC0) to force a reload on the next VMRUN**; writes
   the success cookie
5. **Post-resume**: the guest now runs on the host page tables; with
   the pre-rest guest-pmap edits, kernel `.text` is readable and
   writable immediately (their demo dumps and edits it)

Key deltas from our earlier design: **NP-disable instead of
NESTED_CR3 redirect** (simpler, stronger — the whole guest runs with
the host view), and the **fault-frame register replacement** (the
kernel itself makes the hypercall with our arguments — no ROP call of
the hypercall needed).

## Field mapping: their 13.60 table vs our 12.02 holdings

Their offsets are ktext-relative; ours are kdata-relative — the port
anchors both per boot (we derive both bases).

| Their field | Their 13.60 | Our 12.02 status |
|---|---|---|
| `PMAP_STORE` | 0x3B48FF8 | ✓ in `offsets/12_02.h` (`kernel_pmap_store`) |
| `IDT_ARRAY` | 0x3BB4300 | ✓ (`idt`, delta +0x2E88300) |
| `COMMON_TSS` | 0x3BB6FE0 | ✓ (`tss_array`, +0x2E8AFE0) |
| `SYS_GETUID` | 0x2a8d60 | ✓ via our sysent anchors (746 sy_call entries) |
| `DMPML4I/DMPDPI/PML4PML4I` | pmap self-refs | ✓ functionally — our alias engine resolves PML4/PDP/PD/PT live |
| `DATA_CAVE` | 0x2D39000 | ✓ no static offset needed — `kh_find_cave` zero-scans with our kread |
| `HV_MP_STARTUP_CALL` | 0xC16EE0 | **not needed by our trigger** (below) |
| `ACPI_SLEEP_MACHDEP_HOOK` | 0x3913B0 | not needed (our anchor approaches to it were debunked on 12.02) |
| `MP_STARTUP_INIT_VECTOR` | 0x269FB8 | only needed for the benign-resume variant |
| `PRINTF` | 0x4ADD60 | test-only; drop or derive via sysent |
| `HV_SYM_HEAP_BASE` / `HV_SYM_PCPUS` | HV-internal | **the real port work**: derive dynamically from root 0 (the writeup's own verdict: static artifacts do not port) |

## Gadget mapping (their chain needs vs our `offsets/12_02.h`)

Their gadget set is not sacred — the **chain semantics** are; the port
rewrites chains around our verified gadgets where the exact semantic
match is missing.

| Their gadget | Semantics | Our 12.02 coverage |
|---|---|---|
| `DBREG_RESUME` | resumectx tail (loads DR0-7) | ✓ **`cpu_switch`** — our table's "function whose tail restores DR0/1/2/3/6/7" |
| `REP_MOVSB` | rep movsb; ret | ✓ close — `rep_movsb_pop_rbp_ret` (adapts with a frame qword) |
| `RET_TRAMP` | ret | ✓ `nop_ret` |
| `IRETQ` | iretq | ✓ `doreti_iret` / `pop_all_iret` family |
| `store_rax_rdi`-class stores | mov [rX], rY; ret | partial — `store_rax_rdi` ✓; other reg-pairs need derivation or chain rewrite |
| `pop rXX; ret` ×7 | pop reg; ret | partial — `pop_all_iret` pops all then irets; individual pops need derivation or chain rewrite |
| `PIVOT_ADD_RSP28_RET` | add rsp,0x28; ret | derivation needed (our gate pivots are iret-shaped) |
| `OR_RCX_EAX`, `SET_DR7`, `MOV_RAX_RSI/RDI`, `CLD` | assorted | derivation needed (small) |

Their constants worth recording: `KH_DR7_BP0_EXEC = 0x403`,
`KH_USER_CS 0x43 / SS 0x3b`, `KH_RFLAGS_USER 0x202`,
`KH_RC_DR7 = 0xa0` (the resumectx struct's DR7 slot — our 12.02
`cpu_switch` struct layout needs the same derivation from our dump).

## Our 12.02 trigger: the FACS self-corruption → #GP

Their trigger needs a kernel-**text** target address (they have the
scene's decrypted 13.xx kernels; we do not — reading kernel text is
our goal, not our starting point). Our dump-verified alternative
(docs/10, 2026-10-13): corrupt the `AcpiGbl_FACS` pointer in kernel
data (`kdata+0x2cb4c80`) so the resume path's dereference faults —
**#GP fires at the dereference site, wherever that is — no text
address knowledge needed**. The khook machinery generalizes: their
`khook.c` hardcodes vector 1 (#DB); ours patches the **#GP gate
(vector 13)** + IST instead, with the same save/validate/restore
lifecycle. The chain runs on the #GP instead of the #DB — identical
otherwise.

#### Correction (owner review, 2026-10-13): the engine is NOT proven

The phase-1 write-up below over-claimed: it called the
frames/xchg/int9 machinery "PROVEN LIVE on 12.02". The honest record:
**0 of 4 ring-0 attempts survived** (2026-10-09 + the three on
2026-10-12) — every session ended in a panic or hang. What Oct 9
actually established was *transient* behavior only: the entry did
not instantly kill the machine, and two single-instruction steps
returned sane values (EFER, CR0) — inside a session that then died.
No session completed, no restore ran, no exit verified, no machine
survived, and the freeze cause was never identified. The engine is
**unvalidated as a foundation**; the port's validation ladder must
start from zero assumptions about it.

**Footprint comparison (a concrete candidate for the deaths).** Our
`r0gdb_setup` patches 3 IDT gates (vectors 1/9/179) + 3 TSS IST slots
(IST3/4/6) on **all 16 CPUs** — 48 IST writes — and leaves them
patched for the entire session (indefinite under the park).
Byepervisor's khook patches **1 gate + 1 IST slot on 1 CPU** for a
one-shot, milliseconds-scale trigger. Redirecting three IST indexes
machine-wide reroutes *any* other gate using those indexes (the
NMI/#MC/#DF class) into one shared 2048-byte buffer for the whole
session — a plausible mechanism for the unexplained ~100-250ms
deaths [inference]. The port follows their minimal footprint
regardless: one gate, one IST, one core, milliseconds.

The port's execution model does not inherit the r0gdb failure modes
by construction: it is sessionless (no gdbstub packet loop — where
every freeze landed), one-shot (no per-step round-trips), passive
(the kernel trips the trigger), and brief (the chain runs in
milliseconds, then restores). But the shared machinery class (an
IDT gate patch + IST + frames at CPL0) remains unvalidated beyond
transient single steps — the first live port test must therefore be
the minimal one-shot chain in the port's own execution model (the
KHOOK_TEST-pattern: a safe trigger + a tiny chain + a verified
return + machine-alive), not an assumption carried over from Oct 9.

## Phase 1 results (2026-10-13): the engine decision

**The owner's cross-FW diff idea, tested against our own tables.** We
are not limited to their three headers: our kstuff tree carries the
same field set for **all 65 firmwares** (1_00 … 13_60), so the motion
model was built from our own tables via inter-symbol distances
(anchor-independent). Findings [verified-on-tables]:

- the **12.xx family is nearly frozen** (12.00→12.70: most distances
  identical; movers shift 0x10–0x60; `rdmsr_start`/`pop_all_iret`
  moved at 12.20 and *reverted* at 13.00)
- **13.00 is a major reorganization**: whole regions moved ~0x3a6a0
  (`rep_movsb`, `copyin/copyout`, `push_pop_all_iret`, the syscall
  path), and `store_rax_rdi` jumped regions entirely
  (−0xAA3EEE → +0x11a4e)
- therefore **delta-transfer from their 13.xx headers to 12.02
  crosses the reorganization and is low-confidence** — the
  approximation idea works within a family, and their headers are in
  the wrong one

**Candidate engine substitution.** The pop-gadget ROP chains are
Byepervisor's implementation, not a requirement by themselves. The
kstuff lineage has a different candidate execution engine:
`run_in_kernel` (`r0run.asm`, byte-identical in the upstream fork).
[verified-on-console, partial] The entry and individual reads have
produced transient observations, but the full call/return path is not
validated on 12.02; rung 4 froze during a minimal IDT/IST hold.

- [verified-in-tree] `r0run.asm` exchanges the saved register values
  through the staged frame and uses the iret frame to set RIP/RSP/RFLAGS
  and CS; this is a candidate substitute for a collection of pop gadgets,
  not proof that the overall entry/return path works
- [verified-in-tree] the kernel frame is staged via `copyin` into
  `kframe`; it is not set by the pipe primitive described above
- [verified-on-console, partial] CPL0 entry via the patched vector-9
  gate (`int 9`, DPL3, IST3) —
  the same gate/frame machinery `r0gdb_setup` used. The 2026-10-09
  EFER/CR0 reads were transient; no session completed or restored and
  the machine did not survive the run (`docs/16` correction above).

For the fault-entry side (the FACS #GP trigger), extending the IDT-gate
+ IST pattern to **vector 13 (#GP)** is a design candidate, not an
established working path. The rung-4 freeze shows that a gate pivot
without the complete entry frames is fatal; the full framed #GP path
still needs an offline layout review and a separately approved,
survivable validation.

**Port architecture candidate**: Byepervisor's *structure* (the
FACS #GP trigger, the resume-window launch with the fault-frame
argument replacement, the NP-disable `break_hv`, the pre-rest pmap
edits) + a possible **kstuff engine substitution** (frames/xchg/int9
instead of their pop chains). The missing-gadget set is not established
as empty: the substitution depends on entry/return machinery that is
currently unvalidated, and the direct gadget addresses are audited
below.

Remaining true unknowns: HV-side `pcpus`/heap discovery (dynamic, from
root 0), FACS-trigger integration, and the `break_hv` port. A separate
DR7-style test would additionally need the PCB-layout assumption and
12.02 `resumectx` tail address described in the offset audit; the FACS
trigger itself does not require those.

#### Rungs 1-2 results (2026-10-13): the IST-class death theories are falsified [verified-on-console]

The `idtdump` diagnostic (pure CPL3 `copyout` reads, the `facs_read`
class) measured the whole interrupt surface:

- **only 4 gates use IST3/4/6** — vectors 1, 9, 13, 179: *the same
  four vectors `r0gdb_setup` patches*. No other gate shares the
  patched IST indexes (NMI=v2→IST2, #DF=v8→IST1, v30→IST5,
  v3→IST7). The cross-vector IST-redirection theory is falsified;
  the 48-write maximalism was redundant, not hazardous
- **all four of v1/v9/v13/v179 share one handler** — kdata−0xA9C9DA
  = our own `add_rsp_iret` gadget (doreti_iret−7): Sony implements
  #DB/vector-9/#GP/vector-179 as a shared `add rsp,0xe8; iretq`
  **dismiss-stub** — those exceptions are deliberately neutered on
  12.02 (skip the frame and return; the faulting event is dismissed).
  That is why the kstuff lineage patches them, and it validates the
  port's #GP trigger design on a vector the kernel normally dismisses
- **vector 3 (int3) is the only naturally-DPL3 gate** (IST7, the
  dismiss-stub)
- **vector 179's IST6 slot is one shared direct-map address on all
  16 CPUs** (the dmap region, same region as the elfldr kpipe)
- **5-second IST-stack activity monitor** (before/after/diff over
  all 7 IST stacks × 16 CPUs): **all quiet except IST7 on cpus
  0/1/2/6 — vector 3 (int3) fires naturally and regularly** (small
  repeated-frame diffs at the stack top). Vectors 1/9/13/179/30/2/8
  show **no natural events at all**

Consequences:

- the **natural-event-on-a-patched-vector theory is falsified**
  (nothing fires v1/v9/v13/v179 naturally — the consistent
  ~100–250 ms session deaths had no natural interrupt source)
- the port must **never patch v3/ist7** (the only active vector);
  the port's v13 target is measured-quiet — favorable
- the remaining death-cause candidates: (a) the TSS
  read-modify-write race (`r0gdb_setup` rewrites the whole 0x68-byte
  TSS per CPU ×16, and the scheduler updates TSS rsp0 on every
  context switch — a switch inside a window writes back a stale
  rsp0, corrupting that CPU's ring-0 entry stack; weak fit for the
  *consistent* 100–250 ms timing), (b) something SDK-build-specific
  at ~100–250 ms (the pre-SDK Oct 9 build survived minutes), (c)
  unknown

#### Rung 3a result (2026-10-13): the TSS read-modify-write race is confirmed lethal [verified-on-console]

The identity-rewrite probe (identical bytes, zero semantic change, the
exact `r0gdb_setup` whole-0x68 copyout→copyin pattern ×16 CPUs) killed
the console at **~3400 sweeps / 0.9 s** — the output stopped mid-loop
at the last progress line (the designed death marker), ARP failed
after. A content-independent race: **the whole-TSS read-modify-write
pattern is lethal at ~thousands-of-sweeps exposure** — the scheduler
updates TSS rsp0 on context switches, and a switch inside a
copyout→copyin window writes back a stale rsp0, corrupting that
CPU's ring-0 entry stack. Empirical calibration: ~3×10⁻⁴ kill chance
per 16-CPU sweep.

**Two separate facts — do not conflate them:**

1. the racy pattern is a confirmed, avoidable hazard class —
   `r0gdb_setup` **and `r0gdb_cleanup` both use it** (the cleanup's
   16×(copyout + patch + copyin + verify) sweep, PR #67)
2. **the ~100–250 ms session deaths are NOT this race**: the
   sessions died 4/4 after *one* setup sweep; a 3×10⁻⁴/sweep race
   cannot explain 4/4 consistency. The session-death mystery
   remains open (SDK-build-specific candidate, or unknown)

Design rules (now hard rules for the port):

- **never** use the whole-TSS read-modify-write pattern —
  Byepervisor's `kh_install` already avoids it (the IST slot is
  written via a **single-qword `kwrite_q`**, no read-modify-write);
  the port follows that exactly
- any TSS field change = a field-specific single-qword write
- the port's remaining shared risk with the sessions (the gate
  patch + single-qword IST write + the frames + the trampoline
  entry) is bounded by the session-death mystery being *something
  else* — and the port's first live rung (the minimal one-shot chain)
  tests exactly that machinery in its own execution model

#### Rung 4 result (2026-10-13): the minimal patch froze the console [verified-on-console]

The minimal one-shot patch test — **one** IDT gate (v1, measured quiet
by rung 2) re-encoded to the kstuff pivot (`swapgs_add_rsp_iret`),
**one** TSS IST slot (cpu0's IST4 := cpu1's ist4) via **single-qword**
`copyin` writes (race-free — not the rung-3a class), verified
readback, then a 1 s hold — **froze the console during the hold**:
the UI entirely frozen (a full-system freeze, not a
panic-shutdown — owner observation), network dead, no recovery;
owner force-shutdown + reboot.

**Unified freeze signature**: every death so far (the four gdb
sessions, `tssrace`, `minpatch`) ends in the same full-freeze
terminal state (UI frozen / no HDMI, network dead, no self-recovery).

Analysis (by elimination — the payload printed through the verified
readback, the only live change during the hold was the patched gate
+ IST):

- **not** the rung-3a race (no read-modify-write anywhere)
- **not** a measured-rate natural v1 event (rung 2: ist4 quiet over
  5 s) — but a **rare** event (<0.2 Hz) remains possible, and the
  test design was **fatal-on-any-entry by construction**: the
  pivot-without-frames gate entered from a kernel-context #DB does
  `swapgs` at CPL0 — clobbering the kernel's GS/per-CPU base at the
  wrong context → per-CPU chaos → the full freeze [inference]
- the same pivot-gate class was live in the gdb sessions (their
  gates also targeted `swapgs_add_rsp_iret`) — a candidate for a
  shared death mechanism, though the sessions' 4/4-at-100–250 ms
  timing still lacks a measured event source (the rung-2
  contradiction stands for the sessions)

Disambiguation rungs (in order):

- **2b**: the 60 s IST-stack activity monitor — characterize the
  rare-event tail (ist4 especially); if ist4 shows ~0.1–1 Hz
  activity, the rare-event theory is confirmed and the port must be
  **survivable-on-entry**
- **4b**: the identity gate + a neutral IST buffer — machinery-only,
  survivable-by-construction
- **4c**: the pivot + the **full trampoline frames** + a neutral
  stack — the port's real design end-to-end, survivable-on-entry
  (Byepervisor's khook is exactly this class)

## Port phases

1. **Offsets + gadget mapping** (offline): retain the known 12.02 table,
   identify which ROP semantics can be removed by using the FACS trigger,
   and mark code gadgets unknown unless 12.02 executable bytes support
   an exact derivation. Sysent anchors alone do not derive interior
   gadget addresses. Any runtime check is a separate console experiment
   subject to the approval and recovery-plan rule.
2. **khook port**: their `khook.c` is nearly firmware-agnostic — port
   it, swap `kgadget/kdlsym/rawoff` for our table, extend the trigger
   to #GP + the FACS corruption
3. **`break_hv` 12.02**: dynamic `pcpus`/heap discovery from root 0
   (scan the HV data range for the 16-pointer array; validate against
   the NESTED_CTRL==9 pattern before any write)
4. **Pre-rest pmap edits**: our alias engine already walks PML4/PDP/
   PD/PT — clear NX on `0x3FFFF000`, xotext/RW on `.text`
5. **Validation ladder** (per phase, console-gated):
   - their `KHOOK_TEST` pattern is the gift: the getuid cookie oracle
     hooks a **syscall** we can trigger at will from CPL3 — the whole
     khook machinery validates with **no rest mode and no real resume
     window** — then
   - the FACS-corruption trigger test (rest cycle, owner-operated),
     then the armed run
6. **Payoffs**: kernel `.text` readable (dump → decompilation — the
   research goal) and writable (the FSGSBASE enable for prospero-win:
   patch the gating code / set CR4 via the now-trivial write)

## Offset audit after rung 4: what can be derived offline

The rung-4 freeze means the khook entry/pivot path is not validated; the
earlier “missing-gadget set becomes empty” statement above is withdrawn.
This audit separates data/layout offsets we can derive now from code
gadget addresses that remain unverified without 12.02 executable bytes.

### Derived 12.02 data and structure offsets

| Item | Derivation | Status |
|---|---|---|
| IDT base | `kdata + 0x2e88300`; vector 13 gate is `idt + 13*16` (`+0xd0`) | [verified-in-tree] `offsets/12_02.h:8`; `minchain2-build/main.c:385` uses the 16-byte gate stride. Live IDT inspection is in this doc's rung 2. |
| Common TSS base and stride | `kdata + 0x2e8afe0`; per-CPU stride `0x68` | [verified-in-tree] `offsets/12_02.h:10`; `minchain2-build/main.c:72,395` uses the same stride. |
| TSS IST slot | `TSS + 0x24 + 8*(IST−1)` | [public-consensus] FreeBSD 11 [`tss.h`](https://github.com/freebsd/freebsd-src/blob/releng/11.0/sys/amd64/include/tss.h#L46-L55) gives IST1 at `+0x24`; `minchain2-build/main.c:73,395` independently places IST3 at `+0x34`. [verified-on-console] rung 2 measured live IST slots and gate-to-IST use. |
| Scratch candidate | `kdata+0x2099000`, two zero-filled pages in `kernel-data-only-1202/kernel-data.bin` at `+0x2099000` | [inference] Byepervisor's 13.60 `DATA_CAVE` at text-relative `0x2d39000`, translated by the dump's `kdata−ktext=0xcc0000`, lands at the same data-relative coordinate. A zero page is only a candidate cave; it may be allocated or used at runtime. Falsifier: a live 12.02 read finds nonzero/owned data there, or a write/readback probe shows it is not safe scratch. The offline one-shot probe checks the full page is zero immediately before staging, but this alone does not establish ownership or runtime safety. |
| FACS global | `kdata + 0x2cb4c80` | [verified-on-dump] `docs/15-facs-global-resume-trigger.md` §2 |
| PCB saved fields | `RBP=0x20`, `RSP=0x28`, `RIP=0x38`, `DR7=0xa0` | [inference] FreeBSD 11 [`pcb.h`](https://github.com/freebsd/freebsd-src/blob/releng/11.0/sys/amd64/include/pcb.h#L51-L73) and [`cpu_switch.S`](https://github.com/freebsd/freebsd-src/blob/releng/11.0/sys/amd64/amd64/cpu_switch.S#L398-L487) provide this field order; Byepervisor independently defines the same [`KH_RC_*` offsets](https://github.com/PS5Dev/Byepervisor-Reborn/blob/main/include/khook.h#L12-L15). This assumes Sony's 12.02 `struct pcb` preserves that layout. Falsifier: 12.02 `resumectx` or generated `PCB_*` offsets differ. |

The PCB field offsets are useful only if the selected chain consumes a
`struct pcb` at that address. They do not identify the 12.02 address of
the `resumectx` DR-restore tail. That function/gadget address remains a
separate unknown. [inference] The passive FACS-trigger route does not
need the DR7 arm step, so `SET_DR7`, `DBREG_RESUME`, and the
saved-context DR7 slot can be removed from that route's required set.
This is falsified if the 12.02 resume trigger requires debug-register
arming before the FACS dereference can fault.

### Cross-dump code-gadget candidates

The new 13.60 pair improves the address audit, but it does not provide
12.02 instruction bytes. [verified-on-dump] In
`kernel-dump-1360-boot1791893784/kernel-text.bin`, the file size is
`0xcc0000` bytes; its IDT and TSS anchors are at data-file offsets
`0x2ef4300` and `0x2ef6fe0`. The earlier `0x2234300`/`0x2236fe0`
figures subtracted the text size twice and were not IDT/TSS records
(correction #18 in `docs/11`). Converting Byepervisor's text-relative
offsets to Kstuff's data-relative coordinates uses
`kdata−ktext = 0xcc0000`. For 12.02, the dump-derived coordinate
difference is `0xd50000`; the IDT bytes at
`kernel-data-only-1202/kernel-data.bin+0x2e88300` and the shared
exception-handler pointers support that base derivation. These
conversions were checked against the IDT/TSS locations and syscall
function pointers. [verified-on-dump] The 13.60 sysentvec declares
`0x2df` entries at `kernel-data.bin+0xddd8f8`; comparing those 735
`sy_call` entries at `+0x1b6e50` with the same indices in the 12.02
table at `+0x1af4d0` gives 735 text-pointer pairs. With dump-specific
text bases `0xffffffffd3b70000` (13.60) and
`0xffffffff884c0000` (12.02), 595 pairs have a 12.02-minus-13.60
text displacement of `+0xadd70`, and 140 have `+0xadd58`. The earlier
`+0x6a340`/`+0x6a328` figures used an incorrect base; they must not
be used for gadget projection.

This is a piecewise map, not one firmware-wide delta. The 13.60 Kstuff
anchors `cpu_switch`, `mov_rax_cr0`, `dr2gpr_start`, `gpr2dr_1_start`,
`gpr2dr_2_start`, and `mov_cr3_rax_mov_ds` all map to 12.02 with the
same displacement `+0x5a1a0`. In the 13.60 dump, Byepervisor's gadgets
sit at these local offsets from the anchors:

| Byepervisor gadget | 13.60 text offset | Local anchor relation | 12.02 candidate | Assessment |
|---|---:|---|---:|---|
| `PIVOT_ADD_RSP28_RET` | `0x25213e` | `cpu_switch - 0x22`; 13.60 dump bytes at `kernel-text.bin+0x25213e` decode as `add rsp,0x28; rep ret` | `0x2ac2de` | [inference] low-confidence adjacency candidate; the gadget is in the preceding code block, so its distance from `cpu_switch` may change |
| `DBREG_RESUME` | `0x2529d8` | `mov_cr3_rax_mov_ds + 0xe1`; 13.60 dump bytes at `kernel-text.bin+0x2529d8` decode as the DR-register restore tail beginning with `mov rax,[rdi+0x78]; mov dr0,rax` | `0x2acb78` | [inference] strong same-region candidate; 12.02 bytes must confirm the tail and entry contract |
| `IRETQ` | `0x257b3d` | exact match to Kstuff `doreti_iret` | `0x2b362d` | [verified-in-tree] already present in `offsets/12_02.h`; requires a compatible frame |

The first two are candidate addresses only. Their falsifier is a 12.02
text image showing different local instructions or routine layout.
Before relying on either in a chain, verify the complete sequence,
entry point, side effects, and stack consumption from 12.02 bytes. Do
not add these candidates to `offsets/12_02.h` as verified gadgets yet.

[verified-on-dump] The 13.60 data dump also contains exact pointers to
many Byepervisor gadgets, clustered around data offsets `0x2079040`
and `0x207ca00` beside frame-like values. The corresponding 12.02
data locations are zero or unrelated. [inference] The clustering and
cross-dump absence indicate runtime chain residue rather than matching
static kernel pointer tables; falsifier: a 13.60 static object definition
assigns those locations and has a homologous 12.02 object. These
pointers therefore do not identify the missing 12.02 gadget addresses.
A useful cross-dump
anchor must instead be the same identified kernel object in both dumps,
with its pointer target in the same local code region. [inference]
Even such an anchor yields an address candidate, not proof of the
12.02 instruction bytes; a 12.02 text image would falsify a wrong
candidate.

### Code gadgets still not derived

The following exact 12.02 instruction addresses remain unknown from the
checked-in evidence: individual `pop rax`,
`pop rcx`, `pop rdi`, `pop rsi`, `pop rdx`, `pop r8`, and `pop rsp` gadgets;
`mov [rcx],r8; ret`; `mov [rdi+8],rcx; ret`; `or [rcx],eax; ret`;
`mov dr7,rax; mov eax,r8d; ret`; `mov [rcx],rdx; ret`;
`mov [rcx],rax; xor eax,eax; ret`; `mov rax,rsi/rdi; ret`;
`cld; ret`; plain `rep movsb; ret`; and the `resumectx` DR-register
restore tail. The pivot and DR-register tail have the cross-dump
candidates above, but their 12.02 byte sequences are not verified.
`offsets/12_02.h` has entries such as
`store_rax_rdi`, `rep_movsb_pop_rbp_ret`, `doreti_iret`, `pop_all_iret`,
and `nop_ret`; byte-level semantics and frame compatibility still need
checking before treating one as a replacement for a Byepervisor gadget.

[inference] The data-only dump cannot independently prove interior
instruction bytes. The 13.60 donor text plus multiple local anchors can
produce bounded 12.02 address candidates in stable code regions, as
above, but cannot establish that Sony kept candidate bytes or
instruction boundaries identical. Sysent anchors identify function
pointers, not arbitrary interior bytes. Falsifier: an identified 12.02
text image or equivalent byte-level capture confirms or rejects the
candidate sequences and containing basic blocks.

The 13.00/13.20/13.60 gadget constants are not substitutes: the table
motion audit above found a major 13.00 reorganization, and the repo's
correction register forbids transferring offsets across that boundary
without a same-firmware anchor (`docs/11` item 17). This audit uses
several same-region Kstuff anchors for the DR-tail candidate and the
adjacency to `cpu_switch` for the lower-confidence pivot candidate; it
does not justify a global delta. The next offline step is to simplify
the 12.02 chain around existing entries and the FACS trigger, recording
each required semantic substitution explicitly. Any other missing code
gadget needs 12.02 byte-level evidence or an equally strong local-anchor
derivation.

The `run_in_kernel` register exchange in `r0run.asm:15-58` is an
interesting alternative to individual pop gadgets [verified-in-tree],
but it is not yet a validated khook replacement: [verified-on-console]
the rung-4 experiment ended in a full-console freeze. Treating that
engine as “proven” would repeat a claim already corrected above.

### 2026-10-13 — one-shot Byepervisor-style #DB/IST probe [verified-on-console, partial]

- **FW:** 12.02 (`0x12020000`), reported by the payload.
- **Build:** isolated `byepervisor_probe_1202.elf`, SHA-256
  `6de8f1865ddfa85efa8a9448735c16ff5ebff8aa4e26b8beeca1c39cc4f2e422`.
- **Expected:** preflight through `[P4]`, one #DB step through the
  low-confidence pivot and staged `iretq` frame, then `[P5]` return and
  `[P6]` restoration confirmation.
- **Actual:** elfldr returned `[P1] fw=12.02 cpu=15`; its response timed out
  after 20 seconds. No later probe line was captured, so there is no evidence
  that execution reached the #DB trigger or returned. Ping and the known
  ps5debug/klog ports also did not respond after the timeout. The exact stop
  point is unknown; this does not validate or falsify the pivot/frame path.
- **Recovery:** console network services were unreachable at capture time.
  The documented recovery is a hard power cycle; completion and post-boot
  state have not yet been confirmed.

### Follow-up: timestamped diagnostic build [verified-on-console, partial]

- **FW:** 12.02 (`0x12020000`), reported by the payload.
- **Kstuff state:** owner reported Kstuff was not running for this attempt.
- **Build:** timestamped diagnostic `byepervisor_probe_1202.elf`, SHA-256
  `3607756eaf63b1743a276325b116f99248b18274424b12b4d974923c9851901b`.
- **Expected:** `[P1]` through `[P3a]` and the pre-arm trace, then `[P4]`;
  on return, `[P5]` and `[P6]`.
- **Actual:** elfldr returned only `[P1] fw=12.02 cpu=15`; the response
  timed out after 30 seconds. No `[P2]`, `[P3a]`, pre-arm trace, or return
  marker was captured. Ping and ports 9021, 744, 755, 1010, and 3232 did not
  respond afterward. The exact stop point and whether frame staging began
  remain unknown. The repeated failure with Kstuff absent means Kstuff is
  not required to reproduce the observed stall; it does not identify the
  stall's cause.
- **Recovery:** network services were unreachable at capture time. Hard
  power-cycle recovery is pending confirmation.

### Read-only preflight isolation run

- **FW:** 12.02 (`0x12020000`), reported by the payload.
- **Build:** `byepervisor_probe_1202_readonly.elf`, SHA-256
  `377058ce88c230d60fd5eb920b822a1ccc8ff20bddf728263fda92c76f6cd56b`.
- **Expected:** flushed T00–T08 checkpoints, P1, both P2 lines, P3, and an
  explicit diagnostic exit before frame staging or kernel writes. Recovery
  plan in case the read-only preflight wedged the console: hard power cycle.
- **Actual:** elfldr returned T00–T08, P1, both P2 lines, P3, and
  `[DIAG] read-only preflight complete; exiting before frame staging`.
  Each displayed checkpoint was `+0 us` after microsecond truncation. The
  payload reported FW 12.02 and CPU 15; all four `kernel_copyout` calls and
  preflight checks returned successfully. No frame staging, IDT/TSS writes,
  or #DB trigger ran. A post-run ping to the console succeeded.
- **Recovery state:** payload exited normally; console remained pingable, so
  no hard power cycle was needed. Other console services were not checked.
- **Interpretation:** this run establishes that the preflight and P1/P2/P3
  output path completed without an immediate freeze in this run. It does not
  rule out a delayed effect under other conditions or establish that the later
  frame/gate path is safe.

### Frame staging isolation run

- **FW:** 12.02 (`0x12020000`), reported by the payload.
- **Build:** `byepervisor_probe_1202_frame_setup.elf`, SHA-256
  `26577c65caf2eb3c027d0591c77ce78c01a6e25822f917d570e063907dba1084`.
- **Expected:** run the validated preflight, construct the six-word frame,
  write it to the inferred scratch candidate, read it back, restore and verify
  the saved scratch bytes, then exit before any IST/IDT write or #DB trigger.
  Recovery plan for a wedge or failed restore: hard power cycle.
- **Actual:** elfldr returned through `[P3a]`, T10–T12, `[P3b]`, T15, and
  `[DIAG] frame setup complete; scratch restored; exiting before IST/IDT
  writes`. Frame readback matched, scratch restoration verified, and a
  post-run ping to the console succeeded. No IST/IDT writes or #DB trigger
  ran. Displayed checkpoint deltas were `+0 us` after microsecond truncation.
- **Recovery state:** payload exited normally; console remained pingable, so
  no hard power cycle was needed. Other console services were not checked.
- **Interpretation:** [verified-on-console] this run validates frame
  construction, staging, readback, and scratch restoration for this run. It
  moves the remaining freeze investigation to the later IST/IDT/#DB/return
  path, while not proving that path safe or ruling out timing differences
  between builds.

### Same-value IST/IDT write isolation run

- **FW:** 12.02 (`0x12020000`), reported by the payload.
- **Build:** `byepervisor_probe_1202_same_value_write.elf`, SHA-256
  `b37ff892e8b7dbd95e40b2b6cc64aa219958f5bf1852125f2041f599d4c8af49`.
- **Expected:** write the saved IST4 pointer and both #DB gate qwords back
  unchanged, read them back, rewrite the originals, verify the final values,
  then exit without frame staging or #DB trigger. Recovery plan for a freeze
  or failed verification: hard power cycle.
- **Actual:** elfldr returned `[W1]` through `[W3]`, verified same-value
  readback at T26, verified the final original values at T27, and printed
  `[DIAG] same-value IDT/IST writes verified; originals retained; exiting
  before frame or #DB trigger`. A post-run ping to the console succeeded.
  Checkpoints displayed about `+999 us` after microsecond conversion; treat
  this clock output as coarse timing, not an exact operation duration.
- **Recovery state:** payload exited normally; console remained pingable, so
  no hard power cycle was needed. Other console services were not checked.
- **Interpretation:** [verified-on-console] the current IST4 and #DB gate
  addresses accepted same-value writes and readback in this run. This does
  not test changed gate/IST values, #DB dispatch, the candidate pivot, or
  `iretq` execution.

### Changed IST/#DB-gate setup isolation run

- **FW:** 12.02 (`0x12020000`), reported by the payload.
- **Build:** `byepervisor_probe_1202_changed_gate.elf`, SHA-256
  `e5e7eeffd0277a03fe5c98959559654c8ddb87851981a4baff9794e10f152f98`.
- **Expected:** stage and verify the frame; set IST4 to the frame area and
  retarget the #DB gate to `ktext+0x2ac2de`; read back the changed values;
  immediately restore and verify the original gate, IST4, and scratch bytes;
  exit without intentionally triggering #DB. Recovery plan for a wedge or
  failed restoration: hard power cycle.
- **Actual:** elfldr returned through T12, `[G4]`, T16, and
  `[DIAG] changed gate/IST readback passed; originals and scratch restored;
  exiting without #DB trigger`. Since the code exits on a failed changed-value
  comparison or restoration, this confirms the changed values matched on
  readback and the original values matched after restoration. A post-run ping
  to the console succeeded. No intentional #DB trigger ran.
- **Recovery state:** payload exited normally; console remained pingable, so
  no hard power cycle was needed. Other console services were not checked.
- **Interpretation:** [verified-on-console] the changed IST4 and #DB gate
  setup, its readback, and restoration completed in this run. This does not
  test CPU exception delivery through the changed gate, the candidate pivot,
  or `iretq`. The prior full probe produced only `[P1]`, so its freeze
  cannot be assigned to any later operation or even shown to have reached
  the #DB trigger.

### Remaining live-path validation boundary

The successful runs above isolate setup operations; they did not execute
the following path. Each item remains [inference] until an observation
at that boundary distinguishes it from the preceding one:

1. **#DB delivery and IST4 selection.** A changed gate and IST4 slot were
   read back, but no intentional #DB was delivered while they were live.
   The CPU might fail before reaching the pivot. Falsifier: a captured
   exception entry with the expected gate target and IST4 stack.
2. **12.02 pivot semantics.** `ktext+0x2ac2de` is a cross-firmware
   adjacency candidate, not a byte-verified 12.02 gadget. Its actual
   instructions and stack consumption are unknown. Falsifier: 12.02 text
   bytes show another sequence, or an entry trace shows a different RSP.
3. **Exception-frame geometry and `iretq` return.** The six staged words
   matched on readback, but the CPU has not consumed them from the
   proposed RSP. The known `doreti_iret` address alone does not validate
   the selected frame or return to `probe_resumed`. Falsifier: a captured
   pre-`iretq` RSP/stack snapshot differs from the intended five-word
   user return frame, or a fault capture identifies the failing return.
4. **Post-return restoration.** Restoring the original gate, IST4, and
   scratch succeeded in the changed-value diagnostic without triggering
   #DB. It has not succeeded after an exception/`iretq` round trip.
   Falsifier: the return marker appears but the subsequent restore or
   final readback fails.

[verified-on-console] The two full-probe attempts emitted only `[P1]`.
Neither reported `[P4]`, the prepatch/trigger marker, nor `[P5]`/`[P6]`.
Their freezes therefore do not identify which, if any, of these four
boundaries was reached. A future trigger attempt is a new console-risky
experiment requiring owner approval and a recovery plan under `AGENTS.md`.

## What this supersedes

- the r0gdb-stepping launch chain (the freeze cause remains unknown;
  the route is retired from the critical path — the ladder remains
  for debugging)
- the NESTED_CR3-redirect design (NP-disable is simpler and stronger)
- the `acpi_sleep_machdep` anchor hunt (debunked; unnecessary)

## Evidence labels

- Their mechanism and code: [public-consensus] (reference, not run)
- Our 12.02 holdings (offsets table, sysent anchors, alias engine,
  pmap/pde knowledge, FACS trigger): [verified-on-dump] /
  [verified-on-console] as recorded in docs/07-10
- The port itself: pending — each phase lands with its own validation
