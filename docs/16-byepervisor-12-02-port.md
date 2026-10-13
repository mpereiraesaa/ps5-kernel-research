# The Byepervisor-Reborn port plan for 12.02

The faithful 11.60 two-transaction #DB chain, its 12.02 evidence gaps, and
failure-observation requirements are inventoried in `17`. The FACS #GP route
below is a separate trigger design with a different exception frame.

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
| `DATA_CAVE` | 0x2D39000 | candidate only — `kh_find_cave` zero-scans, but zero bytes do not establish ownership or cross-boot safety |
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
| `DBREG_RESUME` | starts with `mov dr0,rax`, then loads DR1–3/6/7 and restores/pivots context | candidate `ktext+0x2acb78` from a 13.60 local anchor; `cpu_switch` is only a containing-function anchor, and the 12.02 bytes/entry contract are unverified (`11` #23) |
| `REP_MOVSB` | rep movsb; ret | 12.02 table has `rep_movsb_pop_rbp_ret`; its extra pop requires a different frame, and bytes are unverified |
| `RET_TRAMP` | ret | `nop_ret` has a 12.02 table address; instruction bytes not yet read |
| `IRETQ` | iretq | `doreti_iret` / `pop_all_iret` have 12.02 table addresses; frame contract needs validation |
| `store_rax_rdi`-class stores | mov [rX], rY; ret | 12.02 table names `store_rax_rdi`; exact bytes and the other register pairs need validation or chain rewrite |
| `pop rXX; ret` ×7 | pop reg; ret | individual pops remain unknown; `pop_all_iret` has a different frame contract |
| `PIVOT_ADD_RSP28_RET` | add rsp,0x28; ret | low-confidence candidate `ktext+0x2ac2de` (`16`, cross-dump table); 12.02 bytes unknown and Kstuff's iret-shaped pivot is not equivalent |
| `OR_RCX_EAX`, `SET_DR7`, `MOV_RAX_RSI/RDI`, `CLD` | assorted | unresolved; one-shot omits `OR_RCX_EAX`, but the other 12.02 instruction addresses and contracts require evidence (`17`) |

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
address knowledge needed**. The khook machinery is a candidate pattern:
their `khook.c` hardcodes vector 1 (#DB), while this route would require
a **#GP gate (vector 13)** and a selected IST stack with a
save/validate/restore lifecycle. [public-consensus] The #GP entry frame
is not interchangeable with #DB's: #GP supplies an error code and #DB
does not (`11` #20). The chain's stack consumption and return path remain to be
derived and validated for the selected 12.02 gate setup.

[verified-on-console] The later read-only gate audit below found the
current vector-13 gate at IST0, so a #GP hook would have to encode a
new IST index in that gate and prepare the corresponding TSS slot.
[inference] The old dump's vector-13 IST3 entry was patch-state data;
a clean boot reproducing IST3 without a prior gate-changing payload
would falsify that explanation. No #GP frame or return behavior is
validated by the #DB-only setup probes.

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

#### Rungs 1-2 results (2026-10-13): a kstuff-era gate snapshot [verified-on-console]

The `idtdump` diagnostic (pure CPL3 `copyout` reads, the `facs_read`
class) measured the interrupt surface **at that time**. The owner has
since clarified that the 12.02 data dump was captured with kstuff
running. The dump and this earlier live snapshot must not be used as
evidence of unpatched Sony gate targets; see correction #19 in `11`
and the later read-only audit below.

- **four gates used IST3/4/6 in that snapshot** — vectors 1, 9, 13,
  179. This did not establish the unpatched layout or falsify an IST
  redirection hazard in a different gate state.
- **v1/v9/v13/v179 shared `ktext+0x2b3626` in that snapshot** — the
  `add_rsp_iret` address in `r0gdb/prosper0gdb/offsets/12_02.h:12-14`.
  [inference] This is consistent with kstuff/r0gdb-style gate patching,
  not proof that Sony routes those vectors to a dismiss stub. A clean
  boot gate audit that reproduces these four targets would falsify the
  patch-state explanation.
- **vector 3 was the only naturally-DPL3 gate observed**, with IST7.
- **vector 179's IST6 slot held one shared direct-map address across
  all 16 CPUs** in that snapshot.
- **5-second IST-stack activity monitor** (before/after/diff over
  all 7 IST stacks × 16 CPUs): **all quiet except IST7 on cpus
  0/1/2/6 — vector 3 (int3) fires naturally and regularly** (small
  repeated-frame diffs at the stack top). Vectors 1/9/13/179/30/2/8
  show **no natural events at all**

Consequences:

- no activity was detected on v1/v9/v13/v179 during that five-second
  window; this bounds only that observation, not rare events or the
  current gate state.
- v3/IST7 was active in that window, so using it as a scratch entry
  remains hazardous. The v13 quiet result is scoped to that snapshot.
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
| `DBREG_RESUME` | `0x2529d8` | `mov_cr3_rax_mov_ds + 0xe1`; 13.60 dump bytes at `kernel-text.bin+0x2529d8` begin with `mov dr0,rax`. The preceding `mov rax,[rdi+0x78]` is **outside** the gadget entry. The chain supplies DR0 in RAX. | `0x2acb78` | [inference] strong same-region candidate; 12.02 bytes must confirm the tail and entry contract |
| `IRETQ` | `0x257b3d` | exact match to Kstuff `doreti_iret` | `0x2b362d` | [verified-in-tree] address present in `offsets/12_02.h:12`; 12.02 instruction bytes and frame compatibility remain unverified |

The first two are candidate addresses only. Their falsifier is a 12.02
text image showing different local instructions or routine layout.
Before relying on either in a chain, verify the complete sequence,
entry point, side effects, and stack consumption from 12.02 bytes. Do
not add these candidates to `offsets/12_02.h` as verified gadgets yet.

#### Kstuff return-stub disassembly in the 13.60 donor

[verified-on-dump] Converting Kstuff's 13.60 `doreti_iret` coordinate
(`r0gdb/prosper0gdb/offsets/13_60.h:12-14`) through the dump's
`kdata−ktext=0xcc0000` places it at `kernel-text.bin+0x257b3d`.
Disassembly from `+0x257b33` gives `swapgs` at `+0x257b33`,
`add rsp,0xe8` at `+0x257b36`, and `iretq` at `+0x257b3d`.
The latter also matches Byepervisor's 13.60 `IRETQ` offset. The
`-10` and `-7` Kstuff relations therefore land on actual instruction
boundaries in this **13.60** image.

[verified-in-tree] The 12.02 Kstuff header has the same `-10` and `-7`
relations around its `doreti_iret` address
(`r0gdb/prosper0gdb/offsets/12_02.h:12-14`). Converted through
`kdata−ktext=0xd50000`, they yield `ktext+0x2b3623`,
`ktext+0x2b3626`, and `ktext+0x2b362d`, respectively. [inference]
This is strong cross-firmware support for the **intended** 12.02
`add rsp,0xe8; iretq` entry used by the probe, but it is not a byte
read of 12.02 kernel text. A 12.02 text disassembly showing a different
instruction sequence at those addresses would falsify the transfer.
The failed #DB probes therefore cannot yet distinguish a wrong 12.02
target from exception-frame or return-path failure.

#### Data-pointer cross-check

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

### #DB gate-state correction and read-only audit (2026-10-13)

- **FW:** 12.02 (`0x12020000`), reported by both payloads. The owner
  reports that kstuff was **not running** for these runs and confirms the
  earlier 12.02 dump **was taken with kstuff running**.
- **Guarded IST4 build:** `byepervisor_probe_1202_ist4_delivery.elf`,
  SHA-256 `2a4419d36ef39a004d76011719f857cc94b170db62445c4ba0463f99a284458f`.
  Expected: accept the previously observed `ktext+0x2b3626` #DB
  target, stage a frame, patch only the selected CPU's IST4, then
  report a captured hardware frame after one TF/NOP #DB. Actual:
  `[E0] original #DB target ... != expected stub ...`; the live target
  was `ktext+0x3188b0`. The guard returned **before scratch or IST4
  writes and before the #DB trigger**. The sender's missing expected
  success marker is explained by this deliberate early return.
- **Read-only audit build:** `byepervisor_probe_1202_readonly.elf`,
  SHA-256 `db197575f6cfa7e4b89623d37545855cc33c20633be08f4aa5228dcaef1044b6`.
  Expected: read preflight state and print the four gate entries, with
  no kernel write or exception trigger. Actual: it completed T00–T08,
  printed P1–P3 and the following gate records, then returned the
  explicit read-only completion marker:

  | Vector | IST | Target relative to live `ktext` |
  |---|---:|---:|
  | 1 (#DB) | 4 | `+0x3188b0` |
  | 9 | 0 | `+0x318b68` |
  | 13 (#GP) | 0 | `+0x318b88` |
  | 179 | 0 | `+0x3189e0` |

- **Recovery:** both payloads exited without a trigger or kernel
  write; the console remained reachable and no hard power cycle was
  required. The standing recovery plan for a freeze was a hard power
  cycle. Other console services were not checked.
- **Interpretation:** [verified-on-console] the earlier common
  `ktext+0x2b3626` target and IST3/4/6 map do **not** describe these
  four live gates. [inference] Kstuff patching explains the older
  common-target snapshot, given the owner's dump provenance and
  `r0gdb`'s `add_rsp_iret` offset. A clean boot showing the same
  common target without any prior patch would falsify that explanation.
  The read-only audit does not establish the instruction bytes or
  return contract at `ktext+0x3188b0`, and the guarded IST4 build
  provides **no evidence of #DB delivery or IST4 selection**. It must
  not be rerun by removing the target guard; any live trigger needs a
  separately reviewed frame and return path plus owner approval.

### Patched-gate IST4 delivery attempt (2026-10-13)

- **FW/build:** 12.02 (`0x12020000`),
  `byepervisor_probe_1202_patched_ist4_delivery.elf`, SHA-256
  `86fb2394cd4e541a4685d01b93b92dd8cb435acefa9fd2ec9320ea53668725ab`.
  The owner explicitly approved this changed-gate build and the hard
  power-cycle recovery plan after the earlier guarded build refused.
- **Expected:** require the audited live v1 target
  `ktext+0x3188b0`, single-CPU affinity, IST4, and zero scratch;
  stage a canary and five-word user return frame; point that CPU's
  IST4 at scratch; retarget the shared #DB gate's low qword to the
  kstuff `add_rsp_iret` offset `ktext+0x2b3626`; issue one TF/NOP
  #DB; restore and verify gate, IST4, and scratch; print E2 hardware
  frame and E3 `MATCH`. This design still depends on an unverified
  12.02 instruction/return contract at the kstuff stub. The shared
  gate also exposes other CPUs during the short patch window.
- **Actual:** preflight printed P1/P2/P3 and two E1 lines. E1 reported
  CPU 15 with a single-CPU affinity mask and stated the intended
  IST4 pointer, hardware-frame address, return-frame address, and
  one-qword gate swap. No E2 or E3 appeared. The sender timed out
  after 30 seconds; a subsequent three-ping check received no replies.
- **Recovery state:** console unreachable after the run; the owner
  performed the agreed hard power cycle and confirmed normal operation.
  A later two-ping check also succeeded.
- **Interpretation:** [verified-on-console] the checks and staging
  reached E1, followed by a freeze before the return marker.
  [inference] The failure lies somewhere after E1: IST4 write/readback,
  gate write/readback, #DB delivery, stub/`iretq` return, or early
  restoration. The lack of an E2 marker does **not** prove #DB reached
  the patched CPU or IST4 slot. Evidence of a hardware frame is still
  absent; the experiment does not validate step 1 of the boundary below.

### Exact-value IST4/#DB write isolation run (2026-10-13)

- **FW/build:** 12.02 (`0x12020000`),
  `byepervisor_probe_1202_patch_only_ist4_gate.elf`, SHA-256
  `8f61011a969f2928e8aad53a8b472448236865349b944797c560e3445b940ac0`.
  The owner explicitly approved this exact build and a hard
  power-cycle recovery plan after the frozen attempt.
- **Expected:** repeat the frozen build's preflight and frame staging,
  write/read back the same changed selected-CPU IST4 qword and
  shared #DB gate low qword targeting `ktext+0x2b3626`, restore and
  verify the original full gate, IST4, and scratch, then emit S2 and
  exit without a TF/#DB trigger.
- **Actual:** E1 reported CPU 15 and a single-CPU affinity mask. S2
  printed the changed IST4 pointer and gate low qword after successful
  readback, then `originals restored=YES; no #DB trigger`. The sender
  received the required response, and a post-run two-ping check passed.
- **Recovery state:** payload exited normally; console remained
  reachable; no hard power cycle was needed for this run. Other console
  services were not checked.
- **Interpretation:** [verified-on-console] these exact changed values
  were writable, readable, and restorable in this new run. [inference]
  The frozen attempt is more likely to have failed in the later
  TF/#DB/return path than because these writes are deterministically
  rejected. A timing-sensitive write failure or concurrent #DB could
  still distinguish the frozen run; S2 cannot retrospectively locate
  its last completed instruction. This run does **not** establish
  exception delivery or IST4 frame use.

### Separate kernel-read channel calibration (2026-10-13)

- **FW/build and approval:** 12.02 (`0x12020000`),
  `byepervisor_probe_1202_observer_channel.elf`, SHA-256
  `2566975ee18bdad09d468996417a1620ae35e56f99de35fba5cf6d5cd01ec0ae`.
  The owner explicitly approved sending the rebuilt observer ELF. The
  recovery plan for a freeze or an unsafe pipe restore was a hard power
  cycle; the payload was designed to park on a failed restore or thread join.
- **Expected:** allocate a second pipe object, take SDK reference reads of
  the live vector-1 gate and scratch, pin the trigger thread and observer
  worker to two different permitted CPUs, take the same reads through the
  second pipe, log the worker result independently to `ps5log/1`, compare
  the reference reads before/after, and restore/verify the pipe object and
  original affinity. No IDT/IST/scratch writes or #DB trigger were in
  this calibration build.
- **Actual:** elfldr returned `[O1]` with reserved CPU 9 and observer CPU
  11, then `[O2] trigger CPU pin=YES; observer/SDK match=YES; references
  stable=YES; worker log send=YES; affinity restore=YES; pipe restore=YES`.
  The PC `ps5log/1` server recorded three ordered markers: worker sample
  `rc=0`, stable references/read match, and private-pipe restore. Its
  manifest reported `clean=true`, `records=3`, and no sequence gaps. Two
  post-run pings succeeded.
- **Recovery state:** the payload exited normally and the console remained
  reachable; no hard power cycle was needed. Other console services were
  not checked.
- **Interpretation:** [verified-on-console] a worker on another CPU read
  these two kernel-data regions through a separate pipe and delivered its
  result to the PC in this calibration run. [verified-in-tree] The SDK
  `kernel_copyout`/`kernel_copyin` path configures a pipe via the inherited
  socket pair (`ps5-payload-sdk/crt/kernel.c:462-528`). [inference] The
  observer's per-sample setup still depends on that inherited primitive,
  so a later trigger must serialize SDK kernel reads/writes against the
  observer; overlapping them would falsify the assumed isolation. This run
  did not trigger #DB and did not capture an exception frame, so it leaves
  the four live-path boundaries below unvalidated.

### Observer-enabled #DB frame attempt (2026-10-13)

- **FW/build and approval:** 12.02 (`0x12020000`),
  `byepervisor_probe_1202_observer_frame.elf`, SHA-256
  `42ca623bbacac27e9fa122c2610759d0793efdd04291cfcdfc70ab253943b1eb`.
  The owner said to go ahead after the one-shot frame-capture plan and
  hard power-cycle recovery were described. The risk included a shared #DB
  gate pointing at an unverified 12.02 `add rsp,0xe8; iretq` target while
  only the trigger CPU's IST4 was redirected; an unrelated #DB on the
  observer CPU could also enter that gate.
- **Expected:** after the prior preflight, stage the canary and return
  frame, start a PC-connected worker on another CPU, patch/read back the
  trigger CPU's IST4 and the vector-1 gate, then issue one TF/NOP #DB.
  The worker should log a stable five-qword frame if the CPU pushes one
  at `IST4_top-0x28`; after a normal return, the main thread should
  restore/verify the gate and IST4 before clearing scratch. A matching
  frame would be stronger evidence of the patched-stack delivery than
  the earlier return-only probe.
- **Actual:** elfldr returned P1/P2/P3, `[F1] observer READY cpu=9
  trigger_cpu=15`, and both E1 lines describing the planned one-qword
  gate swap. No E2/E3/F2 followed; the sender timed out after 25 seconds.
  The PC `ps5log/1` server received only one `READY` marker and no BYE;
  it finalized that session uncleanly when stopped. Three subsequent
  pings all failed.
- **Recovery state:** console unreachable after the attempt; the owner
  performed the agreed hard power cycle and confirmed normal operation.
  A subsequent two-ping check passed.
- **Interpretation:** [verified-on-console] the worker reached its ready
  state and the main thread reached E1 before the freeze. [inference] The
  absence of an `armed` marker does **not** locate the failure before the
  gate readback: the main thread stores `OBS_ARMED` immediately before
  TF/NOP without waiting for the worker to run or send that marker. A
  gate/IST4 write/readback failure, a freeze during #DB, or a simultaneous
  worker/network stop could each produce this log; a future marker emitted
  after synchronized patch readback would distinguish them. This run did
  not capture an exception frame and validates none of the four remaining
  live-path boundaries below.

#### Post-patch observer calibration (2026-10-13)

- **FW/build:** 12.02,
  `byepervisor_probe_1202_observer_patch_calibration.elf`, SHA-256
  `c2281cd756d99c9742718a7523e09d7c06be2e7da9acbcb1f134c4d4fe3cb8aa`.
- **Expected:** after guarded IST4 and shared #DB-gate write/readback, the
  observer on a second CPU reads the staged five-qword canary and sends a
  PC `sampled` marker. The main thread waits at most 250 ms for that
  acknowledgment, restores and verifies gate/IST4 and scratch, then exits
  without setting TF or intentionally triggering #DB.
- **Risk and recovery:** the shared gate points to unverified 12.02 handler
  bytes while only one CPU's IST4 is redirected. The observer read and PC
  send extend the changed-gate interval. An unrelated #DB or a stuck read
  can freeze the console. The owner approved this exact build and hard
  power-cycle recovery plan before the run.
- **Actual:** elfldr returned P1/P2/P3, `[F1]`, both E1 lines, and
  `[F2] patch calibration sampled=1 worker=0 PC_log=0; gate, IST4,
  scratch restored; no #DB`. The PC received READY, `patch-calibration
  sampled cpu=9 canary=MATCH`, and a final marker reporting restoration,
  original affinity, and `no_db=1`. The `ps5log/1` manifest recorded
  three records, no sequence gaps, a clean BYE, and a device span of
  0.002313 seconds.
- **Recovery state:** the payload exited normally and two post-run pings
  passed; no hard power cycle was needed. Console UI was not checked.
- **Interpretation:** [verified-on-console] the PC received the canary
  marker and clean completion; elfldr reported restoration. [inference]
  the worker's canary read occurred after IST4/gate readback and before
  restoration because the main thread set `OBS_ARMED` only after those
  readbacks and waited for the worker's completed PC send before restoring.
  A different control-flow order in the built ELF or a marker emitted
  without a successful read would falsify this timing claim. This shows
  the observer can report while those patches are installed; the prior
  freeze remains unlocated because that run lacked the acknowledgment
  wait. The calibration did not trigger #DB or capture an exception frame.

#### Pretrigger frame handshake attempt (2026-10-13)

- **FW/build:** 12.02,
  `byepervisor_probe_1202_observer_frame_handshake.elf`, SHA-256
  `f9104be1641d84f1a1f7c246d81bda3d0d523fc4022effffd3ad51db7ef7e93c`.
- **Expected:** use the calibrated worker to read the canary and complete
  a PC `pretrigger sampled` send while IST4 and the shared #DB gate are
  changed. On a failed or timed-out 250 ms acknowledgment, restore and
  exit without a trigger. On success, issue one TF/NOP #DB and have the
  worker report a stable five-qword frame if it can observe one.
- **Risk and recovery:** this again intentionally dispatches #DB through
  unverified 12.02 handler bytes after a longer changed-gate window. The
  earlier frame attempt froze the console. A different CPU can encounter
  the shared gate; a freeze or failed restoration requires a hard power
  cycle. The owner approved this exact build and recovery plan before the
  run.
- **Actual:** elfldr returned P1/P2/P3, `[F1]`, and both E1 lines, then
  timed out after 25 seconds without E2/E3/F2. The PC received READY and
  `frame-observer pretrigger sampled cpu=9 canary=MATCH` 0.001487 seconds
  later. It received no changed-frame or return marker. The session was
  finalized on server shutdown with two records, no gaps, and no BYE.
  Three subsequent pings failed. **Owner correction:** the console powered
  off during this attempt; this was not merely an unresponsive console.
- **Recovery state:** the owner brought the PS5 back up and confirmed normal
  operation. Network reachability returned after startup; a later two-ping
  check passed.
- **Interpretation:** [verified-on-console] in this run the PC received a
  post-patch canary read before the power-off, so the worker and PC channel
  were active while the changed gate/IST4 were installed. [inference] the
  main thread had completed both patch readbacks before setting the
  observer phase that allowed this read; a different control-flow order
  in the built ELF would falsify that claim. The marker is sent **before**
  the worker stores the acknowledgment that releases the main thread, so
  it does not prove the main thread reached TF/NOP. An unrelated #DB during
  the changed-gate window, a failure at the intended trigger, or failure
  later in handler/return processing remain possible. No exception frame
  was captured and patched-stack delivery remains unvalidated. [inference]
  A fatal exception or panic is more consistent with power-off than a
  payload thread simply spinning; a console-side record of an orderly
  shutdown or external power loss would falsify that interpretation. The
  power-off does not by itself identify NPT.

#### Comparison with Kstuff's kernel-execution path

[public-consensus] Kstuff's installed #DB path uses the same
`add_rsp_iret` gate target and an IST4 pointer to
`noerrc_iret_frame+40`; see its
[`kelf.asm`](https://github.com/EchoStretch/kstuff-lite/blob/main/ps5-kstuff/kelf.asm#L158-L164)
and [IDT/TSS installation](https://github.com/EchoStretch/kstuff-lite/blob/main/ps5-kstuff/main.c#L1542-L1562).
Its `iret_rip` field is 232 bytes into `noerrc_iret_frame`
([`structs.inc`](https://github.com/EchoStretch/kstuff-lite/blob/main/ps5-kstuff/structs.inc#L16-L20)).
Thus, with `F = noerrc_iret_frame+40`, the `add rsp,0xe8` entry
lands at `F+0xc0 = noerrc_iret_frame+232`. [inference] This matches
the one-shot probe's **initial stack arithmetic**. A different
compiled IST4 pointer or frame layout in the working 1.11 build would
falsify the comparison.

[verified-on-console] The owner reports that installed Kstuff 1.11 works
on this 12.02 console. [public-consensus] Its public 12.02 table defines
`add_rsp_iret = doreti_iret - 7`
([`12_02.h`](https://github.com/EchoStretch/kstuff-lite/blob/main/prosper0gdb/offsets/12_02.h#L12-L14)).
[inference] Provided the installed build uses that table and #DB path,
the offset is operationally supported **in Kstuff's own frame context**;
an offset typo is a weaker explanation for this probe's power-off than
its different entry/return state. An inspection of the installed build
showing another offset or entry path would falsify this inference. The
working payload does not byte-verify 12.02 text or prove this probe
reached the target.

[public-consensus] Kstuff installs a prepared #DB IST4 frame for every
CPU ([`main.c`](https://github.com/EchoStretch/kstuff-lite/blob/main/ps5-kstuff/main.c#L1542-L1562));
the handshake probe changed only its pinned CPU's IST4. [inference]
Another CPU taking #DB while the shared gate was changed could therefore
enter that target with a different stack. An exception record showing
that only the patched CPU entered #DB would falsify this possibility for
the observed power-off.

The continuation differs. [public-consensus] Kstuff's first frame at
that landing point has `RIP=justreturn`, kernel `CS=0x20`, flags `2`,
and a kernel-side continuation stack; it then uses more staged frames,
register/GS handling, and a later return
([`kelf.asm`](https://github.com/EchoStretch/kstuff-lite/blob/main/ps5-kstuff/kelf.asm#L245-L295)).
Our probe staged a direct userland return at `F+0xc0`
(`RIP=ist4_evidence_resumed`, `CS=0x43`, flags `0x202`, user RSP,
`SS=0x3b`), with no `justreturn`/kernel continuation. [inference]
This was chosen to reduce gadget dependencies, but the reviewed working
sources did not validate an immediate first return to userland. The
architecture permits a CPL0→CPL3 `iretq`; that fact did not establish
that this 12.02 frame, delivery path, and hypervisor state were valid.
Byepervisor's
[`khook.c`](https://github.com/PS5Dev/Byepervisor-Reborn/blob/main/khook.c#L358-L386)
also returns to user mode via `iretq`, but **after** a staged arm chain;
its dispatch path builds a separate register-preserving resume tail.
This corrects the overbroad idea that no public payload has a
kernel-to-user return, while preserving the narrower gap: no reviewed
working source validated our immediate first-frame return.
The powered-off handshake probe staged Kstuff's gate target and first
stack displacement, without proving that either executed, and **did not
test the kernel-mode continuation
that works in installed Kstuff**. A compiled probe frame showing a
kernel `justreturn` first return would falsify this distinction.
Earlier minchain/r0gdb attempts exercised parts of Kstuff's separate
`run_in_kernel`/INT9 bootstrap; none completed a verified
call/return and restoration on this console (the correction above).

[public-consensus] A long-mode `iretq` can return from CPL0 to CPL3 by
loading the saved user RIP, CS, RFLAGS, RSP, and SS; that privilege
transition is not itself an NPT violation. AMD's
[architecture manual](https://docs.amd.com/v/u/en-US/24593_3.44_APM_Vol2)
describes the `iretq` frame and separately specifies that SMEP blocks an
instruction fetch from a user page **while still at CPL0–2**. [inference]
If the intended user TF/NOP caused this #DB, returning to its adjacent
user code through a valid CPL3 frame would not be rejected merely for
crossing from kernel to user mode. An exception record showing a denied
fetch at the return RIP would falsify that inference. Frame/selector
errors, a page permission or translation fault, and a secondary exception
while the gate/IST4 patch is active remain possible. The pretrigger marker
does not establish that the probe reached `iretq`, and the missing return
marker does not identify NPT as the cause.

#### Scope of a Kstuff-shaped follow-up

[public-consensus] Kstuff's `noerrc_iret_frame` does not stop at the first
`RIP=justreturn` frame. Its next staged entries use `justreturn_pop`,
`wrmsr_ret` to set GSBASE, `push_pop_all_iret` to capture registers, and
`noerrc_entry` to preserve the interrupted frame before continuing
([`kelf.asm`](https://github.com/EchoStretch/kstuff-lite/blob/main/ps5-kstuff/kelf.asm#L245-L299)).
Kstuff installs a separate frame pointer in every CPU's IST4 slot while
using one shared #DB gate
([`main.c`](https://github.com/EchoStretch/kstuff-lite/blob/main/ps5-kstuff/main.c#L1542-L1562)).

[inference] Replacing the probe's direct user frame with only
`RIP=justreturn`, or copying its current fixed user RIP/RSP frame to
every CPU, would leave the continuation incomplete and could return an
unrelated CPU to the probe's user thread. The public `noerrc` stack layout
or a captured first return showing a different continuation would
falsify this reading. A meaningful follow-up must stage a complete
per-CPU entry/continuation/return path that preserves each interrupted
context; only then can a changed shared gate be armed. This is a new
console-risky build, not a reuse of the approved handshake ELF.

[inference] There is a smaller **no-op return** candidate than Kstuff's
full KELF handoff: make the first staged `iretq` enter `justreturn` with
kernel RSP pointing at the five words the CPU pushed at `IST4−0x28`.
The public FreeBSD 11
[`justreturn` handler](https://www.mail-archive.com/svn-src-all@freebsd.org/msg141708.html)
preserves its scratch registers, acknowledges the interrupt, and jumps to
`doreti_iret`, which would consume that saved hardware frame and resume
the interrupted context. Kstuff's subsequent GS/CR3/register chain is
needed for its UELF handoff; this candidate performs no such handoff.
12.02 `justreturn` bytes have not been read, so a disassembly showing a
different control flow or a captured post-`justreturn` stack differing
from the hardware frame would falsify this candidate.

The separate offline build `byepervisor_probe_1202_justreturn_allcpu.c`
stages 16 disjoint 0x200-byte frame regions across two zero-checked
candidate scratch pages, saves/writes each CPU's IST4 as a qword, and
changes the shared #DB gate last. Its first return frame uses Kstuff's
12.02 `justreturn` offset `ktext+0x2b3400`, kernel `CS=0x20`, flags `2`,
and RSP=`IST4−0x28`; the existing `add_rsp_iret` target is
`ktext+0x2b3626`. [inference] `INT1`/ICEBP supplies a one-shot #DB with
TF clear in the saved frame, avoiding the repeated trap a TF/NOP would
cause on this no-op return path. Intel's
[instruction reference](https://cdrdv2-public.intel.com/835781/325462-sdm-vol-1-2abcd-3abcd-4.pdf)
documents `INT1` as a #DB trap with no gate-DPL check. A live #DB that
does not arrive through the patched gate or returns with TF set would
falsify the expected trigger behavior on this console.

- **FW/build identity:** first setup-only ELF SHA-256
  `4eb15b696d04fe2be690dc192d4d86698dd8a145e883777b4df883b6b44a7b24`;
  revised setup-only ELF SHA-256
  `a8a5bf464f81ab7b8c38d02ead8f60593402a71700d7c8fa8677a65b04e6bf0e`;
  revised live INT1 ELF SHA-256
  `b75794ed0624071662c6a5432996c451821c04e77b2d94d6ac8d1b52216a0c22`.
  Both are local payload-tree artifacts and are excluded from this notes repo.
- **Expected setup-only observation:** all 16 staged frames, IST4 writes,
  and the changed gate read back, then originals and scratch restore;
  no intentional #DB. A failed guard exits without arming.
- **Expected live observation:** one `INT1`, return through kernel
  `justreturn` and the saved hardware frame, then gate/IST4/scratch
  restoration and a `MATCH` on saved RIP/CS/RSP/SS and clear TF.
- **Risk/recovery:** the shared gate and all 16 IST4 slots change briefly.
  An incidental #DB during staging, a wrong 12.02 `justreturn` contract,
  or a bad frame can panic or power off the console. Hard power-cycle,
  then confirm normal UI and network operation. The owner approved
  proceeding with a Kstuff-shaped one-shot and this recovery class on
  2026-10-13. The changed `INT1` trigger and both exact builds are
  recorded here before the live console run.

**First setup-only run (2026-10-13):** [verified-on-console] the first
setup-only ELF printed `[J1] fw=12.02 cpu=15 all_cpu_frames=16 ...` after
all 16 frames were staged and read back. The PC received the matching
`ps5log/1` staged marker. Elfldr timed out after 25 seconds without
`[J2]` or BYE; three subsequent pings succeeded, so the console did
not power off. The owner confirmed that the UI was responsive. The
approved hard power-cycle recovery was requested because restoration of
the gate and IST4 slots was not observed. The owner restarted elfldr
without a power cycle and explicitly authorized proceeding. A new
read-only audit before the next write found the expected native #DB
target (`+0x3188b0`), IST4=4, zero IST4 pointers into the staged slots,
and zero nonzero scratch bytes. This establishes the measured pre-run
state, though it does not identify where the first payload stopped.
No `INT1` instruction exists in this setup-only ELF, and the live ELF
was not sent. [inference] One candidate for the payload-thread hang is
the first build's single 8192-byte `kernel_copyin` during scratch
restoration, after restoring the gate/IST4 slots; the SDK implements
this through a pipe `write` (`ps5-payload-sdk/crt/kernel.c:463-493`),
and this call is larger than every 512-byte staging write that completed.
There was no marker between gate/IST4 restoration and that write, so
the location remains unproven. The revised build restores scratch in
512-byte chunks and emits `[J1r]` only after gate/IST4 restoration.

**Read-only audit and revised setup-only run (2026-10-13):**
[verified-on-console] the read-only audit ELF SHA-256
`ff0e29c14ea31a4d9adbe177a11ef91641603152e00ed614f27941b3b43db6be`
reported the baseline values above. The revised setup-only ELF SHA-256
`a8a5bf464f81ab7b8c38d02ead8f60593402a71700d7c8fa8677a65b04e6bf0e`
printed `[J1]`, `[J1r] shared #DB gate and all IST4 slots restored`,
and `[J2] ... originals restored; no #DB`. Its PC `ps5log/1` session
recorded both staged and clean setup-only markers with BYE. The console
answered two subsequent pings. This validates the patch/readback/restore
sequence in that run; it does not validate #DB delivery or the
`justreturn` continuation. Recovery state: normal payload exit; no
power cycle was required for the setup-only run.

**Live one-shot run (2026-10-13):** [verified-on-console] the live ELF
SHA-256 `b75794ed0624071662c6a5432996c451821c04e77b2d94d6ac8d1b52216a0c22`
printed only `[J1]` after frame staging. The elfldr connection closed
about 0.3 seconds later without `[J1r]`, `[J2]`, or a PC `ps5log/1` BYE.
The console answered three pings. A second run of the same read-only
audit showed the #DB gate at `+0x2b3626` (the staged target), all 16
IST4 pointers at their staged frame addresses, and 836 nonzero scratch
bytes. Thus restoration did not run before the payload connection closed.
[inference] The one-shot path failed at or after the gate/IST4 patch,
possibly during #DB delivery or the first kernel return; an observed
pre-`INT1` failure or a captured hardware frame showing no #DB would
falsify the delivery inference. This run **does not prove** that the
12.02 `justreturn` offset or the frame geometry is wrong. Recovery
state: shared gate/IST4 left patched; owner instructed to hard
power-cycle. The owner then reported the console ready. A read-only
audit ELF with the same SHA-256 reported the native #DB target
`+0x3188b0`, IST4=4, zero staged IST4 pointers, and zero nonzero scratch
bytes; the console answered two pings. The specific physical recovery
action and UI state were not separately reported. No further kernel
write or exception trigger was sent after the failed live run.

**Proposed discriminator after recovery (not run):** a rebuilt read-only
audit ELF SHA-256
`f2c9d641b00f537129be8fe6664997a5ce713c60faf10517eb2eea16c6a3f3b2`
compares each staged CPU's five words at `IST4−0x28` with the canaries
written before the live trigger. It makes no IDT/TSS/scratch writes and
does not trigger an exception. [inference] If the same live ELF is run
again and leaves the gate/IST4 patched while the console remains
reachable, a changed hardware-frame slot would support #DB delivery on
that CPU; unchanged canaries would falsify delivery to those staged
slots in that run. The audit cannot establish that the first `iretq`
executed or that `justreturn` returned. The proposed live repeat would
reuse SHA-256 `b75794ed0624071662c6a5432996c451821c04e77b2d94d6ac8d1b52216a0c22`;
its expected outcome is either `[J2] ... frame=MATCH` or a failed
return with a readable staged frame. Its known risk is another
unrestored shared gate/all-CPU IST4 state, with possible console panic.
Recovery is a hard power cycle followed by a read-only baseline audit.
This repeat requires fresh owner approval before sending. On clarification,
the owner asked whether it used a **complete kernel continuation and return
path**. It does not: the proposed repeat reuses the minimal `justreturn`
→ hardware-frame return. The repeat is deferred. A full-chain
probe would be a different build with its own reviewed frame sequence,
build identity, expected observations, and recovery plan.

**Staged `ret` continuation candidate (built offline, deferred):**
[inference] A smaller explicit ROP return path can avoid the unverified
`justreturn` call/EOI behavior without claiming to reproduce Kstuff's
full KELF handoff. The `add_rsp_iret` entry still needs a five-word
kernel `iretq` frame. Set its RIP to Kstuff's 12.02 `nop_ret`
(`ktext+0x2b0b26`), CS=`0x20`, flags=`2`, RSP=`F−0x30`, SS=`0`, where
`F` is that CPU's IST4 value. At `F−0x30`, stage Kstuff's
`doreti_iret` (`ktext+0x2b362d`). The hardware's five-word #DB frame
starts at `F−0x28`. The intended sequence is:

`add_rsp_iret` → `iretq` → `nop_ret` → `ret` → `doreti_iret` →
`iretq` through the CPU-saved frame.

[public-consensus] Kstuff's
[`12_02.h`](https://github.com/EchoStretch/kstuff-lite/blob/main/prosper0gdb/offsets/12_02.h#L12-L18)
defines `add_rsp_iret`, `doreti_iret`, and `nop_ret` (the last from
`wrmsr_ret+2`). The same header defines `justreturn` separately
([`12_02.h`](https://github.com/EchoStretch/kstuff-lite/blob/main/prosper0gdb/offsets/12_02.h#L62-L69)).
[public-consensus] In 64-bit mode, `iretq` pops RSP/SS even on a
same-privilege return
([AMD64 APM Vol. 2](https://docs.amd.com/v/u/en-US/24593_3.44_APM_Vol2));
this is what lets the first frame select `F−0x30` as the ROP stack.
The proposed two-gadget chain makes no deliberate register, GSBASE,
or CR3 changes, so its intended no-op return can consume the original
hardware frame. It is **not** Kstuff's full register/GS/CR3 continuation
or Byepervisor's context-preserving dispatch/return chain. Adding a
`ret` before `iretq` does not supply the state handling those working
paths perform. It must not be presented as a public-validated khook
return path. The 12.02 gadget bytes have not been read. A disassembly showing
another epilogue or a captured frame that does not land at `F−0x28`
would falsify the proposed geometry.

The separate local build uses all 16 staged IST4 frames and changes the
shared #DB gate last, as above. Setup-only ELF SHA-256
`1709f16c0040de299b1d961126f02733c8f93e35acb0be86666793f7867ec71d`;
live `INT1` ELF SHA-256
`cb1440429c62643d65326384883f733c8f47ea51b3dbf285a47f3bbd9198c5a0`.
Both artifacts are outside this notes repo. Expected setup-only result:
`[J1r]` and `[J2]` with no #DB. Expected live result: `[J2] ...
frame=MATCH` and restored gate/IST4/scratch; if it fails while the
console remains reachable, use the read-only frame audit above before
recovery. The changed shared gate and all 16 IST4 slots can again leave
the console in an unsafe state or panic it. Recovery: hard power cycle,
then read-only baseline audit and UI check. No new ELF was sent; this
is a separate console-risky experiment requiring owner approval. The
owner emphasized that Byepervisor's user return occurs **only after**
its staged chain; this minimal two-gadget run is deferred pending a
reviewed context-preserving chain or independent evidence that its
shorter path is safe.

### Full-chain contract before another #DB trigger (offline review)

[public-consensus] Byepervisor's [`kh_install` and `kh_trigger`](https://github.com/PS5Dev/Byepervisor-Reborn/blob/main/khook.c)
use **two different #DB deliveries**. The first is a user-thread,
TF/NOP arm pass. The same gate pivot lands on `arm_chain`, which sets
DR0/DR7 through the `resumectx` tail, changes that CPU's IST pointer to
`disp_chain`, and only then executes a staged `iretq` back to the
triggering user thread. The later kernel breakpoint lands on
`disp_chain`: the CPU writes its five-word frame at `F−0x28`, the
`add rsp,0x28; ret` gate target skips the frame, and the dispatch stub
pivots to `big_chain`. That chain saves selected registers into its own
later restore slots, runs the handler, changes the saved return RIP or
registers as requested, disarms DR7 in one-shot mode, and pivots back
to an `iretq` qword immediately before the **same hardware frame**.
An arm-pass success would not validate the later breakpoint pass.

The reference's register preservation is **selective**, not an all-GPR
snapshot: [public-consensus] `khook.c` saves/restores RDI, RSI, and RDX
in `big_chain`; other gadgets also change RAX and RCX, and the caller's
contract must permit those changes. [inference] A benign 12.02 return
probe needs an explicit live-register contract, or a full trapframe
capture/restore, before it can claim to preserve its caller. A
post-return comparison of the agreed registers with their pretrigger
values would falsify a claimed preservation contract. A console-alive
marker alone would not prove it.

| Stage required for a faithful one-shot dispatch | 12.02 evidence | Blocking question |
|---|---|---|
| #DB gate and per-CPU frame at `F−0x28` | [verified-on-console] changed gate/IST4 values were readable and restorable in setup-only runs; live delivery was not observed | Did #DB actually enter on a prepared CPU's IST4 stack? |
| Skip the hardware frame and `ret` to the dispatch stub | [inference] `ktext+0x2ac2de` from a 13.60 adjacency; 12.02 bytes unknown | Is the complete `add rsp,0x28; ret` sequence present, with the same stack effect? |
| Pivot to an isolated, per-CPU big chain | [public-consensus] 13.60 `POP_RSP`/dispatch layout in `khook.c`; no byte-confirmed 12.02 `pop rsp; ret` | Which 12.02 instruction implements this pivot without clobbering the frame? |
| Save the live registers that later gadgets overwrite | [public-consensus] reference uses `mov rax,rsi/rdi`, stores through RCX, and self-modified restore slots | What are the 12.02 byte-confirmed store/pop/move gadgets and the exact register liveness contract? |
| Perform a benign kernel continuation, then restore registers | [public-consensus] reference `big_chain` places handler work between save and restore; the earlier two-gadget proposal omitted this stage | What harmless operation gives an observable marker **after** dispatch without requiring console logging from the exception path? |
| Return through the original hardware frame | [verified-in-tree] `r0gdb/prosper0gdb/offsets/12_02.h:12-14` names `doreti_iret`; [inference] frame placement and 12.02 instruction bytes remain unconfirmed | Does RSP point at the captured frame before `iretq`, and does the return restore the intended context? |
| Restore gate, IST4, and scratch after user return | [verified-on-console] setup-only restoration passed; live post-return restoration never ran | Did the return marker arrive, and did the read-back match the saved state? |

The narrowest **full-dispatch** candidate uses one userland `ICEBP`
(`#DB`) and no hardware breakpoint. [inference] This removes the
reference's DR7 arm pass from *this* diagnostic while retaining its
dispatch, live-register save, benign handler, restore, and hardware-frame
return. It would establish that dispatch class only; it would say
nothing about arming a kernel breakpoint or the S3 trigger.

The proposed stack contract, with one independent scratch area per
CPU, is:

1. `F` is the staged IST4 top. The CPU writes the five-word #DB frame
   at `F−0x28`; the gate target skips to `F` and returns into a
   dispatch `pop rsp; ret` at `F`, whose next qword selects that CPU's
   big chain. [inference] A different frame size or pivot stack effect
   would falsify this layout.
2. The big chain uses the reference's RDI/RSI/RDX save sequence, writing
   the live values into its later restore-immediate slots. Its benign
   handler writes one fixed marker to a separate scratch qword. An
   independent observer can read the hardware frame and marker even
   if userland never reaches the return marker. [inference] A changed
   frame with no handler marker would localize failure to dispatch or
   earlier big-chain steps; a handler marker with no return marker
   would localize it to restore/pivot/`iretq` or later user execution.
3. The chain pops the saved RDI/RSI/RDX, then `pop rsp` selects
   `F−0x30`, containing one `iretq` gadget. That `ret` leaves RSP at
   `F−0x28`, so `iretq` consumes the CPU's original frame. The
   trigger wrapper must declare every other changed caller-saved
   register (at least RAX/RCX/R8 for this chain) as clobbered; the
   existing `justreturn_allcpu.c` inline `ICEBP` wrapper does not
   declare those clobbers and cannot be reused unchanged. [inference]
   A mismatch in the saved registers, frame, or post-return kernel
   state would falsify the proposed preservation/return contract.

This is a **design**, not a ready ELF. The required `add rsp,0x28; ret`,
`pop rsp; ret`, save/store, marker-store, and restore-pop entries still
need exact 12.02 addresses and byte-level semantics. All-CPU stack
preparation is needed while the shared gate is changed, even though the
triggering thread is pinned. The next artifact can be a staged-chain
builder only after those entries are supported; using guessed offsets
would repeat the failed live-probe pattern in `11` #21–#22.

[verified-on-dump] The 13.60 donor resolves a subtle arm-chain entry
contract: its `DBREG_RESUME` address `+0x2529d8` starts at `mov dr0,rax`.
The preceding load from `[rdi+0x78]` is at `+0x2529d4` and is skipped;
the reference arm chain deliberately pops its hook address into RAX.
The tail subsequently loads DR1/2/3/6/7 and restores R15–R12, RBP,
RSP, and RBX from the context before returning. [inference] The 12.02
candidate `+0x2acb78` cannot be used merely because `cpu_switch` has
the expected region offset; a 12.02 instruction read must confirm the
entry and the full context/RSP side effects. A differing sequence or
layout would falsify that candidate.

[verified-in-tree] A nearest-anchor scan of Kstuff's
`r0gdb/prosper0gdb/offsets/13_60.h:12-76` against Byepervisor's
`include/offsets/13_60.h:26-49` places `POP_RSP` at least `0x8de8`
bytes from its nearest named text offset; `MOV_RAX_RSI` is at least
`0xe89b` away and `MOV_RAX_RDI`
at least `0x1bd66` away. [inference] These gaps are too broad to turn
the earlier local `cpu_switch` displacement into a defensible 12.02
address for the dispatch/save gadgets. The missing gadget list above
remains missing; a local 12.02 disassembly or independent same-function
anchor would falsify this *lack of derivation* for any one gadget.

[verified-on-dump] The 13.60 Kstuff `push_pop_all_iret` target is a
jump thunk into a trap entry that reserves `0xe8` bytes, saves GPRs,
reads state MSRs, calls the kernel trap routine, and jumps into the
return path. Its `pop_all_iret` counterpart loads GPRs from a complete
trapframe, conditionally swaps GS for a user return, then executes
`iretq`. [public-consensus] Kstuff's
[`kelf.asm`](https://github.com/EchoStretch/kstuff-lite/blob/main/ps5-kstuff/kelf.asm)
builds that full frame and its GSBASE/continuation handoff; its
[`12_02.h`](https://github.com/EchoStretch/kstuff-lite/blob/main/prosper0gdb/offsets/12_02.h)
names the 12.02 entries. [inference] Neither entry substitutes for
Byepervisor's isolated save/restore gadgets: `push_pop_all_iret` calls
the real trap handler, while `pop_all_iret` expects a populated full
frame. A 12.02 disassembly and an independently justified full-frame
layout would be needed to use them in a new chain.

**Next construction gate:** derive and byte-check the 12.02 dispatch
pivot, stack pivot, and save/restore gadget sequences, then specify the
exact register and hardware-frame images for the chosen trigger. Until
those contracts are reviewable, the two-gadget ELF remains deferred and
there is no **Byepervisor-dispatch** ELF to send. The Kstuff-family
alternative below has a separate contract. The shared #DB gate still presents
the observed all-CPU risk even if only one thread is pinned; any new
trigger needs prepared stacks for every CPU that can take #DB, a
reviewed expected marker/observer plan, fresh owner approval, and the
hard-power-cycle plus read-only baseline recovery plan.

#### Alternative full continuation using Kstuff's 12.02 gadget family

[public-consensus] Kstuff's
[`kelf.asm` `memcpy` macro](https://github.com/EchoStretch/kstuff-lite/blob/main/ps5-kstuff/kelf.asm)
uses `pop_all_iret` with a populated register frame to enter
`rep_movsb_pop_rbp_ret` and continue from its `pop rbp; ret` epilogue.
Its [12.02 table](https://github.com/EchoStretch/kstuff-lite/blob/main/prosper0gdb/offsets/12_02.h)
names `add_rsp_iret`, `pop_all_iret`, `rep_movsb_pop_rbp_ret`, and
`doreti_iret`; these yield text-relative offsets `0x2b3626`,
`0x2b35ce`, `0x2efbba`, and `0x2b362d` with the dump-derived
`kdata−ktext=0xd50000`. [verified-on-dump] The 13.60 donor decodes the
corresponding `rep_movsb_pop_rbp_ret` entry as `rep movsb; pop rbp; ret`
and `pop_all_iret` as full-GPR loads followed by a conditional `swapgs`
and `iretq`. The exact 12.02 bytes are still unknown. This approach
uses Kstuff's documented chain primitives instead of projecting
Byepervisor's missing individual pop/store gadgets onto 12.02.

[inference] A one-shot diagnostic can stage, for each of 16 CPUs, a
five-word hardware-frame canary at `F−0x28`, a first kernel `iretq`
frame at `F+0xc0`, two complete register frames, and a source/destination
scratch marker. The intended sequence is:

`#DB → add_rsp_iret → pop_all_iret → rep_movsb_pop_rbp_ret`
`→ pop_all_iret → doreti_iret → original #DB hardware frame → user wrapper`.

The first populated frame gives `rep movsb` kernel-data source,
destination, and count 8. Its kernel RFLAGS value 2 clears DF and IF.
The copy writes a fixed marker; `pop rbp; ret` enters the second
`pop_all_iret` frame. That frame gives `doreti_iret` a kernel CS and
RSP=`F−0x28`, so the final `iretq` consumes the CPU frame. A separate
assembly wrapper saves all six ABI callee-saved GPRs on the **user**
stack before `ICEBP`, then restores them after return; the kernel
chain's second register image may set caller-saved GPRs to known
values. The original CPU frame restores user RIP/RSP/RFLAGS/CS/SS.
Falsifiers are a changed hardware frame without the marker, a marker
without a return marker, register/frame mismatch, or another gate/IST
state after cleanup. This validates a Kstuff-style continuation and
return; it would **not** validate Byepervisor's unverified 12.02
`add rsp,0x28; ret` dispatch pivot or DR7 arm pass.

The isolated local source (outside this notes repo) now builds three
FW 12.02 ELFs: setup-only SHA-256
`074ec7dfa2feeff63cee4a096bf00590afe209e76bca4b688e1e55a2d838e99a`,
live SHA-256
`c057f484e66d137a14ddc041e02776da28193c1d9a741b32e27f6b0772fb7aff`,
and read-only audit SHA-256
`0d8676972036143435662b1479cc9b6af049a631e33395f4b3b33defbbd5fefc`.
Build success is an offline fact; **none has been sent** as of this note.
Each CPU gets a `0x500`-byte disjoint slot (`0x5000` total), within a
zero run in the 12.02 data dump; the payload refuses nonzero live
scratch. It also refuses a non-native #DB gate, an unexpected IST4
user, wrong kernel CS, failed single-CPU affinity, or a readback
mismatch. The gate is shared, so all 16 IST4 slots are prepared before
changing it. [inference] Zero bytes alone do not prove this scratch is
unowned; a live change or concurrent owner would falsify the cave
assumption.

**Console plan approved by the owner on 2026-10-13:**
read-only baseline first; then setup-only, expecting `[K1]`, restored
`[K1r]`, and `[K2]` without #DB. Only after clean setup and a fresh
baseline, the live ELF would expect `[K2] frame=MATCH marker=MATCH` and
restored gate/IST4/scratch. The separate read-only audit reports each
CPU's hardware frame and marker only while elfldr remains usable; a
marker alone locates progress through the kernel copy, not through the
return. A changed shared gate and all-CPU IST4
slots can still panic or leave the machine unsafe. Recovery is a hard
power cycle, followed by read-only native-gate/IST4/scratch audit and
UI check.

**Actual observations, 2026-10-13:** [verified-on-console] The initial
read-only audit reported native #DB target `+0x3188b0`, IST4, zero
staged slots, zero nonzero scratch bytes, and no marker. The setup-only
ELF emitted `[K1]`, `[K1r]`, and `[K2]`; a second read-only audit gave
the same clean baseline. The live ELF then emitted `[K1]` only. Its
elfldr connection closed about 0.4 seconds later without `[K1r]` or
`[K2]`; three pings and a port-9021 check immediately afterward
succeeded. A follow-up attempt to send the read-only audit over elfldr
timed out after 25 seconds with no audit marker. The next three pings
failed and port 9021 no longer accepted connections. The PC-side
`ps5log/1` record contains the live staging marker but no return/BYE.
No hardware frame or scratch marker was captured, so neither the
Kstuff-style chain nor any particular instruction was proved to run.
[inference] The changed gate/IST4 state may have persisted when the
first connection closed; a read-only audit payload can still execute
code while that shared gate is changed. The observations do **not**
establish whether the audit attempt caused the later outage or whether
the original live fault progressed independently. Falsifier: an
independent pre-armed observer or fault capture showing the gate had
already been restored, or showing a different causal sequence.

**Recovery state:** [verified-on-console] The owner hard power-cycled
the PS5 and confirmed the UI works normally. A post-reboot ping replied,
but elfldr port 9021 was not listening; the native gate, IST4 slots,
and scratch have therefore not been re-audited after reboot. No ELF was
sent after recovery. For any redesigned probe, the frame/marker observer
must already be running before the live trigger; do not rely on loading
a new audit ELF into an uncertain changed-gate state. This supersedes
the post-stall audit part of the plan above.

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
