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

**The gadget problem dissolves — the engine substitution.** The
pop-gadget ROP chains are *their* engine, not a requirement. The
kstuff lineage has a different, **12.02-proven** execution engine:
`run_in_kernel` (`r0run.asm`, byte-identical in the upstream fork):

- a register struct is loaded via **xchg of all sixteen GPRs** —
  full register control *and* live-register capture in one primitive
- the kernel frame (target RIP/RSP/RFLAGS, cs=0x20) is written to
  `kframe` in kernel data — **registers set by kernel-data writes
  (our pipe primitive), not by pop gadgets**
- CPL0 entry via the patched vector-9 gate (`int 9`, DPL3, IST3) —
  the same gate/frame machinery `r0gdb_setup` used, **proven live on
  2026-10-09** (the EFER/CR0 reads and the store gadgets all ran
  through it)

For the fault-entry side (the FACS #GP trigger), the same machinery
applies: `r0gdb_setup`'s IDT-gate + IST patching pattern, extended
from vectors 1/9/179 to **vector 13 (#GP)** — the fault context's
frame is saved at the IST entry (the proven pivot design) and the
xchg capture preserves the kernel's live registers for the resume.

**The port architecture, revised**: Byepervisor's *structure* (the
FACS #GP trigger, the resume-window launch with the fault-frame
argument replacement, the NP-disable `break_hv`, the pre-rest pmap
edits) + **our engine** (the frames/xchg/int9 machinery instead of
their pop chains). The missing-gadget set becomes: **empty** — every
needed primitive is in our verified 12_02.h table or is the proven
r0gdb machinery itself.

Remaining true unknowns (unchanged): the HV-side `pcpus`/heap
discovery (dynamic, from root 0), the FACS-trigger integration (the
dump-verified anchor), the `break_hv` port, and the `cpu_switch`
struct layout (the resumectx DR7 slot) for the DR7-style arm if the
#GP trigger needs one.

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

## Port phases

1. **Offsets + gadget mapping** (offline + our primitives): the table
   above; derive the missing gadgets via our sysent-anchor method and
   verify each at runtime with our proven kernel-call machinery (the
   r0gdb EFER/CR0 experience — one-shot, park-safe)
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
