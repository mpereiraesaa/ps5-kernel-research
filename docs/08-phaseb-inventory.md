# 08 — Phase B capability inventory & mechanism notes

**⚠ SUPERSEDED 2026-10-12**: The Phase B QA-flags and CR4 gadget plans
were deprioritized in favor of the HCALL 0x0f resume-window AP-launch
design. GPUVM DMA was retired as a 12.02 text-read option after the
v1/v2 outcomes and v3 source audit (`11` #81). The public implementation
shows root-0 kernel-text access; the FW 12.02 port has not reached it
(`17`). See [10-hcall-resume-window-and-noops.md](10-hcall-resume-window-and-noops.md)
for the historical route and NOOP catalog.

Recorded 2026-10-08 so the Phase B starting position is not lost. Labels
per README (`[verified-in-tree]` / `[public-consensus]` / `[inference]`).

## Capabilities we already hold (building blocks for any new route)

- **Calling hypercalls** [inference, strong]: `vmmcall` is ring-0-only,
  but the KELF gadget chains execute in ring 0, and the kernel's `hv_*`
  service wrappers (containing the actual `vmmcall` sites) are text
  functions callable with controlled arguments — the same
  call-a-kernel-function class ps5debug-NG's `CMD_PROC_CALL` proves on
  12.02. Unknown: the 12.02 hypercall service map and each service's
  validation. Probing with wrong args = owner-approved session only.
- **Writing physical address 0 (or any physical address)** [inference,
  strong]: the kernel direct map covers all physical memory, so
  `kernel_copyin(buf, dmap+0, len)` writes PA 0 today; the alias reader
  can read it back. The closed part of the 7.x trick was never the copy
  — it was making the HV *use* attacker memory (APICBASE pivot).
- **Kernel-memory write + read** [verified-on-console]: pipe writes,
  PTE-gated reads, alias reader (`payloads/kalias_sweep/`).
- **GPU command submission + GPU memory management** [verified-in-tree,
  the lab's AGC work]: command buffers, DMEM pools, GPUVA mappings via
  official APIs. Adjacent to, not identical with, hand-rolled GPUVM
  page tables.

## Mechanism notes

### How wrmsr interception works, and why the 7.61 trick was possible

SVM interception is standard: the VMCB holds intercept controls,
including the MSRPM pointer. `MSR_APICBASE (0x1B)` is write-intercepted;
guest `wrmsr` causes a VM exit carrying the guest register state
(RCX=MSR, RAX:RDX=value); the HV handler validates and emulates or
rejects. The 6.50–7.61 vulnerability was **in the handler, not the
mechanism** [public-consensus]: it accepted any page-aligned base with
ENABLED|BSP — including the HV's own stack region — and kept using it.
Subsequent HV APIC accesses landed on attacker-controlled memory
(shellcode pre-copied to PA 0) → execution pivot into host context.
Lesson: **interception ≠ security; the handler's validation is the
battlefield.** Closed on 12.x (validation added).

### GPUVM PTE format and the text-read experiment

The PS5-specific GPUVM entry shape is publicly documented in
`cragson/ps5-hen`'s `gpu_dma.h` and `gpu_dma.cpp` [public-consensus,
PS5 HEN and ps5-jar-loader implementations]. The published walker uses
64-bit entries and PDB2 → PDB1 → PDB0 → PTB levels. Its constants are:

```
bit 0      VALID
bit 54     IS_PTE (2 MiB leaf in this walker)
bit 56     TF
bits 59-63 BLOCK_FRAG field (5-bit mask)
bits 6-47  address field (mask 0x0000FFFFFFFFFFC0)
```

The walker handles 2 MiB leaves and 8 KiB / 64 KiB page-table blocks.
This supersedes the approximate generic GFX10.3 entry sketch above; the
field names and page sizes should still be tied to the referenced source
revision when they are used in an implementation.

**Existing public capability** [public-consensus]: `ps5-hen` remaps a
GPU-visible buffer's PTE and submits a GPU DMA transfer to read or write a
requested physical address. Its README scopes support to FW 1.00–4.51 and
describes patching the IOMMU before disabling nested paging as part of its
HV defeat chain. `ps5-jar-loader` independently documents the remap-and-DMA
kernel accessor. These implementations establish a GPUVM-mediated physical
access technique in their supported, HV-compromised context.

**FW 12.02 correction** [public-consensus; verified-on-console;
verified-in-tree; inference]: the older implementations do not
establish access with the 12.02 HV/IOMMU active. The version-specific
permission outcome was never observed. An approval for a bounded 2026-10-09
experiment is historical; the local attempts and recovery are recorded in
`07`. This route is retired from the 12.02 plan (`11` #81).

### Modern-AMD context

The machinery (VMCB, NPT, MSRPM, intercepts, VMMCALL) is standard AMD
SVM — the same model underlies Hyper-V/KVM/VBS on every Zen machine.
PS5-specific: the xotext/nda NPT bit (Sony–AMD), the thin security HV,
IOMMU under HV control, TMR hardware, and per-handler validation logic.
The universal lesson for Phase B: attack surface = hypervisor exit
handlers + device-translation validation + MSRPM coverage, everywhere.

## Relation to the three closed routes

All three (IOMMU write; `hv_unmap_pt_tmr` abuse; APICBASE hijack —
mechanics in `03-evolution-pre761.md`) targeted the same object: the
**VMCB's `NESTED_CTRL.NP_ENABLE`** (per-CPU, HV-owned memory). Clear it
→ NPT off → guest PTEs become the only translation → text read/write.
A fourth route needs a new ladder to either the VMCB, an equivalent
HV-owned structure, or a translation path that bypasses NPT entirely
(the GPUVM question).

## Q&A addendum (2026-10-08, owner questions)

### Where is the HV's data?

Historically [public-consensus, loader constants]: on 6.50–7.x the HV
code+data sat at physical ~0x62800000+ (`HV_REENTER_HYPERCORE
0x62806380`, `HV_STACK_TABLE 0x6282E120`, `HV_PML4 0x6282E1A0`,
`HV_CODE_CAVE_PA 0x62806F00`). On 12.02: unknown to us.
**Experiment — GPA liveness map**: the alias engine writes arbitrary
GPAs into our own PTEs; NPT-unmapped GPAs fault *recoverably* in
userland (SIGSEGV, counted, skipped). A full guest-physical-space
sweep therefore maps exactly which regions the guest can see and which
are hidden/denied — the holes are the HV/PSP carve-outs. Safe
(zero kernel-context reads of unknown memory), one payload, host-side
analysis.

### HV interception scope (autonomy)

The HV intercepts only sensitive/state-changing operations (CR writes,
MSRs per MSRPM, CPUID, VMMCALL, I/O, interrupts). Everything else runs
at bare-metal speed because **NPT is hardware-walked**: the CPU, not
the HV, enforces second-level policy on every access. Kernel autonomy
is an illusion bounded by NPT.

### PSP MMIO and mailbox reachability

The PSP (ARM core, root of trust — boot chain, keys, secure services)
is programmed via mailbox registers + shared buffers in physical memory
("MMIO"). The kernel side is `sceSblServiceMailbox` (in kstuff's
12_02 table; the ~15 `_lr_` call sites map the protocol's flows).
With kernel r/w the shared buffers are readable/writable in our dumps
and the doorbell is kernel-mapped MMIO — **kstuff's whole fPKG
mechanism already lives on this surface** (pointer-poisoning the
`crypt_singleton_array` at `kdata+0x2d61e30` — present in our dump).
The boundary is PSP-side message validation, not reachability.
**Experiment — mailbox snooping**: dump the singleton/shared-buffer
regions during a game mount to learn the live protocol; forge only
after understanding it.

### Unprotected HV jump tables

Cannot be enumerated without reading HV memory (Phase B chicken-and-egg).
Approachable via: the GPA liveness map (find guest-visible-but-guarded
HV structures — the historically fatal class was a **guest-HV shared
bookkeeping array**, `hv_unmap_pt_tmr`'s `hvm_shm`); black-box
hypercall probing; older-FW structural continuity from the wiki.

### HV growth ⇒ attack surface growth

Post-FW7 HV growth (IOMMU takeover, more services, more handlers) means
more reachable validation code — and we can invoke hypercalls, so each
service is reachable from our position. "Grew + must be correct
everywhere" vs "we need one gap": favorable research odds; same
statistical premise as Phase B itself.

### NPT hardware-walked (mechanism note)

SVM nested paging: the MMU walks guest tables (VA→GPA) then NPT
(GPA→SPA) automatically on TLB miss; no HV code runs per access. NPT
denials raise VM exits the HV handles. Guest-kernel autonomy over its
own tables is real but policy-irrelevant (guest PTEs change VA→GPA,
never GPA→SPA). The memory-path attack surface is therefore NPT
contents, VMCB/NCR3 setup, or silicon — not handler code — which is
why Phase B surveyed non-memory paths (hypercalls, intercepts) and a
GPUVM hypothesis that was later retired (`11` #81).

### NPT covering HV-own memory (premise: present-but-denied, not holes)

[public-consensus from wiki/loader era; unverified on 12.02]
Implications:

1. Hiding is permission-based — a single NPT-entry corruption exposes
   HV memory (holes cannot be "un-hidden"; present-but-denied can).
2. The NPT is a complete SPA map including HV/PSP regions — reading it
   ever = full physical layout of the machine; writing it = total win.
   NPT pages are HV memory (chicken-and-egg), but this defines the
   target hierarchy: NPT read = map, NPT write = endgame.
3. **GPA liveness sweep upgrade — `si_code` classification**: the HV
   synthesizes the guest-visible fault for NPT denials; if it forwards
   the protection/not-present distinction, the alias fault handler can
   record `SEGV_ACCERR` (entry exists → mapped-and-guarded) vs
   `SEGV_MAPERR` (hole) per GPA — classifying not just *where* hidden
   regions are but *how* they are hidden. Either result is a recorded
   12.02 fact.

## Combination-space framework (seeded 2026-10-10; 1k-target pending)

Target: make kernel .text readable (Phase B win condition). Every
known chain reduces to one of five mechanism classes against the
NPT-covers-HV premise:

**A. Make the HV rebuild the map benignly** (no HV write needed)
- A1: QA-flags SL bit + reinit trigger (Byepervisor class) — **PRIMARY
  LEAD; falsifiable now** (flags addr known; setters shipped; rest
  cycle owner-operated; text probe recoverable)
- A2: other NPT-construction inputs the HV reads from guest-shared
  memory (survey: every field the builder consumes — flags, memory
  maps, TMR state)
- A3: any code path that constructs an NPT without xotext (debug/
  updater/SP modes)

**B. Stop enforcement entirely** (NP_ENABLE=0 — the historical routes)
- B1: via VMCB write (needs HV-memory write: jump-table class)
- B2: via HV code execution (ROP/pivot: APICBASE class, needs entry)
- B3: via GMET/NPT control fields through a validation gap

**C. Alternate translation engine** (historical hypotheses)
- C1: GPUVM PTE injection + GPU read — retired as a 12.02 text-read
  option; public success depends on an IOMMU patch and no local text
  DMA request was reached (`11` #81)
- C2: other bus masters with DMA the IOMMU trusts (SP/DMA engines)
- C3: speculative/cache side channels (Zen 2 class issues)

**D. Read the NPT itself** (map without changing enforcement)
- D1: NPT pages via present-but-denied classification sweep
- D2: NPT-derived metadata leakage (TLB behavior, timing)

**E. Data-only kernel mastery** (no text needed — the fallback that
  already works: our current position)

Each combination = (mechanism class × trigger primitive × validation
gate × recovery plan). The 1k enumeration will expand these five
classes against our capability inventory; priority ordering by
(falsification cost, skills match, recovery safety) puts A1 first.

## Simulation lab (2026-10-10): ps5-sim-lab Tier-1 built and green

`engineering/ps5-sim-lab/` — synthetic guest state + payload logic in
testable form. **8/8 replay tests PASS**: every historical console-
killing bug class (unmasked walker descent, 511/512 span drift,
unconditional poison-mask, roundtrip read-before-walk) reproduces in
simulation as a failing case, and chain A1 (QA-flags → rest/reinit →
text probe) rehearses end-to-end against the modeled QA-reading HV
policy — including the restore path (SL cleared → xotext returns).
Boundary stated in-repo: simulation validates our logic and rehearses
chains against MODELED policies; it cannot predict the real 12.02 HV.
Console sessions become falsification-only, with pre-survived payloads.
Tier-2 (QEMU AMD-SVM mini-HV with pluggable policies) is the designated
engine for the 1k-combination narrowing.

## cragson/ps5-hen analysis (2026-10-09): GPUVM DMA recipe found

Source: https://github.com/cragson/ps5-hen (FW 1.00–4.51, 99 stars)
— `gpu_dma.cpp` + `gpu_dma.h` + `offsets.h` read in full.

### What ps5-hen's gpu_dma does in its supported context

1. **Open `/dev/gc`** — the GPU compute device
2. **Allocate 3 GPU-mapped buffers** (victim/transfer/cmd, 2 MiB each)
   via `sceKernelAllocateMainDirectMemory` +
   `sceKernelMapNamedDirectMemory` with `PROT_GPU_READ|PROT_GPU_WRITE`
3. **Find the VMID**: `proc→vmspace→vm_vmid` (kernel data read)
4. **Find the GPU page directory (PDB2)**: `gvmspace[vmid]→page_dir_va`
   (kernel data read — the `DATA_BASE_GVMSPACE` offset is in their
   per-FW table, e.g., 0x064C3F80 for FW 4.x)
5. **Walk the GPUVM page tables** (PDB2→PDB1→PDB0→PTB) using
   kernel_copyout through dmap — GPUVM tables are in kernel memory!
6. **Find the victim buffer's PTE** in the GPUVM page tables
7. **Retarget the PTE**: `kernel_setlong(victim_ptbe_va,
   cleared_ptbe | target_phys)` — a kernel data write that changes the
   GPUVM target; whether the device can reach that physical address
   depends on the remaining translation and permission checks
8. **Submit a PM4 DMA_DATA command** via ioctl to `/dev/gc` —
   the GPU requests a transfer through the resulting device mapping
9. **Restore the original PTE**

### GPUVM page-table format (from gpu_dma.h) [public-consensus → now verified]

```
PDB2 (PML4 equiv) → PDB1 (PDPT) → PDB0 (PD) → PTB (PT)
PTE fields:
  bit 0        VALID
  bit 54       IS_PTE (2 MiB leaf flag)
  bit 56       TF (translation fragmentation)
  bits 59-63   BLOCK_FRAG (fragment size encoding)
  bits 6-47    PHYSICAL ADDRESS (mask 0x0000FFFFFFFFFFC0)
```

### Translation boundary and missing 12.02 evidence

**GPUVM page tables are kernel data** in the public supported chain.
The GPU's own GPUVA translation is separate from CPU NPT translation,
but that does not prove a GPU request can reach a 12.02 kernel-text
physical page. An HV-managed IOMMU or other device permissions may
deny it. The 12.02 v1 observation below found a PDB2 and disjoint
CPU/GPU virtual addresses; it did not transfer text bytes.

On ≤4.51, the public `ps5-hen` chain first patches the IOMMU for
unrestricted memory access and defeats the HV. Its DMA result cannot
be carried over to 12.02 with the HV active. Whether Sony blocks the
same transfer on 12.02 is unknown; no local run has reached a
GPU-to-text DMA request.

### Current 12.02 assessment

This is a **retired 12.02 text-read hypothesis**, not an available
path. The HV-IOMMU is only one unknown: v1 found CPU/GPU VA
separation, v2 stopped during a CPU-side GPUVM-table walk and required
a hard power cycle, and v3 was blocked by source-audit defects before
a console run (`07` §“gpuvm v1 run” through §“gate upgrade”; `11` #45).
Neither a returned ioctl error nor a recoverable GPU fault is assured.
No further GPUVM text-read run is planned. Authenticated 12.02 text
bytes from a verified device path would falsify this evidence boundary.

## CVE analysis (2026-10-09): two HV bug classes confirmed in the wild

### CVE-2026-63794: sev_dbg_crypt page overflow → UAF

**The bug**: `len = min(PAGE_SIZE - s_off, size)` but NOT
`min(len, PAGE_SIZE - d_off)` — a one-line missing bound check.
When `d_off > s_off`, the PSP writes `round_up(4097, 16) = 4112`
bytes into a 4096-byte buffer. Heap overflow → use-after-free →
privilege escalation.

**Why it matters for PS5 12.02**:
1. **Same architecture**: KVM/SVM → PSP debug-decrypt path ↔
   PS5 HV → PSP mailbox path. Both are hypervisor services that
   read/write guest memory through the PSP for debugging.
2. **Same bug class**: a simple length/offset validation gap in a
   hypercall handler — exactly the class we model as
   `validation_gap` policy and hunt via `B3:unmap-gap`.
3. **The PSP path bypasses NPT by design**: the PSP reads physical
   memory directly. If the PS5 HV has an equivalent debug-decrypt
   service (even a private/internal one), invoking it on kernel
   `.text` physical pages would read them without any NPT check.
4. **Sony has the same code-pressure**: their HV is also a
   translation-table manager with debug services. A missing bound
   check there would be equally exploitable.

**New chain candidate — D2: debug-decrypt service**:
- Find or infer a HV service that reads guest memory through the PSP
- The SBL crypto path (`sceSblServiceCryptAsync` /
  `sceSblServiceMailbox`) is the PS5's PSP communication channel
- If any mailbox command can be made to read from an arbitrary
  physical address (a debug variant, a diagnostic mode, or a
  validation gap in the normal path), it bypasses NPT entirely
- Our captured singleton cipher objects + the live `0xdeb7` poison
  slots are the entry points into this path

### CVE-2026-53359: shadow paging UAF via role mismatch

**The bug**: guest modifies a PDE from outside → HV's shadow page
table creates a child with the wrong role (`direct=1` vs `direct=0`)
→ stale rmap entry survives memslot deletion → later walk
dereferences freed page.

**Why it matters for PS5 12.02**:
1. PS5 uses NPT, not shadow paging — but the **bug pattern**
   (stale internal bookkeeping after guest-side modification →
   later HV operation dereferences stale state) applies to ANY
   hypervisor that maintains translation metadata.
2. Our NPT premise: "the HV maps its own physical memory
   present-but-denied." If we can modify something that causes
   the HV's NPT bookkeeping to become inconsistent (e.g., the
   QA flags, the memory map, a TMR entry), a later NPT
   rebuild might use the stale state in a way that exposes
   protected regions.
3. This is the **B-class chain pattern**: modify a shared data
   structure → trigger an HV reinit → the HV's own code operates
   on attacker-influenced state.

**New chain candidate — B5: stale-NPT-state**:
- Modify a guest-visible data structure that the HV's NPT builder
  consumes (QA flags is one; there may be others)
- Trigger a rebuild (rest/resume, or any path that reconstructs)
- If the builder's bookkeeping becomes inconsistent (e.g., partially
  updated state from a race or ordering issue), the rebuilt NPT
  might miss xotext on some pages — even without the QA-flags
  SL bit being set

### Meta-lesson from both CVEs

Both bugs were found in **open-source** Linux KVM (millions of eyes).
The PS5 HV is **closed-source** (zero external audit). The same
classes of simple validation bugs almost certainly exist there —
they're just harder to find without source. Our approach — modeling
the HV's behavior, probing from the guest, and building the
combination matrix — is the systematic way to find them.

Add to the emulator:
- `sev_dbg_overflow` policy: models a debug service with a
  missing bound check (the PSP writes beyond the buffer)
- `stale_npt_state` policy: models a rebuild that uses
  partially-modified state
- Both are new columns in the 1k-combination matrix

## STALEUS analysis (2026-10-09): a new mechanism class — data incoherence

Source: USENIX Security '26, CVE-2025-54509, AMD-SB-3039.
Confirmed on EPYC 9124 (Zen 4) / 9135 (Zen 5). NOT confirmed on PS5.

### The mechanism (behavioral summary)

```
                    CPU cache: [metadata = NEW value (dirty)]
                              ↕ (cache coherence normally synchronizes)
                    DRAM:     [metadata = OLD value]

                    PSP reads DRAM directly (NoSnoop mode):
                    → sees OLD value → security check passes on stale data
```

Two stale-data windows:
1. **PSP reads stale**: CPU wrote newer metadata to cache (not yet
   flushed); PSP reads old DRAM value → security check on wrong data
2. **PSP write lost**: PSP writes to DRAM; CPU cache later evicts
   its dirty copy → overwrites PSP's write → CPU sees old, PSP
   committed new

The attacker (hypervisor) flips a SYSHUB bridge configuration register
to make PSP transactions assert `NoSnoop` — bypassing cache snooping.

### Why this matters for PS5 12.02 — five connections

1. **Same hardware family**: PS5 = AMD APU with PSP, interconnect
   fabric, cache coherence controllers. The architectural pattern
   (even if the exact registers differ) exists on our console.

2. **We already talk to the PSP**: The SBL mailbox path
   (`sceSblServiceCryptAsync` / `sceSblServiceMailbox`) is our
   documented, reachable PSP communication channel. The singleton
   cipher objects we captured ARE the kernel-side PSP state.

3. **Our QA-flags chain is a metadata attack on the HV**; STALEUS is
   a metadata attack on the PSP. Both make a security processor
   consume attacker-influenced state — but through completely
   different mechanisms (direct write vs coherence split).

4. **A possible explanation for "flag didn't take effect"**: If the
   HV reads QA flags from cached memory while our kernel R/W writes
   to DRAM, the HV might see stale flags even after our write
   "succeeds." This could explain why some NPT-construction inputs
   might not behave as expected even when the data looks correct from
   our side.

5. **The PSP path already bypasses NPT**: The PSP reads physical
   memory directly. STALEUS shows that the COHERENCE of what the
   PSP reads can be attacker-controlled. If we can influence what
   the PSP sees (even without the NoSnoop register), we might be
   able to make it operate on data that differs from what the kernel
   considers authoritative.

### New mechanism class: E — data incoherence

Added to the combination framework:

**E: Data incoherence** — make two agents (CPU and PSP) disagree
about the contents of security-critical data.

- E1: **Coherence split via bridge config** (STALEUS proper):
  flip a SYSHUB-like register → PSP reads/writes non-coherent
  → stale metadata consumed. [requires HV privilege on EPYC;
  unknown what privilege is needed on PS5]
- E2: **Race the flush**: write metadata, immediately trigger a PSP
  operation before the cache line is flushed. The PSP reads the
  pre-write value. [doesn't require any register change — just
  timing]
- E3: **Cache-line ping-pong**: write metadata from multiple CPUs
  to keep a cache line dirty, preventing the PSP's DRAM write from
  being visible to the CPU (or vice versa).
- E4: **DMA incoherence**: use the GPU's DMA engine (which has a
  translation path distinct from CPU NPT, but unverified 12.02 access
  to the target page) to write to a page that's also cached
  by the CPU. The GPU writes to DRAM; a dirty CPU cache line
  can overwrite it.

### Practical PS5 chain candidates from STALEUS inspiration

- **E2 (race the flush)**: write QA flags → immediately trigger
  rest/resume before the cache line flushes → the HV's NPT builder
  reads the OLD (pre-SL) flags → NPT built with xotext. This is
  the INVERSE of A1: instead of setting the flag early, we exploit
  that the flag might not be visible yet. [Requires precise timing;
  may explain A1 failures]
- **E4 (GPU incoherence)**: a GPUVM PTE retarget could have a
  coherence requirement, but our v1 attempt stopped during GPUVA
  discovery before a DMA ioctl. It provides no coherence or IOMMU
  outcome (`07` §“gpuvm v1 run”).

### Meta-lesson

STALEUS attacks a layer BELOW the NPT — cache coherence. It means
that even if NPT permissions are perfect, the DATA the security
processors consume can be made stale or inconsistent. This is a
fundamentally different attack surface from everything in our
current matrix, and it exists on the same hardware family.

### Safe adaptation

Build a behavioral simulation in the Tier-3 emulator:
- CPU cache model (dirty lines, eviction)
- DRAM model (authoritative backing store)
- PSP-like agent (reads/writes with coherent vs NoSnoop modes)
- A security check that reads metadata
- Verify: coherent mode preserves invariants; non-coherent mode
  breaks them (stale read, lost write)
- Label as behavioral simulation of the published mechanism

## 2026-10-09 priority update: QA-flags chain is the CR4 prerequisite

The ring-0 sessions (PRs #40/#41) proved the r0gdb machinery can execute
any kernel-text instruction with controlled registers (EFER, CR0 read
live), but CR4 needs a kernel-text `mov rax,cr4` (`0f 20 e0`) address,
and text is XOM to every reader we have. **The A1 QA-flags chain
(qa_probe v2 → rest cycle → qa_check v2) is now the prioritized next
console phase** — a successful QA text read plus a byte-scan delivers
both CR4 gadgets (read + write), after which the ring-0 machinery
becomes the CR4 engine. The GPUVM v3 route was listed as an alternative,
but its 2026-10-14 source audit found an unconverted physical PTE
address, unresolved GPU VA mappings, and unchecked restoration
([verified-in-tree] `07` §“gate upgrade”; `11` #45). The built ELF is
blocked offline and has not been run. Full historical context:
docs/09-live-kernel-state-and-fsgsbase.md.

## 2026-10-12 — New route: HCALL 0x0f STARTUP_MP resume-window AP launch

[public-consensus] ps5-wiki hcall table: `0x0f STARTUP_MP` and `0x10
DISABLE_STARTUP_MP` (03.00.00.33+) — the disable call's existence implies
an availability window. [owner-inference, encoded in
ps5-sim-lab/hvemu/resume_window.py (PR #2)]: resume reinitializes HV
state (startup_mp bitmap cleared, new vcore_t with cur_npt=0 — root 0 =
host view, root 1 = GameOS); the BSP transitions per-vcore on its first
GameOS text fetch (modeled 0x0150d6); parked APs stay on root 0; if
HCALL 0x0f is invocable between resumectx and acpi_wakeup_cpus with
guest-supplied RIP+CR3, the launched AP might run on root 0 = the host
view: kernel text readable, NPT protections absent — strictly better
than every Phase-B text-read route (one shot also enables CR4 writes).

Five falsification knobs (window-reopen W, wake-close C, CPL check K,
arg validation V, AP root R). The falsification ladder, cheapest first:

- **E1 (no rest cycle)**: userland `VMMCALL` with a harmless hcall
  (0x00 GET_MESSAGE_CONF) — discriminates hcall reachability from CPL3
  (K) and the HV's error behavior.
- **E2 (no rest cycle)**: hcall 0x0f at runtime with safe args
  (rip = RWX marker spin page, cr3 = our own process CR3 via
  proc→vmspace→pmap→pm_cr3) — the marker counter discriminates C
  (window closed at runtime?) with zero harmful AP behavior.
- **E3 (rest cycle, owner-operated)**: if C holds (window closed at
  runtime), the invocation must fire inside the window from kernel
  context — candidate invocation points: extended IDT-gate patching
  (the proven r0gdb IDT/data-write class) on a vector that fires during
  resume, or a resume-path data hook. Design gated on E1/E2 results.

Also 2026-10-12: CR4 bit-position correction — the earlier dump scan
labeled SMEP/SMAP as bits 7/8 (those are PGE/PSE); real SMEP/SMAP are
bits 20/21. The live behavioral SMEP proof stands; the `0x45da0`
"SMEP|SMAP" dump interpretation is retracted (boot-specific garbage
per the live 0x1dec read anyway). r0gdb_session.py's CR4 decode fixed.
