# 08 — Phase B capability inventory & mechanism notes

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

**FW 12.02 question** [inference]: the older implementations do not establish
what happens while 12.02's current IOMMU configuration and CPU NPT protections
remain enabled. The PS5 wiki infers from hypercall names that the HV manages
the IOMMU, but does not document whether a GPU request is checked through the
same NPT, which IOMMU translation is applied, or how the two interact.
Falsify this narrow version-specific question against public source and
existing evidence before considering any console experiment. Inferring a
full text-read route from generic AMD GPUVM behavior alone was too broad.

**Owner approval and safety plan**

- **Approval**: the console owner explicitly approved this GPUVM text-read
  experiment in the project conversation on 2026-10-09. This approval is
  scoped to the bounded read experiment described here; it does not cover
  broader GPU, DMA, or hypervisor probing.
- **Risk**: an incorrect GPUVM entry, address, or TLB invalidation may
  target unintended memory or hang the GPU/system. An NPT denial may fault
  or wedge the console and require a forced power cycle. The intended copy
  is read-only, but editing GPU page tables still changes kernel data.
- **Bounded run**: use one unused GPUVA, map one text page, issue one read
  into a dedicated scratch allocation, and make no writes through the GPU
  mapping. Do not widen the mapping or repeat with guessed addresses in the
  same run. If the console remains responsive, remove the test PTE and
  invalidate the GPU translation before ending the session.
- **Stop conditions**: stop on any unexpected GPU fault, missing completion,
  loss of console responsiveness, or output inconsistent with the one-page
  read. Do not issue follow-up GPU commands after a hang or fault.
- **Recovery**: if the console hangs or panics, stop the payload and perform
  the established hard power cycle. On reboot, confirm normal startup and
  inspect the saved host-side logs before any repeat. If normal startup does
  not return, stop and use the owner's established recovery process; do not
  repeat the experiment until the failure is understood.

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
why Phase B targets non-memory paths (hypercalls, intercepts) or
alternate translation engines (GPUVM).

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

**C. Alternate translation engine** (bypass NPT)
- C1: GPUVM PTE injection + GPU read (IOMMU-gated? — falsify DTE first)
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

### What ps5-hen's gpu_dma does (the complete recipe)

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
   cleared_ptbe | target_phys)` — a kernel data write that makes the
   GPUVM entry point at ANY physical address
8. **Submit a PM4 DMA_DATA command** via ioctl to `/dev/gc` —
   the GPU's DMA engine reads/writes whatever the PTE points to
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

### The critical architectural insight

**GPUVM page tables are in KERNEL memory** — they are kernel data
structures, readable and writable by our pipe primitive on ANY
firmware. The GPU's DMA engine translates GPUVA→physical through
these tables, NOT through the NPT. This is architecturally separate
from the CPU's NPT enforcement.

On ≤4.51 with HV defeated: GPU DMA to any physical address works
(proven by this code). On 12.02 with HV active: the question is
whether the HV-managed IOMMU adds a second check between GPUVM and
physical memory, or whether GPUVM is the only translation layer for
the GPU.

### What we need for 12.02

1. `DATA_BASE_GVMSPACE` offset for 12.02 — findable in our kdata dump
   (it's where the 4 GiB-strided aperture table lives, at the region
   we already identified as "GPUVM-class" at kdata+0xc880f0)
2. `VMSPACE_VM_VMID` = 0x1E4 (same across all FWs in their table)
3. The per-FW `sizeof_gvmspace` and `gvmspace_page_dir_va` offsets
4. Everything else is standard: `/dev/gc` open, PM4 command building,
   ioctl submission

### Viability assessment update

Previously: "medium-low odds, cheapest falsification, best skills
match." Now: **the recipe exists in tested code, all the kernel-side
primitives are the same class we already use, and the only unknown
is whether the HV-IOMMU blocks GPU DMA on 12.02.** The experiment is:
retarget a GPUVM PTE to kernel .text physical → PM4 DMA_DATA read →
check if the bytes come back. Worst case: a GPU fault (recoverable —
not a kernel panic, the ioctl returns an error).

This is the strongest Phase B lead after QA-flags.

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
- E4: **DMA incoherence**: use the GPU's DMA engine (which we
  already know bypasses NPT) to write to a page that's also cached
  by the CPU. The GPU writes to DRAM; a dirty CPU cache line
  can overwrite it.

### Practical PS5 chain candidates from STALEUS inspiration

- **E2 (race the flush)**: write QA flags → immediately trigger
  rest/resume before the cache line flushes → the HV's NPT builder
  reads the OLD (pre-SL) flags → NPT built with xotext. This is
  the INVERSE of A1: instead of setting the flag early, we exploit
  that the flag might not be visible yet. [Requires precise timing;
  may explain A1 failures]
- **E4 (GPU incoherence)**: the GPUVM experiment (C1) retargets a
  GPUVM PTE via kernel write. If the GPU's page-table walker has
  its own cache of that PTE, our kernel write might not be what
  the GPU sees — or vice versa. The "ioctl failed" result from
  our v1 attempt could be a coherence artifact, not an IOMMU block.

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
