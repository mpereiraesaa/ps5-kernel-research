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

AMD GPUVM (GFX10.3 family): radix tree, **64-bit entries, 512/table,
~5 levels, 4 KiB + 2 MiB pages** (fragment bits encode large pages).
Canonical entry shape [public-consensus, amdgpu; exact PS5 bit
placement to be verified by us]:

```
bit 0      VALID
bit 1      SYSTEM (system memory vs VRAM)
bits ~5-6  READABLE / WRITEABLE
bits ~7-9  FRAGMENT (large-page size)
bits 12-47 physical address
bits 57-59 MTYPE (cache/coherency policy)
```

**The experiment** [design proposal]: GPUVM page tables are
kernel-memory objects (built by the AGC driver) → present in our dumps
and writable by our primitives. Steps: locate the live GPU page tables
→ insert a PTE mapping an unused GPUVA to kernel-text physical pages →
invalidate the GPU TLB (a command-buffer opcode) → issue a GPU copy
from that GPUVA into garlic memory → read the bytes. If the HV does not
validate GPUVM translations, this reads `.text` wholesale; if it does,
we learn where the validation lives — either result advances Phase B.
Open question it probes: **do GPU accesses traverse the same NPT that
enforces xotext, or does the GPU MMU translate directly to physical
with only GPUVM between?**

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
