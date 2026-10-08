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
