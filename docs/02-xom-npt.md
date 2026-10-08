# 02 — The XOM/NPT boundary on FW 12.02

## Two-level translation (AMD)

```
Level 1  guest page tables   VA -> GPA    kernel-owned data -> we can edit
Level 2  HV's NPT            GPA -> SPA  HV-owned, own R/W/NX bits per page
```

- NPT, not EPT — EPT is Intel's term; the PS5 is AMD Zen 2.
- Kernel `.text` physical pages carry NPT entries with the **xotext bit
  (bit 58)** set [public-consensus, PS5 Developer wiki / Hypervisor page]:
  executable, not readable, not writable.
- Consequence: **any** guest-PTE remapping of text pages (new VA, RW bits
  set, UELF-style alias, dmap access) still resolves through the NPT and
  faults. Page-table ownership does not grant text access.
- The HV additionally intercepts CR0/CR4/MSR accesses (MSR protection map;
  EFER writes to nda/SVME/NXE bits are silently masked) [public-consensus,
  wiki].

## The cheap first layer (guest-PTE XO)

The kernel's own PTEs map `.text` execute-only at the guest level
(FreeBSD-native exec-only mappings). This layer is trivially cleared once
you hold kernel data write, and it was never the real barrier. Its job is
to stop the *previous rung* of attackers: anyone with only a kernel
*read* primitive cannot dump `.text` to find symbols/gadgets. [inference
from loader code + FreeBSD mapping semantics; see 03 for the loader's
`remove_xotext` being one layer of several]

## What this makes impossible on 12.02

- Reading kernel `.text` at runtime (no dumps, no runtime symbol
  resolution, no gadget scanning).
- Writing/patching kernel `.text` (no PS4-style text kpatches, no code
  caves).
- Entering the HV (the ≤7.61 routes are closed — see 03).
- Free MSR/CR manipulation.

## Evidence chain that our stack never touches text

- **[verified-in-tree]** ps5debug-NG's `install_kernel_patch` writes a
  data-flag byte: FW 12.x target `DATA_BASE+0xD83088`, while
  `SECURITY_FLAGS = DATA_BASE+0xD83064` and `TEXT_BASE = DATA_BASE-0xD50000`
  — the target is `security_flags+0x24`, unambiguously in `.data`. All
  "kpatches" in this ecosystem are data-flag edits.
- **[verified-in-tree]** kstuff's architecture (per-FW validated gadget
  chains, ring-3 UELF with custom CR3 doing all bulk work, `mov [rdi],rax`
  store *gadgets* instead of injected code) is explicable only in a world
  where there is no writable executable surface.
- **[verified-in-tree]** No tool in our tree ever issues a kernel-memory
  write targeting the text VA range.
- **[public-consensus]** PS5 Developer wiki: XOM enforced through the HV's
  nested page tables, bit 58; XOM partly an AMD hardware collaboration
  ("nda feature", masked EFER bit 16); on FW ≤ 2.70 the HV was part of the
  kernel binary, later a separately loaded component.

## The PS4 → PS5 delta

PS4: no hypervisor; kernel text RWX-writable via primitives → trivial
kpatch era. PS5: HV + multi-layer XOM from the start → kernel patching
moved to data flags, kernel execution moved to gadget chains, bulk
privileged work moved to ring-3 custom-CR3 contexts.
