# HCALL 0x0f resume-window route: complete state and NOOP catalog

Status document for sharing with other researchers. Everything here is
labeled with its evidence class. Last updated 2026-10-12.

## The route in one paragraph

The PS5 hypervisor's HCALL 0x0f (`khv_startup_mp`) launches an
application processor with a guest-supplied RIP and CR3. During the
resume-from-rest window (after `resumectx` returns, before
`acpi_wakeup_cpus`), the one-shot bitmap reopens and the launched AP
runs on NPT root 0 (the host view) — hypervisor RAM mapped, kernel
text readable, NPT protections absent. From root 0, the VMCB pages
are writable; writing `NESTED_CR3` (+0xb0) on any core redirects that
core's nested page table root, which is the full GameOS/HV boundary
crossing. This supersedes every text-read route (QA flags, GPUVM,
CR4 gadget hunting).

## The HCALL 0x0f ABI [owner-source]

```
Instruction:  VMMCALL
ID register:  RAX = 0x0f
Arguments:    RBX = logical core (must be < 16)
              RCX = start RIP (guest-supplied, not validated)
              RDX = CR3 (guest-supplied, not validated)
Return:       RAX = 0 on success

Handler:      khv_startup_mp at HV 0x105B0
              (src/svm/hypercall.cpp:446)
Guards:       core < 16 AND the one-shot bitmap — nothing else
              (no CPL check, no argument validation)
```

## The complete launch chain [owner-source, partially verified]

The proof used this sequence:

1. **Stage the carrier page** at phys `0x3ffff000` before suspending:
   a 4-KiB position-independent payload on a page the firmware's
   `bios_mapping` table marks root-0 executable (the identity mapping
   ends at 0x40000000). The page survives S3 clean.
2. **Arm #DB** at `acpi_sleep_machdep+0x18e` — the breakpoint fires
   in the resume window (after `resumectx`, before
   `acpi_wakeup_cpus`).
3. The #DB's ROP chain invokes `HCALL 0x0f(core=15,
   RIP=0x3ffff000, CR3=0x68000)` from kernel context.
4. Core 15 launches at 0x3ffff000 with CR3=0x68000. It never fetches
   GameOS kernel text, so the vcore's `cur_npt` stays at 0 (root 0).
5. From root 0, the payload walks the inner HV's `pcpus[]` array and
   converts: `VMCB_phys = pcpu[core].m_vmcb − hv_heap_offset`.
6. The 16 VMCBs are at `0x62a57000 + core × 0x1000` (one page each).
7. **The payoff**: write to `NESTED_CR3` at VMCB+0xb0 to redirect any
   core's NPT root. `NESTED_CTRL` at +0x90 (= 9: NP enable | GMET)
   and `Control2` at +0xb8 (= 1) control the nested paging state.

The proof write/read-back/restored a reserved qword at VMCB+0x100 on
all 16 cores, emitting a success marker only after all 16 restores
verified — confirming the full write primitive.

## Precondition mapping (what we already have)

| Precondition | Our capability | Evidence |
|---|---|---|
| Kernel data read/write | pipe primitive + alias engine | [verified-on-console] |
| Ring-0 text execution | r0gdb single-step gadget machinery | [verified-on-console] |
| Debug breakpoint arming | r0gdb_write_dbreg (DR0-DR3, DR7) | [verified-on-console] |
| Rest-mode cycling | owner-operated | [established] |
| CR3 construction | kernel data read (pm_cr3) + alias engine | [verified-on-console] |
| Carrier page write | alias-engine write to phys 0x3ffff000 | [inferred: same class] |

## What we've verified vs what's still hypothesis

### Verified [verified-on-console]

- **VMMCALL from CPL3 = SIGILL**: the VMCB's VMMCALL intercept is
  clear at runtime on 12.02. Userland hypercalls are impossible. The
  hcall path requires kernel context.
- **SMEP is set** (CR4 bit 20): CPL0 instruction fetch from userland
  pages = #PF → kernel panic (verified the hard way: a ring-0 gadget
  step at a userland RWX page crashed the console).
- **EFER = 0x11d01**: SVME is set — the PS5 kernel itself runs SVM
  virtualization (its app sandboxes are SVM VMs).
- **CR0 = 0x8005003b**: PE|MP|TS|ET|NE|WP|AM|PG.
- **CR4.FSGSBASE = 0**: userland rdfsbase/wrfsbase raise #UD despite
  hardware support (CPUID.7.0:EBX[0]=1).
- **Ring-0 single-step of kernel-text gadgets works**: rdmsr and
  mov_rax_cr0 executed successfully via the r0gdb machinery.
- **The r0gdb ring-0 session is functional**: IDT gate patching,
  TSS IST redirection, and the gdb RSP protocol all work on 12.02.

### From the owner's sources (not yet independently verified)

- The resume window exists (bitmap reopens, VMMCALL intercept is
  enabled in kernel context during resume)
- The AP launches on root 0 (not forced to root 1)
- The VMCB write primitive from root 0 (16-core read-back-verify)
- The firmware bios_mapping carrier page at 0x3ffff000
- The #DB breakpoint at acpi_sleep_machdep+0x18e

### Still unknown

- The exact address of `acpi_sleep_machdep` on 12.02 (best lead: the
  FACS wake vector at phys 0x9bf60, readable via one alias read)
- Whether the VMMCALL intercept is actually enabled during the
  resume window (it's the hypothesis, not yet observed)

## NOOP catalog (what doesn't work on 12.02)

### Definitively dead [verified-on-console]

| What | Why | Evidence class |
|---|---|---|
| Userland VMMCALL / hcalls | VMCB intercept clear at runtime; CPU raises #UD before any VMEXIT | verified-on-console (hcall_h0.elf) |
| CPL0 execution of userland pages | CR4.SMEP = 1; instruction fetch from user page at CPL0 = #PF → kernel panic | verified-on-console (ring-0 session #2 crash) |
| Writing own code to userland RWX and executing at CPL0 | Same SMEP violation | verified-on-console |
| Writing own code to kernel heap and executing at CPL0 | Same SMEP violation (kernel heap pages are user-mapped in the NPT) | inferred from SMEP |
| ET_EXEC / -no-pie payload links via elfldr | MAP_FIXED at link-time base 0x400000 collides with the SceSpZeroConf host eboot; pt_mmap fails EINVAL | verified-on-console |
| kstuff crt-elf stub layer without repair | The raw syscall stubs bootstrap through addr__dynlib_dlsym, which crt-elf sets to the payload_args pointer; any stub call before repair jumps into the struct | verified-on-console |
| Plain gdb without '+' ACK after every reply | The stub's end_packet blocks reading '+'; a missing ack kills the session (produces zombie listeners) | verified-on-console |
| TCP port-probing a live gdb stub | The stub does exactly one accept(); a probe consumes it | verified-on-console |
| The gdb k packet after ring-0 setup | SIGKILL leaves patched IDT gates + TSS IST pointing into freed memory | verified-by-analysis |
| r0gdb cleanup via rip-stepping | The cleanup function's nested ring-0 syscalls (wrmsr, copyin/copyout) are unproven; the client restores IDT/TSS itself via mov-gadget single-steps instead | verified-by-analysis |
| qOffsets from the prosper0gdb stub in static-PIE builds | start_nonreloc gets an R_X86_64_RELATIVE applied, degenerating the formula to a constant | verified-on-console |

### Deprioritized (viable but superseded)

| What | Status | Superseded by |
|---|---|---|
| TMR register reading (E-TMR-2) | Technically readable via alias engine (ECAM confirmed dmap-mapped) | Orthogonal: TMR is a hardware wall under the NPT; the resume path crosses at the NPT level |
| QA-flags chain (qa_probe/qa_check) | Built, gated, staged | Root-0 AP launch reads kernel text directly, no QA flags needed |
| GPUVM route (gpuvm_read v3) | Built, gated, staged | Root-0 AP launch reads NPT-denied physical memory directly |
| CR4 gadget hunting in kernel text | Needed kernel text + a mov rax,cr4 instruction | VMCB NESTED_CR3 write gives full NPT control; kernel text becomes readable from root 0 |
| Finding cpu_stdext_feature | Was needed for FSGSBASE compat | Superseded by the NPT-level boundary crossing |
| fsgsbase_enable CR4 write via kernel data | Boot-specific candidate values; never stable across boots | Superseded |

### Worth knowing but not directly useful

| Finding | Evidence |
|---|---|
| The kernel's CPUID cluster at kdata+0x2e61f60: cpu_feature=0x078bfbff, cpu_id=0x00840f81 (family 0x17, model 0x48 = PS5 APU), cpu_exthigh=0x80000020, amd_feature=0xf5c2b7ff, amd_feature2=0x0000700f. The adjacent dword 0x6799 is NOT cpu_stdext_feature (has INVPCID bit set, impossible on Zen 2) | verified-on-dump |
| sysent table: stride 48, sy_call at +8, at kdata+0x1af4d0, 746 entries. sysarch (165) at kdata−0xa3c878 — verified on 3 boots | verified-on-dump + verified-on-console |
| FreeBSD 11's kernel-side FSGSBASE machinery: initializecpu() gates CR4.FSGSBASE on cpu_stdext_feature & CPUID_STDEXT_FSGSBASE; set_pcb_flags() gates the pcb-save path on the same flag; cpu_switch.S saves pcb_fsbase/gsbase via rdfsbase when the flag is set. If Sony's kernel retains this, setting the flag + CR4 bit activates the full compatibility machinery via a single kernel data write | public-consensus (FreeBSD 11 source) |
| The elfldr (ps5-payload-dev) spawn host is SceSpZeroConf (NPXS40112); Syscore serializes spawns during game launches; the klog msgbuf is small and churns fast | verified-on-console |

## The ACPI text region on 12.02 [verified-on-dump]

From the 134 MiB kernel-data dump, only 3 text pointers exist in the
ACPI region [ktext+0x380000, ktext+0x400000):

| kdata location | ktext target | Context |
|---|---|---|
| kdata+0x01991b8 | ktext+0x396390 | kobj device method (position ~4 in a driver method table) |
| kdata+0x0199bd8 | ktext+0x3b3b60 | kobj device method (position ~6 in a driver method table) |
| kdata+0x2060cd8 | ktext+0x3f9b9f | debug/trace (not useful) |

ACPI table data:
- **FADT** at kdata+0x7604000 (signature "FACP", length 268)
- **FACS at phys 0x9bf60** (from FADT X_FIRMWARE_CTRL)
- The FACS **wake vector** (at +0x0C or +0x18) would give the exact
  kernel resume entry point — one alias-engine read of phys 0x9b000
  page + offset 0xf60
- ACPI strings found in kernel data: "acpi_wakeup: failed to resume
  AP #%d", "acpi_wakeup_event", "acpi_sleep_event", "power_resume",
  "power_suspend"
- No aligned kernel data pointers to the event strings exist (the
  eventhandler lists are not in the dump window)

The ps5-linux-loader's HOOK_ACPI_WAKEUP_MACHDEP across firmwares:
3.00→0x390E73, 4.00→0x391203, 5.00→0x3A7613, 6.00→0x3A75E3. Our 12.02
anchors at ktext+0x396390 and 0x3b3b60 bracket this region.

## The public HV-defeat lineage (for context)

Three generations, all superseded on 5.00+ by our resume-window route:

1. **≤2.xx (embedded HV)**: flatz — disarm via kernel's
   `__hv_vm_area` → VMCB patch (clear NP, GMET, CR intercepts)
2. **3.00-4.51 (external HV)**: ps5-linux — TMR relax → VMCB patch
   via IOMMU physical writes → forced VMCB reload → kernel shellcode
3. **5.00-7.61**: IDT gate patching + IST ROP + APICBASE wrmsr trigger

Our route (12.02): #DB at acpi_sleep_machdep+0x18e → ROP chain →
HCALL 0x0f → AP on root 0 → VMCB write.

## Immediate next steps

1. **FACS wake vector read**: alias-engine read of phys 0x9bf60
   (one page) → the exact `acpi_wakeup` address on 12.02
2. **acpi_sleep_machdep derivation**: from the wake vector, use
   FreeBSD 11 source layout to compute the function and the +0x18e
   breakpoint offset
3. **Carrier page staging**: alias-engine write to phys 0x3ffff000
4. **The resume breakpoint chain**: r0gdb session arms DR0, owner
   cycles rest mode, breakpoint fires, ROP invokes the hcall
5. **The AP payload**: position-independent, walks pcpus, writes
   markers (or patches NESTED_CR3) on all 16 VMCBs

## Repository map

| Document | Contents |
|---|---|
| `01-primitives.md` | Kernel R/W primitives inventory |
| `02-xom-npt.md` | XOM/NPT protection model |
| `03-evolution-pre761.md` | HV evolution through 7.61 |
| `04-route-1202.md` | The original 12.02 research program |
| `05-toolchain-and-observability.md` | Toolchain notes |
| `06-sources.md` | Source catalog |
| `07-evidence.md` | Chronological evidence log (PRs #37-#48) |
| `08-phaseb-inventory.md` | Phase B capability inventory |
| `09-live-kernel-state-and-fsgsbase.md` | Live kernel state + FSGSBASE analysis + HV lineage survey |
| `10-hcall-resume-window-and-noops.md` | This document |
| `evidence-logs/` | Raw protocol logs |

### NOOP: FACS wake vector (2026-10-12)

The FACS at phys 0x9bf60 (from FADT X_FIRMWARE_CTRL) reads as **all
zeros** via the alias engine (no fault, page readable, just empty).
The PS5's firmware does not populate a traditional ACPI FACS wake
vector at this address. The PS5 resume goes through the hypervisor,
not through a BIOS ACPI wake. This approach is dead.

Alternatives for locating `acpi_sleep_machdep`:
1. The kobj method table positions (ktext+0x396390 and ktext+0x3b3b60
   are ACPI device methods — identify which is suspend/resume by
   position in the method table)
2. FreeBSD 11 source layout relative to known text anchors
3. The "acpi_wakeup: failed to resume AP" string's printf xref
