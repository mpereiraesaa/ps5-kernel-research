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
2. **Trigger the resume window.** **CORRECTION (2026-10-13):** the
   public lineage does **not** arm a `#DB` breakpoint. 5.00–7.61 corrupt
   the ACPICA global `AcpiGbl_FACS` in kernel data (`kwrite64(ptrslot,
   ptslot−8)`), so the kernel's own `AcpiSetFirmwareWakingVector`
   dereferences the mangled pointer on resume and takes a **#GP** (IDT 13;
   that loader configures IST6 for its hook). No `acpi_sleep_machdep`
   instruction is involved. `0x18e` is also invalid (`11` #14, `12` §2).
   The 12.02 `AcpiGbl_FACS` anchor is dump-derived at
   `kdata+0x2cb4c80`. See `15` §1–§2 and `11` #16.
3. The proposed #GP ROP chain (with a selected IST stack; the loader
   precedent uses IST6) would invoke `HCALL 0x0f(core=15,
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
- ~~The #DB breakpoint at acpi_sleep_machdep+0x18e~~
  **CORRECTED (2026-10-13):** wrong *kind* — the public lineage uses a
  kernel-data `AcpiGbl_FACS` self-corruption → `#GP` trigger, not a
  breakpoint. See `15` §1 and `11` #16.

### Still unknown

- The exact address of `acpi_sleep_machdep` on 12.02. **CORRECTION
  (2026-10-13):** the FACS is at phys **0x7fd6e000**, not 0x9bf60
  (that is `PM1a_EVT_BLK`); the wake vector lead is untested, not dead.
  See `12` §1.
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
| Manually invoking r0gdb cleanup via rip-stepping | The prior client restore path and cleanup's nested ring-0 operations (RDMSR/WRMSR via `run_in_kernel`) were unproven; auto-cleanup is now wired in source but remains unvalidated on-console | verified-by-analysis |
| qOffsets from the prosper0gdb stub in static-PIE builds | start_nonreloc gets an R_X86_64_RELATIVE applied, degenerating the formula to a constant | verified-on-console |

### Deprioritized (viable but superseded)

| What | Status | Superseded by |
|---|---|---|
| TMR register reading (E-TMR-2) | Technically readable via alias engine (ECAM confirmed dmap-mapped) | Orthogonal: TMR is a hardware wall under the NPT; the resume path crosses at the NPT level |
| QA-flags chain (qa_probe/qa_check) | Built, gated, staged | Root-0 AP launch reads kernel text directly, no QA flags needed |
| GPUVM route (gpuvm_read v3) | Built, unrun; source audit blocks current ELF (`07` §“gate upgrade”; `11` #45) | Root-0 AP launch was the proposed direct text route; it is also unproved |
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

## Code pointers in the ACPI text range on 12.02 [inference]

From the 134 MiB kernel-data dump, only 3 text pointers exist in the
ACPI region [ktext+0x380000, ktext+0x400000):

| kdata location | ktext target | Context |
|---|---|---|
| kdata+0x01991b8 | ktext+0x396390 | `pcib` kobj method, entry 31 of 31 |
| kdata+0x0199bd8 | ktext+0x3b3b60 | `pci` kobj method, entry 51 of 59 |
| kdata+0x2060cd8 | ktext+0x3f9b9f | debug/trace (not useful) |

[inference] The first two targets occupy function fields in alternating
descriptor/function records. Kobj class records point to the containing
arrays and to name strings `pcib` and `pci`; each array ends at a
null/null entry. The `pcib` array is kdata+[0x198fd0,0x1991d0), and its
class record is at kdata+0xdc6308; the `pci` array is
kdata+[0x1998b0,0x199c70), and its class record is at kdata+0xdc7328.
These half-open array ranges include the null/null terminator. This
corrects the earlier rough position estimates and identifies these
targets as PCI bus-class methods, not ACPI sleep/wakeup callbacks. The
attribution would be falsified if the dump contents are invalid or if
the target firmware uses a different kobj record layout.

The structural match uses FreeBSD's `struct kobj_method` descriptor / function
pair and `struct kobj_class` name / methods fields ([FreeBSD 11.0
`sys/sys/kobj.h`](https://github.com/freebsd/freebsd-src/blob/releng/11.0/sys/sys/kobj.h#L43-L64)).

ACPI table data:
- **FADT** at kdata+0x7604000 (signature "FACP", length 268)
- **FACS at phys 0x7fd6e000** (from FADT `FIRMWARE_CTRL` at +0x24;
  corrected 2026-10-13 — earlier 0x9bf60 was `PM1a_EVT_BLK`. See `12` §1.)
- ACPI/power-related strings found in kernel data include
  "acpi_wakeup: failed to resume AP #%d", "acpi_wakeup_event",
  "acpi_sleep_event", and the `power_resume`/`power_suspend` names
  (including `ws_mgmt_*` strings noted below).
- ~~The FACS read at phys 0x9bf60 was all zero~~ **CORRECTED:** 0x9bf60
  is not the FACS; the real FACS at 0x7fd6e000 is unread. See `12` §1.

### Power/ACPI name anchors and source call path

[inference] The offsets below are byte offsets into the 12.02
kernel-data dump, not kernel-text function offsets. The listed bytes
identify the strings or substrings shown in the table; this
classification would be falsified if the dump identity or byte contents
do not match. A data-only dump cannot supply code cross-references to
these names, and the absence of pointers to the strings in `.data` says
nothing about references from `.text`.

| kdata offset | String | Public-source role |
|---|---|---|
| `+0x49fca2` | `acpi_system_eventhandler_sleep` | function-name trace string |
| `+0x3b353b` | `acpi_system_eventhandler_wakeup` | function-name trace string |
| `+0x4821b9` | `acpi_sleep_event` | event-handler registration name |
| `+0x444015` | `acpi_wakeup_event` | event-handler registration name |
| `+0x3735b7` | `acpi_timer_suspend_handler` | timer callback name |
| `+0x3a525f` | `acpi_timer_resume_handler` | timer callback name |
| `+0x3aa120` | `power_suspend_early` | power event name |
| `+0x399a65` | substring in `ws_mgmt_power_suspend` | not a standalone event name |
| `+0x48c6aa` | `power_suspend` | standalone power event name |
| `+0x37b4ee` | substring in `ws_mgmt_power_resume` | not a standalone event name |
| `+0x4395ef` | `power_resume` | standalone power event name |

[public-consensus] FreeBSD 11's `acpi_EnterSleepState` invokes
`power_suspend_early`, stops processes, invokes `power_suspend`, then
calls `acpi_sleep_machdep` with interrupts disabled. On return it calls
`acpi_wakeup_machdep` in the disabled-interrupt path and again after
restoring interrupts; after process resume it invokes `power_resume`.
The machine-dependent wake path calls `acpi_wakeup_cpus` before
`restart_cpus`. The ACPI sleep event handler requests the sleep state;
the base wake event handler is a no-op. The ACPI timer registers a
`power_suspend` callback and may register a `power_resume` callback.
See FreeBSD 11 [`acpi.c`](https://github.com/freebsd/freebsd-src/blob/releng/11.0/sys/dev/acpica/acpi.c),
[`acpi_wakeup.c`](https://github.com/freebsd/freebsd-src/blob/releng/11.0/sys/x86/acpica/acpi_wakeup.c),
and [`acpi_timer.c`](https://github.com/freebsd/freebsd-src/blob/releng/11.0/sys/dev/acpica/acpi_timer.c).

```text
power_suspend_early → stop_all_proc → power_suspend
  → acpi_sleep_machdep
  → acpi_wakeup_machdep (interrupts disabled; acpi_wakeup_cpus)
  → acpi_wakeup_machdep (interrupts enabled)
  → resume_all_proc → power_resume
```

[inference] Under this source model, `power_resume` is a late resume
marker: it occurs after `acpi_wakeup_cpus` and `resume_all_proc`. The
`power_suspend` callbacks are pre-sleep. Neither event name identifies
the early machine-dependent wake path by itself. Also, the named ACPI
`acpi_sleep_event` callback is a request route; the source does not show
that every platform's Rest Mode path enters through that event.

[inference] This gives a source-based ordering hypothesis for the PS5
names, not their 12.02 function addresses or proof that Sony retained
the same control flow. A 12.02 text cross-reference or trace showing a
different caller/order would falsify the model.

[public-consensus] Correction to the earlier firmware attribution:
`HOOK_ACPI_WAKEUP_MACHDEP` is used by the public loader's 3.00–4.51
`hv_defeat_0304` path. That code patches a call at `ktext + hook_offset`
to its kernel code cave. The 5.00+ offset entries mark this hook as
unused, and the 5.00–6.02 route uses a different mechanism. Thus the
previous claim that the `0x3A75E3`–`0x3A7613` values were 5.00–6.50
hook offsets was incorrect: those values belong to 4.50/4.51 and
4.00/4.02/4.03 entries in the public offset table. See the
[`hv_defeat_0304` call site](https://github.com/ps5-linux/ps5-linux-loader/blob/main/source/hv_defeat_0304.c#L10-L33)
and [firmware offset table](https://github.com/ps5-linux/ps5-linux-loader/blob/main/source/offsets.c#L101-L219),
which marks the field unused in the 5.00 profile ([`off_0500`](https://github.com/ps5-linux/ps5-linux-loader/blob/main/source/offsets.c#L2119-L2165)).

[inference] This older public hook supports the semantic placement of
`acpi_wakeup_machdep` in a resume path, but it does not locate the
function or a patch point on 12.02. The 12.02 strings above do not locate
code, and the separate pointers at ktext+0x396390 and ktext+0x3b3b60
were resolved as `pcib` and `pci` kobj methods. A same-firmware text
cross-reference would be needed to refine the 12.02 address.

## The public HV-defeat lineage (for context)

Three generations, all superseded on 5.00+ by our resume-window route:

1. **≤2.xx (embedded HV)**: flatz — disarm via kernel's
   `__hv_vm_area` → VMCB patch (clear NP, GMET, CR intercepts)
2. **3.00-4.51 (external HV)**: ps5-linux — TMR relax → VMCB patch
   via IOMMU physical writes → forced VMCB reload → kernel shellcode
3. **5.00-7.61**: IDT gate patching + IST ROP + APICBASE wrmsr trigger

Our route (12.02): `AcpiGbl_FACS` self-corruption (`kdata+0x2cb4c80`,
candidate) → `#GP` on resume → proposed gate/IST chain → HCALL 0x0f →
AP on root 0 → VMCB write. [verified-on-console] The 12.02 read-only
audit found vector 13 at IST0; the loader's IST6 is a chosen hook setup,
not that observed gate state. The #GP frame and return path remain unvalidated (`16`,
`11` #20). (The old `#DB`/`+0x18e` framing was the wrong trigger
*kind*; see `15` §1 and `11` #16.)

## Next research steps

**2026-10-13**: the route is public-working on 13.xx (Byepervisor-Reborn)
and the implementation phase moved to
[`16-byepervisor-12-02-port.md`](16-byepervisor-12-02-port.md) — the
field/gadget mapping onto our 12.02 holdings, our FACS #GP trigger
(no text-read dependency), and the phased plan. The r0gdb-stepping
launch chain is retired from the critical path.

1. Treat the FreeBSD 11 call order as a comparison model only; identify
   any PS5-specific divergence from same-firmware evidence.
2. To assign 12.02 text locations, obtain a reproducible same-firmware
   code cross-reference for the existing `.data` name anchors. The
   present data dump and cross-firmware offsets do not resolve one.
3. Keep any live validation separate from this static analysis; the
   repository's console-experiment policy requires explicit owner
   approval and a recovery plan before a risky probe.

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
| `11-debunked-theories-and-corrections.md` | Register of debunked theories + corrections |
| `12-acpi-static-anchor-corrections.md` | ACPI static-anchor corrections for this route (FACS, `+0x18e`, string scan) |
| `13-ring0-freeze-instrumentation.md` | Ring-0 freeze capture set + hypotheses + falsifiable test |
| `14-ring0-execution-alternatives.md` | Ring-0 execution alternatives to r0gdb |
| `evidence-logs/` | Raw protocol logs |

### NOOP: FACS wake vector (2026-10-12)

**CORRECTION (2026-10-13) — this NOOP is invalid; it tested the wrong
address.** The read at phys `0x9bf60` targeted the FADT's
`PM1a_EVT_BLK` field (`+0x40`), **not** the FACS. The FACS pointer is
`FIRMWARE_CTRL` at `+0x24` = phys **`0x7fd6e000`** (`X_FIRMWARE_CTRL`
at `+0x84` is 0); the dump's populated FADT confirms this. So the
all-zero read says nothing about a wake vector — it read a PM event
block. The FACS wake-vector lead is **untested, not dead**: one alias
read at `0x7fd6e000`+0x0C/0x18 is still required. See
`12-acpi-static-anchor-corrections.md` §1.

What remains a fair (weaker) conclusion: the PS5's resume control flow
is hypervisor-mediated, so a classic BIOS ACPI wake vector may not be
the entry point — but that is now `[inference]` pending the corrected
read, not a `[verified-on-console]` NOOP.

Alternatives for locating `acpi_sleep_machdep`:
1. The kobj table lead is resolved: ktext+0x396390 belongs to the
   `pcib` class and ktext+0x3b3b60 to the `pci` class, so these are not
   the ACPI sleep/resume callbacks. Continue from the power/ACPI call
   path anchors or other same-firmware evidence.
2. Cross-reference the `acpi_wakeup: failed to resume AP` string from
   same-firmware text when an attributable disassembly is available.
3. Compare the public loader's function identification against its
   documented firmware versions; do not transfer its text offsets to
   12.02 without an independent match.

### r0gdb stub "failures" — root cause: zombie port confusion (2026-10-12)

**Every observed stub death was connecting to a zombie process on a
previously-used port, not to the live stub.** Proven by stub_repro v7:
the COMPLETE r0gdb code (real dbg.c, real gdbstub_main_loop, real GDB
protocol) works perfectly when connected to the correct port:

```
connected to port 21000 → send '+' → handler fires → GDB responds:
+$T05#B9 (SIGTRAP stop reply)
```

**The debugging journey** (all ruled out or fixed):
1. ~~+48 mcontext offset~~ — correct for PS5 (verified by sigframe_dump)
2. ~~sysarch GS base = 0~~ — fixed (NO_SYSARCH_GSBASE + if(mc->mc_gsbase))
3. ~~SIGPIPE from stdout~~ — fixed (blocked in main)
4. ~~SIGTRAP sigaction~~ — works fine (proven by stub_repro v5)
5. ~~gdbstub_main_loop crash~~ — works (proven by stub_repro v7)
6. **Zombie port confusion** — the ACTUAL root cause

**Fixes retained** (all correct, even if not the root cause):
- SIGPIPE blocked in main (adapter)
- NO_SYSARCH_GSBASE compiled out for userland builds
- if(mc->mc_gsbase) defensive guard for ring-0 builds (other agent)

**NOOP addition**: connecting to zombie ports on 1234 while the live
stub is on a higher port produces ConnectionResetError that looks
exactly like a crash. Always verify the port is OUR process.

### Anti-zombie harness (v4 session client, 2026-10-12)

The r0gdb session client (v5) uses **computed** port discovery —
never a post-scan diff. Two on-console facts drive the design:

- The stub binds the **first free port scanning up from 1234**
  (the bind loop in `gdb_stub/dbg.c`), so the port a fresh payload
  *will* take is simply the first port >= 1234 that the pre-scan
  finds closed. [verified-on-console 2026-10-12]
- The stub takes exactly **one** `accept()` and reads one byte
  expecting `'+'`. A port-scan probe that connects-and-closes makes
  that read fail and the stub **silently exits**. The earlier v4
  design (pre-scan, send, post-scan, connect to the diff) would have
  killed its own stub with the post-scan. [verified-on-console
  2026-10-12 — the post-scan probe was eliminated before it could
  ever fire]

Stage 0 (full auto) is therefore: parallel pre-scan of 1234-1400
(closed ports drop SYNs, no RST — each miss costs the full connect
timeout, so the old sequential 1234-22000 scan was measured at >120s
with zero progress), compute the expected port, send the payload,
connect straight to it. Side effect: pre-scan probes do connect to
zombie ports; a zombie sitting in `accept()` exits on the probe.
Acceptable — zombies are stale.

Usage:

```sh
python3 r0gdb_session.py              # auto: send + computed port
python3 r0gdb_session.py --no-send    # manual: scan for live stub
python3 r0gdb_session.py --port 1234  # manual: known port
```

The CR4 read stage is now skipped (SMEP makes userland gadgets
fatal). CR4 requires a kernel-text `mov rax,cr4` gadget — which
requires a Phase-B text read, which requires the resume-window
chain. The dependency chain is now fully explicit.

### Graduated safety ladder for ring-0 work (2026-10-12)

Before any kernel-text single-stepping, run the three verification
levels in order (`tools/stub_verify*.py` in this repo — the
sanitized regression baselines; the working copies live in the lab):

| Level | Script | Tests | Risk | Status |
|---|---|---|---|---|
| 1 | stub_verify.py | Anti-zombie + connect + base + kdata + offsets + M write/read | Zero (userland only) | **PASSED on-console 2026-10-12** |
| 2 | stub_verify2.py | Level 1 + ring-0 entry + EFER read + restore + exit | Low | Written; first run pending owner review |
| 3 | stub_verify3.py | Level 2 + CR0 read + sanity check | Low | Written; first run pending |
| 4 | acpi probe | Level 3 + single-step from ACPI text anchors | Moderate | Blocked on levels 2-3 |

**Level 1 is the regression gate**: it must be green before any
ring-0 session. It validates the whole stub protocol against the
payload build with zero ring-0 risk, so payload or protocol drift
fails fast instead of hanging the console on a bad assumption.

#### Level 1 results (2026-10-12) [verified-on-console]

All five sub-tests green, three zombie ports (1234-1236, left by the
failed development runs) correctly skipped by computed discovery
(stub bound 1237):

- handshake `?` -> `T05`
- registers: fault rip = **base+0x4ef** (see the START_RIP_OFF
  correction below), rsp userland
- base verification: load base = **0x200000000**
- kdata_base = **0xffffffff85d10000** (per-boot KASLR — the check is
  the canonical-prefix test, not the value)
- M write/read/restore round-trip on payload memory

#### Two bugs found and fixed by the level-1 run (2026-10-12)

1. **`START_RIP_OFF = 0x4DF` was a D/E typo** — the real fault rip
   offset is **0x4EF** [verified-on-console: reading at
   `rip-0x4EF+0x228c0` returned exactly the ELF bytes at vaddr
   0x228c0, base landing page-aligned at 0x200000000]. Fixed in the
   session client and the ladder.
2. **The v4 post-scan diff design would kill the stub** (see the
   computed-port section above). Also the sequential 1234-22000
   pre-scan was unusably slow (>120s, zero progress — closed ports
   drop SYNs). Fixed: parallel 1234-1400 pre-scan + computed port.

#### The SMEP-fatal restore path, found and fixed (2026-10-12)

A second hardening round (the parallel agent, 21:03) caught a **fatal
flaw shared by the original level 2, level 3, and the session
client's stage G**: the restore path wrote `mov [rcx],rax`
(`488901`) into the payload's userland write slot
(`base+GADGET_WRITE_QWORD`) and single-stepped it **at CPL0** —
exactly the SMEP #PF panic mode live-confirmed on Oct 9 (the `0f20e0`
CR4 attempt: userland rip at CPL0 = panic). The restore path had
never been exercised on-console (the Oct 9 session parked before
reaching it), so the flaw was invisible until reviewed.

The fix, now in levels 2/3 and the session client (v5.1):
- restore ONLY through the kernel-text `store_rax_rdi` gadget from
  the firmware offset table (SMEP-safe; kernel text at CPL0 is fine)
- per-store `m` readback of every kernel write
- TSS restore writes every IST word **including zeros** (the old
  `if val:` skip would leave patched zeros live where the original
  value was zero)
- saved AND live IDT gates validated before any write (selector
  0x20, expected IST/attr per vector: 1:(4,0x8E), 6:(4,0x8E),
  9:(3,0xEE), 179:(6,0xEE), canonical kernel handlers)
- staged ABI-aligned return frame at entry; the exit must return to
  the exact original RIP/RSP, and the frame word is restored even on
  the park path
- operator gates (`--ring0`, `--verified-store-gadget`,
  `--recovery-plan-confirmed`) — levels 2/3 refuse BEFORE any payload
  is sent

#### The pinned-delta bug, found and fixed (2026-10-12)

The hardening round pinned the live offset deltas to the **13.60**
header values. Definitively wrong for this console: the payload
selects its table from the console's **live sysctl FW version**
(`offsets.c` `set_offsets()` dispatches `case 0x1202:
set_offsets_1202()`), and this console is 12.02 — so the live deltas
are the **12_02.h** values [cross-validated on-console 2026-10-09:
`rdmsr_start`/`mov_rax_cr0` from this table produced the sane
EFER (0x11d01)/CR0 (0x8005003b) reads]. The 13.60 pin would have made
level 2 refuse on a healthy console (safe direction, but blocking).
Corrected to the 12.02 pin before any live run:

| Offset | Pinned delta (kdata-relative, offsets/12_02.h) |
|---|---|
| rdmsr_start | −0xA9E10A |
| mov_rax_cr0 | −0xAA3C61 |
| store_rax_rdi | −0xAA3EEE |
| tss_array | +0x2E8AFE0 |
| idt | +0x2E88300 |

All of levels 2/3 and the session client v5.1 remain **pending live
validation** — the next console window runs level 2 (gated), then
level 3, before any real session work.

#### Level 2 first live run (2026-10-12, evening) — partial pass, then a console death

What validated green before the incident [verified-on-console]:

- Level 1 green twice more (base 0x200000000, kdata
  0xffffffff85d10000 — the console was NOT restarted; the same boot
  as the afternoon runs)
- The **corrected 12.02 pin passed live** (rdmsr_start −0xa9e10a,
  store_rax_rdi −0xaa3eee, tss_array +0x2e8afe0, idt +0x2e88300) —
  definitive on-console disproof of the original 13.60 pin, which
  would have refused right there
- Staged return frame written + read back (the live readback also
  caught and fixed a client bug: `read_mem` misparsed any reply
  starting `E…` as a GDB error — valid data like the little-endian
  `0x00000002000004EF` → `EF04000002000000` — the stub never sends
  E-replies for `m`; fixed to length-only validation)
- **Ring-0 entry via the staged frame: VALIDATED LIVE** — `c` → OK →
  T05 synthetic stop with kernel rsp `0xffffff801ff4c838`. The
  hardened entry design works on-console.

Then the freeze, root-caused by reading `dbg.c`/`r0gdb.c`
[verified-in-tree]:

1. `r0gdb_loop` held `in_signal_handler` across the entire blocking
   packet session.
2. each incoming byte used its own blocking `read()`; a `G` write
   required **337 consecutive single-byte reads**.
3. installed process-wide signal handlers spun on the same flag.
4. a signal delivered to the session-owning thread during the `G`
   window could enter the handler, which waited on a flag held by the
   interrupted loop. The loop could not resume until the handler
   returned, producing the observed freeze. This causal explanation
   is [inference]; it would be falsified if a trace showed the freeze
   occurred outside the handler/lock wait.

The source repair is now present [verified-in-tree] in the canonical
`r0gdb/` tree. The shared signal mask and lock implementation are in
`r0gdb/gdb_stub/dbg.c:1387-1470`; callers are in `dbg.c:1155-1188`,
`r0gdb/gdb_stub/ring0.c:170-181`, and
`r0gdb/prosper0gdb/r0gdb.c:468-480`. These callers block the debugger
signals on the owning thread before acquiring the shared flag, then
release the flag before restoring the prior signal mask. This prevents
the handler from interrupting a thread that owns the session lock;
handlers also mask the debugger signal set and use `SA_RESTART`
(`dbg.c:1403`, `dbg.c:1475`, `r0gdb/prosper0gdb/r0gdb.c:900`). The RSP
reader at `dbg.c:75-160` buffers socket bytes, assembles and checksums
a bounded whole packet before dispatch, and uses the same buffer for
outgoing ACK reads so read-ahead preserves subsequent protocol bytes.
Transport failure exits the session parser (`dbg.c:662-668`); the
signal-handler and ring-0 mailbox paths leave their original register
snapshots intact (`dbg.c:1108-1110`, `ring0.c:177-181`), and
`r0gdb_loop` does not run stale state (`r0gdb.c:472-480`).

This repair was built and run on-console 2026-10-13 (build
`cbd34cbd…`): the ring-0 entry succeeded but the freeze **recurred**,
so this repair is necessary-but-not-sufficient for the freeze — see the
"GS-base freeze theory: FALSIFIED" subsection below, which shows the
freeze's hypothesized GS-clobber link does not hold on this console.
The level-2 restore phase and full ring-0 sessions remain gated. The
Oct 9 "stub death" may share this cause, but remains an [inference]
without a captured trace.

#### What Oct 9 proved at ring-0 [verified-on-console]

The preserved protocol log (`session_protocol.log`, archived
entries) of the 2026-10-09 session shows the full ring-0 machinery
working before the CR4 attempt ended it:

- ring-0 **entry** (IDT/TSS patch + the int179 trampoline): worked;
  ring-0 confirmed by kernel-stack rsp
- **`rdmsr_start`** (kernel text) stepped at CPL0: EFER = `0x11d01`
- **`mov_rax_cr0`** (kernel text) stepped at CPL0: CR0 = `0x8005003b`
- then the CR4 attempt wrote a `mov rax,cr4` gadget (`0f 20 e0`)
  into the payload's **userland** memory and stepped it at CPL0 →
  SMEP `#PF` (vector 14, not gated by the stub) → **console panic →
  power cycle**. This is the live confirmation of CR4.SMEP=1 and the
  origin of the kernel-text-only rule for ring-0 rip targets.

Two distinct failure classes are on record — do not conflate them
(an earlier version of this account did):

- **Oct 9**: the panic was immediate, **during** the step — a SMEP
  `#PF` on a userland rip at CPL0; the OS died mid-instruction
  [verified-on-console].
- **2026-10-12**: the freeze was **before any step** — the
  signal-handler spin deadlock during packet processing
  [verified-on-dump of the payload sources]; the console survived
  until the `timeout` wrapper closed the socket over the patched
  state.

For level 2 this means: the entry, the trampoline, and kernel-text
gadget **stepping** are proven on-console; the unproven pieces are
the `store_rax_rdi` **write** gadget specifically (the two proven
gadgets are reads), the full restore sequence, the verified return,
and the #60/#62 stub changes at ring-0.

#### Stub-side cleanup after disconnect

The automatic cleanup path is now wired in source [verified-in-tree].
`r0gdb_loop()` exits on normal `r0gdb_exit` or parser/transport
failure; `r0gdb()` then calls `r0gdb_cleanup()` before returning
(`r0gdb/prosper0gdb/r0gdb.c:540-549`). The checked cleanup restores
each TSS IST field before restoring the patched IDT gates, verifies
those values through `copyout()`, and clears its initialized state
only after the checks pass (`r0gdb/prosper0gdb/r0gdb.c:427-537`). It
also applies and verifies the existing IA32_FMASK setting through
RDMSR/WRMSR helpers using `run_in_kernel()`.

If a transfer or readback check fails, the cleanup routine keeps the
payload mapped by parking in userland rather than returning while an
IDT target may still point into the payload [verified-in-tree]. In
this source tree, `copyin()` and `copyout()` are not `sysarch` calls:
they configure pipe-based kernel access through `kwrite20()` and then
use pipe `read()`/`write()` (`r0gdb/prosper0gdb/r0gdb.c:173-197`).

This is a source-level repair, not a demonstrated safety result. If
the complete cleanup returns successfully, a debugger-client
disconnect should reduce the stale-gate exposure to the cleanup
interval [inference]. This does not cover forced termination of the
stub process, a fault that prevents the cleanup routine from returning,
power loss during cleanup, or a setup failure before the initialized
state is recorded. The SDK payload cross-build passed after syncing the
canonical source into the lab build tree; it emitted pointer-sign
warnings from the existing GDB packet-formatting code and a GNU-stack
note for `r0run.o`. No console run was performed. Validate this path
through the graduated ladder before shortening parked-session timeouts
or treating client termination as safe.

Operational lesson (also live): the parked script must hold its
socket open indefinitely — running gated ring-0 scripts under
`timeout N` kills the park and closes the socket over the
un-restored IDT/TSS state. That is what killed the console tonight
(ARP failed; owner power cycle required). Never wrap these scripts
in a timeout.

**Stub source maintenance moved in-repo (2026-10-12)**: the
`gdb_stub/` + `prosper0gdb/` sources are now canonically maintained
in this repo under [`r0gdb/`](../r0gdb/) (the lab payload tree is the
build sandbox only — edit here, sync, build there). The deadlock fix
above is implemented in the canonical source tree for review,
replacing the unversioned mtime-archaeology workflow that made
tonight's edits invisible.

**The session clients are also canonical in-repo (2026-10-12,
owner-directed)**: `tools/stub_verify*.py` and
`tools/r0gdb_session.py` are the only editable copies; the lab
payload directory keeps no duplicates (it remains the operational
sandbox: build tree, binaries, protocol logs, and a private `env.sh`
exporting `PS5_HOST` / `R0GDB_ELF` / `R0GDB_SEND_ELF` /
`R0GDB_LOG`). Clients run from the repo.

Unrelated transient during the same window: four stub ports
(1234–1237) opened and died on their own around the failed level-1
attempt, with no sends from any agent — attributed to console-side
supervision churn while the afternoon zombie processes expired; not
reproducible and not blocking.

#### GS-base freeze theory: FALSIFIED on-console (2026-10-13)

After the 2026-10-12 evening incident, a root-cause theory was proposed
for the ring-0 freeze: the PS5's signal frame carries `mc_gsbase=0`; the
ring-0 entry passes through the kernel's sigreturn; if that restore
clobbers the thread's GS base, the SDK libc's errno-TLS access faults at
the first failing syscall (~100–250 ms in), and the nested SIGSEGV met
the still-spinning handler, freezing the session and holding the patched
IDT/TSS window open. Fix #70 implemented two parts: (a) save the
boot-time GS base via `SYS_sysarch AMD64_GET_GSBASE` in `r0gdb_init()`
and restore it as `r0gdb()`'s first action
(`r0gdb/prosper0gdb/r0gdb.c:573-620, 1857`); (b) make `signal_handler`
never spin when the flag is held (non-fault signals dropped; fault
signals park on a raw `nanosleep` loop, `dbg.c:1093-1120`).

Instrumentation was added to test it against evidence instead of
inference [verified-in-tree]: the stub captures the fault `ucontext` it
is delivered on (`gdb_stub/dbg.c:1128-1134`) and exposes it via a
non-invasive `qDiagF4` query (`dbg.c:856-884`); the clients decode it
with a self-locating `__mcontext` scanner (`tools/stub_verify.py`
`analyze_fault_frame` / `--diag-f4`; `tools/experiment_exit.py` prints the
entry-frame verdict). New build sha `cbd34cbd…`; level 1 re-run green
(base `0x200000000`, kdata `0xffffffff8b150000`).

On-console result (2026-10-13, experiment 1 on the #70 build)
[verified-on-console]:

- Entry worked: synthetic stop with kernel-stack `rsp=0xffffff801aee4838`
- The captured entry fault frame decoded to `mc_flags=0x5`,
  `mc_fsbase=0x0`, `mc_gsbase=0x0`, `cs=0x33`, `ss=0x2b`
- `mc_flags=0x5` = `_MC_HASSEGS` (0x1) set, **`_MC_HASBASES` (0x2)
  clear**. FreeBSD `set_mcontext` (`machine/ucontext.h`) only restores
  `mc_fsbase`/`mc_gsbase` when `_MC_HASBASES` is set, so the ring-0
  entry's sigreturn does **not** clobber the GS base from `mc_gsbase=0`
- Therefore the GS-clobber link is **falsified**, and since
  `fsbase==gsbase==0` the "wrong TLS register" variant is moot
- **The freeze still occurred** on the same run: the packet after the
  synthetic-stop `g` got no reply and the client parked (~131 s). Freeze
  signature identical to the 2026-10-12 runs; #70 did not fix it

Two consequences: (1) fix #70(a) (GS restore) targets a mechanism that
does not fire on this path — inert; (2) fix #70(b) converts the handler's
busy-spin into a park, which is client-indistinguishable from the old
spin (both hang the session) and may mask the true fault by sleeping
through it. The real freeze is a genuine hang that is neither the GS→TLS
chain nor the busy-spin, and remains **unexplained**. Prime remaining
suspects: a lock/mailbox deadlock in the ring-0 session path itself (the
`gdbstub_session_lock` flag interaction when packets are served from the
entry handler context), or `r0gdb_cleanup()`'s `run_in_kernel` MSR step.
Next instrument: a handler-entry counter + park counter (F4 extension) to
determine whether a nested signal occurs at the freeze point or the hang
is a plain packet-read deadlock.
