# Live kernel state and the FSGSBASE path (2026-10-09)

Consolidated findings from the 2026-10-09 sessions (userland FSGSBASE
probes, prosper0gdb bring-up, ring-0 sessions #1-2). Full chronological
record in `07-evidence.md` (PRs #37-#41).

## Live control/MSR state [verified-on-console]

Read at ring-0 via the r0gdb single-step machinery (kernel-text gadget
RIPs, one instruction per round, full register capture):

- **EFER = `0x11d01`** = SCE|LME|LMA|NXE|**SVME**
  - Bit 16 (SVME) is set: **the PS5 kernel itself runs SVM
    virtualization** — consistent with the `vm#0`/`vm#1` tags on every
    app EXEC log line: the per-app sandboxes are SVM VMs.
- **CR0 = `0x8005003b`** = PE|MP|TS|ET|NE|WP|AM|PG
  - TS set on the stepped CPU (lazy-FPU state; passes kstuff's
    `is_sane_cr0`: known bits `0xe005003f`, required `0x80000001`)
- **CR4.SMEP = 1** — derived: a one-instruction gadget pointed at a
  USER page (the payload's own RWE segment) faulted at CPL0 with no
  trap return (#PF, vector 14, not gated by the stub → kernel panic),
  while the identical mechanism against kernel text executed
  perfectly in the same session. Instruction fetch at CPL0 from a
  user page = SMEP violation ⇒ SMEP set (SMEP is CR4 bit 20 per
  SDM/ps5-wiki; the earlier dump-scan labeled SMEP/SMAP as bits 7/8
  — those are PGE/PSE-adjacent — so the pre-live `0x45da0`
  "SMEP|SMAP|OSXSAVE" interpretation is retracted: that value decodes
  as PAE|PGE|OSXMMEXCPT|UMIP|OSXSAVE plus reserved bits, and was
  boot-specific garbage anyway, per the later live read of `0x1dec`
  there. The behavioral SMEP proof stands regardless.)
- **CR4.FSGSBASE = 0** — userland `rdfsbase`/`rdgsbase` raise #UD
  while CPUID.7.0:EBX[0]=1 (Zen 2 hardware supports it)
- Remaining CR4 bits: unknown until the kernel-text gadget read
  (below)

## prospero-win baseline [verified-on-console]

- `sysarch(AMD64_GET_FSBASE)` returns 0 (success; FS base readable),
  and the SET path is functional — games run on it today. The FSGSBASE
  enable is purely a performance change (syscall → userland
  instruction) for TLS switching, not a functional one.

## FreeBSD 11 kernel-side FSGSBASE machinery [public-consensus + our offsets triangulation]

The FreeBSD 11 tree in the lab clone knows FSGSBASE end-to-end:

- `initializecpu()` (`initcpu.c:219-256`): at boot,
  `if (cpu_stdext_feature & CPUID_STDEXT_FSGSBASE) cr4 |= CR4_FSGSBASE`
- `set_pcb_flags()` (`machdep.c:2620-2645`): the pcb-save machinery
  that makes userland `wrfsbase` survive context switches
  (`pcb->pcb_fsbase = rdfsbase()` on PCB_FULL_IRET) is gated on the
  **same single kernel data global**
- `cpu_switch.S:106-121`: the switch path saves pcb_fsbase/pcb_gsbase
  via `rdfsbase`/`rdmsr(MSR_KGSBASE)` when the flag is set;
  `exception.S:473-495` handles the user-gsbase return paths

**Key insight**: if Sony's kernel retains this machinery, then after
setting CR4.FSGSBASE, setting bit 0 in the kernel's
`cpu_stdext_feature` global — a plain kernel data write, our proven
class — activates the entire save/restore machinery, making userland
`wrfsbase` coherent across context switches. The flag's runtime
address is not yet identified (see the CPUID cluster below).

## The kernel CPUID cluster [verified-on-dump]

At kdata+`0x2e61f60` in our 134 MiB alias dump (values are
CPUID-derived; PS5 APU):

| offset | value | identification |
|---|---|---|
| +0x2e61f60 | `0x078bfbff` | `cpu_feature` (CPUID.1.EDX, HTT clear) |
| +0x2e61f64 | `0x00000010` | `cpu_high` (Zen 2 max basic leaf = 0x10) |
| +0x2e61f68 | `0x00001022` | adjacent dword (unidentified) |
| +0x2e61f6c | `0x00006799` | **NOT `cpu_stdext_feature`**: has bits 4/13/14 (HLE/MPX-class, Intel-only) and bit 10 (INVPCID, absent on Zen 2) — a mask cannot set bits the CPU does not report. Possibly a Sony-specific feature bitmap with Sony bit semantics. Identification unresolved. |
| +0x2e61f70 | `0x00840f81` | `cpu_id` = CPUID.1.EAX: family 0x17, model 0x48, stepping 1 — **the PS5 APU signature** |
| +0x2e61f78 | `0x80000020` | `cpu_exthigh` |
| +0x2e61f7c | `0xf5c2b7ff` | `amd_feature` (with 3DNow-class bits — HV-virtualized CPUID or non-CPUID semantics) |
| +0x2e61f80 | `0x0000700f` | `amd_feature2` |

The dump's earlier CR4-shaped candidates (e.g. `0x45da0` at
kdata+0x21bf828/30) were **boot-specific** — live reads on a later
boot showed `0x1dec` there; never assume dump values for these
unidentified globals across boots.

## sysent table [verified-on-dump, confirmed live on 3 boots]

- PS5 12.02 `sysent`: **stride 48, `sy_call` at +8**, table at
  kdata+`0x1af4d0`
- Verified against every anchor in our alias dump
  (`payloads/kalias_sweep/runs/sysent_anchors.txt`, 746 entries)
- `sysent[165].sy_call` (sysarch) at kdata−`0xa3c878` — live-confirmed
  on three different boots (the r0gdb payload's D7 self-check)

## The r0gdb capability (what we can now do at will) [verified-on-console]

- Execute **any kernel-text instruction** with fully controlled
  registers, one instruction per round, capturing the full register
  file afterwards: `rdmsr` (any MSR), `mov rax, cr0` (CR0), and every
  gadget in kstuff's 12.02 table (~90 verified text addresses)
- The full working stack is documented in
  `payloads/prosper0gdb_elfldr/README.md` (elfldr payload recipe,
  session client, protocol facts, park rules)
- **Constraint**: gadget RIPs must be kernel text. CPL0 execution of
  userland pages (even RWE ones) is a guaranteed console panic
  (SMEP). This also kills any "write own code to kernel-heap/user
  pages and execute" plan unless SMEP is first cleared — which itself
  needs a kernel-text CR4 gadget.

## The missing piece and the Phase-B redirect

Reading (and later writing) CR4 requires kernel-text gadget
addresses: `mov rax, cr4` (`0f 20 e0`) / `mov cr4, rax`
(`0f 22 e0`). Kernel text is XOM for every reader we have, so the
prerequisite is a **Phase-B text read**:

1. **qa_probe v2 → rest cycle → qa_check v2** (the A1 QA-flags chain:
   HV builds text pages RW without xotext → text readable → byte-scan
   for the CR4 gadgets) — now the prioritized next console phase
2. or **gpuvm_read v3** (PDB2 scan → retarget to .text → PM4 DMA)

Both are built, gated, and staged. After the text read, the ring-0
machinery becomes the CR4 read/write engine, and the FSGSBASE enable
is: read CR4 → write CR4|`0x10000` (owner-gated) → identify and set
`cpu_stdext_feature` bit 0 → live `rdfsbase` test → prospero-win
native TLS switching.

## 2026-10-12 — Public HV-defeat lineage survey (the E1 ABI verdict + the TMR layer)

### The raw hcall ABI: NOT publicly established [public-consensus: absence]

Per the owner's discipline (verify the 0x00 handler and ABI from
available evidence before any launch), the survey result is negative:

- ps5-wiki: hcall **names only** ("little information is known beyond
  the call names"); no ABI, no GET_MESSAGE_CONF semantics
- Byepervisor (≤2.xx): reuses the kernel's own wrapper gadget
  (`VMMCALL_HV_SET_CPUID_PS4` at kernel-text addresses) — the raw
  convention stays inside the wrappers
- flatz's HV exploit gist (HvExploit.java, the "Prosperous" lineage)
  and ps5-linux/ps5-linux-loader (3.00–7.61): **no raw hcalls at all**
  — both defeat the HV via memory/VMCB manipulation, never by calling
  it. E1 stays **held**: no guess-launches.

### The three public HV-defeat generations [public-consensus]

1. **≤2.xx (embedded HV)** — flatz's gist: TMR relax + disarm via the
   kernel's exported `__hv_vm_area` (vcpu_t array → vmcb_va → VMCB
   physical) → patch the VMCB control area: NP_CTRL (clear NP enable +
   GMET enable), CR intercepts = 0, general1 cleared (keep CPUID),
   general2 → 0xF (keep VMRUN/VMMCALL/VMLOAD/VMSAVE)
2. **3.00–4.51 (external HV "HyLonome")** — ps5-linux hv_defeat_0304:
   stage1 TMR relax (regions 5/16/17/18 → permissive via the D18F2
   index/data ports), stage2 VMCB patch via IOMMU physical writes
   (VMCB bases hardcoded per FW: 0x6290B000 / 0x62A05000 + core*0x3000),
   stage3 forced VMCB reload per core (exception-safe VMMCALL harness:
   SIGILL handler + setjmp + pin-to-core — the exact pattern for E1),
   then kernel shellcode in a code cave + a `HOOK_ACPI_WAKEUP_MACHDEP`
   call-near hook into the resume path
3. **5.00–7.61 (TMR/VMCB patched)** — hv_defeat_0506/0607: IDT gate
   patching + ROP chains on the HV's per-CPU IST stacks + the APICBASE
   wrmsr trigger (the 7.61 APICBASE validator — already modeled in our
   emulator), IPIs between vcpus, GMET bit in NP_CTRL

### The TMR layer (new mechanism for our model) [public-consensus]

The memory protections are three layers: NPT (per-root), **TMR —
Trusted Memory Region, a HARDWARE protection with per-fabric
source-access-enable bits (SMU/PIE/CCM/GFX/NCM/IOM)** configured via
PCI D18F2x80/x84 (index/data port) MMIO, and XOM. The kernel text and
the HV region each have a TMR region; ctl=0 + all SAE bits + WE/CE/V
disarms one. **"TMR based HV exploit is patched on 5.00"** (flatz) —
but the registers remain the protection mechanism, so reading the TMR
table on 12.02 is free intel and writing it is a testable question.

### The HV physical layout (per-FW drift, 0x62x physical) [public-consensus]

VMCB bases: 3.00 0x6290B000+core*0x3000; 4.x 0x62A05000+core*0x3000;
5.x 0x62a08000+core*0x2000; 6.00-6.02 0x62a57000+core*0x2000;
6.50/7.x hv_stack 0x628d0000 / 0x628ec000. hv_shm: 0x62a01000 (5.x),
0x62a22000 (6.00-6.02). Our emulator's "HV-own physical regions"
(NPT-denied) align with this band. The 12.02 equivalents are unknown —
findable via our GPUVM/PM4 route into the 0x62 band.

### E-TMR: risk correction (owner challenge accepted)

The initial "zero crash risk" claim was WRONG. Retracted. The honest
risk analysis:

1. **The NPT governs the kernel too.** The question is not whether a
   TMR register read is semantically harmless — it is whether the
   GUEST (kernel included) is permitted to touch that physical page
   on 12.02. A kernel load from an NPT-denied page = kernel #PF =
   panic. Nothing about the read being "just a config read" protects
   against this.
2. **Device MMIO is on our own measured never-pipe list** — the
   boundary knowledge from the six console crashes explicitly lists
   device MMIO among the pipe primitive's panic classes. The TMR
   index/data ports ARE device MMIO (D18F2 PCI config). The proposal
   violated our own lab rule.
3. **The 5.00+ patch's most plausible form is exactly this denial** —
   Sony patched the TMR exploit on 5.00; NPT-denying the guest's
   access to the D18F2 config alias is the natural patch, in which
   case the kernel read faults on sight.
4. **Dmap layout drift** — the dmap alias of the config region is a
   <=4.51 fact; on 12.02 the VA may simply be unmapped → the
   measured unmapped-panic class.
5. **No public datasheet for the Sony-custom TMR registers** —
   read side effects are not provably absent.

Corrected ladder for E-TMR:

- **E-TMR-1 (genuinely safe)**: walk the kernel page tables (kernel
  data, proven class) for the PCI-config dmap alias region — does a
  mapping exist on 12.02, at which VA, pointing at which physical
  address, with which PTE attributes (M/PAT bits would even confirm
  it is MMIO-typed). No MMIO access occurs.
- **E-TMR-2**: only if an alias exists — validate the underlying
  physical page with the established oracle methodology (the
  anchor_read discipline: 146 pages, 0 faults) BEFORE any read.
- **E-TMR-3**: if the page is NPT-denied, no guest-side reader can
  read it at all — the question moves to the GPUVM/PM4 route or a
  root-0 execution, not to a riskier pipe attempt.
