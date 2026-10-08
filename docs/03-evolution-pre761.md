# 03 — Evolution: how the pre-8.00 world defeated NPT (ps5-linux-loader)

Reference: https://github.com/ps5-linux/ps5-linux-loader
(files read 2026-10-08: `source/main.c`, `source/prepare_resume.c`,
`source/utils.c`, `source/hv_defeat_0304.c`, `source/hv_defeat_0506.c`,
`source/hv_defeat_0607.c`, `shellcode_0607/main.c`,
`shellcode_kernel/main.c`).

## Correction of a naive model

A first-pass reading suggests "XOM was guest-PTE-level on old FWs and
moved to NPT later." That is **wrong**. The loader documents that
second-level enforcement existed from the beginning; what changed per FW
family was only the *route used to reach and defeat it*:

| FW | NPT-defeat route |
|---|---|
| 3.x–4.x | `stage1_tmr_relax` — reconfigure hardware TMR range registers to permissive; `stage2` — **IOMMU arbitrary physical write** zeroes `NESTED_CTRL` (VMCB+0x90) on all 16 cores; `stage3` — `vmmcall` per core forces VMCB reload. Then `.text` is kwrite-able (code cave + `hook_call_near` patches a `call` in .text). |
| 5.x–6.x | IOMMU route closed → ROP chain abuses the kernel's legitimate **`hv_unmap_pt_tmr` hypercall** with an attacker-computed `tmr_id` (the HV's own TMR bookkeeping entry corresponding to the VMCB page: `hvm_shm + tmr_id*0x18 + 0x298 == vmcb0 + vcpu*0x2000 + 0x90`) so the HV itself drops the protection on the VMCB physical page; then `NESTED_CTRL` on all 16 VMCBs is written **through the kernel direct map** (`pa_to_dmap`, VMCBs at low physical `0x62a08000+core*0x2000`). |
| 6.50–7.61 | dmap/hypercall routes closed → **full HV entry**: IDT #GP gate + TSS IST6 rewired (kernel data), a corrupted `AcpiSetFirmwareWakingVector` FACS pointer guarantees a #GP on suspend→resume, the IST ROP chain memcpy's a shellcode to physical 0 and does `wrmsr(MSR_APICBASE, hv_stack|ENABLED|BSP)` — the APICBASE-MSR stack hijack that runs the shellcode **inside the HV (host context)**; it walks the HV's own page tables (`hv_pml4`, per-FW hardcoded), finds all 16 VMCBs via `g_vm_tab`, clears `NP_ENABLE` per CPU, restores APIC/GS base, and jumps to `hv_reenter_hypercore` — the HV keeps running with NPT off for every vCPU. |
| 8.00+ | **no route exists in the repo** |

After any of these, the loader's earlier `remove_xotext()` (guest-PTE
RW/XO clear over the whole text range) becomes sufficient: with NPT off,
guest PTEs are the only translation, and `.text` is readable *and*
writable through ordinary kernel memory access (the resume-time
`shellcode_kernel` patches kernel CFI `0xC3` in `.text`).

## Epistemic status of "the routes died at 8.00+"

- **[verified-in-tree]** Sony iterated hardening *per family* — three
  different defeat routes in ~4 years, each closing the previous. The
  arms race is continuous; it did not start at 8.00.
- **[weak evidence]** The loader's ceiling at 7.61 — absence of an
  `hv_defeat_8xxx` is consistent with "the MSR/HV-entry route died" but a
  repo going unmaintained looks identical.
- **[inference]** Our 12.02 stack's architecture (kstuff gadget chains,
  ring-3 UELF, data-flag-only patches, nobody writing text anywhere)
  behaves exactly like a world where text writes and HV entry are both
  dead — that expensive machinery would never exist otherwise.
- **[public-consensus]** PS5 Developer wiki describes current-design
  NPT-enforced XOM.
- What we do **not** have: a dated changelog of which route closed on
  which FW. "Post-7.61" as a boundary is inference from the repo's
  ceiling, not a measured transition.

## Why the guest-PTE XO layer exists at all

It is essentially free (FreeBSD-native exec-only mappings) and stops the
*previous rung* of the attack ladder: kernel *read* primitives (the
classic browser-exploit outcome) cannot dump `.text`. Defense-in-depth
where the cheap layer blocks the cheap attack and the expensive layers
(TMR/NPT/VMCB placement) are the actual escalation fight.

## Consequences for kernel-image knowledge

- On ≤ 7.61, after the family-appropriate defeat, `.text` was fully
  dumpable and patchable — a byproduct of the NPT-off state, not a quiet
  passive read. Text-patching HENs were the norm, exactly like PS4.
- That is where offline decrypted kernel images and Ghidra DBs for old
  FWs come from. On modern FWs (ours), `.text` is undumpable at runtime,
  so symbol knowledge must come from:
  1. **kernel `.data` dumps** — dumpable on *any* FW with kernel R/W
     (sleirsgoevy's `porting_tool` dumps ~134 MB of kdata and derives
     rootvnode/IDT/GDT/TSS/allproc from structural signatures). Fully
     reproducible with our own primitives on 12.02.
  2. **published per-FW offset tables** — the distillation of the
     private dumps (ps5-payload-sdk switch, kstuff layouts, ps5debug-NG
     kpatch table, Specter's offset documents, ps5-linux-loader
     `offsets.c`).
  3. **private scene channels** — text dumps and Ghidra DBs circulate
     among researchers (Discords linked from kstuff / ps5debug-NG /
     ShadowMountPlus); never public, Sony proprietary code.
  4. **FreeBSD 11 source** — the structural oracle the published offsets
     were sanity-checked against.

See `06-sources.md` for links.
