# PS5 kernel research — FW 12.02

## CURRENT FOCUS: the resume-window HV bug (HCALL 0x0f) — sole active route

**As of 2026-10-12, this lab is working on exactly one thing**: the
HCALL 0x0f (`khv_startup_mp`) resume-window AP launch — a boundary
crossing from compromised-kernel context to a root-0 (host-view) AP
that can write the VMCB pages, giving full NPT control. All other
routes (QA-flags text read, GPUVM DMA, CR4 gadget hunting, TMR) are
**superseded** or **deprioritized** — see the NOOP catalog.

**Start here**: [`docs/10-hcall-resume-window-and-noops.md`](docs/10-hcall-resume-window-and-noops.md)
— the complete current state: the ABI, the launch chain, what's
verified, what's hypothesis, what's dead, and what's next.

## The route in one paragraph

The PS5 hypervisor's HCALL 0x0f launches an application processor with
a guest-supplied RIP and CR3. During the resume-from-rest window
(after `resumectx`, before `acpi_wakeup_cpus`), the one-shot bitmap
reopens and the launched AP runs on NPT root 0 (the host view) —
kernel text readable, NPT protections absent. From root 0, writing
`NESTED_CR3` on any VMCB redirects that core's nested page table
root. This supersedes every text-read route previously pursued.

## Document map

| Document | Status | Contents |
|---|---|---|
| [`10-hcall-resume-window-and-noops.md`](docs/10-hcall-resume-window-and-noops.md) | **★ ACTIVE** | The resume-window route + the NOOP catalog |
| [`09-live-kernel-state-and-fsgsbase.md`](docs/09-live-kernel-state-and-fsgsbase.md) | Active (reference) | Live kernel state (EFER/CR0/CR4), FSGSBASE analysis, HV lineage |
| [`07-evidence.md`](docs/07-evidence.md) | Active (log) | Chronological evidence log (PRs #37-#49) |
| [`08-phaseb-inventory.md`](docs/08-phaseb-inventory.md) | **SUPERSEDED** | Phase B text-read inventory (QA flags, GPUVM — no longer the route) |
| [`04-route-1202.md`](docs/04-route-1202.md) | **SUPERSEDED** | Original Phase A/B research program |
| [`01-primitives.md`](docs/01-primitives.md) | Reference | Kernel R/W primitives inventory |
| [`02-xom-npt.md`](docs/02-xom-npt.md) | Reference | XOM/NPT protection model |
| [`03-evolution-pre761.md`](docs/03-evolution-pre761.md) | Reference | HV evolution through 7.61 |
| [`05-toolchain-and-observability.md`](docs/05-toolchain-and-observability.md) | Reference | Toolchain notes |
| [`06-sources.md`](docs/06-sources.md) | Reference | Source catalog |
| [`evidence-logs/`](docs/evidence-logs/) | Archive | Raw protocol logs |

## Quick facts (unchanged)

| Item | Value |
|---|---|
| Console | Owned PS5, FW 12.02 (0x12020000) |
| Kernel | FreeBSD 11-based, 8-core Zen 2 (CPUID family 0x17 model 0x48) |
| Hypervisor | External ("HyLonome"), 3.00.00.33+ |
| kdata base | Per-boot KASLR (e.g. 0xffffffff89210000 at dump time) |
| ktext base | Per-boot (e.g. 0xffffffff884c0000) |
| dmap base | Per-boot randomized (e.g. 0xffff89a100000000) |
| RAM | 16.595 GiB total (11.848 shared + 4.747 system) |
| SMEP | **Set** (CR4 bit 20) [verified-on-console] |
| SMAP | Unknown (bit 21) |
| CR4.FSGSBASE | **Clear** (rdfsbase #UD) [verified-on-console] |
| EFER.SVME | **Set** (kernel runs SVM virtualization) [verified-on-console] |
| VMCB intercept at runtime | **VMMCALL clear** (userland hcalls impossible) [verified-on-console] |

Findings only. No Sony proprietary code, no kernel dumps, no Ghidra
databases — links and knowledge, never payload material (see
`AGENTS.md`).

Started 2026-10-08 from a consolidation session over the local lab
(`homebrew_ps5`, `ps5debug-NG`, `prospero-win`, `payloads/`) and public
scene sources. Pivoted to the resume-window route 2026-10-12.
