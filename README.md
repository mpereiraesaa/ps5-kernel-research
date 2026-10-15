# PS5 kernel research — FW 12.02

## CURRENT FOCUS: the resume-window HV bug (HCALL 0x0f) — sole active route

**As of 2026-10-13, this lab is working on exactly one thing**: the
HCALL 0x0f (`khv_startup_mp`) resume-window AP launch — a boundary
crossing from compromised-kernel context to a root-0 (host-view) AP
that disables nested paging on all 16 VMCBs. The route is now
**public-working on 13.xx** (Byepervisor-Reborn, 2026-10) and we are
porting it to 12.02 — see
[`docs/16-byepervisor-12-02-port.md`](docs/16-byepervisor-12-02-port.md)
(the port plan: the field/gadget mapping, our FACS #GP trigger, the
phases). All other routes (QA-flags text read, GPUVM DMA, CR4 gadget
hunting, TMR, the r0gdb-stepping launch chain) are **superseded** or
**deprioritized** — see the NOOP catalog in
[`docs/10-hcall-resume-window-and-noops.md`](docs/10-hcall-resume-window-and-noops.md).

## The route in one paragraph

The PS5 hypervisor's HCALL 0x0f launches an application processor with
a guest-supplied RIP and CR3. During the resume-from-rest window
(after `resumectx`, before `acpi_wakeup_cpus`), the one-shot bitmap
reopens and the launched AP runs on NPT root 0 (the host view) —
kernel text readable, NPT protections absent. From root 0, the AP
disables nested paging on every VMCB (clear bit 0 of NESTED_CTRL +
force a VMCB reload), so post-resume the guest runs on the host page
tables: kernel .text readable and writable — the decompilation goal
and the FSGSBASE enable in one shot.

## Document map

| Document | Status | Contents |
|---|---|---|
| [`10-hcall-resume-window-and-noops.md`](docs/10-hcall-resume-window-and-noops.md) | **★ ACTIVE** | The resume-window route + the NOOP catalog |
| [`16-byepervisor-12-02-port.md`](docs/16-byepervisor-12-02-port.md) | **★ ACTIVE (implementation)** | The Byepervisor-Reborn port plan for 12.02: field/gadget mapping, our FACS #GP trigger, the phases |
| [`17-kernel-data-survey-1202.md`](docs/17-kernel-data-survey-1202.md) | Active (reference) | Two-boot 12.02 data-anchor survey: allproc, pmap, paging-index fields, IDT, GDT, TSS, and PCPU records with observed values and strides |
| [`11-debunked-theories-and-corrections.md`](docs/11-debunked-theories-and-corrections.md) | Active (register) | Every theory we got wrong, and why — so we don't repeat mistakes |
| [`12-acpi-static-anchor-corrections.md`](docs/12-acpi-static-anchor-corrections.md) | Active (register) | Resume-route anchors we mis-derived (FACS address, `+0x18e` breakpoint, string-pointer scan; superseded mechanism in `15`) |
| [`13-ring0-freeze-instrumentation.md`](docs/13-ring0-freeze-instrumentation.md) | Active (instrumentation) | The freeze capture set (F5 + klog), the 3 remaining hypotheses, and the falsifiable test |
| [`14-ring0-execution-alternatives.md`](docs/14-ring0-execution-alternatives.md) | Active (research) | Safer ring-0 substrates vs r0gdb, mapped onto the freeze classes |
| [`15-facs-global-resume-trigger.md`](docs/15-facs-global-resume-trigger.md) | Active (research) | The real resume trigger (`AcpiGbl_FACS` self-corruption → #GP) and the dump-verified 12.02 `AcpiGbl_FACS` anchor (`kdata+0x2cb4c80`) |
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

## r0gdb/ — the stub toolchain (ours, in-repo)

[`r0gdb/`](r0gdb/) is the canonical source of the GDB stub
toolchain (`gdb_stub/` + `prosper0gdb/` incl. the per-FW offset
tables), maintained in this repo since 2026-10-12 — previously it
lived unversioned in the lab payload tree. Rule: **edit sources in
the repo, sync to the lab sandbox, build there** (the sandbox holds
the external build deps: freebsd-headers, yasm, the payload SDK).
Builds produce `payload-elfldr-sdk.elf`; the sha is recorded per
build and the `tools/` ladder re-validates each new build. See
[`r0gdb/README.md`](r0gdb/README.md) for lineage, the build flow, and
the pending signal-handling deadlock fix.

## Tools (regression gates)

The graduated verification ladder for the r0gdb stub, published as
runnable code. **Level 1 is a regression gate: it must be green before
any ring-0 session** — it validates the full stub protocol (handshake,
register layout, base/kdata constants, m/M round-trips) with zero
ring-0 risk, so payload or protocol drift fails fast instead of
hanging the console on a bad assumption.

| Tool | Status | Purpose |
|---|---|---|
| [`tools/stub_verify.py`](tools/stub_verify.py) | **Validated green on-console (2026-10-12)** | Level 1: userland-only full protocol check (the regression gate) |
| [`tools/stub_verify2.py`](tools/stub_verify2.py) | Hardened; first live ring-0 run pending | Level 2: gated ring-0 EFER read + validated IDT/TSS restore (kernel-text `store_rax_rdi` only, pinned 12.02 deltas) |
| [`tools/stub_verify3.py`](tools/stub_verify3.py) | Ported; first live run pending | Level 3: level-2 pattern + CR0 read + sanity check |
| [`tools/r0gdb_session.py`](tools/r0gdb_session.py) | v5.1, ported; pending live validation | The production ring-0 session client (computed-port discovery, staged return frame, SMEP-safe restore) |

Levels 2/3 and the session client refuse ring-0 work until the live
offset deltas match the pinned **12.02** table and the operator gates
(`--ring0`, `--verified-store-gadget`, `--recovery-plan-confirmed`) are
supplied. The ring-0 restore path uses ONLY the kernel-text
`store_rax_rdi` gadget — the old userland write-slot stepped rip at
payload memory at CPL0, the live-confirmed SMEP #PF panic mode.

Live status (2026-10-12 evening): the 12.02 pin and the staged-frame
ring-0 entry validated green on-console; the run then froze in the
stub's signal-handler spin deadlock during a `G` write (root-caused;
stub fix pending) and the console died when a `timeout` wrapper killed
the parked session — never wrap gated ring-0 scripts in a timeout.
See docs/10 for the full post-mortem.

Required environment: `PS5_HOST` (console address — never hardcoded in
this repo), `R0GDB_ELF` (path to the exact `payload-elfldr-sdk.elf`
build under test), `R0GDB_SEND_ELF` (path to `send_elf.py`),
`R0GDB_LOG` (protocol log path — defaults beside the script),
`R0GDB_OFFSET_LIST` (defaults to this repo's own canonical
`r0gdb/prosper0gdb/offsets/offset_list.txt`).

**These `tools/` copies are the CANONICAL, editable clients** (since
2026-10-12, owner-directed — the lab payload directory is the
operational sandbox only: build tree, binaries, logs, and a private
env file exporting the variables above). Run from here:

```sh
source <lab-sandbox>/env.sh   # exports PS5_HOST, R0GDB_ELF, ...
python3 tools/stub_verify.py  # level 1 — the regression gate
```

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

## Evidence labels

- `[verified-in-tree]` — directly supported by this repository; cite the
  exact file and line.
- `[verified-on-dump]` — directly supported by a local firmware or memory
  dump; cite the dump name and byte offset. Never add the dump to this repo.
- `[verified-on-console]` — observed on the console; cite the research note
  and the experiment record, including firmware and recovery state.
- `[public-consensus]` — documented in a cited public source.
- `[inference]` — derived from evidence; state the reasoning and what
  observation would falsify it.

Started 2026-10-08 from a consolidation session over the local lab
(`homebrew_ps5`, `ps5debug-NG`, `prospero-win`, `payloads/`) and public
scene sources. Pivoted to the resume-window route 2026-10-12.
