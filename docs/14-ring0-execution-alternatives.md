# 14 — Ring-0 execution: alternatives to r0gdb (offline research, 2026-10-13)

Status: **historical offline alternatives; no alternative here was
validated on-console.** Read with `13` if interactive r0gdb work resumes.
The current 12.02 Byepervisor evidence boundary is in `17`.

Goal being served: **stable ring-0 stepping** so the resume-window work
(`10`, Route HCALL 0x0f) can proceed. **UPDATE (2026-10-13):** the
resume trigger is *not* a breakpoint. The public lineage corrupts the
`AcpiGbl_FACS` kernel-data pointer so the kernel's own resume code takes
a `#GP`; see `15`. That means `acpi_sleep_machdep` is not needed at all,
and the candidate substrate is a one-shot kernel-data write + a `#GP`
handler with a selected stack — the non-interactive end of this inventory.
[public-consensus] The public loader chooses IST6 (`15` §1);
[verified-on-console] the later 12.02 audit found the current vector-13
gate at IST0 (`16`). No 12.02 #GP frame/return is validated.

## What the resume route actually requires from a ring-0 substrate

From `10` and the attachment, the target needs exactly three capabilities:

| # | Requirement | Why |
|---|---|---|
| R1 | **Execute VMMCALL from kernel (CPL0, GameOS-guest) context** | the hcall intercept is clear at CPL3, so the HCALL 0x0f must be issued by kernel code |
| R2 | **Cause a kernel fault inside the resume window** (after `resumectx`, before `acpi_wakeup_cpus`) — e.g. corrupt `AcpiGbl_FACS` so the kernel's own `AcpiSetFirmwareWakingVector` dereferences it (→ `#GP`), per `15` | the window is narrow; the trigger must be timed |
| R3 | **Take a controlled action when that fault fires** (e.g. via a selected IST stack and `#GP` ROP page) | run the VMMCALL, or pivot to the carrier page |

Everything else (kernel R/W, CR3 construction, carrier-page write) is already
covered by the pipe/alias primitives [verified-on-console].

The current r0gdb design meets R1/R2/R3, but its **R2/R3 delivery path is the
one that freezes**: the breakpoint's exception is routed through the patched
IDT gate into the mailbox/`gdbstub_main_loop` packet reader (`ring0.c:134-181`, `dbg.c:793`), which blocks on the RSP socket. The freeze is in that path.

## Substrate inventory (in-repo, [verified-in-tree])

| Id | Substrate | How it enters ring-0 | Blocks on socket? | Needs IDT/TSS patch? | SMEP exposure |
|---|---|---|---|---|---|
| A0 | **r0gdb interactive** (`r0gdb()` → `r0gdb_loop`) | staged-frame entry → int179 trampoline; IDT vectors 1/6/9/179 + TSS IST redirect (`r0gdb.c:358`) | **yes** (`gdbstub_main_loop` waits for packets) | yes | steps kernel text only (`store_rax_rdi`, rdmsr/wrmsr/DR gadgets) |
| A1 | **r0gdb trace / instrument** (`r0gdb_instrument`→`r0gdb_trace`) | same `r0gdb_setup` + INT9→int179 hook, but the trap runs an in-process `trace_prog` callback (`r0gdb.c:754`, `r0gdb_instrument` at `r0gdb.c:910`) | **no** | yes | same |
| A2 | **r0gdb kfncall** (`r0gdb_kfncall`) | trace machinery, RIP-swaps a kernel function call (`r0gdb.c:1193`) | **no** | yes | same |
| A3 | **kernel-text ROP / VMMCALL gadget** (no r0gdb trap path) | would need a control-transfer primitive other than the IDT patch (e.g. overwrite a return address on a kernel stack) | no | **no** (if a valid control-transfer exists) | kernel text only |
| A4 | **HV AP-launch substrate** | the resume-window HCALL itself (this is the *target*, not a general stepper) | no | no | root-0 carrier page is executable by design |

**Update:** the `AcpiGbl_FACS` self-corruption route (`15`) instantiates
a "passive" trigger — a single kernel-data qword write, no breakpoint, no
packet reader — which sits between A2 and A3: it still needs a `#GP`
IDT gate and, for this proposed ROP path, a chosen TSS IST stack (like
A0/A1/A2), but no interactive session.
It is the concrete form of the non-interactive recommendation below.

A0 is the interactive implementation that froze. A1/A2 are in the tree
and were proposed as alternatives because they remove the packet reader,
one candidate freeze locus (H2 in `13`), while reusing the same ring-0
entry. [inference] This only removes H2 if H2 actually caused that run;
an F5/klog trace locating the freeze elsewhere would falsify it. A1/A2
have no completed 12.02 console validation. A3 remains a proposed
"no IDT patch" route; A4 is the intended destination.

## Analysis: which alternatives eliminate which freeze mechanism

The freeze class is not yet known (that is `13`'s job). Per class, the fix:

- **H1 nested-signal re-entry.** A1/A2 do **not** automatically fix this — a
  nested signal can still arrive while `in_signal_handler` is held by the
  trace/kfncall path. But A1/A2 remove the *long* hold (no multi-second
  packet session), so the window for a nested delivery shrinks enormously.
  The real fix is in the handler/flag protocol (`13`), independent of A0/A1.
- **H2 packet-read block.** A1/A2 **eliminate this class by construction** —
  there is no packet reader to block. This is the strongest argument for
  A1/A2: if the freeze is the packet interaction (the leading hypothesis),
  the non-interactive substrates are a complete workaround, not a patch.
- **H3 cleanup/`run_in_kernel` wedge.** A1/A2 avoid `r0gdb_cleanup()`
  entirely (they never enter `r0gdb_loop`), so if the wedge is in cleanup
  they also fix it. If the wedge is in `run_in_kernel` itself, all of
  A0/A1/A2 share it (all use `run_in_kernel`) and the fix is at that layer.

**Historical assessment:** a non-interactive substrate (A1 or A2, or a
purpose-built handler derived from them) could avoid the packet-reader and
cleanup paths, but may retain a shared `run_in_kernel` fault and the
IDT/TSS patch risk. [inference] A successful same-firmware return through
A1/A2 would support this assessment; a repeat freeze at their shared
entry would falsify its proposed benefit. Neither was validated here.

## A3 — the "no IDT patch" route (research notes, unproven)

If the IDT/TSS patch window itself is the root hazard (it holds a live
redirect into payload memory; a bad restore = panic), the ideal substrate
never touches the IDT. Candidates:

- **Kernel-text VMMCALL gadget.** The GameOS kernel runs as a guest of the
  outer HV and issues hypercalls, so kernel `.text` plausibly contains a
  `VMMCALL` instruction inside the HV-call wrapper. If a `vmmcall` in kernel
  text exists and a controlled RIP-transfer to it exists, R1 is satisfied
  **without any IDT patch**. Status: **[hypothesis]** — falsifiable by
  disassembling kernel `.text`; cannot be checked offline because
  `kernel-data.bin` is a data-only dump (no `.text`, no symbol table,
  confirmed in `12` §4). Needs a text image or an online disassembler.
- **Return-address overwrite on a kernel stack.** A syscall that copies a
  controlled value onto a kernel stack slot whose return address we can
  rewrite would give RIP control with no IDT patch. Requires a stack leak;
  the pipe/alias primitives can read kernel memory, so a leak is plausible,
  but no gadget/entry has been identified. Status: **[hypothesis]**.
- **`sy_call` pointer patch.** `sysent[…].sy_call` is kernel data
  (`offsets.sysents`); pointing an unused syscall at attacker code would
  give kernel execution — but SMEP blocks executing userland pages at CPL0
  (verified: Oct-9 CR4 crash), and kernel *heap* pages are user-mapped in the
  NPT (SMEP applies). So the target must be kernel `.text` (read-only, not
  writable), which loops back to needing a kernel-text gadget. Status:
  blocked on SMEP unless a kernel-text gadget exists.

**Honest verdict on A3:** attractive but currently unproven on every leg.
It should be pursued *only* if A1/A2 also freeze (i.e. the hazard is the
patch window or `run_in_kernel`, not the packet reader). Offline we cannot
advance it without kernel text.

## Historical proposed sequence (not a current run plan)

1. **Run `13`'s instrumented test first** (A0 + F5/klog). It is the only way
   to know which class we are fixing; a substrate change without that data is
   a guess.
2. If the verdict is H2 (packet-read) or H3 (cleanup), **adopt a
   non-interactive substrate** for the resume trigger: use `r0gdb_trace`/
   `r0gdb_instrument` as the delivery mechanism (run the resume action inside
   a `trace_prog` callback) instead of `gdbstub_main_loop`. This is the
   smallest change that removes the freeze-prone component while reusing the
   proven entry.
3. If the verdict is H1 (nested signal), fix the handler/flag protocol in
   `dbg.c` (the instrumentation already tells us the signum and faulting
   `rip`), then keep A0/A1.
4. If all of A0/A1/A2 still freeze, the fault is in the IDT/TSS patch window
   or `run_in_kernel`; escalate to A3 research (needs a kernel text image) or
   re-examine the `run_in_kernel` handoff.

## What is NOT claimed here

- No claim that any alternative is *free* of console risk: A1/A2 patch the
  same IDT/TSS window as A0 and can panic if a restore is missed. The
  recovery plan requirement (`AGENTS.md`) applies to all of them.
- No claim that a kernel-text VMMCALL gadget exists — A3 is unproven and
  offline-uncheckable with the current data-only dump.
- No claim about the *actual* freeze class; that is `13`'s falsifiable test.
