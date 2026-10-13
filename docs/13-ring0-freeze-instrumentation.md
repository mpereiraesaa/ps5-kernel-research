# 13 — Ring-0 freeze: instrumentation set (drafted offline, 2026-10-13)

Status: **instrumentation drafted, built, and offline-validated; no console
run.** The ring-0 session freeze (see `10` §"GS-base freeze theory:
FALSIFIED") still has an unexplained root cause. This document is the
complete instrumentation set needed to (a) capture the freeze as evidence
and (b) discriminate between the remaining mechanism classes, plus the
falsifiable test for each.

Read `11` (debunked theories) first: the GS→TLS theory (#2) is dead, the
`acpi_sleep_machdep+0x18e` breakpoint (#14) is unverified, and the resume
trigger is known to be a kernel-data `AcpiGbl_FACS` corruption → `#GP`, not a
breakpoint at all (#16, `15` §1). Do not rebuild a theory on any of them.

## Why the current instruments are insufficient

`qDiagF4` captures the last fault `ucontext`. It answered the GS question
(mc_flags gate) but cannot answer the freeze question, because:

- The freeze is a **timeout on the RSP socket**: the packet after the
  synthetic-stop `g` gets no reply and the client parks. Whatever instrument
  we add must produce evidence **even when the socket reader is wedged** — a
  query sent over that same socket may never be read.
- `qDiagF4` records one frame, last-writer-wins. It cannot tell us *which
  code path* hung or *whether a second signal was delivered* at the freeze
  point.

So the freeze instrumentation has two independent channels:

1. **klog side channel** — `[r0gdb-diag] …` lines emitted on state
   transitions. `klog_printf` goes through the SDK crt's `__crt_syscall`
   (bare `syscall`, no TLS/errno/locking; `__klog_init` aborts the payload if
   it fails, so it is always available). It survives a wedged RSP socket.
2. **F5 query** — a fixed-layout counter block + event ring, readable over
   RSP *if* the reader is not fully stuck; best-effort on the freeze path.

## The three remaining freeze hypotheses and their discriminators

Derived from code reading [verified-in-tree] of `r0gdb/gdb_stub/dbg.c` and
`r0gdb/prosper0gdb/r0gdb.c`. Root cause is unknown; these are the live
classes.

| # | Hypothesis | Mechanism | Discriminator |
|---|---|---|---|
| H1 | **Nested-signal re-entry** | A debugger signal is delivered *while* `r0gdb_loop`/mailbox holds `in_signal_handler` across the blocking `gdbstub_main_loop` session. `signal_handler` sees busy=1; a fault signal parks (`dbg.c:1267`). | `F5 counts.nested > 0`; the nested ring event carries the faulting `rip`/signum. klog: `nested debugger signal … park`. |
| H2 | **Plain packet-read block** | No debugger signal at all; the reader is blocked in `wait_for_packet()` (`dbg.c:817`; e.g. the interrupter's `kill(SIGINT)` never fires, or the client's next packet never arrives / is mis-framed). | `F5 counts.nested == 0` and `packet_waits > packet_recvs`; klog shows `packet_wait` growth with no `recv`. |
| H3 | **Cleanup / run_in_kernel wedge** | The freeze is in `r0gdb_cleanup()`'s `run_in_kernel` MSR step (`SFMASK`) or the TSS/IDT restore, after the loop exits. | klog: `cleanup: begin` with no matching `cleanup: … OK`; F5 has `cleanup_step`/`cleanup_park` or loop-exit events with no cleanup-complete. |

H1 and H2 are the shapes `10` already named ("nested signal vs plain
packet-read read"). H3 was added when the auto-cleanup path (`#67`) landed
but was never ring-0-validated; the freeze could be downstream of a loop exit
that the client mis-attributes to the `g` packet.

## The instrumentation (as built, sha `a6a227ef…`)

All in-repo [verified-in-tree]; the lab tree mirrors it exactly (they are
byte-identical, confirmed before building).

### Stub — `r0gdb/gdb_stub/dbg.c`

- **F5 event ring + counters** (new, at the top of the file): a
  16-slot fixed-layout ring (`struct gdb_diag_evt`) plus scalar counters
  (`gdb_diag_handler_entries`, `_nested_entries`, `_park_entries`,
  `_session_locks`, `_session_waits`, `_packet_waits`, `_packet_recvs`,
  `_interrupter_fires`). `gdb_diag_record()` is a lock-free, allocation-free
  store safe in a signal handler.
- **`signal_handler`** now records `DIAG_HANDLER_ENTRY` on every call; when
  the flag was already held it records `DIAG_NESTED_SIGNAL` (with the
  top-of-frame `rip` and signum) and, for fault signals, `DIAG_PARK`, and
  emits the klog beacons `nested debugger signal … park` /
  `fault-signal park …`.
- **`gdbstub_session_lock`** counts acquisitions and increments
  `_session_waits` (with a klog line) the first time it has to spin.
- **`gdbstub_main_loop`** counts each `wait_for_packet()` (`DIAG_PACKET_WAIT`)
  and each dispatched packet (`DIAG_PACKET_RECV`), each recording the current
  `in_signal_handler` value.
- **`interrupter_thread`** records `DIAG_INTERRUPTER` + `_interrupter_fires`
  and a klog line when it sends its `SIGINT`.
- **`qDiagF5`** query: pure memory reads, emits
  `F5:<hdr 32 hex>:<ring 16×32 hex>`.
- **`diag_klog`, `diag_cleanup_event`, `diag_loop_event`**: non-static
  bridges used by the payload side. `diag_klog` maps to `klog_printf` in the
  SDK-crt build and to a no-op in the elfldr/BLOB builds.

### Payload — `r0gdb/prosper0gdb/r0gdb.c`

- **`r0gdb_loop`** emits `DIAG_LOOP_ENTER` each iteration and
  `DIAG_LOOP_EXIT` (with the resulting `ts.regs.rip`) after the session
  returns. Together with the packet counters this brackets each
  `run_in_kernel()` call, so an H3 wedge is attributable to a specific gadget
  boundary without touching the delicate ring-0 asm.
- **`r0gdb_cleanup` / `r0gdb_park_after_cleanup_failure`** emit
  `cleanup: begin` / `cleanup: … OK|FAILURE` klog lines and
  `DIAG_CLEANUP_STEP` / `DIAG_CLEANUP_PARK` ring events.

### Clients — `tools/`

- `Session.diag_f5()` + `decode_diag_f5()` + `analyze_freeze()` in
  `stub_verify.py`; `--diag-f5` CLI flag that prints counts, the ring, and a
  class verdict (`nested-signal` / `packet-read-block` / `indeterminate`).
- `experiment_exit.py` attempts one best-effort `qDiagF5` on the freeze path
  (3 s timeout) before parking; a second timeout is itself evidence (reader
  fully wedged) and tells the operator to read dmesg for `[r0gdb-diag]`.

## The falsifiable test

Per hypothesis, the run that would *confirm* vs *falsify*, all read from the
two channels above:

1. **H1 nested-signal** — run experiment 1 on the instrumented build and, at
   the freeze, read `F5 counts.nested`. `nested > 0` ⇒ H1 confirmed and the
   ring's nested `rip` names the faulting instruction. `nested == 0` ⇒ H1
   falsified for this freeze.
2. **H2 packet-read block** — `nested == 0` **and**
   `packet_waits > packet_recvs` **and** dmesg shows the last
   `[r0gdb-diag]` beacon before the hang is not a park/cleanup line ⇒ H2. If
   instead dmesg ends at `cleanup: begin`, it is H3, not H2.
3. **H3 cleanup wedge** — `cleanup: begin` present with no
   `cleanup: … OK|FAILURE` ⇒ the hang is inside `r0gdb_cleanup_checked()`
   (most likely the `SFMASK` `run_in_kernel` MSR step). Falsified if the loop
   beacons show a final `DIAG_LOOP_EXIT` and a clean `cleanup: … OK` but the
   socket still never answers (then the hang is transport-side, a fourth
   class).

A freeze that produces **no** klog beacon past the entry stop and **no**
readable F5 is inconclusive by construction — it means the whole process
stopped emitting (a hard wedge such as a #PF/#MC at CPL0 that took the CPU
out of the payload); that is the signature of the Oct-9 panic class, not the
2026-10-12 freeze class, and must be labelled separately (`10` §543).

## Console-experiment policy

The instrumented build is `a6a227ef…` (below). The test is **ring-0**: it
patches the IDT/TSS window and can panic the console. It requires explicit
owner approval and a recovery plan per `AGENTS.md`. Nothing here has been
run on-console; the console was off for this whole session.

### Build identity

| Field | Value |
|---|---|
| sha256 | `a6a227ef485d48db6323f31c1bd3caf847a7fcca61f3953d804c220b28e7a3b0` |
| base | `cbd34cbd…` (PR #71) + freeze instrumentation |
| symbols | `r0gdb=0x695E`, `r0gdb_exit=0x6728`, `kdata_base=0x4DD48`, `offsets=0x5EE40`, `og_tss=0x4DDE0`, `SYM_M_TEST=0x5E000` (BSS tail) |
| reproducible | yes — `make clean && make` reproduces the sha (verified) |
| clients | `tools/stub_verify*.py` `--diag-f5`/`--diag-f4`; `tools/experiment_exit.py` F5-on-freeze |
| F5 layout | `F5:` + 8×u16 BE counters (4 hex each) + `:` + 16 slots × 32 hex (kind/busy/signum/rip8/tid4/seq) |

## What is still missing (honest gaps)

- **`run_in_kernel` micro-beacon.** The loop beacons bracket a whole
  `run_in_kernel` call, not each inside-gadget step. Adding a beacon inside
  `r0run.asm` would localize an H3 wedge to the exact gadget, but editing the
  low-level ring-0 asm carries its own risk; deferred until the coarser test
  says H3 is real.
- **Interrupter-thread identification.** `gdb_diag_record` captures
  `thr_self()` (FreeBSD `thr_self` returns the TID, so the field is named
  `tid`), but the *logical* thread id (`getpid()`) is not recorded. If H1 is
  confirmed, distinguishing "signal delivered to the session-owning thread"
  from "delivered to another thread" needs the payload TID added.
- **No automatic panic capture.** klog ring churns; the operator must read
  dmesg promptly after a freeze. A dedicated `ps5log/1` sink would be more
  durable but needs `projects/logging_server` wired into the payload — future
  work, not required for the first discriminating run.
