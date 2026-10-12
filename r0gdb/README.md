# r0gdb — the PS5 kernel GDB stub toolchain (ours, in-repo)

This folder is the **canonical source** of the r0gdb GDB stub
toolchain (the `gdb_stub/` stub + the `prosper0gdb/` payload side),
maintained in this repo as of 2026-10-12. Before that the sources
lived unversioned in the lab payload tree — no history, no review,
mtime archaeology (see the 2026-10-12 post-mortem in
[`../docs/10-hcall-resume-window-and-noops.md`](../docs/10-hcall-resume-window-and-noops.md)).

## Layout

| Path | Contents |
|---|---|
| `gdb_stub/` | The GDB stub: `dbg.c` (RSP protocol, packet layer, signal handlers), `ring0.c` (run_in_kernel + mailbox machinery), `trap_state.h`, `r0hooks.asm`, build files |
| `prosper0gdb/r0gdb.c` | The payload ring-0 side: `r0gdb_setup` (IDT/TSS patch), `r0gdb_loop`, `r0gdb_cleanup`, the MSR gadget wrappers |
| `prosper0gdb/offsets/` | Per-FW kernel offset tables (`12_02.h` is this console's; selected at runtime from the live sysctl FW version — see `offsets.c`) |
| `prosper0gdb/sdk-build/Makefile` | The build recipe (sanitized: `PS5_PAYLOAD_SDK` and `PS5_HOST` are env/make-required) |

## Lineage and ownership

Derived from the public **kstuff / prosper0gdb** lineage (the
"kstuff-lite" trimmed fork we have carried in the lab), with our own
PS5 porting and fixes layered on: the 12.02 offset table wiring, the
SDK crt/libc elfldr build, SIGPIPE blocking, `NO_SYSARCH_GSBASE` +
the gsbase guard for the SDK-TLS build, and the ring-0 mailbox
machinery. No upstream license headers exist in the files; this is
our working research fork of a scene toolchain. The payload binaries
are **not** committed here (build artifacts; embed local build
paths).

## Build

Builds happen in the lab sandbox
(`engineering/payloads/prosper0gdb_elfldr/kstuff-lite/`), which
provides the external dependencies that are intentionally NOT in
this repo:

- `freebsd-headers/` — 2052 upstream FreeBSD ABI headers
- `tools/yasm-local/` — extracted yasm binary
- `PS5_PAYLOAD_SDK` — the prospero payload toolchain (clang, crt, libc)

**Rule: edit sources HERE, sync to the sandbox, build there.** The
sandbox copies are build inputs only — never edit them (they are
not versioned; edits there are invisible and get overwritten by the
next sync).

```sh
# sync (repo -> sandbox) then build:
cd <sandbox>/prosper0gdb/sdk-build && make
# result: payload-elfldr-sdk.elf (record the sha256; the session
# tools pin expectations per build)
```

After any stub change, re-run the graduated ladder
(`tools/stub_verify.py` level 1 first — it is the regression gate
and validates the new build's protocol/constants).

## Signal/session deadlock fix (2026-10-12)

The ring-0 session freeze and its source-level repair are recorded in
[`../docs/10-hcall-resume-window-and-noops.md`](../docs/10-hcall-resume-window-and-noops.md).
Four code paths acquire the shared `in_signal_handler` flag: the
signal handler, `r0gdb_loop`, the ring-0 mailbox thread, and
`gdb_remote_syscall`. The three non-handler paths now use
`gdbstub_session_lock()` / `gdbstub_session_unlock()`, which block
the debugger signal set on the owning thread before taking the flag
and restore the prior mask after releasing it. The handler retains a
spin acquisition: it cannot interrupt an owner holding the lock, and
a handler on another thread can wait while the owner progresses.

All installed debugger signal actions use `SA_RESTART` and mask the
debugger signal set while a handler runs. Incoming RSP data is read
ahead in chunks, assembled into a bounded complete packet, checksummed,
then parsed from memory. Outgoing ACK reads share the same buffered
stream reader so read-ahead cannot consume bytes needed by the next
packet. A transport failure now returns from the parser; the signal
handler and ring-0 mailbox path preserve the original register
snapshot, and `r0gdb_loop` does not execute stale register state.

These are source changes [verified-in-tree]: packet assembly is in
`gdb_stub/dbg.c:75-160`, parser error handling is at `dbg.c:662-668`,
the signal mask and session lock are at `dbg.c:1340-1386`, and callers
are at `dbg.c:1155-1188`, `gdb_stub/ring0.c:170-181`, and
`prosper0gdb/r0gdb.c:468-480`. The original signal context is restored
on parser failure at `dbg.c:1108-1110`. Signal actions use restart
semantics at `dbg.c:1437-1449` and `prosper0gdb/r0gdb.c:764-768`.
The change has not been built or run on a console. Keep level 2 and
full ring-0 sessions gated until the documented local build and
graduated validation ladder pass.

One separate safety gap remains [verified-in-tree]: `r0gdb_loop()` can
return after a transport failure, but `r0gdb()` does not call
`r0gdb_cleanup()` on that or its normal exit path. A disconnected
client can therefore leave the patched IDT/TSS state installed while
the payload remains alive. Automatic cleanup on every session exit is
the next design task (`prosper0gdb/r0gdb.c:427-453, 461-487`). The
cleanup routine uses the setup `copyin()`/`copyout()` path to restore
IDT/TSS, but its full sequence (including the `run_in_kernel()` MSR
operations) has not been validated after ring-0 entry. In this tree,
those copy helpers use `kwrite20()` plus pipe I/O rather than `sysarch`
(`prosper0gdb/r0gdb.c:173-197`). Keep the socket park and recovery
plan until automatic cleanup is independently proven. See the
incident record in
[`../docs/10-hcall-resume-window-and-noops.md`](../docs/10-hcall-resume-window-and-noops.md).
