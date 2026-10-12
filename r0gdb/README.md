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

## Known defect to fix next (2026-10-12 post-mortem)

The ring-0 session freeze (root-caused, see docs/10): three
consumers share `in_signal_handler` with an unconditional spin —
`gdb_stub/dbg.c:966` (signal handler), `prosper0gdb/r0gdb.c:469`
(`r0gdb_loop`, holds the flag across the entire blocking packet
session), `gdb_stub/ring0.c:171` (mailbox thread). Any signal
during a ring-0 packet session freezes the handling thread forever
(a `G` write is 337 single-char blocking reads — the largest
window). The fix, agreed in the coordination mailbox:

1. the signal handler must NOT spin when the flag is already held
   (return/defer), or better: block the dbg signals on the r0gdb
   thread while it holds the flag
2. `SA_RESTART` on the sigactions so `EINTR` cannot desync the
   per-char reads
3. ideally: buffer whole incoming packets before parsing to shrink
   the interrupt windows from N reads to ~1

Until this lands and the ladder re-validates, **do not run level 2
or full ring-0 sessions**.
