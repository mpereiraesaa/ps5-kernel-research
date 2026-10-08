# 05 — Toolchain and observability (payload route, not homebrew titles)

## Compiling payload ELFs

- Host deps: `clang-18` + `lld-18`.
- SDK: the locally built install tree at
  `engineering/ps5debug-NG/ps5-payload-sdk/install/` (full `bin/` +
  `target/` sysroot + `ldscripts/`). The two old copies
  (`engineering/ps5sdk/`, root `engineering/ps5-payload-sdk/`) were
  removed 2026-10-08 — they lacked `target/` and broke builds with
  `crt1.o not found`.
- `toolchain/prospero.mk` defines `prospero-clang/lld/deploy/...`;
  wrappers auto-link `crt1.o`, `-lc`, `-lSceLibcInternal`, `-lSceNet`,
  `-lkernel_web`.
- `ldscripts/elf_x86_64.x`: flat PIE ELF — single RWX text `PT_LOAD`,
  rodata/data phdrs, `PT_DYNAMIC`. **No fSELF/eboot signing, no fpkg, no
  PRX packing.** A payload is a plain `main()` C file.
- Local payload consumers (defaults repointed 2026-10-08):
  `payloads/{modovl,modovld,dumpmaker,imgrepack,pakprobe,ps5debug-recovery}`
  and `re4r_modding/payloads/{diskcheck,stageverify,stageassemble}` —
  all build with a bare `make`; `PS5_PAYLOAD_SDK` overrides still work.

## Deploying: elfldr (TCP 9021)

- The running elfldr listener loads the ELF **in-memory into its own
  elevated loader context** — the source of "elevated capabilities"
  (kernel data R/W, `nmount`, klog, decrypted `/mnt/sandbox` views).
- `prospero-deploy -h <ip> -p 9021 payload.elf` or
  `engineering/send_elf.py` (`--wait-response` / `--expect-response`
  read the payload's stdout echoed back over the same socket).

## Three TCP logging routes

1. **elfldr inline (9021)** — payload stdout echoed back over the send
   socket. One-shot, no persistence.
2. **`ps5log/1` → `ps5logd` (9300)** — the structured route for payloads
   *and* titles. Server: `make -C projects/logging_server serve`
   (PC, `0.0.0.0:9300`) writes `runs/<utc>_<title>_<app>_<boot>.log` +
   `.json` manifest (records, gaps, sha256, clean/BYE). Client: single
   header `client/ps5log.h`; config `/data/homebrew/dev.conf`
   (payloads) or `/app0/dev.conf` (titles); three levels — stdio capture
   (`PS5LOG_CAPTURE_STDIO`), structured `LOG/LOGE/LOGM` records
   (`<seq>\t<mono_ns>\t<level>\t<text>`), or no client at all
   (`nc <pc> 9300`). Wire: `HELLO ps5log/1 ...` first, `BYE seq=...
   reason=...` last; empty `gaps` + `clean=true` = complete run.
   Hardware-verified on FW 12.02 through elfldr (gate table in the
   logging_server README).
3. **klog forwarder (3232)** — kernel log stream (ps5debug-NG service
   family), e.g. watching `[modovld] overlay ON` live.

## Elevation for homebrew processes (Lapy)

- `PS5-Lapy-JB-Daemon` (owned-root fork): resident daemon + one-shot
  elfldr helper. Cooperative protocol — the *target* calls
  `seteuid(geteuid())` (clones its own credential) before writing
  `/download0/elevate_proc` with its PID; the daemon transfers two root
  vnode refs obtained by native `rfork` donors (legacy direct
  root/jail-pointer overwrites panicked after ~20–29 elevations/boot).
- Multi-FW: `offsets_v940.cpp` override (see `01-primitives.md`) +
  runtime layout preflight; validated on 12.02 (daemon) and 6.02/12.70
  (one-shot helper 5/5 each). Other FWs: table says yes + preflight
  passed = experimental, not validated.

## Console-side services map (our ports)

| Port | Service |
|---|---|
| 9021 | elfldr payload listener |
| 9300 | ps5logd (PC side; console connects out) |
| 3232 | klog forwarder |
| 744 / 755 / 1010 | ps5debug-NG command / async-interrupt / discovery |
| 2121 / 2323 | ftpsrv (raw SELF mode for deploys) |
