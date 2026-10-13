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

### KH2 formatting boundary (offline)

The local payload workspace has a pure native formatter at
`engineering/payloads/byepervisor_probe_1202/kh2_trace_format.c/.h`.
It bounds a `KH2` text record to 960 bytes before the `ps5log/1` wrapper,
selects the stage's source tag, and rejects duplicate/malformed fields.
Its host check, `kh2_trace_format_host_test.py --notes-repo /path/to/ps5-kernel-research`,
compiled it with the host C compiler and passed all 16 stage formats and
18 records (including the R0/R1/Q1/R2/Q2 handoffs) through this repo's
`tools/khook_trace_classify.py`. The source SHA-256 is
`b1c197a74e763c415df3d496050934d54dd6259e196751970af5da1eea249b99`.
No console operation was performed. This formatter has no kernel read path
and is not wired into a 12.02 KH2 chain. A future user-mode producer must
check each `ps5log_line` result; even a successful send is not proof that the
PC persisted the line. The retained PC log and matching manifest are the
evidence that the classifier assesses (`17`).

The separate local payload workspace also has a **read-only KH2 capture
core** at `engineering/payloads/byepervisor_probe_1202/kh2_capture.c/.h`.
It accepts kernel-data read and log-send callbacks, reads the gate/IST6,
frame slots, and journal words, and emits R0/R1/Q1/R2/Q2 plus changed frame
and journal records. A failed read attempts an ERR-level `KH2E` line naming
the stage, region, and address. Bounded R0/R1/R2 reads also emit paired
`KH2R begin/done` records; a failed begin send prevents that read. The
continuous F1/F2/journal scans do not emit these brackets, to avoid two
extra PC sends per poll. Its host check,
`kh2_capture_host_test.py --notes-repo /path/to/ps5-kernel-research`,
compiled the sampler with `cc`, produced 11 native milestones plus 30 read
brackets, and combined them with B0/B1/B2/A2/D2 fixtures for a complete
18-milestone, 48-line classifier run.
The host memory mock now uses a packed, unaligned IST6 field address;
the sampled pointer value remains aligned. No console read of that revised
path has occurred.
It also checked mismatch, failed-read, failed-send (including the error
line), and premature-quiesce paths. Source SHA-256: `kh2_capture.c`
`e938883f305114de17ab2ba9a90931413eed602d5a5c6ae64855b35d94285b72`,
`kh2_capture.h`
`96789919226b4d004958bb5dddcbc8766106c3d8948fcb0b25a22ed2b9db42b6`.
The host-test source SHA-256 is
`ad85f7289049ffaa0b4e943bc797d55a925e944a129b143de992130f16855349`.
This code has no thread handoff, PS5 SDK adapter, or 12.02 chain integration;
its phase guard checks call order only. `kh2_capture.c` also compiled as a
PS5 SDK relocatable object; no payload link or console operation was performed.

An offline pthread schedule at
`engineering/payloads/byepervisor_probe_1202/kh2_worker.c/.h` now wraps that
capture core. Its `begin_arm`/`end_arm` and
`begin_dispatch`/`end_dispatch` calls model SDK/logger ownership between
main and observer, requiring a worker read/sample acknowledgment before
each trigger and quiescence before main resumes reads/logging. The host check
`kh2_worker_host_test.py --notes-repo /path/to/ps5-kernel-research` ran 20
mocked two-transaction handoffs, accepted each combined 18-milestone trace
with 30 observer read brackets, and checked early-quiesce rejection,
bad-R1 blocking, active read failure,
and no reads in the main-owned interval. Source SHA-256: `kh2_worker.c`
`8d0123922018fc7e3e56539f6e6e2de6152064838e4fc054a2f2f2071b4ccf9f`,
`kh2_worker.h`
`61606cbcaeb2003f1ab18ff46f58ea75a5ef5a7499a63173e757b7b67cd1b921`.
The worker host-test source SHA-256 is
`7a4ad81dfa58ca6e271784808692562367008a3baf2ce7303505bbc7bdd0679c`.
The worker source cross-compiled as a PS5 SDK object. The callback bridge
below now supplies linkable pinned-CPU/pipe/log functions, but there is no
12.02 chain integration or console run.

The local `kh2_main_capture.c/.h` adds B0/B1/B2/A2/D2 readback production
through supplied kernel-read, SHA-256, and log callbacks. Its supplied write
callback and read callback now use at most `0x500` bytes per attempt. Each
main-thread read emits `KH2R begin` before the callback and `KH2R done`
after it returns success; a returned error emits `KH2E operation=read`.
A failed `begin` send prevents that read. These markers name an unresolved
address if a read or following log send does not finish, subject to PC
transport retention. The extra sends can lengthen the patched-gate window;
their runtime cost has not been measured on a console. The supplied write
callback stages B1 in `0x500`-byte calls. B2 requires the four context
qwords first, all 16 IST6 qwords second, then separate high and low gate
qword writes (`11` #40–#41). A failed callback emits `KH2E operation=write` with its attempted
address and blocks the
success record. The A2 wrapper writes the selected IST6 and armed journal
word in the main-owned interval; the D2 wrapper restores the native gate's
high and low qwords separately,
all 16 IST6 words, three B1 spans, and B0 scratch after the worker stops.
Their failed callbacks also emit `KH2E` and block further wrapper writes.
Every B1/B2/A2/D2 callback is bracketed by `KH2W begin` and `done` log
attempts. The producer waits for `begin` send to return before the write;
its failure stops the write. A missing `done` cannot by itself prove where
the console stopped because PC retention is separate from a send return.
It captures each B1 span's prewrite hash, verifies the staged/readback bytes,
and later checks **all three** restored span hashes at D2 alongside the B0 scratch
baseline (`11` #33). The image B1 record now bounds all four later context
qword writes, and A2 requires its armed-state address inside the B1 journal
span, away from marker words (`11` #34). A2 also reads all 16 IST6 qwords,
links its arm-image hash to B2, and reports the first CPU with a pointer
mismatch before permitting the second trigger. The main host check rejects both
out-of-span cases. `kh2_main_host_test.py` combined seven native main
milestones with 11 records from a separate worker mock into a classifier-accepted
transcript with 18 KH2 milestones, 98 write brackets, and 170 read brackets.
An un-restored journal and a changed nonselected IST6
pointer were rejected at D2 and A2 respectively. Injected B1/B2/A2/D2 write
failures produced `KH2E` without their success records, and retries were
rejected. A context-write failure left the gate unwritten; separate injected
high- and low-qword failures reported the corresponding gate address. The
host check verified the successful B2 write order. It paired 49 write attempts in a
complete transcript
and 85 main-thread read attempts; it rejected failed `begin` sends before
either callback type ran. The updated combined host test pairs 15 bounded
observer reads as well, for 100 paired reads total; its source SHA-256 is
`5bb95743fa44939b5f520f7c8218418646e26d6fac6e7257557b1eb31ce1d61f`.
This verifies format and baseline linkage across
two mock processes, not a same-attempt
console trace. Source SHA-256: `kh2_main_capture.c`
`1f82a4e36d3d2eb802fbaab2063a77f8cb4be0de89bbc1c52e12a4783cb799b2`,
`kh2_main_capture.h`
`f31a10c6e3a0274943dde6ea8d445f894a13d6a7f4e93262fb3cd2a775f74696`.
The C source cross-compiled as a PS5 SDK object. No 12.02 payload invokes
this producer.

The off-tree `kh2_ps5_adapter.c/.h` now binds the main read/write callbacks
to chunked SDK `kernel_copyout`/`kernel_copyin`, the worker read to `observer_channel_read`,
and the send callback to `ps5log_line`; worker prepare/finish pins and checks
the observer CPU and opens/restores its separate pipe. `kh2_sha256.c/.h`
supplies the missing SHA-256 callback without relying on the SDK's
unresolved `_libmd_SHA256_*` symbols. Its 17 host vectors, including SHA
padding boundaries and a million-byte input, matched Python `hashlib`.
`kh2_ps5_adapter_host_test.py` also linked a PS5 SDK smoke ELF containing
the bridge and all KH2 capture/worker/main modules. Source SHA-256:
`kh2_ps5_adapter.c` `f1ca2571532332e01a0a2ece0343c535d8f0854d97fdab67912cbf27c19c2f75`,
`kh2_ps5_adapter.h` `67eaa92529f629a677264dc562489f452b646360f6fcba46cc96cd66152e1e66`,
`kh2_sha256.c` `973d80697bc965d4bf9ed86456dac5ceb33400810425154328f572855cd5ec64`,
`kh2_sha256.h` `cd45c004b36a8b99bf88f73b9517425a6a7e6ea2df5d2d93c214dff7c36e8e28`.
This proves host hash agreement and SDK linkability only: it does not
exercise a PS5 read, logger session, shared-resource handoff, or a #DB.

[verified-in-tree] The off-tree `kh2_ps5_adapter_runtime_host_test.py`
compiles the actual adapter against temporary host stubs and runs
`kh2_ps5_adapter_runtime_host.c:98-143`. It checked `0x1000`/`0x800`
SDK chunks for a `0x1800` read and write, rejected main/worker calls on
the wrong CPU or before worker prepare, opened the separate pipe only after
observer pinning, propagated MARK/ERR send success and failure, retained
`prepared=1` after a failed pipe close, and avoided opening a pipe after a
pin failure. Run it with:

```sh
python3 kh2_ps5_adapter_runtime_host_test.py \
  --ps5log /path/to/logging_server/client
```

The harness C source SHA-256 is
`fe05d942772d1ae3a10bbc681a9ed199f98bb7745ec8c7160d775a20cd9bac4a`;
the Python wrapper SHA-256 is
`a21f360c1794665d78cd3a6b60f169a3966fadfb15a950b261bf6ba59734c883`.
These are callback and state checks under host stubs; they do not exercise
the SDK kernel primitive, actual CPU affinity, the PS5 pipe, or PC retention.

`kh2_integrated_host.c` then ran the actual main emitter and pthread worker
in **one host process** over one mutex-protected mock memory image and
ordered log. Its callbacks reject a read, send, or main staging write by
the wrong owner. The `kh2_integrated_host_test.py` check, pointed at this
notes checkout with `--notes-repo`, classified 20 complete attempts with
18 KH2 milestones, 98 `KH2W` lines, and 200 `KH2R` lines each (170 main,
30 observer). No callback-owner
violation or stage-order conflict occurred; a journal left changed
was rejected at D2. Source SHA-256: `kh2_integrated_host.c`
`8a3632b8d4da5eba624e369010084cfa9ec3bf1d2d32824752f7aaa8b488efbe`,
`kh2_integrated_host_test.py`
`8a87511ade0c5770051ed7ded79e4c46363f818e67330e6bb14f8e68053d33db`.
The two mock kernel events set frame/journal bytes directly; they are not
hardware traps or a PS5 SDK/log transport test.

[inference] The local prearmed worker's `observer_channel_read` uses the
inherited SDK `kernel_copyin` primitive to configure its separate pipe
(`engineering/payloads/byepervisor_probe_1202/observer_channel.c:65-75`),
so a second pipe alone does not permit concurrent main-thread kernel R/W.
The client header explicitly says `ps5log` is not thread-safe
(`engineering/homebrew_ps5/projects/logging_server/client/ps5log.h:31`).
For the two-trap KH2 proposal, main and observer must hand off ownership of
both resources around the arm return and the later test syscall. A verified
replacement with independent primitives and a thread-safe logger would
falsify this scheduling requirement for that replacement; the current
implementation has neither. Captured stdout shares the log socket, so
`printf` during worker-owned sampling must also be deferred or serialized
(`11` #32, `17` handoff schedule).

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
