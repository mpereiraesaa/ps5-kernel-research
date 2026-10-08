# 07 — Console evidence log

Chronological record of console experiments. Format per `AGENTS.md`:
date, FW, payload identity, expected observation, actual observation,
recovery state. Epistemic label: `[verified-on-console]` (see README).

## 2026-10-08 — kdata_probe (route step 1, first validation)

- **Payload**: `engineering/payloads/kdata_probe/kdata_probe.elf`
  — sha256 `16d378f3e8eea94b7c0fb7a5a252167426c5d32cea5d106ae990d4a31d901327`,
  113,504 bytes.
- **Delivery**: elfldr TCP 9021 (`send_elf.py --wait-response
  --expect-response "kdata_probe OK"`). Response verbatim on the same
  socket.
- **FW**: `kernel_get_fw_version() = 0x12020000` (12.02).

### Expected

- `fw=0x12020000`; non-null SDK-resolved `KERNEL_ADDRESS_*`;
  `kernel_copyout` of one page at `allproc` returns 0; 16 bytes readable
  at the ps5debug-NG FW 12.x kpatch address with byte[1] bits 0b11 set
  (jailbreak applied state).

### Observed [verified-on-console]

```
kdata_probe fw=0x12020000
ktext_base  =0xffffffffd7750000
kdata_base  =0xffffffffd84a0000
allproc     =0xffffffffdad25e00
prison0     =0xffffffffda3c29f0
rootvnode   =0xffffffffdb577510
sec_flags   =0xffffffffd9223064
utoken_flags=0xffffffffd92230f0
qa_flags    =0xffffffffd9223088
proc_p_pid_off=0xbc
copyout allproc page rc=0
(allproc page hexdump: kernel heap pointers 0xffffa465..., kernel
 image pointers 0xffffffffd88fb9bf / 0xffffffffd88d18f3, zeroed tail)
copyout kpatch rc=0
ffffffffd9223088  00 03 01 00 00 00 00 00 00 00 00 00 00 00 00 00
kpatch byte[1]=0x03
kdata_probe OK
```

### Cross-checks

- **SDK 12.x table matches live memory** [verified-on-console]:
  `allproc − kdata_base = 0x2885E00` and
  `ktext_base − kdata_base = −0xD50000` — both equal the SDK
  `crt/kernel.c` FW 12.x entries.
- **ps5debug-NG kpatch target is `.data`** [verified-on-console]:
  `kdata+0xD83088 = 0xffffffffd9223088 = security_flags (0xffffffffd9223064) + 0x24`
  — the FW 12.x kpatch target lies inside the security-flags area, deep
  in `.data`, as claimed in `02-xom-npt.md`.
- **Jailbreak data-flag state** [verified-on-console]: kpatch byte[1] =
  `0x03` — bits 0b11 set; matches ps5debug-NG's "already set by
  jailbreak" branch. The probe did not write it.
- **allproc page plausibility** [inference]: the page contains kernel
  heap pointers and pointers into the kernel image range — consistent
  with the `proclist` head region. No semantics were assumed; the full
  dump + structural derivation (route step 1 remainder) will verify.

### Recovery state

Probe is read-only; no kernel memory written; no restore needed;
console untouched.

## 2026-10-08 — kdata_dump sequential read: KERNEL PANIC (negative result)

- **Payload**: `engineering/payloads/kdata_dump/kdata_dump.elf`
  (sha256 `91e4a0756aea89fc8f83924f257e8ec8d51c1963f77f890203a185577ed5b7f6`,
  file-mode build), sent via elfldr 9021, FW 12.02.
- **Expected**: sequential `kernel_copyout` of 134 MiB from `kdata_base`
  in 4 KiB pages, with unmapped pages failing gracefully and being
  counted as zero-filled holes.
- **Actual**: dump progressed normally (holes=0 for the first ~28+ MiB
  observed; 1 MiB writes to `/data/homebrew/kdata_dump.bin` healthy),
  then the console suffered a **kernel panic and powered off** mid-run.
  No title was running; the payload never wrote kernel memory; the
  partial `/data` file is harmless (next run opens `O_TRUNC`).
  Recovery: normal boot; the whole kstuff chain reloads at boot.
- **Finding** [verified-on-console, negative]: the kstuff loader-pipe
  `kernel_copyout` primitive is **not fault-tolerant on unmapped kernel
  addresses** — reading past the mapped extent of the data segment
  page-faults the kernel in the corrupted-pipe read path and panics,
  instead of returning an error. "Hole-tolerant" sequential dumping
  across unknown-mappedness memory is unsafe with this primitive.
- **Root cause of the attempt**: the design assumed graceful failure
  from prior field evidence — but that evidence (kdata_probe, Lapy,
  porting_tool) only ever exercised *mapped* pages. This experiment was
  exactly the crash-risk class `AGENTS.md` requires explicit owner
  approval and a recovery plan for; the recovery plan existed (reboot,
  nothing at risk) but the crash-risk itself was under-assessed.
- **Fix**: panic-safe dumping must gate every page through a guest
  page-table walk first (PML4 of the kernel pmap, PTEs read through the
  direct map — itself mapped memory) and only `kernel_copyout` pages
  whose PTE is present; everything else is a recorded hole. This also
  yields the exact mapped extent of the data segment.
- Also observed the same session: outbound `connect()` from the elfldr
  payload context is dead across the board (router, console-local,
  PC targets all ETIMEDOUT; `payloads/port_probe/`), while inbound
  listeners keep working — hence the /data + FTP-pull transport
  (`kdata_fetch.py`). Root cause of the outbound breakage still unknown;
  ps5log-based payload runs connected fine earlier the same morning.

## 2026-10-08 — port_probe: outbound connects dead from payload context

- **Payload**: `engineering/payloads/port_probe/port_probe.elf`,
  read-only, FW 12.02, elfldr 9021.
- **Observed** [verified-on-console]: blocking `sceNetConnect` from the
  elfldr payload context to **every** target timed out (errno 60): PC
  9300 (ps5logd, listening, had accepted console connections the same
  morning), PC 9301, router 53/80, console-local 3232. PC-originated
  connections to the console (elfldr 9021, ftpsrv 2121) work fine.
- ufw on the PC is **inactive** (Status: inactive, 2026-10-08) —
  exonerated. PC Wi-Fi (wlp0s20f3) active; PC↔console ICMP works.
- **Status**: unresolved; suspected console-side sceNet/outbound state
  degradation after the morning game session. The /data + FTP transport
  bypasses it (inbound only).
