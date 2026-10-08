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
