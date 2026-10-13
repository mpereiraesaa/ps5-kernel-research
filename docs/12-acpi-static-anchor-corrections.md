# 12 — ACPI static-anchor corrections (resume-window route)

Status: offline corrections, 2026-10-13. No console work was performed
for anything in this document — every claim is derived from the local
kernel-data dump and free/public sources. Read this before re-deriving
any `acpi_sleep_machdep` / FACS / resume anchor for the HCALL 0x0f
route (`10-hcall-resume-window-and-noops.md`).

These three items correct earlier claims in `09` and `10`. They are
recorded here **and** the source lines were fixed in place (per the
correction policy in `AGENTS.md`), so a stale number cannot be copied
forward.

## 1. The FACS wake vector is at phys `0x7fd6e000`, not `0x9bf60` [verified-on-dump]

**Old claim** (`09` §"ACPI tables", `10` NOOP catalog): "FACS at phys
`0x9bf60`, from FADT X_FIRMWARE_CTRL at +0x40"; the alias read at
`0x9bf60` was all zero.

**What is actually true.** From the local `kernel-data.bin`
(140509184 bytes = `0x8600000`, base `kdata = 0xffffffff89210000`; file
offset == kdata-relative offset — see §4), the populated FADT (signature
`FACP` at file `0x7604000`, length 268, rev 5, OEM `"SIE"`) reads:

| FADT field | offset | value |
|---|---|---|
| `FIRMWARE_CTRL` (FACS pointer, 32-bit) | `+0x24` | **`0x7fd6e000`** |
| `DSDT` (32-bit) | `+0x28` | `0x7fd89000` |
| `PM1a_EVT_BLK` | `+0x40` | `0x9bf60` |
| `X_FIRMWARE_CTRL` (64-bit) | `+0x84` | `0x0` |
| `X_DSDT` (64-bit) | `+0x8c` | `0x7fd89000` |

Our own dump disassembly confirms the confusion source: **`0x9bf60` is
the `PM1a_EVT_BLK` value at `+0x40`, not the FACS.** The FACS pointer is
`FIRMWARE_CTRL` at `+0x24` = `0x7fd6e000`; `X_FIRMWARE_CTRL` is zero, so
the 32-bit field is authoritative. All four embedded `FACP` copies in
the dump agree (the 276-byte copy at `0x2cb4b15` also gives
`FIRMWARE_CTRL=0x7fd6e000`).

**Consequence.** The "FACS wake vector" NOOP was tested against the
**wrong physical address** (`PM1a_EVT_BLK`, which is not required to
contain a wake vector). It is therefore **not** a debunk — it is an
untested lead with the wrong address. The real FACS is at phys
`0x7fd6e000`; one alias read of `+0x0C` (32-bit) / `+0x18` (64-bit)
would reveal whether the firmware populates a wake vector. `0x7fd6e000`
lies well above the dump window (`0x8600000`), so it is only reachable
via the alias engine, exactly as previously planned — just at the right
address.

**Lesson.** When a spec field "at +N" is empty, re-derive `N` from the
same table you are reading. ACPI's `FIRMWARE_CTRL` is at `+0x24`
(`X_FIRMWARE_CTRL` at `+0x84`), not `+0x40`. Reading a neighbouring
PM-block field as the FACS pointer produced a plausible-looking but
meaningless all-zero read, which was then over-interpreted as a firmware
design fact.

## 2. `acpi_sleep_machdep+0x18e` does not point inside the function [verified-in-source]

**Old claim** (`09` §"Consequence for the route", `10` launch-chain step
2): "arm #DB at `acpi_sleep_machdep+0x18e`". Presented as an
owner-supplied breakpoint offset.

**What the public source shows.** FreeBSD 11.0
`sys/x86/acpica/acpi_wakeup.c` (`sys_x86_acpica_acpi_wakeup.c`) defines:

- `acpi_sleep_machdep()` — 67 source lines: guard, `intr_suspend`,
  `savectx`, AP suspend, `AcpiEnterSleepState`, then an infinite
  `for(;;) ia32_pause();` resume point.
- `acpi_wakeup_machdep()` — 42 source lines: the disabled-interrupt
  resume block (`pmap_init_pat`, `initializecpu`, `lapic_xapic_mode`,
  `acpi_wakeup_cpus`), `restart_cpus`, `mca_resume`, `vmm_resume_p`,
  `intr_resume`, `AcpiSetFirmwareWakingVector`, then an
  interrupt-enabled block.

**Magnitude check.** `0x18e` = **398 bytes**. A deliberately crude
measurement — compiling just these two functions with stub globals and
`clang -O0` — gives `acpi_sleep_machdep` = **`0x10e` = 270 bytes** and
`acpi_wakeup_machdep` = **`0xda` = 218 bytes** (with full 512-byte
suspended-FPU save/restore calls; `susppcbs[0]->sp_fpu*` are much
smaller in reality, so this is an upper bound). At `-Os` the same
functions are 12 and 50 bytes because the stubs collapse (`savectx`
returns 0, `WAKECODE_FIXUP` no-ops) — a lower bound. The realistic size
is between. **398 bytes exceeds even the fully-inlined `-O0` upper
bound of either function**, so `acpi_sleep_machdep+0x18e` cannot be an
instruction inside `acpi_sleep_machdep` under any layout resembling the
public source.

This is `[verified-in-source]` for the FreeBSD 11.0 function bodies plus
`[inference]` for the byte-size rejection; the rejection would be
falsified only if Sony's 12.02 `acpi_sleep_machdep` were ~40%+ larger
than the fully-inlined public version.

**Consequence.** The `+0x18e` offset is either (a) relative to a
different symbol/base than `acpi_sleep_machdep`, (b) a mis-transcribed
value, or (c) valid only for a different FW build. **Do not arm a #DB at
`acpi_sleep_machdep+0x18e`** until the containing function is identified
from same-firmware evidence. The route's *window* is real (between
`resumectx` and `acpi_wakeup_cpus`); only the chosen instruction is
unverified. Re-derive a breakpoint that actually lands in that window —
the natural candidates are the `intr_resume` / `AcpiSetFirmwareWakingVector`
tail of `acpi_wakeup_machdep`, or a `khv_startup_mp`-adjacent resume
hook — each still requiring a 12.02 text address.

**Lesson.** A disassembly-relative offset is only meaningful against the
function it was measured on. `+0x18e` was carried as fact without ever
checking it against a function body; a 30-second size sanity check
(before any console risk) would have caught it. See register entry #3
(`START_RIP_OFF` typo) for the same failure mode.

## 3. Aligned data pointers to the ACPI strings do not exist — by design [verified-on-dump]

**Old framing** (`09` §"ACPI strings in kernel data"): "No aligned kernel
data pointers to these strings exist (the eventhandler lists are outside
the dump window or use a different naming scheme on PS5)." Re-checked:
scanning all 140 MiB of `kernel-data.bin` for any 8-byte-aligned
little-endian `kdata+off` pointer to each string returns **zero hits** for
`acpi_wakeup: failed to resume AP`, `acpi_wakeup_event`,
`acpi_sleep_event`, `power_resume`, and
`acpi_system_eventhandler_sleep`.

**Why this is expected, not informative.** In FreeBSD 11 the eventhandler
registration (`EVENTHANDLER_REGISTER`) stores the *name* as a pointer to
a string literal **in `.rodata` inside the text segment**, which this
data-only dump does not contain. The event names are not `.data`
objects. So "no data pointer found" says nothing about whether the
events are wired — the reference simply lives in the un-dumped `.text`.
Do **not** use absence-of-pointer as evidence that PS5 renamed or dropped
the ACPI event path.

**Consequence.** The string-address → `.data`-pointer method is dead for
these anchors (it works only for pointers held in `.data`, e.g. the
kobj method tables). Locating `acpi_sleep_machdep` / the resume path on
12.02 needs a `.text` cross-reference or a same-firmware disassembly,
not more `.data` string scanning.

**Lesson.** Absence of a pointer in a partial dump is absence of
evidence, not evidence of absence. Confirm where the reference *would*
live before treating "not found" as a finding.

## 4. Dump-base re-confirmation and offset convention [verified-on-dump]

Re-verified while producing the above, so later work need not re-derive:

- `kernel-data.bin` size = `0x8600000`; base `kdata = 0xffffffff89210000`.
- The sysent table anchor (`sysents` at file `0x1af4d0`, stride 48,
  `sy_call` at `+8`, `sysarch` index 165) lands on `kdata`-consistent
  addresses; **file offset == kdata-relative offset** throughout the dump.
- No symbol table (`acpi_sleep_machdep`, `khv_startup_mp`, etc.) is
  present in the dump — it is a data dump, not a text/symbol image.

## 5. Update (2026-10-13): the resume trigger is `AcpiGbl_FACS`, not a breakpoint

Follow-on work resolved the *kind* of trigger this route needs. The
public loader (5.00–7.61) does not arm a `#DB`; it corrupts the ACPICA
global `AcpiGbl_FACS` in kernel data so the kernel's own
`AcpiSetFirmwareWakingVector` faults on resume (`#GP`, IDT 13 + IST6).
The 12.02 `AcpiGbl_FACS` anchor is dump-derived at `kdata+0x2cb4c80`.
This makes §2's conclusion moot for the trigger path (no
`acpi_sleep_machdep` instruction is needed) while leaving §1 and §2
correct as recorded. See `15-facs-global-resume-trigger.md`.

## Cross-references

- `15-facs-global-resume-trigger.md` — the real trigger kind + the
  12.02 `AcpiGbl_FACS` anchor.
- `09-live-kernel-state-and-fsgsbase.md` — ACPI tables/strings section:
  FACS address and string-pointer framing corrected in place.
- `10-hcall-resume-window-and-noops.md` — launch-chain step 2 and the
  FACS NOOP / "still unknown" section corrected in place.
- `11-debunked-theories-and-corrections.md` — register rows #13–#15.
