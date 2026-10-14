# 15 — The `AcpiGbl_FACS` resume trigger, and the 12.02 global anchor

Status: **historical offline proposal, 2026-10-13; no 12.02 #GP trigger
or return was validated.**
This document corrects the *kind* of resume trigger the HCALL 0x0f route
(`10`) has been assuming, and records a new, dump-verified kernel-data
anchor for FW 12.02. Read it with `12` (anchor corrections) and `14`
(execution substrates). Its suggested substrate remains a design, not a
12.02 console result (`16` §“Our 12.02 trigger”).

## 1. The premise we had, and why it was the wrong *kind* of trigger [verified-in-source]

`10` and `09` describe the route as "arm **#DB** at
`acpi_sleep_machdep+0x18e`". `12` §2 already showed that offset cannot be
an instruction inside `acpi_sleep_machdep`, leaving the mechanism itself
unchecked.

The public loader (`ps5-linux/ps5-linux-loader`) does **not** use a
debug-breakpoint trigger at all. For FW 5.00–7.61 its resume trigger is a
**kernel-data self-corruption of the ACPICA global `AcpiGbl_FACS`**,
paired with a `#GP` IDT gate + IST ROP chain:

- `source/hv_defeat_0607.c:137-140` (FW 6.50–7.61):

  ```c
  // During suspend, AcpiSetFirmwareWakingVector will corrupt its own pointer,
  // and during resume it will trigger #GP, thus executing our ROP chain.
  kwrite64(ktext + env_offset.ACPIGBL_FACS,
           ktext + env_offset.ACPIGBL_FACS - 8);
  ```

- `source/hv_defeat_0506.c:191-194` (FW 5.00–6.02) does the same write.

- The two handlers are installed immediately before it, and are the ones
  the `#GP` lands in (`hv_defeat_0607.c:119-135`): TSS `tss_ist6` →
  a ROP page, IDT vector `IDT_GP` (13) → `GAD_ADD_RSP_28_POP_RBP_RET` with
  IST 6; and `tss_ist7` + IDT vector `IDT_SX` (30, `#SX`) with IST 7.

The `#DB` (`acpi_sleep_machdep+0x18e`) is therefore **our lab's own
invention**, not the loader's mechanism. The loader's trigger is
`[public-consensus]` from its source; our `+0x18e` was never sourced to a
matching firmware.

### What the `AcpiGbl_FACS` write actually does [inference]

`AcpiSetFirmwareWakingVector` (`hwxfsleep.c`) is:

```c
if (AcpiGbl_FACS)
    AcpiHwSetFirmwareWakingVector (AcpiGbl_FACS, PhysicalAddress, PhysicalAddress64);
```

and `AcpiHwSetFirmwareWakingVector` dereferences the passed `Facs` and
writes `Facs->FirmwareWakingVector` (`+0x0C`), `Facs->Length` (`+0x04`)
and `Facs->XFirmwareWakingVector` (`+0x18`). By rewriting the
`AcpiGbl_FACS` **pointer storage** to `(its own address − 8)`, those field
writes alias into the pointer's own 8 bytes and corrupt it. On the
*suspend* call the pointer becomes garbage; on the *resume* call
(`AcpiSetFirmwareWakingVector(0, 0)`, `acpi_wakeup.c:300`) the garbage
pointer is dereferenced → **`#GP`**, → the patched IDT gate → ROP chain.
Source: ACPICA `hwxfsleep.c` / `acpi_wakeup.c` [public-consensus];
mechanism [inference] (it explains the loader's own comment).

**Key property:** the trigger is a single **kernel-data qword write** — no
interactive debug registers, no `gdbstub_main_loop` packet reader, and no
`acpi_sleep_machdep` symbol required. It is exactly the "no packet reader"
substrate `14` recommends, and it removes the `#DB` arming step that `12`
§2 invalidated.

## 2. The 12.02 anchor: `AcpiGbl_FACS` is at `kdata+0x2cb4c80` [verified-on-dump]

We located the 12.02 `AcpiGbl_FACS` global directly from the dump, without
needing `acpi_sleep_machdep` or a text image.

The FADT's `FIRMWARE_CTRL` (`+0x24`) gives FACS phys `0x7fd6e000`, and
`DSDT` (`+0x28`) gives `0x7fd89000` (`12` §1). Scanning the dump for the
dmap mappings of those physical addresses finds exactly one pointer to
each, adjacent in `.data`:

| kdata offset | qword value | target | role |
|---|---|---|---|
| `kdata+0x2cb4c50` | `0xffff89a17fd89000` | `dmap+0x7fd89000` | DSDT table pointer |
| `kdata+0x2cb4c58` | `"DSDT"` `f4 01 00 00` … | embedded DSDT header copy | original-DSDT header |
| `kdata+0x2cb4c80` | `0xffff89a17fd6e000` | `dmap+0x7fd6e000` | **`AcpiGbl_FACS`** (FACS pointer) |

Raw bytes around `kdata+0x2cb4c50`:

```text
0x2cb4c50  00 90 d8 7f a1 89 ff ff 44 53 44 54 f4 01 00 00   ........DSDT....
0x2cb4c60  02 40 53 49 45 20 20 20 50 50 52 20 20 20 20 20   .@SIE   PPR
0x2cb4c80  00 e0 d6 7f a1 89 ff ff 00 10 00 00 60 bf 09 00   ............`...
```

(The `0xffff89a1…` high half is the 12.02 dmap base `0xffff89a100000000`,
same convention as `09`. The FADT/FACS/DSDT physical values all come from
the dump's populated `FACP`.)

**Why this is `AcpiGbl_FACS` and not some other pointer** [inference]:

1. Its value is the dmap mapping of the FACS physical address that the
   **FADT itself names** (`FIRMWARE_CTRL`). ACPICA keeps `AcpiGbl_FACS`
   as a pointer to the *mapped* FACS (it must stay at its physical
   location for the BIOS wake code), so `AcpiGbl_FACS = dmap+FACS_phys`
   is the expected shape. `AcpiTbInitializeFacs` sets it
   (`components/tables/tbutils.c`) [public-consensus].
2. It sits immediately after the DSDT pointer + embedded DSDT header
   copy, which matches ACPICA's global ordering in `acglobal.h`
   (`AcpiGbl_DSDT`, `AcpiGbl_OriginalDsdtHeader`, then `AcpiGbl_FACS`)
   [public-consensus]. The same global cluster is where the loader's
   `ACPIGBL_FACS` offset lands in its own firmware table.
3. It is the **only** dump pointer to `dmap+0x7fd6e000`, mirroring the
   DSDT pointer as the only one to `dmap+0x7fd89000` — the two FADT-named
   tables each get exactly one stored pointer.

4. **Band range (weak, not directional).** Re-expressed in the dump's
   kernel-text coordinate (`ktext = kdata − 0xd50000`), the candidate is
   at `ktext+0x3a04c80`. The loader's per-FW `ACPIGBL_FACS` values span
   `ktext+[0x38b9c50, 0x3a882a0]` (§3); the candidate lies inside that
   *range*. **Caveat:** the loader values *decrease* monotonically as FW
   rises (5.00 `0x3a882a0` → 7.61 `0x38b9c50`), so a firmware newer than
   7.61 should fall *below* `0x38b9c50`; the candidate is instead between
   the 5.00 and 6.00 values. The differing link coordinate and the
   non-continuing trend mean this is at most "in the same region" — it
   neither confirms nor refutes the anchor, and must not be read as a
   directional match. The identification rests on points 1–3 above.

Falsified if: the FADT fields were misread (`12` §1 stands against the
dump), or 12.02's ACPICA is built `ACPI_REDUCED_HARDWARE`/without FACS
(which would leave no such pointer — but one exists).

## 3. Cross-firmware ownership table (loader) and the coordinate caveat

The loader's `ACPIGBL_FACS` (`offsets.h:13`; `KERNEL_TEXT =
0xffffffff80210000`) and per-FW values:

| FW profile | `offsets.c` line | `ACPIGBL_FACS` (link coord) | ktext-relative |
|---|---|---|---|
| `off_0300`…`off_0451` | 5–220 | *(field absent — 4.51 and below use the `hook_call_near` route)* | — |
| `off_0500`/`0502`/`0510` | 226, 268, 310 | `0xffffffff83c982a0` | `0x3a882a0` |
| `off_0550` | 352 | `0xffffffff83c942a0` | `0x3a842a0` |
| `off_0600`/`0602`/`0650` | 394, 436, 478 | `0xffffffff83c04540` | `0x39f4540` |
| `off_0700`…`off_0761` | 522…732 | `0xffffffff83ac9c50` | `0x38b9c50` |

[public-consensus] The 3.00–4.51 `hv_defeat_0304` path instead patches a
call at `HOOK_ACPI_WAKEUP_MACHDEP` (`hv_defeat_0304.c:31`,
`hook_call_near`); `HOOK_ACPI_WAKEUP_MACHDEP` is marked "not needed" from
5.00 onward and `ACPIGBL_FACS` appears instead. The field is literally
absent (not zero) in the ≤4.51 structs — the mechanism *changed from a
text-hook to a data-corruption trigger* across that boundary, which is
itself worth remembering.

**Coordinate caveat.** The loader hardcodes `KERNEL_TEXT =
0xffffffff80210000`; our dump's implied kernel-text base is
`0xffffffff884c0000` (`kdata−ktext = 0xd50000`, `09`/`12` §4). The two
are different link coordinates, and our dump is FW 12.02 (newer than any
loader profile), so **the loader's `ACPIGBL_FACS` offsets must not be
transferred to 12.02**. The dump-derived `kdata+0x2cb4c80` is the
12.02-specific value. The loader table is cited only as mechanism
evidence, not as a 12.02 offset.

## 4. What this changes for the route

- **The trigger is kernel data, not a breakpoint.** `10` step 2 ("arm
  #DB at `acpi_sleep_machdep+0x18e`") can be replaced by: write the
  12.02 `AcpiGbl_FACS` qword (candidate `kdata+0x2cb4c80`) to
  `self−8`, then let the kernel's own `AcpiSetFirmwareWakingVector`
  produce the fault. No `acpi_sleep_machdep` address is needed. This
  matches `14`'s "A3/no-IDT-breakpoint" direction more closely than the
  interactive A0 substrate.
- **The trigger uses `#GP`, not `#DB`.** [public-consensus] The public
  6.50–7.61 loader installs IDT vector 13 and selects TSS `tss_ist6` for its hook
  (`hv_defeat_0607.c:119-127`); `#SX` (30, IST 7) is its
  secondary/first core. This is the loader's selected setup, not an
  observed 12.02 gate layout. [verified-on-console] The later 12.02
  read-only audit found vector 13 at IST0 (`16` gate-state audit); a replacement
  stack and the #GP frame/return contract remain unvalidated (`11` #20).
- **`acpi_sleep_machdep` is no longer load-bearing for the trigger.**
  `12` §2's conclusion still stands (the `+0x18e` breakpoint is invalid),
  but the route no longer needs any `acpi_sleep_machdep` instruction —
  only the `AcpiGbl_FACS` global. Locating the function remains useful
  only as an independent cross-check.
- **`12` §1's "untested FACS lead" is now partly resolved:** the kernel
  holds a dmap mapping of the real FACS phys `0x7fd6e000`, so the FACS is
  mapped and reachable; its `FirmwareWakingVector` (`+0x0C`) is still only
  readable by an alias-engine read at `0x7fd6e000`.

## 5. Falsifiers and what is still unproven

- **Anchor falsifier:** if `kdata+0x2cb4c80` did not move when a
  same-firmware alias read shows `AcpiGbl_FACS` elsewhere (e.g. via a
  controlled `AcpiSetFirmwareWakingVector` observation), the cluster
  attribution is wrong.
- **Mechanism falsifier:** if 12.02's `AcpiSetFirmwareWakingVector`
  null-checks `AcpiGbl_FACS` and the corrupted pointer is never
  dereferenced, no `#GP` fires (the loader relies on it firing).
- **Not claimed:** that the loader's selected IST6/IST7 setup applies
  to 12.02; that the FACS `Length > 32` branch is taken; or that the
  ROP page survives S3 the same way. Those need same-firmware confirmation.
- **Not claimed:** any offset transfer from the loader's coordinate to
  12.02 (see §3).

## 6. Console policy

Nothing here is a console action. A follow-on test *would* be ring-0
(IDT `#GP` gate + TSS IST patch + a kernel-data qword write) and is
**ring-0 risky**: it can panic the console, so it needs explicit owner
approval and a recovery plan per `AGENTS.md`, exactly like the `13` test.

## Cross-references

- `11-debunked-theories-and-corrections.md` — register rows #16 (the
  `#DB`/`+0x18e` *kind* was wrong) and #17 (loader offsets not
  transferable).
- `12-acpi-static-anchor-corrections.md` §2 — the invalid `+0x18e`.
- `14-ring0-execution-alternatives.md` — substrate choice; the
  `AcpiGbl_FACS` route is the non-interactive, no-breakpoint option.
- Loader clone read for this doc: `/tmp/ps5ll` (public
  `ps5-linux/ps5-linux-loader`); ACPICA `hwxfsleep.c`/`tbutils.c` from the
  FreeBSD 11.0 ACPICA snapshot.
