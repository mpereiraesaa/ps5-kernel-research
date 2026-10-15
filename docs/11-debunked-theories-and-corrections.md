# 11 — Debunked theories and corrections register

The lab's institutional memory of **things we got wrong**, so no agent
or researcher repeats them. Every entry: what the theory was, why it
looked plausible, how it was falsified or retracted, its evidence class,
and the lesson. Format per `AGENTS.md`: corrections are first-class
contributions.

Labels follow `README.md` (`[verified-in-tree]`, `[public-consensus]`,
`[inference]`) plus the console-practice labels used in `docs/10`
(`[verified-on-console]`, etc.).

## Register

| # | Debunked claim | Verdict | Evidence |
|---|---|---|---|
| 1 | XOM moved from guest-PTE to NPT across FW history | **WRONG** — NPT enforcement existed from the start; only the *route* changed | [verified-in-tree] `03-evolution-pre761.md` |
| 2 | Sign-frame `mc_gsbase=0` clobbers GS → errno-TLS fault → ring-0 freeze (#70) | **FALSIFIED** on-console 2026-10-13 | [verified-on-console] `10`, `07` |
| 3 | `START_RIP_OFF = 0x4DF` | **WRONG** — D/E hex typo; real 0x4EF, re-derived 0x551 | [verified-on-console] `10` §419 |
| 4 | CR4 dump-scan: SMEP/SMAP at bits 7/8 (`0x45da0` = SMEP\|SMAP\|OSXSAVE) | **RETRACTED** — real bits 20/21; dump value was boot garbage | [verified-on-console] `09`, `08` |
| 5 | Level-2 offset pin from the 13.60 header table | **WRONG** for a 12.02 console — live deltas are `12_02.h` | [verified-on-console] `10` §458 |
| 6 | E-TMR register read has "zero crash risk" | **WRONG** — retracted (NPT governs the kernel too; device MMIO panic class) | [inference] `09` §184 |
| 7 | A `m`-reply starting `E…` is a GDB error | **WRONG** — client bug; stub never sends E-replies for `m` | [verified-on-console] `10` §495 |
| 8 | The stub "crashes" on connect | **WRONG** — connecting to zombie listeners, not stub bugs | [verified-on-console] `10` §318 |
| 9 | The original stub failure was `sysarch` GS base = 0 | **WRONG root cause** — zombie ports; the fixes were kept anyway | [verified-on-console] `10` §332 |
| 10 | `cpu_stdext_feature` = the dword adjacent to the CPUID cluster (`0x6799`) | **WRONG** — has INVPCID (impossible on Zen 2) | [verified-on-dump] `10` §137 |
| 11 | `fsgsbase_enable` CR4 write via a kernel-data boot candidate | **WRONG** — candidates never stable across boots | [verified-on-console] `10` §135 |
| 12 | `vm_map` gating is a valid oracle for the static image | **WRONG** — the static image has no vm_map entries | [verified-in-tree] `07` §153 |
| 13 | "FACS wake vector at phys `0x9bf60` is all-zero → PS5 has no FACS wake" | **WRONG ADDRESS** — `0x9bf60` is `PM1a_EVT_BLK`; FACS is `0x7fd6e000` | [verified-on-dump] `12` §1, `09`, `10` |
| 14 | `acpi_sleep_machdep+0x18e` is a valid #DB breakpoint in the resume window | **WRONG** — `0x18e`=398 B exceeds the function's compiled size | [verified-in-source] `12` §2, `09`, `10` |
| 15 | "No `.data` pointer to the ACPI strings ⇒ PS5 dropped/renamed the event path" | **WRONG** — references live in un-dumped `.text`, not `.data` | [verified-on-dump] `12` §3 |
| 16 | The resume trigger is a **#DB breakpoint** at `acpi_sleep_machdep+0x18e` | **WRONG KIND** — the public loader triggers via a kernel-data **`AcpiGbl_FACS` self-corruption → #GP** (IST6), no breakpoint; `+0x18e` also invalid (#14). | [verified-in-source] `15` §1 |
| 17 | The public loader's `ACPIGBL_FACS` offsets can be used on 12.02 | **WRONG METHOD** — loader is a different link coordinate (`KERNEL_TEXT=…80210000`) and tops out at 7.61; transfer is invalid. Use the dump-derived `kdata+0x2cb4c80`. | [verified-on-dump] `15` §2–§3 |
| 18 | The 13.60 IDT/TSS are at data-file offsets `0x2234300`/`0x2236fe0`, and matched syscalls imply `+0x6a340`/`+0x6a328` 12.02 code shifts | **WRONG COORDINATES** — the data-file offsets are `0x2ef4300`/`0x2ef6fe0`; the declared 735 sysent pairs yield `+0xadd70`/`+0xadd58` under dump-specific text bases. The old offsets subtracted the `0xcc0000` text size twice. | [verified-on-dump] `16` cross-dump audit |
| 19 | The 12.02 dump's shared v1/v9/v13/v179 `add_rsp_iret` target proves Sony's native dismiss-stub layout | **WRONG BASELINE** — the owner confirms kstuff was running during the dump. A later live read-only audit reported four distinct targets and IST0 for v9/v13/v179; the 2026-10-15 full census independently reproduced that map. Neither snapshot alone proves pristine firmware state. | [verified-on-console] `16` gate-state audit; `17` §complete live census; [verified-in-tree] `r0gdb/prosper0gdb/offsets/12_02.h:12-14` |
| 20 | The #DB chain can run on #GP with an otherwise identical entry frame | **WRONG FRAME ASSUMPTION** — #GP supplies an error code; #DB does not. No 12.02 #GP chain or return has been validated. | [public-consensus] [AMD64 APM Vol. 2 §§8.2.2, 8.2.14](https://docs.amd.com/v/u/en-US/24593_3.44_APM_Vol2); [verified-in-tree] `docs/16-byepervisor-12-02-port.md:117-120` |
| 21 | A working page-table alias walker validates named `DMPML4I/DMPDPI/PML4PML4I` globals | **WRONG IMPLICATION** — the walker discovers and follows page tables without reading these fields. Two 12.02 captures now locate `DMPML4I/DMPDPI` and validate their values against the observed dmap base; `PML4PML4I` remains a same-region candidate pending a recursive-entry check. | [verified-on-dump] `17` §paging-index data globals; [verified-in-tree] `16` field-map correction |
| 22 | The first TSS row necessarily belongs to the CPU running a probe | **WRONG ASSUMPTION** — both archived 12.02 captures and the 2026-10-15 live census contain 16 PCPU records with `pc_cpuid=0..15`; each record's two TSS pointers identify its own TSS row. A probe on CPU `i` must follow that mapping rather than select row 0. | [verified-on-dump] `17` §complete archived IDT/TSS census; [verified-on-console] `17` §complete live census |
| 23 | A zero scan plus scratch frame readback/restore establishes a ready `DATA_CAVE` | **OVERCLAIM WITHDRAWN** — the frame-setup run proved its selected scratch bytes could be staged, read back, and restored, but it did not record the required span's actual leaf mapping and permissions, marker persistence, or full-span zero restoration. Those conditions were established later for one boot and the `0x5000`-byte 12.02 candidate by the separate 2026-10-15 cave-only run. | [verified-on-console] `16` §frame staging isolation; `18` §completed cave validation |
| 24 | The 13.60 donor `DATA_CAVE=0x2d39000` projects to the 12.02 scratch candidate `kdata+0x2099000` after subtracting `0xcc0000` | **WRONG ARITHMETIC AND CROSS-FIRMWARE INFERENCE** — `0x2d39000−0xcc0000=0x2079000` in the 13.60 kdata coordinate. The 12.02 `+0x2099000` candidate was used by historical probes and has a five-page zero run in both archived 12.02 captures; it is not derived from the donor coordinate. | [verified-in-tree] `16` §derived 12.02 data and structure offsets; [verified-on-dump] `17` §capture identity and both archived kdata captures |
| 25 | Sixteen separate IST4 stacks make a global #DB gate safe for a pivot-return probe | **WRONG SAFETY CLAIM** — the 2026-10-15 one-shot image used the *same user RIP and RSP* in all 16 return frames. A foreign CPU would enter on its own stack but could resume an unrelated thread into the selected thread's context. The run stopped after `[ARMED]` without return or cleanup; this does not prove a foreign CPU entered. | [inference] `18` §pivot-return run and the off-Git build's recorded source hashes; [public-consensus] [multicore hook invariants](https://github.com/gzimbric/ps5-hv-bypass-porting/blob/main/docs/multicore-debug-hook.md) |
| 26 | A responsive UI and elfldr imply that a stopped #DB probe's gate/IST state is clean | **WRONG RECOVERY ASSUMPTION** — after the replacement probe stopped at `[PREARM]`, a read-only audit found the gate still targeting the candidate pivot, all 16 IST4 rows staged, and cave scratch nonzero while ping worked. The owner's “yes all good” did not explicitly confirm the hard power cycle; sending the audit before that confirmation violated the recovery plan. | [verified-on-console] `18` §replacement pivot-return image and first run |

## Detail on the load-bearing ones

### #26 — Responsiveness did not establish a clean hook [verified-on-console]

The replacement probe's elfldr response closed before a cleanup marker.
The owner answered “yes all good” to a compound readiness question, and
we incorrectly treated that as confirmation of a completed hard power
cycle. The read-only audit found the candidate `+0x2a82de` #DB gate,
all 16 staged IST4 pointers, and `1359/20480` nonzero scratch bytes.
Ping still worked. No second payload should have been loaded before an
explicitly confirmed hard power cycle. The audit does not show whether
`ICEBP` fired; it shows that kernel hook state remained changed when
the audit ran.
After the owner explicitly confirmed a full power cycle, the same
read-only audit reported the native gate, no staged IST4 pointers, and
zero cave scratch (`18` §replacement pivot-return image and first run).

### #25 — Separate stacks did not isolate return contexts [inference]

The pivot-return image staged one hardware-frame canary and return frame
per TSS row, but every frame contained the selected wrapper's user RIP,
RSP, CS, SS, and flags. The shared vector-1 gate can receive #DB on any
CPU, even when the initiating thread is pinned. The public porting
[multicore rules](https://github.com/gzimbric/ps5-hv-bypass-porting/blob/main/docs/multicore-debug-hook.md)
require other CPUs to have register-neutral passthrough paths and private
state. A foreign entry into this image would violate that requirement.
The actual run reached `[ARMED]` and then stopped without a captured
frame or return; it does **not** identify a foreign entry as the cause.
A same-attempt trace proving only the selected CPU entered #DB would
falsify that explanation for this stop. Do not rerun this exact image;
any replacement must give each CPU a valid isolated return path and an
observation before cleanup can hide a successful return.

### #20 — #GP and #DB entry frames differ [public-consensus]

The earlier `16` port text proposed swapping the #DB hook for #GP and
called the chain "identical otherwise." That was plausible because both
vectors can enter through an IDT gate and a selected IST stack, but it
skipped a processor-supplied stack item: #GP returns an error code
(zero or a selector index), whereas #DB returns none. See the
[AMD64 Architecture Programmer's Manual, Vol. 2, §§8.2.2 and 8.2.14](https://docs.amd.com/v/u/en-US/24593_3.44_APM_Vol2).
The same stack consumption and return sequence cannot be assumed for
both vectors. This is an architectural correction, not a console test;
the selected 12.02 #GP chain remains unvalidated (`16`).

### #19 — A patched dump is not a firmware gate baseline [verified-on-console]

The owner confirms the 12.02 data dump was captured while kstuff was
running. Its v1/v9/v13/v179 gate targets at `ktext+0x2b3626` match the
12.02 `add_rsp_iret` offset (`r0gdb/prosper0gdb/offsets/12_02.h:12-14`).
An earlier `idtdump` snapshot showed the same shared target, but that
does not make it Sony's native #DB/#GP handler. With kstuff reported
absent, the later read-only audit in `16` observed v1 at
`ktext+0x3188b0`/IST4 and distinct v9/v13/v179 targets at IST0.
These observations correct the original "Sony dismisses all four"
claim. [inference] The earlier common target reflects a patched
state; a clean boot with no earlier gate-changing payload that still
shows all four gates at that common target would falsify this.

### #18 — Cross-dump coordinates must be checked against records [verified-on-dump]

The former `16` audit put the 13.60 IDT at data-file offset
`0x2234300`. That location contains unrelated data, while
`0x2ef4300` decodes as IDT gates; the TSS likewise starts at
`0x2ef6fe0`. Byepervisor's text-relative IDT value `0x3bb4300`
must have the `0xcc0000` text span subtracted **once** to become a
data-file offset. Re-reading the 13.60 sysentvec size (`0x2df`) and
its 735 code-pointer entries against the 12.02 table gives 595
offset pairs at `+0xadd70` and 140 at `+0xadd58`, under the
dump-specific text bases recorded in `16`. The earlier reported
`+0x6a340`/`+0x6a328` shifts are retracted. [inference] The 13.60
data dump's clustered gadget pointers appear to be staged chain/frame
residue: the same locations in 12.02 are zero or unrelated. A static
object definition at those 13.60 locations would falsify this reading.

**Lesson**: inspect a purported structure at its calculated data-file
offset and confirm its shape before using it to project code addresses.

### #1 — XOM never "moved" from PTE to NPT [verified-in-tree]

The naive reading was "guest-PTE exec-only on old FWs, NPT later." The
ps5-linux-loader source shows second-level (NPT) enforcement is
**present throughout**; what changed per FW family was only the route
used to reach and defeat it (TMR+IOMMU → `hv_unmap_pt_tmr` →
APICBASE HV-entry → closed at 8.00+). See `03-evolution-pre761.md`.

**Lesson**: a changing *attack route* is not evidence of a changing
*protection model*. Derive the model from the enforcement mechanism,
not from what a given exploit tool happened to use.

### #2 — The GS-base freeze theory is falsified [verified-on-console]

**Theory** (pre-#70): the PS5 signal frame carries `mc_gsbase=0`; the
ring-0 entry passes through the kernel's sigreturn; if that restore
clobbers the thread's GS base, the SDK libc's errno-TLS access faults,
the nested SIGSEGV hits the session, and the handler/flag interaction
freezes the session holding the patched IDT/TSS window open.

**Why it looked plausible**: the repo already documented
`mc_gsbase=0` in the signal frame and had a `NO_SYSARCH_GSBASE` guard
for exactly this symptom class; the freeze was ~100-250 ms in (after
early syscalls), timing that fits a first-failing-syscall TLS fault; and
build-invariance / level-1-exemption / Oct-9-survival were all
consistent.

**Falsification (2026-10-13, build `cbd34cbd…`)**: the entry fault
frame was captured on-console via the new `qDiagF4` query and decoded
to `mc_flags=0x5` — `_MC_HASSEGS` set, **`_MC_HASBASES` clear** — with
`mc_fsbase==mc_gsbase==0`, `cs=0x33`, `ss=0x2b`. FreeBSD
`set_mcontext` (`machine/ucontext.h`) restores `mc_fsbase`/`mc_gsbase`
**only when `_MC_HASBASES` is set**. It is clear, so the entry's
sigreturn does not touch the GS base from `mc_gsbase=0`: the
GS-clobber link cannot fire. With `fsbase==gsbase==0`, the "wrong TLS
register" variant is moot. **The freeze still recurred on the same
run**, so #70 did not fix it.

**Consequences**: fix #70(a) (GS restore) is inert on this path; #70(b)
(park instead of spin) is client-indistinguishable from the old spin
and may mask a real fault. The freeze is a genuine hang that is neither
the GS→TLS chain nor the busy-spin, and remains unexplained — prime
suspects are a session-lock/mailbox deadlock in the entry-handler path
or `r0gdb_cleanup`'s `run_in_kernel` MSR step.

**Lesson**: before assuming a signal-frame field drives behavior,
verify the `mc_flags` gate that decides whether the kernel *reads* it.
"Field is zero in the frame" ≠ "kernel uses the zero."

### #13–#15 — Three ACPI static-anchor errors, one shared lesson [see `12`]

The resume route (`10`) hinged on three "facts" that were never checked
against the object they described. Each had a cheap offline falsifier,
and none was ever run before console risk. Full detail in
`12-acpi-static-anchor-corrections.md`.

- **#13 — wrong FADT field.** The FACS was claimed at phys `0x9bf60`
  "from X_FIRMWARE_CTRL at +0x40." ACPI puts `FIRMWARE_CTRL` at
  `+0x24` (`X_FIRMWARE_CTRL` at `+0x84`); `+0x40` is `PM1a_EVT_BLK`.
  The dump's populated FADT gives `FIRMWARE_CTRL = 0x7fd6e000`
  (`X_FIRMWARE_CTRL = 0`). So the all-zero `0x9bf60` read tested the
  PM-block base, not the FACS — the "no FACS wake" NOOP is invalid and
  the real FACS (`0x7fd6e000`) is an **untested** lead.
- **#14 — off-the-end breakpoint.** `acpi_sleep_machdep+0x18e` (398
  bytes) exceeds what that function can compile to (crude `-O0`
  upper bound `0x10e`; `-Os` lower bound 12 B). The offset is not
  inside `acpi_sleep_machdep` for any layout near FreeBSD 11.0. The
  resume *window* is real; the *instruction* is unverified.
- **#15 — misread absence.** "No `.data` pointer to the ACPI event
  strings" was read as "PS5 dropped/renamed the path." In FreeBSD 11
  those names are string literals referenced from `.text`; a data-only
  dump cannot see them. Absence of a pointer in a partial dump is
  evidence of nothing.

**Shared lesson**: derive a constant from the object it indexes (`+N`
from the *same* table/function), never transcribe a neighbouring field
or an offset whose containing symbol you never sized. All three would
have been caught by one structural cross-check before touching the
console. Reinforces #3 (`START_RIP_OFF` typo) and #4 (CR4 bit scan):
**measurement beats interpretation, and the cheapest measurement is the
one you do offline.**

### #16/#17 — The resume trigger's *kind*, and one cross-FW transfer trap

The route was described as "arm #DB at `acpi_sleep_machdep+0x18e`".
Fixing the offset (#14) was not enough: the **mechanism itself** was
wrong for the public lineage. Full detail in
`15-facs-global-resume-trigger.md`.

- **#16 — wrong trigger kind.** 5.00–7.61 do not arm a breakpoint. They
  corrupt the ACPICA global `AcpiGbl_FACS` pointer in kernel data
  (`kwrite64(ktext+ACPIGBL_FACS, self−8)`), so the kernel's own
  `AcpiSetFirmwareWakingVector` dereferences the mangled pointer on resume
  and takes a **#GP** (IDT 13 + TSS IST6). No `acpi_sleep_machdep`
  instruction is involved. The `#DB`/`+0x18e` plan was our own invention.
- **#17 — cross-firmware offset transfer.** The loader hardcodes
  `KERNEL_TEXT = 0xffffffff80210000` and only covers ≤7.61; our dump's
  kernel-text base is `0xffffffff884c0000` and the firmware is 12.02. Its
  `ACPIGBL_FACS` values are mechanism evidence only, never a 12.02 offset.
  The dump-derived anchor is `kdata+0x2cb4c80` (the sole pointer to
  `dmap+FACS_phys`; `15` §2).

**Shared lesson**: a "place to break" is not the same as "the way the
firmware faults". Verify the *mechanism class* against a source that
actually ran on a firmware lineage before transferring any address; and
never move an offset across a firmware family without a same-firmware
anchor. This is the same failure family as #13/#14 (a plausible-looking
constant carried forward without a same-object check) and #5 (a header
table used on the wrong firmware).

### #3/#4 — Two lab-wide "measurement beats interpretation" lessons

`START_RIP_OFF` (#3) and the CR4 bit scan (#4) share one lesson:
**prefer a structural derivation plus a live cross-check over a
human-transcribed constant.** #3 came from transposing hex digits
(`4DF` vs `4EF`); the fix is to derive the offset from the disassembly
(the `call dbg_enter` return address) and confirm `base+VERIFY_OFF`
matches the ELF bytes. #4 came from reading CR4 bit positions off an
unreliable dump qword; the behavioral SMEP proof (CPL0 fetch of a user
page → #PF) stands and was always the trustworthy signal.

## Process notes

- The two 2026-10-12 failure classes must never be conflated again: the
  Oct 9 **panic** was a SMEP `#PF` *during* a step; the 2026-10-12
  **freeze** was *before any step*. See `10` §543+.
- Every kernel-behavior claim carries a label; corrections record both
  the wrong claim and the falsifying observation (per `AGENTS.md`).
