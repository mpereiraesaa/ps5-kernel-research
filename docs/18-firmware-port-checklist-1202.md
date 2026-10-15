# 18 — Firmware port checklist: FW 12.02

Status on 2026-10-15 for the proposed FW 12.02 Byepervisor-Reborn port.
`[x]` means the named requirement has direct evidence at the scope
stated here. `[ ]` means it is missing, only partly demonstrated, or
supported by a candidate rather than a completed observation. A dump
value does not satisfy a **live** value, and a setup-only restore does
not satisfy a post-trigger restore. This is a research status record,
not a claim that the port works.

This audit has **12 checked requirements and 29 open requirements**.
Document numbers below refer to [05](05-toolchain-and-observability.md),
[07](07-evidence.md),
[11](11-debunked-theories-and-corrections.md),
[15](15-facs-global-resume-trigger.md),
[16](16-byepervisor-12-02-port.md), and
[17](17-kernel-data-survey-1202.md).

## Identity

- [x] **Firmware exact value:** `0x12020000` [verified-on-console]. The
  completed live census reported it (`17` §complete live census).
- [ ] **Console model:** the record says owned PS5, but gives no CFI
  model identifier (`README.md` §quick facts). Record the exact model
  before treating model-specific physical bounds as established.
- [ ] **Loader and kernel exploit:** elfldr on TCP 9021 and its elevated
  pipe-based kernel read/write context are documented
  (`05` §deploying; `07` §prosper0gdb live). The exact exploit and load
  sequence that supplied this context are not recorded as a reproducible
  port input.
- [ ] **No automatically loaded payloads:** the owner reported kstuff
  absent for the 2026-10-13 gate audit (`16` §#DB gate-state
  correction), but no current-boot inventory establishes that nothing
  else loaded automatically.

## Coordinates

- [x] **`kdata - ktext`:** `0xd50000` for FW 12.02
  [verified-on-dump] (`16` §cross-dump code-gadget candidates). Applying
  it to the 2026-10-15 live `kdata` gives the handler offsets seen in
  the earlier limited gate audit [inference] (`17` §complete live
  census). This is a coordinate conversion, not a kernel-text read.
- [x] **First independent anchor:** the 12.02 IDT location and decoded
  handler pointers in the kstuff-era data capture constrain the text base
  [verified-on-dump] (`16` §cross-dump code-gadget candidates; `17`
  §complete archived IDT/TSS census).
- [ ] **Second independent anchor:** 735 paired syscall pointers show
  two consistent cross-firmware displacement groups, but their
  text-relative offsets use the already selected dump-specific text
  bases (`16` §cross-dump code-gadget candidates). That is a useful
  cross-check, not a second independent derivation of the 12.02
  `kdata - ktext` gap. A separately measured current-boot text base
  would close this item; disagreement would falsify the conversion.
- [x] **Dump origin, if any:** both 12.02 kdata captures have FW, boot
  base, size, hole policy, SHA-256, and off-Git manifest location
  [verified-on-dump] (`17` §capture identity). The 13.60 donor text/data
  pair and its coordinate convention are identified in `16`
  §cross-dump code-gadget candidates.

## Data-side survey

- [ ] **`allproc`:** `kdata+0x2885e00` is a cross-boot, readable list
  head [verified-on-dump], but the first pointer has not been validated
  by a process-list walk (`17` §static data anchors).
- [x] **Pmap store:** `kernel_pmap_store` at `kdata+0x2e1cfb8` has the
  same structural signature in both 12.02 captures
  [verified-on-dump] (`17` §static data anchors). Its complete Sony
  `struct pmap` layout remains open.
- [ ] **`DMPML4I` and `DMPDPI` live values:** the field locations and
  two boot-specific dump values reconstruct their recorded dmap bases
  [verified-on-dump] (`17` §paging-index data globals). Neither field
  was read in the 2026-10-15 live census.
- [x] **IDT:** `kdata+0x2e88300`, 256 present gates, `0x10` stride,
  exact `0x1000`-byte live read [verified-on-console] (`17` §complete
  live census). Handler values are boot-state dependent.
- [x] **Common TSS:** `kdata+0x2e8afe0`, 16 rows, `0x68` stride,
  exact `0x680`-byte live read [verified-on-console] (`17` §complete
  live census).
- [x] **PCPU array:** `kdata+0x2e9cf00`, 16 exact `0x980`-byte live
  reads; `pc_cpuid` and both TSS pointers were validated for every
  record [verified-on-console] (`17` §complete live census).
- [x] **Cave contents and page permissions:** the 2026-10-15 live FW
  12.02 check read all `0x5000` bytes at `kdata+0x2099000` as zero,
  resolved every covered page through one present, writable,
  supervisor-only, NX 2 MiB leaf, and read back one exact marker per
  page. All five markers survived the owner-operated rest/wake cycle.
  The cleanup ELF removed them and reread all 20,480 bytes as zero
  [verified-on-console] §completed cave validation below. This closes
  the requested one-boot exit condition. It does not establish permanent
  ownership of the pages across future boots or payload sets.

For the historical 16-CPU scratch layout, the proposed 12.02 span is
`kdata+0x2099000..+0x209dfff` (`16 × 0x500 = 0x5000` bytes, five pages)
[inference] from the historical probe's `CPU_COUNT=16`,
`SLOT_SIZE=0x500`, and `SCRATCH_OFF=0x2099000`; a larger active chain
footprint would falsify this as the entire required span.
[verified-on-dump] Both archived 12.02 kdata captures contain five zero
pages there, then populated data in the sixth page. This is an offline
selection only; no live mapping, ownership, or rest/wake result is
established. The FW 12.20 four-page example does not set the 12.02
required span. The donor 13.60 cave coordinate does not translate to
this offset (`11` correction #24).

The evidence record for a new firmware should have this shape. Its
placeholders are separate from the completed 12.02 record below; a
cave result from another firmware does not validate 12.02.

```text
[cave]
fw=<exact reported firmware>
build_sha256=<exact probe build>
coordinate=<kdata-relative offset or absolute VA, explicitly named>
offset=<proposed cave offset>
size=<entire required span>
leaf_coverage=<bytes covered by resolved leaves>/<size>
leaf_mappings=<one record per leaf: VA range, PA base, page size, P/RW/US/NX>
initial_zero_pages=<pages checked>/<pages required>
initial_zero_bytes=<bytes checked>/<size>
write_readback=<passed|failed; exact marker match>
marker_survived_rest_wake=<yes|no|not tested>
marker_cleanup=<passed|failed>
zero_restoration=<passed|failed; entire required span re-read>
recovery=<UI/loader state and any reboot>
```

For the planned rest/wake path, `marker_survived_rest_wake=yes` is
required to accept this cave. A `no` is useful evidence that rejects
the candidate. Keep the raw per-boot record outside Git and cite its
hash when summarizing the result here (`AGENTS.md` §scope and material
boundaries).

### Completed FW 12.02 cave-only diagnostic

[verified-on-console] The owner approved two exact builds and confirmed
console/elfldr readiness. The off-Git stage ELF has SHA-256
`0b3999503095109b414d390465e3d224d8184eee76ca80cd2c98f3492c260dc2`;
the verify/cleanup ELF has SHA-256
`6393299e1def238bc2ece5e430c2af1a5666340b44c3bad167cfb7c318cae4c1`.
Expected observation: five zero pages with a present, writable leaf;
exact marker readback before rest; five matching markers after wake;
then zero restoration over all 20,480 bytes. A pre-write rejection or
missing response would leave the cave item open.
The stage checked FW, kernel bases, a validated page-table root, the
live `0x5000`-byte zero span, and all five leaf mappings before writing
one eight-byte marker in each page. It reported exact full-span marker
readback. The owner then entered Rest Mode and woke the console; the
second ELF found all five exact markers, removed them, and reread all
`0x5000` bytes as zero. The two off-Git responses have SHA-256
`391dfcb136a11182799d744a05bf749dcbc4ad845f767d2bef4a875fa98c6af4`
(stage) and
`1772fc975d19c3d55e8f23d8a558a6e0ba63d8560fdb4a1af7a760b6c3ff91e8`
(verify/cleanup). Both reported `fw=0x12020000`, the same boot's
`kdata` base, and the same physical leaf; the process page-table root
changed between ELFs, as expected. The owner confirmed the UI and
elfldr were normal after cleanup; no recovery reboot was needed.

```text
[cave]
fw=0x12020000
stage_build_sha256=0b3999503095109b414d390465e3d224d8184eee76ca80cd2c98f3492c260dc2
verify_build_sha256=6393299e1def238bc2ece5e430c2af1a5666340b44c3bad167cfb7c318cae4c1
coordinate=kdata-relative
offset=0x2099000
size=0x5000
leaf_coverage=0x5000/0x5000
leaf_mappings=one 2MiB leaf: VA kdata+0x1ec0000..+0x20bffff, PA 0x22200000..0x223fffff, P=1 RW=1 US=0 NX=1 PWT=0 PCD=0
leaf_entry=0x80000000222001e3
mapped_physical_pages=0x223d9000,0x223da000,0x223db000,0x223dc000,0x223dd000
initial_zero_pages=5/5
initial_zero_bytes=20480/20480
write_readback=passed; exact full-span marker image
marker_survived_rest_wake=yes; 5/5 exact, no other changed bytes
marker_cleanup=passed
zero_restoration=passed; 20480/20480 bytes zero
recovery=UI and elfldr normal; no reboot
```

This is a console-risky kernel write: the probe can stall or panic, and
the stage intentionally left markers in the cave until after wake. The
approved recovery plan was to send no further ELF if either stage
stopped without confirmed cleanup, then hard power cycle before a
read-only cave baseline audit. That contingency was not needed: both
ELFs completed and the full-span zero restoration was reported.

## Kernel hook path

- [x] **Complete IDT/TSS census:** the 2026-10-15 read covered all
  256 gates and 16 TSS rows and recorded every IST-using gate and the
  requested vector handlers [verified-on-console] (`17` §complete
  live census).
- [x] **CPU-to-TSS-row mapping:** `pc_cpuid=0..15`; both PCPU TSS
  pointers identify row `i` for CPU `i` [verified-on-console] (`17`
  §complete live census). Selecting row 0 for an arbitrary probe CPU
  is rejected in `11` correction #22.
- [ ] **Prepare-only write/readback/restore:** the changed IST4/#DB
  gate diagnostic read back staged values, then restored and verified
  originals without triggering #DB [verified-on-console] (`16`
  §changed IST/#DB-gate setup isolation run). Its measured scope was
  one selected IST4, the shared #DB gate, and its staged scratch bytes.
  A separate observer calibration reported restoration of its original
  affinity (`16` §separate kernel-read channel calibration). Neither
  record reports authid before/after values or restoration of all 16
  IST4 slots. Thus the stricter combined exit condition—gate, every
  staged IST, scratch, affinity, and authid all restored in the **same**
  prepare-only run—is still open [inference]; a complete same-run
  readback or proof that authid was never modified would resolve the
  corresponding gap.
- [ ] **Pivot-only return:** no completed exception/pivot/return
  marker has been observed (`16` §remaining live-path validation
  boundary).
- [ ] **Complete IRET frame:** six words were staged and read back,
  but the CPU has not been observed consuming them or returning to the
  proposed user RIP (`16` §frame staging isolation; §remaining
  live-path validation boundary).
- [ ] **One-instruction oracle:** the monitored probes did not capture
  a conclusive hardware frame or post-return marker (`16` §remaining
  live-path validation boundary).
- [ ] **Each required gadget accepted:** the 12.02 pivot and DR-restore
  tail are candidates; the full gadget set and entry contracts are
  unverified (`16` §code gadgets still not derived; §remaining
  live-path validation boundary).
- [ ] **Full chain stack layout reviewed:** the staged frame was
  checked in isolation, but no full 12.02 chain has a validated stack
  consumption and return trace (`16` §remaining live-path validation
  boundary).
- [ ] **Per-core isolated paths:** all 16 CPU/TSS links are known;
  per-core hook execution and cleanup have not been demonstrated
  (`16` §remaining live-path validation boundary).
- [ ] **Gate published last:** setup write/readback was isolated, but
  this ordering has not been established for a completed full-chain
  run (`16` §changed IST/#DB-gate setup isolation run).
- [ ] **Stock gate and all IST entries restored:** the prepare-only
  diagnostic restored its selected gate/IST4 and scratch. Restoration
  after exception delivery, across all modified CPU rows, has not
  completed (`16` §remaining live-path validation boundary).

### Retired one-shot pivot-return diagnostic

[inference] The narrow FW 12.02 pivot-return test retargets vector 1 to
the projected `ktext+0x2a82de` `add rsp,0x28; ret`, places the Kstuff
`doreti_iret` address `ktext+0x2b362d` at the resulting stack landing,
and follows it with a complete five-word user IRET frame. The native
gate (`+0x3188b0`, IST4), logical CPU-to-TSS-row mapping, and five-page
zero cave have been measured on the console (`17` §complete live census;
this document §completed cave-only diagnostic). The proposed pivot and
IRET instruction bytes have **not** been measured on FW 12.02 (`16`
§gadget mapping). A different instruction or stack effect at either
address would falsify the planned path.

[inference] The public FW 12.20 ledger labels pivot `+0x2a815e` and
IRET `+0x2b34ad` as hardware-validated
([12.20 manifest](https://github.com/gzimbric/ps5-hv-bypass-porting/blob/main/firmwares/12.20.json)).
Both lie exactly `0x180` below this probe's 12.02 candidates. The
matching delta supports the *offset projection* but does not verify
12.02 instruction bytes or return behavior. A 12.02 instruction trace
or text image showing a different sequence would falsify the projection.

The off-Git ELF has SHA-256
`d3f7dac6a33252591b4e480afbe44250c1ed014607bb3768411d792b0e3f9f30`;
its C and assembly source hashes are respectively
`ee9e69d91c1434f57f6669942fbb42b800f8c689e2ede2ef8793e72d68edcebd`
and
`f8bf7bbfbe66b31a5d4cd986c4b11f32c3db1f590c4c04006472801a958723e3`.
The build passed cross-compilation and an offline check of the 16 disjoint
`0x500` slots, five-word hardware frame, pivot landing, user IRET frame,
and single emitted `ICEBP`. These checks did **not** validate the
per-core return contexts or establish kernel execution.

[inference] The ELF requires a native vector-1 gate, all 16 IST4 values,
and a fully zero `0x5000` cave before writing. It stages and reads back
all 16 images, redirects and reads back all 16 IST4 slots, then publishes
the gate **last**. Its pinned thread executes one `ICEBP`. On return it
records the user continuation, restores and verifies the native gate
**first**, checks the hardware frames, then restores/verifies every IST4,
the entire zero cave, affinity, and unchanged authid. It never writes
authid or DR/CR/MSR state.

Acceptance requires `[RETURN]`, a hardware frame in the selected CPU row
matching the wrapper's saved RIP/CS/RSP/SS, and `[DONE]` reporting full
restoration and unchanged authid. `[RETURN]` without the matching frame
does not attribute execution to the candidate pivot. `[ARMED]`, a silent
stop, or an unchanged frame does not reject the pivot because delivery,
instruction bytes, and IRET remain unobserved. The public
[porting workflow](https://github.com/gzimbric/ps5-hv-bypass-porting/blob/main/docs/porting-workflow.md)
§stage 5 explicitly calls for **pivot plus complete IRET frame** as a
bounded diagnostic. This image stages `RIP, CS, RFLAGS, RSP, SS` and
places the IRET target before them, so the frame *shape* follows that
stage. It has **not** met the stage's exit condition: observed RIP/RSP
movement, clean return, and full cleanup. Direct IRET itself is not
rejected by the workflow; see correction #27 in `11`.

The live action could stall, panic, or power off the console. The owner
approved one transfer. With `[DONE]` absent, send no further ELF on that boot. Hard power
cycle, restart elfldr, and run only a read-only native gate/IST4/zero-cave
baseline audit after recovery. That off-Git read-only audit ELF is already
built (SHA-256
`185623745a4cffa1ee74918139856302eaab47f6eb41d8e60d522477ca8a91f0`);
it checks the native vector-1 gate, all 16 IST4 rows against the staged
addresses, and all `0x5000` cave bytes. Record the FW, build hash,
observed markers, console/elfldr state, and audit result here after the
attempt.

[inference] Reviewing the image against the public
[multicore hook rules](https://github.com/gzimbric/ps5-hv-bypass-porting/blob/main/docs/multicore-debug-hook.md)
found a design defect: all 16 rows were given the **same selected-thread
user RIP and RSP**. Separate IST4 stacks alone do not provide a safe
foreign-CPU path. The exact ELF above is retired and must not be retried;
see correction #25 in `11`. No same-attempt frame was captured, so this
defect is a plausible failure class, not an observed cause.

### First pivot-return run and recovery audit

[verified-on-console] The owner approved one transfer of the exact FW
12.02 ELF SHA-256
`d3f7dac6a33252591b4e480afbe44250c1ed014607bb3768411d792b0e3f9f30`.
The attempt response (off-Git SHA-256
`19645719f06fc5b6f619b1400192342b2bd4f084b414fbaa7529f253e4a1eb57`)
reported native `+0x3188b0` vector-1 gate, 16 readable IST4 rows,
and zero `20480/20480` cave bytes at `[P0]`. It then printed `[ARMED]`
for CPU 9, `+0x2a82de` pivot, `+0x2b362d` IRET, and gate-last
publication. The elfldr response reached EOF without `[RETURN]`,
`[FRAME]`, or `[DONE]`; the sender exited 3 because the required
`[DONE]` text was absent. Two ICMP replies followed. `[ARMED]` is
printed immediately **before** the wrapper executes `ICEBP`, so this
record does not establish that the instruction fired or that the gate
was restored [inference]. A matching frame or post-return marker in a
same-attempt capture would falsify that boundary.

The owner hard power cycled and restarted elfldr. The agreed read-only
audit ELF SHA-256
`185623745a4cffa1ee74918139856302eaab47f6eb41d8e60d522477ca8a91f0`
then reported FW `0x12020000`, native gate `+0x3188b0`, zero staged
IST4 pointers among 16 valid rows, and zero nonzero bytes in the
`20480`-byte scratch span [verified-on-console]. The missing
`[RETURN]` does not exclude an
IRET that reached user code and then stalled during the gate-restoration
call: the first externally visible return marker is printed **after**
that call [inference]. An observer record at the wrapper's first
post-`ICEBP` instruction would falsify this ambiguity for a future run.

### Replacement pivot-return image and first run

[inference] A replacement FW 12.02 ELF was built off-Git with SHA-256
`235f83a238ed7b7dbde9f344c457dbaca61d1533c5200091eba21fe990b0d284`.
It retains the selected CPU's user return frame. Each of the other 15
IST4 stacks instead stages a CPL0 `iretq` frame targeting the **saved
native #DB gate handler**, with `RSP` set to that CPU's own hardware
frame at `IST4_top-0x28`. This is a proposed foreign-CPU fallback, not
the `pop rsp; ret` chain used by the working 11.60 design. The latter's
FW 12.02 address is unknown; the FW 12.70 PR's entry is expressly an
inherited candidate ([12.70 table](https://github.com/PS5Dev/Byepervisor-Reborn/pull/12/files)).
[AMD's long-mode interrupt rules](https://docs.amd.com/api/khub/documents/sD1_QL~h4Afq2_tvzxqqSQ/content)
support the frame geometry: long-mode interrupts push five qwords, and
`iretq` pops `SS:RSP` even when returning to CPL0; a null `SS` is
permitted for a 64-bit CPL0 target. They do **not** establish that the
12.02 stock handler accepts this synthetic entry. A foreign-core frame
followed by a handler fault, or a mismatched handler stack, would
falsify this fallback. The selected CPU still has a race if another
thread takes #DB during the short shared-gate window.

[inference] The ELF emits `[PREARM]` before publishing the gate, then
triggers one `ICEBP` after the gate write/readback. The first selected
user instruction writes a volatile return flag; the next action is a
direct `[RETURN-EARLY]` stdout write **before** the gate-restoration
call. If this marker is absent, delivery/pivot/IRET and the marker
write remain distinct possibilities. A positive marker establishes
selected user continuation but says nothing by itself about cleanup.
The existing `[RETURN]`, frame census, and `[DONE]` still require
readback of the native gate, all 16 IST4 values, zero scratch, original
affinity, and unchanged authid.

This is a console-risky candidate because it redirects the global #DB
gate to unverified FW 12.02 instructions and uses a new CPL0 fallback.
After the clean audit above, the owner explicitly approved the next
pivot ELF; the exact build hash was stated back before transfer. The
expected observation was `[RETURN-EARLY]` followed by gate/IST4/cave,
affinity, and authid cleanup at `[DONE]`. The agreed recovery plan was
to send no second ELF if `[DONE]` was missing, then hard power cycle,
restart elfldr, and run only the read-only native-gate/IST4/zero-cave
audit.

[verified-on-console] The one transfer returned `[P0]` with FW
`0x12020000`, native gate `+0x3188b0`, 16 readable IST4 rows, and zero
`20480/20480` cave bytes. It then printed `[PREARM]` for CPU 9, pivot
`+0x2a82de`, IRET `+0x2b362d`, and `native_fallback=15/15`. The
elfldr response closed without `[RETURN-EARLY]`, `[RETURN]`, or `[DONE]`;
the sender exited 3 because `[DONE]` was absent. The response log's
off-Git SHA-256 is
`0621627ff612147feb6bce4aead243f6d4e9e3e3ac6629f1aa08a93252011435`.
Two ICMP replies followed. `[PREARM]` is printed **before** gate
publication, so that response alone could not prove that the gate was
patched or that `ICEBP` fired [inference].

[verified-on-console] A subsequent **read-only audit ELF was mistakenly
sent before a confirmed hard power cycle**. The owner answered “yes all
good” to a compound question about power cycling, elfldr, and UI state;
we treated it as post-reboot readiness. The audit result proves the
kernel was not at a clean baseline: FW `0x12020000`, vector-1 gate
`+0x2a82de` (`native=no`), all `16/16` IST4 rows still pointing to
staged cave frames, and `1359/20480` cave bytes nonzero. Its off-Git
response SHA-256 is
`fb055dd894ef2e6143388e5215273e4947a942d05d3fe782e5fb88490a1b3d1d`.
The audit completed and two ICMP replies followed; this does not make
the changed global gate safe. The readback establishes that gate and
IST4 writes persisted after the probe response closed. It does **not**
establish that `ICEBP` fired or that the pivot ran [inference]. Sending
the audit before explicit hard-cycle confirmation violated the agreed
recovery plan; see `11` correction #26. No further ELF was sent after
the abnormal audit.

[inference] The byte count adds a narrower observation. The image
builder writes five canary qwords plus six return qwords per CPU and
zeros everything else. Those values have at most `1043` nonzero bytes
in all 16 slots: `619` canary bytes, at most `390` foreign-return
bytes, and at most `34` selected-return bytes. Even replacing all 16
five-qword canary areas with arbitrary hardware frames raises that
maximum only to `1064`. The audit's `1359` means at least `295`
nonzero bytes appeared **outside** the staged return and hardware-frame
slots. The clean census found vector 1 was the only IST4 user (`17`
§complete live census), making a #DB entry and subsequent stack
activity a plausible explanation. A separate writer to this cave, or
a different live gate/IST map, would falsify that attribution. The
audit did not capture addresses of the changed bytes, so it cannot
identify a CPU, the pivot instruction, or a successful return.

[verified-on-console] The owner then explicitly confirmed a full power
cycle and elfldr restart. The same read-only audit ELF (SHA-256
`185623745a4cffa1ee74918139856302eaab47f6eb41d8e60d522477ca8a91f0`)
returned FW `0x12020000`, native vector-1 gate `+0x3188b0`, zero
staged IST4 pointers among 16 valid rows, and zero nonzero bytes in
the `20480`-byte cave. The post-cycle response's off-Git SHA-256 is
`8d6cc034ed170c1847314d7f2c77bd2041fcd854105081fc642ae714be8c924f`.
Two ICMP replies followed. The agreed post-run recovery baseline is
therefore verified; no further pivot ELF was sent.

### Published return-path comparison

[public-consensus] The published 11.60
[diagnostic](https://github.com/gzimbric/Byepervisor-Reborn/blob/340ed30a455e03e9bf29662f257136f9a45d702c/issue9_diag.c)
retargets vector 1 to **IST6**, after checking that IST6 is free; it
leaves the stock IST4 pointers available to the stock handler. Its
per-CPU kernel chain restores the shared gate first, records a CPU
marker, then uses `pop rsp; ret` to reach an IRET trampoline immediately
before the *hardware* exception frame. It triggers TF on a user NOP and
checks the marker, frame fields, stock gate, and all 16 IST6 values on
return. The 12.70 [PR #12](https://github.com/PS5Dev/Byepervisor-Reborn/pull/12)
describes the same isolated IST6 and gate-first hardening, while its
console validation applies to the underlying standalone 12.70 path;
the combined hardened build has host checks, not a reported console run.

[verified-on-console] The 12.02 census found IST6 zero on all 16 CPUs
(`17` §complete live census). [inference] Our replacement ELF instead
repurposed all native IST4 values, skipped the hardware frame on the
selected CPU in favor of a separately staged user frame, gave foreign
CPUs synthetic CPL0 returns to the stock handler, and deferred gate
restoration until **after** user continuation and a `write()` marker.
These are concrete path differences; the stopped run does not identify
which one caused the stop. A same-attempt record of the selected hardware
frame, a kernel-side marker, or a verified user continuation would
distinguish those boundaries. The earlier post-stop audit retained only
the total nonzero cave count, not a per-slot frame image.

[public-consensus] The published 11.60 gadget pair is pivot
`+0x2a0ede`, IRET `+0x2ac22d`
([11.60 offsets](https://github.com/gzimbric/Byepervisor-Reborn/blob/340ed30a455e03e9bf29662f257136f9a45d702c/include/offsets/11_60.h));
the hardware-validated 12.20 pair is `+0x2a815e`, `+0x2b34ad`
([12.20 manifest](https://github.com/gzimbric/ps5-hv-bypass-porting/blob/main/firmwares/12.20.json)).
Our 12.02 candidates `+0x2a82de`, `+0x2b362d` move **both** members
by `+0x7400` relative to 11.60 and `+0x180` relative to 12.20.
[inference] This paired agreement supports the coordinate projection,
but only a 12.02 instruction or entry trace can establish their actual
semantics. A changed instruction at either address would falsify the
projection.

### Isolated IST6 comparison: build and first run

[inference] The next bounded diagnostic keeps the replacement image's
`+0x2a82de` pivot, `+0x2b362d` direct IRET target, selected user frame,
15 proposed native-handler fallbacks, and single `ICEBP`. It changes
only the experimental gate's IST selector from 4 to 6 and stages the
same 16 per-CPU stack tops in TSS IST6, after refusing any nonzero IST6
row. It reads every native IST4 value before arming and verifies those
values are unchanged during cleanup. This isolates whether occupying
native IST4 contributes to the prior stop; it does **not** validate the
synthetic foreign-core fallback or prove the 12.02 gadget instructions.
A clean user return with this variant would support the IST4-interference
hypothesis; another stop would falsify IST4 interference as a *sufficient*
explanation, not prove a bad IRET offset.

The off-Git diagnostic ELF SHA-256 is
`d5c2f24cfc73af857e3fea26218544c753ad87483fff56dc38a8f44c0664edb5`.
The read-only ps5debug-NG watcher SHA-256 is
`ea6c39f40dc3ba99bd1c5840278bdb9eece1c56f93e8db113e5d9b963cb0b063`;
it captures the gate, all 16 IST4/IST6 rows, and each staged hardware
frame slot during the run. A changed frame with a plausible RIP/CS/RSP
would support exception delivery to that CPU, but a silent or timed-out
watcher would remain inconclusive. The post-hard-cycle read-only audit
ELF SHA-256 is
`b1618308780d33d945658a72a4523ae169316d79b72a4288018503a62473a414`.
Compilation and an offline watcher parser check passed before the
one console run described below.

This test can stall or panic while the shared #DB gate is patched to
candidate kernel instructions. The desired observation is one changed
selected-CPU hardware frame, `[RETURN-EARLY]`, then `[DONE]` only after
the selected frame is the sole changed frame and stock gate, all IST6
values, native IST4, zero cave, affinity, and authid read back clean.
If cleanup is not reported, send no further ELF on that boot.
The approved fallback recovery was a confirmed full power cycle, elfldr
restart, then only the read-only audit above for native #DB gate/IST4,
zero IST6, and zero scratch. The owner approved the monitored run
described below.

[verified-on-console] The owner replied “Ready; run the monitored IST6
comparison” to the exact procedure above, with ps5debug-NG and elfldr
available. The read-only watcher first sampled the FW 12.02 native gate
on IST4, 16 zero IST6 rows, and a zero `0x5000` cave for 25 polls in two
seconds. During the one approved ELF transfer it obtained 375 samples
in 25 seconds (off-Git watcher log SHA-256
`8b2e9f1874557c3aad4c39b3350c873d3e2f99ef25e171540b6b73595edcf024`).
At 4.248 seconds it saw `1030` nonzero staged cave bytes with the
native gate and zero IST6 rows. At 4.315 seconds it saw the candidate
gate `+0x2a82de/IST6`, all `16/16` IST6 rows staged, native IST4
unchanged `16/16`, and **zero changed hardware frames**. Its final
sample still had that gate and zero changed frames. The ELF response
(off-Git SHA-256
`3c9e8483dcfe4351d8b94502b36ff5296f779436f69aadf534a5cdd7cc3677eb`)
reported `[P0]` and `[PREARM]` for selected CPU 9, then closed without
`[RETURN-EARLY]`, `[FRAME]`, or `[DONE]`.

[inference] The live watcher proves this image staged its frame and
published the intended IST6 gate, but it does not show the selected
hardware frame being pushed. The first remaining boundary is whether
the gate write/readback call returned to the wrapper and its `ICEBP`
executed; this run does **not** test the IRET target. A same-attempt
post-gate/pre-`ICEBP` marker or a changed hardware frame would resolve
that boundary. A watcher read that failed to reflect a real frame write
would falsify the zero-frame observation, though the watcher did see
the cave staging change in this attempt.

[verified-on-console] The owner asked why the still-responsive console
could not be restored through the independent ps5debug-NG connection.
A fresh read-only sample still matched this exact stopped image: the
candidate `+0x2a82de/IST6` gate, all 16 staged IST6 pointers, unchanged
native IST4, a staged cave, and zero changed hardware frames. An off-Git
restoration script (SHA-256
`32a0d78a3dbc215716f62760330f8df0b4d74df33d068fffd555aed61cf33ff3`)
checked the FW/build identity and this state twice before writing. Its
no-write dry run passed. It then restored the stock gate **first** and
read back the full gate; zeroed and read back each of 16 IST6 entries;
and zeroed and read back all five cave pages. The restore log SHA-256 is
`05a97b7b58f8b565d629c5d6378d42aefbafdd3b0310cde68a91371216f730aa`.
An independent two-second, 24-sample read-only audit confirmed native
`+0x3188b0/IST4`, `0/16` staged IST6 entries, unchanged native IST4,
zero cave bytes, and zero changed hardware frames (off-Git audit log
SHA-256
`8468cc54d3f93403b5890cd771edb7a58fe040215b815f597179f8909d1e7cfe`).
No hard power cycle or further ELF was needed for this recovery.

## HV path

The FW 12.02 root-0 `break_hv` port is still proposed, with dynamic
`pcpus`/heap discovery outstanding (`16` §remaining true unknowns and
§port phases). The following are acceptance gates, not observed results.

- [ ] **Model-specific physical bounds surveyed:** the documented
  kernel-data/dmap reads do not identify a validated HV scan interval.
- [ ] **Scan-only self match equals 1:** no FW 12.02 root-0 scan record.
- [ ] **Scan-only target count equals 16:** no FW 12.02 root-0 scan record.
- [ ] **Self belongs to target set:** no FW 12.02 root-0 scan record.
- [ ] **Guarded write pass:** no FW 12.02 root-0 target write record.
- [ ] **Independent 16/16 readback:** no FW 12.02 root-0 readback record.

## Post-wake

The #GP/FACS entry-frame and return contract are unvalidated on 12.02
(`15` §falsifiers and what is still unproven; `11` correction #20). No post-wake port result
is documented.

- [ ] **Exact success shape:** no FW 12.02 post-wake success record.
- [ ] **Hook cleanup verified:** no post-wake cleanup and readback.
- [ ] **Small kernel-text proof:** no post-wake execution or text read
  proof for this port.
- [ ] **Full dump validated against execution-derived anchors:** no
  post-wake full dump or such anchor comparison.

## Publication

- [ ] **No dumps, keys, secrets, binaries, or private paths:** this
  checklist PR adds notes only. A final public-tree review of the
  complete port has not occurred (`AGENTS.md` §scope and material
  boundaries).
- [ ] **All values have basis, status, and evidence:** the checked
  items here cite evidence, but the full port manifest and every
  future value have not been audited (`AGENTS.md` §epistemic
  discipline).
- [x] **Rejected candidates recorded:** the known coordinate,
  frame, and mechanism corrections are in `11`; the outstanding
  gadget candidates are explicitly scoped in `16` [verified-in-tree]
  (`docs/11-debunked-theories-and-corrections.md:18-38`,
  `docs/16-byepervisor-12-02-port.md:489-523`). This covers the
  current research record, not future candidates.
- [ ] **Manifest validator passes:** no FW 12.02 port manifest and
  validator result are recorded.
- [ ] **Public-tree check passes:** no final public-tree gate has been
  defined and run for the completed port.
