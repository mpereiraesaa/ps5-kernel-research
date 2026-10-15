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
- [ ] **Cave contents and page permissions:** for the proposed cave,
  live-read the **entire required span** and confirm it is zero and
  readable. Resolve every actual leaf covering that span and record
  each page size, mapped physical page, and P/RW/US/NX permission bits. Write a
  distinctive marker, read back the exact bytes, then test whether it persists
  across the planned rest/wake interval and explain any change. Restore all
  touched bytes, then re-read the entire required span to verify zero.
  **Exit condition:**
  exact marker readback, persistence behavior understood, and zero
  restoration verified across the required span. The earlier
  frame-setup run proved staging/readback/restoration for its scratch
  bytes [verified-on-console] (`16` §frame staging isolation); it did
  not report the leaf mapping, its permissions, or the persistence
  behavior (`11` correction #23).

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

The evidence record for this item should have this shape. Placeholders
are deliberately unfilled; a cave result from another firmware does
not validate 12.02.

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

## Kernel hook path

- [x] **Complete IDT/TSS census:** the 2026-10-15 read covered all
  256 gates and 16 TSS rows and recorded every IST-using gate and the
  requested vector handlers [verified-on-console] (`17` §complete
  live census).
- [x] **CPU-to-TSS-row mapping:** `pc_cpuid=0..15`; both PCPU TSS
  pointers identify row `i` for CPU `i` [verified-on-console] (`17`
  §complete live census). Selecting row 0 for an arbitrary probe CPU
  is rejected in `11` correction #22.
- [x] **Prepare-only write/readback/restore:** the changed IST4/#DB
  gate diagnostic read back staged values, then restored and verified
  originals without triggering #DB [verified-on-console] (`16`
  §changed IST/#DB-gate setup isolation run). This checks that setup
  path only.
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
