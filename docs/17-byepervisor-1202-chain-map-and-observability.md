# 17 — Byepervisor 12.02 chain map and failure evidence (offline)

**Status:** offline mapping only. No 12.02 chain was installed or triggered for
this document. The source of the working 11.60 sequence is
[`5299395`](https://github.com/gzimbric/Byepervisor-Reborn/commit/5299395b15ec91f7484ded2e7631977e0df94a4d),
especially its [`khook.c`](https://github.com/gzimbric/Byepervisor-Reborn/blob/5299395b15ec91f7484ded2e7631977e0df94a4d/khook.c)
and [`11.60-port.md`](https://github.com/gzimbric/Byepervisor-Reborn/blob/5299395b15ec91f7484ded2e7631977e0df94a4d/docs/11.60-port.md).
Read `11` before using this map. The earlier 12.02 `INT1`/`justreturn`
failure (`16`, live one-shot run) did not capture the hardware frame and
therefore did not identify the failing instruction.

## What “same chain” means

[public-consensus] The validated 11.60 path is two #DB transactions, not a
single return gadget. `kh_install` stages an arm chain, a dispatch stub, and a
handler chain that saves selected registers; it patches the chosen IST slot and vector-1
gate. `kh_trigger` sets TF for one user-mode NOP. The arm chain loads a
`resumectx` that enables a DR0 execute breakpoint, changes the IST pointer to
the dispatch stack, and returns to user mode. The later breakpoint at the
kernel hook target enters the dispatch chain, which saves interrupted
RSI/RDI/RDX, performs its work, disarms DR7, and resumes the interrupted frame
([`khook.c` lines 296–484](https://github.com/gzimbric/Byepervisor-Reborn/blob/5299395b15ec91f7484ded2e7631977e0df94a4d/khook.c#L296-L484)).
Its 11.60 hook chooses IST6 and pins the intended core
([`main.c` lines 17–25, 297–310](https://github.com/gzimbric/Byepervisor-Reborn/blob/5299395b15ec91f7484ded2e7631977e0df94a4d/main.c#L17-L25)).

[inference] A close 12.02 port should preserve **both transactions and their
state transitions**, while replacing every instruction address and validating
the changed firmware's stack and `resumectx` contract. A 12.02 trace that
reaches a user return after the arm transaction and then a kernel breakpoint
handler would support this mapping; a different actual control flow would
falsify it. The FACS-induced #GP proposal in `15`/`16` is a separate design:
it has an error-code frame and no DR0 breakpoint. It cannot use this #DB
stack layout unchanged (`11` #20).

The 11.60 port itself says its **offsets were insufficient**: hypervisor
globals were zero at AP execution time, so it used live VMCB discovery and
also changed gadget and page-table handling
([`11.60-port.md`](https://github.com/gzimbric/Byepervisor-Reborn/blob/5299395b15ec91f7484ded2e7631977e0df94a4d/docs/11.60-port.md)).
That runtime method is a model for a later 12.02 AP phase, not evidence that
the 11.60 heap range or VMCB population transfers to 12.02.

[inference] The one-`ICEBP` full-dispatch diagnostic in `16` is a narrower
predecessor to this two-transaction port. It would test the selected-core #DB
frame, pivot, register save, benign handler, and return without asserting
that DR7 was armed or that a kernel-text breakpoint fired. A completed
one-trap return would support those shared dispatch steps; it would not
establish the arm transaction, the kernel breakpoint, or the AP path.

## Coordinate and symbol map

`r0gdb/prosper0gdb/offsets/12_02.h` uses offsets relative to **kdata**;
`5299395`'s `11_60.h` uses **ktext**. [verified-in-tree] The 12.02 conversion
used in `16` is `ktext offset = 0xd50000 + signed kdata offset` (see
`16`, Kstuff return-stub disassembly). It is a coordinate conversion, not a
claim that equivalent code has the same bytes. Resolve both bases per boot.

| Required object | 12.02 evidence | Status for faithful #DB port |
|---|---|---|
| IDT and common TSS | [verified-in-tree] `r0gdb/prosper0gdb/offsets/12_02.h:8,10`: `kdata+0x2e88300`, `kdata+0x2e8afe0`; `16` §“Derived 12.02 data and structure offsets” records TSS stride `0x68` from `r0gdb/prosper0gdb/minchain2-build/main.c:72,395`. | Addressed; selected CPU, native gate type/IST, and saved qwords must still be read live. |
| Scratch | [verified-on-console] The earlier two-page setup at `kdata+0x2099000` was superseded by PR #97's setup-only run: `16` §“Full Kstuff-style continuation probe” records staging/readback/restoration of **16 × `0x500` = `0x5000` bytes** there. [public-consensus] `5299395/include/khook.h:30-37` reserves `0x4000` bytes and begins its big chain at `+0x3a00`. | The tested byte span is large enough for the **reference image by size alone**. The existing all-CPU slots already occupy the entire `0x5000` span, so overlaying that image would collide. A disjoint or redesigned joint layout and independent ownership evidence are still required. |
| Test hook target | [verified-in-tree] `12_02.h:29` identifies `sysents`; [public-consensus] the 11.60 test uses `getuid + 0xe` (`5299395/main.c:63`). | Function pointer can be located through `sysents`; the **12.02 instruction boundary** and safe resume address are unknown. Do not transfer `+0xe`. |
| Resume-window hook target and AP init vector | [public-consensus] 11.60 identifies both in its `include/offsets/11_60.h`. | No verified 12.02 addresses. Neither the debunked `acpi_sleep_machdep+0x18e` nor a global text delta supplies one (`11` #14, #18). |
| `resumectx` layout | [public-consensus] `5299395/include/khook.h:12-15` uses RBP `+0x20`, RSP `+0x28`, RIP `+0x38`, DR7 `+0xa0`. | Candidate FreeBSD lineage only (`16`, PCB table). Validate the 12.02 consumer before a DR7 arm. |
| Hypervisor AP/VMCB location | [public-consensus] 11.60 discovers a live 16-entry set and validates it before writes. | No 12.02 runtime location or validated population; outside the first khook proof. |

The local 12.02 kdata dump was taken while Kstuff ran; its patched gate and
IST values are **not** a native baseline (`11` #19). A fresh read-only live
baseline is required for any later experiment.

[verified-in-tree] In the current `fullchain_allcpu.c` layout, CPU `i` owns
`[scratch+i×0x500, scratch+(i+1)×0x500)`. The 11.60 reference image uses
`[scratch, scratch+0x4000)`, including its big chain at
`[scratch+0x3a00, scratch+0x4000)` (`5299395/include/khook.h:30-37`).
Overlaying them at the same base would intersect the first 13 CPU slots;
the big chain alone intersects CPU 11 and 12 slots. [inference] A direct
combined build therefore needs separate regions or a proved repacking,
even though `0x5000 > 0x4000`. A disjoint layout with readback on every
region would falsify the claimed overlap for that redesigned placement;
the overlap calculation applies to the current shared base only (`11` #25).

[inference] The shared vector-1 gate plus a **selected-core-only** IST6
rewrite in 11.60 leaves another core's incidental #DB with the new pivot but
its old stack. The 12.02 single-core attempts already exposed this hazard
(`16`, patched-gate run). A 12.02 port must either prove an acceptable
selected-core window or stage a compatible per-CPU landing layout before
arming the shared gate. A captured concurrent #DB on an unmodified core that
returns safely through the new pivot would falsify the hazard in that case;
mere affinity of the triggering user thread does not. Per-CPU copies must
also fit the chosen scratch allocation and cannot overlap one another.

## Gadget inventory, in execution order

The 11.60 offsets below come from
[`include/offsets/11_60.h`](https://github.com/gzimbric/Byepervisor-Reborn/blob/5299395b15ec91f7484ded2e7631977e0df94a4d/include/offsets/11_60.h).
“Table address” means a Kstuff 12.02 offset names the location; it does
**not** mean the bytes, side effects, or entry stack contract were verified
in a 12.02 text image. `16`'s 13.60 donor disassembly supports only its
own firmware. There is no held 12.02 ktext image in this audit.

| Required semantic / phase | 11.60 `ktext+` | 12.02 evidence and verdict |
|---|---:|---|
| `PIVOT_ADD_RSP28_RET` for both #DB entries | `0x2a0ede` | **Candidate** `ktext+0x2ac2de`, inferred from 13.60 pivot's position near `cpu_switch` (`16`, cross-dump gadget table). 12.02 bytes and stack consumption missing. Kstuff's `add rsp,0xe8; iretq` at `+0x2b3626` is a different contract. |
| `IRETQ` for arm and dispatch returns | `0x2ac22d` | **Table address** `doreti_iret` at `+0x2b362d` (`12_02.h:12`); 12.02 bytes not read. |
| `RET_TRAMP` | `0x338d2b` | **Table address** `nop_ret` at `+0x2b0b26` (`12_02.h:17-18`); exact 12.02 bytes not read. |
| `POP_RAX`, `POP_RCX`, `POP_RDI` for arm/context/store | `0x338d2a`, `0x339712`, `0x289e0a` | **Unknown** individually; `pop_all_iret` is not a drop-in replacement because it consumes a different frame. |
| `DBREG_RESUME` tail | `0x2a5778` | **Candidate** `+0x2acb78` from the 13.60 donor's local relation to Kstuff `mov_cr3_rax_mov_ds` (`16`). [verified-on-dump] The 13.60 donor entry is `mov dr0,rax`; the preceding load from `[rdi+0x78]` is outside the gadget, and the arm chain supplies DR0 in RAX (`11` #23). The 12.02 entry, remaining debug-register loads, and continuation stack are unverified. `cpu_switch` alone does not prove this tail. |
| `STORE_RDI8_RCX` to write `IST+8` in arm continuation | `0x3cc4af` | **Unknown** equivalent. |
| `POP_RSP` for dispatch stub and resume tail | `0x33974d` | **Unknown**. |
| `MOV_RAX_RSI`, `MOV_RAX_RDI`, `ST_RCX_RAX`, `ST_RCX_RDX` for register save | `0x958504`, `0xc5e5da`, `0x3620bf`, `0x8a2725` | **Unknown** as a set. `store_rax_rdi` at 12.02 `+0x2ac112` is a different register pairing; any substitution needs a new register-liveness proof. |
| `POP_RSI`, `POP_RDX`, `SET_DR7` for one-shot resume | `0x8aafb5`, `0x3476db`, `0xa7bd86` | **Unknown**. A debug-register instruction cannot be inferred from a nearby function address. |
| handler marker using `POP_RCX`, `POP_RAX`, `ST_RCX_RAX` | `0x339712`, `0x338d2a`, `0x3620bf` | **Unknown** on 12.02. A marker cannot be promised until a store sequence is proven and its clobbers are accounted for. |
| `CLD`, `REP_MOVSB` for later AP-copy path | `0x462c1a`, `0x304367` | `CLD` **unknown**. **Table address** `rep_movsb_pop_rbp_ret` at `+0x2efdba` (`12_02.h:15`) has an extra pop and needs a distinct frame; the 11.60 copy chain cannot be pasted. |
| `OR_RCX_EAX` for persistent hook | unused in 11.60 one-shot path | Not required if the 12.02 proof remains one-shot. |
| `POP_R8`, `STORE_RCX_R8` | absent/unused in 11.60 | Not required: `5299395/khook.c:75-84` uses RAX stores instead. The RAX store remains unverified on 12.02. |

[inference] The table covers every gadget class used by the 11.60 arm,
dispatch, one-shot return, and AP copy path, but does **not** yield an
executable 12.02 map. A byte-level 12.02 disassembly agreeing with each
candidate would strengthen it; a differing entry instruction, side effect,
or stack delta would falsify that substitution. The unresolved pivot,
`resumectx` tail, store sequence, `pop rsp`, and hook target are blocking
dependencies for a faithful build. Mark them **unresolved**, not zero or
borrowed 11.60/13.60 addresses.

## Failure evidence that survives a failed return

[public-consensus] The 11.60 source already uses kernel-data cookies:
`CHAIN_MARK` in its handler, an armed-state value and saved gate/IST in the
cave, and AP `entered`/`done` plus per-VMCB counts
([`main.c` lines 17–32, 103–153, 243–275](https://github.com/gzimbric/Byepervisor-Reborn/blob/5299395b15ec91f7484ded2e7631977e0df94a4d/main.c#L17-L32)).
For 12.02, keep **raw evidence plus ordered milestones**. A PC log line is
only proof that the sender reached its own call; a missing line can also mean
the sender or transport stopped. Do not put socket I/O in the kernel chain.

| Milestone | Writer and durable evidence | What a positive observation establishes |
|---|---|---|
| B0 native baseline | User-mode read-only gate, all relevant IST slots, scratch/journal; `ps5log/1` with FW, build hash, boot identity without console identifiers, pinned CPU. | Starting state for this boot. |
| B1 image staged | User-mode write/readback of each disjoint arm, dispatch, handler, and frame region; log their sizes and independent checksums. | Staging completed; no #DB implication. |
| B2 gate armed | User-mode gate/IST readback plus a final pretrigger `ps5log/1` record. | Patch was observed before the deliberate first trap; does not prove the trap ran. |
| F1 first hardware frame | Preseed five distinct canaries at the **selected IST6 hardware-frame slot**; in the reference layout, IST6=`scratch+0x40` and the five words start at `scratch+0x18`. A **pre-armed** independent observer captures raw RIP/CS/RFLAGS/RSP/SS without loading a new ELF after a stall. | Matching replacement by a plausible frame supports first #DB delivery to that stack, even if the pivot fails. Changed bytes alone need raw-frame review. |
| A1 arm continuation | A first in-chain kernel-data marker **after** a verified pivot/store and a second after `DBREG_RESUME` continuation, if those store sequences can be validated without losing live registers. | Narrows entry/pivot versus debug-register restore/continuation; neither marker alone proves DR7 value. |
| A2 arm returned | User-mode `ps5log/1` record after the TF/NOP arm return, with readback of the dispatch IST pointer and journal. | First return completed and dispatch stack was selected. |
| F2 second hardware frame | Distinct canaries in the **dispatch IST6 frame slot**; in the reference layout, IST6=`scratch+0x240` and the words start at `scratch+0x218`. The pre-armed observer samples independently before recovery if a later failure occurs. | Supports kernel hook #DB delivery; not handler completion. |
| D1 dispatch/handler | In-chain marker only **after** the required interrupted registers are saved and a 12.02 liveness review proves the marker's RAX/RCX clobbers harmless; later marker after the test oracle store and before the resume tail. Record raw frame and marker words in the independent audit. | Separates entry/register-save, handler action, and resume-tail failures, subject to verified store gadgets. |
| D2 kernel resumed | User-mode record after the selected test syscall returns, then gate/IST restoration readback and BYE. | Full test-hook transaction completed; it does not prove the later sleep/AP phase. |
| H1 AP phase | Separate `entered`, selected-VMCB count, write count, verify count, and `done` evidence, following the 11.60 read-before-write validation pattern. | Only a full expected set and readback can support a 12.02 AP claim. |

**Proposed host log contract, not yet emitted by a 12.02 chain.** After
independently checking each observation, a user-mode observer would send a
`ps5log/1` `MARK` record with text `KH1 stage=F1 source=frame verified=1`
(likewise `B0`, `B1`, `B2`, `A1`, `A2`, `F2`, `D1`, `D2`). `B*`, `A2`, and
`D2` use `source=user`; `F*` uses `source=frame`; `A1`/`D1` use
`source=journal`. The source tag states where the observer obtained the
evidence; `verified=1` must follow raw readback and comparison against the
recorded preseed, not mere receipt of a value. Preserve the raw values,
canaries, layout version, and build hash alongside these records. The AP
phase has a separate evidence set and is not inferred from `D2`.

`tools/khook_trace_classify.py RUN.log --manifest RUN.json` checks this
proposed record order, the ps5logd manifest's gaps/clean flag, and the
verbatim log SHA-256. It returns the **first missing direct observation**,
later records, and transport status; it does not inspect the kernel bytes or
turn absence into a claim that a trap failed. A later stage with a missing
earlier marker is a coverage gap, and a reversed stage order is flagged. The
classifier has synthetic tests in `tests/test_khook_trace_classify.py`; no
real 12.02 run has yet produced this record format.

### Current Kstuff-style one-`ICEBP` build

The later offline build documented in `16` uses a different IST4 layout
and Kstuff's `pop_all_iret` → `rep_movsb_pop_rbp_ret` → `pop_all_iret`
continuation. The **IST6** audit scaffold below does not inspect its
per-CPU `0x500`-byte slots. Its own `fullchain_audit.c` emits `[KA1]`
gate/IST4/marker values and `[KA2]` changed-frame values. The live
`fullchain_allcpu.c` emits `[K1]` and a `ps5log/1` staging record
**before** the IST4 and gate writes (`fullchain_allcpu.c:327-356`),
then `[K1r]` and `[K2]` only after returning and restoring
(`fullchain_allcpu.c:370-395`). There is no durable PC marker between
the final gate readback and `ICEBP` in that build. [inference] A run that
stops after staging cannot distinguish patching failure, trap delivery,
or later continuation without same-attempt evidence from an observer already
running before the trigger; a later trace
showing an intermediate marker would falsify this record inventory.

The classifier accepts those **actual** records separately from the
proposed two-transaction `KH1` format:

```text
python3 tools/khook_trace_classify.py elfldr.log --mode kstuff-fullchain \
  --audit fullchain-audit.log --audit-same-attempt \
  --pc-log run.log --manifest run.json --pc-same-run
```

`--audit-same-attempt` is an explicit operator assertion; absent a verified
same-attempt link before recovery, audit values are shown but cannot
advance the reported boundary. `--pc-same-run` likewise asserts that the
PC log and elfldr output belong to the same run; its manifest checks integrity and gaps
but does not by itself link two different output channels. A changed
`[KA2]` frame with no marker bounds failure after
the frame change and before the copy marker or its observation; a marker
with no return bounds it after the copy and before the user return or its
log. Those are **classes**, not instruction identifications. The audit
reports canary replacement, not an independently validated #DB frame;
raw RIP/CS/RFLAGS/RSP/SS still require review. A post-power-cycle audit
cannot negate an earlier delivery. Tests cover these cases with synthetic
`[K]`/`[KA]`/`ps5log/1` transcripts.

**Correction from the live run in `16` and `11` #24:** The setup-only
ELF completed, but the live build emitted only its prepatch `[K1]` and
PC staging marker. A later attempt to load `fullchain_audit.elf` timed
out and the console became unreachable; no `[KA]` frame or marker was
captured. The owner hard power-cycled it and confirmed the UI recovered.
[verified-on-console] Applying the host classifier to the retained PC
logs reports `setup_only_completed_no_db_triggered` with complete
transport for the setup run, then
`prepatch_staging_seen_gate_patch_or_later_unproven` with incomplete
transport for the live run. These are evidence boundaries, not a
diagnosis of the failing instruction.
[inference] Loading another ELF after a stall can be unsafe while the
shared gate/IST state is unknown, even if ping and elfldr initially
answer. A future observer must be active **before** patching the gate
and have an independent reporting path. A captured restored gate before
the audit attempt would falsify the proposed changed-gate link; the
available logs do not establish what caused the outage.

**Isolated prearmed Kstuff variant, built offline and not run.**
[verified-in-tree] Our separate local source
`engineering/payloads/byepervisor_probe_1202/fullchain_prearmed.c:113-249,526-627`
builds `byepervisor_probe_1202_fullchain_prearmed.elf`, SHA-256
`522ba85be24e213ad22ab2ed1d1c667b6f54f82280c5d2bddaec51449672d489`.
The earlier PR #97 live, setup, and audit ELF hashes remain unchanged.
The worker runs on a second permitted CPU and sends `FC1 READY` before the
main thread stages IST4 or changes the gate. After the main thread writes and
reads back all 16 IST4 slots and the gate, the worker independently reads the
full gate and all 16 IST4 values and sends `FC1 GATE_VERIFIED` with raw gate
qwords, expected qwords, matched count, and first mismatch. The trigger waits
for that PC send and acknowledgment. While armed, the worker reads all 16
preseeded five-word frames and copy markers, sending each first change as
`FC1 FRAME` or `FC1 MARKER`; successful return joins it before the main
thread resumes SDK kernel R/W operations. A timeout or unsafe teardown parks.

[verified-in-tree] The `FC1` local sequence begins at 1; its stages are
`READY`, `GATE_VERIFIED`, zero or more `FRAME`/`MARKER` records, and
`QUIESCED` (or `READ_FAIL`). `READY` includes FW, a **version tag**
`build=prearmed-v1`, and selected/observer CPU numbers. The exact ELF SHA is
recorded above, while `ps5log/1`'s `HELLO` boot token identifies the PC
session; the version tag is not an ELF hash. `tools/khook_trace_classify.py`
preserves raw `FC1` fields and sequence issues. With `--pc-same-run`, a
matching gate/16 IST4 record advances the observed boundary beyond PR #97's
prepatch `[K1]`; a selected CPU's changed frame or copy marker narrows it
further. Without that operator assertion, these records remain visible but do
not advance a separate elfldr transcript. An `FC1` marker is only a copy
side effect, not proof of a valid return or debug-register arm. A changed
frame is raw canary replacement and needs RIP/CS/RFLAGS/RSP/SS review.
`tests/test_khook_trace_classify.py` covers linked and unlinked records,
gate mismatch, frame/marker progression, nonselected CPU activity, and a
failed observer on return using synthetic transcripts.

[inference] This is still a risky one-`ICEBP` diagnostic, not the 11.60
two-transaction port. Its second `pop_all_iret` frame does not restore an
incidental CPU's original GPRs, and the observer itself runs during the
shared-gate window. A byte-level all-register save/restore path in the
current build would falsify this source reading; none is present in
`fullchain_prearmed.c:478-510` or `fullchain_icebp.S:9-27`. The 12.02 gadget
bytes remain unavailable. Building and classifying it offline do not approve
a console run.

**Pre-armed observer contract for a later two-transaction build [inference].** The
separate-pipe calibration in `16` observed a pinned worker reading the
gate/scratch and sending a PC record; the later pretrigger handshake
observed a canary while a changed gate was installed. Neither run
captured a post-trigger frame. The one-trap variant above covers only its
IST4 frames and copy markers. A two-transaction design must keep the
worker and its PC channel alive **before** any IST/gate write, then use
an explicit sequence number and one shared phase word:

1. The worker sends `READY` with FW, build hash, selected and observer
   CPUs, and a run token before the main thread writes the shared gate.
2. After all per-CPU slots and the gate are read back, the main thread
   stores `GATE_VERIFIED` with release ordering. The worker samples the
   gate and all IST4 pointers, and sends the raw state plus its phase
   sequence before acknowledging. This places a durable boundary after
   patch readback, which the failed fullchain run lacked. A missing
   acknowledgment still leaves the main thread's last completed store
   uncertain.
3. The main thread issues `ICEBP` only after that acknowledgment. The
   worker samples **all 16** canary frames and marker words repeatedly
   during the short changed-gate window, reporting the first changed
   CPU and raw frame fields, then each marker transition. The records
   must name the slot layout and be flushed independently of elfldr.
4. On a successful return, the main thread asks the worker to quiesce
   before using the SDK kernel R/W primitive for restoration; the final
   record includes gate/IST/scratch readback and BYE. A bounded worker
   wait and a documented park/recovery state are needed if it does not
   quiesce. The existing `observer_channel_read` reconfigures its pipe
   through the SDK's inherited primitive, so all such calls must be
   serialized with the main thread's SDK reads/writes (`16`, separate
   channel calibration). Merely allocating a second pipe is not enough.

This is an observation design, not authorization to run or a guarantee
of safe concurrent #DB handling. The worker itself executes on another
CPU while the gate is shared, and the register-preservation gap below
still applies. A complete trace with `GATE_VERIFIED` but no changed
frame would leave trigger execution, delivery, and frame placement
unresolved; a changed frame on a nonselected CPU would falsify an
assumption that pinning confines #DB to the trigger CPU.

[inference] Preparing all 16 IST4 slots in that build addresses the
wrong-stack hazard, but does not preserve an incidental #DB's interrupted
registers. `fullchain_allcpu.c:283-315` zeros each slot and fills only
selected fields of its second `pop_all_iret` register frame; the
`fullchain_icebp.S:9-27` save/restore wrapper applies only to the
chosen user thread. An unrelated #DB on another CPU would enter its
prepared chain and, if it returned, use GPRs from that frame. A
byte-level audit showing a separate all-register save/restore path in
the built ELF would falsify this source reading; the current source
contains none. The classifier reports changed frames or written markers
on nonselected CPUs as a distinct review flag. This is a blocker for
calling the shared-gate window safe merely because each CPU has a stack.

[inference] The first divergence between a preseeded frame, an in-chain
marker, and a post-return marker localizes the **class** of failure, not
necessarily the exact instruction. An observer already running before
the trigger must sample the frame/journal **before a hard power cycle**;
post-recovery zero state cannot reconstruct the failed run (`16`, one-shot
record). If the console powers off, the last durable PC record is the bound:
there is no claim that later kernel milestones did or did not execute. A trace
showing an unchanged canary despite independently confirmed delivery would
falsify this placement or the audit's address calculation.

The journal layout and marker-store gadget are deliberately **not assigned
addresses yet**. The 11.60 image occupies the first `0x500` bytes and places
its big chain at `+0x3a00` (`khook.h:30-37`); a 12.02 port must prove every
marker slot is disjoint from both chains, both hardware frames, the saved
baseline, and the AP stash. A marker written before the register-save stage
would change the interrupted context and cannot be called passive logging.

**Offline-built read-only capture scaffold (not run):** our local tooling
`engineering/payloads/byepervisor_probe_1202/khook_1202_readonly_audit.c`
builds `byepervisor_probe_1202_khook_readonly_audit.elf`, SHA-256
`b3efc11a33eea37634eafcb598d4dd31c775e8fa85b0f242c59f4f9872ac549b`.
It reads the vector-1 gate, all 16 IST6 pointers, four pages beginning at
the **candidate** scratch address, raw five-word frames at the 11.60 arm
and dispatch IST positions, and 32 qwords at provisional `scratch+0x700`.
Its compiled `main` calls `kernel_copyout` and no `kernel_copyin`; no console
operation was performed. [inference] A read-only sample can help distinguish
frame delivery from later-chain progress if a future build uses those exact
slots; a different finalized layout would falsify the positional reading and
requires rebuilding the audit. It is **not** a post-stall recovery tool:
`11` #24 rules out assuming that a new ELF can be loaded safely after a
failed live trigger. The four-page read span is within the later
`0x5000` setup-only staging span, but that run did not validate the
reference chain's placement, journal ownership, or marker-store path.
Compiling this audit ELF validates none of those contracts.

## Offline exit gates and console boundary

1. Identify the 12.02 instruction bytes and containing basic blocks for the
   pivot, `DBREG_RESUME`, return, stores, pops, and DR7 disarm; record stack
   deltas and clobbers. The current data-only 12.02 dump cannot prove these.
2. Identify a 12.02 test-hook instruction boundary and resume contract, then
   separately the resume-window `startup_mp` call and AP init vector. A
   `sysent` function pointer alone does not identify an interior instruction.
3. Freeze a disjoint frame/journal layout and check it offline for all staged
   regions, 16 CPUs if per-CPU landings are used with the shared gate, and
   both #DB transactions. PR #97 demonstrated write/readback/restoration
   across `0x5000` bytes, but its 16 per-CPU slots occupy that entire span.
   A separate `0x4000` reference image cannot be overlaid at the same base;
   a jointly packed layout needs explicit interval and ownership proofs.
4. Finalize a **pre-armed observer** against the chosen layout, including both
   frame slots, all journal words, gate/IST state, and the saved baseline.
   The offline-built audit scaffold above covers the reference slot positions
   only; it has not been run or paired with an executing chain, and loading
   it after a stalled trigger is not an acceptable observation path. Pair the final
   version with user-mode `ps5log/1` records and validate classification on
   synthetic data before any live run.
5. Only after those gates, specify one exact FW 12.02 build, the expected
   marker sequence and falsifiers, the risk of a stranded gate/IST or panic,
   hard power-cycle recovery, and read-only baseline verification. Obtain
   explicit owner approval for that **specific** console-risky experiment
   under `AGENTS.md`. No run is authorized by this offline map.

The current result is a **complete inventory of required semantics and
evidence points**, with unresolved entries visible. It is not a completed
12.02 gadget port or a prediction that the next live attempt returns.
