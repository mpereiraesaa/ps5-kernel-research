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
| Test hook target | [verified-in-tree] `r0gdb/prosper0gdb/offsets/12_02.h:29` identifies `sysents`; [public-consensus] the 11.60 test uses `getuid + 0xe` (`5299395/main.c:63`). [verified-on-dump] The 12.02 table's `sysent[24].sy_call` is `ktext+0x3130a0`; the 13.60 donor's `sy_call` is a jump entry, distinct from its getuid body (`16` §“getuid table entry versus hook body”). | Only the 12.02 **table entry** is located. Its instruction bytes, body target, `+0xe` hook boundary, and safe resume address remain unknown. Do not transfer donor body offsets or use `sy_call+0xe` as the hook. |
| Resume-window hook target and AP init vector | [public-consensus] 11.60 identifies both in its `include/offsets/11_60.h`. | No verified 12.02 addresses. Neither the debunked `acpi_sleep_machdep+0x18e` nor a global text delta supplies one (`11` #14, #18). |
| `resumectx` layout | [public-consensus] `5299395/include/khook.h:12-15` uses RBP `+0x20`, RSP `+0x28`, RIP `+0x38`, DR7 `+0xa0`. | Candidate FreeBSD lineage only (`16`, PCB table). Validate the 12.02 consumer before a DR7 arm. |
| Hypervisor AP/VMCB location | [public-consensus] 11.60 discovers a live 16-entry set and validates it before writes. | No 12.02 runtime location or validated population; outside the first khook proof. |

The local 12.02 kdata dump was taken while Kstuff ran; its patched gate and
IST values are **not** a native baseline (`11` #19). A fresh read-only live
baseline is required for any later experiment.

[verified-in-tree] In the current `fullchain_allcpu.c` layout, CPU `i` owns
`[scratch+i×0x500, scratch+(i+1)×0x500)`. The 11.60 image **reserves**
`[scratch, scratch+0x4000)`, intersecting slots 0–12 at the same base
(`5299395/include/khook.h:30-37`). Its actual writes include the first
`0x500` bytes (`khook.c:440-441`, colliding with CPU 0), state at `+0x600`
and saved gate/IST at `+0x620..+0x637` (`main.c:21-24,76-79`, colliding
with CPU 1), and a big chain starting at `+0x3a00` (`khook.c:390,437`,
colliding with CPU 11). The reserved `0x600`-byte big-chain capacity reaches
CPU 12, though its actual emitted length depends on the handler. [inference]
A direct combined build therefore needs separate regions or a proved
repacking, even though `0x5000 > 0x4000`. A disjoint layout with readback on
every region would falsify the claimed overlap for that redesigned placement;
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
| `PIVOT_ADD_RSP28_RET` for both #DB entries | `0x2a0ede` | **Candidate** `ktext+0x2ac2de`: the `cpu_switch−0x22` relation appears in the published 13.00, 13.20, and 13.60 tables (`16`, cross-firmware local-anchor consistency). 12.02 bytes and stack consumption remain missing. Kstuff's `add rsp,0xe8; iretq` at `+0x2b3626` is a different contract. |
| `IRETQ` for arm and dispatch returns | `0x2ac22d` | **Table address** `doreti_iret` at `+0x2b362d` (`12_02.h:12`); 12.02 bytes not read. |
| `RET_TRAMP` | `0x338d2b` | **Table address** `nop_ret` at `+0x2b0b26` (`12_02.h:17-18`); [verified-on-dump] the 13.60 donor's corresponding entry at `+0x255036` is a plain `ret`, despite the symbol name. Exact 12.02 bytes not read. |
| `POP_RAX`, `POP_RCX`, `POP_RDI` for arm/context/store | `0x338d2a`, `0x339712`, `0x289e0a` | **Unknown** individually; `pop_all_iret` is not a drop-in replacement because it consumes a different frame. |
| `DBREG_RESUME` tail | `0x2a5778` | **Candidate** `+0x2acb78`: the `mov_cr3_rax_mov_ds+0xe1` relation appears in the published 13.00, 13.20, and 13.60 tables (`16`). [verified-on-dump] The 13.60 donor entry is `mov dr0,rax`; the preceding load from `[rdi+0x78]` is outside the gadget, and the arm chain supplies DR0 in RAX (`11` #23). The 12.02 entry, remaining debug-register loads, and continuation stack are unverified. `cpu_switch` alone does not prove this tail. |
| `STORE_RDI8_RCX` to write `IST+8` in arm continuation | `0x3cc4af` | **Unknown** equivalent. |
| `POP_RSP` for dispatch stub and resume tail | `0x33974d` | **Unknown**. |
| `MOV_RAX_RSI`, `MOV_RAX_RDI`, `ST_RCX_RAX`, `ST_RCX_RDX` for register save | `0x958504`, `0xc5e5da`, `0x3620bf`, `0x8a2725` | **Unknown** as a set. `store_rax_rdi` at 12.02 `+0x2ac112` is a different register pairing; any substitution needs a new register-liveness proof. |
| `POP_RSI`, `POP_RDX`, `SET_DR7` for one-shot resume | `0x8aafb5`, `0x3476db`, `0xa7bd86` | **Unknown**. A debug-register instruction cannot be inferred from a nearby function address. |
| handler marker using `POP_RCX`, `POP_RAX`, `ST_RCX_RAX` | `0x339712`, `0x338d2a`, `0x3620bf` | **Unknown** on 12.02. A marker cannot be promised until a store sequence is proven and its clobbers are accounted for. |
| `CLD`, `REP_MOVSB` for later AP-copy path | `0x462c1a`, `0x304367` | `CLD` **unknown**. **Table address** `rep_movsb_pop_rbp_ret` at `+0x2efdba` (`12_02.h:15`) has an extra pop and needs a distinct frame; the 11.60 copy chain cannot be pasted. |
| `OR_RCX_EAX` for persistent hook | unused in 11.60 one-shot path | Not required if the 12.02 proof remains one-shot. |
| `POP_R8`, `STORE_RCX_R8` | absent/unused in 11.60 | Not required: `5299395/khook.c:75-84` uses RAX stores instead. The RAX store remains unverified on 12.02. |
| `getuid` DR0 execute target for F2 | Public test uses an interior body instruction | [inference] **Entry-only diagnostic candidate** `ktext+0x3130a0` from 12.02 `sysent[24].sy_call` (`16`, entry-only target). An F2 frame RIP matching this pointer would support delivery to the table entry if DR0/DR7 and dispatch are independently linked. It does not identify the public `getuid` body `+0xe` instruction or validate return. |

[inference] The table covers every gadget class used by the 11.60 arm,
dispatch, one-shot return, and AP copy path, but does **not** yield an
executable 12.02 map. A byte-level 12.02 disassembly agreeing with each
candidate would strengthen it; a differing entry instruction, side effect,
or stack delta would falsify that substitution. The unresolved pivot,
`resumectx` tail, store sequence, `pop rsp`, and the public hook's body
target are blocking dependencies for a faithful build. The data-derived
`sy_call` entry candidate narrows only an F2 delivery diagnostic. Mark
the remaining dependencies **unresolved**, not zero or
borrowed 11.60/13.60 addresses.

## Failure evidence that survives a failed return

[public-consensus] The 11.60 source already uses kernel-data cookies:
`CHAIN_MARK` in its handler, an armed-state value and saved gate/IST in the
cave, and AP `entered`/`done` plus per-VMCB counts
([`main.c` lines 17–32, 103–153, 243–275](https://github.com/gzimbric/Byepervisor-Reborn/blob/5299395b15ec91f7484ded2e7631977e0df94a4d/main.c#L17-L32)).
For 12.02, keep **raw evidence plus ordered milestones**. A PC log line is
only proof that the sender reached its own call; a missing line can also mean
the sender or transport stopped. Do not put socket I/O in the kernel chain.

| Milestone | Writer and retained PC evidence | What a positive observation establishes |
|---|---|---|
| B0 native baseline | User-mode read-only gate, all relevant IST slots, scratch/journal; `ps5log/1` with FW, build hash, boot identity without console identifiers, pinned CPU. | Starting state for this boot. |
| B1 image staged | User-mode write/readback of three **physical** spans: the small image containing arm, dispatch, and frame slots; the big chain; and a separate preseeded journal. Log sizes and independent checksums. | Staging completed; no #DB implication. |
| R0 idle worker ready | A distinct worker CPU opens its pipe and independently reads native selected gate/IST while main is idle. | Worker was present before the gate patch, with readbacks linked to B0; no trap implication. |
| B2 final pretrigger state | After all `kh_trigger`-style RBP/RIP/RSP writes, read back the selected gate/IST, those three fields, and the planned DR7 value; send the final pretrigger `ps5log/1` record before setting TF. | Gate, selected IST6 pointer to the first frame, and return context were observed before the deliberate first trap; does not prove the trap ran. |
| R1 first sampling ready | Worker rereads gate/IST, both frame preseeds, and journal preseed after B2, sends a linked record, then acknowledges the handoff. | Worker sampled the intended pretrigger locations before main issued TF; no proof TF executed. |
| F1 first hardware frame | Preseed five distinct canaries at the **selected IST6 hardware-frame slot**; in the reference layout, IST6=`scratch+0x40` and the five words start at `scratch+0x18`. A **pre-armed** independent observer captures raw RIP/CS/RFLAGS/RSP/SS without loading a new ELF after a stall. | Matching replacement by a plausible frame supports first #DB delivery to that stack, even if the pivot fails. Changed bytes alone need raw-frame review. |
| A1P / A1R arm continuation | Separate in-chain kernel-data markers **after** a verified pivot/store (A1P) and after `DBREG_RESUME` continuation (A1R), if those store sequences can be validated without losing live registers. | Narrows entry/pivot versus debug-register restore/continuation; neither marker alone proves DR7 value. |
| Q1 first sampling quiesced | Worker finishes in-flight reads/logging and reports idle after main signals an arm return. | Bounds the SDK/logger ownership transfer before A2; it is a control report, not proof of a valid kernel return. |
| A2 arm returned | User-mode `ps5log/1` record after the TF/NOP arm return, with readback of all 16 IST6 qwords, the selected dispatch pointer, and the journal armed word. | First return completed; all 16 values matched when read before the second trigger. The reads are sequential, not an atomic snapshot. |
| R2 second sampling ready | Worker rereads patched gate, dispatch IST6, untouched F2 canaries, and D1S/D1O preseed after A2, then acknowledges the handoff. | Worker sampled the second pretrigger state before the selected test syscall; no proof the syscall reached the hook. |
| F2 second hardware frame | Distinct canaries in the **dispatch IST6 frame slot**; in the reference layout, IST6=`scratch+0x240` and the words start at `scratch+0x218`. The pre-armed observer samples independently before recovery if a later failure occurs. | Supports kernel hook #DB delivery; not handler completion. |
| D1S / D1O dispatch/handler | Separate in-chain markers **after** the required interrupted registers are saved (D1S) and after the test oracle store but before the resume tail (D1O). A 12.02 liveness review must prove the marker's RAX/RCX clobbers harmless. Record raw frame and marker words in the independent audit. | Separates entry/register-save, handler action, and resume-tail failures, subject to verified store gadgets. |
| Q2 second sampling quiesced | Worker finishes in-flight reads/logging and reports idle after main signals a syscall return. | Bounds the ownership transfer before restoration; it is not an independent kernel-return proof. |
| D2 kernel resumed | User-mode record after the selected test syscall returns, then gate/IST restoration readback and BYE. | Full test-hook transaction completed; it does not prove the later sleep/AP phase. |
| H1 AP phase | Separate `entered`, selected-VMCB count, write count, verify count, and `done` evidence, following the 11.60 read-before-write validation pattern. | Only a full expected set and readback can support a 12.02 AP claim. |

**Proposed KH2 host log contract, not yet emitted by a 12.02 chain.** A
user-mode observer sends `ps5log/1` `MARK` lines beginning `KH2 stage=…
source=… cpu=… verified=1`. The source tag names where it read the evidence:
`B*`, `A2`, and `D2` use `user`; `F*` uses `frame`; `A1P`, `A1R`, `D1S`, and
`D1O` use `journal`; the `R*`/`Q*` handoffs use `observer`.
`verified=1` alone is never accepted; each stage carries
the raw values below. All addresses and 64-bit words use `0x` hex, all
SHA-256 values use 64 hex digits, and CPU is a decimal 0–15. These checks
test internal consistency; instruction-byte validation and independent
same-attempt capture are separate requirements. A duplicate or malformed
`key=value` field is rejected so a later value cannot silently replace an
earlier one in the host parse.

| Stage | Required KH2 fields after the common header | Host check |
|---|---|---|
| B0 | `fw=12.02 build_sha=… scratch_sha=… gate_lo=… gate_hi=… ist6=… f1_slot=… f2_slot=…` | Records the native gate/IST/scratch baseline and two aligned, nonoverlapping planned five-word frame slots. A run identity and layout version remain in the surrounding `ps5log/1` manifest. |
| B1 | Three records, one each with `part=image`, `big`, `journal`; each has `addr=… bytes=… before_sha=… image_sha=… readback_sha=…`. The image carries `rbp_addr=… rip_addr=… rsp_addr=… dr7_addr=…`; the journal carries `<stage>_addr=… <stage>_before=…` for each of `a1p`, `a1r`, `d1s`, `d1o`. | Read and hash each span **before** its write, then hash the staged bytes and their readback. Each span has positive length, matching staged/readback hashes, and is disjoint from the other two; only all three count as B1. Both frame slots and four distinct aligned context qwords fit within `image`, without overlapping each other. The journal preseed words occupy distinct aligned qwords inside its region. |
| R0 | `observer_cpu=… build_sha=… gate_lo=… gate_hi=… ist6=… pipe_ready=1 idle=1` | A distinct CPU reports that its pipe is open and it sampled the native selected gate/IST while idle after B0/B1, before main patches the gate. Build hash and readbacks must match B0; this is a worker report, not a kernel-frame observation. |
| B2 | `gate_lo=… expected_lo=… gate_hi=… expected_hi=… ist_count=… ist_matched=… ist_image_sha=… ist_readback_sha=… ist6_actual=… ist6_expected=… rbp_actual=… rbp_expected=… rip_actual=… rip_expected=… rsp_actual=… rsp_expected=… dr7_actual=0x403 dr7_expected=0x403 f1_can0=…` through `f1_can4=…`, and `f2_can0=…` through `f2_can4=…` | Gate words agree and differ from B0; all 16 IST6 values match the planned image and its readback hash. The selected IST6 readback and expectation must both equal `B0.f1_slot+0x28` and differ from native `B0.ist6`. Final RBP/RIP/RSP values match the captured user continuation, RIP/RSP are nonzero, and the `resumectx` DR7 arm word matches the 11.60 value. All ten pretrigger frame canaries are distinct. This record belongs **after** the final context writes and **before** TF. |
| R1 | `observer_cpu=… gate_lo=… gate_hi=… ist6=… f1_slot=… f2_slot=… f1_can0..4=… f2_can0..4=…` and each `<stage>_addr=… <stage>_before=…` for `a1p`, `a1r`, `d1s`, `d1o` | Worker rereads the selected gate/IST, both frame preseeds, and all journal preseeds after B2. Values must match B0/B1/B2, and CPU must match R0. Main waits for this report and acknowledgment before TF. |
| F1 / F2 | `slot=… rip=… cs=… flags=… rsp=… ss=… can0=… can1=… can2=… can3=… can4=…` | Slot matches B0; all five reported canaries match that frame's independent B2 readback, and the raw five-word frame differs. A plausible hardware frame still needs human review. |
| A1P / A1R / D1S / D1O | `addr=… before=… after=… expected=…` | Address and `before` match that marker's B1 journal preseed; the word changed and equals the expected marker. Marker ownership and gadget placement still need independent proof. |
| Q1 | `observer_cpu=… reason=arm_return idle=1 inflight=0 samples=…` | Worker reports quiescence after the first return signal, with at least one sample and no read in flight. Main waits for acknowledgment before SDK reads/writes and A2. Missing Q1 leaves that ownership handoff unverified. |
| A2 | `ist_count=… ist_matched=… ist_before_sha=… ist_image_sha=… ist_readback_sha=… first_bad_cpu=… first_bad_ist=… ist_actual=… ist_expected=… armed_addr=… armed_actual=… armed_expected=…` | All 16 IST6 qwords are reread: count matches B2, `ist_before_sha` links to B2's arm image, the planned dispatch image hash equals the readback hash, and every pointer matches. Success uses `first_bad_cpu=16 first_bad_ist=0x0`; a mismatch record names its first CPU and raw pointer but is not accepted as A2. The selected value equals `B0.f2_slot+0x28` and differs from native `B0.ist6`. The nonzero armed-state qword is a free aligned word inside B1's journal. |
| R2 | `observer_cpu=… gate_lo=… gate_hi=… ist6=… f2_slot=… f2_can0..4=… d1s_addr=… d1s_before=… d1o_addr=… d1o_before=…` | After A2, worker rereads the patched gate, selected dispatch IST6, untouched F2 canaries and dispatch journal words. Values must match B1/B2/A2; main waits for acknowledgment before the test syscall. |
| Q2 | `observer_cpu=… reason=syscall_return idle=1 inflight=0 samples=…` | Worker reports quiescence after the second return signal. Main waits for acknowledgment before D2 restoration and logging. |
| D2 | `returned=1 gate_restored=1 scratch_restored=1 ist_restored=… gate_lo=… gate_hi=… ist6=… scratch_readback_sha=… image_restored_sha=… big_restored_sha=… journal_restored_sha=…` | The return/restoration assertions are present; restored IST count equals B2's count, selected gate/IST/scratch readbacks equal B0, and each B1 span's final hash equals its prewrite `before_sha`. B1/A2 geometry links the later context and armed-state writes to restored spans (`11` #33–#34). The AP phase has its own evidence set. |

The planned phase order is `B0 B1 R0 B2 R1 F1 A1P A1R Q1 A2 R2 F2
D1S D1O Q2 D2`; B1 has three physical-part records. Frame and journal
reports can arrive later than their kernel writes. The `R*`/`Q*` records are
worker-origin control evidence; they must use the same selected CPU, name
the distinct observer CPU from R0, and be linked to earlier raw readbacks.
They do not authenticate the worker or prove a #DB instruction executed.

Legacy bare `KH1 … verified=1` records are rejected because they omit the
frame, journal, and readback values. A KH2 line can still be false if its
producer fabricated or sampled the wrong address; the classifier cannot
authenticate a kernel event from text alone.
The separate `ERR` line `KH2E stage=… cpu=… operation=read|hash|write
region=… addr=…` is a separate failure report. The classifier preserves it
as `capture_errors`/`first_capture_error` but never counts it as a KH2
milestone. A retained R1 `KH2E` with no R1 record identifies the reported
failed read; it says nothing about whether a later trap could have fired.
`write` is accepted for B1/B2/A2/D2. The off-tree main producer's
write wrappers report an attempted B1 chunk, B2 gate/IST6/context, A2
selected IST6/armed word, or D2 gate/IST6/span/scratch address if its
callback fails. `tools/kh2_layout_check.py --log` maps such errors
to the proposed B1 offset and landing CPU when applicable, IST6 CPU,
gate word, context field, or armed journal word in
`write_error_locations`; a failed write leaves that stage unverified.
The D2 scratch address remains raw with `plan_match=false` unless the plan
also includes a scratch base and size. A reported address identifies the
failed callback attempt, not the last byte written or the first instruction
that failed.
[inference] `KH2E` cannot appear if a console freeze prevents the write
callback from returning. The off-tree producer now emits `KH2W
stage=… cpu=… region=… addr=… bytes=… state=begin|done` before and after
each B1/B2/A2/D2 write callback. Its send must return before the callback
starts; a failed `begin` send blocks that write. The classifier pairs these
records and reports `open_write_attempts` and `last_write_attempt`, while
`tools/kh2_layout_check.py --log` maps each attempt to the proposed span,
landing CPU, or field. A retained `begin` without `done` or `KH2E` narrows
the unobserved interval to that callback or its following log send; missing
transport, a partial write, or an unobserved later record can produce the
same pattern. A retained same-attempt `done` would falsify the claim that
this particular callback stayed in flight. `done` means the callback
returned success, not that the kernel bytes were read back; the KH2 stage
record still carries that later evidence.
[inference] The main-thread `kernel_copyout` path has the same returned-error
blind spot. Its off-tree producer now emits `KH2R stage=… cpu=… region=…
addr=… bytes=… state=begin|done` around each B0/B1/B2/A2/D2 read callback,
in chunks no larger than `0x500`. The classifier reports
`open_read_attempts` separately from KH2 milestones, and the layout checker
maps the reported range to a candidate gate, IST6 CPU, frame, context word,
or staged span when the full range fits. A retained open read narrows an
unobserved interval; a missing `done` can also mean the following log send
failed or its PC record was lost. A retained `done` would falsify the claim
that this callback remained in flight. The host run paired 85 main reads;
its added 170 log lines may change timing while the shared gate is patched.
[inference] The bounded observer handoff reads now emit the same paired
`KH2R` format at R0 (two reads), R1 (eight), and R2 (five). The classifier
and layout checker accept and locate these 15 attempts separately from the
handoff milestones. A retained open R1/R2 bracket narrows a missing handoff
to that read callback or its following send, subject to transport loss.
The repeated F1/F2 and journal scans remain unbracketed so the observer
does not double its PC sends on every poll; a stall in one of those scans
still cannot be located more closely than its last retained frame/journal
record or `KH2E`. Same-attempt evidence of a completed read would falsify
an inference that its callback stayed in flight. No console timing or
retention test has validated the added handoff sends.
A larger 12.02 span would emit more lines.
No console timing or PS5 read callback was exercised in this offline check.
[inference] A callback may have changed part of a span before returning an
error; a same-attempt read of the entire original span would falsify a
partial-change claim for that event. The logger's send result is not a
durable PC acknowledgment (`engineering/projects/logging_server/client/ps5log.h:734-749`).
[verified-in-tree] `tools/khook_trace_classify.py:336-470,593-602` and
`tools/kh2_layout_check.py:176-226,287-299,333-358` define the host-side
distinction; their focused tests exercise it.

[inference] A later frame report cannot establish a canary replacement by
supplying its own unlinked `can0..4` values; likewise a journal report cannot
establish a transition by supplying its own `before` word. The independent
B2 pretrigger frame readback and B1 journal preseed make these comparisons
auditable across records. A same-attempt capture showing different preseed
values at the stated addresses would falsify the reported change or the
address map. The values still do not authenticate the producer or prove a
valid #DB entry (`11` #29). Likewise, D2 must compare **all three** B1
prewrite span hashes, because B0's scratch region need not contain those
separate spans. A layout proving every B1 write lies wholly within the B0
scratch hash region would falsify the need for separate D2 hashes for that
specific layout (`11` #33). Those hashes cover later `resumectx` and
armed-state writes only if their actual addresses lie inside the B1 image
and journal respectively; B1 and A2 now report/check that geometry (`11`
#34). A same-attempt direct read at a different write address would falsify
the reported coverage.

[public-consensus] The 11.60 installer writes one first-`0x500` image
containing the arm and dispatch stacks/frames and separately writes its big
chain (`5299395/khook.c:390-441`). Its `kh_trigger` then patches the saved
user RBP and arm RIP/RSP **after** the gate has been installed and just before
setting TF (`khook.c:458-478`). [inference] A 12.02 copy that logs only the
image hash and gate readback before these final writes leaves a preparation
gap: it cannot tell a bad return-context value from a failed exception
delivery. B2 closes that *logging* gap by reading the final fields before
TF; it does not validate the 12.02 `resumectx` consumer or guarantee safe
delivery. A future trace showing the final fields differ despite B2 claiming
equality would falsify the proposed readback or its address calculation.

[inference] The pinned two-frame geometry places each five-qword hardware
frame immediately below its IST6 top, so the selected pretrigger pointer must
be `f1_slot+0x28` and the selected post-arm pointer must be `f2_slot+0x28`.
Hash/count equality for an IST write can be true even if the image contains
the native pointer or a wrong stack address. KH2 therefore records the
selected qword separately in B2 and A2 (`11` #31). A finalized 12.02 layout
that deliberately uses another frame size or stack placement would falsify
these equations and require a new contract/layout version before use; this
check does not validate the still unknown 12.02 pivot instruction.

`tools/khook_trace_classify.py RUN.log --manifest RUN.json` compares this
proposed phase order with **report arrival order**, checks the ps5logd manifest's gaps/clean flag, and the
verbatim log SHA-256. It returns the **first missing direct observation**,
later records, and transport status; it does not inspect the kernel bytes or
turn absence into a claim that a trap failed. A later stage with a missing
earlier marker is a coverage gap. `out_of_order` flags a difference in report
arrival order; it is **not** proof that kernel execution reversed. The
independent observer may sample frame and journal addresses after subsequent
steps have already run, or emit their reports in scan order.
`causal_order_conflict` is reserved for reversal among the user/observer
handoff records `B0`, `B1`, `R0`, `B2`, `R1`, `Q1`, `A2`, `R2`, `Q2`, and `D2`.
A B1 part sent before B0 is rejected
because its physical layout cannot yet be checked. B2 gate and D2 restoration claims require the B0 native baseline for
comparison (`11` #27). The
classifier reports every missing stage and the missing handoff records in
addition to the first gap. Its synthetic tests are in
`tests/test_khook_trace_classify.py`; no real 12.02 run has yet produced this
record format.

[inference] For the entry-only candidate in `16`, the classifier accepts an
optional `--f2-entry-ktext-base` supplied from the **same run**. It adds the
data-derived `0x3130a0` offset and compares the accepted F2 frame RIP with
that absolute address, reporting `equal`, `different`, or `no_accepted_f2`.
The comparison preserves a changed F2 frame even when RIP differs; it does
not turn a missing frame into a failed-breakpoint verdict. The base is an
operator assertion, not authenticated by the KH2 log, and address equality
alone cannot establish DR0/DR7 programming, the syscall dispatch path, or a
valid handler return. A same-attempt DR0 readback or instruction trace
contradicting the asserted target would falsify its link to this F2 frame.
The flag is unavailable in the legacy `kstuff-fullchain` mode.

[inference] B2's gate readback currently compares with expected words supplied
by the same producer; that alone cannot identify the intended pivot. With
`--b2-pivot-ktext-base` from the **same run**, the classifier independently
encodes the candidate `ktext+0x2ac2de` as a present DPL0 interrupt gate using
selector `0x20` and IST6, then compares both accepted B2 qwords. It reports
`equal`, `different`, or `no_accepted_b2` plus the decoded target, selector,
IST, type, DPL, and present bit. The selector is the live native 12.02 value
recorded in `16`; the target offset remains a cross-firmware candidate, not
verified 12.02 instruction bytes (`11` #23). The base is an operator
assertion, and an address match does not prove the pivot executes or the
first #DB was delivered. A same-attempt gate readback with different words
would falsify equality; a 12.02 text image lacking the required pivot bytes
would falsify the candidate's execution contract. [public-consensus] The
descriptor encoding follows the public
[`gate_encode`](https://github.com/gzimbric/Byepervisor-Reborn/blob/5299395b15ec91f7484ded2e7631977e0df94a4d/khook.c#L22-L33).
The option is unavailable in the legacy `kstuff-fullchain` mode.

**Native format scaffold, built and host-tested offline:** the separate local
payload workspace now contains `kh2_trace_format.c/.h` and
`kh2_trace_format_host_test.py` under
`engineering/payloads/byepervisor_probe_1202/`. The pure C formatter
generates bounded KH2 text for `ps5log/1` without kernel reads or writes.
The host check compiled it with `cc`, matched every one of the 16 stage
formats and 18 records (including all B1 parts and five handoffs) against the classifier's
fixture, and classified the resulting complete transcript with no rejected
record. The formatter source SHA-256 is
`b1c197a74e763c415df3d496050934d54dd6259e196751970af5da1eea249b99`.
This is a **formatter**, not a KH2 producer: no 12.02 chain supplies its
raw fields, no prearmed KH2 frame/journal observer is integrated, and no
console experiment has run. A successful `ps5log_line` call means the
client accepted a send, while only a retained PC log and matching manifest
show what reached `ps5logd` before a possible shutdown. A generated fixture
does not establish any kernel milestone.

**Native capture scaffold, host-tested offline:** the separate payload
workspace now also contains `kh2_capture.c/.h` and
`kh2_capture_host_test.py`. The sampler reads selected kernel-data addresses
through a supplied callback, emits raw R0/R1/R2 values before reporting a
mismatch, samples F1/F2 and four journal words, and formats Q1/Q2 after at
least one successful pass. Its host test generated 11 native milestones
and 30 R0/R1/R2 read brackets; with the existing B0/B1/B2/A2/D2 fixtures,
the classifier accepted all 18 milestones and 15 paired observer reads.
It also exercised a wrong F1 canary, failed read with `KH2E`,
failed send (including the `KH2E` path), and premature Q1. The C source SHA-256 is
`e938883f305114de17ab2ba9a90931413eed602d5a5c6ae64855b35d94285b72`.
The sampler is **not a synchronized worker**: its Q records depend on a
main/worker return signal and ownership transfer, which it cannot
verify on its own. The separate worker schedule below supplies those calls
in a host mock. A host fixture does not establish a console event. The later
PS5 callback bridge links this core into a smoke ELF, but no 12.02 chain
invokes it. The first changed frame sample
may also be partial and needs raw frame review.
The current host mocks exercise a packed IST6 field address at `+4` modulo
8; the capture initializer no longer rejects that TSS geometry (`11` #37).

**Host-only worker handoff scaffold:** `kh2_worker.c/.h` runs the sampler on a
pthread. R0 completes before main owns B2; `begin_arm` returns only after
R1 and one scan, `end_arm` waits for an in-flight scan and Q1 before main
owns A2; the second pair similarly bounds R2, the test syscall, and Q2.
`stop` runs the worker's close callback before D2. Its host check completed
20 two-transaction mock schedules with 18-record classifier acceptance,
observed no worker reads while main owned the inter-trap interval, blocked
a mismatched R1, and reported an active read failure with `KH2E` and no Q1.
The C source SHA-256 is
`8d0123922018fc7e3e56539f6e6e2de6152064838e4fc054a2f2f2071b4ccf9f`;
it cross-compiled as a PS5 SDK object. The `prepare`/`finish` callbacks are
mocked, so this does not prove a distinct console CPU, real pipe ownership,
logger serialization, or any #DB delivery. A timeout leaves ownership
uncertain and cannot be treated as permission for another trigger.

**Host-only main readback scaffold:** `kh2_main_capture.c/.h` reads and emits
B0, the three B1 parts, B2, A2, and D2 through supplied read, SHA-256, and
send callbacks. It requires a B1 prewrite snapshot for each physical span;
its write callback wrappers then stage each B1 span in at most `0x500`-byte
calls, reporting a failed call's address as `KH2E`. The B2 wrapper requires
four context writes, then all 16 IST6 writes, and separate high- then
low-qword shared-gate writes last; an early gate, IST6, or low-qword request
is rejected (`11` #40–#41). It reports any callback
failure before the final B2 readback. A failed write
does not authorize a trigger or imply successful restoration.
[inference] Moving context writes ahead of the gate removes the deliberate
sequence in which some had not yet been attempted after redirection. It does
not prove their values at the patch instant: B2 reads them only afterward.
The native #DB handler can still see staged IST6 values before the gate
patch, and the new handler can be reached before B2 readback. A same-attempt
pre-gate read contradicting any planned context qword would falsify the
assumption that all four were staged before redirection. No console run has
tested this sequence.
[inference] Each gate qword has its own `KH2W` bracket at `gate+8` or `gate+0`; a failed
callback identifies which qword was attempted. A retained high `done` and
low `begin` without `done` bounds the failure to the low callback or its
following send, subject to PC transport retention; a same-attempt low `done`
would falsify that narrower in-flight reading. [public-consensus] The public
11.60 installer writes high then low
([`khook.c:443-454`](https://github.com/gzimbric/Byepervisor-Reborn/blob/5299395b15ec91f7484ded2e7631977e0df94a4d/khook.c#L443-L454)).
[inference] This does not make the intermediate gate state safe or prove either word's
readback before B2. Each wrapper sends `KH2W begin` before the supplied write callback and
`KH2W done` only after it returns success. A send failure blocks later
wrapper writes. The host check exercised 49 paired attempts in its complete
transcript and a failed `begin` send that invoked no write callback.
The A2 wrapper requires the main-owned intertrap interval, writes the
selected IST6 pointer to F2 and then a nonzero free journal word. The D2
wrapper requires the worker stopped, restores native gate high then low as
separate qwords and all 16 IST6
words, then three B1 spans in `0x500`-byte chunks and B0 scratch. Failed
A2/D2 callbacks report `KH2E` and block a wrapper retry. A failed D2
restoration leaves the actual kernel state unknown until a separate read or
recovery.
D2 rereads all three spans and compares their hashes to those snapshots.
B2/A2/D2 require the matching main-owned worker state. A2 now rereads all
16 IST6 qwords, compares them with B2's arm image after advancing only the
selected pointer to F2, and emits the first mismatching CPU and raw value.
The host check used
native C to emit seven main records and combined them with 11 records from
the separate worker mock; the resulting 18-record transcript passed the
classifier. An un-restored journal was rejected at D2; changing another
CPU's IST6 qword was rejected at A2 with `first_bad_cpu=7`. Injected
B1/B2/A2/D2 write failures emitted retained `KH2E` without the
corresponding success record. These are two mock
processes, not one same-attempt console trace. The C source SHA-256 is
`1f82a4e36d3d2eb802fbaab2063a77f8cb4be0de89bbc1c52e12a4783cb799b2`;
it cross-compiled as a PS5 SDK object. The expected 12.02 addresses/values
and mock worker states still require a real chain.

[inference] The extra 15 SDK reads at A2 lengthen the interval with the
shared #DB gate patched. A live build must budget and log this duration and
retain the approved hard power-cycle recovery plan; a measured shorter or
unchanged window in an integrated run would falsify the estimated exposure.
No updated A2 producer has run on the console. Sequential reads cannot rule
out an unrelated concurrent write between two samples.

**Off-tree PS5 callback bridge:** `kh2_ps5_adapter.c/.h` supplies the SDK
main-read and main-write, separate-pipe worker-read, `ps5log` send, CPU pin/check, and
pipe prepare/finish callbacks. `kh2_sha256.c/.h` supplies the SHA callback;
its 17 host vectors matched `hashlib`, including padding boundaries and a
million-byte input. A PS5 SDK smoke ELF linked the bridge, logger, observer
channel, and all KH2 producer modules. It did not run on a console or
call those callbacks. The callback source hashes and test name are in `05`.
The bridge does not supply a staged chain or restoration sequence, a verified 12.02
layout or gadget bytes, a test-hook boundary, or a return signal. A socket
send result still needs a retained PC run file and manifest to establish
transport integrity.

**Single-process host rehearsal:** `kh2_integrated_host.c` uses the real
main emitter and pthread worker against one mock memory image and one log,
with callback ownership checks through both transactions, including A2
and D2 writes. The host test
completed 20 ordered transcripts with 18 KH2 milestones, 98 `KH2W` lines,
and 200 `KH2R` lines each; an un-restored journal caused
D2 rejection. The source hashes and test name are in `05`. The two
frame/journal changes are simulated mock writes, so the passing transcripts
establish callback ordering and record linkage, not a #DB, an SDK pipe
handoff on PS5, or PC retention.

### Two-transaction observer ownership schedule

[inference] The one-trap prearmed worker cannot simply keep sampling across
the faithful two-trap test. Its `observer_channel_read` writes its pipe fields
through the inherited SDK primitive before reading from a distinct pipe
(`engineering/payloads/byepervisor_probe_1202/observer_channel.c:65-75`);
the existing worker yields that primitive to main only after stopping
(`fullchain_prearmed.c:602-625`). The `ps5log` client also states that calls
from different threads must be serialized
(`engineering/homebrew_ps5/projects/logging_server/client/ps5log.h:31`).
[inference] If stdout capture is enabled, main-thread `printf` also writes
through the log socket; it must be deferred or covered by the same logger
handoff. A trace with clean, noninterleaved records from a separately
synchronized logging implementation would falsify this restriction for that
implementation.
[public-consensus] The reference `kh_trigger` writes RBP/RIP/RSP after gate
installation ([`khook.c:462-482`](https://github.com/gzimbric/Byepervisor-Reborn/blob/5299395b15ec91f7484ded2e7631977e0df94a4d/khook.c#L462-L482));
the test path performs further kernel writes after the arm return and before
its first `getuid`
([`main.c:71-80`](https://github.com/gzimbric/Byepervisor-Reborn/blob/5299395b15ec91f7484ded2e7631977e0df94a4d/main.c#L71-L80),
[`main.c:462-475`](https://github.com/gzimbric/Byepervisor-Reborn/blob/5299395b15ec91f7484ded2e7631977e0df94a4d/main.c#L462-L475)).

| Interval | SDK kernel R/W and `ps5log` owner | Required handoff evidence before the next boundary |
|---|---|---|
| Before first trap | Worker opens its independent pipe, reads native gate/IST, and sends R0 while main is idle, then yields. Main owns staging, context writes, all IST6 writes, the final gate patch, and B2 readback/log while worker waits idle. | After B2, main relinquishes both shared resources. Worker samples gate, selected IST6, both frame preseeds, and journal preseed, reports R1 raw values, then acknowledges readiness. Only then may main issue TF/NOP without SDK reads/writes or logger calls. |
| First trap through arm return | Worker owns sampling and logging of F1/A1P/A1R. Main executes the trap/return path without touching the SDK primitive or logger. | On return, main requests quiescence. Worker finishes any in-flight read/send and acknowledges idle before main reads the dispatch IST6 or emits A2. If no return, worker can continue sampling until shutdown, subject to transport survival. |
| Between traps | Main owns A2 readback/log and any state/oracle writes or reads required before the test syscall. Worker remains idle. | Main relinquishes the resources again. Worker verifies dispatch IST6 and F2 canaries, reports its pretrigger sample, and acknowledges readiness before main calls `getuid`. |
| Second trap through return | Worker owns F2/D1S/D1O sampling and logging. Main invokes the test syscall without concurrent SDK R/W or logger calls. | After return, worker quiesces and acknowledges idle before main performs D2 restoration/readback and closes the log. |

The proposed KH2 contract now names R0/R1/Q1/R2/Q2 and the classifier
checks their raw links and order. The host sampler can format them from mock
data, but **no integrated 12.02 producer or worker emits them**, so this
remains an offline log specification, not a verified ownership schedule.
The host-only worker and main emitter complete a same-process mock handoff,
and the SDK callback bridge links offline. A console attempt still needs
integration with verified 12.02 addresses and gadget bytes, actual
staging/restoration writes, a return signal, and a retained PC transcript.
An implementation with a truly independent kernel
read primitive and synchronized thread-safe logger would falsify the need for
this exact ownership transfer, but not the need to capture both frames before
recovery (`11` #32). The observer CPU's own incidental #DB remains a separate
shared-gate hazard. This is an offline map only; any live 12.02 build still
requires owner approval and a hard power-cycle recovery plan.

### Pinned 11.60 marker placement arithmetic

[public-consensus] In commit `5299395`, `kh_chain_store` emits five qwords
(`POP_RCX`, address, `POP_RAX`, value, `ST_RCX_RAX`), so each proposed marker
costs `0x28` bytes
([`khook.c:75-84`](https://github.com/gzimbric/Byepervisor-Reborn/blob/5299395b15ec91f7484ded2e7631977e0df94a4d/khook.c#L75-L84)).
The fixed arm, continuation, and big-chain limits come from that commit's
[`khook.h:30-37`](https://github.com/gzimbric/Byepervisor-Reborn/blob/5299395b15ec91f7484ded2e7631977e0df94a4d/include/khook.h#L30-L37).
[inference] The following **source-layout plan**, with offsets relative to
the reference scratch or big-chain base, accommodates four markers; a
12.02 build with different gadget stack effects or code layout would
falsify its applicability.

| Region | Proposed intervals and consequence |
|---|---|
| Arm `scratch+0x40..0xa0` | A1P at `+0x40..0x68`, then the original five-qword arm chain at `+0x68..0x90`; `0x10` remains before the continuation. |
| Continuation `scratch+0xa0..0x140` | A1R at `+0xa0..0xc8`, then the original continuation and user iret frame at `+0xc8..0x120`; `0x20` remains before the `resumectx` area. The generated arm RIP and RSP slots move to `scratch+0xf8` and `scratch+0x110`. |
| Dispatch `big+0x00..0x600` | The register save ends at `+0x58`; D1S is `+0x58..0x80`, the one-store test handler is `+0x80..0xa8`, and D1O is `+0xa8..0xd0`. The restore sequence starts at `+0xd0`; with the pinned one-shot test tail the chain ends at `+0x138`, within the `0x600` buffer. |

[inference] The two dispatch markers move `restore_off` from the original
`0x80` to `0xd0`. The three self-modifying save targets must therefore
move from `big+0x88/0x98/0xa8` to `big+0xd8/0xe8/0xf8` for RDI/RSI/RDX,
respectively. The pinned source computes these targets from `restore_off`
([`khook.c:401-419`](https://github.com/gzimbric/Byepervisor-Reborn/blob/5299395b15ec91f7484ded2e7631977e0df94a4d/khook.c#L401-L419));
adding marker qwords without changing that formula would make the save
gadgets write into the wrong chain words. A source build showing correctly
relocated save targets would falsify this specific omitted-update failure.

[inference] Placement before the arm's existing `POP_RAX` reloads the hook
target after A1P's RAX/RCX clobbers. Placement at the start of the
continuation precedes its `POP_RDI`/`POP_RCX` reloads. D1S follows the
reference RSI/RDI/RDX saves, and D1O follows the **one-store test** handler;
the latter's RAX/RCX clobbers need a separate liveness review for any other
handler. This is conditional on the actual gadget side effects and does not
turn an unverified 12.02 store sequence into a usable marker.

`tools/khook_marker_layout.py` reproduces the numeric check from the three
public files in commit `5299395` (`include/khook.h`, `khook.c`, `main.c`).
From a local clone of the public repo, run:

```sh
git -C /path/to/Byepervisor-Reborn show 5299395b15ec91f7484ded2e7631977e0df94a4d:include/khook.h > /tmp/khook-529.h
git -C /path/to/Byepervisor-Reborn show 5299395b15ec91f7484ded2e7631977e0df94a4d:khook.c > /tmp/khook-529.c
git -C /path/to/Byepervisor-Reborn show 5299395b15ec91f7484ded2e7631977e0df94a4d:main.c > /tmp/khook-529-main.c
python3 tools/khook_marker_layout.py --header /tmp/khook-529.h --source /tmp/khook-529.c --main /tmp/khook-529-main.c
```

It verifies the five-qword helper and source-side save/restore slot formula,
reports the computed intervals and source hashes, and rejects the later
unmodified upstream `kh_chain_store` helper because it uses a different
POP_R8/store pair. It also rejects a deliberately changed RDX save-slot
offset. No third-party source, dump, or payload is stored in this repo.
This check proves source arithmetic only; it does not supply 12.02 gadget
bytes, journal ownership, a final per-CPU layout, or a runnable ELF.

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
proposed two-transaction `KH2` format:

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
`engineering/payloads/byepervisor_probe_1202/fullchain_prearmed.c:113-262,550-652`
builds `byepervisor_probe_1202_fullchain_prearmed.elf`, SHA-256
`39b9ba4bd673c2771a90c49f5808327af9e77288eab85a39d4aae1f5e82e7ca5`.
The earlier PR #97 live, setup, and audit ELF hashes remain unchanged.
The worker runs on a second permitted CPU and sends `FC1 READY` before the
main thread stages IST4 or changes the gate. After the main thread writes and
reads back all 16 IST4 slots and the gate, the worker independently reads the
full gate and all 16 IST4 values and sends `FC1 GATE_VERIFIED` with raw gate
qwords, expected qwords, matched count, and first mismatch. The trigger waits
for that PC send and acknowledgment. While armed, the worker reads all 16
preseeded five-word frames and copy markers, sending each first change as
`FC1 FRAME` or `FC1 MARKER`; successful return joins it before the main
thread resumes SDK kernel R/W operations. In this second offline build the
worker first reads the selected CPU's `0x500`-byte slot and reports it, then
sweeps all 16 slots. Each frame/marker record includes `sample=targeted` or
`sample=sweep`. This reduces the selected frame's first-read latency relative
to a five-page sweep; it cannot guarantee a sample before an immediate
shutdown. A timeout or unsafe teardown parks.

[verified-in-tree] The `FC1` local sequence begins at 1; its stages are
`READY`, `GATE_VERIFIED`, zero or more `FRAME`/`MARKER` records, and
`QUIESCED` (or `READ_FAIL`). `READY` includes FW, a **version tag**
`build=prearmed-v2`, and selected/observer CPU numbers. The exact ELF SHA is
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
[verified-in-tree] The classifier also compares the selected CPU named by
`[K1]`, the PC staging record, and `FC1 READY` when `--pc-same-run` is
asserted. A disagreement yields `conflicting_probe_cpu_records` before any
gate/frame/marker progress claim (`tools/khook_trace_classify.py`).
For `prearmed-v2` it requires the sample mode and rejects a `targeted`
record naming a CPU other than the trigger CPU; v1 records remain readable.

[verified-in-tree] The worker also emits `FC1 READ_FAIL` if its private-pipe
read fails and emits an `ERR`-level `GATE_VERIFIED` with raw values if the
gate or an IST4 pointer differs (`fullchain_prearmed.c:181-213,250-256`).
The host classifier reports these separately as
`observer_read_failed_after_main_patch_phase` and
`observer_gate_or_ist_mismatch_after_main_readback` when linked to the same
run. Both mean the main thread reached the observer handoff after its own
patch readback; neither proves `ICEBP` executed. A later `READ_FAIL` during
scratch sampling is retained as a signal without erasing a preceding
positive gate/frame/marker record. The classifier flags a copy marker with
no corresponding frame report for raw review. [inference] The targeted
`0x500` read is not guaranteed to be atomic across a page boundary, and the
later sweep reads five pages sequentially. A sample can therefore combine a
pretrap frame with a later marker; a second sample showing the changed frame
would resolve that sampling ambiguity. This does not justify calling the
missing frame a failed #DB delivery.

[inference] This is still a risky one-`ICEBP` diagnostic, not the 11.60
two-transaction port. Its second `pop_all_iret` frame does not restore an
incidental CPU's original GPRs, and the observer itself runs during the
shared-gate window. A byte-level all-register save/restore path in the
current build would falsify this source reading; none is present in
`fullchain_prearmed.c:502-534` or `fullchain_icebp.S:9-27`. The 12.02 gadget
bytes remain unavailable. Building and classifying it offline do not approve
a console run.

**Source-layout cross-check.** [verified-in-tree]
`tools/fullchain_layout_check.py` reads the isolated C source and public
Kstuff `ps5-kstuff/structs.inc` rather than assuming the two register-frame
layouts agree. Run it with those two paths, for example:

```text
python3 tools/fullchain_layout_check.py \
  /home/manuel/personal/ing_pereira/engineering/payloads/byepervisor_probe_1202/fullchain_prearmed.c \
  /home/manuel/personal/ing_pereira/engineering/third_party/kstuff-lite/ps5-kstuff/structs.inc
```

It checks eight register offsets, the `F−0x28` hardware frame, the
`+0xe8` entry-iret landing, both pop-all frames, the copy `pop rbp; ret`
handoff, slot bounds and overlap, and the staged/observer canary formula.
The current prearmed source passes geometry with 16 disjoint `0x500` slots
(`0x5000` total) and **80 distinct canary words**. The unchanged PR #97
`fullchain_allcpu.c` has the same source geometry but only **20 distinct
values among 80 canary words**: bitwise OR with `cpu<<8` cannot encode all
16 CPUs because the base constant already has bits set in that byte
(`11` #26). Each slot still has a distinct address and five different
word canaries; the collision limits value-only CPU attribution. This
checker does **not** inspect the ELF's actual instructions, 12.02 gadget
bytes, runtime scratch ownership, or exception delivery.

[inference] A read-only `llvm-objdump` check of the exact prearmed ELF above
found `fullchain_icebp` at ELF `.text+0x2270`, its literal trap byte `f1`
at `+0x227d`, and `fullchain_after_icebp` at `+0x227e`. In `main`, the
emitted call at `+0xf6d` targets that wrapper, followed by `stop_observer`
at `+0xf73` and `restore_all` at `+0xf91`. The worker has four emitted
`observer_channel_read` call sites: the targeted `0x500` read at `+0x1cab`
precedes `report_slot` at `+0x1d03`, then the page-sweep read at `+0x1d5f`
precedes the sweep report at `+0x1df5`. This corroborates the selected source
path and intended postreturn ordering in this build; it does not prove
any instruction after `ICEBP` executed on the console. A different
disassembly for the recorded SHA-256 would falsify this binary reading.

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
   [verified-in-tree] `tools/kh2_gadget_contract.py:16-37,51-67,70-115`
   checks four proposed
   entry instruction sequences at explicitly supplied offsets in a raw text
   image. It uses bounded `objdump` disassembly, records the image SHA-256 and
   the first mismatching instruction, and exits nonzero on a mismatch. For a
   matching FW 12.02 image outside this notes repo, run:

   ```sh
   python3 tools/kh2_gadget_contract.py \
     --text /path/outside/repo/kernel-text.bin --firmware 12.02 \
     --pivot-offset 0x2ac2de --dbreg-offset 0x2acb78 \
     --iret-offset 0x2b362d --ret-tramp-offset 0x2b0b26
   ```

   [verified-on-dump] The held 13.60 donor text (SHA-256
   `20da45a0910c990153fbfb7c94e16356867e0bd84f7c9fbf754a45a5dd129673`)
   passes the same checker at pivot `+0x25213e`, debug-register tail
   `+0x2529d8`, `iretq` `+0x257b3d`, and plain `ret` `+0x255036`. The
   latter is Kstuff's `nop_ret` table address
   (`r0gdb/prosper0gdb/offsets/13_60.h:17-18`) but starts
   at the `ret` instruction in the donor. This calibrates
   the checker against the donor, not against 12.02. [inference] A mismatch in
   12.02 would falsify transfer of that **listed instruction shape** at
   the projected offset, though a semantically different implementation
   might still support a redesigned chain. A match would establish only
   local instruction shape: the remaining gadgets, stack/frame context,
   executable runtime mapping, and any actual #DB delivery still require
   separate evidence. The `--firmware` value is a label, not authentication;
   retain independent image provenance alongside the reported digest.
2. Identify a 12.02 test-hook instruction boundary and resume contract, then
   separately the resume-window `startup_mp` call and AP init vector. A
   `sysent` function pointer alone does not identify the getuid body or an
   interior instruction; the 13.60 donor's pointer first reaches a jump
   entry (`16` §“getuid table entry versus hook body”; `11` #30).
3. Freeze a disjoint frame/journal layout and check it offline for all staged
   regions, 16 CPUs if per-CPU landings are used with the shared gate, and
   both #DB transactions. PR #97 demonstrated write/readback/restoration
   across `0x5000` bytes, but its 16 per-CPU slots occupy that entire span.
   A separate `0x4000` reference image cannot be overlaid at the same base;
   a jointly packed layout needs explicit interval and ownership proofs.
   [verified-in-tree] `tools/kh2_layout_check.py:44-155` checks a candidate JSON
   plan's 16 explicitly placed CPU landings, three physical B1 spans, optional reference
   reservations, gate and IST words, arm/dispatch IST targets, two frame slots,
   four context words, and five journal words. Its interval checks reject the
   existing shared-base collision (`tests/test_kh2_layout_check.py:28-45`).
   Run the deliberately synthetic
   passing fixture with
   `python3 tools/kh2_layout_check.py examples/kh2_layout_synthetic.json`.
   The JSON defines spans by absolute base and byte size; the checker treats
   them as half-open intervals and accepts integer or `0x` string values.
   It ties the vector-1 gate and all 16 IST6 field addresses to one supplied
   `kdata_base` using the 12.02 IDT/TSS offsets and `0x68` TSS stride
   (`docs/16-byepervisor-12-02-port.md:394-396`). The packed IST6 field address is at TSS `+0x4c`, which
   may be unaligned; the **stored stack top** is required to be aligned
   (`11` #37). The fixture uses `kdata_base=0` solely for synthetic geometry.
   Every CPU landing must lie inside the staged/read-back B1 image. The
   selected landing contains **both** frame slots and all four context
   words; the big and journal spans must be disjoint from every landing.
   This corrects the earlier plan that placed 15 IST targets in unobserved
   bytes (`11` #35, #39). A reference reservation may contain the selected
   landing and its B1 writes, but it must not overlap another CPU landing.
   Each planned IST top must
   leave a `0x28`-byte hardware frame inside that CPU's landing. The selected
   tops equal F1/F2 `+0x28`; other CPU tops stay fixed between arm and
   dispatch in this plan; A2 now rereads all 16 to catch drift (`11` #36–#38).
   The checker outputs SHA-256 for the 16 arm and dispatch targets as
   little-endian qwords for comparison with B2/A2 `ist_image_sha`, plus the
   selected A2 expected top.
   [verified-in-tree] `tools/kh2_layout_check.py` now accepts a retained
   KH2 `ps5log/1` file and optional same-run manifest:

   ```sh
   python3 tools/kh2_layout_check.py candidate.json \
     --log retained-run.log --manifest retained-run.json
   ```

   [inference] Adding `--b2-pivot-ktext-base` with a same-run 12.02 text
   base also brings the conditional descriptor comparison into this plan/log
   join. A different accepted B2 gate makes `comparison_status=mismatch` and
   exits nonzero; absent B2 remains a coverage gap. The supplied base and
   candidate pivot bytes are not authenticated by that comparison. A
   same-attempt gate readback with the encoded candidate words would falsify
   a reported descriptor mismatch, but would not validate the gadget bytes.

   It joins only classifier-accepted B0, three B1 parts, B2, and A2 to the
   candidate. It compares selected CPU and frame slots; B1 span bases/sizes,
   context and journal addresses; B2/A2 full IST image hashes, selected
   pointers, count, and A2 armed-word address. A log comparison additionally
   requires `build_sha` at the plan root and `image_sha` in each B1 span;
   it compares those with B0's reported build tag and each B1 staged-byte
   hash. The synthetic fixture uses placeholder hashes, so its success is
   a parser example, not evidence about a real build. For a real candidate,
   calculate the B1 hashes from the exact off-repo staged bytes and tie the
   build tag to a recorded build procedure. These fields detect an accidental
   plan/build mix-up even when each reported B1 write/readback pair agrees.
   A mismatched manifest hash,
   ambiguous sequence, rejected classifier record, or capture error causes a
   nonzero exit. `partial_observed_fields_match` lists missing records as
   coverage gaps, not failed execution. `no_comparable_records` also exits
   nonzero. The PR #97 `[K1]` console marker is from a different log format
   and cannot be joined as a KH2 B0/B1/B2/A2 report. The join checks what a
   retained producer *reported*, not independent memory ownership or code
   execution; an unobserved stage remains unlocated. It does not compare the
   gate/IST **field addresses**, because those are absent from KH2 records,
   or independently authenticate the source build behind a reported
   `build_sha`; the plan and producer can both make the same false claim.
   A passing result still reports
   `ownership_verified: false`: it establishes disjoint geometry and agreement
   with the accepted reported fields only. [inference]
   A real 12.02 candidate must still obtain independently supported scratch,
   gate, and IST ownership plus readback; a later allocation or native-state
   observation contradicting that ownership would falsify the candidate even
   if this checker passes.

   [verified-on-dump] A read-only zero-run scan of the held FW 12.02
   `kernel-data-only-1202/kernel-data.bin` (SHA-256
   `222bed173183ac5981557840816ca2efa4c7d8b95fde780a475533b18928cdee`)
   found the contiguous zero interval `[kdata+0x208e5f8,
   kdata+0x209eb18)`, length `0x10520`. The adjacent bytes on both ends
   were nonzero. `examples/kh2_layout_1202_zero_span_candidate.json`
   places a single `0x5000` B1 image at `kdata+0x2094500` covering all
   16 `0x500` landings, with the selected landing last at the previously
   tested `+0x2099000`; a `0x200` state/journal span at `+0x2099600`
   covers the reference's `+0x600` state and `+0x620` saved gate/IST
   positions, and a `0x600` big-chain span begins at `+0x209ca00`.
   All three writes and the `0x4000` reference reservation end before
   `+0x209eb18`; the checker reports valid interval geometry. The JSON
   uses `kdata_base=0` to express offsets; it is **not** a runtime address
   plan and has no real build or staged-image hashes. Log comparison
   therefore refuses it until exact off-repo bytes and a build identity
   exist.

   [inference] This is a placement candidate only. The dump was captured
   with Kstuff active and zero bytes cannot establish live ownership or
   safe scratch. The 15 nonselected landing chains have not been built or
   checked for a valid 12.02 pivot and return. A live read showing occupied
   bytes, an allocation owner, a different selected CPU, or a byte-verified
   chain that exceeds these spans would falsify this placement. No console
   write or trigger is authorized by this zero-run calculation.
4. Finalize a **pre-armed observer** against the chosen layout, including both
   frame slots, all journal words, gate/IST state, and the saved baseline.
   The offline-built audit scaffold above covers the reference slot positions
   only; it has not been run or paired with an executing chain, and loading
   it after a stalled trigger is not an acceptable observation path. Pair the final
   version with user-mode `ps5log/1` records, explicit worker-ready/quiesced
   handoffs for both traps, and validate classification on synthetic data
   before any live run.
5. Only after those gates, specify one exact FW 12.02 build, the expected
   marker sequence and falsifiers, the risk of a stranded gate/IST or panic,
   hard power-cycle recovery, and read-only baseline verification. Obtain
   explicit owner approval for that **specific** console-risky experiment
   under `AGENTS.md`. No run is authorized by this offline map.

The current result is a **complete inventory of required semantics and
evidence points**, with unresolved entries visible. It is not a completed
12.02 gadget port or a prediction that the next live attempt returns.
