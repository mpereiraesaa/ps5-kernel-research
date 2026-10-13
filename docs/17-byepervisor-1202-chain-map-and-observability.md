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

## Coordinate and symbol map

`r0gdb/prosper0gdb/offsets/12_02.h` uses offsets relative to **kdata**;
`5299395`'s `11_60.h` uses **ktext**. [verified-in-tree] The 12.02 conversion
used in `16` is `ktext offset = 0xd50000 + signed kdata offset` (see
`16`, Kstuff return-stub disassembly). It is a coordinate conversion, not a
claim that equivalent code has the same bytes. Resolve both bases per boot.

| Required object | 12.02 evidence | Status for faithful #DB port |
|---|---|---|
| IDT and common TSS | [verified-in-tree] `r0gdb/prosper0gdb/offsets/12_02.h:8,10`: `kdata+0x2e88300`, `kdata+0x2e8afe0`; `16` §“Derived 12.02 data and structure offsets” records TSS stride `0x68` from `r0gdb/prosper0gdb/minchain2-build/main.c:72,395`. | Addressed; selected CPU, native gate type/IST, and saved qwords must still be read live. |
| Scratch | [verified-on-console] `16` setup-only run wrote, read back, and restored **two pages (`0x2000` bytes)** at `kdata+0x2099000`. [public-consensus] `5299395/include/khook.h:30-37` reserves `0x4000` bytes and begins its big chain at `+0x3a00`. | The tested 12.02 region is **too small for a literal 11.60 image**. A new disjoint layout or a separately verified larger cave is required; zero contents do not establish ownership or cross-boot safety. |
| Test hook target | [verified-in-tree] `12_02.h:29` identifies `sysents`; [public-consensus] the 11.60 test uses `getuid + 0xe` (`5299395/main.c:63`). | Function pointer can be located through `sysents`; the **12.02 instruction boundary** and safe resume address are unknown. Do not transfer `+0xe`. |
| Resume-window hook target and AP init vector | [public-consensus] 11.60 identifies both in its `include/offsets/11_60.h`. | No verified 12.02 addresses. Neither the debunked `acpi_sleep_machdep+0x18e` nor a global text delta supplies one (`11` #14, #18). |
| `resumectx` layout | [public-consensus] `5299395/include/khook.h:12-15` uses RBP `+0x20`, RSP `+0x28`, RIP `+0x38`, DR7 `+0xa0`. | Candidate FreeBSD lineage only (`16`, PCB table). Validate the 12.02 consumer before a DR7 arm. |
| Hypervisor AP/VMCB location | [public-consensus] 11.60 discovers a live 16-entry set and validates it before writes. | No 12.02 runtime location or validated population; outside the first khook proof. |

The local 12.02 kdata dump was taken while Kstuff ran; its patched gate and
IST values are **not** a native baseline (`11` #19). A fresh read-only live
baseline is required for any later experiment.

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
| `DBREG_RESUME` tail | `0x2a5778` | **Candidate** `+0x2acb78` from the 13.60 donor's local relation to Kstuff `mov_cr3_rax_mov_ds` (`16`). The 12.02 entry, DR0/DR7 loads, and continuation stack are unverified. The `cpu_switch` function offset alone does not prove this tail. |
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
| F1 first hardware frame | Preseed five distinct canaries at the **selected IST6 hardware-frame slot**; an independent read-only audit captures raw RIP/CS/RFLAGS/RSP/SS while the console is reachable. | Matching replacement by a plausible frame supports first #DB delivery to that stack, even if the pivot fails. Changed bytes alone need raw-frame review. |
| A1 arm continuation | A first in-chain kernel-data marker **after** a verified pivot/store and a second after `DBREG_RESUME` continuation, if those store sequences can be validated without losing live registers. | Narrows entry/pivot versus debug-register restore/continuation; neither marker alone proves DR7 value. |
| A2 arm returned | User-mode `ps5log/1` record after the TF/NOP arm return, with readback of the dispatch IST pointer and journal. | First return completed and dispatch stack was selected. |
| F2 second hardware frame | Distinct canaries in the **dispatch IST6 frame slot**, sampled independently before recovery if a later failure occurs. | Supports kernel hook #DB delivery; not handler completion. |
| D1 dispatch/handler | In-chain marker only **after** the required interrupted registers are saved and a 12.02 liveness review proves the marker's RAX/RCX clobbers harmless; later marker after the test oracle store and before the resume tail. Record raw frame and marker words in the independent audit. | Separates entry/register-save, handler action, and resume-tail failures, subject to verified store gadgets. |
| D2 kernel resumed | User-mode record after the selected test syscall returns, then gate/IST restoration readback and BYE. | Full test-hook transaction completed; it does not prove the later sleep/AP phase. |
| H1 AP phase | Separate `entered`, selected-VMCB count, write count, verify count, and `done` evidence, following the 11.60 read-before-write validation pattern. | Only a full expected set and readback can support a 12.02 AP claim. |

[inference] The first divergence between a preseeded frame, an in-chain
marker, and a post-return marker localizes the **class** of failure, not
necessarily the exact instruction. An independent observer must sample the
frame/journal **before a hard power cycle** when the console remains reachable;
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

## Offline exit gates and console boundary

1. Identify the 12.02 instruction bytes and containing basic blocks for the
   pivot, `DBREG_RESUME`, return, stores, pops, and DR7 disarm; record stack
   deltas and clobbers. The current data-only 12.02 dump cannot prove these.
2. Identify a 12.02 test-hook instruction boundary and resume contract, then
   separately the resume-window `startup_mp` call and AP init vector. A
   `sysent` function pointer alone does not identify an interior instruction.
3. Freeze a disjoint frame/journal layout and check it offline for all staged
   regions, 16 CPUs if per-CPU landings are used with the shared gate, and
   both #DB transactions. The validated two-page 12.02 scratch candidate
   cannot hold the reference `0x4000`-byte image as-is.
4. Build a read-only audit that reports both frame slots, all journal words,
   gate/IST state, and the saved baseline. Pair it with user-mode `ps5log/1`
   records; validate its parsing on synthetic data before any live run.
5. Only after those gates, specify one exact FW 12.02 build, the expected
   marker sequence and falsifiers, the risk of a stranded gate/IST or panic,
   hard power-cycle recovery, and read-only baseline verification. Obtain
   explicit owner approval for that **specific** console-risky experiment
   under `AGENTS.md`. No run is authorized by this offline map.

The current result is a **complete inventory of required semantics and
evidence points**, with unresolved entries visible. It is not a completed
12.02 gadget port or a prediction that the next live attempt returns.
