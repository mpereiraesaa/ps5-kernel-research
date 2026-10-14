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
| 19 | The 12.02 dump's shared v1/v9/v13/v179 `add_rsp_iret` target proves Sony's native dismiss-stub layout | **WRONG BASELINE** — the owner confirms kstuff was running during the dump. A later live read-only audit with no kstuff running reported four distinct targets and IST0 for v9/v13/v179. Neither snapshot alone proves pristine firmware state. | [verified-on-console] `16` gate-state audit; [verified-in-tree] `r0gdb/prosper0gdb/offsets/12_02.h:12-14` |
| 20 | The #DB chain can run on #GP with an otherwise identical entry frame | **WRONG FRAME ASSUMPTION** — #GP supplies an error code; #DB does not. No 12.02 #GP chain or return has been validated. | [public-consensus] [AMD64 APM Vol. 2 §§8.2.2, 8.2.14](https://docs.amd.com/v/u/en-US/24593_3.44_APM_Vol2); [verified-in-tree] `docs/16-byepervisor-12-02-port.md:117-120` |
| 21 | Successful all-CPU IST4/gate setup and Kstuff offsets imply the minimal `INT1` → `justreturn` probe will return | **FALSIFIED AS A RUN PREDICTION** — the setup-only build restored cleanly, but the live one-shot closed without a return marker and left gate/IST4 patched. The failing instruction and cause remain unknown. | [verified-on-console] `16` live one-shot run |
| 22 | An immediate CPL0→CPL3 `iretq` frame is an adequate first khook probe because the architecture permits it | **UNSUPPORTED EXPERIMENT DESIGN** — the reviewed working implementations use staged kernel continuation before returning to user mode; our direct frame had no such precedent, and the console power-off did not identify the failing step. Architectural legality did not establish this 12.02 path. | [verified-on-console] `16` pretrigger handshake; [public-consensus] Kstuff `kelf.asm`, Byepervisor `khook.c` |
| 23 | Kstuff's 12.02 `cpu_switch` entry is a verified replacement for Byepervisor's `DBREG_RESUME`, and the 13.60 gadget starts by loading DR0 from `[rdi+0x78]` | **WRONG ENTRY CONTRACT** — `cpu_switch` is only a same-region anchor. In the 13.60 donor, `DBREG_RESUME` starts at `mov dr0,rax`; the preceding RAX load is skipped, because the arm chain supplies DR0 in RAX. The proposed 12.02 address remains a byte-unverified candidate. | [verified-on-dump] 13.60 `kernel-text.bin+0x2529d4..0x252a32`; [public-consensus] Byepervisor `khook.c`; [inference] `16` cross-dump candidate |
| 24 | A read-only audit ELF is a safe way to collect a frame after a live #DB probe stops returning, if the console still answers ping | **UNSUPPORTED RECOVERY ASSUMPTION** — after the Kstuff-style probe emitted `[K1]` without a return marker, ping and elfldr initially worked; the follow-up audit ELF timed out, and the console then stopped answering. This does not prove the audit caused the outage, but read-only intent did not make loading new code safe while shared gate/IST4 state was unknown. | [verified-on-console] `16` full-continuation run; [inference] possible persistent changed gate |
| 25 | The tested 12.02 scratch span is only `0x2000`, so it is too small for the `0x4000` 11.60 image | **OUTDATED CAPACITY CLAIM** — PR #97's setup-only run staged, read back, and restored `16 × 0x500 = 0x5000` bytes. The byte count can fit the reference image in isolation, but the current 16 CPU slots consume the same span; overlaying both at one base collides. Runtime ownership remains unproved. | [verified-on-console] `16` §“Full Kstuff-style continuation probe”; [verified-in-tree] `engineering/payloads/byepervisor_probe_1202/fullchain_allcpu.c:15-19,278-325`; [public-consensus] `5299395/include/khook.h:30-37` |
| 26 | Bitwise OR of the frame-canary base with `cpu<<8` makes all 16 CPU canary values distinct | **FALSE** — the base already has bits set in that byte. The PR #97 source produces 20 unique values across 80 CPU/word combinations, although per-CPU slot addresses remain disjoint. The isolated prearmed variant uses addition and produces 80 distinct values. | [verified-in-tree] `engineering/payloads/byepervisor_probe_1202/fullchain_allcpu.c:287-290`, `fullchain_prearmed.c:123-124,507-508`; `tools/fullchain_layout_check.py` |
| 27 | The KH2 observer's PC report order proves the order of kernel frame and journal writes | **WRONG CAUSAL READING** — independent sampling and sending can lag the writes or scan addresses in a different order. A reversed pair of `F*`/`A1*`/`D1*` reports is an arrival-order difference, not an execution-order reversal. Only ordered user/observer handoff control reports support the narrower causal check. | [verified-in-tree] `tools/khook_trace_classify.py:548-555`; [inference] `engineering/payloads/byepervisor_probe_1202/fullchain_prearmed.c:113-262`; asynchronous sampling can reorder reports |
| 28 | The 11.60 khook's arm, dispatch, handler, and frame are five disjoint physical B1 writes, and gate readback alone is its final preparation step | **WRONG STAGING MODEL** — the first `0x500` image contains arm/dispatch/frame material; the big chain is a separate write. After installation, `kh_trigger` still patches saved RBP and arm RIP/RSP before TF. A closer port needs a final context readback to bound this preparation gap. | [public-consensus] `5299395/khook.c:390-478`; [verified-in-tree] `docs/17-byepervisor-1202-chain-map-and-observability.md` KH2 contract |
| 29 | A KH2 frame or journal report proves a change merely because its own `before` and `after` values differ | **UNLINKED BASELINE** — a later report can supply any canary or `before` word. B2 must read the frame canaries before triggering, and B1 must read the journal preseed; later reports must match those earlier samples before claiming a change. | [verified-in-tree] `tools/khook_trace_classify.py` `_raw_fields` and `classify`, `tests/test_khook_trace_classify.py`; [inference] same-attempt baseline linkage is required for a change claim |
| 30 | The 12.02 `sysent[24].sy_call` pointer identifies the `getuid` body, so its `+0xe` instruction is a usable test hook | **ENTRY/BODY CONFLATION** — 13.60 `sy_call` names a jump entry at `ktext+0x265330`, while its getuid body is `ktext+0x2a8d60`. 12.02 data locates only its entry at `ktext+0x3130a0`; no 12.02 text is held to resolve the body or instruction boundary. The old `746` sysent count was also wrong; the 13.60 declared count is 735. | [verified-on-dump] `kernel-dump-1360-boot1791893784/kernel-data.bin+0x1b6e50`, `kernel-text.bin+0x265330`, `kernel-data-only-1202/kernel-data.bin+0x1af4d0`; [verified-in-tree] `tools/sysent_trampoline_map.py:15-77`, `docs/16-byepervisor-12-02-port.md` §“getuid table entry versus hook body” |
| 31 | A matching IST image/readback hash and `ist_matched` count prove the selected #DB stack points to the intended arm or dispatch frame | **UNLINKED STACK POINTER** — those checks can match an unchanged native pointer or the wrong staged address. KH2 B2 now requires the selected IST6 qword to equal `f1_slot+0x28` before TF; A2 requires `f2_slot+0x28` after the arm return, both different from B0's native pointer. | [verified-in-tree] `tools/khook_trace_classify.py:150-159,246-252`, `tests/test_khook_trace_classify.py:642-660`; [public-consensus] [`5299395/khook.c:341-345,371-376,443-454`](https://github.com/gzimbric/Byepervisor-Reborn/blob/5299395b15ec91f7484ded2e7631977e0df94a4d/khook.c#L341-L454); [inference] selected-pointer equality is required for the proposed frame placement |
| 32 | The one-trap prearmed worker can sample continuously through both KH2 transactions while the main thread performs A2 and the test setup | **SHARED-PRIMITIVE RACE** — each observer read reconfigures its pipe with the inherited SDK kernel-write primitive, and `ps5log` is not thread-safe. The public test writes kernel data after the arm return and before `getuid`. A two-trap port needs explicit idle/sample/quiesce handoffs around both traps. Proposed R0/R1/Q1/R2/Q2 values and order are checked, and a host-only pthread schedule exercises the handoffs; no integrated 12.02 producer emits them. | [verified-in-tree] `tools/khook_trace_classify.py:105-123,141-180,217-256,548-555`, `tests/test_khook_trace_classify.py:520-553`; [inference] `engineering/payloads/byepervisor_probe_1202/observer_channel.c:65-75`, `fullchain_prearmed.c:175-241,602-625`, `kh2_worker.c:40-125,201-236`; `engineering/homebrew_ps5/projects/logging_server/client/ps5log.h:31`; [public-consensus] [`5299395/main.c:71-80`](https://github.com/gzimbric/Byepervisor-Reborn/blob/5299395b15ec91f7484ded2e7631977e0df94a4d/main.c#L71-L80), [`main.c:462-482`](https://github.com/gzimbric/Byepervisor-Reborn/blob/5299395b15ec91f7484ded2e7631977e0df94a4d/main.c#L462-L482) |
| 33 | D2's B0 scratch hash and `scratch_restored=1` prove the separately staged B1 image, big chain, and journal were restored | **UNCOVERED SPANS** — B1 permits three disjoint physical spans that need not lie inside the B0 scratch hash range. B1 now records each span's prewrite `before_sha`, and D2 requires a matching final hash for each span. A matching scratch hash alone cannot cover bytes outside that range. | [verified-in-tree] `tools/khook_trace_classify.py:90-99,296-314,531-546`, `tests/test_khook_trace_classify.py:478-489`, `docs/17-byepervisor-1202-chain-map-and-observability.md` KH2 contract; [inference] disjoint B1 placement in `17` leaves independent restore obligations |
| 34 | Restoring all three B1 spans necessarily restores the later `resumectx` and armed-state writes | **UNBOUND WRITE ADDRESSES** — a matching span hash covers only that span's bytes. B1 `image` now reports four distinct context qword addresses within the image, and A2 reports an armed-state address within the B1 journal, away from marker words. The host producer blocks out-of-span values. A future layout with either write elsewhere needs its own baseline and final readback. | [verified-in-tree] `tools/khook_trace_classify.py:100-115,217-231`, `tests/test_khook_trace_classify.py:500-518`; [inference] the reported write addresses must belong to a restored span for that restoration claim |
| 35 | All 16 CPU landing slots must be disjoint from the B1 image | **WRONG FOR THE SELECTED CPU** — its two #DB hardware-frame slots are B1 image fields, so the selected landing must contain them inside that image. The earlier checker kept the other 15 outside it; #39 supersedes that arrangement because their staged bytes had no B1 readback. A 16-slot contiguous PR #97 placement at the image base still conflicts with the reference reservation and big-chain write on other CPUs. | [verified-in-tree] `tools/kh2_layout_check.py`, `tests/test_kh2_layout_check.py`; [inference] `docs/17-byepervisor-1202-chain-map-and-observability.md` frame/IST6 contract. A separately read-back landing bank would also satisfy the byte-coverage need without putting all 16 inside B1 image. |
| 36 | Disjoint CPU landing spans alone prove the shared gate routes each CPU's #DB frame into its own staged slot | **UNBOUND IST TARGETS** — a nonoverlapping landing can be bypassed by a wrong IST6 pointer. The layout checker requires each phase's 16 pointer tops to leave a `0x28`-byte frame inside the corresponding landing, links the selected tops to F1/F2, and exports both phase image hashes. The current plan holds other CPU targets fixed between phases; A2 now rereads all 16 to detect drift before the second trigger. | [verified-in-tree] `tools/kh2_layout_check.py:83-99,150-160`, `tests/test_kh2_layout_check.py:273-284`, `tools/khook_trace_classify.py:217-252`; [inference] actual pointer values and frame contents still need same-attempt readback. A validated 12.02 design that changes the other CPU targets and logs a complete dispatch image would falsify the fixed-target assumption. |
| 37 | An IST6 qword address must be 8-byte aligned | **WRONG FOR PACKED TSS** — the documented 12.02 TSS base plus IST6 `+0x4c` is four bytes off an 8-byte boundary. The pointed-to stack top is a separate value and is checked for alignment. The layout checker derives every IST6 field address from the 12.02 TSS base/stride, and the off-tree main and observer capture initializers no longer reject packed addresses. Their byte-addressed host mocks now exercise that case. | [verified-in-tree] `docs/16-byepervisor-12-02-port.md:394-396`, `tools/kh2_layout_check.py:68-82,114-118`, `tests/test_kh2_layout_check.py:286-294`; [inference] `engineering/payloads/byepervisor_probe_1202/kh2_main_capture.c:211-217`, `kh2_capture.c:80-93`. A future verified 12.02 TSS layout with a different IST6 field offset would falsify this specific address calculation. |
| 38 | A2's selected IST6 readback proves the other 15 CPUs still route safely after the first return | **UNCOVERED SECOND-PHASE IMAGE** — the old A2 record named only the selected pointer; another CPU's IST6 could differ with no reported address. The revised native producer reads all 16 at A2, records the planned and observed hashes, and reports the first mismatching CPU and raw pointer. The classifier links the prior arm-image hash to B2 and rejects any mismatch. | [verified-in-tree] `tools/khook_trace_classify.py:217-252`, `tests/test_khook_trace_classify.py:669-685`; [inference] `engineering/payloads/byepervisor_probe_1202/kh2_main_capture.c:634-660` is still an off-tree, host-tested producer. A same-attempt direct read contradicting its A2 report would falsify the claimed all-CPU state. |
| 39 | All 16 IST6 targets point into disjoint landing spans, so B2's IST image hash proves every CPU's entry stack was staged | **UNREAD LANDING BYTES** — the earlier passing synthetic plan put 15 landings outside every B1 span. Their IST pointers could all match while their stack bytes remained zero or stale. The checker now requires every landing, including the selected one, inside the B1 image readback span and keeps the big and journal writes disjoint. This binds initial landing bytes to B1's reported hash, but their chain semantics and persistence at exception time remain unverified. | [verified-in-tree] `tools/kh2_layout_check.py`, `tests/test_kh2_layout_check.py`, `examples/kh2_layout_synthetic.json`; [inference] a later same-attempt read showing different landing bytes would falsify the staging report. A separate logged landing-bank span with equivalent readback would replace the all-in-one-image layout rule. |
| 40 | B2 can patch the shared #DB gate before writing the four `resumectx` qwords because it reads them back before the planned trigger | **WRONG PATCH ORDER** — the earlier off-tree scaffold wrote all IST6 slots, then the gate, then RBP/RIP/RSP/DR7. An incidental #DB after the gate patch could enter while that context was incomplete. The revised producer enforces context → all 16 IST6 → gate, and the host check rejects an early gate and a context-write failure without reaching the gate. The native handler can still see staged IST6 values before the gate patch, and B2's later readback still leaves a changed-gate window. | [inference] `engineering/payloads/byepervisor_probe_1202/kh2_main_capture.c:451-486`, `kh2_main_host.c:228-267`, `kh2_main_host_test.py` B2 order/failure checks; a verified first-trap path that never reads these context words before their writes would falsify the specific incomplete-context hazard. |
| 41 | One bracketed 16-byte gate write can localize which gate qword failed and matches the public 11.60 installation sequence | **WRONG WRITE GRANULARITY** — the prior off-tree B2/D2 producer sent one 16-byte callback for the gate. The public installer/restorer writes high then low as two qwords. The revised producer brackets each 8-byte callback separately, requires high before low, and host-injected failures identify `gate+8` versus `gate+0`. A retained `done` means the callback returned success; only B2/D2 readback checks the final bytes. The intermediate gate state remains a live hazard. | [public-consensus] [`5299395/khook.c:443-454`](https://github.com/gzimbric/Byepervisor-Reborn/blob/5299395b15ec91f7484ded2e7631977e0df94a4d/khook.c#L443-L454), [`khook.c:529-534`](https://github.com/gzimbric/Byepervisor-Reborn/blob/5299395b15ec91f7484ded2e7631977e0df94a4d/khook.c#L529-L534); [inference] `engineering/payloads/byepervisor_probe_1202/kh2_main_capture.c:459-490,711-780`, `kh2_main_host_test.py` gate-word failure checks. A same-attempt log in which the reported high `done` lacked a completed high callback would falsify the producer-order interpretation. |
| 42 | B2 gate words that match the producer's own `expected_lo/hi` prove it selected the intended 12.02 pivot | **SELF-CONSISTENT WRONG TARGET** — B2 can accept a different but internally matching gate. The optional classifier comparison instead encodes the candidate pivot from a separately supplied same-run text base and checks the full descriptor, retaining a mismatched B2 record as evidence. Equality still cannot validate unknown 12.02 pivot instruction bytes. | [verified-in-tree] `tools/khook_trace_classify.py:325-333,651-673`, `tests/test_khook_trace_classify.py:131-169`; [inference] a 12.02 text image without a compatible `add rsp,0x28; ret`-class pivot at the candidate address would falsify its execution contract. |
| 43 | An accepted D2 record always verifies that the reported all-CPU IST restoration count matches B2 | **FALSE WHEN B2 WAS MISSING** — the earlier classifier accepted B0/B1/D2 with any positive `ist_restored`, because it compared the count only when B2 had been accepted. D2 now requires an accepted B2 count and exact equality; a retained D2 line without B2 remains in the raw log and is reported as rejected, not promoted to verified restoration. | [verified-in-tree] `tools/khook_trace_classify.py:301-323`, `tests/test_khook_trace_classify.py:618-632` |
| 44 | Direct SDK `kernel_copyout` of 12.02 kernel text is a suitable way to acquire the missing gadget bytes | **FALSIFIED AS AN INSTRUMENT CHOICE** — `qa_probe` attempted a pipe read at `ktext` and the console panicked before the QA change. The guarded alias replacement made the denied baseline read recoverable, but did not yield text bytes. A future byte capture needs a separately validated read path or changed text mapping; shrinking the requested window is not evidence that the raw pipe read becomes safe. | [verified-on-console] `docs/07-evidence.md:693-716,730-741`; [inference] a different NPT state or non-pipe reader could change the result, so this does not claim text is universally unreadable |
| 45 | The GPUVM v3 abstract “safe sequence” gate cleared the built ELF for a 12.02 text read | **WRONG COVERAGE** — the gate models selected reads and skips writes; the ELF returns physical PTE addresses as kernel VAs, lacks verified GPU VAs for command/destination buffers, and reports PTE restoration without checking it. The ELF is unrun, so no console outcome is inferred. | [verified-in-tree] `engineering/ps5-sim-lab/hvemu/gate.py:151-173,188-196`; `engineering/payloads/gpuvm_read/main.c:215,235,265,369-382,419-422,430-470,497,523-524,561-575,577-587`; [inference] revised source plus same-attempt translated-address and restore readbacks would falsify the readiness gap (`07` §“gate upgrade”) |
| 46 | The PR #97 Kstuff fullchain sources used the 12.02 `rep_movsb_pop_rbp_ret` table address | **WRONG COORDINATE** — both sources hardcoded `ktext+0x2efbba`; the public Kstuff `kdata−0xa60246` entry converts with the held 12.02 `0xd50000` gap to `ktext+0x2efdba`, `0x200` later. The historical PR #97 ELF/source are retained; the unrun prearmed variant is corrected and rebuilt. `[K1]` precedes the gate/trigger, so this does **not** diagnose the shutdown. | [verified-in-tree] `r0gdb/prosper0gdb/offsets/12_02.h:15`, `engineering/payloads/byepervisor_probe_1202/fullchain_allcpu.c:43,327-329`, `engineering/payloads/byepervisor_probe_1202/historical/fullchain_prearmed_v2.c:46`, `tools/fullchain_layout_check.py` offset audit; [inference] 12.02 instruction bytes or a same-attempt post-trigger frame/marker would be needed to establish whether the wrong target was reached (`16` §“Alternative full continuation”) |
| 47 | Matching cross-firmware static pointer rows justify carrying a nearby donor gadget's interior displacement to 12.02 | **FALSE CONTAINING-FUNCTION PREMISE** — two 13.60 rows pair with two 12.02 rows, but the donor `ST_RCX_RDX` entry at `+0x82b915` lies `0x5e5` after the first referenced function at `+0x82b330`; that function returns at `+0x82b34b`/`+0x82b34f`, and its adjacent pointer's function also returns before the gadget. The derived `+0x8bbc05` is rejected as a 12.02 gadget candidate. | [verified-on-dump] `16` §“Data-pointer cross-check”, donor `kernel-text.bin+0x82b330..0x82b370`; [verified-in-tree] `tools/kh2_static_table_audit.py:17-120`; [inference] a future 12.02 byte match could independently validate the address but would not make this cross-function transfer valid. |
| 48 | Kstuff's named `gpr2dr_1_start` and `gpr2dr_2_start` can be used as one uninterrupted replacement for Byepervisor's `DBREG_RESUME` | **WRONG CONTINUATION CONTRACT IN THE 13.60 DONOR** — these are entries inside `cpu_switch`, not a standalone chain. The first entry falls through to context MSR writes; the second writes DR6/DR7 and jumps back into `cpu_switch`, with no local `ret`. Kstuff's caller instead advances the first entry in nine single-step calls, then sets RIP to the second for three more, skipping the intervening MSR block. The named 12.02 entries identify addresses, not a validated direct-chain contract. | [verified-on-dump] 13.60 `kernel-text.bin+0x252466..0x252561`; [public-consensus] Kstuff [`r0gdb.c:536-556`](https://github.com/EchoStretch/kstuff-lite/blob/48cd2c4ce62aa9ca0c2cc014c1e512f276ae7c17/prosper0gdb/r0gdb.c#L536-L556), [`r0run.asm:15-91`](https://github.com/EchoStretch/kstuff-lite/blob/48cd2c4ce62aa9ca0c2cc014c1e512f276ae7c17/prosper0gdb/r0run.asm#L15-L91); [inference] 12.02 bytes or a reviewed 12.02 full `cpu_switch` context would be needed to validate a different continuation. |
| 49 | Any `MARK FC1 READY` line with matching CPU strings is enough to link later gate/trigger reports | **FALSE PARSER TRUST GATE** — the classifier previously accepted a READY with wrong FW, unknown build, same or out-of-range observer CPU, or sequence zero; synthetic later records could then advance the boundary. It now requires FW 12.02, a known v1–v5 build, local sequence 1, and two distinct CPUs in 0–15 before linking later reports. Raw malformed lines remain available for inspection. | [verified-in-tree] `tools/khook_trace_classify.py:722-759`, `tests/test_khook_trace_classify.py:466-492,623-638` |
| 50 | KH2 plan/log equality of B0/B2/A2 values also checks where their read/write callbacks went | **UNCHECKED ADDRESS BRACKETS** — the layout join displayed `KH2R`/`KH2W` addresses but did not fail when an observed bracket fell outside the candidate plan. Its A2 mapper also applied the selected-CPU write rule to reads, although A2 rereads all 16 IST6 fields. The join now rejects every retained out-of-plan bracket, mapping A2 reads across all 16 and A2 writes to the selected CPU only. Missing brackets still leave address coverage unproved. | [verified-in-tree] `tools/kh2_layout_check.py:176-210,303-328`, `tests/test_kh2_layout_check.py:198-245`; [inference] a same-run independent read contradicting the logged callback address would falsify producer truthfulness (`17` §“Offline exit gates”). |
| 51 | `observed_fields_match` means the accepted KH2 stages have a complete address trace | **MISSING BRACKET COVERAGE** — the join could report that status for B0/B1/B2/A2 records with zero `KH2R`/`KH2W` brackets. It now counts the off-tree producer's expected callbacks for each accepted control phase, reports missing read/write brackets and undeclared scratch geometry, and returns `partial_address_evidence` with a nonzero CLI exit until coverage is complete. | [verified-in-tree] `tools/kh2_layout_check.py:246-332,390-412,488-496,549-553`, `tests/test_kh2_layout_check.py:75-91,229-245,280-289`; [inference] the contract assumes the current off-tree producer's schedule; a revised producer emitting a different accepted-stage schedule would falsify it and require an update (`17` §“Offline exit gates”). |
| 52 | The full KH2 classifier can validate the standalone native R0 calibration ELF's log | **WRONG RECORD CONTRACT** — the full classifier requires B0 and B1 before it accepts R0, but the R0-only ELF emits neither. A separate checker joins the main native baseline, four gate/IST6 read brackets, R0 build/CPU fields, same-run PC manifest, and final post-affinity stdout marker. Missing brackets or a different build cannot pass as a complete calibration. This does not establish a #DB entry. | [verified-in-tree] `tools/khook_trace_classify.py:132-145`, `tools/kh2_r0_calibration_check.py:47-178`, `tests/test_kh2_r0_calibration_check.py:45-122`; [inference] a future calibration ELF that emits B0/B1 or changes its marker order would require a revised checker, falsifying this exact log contract. |
| 53 | A completed KH2 bracket inside a plan region is harmless even when the producer's accepted stage did not call for it | **UNCOUNTED EXTRA CALLBACK** — the prior join checked that each observed bracket lay inside a plan region and that expected brackets were present, but ignored extra completed brackets. An orphan R0 read, repeated B2 read, or repeated B2 gate write could therefore leave the address-coverage flag true. The join now reports `extra_reads`/`extra_writes` as a multiset difference and withholds `observed_fields_match` until both are empty. | [verified-in-tree] `tools/kh2_layout_check.py:393-420,494-501,556-560`, `tests/test_kh2_layout_check.py:257-279`; [inference] a future producer with intentional retries would need a versioned callback schedule, falsifying the current exact-count assumption (`17` §“Offline exit gates”). |
| 54 | A valid standalone R0 record and matching gate/IST6 bracket addresses establish that the worker saw the main thread's native values | **UNLOGGED MAIN BASELINE** — the old ELF kept the main gate/IST6 snapshot only in memory. A later R0 line could report different values while the PC-only checker lacked the main values to compare. The rebuilt ELF emits `KH2C MAIN_BASELINE` before starting the worker; the checker requires that record and exact equality of its three raw words with R0. An error or absence stops a complete calibration verdict. | [verified-in-tree] `tools/kh2_r0_calibration_check.py:17-18,73-84,127-152`, `tests/test_kh2_r0_calibration_check.py:45-82`; [inference] a same-attempt independent read disagreeing with either reported baseline would falsify producer truthfulness (`17` §“Native R0 calibration”). |

## Detail on the load-bearing ones

### #32 — Two traps need two observer handoffs [inference]

The existing prearmed one-trap worker waits while main patches IST/gate,
then samples until that single trap returns; main stops it before SDK
restoration. In the two-trap reference, `kh_trigger` first performs final
kernel context writes, and after its arm return the test path still writes
saved gate/IST and state, clears the oracle, and later reads it around
`getuid`. Continuous observer reads across those main-thread operations
would share the inherited SDK write primitive. Concurrent `ps5log` calls
would also violate its client contract. A source-level proof of genuinely
independent kernel read/write primitives and a synchronized thread-safe log
client would falsify the shared-resource premise for a redesigned observer;
neither exists in the current local implementation. The proposed handoffs,
their classifier checks, and the host-only pthread schedule in `17` are
offline requirements and fixtures, not evidence of console execution. A
handoff line is still a report by its sender; without an integrated SDK and
logger adapter it cannot prove those shared resources were serialized on a
12.02 console.

### #33 — Restore every staged span [inference]

The proposed KH2 image, big chain, and journal are separate B1 write spans.
The B0 scratch hash may cover none, some, or all of them, depending on a
future layout. Therefore a D2 scratch match does not establish that bytes
outside its range returned to their prewrite state. Capturing `before_sha`
before each B1 write and comparing each D2 readback to it closes that
specific logging gap. A proved layout in which all three B1 spans lie wholly
inside the B0 scratch hash range would falsify the need for the three extra
D2 hashes **for that layout**. The hashes still do not prove an unwritten
address was safe or that the chain returned through a valid instruction.

### #34 — Later writes must belong to a restored span [inference]

B1's image and journal hashes compare byte ranges, not every location the
main thread might modify later. In the proposed three-span contract, the
four `resumectx` qwords later read at B2 have to lie within the B1 image,
and A2's armed-state address has to lie within the B1 journal without
aliasing a diagnostic marker. The classifier checks those reported
coordinates, and the off-tree main emitter rejects a different layout.
A finalized 12.02 chain that writes either value elsewhere would falsify
this three-span layout and require another prewrite/final hash pair. A
same-attempt read proving the actual write address differs from the
reported one would falsify the coverage claim. Text records still cannot
authenticate the producer or prove that a hardware trap occurred.

### #31 — Read back the selected stack qword [inference]

The old KH2 B2 and A2 records could claim that an IST array write matched its
own image while the selected CPU still pointed elsewhere. That would move a
failure caused by bad preparation into the apparent #DB delivery window.
The revised contract links both selected IST6 readbacks to B0's frame slots.
A different validated 12.02 frame placement would falsify these particular
`+0x28` equations and require updating the layout version. The check still
does not establish the pivot bytes or prove #DB fired.

### #30 — A syscall table entry need not be the hook body [inference]

The 13.60 donor supplies both data and text, so the offline resolver can
follow its `getuid` table entry to the body. The 12.02 holding supplies only
data: its table entry and neighboring pointer spacing identify a corresponding
`sy_call` slot, but reveal nothing about bytes at that entry. A future 12.02
text image showing a direct jump to a body with a validated `+0xe` hook
instruction would resolve this gap and falsify the narrower claim that the
hook cannot yet be mapped. It would not make the table entry itself equal to
the body. The correction prevents a data-only address from being promoted
to an instruction-verified breakpoint.

### #29 — A change needs an independently recorded before value [inference]

The first KH2 frame check compared a reported hardware-frame tuple to
`can0..4` supplied **in the same F1/F2 line**. The first journal check
similarly compared `before` and `after` in one marker line. A mistaken or
malformed producer could report arbitrary before values and make unchanged
memory appear changed. The proposed contract now records both five-word
frame canaries in B2 immediately before TF, and all four journal addresses
and preseed words in B1. The classifier accepts a later frame or marker
change only when its before values match those earlier same-run records.

A direct same-attempt memory capture contradicting the B1 or B2 baseline at
the named address would falsify a claimed change. This linkage improves the
log's internal evidence; it does not prove the sender read the intended
kernel address or that #DB fired.

### #28 — Physical staging and final trigger preparation [public-consensus]

The first KH2 draft required five nonoverlapping B1 writes named arm,
dispatch, handler, frame, and journal. That made a direct representation of
the 11.60 installer impossible: its arm and dispatch entries plus both frame
slots reside in one `0x500` image, while the big chain is written separately
(`5299395/khook.c:390-441`). A proposed 12.02 diagnostic journal is a third
physical span. B1 now records these three disjoint *writes*, with logical
substructures allowed to share an image.

The first draft also treated gate/IST readback as final pretrigger evidence.
In the reference, `kh_trigger` writes the saved user RBP and the arm
continuation RIP/RSP **after** `kh_install` has installed and read back the
gate, then sets TF and executes a NOP (`khook.c:458-478`). A future 12.02
copy with only pre-context gate readback cannot localize a bad continuation
value versus a delivery failure. B2 now specifies a readback of those final
fields and DR7 before TF. A trace proving that a finalized 12.02 trigger
does not perform any such post-install context write would falsify the
need for this extra readback in that design. This correction adds evidence
requirements; it does not claim that the 12.02 gadget path works.

### #27 — Observer arrival order is not kernel execution order [inference]

The proposed KH2 classifier initially called any stage reversal a
contradiction of the chain order. That overread the evidence. A hardware
frame can be written before an in-chain journal marker, while a separate
worker notices and sends the marker first because it sampled that address
earlier or because its frame report was delayed. The same problem applies
to two persistent journal words sampled in scan order. The prearmed worker's
targeted read and later sweep (`fullchain_prearmed.c:113-262`) establish an
independent sampling path, not a synchronized instruction trace. A future
emitter with a validated monotonic counter written at each kernel milestone
and a proven ordered capture protocol would falsify this limitation for that
emitter; neither exists for 12.02 today.

The host classifier now calls such a difference `out_of_order` and explains
it as **report arrival order**. `causal_order_conflict` is limited to
user-mode control records that the same run emits in sequence. A missing
frame or journal report remains a coverage gap, especially when transport
ends without a clean BYE. This correction is about inference from logs; it
does not establish that any 12.02 kernel transaction executed.

### #26 — Slot address, not the old canary value, names the CPU [verified-in-tree]

PR #97 staged separate addresses for all 16 CPUs, but its OR expression
collapses four CPU tags into each set of five word values. The observer must
therefore attribute a changed frame by its sampled **slot address**, not by
the old value alone. This does not explain the PR #97 shutdown: no frame was
captured. The separate prearmed source uses addition in both staging and
comparison loops; the host-side checker reports 80 distinct values there.
A source edit or a disassembly showing a different canary expression in the
tested ELF would falsify the source-to-binary application of this result.

### #25 — Capacity and layout are separate questions [verified-in-tree]

The earlier `0x2000` result was a historical measurement, not the latest
tested bound. The later setup-only ELF staged and checked sixteen disjoint
`0x500`-byte slots, then restored them (`16`, full-continuation run). Its
`0x5000` total is numerically larger than the 11.60 `0x4000` image, so
“too small” is false as a capacity statement. In the present layout,
however, CPU slots cover the whole `0x5000`; the 11.60 image at the same
base intersects them. The corrected requirement is a disjoint or jointly
proved layout with live baseline and ownership checks. A future layout
showing nonoverlap would falsify the collision claim for that new design;
it would not retroactively make zero bytes evidence of ownership.

### #24 — Post-stall auditing must be pre-armed [inference]

The audit's kernel-memory operations were reads, but sending it still
started another ELF while the first payload might have left the shared
#DB gate and all IST4 slots redirected. The live probe closed without
restoration evidence; the subsequent audit had no output and the PS5
became unreachable. The causal instruction is unknown, so the
correction is to the **safety assumption**, not a finding that the
audit killed the machine. A future frame/marker observer must be
running before the trigger and able to report without loading another
ELF into this uncertain state. A captured gate restoration before the
audit, or a fault trace showing the outage began independently, would
falsify the proposed link between patched state and audit risk.

### #23 — Region correspondence did not establish a gadget [inference]

The old gadget table in `16` marked `DBREG_RESUME` covered by
`cpu_switch`. They are not interchangeable entry points. The 13.60
donor's `+0x2529d8` is three bytes after the load from `[rdi+0x78]`;
the first executed instruction writes the RAX supplied by the arm chain
to DR0. It then reads other debug registers and resumes a context,
including a stack pivot. This correction changes the 12.02 port
requirement: identify the *exact* entry and complete side effects from
12.02 bytes before placing it in a chain. A matching 12.02 disassembly
would support the candidate; a different instruction boundary or
context layout would falsify it. No console run tested this candidate.

### #22 — Architectural legality was mistaken for an adequate probe [inference]

The direct user-return frame was chosen to reduce gadget dependencies.
That was a hypothesis, not a behavior established by the public payloads
we were using. Kstuff's first `iretq` enters kernel `justreturn` and a
longer continuation (`ps5-kstuff/kelf.asm:245-295`). Byepervisor's
`khook.c:358-386` does contain a CPL0→CPL3 `iretq`, but it follows an
arm chain that sets debug state and IST; its dispatch path also saves
registers and builds a resume tail (`khook.c:250-292, 397-449`). Our
first staged `iretq` instead targeted user code immediately. The
handshake attempt powered off without a captured exception frame, so
it does **not** prove that the immediate return itself failed. It proves
that choosing that frame was not justified by the working examples.
A later two-gadget `nop_ret` → `doreti_iret` candidate stages a return
address but still omits the context handling in those examples; it is
deferred (`16`).
A captured trace showing the direct frame completed and a later,
independent fault powered off the console would falsify a claim that
the direct frame caused that run's failure.

### #21 — Setup-only success did not predict a live return [verified-on-console]

The revised setup-only build staged all 16 frames, changed and read back
the IST4 slots and #DB gate, then restored them with explicit markers.
The subsequent live `INT1` build reached its staging marker but closed
without a return or restoration marker. A read-only audit found the
changed gate and all 16 staged IST4 values still present (`16`, live
one-shot run). The earlier setup result establishes only that the data
writes and restoration path can complete without intentional #DB. It
does not establish that #DB was delivered on the patched stack or that
the staged kernel return is valid. [inference] The live failure occurred
at or after patching; a marker or captured frame placing failure before
the `INT1` instruction would narrow this further. Do not treat the
working Kstuff offsets as validation of this smaller frame layout.

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
