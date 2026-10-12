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

## Detail on the load-bearing ones

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
