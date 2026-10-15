# 17 — FW 12.02 kernel-data survey

This is an address and structure survey, not an execution map. Data
offsets below are relative to the **per-boot `kdata` base**; the one
explicit `ktext` comparison is labeled separately. A data address in
this survey is not an executable entry point. Kstuff was
present for the previously discussed 12.02 dump, so the captured IDT
handlers and IST contents cannot be assumed to represent pristine
firmware (see `11` correction #19). A later FW 12.02 live census is
recorded below, separately from those historical captures.

## Capture identity and address convention

[verified-on-console] The 2026-10-08 PTE-gated capture reported FW
`0x12020000`, `kdata=0xffffffffd7030000`, 64 MiB, no holes, SHA-256
`197d0e04d1e9cab0c22358ecbb688fdde9170071ac7c89f2cc63b522fe3a1c41`.
The later alias-sweep capture reported the same FW,
`kdata=0xffffffff89210000`, `dmap=0xffff89a100000000`, 134 MiB with
absent pages zero-filled, SHA-256
`222bed173183ac5981557840816ca2efa4c7d8b95fde780a475533b18928cdee`.
Their manifests are outside Git at
`engineering/payloads/kdata_dump/runs/manifest.json` and
`engineering/payloads/kalias_sweep/runs/manifest.json`; the original
console record is `docs/07-evidence.md` §§2026-10-08 PTE-gated and
alias-sweep runs. [verified-on-dump] For the populated anchors below,
file offset equals `kdata`-relative offset; `docs/12` §4 independently
checks that convention with the sysent table.

## Static data anchors and historical live addresses

| Object | `kdata` offset | PTE-gated boot VA | Alias-sweep boot VA | Basis |
|---|---:|---:|---:|---|
| `allproc` head | `+0x2885e00` | `0xffffffffd98b5e00` | `0xffffffff8ba95e00` | [verified-on-console] SDK FW 12.x value; readable nonzero heap pointer in both captures; first live `copyout` in `07` §first validation. This is a list head, with no array stride. |
| `kernel_pmap_store` | `+0x2e1cfb8` | `0xffffffffd9e4cfb8` | `0xffffffff8c02cfb8` | [verified-on-dump] Independent pmap-structure signature in `engineering/payloads/kdata_dump/kdata_derive.py:derive_kernel_pmap_store`; same offset in both captures (`07` §derivations and cross-boot reproduction). The full Sony `struct pmap` size is not established here. |
| IDT | `+0x2e88300` | `0xffffffffd9eb8300` | `0xffffffff8c098300` | [verified-on-dump] 256 consecutive gate descriptors in `kdata_derive.py:derive_idt`; stride `0x10`, total `0x1000` bytes; cross-boot match (`07`). Gate targets depend on the captured patch state. |
| GDT array | `+0x2e895e0` | `0xffffffffd9eb95e0` | `0xffffffff8c0995e0` | [verified-on-dump] Repeated descriptor signature in `kdata_derive.py:derive_gdt`; GDT descriptor stride `0x8`; cross-boot match (`07`). |
| Common TSS array | `+0x2e8afe0` | `0xffffffffd9ebafe0` | `0xffffffff8c09afe0` | [verified-on-dump] GDT TSS descriptors point to 16 consecutive TSS records; per-CPU stride `0x68` (`kdata_derive.py:derive_tss`). `docs/16` §derived offsets records IST1 `+0x24`, then `+0x8` per IST slot. |
| `pcpu_array` | `+0x2e9cf00` | `0xffffffffd9eccf00` | `0xffffffff8c0acf00` | [verified-on-dump] Kstuff `r0gdb/prosper0gdb/offsets/12_02.h:11` gives the start. In both captures, 16 records have stride `0x980`: at record `i` offsets `+0x790` and `+0x798` both hold `kdata+0x2e8afe0+i*0x68`, for `i=0..15`. This validates the record sequence and TSS linkage; other PCPU fields are not assigned by this survey. |

[verified-on-dump] The `allproc` head's first qword is
`0xffffa3995907d9e0` in the PTE-gated capture and
`0xffff89a103f9e6d0` in the alias-sweep capture, each a plausible
kernel pointer. [inference] Its exact process-list semantics still
depend on the SDK's name and structural interpretation; a list walk
that fails to recover valid processes would falsify that assignment.

[verified-on-dump] In the alias-sweep snapshot, CPU 0's TSS starts at
`0xffffffff8c09afe0`; its `RSP0` at TSS `+0x4` is
`0xffffff8094807a40`, and its IST4 at `+0x3c` is
`0xffffff801542b860`. CPU 1 starts `0x68` bytes later, with
`RSP0=0xffffff809480fa40` and `IST4=0xffffff8015460860`.
IDT vector 13 occupies `IDT+0xd0` and its captured gate points to
`0xffffffff88773626`. This is a historical gate-state observation,
not a native-firmware handler claim.

## Complete archived IDT/TSS census

[verified-on-dump] I re-read `0x1000` IDT bytes (all 256 gates),
`0x680` TSS bytes (all 16 rows), and `0x9800` PCPU bytes (all 16
records) from **each** of the two FW 12.02 captures above. Every gate
had the present bit and selector `0x20`; exactly eight gates used an
IST. The complete IST-user set and both boot-specific handler values
are below. This is a census of the captured state, which included
kstuff-era gate changes; it is not a clean-state gate map.

| Vector | IST | PTE-gated boot handler | Alias-sweep boot handler |
|---:|---:|---:|---:|
| 1 | 4 | `0xffffffffd6593626` | `0xffffffff88773626` |
| 2 | 2 | `0xffffffffd659362d` | `0xffffffff8877362d` |
| 3 | 7 | `0xffffffffd6593626` | `0xffffffff88773626` |
| 8 | 1 | `0xffffffffd65f8b60` | `0xffffffff887d8b60` |
| 9 | 3 | `0xffffffffd6593626` | `0xffffffff88773626` |
| 13 | 3 | `0xffffffffd6593626` | `0xffffffff88773626` |
| 30 | 5 | `0xffffffffd65f8bb8` | `0xffffffff887d8bb8` |
| 179 | 6 | `0xffffffffd6593626` | `0xffffffff88773626` |

This table explicitly includes the requested vectors 1, 9, 13, 30,
and 179. [verified-on-dump] In both captures, PCPU record `i` has
`pc_cpuid=i` at record `+0x34`; the two pointers at `+0x790/+0x798`
both equal the address of TSS row `i`. The FreeBSD 11 `struct pcpu`
names `pc_cpuid` as the CPU number (`sys/sys/pcpu.h:158`) and
`pc_tssp`/`pc_commontssp` as the active/common TSS pointers
(`sys/amd64/include/pcpu.h:48-49`). The 16 matching triples establish
the **logical CPU → TSS row mapping in these captures**:

| Logical CPU (`pc_cpuid`) | PCPU record from `kdata` | TSS row from `kdata` |
|---:|---:|---:|
| 0 | `+0x2e9cf00` | `+0x2e8afe0` |
| 1 | `+0x2e9d880` | `+0x2e8b048` |
| 2 | `+0x2e9e200` | `+0x2e8b0b0` |
| 3 | `+0x2e9eb80` | `+0x2e8b118` |
| 4 | `+0x2e9f500` | `+0x2e8b180` |
| 5 | `+0x2e9fe80` | `+0x2e8b1e8` |
| 6 | `+0x2ea0800` | `+0x2e8b250` |
| 7 | `+0x2ea1180` | `+0x2e8b2b8` |
| 8 | `+0x2ea1b00` | `+0x2e8b320` |
| 9 | `+0x2ea2480` | `+0x2e8b388` |
| 10 | `+0x2ea2e00` | `+0x2e8b3f0` |
| 11 | `+0x2ea3780` | `+0x2e8b458` |
| 12 | `+0x2ea4100` | `+0x2e8b4c0` |
| 13 | `+0x2ea4a80` | `+0x2e8b528` |
| 14 | `+0x2ea5400` | `+0x2e8b590` |
| 15 | `+0x2ea5d80` | `+0x2e8b5f8` |

The row was determined from each PCPU record's TSS pointers, then
matched to its `pc_cpuid`; it was not selected by assuming row 0. The
historical TSS arrays also supply `RSP0` and all seven IST pointers
for each row; the CPU 0/1 examples above show their field positions.

### Complete live IDT/TSS/PCPU census (2026-10-15)

[verified-on-console] The owner approved the FW 12.02 read-only
diagnostic at `engineering/payloads/idttss_census_1202/census.elf`,
SHA-256 `15c3be249823725294669522d935185edc9853c2da1ace653bb68bd6ac1db5a5`.
It reads one `0x1000`-byte IDT, one `0x680`-byte TSS array, and sixteen
`0x980`-byte PCPU records. Its read primitive temporarily changes pipe
metadata; it does not arm a gate, change an IST slot, or trigger an
exception. Expected: all exact-length reads, 256 decoded gates, every
IST user and selected handler, and a validated PCPU-to-TSS mapping.
Recovery plan: if it stalls or powers off, send no further ELF in that
session; hard power cycle, restart elfldr, and confirm normal UI
operation.

[verified-on-console] The first transfer timed out in the host's
`sock.sendall(payload)` after ten seconds, before its response read.
The payload output file was empty and the number of bytes accepted by
elfldr was unknown. The console still answered ICMP and the owner
confirmed the UI was responsive. No further ELF was sent in that
session. The owner then hard power cycled, restarted elfldr, and
confirmed readiness. This attempt supplied **no** gate or TSS result.

[verified-on-console] After recovery, the **same ELF hash** was sent
once with host-side upload progress and a 30-second send timeout. All
497,552 bytes transferred, and the payload reported FW `0x12020000`,
`kdata=0xffffffffe0340000`, 18 exact-length reads totaling 44,672
bytes, and `[DONE]`. The full off-Git response is
`engineering/payloads/idttss_census_1202/live-retry-2026-10-15.log`,
SHA-256 `98c85eec70b41ea01f2b7492ca13ff706973fdd4ec2531f5f90b70dc36659cf7`.
The host independently checked every reported `got==want`, the 16
unique `pc_cpuid` values and TSS-row links, the four IST-user lines,
and the five requested vector lines. Two ICMP replies followed the
run; the owner confirmed that the UI and elfldr were normal. No
recovery reboot was needed after this successful run.

[verified-on-console] All 256 gates were present, and exactly four
used an IST. The four IST gates and five selected gates all reported
selector `0x20` and attributes `0x8e`. This is the complete live
IST-user set; vectors 3, 9, 13, and 179 did **not** use IST in this
boot, unlike the older kstuff-era captures.

| Vector | IST | Handler in this boot |
|---:|---:|---:|
| 1 | 4 | `0xffffffffdf9088b0` |
| 2 | 2 | `0xffffffffdf908b38` |
| 8 | 1 | `0xffffffffdf908b60` |
| 30 | 5 | `0xffffffffdf908bb8` |

The five requested vector records are:

| Vector | IST | Handler in this boot |
|---:|---:|---:|
| 1 | 4 | `0xffffffffdf9088b0` |
| 9 | 0 | `0xffffffffdf908b68` |
| 13 | 0 | `0xffffffffdf908b88` |
| 30 | 5 | `0xffffffffdf908bb8` |
| 179 | 0 | `0xffffffffdf9089e0` |

[verified-on-console] Every PCPU record `i` reported `pc_cpuid=i`,
and **both** TSS pointers at record `+0x790/+0x798` matched TSS row
`i` for `i=0..15`; the logical CPU-to-row mapping is therefore the
same as the offset table above. IDT, TSS, and PCPU strides were
`0x10`, `0x68`, and `0x980`, respectively. All 16 live TSS rows
returned a nonzero `RSP0`, IST1, IST2, IST4, and IST5; IST3, IST6,
and IST7 were zero in every row. The complete per-row pointer values
remain in the off-Git response named above.

These are one boot's data values. [inference] Applying the independently
derived 12.02 `kdata−ktext=0xd50000` gap from `docs/16` to this boot's
`kdata` yields `ktext=0xffffffffdf5f0000`. The handlers for vectors
1, 9, 13, and 179 then have exactly the `+0x3188b0`, `+0x318b68`,
`+0x318b88`, and `+0x3189e0` offsets in the limited 2026-10-13
read-only audit. An independent current-boot text-base measurement
disagreeing with `0xffffffffdf5f0000` would falsify this conversion.
The absolute gate values and CPU mapping do not depend on it. Neither
audit proves that the handlers are pristine Sony code or establishes
their instruction bytes.

## Paging-index data globals

[verified-on-dump] The following are **32-bit data fields**, not code
locations. Their positions were searched near `kernel_pmap_store` using
the 13.60 Byepervisor field ordering as a hint, then checked in both
12.02 captures. `DMPML4I` and `DMPDPI` reconstruct the independently
observed per-boot direct-map base by
`0xffff800000000000 | (DMPML4I << 39) | (DMPDPI << 30)`.

| Field | `kdata` offset | PTE-gated value | Alias-sweep value | Validation |
|---|---:|---:|---:|---|
| `DMPML4I` | `+0x2e1d254` | `0x147` | `0x113` | [verified-on-dump] Reconstructed dmap matches `0xffffa39900000000` and `0xffff89a100000000`, respectively. |
| `DMPDPI` | `+0x2e1d258` | `0x64` | `0x84` | [verified-on-dump] Same independent dmap agreement. |
| `PML4PML4I` candidate | `+0x2e1be0c` | `0x17a` | `0x1f6` | [inference] Correctly sized index at the expected same-region field position. A page-table self-reference check against that boot's CR3 root could confirm it; a mismatch would falsify the assignment. The alias walker does not perform this check. |

The paging-index **locations** agree across these two 12.02 captures;
their **values vary by boot**. The pointer-walking alias engine proves
that page-table translation works without these numeric field names;
it does not by itself validate the `PML4PML4I` field.

## Remaining boundary

[inference] This survey establishes data locations, observed values,
and the IDT/TSS/PCPU strides across two archived captures and one live
boot. It does not establish ownership or a complete field layout for
`kernel_pmap_store` or `struct pcpu`, or the instruction bytes at the
gate handlers. A new capture that breaks any cross-boot offset or
TSS-pointer progression would falsify the claimed stable layout.
