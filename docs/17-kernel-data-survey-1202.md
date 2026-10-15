# 17 — FW 12.02 kernel-data survey

This is an address and structure survey, not an execution map. Every
offset below is relative to the **per-boot `kdata` base** and names data.
An address in this table is not an executable entry point. Kstuff was
present for the previously discussed 12.02 dump, so the captured IDT
handlers and IST contents cannot be assumed to represent pristine
firmware (see `11` correction #19). No new console experiment was run
for this survey.

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
and the IDT/TSS/PCPU strides. It does not establish ownership or a
complete field layout for `kernel_pmap_store` or `struct pcpu`, nor a
current-boot snapshot. A new capture that breaks any cross-boot offset
or TSS-pointer progression would falsify the claimed stable layout.
