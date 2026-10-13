# 06 — Public sources and reference repos

All public. Nothing here contains proprietary Sony material; these are
scene research artifacts and documentation.

## Primary references read for these notes

- ps5-linux-loader — https://github.com/ps5-linux/ps5-linux-loader
  - `source/hv_defeat_{0304,0506,0607}.c` — the per-FW NPT-defeat routes
    (see `03-evolution-pre761.md`).
  - `source/hv_defeat_0304.c` consumes `HOOK_ACPI_WAKEUP_MACHDEP` for
    the 3.00–4.51 route; the 5.00+ offset tables mark it unused.
  - `source/utils.c` — `page_chain_set_rw`, `vtophys_custom`,
    `install_page`, `pa_to_dmap`, per-FW offset dispatch.
  - `source/prepare_resume.c` — `remove_xotext`,
    `kernel_pmap_invalidate_all` (pipe + `page_remove_global` TLB
    invalidation trick).
  - `shellcode_0607/main.c`, `shellcode_kernel/main.c` — in-HV NPT
    disable and resume-time ring-0 shellcode.
- sleirsgoevy's offset-porting methodology —
  https://gist.github.com/sleirsgoevy/26c482553b9fa604dd9b8ba7dfe654d6
  ("how I found the offsets for 4.03": data dumps, IDT/TSS derivation,
  single-step gadget discovery, "pointer poisoning" #GP hooks).
- sleirsgoevy's ps4jb-payloads `ps5-kstuff/porting_tool` —
  https://github.com/sleirsgoevy/ps4jb-payloads
  (`main.py`: 134 MB kdata dump via r0gdb/copyout; structural-signature
  symbol derivation for rootvnode/IDT/GDT/TSS/kernel_pmap_store).
- AMD64 Architecture Programmer's Manual, Vol. 2, §13.1.3.1 —
  https://docs.amd.com/v/u/en-US/24593_3.44_APM_Vol2
  (instruction-address breakpoints fault before the instruction executes;
  the return path must prevent repeat delivery or clear the breakpoint).
- PS5 Developer wiki:
  - https://psdevwiki.com/ps5/index.php/Kernel
  - https://www.psdevwiki.com/ps5/index.php/Hypervisor
  (NPT xotext bit 58; HV maps text RW in its own tables; "nda feature"
  AMD hardware XOM collaboration; masked EFER bits; HV part of kernel
  binary ≤ FW 2.70.)
- cragson/ps5-hen — https://github.com/cragson/ps5-hen
  (`gpu_dma.h` / `gpu_dma.cpp`: PS5 GPUVM PTE fields, page-table walker,
  and GPU DMA physical-access helper; README scopes the project to FW
  1.00–4.51 and describes IOMMU patching plus NPT disable in its HV
  defeat chain. These details do not establish FW 12.02 behavior.)
- hammer-83/ps5-jar-loader — https://github.com/hammer-83/ps5-jar-loader
  (`KernelAccessorAgc.java`: independent GPU PTE remap and DMA-based
  kernel-memory accessor implementation.)
- Cryptogenic/PS5-SELF-Decrypter —
  https://github.com/Cryptogenic/PS5-SELF-Decrypter
  (decrypt system SELF/SPRX files from the filesystem via kernel R/W —
  how public decrypted system-module sets are made; not the kernel
  itself).

## The stack we run

- kstuff-lite (EchoStretch) — https://github.com/EchoStretch/kstuff-lite
  (`1.11-opt`: UELF/KELF machinery, cached fixed mappings, CR0/FPU
  chains, debug-register transitions, prosper0gdb handoff).
- ps5-payload-sdk (ps5-payload-dev) —
  https://github.com/ps5-payload-dev/sdk
  (`crt/kernel.c` primitive implementation, `kernel.h` contract).
- PS5-Lapy-JB-Daemon (ours) —
  https://github.com/mpereiraesaa/PS5-Lapy-JB-Daemon
  (owned-root daemon, cooperative elevation, multi-FW offsets override,
  layout preflight; design docs under `docs/`).
- ShadowMountPlus — https://github.com/drakmor/shadowMountPlus
  (auto-mounter; requires kstuff-lite ≥ 1.07; nmount unionfs
  fakelib/backports).
- ps5debug-NG (local) — wire-compatible ps5debug successor; kernel R/W,
  process manipulation, scans, guarded page-table aliasing; see the
  local checkout `engineering/ps5debug-NG/`.

## Where decrypted kernel knowledge lives

1. Reproducible by us: kernel `.data` dumps (any FW, our primitives) +
   structural derivation (porting_tool method).
2. Public: per-FW offset tables embedded in the repos above; Specter's
   offset documents (`document/en/ps5/offsets` referenced by the
   porting tool README).
3. Private scene channels: full `.text` dumps / Ghidra DBs for old FWs
   (≤ 7.61 captures), traded in the research Discords linked from those
   projects. Never public — Sony proprietary code. Never commit any of
   it here.
4. FreeBSD 11.0 source — the structural oracle.
   For the kobj method/class layout used in the 12.02 data-only
   attribution, see [`sys/sys/kobj.h`](https://github.com/freebsd/freebsd-src/blob/releng/11.0/sys/sys/kobj.h#L43-L64).
   For the power/ACPI call-path baseline, see [`acpi.c`](https://github.com/freebsd/freebsd-src/blob/releng/11.0/sys/dev/acpica/acpi.c),
   [`acpi_wakeup.c`](https://github.com/freebsd/freebsd-src/blob/releng/11.0/sys/x86/acpica/acpi_wakeup.c),
   and [`acpi_timer.c`](https://github.com/freebsd/freebsd-src/blob/releng/11.0/sys/dev/acpica/acpi_timer.c).
