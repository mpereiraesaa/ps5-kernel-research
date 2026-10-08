# PS5 kernel research — FW 12.02

**Research goal** (owner-set 2026-10-08): *full understanding of this one
machine* — a locally decompiled, semantically mapped 12.02 kernel and,
eventually, the hypervisor, through our own capabilities on our own
console:

- **Phase A — semantic kernel map** (FW 12.02-native, no offline dumps):
  anchor every kernel text address we can identify (syscall table, ops
  tables, kstuff's public gadget/function tables, runtime derivations)
  and correlate against FreeBSD 11 source. Honest limit: Sony's
  *modifications* remain unknown until a text-read route opens.
- **Phase B — text-read research program**: find a route to read
  `.text` bytes (and, beyond it, HV memory). Known-closed on 12.x:
  IOMMU write, `hv_unmap_pt_tmr` abuse, APICBASE-MSR hijack. Open
  surface: GPU/GPUVM translation (do GPU accesses traverse the NPT?),
  MSRPM coverage, hypercall validation, HV intercept handlers,
  speculative channels. Three closed routes ≠ closed problem.

Findings only. No Sony proprietary code, no kernel dumps, no Ghidra
databases — links and knowledge, never payload material (see
`AGENTS.md`).

Started 2026-10-08 from a consolidation session over the local lab
(`homebrew_ps5`, `ps5debug-NG`, `prospero-win`, `payloads/`) and public
scene sources.

## Quick facts

| Item | Value |
|---|---|
| Console firmware | 12.02 (kernel `kern.sdk_version` = `0x12020000`) |
| CPU | AMD Zen 2 (Oberon APU) |
| Kernel | FreeBSD 11.0 fork ("Prospero") |
| Second-level translation | **NPT** (AMD nested paging — not EPT; EPT is Intel's term) |
| Kernel text protection | XOM via NPT PTE bit 58; blocks read *and* write |
| Privilege stack | ring 3 userland / ring 0 guest kernel / HV host (SVM) |
| Exploit chain | kstuff-lite `1.11-opt` + ps5-payload-sdk |
| What we never reach | HV host memory, kernel `.text` read/write, MSR/CR freedom |

## Document index

- [`docs/01-primitives.md`](docs/01-primitives.md) — the kernel-primitive
  inventory: kread/kwrite mechanics, page-table access, gadget execution,
  UELF/KELF, multi-FW dispatch.
- [`docs/02-xom-npt.md`](docs/02-xom-npt.md) — the XOM/NPT boundary: the
  two-level translation model, why text is unpatchable even with
  page-table control, evidence chain.
- [`docs/03-evolution-pre761.md`](docs/03-evolution-pre761.md) — the
  ps5-linux-loader comparison: how FW 3.x–7.61 defeated the NPT layer, why
  those routes are dead on 12.02, and where decrypted kernel images live
  offline.
- [`docs/04-route-1202.md`](docs/04-route-1202.md) — the forward plan:
  hard boundaries, owned foundation, ordered steps, backlog.
- [`docs/05-toolchain-and-observability.md`](docs/05-toolchain-and-observability.md)
  — payload toolchain, deploy via elfldr, and the three TCP logging
  routes.
- [`docs/06-sources.md`](docs/06-sources.md) — public sources and
  reference repos.
- [`docs/07-evidence.md`](docs/07-evidence.md) — console evidence log
  (dated experiment records: identity, expected, observed, recovery).

## Epistemic labels used throughout

Every kernel-behavior claim in these docs carries one of:

- **[verified-in-tree]** — directly evidenced by source in our local
  repos (file paths cited).
- **[verified-on-console]** — directly observed on the owned FW 12.02
  console; full record in `docs/07-evidence.md`.
- **[public-consensus]** — documented by the PS5 Developer wiki or
  multiple independent scene projects; not independently reproduced by
  us.
- **[inference]** — our conclusion from absence/architecture; labeled
  with the specific reasoning and what would falsify it.
