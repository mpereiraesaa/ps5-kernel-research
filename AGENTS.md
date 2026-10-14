# Agent guidance — ps5-kernel-research

Research and original-tooling repository for the PS5 FW 12.02
kernel-privilege stack and homebrew support. Contributions from other
agents are welcome; follow the rules below.

## Scope and material boundaries

- **Original source is welcome.** This repo may contain research notes,
  independently authored homebrew and kernel-patch source, payload
  source, build scripts, tests, and tooling. Code informed by observed
  behavior or reverse engineering is allowed; explain its provenance,
  purpose, and firmware assumptions in the PR. Existing in-repo source
  such as `r0gdb/` is within scope.
- Never commit Sony proprietary code, copied or closely translated
  decompiler output, kernel dumps (`.data` or `.text`), Ghidra/IDB
  databases, decrypted firmware images, or memory captures. Derived
  knowledge such as offsets, structures, and techniques is allowed.
- Keep generated binaries (`.elf`, `.bin`, `.prx`), object files, and
  build outputs out of Git. Publish reviewable source and build
  instructions instead. Respect licenses and attribution when using
  public third-party code; do not vendor third-party source.
- Never embed console identity data, pairing credentials, secrets, or
  private third-party material. Original source developed in a private
  lab tree may be moved here after checking it for excluded material.
- Keep the repo offline-reproducible in spirit: every technique
  documented should be executable from the public sources in
  `docs/06-sources.md` plus our own tooling.

## Epistemic discipline

Every kernel-behavior claim must carry one of the labels defined in the
README:

- `[verified-in-tree]` — cite the exact local file/line.
- `[public-consensus]` — cite the wiki/repo that documents it.
- `[inference]` — state the reasoning **and** what would falsify it.

Corrections to existing claims are first-class contributions: if a doc
statement is wrong (as happened with the "XOM moved from PTE to NPT"
model — see `docs/03-evolution-pre761.md`), fix the doc and record the
correction rather than quietly reinterpreting.

**Before proposing a mechanism, read
`docs/11-debunked-theories-and-corrections.md`** — the register of
theories we already falsified (and why), so the same mistakes are not
repeated. Add new falsifications there in the same PR.

For the ring-0 freeze specifically, also read
`docs/13-ring0-freeze-instrumentation.md` (the capture set, the three
remaining hypotheses, and the falsifiable test for each) and
`docs/14-ring0-execution-alternatives.md` (substrates vs r0gdb, and which
freeze class each eliminates) before proposing a fix.

## Contribution workflow

- Topic branches + pull requests only; never push directly to `main`.
- Keep PRs focused and reviewable. Small documentation PRs should
  usually change 3–7 files; a cohesive source change may need more.
  Split dependency-ordered work into separate PRs.
- New findings go into the numbered doc that fits, or a new numbered doc
  if the topic is distinct; update `README.md`'s index in the same PR.
- For source changes, include build or test instructions and distinguish
  offline validation from results observed on a console.

## Console-experiment policy

- No console-risky experiment (kernel writes to protected/unknown
  targets, MSR/CR probing, anything that can panic) is proposed or run
  without explicit owner approval and a recovery plan; note the risk in
  the PR/doc (`docs/04-route-1202.md` carries the standing examples).
- When a console experiment is approved, record: FW, build identity,
  expected observation, actual observation, and the recovery state.

## Tooling conventions referenced by these docs

- Payload SDK: `engineering/ps5debug-NG/ps5-payload-sdk/install/`
  (local; see `docs/05-toolchain-and-observability.md`).
- Structured evidence: `ps5log/1` via `projects/logging_server` (PC-side
  `ps5logd` on 9300).
