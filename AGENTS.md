# Agent guidance — ps5-kernel-research

Research-notes repository for the PS5 FW 12.02 kernel-privilege
stack. Contributions from other agents are welcome; follow the rules
below.

## Scope and material boundaries

- **Findings and knowledge only.** Never commit Sony proprietary code,
  kernel dumps (`.data` or `.text`), Ghidra/IDB databases, decrypted
  firmware images, memory captures, or any payload material. Links and
  derived knowledge (offsets, structures, techniques) are fine.
- Never embed console identity data, pairing credentials, or anything
  from the private research trees into this repo.
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

## Contribution workflow

- Topic branches + pull requests only; never push directly to `main`.
- Keep PRs small and single-purpose (3–7 changed files). Split
  dependency-ordered work into separate PRs.
- New findings go into the numbered doc that fits, or a new numbered doc
  if the topic is distinct; update `README.md`'s index in the same PR.
- No generated artifacts, no vendored third-party source.

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
