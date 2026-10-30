# HyperPlonk + WHIR — execution ledger

Single source of truth for execution state (PLAN.md §7.4). Update and commit (`status: …`) before every agent launch and after every return, merge or gate.

## Header
- **Phase:** kick-off (PLAN §0)
- **Branch:** `feature/hyperplonk` (pushed to `origin`)
- **Last checkpoint commit:** `06ca7bd6` (docs) on `feature/hyperplonk`, based on `master` @ `16a40bc2`
- **Next action:** K3 hygiene PR to `master`; K7 full briefs for M0a/M1a; K8 allowlist (show to user)
- **Pending user decisions:** **D8 Panurus integration model** (panurus#2539 merged by vendoring, PLAN §4)
- **Reference pin:** `WizardOfMenlo/whir@c73b8d3`

## Restart procedure
1. Read `CLAUDE.md` → `PROJECT.md` → this file; `git fetch`; check out the branch above.
2. For each `running` row: inspect its agent branch. Returned but not recorded → write `reports/<ID>.md`, set `returned`. Mid-work → relaunch a fresh agent with the same brief + a "resume" section (last commit, done, remaining). Unusable → `failed`, reset the agent branch to its base, relaunch. Never assume an old agent session is alive.
3. `returned` / `in-review` rows: continue review/merge (PLAN §7.2).
4. Re-run the full-tree check on `feature/hyperplonk` and the current `hp/<milestone>`; log `resumed`.
5. A pending user decision or gate in the header → ask the user first.

## Tasks
States: todo · ready · running · returned · in-review · merged · blocked · failed · abandoned (non-branch items use `done`)

| ID | State | Owner | Branch | Base | Last commit | Brief | Report | Updated |
|---|---|---|---|---|---|---|---|---|
| K1 | merged | user | master | — | 16a40bc2 | — | — | 2026-10-27 |
| K2 | done | coordinator | feature/hyperplonk | 16a40bc2 | 06ca7bd6 | — | — | 2026-10-30 |
| K3 | todo | coordinator → agent | hp/m-1-hygiene → master | 16a40bc2 | — | briefs/K3.md | — | 2026-10-27 |
| K4 | done (decision: local gate evidence) | user | — | — | — | — | — | 2026-10-27 |
| K5 | done (spec edits) | coordinator | hyperplonk-design | — | — | — | — | 2026-10-27 |
| K6 | done | coordinator | feature/hyperplonk | 16a40bc2 | cac2903e | — | — | 2026-10-30 |
| K7 | todo (templates done) | coordinator | feature/hyperplonk | — | — | — | — | 2026-10-27 |
| K9 | done (session log) | coordinator | — | — | — | — | — | 2026-10-27 |
| K8 | ready (approved; allowlist to write) | coordinator | — | — | — | — | — | 2026-10-27 |
| K10 | done | coordinator | feature/hyperplonk | 16a40bc2 | 06ca7bd6 | — | — | 2026-10-30 |
| M−1 | todo | agent | hp/m-1-hygiene | — | — | — | — | — |
| M0a | todo | Foundations | hp/m0a | — | — | — | — | — |
| M0b | todo | Calculator, RustRef, PyRef | hp/m0b | — | — | — | — | — |
| G0 | todo | user | — | — | — | — | gates/G0.md | — |
| M1a | todo | Sumcheck | hp/m1a | — | — | — | — | — |
| M1b | todo | PIOP | hp/m1b | — | — | — | — | — |
| M1c1 | todo | WHIR | hp/m1c1 | — | — | — | — | — |
| M1c2 | todo | WHIR | hp/m1c2 | — | — | — | — | — |
| M1c3 | todo | WHIR | hp/m1c3 | — | — | — | — | — |
| M2 | todo | PIOP | hp/m2 | — | — | — | — | — |
| G1 | todo | user | — | — | — | — | gates/G1.md | — |
| M3a–f | todo | WHIR, PIOP, Adversary | hp/m3a…m3f | — | — | — | — | — |
| G2 | todo | user | — | — | — | — | gates/G2.md | — |
| M4 | todo | Perf/Hardening | hp/m4 | — | — | — | — | — |
| M5 | todo | Perf/Hardening | hp/m5 | — | — | — | — | — |
| M6 | todo | Reviewers | hp/m6 | — | — | — | — | — |
| M7 | blocked (D8) | Panurus integrator | (Panurus repo) | — | — | — | — | — |

## Event log
| Date | ID | Event | Detail |
|---|---|---|---|
| 2026-10-27 | design | plan + specs written | 4 research agents; docs in `docs/hyperplonk-whir/` |
| 2026-10-27 | design | review 1 | 22 findings accepted (PLAN §10) |
| 2026-10-27 | design | review 2 | 20 findings accepted (PLAN §11) |
| 2026-10-27 | design | readiness audit | 34 gaps accepted (PLAN §12) |
| 2026-10-27 | K1 | merged | PR #9 → master `16a40bc2` (user) |
| 2026-10-27 | K4, K8 | user decision | local gate evidence; agent permissions approved |
| 2026-10-27 | D7 | user decision | develop on `feature/hyperplonk` |
| 2026-10-27 | §7.4 | user request | execution tracking/restart added; this ledger created |
| 2026-10-30 | docs | OVERVIEW expanded | toy examples, 7 animated SVG figures, 3 Mermaid diagrams; generators in `toy/` |
| 2026-10-30 | docs | review started | independent document review (gaps, references) on a frozen snapshot |
| 2026-10-30 | docs | review returned | 49 findings; all accepted; D8 opened (panurus#2539 merged by vendoring) |
| 2026-10-30 | K2, K6, K10 | done | user asked to commit and push; `feature/hyperplonk` created from `16a40bc2` and pushed: `cac2903e` (papers), `06ca7bd6` (docs) |
