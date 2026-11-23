# HyperPlonk + WHIR for gnark — our documentation

Branch: `hyperplonk-whir`.

## Scope

One goal: implement a `backend/hyperplonk` for gnark — the HyperPlonk polynomial IOP with WHIR as the multilinear polynomial commitment — and support every part of the implementation with theory that has been checked against the papers in `resources/`.

Out of scope for now: Panurus integration, performance targets, multi-agent execution. Decision D8: when integration is taken up later, the backend is vendored (copied), as was done for plonkfri. The only consequence today is a packaging rule: everything the backend needs lives under `backend/hyperplonk/`, with no imports of other fork-only packages.

## Relation to the existing documents

`origin/feature/hyperplonk` holds A. De Caro's design set in `docs/hyperplonk-whir/` (PLAN, SPEC-PIOP, SPEC-WHIR, PANURUS, STATUS, OVERVIEW, LOGUP, SUMCHECK). It is left unchanged and is not merged into this branch. Only the reference papers were taken from that branch (`resources/`). The documents here are written independently from the papers; where a design choice differs from that set, PLAN.md says so.

## Code

| Path | Content |
|---|---|
| `backend/hyperplonk` | Public API: `Setup`, `Prove`, `Verify`, key and proof constructors |
| `backend/hyperplonk/bn254` | The proof system on bn254: composition, keys, serialization |
| `backend/hyperplonk/internal/piop` | HyperPlonk PIOP for SparseR1CS (gate and wiring identity) |
| `backend/hyperplonk/internal/{sumcheck,grandprod,permcheck}` | Sumcheck and zerocheck, grand-product argument, permutation check |
| `backend/hyperplonk/internal/whir` | WHIR: parameters, encoding, Merkle tree, batched commit/open/verify |
| `backend/hyperplonk/internal/{transcript,par}` | Fiat–Shamir transcript; parallel loops |

The backend is not zero-knowledge. A zero-knowledge variant (slower) is on the local branch `hyperplonk-whir-zk`; see `ZK-DESIGN.md`.

## Files

| File | Content |
|---|---|
| `THEORY.md` | Ledger of the claims the implementation relies on: statement, paper, section, verification status. Includes the instantiation over bn254 and the open theory questions. |
| `PLAN.md` | Design decisions (taken and open) and milestones. Each milestone lists the claims it implements and the tests that check them. |
| `ZK-DESIGN.md` | What the proof reveals today, the zero-knowledge building blocks in the literature, and the options (proposal for decision). |

## Verification policy

A claim may be used by the code only if it has an entry in THEORY.md. Each entry carries a status:

| Tag | Meaning |
|---|---|
| S | Statement read in the paper and transcribed. The proof was not read. |
| P | Proof read and followed. |
| T | Checked by a test in this repository (test name given). |
| R | Recalled or recorded in an earlier session; not re-checked against the paper. |

Rules:
1. A milestone is complete only when every claim it uses is at least S, and every claim that can be checked computationally is T.
2. Numbers for our parameters are computed from the cited formula and marked "computed"; they are estimates until a test reproduces them.
3. A discrepancy between a paper and our reading is recorded in THEORY.md §7 and is not resolved silently.
4. Preprints and results that are not peer reviewed are marked as such.

## Conventions

- Field: F = bn254 scalar field, log₂|F| ≈ 253.6.
- μ: number of variables of the PIOP polynomials (2^μ = number of constraints). m: number of variables of a WHIR codeword. Papers keep their own letters in quotations.
- B_μ = {0,1}^μ, the boolean hypercube. eq(x, y) = Π_i (x_i·y_i + (1 − x_i)(1 − y_i)).
- ePrint numbers identify papers; the PDF is `resources/<year>-<number>.pdf`.
