# Plan

Claim IDs (H…, W…, A…, C…, Q…, O…) refer to THEORY.md.

## 1. Target

`backend/hyperplonk` for gnark, bn254, native (out-of-circuit) prover and verifier:
HyperPlonk PIOP (H12) for gnark's SparseR1CS, with WHIR (W10) as the commitment to every multilinear oracle, made non-interactive with Merkle trees and Fiat–Shamir.

## 2. Decisions

Taken:

| # | Decision | Reason |
|---|---|---|
| D1 | Field bn254 `fr`, hash sha256, target 128-bit classical ("plausibly post-quantum"), as for plonkfri. | Same target makes the two backends comparable; no extension field is needed (THEORY §6). |
| D8 | Vendoring model for later integration; Panurus itself out of scope. | User. Packaging rule: all code under `backend/hyperplonk/`. |
| D5 | Non-zero-knowledge first. ZK is a later phase (Q5). | The ZK composition is not covered by one paper; soundness must be settled first. |
| D3 | Wiring identity: HyperPlonk's own permutation check (H7–H9). LogUp (G1–G3) is a later optimisation, to be measured against it. | User. Thm 3.6 states the soundness for exactly this use; a LogUp permutation argument would need a bound we derive ourselves. |
| D2 | WHIR regime: δ is a parameter; unique decoding (W6) for the first complete version, Johnson (A1/A2) as a second parameter set; both sizes reported. | User. UD is proven inside the WHIR paper; Johnson rests on preprints. |
| D7 | Rate ρ = 1/8, folding parameter k = 4; revisit after the first measurements. | User. Same rate as plonkfri; k as in WHIR §6.2. |
| D4 | Openings: one batched WHIR test for all polynomials (Construction 7.4), after a first version with one test per polynomial. | User. It is the form Thm 7.5 covers, and it cut the proof 3.4× (measured). |
| D6 | Plain gates only (q_L, q_R, q_M, q_O, q_C + copy constraints), as in plonkfri v1. No custom gates, lookups or BSB22 commitments. | Keeps the PIOP equal to H11/H12 with d = 3. |

Open (recommendation first; to be confirmed by the user before the milestone that needs it):

| # | Question | Recommendation | Needed by |
|---|---|---|---|

## 3. Method

Carried over from plonkfri (PROJECT.md "Lessons"):
1. Theory first: before a milestone starts, its claims are in THEORY.md with status S or better.
2. Red first: the test is written and seen to fail before the implementation.
3. Every soundness check has a cheating prover that is rejected, with the rejecting check recorded.
4. Every formula is checked on a hand-computed toy instance before it is used at real size.
5. Anything prover and verifier must agree on (variable order, transcript order, claim order) comes from one shared function.
6. Estimate before measuring.

## 4. Milestones

| M | Content | Claims | Tests (done when) |
|---|---|---|---|
| M0 | Reading: proofs of H5, H6; Construction 5.1 with the proof of Thm 5.2 (resolve O2, O3); Thm 5.6 (W12). Write a hand example of one WHIR round on m = 3. | H5, H6, W10–W12 → P | Example in THEORY.md reproduced by a throwaway script. |
| M1 | Multilinear toolbox and sumcheck: evaluation, eq, folding of a table; generic sumcheck prover/verifier for a sum of products of multilinear tables; zerocheck. Reuse `gnark-crypto/ecc/bn254/fr/polynomial.MultiLin` where it fits. | H1, H2, H5, H6 | Brute-force sum equals the claimed sum on μ ≤ 4; wrong claim, wrong round polynomial, degree overflow each rejected; measured acceptance of a random cheating message consistent with dμ/\|F\| on a small test field. |
| M2 | WHIR parameters: a calculator that maps (m, ρ, k, δ-regime, λ) to (M, L_i, t_i, list sizes) and evaluates every term of W11. | W4, W6, W11, W13, A1 | Reproduces the THEORY §6 table; every term ≤ 2⁻¹²⁸ for m ∈ [10, 20]; cross-check against one row of the WHIR paper's tables. |
| M3 | PIOP on an ideal oracle: setup (selectors, s_id, s_σ from gnark's permutation), prove, verify, with polynomial evaluations answered by a trusted in-memory oracle instead of a commitment. | H7–H9, H11–H13; Q3 | gnark's shared circuit suite passes; cheaters rejected: violated gate, broken copy constraint, wrong public input, wrong product oracle ṽ. |
| M4 | WHIR: RS encoding on a smooth coset, Merkle commitment, folding, the protocol W10 for evaluation weights, verifier. | W1–W3, W8–W12; O2, O3 | Fold(f, α) equals the encoding of f̂(α, ·) (W8); honest proofs verify; cheaters rejected: non-codeword, wrong evaluation claim, wrong out-of-domain answer, wrong final polynomial; proof size equals the calculator's prediction. |
| M5 | Composition: replace the ideal oracle by WHIR (C1); Fiat–Shamir transcript binding the verifying key and public inputs first. | C1–C4, A4, A5; Q1, Q2 | Suite passes; all M3 and M4 cheaters still rejected end to end; security-status table for hyperplonk added to PROJECT.md. |
| M6 | Measurements against plonkfri and KZG PLONK at the same circuit sizes: proof size, prover and verifier time, for UD and JB. | — | Table in PROJECT.md with estimate vs measured. |
| Later | Zero knowledge (Q5); batching/stacking (D4); LogUp wiring (D3); serialization; in-circuit verifier. | H14, ePrint 2026/391 | — |

## 5. Differences from `docs/hyperplonk-whir/` (feature/hyperplonk)

| Topic | There | Here | Why |
|---|---|---|---|
| Purpose | Backend for Panurus, built by a coordinated agent team with gates | Backend supported by checked theory; single line of work | User scope |
| Wiring identity | LogUp | HyperPlonk permutation check (D3) | Stated theorem for this exact use |
| WHIR structure | ZK-ready structure of ePrint 2026/391 from the start | WHIR as in ePrint 2024/1586, Construction 5.1; ZK later | The first version should match one paper's theorem |
| Regime | Johnson default | UD first, Johnson second (D2) | UD is proven inside the WHIR paper |
| Cross-check | Pinned Rust reference + Python reference | Hand examples and the paper's tables; a reference implementation may be added | Not decided; no dependency assumed |

## 6. Progress

| Milestone | State |
|---|---|
| M1 sumcheck + zerocheck | Done, except parallel proving (not needed for correctness). Packages `backend/hyperplonk/internal/{transcript,sumcheck}`. Claims H5, H6 at P·T. Every verifier check was switched off once and a test failed each time (7 mutations: round sum, message length, round count, final check, eq factor, claim binding, τ order). |
| M3 (part): product check | Done as a building block: `backend/hyperplonk/internal/prodcheck`, H7 at P·T, 5 mutations caught. Returns evaluation claims for the caller to verify (answers part of Q3: ṽ is opened at (1,r), (r,0), (r,1), (0,r) and (1,…,1,0)). Remaining for M3: multiset and permutation check, gate identity for gnark's SparseR1CS, public inputs, ideal-oracle prover/verifier. |
| M3 PIOP on an ideal oracle | Done. `internal/permcheck` (H8, H9) and `internal/piop` (index from SparseR1CS, prover, verifier returning evaluation claims). gnark's shared circuit suite: 31 circuits pass, 2 skipped (api.Commit, out of scope D6). Cheaters rejected with the rejecting check recorded: violated gate → gate round sum; broken copy constraint → product root claim; false or different public input → gate round sum; changed evaluations → final/linear check. Mutations: 4 (permcheck) + 6 (piop), all caught after two tests were added. Commitment stand-in: hash of the whole table (binding, not succinct). The package stays internal until WHIR replaces the stand-in. Q3 answered: see below. |
| M0 reading | Done for what M1–M4 use: sumcheck, zerocheck, product, multiset, permutation proofs; WHIR Thm 5.2 state function and query bounds, Construction 5.5/Thm 5.6. Not read: Thm 4.20 and Claim 5.3 (fold bound), the proofs of A1/A2. The hand example of a WHIR round was replaced by `whir.TestFoldLeaf` and `TestEncode`, which check the same identities on random inputs. |
| M2 parameters | Done: `internal/whir/params.go`. Schedule, query counts and every error term of Thm 5.2/5.6 for both regimes; query counts minimal (one fewer fails the check). At m = 20, ρ = 1/8, k = 4: queries per iteration 155/131/129/129/129 (UD) and 90/44/29/22/18 (Johnson). |
| M4 WHIR | Done (non-ZK, one polynomial per commitment, evaluation claims only): `internal/whir`. Honest proofs verify for m = 0..11 in both regimes; cheaters rejected with the rejecting check recorded; 10 mutations caught after two tests were added (claim binding, leaf size). Measured proof size for one opening equals the size predicted from the parameters: m = 14: 365 KiB (UD), 145 KiB (Johnson); predicted m = 20: 697 KiB (UD), 216 KiB (Johnson). No Merkle path sharing yet. |

Implementation decisions taken in M1 and their basis:

| Decision | Basis |
|---|---|
| Bind X₁ first; table index Σ bᵢ·2^(μ−i) | Same as gnark-crypto `MultiLin` and WHIR Claim 4.15 (W8); the soundness proof is symmetric in the variable order. Resolves O3. |
| Round message = d+1 values at 0..d; any other length rejected | A degree-≤d polynomial is fixed by d+1 values, so the degree bound required by H5 holds by construction. |
| Final check left to the caller, with the oracle values as input | In the PIOP those values come from the commitment (H4, C1); the sumcheck itself cannot know them. |
| Challenges from a 512-bit hash output reduced mod r | S1. |
| Statement (μ, d, claimed sum) absorbed before the first message | Strong Fiat–Shamir, ePrint 2023/691 Def. 3 (status R); `TestClaimIsBound`. |
| Zerocheck draws τ before the sumcheck starts | H6: τ must be chosen after the tables are fixed and before the prover's messages. |

| M5 composition | Done: `backend/hyperplonk/bn254` (`Setup`, `Prove`, `Verify`; regime selectable). The PIOP gained an out-of-domain sample after each prover commitment (WHIR §2.2), so there are now 17 claims on 8 polynomials. gnark circuit suite: 31 pass end to end, 2 skipped. 38 tampered proofs rejected; 4 mutations of the composed verifier caught (two after adding `TestDigestCoversTheKey`). Not done: backend ID / top-level dispatcher, serialization. Security status: THEORY §10. |
| M6 first measurement | 2^13 rows (8177 constraints), Apple M-series laptop, single run: unique decoding 3027 KiB proof, prove 263 ms, verify 34 ms; Johnson 1186 KiB, prove 247 ms, verify 14 ms. Estimate made before measuring: "several MiB in UD" — confirmed. For comparison plonkfri: 0.84 MiB at 2^16 rows (PROJECT.md). The proof is dominated by 8 separate WHIR openings; a 4-row circuit already costs 454 KiB (UD). |

| D4 batching | Done. `whir.Commit` takes several polynomials per tree; `OpenBatch`/`VerifyBatch` implement Construction 7.4. Backend: four polynomials in μ+3 variables (selectors stacked, s_σ and w padded, ṽ), three trees, 12 distinct points, 48 values sent. Same run as before (2^13 rows): unique decoding 3027 → 888 KiB, verify 34 → 6 ms; Johnson 1186 → 401 KiB, verify 14 → 2 ms; prove unchanged (≈ 0.24 s). plonkfri for reference: 0.84 MiB at 2^16 rows. 70 tampered proofs rejected; 5 + 5 mutations (whir batch, backend) caught. Estimate before measuring was "roughly the size of one opening of the largest polynomial" (≈ 500 KiB UD at m = 16): measured is higher because first-round leaves carry four polynomials. |

| Theory gaps (after batching) | Written: round-by-round state function of the whole PIOP (THEORY §11). Read: BCS §6 and Thm 7.1 (the transformation is a hash chain like ours; differences listed in S16), ePrint 2019/834 Thm 3, WHIR Thm 4.20 with proof (block distance = fraction of Merkle leaves). Code: Merkle hash prefixes made disjoint from the transcript's. Still unread: proofs of WHIR Thm 7.5 and Claim 5.3, BCS Thm 7.1, s̄_sr ≤ b·ε_rbr, and the two Johnson preprints. |

| Engineering: ID, dispatcher, serialization | Done. `backend.HYPERPLONK` ("hyperplonk"); `backend/hyperplonk` with `Setup` (option `WithJohnsonRegime`), `Prove`, `Verify`, `NewProof`/`NewProvingKey`/`NewVerifyingKey`; errors instead of panics for R1CS systems, other curves and foreign types. `WriteTo`/`ReadFrom` for proof and keys: magic + version, canonical field elements, every length bounded before allocation, `MaxLogSize` = 17 for decoded keys. The proving key stores the tables only; decoding recomputes the commitment and checks it against the root and the circuit hash. Tests: round trips, every tested strict prefix rejected, 3548 single-bit flips all rejected (108 by the decoder, 3440 by `Verify`), non-canonical element and oversized length rejected, fuzz target `FuzzProofReadFrom` clean for 45 s. Sizes: verifying key 81 bytes; framing adds 1.05 % to a proof. Outside the backend: `internal/stats` now iterates over the backends that have statistics (groth16, plonk); its test was failing since PLONKFRI was added to `backend.Implemented()`. The root `TestVersion` failure predates this work and is unrelated. |

| M6 comparison | `backend/hyperplonk/compare_test.go` (build tag `hpcompare`). Table below. |

Comparison on the chain-of-squarings circuit used by the other backends' performance tests (bn254, Apple arm64 laptop, 11 CPUs, median of 3 runs, serialized proof size):

| Rows | System | Setup | Prove | Verify | Proof |
|---|---|---|---|---|---|
| 2^12 | plonk (KZG) | 83 ms | 52 ms | 1.2 ms | 0.5 KiB |
| 2^12 | plonkfri | 51 ms | 125 ms | 2.7 ms | 705 KiB |
| 2^12 | hyperplonk, unique decoding | 39 ms | 127 ms | 5.2 ms | 760 KiB |
| 2^12 | hyperplonk, Johnson | 40 ms | 118 ms | 2.3 ms | 374 KiB |
| 2^14 | plonk (KZG) | 255 ms | 158 ms | 1.2 ms | 0.5 KiB |
| 2^14 | plonkfri | 184 ms | 517 ms | 3.2 ms | 841 KiB |
| 2^14 | hyperplonk, unique decoding | 161 ms | 490 ms | 6.4 ms | 924 KiB |
| 2^14 | hyperplonk, Johnson | 162 ms | 493 ms | 2.6 ms | 417 KiB |
| 2^16 | plonk (KZG) | 934 ms | 532 ms | 1.2 ms | 0.5 KiB |
| 2^16 | plonkfri | 741 ms | 2014 ms | 3.8 ms | 990 KiB |
| 2^16 | hyperplonk, unique decoding | 635 ms | 2001 ms | 7.0 ms | 979 KiB |
| 2^16 | hyperplonk, Johnson | 684 ms | 1992 ms | 2.7 ms | 440 KiB |

How to read it:
- The systems do not offer the same properties. plonk needs a trusted setup (here a test SRS, whose generation is included in its setup time). plonkfri is zero-knowledge; hyperplonk is not yet, and zero knowledge will add to its proof size and prover time.
- plonkfri runs in the Johnson regime with correlated agreement from a peer-reviewed result (86 queries). Its like-for-like partner in decoding regime is "hyperplonk, Johnson", whose mutual correlated agreement comes from preprints; "unique decoding" is the conservative setting.
- hyperplonk's proof grows more slowly with the circuit: +29 % from 2^12 to 2^16 in unique decoding (plonkfri +41 %).
- The hyperplonk prover is single-threaded outside the FFT; no profiling or optimisation has been done.

| ZK stage S0: wiring by layered sumcheck | Done. New `internal/grandprod`; `permcheck` rewritten on it; the product polynomial ṽ, its commitment and `internal/prodcheck` removed. Three committed polynomials (Q, S, W), two trees, 7 evaluation points. Circuit suite 31/31, 42 tampered proofs rejected, fuzz clean (20 s). Same comparison run as above, hyperplonk only: 2^12: 84 ms / 624 KiB (UD), 79 ms / 300 KiB (Johnson); 2^14: 332 ms / 783 KiB, 317 ms / 340 KiB; 2^16: 1.36 s / 831 KiB, 1.30 s / 363 KiB (plonkfri in the same run: 2.13 s / 990 KiB). Against the previous version at 2^16: prover −32 %, proof −15 % (UD) and −18 % (Johnson). Theory: THEORY S17 and §12. |

| ZK stage S1: random rows | Done. Rows beyond the public-input and constraint rows are fixed points of σ with zero selectors; the prover fills them and the fourth column with random values (`Index.Wires`, `Index.RandomSlots`, `MinRandomRows` = 1). A first version reserved 2 rows; the benchmark circuit, which fills all but one row of 2^16, then moved to 2^17 rows and its prover time doubled. One row is enough — the rank test covers exactly that least configuration — and with it only a circuit that fills a power of two completely moves to the next size. Rank tests on real proofs: `piop.TestOpenedValuesAreUniform` (5 opened values of w, rank 5, for three circuit sizes; control: rank too small from the fourth column alone) and `bn254.TestOpenedValuesOfWAreUniform` (the 7 values of W in the evaluation table: rank 6, the seventh is identically 0). Proofs are now randomized; the fuzz fixture was made deterministic for that reason. Not yet zero-knowledge: sumcheck messages and openings still depend on the witness. Not derived: a bound on the probability that the verifier's points give a deficient rank (the paper's Lemma 2 covers one point). |

| ZK stage S2: masked messages | Done. New `internal/cbip` (pad tape, affine maps, masked sumcheck rounds, linearization of products). The PIOP is now one protocol description (`piop/protocol.go`) executed by prover and verifier through their sides; the verifier returns evaluation claims and linear constraints on the pad. WHIR claims generalized from points to linear forms (`whir.Form`). Backend: constraints merged into one form on W. Least circuit size 2^9 rows. Circuit suite 31/31; 48 tampered proofs rejected; all four end-to-end cheaters are now rejected by the verifier itself; 10 mutations of the constraint set caught (three only after adding prover deviations that isolate one constraint each); fuzz clean. Measured (same run as the table above, hyperplonk only): 2^12: 89 ms / 10.6 ms verify / 623 KiB (UD); 2^16: 1.40 s / 18.6 ms / 828 KiB (UD), 1.32 s / 14.5 ms / 360 KiB (Johnson). Prover and size unchanged within noise; verifier time up from 7.5 to 18.6 ms at 2^16, from carrying affine maps of the pad. `sumcheck` zerocheck, `grandprod.Prove/Verify` and `permcheck.Prove/Verify` are no longer on the proof path; they remain as tested reference implementations of the unmasked protocols. Theory: THEORY S18, §13. |

| ZK stage S3: hiding opening | Done. Blinding half of W in the last variable, salted leaves for prover trees, mask polynomial with its own out-of-domain point inside `whir.OpenBatch`, `internal/rnd` as the single randomness source, minimum circuit size 2^10 rows (unique decoding) or 2^9 (Johnson). Basis and argument: ZK-DESIGN.md §13–§14. Tests: rank on opened leaves (387/387 at reduced query count), rank on W's form values (11/11, both regimes), opening depends only on the masked combination, salts, fresh blinding; 5 mutations (4 caught; the fifth, salt length, is redundant with the hash check and now has a strictness test). 60 tampered proofs rejected; fuzz clean. |

| Strengthening the ZK claim | `bn254.TestJointRank` (opt-in, 43 s): full rank on everything one proof reveals, 4 proofs, both regimes (up to 2460 × 7843). Bound on rank deficiency derived: three of four groups of rows proven, the fourth conditional (ZK-DESIGN §15.2). Construction compared with the definitions and theorems of ePrint 2026/2880: three differences recorded (§15.3). |

Comparison after all zero-knowledge stages (same circuit and method as the first table; both transparent systems are now zero-knowledge by construction):

| Rows | System | Setup | Prove | Verify | Proof |
|---|---|---|---|---|---|
| 2^12 | plonkfri | 51 ms | 132 ms | 2.9 ms | 705 KiB |
| 2^12 | hyperplonk, unique decoding | 40 ms | 152 ms | 11.5 ms | 783 KiB |
| 2^12 | hyperplonk, Johnson | 43 ms | 149 ms | 9.0 ms | 391 KiB |
| 2^14 | plonkfri | 191 ms | 515 ms | 3.6 ms | 841 KiB |
| 2^14 | hyperplonk, unique decoding | 158 ms | 610 ms | 15.1 ms | 951 KiB |
| 2^14 | hyperplonk, Johnson | 165 ms | 590 ms | 11.3 ms | 437 KiB |
| 2^16 | plonkfri | 773 ms | 2139 ms | 4.1 ms | 990 KiB |
| 2^16 | hyperplonk, unique decoding | 662 ms | 2405 ms | 19.5 ms | 1008 KiB |
| 2^16 | hyperplonk, Johnson | 679 ms | 2353 ms | 14.7 ms | 464 KiB |

Cost of zero knowledge for hyperplonk at 2^16 rows (against stage S0): prover 1.36 → 2.41 s (the mask polynomial is a second word of full size to encode and commit), proof 831 → 1008 KiB in unique decoding and 363 → 464 KiB at Johnson (a third tree in the first iteration, salts, mask values), verifier 7.5 → 19.5 ms (affine maps of the pad). No optimisation has been attempted on any of the three.

| Zero knowledge removed; performance | User decision: the backend is to be a fast transparent prover; zero knowledge is not a goal. The code was restored to the state after stage S0 (wiring by layered sumcheck, no committed product polynomial); stages S1–S3 are kept on the local branch `hyperplonk-whir-zk`, and `ZK-DESIGN.md` remains as the record of that work. Then: (1) polynomials committed at their natural size — four polynomials in μ+2 variables (Q = q_L, q_R, q_M, q_O stacked; C = q_C; S; W) instead of three in μ+3, which halves the prover's encoding and all WHIR work; (2) parallel loops (`internal/par`) in the sumcheck rounds and folding, Merkle hashing, encoding, weight tables, the evaluation table and the product trees; (3) FFT domains cached. A slicing bug introduced by (2) (appending to a leaf overwrote its neighbour) was caught by the existing tests and fixed. All tests green, also under the race detector; fuzz clean. Profile after the changes: the FFT is 40 % of CPU time, Merkle hashing 6 %. |

Comparison after the performance work (same circuit and method as before; hyperplonk is not zero-knowledge, plonkfri is):

| Rows | System | Setup | Prove | Verify | Proof |
|---|---|---|---|---|---|
| 2^12 | plonk (KZG) | 80 ms | 52 ms | 1.2 ms | 0.5 KiB |
| 2^12 | plonkfri | 51 ms | 128 ms | 2.9 ms | 705 KiB |
| 2^12 | hyperplonk, unique decoding | 19 ms | 26 ms | 5.3 ms | 684 KiB |
| 2^12 | hyperplonk, Johnson | 16 ms | 25 ms | 2.7 ms | 337 KiB |
| 2^14 | plonk (KZG) | 277 ms | 160 ms | 1.2 ms | 0.5 KiB |
| 2^14 | plonkfri | 186 ms | 515 ms | 3.5 ms | 841 KiB |
| 2^14 | hyperplonk, unique decoding | 72 ms | 82 ms | 7.1 ms | 838 KiB |
| 2^14 | hyperplonk, Johnson | 63 ms | 81 ms | 3.2 ms | 377 KiB |
| 2^16 | plonk (KZG) | 968 ms | 531 ms | 1.2 ms | 0.5 KiB |
| 2^16 | plonkfri | 769 ms | 2070 ms | 4.0 ms | 990 KiB |
| 2^16 | hyperplonk, unique decoding | 297 ms | 290 ms | 7.5 ms | 887 KiB |
| 2^16 | hyperplonk, Johnson | 272 ms | 288 ms | 3.4 ms | 399 KiB |

At 2^16 rows the hyperplonk prover is 7.1× faster than plonkfri and 1.8× faster than KZG PLONK. Its proof is 10 % smaller than plonkfri's in unique decoding and 60 % smaller at Johnson; its verifier is about 2× slower in unique decoding and slightly faster at Johnson.

Evaluation claims the commitment scheme must prove per proof (answers Q3), with r ∈ F^μ the gate point and r' ∈ F^(μ+2) the wiring point:

| Polynomial | Variables | Points |
|---|---|---|
| q_L, q_R, q_M, q_O, q_C | μ | r (one each) |
| w | μ+2 | (0,0,r), (0,1,r), (1,0,r), r' |
| s_σ | μ+2 | r' |
| ṽ | μ+3 | (1,r'), (r',0), (r',1), (0,r'), (1,…,1,0) |

(Table as of M3. Since stage S0 there is no ṽ: w is opened at (0,0,r), (0,1,r), (1,0,r), the wiring point q and one out-of-domain point; s_σ at q.)

Implementation decisions taken in M3 and their basis: package comments of `permcheck` and `piop`, and THEORY S4–S9.
