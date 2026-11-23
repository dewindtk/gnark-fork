# Zero knowledge — analysis and options

> Note: zero knowledge was removed from the backend by user decision (performance is the goal). This document describes the variant kept on the local branch `hyperplonk-whir-zk`; it does not describe the current code on `hyperplonk-whir`.

Status: exploration. §1–§6 are the first analysis; §7–§10 add a candidate construction found afterwards and the experiments that support it. No protocol code yet. Sections of the sources not yet read are named in §5 and §10.

## 1. What the current proof reveals

The proof is not zero-knowledge. Everything below is a function of the witness.

| # | Leak | Where | Amount |
|---|---|---|---|
| L1 | Values of w and ṽ at the PIOP's points | `GateEvals`, `Perm`, and the table `Values` (every polynomial at every point) | 2 polynomials × 12 points |
| L2 | Out-of-domain answers for w and ṽ | `WOOD`, `VOOD` | 2 values |
| L3 | Sumcheck round polynomials of the gate and wiring checks | `Gate`, `Perm.Prod.Zero` | (μ + μ+2) rounds × 4 or 3 values |
| L4 | Codeword values of W and V at the queried positions | first-iteration openings | t₀ · 2^k values per polynomial (155 · 16 in unique decoding) |
| L5 | All WHIR messages about the combined polynomial g = Σ γ^j·f_j | sumcheck rounds, later oracles, their out-of-domain answers, final polynomial | functions of g, hence of w and ṽ |

## 2. Building blocks in the literature

| Block | Hides | Source | Read | Fits our construction? |
|---|---|---|---|---|
| B1 Zero-knowledge encoding: append t random coefficients to the message before encoding | L4 | ePrint 2026/391, Prop. 3.19 (RS code: message length ℓ − t, randomness t, perfect) | statement | Yes, with one correction (§3). |
| B2 Mask in the batch: commit to a random polynomial, open the combination | L5 | For FRI: ePrint 2024/1037 (used in plonkfri). For constrained codes: ePrint 2026/391, Construction 2.2 and Lemmas 2.3, 2.4 — there the combination h = g + ε·f is sent in clear (not succinct) | overview | Partly. Running WHIR on the masked combination instead of sending it is the natural succinct form, but it is not the statement of Lemma 2.4; the paper's succinct protocols (Thms 1, 2) use a different, finer mechanism. |
| B3 Zero-knowledge sumcheck: add ρ·(random polynomial) to the summand | L3 | Libra, ePrint 2019/317, cited as HyperPlonk Lemma A.2; ePrint 2026/391 §2.5, §6 (masks encoded with a ZK code, "committed sumcheck relation") | statements / overview | Needs a hiding commitment to the mask and an opening that reveals one value of it. |
| B4 Masking the opened values: f* = f + X_ℓ(1 − X_ℓ)·R(X_ℓ) | L1, L2 | HyperPlonk App. A.2 (Lemma A.1), A.4 (Thm A.3), A.5 | read | No, not directly: f* is not multilinear, and A.5 obtains the commitment from an additive, "spanning" scheme (KZG, FRI) via another paper's transformation. WHIR commits to multilinear polynomials. |
| B5 Not revealing the values at all: claims about committed values | L1, L2 | ePrint 2026/391 §2.4 (targets hidden by encoded masks), Thm 1, Cor. 3 | overview | Covers linear constraints on one committed word and an R1CS reduction. It does not cover a PLONK-type PIOP whose final check multiplies opened values (gate, product tree). |

Conclusion: every leak has a known remedy, but no source covers their combination for HyperPlonk over WHIR. A complete design is a new composition whose proof would be ours.

## 3. A finding that constrains B1

Our padding puts the extra variable first: W(Y, X) = (1 − Y)·w(X). The first variable is the lowest power in the univariate form, so the codeword is F(x) = (1 − x)·A(x²) + x·B(x²), with A the encoding polynomial of w and B that of the padding half. A Merkle leaf always contains x and −x, and F(x) + F(−x) = 2·A(x²): the padding half cancels. Random padding in that position hides nothing.

The randomness must sit in the highest coefficients: F(x) = A(x) + x^(2^(m−1))·R(x), i.e. padding in the last variable, F̂(X, Y) = Â(X) + Y·R̂(X). Then any set of at most 2^(m−1) distinct positions sees independent uniform values. This matches the shape of Prop. 3.19 and of the blinding in plonkfri. (Self-derived; to be turned into a test before use.)

Consequence: ṽ has μ+3 variables and no padding variable. Giving it one doubles every codeword (m = μ+4), unless ṽ is restructured.

## 4. Options

| Option | Content | Result | Cost and risk |
|---|---|---|---|
| A Full zero knowledge | B1 + B2 + B3 + a replacement for B4 (multilinear masking of opened values, or B5 extended to the gate and product checks) | HVZK proof system | Largest. Requires reading ePrint 2026/391 §5–§10 in full and designing the PIOP side ourselves. Size and prover time grow (ṽ needs a padding variable; extra mask commitments). The security argument would be new and unreviewed. |
| B Commitment layer only | B1 for W and V, B2 as a mask polynomial in the batch | L4 and L5 closed: the proof then reveals exactly the PIOP transcript (L1–L3) and nothing else about the polynomials. Not zero knowledge. | Moderate, and each step has a structural test (rank of the revealed positions, as in plonkfri's `TestRevealedValuesAreUniform`). The succinct use of B2 needs its own argument. Useful only as a first stage of A. |
| C Stop at soundness | Document the analysis above as future work | The thesis compares a zero-knowledge FRI-PLONK with a sound, non-ZK HyperPlonk + WHIR, and states precisely what ZK would require | None. |

## 5. Not yet read

- ePrint 2026/391: §4 (HVZK for reductions, composition theorem), §5 (succinct linear forms), §6 (ZK sumcheck reduction), §7–§10 (the protocols behind Thms 1 and 2), §11 (R1CS). Only §1–§2.5 and Prop. 3.19 were read.
- Libra, ePrint 2019/317: the ZK sumcheck in the original.
- The transformation cited in HyperPlonk A.5 ("Theorem 10 of [19]"), not in `resources/`.

## 6. Recommendation

Decide between A and C first; B alone has little value.

If zero knowledge is a required result of the thesis: start A with a reading-and-specification step (§5), producing a protocol description and a list of the claims that would be ours to prove, before any code. If it is not required: choose C, and use the time for the open items of THEORY §10 (unread proofs, review of our own arguments) and for prover performance.

## 7. Candidate construction

Idea: keep every committed polynomial multilinear, and obtain hiding from randomness placed where the protocol does not constrain it. Four mechanisms, one per group of leaks of §1.

| # | Mechanism | Closes | Basis |
|---|---|---|---|
| Z1 | **Random rows.** Reserve a few rows whose selectors are zero and whose slots are fixed points of σ; fill them, and the unused fourth column, with random values. Every opened value of w is then a linear function of these values. | L1 for w | Standard for PLONK-type systems (blinding rows). For multilinear polynomials the search turned up "hiding multilinear extensions" in Feneuil–Provin–Rivain, *Sum-Checking SmallWood*, ePrint 2026/2880 (preprint), which formalises random padding attributed to an earlier work [FKR26]. **Not read: the PDF could not be fetched.** Own check: experiment 2. |
| Z2 | **Unconstrained region in ṽ.** Multiply the product-check constraint by a public selector that is zero on the subtree above the unused fourth column, add the constraint "root of that subtree = 1", and fill the subtree with random values. The four opened values of ṽ become linear functions of random entries. The selector is a product of bit literals, so the verifier evaluates it itself. | L1 for ṽ | Own construction; same principle as Z1. Soundness: the subtree's leaves are all 1 in the honest tree, so fixing its root to 1 loses nothing. **To be written and tested.** |
| Z3 | **Zero-knowledge sumcheck.** For each sumcheck the prover commits to a random g(x) = c₀ + Σᵢ gᵢ(xᵢ), sends G = Σ g, receives ρ, and the sumcheck runs on f + ρ·g with claim H + ρ·G; at the end g(r) is opened. | L3 | Libra, ePrint 2019/317; HyperPlonk §A.3, Lemma A.2 (statement read). Own check: experiment 3 (exact, small field). |
| Z4 | **Hiding commitment and opening.** (a) Blinding half in the last variable of every prover polynomial: P(X, Y) = P₀(X) + Y·R(X), R uniform. (b) One more committed polynomial M, uniform, added to the batch, so the WHIR proof runs on M + Σ γ^j·f_j. (c) A random salt in every Merkle leaf of the prover's trees. (d) Evaluation points of the PIOP have Y = 0; all other points at which a prover polynomial must be evaluated (out-of-domain points, points belonging to other polynomials) have Y ≠ 0 and are covered by R. | L2, L4, L5 | (a) ePrint 2026/391 Prop. 3.19; experiment 1. (b) the mask-in-the-batch idea of ePrint 2024/1037 (FRI) and of ePrint 2026/391 Construction 2.2; for WHIR on the masked combination the argument is ours (§8). (c) BCS, ePrint 2016/116, §7.4. |

All opened values become linear forms on committed polynomials (a value of g is Σ c·rᵏ over a block of coefficients). The WHIR code already represents the weight as a sum of coef·eq(point, ·) terms, so claims that are linear combinations of point evaluations need no new mechanism.

## 8. Why the opening is simulatable (sketch, ours)

All WHIR prover messages after the batching challenge are deterministic functions of the combined polynomial h = M + Σ γ^j·f_j and of the verifier's challenges (sumcheck rounds, later oracles, out-of-domain answers, final polynomial). M is uniform and independent, so h is uniform among the polynomials with the claimed values. A simulator samples the opened values of the prover polynomials as uniform (Z1, Z2, Z4a/d), samples h uniformly subject to the resulting constraints, runs the honest WHIR prover on h, answers first-iteration queries to the secret polynomials with uniform values (Z4a) and sets M's answers to h − Σ γ^j·f_j at those positions; unopened leaves are hidden by the salts (Z4c). What makes this exact is a rank condition: the map from the random entries (random rows, free subtree, blinding halves) to everything revealed about each polynomial must have full row rank. That condition is checkable by a test on the real positions, as plonkfri does (`TestRevealedValuesAreUniform`).

The PIOP side then follows the hybrid argument of HyperPlonk Thm A.3 with "uniform because of the mask polynomial" replaced by "uniform because of random rows".

## 9. Experiments (`backend/hyperplonk/internal/zkexp`, tests only)

| # | Claim | Result |
|---|---|---|
| 1 | Blinding in the first variable leaks; in the last variable it hides | 6 Merkle leaves = 96 codeword values. Random half in the first variable: rank 48 of 96 — exactly the sums f(x) + f(−x) are unprotected. Random half in the last variable: rank 96 of 96. |
| 2 | Random rows make the four opened values of w uniform | Rank of the map random slots → (a(r), b(r), c(r), w(r')): 0 with no random slot; 3 with one random row; 4 with two random rows, or with one random row plus the free fourth column. |
| 3 | The ZK sumcheck's messages depend on f only through its sum and f(r) | Over F₇, 2 variables: for 906 pairs (f, f') with equal sum and equal value at r, across all ρ and r, the distributions of the transcript over all 343 masks are identical. Control: without the mask they differ. |

## 10. Assessment

A solution appears to exist without leaving multilinear polynomials. What is sourced: Z3, Z4a, Z4c, and (pending reading) Z1. What would be ours to prove: Z2, the simulation argument of §8, the rank conditions, and the composition of all four — plus the soundness of the modified product check.

Cost estimate (not measured): ṽ needs a blinding variable, so all polynomials move from μ+3 to μ+4 variables, and M is a fifth polynomial: roughly 2.5× the current encoding work, i.e. a prover around 2.5× slower than now and than plonkfri; proof size grows by one more tree in the first iteration, the salts and a few more rounds. Circuits need two spare rows and a minimum size so that the blinding half (2^(μ+3) values) exceeds the number of revealed values (about 2,500 in unique decoding): μ ≥ 9.

To read before a specification: ePrint 2026/2880 (hiding multilinear extensions, and how that paper treats the sumcheck and the commitment), the work it cites as [FKR26], ePrint 2026/391 §4–§10, and Libra's ZK sumcheck in the original. The first two are not in `resources/`; ePrint refuses automated downloads.

## 11. A published framework that covers the composition

Source: Feneuil, Provin, Rivain, *Sum-Checking SmallWood: Smaller Hash-Based Zero-Knowledge Arguments*, ePrint 2026/2880 (preprint), now `resources/2026-2880.pdf`. Read: §3 intro, §3.1, §4.1 (Compiler 2 and Thm 3), §5.1 to Lemma 2, Remarks 11, 14. Not read: §3.2, §4.2–4.3, §5.2–5.3, the appendices with the proofs.

What it provides, and how our candidate (§7) maps onto it:

| Paper | Statement (as read) | Our candidate |
|---|---|---|
| Hiding multilinear extension, Def. 12 | Extend the witness w by a uniform mask m at chosen positions M and take the multilinear extension of (w, m). A point r is hiding if the coefficients χ_x(r), x ∈ M, span the field; then the value at r is uniform. Random padding is attributed to Florentz Konopnicki and Rothblum, CRYPTO 2026 ([FKR26]; not in `resources/`). | Z1 (random rows). Over one large field, a single non-zero coefficient hides one value; several values need the rank condition of experiment 2, which is the same spanning argument for several points. |
| Footnote 2 of §4.1 | The mask coordinates are "nullified": every sum over the hypercube carries a public factor vanishing on the mask positions, so they are unconstrained and only enter the final evaluation. | Exactly Z1 (zero selectors on the random rows) and Z2 (public selector on the random region). So Z2's principle is published; its instance for the product tree remains ours. |
| "Commit, blindly interact, prove" (§3) | The prover commits to the witness and to a random pad t; every prover message mᵢ of the sumcheck-based protocol is sent as mᵢ + tᵢ; the verifier's checks become constraints on (w, t): evaluation constraints w̃(r) = ψ(t) with ψ affine, and "trace constraints" f(t) = 0 of the degree of the original check. A single sumcheck gives no trace constraint: all its checks are affine in the messages. GKR gives one per layer. Masking preserves round-by-round soundness (their Lemma 3). | An alternative to Z3 (Libra mask). The pad makes the transcript uniform by a one-time-pad argument; the price is linear constraints on t to be proven by the commitment. |
| Compiler 1, Thm 2 | Sumcheck-based IP + zero-knowledge linear commitment scheme (proves linear constraints on a committed vector) ⇒ HVZK argument with round-by-round knowledge soundness. | WHIR proves sums Σ_b f̂(b)·W(b) = σ for any weight W, i.e. linear constraints on the committed table: it is a linear commitment scheme. Its zero-knowledge version is Z4 (our argument) or ePrint 2026/391 Thm 1. |
| Compiler 2, Thm 3 | The same with the witness in a ZK multilinear commitment and its evaluation revealed in clear, made safe by the hiding extension: ε_zk = ε_zk(lcs) + ε_zk(mpcs) + ε_hid; round-by-round error max of the parts and 2^m/\|K\|. | The structure of §7: reveal opened values of w, keep the rest padded. |

Consequence: the composition is no longer ours to invent. Thm 2 / Thm 3 give it, provided (a) our interactive protocol fits their Definition 11 (a public-coin protocol whose residual checks are evaluation checks on linear images of one committed witness plus polynomial checks on the messages), and (b) WHIR with Z4 is a zero-knowledge linear commitment scheme in their sense.

### Where our protocol does not fit yet

Their Definition 11 has one committed witness, fixed before the interaction. Our PIOP commits to ṽ after the challenges β, γ. Two ways out:

| Route | Change | Sourced? | Effect |
|---|---|---|---|
| R1 Remove ṽ | Prove the two grand products Π(γ + s_id + β·w) and Π(γ + s_σ + β·w) with a layered sumcheck over the product tree (GKR), instead of committing to the tree. The only committed prover polynomial is w. | GKR: Thaler §4.6 (in `resources/`, not yet read for this); grand products by layered sumcheck are the baseline Quarks improves on (ePrint 2020/1275 §5); LogUp-GKR, ePrint 2023/1284, in `resources/`. In the masked protocol each layer yields one degree-2 trace constraint, handled by the paper's linearization (§3.2, not read). | Fits Definition 11 exactly. Also useful without ZK: one polynomial and one Merkle tree fewer (first-iteration openings shrink by roughly a quarter), no division (observation O4 disappears), no doubling for a blinding variable of ṽ. Cost: about μ² more sumcheck rounds in the proof (tens of KiB), and a rewrite of the wiring argument. |
| R2 Keep ṽ | Treat ṽ as a second committed witness with its own random region (Z2). | No: needs an extension of Thm 2/3 to commitments made during the interaction. | Smaller code change; a new argument of ours. |

## 12. Proposed plan

Recommendation: R1. It replaces a construction of ours by published ones and improves the non-ZK system on the way.

| Stage | Content | Result | Check |
|---|---|---|---|
| S0 | Wiring identity by GKR grand products; remove ṽ from the PIOP and the commitment. Not zero-knowledge yet. | A sound system with only w committed; pure sumcheck-based protocol. | Existing suite and cheaters; round-by-round argument rewritten; measured against the current numbers. |
| S1 | Hiding extension of w: random rows and fourth column, with a test of the spanning (rank) condition on the points actually opened. | Opened values of w are uniform. | Rank test on real proofs, as plonkfri's `TestRevealedValuesAreUniform`. |
| S2 | Commit a pad t together with w; send every prover message masked; express the verifier's checks as linear constraints on t (with the paper's linearization for the per-layer products). | The interactive transcript is uniform. | Exact small-field distribution test, as experiment 3; soundness tests unchanged. |
| S3 | Zero-knowledge WHIR for linear constraints: blinding half in the last variable, mask polynomial in the batch, salted leaves. | L2, L4, L5 closed; with S1–S2 the system is HVZK by Thm 2 of ePrint 2026/2880. | Rank test over all revealed positions; written simulation argument (§8), or adoption of ePrint 2026/391 Thm 1 after reading its §4–§10. |

Still ours after this plan: that WHIR with S3 meets the paper's definition of a zero-knowledge linear commitment scheme; that our protocol meets Definition 11 (selectors and s_σ are public polynomials opened from a fixed commitment). To read before S0: Thaler §4.6. Before S2: ePrint 2026/2880 §3.2, Appendix C. Before S3: its Definitions 4–9 and ePrint 2026/391 §4–§10.

## 13. Stage S3 as built

Reading of ePrint 2026/391 before the decision: §2.2, §2.5 (overview of the ZK sumcheck reduction), Def. 3.16 (ZK encoding), Prop. 3.19, §7 (Thm 7.1, Construction 7.2, Lemma 7.3 with its simulator). Not read: §4–§6, §8–§11, and the proofs of §7.2.

Two constructions are in that paper:

- The efficient one (Thms 1, 2; "o(1) overhead"): interleaved codes, masks for each sumcheck round in a second small code, zero-knowledge code switching. Adopting it means rewriting our WHIR in that structure.
- The simple one (Construction 7.2, Thm 7.1; "2× overhead"): the prover commits to a random codeword g of the same size, the verifier sends γ, the prover sends f* = g + γ·f **in clear**, and the verifier spot-checks f* against the two committed words at t positions. HVZK by Lemma 7.3 if the encoding of f is t-query zero-knowledge.

Decision: the simple one, with one change. Instead of sending f* and spot-checking it, the WHIR protocol is run on the virtual word g + γ·f (our batching already combines committed words with powers of a challenge; the mask is one more word in the batch).

Why this keeps zero knowledge (our argument, short): every message of WHIR after the batching challenge is a function of f* and of the verifier's coins, and the only positions of f and g that are read are those of the first-iteration leaves. So the verifier's view is a function of the view in Construction 7.2 with those leaves as spot-check positions; the simulator of Lemma 7.3, followed by an honest WHIR run on its f*, simulates it. Soundness is unaffected by the mask: it is one more committed polynomial in the batched test of WHIR Thm 7.5.

What was built:

| Part | Code | Check |
|---|---|---|
| Blinding half of W in the last variable: real values at even table positions, uniform values at odd positions | `bn254.blind` | `TestBlindAndSalt`; rank on real positions: `whir.TestBlindedWordStaysHidden` (387 revealed values, rank 387) |
| Mask polynomial M, committed inside the opening with salted leaves and its own out-of-domain point; its values on all forms are sent | `whir.OpenBatch`, `Proof.MaskRoot/MaskValues/MaskOOD` | `whir.TestOpeningDependsOnlyOnTheMaskedCombination`: two different polynomials with compensating masks give identical messages in all later iterations |
| Salted leaves for the prover's trees | `whir.CommitSalted` | `whir.TestSaltedLeaves` |
| Evaluation points of w have last coordinate 0; every other point at which W is evaluated has a non-zero last coordinate and is covered by the blinding | `bn254.statement` | `bn254.TestRevealedValuesOfWAreUniform`: 11 values of W on forms, rank 11, both regimes |
| Minimum size so that the blinding half exceeds the opened codeword values: 2^10 rows in unique decoding (4096 against 2480), 2^9 at Johnson (2048 against 1440) | `bn254.minRows` | same test |
| One source of prover randomness | `internal/rnd` | fuzz fixture reproducible |

## 14. What the zero-knowledge claim rests

Claim: the proof system is honest-verifier zero-knowledge in the interactive setting, hence zero-knowledge after Fiat–Shamir in the random-oracle model (BCS §7.4 for the salted trees). It has **not** been proven as one theorem, and nobody has reviewed it.

| Leak of §1 | Closed by | Basis | Evidence here |
|---|---|---|---|
| L1 opened values of w | random rows and fourth column (S1) | ePrint 2026/2880 Def. 12, §4.1 footnote 2 | rank tests on real proofs |
| L2 out-of-domain values | blinding half (S3) | ePrint 2026/391 Prop. 3.19 | rank tests |
| L3 sumcheck messages | pad (S2) | ePrint 2026/2880 §3 | message = message + pad under fixed challenges |
| L4 opened codeword values | blinding half and salts (S3) | ePrint 2026/391 Prop. 3.19; BCS §7.4 | rank test on opened leaves |
| L5 WHIR messages | mask polynomial (S3) | ePrint 2026/391 Construction 7.2, Lemma 7.3 + our reduction above | dependence only on the masked combination |

Ours, and unreviewed:

1. The reduction from "WHIR on g + γ·f" to Construction 7.2 (§13).
2. That the pieces compose: matched against the definitions of ePrint 2026/2880 in §15.3; three differences from the statement of Thm 3 remain (merged commitment, preprocessed polynomials, values revealed beyond the statement).
3. Joint uniformity across layers: checked at full size by `TestJointRank` (§15.1) for four proofs.
4. The probability that the verifier's points give a rank-deficient set: bounded in §15.2 except for one step (group G), which is conditional on a non-degeneracy that the tests certify only for the opened positions of the tested proofs.
5. The salts make unopened leaves hiding in the random-oracle model; BCS's statement was not re-read for our tree layout.

Not zero-knowledge against a malicious verifier in the interactive protocol; this is the usual situation and Fiat–Shamir removes the interaction.

## 15. Strengthening the claim

### 15.1 Joint rank test at full size

`bn254.TestJointRank` (run with `HP_JOINT_RANK=1`; 43 s on the laptop, elimination in parallel). For one real proof it takes every value that is a linear function of W — the codeword values in all opened first-iteration leaves, W on the 11 forms other than the merged pad constraint, and W at the mask's out-of-domain point — and computes the rank over all random entries of W.

| Regime | Rows | Distinct leaves | Codeword values | Evaluations | Random entries | Rank |
|---|---|---|---|---|---|---|
| Johnson | 2^9 | 89 | 1424 | 12 | 3792 | 1436 of 1436 |
| Johnson | 2^9 | 87 | 1392 | 12 | 3792 | 1404 of 1404 |
| Unique decoding | 2^10 | 153 | 2448 | 12 | 7843 | 2460 of 2460 |
| Unique decoding | 2^10 | 153 | 2448 | 12 | 7843 | 2460 of 2460 |

Four proofs, full rank each time. This closes item 3 of §14 as far as a test can: for these proofs everything revealed about W is jointly uniform.

### 15.2 Probability that the rank is deficient

Notation: m = μ + 3 variables of W; N' = 2^(m−1) blinding values, the table of a polynomial R in m − 1 variables, so that W(X, Y) = A(X) + Y·R(X) with A the table of w. X is the set of opened domain points, k = |X| ≤ t₀·2^k. The rows fall into four groups:

| Group | Rows | Depends on the blinding half? |
|---|---|---|
| C | codeword values at the k points of X | yes: A_uni(x) + x^N'·R_uni(x) |
| O | the out-of-domain points of w and of the mask, pow(z_w), pow(z_M) | yes, same form |
| G | six points with non-zero last coordinate: W at the five selector points and at the point of s_σ | yes: A(z') + y·R(z') |
| P | the four values the PIOP opens, last coordinate 0: a(r), b(r), c(r), w(q) | no |

The matrix is block triangular: rows of P vanish on the blinding columns. So the rank is full iff (i) the rows of C ∪ O ∪ G are independent on the blinding columns, and (ii) the rows of P are independent on the random slots of w.

| Step | Statement | Probability of failure | Status |
|---|---|---|---|
| C | Restricted to the blinding columns a row of C is x^N' times the Vandermonde row (1, x, …, x^(N'−1)) in the monomial basis of R. Distinct non-zero points give independent rows as long as k ≤ N'. | 0, given k ≤ N' (enforced by `minRows`) | proven (Vandermonde) |
| O | The two out-of-domain rows are Vandermonde rows at z_w, z_M. Independent of C and of each other unless z_w or z_M lies in X ∪ {0} or z_w = z_M; needs k + 2 ≤ N'. | ≤ (2k + 3)/\|F\| | proven |
| P | a(r), b(r), c(r) live on different columns, and each has a random row i₀ with coefficient eq(i₀, r), non-zero unless a coordinate of r takes one particular value. w(q) has a non-zero coefficient on a free slot of the fourth column, where the other three vanish, unless a coordinate of q takes one particular value. | ≤ (2μ + 2)/\|F\| | proven (needs one random row and one free fourth-column slot: `MinRandomRows`, `MinHidingSlots`) |
| G | The six rows must be independent modulo the span of C ∪ O. For fixed X, z_w, z_M this is the non-vanishing of some 6 × 6 minor, a polynomial in the coordinates of r and q of total degree ≤ 6μ − 4 (five rows depend on r₁..r_{μ−1}, one on q₁..q_{μ+1}); in addition the two last coordinates r_μ, q_{μ+2} must be non-zero. If the polynomial is not identically zero, Schwartz–Zippel applies. | ≤ (6μ − 2)/\|F\|, **if** the minor is not identically zero for the given X | conditional |

Under that condition the total is at most (2k + 8μ + 3)/|F|, about 2⁻²⁴¹ for k = 2480 and μ = 20.

The condition on G is not proven for every set X of opened positions. What we have: a passing rank test at one choice of challenges exhibits a non-zero minor, hence proves that the polynomial is not identically zero for that X; this happened for the four proofs above and for the proof of `whir.TestBlindedWordStaysHidden`. A proof for all X would have to show that the multiples of the vanishing polynomial of X, of degree below N', are not degenerate with respect to the six evaluation maps; we have not found a short argument. This replaces item 4 of §14 by a narrower open point.

### 15.3 Our construction against the definitions of ePrint 2026/2880

Read: Defs 1–7 and the description of Def. 9 (§2.3), Def. 10–11 (§3.1), Compilers 1 and 2 with Thms 2, 3 (§4.1). Not read: the proofs (Appendix D), Defs 8–9 in full.

| Their notion | What it requires | What we have | Match? |
|---|---|---|---|
| Commit-and-prove system (Def. 1) | Commit on the witness, then Prove on a statement fixed afterwards | `CommitSalted(blind(w))` during the PIOP, `OpenBatch` at the end | yes; our Commit is non-interactive |
| Linear commitment scheme (Def. 5) | proves ⟨a, w⟩ = b for a committed vector w and public (a, b); extension to several queries "easy" | W's even positions are the vector (wires, random slots, pad); the forms are the vectors a (evaluation weights and the merged pad constraint); the values b are public | yes for the statement; see the two rows below |
| HVZK of a CP system (Def. 7) | a simulator, given only the statement, produces commitment and transcripts, programming the random oracle | ZK-DESIGN §13: simulator of ePrint 2026/391 Lemma 7.3 followed by an honest WHIR run on the simulated combination | partly: our argument is at the level of the interactive oracle protocol and relies on BCS for the oracle model; we have not written it in the programmable-oracle form of Def. 7 |
| — | the transcript may reveal only what follows from the statement | our opening also reveals W on forms that are not part of its statement (the forms of the other polynomials and the two out-of-domain points) | extra: these values must be simulated as uniform, which is the rank condition of §15.1–15.2, with its failure probability as additional error |
| Sumcheck-based interactive proof (Def. 11) | one committed witness; residual checks are evaluation checks on linear images of the witness and polynomial checks on the messages | our PIOP after stage S0 | yes, except that the selectors and s_σ are public polynomials the verifier does not evaluate itself: they are opened from the setup commitment in the same batch (THEORY S15). The definition has no preprocessing. |
| Compiler 1 (Thm 2) | all evaluation claims stay hidden as constraints on (w, t), proven by the LCS | — | not what we do |
| Compiler 2 (Thm 3) | the witness in an MPCS with its evaluation revealed (hiding extension), the pad in a separate LCS | we reveal the evaluations as in Compiler 2, but the witness and the pad share one commitment and one opening proof | structure of Thm 3 with the two commitments merged; the theorem is stated for separate schemes |

Result: no step contradicts the framework, and three differences remain between our construction and the statements of the theorems: (1) one commitment in the roles of both the MPCS and the LCS; (2) preprocessed polynomials; (3) values revealed beyond the statement, covered by the rank condition. Each is a place where Thm 3 does not apply verbatim and our own argument fills in.

### 15.4 After reading the proofs

Read and followed: the zero-knowledge proofs of ePrint 2026/2880 Thms 2 and 3 and its Lemma 3; the proof of ePrint 2026/391 Lemma 7.3 (THEORY §14). Consequences for §14–§15.3:

- The hybrid structure of Thm 3's proof is the one our argument uses: commitment transcript simulated from the public statement, masked messages replaced by uniform values, opened evaluation replaced by a uniform value. With one commitment instead of two, the first two hybrids merge. The extra values our opening reveals enter the first hybrid and need the rank condition.
- Lemma 7.3's simulator reads the committed word at the queried positions and nothing else of it. That is what the reduction of §13 needs, and why the word itself must be blinded.
- ePrint 2019/834 Thm 8.6 states that BCS preserves honest-verifier zero knowledge as statistical zero knowledge. This is the published link from our interactive argument to the non-interactive proof (statement read, proof not).
