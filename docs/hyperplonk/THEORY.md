# Theory ledger

Status tags (README): S = statement read, P = proof read, T = tested here, R = recalled, not re-checked.
All S entries below were read from the PDFs in `resources/`. Entries marked P or T name the proof read or the test.

## 1. Structure of the argument

The security argument has four layers. Each layer has one main theorem.

| Layer | What it gives | Main source |
|---|---|---|
| L1 PIOP | The circuit is satisfied, assuming the verifier can evaluate committed multilinear polynomials | HyperPlonk, ePrint 2022/1355, Thm 4.1 |
| L2 PCS | Committed words are (close to) multilinear polynomials with the claimed evaluations | WHIR, ePrint 2024/1586, Thm 5.2 |
| L3 Composition | L1 + L2 give one IOP with round-by-round knowledge soundness | WHIR Thm 7.5 |
| L4 Non-interactive | Merkle trees + Fiat–Shamir give an argument in the random-oracle model | BCS, ePrint 2016/116; bound from ePrint 2023/1071 |

Soundness of the whole is limited by the weakest term. For bn254 the L1 terms are near 2⁻²³³ (§5), so the security level is set by L2 (query count) and L4 (hash).

## 2. L1 — HyperPlonk PIOP (ePrint 2022/1355)

Notation of the paper: F_μ^(≤d) = μ-variate polynomials of individual degree ≤ d; [[f]] = oracle to f.

| ID | Claim | Source | Status |
|---|---|---|---|
| H1 | Every f : B_μ → F has a unique multilinear extension. | Lemma 2.1 | S |
| H2 | Schwartz–Zippel: a non-zero polynomial of total degree d vanishes at a random point of S^μ with probability ≤ d/\|S\|. | Lemma 2.2 | S · T for multilinear polynomials (`TestModelZerocheckChallenge`) |
| H3 | A δ-sound PIOP is knowledge sound (same error). | Lemma 2.3 | S |
| H4 | PIOP + polynomial commitment with witness-extended emulation → argument of knowledge; preserves HVZK if the commitment is hiding with ZK evaluation. | Thm 2.4 | S |
| H5 | SumCheck. Relation: Σ_{b∈B_μ} f(b) = v, f ∈ F_μ^(≤d). μ rounds; round i: prover sends r_i(X) = Σ_b f(b, X, α_{i+1}, …, α_μ) of degree ≤ d; verifier checks v = r_i(0) + r_i(1), samples α_i, sets v ← r_i(α_i); final check f(α) = v. Perfectly complete; knowledge error dμ/\|F\|. | §3.1, Thm 3.1; proof in Thaler, *Proofs, Arguments, and Zero-Knowledge*, Prop. 4.1 | P (both proofs in Thaler read) · T (`sumcheck.TestModelSumcheckSoundness`: exact optimum over all provers on F₇, F₁₁, F₁₃; `TestSumcheckCheaters`) |
| H6 | ZeroCheck. Relation: f(x) = 0 for all x ∈ B_μ. Verifier sends r ∈ F^μ; sumcheck on f(X)·eq(X, r) with claimed sum 0. Knowledge error dμ/\|F\| + δ_sum^{d+1,μ}. Two instances batch as f + α·g with additional error 1/\|F\|. | §3.2, Thm 3.2 | P (proof in the paper read) · T (`TestModelZerocheckChallenge`, `TestZerocheckCheaters`); see O1 |
| H7 | ProductCheck (from Quark). Relation: Π_{x∈B_μ} f₁(x)/f₂(x) = s, f₂ ≠ 0 on B_μ. Prover sends multilinear ṽ in μ+1 variables with ṽ(0, x) = f₁(x)/f₂(x), ṽ(1, x) = ṽ(x, 0)·ṽ(x, 1); zerocheck on both conditions; verifier checks ṽ(1, …, 1, 0) = s. Knowledge error δ_zero^{d′,μ+1}, d′ = max(2, d+1). | §3.3, Thm 3.3 | P (proof in the paper read) · T (`prodcheck.TestBuildProduct`, `TestCheaters`), with the precondition O4 |
| H8 | Multiset check (k = 1): verifier sends r; product check on (r + f)/(r + g) = 1. Knowledge error 2^μ/\|F\| + δ_prod. For k-tuples: random linear combination first, further 2^μ/\|F\|. | §3.4, Thms 3.4, 3.5 | P (both proofs read) · T (`permcheck` tests); completeness caveat O5 |
| H9 | Permutation check. Relation: g(x) = f(σ(x)) on B_μ. Indexer provides multilinear s_id (x ↦ [x] = Σ x_i·2^(i−1)) and s_σ (x ↦ [σ(x)]); multiset check on (s_id, f) versus (s_σ, g). Knowledge error δ_mset,2 = O((2^μ + dμ)/\|F\|). | §3.5, Thm 3.6 | P · T (`permcheck.TestCheaters`, `piop.TestCheaters`) |
| H10 | Batch evaluation: k claims f_i(z_i) = y_i reduce to one sumcheck Σ_i eq(t, ⟨i⟩)·(Σ_b f_i(b)·eq(b, z_i) − y_i) = 0 for random t; prover time O(k·2^μ). | §3.8, Def 3.7, eq. (10)–(11) | S (construction read to eq. (11); theorem statement not yet read) |
| H11 | HyperPlonk relation: selectors q, permutation σ, witness w multilinear; gate identity f̃ = f(q(⟨0⟩, X), …, w(⟨0⟩, X), …) vanishes on B_μ; wiring identity (σ; w, w) ∈ R_PERM; public input p(X) = w(0, …, 0, X). | Def 4.1, eq. (13) | S · T for gnark's gate (`piop.TestIndexMatchesSolver`, `TestCircuitSuite`: 31 circuits) |
| H12 | Protocol (Figure 2): (1) send [[w]]; (2) zerocheck on f̃; (3) permutation check on w; (4) verifier samples r, checks p(r) = w(⟨0⟩, r). Soundness error max{δ_zero^{d,μ}, δ_perm^{1,μ+ν_w}, ν/\|F\|} = O((2^μ + dμ)/\|F\|). | Thm 4.1, Lemma 4.3 | P (Lemma 4.3) · T (`piop` tests). Step (4) replaced by S7. |
| H13 | The two sumchecks can be batched into one by a random linear combination. | Remark 4.2 | S |
| H14 | Zero knowledge: mask f* = f + Z(X_ℓ)·R(X_ℓ), Z(X) = X(1 − X), R random of degree t − 1; t query answers are uniform if the ℓ-th coordinates of the query points are distinct and outside {0, 1}. ZK sumcheck after Libra (ePrint 2019/317): add ρ·g for a random g = c₀ + Σ g_i(x_i). | App. A.2 (Lemma A.1), A.3 (Lemma A.2) | S (A.4, A.5 not yet read) |

Alternative for the wiring identity (not used in v1, see PLAN D3):

| ID | Claim | Source | Status |
|---|---|---|---|
| G1 | For char F > n: Π(X + a_i) = Π(X + b_i) ⇔ Σ 1/(X + a_i) = Σ 1/(X + b_i). | LogUp, ePrint 2022/1530, Lemma 3 | S |
| G2 | Set inclusion {a_i} ⊆ {b_i} ⇔ multiplicities m_i exist with Σ 1/(X + a_i) = Σ m_i/(X + b_i). | Lemma 5 | S |
| G3 | Soundness of the batch-column lookup protocol: ε < ((M+1)·\|H\| − 1)/(\|F\| − \|H\|) + (K+1)/\|F\| + ε_sumcheck. | Thm 4 | S |

Self-derived claims (ours, not from a paper):

| ID | Claim | Argument | Status |
|---|---|---|---|
| S1 | A challenge obtained by reducing a uniform L-bit integer mod r takes each value with probability ≤ ⌈2^L/r⌉/2^L ≤ 1/r + 2^−L. For L = 512 the excess over uniform is a factor below 1 + 2⁻²⁵⁶; for L = 256 it is 6r/2²⁵⁶ ≈ 1.134. Every soundness bound of the form "number of bad challenges / \|F\|" is multiplied by at most this factor. | Each residue has ⌊2^L/r⌋ or ⌈2^L/r⌉ preimages. | T (`transcript.TestReductionBias`, exact integer arithmetic). We use L = 512. |
| S2 | Sumcheck is round-by-round sound with error d/\|F\| per round, for the state "current claim ≠ true partial sum Σ_b p(r₁..r_i, b)". | From Thaler's non-inductive proof: a doomed state is left in round i only if the sent s_i differs from the true polynomial and agrees with it at r_i. Thaler §5.3 attributes the general statement to Canetti et al. [CCH+19]. | P for the argument; matches the description in ePrint 2018/1004 §2.1 (S). |
| S3 | Zerocheck error ≤ μ/\|F\| + (d+1)μ/\|F\| (tighter first term than H6). | Q(Y) = Σ_b g(T(b))·eq(b, Y) is multilinear, total degree ≤ μ; H2. | T for the first term (`TestModelZerocheckChallenge`, every non-zero table over F₃, F₅, F₇); also stated in Quark, ePrint 2020/1275, §5 (S). |
| S4 | Product check as implemented: both equation families combined with a random α and one zerocheck in μ variables (instead of the paper's merge along an extra variable). Error ≤ μ/\|F\| + 3μ/\|F\| + 1/\|F\|, provided f₁, f₂ have no common zero on B_μ. | Batching: HyperPlonk §3.2 "Batching"; if a family is violated at some x, at most one α cancels it there. Then S3 with d = 2. | T (`prodcheck` tests; 5 mutations each caught) |
| S5 | In the multiset check the precondition of S4 holds outside the event already counted: with f₁ = r + f, f₂ = r + g, a common zero at x means F(r) = G(r) = 0 for F(Y) = Π(Y + f(x)), G(Y) = Π(Y + g(x)); for a false statement F ≠ G this lies inside the Schwartz–Zippel event F(r) = G(r) of probability ≤ 2^μ/\|F\| in the proof of Thm 3.4. | Reading of the proof of Thm 3.4. | P (argument) · T (`permcheck.TestModelNoCommonZeroOutsideCountedEvent`, exhaustive over F₁₃ for one false instance) |
| S6 | s_id(x) = Σᵢ xᵢ·2^(μ−i) is linear, hence its own multilinear extension (H1); the verifier evaluates it directly and it needs no commitment. | Uniqueness of the multilinear extension. | T (`permcheck.TestIdentityLabel`) |
| S7 | Public inputs through the gate identity: with PI the table (pub₀, …, pub_{ℓ−1}, 0, …) and rows i < ℓ having q_L = −1 and all other selectors 0, the zerocheck of gate + PI enforces a_i = pub_i. The verifier computes PI(r) = Σ_{i<ℓ} pub_i·eq(i, r) itself. This replaces HyperPlonk Figure 2 step 4 (and its ν/\|F\| term). Same idea as PlonK, ePrint 2019/953, §7 step 3 (there PI := Σ −x_i·L_i). | PI is public, so the zerocheck statement is about committed polynomials plus a known table. | T (`piop.TestPublicInputAt`; cheaters "false public input", "another public input") |
| S8 | The public inputs and the circuit digest must be absorbed before the first challenge. Otherwise: run the gate zerocheck with an arbitrary table PI*, obtain r, then solve the one linear equation PI_pub(r) = PI*(r) for the claimed public inputs. | Weak Fiat–Shamir, ePrint 2023/691 (status R). | T (`piop.TestStatementIsBound`); the attack itself is described, not implemented |
| S9 | The gate identity and the wiring identity run as two sequential sub-protocols on the same committed w; the error is at most the sum of both (union bound). HyperPlonk's batching into one sumcheck (Remark 4.2) is not used: the two sumchecks here have μ and μ+2 variables. | Union bound. | — |
| S10 | In unique decoding δ = (1 − ρ)/2 is admissible: Lemma 4.10 needs δ < δ_C/2 with δ_C the relative minimum distance, and for Reed–Solomon δ_C = 1 − ρ + 1/\|L\| > 1 − ρ. At this δ the list size is 1. | Minimum distance of RS codes (MDS). | Used in `whir.Params.delta`; T via the error table |
| S11 | The shift and final queries may be sampled with replacement, whatever the number of leaves: the bound (1 − δ)^t in the proof of Thm 5.2 is the probability that t independent positions all miss a set of density δ. The ingredient "t_i ≤ \|L_i\|" of Construction 5.1 is not used by that bound. | Proof of Thm 5.2, item 3 (read). | — |
| S12 | For linear weights ŵ = Z·W(X) with W multilinear, the final check Σ_b W(α, b)·f̂_M(b) = claim is computed term by term: each term coef·eq(point, ·) of W contributes coef·eq(head, α')·f̂_M(tail), since Σ_b eq(tail, b)·f̂_M(b) = f̂_M(tail). | Definition of the multilinear extension. | T (`whir.TestComplete`; mutations 3, 4, 5, 10) |
| S13 | The preprocessed polynomials (selectors, s_σ) need no out-of-domain sample: they are encoded by the setup, so the committed word is an exact codeword u, and any other codeword is at distance ≥ 1 − ρ from it, which exceeds δ in both regimes (δ ≤ 1 − √ρ < 1 − ρ). The list around u is {u}. Same argument as plonkfri decision D9. | Minimum distance. | — (the setup is trusted to be the honest encoding; the verifying key can be recomputed from the circuit) |
| S14 | Padding and stacking. Construction 7.4 needs all polynomials in the same number m of variables. A PIOP polynomial p in fewer variables is realised as a restriction of a committed m-variate polynomial P: p(X) := P(c, X) for a fixed bit string c (c = 0 for padding; c = ⟨j⟩ for the j-th stacked selector). The PIOP's soundness is about p; every claim p(z) = v is the claim P(c, z) = v. Nothing needs to be proven about P elsewhere. The honest prover fills the rest with zeros. Out-of-domain points are taken in all m variables, pow(z, m), as Lemma 4.25 requires. | A restriction of a multilinear polynomial is a multilinear polynomial; cf. HyperPlonk Remark 3.2, which WHIR §7.2 cites for this. | T (`bn254` tests; mutations 3, 4, 5) |
| S15 | Preprocessed polynomials inside Construction 7.4. The construction has no indexer ("we do not consider holography"); we treat Q and S as messages of a round 0 whose content is fixed by the verifying key. Thm 7.5 holds for any prover messages, in particular these; the PIOP's indexed soundness applies because the round-0 words are exact codewords (S13), so every element of the interleaved list has exactly the indexed polynomials in those two components. | S13 + Lemma 4.4. | — (argument only) |
| S16 | Our transcript against BCS §6. Same structure: a hash chain over the prover's messages, each challenge a hash of the current chain value under a separate prefix. Differences: (1) the statement enters the chain once at the start (verifying-key digest, public inputs) instead of being an input of every call; (2) each challenge is absorbed back into the chain; (3) short prover messages (sumcheck polynomials, values, final polynomial) are absorbed directly rather than through a Merkle root; (4) one verifier message may consist of several challenges, drawn one after the other; (5) challenges are 512 bits reduced mod r (S1) and query positions are low bits of a challenge; (6) the final chain value is not sent. | (1)–(4), (6) do not remove any dependency of a challenge on earlier messages (tested: `transcript`, `TestClaimIsBound`, `TestStatementIsBound` ×2, `TestDigestCoversTheKey`); (5) costs the factor of S1. **Not proven:** that Thm 7.1 carries over to these differences; we treat it as a standard variant, not as a theorem. | T for the dependencies only |
| S17 | Grand-product equality by layered sumcheck (`grandprod`), used in place of the committed product polynomial. Layer identity V_i(z) = Σ_x eq(z, x)·V_{i+1}(x, 0)·V_{i+1}(x, 1); two claims on V_{i+1} at (r, 0), (r, 1) reduce to one at (r, t) because V_{i+1}(r, T) is linear in T; two tables are combined with a fresh λ per layer. Error per layer i: 1/\|F\| (λ) + 3i/\|F\| (sumcheck) + 1/\|F\| (t). | GKR: Thaler §4.6.4–4.6.5 (protocol read; soundness stated as O(d·log S/\|F\|)); the identity and the line step are immediate from multilinearity. | T (`grandprod.TestLayerIdentity`, `TestCheaters`; 5 mutations caught after adding the "false right child" cheater) |
| S18 | Masked protocol (stage S2). The prover commits to a pad t (the first τ slots of the fourth column of w) and sends every witness-dependent message as m + t_i; the verifier computes affine maps of t and ends with linear constraints and, per layer of the wiring argument, two products of masked values. The products are reduced to two linear constraints by interpolation and a masked quotient; error ≤ (2m − 1)/(\|F\| − m) for m products. All linear constraints are merged with powers of a challenge ρ (error ≤ (k − 1)/\|F\| for k constraints) into one linear form on W, proven by the batched opening. Masking is a bijection for a fixed pad, so the round-by-round soundness of §12 carries over. | ePrint 2026/2880 §3 (definition of the paradigm, Fig. 5), §3.2 (linearization; read), Lemma 3 (statement only). The merge is Schwartz–Zippel in ρ. | T: `cbip` tests (masked rounds agree with the sumcheck; messages = message + pad under fixed challenges; linearization honest, false product, free choice of v); `piop.TestMessagesAreOneTimePadded`; `piop.TestCheaters` with five prover deviations that each violate a single constraint; 10 mutations of the constraint set all caught |
| S19 | Zero-knowledge opening (stage S3): WHIR run on the combination of the committed words and a committed uniform mask is simulatable from the simulator of ePrint 2026/391 Lemma 7.3, because every later message is a function of the combination. Blinding in the last variable makes any 2^(m−1) codeword positions uniform. | ePrint 2026/391 Construction 7.2, Thm 7.1, Lemma 7.3, Prop. 3.19 (statements and the simulator read); the reduction is ours (ZK-DESIGN.md §13). | T: `whir.TestOpeningDependsOnlyOnTheMaskedCombination`, `TestBlindedWordStaysHidden`, `TestSaltedLeaves`; `bn254.TestRevealedValuesOfWAreUniform`, `TestBlindAndSalt` |

## 3. L2 — WHIR (ePrint 2024/1586)

| ID | Claim | Source | Status |
|---|---|---|---|
| W1 | Smooth Reed–Solomon code: L a multiplicative coset of order a power of two, degree bound 2^m. RS[F, L, m] = { f : L → F : f(x) = f̂(x, x², x⁴, …, x^(2^(m−1))) for a multilinear f̂ }. Rate ρ = 2^m/\|L\|. | Def 4.2 | S · T (`whir.TestEncode`) |
| W2 | Constrained RS code: CRS[F, L, m, ŵ, σ] = { f ∈ RS[F, L, m] : Σ_{b∈B_m} ŵ(f̂(b), b) = σ }. An evaluation claim f̂(z) = σ is the weight ŵ(Z, X) = Z·eq(X, z). Several constraints: intersection. | Def 1, Defs 4.5, 4.6, §1.1 | S |
| W3 | Univariate evaluation at r is the weight Z·eq(pow(r, m), ·), pow(r, m) = (r, r², …, r^(2^(m−1))). | Remark 7.3 | S |
| W4 | Johnson bound: RS[F, L, m] is (1 − √ρ − η, 1/(2η√ρ))-list decodable for η ∈ (0, 1 − √ρ). The same holds for interleaved RS codes. | Thm 4.3, Lemma 4.4 | S |
| W5 | Mutual correlated agreement (MCA), definition: except with probability err*(C, ℓ, δ) over the combination coefficients, every large agreement set of the combined word with the code is an agreement set of all individual words. | Def 4.9 | S |
| W6 | MCA holds in the unique-decoding range: for RS with Gen(ℓ; α) = (1, α, …, α^(ℓ−1)), bound B* = (1+ρ)/2 (i.e. δ < (1−ρ)/2), error (ℓ−1)·2^m/(ρ·\|F\|). Proven in the paper. | Lemma 4.10, Cor 4.11 | S |
| W7 | MCA up to the Johnson bound (B* = √ρ) with error (ℓ−1)·2^(2m) / (\|F\|·(2·min{1 − √ρ − δ, √ρ/20})⁷), and up to capacity: conjectured in the WHIR paper. | Conj 4.12 items 1, 2 | S — see A1, A2 in §4 |
| W8 | Folding: Fold(f, α)(x²) = (f(x) + f(−x))/2 + α·(f(x) − f(−x))/(2x). If f ∈ RS[F, L, m] then Fold(f, α) ∈ RS[F, L^(2^k), m − k] with multilinear extension f̂(α, X_{k+1}, …, X_m). | Def 4.14, Claim 4.15 | P (proof of Claim 4.15 read in part) · T (`whir.TestFoldLeaf`) |
| W9 | Folding preserves list decoding: with MCA, Pr_α[Fold(Λ(C, f, δ), α) ≠ Λ(C^(k), Fold(f, α), δ)] < Σ_{i≤k} err*(C^(i), 2, δ). | Thm 4.20, Lemma 4.21, Claims 4.22, 4.23 | P (read and followed). Note: the distance in the list is the block distance of Def. 4.17 (fraction of cosets, i.e. of Merkle leaves, on which the words differ), which is what one query samples. |
| W10 | The WHIR protocol: initial k₀ sumcheck rounds; then for i = 1..M−1: prover sends f_i on L_i (honest: f̂_i = f̂_{i−1}(α_{i−1}, ·)); out-of-domain point z_{i,0} ← F and reply y_{i,0}; shift queries z_{i,1..t_{i−1}} ← L_{i−1}^(2^k) and γ_i; k_i sumcheck rounds for the updated weight ŵ_i = ŵ_{i−1}(Z, α_{i−1}, X) + Z·Σ_j γ_i^(j+1)·eq(z_{i,j}, X); final polynomial f̂_M sent in clear and checked at t_{M−1} points and against the last sumcheck claim. | Construction 5.1 | S · T (`whir.TestComplete`, `TestCheaters`; 10 mutations caught). O2 resolved. |
| W11 | Round-by-round soundness of W10, given MCA for the codes involved and (ℓ_{i,s}, δ_i)-list decodability: ε_fold(0,s) ≤ d*·ℓ_{0,s−1}/\|F\| + err*(C^(0,s), 2, δ₀); ε_out(i) ≤ 2^(m_i)·ℓ_{i,0}²/(2\|F\|); ε_shift(i) ≤ (1 − δ_{i−1})^(t_{i−1}) + ℓ_{i,0}·(t_{i−1}+1)/\|F\|; ε_fold(i,s) ≤ d·ℓ_{i,s−1}/\|F\| + err*(C^(i,s), 2, δ_i); ε_fin ≤ (1 − δ_{M−1})^(t_{M−1}). d* = 1 + deg_Z ŵ₀ + max_i deg_{X_i} ŵ₀, d = max{d*, 3}. | Thm 5.2 | P for the state function and the out-of-domain, shift and final bounds; the fold bound (Claim 5.3, Thm 4.20) only S. T: every term evaluated for bn254 in `whir.Params.Errors` (`TestAllErrorTermsBelowTarget`, m = 0..24, both regimes). |
| W12 | An IOPP for one constraint extends to several constraints (random combination). | §5.2, Construction 5.5, Thm 5.6 | S (construction and theorem read; error (t−1)·ℓ/\|F\|) · T (several claims in `whir.TestComplete`) |
| W13 | Parameter regimes of the paper: UD δ = (1−ρ)/2; JB δ = 1 − √ρ − η with η = √ρ/20 (assumes Conj 4.12 item 1); CB δ = 1 − ρ − η (assumes item 2). Folding parameter k = 4. Hash output 256 bits. Proof-of-work is used to reach the target in the query and proximity-gap rounds. | §6.2 | S |
| W14 | The reference implementation supports only weights Z·eq(z_i, ·) (evaluation claims). | §6.1 | S |

## 4. Assumptions and their state

| ID | Statement | Source | Status |
|---|---|---|---|
| A1 | MCA for RS codes up to the Johnson bound is proven for the line f₀ + z·f₁: for γ = 1 − (1 + 1/(2m))·√ρ, integer m ≥ 3, the exceptional set has size ≤ (ℓ⁷/3)·(ρn)², ℓ = (m + 1/2)/√ρ. | Haböck, ePrint 2025/2110, Thm 2 | S. The abstract says the note "outlines" the proof; preprint, November 2025. |
| A2 | MCA for RS codes and every polynomial generator, same radius, error (1/\|F\|)·((m+1/2)⁷/(3ρ^(3/2)))·d·n². | Bordage–Chiesa–Guan–Manzur, ePrint 2025/2051, Def 9.1, Thm 9.2, Lemma 9.3 | S. Preprint. |
| A3 | The up-to-capacity conjectures (W7 item 2) were disproved over large fields. | ePrint 2025/2046, 2025/2055 | R (recorded; not re-read) |
| A4 | Soundness of the compiled argument: s̄_sr(x, m) + 3(m² + 1)·2^−λ for a prover making m random-oracle queries, λ the oracle's output length, s̄_sr the restricted state-restoration soundness of the IOP. | BCS, ePrint 2016/116, Thm 7.1 | S (statement read; proof not read) |
| A4b | s̄_sr(b) ≤ b·ε_rbr, giving Q·ε_rbr + 3(Q² + 1)/2^κ; quantum: O(t²·ε + t³/2^λ). | ePrint 2023/1071 §2.1 (citing [CMS19, COS20, KPV22]), Thm 3.15; ePrint 2019/834, Thm 3 (informal) and Thm 8.6 | S for 2019/834 Thm 3 (informal statement and proof sketch read); the classical inequality is R |
| A5 | BCS transformation T: σ₀ := ρ₂(x); for each round, verifier message m_i := ρ₁(x ‖ σ_{i−1}), prover oracle f_i, Merkle root rt_i, σ_i := ρ₂(rt_i ‖ σ_{i−1}); final verifier randomness ρ₁(x ‖ σ_k); the proof holds the roots and one authentication path per query. | ePrint 2016/116, §6 | S (construction read) |

Consequence for WHIR's theorem W11: it needs err*(C, 2, δ) only, i.e. MCA for a combination of two words. That is exactly the case A1 states. So the Johnson regime no longer rests on Conjecture 4.12 item 1, but on two preprints whose proofs we have not read. The unique-decoding regime (W6) is proven inside the WHIR paper itself.

## 5. L3 and L4 — composition

| ID | Claim | Source | Status |
|---|---|---|---|
| C1 | Compiler: for each polynomial the PIOP prover sends, send its RS encoding; the verifier sends an out-of-domain point z, the prover answers y = f̂(pow(z)); the PIOP's queries become constraints; one (multi-)constrained proximity test per oracle checks f ∈ CRS[F, L, m, (Z·eq(pow(z), ·), y), (ŵ₁, σ₁), …]. The out-of-domain answer forces a single polynomial out of the list. | WHIR §2.2 | S · T (`backend/hyperplonk/bn254` tests: 31 circuits end to end, 38 tampered proofs rejected). Implemented in this per-polynomial form. |
| C2 | Round-by-round knowledge soundness of the compiled IOP (single proximity test, linear queries): ε_out ≤ s_i·2^m·ℓ²/(2\|F\|); ε_piop ≤ the PIOP's error; ε_com ≤ err*(C, s_poly, δ) + (s_poly − 1)·ℓ^(s_poly)/\|F\|; ε_prx ≤ the IOPP's error. | WHIR Construction 7.4, Thm 7.5 | S (construction read in full; proof of Thm 7.5 not read) · T (`whir.TestBatchComplete`, `TestBatchCheaters`; `bn254` end-to-end tests). This is the form implemented. |
| C3 | List decoding of a constrained RS code follows from list decoding of the RS code. | WHIR Lemma 7.6 | S |
| C4 | A multilinear PIOP in the usual sense is a linear Σ-IOP with queries Z·eq(r, ·). HyperPlonk's queries (H12) are of this form. | WHIR Remark 7.3 | S |

C2 is the theorem that joins HyperPlonk to WHIR. It requires the PIOP to be round-by-round knowledge sound; the HyperPlonk paper states soundness per sub-protocol (H5–H12) and knowledge soundness via H3, not a round-by-round state function. See Q1.

## 6. Instantiation over bn254 (computed, not yet tested)

log₂|F| = 253.597. gnark gate f = q_L·a + q_R·b + q_M·a·b + q_O·c + q_C, degree d = 3 counting selectors.

PIOP terms (H12), for μ = 14 / 16 / 20:
- permutation: (2^μ + μ)/|F| ≈ 2⁻²³⁹·⁶ / 2⁻²³⁷·⁶ / 2⁻²³³·⁶
- zerocheck: (dμ + (d+1)μ)/|F| ≈ 2⁻²⁴⁷ in all three cases

WHIR round-0 query count for 128 bits from the query term alone, t = ⌈128 / −log₂(1 − δ)⌉ (W11, ε_shift without the additive term and without proof-of-work):

| ρ | UD: 1 − δ = (1+ρ)/2 | JB: 1 − δ = 1.05·√ρ | JB list size 1/(2η√ρ) = 10/ρ |
|---|---|---|---|
| 1/2 | 309 | 298 | 20 |
| 1/4 | 189 | 138 | 40 |
| 1/8 | 155 | 90 | 80 |
| 1/16 | 141 | 67 | 160 |

Later rounds run at a lower rate (the domain halves per round while the degree drops by 2^k), so they need fewer queries; exact counts come from the parameter calculator (PLAN M2).

Other terms at ρ = 1/8, JB with η = √ρ/20, for m = 14 / 16 / 20:
- out-of-domain, 2^m·ℓ²/(2|F|) with ℓ = 80: 2⁻²²⁸ / 2⁻²²⁶ / 2⁻²²²
- MCA error from A1 with multiplicity 10 (ℓ = 10.5/√ρ), |E|/|F|: 2⁻¹⁹³ / 2⁻¹⁸⁹ / 2⁻¹⁸¹
- MCA error in UD (W6, ℓ = 2): 2⁻²³⁷ / 2⁻²³⁵ / 2⁻²³¹

All algebraic terms are far below 2⁻¹²⁸ in a 254-bit field without extension fields or proof-of-work; the query term decides the proof size. For comparison, plonkfri uses 86 queries at ρ = 1/8 in the proven Johnson regime (PROJECT.md).

## 7. Open theory questions and observations

| ID | Item | Needed for |
|---|---|---|
| Q1 | Answered by §11 (self-derived) for soundness; the knowledge part rests on H3. Original question: C2 assumes a round-by-round knowledge sound PIOP. Find or write the round-by-round state function for the sumcheck-based HyperPlonk PIOP (candidate sources: ePrint 2023/1071 for the method; Chiesa–Yogev book). | Claiming Fiat–Shamir security of the whole |
| Q2 | Several committed polynomials (selectors, permutation, witness, product ṽ) are opened at different points. Options: one WHIR instance per oracle (C1), a single batched test (C2), stacking into one polynomial, or H10. Each needs its error term written down. | PLAN D4 |
| Q3 | HyperPlonk's product-check oracle ṽ has μ+1 variables and is queried at (1, x), (x, 0), (x, 1) and (1, …, 1, 0). Write the exact list of evaluation claims per oracle for the gnark gate. | M3, M5 |
| Q4 | Read the proofs of A1 and A2 Lemma 9.3, or decide to treat the Johnson regime as "proven in preprints, proof not checked by us". | PLAN D2 |
| Q5 | Zero knowledge: H14 gives the PIOP side; ePrint 2026/391 gives the WHIR side (Prop 3.19: RS[F, L, ℓ] has a t-query ZK encoding with message length ℓ − t and randomness length t; Thm 1, Cor 3: HVZK IOPP with round-by-round knowledge soundness). How the two masks compose is not covered by either paper. | Later phase |
| O1 | Confirmed (S3). Observation (ours): in the proof of H6 the auxiliary polynomial g(Y) = Σ_x f(x)·eq(x, Y) is multilinear, so H2 gives μ/\|F\| for the first term; the theorem states dμ/\|F\|, which is a valid upper bound. We use the paper's value. | — |
| O4 | No longer relevant to our code: the product polynomial and the division were removed (S17); the package `prodcheck` with the test is in the git history. Observation (ours), confirmed by test: Thm 3.3 does not hold when f₁ and f₂ vanish at the same hypercube point. There the equation f₂(x)·ṽ(0, x) = f₁(x) is satisfied by every ṽ(0, x), so the prover can reach any product s; the instance is outside R_PROD (f₂ has a zero) but is accepted. The proof's step "either ĥ ∉ R_ZERO or ṽ(1,…,1,0) ≠ s" overlooks this case. `prodcheck.TestCommonZeroIsNotCaught` builds the forgery. Harmless in the multiset/permutation use (S5). | Any other use of the product check |
| O5 | Observation (ours): the multiset check is not perfectly complete as stated in Thm 3.4: if r = −g(x) for some x, the denominator vanishes and the honest prover has no valid ṽ. Probability ≤ 2^μ/\|F\| (≈ 2⁻²³⁴ at μ = 20). The prover returns an error in that case. | M3 |
| O2 | Resolved by counting variables: at round ℓ, α has ℓ−1 entries, X is one variable, so b ranges over {0,1}^(m₀−ℓ); the paper's exponent m₀−ℓ−1 is an off-by-one. Original note: in Construction 5.1 the honest sumcheck message is written with b ∈ {0,1}^(m₀−ℓ−1); with ℓ starting at 1 this leaves one variable unaccounted for. Resolve against the proof of Thm 5.2 and a hand-computed example before implementing. | M4 |
| O3 | H5 binds variables from μ down to 1; W8 folds X₁ first. Fix one variable order for the code and state it in every test vector. | M1, M4 |

## 8. Gaps in the literature and sources added

| Gap | Resolution |
|---|---|
| The sumcheck soundness proof is in neither HyperPlonk (Thm 3.1 refers to Thaler) nor LogUp (Thm 2 refers to [LFKN92], [Tha13]). | Added `resources/Thaler-ProofsArgsAndZK-2023-07-18.pdf` (https://people.cs.georgetown.edu/jthaler/ProofsArgsAndZK.pdf). Prop. 4.1 with two proofs read; bound checked exhaustively on small fields. |
| Round-by-round soundness of sumcheck-based protocols, needed by WHIR Thm 7.5 (C2, Q1). Thaler §5.3 cites Canetti et al. [CCH+19]. | Source obtained (see below). Still open: the state function for the whole HyperPlonk PIOP (zerocheck challenge τ, permutation challenges β, γ, batching α), to be written with Def 5.3 as the template. |
| HyperPlonk Thm 3.3 (product check) is unsound for inputs with a common zero of f₁, f₂ (O4), and Thm 3.4 is complete only up to 2^μ/\|F\| (O5). No erratum or later source has been looked for yet. | Precondition documented and tested; S5 shows our use is unaffected. Quark checked (see below). |
| Sources added by the user: `resources/2018-1004.pdf` — Canetti, Chen, Holmgren, Lombardi, Rothblum, Rothblum, "Fiat-Shamir From Simpler Assumptions" (the ePrint version behind [CCH+19]; the title recalled earlier was that of the STOC paper) and `resources/2020-1275.pdf` — Setty, Lee, "Quarks: Quadruple-efficient transparent zkSNARKs". | Read: 2018/1004 §2.1, Def 5.3, Prop 5.4; 2020/1275 §5, Lemma 5.1 and the sum-check instance. Results in the three rows below. |
| Round-by-round soundness, definition and the sumcheck case. | 2018/1004 Def 5.3: a State function with (1) reject on the empty transcript for x ∉ L, (2) from a reject state, for every prover message, Pr over the verifier's message of reaching accept ≤ ε, (3) reject on a full transcript implies the verifier rejects. Prop 5.4: standard soundness ≤ r·ε. §2.1 describes the sumcheck state ("doomed if the claim of the current recursion step is false") — the same state as S2. The paper gives this informally and proves the GKR case (§6, Thm 6.4); no standalone sumcheck lemma, so S2 stays a self-derived claim, now with a matching published description. Its Thm 5.8 is Fiat–Shamir in the standard model under a hash assumption; for the random-oracle model the source remains A5 (BCS). |
| Origin of the product check and of O4. | Quark Lemma 5.1 is for a plain product Π v(x): leaves f(0, x) = v(x), nodes f(1, x) = f(x, 0)·f(x, 1), root f(1, …, 1, 0), and f(1, …, 1) = 0 (proof read; same tree as `prodcheck.BuildProduct`). There is no division, hence no zero-denominator case. The rational form f₂·ṽ(0, x) = f₁ is HyperPlonk's extension, and O4 arises there. An O4-free alternative would be two plain products (numerator and denominator) compared at the roots, at the cost of a second tree; not needed given S5. |
| Zerocheck challenge term. | Quark §5 states the error "log m/\|F\|" for g(τ) = 0, i.e. μ/\|F\| — a published source for S3/O1, where HyperPlonk Thm 3.2 writes dμ/\|F\|. |
| Zero knowledge: no source covered HyperPlonk over WHIR. | Added by the user: `resources/2026-2880.pdf` — Feneuil, Provin, Rivain, "Sum-Checking SmallWood" (preprint). It gives hiding multilinear extensions (Def. 12, Lemma 2) and two compilers with security theorems (Thms 2, 3) from a sumcheck-based interactive proof and zero-knowledge linear / multilinear commitments. Mapping and plan: `ZK-DESIGN.md` §11–§12. Its source for random padding, Florentz Konopnicki–Rothblum (CRYPTO 2026), is not in `resources/`. |
| The Fiat–Shamir bound A4 models each challenge as a random-oracle output on the full transcript. Our transcript is a hash chain (state ← H(state ‖ message)). No source for the chained form has been read. | Open; to settle in M5 before the transcript format is frozen. The chain adds at least a collision term for the state (2⁻¹²⁸ level for sha256), to be stated precisely. |

Side observation on existing code (not part of this backend): plonkfri derives challenges by reducing one 256-bit hash mod r (`nativefri.challenge`), i.e. S1 with L = 256, a factor ≤ 1.134 on its challenge-counting error terms (≈ 0.18 bits). Not a break; recorded for the plonkfri follow-ups.

## 9. Error budget of the PIOP as implemented (computed)

For n = 2^μ rows (wire polynomial in μ' = μ+2 variables), all terms over |F| ≈ 2^253.6 and before the factor of S1:

| Step | Term | Source |
|---|---|---|
| Gate zerocheck, degree 3 | μ + 4μ | S3 |
| Tuple combination β | 2^μ' | H8 (Thm 3.5) |
| Multiset challenge γ | 2^μ' | H8 (Thm 3.4) |
| Product check on μ' variables | μ' + 3μ' + 1 | S4 |

Total ≤ (2^(μ+3) + 9μ + 9)/|F|: about 2⁻²³¹ at μ = 20. This is the soundness of the interactive PIOP with ideal oracles; round-by-round soundness of the whole (Q1) and the commitment are separate.

## 10. Security status of `backend/hyperplonk/bn254`

Not reviewed. Not zero-knowledge. What the soundness claim rests on, layer by layer:

| # | Layer | State |
|---|---|---|
| 1 | PIOP, interactive, ideal oracles | Each step has a read source or a self-derived claim with a test (H5–H12, S3–S9); error ≈ 2⁻²³¹ at μ = 20 (§9). |
| 2 | WHIR as IOP of proximity | Thm 5.2 with every term evaluated for bn254 (≤ 2⁻¹²⁸). The whole proof is read (§14). Unique decoding needs nothing beyond the WHIR paper; Johnson needs A1/A2 (preprints, proofs not read). |
| 3 | Composition PIOP + WHIR | Round-by-round soundness of the PIOP: §11 (self-derived). Implemented as WHIR Construction 7.4: out-of-domain sample after each prover commitment, the value of every polynomial at every point sent, one proximity test on the random combination. Its error terms (Thm 7.5: batch, commit-out) are evaluated in `whir.Params.Errors`. Own additions: padding/stacking (S14) and preprocessed polynomials (S15). Proof of Thm 7.5 read (§14). **Remaining:** §11–§13, S14 and S15 are our own arguments and unreviewed; non-oracle prover messages are not covered verbatim by Construction 7.4. |
| 4 | Fiat–Shamir + Merkle (BCS) | The BCS transformation is itself a hash chain (A5), and our transcript follows it up to the differences listed in S16. Bound: A4 with A4b. Statement binding tested. From round-by-round soundness to the compiled argument: ePrint 2019/834 Thm 8.6 (statement), or BCS Thm 7.1 (proof read in outline) with S20. **Remaining:** the differences of S16 are argued, not proven; BCS Lemmas 3.2, 7.2 and the proof of 2019/834 Thm 8.6 are not read. |
| 5 | Hash | sha256 for Merkle trees and transcript; 128-bit collision resistance is the cap of the classical level. |
| 6 | Zero knowledge | None (removed by user decision; the zero-knowledge variant is on the branch `hyperplonk-whir-zk`, described in ZK-DESIGN.md). Openings reveal evaluations of w and codeword values. S18, S19 and §13 describe that variant, not the current code. |

"128 bits" therefore currently means: every round-by-round error term of the interactive protocols is ≤ 2⁻¹²⁸ under layers 1–2; layers 3–4 are implemented according to the papers' constructions but their theorems are not yet matched one to one.

## 11. Round-by-round soundness of the PIOP (self-derived)

Definition used: WHIR §3.1 (state function; same notion as ePrint 2018/1004 Def. 5.3 and ePrint 2023/1071 Def. 3.12). State = 1 means "not doomed". A prover message must never turn 0 into 1; a verifier message may, with probability at most ε; a full transcript in state 0 is rejected.

The PIOP as an interactive protocol with oracles (queries are answered by the oracles; in the compiled protocol the prover sends the answers and WHIR ties them to the commitments). n = 2^μ rows, μ' = μ + 2.

Notation. G_w(b): value of the gate polynomial (with PI) at row b for the wire oracle w. Wiring(w): w(x) = w(σ(x)) on the hypercube. For challenges β, γ: num = γ + s_id + β·w, den = γ + s_σ + β·w, F(γ) = Π_x num(x), G(γ) = Π_x den(x). For a product oracle ṽ: the two equation families of H7 and the root condition ṽ(1, …, 1, 0) = 1. "Valid" means all sumcheck round checks so far hold. T(·) is the true partial sum of the sumcheck in progress and c the running claim.

| Step | Message | State = 1 iff | Error of the verifier message |
|---|---|---|---|
| 0 | — | the instance has a satisfying witness | — |
| 1 | P: oracle w | G_w ≡ 0 on the hypercube and Wiring(w) | — (no w has both if the instance is false) |
| 2 | V: τ ∈ F^μ | Wiring(w) and Σ_b G_w(b)·eq(b, τ) = 0 | μ/\|F\| (S3) |
| 3.i | P: s_i; V: r_i (i = 1..μ) | Wiring(w), valid, and c_i = T(r₁..r_i) for p = G_w·eq(·, τ) | 4/\|F\| each (S2, degree 4) |
| 4 | V: β, γ | [valid and c_μ = G_w(r)·eq(r, τ)] and F(γ) = G(γ) | 2·2^μ'/\|F\| (H8: 2^μ' for β, 2^μ' for γ) |
| 5 | P: oracle ṽ | [gate part as in 4] and ṽ satisfies both families and the root condition | — (see below) |
| 6 | V: α, τ' ∈ F^μ' | [gate part], root condition, and Σ_x H(x)·eq(x, τ') = 0, H = (A − B·C) + α·(den·D − num) | (1 + μ')/\|F\| (batching 1, then S3) |
| 7.i | P: s'_i; V: r'_i (i = 1..μ') | [gate part], root condition, valid, and c'_i = T'(r'₁..r'_i) | 3/\|F\| each (S2, degree 3) |
| end | queries | — | State 0 ⇒ reject |

Why the rules hold:

- Step 1. If the instance is false, no w satisfies both identities, so the state is 0 after any w.
- Steps 2–3. If Wiring(w) fails the state stays 0 whatever happens (it is part of the condition up to step 4). Otherwise some row violates the gate identity and S3, then S2 apply.
- Step 4. If the gate part fails, the state stays 0. Otherwise Wiring(w) fails, and the multisets of pairs differ; H8 bounds the probability over β that the combined multisets coincide, and then over γ that F(γ) = G(γ). Both challenges are one verifier message.
- Step 5 (a prover message cannot repair F(γ) ≠ G(γ)). If den has no zero, the families force ṽ(0, x) = num(x)/den(x) and the root to be F(γ)/G(γ) ≠ 1. If den(x₀) = 0 for some x₀ then G(γ) = 0 ≠ F(γ), so num(x₀) ≠ 0 and the leaf equation den(x₀)·ṽ(0, x₀) = num(x₀) has no solution (this is S5).
- Step 6. From state 0 with the gate part and root condition intact, one family is violated at some x₀; at most one α makes H(x₀) = 0; then S3.
- End. State 0 means one of: a failed round check, c_μ ≠ G_w(r)·eq(r, τ), root ≠ 1, or c'_μ' ≠ H(r')·eq(r', τ'). The verifier checks each of these from the oracle answers (in the code: `ZeroResult.Check` for the gate, `prodcheck.Verify` with the linear relations of `permcheck.Verify`, and the root claim).

Maximum over the rounds: 2^(μ+3)/|F| (step 4), about 2⁻²³¹ at μ = 20. Sum over all rounds: the bound of §9 (Prop. 5.4 of ePrint 2018/1004).

Knowledge: the witness is the table of w, readable from the first oracle; with WHIR's definition the extraction condition only concerns transcripts in state 0 whose next challenge reaches state 1 with probability above the error, which by the above does not occur. We rely on HyperPlonk Lemma 2.3 (H3) for the statement that the sound PIOP is knowledge sound.

Status: written and checked by us only. Components tested: S2, S3 (exhaustive small-field models), S5 (model over F₁₃), the cheaters of `piop` and `permcheck` for each final check. No test covers the argument as a whole.

## 12. Protocol after removing the product polynomial

The wiring identity is now: β, γ; then `grandprod` proves Π(γ + s_id + β·w) = Π(γ + s_σ + β·w) by layered sumcheck; then w(q) and s_σ(q) are opened at the final point q. H7 (product check), S4, S5, O4, O5 no longer apply. The prover commits to w only.

Error budget (replaces §9), wire polynomial in μ' = μ + 2 variables:

| Step | Term (numerator over \|F\|) | Source |
|---|---|---|
| Gate zerocheck, degree 3 | μ + 4μ | S3 |
| β, γ | 2·2^μ' | H8 |
| Layers i = 0..μ'−1 | Σ (3i + 2) = 3μ'(μ'−1)/2 + 2μ' | S17 |

Total ≈ 2^(μ+3)/|F| as before; the layer terms add about 2^10 at μ = 20.

Round-by-round state (replaces steps 4–7 of §11; steps 0–3 unchanged):

| Step | Message | State = 1 iff | Error |
|---|---|---|---|
| 4 | V: β, γ | [gate part] and F(γ) = G(γ) | 2·2^μ'/\|F\| |
| 5 | P: the two roots | [gate part], F(γ) = G(γ), and both sent roots equal the true products (then they are equal) | — |
| 6.i.a | V: λ | [gate part] and c₁ + λ·c₂ = V_i¹(z) + λ·V_i²(z) for the current claims c and true layers V | 1/\|F\| |
| 6.i.b | sumcheck rounds | [gate part], valid, running claim = true partial sum | 3/\|F\| each |
| 6.i.c | P: four layer values; V: t | [gate part] and the two new claims (1−t)·l + t·r equal V_{i+1}(r, t) for both tables | 1/\|F\| |
| end | queries w(q), s_σ(q) | — | State 0 ⇒ reject |

Step 5: if F(γ) ≠ G(γ), two equal roots cannot both be the true products, so the state is 0; if the roots differ the verifier rejects. Step 6.i.c: if the state is 0 after the sumcheck but the prover's four values pass the layer check, at least one value differs from the true one, and the line through the reported pair meets the true line in at most one t. End: the final claims are compared with γ + s_id(q) + β·w(q) and γ + s_σ(q) + β·w(q) computed from the opened values.

The protocol is now a sumcheck-based interactive proof with a single committed witness, the form required by ePrint 2026/2880 Def. 11 (ZK-DESIGN.md §11).

## 13. Protocol after masking (stage S2)

Sizes for 2^μ rows, d = μ + 2: pad length τ = 4μ + 2 + 3d(d−1)/2 + 8d + 1 (250 at μ = 8, 292 at μ = 9, 778 at μ = 16 — computed by `piop.PadSize`). The pad must fit in the fourth column with 8 slots to spare, so the least circuit size is 2^9 rows; smaller circuits are padded to it.

Constraints the verifier produces: 1 (gate) + 1 (equal products) + d (layers) + 2 (leaves) + 2 (linearization of 2d products) = d + 6 linear constraints, merged into one.

What a proof now contains in clear, beside public data: the opened values of w (covered by the random slots, stage S1), and the linearization value v (uniform through a fresh pad coordinate; `cbip.TestLinearizationValueIsMasked`). Everything else from the PIOP is masked. Still witness-dependent and unmasked: the WHIR opening (stage S3).

Additional soundness terms over §12: (4d − 1)/(|F| − 2d) for the linearization and (d + 5)/|F| for the merge.

## 14. Proofs read

Status P below means: read in the PDF text and followed step by step. It does not mean checked by anyone else.

| Result | Read | Outcome |
|---|---|---|
| WHIR Claim 5.3 (fold round of Thm 5.2) | proof | P. A sumcheck-type identity argument: the true round polynomial of a list element differs from the sent one, they agree at α with probability ≤ d*/\|F\|, union over the list. Together with Thm 4.20 (read earlier) this completes the fold-round bound. All parts of the proof of Thm 5.2 are now read. |
| WHIR Thm 7.5 (composition) | proof, incl. Claims 7.8, 7.9 | P. The state function applies the PIOP's state function to the codewords decoded from the committed words (unique thanks to the out-of-domain constraint). Batching error: mutual correlated agreement for the s combined words, plus a degree-(s−1) polynomial identity in γ, union over the interleaved list. Matches the terms in `whir.Params.Errors`. |
| ePrint 2026/2880 Lemma 3 (masking preserves round-by-round soundness) | Def. 13 and proof | P. Masking with a fixed pad is a bijection on transcripts that leaves verifier messages untouched. Its Def. 13 lets the state depend on the committed witness, as our §11–§12 do. |
| ePrint 2026/2880 Thms 2, 3, zero-knowledge parts | proofs (hybrids) | P. Replace the commitment transcripts by their simulators on the public statement; replace masked messages by uniform values (one-time pad, including the two linearization messages); replace the revealed evaluation by a uniform value (hiding extension). The soundness parts (extractors, commit states) were only skimmed. |
| ePrint 2026/391 Lemma 7.3 (simulator of Construction 7.2) | proof | P. The simulator queries the committed word at the spot-check positions, simulates the mask's values there, and samples the combination uniformly subject to consistency at those positions. This is the structure our S19 reduction relies on. Lemma 7.4 (soundness of 7.2): statement only; we do not use it (our soundness comes from WHIR Thm 7.5). |
| BCS Lemma 7.3 (soundness of the transformation) | proof | Read in outline: an accepting prover in the random-oracle model is turned into a state-restoring prover of the interactive protocol unless a hash collision or an inconsistent Merkle opening occurs, 3(m² + 1)·2^−λ in total. It relies on its Lemmas 3.2 and 7.2 (Merkle extraction), not read. |
| ePrint 2019/834 Thm 8.6 | statement | S. BCS applied to an IOP with round-by-round soundness error ε has soundness error O(t²ε + t³/2^λ) against quantum attackers with t queries; knowledge and (statistical) zero knowledge carry over from round-by-round knowledge and honest-verifier zero knowledge of the IOP. This is a direct theorem from round-by-round soundness to the compiled argument, and it covers zero knowledge. Proof not read. |
| ePrint 2025/2110 (Johnson regime, A1) | whole note | Read. The argument modifies Section 5 of ePrint 2020/654 (decomposition of the Guruswami–Sudan interpolant into irreducible factors, Hensel lift, Claims 5.4 and 5.7, Appendix C) and concludes with the counting Lemma 1 of the note, which we followed. Its correctness depends on those steps of 2020/654, which we have not read. Status stays S for the theorem. |
| ePrint 2025/2051 Lemma 9.3, Thm 9.2 (A2) | not read further | S. |

Self-derived link used in §10 layer 4:

| ID | Claim | Argument |
|---|---|---|
| S20 | An IOP with round-by-round soundness error ε has state-restoration soundness error ≤ b·ε against a prover that obtains b verifier messages. | The empty transcript is doomed, prover messages keep a transcript doomed, and an accepted transcript is alive. So some verifier message drawn during the attack turned a doomed partial transcript alive. Each drawn message does so with probability ≤ ε; union bound over the b messages. (2023/1071 states this by citation; ePrint 2019/834 Thm 8.6 gives the compiled bound directly.) |

Differences from the statements of the theorems that the reading made precise:

1. WHIR Construction 7.4 has the PIOP prover send oracles only. Our prover also sends field elements that the verifier reads in full (masked sumcheck messages, opened values). They are absorbed into the transcript directly; in the theorem's terms they are oracles read entirely. Not covered verbatim.
2. Preprocessed polynomials (S15) and padding/stacking (S14): unchanged, still ours.
3. ePrint 2026/2880 Thm 3 uses two commitment schemes; we use one. Its zero-knowledge proof goes through with one simulator for the merged commitment (the two hybrids become one); for soundness one extractor yields both parts. We consider this a notational difference, but it is our reading, not the paper's statement.

## 15. Current protocol

Not zero-knowledge. The protocol is the one of §12 (gate zerocheck; wiring by layered sumcheck; w the only prover commitment), unmasked, with the batched opening of S14 in this layout: four polynomials in μ+2 variables — Q (q_L, q_R, q_M, q_O stacked), C (q_C in block 0), S (s_σ), W (w) — in two trees (setup: Q, C, S; prover: W), opened at six points: the four gate points (⟨j⟩, r), the wiring point q and the out-of-domain point of W. Stacking is S14 with two selector bits; nothing is padded. Sections §12 (error budget, round-by-round state) and §14 (proofs read) apply; the batch error terms are evaluated for 4 polynomials by `whir.Params.Errors`.
