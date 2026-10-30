# SPEC-PIOP — HyperPlonk over gnark SparseR1CS (bn254), WHIR-instantiated

Normative for the PIOP agent. Source: HyperPlonk, ePrint 2022/1355 (§3.1–3.5, 3.8, 4.2, App. A); EspressoSystems/hyperplonk; LogUp (ePrint 2022/1530); Libra (XZZPS19). Deviations from the paper are deliberate and listed in PLAN.md §3. All size/time numbers are estimates until measured.

## 0. Notation

F = bn254 fr, p ≈ 2^253.6. ℓ = |spr.Public|, ν = ⌈log2 ℓ⌉, n_rows = ℓ + nbConstraints, μ = max(2, ⌈log2 n_rows⌉) in Standard mode and **μ = max(5, ⌈log2 n_rows⌉) in ZK mode** (the W mask block needs 4μ + 7 cells in slot 3; μ = 5 → 27 ≤ 32; H needs only 3 cells; Setup asserts the fit), n = 2^μ.
Indexing is **0-based** everywhere: columns w_0,w_1,w_2, h_0..h_2, masks c_0..c_2, slots ⟨0⟩..⟨3⟩.
ℓ = 0 is allowed: then ν is undefined, PI ≡ 0, and no public rows exist.
Hypercube order follows gnark-crypto `polynomial.MultiLin`: index i = Σ_k 2^{μ−k} b_k (X_1 = MSB; `Fold` binds X_1 first). eq(x,y) = Π (x_k y_k + (1−x_k)(1−y_k)) (`polynomial.EvalEq`, `MultiLin.Eq`).
Stacking: columns c_0..c_{2^s−1} (μ vars) → C(Y,X) on s+μ vars, table = c_0‖c_1‖…, slot bits Y most significant; Σ_j eq(τ,⟨j⟩)·c_j(ρ) = C(τ,ρ).

## 1. Arithmetization

Row layout identical to `backend/plonkfri/bn254/setup.go`. `buildPermutation` is unexported and takes plonkfri's `*ProvingKey`: **M1b moves it to `internal/plonkperm` as `BuildPermutation(spr *cs.SparseR1CS, n int) []int64` and plonkfri calls it** (plonkfri tests must stay green). The solver's L/R/O vectors are reused as-is:
- rows 0..ℓ−1: public placeholders qL = −1, others 0; L = public var i, R = O = wire 0;
- rows ℓ..ℓ+nbConstraints−1: from `spr.GetSparseR1CIterator()`, selectors `spr.Coefficients[c.QL]` etc., wires (XA, XB, XC);
- padding rows: selectors 0, wires = wire 0 (solver convention, `padToDomain`).

MLEs: q_L,q_R,q_O,q_M,q_C; σ_j(⟨i⟩) = Permutation[j·n + i] as field element (j = 0,1,2); w_0,w_1,w_2 = MLE(solution.L,R,O); id_j(X) = j·n + Σ_k 2^{μ−k} X_k (linear, never committed). Variables are 1-based X_1..X_μ with X_1 = MSB — the only 1-based index.

Public input: PI(X) = Σ_{i<ℓ} pub_i·eq(⟨i⟩_μ, X). The verifier first checks len(pub) = ℓ and that every pub_i is canonical (< p), then computes PI(ρ) = Π_{k≤μ−ν}(1−ρ_k) · Σ_i pub_i·eq(⟨i⟩_ν, ρ_{μ−ν+1..μ}) in O(2^ν + μ).
Gate: f(X) = q_L w_0 + q_R w_1 + q_O w_2 + q_M w_0 w_1 + q_C + PI(X) (degree 3). Row i < ℓ gives −w_0 + pub_i = 0.

## 2. PIOP

### 2.1 Permutation: LogUp with committed helpers
After W is committed: β, γ. a_j = γ + w_j + β·id_j, b_j = γ + w_j + β·σ_j. Prover commits h_j = 1/a_j − 1/b_j on B_μ (batch inversion of 6n). Constraints: Z_j = h_j a_j b_j − (b_j − a_j) = 0 on B_μ, and Σ_{B_μ}(h_0+h_1+h_2) = 0. Prover aborts (returns an error; the honest prover simply fails) if some a_j or b_j = 0; probability ≤ 6n/p. **The zero check must be explicit before inversion: gnark-crypto `fr.BatchInvert` silently maps 0 ↦ 0.**
**Edge case that matters for soundness (review F15):** if a_j(x) = b_j(x) = 0 then Z_j(x) = 0 for every h, so h_j(x) is unconstrained. This can only happen at fixed points of σ (id_j(x) = σ_j(x), i.e. single-use wires) with γ = −w_j(x) − β·id_j(x). W is committed before γ, so the probability is ≤ 3n/p. Listed in §5; tested with a forced fixed point.
Alternatives considered: paper product check (5 opening points incl. boolean-coordinate points → breaks ZK masking, more openings); LogUp-GKR (no H tree, ~20–25 % smaller, hard ZK) → v2, out of scope.

### 2.2 Committed objects
- P = stack(q_L,q_R,q_O,q_M,q_C,σ_0,σ_1,σ_2) — μ+3 vars, committed at Setup **always in Standard (non-ZK) mode** (P is public and Setup must be byte-deterministic, PLAN R8); root in VK.
- W = stack(w_0,w_1,w_2,M_W) — μ+2 vars, round 1. M_W = 0 in non-ZK, mask block in ZK (§4).
- H = stack(h_0,h_1,h_2,M_H) — μ+2 vars, round 2.

### 2.3 One batched sumcheck
After H: α ∈ F, r ∈ F^μ. Sumcheck over B_μ with claim 0 (ZK: ρ_g·G) for
F(x) = eq(r,x)·[ f(x) + Σ_{j=0..2} α^{j+1} Z_j(x) ] + α^4 Σ_j h_j(x).
Degree d = 4. Round i message: s_i(t) at t ∈ {0,2,3,4}; verifier derives s_i(1) = claim − s_i(0). Prover: bookkeeping tables + `MultiLin.Fold`, eq as its own table. (Gruen eq-factoring: prover-time optimisation after M2.)
ZK mode changes round 1 only (degree 7, §4); the sumcheck package therefore exposes `Degree(round)` and a round-1 hook (§7).
Final (Standard): checks F(ρ) = final claim. **ZK: F*(ρ) + ρ_g·g(ρ) = final claim.** ρ = (ρ_1..ρ_μ). Prover sends 14 evaluations at ρ: q_* (5), σ_j (3), w_j (3), h_j (3). Verifier computes eq(r,ρ), id_j(ρ), PI(ρ), rebuilds a_j, b_j, f, Z_j and checks F(ρ) = final claim.

### 2.4 Reduction to PCS claims (one WHIR opening per commitment)
τ_P ∈ F³, τ_W, τ_H ∈ F². Slot j of a stack occupies the sub-block with top bits ⟨j⟩.
- P: form L_P = eq((τ_P, ρ), ·) over all 8 slots (`StackedEqSparseForm` without sparse terms); value y_P = Σ_{s<8} eq(τ_P,⟨s⟩)·P_s(ρ).
- W (non-ZK, M_W = 0): L_W = Σ_{j<3} eq(τ_W,⟨j⟩)·eq(ρ, ·)|_{slot j}; **slot 3 gets weight 0** (not eq(τ_W,⟨3⟩)). Value y_W = Σ_{j<3} eq(τ_W,⟨j⟩)·w_j(ρ).
- W (ZK): §4 gives the exact form; same idea — slot 3 is reached only through explicit sparse cells, never through eq over the whole block. This is required for completeness (M_W ≠ 0 in ZK) **and** for ZK: weighting slot 3 by eq would force revealing M_W(ρ), a random combination of the Libra coefficients outside the Libra lemma (review F3).
- H: same as W with τ_H, h_j, M_H.
`EvalMLE` of L_W at r = (r_Y, r_X) ∈ F² × F^μ: Σ_{j<3} eq(τ_W,⟨j⟩)·eq(r_Y,⟨j⟩)·eq(ρ, r_X) (+ sparse terms in ZK) — O(μ).
Completeness test with non-zero M_W required. No BatchEval sumcheck. Joint W+H opening: cost milestone (M4) only.

## 3. Fiat–Shamir schedule (single `transcript.go`)

sha256 hash chain with labels and indexed challenges (`internal/fs`). Exact construction:
- state S₀ = sha256("gnark-hyperplonk-whir-bn254/v1"); `Absorb(label, data)`: S ← sha256(S ‖ 0x01 ‖ len(label) ‖ label ‖ len(data) ‖ data) (lengths as u32 big-endian);
- `ChallengeField(label, i)`: u₀ = sha256(S ‖ 0x02 ‖ len(label) ‖ label ‖ u32(i) ‖ 0x00), u₁ = same with 0x01; c = (u₀‖u₁ as 512-bit big-endian) mod p; then S ← sha256(S ‖ 0x03 ‖ u₀ ‖ u₁);
- `ChallengeIndices(label, count, logDomain)`: per index one 32-byte block as above, masked to logDomain bits;
- `PoW(bits)`: nonce n with leading `bits` zero bits of sha256(S ‖ 0x04 ‖ u64(n)); verifier checks then absorbs n.
Field elements are absorbed as canonical 32-byte big-endian; the domain tag is S₀ only (step 1 below is that initialisation, not a second absorb); `ChallengeIndices(label, count, logDomain)`: block_j = sha256(S ‖ 0x02 ‖ u32(len label) ‖ label ‖ u32(j) ‖ 0x00) for j = 0..count−1; idx_j = BE(block_j) & (2^logDomain − 1); then S ← sha256(S ‖ 0x03 ‖ block_0 ‖ … ‖ block_{count−1}). In `ChallengeField(label, i)`, i is the resampling counter (0 unless resampling). Every named scalar has its own label (`beta`, `gamma`, `alpha`, `r/<k>`, `rho_g`, `tauP/<k>`, …). PoW label `"pow"`. VK and header digests: byte layout in FS-GRAMMAR.md §digests. `MaxLogSize = 17` (Panurus circuits are 2^14; same cap as plonkfri). **M0 deliverable: `FS-GRAMMAR.md` (byte-level grammar) with a test vector, before fs/pyref are written.** Roots are absorbed by the PIOP schedule (steps 4–5), never inside `whir.Commit`. The outer transcript and the PCS share this transcript and `HashID`. `backend.WithProverChallengeHashFunction`/`WithVerifierChallengeHashFunction`: probe the given `hash.Hash` on a fixed test vector against the VK `HashID` (probe a clone if the hash implements one; otherwise document that the option's instance must not be shared across goroutines); mismatch → error (PLAN R10).
1. domain tag `"gnark-hyperplonk-whir-bn254/v1"`;
2. vk.Digest(): format version, μ, ℓ, the canonical `pcs.Header` of P/W/H (incl. TableVersion, NumVars, regime, ρ, k, PoW, λ, mode, hashID) and each header's table-row digest (FS-GRAMMAR §digests), root(P);
3. ℓ and pub_0..pub_{ℓ−1};
4. root(W) (ZK: mask sum G) → β, γ;
5. root(H) → α, r_1..r_μ (ZK: ρ_g, resampled with counter if 0);
6. per round i: s_i(0), s_i(2..d_i) → ρ_i (no resampling: ρ_1 ∈ {0,1} has probability 2/p and only voids ZK of one proof — accepted, review F15);
7. 14 evaluations (ZK: + g(ρ));
8. τ_P (3), τ_W (2), τ_H (2);
9. WHIR openings P, W, H (in this order) on the same transcript.
Cheating seams (part of the M0 contract): before each commit, before each absorb, override of any evaluation or round message, and `transcriptPublic` as in plonkfri. Each verifier check has a disable switch for the R9 mutation check. **Implemented as unexported per-call config fields reached via `export_test.go` — no package globals (races under `t.Parallel` + `-race`), no build tag (CI's `go test -short ./...` would silently skip them).**

## 4. Zero knowledge (v1b)

Leaks to cover: sumcheck round messages; w_j(ρ), h_j(ρ); WHIR transcript (query answers, internal sumcheck, final poly).
(i) **Witness masking** (App. A.2, t = 1 since each column is opened once at ρ): w*_j = w_j + c_j·X_1(1−X_1), h*_j = h_j + c'_j·X_1(1−X_1), c uniform; identical on B_μ. WHIR is not additive, so c_j live in the stacked table: M_W[0..2] = c_0..c_2, M_H[0..2] = c'_0..c'_2. They must be inside the **same** opening as w_j (a separate commitment would make W's public opened value an unmasked combination of w_j(ρ) — rejected in review debate). Exact form:
L_W = Σ_{j<3} eq(τ_W,⟨j⟩)·[ eq(ρ,·)|_{slot j} + ρ_1(1−ρ_1)·e_{cell(c_j)} ],  value y_W = Σ_{j<3} eq(τ_W,⟨j⟩)·w*_j(ρ).
Slot 3 is weighted only through these cells (and the Libra cells below, which use a separate form).
(ii) **ZK sumcheck** (Libra): g(x) = g_0 + Σ_i g_i(x_i) (Libra constant is g_0, not to be confused with mask c_0), deg g_1 = 7, deg g_i = 4 (i ≥ 2) — 1 + 7 + 4(μ−1) coefficients, stored in M_W[3..]; prover sends G = Σ_{B_μ} g; sumcheck on F* + ρ_g·g with claim ρ_g·G. Round 1 has degree 7 (masks are degree 2 in X_1), later rounds degree 4. g(ρ) = g_0 + Σ_i g_i(ρ_i) is a separate sparse linear form L_g on W (cells M_W[3..] in order g_0, g_1 coeffs of degree 1..7, g_2 coeffs 1..4, …; coefficients = powers of ρ_i); its value g(ρ) is revealed (Lemma A.2 allows it). Implementation (review-2 F4 — masks enter F* non-linearly, e.g. q_M·w*_0·w*_1·eq contains c_0c_1·t²(1−t)²·Σ q_M eq, so they cannot be added after `Eval`): in round 1 the hook adds c_col·t(1−t) to each masked column's linear extension **before** `Composition.Eval`, for t ∈ {0..7}; after fold 1 the sumcheck package itself adds `Offset(col, ρ_1)` = c_col·ρ_1(1−ρ_1) to the folded tables; rounds ≥ 2 are the standard degree-4 path. Libra is a separate additive term with g_i(0) = 0 normalisation: Σ_{x′} g(t,x′) = 2^{μ−1}(g_0 + g_1(t)) + 2^{μ−2}·Σ_{i≥2} g_i(1) in round 1 (analogously later rounds), and G = 2^μ·g_0 + 2^{μ−1}·Σ_i g_i(1). Required test: hooked prover equals brute-force evaluation of F* + ρ_g·g on a μ = 3 instance.
(iii) **PCS hiding**: ZK-WHIR (SPEC-WHIR §3), salted leaves.
Simulatability: roots hiding; round messages and G by Lemma A.2; w*_j(ρ), h*_j(ρ) uniform (ρ_1 ∉ {0,1}); q, σ, PI public; WHIR simulated from (root, constraint, value).
Cost: ~6 + 68 field elements in tables (μ = 16), 3 extra round-1 elements, sparse terms; no extra commitment or variable.
Tests (the revealed values are **not** a linear function of all randomness — round 1 is quadratic/cubic in c_j — so the test is split into linear sub-tests, each red with ZK off; review-2 F5):
(a) with c_j fixed, the Libra coefficients map affinely onto (s_1..s_μ, G, g(ρ)); full rank modulo the claim constraint;
(b) c_j ↦ (w*_j(ρ), h*_j(ρ)) has full rank;
(c) per WHIR sub-protocol (encoding, sumcheck masks, cs-mask, base-case blinding): IRS randomness ↦ opened rows + OOD answers has full rank;
(d) attack test: with ZK off, recover w_j(ρ) from the transcript; with ZK on, the same procedure fails;
(e) salt guess-confirmation attack (SPEC-WHIR §3).
**Inventory of revealed values and their cover** (review-2): roots → salted Merkle; G, s_1..s_μ → Libra Lemma A.2; w*_j(ρ), h*_j(ρ) → Lemma A.1, t = 1, ρ_1 ∉ {0,1}; q(ρ), σ(ρ), PI(ρ), y_P, P's opening → public; g(ρ) → Lemma A.2; y_W, y_H → linear in revealed values; W/H ZK openings (masked sumcheck polys, δ, mask-proximity answers, zero-evader OOD answers, ZK-encoded rows, base-case blinded vector) → 2026/391 theorems (ROM, salts). One mask coefficient per column suffices: c_j enters round messages only through s_1, which is re-randomised by ρ_g·2^{μ−1}·g_1(t) (7 fresh coefficients).

## 5. Soundness (n = 2^16)

| Step | Bound | Value |
|---|---|---|
| zerocheck point r (HyperPlonk Thm 3.2's combined bound dμ/p, conservative; μ/p suffices for the point alone) | 4·16/p | 2^-247.6 |
| α batching | 4/p | 2^-251.6 |
| sumcheck | (4·15+7)/p | 2^-247.5 |
| LogUp: β compression of (value, label) pairs ≤ 3n/p + rational identity in γ (numerator degree < 6n) ≤ 6n/p (cf. 2022/1530 §3) | 9n/p | 2^-234.4 |
| Libra ρ_g | 1/p | 2^-253.6 |
| stacking τ | 7/p | 2^-250.8 |
| LogUp a=b=0 at a σ fixed point (h unconstrained) | 3n/p | 2^-236.0 |
| JB list-union: ×L_W on terms before H is committed (β, γ), ×L_W·L_H after; L ≤ 10/ρ′ with ρ′ the **actual** initial rate of the table row (also in ZK: the list in the masked code projects to ≤ L messages). ρ′ = ρ gives 80; power-of-two rounding (SPEC-WHIR §3) can lower ρ′ to ≈ ρ/2, i.e. L ≈ 160 | ≤ ×160² (worst case) | 2^-234.4·160² ≈ 2^-219.8 |
| **WHIR per opening** | 2^-130 target each, 3 openings | **dominant: ≥ 128 bits total** |

FS: RBR (knowledge) soundness per round (WHIR/zook proven RBR, 2026/391 §2.1; sumcheck rounds d_i/p); a Q = 2^128 hash-query attacker gains ≤ ~2^-92 on the PIOP terms (after the worst-case list-union loss); PCS rounds are set for λ = 130 each. Model: ROM for soundness and ZK (not QROM).
**Binding argument to write down (M0 deliverable, reviewed in M6):** in JB the commitments to W and H each fix a list of ≤ 10/ρ codewords; the extractor's PIOP witness is any list member; union bound over the list multiplies the PIOP error by at most L_W·L_H (L_W alone for steps before H). **Trust assumption:** P is exempt only because an honest VK is an exact codeword (other codewords ≥ 1−ρ > δ away, so its list is {P}); the VK must be reproducible from the circuit (deterministic Setup, R8) — a verifier should regenerate it rather than accept an arbitrary one.
Cheater tests required (Adversary; R9 three-part form): forced σ fixed point with a = b = 0; lie at ρ for each committed column; wrong PI row; broken copy constraint (wrong permutation witness); bad gate witness with honest PCS; h_j table satisfying the sum but not Z_j; a_j = 0 edge; swapped stack slots; wrong y_W with honest openings; transcript field mutation sweep. Each 0/N with the rejecting check recorded.

## 6. Cost estimate (2^16, unmeasured)

Prover: commit W,H (2^18 cells each, RS at ρ=1/8, k=4), degree-4 sumcheck (~10M mul), 6n inversions, 3 openings → est. 0.5–1 s single-thread. Proof: 2 roots, ~2 KB sumcheck, ~0.5 KB evals, 3 WHIR openings at m = μ+3, μ+2, μ+2 ≈ 160–195 KiB each → **≈ 0.48–0.57 MiB at 2^16, ≈ 0.46–0.49 MiB at 2^14** (Standard mode); ≈ 0.3–0.4 MiB after M4. Replaced by `whirparams` at G0. Verifier ≈ 3–6 ms.

## 7. API

```go
// backend/hyperplonk/bn254
type VerifyingKey struct {
    Version          uint8
    NbVars, NbPublic uint64
    WhirP, WhirW, WhirH pcs.Header // WhirP.Mode must be Standard; WhirW.Mode == WhirH.Mode (validated on decode)
    Pre              pcs.Commitment
}
type SetupOption func(*setupConfig) // WithMode(pcs.Standard|pcs.ZeroKnowledge), WithRegime(...)
// Default: Standard + Johnson until M3e (ZK returns pcs.ErrUnsupported); the default flips to ZK + Johnson in M3e.
func Setup(spr *cs.SparseR1CS, opts ...SetupOption) (*ProvingKey, *VerifyingKey, error) // Standard mode is test-only after M3
type ProvingKey struct {
    Vk    *VerifyingKey
    Q     [5]polynomial.MultiLin
    Sigma [3]polynomial.MultiLin
    Pre   pcs.Witness
}
type Evaluations struct{ Q [5]fr.Element; Sigma, W, H [3]fr.Element; G, GRho fr.Element }
type Proof struct {
    W, H     pcs.Commitment
    Sumcheck sumcheck.Proof
    Evals    Evaluations
    OpenP, OpenW, OpenH pcs.Proof // one opening per commitment
}
func Prove(spr *cs.SparseR1CS, pk *ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (*Proof, error)
func Verify(proof *Proof, vk *VerifyingKey, publicWitness fr.Vector, opts ...backend.VerifierOption) error

// internal/sumcheck/bn254
type Composition interface {
    Degree(round int) int
    Eval(cols []fr.Element) fr.Element      // rounds on multilinear tables
}
type Round1Hook interface {                    // ZK only (§4)
    Offset(col int, t fr.Element) fr.Element   // round 1: added to column col's linear extension before Eval;
                                               // after fold 1 the sumcheck package itself does cols[col][i] += Offset(col, ρ1)
    Libra(round int, t fr.Element) fr.Element  // additive mask term ρ_g·Σ g(·), every round
}
type Proof struct{ Rounds [][]fr.Element } // evals at 0,2..d_i
func Prove(t *fs.Transcript, claim fr.Element, cols []polynomial.MultiLin, c Composition, h Round1Hook /* nil in Standard */) (proof Proof, rho []fr.Element, finalEvals []fr.Element)
// Labels: Absorb("sc/round/<i>", s_i(0),s_i(2..d)); ChallengeField("sc/chal", i). The claim is not absorbed (the caller binds it).
func Verify(t *fs.Transcript, claim fr.Element, degrees []int, p Proof) (rho []fr.Element, finalClaim fr.Element, err error)
```

## 8. Scope cuts

Deferred: BSB22 (multi-phase witness; first feature after v1), lookups, high-degree custom gates, recursion, other curves, LogUp-GKR, Gruen. Reuse: `polynomial.MultiLin`, `fr.BatchInvert`, `fft`, `buildPermutation`, `internal/gkr/bn254/sumcheck.go` as structural template (**not** its `SetBytes(h.Sum(nil))` challenge reduction — biased), plonkfri suite test.
