# Project: FRI-IOPP for gnark PLONK

Read this file at the start of every session and write to it during and at the end of every session, per `CLAUDE.md`.

## Goal

Add a FRI-based polynomial commitment backend for gnark's PLONK, fully segregated from the existing KZG backend (`backend/plonk/`), reusing the already-restored FRI code (`internal/nativefri`, `std/commitments/fri`, restored at `fb6e65da` on branch `restore-fri-gadget`) and the pre-2024 `backend/plonkfri` architecture (deleted in `1ed22f78`, "kill backend.PLONK_FRI").

## Key research finding

FRI's soundness doesn't depend on which field it runs over — "FRI over bn254 fr" is just as transparent/PQ as "FRI over koalabear." The old `backend/plonkfri` and the restored `internal/nativefri`/`std/commitments/fri` gadgets both target the curve's own `fr` field. gnark-crypto's koalabear assets (`vortex`, `iop`, `fft`) have **no FRI folding code** — Vortex is a different PCS. So "reuse what's restored" and "target koalabear" are two different, non-overlapping projects; we chose the former for v1.

Primary reference: `resources/2019-1400.pdf` — RedShift (Kattis/Panarin/Vlasov, CCS'22), the paper describing exactly this transformation (their "List Polynomial Commitment" wrapping FRI, Algorithm 2). Full architecture study (KZG seams): https://claude.ai/code/artifact/42bcd5a9-2492-4e0b-ae97-8c4efa2c89a4

Reference papers, all in `resources/` (committed):
- `2019-1400.pdf` — RedShift: Transparent SNARKs from List Polynomial Commitments (primary reference, above)
- `Revision2OfTR17-134.pdf` — Fast Reed-Solomon Interactive Oracle Proofs of Proximity (the original FRI paper, Ben-Sasson/Bentov/Horesh/Riabzev)
- `2019-336 (1).pdf` — DEEP-FRI: Sampling Outside the Box Improves Soundness
- `2020-654.pdf` — Proximity Gaps for Reed–Solomon Codes
- `out.txt` — plain-text extraction of the RedShift paper, used for quick grep/search during the design walkthrough

`std/recursion/plonk` (in-circuit recursive PLONK verification) is deeply KZG/pairing-specific (G1El/G2El, emulated field arithmetic) — a FRI backend cannot plug into it. A FRI-based recursive verifier would be new, built on `std/commitments/fri`, and is out of scope for v1.

## Design decisions (locked in for v1)

- **Field**: curve scalar field (bn254 `fr`), not koalabear. Reuses `internal/nativefri` almost as-is.
- **Curve scope**: bn254 only, hand-written (no bavard codegen). Other curves are additive later.
- **Milestone scope**: native (out-of-circuit) backend only. No in-circuit verifier / recursion in v1.
- **Hash**: sha256 (matches the vendored `internal/nativefri` and old `backend/plonkfri` as-is). Poseidon2 swap deferred to when an in-circuit verifier is built.
- **FRI security**: rate ρ=1/8 (`rho = 8`), **86 queries = 128-bit proven** soundness (Johnson bound). See "Security status".
- **Security target** (decided 2026-10-07): **128-bit classical, "plausibly post-quantum"** — option (a) in "Post-quantum target" below; the industry norm (ethSTARK, Plonky2, RedShift). Quantum estimate ≈64 bits (Grover-type loss on Fiat-Shamir). Explicit PQ target (b)/(c) revisited after reading [CMS19] + NIST PQC criteria; it changes parameters (queries, hash, field), not the fix B/C design.

## Plan

**Phase 0 — restore the skeleton (near-zero new logic)**
1. Add `PLONK_FRI` back to `backend.ID` (`backend/backend.go`).
2. Copy `backend/plonkfri/bn254/{setup,prove,verify}.go` from commit `1ed22f78^` (last commit before deletion).
3. Repoint their one import: `gnark-crypto/ecc/bn254/fr/fri` → `github.com/consensys/gnark/internal/nativefri` (API already matches: `RADIX_2_FRI`, `Iopp`, `ProofOfProximity`, `OpeningProof`, `GetRho`).
4. Add a thin `backend/plonkfri/plonkfri.go` dispatcher, bn254-only case.

**Phase 1 — make it compile against today's code**
5. Fix `constraint/bn254`/`iop.Polynomial` API drift since 2024 (custom gates, lookups, BSB22 commitments were added to `backend/plonk` after PLONK_FRI was deleted — the restored files predate all of that). Expect deletions/renames, not new design.
6. v1 ceiling (explicit scope cut): plain PLONK gates only (`qL,qR,qO,qM,qC` + copy constraints). No custom gates/lookups/BSB22.

**Phase 2 — prove it works**
7. End-to-end test in the shape of `backend/plonk/plonk_test.go`: toy circuit → `plonkfri.Setup` → `Prove` → `Verify`; assert success and assert tamper detection.

**Phase 3 (later, not v1)**: in-circuit verifier / recursion, building on `std/commitments/fri`.

## Pseudocode (mirrors backend/plonk/bn254, KZG replaced by FRI at each seam)

```
type ProvingKey struct {
    Domain[2] fft.Domain            // identical to plonk
    Ql, Qr, Qm, Qo, Qk []fr.Element  // selector polys, identical to plonk
    S1, S2, S3         []fr.Element  // permutation polys, identical to plonk
    Iopp fri.Iopp                    // <- replaces kzg.ProvingKey
}

type VerifyingKey struct {
    Size, Generator, CosetShift ...
    Qpp [5]fri.ProofOfProximity   // <- replaces KZG commitments to Ql,Qr,Qm,Qo,Qk
    Spp [3]fri.ProofOfProximity   // <- replaces KZG commitments to S1,S2,S3
    Iopp fri.Iopp
}

func Setup(ccs) (*ProvingKey, *VerifyingKey, error) {
    build fft domains, selector polys, permutation polys      // identical to plonk/bn254/setup.go
    pk.Iopp = fri.RADIX_2_FRI.New(domainSize, sha256.New())
    for each selector/permutation poly p:
        vk.*pp[i] = pk.Iopp.BuildProofOfProximity(p)           // was: kzg.Commit(p, srs)
}

func Prove(ccs, pk, witness) (*Proof, error) {
    compute + blind wire polys a,b,c                           // identical to plonk
    proof.LRO[i] = pk.Iopp.BuildProofOfProximity(blinded_i)     // was: kzg.Commit
    beta, gamma  = FiatShamir(transcript)                      // transcript absorbs Merkle roots, not G1 points
    Z = permutation grand product
    proof.Z = pk.Iopp.BuildProofOfProximity(Z)                 // was: kzg.Commit
    alpha = FiatShamir(transcript)
    F = qL*a + qR*b + qO*c + qM*a*b + qC + alpha*(perm check)  // identical algebra to plonk
    H0,H1,H2 = split(F / vanishingPoly)
    proof.H[i] = pk.Iopp.BuildProofOfProximity(Hi)              // was: kzg.Commit
    zeta = FiatShamir(transcript)
    for each committed poly p (+ Z at zeta*g):
        proof.Openings[p] = pk.Iopp.Open(p, positionOf(zeta))   // was: kzg.Open / BatchOpenSinglePoint
}

func Verify(proof, vk, publicWitness) error {
    beta, gamma, alpha, zeta = replay FiatShamir from proof's roots
    for each opened poly:
        vk.Iopp.VerifyOpening(position, proof.Openings[p], vk.*pp)  // was: KZG pairing check
    check PLONK identity at zeta using opened values             // identical algebra to plonk/bn254/verify.go
}
```

## Understanding notes: FRI-PLONK mechanics

Captured from a section-by-section design walkthrough of the pseudocode above, using a toy circuit as a running example, plus a full read of the real old `backend/plonkfri/bn254/{prove,verify}.go` (`1ed22f78^`). Read this before touching Phase 0/1 code — it resolves several mechanism questions the pseudocode alone leaves open.

### Toy example used throughout

Circuit: prove `x²·y = out`, `x=3, y=2, out=18`. Two multiplication gates:
```
gate0: a0=x=3, b0=x=3, c0=t=9      (checks x*x=t)
gate1: a1=t=9, b1=y=2, c1=out=18   (checks t*y=out)
```
`n=2`, Domain[0] = `{1,-1}` (generator `g=-1`). Copy constraints: `{a0,b0}` both hold `x=3`; `{c0,a1}` both hold `t=9`.

### Data structures (Section 1)

- **Two FFT domains**: Domain[0] (size `n`, one point per gate) holds selectors/wires directly. Domain[1] (`~4n`) exists because multiplying two degree-`~n` polynomials (e.g. `qM·a·b`) produces degree `~2n-3n`, which *aliases* on an `n`-point domain — two different higher-degree polynomials can look identical there. Toy check: `a,b` have degree `≤1` on the 2-point domain; `qM·a·b` reaches degree `2`, which 2 points can't pin down uniquely.
- **Selector polys** (`qL,qR,qO,qM,qC`): fixed per-gate "which operation" vectors, interpolated over Domain[0]. Toy: `qM=[1,1]`→constant poly `1`; `qO=[-1,-1]`→constant `-1`; others `0`.
- **Permutation polys** (`S1,S2,S3`/`Sid,Sσ`): encode copy constraints as a permutation over the `3n` wire slots, grouped into cycles. Toy: cycle `{a0,b0}`, cycle `{c0,a1}`, fixed points `{b1,c1}`.
- **Basis**: same polynomial, two representations — coefficients (canonical) vs. values-at-domain-points (evaluation/Lagrange); FFT converts between them. Matches real field names: `CQl` (canonical), `LQkIncompleteDomainSmall` (Lagrange, small domain), `EvaluationQlDomainBigBitReversed` (evaluation, big domain, bit-reversed).
- **VerifyingKey substitution**: KZG commitment (1 group element) → `fri.ProofOfProximity` (a full FRI proof: Merkle root + every folding round), baked into VK permanently at setup. Real cost trade-off: FRI VK is materially bigger than KZG's.

### Setup (Section 2)

Build domains/polys as usual, then `pk.Iopp = fri.RADIX_2_FRI.New(domainSize, sha256.New())` (domainSize = Domain[0].Cardinality + 2, padded for blinding), then commit every selector/permutation poly once via `BuildProofOfProximity` (was `kzg.Commit`). Runs once per circuit; cost is amortized into VK size, not paid per-proof.

### Prove, step by step (Section 3)

1. Interpolate wire polys `a,b,c` from the witness, then blind (add random·vanishing-poly) so an opening at a random challenge point later can't leak the witness.
2. Commit blinded `a,b,c` via FRI → `proof.LRO`.
3. Derive `beta,gamma` via Fiat-Shamir (hash of the just-published Merkle roots) — build the permutation grand-product `Z` (see below).
4. Commit `Z` via FRI.
5. Derive `alpha`, combine every "must vanish on the domain" check into one polynomial `F = check1 + alpha·check2 + alpha²·check3` (gate eq + Z's boundary/step conditions) — confirmed structure, see real-code findings below.
6. Quotient `H = F / vanishingPoly` — only divides evenly if the witness is valid. This is the core succinctness trick: one division stands in for `n` separate checks.
7. Split `H` into `H0,H1,H2` (same aliasing/degree reasoning as the two domains), commit each via FRI.
8. Derive `zeta`, open every committed polynomial there. Soundness argument: two different bounded-degree polynomials agree at a random point with negligible probability (Schwartz-Zippel), so one spot-check stands in for a full-domain check.

**`beta`/`gamma`/`Z` in depth**: gate equations only check *within* one gate — nothing stops a cheating prover from submitting an output on one gate and an unrelated input on the next, unless copy constraints are checked separately. Mechanism: give every wire slot a label (`Sid` = its own default label; `Sσ` = the label of whatever slot it's linked to). Toy labels: `Sid=(a0:1,a1:-1,b0:2,b1:-2,c0:3,c1:-3)`, `Sσ=(a0:2,a1:3,b0:1,b1:-2,c0:-1,c1:-3)`. For challenge `beta,gamma`, compute `value + beta·label + gamma` per slot and multiply all six together, once using `Sid` labels and once using `Sσ` labels — if real copy constraints hold, both products match (same multiset of factors, permuted); worked example with `beta=2,gamma=3` gives `216000` both ways. `Z` is the *running* product of these per-step ratios, and lands back on exactly `1` after a full domain pass iff every copy constraint held (toy: `1 → 1.8 → 1.0` exactly). Two challenges rather than one: `beta` ties each slot's *label* into the check (so it verifies "value X is specifically in slot L", not just "value X exists somewhere"); `gamma` is an independent second random shift — together they close off algebraic tricks a single random value would leave open.

**Fiat-Shamir mechanism** (confirmed by reading `gnark-crypto/fiat-shamir/transcript.go`): no live verifier — a hash function simulates one. `Transcript.ComputeChallenge(name) = H(name || previous_challenge_value || all_bound_values)`, chained. Prover commits (publishes Merkle roots) *before* the challenge derived from them exists, so it has zero freedom to pick convenient witness values for a known challenge. The verifier never trusts the prover's claimed challenges — it recomputes all of them itself from the same public data and the final check only passes if the prover used the same ones.

### Verify (Section 4)

Replay Fiat-Shamir from the proof's published roots + public inputs to get `beta,gamma,alpha`, and a `zeta` derived as `GenOpening^position` (see below). `VerifyOpening` does two jobs per polynomial: (1) Merkle-path check (this leaf really is at this position in the committed tree) and (2) low-degree/proximity check (the tree's leaves really are evaluations of *some* bounded-degree polynomial) — job (2) is what "IOPP" means and is unique to FRI; a KZG commitment gets it for free from how it's constructed. Setup polynomials get opened via FRI too, even though they're public, because direct evaluation would cost `O(d)` and break succinctness (this is explicitly called out in the RedShift paper). Final check: recombine `H0,H1,H2→H(zeta)`, rebuild `F(zeta)` from opened values via the same `alpha`-combination as `Prove`, evaluate the vanishing polynomial at `zeta`, and check `F(zeta) =? Z_H(zeta)·H(zeta)` — one scalar equation standing in for the whole circuit having been satisfied.

### Confirmed by reading the real old code (`backend/plonkfri/bn254/{prove,verify}.go` @ `1ed22f78^`)

- **`zeta` is not sampled as an arbitrary field element.** Fiat-Shamir output is reduced mod the FRI domain size (`friSize = 2·rho·vk.Size`) into an integer *position* first; `zeta = vk.GenOpening ^ position` is computed only afterward, purely for the final algebraic check. There is no general "open at an arbitrary point" (RedShift's Algorithm 1 LPC quotient-wrapper) anywhere in this code — it sidesteps that entirely by construction. This resolves what was an open question during the pseudocode walkthrough.
- **No batching, confirmed**: 18 separate `Open`/`VerifyOpening` calls per proof (`ql,qr,qm,qo,qk,l,r,o,h1,h2,h3,s1,s2,s3,id1,id2,id3,z,zshift`), each a full independent FRI proof. Real, measured proof-size cost vs. KZG's one batched opening — a likely future optimization target, out of scope for v1.
- **Public inputs bypass FRI entirely**: `qk` is committed/opened in an "incomplete" form (zeroed at public-input slots); the verifier adds the public-input contribution back in locally via `completeQk()`, a direct Lagrange-basis formula using the public witness it already has — no commitment needed since public inputs aren't secret.
- **Blinding degree isn't uniform**: `L,R,O` blinded with 2 random coefficients (order 1); `Z` blinded with 3 (order 2) — why `Setup`'s FRI domain padding is "+2" (sized for `Z`, the larger case) and why the final verify exponent is `zeta^(Size+2)`, not `zeta^Size`.
- **A naming swap in the real code (harmless, but a trap for future maintainers)** — identical in both `prove.go` and `verify.go`:
  ```go
  beta, err  := deriveRandomnessFixedSize(fs, "gamma", dataFiatShamir...)  // transcript slot "gamma" → Go var beta
  gamma, err := deriveRandomness(fs, "beta", nil)                          // transcript slot "beta"  → Go var gamma
  ```
  Internally consistent (prover and verifier both do the identical swap), so not a bug — do **not** "fix" this when porting without changing both sides identically.
- **Scope cut confirmed real**: `evalConstraintsInd` only computes `ql·l+qr·r+qm·l·r+qo·o+qk` — no custom gates, no lookups, no BSB22 commitments anywhere in this code. Consistent with the v1 ceiling already decided.
- **Not yet checked**: how much `constraint/bn254.SparseR1CS`'s `Solve()`/`SparseR1CSSolution` API has drifted since this code was written (2024) — still a Phase 1 task.
- **Not yet read**: `computeQuotientCanonical`'s coset-FFT trick in detail, and the permutation-index bookkeeping (`pk.Permutation[i]`) in `computeBlindedZCanonical` — flagged as unread, not blocking Phase 0/1 start.

## Security status (current state — read before using or extending plonkfri)

**Sound (fix B) and zero-knowledge (fix C), as of 2026-10-07 — not externally reviewed.** All known forgeries are rejected (attack tests: 0/800, 0/200, 0/50); the values a verifier sees are uniformly random by HK24 Lemma 1/2/4, checked structurally by `TestRevealedValuesAreUniform`. ZK is honest-verifier in the IOP, NIZK after Fiat-Shamir (random-oracle model). Unreviewed research code: do not rely on it for real secrets. Details, measurements and reasoning are in the 2026-10-07 session-log entries below.

A FRI-PLONK proof rests on two promises: (1) every committed table is a low-degree polynomial — FRI's job; (2) those polynomials satisfy the circuit identity, checked at one random point `zeta` — PLONK's job. Soundness is the *weakest* of the checks, so every one must reach the target.

| # | Concern | Protocol part | Effect | Status |
|---|---|---|---|---|
| 1 | FRI checked **1 query** per proof (`nbRounds = 1`) | FRI (`internal/nativefri`) — all 18 commitments | Garbage accepted ~1/8 → ~3 bits; e.g. a pointwise `H = F/Z_H` table passes PLONK at every `zeta`, only FRI could catch it | ✅ Fixed (A): fold once, **86 queries** = 128-bit proven (Johnson bound, ρ=1/8, `s = 2λ/log₂(1/ρ)`) |
| 4 | `VerifyOpening` never tied `ClaimedValue` to the Merkle-authenticated leaf | FRI opening ↔ PLONK final check | Cheater claims any value at `zeta` (solve for `h`) → forgery with probability 1 | ✅ Fixed (A): `ErrClaimedValue` |
| 2 | `zeta` drawn from the 16n-point FRI domain, not the whole field | PLONK final check (`prove.go`/`verify.go`) | Schwartz–Zippel escape up to ~19%; 1/16 of positions put `zeta` in the circuit domain (`Z_H(zeta)=0`) → honest low-degree polys for a witness breaking one gate pass ~1/16. **Measured 2026-10-07** (`attack_test.go`, red until fix B): false statement "X²=5" (5 is a non-square) accepted **36/800 = 4.5%**, all with ζ ∈ H; predicted 1/16·(n−1)/n = 4.69% for n=4 | ✅ Fixed (B): `zeta ∈ F \ (D' ∪ H)`, all values opened by one batched DEEP-FRI. Same attack after B: **0/800** accepted (all rejected by the identity check); solving `h1(zeta)` from the identity and opening the lie: **0/200** (all rejected by FRI folding) |
| 3 | Blinding (2 coeffs L/R/O, 3 for Z) vs values revealed by queries + openings | PLONK prover blinding (`prove.go`) | Zero-knowledge (privacy) only, not soundness; with 86 queries it clearly leaks | ✅ Fixed (C): l/r/o/z blinded with 174 random coefficients, h1/h2/h3 split randomized (173), mask R in every FRI opening. `TestRevealedValuesAreUniform`: full rank on all revealed points (was rank 2–3 vs ~160 points) |
| 5 | FRI domain is a subgroup ⊇ circuit domain H (no coset shift) | FRI domain (`nativefri.newRadixTwoFri`) | ZK only: queries landing in H (1/16) reveal raw wire values, blinding vanishes there. **Measured 2026-10-07:** 60-secret-wire circuit, one proof → L/R/O each reveal 172 codeword values, of which 9/5/11 are raw secret wire values (expected 172/16≈11) | ✅ Fixed (B): FRI on coset `a·D`; regression test: 0 of 516 revealed values are secret wire values |
| 6 | Transcript doesn't bind the verifying key / circuit | Fiat-Shamir in `prove.go`/`verify.go` | "Weak Fiat-Shamir" class [DMWG23]; matters if the VK can be chosen adversarially | ✅ Fixed (B): VK digest + public inputs bound first; the batched opening's transcript also binds every root and claim |

Parameter choice (decided 2026-10-07): **proven** 128-bit, not conjectured. Rationale: once FRI folds once, query count costs only proof size/verify time, not prover time (RedShift §6–7), and the proven regime keeps knowledge-soundness extractable. Conjectured alternative (43 queries, ~half the size) remains an opt-in for later. Sources: `resources/2020-654.pdf` §3.2/§8 (2λ/log(1/ρ) proven for q ≫ n²; λ/log(1/ρ) conjectured), `resources/2019-1400.pdf` Table 1, `resources/Revision2OfTR17-134.pdf` Thm 3.3 / Conj. 1.5.

Lessons that generalize: (a) passing honest-proof tests says nothing about soundness — every check needs a test that a *cheating* prover is rejected; (b) any value the verifier uses must be bound to something it verified (here: `ClaimedValue` ↔ leaf, `ID` ↔ `Roots[0]`, layer sizes computed not trusted); (c) measure acceptance rates empirically — the 1/8 measurement exposed concern 1 before the theory did. From fix B: (d) write the attack test *before* the fix and check its measured rate against a prediction (36/800 vs 4.69% predicted) — a match confirms the cause, not just a correlation; (e) record *which* check rejects each cheater: the in-domain-zeta forgery is caught by the identity check, the lie-at-zeta by FRI folding, so each defence is shown to do its own job (tampering with transcript inputs is caught indirectly — query positions move — and does not test folding); (f) anything prover and verifier must agree on (claim order → batching coefficients, transcript order) comes from one shared function, not two copies; (g) estimate before measuring (0.9 MB estimated, 0.84 MB measured) so surprises are visible. From fix C: (h) privacy can't be tested by sampling (every 254-bit value looks random) — test the structural condition the proof relies on (full rank of the blinding map on the revealed points), red first; (i) demonstrate a design rule by showing the attack it prevents succeeding without it (crafted mask: 50/50 unsafe vs 0/50), and make the test fail if the attack stops working, so it can't become vacuous; (j) re-derive a formula on the *old* parameters and match the old code before using it with new ones (piece size n+2 ✓ → n+231); (k) when a struct gains a field, check every copy helper (mask `clone()` bug); (l) to measure old behaviour, use a `git worktree` at the old commit, not `git stash`.

## Literature basis for the security plan (checked 2026-10-07)

Every planned protocol change maps to a specific, published construction in `resources/`. Engineering-only steps (Step 0, serialization, Merkle internals) need no paper.

| Change | Source (in `resources/`) | What it says |
|---|---|---|
| Fix A: query count (done) | `2020-654` §3.2, §8 (Lemma 8.2, Conj. 8.4); `2019-1400` Table 1; `Revision2OfTR17-134` Thm 3.3 / Conj. 1.5 | s ≈ 2λ/log(1/ρ) proven for q ≫ n²; λ/log(1/ρ) conjectured |
| Fix B: why in-domain `zeta` is weak | `2019-336` §6.3 (DEEP-ALI vs ALI) | ALI samples "at random locations from the evaluation domain" → distance bound stuck at 1/8; sampling `z` from the whole field fixes it ("DEEP": Domain Extension for Eliminating Pretenders) |
| Fix B: `zeta ∈ F \ D` | `2019-1400` Algorithm 2, step 10 | "V sends P a random evaluation point y ∈ F\D" — also the step PLONK opens at (incl. `y·g` for the grand product) |
| Fix B: proving `f(z)=v` with FRI | `2019-1400` §1.2.1 + Algorithm 1 (LPC); `2019-336` Protocol 6.4 step 6 (QUOTIENT) | q(X) = (f(X) − U(X)) / Π(X − zᵢ), FRI on q with degree d − N; verifier simulates q from f's oracle (no extra commitment); correctness by Bézout |
| Fix B: batching all openings into one FRI | `2019-1400` §8.1 + Appendix G (Batched FRI, Thm 8 / Cor. 1); `2020-654` §8 "Batching" + Lemma 8.2 | FRI on Σ αⁱ⁻¹ fᵢ with verifier-chosen α; batched soundness error bounded via correlated agreement |
| Fix B: binding for *setup* polys | `2019-1400` §4.3 (PES, Defs. 11–12, Thm 5) | Beyond the unique-decoding radius a Merkle root can be close to several polynomials (a *list*); witness polys only need existence, but setup polys need uniqueness → add "distinguishing" evaluation points fixed at setup. **Design decision to make in B1.** |
| Fix C: blinding degree | `2019-1400` Appendix D.3 (ZK proof), §5 remark | Mask `Z(X)·Hᵢ(X)` with deg Hᵢ ≥ \|Kᵢ\| = number of points where fᵢ is revealed; sampling y outside D gives *perfect* ZK |
| Fiat-Shamir safety of the whole thing | `2019-1400` Thm 7 (round-by-round knowledge soundness) | RBR soundness is what makes the non-interactive (hashed) version sound |

Added to `resources/` 2026-10-07: `2021-582` (ethSTARK Documentation v1.2), `2022-1216` (Haböck, A summary on the FRI low degree test, Dec 2024 rev.), `2023-1071` (Block et al., Fiat-Shamir Security of FRI and Related SNARKs).

| Change / question | Source | What it says |
|---|---|---|
| Fix B protocol as a whole | `2023-1071` §2.4 (OPlonky), §6–7 | Our post-B design (zeta ∈ F, one batched FRI over `(f(X)−f(z))/(X−z)`) is their "OPlonky" ≈ Plonky2; they prove RBR (knowledge) soundness → FS-secure. Non-FRI error terms (`rn/|F|`, `(k+s)/|F|`, `deg·n/|F|`) negligible in bn254. |
| FS security of (batched) FRI | `2023-1071` Cor. 4.3/4.4; `2021-582` Def. 9, Claim 1, Thm 7 | `ε_fs = Q·ε_rbr + 3(Q²+1)/2^κ` for a Q-hash attacker; "λ bits" ⇔ `ε_rbr ≤ 2^-λ` and digest ≥ 2λ (sha256 OK for 128). |
| Exact query count | `2022-1216` Thm 2 (= BCIKS20 Thm 8.3), §3.5; `2021-582` §5.10.2 | Error = `ε_C + (√ρ(1+1/2m))^s`. Recomputed for bn254 (|F|≈2^253.6), ρ=1/8: **s=86 gives ≈128.8–129 bits** (m≈40+); strict half/half split → 87. 86 stands. |
| Batching w/ different degree bounds | `2022-1216` §1 | "degree correction factors … are not needed for the DEEP method." |
| Grinding (optional) | `2021-582` §3.11.3, §6.3 Thm 6 | Proof-of-work nonce before queries multiplies the query-round error by 2^-z; e.g. z=20 saves ~13 queries. |

### Additional considerations found (not previously in the plan)

1. **ZK leak via the FRI domain (`2022-1216` §3.7).** FRI must run on a coset `a·D` disjoint from the circuit domain H. Ours is a plain subgroup (`fft.NewDomain`) ⊇ H, and blinding `Z_H·(…)` vanishes on H → each query landing in H (1 in 16) reveals raw wire values; ~10 per witness polynomial per proof at 86 queries. Fix: coset FRI domain. Also required by fix B (quotient `1/(x−zeta)` and `zeta ∉ D ∪ H`). → fold into **B**.
2. **ZK of the FRI folding oracles (`2022-1216` §3.7, ref. [HK24]).** "crucial to add a separate blinding polynomial h(x) to the batch". Masking the inputs (RedShift D.3) is not sufficient alone. → part of **C**. Reference to fetch: Haböck & Al Kindi, *A note on adding zero-knowledge to STARKs* (ePrint 2024/1037 — verify).
3. **Weak Fiat-Shamir (`2023-1071` ref. [DMWG23]).** Transcript binds public inputs + proof roots but **not the verifying key** (selector/permutation/id roots) or circuit. Standard hardening: bind a VK digest first. → add to **B**. Reference to fetch: Dao, Miller, Wright, Grubbs, *Weak Fiat-Shamir Attacks on Modern Proof Systems* (IEEE S&P 2023; ePrint 2023/691 — verify).
4. **Post-quantum security level is ~half the classical one (`2023-1071` Cor. 4.3/4.4).** Quantum adversary: error `Θ(Q²·ε_rbr)` → 128 classical bits ≈ 64 PQ bits. 128-bit PQ would need ~172 proven queries, and the commit-phase term `~|D|²/|F|` in a 254-bit field caps *proven* PQ security near ~100 bits for |D|≈2^20 (would need an extension field / bigger field beyond that). **Decision needed: state the target as classical bits (industry norm) or set a PQ target.**
5. **Setup-polynomial binding (RedShift §4.3 PES)** — likely moot for us: setup is deterministic and the VK roots are re-derivable from the circuit, so committed setup words are exact codewords; distinct codewords are ≥ 1−ρ = 0.875 apart > δ ≤ 1−√ρ ≈ 0.646, so no other polynomial is δ-close. **Resolved in B1 (D9):** no PES needed; preprocessed oracle is checked by every batched FRI.
6. **Query sampling** `H(seed‖j) mod |D|` with |D| a power of two is unbiased; sampling with replacement matches the analysis. No change.

### Post-quantum target — what the literature gives us (checked 2026-10-07)

Only `2023-1071` (Block et al.) states quantum bounds; every other paper says "plausibly post-quantum" and cites **[CMS19]** (Chiesa–Manohar–Spooner, *Succinct Arguments in the Quantum Random Oracle Model*, TCC 2019) for the underlying theorem. `2023-1071` Thm 3.15 (from [BCS16, CMS19, COS20]):
- classical: `ε_fs = Q·ε_rbr + 3(Q²+1)/2^κ`
- quantum: `ε_qfs = Θ(Q·ε_fs) = Θ(Q²·ε_rbr + Q³/2^κ)` (κ = hash digest bits)

Consequences for us (bn254 fr, sha256):
1. **Protocol term** `Q²·ε_rbr`: λ_q PQ bits need `ε_rbr ≤ ~2^-2λ_q` → 128 classical bits (86 queries) ≈ **64 PQ bits**; 128 PQ bits ≈ 172 proven queries. This matches the generic Grover attack on Fiat-Shamir (search for a lucky transcript in ~√(1/ε) quantum queries), so the square-root loss is essentially inherent, not a proof artifact.
2. **Hash term** `Q³/2^κ`: λ_q needs `κ ≥ ~3λ_q` → **sha256 caps PQ security at ~85 bits** (128 PQ would need a 384-bit digest). This is the Brassard–Høyer–Tapp 2^(κ/3) collision bound; whether that is the right *cost* model is disputed (Bernstein 2009 argues quantum collision search is not cheaper than classical in realistic hardware) — NIST's PQC criteria rate SHA-256 collision as Category 2.
3. **Commit-phase term** `~|D|²/|F|` in a 254-bit field caps *proven* PQ soundness near ~100 bits for |D|≈2^20.
4. Θ hides constants; the bounds are asymptotic → treat PQ numbers as estimates.
→ Realistic options: (a) state classical 128 bits and "plausibly PQ" (industry norm: ethSTARK, Plonky2, RedShift all do this); (b) target an explicit PQ level ≤ ~85 bits with sha256 + ~2× queries; (c) for ≥128 PQ: 384-bit hash, ~172+ queries, and likely an extension field.
Sources to obtain/verify (not yet in `resources/`, IDs from memory): [CMS19] ePrint 2019/834; Chiesa & Yogev, *Building Cryptographic Proofs from Hash Functions* (2024 book, free online; full BCS/QROM treatment); NIST PQC *Submission Requirements and Evaluation Criteria* (2016) §4.A.5 (security categories); Brassard–Høyer–Tapp 1997 (*Quantum cryptanalysis of hash and claw-free functions*); Bernstein 2009 (*Cost analysis of hash collisions: will quantum computers make SHARCS obsolete?*).

### Findings from `2023-691` (weak F-S) and `2024-1037` (HK24, ZK for STARKs)
- **Strong F-S** (`2023-691` Def. 3): `cᵢ = H(pp, x, a₁…aᵢ)` — public parameters (for PLONK: the preprocessed/index polynomials = our VK) **and** public inputs **and** all prover messages. Their Plonk attack exploits unbound *public inputs*; we do bind public inputs (not vulnerable to that attack), but not `pp`/VK → consideration 3 stands (bind VK digest first). Their mitigation advice: declare all transcript inputs up front and fail if any is missing.
- **ZK opening protocol** (`2024-1037` Protocol 2): openings at `z ∈ F \ (D ∪ H)` + a separate mask polynomial `R(X)` in the batch; without `R` each FRI fold halves the randomizer space → leaks (confirms considerations 1–2).
- **Quotient split** (`2024-1037` §1, §4): our `h1,h2,h3` monomial split is randomizable, but the pieces must be randomized too → part of fix C.
- **Permutation argument** (`2024-1037` App. A): the grand product reveals "challenge ≠ any witness value"; negligible for *statistical* ZK in a 254-bit field with one challenge; perfect ZK needs extra modifications (optional).

## Open questions / next steps

Done: Phase 0–2 (restore, compile, shared circuit suite 30/30); security fix A (86-query FRI, opening/ID binding) — PRs #1–#3 merged 2026-10-07.

**Step 0 — `master` red → done 2026-10-07 (stopgap).** `std/commitments/fri/fri_test.go` (in-circuit gadget, PR #2) builds native proofs with `nativefri` and stopped compiling after fix A changed the proof format. Missed at PR #2 resolution because only textual conflicts were checked, not compilation of the merged result — always compile/test the *combined* tree (`go build ./... && go test -run XXX ./...` compiles every test package).
- Why not just reshape the proof in the test: the gadget and nativefri now disagree on *which positions are queried* (gadget: `seed mod |D|`, one query; nativefri: `H(seed‖j) mod |D|`, 86 queries), not only on the struct layout → a real port, i.e. Phase 3 work.
- Done: test gated behind build tag `fri_gadget_phase3` with a TODO header explaining the mismatch. `go test -tags fri_gadget_phase3 ./std/commitments/fri/` still reproduces the breakage. Port it in Phase 3 (one commit phase, s queries, H(seed‖j) positions in MiMC, root/ID binding), then drop the tag.

**Step 1 — Fix B: out-of-domain `zeta` (DEEP), coset domain, batched opening, VK binding. Blocks "sound".**
**✅ Done 2026-10-07** (B1 design → B4 red test → B2 → B3).
- B1 design: **approved 2026-10-07 — see "Fix B design (B1)" below.** Covers considerations 1, 3, 5 (coset domain, VK digest, setup binding).
- **B4 red test written first (2026-10-07):** `TestForgeryZetaInDomain` — fails today (36/800 forgeries accepted), must pass (0) after B3. Branch stays unmerged until then.
- **B2 done (2026-10-07):** `internal/nativefri/batch.go` (`Scheme`, `Commit`, `Open`, `Verify`) + `batch_test.go`, alongside the old API (removed in B3). 
- **B3 done:** setup/prove/verify on `Scheme`; old per-polynomial `nativefri` API removed. B4 tests: in-domain-zeta forgery 0/800, lie-at-zeta 0/200, witness-leak 0/516.

**Step 2 — Fix C: zero-knowledge. C1 design drafted 2026-10-07 — see "Fix C design (C1)" below; decisions 1–3 approved (173, mask always on, larger tiny proofs). C2 red test written 2026-10-07 (`zk_test.go`, fails as intended). C3 done (mask R in nativefri). C4 done (blinding + randomized split; `TestRevealedValuesAreUniform` green). C5 done. ✅ Fix C complete.** Original note: Also add a separate random blinding polynomial to the FRI batch (consideration 2, [HK24]). After B the exact count is known: each committed poly is revealed at ~2·86 FRI positions + its `zeta` openings → blinding degree must be ≥ that; FRI degree bound/domain sizing must absorb it. RedShift samples outside D for perfect ZK — check §6.

**Decided — security target (consideration 4):** option (a), classical 128 bits + "plausibly PQ" (see Design decisions). To revisit: explicit PQ target after reading [CMS19] / Chiesa–Yogev / NIST PQC criteria; optional grinding to trade queries for prover work.

**Step 3 — Malicious-prover test harness.** A reusable way to build deliberately bad proofs (lying openings, pointwise-H, bad-gate witness) so every soundness claim has a test that a cheater fails. Largely built during B4/C3: `prove(…, transcriptPublic)`, `testHookBeforeOpen`, `Scheme.commit`/`commitEvals`/`open(…, mask)`, `firstClaimPower`. Remaining: collect them behind one documented test helper; add pointwise-H and wrong-permutation cheaters.

**After "sound + ZK"** → see **"Follow-ups (after fixes A–C)"** below (F1–F12, prioritized).

## Follow-ups (after fixes A–C) — recorded 2026-10-07

Status at this point: plonkfri on bn254 is sound (fix A + B) and honest-verifier zero-knowledge (fix C) by construction, with a test per mechanism; **not externally reviewed**. Items are grouped by when they matter; within a group, roughly by priority. Each has a "done when" so it can be worked test-first like A–C.

### Before any real use
| # | Follow-up | Why | Approach | Done when |
|---|---|---|---|---|
| F1 | **External review** of fixes A–C | All analysis and tests so far are self-made; a reviewer catches what the author can't (the `ClaimedValue` hole was only found by re-reading). | Hand a reviewer PROJECT.md (designs B1/C1 with sources) + the attack/ZK tests as the claims to check. | Review findings triaged; each accepted finding has a red test → fix. |
| F2 | **Proof / VK serialization** (`WriteTo`/`ReadFrom`, as in `backend/plonk`) | No format exists: proofs can't leave the process. Parsing is also an attack surface (malformed lengths, non-canonical field elements). | Length-prefixed fields; decode field elements with `SetBytesCanonical`; reject trailing bytes. | Round-trip test; fuzz test (`go test -fuzz`) never panics; serialized size matches `proofSize`. |
| F3 | **Concurrency:** `nativefri.Scheme` holds one `hash.Hash` | A VK shared by goroutines (normal in a server) races on the hash state → wrong challenges / spurious rejects. Pre-existing (old `Iopp` had the same). | Store a hash constructor (`func() hash.Hash`) and create a hasher per Commit/Open/Verify call. | `go test -race` with parallel Verify/Prove on one VK passes. |

### Robustness of the security claims
| # | Follow-up | Why | Approach | Done when |
|---|---|---|---|---|
| F4 | **Malicious-prover harness** (old Step 3) | Every soundness claim should have a cheater that fails. The pieces exist but are scattered: `prove(…, transcriptPublic)`, `testHookBeforeOpen`, `Scheme.commit`/`commitEvals`/`open(…, mask)`, `firstClaimPower`. | One documented test helper; add cheaters not yet covered: pointwise-H table, broken copy constraint (wrong permutation), wrong `z(ω·ζ)`, wrong public-input row, h pieces swapped. | Each cheater has a test with measured acceptance 0/N and the rejecting check recorded (lesson (e)). |
| F5 | **Reconcile HK24's quotient-randomizer count** (87, eq. (9)) with ours (173) | We use 173 because we count the pair {x, −x} per FRI query; if HK24 is right with 87 we pay ~86 extra coefficients per piece — harmless, but the discrepancy means one of the two counts is misunderstood. | Re-read `2024-1037` Lemma 4 + Protocol 2 for how a FRI query's sibling point is counted; check against `TestRevealedValuesAreUniform` (it reports actual revealed points: 171 for h). | Written explanation in C.7; keep 173 unless the explanation is airtight. |

### Cost
| # | Follow-up | Why | Approach | Done when |
|---|---|---|---|---|
| F6 | **Proof size** (0.90 MB at 65k; KZG < 1 KB) | Size is the main practical cost of FRI-PLONK. | Merkle caps / shared upper path nodes across 86 queries; optional grinding (`2021-582` §3.11.3: ~20 bits of work saves ~13 queries); conjectured-regime 43 queries as an explicit opt-in (decided against as default). | Each option measured with `TestPerfRef` against the C.8 table; security impact written down. |
| F7 | **Prover time** (2.1 s at 65k vs KZG 0.65 s) | Second practical cost. | Profile first (`go test -cpuprofile`); suspects: per-commitment coset FFTs at |D| = 16n, Merkle hashing (sequential sha256), evaluating at ζ by Horner. Parallelize hashing; reuse FFTs. | Profile recorded; each change measured. |
| F8 | **Tiny circuits** (2 constraints → 0.43 MB, DegreeBound ≥ 512) | ZK blinding adds ~400 coefficients regardless of n (decision C7). Matters only if many tiny proofs are produced. | Accept unless a use case needs it; the revealed-point count (≤ 1 + 2·86) doesn't shrink with n, so the blinding can't either — only the domain could be sized more tightly. | Decision recorded with a use case, or closed as won't-fix. |

### Research decisions to revisit
| # | Follow-up | Why | Approach | Done when |
|---|---|---|---|---|
| F9 | **Post-quantum target** (decided: classical 128, "plausibly PQ") | ≈ 64 PQ bits today; sha256 caps PQ at ~85 bits. | Read [CMS19] (ePrint 2019/834), Chiesa–Yogev book, NIST PQC criteria §4.A.5, BHT97, Bernstein 2009; decide (a)/(b)/(c) of "Post-quantum target". | Decision + parameters (queries, hash, field) recorded. |

### Later phases
| # | Follow-up | Why | Approach | Done when |
|---|---|---|---|---|
| F10 | **Phase 3: in-circuit verifier** | Recursion / on-chain verification. The gadget (`std/commitments/fri`) still implements the pre-fix-A 1-query FRI; its test is gated (`fri_gadget_phase3`). | Port A–C to the gadget (86 queries, H(seed‖j) positions, DEEP batch, coset, mask), Poseidon2 instead of sha256/MiMC for in-circuit cost. | Gated test un-gated and green; native and in-circuit verifier agree on the same proofs. |
| F11 | **Features:** BSB22 commitments (`api.Commit`), more curves | `commit`, `gkr_cube` circuits are skipped (`ErrCommitmentsUnsupported`); only bn254. | Commitments need an extra committed polynomial + transcript binding; curves are copy/codegen of `bn254`. | Suite runs those circuits; other curves pass the suite. |
| F12 | **Housekeeping:** `internal/stats/generate/main.go` | Manual stats tool doesn't know `PLONKFRI` (noted in Phase 0; non-blocking, not part of tests). | Teach it plonkfri or skip it explicitly. | `go run ./internal/stats/generate` works. |

## Fix B design (B1) — approved 2026-10-07

### B.0 The problem, in one paragraph
PLONK reduces "the witness satisfies the circuit" to one polynomial identity, checked at one random point `zeta`. That check is only convincing if `zeta` is unpredictable among *all* field elements (Schwartz–Zippel: two different degree-d polynomials agree on ≤ d points out of |F| ≈ 2^254). Today `zeta = GenOpening^position` is one of only 16n FRI-domain points, because our opening mechanism (`VerifyOpening` = a Merkle path) can only reveal values the prover already wrote down — i.e. points of D. So the bad-point fraction is ~d/16n instead of ~d/2^254, and 1/16 of the time `zeta ∈ H` where `Z_H(zeta)=0` makes the check vacuous (concern 2). No parameter fixes this: we need a way to prove `f(z)=v` for a `z` the prover never committed to. That is the DEEP method.

### B.1 The idea (DEEP quotient), why it works
To prove `f(z) = v` for committed `f`: the polynomial `f(X) − v` has a root at `z` **iff** `f(z)=v`, and then `q(X) = (f(X) − v)/(X − z)` is a polynomial of degree deg f − 1. If `f(z) ≠ v`, `q` is not a polynomial — FRI rejects it as far from low-degree. The verifier never needs `q` committed: at any FRI query point `x` it computes `q(x) = (f(x) − v)/(x − z)` from the opened `f(x)` (`2022-1216` §4.1.1: "evaluations on D can be computed from the values of p(x)"). Requires `z ∉ D` (no division by 0). All claims are batched with powers of one challenge `λ` into a single FRI. Source protocol: **`2022-1216` §5.2 Protocol 3 + Theorem 8 (DEEP-ALI)** — "Plonk … can be treated similarly"; for PLONK specifically `2023-1071` §2.4 "OPlonky" (≈ Plonky2), with a Fiat-Shamir proof.

### B.2 Target protocol after fix B
Notation: n = |H|, u = coset shift for the permutation (`CosetShift`), ω = generator of H, FRI code RS[k=2n, |D|=16n] (ρ=1/8), D' = a·D the shifted FRI domain.

**Setup** (deterministic from the circuit)
1. Interpolate ql, qr, qm, qo, qk_incomplete, s1, s2, s3 (8 polys). Evaluate on D'; one Merkle tree, leaf i = the 8 values at point i → root `C_pre`.
2. VK = {n, u, ω, a, ρ, nbQueries, nbPublic, `C_pre`}; `vkDigest = H(VK)`. VK becomes O(1) size (today it carries 11 FRI proofs + 6 full polynomials).

**Prove** — one transcript throughout (strong Fiat-Shamir, `2023-691` Def. 3):
1. Bind `vkDigest`, public inputs.
2. Commit L, R, O (blinded as today) on D' → one tree, root `C_lro`. Bind → derive β, γ.
3. Commit Z → root `C_z`. Bind → derive α.
4. Compute h, split h1, h2, h3 → one tree, root `C_h`. Bind → derive ζ ∈ F. **Reject if ζ ∈ D' ∪ H** (checks: `ζⁿ ≠ 1`, `(ζ/a)^|D| ≠ 1`; probability ~2^-230).
5. Send evaluations at ζ: l, r, o, z, h1, h2, h3, ql, qr, qm, qo, qk, s1, s2, s3 (15 values), and z(ωζ). Bind all → derive λ.
6. Batched FRI on `q(X) = Σᵢ λⁱ (fᵢ(X) − fᵢ(ζ))/(X − ζ) + λ¹⁵ (Z(X) − Z(ωζ))/(X − ωζ)`. Layer 0 is *virtual* (never committed); FRI folding challenges and query seed continue the same transcript. 86 queries; each query opens the 4 trees at the sibling pair (x, −x) plus the usual FRI layer paths.

**Verify**
1. Rebuild the transcript identically (`vkDigest`, public inputs, roots, evaluations) → β, γ, α, ζ, λ. Reject if ζ ∈ D' ∪ H.
2. Compute itself: `Id_k(ζ) = uᵏ·ζ` (confirmed in `setup.go:getIDSmallDomain`: Id values are `uᵏ·ωⁱ`), `L₁(ζ)`, `PI(ζ)` (already done), `Z_H(ζ)`.
3. Check the PLONK identity at ζ with the 16 sent values (same formula as `verify.go` today).
4. Verify the batched FRI; at each query compute q(x), q(−x) from the 4 opened leaf rows, check Merkle paths against `C_pre, C_lro, C_z, C_h`, then the folding chain as today.

### B.3 Design decisions (each with the reason)
| # | Decision | Why | Source |
|---|---|---|---|
| D1 | ζ from the whole field, reject if in D' ∪ H | Restores Schwartz–Zippel over F; ζ ∈ H would make `Z_H(ζ)=0`, ζ ∈ D' divides by 0 | `2022-1216` Protocol 3 step 2; `2019-1400` Alg. 2 step 10 |
| D2 | FRI domain = coset `a·D`, a = `FrMultiplicativeGen` | H ⊂ D (both 2-adic subgroups, \|H\| divides \|D\|) → today 1/16 of queries hit H where blinding vanishes; **measured leak** (table row 5). a generates F*, so a ∉ D and a·D ∩ H = ∅ (cosets of D are disjoint from D ⊇ H). Implemented as FRI on `f(a·X)` over D (`2022-1216` §3.7) | `2022-1216` §3.7; `2024-1037` Protocol 2 |
| D3 | One batched FRI over all DEEP quotients, powers of λ; Z's two points (ζ, ωζ) as two separate terms | One FRI instead of 18 (size, verify time). Separate terms are simpler than the multi-point quotient (`2022-1216` §4.1.3) and only add one batch term. Algebraic (powers-of-λ) batching error grows with #terms (16) — negligible in bn254 | `2022-1216` §3.3 + Thm 2, Protocol 3 step 4; `2019-1400` App. G |
| D4 | No degree-correction factors | All quotients have degree ≤ n+1 < k = 2n; the PLONK identity's degree only enters the negligible Schwartz–Zippel term | `2022-1216` §1, §4.1.2; Thm 8 |
| D5 | One Merkle tree per prover round; leaf = all that round's polys at one point (4 trees: pre, LRO, Z, H) | A query opens every poly at the same x anyway → one path per round instead of per poly. Sibling pair (x, −x) kept adjacent as today → one path covers both | `2021-582` §3.5 item 1 ("group all field elements in a trace LDE row into a single Merkle leaf") |
| D6 | Drop the Id1..3 commitments; verifier computes `uᵏ·ζ` | They are public linear functions; committing them costs 3 trees' worth of openings for nothing | code (`getIDSmallDomain`) |
| D7 | Strong Fiat-Shamir: single transcript, `vkDigest` first; FRI challenges continue the PLONK transcript | Consideration 3 (weak F-S). Today each FRI proof starts a fresh transcript; with a virtual layer 0 the first fold *must* depend on ζ, λ and the evaluations or the prover could choose them after seeing the folding challenges | `2023-691` Def. 3 + mitigations; `2023-1071` (BCS over the whole IOP) |
| D8 | Keep **86 queries** | FRI code is RS[2n, 16n]: ρ = 1/8 exactly (the k⁺ = k+2 adjustment of Thm 8 is absorbed by our slack: quotient degree ≤ n+1 < 2n). Extra DEEP terms of Thm 8: `L⁺·(C/|F| + (d(k⁺−1)+(k−1))/(|F|−|D∪H|))` ≈ 2^7·2^19/2^254 ≈ 2^-228 at n=2^16 → ε_FRI (2^-128.8) dominates | `2022-1216` Thm 8, Thm 2 |
| D9 | Setup-binding (consideration 5): **no PES points, no VK proximity proofs** | The preprocessed oracle `C_pre` enters every batched FRI, so its proximity is checked in every proof. Uniqueness: honest setup words are exact codewords, distinct codewords are ≥ 1−ρ = 0.875 apart > δ ≤ 0.646 → no other polynomial is δ-close. Assumption (same as KZG PLONK): VK is produced honestly / re-derivable from the circuit | `2019-1400` §4.3 (why PES exists); `2022-1216` §4.2 |
| D10 | FRI degree bound k becomes an explicit parameter (`k = NextPow2(maxdeg+1)`), not `2·Size` hard-coded in 3 places | Fix C adds blinding of degree ~2·86+ which exceeds 2n for small circuits; also removes the `friSize = 2·rho·Size` coupling that broke the tiny-circuit fix earlier | lesson from `minDomainSize` bug |

### B.4 Code plan
- **B2 `internal/nativefri`**: coset domain; `Commit(polys [][]fr.Element) → (root, *Committed)` (multi-poly leaves, sorted sibling layout); `BatchOpen(fs, commitments, claims) → OpeningProof` (virtual layer 0, transcript passed in) and `VerifyBatchOpen(fs, roots, claims, proof)`; explicit degree bound. Keep the 86-query, Merkle and folding code from fix A. Tests: completeness; lying evaluation rejected; poly of too-high degree rejected; tampered leaf/row rejected; ζ ∈ D' rejected; transcript-order (changing any claim changes every FRI challenge).
- **B3 `backend/plonkfri/bn254`**: setup builds `C_pre` + `vkDigest`; prove/verify follow B.2; delete per-poly `ProofOfProximity`/`OpeningProof` fields, `Idpp`, `IdCanonical`, `SCanonical`, `GenOpening`. Before B3, read the two unread prover functions (`computeQuotientCanonical` permutation part, `computeBlindedZCanonical` bookkeeping).
- **B4 adversarial tests, written red-first (as with fix A's `ErrClaimedValue`)**: (a) witness breaking one gate, prover commits honest-degree polys and retries until ζ ∈ H — measure acceptance today (expected ~1/16), must be 0 after B; (b) lie about one evaluation at ζ; (c) ZK-leak probe from row 5 turned into a test: 0 raw wire values revealed.

### B.5 Expected effect (estimates written before coding; measured results below)
- Soundness: concern 2 closed; overall ≈ 128 bits (D8).
- Proof size at 65k constraints: ~0.9 MB (4 tree openings ≈ 3.5 KB/query + FRI layers ≈ 7 KB/query, × 86) vs 4.8 MB today.
- Verify: 1 FRI instead of 18 → roughly 10× faster; VK shrinks from O(n) to O(1).

**Measured after B3** (`PLONKFRI_PERF=1 go test -run TestPerfRef -v ./backend/plonkfri/bn254/`, same `refCircuit` and machine as earlier rows):

| constraints | | setup | prove | verify | proof |
|---|---|---|---|---|---|
| 4094 | fix A | 260 ms | 383 ms | 39 ms | — |
| 4094 | **fix B** | **49 ms** | **122 ms** | **2.6 ms** | **0.60 MB** |
| 65534 | fix A | 4.1 s | 6.8 s | 69 ms | ≈4.8 MB (proximity proofs alone) |
| 65534 | **fix B** | **0.75 s** | **1.97 s** | **4.5 ms** | **0.84 MB** (estimate ~0.9) |

KZG PLONK at 65534 for reference: setup 0.16 s, prove 0.65 s, verify 1.3 ms, proof < 1 KB.

### B.6 Questions for review — answered 2026-10-07: yes to all three (multi-poly leaves; reject ζ ∈ D' ∪ H; accept 2× FRI size for now)
1. **D5 multi-poly leaves** — recommended; the alternative (one tree per poly) is a smaller diff but keeps ~15 Merkle paths per query.
2. **D1 on ζ ∈ D' ∪ H**: reject (honest prover fails with prob ~2^-230) vs re-derive with a counter. Recommended: reject — simpler, standard.
3. FRI code is 2× larger than needed (degrees ~n+3 force k = 2n). Accept for now; optimization later (e.g. smaller blinding or splitting).

## Fix C design (C1) — drafted 2026-10-07, decisions approved

### C.0 The problem, in one paragraph
Zero-knowledge means: everything the verifier sees could have been produced without the witness. The verifier sees each secret polynomial (l, r, o, z, h1–h3) at up to **174 points** — ζ, ω·ζ (z only), and the pair {x, −x} of each of the 86 FRI queries — plus every folded FRI layer value. Today l, r, o carry 2 random coefficients, z 3, h1–h3 none, and the FRI layers have no mask. After fix B the raw-wire leak on H is gone (0/516), but the revealed values are still functions of the witness with far too little randomness to hide it.

### C.1 The idea, and why it works (HK24 Lemma 1)
Blind a witness polynomial as `ŵ(X) = w(X) + Z_H(X)·r(X)` with r uniformly random with `b` coefficients. On H nothing changes (`Z_H = 0` there), so the circuit identity still holds. At any revealed point x ∉ H, `ŵ(x) = w(x) + Z_H(x)·r(x)`. If there are m ≤ b distinct revealed points, the map `r ↦ (Z_H(xᵢ)·r(xᵢ))ᵢ` is a (scaled) m×b Vandermonde map of **full rank m** — so it hits every vector of values equally often, and the revealed values are uniformly random **whatever w is**. That is the whole argument; it needs (1) points outside H (fix B's coset + ζ ∉ H) and (2) `b ≥ number of distinct revealed points`. Source: `2024-1037` Lemma 1 (with e = 1: we work in the base field, no extension), RedShift `2019-1400` App. D.3.

The same idea is applied twice more: to the quotient pieces (they are revealed too, `2024-1037` §4.1, Lemma 4) and to the FRI folding layers via a mask polynomial (`2024-1037` Protocol 2, Lemma 2) — blinding the inputs does not protect the folds, because each fold halves the randomizer space (`Z_H` is even, so `Z_H·F[X]<b` folds into `Z_{H²}·F[X]<b/2`) while the witness part keeps its structure (`2024-1037` §2).

### C.2 Protocol changes
1. **Witness blinding (C-a):** l, r, o, z: `ŵ = w + Z_H·r`, r with **b = 174** random coefficients (was 2 / 3).
2. **Randomized quotient split (C-b):** h = h1 + Xᵏ·h2 + X²ᵏ·h3 (canonical split, k = piece size). Prover draws t1, t2 with **173** random coefficients and commits `ĥ1 = h1 + Xᵏ·t1`, `ĥ2 = h2 + Xᵏ·t2 − t1`, `ĥ3 = h3 − t2`. The sum telescopes back to h, so the verifier's equation is unchanged (`2024-1037` §4.1 eq. (8); GWC19 for the 1-coefficient version).
3. **Mask polynomial (C-c):** inside `nativefri.Scheme.Open`, before λ: the prover samples R uniformly with `DegreeBound − 1` coefficients, commits it (own Merkle tree), binds its root into the transcript, and runs FRI on `R + Σₜ λᵗ⁺¹·(fₜ − vₜ)/(X − zₜ)`. The verifier opens R at each query like any commitment.

### C.3 Design decisions
| # | Decision | Why | Source |
|---|---|---|---|
| C1 | b = 174 for l, r, o, z | Distinct revealed points: z: ζ, ωζ, ≤ 2·86 FRI points = 174; l, r, o: 173. One value for all = HK24's bound `2·(e·n_F + n_D)` = 2·(1+86) = 174 — independent derivation and paper agree | `2024-1037` eq. (10), Lemma 1 |
| C2 | t1, t2 with **173** coefficients (user decision) | h pieces are revealed at ζ + ≤ 172 FRI points = 173. HK24 eq. (9) only asks `n_F + n_D` = 87 — likely counts one point per FRI query, while our FRI reveals the pair {x, −x}. Not reconciled → take the count that is certainly sufficient; cost is ~173 coefficients per piece | `2024-1037` §4.1, Lemma 4; own count |
| C3 | Mask R **always on** in `Scheme` (user decision) | PLONK is the only user and must be ZK; one code path, no flag to forget. Cost: one tree + 86 pair openings | `2024-1037` Protocol 2 step 1 |
| C4 | R committed **before λ**, coefficient 1; claims get λ¹, λ², … (today λ⁰, λ¹, …) | If R shared a coefficient with a claim, a cheater could commit a non-low-degree "R" = (low-degree P) − (false quotient Q₀): FRI only sees R + Q₀ = P and accepts. Distinct powers + R bound before λ → correlated agreement applies to R and each quotient separately | `2024-1037` eq. (2) (claims start at λ¹); found while deriving C-c |
| C5 | R has `DegreeBound − 1` coefficients | The decoupling argument needs R uniform over the whole space the quotients live in (degree < DegreeBound − 1), so R + (quotients) is uniform there regardless of the witness | `2024-1037` Lemma 2 (`R ∈ F[X]<|H|+h−1`) |
| C6 | Sizes become computed VK parameters: piece size k, quotient domain, DegreeBound; k and DegreeBound in `vk.digest()` | Today `n+2` is hard-coded in setup, prove and verify (the tiny-circuit bug came from such a coupling). One computation, bound into the transcript → prover and verifier cannot disagree | lesson from `minDomainSize`, D10 |
| C7 | Accept larger proofs for tiny circuits (DegreeBound ≥ 512) (user decision) | Blinding adds ~400 coefficients regardless of n; for n ≥ 512 the bound stays 2n | — |
| C8 | Preprocessed polys stay unblinded | They are public | — |
| C9 | No extra measure for the permutation-argument leak | Reveals only "β, γ ≠ special values"; statistical, negligible in a 254-bit field; perfect ZK would need more | `2024-1037` App. A |

### C.4 Parameters and degrees (n = |H|, b = 174, t = 173)
- l̂, r̂, ô, ẑ: n + b coefficients.
- Identity numerator degree: max of gate `qm·l·r` (3n + 2b − 3) and permutation `z(ωX)·∏(l + β·s + γ)` (**4n + 4b − 4**). Divided by Z_H (degree n): **deg h = 3n + 4b − 4**, i.e. 3n + 4b − 3 coefficients. (Check against today, b = 2/3: 3n + 6 coefficients → pieces n + 2 ✓.)
- Piece size: k = ⌈(3n + 4b − 3)/3⌉ = **n + 231** (exact count, implemented in `setup.go:sizes`; HK24's simpler k̂ = n + ⌈4b/3⌉ gives n + 232 — one more than needed).
- Randomized pieces: ĥ1, ĥ2 have k + t = **n + 404** coefficients — the largest committed polynomials.
- `DegreeBound = NextPow2(n + 404)`: n = 4 → 512; n = 512 → 1024 = 2n; n ≥ 512 → 2n (unchanged from today).
- Quotient domain: |Domain[1]| = NextPow2(3k) (must exceed deg h): n = 65536 → 4n (unchanged); small n larger.
- Mask R: DegreeBound − 1 coefficients.

### C.5 Code plan
- **C2 (red first):** constants `nbBlindWitness`, `nbBlindQuotient` introduced in `prove.go` *with today's values* (behaviour unchanged); `nativefri` gains `(*Scheme).QueriedPoints(...)` (replays the transcript, returns the layer-0 points a proof reveals). Test `TestRevealedValuesAreUniform`: for a real proof, per secret polynomial, collect distinct revealed points, build the matrix `[Z_H(xᵢ)·xᵢʲ]` (j < blinding coefficients) and require **full row rank** (Lemma 1's exact condition) — fails today. Plus a check that the committed polys really have n + b coefficients (the test must measure what the prover does, not just a constant).
- **C3 `nativefri`:** mask R in `Open`/`Verify`; claims shifted to λ¹…; `BatchProof` gains `Mask` root + per-query opening. Tests: completeness; R tampering rejected; the C4 attack (R = P − Q₀ with false Q₀) rejected 0/100; B2 cheater tests still 0/100.
- **C4 `plonkfri`:** blinding b = 174; randomized split with k; `Setup` computes k, Domain[1], DegreeBound (C6); verifier RHS uses ζᵏ instead of ζⁿ⁺².
- **C5:** rank test green; attack tests 0/800, 0/200; leak 0; suite 30/30 + tiny 200; perf.

### C.6 Expected cost (estimates before coding)
- Proof size: + mask tree openings ≈ 86 × (2·32 B + 19·32 B path) ≈ **+58 KB at 65k** (→ ~0.90 MB), ≈ +47 KB at 4k (→ ~0.65 MB).
- Prove time at 65k: same domains (DegreeBound and quotient domain unchanged); + one commitment of R (FFT on |D| + Merkle) → **~+5–10 %** (~2.1 s).
- Tiny circuits (n = 4): DegreeBound 8 → 512, |D| 64 → 4096 → proofs of a few hundred KB, ms-level time.
- Soundness unchanged: 86 queries, ρ = 1/8 (rate is defined by DegreeBound, which only grows for tiny n with |D| = 8·DegreeBound).

### C.8 Results (measured 2026-10-07, after C5)
| | before fix C (after B) | after fix C |
|---|---|---|
| Rank test (revealed points / random coefficients / rank) | l,r,o 159 / 2 / 2; z 160 / 3 / 3; h 159 / 0 / 0 — **fails** | l,r,o 171 / 174 / 171; z 172 / 174 / 172; h 171 / 173 / 171 — **full rank** |
| Same statement opened twice | identical FRI layers | no shared layer root or final value |
| Crafted mask cancelling a false claim | — | 0/50 (50/50 in the unsafe shared-λ⁰ variant) |
| Attacks (zeta in domain / lie at zeta) | 0/800, 0/200 | 0/800, 0/200 |
| 65534 constraints: setup / prove / verify / proof | 0.75 s / 1.97 s / 4.5 ms / 0.84 MB | 0.79 s / 2.10 s / 4.9 ms / **0.90 MB** |
| 4094 constraints | 49 ms / 122 ms / 2.6 ms / 0.60 MB | 50 ms / 132 ms / 2.8 ms / 0.64 MB |
| 2 constraints | ~0 / ~0 / 1 ms / 0.19 MB | 4 ms / 10 ms / 2 ms / 0.43 MB |

Estimates (C.6) vs measured: +58 KB vs +60 KB at 65k; +5–10 % prove vs +7 %; tiny "few hundred KB" vs 0.43 MB.

### C.7 Open points
1. Reconcile HK24 eq. (9)/(10) counting of FRI query points (one vs pair) — affects only whether 173 could be 87 later.
2. ZK is *honest-verifier* in the IOP; with Fiat-Shamir it becomes NIZK in the random-oracle model (standard; BCS) — no extra work, noted for the write-up.
3. Prover randomness comes from `fr.SetRandom` (crypto/rand) — fine; a deterministic RNG would break ZK.

## Session Log

### 2026-09-26
- Reset to a clean start: confirmed `master` (`fd5c2443`) has no FRI code (SSH access to `origin` fixed and fetch confirmed up to date); created working branch `pq-pcs-dev` off master, leaving `restore-fri-gadget` (`fb6e65da`) intact for reference.
- Set up permanent SSH access to GitHub (Keychain-backed agent key + `~/.ssh/config` entry) so `git fetch`/`git log` on remote refs works in every future session.
- Read `resources/2019-1400.pdf` (RedShift paper) and inspected prior-art commits `1ed22f78` (deletion of `backend/plonkfri`) and the restored `internal/nativefri`/`std/commitments/fri` gadgets, plus gnark-crypto v0.21.0's koalabear packages (confirmed: no FRI code there, only Vortex).
- Locked in v1 design: bn254 fr field, single curve hand-written, native-backend-only milestone, sha256 hash. Wrote the restore-based plan and pseudocode above. No code changes yet — next session starts Phase 0.
- Walked the Setup/Prove/Verify pseudocode section by section with the user, building a worked toy-circuit numeric example (incl. a from-scratch derivation of the permutation grand-product `Z` with real numbers) and confirming the Fiat-Shamir transcript mechanism by reading `gnark-crypto/fiat-shamir/transcript.go`.
- Read the real old `backend/plonkfri/bn254/{prove,verify}.go` (`1ed22f78^`) in full and reconciled it against the pseudocode — see "Understanding notes" section above for what was confirmed, refined, or newly discovered (notably: `zeta` is `GenOpening^position`, not an arbitrary field element; no opening batching (18 separate FRI proofs per proof); public inputs bypass FRI via `completeQk()`; non-uniform blinding degrees; a harmless but confusing beta/gamma transcript-label swap present identically in both files). No code changes yet.
- **Phase 0 started**: restored `internal/nativefri` verbatim from `restore-fri-gadget`, restored `backend/plonkfri/bn254/setup.go` from `1ed22f78^` with only the package-qualifier repoint (`fri.X`→`nativefri.X`, 6 call sites, no logic changes) — see the diff in git history. Contrary to an earlier (wrong) claim about API drift, `constraint/bn254`'s `Public`/`Secret`/`NbInternalVariables`/`Coefficients` are still plain fields (promoted through embedding) alongside newer getters, so no adaptation was needed. Added `TestSetupSmoke` (toy circuit `X²·Y=Out`, runs `Setup` end-to-end, checks output shape) — passes. Committed (`6ec647e9`, `07cb0512`) and fast-forward merged `pq-pcs-dev` into `master`, pushed to `origin/master`. `resources/` still untracked/uncommitted (open question stands).
- **`prove.go` restored** the same way (`1ed22f78^`, same 10-line qualifier repoint, no other changes) and `TestProveSmoke` written (Setup+Prove end-to-end on the toy circuit's real witness X=3,Y=2,Out=18). This surfaced a **real bug** in vendored `internal/nativefri`, not a false alarm: `BuildProofOfProximity` never set `ProofOfProximity.ID`, which `prove.go`/`verify.go` bind into the Fiat-Shamir transcript — meaning every challenge derivation was unbound from the actual commitment (a genuine soundness gap, not cosmetic). Root cause: the real commitment root (`rh`, the Merkle root of the original unfolded evaluations) was computed inside `buildProofOfProximitySingleRound`'s first fold step but never surfaced. Fixed with a small, additive patch (new `Round.InitialRoot` field, set at `i==0`; `BuildProofOfProximity` copies `Rounds[0].InitialRoot` into `proof.ID`) — 14 lines added, nothing removed. Both smoke tests pass after the fix. This is the first genuine logic change beyond mechanical restoration — `internal/nativefri` is no longer a byte-for-byte vendor copy.
- **`verify.go` restored** the same way (`1ed22f78^`, single-line qualifier repoint, no other changes) and `TestRoundTrip` written: `Setup → Prove → Verify` on the toy circuit's real witness (X=3,Y=2,Out=18) — passes, plus a negative test (tamper with a claimed opening value) that Verify correctly rejects. **This is the first real correctness check of the whole session** — everything before this only checked "runs without crashing"; this confirms the FRI substitution is actually sound end-to-end for this circuit shape.
- Not yet committed/merged: `prove.go`/`prove_test.go`, `verify.go`/`verify_test.go`, and the `internal/nativefri` `.ID` fix are all sitting locally, pending the user's call on when to commit.
- **Phase 0 complete**: added `PLONKFRI` to `backend.ID` (`backend/backend.go`, mirroring the old `1ed22f78^` naming exactly: `PLONKFRI`/`"plonkFRI"`), confirmed a full-repo `go build ./...`/`go vet ./...` still passes (the only other consumer of `backend.Implemented()`, `internal/stats`, already skips backends with no precomputed stats — safe; its `generate/main.go` companion tool is a manual, non-test entry point, not fixed now, noted as a non-blocking follow-up). Added `backend/plonkfri/plonkfri.go`, a thin bn254-only dispatcher mirroring `backend/plonk/plonk.go`'s shape. Added `TestDispatcherRoundTrip`, exercising `Setup/Prove/Verify` through the dispatcher's interfaces (not the bn254 subpackage directly) — passes, confirming the type-assertion plumbing works at runtime, not just that it compiles.
- Phase 0 is now fully done per the original plan: `backend/plonkfri/bn254/{setup,prove,verify}.go` restored and correct (round-trip + tamper test both pass), `internal/nativefri`'s real `.ID` bug fixed, `backend.ID` entry and dispatcher in place. Next is Phase 1 proper: expanding beyond the single toy circuit (more gate types, edge cases) and deciding what comes after v1 (more curves, in-circuit verifier, batched openings) per the "Open questions" list below.

### 2026-10-07
- Ran the library's shared circuit suite (`internal/backend/circuits`, the set `integration_test.go` runs against KZG PLONK/Groth16) through `plonkfri` on bn254 via new harness `backend/plonkfri/suite_test.go` (uncommitted). **28/32 pass** (valid witness proves+verifies; invalid witness rejected).
- **Real bug found — completeness failure at `vk.Size == 2`** (`assert_equal`, `noComputationCircuit`): ~88% of honest proofs rejected (884/1000 measured), randomly depending on blinding. Root cause: `Z` is blinded with order 2 → `n+3` coefficients, but FRI degree bound is `NextPowerOfTwo(n+2)`; for `n=2` that's 4 < 5. `setup.go:138` assumes `NextPow2(Card+2) == 2·Card`, false for Card ≤ 2. Naively bumping `sizeIopp` to `+3` makes it 100% fail, because `prove.go:218`/`verify.go:67` hardcode `friSize = 2·rho·Size`. Candidate fix: enforce a minimum `Domain[0]` cardinality of 4 in Setup (keeps all invariants). Not yet applied.
- **Expected failures (v1 scope cut)**: `commit`, `gkr_cube` use BSB22 commitments → Verify fails with "algebraic relation does not hold". Setup silently accepts such circuits; it should reject them with an explicit "unsupported" error.
- Verify with a full witness in place of the public one is rejected, but with a misleading error ("merkle path proof is wrong"); KZG backend does an explicit length check ("witness length is invalid").
- Perf vs KZG (bn254, `refCircuit`, M-series laptop): 4094 constraints: setup 550ms vs 16ms, prove 534ms vs 51ms, verify 0.6ms vs 1.1ms. 65534 constraints: setup 8.3s vs 0.16s, prove 9.2s vs 0.65s, verify 1.0ms vs 1.3ms. Prover ~10–14× slower, verifier slightly faster.
- **All three fixes applied (same day)**:
  1. Small-domain completeness bug: `Setup` now pads `Domain[0]` to at least `minDomainSize = 4` (`setup.go`). This exposed a second hidden assumption: `prove.go` used solver L/R/O vectors directly, which are only sized `NextPow2(constraints+public)`. They're now padded to the domain size via `padToDomain`, filling with **wire 0's value, not zero**. That matches the solver's own convention (`constraint/bn254/solver.go` `initSparseLRO`), because `buildPermutation` links every padding slot to wire 0. Zero-padding was tried first and broke the copy constraint.
  2. `Setup` returns `ErrCommitmentsUnsupported` for circuits with BSB22 commitments.
  3. `Verify` checks `len(publicWitness) == vk.NbPublicVariables` → `"witness length is invalid"` (same message as KZG backend).
- Result: suite now **30/30 in-scope circuits pass, 2 skipped as out-of-scope** (`commit`, `gkr_cube`). New regression test `TestTinyCircuitCompleteness` (200 proofs on a 1-constraint circuit); ad-hoc stress run of 1000 proofs each on 1–2 constraint circuits with/without public inputs: 0 rejections. `go build ./...` clean.
- Next: commit fixes + `suite_test.go`; v1 is functionally complete. Then pick post-v1 direction (batched openings for prover speed vs. more curves vs. in-circuit verifier).

### 2026-10-07 (cont.) — security-parameter audit
Measured, not just reasoned (probe tests in `internal/nativefri`, removed afterwards; code unchanged):
- **FRI: 1 query per proof → ~3 bits of security.** `nativefri` has `rho = 8`, `nbRounds = 1`; each "round" derives exactly one query position. Measured acceptance (n=16, 4000 trials): honest 100%; one coefficient over-degree 12.5%; 2× degree 12.9%; *completely random codeword* 13.2% (≈ 1/rho: the final folded layer has rho=8 points). Under Fiat-Shamir a cheater grinds (re-randomizes blinding) → forging costs ~8 hash attempts. Target is ~100–128 bits.
- **PLONK layer: `zeta` drawn from a set of only 16n points** (`zeta = GenOpening^position`, `position < 2·rho·n`), not the whole field. Schwartz–Zippel escape probability up to ~3n/16n ≈ 19%. Worse: 1/16 of positions give `zeta^n = 1` (zeta inside the circuit domain) → `Z_H(zeta)=0`, RHS=0, H unchecked, the check degenerates to a single gate row. This is structural — the cost of the old code's "sidestep" of opening at arbitrary points — fixable only by DEEP/RedShift-LPC style out-of-domain opening (quotient `(f(X)−f(z))/(X−z)` proven low-degree).
- **Naive fix cost** (set `nbRounds=43`, n=4096): build one FRI proof 24ms → 969ms (41×), ~4.8KB → ~206KB, random codeword accepted 0/2000. Cost is because each round re-runs all folding + Merkle trees for a single query; standard FRI folds once and answers all queries from the same trees.
- **Query counts needed for rate 1/8** (bits/query = −log2(1−δ)): provable unique-decoding δ<0.4375 → 0.83 bits/query (~154 queries for 128 bits); Johnson bound δ<1−√ρ≈0.646 → 1.5 bits/query (~86); conjectured δ→1−ρ → 3 bits/query (~43 for 128, ~34 for 100), the measured 1/8 matches the conjectured regime. Grinding/proof-of-work can add ~16–20 bits cheaply.
- **ZK interaction (not soundness)**: every FRI query + opening reveals evaluations of the blinded polys; L/R/O are blinded with only 2 random coeffs, Z with 3. More queries ⇒ blinding degree must grow with the number of revealed evaluations or zero-knowledge breaks.
- Proposed plan: (A) restructure `nativefri` to one commit phase + s queries, s derived from a target security level; (B) DEEP-style out-of-domain `zeta` from the full field; (C) scale blinding with revealed evaluations. Open decision: provable (Johnson) vs conjectured security parameterization.

### 2026-10-07 (cont.) — query count from the literature (`resources/`)
Per-query soundness error for rate ρ, and resulting queries s for λ bits (s = λ / −log2(per-query error)):
- Original FRI (`Revision2OfTR17-134`, Thm 3.3): proven only for δ ≤ (1−3ρ)/4 → per-query reject ≥ 5/32 at ρ=1/8 (~0.25 bits/query; impractical). Conj. 1.5: δ up to 1−ρ. Paper's own example: ρ=1/8, ε=2⁻⁸⁰.
- DEEP-FRI (`2019-336`): proven per-query error max(1−δ, √ρ) up to the Johnson bound, needs larger fields.
- Proximity Gaps (`2020-654`, §3.2/§8): history t≈4λ/log(1/ρ) [BKS18] → 3λ/log(1/ρ) [BGKS20] → **2λ/log(1/ρ) proven for q ≫ n²** (Johnson bound, error √ρ). **λ/log(1/ρ) conjectured** (BBHR18b lower bound; Conj. 8.4). "λ often fixed to 128."
- RedShift (`2019-1400`, Table 1, 80-bit target): ρ=1/16 → 88 (unique decoding) / 40 (Johnson, q>|D|²) / 20 (conjectured). Their implementation targets 80 bits, ρ=1/16. Notes: query count does **not** affect prover time, only proof size/verify; beyond Johnson, knowledge-soundness is non-extractable.
- **Our setting**: bn254 fr (q≈2²⁵⁴ ≫ n²), so the proven Johnson regime applies. ρ=1/8 (log 1/ρ = 3):

| λ | conjectured (λ/3) | proven Johnson (2λ/3) | unique decoding (λ/0.83) |
|---|---|---|---|
| 80 | 27 | 54 | 97 |
| 100 | 34 | 67 | 121 |
| 128 | 43 | 86 | 154 |

Measured per-query acceptance of garbage = 1/8 = ρ, i.e. the conjectured regime is what we observe in practice; the proven bound is a 2× safety margin.

### 2026-10-07 (cont.) — fix A landed
- `internal/nativefri` restructured: COMMIT phase once (each layer's Merkle tree built once, all nodes kept via new `merkleTree`, path-compatible with gnark-crypto's `merkletree.VerifyProof`), then **`nbQueries = 86`** query chains (proven Johnson-bound, 128 bits at ρ=1/8). Query positions: one Fiat-Shamir seed after all roots + final evaluation are bound, position j = H(seed‖j) mod |D|. Proof format: `Rounds []Round` → `Roots [][]byte` + `Queries []Query` + `Evaluation`.
- **Found and fixed a 4th, critical hole**: `VerifyOpening` never checked `ClaimedValue` against the Merkle-authenticated leaf (`ProofSet[0]`), and `verify.go` uses `ClaimedValue` — a cheater could claim any evaluation (e.g. solve the final identity for h(zeta)) with a valid path → forgery with probability 1. Now rejected (`ErrClaimedValue`); regression test written first and confirmed failing on the old code.
- Verifier hardening: checks `ID == Roots[0]` (ID is what PLONK binds into Fiat-Shamir), computes layer sizes itself instead of trusting prover-supplied `numLeaves`, rejects malformed shapes with `ErrMalformedProof` instead of panicking.
- Tests (`internal/nativefri/fri_test.go`): Merkle-path equivalence with gnark-crypto, completeness, soundness (0/600 far words accepted vs ~1/8 before), tampering cases, opening-lie. Full plonkfri suite still 30/30 + 2 skipped.
- Perf (bn254 refCircuit, before → after): 4094 constraints setup 550→260ms, prove 534→383ms, verify 0.6→39ms; 65534: setup 8.3→4.1s, prove 9.2→6.8s, verify 1.0→69ms. Proof's 7 proximity proofs ≈ 3.2MB / 4.8MB. Verify cost is 18 proximity proofs × 86 chains; the 11 VK proofs are fixed and could be checked once at setup (cheap later win). Size is the next driver for batching + Merkle path dedup.
- Still open: fix B (out-of-domain zeta — currently caps soundness at ~4 bits), fix C (blinding vs 86×revealed evaluations — ZK now clearly insufficient).

### 2026-10-07 (cont.) — literature review + security target
- Checked the security plan against the papers in `resources/` (FRI/ethSTARK, DEEP-FRI, RedShift, `2021-582`, `2022-1216`, `2023-1071` Block et al., `2023-691` weak F-S, `2024-1037` HK24). Fix B/C designs confirmed and extended: coset FRI domain, VK digest in the transcript, separate mask polynomial R(X), randomized quotient pieces. See "Literature basis", "Additional considerations", "Findings from 2023-691 / 2024-1037".
- PQ analysis (only `2023-1071` Thm 3.15 gives quantum bounds): 128 classical ≈ 64 PQ bits; sha256 caps PQ at ~85 bits; bn254 fr caps proven PQ near ~100 bits.
- **Decided: security target (a)** — 128-bit classical, "plausibly PQ".
- To obtain/verify: [CMS19] ePrint 2019/834, Chiesa–Yogev book, NIST PQC criteria §4.A.5, BHT97, Bernstein 2009.
- Next: Step 0 (master red: gadget `fri_test.go`), then fix B (B1 design first).

### 2026-10-07 (cont.) — Step 0 done, fix B designed (B1)
- **Step 0**: gadget test gated behind `fri_gadget_phase3` (commit `ef94dacb`). Reasoning: a reshape of the proof struct would compile but still fail — gadget and nativefri query *different positions* (`seed mod |D|` vs `H(seed‖j) mod |D|`), so a real port is needed (Phase 3). Verified the whole tree's test packages compile (`go test -run XXX ./...`), nativefri + plonkfri suites green.
- **Measured the coset-domain ZK leak** with a throwaway probe (60 secret wires): each of L/R/O reveals 172 codeword values per proof, 5–11 of which are raw secret wire values (≈172/16 expected) — so consideration 1 is a concrete break, not a theoretical one.
- **B1 design written** ("Fix B design (B1)"). Key reading: `2022-1216` §4–5 (DEEP PCS, Protocol 3, Thm 8) turned out to be an almost direct template; `2023-1071` §2.4 OPlonky for the PLONK/F-S side; `2021-582` §3.5 for multi-column Merkle leaves. Decisions D1–D10; 86 queries remain valid (D8); setup binding resolved (D9); Id polys dropped (D6). App. C of `2023-1071` (parallel repetition subtlety) only concerns t>1 in small fields — not us.
- Design approved (B.6: yes to all three). Next: B4's red-first attack test, then B2.

### 2026-10-07 (cont.) — B4: concern 2 attack demonstrated
- Attack design: prove the **false** statement "∃X: X²=5" (5 is a non-square in bn254 fr). Cheater computes every polynomial from a real witness (X=3, Y=9) but binds Y=5 into Fiat-Shamir like the verifier. The two statements differ only by `(5−9)·L₀(X)`, and `L₀` is 0 on every row of H except row 0 → whenever ζ = ωʲ, j≠0, the verifier's identity holds; the h-side is `h(ζ)·Z_H(ζ) = 0` anyway. Cheater just retries with fresh blinding.
- Hook: `prove(..., transcriptPublic, ...)` (unexported; `Prove` passes nil → unchanged). Lets tests play a cheater without copying the prover; seed for the Step 3 malicious-prover harness.
- Result: **36/800 accepted (4.5%), all 36 with ζ ∈ H**; prediction 1/16·3/4 = 4.69% (n=4, row 0 excluded). Theory and measurement agree; cause confirmed, not just correlated.
- Test is red on `pq-pcs-dev` by design; it becomes the acceptance criterion for fix B (must be 0/800). Next: B2.

### 2026-10-07 (cont.) — B2: batched DEEP-FRI in `nativefri`
- New file `internal/nativefri/batch.go`; old per-polynomial API kept untouched so every package stays green until B3 switches PLONK over (only shared helpers `queryChain`/`queryPositions` extracted).
- Key simplification (`2022-1216` §3.7): FRI over the coset a·D = plain FRI over D on `q(a·X)`. Committed values are the same; only the DEEP quotient uses the real point `x = a·gⁱ`. → fix A's folding code reused unchanged.
- API: `NewScheme(degreeBound, h)`; `Commit(polys...)` (one tree, leaf = all polys at one point, sibling pair {x, −x} adjacent); `Open(seed, committed, claims)` / `Verify(seed, commitments, claims, proof)`. Transcript binds caller seed + every root (+width) + every claim (point, poly ref, value) before λ; folding challenges + query seed follow. Points in a·D rejected (`ErrPointInDomain`); leaves parsed canonically. Merkle openings are now pair openings (two rows + one path) instead of fix A's `[2]MerkleProof` trick.
- Tests (all green): coset evaluation correct and disjoint from the subgroup (so from H); completeness for degree bounds 2/4/64 with PLONK-like layout (3 commitments, claims at z and ω·z); **false evaluation 0/100 accepted, high-degree poly 0/100 accepted — all 200 rejected by the folding check**, i.e. by the intended mechanism; 12 tampering cases rejected.
- Observation: tampering with anything bound into Fiat-Shamir (seed, claims, final evaluation) is rejected via *Merkle path* errors because the query positions move. Correct, but it means only the "cheater re-runs the prover on its lie" tests exercise the folding check — that's why those two tests tally the rejection reason.
- Fixture bug found by the completeness test (3-coeff poly with degreeBound 2 → `ErrDegree`): test bug, not scheme bug.
- Next: B3 — rewire PLONK setup/prove/verify onto `Scheme`; acceptance criterion `TestForgeryZetaInDomain` 0/800.

### 2026-10-07 (cont.) — B3: PLONK rewired, fix B complete
- Setup: one tree for the 8 preprocessed polys (ql, qr, qm, qo, qk, s1, s2, s3); Id polys dropped (verifier computes `uᵏ·ζ`); `DegreeBound = NextPow2(n+3)` explicit (D10); VK is O(1): roots + parameters + `digest()`.
- Prove/verify: transcript object advanced round by round (`newTranscript`, `afterLRO`, `afterZ`, `afterH`) shared by prover, verifier and tests — first version replayed the whole transcript with placeholder roots, rewritten because it was hard to read. Claims and commitment order built by one shared function (`Proof.claims`), so prover and verifier can't disagree on batching coefficients.
- Attack results (acceptance criterion): in-domain-zeta forgery **0/800** (was 36/800), all rejected by the *identity* check — honest openings, false statement, random ζ. New test: cheater solves `h1(ζ)` from the identity so the identity holds by construction (checked in the test) → **0/200**, all rejected by *FRI folding*. Each defence is shown to catch its own attack.
- Witness leak: 0/516 revealed l/r/o values are secret wires (was ~1/16).
- Old `nativefri` API (per-polynomial proofs, openings only at domain points) deleted: unused and unsafe to reuse. `fri.go` keeps the shared pieces; Merkle-format test extended to pair openings. Only the gated gadget test referenced it (Phase 3).
- `playground_test.go` deleted at the user's request (used removed fields).
- Perf/size measured (B.5 table): 65k constraints prove 6.8 s → 1.97 s, verify 69 → 4.5 ms, proof ≈ 0.84 MB (estimate 0.9).
- Known caveat: `Scheme` holds one `hash.Hash`, so a VK must not be used by concurrent goroutines (same as before B). Fix with a hash constructor when needed.
- Next: fix C (zero-knowledge): blinding degree vs ~2·86 revealed points + ζ openings, mask polynomial R in the batch (HK24 Protocol 2), randomized quotient pieces.

### 2026-10-07 (cont.) — C1: fix C design
- Read `2024-1037` Protocol 1–3, Lemma 1–2, §4.1 (canonical split randomization, Lemma 4). §4.1 is exactly our h1/h2/h3 split.
- Derived parameters from first principles and compared with the paper: witness blinding b = 174 (own count = HK24 eq. (10)); quotient randomizer 173 (own count) vs HK24's 87 — unreconciled (one vs two points per FRI query); user chose 173. Mask always on; tiny circuits get DegreeBound ≥ 512 (user decisions).
- **Found while deriving:** the mask R must not share the coefficient λ⁰ with the first claim — otherwise a cheater commits "R" = P − Q₀ for a false quotient Q₀ and FRI, which only sees R + Q₀, accepts. Claims move to λ¹, λ², … (as in HK24 eq. (2)); a test for this attack is planned in C3.
- Degree check of the derivation against today's code (b = 2/3 → pieces n+2 ✓) before trusting it for b = 174.
- Testing choice: ZK can't be tested statistically (every 254-bit value looks random); test the structural condition of Lemma 1 (full rank of the blinding map on the revealed points) instead, red first.

### 2026-10-07 (cont.) — C2: zero-knowledge test, red first
- Behaviour-preserving refactors first (all tests green after them): `nativefri.(*Scheme).QueriedPoints` (shares the transcript replay with `Verify` via `replay`, so it can't drift); blinding sizes as named constants `nbBlindLRO=2`, `nbBlindZ=3`, `nbBlindQuotient=0`; the hard-coded `n+2` piece size now lives only in `vk.pieceSize()` (prover split + verifier RHS).
- `TestRevealedValuesAreUniform` checks HK24 Lemma 1's exact condition on a real proof: per secret polynomial, the matrix `[B(xᵢ)·xᵢʲ]` over the distinct revealed points (B = Z_H for l/r/o/z, Xᵏ for h1/h2) must have full row rank. Also checks the prover really outputs n + b coefficients (measures the prover, not a constant). `TestRank` sanity-checks the elimination helper on Vandermonde matrices.
- **Result (red, as intended):** l/r/o revealed at 159 points with rank 2; z 160 points, rank 3; h1/h2 159 points, rank 0.
- Observation: 159, not 173 — queries are drawn with replacement and this circuit's FRI domain has 512 pairs, so ≈ 86·85/(2·512) ≈ 7 collide → 1 + 2·(86 − 7) ≈ 159 predicted, 159 measured. Large circuits collide less, so the 173/174 bound is still what's needed.

### 2026-10-07 (cont.) — C3: mask polynomial R in `nativefri`
- Order: plumbing with the mask *off* (internal `open(…, mask)`, claims moved to λ¹, λ², …) → all tests green except the known C2 red test → mask tests written → `TestMaskRandomizesOpening` red (no mask) → mask switched on in `Open` (R with DegreeBound − 1 random coefficients, own Merkle tree, root bound before λ; `Verify` requires it) → green.
- **Decision C4 demonstrated, not just argued:** `TestMaskCannotCancelFalseClaim` commits a crafted "R" = P − E that cancels a false claim's error term E. With R sharing λ⁰ with the first claim (`firstClaimPower = 0`, unsafe): **50/50 accepted**. With our design (claims at λ¹…): **0/50**. The test also fails if the attack stops working in the unsafe variant, so it can't silently become vacuous.
- With the mask: two openings of the same statement share no FRI layer root or final value (fresh randomness in every fold); mask root/row tampering and a missing mask are rejected; B2 cheater tests unchanged (0/100, 0/100); PLONK attack tests unchanged (0/800, 0/200), leak 0/516.
- Test bug found: the tampering test's proof `clone()` didn't copy the new `Mask` field → index panic. Fixed the helper; lesson: when a struct gains a field, check every deep-copy helper.
- Measured vs estimate (C.6): proof 65k 0.84 → **0.90 MB** (+60 KB, est. +58 KB); 4k 0.60 → 0.64 MB (+40 KB, est. +47 KB); prove 65k 1.97 → 2.07 s (+5 %, est. 5–10 %).
- Still red: `TestRevealedValuesAreUniform` (witness blinding + quotient split are C4).

### 2026-10-07 (cont.) — C4: blinding and randomized quotient split in `plonkfri`
- Blinding constants derived in code from `nativefri.NbQueries` (exported): l/r/o/z 2·(1+86) = 174, quotient randomizers 1 + 2·86 = 173.
- One `sizes(n)` in `setup.go` replaces three hard-coded rules (FRI bound `n+3`, quotient domain 4n/8n, pieces `n+2`): piece size k = ⌈(3n + b_Z + 3·b_LRO − 3)/3⌉, DegreeBound = NextPow2(max(k + 173, n + 174)), quotient domain = NextPow2(3k). **Checked the formula against the old values first** (b = 2/3 → k = n+2 ✓) before trusting it at 174. Exact count gives k = n+231; the design's HK24-based estimate said n+232 — doc corrected. `PieceSize` stored in the VK and bound in its digest.
- Randomized split: ĥ1 = h1 + Xᵏt1, ĥ2 = h2 + Xᵏt2 − t1, ĥ3 = h3 − t2 (telescopes to h; `TestRoundTrip` and the suite confirm the verifier's equation is unchanged).
- **`TestRevealedValuesAreUniform` green:** l/r/o 171 points / 174 coefficients / rank 171; z 172/174/172; h1,h2 171/173/171. (171 vs 159 before: the tiny circuit's FRI domain grew 1024 → 4096 points, fewer query collisions.)
- All other tests green: attacks 0/800 and 0/200, leak 0/516, mask 0/50, suite 30/30 (+2 skipped), tiny 200, nativefri 10/10.
- Measured: 65k and 4k unchanged vs C3 (DegreeBound stays 2n) — 65k: prove 2.15 s, verify 4.2 ms, 0.90 MB. Tiny circuit (2 constraints): proof 0.19 → 0.43 MB, prove ~0 → 10 ms (decision C7, as estimated). Side effect: the 800-attempt attack test went 1.0 s → 8.8 s for the same reason.
- Measuring the pre-C4 tiny size needed the old code: done in a temporary `git worktree` at the C3 commit (a `git stash` attempt measured nothing — the stashed code lacked the tiny case).

### 2026-10-07 (cont.) — C5: fix C complete
- Final run: whole-repo build + every test package compiles; vet/gofmt clean; nativefri 10/10, suite 30/30 (+2 skipped), tiny 200, bn254 all green incl. attacks (0/800, 0/200), mask (0/50), leak (0/516), rank test (full rank).
- Results table in "Fix C design" C.8; lessons (h)–(l) added to "Lessons that generalize"; next steps updated (Step 3 harness mostly exists; concurrency, tiny-circuit sizing, HK24 87-vs-173, external review added).
- Status: plonkfri on bn254 is sound and (honest-verifier) zero-knowledge by construction, with tests for each mechanism; not externally reviewed.

### 2026-10-07 (cont.) — follow-ups documented
- New section "Follow-ups (after fixes A–C)": F1–F12 grouped as before-real-use (review, serialization, concurrency), robustness (malicious-prover harness, HK24 87-vs-173), cost (size, prover time, tiny circuits), research (PQ target), later phases (in-circuit verifier, features, housekeeping). Each with why / approach / "done when", so the next work can start test-first.
- Branch `pq-pcs-followups` (stacked on PR #6, which was still open).
