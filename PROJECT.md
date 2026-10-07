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

**Not yet sound.** Proofs verify correctly, but a dishonest prover can still forge one in ~16 attempts (concern 2). Do not treat any output as secure until fixes B and C land. Details, measurements and reasoning are in the 2026-10-07 session-log entries below.

A FRI-PLONK proof rests on two promises: (1) every committed table is a low-degree polynomial — FRI's job; (2) those polynomials satisfy the circuit identity, checked at one random point `zeta` — PLONK's job. Soundness is the *weakest* of the checks, so every one must reach the target.

| # | Concern | Protocol part | Effect | Status |
|---|---|---|---|---|
| 1 | FRI checked **1 query** per proof (`nbRounds = 1`) | FRI (`internal/nativefri`) — all 18 commitments | Garbage accepted ~1/8 → ~3 bits; e.g. a pointwise `H = F/Z_H` table passes PLONK at every `zeta`, only FRI could catch it | ✅ Fixed (A): fold once, **86 queries** = 128-bit proven (Johnson bound, ρ=1/8, `s = 2λ/log₂(1/ρ)`) |
| 4 | `VerifyOpening` never tied `ClaimedValue` to the Merkle-authenticated leaf | FRI opening ↔ PLONK final check | Cheater claims any value at `zeta` (solve for `h`) → forgery with probability 1 | ✅ Fixed (A): `ErrClaimedValue` |
| 2 | `zeta` drawn from the 16n-point FRI domain, not the whole field | PLONK final check (`prove.go`/`verify.go`) | Schwartz–Zippel escape up to ~19%; 1/16 of positions put `zeta` in the circuit domain (`Z_H(zeta)=0`) → honest low-degree polys for a witness breaking one gate pass ~1/16 | ❌ Open — fix **B**: sample `zeta ∈ F`, open via DEEP/RedShift quotient `(f(X)−f(z))/(X−z)` proven low-degree. Not fixable by any parameter. |
| 3 | Blinding (2 coeffs L/R/O, 3 for Z) vs values revealed by queries + openings | PLONK prover blinding (`prove.go`) | Zero-knowledge (privacy) only, not soundness; with 86 queries it clearly leaks | ❌ Open — fix **C**: blinding degree ≥ number of revealed evaluations + a separate blinding polynomial in the FRI batch (Haböck §3.7); depends on final query/opening design from B |
| 5 | FRI domain is a subgroup ⊇ circuit domain H (no coset shift) | FRI domain (`nativefri.newRadixTwoFri`) | ZK only: queries landing in H (1/16) reveal raw wire values, blinding vanishes there | ❌ Open — coset domain, as part of **B** (Haböck §3.7) |
| 6 | Transcript doesn't bind the verifying key / circuit | Fiat-Shamir in `prove.go`/`verify.go` | "Weak Fiat-Shamir" class [DMWG23]; matters if the VK can be chosen adversarially | ❌ Open — bind VK digest first, as part of **B** |

Parameter choice (decided 2026-10-07): **proven** 128-bit, not conjectured. Rationale: once FRI folds once, query count costs only proof size/verify time, not prover time (RedShift §6–7), and the proven regime keeps knowledge-soundness extractable. Conjectured alternative (43 queries, ~half the size) remains an opt-in for later. Sources: `resources/2020-654.pdf` §3.2/§8 (2λ/log(1/ρ) proven for q ≫ n²; λ/log(1/ρ) conjectured), `resources/2019-1400.pdf` Table 1, `resources/Revision2OfTR17-134.pdf` Thm 3.3 / Conj. 1.5.

Lessons that generalize: (a) passing honest-proof tests says nothing about soundness — every check needs a test that a *cheating* prover is rejected; (b) any value the verifier uses must be bound to something it verified (here: `ClaimedValue` ↔ leaf, `ID` ↔ `Roots[0]`, layer sizes computed not trusted); (c) measure acceptance rates empirically — the 1/8 measurement exposed concern 1 before the theory did.

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
5. **Setup-polynomial binding (RedShift §4.3 PES)** — likely moot for us: setup is deterministic and the VK roots are re-derivable from the circuit, so committed setup words are exact codewords; distinct codewords are ≥ 1−ρ = 0.875 apart > δ ≤ 1−√ρ ≈ 0.646, so no other polynomial is δ-close. Confirm in B1; only relevant if an untrusted party ever produces the VK.
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

**Step 1 — Fix B: out-of-domain `zeta` (DEEP / RedShift LPC). Blocks "sound".**
- B1 design: read RedShift §4 (LPC) + DEEP-FRI §5 + Block et al. §2.4/§7 (OPlonky) + Haböck §4–5; write the design here before coding. Includes: **coset FRI domain** (consideration 1), **VK digest bound first in the transcript** (consideration 3), setup-binding check (consideration 5).
- Core idea: `zeta` ∈ F (whole field, as in KZG PLONK). To prove `f(zeta)=v`, show `q(X)=(f(X)−v)/(X−zeta)` is low-degree with FRI. q needs no commitment: the verifier computes q's value at any FRI query point x from the opened f(x). All openings combine with random coefficients into **one** FRI proof: `Σ αⁱ (fᵢ(X)−vᵢ)/(X−zeta)` (+ terms at `zeta·ω` for Z) → batching comes almost for free (18 proximity proofs → 1).
- Consequences: commitments become plain Merkle roots; VK stores roots, not 11 proximity proofs (verify gets cheaper); `nativefri` gains `Commit` + `BatchOpen`/`VerifyBatchOpen`; prove/verify rewired.
- B2 nativefri API + tests (incl. cheating cases). B3 rewire prove/verify. B4 adversarial tests for concern 2 (single-bad-gate witness, pointwise-H table) — must be rejected.
- Before B3: read the two still-unread prover functions (`computeQuotientCanonical`, permutation bookkeeping in `computeBlindedZCanonical`), since B rewires around them.

**Step 2 — Fix C: blinding vs revealed evaluations (zero-knowledge).** Also add a separate random blinding polynomial to the FRI batch (consideration 2, [HK24]). After B the exact count is known: each committed poly is revealed at ~2·86 FRI positions + its `zeta` openings → blinding degree must be ≥ that; FRI degree bound/domain sizing must absorb it. RedShift samples outside D for perfect ZK — check §6.

**Decided — security target (consideration 4):** option (a), classical 128 bits + "plausibly PQ" (see Design decisions). To revisit: explicit PQ target after reading [CMS19] / Chiesa–Yogev / NIST PQC criteria; optional grinding to trade queries for prover work.

**Step 3 — Malicious-prover test harness.** A reusable way to build deliberately bad proofs (lying openings, pointwise-H, bad-gate witness) so every soundness claim has a test that a cheater fails. Partly built during B4.

**After "sound + ZK"** (pick by priority):
- Proof serialization (`WriteTo`/`ReadFrom`) — none exists; needed for any real use.
- Size/speed: Merkle path dedup / caps, parallel hashing.
- Phase 3: port fix A/B to the in-circuit gadget, Poseidon2, recursive verifier.
- Features: BSB22 commitments, more curves.
- Housekeeping: `playground_test.go` (keep/delete?), `internal/stats/generate/main.go`.

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
