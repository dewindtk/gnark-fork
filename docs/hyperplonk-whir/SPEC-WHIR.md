# SPEC-WHIR — WHIR multilinear PCS over bn254 fr, zook structure (Standard + ZK modes)

Normative for the WHIR agents. Sources: WHIR ePrint 2024/1586; ZK IOPPs for constrained interleaved codes ePrint 2026/391 (Chiesa/Fenzi/Weissenberg); SoK 2026/1367; reference implementation github.com/WizardOfMenlo/whir **pinned at `c73b8d3`** (2026-10-22): `protocols/zook` (`commit.rs`, `prover.rs`, `verifier.rs`, `joint.rs`), `protocols/{irs_commit,code_switch,basecase,mask_proximity,sumcheck}`, `params/{protocol_config,regime,…}`, `algebra/linear_form`. The reference describes itself as an academic prototype. Parameter numbers below are estimates from a script implementing §2. The source of truth is the frozen table generated offline by `whirparams` (a port of reference `params/*`), checked against the Rust reference's `ProtocolConfig::derive` (container, PLAN D6) and by pyref's independent security checker (from the papers only).

Notation: m vars, k folding factor, ρ rate, λ = 130 per opening (PLAN R2), index bits MSB-first (gnark-crypto `MultiLin.Fold` binds X₁ first).

**Why zook and not legacy WHIR (review F1).** Legacy WHIR (`whir` + `irs_commit::commit_with_ood`) samples OOD at commit; in ZK an OOD answer at commit reveals f(x) unmasked, so zook moves OOD into each code-switch round (where it is answered through a private zero-evader in ZK mode). Building zook's structure from the start makes ZK a mode switch, keeps one parameter derivation and keeps v1a proofs/VKs format-compatible apart from the mode flag.

## 1. Protocol

**Encoding (interleaved RS).** Message v ∈ F^{2^m} = hypercube table (no Möbius transform). Split into K = 2^k chunks c_b (b = top k bits), each read as univariate coefficients ĉ_b(X), evaluated on L_i = ⟨ω_N⟩, ω_N = the order-N root of unity of gnark-crypto (`fft.NewDomain(N).Generator`, multiplicative generator 5, same as arkworks `Field256`), **subgroup, no coset, natural order: leaf index j ↦ point ω_N^j** (gnark DIF output is bit-reversed → reorder; reference KATs built with `rs_in_order`); |L₀| = 2^{m−k}/ρ. Leaf j = (ĉ_0(ω^j), …, ĉ_{K−1}(ω^j)) in chunk order b = 0..K−1. Leaf at x = (ĉ_b(x))_b. Fold by α ∈ F^k: Σ_b eq(b,α)ĉ_b(x) encodes P(α,·) (2026/391 Claim 2.9). Constraint m − k + log(1/ρ) ≤ 28. ZK mode: each chunk is ZK-encoded, Enc(f, r) = (f̂ + X^ℓ r̂)(L) with |r| ≥ t + s (§3).

**Claims = linear forms** on v. Built-ins (internal): `EqForm{z}`; `StackedEqSparseForm` (eq over a sub-block + sparse cell terms, succinct `EvalMLE`; used by the PIOP, SPEC-PIOP §2.4); univariate pow form ŵ_x(r) = Π_j((1−r_j) + r_j x^{2^{m'−j}}) (OOD/shift constraints); `Covector` (tests only, O(N) verifier).

**Commit**: encode, Merkle (domain-separated leaf/node; salted in ZK mode — every tree, incl. mask and base-case blinding trees) → root. **No OOD at commit. `Commit` does not touch the transcript**: the caller absorbs the root (P is committed at Setup, where no transcript exists). Commitment = root only.

**Open(forms, values)** on one commitment, any number of forms (B = 1):
1. absorb params digest, root, forms (descriptor), values;
2. γ: combine forms w₀ = Σ γ^ℓ form_ℓ, σ₀ = Σ γ^ℓ value_ℓ;
3. for each round i = 0..M−1 (zook round):
   - (ZK only) commit sumcheck-mask tree (k short masks), §3;
   - k sumcheck rounds on Σ_b v[b]w[b] = σ: send round polynomial as **coefficients (c₀, c₂)**, c₁ derived (as reference `protocols/sumcheck.rs`; WHIR's internal sumcheck is separate from `internal/sumcheck` in v1, unification in M4), optional PoW, α, fold v and w on MSB;
   - (ZK only) commit code-switch mask tree; send δ, reconcile σ;
   - **code switch**: commit f_{i+1} = Enc(v folded) on L_{i+1} (|L_{i+1}| = |L_i|/2); optional PoW (reference grinds **before** the OOD challenge, "Lemma 9.9 OOD gap"); s_i ≥ 1 OOD points + answers (ZK: via private zero-evader); t_i in-domain query indices into L_i, open leaves of f_i (v1: independent Merkle paths, indices deduplicated; multiproof is an M4 format change), verifier folds leaves; γ_i adds OOD + shift constraints to w, σ;
   - (ZK only) **mask proximity, every round** (`verify_and_discharge`): one protocol per mask tree (sumcheck-mask tree, cs-mask tree), each with its own γ and in-domain queries;
4. **base case** (reference `basecase`): Standard — send final vector v_M (and masks if any), t_M spot checks against f_M, then a **base-case sumcheck** over the remaining variables ending at r; check l(r) = sum / mle(v_M)(r), **reject if mle(v_M)(r) = 0** (honest prover aborts, probability ≤ m_M/p). ZK — blinding commitment, blinding inner product μ′, PoW, γ, combined vector and IRS randomness in clear, spot checks against both commitments, then the base-case sumcheck. **The exact per-round and base-case message order is transcribed from the pinned code in M1c (Standard) and M3 (ZK) into `docs/hyperplonk-whir/WHIR-TRANSCRIPT.md` before coding** (review-2 F2).
**Decision**: final claim σ_final = ṽ_M(r_fin)·W(r) with r the concatenation of all fold challenges and base-case points, W(r) = scale·Σ γ^ℓ form_ℓ.EvalMLE(r) + per-round constraint contributions on the right suffix of r; plus all sumcheck, Merkle and query checks. (Reference: `zook::FinalClaim::verify`.)
Verifier cost: Σ t_i(2^k mul + one path) + O(#forms·m) (+ mask trees in ZK).

**Binding in the Johnson regime.** Without commit-time OOD the initial codeword is only shown δ-close: the commitment fixes a list of ≤ ℓ₀ = 1/(2η√ρ) = 10/ρ codewords (80 at ρ = 1/8). Soundness of the composed SNARK takes a union bound over that list (SPEC-PIOP §5): ~log₂ 80 ≈ 6.3 bits per committed oracle against the PIOP terms (~2^-234), harmless. In UD, ℓ₀ = 1. 2026/391 proves RBR knowledge soundness of the IOR with a straightline extractor (§2.1).

## 2. Parameters

| Term | Bound |
|---|---|
| fold (per sumcheck round) | d·ℓ_i/|F| + err*(δ_i) |
| OOD (≥ 1 sample per round, all regimes) | (ℓ_i²/2)(2^{m_i}/|F|)^{s_i} |
| shift / queries | (1−δ_i)^{t_i} + ℓ_i(t_i+1)/|F| |
| base case | (1−δ_M)^{t_M} |
| form batching | (#forms−1)·ℓ/|F| |

Queries t_i = ⌈(λ − z_i)/(−log₂(1−δ_i))⌉, z_i = PoW bits.
- **UD**: δ = (1−ρ)/2, ℓ = 1, s = 1 (required by code switch, F5). err* from WHIR Lemma 4.10 / Cor. 4.11 (proven in WHIR).
- **JB (default)**: δ_i = 1 − √ρ_i − η_i, η_i = √ρ_i/20, ℓ_i ≤ 10/ρ_i, s = 1. MCA up to Johnson: Bordage–Chiesa–Guan–Manzur ePrint 2025/2051 (verified; rev. 2026-05-19) and Haböck ePrint 2025/2110 — **both unrefereed**. The reference `regime.rs` uses a linear-in-n constant labelled "BCSS25" (the paper is Ben-Sasson–Carmon–Haböck–Kopparty–Saraf, ePrint 2025/2055, i.e. **BCHKS25**): ε ≈ (2·10.5⁵/3)·n·ρ^{−3/2}/|F|. **Caveat:** 2025/2055 Thm 1.5 proves ordinary correlated agreement for lines; the *mutual* version WHIR needs is only outlined in its §4. The fully **proven** MCA bounds are O(n²)/|F|: Haböck 2025/2110 Thm 2 (ℓ⁷/3·(ρn)²) and Bordage–Chiesa–Guan–Manzur 2025/2051 Def. 9.1 / Thm 9.2 ((m+½)⁷/(3ρ^{3/2})·d·n²) — ≈ 2^-191 at m = 19. **`whirparams` may follow the reference constant, but pyref's checker uses the proven O(n²) bound**; either way it is far below 2^-130, so only query terms bind.
- **Capacity**: excluded — the up-to-capacity conjectures *as stated* are false (Crites–Stewart 2025/2046; 2025/2055's unconditional counterexamples use characteristic-2 structure, prime-field results are weaker/conditional; see SoK §5.4).

Round layout (reference `layout.rs`): keep folding by k while num_vars ≥ k_i + k_{i+1} (i.e. ≥ 8 for k = 4); the base case then holds ≤ 2^7 values. E.g. m = 18: 18 → 14 → 10 → 6, base case 6. Harness tuning pinned to `RateSchedule::Stepping`, `FoldingFactor::Constant(4)`, `PowBudget::Forbidden` (v1), `hash::SHA2`.

Estimates (λ = 128 shown; λ = 130 adds 0–1 queries/round in JB (90/44/29/22 → 91/45/30/22), ~2 in UD; k = 4, B = 1, 32-byte elements/digests, no path pruning — multiproofs save ~20–30 %):

| Regime | ρ | m | t_i | size |
|---|---|---|---|---|
| JB | 1/8 | 16 | 90, 44, 29 | ≈157 KiB |
| JB | 1/8 | 20 | 90, 44, 29, 22 | ≈200 KiB |
| UD | 1/8 | 16/20 | 155, 131, 129, … | ≈392/573 KiB |

**Per-proof estimate (to be replaced at G0)**: openings at m = μ+3 (P), μ+2 (W), μ+2 (H) → at 2^14: m = 17/16/16; at 2^16: m = 19/18/18. JB ρ = 1/8 ≈ 3 × 160–195 KiB ≈ **0.48–0.57 MiB at 2^16**, ≈ 0.46–0.49 MiB at 2^14 (round-0 queries dominate and barely shrink with m). After M4 (multiproof, 16-bit PoW, joint W+H): ≈ 0.3–0.4 MiB. **ZK overhead (unmeasured, estimate +40–80 % on the whole proof, ≈ +250–400 KiB over W and H)**: per ZK round a cs-mask tree (ℓ_zk ≈ 128 at the reference's fixed mask-code rate 2^-4 → ~2048 leaves, ~91 queries) and a sumcheck-mask tree (messages next_pow_2(mask_length) = 4 → ~64 leaves × 8 columns; reference does not deduplicate in-domain queries: ≈ 37 KiB, ≈ 8 KiB with dedup/multiproof), ~3 rounds + ZK base case. **Measured with the reference at G0** (RustRef prints real proof byte counts, both modes) and reported to the user before M1c.
**Default:** JB, ρ = 1/8, k = 4, s = 1, PoW 0 (16 in M4, placement and credited slot decided with a written note), reference layout rule; UD selectable. Grover halves the value of PoW bits (PQ note).

## 3. Zero knowledge (2026/391; port pinned `protocols/zook`)

Per round (reference `zook/prover.rs` header):
- **ZK encoding** (Prop. 3.19, Lemma 9.5): per-chunk randomness ≥ t_i + s_i; keep codeword length if effective rate ≤ 1.2ρ (reference `try_new`). **Deliberate deviation:** the reference then falls back to `next_order(masked_len/ρ)`, which on bn254 (`Field256` NTT order 9·2^28) can be non-power-of-two (e.g. 6144 = 3·2^11); gnark-crypto `fft` and our unbiased index sampling are power-of-two only, so **we round up to the next power of two**. Rounding up lowers the rate, which changes δ and t, so for **ZK rows our counts must be ≤ Rust's** and are re-checked by pyref's checker at our lengths; **equality is required only for Standard rows**.
- **ZK sumcheck** (Construction 6.3, Thm 6.2, Lemma 6.4/6.5): k short degree-2 masks, committed in a **sumcheck-mask tree before** the sumcheck; post-sumcheck sum δ + γ·dot.
- **ZK code switch** (Construction 9.7, Thm 9.6): fresh target encoding; cs_mask = (fold(source masks) ‖ fresh padding), committed in a **separate cs-mask tree after** the sumcheck; δ sent in clear and reconciled; OOD via **private zero-evader** (Def. 9.2, Lemma 9.3), requires t_ood ≥ 1.
- **Mask proximity** (Construction 7.2, Thm 7.1): run **every round**, once per mask tree (see §1 step 3).
- **ZK base case**: see §1 step 4.
- After FS: CSPRNG prover randomness; ROM.
- **Salted leaves — deliberate deviation** (the reference `matrix_commit`/`merkle_tree` has none): with only t + s random coefficients per chunk, a verifier who guesses a low-entropy witness can solve for the randomness from opened rows + OOD answers, recompute an unopened leaf and compare its hash. Salts (32 random bytes per leaf, every tree) stop this. Required test: the guess-confirmation attack succeeds without salts and fails with them.
- Never open one ZK oracle twice with independent query sets.
Overhead 1 + o(1) (Thm 1/4, Cor. 3). Joint openings (`joint.rs`, ZK since 2026-10-13, still changing) are not in v1.

## 4. PCS boundary (frozen in M0a; changes via coordinator)

The boundary lives in its own package **`internal/whir/pcs`**. Real WHIR (`internal/whir/bn254`) and the mock (`internal/whir/bn254/mock`) are two implementations of `pcs.Scheme`; the PIOP depends only on `pcs` and receives a `Scheme` (real by default, mock via unexported per-call config in its tests).

```go
package pcs

type HashID uint8 // 0 invalid; SHA256 = 1 (Poseidon2 later)
type Regime uint8 // 0 invalid; UniqueDecoding = 1, Johnson = 2
type Mode uint8   // 0 invalid; Standard = 1, ZeroKnowledge = 2

// Header: canonical parameter key, stored in the VK (single list for R6, PANURUS §3, transcript step 2).
type Header struct {
    TableVersion uint16
    NumVars, LogInvRate, FoldingFactor, PowBits, Security uint8
    Regime Regime; Mode Mode; Hash HashID
}

var (
    ErrInvalidProof   = errors.New("pcs: invalid proof")
    ErrUnknownParams  = errors.New("pcs: header not in parameter table")
    ErrUnsupported    = errors.New("pcs: mode not supported by this implementation")
)

type Commitment struct{ Root [32]byte }

type Cell struct{ Index uint32; Coeff fr.Element }

// LinearForm: ⟨form, table⟩. Bind writes Absorb("form", tag ‖ payload) with
// tag 1 = Eq(point), 2 = StackedEqSparse(slotBits, weights[], point[], cells[]), 3 = Sparse(cells[]);
// field elements canonical 32-byte BE, counts/indices u32 BE (FS-GRAMMAR.md).
type LinearForm interface {
    Size() int
    Accumulate(dst []fr.Element, scale fr.Element) // prover: dst += scale·form (dense)
    EvalMLE(r []fr.Element) fr.Element             // verifier: succinct
    Bind(t *fs.Transcript)
}
func NewEq(point []fr.Element) LinearForm
func NewStackedEqSparse(slotBits int, weights []fr.Element, point []fr.Element, cells []Cell) LinearForm
// slot s (top slotBits bits) weighted by weights[s]·eq(point,·) over its block (len(weights) ≤ 2^slotBits; missing = 0), plus Σ cells
func NewSparse(numVars int, cells []Cell) LinearForm

type Witness interface{ Commitment() Commitment }          // opaque, owned by the implementation
type Proof interface{ io.WriterTo; io.ReaderFrom }         // opaque

type Option func(*options) // test-only switches (disable a named check) — unexported fields, set from tests in the implementing package via export_test.go

type Scheme interface {
    Params(h Header) error // ErrUnknownParams / ErrUnsupported
    // Commit does NOT touch any transcript; the caller absorbs Root.
    // Standard mode: rng may be nil and is never read (deterministic). ZK: rng required (crypto/rand in production).
    Commit(h Header, table []fr.Element, rng io.Reader) (Witness, error)
    // Open must not mutate w; concurrent Opens on one Witness are safe (-race test).
    Open(t *fs.Transcript, h Header, w Witness, forms []LinearForm, values []fr.Element, rng io.Reader, opts ...Option) (Proof, error)
    Verify(t *fs.Transcript, h Header, c Commitment, forms []LinearForm, values []fr.Element, p Proof, opts ...Option) error
    NewProof(h Header) Proof
}
func Stack(cols [][]fr.Element) []fr.Element
```
- `Params`/`RoundParams`/`BaseParams` and the generated table are **internal to `internal/whir/bn254`** (owned by Calculator/WHIR, not frozen); the PIOP uses only `Header`. `Digest()` of a header = sha256 over the canonical encoding of the header ‖ the full table row (FS-GRAMMAR.md §digests).
- The mock accepts any header with `TableVersion = 0` (test-only), "commits" by hashing the table, and its proof is the table in clear; `Verify` recomputes ⟨form, table⟩. It honours the same `Option`s where meaningful.
- `Open` re-binds the header digest, root, forms and values at its start (step 1) even though the PIOP has absorbed some of them: explicit and harmless.
- `fs.Transcript` is owned by `internal/fs` (M0a).
- Mutation rule: **WHIR-level mutation tests live in `internal/whir`**; PIOP-level tests use only PIOP seams and the mock.

## 5. Pitfalls → required tests (each in R9 three-part form)

1. Transcript binding of digest/root/forms/values before γ — mutation sweep, every field rejected.
2. OOD present in every round and rejection-sampled outside L ∪ {0,1} (deviation: reference samples uniformly; kept) — tampered answer rejected; mutation flag "skip OOD constraint" makes a list-decoding cheater pass.
3. Bit order: chunking vs fold vs pow-MLE — property: fully folding ⟨v, x^·⟩ yields ŵ_x(r)·ṽ(r); KATs vs pyref. **Write first.**
4. Index sampling: power-of-two leaf counts + bit mask; chi-square.
5. Duplicate queries deduplicated identically in prover and verifier (v1); canonical multiproof in M4.
6. Base case: exactly 2^{m_M} values — ±1 length rejected; non-codeword with fitted final vector rejected N/N (0/N accepted, R11).
7. Sumcheck: lie v+1 for a form value rejected N/N, rejecting check recorded.
8. W(r) completeness and suffix alignment — one corrupted queried leaf rejected.
9. Merkle: domain separation, canonical elements, depth from params — leaf/node swap, non-reduced encoding rejected.
10. Challenge reduction from 512 bits (two sha256 squeezes; exact construction in SPEC-PIOP §3).
11. PoW nonce checked then absorbed — wrong nonce rejected.
12. ZK: per-chunk randomness ≥ t + s, salts (guess-confirmation attack test), mask trees ordering — per-sub-protocol linear rank tests (IRS randomness → opened rows + OOD answers), red with ZK off.
13. Base case: mle(v_M)(r) = 0 → reject.
14. Parameter table: every row re-checked by an exact/conservative security checker (`q·(−log2(1−δ)) ≥ λ` with margin; OOD/list, MCA terms); regeneration-and-diff test pinned to one GOARCH in CI; rows never edited in place (new rows or new `TableVersion`).
15. Edge cases: m < k, m_M = 0, zero forms; never derive parameters from the proof.

## 6. Citations per decision

Code: WHIR Def. 4.1/4.2. Folding: Def. 4.14, Claim 4.15. Rounds/errors: Construction 5.1, Thm 5.2; form batching: Construction 5.5, Thm 5.6. List sizes: Thm 4.3, Lemma 4.4. MCA UD: Lemma 4.10, Cor. 4.11; Conj. 4.12 (now: 2025/2051, 2025/2110). Johnson constant: reference constant from 2025/2055 Thm 1.5 (CA) + its §4 MCA outline; proven MCA: 2025/2051 Thm 9.2, 2025/2110 Thm 2. OOD: Lemma 4.24/4.25. Params: §6.2. Interleaved (zook) leaf: 2026/391 Def. 2.7 / 3.22 (WHIR §2.1.4 is the legacy per-coset variant). zook/ZK: 2026/391 Def. 2.7/2.8, Claim 2.9, §2.1 (RBR KS, straightline extractor), Def. 3.16, Prop. 3.19, Thm 6.2, Constr. 6.3, Lemma 6.4/6.5, Thm 7.1, Constr. 7.2, Def. 9.2, Lemma 9.1/9.3/9.5, Thm 9.6, Constr. 9.7, Thm 9.10, Thm 4, Cor. 3, Lemma 2.6. Capacity refuted: SoK §5.4. FS/grinding: SoK §5.5.
