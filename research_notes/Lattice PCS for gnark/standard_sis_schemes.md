# Lattice PCS from standard assumptions (Ajtai + folding / LaBRADOR lineage): fit for univariate PLONK over bn254 Fr

Source access note: eprint.iacr.org returned HTTP 403 for every PDF (both WebFetch and curl). Abstract pages were readable but only as model summaries, not verbatim text. Most of the detailed technical facts below therefore come from the full text of Akita (ePrint 2026/1983; local copy at `resources/2026-1983.pdf`), which has a 2026 related-work section, a comparison table (Table 1), independent benchmarks of Greyhound and RoKoKo (Table 9), and an audit appendix of prior papers and code (Appendix F). Facts taken from Akita are marked "(via Akita)". I could not read any primary paper's parameter tables (Greyhound, LaBRADOR, Hachi, SLAP, FMN, LaZer-ZK).

Scheme roster (2023–2026, standard or near-standard lattice assumptions):
- LaBRADOR (Beullens–Seiler, CRYPTO 2023): base proof system, not a PCS.
- Greyhound (Nguyen–Seiler, CRYPTO 2024, ePrint 2024/1293): first concretely efficient lattice PCS, univariate.
- SLAP (Albrecht–Fenzi–Lapiha–Nguyen, EUROCRYPT 2024, ePrint 2023/1469): polylog, asymptotic.
- FMN (Fenzi–Moghaddas–Nguyen, ePrint 2023/846; J. Cryptology 37(3) 2024): ring-BASIS.
- Cini–Malavolta–Nguyen–Wee (CMNW, CRYPTO 2024, ePrint 2024/281): univariate, transparent, Module-SIS.
- CELPC (Hwang–Seo–Song, CRYPTO 2024, ePrint 2024/306): square-root sizes, transparent.
- Jindo (Hwang–Lee–Seo–Song, ePrint 2026/044): multilinear, cube-root, Go implementation.
- Hachi (Nguyen–O'Rourke–Zhang, ePrint 2026/156): multilinear over extension fields.
- Grand Danois (Kallesøe–Khoshakhlagh, ePrint 2026/1196): uses the vSIS assumption, so not standard.
- RoKoKo (Klooß–Lai–Nguyen–Osadnik–Tucci, ePrint 2026/575): uses vSIS, so not standard; comparison point only.
- Maltese (Cheng–Nguyen–Tyagi, ePrint 2026/2067): Module-SIS, Merkle tree over the Ajtai hash.
- LaBinius (Osadnik–Seiler, ePrint 2026/2103): binary-field claims, composite commitment modulus.
- Biasioli et al. ZK toolkit (ePrint 2026/1289): adds ZK to LaBRADOR in LaZer.
- Orthus (ePrint 2026/398, CRYPTO 2026): batch verification, not a PCS.
- Akita (ePrint 2026/1983): already assessed; comparison only.

## 1. Polynomial type and evaluation-claim interface

### Takeaway
Only Greyhound and CMNW in the concrete/standard-SIS group are natively univariate, with f(x) = v for f ∈ Z_q[X] and x, v ∈ Z_q (or over R_q for CMNW). Every 2026 scheme (Hachi, Jindo, Grand Danois, Akita, Maltese, LaBinius, RoKoKo) is multilinear. In all of them the claim lives in Z_q, in an extension F_{q^k}, or (LaBinius only) in a binary field. In every case the field is tied to the commitment modulus, not chosen freely.

### Cited Findings
- Greyhound: a three-round protocol proves evaluations of polynomials "of bounded degree N", with O(√N) verifier time. Composing it with LaBRADOR yields polylog proofs — [ePrint 2024/1293 abstract page](https://eprint.iacr.org/2024/1293).
- Greyhound's "split-and-fold evaluation protocol has a square-root verifier, and recursive compression gives a reported 53 KB proof at degree 2^30" (via Akita) — [Akita, ePrint 2026/1983, §1.2](https://eprint.iacr.org/2026/1983).
- CMNW: univariate polynomials f ∈ R[X] of degree L. The prover shows f(x) = u at public x, u ∈ R. The artifact supports "polynomials over R_q" or "polynomials over Z_q". The Z_q option uses ring degree d = 256 via the generic transformation of AFLN23 (SLAP) §5.5 — [ePrint 2024/281](https://eprint.iacr.org/2024/281); [IACR artifact readme](https://artifacts.iacr.org/crypto/2024/a5/readme.html).
- FMN: commits to p of degree d and proves p(u) = z. The abstract page does not say univariate or multilinear. The paper instantiates a SNARK with Marlin, a univariate PIOP — [ePrint 2023/846](https://eprint.iacr.org/2023/846).
- SLAP: a "tree-based commitment scheme, along with an efficient proof of polynomial evaluation", inspired by FRI — [ePrint 2023/1469](https://eprint.iacr.org/2023/1469).
- Hachi: multilinear PCS for ℓ-variate polynomials over extension fields F_{q^k}. It includes a generic reduction from evaluation claims over F_{q^k} to statements over R_q — [ePrint 2026/156](https://eprint.iacr.org/2026/156).
- Hachi's base-field specialisation (§3.2: base-field coefficients, extension-field point) is unsound as published. Two E-linear checks do not bind the partial evaluations, and Akita gives an explicit forgery v′ ≠ v. The Hachi authors told Akita they had corrected later, non-public versions. The generic §3.1 transformation is unaffected (via Akita) — [Akita App. F.1](https://eprint.iacr.org/2026/1983).
- Jindo "supports multilinear polynomials" and "diverse field choices" — [ePrint 2026/044](https://eprint.iacr.org/2026/044).
- Maltese: multilinear, N = 2^30 — [ePrint 2026/2067](https://eprint.iacr.org/2026/2067).
- LaBinius: the claim lives in a binary extension field; the commitment uses a composite NTT-friendly modulus — [ePrint 2026/2103](https://eprint.iacr.org/2026/2103).
- LaBRADOR is a proof system for R1CS and dot-product/norm relations, not a PCS. Its reported proofs are 47–58 KB for R1CS with 2^10–2^20 constraints (via Akita) — [Akita §1.2](https://eprint.iacr.org/2026/1983).

### Inferences
- For gnark's existing univariate `Scheme` seam (claims at ζ and ωζ), Greyhound is the only concretely efficient candidate that matches the interface natively. CMNW matches the interface, but its proofs are megabytes (see §4).
- The multilinear schemes could serve univariate claims the same way WHIR does (weight ⊗ⱼ(1, ζ^(2^j))). Only Hachi-style multilinear-over-F_{q^k} schemes come with an explicit reduction, and that reduction is to the commitment modulus's own field.

### Gaps
- I could not confirm from the Greyhound PDF that coefficients and evaluation point are exactly in Z_q (not R_q). This is consistent with the abstract and with Akita calling it a "field" scheme, but unverified.
- FMN's and SLAP's exact polynomial interface (univariate over Z_q vs R_q) is not readable from the abstract pages.

## 2. Ring, modulus and splitting requirements; can q = r (bn254 Fr)?

### Takeaway
LaBRADOR, Greyhound and Hachi are all instantiated at q ≈ 2^32 with minimal splitting: X^d + 1 splits into 2 factors, q ≡ 5 (mod 8), d = 64. The evaluation field must equal Z_q or F_{q^k} for the commitment modulus q. No scheme in this family was found that proves claims over an unrelated large prime field. Setting q = r (254-bit, fully splitting) is not excluded by the soundness issue that breaks small fully-split rings, because each CRT factor then has size r. But no paper parameterises or analyses it.

### Cited Findings
- The partial-splitting condition: if q ≡ 2s + 1 (mod 4s), then X^d + 1 splits into s irreducible factors of degree d/s. "The case s = 2 (i.e. q ≡ 5 (mod 8)) is the minimal splitting used in most prior work [LaBRADOR, Greyhound, Hachi]". A larger s gives faster NTT but "a tighter invertibility threshold" (via Akita) — [Akita §3.1](https://eprint.iacr.org/2026/1983).
- "Akita and Greyhound use the same 32-bit field" in the Akita benchmarks. The Greyhound reference fork refers to a "32-bit modulus" and "64-coefficient input polynomials" — [Akita §13.2](https://eprint.iacr.org/2026/1983); [LayerZero greyhound-reference](https://github.com/LayerZero-Labs/greyhound-reference). Akita's 32-bit profile is 2^32 − 99, per the project's earlier Akita reading (PROJECT.md 2026-10-25), and 2^32 − 99 ≡ 5 (mod 8) (computed).
- "Fully- or near-fully-splitting rings often do not admit rigorous challenge sets". Works using them (PikkuFold, RoKoKo, Cyclo, Jindo) accept "only heuristic guarantees on these fold challenges" (via Akita) — [Akita §1.2](https://eprint.iacr.org/2026/1983).
- LaBinius: "the need for invertible challenge differences … rules out fully splitting moduli". Also "the constraint field's characteristic must equal the commitment modulus" in existing schemes. LaBinius decouples the two only for binary extension fields — [ePrint 2026/2103](https://eprint.iacr.org/2026/2103).
- zkSecurity (2026-04-30) found that LaBRADOR needs X^d + 1 to split into exactly two factors so that each factor has order q^{d/2}. Implementations over NTT-friendly rings with small factors lost soundness. icicle-labrador (KoalaBear×BabyBear composite) had about 31 bits; condor-rs (q = 2^32 − 1) about 6 bits; Lazarus (Z_{2^32}) about 1 bit. lattice-dogs/labrador and LaZer were not affected — [zkSecurity blog](https://blog.zksecurity.xyz/posts/labrador-bugs/).
- Hachi works over power-of-two cyclotomic R_q = Z_q[X]/(X^d + 1) with claims over F_{q^k}. The Hachi/Akita concrete parameters use extension degree k = 4 (via Akita) — [ePrint 2026/156](https://eprint.iacr.org/2026/156); [Akita App. F.1](https://eprint.iacr.org/2026/1983).
- The CMNW artifact searches over log q, n, d and other parameters under MSIS hardness checks at λ = 128. The Z_q mode fixes d = 256 — [IACR artifact readme](https://artifacts.iacr.org/crypto/2024/a5/readme.html).

### Inferences
- Computed for bn254 Fr: log₂ r ≈ 253.6 and 2-adicity 28, so r ≡ 1 (mod 4d) and X^d + 1 splits fully (s = d) for every d ≤ 2^27.
- The LS18 small-invertibility bound is ‖c − c′‖∞ < q^{1/s}/√s. I recalled this from Lyubashevsky–Seiler 2018 (ePrint 2017/523, Cor. 1.2) and did not fetch the paper. With s = d and q = r it gives:
  - d = 16: ≈ 14 764
  - d = 32: ≈ 43.0
  - d = 64: ≈ 1.95
  - d = 128: ≈ 0.35

  So a rigorous invertible challenge set exists for q = r at d ≤ 32. For example, coefficients in [−21, 21] at d = 32 give about 43^32 ≈ 2^173 challenges. At d = 64 even ternary challenges fail (differences up to 2). This would replace d = 64 with d ≤ 32.
- The zkSecurity failure mode (soundness ≈ 1/(size of the smallest CRT factor)) does not apply to q = r, because each factor is F_r of size 2^254.
- Main costs of q = r, not quantified by any source:
  - 254-bit coefficients must be gadget-decomposed into small digits, which multiplies the witness length by about 254/log₂(b).
  - Ring arithmetic runs on 4-limb multiprecision instead of 32-bit words.
  - MSIS dimensions grow with log q.

  Expect commitment and prover cost to be much worse than the 32-bit benchmarks. Proof size, which scales with log q, would also grow.
- Alternative: commit over a small q and switch fields. No published reduction maps a claim over bn254 Fr onto a small-q lattice commitment. LaBinius decouples only for binary fields; Hachi's reduction works only for F_{q^k} with the same q. Doing this would be new research.

### Gaps
- No paper or implementation found that instantiates Greyhound, LaBRADOR or Hachi at a ~254-bit prime modulus, or estimates its sizes.
- I could not confirm the exact Greyhound modulus value from the Greyhound paper itself (PDF blocked).
- Jindo's "diverse field choices" are unspecified on the abstract page; it may support larger NTT-friendly primes (worth a direct read).

## 3. Assumptions, setup, soundness model, zero-knowledge

### Takeaway
Greyhound, Hachi, CMNW, CELPC, Jindo, Maltese and Akita claim plain Module-SIS with transparent setup. FMN (ring-BASIS) and SLAP (Power-Ring BASIS natively, reduced to Module-SIS) rest on BASIS-type assumptions. Fiat–Shamir is proven only in the classical ROM for the Greyhound/Hachi/Akita line; CMNW claims knowledge soundness against quantum adversaries. ZK is not native to Greyhound or Hachi. It exists for LaBRADOR via LNP22 (Biasioli et al.) at linear-size overhead, and Jindo claims evaluation hiding.

### Cited Findings
- Greyhound and Hachi "obtain small proofs from standard Module-SIS". Grand Danois and RoKoKo lean on "vanishing SIS … that ha[s] received far less cryptanalytic attention" (via Akita) — [Akita §1](https://eprint.iacr.org/2026/1983).
- Implementation-level assumption gap: the LaBRADOR and Greyhound C implementations compute commitments by extension-ring products truncated to κ < p coordinates. Collisions are then not Module-SIS solutions; Akita calls this "truncated-output Ring-SIS". Greyhound's paper (§6.1) mentions extension rings but not the truncation (via Akita) — [Akita App. F.2](https://eprint.iacr.org/2026/1983).
- Akita also had to fix the Greyhound reference's Johnson–Lindenstrauss projection. The dense-sign projection did not match the certified tail bound, so it was replaced by sparse ternary with slack √(128/29). It added challenge grinding for completeness failures (via Akita) — [Akita §13.2](https://eprint.iacr.org/2026/1983).
- The folding analysis in this line uses coordinate-wise special soundness (from FMN) with a classical-ROM Fiat–Shamir theorem: "This statement is not a QROM theorem" (via Akita) — [Akita §3](https://eprint.iacr.org/2026/1983).
- CMNW: the interactive variant relies on "standard (Module-)SIS". Setup is transparent; it is non-interactive via Fiat–Shamir in the ROM, and it claims knowledge soundness against quantum adversaries — [ePrint 2024/281](https://eprint.iacr.org/2024/281); Akita describes it as "knowledge soundness against quantum adversaries" — [Akita §1.2](https://eprint.iacr.org/2026/1983).
- FMN: extractable in the ROM under a "natural ring version" of BASIS (Wee–Wu, EUROCRYPT 2023). Its SNARK is described as "publicly-verifiable trusted-setup". A revision switched from decisional NTRU to statistical NTRU — [ePrint 2023/846](https://eprint.iacr.org/2023/846).
- SLAP: natively a "multi-instance version" of Power-Ring BASIS, "fully reduced to Module-SIS" by re-randomisation — [ePrint 2023/1469](https://eprint.iacr.org/2023/1469).
- CELPC: "standard lattice-based assumptions", transparent setup — [ePrint 2024/306](https://eprint.iacr.org/2024/306).
- Jindo uses a heuristic challenge set (via Akita) — [Akita §1.2](https://eprint.iacr.org/2026/1983). It claims evaluation hiding with "sublinear masking overhead" — [ePrint 2026/044](https://eprint.iacr.org/2026/044).
- Maltese: "secure under the standard Module-SIS assumption" — [ePrint 2026/2067](https://eprint.iacr.org/2026/2067).
- Biasioli et al. give the "first concrete construction and implementation" of ZK for LaBRADOR. It integrates the linear-size ZK proof of Lyubashevsky–Nguyen–Plançon (CRYPTO 2022), which was previously only described (in LaBRADOR, AFLN EUROCRYPT 2024, del Pino et al. CRYPTO 2025) — [ePrint 2026/1289](https://eprint.iacr.org/2026/1289).
- Akita (comparison): Module-SIS, classical ROM only, QROM "future work", no ZK yet — [Akita §1.1, §14](https://eprint.iacr.org/2026/1983).

### Inferences
- BASIS-type schemes (FMN; SLAP natively) need a CRS sampled with a trapdoor, i.e. not transparent. FMN's "trusted-setup" wording supports this for FMN; for SLAP I did not confirm it.
- For a PQ target, none of the concretely efficient schemes (Greyhound, Hachi, Akita) currently has a QROM proof. That is the same weakness the project already noted for Akita.
- A ZK Greyhound would most plausibly use the same LNP22 masking as the Biasioli toolkit, with linear-size overhead. No paper quantifies this for Greyhound specifically.

### Gaps
- Whether Greyhound's or Hachi's papers discuss ZK at all (PDFs blocked).
- CMNW's exact quantum-soundness model (QROM Fiat–Shamir vs interactive only) is not clear from the abstract page.

## 4. Concrete numbers

### Takeaway
Greyhound-family proofs are about 46–66 KB at 2^22–2^30 coefficients over a 32-bit field, but verification is square-root: 0.07–1.5 s single-thread in independent measurement. Hachi is about 55 KB (an estimate), with a claimed 12.5× faster verifier than Greyhound. The asymptotically succinct standard-assumption schemes (FMN, SLAP, CMNW, Maltese) are 0.3–767 MB at 2^30. All numbers are for ~32-bit (or ~50-bit) moduli; nothing is measured at a 254-bit modulus.

### Cited Findings
- Akita Table 1: Greyhound 46–53 KB at N = 2^26–2^30 (reported). Hachi 55 KB at N = 2^30 "(estimate)". Jindo 315–1207 KB at N = 2^14–2^20, with Õ(N^{1/3}) verifier. RoKoKo (vSIS) 115 KB. Grand Danois (vSIS) 80–90 KB at 2^32 "(estimate)" — [Akita Table 1](https://eprint.iacr.org/2026/1983).
- At degree 2^30, FMN, SLAP and CMNW "report proofs of 8.3 MB, 767 MB, and 5.17 MB" respectively (via Akita) — [Akita §1.2](https://eprint.iacr.org/2026/1983).
- Independent Greyhound benchmark (security-recalibrated revision 687a6f8; AMD Ryzen 9 9950X; one thread; 32-bit field). Proof sizes exclude the commitment.

  | Committed bits (coefficients) | Commit | Open | Verify | Proof | Peak RAM |
  |---|---|---|---|---|---|
  | 2^27 (2^22) | 0.108 s | 0.183 s | 73.8 ms | 59.3 KB | — |
  | 2^29 (2^24) | 0.425 s | 0.368 s | 138 ms | 59.3 KB | — |
  | 2^31 (2^26) | 2.20 s | 1.07 s | 305 ms | 64.6 KB | — |
  | 2^33 (2^28) | 11.0 s | 4.29 s | 641 ms | 64.6 KB | — |
  | 2^35 (2^30) | 59.4 s | 21.3 s | 1525 ms | 66.1 KB | 104.8 GiB |

  Akita, same table and machine: verification 7.6–33.3 ms direct and 8.1–16.2 ms offloaded; 61–67 KB — [Akita Table 9](https://eprint.iacr.org/2026/1983).
- Greyhound's own claims: about 53 KB at degree ≤ 2^30, ">10^4 times smaller than SLAP" and about 3 orders of magnitude smaller than Ligero/Brakedown — [ePrint 2024/1293](https://eprint.iacr.org/2024/1293). A secondary summary says the IBM Research publication page gives 93 KB instead — [IBM Research](https://research.ibm.com/publications/greyhound-fast-polynomial-commitments-from-lattices). Unresolved; possibly a pre-revision figure.
- Greyhound reference fork (Apple M4 Max, 8 threads, portable backend): median proofs about 56 KB at 2^20 to about 64 KB at 2^25/2^28, with about 128–131-bit quantum security (ADPS16). The README flags these as historical and needing re-benchmarking — [greyhound-reference README](https://github.com/LayerZero-Labs/greyhound-reference).
- Hachi: about 55 KB, a 12.5× verifier speedup over Greyhound, and an Õ(λ) asymptotic verifier improvement — [ePrint 2026/156](https://eprint.iacr.org/2026/156). Its artifact measures only the first folding round, not an end-to-end opening. The concrete protocol does one Hachi fold and then hands off to a Greyhound tail (via Akita) — [Akita §1.2, App. F.1](https://eprint.iacr.org/2026/1983).
- LaBRADOR + ZK (Biasioli et al.): on large instances, verification takes more than 1 s and runs at one-third to one-half of proving time (Akita citing Tables 1–2 of 2026/1289) — [Akita §1 footnote 3](https://eprint.iacr.org/2026/1983). The abstract claims LaBRADOR-based proofs under 100 KB — [ePrint 2026/1289](https://eprint.iacr.org/2026/1289).
- Maltese: 335 KB at N = 2^30. That is about 300× smaller than prior polylog-verifier schemes, and 2–6× larger than square-root or structured-assumption schemes — [ePrint 2026/2067](https://eprint.iacr.org/2026/2067).
- LaBinius: under 100 KiB with LaBRADOR compression; verification under 40 ms; binary-field claims only — [ePrint 2026/2103](https://eprint.iacr.org/2026/2103).
- CMNW: at L = 2^20, about 2× smaller than FRI (Block et al.) and about 70× smaller than SLAP — [ePrint 2024/281](https://eprint.iacr.org/2024/281).
- CELPC: comparable to Brakedown on all metrics; proofs about 4.1× smaller than SLAP — [ePrint 2024/306](https://eprint.iacr.org/2024/306). Jindo: about 10× better than CELPC; about 10× faster proving than PIP-FRI with similar verification and size — [ePrint 2026/044](https://eprint.iacr.org/2026/044).
- FMN: 17 MB for 2^20 R1CS constraints with Marlin — [ePrint 2023/846](https://eprint.iacr.org/2023/846).

### Inferences
- For the gnark FRI baseline (hundreds of KB of proof, ms-scale verification), Greyhound would trade proof size (~60 KB, a gain) for verifier time (0.1–1.5 s, a large loss) at 32-bit parameters. At a 254-bit modulus all of these numbers are unknown and likely worse in time.
- Proof sizes across papers use different security models (ADPS16 core-SVP, other cost models, estimates vs measurements). Akita warns these are "not an apple-to-apple parameter comparison".

### Gaps
- Greyhound's own paper tables (prover/verifier times at 2^30) were not readable.
- Hachi prover/verifier absolute timings are not available from the abstract page.
- No concrete numbers for any scheme at a 254-bit modulus.

## 5. Implementations

### Takeaway
All mature artifacts are C with AVX-512, or Rust, at 32/50-bit moduli. There is a Go implementation for Jindo (repository not located), but none for Greyhound or Hachi. None targets a 254-bit field, and several public LaBRADOR ports were found unsound.

### Cited Findings
- lattice-dogs/labrador (IBM upstream): LaBRADOR plus the Chihuahua, Dachshund and Greyhound front ends. AVX-512 only ("can only be compiled for and run on CPUs that support the AVX512"); 5 commits, 54 stars — [GitHub lattice-dogs/labrador](https://github.com/lattice-dogs/labrador).
- LayerZero-Labs/greyhound-reference: C2x research fork of lattice-dogs at 8b6626b, Apache-2.0 (upstream © IBM 2024). It adds a portable/SIMDe backend and an L2-quantum-128 ADPS16 policy; unaudited; "not an end-to-end security proof" — [GitHub greyhound-reference](https://github.com/LayerZero-Labs/greyhound-reference).
- LaZer: C with Python (cffi) bindings and a `golang` directory; MIT licence. Requires AVX-512 + AES and Linux x86-64. Parameters are generated from `*params.py` by Sage — [GitHub lazer-crypto/lazer](https://github.com/lazer-crypto/lazer). The ZK toolkit (2026/1289) extends LaZer — [ePrint 2026/1289](https://eprint.iacr.org/2026/1289).
- Akita Table 1 artifacts: Greyhound is "End-to-end C, AVX-512 only"; Hachi is "Partial Rust, single fold"; Jindo is "End-to-end Go"; RoKoKo is "End-to-end Rust"; Grand Danois has "No implementation" — [Akita Table 1](https://eprint.iacr.org/2026/1983).
- Benchmark harness covering hash-based and lattice PCSs — [LayerZero-Labs/pcs-benchmarks](https://github.com/LayerZero-Labs/pcs-benchmarks), cited in [Akita §13](https://eprint.iacr.org/2026/1983).
- CMNW: parameter-estimation Python script only (numpy/scipy), no prover — [IACR artifact](https://artifacts.iacr.org/crypto/2024/a5/readme.html).
- Unsound third-party LaBRADOR ports: Lazarus (Rust), icicle-labrador (C++), condor-rs (Rust), and an example in lattirust/labrador — [zkSecurity blog](https://blog.zksecurity.xyz/posts/labrador-bugs/).

### Inferences
- A gnark port of Greyhound would be a from-scratch Go implementation of LaBRADOR plus Greyhound: ring NTT, gadget decomposition, JL norm proofs, recursion and a parameter planner. Jindo's Go code, if public, is the nearest Go reference, but it is multilinear and cube-root.
- gnark-crypto's Ring-SIS (Vortex) targets small fully-split primes. It is not directly reusable for a q ≡ 5 (mod 8) ring, but may be for q = r with d ≤ 32 if that path is pursued.

### Gaps
- Jindo's repository URL and licence were not found.
- Licences of lattice-dogs/labrador and the Hachi artifact were not stated on the fetched pages.
