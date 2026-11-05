# Cross-cutting obstacles and Go tooling for a lattice PCS in univariate PLONK over bn254 Fr

Scope note: research done 2026-10-25. ePrint abstract pages were fetchable, but ePrint PDFs returned HTTP 403 (for example eprint.iacr.org/2026/1983.pdf), so paper bodies could not be checked. Where a claim depends on a paper body, it is flagged. GitHub facts come from the GitHub API (`gh api repos/...`) on 2026-10-25.

## 1. The modulus mismatch: proving F_p relations when the lattice modulus q differs from p, or when p is a large fully splitting prime

### Takeaway
No surveyed lattice PCS confirms support for a 254-bit prime field. The working implementations use primes of 24 to 64 bits (LaBRADOR/Greyhound), or 32, 64 and 128 bits (Akita). The bridging techniques that exist are these:
- ring switching (Huang–Mao–Zhang), which goes from Z_Q[X]/(X^N+1) to fields or Galois rings;
- extension-field-to-ring reductions (Hachi);
- lifting from Z_q to Z by approximate range proofs (LNP22);
- per-prime CRT splitting (verifiable FHE).

Each of these assumes that the field is Z_q itself or an extension of it, or else pays a large q-versus-p overhead. The one place where Ring-SIS over a roughly 253-bit SNARK field already runs is gnark-crypto's `ecc/bls12-377/fr/sis`. It is a hash or commitment, not a full PCS.

### Cited Findings
- Huang, Mao and Zhang, "Sublinear Proofs over Polynomial Rings" (USC), introduce "ring switching". It transforms proofs about polynomial-ring arithmetic into proofs over finite fields or Galois rings with prime-power modulus. The paper builds an argument for Ring-R1CS over Z_Q[X]/(X^N+1) for arbitrary prime-power Q, and it works with NTT-friendly and power-of-two moduli. In this paper F_p is the *target* of the switch, not a separate field with an independent lattice modulus. — [ePrint 2025/199](https://eprint.iacr.org/2025/199)
- Hachi (Nguyen, O'Rourke, Zhang) is a lattice multilinear PCS over extension fields F_{q^k}. Its lattice operations run in R_q = Z_q[X]/(X^d+1). It combines Greyhound with HMZ ring switching. It also gives a "generic reduction" that turns evaluation proofs over extension fields into statements over cyclotomic rings, which other lattice PCSs can reuse. The abstract does not mention large prime fields. — [ePrint 2026/156](https://eprint.iacr.org/2026/156)
- LNP22 (Lyubashevsky, Nguyen, Plançon, CRYPTO 2022) proves knowledge of short s with As = t mod q. Inner products are proven "modulo q". Then "using a cheap, approximate range proof, one can then lift the proof to be over Z instead of Z_q." The abstract does not state that relations modulo a different p can be proven. — [ePrint 2022/284](https://eprint.iacr.org/2022/284)
- A speaker abstract on the LNP22 line lists "integer relations, approximate range proofs, and product relations over the native ring" among the provable statements. — [Monash seminar page](https://www.monash.edu/it/ssc/cybersecurity/seminars/2022/lattice-based-zero-knowledge-proofs-and-applications-shorter,-simpler,-and-more-general)
- LaZer (IBM) lets users state lattice relations and norm bounds. It generates the proof system, using LaBRADOR for succinct proofs or LNP22 for linear-size proofs. The abstract does not mention which moduli are supported. — [ePrint 2024/1846](https://eprint.iacr.org/2024/1846)
- A 2026 NIST threshold-call preview describes LaZer as proving lattice relations natively, in module-ring arithmetic, without first arithmetizing them into a circuit. (Seen in a search-result summary only; the page itself was not fetched.) — [NIST CSRC presentation](https://csrc.nist.gov/presentations/2026/tcpt2-2b1)
- The LaBRADOR/Greyhound C reference implementation fixes ring degree N = 64. It has compile-time LOGQ ∈ {24, 32, 40, 48, 56, 64}, with data24.c to data64.c and QOFF offsets, which means pseudo-Mersenne q = 2^k − offset. No 254-bit option exists. — [lattice-dogs/labrador data.h](https://github.com/lattice-dogs/labrador)
- Akita's repository ships schedule artifacts only for the families fp32, fp64 and fp128 (dense, one-hot, recursive variants). Its README lists "smaller large-field proofs via field-size lowering" as a *planned* improvement. — [LayerZero-Labs/akita README and artifacts/schedules](https://github.com/LayerZero-Labs/akita)
- The LatticeFold authors stress that it uses a small 64-bit field, unlike the 256-bit fields of discrete-log folding schemes. — [LatticeFold, ePrint 2024/257](https://eprint.iacr.org/2024/257.pdf)
- Designated-verifier lattice zkSNARKs need the lattice modulus to be much larger than the field: roughly q > 2p²N for correctness. Splitting the linear-PCP coefficients lets them support larger fields while keeping q ≤ 128 bits. (Search-result summary of the paper.) — [Shorter and Faster PQ DV-zkSNARKs from Lattices](https://www.cs.utexas.edu/~dwu4/papers/LatticeDVSNARKs.pdf)
- Verifiable FHE avoids the mismatch by proving each RNS prime q_i separately, giving one SNARK over Z_{q_i} per sub-circuit, and concatenating the proofs. — [ePrint 2024/032](https://eprint.iacr.org/2024/032.pdf)
- gnark-crypto contains a Ring-SIS hash over a roughly 253-bit SNARK scalar field, at `ecc/bls12-377/fr/sis`. It has `NewRSis(seed, logTwoDegree, logTwoBound, maxNbElementsToHash)` and works in Z_p[X]/(X^d+1). Inputs are broken into limbs of `LogTwoBound` bits; the code requires a multiple of 8, at most 64, and documents "B ≥ 3". A fast path exists for degree 64 with a 16-bit bound. Other `sis` packages exist for babybear, goldilocks, koalabear and mamabear. **There is no `ecc/bn254/fr/sis`.** The bn254/fr directory holds fft, iop, mimc, pedersen, permutation, polynomial and poseidon2, but no sis. — [gnark-crypto pkg listing](https://pkg.go.dev/github.com/consensys/gnark-crypto@master); [gnark-crypto repo](https://github.com/consensys/gnark-crypto)

### Inferences
- **Option q = r (native).** Take the bn254 scalar r as the lattice modulus, so R_r = Z_r[X]/(X^d+1) with d | 2^27. Then PLONK's F_r is the coefficient ring of R_r, and HMZ/Hachi-style ring switching applies directly, with F_r as the base field (k = 1). This avoids any mod-p emulation.
  - The cost is that Ajtai/SIS commitments bind only *short* witnesses. Every 254-bit F_r coefficient must be decomposed into digits, for example 254/16 ≈ 16 limbs at a 16-bit bound, as gnark-crypto's RSis does with `LogTwoBound`.
  - That decomposition multiplies the committed witness size by about 16×. Each ring element then costs about 254 bits, versus 32 or 64 bits in Greyhound or Akita, so ring arithmetic per coefficient runs roughly 4 to 8× slower.
  - This is my estimate, not a measured figure.
- **Option q ≠ r (small q, emulate F_r).** The PLONK relations, which are products in F_r, would have to be proven as integer relations: a·b − c − r·k = 0 over Z, with range-bounded k. That means LNP22-style lifting from Z_q to Z, plus range proofs on 254-bit limbs, or CRT over several small primes.
  - No surveyed paper gives a concrete PCS for that case, so it is the costlier and less-trodden path.
- **Integration effort.** The most realistic route to a "lattice PCS over bn254 Fr" is a q = r instance of a Greyhound/Hachi-type scheme.
  - None of the existing codebases supports this without re-parameterisation. LaBRADOR is hard-wired to N = 64 and q ≤ 2^64; Akita offers fp32/64/128.
  - gnark-crypto's bls12-377 SIS code is the closest existing component, being a generator template for a 25x-bit field.

### Gaps
- No paper was found that states support for 254-bit or BN254 fields in a lattice PCS. Akita's README mentions "field-size lowering" without detail.
- Whether LaBRADOR's or LaZer's newer "toolkit" (IBM, "A Toolkit for Succinct Lattice-Based Zero Knowledge Proofs") supports proving relations modulo an arbitrary p ≠ q could not be confirmed from abstracts.
- The exact costs of HMZ ring switching when the base ring is Z_r with r 254-bit were not available; the papers' bodies were blocked.

## 2. Module-SIS / Ring-SIS security with a 254-bit, fully splitting modulus

### Takeaway
For bn254, r ≡ 1 (mod 2^28), so X^d+1 splits into d linear factors mod r for every d ≤ 2^27. That is the "fully splitting" case, where Lyubashevsky–Seiler's guarantee that short challenge differences are invertible becomes weak.

Akita deliberately avoids this case through its q ≡ 2s+1 (mod 4s) condition, which is exactly the Lyubashevsky–Seiler partial-splitting condition. SIS hardness itself is not hurt by a large q, but the parameters have to be re-estimated. Akita sizes its parameters with an LGSA estimator under the ADPS16 quantum core-SVP model.

### Cited Findings
- Lyubashevsky and Seiler (EUROCRYPT 2018) state that practical lattice ZK proofs need challenge sets that are large, have small norm, and have *all nonzero differences invertible*. They show that short nonzero polynomials in Z_p[X]/(Φ_m) are invertible, with a bound that depends on the size of p and on how many irreducible factors Φ_m splits into. Earlier work split only into two factors, which is slow, or used low degree, which gives larger norms. — [ePrint 2017/523](https://eprint.iacr.org/2017/523)
- Akita's production SIS sizing rule says the scalar ℓ∞ LGSA estimator must report ≥ 128 bits under the ADPS16 quantum cost model, with inputs n = rank·d, m = width·d and length bound B. The policy was later raised to "Quantum169BitADPS16" (NIST level 3). The rule fixes ring dimension ≥ 64 for the B and D commitment matrices. — [Akita spec sis-quantum128-scalar-n-table.md](https://github.com/LayerZero-Labs/akita/blob/main/specs/sis-quantum128-scalar-n-table.md)
- Akita's moduli are pseudo-Mersenne, q = 2^k − offset, inherited from the LaBRADOR/Greyhound C implementation. — [Akita README, Acknowledgements](https://github.com/LayerZero-Labs/akita)
- gnark-crypto's Ring-SIS over bls12-377 Fr, a 253-bit prime with high 2-adicity, is fully splitting. It is used as a hash or commitment with a bound B on the limbs, which shows that fully splitting large-q Ring-SIS is used in practice for *binding* in the Vortex line. No challenge-invertibility argument is needed there because no ZK or extraction over short challenges is performed. — [gnark-crypto repo](https://github.com/consensys/gnark-crypto)

### Inferences
- **The invertibility bound, recalled rather than verified.** I recall the Lyubashevsky–Seiler bound (their Corollary 1.2) in this form, but could not check it against the paper body: if X^d+1 splits into k factors mod p, then nonzero y with ‖y‖∞ < p^{1/k}/√k is invertible.
  - For bn254 with k = d = 64 this gives 2^{254/64}/8 ≈ 15.6/8 ≈ 1.95. Differences of ternary challenges, with ‖·‖∞ = 2, are therefore *not* covered.
  - For d = 32 the bound is ≈ 2^{7.9}/5.7 ≈ 43, which is comfortable.
  - So with r, either keep the ring degree small (d ≤ 32), or use subring/"partially split" tricks. Another route is to avoid needing invertibility, by working in the CRT slots directly or by using large-set challenges from Z_r for the parts that are linear over F_r.
- **Bits leak through the CRT slots.** In a fully splitting ring a short element can vanish in some of its d CRT slots. Each slot is an F_r copy, which leaks information slot by slot. ZK masking must therefore be uniform per slot.
- **Ring-SIS hardness with large q.** For a fixed norm bound β, a larger q makes SIS harder, because β/q shrinks. A 254-bit q is therefore not a security problem in itself.
  - The cost is size: each ring element is about 254·d bits, so commitments and openings grow by about 254/32 ≈ 8× compared with Greyhound's q ≈ 2^32 at the same rank.
  - Splitting does not affect known SIS attacks, which are lattice reduction on the coefficient embedding. The splitting concern is about the *proof system*'s soundness and extraction, not about SIS.
- **Estimators.** The malb lattice-estimator's SIS module takes arbitrary (n, q, β) and should accept q ≈ 2^254. Akita's ADPS16 core-SVP LGSA model is another option. I did not verify either one against q ≈ 2^254.

### Gaps
- The exact constant in Lyubashevsky–Seiler's bound could not be verified (PDF blocked). The figures above use a bound recalled from memory.
- No published concrete Module-SIS parameter set for q = bn254 r was found.
- The lattice-estimator documentation was not fetched within the tool budget, so support for 254-bit q is unconfirmed.

## 3. Zero-knowledge for lattice PCSs and QROM status of Fiat–Shamir (2024–2026)

### Takeaway
None of the leading succinct lattice PCSs is described as ZK in its abstract: Greyhound, Hachi, Cini–Malavolta–Nguyen–Wee, RoKoko and Akita. The known Akita gap (no ZK, ROM only) is typical.

ZK is available in the LNP22-style linear-size proofs, which use rejection sampling. LaZer extends LaBRADOR with ZK, and Akita lists ZK ("Whiteout") as future work. The only QROM-type result found is Cini et al. (CRYPTO 2024), who prove knowledge soundness against quantum adversaries for their univariate PCS.

### Cited Findings
- Cini, Malavolta, Nguyen and Wee give a *univariate* lattice PCS with transparent setup under Module-SIS. Fiat–Shamir makes it non-interactive in the ROM. They note that quantum security of prior lattice constructions "was never formally discussed" and give a knowledge soundness proof against quantum adversaries. Their proofs are about 2× smaller than FRI at L = 2^20. ZK is not mentioned. — [ePrint 2024/281](https://eprint.iacr.org/2024/281)
- Greyhound (Nguyen and Seiler, CRYPTO 2024) has about 53 KB proofs for N = 2^30, an O(√N) core verifier, and is composed with LaBRADOR for succinctness. It rests on "standard lattice assumptions". ZK and ROM/QROM are not mentioned in the abstract. — [ePrint 2024/1293](https://eprint.iacr.org/2024/1293)
- The IBM research page gives 93 KB for Greyhound's proofs, which conflicts with the 53 KB in the ePrint revision. — [IBM Research page](https://research.ibm.com/publications/greyhound-fast-polynomial-commitments-from-lattices)
- Hachi has about 55 KB proofs and a 12.5× faster verifier than Greyhound. ZK is not mentioned. — [ePrint 2026/156](https://eprint.iacr.org/2026/156)
- RoKoko (Klooss, Lai, Nguyen, Osadnik, Tucci, 2026) has about 200 KB proofs, roughly 100× faster verification than Greyhound, and a linear-time prover. It supports tensor-structured relations such as polynomial evaluation and sumcheck. ZK is not mentioned. — [ePrint 2026/575](https://eprint.iacr.org/2026/575)
- HyperWolf is a lattice PCS for both univariate and multilinear polynomials, with O(log N) proof size and verifier time. It was **withdrawn** from ePrint on 2025-10-03. ZK is not mentioned. — [ePrint 2025/922](https://eprint.iacr.org/2025/922)
- IBM states that it extended the LaZer library "to add zero-knowledge to LaBRADOR". — [IBM: A toolkit for succinct lattice-based ZK proofs](https://research.ibm.com/publications/a-toolkit-for-succinct-lattice-based-zero-knowledge-proofs)
- LNP22 is a ZK proof system under Module-SIS and Module-LWE: the commitments are hiding, the proofs prove ℓ2 norm, and they lift to Z by approximate range proofs. — [ePrint 2022/284](https://eprint.iacr.org/2022/284)
- The Akita README lists "efficient zero-knowledge techniques under the Whiteout design direction" as a planned protocol improvement. The repository also has a `fold-linf-rejection.md` spec, which suggests rejection-style norm control in folding. — [LayerZero-Labs/akita](https://github.com/LayerZero-Labs/akita)
- The LayerZero blog calls Akita a PCS for "zero-knowledge proving systems" but gives no formal ZK or security-model statement. — [LayerZero blog](https://layerzero.network/blog/introducing-akita)

### Inferences
- **Overhead of ZK.** Adding ZK to an Ajtai-commitment PCS needs two things. First, hiding commitments, which means extra Module-LWE randomness columns, as in LNP22/BDLOP. Second, masking of the folded openings, either by rejection sampling, which costs an expected number of repetitions and larger norm bounds, or by noise flooding, which costs a larger q.
  - For PLONK, a cheaper alternative is ZK at the PIOP level, as gnark does today: blind the PLONK polynomials with random multiples of Z_H(X) and open at a random ζ. A non-hiding PCS might then be enough if the PCS opening leaks nothing beyond the evaluations.
  - That holds for KZG-like PCSs, but a lattice opening reveals folded short witnesses. So PIOP-level blinding alone is probably *not* sufficient without a hiding or masked opening.
  - This needs a formal check.
- **QROM status.** QROM security for succinct lattice arguments is open in general. Cini et al. is the exception, at least for its own construction. Their scheme is also univariate, which makes it the closest match to PLONK's interface.

### Gaps
- No 2025–2026 paper was found proving QROM knowledge soundness for Greyhound, LaBRADOR, Hachi or Akita.
- No concrete measured ZK overhead for a succinct lattice PCS was found.

## 4. Go tooling and reference implementations (maturity, licenses)

### Takeaway
No Go implementation of any lattice PCS exists:
- Lattigo (Go, Apache-2.0) is an RNS-RLWE homomorphic encryption library with ring and NTT utilities, but no SIS, commitment or ZK.
- gnark-crypto (Go, Apache-2.0) has Ring-SIS hashes and a non-production Vortex, for small fields and bls12-377 Fr, but not bn254 Fr.

The reference PCS code is in C (LaBRADOR/Greyhound, Apache-2.0, AVX-512 only, last pushed 2025-02) and Rust (Akita, Apache-2.0/MIT, very active). LaZer (C with Python, MIT) ships a small Go cgo binding for a blind-signature demo, which shows that FFI from Go is feasible.

### Cited Findings
- **Lattigo** (tuneinsight/lattigo) is a Go module of "full-RNS Ring-Learning-With-Errors-based homomorphic-encryption primitives". Its packages are `ring` (RNS polynomial arithmetic, NTT, sampling), `core/rlwe` and `rgsw`, BFV/BGV/CKKS schemes, and multiparty protocols. It is Apache-2.0 and at v6, which is "fast-evolving", with breaking changes possible. It does not mention SIS, commitments or ZK. — [GitHub tuneinsight/lattigo](https://github.com/tuneinsight/lattigo)
- Per the GitHub API, Lattigo was last pushed on 2026-10-20 and has 1457 stars. — [GitHub API](https://github.com/tuneinsight/lattigo)
- **gnark-crypto** has Ring-SIS (`sis`) packages for babybear, goldilocks, koalabear, mamabear and bls12-377/fr, an `algebra/lattice` package, and `field/{koalabear,mamabear}/vortex`, which is marked "not production ready". It is Apache-2.0. There is no bn254/fr/sis and no FRI package. — [pkg.go.dev gnark-crypto@master](https://pkg.go.dev/github.com/consensys/gnark-crypto@master)
- **LaBRADOR/Greyhound C** (lattice-dogs/labrador) implements LaBRADOR plus the Chihuahua, Dachshund and Greyhound front ends. It needs AVX-512. It builds `libdogs.so` with a C header API. The test commits to a 2^26 polynomial and proves an evaluation. It is Apache-2.0 (© 2024 IBM), was last pushed on 2025-02-20, and has 54 stars. — [GitHub lattice-dogs/labrador](https://github.com/lattice-dogs/labrador)
- **LaZer** (lazer-crypto/lazer) is a C library with a Python (cffi) interface and a LaBRADOR submodule. It requires Linux x86-64 with AVX-512 and AES, gcc ≥ 13.2 and SageMath ≥ 10.2. It is MIT (© 2022–2026 IBM) and was last pushed on 2026-10-09. It contains a `golang/` directory with a cgo wrapper (`#cgo LDFLAGS: liblazer.a -lmpfr -lgmp`) exposing a blind-signature demo API, with a placeholder module path. — [GitHub lazer-crypto/lazer](https://github.com/lazer-crypto/lazer)
- **Akita** (LayerZero-Labs/akita) is Rust under Apache-2.0 and MIT. It is split into crates: akita-pcs, -prover, -verifier, -config, -planner, -sumcheck, -transcript and others. It depends on Jolt's `jolt-field`. It was last pushed on 2026-10-24. Its documentation book is "mostly stubs". — [GitHub LayerZero-Labs/akita](https://github.com/LayerZero-Labs/akita)
- The Akita seminar abstract reports, for a 2^26 polynomial over a 128-bit field on an M4 Max: 106 KB proof, 5.9 s commit, 2.5 s prove, 20 ms verify. — [SNU seminar](https://cse.snu.ac.kr/en/community/seminar/1127)
- LayerZero claims, for Jolt with Akita, 2–3× faster proving, about 2× less memory, and 65–80 KB proofs. These are vendor claims. — [LayerZero blog](https://layerzero.network/blog/introducing-akita)
- **LatticeFold** (NethermindEth/latticefold) is Rust, Apache-2.0 and active (pushed 2026-10-12). It is a folding scheme, not a PCS. — [GitHub NethermindEth/latticefold](https://github.com/NethermindEth/latticefold)
- **Hachi** and **Greyhound** have no standalone repositories that GitHub search could find. Greyhound's only public code is the lattice-dogs C repository. — [GitHub search, 2026-10-25]

### Inferences
- **Option A: port into gnark-crypto.** Port a Greyhound- or Hachi-style protocol into gnark-crypto by generating `ecc/bn254/fr/sis` from the existing bls12-377 template (both are about 254-bit, high-2-adicity fields) and adding the PCS layer in Go. This is the most native route.
  - The existing C and Rust code assumes 64-bit or smaller limbs and pseudo-Mersenne q, so it helps only as an algorithmic reference.
- **Option B: FFI.**
  - cgo into `libdogs.so`, which is C with an existing API, is technically easy, but the library is AVX-512-only (no Apple Silicon) and fixed to q ≤ 2^64.
  - Rust FFI into Akita would need a C ABI shim and Jolt's field crate, and Akita supports only fp32, fp64 and fp128.
  - Neither one gives an F_r PCS as-is.
- **Licenses.** Apache-2.0 and MIT throughout, all compatible with gnark's Apache-2.0.

### Gaps
- No Go port of LaBRADOR, Greyhound, Hachi or Akita was found.
- The contents of gnark-crypto's `algebra/lattice` package were not inspected.

## 5. Existing integration of a lattice PCS into a univariate PLONK-style system

### Takeaway
No integration of a lattice PCS into univariate PLONK was found. Deployed or announced integrations go into sumcheck/multilinear stacks: Akita into Jolt, and Hachi and Greyhound into multilinear settings. The univariate lattice PCSs (Cini et al. 2024; Greyhound's degree-N formulation; the withdrawn HyperWolf) exist only as standalone schemes.

### Cited Findings
- Akita's first major deployment is the Jolt zkVM, a sumcheck-based system. — [LayerZero blog](https://layerzero.network/blog/introducing-akita); [a16z/jolt](https://github.com/a16z/jolt)
- Hachi is explicitly multilinear and sumcheck-based. — [ePrint 2026/156](https://eprint.iacr.org/2026/156)
- Cini et al. commit to univariate f ∈ R[X] of degree L and open at a point x, which is the interface PLONK needs. No PLONK integration was reported. — [ePrint 2024/281](https://eprint.iacr.org/2024/281)
- Greyhound is phrased for polynomials of "bounded degree N". — [ePrint 2024/1293](https://eprint.iacr.org/2024/1293)
- HyperWolf claimed a single framework for univariate and multilinear polynomials, but it is withdrawn. — [ePrint 2025/922](https://eprint.iacr.org/2025/922)
- Plonky3 supports a PLONK PIOP with FRI and tensor PCSs plus univariate-to-multivariate adapters. No lattice PCS is listed (search-result summary). — [Plonky3](https://github.com/succinctlabs/plonky3)

### Inferences
- **Univariate is not the hard part.** A univariate claim f(ζ) = v is a tensor-structured inner product ⟨f, (1, ζ, …, ζ^{N−1})⟩ = v. With a √N × √N layout it becomes (1, ζ, …, ζ^{√N−1}) ⊗ (1, ζ^{√N}, …). Greyhound, Hachi and RoKoko-style tensor or sumcheck PCSs can therefore serve univariate openings. The main barriers are the field (Section 1), ZK (Section 3) and Go tooling (Section 4).
- **gnark-specific detail.** gnark PLONK batches openings at ζ and ωζ, and folds many polynomials by random linear combination before KZG opening. With a lattice PCS, the linear combination of commitments must stay a valid commitment to short witnesses. An F_r-linear combination of digit-decomposed witnesses is *not* short. Batching must therefore be done on the claims, via a sumcheck or batched evaluation argument, rather than by homomorphically combining commitments. This is a real structural difference from KZG and affects how much of gnark's PLONK verifier must change.

### Gaps
- No source was found on lattice PCSs in PLONK, KZG-replacement experiments, or gnark-specific attempts.
