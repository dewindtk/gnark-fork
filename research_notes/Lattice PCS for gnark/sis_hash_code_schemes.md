# Code-based PCS with Ring-SIS hashing (Vortex focus) as a "lattice-based" option for the gnark fork

Scope: Vortex (Linea/Consensys) and related code-based schemes that hash with Ring-/Module-SIS, and whether this is a practical lattice option for univariate PLONK over bn254 Fr (254-bit, 2-adicity 28) behind the existing Commit/Open/Verify interface (claims at ζ and ωζ). Research date: 2026-10-25.

Source-access notes: eprint.iacr.org returned HTTP 403 for direct PDF downloads, so the two Vortex PDFs (2024/185 and 2022/1633) were read from Wayback Machine copies (`https://web.archive.org/web/2025id_/https://eprint.iacr.org/2024/185.pdf` and `.../2022/1633.pdf`; the 2022/1633 copy predates or equals rev. 2024-07-22, so later revisions may differ). Code findings come from the local module cache (`/Users/cprince/go/pkg/mod/github.com/consensys/gnark-crypto@v0.21.0`, read-only) and from the Linea monorepo through the GitHub API. `Consensys/linea-monorepo` now redirects to `LFDT-Lineth/lineth-monorepo`, but the Go import path is still `github.com/consensys/linea-monorepo/prover`.

---

## 1. Vortex: construction, polynomial type, evaluation proofs, role of Ring-SIS, field, assumptions, cost, ZK, and Linea's use

### Takeaway
Vortex is a Ligero/Brakedown-style batched *univariate* list polynomial commitment (LPC). The prover RS-encodes the rows of a matrix, hashes each column (Ring-SIS, then MiMC/Poseidon2, then a Merkle tree), and proves an evaluation at one point x through a random row combination plus t column openings. Proof size and verifier time are O(√N). Soundness is proven in the Johnson/list-decoding regime from the proven BCIKS20 correlated-agreement theorem; the capacity regime is explicitly left out. The paper gives no zero-knowledge. Linea makes Vortex succinct by repeated "self-recursion" that exploits the linearity of the SIS hash. Since about April 2026 Linea runs Vortex over KoalaBear (with a BLS12-377 variant for later layers) and does the final wrap in gnark PLONK+KZG over BN254.

### Cited Findings
**Paper and construction**
- Title "Vortex: A List Polynomial Commitment and its Application to Arguments of Knowledge", by Alexandre Belling, Azam Soleimanian and Bogdan Ursu (Linea/Consensys), ePrint 2024/185, received 2024-02-07. It modifies Ligero, drawing on Brakedown, batch-FRI and RedShift, with O(N^{1/2}) messages, and gives a PIOP→AoK compiler whose soundness loss is linear in the list size |L| rather than O(|L|^r). — [ePrint 2024/185](https://eprint.iacr.org/2024/185)
- Commit: the prover encodes the rows of an m×k matrix W with (systematic) Reed–Solomon to get W′ (m×n) and hashes each column of W′. Evaluation: the verifier wants a codeword matrix G close to W′ with G·l = y, where l = (1, x, …, x^k). Proximity check: for random B the prover sends u; the verifier encodes u to u′, opens t random columns, and checks hash consistency and ⟨B, column⟩ = u′. Evaluation check: u·l = B·y. — [ePrint 2024/185 PDF §1.2](https://eprint.iacr.org/2024/185.pdf)
- Unlike Brakedown, "the proximity check is run after seeing the evaluation point". Vortex batches several polynomials at the *same* evaluation point. — [ePrint 2024/185 PDF §1.1–1.2](https://eprint.iacr.org/2024/185.pdf)
- Polynomials longer than the row length are folded into chunks P(X) = P₀(X) + XⁿP₁(X) + …, each inserted as a row, and the verifier recombines the evaluations. — [Linea Prover doc, ePrint 2022/1633 §7.2](https://eprint.iacr.org/2022/1633)

**Role of the Ring-SIS hash**
- Column hashing uses "a hash function based on the Ring-SIS assumption … where we also apply an MIMC hash over the output of the SIS-hash". It is described as "SNARK-friendly … with a linear structure" over R = Z_q[X]/(X^d+1). — [ePrint 2024/185 PDF §1.1](https://eprint.iacr.org/2024/185.pdf)
- The hash is "essentially the same as the SWIFFT hash function", except that inputs are limbs in [0, 2^n−1] rather than {0,1}. Hash(x): split each field element into log q/log b limbs of norm < b, arrange them as polynomials L ∈ R^m, and output A·L. Collision and preimage resistance reduce to Ring-SIS and Ring-ISIS. — [ePrint 2022/1633 §7.1, Fig. 9](https://eprint.iacr.org/2022/1633)
- Self-recursion "relies heavily on the fact that the Vortex verifier uses the Ring-SIS hash for hashing the columns and the Reed-Solomon code to encode the rows". It "reduces the size of the proof by a square root every time it is applied", and after O(log log n) rounds a final proof is produced. Large-degree SIS instances "compress poorly but are very fast"; small-degree ones compress well but are slower, so the degree is reduced across rounds. — [ePrint 2022/1633 §1, §9](https://eprint.iacr.org/2022/1633)
- Linea's code has `HashModXnMinus1`: "This is used as part of the self-recursion procedure. Note that this **does not implement** a collision-resistant hash function … Its purpose is to help constructing a witness for the correctness of computation of a batch of SIS hashes." — [lineth-monorepo prover/crypto/ringsis/ringsis.go](https://github.com/LFDT-Lineth/lineth-monorepo/blob/main/prover/crypto/ringsis/ringsis.go)
- Linea's Vortex compiler has `WithOptionalSISHashingThreshold`: "Allows skipping the SIS hashing of columns of the round matrices if the number of polynomials to commit to for the particular round is less than the threshold". Non-SIS rounds hash the columns directly with Poseidon2. — [lineth-monorepo protocol/compiler/vortex/option.go](https://github.com/LFDT-Lineth/lineth-monorepo/blob/main/prover/protocol/compiler/vortex/option.go); [selfrecursion/linearhashandmerkle.go](https://github.com/LFDT-Lineth/lineth-monorepo/blob/main/prover/protocol/compiler/selfrecursion/linearhashandmerkle.go)

**Security assumptions; proven vs conjectured**
- The paper distinguishes three regimes. Unique decoding (θ < (1−ρ)/2, ε = (N−1)|D|/|F|) and list decoding up to Johnson (θ = 1−√ρ·(1+1/2m), ε = (N−1)(m+½)⁷|D|²/(3ρ^{3/2}|F|)) are proven via BCIKS20. The capacity regime "is currently a conjecture and will not be addressed in this paper." — [ePrint 2024/185 PDF, Def. 7](https://eprint.iacr.org/2024/185.pdf)
- Vortex soundness: ε_soundness ≤ ε_collision + (1−θ)^t + ε, with θ = 1−√ρ−√ρ/(2m′) and m′ ≥ 3. Extraction uses repeated Guruswami–Sudan list decoding in the ROM. — [ePrint 2024/185 PDF §6](https://eprint.iacr.org/2024/185.pdf)
- The compiled AoK has soundness ≈ |L|·ε_PIOP + ε_LPC; the paper states that the generic form "is conjectured" and then proves bounds for its UniEval PIOP construction in §7.2. — [ePrint 2024/185 PDF §7](https://eprint.iacr.org/2024/185.pdf)
- Hash modelling: "Writing F(x) = MiMC(SIS(x)) we heuristically model F as a random oracle … MiMC, being itself modellable as a random oracle, breaks down all the linear properties of the SIS hash." — [ePrint 2022/1633 §7.2](https://eprint.iacr.org/2022/1633)
- Production parameter choice uses Johnson, not capacity: `NbColsToOpen` computes `nb = 2*TargetSecurityLevel/log2(blowup)`, with the comment "the 2 factor comes from the factor that we rely on the Guruswami-Sudan list decoding regime and not the (alleged)-capacity decoding level". `TargetSecurityLevel = 128`. — [lineth-monorepo protocol/compiler/vortex/compiler.go](https://github.com/LFDT-Lineth/lineth-monorepo/blob/main/prover/protocol/compiler/vortex/compiler.go); [prover/crypto/crypto.go](https://github.com/LFDT-Lineth/lineth-monorepo/blob/main/prover/crypto/crypto.go)

**Proof size and verifier cost**
- Proof size and verification time are O(√n). Early benchmark: a 30M-gas block took about 5 minutes for the inner proof only, on a 96-core, 384 GB machine. The post says the system was "still under development". — [ethresear.ch "Vortex: building a prover for the zk-EVM"](https://ethresear.ch/t/vortex-building-a-prover-for-the-zk-evm/14427)
- No concrete byte sizes for a single Vortex opening were found in the sources read.

**Zero-knowledge**
- The Vortex paper has a footnote: "In the blockchain community, sometimes the term zk is employed to mean succinctness". No hiding or ZK variant of Vortex is presented. — [ePrint 2024/185 PDF, footnote 1](https://eprint.iacr.org/2024/185.pdf)
- The ethresear.ch post does not mention zero-knowledge. — [ethresear.ch](https://ethresear.ch/t/vortex-building-a-prover-for-the-zk-evm/14427)

**Field and Linea pipeline**
- Original design (2022–2023): the prover "relies on the bn254 scalar field all the way from the arithmetization to the outer-proof". The SIS hash at that time was plain (non-ring) SIS with n=2 and bound 2³ over bn254 Fr, at about 500·N ns. — [ethresear.ch](https://ethresear.ch/t/vortex-building-a-prover-for-the-zk-evm/14427)
- Current state: "the zkEVM arithmetization is done over KoalaBear 31-bit field for performance reasons" (since April 2026). "Vortex LPC is a batchable polynomial commitment that is based on Ligero with lattice-based hash functions." Multiple rounds of self-recursion arithmetize the Vortex verifier. Aggregation combines PLONK circuits on BW6 and BLS12-377, and "the Linea proof is wrapped in a gnark implementation of Plonk over BN254 curve". There are three trusted setups (Aztec Ignition BN254, Aleo BLS12-377, Celo BW6-761), and the prover "targets 128 bits of security". — [L2BEAT Linea prover](https://l2beat.com/zk-catalog/lineaprover) (third-party catalog)
- Linea's `field.Element = koalabear.Element`. `ringsis.StdParams = {LogTwoBound: 16, LogTwoDegree: 9}` (degree 512, limbs of 16 bits), with the comment "benchmarked at achieve more than the 128 level of security". The last ringsis change was "Prover: Small Fields (#1301)", 2026-03-26. — [lineth-monorepo maths/field/element.go](https://github.com/LFDT-Lineth/lineth-monorepo/blob/main/prover/maths/field/element.go); [ringsis.go](https://github.com/LFDT-Lineth/lineth-monorepo/blob/main/prover/crypto/ringsis/ringsis.go)
- The Vortex compiler builds either `vortex_koalabear.NewParams(...)` or, when `IsBLS`, `vortex_bls12377.NewParams(...)`. So a BLS12-377-field Vortex with SIS is in use alongside the KoalaBear one. — [compiler.go](https://github.com/LFDT-Lineth/lineth-monorepo/blob/main/prover/protocol/compiler/vortex/compiler.go)

### Inferences
- Vortex is a code-based PCS (RS proximity, Ligero test) in which the lattice assumption only protects the column hash (binding). Soundness of the evaluation argument rests on RS proximity (BCIKS20, Johnson regime) plus collision resistance of the column/Merkle hash. It is therefore "lattice-based" only in its hash, not in its commitment structure. ePrint 2025/2046's disproof of up-to-capacity conjectures over large fields does not affect Vortex as analysed and as parameterised by Linea, since both use the Johnson regime.
- Linea's SIS layer exists for one reason: to make the Vortex verifier cheap to re-arithmetize in its own (KoalaBear/BLS12-377) Wizard-IOP during self-recursion. It is not there for native-verifier speed or for any PQ advantage over a plain hash. Linea's end-to-end system is **not** post-quantum, since every layer after self-recursion, including the final wrap, is PLONK+KZG on pairing curves.
- Vortex natively opens all committed rows at a single point x. Our PLONK needs ζ and ωζ, so we would need a multi-point→single-point reduction. Linea has a dedicated `mpts` compiler for this (directory listed in [protocol/compiler](https://github.com/LFDT-Lineth/lineth-monorepo/tree/main/prover/protocol/compiler)), or we could run two Vortex openings.
- Rough size estimate for our setting (my arithmetic, not from a source). Take about 15 PLONK polynomials of degree 2²⁰ over bn254 Fr in a √-shaped matrix with m ≈ k ≈ 4096, at ρ = 1/8 and 128-bit security in the Johnson regime. Then t = ⌈2·128/3⌉ = 86 columns × 4096 × 32 B ≈ 11 MB, plus u (k·(1/ρ) ≈ 32 K elements ≈ 1 MB). That is several MB, against the hundreds of KB typical of FRI. Without recursion, Vortex proofs are much larger than our current FRI proofs.

### Gaps
- No published concrete proof size or verifier time for a standalone (non-self-recursed) Vortex opening at 128 bits was found.
- The QROM status of Vortex is not addressed in either Linea paper. They work in the ROM, and the column hash is modelled heuristically as a RO.
- Whether a later revision of ePrint 2024/185 adds ZK could not be checked, because only an archived copy was accessible.

---

## 2. What exists in gnark-crypto v0.21.0 and in Linea/gnark for Vortex and SIS

### Takeaway
gnark-crypto v0.21.0 ships Ring-SIS for koalabear, babybear, goldilocks and **BLS12-377 Fr only**; there is **no `ecc/bn254/fr/sis`**. It ships one Vortex package, `field/koalabear/vortex`, which is marked "not production ready". Its evaluation points and coins live in the degree-4 extension E4, and Fiat–Shamir is left to the caller. All three packages' tests pass locally. The gnark fork itself contains no Vortex or SIS code. Linea's monorepo has the full stack: Vortex for koalabear and BLS12-377, self-recursion compilers, and a gnark verifier circuit.

### Cited Findings
(All paths are relative to `/Users/cprince/go/pkg/mod/github.com/consensys/gnark-crypto@v0.21.0`; inspected locally, read-only.)
- SIS directories present: `field/koalabear/sis`, `field/babybear/sis`, `field/goldilocks/sis`, `ecc/bls12-377/fr/sis`. No other curve has `fr/sis`, so the prompt's `ecc/*/fr/sis` exists only for bls12-377. Generator: small fields get `field.WithSIS()` (internal/generator/main.go ~l.81), while curves get it only `if conf.Equal(config.BLS12_377)` (~l.157).
- The SIS template is generic: `internal/generator/field/template/sis/*`, with an AVX-512 F31 assembly path for 31-bit fields (`amd64.GenerateF31SIS`) and `sis_fft.go` for big fields. The template comment says it comes "From linea-monorepo/prover/crypto/ringsis/templates/partial_fft.go".
- API: `sis.NewRSis(seed int64, logTwoDegree, logTwoBound, maxNbElementsToHash int) (*RSis, error)` and `(*RSis).Hash(v, res []Element) error`. The ring is Z_p[X]/(X^d+1); A is derived deterministically from the seed (blake2b); `logTwoBound` must be a multiple of 8 and ≤ 64; 64-bit targets only. Fast paths: koalabear d=512 with 16-bit limbs (AVX-512); bls12-377 d=64 with 16-bit limbs (unrolled FFT). Each field ships `sis.sage` and `test_cases.json` reference vectors.
- `field/koalabear/vortex/doc.go`: "Package vortex is not production ready and should not be used in production code. APIs will change". API: `NewParams(numColumns, maxNumRow, sisParams, reedSolomonInvRate ∈ {2,4,8}, numSelectedColumns, opts...)`; `Commit(p, [][]koalabear.Element) (*ProverState, error)`; `(*ProverState).OpenLinComb(alpha fext.E4)`; `OpenColumns(selectedColumns []int)`; `(*Params).Verify(VerifierInput{MerkleRoot, ClaimedValues []fext.E4, EvaluationPoint fext.E4, SelectedColumns, Alpha fext.E4, Proof})`. Options `WithColumnHash` and `WithMerkleHash` take 32-byte hashes; the defaults are SIS for columns and Poseidon2 (koalabear, width 16/24) for leaves and nodes. Verify checks (i) UAlpha against the claimed values, (ii) RS membership of UAlpha, (iii) the column linear combination, and (iv) Merkle paths. Tests use `sis.NewRSis(0, 9, 16, numRow)`, the same as Linea's StdParams.
- Local test run (2026-10-25): `go test ./field/koalabear/sis/ ./field/koalabear/vortex/ ./ecc/bls12-377/fr/sis/` gives all `ok` (vortex 9.5 s).
- CHANGELOG entries: "vortex on koalabear (#645)", "add sis avx512 and fft avx512 for koalabear (#622)", "restored sis (#583)", "expose vortex.ComputeLagrangeBasisAtX". — [gnark-crypto CHANGELOG](https://github.com/Consensys/gnark-crypto/blob/master/CHANGELOG.md) (local copy)
- Linea monorepo: `prover/crypto/ringsis` (a wrapper over gnark-crypto sis), `prover/crypto/vortex/{vortex_koalabear, vortex_bls12377}` (with `verifier_circuit.go`, a gnark circuit), and `protocol/compiler/{vortex, selfrecursion, mpts, univariates, …}`. — [lineth-monorepo prover/crypto](https://github.com/LFDT-Lineth/lineth-monorepo/tree/main/prover/crypto); [protocol/compiler](https://github.com/LFDT-Lineth/lineth-monorepo/tree/main/prover/protocol/compiler)
- gnark fork (`/Users/cprince/Desktop/gnark-fork`): `grep` finds no Go file referencing vortex, ringsis or a `/sis` package.

### Inferences
- Using gnark-crypto's Vortex for our bn254 PLONK would mean either (a) porting `field/koalabear/vortex` to bn254 Fr ourselves (vendored code, since the generator cannot be changed in the module cache), plus generating `bn254/fr/sis` from the template, or (b) switching PLONK to koalabear, which means a new backend and E4 challenges. Neither exists today.
- Porting the SIS template to bn254 Fr is technically low-risk. The bls12-377 Fr instance proves the big-field path works, and bn254 Fr's 2-adicity of 28 supports X^d+1 NTTs for d up to 2²⁷.

### Gaps
- No public plan to add `bn254/fr/sis` or a bn254 Vortex to gnark-crypto was found.
- Coverage and audit status of `field/koalabear/vortex` were not assessed beyond the passing tests.

---

## 3. Ring-SIS over bn254 Fr: feasibility and security parameters

### Takeaway
Yes. Linea itself ran SIS hashing over bn254 Fr in its original design and published Ring-SIS parameter sets for q ≈ 2²⁵⁴ that target 128 bits of classical security. Its estimates rest on Linea's own estimator (BKZ with LD-sieve cost 0.292k+16.4, plus CPW combinatorial attacks), and "no attack is known to work significantly better on ring-SIS" than on plain SIS. A fully splitting modulus is standard for SIS hashing: SWIFFT's own parameters (q=257, n=64) split X^n+1 fully. Caveat: these estimates are Linea's, not independently peer-reviewed, they are classical only, and the specific gnark-crypto fast-path parameters (d=64, 16-bit limbs) do not appear in either published table.

### Cited Findings
- The ring-SIS hardness estimate reduces to the equivalent plain-SIS instance (q, n, m′=nm, b): "In practice, no attack is known to work significantly better on ring-SIS rather than an equivalent SIS instance"; security is "bottlenecked by attacks on collision resistance". — [ePrint 2022/1633 App. B.3](https://eprint.iacr.org/2022/1633)
- Attacks considered: BKZ 2.0 with LD-sieve SVP oracle cost "log t_oracle = 0.292k + 16.4", direct SVP (L2 and L∞), and Camion–Patarin/Wagner (CPW) with refinements. HGJ/BCJ were not considered because the instances are high-density. The authors call some estimates "somewhat over-pessimistic". — [ePrint 2022/1633 App. B.4–B.6](https://eprint.iacr.org/2022/1633)
- Fig. 22 ("Lattice parameters targetting 128 bits of security"), q ≈ 2²⁵⁴ rows (b, n=ring degree → BKZ / CPW cost bits): B1 (2², 7 [non-ring]) → 324.6/259.0; B2 (2⁴, 16) → 355.6/270.0; B3 (2⁶, 32) → 411.7/637.0; B4 (2¹⁰, 64) → 377.8/1262.5; B5 (2¹⁶, 128) → 341.8/2720.3; B6 (2²⁴, 256) → 333.1/5921.3; B7 (2³², 512) → 405.7/13013.8. The q ≈ 2⁶⁴ rows run from A1 (2², 32) to A6 (2²², 1024). Costs exceed 128 because "we are willing to take conservative parameters … our work is, to the best of our knowledge, the first to take SIS-based hash function in production." — [ePrint 2022/1633 App. B.7, Fig. 22](https://eprint.iacr.org/2022/1633)
- An earlier ethresear.ch table (q=2²⁵⁴, β=2², n=7: BKZ 157.7, CPW 259.03) gives a *lower* BKZ figure for the same instance, and the post notes a corrected factor ½ in the root-Hermite-factor formula. — [ethresear.ch](https://ethresear.ch/t/vortex-building-a-prover-for-the-zk-evm/14427). This conflicts with Fig. 22's B1 BKZ of 324.59, so the estimator changed between versions. The paper says the revised estimator had found δ values "lower than what was used in [4]" and had been "very pessimistic". — [ePrint 2022/1633 App. B.7](https://eprint.iacr.org/2022/1633)
- A third table, in the hackmd linked from gnark-crypto's `sis.go`, targets "144 bits of security against lattice reduction and combinatorial attacks". It lists q=2²⁵⁴ with (degree, log₂β) = (2,2), (4,3), (8,4), (16,6), (32,10), (64,15), (128,22), (256,32), and says the modulus must be "compatible with the FFT". — [hackmd 7OODKWQZRRW9RxM5BaXtIw](https://hackmd.io/7OODKWQZRRW9RxM5BaXtIw). These pairs differ from Fig. 22 (e.g. degree 64 with log β = 15 vs 10).
- SWIFFT: ring Z_p[α]/(α^n+1) with "p−1 a multiple of 2n" (i.e. X^n+1 splits completely mod p), standard parameters (n,m,p) = (64,16,257). Power-of-two n (irreducibility over Z) "is crucial for the security proof; otherwise one can find collisions (LASH…)". — [SWIFFT FSE 2008 presentation](https://iacr.org/cryptodb/archive/2008/FSE/presentation/15627.pdf); [Wikipedia: SWIFFT](https://en.wikipedia.org/wiki/SWIFFT) (secondary: ~2¹⁰⁶ collision cost for these parameters)
- Fully splitting is used for speed: when (q−1) | 2d, the product A·L is computed as an NTT/Hadamard product on the coset of 2d-th roots of unity, at O(m·d log d) cost. — [ePrint 2022/1633 §7.1](https://eprint.iacr.org/2022/1633)

### Inferences
- bn254 Fr satisfies q ≡ 1 mod 2d for every d ≤ 2²⁷ (2-adicity 28), so X^d+1 splits completely and the gnark-crypto NTT path applies directly. Full splitting is *not* a known weakness for (Ring-)SIS collision resistance, unlike its role in some Ring-LWE/decisional settings and in lattice-native PCS designs that need partial splitting for challenge invertibility (cf. Akita's condition in PROJECT.md). SWIFFT and Linea both deliberately use fully splitting moduli.
- Reasonable bn254 candidates from Linea's tables are B4 (d=64, b=2¹⁰) or B5 (d=128, b=2¹⁶). gnark-crypto's bls12-377 fast path (d=64, 16-bit limbs) matches neither published 2²⁵⁴ row exactly. Using it on bn254 would require running a lattice estimator ourselves; it is the weaker direction, since a larger bound at the same degree means a lower BKZ cost.
- Compression is poor for wide-element fields. One 254-bit element becomes 16 limbs of 16 bits, and the output is d field elements (d=64 → 64·32 B = 2 KB). The output is d full field elements, so the SIS hash shrinks a column only when it holds more than d field elements (more than 64 rows for d=64). The benefit appears only for tall columns, i.e. many committed rows. That is why Linea skips SIS for rounds with few polynomials (`WithOptionalSISHashingThreshold`).

### Gaps
- No independent (non-Linea) cryptanalysis of Linea's q ≈ 2²⁵⁴ or KoalaBear (q ≈ 2³¹, d=512, 16-bit) parameters was found. The KoalaBear StdParams appear in neither published table; the only support is the code comment "benchmarked at … more than the 128 level".
- No *quantum* security estimate for these SIS instances appears in the Linea sources. They use a classical sieve exponent of 0.292k, and no quantum-sieve-based figure was published.
- How the SIS key width m (number of ring elements) enters Fig. 22 is not tabulated. The rows list (q, b, n) only.

---

## 4. Other code-based schemes with SIS/lattice hashing, and swapping SHA-256 for a SIS hash in our FRI/WHIR Merkle trees

### Takeaway
Vortex is the only deployed code-based PCS found that uses a SIS column hash. Other recent lattice PCS work, such as Maltese (ePrint 2026/2067), builds *lattice-native* commitments over Merkle trees of Ajtai hashes, with Module-SIS binding and multilinear polynomials. That is a different design class. For our native-verifier FRI/WHIR, replacing SHA-256 with a SIS hash brings no benefit and has clear costs: larger digests, limb decomposition, an extra assumption, and loss of the random-oracle modelling unless it is composed with a RO-like hash. The only benefit, cheap in-circuit verification via linearity, matters only if we recursively verify our own proofs inside a circuit over the same field.

### Cited Findings
- Maltese (Cheng, Nguyen, Tyagi; ASIACRYPT 2026, ePrint 2026/2067, 2026-09-17) "operates over a Merkle tree commitment of the lattice-based Ajtai hash function", uses folding plus sum-check to control norm growth, rests on standard Module-SIS, and gives 335 KB openings for multilinear N=2³⁰. It reports about 300× smaller proofs than prior polylog-verifier lattice PCS, and 2–6× larger proofs than schemes with larger verifiers or stronger assumptions. ZK and QROM are not mentioned in the abstract. — [ePrint 2026/2067](https://eprint.iacr.org/2026/2067)
- The Linea papers describe SIS hashing as "SNARK-friendly … with a linear structure" and note "the possibility of using lookup arguments if the hash computation is not done on the verifier side". — [ePrint 2024/185 PDF §1.1](https://eprint.iacr.org/2024/185.pdf)
- In Linea's design, the linear SIS output is fed into MiMC/Poseidon2 before the Merkle tree, explicitly so the composite can be modelled as a random oracle ("breaks down all the linear properties of the SIS hash"). — [ePrint 2022/1633 §7.2](https://eprint.iacr.org/2022/1633); [linearhashandmerkle.go](https://github.com/LFDT-Lineth/lineth-monorepo/blob/main/prover/protocol/compiler/selfrecursion/linearhashandmerkle.go)
- SWIFFT is linear (f(x)+f(y) = f(x+y)), so it is not a drop-in general-purpose hash. — [Wikipedia: SWIFFT](https://en.wikipedia.org/wiki/SWIFFT)
- LatticeFold (Binyi Chen et al.) is a Module-SIS folding scheme whose main difficulty is keeping extracted witnesses low-norm across folding rounds. — [Stanford seminar page: LatticeFold](https://crypto.stanford.edu/seclab/sem-23-24/chen.html)

### Inferences
- In Vortex, the linearity of SIS lets the self-recursion check SIS(opened column) with polynomial-identity tricks (cf. `HashModXnMinus1`) rather than evaluating a hash circuit bit by bit. That only pays off because each Vortex column is tall (many committed rows). FRI and WHIR Merkle leaves are short (a coset of 2–16 elements per query), so a d=64 SIS output (2 KB in bn254) would *expand* the leaf, not compress it. The linearity is not exploited by the FRI/WHIR verifier.
- For our current setting, a native Go verifier with no recursion, SHA-256 is cheaper to verify, has standard QROM treatment (CMS19 BCS-in-QROM), and adds no new assumption. A SIS hash would add Ring-SIS to the assumption set without removing SHA-256 or Poseidon2 for the Merkle/FS layer.
- If the fork later needs in-circuit verification over bn254 (e.g. a gnark PLONK-over-bn254 wrap of FRI proofs), the relevant comparison is SIS-over-bn254 (native field multiplications plus 16-bit range checks for limbs) against Poseidon2-bn254 (already in gnark-crypto, `ecc/bn254/fr/poseidon2`). No source was found that quantifies this trade-off for FRI Merkle paths.

### Gaps
- No paper or implementation was found that pairs Ligero/Brakedown/Blaze/Basefold or a STARK with a SIS *Merkle* hash, other than Vortex/Linea. A search for "lattice-hash STARKs" gave nothing authoritative.
- No constraint-count comparison (SIS vs Poseidon2 vs SHA-256 Merkle paths in gnark circuits) was found.

---

## 5. Post-quantum and QROM status compared with pure hash-based schemes

### Takeaway
A code-based PCS with SIS hashing is plausibly post-quantum, since both RS proximity and Ring-SIS are believed quantum-resistant. But it is **not better** than a pure hash-based scheme (FRI/WHIR with SHA-256): it adds a lattice assumption and keeps the random-oracle heuristic. Linea itself models MiMC∘SIS as a random oracle in the classical ROM and gives no QROM analysis. For our fork, "lattice-based via SIS hashing" would be a label, not a security gain. The Johnson-regime soundness that Vortex uses stands after ePrint 2025/2046.

### Cited Findings
- Linea describes Vortex as "a plausibly post-quantum and transparent polynomial commitment scheme based on a lattice hash function", and the hash's collision and preimage resistance "are directly reducible to SIS". — [ethresear.ch](https://ethresear.ch/t/vortex-building-a-prover-for-the-zk-evm/14427)
- The 2022 Linea work was described as the first transparent and plausibly post-quantum SNARK relying on Ring-SIS (search-summary of the IACR news item; abstract wording not verified). — [IACR news item](https://iacr.org/news/item/19636)
- Vortex knowledge soundness is proven "in the Random Oracle Model" with a straight-line extractor, and the column hash F = MiMC(SIS(·)) is "heuristically" modelled as a RO. — [ePrint 2022/1633 §7.2](https://eprint.iacr.org/2022/1633)
- Linea's deployed pipeline is not PQ end-to-end: recursion layers use PLONK+KZG on BW6/BLS12-377 and the final wrap is PLONK on BN254, with three trusted setups. — [L2BEAT Linea prover](https://l2beat.com/zk-catalog/lineaprover)
- Vortex's proven soundness uses BCIKS20 correlated agreement in the unique- and Johnson-decoding regimes; capacity is "currently a conjecture and will not be addressed". — [ePrint 2024/185 PDF, Def. 7](https://eprint.iacr.org/2024/185.pdf)

### Inferences
- Assumption set, Vortex+SIS: RS proximity (proven to Johnson) + Ring-SIS collision resistance (lattice, believed PQ, concretely estimated by Linea only classically) + a hash modelled as RO (MiMC/Poseidon2, ROM only). Pure FRI/WHIR with SHA-256: RS proximity + SHA-256 as RO, for which BCS has a QROM proof (CMS19) and quantum generic-attack costs are well studied (Grover/BHT). The SIS variant therefore has a strictly larger and less-studied assumption set and no QROM result, at the same RS-proximity footing.
- Vortex's Johnson-regime analysis is unaffected by the Nov 2025 capacity-conjecture disproof (ePrint 2025/2046), as is Linea's production query count (2λ/log(1/ρ)). Johnson-regime parameters do cost about 2× more column openings than capacity-based ones.
- Practical verdict for the gnark fork. A Vortex-style code+SIS PCS is a feasible but unattractive "lattice" option for univariate PLONK over bn254 Fr:
  1. No bn254 implementation exists; we would port koalabear Vortex and generate bn254 SIS.
  2. Proofs are O(√N), in the MB range, without self-recursion, which we lack.
  3. There is no ZK, so masking would have to be designed ourselves, Ligero-style.
  4. Single-point openings need a ζ/ωζ reduction.
  5. The SIS layer gives no PQ or QROM advantage over the current SHA-256 FRI.

  It is defensible only as a deliberate experiment in the "lattice-hash" design class, or as groundwork for in-circuit recursion where SIS linearity pays off. A genuinely lattice-native PCS (Akita, Greyhound, Maltese) is a different design class with the field and multilinear constraints already recorded in PROJECT.md.

### Gaps
- No QROM proof for Vortex or for BCS with a SIS-based (non-RO) Merkle hash was found.
- No ZK Vortex variant was found, and no source was found quantifying masking overhead for a Ligero-style scheme in this setting. Ligero itself is ZK, but the original paper was not fetched in this session.
- No published quantum cost estimates for Linea's SIS parameter sets were found.
