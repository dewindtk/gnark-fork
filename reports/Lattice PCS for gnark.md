# Lattice commitments do not yet fit bn254 PLONK

No lattice-based polynomial commitment scheme surveyed (October 2026) can replace FRI behind gnark's `Scheme` interface over bn254 Fr without new cryptographic research. Only one design class is integrable with engineering effort alone: **Vortex-style Reed–Solomon commitments with a Ring-SIS column hash**. Their lattice component is limited to the hash, so they give no post-quantum or QROM advantage over the current SHA-256 FRI, and our estimate puts their proofs at several MB. The structurally best fit among genuine lattice-native schemes is **Greyhound**: natively univariate, standard Module-SIS, transparent, about 60 KB proofs. It has been instantiated only at a ~32-bit partially splitting modulus, and its verifier is square-root (74 ms at 2²² coefficients against our 4.9 ms). It has no ZK, no QROM proof and no Go code. The only lattice PCS with a quantum knowledge-soundness proof and a univariate interface, **Cini–Malavolta–Nguyen–Wee (CMNW)**, has megabyte proofs and exists only as a parameter script. Every scheme with fast verification (RoKoKo, Grand Danois) rests on the under-analysed vanishing-SIS assumption and has had parameter or soundness errors. The older algebraic line (ACLMT22, CLM23 plain-model, Wee–Wu) either relies on a broken knowledge assumption or is binding-only. Three obstacles apply to the whole family: bn254 Fr's fully splitting ring, about 16× witness blow-up from digit decomposition, and the incompatibility of homomorphic batching with short-witness commitments. Akita's infeasibility therefore reflects the state of the field, not a peculiarity of that scheme. WHIR remains the better next step.

## Three obstacles block every lattice-native scheme on bn254 Fr

The first and decisive obstacle is the modulus. In every lattice-native PCS the evaluation field equals the commitment modulus q, or an extension of it. LaBRADOR, Greyhound and Hachi all use **q ≈ 2³² with minimal splitting**, where X^d + 1 factors into exactly two pieces (q ≡ 5 mod 8, d = 64) ([Akita §3.1](https://eprint.iacr.org/2026/1983)). The reference C code is hard-wired to ring degree 64 and to LOGQ ∈ {24, …, 64} with pseudo-Mersenne moduli ([lattice-dogs/labrador](https://github.com/lattice-dogs/labrador)). Akita ships only fp32/fp64/fp128 profiles ([LayerZero-Labs/akita](https://github.com/LayerZero-Labs/akita)). LaBinius makes the field–modulus dependence explicit: "the constraint field's characteristic must equal the commitment modulus" in existing schemes. LaBinius itself breaks that link only for binary fields ([ePrint 2026/2103](https://eprint.iacr.org/2026/2103)). No published reduction maps claims over an unrelated 254-bit prime onto a small-q lattice commitment. Emulating F_r arithmetic as integer relations with LNP22-style lifting ([ePrint 2022/284](https://eprint.iacr.org/2022/284)) is not developed into any PCS.

That leaves the native route, setting **q = r**. Here bn254's 2-adicity of 28 works against us. Because r ≡ 1 (mod 2²⁸), X^d + 1 splits into d linear factors for every d ≤ 2²⁷. That is the fully splitting regime, which "often do[es] not admit rigorous challenge sets" ([Akita §1.2](https://eprint.iacr.org/2026/1983)). The Lyubashevsky–Seiler invertibility bound ([ePrint 2017/523](https://eprint.iacr.org/2017/523)) is ‖c − c′‖∞ < q^{1/s}/√s, where s is the number of factors. The research notes recalled this bound from memory, and it has not been checked against the paper. Plugging in q = r and s = d gives:

| Ring degree d | Invertibility bound |
|---|---|
| 16 | ≈ 14 764 |
| 32 | ≈ 43 |
| 64 | ≈ 1.95 |

At d = 64, even ternary challenge differences are not covered. At d = 32 the bound is comfortable: coefficients in [−21, 21] give about 2¹⁷³ challenges. **A rigorous q = r instantiation is plausible at d ≤ 32**, but no paper parameterises or analyses it.

One danger does not carry over. The zkSecurity bugs reduced LaBRADOR ports to 31, 6 or even 1 bit of soundness ([zkSecurity](https://blog.zksecurity.xyz/posts/labrador-bugs/)). They arose because the CRT factors of the ring were small. At q = r each factor is a full copy of F_r, so that failure mode does not apply. A larger q also makes SIS harder at a fixed norm bound. The costs at q = r are size and speed instead. Each 254-bit coefficient must be gadget-decomposed into about 16 limbs of 16 bits, so the committed witness grows about 16×. Ring arithmetic moves from 32-bit words to 4-limb multiprecision. Commitments and openings grow roughly 8× per ring element compared with q ≈ 2³². These multipliers are our estimates; no source measures them.

The second obstacle is structural and specific to PLONK. gnark batches many polynomials by a random F_r-linear combination of commitments before opening. With a lattice commitment, that combination of digit-decomposed witnesses is no longer short, so it is not a valid opening. **Batching must move to the claims**, through a sumcheck or a batched-evaluation argument, rather than through homomorphic combination of commitments. Our FRI already batches on claims (18 proofs reduced to 1, per PROJECT.md), so this fits the current seam better than it would have fitted KZG. It still needs a design.

The third obstacle is zero-knowledge. PIOP-level blinding (random multiples of Z_H) is enough for KZG. It is probably not enough here, because a lattice opening reveals folded short witnesses. Adding ZK requires hiding commitments (extra Module-LWE randomness, as in LNP22/BDLOP) plus masking by rejection sampling or noise flooding. In a fully split ring that masking must also be uniform per CRT slot. The only concrete ZK construction in this family is the Biasioli et al. toolkit for LaBRADOR, which has linear-size overhead and verification above 1 s on large instances ([ePrint 2026/1289](https://eprint.iacr.org/2026/1289); [Akita fn. 3](https://eprint.iacr.org/2026/1983)).

## Standard-assumption schemes trade verifier time or proof size for soundness

The Module-SIS family is where a defensible PQ lattice PCS would come from. Each candidate fails a different requirement. The table below records per-scheme fit. Proof sizes come from each paper's own field, at about 32 or 50 bits; none is measured at a 254-bit modulus.

| Scheme | Polynomial type | Assumption / setup | Proof size, verify | ZK | QROM | Code | bn254 Fr fit |
|---|---|---|---|---|---|---|---|
| Greyhound (+LaBRADOR) | Univariate | Module-SIS, transparent | 59–66 KB; 74 ms–1.5 s | No | No (ROM) | C, AVX-512 only | q = r unparameterised; d ≤ 32 needed |
| Hachi | Multilinear over F_{q^k} | Module-SIS, transparent | ~55 KB (estimate); 12.5× faster verify than Greyhound | No | No | Partial Rust, one fold | k = 1 reduction applies to q = r in principle; base-field variant unsound as published |
| CMNW24 | Univariate | Module-SIS, transparent | 5.17 MB at 2³⁰; ~2× smaller than FRI at 2²⁰ | No | **Quantum knowledge soundness** | Python parameter script | Z_q mode fixes d = 256 |
| Jindo | Multilinear | Module-SIS, heuristic challenges | 315–1207 KB; Õ(N^{1/3}) verify | Evaluation hiding | No | Go (repo not located) | "Diverse fields", unspecified |
| Maltese | Multilinear | Module-SIS | 335 KB at 2³⁰ | Not stated | Not stated | Not found | Unknown |
| FMN / SLAP | Univariate (Marlin) / tree | Ring-BASIS (trusted CRS) / Power-Ring BASIS | 8.3 MB / 767 MB at 2³⁰ | No | No | Research | Impractical |
| *Akita (comparison)* | Multilinear | Module-SIS, transparent | 61–67 KB; 8–16 ms | No | No | Rust | Infeasible (partial splitting) |

**Greyhound** is the only concretely efficient lattice PCS whose interface already matches gnark's: it proves f(x) = v for univariate f of bounded degree ([ePrint 2024/1293](https://eprint.iacr.org/2024/1293)). Akita's authors benchmarked a security-recalibrated revision on one thread over a 32-bit field ([Akita Table 9](https://eprint.iacr.org/2026/1983)):

| Coefficients | Proof | Verify | Commit | Open | Peak RAM |
|---|---|---|---|---|---|
| 2²² | 59.3 KB | 73.8 ms | — | — | — |
| 2³⁰ | 66.1 KB | 1525 ms | 59.4 s | 21.3 s | 104.8 GiB |

Our 65k-constraint circuit commits on the order of 2²¹ coefficients, which puts it at the small end of that table. Against FRI's 0.90 MB and 4.9 ms, Greyhound would buy a **~15× smaller proof for a ~15× slower verifier**, and that is before the unmeasured 254-bit penalty.

Akita's audit also found implementation-level gaps in Greyhound:

- The C code computes commitments as truncated extension-ring products, so collisions are not Module-SIS solutions ("truncated-output Ring-SIS").
- Its Johnson–Lindenstrauss projection had to be replaced to match the certified tail bound ([Akita App. F.2, §13.2](https://eprint.iacr.org/2026/1983)).

The IBM publication page reports 93 KB rather than 53 KB for Greyhound ([IBM Research](https://research.ibm.com/publications/greyhound-fast-polynomial-commitments-from-lattices)), a discrepancy that is still unresolved.

**Hachi** is attractive on paper, for two reasons. Its generic reduction from F_{q^k} claims to R_q statements would apply at k = 1 with q = r. It also claims a 12.5× faster verifier than Greyhound ([ePrint 2026/156](https://eprint.iacr.org/2026/156)). In practice its artifact measures only the first fold, and the end-to-end protocol hands off to a Greyhound tail. The published base-field specialisation (§3.2) is unsound: Akita exhibits a forgery v′ ≠ v. The generic §3.1 transformation is unaffected ([Akita App. F.1](https://eprint.iacr.org/2026/1983)).

**CMNW** is the most interesting security outlier. It is univariate, transparent and standard Module-SIS, and it is the only scheme found with a knowledge-soundness proof against quantum adversaries ([ePrint 2024/281](https://eprint.iacr.org/2024/281)). Its artifact is a parameter-estimation script with no prover ([IACR artifact](https://artifacts.iacr.org/crypto/2024/a5/readme.html)), and its proofs reach 5.17 MB at 2³⁰. Its claim of being about 2× smaller than FRI at L = 2²⁰ is the one data point suggesting it could compete with our 0.90 MB at our scale. That comparison is against a different FRI configuration, and its verifier time was not available.

**Jindo** is notable mainly as the only lattice PCS with an end-to-end Go implementation ([Akita Table 1](https://eprint.iacr.org/2026/1983)) and a hiding claim ([ePrint 2026/044](https://eprint.iacr.org/2026/044)). However, it is multilinear, it uses heuristic challenges, and its proofs reach the megabyte range at 2²⁰. **Maltese** gets polylog verification from plain Module-SIS at 335 KB for 2³⁰ ([ePrint 2026/2067](https://eprint.iacr.org/2026/2067)). It is too new to have parameters or code that we could assess.

## Structured-assumption schemes buy speed with fragile security

Fast verification comes almost entirely from assumptions weaker than Module-SIS.

**RoKoKo** is the most mature of these. It has polylog verification measured at 4.8–7.4 ms with about 115 KB proofs, and a Rust implementation over q = 2⁵⁰ − 2687 ([Akita Table 9](https://eprint.iacr.org/2026/1983); [rokoko](https://github.com/lattice-arguments/rokoko)). Its binding rests on vanishing SIS, and its released parameters are wrong:

- An operator-norm error leaves the root instance at **77.32 bits** against a 128-bit target.
- An integer-lifting condition fails by a factor of 38 even at a 50-bit q ([Akita App. F.2](https://eprint.iacr.org/2026/1983); [rokoko #94](https://github.com/lattice-arguments/rokoko/issues/94)).

That second failure gets worse, not better, as norms grow with a 254-bit field.

**Grand Danois** estimates about 80 KB for 2³² evaluations. It has no implementation, and a soundness bug in its first version was fixed after Quang Dao reported it ([ePrint 2026/1196](https://eprint.iacr.org/2026/1196); [Akita App. F.1](https://eprint.iacr.org/2026/1983)). Vanishing SIS itself is unbroken, but the only reductions known are narrow ([Lattice Assumption Zoo](https://latticeassumptionzoo.org/vsis/)). A July 2026 paper already shows weak instances of an integer variant of the vSIS commitment ([ePrint 2026/1554](https://eprint.iacr.org/2026/1554)).

The 2022–23 algebraic line can be ruled out entirely:

- **Knowledge k-M-ISIS is broken.** Wee–Wu's oblivious-sampling attack was implemented and confirmed by Albrecht ([Wee–Wu](https://www.cs.utexas.edu/~dwu4/papers/LatticeFC-Fast.pdf); [SIS-with-hints zoo](https://malb.io/sis-with-hints.html)). That removes the knowledge-soundness argument of the ACLMT22 SNARK and of the plain-model CLM23 SNARK.
- **Wee–Wu's own functional commitments are binding-only** and need structured CRSs. A PLONK PCS needs extractability, so binding alone is insufficient.
- **BCFL23 needs a structured CRS of size w⁵.**
- **HyperWolf**, which claimed univariate support, was withdrawn ([ePrint 2025/922](https://eprint.iacr.org/2025/922)).

## Vortex is integrable but lattice only in its hash

Vortex is the one "lattice" option that gnark tooling nearly supports today. It is a Ligero-style batched univariate list commitment ([ePrint 2024/185](https://eprint.iacr.org/2024/185)): the prover RS-encodes the rows of a matrix, hashes each column with Ring-SIS followed by MiMC/Poseidon2, and builds a Merkle tree over the column hashes. Its evaluation soundness is proven up to the Johnson bound via BCIKS20, and Linea parameterises it there (`nb = 2·128/log₂(blowup)`) ([compiler.go](https://github.com/LFDT-Lineth/lineth-monorepo/blob/main/prover/protocol/compiler/vortex/compiler.go)). So the November 2025 capacity disproofs do not touch it.

Ring-SIS over a ~254-bit field is proven practice:

- Linea's original prover ran SIS over bn254 Fr ([ethresear.ch](https://ethresear.ch/t/vortex-building-a-prover-for-the-zk-evm/14427)).
- Linea published q ≈ 2²⁵⁴ parameter sets above 128-bit classical cost, such as d = 64 with b = 2¹⁰, and d = 128 with b = 2¹⁶ ([ePrint 2022/1633 Fig. 22](https://eprint.iacr.org/2022/1633)).
- Full splitting is harmless for SIS collision resistance; SWIFFT uses it deliberately ([SWIFFT](https://iacr.org/cryptodb/archive/2008/FSE/presentation/15627.pdf)).

gnark-crypto v0.21.0 already has a generic SIS template that runs on bls12-377 Fr, plus a non-production KoalaBear Vortex. **It has no `bn254/fr/sis`** ([gnark-crypto](https://pkg.go.dev/github.com/consensys/gnark-crypto@master)). Integration would take four steps:

1. Generate bn254 SIS from the existing template.
2. Port Vortex from E4 challenges to F_r.
3. Add a ζ/ωζ reduction, since Vortex opens at a single point. Linea's `mpts` compiler does this ([lineth-monorepo](https://github.com/LFDT-Lineth/lineth-monorepo/tree/main/prover/protocol/compiler)).
4. Design Ligero-style ZK ourselves, because the paper presents none.

None of these steps needs new cryptography.

The case against Vortex is cost and purpose, not feasibility. Its proofs are O(√N). As a rough estimate, take our ~2²¹ committed coefficients laid out in a square matrix, with 86 opened columns at ρ = 1/8. That gives roughly 4 MB per proof, about 4× our FRI. The SIS hash also **expands** short leaves: a d = 64 output over bn254 is 2 KB, so it compresses only columns taller than 64 elements. Linea skips SIS for small rounds for exactly this reason ([option.go](https://github.com/LFDT-Lineth/lineth-monorepo/blob/main/prover/protocol/compiler/vortex/option.go)).

SIS linearity pays off only inside recursive self-verification, and Linea's pipeline still ends in PLONK+KZG on BN254, so the deployed system is not post-quantum ([L2BEAT](https://l2beat.com/zk-catalog/lineaprover)). Compared with SHA-256 FRI, Vortex adds a Ring-SIS assumption that has only Linea's own, classical-only estimates. Its MiMC∘SIS hash is modelled heuristically as a random oracle in the classical ROM. Pure hash-based BCS, by contrast, has a QROM proof. For a native Go verifier, this is a label change, not a security gain.

## WHIR remains the benchmark lattice schemes cannot meet

Set against these candidates, WHIR answers every integration question that the lattice schemes leave open:

- **Field:** bn254 Fr works natively, with a 2²⁸ smooth subgroup and no extension field needed.
- **Interface:** univariate claims are served through the weight ⊗ⱼ(1, ζ^(2^j)).
- **Soundness:** proven to the Johnson bound, at 299 KiB for 2²⁴ with ρ = 1/2 at 128 bits ([ePrint 2024/1586](https://eprint.iacr.org/2024/1586)), using mutual correlated agreement from Haböck ([ePrint 2025/2110](https://eprint.iacr.org/2025/2110)).
- **ZK:** honest-verifier ZK at 1 + o(1) overhead ([ePrint 2026/391](https://eprint.iacr.org/2026/391)).
- **Assumptions:** none beyond a hash, with standard QROM treatment.

No lattice candidate offers proof size and verifier time both better than FRI at our scale. Greyhound and Akita win on proof size by about 15× and lose on verification time. CMNW, Maltese and Vortex lose on size.

Steelmanning the lattice option, its real draw is asymptotic. Greyhound's proof size is nearly flat from 2²² to 2³⁰, while hash-based proofs grow with log² N. Lattice homomorphism also opens folding and recursion paths that hashes do not. Both advantages matter for very large or recursive workloads, not for a 65k-constraint native verifier.

## Conclusion

Every lattice scheme fails on bn254 Fr for the same root cause. Lattice-native PCSs want a small modulus with exactly two CRT factors, while PLONK over bn254 wants a 254-bit modulus with 2²⁸-smooth roots of unity. These are opposite algebraic requirements, so no amount of porting reconciles them. The only way to reconcile them is the research problem of instantiating Greyhound or Hachi at q = r with d ≤ 32, and then re-deriving parameters, challenge sets, ZK masking and claim-level batching. That would be a thesis-sized contribution in its own right, not an integration task. The finding also corrects the framing of our earlier Akita assessment: Akita was not an unlucky choice, since every lattice-native candidate hits the same wall.

For the project, this means lattice commitments are a research direction to watch, not an engineering option, and the trigger to revisit is specific. Revisit if a paper publishes parameters for a lattice PCS at a large fully splitting prime, if a field-switching reduction from a large prime field to a small q appears, or if CMNW-style quantum knowledge soundness reaches a concretely efficient scheme. Until one of those exists, WHIR behind the existing `Scheme` interface remains the post-quantum step, and the Vortex/SIS route is worth only an optional experiment tied to future in-circuit recursion over bn254.
