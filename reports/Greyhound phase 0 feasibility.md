# Greyhound over bn254 Fr: Phase 0 feasibility check

Date: 2026-10-25. Tracks Linear IBM-25, Phase 0. Builds on `reports/Lattice PCS for gnark.md`.

Reproduce:
- Analysis script: `research_notes/Greyhound phase 0/phase0.py` (pure Python 3). Its output is in `phase0_output.txt`.
- Benchmark: `research_notes/Greyhound phase 0/_bench/ring_test.go`, Go with gnark-crypto v0.21.0, run on an Apple M3 Pro.

## Question

Can Greyhound [NS24], with LaBRADOR [BS23] as its proof system, be instantiated with lattice modulus q = r, the bn254 scalar field, and ring degree d = 32? If so, is it worth building behind gnark's `Scheme` interface?

## Verdict

| Check | Result | Status |
|---|---|---|
| 1. X^d + 1 splits mod r | Splits fully for every d ≤ 2²⁷ (v₂(r − 1) = 28) | Expected |
| 2. Invertibility of short elements | Bound re-derived and tested: ‖y‖₂ < r^{1/d}. At d = 32 this means ‖c − c′‖₂ < 243 (‖·‖∞ < 43) | **Go** at d = 32; no-go at d ≥ 64 |
| 3. Challenge set at d = 32 | 128-bit sets exist, but with about 6× LaBRADOR's challenge norm | **Go, with changes** that need new proofs |
| 4. Module-SIS security | Commitment size in bits is about the same as at q ≈ 2³² | **Go** |
| 5. Proof size | Estimated at 60–500 KB, below FRI's 0.90 MB | **Go** (wide range) |
| 6. Verifier time | Estimated at 0.4–2 s, against FRI's 4.9 ms | **No-go** as a FRI replacement |

In short, the q = r instantiation looks cryptographically sound at d = 32. Nothing found blocks it. Its verifier, however, would be about two orders of magnitude slower than our FRI. Whether to continue therefore depends on what the thesis needs: smaller proofs and lattice binding, or a verifier competitive with FRI.

## 1. Splitting

r − 1 is divisible by 2²⁸, so F_r contains primitive 2d-th roots of unity for every d ≤ 2²⁷. X^d + 1 = ∏ᵢ (X − ψ^{2i+1}) therefore splits into d linear factors. The script finds these d roots for d ∈ {16, 32, 64, 128}.

This is the "fully splitting" regime. Akita notes that such rings "often do not admit rigorous challenge sets" [Akita §1.2]. LaBRADOR, Greyhound and Hachi all avoid it by using q ≡ 5 (mod 8), which gives two factors [Akita §3.1]. Checks 2 and 3 test whether the regime is still usable at q = r.

## 2. Invertibility bound

The extractor in LaBRADOR and Greyhound needs every challenge difference c − c′ to be invertible in R_q [BS23]. The relevant result is Lyubashevsky–Seiler [LS18, Cor. 1.2]. If X^d + 1 splits into k factors mod p, then every y with 0 < ‖y‖₂ < p^{1/k} is invertible. Equivalently, 0 < ‖y‖∞ < p^{1/k}/√k suffices.

The previous report recalled this bound from memory. I have now re-derived it for the case k = d:
- If y is not invertible, then y(ω) ≡ 0 for some root ω. So y lies in a prime ideal of norm p, and p divides N(y).
- For power-of-two cyclotomics, ‖σ(y)‖₂² = d·‖y‖₂². By AM–GM, |N(y)| ≤ ‖y‖₂^d.
- Therefore ‖y‖₂ ≥ p^{1/d}.

As a numerical check, I enumerated every element in a coefficient box for five toy rings and found the shortest non-invertible one. No toy ring violated the bound. One case is almost tight: at p = 12289, d = 4 the bound is 10.529 and the shortest non-invertible element has norm 10.536.

| d (over r) | ‖c − c′‖₂ bound | ‖c − c′‖∞ bound |
|---|---|---|
| 16 | 59 056 | 14 764 |
| **32** | **243** | **43** |
| 64 | 15.6 | 1.95 |
| 128 | 3.95 | 0.35 |

At d = 64 even ternary challenge differences (‖·‖∞ = 2) are not covered, so **d = 32 is the largest usable ring degree**. d = 16 would also work.

## 3. Challenge set at d = 32

LaBRADOR's set has d = 64, 31 coefficients equal to ±1 and 10 equal to ±2 [BS23]. The script confirms |C| = 2^128.1 for it, with ‖c‖₂ = √71 ≈ 8.4. LaBRADOR then rejection-samples to operator norm ≤ 15. These parameters are recalled; they should be confirmed against the paper.

At d = 32 there are only half as many coefficients, so the same norm buys far fewer challenges.

| Challenge set (d = 32) | log₂ abs(C) | Worst ‖c − c′‖₂ | Median op-norm | 99th-percentile op-norm |
|---|---|---|---|---|
| Sparse: 16 coefficients ±1, 8 coefficients ±2 | 66.8 | 13.9 | 12.5 | 17.5 |
| Uniform in [−4, 4] | 101.4 | 45 | 26.3 | 38.7 |
| **Uniform in [−8, 8]** | **130.8** | **91 < 243** | **50.0** | **74.1** |

Two ways to reach 128-bit soundness:
- **(a) One wide challenge.** Use the uniform [−8, 8] set, rejection-sampled to op-norm ≤ T ≈ 75. Differences remain provably invertible. Norm growth per challenge multiplication rises from 15 to about 75, roughly +2.3 bits on log β.
- **(b) Two sparse challenges in parallel.** Each has about 2⁶⁷ elements and T ≈ 18, which gives about 2¹³³ combined. This doubles the parts of the proof that depend on the challenge. Extraction for parallel repetition must be argued separately, through k-special soundness [AFK22].

Either way, LaBRADOR's norm-growth and extraction bounds have to be re-proved with the new T. This is the main piece of new cryptography that Phase 1–2 would need.

## 4. Module-SIS security

I used the core-SVP methodology of [ADPS16], which the Greyhound reference implementation also quotes:
- BKZ with block size b reaches vectors of length δ(b)^m · q^{n/m}, where n = κ·d.
- δ(b) follows [Che13].
- Cost is 2^{0.265 b} quantum [Laa15] and 2^{0.292 b} classical [BDGL16].
- For 128-bit quantum security, b = 484 and log₂ δ = 0.00502.

At the optimal m, the shortest reachable vector is 2^{2√(n·log₂q·log₂δ)}. So the required number of rows satisfies n·log₂ q ≥ (log₂ β)² / (4·log₂ δ). **A commitment's size in bits therefore depends on the norm bound β, not on q.** The larger 254-bit coefficients are offset by needing a smaller rank κ.

| log₂ β | q ≈ 2³², d = 64: κ (commitment size) | q = r, d = 32: κ (commitment size) |
|---|---|---|
| 16 | 7 (1.75 KB) | 2 (1.98 KB) |
| 24 | 14 (3.50 KB) | 4 (3.96 KB) |
| 32 | insecure (β ≥ q) | 7 (6.93 KB) |
| 40 | insecure | 10 (9.91 KB) |
| 48 | insecure | 15 (14.9 KB) |

Example at q = r: a base-2¹⁶ gadget gives 16 digits per coefficient. With columns of about 2¹¹ coefficients, the witness norm is about 2^{22.5}. Extraction factors from T and c − c′ add 7–8 bits, for log₂ β_ext ≈ 30, so κ ≈ 7.

This is an estimate, not a full lattice-estimator run [APS15]: it ignores ℓ∞ attacks and the "dimensions for free" improvements. A large q also leaves plenty of room for LaBRADOR's exact ℓ₂-norm check, which needs β² < q.

## 5. Proof size

The proof has three kinds of component, and each scales differently from q ≈ 2³² to q = r:
- **Ajtai commitments:** about the same size (check 4).
- **Short vectors**, such as the final LaBRADOR opening: bits ∝ coefficients × log(norm), not log q. The number of coefficients grows with the digit count.
- **Full R_q elements**, such as Greyhound's evaluation vector and LaBRADOR's garbage terms: 254/32 ≈ 7.9× larger.

Without Greyhound's per-component size breakdown, the best estimate is a range:
- Lower end: the reported 53–64 KB [NS24; Akita Table 1].
- Upper end: about 8× that, around 0.5 MB.

Either end is below FRI's 0.90 MB on our 65k-constraint circuit. Narrowing the range requires the size tables of [NS24] §5–6.

## 6. Verifier time (measured)

Measured with gnark-crypto v0.21.0, scalar Go, on an Apple M3 Pro:

| Operation | Time |
|---|---|
| bn254 Fr multiplication | 13.9 ns |
| Z_q multiplication, q = 2³² − 99 (dependent chain) | 2.5 ns |
| Ring multiplication in F_r[X]/(X³² + 1), via 32-point NTT (verified against schoolbook) | 8.5 µs |
| Ring multiplication in Z_q[X]/(X⁶⁴ + 1), schoolbook | 3.9 µs |

The reported Greyhound verifier takes 74 ms at N = 2²² with C and AVX-512 at q ≈ 2³² [Akita §13.2; greyhound-reference]. Its cost is O(√N) field and ring operations.

At q = r each operation is 5.6× slower scalar-to-scalar. The 32-bit code also gains up to 16 lanes from AVX-512, which 4-limb Montgomery arithmetic does not. That gives an **estimated 0.4–2 s** at our size, against FRI's 4.9 ms. This is an extrapolation, not a measurement of Greyhound itself.

## What is still unproven

- LaBRADOR norm-growth and extraction bounds with T ≈ 75, or with two parallel challenges (check 3).
- Fiat–Shamir security in the ROM only; no QROM proof, as in the original [NS24].
- No zero-knowledge. Masking à la [LNP22] or the LaZer toolkit (ePrint 2026/1289) would be needed.
- Implementation-level gaps carry over: truncated-output Ring-SIS and the JL projection fix [Akita App. F.2, §13.2].

## Recommendation

Decision for the user and supervisor:
- **If the thesis goal is a lattice PCS for PLONK**, accepting a slow verifier: Phase 1 is justified. Start by re-deriving LaBRADOR's bounds with the d = 32 challenge set, before writing Go.
- **If the goal is a better FRI replacement**: stop here and take the WHIR route (IBM-22). This check found no cryptographic blocker, but the verifier time rules Greyhound out for that goal.

To confirm the recalled parameters (LaBRADOR's challenge set, Greyhound's size breakdown, the exact statement of LS18), please download ePrint 2017/523, 2022/1341 and 2024/1293 into `resources/`.

## References

- [ADPS16] E. Alkim, L. Ducas, T. Pöppelmann, P. Schwabe. *Post-quantum key exchange — a new hope.* USENIX Security 2016; ePrint 2015/1092. Core-SVP methodology.
- [AFK22] T. Attema, S. Fehr, M. Klooß. *Fiat–Shamir transformation of multi-round interactive proofs.* TCC 2022; ePrint 2021/1377.
- [Akita] Akita: lattice-based multilinear PCS. ePrint 2026/1983; `resources/2026-1983.pdf`.
- [APS15] M. Albrecht, R. Player, S. Scott. *On the concrete hardness of Learning with Errors.* J. Math. Cryptol. 2015; ePrint 2015/046.
- [BDGL16] A. Becker, L. Ducas, N. Gama, T. Laarhoven. *New directions in nearest neighbor searching with applications to lattice sieving.* SODA 2016; ePrint 2015/1128.
- [BS23] W. Beullens, G. Seiler. *LaBRADOR: Compact proofs for R1CS from Module-SIS.* CRYPTO 2023; ePrint 2022/1341.
- [Che13] Y. Chen. *Réduction de réseau et sécurité concrète du chiffrement complètement homomorphe.* PhD thesis, ENS Paris, 2013. See also Chen–Nguyen, *BKZ 2.0*, ASIACRYPT 2011.
- [Laa15] T. Laarhoven. *Search problems in cryptography.* PhD thesis, TU Eindhoven, 2015. Quantum sieving exponent 0.265.
- [LNP22] V. Lyubashevsky, N. K. Nguyen, M. Plançon. *Lattice-based zero-knowledge proofs and applications.* CRYPTO 2022; ePrint 2022/284.
- [LS18] V. Lyubashevsky, G. Seiler. *Short, invertible elements in partially splitting cyclotomic rings.* EUROCRYPT 2018; ePrint 2017/523.
- [NS24] N. K. Nguyen, G. Seiler. *Greyhound: Fast polynomial commitments from lattices.* CRYPTO 2024; ePrint 2024/1293.
