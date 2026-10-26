"""Greyhound Phase 0: can Greyhound/LaBRADOR be instantiated over R_r = Z_r[X]/(X^d+1), r = bn254 Fr?

Checks
  1. Splitting of X^d + 1 mod r.
  2. Invertibility of short elements (Lyubashevsky-Seiler, ePrint 2017/523), proof re-derived
     here and tested exhaustively at toy parameters.
  3. Challenge-set sizes at d = 32 whose differences are provably invertible.
  4. Module-SIS core-SVP security (ADPS16 methodology, as used by the Greyhound reference code).
Pure Python 3, no dependencies. Run: python3 phase0.py
"""
import itertools, math

R = 21888242871839275222246405745257275088548364400416034343698204186575808495617
LOG2R = math.log2(R)

def v2(n):
    k = 0
    while n % 2 == 0:
        n //= 2; k += 1
    return k

def section(t):
    print("\n== " + t)

# ---------------------------------------------------------------- 1. splitting
section("1. Splitting of X^d + 1 mod r")
print(f"log2 r = {LOG2R:.3f}, v2(r-1) = {v2(R-1)}")
# X^d+1 splits into d linear factors iff Z_r has a primitive 2d-th root of unity iff 2d | r-1.
g = next(a for a in range(2, 100) if pow(a, (R - 1) // 2, R) == R - 1)   # quadratic non-residue
for d in (16, 32, 64, 128):
    psi = pow(g, (R - 1) // (2 * d), R)          # primitive 2d-th root
    assert pow(psi, d, R) == R - 1               # psi^d = -1 -> psi is a root of X^d + 1
    roots = {pow(psi, 2 * i + 1, R) for i in range(d)}
    assert len(roots) == d and all(pow(x, d, R) == R - 1 for x in roots)
    print(f"d = {d:4d}: {d} distinct roots of X^d+1 found -> fully splits (k = d factors, each of norm r)")

# ---------------------------------------------------------------- 2. invertibility
section("2. Invertibility bound")
print("""Claim (LS18, ePrint 2017/523, Cor. 1.2 specialised to k = d): if X^d+1 splits into k
factors mod p, any y with 0 < ||y||_2 < p^(1/k) is invertible in Z_p[X]/(X^d+1).
Re-derivation for k = d: if y is not invertible, y(w) = 0 mod p for some root w, so y lies
in a prime ideal P of norm p, hence p | N(y) and N(y) != 0, so |N(y)| >= p. By AM-GM and
||sigma(y)||_2^2 = d * ||y||_2^2 (power-of-two cyclotomic), |N(y)| <= ||y||_2^d. So
||y||_2 >= p^(1/d). Infinity-norm form: ||y||_2 <= sqrt(d)*||y||_inf, giving
||y||_inf < p^(1/d)/sqrt(d).""")

def toy_check(p, d, B):
    """Exhaustive: smallest l2 norm of a non-invertible y with coefficients in [-B, B]."""
    assert (p - 1) % (2 * d) == 0
    gg = next(a for a in range(2, p) if pow(a, (p - 1) // 2, p) == p - 1)
    psi = pow(gg, (p - 1) // (2 * d), p)
    roots = [pow(psi, 2 * i + 1, p) for i in range(d)]
    best = None
    for y in itertools.product(range(-B, B + 1), repeat=d):
        if not any(y):
            continue
        n2 = sum(c * c for c in y)
        if best is not None and n2 >= best[0]:
            continue
        for w in roots:
            if sum(c * pow(w, i, p) for i, c in enumerate(y)) % p == 0:
                best = (n2, y); break
    return best

for p, d, B in ((257, 4, 4), (257, 8, 2), (97, 4, 4), (17, 8, 2), (12289, 4, 7)):
    best = toy_check(p, d, B)
    bound = p ** (1 / d)
    if best:
        n = math.sqrt(best[0])
        print(f"p={p:6d} d={d}: bound p^(1/d) = {bound:6.3f}; shortest non-invertible ||y||_2 = {n:6.3f} "
              f"{'OK' if n >= bound - 1e-9 else 'VIOLATED'}  e.g. y = {best[1]}")
    else:
        print(f"p={p:6d} d={d}: bound {bound:.3f}; no non-invertible y in box [-{B},{B}]^{d} (consistent)")

print("\nbn254 r, fully split:")
for d in (16, 32, 64, 128):
    l2 = 2 ** (LOG2R / d)
    print(f"d = {d:4d}: ||c-c'||_2 < {l2:10.2f}   ||c-c'||_inf < {l2 / math.sqrt(d):9.2f}")

# ---------------------------------------------------------------- 3. challenge sets
section("3. Challenge sets at d = 32 with provably invertible differences")
d = 32
L2B = 2 ** (LOG2R / d)
print(f"Bound: ||c-c'||_2 < {L2B:.1f}. LaBRADOR (ePrint 2022/1341) uses d = 64, |C| ~ 2^128, op-norm <= 15.")
print(" coeff range | log2|C| (uniform) | worst ||c-c'||_inf | worst ||c-c'||_2 | provable? | E||c||_2")
for k in (1, 2, 4, 6, 8, 10, 12, 16, 21):
    logC = d * math.log2(2 * k + 1)
    worst2 = 2 * k * math.sqrt(d)
    e2 = math.sqrt(d * k * (k + 1) / 3)
    ok = "inf-norm" if 2 * k < L2B / math.sqrt(d) else ("no")
    print(f"  [-{k:2d},{k:2d}]   | {logC:17.1f} | {2*k:18d} | {worst2:16.1f} | {ok:9s} | {e2:6.1f}")
# Sparse alternative: weight-w ternary/{±1,±2} like LaBRADOR, restricted by l2 norm instead.
lab = math.comb(64, 31) * math.comb(33, 10) * 2 ** 41
print(f"Baseline, LaBRADOR d=64 set (31 x ±1, 10 x ±2): log2|C| = {math.log2(lab):.1f}, ||c||_2 = sqrt(71) = {math.sqrt(71):.2f}")
print("\nSparse sets bounded by l2 norm (differences have ||c-c'||_2 <= 2*||c||_2):")
for (n1, n2) in ((16, 8), (20, 12), (24, 8), (12, 20), (16, 16)):
    # n1 coefficients of magnitude 1, n2 of magnitude 2, rest 0
    if n1 + n2 > d: continue
    cnt = math.comb(d, n1) * math.comb(d - n1, n2) * 2 ** (n1 + n2)
    norm = math.sqrt(n1 + 4 * n2)
    print(f"  {n1:2d} x ±1, {n2:2d} x ±2: log2|C| = {math.log2(cnt):6.1f}, ||c||_2 = {norm:5.2f}, "
          f"diff bound {2*norm:5.1f} < {L2B:.0f}: {2*norm < L2B}")

# ---------------------------------------------------------------- 4. Module-SIS
section("4. Module-SIS security, core-SVP (ADPS16, ePrint 2015/1092)")
print("""Model: BKZ-b on an m-column sublattice reaches length delta(b)^m * q^(n/m) (n = kappa*d rows);
delta(b) from Chen (thesis 2013); cost 2^(0.292 b) classical [BDGL16], 2^(0.265 b) quantum [Laa15].
Secure at bound beta iff the best length over m exceeds beta. Ignores l_inf, dimension-for-free and
the full lattice-estimator; it is the methodology the Greyhound reference README quotes.""")

def delta(b):
    return ((math.pi * b) ** (1 / b) * b / (2 * math.pi * math.e)) ** (1 / (2 * (b - 1)))

def shortest_log2(n, logq, b):
    ld = math.log2(delta(b))
    m_opt = math.sqrt(n * logq / ld)
    return 2 * math.sqrt(n * logq * ld) if True else m_opt  # delta^m q^(n/m) at optimum m

def sis_bits(n, logq, logbeta, quantum=True):
    if logbeta >= logq:
        return 0.0
    for b in range(60, 3000):
        if shortest_log2(n, logq, b) <= logbeta:
            return (0.265 if quantum else 0.292) * b
    return float("inf")

def min_rank(d, logq, logbeta, target=128, quantum=True):
    for kappa in range(1, 400):
        if sis_bits(kappa * d, logq, logbeta, quantum) >= target:
            return kappa
    return None

b128 = math.ceil(128 / 0.265)
print(f"128-bit quantum core-SVP -> b = {b128}, log2 delta = {math.log2(delta(b128)):.5f}")
print("Rows n*log2 q needed (bits per commitment), = (log2 beta)^2 / (4 log2 delta):")
print(" log2 beta | q=2^32,d=64: kappa (KB/commit) | q=r,d=32: kappa (KB/commit) | q=r,d=64: kappa")
for lb in (12, 16, 20, 24, 32, 40, 48, 64):
    def cell(dd, lq):
        k = min_rank(dd, lq, lb)
        return "   insecure (beta >= q)    " if k is None else f"{k:4d} ({k * dd * lq / 8 / 1024:5.2f} KB)            "
    print(f"   {lb:3d}    | {cell(64, 32)} | {cell(32, LOG2R)} | {cell(64, LOG2R)}")

# ---------------------------------------------------------------- 5. operator norm
section("5. Operator norm of challenges at d = 32 (max_j |c(w_j)| over complex roots of X^d+1)")
import random, cmath
random.seed(1)
W = [cmath.exp(1j * math.pi * (2 * j + 1) / 32) for j in range(32)]
def opnorm(c):
    return max(abs(sum(ci * w ** i for i, ci in enumerate(c))) for w in W)
def sample_uniform(k):
    return [random.randint(-k, k) for _ in range(32)]
def sample_sparse(n1, n2):
    c = [1] * n1 + [2] * n2 + [0] * (32 - n1 - n2); random.shuffle(c)
    return [x * random.choice((-1, 1)) for x in c]
for name, f in (("uniform [-8,8]  (2^130.8)", lambda: sample_uniform(8)),
                ("uniform [-4,4]  (2^101.4)", lambda: sample_uniform(4)),
                ("sparse 16x±1,8x±2 (2^66.8)", lambda: sample_sparse(16, 8))):
    xs = sorted(opnorm(f()) for _ in range(20000))
    print(f"  {name}: median {xs[10000]:6.1f}, 99th pct {xs[19800]:6.1f}, max {xs[-1]:6.1f}")
print("  LaBRADOR d=64 set: ||c||_2 = sqrt(71) ~ 8.4, rejection-sampled to op-norm <= 15 (2022/1341).")
