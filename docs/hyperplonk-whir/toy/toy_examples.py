#!/usr/bin/env python3
"""Toy examples for OVERVIEW.md, recomputed from scratch (stdlib only).

Run:  python3 -I docs/hyperplonk-whir/toy/toy_examples.py
Every number quoted in OVERVIEW.md's toy examples is printed here, so the
student can check it and change the inputs. Small primes are used for
readability; the real system uses the 254-bit bn254 scalar field.
"""
import math
from itertools import product

P = 97            # toy field for the PIOP examples
Q = 17            # toy field for the Reed-Solomon / folding examples


def inv(a, p=P):
    a %= p
    assert a != 0, "inverse of 0"
    return pow(a, p - 2, p)


def eq(b, x, p=P):
    """eq(b, x) = prod_k (b_k x_k + (1-b_k)(1-x_k))."""
    out = 1
    for bk, xk in zip(b, x):
        out = out * (bk * xk + (1 - bk) * (1 - xk)) % p
    return out


def bits(i, mu):
    """Row index -> bits, MSB first (X_1 is the most significant bit)."""
    return [(i >> (mu - 1 - k)) & 1 for k in range(mu)]


def mle(table, x, p=P):
    mu = len(x)
    return sum(table[i] * eq(bits(i, mu), x, p) for i in range(len(table))) % p


def fold(table, r, p=P):
    """gnark-crypto MultiLin.Fold: bind X_1 (MSB) = r -> mix bottom and top halves."""
    h = len(table) // 2
    return [((1 - r) * table[j] + r * table[h + j]) % p for j in range(h)]


def section(title):
    print("\n" + "=" * 70 + "\n" + title + "\n" + "=" * 70)


# ---------------------------------------------------------------- 1. MLE
section("1. Multilinear extension and folding (F_97)")
T = [3, 1, 4, 1]
print("table T (rows 00,01,10,11) =", T)
print("T~(2,3) by the eq formula  =", mle(T, [2, 3]))
T1 = fold(T, 2)
print("fold X1=2 -> ", T1, "; fold X2=3 ->", fold(T1, 3))
print("T~(0,1) =", mle(T, [0, 1]), "(equals T[01] = 1)")

# ------------------------------------------------------------ 2. sumcheck
section("2. Sumcheck: honest run and a lie (F_97)")
F = lambda x1, x2: (x1 + 2 * x1 * x2) % P
S = sum(F(a, b) for a, b in product([0, 1], repeat=2)) % P
print("F(x1,x2) = x1 + 2 x1 x2, S =", S)
r1, r2 = 5, 7
s1 = lambda t: (F(t, 0) + F(t, 1)) % P
print("honest: s1(0)+s1(1) =", (s1(0) + s1(1)) % P, " claim1 = s1(5) =", s1(r1))
s2 = lambda t: F(r1, t)
print("        s2(0)+s2(1) =", (s2(0) + s2(1)) % P, " claim2 = s2(7) =", s2(r2), " F(5,7) =", F(r1, r2))
# lie: claim S' = 5. The best a cheater can do in round 1 is a degree-1 s1' with
# s1'(0)+s1'(1) = 5 that agrees with the true s1 at as many points as possible:
# s1'(t) = 5t differs from s1(t) = 4t by t, so it agrees only at t = 0.
s1l = lambda t: (5 * t) % P
print("lie S'=5: prover sends s1'(t) = 5t ; s1'(0)+s1'(1) =", (s1l(0) + s1l(1)) % P)
lucky1 = [r for r in range(P) if s1l(r) == s1(r)]
print("          r1 for which s1' and s1 agree:", lucky1, "-> survives round 1 w.p.", len(lucky1), "/", P)
cl1 = s1l(r1)
print("          r1 = 5: new claim s1'(5) =", cl1, "but the true s1(5) =", s1(r1), "-> still lying")
s2l = lambda t: (s2(t) + 5 * t) % P
print("          round 2: s2'(t) = s2(t) + 5t ; s2'(0)+s2'(1) =", (s2l(0) + s2l(1)) % P)
lucky2 = [r for r in range(P) if s2l(r) == s2(r)]
print("          r2 for which s2' and s2 agree:", lucky2)
print("          r2 = 7: final check s2'(7) =", s2l(r2), " vs F(5,7) =", F(r1, r2), "-> REJECT")
print("          overall the lie survives with probability <= 2/97 (= mu*d/|F|)")

# 3-variable table for the animation
section("2b. Sumcheck on a 3-variable table (animation figures/sumcheck.svg)")
T3 = [2, 0, 1, 3, 1, 1, 0, 2]
rs = [5, 7, 2]
cur, claim = T3[:], sum(T3) % P
print("table", T3, "sum", claim)
for i, r in enumerate(rs, 1):
    h = len(cur) // 2
    s0, s1v = sum(cur[:h]) % P, sum(cur[h:]) % P
    assert (s0 + s1v) % P == claim
    nxt = fold(cur, r)
    claim = ((1 - r) * s0 + r * s1v) % P
    print(f"round {i}: s(0)={s0} s(1)={s1v} r={r} -> folded {nxt}, claim {claim}")
    cur = nxt
assert cur[0] == claim == mle(T3, rs)
print("final: T~(5,7,2) =", mle(T3, rs))

# ------------------------------------------------------------ 3. zerocheck
section("3. Why the zerocheck needs eq(r, x) (F_97)")
fbad = [1, P - 1, 0, 0]
print("f on the hypercube =", fbad, " plain sum =", sum(fbad) % P, "(0, yet f != 0!)")
r = [3, 10]
print("sum eq(r,x) f(x) at r=(3,10) =", sum(eq(bits(i, 2), r) * fbad[i] for i in range(4)) % P, "(non-zero -> caught)")

# ------------------------------------------------------- 4. toy circuit
section("4. Toy circuit x^2 + x + 5 = out, x = 3 (secret), out = 17 (public), F_97")
n, mu = 4, 2
# row 0: public placeholder  -w0 + pub = 0          (R, O hold wire 0 = the first public var)
# row 1: x * x - v1 = 0                              (qM = 1, qO = -1)
# row 2: v1 + x - v2 = 0                             (qL = qR = 1, qO = -1)
# row 3: v2 - out + 5 = 0                            (qL = 1, qR = -1, qC = 5; O unused -> wire 0)
qL = [P - 1, 0, 1, 1]
qR = [0, 0, 1, P - 1]
qO = [0, P - 1, P - 1, 0]
qM = [0, 1, 0, 0]
qC = [0, 0, 0, 5]
w0 = [17, 3, 9, 12]   # L column: out, x, v1, v2
w1 = [17, 3, 3, 17]   # R column: wire0, x, x, out
w2 = [17, 9, 12, 17]  # O column: wire0, v1, v2, wire0
pub = [17]
PI = [17, 0, 0, 0]


def gates(W):
    return [(qL[i] * W[0][i] + qR[i] * W[1][i] + qO[i] * W[2][i] + qM[i] * W[0][i] * W[1][i] + qC[i] + PI[i]) % P
            for i in range(n)]


W = [w0, w1, w2]
print("gate values per row:", gates(W))
assert gates(W) == [0] * n
# position (column j, row i) has label j*n + i; sigma maps it to the next position of the same variable
cycles = {"out (= wire 0)": [0, 4, 8, 7, 11], "x": [1, 5, 6], "v1": [9, 2], "v2": [10, 3]}
sig = {}
for cyc in cycles.values():
    for a, b in zip(cyc, cyc[1:] + cyc[:1]):
        sig[a] = b
sigma = [[sig[j * n + i] for i in range(n)] for j in range(3)]
print("cycles:", cycles)
print("sigma_0, sigma_1, sigma_2 =", sigma)
for j in range(3):
    for i in range(n):
        lab = sig[j * n + i]
        assert W[j][i] == W[lab // n][lab % n], "copy constraint"


def logup(W, beta, gamma):
    hs, sa, sb = [], 0, 0
    for j in range(3):
        hj = []
        for i in range(n):
            a = (gamma + W[j][i] + beta * (j * n + i)) % P
            b = (gamma + W[j][i] + beta * sigma[j][i]) % P
            sa, sb = (sa + inv(a)) % P, (sb + inv(b)) % P
            hj.append((inv(a) - inv(b)) % P)
        hs.append(hj)
    return hs, sa, sb


beta, gamma = 11, 5
hs, sa, sb = logup(W, beta, gamma)
print(f"beta={beta}, gamma={gamma}: sum 1/a = {sa}, sum 1/b = {sb}")
print("h_0, h_1, h_2 =", hs, " sum of all h =", sum(map(sum, hs)) % P)
Wc = [[17, 3, 9, 12], [17, 3, 4, 17], [17, 9, 13, 17]]
print("cheating witness: x used as 4 in row 2, v2 output 13 but copied as 12; gates:", gates(Wc))
assert gates(Wc) == [0] * n
hc, sac, sbc = logup(Wc, beta, gamma)
print("cheating witness: sum of all h =", sum(map(sum, hc)) % P, "-> non-zero, caught")

# ------------------------------------------------------------- 5. stacking
section("5. Stacking 4 columns of 1 variable into one 3-variable table (F_97)")
cols = [[1, 2], [3, 4], [5, 6], [0, 0]]
stack = sum(cols, [])
tau, rho = [3, 8], 10
lhs = sum(eq(bits(j, 2), tau) * mle(cols[j], [rho]) for j in range(4)) % P
print("stack =", stack, "; sum_j eq(tau,j) c_j(rho) =", lhs, "; C(tau,rho) =", mle(stack, tau + [rho]))
assert lhs == mle(stack, tau + [rho])

# ------------------------------------------------------------- 6. ZK mask
section("6. Witness mask w*(X) = w(X) + c X1(1-X1) (F_97)")
cmask = 40
wstar = lambda x: (mle(w0, x) + cmask * x[0] * (1 - x[0])) % P
print("on the hypercube:", [wstar(bits(i, 2)) for i in range(4)], "== w0 =", w0)
pt = [10, 20]
print("at rho=(10,20): w~(rho) =", mle(w0, pt), " w*(rho) =", wstar(pt),
      " offset c*rho1*(1-rho1) =", cmask * 10 * (1 - 10) % P)

# ------------------------------------------------------- 7. Reed-Solomon
section("7. Reed-Solomon code over F_17, domain = <2> (order 8), rate 1/4")
L = [pow(2, i, Q) for i in range(8)]
f = lambda X: (3 + 2 * X) % Q
cw = [f(x) for x in L]
print("domain L =", L)
print("codeword of f(X)=3+2X:", cw)
bad = cw[:]
for pos, val in [(1, 0), (4, 0), (6, 0)]:
    bad[pos] = val
print("corrupted word (3 of 8 positions changed):", bad)
for t in (1, 5, 10, 15):
    print(f"  {t:2d} queries all miss with probability (5/8)^{t} = {(5/8)**t:.4f}")
print("  queries for 2^-10: t >= 10/log2(8/5) =", math.ceil(10 / math.log2(8 / 5)))

# ---------------------------------------------- 8. interleaved RS + fold
section("8. Interleaved encoding and folding (WHIR, k=1, F_17)")
v = [3, 1, 4, 1]
c0 = lambda X: (v[0] + v[1] * X) % Q   # chunk b=0 (top bit 0)
c1 = lambda X: (v[2] + v[3] * X) % Q   # chunk b=1
leaves = [(c0(x), c1(x)) for x in L]
print("leaves (c0(x), c1(x)) for x in L:", leaves)
alpha = 5
folded_table = [((1 - alpha) * v[0] + alpha * v[2]) % Q, ((1 - alpha) * v[1] + alpha * v[3]) % Q]
print("P(alpha=5, .) table =", folded_table)
x = 4
lf = leaves[L.index(x)]
print(f"verifier folds leaf at x={x}: (1-5)*{lf[0]} + 5*{lf[1]} =", ((1 - alpha) * lf[0] + alpha * lf[1]) % Q,
      "; encoding of folded table at x:", (folded_table[0] + folded_table[1] * x) % Q)

# ------------------------------------------------------- 9. query counts
section("9. WHIR query counts (Johnson: 1-delta = 1.05*sqrt(rho); UD: (1+rho)/2), lambda=128")
for rho_i in (1 / 8, 1 / 64, 1 / 512):
    jb = math.ceil(128 / -math.log2(1.05 * math.sqrt(rho_i)))
    ud = math.ceil(128 / -math.log2((1 + rho_i) / 2))
    print(f"  rate 1/{round(1/rho_i):3d}: bits/query JB {-math.log2(1.05*math.sqrt(rho_i)):.3f} -> {jb:3d} queries;"
          f" UD {-math.log2((1+rho_i)/2):.3f} -> {ud:3d}")
section("10. WHIR rate schedule, m=12, k=4, rho0=1/8")
m, kf, logD = 12, 4, 12 - 4 + 3
while m >= 2 * kf:
    print(f"  m={m:2d}: chunk length 2^{m-kf}, domain 2^{logD}, rate 2^-{logD-(m-kf)}")
    m, logD = m - kf, logD - 1
print(f"  m={m:2d}: base case, send {2**m} values")
