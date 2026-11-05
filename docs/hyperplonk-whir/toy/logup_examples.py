#!/usr/bin/env python3
"""Toy examples for LOGUP.md, recomputed from scratch (stdlib only).

Run:  python3 -I docs/hyperplonk-whir/toy/logup_examples.py
Every number quoted in LOGUP.md is printed here. The running example is the
same circuit as OVERVIEW.md (x^2 + x + 5 = out over F_97).
"""
from itertools import product

P = 97


def inv(a, p=P):
    a %= p
    assert a != 0, "inverse of 0"
    return pow(a, p - 2, p)


def frac_sum(vals, shift, p=P, mult=None):
    """sum_i m_i / (shift + v_i) mod p; None if a denominator vanishes."""
    mult = mult or [1] * len(vals)
    s = 0
    for v, m in zip(vals, mult):
        d = (shift + v) % p
        if d == 0:
            return None
        s = (s + m * inv(d, p)) % p
    return s


def section(title):
    print("\n" + "=" * 70 + "\n" + title + "\n" + "=" * 70)


# ------------------------------------------------- 1. log-derivative identity
section("1. Equal multisets <=> equal sums of reciprocals (F_97)")
A, B = [2, 3, 3], [3, 2, 3]
print("A =", A, " B =", B, " (same multiset, other order)")
for g in [5, 40]:
    print(f"  gamma={g}: sum 1/(gamma+a) = {frac_sum(A, g)}, sum 1/(gamma+b) = {frac_sum(B, g)}")

# ---------------------------------------------- 2. bad challenges for {1,2} vs {0,3}
section("2. Different multisets agree only at few gamma (F_97)")
A, B = [1, 2], [0, 3]
bad = [g for g in range(P) if frac_sum(A, g) is not None and frac_sum(A, g) == frac_sum(B, g)]
poles = [g for g in range(P) if frac_sum(A, g) is None or frac_sum(B, g) is None]
print("A =", A, " B =", B)
print("gammas where the sums agree:", bad, " (expected -3/2 =", (-3 * inv(2)) % P, ")")
print("gammas where a denominator is 0 (prover aborts):", poles)
g = bad[0]
print(f"  check gamma={g}: 1/{g+1} + 1/{g+2} = {frac_sum(A, g)},  1/{g} + 1/{g+3} = {frac_sum(B, g)}")
print(f"  e.g. gamma=5: {frac_sum(A, 5)} vs {frac_sum(B, 5)}")
A2, B2 = [0, 1], [2, 3]
print("A =", A2, " B =", B2, ": agree at", [g for g in range(P) if frac_sum(A2, g) is not None and frac_sum(A2, g) == frac_sum(B2, g)],
      "(two bad gammas, the maximum 2N-2 for N = 2)")

# -------------------------------------------------- 3. characteristic caveat
section("3. Why the field characteristic must exceed the multiset size")
p5 = 5
for g in range(5):
    print(f"  F_5, gamma={g}: five 1s -> {frac_sum([1]*5, g, p5)}, five 2s -> {frac_sum([2]*5, g, p5)}")
print("  (None = a denominator is 0; otherwise both sums are 0 although the multisets differ)")


# --------------------------------------------- 4. lookups with multiplicities
section("4. Lookup: f = (2,5,2,2) into t = (2,5,7), m = (3,1,0) (F_97)")
f, t, m = [2, 5, 2, 2], [2, 5, 7], [3, 1, 0]
for g in [5, 40]:
    print(f"  gamma={g}: sum 1/(g+f) = {frac_sum(f, g)}, sum m/(g+t) = {frac_sum(t, g, mult=m)}")
fbad = [2, 5, 2, 3]   # 3 is not in the table
print("  f' = (2,5,2,3) with m = (2,1,0):", frac_sum(fbad, 5), "vs", frac_sum(t, 5, mult=[2, 1, 0]), "-> caught")

# ------------------------------------------- 5. running example (OVERVIEW 5.1)
section("5. Running example: x^2 + x + 5 = out, beta = 11, gamma = 5 (F_97)")
n = 4
W = [[17, 3, 9, 12], [17, 3, 3, 17], [17, 9, 12, 17]]
cycles = {"out": [0, 4, 8, 7, 11], "x": [1, 5, 6], "v1": [9, 2], "v2": [10, 3]}
sig = {}
for cyc in cycles.values():
    for a_, b_ in zip(cyc, cyc[1:] + cyc[:1]):
        sig[a_] = b_
sigma = [[sig[j * n + i] for i in range(n)] for j in range(3)]
print("sigma_0, sigma_1, sigma_2 =", sigma)


def gates_of(W):
    qL, qR, qO, qM, qC, PI = [P-1, 0, 1, 1], [0, 0, 1, P-1], [0, P-1, P-1, 0], [0, 1, 0, 0], [0, 0, 0, 5], [17, 0, 0, 0]
    return [(qL[i]*W[0][i] + qR[i]*W[1][i] + qO[i]*W[2][i] + qM[i]*W[0][i]*W[1][i] + qC[i] + PI[i]) % P for i in range(n)]


def logup(W, beta, gamma):
    a = [[(gamma + W[j][i] + beta * (j * n + i)) % P for i in range(n)] for j in range(3)]
    b = [[(gamma + W[j][i] + beta * sigma[j][i]) % P for i in range(n)] for j in range(3)]
    h = [[(inv(a[j][i]) - inv(b[j][i])) % P for i in range(n)] for j in range(3)]
    return a, b, h


beta, gamma = 11, 5
a, b, h = logup(W, beta, gamma)
print("a =", a)
print("b =", b)
print("h =", h)
print("row sums of h0+h1+h2 =", [sum(h[j][i] for j in range(3)) % P for i in range(n)],
      " total =", sum(map(sum, h)) % P)
print("column sums of h_j =", [sum(h[j]) % P for j in range(3)])
print("multiset a == multiset b:", sorted(sum(a, [])) == sorted(sum(b, [])))
j, i = 1, 2
print(f"cell (w1,row2): a = {gamma}+{W[j][i]}+{beta}*{j*n+i} = {a[j][i]}, "
      f"b = {gamma}+{W[j][i]}+{beta}*{sigma[j][i]} = {b[j][i]}, h = {h[j][i]}")
print("  row identity h*a*b - (b-a) =", (h[j][i] * a[j][i] * b[j][i] - (b[j][i] - a[j][i])) % P)
Wc = [[17, 3, 9, 12], [17, 3, 4, 17], [17, 9, 13, 17]]
ac, bc, hc = logup(Wc, beta, gamma)
print("cheater (x=4 in row 2, v2=13 copied as 12): total h =", sum(map(sum, hc)) % P)
print("  multiset a == multiset b:", sorted(sum(ac, [])) == sorted(sum(bc, [])))
print("  every row identity still holds for the cheater's honest h:",
      all((hc[j][i] * ac[j][i] * bc[j][i] - (bc[j][i] - ac[j][i])) % P == 0 for j in range(3) for i in range(n)))
bad_g = [g for g in range(P)
         if all((g + Wc[j][i] + beta * (j * n + i)) % P and (g + Wc[j][i] + beta * sigma[j][i]) % P
                for j in range(3) for i in range(n))
         and sum(map(sum, logup(Wc, beta, g)[2])) % P == 0]
print("  gammas (beta=11) for which the cheater would pass:", bad_g)

# --------------------------------------------------- 6. why labels are needed
section("6. Without labels the check is vacuous; with a known beta a cycle can be forged")
vals_left = sorted(sum(Wc, []))
vals_right = sorted(Wc[s // n][s % n] for j in range(3) for s in sigma[j])
print("value multisets (no labels) equal for the cheater:", vals_left == vals_right)
Wf = [row[:] for row in W]
Wf[0][1], Wf[1][1], Wf[1][2] = 3, 45, 89      # x-cycle cells 1, 5, 6
cl = sorted((Wf[c // n][c % n] + beta * c) % P for c in range(3 * n))
cr = sorted((Wf[c // n][c % n] + beta * sigma[c // n][c % n]) % P for c in range(3 * n))
print("known beta=11, x-cells set to (3,45,89): compressed multisets equal:", cl == cr)
print("  gates of the forged table:", gates_of(Wf), "(only the gate check catches it)")
single = sum(1 for c in range(3 * n) for v in range(P) for bt in range(1, P)
             if (lambda Wx: sorted((Wx[k // n][k % n] + bt * k) % P for k in range(3 * n))
                 == sorted((Wx[k // n][k % n] + bt * sigma[k // n][k % n]) % P for k in range(3 * n)))(
                 [[(v if (jj * n + ii) == c else W[jj][ii]) for ii in range(n)] for jj in range(3)])
             and v != W[c // n][c % n])
print("single-cell changes that keep compressed multisets equal for some beta != 0:", single)

# ------------------------------------------------ 7. the per-row identity
section("7. h*a*b = b - a pins h = 1/a - 1/b unless a = b = 0")
aa, bb = 7, 12
sols = [x for x in range(P) if (x * aa * bb - (bb - aa)) % P == 0]
print(f"a={aa}, b={bb}: solutions h = {sols}, 1/a - 1/b = {(inv(aa) - inv(bb)) % P}")
print("a=b=0: every h satisfies h*0*0 - 0 = 0 -> unconstrained")
print("a=0, b=12: h*0 = 12 has no solution -> honest prover must abort")
