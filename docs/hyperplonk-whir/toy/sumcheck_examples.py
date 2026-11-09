#!/usr/bin/env python3
"""Toy examples for SUMCHECK.md, recomputed from scratch (stdlib only).

Run:  python3 -I docs/hyperplonk-whir/toy/sumcheck_examples.py
Every number quoted in SUMCHECK.md is printed here. Field F_97 throughout;
the running circuit is the same as OVERVIEW.md (x^2 + x + 5 = out).
"""
import hashlib
from itertools import product

P = 97


def inv(a, p=P):
    a %= p
    assert a != 0, "inverse of 0"
    return pow(a, p - 2, p)


def eq(b, x, p=P):
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
    h = len(table) // 2
    return [((1 - r) * table[j] + r * table[h + j]) % p for j in range(h)]


def interp(evals, r, p=P):
    """Evaluate at r the polynomial of degree len(evals)-1 with values evals[t] at t = 0..d."""
    d = len(evals) - 1
    out = 0
    for i in range(d + 1):
        num, den = 1, 1
        for j in range(d + 1):
            if j != i:
                num = num * (r - j) % p
                den = den * (i - j) % p
        out = (out + evals[i] * num * inv(den, p)) % p
    return out


def round_msg(cols, comp, d, p=P):
    """Prover's round message: s(t) for t = 0..d, summing comp over the second half-cube."""
    h = len(cols[0]) // 2
    msg = []
    for t in range(d + 1):
        s = 0
        for j in range(h):
            vals = [((1 - t) * c[j] + t * c[h + j]) % p for c in cols]
            s = (s + comp(vals)) % p
        msg.append(s)
    return msg


def sumcheck(cols, comp, d, challenges, claim, verbose=True, p=P):
    """Run prover and verifier together. Returns (accepted, final claim, rho, final column values)."""
    cols = [c[:] for c in cols]
    for i, r in enumerate(challenges, 1):
        msg = round_msg(cols, comp, d, p)
        ok = (msg[0] + msg[1]) % p == claim
        new_claim = interp(msg, r, p)
        if verbose:
            sent = [msg[0]] + msg[2:]
            print(f"  round {i}: s(0..{d}) = {msg}  [sent: s(0), s(2..d) = {sent}]"
                  f"  s(0)+s(1) = {(msg[0] + msg[1]) % p} vs claim {claim} {'ok' if ok else 'FAIL (textbook round check)'}"
                  f"  r = {r} -> claim {new_claim}")
        if not ok:
            return False, None, None, None
        claim = new_claim
        cols = [fold(c, r, p) for c in cols]
    finals = [c[0] for c in cols]
    return comp(finals) == claim, claim, challenges, finals


def section(title):
    print("\n" + "=" * 70 + "\n" + title + "\n" + "=" * 70)


# ------------------------------------------------------------ 1. hand example
section("1. Sumcheck for the product of two tables, mu = 2 (F_97)")
A = [1, 2, 3, 4]
B = [2, 0, 1, 3]
S = sum(a * b for a, b in zip(A, B)) % P
print("A =", A, " B =", B, " S = sum A*B =", S)
prod2 = lambda v: v[0] * v[1] % P
At = lambda t: [((1 - t) * A[j] + t * A[2 + j]) % P for j in range(2)]
Bt = lambda t: [((1 - t) * B[j] + t * B[2 + j]) % P for j in range(2)]
print("A(t,.) at t=0,1,2:", At(0), At(1), At(2), "  B(t,.):", Bt(0), Bt(1), Bt(2))
print("fold A at 5:", fold(A, 5), "then at 7:", fold(fold(A, 5), 7), "; fold B at 5:", fold(B, 5))
ok, fc, rho, fin = sumcheck([A, B], prod2, 2, [5, 7], S)
print("final: A~(5,7) =", fin[0], " B~(5,7) =", fin[1], " product =", prod2(fin), " claim =", fc, "->", ok)
assert ok and fin[0] == mle(A, [5, 7]) and fin[1] == mle(B, [5, 7])
# round-1 polynomial in coefficient form: s1(t) = c0 + c1 t + c2 t^2
e = round_msg([A, B], prod2, 2)
c0 = e[0]; c2 = (e[2] - 2 * e[1] + e[0]) * inv(2) % P; c1 = (e[1] - c0 - c2) % P
print(f"s1(t) = {c0} + {c1} t + {c2} t^2  (check s1(5) = {(c0 + 5 * c1 + 25 * c2) % P})")

# ------------------------------------------------------- 2. folding the product is wrong
section("2. Pitfall: the MLE of a product is not the product of MLEs")
AB = [a * b % P for a, b in zip(A, B)]
print("table A*B =", AB, "; its MLE at (5,7) =", mle(AB, [5, 7]),
      " but A~(5,7)*B~(5,7) =", mle(A, [5, 7]) * mle(B, [5, 7]) % P)
print("folding A*B at r1=5 gives", fold(AB, 5), "; summing the halves at t=5 instead gives s1(5) =",
      interp(round_msg([A, B], prod2, 2), 5))
print("a prover that folds A*B is an honest prover for (A*B)~: every round check passes")
okw, fcw, _, finw = sumcheck([AB], lambda v: v[0], 1, [5, 7], S)
print("  its final claim", fcw, "vs the verifier's A~(rho)*B~(rho) =", mle(A, [5, 7]) * mle(B, [5, 7]) % P, "-> REJECT")

# ------------------------------------------------------- 3. lucky challenges
section("3. A false claim: how many challenges let the cheater escape?")
Sfalse = (S + 1) % P
true1 = round_msg([A, B], prod2, 2)
# best cheater: a degree-2 s1' with s1'(0)+s1'(1) = S+1 that agrees with s1 at two points.
# s1'(t) = s1(t) + e(t) with e(0)+e(1) = 1 and e of degree <= 2 with two roots: e(t) = c (t-a)(t-b)
best = 0
best_e = None
for a_ in range(P):
    for b_ in range(a_, P):
        val = ((0 - a_) * (0 - b_) + (1 - a_) * (1 - b_)) % P
        if val == 0:
            continue
        c = inv(val)
        roots = {a_, b_}
        if len(roots) > best:
            best, best_e = len(roots), (c, a_, b_)
c, a_, b_ = best_e
print(f"best error polynomial e(t) = {c}(t-{a_})(t-{b_}) has {best} roots: the cheater survives round 1 w.p. {best}/97")
lucky = [r for r in range(P) if (c * (r - a_) * (r - b_)) % P == 0]
print("lucky r1 values:", lucky)
# exhaustive check over all deg<=2 polynomials passing the round-1 check: max agreement with s1
mx = 0
for e0 in range(P):
    e1 = (1 - e0) % P
    for e2 in range(P):
        err = [e0, e1, e2]
        z = sum(1 for r in range(P) if interp(err, r) == 0)
        mx = max(mx, z)
print("exhaustive over all 97^2 passing lies: max number of lucky r1 =", mx, "(= d)")
# empirical probability over all (r1, r2) for the 'push the lie' strategy
wins = 0
for r1 in range(P):
    # round 1: cheater sends s1' = s1 + e1 with e1(t) = c(t-a)(t-b)
    e1r = c * (r1 - a_) * (r1 - b_) % P
    if e1r == 0:
        wins += P  # lie disappeared; every r2 passes
        continue
    # round 2: claim is s1(r1)+e1r but truth is s1(r1); cheater adds e2 with e2(0)+e2(1)=e1r, two roots
    # e2(t) = e1r * c * (t-a)(t-b): roots a, b
    for r2 in range(P):
        if (r2 - a_) * (r2 - b_) % P == 0:
            wins += 1
print(f"over all {P*P} challenge pairs the cheater wins {wins} times: rate {wins/P/P:.4f}"
      f"  vs bound mu*d/|F| = {2*2/P:.4f}")

# ---------------------------------------------- 4. predictable challenges
section("4. Predictable challenges: a perfect forgery")
r1, r2 = 5, 7
# cheater claims S' = S+1. It knows r1: pick a line through (r1, s1(r1)) with s'(0)+s'(1)=S'
# a degree-1 polynomial l(t) = u + v t: u + (u+v) = S', u + v r1 = s1(r1)
target = interp(true1, r1)
# 2u + v = S', u + v r1 = target -> v (r1 - 1/2 *... ) solve linear system
det = (2 * r1 - 1) % P
u = (Sfalse * r1 - target) * inv(det) % P
v = (2 * target - Sfalse) * inv(det) % P
forged = [u, (u + v) % P, (u + 2 * v) % P]
print(f"cheater claims S' = {Sfalse}; knowing r1 = {r1} it sends s1'(t) = {u} + {v} t")
print(f"  s1'(0)+s1'(1) = {(forged[0] + forged[1]) % P}, s1'(r1) = {interp(forged, r1)} = true s1(r1) = {target}")
ok2, *_ = sumcheck([fold(A, r1), fold(B, r1)], prod2, 2, [r2], target, verbose=False)
print("  from round 2 on the prover is honest; final check passes:", ok2)

# --------------------------------------------- 5. zerocheck on the running circuit
section("5a. Bit order and the plain-sum pitfall (numbers quoted in SUMCHECK.md s.2, s.9)")
T = [3, 1, 4, 1]
print("T = (3,1,4,1): T~(2,3) MSB-first =", mle(T, [2, 3]), "; LSB-first reading gives T~(3,2) =", mle(T, [3, 2]))
fz = [1, P - 1, 0, 0]
print("f = (1,-1,0,0): plain sum", sum(fz) % P, "; sum eq((3,10),x) f(x) =",
      sum(eq(bits(i, 2), [3, 10]) * fz[i] for i in range(4)) % P)

section("5. Zerocheck of the gate on the running circuit (mu = 2, degree 4)")
n, mu = 4, 2
qL = [P - 1, 0, 1, 1]; qR = [0, 0, 1, P - 1]; qO = [0, P - 1, P - 1, 0]
qM = [0, 1, 0, 0]; qC = [0, 0, 0, 5]
w0 = [17, 3, 9, 12]; w1 = [17, 3, 3, 17]; w2 = [17, 9, 12, 17]
PI = [17, 0, 0, 0]
gate = lambda v: (v[0] * v[5] + v[1] * v[6] + v[2] * v[7] + v[3] * v[5] * v[6] + v[4] + v[8]) % P
fvals = [gate([qL[i], qR[i], qO[i], qM[i], qC[i], w0[i], w1[i], w2[i], PI[i]]) for i in range(n)]
print("gate values on the rows:", fvals)
r = [3, 10]
E = [eq(bits(i, mu), r) for i in range(n)]
print("eq(r, x) table for r = (3,10):", E, " sum =", sum(E) % P)
zc = lambda v: v[9] * gate(v[:9]) % P
cols = [qL, qR, qO, qM, qC, w0, w1, w2, PI, E]
ok, fc, rho, fin = sumcheck(cols, zc, 4, [20, 33], 0)
print("final column values at rho = (20,33):", fin[:9], " eq(r,rho) =", fin[9], " eq formula:", eq(r, [20, 33]))
print("verifier recomputes eq(r,rho)*f(rho) =", zc(fin), " final claim =", fc, "->", ok)
# bad witness: v1 = 10 instead of 9 in row 1 (O column) and propagate nothing -> row 1 fails
w2b = [17, 10, 12, 17]
fb = [gate([qL[i], qR[i], qO[i], qM[i], qC[i], w0[i], w1[i], w2b[i], PI[i]]) for i in range(n)]
print("bad witness (w2[1] = 10): gate values", fb, "; sum eq(r,x) f(x) =",
      sum(E[i] * fb[i] for i in range(n)) % P, "!= 0 -> the honest sumcheck on claim 0 fails at round 1:")
sumcheck([qL, qR, qO, qM, qC, w0, w1, w2b, PI, E], zc, 4, [20, 33], 0)
# a bad r that misses the error: r with eq(r, <01>) = 0 i.e. r1 = 1 or r2 = 0
print("eq(r, 01) vanishes when r1 = 1 or r2 = 0: e.g. r = (1, 5) gives sum",
      sum(eq(bits(i, 2), [1, 5]) * fb[i] for i in range(n)) % P, "(the bad row is invisible)")
miss = sum(1 for a in range(P) for b in range(P)
           if sum(eq(bits(i, 2), [a, b]) * fb[i] for i in range(n)) % P == 0)
print(f"number of r in F_97^2 that miss the bad row: {miss} of {P*P}, catch {P*P - miss} (rate {miss/P/P:.4f}; bound mu/|F| = {2/P:.4f})")

# --------------------------------------------- 6. the full batched sumcheck
section("6. The full hyperplonk sumcheck on the running example (degree 4)")
cycles = {"out (= wire 0)": [0, 4, 8, 7, 11], "x": [1, 5, 6], "v1": [9, 2], "v2": [10, 3]}  # toy_examples.py s.4
sig = {}
for cyc in cycles.values():
    for a_, b_ in zip(cyc, cyc[1:] + cyc[:1]):
        sig[a_] = b_
sigma = [[sig[j * n + i] for i in range(n)] for j in range(3)]
print("sigma_0, sigma_1, sigma_2 =", sigma)
beta, gamma = 11, 5
W = [w0, w1, w2]
ID = [[j * n + i for i in range(n)] for j in range(3)]
H = []
for j in range(3):
    hj = []
    for i in range(n):
        a = (gamma + W[j][i] + beta * ID[j][i]) % P
        b = (gamma + W[j][i] + beta * sigma[j][i]) % P
        hj.append((inv(a) - inv(b)) % P)
    H.append(hj)
print("h_0, h_1, h_2 =", H, " sum =", sum(map(sum, H)) % P)
alpha = 2


def big_F(v):
    q = v[0:5]; s = v[5:8]; w = v[8:11]; h = v[11:14]; ids = v[14:17]; pi = v[17]; e = v[18]
    f = (q[0] * w[0] + q[1] * w[1] + q[2] * w[2] + q[3] * w[0] * w[1] + q[4] + pi) % P
    zsum = f
    for j in range(3):
        a = (gamma + w[j] + beta * ids[j]) % P
        b = (gamma + w[j] + beta * s[j]) % P
        zj = (h[j] * a * b - (b - a)) % P
        zsum = (zsum + pow(alpha, j + 1, P) * zj) % P
    return (e * zsum + pow(alpha, 4, P) * (h[0] + h[1] + h[2])) % P


cols6 = [qL, qR, qO, qM, qC] + sigma + W + H + ID + [PI, E]
print(f"alpha = {alpha}, r = {r}; claim 0; degree 4; challenges rho = (20, 33)")
ok, fc, rho, fin = sumcheck(cols6, big_F, 4, [20, 33], 0)
names = ["qL", "qR", "qO", "qM", "qC", "s0", "s1", "s2", "w0", "w1", "w2", "h0", "h1", "h2"]
print("the 14 evaluations at rho:", dict(zip(names, fin[:14])))
idr = [(j * n + 2 * 20 + 33) % P for j in range(3)]
pir = PI[0] * eq([0, 0], [20, 33]) % P
print("verifier computes id_j(rho) = j*n + 2*rho1 + rho2 =", idr, "(table fold:", fin[14:17], ")")
print("  PI(rho) = 17*(1-rho1)(1-rho2) =", pir, "(table fold:", fin[17], ")  eq(r,rho) =", eq(r, [20, 33]))
check = big_F(fin[:14] + idr + [pir, eq(r, [20, 33])])
print("  recomputed F(rho) =", check, " final claim =", fc, "->", check == fc)
# the cheating witness of OVERVIEW 5.3: every gate holds, copies broken
Wc = [[17, 3, 9, 12], [17, 3, 4, 17], [17, 9, 13, 17]]
Hc = [[(inv((gamma + Wc[j][i] + beta * ID[j][i]) % P) - inv((gamma + Wc[j][i] + beta * sigma[j][i]) % P)) % P
       for i in range(n)] for j in range(3)]
tot = sum(big_F([c[i] for c in [qL, qR, qO, qM, qC] + sigma + Wc + Hc + ID + [PI, E]]) for i in range(n)) % P
hsum = sum(map(sum, Hc)) % P
print("copy-breaking cheater: sum h =", hsum, "; sum over the cube of F =", tot, "= alpha^4 *", hsum, "=",
      pow(alpha, 4, P) * hsum % P, "-> claim 0 is false")

# --------------------------------------------- 7. Fiat-Shamir
section("7. Fiat-Shamir: challenges from a hash (toy reduction mod 97)")


def chal(state, label, data):
    hsh = hashlib.sha256(state + label.encode() + bytes(data)).digest()
    return hsh, int.from_bytes(hsh, "big") % P


# toy only: binds S as a caller would, no length prefixes; not the FS-GRAMMAR of SPEC-PIOP s.3
st = hashlib.sha256(b"toy-sumcheck").digest()
st = hashlib.sha256(st + b"claim" + bytes([S])).digest()
msgs = []
cols_fs = [A, B]
claim = S
rs = []
for i in range(2):
    m = round_msg(cols_fs, prod2, 2)
    st, ri = chal(st, f"sc/round/{i+1}", [m[0]] + m[2:])
    rs.append(ri)
    claim = interp(m, ri)
    cols_fs = [fold(c, ri) for c in cols_fs]
    print(f"  round {i+1}: message s(0), s(2) = {[m[0], m[2]]} -> r{i+1} = H(state || message) mod 97 = {ri}")
print("  final check:", prod2([cols_fs[0][0], cols_fs[1][0]]) == claim, " (rho =", rs, ")")

# unbound claim: absorb only s1(0), s1(2); pick S' after seeing r1
s0f, s2f, r1f = 3, 4, 10
target = interp(true1, r1f)
Sf = next(x for x in range(P) if interp([s0f, (x - s0f) % P, s2f], r1f) == target)
print(f"unbound claim: cheater fixes s1(0) = {s0f}, s1(2) = {s2f}, gets r1 = {r1f}, then declares S' = {Sf}"
      f" (true S = {S}); s1'(r1) = {interp([s0f, (Sf - s0f) % P, s2f], r1f)} = true s1(r1) = {target}")
okf, *_ = sumcheck([fold(A, r1f), fold(B, r1f)], prod2, 2, [7], target, verbose=False)
print("  honest from round 2 on; final check passes:", okf)

# --------------------------------------------- 8. zero knowledge
section("8. Zero knowledge: what the messages leak, and the masks")
secret = 42
T = [secret, 10, 20, 30]
m = round_msg([T], lambda v: v[0], 1)
print(f"table (secret, 10, 20, 30): round-1 message s(0) = {m[0]} = secret + 10 -> secret = {(m[0] - 10) % P}")
# witness mask: w* = w + c X1 (1-X1) changes round 1 only, and raises the degree
c_a, c_b = 40, 23


def s1_masked(t, ca, cb):
    a = [((1 - t) * A[j] + t * A[2 + j] + ca * t * (1 - t)) % P for j in range(2)]
    b = [((1 - t) * B[j] + t * B[2 + j] + cb * t * (1 - t)) % P for j in range(2)]
    return sum(x * y for x, y in zip(a, b)) % P


me = [s1_masked(t, c_a, c_b) for t in range(5)]
print("masked A*, B* (c = 40, 23): round-1 s1 at t=0..4 =", me,
      " s1(0)+s1(1) =", (me[0] + me[1]) % P, "(still", S, ")")
print("  unmasked s1 at t=0..4 =", [interp(true1, t) for t in range(5)],
      "-> degree rose from 2 to 4 (=", 2, "+ 2 per masked factor)")
# degree check: 5 points determine deg<=4; check interpolation of deg-2 fit fails
print("  does a degree-2 polynomial fit the masked values?", interp(me[:3], 3) == me[3])
# Libra: add rho_g * g with g = g0 + g1(x1) + g2(x2), g_i(0) = 0
g0, g1c, g2c = 7, [3, 5], [11, 2]  # g1(t) = 3t + 5t^2, g2(t) = 11t + 2t^2
g1 = lambda t: (g1c[0] * t + g1c[1] * t * t) % P
g2 = lambda t: (g2c[0] * t + g2c[1] * t * t) % P
G = (4 * g0 + 2 * g1(1) + 2 * g2(1)) % P
print(f"Libra g = {g0} + g1(x1) + g2(x2), G = sum over cube = 4*g0 + 2*g1(1) + 2*g2(1) = {G}")
rho_g = 3
gt = [g0 + g1(i) + g2(j) for i, j in product([0, 1], repeat=2)]
gtab = [x % P for x in gt]
comb = lambda v: (v[0] * v[1] + rho_g * v[2]) % P
print(f"rho_g = {rho_g}: sumcheck on A*B + rho_g*g with claim S + rho_g*G = {(S + rho_g * G) % P}")
# g is not multilinear in general but here deg g_i = 2; use the closed form per round
claim = (S + rho_g * G) % P
r1, r2 = 5, 7
s1 = [(interp(true1, t) + rho_g * (2 * (g0 + g1(t)) + g2(1))) % P for t in range(3)]
print("  round 1 message (degree 2):", s1, " s(0)+s(1) =", (s1[0] + s1[1]) % P)
cl = interp(s1, r1)
s2true = round_msg([fold(A, r1), fold(B, r1)], prod2, 2)
s2 = [(s2true[t] + rho_g * (g0 + g1(r1) + g2(t))) % P for t in range(3)]
print("  round 2 message:", s2, " s(0)+s(1) =", (s2[0] + s2[1]) % P, " vs claim", cl)
cl2 = interp(s2, r2)
fin = (mle(A, [r1, r2]) * mle(B, [r1, r2]) + rho_g * (g0 + g1(r1) + g2(r2))) % P
print("  final: A~B~(rho) + rho_g*g(rho) =", fin, " claim", cl2, "->", fin == cl2)
print("  without the mask, round 1 would have sent", [true1[0], true1[2]], "; with it,", [s1[0], s1[2]])
