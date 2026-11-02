#!/usr/bin/env python3
"""Parameter model for OVERVIEW.md §9 (stdlib only).

Run:  python3 -I docs/hyperplonk-whir/toy/param_model.py

THIS IS A MODEL, NOT A MEASUREMENT. It implements the query rule of SPEC-WHIR §2
(t = ceil(lambda / -log2(1 - delta)), Johnson: 1-delta = 1.05*sqrt(rho); unique
decoding: 1-delta = (1+rho)/2), the round layout rule of the pinned reference
(fold by k while vars >= 2k), and a byte count of what a proof contains. The
authoritative numbers will come from the frozen parameter table (milestone M0b,
gate G0). The script asserts the query counts quoted in SPEC-WHIR §2.
"""
import math

P = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001  # bn254 scalar field
LOG2P = math.log2(P)
ELEM, DIGEST = 32, 32  # bytes


def queries(rho, lam, regime="JB"):
    one_minus_delta = 1.05 * math.sqrt(rho) if regime == "JB" else (1 + rho) / 2
    return math.ceil(lam / -math.log2(one_minus_delta))


def layout(m, k=4):
    """variable counts per round; the last entry is the base case."""
    ms = [m]
    while ms[-1] >= 2 * k:
        ms.append(ms[-1] - k)
    return ms


def opening(m, k=4, log_inv_rho0=3, lam=130, regime="JB", base_checks=True):
    """Model of one WHIR opening (Standard mode). Returns (bytes, per-phase queries, layout)."""
    ms = layout(m, k)
    rounds = len(ms) - 1
    total, ts = 0, []
    for i in range(rounds + (1 if base_checks else 0)):
        lr = log_inv_rho0 + (k - 1) * i  # rate falls by 2^(k-1) per round
        dom = ms[i] - k + lr  # log2 of the domain size
        if dom > 28:  # 2-adicity of the bn254 scalar field
            return None
        t = queries(2.0 ** -lr, lam, regime)
        ts.append(t)
        total += t * (2 ** k * ELEM + DIGEST * dom)  # leaf + Merkle path
    total += rounds * DIGEST  # one root per round
    total += rounds * 2 * ELEM  # one OOD answer + one folded claim per round (approx.)
    total += sum(ms[i] - ms[i + 1] for i in range(rounds)) * 2 * ELEM  # sumcheck (c0, c2)
    total += 2 ** ms[-1] * ELEM + ms[-1] * 2 * ELEM  # base case vector + its sumcheck
    return total, ts, ms


def proof(mu, lam=130, regime="JB", base_checks=True):
    """Whole Standard-mode proof at mu = log2(rows): P, W, H openings plus PIOP data."""
    ms = (mu + 3, mu + 2, mu + 2)
    ops = [opening(m, lam=lam, regime=regime, base_checks=base_checks) for m in ms]
    piop = 2 * DIGEST + mu * 4 * ELEM + 14 * ELEM  # roots of W,H; sumcheck (4 elems/round); 14 evaluations
    return sum(o[0] for o in ops) + piop, ops, piop


def mib(b):
    return b / 2 ** 20


def main():
    print("== query counts (rounds 0..2 then the base-case spot checks) ==")
    jb128 = [queries(2.0 ** -(3 + 3 * i), 128) for i in range(4)]
    jb130 = [queries(2.0 ** -(3 + 3 * i), 130) for i in range(4)]
    ud128 = [queries(2.0 ** -(3 + 3 * i), 128, "UD") for i in range(3)]
    ud130 = [queries(2.0 ** -(3 + 3 * i), 130, "UD") for i in range(3)]
    print("JB lambda=128:", jb128, " lambda=130:", jb130)
    print("UD lambda=128:", ud128, " lambda=130:", ud130)
    assert jb128 == [90, 44, 29, 22] and jb130 == [91, 45, 30, 22]
    assert ud128 == [155, 131, 129] and ud130 == [157, 133, 131]
    print("bits per query, JB: rho=1/2: %.2f  1/4: %.2f  1/8: %.2f  1/16: %.2f"
          % tuple(-math.log2(1.05 * math.sqrt(r)) for r in (.5, .25, .125, .0625)))
    print("mask code (rate 1/16, same regime and lambda): JB %d, UD %d queries per mask tree per round"
          % (queries(1 / 16, 130), queries(1 / 16, 130, "UD")))

    print("\n== one opening, lambda=128, JB (SPEC-WHIR §2 quotes 157 / 200 KiB: WITHOUT base-case checks) ==")
    for m in (16, 20):
        with_b = opening(m, lam=128)[0] / 1024
        no_b = opening(m, lam=128, base_checks=False)[0] / 1024
        print("m=%d  with base-case checks %.1f KiB   without %.1f KiB" % (m, with_b, no_b))

    print("\n== whole proof, Standard mode, lambda=130 ==")
    for mu in (14, 16):
        wb, ops, piop = proof(mu)
        nb = proof(mu, base_checks=False)[0]
        ud = proof(mu, regime="UD")[0]
        print("rows 2^%d: layouts %s" % (mu, [o[2] for o in ops]))
        print("   per opening (KiB): P %.1f  W %.1f  H %.1f   PIOP data %.1f KiB"
              % (ops[0][0] / 1024, ops[1][0] / 1024, ops[2][0] / 1024, piop / 1024))
        print("   JB with base-case checks %.2f MiB | without %.2f MiB | UD with %.2f MiB" % (mib(wb), mib(nb), mib(ud)))
        t = sum(ops[0][1])
        print("   Merkle paths opened: %d (= 3 openings x %d)" % (3 * t, t))
        enc = lambda m: 2 ** m * 8 * ELEM  # codeword = 2^m / rho field elements at rho = 1/8
        print("   encoded P/W/H: %.0f / %.0f / %.0f MiB (sum %.0f MiB)"
              % (mib(enc(mu + 3)), mib(enc(mu + 2)), mib(enc(mu + 2)), mib(enc(mu + 3) + 2 * enc(mu + 2))))

    print("\n== sweep: rate rho_0 = 2^-r at m=18, k=4, lambda=130, JB (model) ==")
    print(" r  opening KiB  encoded W MiB")
    for r in (1, 2, 3, 4, 5, 6):
        o = opening(18, log_inv_rho0=r)
        print(" %d  %10.1f  %12.0f" % (r, o[0] / 1024, 2 ** 18 * 2 ** r * ELEM / 2 ** 20))
    print("\n== sweep: folding factor k at m=18, rho_0=1/8 ==")
    for k in range(2, 7):
        o = opening(18, k=k)
        print(" k=%d  %s" % (k, "-" if o is None else "%.1f KiB, queries %s, layout %s" % (o[0] / 1024, o[1], o[2])))

    print("\n== Fiat-Shamir bound  eps = Q*eps_rbr + 3(Q^2+1)/2^kappa   (ePrint 2023/1071 Cor. 4.3/4.4) ==")
    l3 = math.log2(3)
    print(" success prob 2^-s | max log2 Q for query term (3 openings x 2^-130) | for digest term (kappa=256)")
    for s in (0, 1, 2.43, 10, 20):
        print(" %8.2f         | %6.1f                                         | %6.1f"
              % (s, 130 - s - l3, (256 - s - l3) / 2))

    print("\n== other numbers quoted in the text ==")
    print("log2 p = %.2f ; 3*2^-130 = 2^%.2f" % (LOG2P, math.log2(3) - 130))
    print("LogUp term 9n/p at n=2^16: 2^%.1f" % (math.log2(9 * 2 ** 16) - LOG2P))
    for mu in (4, 5):
        print("ZK mask block 4mu+7 at mu=%d: %d cells (slot has %d)" % (mu, 4 * mu + 7, 2 ** mu))
    print("max m for k=4, rho=1/8 under 2-adicity 28: m-4+3 <= 28 -> m <= %d (mu <= %d)" % (29, 26))
    print("encoded P at MaxLogSize mu=17: %.0f MiB" % mib(2 ** 20 * 8 * ELEM))


if __name__ == "__main__":
    main()
