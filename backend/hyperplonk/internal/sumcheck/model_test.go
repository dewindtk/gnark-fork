// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package sumcheck

// Exhaustive checks of the theorems the package relies on, over small prime
// fields where every prover strategy and every challenge can be enumerated.
// These tests do not exercise the bn254 code; they check the theory
// (docs/hyperplonk/THEORY.md, claims H5, H6, O1).

import (
	"math/rand"
	"testing"
)

type smallField struct{ p uint64 }

func (f smallField) add(a, b uint64) uint64 { return (a + b) % f.p }
func (f smallField) sub(a, b uint64) uint64 { return (a + f.p - b) % f.p }
func (f smallField) mul(a, b uint64) uint64 { return a * b % f.p }
func (f smallField) inv(a uint64) uint64 {
	r, e := uint64(1), f.p-2
	for b := a; e > 0; e >>= 1 {
		if e&1 == 1 {
			r = f.mul(r, b)
		}
		b = f.mul(b, b)
	}
	return r
}

// mle evaluates at x the multilinear extension of table (index Σ bᵢ·2^(μ−i),
// X₁ first, as in gnark-crypto's MultiLin).
func (f smallField) mle(table []uint64, x []uint64) uint64 {
	cur := append([]uint64(nil), table...)
	for _, xi := range x {
		half := len(cur) / 2
		for i := range half {
			cur[i] = f.add(cur[i], f.mul(xi, f.sub(cur[i+half], cur[i])))
		}
		cur = cur[:half]
	}
	return cur[0]
}

// interp evaluates at x the polynomial of degree ≤ d with values evals at 0..d.
func (f smallField) interp(evals []uint64, x uint64) uint64 {
	var res uint64
	for t := range evals {
		num, den := uint64(1), uint64(1)
		for j := range evals {
			if j == t {
				continue
			}
			num = f.mul(num, f.sub(x, uint64(j)))
			den = f.mul(den, f.sub(uint64(t), uint64(j)))
		}
		res = f.add(res, f.mul(evals[t], f.mul(num, f.inv(den))))
	}
	return res
}

// model is the sumcheck for p(X) = Π_j T_j(X), individual degree d = len(tables).
type model struct {
	f      smallField
	mu, d  int
	tables [][]uint64
	memo   map[[3]uint64]uint64
}

func (m *model) p(x []uint64) uint64 {
	v := uint64(1)
	for _, t := range m.tables {
		v = m.f.mul(v, m.f.mle(t, x))
	}
	return v
}

// trueSum is Σ_b p(prefix, b).
func (m *model) trueSum(prefix []uint64) uint64 {
	rest := m.mu - len(prefix)
	x := append(append([]uint64(nil), prefix...), make([]uint64, rest)...)
	var s uint64
	for b := 0; b < 1<<rest; b++ {
		for i := range rest {
			x[len(prefix)+i] = uint64(b>>(rest-1-i)) & 1
		}
		s = m.f.add(s, m.p(x))
	}
	return s
}

// best returns the number of challenge suffixes (out of p^(μ−i)) for which
// the verifier accepts, maximised over all prover strategies, when the current
// claim after challenges prefix is c.
func (m *model) best(prefix []uint64, c uint64) uint64 {
	i := len(prefix)
	if i == m.mu {
		if c == m.p(prefix) {
			return 1
		}
		return 0
	}
	var code uint64
	for _, x := range prefix {
		code = code*m.f.p + x
	}
	key := [3]uint64{uint64(i), code, c}
	if v, ok := m.memo[key]; ok {
		return v
	}
	total := uint64(1)
	for range m.mu - i {
		total *= m.f.p
	}
	var bestCount uint64
	if c == m.trueSum(prefix) {
		bestCount = total // the honest prover is always accepted
	} else {
		// Enumerate every message: a polynomial s of degree ≤ d with
		// s(0) + s(1) = c, given by (s(0), s(2), …, s(d)).
		evals := make([]uint64, m.d+1)
		free := make([]uint64, m.d)
		for {
			evals[0] = free[0]
			evals[1] = m.f.sub(c, free[0])
			copy(evals[2:], free[1:])
			var count uint64
			for alpha := uint64(0); alpha < m.f.p; alpha++ {
				count += m.best(append(prefix, alpha), m.f.interp(evals, alpha))
			}
			if count > bestCount {
				bestCount = count
			}
			k := 0
			for ; k < len(free); k++ {
				free[k]++
				if free[k] < m.f.p {
					break
				}
				free[k] = 0
			}
			if k == len(free) {
				break
			}
		}
	}
	m.memo[key] = bestCount
	return bestCount
}

// Claim H5 (Thaler Prop. 4.1, HyperPlonk Thm 3.1): for a false claim, no
// prover is accepted with probability above μ·d/|F|. Checked exactly.
func TestModelSumcheckSoundness(t *testing.T) {
	for _, tc := range []struct {
		p     uint64
		mu, d int
	}{{7, 2, 2}, {11, 3, 2}, {7, 2, 3}, {13, 2, 1}} {
		rng := rand.New(rand.NewSource(int64(tc.p)*100 + int64(tc.mu)*10 + int64(tc.d)))
		f := smallField{tc.p}
		m := &model{f: f, mu: tc.mu, d: tc.d, memo: map[[3]uint64]uint64{}}
		for range tc.d {
			tab := make([]uint64, 1<<tc.mu)
			for i := range tab {
				tab[i] = uint64(rng.Intn(int(tc.p)))
			}
			m.tables = append(m.tables, tab)
		}
		total := uint64(1)
		for range tc.mu {
			total *= tc.p
		}
		// bound: accepted suffixes ≤ μ·d·p^(μ−1)
		bound := uint64(tc.mu*tc.d) * total / tc.p
		truth := m.trueSum(nil)
		var worst uint64
		for c := uint64(0); c < tc.p; c++ {
			if c == truth {
				if m.best(nil, c) != total {
					t.Fatalf("p=%d: honest claim not accepted with probability 1", tc.p)
				}
				continue
			}
			if got := m.best(nil, c); got > worst {
				worst = got
			}
		}
		if worst > bound {
			t.Fatalf("p=%d μ=%d d=%d: best cheater accepted on %d/%d challenges, bound %d", tc.p, tc.mu, tc.d, worst, total, bound)
		}
		if worst == 0 {
			t.Fatalf("p=%d μ=%d d=%d: no cheater ever accepted; the test would be vacuous", tc.p, tc.mu, tc.d)
		}
		t.Logf("p=%d μ=%d d=%d: best cheater %d/%d = %.4f, bound μd/p = %.4f", tc.p, tc.mu, tc.d, worst, total, float64(worst)/float64(total), float64(tc.mu*tc.d)/float64(tc.p))
	}
}

// First term of the zerocheck error (claim O1): for every table that is not
// identically zero, Q(τ) = Σ_b table[b]·eq(b, τ) vanishes for at most
// μ·p^(μ−1) of the p^μ challenges τ. Checked for every table.
func TestModelZerocheckChallenge(t *testing.T) {
	for _, tc := range []struct {
		p  uint64
		mu int
	}{{5, 2}, {3, 3}, {7, 2}} {
		f := smallField{tc.p}
		size := 1 << tc.mu
		total := uint64(1)
		for range tc.mu {
			total *= tc.p
		}
		bound := uint64(tc.mu) * total / tc.p
		table := make([]uint64, size)
		tau := make([]uint64, tc.mu)
		var worst uint64
		for {
			// next table
			k := 0
			for ; k < size; k++ {
				table[k]++
				if table[k] < tc.p {
					break
				}
				table[k] = 0
			}
			if k == size {
				break // wrapped around to the zero table: all others visited
			}
			var zeros uint64
			for code := uint64(0); code < total; code++ {
				c := code
				for i := range tau {
					tau[i] = c % tc.p
					c /= tc.p
				}
				// Q(τ) is the multilinear extension of table at τ
				if f.mle(table, tau) == 0 {
					zeros++
				}
			}
			if zeros > worst {
				worst = zeros
			}
		}
		if worst > bound {
			t.Fatalf("p=%d μ=%d: a non-zero table vanishes at %d/%d challenges, bound %d", tc.p, tc.mu, worst, total, bound)
		}
		t.Logf("p=%d μ=%d: worst non-zero table vanishes at %d/%d challenges, bound μ·p^(μ−1) = %d", tc.p, tc.mu, worst, total, bound)
	}
}
