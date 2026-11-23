// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Package sumcheck implements the sumcheck protocol and the zerocheck built
// on it, over the bn254 scalar field.
//
// Claim proven: Σ_{b ∈ {0,1}^μ} g(T₁(b), …, T_k(b)) = H, where T₁, …, T_k are
// multilinear polynomials given by their tables on the hypercube and g is a
// polynomial of total degree ≤ d. The summand p(X) = g(T₁(X), …, T_k(X)) then
// has degree ≤ d in each variable.
//
// Protocol (Thaler, "Proofs, Arguments, and Zero-Knowledge", §4.1; HyperPlonk,
// ePrint 2022/1355, §3.1). In round i = 1..μ the prover sends
//
//	sᵢ(X) = Σ_{b ∈ {0,1}^(μ−i)} p(r₁, …, r_{i−1}, X, b),
//
// the verifier checks sᵢ(0) + sᵢ(1) = current claim, draws rᵢ, and the claim
// becomes sᵢ(rᵢ). After round μ the claim must equal p(r₁, …, r_μ); that last
// check needs the values T_j(r) and is left to the caller.
//
// Soundness error ≤ μ·d/|F| (Thaler Prop. 4.1; HyperPlonk Thm 3.1). The proof
// also gives round-by-round soundness with error d/|F| per round: the state
// "claim ≠ true partial sum" is left only if sᵢ(rᵢ) agrees with the true
// polynomial at rᵢ although the two differ (docs/hyperplonk/THEORY.md, H5).
//
// Design choices and their justification:
//
//   - Variable order: X₁ is bound first. This matches gnark-crypto's MultiLin
//     (Fold fixes X₁; table index Σ bᵢ·2^(μ−i)) and WHIR's folding, where
//     Fold(f, α) encodes f̂(α, X₂, …) (ePrint 2024/1586, Claim 4.15).
//   - Message format: sᵢ is sent as its d+1 values at 0, 1, …, d. A polynomial
//     of degree ≤ d is determined by d+1 values, so the degree bound, which
//     the soundness proof needs, holds for every message the verifier can
//     parse; the verifier rejects any other length.
package sumcheck

import (
	"errors"
	"fmt"
	"math/bits"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"

	"github.com/consensys/gnark/backend/hyperplonk/internal/par"
)

// Challenger is the Fiat–Shamir transcript as the protocol sees it.
type Challenger interface {
	AppendElements(label string, xs ...fr.Element)
	Challenge(label string) fr.Element
}

// Gate is the polynomial g. Eval must be a polynomial of total degree at most
// Degree in its inputs; the prover's messages are wrong otherwise.
type Gate struct {
	Degree int
	Eval   func(vals []fr.Element) fr.Element
}

// Proof holds, for each round i, the values sᵢ(0), sᵢ(1), …, sᵢ(d).
type Proof struct {
	Rounds [][]fr.Element
}

var (
	ErrRoundCount  = errors.New("sumcheck: wrong number of rounds")
	ErrRoundLength = errors.New("sumcheck: round message has the wrong number of values")
	ErrRoundSum    = errors.New("sumcheck: s(0) + s(1) differs from the current claim")
	ErrFinalCheck  = errors.New("sumcheck: final claim differs from the value at the challenge point")
)

func bindStatement(tr Challenger, claim fr.Element, numVars, degree int) {
	var mu, d fr.Element
	mu.SetUint64(uint64(numVars))
	d.SetUint64(uint64(degree))
	tr.AppendElements("sumcheck/statement", mu, d, claim)
}

// Prove runs the prover. It returns the proof, the challenge point
// r = (r₁, …, r_μ) and the values T_j(r). The tables are not modified.
func Prove(tr Challenger, claim fr.Element, tables []polynomial.MultiLin, g Gate) (Proof, []fr.Element, []fr.Element, error) {
	if len(tables) == 0 {
		return Proof{}, nil, nil, errors.New("sumcheck: no tables")
	}
	size := len(tables[0])
	if size == 0 || size&(size-1) != 0 {
		return Proof{}, nil, nil, errors.New("sumcheck: table size must be a power of two")
	}
	for _, t := range tables {
		if len(t) != size {
			return Proof{}, nil, nil, errors.New("sumcheck: tables differ in size")
		}
	}
	if g.Degree < 1 || g.Eval == nil {
		return Proof{}, nil, nil, errors.New("sumcheck: gate needs degree ≥ 1 and an evaluation function")
	}
	numVars := bits.TrailingZeros(uint(size))

	work := make([]polynomial.MultiLin, len(tables))
	for j := range tables {
		work[j] = tables[j].Clone()
	}

	bindStatement(tr, claim, numVars, g.Degree)
	rounds, point := ProveRounds(tr, work, g, numVars)

	final := make([]fr.Element, len(work))
	for j := range work {
		final[j] = work[j][0]
	}
	return Proof{Rounds: rounds}, point, final, nil
}

// ProveRounds runs k sumcheck rounds on tables of equal power-of-two size
// ≥ 2^k and returns the round messages and the challenges. The tables are
// folded in place: afterwards tables[j] is T_j(r₁, …, r_k, ·).
//
// It does not bind any statement; the caller is responsible for what the
// transcript contains before the first round. WHIR uses it to interleave
// sumcheck rounds with its own messages (ePrint 2024/1586, Construction 5.1).
func ProveRounds(tr Challenger, tables []polynomial.MultiLin, g Gate, k int) ([][]fr.Element, []fr.Element) {
	rounds := make([][]fr.Element, k)
	point := make([]fr.Element, k)
	for i := range k {
		evals := RoundEvals(tables, g)
		rounds[i] = evals
		tr.AppendElements("sumcheck/round", evals...)
		point[i] = tr.Challenge("sumcheck/r")
		Fold(tables, point[i])
	}
	return rounds, point
}

// parallelThreshold is the least number of table rows per goroutine.
const parallelThreshold = 1 << 10

// RoundEvals returns s(0), s(1), …, s(d) for the round polynomial
// s(X) = Σ_b g(T₁(X, b), …, T_k(X, b)) of the tables in their current state.
// The tables are not modified. The sum over b is split across CPUs.
func RoundEvals(tables []polynomial.MultiLin, g Gate) []fr.Element {
	d := g.Degree
	half := len(tables[0]) / 2
	var mu sync.Mutex
	evals := make([]fr.Element, d+1)
	par.Range(half, parallelThreshold, func(start, end int) {
		vals := make([]fr.Element, len(tables))
		diff := make([]fr.Element, len(tables))
		local := make([]fr.Element, d+1)
		// For each assignment b of the remaining variables, the tables are
		// linear in X₁: T(X, b) = T(0, b) + X·(T(1, b) − T(0, b)). Walk
		// X = 0, 1, …, d by repeated addition and accumulate g.
		for b := start; b < end; b++ {
			for j := range tables {
				vals[j] = tables[j][b]
				diff[j].Sub(&tables[j][b+half], &tables[j][b])
			}
			for t := 0; t <= d; t++ {
				if t > 0 {
					for j := range vals {
						vals[j].Add(&vals[j], &diff[j])
					}
				}
				v := g.Eval(vals)
				local[t].Add(&local[t], &v)
			}
		}
		mu.Lock()
		for t := range evals {
			evals[t].Add(&evals[t], &local[t])
		}
		mu.Unlock()
	})
	return evals
}

// Fold fixes the first variable of every table to r, in place: afterwards
// tables[j] is T_j(r, ·), of half the size.
func Fold(tables []polynomial.MultiLin, r fr.Element) {
	for j := range tables {
		t := tables[j]
		half := len(t) / 2
		par.Range(half, 4*parallelThreshold, func(start, end int) {
			var x fr.Element
			for i := start; i < end; i++ {
				x.Sub(&t[i+half], &t[i])
				x.Mul(&x, &r)
				t[i].Add(&t[i], &x)
			}
		})
		tables[j] = t[:half]
	}
}

// Verify checks the round messages and returns the challenge point r and the
// final claim. The proof is valid only if, in addition, the final claim equals
// g(T₁(r), …, T_k(r)); use CheckFinal once those values are known.
func Verify(tr Challenger, claim fr.Element, numVars, degree int, proof Proof) ([]fr.Element, fr.Element, error) {
	if degree < 1 || numVars < 0 {
		return nil, fr.Element{}, errors.New("sumcheck: invalid parameters")
	}
	if len(proof.Rounds) != numVars {
		return nil, fr.Element{}, ErrRoundCount
	}
	bindStatement(tr, claim, numVars, degree)
	return VerifyRounds(tr, claim, degree, proof.Rounds)
}

// VerifyRounds checks the given round messages against the running claim and
// returns the challenges and the new claim. Counterpart of ProveRounds.
func VerifyRounds(tr Challenger, claim fr.Element, degree int, rounds [][]fr.Element) ([]fr.Element, fr.Element, error) {
	point := make([]fr.Element, len(rounds))
	for i, evals := range rounds {
		if len(evals) != degree+1 {
			return nil, fr.Element{}, fmt.Errorf("round %d: %w", i+1, ErrRoundLength)
		}
		var sum fr.Element
		sum.Add(&evals[0], &evals[1])
		if !sum.Equal(&claim) {
			return nil, fr.Element{}, fmt.Errorf("round %d: %w", i+1, ErrRoundSum)
		}
		tr.AppendElements("sumcheck/round", evals...)
		point[i] = tr.Challenge("sumcheck/r")
		claim = interpolate(evals, point[i])
	}
	return point, claim, nil
}

// CheckFinal is the last verifier check: finalClaim = g(vals), where vals are
// the values T_j(r) obtained from the polynomial oracles.
func CheckFinal(g Gate, vals []fr.Element, finalClaim fr.Element) error {
	v := g.Eval(vals)
	if !v.Equal(&finalClaim) {
		return ErrFinalCheck
	}
	return nil
}

// interpolate returns s(x) for the polynomial s of degree ≤ d with
// s(t) = evals[t], t = 0..d (Lagrange):
//
//	s(x) = Σ_t evals[t] · Π_{j≠t} (x − j) / (t − j)
//
// The nodes 0..d are distinct in F because d < char F.
func interpolate(evals []fr.Element, x fr.Element) fr.Element {
	d := len(evals) - 1
	var res, num, den, term, tmp fr.Element
	for t := 0; t <= d; t++ {
		num.SetOne()
		den.SetOne()
		for j := 0; j <= d; j++ {
			if j == t {
				continue
			}
			tmp.SetInt64(int64(j))
			tmp.Sub(&x, &tmp)
			num.Mul(&num, &tmp)
			tmp.SetInt64(int64(t - j))
			den.Mul(&den, &tmp)
		}
		den.Inverse(&den)
		term.Mul(&evals[t], &num).Mul(&term, &den)
		res.Add(&res, &term)
	}
	return res
}
