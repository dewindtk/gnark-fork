// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package sumcheck

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"
)

// Zerocheck (HyperPlonk, ePrint 2022/1355, §3.2).
//
// Claim proven: g(T₁(b), …, T_k(b)) = 0 for every b ∈ {0,1}^μ.
//
// The verifier draws τ ∈ F^μ and the parties run a sumcheck for
//
//	Σ_b g(T₁(b), …, T_k(b)) · eq(b, τ) = 0,
//
// whose summand has degree ≤ d+1 in each variable.
//
// Why this is sound: Q(Y) = Σ_b g(T(b))·eq(b, Y) is the multilinear polynomial
// with Q(b) = g(T(b)) on the hypercube. If the claim is false, Q ≠ 0, and a
// multilinear polynomial in μ variables has total degree ≤ μ, so
// Pr_τ[Q(τ) = 0] ≤ μ/|F| (Schwartz–Zippel). Otherwise the sumcheck runs on a
// false claim: error ≤ μ(d+1)/|F|. Total ≤ μ(d+2)/|F|. HyperPlonk Thm 3.2
// states the larger value dμ/|F| + (d+1)μ/|F| (docs/hyperplonk/THEORY.md, H6,
// O1; the μ/|F| term is checked exhaustively in TestModelZerocheckChallenge).

// ZeroResult is what the zerocheck verifier hands to its caller.
type ZeroResult struct {
	Point      []fr.Element // r, the sumcheck challenge point
	FinalClaim fr.Element   // must equal g(T(r)) · eq(r, τ)
	EqAtPoint  fr.Element   // eq(r, τ), computed by the verifier
}

// Check is the last verifier check, given the values T_j(r).
func (z ZeroResult) Check(g Gate, vals []fr.Element) error {
	v := g.Eval(vals)
	v.Mul(&v, &z.EqAtPoint)
	if !v.Equal(&z.FinalClaim) {
		return ErrFinalCheck
	}
	return nil
}

func zeroChallenges(tr Challenger, numVars int) []fr.Element {
	tau := make([]fr.Element, numVars)
	for i := range tau {
		tau[i] = tr.Challenge("zerocheck/tau")
	}
	return tau
}

func withEq(g Gate, k int) Gate {
	return Gate{
		Degree: g.Degree + 1,
		Eval: func(vals []fr.Element) fr.Element {
			v := g.Eval(vals[:k])
			v.Mul(&v, &vals[k])
			return v
		},
	}
}

// ProveZero runs the zerocheck prover. It returns the proof, the challenge
// point r and the values T_j(r).
func ProveZero(tr Challenger, tables []polynomial.MultiLin, g Gate) (Proof, []fr.Element, []fr.Element, error) {
	if len(tables) == 0 {
		return Prove(tr, fr.Element{}, tables, g) // reports the error
	}
	size := len(tables[0])
	numVars := 0
	for 1<<numVars < size {
		numVars++
	}
	tau := zeroChallenges(tr, numVars)

	eq := make(polynomial.MultiLin, 1<<numVars)
	eq[0].SetOne()
	eq.Eq(tau) // eq[b] = eq(τ, b)

	all := make([]polynomial.MultiLin, 0, len(tables)+1)
	all = append(all, tables...)
	all = append(all, eq)

	proof, point, vals, err := Prove(tr, fr.Element{}, all, withEq(g, len(tables)))
	if err != nil {
		return Proof{}, nil, nil, err
	}
	return proof, point, vals[:len(tables)], nil
}

// VerifyZero checks the round messages. The proof is valid only if
// ZeroResult.Check also passes.
func VerifyZero(tr Challenger, numVars, degree int, proof Proof) (ZeroResult, error) {
	tau := zeroChallenges(tr, numVars)
	point, final, err := Verify(tr, fr.Element{}, numVars, degree+1, proof)
	if err != nil {
		return ZeroResult{}, err
	}
	res := ZeroResult{Point: point, FinalClaim: final}
	if numVars == 0 {
		res.EqAtPoint.SetOne()
	} else {
		res.EqAtPoint = polynomial.EvalEq(point, tau)
	}
	return res, nil
}
