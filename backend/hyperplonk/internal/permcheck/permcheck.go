// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Package permcheck implements the permutation check for the wiring identity
// (HyperPlonk, ePrint 2022/1355, §3.4–3.5), with the product equality proven
// by a layered sumcheck (package grandprod) instead of a committed product
// polynomial.
//
// Claim proven: w(x) = w(σ(x)) for every x ∈ {0,1}^μ, where σ is a fixed
// permutation of the hypercube, given by the preprocessed multilinear
// polynomial s_σ with s_σ(x) = [σ(x)]. Here [x] is the index of x as a field
// element.
//
// Protocol:
//
//  1. The claim is the multiset equality {([x], w(x))} = {([σ(x)], w(x))}
//     (§3.5, Thm 3.6).
//  2. The verifier sends β; pairs become single values:
//     f̂ = s_id + β·w and ĝ = s_σ + β·w (§3.4, Thm 3.5).
//  3. The verifier sends γ; the multisets {f̂(x)}, {ĝ(x)} are equal iff
//     Π_x (γ + f̂(x)) = Π_x (γ + ĝ(x)), except with small probability
//     (§3.4, proof of Thm 3.4: two different monic polynomials of degree 2^μ
//     agree at a random point with probability at most 2^μ/|F|).
//  4. The two products are proven equal by grandprod, which ends with one
//     claim on each of the tables γ + f̂ and γ + ĝ at a common point q.
//  5. Both tables are linear in w and s_σ, so the two claims follow from the
//     values w(q) and s_σ(q), which the prover sends and the caller verifies
//     against the commitments.
//
// Soundness error (docs/hyperplonk/THEORY.md, H8, H9, S6, S17):
// 2^μ/|F| (step 2) + 2^μ/|F| (step 3) + the error of grandprod.
//
// Differences from the previous version of this package: no product
// polynomial is committed, and no division occurs, so the corner cases of the
// rational product check (THEORY O4, O5) do not arise.
//
// s_id is not an oracle: s_id(x) = [x] = Σᵢ xᵢ·2^(μ−i) is a linear polynomial,
// hence equal to its own multilinear extension, and the verifier evaluates it
// directly (S6, TestIdentityLabel).
package permcheck

import (
	"errors"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"

	"github.com/consensys/gnark/backend/hyperplonk/internal/grandprod"
	"github.com/consensys/gnark/backend/hyperplonk/internal/par"
	"github.com/consensys/gnark/backend/hyperplonk/internal/sumcheck"
)

// ErrLinearCheck is returned when the sent values w(q), s_σ(q) do not explain
// the final claims of the product argument.
var ErrLinearCheck = errors.New("permcheck: w(q), s_σ(q) inconsistent with the product argument")

// Oracle names the polynomial an evaluation claim is about.
type Oracle int

const (
	OracleW     Oracle = iota // the wire polynomial w, μ variables
	OracleSigma               // the preprocessed s_σ, μ variables
)

// Claim states Oracle(Point) = Value; the caller must verify each one.
type Claim struct {
	Oracle Oracle
	Point  []fr.Element
	Value  fr.Element
}

// Proof is the product-equality proof and the two values w(q), s_σ(q).
type Proof struct {
	Prod    grandprod.Proof
	WAt     fr.Element
	SigmaAt fr.Element
}

// IdentityLabel returns s_id(x) = Σᵢ xᵢ·2^(μ−i). On the hypercube this is the
// table index of x (gnark-crypto MultiLin layout).
func IdentityLabel(x []fr.Element) fr.Element {
	var res fr.Element
	for i := range x {
		res.Double(&res).Add(&res, &x[i])
	}
	return res
}

// SigmaTable returns the table of s_σ from the permutation: entry i is σ(i)
// as a field element. perm must be a permutation of 0..len-1.
func SigmaTable(perm []int) (polynomial.MultiLin, error) {
	seen := make([]bool, len(perm))
	t := make(polynomial.MultiLin, len(perm))
	for i, p := range perm {
		if p < 0 || p >= len(perm) || seen[p] {
			return nil, errors.New("permcheck: not a permutation")
		}
		seen[p] = true
		t[i].SetUint64(uint64(p))
	}
	return t, nil
}

// Prove runs the prover. The commitments to w and s_σ must have been absorbed
// into tr before the call: β and γ must depend on them.
func Prove(tr sumcheck.Challenger, w, sigma polynomial.MultiLin) (Proof, error) {
	n := len(w)
	if n == 0 || n&(n-1) != 0 || len(sigma) != n {
		return Proof{}, errors.New("permcheck: tables must have equal power-of-two size")
	}
	beta := tr.Challenge("permcheck/beta")
	gamma := tr.Challenge("permcheck/gamma")

	num := make(polynomial.MultiLin, n)
	den := make(polynomial.MultiLin, n)
	par.Range(n, 1<<12, func(start, end int) {
		var bw, id fr.Element
		for i := start; i < end; i++ {
			bw.Mul(&beta, &w[i]).Add(&bw, &gamma)
			id.SetUint64(uint64(i))
			num[i].Add(&bw, &id)
			den[i].Add(&bw, &sigma[i])
		}
	})
	prod, q, _, err := grandprod.Prove(tr, num, den)
	if err != nil {
		return Proof{}, err
	}
	p := Proof{Prod: prod, WAt: w.Evaluate(q, nil), SigmaAt: sigma.Evaluate(q, nil)}
	tr.AppendElements("permcheck/evals", p.WAt, p.SigmaAt)
	return p, nil
}

// Verify checks the proof and returns the two evaluation claims that remain
// to be verified against the commitments: one on w and one on s_σ.
func Verify(tr sumcheck.Challenger, numVars int, proof Proof) ([]Claim, error) {
	beta := tr.Challenge("permcheck/beta")
	gamma := tr.Challenge("permcheck/gamma")

	q, claims, err := grandprod.Verify(tr, numVars, proof.Prod)
	if err != nil {
		return nil, err
	}

	// The two tables are defined from w and s_σ; check the definitions at q:
	//   num(q) = γ + s_id(q) + β·w(q),   den(q) = γ + s_σ(q) + β·w(q).
	var bw, want fr.Element
	bw.Mul(&beta, &proof.WAt).Add(&bw, &gamma)
	id := IdentityLabel(q)
	want.Add(&bw, &id)
	if !want.Equal(&claims[0]) {
		return nil, ErrLinearCheck
	}
	want.Add(&bw, &proof.SigmaAt)
	if !want.Equal(&claims[1]) {
		return nil, ErrLinearCheck
	}
	tr.AppendElements("permcheck/evals", proof.WAt, proof.SigmaAt)

	return []Claim{
		{OracleW, q, proof.WAt},
		{OracleSigma, q, proof.SigmaAt},
	}, nil
}
