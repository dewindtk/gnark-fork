// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Package grandprod proves that two tables have the same product, with the
// GKR protocol on their product trees (Thaler, "Proofs, Arguments, and
// Zero-Knowledge", §4.6; this special case is the layered-sumcheck grand
// product that Quarks, ePrint 2020/1275 §5, takes as its starting point).
//
// For a table with 2^d entries let V_d be the table and
// V_i(x) = V_{i+1}(x, 0)·V_{i+1}(x, 1) for i < d; V_0 is the product. Nothing
// but the two input tables is committed: the prover only answers questions
// about the multilinear extensions of the layers.
//
// One iteration reduces a claim V_i(z) = c to a claim about V_{i+1}:
//
//  1. V_i(z) = Σ_{x ∈ {0,1}^i} eq(z, x)·V_{i+1}(x, 0)·V_{i+1}(x, 1): both sides
//     are multilinear in z and agree on the hypercube. A sumcheck reduces the
//     claim to the summand at a random point r.
//  2. The prover sends l = V_{i+1}(r, 0) and r' = V_{i+1}(r, 1); the verifier
//     checks eq(z, r)·l·r' against the sumcheck's final claim.
//  3. V_{i+1}(r, T) is linear in T, so for a random t the single claim
//     V_{i+1}(r, t) = (1 − t)·l + t·r' replaces the two: if l or r' is wrong,
//     the combination is right for at most one t.
//
// After d iterations there is one claim on the input table at one point.
// The two tables (numerator and denominator) run through the same
// iterations: each sumcheck is on the combination "first + λ·second" for a
// fresh λ, with the same r and t, so both final claims are at the same point.
//
// Soundness error per iteration i (i variables): 1/|F| for λ, 3i/|F| for the
// sumcheck (degree 3), 1/|F| for t (docs/hyperplonk/THEORY.md, S17).
package grandprod

import (
	"errors"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"

	"github.com/consensys/gnark/backend/hyperplonk/internal/par"
	"github.com/consensys/gnark/backend/hyperplonk/internal/sumcheck"
)

var (
	ErrProofShape = errors.New("grandprod: proof has the wrong shape")
	ErrRoots      = errors.New("grandprod: the two products differ")
	ErrLayer      = errors.New("grandprod: layer values inconsistent with the sumcheck")
)

// LayerProof holds the messages of one iteration.
type LayerProof struct {
	Rounds [][]fr.Element // sumcheck rounds, 4 values each
	Evals  [4]fr.Element  // V(r,0), V(r,1) of the first table, then of the second
}

// Proof is a grand-product equality proof.
type Proof struct {
	Roots  [2]fr.Element // the two products
	Layers []LayerProof  // iteration i reduces layer i to layer i+1
}

// tree returns the layers V_0, …, V_d of the product tree of leaves.
func tree(leaves polynomial.MultiLin) []polynomial.MultiLin {
	d := 0
	for 1<<d < len(leaves) {
		d++
	}
	layers := make([]polynomial.MultiLin, d+1)
	layers[d] = leaves
	for i := d - 1; i >= 0; i-- {
		next := layers[i+1]
		cur := make(polynomial.MultiLin, len(next)/2)
		par.Range(len(cur), 1<<12, func(start, end int) {
			for x := start; x < end; x++ {
				cur[x].Mul(&next[2*x], &next[2*x+1])
			}
		})
		layers[i] = cur
	}
	return layers
}

// halves splits V_{i+1} into the tables x ↦ V_{i+1}(x, 0) and x ↦ V_{i+1}(x, 1).
func halves(v polynomial.MultiLin) (polynomial.MultiLin, polynomial.MultiLin) {
	l := make(polynomial.MultiLin, len(v)/2)
	r := make(polynomial.MultiLin, len(v)/2)
	par.Range(len(l), 1<<13, func(start, end int) {
		for x := start; x < end; x++ {
			l[x], r[x] = v[2*x], v[2*x+1]
		}
	})
	return l, r
}

// gate is eq·(L₁·R₁ + λ·L₂·R₂) on the values [eq, L₁, R₁, L₂, R₂].
func gate(lambda fr.Element) sumcheck.Gate {
	return sumcheck.Gate{
		Degree: 3,
		Eval: func(v []fr.Element) fr.Element {
			var a, b fr.Element
			a.Mul(&v[1], &v[2])
			b.Mul(&v[3], &v[4]).Mul(&b, &lambda)
			a.Add(&a, &b).Mul(&a, &v[0])
			return a
		},
	}
}

// line returns (1 − t)·a + t·b.
func line(a, b, t fr.Element) fr.Element {
	b.Sub(&b, &a).Mul(&b, &t).Add(&b, &a)
	return b
}

// Prove proves that the two tables (of equal power-of-two size) have the
// products it reports in Proof.Roots. It returns the point q and the values
// of the two tables' multilinear extensions at q that the verifier will ask
// the caller to justify.
func Prove(tr sumcheck.Challenger, first, second polynomial.MultiLin) (Proof, []fr.Element, [2]fr.Element, error) {
	n := len(first)
	if n == 0 || n&(n-1) != 0 || len(second) != n {
		return Proof{}, nil, [2]fr.Element{}, errors.New("grandprod: tables must have equal power-of-two size")
	}
	t1, t2 := tree(first), tree(second)
	d := len(t1) - 1
	proof := Proof{Roots: [2]fr.Element{t1[0][0], t2[0][0]}, Layers: make([]LayerProof, d)}
	tr.AppendElements("grandprod/roots", proof.Roots[:]...)

	claims := proof.Roots
	var z []fr.Element
	for i := range d {
		lambda := tr.Challenge("grandprod/lambda")
		eq := make(polynomial.MultiLin, 1<<i)
		eq[0].SetOne()
		if i > 0 {
			eq.Eq(z)
		}
		l1, r1 := halves(t1[i+1])
		l2, r2 := halves(t2[i+1])
		tables := []polynomial.MultiLin{eq, l1, r1, l2, r2}
		rounds, r := sumcheck.ProveRounds(tr, tables, gate(lambda), i)
		lp := LayerProof{Rounds: rounds, Evals: [4]fr.Element{tables[1][0], tables[2][0], tables[3][0], tables[4][0]}}
		tr.AppendElements("grandprod/evals", lp.Evals[:]...)
		t := tr.Challenge("grandprod/t")
		claims[0] = line(lp.Evals[0], lp.Evals[1], t)
		claims[1] = line(lp.Evals[2], lp.Evals[3], t)
		z = append(r, t)
		proof.Layers[i] = lp
	}
	return proof, z, claims, nil
}

// Verify checks the proof for tables with 2^numVars entries. It returns the
// point q and the two values the tables' multilinear extensions must have at
// q; the proof is valid only if they do, which the caller must check.
func Verify(tr sumcheck.Challenger, numVars int, proof Proof) ([]fr.Element, [2]fr.Element, error) {
	if len(proof.Layers) != numVars {
		return nil, [2]fr.Element{}, ErrProofShape
	}
	if !proof.Roots[0].Equal(&proof.Roots[1]) {
		return nil, [2]fr.Element{}, ErrRoots
	}
	tr.AppendElements("grandprod/roots", proof.Roots[:]...)

	claims := proof.Roots
	var z []fr.Element
	for i, lp := range proof.Layers {
		if len(lp.Rounds) != i {
			return nil, [2]fr.Element{}, ErrProofShape
		}
		lambda := tr.Challenge("grandprod/lambda")
		g := gate(lambda)
		var claim fr.Element
		claim.Mul(&lambda, &claims[1]).Add(&claim, &claims[0])
		r, final, err := sumcheck.VerifyRounds(tr, claim, g.Degree, lp.Rounds)
		if err != nil {
			return nil, [2]fr.Element{}, fmt.Errorf("grandprod: layer %d: %w", i, err)
		}
		var eq fr.Element
		eq.SetOne()
		if i > 0 {
			eq = polynomial.EvalEq(z, r)
		}
		if want := g.Eval([]fr.Element{eq, lp.Evals[0], lp.Evals[1], lp.Evals[2], lp.Evals[3]}); !want.Equal(&final) {
			return nil, [2]fr.Element{}, fmt.Errorf("layer %d: %w", i, ErrLayer)
		}
		tr.AppendElements("grandprod/evals", lp.Evals[:]...)
		t := tr.Challenge("grandprod/t")
		claims[0] = line(lp.Evals[0], lp.Evals[1], t)
		claims[1] = line(lp.Evals[2], lp.Evals[3], t)
		z = append(r, t)
	}
	return z, claims, nil
}
