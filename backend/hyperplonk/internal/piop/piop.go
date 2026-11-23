// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package piop

import (
	"errors"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/witness"
	cs "github.com/consensys/gnark/constraint/bn254"

	"github.com/consensys/gnark/backend/hyperplonk/internal/permcheck"
	"github.com/consensys/gnark/backend/hyperplonk/internal/sumcheck"
	"github.com/consensys/gnark/backend/hyperplonk/internal/transcript"
)

// Oracle names a committed polynomial.
type Oracle int

const (
	OracleQL Oracle = iota
	OracleQR
	OracleQM
	OracleQO
	OracleQC
	OracleSigma
	OracleW // wire polynomial, μ+2 variables
)

// Claim states Oracle(Point) = Value.
//
// For an out-of-domain claim Point is nil and Z holds the sampled field
// element: the evaluation point is (Z, Z², Z⁴, …) with as many coordinates as
// the committed polynomial has in the commitment scheme, which may be more
// than in the PIOP (padding). The commitment layer expands it.
type Claim struct {
	Oracle Oracle
	Point  []fr.Element
	Value  fr.Element
	OOD    bool
	Z      fr.Element
}

// Proof is the PIOP transcript: commitments, sumcheck messages and the
// evaluations the prover asserts.
type Proof struct {
	WCommit   []byte
	WOOD      fr.Element // w at the out-of-domain point drawn after WCommit
	Gate      sumcheck.Proof
	GateEvals [8]fr.Element // q_L, q_R, q_M, q_O, q_C, a, b, c at the gate point
	Perm      permcheck.Proof
}

// Tables are the polynomials the prover committed to in a proof.
type Tables struct {
	W polynomial.MultiLin
}

// Commitment is what the commitment layer returns for a table: bytes that
// bind it, and a function giving the committed polynomial's value at the
// out-of-domain point derived from z.
type Commitment struct {
	Bytes []byte
	OOD   func(z fr.Element) fr.Element
}

// Commit is the commitment function.
type Commit func(polynomial.MultiLin) Commitment

var ErrPublicInputs = errors.New("hyperplonk: wrong number of public inputs")

// gate is q_L·a + q_R·b + q_M·a·b + q_O·c + q_C + PI on the values
// [q_L, q_R, q_M, q_O, q_C, PI, a, b, c].
var gate = sumcheck.Gate{
	Degree: 3,
	Eval: func(v []fr.Element) fr.Element {
		var res, t fr.Element
		res.Mul(&v[0], &v[6])
		t.Mul(&v[1], &v[7])
		res.Add(&res, &t)
		t.Mul(&v[2], &v[6]).Mul(&t, &v[7])
		res.Add(&res, &t)
		t.Mul(&v[3], &v[8])
		res.Add(&res, &t)
		res.Add(&res, &v[4]).Add(&res, &v[5])
		return res
	},
}

// start binds the statement: circuit digest and public inputs come first, so
// every challenge depends on them (strong Fiat–Shamir, ePrint 2023/691).
func start(idx *Index, public []fr.Element) *transcript.Transcript {
	tr := transcript.New("gnark/hyperplonk/bn254/piop")
	tr.Append("index", idx.Digest[:])
	tr.AppendElements("public", public...)
	return tr
}

// Out-of-domain samples. Right after a prover commitment is absorbed, the
// verifier draws z ∈ F and the prover answers with the value of the committed
// polynomial at (z, z², z⁴, …), which becomes one more evaluation claim.
//
// Basis: WHIR's compiler, ePrint 2024/1586, Construction 7.4 steps 2–3:
// beyond unique decoding a commitment is close to a list of polynomials, and
// the answer at a random point selects one of them before the PIOP continues
// (error s·2^m·ℓ²/(2|F|), Thm 7.5).

// Prove solves the circuit and runs the PIOP prover. It returns the
// transcript so that the caller can continue with the opening proofs.
func Prove(spr *cs.SparseR1CS, idx *Index, fullWitness witness.Witness, commit Commit, opts ...backend.ProverOption) (*Proof, *Tables, *transcript.Transcript, error) {
	opt, err := backend.NewProverConfig(opts...)
	if err != nil {
		return nil, nil, nil, err
	}
	sol, err := spr.Solve(fullWitness, opt.SolverOpts...)
	if err != nil {
		return nil, nil, nil, err
	}
	solution := sol.(*cs.SparseR1CSSolution)
	full, ok := fullWitness.Vector().(fr.Vector)
	if !ok || len(full) < idx.NbPublic {
		return nil, nil, nil, ErrPublicInputs
	}
	return ProveWires(idx, full[:idx.NbPublic], solution.L, solution.R, solution.O, commit)
}

// ProveWires runs the prover on given wire columns, without checking that
// they satisfy the circuit. Tests use it to build cheating provers.
func ProveWires(idx *Index, public, a, b, c []fr.Element, commit Commit) (*Proof, *Tables, *transcript.Transcript, error) {
	n := 1 << idx.NumVars
	if len(a) != n || len(b) != n || len(c) != n {
		return nil, nil, nil, fmt.Errorf("hyperplonk: wire columns must have %d entries", n)
	}
	if len(public) != idx.NbPublic {
		return nil, nil, nil, ErrPublicInputs
	}
	tr := start(idx, public)

	// 1. commit to the wires
	w := make(polynomial.MultiLin, 4*n)
	copy(w, a)
	copy(w[n:], b)
	copy(w[2*n:], c)
	wc := commit(w)
	proof := &Proof{WCommit: wc.Bytes}
	tr.Append("w", proof.WCommit)
	proof.WOOD = wc.OOD(tr.Challenge("w/ood"))
	tr.AppendElements("w/ood/answer", proof.WOOD)

	// 2. gate identity (zerocheck)
	pi := make(polynomial.MultiLin, n)
	copy(pi, public)
	tables := []polynomial.MultiLin{idx.QL, idx.QR, idx.QM, idx.QO, idx.QC, pi, w[:n], w[n : 2*n], w[2*n : 3*n]}
	gateProof, _, vals, err := sumcheck.ProveZero(tr, tables, gate)
	if err != nil {
		return nil, nil, nil, err
	}
	proof.Gate = gateProof
	copy(proof.GateEvals[:5], vals[:5])
	copy(proof.GateEvals[5:], vals[6:])
	tr.AppendElements("gate/evals", proof.GateEvals[:]...)

	// 3. wiring identity (permutation check); nothing further is committed
	proof.Perm, err = permcheck.Prove(tr, w, idx.Sigma)
	if err != nil {
		return nil, nil, nil, err
	}
	return proof, &Tables{W: w}, tr, nil
}

// Verify checks the PIOP messages and returns the evaluation claims. The
// proof is valid only if every claim holds for the committed polynomials.
//
// Only NumVars, NbPublic and Digest of idx are used. The transcript is
// returned so that the caller can continue with the opening proofs.
func Verify(idx *Index, public []fr.Element, proof *Proof) ([]Claim, *transcript.Transcript, error) {
	if len(public) != idx.NbPublic {
		return nil, nil, ErrPublicInputs
	}
	tr := start(idx, public)
	tr.Append("w", proof.WCommit)
	zw := tr.Challenge("w/ood")
	tr.AppendElements("w/ood/answer", proof.WOOD)

	// gate identity
	res, err := sumcheck.VerifyZero(tr, idx.NumVars, gate.Degree, proof.Gate)
	if err != nil {
		return nil, nil, fmt.Errorf("gate identity: %w", err)
	}
	r := res.Point
	vals := make([]fr.Element, 9)
	copy(vals[:5], proof.GateEvals[:5])
	vals[5] = publicInputAt(public, r) // computed by the verifier, not claimed
	copy(vals[6:], proof.GateEvals[5:])
	if err := res.Check(gate, vals); err != nil {
		return nil, nil, fmt.Errorf("gate identity: %w", err)
	}
	tr.AppendElements("gate/evals", proof.GateEvals[:]...)

	var zero, one fr.Element
	one.SetOne()
	column := func(b0, b1 fr.Element) []fr.Element { return append([]fr.Element{b0, b1}, r...) }
	claims := []Claim{
		{Oracle: OracleQL, Point: r, Value: proof.GateEvals[0]},
		{Oracle: OracleQR, Point: r, Value: proof.GateEvals[1]},
		{Oracle: OracleQM, Point: r, Value: proof.GateEvals[2]},
		{Oracle: OracleQO, Point: r, Value: proof.GateEvals[3]},
		{Oracle: OracleQC, Point: r, Value: proof.GateEvals[4]},
		{Oracle: OracleW, Point: column(zero, zero), Value: proof.GateEvals[5]}, // a(r)
		{Oracle: OracleW, Point: column(zero, one), Value: proof.GateEvals[6]},  // b(r)
		{Oracle: OracleW, Point: column(one, zero), Value: proof.GateEvals[7]},  // c(r)
		{Oracle: OracleW, Value: proof.WOOD, OOD: true, Z: zw},
	}

	// wiring identity
	pc, err := permcheck.Verify(tr, idx.NumVars+2, proof.Perm)
	if err != nil {
		return nil, nil, fmt.Errorf("wiring identity: %w", err)
	}
	for _, c := range pc {
		o := OracleW
		if c.Oracle == permcheck.OracleSigma {
			o = OracleSigma
		}
		claims = append(claims, Claim{Oracle: o, Point: c.Point, Value: c.Value})
	}
	return claims, tr, nil
}
