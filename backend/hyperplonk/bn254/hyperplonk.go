// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Package hyperplonk is a transparent proof system for gnark's SparseR1CS on
// bn254: the HyperPlonk polynomial IOP (ePrint 2022/1355) with WHIR
// (ePrint 2024/1586) as the commitment to every multilinear polynomial,
// made non-interactive with Merkle trees and Fiat–Shamir.
//
// Status: research code, not reviewed, NOT zero-knowledge (the proof reveals
// information about the witness), plain gates only. The theory each part
// rests on, and what is still open, is recorded in docs/hyperplonk/.
//
// Composition (WHIR Construction 7.4, Thm 7.5). Four polynomials in
// m = μ+2 variables are committed (2^μ = number of rows):
//
//	Q  the selectors q_L, q_R, q_M, q_O stacked: Q(⟨j⟩, X) = q_j(X)   (setup)
//	C  the constant selector: C(0, 0, X) = q_C(X)                    (setup)
//	S  the permutation polynomial s_σ                                (setup)
//	W  the wire polynomial w: W(⟨j⟩, X) is column j                  (prover)
//
// W is the only polynomial the prover commits to, and it is committed at its
// natural size: every extra variable would double the prover's encoding
// work. The wiring identity is proven by a layered sumcheck over product
// trees that are never committed. After the commitment the verifier draws an
// out-of-domain point and the prover answers with the value there. The PIOP
// then leaves a list of evaluation claims at a set of points; the prover
// sends the value of every polynomial at every point, and one batched WHIR
// proof covers all of them.
//
// Stacking (docs/hyperplonk/THEORY.md, S14): a selector is defined as the
// restriction of the committed polynomial to a block, q_j(X) := Q(⟨j⟩, X), so
// a claim about q_j is a claim about Q at a point with a boolean prefix. The
// gate point of the wires (⟨j⟩, r) is the same point as that of selector j,
// so the batch has only six distinct points.
package hyperplonk

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/witness"
	cs "github.com/consensys/gnark/constraint/bn254"

	"github.com/consensys/gnark/backend/hyperplonk/internal/piop"
	"github.com/consensys/gnark/backend/hyperplonk/internal/whir"
)

// Fixed parameters (docs/hyperplonk/PLAN.md, D1, D7).
const (
	logInvRate   = 3   // ρ = 1/8
	folding      = 4   // k
	securityBits = 128 // every round-by-round error ≤ 2^−128
)

// Regime selects the proximity regime of WHIR (decision D2).
type Regime = whir.Regime

const (
	// UniqueDecoding rests on results proven in the WHIR paper. Default.
	UniqueDecoding = whir.UniqueDecoding
	// Johnson gives smaller proofs and rests in addition on ePrint 2025/2110
	// and 2025/2051 (preprints, proofs not checked by us).
	Johnson = whir.Johnson
)

// The committed polynomials, in commitment order.
const (
	polyQ = iota
	polyC
	polyS
	polyW
	nbPolys
)

// ErrCommitmentsUnsupported is returned by Setup for circuits using api.Commit.
var ErrCommitmentsUnsupported = piop.ErrCommitmentsUnsupported

var (
	ErrInvalidProof = errors.New("hyperplonk: malformed proof")
	ErrTooLarge     = errors.New("hyperplonk: circuit too large")
	ErrEvaluation   = errors.New("hyperplonk: a value used by the PIOP differs from the opened value")
)

// VerifyingKey is what the verifier needs: sizes, the commitment to the
// preprocessed polynomials, and a digest binding all of it.
type VerifyingKey struct {
	NumVars  int // μ: the circuit has 2^μ rows
	NbPublic int
	Regime   Regime
	Circuit  [sha256.Size]byte // hash of the preprocessed tables
	Root     whir.Digest       // commitment to Q and S
	Digest   [sha256.Size]byte // binds all fields above; derived, not serialized
}

// NbPublicWitness returns the number of public inputs the verifier expects.
func (vk *VerifyingKey) NbPublicWitness() int { return vk.NbPublic }

// VerifyingKey returns the verifying key that belongs to the proving key.
func (pk *ProvingKey) VerifyingKey() interface{} { return pk.Vk }

// ProvingKey holds the preprocessed polynomials and their commitment.
type ProvingKey struct {
	Vk        *VerifyingKey
	index     *piop.Index
	committed *whir.Committed
}

// Proof is the PIOP transcript, the value of every committed polynomial at
// every evaluation point, and one batched opening proof.
type Proof struct {
	PIOP    *piop.Proof
	Values  [][]fr.Element // [polynomial][point]
	Opening *whir.Proof
}

// params returns the WHIR parameters: all polynomials have μ+3 variables.
func (vk *VerifyingKey) params() (whir.Params, error) {
	p, err := whir.NewParams(vk.NumVars+2, logInvRate, folding, securityBits, vk.Regime)
	if err != nil {
		return p, ErrTooLarge
	}
	return p, nil
}

// digest binds the circuit, the parameters and the commitment. It is the
// first thing absorbed into the transcript.
func (vk *VerifyingKey) digest() [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte("gnark/hyperplonk/bn254/vk/v6"))
	var hdr [48]byte
	for i, v := range []int{vk.NumVars, vk.NbPublic, int(vk.Regime), logInvRate, folding, securityBits} {
		binary.BigEndian.PutUint64(hdr[8*i:], uint64(v))
	}
	h.Write(hdr[:])
	h.Write(vk.Circuit[:])
	h.Write(vk.Root[:])
	var d [sha256.Size]byte
	h.Sum(d[:0])
	return d
}

// index is the statement as the PIOP verifier sees it.
func (vk *VerifyingKey) index() *piop.Index {
	return &piop.Index{NumVars: vk.NumVars, NbPublic: vk.NbPublic, Digest: vk.Digest}
}

// Setup preprocesses the circuit. There is no trusted setup: everything is
// derived from the circuit, and the verifying key can be recomputed by anyone.
func Setup(spr *cs.SparseR1CS, regime Regime) (*ProvingKey, *VerifyingKey, error) {
	idx, err := piop.NewIndex(spr)
	if err != nil {
		return nil, nil, err
	}
	vk := &VerifyingKey{NumVars: idx.NumVars, NbPublic: idx.NbPublic, Regime: regime, Circuit: idx.Digest}
	pk := &ProvingKey{Vk: vk, index: idx}
	if err := pk.commit(); err != nil {
		return nil, nil, err
	}
	vk.Root = pk.committed.Root
	vk.Digest = vk.digest()
	idx.Digest = vk.Digest // the PIOP binds the full verifying key
	return pk, vk, nil
}

// commit builds and commits to the polynomials Q and S of the index.
func (pk *ProvingKey) commit() error {
	idx := pk.index
	params, err := pk.Vk.params()
	if err != nil {
		return err
	}
	// Q: selector j occupies the block of indices with top two bits j;
	// C: the constant selector in block 0
	n := 1 << idx.NumVars
	q := make(polynomial.MultiLin, 4*n)
	for j, t := range []polynomial.MultiLin{idx.QL, idx.QR, idx.QM, idx.QO} {
		copy(q[j*n:], t)
	}
	qc := make(polynomial.MultiLin, 4*n)
	copy(qc, idx.QC)
	pk.committed, err = whir.Commit(params, q, qc, idx.Sigma)
	return err
}

// statement turns the PIOP's claims into the input of the batched opening:
// the list of distinct evaluation points in F^(μ+3), and for each claim the
// polynomial and the index of its point. Prover and verifier both use it.
type claimRef struct {
	poly, point int
	value       fr.Element
}

func statement(claims []piop.Claim, numVars int) ([][]fr.Element, []claimRef, error) {
	m := numVars + 2
	var zero fr.Element
	bit := func(b int) fr.Element {
		var e fr.Element
		e.SetUint64(uint64(b))
		return e
	}
	var points [][]fr.Element
	refs := make([]claimRef, 0, len(claims))
	for _, c := range claims {
		var poly int
		var pt []fr.Element
		switch {
		case c.Oracle <= piop.OracleQC: // selector j: Q(⟨j⟩, r)
			j := int(c.Oracle)
			poly, pt = polyQ, append([]fr.Element{bit(j >> 1), bit(j & 1)}, c.Point...)
			if c.Oracle == piop.OracleQC {
				poly, pt = polyC, append([]fr.Element{zero, zero}, c.Point...)
			}
		case c.Oracle == piop.OracleSigma:
			poly, pt = polyS, c.Point
		case c.Oracle == piop.OracleW:
			poly, pt = polyW, c.Point
		default:
			return nil, nil, ErrInvalidProof
		}
		if c.OOD {
			pt = whir.Pow(c.Z, m)
		}
		if len(pt) != m {
			return nil, nil, ErrInvalidProof
		}
		// reuse the point if it is already in the list
		k := 0
	search:
		for ; k < len(points); k++ {
			for i := range pt {
				if !points[k][i].Equal(&pt[i]) {
					continue search
				}
			}
			break
		}
		if k == len(points) {
			points = append(points, pt)
		}
		refs = append(refs, claimRef{poly, k, c.Value})
	}
	return points, refs, nil
}

// Prove generates a proof.
func Prove(spr *cs.SparseR1CS, pk *ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (*Proof, error) {
	opt, err := backend.NewProverConfig(opts...)
	if err != nil {
		return nil, err
	}
	sol, err := spr.Solve(fullWitness, opt.SolverOpts...)
	if err != nil {
		return nil, err
	}
	solution := sol.(*cs.SparseR1CSSolution)
	full, ok := fullWitness.Vector().(fr.Vector)
	if !ok || len(full) < pk.Vk.NbPublic {
		return nil, piop.ErrPublicInputs
	}
	return proveWires(pk, full[:pk.Vk.NbPublic], solution.L, solution.R, solution.O)
}

// proveWires proves for given wire columns, valid or not (used by tests).
func proveWires(pk *ProvingKey, public, a, b, c []fr.Element) (*Proof, error) {
	params, err := pk.Vk.params()
	if err != nil {
		return nil, err
	}
	m := params.NumVars
	committed := []*whir.Committed{pk.committed}
	var commitErr error
	// the PIOP commits to w at its natural size (μ+2 variables)
	commit := func(t polynomial.MultiLin) piop.Commitment {
		c, err := whir.Commit(params, t)
		if err != nil {
			commitErr = err
			return piop.Commitment{OOD: func(fr.Element) fr.Element { return fr.Element{} }}
		}
		committed = append(committed, c)
		return piop.Commitment{
			Bytes: c.Root[:],
			OOD:   func(z fr.Element) fr.Element { return t.Evaluate(whir.Pow(z, m), nil) },
		}
	}
	p, _, tr, err := piop.ProveWires(pk.index, public, a, b, c, commit)
	if commitErr != nil {
		return nil, commitErr
	}
	if err != nil {
		return nil, err
	}
	// The prover derives the claims as the verifier will: by running the
	// PIOP verifier on its own proof.
	claims, _, err := piop.Verify(pk.Vk.index(), public, p)
	if err != nil {
		return nil, err
	}
	points, _, err := statement(claims, pk.Vk.NumVars)
	if err != nil {
		return nil, err
	}
	proof := &Proof{PIOP: p, Values: whir.Evaluations(committed, points)}
	if proof.Opening, err = whir.OpenBatch(tr, params, committed, points, proof.Values); err != nil {
		return nil, err
	}
	return proof, nil
}

// Verify checks a proof against the public inputs.
func Verify(proof *Proof, vk *VerifyingKey, public fr.Vector) error {
	if proof == nil || proof.PIOP == nil || proof.Opening == nil || len(proof.PIOP.WCommit) != sha256.Size {
		return ErrInvalidProof
	}
	params, err := vk.params()
	if err != nil {
		return err
	}
	claims, tr, err := piop.Verify(vk.index(), public, proof.PIOP)
	if err != nil {
		return err
	}
	points, refs, err := statement(claims, vk.NumVars)
	if err != nil {
		return err
	}
	if len(proof.Values) != nbPolys {
		return ErrInvalidProof
	}
	for _, row := range proof.Values {
		if len(row) != len(points) {
			return ErrInvalidProof
		}
	}
	// every value the PIOP used must be the opened value of its polynomial
	// at its point (Construction 7.4, decision phase, items 1 and 3)
	for _, r := range refs {
		if !proof.Values[r.poly][r.point].Equal(&r.value) {
			return ErrEvaluation
		}
	}
	roots := make([]whir.Digest, 2)
	roots[0] = vk.Root
	copy(roots[1][:], proof.PIOP.WCommit)
	return whir.VerifyBatch(tr, params, roots, []int{3, 1}, points, proof.Values, proof.Opening)
}
