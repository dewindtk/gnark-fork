// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Package piop is the HyperPlonk polynomial IOP (ePrint 2022/1355, §4,
// Figure 2) for gnark's SparseR1CS, without a polynomial commitment.
//
// The verifier here does not decide alone: it returns evaluation claims
// "polynomial P has value y at point z" that must be verified against
// commitments. Until the commitment scheme (WHIR) is attached, the tests use
// the tables themselves as the opening. The package is internal for that
// reason: Verify must not be mistaken for a complete verifier.
//
// Statement. n = 2^μ rows; row i has selectors q_L, q_R, q_M, q_O, q_C and
// wires a, b, c. With PI the table of public inputs (pub_i in row i < ℓ, zero
// elsewhere):
//
//	gate identity:   q_L·a + q_R·b + q_M·a·b + q_O·c + q_C + PI = 0 on every row
//	wiring identity: w(x) = w(σ(x)) for the table w = a ‖ b ‖ c ‖ 0 of 4n slots
//
// Layout choices and their basis (docs/hyperplonk/THEORY.md):
//
//   - One wire polynomial w in μ+2 variables whose first two variables select
//     the column, as in HyperPlonk Def. 4.1; a(X) = w(0,0,X), b(X) = w(0,1,X),
//     c(X) = w(1,0,X). The fourth column is zero and fixed by σ.
//   - Public inputs enter the gate identity through PI, as in PlonK
//     (ePrint 2019/953, §7, step 3; there with the opposite sign) and gnark's constraint system: row i < ℓ is
//     −a_i + pub_i = 0. The verifier evaluates PI itself, so HyperPlonk's
//     separate public-input check (Figure 2, step 4) is not needed (S7).
//   - Rows, public-input rows and unused slots follow gnark's solver: unused
//     slots carry the value of variable 0 and are wired to it.
package piop

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/bits"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"
	cs "github.com/consensys/gnark/constraint/bn254"

	"github.com/consensys/gnark/backend/hyperplonk/internal/permcheck"
)

// ErrCommitmentsUnsupported is returned for circuits that use api.Commit
// (BSB22 commitments); only plain gates are supported.
var ErrCommitmentsUnsupported = errors.New("hyperplonk: circuits with commitments (api.Commit) are not supported")

// Index is the preprocessed circuit.
type Index struct {
	NumVars            int                 // μ
	NbPublic           int                 // ℓ
	QL, QR, QM, QO, QC polynomial.MultiLin // 2^μ entries each
	Sigma              polynomial.MultiLin // s_σ, 2^(μ+2) entries
	Digest             [sha256.Size]byte   // binds everything above

	perm []int // σ on the 4n slots, kept for tests
}

// NewIndex preprocesses a circuit.
func NewIndex(spr *cs.SparseR1CS) (*Index, error) {
	if len(spr.GetCommitments().CommitmentIndexes()) > 0 {
		return nil, ErrCommitmentsUnsupported
	}
	nbPublic := len(spr.Public)
	// same size as the solver's L, R, O vectors
	n := int(ecc.NextPowerOfTwo(uint64(spr.GetNbConstraints() + nbPublic)))
	idx := &Index{NumVars: bits.TrailingZeros(uint(n)), NbPublic: nbPublic}
	idx.QL = make(polynomial.MultiLin, n)
	idx.QR = make(polynomial.MultiLin, n)
	idx.QM = make(polynomial.MultiLin, n)
	idx.QO = make(polynomial.MultiLin, n)
	idx.QC = make(polynomial.MultiLin, n)

	// public-input rows: −a_i + PI_i = 0
	for i := range nbPublic {
		idx.QL[i].SetOne()
		idx.QL[i].Neg(&idx.QL[i])
	}

	// slot → variable. Slots are a ‖ b ‖ c ‖ pad; unused slots of a, b, c
	// refer to variable 0, as the solver fills them with its value.
	slotVar := make([]int, 3*n)
	for i := range nbPublic {
		slotVar[i] = i
	}
	j := nbPublic
	it := spr.GetSparseR1CIterator()
	for c := it.Next(); c != nil; c = it.Next() {
		idx.QL[j].Set(&spr.Coefficients[c.QL])
		idx.QR[j].Set(&spr.Coefficients[c.QR])
		idx.QM[j].Set(&spr.Coefficients[c.QM])
		idx.QO[j].Set(&spr.Coefficients[c.QO])
		idx.QC[j].Set(&spr.Coefficients[c.QC])
		slotVar[j] = int(c.XA)
		slotVar[n+j] = int(c.XB)
		slotVar[2*n+j] = int(c.XC)
		j++
	}

	// σ: the slots of one variable form one cycle; the pad column is fixed.
	nbVariables := spr.NbInternalVariables + len(spr.Public) + len(spr.Secret)
	if nbVariables < 1 {
		nbVariables = 1
	}
	idx.perm = make([]int, 4*n)
	last := make([]int, nbVariables)
	for i := range last {
		last[i] = -1
	}
	for i := range idx.perm {
		idx.perm[i] = -1
	}
	for i, v := range slotVar {
		if last[v] != -1 {
			idx.perm[i] = last[v]
		}
		last[v] = i
	}
	for i, v := range slotVar {
		if idx.perm[i] == -1 {
			idx.perm[i] = last[v] // close the cycle
		}
	}
	for i := 3 * n; i < 4*n; i++ {
		idx.perm[i] = i
	}
	var err error
	if idx.Sigma, err = permcheck.SigmaTable(idx.perm); err != nil {
		return nil, err
	}

	idx.Digest = idx.ComputeDigest()
	return idx, nil
}

// ComputeDigest hashes the sizes and all preprocessed tables.
func (idx *Index) ComputeDigest() [sha256.Size]byte {
	h := sha256.New()
	var hdr [16]byte
	binary.BigEndian.PutUint64(hdr[:8], uint64(idx.NumVars))
	binary.BigEndian.PutUint64(hdr[8:], uint64(idx.NbPublic))
	h.Write(hdr[:])
	for _, t := range []polynomial.MultiLin{idx.QL, idx.QR, idx.QM, idx.QO, idx.QC, idx.Sigma} {
		for i := range t {
			b := t[i].Bytes()
			h.Write(b[:])
		}
	}
	var d [sha256.Size]byte
	h.Sum(d[:0])
	return d
}

// publicInputAt returns PI(r) = Σ_{i<ℓ} pub_i · eq(i, r), where eq(i, r) is
// the product over the bits of i (first variable = top bit) of r_k or 1 − r_k.
func publicInputAt(public []fr.Element, r []fr.Element) fr.Element {
	var res, term, one, f fr.Element
	one.SetOne()
	mu := len(r)
	for i := range public {
		term.Set(&public[i])
		for k := range mu {
			if (i>>(mu-1-k))&1 == 1 {
				term.Mul(&term, &r[k])
			} else {
				f.Sub(&one, &r[k])
				term.Mul(&term, &f)
			}
		}
		res.Add(&res, &term)
	}
	return res
}
