// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package hyperplonk

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"

	"github.com/consensys/gnark/backend/hyperplonk/internal/grandprod"
	"github.com/consensys/gnark/backend/hyperplonk/internal/piop"
	"github.com/consensys/gnark/backend/hyperplonk/internal/whir"
)

// Binary encodings of keys and proofs.
//
// Rules of the format:
//
//   - Every object starts with a 4-byte magic and a version byte.
//   - Integers are 4-byte big-endian. Field elements are 32-byte big-endian
//     and must be canonical (below the modulus): each value has one encoding.
//   - Every variable-length part is preceded by its length, and every length
//     is checked against a fixed bound before anything is allocated, so a
//     short malicious input cannot make the decoder allocate much. Memory
//     use follows the amount of data actually present.
//   - Decoding checks the shape only. Whether a proof is valid is decided by
//     Verify, which checks every length again against the verifying key.

// MaxLogSize bounds log₂ of the number of rows accepted when decoding a key.
// Decoding a proving key recomputes the commitment, which encodes two
// polynomials of 2^(MaxLogSize+3) values at rate 1/8: about 1 GB at 17.
const MaxLogSize = 17

const version = 2

var (
	magicVK    = [4]byte{'g', 'h', 'p', 'V'}
	magicPK    = [4]byte{'g', 'h', 'p', 'K'}
	magicProof = [4]byte{'g', 'h', 'p', 'P'}
)

// ErrInvalidKey is returned (wrapped) when a decoded key is inconsistent.
var ErrInvalidKey = errors.New("hyperplonk: invalid key encoding")

// Bounds on the variable-length parts of a proof. They exceed what any
// supported size produces (PLAN.md, D7: k = 4, at most 26 variables).
const (
	maxRounds  = 32   // sumcheck rounds in one message group
	maxDegree  = 8    // values per sumcheck round
	maxPolys   = 16   // rows of the evaluation table
	maxPoints  = 64   // columns of the evaluation table
	maxIter    = 32   // WHIR iterations
	maxQueries = 1024 // openings per oracle
	maxTrees   = 8    // commitments opened per query
	maxLeaf    = 1024 // field elements per leaf
	maxPath    = 64   // digests per Merkle path
	maxFinal   = 256  // values of the final polynomial
	readChunk  = 1 << 12
)

type writer struct {
	w   io.Writer
	n   int64
	err error
}

func (w *writer) bytes(b []byte) {
	if w.err != nil {
		return
	}
	k, err := w.w.Write(b)
	w.n += int64(k)
	w.err = err
}

func (w *writer) u32(v int) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(v))
	w.bytes(b[:])
}

func (w *writer) elem(e *fr.Element) {
	b := e.Bytes()
	w.bytes(b[:])
}

func (w *writer) elems(es []fr.Element) {
	w.u32(len(es))
	for i := range es {
		w.elem(&es[i])
	}
}

func (w *writer) rounds(rs [][]fr.Element) {
	w.u32(len(rs))
	for _, r := range rs {
		w.elems(r)
	}
}

type reader struct {
	r   io.Reader
	n   int64
	err error
}

func (r *reader) fail(format string, args ...any) {
	if r.err == nil {
		r.err = fmt.Errorf(format, args...)
	}
}

func (r *reader) bytes(b []byte) {
	if r.err != nil {
		return
	}
	k, err := io.ReadFull(r.r, b)
	r.n += int64(k)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		r.err = err
	}
}

// u32 reads an integer and fails if it exceeds max.
func (r *reader) u32(max int) int {
	var b [4]byte
	r.bytes(b[:])
	v := binary.BigEndian.Uint32(b[:])
	if r.err == nil && uint64(v) > uint64(max) {
		r.fail("length %d exceeds the bound %d", v, max)
	}
	if r.err != nil {
		return 0
	}
	return int(v)
}

func (r *reader) elem(e *fr.Element) {
	var b [fr.Bytes]byte
	r.bytes(b[:])
	if r.err != nil {
		return
	}
	if err := e.SetBytesCanonical(b[:]); err != nil {
		r.fail("non-canonical field element")
	}
}

// elemsN reads n field elements, growing the slice in bounded steps.
func (r *reader) elemsN(n int) []fr.Element {
	out := make([]fr.Element, 0, min(n, readChunk))
	for len(out) < n && r.err == nil {
		var e fr.Element
		r.elem(&e)
		out = append(out, e)
	}
	if r.err != nil {
		return nil
	}
	return out
}

func (r *reader) elems(max int) []fr.Element { return r.elemsN(r.u32(max)) }

func (r *reader) rounds() [][]fr.Element {
	n := r.u32(maxRounds)
	out := make([][]fr.Element, 0, n)
	for i := 0; i < n && r.err == nil; i++ {
		out = append(out, r.elems(maxDegree))
	}
	return out
}

func (r *reader) header(magic [4]byte) {
	var b [5]byte
	r.bytes(b[:])
	if r.err == nil && ([4]byte(b[:4]) != magic || b[4] != version) {
		r.fail("wrong magic or version")
	}
}

// ---------------------------------------------------------------------------
// VerifyingKey

func (vk *VerifyingKey) write(w *writer) {
	w.u32(vk.NumVars)
	w.u32(vk.NbPublic)
	w.u32(int(vk.Regime))
	w.bytes(vk.Circuit[:])
	w.bytes(vk.Root[:])
}

func (vk *VerifyingKey) read(r *reader) {
	vk.NumVars = r.u32(MaxLogSize)
	vk.NbPublic = r.u32(1 << MaxLogSize)
	vk.Regime = Regime(r.u32(int(Johnson)))
	r.bytes(vk.Circuit[:])
	r.bytes(vk.Root[:])
	if r.err == nil && vk.NbPublic > 1<<vk.NumVars {
		r.fail("more public inputs than rows")
	}
	vk.Digest = vk.digest() // derived, never read from the stream
}

// WriteTo writes the binary encoding of the verifying key.
func (vk *VerifyingKey) WriteTo(out io.Writer) (int64, error) {
	w := &writer{w: out}
	w.bytes(append(magicVK[:], version))
	vk.write(w)
	return w.n, w.err
}

// ReadFrom decodes a verifying key, overwriting *vk on success.
func (vk *VerifyingKey) ReadFrom(in io.Reader) (int64, error) {
	r := &reader{r: in}
	var v VerifyingKey
	r.header(magicVK)
	v.read(r)
	if r.err != nil {
		return r.n, fmt.Errorf("%w: %v", ErrInvalidKey, r.err)
	}
	*vk = v
	return r.n, nil
}

// ---------------------------------------------------------------------------
// ProvingKey

// WriteTo writes the binary encoding of the proving key: the verifying key
// and the preprocessed tables. The commitment is not stored.
func (pk *ProvingKey) WriteTo(out io.Writer) (int64, error) {
	w := &writer{w: out}
	w.bytes(append(magicPK[:], version))
	pk.Vk.write(w)
	idx := pk.index
	for _, t := range []polynomial.MultiLin{idx.QL, idx.QR, idx.QM, idx.QO, idx.QC, idx.Sigma} {
		for i := range t {
			w.elem(&t[i])
		}
	}
	return w.n, w.err
}

// ReadFrom decodes a proving key, overwriting *pk on success. The tables are
// checked against the circuit hash of the embedded verifying key, and the
// commitment is recomputed and checked against its root.
func (pk *ProvingKey) ReadFrom(in io.Reader) (int64, error) {
	r := &reader{r: in}
	vk := &VerifyingKey{}
	r.header(magicPK)
	vk.read(r)
	if r.err != nil {
		return r.n, fmt.Errorf("%w: %v", ErrInvalidKey, r.err)
	}
	n := 1 << vk.NumVars
	idx := &piop.Index{NumVars: vk.NumVars, NbPublic: vk.NbPublic}
	for _, t := range []*polynomial.MultiLin{&idx.QL, &idx.QR, &idx.QM, &idx.QO, &idx.QC} {
		*t = r.elemsN(n)
	}
	idx.Sigma = r.elemsN(4 * n)
	if r.err != nil {
		return r.n, fmt.Errorf("%w: %v", ErrInvalidKey, r.err)
	}
	if idx.ComputeDigest() != vk.Circuit {
		return r.n, fmt.Errorf("%w: tables do not match the circuit hash", ErrInvalidKey)
	}
	p := &ProvingKey{Vk: vk, index: idx}
	if err := p.commit(); err != nil {
		return r.n, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	if p.committed.Root != vk.Root {
		return r.n, fmt.Errorf("%w: tables do not match the commitment", ErrInvalidKey)
	}
	idx.Digest = vk.Digest
	*pk = *p
	return r.n, nil
}

// ---------------------------------------------------------------------------
// Proof

func writeQueries(w *writer, qs []whir.Query) {
	w.u32(len(qs))
	for _, q := range qs {
		w.u32(len(q.Leaves))
		for t := range q.Leaves {
			w.elems(q.Leaves[t])
			w.u32(len(q.Paths[t]))
			for i := range q.Paths[t] {
				w.bytes(q.Paths[t][i][:])
			}
		}
	}
}

func readQueries(r *reader) []whir.Query {
	n := r.u32(maxQueries)
	qs := make([]whir.Query, 0, min(n, 64))
	for i := 0; i < n && r.err == nil; i++ {
		var q whir.Query
		trees := r.u32(maxTrees)
		for t := 0; t < trees && r.err == nil; t++ {
			q.Leaves = append(q.Leaves, r.elems(maxLeaf))
			depth := r.u32(maxPath)
			path := make([]whir.Digest, depth)
			for j := range path {
				r.bytes(path[j][:])
			}
			q.Paths = append(q.Paths, path)
		}
		qs = append(qs, q)
	}
	return qs
}

// WriteTo writes the binary encoding of the proof.
func (proof *Proof) WriteTo(out io.Writer) (int64, error) {
	if proof.PIOP == nil || proof.Opening == nil || len(proof.PIOP.WCommit) != len(whir.Digest{}) {
		return 0, ErrInvalidProof
	}
	for _, o := range proof.Opening.Rounds {
		for _, q := range o.Queries {
			if len(q.Leaves) != len(q.Paths) {
				return 0, ErrInvalidProof
			}
		}
	}
	for _, q := range proof.Opening.FinalQueries {
		if len(q.Leaves) != len(q.Paths) {
			return 0, ErrInvalidProof
		}
	}
	w := &writer{w: out}
	w.bytes(append(magicProof[:], version))

	p := proof.PIOP
	w.bytes(p.WCommit)
	w.elem(&p.WOOD)
	w.rounds(p.Gate.Rounds)
	for i := range p.GateEvals {
		w.elem(&p.GateEvals[i])
	}
	w.elem(&p.Perm.Prod.Roots[0])
	w.elem(&p.Perm.Prod.Roots[1])
	w.u32(len(p.Perm.Prod.Layers))
	for _, l := range p.Perm.Prod.Layers {
		w.rounds(l.Rounds)
		for i := range l.Evals {
			w.elem(&l.Evals[i])
		}
	}
	w.elem(&p.Perm.WAt)
	w.elem(&p.Perm.SigmaAt)

	w.u32(len(proof.Values))
	for _, row := range proof.Values {
		w.elems(row)
	}

	o := proof.Opening
	w.rounds(o.Initial)
	w.u32(len(o.Rounds))
	for _, rp := range o.Rounds {
		w.bytes(rp.Root[:])
		w.elem(&rp.OOD)
		writeQueries(w, rp.Queries)
		w.rounds(rp.Sumcheck)
	}
	w.elems(o.Final)
	writeQueries(w, o.FinalQueries)
	return w.n, w.err
}

// ReadFrom decodes a proof, overwriting *proof on success.
func (proof *Proof) ReadFrom(in io.Reader) (int64, error) {
	r := &reader{r: in}
	r.header(magicProof)

	p := &piop.Proof{WCommit: make([]byte, len(whir.Digest{}))}
	r.bytes(p.WCommit)
	r.elem(&p.WOOD)
	p.Gate.Rounds = r.rounds()
	for i := range p.GateEvals {
		r.elem(&p.GateEvals[i])
	}
	r.elem(&p.Perm.Prod.Roots[0])
	r.elem(&p.Perm.Prod.Roots[1])
	layers := r.u32(maxRounds)
	for i := 0; i < layers && r.err == nil; i++ {
		var l grandprod.LayerProof
		l.Rounds = r.rounds()
		for j := range l.Evals {
			r.elem(&l.Evals[j])
		}
		p.Perm.Prod.Layers = append(p.Perm.Prod.Layers, l)
	}
	r.elem(&p.Perm.WAt)
	r.elem(&p.Perm.SigmaAt)

	res := Proof{PIOP: p, Opening: &whir.Proof{}}
	rows := r.u32(maxPolys)
	for i := 0; i < rows && r.err == nil; i++ {
		res.Values = append(res.Values, r.elems(maxPoints))
	}

	o := res.Opening
	o.Initial = r.rounds()
	iters := r.u32(maxIter)
	for i := 0; i < iters && r.err == nil; i++ {
		var rp whir.RoundProof
		r.bytes(rp.Root[:])
		r.elem(&rp.OOD)
		rp.Queries = readQueries(r)
		rp.Sumcheck = r.rounds()
		o.Rounds = append(o.Rounds, rp)
	}
	o.Final = r.elems(maxFinal)
	o.FinalQueries = readQueries(r)

	if r.err != nil {
		return r.n, fmt.Errorf("%w: %v", ErrInvalidProof, r.err)
	}
	*proof = res
	return r.n, nil
}
