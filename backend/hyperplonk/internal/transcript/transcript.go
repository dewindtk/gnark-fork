// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Package transcript derives verifier challenges by hashing (Fiat–Shamir).
//
// Status: working instantiation for the protocol packages and their tests.
// The byte-level format is not frozen; it is fixed in milestone M5
// (docs/hyperplonk/PLAN.md), where the statement binding is specified.
//
// Two properties are relied upon and tested here:
//
//  1. Every challenge depends on every message absorbed before it, in order
//     (the state is a hash chain). This is the "strong Fiat–Shamir" rule:
//     cᵢ = H(pp, x, a₁, …, aᵢ) (ePrint 2023/691, Def. 3).
//  2. A challenge is close to uniform in F. It is the reduction mod r of a
//     512-bit hash output, so each field element has probability at most
//     1/r + 2⁻⁵¹² (docs/hyperplonk/THEORY.md, claim S1). The soundness bounds
//     of the papers assume uniform challenges; with this derivation they hold
//     up to a factor 1 + 2⁻²⁵⁸.
package transcript

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Domain-separation tags: the first hashed byte tells the three uses of the
// hash function apart, so an absorb can never collide with a squeeze.
const (
	tagInit   = 0x00
	tagAbsorb = 0x01
	tagSqueez = 0x02
)

// Transcript is a sha256 hash chain. It is not safe for concurrent use.
type Transcript struct {
	state [sha256.Size]byte
}

// New returns a transcript whose initial state binds the protocol name.
func New(protocol string) *Transcript {
	t := &Transcript{}
	h := sha256.New()
	h.Write([]byte{tagInit})
	writeLenPrefixed(h, []byte(protocol))
	h.Sum(t.state[:0])
	return t
}

// Append absorbs a labelled message:
//
//	state ← H(0x01 ‖ state ‖ len(label) ‖ label ‖ len(data) ‖ data)
//
// Lengths are 8-byte big-endian, so (label, data) is parsed uniquely.
func (t *Transcript) Append(label string, data []byte) {
	h := sha256.New()
	h.Write([]byte{tagAbsorb})
	h.Write(t.state[:])
	writeLenPrefixed(h, []byte(label))
	writeLenPrefixed(h, data)
	h.Sum(t.state[:0])
}

// AppendElements absorbs field elements in their canonical 32-byte
// big-endian encoding.
func (t *Transcript) AppendElements(label string, xs ...fr.Element) {
	buf := make([]byte, 0, len(xs)*fr.Bytes)
	for i := range xs {
		b := xs[i].Bytes()
		buf = append(buf, b[:]...)
	}
	t.Append(label, buf)
}

// Challenge returns a field element derived from the state and absorbs it,
// so that two consecutive challenges differ:
//
//	wide ← H(0x02 ‖ state ‖ len(label) ‖ label ‖ 0) ‖ H(0x02 ‖ state ‖ len(label) ‖ label ‖ 1)
//	c    ← wide mod r
func (t *Transcript) Challenge(label string) fr.Element {
	var wide [2 * sha256.Size]byte
	for i := byte(0); i < 2; i++ {
		h := sha256.New()
		h.Write([]byte{tagSqueez})
		h.Write(t.state[:])
		writeLenPrefixed(h, []byte(label))
		h.Write([]byte{i})
		h.Sum(wide[:int(i)*sha256.Size])
	}
	var c fr.Element
	c.SetBytes(wide[:]) // big-endian integer reduced mod r
	t.AppendElements(label, c)
	return c
}

type writer interface{ Write([]byte) (int, error) }

func writeLenPrefixed(w writer, b []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(b)))
	w.Write(n[:])
	w.Write(b)
}
