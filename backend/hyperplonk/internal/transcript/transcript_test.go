// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package transcript

import (
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestDeterministic(t *testing.T) {
	run := func() fr.Element {
		tr := New("test")
		tr.Append("a", []byte{1, 2, 3})
		return tr.Challenge("c")
	}
	a, b := run(), run()
	if !a.Equal(&b) {
		t.Fatal("same messages must give the same challenge")
	}
}

// Every earlier input must change the challenge: protocol name, label,
// data, order, and the split between label and data.
func TestChallengeDependsOnEverything(t *testing.T) {
	base := func() *Transcript {
		tr := New("test")
		tr.Append("a", []byte{1})
		tr.Append("b", []byte{2})
		return tr
	}
	ref := base().Challenge("c")

	variants := map[string]func() fr.Element{
		"protocol name": func() fr.Element {
			tr := New("test2")
			tr.Append("a", []byte{1})
			tr.Append("b", []byte{2})
			return tr.Challenge("c")
		},
		"data": func() fr.Element {
			tr := New("test")
			tr.Append("a", []byte{9})
			tr.Append("b", []byte{2})
			return tr.Challenge("c")
		},
		"label": func() fr.Element {
			tr := New("test")
			tr.Append("x", []byte{1})
			tr.Append("b", []byte{2})
			return tr.Challenge("c")
		},
		"order": func() fr.Element {
			tr := New("test")
			tr.Append("b", []byte{2})
			tr.Append("a", []byte{1})
			return tr.Challenge("c")
		},
		"challenge label": func() fr.Element { return base().Challenge("d") },
		"missing message": func() fr.Element {
			tr := New("test")
			tr.Append("a", []byte{1})
			return tr.Challenge("c")
		},
	}
	for name, f := range variants {
		if got := f(); got.Equal(&ref) {
			t.Errorf("challenge did not change with %s", name)
		}
	}

	// label/data boundary: ("ab", "c") vs ("a", "bc")
	t1, t2 := New("test"), New("test")
	t1.Append("ab", []byte("c"))
	t2.Append("a", []byte("bc"))
	c1, c2 := t1.Challenge("c"), t2.Challenge("c")
	if c1.Equal(&c2) {
		t.Error("label/data boundary is ambiguous")
	}
}

func TestConsecutiveChallengesDiffer(t *testing.T) {
	tr := New("test")
	a := tr.Challenge("c")
	b := tr.Challenge("c")
	if a.Equal(&b) {
		t.Fatal("two challenges with the same label must differ")
	}
}

// Claim S1: reducing an L-bit uniform integer mod r gives each residue a
// probability of at most ⌈2^L/r⌉/2^L ≤ 1/r + 2^−L. Checked here with exact
// integer arithmetic for L = 512 (used) and L = 256 (rejected: factor 1.134).
func TestReductionBias(t *testing.T) {
	r := fr.Modulus()
	maxProbTimesR := func(L uint) *big.Rat {
		pow := new(big.Int).Lsh(big.NewInt(1), L)
		q, rem := new(big.Int).QuoRem(pow, r, new(big.Int))
		if rem.Sign() != 0 {
			q.Add(q, big.NewInt(1)) // ⌈2^L / r⌉ preimages for the most likely residue
		}
		return new(big.Rat).SetFrac(new(big.Int).Mul(q, r), pow) // (⌈2^L/r⌉ / 2^L) · r
	}

	// L = 512: the excess over uniform is below 2^-256.
	excess := new(big.Rat).Sub(maxProbTimesR(512), big.NewRat(1, 1))
	bound := new(big.Rat).SetFrac(big.NewInt(1), new(big.Int).Lsh(big.NewInt(1), 256))
	if excess.Cmp(bound) >= 0 {
		t.Fatalf("512-bit reduction: relative excess %s not below 2^-256", excess.FloatString(80))
	}

	// L = 256: the most likely residue is 6·r/2^256 ≈ 1.134 times too likely.
	f, _ := maxProbTimesR(256).Float64()
	if f < 1.13 || f > 1.14 {
		t.Fatalf("256-bit reduction: expected factor ≈ 1.134, got %f", f)
	}
}

// The challenge is the documented function of the state (guards against an
// accidental change of the derivation).
func TestChallengeFormula(t *testing.T) {
	tr := New("p")
	state := tr.state
	got := tr.Challenge("c")

	var wide []byte
	for i := byte(0); i < 2; i++ {
		h := sha256.New()
		h.Write([]byte{0x02})
		h.Write(state[:])
		h.Write([]byte{0, 0, 0, 0, 0, 0, 0, 1, 'c', i})
		wide = h.Sum(wide)
	}
	want := new(big.Int).Mod(new(big.Int).SetBytes(wide), fr.Modulus())
	if got.BigInt(new(big.Int)).Cmp(want) != 0 {
		t.Fatal("challenge does not match the documented derivation")
	}
}
