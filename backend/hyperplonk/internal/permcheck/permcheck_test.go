// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package permcheck

import (
	"errors"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"

	"github.com/consensys/gnark/backend/hyperplonk/internal/grandprod"
	"github.com/consensys/gnark/backend/hyperplonk/internal/transcript"
)

var errOracle = errors.New("evaluation claim is false for the committed polynomial")

// instance returns a random permutation made of cycles and a table that is
// constant on every cycle, i.e. w(x) = w(σ(x)).
func instance(numVars int, rng *rand.Rand) ([]int, polynomial.MultiLin) {
	n := 1 << numVars
	order := rng.Perm(n)
	perm := make([]int, n)
	w := make(polynomial.MultiLin, n)
	for start := 0; start < n; {
		size := 1 + rng.Intn(4)
		if start+size > n {
			size = n - start
		}
		var val fr.Element
		val.MustSetRandom()
		for k := range size {
			perm[order[start+k]] = order[start+(k+1)%size]
			w[order[start+k]] = val
		}
		start += size
	}
	return perm, w
}

func run(numVars int, w, sigma polynomial.MultiLin, committedW polynomial.MultiLin, tamper func(*Proof)) error {
	p, err := Prove(transcript.New("test"), w, sigma)
	if err != nil {
		return err
	}
	if tamper != nil {
		tamper(&p)
	}
	claims, err := Verify(transcript.New("test"), numVars, p)
	if err != nil {
		return err
	}
	for _, c := range claims {
		var got fr.Element
		switch c.Oracle {
		case OracleW:
			got = committedW.Evaluate(c.Point, nil)
		case OracleSigma:
			got = sigma.Evaluate(c.Point, nil)
		}
		if !got.Equal(&c.Value) {
			return errOracle
		}
	}
	return nil
}

func TestComplete(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for numVars := 0; numVars <= 6; numVars++ {
		perm, w := instance(numVars, rng)
		sigma, err := SigmaTable(perm)
		if err != nil {
			t.Fatal(err)
		}
		if err := run(numVars, w, sigma, w, nil); err != nil {
			t.Fatalf("μ=%d: honest proof rejected: %v", numVars, err)
		}
	}
}

// S6: s_id is its own multilinear extension, so the verifier's direct
// formula equals the evaluation of the table [0, 1, …, 2^μ − 1].
func TestIdentityLabel(t *testing.T) {
	const numVars = 5
	table := make(polynomial.MultiLin, 1<<numVars)
	for i := range table {
		table[i].SetUint64(uint64(i))
	}
	x := make([]fr.Element, numVars)
	for i := range x {
		x[i].MustSetRandom()
	}
	got, want := IdentityLabel(x), table.Evaluate(x, nil)
	if !got.Equal(&want) {
		t.Fatal("IdentityLabel is not the multilinear extension of the index table")
	}
}

func TestSigmaTableRejectsNonPermutations(t *testing.T) {
	for _, bad := range [][]int{{0, 0}, {0, 2}, {-1, 0}} {
		if _, err := SigmaTable(bad); err == nil {
			t.Fatalf("%v accepted", bad)
		}
	}
}

func TestCheaters(t *testing.T) {
	const numVars = 5
	rng := rand.New(rand.NewSource(2))
	perm, w := instance(numVars, rng)
	sigma, _ := SigmaTable(perm)
	var one fr.Element
	one.SetOne()

	// find a slot that is not a fixed point of σ
	slot := 0
	for perm[slot] == slot {
		slot++
	}

	t.Run("one copy constraint broken: products differ", func(t *testing.T) {
		bad := w.Clone()
		bad[slot].Add(&bad[slot], &one)
		if err := run(numVars, bad, sigma, bad, nil); !errors.Is(err, grandprod.ErrRoots) {
			t.Fatalf("got %v", err)
		}
	})

	// Two slots of different cycles swap their values: the multiset of values
	// is unchanged, only the positions differ. This is what the labels
	// (β-term) are for.
	t.Run("values of two cycles swapped: products differ", func(t *testing.T) {
		bad := w.Clone()
		other := 0
		for bad[other].Equal(&bad[slot]) {
			other++
		}
		bad[slot], bad[other] = bad[other], bad[slot]
		if err := run(numVars, bad, sigma, bad, nil); !errors.Is(err, grandprod.ErrRoots) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("proof from a valid w, other w committed: oracle", func(t *testing.T) {
		committed := w.Clone()
		committed[slot].Add(&committed[slot], &one)
		if err := run(numVars, w, sigma, committed, nil); !errors.Is(err, errOracle) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("sent w(q) changed: linear check", func(t *testing.T) {
		err := run(numVars, w, sigma, w, func(p *Proof) { p.WAt.Add(&p.WAt, &one) })
		if !errors.Is(err, ErrLinearCheck) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("sent s_σ(q) changed: linear check", func(t *testing.T) {
		err := run(numVars, w, sigma, w, func(p *Proof) { p.SigmaAt.Add(&p.SigmaAt, &one) })
		if !errors.Is(err, ErrLinearCheck) {
			t.Fatalf("got %v", err)
		}
	})

	// w(q) and s_σ(q) changed together so that the denominator relation still
	// holds: only the numerator relation (the one with s_id) can catch it.
	t.Run("w(q) and s_σ(q) changed consistently for the denominator: linear check", func(t *testing.T) {
		beta := transcript.New("test").Challenge("permcheck/beta")
		err := run(numVars, w, sigma, w, func(p *Proof) {
			p.WAt.Add(&p.WAt, &one)
			p.SigmaAt.Sub(&p.SigmaAt, &beta)
		})
		if !errors.Is(err, ErrLinearCheck) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("a layer value of the product argument changed", func(t *testing.T) {
		err := run(numVars, w, sigma, w, func(p *Proof) { p.Prod.Layers[2].Evals[0].Add(&p.Prod.Layers[2].Evals[0], &one) })
		if !errors.Is(err, grandprod.ErrLayer) {
			t.Fatalf("got %v", err)
		}
	})
}

// S5: a false statement cannot be saved by a common zero of numerator and
// denominator. For every (β, γ) of a small exhaustive model, whenever the
// multisets differ after β and γ is not a root of F − G, numerator and
// denominator have no common zero. Checked over F₁₃ for a fixed false
// instance, all 13² challenge pairs.
func TestModelNoCommonZeroOutsideCountedEvent(t *testing.T) {
	const p = 13
	// 4 slots, σ swaps 0↔1 and fixes 2, 3; w violates the copy constraint.
	w := []uint64{5, 7, 1, 1}
	sigma := []uint64{1, 0, 2, 3}
	counted, total := 0, 0
	for beta := uint64(0); beta < p; beta++ {
		for gamma := uint64(0); gamma < p; gamma++ {
			total++
			F, G := uint64(1), uint64(1)
			commonZero := false
			for i := range w {
				num := (gamma + uint64(i) + beta*w[i]) % p
				den := (gamma + sigma[i] + beta*w[i]) % p
				F, G = F*num%p, G*den%p
				if num == 0 && den == 0 {
					commonZero = true
				}
			}
			if F == G {
				counted++ // the event the soundness bound already pays for
				continue
			}
			if commonZero {
				t.Fatalf("β=%d γ=%d: common zero although F(γ) ≠ G(γ)", beta, gamma)
			}
		}
	}
	// the counted event must stay within the bound 2·2^μ/p of steps 2 and 3
	if bound := total * 2 * len(w) / p; counted > bound {
		t.Fatalf("counted event %d/%d exceeds the bound %d", counted, total, bound)
	}
	t.Logf("challenge pairs with F(γ) = G(γ): %d/%d (bound 2·2^μ/p·p² = %d)", counted, total, total*2*len(w)/p)
}
