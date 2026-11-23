// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package grandprod

import (
	"errors"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"

	"github.com/consensys/gnark/backend/hyperplonk/internal/sumcheck"
	"github.com/consensys/gnark/backend/hyperplonk/internal/transcript"
)

var errOracle = errors.New("final claim is false for the table")

func randomTable(numVars int) polynomial.MultiLin {
	t := make(polynomial.MultiLin, 1<<numVars)
	for i := range t {
		t[i].MustSetRandom()
	}
	return t
}

// shuffled returns a table with the same entries in another order.
func shuffled(t polynomial.MultiLin, rng *rand.Rand) polynomial.MultiLin {
	out := t.Clone()
	rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

func verifyFull(numVars int, p Proof, first, second polynomial.MultiLin) error {
	q, claims, err := Verify(transcript.New("test"), numVars, p)
	if err != nil {
		return err
	}
	// the tables' values at q, computed independently of the prover
	if v := first.Evaluate(q, nil); !v.Equal(&claims[0]) {
		return errOracle
	}
	if v := second.Evaluate(q, nil); !v.Equal(&claims[1]) {
		return errOracle
	}
	return nil
}

// The identity each iteration rests on:
// V_i(z) = Σ_x eq(z, x)·V_{i+1}(x, 0)·V_{i+1}(x, 1) for z outside the hypercube.
func TestLayerIdentity(t *testing.T) {
	layers := tree(randomTable(5))
	for i := 0; i < 5; i++ {
		z := make([]fr.Element, i)
		for k := range z {
			z[k].MustSetRandom()
		}
		eq := make(polynomial.MultiLin, 1<<i)
		eq[0].SetOne()
		if i > 0 {
			eq.Eq(z)
		}
		l, r := halves(layers[i+1])
		var sum, term fr.Element
		for x := range eq {
			term.Mul(&l[x], &r[x]).Mul(&term, &eq[x])
			sum.Add(&sum, &term)
		}
		if want := layers[i].Evaluate(z, nil); !want.Equal(&sum) {
			t.Fatalf("layer %d: identity fails", i)
		}
	}
	// and the root is the product of the leaves
	var prod fr.Element
	prod.SetOne()
	for _, v := range layers[5] {
		prod.Mul(&prod, &v)
	}
	if !prod.Equal(&layers[0][0]) {
		t.Fatal("root is not the product")
	}
}

func TestComplete(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for numVars := 0; numVars <= 7; numVars++ {
		first := randomTable(numVars)
		second := shuffled(first, rng)
		p, q, claims, err := Prove(transcript.New("test"), first, second)
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyFull(numVars, p, first, second); err != nil {
			t.Fatalf("μ=%d: honest proof rejected: %v", numVars, err)
		}
		// the prover's returned claims are the tables' values at q
		if v := first.Evaluate(q, nil); !v.Equal(&claims[0]) {
			t.Fatalf("μ=%d: prover's claim is not the first table at q", numVars)
		}
	}
}

// Tables containing zeros are no special case (no division is involved).
func TestZeros(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	first := randomTable(4)
	first[3].SetZero()
	second := shuffled(first, rng)
	p, _, _, _ := Prove(transcript.New("test"), first, second)
	if err := verifyFull(4, p, first, second); err != nil {
		t.Fatal(err)
	}
	// both products zero, but different tables: accepted, as it must be —
	// the statement "equal products" is true. (The caller's multiset
	// argument counts this event; see permutation check.)
	other := randomTable(4)
	other[9].SetZero()
	p, _, _, _ = Prove(transcript.New("test"), first, other)
	if err := verifyFull(4, p, first, other); err != nil {
		t.Fatal(err)
	}
}

func TestCheaters(t *testing.T) {
	const numVars = 5
	rng := rand.New(rand.NewSource(3))
	first := randomTable(numVars)
	second := shuffled(first, rng)
	var one fr.Element
	one.SetOne()

	t.Run("different products, honest messages: roots", func(t *testing.T) {
		bad := second.Clone()
		bad[4].Add(&bad[4], &one)
		p, _, _, _ := Prove(transcript.New("test"), first, bad)
		if err := verifyFull(numVars, p, first, bad); !errors.Is(err, ErrRoots) {
			t.Fatalf("got %v", err)
		}
	})

	// The prover lies about one root to make them equal and is otherwise
	// honest: the first layer's values multiply to the true root.
	t.Run("different products, one root overwritten: first layer", func(t *testing.T) {
		bad := second.Clone()
		bad[4].Add(&bad[4], &one)
		tr := &rootTamper{Transcript: transcript.New("test")}
		p, _, _, _ := Prove(tr, first, bad)
		if !p.Roots[0].Equal(&p.Roots[1]) {
			t.Fatal("test setup: roots should be equal now")
		}
		if err := verifyFull(numVars, p, first, bad); !errors.Is(err, ErrLayer) {
			t.Fatalf("got %v", err)
		}
	})

	// The lie is moved into the right child of the root: the prover reports
	// the true left child and a right child chosen so that their product is
	// the false root. Only the random point on the line between the two
	// children (step 3) forces the right child to be checked further down.
	t.Run("different products, false right child at the root: next layer", func(t *testing.T) {
		bad := second.Clone()
		bad[4].Add(&bad[4], &one)
		tr := &rootTamper{Transcript: transcript.New("test"), fixRightChild: true}
		p, _, _, _ := Prove(tr, first, bad)
		var prod fr.Element
		prod.Mul(&p.Layers[0].Evals[2], &p.Layers[0].Evals[3])
		if !p.Roots[0].Equal(&p.Roots[1]) || !prod.Equal(&p.Roots[1]) {
			t.Fatal("test setup: the false root should be consistent with the reported children")
		}
		err := verifyFull(numVars, p, first, bad)
		if !errors.Is(err, sumcheck.ErrRoundSum) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("proof for other tables than the committed ones: final claims", func(t *testing.T) {
		p, _, _, _ := Prove(transcript.New("test"), first, second)
		committed := second.Clone()
		committed[4], committed[5] = committed[5], committed[4] // same product, other table
		if committed[4].Equal(&committed[5]) {
			t.Skip()
		}
		if err := verifyFull(numVars, p, first, committed); !errors.Is(err, errOracle) {
			t.Fatalf("got %v", err)
		}
	})

	for layer := 0; layer < numVars; layer++ {
		for k := range 4 {
			p, _, _, _ := Prove(transcript.New("test"), first, second)
			p.Layers[layer].Evals[k].Add(&p.Layers[layer].Evals[k], &one)
			if err := verifyFull(numVars, p, first, second); !errors.Is(err, ErrLayer) {
				t.Fatalf("layer %d value %d changed: got %v", layer, k, err)
			}
		}
	}

	t.Run("sumcheck message changed", func(t *testing.T) {
		p, _, _, _ := Prove(transcript.New("test"), first, second)
		p.Layers[3].Rounds[1][0].Add(&p.Layers[3].Rounds[1][0], &one)
		if err := verifyFull(numVars, p, first, second); !errors.Is(err, sumcheck.ErrRoundSum) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("wrong shapes", func(t *testing.T) {
		p, _, _, _ := Prove(transcript.New("test"), first, second)
		q := p
		q.Layers = p.Layers[:numVars-1]
		if err := verifyFull(numVars, q, first, second); !errors.Is(err, ErrProofShape) {
			t.Fatalf("missing layer: got %v", err)
		}
		q = p
		q.Layers = append([]LayerProof(nil), p.Layers...)
		q.Layers[2].Rounds = q.Layers[2].Rounds[:1]
		if err := verifyFull(numVars, q, first, second); !errors.Is(err, ErrProofShape) {
			t.Fatalf("missing round: got %v", err)
		}
	})
}

// rootTamper makes the second root equal to the first, in the message that is
// absorbed and therefore in the proof. With fixRightChild it also replaces
// the second table's right child at the root by (false root)/(left child).
type rootTamper struct {
	*transcript.Transcript
	fixRightChild bool
	root          fr.Element
	layers        int
}

func (r *rootTamper) AppendElements(label string, xs ...fr.Element) {
	switch label {
	case "grandprod/roots":
		xs[1] = xs[0]
		r.root = xs[0]
	case "grandprod/evals":
		if r.fixRightChild && r.layers == 0 {
			xs[3].Div(&r.root, &xs[2])
		}
		r.layers++
	}
	r.Transcript.AppendElements(label, xs...)
}
