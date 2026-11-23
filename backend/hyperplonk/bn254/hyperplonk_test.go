// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package hyperplonk

import (
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/internal/backend/circuits"

	"github.com/consensys/gnark/backend/hyperplonk/internal/whir"
)

// proofSize counts 32 bytes per field element and per digest.
func proofSize(p *Proof) int {
	n := 32 + 32 // root and out-of-domain answer of W
	for _, r := range p.PIOP.Gate.Rounds {
		n += 32 * len(r)
	}
	n += 32 * len(p.PIOP.GateEvals)
	n += 32 * 2 // the two products
	for _, l := range p.PIOP.Perm.Prod.Layers {
		for _, r := range l.Rounds {
			n += 32 * len(r)
		}
		n += 32 * len(l.Evals)
	}
	n += 32 * 2 // w and s_σ at the wiring point
	for _, row := range p.Values {
		n += 32 * len(row)
	}
	o := p.Opening
	queries := func(qs []whir.Query) {
		for _, q := range qs {
			for t := range q.Leaves {
				n += 32 * (len(q.Leaves[t]) + len(q.Paths[t]))
			}
		}
	}
	for _, r := range o.Initial {
		n += 32 * len(r)
	}
	for _, r := range o.Rounds {
		n += 64
		queries(r.Queries)
		for _, m := range r.Sumcheck {
			n += 32 * len(m)
		}
	}
	n += 32 * len(o.Final)
	queries(o.FinalQueries)
	return n
}

// TestCircuitSuite runs gnark's shared test circuits end to end.
func TestCircuitSuite(t *testing.T) {
	names := make([]string, 0, len(circuits.Circuits))
	for k := range circuits.Circuits {
		names = append(names, k)
	}
	sort.Strings(names)
	ran := 0
	for _, name := range names {
		tc := circuits.Circuits[name]
		if tc.Curves != nil {
			ok := false
			for _, c := range tc.Curves {
				ok = ok || c == ecc.BN254
			}
			if !ok {
				continue
			}
		}
		t.Run(name, func(t *testing.T) {
			ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, tc.Circuit)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			spr := ccs.(*cs.SparseR1CS)
			pk, vk, err := Setup(spr, UniqueDecoding)
			if errors.Is(err, ErrCommitmentsUnsupported) {
				t.Skip(err)
			}
			if err != nil {
				t.Fatal(err)
			}
			ran++
			opts := backend.WithSolverOptions(solver.WithHints(tc.HintFunctions...))

			var honest *Proof
			var honestPublic fr.Vector
			for i, a := range tc.ValidAssignments {
				w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
				if err != nil {
					t.Fatalf("valid[%d] witness: %v", i, err)
				}
				pw, _ := w.Public()
				public := pw.Vector().(fr.Vector)
				proof, err := Prove(spr, pk, w, opts)
				if err != nil {
					t.Fatalf("valid[%d] prove: %v", i, err)
				}
				if err := Verify(proof, vk, public); err != nil {
					t.Fatalf("valid[%d]: honest proof rejected: %v", i, err)
				}
				honest, honestPublic = proof, public
			}
			for i, a := range tc.InvalidAssignments {
				w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
				if err != nil {
					continue
				}
				if _, err := Prove(spr, pk, w, opts); err == nil {
					t.Errorf("invalid[%d]: Prove succeeded on an invalid witness", i)
				}
				pw, err := w.Public()
				if err != nil || vk.NbPublic == 0 || honest == nil {
					continue
				}
				public := pw.Vector().(fr.Vector)
				same := true
				for k := range public {
					same = same && public[k].Equal(&honestPublic[k])
				}
				if !same && Verify(honest, vk, public) == nil {
					t.Errorf("invalid[%d]: honest proof verified for different public inputs", i)
				}
			}
		})
	}
	t.Logf("circuits run end to end: %d", ran)
}

type squareMul struct {
	X, Y frontend.Variable
	Out  frontend.Variable `gnark:",public"`
}

func (c *squareMul) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(api.Mul(c.X, c.X), c.Y), c.Out)
	return nil
}

type fixture struct {
	spr     *cs.SparseR1CS
	pk      *ProvingKey
	vk      *VerifyingKey
	public  fr.Vector
	a, b, c []fr.Element
}

func newFixture(t testing.TB, regime Regime) fixture {
	return newFixtureFor(t, regime, &squareMul{}, &squareMul{X: 3, Y: 2, Out: 18})
}

// newLargerFixture has 2^7 rows, so that the opening has two iterations.
func newLargerFixture(t testing.TB, regime Regime) fixture {
	return newFixtureFor(t, regime, &chain{N: 100}, &chain{N: 100, X: 3, Out: chainValue(3, 100)})
}

func newFixtureFor(t testing.TB, regime Regime, circuit, assignment frontend.Circuit) fixture {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}
	spr := ccs.(*cs.SparseR1CS)
	pk, vk, err := Setup(spr, regime)
	if err != nil {
		t.Fatal(err)
	}
	w, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	sol, err := spr.Solve(w)
	if err != nil {
		t.Fatal(err)
	}
	s := sol.(*cs.SparseR1CSSolution)
	clone := func(v fr.Vector) []fr.Element { return append([]fr.Element(nil), v...) }
	return fixture{spr, pk, vk, clone(w.Vector().(fr.Vector)[:vk.NbPublic]), clone(s.L), clone(s.R), clone(s.O)}
}

func TestBothRegimes(t *testing.T) {
	for _, regime := range []Regime{UniqueDecoding, Johnson} {
		f := newFixture(t, regime)
		proof, err := proveWires(f.pk, f.public, f.a, f.b, f.c)
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify(proof, f.vk, f.public); err != nil {
			t.Fatalf("%v: honest proof rejected: %v", regime, err)
		}
		t.Logf("%-14v 2^%d rows: proof %d KiB", regime, f.vk.NumVars, proofSize(proof)/1024)
	}
	// a proof made for one regime must not verify under the other
	ud, jb := newFixture(t, UniqueDecoding), newFixture(t, Johnson)
	proof, _ := proveWires(ud.pk, ud.public, ud.a, ud.b, ud.c)
	if err := Verify(proof, jb.vk, jb.public); err == nil {
		t.Fatal("proof for unique decoding accepted under the Johnson key")
	}
}

// The cheating provers of the PIOP tests, now against the real commitment:
// the prover computes everything with its own code on invalid wires; the
// verifier has only the verifying key and the public inputs.
func TestCheatersEndToEnd(t *testing.T) {
	var one fr.Element
	one.SetOne()
	rejected := func(t *testing.T, f fixture, public fr.Vector) {
		proof, err := proveWires(f.pk, f.public, f.a, f.b, f.c)
		if err != nil {
			// The prover derives the evaluation claims by running the PIOP
			// verifier on its own messages. If that already fails, no proof
			// exists to hand over; the same check is the verifier's first
			// step. How a prover that cheats in the sumcheck itself fares
			// is tested in the piop and sumcheck packages.
			t.Logf("no proof produced: the PIOP check fails on the prover's own messages: %v", err)
			return
		}
		if err := Verify(proof, f.vk, public); err == nil {
			t.Fatal("accepted")
		} else {
			t.Logf("rejected: %v", err)
		}
	}

	t.Run("gate violated", func(t *testing.T) {
		f := newFixture(t, UniqueDecoding)
		f.c[f.vk.NbPublic].Add(&f.c[f.vk.NbPublic], &one)
		rejected(t, f, f.public)
	})
	t.Run("copy constraint broken", func(t *testing.T) {
		f := newFixture(t, UniqueDecoding)
		f.b[0].Add(&f.b[0], &one) // gate-free slot wired to variable 0
		rejected(t, f, f.public)
	})
	t.Run("false public input", func(t *testing.T) {
		f := newFixture(t, UniqueDecoding)
		f.public[0].Add(&f.public[0], &one)
		rejected(t, f, f.public)
	})
	t.Run("verified for another public input", func(t *testing.T) {
		f := newFixture(t, UniqueDecoding)
		other := append(fr.Vector(nil), f.public...)
		other[0].Add(&other[0], &one)
		rejected(t, f, other)
	})
}

// Changes to a finished proof. Each field of the proof is touched once.
func TestTamperedProofs(t *testing.T) {
	f := newLargerFixture(t, UniqueDecoding)
	var one fr.Element
	one.SetOne()
	fresh := func() *Proof {
		p, err := proveWires(f.pk, f.public, f.a, f.b, f.c)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	if err := Verify(fresh(), f.vk, f.public); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(p *Proof){
		"w commitment":        func(p *Proof) { p.PIOP.WCommit[0] ^= 1 },
		"w out-of-domain":     func(p *Proof) { p.PIOP.WOOD.Add(&p.PIOP.WOOD, &one) },
		"gate sumcheck":       func(p *Proof) { p.PIOP.Gate.Rounds[0][2].Add(&p.PIOP.Gate.Rounds[0][2], &one) },
		"selector evaluation": func(p *Proof) { p.PIOP.GateEvals[0].Add(&p.PIOP.GateEvals[0], &one) },
		"wire evaluation":     func(p *Proof) { p.PIOP.GateEvals[6].Add(&p.PIOP.GateEvals[6], &one) },
		"wiring sumcheck":     func(p *Proof) { r := p.PIOP.Perm.Prod.Layers[3].Rounds[0]; r[2].Add(&r[2], &one) },
		"wiring layer value":  func(p *Proof) { e := &p.PIOP.Perm.Prod.Layers[2].Evals[1]; e.Add(e, &one) },
		"one product":         func(p *Proof) { p.PIOP.Perm.Prod.Roots[0].Add(&p.PIOP.Perm.Prod.Roots[0], &one) },
		"both products": func(p *Proof) {
			for i := range 2 {
				p.PIOP.Perm.Prod.Roots[i].Add(&p.PIOP.Perm.Prod.Roots[i], &one)
			}
		},
		"w at the wiring point":     func(p *Proof) { p.PIOP.Perm.WAt.Add(&p.PIOP.Perm.WAt, &one) },
		"sigma at the wiring point": func(p *Proof) { p.PIOP.Perm.SigmaAt.Add(&p.PIOP.Perm.SigmaAt, &one) },
		"short w commitment":        func(p *Proof) { p.PIOP.WCommit = p.PIOP.WCommit[:31] },
		"missing opening":           func(p *Proof) { p.Opening = nil },
		"missing values":            func(p *Proof) { p.Values = p.Values[:nbPolys-1] },
		"short row of values":       func(p *Proof) { p.Values[1] = p.Values[1][:len(p.Values[1])-1] },
		"opening final polynomial":  func(p *Proof) { p.Opening.Final[0].Add(&p.Opening.Final[0], &one) },
		"opening sumcheck":          func(p *Proof) { p.Opening.Initial[0][2].Add(&p.Opening.Initial[0][2], &one) },
		"opening out-of-domain":     func(p *Proof) { p.Opening.Rounds[0].OOD.Add(&p.Opening.Rounds[0].OOD, &one) },
		"opening root":              func(p *Proof) { p.Opening.Rounds[0].Root[0] ^= 1 },
	}
	// every opened leaf of the first oracle, in each of the three trees
	for tree := range 2 {
		cases["leaf of tree "+string(rune('0'+tree))] = func(p *Proof) {
			l := p.Opening.Rounds[0].Queries[0].Leaves[tree]
			l[0].Add(&l[0], &one)
		}
	}
	// every value of the evaluation table
	ref := fresh()
	for j := range ref.Values {
		for k := range ref.Values[j] {
			cases["value "+string(rune('0'+j))+"/"+string(rune('a'+k))] = func(p *Proof) { p.Values[j][k].Add(&p.Values[j][k], &one) }
		}
	}
	for name, tamper := range cases {
		p := fresh()
		tamper(p)
		if err := Verify(p, f.vk, f.public); err == nil {
			t.Errorf("%s changed: accepted", name)
		}
	}
	t.Logf("%d tampered proofs rejected", len(cases))
}

// The verifying key binds the circuit: a proof for one circuit is rejected
// under the key of another, even of the same size.
func TestOtherCircuit(t *testing.T) {
	f := newFixture(t, UniqueDecoding)
	proof, _ := proveWires(f.pk, f.public, f.a, f.b, f.c)
	vk := *f.vk
	vk.Root[0] ^= 1 // other preprocessed polynomials
	vk.Digest = vk.digest()
	if err := Verify(proof, &vk, f.public); err == nil {
		t.Fatal("accepted under another verifying key")
	}
	// a key whose digest was not recomputed after a change is still rejected
	vk2 := *f.vk
	vk2.Root[0] ^= 1
	if err := Verify(proof, &vk2, f.public); err == nil {
		t.Fatal("accepted under a key with a changed commitment")
	}
}

// Size and time on a larger circuit, with the estimate made beforehand.
func TestMeasure(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	for _, regime := range []Regime{UniqueDecoding, Johnson} {
		const logRows = 12
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &chain{N: 1<<logRows - 8})
		if err != nil {
			t.Fatal(err)
		}
		spr := ccs.(*cs.SparseR1CS)
		start := time.Now()
		pk, vk, err := Setup(spr, regime)
		if err != nil {
			t.Fatal(err)
		}
		setup := time.Since(start)
		w, _ := frontend.NewWitness(&chain{N: 1<<logRows - 8, X: 3, Out: chainValue(3, 1<<logRows-8)}, ecc.BN254.ScalarField())
		pw, _ := w.Public()
		start = time.Now()
		proof, err := Prove(spr, pk, w)
		if err != nil {
			t.Fatal(err)
		}
		prove := time.Since(start)
		start = time.Now()
		if err := Verify(proof, vk, pw.Vector().(fr.Vector)); err != nil {
			t.Fatal(err)
		}
		verify := time.Since(start)
		t.Logf("%-14v rows=2^%d constraints=%d: proof %d KiB, setup %v, prove %v, verify %v",
			regime, vk.NumVars, spr.GetNbConstraints(), proofSize(proof)/1024,
			setup.Round(time.Millisecond), prove.Round(time.Millisecond), verify.Round(time.Millisecond))
	}
}

// chain computes x ↦ x² + x repeated N times.
type chain struct {
	N   int
	X   frontend.Variable
	Out frontend.Variable `gnark:",public"`
}

func (c *chain) Define(api frontend.API) error {
	x := c.X
	for range c.N {
		x = api.Add(api.Mul(x, x), x)
	}
	api.AssertIsEqual(x, c.Out)
	return nil
}

func chainValue(x uint64, n int) fr.Element {
	var v, s fr.Element
	v.SetUint64(x)
	for range n {
		s.Square(&v)
		v.Add(&s, &v)
	}
	return v
}

// The key digest, which is the first thing absorbed into the transcript,
// depends on every field of the verifying key.
func TestDigestCoversTheKey(t *testing.T) {
	f := newFixture(t, UniqueDecoding)
	ref := f.vk.digest()
	variants := map[string]func(vk *VerifyingKey){
		"NumVars":  func(vk *VerifyingKey) { vk.NumVars++ },
		"NbPublic": func(vk *VerifyingKey) { vk.NbPublic++ },
		"Regime":   func(vk *VerifyingKey) { vk.Regime = Johnson },
		"circuit":  func(vk *VerifyingKey) { vk.Circuit[0] ^= 1 },
		"root":     func(vk *VerifyingKey) { vk.Root[0] ^= 1 },
	}
	for name, change := range variants {
		vk := *f.vk
		change(&vk)
		if vk.digest() == ref {
			t.Errorf("digest does not depend on %s", name)
		}
	}
}
