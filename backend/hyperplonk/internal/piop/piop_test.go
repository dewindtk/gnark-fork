// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package piop

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"sort"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"
	"github.com/consensys/gnark/backend"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/internal/backend/circuits"

	"github.com/consensys/gnark/backend/hyperplonk/internal/grandprod"
	"github.com/consensys/gnark/backend/hyperplonk/internal/sumcheck"
)

// hashCommit commits to a table by hashing all of it. Binding follows from
// collision resistance; the "opening" is the whole table. Not succinct —
// a stand-in for WHIR that makes the PIOP testable end to end.
func hashCommit(t polynomial.MultiLin) Commitment {
	return Commitment{Bytes: hashTable(t), OOD: func(z fr.Element) fr.Element { return t.Evaluate(powers(z, len(t)), nil) }}
}

func hashTable(t polynomial.MultiLin) []byte {
	h := sha256.New()
	for i := range t {
		b := t[i].Bytes()
		h.Write(b[:])
	}
	return h.Sum(nil)
}

// powers returns (z, z², z⁴, …) with log₂(size) coordinates.
func powers(z fr.Element, size int) []fr.Element {
	var p []fr.Element
	for n := 1; n < size; n *= 2 {
		p = append(p, z)
		z.Square(&z)
	}
	return p
}

var (
	errCommitment = errors.New("opened table does not match the commitment")
	errOracle     = errors.New("evaluation claim is false for the committed polynomial")
)

// checkClaims is the opening check of the stand-in commitment.
func checkClaims(idx *Index, proof *Proof, t *Tables, claims []Claim) error {
	if !bytes.Equal(hashTable(t.W), proof.WCommit) {
		return errCommitment
	}
	oracles := map[Oracle]polynomial.MultiLin{
		OracleQL: idx.QL, OracleQR: idx.QR, OracleQM: idx.QM, OracleQO: idx.QO, OracleQC: idx.QC,
		OracleSigma: idx.Sigma, OracleW: t.W,
	}
	for _, c := range claims {
		point := c.Point
		if c.OOD {
			point = powers(c.Z, len(oracles[c.Oracle]))
		}
		if got := oracles[c.Oracle].Evaluate(point, nil); !got.Equal(&c.Value) {
			return errOracle
		}
	}
	return nil
}

func verifyFull(idx *Index, public []fr.Element, proof *Proof, t *Tables) error {
	claims, _, err := Verify(idx, public, proof)
	if err != nil {
		return err
	}
	return checkClaims(idx, proof, t, claims)
}

// TestCircuitSuite runs gnark's shared test circuits (the set used for the
// Groth16, PLONK and plonkfri backends) through the PIOP.
func TestCircuitSuite(t *testing.T) {
	names := make([]string, 0, len(circuits.Circuits))
	for k := range circuits.Circuits {
		names = append(names, k)
	}
	sort.Strings(names)
	ran, skipped := 0, 0
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
			idx, err := NewIndex(spr)
			if errors.Is(err, ErrCommitmentsUnsupported) {
				skipped++
				t.Skip(err)
			}
			if err != nil {
				t.Fatal(err)
			}
			ran++
			opts := backend.WithSolverOptions(solver.WithHints(tc.HintFunctions...))

			var honest *Proof
			var honestTables *Tables
			var honestPublic fr.Vector
			for i, a := range tc.ValidAssignments {
				w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
				if err != nil {
					t.Fatalf("valid[%d] witness: %v", i, err)
				}
				pw, _ := w.Public()
				public := pw.Vector().(fr.Vector)
				proof, tables, _, err := Prove(spr, idx, w, hashCommit, opts)
				if err != nil {
					t.Fatalf("valid[%d] prove: %v", i, err)
				}
				if err := verifyFull(idx, public, proof, tables); err != nil {
					t.Fatalf("valid[%d]: honest proof rejected: %v", i, err)
				}
				honest, honestTables, honestPublic = proof, tables, public
			}

			for i, a := range tc.InvalidAssignments {
				w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
				if err != nil {
					continue
				}
				if _, _, _, err := Prove(spr, idx, w, hashCommit, opts); err == nil {
					t.Errorf("invalid[%d]: Prove succeeded on an invalid witness", i)
				}
				// an honest proof must not verify for other public inputs
				pw, err := w.Public()
				if err != nil || idx.NbPublic == 0 || honest == nil {
					continue
				}
				public := pw.Vector().(fr.Vector)
				same := true
				for k := range public {
					same = same && public[k].Equal(&honestPublic[k])
				}
				if same {
					continue
				}
				if err := verifyFull(idx, public, honest, honestTables); err == nil {
					t.Errorf("invalid[%d]: honest proof verified for different public inputs", i)
				}
			}
		})
	}
	t.Logf("circuits run: %d, skipped (commitments): %d", ran, skipped)
}

// x²·y = out, out public.
type squareMul struct {
	X, Y frontend.Variable
	Out  frontend.Variable `gnark:",public"`
}

func (c *squareMul) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(api.Mul(c.X, c.X), c.Y), c.Out)
	return nil
}

type fixture struct {
	idx     *Index
	public  []fr.Element
	a, b, c []fr.Element
}

func newFixture(t *testing.T) fixture {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &squareMul{})
	if err != nil {
		t.Fatal(err)
	}
	spr := ccs.(*cs.SparseR1CS)
	idx, err := NewIndex(spr)
	if err != nil {
		t.Fatal(err)
	}
	w, _ := frontend.NewWitness(&squareMul{X: 3, Y: 2, Out: 18}, ecc.BN254.ScalarField())
	sol, err := spr.Solve(w)
	if err != nil {
		t.Fatal(err)
	}
	s := sol.(*cs.SparseR1CSSolution)
	clone := func(v fr.Vector) []fr.Element { return append([]fr.Element(nil), v...) }
	return fixture{idx, clone(w.Vector().(fr.Vector)[:idx.NbPublic]), clone(s.L), clone(s.R), clone(s.O)}
}

func (f fixture) run(public []fr.Element) error {
	proof, tables, _, err := ProveWires(f.idx, f.public, f.a, f.b, f.c, hashCommit)
	if err != nil {
		return err
	}
	return verifyFull(f.idx, public, proof, tables)
}

// slot returns a pointer to slot i of a ‖ b ‖ c.
func (f fixture) slot(i int) *fr.Element {
	n := len(f.a)
	switch i / n {
	case 0:
		return &f.a[i%n]
	case 1:
		return &f.b[i%n]
	default:
		return &f.c[i%n]
	}
}

// Cheating provers; each sub-test names the check that rejects.
func TestCheaters(t *testing.T) {
	var one fr.Element
	one.SetOne()

	t.Run("honest", func(t *testing.T) {
		f := newFixture(t)
		if err := f.run(f.public); err != nil {
			t.Fatal(err)
		}
	})

	// The value of one variable is changed in all its slots: every copy
	// constraint still holds, a gate does not.
	t.Run("gate violated, wiring intact: gate round sum", func(t *testing.T) {
		f := newFixture(t)
		n := len(f.a)
		// pick a slot of a real gate row (not a public-input or padding row)
		start := f.idx.NbPublic // column a of the first gate
		for i := start; ; {
			f.slot(i).Add(f.slot(i), &one)
			i = f.idx.perm[i]
			if i == start {
				break
			}
		}
		_ = n
		err := f.run(f.public)
		if !errors.Is(err, sumcheck.ErrRoundSum) {
			t.Fatalf("got %v", err)
		}
	})

	// Slot b of public-input row 0 has selector 0 (no gate looks at it) but
	// is wired to variable 0. Changing it breaks only the wiring.
	t.Run("copy constraint broken, gates intact: products differ", func(t *testing.T) {
		f := newFixture(t)
		if f.idx.NbPublic == 0 || f.idx.perm[len(f.a)] == len(f.a) {
			t.Fatal("test setup: expected a wired, gate-free slot")
		}
		f.b[0].Add(&f.b[0], &one)
		if err := f.run(f.public); !errors.Is(err, grandprod.ErrRoots) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("verified for another public input", func(t *testing.T) {
		f := newFixture(t)
		other := append([]fr.Element(nil), f.public...)
		other[0].Add(&other[0], &one)
		if err := f.run(other); err == nil {
			t.Fatal("accepted")
		}
	})

	// The prover claims a false public input and uses it consistently: the
	// transcript matches, the public-input row a₀ = pub₀ does not hold.
	t.Run("false public input used by the prover: gate round sum", func(t *testing.T) {
		f := newFixture(t)
		f.public[0].Add(&f.public[0], &one)
		if err := f.run(f.public); !errors.Is(err, sumcheck.ErrRoundSum) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("wrong number of public inputs", func(t *testing.T) {
		f := newFixture(t)
		proof, _, _, err := ProveWires(f.idx, f.public, f.a, f.b, f.c, hashCommit)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := Verify(f.idx, nil, proof); !errors.Is(err, ErrPublicInputs) {
			t.Fatalf("got %v", err)
		}
	})

	for i := range 8 {
		t.Run("one gate evaluation changed: gate final check", func(t *testing.T) {
			f := newFixture(t)
			proof, tables, _, _ := ProveWires(f.idx, f.public, f.a, f.b, f.c, hashCommit)
			proof.GateEvals[i].Add(&proof.GateEvals[i], &one)
			err := verifyFull(f.idx, f.public, proof, tables)
			// q_R, q_O may be zero-weighted at the point only by chance; the
			// change must be caught by the final check or, if the term it
			// multiplies cancels, by the oracle.
			if !errors.Is(err, sumcheck.ErrFinalCheck) && !errors.Is(err, errOracle) {
				t.Fatalf("evaluation %d: got %v", i, err)
			}
		})
	}

	t.Run("out-of-domain answer for w changed: oracle", func(t *testing.T) {
		f := newFixture(t)
		proof, tables, _, _ := ProveWires(f.idx, f.public, f.a, f.b, f.c, hashCommit)
		proof.WOOD.Add(&proof.WOOD, &one)
		if err := verifyFull(f.idx, f.public, proof, tables); err == nil {
			t.Fatal("accepted")
		}
	})

	t.Run("other wire table opened than committed", func(t *testing.T) {
		f := newFixture(t)
		proof, tables, _, _ := ProveWires(f.idx, f.public, f.a, f.b, f.c, hashCommit)
		tables.W[1].Add(&tables.W[1], &one)
		if err := verifyFull(f.idx, f.public, proof, tables); !errors.Is(err, errCommitment) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("proof for another circuit", func(t *testing.T) {
		f := newFixture(t)
		proof, tables, _, _ := ProveWires(f.idx, f.public, f.a, f.b, f.c, hashCommit)
		other := *f.idx
		other.Digest[0] ^= 1
		if err := verifyFull(&other, f.public, proof, tables); err == nil {
			t.Fatal("accepted")
		}
	})
}

// PI(r) computed by the verifier is the multilinear extension of the public
// input table (S7).
func TestPublicInputAt(t *testing.T) {
	const mu = 4
	public := make([]fr.Element, 5)
	table := make(polynomial.MultiLin, 1<<mu)
	for i := range public {
		public[i].MustSetRandom()
		table[i] = public[i]
	}
	r := make([]fr.Element, mu)
	for i := range r {
		r[i].MustSetRandom()
	}
	got, want := publicInputAt(public, r), table.Evaluate(r, nil)
	if !got.Equal(&want) {
		t.Fatal("PI(r) is not the multilinear extension of the public input table")
	}
}

// The index reproduces the circuit: on a solved witness every row satisfies
// the gate identity and every slot the wiring identity.
func TestIndexMatchesSolver(t *testing.T) {
	f := newFixture(t)
	n := len(f.a)
	for i := range n {
		var pi fr.Element
		if i < f.idx.NbPublic {
			pi = f.public[i]
		}
		v := gate.Eval([]fr.Element{f.idx.QL[i], f.idx.QR[i], f.idx.QM[i], f.idx.QO[i], f.idx.QC[i], pi, f.a[i], f.b[i], f.c[i]})
		if !v.IsZero() {
			t.Fatalf("row %d does not satisfy the gate identity", i)
		}
	}
	for i := range 3 * n {
		if !f.slot(i).Equal(f.slot(f.idx.perm[i])) {
			t.Fatalf("slot %d does not satisfy the wiring identity", i)
		}
	}
}

// The first challenge must depend on the public inputs and on the circuit.
//
// Why a separate test: with unbound public inputs the other tests still pass,
// because PI(r) enters the final check. But the proof would be forgeable
// (weak Fiat–Shamir, ePrint 2023/691): the prover runs the gate zerocheck
// with an arbitrary table PI* in place of the public inputs, obtains r, and
// only then solves the single linear equation PI_pub(r) = PI*(r) for the
// public inputs it claims.
func TestStatementIsBound(t *testing.T) {
	f := newFixture(t)
	ref := start(f.idx, f.public).Challenge("c")

	other := append([]fr.Element(nil), f.public...)
	other[0].SetUint64(7)
	if c := start(f.idx, other).Challenge("c"); c.Equal(&ref) {
		t.Fatal("challenges do not depend on the public inputs")
	}
	idx := *f.idx
	idx.Digest[0] ^= 1
	if c := start(&idx, f.public).Challenge("c"); c.Equal(&ref) {
		t.Fatal("challenges do not depend on the circuit digest")
	}
}
