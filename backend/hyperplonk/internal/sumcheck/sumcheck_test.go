// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package sumcheck

import (
	"errors"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"

	"github.com/consensys/gnark/backend/hyperplonk/internal/transcript"
)

// g(a, b, c) = a·b·c + 2·a + b, total degree 3.
var testGate = Gate{
	Degree: 3,
	Eval: func(v []fr.Element) fr.Element {
		var r, t fr.Element
		r.Mul(&v[0], &v[1]).Mul(&r, &v[2])
		t.Double(&v[0])
		r.Add(&r, &t).Add(&r, &v[1])
		return r
	},
}

func randomTables(k, numVars int) []polynomial.MultiLin {
	tables := make([]polynomial.MultiLin, k)
	for j := range tables {
		tables[j] = make(polynomial.MultiLin, 1<<numVars)
		for i := range tables[j] {
			tables[j][i].MustSetRandom()
		}
	}
	return tables
}

// bruteSum computes Σ_b g(T(b)) directly from the definition.
func bruteSum(tables []polynomial.MultiLin, g Gate) fr.Element {
	var sum fr.Element
	vals := make([]fr.Element, len(tables))
	for b := range tables[0] {
		for j := range tables {
			vals[j] = tables[j][b]
		}
		v := g.Eval(vals)
		sum.Add(&sum, &v)
	}
	return sum
}

func evalAll(tables []polynomial.MultiLin, point []fr.Element) []fr.Element {
	vals := make([]fr.Element, len(tables))
	for j := range tables {
		vals[j] = tables[j].Evaluate(point, nil)
	}
	return vals
}

func verifyFull(claim fr.Element, numVars int, g Gate, proof Proof, tables []polynomial.MultiLin) error {
	point, final, err := Verify(transcript.New("test"), claim, numVars, g.Degree, proof)
	if err != nil {
		return err
	}
	// the oracle values are computed independently of the prover
	return CheckFinal(g, evalAll(tables, point), final)
}

func TestSumcheckComplete(t *testing.T) {
	for numVars := 0; numVars <= 5; numVars++ {
		tables := randomTables(3, numVars)
		claim := bruteSum(tables, testGate)
		proof, point, vals, err := Prove(transcript.New("test"), claim, tables, testGate)
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyFull(claim, numVars, testGate, proof, tables); err != nil {
			t.Fatalf("μ=%d: honest proof rejected: %v", numVars, err)
		}
		// the prover's returned values are the table evaluations at the point
		want := evalAll(tables, point)
		for j := range want {
			if !want[j].Equal(&vals[j]) {
				t.Fatalf("μ=%d: prover value %d is not T(r)", numVars, j)
			}
		}
	}
}

// The round polynomial is the one the protocol defines: check every sent
// value against the definition sᵢ(t) = Σ_b p(r₁..r_{i−1}, t, b).
func TestRoundPolynomialDefinition(t *testing.T) {
	const numVars = 3
	tables := randomTables(3, numVars)
	claim := bruteSum(tables, testGate)
	proof, point, _, err := Prove(transcript.New("test"), claim, tables, testGate)
	if err != nil {
		t.Fatal(err)
	}
	for i := range numVars {
		rest := numVars - i - 1
		for tt := 0; tt <= testGate.Degree; tt++ {
			var want fr.Element
			x := make([]fr.Element, numVars)
			copy(x, point[:i])
			x[i].SetInt64(int64(tt))
			for b := 0; b < 1<<rest; b++ {
				for k := range rest {
					x[i+1+k].SetUint64(uint64(b>>(rest-1-k)) & 1)
				}
				v := testGate.Eval(evalAll(tables, x))
				want.Add(&want, &v)
			}
			if !want.Equal(&proof.Rounds[i][tt]) {
				t.Fatalf("round %d, value at %d differs from the definition", i+1, tt)
			}
		}
	}
}

// The claimed sum is part of the statement and must influence the challenges
// (strong Fiat–Shamir, ePrint 2023/691 Def. 3): otherwise a prover could fix
// its messages first and choose the claim afterwards.
func TestClaimIsBound(t *testing.T) {
	tables := randomTables(3, 3)
	claim := bruteSum(tables, testGate)
	var other fr.Element
	other.SetOne()
	other.Add(&other, &claim)
	_, p1, _, _ := Prove(transcript.New("test"), claim, tables, testGate)
	_, p2, _, _ := Prove(transcript.New("test"), other, tables, testGate)
	if p1[0].Equal(&p2[0]) {
		t.Fatal("the first challenge does not depend on the claimed sum")
	}
}

func TestInterpolate(t *testing.T) {
	// s(X) = 3X³ + X + 5
	s := func(x fr.Element) fr.Element {
		var r, c fr.Element
		r.Square(&x).Mul(&r, &x)
		c.SetUint64(3)
		r.Mul(&r, &c).Add(&r, &x)
		c.SetUint64(5)
		r.Add(&r, &c)
		return r
	}
	evals := make([]fr.Element, 4)
	for i := range evals {
		var x fr.Element
		x.SetUint64(uint64(i))
		evals[i] = s(x)
	}
	var x fr.Element
	x.MustSetRandom()
	got, want := interpolate(evals, x), s(x)
	if !got.Equal(&want) {
		t.Fatal("interpolation differs from the polynomial")
	}
	for i := range evals {
		x.SetUint64(uint64(i))
		if got := interpolate(evals, x); !got.Equal(&evals[i]) {
			t.Fatalf("interpolation at node %d", i)
		}
	}
}

// Cheating provers. For each, the test records which check rejects.
func TestSumcheckCheaters(t *testing.T) {
	const numVars = 4
	tables := randomTables(3, numVars)
	claim := bruteSum(tables, testGate)
	var one, wrong fr.Element
	one.SetOne()
	wrong.Add(&claim, &one)

	honest := func(c fr.Element) Proof {
		p, _, _, err := Prove(transcript.New("test"), c, tables, testGate)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	clone := func(p Proof) Proof {
		q := Proof{Rounds: make([][]fr.Element, len(p.Rounds))}
		for i := range p.Rounds {
			q.Rounds[i] = append([]fr.Element(nil), p.Rounds[i]...)
		}
		return q
	}

	t.Run("wrong claim, honest messages: round 1 sum", func(t *testing.T) {
		err := verifyFull(wrong, numVars, testGate, honest(wrong), tables)
		if !errors.Is(err, ErrRoundSum) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("wrong claim, first message adjusted: round 2 sum", func(t *testing.T) {
		p := clone(honest(wrong))
		p.Rounds[0][0].Add(&p.Rounds[0][0], &one) // now s₁(0)+s₁(1) = wrong claim
		err := verifyFull(wrong, numVars, testGate, p, tables)
		if !errors.Is(err, ErrRoundSum) {
			t.Fatalf("got %v", err)
		}
	})

	// The strongest simple cheater: every message is shifted so that every
	// round check passes. Only the final check against the oracle values
	// can catch it — this is the check the soundness proof ends with.
	t.Run("wrong claim, all rounds consistent: final check", func(t *testing.T) {
		tr := transcript.New("test")
		bindStatement(tr, wrong, numVars, testGate.Degree)
		work := make([]polynomial.MultiLin, len(tables))
		for j := range tables {
			work[j] = tables[j].Clone()
		}
		cur := wrong
		var two, half fr.Element
		two.SetUint64(2)
		half.Inverse(&two)
		p := Proof{}
		for range numVars {
			// honest round values for the current tables
			evals := make([]fr.Element, testGate.Degree+1)
			h := len(work[0]) / 2
			for b := range h {
				for tt := 0; tt <= testGate.Degree; tt++ {
					var x fr.Element
					x.SetUint64(uint64(tt))
					vals := make([]fr.Element, len(work))
					for j := range work {
						var d fr.Element
						d.Sub(&work[j][b+h], &work[j][b]).Mul(&d, &x)
						vals[j].Add(&work[j][b], &d)
					}
					v := testGate.Eval(vals)
					evals[tt].Add(&evals[tt], &v)
				}
			}
			// shift by a constant so that s(0)+s(1) = cur
			var shift fr.Element
			shift.Add(&evals[0], &evals[1])
			shift.Sub(&cur, &shift).Mul(&shift, &half)
			for i := range evals {
				evals[i].Add(&evals[i], &shift)
			}
			p.Rounds = append(p.Rounds, evals)
			tr.AppendElements("sumcheck/round", evals...)
			r := tr.Challenge("sumcheck/r")
			cur = interpolate(evals, r)
			for j := range work {
				work[j].Fold(r)
			}
		}
		_, _, err := Verify(transcript.New("test"), wrong, numVars, testGate.Degree, p)
		if err != nil {
			t.Fatalf("the cheater is meant to pass every round check, got %v", err)
		}
		if err := verifyFull(wrong, numVars, testGate, p, tables); !errors.Is(err, ErrFinalCheck) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("message with one value too many (degree overflow)", func(t *testing.T) {
		p := clone(honest(claim))
		p.Rounds[1] = append(p.Rounds[1], one)
		if err := verifyFull(claim, numVars, testGate, p, tables); !errors.Is(err, ErrRoundLength) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("message with one value too few", func(t *testing.T) {
		p := clone(honest(claim))
		p.Rounds[1] = p.Rounds[1][:testGate.Degree]
		if err := verifyFull(claim, numVars, testGate, p, tables); !errors.Is(err, ErrRoundLength) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("missing round", func(t *testing.T) {
		p := clone(honest(claim))
		p.Rounds = p.Rounds[:numVars-1]
		if err := verifyFull(claim, numVars, testGate, p, tables); !errors.Is(err, ErrRoundCount) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("extra round", func(t *testing.T) {
		p := clone(honest(claim))
		p.Rounds = append(p.Rounds, p.Rounds[0])
		if err := verifyFull(claim, numVars, testGate, p, tables); !errors.Is(err, ErrRoundCount) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("one value changed in the last round", func(t *testing.T) {
		p := clone(honest(claim))
		last := p.Rounds[numVars-1]
		last[2].Add(&last[2], &one) // s(0)+s(1) unchanged: only the final check sees it
		if err := verifyFull(claim, numVars, testGate, p, tables); !errors.Is(err, ErrFinalCheck) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("proof for other tables", func(t *testing.T) {
		other := randomTables(3, numVars)
		p, _, _, _ := Prove(transcript.New("test"), bruteSum(other, testGate), other, testGate)
		if err := verifyFull(claim, numVars, testGate, p, tables); err == nil {
			t.Fatal("accepted")
		}
	})
}

// c = a·b on every row: the gate a·b − c vanishes on the hypercube.
var mulGate = Gate{
	Degree: 2,
	Eval: func(v []fr.Element) fr.Element {
		var r fr.Element
		r.Mul(&v[0], &v[1]).Sub(&r, &v[2])
		return r
	},
}

func satisfyingTables(numVars int) []polynomial.MultiLin {
	tables := randomTables(3, numVars)
	for i := range tables[2] {
		tables[2][i].Mul(&tables[0][i], &tables[1][i])
	}
	return tables
}

func verifyZeroFull(numVars int, g Gate, proof Proof, tables []polynomial.MultiLin) error {
	res, err := VerifyZero(transcript.New("test"), numVars, g.Degree, proof)
	if err != nil {
		return err
	}
	return res.Check(g, evalAll(tables, res.Point))
}

func TestZerocheckComplete(t *testing.T) {
	for numVars := 0; numVars <= 5; numVars++ {
		tables := satisfyingTables(numVars)
		proof, _, _, err := ProveZero(transcript.New("test"), tables, mulGate)
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyZeroFull(numVars, mulGate, proof, tables); err != nil {
			t.Fatalf("μ=%d: honest proof rejected: %v", numVars, err)
		}
	}
}

func TestZerocheckCheaters(t *testing.T) {
	const numVars = 4
	var one fr.Element
	one.SetOne()

	t.Run("one violated row, honest messages: round 1 sum", func(t *testing.T) {
		tables := satisfyingTables(numVars)
		tables[2][5].Add(&tables[2][5], &one)
		proof, _, _, err := ProveZero(transcript.New("test"), tables, mulGate)
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyZeroFull(numVars, mulGate, proof, tables); !errors.Is(err, ErrRoundSum) {
			t.Fatalf("got %v", err)
		}
	})

	// The prover computes the proof from satisfying tables, but the committed
	// tables (what the oracles answer from) violate one row.
	t.Run("proof from other tables than the committed ones: final check", func(t *testing.T) {
		tables := satisfyingTables(numVars)
		proof, _, _, err := ProveZero(transcript.New("test"), tables, mulGate)
		if err != nil {
			t.Fatal(err)
		}
		committed := make([]polynomial.MultiLin, len(tables))
		for j := range tables {
			committed[j] = tables[j].Clone()
		}
		committed[2][5].Add(&committed[2][5], &one)
		if err := verifyZeroFull(numVars, mulGate, proof, committed); !errors.Is(err, ErrFinalCheck) {
			t.Fatalf("got %v", err)
		}
	})

	// The challenge τ must come after the tables are fixed. Here the
	// verifier's transcript differs from the prover's, so τ differs.
	t.Run("different transcript", func(t *testing.T) {
		tables := satisfyingTables(numVars)
		proof, _, _, err := ProveZero(transcript.New("other"), tables, mulGate)
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyZeroFull(numVars, mulGate, proof, tables); err == nil {
			t.Fatal("accepted")
		}
	})
}

// eq table and EvalEq agree: the multilinear extension of the table built by
// MultiLin.Eq(τ), evaluated at r, is eq(r, τ). The zerocheck verifier relies
// on this identity.
func TestEqTableMatchesEvalEq(t *testing.T) {
	const numVars = 4
	tau := make([]fr.Element, numVars)
	r := make([]fr.Element, numVars)
	for i := range tau {
		tau[i].MustSetRandom()
		r[i].MustSetRandom()
	}
	eq := make(polynomial.MultiLin, 1<<numVars)
	eq[0].SetOne()
	eq.Eq(tau)
	got := eq.Evaluate(r, nil)
	want := polynomial.EvalEq(r, tau)
	if !got.Equal(&want) {
		t.Fatal("eq table and EvalEq disagree")
	}
	// and by the definition Π (xᵢyᵢ + (1−xᵢ)(1−yᵢ))
	var def, one fr.Element
	one.SetOne()
	def.SetOne()
	for i := range tau {
		var a, b, c fr.Element
		a.Mul(&r[i], &tau[i])
		b.Sub(&one, &r[i])
		c.Sub(&one, &tau[i])
		b.Mul(&b, &c)
		a.Add(&a, &b)
		def.Mul(&def, &a)
	}
	if !def.Equal(&want) {
		t.Fatal("EvalEq differs from the definition of eq")
	}
}
