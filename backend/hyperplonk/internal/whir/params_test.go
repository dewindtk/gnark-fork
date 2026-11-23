// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package whir

import (
	"math"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestLogField(t *testing.T) {
	f, _ := new(big.Float).SetInt(fr.Modulus()).Float64()
	if math.Abs(math.Log2(f)-logField) > 1e-9 {
		t.Fatalf("logField = %v, want %v", logField, math.Log2(f))
	}
}

// The round-0 query counts of docs/hyperplonk/THEORY.md §6, which were
// computed by hand from (1 − δ)^t ≤ 2^−128.
func TestRoundZeroQueries(t *testing.T) {
	for _, tc := range []struct {
		logInvRate int
		ud, jb     int
	}{{1, 309, 298}, {2, 189, 138}, {3, 155, 90}, {4, 141, 67}} {
		for regime, want := range map[Regime]int{UniqueDecoding: tc.ud, Johnson: tc.jb} {
			p, err := NewParams(16, tc.logInvRate, 4, 128, regime)
			if err != nil {
				t.Fatal(err)
			}
			if got := p.Rounds[0].Queries; got != want {
				t.Errorf("ρ=2^-%d %v: %d queries, want %d", tc.logInvRate, regime, got, want)
			}
		}
	}
}

// Every error term of Thm 5.2 / 5.6 is at most 2^−128 for all sizes we use,
// and the schedule accounts for every variable.
func TestAllErrorTermsBelowTarget(t *testing.T) {
	for _, regime := range []Regime{UniqueDecoding, Johnson} {
		for m := 0; m <= 24; m++ {
			p, err := NewParams(m, 3, 4, 128, regime)
			if err != nil {
				t.Fatalf("m=%d %v: %v", m, regime, err)
			}
			sum := p.FinalVars
			for _, r := range p.Rounds {
				sum += r.Fold
			}
			if sum != m || p.FinalVars >= 4 && m >= 4 {
				t.Fatalf("m=%d: schedule %+v", m, p)
			}
			worst := ErrorTerm{Log2: math.Inf(-1)}
			for _, e := range p.Errors(64, 16) {
				if e.Log2 > worst.Log2 {
					worst = e
				}
			}
			if worst.Log2 > -128 {
				t.Fatalf("m=%d %v: %s = 2^%.3f", m, regime, worst.Name, worst.Log2)
			}
			if m == 20 {
				q := make([]int, len(p.Rounds))
				for i, r := range p.Rounds {
					q[i] = r.Queries
				}
				t.Logf("m=20 %v: queries per round %v, worst term %s = 2^%.2f", regime, q, worst.Name, worst.Log2)
			}
		}
	}
}

// One query fewer must break the target: the counts are minimal, and the
// check is not vacuous.
func TestQueryCountsAreMinimal(t *testing.T) {
	p, err := NewParams(16, 3, 4, 128, UniqueDecoding)
	if err != nil {
		t.Fatal(err)
	}
	for i := range p.Rounds {
		q := p
		q.Rounds = append([]Round(nil), p.Rounds...)
		q.Rounds[i].Queries--
		if q.Check() == nil {
			t.Fatalf("round %d: one query fewer still passes the check", i)
		}
	}
}
