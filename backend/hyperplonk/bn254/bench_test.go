// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package hyperplonk

import (
	"testing"

	cs "github.com/consensys/gnark/constraint/bn254"
)

// benchSetup builds the chain circuit with about 2^logRows rows.
func benchSetup(b *testing.B, logRows int, regime Regime) (fixture, *cs.SparseR1CS) {
	n := 1<<logRows - 8
	f := newFixtureFor(b, regime, &chain{N: n}, &chain{N: n, X: 3, Out: chainValue(3, n)})
	return f, f.spr
}

func BenchmarkProve16(b *testing.B) {
	f, _ := benchSetup(b, 16, UniqueDecoding)
	b.ResetTimer()
	for range b.N {
		if _, err := proveWires(f.pk, f.public, f.a, f.b, f.c); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify16(b *testing.B) {
	f, _ := benchSetup(b, 16, UniqueDecoding)
	proof, err := proveWires(f.pk, f.public, f.a, f.b, f.c)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for range b.N {
		if err := Verify(proof, f.vk, f.public); err != nil {
			b.Fatal(err)
		}
	}
}
