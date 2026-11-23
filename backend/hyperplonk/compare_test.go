// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

//go:build hpcompare

// Comparison with the other PLONK backends of this repository on the same
// circuit. Behind a build tag because it imports backend/plonkfri, which is
// not part of the vendored backend (docs/hyperplonk/README.md, D8), and
// because it takes minutes.
//
//	go test -tags hpcompare -run TestCompare -v -timeout 60m ./backend/hyperplonk/
package hyperplonk_test

import (
	"bytes"
	"fmt"
	"io"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/hyperplonk"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/plonkfri"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

// refCircuit is the chain of squarings used by the performance tests of
// backend/plonk and backend/plonkfri.
type refCircuit struct {
	nbConstraints int
	X             frontend.Variable
	Y             frontend.Variable `gnark:",public"`
}

func (c *refCircuit) Define(api frontend.API) error {
	for i := 0; i < c.nbConstraints; i++ {
		c.X = api.Mul(c.X, c.X)
	}
	api.AssertIsEqual(c.X, c.Y)
	return nil
}

type system struct {
	name  string
	setup func(ccs constraint.ConstraintSystem) (prove func(w witness.Witness) (io.WriterTo, error), verify func(p io.WriterTo, pw witness.Witness) error, err error)
}

func median(ds []time.Duration) time.Duration {
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	return ds[len(ds)/2]
}

func TestCompare(t *testing.T) {
	systems := []system{
		{"plonk (KZG)", func(ccs constraint.ConstraintSystem) (func(witness.Witness) (io.WriterTo, error), func(io.WriterTo, witness.Witness) error, error) {
			srs, lag, err := unsafekzg.NewSRS(ccs)
			if err != nil {
				return nil, nil, err
			}
			pk, vk, err := plonk.Setup(ccs, srs, lag)
			return func(w witness.Witness) (io.WriterTo, error) { return plonk.Prove(ccs, pk, w) },
				func(p io.WriterTo, pw witness.Witness) error { return plonk.Verify(p.(plonk.Proof), vk, pw) }, err
		}},
		{"plonkfri", func(ccs constraint.ConstraintSystem) (func(witness.Witness) (io.WriterTo, error), func(io.WriterTo, witness.Witness) error, error) {
			pk, vk, err := plonkfri.Setup(ccs)
			return func(w witness.Witness) (io.WriterTo, error) { return plonkfri.Prove(ccs, pk, w) },
				func(p io.WriterTo, pw witness.Witness) error { return plonkfri.Verify(p.(plonkfri.Proof), vk, pw) }, err
		}},
		{"hyperplonk UD", func(ccs constraint.ConstraintSystem) (func(witness.Witness) (io.WriterTo, error), func(io.WriterTo, witness.Witness) error, error) {
			pk, vk, err := hyperplonk.Setup(ccs)
			return func(w witness.Witness) (io.WriterTo, error) { return hyperplonk.Prove(ccs, pk, w) },
				func(p io.WriterTo, pw witness.Witness) error { return hyperplonk.Verify(p.(hyperplonk.Proof), vk, pw) }, err
		}},
		{"hyperplonk JB", func(ccs constraint.ConstraintSystem) (func(witness.Witness) (io.WriterTo, error), func(io.WriterTo, witness.Witness) error, error) {
			pk, vk, err := hyperplonk.Setup(ccs, hyperplonk.WithJohnsonRegime())
			return func(w witness.Witness) (io.WriterTo, error) { return hyperplonk.Prove(ccs, pk, w) },
				func(p io.WriterTo, pw witness.Witness) error { return hyperplonk.Verify(p.(hyperplonk.Proof), vk, pw) }, err
		}},
	}

	const runs = 3
	t.Logf("%s/%s, %d CPUs, median of %d runs; proof size = serialized bytes", runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runs)
	t.Logf("%-8s %-14s %10s %10s %10s %12s", "rows", "system", "setup", "prove", "verify", "proof")
	for _, logRows := range []int{12, 14, 16} {
		nb := 1<<logRows - 3
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &refCircuit{nbConstraints: nb})
		if err != nil {
			t.Fatal(err)
		}
		var x, y fr.Element
		x.SetUint64(3)
		y = x
		for range nb {
			y.Square(&y)
		}
		w, err := frontend.NewWitness(&refCircuit{nbConstraints: nb, X: x, Y: y}, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		pw, _ := w.Public()

		for _, s := range systems {
			start := time.Now()
			prove, verify, err := s.setup(ccs)
			if err != nil {
				t.Fatalf("%s setup: %v", s.name, err)
			}
			setup := time.Since(start)
			var proves, verifies []time.Duration
			var size int
			for range runs {
				start = time.Now()
				proof, err := prove(w)
				if err != nil {
					t.Fatalf("%s prove: %v", s.name, err)
				}
				proves = append(proves, time.Since(start))
				start = time.Now()
				if err := verify(proof, pw); err != nil {
					t.Fatalf("%s verify: %v", s.name, err)
				}
				verifies = append(verifies, time.Since(start))
				var buf bytes.Buffer
				if _, err := proof.WriteTo(&buf); err != nil {
					t.Fatal(err)
				}
				size = buf.Len()
			}
			t.Logf("2^%-6d %-14s %10v %10v %10v %12s", logRows, s.name, setup.Round(time.Millisecond),
				median(proves).Round(time.Millisecond), median(verifies).Round(100*time.Microsecond), fmt.Sprintf("%.1f KiB", float64(size)/1024))
			runtime.GC()
		}
	}
}
