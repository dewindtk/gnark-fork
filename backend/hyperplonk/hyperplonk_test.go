// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package hyperplonk_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/hyperplonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
)

type cubic struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

// x³ + x + 5 = y
func (c *cubic) Define(api frontend.API) error {
	x3 := api.Mul(c.X, c.X, c.X)
	api.AssertIsEqual(c.Y, api.Add(x3, c.X, 5))
	return nil
}

// The public API, including serialization of every object, as a user of
// gnark would call it.
func TestAPI(t *testing.T) {
	field := ecc.BN254.ScalarField()
	for name, opts := range map[string][]hyperplonk.Option{"unique decoding": nil, "Johnson": {hyperplonk.WithJohnsonRegime()}} {
		ccs, err := frontend.Compile(field, scs.NewBuilder, &cubic{})
		if err != nil {
			t.Fatal(err)
		}
		pk, vk, err := hyperplonk.Setup(ccs, opts...)
		if err != nil {
			t.Fatal(err)
		}
		w, _ := frontend.NewWitness(&cubic{X: 3, Y: 35}, field)
		pw, _ := w.Public()
		proof, err := hyperplonk.Prove(ccs, pk, w)
		if err != nil {
			t.Fatal(err)
		}
		if err := hyperplonk.Verify(proof, vk, pw); err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		// through bytes: proof and verifying key as a verifier would get them
		var pb, vb, kb bytes.Buffer
		proof.WriteTo(&pb)
		vk.WriteTo(&vb)
		pk.WriteTo(&kb)
		proof2, vk2, pk2 := hyperplonk.NewProof(ecc.BN254), hyperplonk.NewVerifyingKey(ecc.BN254), hyperplonk.NewProvingKey(ecc.BN254)
		if _, err := proof2.ReadFrom(&pb); err != nil {
			t.Fatal(err)
		}
		if _, err := vk2.ReadFrom(&vb); err != nil {
			t.Fatal(err)
		}
		if _, err := pk2.ReadFrom(&kb); err != nil {
			t.Fatal(err)
		}
		if err := hyperplonk.Verify(proof2, vk2, pw); err != nil {
			t.Fatalf("%s, after serialization: %v", name, err)
		}
		if vk2.NbPublicWitness() != 1 {
			t.Fatal("NbPublicWitness")
		}
		proof3, err := hyperplonk.Prove(ccs, pk2, w)
		if err != nil {
			t.Fatal(err)
		}
		if err := hyperplonk.Verify(proof3, vk2, pw); err != nil {
			t.Fatalf("%s, decoded proving key: %v", name, err)
		}

		// wrong inputs
		bad, _ := frontend.NewWitness(&cubic{X: 3, Y: 36}, field)
		if _, err := hyperplonk.Prove(ccs, pk, bad); err == nil {
			t.Fatal("proved a false statement")
		}
		badPublic, _ := bad.Public()
		if err := hyperplonk.Verify(proof, vk, badPublic); err == nil {
			t.Fatal("verified for another public input")
		}
		if err := hyperplonk.Verify(proof, vk, w); err == nil {
			t.Fatal("verified with the full witness as public witness")
		}
	}
}

func TestUnsupportedInputs(t *testing.T) {
	field := ecc.BN254.ScalarField()
	// an R1CS (groth16) system must be refused, not misread
	r, err := frontend.Compile(field, r1cs.NewBuilder, &cubic{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := hyperplonk.Setup(r); !errors.Is(err, hyperplonk.ErrUnsupported) {
		t.Fatalf("R1CS: got %v", err)
	}
	// another curve
	other, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, &cubic{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := hyperplonk.Setup(other); !errors.Is(err, hyperplonk.ErrUnsupported) {
		t.Fatalf("bls12-381: got %v", err)
	}
}

func TestBackendID(t *testing.T) {
	if backend.HYPERPLONK.String() != "hyperplonk" || backend.IDFromString("hyperplonk") != backend.HYPERPLONK {
		t.Fatal("backend ID is not registered consistently")
	}
	found := false
	for _, id := range backend.Implemented() {
		found = found || id == backend.HYPERPLONK
	}
	if !found {
		t.Fatal("HYPERPLONK missing from backend.Implemented()")
	}
}
