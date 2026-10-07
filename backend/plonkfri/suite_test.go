package plonkfri_test

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/plonkfri"
	plonkfri_bn254 "github.com/consensys/gnark/backend/plonkfri/bn254"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/internal/backend/circuits"
)

// TestCircuitSuite runs every circuit of the shared gnark test suite
// (internal/backend/circuits, the same set integration_test.go runs against
// the KZG PLONK and Groth16 backends) through plonkfri on bn254.
//
// For each circuit:
//   - every valid assignment must Setup/Prove/Verify;
//   - every invalid assignment must fail, either at Prove (solver) or when
//     its public part is used to Verify an honest proof.
func TestCircuitSuite(t *testing.T) {
	names := make([]string, 0, len(circuits.Circuits))
	for k := range circuits.Circuits {
		names = append(names, k)
	}
	sort.Strings(names)

	curve := ecc.BN254
	for _, name := range names {
		tc := circuits.Circuits[name]
		if tc.Curves != nil && !containsCurve(tc.Curves, curve) {
			t.Logf("%-28s SKIP (circuit not defined for bn254)", name)
			continue
		}
		t.Run(name, func(t *testing.T) {
			runCircuit(t, name, tc, curve)
		})
	}
}

func runCircuit(t *testing.T, name string, tc circuits.TestCircuit, curve ecc.ID) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("PANIC: %v", r)
		}
	}()

	ccs, err := frontend.Compile(curve.ScalarField(), scs.NewBuilder, tc.Circuit)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	start := time.Now()
	pk, vk, err := plonkfri.Setup(ccs)
	if errors.Is(err, plonkfri_bn254.ErrCommitmentsUnsupported) {
		t.Skipf("out of v1 scope: %v", err)
	}
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	setupTime := time.Since(start)

	proverOpts := []backend.ProverOption{backend.WithSolverOptions(solver.WithHints(tc.HintFunctions...))}

	var honestProof plonkfri.Proof
	var proveTime, verifyTime time.Duration
	for i, a := range tc.ValidAssignments {
		w, err := frontend.NewWitness(a, curve.ScalarField())
		if err != nil {
			t.Fatalf("valid[%d] witness: %v", i, err)
		}
		pw, _ := w.Public()

		start = time.Now()
		proof, err := plonkfri.Prove(ccs, pk, w, proverOpts...)
		proveTime = time.Since(start)
		if err != nil {
			t.Fatalf("valid[%d] prove: %v", i, err)
		}
		start = time.Now()
		err = plonkfri.Verify(proof, vk, pw)
		verifyTime = time.Since(start)
		if err != nil {
			t.Fatalf("valid[%d] verify (completeness failure): %v", i, err)
		}
		// the full witness must be refused as a public witness, with a clear error
		if err := plonkfri.Verify(proof, vk, w); err == nil || !strings.Contains(err.Error(), "witness length is invalid") {
			t.Errorf("valid[%d]: Verify with full witness: got %v, want witness length error", i, err)
		}
		honestProof = proof
	}

	for i, a := range tc.InvalidAssignments {
		w, err := frontend.NewWitness(a, curve.ScalarField())
		if err != nil {
			continue // invalid assignment not even representable: rejected
		}
		if _, err := plonkfri.Prove(ccs, pk, w, proverOpts...); err == nil {
			t.Errorf("invalid[%d]: Prove succeeded on an invalid witness", i)
		}
		// soundness w.r.t. public inputs: an honest proof must not verify
		// against a different (invalid) public witness.
		pw, err := w.Public()
		if err != nil || vk.NbPublicWitness() == 0 || honestProof == nil {
			continue
		}
		if err := plonkfri.Verify(honestProof, vk, pw); err == nil {
			// only a failure if the public part actually differs
			vw, _ := frontend.NewWitness(tc.ValidAssignments[len(tc.ValidAssignments)-1], curve.ScalarField())
			vpw, _ := vw.Public()
			if fmt.Sprint(vpw.Vector()) != fmt.Sprint(pw.Vector()) {
				t.Errorf("invalid[%d]: honest proof verified against a different public witness", i)
			}
		}
	}

	t.Logf("%-28s constraints=%-6d setup=%-10v prove=%-10v verify=%v",
		name, ccs.GetNbConstraints(), setupTime.Round(time.Millisecond),
		proveTime.Round(time.Millisecond), verifyTime.Round(time.Millisecond))
}

func containsCurve(curves []ecc.ID, c ecc.ID) bool {
	for _, x := range curves {
		if x == c {
			return true
		}
	}
	return false
}

type assertEqualCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (c *assertEqualCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.X, c.Y)
	return nil
}

// TestTinyCircuitCompleteness is a regression test: single-constraint circuits
// used to get a 2-row domain, on which the blinded Z polynomial exceeded the
// FRI degree bound and ~88% of honest proofs were rejected (depending on the
// blinding randomness). Prove many times to catch the probabilistic failure.
func TestTinyCircuitCompleteness(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &assertEqualCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := plonkfri.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	w, err := frontend.NewWitness(&assertEqualCircuit{X: 3, Y: 3}, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	pw, _ := w.Public()
	for i := 0; i < 200; i++ {
		proof, err := plonkfri.Prove(ccs, pk, w)
		if err != nil {
			t.Fatal(err)
		}
		if err := plonkfri.Verify(proof, vk, pw); err != nil {
			t.Fatalf("iteration %d: honest proof rejected: %v", i, err)
		}
	}
}
