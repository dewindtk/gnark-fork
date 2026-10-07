package plonkfri_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/stretchr/testify/require"

	plonkfri "github.com/consensys/gnark/backend/plonkfri/bn254"
	cs "github.com/consensys/gnark/constraint/bn254"
)

// TestRoundTrip is the first real correctness check (not just a smoke test):
// Setup -> Prove -> Verify on the toy circuit (X^2*Y=Out, X=3,Y=2,Out=18)
// must succeed, and Verify must reject a tampered proof.
func TestRoundTrip(t *testing.T) {
	assert := require.New(t)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &squareMulCircuit{})
	assert.NoError(err)
	sparseR1CS := ccs.(*cs.SparseR1CS)

	pk, vk, err := plonkfri.Setup(sparseR1CS)
	assert.NoError(err)

	assignment := &squareMulCircuit{X: 3, Y: 2, Out: 18}
	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
	publicWitness, err := fullWitness.Public()
	assert.NoError(err)
	publicVector, ok := publicWitness.Vector().(fr.Vector)
	assert.True(ok, "expected an fr.Vector public witness")

	proof, err := plonkfri.Prove(sparseR1CS, pk, fullWitness)
	assert.NoError(err)

	err = plonkfri.Verify(proof, vk, publicVector)
	assert.NoError(err, "a valid proof must verify")

	// negative test: tamper with a claimed opening value and confirm Verify rejects it.
	tampered := *proof
	tampered.OpeningsLROmp[0].ClaimedValue.Add(
		&tampered.OpeningsLROmp[0].ClaimedValue,
		&tampered.OpeningsLROmp[0].ClaimedValue,
	) // double it -- guaranteed different from the original since X=3 makes it nonzero

	err = plonkfri.Verify(&tampered, vk, publicVector)
	assert.Error(err, "a tampered proof must NOT verify")
}
