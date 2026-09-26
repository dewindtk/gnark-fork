package plonkfri_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/stretchr/testify/require"

	"github.com/consensys/gnark/backend/plonkfri"
)

type squareMulCircuit struct {
	X   frontend.Variable
	Y   frontend.Variable
	Out frontend.Variable `gnark:",public"`
}

func (c *squareMulCircuit) Define(api frontend.API) error {
	t := api.Mul(c.X, c.X)
	out := api.Mul(t, c.Y)
	api.AssertIsEqual(out, c.Out)
	return nil
}

// TestDispatcherRoundTrip exercises the top-level backend/plonkfri dispatcher
// (Setup/Prove/Verify, not the bn254 subpackage directly) to confirm the
// interface/type-assertion plumbing actually works at runtime, not just that
// it compiles.
func TestDispatcherRoundTrip(t *testing.T) {
	assert := require.New(t)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &squareMulCircuit{})
	assert.NoError(err)

	pk, vk, err := plonkfri.Setup(ccs)
	assert.NoError(err)

	assignment := &squareMulCircuit{X: 3, Y: 2, Out: 18}
	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
	publicWitness, err := fullWitness.Public()
	assert.NoError(err)

	proof, err := plonkfri.Prove(ccs, pk, fullWitness)
	assert.NoError(err)

	err = plonkfri.Verify(proof, vk, publicWitness)
	assert.NoError(err, "a valid proof must verify through the dispatcher")
}
