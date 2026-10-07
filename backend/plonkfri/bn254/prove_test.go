package plonkfri_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/stretchr/testify/require"

	plonkfri "github.com/consensys/gnark/backend/plonkfri/bn254"
	cs "github.com/consensys/gnark/constraint/bn254"
)

// TestProveSmoke is a Phase 0 smoke test: it runs Setup then Prove end-to-end
// on the same toy circuit as TestSetupSmoke, with the running example's
// witness (X=3, Y=2, Out=18), and checks the resulting Proof is
// structurally sane. It cannot check correctness -- that needs Verify,
// which doesn't exist on this branch yet.
func TestProveSmoke(t *testing.T) {
	assert := require.New(t)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &squareMulCircuit{})
	assert.NoError(err)
	sparseR1CS := ccs.(*cs.SparseR1CS)

	pk, _, err := plonkfri.Setup(sparseR1CS)
	assert.NoError(err)

	assignment := &squareMulCircuit{X: 3, Y: 2, Out: 18}
	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	assert.NoError(err)

	proof, err := plonkfri.Prove(sparseR1CS, pk, fullWitness)
	assert.NoError(err)
	assert.NotNil(proof)

	// every commitment must have gone through a real FRI BuildProofOfProximity
	// (non-empty rounds, non-empty ID -- ID is what gets bound into the
	// Fiat-Shamir transcript for the next challenge).
	for i, pp := range proof.LROpp {
		assert.NotEmpty(pp.Queries, "LROpp[%d] has no queries", i)
		assert.NotEmpty(pp.ID, "LROpp[%d] has no ID", i)
	}
	assert.NotEmpty(proof.Zpp.Queries, "Zpp has no queries")
	assert.NotEmpty(proof.Zpp.ID, "Zpp has no ID")
	for i, pp := range proof.Hpp {
		assert.NotEmpty(pp.Queries, "Hpp[%d] has no queries", i)
		assert.NotEmpty(pp.ID, "Hpp[%d] has no ID", i)
	}

	// every opening must carry a real Merkle proof set backing its claimed value.
	for i, op := range proof.OpeningsLROmp {
		assert.NotEmpty(op.ProofSet, "OpeningsLROmp[%d] has no proof set", i)
	}
	for i, op := range proof.OpeningsHmp {
		assert.NotEmpty(op.ProofSet, "OpeningsHmp[%d] has no proof set", i)
	}
	for i, op := range proof.OpeningsQlQrQmQoQkincompletemp {
		assert.NotEmpty(op.ProofSet, "OpeningsQlQrQmQoQkincompletemp[%d] has no proof set", i)
	}
	for i, op := range proof.OpeningsS1S2S3mp {
		assert.NotEmpty(op.ProofSet, "OpeningsS1S2S3mp[%d] has no proof set", i)
	}
	for i, op := range proof.OpeningsId1Id2Id3mp {
		assert.NotEmpty(op.ProofSet, "OpeningsId1Id2Id3mp[%d] has no proof set", i)
	}
	assert.NotEmpty(proof.OpeningsZmp[0].ProofSet, "OpeningsZmp[0] has no proof set")
	assert.NotEmpty(proof.OpeningsZmp[1].ProofSet, "OpeningsZmp[1] (shifted) has no proof set")
}
