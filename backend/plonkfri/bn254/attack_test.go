package plonkfri

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark/backend"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/internal/nativefri"
)

// squareCircuit proves knowledge of X such that X² = Y, Y public.
type squareCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (c *squareCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.X, c.X), c.Y)
	return nil
}

// TestForgeryZetaInDomain is the red-first test for concern 2 (fix B).
//
// The cheater proves the FALSE statement "I know X with X² = 5" (5 is a
// non-square in bn254 fr, so no such X exists). It computes every polynomial
// from a real witness (X=3, Y=9) but binds Y=5 into Fiat-Shamir, exactly as the
// verifier will. The two statements differ only in the public-input term
// Y·L₀(X), and L₀ vanishes on every row of H except row 0. So whenever zeta
// lands on a row ωʲ (j≠0) -- which happens because zeta is drawn from the FRI
// domain, 1/16 of which is H -- the verifier sees a consistent proof and
// accepts. Expected forgery rate: ≈ 1/16.
//
// After fix B (zeta ∈ F \ (D ∪ H)) the forgery rate must be 0.
func TestForgeryZetaInDomain(t *testing.T) {
	const attempts = 800

	var fake fr.Element
	fake.SetUint64(5)
	if fake.Legendre() != -1 {
		t.Fatal("5 must be a non-square for the statement to be false")
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &squareCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	spr := ccs.(*cs.SparseR1CS)
	pk, vk, err := Setup(spr)
	if err != nil {
		t.Fatal(err)
	}
	w, err := frontend.NewWitness(&squareCircuit{X: 3, Y: 9}, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	fakePublic := fr.Vector{fake}

	accepted, acceptedInH := 0, 0
	for i := 0; i < attempts; i++ {
		// each attempt draws fresh blinding → new commitments → new zeta
		proof, err := prove(spr, pk, w, fakePublic)
		if err != nil {
			t.Fatal(err)
		}
		if Verify(proof, vk, fakePublic) != nil {
			continue
		}
		accepted++
		if zetaInH(t, proof, vk, fakePublic) {
			acceptedInH++
		}
	}
	t.Logf("false statement X²=5: %d/%d forged proofs accepted (%.1f%%, expected ≈ 1/16 = 6.25%% before fix B); %d of them had zeta ∈ H",
		accepted, attempts, 100*float64(accepted)/attempts, acceptedInH)
	if accepted > 0 {
		t.Errorf("verifier accepted %d proofs of a false statement (concern 2: zeta sampled from the FRI domain)", accepted)
	}
}

// zetaInH recomputes zeta exactly as Verify does and reports whether it lies in
// the circuit domain H (zetaⁿ = 1).
func zetaInH(t *testing.T, proof *Proof, vk *VerifyingKey, public fr.Vector) bool {
	cfg, _ := backend.NewVerifierConfig()
	fs := fiatshamir.NewTranscript(cfg.ChallengeHash, "gamma", "beta", "alpha", "zeta")
	data := make([][fr.Bytes]byte, len(public)+3)
	for i := range public {
		copy(data[i][:], public[i].Marshal())
	}
	for k := 0; k < 3; k++ {
		copy(data[len(public)+k][:], proof.LROpp[k].ID)
	}
	if _, err := deriveRandomnessFixedSize(fs, "gamma", data...); err != nil {
		t.Fatal(err)
	}
	if _, err := deriveRandomness(fs, "beta", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := deriveRandomness(fs, "alpha", proof.Zpp.ID); err != nil {
		t.Fatal(err)
	}
	r, err := deriveRandomness(fs, "zeta", proof.Hpp[0].ID, proof.Hpp[1].ID, proof.Hpp[2].ID)
	if err != nil {
		t.Fatal(err)
	}
	friSize := big.NewInt(int64(2 * uint64(nativefri.GetRho()) * vk.Size))
	var pos big.Int
	pos.SetBytes(r.Marshal()).Mod(&pos, friSize)
	var zeta, zn fr.Element
	zeta.Exp(vk.GenOpening, &pos)
	zn.Exp(zeta, big.NewInt(int64(vk.Size)))
	return zn.IsOne()
}
