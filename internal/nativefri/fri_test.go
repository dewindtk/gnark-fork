package nativefri

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func randomPoly(n int) []fr.Element {
	p := make([]fr.Element, n)
	for i := range p {
		p[i].SetRandom()
	}
	return p
}

// TestOpeningRejectsWrongClaimedValue: an opening proof carries a Merkle path
// (whose first entry is the leaf) and a ClaimedValue, which is what callers
// actually use. The verifier must reject a ClaimedValue that differs from the
// authenticated leaf -- otherwise a prover can claim any evaluation it likes
// (e.g. solve the PLONK identity for h(zeta)) with a perfectly valid path.
func TestOpeningRejectsWrongClaimedValue(t *testing.T) {
	const n = 16
	iop := RADIX_2_FRI.New(n, sha256.New())
	p := randomPoly(n)
	pp, err := iop.BuildProofOfProximity(p)
	if err != nil {
		t.Fatal(err)
	}
	const position = 5
	op, err := iop.Open(p, position)
	if err != nil {
		t.Fatal(err)
	}
	if err := iop.VerifyOpening(position, op, pp); err != nil {
		t.Fatalf("honest opening rejected: %v", err)
	}

	var one fr.Element
	one.SetOne()
	op.ClaimedValue.Add(&op.ClaimedValue, &one) // lie about the value, keep the valid path
	if err := iop.VerifyOpening(position, op, pp); err == nil {
		t.Fatal("opening with a ClaimedValue different from the committed leaf was accepted")
	}
}

// TestMerkleTreeMatchesGnarkCrypto: our stored-node tree must produce exactly
// the roots and paths of gnark-crypto's streaming tree, so that
// merkletree.VerifyProof accepts them.
func TestMerkleTreeMatchesGnarkCrypto(t *testing.T) {
	h := sha256.New()
	for _, size := range []int{2, 16, 128} {
		leaves := make([][]byte, size)
		for i, e := range randomPoly(size) {
			leaves[i] = e.Marshal()
		}
		ours := newMerkleTree(h, leaves)
		for i := 0; i < size; i++ {
			ref := merkletree.New(h)
			if err := ref.SetIndex(uint64(i)); err != nil {
				t.Fatal(err)
			}
			for _, l := range leaves {
				ref.Push(l)
			}
			root, path, _, _ := ref.Prove()
			if !bytes.Equal(root, ours.root()) {
				t.Fatalf("size %d: root mismatch", size)
			}
			got := ours.proof(i)
			if len(got) != len(path) {
				t.Fatalf("size %d leaf %d: path length %d, want %d", size, i, len(got), len(path))
			}
			for k := range path {
				if !bytes.Equal(got[k], path[k]) {
					t.Fatalf("size %d leaf %d: path entry %d differs", size, i, k)
				}
			}
		}
	}
}

func TestProofOfProximityShape(t *testing.T) {
	iop := RADIX_2_FRI.New(16, sha256.New()).(radixTwoFri)
	pp, err := iop.BuildProofOfProximity(randomPoly(16))
	if err != nil {
		t.Fatal(err)
	}
	if len(pp.Queries) != nbQueries || len(pp.Roots) != iop.nbSteps {
		t.Fatalf("got %d queries / %d roots, want %d / %d", len(pp.Queries), len(pp.Roots), nbQueries, iop.nbSteps)
	}
	if !bytes.Equal(pp.ID, pp.Roots[0]) {
		t.Fatal("ID must be the commitment Roots[0]")
	}
}

// TestProximityCompleteness: honest polynomials of every allowed degree are accepted.
func TestProximityCompleteness(t *testing.T) {
	for _, n := range []int{4, 16, 1 << 10} {
		iop := RADIX_2_FRI.New(uint64(n), sha256.New())
		for _, deg := range []int{1, n / 2, n} {
			pp, err := iop.BuildProofOfProximity(randomPoly(deg))
			if err != nil {
				t.Fatal(err)
			}
			if err := iop.VerifyProofOfProximity(pp); err != nil {
				t.Fatalf("n=%d, %d coefficients: honest proof rejected: %v", n, deg, err)
			}
		}
	}
}

// TestProximitySoundness: with one query, words far from the code were
// accepted ~1/8 of the time (measured: 12.5%-13.2%). With nbQueries queries
// the acceptance probability is ≤ 2^-128 (proven) / 2^-258 (conjectured), so
// none of these trials may pass.
func TestProximitySoundness(t *testing.T) {
	const n = 16
	iop := RADIX_2_FRI.New(n, sha256.New())
	for _, c := range []struct {
		name   string
		nCoeff int
	}{
		{"one coefficient too many", n + 1},
		{"twice the allowed degree", 2 * n},
		{"random codeword", n * rho},
	} {
		for k := 0; k < 200; k++ {
			pp, err := iop.BuildProofOfProximity(randomPoly(c.nCoeff))
			if err != nil {
				t.Fatal(err)
			}
			if iop.VerifyProofOfProximity(pp) == nil {
				t.Fatalf("%s: accepted at trial %d", c.name, k)
			}
		}
	}
}

// TestProximityRejectsTampering: the verifier must check the binding between
// ID and the checked commitment, and survive malformed proofs without panicking.
func TestProximityRejectsTampering(t *testing.T) {
	const n = 16
	iop := RADIX_2_FRI.New(n, sha256.New())
	build := func() ProofOfProximity {
		pp, err := iop.BuildProofOfProximity(randomPoly(n))
		if err != nil {
			t.Fatal(err)
		}
		return pp
	}
	other := build()

	cases := map[string]func(pp *ProofOfProximity){
		"ID swapped for another commitment": func(pp *ProofOfProximity) { pp.ID = other.ID },
		"evaluation changed":                func(pp *ProofOfProximity) { pp.Evaluation.SetOne() },
		"one query dropped":                 func(pp *ProofOfProximity) { pp.Queries = pp.Queries[1:] },
		"one root dropped":                  func(pp *ProofOfProximity) { pp.Roots = pp.Roots[1:] },
		"empty interactions":                func(pp *ProofOfProximity) { pp.Queries[3].Interactions = nil },
		"truncated path": func(pp *ProofOfProximity) {
			pp.Queries[0].Interactions[0][0].ProofSet = nil
			pp.Queries[0].Interactions[0][1].ProofSet = nil
		},
		"leaf value changed": func(pp *ProofOfProximity) {
			for c := 0; c < 2; c++ {
				ps := pp.Queries[5].Interactions[1][c].ProofSet
				var one fr.Element
				one.SetOne()
				ps[0] = one.Marshal()
			}
		},
	}
	for name, tamper := range cases {
		pp := build()
		tamper(&pp)
		if err := iop.VerifyProofOfProximity(pp); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
