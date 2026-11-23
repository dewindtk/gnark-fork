// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Package whir implements WHIR (ePrint 2024/1586, Construction 5.1) as a
// commitment scheme for multilinear polynomials over the bn254 scalar field:
// commit to a polynomial, then prove evaluation claims about it.
//
// A commitment is the Merkle root of the Reed–Solomon encoding of the
// polynomial. An opening proves that the committed word is δ-close to a
// codeword whose polynomial f̂ satisfies every claim f̂(z_c) = v_c. Each claim
// is the constraint Σ_b f̂(b)·eq(z_c, b) = v_c; several claims are combined
// with powers of a challenge (Construction 5.5, Thm 5.6).
//
// One iteration: k sumcheck rounds on Σ_b f̂(b)·W(b) = σ fix the first k
// variables to α; the prover commits to the encoding of f̂(α, ·) on a domain
// of half the size; the verifier asks for its value at one point outside the
// domain and checks, at t random points, that it agrees with the folding of
// the previous word (computed from 2^k values each). Those t+1 values become
// new constraints, added to W with powers of a challenge γ. After the last
// iteration the remaining polynomial is sent in clear.
//
// Soundness: round-by-round, Thm 5.2; parameters and every error term in
// params.go. What is implemented is the non-interactive version obtained by
// Merkle commitments and Fiat–Shamir; its security argument (BCS) is not
// yet written down for our transcript (docs/hyperplonk/THEORY.md §8).
//
// Batching (Construction 7.4, Thm 7.5). Several polynomials with the same
// number of variables are opened by one proof: the verifier draws γ and the
// protocol runs on the virtual word g = Σ_j γ^j·f_j. Every polynomial must be
// given a value at every point; the constraint for point z is
// ĝ(z) = Σ_j γ^j·f̂_j(z). A query to g at a position is answered by opening
// every f_j there. Polynomials committed together share one Merkle tree whose
// leaf holds the values of all of them.
//
// Not zero-knowledge.
package whir

import (
	"errors"
	"fmt"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"

	"github.com/consensys/gnark/backend/hyperplonk/internal/par"
	"github.com/consensys/gnark/backend/hyperplonk/internal/sumcheck"
)

// Transcript is the Fiat–Shamir transcript as WHIR uses it.
type Transcript interface {
	sumcheck.Challenger
	Append(label string, data []byte)
}

// Claim states f̂(Point) = Value for the committed polynomial f̂.
type Claim struct {
	Point []fr.Element
	Value fr.Element
}

// Committed is the prover's side of a commitment to one or more polynomials
// with the same number of variables, in one Merkle tree.
type Committed struct {
	Root      Digest
	tables    []polynomial.MultiLin
	codewords [][]fr.Element
	tree      *merkleTree
}

// NbPolys is the number of polynomials in the commitment.
func (c *Committed) NbPolys() int { return len(c.tables) }

// Query is the opening of one position of an oracle. The oracle of the first
// iteration is the virtual combination of all committed polynomials, so its
// opening has one leaf and one path per commitment; later oracles have one.
// The position is derived from the transcript by the verifier.
type Query struct {
	Leaves [][]fr.Element
	Paths  [][]Digest
}

// RoundProof holds the messages of iteration i ≥ 1.
type RoundProof struct {
	Root     Digest         // commitment to f_i
	OOD      fr.Element     // f̂_i at the out-of-domain point
	Queries  []Query        // openings of f_{i−1}
	Sumcheck [][]fr.Element // k_i sumcheck rounds
}

// Proof is an opening proof.
type Proof struct {
	Initial      [][]fr.Element      // k₀ sumcheck rounds
	Rounds       []RoundProof        // iterations 1..M−1
	Final        polynomial.MultiLin // f̂_M on the hypercube
	FinalQueries []Query             // openings of f_{M−1}
}

var (
	ErrProofShape = errors.New("whir: proof has the wrong shape")
	ErrMerkle     = errors.New("whir: Merkle path does not match the commitment")
	ErrFold       = errors.New("whir: final polynomial disagrees with the folded oracle")
	ErrConstraint = errors.New("whir: final polynomial does not satisfy the constraints")
)

// product is the sumcheck summand f̂(b)·W(b).
var product = sumcheck.Gate{
	Degree: 2,
	Eval: func(v []fr.Element) fr.Element {
		var r fr.Element
		r.Mul(&v[0], &v[1])
		return r
	},
}

// Commit encodes the polynomials given by their hypercube tables and commits
// to all of them in one tree. Each table must have 2^p.NumVars entries.
//
// Leaf i holds, for each polynomial in turn, its 2^k values on the points of
// L whose 2^k-th power is ω^(i·2^k) (see leaves).
func Commit(p Params, tables ...polynomial.MultiLin) (*Committed, error) {
	if len(tables) == 0 {
		return nil, errors.New("whir: nothing to commit")
	}
	r0 := p.Rounds[0]
	c := &Committed{tables: tables}
	var all [][]fr.Element
	for _, t := range tables {
		if len(t) != 1<<p.NumVars {
			return nil, fmt.Errorf("whir: table must have 2^%d entries", p.NumVars)
		}
		cw := encode(t, r0.LogDomain)
		c.codewords = append(c.codewords, cw)
		ls := leaves(cw, r0.Fold)
		if all == nil {
			all = ls
		} else {
			for i := range all {
				all[i] = append(all[i], ls[i]...)
			}
		}
	}
	c.tree = newMerkleTree(all)
	c.Root = c.tree.root()
	return c, nil
}

// commitOne commits to a single table in a tree with leaves for folding k.
func commitOne(table polynomial.MultiLin, r Round) *Committed {
	c := &Committed{tables: []polynomial.MultiLin{table}, codewords: [][]fr.Element{encode(table, r.LogDomain)}}
	c.tree = newMerkleTree(leaves(c.codewords[0], r.Fold))
	c.Root = c.tree.root()
	return c
}

// leaf returns leaf i of the commitment's tree.
func (c *Committed) leaf(k, i int) []fr.Element {
	nb := len(c.codewords[0]) >> k
	out := make([]fr.Element, 0, len(c.codewords)<<k)
	for _, cw := range c.codewords {
		for j := range 1 << k {
			out = append(out, cw[i+j*nb])
		}
	}
	return out
}

// Evaluations returns values[j][k] = f̂_j(points[k]) for all committed
// polynomials j, in commitment order.
func Evaluations(cs []*Committed, points [][]fr.Element) [][]fr.Element {
	var tables []polynomial.MultiLin
	for _, c := range cs {
		tables = append(tables, c.tables...)
	}
	out := make([][]fr.Element, len(tables))
	for j := range out {
		out[j] = make([]fr.Element, len(points))
	}
	// one eq table per point, then one inner product per polynomial
	var one fr.Element
	one.SetOne()
	par.Range(len(points), 1, func(start, end int) {
		for k := start; k < end; k++ {
			eq := eqTable(points[k], one)
			for j, t := range tables {
				out[j][k] = innerProduct(t, eq)
			}
		}
	})
	return out
}

// innerProduct returns Σ_i a[i]·b[i].
func innerProduct(a, b []fr.Element) fr.Element {
	var mu sync.Mutex
	var res fr.Element
	par.Range(len(a), 1<<12, func(start, end int) {
		var acc, x fr.Element
		for i := start; i < end; i++ {
			x.Mul(&a[i], &b[i])
			acc.Add(&acc, &x)
		}
		mu.Lock()
		res.Add(&res, &acc)
		mu.Unlock()
	})
	return res
}

func bindStatement(tr Transcript, roots []Digest, points, values [][]fr.Element) {
	for i := range roots {
		tr.Append("whir/root", roots[i][:])
	}
	for _, pt := range points {
		tr.AppendElements("whir/point", pt...)
	}
	for _, row := range values {
		tr.AppendElements("whir/values", row...)
	}
}

// queryIndices draws t positions among nbLeaves (a power of two), each from
// the low bits of a challenge; the positions are independent and uniform up
// to nbLeaves/|F|. Sampling is with replacement, as in the analysis of
// ε_shift: (1 − δ)^t is the probability that t independent positions all miss.
func queryIndices(tr Transcript, t, nbLeaves int) []int {
	idx := make([]int, t)
	for j := range idx {
		c := tr.Challenge("whir/query")
		bits := c.Bits()
		idx[j] = int(bits[0] & uint64(nbLeaves-1))
	}
	return idx
}

func openQueries(cs []*Committed, k int, idx []int) []Query {
	q := make([]Query, len(idx))
	for j, i := range idx {
		for _, c := range cs {
			q[j].Leaves = append(q[j].Leaves, c.leaf(k, i))
			q[j].Paths = append(q[j].Paths, c.tree.path(i))
		}
	}
	return q
}

func checkShape(p Params, nbPolys int, points, values [][]fr.Element) error {
	if len(points) == 0 || nbPolys == 0 || len(values) != nbPolys {
		return errors.New("whir: need at least one polynomial and one point, and one row of values per polynomial")
	}
	for _, pt := range points {
		if len(pt) != p.NumVars {
			return errors.New("whir: point has the wrong length")
		}
	}
	for _, row := range values {
		if len(row) != len(points) {
			return errors.New("whir: every polynomial needs a value at every point")
		}
	}
	return nil
}

// powers returns 1, γ, γ², …, γ^(n−1).
func powers(gamma fr.Element, n int) []fr.Element {
	out := make([]fr.Element, n)
	if n > 0 {
		out[0].SetOne()
	}
	for i := 1; i < n; i++ {
		out[i].Mul(&out[i-1], &gamma)
	}
	return out
}

// Open proves the claims about a commitment to a single polynomial.
func Open(tr Transcript, p Params, c *Committed, claims []Claim) (*Proof, error) {
	points, values := splitClaims(claims)
	return OpenBatch(tr, p, []*Committed{c}, points, [][]fr.Element{values})
}

func splitClaims(claims []Claim) ([][]fr.Element, []fr.Element) {
	points := make([][]fr.Element, len(claims))
	values := make([]fr.Element, len(claims))
	for i, c := range claims {
		points[i], values[i] = c.Point, c.Value
	}
	return points, values
}

// OpenBatch proves, for all polynomials j of the commitments (in order) and
// all points k, that f̂_j(points[k]) = values[j][k]. The transcript must
// already bind everything the caller's protocol did before.
func OpenBatch(tr Transcript, p Params, cs []*Committed, points, values [][]fr.Element) (*Proof, error) {
	var tablesIn []polynomial.MultiLin
	roots := make([]Digest, len(cs))
	for i, c := range cs {
		tablesIn = append(tablesIn, c.tables...)
		roots[i] = c.Root
	}
	if err := checkShape(p, len(tablesIn), points, values); err != nil {
		return nil, err
	}
	bindStatement(tr, roots, points, values)

	// virtual polynomial ĝ = Σ_j γ^j·f̂_j (Construction 7.4)
	batch := powers(tr.Challenge("whir/batch"), len(tablesIn))
	f := make(polynomial.MultiLin, 1<<p.NumVars)
	par.Range(len(f), 1<<12, func(start, end int) {
		var t fr.Element
		for j, tab := range tablesIn {
			for i := start; i < end; i++ {
				t.Mul(&batch[j], &tab[i])
				f[i].Add(&f[i], &t)
			}
		}
	})

	// combine the constraints: W = Σ_k γ₀^k · eq(z_k, ·) (Construction 5.5)
	combine := powers(tr.Challenge("whir/combine"), len(points))
	w := make(polynomial.MultiLin, len(f))
	addEqs(w, points, combine)
	tables := []polynomial.MultiLin{f, w}

	proof := &Proof{}
	proof.Initial, _ = sumcheck.ProveRounds(tr, tables, product, p.Rounds[0].Fold)

	prev := cs
	var coef fr.Element
	for i := 1; i < len(p.Rounds); i++ {
		r, rPrev := p.Rounds[i], p.Rounds[i-1]
		// commit to f_i, the encoding of f̂_i = f̂_{i−1}(α_{i−1}, ·) on L_i
		cur := commitOne(tables[0].Clone(), r)
		rp := RoundProof{Root: cur.Root}
		tr.Append("whir/root", cur.Root[:])

		// out-of-domain point and answer
		z0 := tr.Challenge("whir/ood")
		z0pow := pow(z0, r.NumVars)
		rp.OOD = tables[0].Evaluate(z0pow, nil)
		tr.AppendElements("whir/ood/answer", rp.OOD)

		// shift queries on f_{i−1} and combination challenge
		idx := queryIndices(tr, rPrev.Queries, rPrev.Leaves())
		gamma := tr.Challenge("whir/gamma")
		rp.Queries = openQueries(prev, rPrev.Fold, idx)

		// W_i = W_{i−1}(α_{i−1}, ·) + Σ_j γ^(j+1)·eq(pow(z_j), ·)
		coef = gamma
		pts := make([][]fr.Element, 0, len(idx)+1)
		coefs := make([]fr.Element, 0, len(idx)+1)
		pts, coefs = append(pts, z0pow), append(coefs, coef)
		for _, ix := range idx {
			coef.Mul(&coef, &gamma)
			// z_j = y = (ω^ix)^(2^k) ∈ L_{i−1}^(2^k)
			y := domainElement(rPrev.LogDomain-rPrev.Fold, ix)
			pts, coefs = append(pts, pow(y, r.NumVars)), append(coefs, coef)
		}
		addEqs(tables[1], pts, coefs)

		rp.Sumcheck, _ = sumcheck.ProveRounds(tr, tables, product, r.Fold)
		proof.Rounds = append(proof.Rounds, rp)
		prev = []*Committed{cur}
	}

	// final polynomial in clear, then queries on f_{M−1}
	last := p.Rounds[len(p.Rounds)-1]
	proof.Final = tables[0].Clone()
	tr.AppendElements("whir/final", proof.Final...)
	proof.FinalQueries = openQueries(prev, last.Fold, queryIndices(tr, last.Queries, last.Leaves()))
	return proof, nil
}

// term is one summand coef·eq(point, ·) of the weight, created when `offset`
// variables had already been fixed.
type term struct {
	coef   fr.Element
	point  []fr.Element
	offset int
}

// oracle describes what the verifier knows about an oracle: the roots of the
// trees it is spread over, how many polynomials each tree holds, and the
// coefficients that combine all those polynomials into the oracle.
type oracle struct {
	roots  []Digest
	widths []int
	coefs  []fr.Element
}

func single(root Digest) oracle {
	var one fr.Element
	one.SetOne()
	return oracle{[]Digest{root}, []int{1}, []fr.Element{one}}
}

// checkQueries verifies the openings of an oracle with parameters r and
// returns the folded values Fold(f, alphas)(y_j) and the points y_j.
func checkQueries(o oracle, r Round, idx []int, queries []Query, alphas []fr.Element) ([]fr.Element, []fr.Element, error) {
	if len(queries) != len(idx) {
		return nil, nil, ErrProofShape
	}
	size := 1 << r.Fold
	vals := make([]fr.Element, len(idx))
	ys := make([]fr.Element, len(idx))
	combined := make([]fr.Element, size)
	var t fr.Element
	for j, ix := range idx {
		q := queries[j]
		if len(q.Leaves) != len(o.roots) || len(q.Paths) != len(o.roots) {
			return nil, nil, ErrProofShape
		}
		for i := range combined {
			combined[i].SetZero()
		}
		poly := 0
		for tree := range o.roots {
			leaf := q.Leaves[tree]
			if len(leaf) != o.widths[tree]*size {
				return nil, nil, ErrProofShape
			}
			if !verifyPath(o.roots[tree], r.Leaves(), ix, leaf, q.Paths[tree]) {
				return nil, nil, ErrMerkle
			}
			// the oracle's value is the combination of the polynomials' values
			for w := range o.widths[tree] {
				for i := range size {
					t.Mul(&o.coefs[poly], &leaf[w*size+i])
					combined[i].Add(&combined[i], &t)
				}
				poly++
			}
		}
		vals[j] = foldLeaf(combined, alphas, r.LogDomain, ix)
		ys[j] = domainElement(r.LogDomain-r.Fold, ix)
	}
	return vals, ys, nil
}

// Verify checks an opening proof for a commitment to a single polynomial.
func Verify(tr Transcript, p Params, root Digest, claims []Claim, proof *Proof) error {
	points, values := splitClaims(claims)
	return VerifyBatch(tr, p, []Digest{root}, []int{1}, points, [][]fr.Element{values}, proof)
}

// VerifyBatch checks a batched opening proof: for the commitments roots[i],
// holding nbPolys[i] polynomials each, polynomial j has value values[j][k] at
// points[k].
func VerifyBatch(tr Transcript, p Params, roots []Digest, nbPolys []int, points, values [][]fr.Element, proof *Proof) error {
	total := 0
	for _, n := range nbPolys {
		if n < 1 {
			return errors.New("whir: a commitment holds at least one polynomial")
		}
		total += n
	}
	if len(roots) != len(nbPolys) {
		return errors.New("whir: one polynomial count per commitment")
	}
	if err := checkShape(p, total, points, values); err != nil {
		return err
	}
	if proof == nil || len(proof.Rounds) != len(p.Rounds)-1 || len(proof.Final) != 1<<p.FinalVars || len(proof.Initial) != p.Rounds[0].Fold {
		return ErrProofShape
	}
	bindStatement(tr, roots, points, values)

	batch := powers(tr.Challenge("whir/batch"), total)
	combine := powers(tr.Challenge("whir/combine"), len(points))
	var claim, coef, t fr.Element
	terms := make([]term, 0, len(points))
	for k, pt := range points {
		// σ_k = Σ_j γ^j·values[j][k]
		var sigma fr.Element
		for j := range values {
			t.Mul(&batch[j], &values[j][k])
			sigma.Add(&sigma, &t)
		}
		terms = append(terms, term{combine[k], pt, 0})
		t.Mul(&combine[k], &sigma)
		claim.Add(&claim, &t)
	}
	var allAlphas []fr.Element
	alphas, claim, err := sumcheck.VerifyRounds(tr, claim, product.Degree, proof.Initial)
	if err != nil {
		return fmt.Errorf("whir: initial sumcheck: %w", err)
	}
	allAlphas = append(allAlphas, alphas...)

	prev := oracle{roots, nbPolys, batch}
	for i := 1; i < len(p.Rounds); i++ {
		r, rPrev := p.Rounds[i], p.Rounds[i-1]
		rp := proof.Rounds[i-1]
		if len(rp.Sumcheck) != r.Fold {
			return ErrProofShape
		}
		tr.Append("whir/root", rp.Root[:])
		z0 := tr.Challenge("whir/ood")
		tr.AppendElements("whir/ood/answer", rp.OOD)
		idx := queryIndices(tr, rPrev.Queries, rPrev.Leaves())
		gamma := tr.Challenge("whir/gamma")

		folded, ys, err := checkQueries(prev, rPrev, idx, rp.Queries, alphas)
		if err != nil {
			return fmt.Errorf("whir: iteration %d: %w", i, err)
		}

		// new claim and new weight terms:
		// σ_i = ĥ(α) + γ·y₀ + Σ_j γ^(j+1)·Fold(f_{i−1}, α)(z_j)
		offset := len(allAlphas)
		coef = gamma
		t.Mul(&coef, &rp.OOD)
		claim.Add(&claim, &t)
		terms = append(terms, term{coef, pow(z0, r.NumVars), offset})
		for j := range folded {
			coef.Mul(&coef, &gamma)
			t.Mul(&coef, &folded[j])
			claim.Add(&claim, &t)
			terms = append(terms, term{coef, pow(ys[j], r.NumVars), offset})
		}

		alphas, claim, err = sumcheck.VerifyRounds(tr, claim, product.Degree, rp.Sumcheck)
		if err != nil {
			return fmt.Errorf("whir: iteration %d sumcheck: %w", i, err)
		}
		allAlphas = append(allAlphas, alphas...)
		prev = single(rp.Root)
	}

	// final polynomial against the last oracle
	last := p.Rounds[len(p.Rounds)-1]
	tr.AppendElements("whir/final", proof.Final...)
	idx := queryIndices(tr, last.Queries, last.Leaves())
	folded, ys, err := checkQueries(prev, last, idx, proof.FinalQueries, alphas)
	if err != nil {
		return fmt.Errorf("whir: final queries: %w", err)
	}
	for j := range folded {
		if got := proof.Final.Evaluate(pow(ys[j], p.FinalVars), nil); !got.Equal(&folded[j]) {
			return ErrFold
		}
	}

	// final constraint: Σ_b W(α, b)·f̂_M(b) = claim. Each term of W is
	// coef·eq(point, (α', b)) = coef·eq(head, α')·eq(tail, b), and
	// Σ_b eq(tail, b)·f̂_M(b) = f̂_M(tail).
	var sum fr.Element
	for _, tm := range terms {
		split := len(tm.point) - p.FinalVars
		e := evalEq(tm.point[:split], allAlphas[tm.offset:])
		v := proof.Final.Evaluate(tm.point[split:], nil)
		e.Mul(&e, &v).Mul(&e, &tm.coef)
		sum.Add(&sum, &e)
	}
	if !sum.Equal(&claim) {
		return ErrConstraint
	}
	return nil
}
