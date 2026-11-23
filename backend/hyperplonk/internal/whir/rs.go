// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package whir

import (
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"

	"github.com/consensys/gnark/backend/hyperplonk/internal/par"
)

// Smooth Reed–Solomon codes (ePrint 2024/1586, Def. 4.2).
//
// A multilinear polynomial f̂ in m variables is encoded as the function
//
//	f : L → F,  f(x) = f̂(x, x², x⁴, …, x^(2^(m−1)))
//
// on L = ⟨ω⟩, the subgroup of order 2^logDomain. Equivalently f is the
// evaluation on L of the univariate polynomial whose coefficient of x^e is
// the coefficient of the monomial Π_{i : bit i−1 of e is set} X_i of f̂.
//
// f̂ is given by its table on the hypercube in gnark-crypto's layout (X₁ is the
// top bit of the index). Encoding therefore is: hypercube values → monomial
// coefficients (one subtraction pass per variable), reorder so that X₁ becomes
// the lowest bit (bit reversal), FFT.

// Pow returns (z, z², z⁴, …, z^(2^(m−1))): the point at which the multilinear
// polynomial of a codeword takes the value of its univariate form at z.
func Pow(z fr.Element, m int) []fr.Element { return pow(z, m) }

// pow returns (z, z², z⁴, …, z^(2^(m−1))).
func pow(z fr.Element, m int) []fr.Element {
	p := make([]fr.Element, m)
	for i := range p {
		p[i] = z
		z.Square(&z)
	}
	return p
}

// domainElement returns ω^i for the generator ω of the subgroup of order
// 2^logDomain.
func domainElement(logDomain int, i int) fr.Element {
	gen := generator(logDomain)
	var x fr.Element
	x.Exp(gen, new(big.Int).SetUint64(uint64(i)))
	return x
}

func generator(logDomain int) fr.Element {
	g, err := fft.Generator(1 << logDomain)
	if err != nil {
		panic(err) // logDomain is bounded by NewParams, far below the 2-adicity 28
	}
	return g
}

// domains caches the FFT domains by size: building one precomputes its
// twiddle factors, which costs about as much as a transform.
var domains sync.Map

func domain(size int) *fft.Domain {
	if d, ok := domains.Load(size); ok {
		return d.(*fft.Domain)
	}
	d, _ := domains.LoadOrStore(size, fft.NewDomain(uint64(size)))
	return d.(*fft.Domain)
}

// encode returns the codeword of the table in natural order: out[i] = f(ω^i).
func encode(table polynomial.MultiLin, logDomain int) []fr.Element {
	n := len(table)
	coeffs := make([]fr.Element, 1<<logDomain)
	copy(coeffs, table)
	c := coeffs[:n]
	// hypercube values → monomial coefficients: for each variable,
	// (value at 0, value at 1) → (constant term, slope)
	for half := n / 2; half >= 1; half /= 2 {
		h := half
		par.Range(n/(2*h), max(1, 4096/h), func(first, last int) {
			for blk := first; blk < last; blk++ {
				start := blk * 2 * h
				for i := start; i < start+h; i++ {
					c[i+h].Sub(&c[i+h], &c[i])
				}
			}
		})
	}
	if n > 1 {
		fft.BitReverse(c) // X₁ from top bit to bit 0: index = exponent of x
	}
	domain(len(coeffs)).FFT(coeffs, fft.DIF)
	fft.BitReverse(coeffs)
	return coeffs
}

// leaves groups a codeword on L (|L| = N) into N/2^k leaves. Leaf i holds
// f(x·ζ^j), j = 0..2^k−1, for x = ω^i and ζ = ω^(N/2^k): the 2^k points of L
// whose 2^k-th power is y = ω^(i·2^k). These are exactly the values needed to
// evaluate the k-fold folding at y.
func leaves(codeword []fr.Element, k int) [][]fr.Element {
	nb := len(codeword) >> k
	out := make([][]fr.Element, nb)
	flat := make([]fr.Element, len(codeword))
	par.Range(nb, 1024, func(start, end int) {
		for i := start; i < end; i++ {
			leaf := flat[i<<k : (i+1)<<k : (i+1)<<k] // capacity capped: appending to a leaf must not reach the next one
			for j := range leaf {
				leaf[j] = codeword[i+j*nb]
			}
			out[i] = leaf
		}
	})
	return out
}

// foldLeaf computes Fold(f, α)(y) from leaf i (ePrint 2024/1586, Def. 4.14):
//
//	Fold(f, α)(x²) = (f(x) + f(−x))/2 + α·(f(x) − f(−x))/(2x),
//
// applied once per element of α. After one step the leaf is a leaf of the
// folded function on the squared domain, with half the size.
func foldLeaf(leaf []fr.Element, alphas []fr.Element, logDomain, idx int) fr.Element {
	k := len(alphas)
	cur := append([]fr.Element(nil), leaf...)
	x := domainElement(logDomain, idx)
	zeta := domainElement(logDomain, 1<<(logDomain-k)) // order 2^k
	var xInv, zetaInv, twoInv fr.Element
	xInv.Inverse(&x)
	zetaInv.Inverse(&zeta)
	twoInv.SetUint64(2)
	twoInv.Inverse(&twoInv)

	for s := range k {
		half := len(cur) / 2
		pInv := xInv // inverse of the point x·ζ^j
		for j := range half {
			var sum, diff fr.Element
			sum.Add(&cur[j], &cur[j+half]) // f(p) + f(−p): −p = p·ζ^half
			diff.Sub(&cur[j], &cur[j+half])
			diff.Mul(&diff, &pInv).Mul(&diff, &alphas[s])
			sum.Add(&sum, &diff).Mul(&sum, &twoInv)
			cur[j] = sum
			pInv.Mul(&pInv, &zetaInv)
		}
		cur = cur[:half]
		xInv.Square(&xInv)
		zetaInv.Square(&zetaInv)
	}
	return cur[0]
}

// eqTable returns the table b ↦ coef·eq(point, b).
func eqTable(point []fr.Element, coef fr.Element) polynomial.MultiLin {
	eq := make(polynomial.MultiLin, 1<<len(point))
	eq[0] = coef
	eq.Eq(point)
	return eq
}

// addEq adds coef·eq(point, ·) to the table w.
func addEq(w polynomial.MultiLin, point []fr.Element, coef fr.Element) {
	addEqs(w, [][]fr.Element{point}, []fr.Element{coef})
}

// addEqs adds Σ_i coefs[i]·eq(points[i], ·) to the table w. The eq tables
// are built in parallel, each worker summing its share into a table of its
// own; the partial sums are then added to w.
func addEqs(w polynomial.MultiLin, points [][]fr.Element, coefs []fr.Element) {
	workers := min(par.Workers(), len(points))
	if len(w) < 1<<10 || workers <= 1 {
		for i, pt := range points {
			eq := eqTable(pt, coefs[i])
			for j := range w {
				w[j].Add(&w[j], &eq[j])
			}
		}
		return
	}
	partial := make([]polynomial.MultiLin, workers)
	par.Range(workers, 1, func(start, end int) {
		for k := start; k < end; k++ {
			acc := make(polynomial.MultiLin, len(w))
			for i := k; i < len(points); i += workers {
				eq := eqTable(points[i], coefs[i])
				for j := range acc {
					acc[j].Add(&acc[j], &eq[j])
				}
			}
			partial[k] = acc
		}
	})
	par.Range(len(w), 4096, func(start, end int) {
		for _, acc := range partial {
			for j := start; j < end; j++ {
				w[j].Add(&w[j], &acc[j])
			}
		}
	})
}

// evalEq is eq(a, b) for vectors of equal length; 1 for empty vectors.
func evalEq(a, b []fr.Element) fr.Element {
	if len(a) == 0 {
		var one fr.Element
		one.SetOne()
		return one
	}
	return polynomial.EvalEq(a, b)
}
