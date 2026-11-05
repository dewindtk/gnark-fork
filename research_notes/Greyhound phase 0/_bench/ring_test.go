// Ring-arithmetic cost of R_r = F_r[X]/(X^32+1) (bn254 Fr, gnark-crypto) versus
// R_q = Z_q[X]/(X^64+1), q = 2^32-99 (Greyhound/Akita 32-bit profile), both scalar Go.
// The "_" directory keeps it out of ./... (the parent path has a space, an invalid import path).
// Run: cp -r "research_notes/Greyhound phase 0/_bench" internal/tmpghbench && go test -run x -bench . ./internal/tmpghbench; rm -r internal/tmpghbench
package bench

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
)

const q32 = uint64(1<<32 - 99)

var sink uint64

func BenchmarkFrMul(b *testing.B) {
	var x, y fr.Element
	x.SetRandom()
	y.SetRandom()
	for i := 0; i < b.N; i++ {
		x.Mul(&x, &y)
	}
}

func BenchmarkU32ModMul(b *testing.B) {
	x, y := uint64(123456789), uint64(987654321)
	for i := 0; i < b.N; i++ {
		x = x * y % q32
	}
	sink = x
}

// Negacyclic multiplication over F_r with d = 32: twist by psi^i, 32-point NTT, pointwise, inverse.
func BenchmarkRingMulFr32(b *testing.B) {
	const d = 32
	dom := fft.NewDomain(d)
	// psi: primitive 64th root of unity, psi^32 = -1
	var psi fr.Element
	e := new(big.Int).Div(new(big.Int).Sub(fr.Modulus(), big.NewInt(1)), big.NewInt(2*d))
	psi.SetUint64(5).Exp(psi, e)
	tw := make([]fr.Element, d)
	itw := make([]fr.Element, d)
	tw[0].SetOne()
	for i := 1; i < d; i++ {
		tw[i].Mul(&tw[i-1], &psi)
	}
	for i := range tw {
		itw[i].Inverse(&tw[i])
	}
	a, c := make([]fr.Element, d), make([]fr.Element, d)
	for i := range a {
		a[i].SetRandom()
		c[i].SetRandom()
	}
	A, C := make([]fr.Element, d), make([]fr.Element, d)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		for i := 0; i < d; i++ {
			A[i].Mul(&a[i], &tw[i])
			C[i].Mul(&c[i], &tw[i])
		}
		dom.FFT(A, fft.DIF)
		dom.FFT(C, fft.DIF)
		for i := 0; i < d; i++ {
			A[i].Mul(&A[i], &C[i])
		}
		dom.FFTInverse(A, fft.DIT)
		for i := 0; i < d; i++ {
			A[i].Mul(&A[i], &itw[i])
		}
	}
}

// Schoolbook negacyclic multiplication over Z_q, q = 2^32-99, d = 64 (q = 5 mod 8 has no NTT).
func BenchmarkRingMulQ32(b *testing.B) {
	const d = 64
	a, c, out := make([]uint64, d), make([]uint64, d), make([]uint64, d)
	for i := range a {
		a[i] = uint64(i*2654435761) % q32
		c[i] = uint64(i*40503+7) % q32
	}
	for n := 0; n < b.N; n++ {
		for i := range out {
			out[i] = 0
		}
		for i := 0; i < d; i++ {
			for j := 0; j < d; j++ {
				p := a[i] * c[j] % q32
				if i+j < d {
					out[i+j] = (out[i+j] + p) % q32
				} else {
					out[i+j-d] = (out[i+j-d] + q32 - p) % q32
				}
			}
		}
	}
	sink = out[0]
}

// Sanity: the F_r negacyclic product equals schoolbook.
func TestRingMulFr32(t *testing.T) {
	const d = 32
	dom := fft.NewDomain(d)
	var psi fr.Element
	e := new(big.Int).Div(new(big.Int).Sub(fr.Modulus(), big.NewInt(1)), big.NewInt(2*d))
	psi.SetUint64(5).Exp(psi, e)
	var chk fr.Element
	chk.Exp(psi, big.NewInt(d))
	var m1 fr.Element
	m1.SetOne().Neg(&m1)
	if !chk.Equal(&m1) {
		t.Fatal("psi^32 != -1")
	}
	a, c := make([]fr.Element, d), make([]fr.Element, d)
	for i := range a {
		a[i].SetRandom()
		c[i].SetRandom()
	}
	want := make([]fr.Element, d)
	for i := 0; i < d; i++ {
		for j := 0; j < d; j++ {
			var p fr.Element
			p.Mul(&a[i], &c[j])
			if i+j < d {
				want[i+j].Add(&want[i+j], &p)
			} else {
				want[i+j-d].Sub(&want[i+j-d], &p)
			}
		}
	}
	tw := make([]fr.Element, d)
	tw[0].SetOne()
	for i := 1; i < d; i++ {
		tw[i].Mul(&tw[i-1], &psi)
	}
	A, C := make([]fr.Element, d), make([]fr.Element, d)
	for i := 0; i < d; i++ {
		A[i].Mul(&a[i], &tw[i])
		C[i].Mul(&c[i], &tw[i])
	}
	dom.FFT(A, fft.DIF)
	dom.FFT(C, fft.DIF)
	for i := 0; i < d; i++ {
		A[i].Mul(&A[i], &C[i])
	}
	dom.FFTInverse(A, fft.DIT)
	for i := 0; i < d; i++ {
		var inv fr.Element
		inv.Inverse(&tw[i])
		A[i].Mul(&A[i], &inv)
		if !A[i].Equal(&want[i]) {
			t.Fatalf("coefficient %d differs", i)
		}
	}
}
