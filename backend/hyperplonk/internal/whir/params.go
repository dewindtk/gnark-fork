// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package whir

import (
	"errors"
	"fmt"
	"math"
)

// log2 of the bn254 scalar field size.
const logField = 253.59669135500215

// Regime selects the proximity parameter δ and with it the theory the
// soundness rests on (docs/hyperplonk/THEORY.md, W6, A1, D2).
type Regime int

const (
	// UniqueDecoding: δ = (1 − ρ)/2. Mutual correlated agreement is proven
	// in the WHIR paper (ePrint 2024/1586, Lemma 4.10, Cor. 4.11); lists
	// have size 1.
	UniqueDecoding Regime = iota
	// Johnson: δ = 1 − 1.05·√ρ (η = √ρ/20, WHIR §6.2). Mutual correlated
	// agreement from ePrint 2025/2110, Thm 2 (multiplicity 10); list size
	// 1/(2η√ρ) = 10/ρ by the Johnson bound (WHIR Thm 4.3). Preprint results.
	Johnson
)

func (r Regime) String() string {
	if r == Johnson {
		return "Johnson"
	}
	return "UniqueDecoding"
}

// Round describes iteration i of the protocol: the oracle f_i, a codeword of
// RS[F, L_i, m_i], the number of sumcheck/folding rounds k_i applied to it,
// and the number t_i of queries made to it.
type Round struct {
	NumVars   int // m_i
	LogDomain int // log₂|L_i|
	Fold      int // k_i
	Queries   int // t_i
}

// LogInvRate is log₂(1/ρ_i) = LogDomain − NumVars.
func (r Round) LogInvRate() int { return r.LogDomain - r.NumVars }

// Leaves is the number of Merkle leaves of f_i: one per point of L_i^(2^k_i).
func (r Round) Leaves() int { return 1 << (r.LogDomain - r.Fold) }

// Params fixes one instance of WHIR (ePrint 2024/1586, Construction 5.1).
type Params struct {
	NumVars      int // m = m₀
	LogInvRate   int // log₂(1/ρ₀)
	Folding      int // k
	SecurityBits int // λ: every round-by-round error is at most 2^−λ
	Regime       Regime
	Rounds       []Round // i = 0..M−1
	FinalVars    int     // m_M: the final polynomial is sent in clear
}

// NewParams derives the schedule.
//
//   - k₀ = min(k, m); further iterations with k_i = k while at least k
//     variables remain. The rest (fewer than k variables) is sent in clear.
//   - L_i = L_{i−1}², so |L_i| = |L₀|/2^i and the rate drops by 2^(k−1) per
//     iteration (WHIR §2.1).
//   - t_i is the least number of queries with (1 − δ_i)^t ≤ 2^−λ up to the
//     additive term of ε_shift, which Check accounts for exactly.
func NewParams(numVars, logInvRate, folding, securityBits int, regime Regime) (Params, error) {
	if numVars < 0 || numVars > 26 || logInvRate < 1 || folding < 1 || securityBits < 1 {
		return Params{}, errors.New("whir: invalid parameters")
	}
	p := Params{NumVars: numVars, LogInvRate: logInvRate, Folding: folding, SecurityBits: securityBits, Regime: regime}
	remaining := numVars
	logDomain := numVars + logInvRate
	for i := 0; i == 0 || remaining >= folding; i++ {
		k := min(folding, remaining)
		r := Round{NumVars: remaining, LogDomain: logDomain, Fold: k}
		// the +0.01 leaves room for the additive term ℓ·(t+1)/|F|
		r.Queries = int(math.Ceil((float64(securityBits) + 0.01) / -math.Log2(1-p.delta(r))))
		p.Rounds = append(p.Rounds, r)
		remaining -= k
		logDomain--
	}
	p.FinalVars = remaining
	if err := p.Check(); err != nil {
		return Params{}, err
	}
	return p, nil
}

func (p Params) rate(r Round) float64 { return math.Pow(2, -float64(r.LogInvRate())) }

// delta is δ_i for the codes RS[F, L_i^(2^s), m_i − s], s ≤ k_i. They all
// have rate ρ_i.
//
// Unique decoding: Lemma 4.10 holds for δ < δ_C/2 with δ_C the relative
// minimum distance, which for Reed–Solomon is 1 − ρ + 1/|L| > 1 − ρ. So
// δ = (1 − ρ)/2 lies strictly inside the allowed range (THEORY S10).
func (p Params) delta(r Round) float64 {
	rho := p.rate(r)
	if p.Regime == Johnson {
		return 1 - 1.05*math.Sqrt(rho)
	}
	return (1 - rho) / 2
}

// logListSize is log₂ of the list size bound ℓ at distance δ_i.
func (p Params) logListSize(r Round) float64 {
	if p.Regime == Johnson {
		return math.Log2(10) + float64(r.LogInvRate()) // 1/(2η√ρ) = 10/ρ
	}
	return 0
}

// logMCA is log₂ of err*(C, s, δ) for C = RS[F, L, m'] with rate ρ_i and
// the generator (1, x, …, x^(s−1)): the error of mutual correlated agreement
// for a random combination of s words.
//
//   - Unique decoding: (s − 1)·2^m'/(ρ·|F|) (WHIR Cor. 4.11).
//   - Johnson: (1/|F|)·((10 + 1/2)⁷/(3·ρ^(3/2)))·(s − 1)·n² with n = |L|
//     (ePrint 2025/2051, Def. 9.1, Thm 9.2, multiplicity 10). For s = 2 this
//     is the bound of ePrint 2025/2110, Thm 2.
func (p Params) logMCA(r Round, vars, s int) float64 {
	rate := float64(r.LogInvRate())
	if p.Regime == Johnson {
		n := float64(vars) + rate
		return 7*math.Log2(10.5) - math.Log2(3) + 1.5*rate + math.Log2(float64(s-1)) + 2*n - logField
	}
	return math.Log2(float64(s-1)) + float64(vars) + rate - logField
}

// ErrorTerm is one round-by-round soundness error of WHIR Thm 5.2 (or of
// Thm 5.6 for the combination of constraints), as log₂.
type ErrorTerm struct {
	Name string
	Log2 float64
}

func logAdd(a, b float64) float64 { // log₂(2^a + 2^b)
	if a < b {
		a, b = b, a
	}
	return a + math.Log2(1+math.Pow(2, b-a))
}

// Errors evaluates every error term for a batched opening of nbPolys
// polynomials with nbClaims constraints.
func (p Params) Errors(nbClaims, nbPolys int) []ErrorTerm {
	var out []ErrorTerm
	// Thm 7.5, ε_com: combining the committed words into one,
	// err*(C, s, δ) + (s − 1)·ℓ/|F| (ℓ: list size of the interleaved code,
	// equal to that of the code by Lemma 4.4)
	if nbPolys > 1 {
		r0 := p.Rounds[0]
		out = append(out, ErrorTerm{"batch", logAdd(p.logMCA(r0, r0.NumVars, nbPolys), math.Log2(float64(nbPolys-1))+p.logListSize(r0)-logField)})
		// Thm 7.5, ε_out at commitment time: s·2^m·ℓ²/(2|F|)
		out = append(out, ErrorTerm{"commit-out", math.Log2(float64(nbPolys)) + float64(r0.NumVars) + 2*p.logListSize(r0) - 1 - logField})
	}
	// Thm 5.6: (t − 1)·ℓ/|F|
	if nbClaims > 1 {
		out = append(out, ErrorTerm{"combine", math.Log2(float64(nbClaims-1)) + p.logListSize(p.Rounds[0]) - logField})
	}
	const d = 3 // d* = 1 + deg_Z ŵ + max deg_X ŵ = 3 for linear weights Z·W(X), W multilinear
	for i, r := range p.Rounds {
		l := p.logListSize(r)
		if i > 0 {
			prev := p.Rounds[i-1]
			// ε_out ≤ 2^m_i·ℓ²/(2|F|)
			out = append(out, ErrorTerm{fmt.Sprintf("out[%d]", i), float64(r.NumVars) + 2*l - 1 - logField})
			// ε_shift ≤ (1 − δ_{i−1})^t_{i−1} + ℓ·(t_{i−1} + 1)/|F|
			q := float64(prev.Queries) * math.Log2(1-p.delta(prev))
			out = append(out, ErrorTerm{fmt.Sprintf("shift[%d]", i), logAdd(q, l+math.Log2(float64(prev.Queries+1))-logField)})
		}
		// ε_fold ≤ d·ℓ/|F| + err*(RS[L_i^(2^s), m_i − s], 2, δ_i), s = 1..k_i
		for s := 1; s <= r.Fold; s++ {
			out = append(out, ErrorTerm{fmt.Sprintf("fold[%d,%d]", i, s), logAdd(math.Log2(d)+l-logField, p.logMCA(r, r.NumVars-s, 2))})
		}
	}
	last := p.Rounds[len(p.Rounds)-1]
	out = append(out, ErrorTerm{"final", float64(last.Queries) * math.Log2(1-p.delta(last))})
	return out
}

// Check verifies that every error term is at most 2^−λ and that the schedule
// is consistent.
func (p Params) Check() error {
	for _, e := range p.Errors(64, 16) {
		if e.Log2 > -float64(p.SecurityBits) {
			return fmt.Errorf("whir: error term %s is 2^%.2f, above 2^-%d", e.Name, e.Log2, p.SecurityBits)
		}
	}
	vars := p.NumVars
	for _, r := range p.Rounds {
		if r.NumVars != vars || r.LogDomain < r.NumVars || r.Fold > r.NumVars {
			return errors.New("whir: inconsistent schedule")
		}
		vars -= r.Fold
	}
	if vars != p.FinalVars {
		return errors.New("whir: inconsistent schedule")
	}
	return nil
}
