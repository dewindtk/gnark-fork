# PANURUS — requirements for using `hyperplonk` in the zkatsnark driver

## 0. Status update (2026-10-30) — integration model open (PLAN D8)

panurus#2539 was **merged on 2026-10-28** (merge commit `01e06a2e`, base `feature/zkat-snark-driver`) in a different form than described below: it **vendors plonkfri** into Panurus (`x/token/core/zkatsnark/nogh/v1/crypto/internal/plonkfri/{bn254,nativefri}`), on plain upstream gnark **v0.16.4** / gnark-crypto **v0.22.0**, with **no `replace`** directive; `crypto/backend/plonkfri.go` calls the vendored `plonkfri.Setup(spr *cs_bn254.SparseR1CS)` directly. The sections below were written for the earlier fork-`replace` model; §1 (backend contract), §3 (hardening), §4 (circuits) and §5 (measurements) still hold, while §2 (which gnark API is called) and §6 (go.mod `replace`, stacking on a draft) depend on **D8**. Note: hyperplonk's helpers live in gnark `internal/` packages, so option (a) means vendoring them too.

Derived from LFDT-Panurus/panurus#2539 (plonkfri; read as a draft on 2026-10-27, merged 2026-10-28 — see §0), issue #2538, fork PR #9 (plonkfri serialization) and Panurus `AGENTS.md`. Read 2026-10-27.

## 1. Panurus backend contract

`x/token/core/zkatsnark/nogh/v1/crypto/backend/backend.go`:
```go
type ProofSystemBackend interface {
    Setup(cs constraint.ConstraintSystem) (pk, vk []byte, err error)
    NewProvingKey(raw []byte) (*ProvingKey, error)
    NewVerifyingKey(raw []byte) (*VerifyingKey, error)
    Prove(cs constraint.ConstraintSystem, pk *ProvingKey, w witness.Witness) ([]byte, error)
    Verify(vk *VerifyingKey, proof []byte, publicWitness witness.Witness) error
}
```
Handles are immutable and used concurrently. plonkfri backend: BN254-only constructor; `sparseR1CS(cs)` checks both the Go type and `spr.Type == constraint.SystemSparseR1CS` (R1CS and SparseR1CS share a Go type); `readFromExact` rejects trailing bytes (`ErrTrailingBytes`); handle checks (non-nil, system, curve, type); errors via FSC `errors` package.

## 2. gnark-side API Panurus calls (must exist in `backend/hyperplonk`)

- `Setup(constraint.ConstraintSystem) (ProvingKey, VerifyingKey, error)`; `Prove(ccs, pk, fullWitness, ...backend.ProverOption) (Proof, error)`; `Verify(proof, vk, publicWitness, ...backend.VerifierOption) error`.
- `NewProof/NewProvingKey/NewVerifyingKey(ecc.ID)` — same signature as plonk/plonkfri; never panic on BN254 (tested), documented panic on other curves (Panurus's constructor already rejects non-BN254 before any gnark call).
- Dispatcher `Setup/Prove` return an error (not panic) when `ccs.Type != SystemSparseR1CS` or the type is wrong; R1CS-rejection test in the fork too.
- `Proof`, `ProvingKey`, `VerifyingKey` embed `io.WriterTo`, `io.ReaderFrom`; `ProvingKey.VerifyingKey()`, `VerifyingKey.NbPublicWitness()`.
- Exported: `ErrInvalidKey`, `ErrInvalidProof`, `ErrCommitmentsUnsupported`, `MaxLogSize` (plonkfri: 17 — Panurus circuits are 2^14).

## 3. Hardening (copy plonkfri #9, plus a version tag)

Header validated before allocation (μ ≤ MaxLogSize, ℓ < n, WHIR params looked up from the canonical `whir.Header` (TableVersion, m, logInvRate, k, PoW, λ, regime, mode, hashID) in the frozen table; VK modes validated (P Standard, W = H mode); Panurus backend rejects Standard-mode VKs); all length prefixes bounded; chunked reads (2^14); canonical field elements; PK stores only non-derivable data and on `ReadFrom` recomputes the P commitment and rejects mismatch with the VK; exact consumption; deterministic re-encoding; **magic + version byte** on VK/PK/proof; WHIR parameter set in VK digest. Fuzz property: accepted input re-encodes to exactly the consumed bytes. `-race` parallel Verify on one VK.

## 4. Circuits

Spend and Output circuits (2^14 rows) are commitment-free since #2539 (`ValueCommitCircuit` rewritten with `DoubleBaseScalarMul`; `MaxBits` range check). Migration circuit is BLS12-381-only → unavailable on BN254 (document). `csBuilder` must treat `"hyperplonk"` like `"plonk"`/`"plonkfri"` (scs builder).

## 5. Measured plonkfri trade-offs (BN254, 2-in/2-out, 10 CPUs)

| | plonk | plonkfri |
|---|---|---|
| Proof | 520 B | ~841 KiB |
| Validation P50, 1 worker | 4.21 ms | 10.18 ms |
| Throughput, 1 worker | 235/s | 97/s |
| Memory / validation | 0.37 MB | 19.3 MB |

hyperplonk adds prover memory to watch: the PK holds the encoded P (≈ 32 MiB at 2^14, ρ = 1/8) — report it in the Panurus trade-off table.

Transfer request ≈ 2.5 MiB vs default 256 KiB limit; plonkfri fixtures override `resourceLimitsFor` (16 MiB request/action, 4 MiB proof). Default `MaxProofBytes` = 128 KiB.
Goals for hyperplonk: PLAN.md §5. Per decision D1, Panurus request/proof limits are raised for hyperplonk as for plonkfri; they do not constrain the design.

## 6. Panurus PR checklist (mirror of #2539)

Prerequisite: fork M6 (review) merged; **stacked on panurus#2539** (hard dependency: hyperplonk also rejects BSB22, so it needs #2539's `ValueCommitCircuit` rewrite, `MaxBits` check, trailing-bytes handling; #2539 is itself a draft blocked on fork PR #9); Panurus `replace github.com/consensys/gnark => <fork master commit that merged feature/hyperplonk>` in 5 modules (`x/token/core/zkatsnark`, `cmd/artifactgen`, `cmd/node`, `cmd/tokengen`, `integration`), `make tidy-check` clean.
- `crypto/backend/hyperplonk.go` (copy of `plonkfri.go`, `systemHyperPlonk = "hyperplonk"`), dispatch case in `backend.go`.
- `crypto/backend/hyperplonk_test.go`: construction/other-curve, round trip + wrong public input, deterministic setup, invalid witness, tampered/truncated/nil/garbage proofs, corrupt keys, foreign keys (plonk↔plonkfri↔hyperplonk), nil keys, R1CS rejection, `FuzzHyperPlonkVerifyNoPanic`, row in `TestTrailingBytesRejected`.
- `pp/pp.go` + test: accept `"hyperplonk"` BN254-only — introduce a table/set of BN254-only systems instead of a third string check.
- `setup/setup.go` + test: `csBuilder` case, `CompileCircuits`/`SetupAll`, unsupported-curve error.
- `validator/validator_test.go` e2e row; `benchmark_flags_test.go` flag.
- `testutils/env.go` `resourceLimitsFor` currently matches only `"plonkfri"`: add `"hyperplonk"` with **measured** limits (also used by `env_openpolicy.go`); document required limits in `docs/drivers/zkatsnark.md`.
- proto comment only; `docs/drivers/zkatsnark.md` section (constraints, measured trade-offs, hardening, "experimental / not externally reviewed").
- `.github/workflows/nightly-fuzz.yml` entry.
- Process (Panurus AGENTS.md): issue first (Feature, labels `enhancement`/`security`/`token-driver`, milestone "ZKAT Snark Driver"), `plan.md`, godoc, testify, DCO sign-off, rebase, `golangci-lint`, `make checks`, unit + `-race` + **integration tests run**, `Closes #N`; push/PR only with user go-ahead. 
