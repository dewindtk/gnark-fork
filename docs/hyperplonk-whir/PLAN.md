# HyperPlonk + WHIR for gnark — design and execution plan

Status: **revised 2026-10-27 after two design reviews (§10, §11) and an implementation-readiness audit (§12). Implementation can start once the kick-off checklist (§0) is done.** Student-oriented overview: [`OVERVIEW.md`](OVERVIEW.md). Nothing implemented yet.
Companion specs (normative for implementers):
- [`SPEC-WHIR.md`](SPEC-WHIR.md) — the WHIR multilinear PCS in the zook (code-switch) structure, Standard and ZK modes; parameters; pitfalls.
- [`SPEC-PIOP.md`](SPEC-PIOP.md) — the HyperPlonk PIOP over gnark SparseR1CS, transcript, ZK, soundness.
- [`PANURUS.md`](PANURUS.md) — what the Panurus `zkatsnark` driver needs (mirrors LFDT-Panurus/panurus#2539).

## 0. Kick-off checklist (must be done before the first agent is launched)

| # | Item | Owner | Status |
|---|---|---|---|
| K1 | Merge fork PR #9 into `master` (D4) | user | **done 2026-10-27** (merge commit `16a40bc2`) |
| K2 | Create the **feature branch `feature/hyperplonk`** from `master` @ `16a40bc2`; commit these docs + `PROJECT.md` on it and push (branching model §7.0) | coordinator | **done 2026-10-30** (`06ca7bd6`) |
| K3 | **M−1 hygiene PR → `master`** (it fixes master itself; then merged into `feature/hyperplonk`): master is red under `go test -short ./...` today (verified 2026-10-27): `TestVersion` ("latest git tag is more recent than hardcoded Version") and `internal/stats` `TestCircuitStatistics` panics "not implemented" for PLONKFRI. Fix: `internal/stats` uses `scs.NewBuilder` for every SCS-based backend and skips backends without reference stats; `TestVersion` fixed or skipped with a recorded reason. HYPERPLONK enters `backend.Implemented()` in M1b. | coordinator → agent | open |
| K4 | CI: **decided 2026-10-27 — gate evidence = the coordinator's local run** (full-tree check output pasted into each milestone PR), for now; Actions may be enabled later. Toolchain rule: **no APIs newer than go1.25** (go.mod 1.25.7; local Go 1.27.3); golangci-lint pinned to CI's version (2.10.1). | user | **done** |
| K5 | Spec edits from the readiness audit (§12) | coordinator | **done 2026-10-27** |
| K6 | Papers in `resources/`: all cited ePrint papers (incl. 2022/1355, 2022/1530, 2024/1586, 2026/391, 2026/1367, 2025/2046, 2025/2051, 2025/2055, 2025/2110) | coordinator | **done 2026-10-30** (`cac2903e`) |
| K7 | Brief template (`briefs/TEMPLATE.md`), gate template (`gates/TEMPLATE.md`), full briefs for M0a and M1a | coordinator | template **done**, briefs open |
| K8 | Permissions for background agents: `go build/test/vet`, `gofmt`, `golangci-lint` in worktrees; `docker build/run` for `internal/whir/testdata/rustref` (network only at image build). **Approved by the user 2026-10-27**; the coordinator writes the project allowlist at kick-off and shows it to the user | coordinator | approved, to configure |
| K9 | Session-log entry in `PROJECT.md` | coordinator | done |
| K10 | Execution ledger `STATUS.md` (§7.4) and `reports/` | coordinator | **done 2026-10-30** |

## 1. Goal

A new gnark backend `backend/hyperplonk` (backend ID `HYPERPLONK`): the HyperPlonk PIOP (ePrint 2022/1355) with the WHIR multilinear PCS (ePrint 2024/1586) in the zero-knowledge-ready structure of ePrint 2026/391 ("zook" in the reference implementation), over bn254 `fr`, transparent and plausibly post-quantum. Then integrate it into Panurus's `zkatsnark` driver the same way `plonkfri` is integrated in panurus#2539.

Why: plonkfri proofs are ~841 KiB (Panurus measurement). HyperPlonk + WHIR is estimated 1.5–4× smaller at the same security target (one opening point, three top-level commitments — plus WHIR's per-round trees — instead of five, WHIR's shrinking rounds), with a comparable verifier.

## 2. Requirements

| # | Requirement | Source |
|---|---|---|
| R1 | Input: gnark `SparseR1CS` (bn254) from `scs.NewBuilder`; same gate set as plonkfri (qL,qR,qO,qM,qC + copy constraints). Reject BSB22 commitments with exported `ErrCommitmentsUnsupported`; reject `ccs.Type != SystemSparseR1CS` with an error (R1CS shares the Go type). Shared-suite coverage as plonkfri (31/33). | gnark, PANURUS §3, review F12 |
| R2 | Security: **128-bit classical**, plausibly PQ; random-oracle model (not QROM) for soundness and ZK. Each of the 3 WHIR openings targets λ = 130 so the union stays ≥ 128. Proven bounds only (Johnson via 2025/2051 + 2025/2110, or unique decoding); no capacity conjecture. | PROJECT.md, SPEC-WHIR §2, F17 |
| R3 | Strong Fiat–Shamir: VK digest (incl. WHIR params, hash ID) and public inputs absorbed first. | 2023-691, SPEC-PIOP §3 |
| R4 | Zero-knowledge (HVZK → NIZK in ROM). **Mandatory before Panurus.** | SPEC-PIOP §4 |
| R5 | API parity with plonkfri after fork PR #9: `Setup/Prove/Verify`, `NewProof/NewProvingKey/NewVerifyingKey(ecc.ID)` (same signature; never panic on BN254, documented panic otherwise, tested), `io.WriterTo/ReaderFrom`, `NbPublicWitness()`, exported `ErrInvalidKey/ErrInvalidProof/MaxLogSize`. Dispatcher returns errors on wrong type/kind. | PANURUS §2, F20 |
| R6 | Hardened decoding: magic + version, bounded lengths, chunked reads, canonical field elements, WHIR params looked up from the canonical `whir.Header` (SPEC-WHIR §4) in a frozen table, PK re-derived and checked against VK, exact consumption, deterministic re-encoding, fuzz-clean. | PANURUS §3, F13, review-2 F1/F13 |
| R7 | Concurrency: shared VK/PK safe across goroutines (hash constructors from `HashID`, no mutable scratch in keys); `-race` test. | fork PR #9 |
| R8 | Deterministic transparent Setup (byte-identical keys). P is therefore committed in Standard (non-ZK) mode always. | PANURUS §6, F6 |
| R9 | Every soundness claim has a cheating-prover test that (a) accepts the honest proof, (b) rejects the cheater 0/N, (c) **accepts the cheater when the targeted check is disabled** by a test-only flag (mutation check); rejecting check recorded. ZK has a structural rank test, red with ZK off. | PROJECT.md lessons, F10 |
| R10 | `ChallengeHash` option: probe it (fixed test vector) against the VK's hash ID; mismatch → error. | F14 |
| R11 | Attack tests always run: **N = 8 under `-short`, N = 200 otherwise, acceptance threshold 0/N**; ZK structural tests are deterministic; fuzz and perf are opt-in (`-fuzz`, `HYPERPLONK_PERF=1`); attack tests are never behind a build tag. | F18, review-2 F15, audit 27 |
| R12 | No floating point at Setup/Prove/Verify: WHIR parameters come from a frozen generated table, every row re-checked by an exact security checker. | review-2 F1 |
| R13 | `Setup` options select mode/regime; default Standard + Johnson until M3e (ZK → `pcs.ErrUnsupported`), then ZK + Johnson; the Panurus backend rejects Standard-mode VKs. | review-2 F14, audit 18 |
| R14 | Code ported from `WizardOfMenlo/whir@c73b8d3` (dual-licensed via `LICENSE-MIT` / `LICENSE-APACHE`; no SPDX field in `Cargo.toml`) carries `// Portions derived from github.com/WizardOfMenlo/whir@c73b8d3 (MIT or Apache-2.0)`; `THIRD_PARTY_NOTICES` lists both licence texts. | audit 25 |
| R15 | Golden files: `testdata/golden/<name>.bin`, RNG `math/rand/v2` ChaCha8 seeded `[32]byte{'h','p'}`, `-update` flag regenerates, header records `TableVersion` + FS-grammar version; any change needs a PR note. | audit 28 |
| R16 | Perf: `BenchmarkProve/Verify` at 2^14 and 2^16, `GOMAXPROCS=1` and default, `-benchmem`; peak memory via `runtime.MemStats`; results table in `PROJECT.md`. | audit 29 |

## 3. Architecture

```
backend/backend.go                     + HYPERPLONK (appended after PLONKFRI; String "hyperPlonk")
backend/hyperplonk/hyperplonk.go       dispatcher (shape of plonkfri.go after PR #9) + ccs.Type check
backend/hyperplonk/suite_test.go       copy of plonkfri suite
backend/hyperplonk/bn254/
    setup.go        rows/selectors/permutation (reuse plonkfri buildPermutation), stack P, commit P (Standard), VK digest
    prove.go        solve → commit W → (β,γ) → LogUp helpers → commit H → (α,r) → batched sumcheck → evals → 3 WHIR openings
    verify.go       replay transcript, sumcheck verify, final identity, PI(ρ), id_j(ρ), WHIR verify ×3
    transcript.go   ONE schedule shared by prover and verifier
    export_test.go  test-only cheating seams via unexported per-call config (no globals, no build tag)
    zk.go           witness masks, Libra mask g, round-1 special case
    marshal.go      Proof/VK/PK encoding (R6)
internal/fs/                   labelled sha256 transcript: Absorb, ChallengeField (512-bit = 2 squeezes, exact construction in SPEC-PIOP §3), ChallengeIndices, PoW
internal/encoding/             bounded Reader/Writer (lifted from PR #9)
internal/merkle/               sha256 Merkle: domain-separated leaf/node, salts, single paths + index dedup (multiproof in M4)
internal/sumcheck/bn254/       generic prover/verifier; per-round degree; round-1 hook for ZK
internal/whir/pcs/             FROZEN boundary: Header, enums, errors, Commitment, LinearForm + constructors, Scheme interface (SPEC-WHIR §4)
internal/plonkperm/            BuildPermutation shared with plonkfri (moved in M1b)
internal/whir/bn254/           WHIR (zook structure) implementing pcs.Scheme: irs, sumcheck rounds, code switch, base case; Standard + ZK modes
internal/whir/bn254/mock/      INSECURE test-only pcs.Scheme (tables in clear, TableVersion 0)
internal/whir/cmd/whirparams/  offline parameter generator (port of reference params/*) → internal/whir/bn254/params_table.go
internal/whir/testdata/pyref/  independent Python reference from the papers: encode, fold, ŵ_x, eq KATs + security checker for table rows
internal/whir/testdata/rustref/ container harness for the pinned Rust reference (derive tables, KATs, real proof sizes)
```

Key design decisions:
- **LogUp permutation check** with committed helpers h_j = 1/a_j − 1/b_j → single opening point ρ, no BatchEval. (SPEC-PIOP §2.1)
- **Public inputs folded into the gate** via PI(X) computed by the verifier. (SPEC-PIOP §1)
- **Three stacked commitments, one WHIR opening each**: P (μ+3 vars, Setup, Standard mode), W = stack(w_0,w_1,w_2,M_W) and H = stack(h_0,h_1,h_2,M_H) (μ+2 vars, ZK mode in v1b). Masks live **inside** W/H because the opened value is public and must already be masked (debate on F3).
- **WHIR = zook structure from day one** (review F1): commit has no OOD; each round = ZK-able sumcheck + code switch (new codeword, ≥ 1 OOD sample, in-domain queries); base case at the end. v1a runs `Standard` mode (no masks, final vector in clear); v1b adds `ZeroKnowledge` mode. Same parameter derivation, same proof skeleton → ZK is an add-on, not a rewrite.
- **One commitment per `Open`, B = 1**, any number of linear forms on that vector. No cross terms. Joint W+H opening (reference `joint.rs`, churning) only in the cost milestone.
- **Hash** sha256 (`HashID`), Poseidon2 later for recursion.

## 4. Decisions (user, 2026-10-27)

| # | Decision | Outcome |
|---|---|---|
| D1 | Proof size vs Panurus limits | Panurus limits can be raised; size is a cost to minimise, not a hard gate. |
| D2 | WHIR regime | Johnson-bound default, unique decoding selectable; regime in VK digest; JB dependency on unrefereed MCA results recorded in security status. Note (F5): both regimes use ≥ 1 OOD sample per round in the zook structure. |
| D3 | ZK | Non-ZK (Standard mode) first, ZK second; Panurus only after ZK. |
| D4 | Prerequisite | Merge fork PR #9 first — **merged 2026-10-27 (`16a40bc2`)**. |
| D5 | PR granularity | One PR per milestone **into `feature/hyperplonk`** (§7.0); milestones are sized to be reviewable (M0a/b, M1a–c, M3a–f are separate milestones). |
| D6 | Reference cross-check | **Consent given 2026-10-27**: run the pinned Rust reference (`WizardOfMenlo/whir@c73b8d3`) in a `rust` container (docker/podman installed) to compare parameter derivation (`ProtocolConfig::derive`) and KATs (encode, fold, ŵ_x, `mle_evaluate`) on bn254 (`Field256`). Python reference kept as a second independent check. Byte-identical proofs are not expected (different transcript). |
| D7 | Branching (user, 2026-10-27) | **HyperPlonk is developed on the feature branch `feature/hyperplonk`**; `master` receives it in one PR after M6 (review). |
| D8 | Panurus integration model (**open, user**) | panurus#2539 merged 2026-10-28 by **vendoring** plonkfri into Panurus (`crypto/internal/plonkfri`) on upstream gnark v0.16.4 / gnark-crypto v0.22.0, with no `replace`. hyperplonk's helpers are gnark `internal/` packages, so Panurus cannot import them from the fork. Options: (a) vendor `backend/hyperplonk` + `internal/{fs,merkle,encoding,sumcheck,whir,plonkperm}` into Panurus like plonkfri; (b) `replace` gnark with the fork again; (c) move the helpers to non-internal packages and upstream. Also: the fork is on v0.16.3 / v0.21.0, Panurus on v0.16.4 / v0.22.0. Decide before M7 (affects M5 packaging). |

## 5. Targets (measured at gates)

At 2^14 rows (Panurus spend/output) and 2^16 (plonkfri reference point). Estimates in SPEC-WHIR §2 / SPEC-PIOP §6.

| Metric | plonkfri today | v1a (M2) | after cost work (M4) | stretch |
|---|---|---|---|---|
| Proof size 2^16, Standard | 0.84–0.90 MB | ≤ 0.6 MB | ≤ 0.45 MB | ≤ 0.25 MB |
| Proof size 2^16, ZK | — | — | set at G0 from reference measurement (estimate +40–80 % over Standard) | — |
| Verify, 1 core | 4–10 ms | ≤ 10 ms | ≤ 6 ms | ≤ 5 ms |
| Prove 2^16, 1 core | 2.1 s | ≤ 2.5 s | ≤ 1.5 s | ≤ 1 s |
| Memory / validation | 19 MB | ≤ 10 MB | ≤ 6 MB | ≤ 4 MB |
| VK size | 172 B | ≤ 1 KiB | — | — |
| Prover memory 2^16 (PK encoded P ≈ 128 MiB, W/H ≈ 64 MiB each) | measure | ≤ 300 MiB | ≤ 200 MiB | — |
| PK in memory 2^14 | ~3 MiB serialized | measure | — | — |

## 6. Milestones

Every milestone: tests per R9 → implementation → reviewer agents on the diff → full-tree check (`go build ./... && go test -run XXX ./... && go test -short ./...`, `go vet`, `gofmt`, `golangci-lint`), run locally by the coordinator → PR `hp/<milestone>` → `feature/hyperplonk` with the check output pasted (K4) → `PROJECT.md` updated. Effort is relative (S ≈ 1 agent-session, M ≈ 2–4, L ≈ 5+).

| M | Content | Effort | Depends on | Done when |
|---|---|---|---|---|
| **M0a** Foundations & boundary | `FS-GRAMMAR.md` (byte-level incl. §digests, test vector) and `CONVENTIONS.md` (bit order, 0-based indexing, domain = subgroup in natural order, KAT JSON schema) first; working `internal/fs`, `internal/encoding`, `internal/merkle` (not stubs); frozen **`internal/whir/pcs`** (SPEC-WHIR §4); mock `pcs.Scheme`; merkle with single paths + index dedup only (multiproof = M4); cheating seams; neutral KAT JSON schema + bit-order convention | M | D4 (PR #9 merged) | packages green with R9 tests; grammar test vector reproduced by fs and pyref |
| **M0b** Parameters & references | `whirparams` (port of reference `params/*`) → frozen `params_table.go`, **rows = m ∈ [4, MaxLogSize+3] × {UD, JB} × {Standard, ZK} × logInvRate 3 × k 4 × λ 130 × PoW 0, `TableVersion` 1**, generated with `GOARCH=amd64 GOAMD64=v1` and explicit `float64()` casts around every product (the Go spec allows FMA fusion on any arch; amd64 fuses from `GOAMD64=v3`; the casts are what prevent it); regeneration test pinned to the same settings; RustRef container harness: **own driver binary** (the reference CLI runs legacy `whir`/`whir_zk`, not `zook`) calling `ProtocolConfig::derive(SecuritySpec{mode, regime, 130, PowBudget::Forbidden, SHA2}, TuningSpec{vector_size: 2^m, starting_log_inv_rate: 3, folding_factor: Constant(4), rate_schedule: Stepping})` and the zook prover; KATs with `--features rs_in_order`; image `rust:1.87+` (arm64 OK); network only at build; pyref KATs + security checker | L | M0a | Standard rows = Rust `derive` field by field; ZK rows: our counts ≤ Rust's and pass the checker at our (power-of-two) lengths; every row passes the checker; **Gate G0**: real reference proof sizes (Standard + ZK) for m = 16..20 and the 2^14/2^16 table presented to the user **before M1c** |
| **M1a** Sumcheck | `internal/sumcheck`: generic prover/verifier, evaluations at 0,2..d, per-round degree, round-1 hook (`Offset`/`Libra`; the package applies the offset after fold 1), unbiased challenges; brute-force equality test of the hook on μ = 3 | S | M0a | wrong claim / wrong round / degree overflow rejected; mutation checks |
| **M1b** PIOP on mock | `backend/hyperplonk/bn254` non-ZK on the mock `pcs.Scheme`; dispatcher, backend ID (+ `Implemented()`), suite; move `buildPermutation` to `internal/plonkperm` (plonkfri green) | M | M0a, M1a | suite 31/33 on mock; PIOP attack tests (SPEC-PIOP §5) 0/N |
| **M1c1–3** WHIR Standard (3 PRs: (1) encode, forms, KATs; (2) sumcheck rounds + code switch; (3) base case + golden files) | `internal/whir` zook structure, Standard mode: irs encode/commit, sumcheck rounds, code switch (OOD ≥ 1), base case, linear forms (eq, stacked-eq-with-sparse, univariate), params from `whirparams` | L | M0b (parallel to M1a/b) | `WHIR-TRANSCRIPT.md` (Standard message order transcribed from pinned code) first; KATs vs Rust reference and pyref (encode, fold, ŵ_x, `mle_evaluate`); SPEC-WHIR §5 pitfalls tested; golden-proof file with fixed RNG |
| **M2** Integration v1a | mock → WHIR; perf + Go benchmarks (R16); security-status table for hyperplonk in PROJECT.md; `BINDING.md` (JB list-union argument, coordinator-owned) | S | M1b, M1c3 | suite green; attacks 0/N; **Gate G1**: measured vs §5 and vs calculator → continue / re-plan |
| **M3a–f** ZK v1b (one PR each, D5) | `WHIR-TRANSCRIPT.md` ZK section first; (a) ZK encoding + salted leaves (all trees); (b) ZK sumcheck masks; (c) ZK code switch with private zero-evader; (d) per-round mask proximity + ZK base case; (e) PIOP masks + Libra + round-1 hook, ZK μ floor 5; (f) split linear rank tests + attack/salt tests | L | M2 | sub-tests (a)–(e) of SPEC-PIOP §4 green; soundness tests unchanged; Standard path byte-identical to M2 golden files; **Gate G2**: ZK overhead measured |
| **M4** Cost (format-changing) | Merkle multiproof/cap, PoW grinding, ρ choice, joint W+H opening (if reference stable), unified sumcheck message format | M | M3 | each change measured vs G1/G2 table, security impact written; format frozen |
| **M5** Serialization & hardening | marshal (magic+version), `-race`, determinism, `FuzzReadFrom`, truncation/bit-flip sweeps, `MaxLogSize`, ChallengeHash probe | M | M4 | PANURUS §3 tests green; fuzz 60 s clean |
| **M6** Review (then **PR `feature/hyperplonk` → `master`**, merged by the user) | Reviewer agents per dimension (soundness, ZK, decoding) with code + specs only; external-review package (like plonkfri F1) or explicit "experimental / unreviewed" label (user decides) | M | M5 | findings triaged; each accepted finding → red test → fix |
| **M7** Panurus | Integration model per **D8** (open; PANURUS §0) | M | M6 + merge to `master`; **D8** | Panurus unit + `-race` + **integration tests run**; PR opened **only with user go-ahead** |

Prover-time-only optimisations (Gruen eq-factoring, parallel FFT/hashing) can land any time after M2 — they don't change the format.
Critical path: K2–K10 → M−1 → M0a → M0b (G0) → M1c1–3 → M2 → M3a–f → M4 → M5 → M6 → M7.

**Agent timeline (≤ 4 concurrent):**
- W0: Foundations (M0a) alone; PyRef starts reading papers.
- W1 (after M0a merged into `feature/hyperplonk`): Calculator ∥ RustRef ∥ PyRef (M0b) ∥ Sumcheck (M1a, needs only fs).
- **G0 — user stop** (real reference proof sizes, Standard + ZK).
- W2: PIOP (M1b) ∥ WHIR (M1c1) ∥ Adversary (starts on M1b's seams once M1b lands).
- W3: WHIR (M1c2, M1c3) ∥ Adversary (WHIR attacks) → M2 → **G1 — user stop**.

## 7. Team organisation (executed by the coordinator = main session)

### 7.0 Branching model (D7)

```
master ──●──────────────●(M−1 hygiene)──────────────────────────────●(final merge after M6)
          \               \ (merge master in)                       /
feature/hyperplonk ●──docs──●──M0a──M0b──M1a──M1b──M1c1…──M3f──M4──M5──M6
                           \      ↑ PR per milestone (user merges)
hp/<milestone>              ●──●──●  (milestone branch, from feature/hyperplonk)
hp/<milestone>-<agent>        ●──●     (agent worktree branches, merged by the coordinator)
```
- `feature/hyperplonk` is created from `master` @ `16a40bc2` and holds the docs from the start. It is shared and protected: **no force-push, no rebase**; only milestone PRs land on it.
- Per milestone the coordinator creates `hp/<milestone>` from `feature/hyperplonk`; agents work in worktrees on `hp/<milestone>-<agent>` branched from it; the coordinator merges agent branches into `hp/<milestone>`, runs the full-tree check, and opens **one PR `hp/<milestone>` → `feature/hyperplonk`**, merged by the user.
- Fixes that belong to `master` (M−1 hygiene, anything also affecting plonkfri) go to `master` first; `master` is then **merged** (not rebased) into `feature/hyperplonk` — at least at every gate.
- After M6: one PR `feature/hyperplonk` → `master` (user merges). Panurus (M7) points at that `master` commit.
- Agent worktrees must be based on the current `hp/<milestone>` (not `origin/master`): the coordinator creates the branch first and launches agents with the worktree base set accordingly.

### 7.1 Roles

| Agent | Isolation | Owns | Never does |
|---|---|---|---|
| **Coordinator** (main session) | — | plan, `PROJECT.md`, the frozen boundary, merges, gates, user decisions | package code beyond glue |
| **Foundations** | worktree | M0a fs/encoding/merkle + grammar + boundary + mock + seams | protocol logic |
| **Calculator** | worktree | M0b `whirparams` + `params_table.go` | — |
| **PyRef** | worktree; allowed inputs: **papers in `resources/`, `FS-GRAMMAR.md`, `CONVENTIONS.md`** — not our specs, code or the Rust; stdlib-only Python run with `python3 -I` | `internal/whir/testdata/pyref`: KATs + row security checker | Go code |
| **RustRef** | worktree; container only, nothing installed on the host | `internal/whir/testdata/rustref` (driver source + Dockerfile pinned to `c73b8d3` + generated JSON) | modify the reference |
| **Sumcheck** | worktree | M1a | — |
| **PIOP** | worktree | M1b, M2, M3e | WHIR internals |
| **WHIR** (1 per sub-protocol in M3) | worktree | M1c; M3a–d | PIOP code |
| **Adversary** | worktree; specs + boundary + hooks, no implementation notes | attack and rank tests per R9 | fix code it attacks |
| **Perf/Hardening** | worktree | M4, M5 | change security params without a written impact note |
| **Reviewers** | fresh, read-only | per-milestone diff review | see author's conclusions |
| **Panurus integrator** | Panurus checkout | M7 | push / open PRs without user go-ahead |

At most ~4 agents at once (M1: Sumcheck → PIOP, WHIR, Adversary).

### 7.2 Protocol per task

1. Coordinator writes a **brief** in `docs/hyperplonk-whir/briefs/<M>-<agent>.md` from `briefs/TEMPLATE.md` (goal, exact inputs with commits, owned files, frozen interfaces consumed, done-when as commands, required tests in R9 form with N, out of scope, lessons (a)–(l), return format, pinned reference `WizardOfMenlo/whir@c73b8d3`). Briefs are committed to `hp/<milestone>` before the agent starts. Agents are launched with worktree isolation based on `hp/<milestone>` (§7.0).
2. Agent works in its own **git worktree** branch `hp/<milestone>-<agent>` (from `hp/<milestone>`), commits locally, returns: files changed, tests and measured results, deviations from spec (each justified), open questions.
3. Only the PIOP↔PCS boundary is frozen. Package-internal APIs belong to their owner. Boundary changes go through the coordinator, who updates the contract and notifies affected agents.
4. Coordinator merges agent branches into `hp/<milestone>` in dependency order, runs the full-tree check, runs reviewers, routes findings back to the owner, then opens the milestone PR into `feature/hyperplonk`.
5. Adversary tests: written against the boundary + hooks; a test is accepted only when it passes the three-part R9 check against the real implementation (mutation flag included). Tests are never "red against stubs" — that is failure for the wrong reason.
6. Gates: coordinator writes `gates/G<n>.md` from `gates/TEMPLATE.md` (measurement table vs §5, calculator vs measured, verdict, explicit ask) and stops; no next milestone without user approval. Boundary (`internal/whir/pcs`) changes after M0a are reported to the user in the next milestone PR description.
7. Large ports (zook) are split per sub-protocol so each brief fits one agent's context.

### 7.3 Briefs (summaries; full briefs are written at kick-off)

- **M0a Foundations**: `FS-GRAMMAR.md` first; fs, encoding (from PR #9), merkle (domain separation, salts, single paths + index dedup; multiproof in M4); `boundary.go` (SPEC-WHIR §4), mock PCS checking forms directly; seams via `export_test.go`.
- **M0b Calculator**: port reference `params/*` (BCSS25 Johnson constant, OOD ≥ 1, mask lengths, layout rule, pinned tuning); generate `params_table.go`; regeneration-diff test on one GOARCH.
- **M0b RustRef**: Dockerfile pinned to `c73b8d3`, driver printing `derive` rows, KATs (encode, fold, ŵ_x, `mle_evaluate`, `rs_in_order`), and real proof byte counts in both modes.
- **M0a/b PyRef**: from the WHIR and 2026-391 papers only: encode, fold, ŵ_x, eq KATs; security checker (WHIR Thm 5.2 query term, OOD/list term, JB list size 1/(2η√ρ), BCSS25 ε_mca) applied to every table row.
- **M1a Sumcheck**: SPEC-PIOP §2.3/§7; no biased `SetBytes(h.Sum(nil))` reduction (gkr template).
- **M1b PIOP**: SPEC-PIOP §1–3, §5, §7 non-ZK on mock; mask slots present but zero.
- **M1c WHIR**: SPEC-WHIR §1–2, §4–5 Standard mode; bit-order property test first.
- **M3a–d WHIR ZK**: SPEC-WHIR §3, one sub-protocol each, ported from pinned `protocols/zook`.
- **M3e PIOP ZK**: SPEC-PIOP §4 (explicit W/H form, round-1 degree 7, Libra in M_W).
- **M3f Adversary ZK**: SPEC-PIOP §4 sub-tests (a)–(e), each red with ZK off.

### 7.4 Execution tracking and restart (resumable at any time)

Goal: execution can be stopped at any moment (session ends, machine restarts, user pauses) and resumed by a **fresh coordinator session with no memory of the previous one**, using only what is committed and pushed to git. Agent sessions, background tasks and `/tmp` do not survive and are never relied on.

**The ledger: [`STATUS.md`](STATUS.md)** — single source of truth for execution state. `PROJECT.md` keeps narrative and decisions and points to it, so CLAUDE.md's "read PROJECT.md first" leads here.
- *Header*: phase, branch, last checkpoint commit, next action, pending user decisions, reference pin.
- *Task table*, one row per task (kick-off item, milestone, gate): `ID | state | owner | branch | base commit | last commit | brief | report | updated`. States, only these: `todo → ready → running → returned → in-review → merged`, plus `blocked`, `failed`, `abandoned`.
- *Event log*, append-only: `date | ID | event | detail` (started, returned, merged, gate passed, user decision, resumed, aborted).
- Rule: **the coordinator updates STATUS.md and commits + pushes it (`status: …`) before launching an agent and immediately after every agent return, merge, gate or user decision.** A state change that is not committed did not happen.

**What each task leaves in git** (a restart loses at most the in-flight agent's unpushed work):
- brief `briefs/<ID>.md`, committed before launch;
- agent branch `hp/<milestone>-<agent>`, pushed; agents **commit and push at every green intermediate step** (WIP commits allowed on agent branches only);
- report `reports/<ID>.md` (files, tests, measurements, deviations, open questions), written from the agent's return message and committed on return;
- reviewer findings and dispositions `reports/<ID>-review.md`;
- gate reports `gates/G<n>.md`; user decisions in PLAN §4 and the STATUS event log;
- durable inputs in the repo, never `/tmp`: papers in `resources/` (K6), reference harness and outputs in `internal/whir/testdata/`, reference pin in every brief.

**Restart procedure** (also in STATUS.md's header section):
1. Read `CLAUDE.md` → `PROJECT.md` → `STATUS.md`; `git fetch`; check out the branch in the header.
2. For each `running` row, inspect its agent branch. Returned but not recorded → write the report from the branch, set `returned`. Mid-work → relaunch a **fresh** agent with the same brief plus a "Resume" section (last commit, what the branch's log and tests show done, what remains). Unusable → `failed`, reset the *agent* branch to its base commit (only agent branches may be reset), relaunch. Never assume an old agent session is alive.
3. `returned` / `in-review` rows: continue review and merge (§7.2).
4. Re-run the full-tree check on `feature/hyperplonk` and the current `hp/<milestone>`; log `resumed`.
5. If the header lists a pending user decision or gate, ask the user before anything else.

**Idempotence**: a task is defined by its brief and base commit, so relaunching is safe; every merge commit is recorded in STATUS before the next step; a gate counts as passed only when the user's decision is in the event log.

## 8. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Proofs larger than estimated | cost | G0 estimate, G1 measurement; D1 |
| JB soundness rests on unrefereed preprints (2025/2051, 2025/2110) | security claim | D2; UD option; security status |
| JB binding: commitment fixes a list (≤ 10/ρ) | soundness argument | list-union bound written in SPEC-PIOP §5 (~6 bits per oracle, harmless) |
| ZK size overhead much larger than first assumed (+40–80 %) | cost | measured at G0 with the reference; dedup/multiproof on mask trees in M4 |
| Float-based parameter derivation differs across architectures | liveness (VK rejected on another node) | frozen table + exact row checker (R12) |
| ZK-WHIR recent, unaudited; reference "academic prototype", still moving (commits 10-13, 10-22) | privacy | pin `c73b8d3`; diff on upgrade; rank tests; M6 review |
| zook port large (zook ≈ 84 KB Rust; ≈ 430 KB with the sub-protocols and params it uses) | schedule | split M3 per sub-protocol; Standard skeleton in M1c |
| Cross-check gaps (reference has a different transcript; zook internals may not be exposed publicly) | silent bugs | Rust container KATs + derive (D6), pyref, golden files; if a needed internal is private, the driver uses a patched copy recorded in the harness |
| Bit-order / linear-form mismatches | soundness/completeness | property tests + KATs first |
| Prover/verifier transcript drift; bugs common to both | soundness | one `transcript.go`; mutation sweep; pyref KATs |
| panurus#2539 merged (2026-10-28) by vendoring plonkfri into Panurus on upstream gnark v0.16.4 — the fork-`replace` model is gone | M7 integration model | **D8** (user decision) |
| Agents diverging on interfaces | rework | frozen `pcs` package, change requests via coordinator |
| Session or agent lost mid-execution | lost work, inconsistent state | §7.4: ledger committed at every transition, agents push at every green step, restart procedure |
| Go prover slower than estimate | cost | G1; M4 |

## 9. Out of scope (v1)

BSB22 `api.Commit` (first feature after v1), native lookups, high-degree custom gates, recursion / in-circuit verifier (Poseidon2), other curves, small-field variant, LogUp-GKR (v2), B > 1 leaf layouts, cross-term multi-commitment openings, `InitialFoldingFactor`, ρ₁ resampling.

## 10. Independent review (2026-10-27) — disposition

Reviewer: fresh agent, given docs + code + papers + reference repo, not our reasoning; one debate round. 22 findings (2 blocker, 9 major, 8 minor, 3 nit after re-grading).

| # | Finding (short) | Sev. | Disposition |
|---|---|---|---|
| 1 | Legacy WHIR ≠ zook; M3 would be a rewrite; commit-OOD leaks in ZK | blocker | **Accepted**: zook structure from M1c, Standard then ZK mode; JB list-union argument added |
| 2 | Freeze too early; M1 not parallel; PR too big | blocker | **Accepted**: M0 delivers working foundations, freezes only the boundary; M1 split |
| 3 | ZK stacked claim for W/H omits slot 3 | major | **Accepted**: explicit form in SPEC-PIOP §2.4/§4; alternative "4th commitment" rejected in debate (opened value would leak) |
| 4 | Sumcheck API can't express ZK round 1 | major | **Accepted**: round-1 hook |
| 5 | UD with s = 0 incompatible with code switch | major | **Accepted**: s ≥ 1 always; UD table re-derived |
| 6 | P must be committed non-ZK (determinism) | major | **Accepted** |
| 7 | Multi-commitment / B-batching unsupported in ZK | major | **Accepted**: one commitment per Open, B = 1; joint W+H → M4 |
| 8 | Size goal contradicted by own estimate | major | **Accepted**: targets re-set, 2^14 row added |
| 9 | Format churn M5 vs M4 | major | **Accepted**: cost (format) before serialization |
| 10 | Adversary-first gives vacuous tests | major | **Accepted**: hooks in M0; three-part R9 check |
| 11 | No independent cross-check | major | **Accepted**: pyref by separate agent + Rust reference in a container (D6, consent given) |
| 12 | Dispatcher must check `ccs.Type` | minor | Accepted (R1) |
| 13 | `func() hash.Hash` not serialisable | minor | Accepted: `HashID` |
| 14 | ChallengeHash not bound | minor | Accepted: probe + error (R10) |
| 15 | LogUp a=b=0 edge mis-stated | minor | Accepted; ρ₁ resampling dropped |
| 16 | Citations / Johnson constant | nit | Accepted: 2025/2051 verified, BCSS25 constant (2025/2055 Thm 1.5) |
| 17 | 128-bit statement mixes conventions | minor | Accepted: λ = 130 per opening, ROM |
| 18 | CI / benchmarks / docs / stats / review items | minor | Accepted (R11, M2, M6) |
| 19 | Risks, effort, port size | minor | Accepted (§6, §8) |
| 20 | Panurus: stack on #2539; limits; NewX parity | minor | Accepted (PANURUS §6, R5) |
| 21 | Over-engineering | nit | Accepted (§9) |
| 22 | ℓ = 0, PI checks | nit | Accepted (SPEC-PIOP §1) |

## 11. Second independent review (2026-10-27) — disposition

Fresh reviewer (did not see round-1 debate, only §10), one debate round. 20 findings; no blockers.

| # | Finding (short) | Sev. | Disposition |
|---|---|---|---|
| 1 | Float parameter derivation not platform-deterministic | major → minor | **Accepted, changed**: frozen generated table (`params_table.go`), `TableVersion`, row hash in VK digest, exact row checker, regeneration test on one arch (debate) |
| 2 | ZK base case / mask proximity not as in pinned code (per-round mask proximity, base-case sumcheck, mle ≠ 0) | major | Accepted: SPEC-WHIR §1/§3; `WHIR-TRANSCRIPT.md` transcribed from code before M1c/M3 |
| 3 | ZK overhead ≫ +15 % | major | Accepted: estimate +40–80 %; measured with reference at G0, reported before M1c |
| 4 | Round-1 hook can't express non-linear masks; Libra sums missing multiplicities | major | Accepted: `Offset`/`Libra` hook (AfterFold later removed, §12 #11), corrected sums, brute-force test |
| 5 | Rank test ill-defined (non-linear) | major | Accepted: split linear sub-tests (a)–(e) |
| 6 | Mask block doesn't fit small μ | major | Accepted: ZK floor μ ≥ 5 (debate: extra stack slots rejected) |
| 7 | Reference picks non-power-of-two codewords on bn254 | major | Accepted: deliberate deviation, round up to 2^k; compare counts not lengths |
| 8 | Round layout rule differs | minor | Accepted: reference rule, pinned tuning |
| 9 | PoW placement | minor | Accepted: reference order documented; decided in M4 |
| 10 | Salts deviate from reference, untested | minor | Accepted: deviation recorded, all trees salted, guess-confirmation test |
| 11 | FS not byte-exact; double absorbs | minor | Accepted: `FS-GRAMMAR.md` in M0a; `Commit` doesn't absorb |
| 12 | Stale milestone refs | minor | Fixed |
| 13 | Header/VK field lists disagree; forms not exported | minor | Accepted: one `whir.Header`; VK modes validated; forms exported |
| 14 | No API for mode/regime | minor | Accepted: `SetupOption`s (R13) |
| 15 | Test seams race / build tag skips | minor | Accepted: `export_test.go` per-call config |
| 16 | RustRef feasibility | minor | Confirmed feasible (all needed APIs `pub`); `rs_in_order`, network access noted |
| 17 | M0 undersized; pyref not independent | minor | Accepted: M0a/M0b; pyref from papers only + row security checker (debate) |
| 18 | List-union argument loose; arithmetic | minor | Accepted: L_W / L_W·L_H, ZK case, P trust assumption, corrected numbers |
| 19 | Prover / PK memory not targeted | minor | Accepted: §5 rows |
| 20 | Nits (0-based indexing, OOD deviation, probe race; forms verified correct) | nit | Accepted |

## 12. Implementation-readiness audit (2026-10-27) — disposition

Fresh agent asked "can implementation start tomorrow?", playing the agents of M0a–M1c. Verdict before fixes: M0a/M0b blocked, M1a–c ready with minor gaps. 34 gaps; claims on PR #9, master test failures, CI runner and `fr.BatchInvert` re-verified by the coordinator. All accepted.

| # | Gap | Sev. | Fix |
|---|---|---|---|
| 1 | PR #9 open, no owner | blocks start | K1 (user) |
| 2 | Docs untracked; worktrees wouldn't see them; no branch strategy | blocks start | K2; feature branch `feature/hyperplonk` (D7, §7.0) |
| 3 | Master red under `-short` (TestVersion, internal/stats panic) | blocks start | K3 hygiene PR |
| 4 | Fork CI never ran; self-hosted runner; toolchain skew | blocks milestone | K4 (user), go1.25 rule |
| 5 | Mock/real not swappable; Params table needed before M0b | blocks M0a | `internal/whir/pcs` with `Scheme` interface; mock TableVersion 0; Params internal |
| 6 | `export_test.go` can't cross packages | blocks M0a | `opts ...Option` on Open/Verify; WHIR mutation tests inside `internal/whir` |
| 7 | Commit signature took a transcript | clarify | removed |
| 8 | RoundParams/BaseParams/enums/errors undefined | clarify | internals not frozen; enum values, 0 invalid; exported errors |
| 9 | Witness/rng lifecycle | clarify | Open doesn't mutate; rng nil in Standard |
| 10 | Form descriptor/constructors | clarify | tags + constructors in SPEC-WHIR §4 |
| 11 | AfterFold had no tables; unnamed results; labels | blocks M1a | AfterFold removed (package applies offset), named results, labels |
| 12 | WHIR sumcheck format | clarify | coefficients (c₀, c₂), separate from `internal/sumcheck` in v1 |
| 13 | Mixed 0/1-based indexing; c_0 collision | clarify | 0-based pass; Libra constant g_0 |
| 14 | ChallengeIndices ambiguous | blocks M0a output | exact formula in SPEC-PIOP §3 |
| 15 | Multiproof in both M0a and M4 | clarify | v1 single paths + dedup; multiproof M4 |
| 16 | Domain/leaf order unfixed | clarify | subgroup, natural order, generator 5 (SPEC-WHIR §1, `CONVENTIONS.md`) |
| 17 | Digest layouts, MaxLogSize | clarify | FS-GRAMMAR §digests; MaxLogSize 17 |
| 18 | Default ZK before ZK exists | clarify | R13 |
| 19 | buildPermutation not importable | clarify | `internal/plonkperm` in M1b |
| 20 | Reference CLI doesn't run zook | blocks M0b | own driver (M0b row) |
| 21 | ZK counts can't equal Rust after rounding | blocks M0b done-when | ZK: ≤ Rust + checker |
| 22 | Row set undefined | blocks M0b | M0b row |
| 23 | FMA on arm64 | clarify | generate on amd64, explicit casts |
| 24 | PyRef inputs contradictory; papers in /tmp | blocks M0a | allowed inputs listed; K6 |
| 25 | Licence/attribution | clarify | R14 |
| 26 | Binding argument unowned | clarify | `BINDING.md`, coordinator, M2 |
| 27 | N/thresholds/-short | clarify | R11 |
| 28 | Golden files | clarify | R15 |
| 29 | Perf method | clarify | R16 |
| 30 | `fr.BatchInvert` maps 0 ↦ 0 | note | explicit zero check (SPEC-PIOP §2.1) |
| 31 | Brief/gate storage, merge ownership | blocks start | §7.2, templates, K2 |
| 32 | Timeline implicit | clarify | §6 agent timeline |
| 33 | Background-agent permissions | clarify | K8 (user) |
| 34 | Nits (pitfall numbering, OVERVIEW PI cost, FS-GRAMMAR location) | nit | fixed |

