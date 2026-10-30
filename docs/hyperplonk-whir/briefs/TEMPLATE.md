# Brief <M>-<agent>

- **Milestone / agent:** <e.g. M0a / Foundations>
- **Branch:** `hp/<milestone>-<agent>` from `hp/<milestone>` @ <commit>
- **Reference pin:** `WizardOfMenlo/whir@c73b8d3`

## Goal
<one paragraph>

## Inputs (read these, exact paths and commits)
- `docs/hyperplonk-whir/<SPEC> §<n>` …
- `PROJECT.md` "Lessons that generalize" (a)–(l)

## Owned files (you may create/modify only these)
- …

## Interfaces consumed (frozen — request changes via the coordinator, never edit)
- `internal/whir/pcs` …

## Done when (commands that must pass)
```
go build ./... && go test -run XXX ./...
go test -short ./<pkg>/...
go vet ./<pkg>/... && gofmt -l <pkg>   # empty
golangci-lint run ./<pkg>/...
```

## Required tests (R9 form: honest accepted · cheater 0/N · cheater accepted with check disabled; N = 8 under -short, 200 otherwise)
- …

## Out of scope
- …

## Return format
1. Files changed. 2. Tests run with measured results (counts, rejecting check). 3. Deviations from spec, each justified. 4. Open questions / boundary change requests.
