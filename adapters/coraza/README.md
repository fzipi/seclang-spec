# Coraza reference adapter

Runs the conformance data in `../../tests` against
[Coraza](https://github.com/corazawaf/coraza) through its public API, as `go test`.

```sh
cd adapters/coraza
go test ./...            # everything
go test ./... -run TestEngine -v   # engine-tier profiles, one subtest per file
go test ./... -run 'TestUnit$' -v  # unit-tier files
```

The Coraza version is pinned in `go.mod` (v3.8.1). Change it there to grade a different
release; every other input is the repository's test data.

## How results are gated

`compat/known-gaps.md` is the expected-failure list. For each test file:

| Row for Coraza in known-gaps | Result | Outcome |
|---|---|---|
| none | all pass | pass |
| none | any failure | **fail** (a real defect in Coraza or in the specification) |
| present | any failure | pass, failures logged as `expected (known gap: …)` |
| present | all pass | **fail** with `known-gaps row is obsolete` (remove the row) |

So the build is green exactly when the table is accurate. A new divergence is handled by
adding a row with a source pointer; a fixed one by deleting its row.

Extended features Coraza does not implement are skipped, not failed, as
`spec/00-conventions.md` requires: engine profiles through `requires:`, unit files for
the operators and transformations listed in `conformance_test.go`, and the
`rx-pcre-extensions` cases.

## How the tiers are driven

- **Engine tier** (`engine.go`): one WAF per profile with the profile's `files:` written
  under a temporary root; one transaction per stage through `ProcessConnection`,
  `ProcessURI`, headers, `WriteRequestBody`, `ProcessRequestBody`, the synthetic
  response when the stage has one, and `ProcessLogging`. `triggered_rules` come from
  `MatchedRules()`, `interruption` from `Interruption()`, `log_contains` from the error
  callback. An engine panic is reported as one failure instead of aborting the run.
- **Unit tier** (`unit.go`): each operator or transformation case is wrapped in a rule
  over `REQUEST_BODY`, the input is sent as raw bytes (unit strings are Latin-1 byte
  strings, `tests/README.md`), and the result is read from the matched rule: whether it
  matched for operators, the transformed value for transformations, `TX:0..9` for
  `re_groups`. Coraza treats `\"` as the only escape inside a quoted argument, so
  parameters are inserted with quotes escaped and nothing else (an Apache-based adapter
  would also have to double backslashes; see `spec/01-lexical.md#quoting-and-escapes`).
  Engine-tier `data` is UTF-8 text and is sent as such; unit-tier strings are Latin-1 byte
  strings and are sent byte for byte.

## Adding another engine

Copy the shape: load the data (`profile.go` is engine-neutral), drive the engine, map
observations to the same `Observed`/`UnitResult` structs, reuse `CheckStage`/`CheckUnit`
and `LoadGaps` with your engine's name. ADR-0023 records that reference adapters live
here; an engine may equally keep its adapter in its own repository.
