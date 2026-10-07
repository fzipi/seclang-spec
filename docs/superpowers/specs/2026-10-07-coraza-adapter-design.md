# Coraza Reference Adapter — Design

Status: approved in conversation, 2026-10-07.

## 1. Brief

**You said.** Start the adapter work; the adapter lives in this repository under
`adapters/coraza`.

**Agreed.** A Go module that runs the conformance test data in `tests/` against Coraza
v3.8.1 through its public API, as `go test`, in CI, with the known-gaps table acting as
the expected-failure list.

**Assumptions.**

- Coraza is the first engine because it is a Go library with a public transaction API;
  ModSecurity adapters are future work and may live elsewhere.
- The data-only contract of `tests/` (ADR-0003) stands for every engine; this adapter
  is a *reference* consumer of that data, which revises the design's "no runner in this
  repo" assumption (ADR-0023).
- Divergences the first run uncovers are handled the usual way: a known-gaps row when
  Coraza is wrong, a spec or test fix when the specification is wrong.

## 2. Shape

```
adapters/coraza/
  go.mod            module github.com/OWASP/seclang-spec/adapters/coraza; require coraza v3.8.1
  go.sum
  README.md         how to run; how results map to known-gaps
  profile.go        YAML/JSON loading of tests/engine and tests/unit (types mirror the schemas)
  engine.go         run one stage through the Coraza transaction API; collect results
  unit.go           wrap an operator or transformation case in a rule and evaluate it
  gaps.go           parse compat/known-gaps.md rows for Coraza
  conformance_test.go   TestEngine, TestUnit: subtests per profile/test/stage and per case
```

CI: `.github/workflows/validate.yml` gains a job with `actions/setup-go` and
`go test ./...` run inside `adapters/coraza`.

## 3. Engine tier

For each profile: write `files:` entries under a temporary directory; build one WAF with
`coraza.NewWAFConfig().WithRootFS`/`WithDirectives(rules)` and an error callback that
collects `MatchedRule.ErrorLog()` lines. `expect_error` asserts the constructor fails.
`requires:` entries are compared with a fixed list of Extended anchors Coraza implements
(initially empty: it has no persistent collections); a profile needing an unimplemented
feature is skipped with `t.Skip`.

Each stage: `ProcessConnection(remote_addr or 127.0.0.1, 12345, "127.0.0.1", 80)`,
`ProcessURI(uri, method or GET, version or HTTP/1.1)`, request headers (plus `Host:
localhost` when absent), `ProcessRequestHeaders`, `WriteRequestBody(data bytes)`,
`ProcessRequestBody`, then when the stage has a `response`: response headers,
`ProcessResponseHeaders(status or 200, HTTP/1.1)`, `WriteResponseBody`,
`ProcessResponseBody`; always `ProcessLogging`. Rule evaluation stops where Coraza stops
on an interruption; later phases are not driven once `tx.IsInterrupted()`, except
logging.

Assertions:

| Field | Source |
|---|---|
| `triggered_rules` / `non_triggered_rules` | ids of `tx.MatchedRules()` (chain members report the starter id; `nolog` rules are included) |
| `interruption` | `tx.Interruption()`: `RuleID` (0 for body-limit denials), `Action`, `Status` when asserted |
| `no_interruption` | `tx.Interruption() == nil` |
| `log_contains` / `no_log_contains` | substring over the collected error-log lines |
| `expect_error` | `coraza.NewWAF` returns an error |

Body-limit interruptions arrive from `WriteRequestBody`/`ProcessRequestBody` and are
recorded like any other.

## 4. Unit tier

Inputs are byte strings (`tests/README.md`): each JSON string is Latin-1 encoded to
bytes before use. Cases are grouped by `(type, name, param)`; one WAF per group with:

```
SecRuleEngine On
SecRequestBodyAccess On
SecRule REQUEST_HEADERS:X-Seclang-Unit "@unconditionalMatch" "id:1,phase:1,pass,nolog,ctl:forceRequestBodyVariable=On"
SecRule REQUEST_BODY "@<op> <param>" "id:2,phase:2,pass,nolog"          # operators
SecRule REQUEST_BODY "@unconditionalMatch" "id:2,phase:2,pass,nolog,t:<name>"   # transformations
```

The input is the request body of a `POST /` with `Content-Type: application/octet-stream`.
Operator `ret` = rule 2 matched. Transformation output = `MatchedDatas()[0].Value()` of
rule 2; `ret` is compared as `output != input`. `param` is inserted into the rule with
`"` and `\` escaped; a param the engine cannot parse (`expect` load error) counts as a
failure unless the case is in a known-gaps file. `re_groups` are checked through
`capture` and `TX:0..9` read from the experimental transaction state when present.

Operators Coraza does not register (listed Extended/Deprecated in `06`) are skipped at
the file level with a note; the unit files for them exist for other engines.

## 5. Known gaps

`gaps.go` parses the table in `compat/known-gaps.md`: rows whose Engine cell contains
"Coraza" yield the set of test file paths (several per row allowed, comma separated).
For each file:

- not listed → every subtest must pass;
- listed → failures are reported as expected (`t.Log`, not `t.Fail`); if **no** subtest
  of that file fails, the file-level test fails with "known-gaps row is obsolete: remove
  it".

So the build is green exactly when the table is accurate.

## 6. Errors and limits

- A profile that fails to load when `expect_error` is absent is a failure of every stage
  in it (reported once).
- Timeouts: none needed; 4,300 unit cases build about 300 WAFs; measured budget under one
  minute.
- Coraza build tags are not used; the default build is what the spec grades.

## 7. Testing the adapter itself

`go test` runs the real data, which is the integration test. Unit tests for the adapter's
own logic: `gaps_test.go` (table parsing, obsolete-row detail), `profile_test.go`
(schema-shaped loading, Latin-1 conversion, param escaping), `unit_test.go` (one operator
and one transformation case through a real WAF).

## 8. ADR-0023

Category Clarification: reference adapters live under `adapters/<engine>/` in this
repository and are run by CI; the test data stays engine-neutral; an engine MAY ship its
own adapter instead; a reference adapter's known-gaps handling is the mechanism by which
the table stays truthful.
