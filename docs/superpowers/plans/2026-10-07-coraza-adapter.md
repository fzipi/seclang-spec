# Coraza Reference Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Go test module at `adapters/coraza` that runs every engine-tier profile and every unit-tier case in `tests/` against Coraza v3.8.1, treating `compat/known-gaps.md` as the expected-failure list, wired into CI; plus the triage of what the first real run finds.

**Architecture:** `profile.go` loads the YAML/JSON data into structs mirroring the schemas; `engine.go` drives one stage through Coraza's public transaction API and returns an observed result; `unit.go` wraps each operator or transformation case in a rule and reads the match back; `gaps.go` parses the known-gaps table; `conformance_test.go` turns it all into `go test` subtests with expected-failure handling. Nothing in `tools/` changes except a small validator check that known-gaps paths exist.

**Tech Stack:** Go 1.25+ (local 1.26), `github.com/corazawaf/coraza/v3 v3.8.1`, `gopkg.in/yaml.v3`.

**Spec:** `docs/superpowers/specs/2026-10-07-coraza-adapter-design.md`; data contract `tests/README.md`; ADR-0003.

## Global Constraints

- Coraza pinned to `v3.8.1` in `go.mod`; no `replace` to the local checkout in committed code (the local checkout is at the same tag; use `GOFLAGS=-mod=mod` locally if the module proxy is unreachable, and say so in the ledger).
- Default Coraza build: no build tags.
- Unit strings are Latin-1 byte strings; every JSON string field is encoded with `[]byte` via Latin-1 before reaching Coraza; operator params are inserted into rule text with `"` → `\"` and `\` → `\\`.
- Expected-failure rule: a known-gaps row naming Coraza covers every subtest of the listed file; failures there log, passes do not fail; a listed file with zero failures fails with `known-gaps row is obsolete`.
- Every Go file has a unit test that failed first; the real-data tests are integration tests and are run, read and triaged, not just made green.
- Commits gate on `go test ./...` in `adapters/coraza` **and** `uv run python tools/validate.py` **and** the Python suite.
- Commit messages end with the two attribution lines.

## Review Focus

1. A profile whose `rules` fail to load while `expect_error` is absent (e.g. a Coraza gap such as `@CONTAINS`). Expected: one failure per profile naming the load error, every stage marked failed, and expected-failure handling applies when the file is listed; test in Task 3 (`TestEngine` over `lexical/case-insensitive-names.yaml`, listed).
2. A stage with a `response` but no request body. Expected: response phases run and phase 3/4 rules see the response; Task 3 over `variables/response.yaml`.
3. A unit `param` containing a double quote or backslash (`rx.json` has both). Expected: the rule loads; test in Task 2 (`escapeParam`) and Task 4 over `rx.json`.
4. A unit input containing bytes 0x00 and 0xFF. Expected: delivered byte-for-byte via `WriteRequestBody`; Task 4 over `validateUtf8Encoding.json`.
5. A known-gaps row listing two files in one cell. Expected: both files are covered; Task 1 (`gaps_test.go`).

---

### Task 1: Module skeleton and known-gaps parsing

**Files:**
- Create: `adapters/coraza/go.mod`, `adapters/coraza/gaps.go`, `adapters/coraza/gaps_test.go`
- Modify: `tools/validate.py` (+ `check_gaps`: every `tests/...` path in `compat/known-gaps.md` exists), `tools/test_validate.py`

**Interfaces:**
- `func LoadGaps(path string, engine string) (map[string]string, error)` returns `relative test path → reason` for rows whose Engine cell contains `engine` (case-insensitive). Paths are extracted from backticked `tests/...` tokens in the first cell; several per cell allowed.

- [ ] **Step 1: Failing tests**

`adapters/coraza/gaps_test.go`:
```go
package coraza

import (
	"os"
	"path/filepath"
	"testing"
)

const sampleGaps = "# Known conformance gaps\n\n| Test | Engine | Behaviour today | Decided in |\n|---|---|---|---|\n" +
	"| `tests/engine/a.yaml` | Coraza | one | ADR-1 |\n" +
	"| `tests/engine/b.yaml`, `tests/engine/c.yaml` | libmodsecurity v3, Coraza | two | ADR-2 |\n" +
	"| `tests/engine/d.yaml` | ModSecurity v2 | three | ADR-3 |\n" +
	"| `tests/engine/e.yaml` | Coraza (`some.build.tag` build only) | four | ADR-4 |\n"

func TestLoadGaps(t *testing.T) {
	p := filepath.Join(t.TempDir(), "known-gaps.md")
	if err := os.WriteFile(p, []byte(sampleGaps), 0o644); err != nil {
		t.Fatal(err)
	}
	gaps, err := LoadGaps(p, "coraza")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"tests/engine/a.yaml", "tests/engine/b.yaml", "tests/engine/c.yaml", "tests/engine/e.yaml"} {
		if _, ok := gaps[want]; !ok {
			t.Errorf("missing %s", want)
		}
	}
	if _, ok := gaps["tests/engine/d.yaml"]; ok {
		t.Error("v2-only row must not count for coraza")
	}
	if gaps["tests/engine/b.yaml"] != "two" {
		t.Errorf("reason = %q", gaps["tests/engine/b.yaml"])
	}
}
```
Append to `tools/test_validate.py`:
```python
class GapsCheckTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_repo(Path(self._tmp.name))
        (self.root / "tests/engine/e.yaml").write_text(GOOD_ENGINE)

    def tearDown(self):
        self._tmp.cleanup()

    def test_listed_paths_must_exist(self):
        (self.root / "compat/known-gaps.md").write_text("| Test | Engine | B | D |\n|---|---|---|---|\n| `tests/engine/e.yaml`, `tests/engine/nope.yaml` | Coraza | x | y |\n")
        errors = validate.check_gaps(self.root)
        self.assertEqual(len(errors), 1)
        self.assertIn("nope.yaml", errors[0])

    def test_missing_file_is_fine(self):
        self.assertEqual(validate.check_gaps(self.root), [])
```
- [ ] **Step 2: RED** — `cd adapters/coraza && go mod init github.com/OWASP/seclang-spec/adapters/coraza && go test ./...` → `undefined: LoadGaps`; `uv run python -m unittest tools.test_validate.GapsCheckTests` → AttributeError.
- [ ] **Step 3: Implement**

`adapters/coraza/gaps.go`:
```go
// Package coraza runs the seclang-spec conformance data against Coraza.
package coraza

import (
	"bufio"
	"os"
	"regexp"
	"strings"
)

var gapPathRe = regexp.MustCompile("`(tests/[^`]+)`")

// LoadGaps reads compat/known-gaps.md and returns, for rows whose Engine cell names
// `engine` (case-insensitive substring), the test paths of the first cell mapped to the
// "Behaviour today" cell.
func LoadGaps(path, engine string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "| `tests/") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "| "), " | ")
		if len(cells) < 3 || !strings.Contains(strings.ToLower(cells[1]), strings.ToLower(engine)) {
			continue
		}
		for _, m := range gapPathRe.FindAllStringSubmatch(cells[0], -1) {
			out[m[1]] = strings.TrimSpace(cells[2])
		}
	}
	return out, sc.Err()
}
```
`tools/validate.py`, before `CHECKS`:
```python
GAP_PATH_RE = re.compile(r"`(tests/[^`]+)`")


def check_gaps(root: Path) -> list[str]:
    path = root / "compat" / "known-gaps.md"
    if not path.is_file():
        return []
    errors = []
    for line in path.read_text().splitlines():
        if line.startswith("| `tests/"):
            for p in GAP_PATH_RE.findall(line.split(" | ")[0]):
                if not (root / p).is_file():
                    errors.append(f"compat/known-gaps.md: {p} does not exist")
    return errors
```
and add `check_gaps` to `CHECKS`.
- [ ] **Step 4: GREEN** — both test commands pass; `uv run python tools/validate.py` → `0 error(s)`.
- [ ] **Step 5: Commit** `feat(adapter): coraza module skeleton, known-gaps parsing, gaps path check`.

---

### Task 2: Data loading

**Files:**
- Create: `adapters/coraza/profile.go`, `adapters/coraza/profile_test.go`
- Modify: `adapters/coraza/go.mod` (`require gopkg.in/yaml.v3`)

**Interfaces:**
```go
type Profile struct {
	Meta     struct{ Name, Description string } `yaml:"meta"`
	Spec     string            `yaml:"spec"`
	Requires []string          `yaml:"requires"`
	Files    map[string]string `yaml:"files"`
	Rules    string            `yaml:"rules"`
	Tests    []Test            `yaml:"tests"`
	Path     string            // relative to repo root, set by the loader
}
type Test struct { Title string `yaml:"test_title"`; Spec string `yaml:"spec"`; Stages []struct{ Stage Stage `yaml:"stage"` } `yaml:"stages"` }
type Stage struct { Input Input `yaml:"input"`; Response *Response `yaml:"response"`; Output Output `yaml:"output"` }
type Input struct { Method, URI, Version, Data, RemoteAddr string; Headers map[string]string }   // yaml tags per schema (remote_addr)
type Response struct { Status int; Headers map[string]string; Data string }
type Output struct { TriggeredRules []int `yaml:"triggered_rules"`; NonTriggeredRules []int `yaml:"non_triggered_rules"`; Interruption *struct{ RuleID int `yaml:"rule_id"`; Action string; Status int }; NoInterruption bool `yaml:"no_interruption"`; LogContains, NoLogContains string; ExpectError bool `yaml:"expect_error"` }
type UnitCase struct { Type, Name, Param, Input, Output string; Ret int; Spec string; ReGroups []string `json:"re_groups"`; HasParam bool }
func RepoRoot() string                                   // walks up from the test file to the dir containing tests/
func LoadProfiles(root string) ([]Profile, error)        // tests/engine/**/*.yaml, sorted
func LoadUnitCases(root string) (map[string][]UnitCase, error)  // path → cases, tests/unit/**/*.json
func latin1(s string) []byte                             // one byte per code point; panics on > 0xFF (validator guarantees)
func escapeParam(p string) string                        // backslash and double quote escaped for use inside a quoted directive argument
```
- [ ] **Step 1: Failing tests** — `profile_test.go`: load the real `tests/engine/directives/secruleengine-on.yaml` and assert two tests, first stage URI `/?attack=1`, interruption status 403; load `tests/unit/transformations/base64Decode.json` and assert 4 cases with `Type == "tfn"`; `latin1("Aé")` is `[]byte{0x41, 0xe9}`; `escapeParam(`a"b\c`)` is `a\"b\\c`; `RepoRoot()` contains `spec/00-conventions.md`.
- [ ] **Step 2: RED**; **Step 3: implement** (yaml.v3 decode with `KnownFields(true)` so a schema drift fails loudly; JSON via `encoding/json` into `[]map[string]any` then typed, setting `HasParam`); **Step 4: GREEN**; **Step 5: Commit** `feat(adapter): load engine profiles and unit cases`.

---

### Task 3: Engine tier runner and TestEngine, then triage

**Files:**
- Create: `adapters/coraza/engine.go`, `adapters/coraza/engine_test.go`, `adapters/coraza/conformance_test.go`

**Interfaces:**
```go
type Observed struct { Triggered map[int]bool; Interruption *types.Interruption; Log []string }
func BuildWAF(p Profile, dir string) (coraza.WAF, *[]string, error)   // writes p.Files under dir, WithRootFS(os.DirFS(dir)), WithDirectives(p.Rules), error callback appending ErrorLog() lines
func RunStage(waf coraza.WAF, log *[]string, s Stage) Observed
func CheckStage(o Observed, want Output) []string                    // human-readable mismatches, empty when the stage passes
var implemented = map[string]bool{}                                  // Extended anchors Coraza implements (none yet)
```
`RunStage` follows the design §3 exactly; `Host: localhost` added when absent; the response stage is driven only when `s.Response != nil`; when `tx.IsInterrupted()` after a request phase, response phases are skipped but `ProcessLogging` runs. `CheckStage` compares each asserted field; for `interruption` compares `RuleID` and `Action` always and `Status` only when non-zero in the expectation.

`conformance_test.go`:
```go
func TestEngine(t *testing.T) {
	root := RepoRoot()
	gaps, err := LoadGaps(filepath.Join(root, "compat", "known-gaps.md"), "coraza")
	if err != nil { t.Fatal(err) }
	profiles, err := LoadProfiles(root)
	if err != nil { t.Fatal(err) }
	for _, p := range profiles {
		p := p
		t.Run(p.Path, func(t *testing.T) {
			if reason, skip := needsUnimplemented(p); skip { t.Skip("requires " + reason) }
			_, expected := gaps[p.Path]
			failures := runProfile(t, p)              // collects mismatch strings over all stages; handles expect_error
			switch {
			case expected && len(failures) == 0:
				t.Fatalf("known-gaps row is obsolete: remove the row for %s", p.Path)
			case expected:
				for _, f := range failures { t.Log("expected (known gap): " + f) }
			default:
				for _, f := range failures { t.Error(f) }
			}
		})
	}
}
```
- [ ] **Step 1: Failing unit test** — `engine_test.go`: `TestRunStageDenies` builds a WAF from a two-line rule set and checks `RunStage` reports rule 1 triggered with a 403 deny; `TestCheckStageReportsMismatch` feeds an `Observed` without the expected id.
- [ ] **Step 2: RED**; **Step 3: implement**; **Step 4: GREEN** on the unit tests.
- [ ] **Step 5: First real run** — `go test ./... -run TestEngine -v 2>&1 | tee /tmp/engine-run.txt`; summarise: profiles passed / expected-failed / unexpected-failed / obsolete rows. **Triage every unexpected failure** against source and classify: (a) adapter bug → fix here; (b) Coraza gap → add a known-gaps row with the source pointer; (c) spec or test wrong → fix spec/test (own commit). Record each classification in the ledger. The run is not done until the output is green with the table accurate.
- [ ] **Step 6: Commit** `feat(adapter): engine-tier runner; first run triaged` (+ separate commits for spec/test fixes and known-gaps rows).

---

### Task 4: Unit tier runner and TestUnit, then triage

**Files:**
- Create: `adapters/coraza/unit.go`, `adapters/coraza/unit_test.go`; modify `conformance_test.go`

**Interfaces:**
```go
func unitRules(c UnitCase) string          // the three-directive rule set from design §4; param escaped
func RunUnit(waf coraza.WAF, c UnitCase) (matched bool, output string, groups []string, err error)
var unsupportedOperators = map[string]bool{"containsWord": true, "verifyCC": true, "verifycpf": true, "verifyssn": true}  // not registered in Coraza 3.8.1; files skipped with t.Skip
```
Grouping: build one WAF per distinct `(type, name, param)`; cache in a map within the test. Output for transformations: `MatchedDatas()[0].Value()`; operators: `len(MatchedRules())` includes rule 2. `re_groups`: read `TX:0..n` through `tx.(plugintypes.TransactionState).Variables().TX().Get(strconv.Itoa(i))` when `capture` was added to the rule (added only when the case has `re_groups`).

`TestUnit` mirrors `TestEngine` at file granularity for gaps (a listed unit file: any failing case is expected; zero failing cases → obsolete row).
- [ ] **Step 1: Failing unit tests** — `unit_test.go`: an operator case (`contains`, `"abc"`, input `xabcx`, ret 1) and a transformation case (`lowercase`, `ABC` → `abc`) through a real WAF; a NUL-containing input round-trips.
- [ ] **Step 2: RED**; **Step 3: implement**; **Step 4: GREEN**.
- [ ] **Step 5: First real run and triage**, as Task 3 Step 5, over 4,269 cases; expect the known divergences (`ipMatch` one case, `cssDecode` two, `urlDecodeUni` one, `htmlEntityDecode` two, `uppercase-extra` none for Coraza) and probably more; classify each.
- [ ] **Step 6: Commit** `feat(adapter): unit-tier runner; first run triaged`.

---

### Task 5: CI, README, ADR-0023

- `.github/workflows/validate.yml`: new job `coraza-adapter` with `actions/setup-go@v5` (`go-version-file: adapters/coraza/go.mod`) and `go test ./...` in `adapters/coraza` (working-directory).
- `adapters/coraza/README.md`: how to run, how results relate to `compat/known-gaps.md`, how to add a gap row, what "obsolete row" means.
- `adr/0023-reference-adapters.md` (Clarification) per design §8; index row.
- `README.md`: layout row for `adapters/`; "How an engine adopts this" points at the reference adapter.
- `compat/known-gaps.md` intro: Coraza rows are now **verified by `adapters/coraza`**; v2/v3 rows remain predictions.
- [ ] Validate, Python suite, `go test`, commit `feat(adapter): CI job, README, ADR-0023`.

---

## Self-review notes

- **Spec coverage:** design §2 shape → Tasks 1–2, 5; §3 → Task 3; §4 → Task 4; §5 gaps → Tasks 1, 3, 4; §6 limits → Task 3/4 triage; §7 adapter tests → each task's Step 1; §8 ADR-0023 → Task 5.
- **Review Focus mapping:** 1 → Task 3 Step 5 over `case-insensitive-names.yaml`; 2 → Task 3 over `response.yaml`; 3 → Task 2 `escapeParam` + Task 4 over `rx.json`; 4 → Task 4 over `validateUtf8Encoding.json`; 5 → Task 1 `TestLoadGaps`.
- **Open calls for the reviewer:** gaps at file granularity (not per case); operators Coraza lacks are skipped rather than failed (they are Extended, so correct per conventions); unit tier drives operators through `REQUEST_BODY` with `forceRequestBodyVariable` (Coraza then also parses the body as URLENCODED, which is harmless for `REQUEST_BODY` itself).
