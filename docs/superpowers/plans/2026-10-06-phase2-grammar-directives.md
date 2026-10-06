# SecLang Spec Phase 2 (Grammar, Processing Model, Directives) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Specify the lexical structure, grammar, processing model and every directive of SecLang, with a status for each of the 91 directive names and engine tests for every Core one, plus ADRs 0004–0006 and two new divergence ADRs found while researching this phase.

**Architecture:** Four spec files (`01-lexical`, `02-grammar`, `03-processing-model`, `04-directives`) follow the Phase 1 section template (heading, `**Status:**`, Syntax, Default, Scope, Semantics, Divergence notes, Tests). Facts about each engine are stated with a source pointer so a reviewer can check them. Tests are engine-tier YAML profiles; the schema gains a `files:` map so a profile can ship auxiliary files for `Include`. The matrix gains a `status` column for directives and the validator cross-checks it against the spec.

**Tech Stack:** Markdown, YAML, JSON Schema; Python via `uv run` for `tools/`.

**Spec:** `docs/superpowers/specs/2026-10-06-seclang-spec-design.md` sections 4.3, 4.4, 4.5, 4.6 (Phase 2) and the Phase 1 conventions in `spec/00-conventions.md`.

## Global Constraints

- Every feature heading is `### <Name>` followed by `**Status:** Core|Extended|Deprecated|Engine-specific` as the first non-blank line (validator convention from Phase 1).
- Every Core feature has at least one test whose `spec:` anchor names it; `uv run python tools/validate.py` must report `0 error(s)` at the end of every task.
- Engine facts carry a source pointer in the form `(<engine>: <file>)` using the paths surveyed on 2026-10-06: v2 `apache2/apache2_config.c`, `apache2/modsecurity.h`, `apache2/re.c`; v3 `src/parser/seclang-scanner.ll`, `src/parser/seclang-parser.yy`, `headers/modsecurity/rules_set_properties.h`, `src/transaction.cc`, `src/rules_exceptions.cc`; Coraza `internal/seclang/parser.go`, `internal/seclang/directives.go`, `internal/corazawaf/waf.go`, `internal/corazawaf/rulegroup.go`.
- Defaults that differ between engines are stated per engine and left unspecified, following the `SecRuleEngine` precedent. Only defaults all three share are normative.
- Tests assert on `triggered_rules`, `non_triggered_rules`, `interruption`, `no_interruption`, `expect_error` only.
- Divergence ADRs name their test file(s) under `## Tests`.
- Commit messages end with the two attribution lines from the session reminder; run everything through `uv run`.

## Review Focus

1. A profile whose `rules` block has Windows CRLF line endings. Expected: parses identically to LF; test added to Task 2 (`lexical/crlf-line-endings.yaml`).
2. `SecRuleRemoveById` with a range whose start is greater than its end (`SecRuleRemoveById 200-100`). Expected: configuration error, not a silent no-op; test added to Task 5a.
3. `SecRuleUpdateTargetById` naming an id that does not exist. Expected: accepted silently (all three engines), so the test asserts the config loads; added to Task 5a.
4. A `SecMarker` referenced by `skipAfter` that is defined in a *later* phase than the skipping rule. Expected: the skip only affects the current phase; rules of later phases run; test added to Task 4.
5. `SecRequestBodyLimit 0`. Expected per engines: v3 treats 0 as unlimited (`transaction.cc` checks `m_value > 0`); v2 and Coraza treat it as a zero-byte limit. Expected spec outcome: left unspecified with a divergence note and no test on the zero value; Task 5b must say so explicitly.

---

### Task 1: Matrix status column, `files:` in engine profiles, validator cross-check

**Files:**
- Modify: `compat/matrix.json` (add `"status"` to every `directives` row)
- Modify: `tools/matrix.py` (render a Status column when present)
- Modify: `tools/validate.py` (add `check_matrix_status`; register)
- Modify: `tools/test_matrix.py`, `tools/test_validate.py`
- Modify: `tests/schema/engine.schema.json` (add top-level `files`)
- Modify: `tests/README.md` (document `files`)

**Interfaces:**
- Produces: matrix rows may carry `"status": "Core"|"Extended"|"Deprecated"|"Engine-specific"`. `validate.check_matrix_status(root)` errors when (a) a directive row's status differs from the spec feature `04-directives.md#<slug(name)>`, (b) a row has a status but no spec feature or vice versa, (c) a row with status Core is `false` for any engine. `matrix.render` prints a fifth column `status` for categories where any row has one. Engine profiles may carry `files: {"<relative path>": "<content>"}`; adapters write them next to the profile before loading `rules`.

- [ ] **Step 1: Failing tests for the renderer and the new check**

Append to `tools/test_matrix.py`:

```python
class StatusColumnTests(unittest.TestCase):
    def test_status_column_rendered_when_any_row_has_it(self):
        sample = json.loads(json.dumps(SAMPLE))
        sample["categories"]["operators"][0]["status"] = "Core"
        md = matrix.render(sample)
        self.assertIn("| Name | v2 | v3 | coraza | status |", md)
        self.assertIn("| `rx` | yes | yes | yes | Core |", md)
        self.assertIn("| `restpath` | - | - | yes | - |", md)

    def test_no_status_column_when_absent(self):
        self.assertNotIn("| status |", matrix.render(SAMPLE))
```

Append to `tools/test_validate.py`:

```python
MATRIX_WITH_STATUS = {
    "generated": "2026-10-06",
    "engines": {"v2": "a", "v3": "b", "coraza": "c"},
    "categories": {"directives": [
        {"name": "SecRuleEngine", "v2": True, "v3": True, "coraza": True, "status": "Core"},
        {"name": "SecDataset", "v2": False, "v3": False, "coraza": True, "status": "Engine-specific"},
    ]},
}

SPEC_DIRECTIVES = """\
# Directives

### SecRuleEngine

**Status:** Core

### SecDataset

**Status:** Engine-specific
"""


class MatrixStatusTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_repo(Path(self._tmp.name))
        (self.root / "compat/matrix.json").write_text(json.dumps(MATRIX_WITH_STATUS))
        (self.root / "spec/04-directives.md").write_text(SPEC_DIRECTIVES)

    def tearDown(self):
        self._tmp.cleanup()

    def test_consistent_matrix_and_spec_pass(self):
        self.assertEqual(validate.check_matrix_status(self.root), [])

    def test_status_mismatch_is_reported(self):
        (self.root / "spec/04-directives.md").write_text(SPEC_DIRECTIVES.replace("**Status:** Core", "**Status:** Extended"))
        errors = validate.check_matrix_status(self.root)
        self.assertTrue(any("SecRuleEngine" in e and "Core" in e and "Extended" in e for e in errors))

    def test_core_row_missing_in_an_engine_is_reported(self):
        m = json.loads(json.dumps(MATRIX_WITH_STATUS))
        m["categories"]["directives"][0]["coraza"] = False
        (self.root / "compat/matrix.json").write_text(json.dumps(m))
        errors = validate.check_matrix_status(self.root)
        self.assertTrue(any("SecRuleEngine" in e and "coraza" in e for e in errors))

    def test_spec_feature_without_matrix_row_and_row_without_feature(self):
        (self.root / "spec/04-directives.md").write_text(SPEC_DIRECTIVES + "\n### SecFoo\n\n**Status:** Core\n")
        errors = validate.check_matrix_status(self.root)
        self.assertTrue(any("secfoo" in e.lower() and "matrix" in e for e in errors))
        m = json.loads(json.dumps(MATRIX_WITH_STATUS))
        m["categories"]["directives"].append({"name": "SecBar", "v2": True, "v3": True, "coraza": True, "status": "Core"})
        (self.root / "compat/matrix.json").write_text(json.dumps(m))
        (self.root / "spec/04-directives.md").write_text(SPEC_DIRECTIVES)
        errors = validate.check_matrix_status(self.root)
        self.assertTrue(any("SecBar" in e and "spec" in e for e in errors))

    def test_rows_without_status_are_ignored(self):
        m = json.loads(json.dumps(MATRIX_WITH_STATUS))
        m["categories"]["operators"] = [{"name": "rx", "v2": True, "v3": True, "coraza": True}]
        (self.root / "compat/matrix.json").write_text(json.dumps(m))
        self.assertEqual(validate.check_matrix_status(self.root), [])
```

- [ ] **Step 2: Run to verify RED**

Run: `uv run python -m unittest tools.test_matrix.StatusColumnTests tools.test_validate.MatrixStatusTests`
Expected: FAIL; `StatusColumnTests` on missing column text, `MatrixStatusTests` with `AttributeError: ... 'check_matrix_status'`.

- [ ] **Step 3: Implement**

In `tools/matrix.py`, replace the category loop body after the `missing` check with:

```python
        has_status = any("status" in row for row in rows)
        in_all = sum(all(row[e] for e in ENGINES) for row in rows)
        header = ["Name", *ENGINES] + (["status"] if has_status else [])
        out += [
            "",
            f"## {category} ({in_all} of {len(rows)} in all engines)",
            "",
            "| " + " | ".join(header) + " |",
            "|---|" + "---|" * (len(header) - 1),
        ]
        for row in sorted(rows, key=lambda r: r["name"].lower()):
            cells = [("yes" if row[e] else "-") for e in ENGINES]
            if has_status:
                cells.append(row.get("status", "-"))
            out.append(f"| `{row['name']}` | " + " | ".join(cells) + " |")
```

In `tools/validate.py`, insert before `CHECKS`:

```python
MATRIX_SPEC_FILES = {"directives": "04-directives.md"}


def check_matrix_status(root: Path) -> list[str]:
    """Matrix rows that carry a status must agree with the spec feature of the same name."""
    try:
        matrix = _matrix.load(root)
    except (FileNotFoundError, ValueError):
        return []  # check_matrix reports these
    features = spec_features(root)
    errors = []
    for category, spec_file in MATRIX_SPEC_FILES.items():
        rows = {row["name"]: row for row in matrix["categories"].get(category, [])}
        if not any("status" in row for row in rows.values()):
            continue
        by_anchor = {f"{spec_file}#{slug(name)}": name for name in rows}
        for name, row in sorted(rows.items()):
            anchor = f"{spec_file}#{slug(name)}"
            status = row.get("status")
            spec_status = features.get(anchor)
            if status is None and spec_status is None:
                continue
            if status is None:
                errors.append(f"compat/matrix.json: {category}/{name}: spec has status {spec_status} but matrix row has none")
            elif spec_status is None:
                errors.append(f"compat/matrix.json: {category}/{name}: status {status} but spec/{anchor} does not exist")
            elif status != spec_status:
                errors.append(f"compat/matrix.json: {category}/{name}: matrix says {status}, spec/{anchor} says {spec_status}")
            if status == "Core":
                for e in _matrix.ENGINES:
                    if not row.get(e):
                        errors.append(f"compat/matrix.json: {category}/{name}: Core but absent in {e}")
        for anchor in sorted(a for a in features if a.startswith(spec_file + "#")):
            if anchor not in by_anchor:
                errors.append(f"spec/{anchor}: no matching row in compat/matrix.json {category}")
    return errors
```

and register: `CHECKS = [check_tests, check_coverage, check_adrs, check_matrix, check_matrix_status]`.

In `tests/schema/engine.schema.json` add after `"requires"`:

```json
    "files": {
      "type": "object",
      "additionalProperties": {"type": "string"},
      "propertyNames": {"pattern": "^[A-Za-z0-9_./-]+$"},
      "description": "Auxiliary files written next to the profile before rules are loaded, e.g. for Include or @pmFromFile. Keys are relative paths without '..'."
    },
```

In `tests/README.md`, under "Fields that link tests to the spec", add:

```markdown
- `files: {relative/path: content}` (engine tier) ships auxiliary files. The adapter
  writes each one relative to a temporary directory, then loads `rules` with that
  directory as the configuration directory, so `Include relative/path` and
  `@pmFromFile relative/path` resolve.
```

- [ ] **Step 4: Run to verify GREEN**

Run: `uv run python -m unittest discover -s tools -t .`
Expected: `OK` (31 + 7 = 38 tests).

- [ ] **Step 5: Add statuses to the matrix**

Run from repo root (the statuses are the table in Task 5's preamble; this script encodes it):

```bash
uv run python - <<'EOF'
import json
p = "compat/matrix.json"; m = json.load(open(p))
CORE = set("""Include SecAction SecArgumentSeparator SecArgumentsLimit SecAuditEngine SecAuditLog
SecAuditLogFormat SecAuditLogParts SecAuditLogRelevantStatus SecAuditLogStorageDir SecAuditLogType
SecComponentSignature SecDataDir SecDebugLog SecDebugLogLevel SecDefaultAction SecMarker
SecRequestBodyAccess SecRequestBodyInMemoryLimit SecRequestBodyJsonDepthLimit SecRequestBodyLimit
SecRequestBodyLimitAction SecRequestBodyNoFilesLimit SecResponseBodyAccess SecResponseBodyLimit
SecResponseBodyLimitAction SecResponseBodyMimeType SecResponseBodyMimeTypesClear SecRule
SecRuleEngine SecRuleRemoveById SecRuleRemoveByTag SecRuleUpdateActionById SecRuleUpdateTargetById
SecRuleUpdateTargetByTag SecUploadDir SecUploadFileMode SecUploadKeepFiles""".split())
EXTENDED = set("""SecAuditLogDirMode SecAuditLogFileMode SecCollectionTimeout SecCookieFormat
SecCookieV0Separator SecGeoLookupDb SecHttpBlKey SecParseXmlIntoArgs SecPcreMatchLimit
SecPcreMatchLimitRecursion SecRemoteRules SecRemoteRulesFailAction SecRuleInheritance
SecRulePerfTime SecRuleRemoveByMsg SecRuleScript SecRuleUpdateTargetByMsg SecSensorId
SecServerSignature SecTmpDir SecTmpSaveUploadedFiles SecUnicodeMapFile SecUploadFileLimit
SecWebAppId SecXmlExternalEntity""".split())
ENGINE = set("SecAuditLogPrefix SecDataset SecIgnoreRuleCompilationErrors SecResponseBodyJsonDepthLimit SecRxPreFilter".split())
for row in m["categories"]["directives"]:
    n = row["name"]
    row["status"] = "Core" if n in CORE else "Extended" if n in EXTENDED else "Engine-specific" if n in ENGINE else "Deprecated"
json.dump(m, open(p, "w"), indent=1); open(p, "a").write("\n")
from collections import Counter; print(Counter(r["status"] for r in m["categories"]["directives"]))
EOF
uv run python tools/matrix.py
```
Expected: `Counter({'Core': 38, 'Deprecated': 23, 'Extended': 25, 'Engine-specific': 5})` (sums to 91).

- [ ] **Step 6: Validator on the real repo**

Run: `uv run python tools/validate.py`
Expected: many `no matching row` / `status ... but spec does not exist` errors, because `spec/04-directives.md` only has `SecRuleEngine` yet. That is the correct RED state for Task 5; do **not** commit a red validator. Instead temporarily confirm the check works by running `uv run python -c "from tools import validate; print(len(validate.check_matrix_status(validate.ROOT)))"` → `90`. Then proceed to Step 7 without committing the matrix statuses: `git stash push compat/matrix.json compat/matrix.md` and keep the stash until Task 5c.

- [ ] **Step 7: Commit code and schema only**

```bash
uv run python tools/validate.py   # must be 0 error(s) with the matrix stashed
git add tools tests/schema/engine.schema.json tests/README.md
git commit -m "feat: matrix status column, files: in engine profiles, matrix/spec status cross-check

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01MdECTJovik6Z6EQq73oD1Z"
```

---

### Task 2: `spec/01-lexical.md` complete, with tests

**Files:**
- Modify: `spec/01-lexical.md` (replace the Phase 1 stub paragraph; keep `### Name matching`)
- Create: `tests/engine/lexical/comment-lines.yaml`, `continuation-lines.yaml`, `quoted-arguments.yaml`, `crlf-line-endings.yaml`, `include-relative-file.yaml`, `comment-with-trailing-backslash.yaml`

**Interfaces:**
- Produces anchors: `01-lexical.md#lines-and-directives`, `#comments`, `#line-continuation`, `#quoting-and-escapes`, `#include`, `#name-matching` (exists). ADR-0013 (Task 6) references `comment-with-trailing-backslash.yaml`.

**Facts to state (verified 2026-10-06):**
- Lines: a configuration is a sequence of lines; a directive occupies one logical line; leading whitespace is ignored (all three).
- Comments: a line whose first non-blank character is `#` is a comment (v2: Apache core parser; v3: scanner `#` rules; Coraza `parser.go:119` "ignore all the comments (lines starting with "#") in any circumstances"). There are no trailing comments: `#` inside a directive line is data.
- Continuation: a line ending in `\` (optionally followed by CR) continues onto the next line; the backslash and the line break are removed and the two pieces joined with no inserted whitespace (Coraza `parser.go:139` `TrimSuffix(line, "\\")`; v2 Apache `ap_cfg_getline`; v3 scanner). CRS v4 has 7266 continuation lines.
- **Divergence:** a comment line ending in `\`. v2 (Apache joins continuation lines *before* checking for `#`) and v3 (scanner rules at `seclang-scanner.ll:892-893` enter a COMMENT state for `# SecRule ... \`) treat the continued lines as part of the comment. Coraza drops the comment line first (`parser.go:119` before `:139`) and parses the next line as a new directive. Decision in ADR-0013: the ModSecurity behaviour is normative (a commented-out multi-line rule must stay commented out).
- Quoting: a directive argument is either an unquoted token (no whitespace) or a `"..."`-quoted string. Inside double quotes `\"` yields a literal `"` and `\\` a literal `\`. Single quotes are not argument delimiters at the directive level; they delimit values inside the action list (`msg:'...'`), see 02-grammar.
- CRLF: engines accept CRLF line endings (v3 scanner `[\r\n]`, Coraza trims `\r`, Apache strips). Normative: MUST accept.
- Include: `Include <path>`; relative paths resolve against the directory of the including file (Coraza `parser.go:66-68`; Apache: relative to ServerRoot — **divergence note**: v2 resolves relative to ServerRoot, not the including file); glob patterns (`*`) expand to every match sorted (Coraza `fs.Glob`; Apache `Include` glob). Nested includes are permitted; Coraza caps recursion at `maxIncludeRecursion` = check value in `parser.go:20`. Normative: MUST support absolute paths and `*` globs; relative-path base is **unspecified** (divergence note); a missing non-glob file MUST be a configuration error; an empty glob result MUST NOT be an error (Coraza warns; Apache 2.4 `IncludeOptional` vs `Include` — note that Apache `Include` with an empty wildcard is an error only when the pattern contains no wildcard).

- [ ] **Step 1: Write the test profiles**

`tests/engine/lexical/comment-lines.yaml`:
```yaml
meta:
  name: comment-lines
  description: Lines whose first non-blank character is # are ignored; # inside a directive is data
spec: 01-lexical.md#comments
rules: |
  SecRuleEngine On
  # SecRule ARGS_GET:a "@streq 1" "id:2001,phase:1,deny,status:403"
      # indented comment
  SecRule ARGS_GET:a "@streq #1" "id:2002,phase:1,deny,status:403"
tests:
  - test_title: commented rule does not exist, hash inside operator is literal
    stages:
      - stage:
          input:
            uri: "/?a=%231"
          output:
            triggered_rules: [2002]
            non_triggered_rules: [2001]
            interruption: {rule_id: 2002, action: deny, status: 403}
```

`tests/engine/lexical/continuation-lines.yaml`:
```yaml
meta:
  name: continuation-lines
  description: A trailing backslash joins the next line without inserting whitespace
spec: 01-lexical.md#line-continuation
rules: |
  SecRuleEngine On
  SecRule ARGS_GET:a \
      "@streq abc" \
      "id:2003,\
      phase:1,\
      deny,status:403"
tests:
  - test_title: three-line rule behaves as one line
    stages:
      - stage:
          input:
            uri: /?a=abc
          output:
            triggered_rules: [2003]
            interruption: {rule_id: 2003, action: deny, status: 403}
```

`tests/engine/lexical/quoted-arguments.yaml`:
```yaml
meta:
  name: quoted-arguments
  description: Double-quoted arguments may contain spaces and escaped quotes
spec: 01-lexical.md#quoting-and-escapes
rules: |
  SecRuleEngine On
  SecRule ARGS_GET:a "@streq say \"hi\" now" "id:2004,phase:1,deny,status:403"
tests:
  - test_title: escaped double quote inside operator argument
    stages:
      - stage:
          input:
            uri: '/?a=say%20%22hi%22%20now'
          output:
            triggered_rules: [2004]
            interruption: {rule_id: 2004, action: deny, status: 403}
```

`tests/engine/lexical/crlf-line-endings.yaml`:
```yaml
meta:
  name: crlf-line-endings
  description: CRLF line endings are accepted
spec: 01-lexical.md#lines-and-directives
rules: "SecRuleEngine On\r\nSecRule ARGS_GET:a \"@streq 1\" \"id:2005,phase:1,deny,status:403\"\r\n"
tests:
  - test_title: rules separated by CRLF load and fire
    stages:
      - stage:
          input:
            uri: /?a=1
          output:
            triggered_rules: [2005]
            interruption: {rule_id: 2005, action: deny, status: 403}
```

`tests/engine/lexical/include-relative-file.yaml`:
```yaml
meta:
  name: include-relative-file
  description: Include loads another file; a glob with no match is not an error
spec: 01-lexical.md#include
files:
  included/rules.conf: |
    SecRule ARGS_GET:a "@streq 1" "id:2006,phase:1,deny,status:403"
rules: |
  SecRuleEngine On
  Include included/rules.conf
  Include included/nothing-*.conf
tests:
  - test_title: rule from included file fires
    stages:
      - stage:
          input:
            uri: /?a=1
          output:
            triggered_rules: [2006]
            interruption: {rule_id: 2006, action: deny, status: 403}
```

`tests/engine/lexical/comment-with-trailing-backslash.yaml`:
```yaml
meta:
  name: comment-with-trailing-backslash
  description: A comment line ending in a backslash swallows the continued lines (ADR-0013)
spec: 01-lexical.md#comments
rules: |
  SecRuleEngine On
  # SecRule ARGS_GET:a "@streq 1" \
      "id:2007,phase:1,deny,status:403"
  SecRule ARGS_GET:a "@streq 1" "id:2008,phase:1,pass"
tests:
  - test_title: continued comment is not parsed as a directive
    stages:
      - stage:
          input:
            uri: /?a=1
          output:
            triggered_rules: [2008]
            non_triggered_rules: [2007]
            no_interruption: true
```

- [ ] **Step 2: Validator RED**

Run: `uv run python tools/validate.py`
Expected: errors naming `01-lexical.md#comments`, `#line-continuation`, `#quoting-and-escapes`, `#lines-and-directives`, `#include` as missing anchors.

- [ ] **Step 3: Write `spec/01-lexical.md`**

Replace the two-sentence intro with: "SecLang configuration is line-oriented text. This file defines how lines become directives; `02-grammar.md` defines what a directive line may contain." Then add, before `### Name matching`, the five sections `### Lines and directives`, `### Comments`, `### Line continuation`, `### Quoting and escapes`, `### Include`, each `**Status:** Core`, each following the template (Syntax, Semantics, Divergence notes, Tests) using the facts listed above. In `### Comments`, state the ADR-0013 outcome: "A comment line ending in `\` continues onto the next line like any other line; the whole logical line is the comment. Engines MUST NOT parse the continued text as a directive (ADR-0013)." In `### Include`, state: relative-path base unspecified (v2 ServerRoot vs v3/Coraza including-file directory), recursion limit MAY exist and MUST be at least 10 deep — verify `maxIncludeRecursion` in `parser.go:20` and quote its value.

- [ ] **Step 4: Validator GREEN and commit**

Run: `uv run python tools/validate.py` → `0 error(s)`.

```bash
git add spec/01-lexical.md tests/engine/lexical
git commit -m "spec: lexical structure with tests (lines, comments, continuation, quoting, Include)

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01MdECTJovik6Z6EQq73oD1Z"
```

---

### Task 3: `spec/02-grammar.md` with tests

**Files:**
- Create: `spec/02-grammar.md`
- Create: `tests/engine/grammar/variable-list.yaml`, `variable-count-and-exclusion.yaml`, `variable-selectors.yaml`, `operator-forms.yaml`, `action-list-values.yaml`, `macro-expansion.yaml`

**Interfaces:**
- Produces anchors: `02-grammar.md#directive-line`, `#secrule-structure`, `#variable-list`, `#variable-selectors`, `#operator`, `#action-list`, `#macro-expansion`.

- [ ] **Step 1: Write the EBNF (the normative core of the file)**

```ebnf
config        = { line } ;
line          = comment | directive | empty ;
directive     = name , { WS , argument } ;
argument      = quoted | bare ;
quoted        = '"' , { qchar } , '"' ;        (* qchar: any char except '"', or '\"', or '\\' *)
bare          = NONWS , { NONWS } ;

secrule       = "SecRule" , WS , variables , WS , operator , [ WS , actions ] ;
secaction     = "SecAction" , WS , actions ;

variables     = variable , { "|" , variable } ;
variable      = [ "!" | "&" ] , collection , [ ":" , selector ] ;
collection    = IDENT ;                        (* case-insensitive, see 05-variables *)
selector      = regexsel | key ;
regexsel      = "/" , { rchar } , "/" ;        (* rchar: any char except unescaped "/" *)
key           = { kchar } ;                    (* kchar: any char except "|" and WS *)

operator      = [ "!" ] , [ "@" , opname , [ WS , opparam ] ] | implicit_rx ;
implicit_rx   = text ;                         (* no leading "@": "@rx text"; leading "!" negates *)
opname        = IDENT ;
opparam       = text ;                         (* to end of quoted argument; may contain macros *)

actions       = action , { "," , action } ;
action        = aname , [ ":" , avalue ] ;
avalue        = "'" , { achar } , "'" | { vchar } ; (* achar: any except "'" or "\'" ; vchar: any except "," *)
aname         = IDENT ;

macro         = "%{" , collection , [ "." , key ] , "}" ;
```

Normative notes to write beside it: whitespace around `|` in a variable list is **not** permitted; a `,` inside a single-quoted action value is literal; `t:none` resets the transformation list inherited from `SecDefaultAction`; the three positional arguments of `SecRule` are each one `argument` (so `VARIABLES` with a `:` key containing spaces must be quoted); the `id` action is mandatory on every `SecRule`/`SecAction` that is not a chain member (v2 since 2.7, v3, Coraza) and chain members MUST NOT carry `id`.

Macro expansion: `%{VAR}` and `%{COLLECTION.key}` expand at evaluation time inside action values (`setvar`, `msg`, `logdata`, `tag`, `severity`?) and inside operator parameters for operators that declare macro support (`@streq`, `@eq`, `@ge`, `@gt`, `@le`, `@lt`, `@contains`, `@beginsWith`, `@endsWith`, `@within`, `@rx` in v3/Coraza? — **verify per engine** in Task 3 step 2 and list the agreed set as Core; others Extended). Collection and key names in macros are case-insensitive (CRS uses `%{tx.x}` and `%{TX.X}` interchangeably; 677 vs 285 occurrences).

- [ ] **Step 2: Verify the macro-capable operator set**

```bash
# Coraza: operators that call macro expansion
grep -rln 'macro' /Users/fzipitria/Workspace/OWASP/coraza/coraza/internal/operators/*.go | grep -v _test | xargs -n1 basename | sed 's/\.go//' | sort | tr '\n' ' '; echo
# v3: operators whose constructor builds a RunTimeString / macro
grep -rln 'RunTimeString\|MacroExpansion' /Users/fzipitria/Workspace/OWASP/modsecurity/modsecurity/src/operators/*.cc | xargs -n1 basename | sed 's/\.cc//' | sort | tr '\n' ' '; echo
# v2: operators calling expand_macros
cd /Users/fzipitria/Workspace/OWASP/modsecurity/modsecurity && git show v2/master:apache2/re_operators.c | grep -nE '^static int msre_op_[a-zA-Z]+_execute|expand_macros' | awk '/execute/{op=$0} /expand_macros/{print op}' | grep -oE 'msre_op_[a-zA-Z]+_execute' | sort -u | tr '\n' ' '
```
Record the three-way intersection in `#macro-expansion` as the Core set, the rest as Extended per engine.

- [ ] **Step 3: Write the six test profiles**

`variable-list.yaml` (spec `#variable-list`): rules `SecRule ARGS_GET:a|ARGS_GET:b "@streq 1" "id:3001,phase:1,deny,status:403"`; stage `/?b=1` → 3001 fires; stage `/?c=1` → non_triggered [3001], no_interruption.

`variable-count-and-exclusion.yaml` (spec `#variable-list`): rules
```
SecRule &ARGS_GET "@eq 2" "id:3002,phase:1,pass"
SecRule ARGS_GET|!ARGS_GET:skip "@streq x" "id:3003,phase:1,deny,status:403"
```
stage `/?a=1&b=2` → triggered [3002], non_triggered [3003]; stage `/?skip=x` → non_triggered [3003], no_interruption; stage `/?other=x` → triggered [3003], interruption 403.

`variable-selectors.yaml` (spec `#variable-selectors`): rules
```
SecRule ARGS_GET:/^user_/ "@streq admin" "id:3004,phase:1,deny,status:403"
SecRule REQUEST_HEADERS:X-Test "@streq yes" "id:3005,phase:1,deny,status:403"
```
stage `/?user_name=admin` → 3004; stage headers `{X-Test: yes}` → 3005; stage `/?name=admin` → non_triggered [3004].

`operator-forms.yaml` (spec `#operator`): rules
```
SecRule ARGS_GET:a "^abc$" "id:3006,phase:1,pass"
SecRule ARGS_GET:a "!@streq abc" "id:3007,phase:1,pass"
SecRule ARGS_GET:a "!abc" "id:3008,phase:1,pass"
```
stage `/?a=abc` → triggered [3006], non_triggered [3007, 3008]; stage `/?a=zzz` → triggered [3007, 3008], non_triggered [3006].

`action-list-values.yaml` (spec `#action-list`): rules
```
SecRule ARGS_GET:a "@streq 1" "id:3009,phase:1,deny,status:403,msg:'commas, inside, quotes',tag:'a/b',logdata:'x=%{MATCHED_VAR}'"
```
stage `/?a=1` → interruption 3009/403 (the point is that it parses).

`macro-expansion.yaml` (spec `#macro-expansion`): rules
```
SecAction "id:3010,phase:1,pass,nolog,setvar:tx.expected=secret"
SecRule ARGS_GET:a "@streq %{tx.expected}" "id:3011,phase:1,deny,status:403"
SecRule ARGS_GET:b "@streq %{TX.EXPECTED}" "id:3012,phase:1,deny,status:403"
```
stage `/?a=secret` → triggered [3011]; stage `/?b=secret` → triggered [3012] (case-insensitive macro names).

- [ ] **Step 4: Validator RED → write `spec/02-grammar.md` → GREEN → commit**

Sections, all Core: `### Directive line`, `### SecRule structure`, `### Variable list`, `### Variable selectors`, `### Operator`, `### Action list`, `### Macro expansion`. Each: Syntax (EBNF excerpt), Semantics, Divergence notes (none known unless Step 2 shows differences, then list), Tests.

```bash
uv run python tools/validate.py   # 0 error(s)
git add spec/02-grammar.md tests/engine/grammar
git commit -m "spec: grammar (EBNF) for directives, SecRule, variables, operators, actions, macros, with tests

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01MdECTJovik6Z6EQq73oD1Z"
```

---

### Task 4: `spec/03-processing-model.md` with tests

**Files:**
- Create: `spec/03-processing-model.md`
- Create: `tests/engine/processing/phases.yaml`, `chain.yaml`, `default-action.yaml`, `default-action-constraints.yaml`, `disruptive-actions.yaml`, `skip-and-skipafter.yaml`, `skipafter-later-phase.yaml`, `rule-exceptions.yaml`, `ctl-timing.yaml`

**Interfaces:**
- Produces anchors: `03-processing-model.md#phases`, `#chains`, `#default-actions`, `#disruptive-actions`, `#flow-control`, `#rule-exceptions`, `#ctl-timing`. ADR-0014 (Task 6) references `default-action-constraints.yaml`.

**Facts to state:**
- Phases 1–5: request headers, request body, response headers, response body, logging. Names `phase:request` = 2, `phase:response` = 4, `phase:logging` = 5 (v3 scanner; verify Coraza `internal/actions/phase.go` and v2 `re_actions.c` accept the same aliases). Rules run in phase order, then file order within a phase. A rule with no `phase` inherits it from `SecDefaultAction` of the phase... **careful:** v2/v3: default phase 2 when neither rule nor SecDefaultAction sets it; Coraza default `phase:2` via its default action (`directives.go` "Default: phase:2,log,auditlog,pass"). State: default phase is 2 in all three.
- Chains: `chain` links the next rule; the chain matches only if every member matches; disruptive actions and `id`, `phase`, `msg`, `tag`, `severity`, `logdata`, `skip`, `skipAfter` belong to the first rule; members may carry `t:`, `capture`, `setvar`, `ctl`. Members MUST NOT carry disruptive actions (Coraza `rule_parser.go:428` errors; v2/v3 error too — verify v3 `seclang-parser.yy` message).
- Default actions: `SecDefaultAction` applies to rules of its phase that follow it in file order; its action list is merged into each rule, with the rule's own actions overriding; `t:none` in a rule resets inherited transformations. Constraints (**divergence, ADR-0014**): v2 (`apache2_config.c cmd_default_action`) and v3 (`seclang-parser.yy:1234-1254`) require exactly one disruptive action and a `phase`, forbid `chain`, `id`, `skip`, `skipAfter`, `t:none`?, and allow one `SecDefaultAction` per phase per context; Coraza performs no such checks. Decision: ModSecurity constraints are normative; a violating `SecDefaultAction` MUST be a configuration error.
- Disruptive actions: `deny` (status from `status:`, default 403), `drop` (connection closed; HTTP status unobservable; adapters report `action: drop`), `redirect:URL` (status default 302), `allow` (phase/request/all), `pass` (no interruption), `block` (placeholder replaced by the default action's disruptive action). In `DetectionOnly` none interrupt. Only the first matching disruptive rule interrupts; later rules in that phase MUST NOT run.
- Flow control: `skip:N` skips the next N rules in the same phase; `skipAfter:MARKER` skips to the `SecMarker MARKER` (or rule `id`) in the same phase; markers are phase-less and never execute; a marker in a later phase does not satisfy a skipAfter from an earlier phase (the skip ends with the phase). v2 `re.c:1442-1556`, Coraza `rulegroup.go:207-216`.
- Rule exceptions: `SecRuleRemoveById ID|RANGE...`, `SecRuleRemoveByTag REGEX`, `SecRuleRemoveByMsg REGEX`; `SecRuleUpdateTargetById ID|RANGE "TARGETS"` where a target prefixed `!` removes it and an unprefixed one adds it; `SecRuleUpdateTargetByTag`, `SecRuleUpdateActionById ID "ACTIONS"`. All apply to rules already defined at the point they appear. Ranges `a-b` inclusive; `a > b` is an error (Coraza `directives.go` "invalid range"; v3 `rules_exceptions.cc:153`; v2 TODO comment says range not validated → divergence note, spec says MUST error). Unknown ids are silently ignored (all three).
- ctl timing: `ctl:` actions take effect when their rule matches, for the remainder of the transaction (`ruleEngine`, `auditEngine`, `requestBodyAccess`...) or for rules evaluated afterwards (`ruleRemoveById`, `ruleRemoveTargetById`...). `ctl:requestBodyAccess` and `ctl:requestBodyProcessor` only have effect in phase 1.

- [ ] **Step 1: Write the test profiles** (all `SecRuleEngine On` first; ids 4001–4099)

`phases.yaml` (`#phases`): rules
```
SecRule REQUEST_HEADERS:X-P "@streq 1" "id:4001,phase:1,pass"
SecRule ARGS_POST:p "@streq 1" "id:4002,phase:2,pass"
SecRule RESPONSE_HEADERS:X-R "@streq 1" "id:4003,phase:3,pass"
SecRule RESPONSE_BODY "@contains marker" "id:4004,phase:4,pass"
SecRule TX:seen "@eq 1" "id:4005,phase:5,pass"
SecAction "id:4006,phase:4,pass,nolog,setvar:tx.seen=1"
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain
```
one stage: POST `/` with headers `{X-P: "1", Content-Type: application/x-www-form-urlencoded}`, data `p=1`, response `{status: 200, headers: {X-R: "1", Content-Type: text/plain}, data: "has marker"}` → triggered [4001, 4002, 4003, 4004, 4005, 4006], no_interruption.

`chain.yaml` (`#chains`): rules
```
SecRule ARGS_GET:a "@streq 1" "id:4010,phase:1,deny,status:403,chain"
  SecRule ARGS_GET:b "@streq 2"
SecRule ARGS_GET:c "@streq 1" "id:4011,phase:1,pass,chain"
  SecRule ARGS_GET:d "@streq 2" "t:none,setvar:tx.c=1"
```
stage `/?a=1&b=2` → triggered [4010], interruption 4010/403; stage `/?a=1&b=3` → non_triggered [4010], no_interruption; stage `/?c=1&d=2` → triggered [4011].

`default-action.yaml` (`#default-actions`): rules
```
SecDefaultAction "phase:1,log,deny,status:418"
SecRule ARGS_GET:a "@streq 1" "id:4020"
SecRule ARGS_GET:b "@streq 1" "id:4021,status:403"
SecRule ARGS_GET:c "@streq 1" "id:4022,pass"
```
stage `/?a=1` → interruption 4020 deny 418; stage `/?b=1` → interruption 4021 deny 403; stage `/?c=1` → triggered [4022], no_interruption.

`default-action-constraints.yaml` (`#default-actions`, ADR-0014): three profiles would be needed for three error cases; keep one profile per file — create `default-action-no-phase.yaml` with rules `SecDefaultAction "log,deny"` and a single stage `output: {expect_error: true}`, and `default-action-no-disruptive.yaml` with `SecDefaultAction "phase:1,log"` and `expect_error: true`. (Name the plan's `default-action-constraints.yaml` as these two files.)

`disruptive-actions.yaml` (`#disruptive-actions`): rules
```
SecRule ARGS_GET:a "@streq deny" "id:4030,phase:1,deny"
SecRule ARGS_GET:a "@streq redirect" "id:4031,phase:1,redirect:http://example.com/"
SecRule ARGS_GET:a "@streq drop" "id:4032,phase:1,drop"
SecRule ARGS_GET:a "@streq any" "id:4033,phase:1,deny,status:401"
SecRule ARGS_GET:a "@streq any" "id:4034,phase:1,deny,status:402"
```
stages: `deny` → interruption 4030 deny 403; `redirect` → interruption 4031 redirect 302; `drop` → interruption 4032 drop; `any` → interruption 4033/401 and non_triggered [4034] (first disruptive match stops the phase).

`skip-and-skipafter.yaml` (`#flow-control`): rules
```
SecRule ARGS_GET:a "@streq 1" "id:4040,phase:1,pass,skip:1"
SecRule ARGS_GET:a "@streq 1" "id:4041,phase:1,pass"
SecRule ARGS_GET:a "@streq 1" "id:4042,phase:1,pass,skipAfter:END-A"
SecRule ARGS_GET:a "@streq 1" "id:4043,phase:1,pass"
SecMarker END-A
SecRule ARGS_GET:a "@streq 1" "id:4044,phase:1,pass"
```
stage `/?a=1` → triggered [4040, 4042, 4044], non_triggered [4041, 4043].

`skipafter-later-phase.yaml` (`#flow-control`, Review Focus 4): rules
```
SecRule ARGS_GET:a "@streq 1" "id:4050,phase:1,pass,skipAfter:END-B"
SecRule ARGS_GET:a "@streq 1" "id:4051,phase:1,pass"
SecRule ARGS_GET:a "@streq 1" "id:4052,phase:2,pass"
SecMarker END-B
SecRule ARGS_GET:a "@streq 1" "id:4053,phase:2,pass"
```
stage `/?a=1` → triggered [4050, 4052, 4053], non_triggered [4051]. **Verify on paper against v2 `re.c:1518-1556` and Coraza `rulegroup.go:207-216` before committing**: in Coraza `tx.SkipAfter` persists across phases unless reset at phase start — read `rulegroup.go` around the phase loop; if Coraza carries the skip into phase 2, this is a divergence and the expected output follows ModSecurity with a divergence note and the file becomes the ADR test for a new ADR-0015 "skipAfter scope ends with the phase". Record the finding in the ledger either way.

`rule-exceptions.yaml` (`#rule-exceptions`): rules
```
SecRule ARGS_GET:a "@streq 1" "id:4060,phase:1,deny,status:403"
SecRule ARGS_GET:a "@streq 1" "id:4061,phase:1,deny,status:403,tag:'drop-me'"
SecRule ARGS_GET:a "@streq 1" "id:4062,phase:1,deny,status:403"
SecRule ARGS_GET:a|ARGS_GET:b "@streq 1" "id:4063,phase:1,deny,status:403"
SecRule ARGS_GET:a "@streq 1" "id:4064,phase:1,deny,status:403"
SecRule ARGS_GET:a "@streq 1" "id:4065,phase:1,pass"
SecRuleRemoveById 4060 4070-4080
SecRuleRemoveByTag drop-me
SecRuleUpdateTargetById 4063 "!ARGS_GET:a"
SecRuleUpdateActionById 4064 "pass"
SecRuleUpdateTargetById 999999 "!ARGS_GET:a"
```
stage `/?a=1` → non_triggered [4060, 4061, 4063], triggered [4062], interruption 4062/403. (4064 and 4065 are not reached because 4062 interrupts; a second stage `/?b=1` → triggered [4063], interruption 4063.) Add `rule-exceptions-bad-range.yaml` (Review Focus 2): rules `SecRuleRemoveById 200-100` → `expect_error: true`.

`ctl-timing.yaml` (`#ctl-timing`): rules
```
SecRule ARGS_GET:a "@streq 1" "id:4090,phase:1,pass,nolog,ctl:ruleRemoveById=4091"
SecRule ARGS_GET:a "@streq 1" "id:4091,phase:1,deny,status:403"
SecRule ARGS_GET:a "@streq 1" "id:4092,phase:2,pass,nolog,ctl:ruleEngine=Off"
SecRule ARGS_GET:a "@streq 1" "id:4093,phase:2,deny,status:403"
```
stage `/?a=1` → triggered [4090, 4092], non_triggered [4091, 4093], no_interruption.

- [ ] **Step 2: Validator RED → write `spec/03-processing-model.md` → GREEN → commit**

Sections, all Core: `### Phases`, `### Chains`, `### Default actions`, `### Disruptive actions`, `### Flow control`, `### Rule exceptions`, `### ctl timing`.

```bash
uv run python tools/validate.py   # 0 error(s)
git add spec/03-processing-model.md tests/engine/processing
git commit -m "spec: processing model (phases, chains, default actions, disruptive actions, flow control, exceptions) with tests

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01MdECTJovik6Z6EQq73oD1Z"
```

---

### Task 5: `spec/04-directives.md` — all 91 directives

Split into three commits (5a, 5b, 5c) but one spec file. The file opens with an index table: every directive name, status, one-line purpose, link to its section. Then one `###` section per directive in alphabetical order. Non-Core sections may be short (Syntax, Status, one-paragraph Semantics, which engines implement it), Core sections follow the full template.

**Proposed statuses (the review gate for this plan):**

| Status | Directives |
|---|---|
| **Core (38)** | Include, SecAction, SecArgumentSeparator, SecArgumentsLimit, SecAuditEngine, SecAuditLog, SecAuditLogFormat, SecAuditLogParts, SecAuditLogRelevantStatus, SecAuditLogStorageDir, SecAuditLogType, SecComponentSignature, SecDataDir, SecDebugLog, SecDebugLogLevel, SecDefaultAction, SecMarker, SecRequestBodyAccess, SecRequestBodyInMemoryLimit, SecRequestBodyJsonDepthLimit, SecRequestBodyLimit, SecRequestBodyLimitAction, SecRequestBodyNoFilesLimit, SecResponseBodyAccess, SecResponseBodyLimit, SecResponseBodyLimitAction, SecResponseBodyMimeType, SecResponseBodyMimeTypesClear, SecRule, SecRuleEngine, SecRuleRemoveById, SecRuleRemoveByTag, SecRuleUpdateActionById, SecRuleUpdateTargetById, SecRuleUpdateTargetByTag, SecUploadDir, SecUploadFileMode, SecUploadKeepFiles |
| **Extended (25)** | SecAuditLogDirMode, SecAuditLogFileMode, SecCollectionTimeout, SecCookieFormat, SecCookieV0Separator, SecGeoLookupDb, SecHttpBlKey, SecParseXmlIntoArgs, SecPcreMatchLimit, SecPcreMatchLimitRecursion, SecRemoteRules, SecRemoteRulesFailAction, SecRuleInheritance, SecRulePerfTime, SecRuleRemoveByMsg, SecRuleScript, SecRuleUpdateTargetByMsg, SecSensorId, SecServerSignature, SecTmpDir, SecTmpSaveUploadedFiles, SecUnicodeMapFile, SecUploadFileLimit, SecWebAppId, SecXmlExternalEntity |
| **Deprecated (23)** | SecAuditLog2, SecCacheTransformations, SecChrootDir, SecConnEngine, SecConnReadStateLimit, SecConnWriteStateLimit, SecContentInjection, SecDisableBackendCompression, SecGsbLookupDb, SecGuardianLog, SecHashEngine, SecHashKey, SecHashMethodPm, SecHashMethodRx, SecHashParam, SecInterceptOnError, SecReadStateLimit, SecRequestEncoding, SecStatusEngine, SecStreamInBodyInspection, SecStreamOutBodyInspection, SecUnicodeCodePage, SecWriteStateLimit |
| **Engine-specific (5)** | SecAuditLogPrefix (v3), SecDataset, SecIgnoreRuleCompilationErrors, SecResponseBodyJsonDepthLimit, SecRxPreFilter (Coraza) |

Rationale written into ADR-0001's consequences is already there; the two judgment calls to confirm: `SecArgumentSeparator` is Core although Coraza only parses it (observable semantics, in both recommended configs: a Core gap for Coraza); `SecCookieFormat` and `SecTmpDir` are Extended although in the recommended configs, because Coraza has no observable behaviour for them and cookie v1 is obsolete. `SecHash*`, `SecConn*`, `SecGsbLookupDb`, `SecStatusEngine` are Deprecated because only v2 implements them (v3 and Coraza parse and ignore).

**Per-directive facts for Core sections** (verified 2026-10-06; cite as shown):

| Directive | Syntax | v2 default (`apache2_config.c` / `modsecurity.h`) | v3 default (`rules_set_properties.h`) | Coraza default (`waf.go` / `directives.go`) |
|---|---|---|---|---|
| SecArgumentSeparator | `SecArgumentSeparator CHAR` | `&` | unset → `&` | `&` (parsed, **ignored**) |
| SecArgumentsLimit | `SecArgumentsLimit N` | 1000 | unset → no limit (`m_set` false) | 1000 |
| SecAuditEngine | `On\|Off\|RelevantOnly` | Off | unset (connector) | Off |
| SecAuditLog | `SecAuditLog PATH` | none | none | none |
| SecAuditLogFormat | `Native\|JSON` (+`JsonLegacy`,`OCSF` Coraza-only values → note) | Native | Native | Native |
| SecAuditLogParts | letters `ABCDEFGHIJKZ` | `ABCFHZ` | `ABCFHZ` | `ABCFHZ` |
| SecAuditLogRelevantStatus | `REGEX` | none | none | none |
| SecAuditLogStorageDir | `PATH` | none | none | none |
| SecAuditLogType | `Serial\|Concurrent` (v3 also `Parallel`, Coraza also `HTTPS`,`Syslog`) | Serial | Serial | Serial |
| SecDataDir | `PATH` | none | none | none |
| SecDebugLog | `PATH` | none | none | none |
| SecDebugLogLevel | `0-9` | 0 | 0 | 3 (**differs**) |
| SecRequestBodyAccess | `On\|Off` | Off | unset → Off | Off |
| SecRequestBodyLimit | `BYTES` | 134217728 | unset → unlimited (`m_value > 0` check) | 134217728 |
| SecRequestBodyNoFilesLimit | `BYTES` | 1048576 | unset → no check | 1048576 |
| SecRequestBodyInMemoryLimit | `BYTES` | 131072 | unset | = RequestBodyLimit (**differs**) |
| SecRequestBodyLimitAction | `Reject\|ProcessPartial` | Reject | unset (neither branch) | Reject |
| SecRequestBodyJsonDepthLimit | `N` | 10000 | unset → parser default | 1024 (**differs**) |
| SecResponseBodyAccess | `On\|Off` | Off | unset → Off | Off |
| SecResponseBodyLimit | `BYTES` | 524288 | unset → unlimited | 524288 |
| SecResponseBodyLimitAction | `Reject\|ProcessPartial` | Reject | unset | ProcessPartial (**differs**) |
| SecResponseBodyMimeType | `TYPE...` (space separated, accumulates) | `text/plain text/html` | `text/plain text/html` (verify `rules_set_properties.h` ctor) | `text/html text/plain`? verify `waf.go` |
| SecResponseBodyMimeTypesClear | none | – | – | – |
| SecRuleEngine | (Phase 1) | | | |
| SecUploadDir | `PATH` | none | none | none |
| SecUploadFileMode | `OCTAL` | 0600 | unset | unset |
| SecUploadKeepFiles | `On\|Off\|RelevantOnly` | Off | unset | Off |
| SecComponentSignature | `"STRING"` | appended to signature | same | same |
| SecMarker | `SecMarker ID\|TEXT` | – | – | – |
| SecDefaultAction | `"ACTIONS"` | none (rules need explicit disruptive) | none | `phase:2,log,auditlog,pass` (**differs**: Coraza has a built-in default) |
| SecRule / SecAction / SecRuleRemoveById / SecRuleRemoveByTag / SecRuleUpdateTargetById / SecRuleUpdateTargetByTag / SecRuleUpdateActionById / Include | see 02/03 | | | |

Where the table says *verify*, run the grep in the step and record the result; where it says **differs**, write a Divergence note and leave the default unspecified.

- [ ] **Step 5a: Rule-building directives** — sections for Include (cross-ref 01), SecAction, SecComponentSignature, SecDefaultAction (cross-ref 03, ADR-0014), SecMarker, SecRule, SecRuleRemoveById, SecRuleRemoveByTag, SecRuleRemoveByMsg (Extended), SecRuleUpdateActionById, SecRuleUpdateTargetById, SecRuleUpdateTargetByTag, SecRuleUpdateTargetByMsg (Extended). Tests: Task 4 already covers removal/update/marker/default action; add `tests/engine/directives/seccomponentsignature.yaml` (loads; rule fires), `secaction.yaml` (SecAction with setvar then SecRule reads it), `secruleupdatetargetbytag.yaml` (tag-based target removal), `secruleremovebyid-range.yaml` (range removes 4070–4080 style). Each Core section's `**Tests.**` line lists its files. Validator GREEN, commit `spec: rule-building directives`.

- [ ] **Step 5b: Request/response body and argument directives** — SecArgumentSeparator, SecArgumentsLimit, SecRequestBodyAccess, SecRequestBodyLimit, SecRequestBodyNoFilesLimit, SecRequestBodyInMemoryLimit, SecRequestBodyLimitAction, SecRequestBodyJsonDepthLimit, SecResponseBodyAccess, SecResponseBodyLimit, SecResponseBodyLimitAction, SecResponseBodyMimeType, SecResponseBodyMimeTypesClear, SecResponseBodyJsonDepthLimit (Engine-specific). Tests (each one profile; ids 5100+):
  - `secrequestbodyaccess.yaml`: `On` + phase 2 rule on `ARGS_POST:p` fires for urlencoded POST; second profile `secrequestbodyaccess-off.yaml`: `Off` → rule does not fire.
  - `secrequestbodylimit-reject.yaml`: `SecRequestBodyLimit 10`, `SecRequestBodyLimitAction Reject`, POST 20-byte body → interruption with status 413 (v2/v3/Coraza all use 413 — verify Coraza `types.BodyLimitActionReject` status in `internal/corazawaf/transaction.go`; if any engine differs, assert `interruption.action: deny` without `status`).
  - `secrequestbodylimit-processpartial.yaml`: `ProcessPartial`, rule `SecRule INBOUND_DATA_ERROR "@eq 1" "id:5103,phase:2,pass"` fires; no_interruption.
  - `secargumentslimit.yaml`: `SecArgumentsLimit 2`, rule `SecRule &ARGS_GET "@eq 2" "id:5104,phase:1,pass"` fires on `/?a=1&b=2&c=3`.
  - `secargumentseparator.yaml`: `SecArgumentSeparator ;`, rule on `ARGS_GET:b` fires for `/?a=1;b=2`. (Fails on Coraza today: Core gap, say so in Divergence notes.)
  - `secresponsebodyaccess.yaml`: `On` + `SecResponseBodyMimeType text/plain` + phase 4 rule `RESPONSE_BODY "@contains leak"` fires with response `text/plain` body `leak`; `secresponsebodymimetype.yaml`: same rules but response `Content-Type: application/octet-stream` → rule does not fire; `secresponsebodymimetypesclear.yaml`: `SecResponseBodyMimeTypesClear` then `SecResponseBodyMimeType application/json` → fires only for JSON.
  - `secresponsebodylimit-processpartial.yaml`: `SecResponseBodyLimit 5`, `ProcessPartial`, rule `OUTBOUND_DATA_ERROR "@eq 1" "id:5109,phase:4,pass"` fires.
  - `secrequestbodyjsondepthlimit.yaml`: `SecRequestBodyJsonDepthLimit 2`, `ctl:requestBodyProcessor=JSON` in a phase 1 rule, POST `{"a":{"b":{"c":1}}}` → rule `REQBODY_ERROR "@eq 1" "id:5110,phase:2,pass"` fires.
  - `SecRequestBodyLimit 0` is **not** tested (Review Focus 5); write the divergence note.
  Validator GREEN, commit `spec: body and argument directives`.

- [ ] **Step 5c: Logging, storage and remaining directives** — all remaining names from the status table. Core ones (SecAuditEngine, SecAuditLog, SecAuditLogFormat, SecAuditLogParts, SecAuditLogRelevantStatus, SecAuditLogStorageDir, SecAuditLogType, SecDataDir, SecDebugLog, SecDebugLogLevel, SecUploadDir, SecUploadFileMode, SecUploadKeepFiles) get a `loads` test: one profile `tests/engine/directives/logging-directives-load.yaml` whose `rules` sets every one of them to a valid value (`SecAuditEngine RelevantOnly`, `SecAuditLog /dev/null`, `SecAuditLogFormat JSON`, `SecAuditLogParts ABIJDEFHZ`, `SecAuditLogRelevantStatus "^(?:5|4(?!04))"`, `SecAuditLogStorageDir /tmp`, `SecAuditLogType Serial`, `SecDataDir /tmp`, `SecDebugLog /dev/null`, `SecDebugLogLevel 0`, `SecUploadDir /tmp`, `SecUploadFileMode 0600`, `SecUploadKeepFiles Off`) plus one rule that fires; each section's `**Tests.**` points at it. Plus `secauditlogparts-invalid.yaml` (`SecAuditLogParts XYZ` → `expect_error: true`; verify all three reject unknown letters — v3 scanner `CONFIG_VALUE_PARTS`, Coraza `types.ParseAuditLogParts`, v2 `cmd_audit_log_parts`; if one accepts silently, downgrade to a divergence note and drop the test). Extended/Deprecated/Engine-specific sections: Syntax, Status, two-sentence Semantics, "Implemented by:" line. Then `git stash pop` the matrix statuses from Task 1, run `uv run python tools/matrix.py`, validator GREEN (this is where `check_matrix_status` must come out clean), commit `spec: all remaining directives with statuses; matrix status column populated`.

---

### Task 6: ADRs 0004, 0005, 0006, 0013, 0014 (and 0015 if Task 4 found it)

**Files:**
- Create: `adr/0004-canonical-names-and-aliases.md`, `adr/0005-unknown-and-unsupported-directives.md`, `adr/0006-core-ctl-options.md`, `adr/0013-comment-line-continuation.md`, `adr/0014-secdefaultaction-constraints.md`
- Modify: `adr/README.md` index; `spec/01-lexical.md`, `spec/03-processing-model.md` divergence notes to link the ADR numbers.

**Content (header fields: Status proposed, Date 2026-10-06, Deciders @fzipi):**

**ADR-0004 (Divergence): Canonical names and required aliases.** Context: v2 registers `normalisePath`/`normalizePath` (+Win), `pmf`/`pmFromFile`, `ipmatchf`/`ipmatchFromFile`, `sanitise*`/`sanitize*` (`re_tfns.c`, `re_operators.c`, `re_actions.c`); v3 scanner accepts `normalisePath|normalizePath`, `@ipMatchF|@ipMatchFromFile`, `@pmf|@pmFromFile`, and `Parallel|Concurrent` for `SecAuditLogType`; Coraza registers `normalisePath`/`normalizePath` (+Win), `pmf`/`pmFromFile`, `ipMatchF`/`ipMatchFromFile` (its ADR-0026/0027). Decision: canonical names are `normalisePath`, `normalisePathWin`, `pmFromFile`, `ipMatchFromFile`, `Concurrent`; engines MUST accept the aliases `normalizePath`, `normalizePathWin`, `pmf`, `ipMatchF`; `sanitise*`/`sanitize*` are Deprecated (v2 only); `Parallel` is Engine-specific (v3). No new aliases may be introduced without an ADR. Tests: `tests/engine/grammar/name-aliases.yaml` — rules using `t:normalizePath`, `@pmf`, `@ipMatchF` with `files:` for the two list files; assert the rules fire. (Create the test in this task; anchor `02-grammar.md#operator`.)

**ADR-0005 (Divergence): Unknown versus unsupported directives.** Context: v2 — Apache fails to start on an unknown directive; v3 — parser error, configuration fails to load; Coraza — `parser.go:183` `unknown directive` error, but seven known names are mapped to `directiveUnsupported` which silently returns nil (`SecArgumentSeparator`, `SecCookieFormat`, `SecRuleUpdateTargetByMsg`, `SecRuleScript`, `SecRulePerfTime`, `SecTmpDir`, `secunicodemap`), and `SecRemoteRules` returns an error; `SecIgnoreRuleCompilationErrors On` makes rule compilation errors non-fatal but does not affect unknown directives. Decision: (1) a directive name not defined in this specification MUST be a configuration error; (2) a directive that is Deprecated or Extended-and-not-implemented MUST be accepted and MAY be ignored, and the engine SHOULD log a warning naming the directive; (3) an Engine-specific directive of another engine MUST be a configuration error unless the engine documents otherwise (names are reserved, not portable); (4) a Core directive MUST be implemented, so silent acceptance of a Core directive is non-conforming (today: Coraza `SecArgumentSeparator`). Tests: `tests/engine/directives/unknown-directive.yaml` (`SecFrobnicate On` → `expect_error: true`); `tests/engine/directives/deprecated-directive-accepted.yaml` (`SecGuardianLog /dev/null` + a rule that fires → loads).

**ADR-0006 (Divergence): Core `ctl:` options.** Context: 20 options in the union, 10 in all three; CRS v4 uses `requestBodyProcessor`, `ruleRemoveByTag`, `ruleRemoveById`, `forceRequestBodyVariable`, `auditEngine`, `ruleRemoveTargetByTag`; user exclusions documented by CRS use `ruleRemoveTargetById`, `ruleEngine`. v3 lacks `requestBodyLimit`, `responseBodyAccess`, `responseBodyLimit`, `ruleRemoveByMsg`, `ruleRemoveTargetByMsg`, `debugLogLevel`, `hashEngine`, `hashEnforcement`; Coraza lacks `parseXmlIntoArgs`; only Coraza has `responseBodyProcessor`. Decision: Core = `auditEngine`, `auditLogParts`, `forceRequestBodyVariable`, `requestBodyAccess`, `requestBodyProcessor`, `ruleEngine`, `ruleRemoveById`, `ruleRemoveByTag`, `ruleRemoveTargetById`, `ruleRemoveTargetByTag`; Extended = `requestBodyLimit`, `responseBodyAccess`, `responseBodyLimit`, `ruleRemoveByMsg`, `ruleRemoveTargetByMsg`, `debugLogLevel`, `parseXmlIntoArgs`; Deprecated = `hashEngine`, `hashEnforcement`; Engine-specific = `responseBodyProcessor`. The full `ctl:` specification lands with actions in Phase 3; this ADR fixes the status list. Tests: `tests/engine/processing/ctl-timing.yaml` (Task 4) exercises `ruleRemoveById` and `ruleEngine`; add `tests/engine/processing/ctl-core-options-load.yaml` with one rule per Core option in a valid form (loads and fires).

**ADR-0013 (Divergence): Comment lines ending in a backslash.** Context and decision as in Task 2. Tests: `tests/engine/lexical/comment-with-trailing-backslash.yaml`.

**ADR-0014 (Divergence): `SecDefaultAction` constraints.** Context: v2 `cmd_default_action` and v3 `seclang-parser.yy:1234-1254` reject a `SecDefaultAction` without a disruptive action or without a phase, reject `t:none`, reject a second `SecDefaultAction` for the same phase in one context; Coraza performs none of these checks and applies a built-in `phase:2,log,auditlog,pass`. Decision: a `SecDefaultAction` MUST name exactly one disruptive action and a phase, MUST NOT contain `chain`, `id`, `skip`, `skipAfter` or `t:none`; violating configurations MUST fail to load; a second `SecDefaultAction` for the same phase replaces the first (v3 errors; v2 errors — **verify** `cmd_default_action` lines 37-67 and state the stricter rule if both error). Tests: `default-action-no-phase.yaml`, `default-action-no-disruptive.yaml`.

- [ ] **Step 1: Write the ADR files and index rows; create the three test profiles named above; link ADR numbers from the spec divergence notes**
- [ ] **Step 2: Validator GREEN and commit**

```bash
uv run python tools/validate.py   # 0 error(s)
git add adr spec tests
git commit -m "adr: aliases, unknown directives, Core ctl options, comment continuation, SecDefaultAction constraints

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01MdECTJovik6Z6EQq73oD1Z"
```

---

## Self-review notes

- **Spec coverage:** design 4.3 grammar → Tasks 2–3; 4.1 files 01–04 → Tasks 2–5; 4.5 ADRs 0004–0006 → Task 6 (plus 0013/0014 found in research); 4.7 matrix invariant → Task 1. Variables, operators, transformations, actions remain Phase 3.
- **Review Focus mapping:** 1 → Task 2 `crlf-line-endings.yaml`; 2 → Task 4 `rule-exceptions-bad-range.yaml`; 3 → Task 4 `rule-exceptions.yaml` (id 999999 line); 4 → Task 4 `skipafter-later-phase.yaml`; 5 → Task 5b divergence note, deliberately untested.
- **Type consistency:** anchors used by tests match the `###` headings listed per task after slugging (`Lines and directives` → `lines-and-directives`, `ctl timing` → `ctl-timing`, `Default actions` → `default-actions`).
- **Open judgment calls for the reviewer:** the status table in Task 5; `SecArgumentSeparator` as Core; relative `Include` path base left unspecified.
