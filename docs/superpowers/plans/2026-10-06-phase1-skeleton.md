# SecLang Spec Phase 1 (Skeleton) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the seclang-spec repository skeleton: conventions, ADR process with ADR 0001–0003, both test-file schemas with one worked example each, the compatibility matrix as data plus generated markdown, and a validator that CI runs.

**Architecture:** A documentation repo with one small Python tool. `tools/validate.py` enforces four invariants (test files match their schema, every Core feature has a test and no test points at a missing spec anchor, ADR files and index agree, `compat/matrix.md` is regenerated from `compat/matrix.json`). Spec feature headings carry a `**Status:**` line; tests carry a `spec:` anchor; those two conventions tie the whole repo together.

**Tech Stack:** Markdown, JSON Schema 2020-12, YAML. Python 3.11+ with two dev-only packages, `pyyaml` and `jsonschema`. `unittest` from the stdlib for the tool's own tests. GitHub Actions for CI.

**Spec:** `docs/superpowers/specs/2026-10-06-seclang-spec-design.md` (Sections 4.1, 4.2, 4.4, 4.5, 4.7, Appendix A)

## Global Constraints

- Python stdlib only, plus exactly `pyyaml` and `jsonschema` as dev dependencies (design 4.1; decided in ADR-0003).
- No test runner lives in this repo; only data, schemas and the validator (design 1, 4.4).
- Status vocabulary is exactly `Core`, `Extended`, `Deprecated`, `Engine-specific` (design 4.2).
- ADR categories are exactly `Divergence`, `Clarification`, `Deprecation`, `Extension`; every Divergence ADR names at least one test file (design 4.5).
- Unit-tier files keep the SecRules Test Set shape: `type`, `name`, `param`, `input`, `output`, `ret` (design 4.4).
- Engine-tier files keep the go-ftw / Coraza profile nesting: `tests[].stages[].stage.{input,output}` (design 4.4).
- Spec anchors are GitHub heading slugs: lowercase, drop every character that is not a letter, digit, space or hyphen, then spaces become hyphens.
- Commit messages end with the two attribution lines given in the session reminder.

## Review Focus

1. A YAML engine test that is a list at top level (someone pastes several go-ftw profiles into one file). Expected: validator reports a schema error naming the file, not a Python traceback. Test added to Task 3.
2. A `spec:` anchor whose file exists but whose heading has no `**Status:**` line. Expected: reported as dangling, since only status-bearing headings are features. Test added to Task 4.
3. Two spec files defining the same heading text (e.g. `### rx` under operators and under lexical). Expected: anchors are file-qualified so no collision; validator must not merge them. Test added to Task 4.
4. An ADR whose filename number and `# ADR-NNNN` title number disagree. Expected: error naming both numbers. Test added to Task 5.
5. `matrix.json` edited by hand with a row missing an engine key. Expected: `matrix.py` raises a clear `KeyError` message naming the row, and `validate.py` reports it instead of crashing. Test added to Task 1.

---

### Task 1: Compatibility matrix as data plus generated markdown

**Files:**
- Create: `compat/matrix.json` (restructured from `docs/superpowers/specs/2026-10-06-compat-matrix.json`)
- Create: `tools/matrix.py`
- Create: `tools/__init__.py` (empty, so `python -m unittest discover tools` imports work)
- Create: `tools/test_matrix.py`
- Create: `compat/matrix.md` (generated)
- Delete: `docs/superpowers/specs/2026-10-06-compat-matrix.json`

**Interfaces:**
- Produces: `tools.matrix.ENGINES = ("v2", "v3", "coraza")`, `tools.matrix.render(matrix: dict) -> str`, `tools.matrix.load(root: Path) -> dict`, `tools.matrix.main() -> None`. Matrix JSON shape: `{"generated": "YYYY-MM-DD", "engines": {"v2": str, "v3": str, "coraza": str}, "categories": {name: [{"name": str, "v2": bool, "v3": bool, "coraza": bool}, ...]}}`.

- [ ] **Step 1: Write the failing tests**

```python
# tools/test_matrix.py
import json
import tempfile
import unittest
from pathlib import Path

from tools import matrix

SAMPLE = {
    "generated": "2026-10-06",
    "engines": {"v2": "ModSecurity v2", "v3": "libmodsecurity v3", "coraza": "Coraza"},
    "categories": {
        "operators": [
            {"name": "rx", "v2": True, "v3": True, "coraza": True},
            {"name": "restpath", "v2": False, "v3": False, "coraza": True},
        ]
    },
}


class RenderTests(unittest.TestCase):
    def test_header_and_rows(self):
        md = matrix.render(SAMPLE)
        self.assertIn("## operators (1 of 2 in all engines)", md)
        self.assertIn("| `restpath` | - | - | yes |", md)
        self.assertIn("| `rx` | yes | yes | yes |", md)
        self.assertIn("Do not edit by hand", md)

    def test_rows_sorted_case_insensitively(self):
        md = matrix.render(SAMPLE)
        self.assertLess(md.index("`restpath`"), md.index("`rx`"))

    def test_missing_engine_key_names_row(self):
        broken = json.loads(json.dumps(SAMPLE))
        del broken["categories"]["operators"][1]["coraza"]
        with self.assertRaises(ValueError) as cm:
            matrix.render(broken)
        self.assertIn("restpath", str(cm.exception))
        self.assertIn("coraza", str(cm.exception))

    def test_main_writes_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "compat").mkdir()
            (root / "compat" / "matrix.json").write_text(json.dumps(SAMPLE))
            matrix.main(root)
            self.assertEqual((root / "compat" / "matrix.md").read_text(), matrix.render(SAMPLE))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/fzipitria/Workspace/OWASP/seclang-spec && touch tools/__init__.py && python3 -m unittest tools.test_matrix -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'tools.matrix'`

- [ ] **Step 3: Write the renderer**

```python
# tools/matrix.py
"""Render compat/matrix.md from compat/matrix.json.

Usage: python3 tools/matrix.py
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENGINES = ("v2", "v3", "coraza")


def load(root: Path = ROOT) -> dict:
    return json.loads((root / "compat" / "matrix.json").read_text())


def render(matrix: dict) -> str:
    out = [
        "# Engine compatibility matrix",
        "",
        f"Generated from `compat/matrix.json` by `tools/matrix.py` on {matrix['generated']}. "
        "Do not edit by hand; edit the JSON and rerun the tool.",
        "",
    ]
    for key, label in matrix["engines"].items():
        out.append(f"- **{key}**: {label}")
    for category, rows in matrix["categories"].items():
        for row in rows:
            missing = [e for e in ENGINES if e not in row]
            if missing:
                raise ValueError(f"{category}/{row.get('name', '?')}: missing engine key(s) {missing}")
        in_all = sum(all(row[e] for e in ENGINES) for row in rows)
        out += [
            "",
            f"## {category} ({in_all} of {len(rows)} in all engines)",
            "",
            "| Name | " + " | ".join(ENGINES) + " |",
            "|---|" + "---|" * len(ENGINES),
        ]
        for row in sorted(rows, key=lambda r: r["name"].lower()):
            cells = " | ".join("yes" if row[e] else "-" for e in ENGINES)
            out.append(f"| `{row['name']}` | {cells} |")
    return "\n".join(out) + "\n"


def main(root: Path = ROOT) -> None:
    (root / "compat" / "matrix.md").write_text(render(load(root)))


if __name__ == "__main__":
    main()
    print("wrote compat/matrix.md", file=sys.stderr)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest tools.test_matrix -v`
Expected: 4 tests, `OK`

- [ ] **Step 5: Convert the survey JSON into the new shape**

Run this one-off from the repo root (it is not kept):

```bash
mkdir -p compat && python3 - <<'EOF'
import json
old = json.load(open("docs/superpowers/specs/2026-10-06-compat-matrix.json"))
new = {
  "generated": "2026-10-06",
  "engines": {
    "v2": "ModSecurity v2 (owasp-modsecurity/ModSecurity branch v2/master, 2026-09)",
    "v3": "libmodsecurity v3.0.16 (owasp-modsecurity/ModSecurity branch v3/master)",
    "coraza": "Coraza v3.8.1 (corazawaf/coraza)"
  },
  "categories": {cat: [{"name": n, "v2": a, "v3": b, "coraza": c} for n, a, b, c in rows] for cat, rows in old.items()}
}
json.dump(new, open("compat/matrix.json", "w"), indent=1)
open("compat/matrix.json", "a").write("\n")
EOF
git rm -q docs/superpowers/specs/2026-10-06-compat-matrix.json
python3 tools/matrix.py
grep -c '| `' compat/matrix.md
```
Expected: last command prints `386` (92+48+20+44+38+144 rows).

- [ ] **Step 6: Commit**

```bash
git add compat tools/__init__.py tools/matrix.py tools/test_matrix.py
git commit -m "feat: compatibility matrix as data with generated markdown

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01MdECTJovik6Z6EQq73oD1Z"
```

---

### Task 2: Test-file schemas and worked examples

**Files:**
- Create: `tests/schema/unit.schema.json`
- Create: `tests/schema/engine.schema.json`
- Create: `tests/unit/transformations/base64Decode.json`
- Create: `tests/engine/directives/secruleengine-on.yaml`
- Create: `tests/engine/directives/secruleengine-detectiononly.yaml`
- Create: `tests/engine/directives/secruleengine-off.yaml`
- Create: `tests/engine/lexical/case-insensitive-names.yaml`
- Create: `tests/README.md`
- Create: `requirements-dev.txt`

**Interfaces:**
- Produces: the two schema files, read by Task 3's validator at `tests/schema/{unit,engine}.schema.json`. Spec anchors used by the examples, which Task 4 must define: `07-transformations.md#base64decode`, `04-directives.md#secruleengine`, `01-lexical.md#name-matching`.

- [ ] **Step 1: Install dev dependencies**

```bash
printf 'pyyaml>=6\njsonschema>=4.18\n' > requirements-dev.txt
python3 -m pip install -r requirements-dev.txt
```

- [ ] **Step 2: Write the unit-tier schema**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://github.com/OWASP/seclang-spec/tests/schema/unit.schema.json",
  "title": "SecLang unit-tier test file (operators and transformations)",
  "description": "SecRules Test Set compatible. One file per operator or transformation; an array of cases.",
  "type": "array",
  "minItems": 1,
  "items": {
    "type": "object",
    "additionalProperties": false,
    "required": ["type", "name", "input", "ret"],
    "properties": {
      "type": {"enum": ["op", "tfn"], "description": "op = operator, tfn = transformation"},
      "name": {"type": "string", "minLength": 1, "description": "Canonical operator or transformation name"},
      "param": {"type": "string", "description": "Operator parameter (the text after @name)"},
      "input": {"type": "string", "description": "Value under test; JSON escapes allowed"},
      "output": {"type": "string", "description": "Transformation result"},
      "ret": {"enum": [0, 1], "description": "op: 1 if matched. tfn: 1 if the value changed"},
      "spec": {"type": "string", "pattern": "^[0-9]{2}-[a-z0-9-]+\\.md#[a-z0-9-]+$", "description": "Spec anchor, e.g. 07-transformations.md#base64decode"},
      "status": {"enum": ["Core", "Extended", "Deprecated"]},
      "note": {"type": "string"}
    },
    "allOf": [
      {"if": {"properties": {"type": {"const": "op"}}}, "then": {"required": ["param"]}},
      {"if": {"properties": {"type": {"const": "tfn"}}}, "then": {"required": ["output"]}}
    ]
  }
}
```

- [ ] **Step 3: Write the engine-tier schema**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://github.com/OWASP/seclang-spec/tests/schema/engine.schema.json",
  "title": "SecLang engine-tier test profile",
  "description": "go-ftw / Coraza profile derived. One profile per YAML file: a rule set plus transactions and expected outcomes.",
  "type": "object",
  "additionalProperties": false,
  "required": ["meta", "rules", "tests"],
  "properties": {
    "meta": {
      "type": "object",
      "additionalProperties": false,
      "required": ["name", "description"],
      "properties": {
        "name": {"type": "string", "minLength": 1},
        "description": {"type": "string"},
        "author": {"type": "string"},
        "enabled": {"type": "boolean", "default": true}
      }
    },
    "spec": {"type": "string", "pattern": "^[0-9]{2}-[a-z0-9-]+\\.md#[a-z0-9-]+$"},
    "requires": {
      "type": "array",
      "items": {"type": "string", "pattern": "^[a-z0-9-]+$"},
      "description": "Extended feature ids an engine must implement to run this profile; otherwise it skips the whole file"
    },
    "rules": {"type": "string", "minLength": 1, "description": "SecLang configuration loaded before every test"},
    "tests": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["test_title", "stages"],
        "properties": {
          "test_title": {"type": "string", "minLength": 1},
          "desc": {"type": "string"},
          "spec": {"type": "string", "pattern": "^[0-9]{2}-[a-z0-9-]+\\.md#[a-z0-9-]+$"},
          "stages": {
            "type": "array",
            "minItems": 1,
            "items": {
              "type": "object",
              "additionalProperties": false,
              "required": ["stage"],
              "properties": {
                "stage": {
                  "type": "object",
                  "additionalProperties": false,
                  "required": ["input", "output"],
                  "properties": {
                    "input": {
                      "type": "object",
                      "additionalProperties": false,
                      "properties": {
                        "method": {"type": "string", "default": "GET"},
                        "uri": {"type": "string", "default": "/"},
                        "version": {"type": "string", "default": "HTTP/1.1"},
                        "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                        "data": {"type": "string"},
                        "dest_addr": {"type": "string"},
                        "port": {"type": "integer"}
                      }
                    },
                    "response": {
                      "type": "object",
                      "additionalProperties": false,
                      "description": "Synthetic backend response for phase 3-5 tests",
                      "properties": {
                        "status": {"type": "integer", "default": 200},
                        "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                        "data": {"type": "string"}
                      }
                    },
                    "output": {
                      "type": "object",
                      "additionalProperties": false,
                      "properties": {
                        "triggered_rules": {"type": "array", "items": {"type": "integer"}},
                        "non_triggered_rules": {"type": "array", "items": {"type": "integer"}},
                        "interruption": {
                          "type": "object",
                          "additionalProperties": false,
                          "required": ["rule_id", "action"],
                          "properties": {
                            "rule_id": {"type": "integer"},
                            "action": {"enum": ["deny", "drop", "redirect", "allow"]},
                            "status": {"type": "integer"},
                            "data": {"type": "string"}
                          }
                        },
                        "no_interruption": {"type": "boolean"},
                        "log_contains": {"type": "string"},
                        "no_log_contains": {"type": "string"},
                        "expect_error": {"type": "boolean", "description": "Configuration must fail to load"}
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

- [ ] **Step 4: Write the example unit file**

```json
[
  {"type": "tfn", "name": "base64Decode", "input": "", "output": "", "ret": 0,
   "spec": "07-transformations.md#base64decode"},
  {"type": "tfn", "name": "base64Decode", "input": "VGVzdENhc2U=", "output": "TestCase", "ret": 1,
   "spec": "07-transformations.md#base64decode"},
  {"type": "tfn", "name": "base64Decode", "input": "VGVzdENhc2Ux", "output": "TestCase1", "ret": 1,
   "spec": "07-transformations.md#base64decode"},
  {"type": "tfn", "name": "base64Decode", "input": "VGVzdABDYXNl", "output": "Test\u0000Case", "ret": 1,
   "spec": "07-transformations.md#base64decode",
   "note": "NUL bytes in the decoded value are preserved"},
  {"type": "tfn", "name": "base64Decode", "input": "VGVzdENhc2U=\u0000VGVzdENhc2U=", "output": "TestCase", "ret": 1,
   "spec": "07-transformations.md#base64decode",
   "note": "decoding stops at the first character outside the alphabet"}
]
```

- [ ] **Step 5: Write the three SecRuleEngine profiles**

`tests/engine/directives/secruleengine-on.yaml`:

```yaml
meta:
  name: secruleengine-on
  description: SecRuleEngine On evaluates rules and honours disruptive actions
spec: 04-directives.md#secruleengine
rules: |
  SecRuleEngine On
  SecRule ARGS_GET:attack "@streq 1" "id:1001,phase:1,deny,status:403,log,msg:'engine test'"
tests:
  - test_title: matching request is denied
    stages:
      - stage:
          input:
            uri: /?attack=1
          output:
            triggered_rules: [1001]
            interruption:
              rule_id: 1001
              action: deny
              status: 403
  - test_title: non-matching request passes
    stages:
      - stage:
          input:
            uri: /?attack=0
          output:
            non_triggered_rules: [1001]
            no_interruption: true
```

`tests/engine/directives/secruleengine-detectiononly.yaml`:

```yaml
meta:
  name: secruleengine-detectiononly
  description: SecRuleEngine DetectionOnly evaluates and logs but never interrupts
spec: 04-directives.md#secruleengine
rules: |
  SecRuleEngine DetectionOnly
  SecRule ARGS_GET:attack "@streq 1" "id:1001,phase:1,deny,status:403,log,msg:'engine test'"
tests:
  - test_title: matching request is logged, not denied
    stages:
      - stage:
          input:
            uri: /?attack=1
          output:
            triggered_rules: [1001]
            no_interruption: true
```

`tests/engine/directives/secruleengine-off.yaml`:

```yaml
meta:
  name: secruleengine-off
  description: SecRuleEngine Off does not evaluate rules at all
spec: 04-directives.md#secruleengine
rules: |
  SecRuleEngine Off
  SecRule ARGS_GET:attack "@streq 1" "id:1001,phase:1,deny,status:403,log,msg:'engine test'"
tests:
  - test_title: matching request is neither logged nor denied
    stages:
      - stage:
          input:
            uri: /?attack=1
          output:
            non_triggered_rules: [1001]
            no_interruption: true
```

- [ ] **Step 6: Write the ADR-0002 profile**

`tests/engine/lexical/case-insensitive-names.yaml`:

```yaml
meta:
  name: case-insensitive-names
  description: Directive, operator, action and transformation names match case-insensitively (ADR-0002)
spec: 01-lexical.md#name-matching
rules: |
  SECRULEENGINE On
  secrule ARGS_GET:a "@CONTAINS x" "ID:1002,PHASE:1,T:LOWERCASE,DENY,STATUS:403,LOG"
tests:
  - test_title: mixed-case names load and the rule fires
    stages:
      - stage:
          input:
            uri: /?a=X
          output:
            triggered_rules: [1002]
            interruption:
              rule_id: 1002
              action: deny
              status: 403
```

- [ ] **Step 7: Check every example against its schema by hand**

```bash
python3 - <<'EOF'
import json, yaml, pathlib, jsonschema
u = json.load(open("tests/schema/unit.schema.json")); e = json.load(open("tests/schema/engine.schema.json"))
for p in pathlib.Path("tests/unit").rglob("*.json"): jsonschema.validate(json.load(open(p)), u); print("ok", p)
for p in pathlib.Path("tests/engine").rglob("*.yaml"): jsonschema.validate(yaml.safe_load(open(p)), e); print("ok", p)
EOF
```
Expected: five `ok` lines, no exception.

- [ ] **Step 8: Write `tests/README.md`**

```markdown
# Conformance tests

This directory holds **data only**. There is no runner here: each engine writes a
small adapter that loads these files and asserts the expectations with its own test
framework. The schemas in `schema/` are the contract.

## Tiers

| Tier   | Path             | Format | Schema                      | Reused from |
|--------|------------------|--------|-----------------------------|-------------|
| unit   | `unit/**/*.json` | JSON   | `schema/unit.schema.json`   | SecRules Test Set (`secrules-language-tests`) |
| engine | `engine/**/*.yaml` | YAML | `schema/engine.schema.json` | go-ftw YAML / Coraza `testing/profile` |

**Unit** cases exercise one operator or transformation in isolation. `ret` is 1 when an
operator matches, or when a transformation changed its input. `input`/`output` are JSON
strings, so `\u0000` and other escapes are legal.

**Engine** profiles load `rules`, then run each stage's `input` as a transaction. When a
stage has a `response`, the adapter must feed it as the backend response so phases 3–5
run. `output` asserts on rule IDs and interruption only; log wording is never asserted
beyond `log_contains`/`no_log_contains` substrings.

## Fields that link tests to the spec

- `spec: NN-file.md#anchor` points at the heading in `spec/` the case verifies. The
  validator fails if the anchor does not exist or has no `**Status:**` line.
- `requires: [feature-id, ...]` (engine tier) lists Extended features the profile needs.
  An engine that does not implement one of them must **skip** the file, not fail it.

## Adding a case

1. Pick the tier and copy an existing file.
2. Set `spec` to the heading you are testing. If the heading does not exist yet, add it
   to `spec/` with a status line first.
3. Run `python3 tools/validate.py` from the repo root.
```

- [ ] **Step 9: Commit**

```bash
git add tests requirements-dev.txt
git commit -m "feat: unit and engine test schemas with worked examples

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01MdECTJovik6Z6EQq73oD1Z"
```

---

### Task 3: Validator, part 1: schema check and CLI

**Files:**
- Create: `tools/validate.py`
- Create: `tools/test_validate.py`

**Interfaces:**
- Consumes: `tests/schema/*.json` from Task 2.
- Produces: `tools.validate.check_tests(root: Path) -> list[str]`, `tools.validate.load_test_files(root) -> Iterator[tuple[Path, object]]`, `tools.validate.main(root: Path = ROOT) -> int` (0 ok, 1 errors). Tasks 4–6 append `check_*` functions to `CHECKS`.
- Test fixture helper `make_repo(tmp: Path) -> Path` in `tools/test_validate.py` copies the real `tests/schema/` into a temp repo and creates empty `tests/unit`, `tests/engine`, `spec`, `adr`, `compat` directories. Later tasks extend this helper.

- [ ] **Step 1: Write the failing tests**

```python
# tools/test_validate.py
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from tools import validate

REAL_ROOT = Path(__file__).resolve().parent.parent

GOOD_UNIT = [{"type": "tfn", "name": "lowercase", "input": "A", "output": "a", "ret": 1,
              "spec": "07-transformations.md#lowercase"}]

GOOD_ENGINE = """\
meta:
  name: sample
  description: sample profile
spec: 04-directives.md#secruleengine
rules: |
  SecRuleEngine On
tests:
  - test_title: t
    stages:
      - stage:
          input:
            uri: /
          output:
            no_interruption: true
"""


def make_repo(tmp: Path) -> Path:
    for d in ("tests/unit", "tests/engine", "spec", "adr", "compat"):
        (tmp / d).mkdir(parents=True)
    shutil.copytree(REAL_ROOT / "tests" / "schema", tmp / "tests" / "schema")
    return tmp


class SchemaCheckTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_repo(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    def test_valid_files_produce_no_errors(self):
        (self.root / "tests/unit/t.json").write_text(json.dumps(GOOD_UNIT))
        (self.root / "tests/engine/e.yaml").write_text(GOOD_ENGINE)
        self.assertEqual(validate.check_tests(self.root), [])

    def test_unit_schema_violation_is_reported_with_path(self):
        bad = [{"type": "op", "name": "rx", "input": "x", "ret": 1}]  # op without param
        (self.root / "tests/unit/bad.json").write_text(json.dumps(bad))
        errors = validate.check_tests(self.root)
        self.assertEqual(len(errors), 1)
        self.assertIn("tests/unit/bad.json", errors[0])
        self.assertIn("param", errors[0])

    def test_engine_unknown_field_is_reported(self):
        (self.root / "tests/engine/e.yaml").write_text(GOOD_ENGINE.replace("no_interruption", "no_interuption"))
        errors = validate.check_tests(self.root)
        self.assertEqual(len(errors), 1)
        self.assertIn("no_interuption", errors[0])

    def test_engine_file_that_is_a_list_is_a_schema_error_not_a_crash(self):
        (self.root / "tests/engine/list.yaml").write_text("- a\n- b\n")
        errors = validate.check_tests(self.root)
        self.assertEqual(len(errors), 1)
        self.assertIn("tests/engine/list.yaml", errors[0])

    def test_unparseable_yaml_is_reported(self):
        (self.root / "tests/engine/broken.yaml").write_text("meta: [unclosed\n")
        errors = validate.check_tests(self.root)
        self.assertEqual(len(errors), 1)
        self.assertIn("broken.yaml", errors[0])

    def test_main_returns_1_on_errors_and_0_otherwise(self):
        self.assertEqual(validate.main(self.root, checks=[validate.check_tests]), 0)
        (self.root / "tests/unit/bad.json").write_text("[]")
        self.assertEqual(validate.main(self.root, checks=[validate.check_tests]), 1)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest tools.test_validate -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'tools.validate'`

- [ ] **Step 3: Write the validator**

```python
#!/usr/bin/env python3
"""Validate seclang-spec repository invariants.

Usage: python3 tools/validate.py        (exit 1 if anything is wrong)

Checks: test files match their schema; every Core spec feature has a test and no test
points at a missing anchor; ADR files and index agree; compat/matrix.md is current.
"""
import json
import sys
from pathlib import Path
from typing import Callable, Iterator

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parent.parent


def _rel(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def load_test_files(root: Path) -> Iterator[tuple[Path, object]]:
    """Yield (path, parsed) for every test file. Parse failures yield (path, exception)."""
    for path in sorted((root / "tests" / "unit").rglob("*.json")):
        try:
            yield path, json.loads(path.read_text())
        except ValueError as exc:
            yield path, exc
    for path in sorted((root / "tests" / "engine").rglob("*.yaml")):
        try:
            yield path, yaml.safe_load(path.read_text())
        except yaml.YAMLError as exc:
            yield path, exc


def check_tests(root: Path) -> list[str]:
    schemas = {
        tier: jsonschema.Draft202012Validator(json.loads((root / "tests" / "schema" / f"{tier}.schema.json").read_text()))
        for tier in ("unit", "engine")
    }
    errors = []
    for path, data in load_test_files(root):
        rel = _rel(root, path)
        if isinstance(data, Exception):
            errors.append(f"{rel}: cannot parse: {data}")
            continue
        tier = path.relative_to(root / "tests").parts[0]
        for err in sorted(schemas[tier].iter_errors(data), key=lambda e: list(map(str, e.absolute_path))):
            where = "/".join(map(str, err.absolute_path)) or "<root>"
            errors.append(f"{rel}: {where}: {err.message}")
    return errors


CHECKS: list[Callable[[Path], list[str]]] = [check_tests]


def main(root: Path = ROOT, checks: list[Callable[[Path], list[str]]] | None = None) -> int:
    errors = [e for check in (checks or CHECKS) for e in check(root)]
    for e in errors:
        print(e, file=sys.stderr)
    print(f"{len(errors)} error(s)", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest tools.test_validate -v`
Expected: 6 tests, `OK`

- [ ] **Step 5: Run the validator on the real repo**

Run: `python3 tools/validate.py`
Expected: `0 error(s)`, exit 0

- [ ] **Step 6: Commit**

```bash
git add tools/validate.py tools/test_validate.py
git commit -m "feat: validator checks test files against their schemas

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01MdECTJovik6Z6EQq73oD1Z"
```

---

### Task 4: Conventions, first spec features, and the coverage check

**Files:**
- Create: `spec/00-conventions.md`
- Create: `spec/01-lexical.md`
- Create: `spec/04-directives.md`
- Create: `spec/07-transformations.md`
- Modify: `tools/validate.py` (add `slug`, `spec_features`, `test_spec_refs`, `check_coverage`; register in `CHECKS`)
- Modify: `tools/test_validate.py` (add `CoverageTests`)

**Interfaces:**
- Produces: `validate.slug(heading: str) -> str`; `validate.spec_features(root) -> dict[str, str]` mapping `"04-directives.md#secruleengine"` to its status; `validate.test_spec_refs(root) -> dict[str, list[str]]` mapping anchor to the test files referencing it; `validate.check_coverage(root) -> list[str]`.
- Feature convention consumed by every later spec task: a `###` heading immediately followed (after optional blank lines) by a line `**Status:** Core|Extended|Deprecated|Engine-specific`.

- [ ] **Step 1: Write the failing tests**

Append to `tools/test_validate.py`:

```python
SPEC_FEATURE = """\
# Transformations

### lowercase

**Status:** Core

Lowercases ASCII letters.

### uppercase

**Status:** Extended

### `rx`

**Status:** Core
"""


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_repo(Path(self._tmp.name))
        (self.root / "spec/07-transformations.md").write_text(SPEC_FEATURE)
        (self.root / "spec/04-directives.md").write_text("# Directives\n\n### SecRuleEngine\n\n**Status:** Core\n")
        (self.root / "tests/unit/t.json").write_text(json.dumps(GOOD_UNIT))
        (self.root / "tests/engine/e.yaml").write_text(GOOD_ENGINE)

    def tearDown(self):
        self._tmp.cleanup()

    def test_slug_matches_github(self):
        self.assertEqual(validate.slug("SecRuleEngine"), "secruleengine")
        self.assertEqual(validate.slug("Name matching"), "name-matching")
        self.assertEqual(validate.slug("`rx`"), "rx")
        self.assertEqual(validate.slug("ctl: ruleRemoveById"), "ctl-ruleremovebyid")

    def test_spec_features_are_file_qualified_with_status(self):
        feats = validate.spec_features(self.root)
        self.assertEqual(feats["07-transformations.md#lowercase"], "Core")
        self.assertEqual(feats["07-transformations.md#uppercase"], "Extended")
        self.assertEqual(feats["07-transformations.md#rx"], "Core")
        self.assertEqual(feats["04-directives.md#secruleengine"], "Core")
        self.assertNotIn("07-transformations.md#transformations", feats)  # no status line

    def test_same_heading_in_two_files_does_not_collide(self):
        (self.root / "spec/06-operators.md").write_text("# Operators\n\n### `rx`\n\n**Status:** Core\n")
        feats = validate.spec_features(self.root)
        self.assertIn("06-operators.md#rx", feats)
        self.assertIn("07-transformations.md#rx", feats)

    def test_core_feature_without_test_is_reported(self):
        errors = validate.check_coverage(self.root)
        self.assertTrue(any("07-transformations.md#rx" in e and "no test" in e for e in errors))
        self.assertFalse(any("uppercase" in e for e in errors))  # Extended is not required

    def test_dangling_ref_is_reported(self):
        bad = [dict(GOOD_UNIT[0], spec="07-transformations.md#nope")]
        (self.root / "tests/unit/bad.json").write_text(json.dumps(bad))
        errors = validate.check_coverage(self.root)
        self.assertTrue(any("tests/unit/bad.json" in e and "#nope" in e for e in errors))

    def test_ref_to_heading_without_status_is_dangling(self):
        bad = [dict(GOOD_UNIT[0], spec="07-transformations.md#transformations")]
        (self.root / "tests/unit/bad.json").write_text(json.dumps(bad))
        errors = validate.check_coverage(self.root)
        self.assertTrue(any("#transformations" in e for e in errors))

    def test_fully_covered_repo_has_no_errors(self):
        (self.root / "spec/07-transformations.md").write_text(SPEC_FEATURE.replace("### `rx`\n\n**Status:** Core\n", ""))
        self.assertEqual(validate.check_coverage(self.root), [])
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest tools.test_validate.CoverageTests -v`
Expected: FAIL with `AttributeError: module 'tools.validate' has no attribute 'slug'`

- [ ] **Step 3: Implement the coverage check**

Insert into `tools/validate.py` after `check_tests` and before `CHECKS`:

```python
import re  # move to the import block at the top

HEADING_RE = re.compile(r"^#{2,4}\s+(.+?)\s*$")
STATUS_RE = re.compile(r"^\*\*Status:\*\*\s+(Core|Extended|Deprecated|Engine-specific)\s*$")


def slug(heading: str) -> str:
    """GitHub-style heading anchor."""
    cleaned = re.sub(r"[^a-z0-9 -]", "", heading.lower())
    return cleaned.strip().replace(" ", "-")


def spec_features(root: Path) -> dict[str, str]:
    """Map 'NN-file.md#anchor' -> status for every heading followed by a **Status:** line."""
    features = {}
    for path in sorted((root / "spec").glob("*.md")):
        heading = None
        for line in path.read_text().splitlines():
            if m := HEADING_RE.match(line):
                heading = slug(m.group(1))
            elif (m := STATUS_RE.match(line)) and heading:
                features[f"{path.name}#{heading}"] = m.group(1)
                heading = None
            elif line.strip():
                heading = None  # status must directly follow its heading
    return features


def test_spec_refs(root: Path) -> dict[str, list[str]]:
    """Map spec anchor -> test files that reference it."""
    refs: dict[str, list[str]] = {}
    for path, data in load_test_files(root):
        if isinstance(data, Exception):
            continue
        rel = _rel(root, path)
        found = []
        if isinstance(data, list):
            found = [c.get("spec") for c in data if isinstance(c, dict)]
        elif isinstance(data, dict):
            found = [data.get("spec")] + [t.get("spec") for t in data.get("tests", []) if isinstance(t, dict)]
        for ref in found:
            if ref:
                refs.setdefault(ref, []).append(rel)
    return refs


def check_coverage(root: Path) -> list[str]:
    features = spec_features(root)
    refs = test_spec_refs(root)
    errors = []
    for ref, files in sorted(refs.items()):
        if ref not in features:
            for f in sorted(set(files)):
                errors.append(f"{f}: spec anchor {ref} does not exist or has no **Status:** line")
    for anchor, status in sorted(features.items()):
        if status == "Core" and anchor not in refs:
            errors.append(f"spec/{anchor}: Core feature has no test")
    return errors
```

Then change the registry line to:

```python
CHECKS: list[Callable[[Path], list[str]]] = [check_tests, check_coverage]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest tools.test_validate -v`
Expected: 13 tests, `OK`

- [ ] **Step 5: Write `spec/00-conventions.md`**

```markdown
# 00. Conventions

This specification describes SecLang, the rule language shared by ModSecurity v2,
libmodsecurity v3, Coraza and any future engine. It standardizes what the engines
already agree on and, where they diverge, records a decision as an ADR in `adr/`.

## Requirement words

"MUST", "MUST NOT", "SHOULD", "SHOULD NOT" and "MAY" are used as defined in RFC 2119
and RFC 8174, and carry that meaning only when written in capitals.

## Feature status

Every directive, variable, operator, transformation, action and `ctl:` option in this
specification is a *feature* and carries exactly one status, written on the line
directly after its heading as `**Status:** <value>`:

| Status            | Meaning for an implementing engine |
|-------------------|------------------------------------|
| `Core`            | MUST be implemented as specified. Conformance requires every Core feature. Every Core feature has at least one test in `tests/`. |
| `Extended`        | SHOULD be implemented. Fully specified. An engine declares which Extended features it supports; tests for them carry `requires:` so other engines skip them. |
| `Deprecated`      | MUST be accepted by the parser. MAY be ignored with a warning. MUST NOT be used in new rulesets. |
| `Engine-specific` | Listed so the name is reserved. Not specified here; another engine MUST NOT give the name different semantics. |

The initial Core set is the intersection of the three surveyed engines, restricted to
features used by OWASP CRS v4 or by the engines' recommended configuration files.
Promoting a feature to Core needs an ADR (see ADR-0001).

## Spec versioning

The specification is versioned `vMAJOR.MINOR`. Adding features, or moving a feature
between `Extended`, `Deprecated` and `Engine-specific`, is a MINOR change. Changing the
semantics of a Core feature, or promoting to or demoting from Core, is MAJOR and
requires an ADR.

## Conformance statement

An engine conforms to `seclang-spec vX.Y` when it passes every test under `tests/` that
is not skipped by a `requires:` clause for an Extended feature it does not declare.
Core tests can never be skipped.

## Reading this document

Each feature section is organized as: **Syntax**, **Default** (where applicable),
**Scope** (where a directive may appear), **Semantics**, **Divergence notes** (links to
ADRs), **Tests** (paths under `tests/`).

## Source anchors

Tests reference features by `NN-file.md#anchor`, where `anchor` is the GitHub heading
slug: lowercase the heading, drop every character that is not a letter, digit, space or
hyphen, then replace spaces with hyphens. `tools/validate.py` enforces that every
reference resolves and every Core feature is referenced.
```

- [ ] **Step 6: Write `spec/01-lexical.md` with the one section ADR-0002 needs**

```markdown
# 01. Lexical structure

This file will grow to cover lines, continuation, quoting, comments and `Include`
(design Section 4.3). Phase 1 defines only the section ADR-0002 depends on.

### Name matching

**Status:** Core

**Syntax.** Directive names (`SecRule`), operator names (`@contains`), action names
(`deny`, `t:`), transformation names (`lowercase`) and `ctl:` option names
(`ruleEngine`) are identifiers made of ASCII letters and digits.

**Semantics.** Engines MUST match all of these identifiers case-insensitively.
`secrule`, `SecRule` and `SECRULE` denote the same directive; `@CONTAINS` and
`@contains` the same operator; `T:LOWERCASE` and `t:lowercase` the same
transformation. The canonical spelling used in this specification is the mixed-case
form from the ModSecurity reference manual; engines SHOULD emit that spelling in logs
and error messages.

Variable and collection names (`ARGS`, `TX`) and collection keys are **not** covered by
this section; their case rules are defined with the variables (ADR-0008, Phase 3).

**Divergence notes.** ModSecurity v2 and v3 already behave this way. Coraza 3.8.1
matches directive, action and transformation names case-insensitively but operator
names case-sensitively. See ADR-0002.

**Tests.** `tests/engine/lexical/case-insensitive-names.yaml`
```

- [ ] **Step 7: Write `spec/04-directives.md` with SecRuleEngine**

```markdown
# 04. Directives

One section per directive. Phase 1 contains the single worked example; the remaining
Core directives arrive in Phase 2.

### SecRuleEngine

**Status:** Core

**Syntax.** `SecRuleEngine On|Off|DetectionOnly`

**Default.** `Off` in ModSecurity v2 and Coraza. libmodsecurity v3 has no engine-level
default: the connector supplies one. Rulesets MUST set it explicitly.

**Scope.** Main configuration and any included file. The last occurrence before a
transaction starts wins. `ctl:ruleEngine` changes the value for the current
transaction only.

**Semantics.**

- `On`: rules are evaluated and disruptive actions (`deny`, `drop`, `redirect`,
  `allow`) take effect.
- `DetectionOnly`: rules are evaluated, matches are logged, variables are set, but no
  disruptive action interrupts the transaction. The status code of the transaction is
  unaffected.
- `Off`: no rules are evaluated. Nothing is logged by rules. Request and response body
  handling directives still apply where the engine needs them for other purposes.

**Divergence notes.** None known for the three values. Engines differ on the default;
this specification does not standardize the default because every published ruleset
sets it.

**Tests.** `tests/engine/directives/secruleengine-on.yaml`,
`tests/engine/directives/secruleengine-detectiononly.yaml`,
`tests/engine/directives/secruleengine-off.yaml`
```

- [ ] **Step 8: Write `spec/07-transformations.md` with base64Decode**

```markdown
# 07. Transformations

One section per transformation. Phase 1 contains the single worked example; the rest of
the Core set arrives in Phase 3 together with the imported SecRules Test Set cases.

### base64Decode

**Status:** Core

**Syntax.** `t:base64Decode`

**Semantics.** Decodes the input as standard Base64 (RFC 4648 section 4, alphabet
`A-Z a-z 0-9 + /`, `=` padding). Decoding proceeds from the start of the input and
stops at the first byte that is not in the alphabet or padding; bytes after that point
are discarded. Missing padding is tolerated. Decoded NUL bytes are preserved in the
output. The empty input decodes to the empty output and reports no change.

Compare `base64DecodeExt`, which skips characters outside the alphabet instead of
stopping at them.

**Divergence notes.** None known.

**Tests.** `tests/unit/transformations/base64Decode.json`
```

- [ ] **Step 9: Run the validator on the real repo**

Run: `python3 tools/validate.py`
Expected: `0 error(s)`. If it reports a Core feature with no test or a dangling anchor, the heading text and the `spec:` values in Task 2 disagree; fix the spec heading, not the test.

- [ ] **Step 10: Commit**

```bash
git add spec tools/validate.py tools/test_validate.py
git commit -m "feat: conventions, first spec features, and Core coverage check

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01MdECTJovik6Z6EQq73oD1Z"
```

---

### Task 5: ADR process, ADR 0001–0003, and the ADR index check

**Files:**
- Create: `adr/README.md`
- Create: `adr/0000-template.md`
- Create: `adr/0001-status-labels-and-core.md`
- Create: `adr/0002-case-insensitive-names.md`
- Create: `adr/0003-test-formats.md`
- Modify: `tools/validate.py` (add `check_adrs`; register)
- Modify: `tools/test_validate.py` (add `AdrTests`)

**Interfaces:**
- Produces: `validate.check_adrs(root) -> list[str]`. ADR header contract: title line `# ADR-NNNN: <title>`; then a bullet block with exactly these fields in this order: `- **Status:** proposed|accepted|superseded|rejected`, `- **Date:** YYYY-MM-DD`, `- **Deciders:** ...`, `- **Category:** Divergence|Clarification|Deprecation|Extension`. A `Divergence` ADR has a `## Tests` section containing at least one `tests/...` path that exists. Index row format in `adr/README.md`: `| [NNNN](NNNN-slug.md) | Title | Category | status |`.

- [ ] **Step 1: Write the failing tests**

Append to `tools/test_validate.py`:

```python
ADR_OK = """\
# ADR-0001: Example decision

- **Status:** proposed
- **Date:** 2026-10-06
- **Deciders:** @someone
- **Category:** Clarification

## Context

Why.

## Decision

What.
"""

ADR_DIVERGENCE = ADR_OK.replace("0001", "0002").replace("Clarification", "Divergence") + """
## Tests

- `tests/engine/e.yaml`
"""

INDEX_OK = """\
# ADRs

| ADR | Title | Category | Status |
|---|---|---|---|
| [0001](0001-example-decision.md) | Example decision | Clarification | proposed |
"""


class AdrTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_repo(Path(self._tmp.name))
        (self.root / "adr/0000-template.md").write_text("# ADR-NNNN: template\n")
        (self.root / "adr/0001-example-decision.md").write_text(ADR_OK)
        (self.root / "adr/README.md").write_text(INDEX_OK)
        (self.root / "tests/engine/e.yaml").write_text(GOOD_ENGINE)

    def tearDown(self):
        self._tmp.cleanup()

    def test_valid_adr_and_index(self):
        self.assertEqual(validate.check_adrs(self.root), [])

    def test_bad_filename(self):
        (self.root / "adr/0003_Bad_Name.md").write_text(ADR_OK.replace("0001", "0003"))
        errors = validate.check_adrs(self.root)
        self.assertTrue(any("0003_Bad_Name.md" in e and "filename" in e for e in errors))

    def test_title_number_mismatch(self):
        (self.root / "adr/0001-example-decision.md").write_text(ADR_OK.replace("ADR-0001", "ADR-0007"))
        errors = validate.check_adrs(self.root)
        self.assertTrue(any("0001" in e and "0007" in e for e in errors))

    def test_unknown_category_and_status(self):
        (self.root / "adr/0001-example-decision.md").write_text(
            ADR_OK.replace("Clarification", "Perf").replace("proposed", "draft"))
        errors = validate.check_adrs(self.root)
        self.assertTrue(any("Category" in e and "Perf" in e for e in errors))
        self.assertTrue(any("Status" in e and "draft" in e for e in errors))

    def test_missing_field(self):
        (self.root / "adr/0001-example-decision.md").write_text(ADR_OK.replace("- **Date:** 2026-10-06\n", ""))
        errors = validate.check_adrs(self.root)
        self.assertTrue(any("Date" in e for e in errors))

    def test_divergence_requires_existing_test(self):
        (self.root / "adr/0002-second.md").write_text(ADR_DIVERGENCE)
        (self.root / "adr/README.md").write_text(INDEX_OK + "| [0002](0002-second.md) | Second | Divergence | proposed |\n")
        self.assertEqual(validate.check_adrs(self.root), [])
        (self.root / "adr/0002-second.md").write_text(ADR_DIVERGENCE.replace("e.yaml", "missing.yaml"))
        errors = validate.check_adrs(self.root)
        self.assertTrue(any("missing.yaml" in e for e in errors))
        (self.root / "adr/0002-second.md").write_text(ADR_DIVERGENCE.split("## Tests")[0])
        errors = validate.check_adrs(self.root)
        self.assertTrue(any("0002-second.md" in e and "Tests" in e for e in errors))

    def test_file_missing_from_index_and_index_row_without_file(self):
        (self.root / "adr/0002-second.md").write_text(ADR_OK.replace("0001", "0002"))
        errors = validate.check_adrs(self.root)
        self.assertTrue(any("0002-second.md" in e and "index" in e for e in errors))
        (self.root / "adr/README.md").write_text(INDEX_OK + "| [0009](0009-ghost.md) | Ghost | Clarification | proposed |\n")
        errors = validate.check_adrs(self.root)
        self.assertTrue(any("0009-ghost.md" in e for e in errors))
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest tools.test_validate.AdrTests -v`
Expected: FAIL with `AttributeError: module 'tools.validate' has no attribute 'check_adrs'`

- [ ] **Step 3: Implement the ADR check**

Insert into `tools/validate.py` before `CHECKS`:

```python
ADR_FILE_RE = re.compile(r"^(\d{4})-[a-z0-9]+(?:-[a-z0-9]+)*\.md$")
ADR_TITLE_RE = re.compile(r"^# ADR-(\d{4}): \S")
ADR_FIELD_RE = re.compile(r"^- \*\*(Status|Date|Deciders|Category):\*\* (.+?)\s*$")
ADR_INDEX_RE = re.compile(r"^\| \[(\d{4})\]\(([^)]+)\) \|")
ADR_TEST_PATH_RE = re.compile(r"`(tests/[^`\s]+)`")
ADR_FIELDS = ("Status", "Date", "Deciders", "Category")
ADR_STATUSES = {"proposed", "accepted", "superseded", "rejected"}
ADR_CATEGORIES = {"Divergence", "Clarification", "Deprecation", "Extension"}


def check_adrs(root: Path) -> list[str]:
    adr_dir = root / "adr"
    errors = []
    files = sorted(p for p in adr_dir.glob("*.md") if p.name not in ("README.md", "0000-template.md"))
    for path in files:
        rel = _rel(root, path)
        m = ADR_FILE_RE.match(path.name)
        if not m:
            errors.append(f"{rel}: filename must be NNNN-lower-kebab.md")
            continue
        number = m.group(1)
        text = path.read_text()
        lines = text.splitlines()
        tm = ADR_TITLE_RE.match(lines[0] if lines else "")
        if not tm:
            errors.append(f"{rel}: first line must be '# ADR-{number}: <title>'")
        elif tm.group(1) != number:
            errors.append(f"{rel}: filename number {number} but title says ADR-{tm.group(1)}")
        fields = {}
        for line in lines[1:]:
            if line.startswith("## "):
                break
            if fm := ADR_FIELD_RE.match(line):
                fields[fm.group(1)] = fm.group(2)
        for name in ADR_FIELDS:
            if name not in fields:
                errors.append(f"{rel}: missing header field **{name}:**")
        if "Status" in fields and fields["Status"] not in ADR_STATUSES:
            errors.append(f"{rel}: Status '{fields['Status']}' not in {sorted(ADR_STATUSES)}")
        if "Category" in fields and fields["Category"] not in ADR_CATEGORIES:
            errors.append(f"{rel}: Category '{fields['Category']}' not in {sorted(ADR_CATEGORIES)}")
        if "Date" in fields and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", fields["Date"]):
            errors.append(f"{rel}: Date '{fields['Date']}' must be YYYY-MM-DD")
        if fields.get("Category") == "Divergence":
            section = text.split("\n## Tests", 1)
            paths = ADR_TEST_PATH_RE.findall(section[1].split("\n## ", 1)[0]) if len(section) == 2 else []
            if not paths:
                errors.append(f"{rel}: Divergence ADR needs a '## Tests' section listing at least one `tests/...` path")
            for p in paths:
                if not (root / p).is_file():
                    errors.append(f"{rel}: listed test {p} does not exist")
    index_path = adr_dir / "README.md"
    indexed = {}
    if index_path.is_file():
        for line in index_path.read_text().splitlines():
            if im := ADR_INDEX_RE.match(line):
                indexed[im.group(2)] = im.group(1)
    else:
        errors.append("adr/README.md: missing")
    on_disk = {p.name for p in files}
    for name in sorted(on_disk - set(indexed)):
        errors.append(f"adr/{name}: not listed in adr/README.md index")
    for name in sorted(set(indexed) - on_disk):
        errors.append(f"adr/README.md: index row for {name} but no such file")
    return errors
```

Then change the registry line to:

```python
CHECKS: list[Callable[[Path], list[str]]] = [check_tests, check_coverage, check_adrs]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest tools.test_validate -v`
Expected: 20 tests, `OK`

- [ ] **Step 5: Write `adr/0000-template.md`**

```markdown
# ADR-NNNN: <short decision title>

- **Status:** proposed
- **Date:** YYYY-MM-DD
- **Deciders:** @handle, @handle
- **Category:** Divergence | Clarification | Deprecation | Extension

## Context

What the engines do today, with file or doc references for each engine surveyed. For a
Divergence, state each engine's behaviour in one line.

## Decision

The normative outcome, in RFC 2119 words, as it will appear in `spec/`.

## Options considered

- Option A: what it is, what it costs.
- Option B: ...

If there was only one realistic option, say so.

## Consequences

- For ModSecurity: ...
- For Coraza: ...
- For rule authors: ...

## Tests

Required for a Divergence; recommended otherwise. Paths in backticks:

- `tests/engine/<topic>/<case>.yaml`

## References

- Links to issues, PRs, manual sections, engine ADRs.
```

- [ ] **Step 6: Write `adr/README.md`**

```markdown
# Architecture Decision Records

An ADR records a decision about the SecLang specification: what was decided, which
alternatives existed, and why. Write one whenever the engines disagree and the spec
has to pick (Divergence), when behaviour is undocumented but agreed (Clarification),
when a legacy feature is retired (Deprecation), or when an engine-specific feature is
promoted into the spec (Extension).

## Process

1. Copy `0000-template.md` to `NNNN-short-slug.md` with the next free number.
2. Fill every header field. `Status` is `proposed` until maintainers of at least two
   implementing engines agree, then `accepted`. `superseded` and `rejected` are terminal.
3. A `Divergence` ADR must list at least one test under `## Tests` that encodes the
   outcome. The validator checks the paths exist.
4. Add a row to the index below. `python3 tools/validate.py` fails if a file and the
   index disagree.
5. Update the affected section of `spec/` in the same PR.

## Index

| ADR | Title | Category | Status |
|---|---|---|---|
| [0001](0001-status-labels-and-core.md) | Status labels and the meaning of Core | Clarification | proposed |
| [0002](0002-case-insensitive-names.md) | Directive, operator, action and transformation names match case-insensitively | Divergence | proposed |
| [0003](0003-test-formats.md) | Test formats: SecRules Test Set JSON for units, go-ftw-derived YAML for engine profiles | Clarification | proposed |
```

- [ ] **Step 7: Write ADR-0001**

`adr/0001-status-labels-and-core.md`:

```markdown
# ADR-0001: Status labels and the meaning of Core

- **Status:** proposed
- **Date:** 2026-10-06
- **Deciders:** @fzipi
- **Category:** Clarification

## Context

No prior specification exists. A survey on 2026-10-06 of ModSecurity v2 (`v2/master`),
libmodsecurity v3.0.16 and Coraza v3.8.1 found 92 directive names, 48 actions, 20
`ctl:` options, 44 operators, 38 transformations and 144 variables in the union, of
which 65, 33, 10, 28, 33 and 74 respectively exist in all three (`compat/matrix.md`).
Some union members are legacy (`sanitise*`, `PERF_*`), some are engine extensions
(`SecDataset`, `rxGlobal`), and some are accepted by a parser without being
implemented. A single "supported / not supported" axis cannot express this.

## Decision

Every feature carries exactly one of four statuses, defined normatively in
`spec/00-conventions.md`: **Core** (MUST implement), **Extended** (SHOULD implement,
fully specified, declared per engine), **Deprecated** (MUST parse, MAY ignore),
**Engine-specific** (name reserved, not specified).

The initial Core set is the intersection of the three surveyed engines **restricted
to** features used by OWASP CRS v4 or by the engines' recommended configuration files.
A feature in the intersection but unused by CRS v4 starts as Extended. Moving a feature
into or out of Core requires an ADR.

Conformance is all-or-nothing for Core and declared per feature for Extended.

## Options considered

- Union as Core: forces every engine to implement every legacy feature; rejected.
- Intersection as Core, unfiltered: makes e.g. `SecGsbLookupDb` Core although nothing
  uses it; rejected.
- Intersection filtered by CRS v4 usage: chosen. CRS v4 is the one ruleset every engine
  already claims to run, so it is the practical definition of compatibility.
- A numeric conformance level (1, 2, 3): hides which features differ; rejected.

## Consequences

- For ModSecurity: v2-only features will be labelled Deprecated or Engine-specific.
- For Coraza: features it lacks but CRS uses (if any are found in Phase 2–3) become
  Core gaps to close; persistent collections are Extended (ADR-0007, Phase 3).
- For rule authors: a ruleset using only Core features is portable by construction.

## Tests

Not applicable; this ADR defines process. Enforcement is `tools/validate.py`, which
fails when a Core feature has no test.

## References

- `docs/superpowers/specs/2026-10-06-seclang-spec-design.md` sections 2 and 4.2
- `compat/matrix.md`
```

- [ ] **Step 8: Write ADR-0002**

`adr/0002-case-insensitive-names.md`:

```markdown
# ADR-0002: Directive, operator, action and transformation names match case-insensitively

- **Status:** proposed
- **Date:** 2026-10-06
- **Deciders:** @fzipi
- **Category:** Divergence

## Context

- ModSecurity v2: directives are Apache configuration commands and Apache matches them
  case-insensitively. Actions, operators, transformations and variables are looked up
  in APR tables (`apache2/re.c`, `apr_table_get`), whose keys are case-insensitive.
- libmodsecurity v3: the Flex scanner (`src/parser/seclang-scanner.ll`) wraps every
  directive, action, operator and transformation token in `(?i:...)`.
- Coraza 3.8.1: directive names are lowercased before lookup
  (`internal/seclang/directivesmap.gen.go`), action names are lowercased in
  `internal/actions/actions.go` `Get`, transformation names are lowercased in
  `internal/transformations/transformations.go` `GetTransformation`, but operator names
  are looked up verbatim in `internal/operators/operators.go` `Get`. `@IPMATCH` or
  `@ipmatch` (the ModSecurity v2 spelling) fails to load in Coraza.

Rulesets in the wild mix spellings: CRS uses `@ipMatch`, older third-party rules use
`@ipmatch` and `@pmf`.

## Decision

Engines MUST match directive names, operator names, action names, transformation names
and `ctl:` option names case-insensitively. The canonical spelling is the mixed-case
form from the ModSecurity reference manual; engines SHOULD use it in logs.

Variable and collection names, and collection keys, are out of scope here (ADR-0008).

## Options considered

- Case-insensitive everywhere (chosen): matches two of three engines and all
  historical documentation; costs Coraza one `strings.ToLower` in operator lookup.
- Case-sensitive canonical names only: would break existing rulesets on ModSecurity
  users who migrate; rejected.
- Case-insensitive for directives only: leaves the actual observed incompatibility in
  place; rejected.

## Consequences

- For ModSecurity: no change.
- For Coraza: lowercase the operator name in `operators.Get` (or at registration and
  lookup). Plugin operators registered with mixed case keep working.
- For rule authors: spelling variants of the same name are safe; distinct names that
  differ only in case cannot exist, so no engine may introduce one.

## Tests

- `tests/engine/lexical/case-insensitive-names.yaml`

## References

- `spec/01-lexical.md#name-matching`
- Coraza ADR-0026 (`pmf` alias) and ADR-0027 (`ipMatchF` alias) in
  `corazawaf/coraza/docs/adr`, which added spelling aliases one at a time.
```

- [ ] **Step 9: Write ADR-0003**

`adr/0003-test-formats.md`:

```markdown
# ADR-0003: Test formats: SecRules Test Set JSON for units, go-ftw-derived YAML for engine profiles

- **Status:** proposed
- **Date:** 2026-10-06
- **Deciders:** @fzipi
- **Category:** Clarification

## Context

Three machine-readable test corpora already exist for SecLang engines:

- The SecRules Test Set (`SpiderLabs/secrules-language-tests`, vendored as a submodule
  by libmodsecurity v3): JSON arrays of `{type, name, param, input, output, ret}`
  cases for operators and transformations. Both ModSecurity v3 and Coraza have
  runners for this shape.
- libmodsecurity v3 regression tests (`test/test-cases/regression/*.json`): a full
  synthetic transaction plus expected debug-log substrings and HTTP code. Tied to v3
  debug-log wording.
- go-ftw YAML (`coreruleset/go-ftw`, documented in `waf-test-spec/YAMLFormat.md`) and
  Coraza's in-tree `testing/profile` Go structs, which mirror it and add `rules`,
  `triggered_rules`, `non_triggered_rules` and `interruption`.

This repository must stay runner-free (design assumption 4), so the formats must be
loadable by Go and C++ test code with off-the-shelf libraries.

## Decision

Two tiers, both with a JSON Schema in `tests/schema/`:

1. **Unit tier**, `tests/unit/**/*.json`: the SecRules Test Set shape unchanged, plus
   optional `spec`, `status` and `note` fields.
2. **Engine tier**, `tests/engine/**/*.yaml`: one profile per file in the Coraza
   profile / go-ftw shape (`meta`, `rules`, `tests[].stages[].stage.{input,output}`),
   plus `spec`, `requires`, a `stage.response` block for synthetic backend responses,
   and `output.no_interruption`.

Assertions are limited to rule IDs, interruption and log substrings. Audit-log layout,
debug-log wording and timing are never asserted.

The validator uses two Python dev dependencies, `pyyaml` and `jsonschema`, because
YAML parsing and JSON Schema 2020-12 validation are not worth reimplementing and both
are available in every CI image.

## Options considered

- Invent a new unified format: nothing can run it on day one; rejected.
- JSON for the engine tier too: one parser fewer, but go-ftw users write YAML and the
  multi-line `rules` block is unreadable as a JSON string; rejected.
- Reuse v3 regression JSON: assertions depend on v3 debug-log wording; rejected.
- stdlib-only validator: would need a hand-written YAML subset parser and schema
  checker; rejected as more code than the rest of the repo.

## Consequences

- For ModSecurity: the unit tier is already runnable; the engine tier needs a small
  adapter over the existing regression harness (`test/regression`).
- For Coraza: `testing/profile` already loads the engine tier minus `response`,
  `requires`, `spec` and `no_interruption`; add those fields and a skip on `requires`.
- For contributors: write YAML/JSON, run `python3 tools/validate.py`, no toolchain.

## Tests

- `tests/unit/transformations/base64Decode.json`
- `tests/engine/directives/secruleengine-on.yaml`

## References

- `tests/README.md`
- https://github.com/coreruleset/go-ftw
- https://github.com/SpiderLabs/secrules-language-tests
```

- [ ] **Step 10: Run the validator on the real repo**

Run: `python3 tools/validate.py`
Expected: `0 error(s)`

- [ ] **Step 11: Commit**

```bash
git add adr tools/validate.py tools/test_validate.py
git commit -m "feat: ADR process with ADR 0001-0003 and index check

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01MdECTJovik6Z6EQq73oD1Z"
```

---

### Task 6: Matrix freshness check, README, CI

**Files:**
- Modify: `tools/validate.py` (add `check_matrix`; register)
- Modify: `tools/test_validate.py` (add `MatrixCheckTests`)
- Create: `README.md`
- Create: `.github/workflows/validate.yml`
- Create: `.gitignore`

**Interfaces:**
- Consumes: `tools.matrix.render`, `tools.matrix.load` from Task 1.
- Produces: `validate.check_matrix(root) -> list[str]`.

- [ ] **Step 1: Write the failing tests**

Append to `tools/test_validate.py`:

```python
from tools import matrix as matrix_mod
from tools.test_matrix import SAMPLE as MATRIX_SAMPLE


class MatrixCheckTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_repo(Path(self._tmp.name))
        (self.root / "compat/matrix.json").write_text(json.dumps(MATRIX_SAMPLE))

    def tearDown(self):
        self._tmp.cleanup()

    def test_fresh_markdown_passes(self):
        matrix_mod.main(self.root)
        self.assertEqual(validate.check_matrix(self.root), [])

    def test_stale_markdown_is_reported(self):
        (self.root / "compat/matrix.md").write_text("# old\n")
        errors = validate.check_matrix(self.root)
        self.assertEqual(len(errors), 1)
        self.assertIn("tools/matrix.py", errors[0])

    def test_missing_markdown_is_reported(self):
        errors = validate.check_matrix(self.root)
        self.assertEqual(len(errors), 1)
        self.assertIn("compat/matrix.md", errors[0])

    def test_broken_json_row_is_reported_not_raised(self):
        broken = json.loads(json.dumps(MATRIX_SAMPLE))
        del broken["categories"]["operators"][0]["v2"]
        (self.root / "compat/matrix.json").write_text(json.dumps(broken))
        errors = validate.check_matrix(self.root)
        self.assertEqual(len(errors), 1)
        self.assertIn("rx", errors[0])
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest tools.test_validate.MatrixCheckTests -v`
Expected: FAIL with `AttributeError: module 'tools.validate' has no attribute 'check_matrix'`

- [ ] **Step 3: Implement the matrix check**

Add to the import block of `tools/validate.py`:

```python
from tools import matrix as _matrix
```

If running `python3 tools/validate.py` directly then fails with `ModuleNotFoundError: No module named 'tools'`, add this line immediately before that import:

```python
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
```

Insert before `CHECKS`:

```python
def check_matrix(root: Path) -> list[str]:
    md = root / "compat" / "matrix.md"
    if not md.is_file():
        return ["compat/matrix.md: missing; run python3 tools/matrix.py"]
    try:
        expected = _matrix.render(_matrix.load(root))
    except (ValueError, KeyError) as exc:
        return [f"compat/matrix.json: {exc}"]
    if md.read_text() != expected:
        return ["compat/matrix.md: stale; run python3 tools/matrix.py and commit the result"]
    return []
```

Then change the registry line to:

```python
CHECKS: list[Callable[[Path], list[str]]] = [check_tests, check_coverage, check_adrs, check_matrix]
```

- [ ] **Step 4: Run all tool tests and the validator**

Run: `python3 -m unittest discover -s tools -t . -v && python3 tools/validate.py`
Expected: 28 tests `OK`, then `0 error(s)`

- [ ] **Step 5: Write `README.md`**

```markdown
# SecLang Specification

A formal specification of **SecLang**, the rule language implemented by
[ModSecurity](https://github.com/owasp-modsecurity/ModSecurity) (v2 and libmodsecurity
v3) and [Coraza](https://github.com/corazawaf/coraza), with engine-neutral conformance
tests and Architecture Decision Records for the places where engines diverge.

## Layout

| Path | What |
|---|---|
| `spec/` | The specification, one file per topic. Every feature heading has a `**Status:**` line. |
| `adr/` | Decisions. `Divergence` ADRs pick a behaviour where engines disagree and name the test that encodes it. |
| `tests/` | Conformance test data (no runner). `unit/` for operators and transformations, `engine/` for everything else. |
| `compat/` | Three-engine feature matrix. Edit `matrix.json`, regenerate `matrix.md` with `tools/matrix.py`. |
| `tools/` | `validate.py` enforces the repo's invariants; CI runs it. |

## Status labels

`Core` MUST be implemented. `Extended` SHOULD be, and is declared per engine.
`Deprecated` MUST parse and MAY be ignored. `Engine-specific` is reserved, not specified.
Definitions: `spec/00-conventions.md`. Rationale: `adr/0001-status-labels-and-core.md`.

## Running the checks

```sh
python3 -m pip install -r requirements-dev.txt
python3 tools/validate.py
python3 -m unittest discover -s tools -t .
```

## Implementing an engine adapter

Read `tests/README.md`. Load every file under `tests/unit` and `tests/engine`, skip
engine profiles whose `requires` lists a feature you do not implement, and assert the
`output` blocks. Report the spec version you conform to.

## Contributing

Open an ADR for any behavioural decision; add or update tests in the same change; run
the validator. The design document is in `docs/superpowers/specs/`.
```

- [ ] **Step 6: Write CI workflow and `.gitignore`**

`.github/workflows/validate.yml`:

```yaml
name: validate
on:
  push:
    branches: [main]
  pull_request:
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python3 -m pip install -r requirements-dev.txt
      - run: python3 -m unittest discover -s tools -t . -v
      - run: python3 tools/validate.py
```

`.gitignore`:

```
__pycache__/
*.pyc
.venv/
```

- [ ] **Step 7: Final full run and commit**

Run: `python3 -m unittest discover -s tools -t . && python3 tools/validate.py && git status --short`
Expected: `OK`, `0 error(s)`, and only the new files listed.

```bash
git add README.md .github .gitignore tools/validate.py tools/test_validate.py
git commit -m "feat: matrix freshness check, README and CI workflow

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01MdECTJovik6Z6EQq73oD1Z"
```

---

## Self-review notes

- **Spec coverage.** Design 4.1 layout: all Phase 1 paths created (spec/00, adr/, tests/schema, tests/README, tools/validate.py, compat/). Spec files 02, 03, 05, 06, 08, 09, 10 are Phase 2–4 by design. 4.2 conventions: Task 4. 4.4 formats: Task 2 and ADR-0003. 4.5 ADR process and ADRs 0001–0003: Task 5. 4.7 validator invariants: Tasks 3–6, one check each. Appendix A: Task 1.
- **Type consistency.** `make_repo`, `GOOD_UNIT`, `GOOD_ENGINE` defined in Task 3 and reused in Tasks 4–6. `CHECKS` registry grows by one function per task; `main(root, checks=None)` signature fixed in Task 3. `matrix.render`/`matrix.load`/`matrix.main(root)` from Task 1 used in Task 6.
- **Review Focus mapping.** 1 → Task 3 `test_engine_file_that_is_a_list...`; 2 → Task 4 `test_ref_to_heading_without_status_is_dangling`; 3 → Task 4 `test_same_heading_in_two_files_does_not_collide`; 4 → Task 5 `test_title_number_mismatch`; 5 → Task 1 `test_missing_engine_key_names_row` and Task 6 `test_broken_json_row_is_reported_not_raised`.
- **Open item for the repo owner, not the plan:** no `LICENSE` file is created. OWASP projects commonly use Apache-2.0 for code and CC-BY-SA-4.0 for documentation; choose and add one before publishing.
