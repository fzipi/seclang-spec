# SecLang Spec Phase 3 (Variables, Operators, Transformations, Actions) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Specify every variable, operator, transformation, action and `ctl:` option known to the three engines, with a status for each, engine tests for every Core variable and action, the SecRules Test Set imported as the unit tier for operators and transformations, and ADRs 0007–0012 plus three new ones found in research.

**Architecture:** Four spec files (`05-variables`, `06-operators`, `07-transformations`, `08-actions`) in the Phase 2 shape: an index of every name with status, full sections for Core features, short sections for the rest. Unit-tier JSON is generated once from the SecRules Test Set by a small converter in `tools/` that undoes the corpus's double escaping and attaches `spec:` anchors; it is run, its output committed, and the converter kept so the import can be redone when the corpus changes. The matrix gains statuses for the five remaining categories and the validator cross-checks all of them.

**Tech Stack:** Markdown, YAML, JSON; Python via `uv run` for `tools/`.

**Spec:** `docs/superpowers/specs/2026-10-06-seclang-spec-design.md` sections 4.4, 4.5, 4.6 (Phase 3); `spec/00-conventions.md`; `adr/0001`–`0006`, `0013`–`0017`.

## Global Constraints

- Feature headings `### Name` with `**Status:**` as the first non-blank line; every Core feature has a test anchored to it; `uv run python tools/validate.py` reports `0 error(s)` at the end of every task.
- Engine facts cite a source pointer. Paths surveyed 2026-10-06: v2 `apache2/re_variables.c`, `re_operators.c`, `re_tfns.c`, `re_actions.c`, `msc_parsers.c`; v3 `src/variables/*.cc`, `src/operators/*.cc`, `src/actions/**`, `headers/modsecurity/anchored_set_variable.h`; Coraza `internal/variables/`, `internal/collections/`, `internal/operators/`, `internal/transformations/`, `internal/actions/`, `types/variables/variables.go`.
- Status rule (ADR-0001): Core = present in all three engines **and** used by OWASP CRS v4 or the recommended configurations, **or** a component of a Core feature (`ARGS_POST` is a component of `ARGS`); two engines = Extended; v2-only = Deprecated; one other engine = Engine-specific. Deviations are named in the status tables below.
- Unit-tier files keep the SecRules Test Set field names; escapes are plain JSON escapes (ADR-0003). The schema gains optional `re_groups`.
- Divergences where the spec follows the majority get a divergence note and a `compat/known-gaps.md` row; a decision against a majority or against the ModSecurity manual gets an ADR.
- Commit messages end with the two attribution lines from the session reminder.

## Review Focus

1. A request whose query string has a repeated key (`?a=1&a=2`). Expected: `ARGS_GET:a` selects both values, `&ARGS_GET:a` counts 2, `ARGS_GET_NAMES` lists `a` twice; test added to Task 2 (`variables/args.yaml`).
2. A cookie header with two cookies of the same name. Expected: both selected by `REQUEST_COOKIES:name`; test added to Task 2 (`variables/request-cookies.yaml`).
3. `@eq` with a non-numeric target such as `abc`. Expected per source: v2 `atoi`, v3 `stoi` with catch, Coraza `Atoi` ignoring the error all yield 0, so `@eq 0` matches; test added to Task 3 as a unit case.
4. `@pm` with mixed-case input. Expected: case-insensitive in all three (v2 ACMP, v3 ACMP, Coraza `strings.ToLower` in `pm.go`); unit cases already exist in the imported corpus; Task 3 keeps them Core.
5. `setvar:tx.x=+1` when `tx.x` is unset. Expected: treated as 0 then incremented to 1 in all three (CRS anomaly scoring depends on it); test added to Task 5 (`actions/setvar.yaml`).

---

### Task 1: Tooling for Phase 3

**Files:**
- Modify: `compat/matrix.json` (fix: operators row `validateUtf8Encoding` coraza → `true`; add ctl row `forceResponseBodyVariable` coraza-only)
- Modify: `tools/validate.py` (`MATRIX_SPEC_FILES` becomes a mapping to `(file, heading prefix)` so `ctl` rows resolve to `08-actions.md#ctl<slug>`; `check_tests` rejects `files:` keys containing `..`)
- Modify: `tests/schema/unit.schema.json` (add `re_groups`: array of strings, meaningful only for `op` cases)
- Create: `tools/import_sts.py` (converter; see Interfaces)
- Modify: `tools/test_validate.py`, create `tools/test_import_sts.py`
- Modify: `tests/README.md` (define "triggered", document `re_groups` and the import)

**Interfaces:**
- `validate.MATRIX_SPEC_FILES = {"directives": ("04-directives.md", ""), "variables": ("05-variables.md", ""), "operators": ("06-operators.md", ""), "transformations": ("07-transformations.md", ""), "actions": ("08-actions.md", ""), "ctl": ("08-actions.md", "ctl")}`; anchor = `f"{file}#{prefix}{slug(name)}"`. Rows without `status` are skipped (alias rows such as `pmf`, `normalizePath`, `sanitize*` carry no status).
- `import_sts.convert_case(case: dict, anchor: str) -> dict | None`: returns the case with `input`, `output`, `param` unescaped (the corpus stores `\\u0000` as a literal backslash sequence; decode with `codecs.decode(s, "unicode_escape")` after `latin-1` encoding), `spec` set, `re_groups` kept, `resource` cases dropped (returns `None`). `import_sts.main(src: Path, dest: Path, anchors: dict[str, str]) -> dict[str, int]` writes one file per operator/transformation that has an anchor, skipping names without one (unsupported features), and returns counts.
- `tests/README.md` "triggered" definition: a rule is *triggered* when its operator matched (for a chain, when every member matched) regardless of `log`/`nolog`/`auditlog`; adapters MUST derive it from the engine's matched-rule list, not from log output.

- [ ] **Step 1: Failing tests**

Append to `tools/test_validate.py`:
```python
class Phase3ToolingTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = make_repo(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    def test_ctl_rows_resolve_to_prefixed_anchor(self):
        m = {"generated": "x", "engines": {"v2": "", "v3": "", "coraza": ""},
             "categories": {"ctl": [{"name": "ruleEngine", "v2": True, "v3": True, "coraza": True, "status": "Core"}]}}
        (self.root / "compat/matrix.json").write_text(json.dumps(m))
        (self.root / "spec/08-actions.md").write_text("# Actions\n\n### ctl:ruleEngine\n\n**Status:** Core\n")
        self.assertEqual(validate.check_matrix_status(self.root), [])

    def test_files_key_with_dotdot_is_rejected(self):
        prof = GOOD_ENGINE.replace("rules: |", "files:\n  ../x.conf: SecRuleEngine On\nrules: |")
        (self.root / "tests/engine/e.yaml").write_text(prof)
        errors = validate.check_tests(self.root)
        self.assertTrue(any("tests/engine/e.yaml" in e and ".." in e for e in errors))

    def test_unit_case_may_carry_re_groups(self):
        case = [{"type": "op", "name": "rx", "param": "(a)(b)", "input": "ab", "ret": 1, "re_groups": ["ab", "a", "b"],
                 "spec": "06-operators.md#rx"}]
        (self.root / "tests/unit/rx.json").write_text(json.dumps(case))
        self.assertEqual(validate.check_tests(self.root), [])
```
Create `tools/test_import_sts.py`:
```python
import json
import tempfile
import unittest
from pathlib import Path

from tools import import_sts


class ConvertTests(unittest.TestCase):
    def test_unescapes_literal_backslash_sequences(self):
        case = {"type": "tfn", "name": "base64Decode", "input": "VGVzdABDYXNl", "output": "Test\\u0000Case", "ret": 1}
        out = import_sts.convert_case(case, "07-transformations.md#base64decode")
        self.assertEqual(out["output"], "Test\u0000Case")
        self.assertEqual(out["spec"], "07-transformations.md#base64decode")

    def test_plain_strings_unchanged_and_param_unescaped(self):
        case = {"type": "op", "name": "rx", "param": "a\\\\d", "input": "a1", "ret": 1}
        out = import_sts.convert_case(case, "06-operators.md#rx")
        self.assertEqual(out["param"], "a\\d")
        self.assertEqual(out["input"], "a1")

    def test_resource_cases_dropped_and_re_groups_kept(self):
        self.assertIsNone(import_sts.convert_case({"type": "op", "name": "pmFromFile", "param": "x", "input": "y", "ret": 1, "resource": "f"}, "a#b"))
        out = import_sts.convert_case({"type": "op", "name": "rx", "param": "(a)", "input": "a", "ret": 1, "re_groups": ["a", "a"]}, "a#b")
        self.assertEqual(out["re_groups"], ["a", "a"])

    def test_main_writes_only_anchored_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src"; dest = Path(tmp) / "dest"
            (src / "operators").mkdir(parents=True); (src / "transformations").mkdir()
            (src / "operators" / "rx.json").write_text(json.dumps([{"type": "op", "name": "rx", "param": "a", "input": "a", "ret": 1}]))
            (src / "operators" / "gsbLookup.json").write_text(json.dumps([{"type": "op", "name": "gsbLookup", "param": "a", "input": "a", "ret": 0}]))
            (src / "transformations" / "lowercase.json").write_text(json.dumps([{"type": "tfn", "name": "lowercase", "input": "A", "output": "a", "ret": 1}]))
            counts = import_sts.main(src, dest, {"rx": "06-operators.md#rx", "lowercase": "07-transformations.md#lowercase"})
            self.assertEqual(counts, {"rx": 1, "lowercase": 1})
            self.assertTrue((dest / "operators" / "rx.json").is_file())
            self.assertFalse((dest / "operators" / "gsbLookup.json").exists())
            self.assertEqual(json.loads((dest / "transformations" / "lowercase.json").read_text())[0]["spec"], "07-transformations.md#lowercase")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: RED** — `uv run python -m unittest tools.test_validate.Phase3ToolingTests tools.test_import_sts` → failures/ImportError.

- [ ] **Step 3: Implement**

`tools/import_sts.py`:
```python
"""Import SecRules Test Set JSON into tests/unit with plain JSON escapes and spec anchors.

Usage: uv run python tools/import_sts.py <sts-dir> [--dest tests/unit]
The anchors come from spec/06-operators.md and spec/07-transformations.md feature headings.
"""
import codecs
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools import validate  # noqa: E402

FIELDS = ("input", "output", "param")


def unescape(s: str) -> str:
    if "\\" not in s:
        return s
    return codecs.decode(s.encode("latin-1", "backslashreplace"), "unicode_escape")


def convert_case(case: dict, anchor: str) -> dict | None:
    if "resource" in case:
        return None
    out = {k: (unescape(v) if k in FIELDS and isinstance(v, str) else v) for k, v in case.items()}
    out["spec"] = anchor
    return out


def main(src: Path, dest: Path, anchors: dict[str, str]) -> dict[str, int]:
    counts = {}
    for tier in ("operators", "transformations"):
        for path in sorted((src / tier).glob("*.json")):
            name = path.stem
            anchor = anchors.get(name) or anchors.get(name.lower())
            if not anchor:
                continue
            cases = [c for c in (convert_case(c, anchor) for c in json.loads(path.read_text())) if c]
            if not cases:
                continue
            (dest / tier).mkdir(parents=True, exist_ok=True)
            (dest / tier / f"{name}.json").write_text(json.dumps(cases, indent=1, ensure_ascii=False) + "\n")
            counts[name] = len(cases)
    return counts


def anchors_from_spec(root: Path) -> dict[str, str]:
    feats = validate.spec_features(root)
    out = {}
    for anchor in feats:
        file, frag = anchor.split("#")
        if file in ("06-operators.md", "07-transformations.md"):
            out[frag] = anchor  # heading slug == lowercased name
    return out


if __name__ == "__main__":
    src = Path(sys.argv[1])
    dest = Path(sys.argv[sys.argv.index("--dest") + 1]) if "--dest" in sys.argv else validate.ROOT / "tests" / "unit"
    counts = main(src, dest, anchors_from_spec(validate.ROOT))
    print(f"imported {sum(counts.values())} cases into {len(counts)} files", file=sys.stderr)
```
Note `anchors_from_spec` keys by the heading slug, so `main`'s lookup must try `name.lower()`; the STS file names are mixed case (`beginsWith.json`) and the slug is lowercase (`beginswith`).

`tools/validate.py`: change `MATRIX_SPEC_FILES` to the mapping in Interfaces and the loop to `for category, (spec_file, prefix) in MATRIX_SPEC_FILES.items():` with `anchor = f"{spec_file}#{prefix}{slug(name)}"` (both places) and `by_anchor` built the same way. In `check_tests`, after schema validation of an engine profile: `for key in (data.get("files") or {}): if ".." in key.split("/"): errors.append(f"{rel}: files: {key}: path segments must not be '..'")`.

`tests/schema/unit.schema.json`: add `"re_groups": {"type": "array", "items": {"type": "string"}, "description": "For @rx: the full match followed by capture groups, as the capture action would store them in TX:0..9"}` to `properties`.

Matrix fix script:
```bash
uv run python - <<'EOF'
import json
p="compat/matrix.json"; m=json.load(open(p))
for r in m["categories"]["operators"]:
    if r["name"]=="validateUtf8Encoding": r["coraza"]=True
m["categories"]["ctl"].append({"name":"forceResponseBodyVariable","v2":False,"v3":False,"coraza":True})
json.dump(m,open(p,"w"),indent=1); open(p,"a").write("\n")
EOF
uv run python tools/matrix.py
```

`tests/README.md`: add the "triggered" definition paragraph and a line on `re_groups`; add a "Unit tier provenance" paragraph: files under `tests/unit/{operators,transformations}` are generated by `tools/import_sts.py` from `secrules-language-tests` (libmodsecurity v3's `test/test-cases/secrules-language-tests` submodule), edits go into the converter or into hand-written `*-extra.json` files next to them.

- [ ] **Step 4: GREEN** — `uv run python -m unittest discover -s tools -t .` (38 + 7 = 45 tests) and `uv run python tools/validate.py` → `0 error(s)` (matrix has no new statuses yet; the `check_matrix_status` for the fixed row passes because operators rows carry no status).

- [ ] **Step 5: Commit** `feat: Phase 3 tooling (STS importer, ctl anchors, re_groups, files guard, matrix fixes)`.

---

### Task 2: `spec/05-variables.md` and variable tests; ADR-0007, ADR-0008

**Status table (144 names):**

| Status | Variables |
|---|---|
| **Core (41)** | ARGS ARGS_COMBINED_SIZE ARGS_GET ARGS_GET_NAMES ARGS_NAMES ARGS_POST ARGS_POST_NAMES FILES FILES_COMBINED_SIZE FILES_NAMES INBOUND_DATA_ERROR MATCHED_VAR MATCHED_VAR_NAME MATCHED_VARS MULTIPART_PART_HEADERS MULTIPART_STRICT_ERROR OUTBOUND_DATA_ERROR QUERY_STRING REMOTE_ADDR REQBODY_ERROR REQBODY_ERROR_MSG REQBODY_PROCESSOR REQUEST_BASENAME REQUEST_BODY REQUEST_BODY_LENGTH REQUEST_COOKIES REQUEST_COOKIES_NAMES REQUEST_FILENAME REQUEST_HEADERS REQUEST_HEADERS_NAMES REQUEST_LINE REQUEST_METHOD REQUEST_PROTOCOL REQUEST_URI REQUEST_URI_RAW RESPONSE_BODY RESPONSE_HEADERS RESPONSE_STATUS TX UNIQUE_ID XML |
| **Extended (56)** | the other 33 three-engine names (DURATION ENV FILES_SIZES FILES_TMPNAMES FILES_TMP_CONTENT FULL_REQUEST_LENGTH GEO HIGHEST_SEVERITY MATCHED_VARS_NAMES MULTIPART_DATA_AFTER MULTIPART_FILENAME MULTIPART_INVALID_QUOTING MULTIPART_NAME REMOTE_HOST REMOTE_PORT REQBODY_PROCESSOR_ERROR REQBODY_PROCESSOR_ERROR_MSG RESPONSE_CONTENT_LENGTH RESPONSE_CONTENT_TYPE RESPONSE_HEADERS_NAMES RESPONSE_PROTOCOL RULE SERVER_ADDR SERVER_NAME SERVER_PORT TIME TIME_DAY TIME_EPOCH TIME_HOUR TIME_MIN TIME_MON TIME_SEC TIME_WDAY TIME_YEAR URLENCODED_ERROR); the v2+v3 names (AUTH_TYPE FULL_REQUEST MODSEC_BUILD MULTIPART_BOUNDARY_QUOTED MULTIPART_BOUNDARY_WHITESPACE MULTIPART_CRLF_LF_LINES MULTIPART_DATA_BEFORE MULTIPART_FILE_LIMIT_EXCEEDED MULTIPART_HEADER_FOLDING MULTIPART_INVALID_HEADER_FOLDING MULTIPART_INVALID_PART MULTIPART_LF_LINE MULTIPART_MISSING_SEMICOLON MULTIPART_UNMATCHED_BOUNDARY PATH_INFO REMOTE_USER); the persistent collections (GLOBAL IP RESOURCE SESSION SESSIONID USER USERID WEBAPPID, ADR-0007); STATUS_LINE (v2+Coraza) |
| **Deprecated (24)** | MULTIPART_CRLF_LINE PERF_ALL PERF_COMBINED PERF_GC PERF_LOGGING PERF_PHASE1 PERF_PHASE2 PERF_PHASE3 PERF_PHASE4 PERF_PHASE5 PERF_RULES PERF_SREAD PERF_SWRITE SCRIPT_BASENAME SCRIPT_FILENAME SCRIPT_GID SCRIPT_GROUPNAME SCRIPT_MODE SCRIPT_UID SCRIPT_USERNAME SDBM_DELETE_ERROR STREAM_INPUT_BODY STREAM_OUTPUT_BODY USERAGENT_IP WEBSERVER_ERROR_LOG |
| **Engine-specific (18)** | Coraza: ARGS_PATH ARGUMENTS_LIMIT_REACHED JSON MULTIPART_DUPLICATE_PART_HEADER MULTIPART_FILENAME_CHARSET MULTIPART_FILENAME_LANGUAGE REQUEST_XML RES_BODY_ERROR RES_BODY_ERROR_MSG RES_BODY_PROCESSOR RES_BODY_PROCESSOR_ERROR RES_BODY_PROCESSOR_ERROR_MSG RESPONSE_ARGS RESPONSE_XML URI_PARSE_ERROR; v3: MSC_PCRE_ERROR MSC_PCRE_LIMITS_EXCEEDED STATUS |

(Counts must sum to 144 minus the names the executor finds duplicated; `MULTIPART_UNMATCHED_BOUNDARY` is Extended although `modsecurity.conf-recommended` uses it, because Coraza lacks it and Coraza's own recommended file omits it: say so in its section and in ADR-0005's gap list.)

**Facts for Core sections (verified 2026-10-06):**
- Collection key matching is case-insensitive in all three by default: v2 `re_variables.c` `strcasecmp(arg->name, var->param)`; v3 `anchored_set_variable.h` `MyEqual`/`MyHash` lower-case; Coraza `internal/collections/map.go` `strings.ToLower(key)` unless built with `coraza.rule.case_sensitive_args_keys` (its ADR-0016). **ADR-0008** makes case-insensitive keys normative and the Coraza tag non-conforming. Header names are case-insensitive by HTTP; cookie names and argument names likewise by this decision.
- `ARGS` = `ARGS_GET` ∪ `ARGS_POST`, in that order; repeated keys yield repeated members; `&ARGS` counts members; `ARGS_NAMES` lists names (repeated too). `ARGS_POST` is empty until phase 2 and only for `URLENCODED` and `MULTIPART` processors (and `XML` with `SecParseXmlIntoArgs`, Extended; Coraza also JSON → `ARGS_POST` with dotted keys: **Engine-specific note**, verify `internal/bodyprocessors/json.go`).
- `REQUEST_URI` = path + query (no scheme/host); `REQUEST_URI_RAW` = as sent, may include scheme/host for absolute-form; `REQUEST_FILENAME` = path only, URL-decoded? **verify per engine** (v2: decoded by Apache; v3 and Coraza: raw path) and write a divergence note if they differ; `REQUEST_BASENAME` = last path segment; `QUERY_STRING` = after `?`, raw.
- `REQUEST_LINE` = `METHOD SP URI SP PROTOCOL` as received; `REQUEST_PROTOCOL` = `HTTP/1.1`; `REQUEST_METHOD` as received, case preserved.
- `REQUEST_HEADERS` collection; `REQUEST_HEADERS_NAMES`; `REQUEST_COOKIES` parsed from every `Cookie` header, `;`-separated, names and values **not** URL-decoded; `REQUEST_COOKIES_NAMES`.
- `REQUEST_BODY` raw body (only when the processor is `URLENCODED` or forced with `ctl:forceRequestBodyVariable`; empty for `MULTIPART`); `REQUEST_BODY_LENGTH` bytes received.
- `FILES` (original file names), `FILES_NAMES` (form field names), `FILES_COMBINED_SIZE`; all keyed by field name; multipart only.
- `MULTIPART_PART_HEADERS` (collection keyed by part name, each value the raw headers of that part), `MULTIPART_STRICT_ERROR` ("1" on any multipart parsing anomaly; Coraza's own ADR-0017 lists which), `REQBODY_ERROR` / `REQBODY_ERROR_MSG`, `REQBODY_PROCESSOR` (`URLENCODED`, `MULTIPART`, `XML`, `JSON`; empty when no body), `INBOUND_DATA_ERROR`, `OUTBOUND_DATA_ERROR` (Phase 2 tests).
- `MATCHED_VAR`, `MATCHED_VAR_NAME` (full name `ARGS:foo`), `MATCHED_VARS`, `MATCHED_VARS_NAMES`: set after an operator matches; available to the same rule's actions and to following rules until the next match. Divergence to **verify**: whether `MATCHED_VAR` holds the transformed or the original value (v2: transformed; v3 and Coraza: check `rule_with_operator.cc` / `rule.go`).
- `TX`: per-transaction read-write collection; `TX:0`–`TX:9` hold `capture` groups; CRS stores scores in `TX`. `setvar` semantics are in `08-actions.md`.
- `RESPONSE_BODY`, `RESPONSE_HEADERS`, `RESPONSE_STATUS` (decimal string); `XML` requires the `XML` processor and takes XPath selectors (`XML:/*`); its values are element text with tags stripped; `XML://@*` attributes.
- `REMOTE_ADDR` client IP as a string; `UNIQUE_ID` opaque string unique per transaction (v2 Apache `mod_unique_id`, v3 `UniqueId` SHA-1 hex or timestamp+counter, Coraza `stringutils.RandomString(19)`), format unspecified, MUST be non-empty.
- `DURATION` (Extended): v2 microseconds of wall-clock since request start (`apr_time_now() - r->request_time`); v3 CPU seconds as a floating-point string (`utils::cpu_seconds()`); Coraza always `"0"` (`waf.go`). Units unspecified; new **ADR-0019** records it as Extended with unspecified units and a recommendation.

**Tests** (`tests/engine/variables/`, ids 6000–6099): `args.yaml` (GET and POST, repeated key, `&` count, `ARGS_NAMES`, `ARGS_COMBINED_SIZE`), `request-line.yaml` (`REQUEST_URI`, `REQUEST_URI_RAW`, `REQUEST_FILENAME`, `REQUEST_BASENAME`, `QUERY_STRING`, `REQUEST_METHOD`, `REQUEST_PROTOCOL`, `REQUEST_LINE`), `request-headers.yaml`, `request-cookies.yaml` (incl. duplicate cookie name), `request-body.yaml` (`REQUEST_BODY`, `REQUEST_BODY_LENGTH`, `REQBODY_PROCESSOR` for urlencoded and JSON via ctl), `multipart.yaml` (`FILES`, `FILES_NAMES`, `FILES_COMBINED_SIZE`, `MULTIPART_PART_HEADERS`, `MULTIPART_STRICT_ERROR` with a malformed body), `matched-vars.yaml`, `tx-and-capture.yaml`, `response.yaml` (`RESPONSE_STATUS`, `RESPONSE_HEADERS`, `RESPONSE_BODY`), `xml.yaml` (needs `ctl:requestBodyProcessor=XML`), `remote-addr-unique-id.yaml` (`REMOTE_ADDR` with `dest_addr`/client IP: the engine schema has no client IP field — add `input.remote_addr` to `engine.schema.json` in this task; `UNIQUE_ID "!@streq "` fires). Each Core variable gets a per-test `spec:` anchor. Persistent collections get no test (Extended).

**ADR-0007 (Divergence, Extended):** persistent collections `IP`, `SESSION`, `USER`, `GLOBAL`, `RESOURCE` with `initcol`, `setsid`, `setuid`, `setrsc`, `expirevar`-on-collections, `SecDataDir`, `SecCollectionTimeout`: implemented by v2 (SDBM), v3 (in-memory per process, LMDB optional), absent in Coraza. Decision: Extended as one feature `persistent-collections`; `requires:` anchor `05-variables.md#persistent-collections`; CRS v4 core does not use them (plugins do).
**ADR-0008 (Divergence):** collection keys match case-insensitively (above). Test: `tests/engine/variables/key-case.yaml` (`ARGS:Foo` matches `?foo=1` and `?FOO=1`; `REQUEST_HEADERS:x-test` matches `X-Test`).
**ADR-0019 (Clarification):** `DURATION` Extended, units unspecified; recommend milliseconds for new implementations.

- [ ] Steps: write tests → validator RED → write `spec/05-variables.md` (index + sections) → ADRs 0007, 0008, 0019 + index rows → apply variable statuses to `compat/matrix.json` and regenerate → GREEN → commit `spec: variables with tests; ADR-0007, ADR-0008, ADR-0019`.

---

### Task 3: `spec/06-operators.md`, imported operator unit tests, regex dialect ADR

**Status table (44 names; `pmf` and `ipMatchF` are aliases listed under their canonical names, rows without status):**

| Status | Operators |
|---|---|
| **Core (20)** | beginsWith contains detectSQLi detectXSS endsWith eq ge gt le lt ipMatch pm pmFromFile rx streq unconditionalMatch validateByteRange validateUrlEncoding validateUtf8Encoding within |
| **Extended (18)** | geoLookup inspectFile ipMatchFromFile noMatch rbl strmatch validateSchema (three engines, unused by CRS); containsWord fuzzyHash rsub validateDTD validateHash verifyCC verifyCPF verifySSN (v2+v3) |
| **Deprecated (1)** | gsbLookup |
| **Engine-specific (6)** | v3: rxGlobal verifySVNR; Coraza: ipMatchFromDataset pmFromDataset restpath validateNid |

**Facts:** numeric operators parse the target and the value as integers, non-numeric → 0 (v2 `atoi`, v3 `std::stoi` with catch, Coraza `strconv.Atoi` ignoring the error); `@pm`/`@pmFromFile` case-insensitive, `|hex|` escapes, file: one phrase per line, `#` comments; `@within` is "value is one of the space-separated words in the parameter"? **verify**: v2 `within` tests whether the *input* is a substring of the *parameter*; `@contains` the reverse; `@validateByteRange` ranges `a-b` and single values, comma separated, matches when any byte is **outside**; `@validateUrlEncoding` matches on invalid `%XX`; `@validateUtf8Encoding` matches on invalid UTF-8 including overlong forms; `@ipMatch` IPv4/IPv6 with CIDR, comma-separated; `@detectSQLi`/`@detectXSS` via libinjection (v2, v3) and its Go port (Coraza): same library, same fingerprints, Core; `@rx` captures into `TX:0..9` only with `capture`; `@streq`/`@contains`/`@beginsWith`/`@endsWith`/`@within`/numeric expand macros (02-grammar).

**Regex dialect, ADR-0018 (Divergence):** v2 PCRE, v3 PCRE2 (`configure.ac`), Coraza Go `regexp` (RE2). Decision: the Core `@rx` syntax is the RE2-compatible subset (no lookaround, no backreferences, no possessive quantifiers, no `\K`, no recursion, no `(?<name>)`-only differences — Go accepts `(?P<name>)` and `(?<name>)`; PCRE accepts both); CRS v4 is written within it (crs-toolchain). PCRE-only features are Extended per engine; a Core test MUST NOT use them. `(?i)` and other inline flags shared by both are Core. Unit cases: keep every imported `rx` case that is RE2-compatible; move the rest to `rx-pcre-extra.json` anchored to an `#rx-pcre-extensions` Extended section.

**Import:** run `uv run python tools/import_sts.py /Users/fzipitria/Workspace/OWASP/modsecurity/modsecurity/test/test-cases/secrules-language-tests` after writing `06-operators.md` (anchors come from the headings). Expected: ~3,900 operator cases across ~24 files (names without an anchor, i.e. Deprecated/Engine-specific ones such as `gsbLookup`, `rxGlobal`, `verifysvnr`, are skipped). Then review the `ipMatch` divergence found in research (`0:0::/80` vs `0000:0000:0000:0000:0000:ffff:ffff:ffff`: STS says match, Coraza says no) and write it as a divergence note with the case kept at the STS expectation. Add `operators/eq-extra.json` with the non-numeric cases (Review Focus 3) and `operators/within-extra.json`, `operators/validateByteRange-extra.json` if the corpus lacks the documented edge (verify counts).

**Engine tests** (`tests/engine/operators/`): `rx-capture.yaml` (`capture` → `TX:1`), `pmfromfile.yaml` (with `files:`), `ipmatch.yaml` (uses `input.remote_addr` from Task 2), `detect-sqli-xss.yaml` (`' or 1=1--` and `<script>`), `numeric.yaml` (`@lt`/`@gt` on `&ARGS`).

- [ ] Steps: tests + import → RED → `spec/06-operators.md` → ADR-0018 → matrix statuses → GREEN → commit `spec: operators with imported unit tests; ADR-0018 regex dialect`.

---

### Task 4: `spec/07-transformations.md`, imported transformation unit tests, ADR-0012

**Status table (38 names; `normalizePath`/`normalizePathWin` are aliases):**

| Status | Transformations |
|---|---|
| **Core (21)** | base64Decode cmdLine compressWhitespace cssDecode escapeSeqDecode hexEncode htmlEntityDecode jsDecode length lowercase none normalisePath normalisePathWin removeCommentsChar removeNulls removeWhitespace replaceComments sha1 urlDecodeUni utf8toUnicode **uppercase** (ADR-0012) |
| **Extended (13)** | base64DecodeExt base64Encode hexDecode md5 removeComments replaceNulls trim trimLeft trimRight urlDecode urlEncode (three engines, unused by CRS); parityEven7bit parityOdd7bit parityZero7bit sqlHexDecode (v2+v3) → 15 |
| **Deprecated (0)** | — |

(Recount at execution: 21 + 15 = 36 plus 2 alias rows = 38.)

**ADR-0012 (Extension):** `uppercase` (v3 and Coraza, Coraza's ADR-0007) promoted to Core as the design seeded; it is the only Core feature absent from an engine by construction and the v2 gap goes to `compat/known-gaps.md`. **Executor: if the reviewer of this plan prefers Extended, change this row and the ADR category to Clarification.**

**Facts and known divergences from the corpus diff (research 2026-10-06):** `cssDecode` differs between STS and Coraza on two inputs (`\123456` six-digit escapes: v2/v3 emit the low byte, Coraza emits U+FFFD; keep STS expectation, note); `urlDecodeUni` differs on one input (`%u` handling of full-width characters, keep STS); `base64Decode` as decided in Phase 1 (well-formed only; remove any imported malformed case into `base64Decode-divergent.json` anchored to a `#base64decode` divergence subsection? **No** — drop them; the Phase 1 decision already documents the divergence); `sha1`/`md5` outputs are raw bytes — the corpus encodes them as `\u00XX` escapes which the importer turns into real bytes; keep them (JSON can carry them). `t:none` resets inherited transformations (02-grammar). `length` returns the byte length as a decimal string. `utf8toUnicode` converts to `%uXXXX`. `urlDecodeUni` handles `%uXXXX` (with the Unicode map when configured) and `+`. `cmdLine` normalisation steps listed from the manual (remove `\ ^ ' "`, lowercase, collapse spaces, remove spaces around `/` and `(`, remove `,` and `;` as the manual lists). `normalisePath` resolves `.`/`..` and duplicate slashes without touching the query string.

- [ ] Steps: import (same converter run; transformations anchors from the new file) → hand-written extra cases for `uppercase` (none in STS; Coraza has `uppercase.json`: copy its cases) → RED → `spec/07-transformations.md` (keep the Phase 1 `base64Decode` section) → ADR-0012 → matrix statuses → GREEN → commit `spec: transformations with imported unit tests; ADR-0012 uppercase`.

---

### Task 5: `spec/08-actions.md` with `ctl:` options, action tests

**Status table (48 action names + 21 ctl options; `sanitize*` are aliases):**

| Status | Actions |
|---|---|
| **Core (25)** | allow auditlog block capture chain ctl deny drop id log logdata msg multiMatch noauditlog nolog pass phase redirect setvar severity skipAfter status t tag ver |
| **Extended (13)** | accuracy exec expirevar initcol maturity rev setenv skip (three engines); setrsc setsid setuid xmlns (v2+v3); + `initcol`/`setsid`/`setuid`/`setrsc` are also governed by ADR-0007 |
| **Deprecated (10)** | append deprecatevar marker pause prepend proxy sanitiseArg sanitiseMatched sanitiseMatchedBytes sanitiseRequestHeader sanitiseResponseHeader (ADR-0011) |
| **ctl** | per ADR-0006: Core 10, Extended 7 (+ absolute auditLogParts), Deprecated 2, Engine-specific `responseBodyProcessor`, `forceResponseBodyVariable` |

**Facts:** `setvar:tx.x=v` set; `setvar:tx.x=+n` / `=-n` arithmetic with unset treated as 0; `setvar:!tx.x` delete; names case-insensitive (ADR-0008); macro expansion in value. `severity` accepts `0`–`7` and the names `EMERGENCY ALERT CRITICAL ERROR WARNING NOTICE INFO DEBUG` (v3 scanner `ACTION_SEVERITY_VALUE`; verify v2 `re_actions.c` and Coraza `severity.go`); `HIGHEST_SEVERITY` tracks the lowest number. `capture` stores `TX:0..9`. `multiMatch` re-runs the operator after each transformation. `t:` cumulative; `t:none` resets. `status:` for `deny`/`redirect`. `log`/`nolog`, `auditlog`/`noauditlog`. `skipAfter`, `chain`, `phase`, `id`, `msg`, `logdata`, `tag`, `ver`, `pass`, `block`, `deny`, `drop`, `redirect`, `allow` as in 03. `ctl:` options: syntax and timing per 03#ctl-timing and ADR-0006; `ctl:ruleRemoveTargetById=ID;TARGETS`.

**Tests** (`tests/engine/actions/`, ids 7000–7099): `setvar.yaml` (set, +=, -=, delete, unset+1 → 1), `severity.yaml` (numeric and named, `HIGHEST_SEVERITY` Extended → no assertion on it), `capture-multimatch.yaml`, `log-flags-load.yaml` (log/nolog/auditlog/noauditlog/msg/logdata/tag/ver load), `status-redirect.yaml`, `block.yaml` (`block` with and without `SecDefaultAction`), `ctl-options.yaml` (one Core option per test entry with per-test `spec:` anchors `08-actions.md#ctl<slug>`), plus `t-none.yaml` (inherited `t:lowercase` reset by `t:none`).

- [ ] Steps: tests → RED → `spec/08-actions.md` (sections `### ctl:ruleEngine` etc. for every option) → matrix statuses for `actions` and `ctl` → GREEN → commit `spec: actions and ctl options with tests`.

---

### Task 6: ADR-0009, ADR-0010, ADR-0011; known-gaps; deferred minors

- **ADR-0009 (Clarification):** phase evaluation model: strict per-phase evaluation as in `03#phases` is normative; an engine MAY evaluate a rule's variables earlier (Coraza multiphase) only if every test in this repository observes identical results; `MATCHED_VAR*` and `TX` effects must appear in the rule's declared phase.
- **ADR-0010 (Clarification):** engine-specific names are reserved: the Engine-specific rows in every category; another engine MUST NOT reuse the name with different semantics; promotion path = Extension ADR.
- **ADR-0011 (Deprecation):** the v2-only legacy set (variables `PERF_*`, `SCRIPT_*`, `STREAM_*`, `WEBSERVER_ERROR_LOG`, `USERAGENT_IP`, `SDBM_DELETE_ERROR`, `MULTIPART_CRLF_LINE`; actions `append prepend proxy pause deprecatevar marker sanitise*`; directives already Deprecated in 04) is Deprecated: MUST parse, MAY ignore with a warning, MUST NOT be used in new rulesets.
- `compat/known-gaps.md`: add rows for Coraza `MULTIPART_UNMATCHED_BOUNDARY` (if any Core test uses it: none, so no row), `uppercase` on v2, key-case build tag on Coraza (opt-in, note only), any Core operator/transformation case that the corpus diff showed Coraza failing (`cssDecode` ×2, `urlDecodeUni` ×1, `ipMatch` ×1).
- Deferred minors from the Phase 2 review: `04#secauditlogdirmode` 0750; `04#secresponsebodymimetype` case comparison unspecified; ADR-0006 note on Coraza absolute form and the 21st option; tests/README "triggered" (done in Task 1).
- [ ] Steps: write → validator GREEN → commit `adr: phase model, reserved names, v2 legacy; known-gaps and deferred fixes`.

---

## Self-review notes

- **Spec coverage:** design 4.1 files 05–08 → Tasks 2–5; 4.4 unit tier import → Tasks 1, 3, 4; 4.5 ADRs 0007–0012 → Tasks 2, 3, 4, 6 (0018, 0019 added from research); matrix statuses for all categories → each task; the directives phase's deferred minors → Task 6.
- **Review Focus mapping:** 1, 2 → Task 2 tests; 3 → Task 3 `eq-extra.json`; 4 → Task 3 (imported `pm` cases); 5 → Task 5 `setvar.yaml`.
- **Open judgment calls for the reviewer:** `uppercase` Core (ADR-0012 as designed) vs Extended; `MULTIPART_UNMATCHED_BOUNDARY` Extended although in a recommended config; `allow`/`drop`/`redirect` Core because 03 already specifies them though CRS does not use them; the RE2-subset decision for `@rx`.
