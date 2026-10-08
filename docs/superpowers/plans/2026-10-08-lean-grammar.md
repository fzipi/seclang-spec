# Lean Stage 2: Lexical Structure and Grammar Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Lean lexer and parser for SecLang configuration text (spec 01, 02, the directive table of 04 and the name tables of 05–08) whose accept/reject verdict matches every engine profile's `expect_error` expectation, run by `lake exe seclang-parse` in CI.

**Architecture:** `tools/engine_rules.py` turns the YAML profiles into one JSON file. `SecLang/Names.lean` holds the vocabulary tables with case-insensitive, alias-aware lookup. `SecLang/Syntax.lean` holds the AST, the lexer over `List Char` (structural recursion, no index proofs), the per-argument parsers and the configuration assembly with its cross-directive checks. `ParseMain.lean` is the runner. Spec fixes ride with the task that forces them.

**Tech Stack:** Lean `v4.34.1` (`export PATH="$HOME/.elan/bin:$PATH"`), Lake 5; Python via `uv` (PyYAML already a dependency).

**Spec:** `docs/superpowers/specs/2026-10-08-lean-grammar-design.md`; normative text `spec/01-lexical.md`, `spec/02-grammar.md`, `spec/03-processing-model.md` (chains, default actions, rule exceptions, disruptive actions), `spec/04-directives.md`; ADR-0002, 0004, 0005, 0013, 0014, 0015.

## Global Constraints

- No new Lean dependency; strings in the AST are Lean `String`s built from the profile text (UTF-8); every lexing decision is made on ASCII delimiters, so a byte-string reader can be swapped in later.
- Every "MUST be a configuration error" in chapters 01–04 that is decidable from text is a `.error` with a message naming the rule; messages are prose, not codes.
- Unknown names: directives, variables, operators, actions, `ctl` options and transformations whose status is Engine-specific are "not defined" (ADR-0005 rule 3) and rejected; Deprecated and Extended ones are accepted.
- Guards first, watched failing. Every commit passes `cd formal && lake build`, and from Task 4 on `lake exe seclang-parse .lake/engine-rules.json`; the validator stays at 0 errors; tools tests pass; the Coraza adapter is rerun when a profile changes.
- Commit messages end with the two attribution lines. Never push.

## Review Focus

1. A continued comment line (`# SecRule … \` then a second physical line). Expected: the whole logical line is dropped, nothing from the second line is parsed (ADR-0013); guard in Task 2.
2. A quoted argument immediately followed by text (`"abc"def`). Expected: configuration error, not a silent merge; guard in Task 2.
3. `SecRule` whose action list has two disruptive actions (`deny,drop`). Expected: configuration error naming the rule; guard in Task 4.
4. `Include` of a file that itself includes a missing file. Expected: the error names the missing path and the line in the including file; guard in Task 4.
5. A `SecDefaultAction` for a phase given by name (`phase:request`) followed by one for `phase:2`. Expected: rejected as a second default action for phase 2; guard in Task 4.

---

### Task 1: Extractor, second executable, vocabulary tables

**Files:**
- Create: `tools/engine_rules.py`, `tools/test_engine_rules.py`, `formal/SecLang/Names.lean`, `formal/ParseMain.lean` (stub)
- Modify: `formal/lakefile.toml`, `formal/SecLang.lean`

**Interfaces:**
- Produces: `SecLang.Status`, `SecLang.ArgKind`, `SecLang.Shape`, `SecLang.VarShape`, `SecLang.ValueKind`, `SecLang.ActionClass`, `SecLang.CtlKind`; tables `directives`, `variables`, `operators`, `actions`, `ctlOptions`, `transformations`; lookups `findDirective : String → Option (String × Shape)`, `findVariable : String → Option (String × VarShape)`, `findOperator : String → Option String`, `findAction : String → Option (String × ValueKind × ActionClass)`, `findCtl : String → Option (String × CtlKind)`, `findTransformation : String → Option String` (all return the canonical spelling; `none` for unknown or Engine-specific).

- [ ] **Step 1: Extractor test (RED)** — `tools/test_engine_rules.py`:

```python
import json
import tempfile
import unittest
from pathlib import Path

from tools import engine_rules

PROFILE = """meta:
  name: x
  description: y
rules: |
  SecRuleEngine On
  Include a.conf
files:
  a.conf: |
    SecRule ARGS "@streq 1" "id:1,phase:1,pass"
tests:
  - test_title: t
    stages:
      - stage:
          input: {}
          output:
            expect_error: true
"""


class ExtractTests(unittest.TestCase):
    def test_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tests" / "engine" / "d").mkdir(parents=True)
            (root / "tests" / "engine" / "d" / "p.yaml").write_text(PROFILE)
            out = engine_rules.extract(root)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["path"], "tests/engine/d/p.yaml")
        self.assertEqual(out[0]["rules"], "SecRuleEngine On\nInclude a.conf\n")
        self.assertEqual(out[0]["files"], {"a.conf": 'SecRule ARGS "@streq 1" "id:1,phase:1,pass"\n'})
        self.assertTrue(out[0]["expect_error"])
        json.dumps(out)
```

`uv run python -m unittest tools.test_engine_rules` → `ModuleNotFoundError`.

- [ ] **Step 2: Extractor** — `tools/engine_rules.py`:

```python
"""Extract every engine profile's configuration for the Lean parser (formal/ParseMain.lean).

Usage: uv run python tools/engine_rules.py > formal/.lake/engine-rules.json
Output: a JSON list of {path, rules, files, expect_error}; expect_error is true when any
stage of the profile asserts expect_error.
"""
import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools import validate  # noqa: E402


def extract(root: Path) -> list[dict]:
    out = []
    for path in sorted((root / "tests" / "engine").rglob("*.yaml")):
        d = yaml.safe_load(path.read_text())
        expect = any(s["stage"]["output"].get("expect_error", False) for t in d["tests"] for s in t["stages"])
        out.append({
            "path": path.relative_to(root).as_posix(),
            "rules": d["rules"],
            "files": d.get("files") or {},
            "expect_error": bool(expect),
        })
    return out


if __name__ == "__main__":
    json.dump(extract(validate.ROOT), sys.stdout, indent=1, ensure_ascii=False)
    print()
```

`uv run python -m unittest tools.test_engine_rules` → OK. `uv run python tools/engine_rules.py | head -c 300` shows the first profile.

- [ ] **Step 3: Lake** — `formal/lakefile.toml`: `defaultTargets = ["seclang-check", "seclang-parse"]` and a second block `[[lean_exe]]` / `name = "seclang-parse"` / `root = "ParseMain"`. `formal/ParseMain.lean` stub: `import SecLang` + `def main (_ : List String) : IO UInt32 := return 0`. `formal/SecLang.lean` adds `import SecLang.Names`.

- [ ] **Step 4: Names.lean guards (RED)** — create `formal/SecLang/Names.lean` with only:

```lean
import SecLang.Bytes
/-! Vocabulary of the specification: every defined name with its status and what the
parser needs to know about it (`spec/04`–`spec/08`). Lookup is case-insensitive (ADR-0002)
and resolves the aliases of ADR-0004; an Engine-specific name is not found (ADR-0005). -/
namespace SecLang

#guard (findDirective "secrule").map (·.1) == some "SecRule"
#guard (findDirective "SecFrobnicate").isNone
#guard (findDirective "SecRxPreFilter").isNone            -- Engine-specific
#guard (findDirective "SecHashEngine").map (·.1) == some "SecHashEngine"   -- Deprecated, accepted
#guard (findVariable "args_get") == some ("ARGS_GET", .collection)
#guard (findVariable "REQUEST_URI") == some ("REQUEST_URI", .scalar)
#guard (findVariable "JSON").isNone
#guard findOperator "PMF" == some "pmFromFile"
#guard findOperator "ipmatchf" == some "ipMatchFromFile"
#guard (findOperator "restpath").isNone
#guard (findAction "DENY").map (·.1) == some "deny"
#guard (findAction "deny").map (·.2.2) == some ActionClass.disruptive
#guard (findAction "msg").map (·.2.2) == some ActionClass.metadata
#guard (findCtl "RULEENGINE").map (·.1) == some "ruleEngine"
#guard (findCtl "responseBodyProcessor").isNone
#guard findTransformation "normalizePath" == some "normalisePath"
#guard findTransformation "NONE" == some "none"

end SecLang
```

`lake build` → unknown identifiers.

- [ ] **Step 5: Tables** (insert above the guards). Statuses and the raw syntax come from the chapters; shapes are the Syntax lines reduced to the parser's needs. Deprecated directives are checked for arity only (`text`), per `spec/00-conventions.md` ("MUST be accepted by the parser. MAY be ignored").

```lean
inductive Status | core | extended | deprecated | engineSpecific
  deriving Repr, BEq, DecidableEq

/-- Value kinds of single directive arguments (`spec/04` Syntax lines). -/
inductive ArgKind
  | onOff | onOffDetectionOnly | onOffRelevantOnly | onOffOnlyArgs | rejectProcessPartial
  | nativeJson | serialConcurrent | abortWarn | zeroOne | nat | level09 | octal | auditParts
  | char | text
  deriving Repr, BEq, DecidableEq

/-- Argument shape of a directive. -/
inductive Shape
  | none | one (k : ArgKind) | two | oneOrTwo | twoOrThree | oneOrMore
  | actions | defaultActions | idRanges | idRangesActions | idRangesTargets | regexTargets
  | rule | include
  deriving Repr, BEq

inductive VarShape | collection | scalar | unspecified
  deriving Repr, BEq, DecidableEq

/-- Value kind of an action (`spec/08` Syntax lines). -/
inductive ValueKind
  | none | allow | id | phase | severity | nat | transformation | ctl | setvar | label | text
  deriving Repr, BEq, DecidableEq

inductive ActionClass | disruptive | metadata | flow | other
  deriving Repr, BEq, DecidableEq

inductive CtlKind
  | onOff | onOffDetectionOnly | onOffRelevantOnly | onOffOnlyArgs | parts | processor | nat
  | idRange | idRangeTargets | text | textTargets
  deriving Repr, BEq, DecidableEq

def directives : List (String × Status × Shape) := [
  ("Include", .core, .include), ("SecAction", .core, .actions),
  ("SecComponentSignature", .core, .one .text), ("SecDefaultAction", .core, .defaultActions),
  ("SecMarker", .core, .one .text), ("SecRule", .core, .rule),
  ("SecRuleRemoveById", .core, .idRanges), ("SecRuleRemoveByMsg", .extended, .one .text),
  ("SecRuleRemoveByTag", .core, .one .text), ("SecRuleUpdateActionById", .core, .idRangesActions),
  ("SecRuleUpdateTargetById", .core, .idRangesTargets), ("SecRuleUpdateTargetByMsg", .extended, .regexTargets),
  ("SecRuleUpdateTargetByTag", .core, .regexTargets),
  ("SecArgumentSeparator", .core, .one .char), ("SecArgumentsLimit", .core, .one .nat),
  ("SecRequestBodyAccess", .core, .one .onOff), ("SecRequestBodyLimit", .core, .one .nat),
  ("SecRequestBodyLimitAction", .core, .one .rejectProcessPartial), ("SecRequestBodyNoFilesLimit", .core, .one .nat),
  ("SecRequestBodyInMemoryLimit", .extended, .one .nat), ("SecRequestBodyJsonDepthLimit", .core, .one .nat),
  ("SecResponseBodyAccess", .core, .one .onOff), ("SecResponseBodyLimit", .core, .one .nat),
  ("SecResponseBodyLimitAction", .core, .one .rejectProcessPartial), ("SecResponseBodyMimeType", .core, .oneOrMore),
  ("SecResponseBodyMimeTypesClear", .core, .none), ("SecResponseBodyJsonDepthLimit", .engineSpecific, .one .nat),
  ("SecRuleEngine", .core, .one .onOffDetectionOnly),
  ("SecAuditEngine", .core, .one .onOffRelevantOnly), ("SecAuditLog", .core, .one .text),
  ("SecAuditLogFormat", .core, .one .nativeJson), ("SecAuditLogParts", .core, .one .auditParts),
  ("SecAuditLogRelevantStatus", .core, .one .text), ("SecAuditLogStorageDir", .core, .one .text),
  ("SecAuditLogType", .core, .one .serialConcurrent), ("SecDataDir", .core, .one .text),
  ("SecDebugLog", .core, .one .text), ("SecDebugLogLevel", .core, .one .level09),
  ("SecUploadDir", .core, .one .text), ("SecUploadFileMode", .core, .one .octal),
  ("SecUploadKeepFiles", .core, .one .onOffRelevantOnly),
  ("SecAuditLogDirMode", .extended, .one .octal), ("SecAuditLogFileMode", .extended, .one .octal),
  ("SecCollectionTimeout", .extended, .one .nat), ("SecCookieFormat", .extended, .one .zeroOne),
  ("SecCookieV0Separator", .extended, .one .char), ("SecGeoLookupDb", .extended, .one .text),
  ("SecHttpBlKey", .extended, .one .text), ("SecParseXmlIntoArgs", .extended, .one .onOffOnlyArgs),
  ("SecPcreMatchLimit", .extended, .one .nat), ("SecPcreMatchLimitRecursion", .extended, .one .nat),
  ("SecRemoteRules", .extended, .twoOrThree), ("SecRemoteRulesFailAction", .extended, .one .abortWarn),
  ("SecRuleInheritance", .extended, .one .onOff), ("SecRulePerfTime", .extended, .one .nat),
  ("SecRuleScript", .extended, .oneOrTwo), ("SecSensorId", .extended, .one .text),
  ("SecServerSignature", .extended, .one .text), ("SecTmpDir", .extended, .one .text),
  ("SecTmpSaveUploadedFiles", .extended, .one .onOff), ("SecUnicodeMapFile", .extended, .two),
  ("SecUploadFileLimit", .extended, .one .nat), ("SecWebAppId", .extended, .one .text),
  ("SecXmlExternalEntity", .extended, .one .onOff),
  ("SecAuditLog2", .deprecated, .one .text), ("SecCacheTransformations", .deprecated, .oneOrMore),
  ("SecChrootDir", .deprecated, .one .text), ("SecConnEngine", .deprecated, .one .text),
  ("SecConnReadStateLimit", .deprecated, .oneOrTwo), ("SecConnWriteStateLimit", .deprecated, .oneOrTwo),
  ("SecContentInjection", .deprecated, .one .text), ("SecDisableBackendCompression", .deprecated, .one .text),
  ("SecGsbLookupDb", .deprecated, .one .text), ("SecGuardianLog", .deprecated, .one .text),
  ("SecHashEngine", .deprecated, .one .text), ("SecHashKey", .deprecated, .oneOrTwo),
  ("SecHashMethodPm", .deprecated, .two), ("SecHashMethodRx", .deprecated, .two),
  ("SecHashParam", .deprecated, .one .text), ("SecInterceptOnError", .deprecated, .one .text),
  ("SecReadStateLimit", .deprecated, .one .text), ("SecRequestEncoding", .deprecated, .one .text),
  ("SecStatusEngine", .deprecated, .one .text), ("SecStreamInBodyInspection", .deprecated, .one .text),
  ("SecStreamOutBodyInspection", .deprecated, .one .text), ("SecUnicodeCodePage", .deprecated, .one .text),
  ("SecWriteStateLimit", .deprecated, .one .text),
  ("SecAuditLogPrefix", .engineSpecific, .one .text), ("SecDataset", .engineSpecific, .one .text),
  ("SecIgnoreRuleCompilationErrors", .engineSpecific, .one .text), ("SecRxPreFilter", .engineSpecific, .one .text)]

def variables : List (String × Status × VarShape) := [
  <the 149 rows generated from spec 05: Core rows with .collection/.scalar from their Semantics
   sentence ("Collection…", "Per-transaction read-write collection" → .collection; "Scalar:" → .scalar),
   every Extended, Deprecated and Engine-specific row .unspecified; see the executor's
   generated listing in the ledger workspace>]

def operators : List (String × Status) := [
  ("beginsWith", .core), ("contains", .core), ("detectSQLi", .core), ("detectXSS", .core),
  ("endsWith", .core), ("eq", .core), ("ge", .core), ("gt", .core), ("ipMatch", .core), ("le", .core),
  ("lt", .core), ("pm", .core), ("pmFromFile", .core), ("rx", .core), ("streq", .core),
  ("unconditionalMatch", .core), ("validateByteRange", .core), ("validateUrlEncoding", .core),
  ("validateUtf8Encoding", .core), ("within", .core),
  ("containsWord", .extended), ("fuzzyHash", .extended), ("geoLookup", .extended), ("inspectFile", .extended),
  ("ipMatchFromFile", .extended), ("noMatch", .extended), ("rbl", .extended), ("strmatch", .extended),
  ("validateDTD", .extended), ("validateHash", .extended), ("validateSchema", .extended),
  ("verifyCC", .extended), ("verifyCPF", .extended), ("verifySSN", .extended),
  ("rsub", .deprecated), ("gsbLookup", .deprecated),
  ("ipMatchFromDataset", .engineSpecific), ("pmFromDataset", .engineSpecific), ("restpath", .engineSpecific),
  ("rxGlobal", .engineSpecific), ("validateNid", .engineSpecific), ("verifySVNR", .engineSpecific)]

/-- ADR-0004 aliases, lower-cased alias → canonical. -/
def operatorAliases : List (String × String) := [("pmf", "pmFromFile"), ("ipmatchf", "ipMatchFromFile")]
def transformationAliases : List (String × String) :=
  [("normalizepath", "normalisePath"), ("normalizepathwin", "normalisePathWin")]

def actions : List (String × Status × ValueKind × ActionClass) := [
  ("allow", .core, .allow, .disruptive), ("auditlog", .core, .none, .other), ("block", .core, .none, .disruptive),
  ("capture", .core, .none, .other), ("chain", .core, .none, .flow), ("ctl", .core, .ctl, .other),
  ("deny", .core, .none, .disruptive), ("drop", .core, .none, .disruptive), ("id", .core, .id, .other),
  ("log", .core, .none, .other), ("logdata", .core, .text, .metadata), ("msg", .core, .text, .metadata),
  ("multiMatch", .core, .none, .other), ("noauditlog", .core, .none, .other), ("nolog", .core, .none, .other),
  ("pass", .core, .none, .disruptive), ("phase", .core, .phase, .other), ("redirect", .core, .text, .disruptive),
  ("setvar", .core, .setvar, .other), ("severity", .core, .severity, .metadata), ("skipAfter", .core, .label, .flow),
  ("status", .core, .nat, .other), ("t", .core, .transformation, .other), ("tag", .core, .text, .metadata),
  ("ver", .core, .text, .metadata),
  ("accuracy", .extended, .nat, .metadata), ("exec", .extended, .text, .other), ("expirevar", .extended, .text, .other),
  ("initcol", .extended, .text, .other), ("maturity", .extended, .nat, .metadata), ("rev", .extended, .text, .metadata),
  ("setenv", .extended, .text, .other), ("setrsc", .extended, .text, .other), ("setsid", .extended, .text, .other),
  ("setuid", .extended, .text, .other), ("skip", .extended, .nat, .flow), ("xmlns", .extended, .text, .other),
  ("append", .deprecated, .text, .other), ("deprecatevar", .deprecated, .text, .other), ("marker", .deprecated, .text, .other),
  ("pause", .deprecated, .text, .other), ("prepend", .deprecated, .text, .other), ("proxy", .deprecated, .text, .other),
  ("sanitiseArg", .deprecated, .text, .other), ("sanitiseMatched", .deprecated, .none, .other),
  ("sanitiseMatchedBytes", .deprecated, .text, .other), ("sanitiseRequestHeader", .deprecated, .text, .other),
  ("sanitiseResponseHeader", .deprecated, .text, .other)]

def ctlOptions : List (String × Status × CtlKind) := [
  ("auditEngine", .core, .onOffRelevantOnly), ("auditLogParts", .core, .parts),
  ("forceRequestBodyVariable", .core, .onOff), ("requestBodyAccess", .core, .onOff),
  ("requestBodyProcessor", .core, .processor), ("ruleEngine", .core, .onOffDetectionOnly),
  ("ruleRemoveById", .core, .idRange), ("ruleRemoveByTag", .core, .text),
  ("ruleRemoveTargetById", .core, .idRangeTargets), ("ruleRemoveTargetByTag", .core, .textTargets),
  ("debugLogLevel", .extended, .nat), ("parseXmlIntoArgs", .extended, .onOffOnlyArgs),
  ("requestBodyLimit", .extended, .nat), ("responseBodyAccess", .extended, .onOff),
  ("responseBodyLimit", .extended, .nat), ("ruleRemoveByMsg", .extended, .text),
  ("ruleRemoveTargetByMsg", .extended, .textTargets),
  ("hashEnforcement", .deprecated, .text), ("hashEngine", .deprecated, .text),
  ("forceResponseBodyVariable", .engineSpecific, .text), ("responseBodyProcessor", .engineSpecific, .text)]

def transformations : List (String × Status) := [
  ("base64Decode", .core), ("cmdLine", .core), ("compressWhitespace", .core), ("cssDecode", .core),
  ("escapeSeqDecode", .core), ("hexEncode", .core), ("htmlEntityDecode", .core), ("jsDecode", .core),
  ("length", .core), ("lowercase", .core), ("none", .core), ("normalisePath", .core), ("normalisePathWin", .core),
  ("removeCommentsChar", .core), ("removeNulls", .core), ("removeWhitespace", .core), ("replaceComments", .core),
  ("sha1", .core), ("uppercase", .core), ("urlDecodeUni", .core), ("utf8toUnicode", .core),
  ("base64DecodeExt", .extended), ("base64Encode", .extended), ("hexDecode", .extended), ("md5", .extended),
  ("parityEven7bit", .extended), ("parityOdd7bit", .extended), ("parityZero7bit", .extended),
  ("removeComments", .extended), ("replaceNulls", .extended), ("sqlHexDecode", .extended), ("trim", .extended),
  ("trimLeft", .extended), ("trimRight", .extended), ("urlDecode", .extended), ("urlEncode", .extended)]

/-- The row whose name equals `s` ignoring case, unless its status is Engine-specific. -/
def findRow (rows : List (String × Status × α)) (s : String) : Option (String × α) :=
  let l := s.toLower
  match rows.find? fun r => r.1.toLower == l with
  | some (n, st, x) => if st == .engineSpecific then none else some (n, x)
  | none => none

def findDirective (s : String) : Option (String × Shape) := findRow directives s
def findVariable (s : String) : Option (String × VarShape) := findRow variables s

def findNamed (rows : List (String × Status)) (aliases : List (String × String)) (s : String) : Option String :=
  let s := (aliases.lookup s.toLower).getD s
  (findRow (rows.map fun (n, st) => (n, st, ())) s).map (·.1)

def findOperator : String → Option String := findNamed operators operatorAliases
def findTransformation : String → Option String := findNamed transformations transformationAliases
def findAction (s : String) : Option (String × ValueKind × ActionClass) := findRow actions s
def findCtl (s : String) : Option (String × CtlKind) := findRow ctlOptions s
```

The `variables` table is pasted from the generated listing (ledger workspace, or regenerate with the Python snippet in the ledger). `lake build` → success, guards pass.

- [ ] **Step 6: Commit** — `feat(formal): vocabulary tables and the engine-profile extractor`.

---

### Task 2: Lexer

**Files:**
- Create: `formal/SecLang/Syntax.lean`
- Modify: `formal/SecLang.lean` (`import SecLang.Syntax`)

**Interfaces:**
- Produces: `SecLang.ConfigError` (`line : Nat`, `msg : String`), `abbrev Parse := Except ConfigError`, `structure Line` (`num : Nat`, `text : List Char`), `logicalLines : String → List Line`, `splitArgs : Line → Parse (List String)` (first element is the directive name).

- [ ] **Step 1: Guards (RED)**

```lean
#guard (logicalLines "a\r\nb\n\n  # c\nd \\\n  e\n# f \\\n  g\nh").map (fun l => (l.num, String.mk l.text))
  == [(1, "a"), (2, "b"), (5, "d   e"), (9, "h")]
#guard (logicalLines "x \\").map (fun l => String.mk l.text) == ["x "]
#guard (splitArgs ⟨1, "SecRule   ARGS_GET:a\t\"@streq 1\"     \"id:1,phase:1\"".toList⟩).toOption
  == some ["SecRule", "ARGS_GET:a", "@streq 1", "id:1,phase:1"]
#guard (splitArgs ⟨1, "SecRule ARGS \"@streq say \\\"hi\\\" now\" \"x\"".toList⟩).toOption
  == some ["SecRule", "ARGS", "@streq say \"hi\" now", "x"]
#guard (splitArgs ⟨1, "SecRule ARGS \"a\\\\b\"".toList⟩).toOption == some ["SecRule", "ARGS", "a\\\\b"]
#guard (splitArgs ⟨3, "SecRule ARGS \"unterminated".toList⟩) matches .error ⟨3, _⟩
#guard (splitArgs ⟨4, "SecRule \"abc\"def".toList⟩) matches .error ⟨4, _⟩
#guard (splitArgs ⟨1, "SecArgumentSeparator ;".toList⟩).toOption == some ["SecArgumentSeparator", ";"]
```

(Line 5 of the first guard: `d \` joins `  e` keeping both whitespace runs, `d ` + `  e` = `d   e`; the comment `# f \` swallows `  g` (ADR-0013); `h` is physical line 9.)

- [ ] **Step 2: Lexer**

```lean
import SecLang.Names
/-! AST, lexer and parser for SecLang configuration text (`spec/01-lexical.md`,
`spec/02-grammar.md`, `spec/04-directives.md`). -/
namespace SecLang

structure ConfigError where
  line : Nat
  msg : String
  deriving Repr, BEq

abbrev Parse := Except ConfigError

def isBlank (c : Char) : Bool := c == ' ' || c == '\t'

/-- A logical line with the number of the physical line it starts on. -/
structure Line where
  num : Nat
  text : List Char

/-- Physical lines: split on LF, a trailing CR dropped (`01#lines-and-directives`). -/
def physicalLines (s : String) : List (List Char) :=
  (s.splitOn "\n").map fun l => (if l.endsWith "\r" then l.dropRight 1 else l).toList

def dropTrailingBlanks (cs : List Char) : List Char := (cs.reverse.dropWhile isBlank).reverse

/-- Logical lines: continuation joined first (`01#line-continuation`, ADR-0013), then blank
and comment lines dropped (`01#comments`). -/
def logicalLines (s : String) : List Line :=
  go (physicalLines s) 1 none
where
  go : List (List Char) → Nat → Option Line → List Line
    | [], _, none => []
    | [], _, some l => emit l
    | p :: rest, n, acc =>
      let t := dropTrailingBlanks p
      let cur : Line := match acc with
        | none => ⟨n, t⟩
        | some l => ⟨l.num, l.text ++ t⟩
      if t.getLast? == some '\\' then
        go rest (n + 1) (some ⟨cur.num, cur.text.dropLast⟩)
      else emit cur ++ go rest (n + 1) none
  emit (l : Line) : List Line :=
    match l.text.dropWhile isBlank with
    | [] => []
    | '#' :: _ => []
    | body => [⟨l.num, dropTrailingBlanks body⟩]

/-- The directive name and its arguments (`01#quoting-and-escapes`, `02` `directive`). -/
def splitArgs (l : Line) : Parse (List String) := go l.text [] []
where
  err (m : String) : Parse (List String) := .error ⟨l.num, m⟩
  /-- `cs` remaining, `cur` the argument being built (reversed) or empty, `acc` finished (reversed). -/
  go : List Char → List Char → List String → Parse (List String)
    | [], [], acc => .ok acc.reverse
    | [], cur, acc => .ok (String.mk cur.reverse :: acc).reverse
    | c :: rest, cur, acc =>
      if isBlank c then
        if cur.isEmpty then go rest [] acc else go rest [] (String.mk cur.reverse :: acc)
      else if c == '"' && cur.isEmpty then quoted rest [] acc
      else go rest (c :: cur) acc
  quoted : List Char → List Char → List String → Parse (List String)
    | [], _, _ => err "unterminated quoted argument"
    | '\\' :: '"' :: rest, cur, acc => quoted rest ('"' :: cur) acc
    | '\\' :: c :: rest, cur, acc => quoted rest (c :: '\\' :: cur) acc
    | '"' :: rest, cur, acc =>
      match rest with
      | [] => .ok (String.mk cur.reverse :: acc).reverse
      | c :: _ => if isBlank c then go rest [] (String.mk cur.reverse :: acc)
                  else err "a closing quote must be followed by whitespace"
    | c :: rest, cur, acc => quoted rest (c :: cur) acc
```

`lake build` → success. If the mutual recursion in `splitArgs` needs it, add `termination_by` on the list length (both functions consume `cs`); otherwise mark `partial`.

- [ ] **Step 3: Commit** — `feat(formal): lexer for lines, continuation, comments and quoted arguments`.

---

### Task 3: Argument parsers

**Files:**
- Modify: `formal/SecLang/Syntax.lean`

**Interfaces:**
- Produces: `Selector`, `Variable`, `Operator`, `Action`, `parseVariables : Nat → String → Parse (List Variable)`, `parseOperator : Nat → String → Parse Operator`, `parseActions : Nat → String → Parse (List Action)`, `parseRanges : Nat → List String → Parse (List (Nat × Nat))`, `checkArg : Nat → ArgKind → String → Parse Unit`, `phaseNumber : String → Option Nat`.

- [ ] **Step 1: Guards (RED)**

```lean
#guard (parseVariables 1 "ARGS_GET:a|!ARGS_GET:skip|&TX:/^x/|XML://@*").toOption ==
  some [⟨false, false, "ARGS_GET", some (.key "a")⟩, ⟨true, false, "ARGS_GET", some (.key "skip")⟩,
        ⟨false, true, "TX", some (.regex "^x")⟩, ⟨false, false, "XML", some (.xpath "//@*")⟩]
#guard (parseVariables 1 "REQUEST_URI:x") matches .error _          -- selector on a scalar
#guard (parseVariables 1 "ARGS:/unterminated") matches .error _
#guard (parseVariables 1 "NOPE") matches .error _
#guard (parseVariables 1 "!&ARGS") matches .error _
#guard (parseVariables 1 "args_get") matches .ok [⟨false, false, "ARGS_GET", none⟩]
#guard (parseOperator 1 "@streq  a b").toOption == some ⟨false, "streq", "a b"⟩
#guard (parseOperator 1 "!@PMF words.txt").toOption == some ⟨true, "pmFromFile", "words.txt"⟩
#guard (parseOperator 1 "!^abc$").toOption == some ⟨true, "rx", "^abc$"⟩
#guard (parseOperator 1 "@detectSQLi").toOption == some ⟨false, "detectSQLi", "">
#guard (parseOperator 1 "@nope x") matches .error _
#guard (parseOperator 1 "@ipMatch 192.0.2.1,198.51.100.0/24,2001:db8::/32") matches .ok _
#guard (parseOperator 1 "@ipMatch 192.0.2.1,10.0.0.0/100") matches .error _
#guard (parseOperator 1 "@validateByteRange 9,10,13,32-126") matches .ok _
#guard (parseOperator 1 "@validateByteRange 9,x") matches .error _
#guard (parseActions 1 "id:1, phase:request,deny,status:403,msg:'a, b \\' c',t:LOWERCASE,ctl:ruleEngine=Off").toOption ==
  some [⟨"id", some "1"⟩, ⟨"phase", some "request"⟩, ⟨"deny", none⟩, ⟨"status", some "403"⟩,
        ⟨"msg", some "a, b ' c"⟩, ⟨"t", some "lowercase"⟩, ⟨"ctl", some "ruleEngine=Off"⟩]
#guard (parseActions 1 "id:'7',severity:'WARNING',redirect:https://x/,setvar:!tx.d,setvar:tx.e=%{tx.a},allow:phase") matches .ok _
#guard (parseActions 1 "nope") matches .error _
#guard (parseActions 1 "id:0") matches .error _
#guard (parseActions 1 "phase:6") matches .error _
#guard (parseActions 1 "severity:8") matches .error _
#guard (parseActions 1 "t:frobnicate") matches .error _
#guard (parseActions 1 "ctl:responseBodyProcessor=X") matches .error _
#guard (parseActions 1 "ctl:ruleRemoveTargetById=7150;ARGS_GET:a") matches .ok _
#guard (parseActions 1 "ctl:ruleRemoveById=200-100") matches .error _
#guard (parseActions 1 "setvar:tx") matches .error _
#guard (parseRanges 1 ["5010", "5012-5013"]).toOption == some [(5010, 5010), (5012, 5013)]
#guard (parseRanges 1 ["200-100"]) matches .error _
#guard (checkArg 1 .auditParts "AXYZ") matches .error _
#guard (checkArg 1 .auditParts "ABIJDEFHZ") matches .ok _
#guard (checkArg 1 .onOffDetectionOnly "detectiononly") matches .ok _
#guard (checkArg 1 .octal "0600") matches .ok _
#guard (checkArg 1 .octal "0699") matches .error _
```

(`t:` values are stored lower-cased canonical: `t:LOWERCASE` → `lowercase`.)

- [ ] **Step 2: Parsers**

```lean
inductive Selector
  | key (k : String) | regex (re : String) | xpath (p : String)
  deriving Repr, BEq

structure Variable where
  negate : Bool
  count : Bool
  collection : String      -- canonical spelling
  selector : Option Selector
  deriving Repr, BEq

structure Operator where
  negate : Bool
  name : String            -- canonical spelling
  param : String
  deriving Repr, BEq

structure Action where
  name : String            -- canonical spelling
  value : Option String    -- quotes removed; `t:` values canonical
  deriving Repr, BEq

def err (line : Nat) (m : String) : Parse α := .error ⟨line, m⟩

def isIdentChar (c : Char) : Bool := c.isAlphanum || c == '_'

/-- `02#variable-list`, `02#variable-selectors`. -/
def parseVariable (line : Nat) (s : String) : Parse Variable := do
  let (negate, s) := if s.startsWith "!" then (true, s.drop 1) else (false, s)
  let (count, s) := if s.startsWith "&" then (true, s.drop 1) else (false, s)
  if s.startsWith "!" || s.startsWith "&" then err line s!"'&' and '!' are mutually exclusive in '{s}'"
  let (name, sel) := match s.splitOn ":" with
    | [c] => (c, none)
    | c :: rest => (c, some (":".intercalate rest))
    | [] => ("", none)
  if name.isEmpty || !name.toList.all isIdentChar then err line s!"invalid variable name '{name}'"
  let some (canon, shape) := findVariable name | err line s!"unknown variable '{name}'"
  let selector ← match sel with
    | none => pure none
    | some sel =>
      if shape == .scalar then err line s!"'{canon}' is a scalar and takes no selector"
      else if canon == "XML" then pure (some (.xpath sel))
      else if sel.startsWith "/" then
        if sel.length ≥ 2 && sel.endsWith "/" then pure (some (.regex ((sel.drop 1).dropRight 1)))
        else err line s!"unterminated regular expression selector '{sel}'"
      else if sel.isEmpty || sel.toList.any (fun c => isBlank c) then err line s!"invalid selector '{sel}'"
      else pure (some (.key sel))
  return ⟨negate, count, canon, selector⟩

def parseVariables (line : Nat) (s : String) : Parse (List Variable) :=
  (s.splitOn "|").mapM (parseVariable line)

def natOf? (s : String) : Option Nat := if s.isEmpty then none else s.toNat?

/-- IPv4 `a.b.c.d`. -/
def isIPv4 (s : String) : Bool :=
  let parts := s.splitOn "."
  parts.length == 4 && parts.all fun p => (natOf? p).any (· ≤ 255) && p.length ≤ 3

/-- IPv6: hex groups of 1–4 digits, at most one `::`, at most 8 groups, optional IPv4 tail. -/
def isIPv6 (s : String) : Bool :=
  let halves := s.splitOn "::"
  let groupsOk (g : String) : Bool :=
    g.isEmpty || (g.splitOn ":").all fun h => !h.isEmpty && h.length ≤ 4 && h.toList.all (fun c => (hexVal c.toNat.toUInt8).isSome)
  let count (g : String) : Nat := if g.isEmpty then 0 else (g.splitOn ":").length
  match halves with
  | [a] =>
    let parts := a.splitOn ":"
    match parts.getLast? with
    | some last => if last.contains '.' then isIPv4 last && parts.length == 7 && groupsOk (":".intercalate parts.dropLast)
                   else parts.length == 8 && groupsOk a
    | none => false
  | [a, b] =>
    let (bHead, tail4) := match (b.splitOn ":").getLast? with
      | some last => if last.contains '.' then (":".intercalate (b.splitOn ":").dropLast, if isIPv4 last then 2 else 99) else (b, 0)
      | none => (b, 0)
    groupsOk a && groupsOk bHead && count a + count bHead + tail4 ≤ 7
  | _ => false

/-- `06#ipmatch`: every entry an address with an optional in-range prefix (ADR-0024). -/
def checkIpMatch (line : Nat) (param : String) : Parse Unit :=
  (param.splitOn ",").forM fun e => do
    let e := e.trim
    let (addr, prefix) := match e.splitOn "/" with
      | [a] => (a, none) | [a, p] => (a, some p) | _ => ("", some "x")
    let max := if addr.contains ':' then 128 else 32
    let ok := (if addr.contains ':' then isIPv6 addr else isIPv4 addr) &&
      match prefix with | none => true | some p => (natOf? p).any (· ≤ max)
    if !ok then err line s!"invalid @ipMatch entry '{e}'" else pure ()

/-- `06#validatebyterange`: decimal bytes or `LOW-HIGH` ranges. -/
def checkByteRange (line : Nat) (param : String) : Parse Unit := do
  if param.trim.isEmpty then err line "@validateByteRange needs at least one range"
  (param.splitOn ",").forM fun r => do
    let ok := match r.trim.splitOn "-" with
      | [a] => (natOf? a).any (· ≤ 255)
      | [a, b] => match natOf? a, natOf? b with | some x, some y => x ≤ y && y ≤ 255 | _, _ => false
      | _ => false
    if !ok then err line s!"invalid @validateByteRange entry '{r}'" else pure ()

/-- `02#operator`. -/
def parseOperator (line : Nat) (s : String) : Parse Operator := do
  let (negate, s) := if s.startsWith "!" then (true, s.drop 1) else (false, s)
  if !s.startsWith "@" then return ⟨negate, "rx", s⟩
  let body := (s.drop 1).toList
  let name := String.mk (body.takeWhile fun c => !isBlank c)
  let param := String.mk ((body.dropWhile fun c => !isBlank c).dropWhile isBlank)
  let some canon := findOperator name | err line s!"unknown operator '@{name}'"
  if canon == "ipMatch" then checkIpMatch line param
  if canon == "validateByteRange" then checkByteRange line param
  return ⟨negate, canon, param⟩

/-- Split an action list on commas outside single quotes (`02#action-list`). -/
def splitActions (s : String) : List String := go s.toList [] [] false
where
  go : List Char → List Char → List String → Bool → List String
    | [], cur, acc, _ => (String.mk cur.reverse :: acc).reverse
    | '\\' :: '\'' :: rest, cur, acc, inQ => go rest ('\'' :: '\\' :: cur) acc inQ
    | '\'' :: rest, cur, acc, inQ => go rest ('\'' :: cur) acc (!inQ)
    | ',' :: rest, cur, acc, false => go rest [] (String.mk cur.reverse :: acc) false
    | c :: rest, cur, acc, inQ => go rest (c :: cur) acc inQ

/-- Strip one pair of single quotes and unescape `\'`. -/
def unquoteValue (v : String) : String :=
  if v.length ≥ 2 && v.startsWith "'" && v.endsWith "'" then
    ((v.drop 1).dropRight 1).replace "\\'" "'"
  else v

def phaseNumber (v : String) : Option Nat :=
  match v.toLower with
  | "1" => some 1 | "2" => some 2 | "3" => some 3 | "4" => some 4 | "5" => some 5
  | "request" => some 2 | "response" => some 4 | "logging" => some 5 | _ => none

def severityNames : List String :=
  ["emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"]

def oneOf (choices : List String) (v : String) : Bool := choices.contains v.toLower

/-- `08#ctl` and the `ctl:` option sections. -/
def checkCtl (line : Nat) (v : String) : Parse String := do
  let (opt, val) := match v.splitOn "=" with
    | [o] => (o, "") | o :: rest => (o, "=".intercalate rest) | [] => ("", "")
  let some (canon, kind) := findCtl opt | err line s!"unknown ctl option '{opt}'"
  let targetsOk (t : String) : Parse Unit := (parseVariables line t).map fun _ => ()
  let rangeOk (r : String) : Parse Unit := (parseRanges line [r]).map fun _ => ()
  match kind with
  | .onOff => if oneOf ["on", "off"] val then pure () else err line s!"ctl:{canon} takes On or Off"
  | .onOffDetectionOnly => if oneOf ["on", "off", "detectiononly"] val then pure () else err line s!"ctl:{canon} takes On, Off or DetectionOnly"
  | .onOffRelevantOnly => if oneOf ["on", "off", "relevantonly"] val then pure () else err line s!"ctl:{canon} takes On, Off or RelevantOnly"
  | .onOffOnlyArgs => if oneOf ["on", "off", "onlyargs"] val then pure () else err line s!"ctl:{canon} takes On, Off or OnlyArgs"
  | .parts => if val.length ≥ 2 && (val.startsWith "+" || val.startsWith "-") then checkArg line .auditParts (val.drop 1)
              else err line s!"ctl:auditLogParts takes +LETTERS or -LETTERS"
  | .processor => if oneOf ["urlencoded", "xml", "json"] val then pure () else err line s!"ctl:requestBodyProcessor takes URLENCODED, XML or JSON"
  | .nat => if (natOf? val).isSome then pure () else err line s!"ctl:{canon} takes a number"
  | .idRange => rangeOk val
  | .idRangeTargets => match val.splitOn ";" with
    | [r, t] => do rangeOk r; targetsOk t
    | _ => err line s!"ctl:{canon} takes ID;TARGET"
  | .textTargets => match val.splitOn ";" with
    | [_, t] => targetsOk t
    | _ => err line s!"ctl:{canon} takes REGEX;TARGET"
  | .text => pure ()
  return s!"{canon}={val}"

/-- `08#setvar`: `[!]COLL.key[=VALUE]`. -/
def checkSetvar (line : Nat) (v : String) : Parse Unit := do
  let (del, v) := if v.startsWith "!" then (true, v.drop 1) else (false, v)
  let (target, value) := match v.splitOn "=" with
    | [t] => (t, none) | t :: rest => (t, some ("=".intercalate rest)) | [] => ("", none)
  if !target.contains '.' || target.startsWith "." || target.endsWith "." then err line s!"setvar target '{target}' is not COLL.key"
  if del && value.isSome then err line s!"setvar:!{target} takes no value"
  pure ()

/-- One action (`02#action-list`, value kinds from `08`). -/
def parseAction (line : Nat) (raw : String) : Parse Action := do
  let s := raw.trim
  let (name, value) := match s.splitOn ":" with
    | [n] => (n.trim, none) | n :: rest => (n.trim, some (unquoteValue (":".intercalate rest))) | [] => ("", none)
  let some (canon, kind, _) := findAction name | err line s!"unknown action '{name}'"
  let need (what : String) : Parse String := match value with
    | some v => pure v | none => err line s!"{canon} needs a value: {what}"
  match kind with
  | .none => return ⟨canon, value⟩
  | .allow => match value with
    | none => return ⟨canon, none⟩
    | some v => if oneOf ["phase", "request"] v then return ⟨canon, some v.toLower⟩ else err line "allow takes phase or request"
  | .id => let v ← need "a positive integer"
           if (natOf? v).any (· > 0) then return ⟨canon, some v⟩ else err line s!"invalid id '{v}'"
  | .phase => let v ← need "1-5, request, response or logging"
              if (phaseNumber v).isSome then return ⟨canon, some v⟩ else err line s!"invalid phase '{v}'"
  | .severity => let v ← need "0-7 or a level name"
                 if (natOf? v).any (· ≤ 7) || oneOf severityNames v then return ⟨canon, some v⟩ else err line s!"invalid severity '{v}'"
  | .nat => let v ← need "a number"
            if (natOf? v).isSome then return ⟨canon, some v⟩ else err line s!"{canon} takes a number, not '{v}'"
  | .transformation => let v ← need "a transformation name"
                       let some t := findTransformation v | err line s!"unknown transformation '{v}'"
                       return ⟨canon, some t⟩
  | .ctl => let v ← need "OPTION=VALUE"
            return ⟨canon, some (← checkCtl line v)⟩
  | .setvar => let v ← need "COLL.key=VALUE"
               checkSetvar line v
               return ⟨canon, some v⟩
  | .label => let v ← need "a label"
              if v.isEmpty then err line s!"{canon} needs a label" else return ⟨canon, some v⟩
  | .text => return ⟨canon, value⟩

def parseActions (line : Nat) (s : String) : Parse (List Action) :=
  (splitActions s).mapM (parseAction line)

/-- `ID` or `A-B` with `A <= B` (`03#rule-exceptions`). -/
def parseRanges (line : Nat) (args : List String) : Parse (List (Nat × Nat)) :=
  args.mapM fun a => match a.splitOn "-" with
    | [x] => match natOf? x with | some n => pure (n, n) | none => err line s!"invalid rule id '{a}'"
    | [x, y] => match natOf? x, natOf? y with
      | some m, some n => if m ≤ n then pure (m, n) else err line s!"invalid range '{a}': start greater than end"
      | _, _ => err line s!"invalid range '{a}'"
    | _ => err line s!"invalid range '{a}'"

/-- Single directive arguments by kind (`04`). -/
def checkArg (line : Nat) (k : ArgKind) (v : String) : Parse Unit :=
  let enum (choices : List String) : Parse Unit :=
    if oneOf choices v then pure () else err line s!"'{v}' is not one of {choices}"
  match k with
  | .onOff => enum ["on", "off"]
  | .onOffDetectionOnly => enum ["on", "off", "detectiononly"]
  | .onOffRelevantOnly => enum ["on", "off", "relevantonly"]
  | .onOffOnlyArgs => enum ["on", "off", "onlyargs"]
  | .rejectProcessPartial => enum ["reject", "processpartial"]
  | .nativeJson => enum ["native", "json"]
  | .serialConcurrent => enum ["serial", "concurrent"]
  | .abortWarn => enum ["abort", "warn"]
  | .zeroOne => enum ["0", "1"]
  | .nat => if (natOf? v).isSome then pure () else err line s!"'{v}' is not a number"
  | .level09 => if (natOf? v).any (· ≤ 9) then pure () else err line s!"'{v}' is not a level 0-9"
  | .octal => if !v.isEmpty && v.toList.all (fun c => '0' ≤ c && c ≤ '7') then pure () else err line s!"'{v}' is not an octal mode"
  | .auditParts => if !v.isEmpty && v.toList.all (fun c => ('A' ≤ c && c ≤ 'K') || c == 'Z') then pure ()
                   else err line s!"invalid audit log parts '{v}': letters A-K and Z only"
  | .char => if v.length == 1 then pure () else err line s!"'{v}' is not a single character"
  | .text => pure ()
```

`lake build` → success. Mutual recursion between `checkCtl` and `parseVariables`/`parseRanges` is not present (they are defined earlier); order the definitions as above.

- [ ] **Step 3: Commit** — `feat(formal): parsers for variables, operators, actions, ranges and directive arguments`.

---

### Task 4: Configuration assembly, runner, first run

**Files:**
- Modify: `formal/SecLang/Syntax.lean`, `formal/ParseMain.lean`, `spec/02-grammar.md`

**Interfaces:**
- Produces: `Rule`, `Directive`, `Config`, `parseConfig : (String → Option String) → String → Parse Config`, `lake exe seclang-parse FILE`.

- [ ] **Step 1: Guards (RED)**

```lean
def noFiles : String → Option String := fun _ => none
#guard (parseConfig noFiles "SecRuleEngine On\nSecRule ARGS \"@streq 1\" \"id:1,phase:1,deny,status:403,chain\"\n  SecRule ARGS:b \"@streq 2\"\nSecAction \"id:2,phase:1,pass\"") matches .ok _
#guard (parseConfig noFiles "SecRule ARGS \"@streq 1\" \"phase:1,pass\"") matches .error ⟨1, _⟩
#guard (parseConfig noFiles "SecRule ARGS \"@streq 1\" \"id:1,phase:1,pass\"\nSecRule ARGS \"@streq 1\" \"id:1,phase:1,pass\"") matches .error ⟨2, _⟩
#guard (parseConfig noFiles "SecRule ARGS \"@streq 1\" \"id:1,phase:1,deny,drop\"") matches .error _
#guard (parseConfig noFiles "SecRule ARGS \"@streq 1\" \"id:1,phase:1,pass,chain\"\nSecRule ARGS \"@streq 2\" \"id:2\"") matches .error ⟨2, _⟩
#guard (parseConfig noFiles "SecDefaultAction \"phase:1,log\"") matches .error _
#guard (parseConfig noFiles "SecDefaultAction \"log,deny\"") matches .error _
#guard (parseConfig noFiles "SecDefaultAction \"phase:request,log,deny\"\nSecDefaultAction \"phase:2,log,pass\"") matches .error ⟨2, _⟩
#guard (parseConfig noFiles "SecDefaultAction \"phase:1,log,deny,t:none\"") matches .error _
#guard (parseConfig noFiles "SecFrobnicate On") matches .error _
#guard (parseConfig noFiles "SecRuleEngine On Off") matches .error _
#guard (parseConfig noFiles "SecRuleRemoveById 200-100") matches .error _
#guard (parseConfig noFiles "SecAuditLogParts AXYZ") matches .error _
#guard (parseConfig (fun p => if p == "a.conf" then some "Include b.conf\n" else none) "Include a.conf") matches .error ⟨1, _⟩
#guard (parseConfig (fun p => if p == "a.conf" then some "SecRule ARGS \"@streq 1\" \"id:5,phase:1,pass\"\n" else none)
          "SecRuleEngine On\nInclude a.conf\nSecRule ARGS \"@streq 1\" \"id:5,phase:1,pass\"") matches .error ⟨3, _⟩
#guard (parseConfig (fun p => if p == "x1.conf" || p == "x2.conf" then some "SecRuleEngine On\n" else none) "Include x*.conf") matches .ok _
#guard (parseConfig noFiles "Include none*.conf") matches .error _
#guard (parseConfig noFiles "SecMarker END\nSecRuleUpdateTargetById 1-3 \"!ARGS:x|REQUEST_HEADERS:y\"\nSecRuleUpdateActionById 4 \"pass\"\nSecResponseBodyMimeType text/plain text/html\nSecResponseBodyMimeTypesClear") matches .ok _
```

- [ ] **Step 2: Assembly**

```lean
structure Rule where
  line : Nat
  variables : List Variable          -- empty for SecAction
  operator : Option Operator         -- none for SecAction
  actions : List Action
  chainMember : Bool
  deriving Repr

inductive Directive
  | rule (r : Rule)
  | defaultAction (line : Nat) (phase : Nat) (actions : List Action)
  | marker (line : Nat) (label : String)
  | removeById (line : Nat) (ranges : List (Nat × Nat))
  | removeByTag (line : Nat) (regex : String)
  | removeByMsg (line : Nat) (regex : String)
  | updateActionById (line : Nat) (ranges : List (Nat × Nat)) (actions : List Action)
  | updateTargetById (line : Nat) (ranges : List (Nat × Nat)) (targets : List Variable)
  | updateTargetByTag (line : Nat) (regex : String) (targets : List Variable)
  | updateTargetByMsg (line : Nat) (regex : String) (targets : List Variable)
  | setting (line : Nat) (name : String) (args : List String)
  deriving Repr

structure Config where
  directives : List Directive
  deriving Repr

/-- Parser state across directives: open chain, ids seen, default-action phases seen. -/
structure St where
  pendingChain : Bool := false
  ids : List Nat := []
  defaultPhases : List Nat := []

def metadataNames : List String := ["msg", "tag", "severity", "logdata", "rev", "ver", "accuracy", "maturity"]

def has (as : List Action) (n : String) : Bool := as.any (·.name == n)
def disruptives (as : List Action) : List Action :=
  as.filter fun a => (findAction a.name).any (·.2.2 == .disruptive)

/-- Rule-level checks (`02#secrule-structure`, `03#chains`, `03#disruptive-actions`, ADR-0015). -/
def checkRule (line : Nat) (as : List Action) (st : St) : Parse St := do
  if (disruptives as).length > 1 then err line "more than one disruptive action"
  if st.pendingChain then
    for n in ["id", "phase"] ++ metadataNames do
      if has as n then err line s!"a chain member must not carry '{n}'"
    if !(disruptives as).isEmpty then err line "a chain member must not carry a disruptive action"
    return { st with pendingChain := has as "chain" }
  else
    let some idv := (as.find? (·.name == "id")).bind (·.value) | err line "rule without an id (ADR-0015)"
    let id := (natOf? idv).getD 0
    if st.ids.contains id then err line s!"duplicate rule id {id}"
    return { st with pendingChain := has as "chain", ids := id :: st.ids }

/-- `03#default-actions`, ADR-0014. -/
def checkDefaultAction (line : Nat) (as : List Action) (st : St) : Parse (Nat × St) := do
  let some pv := (as.find? (·.name == "phase")).bind (·.value) | err line "SecDefaultAction needs a phase"
  let phase := (phaseNumber pv).getD 0
  if (disruptives as).length != 1 then err line "SecDefaultAction needs exactly one disruptive action"
  for n in ["chain", "skip", "skipAfter", "t", "id"] ++ metadataNames do
    if has as n then err line s!"SecDefaultAction must not carry '{n}'"
  if st.defaultPhases.contains phase then err line s!"a second SecDefaultAction for phase {phase}"
  return (phase, { st with defaultPhases := phase :: st.defaultPhases })

/-- Files matching `PATH` with one `*`, in lexicographic order; a plain path matches itself. -/
def resolveInclude (files : List String) (path : String) : List String :=
  match path.splitOn "*" with
  | [_] => if files.contains path then [path] else []
  | [pre, suf] => (files.filter fun f => f.startsWith pre && f.endsWith suf && f.length ≥ pre.length + suf.length).mergeSort (· < ·)
  | _ => []

/-- One logical line into directives (an `Include` yields the included file's directives). -/
partial def parseLine (files : List (String × String)) (depth : Nat) (st : St) (l : Line) : Parse (List Directive × St) := do
  let args ← splitArgs l
  let line := l.num
  let name :: rest := args | return ([], st)
  let some (canon, shape) := findDirective name | err line s!"unknown directive '{name}' (ADR-0005)"
  let arity (lo hi : Nat) : Parse Unit :=
    if rest.length < lo || rest.length > hi then err line s!"{canon} takes {if lo == hi then toString lo else s!"{lo} to {hi}"} argument(s), got {rest.length}" else pure ()
  match shape with
  | .rule =>
    arity 2 3
    let vars ← parseVariables line rest[0]!
    let op ← parseOperator line rest[1]!
    let acts ← if h : rest.length = 3 then parseActions line rest[2]! else pure []
    let st' ← checkRule line acts st
    return ([.rule ⟨line, vars, some op, acts, st.pendingChain⟩], st')
  | .actions =>
    arity 1 1
    let acts ← parseActions line rest[0]!
    let st' ← checkRule line acts st
    return ([.rule ⟨line, [], none, acts, st.pendingChain⟩], st')
  | .defaultActions =>
    arity 1 1
    let acts ← parseActions line rest[0]!
    let (phase, st') ← checkDefaultAction line acts st
    return ([.defaultAction line phase acts], st')
  | .include =>
    arity 1 1
    if depth == 0 then err line "Include nesting deeper than 100 files"
    let matches := resolveInclude (files.map (·.1)) rest[0]!
    if matches.isEmpty then err line s!"Include: no file matches '{rest[0]!}'"
    let mut acc : List Directive := []
    let mut s := st
    for f in matches do
      let (ds, s') ← parseText files (depth - 1) s ((files.lookup f).getD "")
      acc := acc ++ ds; s := s'
    return (acc, s)
  | .idRanges => arity 1 1000; return ([.removeById line (← parseRanges line rest)], st)
  | .idRangesActions => arity 2 2; return ([.updateActionById line (← parseRanges line [rest[0]!]) (← parseActions line rest[1]!)], st)
  | .idRangesTargets => arity 2 2; return ([.updateTargetById line (← parseRanges line [rest[0]!]) (← parseVariables line rest[1]!)], st)
  | .regexTargets =>
    arity 2 2
    let targets ← parseVariables line rest[1]!
    return ([if canon == "SecRuleUpdateTargetByTag" then .updateTargetByTag line rest[0]! targets else .updateTargetByMsg line rest[0]! targets], st)
  | .none => arity 0 0; return ([.setting line canon []], st)
  | .one k =>
    arity 1 1
    checkArg line k rest[0]!
    return ([match canon with
      | "SecMarker" => .marker line rest[0]!
      | "SecRuleRemoveByTag" => .removeByTag line rest[0]!
      | "SecRuleRemoveByMsg" => .removeByMsg line rest[0]!
      | _ => .setting line canon rest], st)
  | .two => arity 2 2; return ([.setting line canon rest], st)
  | .oneOrTwo => arity 1 2; return ([.setting line canon rest], st)
  | .twoOrThree => arity 2 3; return ([.setting line canon rest], st)
  | .oneOrMore => arity 1 1000; return ([.setting line canon rest], st)

/-- Every logical line of `text`, threading the state. -/
partial def parseText (files : List (String × String)) (depth : Nat) (st : St) (text : String) : Parse (List Directive × St) := do
  let mut acc : List Directive := []
  let mut s := st
  for l in logicalLines text do
    let (ds, s') ← parseLine files depth s l
    acc := acc ++ ds; s := s'
  return (acc, s)

/-- A configuration with its auxiliary files (`Include` paths looked up in `files`). -/
def parseConfig (files : String → Option String) (text : String) : Parse Config := do
  -- `files` as an association list for globbing: callers pass the profile's `files:` map.
  let (ds, _) ← parseText (filesList files) 100 {} text
  return ⟨ds⟩
```

`parseConfig`'s first argument is a function in the guards; make the real signature `parseConfig (files : List (String × String)) (text : String)` and change the guards to pass lists (`[]`, `[("a.conf", "…")]`). `parseLine` and `parseText` are mutually recursive through `Include`; `partial def` with the explicit `depth` fuel keeps the cap of 100 (`01#include`) and avoids a termination proof over file contents.

- [ ] **Step 3: Runner** — `formal/ParseMain.lean`:

```lean
import Lean.Data.Json
import SecLang

/-! Loads every engine profile's configuration (from `tools/engine_rules.py` JSON) and
checks the model's verdict against `expect_error`. Exit 1 on any mismatch. -/
open Lean SecLang

structure Profile where
  path : String
  rules : String
  files : List (String × String)
  expectError : Bool

def Profile.ofJson (j : Json) : Except String Profile := do
  let files ← match j.getObjVal? "files" with
    | .ok (.obj kvs) => kvs.fold (init := pure []) fun acc k v => do
        let acc ← acc
        return acc ++ [(k, ← v.getStr?)]
    | _ => pure []
  return { path := ← j.getObjVal? "path" >>= Json.getStr?, rules := ← j.getObjVal? "rules" >>= Json.getStr?,
           files, expectError := ← j.getObjVal? "expect_error" >>= Json.getBool? }

def main (args : List String) : IO UInt32 := do
  let some file := args.head? | IO.eprintln "usage: seclang-parse engine-rules.json"; return 2
  let txt ← IO.FS.readFile file
  let profiles ← IO.ofExcept (Json.parse txt >>= Json.getArr? >>= (·.mapM Profile.ofJson))
  let mut mismatches := 0
  for p in profiles do
    let verdict := parseConfig p.files p.rules
    let (accepted, text) := match verdict with
      | .ok _ => (true, "accepted")
      | .error e => (false, s!"rejected: line {e.line}: {e.msg}")
    let bad := accepted == p.expectError
    IO.println s!"{p.path}: {text}{if bad then "  <-- MISMATCH" else ""}"
    if bad then mismatches := mismatches + 1
  IO.println s!"{profiles.size} profiles, {mismatches} mismatches"
  return if mismatches == 0 then 0 else 1
```

(`Json.getBool?` exists; the `files` object is `Json.obj` holding an `RBNode`; use `kvs.fold` or `j.getObjVal? "files" >>= Json.getObj?` then `.toArray`/`.fold` as the toolchain offers.)

- [ ] **Step 4: First run** — `cd formal && lake build && mkdir -p .lake && uv run --project .. python ../tools/engine_rules.py > .lake/engine-rules.json && lake exe seclang-parse .lake/engine-rules.json | tee <scratch>/parse1.txt | grep -c MISMATCH`. Triage every mismatch: model defect (fix Lean, add a guard), profile defect (fix the YAML, rerun the Coraza adapter), spec defect (fix text). Record each in the ledger. Rerun until `102 profiles, 0 mismatches`.

- [ ] **Step 5: Spec fixes known in advance** — `spec/02-grammar.md`: in the EBNF header change "`IDENT` is one or more ASCII letters and digits" to "`IDENT` is one or more ASCII letters, digits and underscores"; add a `selector` note: after `selector = regexsel | key ;` append `(* for XML the selector is an XPath expression: 05-variables.md#xml *)`; in `### Variable selectors` Semantics add "For the `XML` collection the selector is an XPath expression (`05-variables.md#xml`) and the forms above do not apply."; in `### Variable list` Semantics add "A collection name that this specification does not define MUST be a configuration error; Engine-specific names are reserved, not defined (ADR-0005)." `uv run python tools/validate.py` → 0 errors.

- [ ] **Step 6: Commit** — `feat(formal): configuration assembly and the profile runner; spec: IDENT, XML selectors, unknown variables` (plus separate commits for any profile fix).

---

### Task 5: CI and docs

**Files:**
- Modify: `.github/workflows/validate.yml` (`lean` job), `AGENTS.md`, `README.md`, `formal/README.md`

- [ ] **Step 1: CI** — the `lean` job becomes:

```yaml
  lean:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v6
        with:
          python-version: "3.12"
      - run: uv sync
      - uses: leanprover/lean-action@f061402b660e0c34644504b324e830f2991d4865 # v1.6.1
        with:
          lake-package-directory: formal
          auto-config: "false"
          build: "true"
      - run: lake exe seclang-check
        working-directory: formal
      - run: uv run python tools/engine_rules.py > formal/.lake/engine-rules.json
      - run: lake exe seclang-parse .lake/engine-rules.json
        working-directory: formal
```

- [ ] **Step 2: Docs** — `formal/README.md`: a "Grammar" section with the two commands (`uv run python tools/engine_rules.py > formal/.lake/engine-rules.json`, `lake exe seclang-parse .lake/engine-rules.json`) and what a mismatch means (a profile the model accepts but the corpus expects to fail, or the reverse: a spec, profile or model defect, never a known-gaps row). `AGENTS.md` `formal/` row: mention `SecLang/Syntax.lean` (parser for spec 01–04 against every engine profile) and `seclang-parse`; `tools/` row: add `engine_rules.py`; "Before you commit" line: `(cd formal && lake build && lake exe seclang-check && uv run --project .. python ../tools/engine_rules.py > .lake/engine-rules.json && lake exe seclang-parse .lake/engine-rules.json)`. `README.md` `formal/` row: "…and a parser for the configuration grammar checked against every engine profile."
- [ ] **Step 3: Verify** — validator 0; `uv run python -m unittest discover -s tools -t .` OK; `(cd adapters/coraza && go test ./... -count=1)` ok; both Lean executables green; `hugo … && site/smoke.sh` passes.
- [ ] **Step 4: Commit** — `ci(formal): run the grammar check; docs: formal/ covers the grammar`.

---

### Task 6: Branch review and finish

- [ ] **Step 1: Ledger** — collect rulings and triage results.
- [ ] **Step 2: Whole-branch review** — fresh reviewer on the most capable model with the design, this plan's Review Focus and the ledger; one fix pass.
- [ ] **Step 3: Finish** — `superpowers:finishing-a-development-branch`; standing choice: merge to main locally, never push.
