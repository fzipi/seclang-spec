# SecLang Specification — Project Design

Status: DRAFT for review. Date: 2026-10-06.

## 1. Brief (what you said, what I assumed)

**You said**

- This repo holds the specification for SecLang (the ModSecurity rule language).
- Survey `../modsecurity/modsecurity` and `../coraza/coraza`; list supported directives and what is missing for compatibility.
- No formal spec exists; propose one for approval.
- Record ADRs where the engines diverge and a decision is needed.
- Ship tests wherever possible so implementing engines can prove conformance.

**I assumed** (correct me)

- Three engines matter, not two: ModSecurity **v2** (`v2/master`, Apache C module),
  **libmodsecurity v3** (`v3/master`, 3.0.16+), and **Coraza** v3.8.1. v2 is still the
  de-facto reference for CRS authors, so it is in the matrix even if it is not a target.
- The spec is **descriptive first, prescriptive second**: it standardizes what the
  engines already agree on, and only legislates where they diverge (via an ADR).
- "Compatibility" means: a CRS v4 ruleset plus the recommended `.conf` files parses and
  behaves identically on any conforming engine. Features no ruleset uses (Lua, GSB,
  Guardian log) do not need to be Core.
- Tests must be **engine-agnostic data** with no runner in this repo. Each engine
  writes a small adapter; this repo only ships schemas and a validator for the data.
- Audience: engine maintainers (ModSecurity, Coraza, future implementations) and CRS
  rule authors who need to know which constructs are portable.

## 2. Survey findings

Counts are distinct names after case-folding. "All 3" is the intersection.

| Category         | v2  | v3  | Coraza | All 3 | Union |
|------------------|-----|-----|--------|-------|-------|
| Directives       | 86  | 83  | 70     | 65    | 92    |
| Actions          | 48  | 37  | 33     | 33    | 48    |
| `ctl:` options   | 19  | 11  | 19     | 10    | 20    |
| Operators        | 38  | 40  | 32     | 28    | 44    |
| Transformations  | 37  | 38  | 34     | 33    | 38    |
| Variables        | 124 | 103 | 92     | 74    | 144   |

The full per-name matrix is in Appendix A. Beyond name presence, the survey found
these divergence classes, each of which becomes an ADR candidate:

1. **Naming and case.** v3 and Coraza match directive names case-insensitively; v2
   relies on Apache (also case-insensitive). Operator/action/transformation names have
   spelling variants (`ipmatch`/`ipMatch`, `normalisePath`/`normalizePath`,
   `sanitise*`/`sanitize*`, `pmf`/`pmFromFile`, `multiMatch`/`multimatch`).
2. **Accepted-but-unimplemented directives.** Coraza accepts and ignores 7 directives
   (e.g. `SecRuleScript`, `SecArgumentSeparator`, `SecCookieFormat`,
   `SecRuleUpdateTargetByMsg`) and *rejects* `SecRemoteRules`. v3 parses several
   v2-era directives it does not act on. There is no shared rule for "unknown" vs
   "unsupported" vs "ignored".
3. **`ctl:` coverage.** v3 lacks 8 options v2 and Coraza both have
   (`requestBodyLimit`, `responseBodyAccess`, `responseBodyLimit`, `ruleRemoveByMsg`,
   `ruleRemoveTargetByMsg`, `debugLogLevel`, `hashEngine`, `hashEnforcement`).
4. **Persistent collections.** `IP`, `SESSION`, `USER`, `GLOBAL`, `RESOURCE` and
   `initcol`/`setsid`/`setuid`/`setrsc` exist in v2/v3 only. Coraza has none.
5. **Engine-specific extensions.** Coraza: `SecDataset`, `pmFromDataset`,
   `ipMatchFromDataset`, `restpath`, `validateNid`, `SecRxPreFilter`,
   `SecResponseBodyJsonDepthLimit`, `RESPONSE_ARGS`, `RES_BODY_*`, `JSON`,
   `REQUEST_XML`/`RESPONSE_XML`, `ARGS_PATH`, `MULTIPART_FILENAME_*`. v3:
   `rxGlobal`, `verifySVNR`, `SecAuditLogPrefix`, `MSC_PCRE_*`. v2: `PERF_*`,
   `SCRIPT_*`, `append`/`prepend`/`proxy`/`pause`, `sanitise*`, `deprecatevar`.
6. **Semantics with no name difference.** Coraza's own ADRs record behaviour choices
   that differ from ModSecurity: case-sensitive `ARGS` keys (opt-in), multiphase
   evaluation (opt-in), `uppercase` added, `MULTIPART_STRICT_ERROR` triggers,
   `ctl:auditLogParts` `+`/`-` syntax, regex in `ctl:ruleRemoveTarget*`. ModSecurity has
   no equivalent record. These are the hard ones; the name matrix cannot find them.
7. **Existing test corpora.** Three formats already exist and should be reused rather
   than replaced: the SecRules Test Set JSON for operators/transformations
   (`{"type":"op"|"tfn","name","param","input","ret","output"}`), the ModSecurity v3
   regression JSON (full transaction + expected debug log / HTTP code), and the
   go-ftw YAML profile that Coraza's engine tests mirror (`rules:` + stages with
   `triggered_rules`, `interruption`, `log_contains`).

## 3. Approaches considered

**A. Prose specification only** (RFC-style document per feature). Fast to start,
familiar. Rejected: nothing enforces it, and the survey shows the real divergences are
behavioural, which prose alone will not catch.

**B. Conformance-suite-first specification** — *recommended*. Every normative statement
in the spec that can be tested has a test case in a machine-readable, engine-neutral
format. Divergences are resolved by ADR and the ADR's outcome lands as a test. The spec
text is organized by feature with a status label, and "Core" is defined as the tested
intersection. This is what the request asks for and what both engines can consume with
a thin adapter (Coraza already has a profile runner; ModSecurity has a JSON runner).

**C. Formal grammar plus reference implementation.** Most rigorous, most expensive,
and a reference implementation would itself become a fourth engine to keep in sync.
Rejected for now; the grammar part is kept (Section 4.3) because the lexical rules
*are* a divergence source (quoting, escaping, line continuation, macro expansion).

## 4. Design

### 4.1 Repository layout

```
seclang-spec/
  README.md                 what this is, how to read status labels, how to run tests
  spec/
    00-conventions.md       RFC 2119 terms, status labels, versioning of the spec
    01-lexical.md           file syntax: lines, continuation, quoting, comments, Include
    02-grammar.md           EBNF for directives, SecRule, variables, operators, actions
    03-processing-model.md  phases, chains, default actions, disruptive semantics,
                            rule exceptions (RemoveBy*/UpdateTargetBy*), ctl: timing
    04-directives.md        one section per directive: syntax, default, scope, status
    05-variables.md         one section per variable/collection, selectors, & and !
    06-operators.md
    07-transformations.md
    08-actions.md           incl. ctl: sub-options
    09-body-processors.md   URLENCODED, MULTIPART, XML, JSON (+ limits/error variables)
    10-logging.md           audit log parts and error-log/debug-log minimum contract
  adr/
    README.md               process + index table
    0000-template.md
    0001-....md
  tests/
    README.md               formats, how engines adopt them
    schema/
      unit.schema.json      operator/transformation unit cases (STS-compatible)
      engine.schema.json    engine/transaction cases (YAML, go-ftw-derived)
    unit/
      operators/<name>.json
      transformations/<name>.json
    engine/
      <topic>/<case>.yaml
  tools/
    validate.py             schema-check all test files; check ADR index; check that
                            every Core feature in spec/ has >=1 test
  compat/
    matrix.md               generated from compat/matrix.json (Appendix A today)
    matrix.json
```

No build system, no runner, no dependencies beyond Python 3 stdlib for the validator
(`json`, `re`; YAML via a vendored minimal loader or PyYAML as the single optional dep —
decide in ADR-0003). CI = run `tools/validate.py`.

### 4.2 Conventions (spec/00)

- Requirement words per RFC 2119 / RFC 8174.
- Every named feature carries exactly one **status**:
  - **Core** — MUST be implemented for conformance. Initial Core = intersection of
    all three engines *and* used by CRS v4 or the recommended configs.
  - **Extended** — SHOULD implement; defined by the spec; absent in >=1 engine today.
  - **Deprecated** — defined for parsing compatibility; engines MUST accept and MAY
    ignore with a warning; no new rulesets should use it.
  - **Engine-specific** — listed in the matrix, not specified; names are reserved so
    no other engine redefines them with different semantics.
- Spec versions are `seclang-spec vMAJOR.MINOR`. Status changes are MINOR; semantic
  changes to Core are MAJOR and require an ADR.
- Feature-level conformance statement: an engine declares which Extended features it
  implements; Core is all-or-nothing.

### 4.3 Grammar (spec/01, 02)

EBNF covering: directive line, continuation (`\` at EOL), comment lines, quoted
arguments (`"` and `'`), escape handling inside quotes, `SecRule VARIABLES OPERATOR
[ACTIONS]`, variable list (`|`-separated, `!` exclusion, `&` count, `:selector`,
`:/regex/`), operator (`@name param`, implicit `@rx`, `!@` negation), action list
(`,`-separated, `name[:value]`, quoted values, `t:` ordering), macro expansion
`%{COLLECTION.key}`. Each production gets at least one engine test under
`tests/engine/lexical/`. The recent v3 scanner fix (escaped quote after macro) is
exactly the class of bug this section exists to pin down.

### 4.4 Test formats (tests/)

Two tiers, both reusing existing formats so adapters are cheap.

**Unit tier** (operators, transformations): the SecRules Test Set JSON shape, unchanged,
plus optional `"spec"` (section anchor) and `"status"` fields. Coraza and v3 can already
run this shape. Example:

```json
{"type":"tfn","name":"base64Decode","input":"VGVzdENhc2U=","output":"TestCase","ret":1,
 "spec":"07-transformations.md#base64decode"}
```

**Engine tier** (directives, variables, actions, phases, body processors, logging): YAML
derived from go-ftw / Coraza profiles. Fields: `rules` (inline SecLang), `meta`,
`tests[].stages[].input` (method, uri, headers, data, version), `output`
(`triggered_rules`, `non_triggered_rules`, `interruption{rule_id,action,status}`,
`log_contains`, `no_log_contains`, `expect_error`). Added fields: `spec` anchor and
`requires: [feature...]` so Extended tests are skipped, not failed, by engines without
the feature. Response-phase tests add `stage.response` (status, headers, body) because
neither go-ftw nor the Coraza profile model a synthetic backend response, and Core
includes phases 3–5.

What is deliberately **not** tested: audit-log byte layout, debug-log wording,
performance. Logging tests assert only on rule IDs and `msg` presence.

### 4.5 ADRs (adr/)

Reuse Coraza's template shape (Status, Date, Deciders, Category, Context, Options,
Outcome, Consequences) minus the mandatory PR-quote rule, which does not apply to a
multi-repo decision. Categories: **Divergence** (engines differ, spec picks),
**Clarification** (engines agree but behaviour was undocumented), **Deprecation**,
**Extension** (promote an engine-specific feature). Every Divergence ADR MUST name the
test file(s) that encode the outcome. Seed list, in proposed order:

| # | Title | Category |
|---|-------|----------|
| 0001 | Status labels and what "Core" means (intersection + CRS usage) | Clarification |
| 0002 | Case-insensitive matching of directive, action, operator, transformation names | Divergence |
| 0003 | Test formats: STS JSON for unit tier, go-ftw-derived YAML for engine tier | Clarification |
| 0004 | Canonical names and required aliases (`normalisePath`/`normalizePath`, `pmf`, `ipmatchf`, `sanitise*`) | Divergence |
| 0005 | Handling of unknown vs unsupported directives (error / warn-and-ignore) and the role of `SecIgnoreRuleCompilationErrors` | Divergence |
| 0006 | Core set of `ctl:` options | Divergence |
| 0007 | Persistent collections and `initcol`/`setsid`/`setuid`/`setrsc` are Extended, not Core | Divergence |
| 0008 | Case sensitivity of `ARGS`/`ARGS_NAMES` keys and header names | Divergence |
| 0009 | Phase model: strict per-phase evaluation is normative; multiphase is a permitted optimization only if observably equivalent | Divergence |
| 0010 | Engine-specific extensions are reserved, not standardized (`SecDataset`, `restpath`, `rxGlobal`, …) | Clarification |
| 0011 | v2-only legacy (`sanitise*`, `append`/`prepend`/`proxy`/`pause`, `PERF_*`, `SCRIPT_*`, Lua) is Deprecated | Deprecation |
| 0012 | `uppercase` transformation promoted to Core (v3 + Coraza; trivial for v2) | Extension |

Items 1–3 are process decisions needed before any feature text is written. Items 4–12
come from the matrix and Coraza's existing ADRs and can be approved independently.

### 4.6 Delivery phases

1. **Skeleton** — layout, conventions, ADR process, test schemas, validator, ADR
   0001–0003, generated matrix. (One PR.)
2. **Core directives and grammar** — spec/01–04 for every Core directive, with engine
   tests; ADR 0004–0006.
3. **Core variables, operators, transformations, actions** — spec/05–08; import and
   relabel the STS unit cases; ADR 0007–0012.
4. **Body processors and logging** — spec/09–10.
5. Each engine opens an adapter PR in its own repo and reports conformance.

Phase 1 is the implementation plan I would write next if you approve this design.

### 4.7 Error handling and verification of the spec repo itself

`tools/validate.py` fails CI when: a test file violates its schema; a Core feature in
`spec/` has no test; an ADR is missing from the index or has an unknown Category; the
matrix lists a Core name absent from any engine column. Nothing else.

## Appendix A — Three-way name matrix (2026-10-06)

Sources: v2 `apache2/apache2_config.c`, `re_*.c` on `v2/master`; v3 `src/parser/
seclang-scanner.ll` and `src/{actions,operators,variables}` at v3.0.16-6; Coraza
`internal/seclang/directivesmap.gen.go`, `internal/{actions,operators,
transformations}`, `types/variables` at v3.8.1.

**Directives** (92 total, 65 in all three)

- In v2 + v3, missing in Coraza: SecAuditLog2 SecCacheTransformations SecChrootDir
  SecContentInjection SecCookieV0Separator SecDisableBackendCompression SecGeoLookupDb
  SecGuardianLog SecInterceptOnError SecParseXmlIntoArgs SecRuleInheritance
  SecStatusEngine SecStreamInBodyInspection SecStreamOutBodyInspection
  SecTmpSaveUploadedFiles SecUnicodeMapFile SecXmlExternalEntity
- Coraza only: SecDataset SecIgnoreRuleCompilationErrors SecResponseBodyJsonDepthLimit
  SecRxPreFilter (also a `secunicodemap` key mapped to "unsupported")
- v2 only: SecReadStateLimit SecRequestEncoding SecUnicodeCodePage SecWriteStateLimit
- v3 only: SecAuditLogPrefix
- Coraza accepts but ignores: SecArgumentSeparator SecCookieFormat
  SecRuleUpdateTargetByMsg SecRuleScript SecRulePerfTime SecTmpDir; rejects SecRemoteRules.

**Actions** (48 total, 33 in all three)

- In v2 + v3, missing in Coraza: setrsc setsid setuid xmlns
- v2 only: append deprecatevar marker pause prepend proxy sanitiseArg sanitiseMatched
  sanitiseMatchedBytes sanitiseRequestHeader sanitiseResponseHeader (+ sanitize* aliases)

**`ctl:` options** (20 total, 10 in all three)

- In v2 + v3, missing in Coraza: parseXmlIntoArgs
- In v2 + Coraza, missing in v3: debugLogLevel hashEnforcement hashEngine
  requestBodyLimit responseBodyAccess responseBodyLimit ruleRemoveByMsg
  ruleRemoveTargetByMsg
- Coraza only: responseBodyProcessor

**Operators** (44 total, 28 in all three)

- In v2 + v3, missing in Coraza: containsWord fuzzyHash gsbLookup rsub validateDTD
  validateHash validateUtf8Encoding verifyCC verifyCPF verifySSN
- Coraza only: ipMatchFromDataset pmFromDataset restpath validateNid
- v3 only: rxGlobal verifySVNR

**Transformations** (38 total, 33 in all three)

- In v2 + v3, missing in Coraza: parityEven7bit parityOdd7bit parityZero7bit sqlHexDecode
- In v3 + Coraza, missing in v2: uppercase

**Variables** (144 total, 74 in all three)

- In v2 + v3, missing in Coraza: AUTH_TYPE FULL_REQUEST GLOBAL IP MODSEC_BUILD
  MULTIPART_BOUNDARY_QUOTED MULTIPART_BOUNDARY_WHITESPACE MULTIPART_CRLF_LF_LINES
  MULTIPART_DATA_BEFORE MULTIPART_FILE_LIMIT_EXCEEDED MULTIPART_HEADER_FOLDING
  MULTIPART_INVALID_HEADER_FOLDING MULTIPART_INVALID_PART MULTIPART_LF_LINE
  MULTIPART_MISSING_SEMICOLON MULTIPART_UNMATCHED_BOUNDARY PATH_INFO REMOTE_USER
  RESOURCE SESSION SESSIONID USER USERID WEBAPPID
- Coraza only: ARGS_PATH ARGUMENTS_LIMIT_REACHED JSON MULTIPART_DUPLICATE_PART_HEADER
  MULTIPART_FILENAME_CHARSET MULTIPART_FILENAME_LANGUAGE REQUEST_XML RES_BODY_ERROR
  RES_BODY_ERROR_MSG RES_BODY_PROCESSOR RES_BODY_PROCESSOR_ERROR
  RES_BODY_PROCESSOR_ERROR_MSG RESPONSE_ARGS RESPONSE_XML URI_PARSE_ERROR
- v2 only: MULTIPART_CRLF_LINE PERF_ALL PERF_COMBINED PERF_GC PERF_LOGGING PERF_PHASE1–5
  PERF_RULES PERF_SREAD PERF_SWRITE SCRIPT_BASENAME SCRIPT_FILENAME SCRIPT_GID
  SCRIPT_GROUPNAME SCRIPT_MODE SCRIPT_UID SCRIPT_USERNAME SDBM_DELETE_ERROR
  STREAM_INPUT_BODY STREAM_OUTPUT_BODY USERAGENT_IP WEBSERVER_ERROR_LOG
- v3 only: MSC_PCRE_ERROR MSC_PCRE_LIMITS_EXCEEDED STATUS
- In v3 + Coraza, missing in v2: REQBODY_PROCESSOR_ERROR REQBODY_PROCESSOR_ERROR_MSG
- In v2 + Coraza, missing in v3: STATUS_LINE
