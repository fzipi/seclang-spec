# Lean Formalization, Stage 4: Operators and Multipart Bodies — Design

Status: approved in conversation, 2026-10-08 ("Keep going" after stage 3; stage list in
`docs/superpowers/specs/2026-10-08-lean-formalization-brief.md` §1).

## 1. Brief

**You said.** Continue with stage 4: the operators of `spec/06-operators.md` beyond `@rx`
and `@pm`, then the body processors of `spec/09-body-processors.md` (URL-encoded, done in
stage 3, and multipart).

**Agreed.** The operator evaluation moves out of `Semantics.lean` into its own module and
grows to cover every operator the unit corpus tests and that needs no external library:
`beginsWith`, `contains`, `containsWord`, `endsWith`, `eq`, `ge`, `gt`, `le`, `lt`,
`ipMatch`, `noMatch`, `pm`, `rx` (with capture groups), `streq`, `strmatch`,
`unconditionalMatch`, `validateByteRange`, `validateUrlEncoding`, `validateUtf8Encoding`,
`verifyCC`, `verifyCPF`, `verifySSN`, `within`. `lake exe seclang-check` runs
`tests/unit/operators/*.json` the way it runs the transformations: every case of a
formalized operator is evaluated, `ret` and `re_groups` compared, files of other operators
skipped by name, and a case whose regular expression lies outside the Core subset is
reported as skipped with the reason. A multipart parser populates `ARGS_POST`, `FILES`,
`FILES_NAMES`, `FILES_COMBINED_SIZE`, `MULTIPART_PART_HEADERS` and
`MULTIPART_STRICT_ERROR`, so the four multipart profiles leave the unsupported list of
`seclang-eval`. Every disagreement is fixed in the branch as before.

**Assumptions.**

- Reference semantics is chapter 06 where it is specific; for the Extended operators whose
  entry is an outline (`containsWord`, `strmatch`, `noMatch`, `verifyCC`, `verifyCPF`,
  `verifySSN`) the algorithm is ModSecurity v2 `apache2/re_operators.c`, which
  libmodsecurity v3 ports and Coraza does not implement; the outlines are expanded to say
  what the model does.
- `detectSQLi` and `detectXSS` (libinjection), `pmFromFile`/`ipMatchFromFile` (files),
  `rbl`, `geoLookup`, `inspectFile`, `fuzzyHash`, `validateDTD`, `validateSchema`,
  `validateHash`, the Deprecated and Engine-specific operators stay outside the model; their
  files are skipped by name.
- `rx-pcre-extra.json` holds lookahead patterns (ADR-0018 extensions): its cases are
  skipped by the regex-subset rule, not failed.
- JSON and XML processors stay outside the model (the brief scopes stage 4 to URL-encoded
  and multipart); their profiles remain unsupported in `seclang-eval`.
- The multipart parser handles well-formed RFC 7578 bodies with CRLF line endings, as the
  Core tests do; it sets `MULTIPART_STRICT_ERROR` to 1 on a missing final boundary, bare LF
  line endings, or data before the first boundary, and otherwise 0.

## 2. Shape

```
formal/SecLang/Operators.lean      Oracle; evalOperator and every operator definition (moved from Semantics.lean,
                                   plus containsWord, strmatch, noMatch, verifyCC, verifyCPF, verifySSN); byName table
formal/SecLang/Semantics.lean      imports Operators; evalOperator removed
formal/SecLang/Regex.lean          scoped flag groups `(?i:...)` and mid-pattern `(?i)` (needed by rx.json)
formal/SecLang/Request.lean        parseArgs drops empty pairs (09#urlencoded); parseMultipart; phase2Store multipart branch
formal/Main.lean                   unit runner handles `type: op` cases (param, ret, re_groups, skipped regexes)
formal/EvalMain.lean               FILES*, MULTIPART_* and multipart bodies leave the unsupported lists
```

## 3. The model

**Operators** (`Operators.lean`). `evalOperator (o : Oracle) (name : String) (param v :
ByteArray) : Bool × Option (Array (Option ByteArray))` as today, extended with:

- `containsWord`: the parameter occurs at a position whose predecessor is the start or a
  non-word byte and whose successor is the end or a non-word byte; word bytes are ASCII
  alphanumerics and `_`; the empty parameter matches (v2 `msre_op_containsWord_execute`).
- `strmatch`: as `contains`. `noMatch`: false.
- `verifyCC`: the parameter is a regular expression; for each match found from each
  offset in turn, Luhn is checked over the digits of the whole match; the first Luhn-valid
  match wins (v2 `msre_op_verifyCC_execute`, `luhn_verify`).
- `verifyCPF`: the digits of each match (at most eleven taken) must be exactly eleven, not
  one of the eleven trivial sequences, and the two check digits must agree with the
  weighted sums (v2 `cpf_verify`).
- `verifySSN`: each match must hold exactly nine digits that are neither all consecutive
  ascending nor all equal, with area, group and serial non-zero, area not 666 and below
  740 (v2 `ssn_verify`).
- `rx` returns the groups the oracle gives; a non-participating group is the empty string
  when compared with `re_groups`, as the engines store an empty `TX:n`.

**Unit runner** (`Main.lean`). For a file whose cases have `type: op`: look the name up in
`Operators.byName`; unknown → `skipped (not formalized)`. Per case: `param` is a byte string
(absent → empty); evaluate; `ret` must equal the match; when `re_groups` is present and the
operator matched, the groups `0..n` must equal the listed byte strings in order. A case
whose regular expression (`rx`, `verify*`) fails `Regex.compile` is counted as skipped and
printed with its reason. Output per file: `N passed, M failed, K skipped`.

**Regex** (`Regex.lean`). `(?i:…)`, `(?s:…)`, `(?m:…)` become a `flagged` node whose
flags apply inside the group; a mid-pattern `(?i)` applies to the rest of the enclosing
sequence. Both are in the Core subset (`06#rx` lists inline flags).

**Multipart** (`Request.lean`, `09#multipart`). Boundary from the `Content-Type`
parameter (quoted or bare). The body is split on `CRLF--boundary`; the preamble before the
first `--boundary` must be empty; the last delimiter is `--boundary--`. Each part: header
lines up to the empty line (raw block kept for `MULTIPART_PART_HEADERS`), then content up
to the next delimiter. `Content-Disposition` gives `name` and optionally `filename`
(quoted values, `;`-separated). A part with `filename` adds a `FILES` member (key field,
value file name), a `FILES_NAMES` member and its content size to `FILES_COMBINED_SIZE`;
without it, an `ARGS_POST` member. `REQBODY_PROCESSOR` is `MULTIPART`; `REQUEST_BODY` is
not populated (ADR-0022). `MULTIPART_STRICT_ERROR` is `1` when the body has a bare LF line
ending, data before the first boundary or no closing delimiter, otherwise `0`.

## 4. What the model may force into the spec

- `06`: the Extended outlines for `containsWord`, `strmatch`, `verifyCC`, `verifyCPF`,
  `verifySSN` get the algorithm sentences above and their source pointers.
- `09#urlencoded`: already says an empty pair is ignored; stage 3's `parseArgs` kept it as
  a member with an empty name and is corrected here.
- Anything the 3,915 operator cases surface is classified per `AGENTS.md`.

## 5. Repository integration

- `AGENTS.md`, `README.md`, `formal/README.md`: `seclang-check` now covers operators;
  `seclang-eval` supports multipart.
- CI: unchanged (the same three executables).

## 6. Verdict criteria

`seclang-check` reports every operator file of a formalized operator with zero failures,
skipping only `detectSQLi.json`, `detectXSS.json` and the lookahead cases of
`rx-pcre-extra.json`; `seclang-eval` stays at zero mismatches with the multipart profiles
supported (unsupported count falls from 21 to 17); the transformation and grammar runs are
unchanged; validator, tools tests and the Coraza adapter stay green.
