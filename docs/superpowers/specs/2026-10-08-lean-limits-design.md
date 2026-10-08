# Lean Formalization, Stage 5: Body Limits, JSON, `@rx` Mode, File Operators — Design

Status: approved in conversation, 2026-10-08 ("Continue" after stage 4; the brief's four
stages are done, this stage closes the deferred list that drives `seclang-eval`'s
unsupported profiles).

## 1. Brief

**You said.** Continue.

**Agreed.** The model gains the features that keep 12 of the 17 unsupported profiles out
of `seclang-eval`, plus the one spec decision the stage 4 reviewer surfaced:

- `@rx` compile mode. All three engines compile `@rx` dot-all; ModSecurity v2 adds
  `DOLLAR_ENDONLY` and no multiline, libmodsecurity v3 and Coraza (default build) compile
  multiline. ADR-0027 (Divergence) makes dot-all Core, leaves `^`/`$` against values that
  contain newlines unspecified unless the pattern says `(?m)`, and the model follows the
  v2 reading (anchors only at the subject's ends). A new Core profile checks dot-all on
  the engines.
- Body limits (`04#secrequestbodylimit`, `04#secrequestbodylimitaction`,
  `04#secresponsebodylimit`, `04#secresponsebodylimitaction`): `Reject` interrupts with
  `deny` and no rule id before phase 2 (request) or phase 4 (response);
  `ProcessPartial` truncates and sets `INBOUND_DATA_ERROR` / `OUTBOUND_DATA_ERROR`. The
  processing model gets a phase-boundary hook so the interruption is part of the
  semantics, and the interruption theorem applies to it.
- JSON body processor (`09#json`): core Lean's `Json.parse`; every scalar leaf is an
  `ARGS_POST` member named by the v2 key path (the names are unspecified, ADR-0020);
  a malformed document or nesting deeper than `SecRequestBodyJsonDepthLimit` sets
  `REQBODY_ERROR` and `REQBODY_ERROR_MSG`.
- `@pmFromFile` and `@ipMatchFromFile` read the profile's `files:`; a missing file is a
  configuration error (`06#pmfromfile`).

**Assumptions.**

- Reference semantics is the spec; where it says "not specified" the model makes one
  choice named in a docstring: interruption status 413 (request) and 500 (response), as
  v2 and Coraza; `SecResponseBodyLimitAction` defaults to `Reject` (v2); JSON `null` is
  the empty string and array elements take the containing key (`array` at top level), as
  v2 `apache2/msc_json.c`; `SecRequestBodyJsonDepthLimit` defaults to 10000.
- In `DetectionOnly`, `Reject` does not interrupt and the whole body is processed
  (v2 `apache2/mod_security2.c`, the `is_enabled != MODSEC_DETECTION_ONLY` test around
  the limit).
- `SecRequestBodyNoFilesLimit` is accepted and ignored by the model (v2 applies it to
  non-multipart bodies; no Core test observes it).
- JSON members are produced in key order, not document order; no test depends on order.
- XML, `@detectSQLi`/`@detectXSS`, persistent collections and log assertions stay
  outside the model (5 profiles).

## 2. Shape

```
formal/SecLang/Regex.lean          default flags {dotAll}; `$` only at the subject end unless (?m); compile takes the default
formal/SecLang/Semantics.lean      prepare : Nat → Tx → Tx (boundary hook); phaseBody; theorems restated; body_limit_reject_quiet
formal/SecLang/Request.lean        Settings += limits and json depth; applyRequestLimit, applyResponseLimit; jsonLeaves; JSON branch
formal/SecLang/Operators.lean      Oracle.readFile; pmFromFile, ipMatchFromFile; fileLines
formal/SecLang/Syntax.lean         missing @pmFromFile/@ipMatchFromFile file is a configuration error
formal/EvalMain.lean               settings for limits; boundary hook built from the stage; shorter unsupported lists; files in the oracle
adr/0027-rx-compile-mode.md        Divergence; adr/README.md row; spec 06#rx text
tests/engine/operators/rx-dotall.yaml   Core: `a.b` matches `a%0Ab`
```

## 3. The model

**Regex.** `compile (pat) (dflt : Flags := { dotAll := true })` starts the parser with
`dflt` and wraps atoms in `flagged` only when the flags differ from `dflt`. `.eol`
matches at the subject end, or before a newline only under `multi`; the PCRE
"before a final newline" clause is removed (v2 `DOLLAR_ENDONLY`).

**Boundary hook.** `step o items prepare p tx := phaseBody o items p (prepare p tx)` with
`phaseBody` the existing body (start the phase, run the rules if the phase runs).
`prepare : Nat → Tx → Tx` populates the store and, at phases 2 and 4, applies the body
limits: `Reject` in mode `On` sets `interruption := some ⟨0, "deny", status⟩`;
`ProcessPartial` (or any limit in `DetectionOnly`) truncates the body the store is built
from and sets the error variable to `1`. `interrupted_phase_quiet` is restated on
`phaseBody`; `body_limit_reject_quiet` says a hook that sets an interruption at phase
`p ≠ 5` leaves `evaluated` unchanged.

**JSON.** `jsonLeaves : Json → List (String × String)` with v2 naming; `jsonDepth`;
`phase2Store` with processor `JSON`: parse failure → `REQBODY_ERROR = 1`,
`REQBODY_ERROR_MSG = "JSON parsing error: …"`, no members; depth above the limit →
error, no members; otherwise members under `SecArgumentsLimit`. For the other
processors `REQBODY_ERROR = 0` and the message is empty.

**File operators.** `Oracle.readFile : String → Option String` (default none);
`fileLines` drops empty and `#` lines; `pmFromFile PATH…` is `pm` over the lines of each
path, `ipMatchFromFile` is `ipMatch` over them. `parseLine` rejects a rule whose file
operator names a path absent from `files` (exact name or basename).

## 4. What the model may force into the spec

- `06#rx`: a sentence on the compile mode, ADR-0027.
- `04#secrequestbodylimitaction`: the `DetectionOnly` sentence gains "the body is
  processed in full" if the v2 source confirms it.
- Anything the 12 newly supported profiles surface is classified per `AGENTS.md`.

## 5. Repository integration

- `tests/engine/operators/rx-dotall.yaml` runs under the Coraza adapter in CI and under
  libmodsecurity locally (`src/.libs/libmodsecurity.dylib`); a failing engine gets a
  known-gaps row with a source pointer.
- `compat/matrix.json` unchanged (no new feature rows). `AGENTS.md`, `README.md`,
  `formal/README.md`: the unsupported list shrinks to XML, libinjection, persistent
  collections and log assertions.

## 6. Verdict criteria

`seclang-eval` reports 0 mismatches with 5 unsupported profiles; both unit corpora and
`seclang-parse` unchanged (0 failed, 103/0); the theorems compile; validator, tools tests,
both adapters and the Hugo smoke test stay green.
