# Lean Stage 5: Body Limits, JSON, `@rx` Mode, File Operators — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring `seclang-eval` from 17 to 5 unsupported profiles and settle the `@rx` compile mode.

**Architecture:** Regex default flags; a `Tx → Tx` phase-boundary hook in `Semantics`; limit and JSON code in `Request.lean`; file operators through the oracle; one ADR and one Core profile.

**Tech Stack:** Lean 4 v4.34.1, Lake; `Lean.Data.Json`; `uv` for Python tools.

**Spec:** `docs/superpowers/specs/2026-10-08-lean-limits-design.md`

## Global Constraints

- Byte strings: code points ≤ U+00FF, one byte each.
- Every `#guard` compiles; `lake build` is the test runner; RED before GREEN for every definition.
- Spec changes to Core need an ADR; ADR rows in `adr/README.md`; engine facts carry a source pointer with the surveyed version.
- Never push; commits carry the attribution lines.

## Review Focus

1. `@rx a$` on `a\n`: v2 (DOLLAR_ENDONLY) no match, model no match; guard in Task 1.
2. `@rx (?m)^b` on `a\nb`: match in all engines; guard in Task 1.
3. Request body exactly at the limit (10 bytes, limit 10): not over the limit, no interruption; guard in Task 2.
4. JSON body `[1,[2,[3]]]` with depth limit 2: error; `[1,[2]]`: two members; guards in Task 3.
5. `@pmFromFile a.txt b.txt` with one missing file: configuration error naming the file; guard in Task 4.

---

### Task 1: `@rx` compile mode, ADR-0027, dot-all profile

**Files:** Modify `formal/SecLang/Regex.lean`; Create `adr/0027-rx-compile-mode.md`, `tests/engine/operators/rx-dotall.yaml`; Modify `adr/README.md`, `spec/06-operators.md`.

- [ ] Guards RED: `(searchStr "a.b" "a\nb").isSome`, `(searchStr "a$" "a\n").isNone`, `(searchStr "(?m)^b" "a\nb").isSome`, `(searchStr "(?i:x).y" "X\ny").isSome`. Run `lake build` → the first and fourth fail.
- [ ] `compile (pat) (dflt := { dotAll := true })`; parser starts at `dflt`, wraps when `p.flags != dflt`; `.eol` loses the final-newline clause. Build green; `lake exe seclang-check ../tests/unit/operators` 0 failed.
- [ ] ADR-0027 (Divergence) with v2 `apache2/re_operators.c` `PCRE_DOTALL | PCRE_DOLLAR_ENDONLY`, v3.0.16 `src/utils/regex.cc` `PCRE2_DOTALL|PCRE2_MULTILINE`, Coraza v3.8.1 `internal/operators/rx.go` `(?sm)` default (`(?s)` under the `multilineregex` build tag); README row; `06#rx` sentence.
- [ ] `tests/engine/operators/rx-dotall.yaml`: `SecRule ARGS_GET:v "@rx a.b" "id:6202,phase:1,pass"`, input `/?v=a%0Ab`, triggered. Validator 0; `go test` in `adapters/coraza`; `MODSECURITY_LIB=… uv run python -m unittest discover -s adapters/libmodsecurity`.
- [ ] Commit `feat(formal): @rx compiled dot-all, anchors at subject ends; ADR-0027`.

### Task 2: boundary hook and body limits

**Files:** Modify `formal/SecLang/Semantics.lean`, `formal/SecLang/Request.lean`, `formal/EvalMain.lean`.

- [ ] Guards RED in `Request.lean`: `applyRequestLimit { requestBodyLimit := some 10 } .on "p=1&filler=0123456789"` = `(truncated to 10, false, some ⟨0, "deny", 413⟩)`; with `ProcessPartial` = `(first 10 bytes, true, none)`; with `.detectionOnly` and Reject = `(whole body, false, none)`; body of exactly 10 bytes = `(body, false, none)`; `applyResponseLimit { responseBodyLimit := some 5, responseBodyLimitAction := .processPartial } .on "0123456789"` = `("01234", true, none)`.
- [ ] `Settings += requestBodyLimit responseBodyLimit : Option Nat`, `requestBodyLimitAction responseBodyLimitAction : LimitAction := .reject`, `jsonDepthLimit : Nat := 10000`; the two functions; store sets `INBOUND_DATA_ERROR`/`OUTBOUND_DATA_ERROR` (`0` when under the limit).
- [ ] `Semantics`: `phaseBody`, `step` with `prepare : Nat → Tx → Tx`; `runTransaction`; test helpers adapt (`fun p tx => { tx with store := … }`); theorems restated; `body_limit_reject_quiet`. Build green.
- [ ] `EvalMain`: `settingsOf` parses the four directives and the depth limit; `prepare` becomes the hook applying the limits at 2 and 4; `limitDirectives` and the two error variables leave the unsupported lists. `seclang-eval` → 0 mismatches, 12 unsupported.
- [ ] Commit `feat(formal): phase-boundary hook; request and response body limits`.

### Task 3: JSON processor

**Files:** Modify `formal/SecLang/Request.lean`, `formal/EvalMain.lean`.

- [ ] Guards RED: `jsonLeaves` on `{"a":1,"b":{"c":"x"},"d":[1,2]}` = `[("a","1"),("b.c","x"),("d","1"),("d","2")]`; `jsonDepth` of `{"a":{"b":{"c":1}}}` = 3; `phase2Store` with processor `JSON` on `{"a":` → `REQBODY_ERROR = ["1"]`, non-empty message, no `ARGS_POST`; on `[1,[2,[3]]]` with depth 2 → error; `[1,[2]]` → 2 members.
- [ ] Implement; `REQBODY_ERROR`/`REQBODY_ERROR_MSG` set for every processor (0 / empty otherwise). `EvalMain`: the `ctl` check only rejects `XML`, the content-type check only `xml`, the two variables leave the list. `seclang-eval` → 0 mismatches, 7 unsupported.
- [ ] Commit `feat(formal): JSON body processor with depth limit and REQBODY_ERROR`.

### Task 4: file operators

**Files:** Modify `formal/SecLang/Operators.lean`, `formal/SecLang/Syntax.lean`, `formal/EvalMain.lean`.

- [ ] Guards RED: `fileLines "# c\nforbidden\n\nsecret word\n"` = `["forbidden", "secret word"]`; `evalOperator { testOracle with readFile := fun _ => some "forbidden\nsecret word" } "pmFromFile" "p.txt" "is FORBIDDEN"` true; `ipMatchFromFile` over `10.0.0.0/8\n` on `10.1.2.3` true; `parseConfig [("a.txt","x")] "SecRule ARGS \"@pmFromFile a.txt b.txt\" \"id:1,phase:1,pass\""` is an error mentioning `b.txt`.
- [ ] Implement; `implemented` gains both names; `EvalMain` builds the oracle with `readFile` over `p.files` (exact or basename). `seclang-eval` → 0 mismatches, 5 unsupported.
- [ ] Commit `feat(formal): @pmFromFile and @ipMatchFromFile from profile files`.

### Task 5: docs, verification, review, finish

- [ ] `formal/README.md`, `AGENTS.md`, `README.md`: unsupported list is XML, libinjection, persistent collections, log assertions; limits and JSON supported.
- [ ] Full verification (validator, tools tests, both adapters, three executables, Hugo smoke). Commit `docs(formal): stage 5 coverage`.
- [ ] Fresh reviewer (Opus) with the package, Review Focus, ledger rulings; re-grade; one fix pass RED→GREEN; ledger; `finishing-a-development-branch` (merge to main locally, no push).
