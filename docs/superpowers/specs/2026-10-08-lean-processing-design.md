# Lean Formalization, Stage 3: Processing Model — Design

Status: approved in conversation, 2026-10-08 ("Keep going with stage 3"; stage list in
`docs/superpowers/specs/2026-10-08-lean-formalization-brief.md` §1).

## 1. Brief

**You said.** Continue with stage 3: the processing model (`spec/03-processing-model.md`)
as a small-step semantics over the stage 2 AST, with theorems for the Divergence ADRs
0016 and 0017.

**Agreed.** `formal/` gains an executable semantics of one transaction against a parsed
`Config`: effective rules after rule exceptions and default actions, five phases, chains,
`skip`/`skipAfter`/`SecMarker`, disruptive actions and interruptions, `allow`, engine
modes, `ctl` timing, `setvar`, `capture`, `MATCHED_VAR*`, macro expansion. The semantics
is parametric in a regular-expression oracle and reads variables from an abstract
store. A third executable, `lake exe seclang-eval`, instantiates the oracle with a
Lean matcher for the Core `@rx` subset, populates the store from each engine profile's
stage input for the Core variables that need no body processor beyond URL-encoded, and
checks `triggered_rules`, `non_triggered_rules`, `interruption` and `no_interruption`.
Three theorems are proved: ADR-0017 (a phase-less rule runs in phase 2 whatever the
default actions), ADR-0016 (a pending `skipAfter` never survives its phase), and the
interruption rule (an interruption in phases 1–4 stops the later request/response
phases while phase 5 still runs).

**Assumptions.**

- Reference semantics is the prose of chapter 03 with chapters 05, 06, 08 and 09 where
  it points there. Where the prose says "not specified" the model makes one choice,
  names it in a docstring, and no test may depend on it (`ctl:ruleEngine` within the
  current phase: the model keeps running the phase, the v3/Coraza reading;
  `MATCHED_VAR` after the rule: cleared).
- Variables the runner populates: `REQUEST_*`, `QUERY_STRING`, `REMOTE_ADDR`,
  `UNIQUE_ID`, `ARGS_GET*`, `REQUEST_HEADERS*`, `REQUEST_COOKIES*`, `ARGS*`,
  `REQUEST_BODY`, `REQUEST_BODY_LENGTH`, `REQBODY_PROCESSOR` (URL-encoded only),
  `RESPONSE_STATUS`, `RESPONSE_HEADERS`, `RESPONSE_BODY` (per `SecResponseBodyAccess` and
  `SecResponseBodyMimeType`), `TX`, `MATCHED_VAR`, `MATCHED_VAR_NAME`, `MATCHED_VARS`.
  Profiles that need `MULTIPART`, `JSON`, `XML`, body limits, persistent collections,
  `@detectSQLi`/`@detectXSS`, `@pmFromFile` with files, or log assertions are reported
  as unsupported with the reason; the runner still exits 0 for them. A supported profile
  that disagrees is a mismatch.
- Operators implemented: `@rx` (oracle), `@streq`, `@contains`, `@beginsWith`,
  `@endsWith`, `@within`, `@eq`, `@ge`, `@gt`, `@le`, `@lt`, `@pm`, `@ipMatch` (IPv4 and
  IPv6 with prefixes), `@unconditionalMatch`, `@validateByteRange`,
  `@validateUrlEncoding`, `@validateUtf8Encoding`; transformations come from stage 1.
- Values are byte strings (the stage 1 convention): the store holds `ByteArray`s
  converted from the profile text with UTF-8, and transformations apply to them directly.

## 2. Shape

```
formal/SecLang/Regex.lean          Core @rx subset matcher: Option (Array (Option ByteArray)) groups; guards
formal/SecLang/Semantics.lean      Store, Tx, Oracle, Interruption; effective rules (exceptions, default actions,
                                   chains); variable selection; operators; rule and phase evaluation; theorems
formal/SecLang/Request.lean        Request/Response → initial Store (chapters 05 and 09, URL-encoded only)
formal/EvalMain.lean               lake exe seclang-eval <engine-profiles.json>
tools/engine_rules.py              also emits each profile's tests (stages: input, response, output)
```

## 3. The model

**Effective rules** (`03#rule-exceptions`, `03#default-actions`, `03#chains`). The
`Config` is folded in order: a `rule` directive opens a chain or extends the open one; a
`removeById`/`removeByTag`/`removeByMsg` deletes chains already defined whose starter
matches; `updateTargetBy*` appends targets to the starter's variable list;
`updateActionById` merges actions into the starter with rule-over-default precedence; a
`defaultAction` is recorded per phase and merged into every later chain starter of that
phase at definition time. The result is `List Chain`, each with `id`, `phase` (own
`phase` action or 2, never from the default action), the effective action list and the
members in order. `SecMarker` directives are kept in the same ordered list so that
`skipAfter` can find them.

**Transaction state.** `Tx` carries the store, the `TX` collection, engine mode and the
mode the next phase starts with, per-transaction removals (`ctl:ruleRemove*`), the
request-body flags from phase 1 `ctl`s, the interruption, the `allow` scope, the lists of
triggered and evaluated chain ids, `MATCHED_VAR`, `MATCHED_VAR_NAME` and `MATCHED_VARS`.
The store is a function from canonical collection name to members `(key, value)`;
scalars are one-member collections with the empty key.

**Rule evaluation.** Selected values: for each variable in order, the members of the
collection restricted by the selector (key compared case-insensitively, regex on names
via the oracle, XPath never selects anything here), minus exclusions, with `&` replaced
by the count; the per-transaction target removals apply before. A rule that selects no
value does not match (`06#unconditionalmatch`). For each value the `t:` list is applied
(`t:none` resets; `multiMatch` tests after every step), then the operator with macros
expanded in its parameter; `!` negates per value; the rule matches when any value
matches, and `MATCHED_VAR*` and `capture` are set from the last matching value. On a
match the member's non-disruptive actions run: `setvar` (five forms, macros, numeric
`+`/`-`), `ctl` (removals immediate, `ruleEngine` deferred to the next phase, body flags
recorded), `capture`. A chain matches when every member matches in order; then the
starter's disruptive action applies.

**Phases.** For each phase 1–5: skip the phase when the engine mode is `Off`; otherwise
walk the ordered list with a local `skip` counter and a local pending `skipAfter` label,
both reset at phase start. A marker satisfies a pending label (markers are phase-less);
a chain whose id equals the label does too. Chains of other phases are passed over
without evaluation; chains removed statically or by `ctl` are passed over. After a match
in mode `On`: `deny`/`drop`/`redirect` set the interruption (status per `08`) and end the
phase; `allow` ends the phase and records the scope; `pass` and `block` without an
inherited disruptive action continue. In `DetectionOnly` nothing interrupts. Phases 2–4
do not run after an interruption or under an `allow`/`allow:request` scope; phase 5
always runs. `ctl:ruleEngine` takes effect at the next phase boundary.

**Theorems** (in `Semantics.lean`, proved by `simp`/`rfl` over the definitions):

- `phase_default`: a chain starter without a `phase` action has phase 2, for every
  default-action table (ADR-0017).
- `skipAfter_local`: `runPhase` starts every phase with no pending `skipAfter` and never
  returns one; equivalently the result of a phase does not depend on the skip state left
  by the previous one (ADR-0016).
- `interrupted_skips_to_logging`: if the transaction is interrupted after phase `p ≤ 4`,
  the evaluated-chain list does not change during phases `p+1`–4 and phase 5 still runs.

**Runner.** `lake exe seclang-eval FILE` reads the extended JSON. Per profile: parse the
configuration (an `expect_error` profile is reported as `skipped: expect_error`); detect
unsupported features from the configuration and the stage inputs and report
`unsupported: <reason>`; otherwise, per stage, build the request (and response) store,
run the transaction, and compare the four assertion kinds. Output one line per stage and a
final `N stages, M mismatches, K unsupported`; exit 1 on any mismatch.

## 4. What the model may force into the spec

Known questions, to be settled by the run and recorded in the branch:

- `03#flow-control`: `skipAfter` may name a rule id; the prose says "rule with
  `id:LABEL`" but `08#skipafter` says only `SecMarker`. The model implements both; the
  texts are aligned.
- A rule that selects no values under a negated operator: `06#unconditionalmatch` says a
  rule with no values never matches; `02#operator` says a negated rule matches when the
  operator is false for every value, which is vacuously true. The model follows chapter
  06; chapter 02 gets the exception.
- `block` on a chain member is already a load error; `block` as the `SecDefaultAction`
  disruptive action is accepted by the parser and behaves as `pass` in the model.

## 5. Repository integration

- `.github/workflows/validate.yml`: the `lean` job runs `seclang-eval` after
  `seclang-parse` on the same JSON (the extractor output gains the stages).
- `AGENTS.md`, `README.md`, `formal/README.md`: the third executable and what
  "unsupported" means.

## 6. Verdict criteria

Every supported stage of every profile agrees with the corpus; the unsupported list names
only body-processor, limit, persistent-collection, libinjection and log features; the
three theorems compile; validator, tools tests and the Coraza adapter stay green.
