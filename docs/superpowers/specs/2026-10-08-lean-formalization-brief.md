# Lean formalization — handoff brief

Status: approach approved in conversation on 2026-10-08 ("Go for it"); the spike has not
started. This file is the starting point for a fresh session. Read `AGENTS.md` first.

## 1. Decision so far

Formalize the specification in **Lean 4**, incrementally, starting with a **spike** that
proves the approach pays off before any chapter is committed to it:

- A Lake project under `formal/` with no Mathlib dependency (keep builds fast; the
  executable parts need only core Lean and `Std`).
- Five transformations as `ByteArray → ByteArray` definitions: `lowercase`, `hexEncode`,
  `urlDecodeUni`, `cssDecode`, `base64Decode` (6 + 3 + 32 + 6 + 4 = 51 corpus cases).
- An executable runner (`lake exe …`) that reads `tests/unit/transformations/*.json`
  (core `Lean.Json`), converts each byte string to a `ByteArray` (every code point is one
  byte; see `tests/README.md`), runs the definition, and reports mismatches. Cases for
  transformations that are not yet formalized are skipped by name, not failed.
- Outcome of the spike: either every case passes, or each mismatch is classified exactly
  as adapter disagreements are (`AGENTS.md`, "When an adapter run disagrees with the
  spec"): a corpus or spec defect is fixed in the repository, a model defect is fixed in
  Lean. The formalization is a reference, not an engine, so it gets **no** rows in
  `compat/known-gaps.md`; a surviving mismatch means something is wrong and must be
  resolved before merge.

If the spike proves out, the follow-up stages in order of value:

1. All 35 transformation files (363 cases): the first fully formal chapter (`spec/07`).
2. Lexical structure and grammar (`spec/01`, `spec/02`): a parser from directive lines to
   an AST, tested against the `rules:` blocks of every engine profile, including the
   `expect_error` ones.
3. Processing model (`spec/03`): phases, chains, `skip`/`skipAfter`, default actions,
   `ctl` timing, rule exceptions, as a small-step semantics over an abstract transaction
   with `@rx` as an oracle. Theorems for the Divergence ADRs, e.g. ADR-0016 (an unreached
   `skipAfter` ends with the phase) and ADR-0017 (the default phase is not inherited).
4. Operators other than `@rx`/`@pm*` (`spec/06`), then body processors URL-encoded and
   multipart (`spec/09`). The regex dialect (ADR-0018, RE2 subset) is deferred; XML and
   logging are out of scope.

## 2. Why Lean and not only tests

Every "unspecified" in the English text must become an explicit parameter or a
nondeterministic choice in the model, which surfaces ambiguities the prose hides. The
corpus checks the model and the model checks the corpus (the cssDecode expectation
corrected on 2026-10-07 is the kind of defect a formal definition refuses). A compiled
Lean runner is a fourth implementation independent of all three engines and, later, an
oracle for differential testing of the engines through the adapters.

## 3. Repository facts the Lean work depends on

- Unit-tier strings are **byte strings**: JSON strings whose code points are all ≤ U+00FF,
  one byte each. Encode with Latin-1, never UTF-8. The importer (`tools/import_sts.py`)
  derives them like libmodsecurity's `json2bin`; adapters MUST NOT unescape anything after
  JSON parsing. `ret` for a transformation is 1 when `output != input`.
- Transformation semantics are in `spec/07-transformations.md`, one `###` section each
  with `**Semantics.**` prose and a `**Tests.**` pointer. Known divergences are in the
  section's `**Divergence notes.**` and in `compat/known-gaps.md`; the corpus keeps the
  ModSecurity expectation in each case.
- `cssDecode.json` and `base64Decode.json` are `HAND_MAINTAINED` in the importer (edited
  by hand, not regenerated). `base64Decode` follows libmodsecurity: decode until the first
  character outside the alphabet; the spec text says exactly what to do with padding.
- The two existing adapters show how a runner is shaped and reported:
  `adapters/libmodsecurity/unit_tier.py` + `test_conformance.py` (Python),
  `adapters/coraza/unit.go` + `conformance_test.go` (Go). The Lean runner needs no
  known-gaps gating (see §1).
- Validator: `uv run python tools/validate.py` must stay at `0 error(s)`; the Lean project
  is outside its scope unless a check is added.
- CI: `.github/workflows/validate.yml`. A new job should install the toolchain with
  elan (`leanprover/lean4-action`, pinned to a commit SHA like the other third-party
  action in `pages.yml`), then `lake build` and `lake exe <runner>` from `formal/`.
  Third-party actions are pinned to full commit SHAs.
- Site: `site/` publishes `spec/`, `compat/`, `adr/`; `formal/` would not be published
  unless a page is added deliberately.

## 4. Local environment

- No Lean toolchain is installed on this machine (`elan`, `lean`, `lake` all absent).
  Install elan first (`brew install elan-init` then `elan default stable`, or the official
  `curl` installer), and pin the Lean version in `formal/lean-toolchain`.
- Hugo 0.166, Go 1.26 and `uv` are present. All Python runs through `uv`.
- Engine checkouts for source references: `~/Workspace/OWASP/modsecurity/modsecurity`
  (v2 via `git show v2/master:apache2/<file>`; v3 via `git show v3.0.16:src/<file>`),
  `~/Workspace/OWASP/coraza/coraza` (v3.8.1). A clean libmodsecurity build for the
  Python adapter lives only in a session scratchpad; rebuild from the README recipe if
  needed.

## 5. Working conventions for the next session

- Superpowers flow: this brief plays the role of the approved design conversation; next
  is the written design (`docs/superpowers/specs/2026-10-08-lean-spike-design.md`), then
  `superpowers:writing-plans`, then inline execution on a branch with a ledger, a fresh
  whole-branch review on the most capable model, one fix pass, then the
  finishing-a-development-branch menu. The maintainer has chosen "merge to main locally"
  every time and pushes themselves; never push.
- Commits end with the attribution lines in use throughout the repository (see any
  `git log -1` message).
- Keep the Lean code boring: explicit byte-level loops, no tactics beyond `decide`/`simp`
  for the spike; proofs come with the processing model, not with the transformations.

## 6. Open questions to settle in the design

- Runner output format: mirror the adapters' per-file pass/fail with a list of mismatches.
- Whether `formal/` gets its own README (yes) and a line in `AGENTS.md` (yes, once
  merged).
- Lean version pin and whether to vendor `Std` or rely on the toolchain's bundled copy.
