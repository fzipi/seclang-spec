# Formal model

Lean 4 definitions of the specification, executable against the conformance corpus.
Status: every transformation of `spec/07-transformations.md` (`SecLang/Transformations.lean`,
digests in `SecLang/Digest.lean`, helpers in `SecLang/Bytes.lean`) and every library-free
operator of `spec/06-operators.md` (`SecLang/Operators.lean`); design documents under
`docs/superpowers/specs/2026-10-08-lean-*.md`, roadmap in
`docs/superpowers/specs/2026-10-08-lean-formalization-brief.md`.

## Build and run

Install elan (`brew install elan-init`, or <https://github.com/leanprover/elan>); the
toolchain named in `lean-toolchain` is fetched on first build. No other dependency.

    cd formal
    lake build                                   # also evaluates every #guard in the sources
    lake exe seclang-check                       # ../tests/unit/transformations by default; exit 1 on any mismatch
    lake exe seclang-check ../tests/unit/operators   # the operator corpus

`lake exe seclang-check <dir>` runs any directory of unit-tier files. Operator files are
run for `beginsWith`, `contains`, `containsWord`, `endsWith`, `eq`, `ge`, `gt`, `ipMatch`,
`ipMatchFromFile`, `le`, `lt`, `noMatch`, `pm`, `pmFromFile`, `rx`, `streq`, `strmatch`, `unconditionalMatch`,
`validateByteRange`, `validateUrlEncoding`, `validateUtf8Encoding`, `verifyCC`,
`verifyCPF`, `verifySSN` and `within`; `detectSQLi` and `detectXSS` (libinjection) are
skipped by name, and a case whose regular expression lies outside the Core `@rx` subset
(ADR-0018 extensions such as lookahead) is reported as skipped with its reason.

## Grammar

`SecLang/Syntax.lean` is the parser for `spec/01-lexical.md`, `spec/02-grammar.md` and the
directive table of `spec/04-directives.md`, with the vocabulary of chapters 05–08 in
`SecLang/Names.lean`. It is checked against the configuration of every engine profile:

    uv run python tools/engine_rules.py > formal/.lake/engine-rules.json   # from the repository root
    cd formal && lake exe seclang-parse .lake/engine-rules.json            # exit 1 on any mismatch

A profile whose stages assert `expect_error` must be rejected, every other profile must be
accepted; the runner prints the rule a rejected profile violates.

The same runner is the CRS acceptance run: `tools/crs_rules.py` packages an OWASP CRS
checkout (`crs-setup.conf.example`, every `rules/*.conf`, the `.data` files, and all of them
concatenated as `ALL`) and every profile must be accepted. CI runs it against CRS v4.25.2;
locally:

    uv run python tools/crs_rules.py /path/to/coreruleset > formal/.lake/crs.json
    cd formal && lake exe seclang-parse .lake/crs.json

## Processing model

`SecLang/Semantics.lean` is `spec/03-processing-model.md` over the parsed configuration:
effective rules after exceptions and default actions, the five phases, chains, `skip` and
`skipAfter`, disruptive actions and interruptions, `allow`, engine modes, `ctl`, `setvar`,
`capture` and macros. It is parametric in a regular-expression oracle
(`SecLang/Regex.lean`, the Core `@rx` subset) and in how the variable store is populated
per phase through a phase-boundary hook (`SecLang/Request.lean`: chapters 05 and 09 for
URL-encoded, multipart and JSON bodies, chapter 04 for the request and response body limits,
which the hook applies at phases 2 and 4). Eight theorems close the file: `phase_default` and
`phase_not_inherited` (ADR-0017); `skipAfter_missing` and `later_phase_unaffected` (ADR-0016:
an unsatisfied `skipAfter` leaves the transaction untouched, so every later phase runs as if
it had not fired) with `skipAfter_ends_with_phase` restating the construction;
`interrupted_phase_quiet`, `body_limit_reject_quiet` (a `Reject` limit evaluates no rule of
its phase) and `logging_phase_runs`. `@rx` is compiled dot-all with anchors at the subject
ends (ADR-0027).

    cd formal && lake exe seclang-eval .lake/engine-rules.json    # exit 1 on any mismatch

Every stage of every profile the abstract transaction can carry is run and its
`triggered_rules`, `non_triggered_rules`, `interruption` and `no_interruption` checked. A
profile is reported `unsupported (<reason>)` when it needs the XML body processor,
`setsid`/`setuid`/`setrsc`, `@detectSQLi`/`@detectXSS` or log assertions; that list is the
model's boundary, not a known gap. Persistent collections exist within one transaction only
(`initcol` creates them, `setvar` writes them, nothing survives the transaction).

## What a mismatch means

The model is a reference, not an engine: it has no rows in `compat/known-gaps.md`. A
mismatch, in either runner, is a defect in the corpus, in a profile, in the spec text or
in the model, classified the way an adapter disagreement is (`AGENTS.md`) and fixed before
merge.

Reference semantics is ModSecurity v2 `apache2/msc_util.c`, which is what the corpus
expects; each definition cites the C function it models.
