# Formal model

Lean 4 definitions of the specification, executable against the conformance corpus.
Status: every transformation of `spec/07-transformations.md` (`SecLang/Transformations.lean`,
digests in `SecLang/Digest.lean`, helpers in `SecLang/Bytes.lean`); design documents under
`docs/superpowers/specs/2026-10-08-lean-*.md`, roadmap in
`docs/superpowers/specs/2026-10-08-lean-formalization-brief.md`.

## Build and run

Install elan (`brew install elan-init`, or <https://github.com/leanprover/elan>); the
toolchain named in `lean-toolchain` is fetched on first build. No other dependency.

    cd formal
    lake build                 # also evaluates every #guard in the sources
    lake exe seclang-check     # ../tests/unit/transformations by default; exit 1 on any mismatch

`lake exe seclang-check <dir>` runs another directory of unit-tier files.

## Grammar

`SecLang/Syntax.lean` is the parser for `spec/01-lexical.md`, `spec/02-grammar.md` and the
directive table of `spec/04-directives.md`, with the vocabulary of chapters 05–08 in
`SecLang/Names.lean`. It is checked against the configuration of every engine profile:

    uv run python tools/engine_rules.py > formal/.lake/engine-rules.json   # from the repository root
    cd formal && lake exe seclang-parse .lake/engine-rules.json            # exit 1 on any mismatch

A profile whose stages assert `expect_error` must be rejected, every other profile must be
accepted; the runner prints the rule a rejected profile violates.

## What a mismatch means

The model is a reference, not an engine: it has no rows in `compat/known-gaps.md`. A
mismatch, in either runner, is a defect in the corpus, in a profile, in the spec text or
in the model, classified the way an adapter disagreement is (`AGENTS.md`) and fixed before
merge.

Reference semantics is ModSecurity v2 `apache2/msc_util.c`, which is what the corpus
expects; each definition cites the C function it models.
