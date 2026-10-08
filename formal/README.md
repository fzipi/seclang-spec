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

## What a mismatch means

The model is a reference, not an engine: it has no rows in `compat/known-gaps.md`. A
mismatch is a defect in the corpus, in the spec text or in the model, classified the way
an adapter disagreement is (`AGENTS.md`) and fixed before merge. Files for
transformations not yet formalized are reported as skipped.

Reference semantics is ModSecurity v2 `apache2/msc_util.c`, which is what the corpus
expects; each definition cites the C function it models.
