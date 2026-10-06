# Conformance tests

This directory holds **data only**. There is no runner here: each engine writes a
small adapter that loads these files and asserts the expectations with its own test
framework. The schemas in `schema/` are the contract.

## Tiers

| Tier   | Path               | Format | Schema                      | Reused from |
|--------|--------------------|--------|-----------------------------|-------------|
| unit   | `unit/**/*.json`   | JSON   | `schema/unit.schema.json`   | SecRules Test Set (`secrules-language-tests`) |
| engine | `engine/**/*.yaml` | YAML   | `schema/engine.schema.json` | go-ftw YAML / Coraza `testing/profile` |

**Unit** cases exercise one operator or transformation in isolation. `ret` is 1 when an
operator matches, or when a transformation changed its input. `input`/`output` are JSON
strings, so `\u0000` and other escapes are legal. Unlike the original SecRules Test Set
corpus, which stores a literal backslash sequence and unescapes it a second time after
JSON parsing, these files use plain JSON escapes only: adapters MUST NOT apply a second
unescape pass, and cases imported from that corpus are converted on import.

**Engine** profiles load `rules`, then run each stage's `input` as a transaction. When a
stage has a `response`, the adapter must feed it as the backend response so phases 3–5
run. `output` asserts on rule IDs and interruption only; log wording is never asserted
beyond `log_contains`/`no_log_contains` substrings.

## Fields that link tests to the spec

- `spec: NN-file.md#anchor` points at the heading in `spec/` the case verifies. The
  validator fails if the anchor does not exist or has no `**Status:**` line.
- `requires: [NN-file.md#anchor, ...]` (engine tier) lists the Extended features the
  profile needs, by spec anchor. An engine that does not implement one of them must
  **skip** the file, not fail it. The validator rejects an entry that is not an
  Extended feature. Unit cases have no `requires`; an engine skips a unit case whose
  `spec` anchor is an Extended feature it does not declare.
- `files: {relative/path: content}` (engine tier) ships auxiliary files. The adapter
  writes each one relative to a temporary directory, then loads `rules` with that
  directory as the configuration directory, so `Include relative/path` and
  `@pmFromFile relative/path` resolve.

## Adding a case

1. Pick the tier and copy an existing file.
2. Set `spec` to the heading you are testing. If the heading does not exist yet, add it
   to `spec/` with a status line first.
3. Run `uv run python tools/validate.py` from the repo root.
