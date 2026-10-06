# SecLang Specification

A formal specification of **SecLang**, the rule language implemented by
[ModSecurity](https://github.com/owasp-modsecurity/ModSecurity) (v2 and libmodsecurity
v3) and [Coraza](https://github.com/corazawaf/coraza), with engine-neutral conformance
tests and Architecture Decision Records for the places where engines diverge.

## Layout

| Path | What |
|---|---|
| `spec/` | The specification, one file per topic. Every feature heading has a `**Status:**` line. |
| `adr/` | Decisions. `Divergence` ADRs pick a behaviour where engines disagree and name the test that encodes it. |
| `tests/` | Conformance test data (no runner). `unit/` for operators and transformations, `engine/` for everything else. |
| `compat/` | Three-engine feature matrix. Edit `matrix.json`, regenerate `matrix.md` with `tools/matrix.py`. |
| `tools/` | `validate.py` enforces the repo's invariants; CI runs it. |

## Status labels

`Core` MUST be implemented. `Extended` SHOULD be, and is declared per engine.
`Deprecated` MUST parse and MAY be ignored. `Engine-specific` is reserved, not specified.
Definitions: `spec/00-conventions.md`. Rationale: `adr/0001-status-labels-and-core.md`.

## Running the checks

```sh
python3 -m pip install -r requirements-dev.txt
python3 tools/validate.py
python3 -m unittest discover -s tools -t .
```

## Implementing an engine adapter

Read `tests/README.md`. Load every file under `tests/unit` and `tests/engine`, skip
engine profiles whose `requires` lists a feature you do not implement, and assert the
`output` blocks. Report the spec version you conform to.

## Contributing

Open an ADR for any behavioural decision; add or update tests in the same change; run
the validator. The design document is in `docs/superpowers/specs/`.
