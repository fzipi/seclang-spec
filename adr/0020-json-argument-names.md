# ADR-0020: JSON argument names are unspecified

- **Status:** proposed
- **Date:** 2026-10-07
- **Deciders:** @fzipi
- **Category:** Clarification

## Context

All three engines flatten a JSON request body into `ARGS_POST` members, one per scalar
leaf, but name them differently:

- ModSecurity v2 (`apache2/msc_json.c`): the key path joined with `.`, no prefix for
  top-level keys (`b.c`); a top-level array is named `array`.
- libmodsecurity v3 (`src/request_body_processor/json.cc`): the path of enclosing
  containers joined with `.`, array elements as `array_N`.
- Coraza 3.8.1 (`internal/bodyprocessors/json.go`, `readItems`): every name prefixed with
  `json.`, array elements numbered from 0 (`json.d.0`).

OWASP CRS targets `ARGS` and `ARGS_NAMES` as a whole and never names a JSON path, so no
published ruleset depends on the scheme. A rule author writing `ARGS:json.user.role`
today works on one engine only.

## Decision

The set of leaf values and their count are normative; the member names are not. A rule
that needs a specific JSON leaf MUST match `ARGS_NAMES` with an expression anchored at the
end of the name (for example `(?:^|\.)role$`) or inspect `ARGS` as a whole. Engines
SHOULD document their scheme. A future Divergence ADR may standardise a scheme once an
engine is prepared to change; until then no test asserts a name.

## Options considered

- Pick Coraza's `json.` prefix: self-describing and collision-free with form fields, but
  breaks every ModSecurity exclusion written against bare paths; deferred.
- Pick v2's bare paths: the oldest scheme, but collides with form field names and v3
  does not implement it either; deferred.
- Leave unspecified (chosen).

## Consequences

- For rule authors: never write `ARGS:json.x` or `ARGS:x` for JSON leaves in portable
  rules.
- For engines: no change now.

## Tests

- `tests/engine/body/json-args.yaml` (asserts count, a value and an anchored name regex)

## References

- `spec/09-body-processors.md#json`
